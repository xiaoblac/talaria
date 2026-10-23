// Sandbox device init primitives — 对齐 syzkaller `do_sandbox_none()` 序列。
//
// reFuzz worker `ApplyNone` 之前只做 SandboxCommon + DropSyzkallerCaps +
// NEWNET + ping_group_range,缺 syzkaller 的 8 段 device init:
// initialize_vhci / initialize_netdevices_init / initialize_devlink_pci /
// initialize_tun / initialize_netdevices / initialize_wifi_devices /
// sandbox_common_mount_tmpfs (内部 call setup_gadgetfs + setup_binderfs +
// setup_fusectl + initialize_cgroups)。
//
// 完整 plan / 优先级见 docs/plans/sandbox-device-init.md。本 header 公开各
// init primitives;ApplyNone 按 syzkaller 序列调用。VHCI、TUN、WiFi 和
// tmpfs/chroot 的关键失败返回负 errno，loop 发送 failed startup ACK，daemon
// 重建 execution domain。只有显式 host-test degraded sandbox 可忽略这些失败。
//
// 调用上下文:在 loop child 进 sandbox setup 内,unshare(NEWNS) + NEWNET
// 之后(本 mount namespace 隔离,bind mount 不影响 host)。
// 调用前 cwd 由 launcher 决定(reFuzz 是 ivshmem_worker daemon
// inherited),`SandboxCommonMountTmpfs` 内部 chdir("/") 起步以使相对路径
// 可预测。

#pragma once

#include <cstdint>

namespace refuzz::worker::sandbox::device_init {

// D3 pre-NEWNET (operates on host netns): NETROM (`nr`) + ROSE (`rose`)
// devices 加 IPv4/IPv6 地址 + MAC + up。 procid 用于 device name suffix
// + IP 第 3 段;reFuzz 单 worker oracle default 0,multi-worker future 传
// executor_id。详见 common_linux.h:1696。
void InitializeNetdevicesInit(std::uint64_t procid = 0);

// D3 post-NEWNET: open /dev/net/tun → fd 200,ioctl TUNSETIFF "syz_tun" +
// IFF_TAP|IFF_NO_PI,IPv6 sysctl 抑制 DAD/RS,setup local/remote IPv4+IPv6
// addresses + ARP/ND entries,device up + LOCAL_MAC。详见 common_linux.h:668。
int InitializeTun();

// Verify that /dev/net/tun is character device 10:200 and recreate it when a
// previous program removed or replaced the node. InitializeTun calls this
// immediately before open(), matching syzkaller correct_dev_net_tun().
void CorrectDevNetTun();

// D4 post-NEWNET: 在新 netns 创建一大堆虚拟 netdev (bridge/bond/team/batadv/
// hsr/vxcan/veth/wireguard/dummy/nlmon/caif/vcan/virt_wifi/macvtap/macsec/
// vlan/macvlan/ipvlan/geneve/netdevsim/xfrm/ip6gretap...), 给每个加
// IPv4/IPv6/MAC + up。procid 用作 netdevsim 实例编号 + DEV_IPV4 index 基。
// 详见 common_linux.h:1488-1693。
void InitializeNetdevices(std::uint64_t procid = 0);

// D4 internal helper: write /sys/bus/netdevsim/{del,new}_device。
// (initialize_netdevices 自己调,供 D7 future override 用)。
void NetdevsimAdd(unsigned addr, unsigned port_count);

// D4 internal helper: WireGuard 三 device 互为 peer 设置 (wg0/wg1/wg2)。
// 必须在 NetlinkAddDevice("wireguard", "wg{0,1,2}") 之后才有效。
// 详见 common_linux.h:1251-1453。
void NetlinkWireguardSetup();

// D5 post-NEWNET: 创建 mac80211_hwsim 2 radios + 把 wlan0/wlan1 join 同一
// IBSS network (wiphy_freq=2412)。给 syz_80211_inject_frame /
// syz_80211_join_ibss 等 pseudo fuzz 一个 ready wireless stack。详见
// common_linux.h:1100-1166。缺少所需 kernel feature 时返回失败。
int InitializeWifiDevices();

// 端口 syz_80211_join_ibss fuzz-time path (common_linux.h:5654)。
// 内部走 upstream 4 步:if_nametoindex → nl80211_set_interface(ADHOC) →
// set_interface_state(UP) → nl80211_join_ibss;mode==NO_SCAN 时再
// await_ifla_operstate(IF_OPER_UP)。
//
// caller(pseudo handler)负责 ssid_len / mode 合法性校验,本函数只做
// "执行 setup 流程"。返 0 成功,-1 失败 (errno 保留 kernel 报的真值或
// helper internal,例 NLMSG_ERROR -EALREADY → errno=EALREADY)。
//
// 设计目标:fuzz-time 与 setup-time (InitializeWifiDevices 内 wlan0/1
// join) 走完全同一组 helper,避免实现分叉。byte-equal 上游
// `syz_80211_join_ibss` runtime path,不直接暴露 Nlmsg/sock/family_id。
int WifiJoinIbssFuzzTime(const char* iface,
                         const std::uint8_t* ssid,
                         int ssid_len,
                         int mode);

// D6 pre-sandbox_common: open /dev/vhci → fd 202, dup2, send vendor_pkt,
// spawn event_thread, HCIDEVUP + HCISETSCAN + fake BR/EDR/LE connections,
// pthread_join。 给 syz_emit_vhci / Bluetooth socket fuzz 一个 ready virtual
// HCI controller。详见 common_linux.h:2660-2923。
// kernel CONFIG_BT + CONFIG_BT_HCIVHCI 缺失或初始化失败时返回失败。
int InitializeVhci();

// D7 post-NEWNET: setns 回 init netns,devlink reload "pci/0000:00:10.0"
// instance 到 sandbox netns,然后 dump ports 并 rename 为 netpci0/1/...。
// kInitNetNsFd (sandbox.cpp:113) = 201,与本模块同步使用。
// kernel CONFIG_NET_DEVLINK + 实际 PCI devlink device 缺时 silent skip。
void InitializeDevlinkPci();

// D7 helper shared by PCI and netdevsim setup. Dump the devlink ports for one
// instance, then bring them up and rename them with a stable prefix.
void InitializeDevlinkPorts(const char* bus_name,
                            const char* dev_name,
                            const char* netdev_prefix);


// D1 main entry: 对齐 syzkaller `sandbox_common_mount_tmpfs`
// (common_linux.h:3930)。完整序列:
//   write /proc/sys/fs/mount-max=100000
//   mkdir+mount tmpfs ./syz-tmp
//   8 bind mount: dev / proc / selinux / sys / kernel/debug / smackfs /
//                 binfmt_misc / syz-inputs
//   InitializeCgroups (bind /syzcgroup/{unified,cpu,net})
//   pivot_root + umount old + chroot ./newroot + chdir /
//   SetupGadgetfs / SetupBinderfs / SetupFusectl (after chroot)
//
// 要求 CAP_SYS_ADMIN (sandbox=none 保留;DropSyzkallerCaps 只丢
// PTRACE+NICE)。调用方应已 unshare(CLONE_NEWNS)。
int SandboxCommonMountTmpfs();

// D1 helper: mount cgroup{,/cpu,/net} bind 到 newroot 内 (common_linux.h:3893)。
// 仅在 SandboxCommonMountTmpfs 内部 (tmpfs + newroot 已建好之后) call。
// host 缺 /syzcgroup/* 时各 bind silent log;
// mkdir 也只有 newroot/syzcgroup 自己 fail 致命(无 newroot 就完全不对了)。
void InitializeCgroups();

// worker 0 在 daemon Register() 发布 CLAIMED/heartbeat 后、domain sandbox
// 启动前调用一次。其它 worker 不调用。
// mkdir /syzcgroup + mount cgroup2 unified(+cpu/+io/+pids subtree_control)+
// mount cgroup v1 cpu(cpuset,cpuacct,hugetlb,rlimit,memory)+ mount cgroup v1
// net(net,net_prio,devices,blkio,freezer)+ clone_children/memory_pressure_enabled
// sysctl。host 自己没挂 cgroup 时(常见,VM image 不一定预 mount)这一步把
// hierarchy 准备好,后续 InitializeCgroups bind / SetupCgroupsLoop mkdir 才
// 有实物可操作。对应 syzkaller `setup_cgroups` (common_linux.h:3795-3818)
// + `mount_cgroups` / `mount_cgroups2` (3725-3793),
// 在 syz-executor 由 executor_runner.h:735 早期调用。
void MountCgroupsHost();

// Host/VM sysctl initialization aligned with syzkaller `setup_sysctl`
// (executor/common_linux.h:5537). Worker 0 invokes this once from the
// post-register hook. Each write is best-effort: a missing kernel/debugfs node
// does not prevent the worker from starting. The table includes
// hung_task_check_interval_secs=20 and the current upstream diagnostic, OOM,
// BPF, mount, and Ctrl-Alt-Del settings. Ctrl-Alt-Del uses a transient live PID.
void SetupVmSysctls();

// 与 MountCgroupsHost 同一个 worker-0 post-register hook 调一次。mount
// binfmt_misc(EBUSY OK,
// host 可能已挂)+ 写 /proc/sys/fs/binfmt_misc/register 注册 syz0/syz1 两个
// magic-based binfmt(M:0:\x01:./file0 和 M:1:\x02:./file0:POC)。
//
// 没这一步:execveat$binfmt 在 magic 0x01/0x02 文件上找不到匹配 binfmt
// handler,fall-through 到 script/ELF/aout 检查,全部失败 → 一律返 ENOEXEC。
// 上游对应 calls 按文件实际状态返 ENOENT(文件不在)/ EACCES(权限不够)/
// ENOEXEC(格式错)。10 个 actionable execveat$binfmt mismatch 的根因。
//
// 对应 syzkaller `setup_binfmt_misc` (common_linux.h:5075-5093),由 executor
// feature setup chain (executor_linux.h:378) 在 BinFmtMisc feature enabled
// 时调用。reFuzz unconditional 调,所有 trace 都假定 binfmt 注册了。
void SetupBinfmtMisc();

// loop_child 进 main exec loop 之前 call 一次。创 /syzcgroup/unified/syz<procid>
// + pids.max=32 + 把 loop_child 写入 cgroup.procs,后续 fork 出来的 program-child
// 全在同 cgroup,累积 task 数超 32 时 fork 返 EAGAIN(对齐上游 fork-bomb 防护)。
// 同时创 cpu/net cgroup,cpu 加 memory.{soft_limit,limit}_in_bytes 300 MB。
// 对应 syzkaller `setup_cgroups_loop` (common_linux.h:3821-3869)。
void SetupCgroupsLoop(std::uint64_t procid);

// 每个 program-child fork 之后、跑 program 之前 call 一次。在当前 cwd 创
// ./cgroup / ./cgroup.cpu / ./cgroup.net symlink 指向 host /syzcgroup/.../
// syz<procid>。给 corpus 里需要 cgroup path 的 fuzz target 一个稳定入口。
// 对应 syzkaller `setup_cgroups_test` (common_linux.h:3871-3890)。
void SetupCgroupsTest(std::uint64_t procid);

// ForkingProgramExecutor 的 program-child fork 后无条件调用。镜像 upstream
// `setup_test` 中与 cwd 无关的进程契约:prctl(PR_SET_PDEATHSIG, SIGKILL) +
// setpgrp() + oom_score_adj=1000。
//
// **setpgrp() 是 stopped-child cleanup 核心**:program-child 成 group
// leader,program 完成 _exit(0) 后整个 group orphaned,kernel 自动 SIGHUP+
// SIGCONT 杀死所有 stopped 状态的 grand-child(包括 ptrace 截停的 syz_clone
// child),cgroup pids 自动释放。没这一步会有 over-EAGAIN(11 个 stopped
// child 累积撑爆 pids.max=32,实测见 [eagain-snap-proc] 输出)。
void SetupTestProcess();

// ProgramRuntime 成功切入 per-program cwd 后调用。只执行依赖当前 cwd 的
// setup_cgroups_test/binderfs symlink，以及既有 test-child fd hygiene。
void SetupTestWorkdir(std::uint64_t procid);

// Match syzkaller close_fds() at the end of execute_one(): close the program
// ABI fd range after backend cleanup but before observation SessionEnd packs
// release-triggered device coverage. Internal loop/KCOV fds live at 200+.
void CloseProgramFds();

// Checkpoint the network namespace once before the loop becomes ready. This
// mirrors syzkaller `checkpoint_net_namespace`: the GET_INFO/GET_ENTRIES calls
// also lazy-register netfilter hooks in the new namespace.
//
// 每张表 getsockopt(SOCK_STREAM/IPPROTO_TCP/SO_GET_INFO)。**副作用**是 kernel
// 在该 netns lazy-register 对应的 netfilter hook。**没这步**:netns 里 iptables
// hooks 未注册,emit_ethernet 注入的 packet 进 RX 直接 skip iptables 链 →
// KCOV 看不到 ipt_do_table / iptable_mangle_hook / ip_packet_match → syz capture
// vs reFuzz replay 在 net-inject 类 syscall 上 union jaccard 0.28。F4 worklist 根因。
//
// ENOPROTOOPT/EPERM/ENOENT for an individual absent table are soft skips, as
// are unsupported protocol families. Other errors and partial captures return
// false; the caller must discard the execution domain.
bool CheckpointNetNamespace();

// Restore every captured table whose current header or entries differ from the
// checkpoint. A false return is fatal for the current execution domain. The
// caller gates this API off for sandbox=setuid, where the post-sandbox process
// no longer has the privileges required by netfilter replacement.
bool ResetNetNamespace();

// [F4 fix] program-child fork 之后(在 SetupTest 之后)call 一次。对齐 syzkaller
// `flush_tun` (common_linux.h:2302):读 tun fd 200 直到 EAGAIN/EWOULDBLOCK,
// 清掉前一 program 留在 tun 队列里的 packet。**没这步**:跨 program packet
// bleed-through 让 RX 路径上的 recvfrom / KCOV cover 包含其它 program 的余孽。
void FlushTun();

// [post-exit dump diag] loop_parent 在 program-child waitpid 收尸完成
// 之后调一次,dump /syzcgroup/unified/syz<wid>/cgroup.procs 每 pid 一行
// (state/pgid/sid/ppid)。给 over-EAGAIN 诊断用,看 setpgrp 是否生效
// (stopped child 的 pgid 应该 == 历次 program-child pid)以及 orphaned-pgrp
// cleanup 为啥没触发(task_session(real_parent) == task_session(p) 命中?)。
//
// 默认 no-op,env REFUZZ_DUMP_POST_EXIT=1 开启;前 256 个 program 全 dump,
// 之后只在 pids.current >= 24 时 dump,避免 ttyS0 burst。
void DumpCgroupSnapshotPostExit(std::uint32_t proc_id,
                                std::uint64_t prog_seq);

// D1: gadgetfs 实例 mount 到 /dev/gadgetfs (common_linux.h:4010)。
// must be called after chroot —— /dev 已 bind 至 newroot 视图。
// 缺 CONFIG_USB_GADGETFS 时 silent log。
void SetupGadgetfs();

// D1: binderfs 实例独立 mount 到 /dev/binderfs (common_linux.h:4034)。
// must be called after chroot。缺 CONFIG_ANDROID_BINDERFS silent log。
void SetupBinderfs();

// D1: fusectl 类型 mount 到 /sys/fs/fuse/connections (common_linux.h:4027)。
// must be called after chroot。缺 CONFIG_FUSE_FS / 路径不存在 silent log。
void SetupFusectl();

// Timeout escalation matching syzkaller kill_and_wait(): abort every FUSE
// connection visible through this execution domain's fusectl mount. Returns
// the number of abort files successfully written.
// `absolute_deadline_us == 0` preserves the existing unlimited program-level
// watchdog behavior. A non-zero deadline is checked before the scan and
// between connection entries; abort-file opens are non-blocking.
std::uint32_t AbortFuseConnections(std::uint64_t absolute_deadline_us = 0);

} // namespace refuzz::worker::sandbox::device_init
