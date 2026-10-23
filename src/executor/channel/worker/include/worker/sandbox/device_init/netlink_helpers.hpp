// Netlink foundation primitives — 对齐 syzkaller `executor/common_linux.h`
// 132-369 行的 `struct nlmsg` + `netlink_init/attr/nest/done/send/send_ext/
// query_family_id/next_msg`。
//
// 范围:仅 foundation 层(消息构造 + 收发 + family lookup)。 device-specific
// builder (netlink_add_veth / netlink_add_geneve / netlink_add_vlan / ...)
// 不在 D2,跟随各自 D3-D5 init function 放在同文件内。
//
// 与上游差异:
//   - `fail()` / `failmsg()` 替换为 `WorkerLog(...)` + 返回 -1 / 设置 errno
//   - `dofail` 仍保留语义:true → LOG loud (init 期), false → LOG quiet (exec 期);
//     reFuzz device_init 全 init-only,实际几乎都 dofail=true
//   - caller-owned `Nlmsg buf{}`(stack alloc 4 KiB) 替换 upstream 的两个
//     file-static `struct nlmsg nlmsg, nlmsg2`;每个 init 自带局部 buf,
//     不再担心嵌套 builder 共享 buffer 的边界情况
//   - PascalCase 类型名 `Nlmsg`(API 行为 byte-equal 上游 `struct nlmsg`)
//
// 调用上下文:device_init / initialize_* 内 init-time。
// CAP_NET_ADMIN 需在 caller 端保证(sandbox=none 默认保留)。
//
// 失败语义:
//   - `NetlinkInit/Attr/Nest/Done` void 返回,失败 LOG 但不 abort
//   - `NetlinkSend/SendExt` 返回 0 成功 / -errno 失败 / -1 通用错误
//   - `NetlinkQueryFamilyId` 返回 family_id > 0 / -1 失败

#pragma once

#include <linux/netlink.h>

#include <cstdint>
#include <cstddef>

namespace refuzz::worker::sandbox::device_init {

// 与 upstream `struct nlmsg` 字段同序同义。caller stack-alloc;`Reset()`
// 等价 `memset(0, sizeof)`(NetlinkInit 自动 reset,通常无需手动)。
struct Nlmsg {
    // 当前 write head;初次 NetlinkInit 之后指向 nlmsghdr 之后。
    char* pos;
    // 当前 nesting depth(NetlinkNest++ / NetlinkDone--)。
    int nesting;
    // 嵌套 attr 栈(最多 8 层,upstream 同值)。
    struct ::nlattr* nested[8];
    // 4 KiB netlink buffer,与 upstream NLMSG_BUF_SIZE 等同。
    char buf[4096];

    void Reset();
};

// === foundation: build ===========================================

// 初始化 nlmsg buffer + 首部 nlmsghdr:
//   memset(0); set type/flags; payload = data[0..size]; pos 指向 payload 末。
// 与 upstream `netlink_init` 同语义。
void NetlinkInit(Nlmsg* msg, int typ, int flags, const void* data, int size);

// 追加 attribute (TLV) 到 buffer。NetlinkInit 之后任意时刻可调。
void NetlinkAttr(Nlmsg* msg, int typ, const void* data, int size);

// 嵌套 attribute 开始 —— push 当前 attr 到 nested[] 栈。
// NetlinkDone 配对结束 nesting。
void NetlinkNest(Nlmsg* msg, int typ);

// 关闭最近一层 nest,回填 nla_len = pos - attr_start。
void NetlinkDone(Nlmsg* msg);

// === foundation: I/O =============================================

// 把已构造好的消息 sendto(socket) + recv ack。
// reply_type / reply_len 用于 read-back (eg. CTRL_CMD_GETFAMILY)。
//   reply_len != NULL 且 reply matches reply_type:把读到的字节数填入。
// 返回:
//   0   = ACK 成功 (NLMSG_DONE 或 reply_type 匹配)
//   -errno = kernel 报错 (NLMSG_ERROR 解出 -err)
//   -1  = sendto / recv 短读/短写,errno 已设
//
// dofail = true → LOG loud(syzkaller upstream fail() 语义,reFuzz 改 LOG)
// dofail = false → LOG quiet(syzkaller upstream debug() 语义)
int NetlinkSendExt(Nlmsg* msg, int sock, std::uint16_t reply_type,
                   int* reply_len, bool dofail);

// 等价 NetlinkSendExt(msg, sock, 0, NULL, true) —— 简单 ACK-only 包。
int NetlinkSend(Nlmsg* msg, int sock);

// 用 GENL_ID_CTRL + CTRL_CMD_GETFAMILY 查 family_id。
// 失败返回 -1,成功返回 family id (uint16,范围内总 > 0)。
int NetlinkQueryFamilyId(Nlmsg* msg, int sock, const char* family_name,
                         bool dofail);

// === foundation: parse ===========================================

// 在 multi-part dump (NLM_F_MULTI) reply 里遍历下一条 nlmsghdr。
// total_len = 前一次 recv 返回的总字节数;offset = 当前已 parsed 字节数。
// 返回:
//   下一条 hdr 的 nlmsg_len  if offset 内还有完整 msg
//   -1                       if 已耗尽 或 offset+hdr_len > total_len
int NetlinkNextMsg(const Nlmsg* msg, unsigned offset, unsigned total_len);

} // namespace refuzz::worker::sandbox::device_init
