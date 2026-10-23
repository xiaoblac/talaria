# Distinct Bug Inventory

Bugs found in eight independent 48-hour campaigns on Linux v7.1 (Section V-E, Table V of the paper).
Each row is one distinct bug: crash signatures produced by the same underlying fault are merged into one entry, and failures caused by the experimental infrastructure are excluded.
The impact category follows Syzkaller's impact ordering: memory corruption; information leaks and concurrency; denial of service, hangs, and leaks; and ordinary BUG and WARNING reports, which carry no impact priority.
Rows that list two signatures separated by a semicolon denote one fault observed under two manifestations; the higher priority determines the impact category.

## Bugs discovered by Talaria but missed by Syzkaller (25)

| No. | Bug signature | Impact category |
|---:|---|---|
| 1 | KASAN: slab-use-after-free Read in `ath9k_hif_request_firmware` | Memory corruption |
| 2 | KASAN: slab-use-after-free Read in `release_metapage` | Memory corruption |
| 3 | KASAN: use-after-free Read in `copy_folio_from_iter_atomic` | Memory corruption |
| 4 | KASAN: slab-use-after-free Read in `jfs_lazycommit` | Memory corruption |
| 5 | BUG: spinlock bad magic in `ocfs2_fileattr_get` | Information leaks and concurrency |
| 6 | WARNING in `bfs_get_block`; general protection fault in `bfs_get_block` | Denial of service, hangs, and leaks |
| 7 | INFO: task hung in `blk_trace_setup` | Denial of service, hangs, and leaks |
| 8 | INFO: task hung in `vfs_coredump` | Denial of service, hangs, and leaks |
| 9 | INFO: task hung in `corrupted` | Denial of service, hangs, and leaks |
| 10 | INFO: task hung in `deactivate_super` | Denial of service, hangs, and leaks |
| 11 | INFO: task hung in `__fuse_simple_request` | Denial of service, hangs, and leaks |
| 12 | INFO: task hung in `__buffer_migrate_folio` | Denial of service, hangs, and leaks |
| 13 | INFO: task hung in `__writeback_inodes_sb_nr` | Denial of service, hangs, and leaks |
| 14 | INFO: task hung in `bdev_open` | Denial of service, hangs, and leaks |
| 15 | INFO: task hung in `bdev_release` | Denial of service, hangs, and leaks |
| 16 | INFO: task hung in `nbd_ioctl` | Denial of service, hangs, and leaks |
| 17 | kernel BUG in `dbBackSplit` | Ordinary bugs |
| 18 | WARNING in `print_bfs_bug` | Ordinary bugs |
| 19 | WARNING: possible circular locking dependency detected | Ordinary bugs |
| 20 | WARNING in `kernfs_get` | Ordinary bugs |
| 21 | WARNING in `lru_gen_exit_memcg` | Ordinary bugs |
| 22 | WARNING in `path_noexec` | Ordinary bugs |
| 23 | WARNING in `netif_rx_mode_run` | Ordinary bugs |
| 24 | WARNING in `bdev_getblk` | Ordinary bugs |
| 25 | WARNING in `io_ring_exit_work` | Ordinary bugs |

## Bugs discovered by Syzkaller but missed by Talaria (18)

| No. | Bug signature | Impact category |
|---:|---|---|
| 1 | KASAN: slab-out-of-bounds Write in `try_module_get` | Memory corruption |
| 2 | BUG: spinlock bad magic in `ocfs2_permission` | Information leaks and concurrency |
| 3 | possible deadlock in `hfsplus_get_block` | Information leaks and concurrency |
| 4 | possible deadlock in `ocfs2_init_acl` | Information leaks and concurrency |
| 5 | possible deadlock in `ocfs2_reserve_suballoc_bits` | Information leaks and concurrency |
| 6 | possible deadlock in `ocfs2_try_remove_refcount_tree` | Information leaks and concurrency |
| 7 | possible deadlock in `ocfs2_xattr_set` | Information leaks and concurrency |
| 8 | general protection fault in `__gfs2_trans_begin` | Denial of service, hangs, and leaks |
| 9 | INFO: task hung in `afs_cell_purge` | Denial of service, hangs, and leaks |
| 10 | INFO: task hung in `nbd_queue_rq` | Denial of service, hangs, and leaks |
| 11 | INFO: task hung in `xlog_grant_head_check` | Denial of service, hangs, and leaks |
| 12 | WARNING in `io_wq_put_and_exit` | Ordinary bugs |
| 13 | WARNING in `blk_mq_alloc_tag_set` | Ordinary bugs |
| 14 | WARNING in `__rate_control_send_low` | Ordinary bugs |
| 15 | WARNING in `btrfs_space_info_update_bytes_may_use` | Ordinary bugs |
| 16 | WARNING in `udf_setsize` | Ordinary bugs |
| 17 | INFO: trying to register non-static key in `ocfs2_dlm_shutdown` | Ordinary bugs |
| 18 | kernel BUG in `ocfs2_iget` | Ordinary bugs |

## Bugs discovered by both tools (9)

`txEnd` (a use-after-free Write for Talaria and a Read for Syzkaller), `call_timer_fn`, `p9_fd_close`, `reserve_ds_buffers`, `__gfs2_lookup`, `dvb_device_open`, `gfs2_jhead_process_page`, `sync_bdevs`, and `udf_truncate_extents`.
