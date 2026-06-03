# Fermata-eBPF

Android 后台进程冻结引擎，eBPF CO-RE 版。

内核态通过 tracepoint 追踪进程生灭和 CPU 时间，用户态 epoll 事件驱动，
按内存压力 + 缓存状态自动冻结/杀死进程，替代传统轮询 `/proc`。

## 架构

```
BPF (内核态)                         用户态 (C++)
─────────────                        ────────────
sched_process_exit  ──ringbuf──→   实时清理退出 PID
sched_switch        ──hash map─→   每进程 CPU 时间 (per-CPU)
                                     │
                                     ├─ epoll_wait (ringbuf + inotify)
                                     ├─ cgroup.freeze + nice=19
                                     └─ 配置文件热加载
```

**性能对比 (骁龙 8E5 / 8 核):**

| | eBPF v4.0 | v3.1.0 轮询 |
|---|---|---|
| CPU | 10~25% | <1% |
| 内存 | ~5 MB | ~5 MB |
| 二进制 | 252 KB | 72 KB |
| 精度 | 实时 (每次调度切换) | 3 秒轮询 |

`sched_switch` 是内核最热的 tracepoint，8 核设备每秒触发上万次 BPF 程序。
日常使用推荐 v3.1.0 轮询版。本仓库为学习/研究用途。

## 要求

- 内核 5.4+ 且开启 BTF (`/sys/kernel/btf/vmlinux` 存在)
- Android 12+
- Root + Magisk/KernelSU
- Termux (编译用)

## 快速编译 (手机 Termux)

项目里带了两个脚本，放到 `/sdcard/Download/`：

**首次编译** (含 git clone bpftool, 需网络, ~5 分钟)：
```bash
bash /sdcard/Download/build.sh
```

**日常改代码后重编** (只重编 libbpf.a + 守护进程, ~10 秒)：
```bash
bash /sdcard/Download/compile.sh
```

编译产物 `fermata_ebpf` (~252KB) 会自动部署到 `/data/adb/modules/fermata/`。

## 手动编译步骤

```bash
# 1. 装依赖
pkg install clang git make libelf zlib

# 2. 编译 libbpf.a (注意 AR=llvm-ar 是 LTO 生效的关键)
git clone --depth 1 --recurse-submodules https://github.com/libbpf/bpftool
cd bpftool/libbpf/src
CFLAGS="-Os -flto -fdata-sections -ffunction-sections" AR=llvm-ar make -j4
mkdir -p ../include/bpf && cp *.h ../include/bpf/

# 3. 编译 BPF 字节码 (需要 -g 否则 CO-RE 重定位失败)
clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c fermata_core.bpf.c -o fermata_core.bpf.o

# 4. 生成 skeleton (bpftool 在 Termux 上编不了，从 CI 下载或用预编译)
bpftool gen skeleton fermata_core.bpf.o > fermata_core.skel.h

# 5. 编译守护进程
clang++ -std=c++17 -Os -s -flto \
    -fdata-sections -ffunction-sections \
    -Wl,--gc-sections -Wl,--strip-all \
    -I~/bpftool/libbpf/include \
    fermata_main.cpp \
    ~/bpftool/libbpf/src/libbpf.a \
    -lelf -lz -o fermata_ebpf

# 6. 部署
su -c "cp fermata_ebpf /data/adb/modules/fermata/fermata"
su -c "chmod 755 /data/adb/modules/fermata/fermata"
su -c "killall fermata 2>/dev/null; sleep 1; /data/adb/modules/fermata/service.sh &"
```

## Bionic 兼容性

Android Bionic libc 和 glibc 有两点差异，已在源码处理：

**`struct sysinfo` 不公开** — Bionic 声明了 `sysinfo()` 但不暴露结构体，
用内核布局自定义结构体强转调用。

**`bpf_map_lookup_elem` 缺失** — libbpf v1.3+ 移除了这个包装函数，
改为直接 `syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, ...)`。

## 配置 (fermata.conf)

`/data/adb/modules/fermata/fermata.conf`，修改后自动热加载：

```ini
# 白名单 (逗号分隔)
whitelist=com.tencent.mm,com.example.app

# 进程进入缓存后冻结延迟 (扫描周期数, 默认 1)
freeze_delay=1

# 主循环扫描间隔 ms (默认 3000)
scan_ms=3000

# 内存阈值 MB (默认 low=2000, mid=4000)
mem_low=2000
mem_mid=4000

# 调试日志
debug_log=0
```

完整参数见源码 `load_config()` 函数。

## 体积优化

| 优化 | 大小 |
|---|---|
| -O2 初始 | 406 KB |
| -Os -flto (仅守护进程) | 377 KB |
| libbpf.a 也 -Os -flto + AR=llvm-ar | **252 KB** |

## 调试

```bash
# 开日志
echo "debug_log=1" >> /data/adb/modules/fermata/fermata.conf

# 看 BPF 程序状态
cat /sys/kernel/debug/tracing/trace_pipe

# 看进程冻结情况
cat /sys/fs/cgroup/*/cgroup.events | grep frozen
```

## 后续优化方向

- **采样率**: `sched_switch` 每进程每 100ms 只记一次，CPU 可从 10~25% 降到 2~3%
- **去掉 ringbuf**: 进程退出改读 `/proc` 轮询，减少内核态内存分配
- **per-CPU hash 改 array**: 固定 key 范围用 BPF_MAP_TYPE_ARRAY 替代 HASH，更快
- **用户态瘦身**: 去掉 `<iostream>`/`<fstream>`，改用纯 C FILE*，libc++ → libc

## 已知问题

- bpftool 无法在 Termux 直接编译 (Bionic 头文件冲突 + 缺 qsort_r)，骨架由 CI 预生成
- GitHub Actions NDK 交叉编译 libelf 暂不通 (缺 argp)
- SELinux Enforcing 下部分 `/proc` 路径可能受限

## 许可

GPL-3.0
