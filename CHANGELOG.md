# Fermata eBPF 开发日志

## 项目概述

Fermata 是一个 Android 进程调度优化守护进程，通过 eBPF CO-RE 技术在内核态追踪
进程 CPU 时间，用户态根据内存压力、进程缓存状态等策略冻结/恢复/杀死进程，
达到省电优化目的。

### 设备环境

- 设备: 红米 K90 Pro Max (骁龙 8E5, 2 大核 + 6 中核)
- 内核: 6.12.23-android16 (支持 BTF CO-RE)
- 系统: HyperOS (Android 16)
- 大核起始编号: CPU 6
- Magisk 模块路径: `/data/adb/modules/fermata/`

### 文件结构

```
fermata-bpf/
├── .github/workflows/build.yml    # GitHub Actions CI (NDK 交叉编译)
├── fermata_core.bpf.c             # BPF 内核态程序 (tracepoint 钩子)
├── fermata_core.bpf.o             # BPF 字节码 (CI 产物)
├── fermata_core.skel.h            # BPF skeleton 头文件 (CI 产物)
├── fermata_main.cpp               # 用户态守护进程 (C++17)
├── vmlinux_min.h                  # 最小化内核类型定义 (替代 vmlinux.h)
├── build.sh                       # 手机 Termux 一键编译+部署
├── compile.sh                     # 手机 Termux 快速重编译 (仅守护进程)
├── fermata_ebpf                   # 最终产物: arm64 静态守护进程
└── CHANGELOG.md                   # 本文件
```

---

## BPF 内核态 (fermata_core.bpf.c)

### 挂载点

| tracepoint | 作用 |
|---|---|
| `sched/sched_process_exit` | 进程退出时通过 ringbuf 通知用户态清理状态 |
| `sched/sched_switch` | 每次调度切换时记录进程 CPU 运行时间 |

### BPF Maps

| Map 名 | 类型 | Key | Value | 用途 |
|---|---|---|---|---|
| `exit_events` | `BPF_MAP_TYPE_RINGBUF` | — | `struct exit_event` (32bit pid) | 进程退出事件队列 |
| `cpu_time` | `BPF_MAP_TYPE_PERCPU_HASH` | `u32` (pid) | `u64` (CPU ns) | 每进程累计 CPU 时间 |
| `run_start` | `BPF_MAP_TYPE_PERCPU_HASH` | `u32` (pid) | `u64` (timestamp ns) | 记录进程开始运行时间戳 |

### 编译参数

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c fermata_core.bpf.c -o fermata_core.bpf.o
```

`-g` 必须保留，BPF CO-RE 的 `__attribute__((preserve_access_index))` 依赖 BTF 调试信息。

---

## Bionic/Android 兼容性修复

Android NDK/Bionic libc 与 glibc 存在差异，`fermata_main.cpp` 做了以下适配:

### 1. `struct sysinfo` 不公开

Bionic `<sys/sysinfo.h>` 声明了 `sysinfo()` 函数但不公开结构体定义。
改用内核布局自定义结构体 `sysinfo_full`，通过强制类型转换调用 `sysinfo()`。

```cpp
struct sysinfo_full {
    long uptime;
    unsigned long loads[3], totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    unsigned short procs, pad;
    unsigned long totalhigh, freehigh;
    unsigned mem_unit;
    char _f[0];
};
// 调用: sysinfo((struct sysinfo*)&si)
```

### 2. `bpf_map_lookup_elem` 被新版 libbpf 移除

libbpf v1.3+ 移除了 `bpf_map_lookup_elem()` 包装函数。
改为直接调用 `syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, ...)` 实现。

```cpp
#include <sys/syscall.h>
static inline int bpf_map_lookup_elem(int fd, const void *key, void *value) {
    union bpf_attr attr = {};
    attr.map_fd = (__u32)fd;
    attr.key = (__u64)(unsigned long)key;
    attr.value = (__u64)(unsigned long)value;
    return syscall(__NR_bpf, 1 /* BPF_MAP_LOOKUP_ELEM */, &attr, sizeof(attr));
}
```

### 3. `<bpf/libbpf.h>` 头文件路径

Termux 编译 libbpf 后不会自动安装 include 目录。需手动创建:

```bash
mkdir -p ~/bpftool/libbpf/include/bpf
cp ~/bpftool/libbpf/src/*.h ~/bpftool/libbpf/include/bpf/
```

编译时使用 `-I$HOME/bpftool/libbpf/include`。

---

## 编译流水线

### 方案 A: GitHub Actions (完整 CI)

**触发**: `git push` 到 main 分支

**流程**:
1. 下载 Android NDK r27c
2. 从源码编译 libelf (elfutils 0.191)
3. 从源码编译 libbpf (git master)
4. clang 编译 BPF 字节码 (`-target bpf`)
5. bpftool 生成 skeleton 头文件
6. NDK clang++ 交叉编译 `fermata_ebpf` (arm64, 静态链接)
7. 上传 artifact

**artifact 内容**: `fermata_ebpf`, `fermata_core.bpf.o`, `fermata_core.skel.h`

**当前状态**: 编译 libelf 步骤因 android NDK sysroot 缺少 `argp` 而失败，待修复。
BPF 字节码和 skeleton 生成步骤可正常工作。

### 方案 B: 手机 Termux 本地编译 (当前主用)

**前置条件**:
- Termux 已安装，执行过 `pkg install clang git make libelf zlib`
- bpftool 源码已 clone 到 `~/bpftool/`
- 源文件已推到 `/sdcard/Download/`

**首次完整编译** (`bash /sdcard/Download/build.sh`):
1. `pkg install` 安装依赖 (clang, git, make, libelf, zlib)
2. `git clone --recurse-submodules` bpftool
3. `make` 编译 libbpf.a
4. 创建 include 目录
5. `clang++` 编译守护进程
6. `su -c cp` 部署到 Magisk 模块目录

**日常快速重编译** (`bash /sdcard/Download/compile.sh`):
1. `make clean && CFLAGS=... make` 重编 libbpf.a (LTO 优化)
2. `clang++` 编译守护进程

**编译参数 (守护进程)**:
```bash
clang++ -std=c++17 -Os -s -flto \
    -fdata-sections -ffunction-sections \
    -Wl,--gc-sections -Wl,--strip-all \
    -I$H/bpftool/libbpf/include \
    fermata_main.cpp \
    $H/bpftool/libbpf/src/libbpf.a \
    -lelf -lz \
    -o fermata_ebpf
```

**libbpf.a 编译参数**:
```bash
CFLAGS="-Os -flto -fdata-sections -ffunction-sections" AR=llvm-ar make -j4
```

注意: `AR=llvm-ar` 是 LTO 生效的关键，GNU ar 无法正确处理 LLVM bitcode。

### 体积优化效果

| 阶段 | 大小 | 优化措施 |
|---|---|---|
| 初始 | 406 KB | `-O2` |
| 第一轮 | 377 KB | `-Os -flto -fdata-sections -ffunction-sections -Wl,--gc-sections` (仅守护进程) |
| 第二轮 | 379 KB | 新增配置参数逻辑，抵消了部分优化 |
| 第三轮 | 252 KB | libbpf.a 也 `-Os -flto` + `AR=llvm-ar` + `make clean` 强制重编 |

**总共压缩 38%** (406KB → 252KB)

---

## 配置项 (fermata.conf)

配置文件路径: `/data/adb/modules/fermata/fermata.conf`

| 键 | 默认值 | 说明 |
|---|---|---|
| `whitelist` | — | 逗号分隔的白名单进程名 |
| `freeze_delay` | 1 | 进程进入缓存后延迟多少周期冻结 |
| `scan_ms` | 3000 | 主循环扫描间隔 (ms) |
| `idle_ms` | 8000 | 空闲态扫描间隔 (ms) |
| `mem_low` | 2000 | 低内存阈值 (MB) |
| `mem_mid` | 4000 | 中内存阈值 (MB) |
| `tombstone_max` | 1 | 墓碑计数上限 |
| `frz_cooldown` | 5 | 冻结冷却时间 (秒) |
| `pri_cooldown` | 8 | 设置优先级冷却时间 (秒) |
| `cache_refresh` | 60 | 缓存刷新周期数 |
| `cpu_abuse_pct` | 5 | CPU 滥用百分比阈值 |
| `cpu_abuse_cnt` | 3 | CPU 滥用连续计数阈值 |
| `debug_log` | 0 | 调试日志开关 |

---

## 部署流程

```bash
# 1. 编译产物传到手机
adb push fermata_ebpf /sdcard/Download/

# 2. 替换并重启服务 (通过 Termux 或 adb root)
su -c "cp /sdcard/Download/fermata_ebpf /data/adb/modules/fermata/fermata"
su -c "chmod 755 /data/adb/modules/fermata/fermata"
su -c "killall fermata 2>/dev/null; sleep 1"
su -c "/data/adb/modules/fermata/service.sh"

# 3. 查看日志
cat /data/adb/modules/fermata/log/fermata.log
```

---

## 调试

```bash
# 开启 debug 日志
echo "debug_log=1" >> /data/adb/modules/fermata/fermata.conf

# 查看 eBPF 程序加载状态
cat /sys/kernel/debug/tracing/trace_pipe

# 检查 BPF maps
ls -la /sys/fs/bpf/

# 查看进程冻结状态
cat /sys/fs/cgroup/*/cgroup.events | grep frozen
```

---

## 已知问题

1. **GitHub Actions NDK 构建**: libelf 交叉编译失败 (`argp_parse` 缺失)，需补充 argp 兼容层或改用预编译包
2. **bpftool 不能直接在 Termux 编译**: Bionic 头文件冲突 + `qsort_r` 缺失，规避方案是 CI 生成 skeleton + 手机只编译守护进程
3. **SELinux Enforcing**: 部分 `/proc` 路径可能被限制访问，需确认 Magisk 模块有正确 SELinux 上下文
