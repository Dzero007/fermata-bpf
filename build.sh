#!/data/data/com.termux/files/usr/bin/bash
# Fermata eBPF 一键编译脚本 (在 Termux 中运行)

set -ex
H=/data/data/com.termux/files/home

echo "=== 1/4 安装依赖 ==="
pkg install -y clang git make libelf zlib

echo "=== 2/4 编译 libbpf.a (体积优化) ==="
cd $H
rm -rf bpftool
git clone --depth 1 --recurse-submodules https://github.com/libbpf/bpftool
cd bpftool/libbpf/src
CFLAGS="-Os -flto -fdata-sections -ffunction-sections" make -j4
mkdir -p $H/bpftool/libbpf/include/bpf
cp $H/bpftool/libbpf/src/*.h $H/bpftool/libbpf/include/bpf/

echo "=== 3/4 编译守护进程 ==="
su -c "rm -f $H/fermata_main.cpp $H/fermata_core.skel.h" 2>/dev/null
rm -f $H/fermata_main.cpp $H/fermata_core.skel.h
cp /sdcard/Download/fermata_main.cpp $H/
cp /sdcard/Download/fermata_core.skel.h $H/
test -f $H/fermata_core.skel.h || { echo "!!! 缺少 skel.h"; exit 1; }
cd $H
clang++ -std=c++17 -Os -s -flto \
    -fdata-sections -ffunction-sections \
    -Wl,--gc-sections -Wl,--strip-all \
    -I$H/bpftool/libbpf/include \
    fermata_main.cpp \
    $H/bpftool/libbpf/src/libbpf.a \
    -lelf -lz \
    -o fermata_ebpf

echo "=== 4/4 部署 ==="
su -c "cp $H/fermata_ebpf /data/adb/modules/fermata/fermata"
su -c "chmod 755 /data/adb/modules/fermata/fermata"
su -c "killall fermata 2>/dev/null; sleep 1; /data/adb/modules/fermata/service.sh"

echo "=== 完成 ==="
file $H/fermata_ebpf
echo "日志: cat /data/adb/modules/fermata/log/fermata.log"
