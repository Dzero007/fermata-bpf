#!/data/data/com.termux/files/usr/bin/bash
H=/data/data/com.termux/files/home

echo "=== 1/2 重编 libbpf.a (体积优化) ==="
cd $H/bpftool/libbpf/src
make clean 2>/dev/null
CFLAGS="-Os -flto -fdata-sections -ffunction-sections" AR=llvm-ar make -j4
mkdir -p $H/bpftool/libbpf/include/bpf
cp $H/bpftool/libbpf/src/*.h $H/bpftool/libbpf/include/bpf/

echo "=== 2/2 编译守护进程 ==="
cp /sdcard/Download/fermata_main.cpp $H/
cd $H
clang++ -std=c++17 -Os -s -flto \
    -fdata-sections -ffunction-sections \
    -Wl,--gc-sections -Wl,--strip-all \
    -I$H/bpftool/libbpf/include \
    fermata_main.cpp \
    $H/bpftool/libbpf/src/libbpf.a \
    -lelf -lz \
    -o fermata_ebpf

echo "=== 编译完成 ==="
ls -lh fermata_ebpf
