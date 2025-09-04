<p align="center">

  <img src="images/minnka.png" width="250">

</p>

An exploit for the Mali Utgard GPU kernel driver for Linux kernel version 3.18.35. The bug it leverages was discovered on version *r6p2* of the driver, but it likely impacts later versions, I just don't have a device to test.

**Note:** To use this on other devices/kernels, compatiblity will need to be checked as the bug may be at a different offset to my device, meaning the `/dev/ion` exploit method used here will not work. Also some hardcoded offsets will need to be updated for your kernel.

## Blogs

[[0] Dumping Filesystem + Unlocking ADB Shell](https://luke-m.xyz/translator/p1.md)

[[1] Looking at Drivers, Rediscovering CVE-2022-34830](https://luke-m.xyz/translator/p2.md)

[[2] Finding Other Bugs in mali Driver](https://luke-m.xyz/translator/p3.md)

[[3] 2 Drivers, 1 Exploit](https://luke-m.xyz/translator/p4.md)

## Building/Running

Easiest with an Android NDK with pre-built toolchains:
- `./android-ndk-r21e/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi24-clang minnka.c -o minnka`
- `adb push minnka /data/local/tmp`
- `adb shell /data/local/tmp/minnka`

## Example Run


<img src="images/minnka.gif" width="720">