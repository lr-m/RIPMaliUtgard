<p align="center">

  <img src="images/logo.jpg" width="250">

</p>

Exploits for a forever-day use-after-free in the Mali Utgard GPU kernel driver. The bug it leverages was discovered on version *r6p2* of the driver, but it likely impacts later versions.

**Note:** To use these on other devices/kernels, compatiblity will need to be checked as the bug may be at a different offset to my device, I'll give as much detail about the specifics of the device I wrote the exploit for where possible.

## Blogs

[[0] Dumping Filesystem + Unlocking ADB Shell](https://luke-m.xyz/translator/p1.md)

[[1] Looking at Drivers, Rediscovering CVE-2022-34830](https://luke-m.xyz/translator/p2.md)

[[2] Finding Other Bugs in mali Driver](https://luke-m.xyz/translator/p3.md)

[[3] 2 Drivers, 1 Exploit](https://luke-m.xyz/translator/p4.md)

[[5] Should be an Easy Port, Right?](https://luke-m.xyz/translator/p6.md)

## Building/Running

Easiest with an Android NDK with pre-built toolchains, here is `minnka` for example:
- `./android-ndk-r21e/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi24-clang minnka.c -o minnka`
- `adb push minnka /data/local/tmp`
- `adb shell /data/local/tmp/minnka`


## Minnka

This is an exploit I wrote for the T11 translator, it works by attacking the `sg_table` pointer in an `ion_buffer` that gets allocated in place of the free'd `mali_alloc` object. This lets you map arbitrary physical memory to userland and escalate privileges to root.

### Device Specifics According to Settings

| Property | Value |
| - | - |
| Model number | T11/T16 |
| Android version | 7.0 |
| Kernel version | 3.18.35 |
| Build number | `K8321_V1.0.0_20240509` |

### Example Run

<img src="images/minnka.gif" width="720">

## Frels

This is an exploit I wrote for the Soyes XS11, the `ion_buffer` method didn't work, so I used the UAF to free the same `mali_alloc` memory twice (and then holding it to prevent a double free), the second time with a completely controlled fake `mali_alloc` letting me get a write in the kernel and escalate privileges to root.

### Device Specifics According to Settings

| Property | Value |
| - | - |
| Model number | XS11 |
| Android version | 6.0 |
| Kernel version | 3.18.19 |
| Build number | `A28C_T8_welcome-EN-G_V2_GSL2038_2_20230711` |

### Example Run

<img src="images/frels.gif" width="720">

