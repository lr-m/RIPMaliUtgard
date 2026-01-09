<p align="center">

  <img src="images/logo.jpg" width="300">

</p>

Exploits for a forever-day use-after-free in the ARM Mali Utgard GPU kernel driver (only devices that use the open-source ARM driver that used to be on their website). The bug it leverages was discovered on version *r6p2* of the driver (but impacts other versions as well).

**Known vulnerable devices:**
- MT6580-based devices (T11 translator, Soyes XS11, Doogee X5. Blackview A60)
- Kirin 620-based devices (Huawei P8 Lite)
- Any device with a Mali Utgard GPU that uses the ARM driver

**Known safe devices (tested):**
- Samsung devices with a Mali Utgard GPU (S3, S3 Mini, S5 Mini, Star, etc) - Necessary ioctl commands don't exist
- Amazon Kindle Fire 7th Gen (MT8127) - Necessary ioctl commands don't exist
- Sony Xperia E4 - Necessary ioctl commands don't exist

**Note:** To use these on other devices/kernels, compatibility will need to be checked as the bug may be present but a lot of work might be needed to get root, this collection of exploits should be a good reference to work with.

## Blogs

[[0] Dumping Filesystem + Unlocking ADB Shell](https://luke-m.xyz/translator/p1.md)

[[1] Looking at Drivers, Rediscovering CVE-2022-34830](https://luke-m.xyz/translator/p2.md)

[[2] Finding Other Bugs in mali Driver](https://luke-m.xyz/translator/p3.md)

[[3] 2 Drivers, 1 Exploit](https://luke-m.xyz/translator/p4.md)

[[5] Should be an Easy Port, Right?](https://luke-m.xyz/translator/p6.md)

[[6] Three More Exploits](https://luke-m.xyz/translator/p7.md)

## Building/Running

Easiest with an Android NDK with pre-built toolchains, here is a `minnka` example for a 32-bit chipset (like the MT6580):
- `./android-ndk-r21e/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi24-clang minnka_t11_translator.c -o minnka -static`
- `adb push minnka /data/local/tmp`
- `adb shell /data/local/tmp/minnka`

And `frels` for a 64-bit chipset (like the Kirin 620):
- `android-ndk-r21e-linux-x86_64/android-ndk-r21e/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang frels_huawei_p8_lite.c -o frels -static`
- `adb push frels /data/local/tmp`
- `adb shell /data/local/tmp/frels`


## Minnka - T11 Translator

This is an exploit I wrote for the T11 translator, it works by attacking the `sg_table` pointer in an `ion_buffer` that gets allocated in place of the free'd `mali_alloc` object. This lets you map arbitrary physical memory to userland and escalate privileges to root.

<img src="images/t11_translator.png" width="150">

### Device Specifics According to Settings

| Property | Value |
| - | - |
| Model number | T11/T16 |
| Chipset | MT6580 |
| GPU | ARM Mali-400 MP |
| Android version | 7.0 |
| Kernel version | 3.18.35 |
| Build number | `K8321_V1.0.0_20240509` |
| SELinux | No |

### Example Run

<img src="images/minnka_t11_translator.gif" width="720">

## Frels - Soyes XS11

This is an exploit I wrote for the Soyes XS11, the `ion_buffer` method didn't work, so I used the UAF to free the same `mali_alloc` memory twice (and then holding it to prevent a double free), the second time with a completely controlled fake `mali_alloc` letting me get a write in the kernel and escalate privileges to root.

<img src="images/soyes_xs11.png" width="250">

### Device Specifics According to Settings

| Property | Value |
| - | - |
| Model number | XS11 |
| Chipset | MT6580 |
| GPU | ARM Mali-400 MP |
| Android version | 6.0 |
| Kernel version | 3.18.19 |
| Build number | `A28C_T8_welcome-EN-G_V2_GSL2038_2_20230711` |
| SELinux | No |

### Example Run

<img src="images/frels_soyes_xs11.gif" width="720">

## Frels - Huawei P8 Lite

This device runs a 64-bit Kirin 620 which also has the bug. This is basically the same exploit as the XS11, but using `add_key` for spraying fake `mali_alloc` objects, and fixing the freelist in the JOP-chain. This device has SELinux, but that is easily bypassed by setting the `enforcing` global in the JOP-chain.

<img src="images/p8_lite.png" width="150">

### Device Specifics According to Settings

| Property | Value |
| - | - |
| Model number | ALE-L21 |
| Chipset | Kirin 620 |
| GPU | ARM Mali-450 MP4 |
| Android version | 6.0 |
| EMUI version | 4.0 |
| Kernel version | 3.10.86-g6a5da10 |
| Build number | `ALE-L21C432B560` |
| SELinux | Yes |

### Example Run

<img src="images/frels_p8_lite.gif" width="720">

## Frels - Doogee X5

Basically identical exploit to the Huawei P8 Lite, using `add_key` for the spray and fixing the freelist in the JOP-chain, decent reliability.

<img src="images/doogee_x5.png" width="250">

### Device Specifics According to Settings

| Property | Value |
| - | - |
| Model number | X5 |
| Chipset | MT6580 |
| GPU | ARM Mali-400 MP |
| Android version | 6.0 |
| Kernel version | 3.18.19 |
| Build number | `DOOGEE-X5-Android6.0-20170904` |
| SELinux | Yes |

### Example Run

<img src="images/frels_doogee_x5.gif" width="720">

## Frels - Blackview A60

This is one of the more 'modern' MT6580-based devices, I wanted to see if it was easy enough to port these exploits to a later Android version (in this case, 8.1.0). Annoyingly, a decent amount has changed, kernel code is no longer writeable by the kernel (so no longer trivial to overwrite fop pointers in drivers), and userland memory is no longer accessible from kernel (or executable of course, but we already encountered that). 

There is also an annoying change in the driver on this device, they seem to have patched some race condition by adding some extra checks/object tracking, which avoids a UAF, but luckily it is super easy to work around - you just have to do an extra allocation to render their check ineffective and hit this bug.

Despite this, I ended up needing another bug as the existing 'patch function pointer in fop table' no longer works as kernel code isn't writeable. Luckily I had a Mediatek bug in my back pocket which lets me leak data from the kernel. This let me leak `/proc/driver/wmt_aee`'s `proc_dir_entry` address, letting me locate the fop handlers and therefore the address of the `open` handler, this gives me code execution. To get memory in a known place for the JOP-chain, I just allocated an ion buffer of about 500mb and filled it with the JOP-chain, due to lack of kASLR, I was able to just 'guess' a pointer that might have the controlled data in it, and most of the time it does!

This exploit is kinda reliable, you need both the ion spray to work, and the UAF to land - but it can be leveraged to get root! However, when it comes to MT6580, I think this is as 'modern' as it gets.

<img src="images/blackview_a60.png" width="200">

### Device Specifics According to Settings

| Property | Value |
| - | - |
| Model number | A60 |
| Chipset | MT6580 |
| GPU | ARM Mali-400 MP |
| Android version | GO (8.1.0) |
| Kernel version | 3.18.79+ |
| Build number | `A60_W168_EEA_V1.0_20201123V23` |
| SELinux | Yes |

### Example Run

<img src="images/frels_blackview_a60.gif" width="720">
