# Qualcomm device integration

OpenHarmony product selection, hardware implementations and bootloader inputs
are separate contracts. Adding an HDI component builds its interfaces and common
code. A usable hardware path also needs a selected implementation, its kernel
interface, installation, startup, access policy and required firmware.

## Source ownership

| Area | Content |
| --- | --- |
| Shared Qualcomm adaptation | Reusable Linux/Qualcomm providers, allocator/composer contracts, build glue and common kernel requirements. Keep SoC and board constants out of shared implementations. |
| SoC configuration | Architecture, selected controller families and provider dependencies for the actual SoC/kernel interface. |
| Board tree | Panel, touch, audio routing, accessory and sensor wiring; init, permissions, HDF configuration and board-specific choices. |
| Kernel tree | Source/config or an explicitly selected Image/config, matching module inputs, DT/DTBO and module deployment. |
| Vendor/product tree | Product component and feature selection, parameters, service configuration, image configuration and selected private inputs. |

An OpenHarmony vendor repository can contain product source and hardware
configuration. It is not restricted to generated proprietary-file lists.
Hardware providers can live in SoC/vendor source and be built through native GN
targets. HCS describes HDF deployment; it does not replace kernel DTS/DTB or
supply an unimplemented driver.

## Stock inputs

Keep three classes distinct:

- Kernel modules must match the selected kernel's ABI, symbol versions,
  namespaces and signature policy. Module names and release labels alone do
  not prove compatibility. Resolve hard and soft dependencies and early probe
  requirements before generating load order.
- Firmware is data consumed by kernel drivers or remote processors. Bind it
  to the controller/driver and expected lookup path. A firmware entry in module
  metadata is useful evidence but is not a complete inventory of dynamic
  firmware requests.
- Android userspace HAL libraries require their Bionic dependencies, loader
  namespaces, service protocols and platform interfaces. They cannot simply be
  renamed to native OpenHarmony provider filenames. Selecting a compatibility
  environment is an architectural decision with its own dependency closure.

Use native implementations over existing Linux interfaces where the actual
driver contract permits it. Open-source graphics support still depends on the
exact GPU, kernel backend, allocation, buffer layout and synchronization path.
Mesa's Zink driver requires a Vulkan implementation; it does not supply one.
See [Mesa Zink](https://docs.mesa3d.org/drivers/zink.html) and
[Freedreno](https://docs.mesa3d.org/drivers/freedreno.html).

## Core subsystem contracts

| Subsystem | Required integration |
| --- | --- |
| Storage and init | Controller/PHY clocks and regulators; early module and DT inputs; logical-device mapping; root/vendor mounts; kernel arguments and native first-stage init. |
| USB diagnostics | Controller/PHY and role switching; configfs/FunctionFS gadget setup; HDC endpoint ownership and policy. |
| Input | Kernel event devices, libinput classification, touch/pen coordinate transforms, hotplug and accessory events. |
| Display and graphics | Allocation/import/export, format/modifier agreement, fences/cache synchronization, composer/scanout and an actual EGL/GLES/Vulkan renderer. |
| Audio | DSP/firmware and ALSA interfaces, mixer topology, routing, stream timing, capture/playback and HDI implementation. |
| Wi-Fi/Bluetooth | Bus/controller modules, firmware/calibration, native control interface, supplicant/HCI transport and service permissions. |
| Power/thermal/battery | Correct sysfs units and notifications, charging controls, thermal sensors/cooling policy, suspend/wake and reported hardware values. |
| Sensors/haptics/lights | Physical input/IIO/sysfs or vendor protocol, calibration, timestamps, batching/notifications and matching HDI services. |
| Media/camera | Codec/ISP kernel interfaces, firmware, buffer and fence compatibility, capabilities, tuning and provider lifetime. |
| Security/storage services | Binder and caller identity, access tokens, SELinux, entropy, key storage and encryption interfaces required by the product. |

Libraries found by dependency inspection may be linked dependencies or optional
runtime loader alternatives. Trace the selected source branch before changing
packaging or validation. A filename-only substitute is not a hardware provider.

## Boot and partition layout

Read the target's actual boot-chain inputs. Boot header v4, vendor ramdisk tables,
DTB, bootconfig, init_boot and recovery have independent roles. Preserve the
observed division rather than inferring it from Android version or SoC name.
[AOSP boot headers](https://source.android.com/docs/core/architecture/bootloader/boot-image-header).

Maintain one mapping from each OpenHarmony filesystem role to its actual
physical or logical partition, slot, mount point and byte budget. Logical
partitions also need complete group accounting, super metadata and recovery
mapping/update support. A sparse image's expanded byte size is the relevant
capacity check. A debug filesystem construction allowance is not a physical
partition declaration.

An unused Android OS partition can be preserved, removed from a selected logical
layout, or replaced with a valid filesystem image when that is required. Each is
a different operation. A zero-length image does not create an empty filesystem;
omitting an image does not delete the existing partition. Preserve firmware,
bootloader, calibration and device-unique data unless a separate operation
explicitly requires them.

## AVB and recovery packages

Boot header version and AVB flags are independent. Development verification
disable belongs to the top-level vbmeta policy. Chained vbmeta headers have zero
flags and zero rollback-index location; the parent chain descriptor supplies
the child's location and public key. Resolve the actual chain rather than
creating conventional filenames that the board does not use.
[AOSP AVB header](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/libavb/avb_vbmeta_image.h).

OpenHarmony recovery supports native signed ZIP packages. Its scripts,
`updater_binary` invocation and package certificate are different from an Android
recovery update ZIP. Reuse the native packaging tools and install the selected
partition map in recovery. A package signature trusted by recovery and AVB's
development policy solve different checks.

Validate source/component selection, compiled targets, installed files, final
filesystem contents, boot/update containers and hardware behavior separately.
Keep input provenance and per-device results outside reusable public source.
