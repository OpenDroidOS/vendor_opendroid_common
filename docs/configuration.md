# Common product configuration

## Product inheritance

Phone and tablet products select their OpenHarmony component set through the
device product's `base_product` input. The generator then adds `base.json` for
shared OpenDroidOS settings. Device-specific selections stay in the product's
`vendor/<company>/<product>/config.json`.

`system_profile: "base"` uses that component set directly. The optional `tablet`
profile also inherits OpenHarmony's `productdefine/common/inherit/tablet.json`,
followed by this repository's `tablet.json` for its build dependencies and
component overrides. This profile controls component selection; it does not
describe hardware compatibility.

## Feature options

Set `product_features` in the tree generator's device input. Omitted options use
the defaults in [product-features.json](../product-features.json).

| Option | Default | Effect when enabled |
| --- | --- | --- |
| `safwk_run_on_demand_qos` | `false` | Enable SAFWK's run-on-demand start QoS priority adjustment. |
| `hitrace_executable` | `true` | Build Hitrace command-line tools when `support_jsapi` is enabled. |

For example:

```json
{
  "product_features": {
    "safwk_run_on_demand_qos": true,
    "hitrace_executable": false
  }
}
```

Each option requires its native component to be selected. If applying a shared
default would replace additional inherited feature assignments or component
metadata, the generator requires an explicit choice and preserves that data
in the generated override.

## Prebuilt kernel setup

The device kernel repository supplies its prebuilt manifest, kernel requirements
and optional module load order. Its README provides the preparation command.

Run [scripts/stage_kernel.py](../scripts/stage_kernel.py) with `--prepare` to
validate those inputs and write a selection file outside the source checkout.
Pass its path to the build as the GN argument `opendroid_kernel_selection`.
Prepare a new selection after changing inputs or their paths. The build's
staging step revalidates the selected files and kernel requirements before
copying outputs. Run the script with `--help` for its arguments.


## Modules needed before root mounts

Kernel targets can import `kernel_modules.gni` and use
`opendroid_kernel_modules` with their prepared `selection`, `stage_dir`,
`stage_dep`, `part_name` and `subsystem_name`. The staging dependency must
validate that same immutable selection with `stage_kernel.py` before any
installed copy. Module bytes retain the existing vendor installation.

The selection's `module_load_order` additionally installs those modules and
ordered `/lib/modules/modules.load` and `/lib/modules/modules.load.ohos` files in
the native boot and updater/recovery ramdisks. Native init prefers the latter,
so appending a vendor ramdisk cannot replace its selection with a vendor list.
The conventional filename remains available to preceding init stages. Basenames must
be unique, contain only letters, digits, underscore or hyphen, and end in
`.ko`. Other modules stay out of the ramdisk. An empty order adds no ramdisk
payload. Prepare the selection with the intended `--module-order` file; its
path and hash are part of the selection, not inferred from a source default.

For products using this list, select the native init hook with the existing
`init_extra_static_modules` feature, pointing to
`//base/startup/init/services/modules/early_modules:early_modules`. If another
static extension is already selected, use a group containing both targets.
The hook runs before updater-mode dispatch, root discovery and required mounts. It uses normal
kernel module checks and stops early init if a required module cannot load.

Choose an explicit dependency-ordered set that matches the kernel, DT and
firmware. Staging hashes, a native link and module ABI audits alone do not
prove that a controller will probe or that the device will boot.

## Firmware needed during early probe

A selected kernel manifest can include explicit `firmware` records. Stage their
destinations below `kernel/firmware/`, preserving the filename or relative path
requested by the driver. Each record uses the same source-path and SHA256 checks
as the other selected files. Firmware selection also requires
`CONFIG_FW_LOADER=y`; it does not establish that the payload matches the device.

`opendroid_kernel_modules` installs those files in `/lib/firmware` in both native
boot and recovery ramdisks, and in `/vendor/firmware` for the normal system.
Subdirectories are preserved. This makes explicitly selected firmware available
before required root mounts and module probes. No firmware is selected, obtained,
renamed or redistributed by default. Keep stock payloads and their provenance
outside public source repositories, and verify the kernel, driver and device
contract before selecting them.
