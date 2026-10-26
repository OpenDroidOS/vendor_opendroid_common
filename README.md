# OpenDroid common configuration

Shared OpenHarmony product components, distribution parameters and prebuilt staging tools.

`scripts/stage_kernel.py --prepare` writes a private GN selection description. Set
`opendroid_kernel_selection` to that file. Staging rechecks descriptors, selected
file hashes and kernel configuration before publishing outputs.

Tablet products inherit `tablet.json` after `productdefine/common/inherit/tablet.json`.
