# OpenDroid common configuration

Shared OpenHarmony product components, distribution parameters and prebuilt staging tools.

`scripts/stage_kernel.py --prepare` writes a private GN selection description. Set
`opendroid_kernel_selection` to that file. Staging rechecks descriptors, selected
file hashes and kernel configuration before publishing outputs.

`product-features.json` defines typed Boolean `product_features` choices.
`safwk_run_on_demand_qos` defaults to false; true enables SAFWK's run-on-demand
start QoS priority adjustment. `hitrace_executable` defaults to true; true builds
Hitrace command-line tools when `support_jsapi` is enabled, while false omits them.
For example, use `{"product_features": {"safwk_run_on_demand_qos": true, "hitrace_executable": false}}`
in the device input. Omitted choices use these shared defaults. Choices require
their native component to be selected and do not establish provider or hardware
support. If a shared default would replace additional inherited feature
assignments or component metadata, generation requires an explicit choice for
that component; the override preserves that data.

Tablet products inherit `tablet.json` after `productdefine/common/inherit/tablet.json`.

Source synchronization is configured by
[OpenDroidOS/manifest](https://github.com/OpenDroidOS/manifest), using the
`opendroid-7.0` branch. Board, kernel and device vendor repositories are cloned
or created separately by the porter.
