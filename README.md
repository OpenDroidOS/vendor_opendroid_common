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

`manifests/opendroid.xml` selects the shared repositories and maintained
OpenDroidOS platform forks. Use it with OpenHarmony `weekly_20261026`:

```sh
mkdir -p .repo/local_manifests
curl -fL https://raw.githubusercontent.com/OpenDroidOS/vendor_opendroid_common/opendroid-7.0/manifests/opendroid.xml \
  -o .repo/local_manifests/opendroid.xml
repo sync -c -j8
```

Run these commands from the source root while no build or sync is running.
Keep other local manifests from declaring the same projects. Board, kernel
and device vendor repositories are cloned or created separately by the porter.
After updating this repository, copy the manifest again before the next sync
to pick up changes to the project list.
