# Image builds and recovery packages

The common vendor build entry runs OpenHarmony's normal image build, waits for
its post-build checks, then produces a native signed recovery ZIP. Packaging,
signing and AVB utilities live here; tree generation stays in opendroid-treegen.

Generate a signing identity outside the source checkout:

```sh
python3 vendor/opendroid/common/tools/device-packager/generate_keys.py \
  --output "$HOME/.local/share/device-signing/example" --common-name "Example development"
export OPENDROID_PACKAGE_KEY="$HOME/.local/share/device-signing/example/package-key.pem"
export OPENDROID_PACKAGE_CERT="$HOME/.local/share/device-signing/example/package-cert.pem"
```

Every developer generates and retains their own private key. The helper refuses
existing output directories and source repositories; no test or shared key is
selected by the build. The private PEM is unencrypted for unattended local
builds and created with owner-only permissions. Keep it protected and retain it
for later updates. AVB keys are separate inputs to the selected boot trust chain.

The product supplies a partition manifest and a matching native `fstab.updater`.
Use measured capacities, actual slot mappings and recovery-supported logical
devices. See [native package inputs](../tools/device-packager/README.md) and
[Qualcomm integration](qualcomm-integration.md). Images in the manifest can point
to their eventual output paths; they are read only after the native build passes.

```sh
python3 vendor/opendroid/common/build.py \
  --source-root "$PWD" --out-dir "$PWD/out/example" \
  --manifest vendor/example/device/installation.json \
  --recovery-fstab vendor/example/device/fstab.updater \
  -- --product-name device@example --build-target images --ninja-args=-j16
```

Use `--signing-key` and `--certificate` instead of environment variables when
desired. The same Python environment needs `xmltodict`, `asn1crypto` and
`cryptography`. The selected native packager must support version 3 for large
components. Boot/AVB image assembly remains part of the board's selected image
targets and requires its actual keys and partition layout.

The entry selects the public certificate and recovery partition map through GN;
the common product target installs them in recovery. The private key is only
read by the package signer. After build success it reads the actual updater
ramdisk and checks those installed files against the selection. It then checks
the package mapping, signatures, hash tables and payload bytes before replacing
`out/<product>/packages/phone/update/updater_sd.zip`. One final ZIP is retained.
Failed packaging retains its working directory and leaves the last verified ZIP
in place. Check the command's exit status before using an artifact.

Use this vendor entry for automatic packaging. It forwards native build
arguments after `--`; partial targets, GN-only builds and Ninja dry runs are
rejected. No second manual pack command is needed after a successful image build.
The entry does not install or flash anything.
