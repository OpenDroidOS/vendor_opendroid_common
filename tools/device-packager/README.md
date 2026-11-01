# Native update package preparation

Prepare image inputs for OpenHarmony's existing signed update ZIP format:

```sh
python3 vendor/opendroid/common/tools/device-packager/package.py inspect --manifest installation.json --output plan.json
python3 vendor/opendroid/common/tools/device-packager/package.py prepare --manifest installation.json \
  --updater-binary out/product/updater/updater/updater_binary --output prepared
python3 vendor/opendroid/common/tools/device-packager/package.py build --manifest installation.json \
  --updater-binary out/product/updater/updater/updater_binary \
  --packaging-tools base/update/packaging_tools \
  --signing-key /path/to/private/key.pem --certificate /path/to/public/cert.pem \
  --output package-build
```

The plan declares board identifiers, product/version, slot, logical groups and
each OS partition's write or preserve operation. Supply measured byte budgets
and explicit block-device paths. No board geometry or unused partition image is
inferred. Android sparse images are checked against their expanded size during
inspection; preparation currently accepts raw images only.

```json
{
  "format_version": 1,
  "boards": ["example"],
  "product_id": "example",
  "version": "1.0",
  "slot": "a",
  "logical_backend": "existing-mappers",
  "groups": {"os_a": 1073741824},
  "partitions": [
    {
      "name": "system",
      "operation": "write",
      "kind": "logical",
      "group": "os_a",
      "capacity_bytes": 536870912,
      "block_device": "/dev/block/mapper/system_a",
      "image": "system.img"
    },
    {
      "name": "system_ext",
      "operation": "preserve",
      "kind": "logical",
      "group": "os_a",
      "capacity_bytes": 536870912,
      "block_device": "/dev/block/mapper/system_ext_a",
      "image": null
    }
  ]
}
```

Example sizes are illustrative. Include preserved logical allocations when
accounting for group capacity. This is not a super metadata editor: logical
devices must already be mapped by the selected recovery. `preserve` performs no
write and does not delete a partition. Do not turn physical repartition commands
into Android logical partition operations. Firmware, calibration, bootloader and
userdata writes are excluded from this OS package frontend.

Preparation writes native `updater_specified_config.xml`, `BOARD.list`,
`VERSION.mbn`, a partition report and a proposed `fstab.updater`. Image and updater
binary inputs are symlinked into the target directory, without copying their
data. Integrate the fstab into the board recovery and verify its slot/mapping
behavior before installation. Keep these prepared files outside public source.

OpenHarmony's `base/update/packaging_tools/build_update.py` consumes that target
directory and creates `updater_sd.zip` containing `update.bin` and `build_tools.zip`.
Its embedded `updater_binary`, native scripts and signed hash data are consumed
by OpenHarmony recovery. An Android `META-INF/.../update-binary` ZIP has a
different installer contract. Package signing certificates must match recovery's
trusted certificate; AVB development flags do not disable package verification.

`build` invokes the selected native packager in a new output directory, leaving
its source and signing inputs in place. It requires the packager's Python
dependencies (`xmltodict`, `asn1crypto`, `cryptography`); use `--python` to select
an environment containing them. Full native packaging currently uses RSA-2048.
The frontend checks that the certificate matches the key, then verifies the
produced ZIP's data CRCs, native entries, certificate and outer signature, then
matches component headers and streamed payload hashes to the prepared inputs.
It selects native SD-card packaging, which includes the block-hash tables
required by recovery's SD-card and USB install modes. The frontend verifies
those ranges, block digests and signed package header. Recovery's embedded tool
checks and actual installation remain separate.
Only explicit signing inputs are accepted; there is no bundled default key.

Packages default to native file version 2, whose Python encoder uses signed
32-bit component sizes. Preparation rejects components above 2 GiB with that
version. Select `--package-version 3` for larger raw images and use a native
packager with 64-bit component sizes and hash ranges. Recovery must support
version 3. The frontend checks the emitted version, component sizes and payloads.

The maintained native encoder reads full-package inputs in bounded blocks and
keeps the original image files in place. It still creates a temporary uncompressed
`update.bin` alongside the compressed ZIP. Budget disk space for both; ZIP
compression does not reduce a filesystem's expanded partition requirement.
Temporary files use the output directory's disk-backed `tmp`. A failed run
retains its log and prepared inputs. Native streaming-update mode is a separate
format and is not selected by `--package-version`.

Boot/header v3/v4 checks are independent of AVB. AVB images require complete AVB0
headers; chained images must have zero header flags and rollback-index location.
The top-level development policy and chain descriptors/keys require a separate
AVB graph validation. A zero-length file is rejected; an unused filesystem
partition needs either an explicit preserve/delete policy or a real filesystem
image of the selected format. Final filesystem contents and device boot are
separate from static package preparation.

## AVB images

```sh
python3 vendor/opendroid/common/tools/device-packager/avb_bundle.py --manifest avb.json --avbtool /path/to/avbtool \
  --output-dir avb-images --disable-verification
```

The manifest contains a `partitions` array. Each entry supplies `name`, `role`
(`top-level` or `chained`), `output` (`name.img`), `partition_size`, `key`,
`algorithm`, `rollback_index`, `rollback_index_location`, `descriptors_from`
and `chain_partitions`. Descriptor entries contain `image` and `partition_name`.
Chain entries contain `name`, `rollback_index_location` and `public_key`.
Paths resolve relative to the manifest. Output must be a new directory.

Exactly one top-level image must reach every chained image. Each chain needs a
unique nonzero rollback-index location, a single parent and the actual child's
AVB public key. Chained header locations remain zero. The helper derives each
child's public key with the supplied AOSP avbtool, compares it with the parent's
selection, then follows the generated chain during verification.

`--disable-verification` sets flags `2` on the top-level image only. Without it,
all flags are zero and unsigned `NONE` images are rejected. Chained images always
require signing keys. No boot header or payload metadata is relabeled. Keep
private keys outside source; use the actual selected device capacities and
rollback policy. Validation of generated bytes does not prove bootloader trust
or authorize installation.
