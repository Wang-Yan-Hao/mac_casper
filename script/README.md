# Helper scripts

Scripts in this directory are development and system-administration helpers.
Run them from any working directory unless their section below says otherwise.
Most require FreeBSD; scripts that change the kernel module or system labels
also require root.

## Common helpers

| Script | Purpose | Requirements / effects |
| --- | --- | --- |
| `format.sh` | Format the module, checker, label definitions, and split hook files. | `clang-format`; edits source files in place. |
| `test_all_perf.sh` | Build and run selected Casper demos and the DNS function benchmark. | FreeBSD, Casper libraries, network/DNS; executes test programs. |

Examples:

```sh
sh script/format.sh
sh script/test_all_perf.sh
```

## Labels

`label/set_label_on_file.sh` applies the configured object labels immediately.
It requires root and `/usr/sbin/setfmac`, skips paths that are absent, and
stops on a labeling error. The boot-time rc service
`label/casper_label_rc` applies the same mapping after `syslogd` starts.

Review the path map in `label.h` before applying labels. Persistent labels
require a compatible multilabel filesystem and MAC extended-attribute
support. Do not enable the rc service until manual labeling has been tested
on a disposable system.

## DTrace

[`dtrace/README.md`](./dtrace/README.md) documents a DTrace probe for denied
MAC hooks. DTrace may require elevated privileges and a loaded kernel module.

## Development-only scripts

`develop/generate_deny.sh` and `develop/rpi4_link.sh` are experimental
utilities, not part of the supported build path:

- `generate_deny.sh` uses text matching on kernel callback typedefs and emits
  templates that require manual review. It is not a C parser and should not
  be used to generate production policy code.
- `rpi4_link.sh` hard-codes an AArch64 linker flow and assumes the expected
  object files and FreeBSD kernel build artifacts are already present. Prefer
  the root `make` target on the target FreeBSD system.

The DTrace source and baseline programs under `dtrace/` are profiling
experiments, not policy tests.
