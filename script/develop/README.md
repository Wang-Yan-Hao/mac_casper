# Development experiments

These scripts are not used by the normal kernel-module build.

- `generate_deny.sh` is a prototype that extracts callback declarations using
  `grep` and `sed`. C declarations can span lines or contain nested syntax, so
  its output is only a starting point and must be reviewed and compiled by a
  developer. Pass a new output path explicitly; the script refuses to
  overwrite an existing file.
- `rpi4_link.sh` contains a manual AArch64 linker sequence for an older
  Raspberry Pi workflow. It assumes compatible object files, linker tools,
  and FreeBSD kernel artifacts are already available in the current directory.

Use the root `make` target on the target FreeBSD system for normal builds.
Keep generated output and architecture-specific artifacts out of tracked
source unless they are intentionally maintained.
