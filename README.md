# mac_casper

`mac_casper` is an experimental FreeBSD MAC policy module that assigns labels
to Casper service processes and selected system files. The policy restricts
which files labeled service processes may open and applies additional
service-specific checks to operations such as socket access.

This is a FreeBSD kernel project. The kernel module, MAC framework, Casper
services, `setfmac`, and DTrace examples cannot be built or exercised on Linux.
Use a test machine or VM: loading a MAC policy and changing system labels can
affect normal system services.

## Repository guide

- [`src/`](./src/README.md) contains hook implementations and their internal
  declarations.
- [`casper_src/`](./casper_src/README.md) contains a modified
  `libcasper` service source file used to apply subject labels.
- [`demo/`](./demo/README.md) contains small service examples.
- [`test/`](./test/README.md) contains effect and performance tests.
- [`script/`](./script/README.md) contains development, label, and
  DTrace helpers.

## Build the kernel module

Build and install on FreeBSD with a source tree and kernel build environment
compatible with the running system:

```sh
sudo make clean
sudo make all install
```

This installs the module using the FreeBSD kernel-module build framework,
normally under `/boot/modules`.

This policy is managed as a boot-time module on the target system. Do not use
`kldload` or `kldunload` as the normal activation or update procedure; a
running MAC policy can be rejected for late loading or may not be safely
unloaded. Enable it in `/boot/loader.conf`:

```sh
mac_casper_load="YES"
```

Add the setting with an editor or:

```sh
sudo sysrc -f /boot/loader.conf mac_casper_load="YES"
```

Reboot to load the policy, then verify it:

```sh
kldstat -m mac_casper
```

After changing or reinstalling the module, reboot to activate the new version.

## Filesystem labels and service labels

File extattrs are used to persist object labels. Before using the policy,
verify that the filesystem containing the labeled files supports MAC
multilabel and that the required extended-attribute namespace is available.
The exact setup depends on the filesystem and FreeBSD release.

Check the mounted filesystem and the correct backing device first. Do not run
`tunefs` against `/` or a guessed device: changing filesystem features is an
administrative operation and may require the filesystem to be unmounted.
Consult the FreeBSD `tunefs(8)` and `mount(8)` documentation for the target
system.

The policy's canonical object-label and file-path maps are in
[`label.h`](./label.h); the subject-to-object open permissions are in
[`checker.h`](./checker.h). Apply labels using the reviewed helper:

```sh
sudo sh script/label/set_label_on_file.sh
```

The helper skips paths that do not exist and stops if `setfmac` fails. To
apply labels manually, run it after rebooting with the policy loaded. To apply
them at boot, install and enable the optional rc service after confirming the
file list:

```sh
sudo install -m 555 script/label/casper_label_rc \
  /usr/local/etc/rc.d/casper_label
sudo sysrc casper_label_enable="YES"
```

The service runs after `syslogd` and may relabel system files. Test it first
on a disposable FreeBSD machine.

To use textual MAC labels such as `casper/dns`, the system MAC label
configuration must recognize the `casper` label element. Follow the
configuration procedure for the target FreeBSD release and preserve existing
`/etc/mac.conf` settings; do not replace the system's `default_labels` line
with a copied example.

## `libcasper` integration

[`casper_src/service.c`](./casper_src/service.c) is a modified FreeBSD
`libcasper` service implementation. It checks whether `CasperMAC` is loaded
and assigns a subject label to recognized services. It is **not** built as
part of the kernel module.

The file is based on a particular FreeBSD source version. Before integrating
it, identify the matching FreeBSD source revision and inspect the differences
against that revision's `lib/libcasper/libcasper/service.c`. Do not copy it
over `/usr/src` blindly: keep a backup or source-control diff, build and test
`libcasper`, and retain a recovery path. See
[`casper_src/README.md`](./casper_src/README.md).

## Tests and examples

Build and run an individual example from its directory, for example:

```sh
cd demo/dns
make
./getadd
```

The example needs network/DNS access. Other examples may require the MAC
module and the matching Casper service libraries to be installed.

[`script/test_all_perf.sh`](./script/test_all_perf.sh) is a FreeBSD service
smoke-test helper; it builds and runs several examples and a DNS benchmark.
Some tests require working Casper libraries, network access, or a configured
MAC policy. It is not a substitute for the structured benchmark runners
under `test/performance/`.

The FreeBSD Casper test suite can be run with `kyua` when the corresponding
system tests are installed. For effect and performance test prerequisites,
commands, and result handling, see [`test/README.md`](./test/README.md) and
[`test/performance/README.md`](./test/performance/README.md).

## Development

Run the formatter with:

```sh
sh script/format.sh
```

The script formats the module, checker, label definitions, and the split hook
sources. It requires `clang-format`.

The contents of this repository are experimental. Review the policy and test
on an isolated FreeBSD system before deploying it.
