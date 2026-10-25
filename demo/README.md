# Casper examples

This directory contains small C programs for exercising selected Casper
services. Each service example has a local `Makefile`; build and run it from
its own directory on FreeBSD:

```sh
cd demo/dns
make
./getadd
```

Available examples:

| Directory | Program(s) | Dependency |
| --- | --- | --- |
| `dns/` | `getadd` | `libcasper`, DNS/network access |
| `fileargs/` | `fileargs_demo`, `casper_fileargs_demo` | `libcasper`, `libcap_fileargs` |
| `grp/` | `casper_grp_demo` | `libcasper`, `libcap_grp` |
| `netdb/` | `casper_netdb_demo` | `libcasper`, `libcap_netdb` |
| `pwd/` | `casper_pwd_demo` | `libcasper`, `libcap_pwd` |
| `sysctl/` | `casper_sysctl_demo` | `libcasper`, `libcap_sysctl` |
| `syslog/` | `casper_syslog_demo` | `libcasper`, `libcap_syslog` |

`mac_set/` contains examples for setting MAC labels. `other/` contains
standalone experiments and archived code; these are not part of the supported
smoke-test path.

Some examples are most useful with the `mac_casper` policy and matching
service labels configured. They may fail or show expected access denials
without that setup. Do not run the system-file symlink experiment on a
production host:

```sh
cd demo/soft_link
make -C ../../test/performance/function/dns
make -C ../../test/performance/function/grp
make -C ../../test/performance/function/netdb
sudo sh ./soft_link_test.sh --confirm-system-file-replacement
```

That experiment temporarily replaces `/etc/resolv.conf`, `/etc/group`, and
`/etc/protocols`. It requires root, restores the originals on exit when
possible, and should only be used on a disposable FreeBSD VM. See
[`../script/README.md`](../script/README.md) for the other helper scripts.
