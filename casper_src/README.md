# Modified `libcasper` source

[`service.c`](./service.c) is a modified copy of FreeBSD's
`lib/libcasper/libcasper/service.c`. In `service_start()`, it checks whether
the `CasperMAC` policy is loaded and assigns a `casper/<service>` process label
to selected services (DNS, net, fileargs, grp, netdb, pwd, sysctl, and syslog).

This file is not part of the kernel-module `Makefile`. It must be integrated
into and built with the matching FreeBSD source tree and system libraries.
FreeBSD source changes between releases, so first identify the source revision
from which this file was derived and compare it with the target system's
version:

```sh
diff -u /usr/src/lib/libcasper/libcasper/service.c casper_src/service.c
```

Run the comparison from the repository root. Do not copy this file over
`/usr/src` without reviewing the diff. Keep the
original source or a version-control patch, build and test the replacement
`libcasper`, and have a recovery plan before installing it. The module must
also be loaded and the `casper` MAC label element configured for the label
assignment to take effect.
