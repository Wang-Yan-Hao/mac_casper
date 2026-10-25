# DTrace experiments

This directory contains baseline programs and DTrace-related experiments for
observing Casper service behavior. These are not part of the module build or
an automated correctness test suite.

## Trace MAC hook denials

On FreeBSD, with the module loaded and DTrace permitted, trace hook return
values of `EACCES` (13 on FreeBSD):

```sh
sudo dtrace -n 'fbt:mac_casper::return /arg1 == 13/ {
	printf("%s returned EACCES(%d)\n", probefunc, arg1);
}'
```

Probe availability depends on the FreeBSD kernel configuration and whether
the function is visible to FBT. A trace with no matching probes does not
establish that the policy has no denials.

The subdirectories contain small baseline programs and Makefiles for selected
services. Build them on the target FreeBSD system and review the corresponding
Makefile before running; some binaries link directly against system Casper
libraries.
