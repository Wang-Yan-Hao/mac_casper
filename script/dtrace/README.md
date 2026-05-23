# DTrace Profiling for Casper Services

This directory contains the **baseline code** and **DTrace scripts** used to analyze the runtime behavior of Casper services.

## Script

DTrace script to trace any deny of the module.

```sh
kola@generic:~/proj/mac_casper/test/performance/macro/sockstat $ sudo dtrace
-n 'fbt:mac_casper::return /arg1 == 13/ { printf("%s returned EACCESS(%d)",
 probefunc, arg1); }'
Password:
dtrace: description 'fbt:mac_casper::return ' matched 133 probes
```

