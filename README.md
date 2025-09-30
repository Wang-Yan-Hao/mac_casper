# mac_casper

## Introduction

Capsicum is a lightweight capability-based security framework in FreeBSD
designed to restrict process privileges. Casper builds on Capsicum by
providing various system services, such as DNS resolution, but these
services run in normal mode, leaving potential security vulnerabilities.

We propose a sandboxing mechanism for Casper based on Mandatory
Access Control (MAC), which mitigates the risks of privilege
escalation, unauthorized network access, and data tampering.

## Build and Rsun

### Build

To build the project and load the module:

```sh
sudo make all # Build the project
sh script/unload_load.sh # Reload the kernel module
```

### Install

To install the service into the FreeBSD Casper library:

```sh
cp casper_src/service.c /usr/src/lib/libcasper/libcasper/service.c
cd /usr/src/lib/libcasper/libcasper
sudo make all install
```

### Test

All test code is located under the `test_program` folder.
Each Casper service has its own folder containing demo programs.
For example, to test the DNS service:

```sh
cd test_program/dns # DNS service
make
./getaddr
```

Example output:

```sh
Testing getaddrinfo for www.google.com:
IPv6: 2404:6800:4012:9::2004
IPv4: 142.250.204.36

Testing getnameinfo for 142.250.72.196:
Hostname: sfo03s21-in-f4.1e100.net

Testing gethostbyname for www.google.com:
IP: 142.250.204.36

Testing gethostbyname2 for www.google.com (family: IPv4):
IP: 142.250.204.36

Testing gethostbyaddr for 142.250.72.196:
Hostname: sfo03s21-in-f4.1e100.net

Open failed
Chdir failed
```

Note: The last two errors (open and chdir) are expected.
They occur because the MAC module restricts process access.

Casper also includes its own test suite, which can be run using `kyua`.

```sh
kola@freebsd:/usr/tests/lib/libcasper/services $ ls
Kyuafile        cap_dns         cap_fileargs    cap_grp         cap_net         cap_netdb       cap_pwd         cap_sysctl
kola@freebsd:/usr/tests/lib/libcasper/services $ sudo kyua test
cap_netdb/netdb_test:cap_netdb__getprotobyname  ->  passed  [0.005s]
cap_fileargs/fileargs_test:fileargs__fopen_create  ->  passed  [0.058s]

...

cap_sysctl/sysctl_test:cap_sysctl__operation  ->  passed  [0.027s]
cap_sysctl/sysctl_test:cap_sysctl__recursive_limits  ->  passed  [0.004s]

Results file id is usr_tests_lib_libcasper_services.20250930-170345-409518
Results saved to /root/.kyua/store/results.usr_tests_lib_libcasper_services.20250930-170345-409518.db

57/57 passed (0 broken, 0 failed, 0 skipped)
```

As the output shows, our module successfully allows all legitimate actions without denial.

### Performance Test

Each service folder also contains a `performance` subfolder with benchmarking code.

For example, to test DNS service performance:

```sh
cd test_program/dns/performance
make
./cap_dns
```

Example output:

```
getnameinfo took 0.045159 seconds for 1 iterations
gethostbyname took 0.009020 seconds for 1 iterations
gethostbyname2 took 0.004265 seconds for 1 iterations
gethostbyaddr took 0.045715 seconds for 1 iterations
```

To run all performance tests:

```sh
cd script
sh test_all_perf.sh
```

### Performance Test Utilities

The `test_program/share/` folder contains Python scripts for analyzing performance test results:

* `test_perf_mode.py`: Runs tests 50 times and reports the mode of the results.
* `test_perf_mode_qps.py`: Calculates QPS (queries per second) results for DNS tests.
* `test_perf_filtered.py`: Runs tests 50 times and filters out the lowest 5% and highest 5% of results.

```sh
kola@freebsd:~/git_projects/mac_casper/test_program/share $ python3.11 test_perf_mode.py -h
Usage: python3 test_perf_mode.py [services] [--iter N] [--plot | --save-plot]
Options:
  --iter N        Run each test N times (default: 50)
  --plot          Show KDE + histogram plots
  --save-plot     Save KDE + histogram plots as PNG files
  -h, --help      Show this help message and exit
Examples:
  python3 test_perf_mode.py fileargs --iter 100 --save-plot
  python3 test_perf_mode.py dns grp
  python3 test_perf_mode.py              # Run all services
```

## Limit Privileged Implements Abstract

![image](https://github.com/user-attachments/assets/16e1e28b-5505-4208-ab16-e1e2e37fc3bd)

In Casper ([libcasper(3)](https://man.freebsd.org/cgi/man.cgi?query=libcasper&apropos=0&sektion=3&manpath=FreeBSD+15.0-CURRENT&arch=default&format=html)), multiple services run independently, and each should have its own namespace. Below is an overview of the required permissions for each service:

### Dns

The DNS service should be able to open, read, and perform lookups on the following files:

1. `/etc/services`
2. `/etc/nsswitch.conf`
3. `/etc/resolv.conf`
4. `/etc/hosts`

Additionally, it should only be allowed to connect and send requests to the servers listed in `/etc/resolv.conf`. It may also perform receive system calls.  
All other system calls should be restricted.

### Net

Similar to the DNS service, the Net service has network-related permissions but is more general. It is allowed to connect and bind to user-defined IP lists.  
All other system calls should be restricted.

### Fileargs

This service is responsible for opening user-defined files.  
All other system calls should be restricted.

### Grp

This service should only be allowed to open the following files:

1. `/etc/group`
2. `/etc/nsswitch.conf`
3. `/var/db/cache/group.cache` (if `nscd` is running)

> The group cache file is used by the Name Service Cache Daemon (nscd). If caching is enabled, group lookups may access this file instead of `/etc/group`.

The service should only be allowed to perform `fstat`, `fstatat`, and `lseek` system calls.  
All other system calls should be restricted.

### Netdb

This service should only be allowed to open:

1. `/etc/nsswitch.conf`
2. `/etc/protocols`

It should be restricted to using only the `ioctl` and `open` system calls.  
All other system calls should be restricted.

### Pwd

This service should only be allowed to open:

1. `/etc/nsswitch.conf`
2. `/etc/spwd.db`
3. `/etc/pwd.db`

It should only use the following system calls:

- `getuid`
- `geteuid`
- `getlogin`
- `fstat`
- `ioctl`

All other system calls should be restricted.

### Sysctl

This service should only be allowed to open `/etc/pwd.db`.  
It should only be permitted to use the `fstat`, `ioctl`, and `open` system calls.  
All other system calls should be restricted.

### Syslog

This service should only be allowed to open:

1. `/etc/localtime`
2. `/etc/pwd.db`

It should only use the following system calls:

- `socket`
- `connect`
- `sendto`

All other system calls should be restricted.
