# mac_casper

## Introduction

Capsicum is a lightweight capability-based security framework in FreeBSD
designed to restrict process privileges. Casper builds on Capsicum by
providing various system services, such as DNS resolution, but these
services run in normal mode, leaving potential security vulnerabilities.

We propose a sandboxing mechanism for Casper based on Mandatory
Access Control (MAC), which mitigates the risks of privilege
escalation, unauthorized network access, and data tampering.

## Install

### Prerequisites

Before installing the module, ensure your file system supports MAC Multilabel.
This is required for persistent label storage.

Check status:

```sh
# Option 1: Check running system (Recommended)
mount | grep "/"
# Look for "multilabel" in the parentheses.

# Option 2: Check filesystem superblock
# (Replace /dev/gpt/rootfs your actual root device)
tunefs -p /dev/gpt/rootfs | grep "MAC multilabel"
# Expected: MAC multilabel: (-l)
```

If multilabel is not present, boot into Single User Mode and run:

```sh
tunefs -l enable /
```

### Build and Install

To compile the kernel module and install it to the system:

```sh
# Compile and install the module into /boot/modules
sudo make all install
```

To load the module automatically at system boot:

```sh
# This adds mac_casper_load="YES" to /boot/loader.conf
sudo sysrc -f /boot/loader.conf mac_casper_load="YES"
```

### Label Setup

The MAC module relies on file labels to enforce security policies.
You must apply these labels to the relevant system files.

Set up the `rc.d` service. This ensures labels are correctly applied on every boot.

```sh
# -m 755: Sets mode to rwxr-xr-x (Read/Write/Execute for Owner, Read/Execute for others)
sudo install -m 755 script/label/casper_label_rc /usr/local/etc/rc.d/casper_label

# 2. Enable the service in /etc/rc.conf
sudo sysrc casper_label_enable="YES"

# 3. Start the service immediately (no need to reboot yet)
sudo service casper_label start
```

You need to register the casper label name in the system configuration. Open `/etc/mac.conf`
and append `,?casper` to the default_labels line:

```sh
# Edit /etc/mac.conf
# Look for the 'default_labels file' line and add ',?casper' to the end.

default_labels file ?biba,?lomac,?mls,?sebsd,?casper
```

## Test

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
