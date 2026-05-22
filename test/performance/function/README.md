# Service Function Performance Tests

This directory contains performance benchmarking tests for individual system services (e.g., `dns`, `pwd`, `grp`, `netdb`).

## Directory Structure

* **Service Folders** (`dns/`, `fileargs/`, `grp/`, `net/`, `netdb/`, `pwd/`, `sys/`): Contain specific test cases and configurations for their respective services.
* **`share/`**: Contains shared testing scripts and utilities used across all service benchmarks.

For dns service, you need run your local dns server first to reduce the effect of internet.

```sh
sudo service local_unbound onestart

vim /etc/resolv.conf
# Add nameserver 127.0.0.1

drill freebsd.org @127.0.0.1 # You should see SERVER show 127.0.0.1
```

## Shared Utilities (`share/`)

The `share/` folder provides the core testing logic:

* **`test_perf_filtered.py`**: Executes performance tests across different services and applies a 5th–95th percentile filter to remove execution time outliers.
* **`test_perf_mode.py`**: Applies Kernel Density Estimation (KDE) to the test data to determine the mode (peak density) of the execution times.
* **`test_perf_mode_qps.py`**: Evaluates the Queries Per Second (QPS) specifically for the DNS service, using KDE mode analysis to report stable throughput.
* **`config.py`**: Shared configuration settings for the test runs.

Before running python test, you need run `sh build_all.sh` in `share` folder to build all test.

Then run like differnt python script.

```sh
kola@generic:~/proj/mac_casper/test/performance/function/share $ python3.11 test_perf_mode.py -h
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

