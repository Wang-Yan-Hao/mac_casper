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

Before running the Python tests, run `sh build_all.sh` in the `share` folder to
build all test programs. Run on FreeBSD.

For the function benchmark, specify whether this run is the baseline or
with-MAC scenario. Results are written to
[`../../perf_plot/function/test_results.json`](../../perf_plot/function/test_results.json)
and are ignored by Git.

```sh
cd share
sh build_all.sh
python3 test_perf_mode.py --scenario baseline
python3 test_perf_mode.py --scenario with_mac
python3 test_perf_mode_qps.py --scenario baseline dns
python3 test_perf_mode_qps.py --scenario with_mac dns
```

The DNS QPS executable performs a long-running measurement and does not use
`--iter`. The helper scripts can also select specific services; use `-h` for
the available options.
