# Service Function Performance Tests

This directory contains performance benchmarking tests for individual system services (e.g., `dns`, `pwd`, `grp`, `netdb`).

## Directory Structure

* **Service Folders** (`dns/`, `fileargs/`, `grp/`, `net/`, `netdb/`, `pwd/`, `sys/`): Contain specific test cases and configurations for their respective services.
* **`share/`**: Contains shared testing scripts and utilities used across all service benchmarks.

## Shared Utilities (`share/`)

The `share/` folder provides the core testing logic:

* **`test_perf_filtered.py`**: Executes performance tests across different services and applies a 5th–95th percentile filter to remove execution time outliers.
* **`test_perf_mode.py`**: Applies Kernel Density Estimation (KDE) to the test data to determine the mode (peak density) of the execution times.
* **`test_perf_mode_qps.py`**: Evaluates the Queries Per Second (QPS) specifically for the DNS service, using KDE mode analysis to report stable throughput.
* **`config.py`**: Shared configuration settings for the test runs.
