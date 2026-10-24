# Performance Benchmarks

This directory contains the source code and scripts for measuring Casper
performance on FreeBSD. The benchmark results and plots are handled separately
under [`../perf_plot/`](../perf_plot/).

## Directory Structure

1. **`function/`**: Contains micro-benchmarks for internal Casper functions and security policy logic.
2. **`syscall/`**: Focuses on System Call overhead analysis (e.g., `open`, `socket`, `sysctl`).
    > **Note**: To successfully capture the C-program output via Python scripts, the `mpo_pipe_check_write` policy must be temporarily commented out in the Casper kernel module to avoid blocking the standard output pipe.
3. **`macro/`**: Macro benchmarks for common system utilities.

## Python Environment

Install the shared dependencies from the repository root as described in
[`../README.md`](../README.md).

## Save benchmark results

On FreeBSD, configure the system for the baseline or with-MAC setup and run the
relevant benchmark with the matching `--scenario` option. The scripts do not
change the module or labels. Each run updates its architecture/scenario entry
in `test/perf_plot/<suite>/test_results.json`; other architecture and scenario
entries are retained.

Function benchmarks:

```sh
cd test/performance/function/share
sh build_all.sh
python3 test_perf_mode.py --scenario baseline
python3 test_perf_mode.py --scenario with_mac
```

DNS queries-per-second benchmark:

```sh
cd test/performance/function/share
python3 test_perf_mode_qps.py --scenario baseline dns
python3 test_perf_mode_qps.py --scenario with_mac dns
```

Each DNS QPS run performs a long-running measurement; it does not use the
function benchmark's `--iter` option.

Syscall benchmarks:

```sh
cd test/performance/syscall
python3 test_syscall_mode.py --scenario baseline
python3 test_syscall_mode.py --scenario with_mac
```

The syscall runner rebuilds its test binaries before collecting results. For
build details and FreeBSD-specific prerequisites, see the README files in the
benchmark subdirectories.
