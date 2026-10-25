# Syscall Test

This directory contains the benchmarking suite designed to measure the overhead of the module across various FreeBSD system calls. This performance evaluation focuses exclusively on benchmarking three specific system calls: `open`, `socket`, and `sysctl`.

* `test_syscall_mode.py`: The primary execution script that runs the benchmarks and collects performance metrics.
* `build_all.sh`: A shell script to compile all C-based syscall test programs in the subdirectories.
* `config.py`: Contains configuration parameters for the tests, such as iteration counts and specific syscall targets.

Run the benchmark on FreeBSD with an explicit scenario. The script rebuilds the
binaries, runs the benchmarks, and updates
[`../../perf_plot/syscall/`](../../perf_plot/syscall/):

```sh
python3 test_syscall_mode.py --scenario baseline
python3 test_syscall_mode.py --scenario with_mac
```

Results are stored separately by architecture and scenario. Generated JSON is
ignored by Git.

> Note: To successfully capture the C-program output via Python scripts, the mpo_pipe_check_write policy must be temporarily commented out in the Casper kernel module to avoid blocking the standard output pipe.
