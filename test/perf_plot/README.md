# Plot

This directory contains Python scripts for visualizing performance benchmark
results. Benchmark-generated JSON data is local output and is not tracked by
Git.

Create and activate the shared virtual environment, then install dependencies
from the repository root:

```sh
python3 -m venv test/.venv
. test/.venv/bin/activate
python -m pip install -r test/requirements.txt
```

Run the benchmarks documented in
[`../performance/README.md`](../performance/README.md) for both architectures
and both scenarios (`baseline` and `with_mac`). Each benchmark writes or updates
`test_results.json` in its matching directory. Generated JSON files are ignored
by Git. Then generate plots from the repository root:

```sh
python3 test/perf_plot/syscall/plot.py
python3 test/perf_plot/qps/plot.py
python3 test/perf_plot/function/plot.py
```

The scripts read `test_results.json` relative to their own location and write
PNG files to the current working directory. Function comparison plots require
both scenarios for an architecture; syscall and QPS plots show the scenarios
that have been recorded.

## Directory

The analysis is divided into three specialized categories:

1. **`syscall/`**: Analyzes overhead across the `open`, `socket`, and `sysctl` system calls. Results are stored in `syscall/test_results.json`.
2. **`qps/`**: Measures DNS Queries Per Second (throughput). Results are stored in `qps/test_results.json`.
3. **`function/`**: Compares Casper service function timings. Results are stored in `function/test_results.json`.
