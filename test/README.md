# Tests

This directory contains functional and performance tests for the Casper MAC
module.

## Directories

- [`effect_eval/`](effect_eval/): evaluates the module's security-policy effects.
- [`performance/`](performance/): FreeBSD-only microbenchmarks, syscall
  benchmarks, and macro benchmarks.
- [`perf_plot/`](perf_plot/): scripts for visualizing performance benchmark
  data. See its [README](perf_plot/README.md) for usage.

## Python environment

Python tools used by the tests and plots share
[`requirements.txt`](requirements.txt). From the repository root, create and
activate a virtual environment and install the dependencies:

```sh
python3 -m venv test/.venv
. test/.venv/bin/activate
python -m pip install -r test/requirements.txt
```

The performance benchmarks that interact with FreeBSD kernel services must be
built and run on FreeBSD. Plot generation can run on any platform with the
listed Python dependencies installed. Benchmark runs write local JSON results
under `perf_plot/`; these generated files are intentionally excluded from Git.
Select the matching FreeBSD setup before each `baseline` or `with_mac` run; the
benchmark scripts do not alter the loaded module or system labels.
