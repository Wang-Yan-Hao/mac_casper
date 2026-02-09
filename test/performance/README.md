# Performance Testing and Visualization

This directory contains the source code, raw data, and visualization scripts for evaluating the performance of the Casper framework across different system architectures (AMD64 and ARM64).

## Directory Structure

1. **`function/`**: Contains micro-benchmarks for internal Casper functions and security policy logic.
2. **`syscall/`**: Focuses on System Call overhead analysis (e.g., `open`, `socket`, `sysctl`).
    > **Note**: To successfully capture the C-program output via Python scripts, the `mpo_pipe_check_write` policy must be temporarily commented out in the Casper kernel module to avoid blocking the standard output pipe.
3. **`plot/`**: Contains Python-based visualization scripts (using `matplotlib` or `seaborn`) to generate technical graphs for reports and publications.

