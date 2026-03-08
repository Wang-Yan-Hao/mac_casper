# Plot

This directory contains Python scripts and data structures used to visualize the performance overhead and benchmarks of the module.

Note: The data is from my machine test results.

## Directory

The analysis is divided into three specialized categories:

1. **`syscall/`**: Analyzes the overhead introduced during system call interception and filtering. Data is stored in `syscall/data.json`.
2. **`qps/`**: Measures Queries Per Second (throughput) under various load conditions to evaluate system scalability. Data is stored in `qps/data.json`.
3. **`function/`**: Micro-benchmarks for specific internal kernel functions or MAC policy checks. Data is stored in `function/data.json`.

