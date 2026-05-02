# Macro Test

This directory contains a suite of macro-benchmarks designed to evaluate the performance overhead of the FreeBSD Casper framework and the `mac_casper` module. These tests focus on common system utilities running within a sandboxed environment.

### Adjust ICMP Rate Limiting
When running `ping` tests, the default FreeBSD ICMP rate limiting may drop response packets, leading to inconsistent data in `ping_base.txt`.
*   **Problem**: `dmesg` reporting `limiting icmp ping response`.
*   **Solution**: Run the following command to disable the limit during testing:
    ```bash
    sudo sysctl net.inet.icmp.icmplim=0
    ```

## Test Suite Overview

| Utility | Casper Service | Description |
| :--- | :--- | :--- |
| **`md5`** | `fileargs` | Tests file descriptor proxying and sandboxed file access. |
| **`ping`** | `dns` | Evaluates IPC latency for name resolution. Use `ping -n` to bypass external DNS variables. |
| **`sockstat`** | `net` / `sysctl` / `netdb` / `pwd` | Monitors the overhead of multiple Casper helper processes and IPC tunnels. |
| **`wc`** | `fileargs` | Measures the cost of `vnode_check_open` interceptions during file reads. |
| **`kdump`** | `pwd` / `grp` | Used for tracing system call behavior during policy enforcement. |

## Running Benchmarks

Use the provided `test_all.sh` script to execute the full suite and record baseline data:
```bash
chmod +x test_all.sh
./test_all.sh
```

Run `python kde.py` to get the statistics.

### Post-Test Cleanup

Run `pkill nc` after running `sockstat` test. 
