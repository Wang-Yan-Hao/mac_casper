#!/bin/sh

# Check arguments
if [ "$1" != "base" ] && [ "$1" != "exp" ]; then
    echo "Usage: $0 [base|exp]"
    exit 1
fi

MODE=$1
TESTS="md5 wc sockstat kdump ping logger"
BASE_DIR=$(pwd)

echo "=========================================================="
echo "  Casper MAC Performance Benchmarking - ALL TESTS"
echo "  Mode: ${MODE}"
echo "  Started at: $(date)"
echo "=========================================================="

# If running Experiment, check if the MAC module is loaded
if [ "$MODE" = "exp" ]; then
    if ! kldstat | grep -q "mac_casper"; then
        echo "Error: mac_casper module NOT loaded!"
        echo "Please run: sudo kldload mac_casper.ko before testing."
        exit 1
    fi
    echo "[Checked] MAC module is active."
fi

# Run each test
for cmd in $TESTS; do
    if [ -d "$cmd" ]; then
        echo ""
        echo ">>> Running Benchmark: $cmd ..."
        cd "$cmd"

        # Check if the script exists
        if [ -f "bench_${cmd}.sh" ]; then
            sh "bench_${cmd}.sh" "$MODE"
        else
            echo "Warning: bench_${cmd}.sh not found in $cmd/"
        fi

        cd "$BASE_DIR"
    else
        echo "Warning: Directory $cmd/ not found, skipping..."
    fi
done

echo ""
echo "=========================================================="
echo "  All benchmarks completed!"
echo "  You can now run 'python3.11 kde.py' to see the results."
echo "=========================================================="
