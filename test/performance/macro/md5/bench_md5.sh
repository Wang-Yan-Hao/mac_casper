#!/bin/sh

if [ "$1" != "base" ] && [ "$1" != "exp" ]; then
    echo "Usage: $0 [base|exp]"
    exit 1
fi

MODE=$1
ITERATIONS=100
TEST_FILE="/tmp/testdata_256M"
OUTPUT_FILE="md5_${MODE}.txt"

ARCH=$(uname -m)
CPU_MODEL=$(sysctl -n hw.model)

echo "Detected Architecture: $ARCH"
echo "Detected CPU: $CPU_MODEL"

case "$ARCH" in
    "arm64")
        # RPI4 takes ~1s for 256MB. 1-2 repeats provide good precision.
        REPEAT_COUNT=1
        echo "Platform: RPI4/ARM64 - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    "amd64")
        # AMD64 is very fast; 10 repeats on 256MB ensures a stable 0.5s-1.0s sample.
        REPEAT_COUNT=10
        echo "Platform: AMD64 PC - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    *)
        REPEAT_COUNT=1
        echo "Platform: Unknown - Using default REPEAT_COUNT: $REPEAT_COUNT"
        ;;
esac

# 1. Generate 256MB test data if it doesn't exist
if [ ! -f $TEST_FILE ]; then
    echo "Generating 256MB test file in /tmp..."
    dd if=/dev/urandom of=$TEST_FILE bs=1M count=256 status=none
fi

# 2. Cleanup old results
rm -f $OUTPUT_FILE

echo "Running $ITERATIONS iterations (Sample size: $REPEAT_COUNT per iteration) - MODE: ${MODE}..."

# 3. Warm-up to ensure file is in Buffer Cache
for i in $(jot 3); do
    md5 $TEST_FILE > /dev/null
done

# 4. Main benchmark loop
for i in $(jot $ITERATIONS); do
    # Measure the cumulative real-time of REPEAT_COUNT executions
    ( /usr/bin/time -p sh -c "for j in \$(jot $REPEAT_COUNT); do md5 $TEST_FILE > /dev/null; done" ) 2>&1 | grep real | awk '{print $2}' >> $OUTPUT_FILE

    if [ $((i % 10)) -eq 0 ]; then
        echo "Progress: $i / 100"
    fi
done

echo "Done! Data saved to $OUTPUT_FILE"
