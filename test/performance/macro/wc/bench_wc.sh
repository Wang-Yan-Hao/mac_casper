#!/bin/sh

if [ "$1" != "base" ] && [ "$1" != "exp" ]; then
    echo "Usage: $0 [base|exp]"
    exit 1
fi

MODE=$1
ITERATIONS=100
TEST_DIR="/tmp/wc_test_dir"
OUTPUT_FILE="wc_${MODE}.txt"

# --- Platform Detection and Parameter Scaling ---
ARCH=$(uname -m)
CPU_MODEL=$(sysctl -n hw.model)

echo "Detected Architecture: $ARCH"
echo "Detected CPU: $CPU_MODEL"

case "$ARCH" in
    "arm64")
        # Raspberry Pi 4 settings
        FILE_COUNT=100
        REPEAT_PER_ITER=2
        echo "Platform: RPI4/ARM64 - Setting REPEAT_PER_ITER to $REPEAT_PER_ITER"
        ;;
    "amd64")
        # Modern PC settings - scaled up to ensure measurable execution time
        FILE_COUNT=500
        REPEAT_PER_ITER=80
        echo "Platform: AMD64 PC - Setting REPEAT_PER_ITER to $REPEAT_PER_ITER"
        ;;
    *)
        FILE_COUNT=500
        REPEAT_PER_ITER=10
        echo "Platform: Unknown - Using default REPEAT_PER_ITER: $REPEAT_PER_ITER"
        ;;
esac
# -----------------------------------------------

# 1. Generate test data if it does not exist
if [ ! -d $TEST_DIR ]; then
    echo "Generating $FILE_COUNT test files in $TEST_DIR..."
    mkdir -p $TEST_DIR
    dd if=/dev/urandom of=/tmp/big_seed bs=1M count=50 status=none
    split -n $FILE_COUNT /tmp/big_seed "$TEST_DIR/file_"
    rm /tmp/big_seed
fi

# 2. Cleanup old data
rm -f $OUTPUT_FILE

echo "Running $ITERATIONS iterations (MODE: $MODE)..."
echo "Each sample performs $REPEAT_PER_ITER x wc calls on $FILE_COUNT files."

# 3. Main benchmark loop
for i in $(jot $ITERATIONS); do
    # Execute the command in a subshell via time -p to aggregate overhead
    ( /usr/bin/time -p sh -c "
        for j in \$(jot $REPEAT_PER_ITER); do
            find $TEST_DIR -type f | xargs wc > /dev/null
        done
    " ) 2>&1 | grep real | awk '{print $2}' >> $OUTPUT_FILE

    if [ $((i % 10)) -eq 0 ]; then
        echo "Progress: $i / 100"
    fi
done

echo "Done! Data saved to $OUTPUT_FILE"
