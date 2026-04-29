#!/bin/sh

if [ "$1" != "base" ] && [ "$1" != "exp" ]; then
    echo "Usage: $0 [base|exp]"
    exit 1
fi

MODE=$1
ITERATIONS=100
OUTPUT_FILE="sockstat_${MODE}.txt"
DUMMY_COUNT=200

# --- Platform Detection and Parameter Scaling ---
ARCH=$(uname -m)
CPU_MODEL=$(sysctl -n hw.model)

echo "Detected Architecture: $ARCH"
echo "Detected CPU: $CPU_MODEL"

case "$ARCH" in
    "arm64")
        # Raspberry Pi 4 settings
        REPEAT_COUNT=80
        echo "Platform: RPI4/ARM64 - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    "amd64")
        # Modern PC settings - scaled up to ensure measurable execution time
        REPEAT_COUNT=400
        echo "Platform: AMD64 PC - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    *)
        REPEAT_COUNT=80
        echo "Platform: Unknown - Using default REPEAT_COUNT: $REPEAT_COUNT"
        ;;
esac
# -----------------------------------------------

# 1. Generate background load (Dummy sockets)
if ! pgrep -f "nc -l 127.0.0.1" > /dev/null; then
    echo "Creating $DUMMY_COUNT dummy sockets for testing..."
    for i in $(jot $DUMMY_COUNT); do
        nc -l 127.0.0.1 $((10000 + i)) > /dev/null 2>&1 &
    done
    sleep 2
fi

# 2. Cleanup old data
rm -f $OUTPUT_FILE

echo "Running $ITERATIONS iterations for sockstat - MODE: ${MODE}..."

# 3. Warm-up
for i in $(jot 5); do
    sockstat -46 > /dev/null
done

# 4. Main benchmark loop
for i in $(jot $ITERATIONS); do
    # -46: IPv4 & IPv6
    # -L: Listeners only
    # -n: Numerical output only (avoids DNS noise)
    ( /usr/bin/time -p sh -c "for j in \$(jot $REPEAT_COUNT); do sockstat -46Ln > /dev/null; done" ) 2>&1 | grep real | awk '{print $2}' >> $OUTPUT_FILE

    if [ $((i % 10)) -eq 0 ]; then
        echo "Progress: $i / 100"
    fi
done

echo "Done! Data saved to $OUTPUT_FILE"
echo "Note: Background nc processes are still running. Use 'pkill nc' to clean up if needed."
