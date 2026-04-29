#!/bin/sh

if [ "$1" != "base" ] && [ "$1" != "exp" ]; then
    echo "Usage: $0 [base|exp]"
    exit 1
fi

MODE=$1
ITERATIONS=100
OUTPUT_FILE="logger_${MODE}.txt"
TAG="MAC_BENCH"

ARCH=$(uname -m)
CPU_MODEL=$(sysctl -n hw.model)

echo "Detected Architecture: $ARCH"
echo "Detected CPU: $CPU_MODEL"

case "$ARCH" in
    "arm64")
		REPEAT_COUNT=200
        echo "Platform: RPI4/ARM64 - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    "amd64")
        REPEAT_COUNT=1000
        echo "Platform: AMD64 PC - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    *)
        REPEAT_COUNT=200
        echo "Platform: Unknown - Using default REPEAT_COUNT: $REPEAT_COUNT"
        ;;
esac
# ----------------------------

rm -f $OUTPUT_FILE

echo "Running $ITERATIONS iterations for logger - MODE: ${MODE}..."
echo "Service: cap_syslog (Interception of system logging)"

for i in $(jot 5); do
    logger -t $TAG "Warm-up message"
done

for i in $(jot $ITERATIONS); do
    ( /usr/bin/time -p sh -c "for j in \$(jot $REPEAT_COUNT); do logger -t $TAG 'Performance test message \$j'; done" ) 2>&1 | grep real | awk '{print $2}' >> $OUTPUT_FILE

    if [ $((i % 10)) -eq 0 ]; then
        echo "Progress: $i / 100"
    fi
done

echo "Done! Data saved to $OUTPUT_FILE"
echo "Tip: You can check the logs using 'grep $TAG /var/log/messages'"
