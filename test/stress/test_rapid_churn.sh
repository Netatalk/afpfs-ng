#!/bin/bash
# Test D: Rapid open/close cycles
# Tests fork lifecycle management and resource cleanup

set -e

SCRIPT_NAME="test_rapid_churn"
MOUNT_POINT="${1:-mnt}"
NUM_CYCLES="${2:-1000}"

if [ ! -d "$MOUNT_POINT" ]; then
    echo "Error: Mount point '$MOUNT_POINT' does not exist"
    exit 1
fi

TEST_DIR="$MOUNT_POINT/${SCRIPT_NAME}_$$"

echo "[$SCRIPT_NAME] Creating test directory: $TEST_DIR"
mkdir -p "$TEST_DIR"

echo "[$SCRIPT_NAME] Running $NUM_CYCLES rapid create/delete cycles"
START_TIME=$(date +%s)

FAILURES=0
for i in $(seq 1 "$NUM_CYCLES"); do
    if ! touch "$TEST_DIR/rapid_$i" 2>/dev/null; then
        echo "[$SCRIPT_NAME] Failed to create file at iteration $i"
        FAILURES=$((FAILURES + 1))
    elif ! rm "$TEST_DIR/rapid_$i" 2>/dev/null; then
        echo "[$SCRIPT_NAME] Failed to delete file at iteration $i"
        FAILURES=$((FAILURES + 1))
    fi

    # Progress indicator every 100 iterations
    if [ $((i % 100)) -eq 0 ]; then
        echo "[$SCRIPT_NAME] Progress: $i/$NUM_CYCLES (failures: $FAILURES)"
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [ $FAILURES -eq 0 ]; then
    RESULT="PASS"
    EXIT_CODE=0
else
    RESULT="FAIL"
    EXIT_CODE=1
fi

echo "[$SCRIPT_NAME] Result: $RESULT"
echo "[$SCRIPT_NAME] Cycles completed: $((NUM_CYCLES - FAILURES))/$NUM_CYCLES"
echo "[$SCRIPT_NAME] Failures: $FAILURES"
echo "[$SCRIPT_NAME] Duration: ${DURATION}s"

# Cleanup
echo "[$SCRIPT_NAME] Cleaning up..."
rm -rf "$TEST_DIR"

exit $EXIT_CODE
