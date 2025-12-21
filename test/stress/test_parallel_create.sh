#!/bin/bash
# Test B: Parallel file creation (touch only, no writes)
# Tests fork ID allocation and open_forks list handling

set -e

SCRIPT_NAME="test_parallel_create"
MOUNT_POINT="${1:-mnt}"
NUM_FILES="${2:-100}"
PARALLELISM="${3:-10}"

if [ ! -d "$MOUNT_POINT" ]; then
    echo "Error: Mount point '$MOUNT_POINT' does not exist"
    exit 1
fi

TEST_DIR="$MOUNT_POINT/${SCRIPT_NAME}_$$"

echo "[$SCRIPT_NAME] Creating test directory: $TEST_DIR"
mkdir -p "$TEST_DIR"

echo "[$SCRIPT_NAME] Creating $NUM_FILES files with parallelism=$PARALLELISM"
START_TIME=$(date +%s)

# Create empty files in parallel
if seq 1 "$NUM_FILES" | xargs -P "$PARALLELISM" -I {} touch "$TEST_DIR/file_{}" 2>&1; then
    RESULT="PASS"
    EXIT_CODE=0
else
    RESULT="FAIL"
    EXIT_CODE=1
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Count actual files created
CREATED=$(find "$TEST_DIR" -type f -name 'file_*' | wc -l | tr -d ' ')

echo "[$SCRIPT_NAME] Result: $RESULT"
echo "[$SCRIPT_NAME] Files created: $CREATED/$NUM_FILES"
echo "[$SCRIPT_NAME] Duration: ${DURATION}s"

# Cleanup
echo "[$SCRIPT_NAME] Cleaning up..."
rm -rf "$TEST_DIR"

exit $EXIT_CODE
