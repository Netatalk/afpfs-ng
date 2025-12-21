#!/bin/bash
# Test C: Parallel file creation with writes
# Tests concurrent write/flush operations and file size updates

set -e

SCRIPT_NAME="test_parallel_write"
MOUNT_POINT="${1:-mnt}"
NUM_FILES="${2:-50}"
PARALLELISM="${3:-10}"
FILE_SIZE_KB="${4:-10}"

if [ ! -d "$MOUNT_POINT" ]; then
    echo "Error: Mount point '$MOUNT_POINT' does not exist"
    exit 1
fi

TEST_DIR="$MOUNT_POINT/${SCRIPT_NAME}_$$"

echo "[$SCRIPT_NAME] Creating test directory: $TEST_DIR"
mkdir -p "$TEST_DIR"

echo "[$SCRIPT_NAME] Creating $NUM_FILES files (${FILE_SIZE_KB}KB each) with parallelism=$PARALLELISM"
START_TIME=$(date +%s)

# Create and write files in parallel
if seq 1 "$NUM_FILES" | xargs -P "$PARALLELISM" -I {} sh -c \
    "dd if=/dev/zero of=\"$TEST_DIR/file_{}\" bs=1024 count=$FILE_SIZE_KB 2>/dev/null" 2>&1; then
    RESULT="PASS"
    EXIT_CODE=0
else
    RESULT="FAIL"
    EXIT_CODE=1
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Count actual files created and verify sizes
CREATED=$(find "$TEST_DIR" -type f -name 'file_*' | wc -l | tr -d ' ')
EXPECTED_SIZE=$((FILE_SIZE_KB * 1024))
WRONG_SIZE=$(find "$TEST_DIR" -type f -name 'file_*' ! -size ${EXPECTED_SIZE}c | wc -l | tr -d ' ')

echo "[$SCRIPT_NAME] Result: $RESULT"
echo "[$SCRIPT_NAME] Files created: $CREATED/$NUM_FILES"
echo "[$SCRIPT_NAME] Files with incorrect size: $WRONG_SIZE"
echo "[$SCRIPT_NAME] Duration: ${DURATION}s"

# Cleanup
echo "[$SCRIPT_NAME] Cleaning up..."
rm -rf "$TEST_DIR"

exit $EXIT_CODE
