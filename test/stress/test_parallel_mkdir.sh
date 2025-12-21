#!/bin/bash
# Test A: Parallel directory creation
# Tests DID cache handling under concurrent mkdir operations

set -e

SCRIPT_NAME="test_parallel_mkdir"
MOUNT_POINT="${1:-mnt}"
NUM_DIRS="${2:-100}"
PARALLELISM="${3:-10}"

if [ ! -d "$MOUNT_POINT" ]; then
    echo "Error: Mount point '$MOUNT_POINT' does not exist"
    exit 1
fi

TEST_DIR="$MOUNT_POINT/${SCRIPT_NAME}_$$"

echo "[$SCRIPT_NAME] Creating test directory: $TEST_DIR"
mkdir -p "$TEST_DIR"

echo "[$SCRIPT_NAME] Creating $NUM_DIRS directories with parallelism=$PARALLELISM"
START_TIME=$(date +%s)

# Create directories in parallel
if seq 1 "$NUM_DIRS" | xargs -P "$PARALLELISM" -I {} mkdir "$TEST_DIR/dir_{}" 2>&1; then
    RESULT="PASS"
    EXIT_CODE=0
else
    RESULT="FAIL"
    EXIT_CODE=1
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Count actual directories created
CREATED=$(find "$TEST_DIR" -type d -name 'dir_*' | wc -l | tr -d ' ')

echo "[$SCRIPT_NAME] Result: $RESULT"
echo "[$SCRIPT_NAME] Directories created: $CREATED/$NUM_DIRS"
echo "[$SCRIPT_NAME] Duration: ${DURATION}s"

# Cleanup
echo "[$SCRIPT_NAME] Cleaning up..."
rm -rf "$TEST_DIR"

exit $EXIT_CODE
