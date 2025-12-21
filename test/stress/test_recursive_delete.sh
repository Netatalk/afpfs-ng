#!/bin/bash
# Test E: Recursive directory deletion
# Tests directory entry cache consistency during rm -rf operations
# Specifically targets "Directory not empty" errors on macOS

set -e

SCRIPT_NAME="test_recursive_delete"
MOUNT_POINT="${1:-mnt}"
DEPTH="${2:-3}"
FILES_PER_DIR="${3:-10}"

if [ ! -d "$MOUNT_POINT" ]; then
    echo "Error: Mount point '$MOUNT_POINT' does not exist"
    exit 1
fi

TEST_DIR="$MOUNT_POINT/${SCRIPT_NAME}_$$"

echo "[$SCRIPT_NAME] Creating test directory structure: $TEST_DIR"
mkdir -p "$TEST_DIR"

# Create nested directory structure
echo "[$SCRIPT_NAME] Creating nested directories (depth=$DEPTH, files_per_dir=$FILES_PER_DIR)"
START_TIME=$(date +%s)

# Build a complex nested structure similar to .git/modules/subprojects/...
create_nested_structure() {
    local base_dir="$1"
    local current_depth="$2"
    local max_depth="$3"

    if [ "$current_depth" -ge "$max_depth" ]; then
        return
    fi

    # Create subdirectories
    for i in $(seq 1 3); do
        local subdir="$base_dir/level${current_depth}_dir${i}"
        mkdir -p "$subdir"

        # Create files in this directory
        for j in $(seq 1 "$FILES_PER_DIR"); do
            touch "$subdir/file_$j"
        done

        # Recurse
        create_nested_structure "$subdir" $((current_depth + 1)) "$max_depth"
    done
}

create_nested_structure "$TEST_DIR" 0 "$DEPTH"

# Count what we created
TOTAL_DIRS=$(find "$TEST_DIR" -type d | wc -l | tr -d ' ')
TOTAL_FILES=$(find "$TEST_DIR" -type f | wc -l | tr -d ' ')

echo "[$SCRIPT_NAME] Created: $TOTAL_DIRS directories, $TOTAL_FILES files"

# Now try to delete it all
echo "[$SCRIPT_NAME] Attempting recursive delete..."
DELETE_START=$(date +%s)

if rm -rf "$TEST_DIR" 2>&1; then
    RESULT="PASS"
    EXIT_CODE=0
else
    RESULT="FAIL"
    EXIT_CODE=1

    # Check what's left behind
    if [ -d "$TEST_DIR" ]; then
        echo "[$SCRIPT_NAME] ERROR: Directory still exists after rm -rf"
        REMAINING_DIRS=$(find "$TEST_DIR" -type d 2>/dev/null | wc -l | tr -d ' ')
        REMAINING_FILES=$(find "$TEST_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
        echo "[$SCRIPT_NAME] Remaining: $REMAINING_DIRS directories, $REMAINING_FILES files"

        # Show the structure that couldn't be deleted
        echo "[$SCRIPT_NAME] Remaining structure:"
        find "$TEST_DIR" -type d 2>/dev/null | head -20
    fi
fi

DELETE_END=$(date +%s)
DELETE_DURATION=$((DELETE_END - DELETE_START))

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "[$SCRIPT_NAME] Result: $RESULT"
echo "[$SCRIPT_NAME] Delete duration: ${DELETE_DURATION}s"
echo "[$SCRIPT_NAME] Total duration: ${DURATION}s"

# Force cleanup if normal delete failed
if [ $EXIT_CODE -ne 0 ] && [ -d "$TEST_DIR" ]; then
    echo "[$SCRIPT_NAME] Attempting forced cleanup..."
    # Try multiple times with sync in between
    for attempt in 1 2 3; do
        echo "[$SCRIPT_NAME] Cleanup attempt $attempt/3"
        sync
        sleep 1
        if rm -rf "$TEST_DIR" 2>/dev/null; then
            echo "[$SCRIPT_NAME] Cleanup succeeded on attempt $attempt"
            break
        fi
    done

    # Last resort: delete files first, then directories bottom-up
    if [ -d "$TEST_DIR" ]; then
        echo "[$SCRIPT_NAME] Using bottom-up deletion strategy..."
        find "$TEST_DIR" -type f -delete 2>/dev/null || true
        find "$TEST_DIR" -depth -type d -delete 2>/dev/null || true
    fi
fi

exit $EXIT_CODE
