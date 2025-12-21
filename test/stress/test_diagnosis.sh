#!/bin/bash
# Diagnostic script to identify the root cause of I/O errors
# Monitors daemon health and captures failure context

set -e

SCRIPT_NAME="test_diagnosis"
MOUNT_POINT="${1:-mnt}"

if [ ! -d "$MOUNT_POINT" ]; then
    echo "Error: Mount point '$MOUNT_POINT' does not exist"
    exit 1
fi

TEST_DIR="$MOUNT_POINT/${SCRIPT_NAME}_$$"

echo "======================================================================"
echo "I/O Error Diagnostic Test"
echo "======================================================================"
echo "This test creates files one at a time and monitors for failure"
echo

# Find the afpfsd daemon PID
DAEMON_PID=$(pgrep -f "afpfsd" | head -1)

if [ -z "$DAEMON_PID" ]; then
    echo "ERROR: Cannot find afpfsd daemon process"
    exit 1
fi

echo "[INFO] Found afpfsd daemon: PID $DAEMON_PID"
echo "[INFO] Daemon file descriptors: $(lsof -p $DAEMON_PID 2>/dev/null | wc -l)"
echo

mkdir -p "$TEST_DIR"

# Create files one by one, checking daemon health
MAX_FILES=10000
FAILURE_COUNT=0

for i in $(seq 1 $MAX_FILES); do
    # Check if daemon is still alive
    if ! kill -0 $DAEMON_PID 2>/dev/null; then
        echo "[FATAL] Daemon process $DAEMON_PID has died at iteration $i"
        exit 1
    fi

    # Try to create a file
    if ! touch "$TEST_DIR/file_$i" 2>/dev/null; then
        echo "[ERROR] Failed to create file_$i at iteration $i"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))

        # Capture diagnostic info
        echo "[DIAG] Daemon still alive: $(kill -0 $DAEMON_PID 2>/dev/null && echo YES || echo NO)"
        echo "[DIAG] Open FDs: $(lsof -p $DAEMON_PID 2>/dev/null | wc -l || echo UNKNOWN)"
        echo "[DIAG] Memory usage: $(ps -o rss= -p $DAEMON_PID 2>/dev/null || echo UNKNOWN) KB"

        # Try again after a delay
        sleep 0.1
        if touch "$TEST_DIR/file_${i}_retry" 2>/dev/null; then
            echo "[INFO] Retry succeeded - transient error"
        else
            echo "[ERROR] Retry also failed - persistent error"

            # Try to diagnose further
            if ! ls "$TEST_DIR" > /dev/null 2>&1; then
                echo "[FATAL] Cannot even list directory - mount may be dead"
                exit 1
            fi

            # Count how many files we actually created
            ACTUAL=$(find "$TEST_DIR" -type f | wc -l | tr -d ' ')
            echo "[INFO] Successfully created $ACTUAL files before failure"

            break
        fi
    fi

    # Progress indicator
    if [ $((i % 100)) -eq 0 ]; then
        echo "[PROGRESS] Created $i files successfully"
    fi
done

CREATED=$(find "$TEST_DIR" -type f | wc -l | tr -d ' ')

echo
echo "======================================================================"
echo "DIAGNOSTIC SUMMARY"
echo "======================================================================"
echo "Files created: $CREATED"
echo "Failures: $FAILURE_COUNT"
echo "Daemon status: $(kill -0 $DAEMON_PID 2>/dev/null && echo ALIVE || echo DEAD)"

# Cleanup
echo
echo "Cleaning up..."
rm -rf "$TEST_DIR"

if [ $FAILURE_COUNT -gt 0 ]; then
    echo "Result: REPRODUCED - Failed after $CREATED file operations"
    exit 1
else
    echo "Result: No errors detected in $MAX_FILES operations"
    exit 0
fi
