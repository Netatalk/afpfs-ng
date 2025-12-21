#!/bin/bash
# Master test runner for I/O error reproduction
# Runs all test suites multiple times to catch non-deterministic failures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOUNT_POINT="${1:-mnt}"
ITERATIONS="${2:-10}"

# Validate mount point
if [ ! -d "$MOUNT_POINT" ]; then
    echo "Error: Mount point '$MOUNT_POINT' does not exist"
    echo "Usage: $0 <mount_point> [iterations]"
    exit 1
fi

# Check if it's actually mounted
if ! mount | grep -q "$MOUNT_POINT"; then
    echo "Warning: '$MOUNT_POINT' does not appear to be mounted"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "======================================================================"
echo "I/O Error Reproduction Test Suite"
echo "======================================================================"
echo "Mount point: $MOUNT_POINT"
echo "Iterations: $ITERATIONS"
echo "Start time: $(date)"
echo "======================================================================"
echo

# Test configurations: script_name num_items parallelism
declare -a TESTS=(
    "test_parallel_mkdir.sh:100:10"
    "test_parallel_create.sh:100:10"
    "test_parallel_write.sh:50:10"
    "test_rapid_churn.sh:1000:1"
)

# Statistics tracking
declare -A TOTAL_RUNS
declare -A TOTAL_FAILURES

# Make all scripts executable
chmod +x "$SCRIPT_DIR"/*.sh

# Run each test multiple times
for test_config in "${TESTS[@]}"; do
    IFS=':' read -r test_script param1 param2 <<< "$test_config"
    test_name="${test_script%.sh}"

    echo "======================================================================"
    echo "Running: $test_name ($ITERATIONS iterations)"
    echo "======================================================================"

    TOTAL_RUNS[$test_name]=0
    TOTAL_FAILURES[$test_name]=0

    for i in $(seq 1 "$ITERATIONS"); do
        echo "[$test_name] Iteration $i/$ITERATIONS"

        if "$SCRIPT_DIR/$test_script" "$MOUNT_POINT" "$param1" "$param2"; then
            echo "[$test_name] Iteration $i: PASS"
        else
            echo "[$test_name] Iteration $i: FAIL *** ERROR DETECTED ***"
            TOTAL_FAILURES[$test_name]=$((${TOTAL_FAILURES[$test_name]} + 1))
        fi

        TOTAL_RUNS[$test_name]=$((${TOTAL_RUNS[$test_name]} + 1))
        echo

        # Small delay between iterations
        sleep 0.5
    done
done

# Print summary report
echo "======================================================================"
echo "TEST SUMMARY"
echo "======================================================================"
echo "End time: $(date)"
echo

TOTAL_ERRORS=0
for test_config in "${TESTS[@]}"; do
    IFS=':' read -r test_script _ _ <<< "$test_config"
    test_name="${test_script%.sh}"

    runs=${TOTAL_RUNS[$test_name]}
    failures=${TOTAL_FAILURES[$test_name]}
    passes=$((runs - failures))

    if [ $failures -eq 0 ]; then
        status="✓ PASS"
    else
        status="✗ FAIL"
        TOTAL_ERRORS=$((TOTAL_ERRORS + failures))
    fi

    failure_rate="0.0%"
    if [ $runs -gt 0 ] && [ $failures -gt 0 ]; then
        failure_rate=$(awk "BEGIN {printf \"%.2f%%\", ($failures/$runs)*100}")
    fi

    printf "%-30s %s (%d/%d passed, %s failure rate)\n" \
        "$test_name:" "$status" "$passes" "$runs" "$failure_rate"
done

echo "======================================================================"

if [ $TOTAL_ERRORS -eq 0 ]; then
    echo "Result: ALL TESTS PASSED"
    exit 0
else
    echo "Result: FAILURES DETECTED ($TOTAL_ERRORS total errors)"
    echo
    echo "Next steps:"
    echo "  1. Re-run failing tests individually with increased iterations"
    echo "  2. Enable debug build: meson setup build -Dbuildtype=debug"
    echo "  3. Capture stderr during test runs for error analysis"
    exit 1
fi
