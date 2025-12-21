# I/O Error Reproduction Tests

Minimal test suite for reproducing non-deterministic I/O errors during concurrent file operations on AFP-mounted filesystems.

## Problem Description

When copying large numbers of small files to a FUSE-mounted AFP volume, non-deterministic I/O errors occur with very low frequency (~0.0002% failure rate). Errors manifest as:

- `Input/output error` during `mkdir()` operations
- `Input/output error` during file creation
- Different files fail on each run
- More likely with high parallelism (e.g., `cp -r`)

## Platform-Specific Issues

### Linux (Fedora)

- `Input/output error` during file/directory creation
- Failures occur during write operations
- ~0.0002% failure rate

### macOS

- **Different failure mode:** `rm -rf` operations fail with "Directory not empty"
- Copy operations may succeed, but subsequent deletions fail intermittently
- Suggests directory entry cache inconsistency or delayed unlink propagation

## Test Suite

Five focused tests isolate different failure modes:

### Test A: Parallel Directory Creation

**Script:** `test_parallel_mkdir.sh`
**Tests:** DID cache handling during concurrent mkdir operations
**Default:** 100 directories, parallelism=10

```bash
./test_parallel_mkdir.sh mnt [num_dirs] [parallelism]
```

**What it reveals:** DID cache corruption or directory creation race conditions

### Test B: Parallel File Creation

**Script:** `test_parallel_create.sh`
**Tests:** Fork ID allocation and open_forks list management
**Default:** 100 files, parallelism=10

```bash
./test_parallel_create.sh mnt [num_files] [parallelism]
```

**What it reveals:** Fork ID exhaustion/collision, open_forks mutex issues

### Test C: Parallel File Writes

**Script:** `test_parallel_write.sh`
**Tests:** Concurrent write/flush operations and file size updates
**Default:** 50 files of 10KB each, parallelism=10

```bash
./test_parallel_write.sh mnt [num_files] [parallelism] [file_size_kb]
```

**What it reveals:** Write/flush race conditions, DSI request/reply misalignment

### Test D: Rapid File Churn

**Script:** `test_rapid_churn.sh`
**Tests:** Fork lifecycle management under rapid create/delete cycles
**Default:** 1000 sequential cycles

```bash
./test_rapid_churn.sh mnt [num_cycles]
```

**What it reveals:** Resource cleanup issues, fork ID reuse problems

### Test E: Recursive Directory Deletion (macOS-specific)

**Script:** `test_recursive_delete.sh`
**Tests:** Directory entry cache consistency during `rm -rf` operations
**Default:** Depth=3, 10 files per directory

```bash
./test_recursive_delete.sh mnt [depth] [files_per_dir]
```

**What it reveals:** Directory entry cache stale data, unlink propagation delays

Creates a nested directory structure (similar to `.git/modules/subprojects/...`) and attempts recursive deletion.
On macOS, this reproduces "Directory not empty" errors.

## Quick Start

### 1. Mount your AFP volume

```bash
mount_afpfs "afp://;AUTH=No User Authent@localhost/afp1" mnt
```

### 2. Run all tests

```bash
./run_all_tests.sh mnt 10
```

This runs each test 10 times and reports failure rates.

### 3. Run individual tests

For targeted reproduction:

```bash
# Test just parallel writes, 100 iterations
for i in {1..100}; do
    echo "Run $i"
    ./test_parallel_write.sh mnt
done
```

## Interpreting Results

### Success Patterns

- **All tests pass consistently** → Issue may be specific to full `cp -r` workflow
- **Tests pass at low parallelism** → Tune parallelism to find threshold

### Failure Patterns

- **Test A fails** → DID cache corruption in directory operations
- **Test B/C fail, Test A passes** → Fork ID or open_forks list issues
- **Test D fails** → Fork lifecycle or cleanup problems
- **Test E fails (macOS)** → Directory entry cache not invalidated on unlink
- **Random failures across tests** → Timing-dependent race condition

### Failure Rate Analysis

```
Original issue: 8 failures / 3840 files = 0.21% failure rate
Target: Reproduce similar rate with minimal test case
```

If test achieves >0.1% failure rate over 100+ runs, it's a valid reproducer.

## Debugging Workflow

### Step 1: Establish Baseline

```bash
# Run each test 100 times
for test in test_*.sh; do
    echo "Testing $test"
    for i in {1..100}; do
        ./"$test" mnt || echo "FAIL at iteration $i"
    done
done
```

### Step 2: Amplify the Issue

Increase parallelism or item counts:

```bash
# Stress test with higher parallelism
./test_parallel_write.sh mnt 100 20
./test_parallel_write.sh mnt 200 30
```

### Step 3: Capture Error Context

```bash
# Run with debug build and capture stderr
meson setup build_debug -Dbuildtype=debug
meson compile -C build_debug
sudo ./build_debug/fuse/afpfsd 2> afpfs_errors.log &

# Mount and run tests
mount_afpfs "afp://..." mnt
./run_all_tests.sh mnt 50
```

### Step 4: Reduce Variables

Test serialization to confirm race condition:

```bash
# Force single-threaded operation
./test_parallel_write.sh mnt 100 1
```

If errors disappear, confirms concurrency issue.

## Expected Outcomes

Based on the failure patterns, these tests will help identify:

1. **Which layer is failing:**
   - FUSE operations (fuse_int.c)
   - Midlevel API (midlevel.c)
   - DSI protocol layer (dsi.c)

2. **Which resource is exhausted/corrupted:**
   - Fork IDs
   - DID cache entries
   - DSI request queue
   - Mutex contention

3. **Timing characteristics:**
   - Minimum parallelism to trigger
   - Failure rate vs. concurrency level
   - Whether localhost-only or network-dependent

## Next Steps After Reproduction

Once you've identified a reliable reproducer:

1. **Add instrumentation** - Patch error-path logging into suspected code
2. **Compare traces** - Run passing vs. failing iterations, diff logs
3. **Isolate resource** - Add counters for fork IDs, DID cache size, etc.
4. **Test fix** - Apply patch and re-run reproducer 1000+ times

## Files

```
test/stress/
├── README.md                    # This file
├── run_all_tests.sh             # Master test runner
├── test_parallel_mkdir.sh       # Test A: Directory creation
├── test_parallel_create.sh      # Test B: File creation
├── test_parallel_write.sh       # Test C: File writes
├── test_rapid_churn.sh          # Test D: Rapid churn
└── test_recursive_delete.sh     # Test E: Recursive deletion (macOS)
```

## Requirements

- Mounted AFP volume (via afpfsd)
- Standard Unix utilities: `seq`, `xargs`, `dd`, `find`
- Bash 4.0+

## Notes

- Tests create temporary directories with PID suffix for isolation
- All tests clean up after themselves (even on failure)
- Progress indicators help monitor long-running test suites
- Each test is independent and can run in any order
