# AFP Client Refactoring Summary

## Quick Overview

This refactoring addresses three main problems:

1. **daemon/ has bitrotted** - missing features from fuse/, old build system
2. **daemon/ and fuse/ have massive code duplication** - hard to maintain
3. **cmdline/ (afpcmd) doesn't use the stateless library** - duplicates connection logic

## Key Decision: Two Daemon Architecture

We will create **two separate daemon binaries**:

### `afpsld` - AFP Stateless Daemon
- **Location**: `daemon/`
- **Purpose**: Remote file operations via stateless API
- **Dependencies**: libafpclient.so only (NO FUSE)
- **Socket**: `/tmp/afpsld-<uid>`
- **Commands**: CONNECT, ATTACH, OPEN, READ, CLOSE, STAT, READDIR
- **Use case**: GUI apps, scripts, afpcmd

### `afpfsd` - AFP FUSE Daemon
- **Location**: `fuse/`
- **Purpose**: Mount AFP volumes as local filesystems
- **Dependencies**: libafpclient.so + libfuse
- **Socket**: `/tmp/afpfsd-<uid>-<mountpoint>`
- **Commands**: MOUNT, UNMOUNT, STATUS (+ local FUSE operations)
- **Use case**: mount.afp, filesystem mounting

## Why Two Daemons?

1. ✅ Build afpsld + libafpsl **without libfuse** dependency
2. ✅ Clean separation: stateless operations vs FUSE mounting
3. ✅ GUI apps work on systems without FUSE
4. ✅ Each daemon optimized for its specific purpose
5. ✅ No conflict with Netatalk's `afpd` server

## Architecture Diagram

```
Client Apps
    ↓
libafpsl.la (stateless client library)
    ↓
┌─────────────┬──────────────┐
│   afpsld    │   afpfsd     │
│  (stateless)│   (FUSE)     │
│  NO FUSE    │  WITH FUSE   │
└─────────────┴──────────────┘
    ↓
libafpclient.so (AFP protocol)
```

## Implementation Phases

### Phase 0: Remove FUSE from daemon/ ✅ COMPLETE
- ✅ Created `afpsld` without FUSE dependency
- ✅ Removed daemon/fuse_int.c, daemon_fuse.c, fuse_error.c (moved to attic/)
- ✅ Created daemon/meson.build
- ✅ Updated socket naming to use afpsld

### Phase 1: Foundation ✅ COMPLETE
**Critical bug fixes ported from fuse/ to daemon/:**
- ✅ Fixed buffer overflow vulnerabilities with strlcpy() bounds checking
- ✅ Added SIGCHLD handler to prevent zombie processes
- ✅ Added NULL pointer checks in volume operations
- ✅ Added malloc() error checking throughout commands.c
- ✅ Fixed unsafe snprintf() calls with proper size calculations
- ✅ Fixed format string security issue in daemon_log_for_client()
- ✅ Verified libafpsl.so and afpsld build successfully

### Phase 2: Modernization ✅ SKIPPED
- Already completed prior to refactoring project
- fuse/afpfsd has all modern features (FUSE 2.x, 3.x, xattr, platform support)

### Phase 3: Consolidation (NEXT)
- Create shared daemon infrastructure (lib/daemon_common.c)
- Reduce code duplication

### Phase 4: cmdline Migration (Weeks 8-9)
- Extend stateless library API
- Migrate afpcmd to use afp_sl_* functions

### Phase 5: Cleanup (Week 10)
- Documentation, optimization, polish

## Build Configuration Examples

**Without FUSE**:
```bash
meson setup build -Denable-fuse=false
meson compile -C build
# Builds: libafpclient.so, libafpsl.so, afpsld, afp_extra, afpcmd
# Does NOT build: afpfsd
```

**With FUSE**:
```bash
meson setup build -Denable-fuse=true
meson compile -C build
# Builds: Everything including afpfsd
```

## Documentation

- `REFACTORING_PLAN.md` - Comprehensive refactoring plan with all phases
- `DAEMON_ARCHITECTURE.md` - Detailed architecture analysis and Phase 0 implementation
- `AGENTS.md` - Project overview and existing documentation

## Key Changes from Original Plan

**Original idea**: Modernize daemon/ by porting FUSE features from fuse/

**New approach**:
- **Remove FUSE entirely from daemon/** → create `afpsld` (stateless only)
- Keep FUSE in fuse/ → `afpfsd` remains the FUSE daemon
- Both daemons coexist, serve different purposes

This is cleaner, more maintainable, and solves the "build without FUSE" requirement.

## Progress Status

### ✅ Completed Phases

#### Phase 0 (Complete)
Successfully removed FUSE dependencies from daemon/ directory:
- Moved FUSE-specific files (fuse_int.c, daemon_fuse.c, fuse_error.c) to attic/
- Created daemon/meson.build for building afpsld without libfuse
- Renamed daemon binary from afpfsd to afpsld to avoid naming conflicts
- Updated socket naming to use /tmp/afpsld-<uid>

#### Phase 1 (Complete)
Ported critical bug fixes and safety improvements from fuse/ to daemon/:

**Security Fixes:**
- daemon/daemon.c:122, 178 - Replaced unsafe strcpy() with strlcpy() + bounds checking
- daemon/daemon.c:311 - Replaced sprintf() with snprintf()
- daemon/daemon.c:78-80 - Fixed format string vulnerability in logging function
- daemon/commands.c:161, 168, 177 - Fixed all snprintf() calls to use sizeof()

**Memory Safety:**
- daemon/commands.c - Added malloc() error checking at 8 critical allocation sites
- daemon/daemon.c:115-119 - Added NULL pointer validation in daemon_unmount_volume()

**Process Management:**
- daemon/daemon.c:57-68 - Added SIGCHLD handler to prevent zombie processes
- daemon/daemon.c:336-342 - Installed signal handler in main() before starting main loop

**Build Status:**
- ✅ daemon/afpsld compiles successfully
- ✅ daemon/libafpsl.so compiles successfully
- ⚠️  Some compiler warnings remain (unused variables, sign comparison) but no errors

#### Phase 2 (Complete - Pre-existing)
FUSE modernization was completed prior to this refactoring project:
- ✅ FUSE 2.x and 3.x API support with conditional compilation
- ✅ Platform-specific support (macOS Darwin, Linux, BSD)
- ✅ Extended attributes (xattr) support
- ✅ Modern FUSE operations (create, flush, truncate)
- ✅ Enhanced error handling and logging

### 🔄 Next Steps: Phase 3 - Consolidation

Phase 3 will focus on creating shared daemon infrastructure to reduce code duplication between daemon/ and fuse/.

**Goals:**
- Extract common socket management code
- Create shared daemon infrastructure (lib/daemon_common.c)
- Reduce code duplication between afpsld and afpfsd
- Consolidate common protocol handling

**Estimated remaining work:**
- Phase 3: Consolidation (shared daemon infrastructure)
- Phase 4: cmdline Migration (afpcmd to use stateless library)
- Phase 5: Cleanup (documentation, optimization)
