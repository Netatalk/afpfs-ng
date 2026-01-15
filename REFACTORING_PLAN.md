# AFP Client Refactoring Plan

## Executive Summary

This document outlines a comprehensive refactoring plan to consolidate the duplicated code between `daemon/` and `fuse/`, modernize the `daemon/` stateless client implementation, and migrate `cmdline/` (afpcmd) to use the stateless library.

**Important**: See `DAEMON_ARCHITECTURE.md` for detailed analysis of Phase 0 (removing FUSE from daemon/) and the two-daemon architecture (`afpsld` vs `afpfsd`).

## Current State Analysis

### Directory Structure

```
afpfs-ng/
├── lib/              # libafpclient.so - core AFP protocol library
├── fuse/             # Modern FUSE filesystem client (CURRENT, MAINTAINED)
│   ├── client.c      # Mount client, socket management
│   ├── daemon.c      # Daemon main loop, socket listener
│   ├── commands.c    # Mount-focused commands (7 commands)
│   ├── fuse_int.c    # FUSE operations (20+ callbacks)
│   └── fuse_error.c  # Error reporting
├── daemon/           # Legacy stateless client (BITROTTED, OLD BUILD SYSTEM)
│   ├── stateless.c   # Stateless library implementation (libafpsl.la)
│   ├── daemon.c      # Old daemon implementation
│   ├── commands.c    # File operation commands (20+ commands)
│   ├── fuse_int.c    # Old FUSE operations
│   └── fuse_error.c  # Basic error reporting
└── cmdline/          # afpcmd CLI tool
    └── cmdline_afp.c # Uses midlevel API (ml_*) directly
```

### Key Findings

1. **daemon/ is NOT in the Meson build system** - still uses old Makefile.am (autotools)
2. **fuse/ is actively maintained** with modern features:
   - FUSE 2.x, 3.0+, and platform-specific API support
   - Extended attributes (xattr) support
   - macOS-specific optimizations
   - Better error handling
   - Proper file operations (create, flush)
3. **daemon/ has significant bitrot**:
   - Frozen at FUSE 2.9 API
   - Missing xattr support
   - Missing create() and flush() callbacks
   - Security issues in error reporting (fixed filename)
4. **cmdline/ uses midlevel API directly** instead of stateless library
5. **daemon/stateless.c provides useful abstraction** but is disconnected from modern codebase

## Problems to Solve

### Problem 1: daemon/ Bitrot and Build System

**Issue**: daemon/ uses old autotools build system and has fallen behind fuse/ in features.

**Impact**:
- Cannot be built with modern Meson build system
- Missing critical FUSE 3+ support
- Missing xattr support
- Security vulnerabilities in error handling

### Problem 2: Massive Code Duplication

**Issue**: daemon/ and fuse/ share nearly identical implementations of:
- `fuse_int.c` - FUSE operations (~924 lines vs ~532 lines)
- `fuse_error.c` - Error reporting (~172 lines vs ~41 lines)
- `commands.c` - Command processing (different designs but overlapping code)
- `daemon.c` - Daemon main loop

**Impact**:
- Bug fixes must be applied twice
- Features developed in fuse/ don't propagate to daemon/
- Maintenance burden

### Problem 3: cmdline/ Direct Midlevel API Usage

**Issue**: afpcmd uses `ml_*()` functions directly instead of the stateless library (`afp_sl_*()`)

**Impact**:
- Duplicates connection/session management logic
- Cannot leverage daemon-based architecture
- Inconsistent with other clients

## Refactoring Strategy

### Phase 1: Modernize daemon/ with fuse/ Improvements

**Goal**: Port modern features from fuse/ to daemon/ and migrate to Meson build system

#### Tasks:

1. **Port FUSE version support abstraction**
   - Copy FUSE 2.x/3.x conditional compilation from fuse/fuse_int.c
   - Add platform detection (macOS Darwin, Linux, BSD)
   - Add FUSE_NEW_API support

2. **Port extended attributes (xattr) support**
   - Copy xattr functions from fuse/fuse_int.c:
     - `fuse_getxattr()`
     - `fuse_setxattr()`
     - `fuse_listxattr()`
     - `fuse_removexattr()`
   - Add header detection for sys/xattr.h, sys/extattr.h, attr/xattr.h

3. **Port new FUSE operations**
   - Add `fuse_create()` callback
   - Add `fuse_flush()` callback
   - Port improved `fuse_truncate()` implementation

4. **Improve error handling**
   - Replace daemon/fuse_error.c with fuse/fuse_error.c
   - Port `fuse_result_to_string()` and `mount_errno_to_string()`
   - Fix security issue (mkstemp vs fixed filename)

5. **Port daemon improvements**
   - Add SIGCHLD handler for process management
   - Port safety checks and NULL pointer guards
   - Improve logging (DEBUG vs WARNING discrimination)

6. **Migrate to Meson build system**
   - Create `daemon/meson.build`
   - Build libafpsl.la (stateless library)
   - Build afpfsd daemon (if needed for legacy support)
   - Build mount_afp and afp_extra
   - Add conditional compilation options

7. **Remove FUSE-specific code from daemon/**
   - Identify code paths that only make sense in FUSE context
   - Remove or abstract FUSE dependencies where appropriate
   - Ensure stateless library (libafpsl.la) has no FUSE dependencies

### Phase 2: Refactor to Reduce Code Duplication

**Goal**: Create shared components between daemon/ and fuse/ to eliminate duplication

#### Strategy Options:

**Option A: Shared Library Approach** (Recommended)
- Create `lib/fuse_common.c` for shared FUSE operations
- Create `lib/daemon_common.c` for shared daemon code
- Both daemon/ and fuse/ link against these shared components
- Keep daemon-specific and FUSE-specific code separate

**Option B: Consolidation Approach**
- Merge daemon/ into fuse/ with conditional compilation
- Use `#ifdef STATELESS_CLIENT` to differentiate
- Single codebase with two build targets
- Risk: more complex codebase

**Option C: Keep Separate** (Status Quo)
- Only share bug fixes manually
- Accept some duplication for clarity
- Use automated diffing/syncing tools

#### Recommended: Option A Tasks

1. **Create lib/fuse_common.c**
   - Extract common FUSE operation implementations
   - Create shared helpers for:
     - Path translation
     - Error code mapping
     - File handle management
     - Directory listing

2. **Create lib/daemon_common.c**
   - Extract shared daemon infrastructure:
     - Socket creation and management
     - Signal handling
     - Client connection handling
     - Command dispatch framework

3. **Refactor daemon/fuse_int.c**
   - Use shared implementations from lib/fuse_common.c
   - Keep only daemon-specific logic

4. **Refactor fuse/fuse_int.c**
   - Use shared implementations from lib/fuse_common.c
   - Keep only FUSE-specific logic

5. **Create shared error reporting**
   - Move error reporting to lib/error_reporting.c
   - Both daemon/ and fuse/ use same implementation

### Phase 3: Migrate cmdline/ to Stateless Library

**Goal**: Refactor afpcmd to use `afp_sl_*()` API instead of `ml_*()` API

#### Analysis:

Current cmdline/cmdline_afp.c usage:
- Direct midlevel API calls: `ml_readdir()`, `ml_open()`, `ml_read()`, `ml_write()`, etc.
- Direct volume access: `struct afp_volume *vol`
- Direct server access: `struct afp_server *server`

Target stateless library API (afpsl.h):
- Connection: `afp_sl_connect()`, `afp_sl_getvolid()`
- Volume ops: `afp_sl_attach()`, `afp_sl_detach()`
- File ops: `afp_sl_stat()`, `afp_sl_open()`, `afp_sl_read()`, `afp_sl_close()`
- Directory ops: `afp_sl_readdir()`

#### Tasks:

1. **Create migration compatibility layer**
   - Add wrapper functions in cmdline/ if needed
   - Map current command structure to stateless API
   - Handle volumeid_t and serverid_t opaque types

2. **Refactor connection management**
   - Replace `struct afp_server *server` with `serverid_t`
   - Replace `struct afp_volume *vol` with `volumeid_t`
   - Use `afp_sl_connect()` for server connection
   - Use `afp_sl_attach()` for volume mounting

3. **Refactor file operations**
   - Replace `ml_open()` → `afp_sl_open()`
   - Replace `ml_read()` → `afp_sl_read()`
   - Replace `ml_write()` → `afp_sl_write()` (if available, or extend API)
   - Replace `ml_close()` → `afp_sl_close()`
   - Replace `ml_getattr()` → `afp_sl_stat()`

4. **Refactor directory operations**
   - Replace `ml_readdir()` → `afp_sl_readdir()`

5. **Extend stateless library if needed**
   - Check if all ml_* operations have afp_sl_* equivalents
   - Add missing operations to daemon/stateless.c:
     - `afp_sl_write()` (appears missing)
     - `afp_sl_mkdir()` (appears missing)
     - `afp_sl_rmdir()` (appears missing)
     - `afp_sl_unlink()` (appears missing)
     - `afp_sl_rename()` (appears missing)
     - `afp_sl_chmod()` (appears missing)
     - `afp_sl_truncate()` (appears missing)

6. **Update daemon/commands.c**
   - Ensure daemon can handle all commands from cmdline
   - Add missing command handlers if needed

7. **Test migration**
   - Verify all afpcmd commands work through stateless API
   - Performance testing
   - Error handling validation

## Implementation Roadmap

### Stage 0: Remove FUSE from daemon/ (Week 1)
- Create `afpsld` (stateless daemon) without FUSE dependency
- Split daemon/ into stateless components only
- Remove daemon/fuse_int.c, daemon_fuse.c, fuse_error.c
- Create daemon/meson.build
- Update socket naming to use `afpsld`
- Test builds with and without FUSE

### Stage 1: Foundation (Weeks 2-3)
- ✓ Complete analysis (current)
- Port critical bug fixes from fuse/ to daemon/ (stateless parts only)
- Ensure libafpsl.la builds and works

### Stage 2: Modernization (Weeks 4-5)
- Port improvements to fuse/afpfsd if needed
- Ensure fuse/afpfsd has all modern FUSE 3+ support
- No need to port FUSE features to daemon/ (it's FUSE-free now!)

### Stage 3: Consolidation (Weeks 6-7)
- Create shared library components (lib/daemon_common.c for socket handling)
- Refactor daemon/afpsld and fuse/afpfsd to use shared daemon infrastructure
- Consolidate common protocol handling code

### Stage 4: cmdline Migration (Weeks 8-9)
- Extend stateless library with missing operations
- Refactor cmdline/cmdline_afp.c to use afp_sl_* API
- Testing and validation

### Stage 5: Cleanup (Week 10)
- Remove deprecated code
- Update documentation
- Performance optimization

## Risk Assessment

### High Risk Items

1. **Breaking existing functionality**: Extensive testing required
   - Mitigation: Comprehensive test suite, phased rollout
2. **API incompatibilities**: stateless library may not support all operations
   - Mitigation: Extend API before migration
3. **Performance regression**: Stateless API adds overhead
   - Mitigation: Benchmark before/after, optimize critical paths

### Medium Risk Items

1. **Build system complexity**: Meson migration may break existing builds
   - Mitigation: Keep Makefile.am temporarily for fallback
2. **Platform-specific issues**: macOS, Linux, BSD differences
   - Mitigation: Test on all platforms early

### Low Risk Items

1. **Code organization**: Refactoring may temporarily reduce readability
   - Mitigation: Good documentation, clear module boundaries

## Success Criteria

1. **daemon/afpsld builds without FUSE dependency** via Meson
2. **fuse/afpfsd builds with FUSE dependency** via Meson
3. **Code duplication reduced by >60%** in shared components
4. **afpcmd uses stateless library** for all operations
5. **All existing functionality preserved** - no regressions
6. **Performance within 10%** of baseline
7. **All platforms supported** (macOS, Linux, BSD)
8. **Can build without libfuse** - afpsld + libafpsl work standalone

## Open Questions

1. **Should daemon/afpfsd be deprecated?** Or is it needed for specific use cases?
2. **Should we maintain two FUSE clients?** Or merge into one with build options?
3. **What is the future of the stateless library?** Is it the primary API going forward?
4. **Are there GUI applications depending on current daemon/ implementation?**

## Next Steps

1. Review and approve this plan
2. Set up development branch
3. Create detailed task breakdown for Phase 1
4. Begin Meson migration for daemon/
