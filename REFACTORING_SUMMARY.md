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

### Phase 0: Remove FUSE from daemon/ (Week 1) ⭐ NEW
- Create `afpsld` without FUSE dependency
- Remove daemon/fuse_int.c, daemon_fuse.c, fuse_error.c
- Create daemon/meson.build
- Update socket naming

### Phase 1: Foundation (Weeks 2-3)
- Port bug fixes from fuse/ to daemon/
- Ensure libafpsl builds correctly

### Phase 2: Modernization (Weeks 4-5)
- Ensure fuse/afpfsd has all modern features
- (No need to modernize daemon/ FUSE code - it's gone!)

### Phase 3: Consolidation (Weeks 6-7)
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

## Next Steps

1. ✅ Review and approve architecture (DONE)
2. ✅ Choose daemon name: `afpsld` (DONE)
3. Create feature branch: `refactor/split-daemons`
4. Implement Phase 0 from DAEMON_ARCHITECTURE.md
5. Test both build configurations

## Key Changes from Original Plan

**Original idea**: Modernize daemon/ by porting FUSE features from fuse/

**New approach**:
- **Remove FUSE entirely from daemon/** → create `afpsld` (stateless only)
- Keep FUSE in fuse/ → `afpfsd` remains the FUSE daemon
- Both daemons coexist, serve different purposes

This is cleaner, more maintainable, and solves the "build without FUSE" requirement.
