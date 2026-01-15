# Daemon Architecture Analysis & Recommendations

## Current State: daemon/ FUSE Dependencies

### Build Analysis

From `daemon/Makefile.am`:
```makefile
# libafpsl.la - Stateless client library (NO FUSE)
lib_LTLIBRARIES = libafpsl.la
libafpsl_la_SOURCES = stateless.c

# afpfsd - Daemon binary (HAS FUSE)
afpfsd_SOURCES = commands.c daemon.c fuse_int.c fuse_error.c daemon_client.c daemon_fuse.c
afpfsd_LDADD = $(top_builddir)/lib/libafpclient.la -lfuse

# mount_afp - Mount client (NO FUSE)
mount_afp_SOURCES = client.c
mount_afp_LDADD = $(top_builddir)/lib/libafpclient.la $(top_builddir)/daemon/libafpsl.la

# afp_extra - Utility (NO FUSE)
afp_extra_SOURCES = extra.c
afp_extra_LDADD = $(top_builddir)/lib/libafpclient.la $(top_builddir)/daemon/libafpsl.la
```

### FUSE Dependencies Map

**NO FUSE dependency:**
- ✓ `daemon/stateless.c` - Client library (libafpsl.la)
- ✓ `daemon/client.c` - Mount client utility
- ✓ `daemon/extra.c` - Extra utility

**HAS FUSE dependency:**
- ✗ `daemon/afpfsd` - Daemon binary (links -lfuse)
- ✗ `daemon/commands.c` - Includes "fuse_int.h", calls `fuse_mount()`
- ✗ `daemon/daemon_fuse.c` - Implements `fuse_mount()`, FUSE integration
- ✗ `daemon/fuse_int.c` - FUSE operations (includes <fuse.h>)
- ✗ `daemon/fuse_error.c` - FUSE error reporting

### Current Daemon Capabilities

The `daemon/afpfsd` daemon can handle TWO types of operations:

1. **Remote file operations** (stateless mode)
   - Client sends: CONNECT, OPEN, READ, WRITE, CLOSE, STAT, READDIR
   - Daemon executes AFP operations and returns results
   - No FUSE required for this functionality

2. **FUSE mount operations** (FUSE mode)
   - Client sends: MOUNT command with volume URL
   - Daemon calls `fuse_mount()` → starts FUSE filesystem
   - Daemon runs FUSE main loop with local operations
   - Requires FUSE library

**Key finding**: The MOUNT command in `daemon/commands.c` calls `fuse_mount()`, making the entire daemon dependent on FUSE even if clients never use MOUNT.

## Problem Statement

**Goal**: Build `libafpsl.la` and a stateless daemon WITHOUT libfuse dependency

**Use case**: GUI applications (e.g., macOS AFP client) need:
- Stateless client library to talk to daemon
- Daemon to handle AFP protocol operations
- No FUSE filesystem mounting required
- Should work on systems without libfuse installed

**Current blocker**: daemon/afpfsd cannot be built without libfuse because:
1. `commands.c` includes FUSE headers
2. `fuse_mount()` is always compiled in
3. Daemon links against `-lfuse`

## Architecture Options

### Option 1: Two Separate Daemon Binaries (RECOMMENDED)

Create two distinct daemon binaries with different responsibilities:

#### 1a. `afpsld` - Pure Stateless Daemon (NEW)

**Location**: `daemon/` (refactored)

**Purpose**: Handle remote AFP operations via Unix socket

**Note**: Named `afpsld` to avoid conflict with Netatalk's `afpd` (AFP server).

**Features**:
- No FUSE dependency
- Handles stateless commands: CONNECT, ATTACH, DETACH, OPEN, READ, CLOSE, STAT, READDIR
- Does NOT handle MOUNT command
- Small, focused binary
- Works on systems without FUSE

**Build**:
```meson
# daemon/meson.build
afpsld = executable('afpsld',
    sources: ['daemon.c', 'commands.c', 'daemon_client.c'],
    dependencies: [libafpclient_dep],
    # NO fuse_dep
)

libafpsl = library('afpsl',
    sources: ['stateless.c'],
    dependencies: [libafpclient_dep],
    # NO fuse_dep
)
```

**Removed files**:
- `daemon/fuse_int.c` → moved to fuse/
- `daemon/daemon_fuse.c` → moved to fuse/
- `daemon/fuse_error.c` → moved to fuse/ or lib/

**Modified files**:
- `daemon/commands.c` - Remove MOUNT command handler, remove FUSE includes

#### 1b. `afpfsd` - FUSE Filesystem Daemon (EXISTING)

**Location**: `fuse/` (current)

**Purpose**: Mount AFP volumes as local filesystems

**Features**:
- Requires FUSE dependency
- Handles FUSE operations locally
- Handles mount management commands: MOUNT, UNMOUNT, STATUS
- Full FUSE integration

**Build**:
```meson
# fuse/meson.build (already exists)
afpfsd = executable('afpfsd',
    sources: ['daemon.c', 'commands.c', 'fuse_int.c', 'client.c', ...],
    dependencies: [libafpclient_dep, fuse_dep],
)
```

**Architecture Diagram**:
```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                       │
├──────────────────────┬──────────────────────────────────────┤
│   GUI Apps           │   CLI: mount.afp, afpcmd             │
│   (macOS Finder)     │   (FUSE mounts)                      │
└──────┬───────────────┴────────────┬─────────────────────────┘
       │                             │
       │ libafpsl.la                 │ libafpsl.la
       │ (stateless API)             │ (mount commands)
       ↓                             ↓
┌──────────────────┐          ┌─────────────────────────────┐
│   afpsld         │          │   afpfsd                    │
│   (Stateless)    │          │   (FUSE)                    │
├──────────────────┤          ├─────────────────────────────┤
│ • CONNECT        │          │ • MOUNT/UNMOUNT             │
│ • OPEN/READ      │          │ • Local FUSE operations     │
│ • CLOSE/STAT     │          │ • fuse_read/fuse_write      │
│ • READDIR        │          │ • No remote commands        │
│                  │          │                             │
│ NO FUSE dep      │          │ Requires libfuse            │
└────────┬─────────┘          └──────────┬──────────────────┘
         │                               │
         └───────────┬───────────────────┘
                     ↓
         ┌───────────────────────┐
         │   libafpclient.so     │
         │   (AFP Protocol)      │
         └───────────────────────┘
```

**Pros**:
- ✅ Clean separation of concerns
- ✅ `libafpsl.la` and `afpsld` build without FUSE
- ✅ Each daemon optimized for its use case
- ✅ Can run both simultaneously (different sockets)
- ✅ GUI apps work without FUSE installed
- ✅ Clear naming: `afpsld` = stateless daemon, `afpfsd` = FUSE daemon
- ✅ No conflict with Netatalk's `afpd` server

**Cons**:
- Two daemon binaries to maintain
- Need to coordinate socket naming
- Packaging complexity (but manageable)

**Socket Naming**:
- `afpsld`: `/tmp/afpsld-<uid>` (stateless operations)
- `afpfsd`: `/tmp/afpfsd-<uid>-<mountpoint-hash>` (FUSE mounts)

---

### Option 2: Single Daemon with Conditional Compilation

Keep one daemon binary with `#ifdef HAVE_LIBFUSE` blocks.

**Build**:
```meson
afpfsd_deps = [libafpclient_dep]
afpfsd_sources = ['daemon.c', 'commands.c', 'daemon_client.c']

if fuse_dep.found()
    afpfsd_deps += fuse_dep
    afpfsd_sources += ['fuse_int.c', 'daemon_fuse.c', 'fuse_error.c']
    afpfsd_cflags += '-DHAVE_LIBFUSE'
endif

afpfsd = executable('afpfsd',
    sources: afpfsd_sources,
    dependencies: afpfsd_deps,
)
```

**Code changes**:
```c
// daemon/commands.c
case AFP_SERVER_COMMAND_MOUNT:
#ifdef HAVE_LIBFUSE
    response_result = fuse_mount(c, &volumeid);
#else
    response_result = AFP_SERVER_RESULT_NOTSUPPORTED;
    daemon_log_for_client(c, LOG_ERR,
        "MOUNT not supported: daemon built without FUSE\n");
#endif
    break;
```

**Pros**:
- ✅ Single binary name
- ✅ Can build without FUSE when not needed
- ✅ Simpler deployment

**Cons**:
- ✗ Still need FUSE headers/libs for full build
- ✗ Different capabilities depending on build flags
- ✗ Testing complexity (must test both builds)
- ✗ Runtime capability detection needed
- ✗ Less clear separation of concerns

---

### Option 3: Single Daemon with Runtime Mode Selection

One binary, choose mode at startup: `afpfsd --mode=[stateless|fuse]`

**Pros**:
- Single binary
- Flexible runtime configuration

**Cons**:
- ✗ Always requires FUSE to build
- ✗ Most complex implementation
- ✗ Doesn't solve the "build without FUSE" requirement

---

## Recommendation: Option 1 (Two Separate Daemons)

### Implementation Plan

#### Phase 0: Refactor daemon/ to Remove FUSE (NEW PHASE)

**Goal**: Create a pure stateless daemon without FUSE dependencies

**Tasks**:

1. **Split daemon/commands.c**
   - Update `daemon/commands.c` - file operations only
   - Remove MOUNT command handler
   - Remove `#include "fuse_int.h"` and `#include "fuse_error.h"`
   - Keep: CONNECT, ATTACH, DETACH, OPEN, READ, CLOSE, STAT, READDIR, etc.

2. **Remove FUSE files from daemon/**
   - Move `daemon/fuse_int.c` → `fuse/fuse_int.c` (merge with existing)
   - Move `daemon/daemon_fuse.c` → `fuse/daemon_fuse.c`
   - Move `daemon/fuse_error.c` → `lib/fuse_error.c` (shared)
   - Update includes in remaining daemon/ files

3. **Create daemon/meson.build** (without FUSE)
   ```meson
   # Pure stateless daemon (named afpsld to avoid conflict with Netatalk's afpd)
   afpsld_sources = [
       'daemon.c',
       'commands.c',
       'daemon_client.c',
   ]

   afpsld = executable('afpsld',
       sources: afpsld_sources,
       dependencies: [libafpclient_dep, pthread_dep],
       # NO fuse_dep!
       install: true,
   )

   # Stateless client library
   libafpsl = shared_library('afpsl',
       sources: ['stateless.c'],
       dependencies: [libafpclient_dep],
       install: true,
       version: meson.project_version(),
   )
   ```

4. **Update root meson.build**
   ```meson
   # Always build daemon/ (no FUSE required)
   subdir('daemon')

   # Only build fuse/ if FUSE available
   if with_fuse
       subdir('fuse')
   endif
   ```

5. **Update socket naming**
   - `afpsld` listens on: `/tmp/afpsld-<uid>`
   - `afpfsd` listens on: `/tmp/afpfsd-<uid>-<mountpoint>` (existing)
   - Update `SERVER_FILENAME` in `include/afpfsd.h` to use `afpsld`

6. **Update libafpsl.la to connect to afpsld**
   - Modify `daemon/stateless.c:daemon_connect()`
   - Connect to `/tmp/afpsld-<uid>` (afpsld socket)
   - Add auto-start capability for afpsld (not afpfsd)
   - Update `AFPFSD_FILENAME` constant to `"afpsld"`

7. **Test builds**
   ```bash
   # Test 1: Build without FUSE
   meson setup build-nofuse -Denable-fuse=false
   meson compile -C build-nofuse
   # Should build: libafpclient.so, libafpsl.so, afpsld, afp_extra
   # Should NOT build: afpfsd

   # Test 2: Build with FUSE
   meson setup build-fuse -Denable-fuse=true
   meson compile -C build-fuse
   # Should build: everything including afpfsd
   ```

#### Phase 1-4: (From previous REFACTORING_PLAN.md)
- Port improvements from fuse/ to remaining stateless code
- Consolidate shared code
- Migrate cmdline/ to stateless API

### Command Matrix After Refactoring

| Command | afpsld (stateless) | afpfsd (FUSE) | Client |
|---------|-------------------|---------------|---------|
| CONNECT | ✓ Handles | - | libafpsl → afpsld |
| ATTACH | ✓ Handles | - | libafpsl → afpsld |
| DETACH | ✓ Handles | - | libafpsl → afpsld |
| OPEN | ✓ Handles | - | libafpsl → afpsld |
| READ | ✓ Handles | - | libafpsl → afpsld |
| CLOSE | ✓ Handles | - | libafpsl → afpsld |
| STAT | ✓ Handles | - | libafpsl → afpsld |
| READDIR | ✓ Handles | - | libafpsl → afpsld |
| MOUNT | ✗ Not supported | ✓ Handles | libafpsl → afpfsd |
| UNMOUNT | ✗ Not supported | ✓ Handles | libafpsl → afpfsd |
| STATUS | ✗ Not supported | ✓ Handles | libafpsl → afpfsd |

### Migration Path for Existing Code

**For GUI applications using libafpsl.la**:
- No changes required!
- libafpsl.la connects to `afpsld` automatically
- All file operation commands work the same

**For FUSE mount operations**:
- `mount_afp` and `fuse/client.c` connect to `afpfsd`
- MOUNT/UNMOUNT/STATUS commands handled by afpfsd
- No changes to existing fuse/ code

**For cmdline/afpcmd**:
- Will use libafpsl.la to connect to `afpsld`
- No FUSE dependency
- File operations work through stateless API

## Decisions Made

### 1. Daemon naming
✅ **RESOLVED** - Using `afpsld` (AFP stateless daemon) to avoid conflict with Netatalk's `afpd`

### 2. Backward compatibility
✅ **RESOLVED** - NO backward compatibility needed
- Application has minimal user base
- Clean break is acceptable
- No symlinks or compatibility shims required

### 3. Documentation
✅ **RESOLVED** - Minimal documentation approach
- Client applications (libafpsl.la, mount_afp) will auto-start appropriate daemon transparently
- Users don't need to know which daemon is running
- Document in man pages only:
  - `afpsld(8)` - Stateless daemon for remote file operations
  - `afpfsd(8)` - FUSE daemon for mounting AFP volumes
  - Most users never interact with daemons directly

### 4. Packaging
✅ **RESOLVED** - Defer to downstream packagers
- Suggested split:
  - `afpfs-ng-stateless` (afpsld + libafpsl)
  - `afpfs-ng-fuse` (afpfsd, depends on libfuse)
  - `afpfs-ng-cmdline` (afpcmd)
  - `afpfs-ng` (metapackage)
- Let distribution maintainers decide final packaging strategy
