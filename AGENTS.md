# afpfs-ng AI Coding Agent Instructions

## Project Overview

**afpfs-ng** is an Apple Filing Protocol (AFP) client library and FUSE filesystem for accessing AFP shares from macOS/Linux/BSD.

## Architecture

Three-layer architecture (see `docs/DEVELOPER.md`):

```text
┌───────────────────────────────────────┐
│ Clients: FUSE (afpfsd) | CLI (afpcmd) │
├───────────────────────────────────────┤
│ libafpclient.so                       │
│  ├─ Midlevel API (ml_*)               │ ← Use this layer
│  ├─ Lowlevel API (ll_*)               │ ← Only used via Midlevel
│  └─ Protocol API (afp_*)              │ ← Almost never use directly
├───────────────────────────────────────┤
│ AFP/DSI Protocol Engine               │
└───────────────────────────────────────┘
```

**Key directories**:

- `lib/` - libafpclient core (midlevel.c, proto_*.c, dsi.c)
- `fuse/` - FUSE filesystem client (fuse_int.c, daemon.c)
- `cmdline/` - Interactive CLI client
- `include/` - Public APIs (afp.h, midlevel.h, afp_protocol.h)

## Build System (Meson)

**Setup**:

- `meson setup build -Dbuildtype=release|debug`
- Debug builds get `-DDEBUG` → enables `DEBUG_DSI` and `DEBUG_LOOP` logging
- FUSE version detected automatically → sets `FUSE_USE_VERSION=29` or `35`

**Conditional features** (see `meson.build`):

- `with_crypt` (DHX/DHX2 UAMs) requires libgcrypt + libgmp
- `with_fuse` requires FUSE 2.9+ or FUSE 3.0+
- `with_afpcmd` requires ncurses + readline/libedit

**Build**: `meson compile -C build`
**Install**: `sudo meson install -C build`

## Authentication (UAMs)

**Available UAMs** (see `docs/FEATURES.md`, `lib/uams.c`):

- `No User Authent` (anonymous/guest) - always available
- `Cleartxt Passwrd` - always available
- `Randnum Exchange`, `2-Way Randnum Exchange`, `DHCAST128`, `DHX2` - **only if built with libgcrypt**

**URL format**:

- `afp://[user[;AUTH=uamname][:password]@]server[:port]/volume[/path]`
- `afp://guest;AUTH=No User Authent:@server/vol` (anonymous)
- `afp://user:pass@server/vol` (auto-select best UAM)
- `afp://user;AUTH=DHX2:pass@server/vol` (force DHX2)

## Core Data Structures

```c
struct afp_volume {
    unsigned short volid;
    struct afp_server *server;
    struct afp_file_info *open_forks;  // Linked list of open files
    pthread_mutex_t open_forks_mutex;
    struct did_cache_entry *did_cache_base;  // Directory ID cache
    unsigned int extra_flags;  // VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN, etc.
    void *priv;  // FUSE/CLI-specific context
};

struct afp_file_info {
    unsigned short forkid;  // Server-assigned fork ID (critical!)
    unsigned long long size;  // Cached size - MUST update after writes
    unsigned int did;  // Directory ID of parent
    char name[AFP_MAX_PATH];
    struct afp_file_info *next;  // For open_forks list
};
```

## Common Pitfalls

1. **Netatalk chmod quirks**: Server type `AFPFS_SERVER_TYPE_NETATALK` with `VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN`
only supports `AFP_CHMOD_ALLOWED_BITS_22`. See `lib/midlevel.c:75-85`.

2. **FUSE operation order**: `create() → write() → flush() → getattr() → release()`.
Flush is critical on macOS.

3. **AFP error codes**: Return values like `kFPAccessDenied` must be mapped to errno (`-EACCES`).
See `fuse/fuse_error.c`.

4. **Thread safety**: libafpclient spawns threads and overrides signals.
Use provided loop, don't write custom `select()` loops.

5. **Path translation**: `unixpath_to_afppath()` converts `/` to `:` for AFP protocol.
See `lib/utils.c`.

## Development Workflow

**Debug logging**: Build with `-Dbuildtype=debug` and check stderr or syslog:

```shell
meson setup build -Dbuildtype=debug
meson compile -C build
sudo ./build/fuse/afpfsd 2>&1 | tee debug.log
```

**Testing**: See `test/Makefile` for FUSE mount/unmount tests requiring an AFP server.

When built with DEBUG, `afpcmd` has a *test* menu option for internal function tests.

**Code style**:

- `.editorconfig` settings for shell scripts (4-space tabs, LF endings).
- `.astylerc` contains Astyle configuration for C code.
- `.markdownlint.yaml` for Markdown files.
- `.yamlfmt.yaml` for YAML files.

Run `./codefmt.sh` for formatting.

## When Modifying FUSE Operations

1. Check if operation has platform-dependent signature
2. For write operations, ensure flush is properly implemented
3. Update cached `fp->size` when extending files
4. Test on both Linux and macOS if possible

## When Adding Multi-Mount Features

1. **Mountpoint handling**: Always extract and resolve absolute path
   - Use `resolve_mountpoint()` to convert relative → absolute paths
   - Pass to `daemon_connect(mountpoint)` for correct socket selection

2. **Socket naming**: `get_daemon_filename()` handles platform logic
   - Never hardcode socket names in client code
   - Let `get_daemon_filename()` compute based on platform + mountpoint

3. **Daemon startup**: `start_afpfsd(mountpoint)` handles everything
   - Computes socket ID internally
   - Passes it to daemon via `--socket-id` argument
   - Maintains backward compatibility

4. **Platform differences**: Use `#ifdef __APPLE__` only in `get_daemon_filename()`
   - macOS: per-mount sockets (unique hash per path)
   - Linux: shared socket (ignores mountpoint)

## Key Files Reference

- `fuse/fuse_int.c` - All FUSE operations, platform detection
- `fuse/client.c` - Mount client, socket management, multi-mount logic
  - `get_daemon_filename()` - platform-specific socket naming
  - `daemon_connect()` - IPC with daemon, handles startup
  - `start_afpfsd()` - daemon fork/exec with socket ID
  - `resolve_mountpoint()` - convert relative → absolute paths
- `fuse/daemon.c` - Daemon main loop, socket listener
  - `main()` - accepts `--socket-id` for per-mount mode
- `lib/midlevel.c` - High-level API (ml_open, ml_write, ml_close, etc.)
- `lib/proto_fork.c` - AFP fork operations (afp_flushfork, afp_setforkparms)
- `lib/dsi.c` - DSI protocol transport layer
- `include/afp.h` - Core data structures
- `include/afp_protocol.h` - AFP protocol constants (kFPNoErr, etc.)
