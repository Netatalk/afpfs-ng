# Developer Documentation for afpfs-ng

The Apple Filing Protocol is a network filesystem that is commonly used
to share files between Apple Macintosh computers.

A network connection must be established to a server and maintained.  
afpfs-ng provides a basic library on which to build full clients
(called libafpclient), and a sample of clients (FUSE and a simple
command line).

## Architectural Diagram

```text
                                +------+------+------+
                                | fuse | kio  | gio  |
                                +--------------------+
                                             afpsl.h, afpfsd_conn
                                +--------------------+
                                | afpfsd             |
                                +--------------------+


                +----------+
                | cmdline  |
 afp.h          +----------+---+---+---------+
                | midlevel |   |   | command |
 libafpclient   +----------+   |   |
                |   lowlevel   |   |
                +--------------+   |
                |   proto_*        |
                +------------------+
                | Engine                     |
                +----------------------------+
```

## libafpclient

This is a shared library (libafpclient.so) that implements the basic DSI
and AFP communication requirements for connecting to AFP servers.  An
AFP client uses this library through several APIs, defined later.

You should use libafpclient in a situation where you have a stateful process.
This means that the process that's handling your client lives for the duration
of the transactions required.

A key point to know when building libafpclients is that libafpclient will
spawn threads and override signals.  Asynchronous events need to be
hooked into a loop provided by libafpclient.  You cannot write your own
select() loop!

The major subcomponents of libafpclient are all in the lib/ directory.

They are:

### Midlevel

This is an API that simplifies the AFP functions that does some simplification
of the protocol, such as calling multiple AFP functions to perform a basic
task.  This is the most likely API set to use when using libafpclient
directly.

Typically, a midlevel function will:

- translate filenames for you
- handle metainformation (resource forks, special files)
- call the lowlevel function

### Lowlevel

This is an API that handles many AFP functions, while taking care of some
AFP details, such as behaviour differences between AFP versions and
situations where servers don't adhere to the exact protocol.

An example of this is when listing a directory; ll_readdir() will
figure out what AFP version is being used, and either call protocols
afp_enumerateext() for AFP 2.x or afp_enumerateext2 for 3.x (which can
handle larger file lists).

These are implemented in lib/midlevel.c.  The API is exposed in midlevel.h.

You should generally not use these functions.

### Protocol

This is the raw API that exposes individual AFP functions, this
includes things like afp_listextattr().

These are implemented in lib/proto_* files and exposed in afp.h.

You should almost never use this set of functions.

Other topics

- startup
- metainformation
- scheduling

## Multi-Mount Architecture

**Problem**: macOS signal handler limitation prevents multiple FUSE mounts in a single
process. Multiple mounts would fail with "cannot register source for signal 1."

**Solution**: Platform-specific daemon management with per-mount socket selection.

### Linux / FreeBSD - Single Daemon Model

```text
┌─────────────────────────────────────────────────────────────┐
│ mount_afpfs afp://server/vol1 /mnt/vol1                     │
│ mount_afpfs afp://server/vol2 /mnt/vol2                     │
└─────────────────────────────────────────────────────────────┘
             ↓
┌─────────────────────────────────────────────────────────────┐
│ afpfsd (PID: 1000)  [socket: afpfsd-501]                    │
│   ├── Mount 1 FUSE thread                                   │
│   └── Mount 2 FUSE thread                                   │
└─────────────────────────────────────────────────────────────┘
```

Flow:

1. mount_afpfs → get_daemon_filename(path1) → "afpfsd-501"
2. daemon_connect("afpfsd-501") → socket doesn't exist
3. start_afpfsd(path1) → fork/exec "afpfsd --socket-id afpfsd-501"
4. daemon listens on afpfsd-501, client connects ✓
5. mount_afpfs → get_daemon_filename(path2) → "afpfsd-501" (same!)
6. daemon_connect("afpfsd-501") → socket exists, connects ✓
7. Single daemon handles both mounts with separate FUSE threads

**Efficiency**: One daemon process + N threads for N mounts

### macOS - Per-Mount Daemon Model

```text
┌─────────────────────────────────────────────────────────────┐
│ mount_afpfs afp://server/vol1 /Volumes/vol1                 │
│ mount_afpfs afp://server/vol2 /Volumes/vol2                 │
└─────────────────────────────────────────────────────────────┘
             ↓
┌──────────────────────────────┬──────────────────────────────┐
│ afpfsd (PID: 2001)           │ afpfsd (PID: 2002)           │
│ [socket: afpfsd-501-hash1]   │ [socket: afpfsd-501-hash2]   │
│   Mount 1 FUSE thread        │   Mount 2 FUSE thread        │
└──────────────────────────────┴──────────────────────────────┘
```

Flow:

1. mount_afpfs → get_daemon_filename("/Volumes/vol1") → "afpfsd-501-bdb4..."
2. daemon_connect() → socket doesn't exist
3. start_afpfsd("/Volumes/vol1") → fork/exec "afpfsd --socket-id afpfsd-501-bdb4..."
4. daemon 1 listens on afpfsd-501-bdb4..., client connects ✓
5. mount_afpfs → get_daemon_filename("/Volumes/vol2") → "afpfsd-501-xyz9..."
6. daemon_connect() → socket doesn't exist
7. start_afpfsd("/Volumes/vol2") → fork/exec "afpfsd --socket-id afpfsd-501-xyz9..."
8. daemon 2 listens on afpfsd-501-xyz9..., client connects ✓
9. Two independent daemon processes, each with own signal handler ✓

**Signal Isolation**: Each daemon registers its own FUSE signal handlers, avoiding conflicts

**Key Functions**:

- `get_daemon_filename(char *name, size_t size, const char *mountpoint)` in `fuse/client.c`
  - macOS: hashes mountpoint path → unique socket per mount
  - Linux / FreeBSD: ignores mountpoint → shared socket for all mounts
  - NULL mountpoint (management): returns shared socket on both platforms

- `start_afpfsd(const char *mountpoint)` in `fuse/client.c`
  - Computes socket ID via `get_daemon_filename()`
  - Forks child process with: `afpfsd --socket-id <computed_id>`
  - Daemon receives socket ID and listens on that socket

- `daemon.c main()` - accepts `--socket-id` option
  - If provided: `snprintf(commandfilename, "%s", socket_id)`
  - If not provided: uses default `afpfsd-<uid>` (backward compatible)

**Platform Detection**:

- `#ifdef __APPLE__` determines platform-specific socket naming strategy
- Linux / FreeBSD: single efficient daemon for all mounts (unchanged behavior)
- macOS: per-mount daemons avoid signal handler conflicts

### Management Commands (status, unmount, exit)

Use NULL mountpoint in `daemon_connect()`, which causes:

- `get_daemon_filename(NULL)` → returns shared socket name (e.g., `afpfsd-501`)
- Management commands connect to "first" daemon (any active daemon)
- Can query/control all mounts from any daemon in the group

## AFP Protocol Compliance

### AFP 3.3 (OS X 10.6)

#### Replay Cache Support

AFP 3.3 **mandates** support for the AFP Replay Cache mechanism, which ensures reliable operation across
network interruptions and reconnections.

1. **Persistent Request IDs**: Request IDs are no longer reset to 0 on reconnection when the server
   supports replay cache. They wrap around from 65535 to 1 (avoiding 0).

2. **Server Capability Detection**: During `DSIOpenSession`, the client now parses the
   `kServerReplayCacheSize` option from the server's reply to detect replay cache support.

3. **Dynamic Behavior**:
   - If server advertises replay cache support → persistent request IDs enabled
   - If server doesn't support replay cache → legacy behavior (reset to 0 on reconnect)

#### Code Changes

- **`include/afp.h`**: Added `replay_cache_size` and `supports_replay_cache` fields to
  `struct afp_server`
- **`lib/dsi_protocol.h`**: Added `kServerReplayCacheSize` constant (0x02)
- **`lib/dsi.c`**:
  - `dsi_opensession_reply()` now parses replay cache options
  - `dsi_setup_header()` conditionally resets request IDs based on replay cache support
- **`lib/afp.c`**:
  - `afp_server_connect()` preserves request IDs on reconnect when replay cache is supported
  - `afp_server_init()` initializes replay cache fields

#### Benefits

- **Improved Reliability**: Prevents duplicate operations after network interruptions
- **Better Reconnection**: Smoother recovery from temporary disconnections
- **Protocol Compliance**: Full AFP 3.3 compliance when connecting to modern servers
