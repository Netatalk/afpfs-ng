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

**Design Choice**: afpfs-ng uses a manager daemon architecture where each mount gets its own isolated daemon process,
providing fault isolation and simpler state management for multiple mounts.

Compared to a single shared daemon with per-mount multi threading or multiplexing, this design offers:

**Benefits**:

- **Fault Isolation**: One mount crashing doesn't affect others
- **Resource Isolation**: Independent memory spaces and CPU usage
- **Security Compartmentalization**: Credential isolation per mount

**Trade-offs**:

- ~2-3 MB memory overhead per additional mount
- Slightly slower multi-mount startup (each daemon forks independently)
- More socket files in /tmp

### Multi-Daemon Model Overview

```text
┌─────────────────────────────────────────────────────────────┐
│ mount_afpfs afp://server/vol1 /mnt/vol1                     │
│ mount_afpfs afp://server/vol2 /mnt/vol2                     │
│ mount_afpfs afp://server/vol3 /mnt/vol3                     │
└─────────────────────────────────────────────────────────────┘
             ↓ All requests go through manager
┌─────────────────────────────────────────────────────────────┐
│ afpfsd --manager (PID: 1000) [socket: afpfsd-501]           │
│   ├── Tracks child PIDs: [2001, 2002, 2003]                 │
│   ├── Spawns mount-specific daemons on demand               │
│   └── Handles coordinated shutdown (exit command)           │
└─────────────────────────────────────────────────────────────┘
          ↓ Spawns independent mount daemons
┌──────────────────────────────┬──────────────────────────────┬──────────────────────────────┐
│ afpfsd --socket-id ... (2001)│ afpfsd --socket-id ... (2002)│ afpfsd --socket-id ... (2003)│
│ [socket: afpfsd-501-bdb4...] │ [socket: afpfsd-501-8f3e...] │ [socket: afpfsd-501-c7d2...] │
│   /mnt/vol1 FUSE mount       │   /mnt/vol2 FUSE mount       │   /mnt/vol3 FUSE mount       │
└──────────────────────────────┴──────────────────────────────┴──────────────────────────────┘
```

### Mount Flow

1. `mount_afpfs afp://server/vol1 /mnt/vol1`
2. Client computes mount socket ID via hash of `/mnt/vol1` → `afpfsd-501-bdb4a5c2`
3. Client tries to connect to mount socket → doesn't exist
4. Client connects to manager socket `afpfsd-501`
5. If manager doesn't exist, client spawns it: `afpfsd --manager`
6. Client sends `AFP_SERVER_COMMAND_SPAWN_MOUNT` with socket ID and mountpoint
7. Manager forks child process: `afpfsd --socket-id afpfsd-501-bdb4a5c2`
8. Mount daemon listens on its unique socket and performs FUSE mount
9. Client receives success, sends actual mount request to mount daemon socket

### Coordinated Shutdown

```shell
afp_client exit
```

1. Client connects to manager socket `afpfsd-501` (NULL mountpoint)
2. Sends `AFP_SERVER_COMMAND_EXIT`
3. Manager daemon:
   - Sends SIGTERM to all tracked child PIDs
   - Waits 1 second for graceful shutdown
   - Sends SIGKILL to any remaining children
   - Waits for all children with `waitpid()`
   - Exits manager daemon

Result: All mounts unmounted cleanly, no orphaned processes

**Key Functions**:

- `get_daemon_filename(char *name, size_t size, const char *mountpoint)` in `fuse/client.c`
  - mountpoint != NULL: hashes path → unique socket per mount (e.g., `afpfsd-501-bdb4a5c2`)
  - mountpoint == NULL: returns manager socket (e.g., `afpfsd-501`)
  - Used on all platforms (no `#ifdef` branching)

- `start_manager_daemon()` in `fuse/client.c`
  - Forks and execs: `afpfsd --manager`
  - Only runs if manager socket doesn't exist

- `start_afpfsd(const char *mountpoint)` in `fuse/client.c`
  - Connects to manager socket (starts manager if needed)
  - Sends `AFP_SERVER_COMMAND_SPAWN_MOUNT` request
  - Manager spawns mount daemon with unique socket ID

- `run_manager_daemon()` in `fuse/daemon.c`
  - Listens on shared socket (e.g., `afpfsd-501`)
  - Handles `SPAWN_MOUNT`, `EXIT`, `PING` commands
  - Tracks child daemon PIDs in linked list
  - Reaps dead children periodically via `waitpid(..., WNOHANG)`

- `main()` in `fuse/daemon.c`
  - Detects `--manager` flag → calls `run_manager_daemon()`
  - Detects `--socket-id` flag → runs mount daemon on that socket
  - No flag: backward compatible mode (shared socket, deprecated)

### Socket Naming

All socket files are created in `/tmp/`:

- **Manager socket**: `/tmp/afp_server-<uid>` (e.g., `/tmp/afp_server-501`)
- **Mount sockets**: `/tmp/afp_server-<uid>-<hash>` (e.g., `/tmp/afp_server-501-bdb4a5c2`)
  - Hash is computed via djb2 algorithm on mountpoint absolute path
  - Ensures unique socket per mountpoint

### Management Commands (status, unmount, exit)

Use NULL mountpoint in `daemon_connect()`, which causes:

- `get_daemon_filename(NULL)` → returns manager socket name (e.g., `afpfsd-501`)
- Commands connect to manager daemon

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
