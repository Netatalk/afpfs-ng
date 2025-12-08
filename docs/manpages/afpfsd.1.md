# NAME

afpfsd - Daemon to manage AFP sessions for the afpfs-ng FUSE client

# SYNOPSIS

**afpfsd** \[-l|logmethod=*method*\] \[-f|--foreground\] \[-d|--debug\]
\[-s|--socket-id=*socket_name*\]

# DESCRIPTION

**afpfsd** is a daemon that manages AFP sessions. Functions (like
mounting, getting status, etc) can be performed using the afp_client(1)
tool. This client communicates with the daemon over a named pipe.

afpfsd will not start if another instance is already running. There
needs to be one copy of afpfsd running per user.

On macOS, multiple afpfsd daemons can run simultaneously to support
multiple macFUSE mounts, each with its own Unix domain socket.
On Linux or FreeBSD,
a single afpfsd daemon handles multiple mounts via the shared socket.

# OPTIONS

**-l|--logmethod** sets the method used to log; values are stdout or
syslog

**-f|--foreground** doesn't fork the daemon

**-d|--debug** puts the daemon in the foreground and dumps logs to
stdout

**-s|--socket-id** specifies the Unix domain socket filename to listen
on. This option is primarily used internally by the mount_afpfs(1)
client for per-mount daemon support on macOS.
On macOS, each mount gets a unique socket name
(including a hash of the mountpoint)
to work around FUSE signal handler limitations.
On Linux or FreeBSD, this is typically the same for all mounts.
If not specified, defaults to `afpfsd-<uid>`.

# MULTI-MOUNT SUPPORT

On Linux or FreeBSD, a single afpfsd daemon efficiently handles multiple mounts
using separate FUSE threads. On macOS, the macFUSE signal handler
registration limitation requires each mount to have its own daemon
process. The `--socket-id` option enables this by allowing each daemon
to listen on a unique socket determined by the mountpoint path.

Management commands (status, unmount, exit) connect to any running
daemon via its shared socket name.

# SEE ALSO

afp_client(1), mount_afpfs(1)
