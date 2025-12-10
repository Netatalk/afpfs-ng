# NAME

afpfsd - Daemon to manage AFP sessions for the afpfs-ng FUSE client

# SYNOPSIS

**afpfsd** \[-l|logmethod=*method*\] \[-f|--foreground\] \[-d|--debug\]
\[-m|--manager\] \[-s|--socket-id=*socket_name*\]

# DESCRIPTION

**afpfsd** is the daemon used by the FUSE client. There are two modes:

- **Manager daemon** (one per user): started with `--manager`, listens on
  a shared socket, and spawns mount-specific daemons.
- **Mount daemon** (one per mount): started with `--socket-id`, owns a
  single FUSE mount.

afp_client(1) talks to the manager; the manager spawns per-mount
daemons as needed. Management commands (status, unmount, exit) go to the
manager, which coordinates the mount daemons.

# OPTIONS

**-l|--logmethod** sets the method used to log; values are stdout or
syslog

**-f|--foreground** doesn't fork the daemon

**-d|--debug** puts the daemon in the foreground and dumps logs to
stdout

**-m|--manager** run in manager mode (per user). This is started
automatically by afp_client(1) if not already running.

**-s|--socket-id** specifies the Unix domain socket filename to listen
on. The manager listens on `/tmp/afp_server-<uid>`. Each mount daemon
uses a unique socket derived from the mountpoint hash, e.g.
`/tmp/afp_server-<uid>-<hash>`. This option is primarily used
internally by afp_client(1).

# SEE ALSO

afp_client(1), mount_afpfs(1)
