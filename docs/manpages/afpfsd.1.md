# NAME

afpfsd - Daemon to manage AFP sessions for the afpfs-ng FUSE client

# SYNOPSIS

**afpfsd** \[-l|logmethod=*method*\] \[-f|--foreground\] \[-d|--debug\]

# DESCRIPTION

**afpfsd** is a daemon that manages AFP sessions. Functions (like
mounting, getting status, etc) can be performed using the afp_client(1)
tool. This client communicates with the daemon over a named pipe.

afpfsd will not start if another instance is already running. There
needs to be one copy of afpfsd running per user.

# OPTIONS

**-l|--logmethod** sets the method used to log; values are stdout or
syslog

**-f|--foreground** doesn't fork the daemon

**-f|--debug** puts the daemon in the foreground and dumps logs to
stdout

# SEE ALSO

afp_client(1), mount_afpfs(1)
