# NAME

afp_client - Mount, unmount and control Apple Filing Protocol (AFP)
sessions using the FUSE infrastructure

# SYNOPSIS

**afp_client** \[mount|status|unmount|suspend|resume|exit\] \[*options*\]

# DESCRIPTION

**afp_client** command allows you to perform some basic functions to
access AFP volumes, such as mount, unmount, get status, suspend and
resume.

Do not confuse this with afpcmd; afp_client is to be used only for the FUSE client,
in conjunction with afpfsd(1).
afpcmd, on the other hand, is a batch-mode file transferring client.
Both of them use the afpfs-ng libraries.

The mount_afpfs(1) command is in fact a symlink to afp_client.
When invoked with a fully formed AFP URL, it will execute a FUSE mount command.

Multiple volumes can be mounted simultaneously on all supported platforms.
Each mount request talks to a per-user manager daemon, which spawns a
per-mount afpfsd daemon that owns that FUSE mount.

# COMMANDS

**mount** \[mount options\] *server:volume* *mountpoint*

> Using the authentication and server information provided with the mount
options, mount the remote filesystem on mountpoint. For more information, see
the "mount options" section later in this man page. If you would prefer to use
the AFP URL syntax, see mount_afpfs(1) for more information.

**unmount** *mountpoint*

> Remove the AFP mount that is currently connected to **mountpoint**

*NOTE:* When using macFUSE on macOS, it is recommended to use umount(8) or
the Finder to unmount AFP volumes.

**status**

> Show status summary of all connected servers.

**status** *mountpoint*

> Show status information of the connected server for the specified mountpoint.
This will provide information on connected servers' IP address, server descriptions
(machine type, machine name, signature, login message) and available
volumes. It also provides statistics and other details.

**suspend** *mountpoint*

> Suspends but does not unmount the connection to the server for the volume
mounted at *mountpoint*. This terminates the network connection but keeps the
mount active, useful for laptop suspend/resume scenarios.

**resume** *mountpoint*

> Resumes the server connection for the volume mounted at *mountpoint*.
Reconnects to the AFP server and restores the session.

**exit**

> Stop all mounts owned by the current user and shut down the manager
> daemon. It is recommended to run **unmount** on each mountpoint first.

# MOUNT FLAGS

**-a, --uam \<uam\>** Set the authentication method, to one of:

- *No User Authent*

- *Cleartxt Passwrd*

- *Randnum Exchange*

- *2-Way Randnum Exchange*

- *DHCAST128*

- *DHX2*

If you do not specify a UAM, the most secure one common to both the
server and client (afpfs-ng) will be chosen.

**-m, --map** *mapping*

> Set the method used to map local to server UID and GIDs. Possible values
are:

*Common user directory* (or *common*) - Use in environments where the UID
and GID of the client and server match perfectly, such as with NIS or LDAP.

*Login ids* (or *loginids*) - All files appear owned by the local user who
mounted the volume. This is the safest option when client and server have
different user databases.

**-O, --options** *options*

> Comma-separated list of mount options. See fuse(8) for more
information.

**-o, --port** *portnum*

> Use TCP *portnum* instead of the default, 548.

**-p, --pass** *password*

> If you specify a '-' as the password, you will be prompted for it. This
allows you to use a password without having to expose it on the command
line.

**-u, --user** *username*

> Log in using *username*

**-V, --volumepassword** *volumepassword*

> Use this if the volume you're accessing uses a volume password (a very
weak form of protection as it is transferred as clear text). If you
specify a '-' as the password, you will be prompted for it. This allows
you to use a password without having to expose it on the command line.

If you specify a '-' as the password, you will be prompted for it. This
allows you to use a password without having to expose it on the command
line.

**-v, --afpversion** *afp version*

> Specify the AFP protocol version that will be used for a mount.
By default afpfs-ng will choose the highest AFP version shared between
the client and server.
afpfs-ng supports AFP 2.0 up to 3.4.

# HISTORY

afp_client is part of the FUSE implementation of afpfs-ng.

# SEE ALSO

afpfsd(1), mount_afpfs(1)

# AUTHORS

Alex deVries, <alexthepuffin@gmail.com>
