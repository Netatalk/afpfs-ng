# NAME

afp_client - Mount, unmount and control Apple Filing Protocol (AFP)
sessions using the FUSE infrastructure

# SYNOPSIS

**afp_client mount|status|unmount|suspend|resume|exit \[options\]**

# DESCRIPTION

**afp_client** command allows you to perform some basic functions to
access AFP volumes, such as mount, unmount, get status, suspend and
resume.

Do not confuse this with afpcmd; afp_client is to be used only for the
FUSE client, in conjunction with afpfsd(1). afpcmd is a batch-mode file
transferring client. Both of them use the afpfs-ng libraries.

afp_mount(1) is normally a symlink to afp_client. It only handles
mounting commands with a fully formed AFP URL.

# COMMANDS

**mount**

> The name of the interface. This is usually a driver name followed by a
unit number, for example **eth0** for the first Ethernet interface.

**mount \[mount options\] node**

> Using the authentication and server information provided with the mount
options, mount the remove filesystem on node. For more information, see
the "mount options" later in this man page. If you would prefer to use
the AFP URL syntax, see mount_afp(1) for more information.

**unmount node**

> Remove the AFP mount that is currently connected to **node**

**status**

> Show status information of all connected servers. This will provide
information on connected servers' IP address, server descriptions
(machine type, machine name, signature, login message) and available
volumes. It also provides statistics and other details.

This is crtical for debugging.

**suspend**

> Suspends but does not unmount the current connections to all currently
connected server. Currently unsupported.

**resume**

> Resumes all suspended server connections. Currently unsupported. Enable
or disable the **promiscuous** mode of the interface. If selected, all
packets on the network will be received by the interface.

# MOUNT FLAGS

**-u, --user \<username\>**

> Log in using \<username\>

**-p, --pass \<password\>**

> If you specify a '-' as the password, you will be prompted for it. This
allows you to use a password without having to expose it on the command
line.

**-o, --port \<portnum\>**

> Use TCP portnum instead of the default, 548.

**-V, --volumepassword \<volumepassword\>**

> Use this if the volume you're accessing uses a volume password (a very
weak form of protection as it is transferred as clear text). If you
specify a '-' as the password, you will be prompted for it. This allows
you to use a password without having to expose it on the command line.

If you specify a '-' as the password, you will be prompted for it. This
allows you to use a password without having to expose it on the command
line.

**-v, --version \<afp version\>**

> Specify the AFP version that will be used for a mount. For AFP 2.2, use
'22', for 3.2, use '32', etc. By default afpfs-ng will choose the
highest AFP version shared between the client and server. afpfs-ng
supports AFP 2.0 up to 3.2. **-a, --uam \<uam\>** Set the authentication
method, to one of:

- *No User Authent*

- *Cleartxt Passwrd*

- *Randnum Exchange*

- *2-Way Randnum Exchange*

- *DHCAST128*

- *Client Krb v2*

- *DHX2*

If you do not specify a UAM, the most secure one common to both the
server and client (afpfs-ng) will be chosen.

**-m, --map \<uam\>**

> Set the method used to map local to server UID and GIDs. Posible values
are:

*Common user directory* This should be used in an environment where the
UID and GID of the client and server are expected to match perfectly. An
example of this is where there is an NIS or open directory server.

*Login ids* Use this when you want all files to appear to be owned by
the uid and gid of the userid that you used for your authentication
information.

# HISTORY

afp_client is part of the FUSE implementation of afpfs-ng.

# SEE ALSO

afpfsd(1), mount_afpfs(1)

# AUTHORS

Alex deVries, alexthepuffin@gmail.com
