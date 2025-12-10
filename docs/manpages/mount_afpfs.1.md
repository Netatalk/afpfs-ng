# NAME

mount_afpfs — mount an Apple Filing Protocol (AFP) filesystem using FUSE

# SYNOPSIS

**mount_afpfs** \[-o *options*\] *afp_url* *node*

# DESCRIPTION

The **mount_afpfs** command is used to mount an AFP volume in the format
*afp://\[user\[;AUTH=uamname\]\[:password\]@\]host\[:port\]/volumename* at
the designated mount point *node*.

This command is a symlink to the afp_client(1)
executable, which is a full implementation to mount AFP volumes using
the FUSE infrastructure. It communicates with afpfsd, a daemon that
manages AFP sessions.

In order to mount multiple AFP volumes simultaneously, the afp_client(1)
talks to a per-user manager daemon (afpfsd in manager mode), which
spawns a dedicated afpfsd daemon for each mount request.

The arguments and options are:

**-o**

> Options passed to mount(2) are specified with
the **-o** option followed by a comma separated string of options. man
page for possible options and their meanings. Additional options
supported by the AFP Client are as follows:

**volpass=\<password\>**

> The only available option is "-o volpassword=XXX" to set the volume
password (since there is no facility for that in an AFP URL).

**rw**

> Mount the volume as writeable. This is the default, so it has no effect.

**ro**

> Mount the volume as readonly.

**group=\<groupname\>**

> Mount the volume as groupname.

**user=\<username\>**

> Mount the volume as username.

*afp_url*

> The AFP URL to mount, in the format:
>
> **afp://\[user\[;AUTH=uamname\]\[:password\]@\]host\[:port\]/volume**
>
> Specifies the AFP server and sharepoint to be mounted.
It can also include the username and password needed for authentication.
The uamname parameter represents the authentication method's name.
If no port is provided, the default port 548 is used.

*node*

> The path to the mount point, which must be a directory where the user
has write permissions.

# EXAMPLES

The following example demonstrates how to mount the AFP volume
fileserver.example.net/sharedDocs/ at the mount point /mnt/shared:

    mkdir /mnt/shared
    mount_afpfs afp://user123:securepass@fileserver.example.net/sharedDocs/ /mnt/shared

This example shows the correct URL format for mounting the volume publicData
from the AFP server backupserver as a guest user:

    mkdir /mnt/public
    mount_afpfs "afp://;AUTH=No%20User%20Authent@backupserver/publicData" /mnt/public

The following illustrates how to use a username of "john.doe"
and a password of "p@ssw0rd!" to mount fileshare from datahub.local
at the mount point /mnt/files:

    mkdir /mnt/files
    mount_afpfs afp://john.doe:p@@ssw0rd!@datahub.local/fileshare/ /mnt/files

# RETURN VALUES

0

> *mount_afpfs* successfully mounted the volume directory.

-1

> The server volume could not be mounted.

# SEE ALSO

afp_client(1), afpfsd(1)
