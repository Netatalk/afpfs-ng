# NAME

afpcmd - Transfer files over the network using the Apple Filing
Protocol (AFP)

# SYNOPSIS

**afpcmd** \[-r\] \[-v *loglevel*\] \[*afp url*\]

# DESCRIPTION

**afpcmd** is a command-line tool to help transfer files to and from a
server using AFP. This is typically either Netatalk or Mac OS or Mac OS
X.

This can be done as a non-root user. It offers either an interactive
command-line (like a traditional FTP client) or for batch retrievals.

Do not confuse this with the FUSE mounting tools (mount_afpfs, afpfsd,
afp_client), which offer the ability to mount an entire filesystem.

# OPTIONS

**-r** sets the recursive flag.

**-v**, **--loglevel** *level* sets the log verbosity level. Accepted
values are **debug**, **info**, **notice**, **warning**, and **error**.
Default is **notice**. Logs are written to syslog.

**afp url** uses the standard AFP URL format.

# AFP version support

Look at the afpfs-ng documentation for more information on specific AFP
version compatibility information.

# Batch mode

Batch file transfers can be done in one of two ways:

**afpcmd -r** *afp url to directory*

This does a recursive transfer of all subdirectories and files locally.

**afpcmd** *afp url to file*

This transfers just the file locally.

After either of these is finished, the command exits.

# Interactive mode

If a URL is provided on the command line, afpcmd connects and enters the
volume and directory specified.

Standard readline keystrokes are enabled. Command line competion (using
tab) and history (using up and down arrows) is provided. Local filename
completion is enabled.

**Most common commands**

*connect* \<afp URL\>: Connect to server, change to volume and directory

*cd*: Change directories on the server

*get* \<filename\>: retrieve file

*get* -r \<directory\>: Recursively retrieve the directory

*put* \<filename\>: Upload file

*quit*: Quit

**Connect/disconnect commands**

*disconnect*: Disconnect from current server

*user* \<user\>: Set the user

**Remote directory commands**

*pwd*: Show current directory on server

*mkdir* \<directory\>: create new directory

*rmdir* \<directory\>: remove directory

*ls* or *dir*: show files in current directory

**Remote file commands**

*mv* or *rename* old_file new_file: Rename \<old file\> to \<new file\>

*touch* \<filename\>: Create a blank file

*view* \<filename\>: Show file

*chmod*: \<file\> \<mode\>: Change the mode of a file on the server

*delete* of *rm*: \<file\>: Remove file from the server

**Status commands**

*status*: Show status of the connection and server. For debugging.

*df*: Show the disk size and available blocks.

**Local commands**

*lpwd*: Show current local

*lcd*: Change local directory

**Other commands**

*help* or *?*: show help

# AFP URLs

A typical usage of afpcmd is:

**afpcmd** "afp://username:password@servername/volume"

The complete syntax of a URL is:

afp://username;AUTH=authtype:password@server:port/volume/path

If a password of "-" is provided, the user is prompted for a password.

# SEE ALSO

afpgetstatus(1)
