# Apple Filing Protocol Client Library - afpfs-ng - libafpclient

## Description

**AFPFS-NG** is a client implementation of the Apple Filing Protocol written in C
which can be used to access AFP shares exposed by multiple devices,
notably older Mac OS computers, Linux/*BSD/Solaris (or even macOS) servers
exporting shares with [netatalk](https://netatalk.io/),
Apple Airport and Time Capsule products as well as other NAS devices from various vendors.

## Usage

You can use afpfs-ng either to mount an AFP share with FUSE, or interactively with the command-line client.

### FUSE

Mount the *File Sharing* volume from afpserver.local on /home/myuser/fusemount
authenticated as user *myuser* (you will be prompted for the password):

    % afp_client mount --user myuser --pass - "afpserver.local/File Sharing" /home/myuser/fusemount

Get status information about all AFP volumes mounted by the current user:

    % afp_client status

Unmount the volume when you are done:

    % afp_client unmount /home/myuser/fusemount

Shut down the afpfs-ng management daemon (*afpfsd*):

    % afp_client exit

There is also an alternative command *mount_afpfs* included for mounting by AFP URL:

    % mount_afpfs "afp://myuser:-@afpserver.local/File Sharing" /home/myuser/fusemount

**Note:** Quotation marks around the AFP URL are mandatory when spaces,
colons, or other special characters are present.

### command line client

The *afpcmd* command line client allows you to interactively access AFP shares.
In the most basic use case, it takes an AFP URL as argument.

Open volume File Sharing on afpserver.local:

    $ afpcmd "afp://myuser:-@afpserver.local/File Sharing"
    Password: [input hidden]
    Connected to server afpserver
    afpcmd:

Connect anonymously to afpserver.local, list all volumes available to guest users:

    $ afpcmd "afp://afpserver.local"
    Connected to server afpserver
    Not attached to a volume. Run the 'ls' command to list available volumes
    afpcmd: cd Dropbox
    Attached to volume Dropbox
    afpcmd: ls
    -rw-r--r--   6148 2025-07-11 14:09 .DS_Store
    -rw-r--r-- 108320 2025-10-12 13:59 afpfs-ng-0.9.0.tar.xz
    -rw-------      0 2025-10-12 00:39 bork.txt
    -rw-r--r-- 525362 2024-10-09 13:02 group_photo.jpg
    -rw-r--r--  46954 2023-08-03 02:03 Information Sheet.xlsx
    drwxrwxrwx      0 2025-10-12 00:22 Scanned Documents
    afpcmd:

cd to change directories, *ls* to list, *get* file to retrieve file, *put* file to download file,
and *help* for a list of all supported commands.

Download a file from the AFP share to the current directory:

    $ afpcmd "afp://myuser:-@afpserver.local/File Sharing/afpfs-ng-0.9.0.tar.xz" .
    Password: [input hidden]
    Connected to server afpserver
        Downloading file afpfs-ng-0.9.0.tar.xz
        Transferred 108320 bytes in 0.015 seconds. (7200 kB/s)
    Transfer complete. 108320 bytes received.

## Credits and license

The afpfs-ng project was created by Alex deVries and is distributed under the GNU GPL v2.

As the development of the [original afpfs-ng project](https://sourceforge.net/projects/afpfs-ng/) stopped in 2009,
this fork was created in 2024 after consulting with Alex deVries with the intention to maintain and extend the project.

It contains elements from another [defunct fork](https://github.com/simonvetter/afpfs-ng)
created by Simon Vetter in 2015, which added IPv6 support, UTF8 support and various bug fixes
from the Boxee and XBMC (Kodi) projects.
