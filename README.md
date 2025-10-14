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

Mount the time_travel volume from delorean.local on /mnt/timetravel without authentication:

```shell
% mount_afpfs "afp://delorean.local/time_travel" /mnt/timetravel
```

Same, with authentication:

```shell
% mount_afpfs "afp://simon:mypassword@delorean.local/time_travel" /mnt/timetravel
```

Same, with authentication, forcing the UAM of your choice (usually not needed):

```shell
% mount_afpfs "afp://simon;AUTH=DHX2:mypassword@delorean.local/time_travel" /mnt/timetravel
```

**Note:** Quotation marks around the AFP URL are mandatory when spaces,
a colon, or other special characters are present.

Unmount the volume:

```shell
% fusermount -u /mnt/timetravel
```

### command line client

Open volume time_travel on delorean.local:

```shell
$ afpcmd "afp://simon:mypassword@delorean.local/time_travel"
Attempting connection to delorean.local ...
Connected to server Delorean using UAM "DHX2"
Connected to volume time_travel
afpcmd:
```

Connect anonymously to delorean.local, list all volumes available to guest users:

```shell
$ afpcmd "afp://guest;AUTH=No User Authent:@delorean.local"
Attempting connection to delorean.local ...
Connected to server Delorean using UAM "No User Authent"
Specify a volume with 'cd volume'. Choose one of: dropbox, time_travel
afpcmd: cd dropbox
Connected to volume dropbox
afpcmd: ls
-rw-r--r--   6148 2025-07-11 14:09 .DS_Store
-rw-------      0 2025-10-12 00:39 bork.txt
-rw-r--r-- 108320 2025-10-12 13:59 afpfs-ng-0.9.0.tar.xz
-rw-r--r--  46954 2023-08-03 02:03 Information Sheet.xlsx
drwxrwxrwx      0 2025-10-12 00:22 Scanned Documents
-rw-r--r-- 525362 2024-10-09 13:02 group_photo.jpg
afpcmd:
```

cd to change directories, *ls* to list, *get* file to retrieve file, *put* file to download file,
and *help* for a list of all supported commands.

Download a file from the AFP share to the current directory:

```shell
$ afpcmd "afp://simon:mypassword@delorean.local/time_travel/afpfs-ng-0.9.0.tar.xz" .
Attempting connection to delorean.local ...
Connected to server Delorean using UAM "DHX2"
Connected to volume time_travel
    Getting file /afpfs-ng-0.9.0.tar.xz
Transferred 108320 bytes in 0.002 seconds. (54000 kB/s)
```

## Credits and license

The afpfs-ng project was created by Alex deVries and is distributed under the GNU GPL v2.

As the development of the [original afpfs-ng project](https://sourceforge.net/projects/afpfs-ng/) stopped in 2008,
this fork was created with the understanding of Alex deVries to maintain and extend the project.

It contains elements from another [defunct fork](https://github.com/simonvetter/afpfs-ng)
by Simon Vetter, which added IPv6 support, UTF8 support and various bug fixes
from the Boxee and XBMC (Kodi) projects.
