# Apple Filing Protocol Client Library - afpfs-ng - libafpclient

## Description

**AFPFS-NG** is a client implementation of the Apple Filing Protocol written in C which
can be used to access AFP shares exposed by multiple devices, notably Mac OS X
computers, linux devices exporting shares with netatalk, Apple Airport and 
Time Capsule products as well as other NAS devices from various vendors.

## Usage

You can either use afpfs-ng to mount an AFP share with FUSE or with the command-line client.

### FUSE

Mount the time_travel volume from delorean.local (in this example, my time capsule's hostname)
on /mnt/timetravel without authentication:

```bash
$ mount_afpfs "afp://delorean.local/time_travel" /mnt/timetravel
```

Same, with authentication:

```bash
$ mount_afpfs "afp://simon:mypassword@delorean.local/time_travel" /mnt/timetravel
```

Same, with authentication, forcing the UAM of your choice (usually not needed):

```bash
$ mount_afpfs "afp://simon;AUTH=DHX2:mypassword@delorean.local/time_travel" /mnt/timetravel
```

*Note:* Quotation marks around the AFP URL are mandatory
when spaces, a colon, or other special characters are present.

Unmount the volume:

```bash
$ fusermount -u /mnt/timetravel
```

### command line client

Open volume time_travel on delorean.local:

```bash
$ afpcmd afp://simon:mypassword@delorean.local/time_travel
```

Connect anonymously to delorean.local, list all available volumes:

```bash
$ afpcmd afp://simon:mypassword@delorean.local/
```

cd to change directories, ls to list, get file to retrieve file, put file to put file...
and help for a list of supported commands.


## Credits and license

This is a fork of a fork of a fork of the original afpfs-ng project by Alex deVries.

This repository includes many patches collected by the XBMC project
(www.xbmc.org) and other sources, in a bid to improve stability, performance and
to implement new features.

The original [afpfs-ng webiste](http://web.archive.org/web/20150314201707/https://sites.google.com/site/alexthepuffin/home) can be found on the Wayback Machine.

This project retains the original author's license and is distributed under the GNU GPL v2.
