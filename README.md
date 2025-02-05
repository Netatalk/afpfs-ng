## WARNING

The FUSE2 implementation is highly unstable when built with FUSE 2.99,
and not recommended for production use on modern systems.

The `afpcmd` CLI client can be used as a stop-gap measure.

## Apple Filing Protocol Client Library - afpfs-ng - libafpclient

### Description

AFPFS is a client implementation of the Apple Filing Protocol written in C which
can be used to access AFP shares exposed by multiple devices, notably Mac OS X
computers, linux devices exporting shares with netatalk, Apple Airport and 
Time Capsule products as well as other NAS devices from various vendors.

### Installation

#### Dependencies

This project uses the Meson build system with a Ninja backend.
First off, make sure `meson` and `ninja` (sometimes packaged as `ninja-build`) are installed.

The mandatory dependency is `pthread`.

The `libgcrypt`  and `gmp` libraries are optional,
and will be used for encrypted password authentication (DHX2, DHCAST128, RandNum UAMs.)

For the CLI client, `ncurses` and `libreadline` are required.

For the FUSE2 implementation, `libfuse` is required.

#### Building

With the Meson build system, you can build the project with:

```sh
meson setup build
```

Build and install the software.

```sh
meson compile -C build
sudo meson install -C build
```

To see available options, run:

```sh
meson configure
```

### Usage

You can either use afpfs to mount an AFP share with fuse or with the command-line client.

#### fuse

Mount the time_travel volume from delorean.local (in this example, my time capsule's hostname)
on /mnt/timetravel without authentication:

```bash
$ mount_afpfs afp://delorean.local/time_travel /mnt/timetravel
```

Same, with authentication:

```bash
$ mount_afpfs afp://simon:mypassword@delorean.local/time_travel /mnt/timetravel
```

Same, with authentication, forcing the UAM of your choice (usually not needed):

```bash
$ mount_afpfs "afp://simon;AUTH=DHX2:mypassword@delorean.local/time_travel" /mnt/timetravel
```

*Note:* Put the afp URL in quotes if it contains spaces, a colon, or other special characters.

Unmount the volume:

```bash
$ fusermount -u /mnt/timetravel
```

#### command line client

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


### Credits and license

This is a fork of a fork of a fork of the original afpfs-ng project that has gone unmaintained
for quite some time.

This repository includes many patches collected by the XBMC project
(www.xbmc.org) and other sources, in a bid to improve stability, performance and
to implement new features.

Check AUTHORS for a somewhat complete list of contributors.

The original [afpfs-ng webiste](http://web.archive.org/web/20150314201707/https://sites.google.com/site/alexthepuffin/home) can be found on the Wayback Machine.

This project retains the original author's license and is distributed under the GPL.
