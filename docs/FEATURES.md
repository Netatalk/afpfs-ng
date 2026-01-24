# Compatibility details for afpfs-ng

## A. Login methods

The following UAMs are implemented:

- Cleartxt Passwrd
- No User Authent
- Randnum Exchange*
- 2-Way Randnum Exchange*
- DHCAST128*
- DHX2*

However, only those with a (*) will exist if you build with libgcrypt.
By default, Mac OS X 10.5 and later only support those with a (*).
It is possible to enable cleartext passwords in those versions, but this is
not a great idea.

The following UAMs have not yet been implemented:

- kerberos, this requires integration with a KDC
- reconnect, it is a bit unclear how this should be done with session keys.
  This isn't properly described in the docs.  It also isn't really a UAM.

Password changing isn't implemented, although it has been roughed in.
The interface would be in afpcmd.

There is no support for open directory.

'status' will show you what UAMs are compiled in and what is being used.

## B. Connect, disconnect

There are basic facilities to receive and send session keys, but these are not
used.

Server disconnect and reconnect can be done with the FUSE client,
with the afp_client suspend and resume commands.

The client doesn't recover if the server goes down partway through a transaction.

## C. UID and GID mapping

One area of complication is around UID and GID mappings.  These may differ
between the client and server.  There are two modes that are enabled in
afpfs-ng:

### Common user directory

This is where both the client and server have
identical UIDs and GIDs.  This is the case where you have an NIS server
between them, or some other common directory.

### Login IDs

This is where all the files appear as the user that logged in.  This would
typically be used where the databases are separate, and one user expects to
be able to read/write all the files he sees.  This can get confusing, since
any files that aren't his will appear to be owned by him, but writing to
them will result in an EPERM.

### Named mapping

This is where the name (not uid) of the owner is mapped correctly.  This is
not implemented.

### Mapping from file

This is where a file is read that translates client and server ids.  This is
not implemented.

afpfs-ng attempts to detect the mapping type automatically; do 'afp_client
status' (for FUSE monts) or 'status' within afpcmd to see what it guessed.

## D. Meta information

### Server icon

A readonly copy of the server icon can be found in /.servericon.

### Resource forks

Depending on the AFP server type and version, resource forks may be stored in
extended attributes or in AppleDouble files.

#### When using AppleDouble files

Every directory has a hidden directory called .AppleDouble, and if a resource
fork exists, you'll find it there.  As an example, the resource fork for
/foo/bar/testfile can be found in /foo/bar/.AppleDouble/testfile.

The permissions of the resource fork are the same as the data fork.

#### When using extended attributes

Resource forks are stored in the extended attribute named "com.apple.ResourceFork".
The afpfs-ng FUSE client does *NOT* reading and writing this extended attribute yet,
so resource forks will not be visible when using extended attributes,
and if you write files with resource forks, they will be lost.

### Desktop functions

#### a) Comments

The only desktop function that's actually implemented is comments.  For file
/dir/foo, they can be found in /dir/.AppleDouble/file.comment

Permissions for the comment are the same as the data fork.

1. Catalog searching
2. Icon searching
3. APPL
4. Finder info

1 through 3 are not really suitable as a filesystem.  But you could get access
to them if you wrote your own client.

Finder info for files and directories for /dir/foo can be found in
/dir/.AppleDouble/foo.finderinfo.

## E. ACLs and extended attributes

### ACLs

ACLs have not been implemented.

### Extended Attributes (AFP 3.2+)

Extended attributes (EAs) are supported for servers that support AFP 3.2 or later (including netatalk
3.0+). This allows preservation of macOS metadata like Finder tags, quarantine flags, and other file
attributes.

#### Supported Operations

- **List EAs**: View all extended attributes attached to a file
- **Read EAs**: Retrieve the value of a specific extended attribute
- **Write EAs**: Set or modify extended attributes on files
- **Remove EAs**: Delete extended attributes from files

#### Platform-Specific Behavior

##### Linux

On Linux, extended attributes work fully across all operations.
Linux requires the `user.` namespace prefix for user-defined attributes:

    # Set an EA (automatically adds "user." prefix for AFP protocol)
    setfattr -n user.myattr -v "myvalue" /mnt/afp/file.txt

    # Read an EA
    getfattr -n user.myattr /mnt/afp/file.txt

    # List all EAs
    getfattr -d /mnt/afp/file.txt

    # Copy files with EAs preserved
    cp -a source.txt /mnt/afp/          # GNU cp with -a flag
    rsync -aX source.txt /mnt/afp/      # rsync with -X flag

##### macOS

On macOS, EA read, write, and list operations work correctly.

    # List EAs
    xattr -l /Volumes/afp/file.txt

    # Read EA
    xattr -p com.apple.metadata:kMDLabel /Volumes/afp/file.txt

    # Write EA
    xattr -w user.test "value" /Volumes/afp/file.txt

    # Copying files with EAs
    cp file.txt /Volumes/afp/

##### FreeBSD

On FreeBSD, all EA operations work correctly with `setextattr` and `getextattr` commands:

    # Set an EA
    setextattr user myattr "myvalue" /mnt/afp/file.txt

    # Read an EA
    getextattr user myattr /mnt/afp/file.txt

    # List all EAs
    lsextattr user /mnt/afp/file.txt

    # Remove an EA
    rmextattr user myattr /mnt/afp/file.txt

**Important**: FreeBSD's native `cp` command does **not** preserve extended attributes, even with the `-p` flag.
This is a known limitation of FreeBSD's base system
(see [FreeBSD bug #240146](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=240146)).

To copy files with extended attributes preserved on FreeBSD:

    # Use rsync with -X flag
    rsync -aX source.txt /mnt/afp/

#### EA Filtering

afpfs-ng automatically filters internal server metadata to prevent corruption:

- `org.netatalk.Metadata` - Internal netatalk server metadata (always filtered)

All other extended attributes, including macOS system attributes like `com.apple.*`,
are transmitted to and stored on the server as expected.

#### Server Requirements

- Server must support AFP 3.2 or later
- For netatalk: version 3.0 or later with `ea = sys` configuration (native filesystem xattrs)

## F. Internationalization

For servers that support it, UTF8 usernames, server names, volume names and files are supported.

Older clients (Mac OS 9) that don't use filenames of type long.  Other
charsets for files (MacRomanian, etc) are not supported properly.  Servernames
are supported.

## G. Networks

IPv6: As of v0.8.2, we have support for IPv6.
IPv4: Yes, of course.
Appletalk: There is no support for Appletalk.

There's no concept of multiple protocols, eg. doing getstatus with one protocol,
then connecting with another, which is what some Apple clients do.

There's no ability to connect based on a name advertized by Bonjour/Avahi, you
need to use the IP or DNS name.

## H. Server-specific information

afpfs-ng detects the server type by parsing the Machine Type field in
getstatus.  The command line 'afpgetstatus' will show this without you having
to log in.  'status' will show you this also.

The detection is done in order to deal with some details.

### Mac OS 8

afpfs-ng has never been used with Mac OS 8, so there's no data.  You could do
this with AFP over TCP/IP, but this could be difficult. Email me if you have any info.

### Mac OS 9

This speaks AFP 2.1, so this presents certain restrictions, such as:

- smaller limits on file and disk sizes (4GB)
  - creating files larger than 2GB isn't possible and isn't handled properly
  - 'df' will report a max of 4GB.
- no support for Unix privileges; all files are reported as 0600, directories
  as 0700.
- for directories, timestamps are reported as the mount times, which is what
  the Mac OS X client does.

There is no proper charset conversions for filenames.  Patches accepted.

This has been lightly tested.

### Mac OS X

Various versions have been tested, including 10.2, 10.3, 10.4 and 10.5.x. This has been most
heavily tested.  Note the restrictions on UAMs above.

### Airport Extreme

The airport extreme with firmware 7.1 and 7.2.1 has been tested, and has two
oddities:

- Unix permissions aren't handled at all

- the device has a software bug which can let an authenticated user freeze the
  device.  I won't describe the problem in any more detail.  Apple has
  acknowledged the problem, but hasn't yet released updated firmware.

Note that the Airport can serve up SMB and AFP disks; afpfs-ng only handles
AFP.

### Time Capsule

The Time Capsule is a network backup device meant to handle Time Machine
backups over AFP.  This hasn't been released and my wife won't let me buy one,
so there's been no testing.  Donations appreciated.

### Netatalk

This open source server has been extensively tested with afpfs-ng
and should work well with afpfs-ng.

You must use netatalk 2.0.4 or later with afpfs-ng as earlier versions has
broken Unix privilege support, notably when setting the execute bit.

### LaCie devices

The LaCie device has an ARM processor in it, and speaks netatalk.  Part of the
problem with that some login crypto is so slow that older versions of afpfs-ng
timeout before the server can complete the crypto.  This should be fixed as of
0.8, but this hasn't been tested properly.

## I. FUSE-specific bugs

There are no facilities for automounting home directories, which is something
that people ask for frequently.  This requires having integration into open
directory.

## J.Other

Deliberately left blank.

## K. References

Not all references are easy to find. The useful ones are:

- Apple Filing Protocol Programming Guide, Version 3.2, 2005-06-04
- AppleTalk Filing Protocol, Versions 2.1 and version 2.2., Apple Computer Inc, 1999
- Inside Macintosh, Macintosh Toolbox Essentials, 1992

And other software:

- netatalk: Netatalk is the server side, and it implements AFP 3.4 over
  Appletalk and TCP/IP. It has a long history and has been heavily tested.

- afpfs: The original afpfs was last released for Linux kernel 2.2.5 and was
  written in kernel space. It was written by Ben Hekster, then taken over by
  David Foster. I think it was last maintained in 1999 and only handled AFP 2.x.
  Truly, afpfs-ng was intended to take over where they left off, but this is a
  complete rewrite in order to fit into FUSE.

- hfsplus: This might not seem related, but the way that hfsplus handles
  presenting resource forks to userspace may be relevant to how afpfs-ng does
  the same.

- wireshark (aka ethereal): the AFP packet parsing is excellent
