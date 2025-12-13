# Installation Instructions

## Requirements

This is a quick guide on how to install afpfs-ng.

This project uses the Meson build system with a Ninja backend.
First off, make sure `meson` and `ninja` (sometimes packaged as `ninja-build`) are installed.

The mandatory dependency for all platforms is `pthread`.
On Linux when glibc < 2.38, the `libbsd` library is required.

To build man pages, you need `cmark`. If you want plain text versions of readmes,
you need `cmark-gfm` (which can also be used for man pages.)

### Linux

In addition to the above, you need:

- libgcrypt, libgmp for the encrypted login methods
- readline (or libedit) and ncurses for the command line client
- libfuse v3 (backwards compatible with v2.9) for the FUSE client

### FreeBSD

In addition to the above, you need:

- libgcrypt (1.4.0 or later), libgmp for the encrypted login methods
- readline (or libedit) and ncurses for the command line client
- libfuse v3 (backwards compatible with v2.9) for the FUSE client

### macOS

Use Homebrew or MacPorts to install the baseline dependencies.

macFUSE is required for the FUSE client, and can be installed from
[https://macfuse.github.io/](the macFUSE website) or via Homebrew.
Follow the instructions to install the macFUSE software and kernel extension.

## Compile and install

From the top level source directory, run:

    meson setup build -Dbuildtype=release

Build and install the software.

    meson compile -C build
    sudo meson install -C build

To see available options, run:

    meson configure

## Development files

The build system will install the libafpclient shared library and development headers.
A pkg-config file `libafpclient.pc` is installed to the configured
`pkgconfig` directory (use `pkg-config --cflags --libs libafpclient` to build
against the library).
