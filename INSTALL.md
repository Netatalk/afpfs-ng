# Installation Instructions

## Requirements

This is a quick guide on how to install afpfs-ng.

This project uses the Meson build system with a Ninja backend.
First off, make sure `meson` and `ninja` (sometimes packaged as `ninja-build`) are installed.

The mandatory dependency for all platforms is `pthread`.
On Linux when glibc < 2.38, the `libbsd` library is required.

### Linux

In addition to the above, you need:

- libgcrypt for the encrypted login methods
- readline (or libedit) for the command line client
- libfuse3 (backwards compatible with v2.9) for the FUSE client

### FreeBSD

In addition to the above, you need:

- libgcrypt (1.4.0 or later) for the encrypted login methods
- libfuse3 (backwards compatible with v2.9) for the FUSE client

### macOS

Use Homebrew or MacPorts to install the dependencies.

- libgcrypt for the encrypted login methods
- macFUSE (5.1.3 or later) for the FUSE client

macFUSE can be installed from [https://macfuse.github.io/](the macFUSE website) or via Homebrew.
Follow the instructions to install the macFUSE software and kernel extension.

Note that macFUSE 5.1.2 and earlier have a bug that prevents writing extended attributes.

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
