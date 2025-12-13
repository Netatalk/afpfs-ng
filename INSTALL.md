# Requirements

This is a quick guide on how to install afpfs-ng.

This project uses the Meson build system with a Ninja backend.
First off, make sure `meson` and `ninja` (sometimes packaged as `ninja-build`) are installed.

The mandatory dependency for all platforms is `pthread`.
On Linux when glibc < 2.38, the `libbsd` library is required.

To build man pages, you need `cmark`. If you want plain text versions of readmes,
you need `cmark-gfm` (which can also be used for man pages.)

Note that FUSE3 is not supported yet.

a) Linux

- libgcrypt, libgmp for the encrypted login methods
- readline and ncurses for the command line client
- libfuse (2.7.0 - 2.9.9) for the FUSE client

b) FreeBSD

- libgcrypt (1.4.0 or later), libgmp for the encrypted login methods
- readline and ncurses for the command line client
- libfuse (2.7.0 - 2.9.9) for the untested FUSE client

c) Mac OS X

- Homebrew
- macFUSE for the FUSE client

# Compile and install

From the top level source directory, run:

    meson setup build -Dbuildtype=release

Build and install the software.

    meson compile -C build
    sudo meson install -C build

To see available options, run:

    meson configure

Development files

When you run `sudo meson install -C build` the library and development files
are installed. Public headers are installed to the configured include directory
and a pkg-config file `libafpclient.pc` is installed to the configured
`pkgconfig` directory (use `pkg-config --cflags --libs libafpclient` to build
against the library).
