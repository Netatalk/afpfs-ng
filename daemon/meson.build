# daemon/meson.build
# Build configuration for afpsld (AFP Stateless Daemon)
# Copyright (C) 2026 Daniel Markstedt <daniel@mindani.net>
#
# This daemon provides stateless AFP operations without FUSE dependencies.
# For FUSE mounting, use afpfsd from the fuse/ directory instead.
#
# This build is minimal - only the daemon and library needed for GUI applications.
# Command-line utilities (mount_afp, afp_extra) are built elsewhere.

# Stateless daemon binary (NO FUSE dependency)
afpsld_sources = [
    'daemon.c',
    'commands.c',
    'daemon_client.c',
]

afpsld = executable(
    'afpsld',
    sources: afpsld_sources,
    dependencies: [
        pthread_dep,
    ],
    link_with: [libafpclient],
    include_directories: incdir,
    c_args: cflags,
    install: true,
)

# Stateless client library (NO FUSE dependency)
# This is what GUI applications link against
libafpsl = shared_library(
    'afpsl',
    sources: ['stateless.c'],
    dependencies: [],
    link_with: [libafpclient],
    include_directories: incdir,
    c_args: cflags,
    install: true,
    version: meson.project_version(),
)

# Generate pkg-config file for libafpsl
pkg.generate(
    libafpsl,
    description: 'AFP stateless client library for GUI applications',
    name: 'libafpsl',
)

# Note: The following are NOT built here:
# - mount_afp (client.c) - FUSE mount utility, should be built with fuse/
# - afp_extra (extra.c) - Optional CLI utility, can be built separately
# - FUSE-specific files: fuse_int.c, daemon_fuse.c, fuse_error.c
#   These are only used by afpfsd in the fuse/ directory
