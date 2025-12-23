# Stateless AFP client library (libafpsl)
# This library provides a stateless IPC interface to the afpfsd daemon
libafpsl = static_library(
    'afpsl',
    sources: ['stateless.c'],
    include_directories: incdir,
    c_args: cflags,
    dependencies: [root_dependencies],
)

# Original mount client (uses IPC to daemon for mount commands)
mount_afpfs_sources = ['client.c']

executable(
    'mount_afpfs',
    sources: mount_afpfs_sources,
    include_directories: incdir,
    link_with: libafpclient,
    c_args: cflags,
    dependencies: [root_dependencies],
    install: true,
)

# AFP daemon with FUSE support
afpfsd_sources = ['commands.c', 'daemon.c', 'fuse_int.c', 'fuse_error.c']

executable(
    'afpfsd',
    sources: afpfsd_sources,
    include_directories: incdir,
    link_with: libafpclient,
    c_args: cflags,
    dependencies: [root_dependencies, fuse_dep, pthread_dep],
    install: true,
)

# Stateless FUSE client (thin shim that uses libafpsl for all operations)
# This is the new architecture that solves concurrency issues
mount_afpfs_sl_sources = ['fuse_stateless.c', 'fuse_error.c']

executable(
    'mount_afpfs_sl',
    sources: mount_afpfs_sl_sources,
    include_directories: incdir,
    link_with: [libafpsl, libafpclient],
    c_args: cflags,
    dependencies: [root_dependencies, fuse_dep],
    install: true,
)

install_symlink('afp_client', pointing_to: 'mount_afpfs', install_dir: bindir)
