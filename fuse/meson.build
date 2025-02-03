mount_afp_sources = ['client.c']

mount_afp = executable(
  'mount_afp',
  sources: mount_afp_sources,
  include_directories: incdir,
  link_with: libafpclient,
  c_args: cflags,
  install: true,
)

afpfsd_sources = ['commands.c', 'daemon.c', 'fuse_int.c', 'fuse_error.c']

afpfsd = executable(
  'afpfsd',
  sources: afpfsd_sources,
  include_directories: incdir,
  link_with: libafpclient,
  c_args: cflags,
  dependencies: [fuse_dep, pthread_dep],
  install: true,
)

install_symlink('afp_client', pointing_to: 'mount_afp', install_dir: get_option('bindir'))

install_man(['afpfsd.1', 'afp_client.1', 'mount_afp.1'])
