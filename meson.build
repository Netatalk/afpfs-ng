project(
  'afpfs-ng',
  'c',
  version: '0.9.0',
  license: 'GPLv2',
  default_options: ['warning_level=3', 'c_std=c11'],
  meson_version: '>=0.61',
)

cc = meson.get_compiler('c')
host_os = host_machine.system()
build_type = get_option('buildtype')
afpfsng_version = meson.project_version()

install_prefix = get_option('prefix')
bindir = install_prefix / get_option('bindir')
libdir = install_prefix / get_option('libdir')
mandir = install_prefix / get_option('mandir')
datadir = install_prefix / get_option('datadir')

root_dependencies = []
libsearch_dirs = []
include_dirs = []
cflags = [
  '-DAFPFS_VERSION="' + afpfsng_version + '"',
  '-DBINDIR=' + bindir,
  '-D_FILE_OFFSET_BITS=64',
  '-D_GNU_SOURCE',
]

if build_type == 'debug'
    cflags += '-DDEBUG'
endif

if host_os in ['dragonfly', 'freebsd', 'openbsd']
    libsearch_dirs += '/usr/local/lib'
    include_dirs += ['/usr/local/include']
    cflags += '-DLIBICONV_PLUG'
elif host_os == 'netbsd'
    libsearch_dirs += '/usr/pkg/lib'
    include_dirs += ['/usr/pkg/include']
endif

ncurses_dep = cc.find_library('ncurses', dirs: libsearch_dirs, required: false)
readline_dep = cc.find_library('readline', dirs: libsearch_dirs, required: false)
pthread_dep = cc.find_library('pthread', dirs: libsearch_dirs, required: true)
libiconv_dep = cc.find_library('iconv', dirs: libsearch_dirs, required: false)
libbsd_dep = cc.find_library('bsd', dirs: libsearch_dirs, required: false)

if libbsd_dep.found()
    root_dependencies += libbsd_dep
    cflags += '-DHAVE_LIBBSD'
endif

gcrypt_dep = dependency('libgcrypt', version: '>=1.2.3', required: false)
libgmp_dep = dependency('gmp', required: false)
fuse_dep = cc.find_library('fuse', dirs: libsearch_dirs, required: false)

cmark = find_program('cmark', required: false)
cmarkgfm = find_program('cmark-gfm', required: false)

if cmark.found()
    cmark_man = cmark
else
    cmark_man = cmarkgfm
endif

with_afpcmd = ncurses_dep.found() and readline_dep.found()
with_fuse = get_option('enable-fuse') and fuse_dep.found()
with_crypt = gcrypt_dep.found() and libgmp_dep.found()

if with_fuse
  cflags += [
    '-DHAVE_LIBFUSE',
    '-DFUSE_USE_VERSION=29',
  ]
endif

incdir = include_directories(['.', 'include', include_dirs])

if with_crypt
  add_project_arguments('-DHAVE_LIBGCRYPT', language: 'c')
endif

subdir('lib')

if with_afpcmd
  subdir('cmdline')
endif

if with_fuse
  subdir('fuse')
endif

install_data(
  ['AUTHORS', 'BUGS', 'COPYING', 'NEWS', 'TODO'],
  install_dir: datadir / 'doc' / 'afpfs-ng',
)

if cmarkgfm.found()
  foreach file : ['INSTALL', 'README']
    custom_target(
      'readmes_' + file,
      input: file + '.md',
      output: file + '.txt',
      command: [
          cmarkgfm,
          '--width', '80',
          '--to', 'plaintext',
          '@INPUT@',
      ],
      capture: true,
      install: true,
      install_dir: datadir / 'doc' / 'afpfs-ng',
    )
  endforeach
endif

subdir('docs')

summary_info = {
    'Build directory': meson.current_build_dir(),
    'Source path': meson.current_source_dir(),
}
summary(summary_info, bool_yn: true, section: 'Build environment:')

summary_info = {
    'Installation prefix': install_prefix,
    'Executable directory': bindir,
    'Library directory': libdir,
    'Manual page directory': mandir,
}
summary(summary_info, bool_yn: true, section: 'Directories:')

summary_info = {
    'Host CPU': host_machine.cpu_family(),
    'Host endianness': build_machine.endian(),
    'C compiler': cc.get_id(),
    'Build stype': build_type,
    'Shared or static libraries': get_option('default_library'),
}
summary(summary_info, bool_yn: true, section: 'Compilation:')

summary_info = {
    'AFP CLI client': with_afpcmd,
    'AFP FUSE client': with_fuse,
    'DHX2 / DHX UAM support': with_crypt,
    'man pages': cmark_man.found(),
}
summary(summary_info, bool_yn: true, section: 'Options:')
