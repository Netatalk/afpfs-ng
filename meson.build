project(
  'afpfs-ng',
  'c',
  version: '0.8.2',
  license: 'GPLv2',
  default_options: ['warning_level=3', 'c_std=gnu99'],
  meson_version: '>=0.61',
)

cc = meson.get_compiler('c')
host_os = host_machine.system()

uname = find_program('uname', required: false)

uname_stdout = run_command(uname, '-a', check: false).stdout().strip()
libsearch_dirs = []

if host_os in ['dragonfly', 'freebsd', 'openbsd']
    libsearch_dirs += '/usr/local/lib'
endif

if host_os == 'netbsd'
    libsearch_dirs += '/usr/pkg/lib'
endif

if uname.found() and uname_stdout.to_lower().contains('omnios')
    libsearch_dirs += '/opt/local/lib'
endif

cflags = ['-D_FILE_OFFSET_BITS=64']
include_dirs = []

if host_os in ['dragonfly', 'freebsd', 'openbsd']
    include_dirs += ['/usr/local/include']
    cflags += '-DLIBICONV_PLUG'
elif host_os == 'netbsd'
    include_dirs += ['/usr/pkg/include']
elif host_os == 'omnios'
    include_dirs += ['/opt/local/include']
endif

ncurses_dep = cc.find_library('ncurses', dirs: libsearch_dirs, required: true)
readline_dep = cc.find_library('readline', dirs: libsearch_dirs, required: false)
pthread_dep = cc.find_library('pthread', dirs: libsearch_dirs, required: true)
libiconv_dep = cc.find_library('iconv', dirs: libsearch_dirs, required: false)

gcrypt_dep = dependency('libgcrypt', version: '>=1.2.3', required: false)
fuse_dep = cc.find_library('fuse', dirs: libsearch_dirs, required: false)

with_fuse = get_option('enable-fuse') and fuse_dep.found()

if with_fuse
  cflags += [
    '-DHAVE_LIBFUSE',
    '-DFUSE_USE_VERSION=29',
  ]
endif

incdir = include_directories(['.', 'include', include_dirs])

if gcrypt_dep.found()
  add_project_arguments('-DHAVE_LIBGCRYPT', language: 'c')
endif

subdir('lib')
subdir('cmdline')
subdir('docs')

if with_fuse
  subdir('fuse')
endif
