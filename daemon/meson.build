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

libafpsl = shared_library(
    'afpsl',
    sources: ['stateless.c'],
    dependencies: root_dependencies,
    link_with: libafpclient,
    include_directories: incdir,
    c_args: cflags,
    install: true,
    version: meson.project_version(),
)

pkg.generate(
    libafpsl,
    description: 'AFP stateless client library for GUI applications',
    name: 'libafpsl',
)
