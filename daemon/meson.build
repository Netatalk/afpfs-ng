afpsld_sources = [
    'daemon.c',
    'commands.c',
    'daemon_client.c',
]

executable(
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
    include_directories: incdir,
    link_with: libafpclient,
    c_args: cflags,
    install: true,
    version: afpfsng_version,
)

pkg.generate(
    libafpsl,
    description: 'AFP stateless client library',
    name: 'libafpsl',
    version: afpfsng_version,
)

afpsl_dep = declare_dependency(
    link_with: libafpsl,
    include_directories: incdir,
    version: afpfsng_version,
)
