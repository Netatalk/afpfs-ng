make_man = find_program('make_man.sh')

manfiles = []

if with_afpcmd
    manfiles += [
        'afpcmd',
        'afpgetstatus',
    ]
endif

if with_fuse
    manfiles += [
        'afp_client',
        'afpfsd',
        'mount_afpfs',
    ]
endif

foreach man : manfiles
    custom_target(
        man + '.1',
        input: man + '.1.md',
        output: man + '.1',
        command: [
            make_man,
            cmark_man,
            '@INPUT@',
            man,
            '1',
            afpfsng_version,
        ],
        capture: true,
        install: true,
        install_dir: mandir / 'man1',
        build_by_default: true,
    )
endforeach
