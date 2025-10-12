if cmarkgfm.found()
    readme_docs_files = [
        'DEVELOPER',
        'FEATURES',
        'GETTING_STARTED',
        'PERFORMANCE',
        'REPORTING_BUGS',
    ]

    foreach file : readme_docs_files
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

if cmark_man.found()
    subdir('manpages')
endif
