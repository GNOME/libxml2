
pymod = import('python')
py = pymod.find_installation('python3', required: false)

if py.found() == true
    message('Installing python modules to', py.get_install_dir())

    pygenerated = custom_target(
        'Python generated files',
        input: files('generator.py'),
        depend_files: files(
            '..' / 'doc' / 'libxml2-api.xml',
            'libxml2-python-api.xml',
        ),
        output: [
            'libxml2-py.h',
            'libxml2-export.c',
            'libxml2-py.c',
            'libxml2class.py',
            'libxml2class.txt',
        ],
        command: [py, '@INPUT@', meson.current_build_dir()],
    )
    pygenerated_dep = declare_dependency(
        sources : [pygenerated[0]],
    )

    libxml2_py = custom_target(
        'libxml2.py',
        input: [files('libxml.py'), pygenerated[3]],
        output: 'libxml2.py',
        command: [find_program('cat'), '@INPUT@'],
        capture: true,
        install: true,
        install_dir: py.get_install_dir(),
    )

    libxml2mod_src = [
        files('libxml.c', 'types.c'),
        pygenerated[2],
    ]

    py.extension_module(
        'libxml2mod',
        libxml2mod_src,
        dependencies: [
            py.dependency(),
            xml_dep,
            pygenerated_dep,
        ],
        include_directories: [config_dir, '.'],
        install: true,
    )

    py.install_sources(files('drv_libxml2.py'))

    setup_py = configuration_data()
    setup_py.set('prefix', get_option('prefix'))
    setup_py.set('LIBXML_VERSION', meson.project_version())
    setup_py.set('WITH_ICONV', want_iconv.to_int())
    setup_py.set('WITH_ICU', want_icu.to_int())
    setup_py.set('WITH_LZMA', want_lzma.to_int())
    setup_py.set('WITH_ZLIB', want_zlib.to_int())
    setup_py.set('WITH_THREADS', want_threads.to_int())
    configure_file(
        input: 'setup.py.in',
        output: 'setup.py',
        configuration: setup_py,
    )

    subdir('tests')

endif
