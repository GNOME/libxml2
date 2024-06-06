
pymod = import('python')
py = pymod.find_installation('python3', required: false)

if py.found() == true
    r = run_command(py, 'generator.py', meson.current_source_dir(), check: true)

    libxml2mod_src = ['libxml.c', 'libxml2-py.c', 'types.c']

    message(py.get_install_dir())

    py.extension_module(
        'libxml2mod',
        files(libxml2mod_src),
        dependencies: [py.dependency(), xml_dep],
        include_directories: [config_dir],
        install: true,
    )

    setup_py = configuration_data()
    setup_py.set('prefix', get_option('prefix'))
    setup_py.set('LIBXML_VERSION', meson.project_version())
    setup_py.set('WITH_ICONV', iconv_dep.found().to_int())
    setup_py.set('WITH_ICU', icu_dep.found().to_int())
    setup_py.set('WITH_LZMA', lzma_dep.found().to_int())
    setup_py.set('WITH_ZLIB', zlib_dep.found().to_int())
    setup_py.set('WITH_THREADS', threads_dep.found().to_int())
    configure_file(
        input: 'setup.py.in',
        output: 'setup.py',
        configuration: setup_py,
    )

    subdir('tests')

endif
