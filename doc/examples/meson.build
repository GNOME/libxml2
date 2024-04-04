
## tests

example_checks = [
    ['io1', ''],
    ['io2', ''],
    ['parse1', 'test1.xml'],
    ['parse2', 'test2.xml'],
    ['parse3', ''],
    ['parse4', 'test3.xml'],
    ['reader1', 'test2.xml'],
    ['reader2', 'test2.xml'],
    ['reader3', ''],
    ['reader4', ['test1.xml', 'test2.xml', 'test3.xml']],
    ['testWriter', ''],
    ['tree1', 'test2.xml'],
    ['tree2', ''],
    ['xpath1', ['test3.xml', '//child2']],
    ['xpath2', ['test3.xml', '//discarded', 'discarded']],
]

foreach check : example_checks
    exe = executable(
        check[0],
        files(check[0] + '.c'),
        dependencies: xml_dep,
        include_directories: config_dir,
    )
    test(
        check[0],
        exe,
        args: check[1],
        timeout: 0,
        workdir: meson.current_source_dir(),
    )
endforeach

## example files

example_files = files(
    'index.html',
    'io1.c',
    'io2.c',
    'parse1.c',
    'parse2.c',
    'parse3.c',
    'parse4.c',
    'reader1.c',
    'reader2.c',
    'reader3.c',
    'reader4.c',
    'testWriter.c',
    'tree1.c',
    'tree2.c',
    'xpath1.c',
    'xpath2.c',
)

install_data(example_files, install_dir: dir_doc / 'examples')
