project(
    'libxml2',
    'c',
    version: '2.13.0',
    license: 'MIT',
    default_options: ['buildtype=debug', 'warning_level=3'],
    meson_version: '>= 0.61',
)

v_array = meson.project_version().split('.')
v_maj = v_array[0]
v_min = v_array[1]
v_mic = v_array[2]
v_nbr = v_maj.to_int() * 10000 + v_min.to_int() * 100 + v_mic.to_int()
v_extra = ''
r = run_command('git', 'describe', check: false)
if (r.returncode() == 0)
    v_extra = '-GIT' + r.stdout().strip()
endif

# install paths
dir_prefix = get_option('prefix')
dir_bin = dir_prefix / get_option('bindir')
dir_include = dir_prefix / get_option('includedir')
dir_pkginclude = dir_include / meson.project_name()
dir_lib = dir_prefix / get_option('libdir')
dir_data = dir_prefix / get_option('datadir')
dir_doc = dir_data / 'doc' / 'libxml2'
dir_locale = dir_prefix / get_option('localedir')

# host

host_os = host_machine.system()

cygwin = 'cygwin'
windows = 'windows'
sys_cygwin = cygwin.contains(host_os)
sys_windows = windows.contains(host_os)

libxml2_cflags = []
xml_cflags = ''
dep_args = []

if sys_cygwin or sys_windows
    if get_option('default_library') == 'static'
        xml_cflags = '-DLIBXML_STATIC'
        libxml2_cflags += '-DLIBXML_STATIC'
        dep_args += '-DLIBXML_STATIC'
    endif
endif

# binaries
cc = meson.get_compiler('c')

# options

# disabled by default
want_icu = get_option('icu').enabled()
want_legacy = get_option('legacy').enabled()
want_thread_alloc = get_option('thread-alloc').enabled()
want_tls = get_option('tls').enabled()

# default depends on minimum option

want_minimum = get_option('minimum')

feature = get_option('catalog')
want_catalog = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('debugging')
want_debug = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('html')
want_html = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('iconv')
want_iconv = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('ipv6')
want_ipv6 = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('iso8859x')
want_iso8859x = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('iso8859x')
want_python = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('modules')
want_modules = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('sax1')
want_sax1 = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('threads')
want_threads = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('valid')
want_valid = want_minimum ? feature.enabled() : feature.allowed()

# default depends on legacy option

feature = get_option('http')
want_http = want_legacy ? feature.allowed() : feature.enabled()

feature = get_option('lzma')
want_lzma = want_legacy ? feature.allowed() : feature.enabled()

feature = get_option('zlib')
want_zlib = want_legacy ? feature.allowed() : feature.enabled()

# dependencies

feature = get_option('output')
want_output = not want_minimum \
    or get_option('c14n').enabled() \
    or get_option('writer').enabled() ? \
    feature.allowed() : feature.enabled()

feature = get_option('pattern')
want_pattern = not want_minimum \
    or get_option('schemas').enabled() \
    or get_option('schematron').enabled() ? \
    feature.allowed() : feature.enabled()

feature = get_option('regexps')
want_regexps = not want_minimum \
    or get_option('schemas').enabled() ? \
    feature.allowed() : feature.enabled()

feature = get_option('push')
want_push = not want_minimum \
    or get_option('reader').enabled() \
    or get_option('writer').enabled() ? \
    feature.allowed() : feature.enabled()

feature = get_option('readline')
want_readline = get_option('history').enabled() ? \
    feature.allowed() : feature.enabled()

feature = get_option('xpath')
want_xpath = not want_minimum \
    or get_option('c14n').enabled() \
    or get_option('schematron').enabled() \
    or get_option('xinclude').enabled() \
    or get_option('xptr').enabled() ? \
    feature.allowed() : feature.enabled()

feature = get_option('c14n') \
    .require(want_output, error_message: 'c14n requires output') \
    .require(want_xpath, error_message: 'c14n requires xpath')
want_c14n = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('history') \
    .require(want_readline, error_message: 'history requires readline')
want_history = feature.enabled()

feature = get_option('reader') \
    .require(want_push, error_message: 'reader requires push')
want_reader = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('schemas') \
    .require(want_pattern, error_message: 'schemas requires pattern') \
    .require(want_regexps, error_message: 'schemas requires regexps')
want_schemas = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('schematron') \
    .require(want_pattern, error_message: 'schematron requires pattern') \
    .require(want_xpath, error_message: 'schematron requires xpath')
want_schematron = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('writer') \
    .require(want_output, error_message: 'writer requires output') \
    .require(want_push, error_message: 'writer requires push')
want_writer = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('xinclude') \
    .require(want_xpath, error_message: 'xinclude requires xpath')
want_xinclude = want_minimum ? feature.enabled() : feature.allowed()

feature = get_option('xptr') \
    .require(want_xpath, error_message: 'xptr requires xpath')
want_xptr = want_minimum ? feature.enabled() : feature.allowed()

cflags_try = []

### workaround for native compilers, see configure.ac
if cc.get_argument_syntax() == 'gcc'
    cflags_try += [
        '-Wshadow',
        '-Wpointer-arith',
        '-Wcast-align',
        '-Wwrite-strings',
        '-Wstrict-prototypes',
        '-Wmissing-prototypes',
        '-Wno-long-long',
        '-Wno-format-extra-args',
    ]

    if host_machine.cpu_family() == 'alpha'
        cflags_try += '-mieee'
    endif
else
    if host_machine.cpu_family() == 'alpha'
        cflags_try += '-ieee'
    elif host_machine.cpu_family() == 'parisc'
        cflags_try += '-Wp,-H30000'
    endif
endif

foreach cf : cflags_try
    if cc.has_argument(cf)
        libxml2_cflags += cf
    endif
endforeach

# configuration
#
# X : done
# N : not done
#
# [X] config.h.in
# [X] include/libxml/xmlversion.h.in
# [X] libxml-2.0.pc.in
# [X] libxml2-config.cmake.in
# [X] python/setup.py.in
# [N] xml2-config.in

## config.h
config_h = configuration_data()
config_h.set_quoted('PACKAGE_NAME', meson.project_name())
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
config_h.set_quoted('PACKAGE_BIN_DIR', dir_bin)
config_h.set_quoted('PACKAGE_LIB_DIR', dir_lib)
config_h.set_quoted('PACKAGE_DATA_DIR', dir_data)
config_h.set_quoted('LOCALEDIR', dir_locale)

# header files
xml_check_headers = [
    'stdint.h',
    'fcntl.h',
    'unistd.h',
    'sys/stat.h',
    'sys/mman.h',
    'sys/socket.h',
    'netinet/in.h',
    'arpa/inet.h',
    'netdb.h',
    'sys/select.h',
    'poll.h',
    'sys/time.h',
    'sys/timeb.h',
    'dl.h',
    'dlfcn.h',
    'glob.h',
]

foreach header : xml_check_headers
    if cc.has_header(header)
        config_h.set10('HAVE_' + header.underscorify().to_upper(), true)
    endif
endforeach

# library functions
xml_check_functions = [
    # fct             | header
    ['gettimeofday', 'sys/time.h'],
    ['ftime', 'sys/timeb.h'],
    ['stat', 'sys/stat.h'],
    ['mmap', 'sys/mman.h'],
    ['munmap', 'sys/mman.h'],
]

foreach function : xml_check_functions
    if cc.has_header_symbol(function[1], function[0])
        config_h.set10('HAVE_' + function[0].to_upper(), true)
    endif
endforeach

# library

config_dir = [include_directories('.'), include_directories('include')]

## dependencies

xml_deps = []

### math library
if sys_windows == false
    m_dep = cc.find_library('m', required: false)
    if m_dep.found()
        xml_deps += m_dep
    endif
endif

### thread local storage
if want_tls
    foreach t : ['_Thread_local', '__thread', '__declspec(thread)']
        if cc.compiles('@0@ int v;'.format(t))
            config_h.set('XML_THREAD_LOCAL', t)
            break
        endif
    endforeach
endif

### __attribute__((destructor))
if cc.has_function_attribute('destructor')
    config_h.set10('HAVE_ATTRIBUTE_DESTRUCTOR', true)
    config_h.set('ATTRIBUTE_DESTRUCTOR', '__attribute__((destructor))')
endif

### DSO support
if sys_cygwin == true
    module_extension = '.dll'
elif sys_windows == true
    module_extension = '.dll'
else
    module_extension = '.so'
endif

if want_modules and host_machine.system() != 'windows'
    if meson.version().version_compare('>=0.62')
        dl_dep = dependency('dl', required: false)
    else
        dl_dep = cc.find_library('dl', required: false)
    endif
    if dl_dep.found()
        config_h.set10('HAVE_DLOPEN', true)
        xml_deps += dl_dep
    endif
endif

### threads
if want_threads
    threads_dep = dependency('threads')
    config_h.set10('HAVE_PTHREAD_H', true)
    xml_deps += threads_dep
else
    threads_dep = dependency('', required: false)
endif

### xmllint shell history
xmllint_deps = []

if want_readline
    readline_dep = dependency('readline')
    config_h.set('HAVE_LIBREADLINE', true)
    xmllint_deps += readline_dep
endif

if want_history
    history_dep = dependency('history')
    config_h.set('HAVE_LIBHISTORY', true)
    xmllint_deps += history_dep
endif

### crypto
if sys_windows == true
    bcrypt_dep = cc.find_library('bcrypt', required: true)
    xml_deps += bcrypt_dep
endif

### inet
if want_http == true
    if sys_windows == true
        net_dep = cc.find_library('ws2_32', required: true)
        xml_deps += net_dep
    else
        net_dep = dependency('', required: false)
        has_in_libc = cc.has_function('gethostbyname')
        if has_in_libc == false
            net_dep = cc.find_library('nsl', required: true)
            if net_dep.found()
                has_in_nsl = cc.has_function(
                    'gethostbyname',
                    dependencies: net_dep,
                    required: false,
                )
                if has_in_nsl == true
                    xml_deps += net_dep
                endif
            endif
        endif
    endif

    ### socket length
    if sys_windows
        netheader = 'winsock2.h'
    else
        netheader = 'sys/socket.h'
    endif
    foreach t : ['socklen_t', 'size_t', 'int']
        if cc.compiles('#include <@0@.h> int main(){getsockopt(1,1,1,0,(@1@*)0);}'.format(netheader, t), dependencies: net_dep)
            cdata.set('XML_SOCKLEN_T', t)
            break
        endif
    endforeach

    if want_ipv6 == true
        config_h.set('SUPPORT_IP6', cc.has_header_symbol(netheader, 'AF_INET6', required: get_option('ipv6')))
    endif
endif

### zlib
if want_zlib
    xml_deps += dependency('zlib')
endif

### lzma
if want_lzma
    xml_deps += dependency('liblzma')
endif

# icu
if want_icu
    icu_dep = dependency('icu-i18n', method: 'pkg-config')
    defs = icu_dep.get_variable(pkgconfig: 'DEFS')
    if cc.has_argument(defs)
        libxml2_cflags += defs
    endif
    xml_deps += icu_dep
endif

### iconv
if want_iconv
    xml_deps += dependency('iconv')
endif

subdir('include/libxml')

# Set config_h after all subdirs and dependencies have set values

configure_file(output: 'config.h', configuration: config_h)

## libxml2 library

xml_src = [
    'buf.c',
    'chvalid.c',
    'dict.c',
    'entities.c',
    'encoding.c',
    'error.c',
    'globals.c',
    'hash.c',
    'list.c',
    'parser.c',
    'parserInternals.c',
    'SAX2.c',
    'threads.c',
    'tree.c',
    'uri.c',
    'valid.c',
    'xmlIO.c',
    'xmlmemory.c',
    'xmlstring.c',
]

xml_opt_src = [
    [want_c14n, ['c14n.c']],
    [want_catalog, ['catalog.c']],
    [want_debug, ['debugXML.c']],
    [want_html, ['HTMLparser.c', 'HTMLtree.c']],
    [want_http, ['nanohttp.c']],
    [want_legacy, ['legacy.c']],
    [want_lzma, ['xzlib.c']],
    [want_modules, ['xmlmodule.c']],
    [want_output, ['xmlsave.c']],
    [want_pattern, ['pattern.c']],
    [want_reader, ['xmlreader.c']],
    [want_regexps, ['xmlregexp.c', 'xmlunicode.c']],
    [want_schemas, ['relaxng.c', 'xmlschemas.c', 'xmlschemastypes.c']],
    [want_schemas and not want_xpath, ['xpath.c']],
    [want_schematron, ['schematron.c']],
    [want_writer, ['xmlwriter.c']],
    [want_xinclude, ['xinclude.c']],
    [want_xpath, ['xpath.c']],
    [want_xptr, ['xlink.c', 'xpointer.c']],
]

foreach file : xml_opt_src
    want = file[0]
    src = file[1]
    if want == true
        if src.length() > 1
            foreach s : src
                xml_src += s
            endforeach
        else
            xml_src += src
        endif
    endif
endforeach

xml_lib = library(
    'xml2',
    files(xml_src),
    c_args: libxml2_cflags,
    dependencies: xml_deps,
    include_directories: config_dir,
    install: true,
    version: meson.project_version(),
)

dep_inc = include_directories('include')
xml_dep = declare_dependency(include_directories: dep_inc, link_with: xml_lib, compile_args: dep_args)

meson.override_dependency('libxml-2.0', xml_dep)

## xmllint tool

executable(
    'xmllint',
    files('xmllint.c', 'shell.c'),
    dependencies: [xml_dep, xmllint_deps],
    include_directories: config_dir,
    install: true,
)

## xmlcatalog tool

executable(
    'xmlcatalog',
    files('xmlcatalog.c'),
    dependencies: [xml_dep, xmllint_deps],
    include_directories: config_dir,
    install: true,
)

## testdso module

testdso_mod = shared_module(
    'testdso',
    files('testdso.c'),
    build_rpath: get_option('libdir'),
    include_directories: config_dir,
    name_prefix: '',
)

## tests

checks = {
    'runsuite': [],
    'runtest': threads_dep,
    'runxmlconf': [],
# Disabled for now, see #694
#    'testModule': [],
    'testapi': [],
    'testchar': [],
    'testdict': [],
    'testlimits': [],
    'testparser': [],
    'testrecurse': [],
}

foreach check, deps : checks
    exe = executable(
        check,
        files(check + '.c'),
        dependencies: [deps, xml_dep],
        include_directories: config_dir,
    )
    if check != 'testlimits'
        test(check, exe, timeout: 0, workdir: meson.current_source_dir())
    endif
endforeach

subdir('example')
subdir('doc')

if want_python == true
    subdir('python')
endif

## pc files

pkgmod = import('pkgconfig')

pkgmod.generate(
    xml_lib,
    description: 'libXML library version2.',
    filebase: 'libxml-2.0',
    name: 'libXML',
    subdirs:  [meson.project_name()],
    variables: 'modules=' + want_modules.to_string('1', '0'),
)

## libxml2-config.cmake file

config_cmake = configuration_data()
config_cmake.set('LIBXML_MAJOR_VERSION', v_maj)
config_cmake.set('LIBXML_MINOR_VERSION', v_min)
config_cmake.set('LIBXML_MICRO_VERSION', v_mic)
config_cmake.set('VERSION', meson.project_version())
config_cmake.set('WITH_ICONV', want_iconv.to_int().to_string())
config_cmake.set('WITH_ICU', want_icu.to_int().to_string())
config_cmake.set('WITH_LZMA', want_lzma.to_int().to_string())
config_cmake.set('WITH_MODULES', want_modules.to_int().to_string())
config_cmake.set('WITH_THREADS', want_threads.to_int().to_string())
config_cmake.set('WITH_ZLIB', want_zlib.to_int().to_string())
config_cmake.set('XML_CFLAGS', xml_cflags)
configure_file(
    input: 'libxml2-config.cmake.in',
    output: 'libxml2-config.cmake',
    configuration: config_cmake,
    install_dir: dir_lib / 'cmake' / 'libxml2',
)

# summary

summary(
    {
        'OS': host_os,
        'c14n': want_c14n,
        'catalog': want_catalog,
        'debug': want_debug,
        'history': want_history,
        'html': want_html,
        'http': want_http,
        'iconv': want_iconv,
        'icu': want_icu,
        'ipv6': want_ipv6,
        'iso8859x': want_iso8859x,
        'legacy': want_legacy,
        'lzma': want_lzma,
        'modules': want_modules,
        'output': want_output,
        'pattern': want_pattern,
        'push': want_push,
        'python': want_python,
        'reader': want_reader,
        'readline': want_readline,
        'regexps': want_regexps,
        'sax1': want_sax1,
        'schemas': want_schemas,
        'schematron': want_schematron,
        'threads': want_threads,
        'thread-alloc': want_thread_alloc,
        'tls': want_tls,
        'valid': want_valid,
        'writer': want_writer,
        'xinclude': want_xinclude,
        'xpath': want_xpath,
        'xptr': want_xptr,
        'zlib': want_zlib,
    },
    section: 'Configuration Options Summary:',
)
