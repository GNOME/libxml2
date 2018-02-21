cmake_minimum_required(VERSION 3.10)

project(libxml2 C)

configure_file(include/libxml/xmlwin32version.h include/libxml/xmlversion.h COPYONLY)    
configure_file(include/win32config.h include/config.h COPYONLY)    

include_directories(
    ./include
    ${CMAKE_BINARY_DIR}/include # configure_file above puts xmlversion.h here.
    )

set(SOURCE_FILES
    buf.c
    c14n.c
    catalog.c
    chvalid.c
    debugXML.c
    dict.c
    DOCBparser.c
    encoding.c
    entities.c
    error.c
    globals.c
    hash.c
    HTMLparser.c
    HTMLtree.c
    legacy.c
    list.c
    nanoftp.c
    nanohttp.c
    parser.c
    parserInternals.c
    pattern.c
#    relaxng.c
#    rngparser.c
#    runsuite.c
#    runtest.c
#    runxmlconf.c
    SAX.c
    SAX2.c
    schematron.c
    tree.c
    trio.c
    trionan.c
    triostr.c
    uri.c
    valid.c
    xinclude.c
    xlink.c
    xmlcatalog.c
    xmlIO.c
#    xmllint.c
    xmlmemory.c
    xmlmodule.c
    xmlreader.c
    xmlregexp.c
    xmlsave.c
    xmlschemas.c
    xmlschemastypes.c
    xmlstring.c
    xmlunicode.c
    xmlwriter.c
    xpath.c
    xpointer.c
    xzlib.c
    )

set(TEST_FILES
    testapi.c
    testAutomata.c
    testC14N.c
    testchar.c
    testdict.c
    testdso.c
    testHTML.c
    testlimits.c
    testModule.c
    testOOM.c
    testOOMlib.c
    testReader.c
    testrecurse.c
    testRegexp.c
    testRelax.c
    testSAX.c
    testSchemas.c
    testThreads.c
    testThreadsWin32.c
    testURI.c
    testXPath.c
    threads.c
    )

set(HEADER_FILES
    include/libxml/c14n.h
    include/libxml/catalog.h
    include/libxml/chvalid.h
    include/libxml/debugXML.h
    include/libxml/dict.h
    include/libxml/DOCBparser.h
    include/libxml/encoding.h
    include/libxml/entities.h
    include/libxml/globals.h
    include/libxml/hash.h
    include/libxml/HTMLparser.h
    include/libxml/HTMLtree.h
    include/libxml/list.h
    include/libxml/nanoftp.h
    include/libxml/nanohttp.h
    include/libxml/parser.h
    include/libxml/parserInternals.h
    include/libxml/pattern.h
    include/libxml/relaxng.h
    include/libxml/SAX.h
    include/libxml/SAX2.h
    include/libxml/schemasInternals.h
    include/libxml/schematron.h
    include/libxml/threads.h
    include/libxml/tree.h
    include/libxml/uri.h
    include/libxml/valid.h
    include/libxml/xinclude.h
    include/libxml/xlink.h
    include/libxml/xmlautomata.h
    include/libxml/xmlerror.h
    include/libxml/xmlexports.h
    include/libxml/xmlIO.h
    include/libxml/xmlmemory.h
    include/libxml/xmlmodule.h
    include/libxml/xmlreader.h
    include/libxml/xmlregexp.h
    include/libxml/xmlsave.h
    include/libxml/xmlschemas.h
    include/libxml/xmlschemastypes.h
    include/libxml/xmlstring.h
    include/libxml/xmlunicode.h
    include/libxml/xmlversion.h
    include/libxml/xmlwriter.h
    include/libxml/xpath.h
    include/libxml/xpathInternals.h
    include/libxml/xpointer.h
    ${CMAKE_BINARY_DIR}/include/libxml/xmlversion.h
    )

add_definitions(-DLIBXML_READER_ENABLED)
set_source_files_properties(${SOURCE_FILES} PROPERTIES LANGUAGE C)

add_library(libxml2 ${SOURCE_FILES} ${HEADER_FILES})
set_target_properties(libxml2 PROPERTIES LANGUAGE C)

install(TARGETS libxml2 ARCHIVE DESTINATION lib)
install(DIRECTORY include/libxml DESTINATION include)
install(FILES ${CMAKE_BINARY_DIR}/include/libxml/xmlversion.h DESTINATION include/libxml)
