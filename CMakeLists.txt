CMAKE_MINIMUM_REQUIRED(VERSION 3.7.0)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE STRING "Modules for CMake" FORCE)

PROJECT(libxml2)

SET(LIBXML2_VERSION_MAJOR 2)
SET(LIBXML2_VERSION_MINOR 9)
SET(LIBXML2_VERSION_MICRO 8)
SET(LIBXML2_VERSION ${LIBXML2_VERSION_MAJOR}.${LIBXML2_VERSION_MINOR}.${LIBXML2_VERSION_MICRO})

INCLUDE(GNUInstallDirs)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckTypeSize)
INCLUDE(CheckSymbolExists)

# Macros & Functions
MACRO(bool_to_int OUT IN)
  IF(${IN})
    SET(${OUT} 1)
  ELSE()
    SET(${OUT} 0)
  ENDIF()
ENDMACRO()


CHECK_INCLUDE_FILES("arpa/inet.h" HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES("arpa/nameser.h" HAVE_ARPA_NAMESER_H)
CHECK_INCLUDE_FILES("ctype.h" HAVE_CTYPE_H)
CHECK_INCLUDE_FILES("dirent.h" HAVE_DIRENT_H)
CHECK_INCLUDE_FILES("dlfcn.h" HAVE_DLFCN_H)
CHECK_INCLUDE_FILES("dl.h" HAVE_DL_H)
CHECK_INCLUDE_FILES("errno.h" HAVE_ERRNO_H)
CHECK_INCLUDE_FILES("fcntl.h" HAVE_FCNTL_H)
CHECK_INCLUDE_FILES("float.h" HAVE_FLOAT_H)
CHECK_INCLUDE_FILES("inttypes.h" HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES("limits.h" HAVE_LIMITS_H)
CHECK_INCLUDE_FILES("lzma.h" HAVE_LZMA_H)
CHECK_INCLUDE_FILES("malloc.h" HAVE_MALLOC_H)
CHECK_INCLUDE_FILES("math.h" HAVE_MATH_H)
CHECK_INCLUDE_FILES("memory.h" HAVE_MEMORY_H)
CHECK_INCLUDE_FILES("ndir.h" HAVE_NDIR_H)
CHECK_INCLUDE_FILES("netdb.h" HAVE_NETDB_H)
CHECK_INCLUDE_FILES("netinet/in.h" HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES("poll.h" HAVE_POLL_H)
CHECK_INCLUDE_FILES("pthread.h" HAVE_PTHREAD_H)
CHECK_INCLUDE_FILES("resolv.h" HAVE_RESOLV_H)
CHECK_INCLUDE_FILES("signal.h" HAVE_SIGNAL_H)
CHECK_INCLUDE_FILES("stdarg.h" HAVE_STDARG_H)
CHECK_INCLUDE_FILES("stdlib.h" HAVE_STDLIB_H)
CHECK_INCLUDE_FILES("string.h" HAVE_STRING_H)
CHECK_INCLUDE_FILES("strings.h" HAVE_STRINGS_H)
CHECK_INCLUDE_FILES("sys/dir.h" HAVE_SYS_DIR_H)
IF(HAVE_SYS_DIR_H)
    UNSET(HAVE_SYS_DIR_H CACHE)
    CHECK_SYMBOL_EXISTS(DIR "sys/dir.h" HAVE_SYS_DIR_H)
ENDIF(HAVE_SYS_DIR_H)
CHECK_INCLUDE_FILES("sys/ndir.h" HAVE_SYS_NDIR_H)
IF(HAVE_SYS_NDIR_H)
    UNSET(HAVE_SYS_NDIR_H CACHE)
    CHECK_SYMBOL_EXISTS(DIR "sys/ndir.h" HAVE_SYS_NDIR_H)
ENDIF(HAVE_SYS_NDIR_H)
CHECK_INCLUDE_FILES("sys/mman.h" HAVE_SYS_MMAN_H)
CHECK_INCLUDE_FILES("sys/select.h" HAVE_SYS_SELECT_H)
CHECK_INCLUDE_FILES("sys/stat.h" HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES("sys/socket.h" HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES("sys/time.h" HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES("sys/timeb.h" HAVE_SYS_TIMEB_H)
CHECK_INCLUDE_FILES("sys/types.h" HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES("time.h" HAVE_TIME_H)
CHECK_INCLUDE_FILES("unistd.h" HAVE_UNISTD_H)
CHECK_INCLUDE_FILES("zlib.h" HAVE_ZLIB_H)

CHECK_FUNCTION_EXISTS(fprintf HAVE_FPRINTF)
CHECK_FUNCTION_EXISTS(ftime HAVE_FTIME)
CHECK_FUNCTION_EXISTS(getaddrinfo HAVE_GETADDRINFO)
CHECK_FUNCTION_EXISTS(gettimeofday HAVE_GETTIMEOFDAY)
CHECK_FUNCTION_EXISTS(isascii HAVE_ISASCII)
CHECK_FUNCTION_EXISTS(isinf HAVE_ISINF)
CHECK_FUNCTION_EXISTS(isnan HAVE_ISNAN)
CHECK_FUNCTION_EXISTS(localtime HAVE_LOCALTIME)
CHECK_FUNCTION_EXISTS(mmap HAVE_MMAP)
CHECK_FUNCTION_EXISTS(munmap HAVE_MUNMAP)
CHECK_FUNCTION_EXISTS(printf HAVE_PRINTF)
CHECK_FUNCTION_EXISTS(putenv HAVE_PUTENV)
CHECK_FUNCTION_EXISTS(rand HAVE_RAND)
CHECK_FUNCTION_EXISTS(rand_r HAVE_RAND_R)
CHECK_FUNCTION_EXISTS(signal HAVE_SIGNAL)
CHECK_FUNCTION_EXISTS(snprintf HAVE_SNPRINTF)
CHECK_FUNCTION_EXISTS(sprintf HAVE_SPRINTF)
CHECK_FUNCTION_EXISTS(srand HAVE_SRAND)
CHECK_FUNCTION_EXISTS(sscanf HAVE_SSCANF)
CHECK_FUNCTION_EXISTS(stat HAVE_STAT)
CHECK_FUNCTION_EXISTS(strftime HAVE_STRFTIME)
CHECK_FUNCTION_EXISTS(time HAVE_TIME)
CHECK_FUNCTION_EXISTS(va_copy HAVE_VA_COPY)
CHECK_FUNCTION_EXISTS(vfprintf HAVE_VFPRINTF)
CHECK_FUNCTION_EXISTS(vsnprintf HAVE_VSNPRINTF)
CHECK_FUNCTION_EXISTS(vsprintf HAVE_VSPRINTF)

IF(HAVE_DL_H)
  SET(CMAKE_REQUIRED_INCLUDES "dl.h")
  SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_DL_LIBS}")
  CHECK_FUNCTION_EXISTS(dlopen HAVE_DLOPEN)
  UNSET(CMAKE_REQUIRED_INCLUDES)
  UNSET(CMAKE_REQUIRED_LIBRARIES)
ENDIF(HAVE_DL_H)

IF(HAVE_DLFCN_H)
  SET(CMAKE_REQUIRED_INCLUDES "dlfcn.h")
  SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_DL_LIBS}")
  CHECK_FUNCTION_EXISTS(dlopen HAVE_DLOPEN)
  UNSET(CMAKE_REQUIRED_INCLUDES)
  UNSET(CMAKE_REQUIRED_LIBRARIES)
ENDIF(HAVE_DLFCN_H)

CHECK_TYPE_SIZE("uint32_t" HAVE_UINT32_T)

OPTION(ENABLE_ZLIB "Enable the use of the system ZLIB library if found" ON)
OPTION(ENABLE_LZMA "Enable the use of the system LZMA library if found" ON)

OPTION(ENABLE_C14N "Add the Canonicalization support" ON)
OPTION(ENABLE_CATALOG "Add the Catalog support" ON)
OPTION(ENABLE_DEBUG "Add the debugging code" ON)
OPTION(ENABLE_FTP "Add the FTP support" ON)
OPTION(ENABLE_HTML "Add the HTML support" ON)
OPTION(ENABLE_HTTP "Add the HTTP support" ON)
OPTION(ENABLE_ICONV "Add ICONV support" ON)
OPTION(ENABLE_ICU "Add ICU support" ON)
OPTION(ENABLE_IPV6 "Enables compilation of IPv6 code" ON)
OPTION(ENABLE_LEGACY "Add deprecated APIs for compatibility" ON)
OPTION(ENABLE_MEM_DEBUG "Add the memory debugging module" OFF)
OPTION(ENABLE_MODULE "Add the dynamic modules support" ON)
OPTION(ENABLE_OUTPUT "Add the serialization support" ON)
OPTION(ENABLE_PATTERN "Add the xmlPattern selection interface" ON)
OPTION(ENABLE_PUSH "Add the PUSH parser interfaces" ON)
OPTION(ENABLE_READER "Add the xmlReader parsing interface" ON)
OPTION(ENABLE_REGEXPS "Add Regular Expressions support" ON)
OPTION(ENABLE_RUN_DEBUG "Add the runtime debugging module" OFF)
OPTION(ENABLE_SAX1 "Add the older SAX1 interface" ON)
OPTION(ENABLE_SCHEMAS "Add Relax-NG and Schemas support" ON)
OPTION(ENABLE_SCHEMATRON "Add Schematron support" ON)
OPTION(ENABLE_TREE "Add the DOM like tree manipulation APIs" ON)
OPTION(ENABLE_VALID "Add the DTD validation support" ON)
OPTION(ENABLE_WRITTER "Add the xmlWriter saving interface" ON)
OPTION(ENABLE_XINCLUDE "Add the XInclude support" ON)
OPTION(ENABLE_XPATH "Add the XPATH support" ON)
OPTION(ENABLE_XPTR "Add the XPointer support" ON)

SET(ADDITIONAL_LIBS "")

find_package(Threads REQUIRED)

#
# Find ZLIB
#
IF(ENABLE_ZLIB)
  FIND_PACKAGE(ZLIB)
ELSE()
  SET(ZLIB_FOUND FALSE) # Override cached value
ENDIF()
IF(ZLIB_FOUND)
  INCLUDE_DIRECTORIES("${ZLIB_INCLUDE_DIR}")
  LIST(APPEND ADDITIONAL_LIBS ${ZLIB_LIBRARIES})
ENDIF(ZLIB_FOUND)
MARK_AS_ADVANCED(CLEAR ZLIB_INCLUDE_DIR)
MARK_AS_ADVANCED(CLEAR ZLIB_LIBRARY)

#
# Find LZMA
#
IF(ENABLE_LZMA)
  FIND_PACKAGE(LibLZMA)
ELSE(ENABLE_LZMA)
  SET(LIBZMA_FOUND FALSE) # Override cached value
ENDIF(ENABLE_LZMA)

IF(LIBLZMA_FOUND)
  INCLUDE_DIRECTORIES("${LIBLZMA_INCLUDE_DIRS}")
  LIST(APPEND ADDITIONAL_LIBS ${LIBLZMA_LIBRARIES})
ENDIF(LIBLZMA_FOUND)

#
# Find ICONV
#
IF(ENABLE_ICONV)
  FIND_PACKAGE(Iconv)
ELSE(ENABLE_ICONV)
  SET(ICONV_FOUND FALSE) # Override cached value
ENDIF(ENABLE_ICONV)

IF(ICONV_FOUND)
  INCLUDE_DIRECTORIES("${ICONV_INCLUDE_DIRS}")
  LIST(APPEND ADDITIONAL_LIBS ${ICONV_LIBRARIES})
  IF(HAVE_ICONV_CONST)
    SET(ICONV_CONST "const")
  ELSE()
    SET(ICONV_CONST " ")
  ENDIF(HAVE_ICONV_CONST)
ENDIF(ICONV_FOUND)

#
# Find ICU
#
IF(ENABLE_ICU)
  FIND_PACKAGE(ICU)
ELSE(ENABLE_ICU)
  SET(ICU_FOUND FALSE) # Override cached value
ENDIF(ENABLE_ICU)

IF(ICU_FOUND)
  INCLUDE_DIRECTORIES("${ICU_INCLUDE_DIRS}")
  LIST(APPEND ADDITIONAL_LIBS ${ICU_LIBRARIES})
ENDIF(ICU_FOUND)

#
# Find m
#
TRY_COMPILE(NEED_M "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/use_pow.c" LINK_LIBRARIES m)
IF(NEED_M)
    LIST(APPEND ADDITIONAL_LIBS m)
ENDIF(NEED_M)

IF(ENABLE_IPV6)
  INCLUDE(CheckStructHasMember)
  CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in6" sin6_addr "netinet/in.h"
                          HAVE_SOCKADDR_IN6_SIN6_ADDR)
  CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in6" sin6_scope_id "netinet/in.h"
                          HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  IF(NOT HAVE_SOCKADDR_IN6_SIN6_ADDR)
    MESSAGE(WARNING "struct sockaddr_in6 not available, disabling IPv6 support")
    # Force the feature off as this name is used as guard macro...
    SET(ENABLE_IPV6 OFF CACHE BOOL "Define if you want to enable IPv6 support" FORCE)
  ENDIF(NOT HAVE_SOCKADDR_IN6_SIN6_ADDR)
ENDIF(ENABLE_IPV6)

FIND_PACKAGE(Threads)

TRY_COMPILE(HAVE_GETHOSTBYNAME_CONST_ARG "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gethostbyname_const.c")
IF(HAVE_GETHOSTBYNAME_CONST_ARG)
    SET(GETHOSTBYNAME_ARG_CAST " ")
ELSE(HAVE_GETHOSTBYNAME_CONST_ARG)
    SET(GETHOSTBYNAME_ARG_CAST "(char *)")
ENDIF(HAVE_GETHOSTBYNAME_CONST_ARG)

TRY_COMPILE(VA_LIST_IS_NOT_ARRAY "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/va-list-is-array.c")
IF(VA_LIST_IS_NOT_ARRAY)
  SET(VA_LIST_IS_ARRAY 0)
ELSE(VA_LIST_IS_NOT_ARRAY)
  SET(VA_LIST_IS_ARRAY 1)
ENDIF(VA_LIST_IS_NOT_ARRAY)

TRY_COMPILE(HAVE_SEND_CONST_ARG2 "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/send_const_arg.c")
IF(HAVE_SEND_CONST_ARG2)
  SET(SEND_ARG2_CAST " ")
ELSE(HAVE_SEND_CONST_ARG2)
  SET(SEND_ARG2_CAST "(char *)")
ENDIF(HAVE_SEND_CONST_ARG2)

TRY_COMPILE(HAVE_GETSOCKOPT_SOCKLEN_T "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/getsockopt_socklen_t.c")
IF(HAVE_GETSOCKOPT_SOCKLEN_T)
  SET(XML_SOCKLEN_T "socklen_t")
ELSE(HAVE_GETSOCKOPT_SOCKLEN_T)
  TRY_COMPILE(HAVE_GETSOCKOPT_SIZE_T "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/getsockopt_size_t.c")
  IF(HAVE_GETSOCKOPT_SIZE_T)
    SET(XML_SOCKLEN_T "size_t")
  ELSE(HAVE_GETSOCKOPT_SIZE_T)
    TRY_COMPILE(HAVE_GETSOCKOPT_INT "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/getsockopt_int.c")
    IF(HAVE_GETSOCKOPT_INT)
      SET(XML_SOCKLEN_T "int")
    ELSE(HAVE_GETSOCKOPT_INT)
      MESSAGE(FATAL_ERROR "Could not determine getsockopt argument type")
    ENDIF(HAVE_GETSOCKOPT_INT)
  ENDIF(HAVE_GETSOCKOPT_SIZE_T)
ENDIF(HAVE_GETSOCKOPT_SOCKLEN_T)

# Hacky
SET(STDC_HEADERS 1)

# Hard dependencies on options
IF(ENABLE_SCHEMAS)
  SET(ENABLE_PATTERN ON)
  SET(ENABLE_REGEXPS ON)
ENDIF(ENABLE_SCHEMAS)

IF(ENABLE_SCHEMATRON)
  SET(ENABLE_PATTERN ON)
  SET(ENABLE_TREE ON)
  SET(ENABLE_XPATH ON)
ENDIF(ENABLE_SCHEMATRON)

IF(ENABLE_READER)
  SET(ENABLE_PUSH ON)
ENDIF(ENABLE_READER)

IF(ENABLE_XPTR)
  SET(ENABLE_XPATH ON)
ENDIF(ENABLE_XPTR)

IF(NOT HAVE_DLOPEN)
  SET(ENABLE_MODULES OFF)
ENDIF(NOT HAVE_DLOPEN)

IF(CMAKE_USE_PTHREADS_INIT)
  SET(HAVE_LIBPTHREAD 1)
ENDIF(CMAKE_USE_PTHREADS_INIT)

# Definitions
IF(Threads_FOUND)
  ADD_DEFINITIONS(-D_REENTRANT)
ENDIF(Threads_FOUND)

SET(MODULE_EXTENSION ${CMAKE_SHARED_LIBRARY_SUFFIX})

# Macros & Functions
FUNCTION(generate_config)
  MATH(EXPR LIBXML2_VERSION_MAJOR_STR "${LIBXML2_VERSION_MAJOR} * 100")
  MATH(EXPR LIBXML2_VERSION_MINOR_STR "${LIBXML2_VERSION_MINOR} * 10")
  MATH(EXPR LIBXML2_VERSION_MICRO_STR "${LIBXML2_VERSION_MICRO} * 1")
  SET(LT_OBJDIR "\".libs/\"")
  SET(PACKAGE "\"${PROJECT_NAME}\"")
  SET(PACKAGE_BUGREPORT "\"\"")
  SET(PACKAGE_NAME "\"${PROJECT_NAME}\"")
  SET(PACKAGE_STRING "\"${PROJECT_NAME} ${LIBXML2_VERSION}\"")
  SET(PACKAGE_TARNAME "\"${PROJECT_NAME}\"")
  SET(PACKAGE_URL "\"\"")
  SET(PACKAGE_VERSION "\"${LIBXML2_VERSION}\"")
  SET(VERSION "\"${LIBXML2_VERSION}\"")
  SET(LIBXML_VERSION_NUMBER "${LIBXML2_VERSION_MAJOR_STR}${LIBXML2_VERSION_MINOR_STR}${LIBXML2_VERSION_MICRO_STR}")
  bool_to_int(WITH_TRIO 0)
  bool_to_int(WITH_THREADS Threads_FOUND)
  bool_to_int(WITH_THREAD_ALLOC Threads_FOUND)
  bool_to_int(WITH_TREE ENABLE_TREE)
  bool_to_int(WITH_OUTPUT ENABLE_OUTPUT)
  bool_to_int(WITH_PUSH ENABLE_PUSH)
  bool_to_int(WITH_READER ENABLE_READER)
  bool_to_int(WITH_PATTERN ENABLE_PATTERN)
  bool_to_int(WITH_WRITER ENABLE_WRITTER)
  bool_to_int(WITH_SAX1 ENABLE_SAX1)
  bool_to_int(WITH_FTP ENABLE_FTP)
  bool_to_int(WITH_HTTP ENABLE_HTTP)
  bool_to_int(WITH_VALID ENABLE_VALID)
  bool_to_int(WITH_HTML ENABLE_HTML)
  bool_to_int(WITH_LEGACY ENABLE_LEGACY)
  bool_to_int(WITH_C14N ENABLE_C14N)
  bool_to_int(WITH_CATALOG ENABLE_CATALOG)
  bool_to_int(WITH_DOCB 0)
  bool_to_int(WITH_XPATH ENABLE_XPATH)
  bool_to_int(WITH_XPTR ENABLE_XPTR)
  bool_to_int(WITH_XINCLUDE ENABLE_XINCLUDE)
  bool_to_int(WITH_ICONV ICONV_FOUND)
  bool_to_int(WITH_ICU ICU_FOUND)
  bool_to_int(WITH_ISO8859X 0)
  bool_to_int(WITH_DEBUG ENABLE_DEBUG)
  bool_to_int(WITH_MEM_DEBUG ENABLE_MEM_DEBUG)
  bool_to_int(WITH_RUN_DEBUG ENABLE_RUN_DEBUG)
  bool_to_int(WITH_REGEXPS ENABLE_REGEXPS)
  bool_to_int(WITH_SCHEMAS ENABLE_SCHEMAS)
  bool_to_int(WITH_SCHEMATRON ENABLE_SCHEMATRON)
  bool_to_int(WITH_MODULES ENABLE_MODULE)
  bool_to_int(WITH_ZLIB ZLIB_FOUND)
  bool_to_int(WITH_LZMA LIBLZMA_FOUND)

  bool_to_int(SUPPORT_IP6 ENABLE_IPV6)

  CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")
  CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/include/libxml/xmlversion.h.in" "${CMAKE_CURRENT_BINARY_DIR}/include/libxml/xmlversion.h")
ENDFUNCTION(generate_config)

FUNCTION(generate_pkgconfig)
  SET(XML_CFLAGS "-I\${includedir}/libxml2")
  SET(THREAD_LIBS "${CMAKE_THREAD_LIBS_INIT}")
  SET(VERSION "${LIBXML2_VERSION}")
  SET(prefix "${CMAKE_INSTALL_PREFIX}")
  SET(exec_prefix "\${prefix}")
  SET(libdir "\${exec_prefix}/lib")
  SET(includedir "\${prefix}/include")

  # Rework LIBS
  SET(LIBS ${ADDITIONAL_LIBS})
  LIST(APPEND ADDITIONAL_LIBS ${CMAKE_DL_LIBS})
  SET(_LIBS ${LIBS})
  SET(LIBS "")
  FOREACH(V ${_LIBS})
    STRING(FIND "${V}" "$-l" out)
    IF("${out}" EQUAL 0)
      LIST(APPEND LIBS "${V}")
    ELSE()
      LIST(APPEND LIBS "-l${V}")
    ENDIF()
  ENDFOREACH()
  STRING(REPLACE ";" " " LIBS "${LIBS}")

  CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/libxml-2.0.pc.in" "${CMAKE_CURRENT_BINARY_DIR}/libxml-2.0.pc" @ONLY)
  CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/libxml-2.0-uninstalled.pc.in" "${CMAKE_CURRENT_BINARY_DIR}/libxml-2.0-uninstalled.pc" @ONLY)
ENDFUNCTION()

FUNCTION(generate_cmake_config)
  SET(LIBXML_MAJOR_VERSION ${LIBXML2_VERSION_MAJOR})
  SET(LIBXML_MINOR_VERSION ${LIBXML2_VERSION_MINOR})
  SET(LIBXML_MICRO_VERSION ${LIBXML2_VERSION_MICRO})
  SET(VERSION ${LIBXML2_VERSION})
  bool_to_int(WITH_THREADS Threads_FOUND)
  bool_to_int(WITH_LZMA LIBLZMA_FOUND)
  bool_to_int(WITH_ZLIB ZLIB_FOUND)
  bool_to_int(WITH_MODULES ENABLE_MODULE)

  # Rework LIBS
  SET(LIBS ${ADDITIONAL_LIBS})
  LIST(APPEND ADDITIONAL_LIBS ${CMAKE_DL_LIBS})
  SET(_LIBS ${LIBS})
  SET(LIBS "")
  FOREACH(V ${_LIBS})
    STRING(FIND "${V}" "$-l" out)
    IF("${out}" EQUAL 0)
      LIST(APPEND LIBS "${V}")
    ELSE()
      LIST(APPEND LIBS "-l${V}")
    ENDIF()
  ENDFOREACH()
  STRING(REPLACE ";" " " LIBS "${LIBS}")

  CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/libxml2-config.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/libxml2-config.cmake" @ONLY)
ENDFUNCTION(generate_cmake_config)

generate_config()
generate_pkgconfig()
generate_cmake_config()

INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/include")
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_BINARY_DIR}/include")
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_BINARY_DIR}")

SET(HEADER_FILES
    "include/libxml/c14n.h"
    "include/libxml/catalog.h"
    "include/libxml/chvalid.h"
    "include/libxml/debugXML.h"
    "include/libxml/dict.h"
    "include/libxml/DOCBparser.h"
    "include/libxml/encoding.h"
    "include/libxml/entities.h"
    "include/libxml/globals.h"
    "include/libxml/hash.h"
    "include/libxml/HTMLparser.h"
    "include/libxml/HTMLtree.h"
    "include/libxml/list.h"
    "include/libxml/nanoftp.h"
    "include/libxml/nanohttp.h"
    "include/libxml/parser.h"
    "include/libxml/parserInternals.h"
    "include/libxml/pattern.h"
    "include/libxml/relaxng.h"
    "include/libxml/SAX2.h"
    "include/libxml/SAX.h"
    "include/libxml/schemasInternals.h"
    "include/libxml/schematron.h"
    "include/libxml/threads.h"
    "include/libxml/tree.h"
    "include/libxml/uri.h"
    "include/libxml/valid.h"
    "include/libxml/xinclude.h"
    "include/libxml/xlink.h"
    "include/libxml/xmlautomata.h"
    "include/libxml/xmlerror.h"
    "include/libxml/xmlexports.h"
    "include/libxml/xmlIO.h"
    "include/libxml/xmlmemory.h"
    "include/libxml/xmlmodule.h"
    "include/libxml/xmlreader.h"
    "include/libxml/xmlregexp.h"
    "include/libxml/xmlsave.h"
    "include/libxml/xmlschemas.h"
    "include/libxml/xmlschemastypes.h"
    "include/libxml/xmlstring.h"
    "include/libxml/xmlunicode.h"
    "include/libxml/xmlwriter.h"
    "include/libxml/xpath.h"
    "include/libxml/xpathInternals.h"
    "include/libxml/xpointer.h"
)

SET(SOURCE_FILES
    "buf.c"
    "c14n.c"
    "catalog.c"
    "chvalid.c"
    "debugXML.c"
    "dict.c"
    "DOCBparser.c"
    "encoding.c"
    "entities.c"
    "error.c"
    "globals.c"
    "hash.c"
    "HTMLparser.c"
    "HTMLtree.c"
    "legacy.c"
    "list.c"
    "nanoftp.c"
    "nanohttp.c"
    "parser.c"
    "parserInternals.c"
    "pattern.c"
    "relaxng.c"
    "SAX2.c"
    "SAX.c"
    "schematron.c"
    "threads.c"
    "tree.c"
    "trionan.c"
    "uri.c"
    "valid.c"
    "xinclude.c"
    "xlink.c"
    "xmlIO.c"
    "xmlmemory.c"
    "xmlmodule.c"
    "xmlreader.c"
    "xmlregexp.c"
    "xmlsave.c"
    "xmlschemas.c"
    "xmlschemastypes.c"
    "xmlstring.c"
    "xmlunicode.c"
    "xmlwriter.c"
    "xpath.c"
    "xpointer.c"
    "xzlib.c"
)

IF(WITH_TRIO)
  SET(SOURCE_FILES "${SOURCE_FILES}" "triostr.c" "trio.c")
ENDIF(WITH_TRIO)

ADD_LIBRARY(xml2 "${HEADER_FILES}" "${SOURCE_FILES}")
SET_TARGET_PROPERTIES(xml2 PROPERTIES PREFIX "lib")
SET_TARGET_PROPERTIES(xml2 PROPERTIES IMPORT_PREFIX "lib")
SET_TARGET_PROPERTIES(xml2 PROPERTIES SOVERSION ${LIBXML2_VERSION_MAJOR})
SET_TARGET_PROPERTIES(xml2 PROPERTIES VERSION ${LIBXML2_VERSION})

ADD_EXECUTABLE(xmllint xmllint.c)
ADD_EXECUTABLE(xmlcatalog xmlcatalog.c)
ADD_EXECUTABLE(runxmlconf runxmlconf.c)
IF(WIN32)
  TARGET_LINK_LIBRARIES(xml2 wsock32 ws2_32)
ENDIF(WIN32)
TARGET_LINK_LIBRARIES(xml2 ${CMAKE_DL_LIBS} ${ADDITIONAL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
TARGET_LINK_LIBRARIES(xmllint xml2)
TARGET_LINK_LIBRARIES(xmlcatalog xml2)
TARGET_LINK_LIBRARIES(runxmlconf xml2)

#------------------------------------------------------------------------------

INSTALL(FILES ${HEADER_FILES} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/libxml2/libxml")
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/libxml/xmlversion.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/libxml2/libxml")
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/libxml-2.0.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/libxml-2.0-uninstalled.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/libxml2-config.cmake" DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/libxml2")

INSTALL(TARGETS xml2 xmllint xmlcatalog runxmlconf
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
