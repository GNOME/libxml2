/*
 * xmlwin32version.h : compile-time version informations for the XML parser
 *                     when compiled on the Windows platform
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#ifndef __XML_VERSION_H__
#define __XML_VERSION_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * use those to be sure nothing nasty will happen if
 * your library and includes mismatch
 */
#define LIBXML_DOTTED_VERSION "2.3.12"
#define LIBXML_VERSION 20312
#define LIBXML_VERSION_STRING "20312"
#define LIBXML_TEST_VERSION xmlCheckVersion(20312);

/**
 * WITH_TRIO:
 *
 * Whether the trio support need to be configured in
 */
#if 0
#define WITH_TRIO
#else
#define WITHOUT_TRIO
#endif

/**
 * LIBXML_FTP_ENABLED:
 *
 * Whether the FTP support is configured in
 */
#if 1
#define LIBXML_FTP_ENABLED
#else
#define LIBXML_FTP_DISABLED
#endif

/**
 * LIBXML_HTTP_ENABLED:
 *
 * Whether the HTTP support is configured in
 */
#if 1
#define LIBXML_HTTP_ENABLED
#else
#define LIBXML_HTTP_DISABLED
#endif

/**
 * LIBXML_HTML_ENABLED:
 *
 * Whether the HTML support is configured in
 */
#if 1
#define LIBXML_HTML_ENABLED
#else
#define LIBXML_HTML_DISABLED
#endif

/**
 * LIBXML_CATALOG_ENABLED:
 *
 * Whether the Catalog support is configured in
 */
#if 1
#define LIBXML_CATALOG_ENABLED
#else
#define LIBXML_CATALOG_DISABLED
#endif

/**
 * LIBXML_DOCB_ENABLED:
 *
 * Whether the SGML Docbook support is configured in
 */
#if 0
#define LIBXML_DOCB_ENABLED
#else
#define LIBXML_DOCB_DISABLED
#endif

/**
 * LIBXML_XPATH_ENABLED:
 *
 * Whether XPath is configured in
 */
#if 1
#define LIBXML_XPATH_ENABLED
#else
#define LIBXML_XPATH_DISABLED
#endif

/**
 * LIBXML_XPTR_ENABLED:
 *
 * Whether XPointer is configured in
 */
#if 1
#define LIBXML_XPTR_ENABLED
#else
#define LIBXML_XPTR_DISABLED
#endif

/**
 * LIBXML_XINCLUDE_ENABLED:
 *
 * Whether XInclude is configured in
 */
#if 1
#define LIBXML_XINCLUDE_ENABLED
#else
#define LIBXML_XINCLUDE_DISABLED
#endif

/**
 * LIBXML_ICONV_ENABLED:
 *
 * Whether iconv support is available
 */
#if defined(__CYGWIN__)
#if 1
#define LIBXML_ICONV_ENABLED
#else
#define LIBXML_ICONV_DISABLED
#endif
#endif

/**
 * LIBXML_DEBUG_ENABLED:
 *
 * Whether Debugging module is configured in
 */
#if 1
#define LIBXML_DEBUG_ENABLED
#else
#define LIBXML_DEBUG_DISABLED
#endif

/**
 * DEBUG_MEMORY_LOCATION:
 *
 * Whether the memory debugging is configured in
 */
#if 0
#define DEBUG_MEMORY_LOCATION
#endif

#ifndef LIBXML_DLL_IMPORT
#if !defined(STATIC)
#define LIBXML_DLL_IMPORT __declspec(dllimport)
#else
#define LIBXML_DLL_IMPORT
#endif
#endif

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro used to signal to GCC unused function parameters
 * Disabled on Windows, this is checked on Linux.
 */
#define ATTRIBUTE_UNUSED

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif


