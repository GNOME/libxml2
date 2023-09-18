/*
 * Summary: interface for all global variables of the library
 * Description: all the global variables and thread handling for
 *              those variables is handled by this module.
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Gary Pennington <Gary.Pennington@uk.sun.com>, Daniel Veillard
 */

#ifndef __XML_GLOBALS_H
#define __XML_GLOBALS_H

#include <libxml/xmlversion.h>
#include <libxml/parser.h>
#include <libxml/xmlerror.h>
#include <libxml/SAX2.h>
#include <libxml/xmlmemory.h>

#ifdef __cplusplus
extern "C" {
#endif

XML_DEPRECATED
XMLPUBFUN void xmlInitGlobals(void);
XML_DEPRECATED
XMLPUBFUN void xmlCleanupGlobals(void);

/**
 * xmlParserInputBufferCreateFilenameFunc:
 * @URI: the URI to read from
 * @enc: the requested source encoding
 *
 * Signature for the function doing the lookup for a suitable input method
 * corresponding to an URI.
 *
 * Returns the new xmlParserInputBufferPtr in case of success or NULL if no
 *         method was found.
 */
typedef xmlParserInputBufferPtr (*xmlParserInputBufferCreateFilenameFunc) (const char *URI,
									   xmlCharEncoding enc);


/**
 * xmlOutputBufferCreateFilenameFunc:
 * @URI: the URI to write to
 * @enc: the requested target encoding
 *
 * Signature for the function doing the lookup for a suitable output method
 * corresponding to an URI.
 *
 * Returns the new xmlOutputBufferPtr in case of success or NULL if no
 *         method was found.
 */
typedef xmlOutputBufferPtr (*xmlOutputBufferCreateFilenameFunc) (const char *URI,
								 xmlCharEncodingHandlerPtr encoder,
								 int compression);

XMLPUBFUN xmlParserInputBufferCreateFilenameFunc
xmlParserInputBufferCreateFilenameDefault (xmlParserInputBufferCreateFilenameFunc func);
XMLPUBFUN xmlOutputBufferCreateFilenameFunc
xmlOutputBufferCreateFilenameDefault (xmlOutputBufferCreateFilenameFunc func);

/**
 * xmlRegisterNodeFunc:
 * @node: the current node
 *
 * Signature for the registration callback of a created node
 */
typedef void (*xmlRegisterNodeFunc) (xmlNodePtr node);
/**
 * xmlDeregisterNodeFunc:
 * @node: the current node
 *
 * Signature for the deregistration callback of a discarded node
 */
typedef void (*xmlDeregisterNodeFunc) (xmlNodePtr node);

typedef struct _xmlGlobalState xmlGlobalState;
typedef xmlGlobalState *xmlGlobalStatePtr;

XMLPUBFUN int xmlCheckThreadLocalStorage(void);
XML_DEPRECATED
XMLPUBFUN void	xmlInitializeGlobalState(xmlGlobalStatePtr gs);
XML_DEPRECATED
XMLPUBFUN xmlGlobalStatePtr
			xmlGetGlobalState(void);

XMLPUBFUN void xmlThrDefSetGenericErrorFunc(void *ctx, xmlGenericErrorFunc handler);

XMLPUBFUN void xmlThrDefSetStructuredErrorFunc(void *ctx, xmlStructuredErrorFunc handler);

XML_DEPRECATED
XMLPUBFUN xmlBufferAllocationScheme
	xmlThrDefBufferAllocScheme(xmlBufferAllocationScheme v);
XML_DEPRECATED
XMLPUBFUN int xmlThrDefDefaultBufferSize(int v);
XMLPUBFUN int xmlThrDefDoValidityCheckingDefaultValue(int v);
XMLPUBFUN int xmlThrDefGetWarningsDefaultValue(int v);
XMLPUBFUN int xmlThrDefIndentTreeOutput(int v);
XMLPUBFUN const char * xmlThrDefTreeIndentString(const char * v);
XMLPUBFUN int xmlThrDefKeepBlanksDefaultValue(int v);
XML_DEPRECATED
XMLPUBFUN int xmlThrDefLineNumbersDefaultValue(int v);
XMLPUBFUN int xmlThrDefLoadExtDtdDefaultValue(int v);
XMLPUBFUN int xmlThrDefParserDebugEntities(int v);
XML_DEPRECATED
XMLPUBFUN int xmlThrDefPedanticParserDefaultValue(int v);
XMLPUBFUN int xmlThrDefSaveNoEmptyTags(int v);
XMLPUBFUN int xmlThrDefSubstituteEntitiesDefaultValue(int v);

XMLPUBFUN xmlRegisterNodeFunc xmlRegisterNodeDefault(xmlRegisterNodeFunc func);
XMLPUBFUN xmlRegisterNodeFunc xmlThrDefRegisterNodeDefault(xmlRegisterNodeFunc func);
XMLPUBFUN xmlDeregisterNodeFunc xmlDeregisterNodeDefault(xmlDeregisterNodeFunc func);
XMLPUBFUN xmlDeregisterNodeFunc xmlThrDefDeregisterNodeDefault(xmlDeregisterNodeFunc func);

XMLPUBFUN xmlOutputBufferCreateFilenameFunc
	xmlThrDefOutputBufferCreateFilenameDefault(xmlOutputBufferCreateFilenameFunc func);
XMLPUBFUN xmlParserInputBufferCreateFilenameFunc
	xmlThrDefParserInputBufferCreateFilenameDefault(
				xmlParserInputBufferCreateFilenameFunc func);

/** DOC_DISABLE */
#if defined(LIBXML_THREAD_ENABLED) && defined(_WIN32) && \
    defined(LIBXML_STATIC_FOR_DLL)
int
xmlDllMain(void *hinstDLL, unsigned long fdwReason,
           void *lpvReserved);
#endif
/** DOC_ENABLE */

/* Declare globals with macro magic */

#define XML_EMPTY

#define XML_GLOBALS_CORE \
  XML_OP(xmlLastError, xmlError, XML_EMPTY) \
  XML_OP(oldXMLWDcompatibility, int, XML_DEPRECATED) \
  XML_OP(xmlBufferAllocScheme, xmlBufferAllocationScheme, XML_DEPRECATED) \
  XML_OP(xmlDefaultBufferSize, int, XML_DEPRECATED) \
  XML_OP(xmlDefaultSAXHandler, xmlSAXHandlerV1, XML_DEPRECATED) \
  XML_OP(xmlDefaultSAXLocator, xmlSAXLocator, XML_DEPRECATED) \
  XML_OP(xmlDoValidityCheckingDefaultValue, int, XML_EMPTY) \
  XML_OP(xmlGenericError, xmlGenericErrorFunc, XML_EMPTY) \
  XML_OP(xmlStructuredError, xmlStructuredErrorFunc, XML_EMPTY) \
  XML_OP(xmlGenericErrorContext, void *, XML_EMPTY) \
  XML_OP(xmlStructuredErrorContext, void *, XML_EMPTY) \
  XML_OP(xmlGetWarningsDefaultValue, int, XML_EMPTY) \
  XML_OP(xmlIndentTreeOutput, int, XML_EMPTY) \
  XML_OP(xmlTreeIndentString, const char *, XML_EMPTY) \
  XML_OP(xmlKeepBlanksDefaultValue, int, XML_EMPTY) \
  XML_OP(xmlLineNumbersDefaultValue, int, XML_DEPRECATED) \
  XML_OP(xmlLoadExtDtdDefaultValue, int, XML_EMPTY) \
  XML_OP(xmlParserDebugEntities, int, XML_EMPTY) \
  XML_OP(xmlParserVersion, const char *, XML_EMPTY) \
  XML_OP(xmlPedanticParserDefaultValue, int, XML_DEPRECATED) \
  XML_OP(xmlSaveNoEmptyTags, int, XML_EMPTY) \
  XML_OP(xmlSubstituteEntitiesDefaultValue, int, XML_EMPTY) \
  XML_OP(xmlRegisterNodeDefaultValue, xmlRegisterNodeFunc, XML_DEPRECATED) \
  XML_OP(xmlDeregisterNodeDefaultValue, xmlDeregisterNodeFunc, \
           XML_DEPRECATED) \
  XML_OP(xmlParserInputBufferCreateFilenameValue, \
           xmlParserInputBufferCreateFilenameFunc, XML_DEPRECATED) \
  XML_OP(xmlOutputBufferCreateFilenameValue, \
           xmlOutputBufferCreateFilenameFunc, XML_DEPRECATED)

#ifdef LIBXML_HTML_ENABLED
  #define XML_GLOBALS_HTML \
    XML_OP(htmlDefaultSAXHandler, xmlSAXHandlerV1, XML_DEPRECATED)
#else
  #define XML_GLOBALS_HTML
#endif

/*
 * In general the memory allocation entry points are not kept
 * thread specific but this can be overridden by LIBXML_THREAD_ALLOC_ENABLED
 *    - xmlMalloc
 *    - xmlMallocAtomic
 *    - xmlRealloc
 *    - xmlMemStrdup
 *    - xmlFree
 */
#ifdef LIBXML_THREAD_ALLOC_ENABLED
  #define XML_GLOBALS_ALLOC \
    XML_OP(xmlMalloc, xmlMallocFunc, XML_EMPTY) \
    XML_OP(xmlMallocAtomic, xmlMallocFunc, XML_EMPTY) \
    XML_OP(xmlRealloc, xmlReallocFunc, XML_EMPTY) \
    XML_OP(xmlFree, xmlFreeFunc, XML_EMPTY) \
    XML_OP(xmlMemStrdup, xmlStrdupFunc, XML_EMPTY)
#else
  #define XML_GLOBALS_ALLOC

  XMLPUBVAR xmlMallocFunc xmlMalloc;
  XMLPUBVAR xmlMallocFunc xmlMallocAtomic;
  XMLPUBVAR xmlReallocFunc xmlRealloc;
  XMLPUBVAR xmlFreeFunc xmlFree;
  XMLPUBVAR xmlStrdupFunc xmlMemStrdup;
#endif

#define XML_GLOBALS \
  XML_GLOBALS_CORE \
  XML_GLOBALS_HTML \
  XML_GLOBALS_ALLOC

#ifdef LIBXML_THREAD_ENABLED
  #define XML_DECLARE_GLOBAL(name, type, attrs) \
    attrs XMLPUBFUN type *__##name(void);
#else
  #define XML_DECLARE_GLOBAL(name, type, attrs) \
    attrs XMLPUBVAR type name;
#endif

#define XML_OP XML_DECLARE_GLOBAL
XML_GLOBALS
#undef XML_OP

#if defined(LIBXML_THREAD_ENABLED) && !defined(XML_GLOBALS_NO_REDEFINITION)
  #define XML_GLOBAL_MACRO(name) (*__##name())

  #define xmlLastError XML_GLOBAL_MACRO(xmlLastError)
  #define oldXMLWDcompatibility XML_GLOBAL_MACRO(oldXMLWDcompatibility)
  #define xmlBufferAllocScheme XML_GLOBAL_MACRO(xmlBufferAllocScheme)
  #define xmlDefaultBufferSize XML_GLOBAL_MACRO(xmlDefaultBufferSize)
  #define xmlDefaultSAXHandler XML_GLOBAL_MACRO(xmlDefaultSAXHandler)
  #define xmlDefaultSAXLocator XML_GLOBAL_MACRO(xmlDefaultSAXLocator)
  #define xmlDoValidityCheckingDefaultValue \
    XML_GLOBAL_MACRO(xmlDoValidityCheckingDefaultValue)
  #define xmlGenericError XML_GLOBAL_MACRO(xmlGenericError)
  #define xmlStructuredError XML_GLOBAL_MACRO(xmlStructuredError)
  #define xmlGenericErrorContext XML_GLOBAL_MACRO(xmlGenericErrorContext)
  #define xmlStructuredErrorContext XML_GLOBAL_MACRO(xmlStructuredErrorContext)
  #define xmlGetWarningsDefaultValue \
    XML_GLOBAL_MACRO(xmlGetWarningsDefaultValue)
  #define xmlIndentTreeOutput XML_GLOBAL_MACRO(xmlIndentTreeOutput)
  #define xmlTreeIndentString XML_GLOBAL_MACRO(xmlTreeIndentString)
  #define xmlKeepBlanksDefaultValue XML_GLOBAL_MACRO(xmlKeepBlanksDefaultValue)
  #define xmlLineNumbersDefaultValue \
    XML_GLOBAL_MACRO(xmlLineNumbersDefaultValue)
  #define xmlLoadExtDtdDefaultValue XML_GLOBAL_MACRO(xmlLoadExtDtdDefaultValue)
  #define xmlParserDebugEntities XML_GLOBAL_MACRO(xmlParserDebugEntities)
  #define xmlParserVersion XML_GLOBAL_MACRO(xmlParserVersion)
  #define xmlPedanticParserDefaultValue \
    XML_GLOBAL_MACRO(xmlPedanticParserDefaultValue)
  #define xmlSaveNoEmptyTags XML_GLOBAL_MACRO(xmlSaveNoEmptyTags)
  #define xmlSubstituteEntitiesDefaultValue \
    XML_GLOBAL_MACRO(xmlSubstituteEntitiesDefaultValue)
  #define xmlRegisterNodeDefaultValue \
    XML_GLOBAL_MACRO(xmlRegisterNodeDefaultValue)
  #define xmlDeregisterNodeDefaultValue \
    XML_GLOBAL_MACRO(xmlDeregisterNodeDefaultValue)
  #define xmlParserInputBufferCreateFilenameValue \
    XML_GLOBAL_MACRO(xmlParserInputBufferCreateFilenameValue)
  #define xmlOutputBufferCreateFilenameValue \
    XML_GLOBAL_MACRO(xmlOutputBufferCreateFilenameValue)

  #ifdef LIBXML_HTML_ENABLED
    #define htmlDefaultSAXHandler XML_GLOBAL_MACRO(htmlDefaultSAXHandler)
  #endif

  #ifdef LIBXML_THREAD_ALLOC_ENABLED
    #define xmlMalloc XML_GLOBAL_MACRO(xmlMalloc)
    #define xmlMallocAtomic XML_GLOBAL_MACRO(xmlMallocAtomic)
    #define xmlRealloc XML_GLOBAL_MACRO(xmlRealloc)
    #define xmlFree XML_GLOBAL_MACRO(xmlFree)
    #define xmlMemStrdup XML_GLOBAL_MACRO(xmlMemStrdup)
  #endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* __XML_GLOBALS_H */
