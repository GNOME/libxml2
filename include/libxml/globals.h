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
#include <libxml/HTMLparser.h>
#include <libxml/parser.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlsave.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _xmlGlobalState xmlGlobalState;
typedef xmlGlobalState *xmlGlobalStatePtr;

XMLPUBFUN int
xmlCheckThreadLocalStorage(void);

XML_DEPRECATED XMLPUBFUN void
xmlInitGlobals(void);
XML_DEPRECATED XMLPUBFUN void
xmlCleanupGlobals(void);
XML_DEPRECATED XMLPUBFUN void
xmlInitializeGlobalState(xmlGlobalStatePtr gs);
XML_DEPRECATED XMLPUBFUN
xmlGlobalStatePtr xmlGetGlobalState(void);

XMLPUBFUN void
xmlThrDefSetGenericErrorFunc(void *ctx, xmlGenericErrorFunc handler);
XMLPUBFUN void
xmlThrDefSetStructuredErrorFunc(void *ctx, xmlStructuredErrorFunc handler);
XMLPUBFUN int
xmlThrDefIndentTreeOutput(int v);
XMLPUBFUN const char *
xmlThrDefTreeIndentString(const char * v);
XMLPUBFUN int
xmlThrDefSaveNoEmptyTags(int v);
XML_DEPRECATED XMLPUBFUN xmlBufferAllocationScheme
xmlThrDefBufferAllocScheme(xmlBufferAllocationScheme v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefDefaultBufferSize(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefDoValidityCheckingDefaultValue(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefGetWarningsDefaultValue(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefKeepBlanksDefaultValue(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefLineNumbersDefaultValue(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefLoadExtDtdDefaultValue(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefParserDebugEntities(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefPedanticParserDefaultValue(int v);
XML_DEPRECATED XMLPUBFUN int
xmlThrDefSubstituteEntitiesDefaultValue(int v);
XMLPUBFUN xmlRegisterNodeFunc
xmlThrDefRegisterNodeDefault(xmlRegisterNodeFunc func);
XMLPUBFUN xmlDeregisterNodeFunc
xmlThrDefDeregisterNodeDefault(xmlDeregisterNodeFunc func);
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

#ifdef __cplusplus
}
#endif

#endif /* __XML_GLOBALS_H */
