/*
 * Summary: dynamic module loading
 * Description: basic API for dynamic module loading, used by
 *              libexslt added in 2.6.17
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Joel W. Reed
 */

#ifndef __XML_MODULE_H__
#define __XML_MODULE_H__

#include <libxml/xmlversion.h>

#ifdef LIBXML_MODULES_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xmlModulePtr:
 *
 * A handle to a dynamically loaded module
 */
typedef struct _xmlModule xmlModule;
typedef xmlModule *xmlModulePtr;

#ifdef __cplusplus
}
#endif 

#ifdef __cplusplus
extern "C" {
#endif

XMLPUBFUN xmlModulePtr XMLCALL xmlModuleOpen	(const char *filename);

XMLPUBFUN void* XMLCALL xmlModuleSymbol	(xmlModulePtr module, const char* name);

XMLPUBFUN int XMLCALL xmlModuleClose	(xmlModulePtr module);

XMLPUBFUN int XMLCALL xmlModuleFree	(xmlModulePtr module);

#ifdef __cplusplus
}
#endif 

#endif /* LIBXML_MODULES_ENABLED */

#endif /*__XML_MODULE_H__ */
