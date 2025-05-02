/**
 * @file
 * 
 * @brief implementation of XInclude
 * 
 * API to handle XInclude processing,
 * implements the
 * World Wide Web Consortium Last Call Working Draft 10 November 2003
 * http://www.w3.org/TR/2003/WD-xinclude-20031110
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
 */

#ifndef __XML_XINCLUDE_H__
#define __XML_XINCLUDE_H__

#include <libxml/xmlversion.h>
#include <libxml/xmlerror.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#ifdef LIBXML_XINCLUDE_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Macro defining the Xinclude namespace: http://www.w3.org/2003/XInclude
 */
#define XINCLUDE_NS (const xmlChar *) "http://www.w3.org/2003/XInclude"
/**
 * Macro defining the draft Xinclude namespace: http://www.w3.org/2001/XInclude
 */
#define XINCLUDE_OLD_NS (const xmlChar *) "http://www.w3.org/2001/XInclude"
/**
 * Macro defining "include"
 */
#define XINCLUDE_NODE (const xmlChar *) "include"
/**
 * Macro defining "fallback"
 */
#define XINCLUDE_FALLBACK (const xmlChar *) "fallback"
/**
 * Macro defining "href"
 */
#define XINCLUDE_HREF (const xmlChar *) "href"
/**
 * Macro defining "parse"
 */
#define XINCLUDE_PARSE (const xmlChar *) "parse"
/**
 * Macro defining "xml"
 */
#define XINCLUDE_PARSE_XML (const xmlChar *) "xml"
/**
 * Macro defining "text"
 */
#define XINCLUDE_PARSE_TEXT (const xmlChar *) "text"
/**
 * Macro defining "encoding"
 */
#define XINCLUDE_PARSE_ENCODING (const xmlChar *) "encoding"
/**
 * Macro defining "xpointer"
 */
#define XINCLUDE_PARSE_XPOINTER (const xmlChar *) "xpointer"

typedef struct _xmlXIncludeCtxt xmlXIncludeCtxt;
typedef xmlXIncludeCtxt *xmlXIncludeCtxtPtr;

/*
 * standalone processing
 */
XMLPUBFUN int
		xmlXIncludeProcess	(xmlDocPtr doc);
XMLPUBFUN int
		xmlXIncludeProcessFlags	(xmlDocPtr doc,
					 int flags);
XMLPUBFUN int
		xmlXIncludeProcessFlagsData(xmlDocPtr doc,
					 int flags,
					 void *data);
XMLPUBFUN int
                xmlXIncludeProcessTreeFlagsData(xmlNodePtr tree,
                                         int flags,
                                         void *data);
XMLPUBFUN int
		xmlXIncludeProcessTree	(xmlNodePtr tree);
XMLPUBFUN int
		xmlXIncludeProcessTreeFlags(xmlNodePtr tree,
					 int flags);
/*
 * contextual processing
 */
XMLPUBFUN xmlXIncludeCtxtPtr
		xmlXIncludeNewContext	(xmlDocPtr doc);
XMLPUBFUN int
		xmlXIncludeSetFlags	(xmlXIncludeCtxtPtr ctxt,
					 int flags);
XMLPUBFUN void
		xmlXIncludeSetErrorHandler(xmlXIncludeCtxtPtr ctxt,
					 xmlStructuredErrorFunc handler,
					 void *data);
XMLPUBFUN void
		xmlXIncludeSetResourceLoader(xmlXIncludeCtxtPtr ctxt,
					 xmlResourceLoader loader,
					 void *data);
XMLPUBFUN int
		xmlXIncludeGetLastError	(xmlXIncludeCtxtPtr ctxt);
XMLPUBFUN void
		xmlXIncludeFreeContext	(xmlXIncludeCtxtPtr ctxt);
XMLPUBFUN int
		xmlXIncludeProcessNode	(xmlXIncludeCtxtPtr ctxt,
					 xmlNodePtr tree);
#ifdef __cplusplus
}
#endif

#endif /* LIBXML_XINCLUDE_ENABLED */

#endif /* __XML_XINCLUDE_H__ */
