/*
 * Summary: implementation of XInclude
 * Description: API to handle XInclude processing,
 * implements the
 * World Wide Web Consortium Working Draft 26 October 2000
 * http://www.w3.org/TR/2000/WD-xinclude-20001026
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Daniel Veillard
 */

#ifndef __XML_XINCLUDE_H__
#define __XML_XINCLUDE_H__

#include <libxml/xmlversion.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * XINCLUDE_NS:
 *
 * Macro defining the Xinclude namespace: http://www.w3.org/2001/XInclude
 */
#define XINCLUDE_NS (const xmlChar *) "http://www.w3.org/2001/XInclude"
/**
 * XINCLUDE_NODE:
 *
 * Macro defining "include"
 */
#define XINCLUDE_NODE (const xmlChar *) "include"
/**
 * XINCLUDE_FALLBACK:
 *
 * Macro defining "fallback"
 */
#define XINCLUDE_FALLBACK (const xmlChar *) "fallback"
/**
 * XINCLUDE_HREF:
 *
 * Macro defining "href"
 */
#define XINCLUDE_HREF (const xmlChar *) "href"
/**
 * XINCLUDE_PARSE:
 *
 * Macro defining "parse"
 */
#define XINCLUDE_PARSE (const xmlChar *) "parse"
/**
 * XINCLUDE_PARSE_XML:
 *
 * Macro defining "xml"
 */
#define XINCLUDE_PARSE_XML (const xmlChar *) "xml"
/**
 * XINCLUDE_PARSE_TEXT:
 *
 * Macro defining "text"
 */
#define XINCLUDE_PARSE_TEXT (const xmlChar *) "text"
/**
 * XINCLUDE_PARSE_ENCODING:
 *
 * Macro defining "encoding"
 */
#define XINCLUDE_PARSE_ENCODING (const xmlChar *) "encoding"

typedef struct _xmlXIncludeCtxt xmlXIncludeCtxt;
typedef xmlXIncludeCtxt *xmlXIncludeCtxtPtr;

/*
 * standalone processing
 */
XMLPUBFUN int XMLCALL	
		xmlXIncludeProcess	(xmlDocPtr doc);
XMLPUBFUN int XMLCALL	
		xmlXIncludeProcessTree	(xmlNodePtr tree);
/*
 * contextual processing
 */
XMLPUBFUN xmlXIncludeCtxtPtr XMLCALL
		xmlXIncludeNewContext	(xmlDocPtr doc);
XMLPUBFUN void XMLCALL
		xmlXIncludeFreeContext	(xmlXIncludeCtxtPtr ctxt);
XMLPUBFUN int XMLCALL
		xmlXIncludeProcessNode	(xmlXIncludeCtxtPtr ctxt,
					 xmlNodePtr tree);
#ifdef __cplusplus
}
#endif
#endif /* __XML_XINCLUDE_H__ */
