/*
 * xinclude.c : API to handle XInclude processing
 *
 * World Wide Web Consortium Working Draft 26 October 2000
 * http://www.w3.org/TR/2000/WD-xinclude-20001026
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#ifndef __XML_XINCLUDE_H__
#define __XML_XINCLUDE_H__

#include <libxml/xmlversion.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XINCLUDE_NS (const xmlChar *) "http://www.w3.org/2001/XInclude"
#define XINCLUDE_NODE (const xmlChar *) "include"
#define XINCLUDE_FALLBACK (const xmlChar *) "fallback"
#define XINCLUDE_HREF (const xmlChar *) "href"
#define XINCLUDE_PARSE (const xmlChar *) "parse"
#define XINCLUDE_PARSE_XML (const xmlChar *) "xml"
#define XINCLUDE_PARSE_TEXT (const xmlChar *) "text"
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
