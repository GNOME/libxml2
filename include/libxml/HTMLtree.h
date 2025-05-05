/**
 * @file
 * 
 * @brief HTML documents
 * 
 * This modules implements functions to work with HTML documents,
 * most of them related to serialization.
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
 */

#ifndef __HTML_TREE_H__
#define __HTML_TREE_H__

#include <stdio.h>
#include <libxml/xmlversion.h>
#include <libxml/tree.h>
#include <libxml/HTMLparser.h>

#ifdef LIBXML_HTML_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

/* Deprecated */
#define HTML_TEXT_NODE		XML_TEXT_NODE
#define HTML_ENTITY_REF_NODE	XML_ENTITY_REF_NODE
#define HTML_COMMENT_NODE	XML_COMMENT_NODE
#define HTML_PRESERVE_NODE	XML_CDATA_SECTION_NODE
#define HTML_PI_NODE		XML_PI_NODE

XMLPUBFUN htmlDocPtr
		htmlNewDoc		(const xmlChar *URI,
					 const xmlChar *ExternalID);
XMLPUBFUN htmlDocPtr
		htmlNewDocNoDtD		(const xmlChar *URI,
					 const xmlChar *ExternalID);
XMLPUBFUN const xmlChar *
		htmlGetMetaEncoding	(htmlDocPtr doc);
XMLPUBFUN int
		htmlSetMetaEncoding	(htmlDocPtr doc,
					 const xmlChar *encoding);
#ifdef LIBXML_OUTPUT_ENABLED
XMLPUBFUN void
		htmlDocDumpMemory	(xmlDocPtr cur,
					 xmlChar **mem,
					 int *size);
XMLPUBFUN void
		htmlDocDumpMemoryFormat	(xmlDocPtr cur,
					 xmlChar **mem,
					 int *size,
					 int format);
XMLPUBFUN int
		htmlSaveFile		(const char *filename,
					 xmlDocPtr cur);
XMLPUBFUN int
		htmlSaveFileEnc		(const char *filename,
					 xmlDocPtr cur,
					 const char *encoding);
XMLPUBFUN int
		htmlSaveFileFormat	(const char *filename,
					 xmlDocPtr cur,
					 const char *encoding,
					 int format);
XMLPUBFUN int
		htmlNodeDump		(xmlBufferPtr buf,
					 xmlDocPtr doc,
					 xmlNodePtr cur);
XMLPUBFUN int
		htmlDocDump		(FILE *f,
					 xmlDocPtr cur);
XMLPUBFUN void
		htmlNodeDumpFile	(FILE *out,
					 xmlDocPtr doc,
					 xmlNodePtr cur);
XMLPUBFUN int
		htmlNodeDumpFileFormat	(FILE *out,
					 xmlDocPtr doc,
					 xmlNodePtr cur,
					 const char *encoding,
					 int format);

XMLPUBFUN void
		htmlNodeDumpOutput	(xmlOutputBufferPtr buf,
					 xmlDocPtr doc,
					 xmlNodePtr cur,
					 const char *encoding);
XMLPUBFUN void
		htmlNodeDumpFormatOutput(xmlOutputBufferPtr buf,
					 xmlDocPtr doc,
					 xmlNodePtr cur,
					 const char *encoding,
					 int format);
XMLPUBFUN void
		htmlDocContentDumpOutput(xmlOutputBufferPtr buf,
					 xmlDocPtr cur,
					 const char *encoding);
XMLPUBFUN void
		htmlDocContentDumpFormatOutput(xmlOutputBufferPtr buf,
					 xmlDocPtr cur,
					 const char *encoding,
					 int format);

#endif /* LIBXML_OUTPUT_ENABLED */

XML_DEPRECATED
XMLPUBFUN int
		htmlIsBooleanAttr	(const xmlChar *name);


#ifdef __cplusplus
}
#endif

#endif /* LIBXML_HTML_ENABLED */

#endif /* __HTML_TREE_H__ */

