/*
 * HTMLparser.h : inf=terface for an HTML 4.0 non-verifying parser
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __HTML_PARSER_H__
#define __HTML_PARSER_H__
#include <libxml/parser.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Most of the back-end structures from XML and HTML are shared
 */
typedef xmlParserCtxt htmlParserCtxt;
typedef xmlParserCtxtPtr htmlParserCtxtPtr;
typedef xmlParserNodeInfo htmlParserNodeInfo;
typedef xmlSAXHandler htmlSAXHandler;
typedef xmlSAXHandlerPtr htmlSAXHandlerPtr;
typedef xmlParserInput htmlParserInput;
typedef xmlParserInputPtr htmlParserInputPtr;
typedef xmlDocPtr htmlDocPtr;
typedef xmlNodePtr htmlNodePtr;

/*
 * Internal description of an HTML element
 */
typedef struct _htmlElemDesc htmlElemDesc;
typedef htmlElemDesc *htmlElemDescPtr;
struct _htmlElemDesc {
    const char *name;	/* The tag name */
    int startTag;       /* Whether the start tag can be implied */
    int endTag;         /* Whether the end tag can be implied */
    int empty;          /* Is this an empty element ? */
    int depr;           /* Is this a deprecated element ? */
    int dtd;            /* 1: only in Loose DTD, 2: only Frameset one */
    const char *desc;   /* the description */
};

/*
 * Internal description of an HTML entity
 */
typedef struct _htmlEntityDesc htmlEntityDesc;
typedef htmlEntityDesc *htmlEntityDescPtr;
struct _htmlEntityDesc {
    int value;		/* the UNICODE value for the character */
    const char *name;	/* The entity name */
    const char *desc;   /* the description */
};

/*
 * There is only few public functions.
 */
htmlElemDescPtr		htmlTagLookup	(const xmlChar *tag);
htmlEntityDescPtr	htmlEntityLookup(const xmlChar *name);

int			htmlIsAutoClosed(htmlDocPtr doc,
					 htmlNodePtr elem);
int			htmlAutoCloseTag(htmlDocPtr doc,
					 const xmlChar *name,
					 htmlNodePtr elem);
htmlEntityDescPtr	htmlParseEntityRef(htmlParserCtxtPtr ctxt,
					 xmlChar **str);
int			htmlParseCharRef(htmlParserCtxtPtr ctxt);
void			htmlParseElement(htmlParserCtxtPtr ctxt);

htmlDocPtr		htmlSAXParseDoc	(xmlChar *cur,
					 const char *encoding,
					 htmlSAXHandlerPtr sax,
					 void *userData);
htmlDocPtr		htmlParseDoc	(xmlChar *cur,
					 const char *encoding);
htmlDocPtr		htmlSAXParseFile(const char *filename,
					 const char *encoding,
					 htmlSAXHandlerPtr sax,
					 void *userData);
htmlDocPtr		htmlParseFile	(const char *filename,
					 const char *encoding);

/**
 * Interfaces for the Push mode
 */
void			htmlFreeParserCtxt	(htmlParserCtxtPtr ctxt);
htmlParserCtxtPtr	htmlCreatePushParserCtxt(htmlSAXHandlerPtr sax,
						 void *user_data,
						 const char *chunk,
						 int size,
						 const char *filename,
						 xmlCharEncoding enc);
int			htmlParseChunk		(htmlParserCtxtPtr ctxt,
						 const char *chunk,
						 int size,
						 int terminate);
#ifdef __cplusplus
}
#endif

#endif /* __HTML_PARSER_H__ */
