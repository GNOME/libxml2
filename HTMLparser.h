/*
 * HTMLparser.h : inf=terface for an HTML 4.0 non-verifying parser
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __HTML_PARSER_H__
#define __HTML_PARSER_H__
#include "parser.h"

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
typedef struct htmlElemDesc {
    const CHAR *name;	/* The tag name */
    int startTag;       /* Whether the start tag can be implied */
    int endTag;         /* Whether the end tag can be implied */
    int empty;          /* Is this an empty element ? */
    int depr;           /* Is this a deprecated element ? */
    int dtd;            /* 1: only in Loose DTD, 2: only Frameset one */
    const char *desc;   /* the description */
} htmlElemDesc, *htmlElemDescPtr;

/*
 * Internal description of an HTML entity
 */
typedef struct htmlEntityDesc {
    int value;		/* the UNICODE value for the character */
    const CHAR *name;	/* The entity name */
    const char *desc;   /* the description */
} htmlEntityDesc, *htmlEntityDescPtr;

/*
 * There is only few public functions.
 */
htmlEntityDescPtr
htmlParseEntityRef(htmlParserCtxtPtr ctxt, CHAR **str);
int htmlParseCharRef(htmlParserCtxtPtr ctxt);
void htmlParseElement(htmlParserCtxtPtr ctxt);

htmlDocPtr htmlSAXParseDoc(CHAR *cur, const char *encoding,
                           htmlSAXHandlerPtr sax, void *userData);
htmlDocPtr htmlParseDoc(CHAR *cur, const char *encoding);
htmlDocPtr htmlSAXParseFile(const char *filename, const char *encoding,
                            htmlSAXHandlerPtr sax, void *userData);
htmlDocPtr htmlParseFile(const char *filename, const char *encoding);

#endif /* __HTML_PARSER_H__ */
