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

typedef xmlParserCtxt htmlParserCtxt;
typedef xmlParserCtxtPtr htmlParserCtxtPtr;
typedef xmlParserNodeInfo htmlParserNodeInfo;
typedef xmlSAXHandler htmlSAXHandler;
typedef xmlSAXHandlerPtr htmlSAXHandlerPtr;
typedef xmlParserInput htmlParserInput;
typedef xmlParserInputPtr htmlParserInputPtr;
typedef xmlDocPtr htmlDocPtr;
typedef xmlNodePtr htmlNodePtr;

xmlEntityPtr htmlParseEntityRef(htmlParserCtxtPtr ctxt);
int htmlParseCharRef(htmlParserCtxtPtr ctxt);
void htmlParseElement(htmlParserCtxtPtr ctxt);

htmlDocPtr htmlSAXParseDoc(CHAR *cur, const char *encoding,
                           htmlSAXHandlerPtr sax, void *userData);
htmlDocPtr htmlParseDoc(CHAR *cur, const char *encoding);
htmlDocPtr htmlSAXParseFile(const char *filename, const char *encoding,
                            htmlSAXHandlerPtr sax, void *userData);
htmlDocPtr htmlParseFile(const char *filename, const char *encoding);

#endif /* __HTML_PARSER_H__ */
