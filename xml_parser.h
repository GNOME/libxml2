/*
 * parser.h : constants and stuff related to the XML parser.
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#ifndef __XML_PARSER_H__
#define __XML_PARSER_H__

#include "xml_tree.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants.
 */
#define XML_DEFAULT_VERSION	"1.0"


typedef struct xmlParserCtxt {
    const char *filename;             /* The file analyzed, if any */
    const CHAR *base;                 /* Base of the array to parse */
    const CHAR *cur;                  /* Current char being parsed */
    int line;                         /* Current line */
    int col;                          /* Current column */
    xmlDocPtr doc;                    /* the document being built */
    int depth;                        /* Depth of current element */
    int max_depth;                    /* Max depth allocated */
    xmlNodePtr *nodes;                /* The node hierarchy being built */
} xmlParserCtxt, *xmlParserCtxtPtr;

/*
 * Interfaces
 */
extern int xmlParseDocument(xmlParserCtxtPtr ctxt);
extern xmlDocPtr xmlParseDoc(CHAR *cur);
extern xmlDocPtr xmlParseMemory(char *buffer, int size);
extern xmlDocPtr xmlParseFile(const char *filename);
extern CHAR *xmlStrdup(const CHAR *input);
extern CHAR *xmlStrndup(const CHAR *input, int n);
extern CHAR *xmlStrchr(const CHAR *str, CHAR val);
extern int xmlStrcmp(const CHAR *str1, const CHAR *str2);
extern int xmlStrncmp(const CHAR *str1, const CHAR *str2, int len);

extern void xmlInitParserCtxt(xmlParserCtxtPtr ctx);
extern void xmlClearParserCtxt(xmlParserCtxtPtr ctx);
extern void xmlSetupParserForBuffer(xmlParserCtxtPtr ctx, const CHAR* buffer,
                                    const char* filename);

extern void xmlReportError(xmlParserCtxtPtr ctx, const CHAR* msg);

#ifdef __cplusplus
}
#endif

#endif /* __XML_PARSER_H__ */

