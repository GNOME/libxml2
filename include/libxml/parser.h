/*
 * parser.h : constants and stuff related to the XML parser.
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#ifndef __XML_PARSER_H__
#define __XML_PARSER_H__

#include "tree.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants.
 */
#define XML_DEFAULT_VERSION	"1.0"

typedef struct xmlParserInput {
    const char *filename;             /* The file analyzed, if any */
    const CHAR *base;                 /* Base of the array to parse */
    const CHAR *cur;                  /* Current char being parsed */
    int line;                         /* Current line */
    int col;                          /* Current column */
} xmlParserInput, *xmlParserInputPtr;

typedef struct xmlParserNodeInfo {
  const struct xmlNode* node;
  /* Position & line # that text that created the node begins & ends on */
  unsigned long begin_pos;
  unsigned long begin_line;
  unsigned long end_pos;
  unsigned long end_line;
} xmlParserNodeInfo;

typedef struct xmlParserNodeInfoSeq {
  unsigned long maximum;
  unsigned long length;
  xmlParserNodeInfo* buffer;
} xmlParserNodeInfoSeq, *xmlParserNodeInfoSeqPtr;

typedef struct xmlParserCtxt {
    struct xmlSAXHandler *sax;        /* The SAX handler */
    xmlDocPtr doc;                    /* the document being built */

    /* Input stream stack */
    xmlParserInputPtr  input;         /* Current input stream */
    int                inputNr;       /* Number of current input streams */
    int                inputMax;      /* Max number of input streams */
    xmlParserInputPtr *inputTab;      /* stack of inputs */

    /* Node analysis stack */
    xmlNodePtr         node;          /* Current parsed Node */
    int                nodeNr;        /* Depth of the parsing stack */
    int                nodeMax;       /* Max depth of the parsing stack */
    xmlNodePtr        *nodeTab;       /* array of nodes */

    int record_info;                  /* Whether node info should be kept */
    xmlParserNodeInfoSeq node_seq;    /* info about each node parsed */
} xmlParserCtxt, *xmlParserCtxtPtr;

/*
 * a SAX Locator.
 */

typedef struct xmlSAXLocator {
    const CHAR *(*getPublicId)(xmlParserCtxtPtr ctxt);
    const CHAR *(*getSystemId)(xmlParserCtxtPtr ctxt);
    int (*getLineNumber)(xmlParserCtxtPtr ctxt);
    int (*getColumnNumber)(xmlParserCtxtPtr ctxt);
} xmlSAXLocator, *xmlSAXLocatorPtr;

/*
 * a SAX Exception.
 */

typedef xmlParserInputPtr (*resolveEntitySAXFunc) (xmlParserCtxtPtr ctxt,
			    const CHAR *publicId, const CHAR *systemId);
typedef void (*notationDeclSAXFunc)(xmlParserCtxtPtr ctxt, const CHAR *name,
			    const CHAR *publicId, const CHAR *systemId);
typedef void (*unparsedEntityDeclSAXFunc)(xmlParserCtxtPtr ctxt,
                            const CHAR *name, const CHAR *publicId,
			    const CHAR *systemId, const CHAR *notationName);
typedef void (*setDocumentLocatorSAXFunc) (xmlParserCtxtPtr ctxt,
                            xmlSAXLocatorPtr loc);
typedef void (*startDocumentSAXFunc) (xmlParserCtxtPtr ctxt);
typedef void (*endDocumentSAXFunc) (xmlParserCtxtPtr ctxt);
typedef void (*startElementSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *name);
typedef void (*endElementSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *name);
typedef void (*charactersSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *ch,
		            int start, int len);
typedef void (*ignorableWhitespaceSAXFunc) (xmlParserCtxtPtr ctxt,
			    const CHAR *ch, int start, int len);
typedef void (*processingInstructionSAXFunc) (xmlParserCtxtPtr ctxt,
                            const CHAR *target, const CHAR *data);
typedef void (*warningSAXFunc) (xmlParserCtxtPtr ctxt, const char *msg, ...);
typedef void (*errorSAXFunc) (xmlParserCtxtPtr ctxt, const char *msg, ...);
typedef void (*fatalErrorSAXFunc) (xmlParserCtxtPtr ctxt, const char *msg, ...);

typedef struct xmlSAXHandler {
    resolveEntitySAXFunc resolveEntity;
    notationDeclSAXFunc notationDecl;
    unparsedEntityDeclSAXFunc unparsedEntityDecl;
    setDocumentLocatorSAXFunc setDocumentLocator;
    startDocumentSAXFunc startDocument;
    endDocumentSAXFunc endDocument;
    startElementSAXFunc startElement;
    endElementSAXFunc endElement;
    charactersSAXFunc characters;
    ignorableWhitespaceSAXFunc ignorableWhitespace;
    processingInstructionSAXFunc processingInstruction;
    warningSAXFunc warning;
    errorSAXFunc error;
    fatalErrorSAXFunc fatalError;
} xmlSAXHandler, *xmlSAXHandlerPtr;

/*
 * Global variables: just the SAX interface tables we are looking for full
 *      reentrancy of the code !
 */
xmlSAXLocator xmlDefaultSAXLocator;
xmlSAXHandler xmlDefaultSAXHandler;

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
extern int xmlStrlen(const CHAR *str);
extern CHAR *xmlStrcat(CHAR *cur, const CHAR *add);
extern CHAR *xmlStrncat(CHAR *cur, const CHAR *add, int len);

extern void xmlInitParserCtxt(xmlParserCtxtPtr ctx);
extern void xmlClearParserCtxt(xmlParserCtxtPtr ctx);
extern void xmlSetupParserForBuffer(xmlParserCtxtPtr ctx, const CHAR* buffer,
                                    const char* filename);

extern void xmlParserError(xmlParserCtxtPtr ctxt, const char *msg, ...);

extern const xmlParserNodeInfo* xmlParserFindNodeInfo(const xmlParserCtxt* c,
                                                      const xmlNode* node);
extern void xmlInitNodeInfoSeq(xmlParserNodeInfoSeqPtr seq);
extern void xmlClearNodeInfoSeq(xmlParserNodeInfoSeqPtr seq);
unsigned long xmlParserFindNodeInfoIndex(const xmlParserNodeInfoSeq* seq,
                                         const xmlNode* node);
extern void xmlParserAddNodeInfo(xmlParserCtxtPtr ctx,
                                 const xmlParserNodeInfo* info);

extern void xmlParserWarning(xmlParserCtxtPtr ctxt, const char *msg, ...);
extern void xmlParserError(xmlParserCtxtPtr ctxt, const char *msg, ...);
extern void xmlDefaultSAXHandlerInit(void);
#ifdef __cplusplus
}
#endif

#endif /* __XML_PARSER_H__ */

