/*
 * parser.h : constants and stuff related to the XML parser.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
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

typedef void (* xmlParserInputDeallocate)(CHAR *);
typedef struct xmlParserInput {
    const char *filename;             /* The file analyzed, if any */
    const CHAR *base;                 /* Base of the array to parse */
    const CHAR *cur;                  /* Current char being parsed */
    int line;                         /* Current line */
    int col;                          /* Current column */
    xmlParserInputDeallocate free;    /* function to deallocate the base */
} xmlParserInput;
typedef xmlParserInput *xmlParserInputPtr;

typedef struct _xmlParserNodeInfo {
  const struct xmlNode* node;
  /* Position & line # that text that created the node begins & ends on */
  unsigned long begin_pos;
  unsigned long begin_line;
  unsigned long end_pos;
  unsigned long end_line;
} _xmlParserNodeInfo;
typedef _xmlParserNodeInfo xmlParserNodeInfo;

typedef struct xmlParserNodeInfoSeq {
  unsigned long maximum;
  unsigned long length;
  xmlParserNodeInfo* buffer;
} _xmlParserNodeInfoSeq;
typedef _xmlParserNodeInfoSeq xmlParserNodeInfoSeq;
typedef xmlParserNodeInfoSeq *xmlParserNodeInfoSeqPtr;

typedef struct _xmlParserCtxt {
    struct xmlSAXHandler *sax;        /* The SAX handler */
    void            *userData;        /* the document being built */
    xmlDocPtr           myDoc;        /* the document being built */
    int            wellFormed;        /* is the document well formed */
    const CHAR     *version;	      /* the XML version string */
    const CHAR     *encoding;         /* encoding, if any */
    int             standalone;       /* standalone document */

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
} _xmlParserCtxt;
typedef _xmlParserCtxt xmlParserCtxt;
typedef xmlParserCtxt *xmlParserCtxtPtr;

/*
 * a SAX Locator.
 */

typedef struct xmlSAXLocator {
    const CHAR *(*getPublicId)(xmlParserCtxtPtr ctxt);
    const CHAR *(*getSystemId)(xmlParserCtxtPtr ctxt);
    int (*getLineNumber)(xmlParserCtxtPtr ctxt);
    int (*getColumnNumber)(xmlParserCtxtPtr ctxt);
} _xmlSAXLocator;
typedef _xmlSAXLocator xmlSAXLocator;
typedef xmlSAXLocator *xmlSAXLocatorPtr;

/*
 * a SAX Exception.
 */

#include "entities.h"

typedef xmlParserInputPtr (*resolveEntitySAXFunc) (xmlParserCtxtPtr ctxt,
			    const CHAR *publicId, const CHAR *systemId);
typedef void (*internalSubsetSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *name,
                            const CHAR *ExternalID, const CHAR *SystemID);
typedef xmlEntityPtr (*getEntitySAXFunc) (xmlParserCtxtPtr ctxt,
                            const CHAR *name);
typedef void (*entityDeclSAXFunc) (xmlParserCtxtPtr ctxt,
                            const CHAR *name, int type, const CHAR *publicId,
			    const CHAR *systemId, CHAR *content);
typedef void (*notationDeclSAXFunc)(xmlParserCtxtPtr ctxt, const CHAR *name,
			    const CHAR *publicId, const CHAR *systemId);
typedef void (*attributeDeclSAXFunc)(xmlParserCtxtPtr ctxt, const CHAR *elem,
                            const CHAR *name, int type, int def,
			    const CHAR *defaultValue, xmlEnumerationPtr tree);
typedef void (*elementDeclSAXFunc)(xmlParserCtxtPtr ctxt, const CHAR *name,
			    int type, xmlElementContentPtr content);
typedef void (*unparsedEntityDeclSAXFunc)(xmlParserCtxtPtr ctxt,
                            const CHAR *name, const CHAR *publicId,
			    const CHAR *systemId, const CHAR *notationName);
typedef void (*setDocumentLocatorSAXFunc) (xmlParserCtxtPtr ctxt,
                            xmlSAXLocatorPtr loc);
typedef void (*startDocumentSAXFunc) (xmlParserCtxtPtr ctxt);
typedef void (*endDocumentSAXFunc) (xmlParserCtxtPtr ctxt);
typedef void (*startElementSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *name,
                            const CHAR **atts);
typedef void (*endElementSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *name);
typedef void (*attributeSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *name,
                                  const CHAR *value);
typedef void (*referenceSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *name);
typedef void (*charactersSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *ch,
		            int len);
typedef void (*ignorableWhitespaceSAXFunc) (xmlParserCtxtPtr ctxt,
			    const CHAR *ch, int len);
typedef void (*processingInstructionSAXFunc) (xmlParserCtxtPtr ctxt,
                            const CHAR *target, const CHAR *data);
typedef void (*commentSAXFunc) (xmlParserCtxtPtr ctxt, const CHAR *value);
typedef void (*warningSAXFunc) (xmlParserCtxtPtr ctxt, const char *msg, ...);
typedef void (*errorSAXFunc) (xmlParserCtxtPtr ctxt, const char *msg, ...);
typedef void (*fatalErrorSAXFunc) (xmlParserCtxtPtr ctxt, const char *msg, ...);
typedef int (*isStandaloneSAXFunc) (xmlParserCtxtPtr ctxt);
typedef int (*hasInternalSubsetSAXFunc) (xmlParserCtxtPtr ctxt);
typedef int (*hasExternalSubsetSAXFunc) (xmlParserCtxtPtr ctxt);

typedef struct xmlSAXHandler {
    internalSubsetSAXFunc internalSubset;
    isStandaloneSAXFunc isStandalone;
    hasInternalSubsetSAXFunc hasInternalSubset;
    hasExternalSubsetSAXFunc hasExternalSubset;
    resolveEntitySAXFunc resolveEntity;
    getEntitySAXFunc getEntity;
    entityDeclSAXFunc entityDecl;
    notationDeclSAXFunc notationDecl;
    attributeDeclSAXFunc attributeDecl;
    elementDeclSAXFunc elementDecl;
    unparsedEntityDeclSAXFunc unparsedEntityDecl;
    setDocumentLocatorSAXFunc setDocumentLocator;
    startDocumentSAXFunc startDocument;
    endDocumentSAXFunc endDocument;
    startElementSAXFunc startElement;
    endElementSAXFunc endElement;
    referenceSAXFunc reference;
    charactersSAXFunc characters;
    ignorableWhitespaceSAXFunc ignorableWhitespace;
    processingInstructionSAXFunc processingInstruction;
    commentSAXFunc comment;
    warningSAXFunc warning;
    errorSAXFunc error;
    fatalErrorSAXFunc fatalError;
} xmlSAXHandler;
typedef xmlSAXHandler *xmlSAXHandlerPtr;

/*
 * Global variables: just the SAX interface tables we are looking for full
 *      reentrancy of the code !
 */
extern xmlSAXLocator xmlDefaultSAXLocator;
extern xmlSAXHandler xmlDefaultSAXHandler;

#include "entities.h"
#include "xml-error.h"

/*
 * CHAR handling
 */
CHAR *xmlStrdup(const CHAR *cur);
CHAR *xmlStrndup(const CHAR *cur, int len);
CHAR *xmlStrchr(const CHAR *str, CHAR val);
int xmlStrcmp(const CHAR *str1, const CHAR *str2);
int xmlStrncmp(const CHAR *str1, const CHAR *str2, int len);
int xmlStrlen(const CHAR *str);
CHAR *xmlStrcat(CHAR *cur, const CHAR *add);
CHAR *xmlStrncat(CHAR *cur, const CHAR *add, int len);

/*
 * Interfaces
 */
xmlDocPtr xmlParseDoc(CHAR *cur);
xmlDocPtr xmlParseMemory(char *buffer, int size);
xmlDocPtr xmlParseFile(const char *filename);

/*
 * Recovery mode 
 */
xmlDocPtr xmlRecoverDoc(CHAR *cur);
xmlDocPtr xmlRecoverMemory(char *buffer, int size);
xmlDocPtr xmlRecoverFile(const char *filename);

/*
 * Internal routines
 */
int xmlParseDocument(xmlParserCtxtPtr ctxt);
xmlDocPtr xmlSAXParseDoc(xmlSAXHandlerPtr sax, CHAR *cur, int recovery);
xmlDocPtr xmlSAXParseMemory(xmlSAXHandlerPtr sax, char *buffer,
                                   int size, int recovery);
xmlDocPtr xmlSAXParseFile(xmlSAXHandlerPtr sax, const char *filename,
                                 int recovery);
void xmlInitParserCtxt(xmlParserCtxtPtr ctxt);
void xmlClearParserCtxt(xmlParserCtxtPtr ctxt);
void xmlSetupParserForBuffer(xmlParserCtxtPtr ctxt, const CHAR* buffer,
                                    const char* filename);

const xmlParserNodeInfo* xmlParserFindNodeInfo(const xmlParserCtxt* ctxt,
                                               const xmlNode* node);
void xmlInitNodeInfoSeq(xmlParserNodeInfoSeqPtr seq);
void xmlClearNodeInfoSeq(xmlParserNodeInfoSeqPtr seq);
unsigned long xmlParserFindNodeInfoIndex(const xmlParserNodeInfoSeq* seq,
                                         const xmlNode* node);
void xmlParserAddNodeInfo(xmlParserCtxtPtr ctxt,
                          const xmlParserNodeInfo* info);

void xmlDefaultSAXHandlerInit(void);
#ifdef __cplusplus
}
#endif

#endif /* __XML_PARSER_H__ */

