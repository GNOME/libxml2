/*
 * parser.h : Interfaces, constants and types related to the XML parser.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_PARSER_H__
#define __XML_PARSER_H__

#include "tree.h"
#include "valid.h"
#include "xmlIO.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants.
 */
#define XML_DEFAULT_VERSION	"1.0"

/**
 * an xmlParserInput is an input flow for the XML processor.
 * Each entity parsed is associated an xmlParserInput (except the
 * few predefined ones). This is the case both for internal entities
 * - in which case the flow is already completely in memory - or
 * external entities - in which case we use the buf structure for
 * progressive reading and I18N conversions to the internal UTF-8 format.
 */

typedef void (* xmlParserInputDeallocate)(CHAR *);
typedef struct xmlParserInput {
    /* Input buffer */
    xmlParserInputBufferPtr buf;      /* UTF-8 encoded buffer */

    const char *filename;             /* The file analyzed, if any */
    const char *directory;            /* the directory/base of teh file */
    const CHAR *base;                 /* Base of the array to parse */
    const CHAR *cur;                  /* Current char being parsed */
    int line;                         /* Current line */
    int col;                          /* Current column */
    int consumed;                     /* How many CHARs were already consumed */
    xmlParserInputDeallocate free;    /* function to deallocate the base */
} xmlParserInput;
typedef xmlParserInput *xmlParserInputPtr;

typedef xmlParserInputPtr (*xmlExternalEntityLoader)(const char *URL,
						     const char *ID,
						     xmlParserInputPtr context);

/**
 * the parser can be asked to collect Node informations, i.e. at what
 * place in the file they were detected. 
 * NOTE: This is off by default and not very well tested.
 */
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

/**
 * The parser is not a state based parser, but we need to maintain
 * minimum state informations, especially for entities processing.
 */
typedef enum xmlParserInputState {
    XML_PARSER_EOF = 0,
    XML_PARSER_PROLOG,
    XML_PARSER_CONTENT,
    XML_PARSER_ENTITY_DECL,
    XML_PARSER_ENTITY_VALUE,
    XML_PARSER_ATTRIBUTE_VALUE,
    XML_PARSER_DTD,
    XML_PARSER_EPILOG,
    XML_PARSER_COMMENT,
    XML_PARSER_CDATA_SECTION 
} xmlParserInputState;

/**
 * The parser context.
 * NOTE This doesn't completely defines the parser state, the (current ?)
 *      design of the parser uses recursive function calls since this allow
 *      and easy mapping from the production rules of the specification
 *      to the actual code. The drawback is that the actual function call
 *      also reflect the parser state. However most of the parsing routines
 *      takes as the only argument the parser context pointer, so migrating
 *      to a state based parser for progressive parsing shouldn't be too hard.
 */
typedef struct _xmlParserCtxt {
    struct xmlSAXHandler *sax;        /* The SAX handler */
    void            *userData;        /* the document being built */
    xmlDocPtr           myDoc;        /* the document being built */
    int       replaceEntities;        /* shall we replace entities ? */
    const CHAR       *version;        /* the XML version string */
    const CHAR      *encoding;        /* encoding, if any */
    int            standalone;        /* standalone document */
    int     hasExternalSubset;        /* reference and external subset */
    int             hasPErefs;        /* the internal subset has PE refs */
    int                  html;        /* are we parsing an HTML document */
    int              external;        /* are we parsing an external entity */

    int            wellFormed;        /* is the document well formed */
    int                 valid;        /* is the document valid */
    int              validate;        /* shall we try to validate ? */
    xmlValidCtxt        vctxt;        /* The validity context */

    xmlParserInputState instate;      /* current type of input */
    int                 token;        /* next char look-ahead */    

    char           *directory;        /* the data directory */
    
    /* Input stream stack */
    xmlParserInputPtr  input;         /* Current input stream */
    int                inputNr;       /* Number of current input streams */
    int                inputMax;      /* Max number of input streams */
    xmlParserInputPtr *inputTab;      /* stack of inputs */

    /* Node analysis stack only used for DOM building */
    xmlNodePtr         node;          /* Current parsed Node */
    int                nodeNr;        /* Depth of the parsing stack */
    int                nodeMax;       /* Max depth of the parsing stack */
    xmlNodePtr        *nodeTab;       /* array of nodes */

    int record_info;                  /* Whether node info should be kept */
    xmlParserNodeInfoSeq node_seq;    /* info about each node parsed */
} _xmlParserCtxt;
typedef _xmlParserCtxt xmlParserCtxt;
typedef xmlParserCtxt *xmlParserCtxtPtr;

/**
 * a SAX Locator.
 */
typedef struct xmlSAXLocator {
    const CHAR *(*getPublicId)(void *ctx);
    const CHAR *(*getSystemId)(void *ctx);
    int (*getLineNumber)(void *ctx);
    int (*getColumnNumber)(void *ctx);
} _xmlSAXLocator;
typedef _xmlSAXLocator xmlSAXLocator;
typedef xmlSAXLocator *xmlSAXLocatorPtr;

/**
 * a SAX handler is bunch of callbacks called by the parser when processing
 * of the input generate data or structure informations.
 */

#include "entities.h"

typedef xmlParserInputPtr (*resolveEntitySAXFunc) (void *ctx,
			    const CHAR *publicId, const CHAR *systemId);
typedef void (*internalSubsetSAXFunc) (void *ctx, const CHAR *name,
                            const CHAR *ExternalID, const CHAR *SystemID);
typedef xmlEntityPtr (*getEntitySAXFunc) (void *ctx,
                            const CHAR *name);
typedef xmlEntityPtr (*getParameterEntitySAXFunc) (void *ctx,
                            const CHAR *name);
typedef void (*entityDeclSAXFunc) (void *ctx,
                            const CHAR *name, int type, const CHAR *publicId,
			    const CHAR *systemId, CHAR *content);
typedef void (*notationDeclSAXFunc)(void *ctx, const CHAR *name,
			    const CHAR *publicId, const CHAR *systemId);
typedef void (*attributeDeclSAXFunc)(void *ctx, const CHAR *elem,
                            const CHAR *name, int type, int def,
			    const CHAR *defaultValue, xmlEnumerationPtr tree);
typedef void (*elementDeclSAXFunc)(void *ctx, const CHAR *name,
			    int type, xmlElementContentPtr content);
typedef void (*unparsedEntityDeclSAXFunc)(void *ctx,
                            const CHAR *name, const CHAR *publicId,
			    const CHAR *systemId, const CHAR *notationName);
typedef void (*setDocumentLocatorSAXFunc) (void *ctx,
                            xmlSAXLocatorPtr loc);
typedef void (*startDocumentSAXFunc) (void *ctx);
typedef void (*endDocumentSAXFunc) (void *ctx);
typedef void (*startElementSAXFunc) (void *ctx, const CHAR *name,
                            const CHAR **atts);
typedef void (*endElementSAXFunc) (void *ctx, const CHAR *name);
typedef void (*attributeSAXFunc) (void *ctx, const CHAR *name,
                                  const CHAR *value);
typedef void (*referenceSAXFunc) (void *ctx, const CHAR *name);
typedef void (*charactersSAXFunc) (void *ctx, const CHAR *ch,
		            int len);
typedef void (*ignorableWhitespaceSAXFunc) (void *ctx,
			    const CHAR *ch, int len);
typedef void (*processingInstructionSAXFunc) (void *ctx,
                            const CHAR *target, const CHAR *data);
typedef void (*commentSAXFunc) (void *ctx, const CHAR *value);
typedef void (*cdataBlockSAXFunc) (void *ctx, const CHAR *value, int len);
typedef void (*warningSAXFunc) (void *ctx, const char *msg, ...);
typedef void (*errorSAXFunc) (void *ctx, const char *msg, ...);
typedef void (*fatalErrorSAXFunc) (void *ctx, const char *msg, ...);
typedef int (*isStandaloneSAXFunc) (void *ctx);
typedef int (*hasInternalSubsetSAXFunc) (void *ctx);
typedef int (*hasExternalSubsetSAXFunc) (void *ctx);

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
    getParameterEntitySAXFunc getParameterEntity;
    cdataBlockSAXFunc cdataBlock;
} xmlSAXHandler;
typedef xmlSAXHandler *xmlSAXHandlerPtr;

/**
 * Global variables: just the default SAX interface tables and XML
 * version infos.
 */
extern const char *xmlParserVersion;

extern xmlSAXLocator xmlDefaultSAXLocator;
extern xmlSAXHandler xmlDefaultSAXHandler;
extern xmlSAXHandler htmlDefaultSAXHandler;

/**
 * entity substitution default behaviour.
 */

extern int xmlSubstituteEntitiesDefaultValue;


#include "entities.h"
#include "xml-error.h"

/**
 * Input functions
 */

int		xmlParserInputRead	(xmlParserInputPtr in,
					 int len);
int		xmlParserInputGrow	(xmlParserInputPtr in,
					 int len);

/**
 * CHAR handling
 */
CHAR *		xmlStrdup		(const CHAR *cur);
CHAR *		xmlStrndup		(const CHAR *cur,
					 int len);
CHAR *		xmlStrsub		(const CHAR *str,
					 int start,
					 int len);
const CHAR *	xmlStrchr		(const CHAR *str,
					 CHAR val);
const CHAR *	xmlStrstr		(const CHAR *str,
					 CHAR *val);
int		xmlStrcmp		(const CHAR *str1,
					 const CHAR *str2);
int		xmlStrncmp		(const CHAR *str1,
					 const CHAR *str2,
					 int len);
int		xmlStrlen		(const CHAR *str);
CHAR *		xmlStrcat		(CHAR *cur,
					 const CHAR *add);
CHAR *		xmlStrncat		(CHAR *cur,
					 const CHAR *add,
					 int len);

/**
 * Basic parsing Interfaces
 */
xmlDocPtr	xmlParseDoc		(CHAR *cur);
xmlDocPtr	xmlParseMemory		(char *buffer,
					 int size);
xmlDocPtr	xmlParseFile		(const char *filename);
int		xmlSubstituteEntitiesDefault(int val);

/**
 * Recovery mode 
 */
xmlDocPtr	xmlRecoverDoc		(CHAR *cur);
xmlDocPtr	xmlRecoverMemory	(char *buffer,
					 int size);
xmlDocPtr	xmlRecoverFile		(const char *filename);

/**
 * Less common routines and SAX interfaces
 */
int		xmlParseDocument	(xmlParserCtxtPtr ctxt);
xmlDocPtr	xmlSAXParseDoc		(xmlSAXHandlerPtr sax,
					 CHAR *cur,
					 int recovery);
xmlDocPtr	xmlSAXParseMemory	(xmlSAXHandlerPtr sax,
					 char *buffer,
                                   	 int size,
					 int recovery);
xmlDocPtr	xmlSAXParseFile		(xmlSAXHandlerPtr sax,
					 const char *filename,
					 int recovery);
xmlDtdPtr	xmlParseDTD		(const CHAR *ExternalID,
					 const CHAR *SystemID);
xmlDtdPtr	xmlSAXParseDTD		(xmlSAXHandlerPtr sax,
					 const CHAR *ExternalID,
					 const CHAR *SystemID);
void		xmlInitParserCtxt	(xmlParserCtxtPtr ctxt);
void		xmlClearParserCtxt	(xmlParserCtxtPtr ctxt);
void		xmlSetupParserForBuffer	(xmlParserCtxtPtr ctxt,
					 const CHAR* buffer,
					 const char* filename);
void		xmlDefaultSAXHandlerInit(void);
void		htmlDefaultSAXHandlerInit(void);

/**
 * Node infos
 */
const xmlParserNodeInfo*
		xmlParserFindNodeInfo	(const xmlParserCtxt* ctxt,
                                               const xmlNode* node);
void		xmlInitNodeInfoSeq	(xmlParserNodeInfoSeqPtr seq);
void		xmlClearNodeInfoSeq	(xmlParserNodeInfoSeqPtr seq);
unsigned long xmlParserFindNodeInfoIndex(const xmlParserNodeInfoSeq* seq,
                                         const xmlNode* node);
void		xmlParserAddNodeInfo	(xmlParserCtxtPtr ctxt,
					 const xmlParserNodeInfo* info);

/*
 * External entities handling actually implemented in xmlIO
 */

void		xmlSetExternalEntityLoader(xmlExternalEntityLoader f);
xmlExternalEntityLoader
		xmlGetExternalEntityLoader(void);
xmlParserInputPtr
		xmlLoadExternalEntity	(const char *URL,
					 const char *ID,
					 xmlParserInputPtr context);
#ifdef __cplusplus
}
#endif

#endif /* __XML_PARSER_H__ */

