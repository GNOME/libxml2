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
#include "entities.h"


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

typedef void (* xmlParserInputDeallocate)(xmlChar *);
typedef struct _xmlParserInput xmlParserInput;
typedef xmlParserInput *xmlParserInputPtr;
struct _xmlParserInput {
    /* Input buffer */
    xmlParserInputBufferPtr buf;      /* UTF-8 encoded buffer */

    const char *filename;             /* The file analyzed, if any */
    const char *directory;            /* the directory/base of teh file */
    const xmlChar *base;              /* Base of the array to parse */
    const xmlChar *cur;               /* Current char being parsed */
    int length;                       /* length if known */
    int line;                         /* Current line */
    int col;                          /* Current column */
    int consumed;                     /* How many xmlChars already consumed */
    xmlParserInputDeallocate free;    /* function to deallocate the base */
    /* added after 2.3.5 integration */
    const xmlChar *end;               /* end of the arry to parse */
    const xmlChar *encoding;          /* the encoding string for entity */
    const xmlChar *version;           /* the version string for entity */
    int standalone;                   /* Was that entity marked standalone */
};

/**
 * the parser can be asked to collect Node informations, i.e. at what
 * place in the file they were detected. 
 * NOTE: This is off by default and not very well tested.
 */
typedef struct _xmlParserNodeInfo xmlParserNodeInfo;
typedef xmlParserNodeInfo *xmlParserNodeInfoPtr;

struct _xmlParserNodeInfo {
  const struct _xmlNode* node;
  /* Position & line # that text that created the node begins & ends on */
  unsigned long begin_pos;
  unsigned long begin_line;
  unsigned long end_pos;
  unsigned long end_line;
};

typedef struct _xmlParserNodeInfoSeq xmlParserNodeInfoSeq;
typedef xmlParserNodeInfoSeq *xmlParserNodeInfoSeqPtr;
struct _xmlParserNodeInfoSeq {
  unsigned long maximum;
  unsigned long length;
  xmlParserNodeInfo* buffer;
};

/**
 * The parser is now working also as a state based parser
 * The recursive one use the stagte info for entities processing
 */
typedef enum {
    XML_PARSER_EOF = -1,	/* nothing is to be parsed */
    XML_PARSER_START = 0,	/* nothing has been parsed */
    XML_PARSER_MISC,		/* Misc* before int subset */
    XML_PARSER_PI,		/* Whithin a processing instruction */
    XML_PARSER_DTD,		/* within some DTD content */
    XML_PARSER_PROLOG,		/* Misc* after internal subset */
    XML_PARSER_COMMENT,		/* within a comment */
    XML_PARSER_START_TAG,	/* within a start tag */
    XML_PARSER_CONTENT,		/* within the content */
    XML_PARSER_CDATA_SECTION,	/* within a CDATA section */
    XML_PARSER_END_TAG,		/* within a closing tag */
    XML_PARSER_ENTITY_DECL,	/* within an entity declaration */
    XML_PARSER_ENTITY_VALUE,	/* within an entity value in a decl */
    XML_PARSER_ATTRIBUTE_VALUE,	/* within an attribute value */
    XML_PARSER_EPILOG, 		/* the Misc* after the last end tag */
    /* added after 2.3.5 integration */
    XML_PARSER_SYSTEM_LITERAL,	/* within a SYSTEM value */
    XML_PARSER_IGNORE		/* within an IGNORED section */
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
typedef struct _xmlParserCtxt xmlParserCtxt;
typedef xmlParserCtxt *xmlParserCtxtPtr;
struct _xmlParserCtxt {
    struct _xmlSAXHandler *sax;       /* The SAX handler */
    void            *userData;        /* the document being built */
    xmlDocPtr           myDoc;        /* the document being built */
    int            wellFormed;        /* is the document well formed */
    int       replaceEntities;        /* shall we replace entities ? */
    const xmlChar       *version;        /* the XML version string */
    const xmlChar      *encoding;        /* encoding, if any */
    int            standalone;        /* standalone document */
    int                  html;        /* are we parsing an HTML document */

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

    int errNo;                        /* error code */

    int     hasExternalSubset;        /* reference and external subset */
    int             hasPErefs;        /* the internal subset has PE refs */
    int              external;        /* are we parsing an external entity */

    int                 valid;        /* is the document valid */
    int              validate;        /* shall we try to validate ? */
    xmlValidCtxt        vctxt;        /* The validity context */

    xmlParserInputState instate;      /* current type of input */
    int                 token;        /* next char look-ahead */    

    char           *directory;        /* the data directory */

    /* Node name stack only used for HTML parsing */
    xmlChar           *name;          /* Current parsed Node */
    int                nameNr;        /* Depth of the parsing stack */
    int                nameMax;       /* Max depth of the parsing stack */
    xmlChar *         *nameTab;       /* array of nodes */

    long               nbChars;       /* number of xmlChar processed */
    long            checkIndex;       /* used by progressive parsing lookup */
    int             keepBlanks;       /* ugly but ... */

    /* Added after integration of 2.3.5 parser */
    int             disableSAX;       /* SAX callbacks are disabled */
    int               inSubset;       /* Parsing is in int 1/ext 2 subset */
    xmlChar *          intSubName;    /* name of subset */
    xmlChar *          extSubURI;     /* URI of external subset */
    xmlChar *          extSubSystem;  /* SYSTEM ID of external subset */

    /* xml:space values */
    int *              space;         /* Should the parser preserve spaces */
    int                spaceNr;       /* Depth of the parsing stack */
    int                spaceMax;      /* Max depth of the parsing stack */
    int *              spaceTab;      /* array of space infos */

    int                depth;         /* to prevent entity substitution loops */
    xmlParserInputPtr  entity;        /* used to check entities boundaries */
    int                charset;       /* encoding of the in-memory content
				         actually an xmlCharEncoding */
    int                nodelen;       /* Those two fields are there to */
    int                nodemem;       /* Speed up large node parsing */
    int                pedantic;      /* signal pedantic warnings or loose
					 behaviour */
    void              *_private;      /* For user data, libxml won't touch it */

    int                loadsubset;    /* should the external subset be loaded */
};

/**
 * a SAX Locator.
 */
typedef struct _xmlSAXLocator xmlSAXLocator;
typedef xmlSAXLocator *xmlSAXLocatorPtr;
struct _xmlSAXLocator {
    const xmlChar *(*getPublicId)(void *ctx);
    const xmlChar *(*getSystemId)(void *ctx);
    int (*getLineNumber)(void *ctx);
    int (*getColumnNumber)(void *ctx);
};

/**
 * a SAX handler is bunch of callbacks called by the parser when processing
 * of the input generate data or structure informations.
 */

typedef xmlParserInputPtr (*resolveEntitySAXFunc) (void *ctx,
			    const xmlChar *publicId, const xmlChar *systemId);
typedef void (*internalSubsetSAXFunc) (void *ctx, const xmlChar *name,
                            const xmlChar *ExternalID, const xmlChar *SystemID);
typedef xmlEntityPtr (*getEntitySAXFunc) (void *ctx,
                            const xmlChar *name);
typedef xmlEntityPtr (*getParameterEntitySAXFunc) (void *ctx,
                            const xmlChar *name);
typedef void (*entityDeclSAXFunc) (void *ctx,
                            const xmlChar *name, int type, const xmlChar *publicId,
			    const xmlChar *systemId, xmlChar *content);
typedef void (*notationDeclSAXFunc)(void *ctx, const xmlChar *name,
			    const xmlChar *publicId, const xmlChar *systemId);
typedef void (*attributeDeclSAXFunc)(void *ctx, const xmlChar *elem,
                            const xmlChar *name, int type, int def,
			    const xmlChar *defaultValue, xmlEnumerationPtr tree);
typedef void (*elementDeclSAXFunc)(void *ctx, const xmlChar *name,
			    int type, xmlElementContentPtr content);
typedef void (*unparsedEntityDeclSAXFunc)(void *ctx,
                            const xmlChar *name, const xmlChar *publicId,
			    const xmlChar *systemId, const xmlChar *notationName);
typedef void (*setDocumentLocatorSAXFunc) (void *ctx,
                            xmlSAXLocatorPtr loc);
typedef void (*startDocumentSAXFunc) (void *ctx);
typedef void (*endDocumentSAXFunc) (void *ctx);
typedef void (*startElementSAXFunc) (void *ctx, const xmlChar *name,
                            const xmlChar **atts);
typedef void (*endElementSAXFunc) (void *ctx, const xmlChar *name);
typedef void (*attributeSAXFunc) (void *ctx, const xmlChar *name,
                                  const xmlChar *value);
typedef void (*referenceSAXFunc) (void *ctx, const xmlChar *name);
typedef void (*charactersSAXFunc) (void *ctx, const xmlChar *ch,
		            int len);
typedef void (*ignorableWhitespaceSAXFunc) (void *ctx,
			    const xmlChar *ch, int len);
typedef void (*processingInstructionSAXFunc) (void *ctx,
                            const xmlChar *target, const xmlChar *data);
typedef void (*commentSAXFunc) (void *ctx, const xmlChar *value);
typedef void (*cdataBlockSAXFunc) (void *ctx, const xmlChar *value, int len);
typedef void (*warningSAXFunc) (void *ctx, const char *msg, ...);
typedef void (*errorSAXFunc) (void *ctx, const char *msg, ...);
typedef void (*fatalErrorSAXFunc) (void *ctx, const char *msg, ...);
typedef int (*isStandaloneSAXFunc) (void *ctx);
typedef int (*hasInternalSubsetSAXFunc) (void *ctx);
typedef int (*hasExternalSubsetSAXFunc) (void *ctx);

typedef struct _xmlSAXHandler xmlSAXHandler;
typedef xmlSAXHandler *xmlSAXHandlerPtr;
struct _xmlSAXHandler {
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
};

/**
 * External entity loaders types
 */
typedef xmlParserInputPtr (*xmlExternalEntityLoader)(const char *URL,
						     const char *ID,
						     xmlParserCtxtPtr context);

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



/**
 * Cleanup
 */
void		xmlCleanupParser	(void);

/**
 * Input functions
 */
int		xmlParserInputRead	(xmlParserInputPtr in,
					 int len);
int		xmlParserInputGrow	(xmlParserInputPtr in,
					 int len);

/**
 * xmlChar handling
 */
xmlChar *	xmlStrdup		(const xmlChar *cur);
xmlChar *	xmlStrndup		(const xmlChar *cur,
					 int len);
xmlChar *	xmlStrsub		(const xmlChar *str,
					 int start,
					 int len);
const xmlChar *	xmlStrchr		(const xmlChar *str,
					 xmlChar val);
const xmlChar *	xmlStrstr		(const xmlChar *str,
					 xmlChar *val);
int		xmlStrcmp		(const xmlChar *str1,
					 const xmlChar *str2);
int		xmlStrncmp		(const xmlChar *str1,
					 const xmlChar *str2,
					 int len);
int		xmlStrlen		(const xmlChar *str);
xmlChar *	xmlStrcat		(xmlChar *cur,
					 const xmlChar *add);
xmlChar *	xmlStrncat		(xmlChar *cur,
					 const xmlChar *add,
					 int len);

/**
 * Basic parsing Interfaces
 */
xmlDocPtr	xmlParseDoc		(xmlChar *cur);
xmlDocPtr	xmlParseMemory		(char *buffer,
					 int size);
xmlDocPtr	xmlParseFile		(const char *filename);
int		xmlSubstituteEntitiesDefault(int val);
int		xmlKeepBlanksDefault	(int val);

/**
 * Recovery mode 
 */
xmlDocPtr	xmlRecoverDoc		(xmlChar *cur);
xmlDocPtr	xmlRecoverMemory	(char *buffer,
					 int size);
xmlDocPtr	xmlRecoverFile		(const char *filename);

/**
 * Less common routines and SAX interfaces
 */
int		xmlParseDocument	(xmlParserCtxtPtr ctxt);
xmlDocPtr	xmlSAXParseDoc		(xmlSAXHandlerPtr sax,
					 xmlChar *cur,
					 int recovery);
int		xmlSAXUserParseFile	(xmlSAXHandlerPtr sax,
					 void *user_data,
					 const char *filename);
int		xmlSAXUserParseMemory	(xmlSAXHandlerPtr sax,
					 void *user_data,
					 char *buffer,
					 int size);
xmlDocPtr	xmlSAXParseMemory	(xmlSAXHandlerPtr sax,
					 char *buffer,
                                   	 int size,
					 int recovery);
xmlDocPtr	xmlSAXParseFile		(xmlSAXHandlerPtr sax,
					 const char *filename,
					 int recovery);
xmlDtdPtr	xmlParseDTD		(const xmlChar *ExternalID,
					 const xmlChar *SystemID);
xmlDtdPtr	xmlSAXParseDTD		(xmlSAXHandlerPtr sax,
					 const xmlChar *ExternalID,
					 const xmlChar *SystemID);
/**
 * SAX initialization routines
 */
void		xmlDefaultSAXHandlerInit(void);
void		htmlDefaultSAXHandlerInit(void);

/**
 * Parser contexts handling.
 */
void		xmlInitParserCtxt	(xmlParserCtxtPtr ctxt);
void		xmlClearParserCtxt	(xmlParserCtxtPtr ctxt);
void		xmlFreeParserCtxt	(xmlParserCtxtPtr ctxt);
void		xmlSetupParserForBuffer	(xmlParserCtxtPtr ctxt,
					 const xmlChar* buffer,
					 const char* filename);
xmlParserCtxtPtr xmlCreateDocParserCtxt	(xmlChar *cur);

/**
 * Interfaces for the Push mode
 */
xmlParserCtxtPtr xmlCreatePushParserCtxt(xmlSAXHandlerPtr sax,
					 void *user_data,
					 const char *chunk,
					 int size,
					 const char *filename);
int		 xmlParseChunk		(xmlParserCtxtPtr ctxt,
					 const char *chunk,
					 int size,
					 int terminate);

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
					 xmlParserCtxtPtr context);

/*
 * Interface for the compatibility mode of 1.8.11/2.3.5
 */
int		xmlUseNewParser		(int val);

#ifdef __cplusplus
}
#endif

#endif /* __XML_PARSER_H__ */

