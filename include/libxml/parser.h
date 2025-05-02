/**
 * @file
 * 
 * @brief the core parser module
 * 
 * Interfaces, constants and types related to the XML parser
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
 */

#ifndef __XML_PARSER_H__
#define __XML_PARSER_H__

#include <libxml/xmlversion.h>
#define XML_TREE_INTERNALS
#include <libxml/tree.h>
#undef XML_TREE_INTERNALS
#include <libxml/dict.h>
#include <libxml/hash.h>
#include <libxml/valid.h>
#include <libxml/entities.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlstring.h>
#include <libxml/xmlmemory.h>
#include <libxml/encoding.h>
#include <libxml/xmlIO.h>
/* for compatibility */
#include <libxml/SAX2.h>
#include <libxml/threads.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The default version of XML used: 1.0
 */
#define XML_DEFAULT_VERSION	"1.0"

/**
 * Status after parsing a document
 */
typedef enum {
    /** not well-formed */
    XML_STATUS_NOT_WELL_FORMED          = (1 << 0),
    /** not namespace-well-formed */
    XML_STATUS_NOT_NS_WELL_FORMED       = (1 << 1),
    /** DTD validation failed */
    XML_STATUS_DTD_VALIDATION_FAILED    = (1 << 2),
    /** catastrophic failure like OOM or I/O error */
    XML_STATUS_CATASTROPHIC_ERROR       = (1 << 3)
} xmlParserStatus;

/**
 * Resource type for resource loaders
 */
typedef enum {
    /** unknown */
    XML_RESOURCE_UNKNOWN = 0,
    /** main document */
    XML_RESOURCE_MAIN_DOCUMENT,
    /** external DTD */
    XML_RESOURCE_DTD,
    /** external general entity */
    XML_RESOURCE_GENERAL_ENTITY,
    /** external parameter entity */
    XML_RESOURCE_PARAMETER_ENTITY,
    /** XIncluded document */
    XML_RESOURCE_XINCLUDE,
    /** XIncluded text */
    XML_RESOURCE_XINCLUDE_TEXT
} xmlResourceType;

/**
 * Flags for parser input
 */
typedef enum {
    /** The input buffer won't be changed during parsing. */
    XML_INPUT_BUF_STATIC            = (1 << 1),
    /** The input buffer is zero-terminated. (Note that the zero
        byte shouldn't be included in buffer size.) */
    XML_INPUT_BUF_ZERO_TERMINATED   = (1 << 2),
    /** Uncompress gzipped file input */
    XML_INPUT_UNZIP                 = (1 << 3),
    /** Allow network access. Unused internally. */
    XML_INPUT_NETWORK               = (1 << 4)
} xmlParserInputFlags;

/* Deprecated */
typedef void (* xmlParserInputDeallocate)(xmlChar *str);

/**
 * An xmlParserInput is an input flow for the XML processor.
 * Each entity parsed is associated an xmlParserInput (except the
 * few predefined ones). This is the case both for internal entities
 * - in which case the flow is already completely in memory - or
 * external entities - in which case we use the buf structure for
 * progressive reading and I18N conversions to the internal UTF-8 format.
 */
struct _xmlParserInput {
    /* Input buffer */
    xmlParserInputBufferPtr buf;
    /* The file analyzed, if any */
    const char *filename;
    /* unused */
    const char *directory XML_DEPRECATED_MEMBER;
    /* Base of the array to parse */
    const xmlChar *base;
    /* Current char being parsed */
    const xmlChar *cur;
    /* end of the array to parse */
    const xmlChar *end;
    /* unused */
    int length XML_DEPRECATED_MEMBER;
    /* Current line */
    int line;
    /* Current column */
    int col;
    /* How many xmlChars already consumed */
    unsigned long consumed;
    /* function to deallocate the base */
    xmlParserInputDeallocate free XML_DEPRECATED_MEMBER;
    /* unused */
    const xmlChar *encoding XML_DEPRECATED_MEMBER;
    /* the version string for entity */
    const xmlChar *version XML_DEPRECATED_MEMBER;
    /* Flags */
    int flags XML_DEPRECATED_MEMBER;
    /* an unique identifier for the entity */
    int id XML_DEPRECATED_MEMBER;
    /* unused */
    unsigned long parentConsumed XML_DEPRECATED_MEMBER;
    /* entity, if any */
    xmlEntityPtr entity XML_DEPRECATED_MEMBER;
};

/*
 * The parser can be asked to collect Node information, i.e. at what
 * place in the file they were detected.
 *
 * NOTE: This feature is off by default and deprecated.
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

/*
 * Internal type
 */
typedef enum {
    XML_PARSER_EOF = -1,	/* nothing is to be parsed */
    XML_PARSER_START = 0,	/* nothing has been parsed */
    XML_PARSER_MISC,		/* Misc* before int subset */
    XML_PARSER_PI,		/* Within a processing instruction */
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
    XML_PARSER_SYSTEM_LITERAL,	/* within a SYSTEM value */
    XML_PARSER_EPILOG,		/* the Misc* after the last end tag */
    XML_PARSER_IGNORE,		/* within an IGNORED section */
    XML_PARSER_PUBLIC_LITERAL,	/* within a PUBLIC value */
    XML_PARSER_XML_DECL         /* before XML decl (but after BOM) */
} xmlParserInputState;

/** @cond IGNORE */
/*
 * Internal bits in the 'loadsubset' context member
 */
#define XML_DETECT_IDS		2
#define XML_COMPLETE_ATTRS	4
#define XML_SKIP_IDS		8
/** @endcond */

/*
 * Internal type. Only XML_PARSE_READER is used.
 */
typedef enum {
    XML_PARSE_UNKNOWN = 0,
    XML_PARSE_DOM = 1,
    XML_PARSE_SAX = 2,
    XML_PARSE_PUSH_DOM = 3,
    XML_PARSE_PUSH_SAX = 4,
    XML_PARSE_READER = 5
} xmlParserMode;

typedef struct _xmlStartTag xmlStartTag;
typedef struct _xmlParserNsData xmlParserNsData;
typedef struct _xmlAttrHashBucket xmlAttrHashBucket;

/**
 * @param ctxt  parser context
 * @param url  URL to load
 * @param publicId  publid ID from DTD (optional)
 * @param type  resource type
 * @param flags  flags
 * @param out  result pointer
 *
 * Callback for custom resource loaders.
 *
 * `flags` can contain XML_INPUT_UNZIP and XML_INPUT_NETWORK.
 *
 * On success, `out` should be set to a new parser input object and
 * XML_ERR_OK should be returned.
 *
 * @returns an xmlParserErrors code.
 */
typedef xmlParserErrors
(*xmlResourceLoader)(void *ctxt, const char *url, const char *publicId,
                     xmlResourceType type, xmlParserInputFlags flags,
                     xmlParserInputPtr *out);

/*
 * The parser context.
 */
struct _xmlParserCtxt {
    /* The SAX handler */
    struct _xmlSAXHandler *sax;
    /* For SAX interface only, used by DOM build */
    void *userData;
    /* the document being built */
    xmlDocPtr myDoc;
    /* is the document well formed */
    int wellFormed;
    /* shall we replace entities ? */
    int replaceEntities XML_DEPRECATED_MEMBER;
    /* the XML version string */
    const xmlChar *version;
    /* the declared encoding, if any */
    const xmlChar *encoding;
    /* standalone document */
    int standalone;

    /* an HTML(1) document
     * 3 is HTML after <head>
     * 10 is HTML after <body>
     */
    int html;

    /* Input stream stack */

    /* Current input stream */
    xmlParserInputPtr input;
    /* Number of current input streams */
    int inputNr;
    /* Max number of input streams */
    int inputMax XML_DEPRECATED_MEMBER;
    /* stack of inputs */
    xmlParserInputPtr *inputTab;

    /* Node analysis stack only used for DOM building */

    /* Current parsed Node */
    xmlNodePtr node XML_DEPRECATED_MEMBER;
    /* Depth of the parsing stack */
    int nodeNr XML_DEPRECATED_MEMBER;
    /* Max depth of the parsing stack */
    int nodeMax XML_DEPRECATED_MEMBER;
    /* array of nodes */
    xmlNodePtr *nodeTab XML_DEPRECATED_MEMBER;

    /* Whether node info should be kept */
    int record_info;
    /* info about each node parsed */
    xmlParserNodeInfoSeq node_seq XML_DEPRECATED_MEMBER;

    /* error code */
    int errNo;

    /* reference and external subset */
    int hasExternalSubset XML_DEPRECATED_MEMBER;
    /* the internal subset has PE refs */
    int hasPErefs XML_DEPRECATED_MEMBER;
    /* unused */
    int external XML_DEPRECATED_MEMBER;

    /* is the document valid */
    int valid;
    /* shall we try to validate ? */
    int validate XML_DEPRECATED_MEMBER;
    /* The validity context */
    xmlValidCtxt vctxt;

    /* push parser state */
    xmlParserInputState instate XML_DEPRECATED_MEMBER;
    /* unused */
    int token XML_DEPRECATED_MEMBER;

    /* unused internally, still used downstream */
    char *directory;

    /* Node name stack */

    /* Current parsed Node */
    const xmlChar *name XML_DEPRECATED_MEMBER;
    /* Depth of the parsing stack */
    int nameNr XML_DEPRECATED_MEMBER;
    /* Max depth of the parsing stack */
    int nameMax XML_DEPRECATED_MEMBER;
    /* array of nodes */
    const xmlChar **nameTab XML_DEPRECATED_MEMBER;

    /* unused */
    long nbChars XML_DEPRECATED_MEMBER;
    /* used by progressive parsing lookup */
    long checkIndex XML_DEPRECATED_MEMBER;
    /* ugly but ... */
    int keepBlanks XML_DEPRECATED_MEMBER;
    /* SAX callbacks are disabled */
    int disableSAX XML_DEPRECATED_MEMBER;
    /* Parsing is in int 1/ext 2 subset */
    int inSubset;
    /* name of subset */
    const xmlChar *intSubName;
    /* URI of external subset */
    xmlChar *extSubURI;
    /* SYSTEM ID of external subset */
    xmlChar *extSubSystem;

    /* xml:space values */

    /* Should the parser preserve spaces */
    int *space XML_DEPRECATED_MEMBER;
    /* Depth of the parsing stack */
    int spaceNr XML_DEPRECATED_MEMBER;
    /* Max depth of the parsing stack */
    int spaceMax XML_DEPRECATED_MEMBER;
    /* array of space infos */
    int *spaceTab XML_DEPRECATED_MEMBER;

    /* to prevent entity substitution loops */
    int depth XML_DEPRECATED_MEMBER;
    /* unused */
    xmlParserInputPtr entity XML_DEPRECATED_MEMBER;
    /* unused */
    int charset XML_DEPRECATED_MEMBER;
    /* Those two fields are there to */
    int nodelen XML_DEPRECATED_MEMBER;
    /* Speed up large node parsing */
    int nodemem XML_DEPRECATED_MEMBER;
    /* signal pedantic warnings */
    int pedantic XML_DEPRECATED_MEMBER;
    /* For user data, libxml won't touch it */
    void *_private;

    /* should the external subset be loaded */
    int loadsubset;
    /* set line number in element content */
    int linenumbers XML_DEPRECATED_MEMBER;
    /* document's own catalog */
    void *catalogs XML_DEPRECATED_MEMBER;
    /* run in recovery mode */
    int recovery XML_DEPRECATED_MEMBER;
    /* unused */
    int progressive XML_DEPRECATED_MEMBER;
    /* dictionary for the parser */
    xmlDictPtr dict;
    /* array for the attributes callbacks */
    const xmlChar **atts XML_DEPRECATED_MEMBER;
    /* the size of the array */
    int maxatts XML_DEPRECATED_MEMBER;
    /* unused */
    int docdict XML_DEPRECATED_MEMBER;

    /*
     * pre-interned strings
     */
    const xmlChar *str_xml XML_DEPRECATED_MEMBER;
    const xmlChar *str_xmlns XML_DEPRECATED_MEMBER;
    const xmlChar *str_xml_ns XML_DEPRECATED_MEMBER;

    /*
     * Everything below is used only by the new SAX mode
     */

    /* operating in the new SAX mode */
    int sax2 XML_DEPRECATED_MEMBER;
    /* the number of inherited namespaces */
    int nsNr XML_DEPRECATED_MEMBER;
    /* the size of the arrays */
    int nsMax XML_DEPRECATED_MEMBER;
    /* the array of prefix/namespace name */
    const xmlChar **nsTab XML_DEPRECATED_MEMBER;
    /* which attribute were allocated */
    unsigned *attallocs XML_DEPRECATED_MEMBER;
    /* array of data for push */
    xmlStartTag *pushTab XML_DEPRECATED_MEMBER;
    /* defaulted attributes if any */
    xmlHashTablePtr attsDefault XML_DEPRECATED_MEMBER;
    /* non-CDATA attributes if any */
    xmlHashTablePtr attsSpecial XML_DEPRECATED_MEMBER;
    /* is the document XML Namespace okay */
    int nsWellFormed;
    /* Extra options */
    int options;

    /*
     * Those fields are needed only for streaming parsing so far
     */

    /* Use dictionary names for the tree */
    int dictNames XML_DEPRECATED_MEMBER;
    /* number of freed element nodes */
    int freeElemsNr XML_DEPRECATED_MEMBER;
    /* List of freed element nodes */
    xmlNodePtr freeElems XML_DEPRECATED_MEMBER;
    /* number of freed attributes nodes */
    int freeAttrsNr XML_DEPRECATED_MEMBER;
    /* List of freed attributes nodes */
    xmlAttrPtr freeAttrs XML_DEPRECATED_MEMBER;

    /*
     * the complete error information for the last error.
     */
    xmlError lastError XML_DEPRECATED_MEMBER;
    /* the parser mode */
    xmlParserMode parseMode XML_DEPRECATED_MEMBER;
    /* unused */
    unsigned long nbentities XML_DEPRECATED_MEMBER;
    /* size of external entities */
    unsigned long sizeentities XML_DEPRECATED_MEMBER;

    /* for use by HTML non-recursive parser */
    /* Current NodeInfo */
    xmlParserNodeInfo *nodeInfo XML_DEPRECATED_MEMBER;
    /* Depth of the parsing stack */
    int nodeInfoNr XML_DEPRECATED_MEMBER;
    /* Max depth of the parsing stack */
    int nodeInfoMax XML_DEPRECATED_MEMBER;
    /* array of nodeInfos */
    xmlParserNodeInfo *nodeInfoTab XML_DEPRECATED_MEMBER;

    /* we need to label inputs */
    int input_id XML_DEPRECATED_MEMBER;
    /* volume of entity copy */
    unsigned long sizeentcopy XML_DEPRECATED_MEMBER;

    /* quote state for push parser */
    int endCheckState XML_DEPRECATED_MEMBER;
    /* number of errors */
    unsigned short nbErrors XML_DEPRECATED_MEMBER;
    /* number of warnings */
    unsigned short nbWarnings XML_DEPRECATED_MEMBER;
    /* maximum amplification factor */
    unsigned maxAmpl XML_DEPRECATED_MEMBER;

    /* namespace database */
    xmlParserNsData *nsdb XML_DEPRECATED_MEMBER;
    /* allocated size */
    unsigned attrHashMax XML_DEPRECATED_MEMBER;
    /* atttribute hash table */
    xmlAttrHashBucket *attrHash XML_DEPRECATED_MEMBER;

    xmlStructuredErrorFunc errorHandler XML_DEPRECATED_MEMBER;
    void *errorCtxt XML_DEPRECATED_MEMBER;

    xmlResourceLoader resourceLoader XML_DEPRECATED_MEMBER;
    void *resourceCtxt XML_DEPRECATED_MEMBER;

    xmlCharEncConvImpl convImpl XML_DEPRECATED_MEMBER;
    void *convCtxt XML_DEPRECATED_MEMBER;
};

/*
 * A SAX Locator.
 */
struct _xmlSAXLocator {
    const xmlChar *(*getPublicId)(void *ctx);
    const xmlChar *(*getSystemId)(void *ctx);
    int (*getLineNumber)(void *ctx);
    int (*getColumnNumber)(void *ctx);
};

/**
 * @param ctx  the user data (XML parser context)
 * @param publicId  The public ID of the entity
 * @param systemId  The system ID of the entity
 *
 * Callback:
 * The entity loader, to control the loading of external entities,
 * the application can either:
 *    - override this resolveEntity() callback in the SAX block
 *    - or better use the xmlSetExternalEntityLoader() function to
 *      set up it's own entity resolution routine
 *
 * @returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
 */
typedef xmlParserInputPtr (*resolveEntitySAXFunc) (void *ctx,
				const xmlChar *publicId,
				const xmlChar *systemId);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  the root element name
 * @param ExternalID  the external ID
 * @param SystemID  the SYSTEM ID (e.g. filename or URL)
 *
 * Callback on internal subset declaration.
 */
typedef void (*internalSubsetSAXFunc) (void *ctx,
				const xmlChar *name,
				const xmlChar *ExternalID,
				const xmlChar *SystemID);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  the root element name
 * @param ExternalID  the external ID
 * @param SystemID  the SYSTEM ID (e.g. filename or URL)
 *
 * Callback on external subset declaration.
 */
typedef void (*externalSubsetSAXFunc) (void *ctx,
				const xmlChar *name,
				const xmlChar *ExternalID,
				const xmlChar *SystemID);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The entity name
 *
 * Get an entity by name.
 *
 * @returns the xmlEntityPtr if found.
 */
typedef xmlEntityPtr (*getEntitySAXFunc) (void *ctx,
				const xmlChar *name);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The entity name
 *
 * Get a parameter entity by name.
 *
 * @returns the xmlEntityPtr if found.
 */
typedef xmlEntityPtr (*getParameterEntitySAXFunc) (void *ctx,
				const xmlChar *name);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  the entity name
 * @param type  the entity type
 * @param publicId  The public ID of the entity
 * @param systemId  The system ID of the entity
 * @param content  the entity value (without processing).
 *
 * An entity definition has been parsed.
 */
typedef void (*entityDeclSAXFunc) (void *ctx,
				const xmlChar *name,
				int type,
				const xmlChar *publicId,
				const xmlChar *systemId,
				xmlChar *content);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The name of the notation
 * @param publicId  The public ID of the entity
 * @param systemId  The system ID of the entity
 *
 * What to do when a notation declaration has been parsed.
 */
typedef void (*notationDeclSAXFunc)(void *ctx,
				const xmlChar *name,
				const xmlChar *publicId,
				const xmlChar *systemId);
/**
 * @param ctx  the user data (XML parser context)
 * @param elem  the name of the element
 * @param fullname  the attribute name
 * @param type  the attribute type
 * @param def  the type of default value
 * @param defaultValue  the attribute default value
 * @param tree  the tree of enumerated value set
 *
 * An attribute definition has been parsed.
 */
typedef void (*attributeDeclSAXFunc)(void *ctx,
				const xmlChar *elem,
				const xmlChar *fullname,
				int type,
				int def,
				const xmlChar *defaultValue,
				xmlEnumerationPtr tree);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  the element name
 * @param type  the element type
 * @param content  the element value tree
 *
 * An element definition has been parsed.
 */
typedef void (*elementDeclSAXFunc)(void *ctx,
				const xmlChar *name,
				int type,
				xmlElementContentPtr content);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The name of the entity
 * @param publicId  The public ID of the entity
 * @param systemId  The system ID of the entity
 * @param notationName  the name of the notation
 *
 * What to do when an unparsed entity declaration is parsed.
 */
typedef void (*unparsedEntityDeclSAXFunc)(void *ctx,
				const xmlChar *name,
				const xmlChar *publicId,
				const xmlChar *systemId,
				const xmlChar *notationName);
/**
 * @param ctx  the user data (XML parser context)
 * @param loc  A SAX Locator
 *
 * Receive the document locator at startup, actually xmlDefaultSAXLocator.
 * Everything is available on the context, so this is useless in our case.
 */
typedef void (*setDocumentLocatorSAXFunc) (void *ctx,
				xmlSAXLocatorPtr loc);
/**
 * @param ctx  the user data (XML parser context)
 *
 * Called when the document start being processed.
 */
typedef void (*startDocumentSAXFunc) (void *ctx);
/**
 * @param ctx  the user data (XML parser context)
 *
 * Called when the document end has been detected.
 */
typedef void (*endDocumentSAXFunc) (void *ctx);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The element name, including namespace prefix
 * @param atts  An array of name/value attributes pairs, NULL terminated
 *
 * Called when an opening tag has been processed.
 */
typedef void (*startElementSAXFunc) (void *ctx,
				const xmlChar *name,
				const xmlChar **atts);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The element name
 *
 * Called when the end of an element has been detected.
 */
typedef void (*endElementSAXFunc) (void *ctx,
				const xmlChar *name);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The attribute name, including namespace prefix
 * @param value  The attribute value
 *
 * Handle an attribute that has been read by the parser.
 * The default handling is to convert the attribute into an
 * DOM subtree and past it in a new xmlAttr element added to
 * the element.
 */
typedef void (*attributeSAXFunc) (void *ctx,
				const xmlChar *name,
				const xmlChar *value);
/**
 * @param ctx  the user data (XML parser context)
 * @param name  The entity name
 *
 * Called when an entity reference is detected.
 */
typedef void (*referenceSAXFunc) (void *ctx,
				const xmlChar *name);
/**
 * @param ctx  the user data (XML parser context)
 * @param ch  a xmlChar string
 * @param len  the number of xmlChar
 *
 * Receiving some chars from the parser.
 */
typedef void (*charactersSAXFunc) (void *ctx,
				const xmlChar *ch,
				int len);
/**
 * @param ctx  the user data (XML parser context)
 * @param ch  a xmlChar string
 * @param len  the number of xmlChar
 *
 * Receiving some ignorable whitespaces from the parser.
 * UNUSED: by default the DOM building will use characters.
 */
typedef void (*ignorableWhitespaceSAXFunc) (void *ctx,
				const xmlChar *ch,
				int len);
/**
 * @param ctx  the user data (XML parser context)
 * @param target  the target name
 * @param data  the PI data's
 *
 * A processing instruction has been parsed.
 */
typedef void (*processingInstructionSAXFunc) (void *ctx,
				const xmlChar *target,
				const xmlChar *data);
/**
 * @param ctx  the user data (XML parser context)
 * @param value  the comment content
 *
 * A comment has been parsed.
 */
typedef void (*commentSAXFunc) (void *ctx,
				const xmlChar *value);
/**
 * @param ctx  the user data (XML parser context)
 * @param value  The pcdata content
 * @param len  the block length
 *
 * Called when a pcdata block has been parsed.
 */
typedef void (*cdataBlockSAXFunc) (
	                        void *ctx,
				const xmlChar *value,
				int len);
/**
 * @param ctx  an XML parser context
 * @param msg  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format a warning messages, callback.
 */
typedef void (*warningSAXFunc) (void *ctx,
				const char *msg, ...) LIBXML_ATTR_FORMAT(2,3);
/**
 * @param ctx  an XML parser context
 * @param msg  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format an error messages, callback.
 */
typedef void (*errorSAXFunc) (void *ctx,
				const char *msg, ...) LIBXML_ATTR_FORMAT(2,3);
/**
 * @param ctx  an XML parser context
 * @param msg  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format fatal error messages, callback.
 * Note: so far fatalError() SAX callbacks are not used, error()
 *       get all the callbacks for errors.
 */
typedef void (*fatalErrorSAXFunc) (void *ctx,
				const char *msg, ...) LIBXML_ATTR_FORMAT(2,3);
/**
 * @param ctx  the user data (XML parser context)
 *
 * Is this document tagged standalone?
 *
 * @returns 1 if true
 */
typedef int (*isStandaloneSAXFunc) (void *ctx);
/**
 * @param ctx  the user data (XML parser context)
 *
 * Does this document has an internal subset.
 *
 * @returns 1 if true
 */
typedef int (*hasInternalSubsetSAXFunc) (void *ctx);

/**
 * @param ctx  the user data (XML parser context)
 *
 * Does this document has an external subset?
 *
 * @returns 1 if true
 */
typedef int (*hasExternalSubsetSAXFunc) (void *ctx);

/************************************************************************
 *									*
 *			The SAX version 2 API extensions		*
 *									*
 ************************************************************************/
/**
 * Special constant found in SAX2 blocks initialized fields
 */
#define XML_SAX2_MAGIC 0xDEEDBEAF

/**
 * @param ctx  the user data (XML parser context)
 * @param localname  the local name of the element
 * @param prefix  the element namespace prefix if available
 * @param URI  the element namespace name if available
 * @param nb_namespaces  number of namespace definitions on that node
 * @param namespaces  pointer to the array of prefix/URI pairs namespace definitions
 * @param nb_attributes  the number of attributes on that node
 * @param nb_defaulted  the number of defaulted attributes. The defaulted
 *                  ones are at the end of the array
 * @param attributes  pointer to the array of (localname/prefix/URI/value/end)
 *               attribute values.
 *
 * SAX2 callback when an element start has been detected by the parser.
 * It provides the namespace information for the element, as well as
 * the new namespace declarations on the element.
 */

typedef void (*startElementNsSAX2Func) (void *ctx,
					const xmlChar *localname,
					const xmlChar *prefix,
					const xmlChar *URI,
					int nb_namespaces,
					const xmlChar **namespaces,
					int nb_attributes,
					int nb_defaulted,
					const xmlChar **attributes);

/**
 * @param ctx  the user data (XML parser context)
 * @param localname  the local name of the element
 * @param prefix  the element namespace prefix if available
 * @param URI  the element namespace name if available
 *
 * SAX2 callback when an element end has been detected by the parser.
 * It provides the namespace information for the element.
 */

typedef void (*endElementNsSAX2Func)   (void *ctx,
					const xmlChar *localname,
					const xmlChar *prefix,
					const xmlChar *URI);


struct _xmlSAXHandler {
    /*
     * For DTD-related handlers, it's recommended to either use the
     * original libxml2 handler or set them to NULL if DTDs can be
     * ignored.
     */
    internalSubsetSAXFunc internalSubset; /* DTD */
    isStandaloneSAXFunc isStandalone; /* unused */
    hasInternalSubsetSAXFunc hasInternalSubset; /* DTD */
    hasExternalSubsetSAXFunc hasExternalSubset; /* DTD */
    resolveEntitySAXFunc resolveEntity; /* DTD */
    getEntitySAXFunc getEntity; /* DTD */
    entityDeclSAXFunc entityDecl; /* DTD */
    notationDeclSAXFunc notationDecl; /* DTD */
    attributeDeclSAXFunc attributeDecl; /* DTD */
    elementDeclSAXFunc elementDecl; /* DTD */
    unparsedEntityDeclSAXFunc unparsedEntityDecl; /* DTD */
    setDocumentLocatorSAXFunc setDocumentLocator; /* deprecated */
    startDocumentSAXFunc startDocument;
    endDocumentSAXFunc endDocument;
    /*
     * `startElement` and `endElement` are only used by the legacy SAX1
     * interface and should not be used in new software. If you really
     * have to enable SAX1, the preferred way is set the `initialized`
     * member to 1 instead of XML_SAX2_MAGIC.
     *
     * For backward compatibility, it's also possible to set the
     * `startElementNs` and `endElementNs` handlers to NULL.
     *
     * You can also set the XML_PARSE_SAX1 parser option, but versions
     * older than 2.12.0 will probably crash if this option is provided
     * together with custom SAX callbacks.
     */
    startElementSAXFunc startElement;
    endElementSAXFunc endElement;
    referenceSAXFunc reference;
    charactersSAXFunc characters;
    /*
     * `ignorableWhitespace` should always be set to the same value
     * as `characters`. Otherwise, the parser will try to detect
     * whitespace which is unreliable.
     */
    ignorableWhitespaceSAXFunc ignorableWhitespace;
    processingInstructionSAXFunc processingInstruction;
    commentSAXFunc comment;
    warningSAXFunc warning;
    errorSAXFunc error;
    fatalErrorSAXFunc fatalError; /* unused, `error` gets all the errors */
    getParameterEntitySAXFunc getParameterEntity; /* DTD */
    cdataBlockSAXFunc cdataBlock;
    externalSubsetSAXFunc externalSubset; /* DTD */
    /*
     * `initialized` should always be set to XML_SAX2_MAGIC to enable the
     * modern SAX2 interface.
     */
    unsigned int initialized;
    /*
     * The following members are only used by the SAX2 interface.
     */
    void *_private;
    startElementNsSAX2Func startElementNs;
    endElementNsSAX2Func endElementNs;
    /*
     * Takes precedence over `error` or `warning`, but modern code
     * should use xmlCtxtSetErrorHandler.
     */
    xmlStructuredErrorFunc serror;
};

/*
 * SAX Version 1
 */
typedef struct _xmlSAXHandlerV1 xmlSAXHandlerV1;
typedef xmlSAXHandlerV1 *xmlSAXHandlerV1Ptr;
struct _xmlSAXHandlerV1 {
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
    fatalErrorSAXFunc fatalError; /* unused error() get all the errors */
    getParameterEntitySAXFunc getParameterEntity;
    cdataBlockSAXFunc cdataBlock;
    externalSubsetSAXFunc externalSubset;
    unsigned int initialized;
};


/**
 * @param URL  The System ID of the resource requested
 * @param ID  The Public ID of the resource requested
 * @param context  the XML parser context
 *
 * External entity loaders types.
 *
 * @returns the entity input parser.
 */
typedef xmlParserInputPtr (*xmlExternalEntityLoader) (const char *URL,
					 const char *ID,
					 xmlParserCtxtPtr context);

/*
 * Variables
 */

XMLPUBVAR const char *const xmlParserVersion;

/** @cond IGNORE */
XML_DEPRECATED
XMLPUBVAR const xmlSAXLocator xmlDefaultSAXLocator;
#ifdef LIBXML_SAX1_ENABLED
XML_DEPRECATED
XMLPUBVAR const xmlSAXHandlerV1 xmlDefaultSAXHandler;
#endif

XML_DEPRECATED
XMLPUBFUN int *__xmlDoValidityCheckingDefaultValue(void);
XML_DEPRECATED
XMLPUBFUN int *__xmlGetWarningsDefaultValue(void);
XML_DEPRECATED
XMLPUBFUN int *__xmlKeepBlanksDefaultValue(void);
XML_DEPRECATED
XMLPUBFUN int *__xmlLineNumbersDefaultValue(void);
XML_DEPRECATED
XMLPUBFUN int *__xmlLoadExtDtdDefaultValue(void);
XML_DEPRECATED
XMLPUBFUN int *__xmlPedanticParserDefaultValue(void);
XML_DEPRECATED
XMLPUBFUN int *__xmlSubstituteEntitiesDefaultValue(void);

#ifdef LIBXML_OUTPUT_ENABLED
XML_DEPRECATED
XMLPUBFUN int *__xmlIndentTreeOutput(void);
XML_DEPRECATED
XMLPUBFUN const char **__xmlTreeIndentString(void);
XML_DEPRECATED
XMLPUBFUN int *__xmlSaveNoEmptyTags(void);
#endif

#ifndef XML_GLOBALS_NO_REDEFINITION
  #define xmlDoValidityCheckingDefaultValue \
    (*__xmlDoValidityCheckingDefaultValue())
  #define xmlGetWarningsDefaultValue \
    (*__xmlGetWarningsDefaultValue())
  #define xmlKeepBlanksDefaultValue (*__xmlKeepBlanksDefaultValue())
  #define xmlLineNumbersDefaultValue \
    (*__xmlLineNumbersDefaultValue())
  #define xmlLoadExtDtdDefaultValue (*__xmlLoadExtDtdDefaultValue())
  #define xmlPedanticParserDefaultValue \
    (*__xmlPedanticParserDefaultValue())
  #define xmlSubstituteEntitiesDefaultValue \
    (*__xmlSubstituteEntitiesDefaultValue())
  #ifdef LIBXML_OUTPUT_ENABLED
    #define xmlIndentTreeOutput (*__xmlIndentTreeOutput())
    #define xmlTreeIndentString (*__xmlTreeIndentString())
    #define xmlSaveNoEmptyTags (*__xmlSaveNoEmptyTags())
  #endif
#endif
/** @endcond */

/*
 * Init/Cleanup
 */
XMLPUBFUN void
		xmlInitParser		(void);
XMLPUBFUN void
		xmlCleanupParser	(void);
XML_DEPRECATED
XMLPUBFUN void
		xmlInitGlobals		(void);
XML_DEPRECATED
XMLPUBFUN void
		xmlCleanupGlobals	(void);

/*
 * Input functions
 */
XML_DEPRECATED
XMLPUBFUN int
		xmlParserInputRead	(xmlParserInputPtr in,
					 int len);
XMLPUBFUN int
		xmlParserInputGrow	(xmlParserInputPtr in,
					 int len);

/*
 * Basic parsing Interfaces
 */
#ifdef LIBXML_SAX1_ENABLED
XMLPUBFUN xmlDocPtr
		xmlParseDoc		(const xmlChar *cur);
XMLPUBFUN xmlDocPtr
		xmlParseFile		(const char *filename);
XMLPUBFUN xmlDocPtr
		xmlParseMemory		(const char *buffer,
					 int size);
#endif /* LIBXML_SAX1_ENABLED */
XML_DEPRECATED
XMLPUBFUN int
		xmlSubstituteEntitiesDefault(int val);
XML_DEPRECATED
XMLPUBFUN int
                xmlThrDefSubstituteEntitiesDefaultValue(int v);
XMLPUBFUN int
		xmlKeepBlanksDefault	(int val);
XML_DEPRECATED
XMLPUBFUN int
		xmlThrDefKeepBlanksDefaultValue(int v);
XMLPUBFUN void
		xmlStopParser		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int
		xmlPedanticParserDefault(int val);
XML_DEPRECATED
XMLPUBFUN int
                xmlThrDefPedanticParserDefaultValue(int v);
XML_DEPRECATED
XMLPUBFUN int
		xmlLineNumbersDefault	(int val);
XML_DEPRECATED
XMLPUBFUN int
                xmlThrDefLineNumbersDefaultValue(int v);
XML_DEPRECATED
XMLPUBFUN int
                xmlThrDefDoValidityCheckingDefaultValue(int v);
XML_DEPRECATED
XMLPUBFUN int
                xmlThrDefGetWarningsDefaultValue(int v);
XML_DEPRECATED
XMLPUBFUN int
                xmlThrDefLoadExtDtdDefaultValue(int v);

#ifdef LIBXML_SAX1_ENABLED
/*
 * Recovery mode
 */
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlRecoverDoc		(const xmlChar *cur);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlRecoverMemory	(const char *buffer,
					 int size);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlRecoverFile		(const char *filename);
#endif /* LIBXML_SAX1_ENABLED */

/*
 * Less common routines and SAX interfaces
 */
XMLPUBFUN int
		xmlParseDocument	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int
		xmlParseExtParsedEnt	(xmlParserCtxtPtr ctxt);
#ifdef LIBXML_SAX1_ENABLED
XML_DEPRECATED
XMLPUBFUN int
		xmlSAXUserParseFile	(xmlSAXHandlerPtr sax,
					 void *user_data,
					 const char *filename);
XML_DEPRECATED
XMLPUBFUN int
		xmlSAXUserParseMemory	(xmlSAXHandlerPtr sax,
					 void *user_data,
					 const char *buffer,
					 int size);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlSAXParseDoc		(xmlSAXHandlerPtr sax,
					 const xmlChar *cur,
					 int recovery);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlSAXParseMemory	(xmlSAXHandlerPtr sax,
					 const char *buffer,
					 int size,
					 int recovery);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlSAXParseMemoryWithData (xmlSAXHandlerPtr sax,
					 const char *buffer,
					 int size,
					 int recovery,
					 void *data);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlSAXParseFile		(xmlSAXHandlerPtr sax,
					 const char *filename,
					 int recovery);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlSAXParseFileWithData	(xmlSAXHandlerPtr sax,
					 const char *filename,
					 int recovery,
					 void *data);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlSAXParseEntity	(xmlSAXHandlerPtr sax,
					 const char *filename);
XML_DEPRECATED
XMLPUBFUN xmlDocPtr
		xmlParseEntity		(const char *filename);
#endif /* LIBXML_SAX1_ENABLED */

#ifdef LIBXML_VALID_ENABLED
XMLPUBFUN xmlDtdPtr
		xmlCtxtParseDtd		(xmlParserCtxtPtr ctxt,
					 xmlParserInputPtr input,
					 const xmlChar *ExternalID,
					 const xmlChar *SystemID);
XMLPUBFUN int
		xmlCtxtValidateDocument	(xmlParserCtxtPtr ctxt,
					 xmlDocPtr doc);
XMLPUBFUN int
		xmlCtxtValidateDtd	(xmlParserCtxtPtr ctxt,
					 xmlDocPtr doc,
					 xmlDtdPtr dtd);
XML_DEPRECATED
XMLPUBFUN xmlDtdPtr
		xmlSAXParseDTD		(xmlSAXHandlerPtr sax,
					 const xmlChar *ExternalID,
					 const xmlChar *SystemID);
XMLPUBFUN xmlDtdPtr
		xmlParseDTD		(const xmlChar *ExternalID,
					 const xmlChar *SystemID);
XMLPUBFUN xmlDtdPtr
		xmlIOParseDTD		(xmlSAXHandlerPtr sax,
					 xmlParserInputBufferPtr input,
					 xmlCharEncoding enc);
#endif /* LIBXML_VALID_ENABLE */
#ifdef LIBXML_SAX1_ENABLED
XMLPUBFUN int
		xmlParseBalancedChunkMemory(xmlDocPtr doc,
					 xmlSAXHandlerPtr sax,
					 void *user_data,
					 int depth,
					 const xmlChar *string,
					 xmlNodePtr *lst);
#endif /* LIBXML_SAX1_ENABLED */
XMLPUBFUN xmlParserErrors
		xmlParseInNodeContext	(xmlNodePtr node,
					 const char *data,
					 int datalen,
					 int options,
					 xmlNodePtr *lst);
#ifdef LIBXML_SAX1_ENABLED
XMLPUBFUN int
		xmlParseBalancedChunkMemoryRecover(xmlDocPtr doc,
                     xmlSAXHandlerPtr sax,
                     void *user_data,
                     int depth,
                     const xmlChar *string,
                     xmlNodePtr *lst,
                     int recover);
XML_DEPRECATED
XMLPUBFUN int
		xmlParseExternalEntity	(xmlDocPtr doc,
					 xmlSAXHandlerPtr sax,
					 void *user_data,
					 int depth,
					 const xmlChar *URL,
					 const xmlChar *ID,
					 xmlNodePtr *lst);
#endif /* LIBXML_SAX1_ENABLED */
XMLPUBFUN int
		xmlParseCtxtExternalEntity(xmlParserCtxtPtr ctx,
					 const xmlChar *URL,
					 const xmlChar *ID,
					 xmlNodePtr *lst);

/*
 * Parser contexts handling.
 */
XMLPUBFUN xmlParserCtxtPtr
		xmlNewParserCtxt	(void);
XMLPUBFUN xmlParserCtxtPtr
		xmlNewSAXParserCtxt	(const xmlSAXHandler *sax,
					 void *userData);
XMLPUBFUN int
		xmlInitParserCtxt	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
		xmlClearParserCtxt	(xmlParserCtxtPtr ctxt);
XMLPUBFUN void
		xmlFreeParserCtxt	(xmlParserCtxtPtr ctxt);
#ifdef LIBXML_SAX1_ENABLED
XML_DEPRECATED
XMLPUBFUN void
		xmlSetupParserForBuffer	(xmlParserCtxtPtr ctxt,
					 const xmlChar* buffer,
					 const char *filename);
#endif /* LIBXML_SAX1_ENABLED */
XMLPUBFUN xmlParserCtxtPtr
		xmlCreateDocParserCtxt	(const xmlChar *cur);

#ifdef LIBXML_PUSH_ENABLED
/*
 * Interfaces for the Push mode.
 */
XMLPUBFUN xmlParserCtxtPtr
		xmlCreatePushParserCtxt(xmlSAXHandlerPtr sax,
					 void *user_data,
					 const char *chunk,
					 int size,
					 const char *filename);
XMLPUBFUN int
		xmlParseChunk		(xmlParserCtxtPtr ctxt,
					 const char *chunk,
					 int size,
					 int terminate);
#endif /* LIBXML_PUSH_ENABLED */

/*
 * Special I/O mode.
 */

XMLPUBFUN xmlParserCtxtPtr
		xmlCreateIOParserCtxt	(xmlSAXHandlerPtr sax,
					 void *user_data,
					 xmlInputReadCallback   ioread,
					 xmlInputCloseCallback  ioclose,
					 void *ioctx,
					 xmlCharEncoding enc);

XMLPUBFUN xmlParserInputPtr
		xmlNewIOInputStream	(xmlParserCtxtPtr ctxt,
					 xmlParserInputBufferPtr input,
					 xmlCharEncoding enc);

/*
 * Node infos.
 */
XML_DEPRECATED
XMLPUBFUN const xmlParserNodeInfo*
		xmlParserFindNodeInfo	(xmlParserCtxtPtr ctxt,
				         xmlNodePtr node);
XML_DEPRECATED
XMLPUBFUN void
		xmlInitNodeInfoSeq	(xmlParserNodeInfoSeqPtr seq);
XML_DEPRECATED
XMLPUBFUN void
		xmlClearNodeInfoSeq	(xmlParserNodeInfoSeqPtr seq);
XML_DEPRECATED
XMLPUBFUN unsigned long
		xmlParserFindNodeInfoIndex(xmlParserNodeInfoSeqPtr seq,
                                         xmlNodePtr node);
XML_DEPRECATED
XMLPUBFUN void
		xmlParserAddNodeInfo	(xmlParserCtxtPtr ctxt,
					 xmlParserNodeInfoPtr info);

/*
 * External entities handling actually implemented in xmlIO.
 */

XMLPUBFUN void
		xmlSetExternalEntityLoader(xmlExternalEntityLoader f);
XMLPUBFUN xmlExternalEntityLoader
		xmlGetExternalEntityLoader(void);
XMLPUBFUN xmlParserInputPtr
		xmlLoadExternalEntity	(const char *URL,
					 const char *ID,
					 xmlParserCtxtPtr ctxt);

XML_DEPRECATED
XMLPUBFUN long
		xmlByteConsumed		(xmlParserCtxtPtr ctxt);

/*
 * New set of simpler/more flexible APIs
 */

/**
 * This is the set of XML parser options that can be passed down
 * to the xmlReadDoc() and similar calls. See xmlCtxtSetOptions()
 * for a more detailed description.
 */
typedef enum {
    /** recover on errors */
    XML_PARSE_RECOVER	= 1<<0,
    /** substitute entities */
    XML_PARSE_NOENT	= 1<<1,
    /** load the external subset */
    XML_PARSE_DTDLOAD	= 1<<2,
    /** default DTD attributes */
    XML_PARSE_DTDATTR	= 1<<3,
    /** validate with the DTD */
    XML_PARSE_DTDVALID	= 1<<4,
    /** suppress error reports */
    XML_PARSE_NOERROR	= 1<<5,
    /** suppress warning reports */
    XML_PARSE_NOWARNING	= 1<<6,
    /** pedantic error reporting */
    XML_PARSE_PEDANTIC	= 1<<7,
    /** remove blank nodes */
    XML_PARSE_NOBLANKS	= 1<<8,
    /** use the SAX1 interface internally */
    XML_PARSE_SAX1	= 1<<9,
    /** Implement XInclude substitution */
    XML_PARSE_XINCLUDE	= 1<<10,
    /** Forbid network access */
    XML_PARSE_NONET	= 1<<11,
    /** Do not reuse the context dictionary */
    XML_PARSE_NODICT	= 1<<12,
    /** remove redundant namespaces declarations */
    XML_PARSE_NSCLEAN	= 1<<13,
    /** merge CDATA as text nodes */
    XML_PARSE_NOCDATA	= 1<<14,
    /** do not generate XINCLUDE START/END nodes */
    XML_PARSE_NOXINCNODE= 1<<15,
    /** compact small text nodes; no modification of
        the tree allowed afterwards (will possibly
        crash if you try to modify the tree) */
    XML_PARSE_COMPACT   = 1<<16,
    /** parse using XML-1.0 before update 5 */
    XML_PARSE_OLD10	= 1<<17,
    /** do not fixup XINCLUDE xml:base uris */
    XML_PARSE_NOBASEFIX = 1<<18,
    /** relax any hardcoded limit from the parser */
    XML_PARSE_HUGE      = 1<<19,
    /** parse using SAX2 interface before 2.7.0 */
    XML_PARSE_OLDSAX    = 1<<20,
    /** ignore internal document encoding hint */
    XML_PARSE_IGNORE_ENC= 1<<21,
    /** Store big lines numbers in text PSVI field */
    XML_PARSE_BIG_LINES = 1<<22,
    /** disable loading of external content, since 2.13 */
    XML_PARSE_NO_XXE    = 1<<23,
    /** allow compressed content, since 2.14 */
    XML_PARSE_UNZIP          = 1<<24,
    /** disable global system catalog, since 2.14 */
    XML_PARSE_NO_SYS_CATALOG = 1<<25,
    /** allow catalog PIs, sincew 2.14 */
    XML_PARSE_CATALOG_PI     = 1<<26
} xmlParserOption;

XMLPUBFUN void
		xmlCtxtReset		(xmlParserCtxtPtr ctxt);
XMLPUBFUN int
		xmlCtxtResetPush	(xmlParserCtxtPtr ctxt,
					 const char *chunk,
					 int size,
					 const char *filename,
					 const char *encoding);
XMLPUBFUN int
		xmlCtxtGetOptions	(xmlParserCtxtPtr ctxt);
XMLPUBFUN int
		xmlCtxtSetOptions	(xmlParserCtxtPtr ctxt,
					 int options);
XMLPUBFUN int
		xmlCtxtUseOptions	(xmlParserCtxtPtr ctxt,
					 int options);
XMLPUBFUN void *
		xmlCtxtGetPrivate	(xmlParserCtxtPtr ctxt);
XMLPUBFUN void
		xmlCtxtSetPrivate	(xmlParserCtxtPtr ctxt,
					 void *priv);
XMLPUBFUN void *
		xmlCtxtGetCatalogs	(xmlParserCtxtPtr ctxt);
XMLPUBFUN void
		xmlCtxtSetCatalogs	(xmlParserCtxtPtr ctxt,
					 void *catalogs);
XMLPUBFUN xmlDictPtr
		xmlCtxtGetDict		(xmlParserCtxtPtr ctxt);
XMLPUBFUN void
		xmlCtxtSetDict		(xmlParserCtxtPtr ctxt,
					 xmlDictPtr);
XMLPUBFUN xmlSAXHandler *
		xmlCtxtGetSaxHandler	(xmlParserCtxtPtr ctxt);
XMLPUBFUN int
		xmlCtxtSetSaxHandler	(xmlParserCtxtPtr ctxt,
					 const xmlSAXHandler *sax);
XMLPUBFUN xmlDocPtr
		xmlCtxtGetDocument	(xmlParserCtxtPtr ctxt);
XMLPUBFUN int
		xmlCtxtIsHtml		(xmlParserCtxtPtr ctxt);
XMLPUBFUN int
		xmlCtxtIsStopped	(xmlParserCtxtPtr ctxt);
#ifdef LIBXML_VALID_ENABLED
XMLPUBFUN xmlValidCtxtPtr
		xmlCtxtGetValidCtxt	(xmlParserCtxtPtr ctxt);
#endif
XMLPUBFUN const xmlChar *
		xmlCtxtGetVersion	(xmlParserCtxtPtr ctxt);
XMLPUBFUN const xmlChar *
		xmlCtxtGetDeclaredEncoding(xmlParserCtxtPtr ctxt);
XMLPUBFUN int
		xmlCtxtGetStandalone	(xmlParserCtxtPtr ctxt);
XMLPUBFUN xmlParserStatus
		xmlCtxtGetStatus	(xmlParserCtxtPtr ctxt);
XMLPUBFUN void
		xmlCtxtSetErrorHandler	(xmlParserCtxtPtr ctxt,
					 xmlStructuredErrorFunc handler,
					 void *data);
XMLPUBFUN void
		xmlCtxtSetResourceLoader(xmlParserCtxtPtr ctxt,
					 xmlResourceLoader loader,
					 void *vctxt);
XMLPUBFUN void
		xmlCtxtSetCharEncConvImpl(xmlParserCtxtPtr ctxt,
					 xmlCharEncConvImpl impl,
					 void *vctxt);
XMLPUBFUN void
		xmlCtxtSetMaxAmplification(xmlParserCtxtPtr ctxt,
					 unsigned maxAmpl);
XMLPUBFUN xmlDocPtr
		xmlReadDoc		(const xmlChar *cur,
					 const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlReadFile		(const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlReadMemory		(const char *buffer,
					 int size,
					 const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlReadFd		(int fd,
					 const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlReadIO		(xmlInputReadCallback ioread,
					 xmlInputCloseCallback ioclose,
					 void *ioctx,
					 const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlCtxtParseDocument	(xmlParserCtxtPtr ctxt,
					 xmlParserInputPtr input);
XMLPUBFUN xmlNodePtr
		xmlCtxtParseContent	(xmlParserCtxtPtr ctxt,
					 xmlParserInputPtr input,
					 xmlNodePtr node,
					 int hasTextDecl);
XMLPUBFUN xmlDocPtr
		xmlCtxtReadDoc		(xmlParserCtxtPtr ctxt,
					 const xmlChar *cur,
					 const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlCtxtReadFile		(xmlParserCtxtPtr ctxt,
					 const char *filename,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlCtxtReadMemory		(xmlParserCtxtPtr ctxt,
					 const char *buffer,
					 int size,
					 const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlCtxtReadFd		(xmlParserCtxtPtr ctxt,
					 int fd,
					 const char *URL,
					 const char *encoding,
					 int options);
XMLPUBFUN xmlDocPtr
		xmlCtxtReadIO		(xmlParserCtxtPtr ctxt,
					 xmlInputReadCallback ioread,
					 xmlInputCloseCallback ioclose,
					 void *ioctx,
					 const char *URL,
					 const char *encoding,
					 int options);

/**
 * New input API
 */

XMLPUBFUN xmlParserErrors
xmlNewInputFromUrl(const char *url, xmlParserInputFlags flags,
                   xmlParserInputPtr *out);
XMLPUBFUN xmlParserInputPtr
xmlNewInputFromMemory(const char *url, const void *mem, size_t size,
                      xmlParserInputFlags flags);
XMLPUBFUN xmlParserInputPtr
xmlNewInputFromString(const char *url, const char *str,
                      xmlParserInputFlags flags);
XMLPUBFUN xmlParserInputPtr
xmlNewInputFromFd(const char *url, int fd, xmlParserInputFlags flags);
XMLPUBFUN xmlParserInputPtr
xmlNewInputFromIO(const char *url, xmlInputReadCallback ioRead,
                  xmlInputCloseCallback ioClose, void *ioCtxt,
                  xmlParserInputFlags flags);
XMLPUBFUN xmlParserErrors
xmlInputSetEncodingHandler(xmlParserInputPtr input,
                           xmlCharEncodingHandlerPtr handler);

/*
 * Library wide options
 */

/**
 * Used to examine the existence of features that can be enabled
 * or disabled at compile-time.
 * They used to be called XML_FEATURE_xxx but this clashed with Expat
 */
typedef enum {
    /** Multithreading support */
    XML_WITH_THREAD = 1,
    /** @deprecated Always available */
    XML_WITH_TREE = 2,
    /** Serialization support */
    XML_WITH_OUTPUT = 3,
    /** Push parser */
    XML_WITH_PUSH = 4,
    /** XML Reader */
    XML_WITH_READER = 5,
    /** Streaming patterns */
    XML_WITH_PATTERN = 6,
    /** XML Writer */
    XML_WITH_WRITER = 7,
    /** Legacy SAX1 API */
    XML_WITH_SAX1 = 8,
    /** @deprecated FTP support was removed */
    XML_WITH_FTP = 9,
    /** @deprecated HTTP support was removed */
    XML_WITH_HTTP = 10,
    /** DTD validation */
    XML_WITH_VALID = 11,
    /** HTML parser */
    XML_WITH_HTML = 12,
    /** Legacy symbols */
    XML_WITH_LEGACY = 13,
    /** Canonical XML */
    XML_WITH_C14N = 14,
    /** XML Catalogs */
    XML_WITH_CATALOG = 15,
    /** XPath */
    XML_WITH_XPATH = 16,
    /** XPointer */
    XML_WITH_XPTR = 17,
    /** XInclude */
    XML_WITH_XINCLUDE = 18,
    /** iconv */
    XML_WITH_ICONV = 19,
    /** Built-in ISO-8859-X */
    XML_WITH_ISO8859X = 20,
    /** @deprecated Removed */
    XML_WITH_UNICODE = 21,
    /** Regular expressions */
    XML_WITH_REGEXP = 22,
    /** @deprecated Same as XML_WITH_REGEXP */
    XML_WITH_AUTOMATA = 23,
    /** @deprecated Removed */
    XML_WITH_EXPR = 24,
    /** XML Schemas */
    XML_WITH_SCHEMAS = 25,
    /** Schematron */
    XML_WITH_SCHEMATRON = 26,
    /** Loadable modules */
    XML_WITH_MODULES = 27,
    /** Debugging API */
    XML_WITH_DEBUG = 28,
    /** @deprecated Removed */
    XML_WITH_DEBUG_MEM = 29,
    /** @deprecated Removed */
    XML_WITH_DEBUG_RUN = 30,
    /** GZIP compression */
    XML_WITH_ZLIB = 31,
    /** ICU */
    XML_WITH_ICU = 32,
    /** LZMA compression */
    XML_WITH_LZMA = 33,
    /** RELAXNG, since 2.14 */
    XML_WITH_RELAXNG = 34,
    XML_WITH_NONE = 99999 /* just to be sure of allocation size */
} xmlFeature;

XMLPUBFUN int
		xmlHasFeature		(xmlFeature feature);

#ifdef __cplusplus
}
#endif
#endif /* __XML_PARSER_H__ */
