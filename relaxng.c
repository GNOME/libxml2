/*
 * relaxng.c : implementation of the Relax-NG handling and validity checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

/**
 * TODO:
 * - error reporting
 * - simplification of the resulting compiled trees:
 *    - NOT_ALLOWED
 *    - EMPTY
 * - handle namespace declarations as attributes.
 * - add support for DTD compatibility spec
 *   http://www.oasis-open.org/committees/relax-ng/compatibility-20011203.html
 */

#define IN_LIBXML
#include "libxml.h"

#ifdef LIBXML_SCHEMAS_ENABLED

#include <string.h>
#include <stdio.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/hash.h>
#include <libxml/uri.h>

#include <libxml/relaxng.h>

#include <libxml/xmlschemastypes.h>
#include <libxml/xmlautomata.h>
#include <libxml/xmlregexp.h>
#include <libxml/xmlschemastypes.h>

/*
 * The Relax-NG namespace
 */
static const xmlChar *xmlRelaxNGNs = (const xmlChar *)
    "http://relaxng.org/ns/structure/1.0";

#define IS_RELAXNG(node, type)						\
   ((node != NULL) && (node->ns != NULL) &&				\
    (xmlStrEqual(node->name, (const xmlChar *) type)) &&		\
    (xmlStrEqual(node->ns->href, xmlRelaxNGNs)))


/* #define DEBUG 1 */                /* very verbose output */
/* #define DEBUG_CONTENT 1 */
/* #define DEBUG_TYPE 1 */
/* #define DEBUG_VALID 1 */
/* #define DEBUG_INTERLEAVE 1 */

#define UNBOUNDED (1 << 30)
#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

typedef struct _xmlRelaxNGSchema xmlRelaxNGSchema;
typedef xmlRelaxNGSchema *xmlRelaxNGSchemaPtr;

typedef struct _xmlRelaxNGDefine xmlRelaxNGDefine;
typedef xmlRelaxNGDefine *xmlRelaxNGDefinePtr;

typedef struct _xmlRelaxNGDocument xmlRelaxNGDocument;
typedef xmlRelaxNGDocument *xmlRelaxNGDocumentPtr;

typedef struct _xmlRelaxNGInclude xmlRelaxNGInclude;
typedef xmlRelaxNGInclude *xmlRelaxNGIncludePtr;

typedef enum {
    XML_RELAXNG_COMBINE_UNDEFINED = 0,	/* undefined */
    XML_RELAXNG_COMBINE_CHOICE,		/* choice */
    XML_RELAXNG_COMBINE_INTERLEAVE	/* interleave */
} xmlRelaxNGCombine;

typedef struct _xmlRelaxNGGrammar xmlRelaxNGGrammar;
typedef xmlRelaxNGGrammar *xmlRelaxNGGrammarPtr;

struct _xmlRelaxNGGrammar {
    xmlRelaxNGGrammarPtr parent;/* the parent grammar if any */
    xmlRelaxNGGrammarPtr children;/* the children grammar if any */
    xmlRelaxNGGrammarPtr next;	/* the next grammar if any */
    xmlRelaxNGDefinePtr start;	/* <start> content */
    xmlRelaxNGCombine combine;	/* the default combine value */
    xmlRelaxNGDefinePtr startList;/* list of <start> definitions */
    xmlHashTablePtr defs;	/* define* */
    xmlHashTablePtr refs;	/* references */
};


typedef enum {
    XML_RELAXNG_EMPTY = 0,	/* an empty pattern */
    XML_RELAXNG_NOT_ALLOWED,    /* not allowed top */
    XML_RELAXNG_EXCEPT,    	/* except present in nameclass defs */
    XML_RELAXNG_TEXT,		/* textual content */
    XML_RELAXNG_ELEMENT,	/* an element */
    XML_RELAXNG_DATATYPE,	/* extenal data type definition */
    XML_RELAXNG_VALUE,		/* value from an extenal data type definition */
    XML_RELAXNG_LIST,		/* a list of patterns */
    XML_RELAXNG_ATTRIBUTE,	/* an attrbute following a pattern */
    XML_RELAXNG_DEF,		/* a definition */
    XML_RELAXNG_REF,		/* reference to a definition */
    XML_RELAXNG_EXTERNALREF,	/* reference to an external def */
    XML_RELAXNG_PARENTREF,	/* reference to a def in the parent grammar */
    XML_RELAXNG_OPTIONAL,	/* optional patterns */
    XML_RELAXNG_ZEROORMORE,	/* zero or more non empty patterns */
    XML_RELAXNG_ONEORMORE,	/* one or more non empty patterns */
    XML_RELAXNG_CHOICE,		/* a choice between non empty patterns */
    XML_RELAXNG_GROUP,		/* a pair/group of non empty patterns */
    XML_RELAXNG_INTERLEAVE,	/* interleaving choice of non-empty patterns */
    XML_RELAXNG_START		/* Used to keep track of starts on grammars */
} xmlRelaxNGType;

struct _xmlRelaxNGDefine {
    xmlRelaxNGType type;	/* the type of definition */
    xmlNodePtr	   node;	/* the node in the source */
    xmlChar       *name;	/* the element local name if present */
    xmlChar       *ns;		/* the namespace local name if present */
    xmlChar       *value;	/* value when available */
    void          *data;	/* data lib or specific pointer */
    xmlRelaxNGDefinePtr content;/* the expected content */
    xmlRelaxNGDefinePtr parent;	/* the parent definition, if any */
    xmlRelaxNGDefinePtr next;	/* list within grouping sequences */
    xmlRelaxNGDefinePtr attrs;	/* list of attributes for elements */
    xmlRelaxNGDefinePtr nameClass;/* the nameClass definition if any */
    xmlRelaxNGDefinePtr nextHash;/* next define in defs/refs hash tables */
};

/**
 * _xmlRelaxNG:
 *
 * A RelaxNGs definition
 */
struct _xmlRelaxNG {
    xmlRelaxNGGrammarPtr topgrammar;
    xmlDocPtr doc;

    xmlHashTablePtr defs;	/* define */
    xmlHashTablePtr refs;	/* references */
    xmlHashTablePtr documents;  /* all the documents loaded */
    xmlHashTablePtr includes;   /* all the includes loaded */
    int                  defNr; /* number of defines used */
    xmlRelaxNGDefinePtr *defTab;/* pointer to the allocated definitions */
    void *_private;	/* unused by the library for users or bindings */
};

typedef enum {
    XML_RELAXNG_ERR_OK		= 0,
    XML_RELAXNG_ERR_NOROOT	= 1,
    XML_RELAXNG_ERR_
} xmlRelaxNGValidError;

#define XML_RELAXNG_IN_ATTRIBUTE	1

struct _xmlRelaxNGParserCtxt {
    void *userData;			/* user specific data block */
    xmlRelaxNGValidityErrorFunc error;	/* the callback in case of errors */
    xmlRelaxNGValidityWarningFunc warning;/* the callback in case of warning */
    xmlRelaxNGValidError err;

    xmlRelaxNGPtr      schema;        /* The schema in use */
    xmlRelaxNGGrammarPtr grammar;     /* the current grammar */
    xmlRelaxNGGrammarPtr parentgrammar;/* the parent grammar */
    int                flags;         /* parser flags */
    int                nbErrors;      /* number of errors at parse time */
    int                nbWarnings;    /* number of warnings at parse time */
    const xmlChar     *define;        /* the current define scope */
    xmlRelaxNGDefinePtr def;          /* the current define */

    int                nbInterleaves;
    xmlHashTablePtr    interleaves;   /* keep track of all the interleaves */

    xmlHashTablePtr    documents;     /* all the documents loaded */
    xmlHashTablePtr    includes;      /* all the includes loaded */
    xmlChar	      *URL;
    xmlDocPtr          document;

    int                  defNr;       /* number of defines used */
    int                  defMax;      /* number of defines aloocated */
    xmlRelaxNGDefinePtr *defTab;      /* pointer to the allocated definitions */

    const char     *buffer;
    int               size;

    /* the document stack */
    xmlRelaxNGDocumentPtr doc;        /* Current parsed external ref */
    int                   docNr;      /* Depth of the parsing stack */
    int                   docMax;     /* Max depth of the parsing stack */
    xmlRelaxNGDocumentPtr *docTab;    /* array of docs */

    /* the include stack */
    xmlRelaxNGIncludePtr inc;         /* Current parsed include */
    int                   incNr;      /* Depth of the include parsing stack */
    int                   incMax;     /* Max depth of the parsing stack */
    xmlRelaxNGIncludePtr *incTab;     /* array of incs */
};

#define FLAGS_IGNORABLE		1
#define FLAGS_NEGATIVE		2

/**
 * xmlRelaxNGInterleaveGroup:
 *
 * A RelaxNGs partition set associated to lists of definitions
 */
typedef struct _xmlRelaxNGInterleaveGroup xmlRelaxNGInterleaveGroup;
typedef xmlRelaxNGInterleaveGroup *xmlRelaxNGInterleaveGroupPtr;
struct _xmlRelaxNGInterleaveGroup {
    xmlRelaxNGDefinePtr  rule;	/* the rule to satisfy */
    xmlRelaxNGDefinePtr *defs;	/* the array of element definitions */
};

/**
 * xmlRelaxNGPartitions:
 *
 * A RelaxNGs partition associated to an interleave group
 */
typedef struct _xmlRelaxNGPartition xmlRelaxNGPartition;
typedef xmlRelaxNGPartition *xmlRelaxNGPartitionPtr;
struct _xmlRelaxNGPartition {
    int nbgroups;		/* number of groups in the partitions */
    xmlRelaxNGInterleaveGroupPtr *groups;
};

/**
 * xmlRelaxNGValidState:
 *
 * A RelaxNGs validation state
 */
#define MAX_ATTR 20
typedef struct _xmlRelaxNGValidState xmlRelaxNGValidState;
typedef xmlRelaxNGValidState *xmlRelaxNGValidStatePtr;
struct _xmlRelaxNGValidState {
    xmlNodePtr   node;		/* the current node */
    xmlNodePtr    seq;		/* the sequence of children left to validate */
    int       nbAttrs;		/* the number of attributes */
    int    nbAttrLeft;		/* the number of attributes left to validate */
    xmlChar    *value;		/* the value when operating on string */
    xmlChar *endvalue;		/* the end value when operating on string */
    xmlAttrPtr attrs[1];	/* the array of attributes */
};

/**
 * xmlRelaxNGValidCtxt:
 *
 * A RelaxNGs validation context
 */

struct _xmlRelaxNGValidCtxt {
    void *userData;			/* user specific data block */
    xmlRelaxNGValidityErrorFunc error;	/* the callback in case of errors */
    xmlRelaxNGValidityWarningFunc warning;/* the callback in case of warning */

    xmlRelaxNGPtr           schema;	/* The schema in use */
    xmlDocPtr               doc;	/* the document being validated */
    xmlRelaxNGValidStatePtr state;	/* the current validation state */
    int                     flags;	/* validation flags */
    int                     depth;	/* validation depth */
};

/**
 * xmlRelaxNGInclude:
 *
 * Structure associated to a RelaxNGs document element
 */
struct _xmlRelaxNGInclude {
    xmlChar   *href;		/* the normalized href value */
    xmlDocPtr  doc;		/* the associated XML document */
    xmlRelaxNGDefinePtr content;/* the definitions */
    xmlRelaxNGPtr	schema; /* the schema */
};

/**
 * xmlRelaxNGDocument:
 *
 * Structure associated to a RelaxNGs document element
 */
struct _xmlRelaxNGDocument {
    xmlChar   *href;		/* the normalized href value */
    xmlDocPtr  doc;		/* the associated XML document */
    xmlRelaxNGDefinePtr content;/* the definitions */
    xmlRelaxNGPtr	schema; /* the schema */
};

/************************************************************************
 * 									*
 * 		Preliminary type checking interfaces			*
 * 									*
 ************************************************************************/
/**
 * xmlRelaxNGTypeHave:
 * @data:  data needed for the library
 * @type:  the type name
 * @value:  the value to check
 *
 * Function provided by a type library to check if a type is exported
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
typedef int (*xmlRelaxNGTypeHave) (void *data, const xmlChar *type);

/**
 * xmlRelaxNGTypeCheck:
 * @data:  data needed for the library
 * @type:  the type name
 * @value:  the value to check
 *
 * Function provided by a type library to check if a value match a type
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
typedef int (*xmlRelaxNGTypeCheck) (void *data, const xmlChar *type,
	                            const xmlChar *value);

/**
 * xmlRelaxNGTypeCompare:
 * @data:  data needed for the library
 * @type:  the type name
 * @value1:  the first value
 * @value2:  the second value
 *
 * Function provided by a type library to compare two values accordingly
 * to a type.
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
typedef int (*xmlRelaxNGTypeCompare) (void *data, const xmlChar *type,
	                              const xmlChar *value1,
				      const xmlChar *value2);
typedef struct _xmlRelaxNGTypeLibrary xmlRelaxNGTypeLibrary;
typedef xmlRelaxNGTypeLibrary *xmlRelaxNGTypeLibraryPtr;
struct _xmlRelaxNGTypeLibrary {
    const xmlChar     *namespace;	/* the datatypeLibrary value */
    void                   *data;	/* data needed for the library */
    xmlRelaxNGTypeHave      have;	/* the export function */
    xmlRelaxNGTypeCheck    check;	/* the checking function */
    xmlRelaxNGTypeCompare   comp;	/* the compare function */
};

/************************************************************************
 * 									*
 * 			Allocation functions				*
 * 									*
 ************************************************************************/
static void xmlRelaxNGFreeGrammar(xmlRelaxNGGrammarPtr grammar);
static void xmlRelaxNGFreeDefine(xmlRelaxNGDefinePtr define);

/**
 * xmlRelaxNGFreeDocument:
 * @docu:  a document structure
 *
 * Deallocate a RelaxNG document structure.
 */
static void
xmlRelaxNGFreeDocument(xmlRelaxNGDocumentPtr docu)
{
    if (docu == NULL)
        return;

    if (docu->href != NULL)
	xmlFree(docu->href);
    if (docu->doc != NULL)
	xmlFreeDoc(docu->doc);
    if (docu->schema != NULL)
	xmlRelaxNGFree(docu->schema);
    xmlFree(docu);
}

/**
 * xmlRelaxNGFreeInclude:
 * @incl:  a include structure
 *
 * Deallocate a RelaxNG include structure.
 */
static void
xmlRelaxNGFreeInclude(xmlRelaxNGIncludePtr incl)
{
    if (incl == NULL)
        return;

    if (incl->href != NULL)
	xmlFree(incl->href);
    if (incl->doc != NULL)
	xmlFreeDoc(incl->doc);
    if (incl->schema != NULL)
	xmlRelaxNGFree(incl->schema);
    xmlFree(incl);
}

/**
 * xmlRelaxNGNewRelaxNG:
 * @ctxt:  a Relax-NG validation context (optional)
 *
 * Allocate a new RelaxNG structure.
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlRelaxNGPtr
xmlRelaxNGNewRelaxNG(xmlRelaxNGParserCtxtPtr ctxt)
{
    xmlRelaxNGPtr ret;

    ret = (xmlRelaxNGPtr) xmlMalloc(sizeof(xmlRelaxNG));
    if (ret == NULL) {
        if ((ctxt != NULL) && (ctxt->error != NULL))
            ctxt->error(ctxt->userData, "Out of memory\n");
	ctxt->nbErrors++;
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNG));

    return (ret);
}

/**
 * xmlRelaxNGFree:
 * @schema:  a schema structure
 *
 * Deallocate a RelaxNG structure.
 */
void
xmlRelaxNGFree(xmlRelaxNGPtr schema)
{
    if (schema == NULL)
        return;

    if (schema->topgrammar != NULL)
	xmlRelaxNGFreeGrammar(schema->topgrammar);
    if (schema->doc != NULL)
	xmlFreeDoc(schema->doc);
    if (schema->documents != NULL)
	xmlHashFree(schema->documents, (xmlHashDeallocator)
		xmlRelaxNGFreeDocument);
    if (schema->includes != NULL)
	xmlHashFree(schema->includes, (xmlHashDeallocator)
		xmlRelaxNGFreeInclude);
    if (schema->defTab != NULL) {
	int i;

	for (i = 0;i < schema->defNr;i++)
	    xmlRelaxNGFreeDefine(schema->defTab[i]);
	xmlFree(schema->defTab);
    }

    xmlFree(schema);
}

/**
 * xmlRelaxNGNewGrammar:
 * @ctxt:  a Relax-NG validation context (optional)
 *
 * Allocate a new RelaxNG grammar.
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlRelaxNGGrammarPtr
xmlRelaxNGNewGrammar(xmlRelaxNGParserCtxtPtr ctxt)
{
    xmlRelaxNGGrammarPtr ret;

    ret = (xmlRelaxNGGrammarPtr) xmlMalloc(sizeof(xmlRelaxNGGrammar));
    if (ret == NULL) {
        if ((ctxt != NULL) && (ctxt->error != NULL))
            ctxt->error(ctxt->userData, "Out of memory\n");
	ctxt->nbErrors++;
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGGrammar));

    return (ret);
}

/**
 * xmlRelaxNGFreeGrammar:
 * @grammar:  a grammar structure
 *
 * Deallocate a RelaxNG grammar structure.
 */
static void
xmlRelaxNGFreeGrammar(xmlRelaxNGGrammarPtr grammar)
{
    if (grammar == NULL)
        return;

    if (grammar->next != NULL) {
	xmlRelaxNGFreeGrammar(grammar->next);
    }
    if (grammar->refs != NULL) {
	xmlHashFree(grammar->refs, NULL);
    }
    if (grammar->defs != NULL) {
	xmlHashFree(grammar->defs, NULL);
    }

    xmlFree(grammar);
}

/**
 * xmlRelaxNGNewDefine:
 * @ctxt:  a Relax-NG validation context
 * @node:  the node in the input document.
 *
 * Allocate a new RelaxNG define.
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGNewDefine(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node)
{
    xmlRelaxNGDefinePtr ret;

    if (ctxt->defMax == 0) {
	ctxt->defMax = 16;
	ctxt->defNr = 0;
	ctxt->defTab = (xmlRelaxNGDefinePtr *)
	    xmlMalloc(ctxt->defMax * sizeof(xmlRelaxNGDefinePtr));
	if (ctxt->defTab == NULL) {
	    if ((ctxt != NULL) && (ctxt->error != NULL))
		ctxt->error(ctxt->userData, "Out of memory\n");
	    ctxt->nbErrors++;
	    return (NULL);
	}
    } else if (ctxt->defMax <= ctxt->defNr) {
	xmlRelaxNGDefinePtr *tmp;
	ctxt->defMax *= 2;
	tmp = (xmlRelaxNGDefinePtr *) xmlRealloc(ctxt->defTab,
		ctxt->defMax * sizeof(xmlRelaxNGDefinePtr));
	if (tmp == NULL) {
	    if ((ctxt != NULL) && (ctxt->error != NULL))
		ctxt->error(ctxt->userData, "Out of memory\n");
	    ctxt->nbErrors++;
	    return (NULL);
	}
	ctxt->defTab = tmp;
    }
    ret = (xmlRelaxNGDefinePtr) xmlMalloc(sizeof(xmlRelaxNGDefine));
    if (ret == NULL) {
	if ((ctxt != NULL) && (ctxt->error != NULL))
	    ctxt->error(ctxt->userData, "Out of memory\n");
	ctxt->nbErrors++;
	return(NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGDefine));
    ctxt->defTab[ctxt->defNr++] = ret;
    ret->node = node;
    return (ret);
}

/**
 * xmlRelaxNGFreePartition:
 * @partitions:  a partition set structure
 *
 * Deallocate RelaxNG partition set structures.
 */
static void
xmlRelaxNGFreePartition(xmlRelaxNGPartitionPtr partitions) {
    xmlRelaxNGInterleaveGroupPtr group;
    int j;

    if (partitions != NULL) {
	if (partitions->groups != NULL) {
	    for (j = 0;j < partitions->nbgroups;j++) {
		group = partitions->groups[j];
		if (group != NULL) {
		    if (group->defs != NULL)
			xmlFree(group->defs);
		    xmlFree(group);
		}
	    }
	    xmlFree(partitions->groups);
	}
	xmlFree(partitions);
    }
}
/**
 * xmlRelaxNGFreeDefine:
 * @define:  a define structure
 *
 * Deallocate a RelaxNG define structure.
 */
static void
xmlRelaxNGFreeDefine(xmlRelaxNGDefinePtr define)
{
    if (define == NULL)
        return;

    if ((define->data != NULL) &&
	(define->type == XML_RELAXNG_INTERLEAVE))
	xmlRelaxNGFreePartition((xmlRelaxNGPartitionPtr) define->data);
    if (define->name != NULL)
	xmlFree(define->name);
    if (define->ns != NULL)
	xmlFree(define->ns);
    if (define->value != NULL)
	xmlFree(define->value);
    xmlFree(define);
}

/**
 * xmlRelaxNGNewValidState:
 * @ctxt:  a Relax-NG validation context
 * @node:  the current node or NULL for the document
 *
 * Allocate a new RelaxNG validation state
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlRelaxNGValidStatePtr
xmlRelaxNGNewValidState(xmlRelaxNGValidCtxtPtr ctxt, xmlNodePtr node)
{
    xmlRelaxNGValidStatePtr ret;
    xmlAttrPtr attr;
    xmlAttrPtr attrs[MAX_ATTR];
    int nbAttrs = 0;
    xmlNodePtr root = NULL;

    if (node == NULL) {
	root = xmlDocGetRootElement(ctxt->doc);
	if (root == NULL)
	    return(NULL);
    } else {
	attr = node->properties;
	while (attr != NULL) {
	    if (nbAttrs < MAX_ATTR)
		attrs[nbAttrs++] = attr;
	    else
		nbAttrs++;
	    attr = attr->next;
	}
    }
    
    if (nbAttrs < MAX_ATTR)
	attrs[nbAttrs] = NULL;
    ret = (xmlRelaxNGValidStatePtr) xmlMalloc(sizeof(xmlRelaxNGValidState) +
	                                      nbAttrs * sizeof(xmlAttrPtr));
    if (ret == NULL) {
        if ((ctxt != NULL) && (ctxt->error != NULL))
            ctxt->error(ctxt->userData, "Out of memory\n");
        return (NULL);
    }
    ret->value = NULL;
    ret->endvalue = NULL;
    if (node == NULL) {
	ret->node = (xmlNodePtr) ctxt->doc;
	ret->seq = root;
	ret->nbAttrs = 0;
    } else {
	ret->node = node;
	ret->seq = node->children;
	ret->nbAttrs = nbAttrs;
	if (nbAttrs > 0) {
	    if (nbAttrs < MAX_ATTR) {
		memcpy(&(ret->attrs[0]), attrs,
			sizeof(xmlAttrPtr) * (nbAttrs + 1));
	    } else {
		attr = node->properties;
		nbAttrs = 0;
		while (attr != NULL) {
		    ret->attrs[nbAttrs++] = attr;
		    attr = attr->next;
		}
		ret->attrs[nbAttrs] = NULL;
	    }
	}
    }
    ret->nbAttrLeft = ret->nbAttrs;
    return (ret);
}

/**
 * xmlRelaxNGCopyValidState:
 * @ctxt:  a Relax-NG validation context
 * @state:  a validation state
 *
 * Copy the validation state
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlRelaxNGValidStatePtr
xmlRelaxNGCopyValidState(xmlRelaxNGValidCtxtPtr ctxt,
	                 xmlRelaxNGValidStatePtr state)
{
    xmlRelaxNGValidStatePtr ret;
    unsigned int size;

    if (state == NULL)
	return(NULL);
    
    size = sizeof(xmlRelaxNGValidState) +
	   state->nbAttrs * sizeof(xmlAttrPtr);
    ret = (xmlRelaxNGValidStatePtr) xmlMalloc(size);
    if (ret == NULL) {
        if ((ctxt != NULL) && (ctxt->error != NULL))
            ctxt->error(ctxt->userData, "Out of memory\n");
        return (NULL);
    }
    memcpy(ret, state, size);
    return(ret);
}

/**
 * xmlRelaxNGFreeValidState:
 * @state:  a validation state structure
 *
 * Deallocate a RelaxNG validation state structure.
 */
static void
xmlRelaxNGFreeValidState(xmlRelaxNGValidStatePtr state)
{
    if (state == NULL)
        return;

    xmlFree(state);
}

/************************************************************************
 * 									*
 * 			Document functions					*
 * 									*
 ************************************************************************/
static xmlDocPtr xmlRelaxNGCleanupDoc(xmlRelaxNGParserCtxtPtr ctxt,
	                              xmlDocPtr doc);

/**
 * xmlRelaxNGIncludePush:
 * @ctxt:  the parser context
 * @value:  the element doc
 *
 * Pushes a new include on top of the include stack
 *
 * Returns 0 in case of error, the index in the stack otherwise
 */
static int
xmlRelaxNGIncludePush(xmlRelaxNGParserCtxtPtr ctxt,
	               xmlRelaxNGIncludePtr value)
{
    if (ctxt->incTab == NULL) {
	ctxt->incMax = 4;
	ctxt->incNr = 0;
	ctxt->incTab = (xmlRelaxNGIncludePtr *) xmlMalloc(
		        ctxt->incMax * sizeof(ctxt->incTab[0]));
        if (ctxt->incTab == NULL) {
            xmlGenericError(xmlGenericErrorContext, "malloc failed !\n");
            return (0);
        }
    }
    if (ctxt->incNr >= ctxt->incMax) {
        ctxt->incMax *= 2;
        ctxt->incTab =
            (xmlRelaxNGIncludePtr *) xmlRealloc(ctxt->incTab,
                                      ctxt->incMax *
                                      sizeof(ctxt->incTab[0]));
        if (ctxt->incTab == NULL) {
            xmlGenericError(xmlGenericErrorContext, "realloc failed !\n");
            return (0);
        }
    }
    ctxt->incTab[ctxt->incNr] = value;
    ctxt->inc = value;
    return (ctxt->incNr++);
}

/**
 * xmlRelaxNGIncludePop:
 * @ctxt: the parser context
 *
 * Pops the top include from the include stack
 *
 * Returns the include just removed
 */
static xmlRelaxNGIncludePtr
xmlRelaxNGIncludePop(xmlRelaxNGParserCtxtPtr ctxt)
{
    xmlRelaxNGIncludePtr ret;

    if (ctxt->incNr <= 0)
        return (0);
    ctxt->incNr--;
    if (ctxt->incNr > 0)
        ctxt->inc = ctxt->incTab[ctxt->incNr - 1];
    else
        ctxt->inc = NULL;
    ret = ctxt->incTab[ctxt->incNr];
    ctxt->incTab[ctxt->incNr] = 0;
    return (ret);
}

/**
 * xmlRelaxNGLoadInclude:
 * @ctxt: the parser context
 * @URL:  the normalized URL
 * @node: the include node.
 *
 * First lookup if the document is already loaded into the parser context,
 * check against recursion. If not found the resource is loaded and
 * the content is preprocessed before being returned back to the caller.
 *
 * Returns the xmlRelaxNGIncludePtr or NULL in case of error
 */
static xmlRelaxNGIncludePtr
xmlRelaxNGLoadInclude(xmlRelaxNGParserCtxtPtr ctxt, const xmlChar *URL,
	              xmlNodePtr node) {
    xmlRelaxNGIncludePtr ret = NULL;
    xmlDocPtr doc;
    int i;
    xmlNodePtr root, tmp, tmp2, cur;

    /*
     * check against recursion in the stack
     */
    for (i = 0;i < ctxt->incNr;i++) {
	if (xmlStrEqual(ctxt->incTab[i]->href, URL)) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Detected an externalRef recursion for %s\n",
			    URL);
	    ctxt->nbErrors++;
	    return(NULL);
	}
    }

    /*
     * Lookup in the hash table
     */
    if (ctxt->includes == NULL) {
	ctxt->includes = xmlHashCreate(10);
	if (ctxt->includes == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Failed to allocate hash table for document\n");
	    ctxt->nbErrors++;
	    return(NULL);
	}
    } else {
	ret = xmlHashLookup(ctxt->includes, URL);
	if (ret != NULL)
	    return(ret);
    }


    /*
     * load the document
     */
    doc = xmlParseFile((const char *) URL);
    if (doc == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNG: could not load %s\n", URL);
	ctxt->nbErrors++;
	return (NULL);
    }

    /*
     * Allocate the document structures and register it first.
     */
    ret = (xmlRelaxNGIncludePtr) xmlMalloc(sizeof(xmlRelaxNGInclude));
    if (ret == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNG: allocate memory for doc %s\n", URL);
	ctxt->nbErrors++;
	xmlFreeDoc(doc);
	return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGInclude));
    ret->doc = doc;
    ret->href = xmlStrdup(URL);

    /*
     * push it on the stack and register it in the hash table
     */
    xmlHashAddEntry(ctxt->includes, URL, ret);
    xmlRelaxNGIncludePush(ctxt, ret);

    /*
     * Some preprocessing of the document content, this include recursing
     * in the include stack.
     */
    doc = xmlRelaxNGCleanupDoc(ctxt, doc);
    if (doc == NULL) {
	/* xmlFreeDoc(ctxt->include); */
	ctxt->inc = NULL;
	return(NULL);
    }

    /*
     * Pop up the include from the stack
     */
    xmlRelaxNGIncludePop(ctxt);

    /*
     * Check that the top element is a grammar
     */
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNG: included document is empty %s\n", URL);
	ctxt->nbErrors++;
	xmlFreeDoc(doc);
	return (NULL);
    }
    if (!IS_RELAXNG(root, "grammar")) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		    "xmlRelaxNG: included document %s root is not a grammar\n",
		        URL);
	ctxt->nbErrors++;
	xmlFreeDoc(doc);
	return (NULL);
    }

    /*
     * Elimination of redefined rules in the include.
     */
    cur = node->children;
    while (cur != NULL) {
	if (IS_RELAXNG(cur, "start")) {
	    int found = 0;

	    tmp = root->children;
	    while (tmp != NULL) {
		tmp2 = tmp->next;
		if (IS_RELAXNG(tmp, "start")) {
		    found = 1;
		    xmlUnlinkNode(tmp);
		    xmlFreeNode(tmp);
		}
		tmp = tmp2;
	    }
	    if (!found) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
	"xmlRelaxNG: include %s has a start but not the included grammar\n",
				URL);
		ctxt->nbErrors++;
	    }
	} else if (IS_RELAXNG(cur, "define")) {
	    xmlChar *name, *name2;

	    name = xmlGetProp(cur, BAD_CAST "name");
	    if (name == NULL) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			    "xmlRelaxNG: include %s has define without name\n",
				URL);
		ctxt->nbErrors++;
	    } else {
		int found = 0;

		tmp = root->children;
		while (tmp != NULL) {
		    tmp2 = tmp->next;
		    if (IS_RELAXNG(tmp, "define")) {
			name2 = xmlGetProp(tmp, BAD_CAST "name");
			if (name2 != NULL) {
			    if (xmlStrEqual(name, name2)) {
				found = 1;
				xmlUnlinkNode(tmp);
				xmlFreeNode(tmp);
			    }
			    xmlFree(name2);
			}
		    }
		    tmp = tmp2;
		}
		if (!found) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
    "xmlRelaxNG: include %s has a define %s but not the included grammar\n",
				    URL, name);
		    ctxt->nbErrors++;
		}
		xmlFree(name);
	    }
	}
	cur = cur->next;
    }


    return(ret);
}

/**
 * xmlRelaxNGDocumentPush:
 * @ctxt:  the parser context
 * @value:  the element doc
 *
 * Pushes a new doc on top of the doc stack
 *
 * Returns 0 in case of error, the index in the stack otherwise
 */
static int
xmlRelaxNGDocumentPush(xmlRelaxNGParserCtxtPtr ctxt,
	               xmlRelaxNGDocumentPtr value)
{
    if (ctxt->docTab == NULL) {
	ctxt->docMax = 4;
	ctxt->docNr = 0;
	ctxt->docTab = (xmlRelaxNGDocumentPtr *) xmlMalloc(
		        ctxt->docMax * sizeof(ctxt->docTab[0]));
        if (ctxt->docTab == NULL) {
            xmlGenericError(xmlGenericErrorContext, "malloc failed !\n");
            return (0);
        }
    }
    if (ctxt->docNr >= ctxt->docMax) {
        ctxt->docMax *= 2;
        ctxt->docTab =
            (xmlRelaxNGDocumentPtr *) xmlRealloc(ctxt->docTab,
                                      ctxt->docMax *
                                      sizeof(ctxt->docTab[0]));
        if (ctxt->docTab == NULL) {
            xmlGenericError(xmlGenericErrorContext, "realloc failed !\n");
            return (0);
        }
    }
    ctxt->docTab[ctxt->docNr] = value;
    ctxt->doc = value;
    return (ctxt->docNr++);
}

/**
 * xmlRelaxNGDocumentPop:
 * @ctxt: the parser context
 *
 * Pops the top doc from the doc stack
 *
 * Returns the doc just removed
 */
static xmlRelaxNGDocumentPtr
xmlRelaxNGDocumentPop(xmlRelaxNGParserCtxtPtr ctxt)
{
    xmlRelaxNGDocumentPtr ret;

    if (ctxt->docNr <= 0)
        return (0);
    ctxt->docNr--;
    if (ctxt->docNr > 0)
        ctxt->doc = ctxt->docTab[ctxt->docNr - 1];
    else
        ctxt->doc = NULL;
    ret = ctxt->docTab[ctxt->docNr];
    ctxt->docTab[ctxt->docNr] = 0;
    return (ret);
}

/**
 * xmlRelaxNGLoadExternalRef:
 * @ctxt: the parser context
 * @URL:  the normalized URL
 * @ns:  the inherited ns if any
 *
 * First lookup if the document is already loaded into the parser context,
 * check against recursion. If not found the resource is loaded and
 * the content is preprocessed before being returned back to the caller.
 *
 * Returns the xmlRelaxNGDocumentPtr or NULL in case of error
 */
static xmlRelaxNGDocumentPtr
xmlRelaxNGLoadExternalRef(xmlRelaxNGParserCtxtPtr ctxt, const xmlChar *URL,
	               const xmlChar *ns) {
    xmlRelaxNGDocumentPtr ret = NULL;
    xmlDocPtr doc;
    xmlNodePtr root;
    int i;

    /*
     * check against recursion in the stack
     */
    for (i = 0;i < ctxt->docNr;i++) {
	if (xmlStrEqual(ctxt->docTab[i]->href, URL)) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Detected an externalRef recursion for %s\n",
			    URL);
	    ctxt->nbErrors++;
	    return(NULL);
	}
    }

    /*
     * Lookup in the hash table
     */
    if (ctxt->documents == NULL) {
	ctxt->documents = xmlHashCreate(10);
	if (ctxt->documents == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Failed to allocate hash table for document\n");
	    ctxt->nbErrors++;
	    return(NULL);
	}
    } else {
	if (ns == NULL)
	    ret = xmlHashLookup2(ctxt->documents, BAD_CAST "", URL);
	else
	    ret = xmlHashLookup2(ctxt->documents, ns, URL);
	if (ret != NULL)
	    return(ret);
    }


    /*
     * load the document
     */
    doc = xmlParseFile((const char *) URL);
    if (doc == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNG: could not load %s\n", URL);
	ctxt->nbErrors++;
	return (NULL);
    }

    /*
     * Allocate the document structures and register it first.
     */
    ret = (xmlRelaxNGDocumentPtr) xmlMalloc(sizeof(xmlRelaxNGDocument));
    if (ret == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNG: allocate memory for doc %s\n", URL);
	ctxt->nbErrors++;
	xmlFreeDoc(doc);
	return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGDocument));
    ret->doc = doc;
    ret->href = xmlStrdup(URL);

    /*
     * transmit the ns if needed
     */
    if (ns != NULL) {
	root = xmlDocGetRootElement(doc);
	if (root != NULL) {
	    if (xmlHasProp(root, BAD_CAST"ns") == NULL) {
		xmlSetProp(root, BAD_CAST"ns", ns);
	    }
	}
    }

    /*
     * push it on the stack and register it in the hash table
     */
    if (ns == NULL)
	xmlHashAddEntry2(ctxt->documents, BAD_CAST "", URL, ret);
    else
	xmlHashAddEntry2(ctxt->documents, ns, URL, ret);
    xmlRelaxNGDocumentPush(ctxt, ret);

    /*
     * Some preprocessing of the document content
     */
    doc = xmlRelaxNGCleanupDoc(ctxt, doc);
    if (doc == NULL) {
	xmlFreeDoc(ctxt->document);
	ctxt->doc = NULL;
	return(NULL);
    }

    xmlRelaxNGDocumentPop(ctxt);

    return(ret);
}

/************************************************************************
 * 									*
 * 			Error functions					*
 * 									*
 ************************************************************************/

#define VALID_CTXT() 							\
    if (((ctxt->flags & 1) == 0) || (ctxt->flags & 2))			\
         xmlGenericError(xmlGenericErrorContext,			\
	    "error detected at %s:%d\n",				\
            __FILE__, __LINE__);

#define VALID_ERROR(a)							\
    if (((ctxt->flags & 1) == 0) || (ctxt->flags & 2))			\
        if (ctxt->error != NULL) ctxt->error(ctxt->userData, a)
#define VALID_ERROR2(a, b)						\
    if (((ctxt->flags & 1) == 0) || (ctxt->flags & 2))			\
        if (ctxt->error != NULL) ctxt->error(ctxt->userData, a, b)
#define VALID_ERROR3(a, b, c)						\
    if (((ctxt->flags & 1) == 0) || (ctxt->flags & 2))			\
        if (ctxt->error != NULL) ctxt->error(ctxt->userData, a, b, c)

static const char *
xmlRelaxNGDefName(xmlRelaxNGDefinePtr def) {
    if (def == NULL)
	return("none");
    switch(def->type) {
        case XML_RELAXNG_EMPTY: return("empty");
        case XML_RELAXNG_NOT_ALLOWED: return("notAllowed");
        case XML_RELAXNG_EXCEPT: return("except");
        case XML_RELAXNG_TEXT: return("text");
        case XML_RELAXNG_ELEMENT: return("element");
        case XML_RELAXNG_DATATYPE: return("datatype");
        case XML_RELAXNG_VALUE: return("value");
        case XML_RELAXNG_LIST: return("list");
        case XML_RELAXNG_ATTRIBUTE: return("attribute");
        case XML_RELAXNG_DEF: return("def");
        case XML_RELAXNG_REF: return("ref");
        case XML_RELAXNG_EXTERNALREF: return("externalRef");
        case XML_RELAXNG_PARENTREF: return("parentRef");
        case XML_RELAXNG_OPTIONAL: return("optional");
        case XML_RELAXNG_ZEROORMORE: return("zeroOrMore");
        case XML_RELAXNG_ONEORMORE: return("oneOrMore");
        case XML_RELAXNG_CHOICE: return("choice");
        case XML_RELAXNG_GROUP: return("group");
        case XML_RELAXNG_INTERLEAVE: return("interleave");
        case XML_RELAXNG_START: return("start");
    }
    return("unknown");
}
#if 0
/**
 * xmlRelaxNGErrorContext:
 * @ctxt:  the parsing context
 * @schema:  the schema being built
 * @node:  the node being processed
 * @child:  the child being processed
 *
 * Dump a RelaxNGType structure
 */
static void
xmlRelaxNGErrorContext(xmlRelaxNGParserCtxtPtr ctxt, xmlRelaxNGPtr schema,
                      xmlNodePtr node, xmlNodePtr child)
{
    int line = 0;
    const xmlChar *file = NULL;
    const xmlChar *name = NULL;
    const char *type = "error";

    if ((ctxt == NULL) || (ctxt->error == NULL))
	return;

    if (child != NULL)
	node = child;

    if (node != NULL)  {
	if ((node->type == XML_DOCUMENT_NODE) ||
	    (node->type == XML_HTML_DOCUMENT_NODE)) {
	    xmlDocPtr doc = (xmlDocPtr) node;

	    file = doc->URL;
	} else {
	    /*
	     * Try to find contextual informations to report
	     */
	    if (node->type == XML_ELEMENT_NODE) {
		line = (int) node->content;
	    } else if ((node->prev != NULL) &&
		       (node->prev->type == XML_ELEMENT_NODE)) {
		line = (int) node->prev->content;
	    } else if ((node->parent != NULL) &&
		       (node->parent->type == XML_ELEMENT_NODE)) {
		line = (int) node->parent->content;
	    }
	    if ((node->doc != NULL) && (node->doc->URL != NULL))
		file = node->doc->URL;
	    if (node->name != NULL)
		name = node->name;
	}
    } 
    
    if (ctxt != NULL)
	type = "compilation error";
    else if (schema != NULL)
	type = "runtime error";

    if ((file != NULL) && (line != 0) && (name != NULL))
	ctxt->error(ctxt->userData, "%s: file %s line %d element %s\n",
		type, file, line, name);
    else if ((file != NULL) && (name != NULL))
	ctxt->error(ctxt->userData, "%s: file %s element %s\n",
		type, file, name);
    else if ((file != NULL) && (line != 0))
	ctxt->error(ctxt->userData, "%s: file %s line %d\n", type, file, line);
    else if (file != NULL)
	ctxt->error(ctxt->userData, "%s: file %s\n", type, file);
    else if (name != NULL)
	ctxt->error(ctxt->userData, "%s: element %s\n", type, name);
    else
	ctxt->error(ctxt->userData, "%s\n", type);
}
#endif

/************************************************************************
 * 									*
 * 			Type library hooks				*
 * 									*
 ************************************************************************/
static xmlChar *xmlRelaxNGNormalize(xmlRelaxNGValidCtxtPtr ctxt,
	                            const xmlChar *str);

/**
 * xmlRelaxNGSchemaTypeHave:
 * @data:  data needed for the library
 * @type:  the type name
 *
 * Check if the given type is provided by
 * the W3C XMLSchema Datatype library.
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
static int
xmlRelaxNGSchemaTypeHave(void *data ATTRIBUTE_UNUSED,
	                 const xmlChar *type) {
    xmlSchemaTypePtr typ;

    if (type == NULL)
	return(-1);
    typ = xmlSchemaGetPredefinedType(type, 
	       BAD_CAST "http://www.w3.org/2001/XMLSchema");
    if (typ == NULL)
	return(0);
    return(1);
}

/**
 * xmlRelaxNGSchemaTypeCheck:
 * @data:  data needed for the library
 * @type:  the type name
 * @value:  the value to check
 *
 * Check if the given type and value are validated by
 * the W3C XMLSchema Datatype library.
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
static int
xmlRelaxNGSchemaTypeCheck(void *data ATTRIBUTE_UNUSED,
	                  const xmlChar *type,
			  const xmlChar *value) {
    xmlSchemaTypePtr typ;
    int ret;

    /*
     * TODO: the type should be cached ab provided back, interface subject
     * to changes.
     * TODO: handle facets, may require an additional interface and keep
     * the value returned from the validation.
     */
    if ((type == NULL) || (value == NULL))
	return(-1);
    typ = xmlSchemaGetPredefinedType(type, 
	       BAD_CAST "http://www.w3.org/2001/XMLSchema");
    if (typ == NULL)
	return(-1);
    ret = xmlSchemaValidatePredefinedType(typ, value, NULL);
    if (ret == 0)
	return(1);
    if (ret > 0)
	return(0);
    return(-1);
}

/**
 * xmlRelaxNGSchemaTypeCompare:
 * @data:  data needed for the library
 * @type:  the type name
 * @value1:  the first value
 * @value2:  the second value
 *
 * Compare two values accordingly a type from the W3C XMLSchema
 * Datatype library.
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
static int
xmlRelaxNGSchemaTypeCompare(void *data ATTRIBUTE_UNUSED,
	                    const xmlChar *type ATTRIBUTE_UNUSED,
	                    const xmlChar *value1 ATTRIBUTE_UNUSED,
			    const xmlChar *value2 ATTRIBUTE_UNUSED) {
    TODO
    return(1);
}
 
/**
 * xmlRelaxNGDefaultTypeHave:
 * @data:  data needed for the library
 * @type:  the type name
 *
 * Check if the given type is provided by
 * the default datatype library.
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
static int
xmlRelaxNGDefaultTypeHave(void *data ATTRIBUTE_UNUSED, const xmlChar *type) {
    if (type == NULL)
	return(-1);
    if (xmlStrEqual(type, BAD_CAST "string"))
	return(1);
    if (xmlStrEqual(type, BAD_CAST "token"))
	return(1);
    return(0);
}

/**
 * xmlRelaxNGDefaultTypeCheck:
 * @data:  data needed for the library
 * @type:  the type name
 * @value:  the value to check
 *
 * Check if the given type and value are validated by
 * the default datatype library.
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
static int
xmlRelaxNGDefaultTypeCheck(void *data ATTRIBUTE_UNUSED,
	                   const xmlChar *type ATTRIBUTE_UNUSED,
			  const xmlChar *value ATTRIBUTE_UNUSED) {
    return(1);
}

/**
 * xmlRelaxNGDefaultTypeCompare:
 * @data:  data needed for the library
 * @type:  the type name
 * @value1:  the first value
 * @value2:  the second value
 *
 * Compare two values accordingly a type from the default
 * datatype library.
 *
 * Returns 1 if yes, 0 if no and -1 in case of error.
 */
static int
xmlRelaxNGDefaultTypeCompare(void *data ATTRIBUTE_UNUSED,
	                     const xmlChar *type ATTRIBUTE_UNUSED,
	                     const xmlChar *value1 ATTRIBUTE_UNUSED,
			     const xmlChar *value2 ATTRIBUTE_UNUSED) {
    int ret = -1;

    if (xmlStrEqual(type, BAD_CAST "string")) {
	ret = xmlStrEqual(value1, value2);
    } else if (xmlStrEqual(type, BAD_CAST "token")) {
	if (!xmlStrEqual(value1, value2)) {
	    xmlChar *nval, *nvalue;

	    /*
	     * TODO: trivial optimizations are possible by
	     * computing at compile-time
	     */
	    nval = xmlRelaxNGNormalize(NULL, value1);
	    nvalue = xmlRelaxNGNormalize(NULL, value2);

	    if ((nval == NULL) || (nvalue == NULL) ||
		(!xmlStrEqual(nval, nvalue)))
		ret = -1;
	    if (nval != NULL)
		xmlFree(nval);
	    if (nvalue != NULL)
		xmlFree(nvalue);
	}
    }
    return(ret);
}
 
static int xmlRelaxNGTypeInitialized = 0;
static xmlHashTablePtr xmlRelaxNGRegisteredTypes = NULL;

/**
 * xmlRelaxNGFreeTypeLibrary:
 * @lib:  the type library structure
 * @namespace:  the URI bound to the library
 *
 * Free the structure associated to the type library
 */
static void
xmlRelaxNGFreeTypeLibrary(xmlRelaxNGTypeLibraryPtr lib,
	                  const xmlChar *namespace ATTRIBUTE_UNUSED) {
    if (lib == NULL)
	return;
    if (lib->namespace != NULL)
	xmlFree((xmlChar *)lib->namespace);
    xmlFree(lib);
}

/**
 * xmlRelaxNGRegisterTypeLibrary:
 * @namespace:  the URI bound to the library
 * @data:  data associated to the library
 * @have:  the provide function
 * @check:  the checking function
 * @comp:  the comparison function
 *
 * Register a new type library
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xmlRelaxNGRegisterTypeLibrary(const xmlChar *namespace, void *data,
    xmlRelaxNGTypeHave have, xmlRelaxNGTypeCheck check,
    xmlRelaxNGTypeCompare comp) {
    xmlRelaxNGTypeLibraryPtr lib;
    int ret;

    if ((xmlRelaxNGRegisteredTypes == NULL) || (namespace == NULL) ||
	(check == NULL) || (comp == NULL))
	return(-1);
    if (xmlHashLookup(xmlRelaxNGRegisteredTypes, namespace) != NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"Relax-NG types library '%s' already registered\n",
		        namespace);
	return(-1);
    }
    lib = (xmlRelaxNGTypeLibraryPtr) xmlMalloc(sizeof(xmlRelaxNGTypeLibrary));
    if (lib == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"Relax-NG types library '%s' malloc() failed\n",
		        namespace);
        return (-1);
    }
    memset(lib, 0, sizeof(xmlRelaxNGTypeLibrary));
    lib->namespace = xmlStrdup(namespace);
    lib->data = data;
    lib->have = have;
    lib->comp = comp;
    lib->check = check;
    ret = xmlHashAddEntry(xmlRelaxNGRegisteredTypes, namespace, lib);
    if (ret < 0) {
	xmlGenericError(xmlGenericErrorContext,
		"Relax-NG types library failed to register '%s'\n",
		        namespace);
	xmlRelaxNGFreeTypeLibrary(lib, namespace);
	return(-1);
    }
    return(0);
}

/**
 * xmlRelaxNGInitTypes:
 *
 * Initilize the default type libraries.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xmlRelaxNGInitTypes(void) {
    if (xmlRelaxNGTypeInitialized != 0)
	return(0);
    xmlRelaxNGRegisteredTypes = xmlHashCreate(10);
    if (xmlRelaxNGRegisteredTypes == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"Failed to allocate sh table for Relax-NG types\n");
	return(-1);
    }
    xmlRelaxNGRegisterTypeLibrary(
	    BAD_CAST "http://www.w3.org/2001/XMLSchema-datatypes",
	    NULL,
	    xmlRelaxNGSchemaTypeHave,
	    xmlRelaxNGSchemaTypeCheck,
	    xmlRelaxNGSchemaTypeCompare);
    xmlRelaxNGRegisterTypeLibrary(
	    xmlRelaxNGNs,
	    NULL,
	    xmlRelaxNGDefaultTypeHave,
	    xmlRelaxNGDefaultTypeCheck,
	    xmlRelaxNGDefaultTypeCompare);
    xmlRelaxNGTypeInitialized = 1;
    return(0);
}

/**
 * xmlRelaxNGCleanupTypes:
 *
 * Cleanup the default Schemas type library associated to RelaxNG
 */
void	
xmlRelaxNGCleanupTypes(void) {
    if (xmlRelaxNGTypeInitialized == 0)
	return;
    xmlSchemaCleanupTypes();
    xmlHashFree(xmlRelaxNGRegisteredTypes, (xmlHashDeallocator)
	        xmlRelaxNGFreeTypeLibrary);
    xmlRelaxNGTypeInitialized = 0;
}

/************************************************************************
 * 									*
 * 			Parsing functions				*
 * 									*
 ************************************************************************/

static xmlRelaxNGDefinePtr xmlRelaxNGParseAttribute(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
static xmlRelaxNGDefinePtr xmlRelaxNGParseElement(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
static xmlRelaxNGDefinePtr xmlRelaxNGParsePatterns(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes, int group);
static xmlRelaxNGDefinePtr xmlRelaxNGParsePattern(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
static xmlRelaxNGPtr xmlRelaxNGParseDocument(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
static int xmlRelaxNGParseGrammarContent(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes);
static xmlRelaxNGDefinePtr xmlRelaxNGParseNameClass(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node,
	      xmlRelaxNGDefinePtr def);
static xmlRelaxNGGrammarPtr xmlRelaxNGParseGrammar(
	      xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes);


#define IS_BLANK_NODE(n)						\
    (((n)->type == XML_TEXT_NODE) && (xmlRelaxNGIsBlank((n)->content)))

/**
 * xmlRelaxNGIsBlank:
 * @str:  a string
 *
 * Check if a string is ignorable c.f. 4.2. Whitespace
 *
 * Returns 1 if the string is NULL or made of blanks chars, 0 otherwise
 */
static int
xmlRelaxNGIsBlank(xmlChar *str) {
    if (str == NULL)
	return(1);
    while (*str != 0) {
	if (!(IS_BLANK(*str))) return(0);
	str++;
    }
    return(1);
}

/**
 * xmlRelaxNGGetDataTypeLibrary:
 * @ctxt:  a Relax-NG parser context
 * @node:  the current data or value element
 *
 * Applies algorithm from 4.3. datatypeLibrary attribute
 *
 * Returns the datatypeLibary value or NULL if not found
 */
static xmlChar *
xmlRelaxNGGetDataTypeLibrary(xmlRelaxNGParserCtxtPtr ctxt ATTRIBUTE_UNUSED,
	                     xmlNodePtr node) {
    xmlChar *ret, *escape;

    if ((IS_RELAXNG(node, "data")) || (IS_RELAXNG(node, "value"))) {
	ret = xmlGetProp(node, BAD_CAST "datatypeLibrary");
	if (ret != NULL) {
	    escape = xmlURIEscapeStr(ret, BAD_CAST ":/#?");
	    if (escape == NULL) {
		return(ret);
	    }
	    xmlFree(ret);
	    return(escape);
	}
    }
    node = node->parent;
    while ((node != NULL) && (node->type == XML_ELEMENT_NODE)) {
	ret = xmlGetProp(node, BAD_CAST "datatypeLibrary");
	if (ret != NULL) {
	    escape = xmlURIEscapeStr(ret, BAD_CAST ":/#?");
	    if (escape == NULL) {
		return(ret);
	    }
	    xmlFree(ret);
	    return(escape);
	}
	node = node->parent;
    }
    return(NULL);
}

/**
 * xmlRelaxNGParseValue:
 * @ctxt:  a Relax-NG parser context
 * @node:  the data node.
 *
 * parse the content of a RelaxNG value node.
 *
 * Returns the definition pointer or NULL in case of error
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParseValue(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGDefinePtr def = NULL;
    xmlRelaxNGTypeLibraryPtr lib;
    xmlChar *type;
    xmlChar *library;
    int tmp;

    def = xmlRelaxNGNewDefine(ctxt, node);
    if (def == NULL)
	return(NULL);
    def->type = XML_RELAXNG_VALUE;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type != NULL) {
	library = xmlRelaxNGGetDataTypeLibrary(ctxt, node);
	if (library == NULL)
	    library = xmlStrdup(BAD_CAST "http://relaxng.org/ns/structure/1.0");

	def->name = type;
	def->ns = library;

	lib = (xmlRelaxNGTypeLibraryPtr)
	    xmlHashLookup(xmlRelaxNGRegisteredTypes, library);
	if (lib == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Use of unregistered type library '%s'\n",
			    library);
	    ctxt->nbErrors++;
	    def->data = NULL;
	} else {
	    def->data = lib;
	    if (lib->have == NULL) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "Internal error with type library '%s': no 'have'\n",
			    library);
		ctxt->nbErrors++;
	    } else {
		tmp = lib->have(lib->data, def->name);
		if (tmp != 1) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		    "Error type '%s' is not exported by type library '%s'\n",
				def->name, library);
		    ctxt->nbErrors++;
		}
	    }
	}
    }
    if (node->children == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"Element <value> has no content\n");
	ctxt->nbErrors++;
    } else if ((node->children->type != XML_TEXT_NODE) ||
	       (node->children->next != NULL)) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Expecting a single text value for <value>content\n");
	ctxt->nbErrors++;
    } else {
	def->value = xmlNodeGetContent(node);
	if (def->value == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Element <value> has no content\n");
	    ctxt->nbErrors++;
	}
    }
    /* TODO check ahead of time that the value is okay per the type */
    return(def);
}

/**
 * xmlRelaxNGParseData:
 * @ctxt:  a Relax-NG parser context
 * @node:  the data node.
 *
 * parse the content of a RelaxNG data node.
 *
 * Returns the definition pointer or NULL in case of error
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParseData(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGDefinePtr def = NULL;
    xmlRelaxNGTypeLibraryPtr lib;
    xmlChar *type;
    xmlChar *library;
    xmlNodePtr content;
    int tmp;

    type = xmlGetProp(node, BAD_CAST "type");
    if (type == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"data has no type\n");
	ctxt->nbErrors++;
	return(NULL);
    }
    library = xmlRelaxNGGetDataTypeLibrary(ctxt, node);
    if (library == NULL)
	library = xmlStrdup(BAD_CAST "http://relaxng.org/ns/structure/1.0");

    def = xmlRelaxNGNewDefine(ctxt, node);
    if (def == NULL) {
	xmlFree(type);
	return(NULL);
    }
    def->type = XML_RELAXNG_DATATYPE;
    def->name = type;
    def->ns = library;

    lib = (xmlRelaxNGTypeLibraryPtr)
	xmlHashLookup(xmlRelaxNGRegisteredTypes, library);
    if (lib == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Use of unregistered type library '%s'\n",
		        library);
	ctxt->nbErrors++;
	def->data = NULL;
    } else {
	def->data = lib;
	if (lib->have == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		"Internal error with type library '%s': no 'have'\n",
		        library);
	    ctxt->nbErrors++;
	} else {
	    tmp = lib->have(lib->data, def->name);
	    if (tmp != 1) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "Error type '%s' is not exported by type library '%s'\n",
			    def->name, library);
		ctxt->nbErrors++;
	    }
	}
    }
    content = node->children;
    while (content != NULL) {
	TODO
	ctxt->nbErrors++;
	content = content->next;
    }

    return(def);
}

/**
 * xmlRelaxNGCompareElemDefLists:
 * @ctxt:  a Relax-NG parser context
 * @defs1:  the first list of element defs
 * @defs2:  the second list of element defs
 *
 * Compare the 2 lists of element definitions. The comparison is
 * that if both lists do not accept the same QNames, it returns 1
 * If the 2 lists can accept the same QName the comparison returns 0
 *
 * Returns 1 disttinct, 0 if equal
 */
static int
xmlRelaxNGCompareElemDefLists(xmlRelaxNGParserCtxtPtr ctxt ATTRIBUTE_UNUSED,
	              xmlRelaxNGDefinePtr *def1,
		      xmlRelaxNGDefinePtr *def2) {
    xmlRelaxNGDefinePtr *basedef2 = def2;
    
    if ((def1 == NULL) || (def2 == NULL))
	return(1);
    if ((*def1 == NULL) || (*def2 == NULL))
	return(1);
    while (*def1 != NULL) {
	while ((*def2) != NULL) {
	    if ((*def1)->name == NULL) {
		if (xmlStrEqual((*def2)->ns, (*def1)->ns))
		    return(0);
	    } else if ((*def2)->name == NULL) {
		if (xmlStrEqual((*def2)->ns, (*def1)->ns))
		    return(0);
	    } else if (xmlStrEqual((*def1)->name, (*def2)->name)) {
		if (xmlStrEqual((*def2)->ns, (*def1)->ns))
		    return(0);
	    }
	    def2++;
	}
	def2 = basedef2;
	def1++;
    }
    return(1);
}

/**
 * xmlRelaxNGGetElements:
 * @ctxt:  a Relax-NG parser context
 * @def:  the interleave definition
 *
 * Compute the list of top elements a definition can generate
 *
 * Returns a list of elements or NULL if none was found.
 */
static xmlRelaxNGDefinePtr *
xmlRelaxNGGetElements(xmlRelaxNGParserCtxtPtr ctxt,
	              xmlRelaxNGDefinePtr def) {
    xmlRelaxNGDefinePtr *ret = NULL, parent, cur, tmp;
    int len = 0;
    int max = 0;

    parent = NULL;
    cur = def;
    while (cur != NULL) {
	if ((cur->type == XML_RELAXNG_ELEMENT) ||
	    (cur->type == XML_RELAXNG_TEXT)) {
	    if (ret == NULL) {
		max = 10;
		ret = (xmlRelaxNGDefinePtr *)
		    xmlMalloc((max + 1) * sizeof(xmlRelaxNGDefinePtr));
		if (ret == NULL) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
			    "Out of memory in element search\n");
		    ctxt->nbErrors++;
		    return(NULL);
		}
	    } else if (max <= len) {
		max *= 2;
		ret = xmlRealloc(ret, (max + 1) * sizeof(xmlRelaxNGDefinePtr));
		if (ret == NULL) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
			    "Out of memory in element search\n");
		    ctxt->nbErrors++;
		    return(NULL);
		}
	    }
	    ret[len++] = cur;
	    ret[len] = NULL;
	} else if ((cur->type == XML_RELAXNG_CHOICE) ||
		   (cur->type == XML_RELAXNG_INTERLEAVE) ||
		   (cur->type == XML_RELAXNG_GROUP) ||
		   (cur->type == XML_RELAXNG_ONEORMORE) ||
		   (cur->type == XML_RELAXNG_ZEROORMORE) ||
		   (cur->type == XML_RELAXNG_OPTIONAL) ||
		   (cur->type == XML_RELAXNG_REF) ||
		   (cur->type == XML_RELAXNG_DEF)) {
	    /*
	     * Don't go within elements or attributes or string values.
	     * Just gather the element top list
	     */
	    if (cur->content != NULL) {
		parent = cur;
		cur = cur->content;
		tmp = cur;
		while (tmp != NULL) {
		    tmp->parent = parent;
		    tmp = tmp->next;
		}
		continue;
	    }
	}
	if (cur == def)
	    return(ret);
	if (cur->next != NULL) {
	    cur = cur->next;
	    continue;
	}
	do {
	    cur = cur->parent;
	    if (cur == NULL) break;
	    if (cur == def) return(ret);
	    if (cur->next != NULL) {
		cur = cur->next;
		break;
	    }
	} while (cur != NULL);
    }
    return(ret);
}
	                     
/**
 * xmlRelaxNGComputeInterleaves:
 * @def:  the interleave definition
 * @ctxt:  a Relax-NG parser context
 * @node:  the data node.
 *
 * A lot of work for preprocessing interleave definitions
 * is potentially needed to get a decent execution speed at runtime
 *   - trying to get a total order on the element nodes generated
 *     by the interleaves, order the list of interleave definitions
 *     following that order.
 *   - if <text/> is used to handle mixed content, it is better to
 *     flag this in the define and simplify the runtime checking
 *     algorithm
 */
static void
xmlRelaxNGComputeInterleaves(xmlRelaxNGDefinePtr def,
	                     xmlRelaxNGParserCtxtPtr ctxt,
			     xmlChar *name ATTRIBUTE_UNUSED) {
    xmlRelaxNGDefinePtr cur;

    xmlRelaxNGDefinePtr *list = NULL;
    xmlRelaxNGPartitionPtr partitions = NULL;
    xmlRelaxNGInterleaveGroupPtr *groups = NULL;
    xmlRelaxNGInterleaveGroupPtr group;
    int i,j,ret;
    int nbgroups = 0;
    int nbchild = 0;

#ifdef DEBUG_INTERLEAVE
    xmlGenericError(xmlGenericErrorContext,
		    "xmlRelaxNGComputeInterleaves(%s)\n",
		    name);
#endif
    cur = def->content;
    while (cur != NULL) {
	nbchild++;
	cur = cur->next;
    }
    
#ifdef DEBUG_INTERLEAVE
    xmlGenericError(xmlGenericErrorContext, "  %d child\n", nbchild);
#endif
    groups = (xmlRelaxNGInterleaveGroupPtr *)
	xmlMalloc(nbchild * sizeof(xmlRelaxNGInterleaveGroupPtr));
    if (groups == NULL)
	goto error;
    cur = def->content;
    while (cur != NULL) {
	groups[nbgroups] = (xmlRelaxNGInterleaveGroupPtr)
	    xmlMalloc(sizeof(xmlRelaxNGInterleaveGroup));
	if (groups[nbgroups] == NULL)
	    goto error;
	groups[nbgroups]->rule = cur;
	groups[nbgroups]->defs = xmlRelaxNGGetElements(ctxt, cur);
	nbgroups++;
	cur = cur->next;
    }
    list = NULL;
#ifdef DEBUG_INTERLEAVE
    xmlGenericError(xmlGenericErrorContext, "  %d groups\n", nbgroups);
#endif

    /*
     * Let's check that all rules makes a partitions according to 7.4
     */
    partitions = (xmlRelaxNGPartitionPtr)
		xmlMalloc(sizeof(xmlRelaxNGPartition));
    if (partitions == NULL)
        goto error;
    partitions->nbgroups = nbgroups;
    for (i = 0;i < nbgroups;i++) {
	group = groups[i];
	for (j = i+1;j < nbgroups;j++) {
	    if (groups[j] == NULL)
		continue;
	    ret = xmlRelaxNGCompareElemDefLists(ctxt, group->defs,
						groups[j]->defs);
	    if (ret == 0) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Element or text conflicts in interleave\n");
		ctxt->nbErrors++;
	    }
	}
    }
    partitions->groups = groups;

    /*
     * Free Up the child list, and save the partition list back in the def
     */
    def->data = partitions;
    return;

error:
    if (ctxt->error != NULL)
	ctxt->error(ctxt->userData,
	    "Out of memory in interleave computation\n");
    ctxt->nbErrors++;
    if (list == NULL)
	xmlFree(list);
    if (groups != NULL) {
	for (i = 0;i < nbgroups;i++)
	    if (groups[i] != NULL) {
		if (groups[i]->defs != NULL)
		    xmlFree(groups[i]->defs);
		xmlFree(groups[i]);
	    }
	xmlFree(groups);
    }
    xmlRelaxNGFreePartition(partitions);
}

/**
 * xmlRelaxNGParseInterleave:
 * @ctxt:  a Relax-NG parser context
 * @node:  the data node.
 *
 * parse the content of a RelaxNG interleave node.
 *
 * Returns the definition pointer or NULL in case of error
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParseInterleave(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGDefinePtr def = NULL;
    xmlRelaxNGDefinePtr last = NULL, cur;
    xmlNodePtr child;

    def = xmlRelaxNGNewDefine(ctxt, node);
    if (def == NULL) {
	return(NULL);
    }
    def->type = XML_RELAXNG_INTERLEAVE;

    if (ctxt->interleaves == NULL)
	ctxt->interleaves = xmlHashCreate(10);
    if (ctxt->interleaves == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Failed to create interleaves hash table\n");
	ctxt->nbErrors++;
    } else {
	char name[32];

	snprintf(name, 32, "interleave%d", ctxt->nbInterleaves++);
	if (xmlHashAddEntry(ctxt->interleaves, BAD_CAST name, def) < 0) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Failed to add %s to hash table\n", name);
	    ctxt->nbErrors++;
	}
    }
    child = node->children;
    while (child != NULL) {
	if (IS_RELAXNG(child, "element")) {
	    cur = xmlRelaxNGParseElement(ctxt, child);
	} else {
	    cur = xmlRelaxNGParsePattern(ctxt, child);
	}
	if (cur != NULL) {
	    cur->parent = def;
	    if (last == NULL) {
		def->content = last = cur;
	    } else {
		last->next = cur;
		last = cur;
	    }
	}
	child = child->next;
    }

    return(def);
}

/**
 * xmlRelaxNGParseInclude:
 * @ctxt:  a Relax-NG parser context
 * @node:  the include node
 *
 * Integrate the content of an include node in the current grammar
 *
 * Returns 0 in case of success or -1 in case of error
 */
static int
xmlRelaxNGParseInclude(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGIncludePtr incl;
    xmlNodePtr root;
    int ret = 0, tmp;

    incl = node->_private;
    if (incl == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Include node has no data\n");
	ctxt->nbErrors++;
	return(-1);
    }
    root = xmlDocGetRootElement(incl->doc);
    if (root == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Include document is empty\n");
	ctxt->nbErrors++;
	return(-1);
    }
    if (!xmlStrEqual(root->name, BAD_CAST "grammar")) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Include document root is not a grammar\n");
	ctxt->nbErrors++;
	return(-1);
    }

    /*
     * Merge the definition from both the include and the internal list
     */
    if (root->children != NULL) {
	tmp = xmlRelaxNGParseGrammarContent(ctxt, root->children);
	if (tmp != 0)
	    ret = -1;
    }
    if (node->children != NULL) {
	tmp = xmlRelaxNGParseGrammarContent(ctxt, node->children);
	if (tmp != 0)
	    ret = -1;
    }
    return(ret);
}

/**
 * xmlRelaxNGParseDefine:
 * @ctxt:  a Relax-NG parser context
 * @node:  the define node
 *
 * parse the content of a RelaxNG define element node.
 *
 * Returns 0 in case of success or -1 in case of error
 */
static int
xmlRelaxNGParseDefine(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlChar *name;
    int ret = 0, tmp;
    xmlRelaxNGDefinePtr def;
    const xmlChar *olddefine;

    name = xmlGetProp(node, BAD_CAST "name");
    if (name == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"define has no name\n");
	ctxt->nbErrors++;
    } else {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL) {
	    xmlFree(name);
	    return(-1);
	}
	def->type = XML_RELAXNG_DEF;
	def->name = name;
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "define has no children\n");
	    ctxt->nbErrors++;
	} else {
	    olddefine = ctxt->define;
	    ctxt->define = name;
	    def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 0);
	    ctxt->define = olddefine;
	}
	if (ctxt->grammar->defs == NULL)
	    ctxt->grammar->defs = xmlHashCreate(10);
	if (ctxt->grammar->defs == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Could not create definition hash\n");
	    ctxt->nbErrors++;
	    ret = -1;
	} else {
	    tmp = xmlHashAddEntry(ctxt->grammar->defs, name, def);
	    if (tmp < 0) {
		xmlRelaxNGDefinePtr prev;

		prev = xmlHashLookup(ctxt->grammar->defs, name);
		if (prev == NULL) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
			    "Internal error on define aggregation of %s\n",
			            name);
		    ctxt->nbErrors++;
		    ret = -1;
		} else {
		    while (prev->nextHash != NULL)
			prev = prev->nextHash;
		    prev->nextHash = def;
		}
	    }
	}
    }
    return(ret);
}

/**
 * xmlRelaxNGParsePattern:
 * @ctxt:  a Relax-NG parser context
 * @node:  the pattern node.
 *
 * parse the content of a RelaxNG pattern node.
 *
 * Returns the definition pointer or NULL in case of error or if no
 *     pattern is generated.
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParsePattern(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGDefinePtr def = NULL;

    if (IS_RELAXNG(node, "element")) {
	def = xmlRelaxNGParseElement(ctxt, node);
    } else if (IS_RELAXNG(node, "attribute")) {
	def = xmlRelaxNGParseAttribute(ctxt, node);
    } else if (IS_RELAXNG(node, "empty")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_EMPTY;
    } else if (IS_RELAXNG(node, "text")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_TEXT;
	if (node->children != NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData, "text: had a child node\n");
	    ctxt->nbErrors++;
	}
    } else if (IS_RELAXNG(node, "zeroOrMore")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_ZEROORMORE;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 1);
    } else if (IS_RELAXNG(node, "oneOrMore")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_ONEORMORE;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 1);
    } else if (IS_RELAXNG(node, "optional")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_OPTIONAL;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 1);
    } else if (IS_RELAXNG(node, "choice")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_CHOICE;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 0);
    } else if (IS_RELAXNG(node, "group")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_GROUP;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 0);
    } else if (IS_RELAXNG(node, "ref")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_REF;
	def->name = xmlGetProp(node, BAD_CAST "name");
	if (def->name == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "ref has no name\n");
	    ctxt->nbErrors++;
	} else {
	    if ((ctxt->define != NULL) &&
	        (xmlStrEqual(ctxt->define, def->name))) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Recursive reference to %s not in an element\n",
			        def->name);
		ctxt->nbErrors++;
	    }
	}
	if (node->children != NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "ref is not empty\n");
	    ctxt->nbErrors++;
	}
	if (ctxt->grammar->refs == NULL)
	    ctxt->grammar->refs = xmlHashCreate(10);
	if (ctxt->grammar->refs == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Could not create references hash\n");
	    ctxt->nbErrors++;
	    def = NULL;
	} else {
	    int tmp;

	    tmp = xmlHashAddEntry(ctxt->grammar->refs, def->name, def);
	    if (tmp < 0) {
		xmlRelaxNGDefinePtr prev;

		prev = (xmlRelaxNGDefinePtr)
		      xmlHashLookup(ctxt->grammar->refs, def->name);
		if (prev == NULL) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
			    "Internal error refs definitions '%s'\n",
				    def->name);
		    ctxt->nbErrors++;
		    def = NULL;
		} else {
		    def->nextHash = prev->nextHash;
		    prev->nextHash = def;
		}
	    }
	}
    } else if (IS_RELAXNG(node, "data")) {
	def = xmlRelaxNGParseData(ctxt, node);
    } else if (IS_RELAXNG(node, "define")) {
	xmlRelaxNGParseDefine(ctxt, node);
	def = NULL;
    } else if (IS_RELAXNG(node, "value")) {
	def = xmlRelaxNGParseValue(ctxt, node);
    } else if (IS_RELAXNG(node, "list")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_LIST;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 0);
    } else if (IS_RELAXNG(node, "interleave")) {
	def = xmlRelaxNGParseInterleave(ctxt, node);
    } else if (IS_RELAXNG(node, "externalRef")) {
	xmlRelaxNGDocumentPtr docu;
	xmlNodePtr root;

	docu = node->_private;
	if (docu != NULL) {
	    def = xmlRelaxNGNewDefine(ctxt, node);
	    if (def == NULL)
		return(NULL);
	    def->type = XML_RELAXNG_EXTERNALREF;
	    
	    if (docu->content == NULL) {
		/*
		 * Then do the parsing for good
		 */
		root = xmlDocGetRootElement(docu->doc);
		if (root == NULL) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
				"xmlRelaxNGParse: %s is empty\n",
				    ctxt->URL);
		    ctxt->nbErrors++;
		    return (NULL);
		}
		docu->schema = xmlRelaxNGParseDocument(ctxt, root);
		if ((docu->schema != NULL) &&
		    (docu->schema->topgrammar != NULL)) {
		    docu->content = docu->schema->topgrammar->start;
		}
	    }
	    def->content = docu->content;
	} else {
	    def = NULL;
	}
    } else if (IS_RELAXNG(node, "notAllowed")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_NOT_ALLOWED;
	if (node->children != NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			"xmlRelaxNGParse: notAllowed element is not empty\n");
	    ctxt->nbErrors++;
	}
    } else if (IS_RELAXNG(node, "grammar")) {
	xmlRelaxNGGrammarPtr grammar, old;
	xmlRelaxNGGrammarPtr oldparent;

	oldparent = ctxt->parentgrammar;
	old = ctxt->grammar;
	ctxt->parentgrammar = old;
	grammar = xmlRelaxNGParseGrammar(ctxt, node->children);
	if (old != NULL) {
	    ctxt->grammar = old;
	    ctxt->parentgrammar = oldparent;
	    if (grammar != NULL) {
		grammar->next = old->next;
		old->next = grammar;
	    }
	}
	if (grammar != NULL)
	    def = grammar->start;
	else
	    def = NULL;
    } else if (IS_RELAXNG(node, "parentRef")) {
	if (ctxt->parentgrammar == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			"Use of parentRef without a parent grammar\n");
	    ctxt->nbErrors++;
	    return(NULL);
	}
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_PARENTREF;
	def->name = xmlGetProp(node, BAD_CAST "name");
	if (def->name == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "parentRef has no name\n");
	    ctxt->nbErrors++;
	}
	if (node->children != NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "parentRef is not empty\n");
	    ctxt->nbErrors++;
	}
	if (ctxt->parentgrammar->refs == NULL)
	    ctxt->parentgrammar->refs = xmlHashCreate(10);
	if (ctxt->parentgrammar->refs == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Could not create references hash\n");
	    ctxt->nbErrors++;
	    def = NULL;
	} else {
	    int tmp;

	    tmp = xmlHashAddEntry(ctxt->parentgrammar->refs, def->name, def);
	    if (tmp < 0) {
		xmlRelaxNGDefinePtr prev;

		prev = (xmlRelaxNGDefinePtr)
		      xmlHashLookup(ctxt->parentgrammar->refs, def->name);
		if (prev == NULL) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
			    "Internal error parentRef definitions '%s'\n",
				    def->name);
		    ctxt->nbErrors++;
		    def = NULL;
		} else {
		    def->nextHash = prev->nextHash;
		    prev->nextHash = def;
		}
	    }
	}
    } else {
	TODO
	ctxt->nbErrors++;
	def = NULL;
    }
    return(def);
}

/**
 * xmlRelaxNGParseAttribute:
 * @ctxt:  a Relax-NG parser context
 * @node:  the element node
 *
 * parse the content of a RelaxNG attribute node.
 *
 * Returns the definition pointer or NULL in case of error.
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParseAttribute(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGDefinePtr ret, cur, last;
    xmlNodePtr child;
    int old_flags;

    ret = xmlRelaxNGNewDefine(ctxt, node);
    if (ret == NULL)
	return(NULL);
    ret->type = XML_RELAXNG_ATTRIBUTE;
    ret->parent = ctxt->def;
    child = node->children;
    if (child == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		    "xmlRelaxNGParseattribute: attribute has no children\n");
	ctxt->nbErrors++;
	return(ret);
    } 
    old_flags = ctxt->flags;
    ctxt->flags |= XML_RELAXNG_IN_ATTRIBUTE;
    cur = xmlRelaxNGParseNameClass(ctxt, child, ret);
    if (cur != NULL)
	child = child->next;

    last = NULL;
    while (child != NULL) {
	cur = xmlRelaxNGParsePattern(ctxt, child);
	if (cur != NULL) {
	    cur->parent = ret;
	    switch (cur->type) {
		case XML_RELAXNG_EMPTY:
		case XML_RELAXNG_NOT_ALLOWED:
		case XML_RELAXNG_TEXT:
		case XML_RELAXNG_ELEMENT:
		case XML_RELAXNG_DATATYPE:
		case XML_RELAXNG_VALUE:
		case XML_RELAXNG_LIST:
		case XML_RELAXNG_REF:
		case XML_RELAXNG_PARENTREF:
		case XML_RELAXNG_EXTERNALREF:
		case XML_RELAXNG_DEF:
		case XML_RELAXNG_ONEORMORE:
		case XML_RELAXNG_ZEROORMORE:
		case XML_RELAXNG_OPTIONAL:
		case XML_RELAXNG_CHOICE:
		case XML_RELAXNG_GROUP:
		case XML_RELAXNG_INTERLEAVE:
		    if (last == NULL) {
			ret->content = last = cur;
		    } else {
			if ((last->type == XML_RELAXNG_ELEMENT) &&
			    (ret->content == last)) {
			    ret->content = xmlRelaxNGNewDefine(ctxt, node);
			    if (ret->content != NULL) {
				ret->content->type = XML_RELAXNG_GROUP;
				ret->content->content = last;
			    } else {
				ret->content = last;
			    }
			}
			last->next = cur;
			last = cur;
		    }
		    cur->parent = ret;
		    break;
		case XML_RELAXNG_ATTRIBUTE:
		    cur->next = ret->attrs;
		    ret->attrs = cur;
		    break;
		case XML_RELAXNG_START:
		case XML_RELAXNG_EXCEPT:
		    TODO
		    ctxt->nbErrors++;
		    break;
	    }
	}
	child = child->next;
    }
    ctxt->flags = old_flags;
    return(ret);
}

/**
 * xmlRelaxNGParseExceptNameClass:
 * @ctxt:  a Relax-NG parser context
 * @node:  the except node
 * @attr:  1 if within an attribute, 0 if within an element
 *
 * parse the content of a RelaxNG nameClass node.
 *
 * Returns the definition pointer or NULL in case of error.
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParseExceptNameClass(xmlRelaxNGParserCtxtPtr ctxt,
	                       xmlNodePtr node, int attr) {
    xmlRelaxNGDefinePtr ret, cur, last = NULL;
    xmlNodePtr child;

    if (!IS_RELAXNG(node, "except"))
	return(NULL);
    if (node->children == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"except has no content\n");
	ctxt->nbErrors++;
	return(NULL);
    }

    ret = xmlRelaxNGNewDefine(ctxt, node);
    if (ret == NULL)
	return(NULL);
    ret->type = XML_RELAXNG_EXCEPT;
    child = node->children;
    while (child != NULL) {
	cur = xmlRelaxNGNewDefine(ctxt, child);
	if (cur == NULL)
	    break;
	if (attr)
	    cur->type = XML_RELAXNG_ATTRIBUTE;
	else
	    cur->type = XML_RELAXNG_ELEMENT;
	
        if (xmlRelaxNGParseNameClass(ctxt, child, cur) != NULL) {
	    if (last == NULL) {
		ret->content = cur;
	    } else {
		last->next = cur;
	    }
	    last = cur;
	}
	child = child->next;
    }

    return(ret);
}

/**
 * xmlRelaxNGParseNameClass:
 * @ctxt:  a Relax-NG parser context
 * @node:  the nameClass node
 * @def:  the current definition
 *
 * parse the content of a RelaxNG nameClass node.
 *
 * Returns the definition pointer or NULL in case of error.
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParseNameClass(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node,
	                 xmlRelaxNGDefinePtr def) {
    xmlRelaxNGDefinePtr ret = def;
    xmlChar *val;

    if (IS_RELAXNG(node, "name")) {
	val = xmlNodeGetContent(node);
	ret->name = val;
	val = xmlGetProp(node, BAD_CAST "ns");
	ret->ns = val;
    } else if (IS_RELAXNG(node, "anyName")) {
	ret->name = NULL;
	ret->ns = NULL;
	if (node->children != NULL) {
	    ret->nameClass =
		xmlRelaxNGParseExceptNameClass(ctxt, node->children,
			       (def->type == XML_RELAXNG_ATTRIBUTE));
	}
    } else if (IS_RELAXNG(node, "nsName")) {
	ret->name = NULL;
	ret->ns = xmlGetProp(node, BAD_CAST "ns");
	if (ret->ns == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "nsName has no ns attribute\n");
	    ctxt->nbErrors++;
	}
	if (node->children != NULL) {
	    ret->nameClass =
		xmlRelaxNGParseExceptNameClass(ctxt, node->children,
			       (def->type == XML_RELAXNG_ATTRIBUTE));
	}
    } else if (IS_RELAXNG(node, "choice")) {
	TODO
	ctxt->nbErrors++;
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
    "expecting name, anyName, nsName or choice : got %s\n",
			node->name);
	ctxt->nbErrors++;
	return(NULL);
    }
    return(ret);
}

/**
 * xmlRelaxNGParseElement:
 * @ctxt:  a Relax-NG parser context
 * @node:  the element node
 *
 * parse the content of a RelaxNG element node.
 *
 * Returns the definition pointer or NULL in case of error.
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParseElement(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGDefinePtr ret, cur, last;
    xmlNodePtr child;
    const xmlChar *olddefine;

    ret = xmlRelaxNGNewDefine(ctxt, node);
    if (ret == NULL)
	return(NULL);
    ret->type = XML_RELAXNG_ELEMENT;
    ret->parent = ctxt->def;
    child = node->children;
    if (child == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNGParseElement: element has no children\n");
	ctxt->nbErrors++;
	return(ret);
    } 
    cur = xmlRelaxNGParseNameClass(ctxt, child, ret);
    if (cur != NULL)
	child = child->next;

    if (child == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNGParseElement: element has no content\n");
	ctxt->nbErrors++;
	return(ret);
    } 
    olddefine = ctxt->define;
    ctxt->define = NULL;
    last = NULL;
    while (child != NULL) {
	cur = xmlRelaxNGParsePattern(ctxt, child);
	if (cur != NULL) {
	    cur->parent = ret;
	    switch (cur->type) {
		case XML_RELAXNG_EMPTY:
		case XML_RELAXNG_NOT_ALLOWED:
		case XML_RELAXNG_TEXT:
		case XML_RELAXNG_ELEMENT:
		case XML_RELAXNG_DATATYPE:
		case XML_RELAXNG_VALUE:
		case XML_RELAXNG_LIST:
		case XML_RELAXNG_REF:
		case XML_RELAXNG_PARENTREF:
		case XML_RELAXNG_EXTERNALREF:
		case XML_RELAXNG_DEF:
		case XML_RELAXNG_ZEROORMORE:
		case XML_RELAXNG_ONEORMORE:
		case XML_RELAXNG_OPTIONAL:
		case XML_RELAXNG_CHOICE:
		case XML_RELAXNG_GROUP:
		case XML_RELAXNG_INTERLEAVE:
		    if (last == NULL) {
			ret->content = last = cur;
		    } else {
			if ((last->type == XML_RELAXNG_ELEMENT) &&
			    (ret->content == last)) {
			    ret->content = xmlRelaxNGNewDefine(ctxt, node);
			    if (ret->content != NULL) {
				ret->content->type = XML_RELAXNG_GROUP;
				ret->content->content = last;
			    } else {
				ret->content = last;
			    }
			}
			last->next = cur;
			last = cur;
		    }
		    break;
		case XML_RELAXNG_ATTRIBUTE:
		    cur->next = ret->attrs;
		    ret->attrs = cur;
		    break;
		case XML_RELAXNG_START:
		case XML_RELAXNG_EXCEPT:
		    TODO
		    ctxt->nbErrors++;
		    break;
	    }
	}
	child = child->next;
    }
    ctxt->define = olddefine;
    return(ret);
}

/**
 * xmlRelaxNGParsePatterns:
 * @ctxt:  a Relax-NG parser context
 * @nodes:  list of nodes
 * @group:  use an implicit <group> for elements
 *
 * parse the content of a RelaxNG start node.
 *
 * Returns the definition pointer or NULL in case of error.
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParsePatterns(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes,
	                int group) {
    xmlRelaxNGDefinePtr def = NULL, last = NULL, cur, parent;

    parent = ctxt->def;
    while (nodes != NULL) {
	if (IS_RELAXNG(nodes, "element")) {
	    cur = xmlRelaxNGParseElement(ctxt, nodes);
	    if (def == NULL) {
		def = last = cur;
	    } else {
		if ((group == 1) && (def->type == XML_RELAXNG_ELEMENT) &&
		    (def == last)) {
		    def = xmlRelaxNGNewDefine(ctxt, nodes);
		    def->type = XML_RELAXNG_GROUP;
		    def->content = last;
		}
		last->next = cur;
		last = cur;
	    }
	    cur->parent = parent;
	} else {
	    cur = xmlRelaxNGParsePattern(ctxt, nodes);
	    if (cur != NULL) {
		if (def == NULL) {
		    def = last = cur;
		} else {
		    last->next = cur;
		    last = cur;
		}
	    }
	}
	nodes = nodes->next;
    }
    return(def);
}

/**
 * xmlRelaxNGParseStart:
 * @ctxt:  a Relax-NG parser context
 * @nodes:  start children nodes
 *
 * parse the content of a RelaxNG start node.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
xmlRelaxNGParseStart(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes) {
    int ret = 0;
    xmlRelaxNGDefinePtr def = NULL;

    while (nodes != NULL) {
	if (IS_RELAXNG(nodes, "empty")) {
	    TODO
	    ctxt->nbErrors++;
	} else if (IS_RELAXNG(nodes, "notAllowed")) {
	    TODO
	    ctxt->nbErrors++;
	} else {
	    def = xmlRelaxNGParsePatterns(ctxt, nodes, 1);
	    ctxt->grammar->start = def;
	}
	nodes = nodes->next;
    }
    return(ret);
}

/**
 * xmlRelaxNGParseGrammarContent:
 * @ctxt:  a Relax-NG parser context
 * @nodes:  grammar children nodes
 *
 * parse the content of a RelaxNG grammar node.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
xmlRelaxNGParseGrammarContent(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes)
{
    int ret = 0, tmp;

    if (nodes == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"grammar has no children\n");
	ctxt->nbErrors++;
	return(-1);
    }
    while (nodes != NULL) {
	if (IS_RELAXNG(nodes, "start")) {
	    if (nodes->children == NULL) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
				"grammar has no children\n");
		ctxt->nbErrors++;
	    } else {
		tmp = xmlRelaxNGParseStart(ctxt, nodes->children);
		if (tmp != 0)
		    ret = -1;
	    }
	} else if (IS_RELAXNG(nodes, "define")) {
	    tmp = xmlRelaxNGParseDefine(ctxt, nodes);
	    if (tmp != 0)
		ret = -1;
	} else if (IS_RELAXNG(nodes, "include")) {
	    tmp = xmlRelaxNGParseInclude(ctxt, nodes);
	    if (tmp != 0)
		ret = -1;
        } else {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			"grammar has unexpected child %s\n", nodes->name);
	    ctxt->nbErrors++;
	    ret = -1;
	}
        nodes = nodes->next;
    }
    return (ret);
}

/**
 * xmlRelaxNGCheckReference:
 * @ref:  the ref
 * @ctxt:  a Relax-NG parser context
 * @name:  the name associated to the defines
 *
 * Applies the 4.17. combine attribute rule for all the define
 * element of a given grammar using the same name.
 */
static void
xmlRelaxNGCheckReference(xmlRelaxNGDefinePtr ref,
		xmlRelaxNGParserCtxtPtr ctxt, const xmlChar *name) {
    xmlRelaxNGGrammarPtr grammar;
    xmlRelaxNGDefinePtr def, cur;

    grammar = ctxt->grammar;
    if (grammar == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		    "Internal error: no grammar in CheckReference %s\n",
			name);
	ctxt->nbErrors++;
	return;
    }
    if (ref->content != NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
	    "Internal error: reference has content in CheckReference %s\n",
			name);
	ctxt->nbErrors++;
	return;
    }
    if (grammar->defs != NULL) {
	def = xmlHashLookup(grammar->defs, name);
	if (def != NULL) {
	    cur = ref;
	    while (cur != NULL) {
		cur->content = def;
		cur = cur->nextHash;
	    }
	} else {
	    TODO
	    ctxt->nbErrors++;
	}
    }
    /*
     * TODO: make a closure and verify there is no loop !
     */
}

/**
 * xmlRelaxNGCheckCombine:
 * @define:  the define(s) list
 * @ctxt:  a Relax-NG parser context
 * @name:  the name associated to the defines
 *
 * Applies the 4.17. combine attribute rule for all the define
 * element of a given grammar using the same name.
 */
static void
xmlRelaxNGCheckCombine(xmlRelaxNGDefinePtr define,
	xmlRelaxNGParserCtxtPtr ctxt, const xmlChar *name) {
    xmlChar *combine;
    int choiceOrInterleave = -1;
    int missing = 0;
    xmlRelaxNGDefinePtr cur, last, tmp, tmp2;

    if (define->nextHash == NULL)
	return;
    cur = define;
    while (cur != NULL) {
	combine = xmlGetProp(cur->node, BAD_CAST "combine");
	if (combine != NULL) {
	    if (xmlStrEqual(combine, BAD_CAST "choice")) {
		if (choiceOrInterleave == -1)
		    choiceOrInterleave = 1;
		else if (choiceOrInterleave == 0) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		    "Defines for %s use both 'choice' and 'interleave'\n",
		                    name);
		    ctxt->nbErrors++;
		}
	    } else if (xmlStrEqual(combine, BAD_CAST "interleave")) {
		if (choiceOrInterleave == -1)
		    choiceOrInterleave = 0;
		else if (choiceOrInterleave == 1) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		    "Defines for %s use both 'choice' and 'interleave'\n",
		                    name);
		    ctxt->nbErrors++;
		}
	    } else {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "Defines for %s use unknown combine value '%s''\n",
				name, combine);
		ctxt->nbErrors++;
	    }
	    xmlFree(combine);
	} else {
	    if (missing == 0)
		missing = 1;
	    else {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "Some defines for %s lacks the combine attribute\n",
				name);
		ctxt->nbErrors++;
	    }
	}

	cur = cur->nextHash;
    }
#ifdef DEBUG
    xmlGenericError(xmlGenericErrorContext,
		    "xmlRelaxNGCheckCombine(): merging %s defines: %d\n",
		    name, choiceOrInterleave);
#endif
    if (choiceOrInterleave == -1)
	choiceOrInterleave = 0;
    cur = xmlRelaxNGNewDefine(ctxt, define->node);
    if (cur == NULL)
	return;
    if (choiceOrInterleave == 0)
	cur->type = XML_RELAXNG_INTERLEAVE;
    else
	cur->type = XML_RELAXNG_CHOICE;
    tmp = define;
    last = NULL;
    while (tmp != NULL) {
	if (tmp->content != NULL) {
	    if (tmp->content->next != NULL) {
		/*
		 * we need first to create a wrapper.
		 */
		tmp2 = xmlRelaxNGNewDefine(ctxt, tmp->content->node);
		if (tmp2 == NULL)
		    break;
		tmp2->type = XML_RELAXNG_GROUP;
		tmp2->content = tmp->content;
	    } else {
		tmp2 = tmp->content;
	    }
	    if (last == NULL) {
		cur->content = tmp2;
	    } else {
		last->next = tmp2;
	    }
	    last = tmp2;
	    tmp->content = NULL;
	}
	tmp = tmp->nextHash;
    }
    define->content = cur;
    if (choiceOrInterleave == 0) {
	if (ctxt->interleaves == NULL)
	    ctxt->interleaves = xmlHashCreate(10);
	if (ctxt->interleaves == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Failed to create interleaves hash table\n");
	    ctxt->nbErrors++;
	} else {
	    char tmpname[32];

	    snprintf(tmpname, 32, "interleave%d", ctxt->nbInterleaves++);
	    if (xmlHashAddEntry(ctxt->interleaves, BAD_CAST tmpname, cur) < 0) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Failed to add %s to hash table\n", tmpname);
		ctxt->nbErrors++;
	    }
	}
    }
}

/**
 * xmlRelaxNGCombineStart:
 * @ctxt:  a Relax-NG parser context
 * @grammar:  the grammar
 *
 * Applies the 4.17. combine rule for all the start
 * element of a given grammar.
 */
static void
xmlRelaxNGCombineStart(xmlRelaxNGParserCtxtPtr ctxt,
	               xmlRelaxNGGrammarPtr grammar) {
    xmlRelaxNGDefinePtr starts;
    xmlChar *combine;
    int choiceOrInterleave = -1;
    int missing = 0;
    xmlRelaxNGDefinePtr cur, last, tmp, tmp2;

    starts = grammar->startList;
    if ((starts == NULL) || (starts->nextHash == NULL))
	return;
    cur = starts;
    while (cur != NULL) {
	combine = xmlGetProp(cur->node, BAD_CAST "combine");
	if (combine != NULL) {
	    if (xmlStrEqual(combine, BAD_CAST "choice")) {
		if (choiceOrInterleave == -1)
		    choiceOrInterleave = 1;
		else if (choiceOrInterleave == 0) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		    "<start> use both 'choice' and 'interleave'\n");
		    ctxt->nbErrors++;
		}
	    } else if (xmlStrEqual(combine, BAD_CAST "choice")) {
		if (choiceOrInterleave == -1)
		    choiceOrInterleave = 0;
		else if (choiceOrInterleave == 1) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		    "<start> use both 'choice' and 'interleave'\n");
		    ctxt->nbErrors++;
		}
	    } else {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "<start> uses unknown combine value '%s''\n", combine);
		ctxt->nbErrors++;
	    }
	    xmlFree(combine);
	} else {
	    if (missing == 0)
		missing = 1;
	    else {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "Some <start> elements lacks the combine attribute\n");
		ctxt->nbErrors++;
	    }
	}

	cur = cur->nextHash;
    }
#ifdef DEBUG
    xmlGenericError(xmlGenericErrorContext,
		    "xmlRelaxNGCombineStart(): merging <start>: %d\n",
		    choiceOrInterleave);
#endif
    if (choiceOrInterleave == -1)
	choiceOrInterleave = 0;
    cur = xmlRelaxNGNewDefine(ctxt, starts->node);
    if (cur == NULL)
	return;
    if (choiceOrInterleave == 0)
	cur->type = XML_RELAXNG_CHOICE;
    else
	cur->type = XML_RELAXNG_INTERLEAVE;
    tmp = starts;
    last = NULL;
    while (tmp != NULL) {
	if (tmp->content != NULL) {
	    if (tmp->content->next != NULL) {
		/*
		 * we need first to create a wrapper.
		 */
		tmp2 = xmlRelaxNGNewDefine(ctxt, tmp->content->node);
		if (tmp2 == NULL)
		    break;
		tmp2->type = XML_RELAXNG_GROUP;
		tmp2->content = tmp->content;
	    } else {
		tmp2 = tmp->content;
	    }
	    if (last == NULL) {
		cur->content = tmp2;
	    } else {
		last->next = tmp2;
	    }
	    last = tmp2;
	    tmp->content = NULL;
	}
	tmp = tmp->nextHash;
    }
    starts->content = cur;
}

/**
 * xmlRelaxNGParseGrammar:
 * @ctxt:  a Relax-NG parser context
 * @nodes:  grammar children nodes
 *
 * parse a Relax-NG <grammar> node
 *
 * Returns the internal xmlRelaxNGGrammarPtr built or
 *         NULL in case of error
 */
static xmlRelaxNGGrammarPtr
xmlRelaxNGParseGrammar(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes) {
    xmlRelaxNGGrammarPtr ret, tmp, old;

    ret = xmlRelaxNGNewGrammar(ctxt);
    if (ret == NULL)
        return(NULL);

    /*
     * Link the new grammar in the tree
     */
    ret->parent = ctxt->grammar;
    if (ctxt->grammar != NULL) {
	tmp = ctxt->grammar->children;
	if (tmp == NULL) {
	    ctxt->grammar->children = ret;
	} else {
	    while (tmp->next != NULL)
		tmp = tmp->next;
	    tmp->next = ret;
	}
    }

    old = ctxt->grammar;
    ctxt->grammar = ret;
    xmlRelaxNGParseGrammarContent(ctxt, nodes);
    ctxt->grammar = ret;

    /*
     * Apply 4.17 mergingd rules to defines and starts
     */
    xmlRelaxNGCombineStart(ctxt, ret);
    if (ret->defs != NULL) {
	xmlHashScan(ret->defs, (xmlHashScanner) xmlRelaxNGCheckCombine,
		    ctxt);
    }

    /*
     * link together defines and refs in this grammar
     */
    if (ret->refs != NULL) {
	xmlHashScan(ret->refs, (xmlHashScanner) xmlRelaxNGCheckReference,
		    ctxt);
    }
    ctxt->grammar = old;
    return(ret);
}

/**
 * xmlRelaxNGParseDocument:
 * @ctxt:  a Relax-NG parser context
 * @node:  the root node of the RelaxNG schema
 *
 * parse a Relax-NG definition resource and build an internal
 * xmlRelaxNG struture which can be used to validate instances.
 *
 * Returns the internal XML RelaxNG structure built or
 *         NULL in case of error
 */
static xmlRelaxNGPtr
xmlRelaxNGParseDocument(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGPtr schema = NULL;
    const xmlChar *olddefine;
    xmlRelaxNGGrammarPtr old;

    if ((ctxt == NULL) || (node == NULL))
        return (NULL);

    schema = xmlRelaxNGNewRelaxNG(ctxt);
    if (schema == NULL)
	return(NULL);

    olddefine = ctxt->define;
    ctxt->define = NULL;
    if (IS_RELAXNG(node, "grammar")) {
	schema->topgrammar = xmlRelaxNGParseGrammar(ctxt, node->children);
    } else {
	schema->topgrammar = xmlRelaxNGNewGrammar(ctxt);
	if (schema->topgrammar == NULL) {
	    return(schema);
	}
	schema->topgrammar->parent = NULL;
	old = ctxt->grammar;
	ctxt->grammar = schema->topgrammar;
	xmlRelaxNGParseStart(ctxt, node);
	if (old != NULL)
	    ctxt->grammar = old;
    }
    ctxt->define = olddefine;

#ifdef DEBUG
    if (schema == NULL)
        xmlGenericError(xmlGenericErrorContext,
                        "xmlRelaxNGParseDocument() failed\n");
#endif

    return (schema);
}

/************************************************************************
 * 									*
 * 			Reading RelaxNGs				*
 * 									*
 ************************************************************************/

/**
 * xmlRelaxNGNewParserCtxt:
 * @URL:  the location of the schema
 *
 * Create an XML RelaxNGs parse context for that file/resource expected
 * to contain an XML RelaxNGs file.
 *
 * Returns the parser context or NULL in case of error
 */
xmlRelaxNGParserCtxtPtr
xmlRelaxNGNewParserCtxt(const char *URL) {
    xmlRelaxNGParserCtxtPtr ret;

    if (URL == NULL)
	return(NULL);

    ret = (xmlRelaxNGParserCtxtPtr) xmlMalloc(sizeof(xmlRelaxNGParserCtxt));
    if (ret == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"Failed to allocate new schama parser context for %s\n", URL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGParserCtxt));
    ret->URL = xmlStrdup((const xmlChar *)URL);
    ret->error = xmlGenericError;
    ret->userData = xmlGenericErrorContext;
    return (ret);
}

/**
 * xmlRelaxNGNewMemParserCtxt:
 * @buffer:  a pointer to a char array containing the schemas
 * @size:  the size of the array
 *
 * Create an XML RelaxNGs parse context for that memory buffer expected
 * to contain an XML RelaxNGs file.
 *
 * Returns the parser context or NULL in case of error
 */
xmlRelaxNGParserCtxtPtr
xmlRelaxNGNewMemParserCtxt(const char *buffer, int size) {
    xmlRelaxNGParserCtxtPtr ret;

    if ((buffer == NULL) || (size <= 0))
	return(NULL);

    ret = (xmlRelaxNGParserCtxtPtr) xmlMalloc(sizeof(xmlRelaxNGParserCtxt));
    if (ret == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"Failed to allocate new schama parser context\n");
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGParserCtxt));
    ret->buffer = buffer;
    ret->size = size;
    ret->error = xmlGenericError;
    ret->userData = xmlGenericErrorContext;
    return (ret);
}

/**
 * xmlRelaxNGFreeParserCtxt:
 * @ctxt:  the schema parser context
 *
 * Free the resources associated to the schema parser context
 */
void
xmlRelaxNGFreeParserCtxt(xmlRelaxNGParserCtxtPtr ctxt) {
    if (ctxt == NULL)
	return;
    if (ctxt->URL != NULL)
	xmlFree(ctxt->URL);
    if (ctxt->doc != NULL)
	xmlFreeDoc(ctxt->document);
    if (ctxt->interleaves != NULL)
        xmlHashFree(ctxt->interleaves, NULL);
    if (ctxt->documents != NULL)
	xmlHashFree(ctxt->documents, (xmlHashDeallocator)
		xmlRelaxNGFreeDocument);
    if (ctxt->docTab != NULL)
	xmlFree(ctxt->docTab);
    if (ctxt->incTab != NULL)
	xmlFree(ctxt->incTab);
    if (ctxt->defTab != NULL) {
	int i;

	for (i = 0;i < ctxt->defNr;i++)
	    xmlRelaxNGFreeDefine(ctxt->defTab[i]);
	xmlFree(ctxt->defTab);
    }
    xmlFree(ctxt);
}

/**
 * xmlRelaxNGCleanupDoc:
 * @ctxt:  a Relax-NG parser context
 * @doc:  an xmldocPtr document pointer
 *
 * Cleanup the document from unwanted nodes for parsing, resolve
 * Include and externalRef lookups.
 *
 * Returns the cleaned up document or NULL in case of error
 */
static xmlDocPtr
xmlRelaxNGCleanupDoc(xmlRelaxNGParserCtxtPtr ctxt, xmlDocPtr doc) {
    xmlNodePtr root, cur, delete;

    /*
     * Extract the root
     */
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        if (ctxt->error != NULL)
            ctxt->error(ctxt->userData, "xmlRelaxNGParse: %s is empty\n",
                        ctxt->URL);
	ctxt->nbErrors++;
        return (NULL);
    }

    /*
     * Remove all the blank text nodes
     */
    delete = NULL;
    cur = root;
    while (cur != NULL) {
	if (delete != NULL) {
	    xmlUnlinkNode(delete);
	    xmlFreeNode(delete);
	    delete = NULL;
	}
	if (cur->type == XML_ELEMENT_NODE) {
	    /*
	     * Simplification 4.1. Annotations
	     */
	    if ((cur->ns == NULL) ||
		(!xmlStrEqual(cur->ns->href, xmlRelaxNGNs))) {
		delete = cur;
		goto skip_children;
	    } else {
		if (xmlStrEqual(cur->name, BAD_CAST "externalRef")) {
		    xmlChar *href, *ns, *base, *URL;
		    xmlRelaxNGDocumentPtr docu;

		    ns = xmlGetProp(cur, BAD_CAST "ns");
		    href = xmlGetProp(cur, BAD_CAST "href");
		    if (href == NULL) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
		    "xmlRelaxNGParse: externalRef has no href attribute\n");
			ctxt->nbErrors++;
			delete = cur;
			goto skip_children;
		    }
		    base = xmlNodeGetBase(cur->doc, cur);
		    URL = xmlBuildURI(href, base);
		    if (URL == NULL) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
			"Failed to compute URL for externalRef %s\n", href);
			ctxt->nbErrors++;
			if (href != NULL)
			    xmlFree(href);
			if (base != NULL)
			    xmlFree(base);
			delete = cur;
			goto skip_children;
		    }
		    if (href != NULL)
			xmlFree(href);
		    if (base != NULL)
			xmlFree(base);
		    docu = xmlRelaxNGLoadExternalRef(ctxt, URL, ns);
		    if (docu == NULL) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
				"Failed to load externalRef %s\n", URL);
			ctxt->nbErrors++;
			xmlFree(URL);
			delete = cur;
			goto skip_children;
		    }
		    xmlFree(URL);
		    cur->_private = docu;
		} else if (xmlStrEqual(cur->name, BAD_CAST "include")) {
		    xmlChar *href, *base, *URL;
		    xmlRelaxNGIncludePtr incl;

		    href = xmlGetProp(cur, BAD_CAST "href");
		    if (href == NULL) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
		    "xmlRelaxNGParse: include has no href attribute\n");
			ctxt->nbErrors++;
			delete = cur;
			goto skip_children;
		    }
		    base = xmlNodeGetBase(cur->doc, cur);
		    URL = xmlBuildURI(href, base);
		    if (URL == NULL) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
			"Failed to compute URL for include %s\n", href);
			ctxt->nbErrors++;
			if (href != NULL)
			    xmlFree(href);
			if (base != NULL)
			    xmlFree(base);
			delete = cur;
			goto skip_children;
		    }
		    if (href != NULL)
			xmlFree(href);
		    if (base != NULL)
			xmlFree(base);
		    incl = xmlRelaxNGLoadInclude(ctxt, URL, cur);
		    if (incl == NULL) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
				"Failed to load include %s\n", URL);
			ctxt->nbErrors++;
			xmlFree(URL);
			delete = cur;
			goto skip_children;
		    }
		    xmlFree(URL);
		    cur->_private = incl;
		} else if ((xmlStrEqual(cur->name, BAD_CAST "element")) ||
	            (xmlStrEqual(cur->name, BAD_CAST "attribute"))) {
		    xmlChar *name;
		    xmlNodePtr text = NULL;
		    
		    /*
		     * Simplification 4.8. name attribute of element
		     * and attribute elements
		     */
		    name = xmlGetProp(cur, BAD_CAST "name");
		    if (name != NULL) {
			if (cur->children == NULL) {
			    text = xmlNewChild(cur, cur->ns, BAD_CAST "name",
				               name);
			} else {
			    xmlNodePtr node;
			    node = xmlNewNode(cur->ns, BAD_CAST "name");
			    if (node != NULL) {
				xmlAddPrevSibling(cur->children, node);
				text = xmlNewText(name);
				xmlAddChild(node, text);
				text = node;
			    }
			}
			xmlUnsetProp(cur, BAD_CAST "name");
			xmlFree(name);
		    }
		    if (xmlStrEqual(cur->name, BAD_CAST "attribute")) {
			if (text == NULL) {
			    text = cur->children;
			    while (text != NULL) {
				if ((text->type == XML_ELEMENT_NODE) &&
			            (xmlStrEqual(text->name, BAD_CAST "name")))
				    break;
				text = text->next;
			    }
			}
			if (text != NULL) {
			    xmlSetProp(text, BAD_CAST "ns", BAD_CAST "");
			}
		    }
		} else if ((xmlStrEqual(cur->name, BAD_CAST "name")) ||
			   (xmlStrEqual(cur->name, BAD_CAST "nsName")) ||
			   (xmlStrEqual(cur->name, BAD_CAST "value"))) {
		    /*
		     * Simplification 4.8. name attribute of element
		     * and attribute elements
		     */
		    if (xmlHasProp(cur, BAD_CAST "ns") == NULL) {
			xmlNodePtr node;
			xmlChar *ns = NULL;

			node = cur->parent;
			while ((node != NULL) &&
			       (node->type == XML_ELEMENT_NODE)) {
			    ns = xmlGetProp(node, BAD_CAST "ns");
			    if (ns != NULL) {
				break;
			    }
			    node = node->parent;
			}
			if (ns == NULL) {
			    xmlSetProp(cur, BAD_CAST "ns", BAD_CAST "");
			} else {
			    xmlSetProp(cur, BAD_CAST "ns", ns);
			    xmlFree(ns);
			}
		    }
		    if (xmlStrEqual(cur->name, BAD_CAST "name")) {
			xmlChar *name, *local, *prefix;

			/*
			 * Simplification: 4.10. QNames
			 */
			name = xmlNodeGetContent(cur);
			if (name != NULL) {
			    local = xmlSplitQName2(name, &prefix);
			    if (local != NULL) {
				xmlNsPtr ns;

				ns = xmlSearchNs(cur->doc, cur, prefix);
				if (ns == NULL) {
				    if (ctxt->error != NULL)
					ctxt->error(ctxt->userData,
		    "xmlRelaxNGParse: no namespace for prefix %s\n", prefix);
				    ctxt->nbErrors++;
				} else {
				    xmlSetProp(cur, BAD_CAST "ns", ns->href);
				    xmlNodeSetContent(cur, local);
				}
				xmlFree(local);
				xmlFree(prefix);
			    }
			    xmlFree(name);
			} 
		    }
		}
		/*
		 * Thisd is not an else since "include" is transformed
		 * into a div
		 */
		if (xmlStrEqual(cur->name, BAD_CAST "div")) {
		    /*
		     * implements rule 4.11
		     */
		    xmlNodePtr child, ins, tmp;

		    child = cur->children;
		    ins = cur;
		    while (child != NULL) {
			tmp = child->next;
			xmlUnlinkNode(child);
			ins = xmlAddNextSibling(ins, child);
			child = tmp;
		    }
		    delete = cur;
		    goto skip_children;
		}
	    }
	}
	/*
	 * Simplification 4.2 whitespaces
	 */
	else if (cur->type == XML_TEXT_NODE) {
	    if (IS_BLANK_NODE(cur)) {
	        if (cur->parent->type == XML_ELEMENT_NODE) {
		    if ((!xmlStrEqual(cur->parent->name, BAD_CAST "value")) &&
			(!xmlStrEqual(cur->parent->name, BAD_CAST "param")))
			delete = cur;
		} else {
		    delete = cur;
		    goto skip_children;
		}
	    }
	} else if (cur->type != XML_CDATA_SECTION_NODE) {
	    delete = cur;
	    goto skip_children;
	}

	/*
	 * Skip to next node
	 */
	if (cur->children != NULL) {
	    if ((cur->children->type != XML_ENTITY_DECL) &&
		(cur->children->type != XML_ENTITY_REF_NODE) &&
		(cur->children->type != XML_ENTITY_NODE)) {
		cur = cur->children;
		continue;
	    }
	}
skip_children:
	if (cur->next != NULL) {
	    cur = cur->next;
	    continue;
	}
	
	do {
	    cur = cur->parent;
	    if (cur == NULL)
		break;
	    if (cur == root) {
		cur = NULL;
		break;
	    }
	    if (cur->next != NULL) {
		cur = cur->next;
		break;
	    }
	} while (cur != NULL);
    }
    if (delete != NULL) {
	xmlUnlinkNode(delete);
	xmlFreeNode(delete);
	delete = NULL;
    }

    return(doc);
}

/**
 * xmlRelaxNGParse:
 * @ctxt:  a Relax-NG parser context
 *
 * parse a schema definition resource and build an internal
 * XML Shema struture which can be used to validate instances.
 * *WARNING* this interface is highly subject to change
 *
 * Returns the internal XML RelaxNG structure built from the resource or
 *         NULL in case of error
 */
xmlRelaxNGPtr
xmlRelaxNGParse(xmlRelaxNGParserCtxtPtr ctxt)
{
    xmlRelaxNGPtr ret = NULL;
    xmlDocPtr doc;
    xmlNodePtr root;

    xmlRelaxNGInitTypes();

    if (ctxt == NULL)
        return (NULL);

    /*
     * First step is to parse the input document into an DOM/Infoset
     */
    if (ctxt->URL != NULL) {
	doc = xmlParseFile((const char *) ctxt->URL);
	if (doc == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "xmlRelaxNGParse: could not load %s\n", ctxt->URL);
	    ctxt->nbErrors++;
	    return (NULL);
	}
    } else if (ctxt->buffer != NULL) {
	doc = xmlParseMemory(ctxt->buffer, ctxt->size);
	if (doc == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "xmlRelaxNGParse: could not parse schemas\n");
	    ctxt->nbErrors++;
	    return (NULL);
	}
	doc->URL = xmlStrdup(BAD_CAST "in_memory_buffer");
	ctxt->URL = xmlStrdup(BAD_CAST "in_memory_buffer");
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNGParse: nothing to parse\n");
	ctxt->nbErrors++;
	return (NULL);
    }
    ctxt->document = doc;

    /*
     * Some preprocessing of the document content
     */
    doc = xmlRelaxNGCleanupDoc(ctxt, doc);
    if (doc == NULL) {
	xmlFreeDoc(ctxt->document);
	ctxt->document = NULL;
	return(NULL);
    }

    /*
     * Then do the parsing for good
     */
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        if (ctxt->error != NULL)
            ctxt->error(ctxt->userData, "xmlRelaxNGParse: %s is empty\n",
                        ctxt->URL);
	ctxt->nbErrors++;
        return (NULL);
    }
    ret = xmlRelaxNGParseDocument(ctxt, root);
    if (ret == NULL)
	return(NULL);

    /*
     * Check the ref/defines links
     */
    /*
     * try to preprocess interleaves
     */
    if (ctxt->interleaves != NULL) {
	xmlHashScan(ctxt->interleaves,
		(xmlHashScanner)xmlRelaxNGComputeInterleaves, ctxt);
    }

    /*
     * if there was a parsing error return NULL
     */
    if (ctxt->nbErrors > 0) {
	xmlRelaxNGFree(ret);
	ctxt->document = NULL;
	xmlFreeDoc(doc);
	return(NULL);
    }

    /*
     * Transfer the pointer for cleanup at the schema level.
     */
    ret->doc = doc;
    ctxt->document = NULL;
    ret->documents = ctxt->documents;
    ctxt->documents = NULL;
    ret->includes = ctxt->includes;
    ctxt->includes = NULL;
    ret->defNr = ctxt->defNr;
    ret->defTab = ctxt->defTab;
    ctxt->defTab = NULL;

    return (ret);
}
 
/**
 * xmlRelaxNGSetParserErrors:
 * @ctxt:  a Relax-NG validation context
 * @err:  the error callback
 * @warn:  the warning callback
 * @ctx:  contextual data for the callbacks
 *
 * Set the callback functions used to handle errors for a validation context
 */
void
xmlRelaxNGSetParserErrors(xmlRelaxNGParserCtxtPtr ctxt,
	xmlRelaxNGValidityErrorFunc err,
	xmlRelaxNGValidityWarningFunc warn, void *ctx) {
    if (ctxt == NULL)
	return;
    ctxt->error = err;
    ctxt->warning = warn;
    ctxt->userData = ctx;
}
/************************************************************************
 * 									*
 * 			Dump back a compiled form			*
 * 									*
 ************************************************************************/
static void xmlRelaxNGDumpDefine(FILE * output, xmlRelaxNGDefinePtr define);

/**
 * xmlRelaxNGDumpDefines:
 * @output:  the file output
 * @defines:  a list of define structures
 *
 * Dump a RelaxNG structure back
 */
static void
xmlRelaxNGDumpDefines(FILE * output, xmlRelaxNGDefinePtr defines) {
    while (defines != NULL) {
	xmlRelaxNGDumpDefine(output, defines);
	defines = defines->next;
    }
}

/**
 * xmlRelaxNGDumpDefine:
 * @output:  the file output
 * @define:  a define structure
 *
 * Dump a RelaxNG structure back
 */
static void
xmlRelaxNGDumpDefine(FILE * output, xmlRelaxNGDefinePtr define) {
    if (define == NULL)
	return;
    switch(define->type) {
        case XML_RELAXNG_EMPTY:
	    fprintf(output, "<empty/>\n");
	    break;
        case XML_RELAXNG_NOT_ALLOWED:
	    fprintf(output, "<notAllowed/>\n");
	    break;
        case XML_RELAXNG_TEXT:
	    fprintf(output, "<text/>\n");
	    break;
        case XML_RELAXNG_ELEMENT:
	    fprintf(output, "<element>\n");
	    if (define->name != NULL) {
		fprintf(output, "<name");
		if (define->ns != NULL)
		    fprintf(output, " ns=\"%s\"", define->ns);
		fprintf(output, ">%s</name>\n", define->name);
	    }
	    xmlRelaxNGDumpDefines(output, define->attrs);
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</element>\n");
	    break;
        case XML_RELAXNG_LIST:
	    fprintf(output, "<list>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</list>\n");
	    break;
        case XML_RELAXNG_ONEORMORE:
	    fprintf(output, "<oneOrMore>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</oneOrMore>\n");
	    break;
        case XML_RELAXNG_ZEROORMORE:
	    fprintf(output, "<zeroOrMore>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</zeroOrMore>\n");
	    break;
        case XML_RELAXNG_CHOICE:
	    fprintf(output, "<choice>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</choice>\n");
	    break;
        case XML_RELAXNG_GROUP:
	    fprintf(output, "<group>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</group>\n");
	    break;
        case XML_RELAXNG_INTERLEAVE:
	    fprintf(output, "<interleave>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</interleave>\n");
	    break;
	case XML_RELAXNG_OPTIONAL:
	    fprintf(output, "<optional>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</optional>\n");
	    break;
        case XML_RELAXNG_ATTRIBUTE:
	    fprintf(output, "<attribute>\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</attribute>\n");
	    break;
        case XML_RELAXNG_DEF:
	    fprintf(output, "<define");
	    if (define->name != NULL)
		fprintf(output, " name=\"%s\"", define->name);
	    fprintf(output, ">\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</define>\n");
	    break;
        case XML_RELAXNG_REF:
	    fprintf(output, "<ref");
	    if (define->name != NULL)
		fprintf(output, " name=\"%s\"", define->name);
	    fprintf(output, ">\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</ref>\n");
	    break;
        case XML_RELAXNG_PARENTREF:
	    fprintf(output, "<parentRef");
	    if (define->name != NULL)
		fprintf(output, " name=\"%s\"", define->name);
	    fprintf(output, ">\n");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</parentRef>\n");
	    break;
	case XML_RELAXNG_EXTERNALREF:
	    fprintf(output, "<externalRef");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</externalRef>\n");
	    break;
        case XML_RELAXNG_DATATYPE:
        case XML_RELAXNG_VALUE:
	    TODO
	    break;
	case XML_RELAXNG_START:
	case XML_RELAXNG_EXCEPT:
	    TODO
	    break;
    }
}
   
/**
 * xmlRelaxNGDumpGrammar:
 * @output:  the file output
 * @grammar:  a grammar structure
 * @top:  is this a top grammar 
 *
 * Dump a RelaxNG structure back
 */
static void
xmlRelaxNGDumpGrammar(FILE * output, xmlRelaxNGGrammarPtr grammar, int top)
{
    if (grammar == NULL)
	return;
   
    fprintf(output, "<grammar");
    if (top)
	fprintf(output,
		" xmlns=\"http://relaxng.org/ns/structure/1.0\"");
    switch(grammar->combine) {
	case XML_RELAXNG_COMBINE_UNDEFINED:
	    break;
	case XML_RELAXNG_COMBINE_CHOICE:
	    fprintf(output, " combine=\"choice\"");
	    break;
	case XML_RELAXNG_COMBINE_INTERLEAVE:
	    fprintf(output, " combine=\"interleave\"");
	    break;
	default:
	    fprintf(output, " <!-- invalid combine value -->");
    }
    fprintf(output, ">\n");
    if (grammar->start == NULL) {
	fprintf(output, " <!-- grammar had no start -->");
    } else {
	fprintf(output, "<start>\n");
	xmlRelaxNGDumpDefine(output, grammar->start);
	fprintf(output, "</start>\n");
    }
    /* TODO ? Dump the defines ? */
    fprintf(output, "</grammar>\n");
}

/**
 * xmlRelaxNGDump:
 * @output:  the file output
 * @schema:  a schema structure
 *
 * Dump a RelaxNG structure back
 */
void
xmlRelaxNGDump(FILE * output, xmlRelaxNGPtr schema)
{
    if (schema == NULL) {
	fprintf(output, "RelaxNG empty or failed to compile\n");
	return;
    }
    fprintf(output, "RelaxNG: ");
    if (schema->doc == NULL) {
	fprintf(output, "no document\n");
    } else if (schema->doc->URL != NULL) {
	fprintf(output, "%s\n", schema->doc->URL);
    } else {
	fprintf(output, "\n");
    }
    if (schema->topgrammar == NULL) {
	fprintf(output, "RelaxNG has no top grammar\n");
	return;
    }
    xmlRelaxNGDumpGrammar(output, schema->topgrammar, 1);
}

/************************************************************************
 * 									*
 * 			Validation implementation			*
 * 									*
 ************************************************************************/
static int xmlRelaxNGValidateDefinition(xmlRelaxNGValidCtxtPtr ctxt, 
	                                xmlRelaxNGDefinePtr define);
static int xmlRelaxNGValidateValue(xmlRelaxNGValidCtxtPtr ctxt, 
	                           xmlRelaxNGDefinePtr define);

/**
 * xmlRelaxNGSkipIgnored:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Skip ignorable nodes in that context
 *
 * Returns the new sibling or NULL in case of error.
 */
static xmlNodePtr
xmlRelaxNGSkipIgnored(xmlRelaxNGValidCtxtPtr ctxt ATTRIBUTE_UNUSED,
	              xmlNodePtr node) {
    /*
     * TODO complete and handle entities
     */
    while ((node != NULL) &&
	   ((node->type == XML_COMMENT_NODE) ||
	    (node->type == XML_PI_NODE) ||
	    ((node->type == XML_TEXT_NODE) &&
	     (IS_BLANK_NODE(node))))) {
	node = node->next;
    }
    return(node);
}

/**
 * xmlRelaxNGNormalize:
 * @ctxt:  a schema validation context
 * @str:  the string to normalize
 *
 * Implements the  normalizeWhiteSpace( s ) function from
 * section 6.2.9 of the spec
 *
 * Returns the new string or NULL in case of error.
 */
static xmlChar *
xmlRelaxNGNormalize(xmlRelaxNGValidCtxtPtr ctxt, const xmlChar *str) {
    xmlChar *ret, *p;
    const xmlChar *tmp;
    int len;
    
    if (str == NULL)
	return(NULL);
    tmp = str;
    while (*tmp != 0) tmp++;
    len = tmp - str;

    ret = (xmlChar *) xmlMalloc((len + 1) * sizeof(xmlChar));
    if (ret == NULL) {
	if (ctxt != NULL) {
	    VALID_CTXT();
	    VALID_ERROR("xmlRelaxNGNormalize: out of memory\n");
	} else {
	    xmlGenericError(xmlGenericErrorContext,
		"xmlRelaxNGNormalize: out of memory\n");
	}
        return(NULL);
    }
    p = ret;
    while (IS_BLANK(*str)) str++;
    while (*str != 0) {
	if (IS_BLANK(*str)) {
	    while (IS_BLANK(*str)) str++;
	    if (*str == 0)
		break;
	    *p++ = ' ';
	} else 
	    *p++ = *str++;
    }
    *p = 0;
    return(ret);
}

/**
 * xmlRelaxNGValidateDatatype:
 * @ctxt:  a Relax-NG validation context
 * @value:  the string value
 * @type:  the datatype definition
 *
 * Validate the given value against the dataype
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateDatatype(xmlRelaxNGValidCtxtPtr ctxt, const xmlChar *value,
	                   xmlRelaxNGDefinePtr define) {
    int ret;
    xmlRelaxNGTypeLibraryPtr lib;

    if ((define == NULL) || (define->data == NULL)) {
	return(-1);
    }
    lib = (xmlRelaxNGTypeLibraryPtr) define->data;
    if (lib->check != NULL)
	ret = lib->check(lib->data, define->name, value);
    else 
	ret = -1;
    if (ret < 0) {
	VALID_CTXT();
	VALID_ERROR2("Internal: failed to validate type %s\n", define->name);
	return(-1);
    } else if (ret == 1) {
	ret = 0;
    } else {
	VALID_CTXT();
	VALID_ERROR3("Type %s doesn't allow value %s\n", define->name, value);
	return(-1);
	ret = -1;
    }
    return(ret);
}

/**
 * xmlRelaxNGNextValue:
 * @ctxt:  a Relax-NG validation context
 *
 * Skip to the next value when validating within a list
 *
 * Returns 0 if the operation succeeded or an error code.
 */
static int
xmlRelaxNGNextValue(xmlRelaxNGValidCtxtPtr ctxt) {
    xmlChar *cur;

    cur = ctxt->state->value;
    if ((cur == NULL) || (ctxt->state->endvalue == NULL)) {
	ctxt->state->value = NULL;
	ctxt->state->endvalue = NULL;
	return(0);
    }
    while (*cur != 0) cur++;
    while ((cur != ctxt->state->endvalue) && (*cur == 0)) cur++;
    if (cur == ctxt->state->endvalue)
	ctxt->state->value = NULL;
    else
	ctxt->state->value = cur;
    return(0);
}

/**
 * xmlRelaxNGValidateValueList:
 * @ctxt:  a Relax-NG validation context
 * @defines:  the list of definitions to verify
 *
 * Validate the given set of definitions for the current value
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateValueList(xmlRelaxNGValidCtxtPtr ctxt, 
	                xmlRelaxNGDefinePtr defines) {
    int ret = 0;

    while (defines != NULL) {
	ret = xmlRelaxNGValidateValue(ctxt, defines);
	if (ret != 0)
	    break;
	defines = defines->next;
    }
    return(ret);
}

/**
 * xmlRelaxNGValidateValue:
 * @ctxt:  a Relax-NG validation context
 * @define:  the definition to verify
 *
 * Validate the given definition for the current value
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateValue(xmlRelaxNGValidCtxtPtr ctxt, 
	                xmlRelaxNGDefinePtr define) {
    int ret = 0, oldflags;
    xmlChar *value;

    value = ctxt->state->value;
    switch (define->type) {
	case XML_RELAXNG_EMPTY:
	    if ((value != NULL) && (value[0] != '0'))
		ret = -1;
	    break;
	case XML_RELAXNG_TEXT:
	    break;
	case XML_RELAXNG_VALUE: {
	    if (!xmlStrEqual(value, define->value)) {
		if (define->name != NULL) {
		    xmlRelaxNGTypeLibraryPtr lib;
		    
		    lib = (xmlRelaxNGTypeLibraryPtr) define->data;
		    if ((lib != NULL) && (lib->comp != NULL))
			ret = lib->comp(lib->data, define->name, value,
				        define->value);
		    else
			ret = -1;
		    if (ret < 0) {
			VALID_CTXT();
			VALID_ERROR2("Internal: failed to compare type %s\n",
				    define->name);
			return(-1);
		    } else if (ret == 1) {
			ret = 0;
		    } else {
			ret = -1;
		    }
		} else {
		    xmlChar *nval, *nvalue;

		    /*
		     * TODO: trivial optimizations are possible by
		     * computing at compile-time
		     */
		    nval = xmlRelaxNGNormalize(ctxt, define->value);
		    nvalue = xmlRelaxNGNormalize(ctxt, value);

		    if ((nval == NULL) || (nvalue == NULL) ||
			(!xmlStrEqual(nval, nvalue)))
			ret = -1;
		    if (nval != NULL)
			xmlFree(nval);
		    if (nvalue != NULL)
			xmlFree(nvalue);
		}
	    }
	    break;
	}
	case XML_RELAXNG_DATATYPE: {
	    ret = xmlRelaxNGValidateDatatype(ctxt, value, define);
	    if (ret == 0)
		xmlRelaxNGNextValue(ctxt);
	    
	    break;
	}
	case XML_RELAXNG_CHOICE: {
	    xmlRelaxNGDefinePtr list = define->content;
	    xmlChar *oldvalue;

	    oldflags = ctxt->flags;
	    ctxt->flags |= FLAGS_IGNORABLE;

	    oldvalue = ctxt->state->value;
	    while (list != NULL) {
		ret = xmlRelaxNGValidateValue(ctxt, list);
		if (ret == 0) {
		    break;
		}
		ctxt->state->value = oldvalue;
		list = list->next;
	    }
	    ctxt->flags = oldflags;
	    break;
	}
	case XML_RELAXNG_LIST: {
	    xmlRelaxNGDefinePtr list = define->content;
	    xmlChar *oldvalue, *oldend, *val, *cur;

	    oldvalue = ctxt->state->value;
	    oldend = ctxt->state->endvalue;

	    val = xmlStrdup(oldvalue);
	    if (val == NULL) {
		VALID_CTXT();
		VALID_ERROR("Internal: no state\n");
		return(-1);
	    }
	    cur = val;
	    while (*cur != 0) {
		if (IS_BLANK(*cur))
		    *cur = 0;
		cur++;
	    }
	    ctxt->state->endvalue = cur;
	    cur = val;
	    while ((*cur == 0) && (cur != ctxt->state->endvalue)) cur++;

	    ctxt->state->value = cur;

	    while (list != NULL) {
		ret = xmlRelaxNGValidateValue(ctxt, list);
		if (ret != 0) {
		    break;
		}
		list = list->next;
	    }
	    if ((ret == 0) && (ctxt->state->value != NULL) &&
		(ctxt->state->value != ctxt->state->endvalue)) {
		VALID_CTXT();
		VALID_ERROR2("Extra data in list: %s\n", ctxt->state->value);
		ret = -1;
	    }
	    xmlFree(val);
	    ctxt->state->value = oldvalue;
	    ctxt->state->endvalue = oldend;
	    break;
        }
        case XML_RELAXNG_ONEORMORE:
	    ret = xmlRelaxNGValidateValueList(ctxt, define->content);
	    if (ret != 0) {
		break;
	    }
	    /* no break on purpose */
        case XML_RELAXNG_ZEROORMORE: {
            xmlChar *cur, *temp;

	    oldflags = ctxt->flags;
	    ctxt->flags |= FLAGS_IGNORABLE;
	    cur = ctxt->state->value;
	    temp = NULL;
	    while ((cur != NULL) && (cur != ctxt->state->endvalue) &&
		   (temp != cur)) {
		temp = cur;
		ret = xmlRelaxNGValidateValueList(ctxt, define->content);
		if (ret != 0) {
		    ctxt->state->value = temp;
		    ret = 0;
		    break;
		}
		cur = ctxt->state->value;
	    }
	    ctxt->flags = oldflags;
	    break;
	}
	default:
	    TODO
	    ret = -1;
    }
    return(ret);
}

/**
 * xmlRelaxNGValidateValueContent:
 * @ctxt:  a Relax-NG validation context
 * @defines:  the list of definitions to verify
 *
 * Validate the given definitions for the current value
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateValueContent(xmlRelaxNGValidCtxtPtr ctxt, 
	                       xmlRelaxNGDefinePtr defines) {
    int ret = 0;

    while (defines != NULL) {
	ret = xmlRelaxNGValidateValue(ctxt, defines);
	if (ret != 0)
	    break;
	defines = defines->next;
    }
    return(ret);
}

/**
 * xmlRelaxNGAttributeMatch:
 * @ctxt:  a Relax-NG validation context
 * @define:  the definition to check
 * @prop:  the attribute
 *
 * Check if the attribute matches the definition nameClass
 *
 * Returns 1 if the attribute matches, 0 if no, or -1 in case of error
 */
static int
xmlRelaxNGAttributeMatch(xmlRelaxNGValidCtxtPtr ctxt, 
	                 xmlRelaxNGDefinePtr define,
			 xmlAttrPtr prop) {
    int ret;

    if (define->name != NULL) {
	if (!xmlStrEqual(define->name, prop->name))
	    return(0);
    }
    if (define->ns != NULL) {
	if (define->ns[0] == 0) {
	    if (prop->ns != NULL)
		return(0);
	} else {
	    if ((prop->ns == NULL) ||
		(!xmlStrEqual(define->ns, prop->ns->href)))
		return(0);
	}
    }
    if (define->nameClass == NULL)
	return(1);
    define = define->nameClass;
    if (define->type == XML_RELAXNG_EXCEPT) {
	xmlRelaxNGDefinePtr list;

	list = define->content;
	while (list != NULL) {
	    ret = xmlRelaxNGAttributeMatch(ctxt, list, prop);
	    if (ret == 1)
		return(0);
	    if (ret < 0)
		return(ret);
	    list = list->next;
	}
    } else {
	TODO
    }
    return(1);
}

/**
 * xmlRelaxNGValidateAttribute:
 * @ctxt:  a Relax-NG validation context
 * @define:  the definition to verify
 *
 * Validate the given attribute definition for that node
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateAttribute(xmlRelaxNGValidCtxtPtr ctxt, 
	                    xmlRelaxNGDefinePtr define) {
    int ret = 0, i;
    xmlChar *value, *oldvalue;
    xmlAttrPtr prop = NULL, tmp;

    if (ctxt->state->nbAttrLeft <= 0)
	return(-1);
    if (define->name != NULL) {
        for (i = 0;i < ctxt->state->nbAttrs;i++) {
	    tmp = ctxt->state->attrs[i];
	    if ((tmp != NULL) && (xmlStrEqual(define->name, tmp->name))) {
		if ((((define->ns == NULL) || (define->ns[0] == 0)) &&
		     (tmp->ns == NULL)) ||
		    ((tmp->ns != NULL) &&
		     (xmlStrEqual(define->ns, tmp->ns->href)))) {
		    prop = tmp;
		    break;
		}
	    }
	}
	if (prop != NULL) {
	    value = xmlNodeListGetString(prop->doc, prop->children, 1);
	    oldvalue = ctxt->state->value;
	    ctxt->state->value = value;
	    ctxt->state->endvalue = NULL;
	    ret = xmlRelaxNGValidateValueContent(ctxt, define->content);
	    if (ctxt->state->value != NULL)
		value = ctxt->state->value;
	    if (value != NULL)
		xmlFree(value);
	    ctxt->state->value = oldvalue;
	    if (ret == 0) {
		/*
		 * flag the attribute as processed
		 */
		ctxt->state->attrs[i] = NULL;
		ctxt->state->nbAttrLeft--;
	    }
	} else {
	    ret = -1;
	}
#ifdef DEBUG
	xmlGenericError(xmlGenericErrorContext,
                    "xmlRelaxNGValidateAttribute(%s): %d\n", define->name, ret);
#endif
    } else {
        for (i = 0;i < ctxt->state->nbAttrs;i++) {
	    tmp = ctxt->state->attrs[i];
	    if ((tmp != NULL) &&
		(xmlRelaxNGAttributeMatch(ctxt, define, tmp) == 1)) {
		prop = tmp;
		break;
	    }
	}
	if (prop != NULL) {
	    value = xmlNodeListGetString(prop->doc, prop->children, 1);
	    oldvalue = ctxt->state->value;
	    ctxt->state->value = value;
	    ret = xmlRelaxNGValidateValueContent(ctxt, define->content);
	    if (ctxt->state->value != NULL)
		value = ctxt->state->value;
	    if (value != NULL)
		xmlFree(value);
	    ctxt->state->value = oldvalue;
	    if (ret == 0) {
		/*
		 * flag the attribute as processed
		 */
		ctxt->state->attrs[i] = NULL;
		ctxt->state->nbAttrLeft--;
	    }
	} else {
	    ret = -1;
	}
#ifdef DEBUG
	if (define->ns != NULL) {
	    xmlGenericError(xmlGenericErrorContext,
			"xmlRelaxNGValidateAttribute(nsName ns = %s): %d\n",
			    define->ns, ret);
	} else {
	    xmlGenericError(xmlGenericErrorContext,
			"xmlRelaxNGValidateAttribute(anyName): %d\n",
			    ret);
	}
#endif
    }
    
    return(ret);
}

/**
 * xmlRelaxNGValidateAttributeList:
 * @ctxt:  a Relax-NG validation context
 * @define:  the list of definition to verify
 *
 * Validate the given node against the list of attribute definitions
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateAttributeList(xmlRelaxNGValidCtxtPtr ctxt, 
	                        xmlRelaxNGDefinePtr defines) {
    int ret = 0;
    while (defines != NULL) {
	if (xmlRelaxNGValidateAttribute(ctxt, defines) != 0)
	    ret = -1;
        defines = defines->next;
    }
    return(ret);
}

/**
 * xmlRelaxNGValidateTryPermutation:
 * @ctxt:  a Relax-NG validation context
 * @groups:  the array of groups
 * @nbgroups:  the number of groups in the array
 * @array:  the permutation to try
 * @len:  the size of the set
 *
 * Try to validate a permutation for the group of definitions.
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateTryPermutation(xmlRelaxNGValidCtxtPtr ctxt, 
			    xmlRelaxNGDefinePtr rule,
			    xmlNodePtr *array, int len) {
    int i, ret;

    if (len > 0) {
	/*
	 * One only need the next pointer set-up to do the validation
	 */
	for (i = 0;i < (len - 1);i++)
	    array[i]->next = array[i + 1];
	array[i]->next = NULL;

	/*
	 * Now try to validate the sequence
	 */
	ctxt->state->seq = array[0];
	ret = xmlRelaxNGValidateDefinition(ctxt, rule);
    } else {
	ctxt->state->seq = NULL;
	ret = xmlRelaxNGValidateDefinition(ctxt, rule);
    }

    /*
     * the sequence must be fully consumed
     */
    if (ctxt->state->seq != NULL)
	return(-1);

    return(ret);
}

/**
 * xmlRelaxNGValidateWalkPermutations:
 * @ctxt:  a Relax-NG validation context
 * @groups:  the array of groups
 * @nbgroups:  the number of groups in the array
 * @nodes:  the set of nodes
 * @array:  the current state of the parmutation
 * @len:  the size of the set
 * @level:  a pointer to the level variable
 * @k:  the index in the array to fill
 *
 * Validate a set of nodes for a groups of definitions, will try the
 * full set of permutations
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateWalkPermutations(xmlRelaxNGValidCtxtPtr ctxt, 
			    xmlRelaxNGDefinePtr rule, xmlNodePtr *nodes,
			    xmlNodePtr *array, int len,
			    int *level, int k) {
    int i, ret;

    if ((k >= 0) && (k < len))
	array[k] = nodes[*level];
    *level = *level + 1;
    if (*level == len) {
	ret = xmlRelaxNGValidateTryPermutation(ctxt, rule, array, len);
	if (ret == 0)
	    return(0);
    } else {
	for (i = 0;i < len;i++) {
	    if (array[i] == NULL) {
		ret = xmlRelaxNGValidateWalkPermutations(ctxt, rule,
				    nodes, array, len, level, i);
	        if (ret == 0)
		    return(0);
	    }
	}
    }
    *level = *level - 1;
    array[k] = NULL;
    return(-1);
}

/**
 * xmlRelaxNGNodeMatchesList:
 * @node:  the node
 * @list:  a NULL terminated array of definitions
 *
 * Check if a node can be matched by one of the definitions
 *
 * Returns 1 if matches 0 otherwise
 */
static int
xmlRelaxNGNodeMatchesList(xmlNodePtr node, xmlRelaxNGDefinePtr *list) {
    xmlRelaxNGDefinePtr cur;
    int i = 0;

    if ((node == NULL) || (list == NULL))
	return(0);

    cur = list[i++];
    while (cur != NULL) {
	if ((node->type == XML_ELEMENT_NODE) &&
	    (cur->type == XML_RELAXNG_ELEMENT)) {
	    if (cur->name == NULL) {
		if ((node->ns != NULL) &&
		    (xmlStrEqual(node->ns->href, cur->ns)))
		    return(1);
	    } else if (xmlStrEqual(cur->name, node->name)) {
		if ((cur->ns == NULL) || (cur->ns[0] == 0)) {
		    if (node->ns == NULL)
			return(1);
		} else {
		    if ((node->ns != NULL) &&
			(xmlStrEqual(node->ns->href, cur->ns)))
			return(1);
		}
	    }
	} else if ((node->type == XML_TEXT_NODE) &&
		   (cur->type == XML_RELAXNG_TEXT)) {
	    return(1);
	}
	cur = list[i++];
    }
    return(0);
}

/**
 * xmlRelaxNGValidatePartGroup:
 * @ctxt:  a Relax-NG validation context
 * @groups:  the array of groups
 * @nbgroups:  the number of groups in the array
 * @nodes:  the set of nodes
 * @len:  the size of the set of nodes
 *
 * Validate a set of nodes for a groups of definitions
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidatePartGroup(xmlRelaxNGValidCtxtPtr ctxt, 
			    xmlRelaxNGInterleaveGroupPtr *groups,
			    int nbgroups, xmlNodePtr *nodes, int len) {
    int level, ret = -1, i, j, k, top_j, max_j;
    xmlNodePtr *array = NULL, *list, oldseq;
    xmlRelaxNGInterleaveGroupPtr group;

    list = (xmlNodePtr *) xmlMalloc(len * sizeof(xmlNodePtr));
    if (list == NULL) {
	return(-1);
    }
    array = (xmlNodePtr *) xmlMalloc(len * sizeof(xmlNodePtr));
    if (array == NULL) {
	xmlFree(list);
	return(-1);
    }
    memset(array, 0, len * sizeof(xmlNodePtr));

    /*
     * Partition the elements and validate the subsets.
     */
    oldseq = ctxt->state->seq;
    max_j = -1;
    for (i = 0;i < nbgroups;i++) {
	group = groups[i];
	if (group == NULL)
	    continue;
	k = 0;
	top_j = -1;
	for (j = 0;j < len;j++) {
	    if (nodes[j] == NULL)
		continue;
	    if (xmlRelaxNGNodeMatchesList(nodes[j], group->defs)) {
		list[k++] = nodes[j];
		nodes[j] = NULL;
		top_j = j;
	    }
	}
	if (top_j > max_j)
	    max_j = top_j;
	ctxt->state->seq = oldseq;
	if (k > 1) {
	    memset(array, 0, k * sizeof(xmlNodePtr));
	    level = -1;
	    ret = xmlRelaxNGValidateWalkPermutations(ctxt, group->rule,
					  list, array, k, &level, -1);
	} else {
            ret = xmlRelaxNGValidateTryPermutation(ctxt, group->rule, list, k);
	}
	if (ret != 0) {
	    ctxt->state->seq = oldseq;
	    break;
	}
    }

    for (j = 0;j < max_j;j++) {
	if (nodes[j] != NULL) {
	    TODO /* problem, one of the nodes didn't got a match */
	}
    }
    if (ret == 0) {
	if (max_j + 1 < len)
	    ctxt->state->seq = nodes[max_j + 1];
	else
	    ctxt->state->seq = NULL;
    }

    xmlFree(list);
    xmlFree(array);
    return(ret);
}

/**
 * xmlRelaxNGValidateInterleave:
 * @ctxt:  a Relax-NG validation context
 * @define:  the definition to verify
 *
 * Validate an interleave definition for a node.
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateInterleave(xmlRelaxNGValidCtxtPtr ctxt, 
	                     xmlRelaxNGDefinePtr define) {
    int ret = 0, nbchildren, nbtot, i, j;
    xmlRelaxNGPartitionPtr partitions;
    xmlNodePtr *children = NULL;
    xmlNodePtr *order = NULL;
    xmlNodePtr cur, oldseq;

    if (define->data != NULL) {
	partitions = (xmlRelaxNGPartitionPtr) define->data;
    } else {
	VALID_CTXT();
	VALID_ERROR("Internal: interleave block has no data\n");
	return(-1);
    }

    /*
     * Build the sequence of child and an array preserving the children
     * initial order.
     */
    cur = ctxt->state->seq;
    oldseq = ctxt->state->seq;
    nbchildren = 0;
    nbtot = 0;
    while (cur != NULL) {
	if ((cur->type == XML_COMMENT_NODE) ||
	    (cur->type == XML_PI_NODE) ||
	    ((cur->type == XML_TEXT_NODE) &&
	     (IS_BLANK_NODE(cur)))) {
	    nbtot++;
	} else {
	    nbchildren++;
	    nbtot++;
	}
	cur = cur->next;
    }
    children = (xmlNodePtr *) xmlMalloc(nbchildren * sizeof(xmlNodePtr));
    if (children == NULL)
	goto error;
    order = (xmlNodePtr *) xmlMalloc(nbtot * sizeof(xmlNodePtr));
    if (order == NULL)
	goto error;
    cur = ctxt->state->seq;
    i = 0;
    j = 0;
    while (cur != NULL) {
	if ((cur->type == XML_COMMENT_NODE) ||
	    (cur->type == XML_PI_NODE) ||
	    ((cur->type == XML_TEXT_NODE) &&
	     (IS_BLANK_NODE(cur)))) {
	    order[j++] = cur;
	} else {
	    order[j++] = cur;
	    children[i++] = cur;
	}
	cur = cur->next;
    }

    /* TODO: retry with a maller set of child if there is a next... */
    ret = xmlRelaxNGValidatePartGroup(ctxt, partitions->groups,
	        partitions->nbgroups, children, nbchildren);
    if (ret != 0)
	ctxt->state->seq = oldseq;

    /*
     * Cleanup: rebuid the child sequence and free the structure
     */
    if (order != NULL) {
	for (i = 0;i < nbtot;i++) {
	    if (i == 0)
		order[i]->prev = NULL;
	    else
		order[i]->prev = order[i - 1];
	    if (i == nbtot - 1)
		order[i]->next = NULL;
	    else
		order[i]->next = order[i + 1];
	}
	xmlFree(order);
    }
    if (children != NULL)
	xmlFree(children);

    return(ret);

error:
    if (order != NULL) {
	for (i = 0;i < nbtot;i++) {
	    if (i == 0)
		order[i]->prev = NULL;
	    else
		order[i]->prev = order[i - 1];
	    if (i == nbtot - 1)
		order[i]->next = NULL;
	    else
		order[i]->next = order[i + 1];
	}
	xmlFree(order);
    }
    if (children != NULL)
	xmlFree(children);
    return(-1);
}

/**
 * xmlRelaxNGValidateElementContent:
 * @ctxt:  a Relax-NG validation context
 * @define:  the list of definition to verify
 *
 * Validate the given node content against the (list) of definitions
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateElementContent(xmlRelaxNGValidCtxtPtr ctxt, 
	                  xmlRelaxNGDefinePtr defines) {
    int ret = 0, res;

    if (ctxt->state == NULL) {
	VALID_CTXT();
	VALID_ERROR("Internal: no state\n");
	return(-1);
    }
    while (defines != NULL) {
	res = xmlRelaxNGValidateDefinition(ctxt, defines);
	if (res < 0)
	    ret = -1;
	defines = defines->next;
    }

    return(ret);
}

/**
 * xmlRelaxNGValidateDefinition:
 * @ctxt:  a Relax-NG validation context
 * @define:  the definition to verify
 *
 * Validate the current node against the definition
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateDefinition(xmlRelaxNGValidCtxtPtr ctxt, 
	                     xmlRelaxNGDefinePtr define) {
    xmlNodePtr node;
    int ret = 0, i, tmp, oldflags;
    xmlRelaxNGValidStatePtr oldstate, state;

    if (define == NULL) {
	VALID_CTXT();
	VALID_ERROR("internal error: define == NULL\n");
	return(-1);
    }
    if (ctxt->state != NULL) {
	node = ctxt->state->seq;
    } else {
	node = NULL;
    }
#ifdef DEBUG
    for (i = 0;i < ctxt->depth;i++)
	xmlGenericError(xmlGenericErrorContext, " ");
    xmlGenericError(xmlGenericErrorContext,
	    "Start validating %s ", xmlRelaxNGDefName(define));
    if (define->name != NULL)
	xmlGenericError(xmlGenericErrorContext, "%s ", define->name);
    if ((node != NULL) && (node->name != NULL))
	xmlGenericError(xmlGenericErrorContext, "on %s\n", node->name);
    else
	xmlGenericError(xmlGenericErrorContext, "\n");
#endif
    ctxt->depth++;
    switch (define->type) {
        case XML_RELAXNG_EMPTY:
	    if (node != NULL) {
		VALID_CTXT();
		VALID_ERROR("Expecting an empty element\n");
		ret = -1;
		break;
	    }
	    ret = 0;
	    break;
        case XML_RELAXNG_NOT_ALLOWED:
	    ret = -1;
	    break;
        case XML_RELAXNG_TEXT:
	    if (node == NULL) {
		ret = 0;
		break;
	    }
	    while ((node != NULL) &&
		   ((node->type == XML_TEXT_NODE) ||
		    (node->type == XML_COMMENT_NODE) ||
		    (node->type == XML_PI_NODE) ||
		    (node->type == XML_CDATA_SECTION_NODE)))
		node = node->next;
	    if (node == ctxt->state->seq) {
		VALID_CTXT();
		VALID_ERROR("Expecting text content\n");
		ret = -1;
	    }
	    ctxt->state->seq = node;
	    break;
        case XML_RELAXNG_ELEMENT:
	    node = xmlRelaxNGSkipIgnored(ctxt, node);
	    if (node == NULL) {
		VALID_CTXT();
		VALID_ERROR("Expecting an element, got empty\n");
		ret = -1;
		break;
	    }
	    if (node->type != XML_ELEMENT_NODE) {
		VALID_CTXT();
		VALID_ERROR2("Expecting an element got %d type\n", node->type);
		ret = -1;
		break;
	    }
	    /*
	     * This node was already validated successfully against
	     * this definition.
	     */
	    if (node->_private == define)
		break;
	    if (define->name != NULL) {
		if (!xmlStrEqual(node->name, define->name)) {
		    VALID_CTXT();
		    VALID_ERROR3("Expecting element %s, got %s\n",
			        define->name, node->name);
		    ret = -1;
		    break;
		}
	    }
	    if ((define->ns != NULL) && (define->ns[0] != 0)) {
		if (node->ns == NULL) {
		    VALID_CTXT();
		    VALID_ERROR2("Expecting a namespace for element %s\n",
			        node->name);
		    ret = -1;
		    break;
		} else if (!xmlStrEqual(node->ns->href, define->ns)) {
		    VALID_CTXT();
		    VALID_ERROR3("Expecting element %s has wrong namespace: expecting %s\n",
			        node->name, define->ns);
		    ret = -1;
		    break;
		}
	    } else if (define->name != NULL) {
		if (node->ns != NULL) {
		    VALID_CTXT();
		    VALID_ERROR2("Expecting no namespace for element %s\n",
			        define->name);
		    ret = -1;
		    break;
		}
	    }
	    
	    state = xmlRelaxNGNewValidState(ctxt, node);
	    if (state == NULL) {
		ret = -1;
		break;
	    }

	    oldstate = ctxt->state;
	    ctxt->state = state;
	    if (define->attrs != NULL) {
		tmp = xmlRelaxNGValidateAttributeList(ctxt, define->attrs);
		if (tmp != 0) {
		    ret = -1;
#ifdef DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"E: Element %s failed to validate attributes\n",
		            node->name);
#endif
		}
	    }
	    if (define->content != NULL) {
		tmp = xmlRelaxNGValidateElementContent(ctxt, define->content);
		if (tmp != 0) {
		    ret = -1;
#ifdef DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"E: Element %s failed to validate element content\n",
		            node->name);
#endif
		}
	    }
	    state = ctxt->state;
	    if (state->seq != NULL) {
		state->seq = xmlRelaxNGSkipIgnored(ctxt, state->seq);
		if (state->seq != NULL) {
		    VALID_CTXT();
		    VALID_ERROR3("Extra content for element %s: %s\n",
				node->name, state->seq->name);
		    ret = -1;
#ifdef DEBUG
		    xmlGenericError(xmlGenericErrorContext,
			"E: Element %s has extra content: %s\n",
		            node->name, state->seq->name);
#endif
		}
	    }
	    for (i = 0;i < state->nbAttrs;i++) {
		if (state->attrs[i] != NULL) {
		    VALID_CTXT();
		    VALID_ERROR3("Invalid attribute %s for element %s\n",
				state->attrs[i]->name, node->name);
		    ret = -1;
		}
	    }
	    ctxt->state = oldstate;
	    xmlRelaxNGFreeValidState(state);
	    if (oldstate != NULL)
		oldstate->seq = xmlRelaxNGSkipIgnored(ctxt, node->next);
	    if (ret == 0)
		node->_private = define;


#ifdef DEBUG
	    xmlGenericError(xmlGenericErrorContext,
                    "xmlRelaxNGValidateDefinition(): validated %s : %d",
		            node->name, ret);
	    if (oldstate == NULL)
		xmlGenericError(xmlGenericErrorContext, ": no state\n");
	    else if (oldstate->seq == NULL)
		xmlGenericError(xmlGenericErrorContext, ": done\n");
	    else if (oldstate->seq->type == XML_ELEMENT_NODE)
		xmlGenericError(xmlGenericErrorContext, ": next elem %s\n",
			oldstate->seq->name);
	    else
		xmlGenericError(xmlGenericErrorContext, ": next %s %d\n",
			oldstate->seq->name, oldstate->seq->type);
#endif
	    break;
        case XML_RELAXNG_OPTIONAL:
	    oldflags = ctxt->flags;
	    ctxt->flags |= FLAGS_IGNORABLE;
	    oldstate = xmlRelaxNGCopyValidState(ctxt, ctxt->state);
	    ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
	    if (ret != 0) {
		xmlRelaxNGFreeValidState(ctxt->state);
		ctxt->state = oldstate;
		ret = 0;
		break;
	    }
	    xmlRelaxNGFreeValidState(oldstate);
	    ctxt->flags = oldflags;
	    ret = 0;
	    break;
        case XML_RELAXNG_ONEORMORE:
	    ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
	    if (ret != 0) {
		break;
	    }
	    /* no break on purpose */
        case XML_RELAXNG_ZEROORMORE: {
	    oldflags = ctxt->flags;
	    ctxt->flags |= FLAGS_IGNORABLE;
	    while (ctxt->state->nbAttrLeft != 0) {
		oldstate = xmlRelaxNGCopyValidState(ctxt, ctxt->state);
		ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
		if (ret != 0) {
		    xmlRelaxNGFreeValidState(ctxt->state);
		    ctxt->state = oldstate;
		    break;
		}
		xmlRelaxNGFreeValidState(oldstate);
	    }
	    if (ret == 0) {
		/*
		 * There is no attribute left to be consumed,
		 * we can check the closure by looking at ctxt->state->seq
		 */
		xmlNodePtr cur, temp;

		cur = ctxt->state->seq;
		temp = NULL;
		while ((cur != NULL) && (temp != cur)) {
		    temp = cur;
		    oldstate = xmlRelaxNGCopyValidState(ctxt, ctxt->state);
		    ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
		    if (ret != 0) {
			xmlRelaxNGFreeValidState(ctxt->state);
			ctxt->state = oldstate;
			break;
		    }
		    xmlRelaxNGFreeValidState(oldstate);
		    cur = ctxt->state->seq;
		}
	    }
	    ctxt->flags = oldflags;
	    ret = 0;
	    break;
	}
        case XML_RELAXNG_CHOICE: {
	    xmlRelaxNGDefinePtr list = define->content;

	    oldflags = ctxt->flags;
	    ctxt->flags |= FLAGS_IGNORABLE;

	    while (list != NULL) {
		oldstate = xmlRelaxNGCopyValidState(ctxt, ctxt->state);
		ret = xmlRelaxNGValidateDefinition(ctxt, list);
		if (ret == 0) {
		    xmlRelaxNGFreeValidState(oldstate);
		    break;
		}
		xmlRelaxNGFreeValidState(ctxt->state);
		ctxt->state = oldstate;
		list = list->next;
	    }
	    ctxt->flags = oldflags;
	    break;
	}
        case XML_RELAXNG_DEF:
        case XML_RELAXNG_GROUP: {
	    xmlRelaxNGDefinePtr list = define->content;

	    while (list != NULL) {
		ret = xmlRelaxNGValidateDefinition(ctxt, list);
		if (ret != 0)
		    break;
		list = list->next;
	    }
	    break;
	}
        case XML_RELAXNG_INTERLEAVE:
	    ret = xmlRelaxNGValidateInterleave(ctxt, define);
	    break;
        case XML_RELAXNG_ATTRIBUTE:
	    ret = xmlRelaxNGValidateAttribute(ctxt, define);
	    break;
        case XML_RELAXNG_REF:
        case XML_RELAXNG_PARENTREF:
	case XML_RELAXNG_EXTERNALREF:
	    ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
	    break;
        case XML_RELAXNG_DATATYPE: {
	    xmlChar *content;

	    content = xmlNodeGetContent(node);
	    ret = xmlRelaxNGValidateDatatype(ctxt, content, define);
	    if (ret == -1) {
		VALID_CTXT();
		VALID_ERROR2("internal error validating %s\n", define->name);
	    } else if (ret == 0) {
		if (node != NULL)
		    ctxt->state->seq = node->next;
		else
		    ctxt->state->seq = NULL;
	    }
	    /*
	     * TODO cover the problems with
	     * <p>12<!-- comment -->34</p>
	     * TODO detect full element coverage at compilation time.
	     */
	    if ((node != NULL) && (node->next != NULL)) {
		VALID_CTXT();
		VALID_ERROR2("The data does not cover the full element %s\n",
			    node->parent->name);
		ret = -1;
	    }
	    if (content != NULL)
		xmlFree(content);
	    break;
	}
        case XML_RELAXNG_VALUE: {
	    xmlChar *content;
	    xmlChar *oldvalue;

	    content = xmlNodeGetContent(node);
	    oldvalue = ctxt->state->value;
	    ctxt->state->value = content;
	    ret = xmlRelaxNGValidateValue(ctxt, define);
	    ctxt->state->value = oldvalue;
	    if (ret == -1) {
		VALID_CTXT();
		VALID_ERROR2("internal error validating %s\n", define->name);
	    } else if (ret == 0) {
		ctxt->state->seq = node->next;
	    }
	    /*
	     * TODO cover the problems with
	     * <p>12<!-- comment -->34</p>
	     * TODO detect full element coverage at compilation time.
	     */
	    if ((node != NULL) && (node->next != NULL)) {
		VALID_CTXT();
		VALID_ERROR2("The value does not cover the full element %s\n",
			    node->parent->name);
		ret = -1;
	    }
	    if (content != NULL)
		xmlFree(content);
	    break;
	}
        case XML_RELAXNG_LIST: {
	    xmlChar *content;
	    xmlChar *oldvalue, *oldendvalue;
	    int len;

	    content = xmlNodeGetContent(node);
	    len = xmlStrlen(content);
	    oldvalue = ctxt->state->value;
	    oldendvalue = ctxt->state->endvalue;
	    ctxt->state->value = content;
	    ctxt->state->endvalue = content + len;
	    ret = xmlRelaxNGValidateValue(ctxt, define);
	    ctxt->state->value = oldvalue;
	    ctxt->state->endvalue = oldendvalue;
	    if (ret == -1) {
		VALID_CTXT();
		VALID_ERROR("internal error validating list\n");
	    } else if (ret == 0) {
		ctxt->state->seq = node->next;
	    }
	    /*
	     * TODO cover the problems with
	     * <p>12<!-- comment -->34</p>
	     * TODO detect full element coverage at compilation time.
	     */
	    if ((node != NULL) && (node->next != NULL)) {
		VALID_CTXT();
		VALID_ERROR2("The list does not cover the full element %s\n",
			    node->parent->name);
		ret = -1;
	    }
	    if (content != NULL)
		xmlFree(content);
	    break;
        }
	case XML_RELAXNG_START:
	case XML_RELAXNG_EXCEPT:
	    TODO
	    break;
    }
    ctxt->depth--;
#ifdef DEBUG
    for (i = 0;i < ctxt->depth;i++)
	xmlGenericError(xmlGenericErrorContext, " ");
    xmlGenericError(xmlGenericErrorContext,
	    "Validating %s ", xmlRelaxNGDefName(define));
    if (define->name != NULL)
	xmlGenericError(xmlGenericErrorContext, "%s ", define->name);
    if (ret == 0)
	xmlGenericError(xmlGenericErrorContext, "suceeded\n");
    else
	xmlGenericError(xmlGenericErrorContext, "failed\n");
#endif
    return(ret);
}

/**
 * xmlRelaxNGValidateDocument:
 * @ctxt:  a Relax-NG validation context
 * @doc:  the document
 *
 * Validate the given document
 *
 * Returns 0 if the validation succeeded or an error code.
 */
static int
xmlRelaxNGValidateDocument(xmlRelaxNGValidCtxtPtr ctxt, xmlDocPtr doc) {
    int ret;
    xmlRelaxNGPtr schema;
    xmlRelaxNGGrammarPtr grammar;
    xmlRelaxNGValidStatePtr state;

    if ((ctxt == NULL) || (ctxt->schema == NULL) || (doc == NULL))
	return(-1);

    schema = ctxt->schema;
    grammar = schema->topgrammar;
    if (grammar == NULL) {
	VALID_CTXT();
	VALID_ERROR("No top grammar defined\n");
	return(-1);
    }
    state = xmlRelaxNGNewValidState(ctxt, NULL);
    ctxt->state = state;
    ret = xmlRelaxNGValidateDefinition(ctxt, grammar->start);
    state = ctxt->state;
    if ((state != NULL) && (state->seq != NULL)) {
	xmlNodePtr node;

	node = state->seq;
	node = xmlRelaxNGSkipIgnored(ctxt, node);
	if (node != NULL) {
	    VALID_CTXT();
	    VALID_ERROR("extra data on the document\n");
	    ret = -1;
	}
    }
    xmlRelaxNGFreeValidState(state);

    return(ret);
}

/************************************************************************
 * 									*
 * 			Validation interfaces				*
 * 									*
 ************************************************************************/
/**
 * xmlRelaxNGNewValidCtxt:
 * @schema:  a precompiled XML RelaxNGs
 *
 * Create an XML RelaxNGs validation context based on the given schema
 *
 * Returns the validation context or NULL in case of error
 */
xmlRelaxNGValidCtxtPtr
xmlRelaxNGNewValidCtxt(xmlRelaxNGPtr schema) {
    xmlRelaxNGValidCtxtPtr ret;

    ret = (xmlRelaxNGValidCtxtPtr) xmlMalloc(sizeof(xmlRelaxNGValidCtxt));
    if (ret == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"Failed to allocate new schama validation context\n");
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGValidCtxt));
    ret->schema = schema;
    ret->error = xmlGenericError;
    ret->userData = xmlGenericErrorContext;
    return (ret);
}

/**
 * xmlRelaxNGFreeValidCtxt:
 * @ctxt:  the schema validation context
 *
 * Free the resources associated to the schema validation context
 */
void
xmlRelaxNGFreeValidCtxt(xmlRelaxNGValidCtxtPtr ctxt) {
    if (ctxt == NULL)
	return;
    xmlFree(ctxt);
}

/**
 * xmlRelaxNGSetValidErrors:
 * @ctxt:  a Relax-NG validation context
 * @err:  the error function
 * @warn: the warning function
 * @ctx: the functions context
 *
 * Set the error and warning callback informations
 */
void
xmlRelaxNGSetValidErrors(xmlRelaxNGValidCtxtPtr ctxt,
	xmlRelaxNGValidityErrorFunc err,
	xmlRelaxNGValidityWarningFunc warn, void *ctx) {
    if (ctxt == NULL)
	return;
    ctxt->error = err;
    ctxt->warning = warn;
    ctxt->userData = ctx;
}

/**
 * xmlRelaxNGValidateDoc:
 * @ctxt:  a Relax-NG validation context
 * @doc:  a parsed document tree
 *
 * Validate a document tree in memory.
 *
 * Returns 0 if the document is valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
int
xmlRelaxNGValidateDoc(xmlRelaxNGValidCtxtPtr ctxt, xmlDocPtr doc) {
    int ret;

    if ((ctxt == NULL) || (doc == NULL))
	return(-1);

    ctxt->doc = doc;

    ret = xmlRelaxNGValidateDocument(ctxt, doc);
    /*
     * TODO: build error codes
     */
    if (ret == -1)
	return(1);
    return(ret);
}

#endif /* LIBXML_SCHEMAS_ENABLED */

