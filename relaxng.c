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
/* #define DEBUG_LIST 1 */

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

typedef enum {
    XML_RELAXNG_CONTENT_ERROR = -1,
    XML_RELAXNG_CONTENT_EMPTY = 0,
    XML_RELAXNG_CONTENT_SIMPLE,
    XML_RELAXNG_CONTENT_COMPLEX
} xmlRelaxNGContentType;

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
    XML_RELAXNG_NOOP = -1,	/* a no operation from simplification  */
    XML_RELAXNG_EMPTY = 0,	/* an empty pattern */
    XML_RELAXNG_NOT_ALLOWED,    /* not allowed top */
    XML_RELAXNG_EXCEPT,    	/* except present in nameclass defs */
    XML_RELAXNG_TEXT,		/* textual content */
    XML_RELAXNG_ELEMENT,	/* an element */
    XML_RELAXNG_DATATYPE,	/* extenal data type definition */
    XML_RELAXNG_PARAM,		/* extenal data type parameter */
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
    int            depth;       /* used for the cycle detection */
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

#define XML_RELAXNG_IN_ATTRIBUTE	(1 << 0)
#define XML_RELAXNG_IN_ONEORMORE	(1 << 1)
#define XML_RELAXNG_IN_LIST		(1 << 2)
#define XML_RELAXNG_IN_DATAEXCEPT	(1 << 3)
#define XML_RELAXNG_IN_START		(1 << 4)
#define XML_RELAXNG_IN_OOMGROUP		(1 << 5)
#define XML_RELAXNG_IN_OOMINTERLEAVE	(1 << 6)
#define XML_RELAXNG_IN_EXTERNALREF	(1 << 7)
#define XML_RELAXNG_IN_ANYEXCEPT	(1 << 8)
#define XML_RELAXNG_IN_NSEXCEPT		(1 << 9)

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
    xmlRelaxNGIncludePtr  inc;        /* Current parsed include */
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
    xmlRelaxNGDefinePtr *attrs;	/* the array of attributes definitions */
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
static void xmlRelaxNGNormExtSpace(xmlChar *value);

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
    ret->depth = -1;
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
		    if (group->attrs != NULL)
			xmlFree(group->attrs);
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
 * xmlRelaxNGEqualValidState:
 * @ctxt:  a Relax-NG validation context
 * @state1:  a validation state
 * @state2:  a validation state
 *
 * Compare the validation states for equality
 *
 * Returns 1 if equald, 0 otherwise
 */
static int
xmlRelaxNGEqualValidState(xmlRelaxNGValidCtxtPtr ctxt ATTRIBUTE_UNUSED,
	                 xmlRelaxNGValidStatePtr state1,
			 xmlRelaxNGValidStatePtr state2)
{
    int i;

    if ((state1 == NULL) || (state2 == NULL))
	return(0);
    if (state1 == state2)
	return(1);
    if (state1->node != state2->node)
	return(0);
    if (state1->seq != state2->seq)
	return(0);
    if (state1->nbAttrLeft != state2->nbAttrLeft)
	return(0);
    if (state1->nbAttrs != state2->nbAttrs)
	return(0);
    if (state1->endvalue != state2->endvalue)
	return(0);
    if ((state1->value != state2->value) &&
	(!xmlStrEqual(state1->value, state2->value)))
	return(0);
    for (i = 0;i < state1->nbAttrs;i++) {
	if (state1->attrs[i] != state2->attrs[i])
	    return(0);
    }
    return(1);
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
 * @ns:  the namespace passed from the context.
 *
 * First lookup if the document is already loaded into the parser context,
 * check against recursion. If not found the resource is loaded and
 * the content is preprocessed before being returned back to the caller.
 *
 * Returns the xmlRelaxNGIncludePtr or NULL in case of error
 */
static xmlRelaxNGIncludePtr
xmlRelaxNGLoadInclude(xmlRelaxNGParserCtxtPtr ctxt, const xmlChar *URL,
	              xmlNodePtr node, const xmlChar *ns) {
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
	if (ns == NULL)
	    ret = xmlHashLookup2(ctxt->includes, BAD_CAST "", URL);
	else
	    ret = xmlHashLookup2(ctxt->includes, ns, URL);
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
	xmlHashAddEntry2(ctxt->includes, BAD_CAST "", URL, ret);
    else
	xmlHashAddEntry2(ctxt->includes, ns, URL, ret);
    xmlRelaxNGIncludePush(ctxt, ret);

    /*
     * Some preprocessing of the document content, this include recursing
     * in the include stack.
     */
    doc = xmlRelaxNGCleanupDoc(ctxt, doc);
    if (doc == NULL) {
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
	return (NULL);
    }
    if (!IS_RELAXNG(root, "grammar")) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		    "xmlRelaxNG: included document %s root is not a grammar\n",
		        URL);
	ctxt->nbErrors++;
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

		xmlRelaxNGNormExtSpace(name);
		tmp = root->children;
		while (tmp != NULL) {
		    tmp2 = tmp->next;
		    if (IS_RELAXNG(tmp, "define")) {
			name2 = xmlGetProp(tmp, BAD_CAST "name");
			xmlRelaxNGNormExtSpace(name2);
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

#ifdef DEBUG
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
#endif

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
    if (value == NULL)
	return(-1);
    if (xmlStrEqual(type, BAD_CAST "string"))
	return(1);
    if (xmlStrEqual(type, BAD_CAST "token")) {
#if 0
	const xmlChar *cur = value;

	while (*cur != 0) {
	    if (!IS_BLANK(*cur))
		return(1);
	    cur++;
	}
#endif
	return(1);
    }

    return(0);
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

	    if ((nval == NULL) || (nvalue == NULL))
		ret = -1;
	    else if (xmlStrEqual(nval, nvalue))
		ret = 1;
	    else
		ret = 0;
	    if (nval != NULL)
		xmlFree(nval);
	    if (nvalue != NULL)
		xmlFree(nvalue);
	} else
	    ret = 1;
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
static int xmlRelaxNGElementMatch(xmlRelaxNGValidCtxtPtr ctxt, 
	      xmlRelaxNGDefinePtr define, xmlNodePtr elem);


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
	    if (ret[0] == 0) {
		xmlFree(ret);
		return(NULL);
	    }
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
	    if (ret[0] == 0) {
		xmlFree(ret);
		return(NULL);
	    }
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
	xmlRelaxNGNormExtSpace(type);
	if (xmlValidateNCName(type, 0)) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "value type '%s' is not an NCName\n",
			    type);
	    ctxt->nbErrors++;
	}
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
	def->value = xmlStrdup(BAD_CAST "");
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
    xmlRelaxNGDefinePtr def = NULL, except, last = NULL;
    xmlRelaxNGDefinePtr param, lastparam = NULL;
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
    xmlRelaxNGNormExtSpace(type);
    if (xmlValidateNCName(type, 0)) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"data type '%s' is not an NCName\n",
			type);
	ctxt->nbErrors++;
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

    /*
     * Handle optional params
     */
    while (content != NULL) {
	if (!xmlStrEqual(content->name, BAD_CAST "param"))
	    break;
	if (xmlStrEqual(library,
		        BAD_CAST"http://relaxng.org/ns/structure/1.0")) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		"Type library '%s' does not allow type parameters\n",
			    library);
	    ctxt->nbErrors++;
	    content = content->next;
	    while ((content != NULL) &&
		   (xmlStrEqual(content->name, BAD_CAST "param")))
		content = content->next;
	} else {
	    param = xmlRelaxNGNewDefine(ctxt, node);
	    if (param != NULL) {
		param->type = XML_RELAXNG_PARAM;
		param->name = xmlGetProp(content, BAD_CAST "name");
		if (param->name == NULL) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
			    "param has no name\n");
		    ctxt->nbErrors++;
		}
		param->value = xmlNodeGetContent(content);
		if (lastparam == NULL) {
		    def->attrs = lastparam = param;
		} else {
		    lastparam->next = param;
		    lastparam = param;
		}
	    }
	    content = content->next;
	}
    }
    /*
     * Handle optional except
     */
    if ((content != NULL) && (xmlStrEqual(content->name, BAD_CAST "except"))) {
	xmlNodePtr child;
	xmlRelaxNGDefinePtr tmp2, last2 = NULL;

	except = xmlRelaxNGNewDefine(ctxt, node);
	if (except == NULL) {
	    return(def);
	}
	except->type = XML_RELAXNG_EXCEPT;
	child = content->children;
	if (last == NULL) {
	    def->content = except;
	} else {
	    last->next = except;
	}
	if (child == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "except has no content\n");
	    ctxt->nbErrors++;
	}
	while (child != NULL) {
	    tmp2 = xmlRelaxNGParsePattern(ctxt, child);
	    if (tmp2 != NULL) {
		if (last2 == NULL) {
		    except->content = last2 = tmp2;
		} else {
		    last2->next = tmp2;
		    last2 = tmp2;
		}
	    }
	    child = child->next;
	}
	content = content->next;
    }
    /*
     * Check there is no unhandled data
     */
    if (content != NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Element data has unexpected content %s\n", content->name);
	ctxt->nbErrors++;
    }

    return(def);
}

static const xmlChar *invalidName = BAD_CAST "\1";

/**
 * xmlRelaxNGCompareNameClasses:
 * @defs1:  the first element/attribute defs
 * @defs2:  the second element/attribute defs
 * @name:  the restriction on the name
 * @ns:  the restriction on the namespace
 *
 * Compare the 2 lists of element definitions. The comparison is
 * that if both lists do not accept the same QNames, it returns 1
 * If the 2 lists can accept the same QName the comparison returns 0
 *
 * Returns 1 disttinct, 0 if equal
 */
static int
xmlRelaxNGCompareNameClasses(xmlRelaxNGDefinePtr def1,
	                     xmlRelaxNGDefinePtr def2) {
    int ret = 1;
    xmlNode node;
    xmlNs ns;
    xmlRelaxNGValidCtxt ctxt;
    ctxt.flags = FLAGS_IGNORABLE;

    if ((def1->type == XML_RELAXNG_ELEMENT) ||
	(def1->type == XML_RELAXNG_ATTRIBUTE)) {
	if (def2->type == XML_RELAXNG_TEXT)
	    return(1);
	if (def1->name != NULL) {
	    node.name = def1->name;
	} else {
	    node.name = invalidName;
	}
	node.ns = &ns;
	if (def1->ns != NULL) {
	    if (def1->ns[0] == 0) {
		node.ns = NULL;
	    } else {
		ns.href = def1->ns;
	    }
	} else {
	    ns.href = invalidName;
	}
        if (xmlRelaxNGElementMatch(&ctxt, def2, &node)) {
	    if (def1->nameClass != NULL) {
		ret = xmlRelaxNGCompareNameClasses(def1->nameClass, def2);
	    } else {
		ret = 0;
	    }
	} else {
	    ret = 1;
	}
    } else if (def1->type == XML_RELAXNG_TEXT) {
	if (def2->type == XML_RELAXNG_TEXT)
	    return(0);
	return(1);
    } else if (def1->type == XML_RELAXNG_EXCEPT) {
	TODO
	ret = 0;
    } else {
	TODO
	ret = 0;
    }
    if (ret == 0)
	return(ret);
    if ((def2->type == XML_RELAXNG_ELEMENT) ||
	(def2->type == XML_RELAXNG_ATTRIBUTE)) {
	if (def2->name != NULL) {
	    node.name = def2->name;
	} else {
	    node.name = invalidName;
	}
	node.ns = &ns;
	if (def2->ns != NULL) {
	    if (def2->ns[0] == 0) {
		node.ns = NULL;
	    } else {
		ns.href = def2->ns;
	    }
	} else {
	    ns.href = invalidName;
	}
        if (xmlRelaxNGElementMatch(&ctxt, def1, &node)) {
	    if (def2->nameClass != NULL) {
		ret = xmlRelaxNGCompareNameClasses(def2->nameClass, def1);
	    } else {
		ret = 0;
	    }
	} else {
	    ret = 1;
	}
    } else {
	TODO
	ret = 0;
    }

    return(ret);
}

/**
 * xmlRelaxNGCompareElemDefLists:
 * @ctxt:  a Relax-NG parser context
 * @defs1:  the first list of element/attribute defs
 * @defs2:  the second list of element/attribute defs
 *
 * Compare the 2 lists of element or attribute definitions. The comparison
 * is that if both lists do not accept the same QNames, it returns 1
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
	    if (xmlRelaxNGCompareNameClasses(*def1, *def2) == 0)
		return(0);
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
 * @def:  the definition definition
 * @eora:  gather elements (0) or attributes (1)
 *
 * Compute the list of top elements a definition can generate
 *
 * Returns a list of elements or NULL if none was found.
 */
static xmlRelaxNGDefinePtr *
xmlRelaxNGGetElements(xmlRelaxNGParserCtxtPtr ctxt,
	              xmlRelaxNGDefinePtr def,
		      int eora) {
    xmlRelaxNGDefinePtr *ret = NULL, parent, cur, tmp;
    int len = 0;
    int max = 0;

    /*
     * Don't run that check in case of error. Infinite recursion
     * becomes possible.
     */
    if (ctxt->nbErrors != 0)
	return(NULL);

    parent = NULL;
    cur = def;
    while (cur != NULL) {
	if (((eora == 0) && ((cur->type == XML_RELAXNG_ELEMENT) ||
	     (cur->type == XML_RELAXNG_TEXT))) ||
	    ((eora == 1) && (cur->type == XML_RELAXNG_ATTRIBUTE))) {
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
	    break;
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
 * xmlRelaxNGCheckGroupAttrs:
 * @ctxt:  a Relax-NG parser context
 * @def:  the group definition
 *
 * Detects violations of rule 7.3
 */
static void
xmlRelaxNGCheckGroupAttrs(xmlRelaxNGParserCtxtPtr ctxt,
	                  xmlRelaxNGDefinePtr def) {
    xmlRelaxNGDefinePtr **list;
    xmlRelaxNGDefinePtr cur;
    int nbchild = 0, i, j, ret;

    if ((def == NULL) ||
	((def->type != XML_RELAXNG_GROUP) &&
	 (def->type != XML_RELAXNG_ELEMENT)))
	return;

    /*
     * Don't run that check in case of error. Infinite recursion
     * becomes possible.
     */
    if (ctxt->nbErrors != 0)
	return;

    cur = def->attrs;
    while (cur != NULL) {
	nbchild++;
	cur = cur->next;
    }
    cur = def->content;
    while (cur != NULL) {
	nbchild++;
	cur = cur->next;
    }

    list = (xmlRelaxNGDefinePtr **) xmlMalloc(nbchild *
	                                      sizeof(xmlRelaxNGDefinePtr *));
    if (list == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Out of memory in group computation\n");
	ctxt->nbErrors++;
	return;
    }
    i = 0;
    cur = def->attrs;
    while (cur != NULL) {
	list[i] = xmlRelaxNGGetElements(ctxt, cur, 1);
	i++;
	cur = cur->next;
    }
    cur = def->content;
    while (cur != NULL) {
	list[i] = xmlRelaxNGGetElements(ctxt, cur, 1);
	i++;
	cur = cur->next;
    }

    for (i = 0;i < nbchild;i++) {
	if (list[i] == NULL)
	    continue;
	for (j = 0;j < i;j++) {
	    if (list[j] == NULL)
		continue;
	    ret = xmlRelaxNGCompareElemDefLists(ctxt, list[i], list[j]);
	    if (ret == 0) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Attributes conflicts in group\n");
		ctxt->nbErrors++;
	    }
	}
    }
    for (i = 0;i < nbchild;i++) {
	if (list[i] != NULL)
	    xmlFree(list[i]);
    }
    xmlFree(list);
}

/**
 * xmlRelaxNGComputeInterleaves:
 * @def:  the interleave definition
 * @ctxt:  a Relax-NG parser context
 * @name:  the definition name
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

    xmlRelaxNGPartitionPtr partitions = NULL;
    xmlRelaxNGInterleaveGroupPtr *groups = NULL;
    xmlRelaxNGInterleaveGroupPtr group;
    int i,j,ret;
    int nbgroups = 0;
    int nbchild = 0;

    /*
     * Don't run that check in case of error. Infinite recursion
     * becomes possible.
     */
    if (ctxt->nbErrors != 0)
	return;

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
	groups[nbgroups]->defs = xmlRelaxNGGetElements(ctxt, cur, 0);
	groups[nbgroups]->attrs = xmlRelaxNGGetElements(ctxt, cur, 1);
	nbgroups++;
	cur = cur->next;
    }
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
	    ret = xmlRelaxNGCompareElemDefLists(ctxt, group->attrs,
						groups[j]->attrs);
	    if (ret == 0) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Attributes conflicts in interleave\n");
		ctxt->nbErrors++;
	    }
	}
    }
    partitions->groups = groups;

    /*
     * and save the partition list back in the def
     */
    def->data = partitions;
    return;

error:
    if (ctxt->error != NULL)
	ctxt->error(ctxt->userData,
	    "Out of memory in interleave computation\n");
    ctxt->nbErrors++;
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
    if (child == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData, "Element interleave is empty\n");
	ctxt->nbErrors++;
    }
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
	xmlRelaxNGNormExtSpace(name);
	if (xmlValidateNCName(name, 0)) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "define name '%s' is not an NCName\n",
			    name);
	    ctxt->nbErrors++;
	}
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
 * xmlRelaxNGProcessExternalRef:
 * @ctxt: the parser context
 * @node:  the externlRef node
 *
 * Process and compile an externlRef node
 *
 * Returns the xmlRelaxNGDefinePtr or NULL in case of error
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGProcessExternalRef(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlRelaxNGDocumentPtr docu;
    xmlNodePtr root, tmp;
    xmlChar *ns;
    int newNs = 0, oldflags;
    xmlRelaxNGDefinePtr def;

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
	    /*
	     * ns transmission rules
	     */
	    ns = xmlGetProp(root, BAD_CAST "ns");
	    if (ns == NULL) {
		tmp = node;
		while ((tmp != NULL) &&
		       (tmp->type == XML_ELEMENT_NODE)) {
		    ns = xmlGetProp(tmp, BAD_CAST "ns");
		    if (ns != NULL) {
			break;
		    }
		    tmp = tmp->parent;
		}
		if (ns != NULL) {
		    xmlSetProp(root, BAD_CAST "ns", ns);
		    newNs = 1;
		    xmlFree(ns);
		}
	    } else {
		xmlFree(ns);
	    }

	    /*
	     * Parsing to get a precompiled schemas.
	     */
	    oldflags = ctxt->flags;
	    ctxt->flags |= XML_RELAXNG_IN_EXTERNALREF;
	    docu->schema = xmlRelaxNGParseDocument(ctxt, root);
	    ctxt->flags = oldflags;
	    if ((docu->schema != NULL) &&
		(docu->schema->topgrammar != NULL)) {
		docu->content = docu->schema->topgrammar->start;
	    }

	    /*
	     * the externalRef may be reused in a different ns context
	     */
	    if (newNs == 1) {
		xmlUnsetProp(root, BAD_CAST "ns");
	    }
	}
	def->content = docu->content;
    } else {
	def = NULL;
    }
    return(def);
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

    if (node == NULL) {
	return(NULL);
    }
    if (IS_RELAXNG(node, "element")) {
	def = xmlRelaxNGParseElement(ctxt, node);
    } else if (IS_RELAXNG(node, "attribute")) {
	def = xmlRelaxNGParseAttribute(ctxt, node);
    } else if (IS_RELAXNG(node, "empty")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_EMPTY;
	if (node->children != NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData, "empty: had a child node\n");
	    ctxt->nbErrors++;
	}
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
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Element %s is empty\n", node->name);
	    ctxt->nbErrors++;
	} else {
	    def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 1);
	} 
    } else if (IS_RELAXNG(node, "oneOrMore")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_ONEORMORE;
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Element %s is empty\n", node->name);
	    ctxt->nbErrors++;
	} else {
	    def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 1);
	} 
    } else if (IS_RELAXNG(node, "optional")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_OPTIONAL;
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Element %s is empty\n", node->name);
	    ctxt->nbErrors++;
	} else {
	    def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 1);
	} 
    } else if (IS_RELAXNG(node, "choice")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_CHOICE;
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Element %s is empty\n", node->name);
	    ctxt->nbErrors++;
	} else {
	    def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 0);
	} 
    } else if (IS_RELAXNG(node, "group")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_GROUP;
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Element %s is empty\n", node->name);
	    ctxt->nbErrors++;
	} else {
	    def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 0);
	} 
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
	    xmlRelaxNGNormExtSpace(def->name);
	    if (xmlValidateNCName(def->name, 0)) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"ref name '%s' is not an NCName\n",
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
		    if (def->name != NULL) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
				"Error refs definitions '%s'\n",
					def->name);
		    } else {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
				"Error refs definitions\n");
		    }
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
#if 0
    } else if (IS_RELAXNG(node, "define")) {
	xmlRelaxNGParseDefine(ctxt, node);
	def = NULL;
#endif
    } else if (IS_RELAXNG(node, "value")) {
	def = xmlRelaxNGParseValue(ctxt, node);
    } else if (IS_RELAXNG(node, "list")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_LIST;
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "Element %s is empty\n", node->name);
	    ctxt->nbErrors++;
	} else {
	    def->content = xmlRelaxNGParsePatterns(ctxt, node->children, 0);
	} 
    } else if (IS_RELAXNG(node, "interleave")) {
	def = xmlRelaxNGParseInterleave(ctxt, node);
    } else if (IS_RELAXNG(node, "externalRef")) {
	def = xmlRelaxNGProcessExternalRef(ctxt, node);
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
	} else {
	    xmlRelaxNGNormExtSpace(def->name);
	    if (xmlValidateNCName(def->name, 0)) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"parentRef name '%s' is not an NCName\n",
				def->name);
		ctxt->nbErrors++;
	    }
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
	} else if (def->name != NULL) {
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
    } else if (IS_RELAXNG(node, "mixed")) {
	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Mixed is empty\n");
	    ctxt->nbErrors++;
	    def = NULL;
	} else {
	    def = xmlRelaxNGParseInterleave(ctxt, node);
	    if (def != NULL) {
		xmlRelaxNGDefinePtr tmp;

		if ((def->content != NULL) && (def->content->next != NULL)) {
		    tmp = xmlRelaxNGNewDefine(ctxt, node);
		    if (tmp != NULL) {
			tmp->type = XML_RELAXNG_GROUP;
			tmp->content = def->content;
			def->content = tmp;
		    }
		}

		tmp = xmlRelaxNGNewDefine(ctxt, node);
		if (tmp == NULL)
		    return(def);
		tmp->type = XML_RELAXNG_TEXT;
		tmp->next = def->content;
		def->content = tmp;
	    }
	}
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Unexpected node %s is not a pattern\n",
			node->name);
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
    xmlRelaxNGDefinePtr ret, cur;
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

    if (child != NULL) {
	cur = xmlRelaxNGParsePattern(ctxt, child);
	if (cur != NULL) {
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
		case XML_RELAXNG_ATTRIBUTE:
		    ret->content = cur;
		    cur->parent = ret;
		    break;
		case XML_RELAXNG_START:
		case XML_RELAXNG_PARAM:
		case XML_RELAXNG_EXCEPT:
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		"attribute has invalid content\n");
		    ctxt->nbErrors++;
		    break;
		case XML_RELAXNG_NOOP:
		    TODO
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		"Internal error, noop found\n");
		    ctxt->nbErrors++;
		    break;
	    }
	}
	child = child->next;
    }
    if (child != NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData, "attribute has multiple children\n");
	ctxt->nbErrors++;
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

    if (!IS_RELAXNG(node, "except")) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"Expecting an except node\n");
	ctxt->nbErrors++;
	return(NULL);
    }
    if (node->next != NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
		"exceptNameClass allows only a single except node\n");
	ctxt->nbErrors++;
    }
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
    xmlRelaxNGDefinePtr ret, tmp;
    xmlChar *val;

    ret = def;
    if ((IS_RELAXNG(node, "name")) || (IS_RELAXNG(node, "anyName"))  ||
        (IS_RELAXNG(node, "nsName"))) {
	if ((def->type != XML_RELAXNG_ELEMENT) &&
	    (def->type != XML_RELAXNG_ATTRIBUTE)) {
	    ret = xmlRelaxNGNewDefine(ctxt, node);
	    if (ret == NULL)
		return(NULL);
	    ret->parent = def;
	    if (ctxt->flags & XML_RELAXNG_IN_ATTRIBUTE)
		ret->type = XML_RELAXNG_ATTRIBUTE;
	    else
		ret->type = XML_RELAXNG_ELEMENT;
	}
    }
    if (IS_RELAXNG(node, "name")) {
	val = xmlNodeGetContent(node);
	xmlRelaxNGNormExtSpace(val);
	if (xmlValidateNCName(val, 0)) {
	    if (ctxt->error != NULL) {
		if (node->parent != NULL)
		    ctxt->error(ctxt->userData,
			"Element %s name '%s' is not an NCName\n",
				node->parent->name, val);
		else
		    ctxt->error(ctxt->userData,
			"name '%s' is not an NCName\n",
				val);
	    }
	    ctxt->nbErrors++;
	}
	ret->name = val;
	val = xmlGetProp(node, BAD_CAST "ns");
	ret->ns = val;
	if ((ctxt->flags & XML_RELAXNG_IN_ATTRIBUTE) &&
	    (val != NULL) &&
	    (xmlStrEqual(val, BAD_CAST "http://www.w3.org/2000/xmlns"))) {
	    ctxt->error(ctxt->userData,
		"Attribute with namespace '%s' is not allowed\n",
			val);
	    ctxt->nbErrors++;
	}
	if ((ctxt->flags & XML_RELAXNG_IN_ATTRIBUTE) &&
	    (val != NULL) &&
	    (val[0] == 0) &&
	    (xmlStrEqual(ret->name, BAD_CAST "xmlns"))) {
	    ctxt->error(ctxt->userData,
		"Attribute with QName 'xmlns' is not allowed\n",
			val);
	    ctxt->nbErrors++;
	}
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
	if ((ctxt->flags & XML_RELAXNG_IN_ATTRIBUTE) &&
	    (ret->ns != NULL) &&
	    (xmlStrEqual(ret->ns, BAD_CAST "http://www.w3.org/2000/xmlns"))) {
	    ctxt->error(ctxt->userData,
		"Attribute with namespace '%s' is not allowed\n",
			ret->ns);
	    ctxt->nbErrors++;
	}
	if (node->children != NULL) {
	    ret->nameClass =
		xmlRelaxNGParseExceptNameClass(ctxt, node->children,
			       (def->type == XML_RELAXNG_ATTRIBUTE));
	}
    } else if (IS_RELAXNG(node, "choice")) {
	xmlNodePtr child;
	xmlRelaxNGDefinePtr last = NULL;

	ret = xmlRelaxNGNewDefine(ctxt, node);
	if (ret == NULL)
	    return(NULL);
	ret->parent = def;
	ret->type = XML_RELAXNG_CHOICE;

	if (node->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Element choice is empty\n");
	    ctxt->nbErrors++;
	} else {

	    child = node->children;
	    while (child != NULL) {
		tmp = xmlRelaxNGParseNameClass(ctxt, child, ret);
		if (tmp != NULL) {
		    if (last == NULL) {
			last = ret->nameClass = tmp;
		    } else {
			last->next = tmp;
			last = tmp;
		    }
		}
		child = child->next;
	    }
	}
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
    "expecting name, anyName, nsName or choice : got %s\n",
			node->name);
	ctxt->nbErrors++;
	return(NULL);
    }
    if (ret != def) {
	if (def->nameClass == NULL) {
	    def->nameClass = ret;
	} else {
	    tmp = def->nameClass;
	    while (tmp->next != NULL) {
		tmp = tmp->next;
	    }
	    tmp->next = ret;
	}
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
		case XML_RELAXNG_PARAM:
		case XML_RELAXNG_EXCEPT:
		    TODO
		    ctxt->nbErrors++;
		    break;
		case XML_RELAXNG_NOOP:
		    TODO
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
		"Internal error, noop found\n");
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
    xmlRelaxNGDefinePtr def = NULL, last;

    if (nodes == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"start has no children\n");
	ctxt->nbErrors++;
	return(-1);
    }
    if (IS_RELAXNG(nodes, "empty")) {
	def = xmlRelaxNGNewDefine(ctxt, nodes);
	if (def == NULL)
	    return(-1);
	def->type = XML_RELAXNG_EMPTY;
	if (nodes->children != NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData, "element empty is not empty\n");
	    ctxt->nbErrors++;
	}
    } else if (IS_RELAXNG(nodes, "notAllowed")) {
	def = xmlRelaxNGNewDefine(ctxt, nodes);
	if (def == NULL)
	    return(-1);
	def->type = XML_RELAXNG_NOT_ALLOWED;
	if (nodes->children != NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			"element notAllowed is not empty\n");
	    ctxt->nbErrors++;
	}
    } else {
	def = xmlRelaxNGParsePatterns(ctxt, nodes, 1);
    }
    if (ctxt->grammar->start != NULL) {
	last = ctxt->grammar->start;
	while (last->next != NULL)
	    last = last->next;
	last->next = def;
    } else {
	ctxt->grammar->start = def;
    }
    nodes = nodes->next;
    if (nodes != NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"start more than one children\n");
	ctxt->nbErrors++;
	return(-1);
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
				"start has no children\n");
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
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		"Reference %s has no matching definition\n",
			    name);
	    ctxt->nbErrors++;
	}
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
	    "Reference %s has no matching definition\n",
			name);
	ctxt->nbErrors++;
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
    xmlRelaxNGDefinePtr cur;

    starts = grammar->start;
    if ((starts == NULL) || (starts->next == NULL))
	return;
    cur = starts;
    while (cur != NULL) {
	if ((cur->node == NULL) || (cur->node->parent == NULL) ||
	    (!xmlStrEqual(cur->node->parent->name, BAD_CAST "start"))) {
	    combine = NULL;
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
		    "Internal error: start element not found\n");
	    ctxt->nbErrors++;
	} else {
	    combine = xmlGetProp(cur->node->parent, BAD_CAST "combine");
	}
	
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
	    } else if (xmlStrEqual(combine, BAD_CAST "interleave")) {
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

	cur = cur->next;
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
	cur->type = XML_RELAXNG_INTERLEAVE;
    else
	cur->type = XML_RELAXNG_CHOICE;
    cur->content = grammar->start;
    grammar->start = cur;
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
 * xmlRelaxNGCheckCycles:
 * @ctxt:  a Relax-NG parser context
 * @nodes:  grammar children nodes
 * @depth:  the counter
 *
 * Check for cycles.
 *
 * Returns 0 if check passed, and -1 in case of error
 */
static int
xmlRelaxNGCheckCycles(xmlRelaxNGParserCtxtPtr ctxt, 
	              xmlRelaxNGDefinePtr cur, int depth) {
    int ret = 0;

    while ((ret == 0) && (cur != NULL)) {
	if ((cur->type == XML_RELAXNG_REF) ||
	    (cur->type == XML_RELAXNG_PARENTREF)) {
	    if (cur->depth == -1) {
		cur->depth = depth;
		ret = xmlRelaxNGCheckCycles(ctxt, cur->content, depth);
		cur->depth = -2;
	    } else if (depth == cur->depth) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "Detected a cycle in %s references\n", cur->name);
		ctxt->nbErrors++;
		return(-1);
	    }
	} else if (cur->type == XML_RELAXNG_ELEMENT) {
	    ret = xmlRelaxNGCheckCycles(ctxt, cur->content, depth + 1);
	} else {
	    ret = xmlRelaxNGCheckCycles(ctxt, cur->content, depth);
	}
	cur = cur->next;
    }
    return(ret);
}

/**
 * xmlRelaxNGTryUnlink:
 * @ctxt:  a Relax-NG parser context
 * @cur:  the definition to unlink
 * @parent:  the parent definition
 * @prev:  the previous sibling definition
 *
 * Try to unlink a definition. If not possble make it a NOOP
 *
 * Returns the new prev definition
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGTryUnlink(xmlRelaxNGParserCtxtPtr ctxt ATTRIBUTE_UNUSED, 
	            xmlRelaxNGDefinePtr cur,
		    xmlRelaxNGDefinePtr parent,
		    xmlRelaxNGDefinePtr prev) {
    if (prev != NULL) {
	prev->next = cur->next;
    } else {
	if (parent != NULL) {
	    if (parent->content == cur)
		parent->content = cur->next;
	    else if (parent->attrs == cur)
		parent->attrs = cur->next;
	    else if (parent->nameClass == cur)
		parent->nameClass = cur->next;
	} else {
	    cur->type = XML_RELAXNG_NOOP;
	    prev = cur;
	}
    }
    return(prev);
}

/**
 * xmlRelaxNGSimplify:
 * @ctxt:  a Relax-NG parser context
 * @nodes:  grammar children nodes
 *
 * Check for simplification of empty and notAllowed
 */
static void
xmlRelaxNGSimplify(xmlRelaxNGParserCtxtPtr ctxt, 
	             xmlRelaxNGDefinePtr cur,
		     xmlRelaxNGDefinePtr parent) {
    xmlRelaxNGDefinePtr prev = NULL;

    while (cur != NULL) {
	if ((cur->type == XML_RELAXNG_REF) ||
	    (cur->type == XML_RELAXNG_PARENTREF)) {
	    if (cur->depth != -3) {
		cur->depth = -3;
		xmlRelaxNGSimplify(ctxt, cur->content, cur);
	    }
	} else if (cur->type == XML_RELAXNG_NOT_ALLOWED) {
	    cur->parent = parent;
	    if ((parent != NULL) &&
		((parent->type == XML_RELAXNG_ATTRIBUTE) ||
		 (parent->type == XML_RELAXNG_LIST) ||
		 (parent->type == XML_RELAXNG_GROUP) ||
		 (parent->type == XML_RELAXNG_INTERLEAVE) ||
		 (parent->type == XML_RELAXNG_ONEORMORE) ||
		 (parent->type == XML_RELAXNG_ZEROORMORE))) {
		parent->type = XML_RELAXNG_NOT_ALLOWED;
		break;
	    }
	    if ((parent != NULL) &&
		(parent->type == XML_RELAXNG_CHOICE)) {
		prev = xmlRelaxNGTryUnlink(ctxt, cur, parent, prev);
	    } else
		prev = cur;
	} else if (cur->type == XML_RELAXNG_EMPTY){
	    cur->parent = parent;
	    if ((parent != NULL) &&
		((parent->type == XML_RELAXNG_ONEORMORE) ||
		 (parent->type == XML_RELAXNG_ZEROORMORE))) {
		parent->type = XML_RELAXNG_EMPTY;
		break;
	    }
	    if ((parent != NULL) &&
		((parent->type == XML_RELAXNG_GROUP) ||
		 (parent->type == XML_RELAXNG_INTERLEAVE))) {
		prev = xmlRelaxNGTryUnlink(ctxt, cur, parent, prev);
	    } else
		prev = cur;
	} else {
	    cur->parent = parent;
	    if (cur->content != NULL)
		xmlRelaxNGSimplify(ctxt, cur->content, cur);
	    if (cur->attrs != NULL)
		xmlRelaxNGSimplify(ctxt, cur->attrs, cur);
	    if (cur->nameClass != NULL)
		xmlRelaxNGSimplify(ctxt, cur->nameClass, cur);
	    /*
	     * This may result in a simplification
	     */
	    if ((cur->type == XML_RELAXNG_GROUP) ||
		(cur->type == XML_RELAXNG_INTERLEAVE)) {
		if (cur->content == NULL)
		    cur->type = XML_RELAXNG_EMPTY;
		else if (cur->content->next == NULL) {
		    if ((parent == NULL) && (prev == NULL)) {
			cur->type = XML_RELAXNG_NOOP;
		    } else if (prev == NULL) {
			parent->content = cur->content;
			cur->content->next = cur->next;
			cur = cur->content;
		    } else {
			cur->content->next = cur->next;
			prev->next = cur->content;
			cur = cur->content;
		    }
		}
	    }
	    /*
	     * the current node may have been transformed back
	     */
	    if ((cur->type == XML_RELAXNG_EXCEPT) &&
		(cur->content != NULL) &&
		(cur->content->type == XML_RELAXNG_NOT_ALLOWED)) {
		prev = xmlRelaxNGTryUnlink(ctxt, cur, parent, prev);
	    } else if (cur->type == XML_RELAXNG_NOT_ALLOWED) {
		if ((parent != NULL) &&
		    ((parent->type == XML_RELAXNG_ATTRIBUTE) ||
		     (parent->type == XML_RELAXNG_LIST) ||
		     (parent->type == XML_RELAXNG_GROUP) ||
		     (parent->type == XML_RELAXNG_INTERLEAVE) ||
		     (parent->type == XML_RELAXNG_ONEORMORE) ||
		     (parent->type == XML_RELAXNG_ZEROORMORE))) {
		    parent->type = XML_RELAXNG_NOT_ALLOWED;
		    break;
		}
		if ((parent != NULL) &&
		    (parent->type == XML_RELAXNG_CHOICE)) {
		    prev = xmlRelaxNGTryUnlink(ctxt, cur, parent, prev);
		} else
		    prev = cur;
	    } else if (cur->type == XML_RELAXNG_EMPTY){
		if ((parent != NULL) &&
		    ((parent->type == XML_RELAXNG_ONEORMORE) ||
		     (parent->type == XML_RELAXNG_ZEROORMORE))) {
		    parent->type = XML_RELAXNG_EMPTY;
		    break;
		}
		if ((parent != NULL) &&
		    ((parent->type == XML_RELAXNG_GROUP) ||
		     (parent->type == XML_RELAXNG_INTERLEAVE) ||
		     (parent->type == XML_RELAXNG_CHOICE))) {
		    prev = xmlRelaxNGTryUnlink(ctxt, cur, parent, prev);
		} else
		    prev = cur;
	    } else {
		prev = cur;
	    }
	}
	cur = cur->next;
    }
}

/**
 * xmlRelaxNGGroupContentType:
 * @ct1:  the first content type
 * @ct2:  the second content type
 *
 * Try to group 2 content types
 *
 * Returns the content type
 */
static xmlRelaxNGContentType
xmlRelaxNGGroupContentType(xmlRelaxNGContentType ct1,
		           xmlRelaxNGContentType ct2) {
    if ((ct1 == XML_RELAXNG_CONTENT_ERROR) ||
	(ct2 == XML_RELAXNG_CONTENT_ERROR))
	return(XML_RELAXNG_CONTENT_ERROR);
    if (ct1 == XML_RELAXNG_CONTENT_EMPTY)
	return(ct2);
    if (ct2 == XML_RELAXNG_CONTENT_EMPTY)
	return(ct1);
    if ((ct1 == XML_RELAXNG_CONTENT_COMPLEX) &&
	(ct2 == XML_RELAXNG_CONTENT_COMPLEX))
	return(XML_RELAXNG_CONTENT_COMPLEX);
    return(XML_RELAXNG_CONTENT_ERROR);
}

/**
 * xmlRelaxNGMaxContentType:
 * @ct1:  the first content type
 * @ct2:  the second content type
 *
 * Compute the max content-type
 *
 * Returns the content type
 */
static xmlRelaxNGContentType
xmlRelaxNGMaxContentType(xmlRelaxNGContentType ct1,
		     xmlRelaxNGContentType ct2) {
    if ((ct1 == XML_RELAXNG_CONTENT_ERROR) ||
	(ct2 == XML_RELAXNG_CONTENT_ERROR))
	return(XML_RELAXNG_CONTENT_ERROR);
    if ((ct1 == XML_RELAXNG_CONTENT_SIMPLE) ||
	(ct2 == XML_RELAXNG_CONTENT_SIMPLE))
	return(XML_RELAXNG_CONTENT_SIMPLE);
    if ((ct1 == XML_RELAXNG_CONTENT_COMPLEX) ||
	(ct2 == XML_RELAXNG_CONTENT_COMPLEX))
	return(XML_RELAXNG_CONTENT_COMPLEX);
    return(XML_RELAXNG_CONTENT_EMPTY);
}

/**
 * xmlRelaxNGCheckRules:
 * @ctxt:  a Relax-NG parser context
 * @cur:  the current definition
 * @flags:  some accumulated flags
 * @ptype:  the parent type
 *
 * Check for rules in section 7.1 and 7.2
 *
 * Returns the content type of @cur
 */
static xmlRelaxNGContentType
xmlRelaxNGCheckRules(xmlRelaxNGParserCtxtPtr ctxt, 
	             xmlRelaxNGDefinePtr cur, int flags,
		     xmlRelaxNGType ptype) {
    int nflags = flags;
    xmlRelaxNGContentType ret, tmp, val = XML_RELAXNG_CONTENT_EMPTY;

    while (cur != NULL) {
	ret = XML_RELAXNG_CONTENT_EMPTY;
	if ((cur->type == XML_RELAXNG_REF) ||
	    (cur->type == XML_RELAXNG_PARENTREF)) {
	    if (flags & XML_RELAXNG_IN_LIST) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern list//ref\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_ATTRIBUTE) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern attribute//ref\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//ref\n");
		ctxt->nbErrors++;
	    }
	    if (cur->depth > -4) {
		cur->depth = -4;
		ret = xmlRelaxNGCheckRules(ctxt, cur->content,
			                   flags, cur->type);
		cur->depth = ret - 15 ;
	    } else if (cur->depth == -4) {
		ret = XML_RELAXNG_CONTENT_COMPLEX;
	    } else {
		ret = (xmlRelaxNGContentType) cur->depth + 15;
	    }
	} else if (cur->type == XML_RELAXNG_ELEMENT) {
	    /*
	     * The 7.3 Attribute derivation rule for groups is plugged there
	     */
	    xmlRelaxNGCheckGroupAttrs(ctxt, cur);
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//element(ref)\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_LIST) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern list//element(ref)\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_ATTRIBUTE) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern attribute//element(ref)\n");
		ctxt->nbErrors++;
	    }
	    /*
	     * reset since in the simple form elements are only child
	     * of grammar/define
	     */
	    nflags = 0;
	    ret = xmlRelaxNGCheckRules(ctxt, cur->attrs, nflags, cur->type);
	    if (ret != XML_RELAXNG_CONTENT_EMPTY) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Element %s attributes have a content type error\n",
			        cur->name);
		ctxt->nbErrors++;
	    }
	    ret = xmlRelaxNGCheckRules(ctxt, cur->content, nflags, cur->type);
	    if (ret == XML_RELAXNG_CONTENT_ERROR) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Element %s has a content type error\n",
			        cur->name);
		ctxt->nbErrors++;
	    } else {
		ret = XML_RELAXNG_CONTENT_COMPLEX;
	    }
	} else if (cur->type == XML_RELAXNG_ATTRIBUTE) {
	    if (flags & XML_RELAXNG_IN_ATTRIBUTE) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern attribute//attribute\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_LIST) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern list//attribute\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_OOMGROUP) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		    "Found forbidden pattern oneOrMore//group//attribute\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_OOMINTERLEAVE) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern oneOrMore//interleave//attribute\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//attribute\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//attribute\n");
		ctxt->nbErrors++;
	    }
	    nflags = flags | XML_RELAXNG_IN_ATTRIBUTE;
	    xmlRelaxNGCheckRules(ctxt, cur->content, nflags, cur->type);
	    ret = XML_RELAXNG_CONTENT_EMPTY;
	} else if ((cur->type == XML_RELAXNG_ONEORMORE) ||
		   (cur->type == XML_RELAXNG_ZEROORMORE)) {
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//oneOrMore\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//oneOrMore\n");
		ctxt->nbErrors++;
	    }
	    nflags = flags | XML_RELAXNG_IN_ONEORMORE;
	    ret = xmlRelaxNGCheckRules(ctxt, cur->content, nflags, cur->type);
	    ret = xmlRelaxNGGroupContentType(ret, ret);
	} else if (cur->type == XML_RELAXNG_LIST) {
	    if (flags & XML_RELAXNG_IN_LIST) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern list//list\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//list\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//list\n");
		ctxt->nbErrors++;
	    }
	    nflags = flags | XML_RELAXNG_IN_LIST;
	    ret = xmlRelaxNGCheckRules(ctxt, cur->content, nflags, cur->type);
	} else if (cur->type == XML_RELAXNG_GROUP) {
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//group\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//group\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_ONEORMORE)
		nflags = flags | XML_RELAXNG_IN_OOMGROUP;
	    else
		nflags = flags;
	    ret = xmlRelaxNGCheckRules(ctxt, cur->content, nflags, cur->type);
	    /*
	     * The 7.3 Attribute derivation rule for groups is plugged there
	     */
	    xmlRelaxNGCheckGroupAttrs(ctxt, cur);
	} else if (cur->type == XML_RELAXNG_INTERLEAVE) {
	    if (flags & XML_RELAXNG_IN_LIST) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern list//interleave\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//interleave\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//interleave\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_ONEORMORE)
		nflags = flags | XML_RELAXNG_IN_OOMINTERLEAVE;
	    else
		nflags = flags;
	    ret = xmlRelaxNGCheckRules(ctxt, cur->content, nflags, cur->type);
	} else if (cur->type == XML_RELAXNG_EXCEPT) {
	    if ((cur->parent != NULL) &&
		(cur->parent->type == XML_RELAXNG_DATATYPE))
		nflags = flags | XML_RELAXNG_IN_DATAEXCEPT;
	    else
		nflags = flags;
	    ret = xmlRelaxNGCheckRules(ctxt, cur->content, nflags, cur->type);
	} else if (cur->type == XML_RELAXNG_DATATYPE) {
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//data\n");
		ctxt->nbErrors++;
	    }
	    xmlRelaxNGCheckRules(ctxt, cur->content, flags, cur->type);
	    ret = XML_RELAXNG_CONTENT_SIMPLE;
	} else if (cur->type == XML_RELAXNG_VALUE) {
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//value\n");
		ctxt->nbErrors++;
	    }
	    xmlRelaxNGCheckRules(ctxt, cur->content, flags, cur->type);
	    ret = XML_RELAXNG_CONTENT_SIMPLE;
	} else if (cur->type == XML_RELAXNG_TEXT) {
	    if (flags & XML_RELAXNG_IN_LIST) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
		"Found forbidden pattern list//text\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//text\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//text\n");
		ctxt->nbErrors++;
	    }
	    ret = XML_RELAXNG_CONTENT_COMPLEX;
	} else if (cur->type == XML_RELAXNG_EMPTY) {
	    if (flags & XML_RELAXNG_IN_DATAEXCEPT) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern data/except//empty\n");
		ctxt->nbErrors++;
	    }
	    if (flags & XML_RELAXNG_IN_START) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			"Found forbidden pattern start//empty\n");
		ctxt->nbErrors++;
	    }
	    ret = XML_RELAXNG_CONTENT_EMPTY;
	} else {
	    ret = xmlRelaxNGCheckRules(ctxt, cur->content, flags, cur->type);
	}
	cur = cur->next;
	if (ptype == XML_RELAXNG_GROUP) {
	    val = xmlRelaxNGGroupContentType(val, ret);
	} else if (ptype == XML_RELAXNG_INTERLEAVE) {
	    tmp = xmlRelaxNGGroupContentType(val, ret);
	    if (tmp != XML_RELAXNG_CONTENT_ERROR)
		tmp = xmlRelaxNGMaxContentType(val, ret);
	} else if (ptype == XML_RELAXNG_CHOICE) {
	    val = xmlRelaxNGMaxContentType(val, ret);
	} else if (ptype == XML_RELAXNG_LIST) {
	    val = XML_RELAXNG_CONTENT_SIMPLE;
	} else if (ptype == XML_RELAXNG_EXCEPT) {
	    if (ret == XML_RELAXNG_CONTENT_ERROR)
		val = XML_RELAXNG_CONTENT_ERROR;
	    else
		val = XML_RELAXNG_CONTENT_SIMPLE;
	} else {
	    val = xmlRelaxNGGroupContentType(val, ret);
	}

    }
    return(val);
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
    if (ctxt->grammar == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
	    "Failed to parse <grammar> content\n");
	ctxt->nbErrors++;
    } else if (ctxt->grammar->start == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
	    "Element <grammar> has no <start>\n");
	ctxt->nbErrors++;
    }

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
    if (schema->topgrammar->start != NULL) {
	xmlRelaxNGCheckCycles(ctxt, schema->topgrammar->start, 0);
	if ((ctxt->flags & XML_RELAXNG_IN_EXTERNALREF) == 0) {
	    xmlRelaxNGSimplify(ctxt, schema->topgrammar->start, NULL);
	    while ((schema->topgrammar->start != NULL) &&
		   (schema->topgrammar->start->type == XML_RELAXNG_NOOP) &&
		   (schema->topgrammar->start->next != NULL))
		schema->topgrammar->start = schema->topgrammar->start->content;
	    xmlRelaxNGCheckRules(ctxt, schema->topgrammar->start,
				 XML_RELAXNG_IN_START, XML_RELAXNG_NOOP);
	}
    }

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
    if (ctxt->includes != NULL)
	xmlHashFree(ctxt->includes, (xmlHashDeallocator)
		xmlRelaxNGFreeInclude);
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
 * xmlRelaxNGNormExtSpace:
 * @value:  a value
 *
 * Removes the leading and ending spaces of the value
 * The string is modified "in situ"
 */
static void
xmlRelaxNGNormExtSpace(xmlChar *value) {
    xmlChar *start = value;
    xmlChar *cur = value;
    if (value == NULL)
	return;

    while (IS_BLANK(*cur)) cur++;
    if (cur == start) {
	do {
	    while ((*cur != 0) && (!IS_BLANK(*cur))) cur++;
	    if (*cur == 0)
		return;
	    start = cur;
	    while (IS_BLANK(*cur)) cur++;
	    if (*cur == 0) {
		*start = 0;
	        return;
	    }
	} while (1);
    } else {
	do {
	    while ((*cur != 0) && (!IS_BLANK(*cur))) 
		*start++ = *cur++;
	    if (*cur == 0) {
		*start = 0;
		return;
	    }
	    /* don't try to normalize the inner spaces */
	    while (IS_BLANK(*cur)) cur++;
		*start++ = *cur++;
	    if (*cur == 0) {
		*start = 0;
	        return;
	    }
	} while (1);
    }
}

/**
 * xmlRelaxNGCheckAttributes:
 * @ctxt:  a Relax-NG parser context
 * @node:  a Relax-NG node
 *
 * Check all the attributes on the given node
 */
static void
xmlRelaxNGCleanupAttributes(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) {
    xmlAttrPtr cur, next;

    cur = node->properties;
    while (cur != NULL) {
	next = cur->next;
	if ((cur->ns == NULL) ||
	    (xmlStrEqual(cur->ns->href, xmlRelaxNGNs))) {
	    if (xmlStrEqual(cur->name, BAD_CAST "name")) {
		if ((!xmlStrEqual(node->name, BAD_CAST "element")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "attribute")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "ref")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "parentRef")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "param")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "define"))) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
				"Attribute %s is not allowed on %s\n",
				    cur->name, node->name);
		    ctxt->nbErrors++;
		}
	    } else if (xmlStrEqual(cur->name, BAD_CAST "type")) {
		if ((!xmlStrEqual(node->name, BAD_CAST "value")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "data"))) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
				"Attribute %s is not allowed on %s\n",
				    cur->name, node->name);
		    ctxt->nbErrors++;
		}
	    } else if (xmlStrEqual(cur->name, BAD_CAST "href")) {
		if ((!xmlStrEqual(node->name, BAD_CAST "externalRef")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "include"))) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
				"Attribute %s is not allowed on %s\n",
				    cur->name, node->name);
		    ctxt->nbErrors++;
		}
	    } else if (xmlStrEqual(cur->name, BAD_CAST "combine")) {
		if ((!xmlStrEqual(node->name, BAD_CAST "start")) &&
		    (!xmlStrEqual(node->name, BAD_CAST "define"))) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
				"Attribute %s is not allowed on %s\n",
				    cur->name, node->name);
		    ctxt->nbErrors++;
		}
	    } else if (xmlStrEqual(cur->name, BAD_CAST "datatypeLibrary")) {
		xmlChar *val;
		xmlURIPtr uri;

		val = xmlNodeListGetString(node->doc, cur->children, 1);
		if (val != NULL) {
		    if (val[0] != 0) {
			uri = xmlParseURI((const char *) val);
			if (uri == NULL) {
			    if (ctxt->error != NULL)
				ctxt->error(ctxt->userData,
				"Attribute %s contains invalid URI %s\n",
					    cur->name, val);
			    ctxt->nbErrors++;
			} else {
			    if (uri->scheme == NULL) {
				if (ctxt->error != NULL)
				    ctxt->error(ctxt->userData,
				    "Attribute %s URI %s is not absolute\n",
						cur->name, val);
				ctxt->nbErrors++;
			    }
			    if (uri->fragment != NULL) {
				if (ctxt->error != NULL)
				    ctxt->error(ctxt->userData,
				    "Attribute %s URI %s has a fragment ID\n",
						cur->name, val);
				ctxt->nbErrors++;
			    }
			    xmlFreeURI(uri);
			}
		    }
		    xmlFree(val);
		}
	    } else if (!xmlStrEqual(cur->name, BAD_CAST "ns")) {
		if (ctxt->error != NULL)
		    ctxt->error(ctxt->userData,
			    "Unknown attribute %s on %s\n",
				cur->name, node->name);
		ctxt->nbErrors++;
	    }
	}
	cur = next;
    }
}

/**
 * xmlRelaxNGCleanupTree:
 * @ctxt:  a Relax-NG parser context
 * @root:  an xmlNodePtr subtree
 *
 * Cleanup the subtree from unwanted nodes for parsing, resolve
 * Include and externalRef lookups.
 */
static void
xmlRelaxNGCleanupTree(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr root) {
    xmlNodePtr cur, delete;

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
		if ((cur->parent != NULL) &&
		    (cur->parent->type == XML_ELEMENT_NODE) &&
		    ((xmlStrEqual(cur->parent->name, BAD_CAST "name")) ||
		     (xmlStrEqual(cur->parent->name, BAD_CAST "value")) ||
		     (xmlStrEqual(cur->parent->name, BAD_CAST "param")))) {
		    if (ctxt->error != NULL)
			ctxt->error(ctxt->userData,
				"element %s doesn't allow foreign elements\n",
				    cur->parent->name);
		    ctxt->nbErrors++;
		}
		delete = cur;
		goto skip_children;
	    } else {
		xmlRelaxNGCleanupAttributes(ctxt, cur);
		if (xmlStrEqual(cur->name, BAD_CAST "externalRef")) {
		    xmlChar *href, *ns, *base, *URL;
		    xmlRelaxNGDocumentPtr docu;
		    xmlNodePtr tmp;

		    ns = xmlGetProp(cur, BAD_CAST "ns");
		    if (ns == NULL) {
			tmp = cur->parent;
			while ((tmp != NULL) &&
			       (tmp->type == XML_ELEMENT_NODE)) {
			    ns = xmlGetProp(tmp, BAD_CAST "ns");
			    if (ns != NULL)
				break;
			    tmp = tmp->parent;
			}
		    }
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
		    if (ns != NULL)
			xmlFree(ns);
		    xmlFree(URL);
		    cur->_private = docu;
		} else if (xmlStrEqual(cur->name, BAD_CAST "include")) {
		    xmlChar *href, *ns, *base, *URL;
		    xmlRelaxNGIncludePtr incl;
		    xmlNodePtr tmp;

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
		    ns = xmlGetProp(cur, BAD_CAST "ns");
		    if (ns == NULL) {
			tmp = cur->parent;
			while ((tmp != NULL) &&
			       (tmp->type == XML_ELEMENT_NODE)) {
			    ns = xmlGetProp(tmp, BAD_CAST "ns");
			    if (ns != NULL)
				break;
			    tmp = tmp->parent;
			}
		    }
		    incl = xmlRelaxNGLoadInclude(ctxt, URL, cur, ns);
		    if (ns != NULL)
			xmlFree(ns);
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
		    xmlChar *name, *ns;
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
			if (text == NULL) {
			    if (ctxt->error != NULL)
				ctxt->error(ctxt->userData,
				"Failed to create a name %s element\n", name);
			    ctxt->nbErrors++;
			}
			xmlUnsetProp(cur, BAD_CAST "name");
			xmlFree(name);
			ns = xmlGetProp(cur, BAD_CAST "ns");
			if (ns != NULL) {
			    if (text != NULL) {
				xmlSetProp(text, BAD_CAST "ns", ns);
				/* xmlUnsetProp(cur, BAD_CAST "ns"); */
			    }
			    xmlFree(ns);
			} else if (xmlStrEqual(cur->name,
				   BAD_CAST "attribute")) {
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
		    /*
		     * 4.16
		     */
		    if (xmlStrEqual(cur->name, BAD_CAST "nsName")) {
			if (ctxt->flags & XML_RELAXNG_IN_NSEXCEPT) {
			    if (ctxt->error != NULL)
				ctxt->error(ctxt->userData,
		    "Found nsName/except//nsName forbidden construct\n");
			    ctxt->nbErrors++;
			}
		    }
		} else if ((xmlStrEqual(cur->name, BAD_CAST "except")) &&
			   (cur != root)) {
		    int oldflags = ctxt->flags;

		    /*
		     * 4.16
		     */
		    if ((cur->parent != NULL) &&
			(xmlStrEqual(cur->parent->name, BAD_CAST "anyName"))) {
			ctxt->flags |= XML_RELAXNG_IN_ANYEXCEPT;
			xmlRelaxNGCleanupTree(ctxt, cur);
			ctxt->flags = oldflags;
			goto skip_children;
		    } else if ((cur->parent != NULL) &&
			(xmlStrEqual(cur->parent->name, BAD_CAST "nsName"))) {
			ctxt->flags |= XML_RELAXNG_IN_NSEXCEPT;
			xmlRelaxNGCleanupTree(ctxt, cur);
			ctxt->flags = oldflags;
			goto skip_children;
		    }
		} else if (xmlStrEqual(cur->name, BAD_CAST "anyName")) {
		    /*
		     * 4.16
		     */
		    if (ctxt->flags & XML_RELAXNG_IN_ANYEXCEPT) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
		"Found anyName/except//anyName forbidden construct\n");
			ctxt->nbErrors++;
		    } else if (ctxt->flags & XML_RELAXNG_IN_NSEXCEPT) {
			if (ctxt->error != NULL)
			    ctxt->error(ctxt->userData,
		"Found nsName/except//anyName forbidden construct\n");
			ctxt->nbErrors++;
		    }
		}
		/*
		 * Thisd is not an else since "include" is transformed
		 * into a div
		 */
		if (xmlStrEqual(cur->name, BAD_CAST "div")) {
		    xmlChar *ns;
		    xmlNodePtr child, ins, tmp;

		    /*
		     * implements rule 4.11
		     */

		    ns = xmlGetProp(cur, BAD_CAST "ns");

		    child = cur->children;
		    ins = cur;
		    while (child != NULL) {
			if (ns != NULL) {
			    if (!xmlHasProp(child, BAD_CAST "ns")) {
				xmlSetProp(child, BAD_CAST "ns", ns);
			    }
			}
			tmp = child->next;
			xmlUnlinkNode(child);
			ins = xmlAddNextSibling(ins, child);
			child = tmp;
		    }
		    if (ns != NULL)
			xmlFree(ns);
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
    xmlNodePtr root;

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
    xmlRelaxNGCleanupTree(ctxt, root);
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
	xmlFreeDoc(doc);
        return (NULL);
    }
    ret = xmlRelaxNGParseDocument(ctxt, root);
    if (ret == NULL) {
	xmlFreeDoc(doc);
	return(NULL);
    }

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
	    fprintf(output, "<externalRef>");
	    xmlRelaxNGDumpDefines(output, define->content);
	    fprintf(output, "</externalRef>\n");
	    break;
        case XML_RELAXNG_DATATYPE:
        case XML_RELAXNG_VALUE:
	    TODO
	    break;
	case XML_RELAXNG_START:
	case XML_RELAXNG_EXCEPT:
	case XML_RELAXNG_PARAM:
	    TODO
	    break;
	case XML_RELAXNG_NOOP:
	    xmlRelaxNGDumpDefines(output, define->content);
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

/**
 * xmlRelaxNGDumpTree:
 * @output:  the file output
 * @schema:  a schema structure
 *
 * Dump the transformed RelaxNG tree.
 */
void
xmlRelaxNGDumpTree(FILE * output, xmlRelaxNGPtr schema)
{
    if (schema == NULL) {
	fprintf(output, "RelaxNG empty or failed to compile\n");
	return;
    }
    if (schema->doc == NULL) {
	fprintf(output, "no document\n");
    } else {
	xmlDocDump(output, schema->doc); 
    }
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
    if ((ret == 0) && (define->content != NULL)) {
	const xmlChar *oldvalue, *oldendvalue;

	oldvalue = ctxt->state->value;
	oldendvalue = ctxt->state->endvalue;
	ctxt->state->value = (xmlChar *) value;
	ctxt->state->endvalue = NULL;
	ret = xmlRelaxNGValidateValue(ctxt, define->content);
	ctxt->state->value = (xmlChar *) oldvalue;
	ctxt->state->endvalue = (xmlChar *) oldendvalue;
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
	case XML_RELAXNG_EMPTY: {
	    if ((value != NULL) && (value[0] != 0)) {
		int idx = 0;

		while (IS_BLANK(value[idx]))
		    idx++;
		if (value[idx] != 0)
		    ret = -1;
	    }
	    break;
	}
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
	    if (ret == 0)
		xmlRelaxNGNextValue(ctxt);
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
	    if (ret == 0)
		xmlRelaxNGNextValue(ctxt);
	    break;
	}
	case XML_RELAXNG_LIST: {
	    xmlRelaxNGDefinePtr list = define->content;
	    xmlChar *oldvalue, *oldend, *val, *cur;
#ifdef DEBUG_LIST
	    int nb_values = 0;
#endif

	    oldvalue = ctxt->state->value;
	    oldend = ctxt->state->endvalue;

	    val = xmlStrdup(oldvalue);
	    if (val == NULL) {
		val = xmlStrdup(BAD_CAST "");
	    }
	    if (val == NULL) {
		VALID_CTXT();
		VALID_ERROR("Internal: no state\n");
		return(-1);
	    }
	    cur = val;
	    while (*cur != 0) {
		if (IS_BLANK(*cur)) {
		    *cur = 0;
		    cur++;
#ifdef DEBUG_LIST
		    nb_values++;
#endif
		    while (IS_BLANK(*cur))
			*cur++ = 0;
		} else
		    cur++;
	    }
#ifdef DEBUG_LIST
	    xmlGenericError(xmlGenericErrorContext,
		    "list value: '%s' found %d items\n", oldvalue, nb_values);
	    nb_values = 0;
#endif 
	    ctxt->state->endvalue = cur;
	    cur = val;
	    while ((*cur == 0) && (cur != ctxt->state->endvalue)) cur++;

	    ctxt->state->value = cur;

	    while (list != NULL) {
		if (ctxt->state->value == ctxt->state->endvalue)
		    ctxt->state->value = NULL;
		ret = xmlRelaxNGValidateValue(ctxt, list);
		if (ret != 0) {
#ifdef DEBUG_LIST
		    xmlGenericError(xmlGenericErrorContext,
			"Failed to validate value: '%s' with %d rule\n",
		                    ctxt->state->value, nb_values);
#endif
		    break;
		}
#ifdef DEBUG_LIST
		nb_values++;
#endif
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
        case XML_RELAXNG_EXCEPT: {
	    xmlRelaxNGDefinePtr list;

	    list = define->content;
	    while (list != NULL) {
		ret = xmlRelaxNGValidateValue(ctxt, list);
		if (ret == 0) {
		    ret = -1;
		    break;
		} else 
		    ret = 0;
		list = list->next;
	    }
	    break;
	}
        case XML_RELAXNG_GROUP: {
	    xmlRelaxNGDefinePtr list;

	    list = define->content;
	    while (list != NULL) {
		ret = xmlRelaxNGValidateValue(ctxt, list);
		if (ret != 0) {
		    ret = -1;
		    break;
		} else 
		    ret = 0;
		list = list->next;
	    }
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
    int ret = 0, i, nbgroups, left;
    xmlRelaxNGPartitionPtr partitions;
    xmlRelaxNGInterleaveGroupPtr group = NULL;
    xmlNodePtr cur, start, last = NULL, lastchg = NULL, lastelem;
    xmlNodePtr *list = NULL, *lasts = NULL;

    if (define->data != NULL) {
	partitions = (xmlRelaxNGPartitionPtr) define->data;
	nbgroups = partitions->nbgroups;
	left = nbgroups;
    } else {
	VALID_CTXT();
	VALID_ERROR("Internal: interleave block has no data\n");
	return(-1);
    }

    /*
     * Build arrays to store the first and last node of the chain
     * pertaining to each group
     */
    list = (xmlNodePtr *) xmlMalloc(nbgroups * sizeof(xmlNodePtr));
    if (list == NULL) {
	VALID_CTXT();
	VALID_ERROR("Internal: out of memory in interleave check\n");
	return(-1);
    }
    memset(list, 0, nbgroups * sizeof(xmlNodePtr));
    lasts = (xmlNodePtr *) xmlMalloc(nbgroups * sizeof(xmlNodePtr));
    if (lasts == NULL) {
	VALID_CTXT();
	VALID_ERROR("Internal: out of memory in interleave check\n");
	return(-1);
    }
    memset(lasts, 0, nbgroups * sizeof(xmlNodePtr));

    /*
     * Walk the sequence of children finding the right group and
     * sorting them in sequences.
     */
    cur = ctxt->state->seq;
    cur = xmlRelaxNGSkipIgnored(ctxt, cur);
    start = cur;
    while (cur != NULL) {
	ctxt->state->seq = cur;
	for (i = 0;i < nbgroups;i++) {
	    group = partitions->groups[i];
	    if (group == NULL)
		continue;
	    if (xmlRelaxNGNodeMatchesList(cur, group->defs))
		break;
	}
	/*
	 * We break as soon as an element not matched is found
	 */
	if (i >= nbgroups) {
	    break;
	}
	if (lasts[i] != NULL) {
	    lasts[i]->next = cur;
	    lasts[i] = cur;
	} else {
	    list[i] = cur;
	    lasts[i] = cur;
	}
	if (cur->next != NULL)
	    lastchg = cur->next;
	else
	    lastchg = cur;
	cur = xmlRelaxNGSkipIgnored(ctxt, cur->next);
    }
    if (ret != 0) {
	VALID_CTXT();
	VALID_ERROR("Invalid sequence in interleave\n");
	ret = -1;
	goto done;
    }
    lastelem = cur;
    for (i = 0;i < nbgroups;i++) {
	group = partitions->groups[i];
	if (lasts[i] != NULL) {
	    last = lasts[i]->next;
	    lasts[i]->next = NULL;
	}
	ctxt->state->seq = list[i];
	ret = xmlRelaxNGValidateDefinition(ctxt, group->rule);
	if (ret != 0)
	    break;
	cur = ctxt->state->seq;
	cur = xmlRelaxNGSkipIgnored(ctxt, cur);
	if (cur != NULL) {
	    VALID_CTXT();
	    VALID_ERROR2("Extra element %s in interleave\n", cur->name);
	    ret = -1;
	    goto done;
	}
	if (lasts[i] != NULL) {
	    lasts[i]->next = last;
	}
    }
    ctxt->state->seq = lastelem;
    if (ret != 0) {
	VALID_CTXT();
	VALID_ERROR("Invalid sequence in interleave\n");
	ret = -1;
	goto done;
    }

done:
    /*
     * builds the next links chain from the prev one
     */
    cur = lastchg;
    while (cur != NULL) {
	if ((cur == start) || (cur->prev == NULL))
	    break;
	cur->prev->next = cur;
	cur = cur->prev;
    }

    xmlFree(list);
    xmlFree(lasts);
    return(ret);
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
 * xmlRelaxNGElementMatch:
 * @ctxt:  a Relax-NG validation context
 * @define:  the definition to check
 * @elem:  the element
 *
 * Check if the element matches the definition nameClass
 *
 * Returns 1 if the element matches, 0 if no, or -1 in case of error
 */
static int
xmlRelaxNGElementMatch(xmlRelaxNGValidCtxtPtr ctxt, 
	               xmlRelaxNGDefinePtr define,
		       xmlNodePtr elem) {
    int ret, oldflags;

    if (define->name != NULL) {
	if (!xmlStrEqual(elem->name, define->name)) {
	    VALID_CTXT();
	    VALID_ERROR3("Expecting element %s, got %s\n",
			define->name, elem->name);
	    return(0);
	}
    }
    if ((define->ns != NULL) && (define->ns[0] != 0)) {
	if (elem->ns == NULL) {
	    VALID_CTXT();
	    VALID_ERROR2("Expecting a namespace for element %s\n",
			elem->name);
	    return(0);
	} else if (!xmlStrEqual(elem->ns->href, define->ns)) {
	    VALID_CTXT();
	    VALID_ERROR3("Expecting element %s has wrong namespace: expecting %s\n",
			elem->name, define->ns);
	    return(0);
	}
    } else if ((elem->ns != NULL) && (define->ns != NULL) &&
	       (define->name == NULL)) {
	VALID_CTXT();
	VALID_ERROR2("Expecting no namespace for element %s\n",
		    define->name);
	return(0);
    } else if ((elem->ns != NULL) && (define->name != NULL)) {
	VALID_CTXT();
	VALID_ERROR2("Expecting no namespace for element %s\n",
		    define->name);
	return(0);
    }

    if (define->nameClass == NULL)
	return(1);

    define = define->nameClass;
    if (define->type == XML_RELAXNG_EXCEPT) {
	xmlRelaxNGDefinePtr list;
	oldflags = ctxt->flags;
	ctxt->flags |= FLAGS_IGNORABLE;

	list = define->content;
	while (list != NULL) {
	    ret = xmlRelaxNGElementMatch(ctxt, list, elem);
	    if (ret == 1) {
		ctxt->flags = oldflags;
		return(0);
	    }
	    if (ret < 0) {
		ctxt->flags = oldflags;
		return(ret);
	    }
	    list = list->next;
	}
	ret = 1;
	ctxt->flags = oldflags;
    } else if (define->type == XML_RELAXNG_CHOICE) {
	xmlRelaxNGDefinePtr list;
	oldflags = ctxt->flags;
	ctxt->flags |= FLAGS_IGNORABLE;

	list = define->nameClass;
	while (list != NULL) {
	    ret = xmlRelaxNGElementMatch(ctxt, list, elem);
	    if (ret == 1) {
		ctxt->flags = oldflags;
		return(1);
	    }
	    if (ret < 0) {
		ctxt->flags = oldflags;
		return(ret);
	    }
	    list = list->next;
	}
	ret = 0;
	ctxt->flags = oldflags;
    } else {
	TODO
	ret = -1;
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
	    node = xmlRelaxNGSkipIgnored(ctxt, node);
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
#if 0
	    if (node == NULL) {
		ret = 0;
		break;
	    }
#endif
	    while ((node != NULL) &&
		   ((node->type == XML_TEXT_NODE) ||
		    (node->type == XML_COMMENT_NODE) ||
		    (node->type == XML_PI_NODE) ||
		    (node->type == XML_CDATA_SECTION_NODE)))
		node = node->next;
#if 0
	    if (node == ctxt->state->seq) {
		VALID_CTXT();
		VALID_ERROR("Expecting text content\n");
		ret = -1;
	    }
#endif
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
	    if (node->_private == define) {
		ctxt->state->seq = xmlRelaxNGSkipIgnored(ctxt, node->next);
		break;
	    }

	    ret = xmlRelaxNGElementMatch(ctxt, define, node);
	    if (ret <= 0) {
		ret = -1;
		break;
	    }
	    ret = 0;
	    
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
	    int success = 0;

	    oldflags = ctxt->flags;
	    ctxt->flags |= FLAGS_IGNORABLE;

	    while (list != NULL) {
		oldstate = xmlRelaxNGCopyValidState(ctxt, ctxt->state);
		ret = xmlRelaxNGValidateDefinition(ctxt, list);
		if (ret == 0) {
		    if (xmlRelaxNGEqualValidState(ctxt, ctxt->state, oldstate)){
			/*
			 * if that pattern was nullable flag it but try 
			 * to make more progresses
			 */
			success = 1;
		    } else {
			xmlRelaxNGFreeValidState(oldstate);
			break;
		    }
		}
		xmlRelaxNGFreeValidState(ctxt->state);
		ctxt->state = oldstate;
		list = list->next;
	    }
	    ctxt->flags = oldflags;
	    if (success == 1)
		ret = 0;
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
	case XML_RELAXNG_NOOP:
        case XML_RELAXNG_REF:
        case XML_RELAXNG_PARENTREF:
	case XML_RELAXNG_EXTERNALREF:
	    ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
	    break;
        case XML_RELAXNG_DATATYPE: {
	    xmlNodePtr child;
	    xmlChar *content = NULL;

	    child = node;
	    while (child != NULL) {
		if (child->type == XML_ELEMENT_NODE) {
		    VALID_CTXT();
		    VALID_ERROR2("Element %s has child elements\n",
				 node->parent->name);
		    ret = -1;
		    break;
		} else if ((child->type == XML_TEXT_NODE) ||
			   (child->type == XML_CDATA_SECTION_NODE)) {
		    content = xmlStrcat(content, child->content);
		}
		/* TODO: handle entities ... */
		child = child->next;
	    }
	    if (ret == -1) {
		if (content != NULL)
		    xmlFree(content);
		break;
	    }
	    if (content == NULL) {
		content = xmlStrdup(BAD_CAST "");
		if (content == NULL) {
		    VALID_CTXT();
		    VALID_ERROR("Allocation failure\n");
		    ret = -1;
		    break;
		}
	    }
	    ret = xmlRelaxNGValidateDatatype(ctxt, content, define);
	    if (ret == -1) {
		VALID_CTXT();
		VALID_ERROR2("internal error validating %s\n", define->name);
	    } else if (ret == 0) {
		ctxt->state->seq = NULL;
	    }
	    if (content != NULL)
		xmlFree(content);
	    break;
	}
        case XML_RELAXNG_VALUE: {
	    xmlChar *content = NULL;
	    xmlChar *oldvalue;
	    xmlNodePtr child;

	    child = node;
	    while (child != NULL) {
		if (child->type == XML_ELEMENT_NODE) {
		    VALID_CTXT();
		    VALID_ERROR2("Element %s has child elements\n",
				 node->parent->name);
		    ret = -1;
		    break;
		} else if ((child->type == XML_TEXT_NODE) ||
			   (child->type == XML_CDATA_SECTION_NODE)) {
		    content = xmlStrcat(content, child->content);
		}
		/* TODO: handle entities ... */
		child = child->next;
	    }
	    if (ret == -1) {
		if (content != NULL)
		    xmlFree(content);
		break;
	    }
	    if (content == NULL) {
		content = xmlStrdup(BAD_CAST "");
		if (content == NULL) {
		    VALID_CTXT();
		    VALID_ERROR("Allocation failure\n");
		    ret = -1;
		    break;
		}
	    }
	    oldvalue = ctxt->state->value;
	    ctxt->state->value = content;
	    ret = xmlRelaxNGValidateValue(ctxt, define);
	    ctxt->state->value = oldvalue;
	    if (ret == -1) {
		VALID_CTXT();
		if (define->name != NULL) {
		    VALID_ERROR2("error validating value %s\n", define->name);
		} else {
		    VALID_ERROR("error validating value\n");
		}
	    } else if (ret == 0) {
		ctxt->state->seq = NULL;
	    }
	    if (content != NULL)
		xmlFree(content);
	    break;
	}
        case XML_RELAXNG_LIST: {
	    xmlChar *content;
	    xmlNodePtr child;
	    xmlChar *oldvalue, *oldendvalue;
	    int len;

	    /*
	     * Make sure it's only text nodes
	     */
	    
	    content = NULL;
	    child = node;
	    while (child != NULL) {
		if (child->type == XML_ELEMENT_NODE) {
		    VALID_CTXT();
		    VALID_ERROR2("Element %s has child elements\n",
				 node->parent->name);
		    ret = -1;
		    break;
		} else if ((child->type == XML_TEXT_NODE) ||
			   (child->type == XML_CDATA_SECTION_NODE)) {
		    content = xmlStrcat(content, child->content);
		}
		/* TODO: handle entities ... */
		child = child->next;
	    }
	    if (ret == -1) {
		if (content != NULL)
		    xmlFree(content);
		break;
	    }
	    if (content == NULL) {
		content = xmlStrdup(BAD_CAST "");
		if (content == NULL) {
		    VALID_CTXT();
		    VALID_ERROR("Allocation failure\n");
		    ret = -1;
		    break;
		}
	    }
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
		VALID_ERROR("error validating list\n");
	    } else if ((ret == 0) && (node != NULL)) {
		ctxt->state->seq = node->next;
	    }
	    if (content != NULL)
		xmlFree(content);
	    break;
        }
	case XML_RELAXNG_START:
	case XML_RELAXNG_EXCEPT:
	case XML_RELAXNG_PARAM:
	    TODO
	    ret = -1;
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

