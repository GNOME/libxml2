/*
 * relaxng.c : implementation of the Relax-NG handling and validity checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <veillard@redhat.com>
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

/*
 * The Relax-NG namespace
 */
static const xmlChar *xmlRelaxNGNs = (const xmlChar *)
    "http://relaxng.org/ns/structure/1.0";

#define IS_RELAXNG(node, type)						\
   ((node != NULL) && (node->ns != NULL) &&				\
    (xmlStrEqual(node->name, (const xmlChar *) type)) &&		\
    (xmlStrEqual(node->ns->href, xmlRelaxNGNs)))


#define DEBUG 1                 /* very verbose output */
#define DEBUG_CONTENT 1
#define DEBUG_TYPE 1
#define DEBUG_VALID 1

#define UNBOUNDED (1 << 30)
#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

typedef struct _xmlRelaxNGSchema xmlRelaxNGSchema;
typedef xmlRelaxNGSchema *xmlRelaxNGSchemaPtr;

typedef struct _xmlRelaxNGDefine xmlRelaxNGDefine;
typedef xmlRelaxNGDefine *xmlRelaxNGDefinePtr;

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
    xmlHashTablePtr defs;	/* define* */
    xmlHashTablePtr refs;	/* references */
};


typedef enum {
    XML_RELAXNG_EMPTY = 0,	/* an empty pattern */
    XML_RELAXNG_NOT_ALLOWED,    /* not allowed top */
    XML_RELAXNG_TEXT,		/* textual content */
    XML_RELAXNG_ELEMENT,	/* an element */
    XML_RELAXNG_DATATYPE,	/* extenal data type definition */
    XML_RELAXNG_VALUE,		/* value from an extenal data type definition */
    XML_RELAXNG_LIST,		/* a list of patterns */
    XML_RELAXNG_ATTRIBUTE,	/* an attrbute following a pattern */
    XML_RELAXNG_DEF,		/* a definition */
    XML_RELAXNG_REF,		/* reference to a definition */
    XML_RELAXNG_OPTIONAL,	/* optional patterns */
    XML_RELAXNG_ZEROORMORE,	/* zero or more non empty patterns */
    XML_RELAXNG_ONEORMORE,	/* one or more non empty patterns */
    XML_RELAXNG_CHOICE,		/* a choice between non empty patterns */
    XML_RELAXNG_GROUP,		/* a pair/group of non empty patterns */
    XML_RELAXNG_INTERLEAVE	/* interleaving choice of non-empty patterns */
} xmlRelaxNGType;

struct _xmlRelaxNGDefine {
    xmlRelaxNGType type;	/* the type of definition */
    xmlNodePtr	   node;	/* the node in the source */
    xmlChar       *name;	/* the element local name if present */
    xmlChar       *ns;		/* the namespace local name if present */
    void          *data;	/* data lib or specific pointer */
    xmlRelaxNGDefinePtr content;/* the expected content */
    xmlRelaxNGDefinePtr next;	/* list within grouping sequences */
    xmlRelaxNGDefinePtr attrs;	/* list of attributes for elements */
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
    int                flags;         /* parser flags */
    int                nbErrors;      /* number of errors at parse time */
    int                nbWarnings;    /* number of warnings at parse time */
    const xmlChar     *define;        /* the current define scope */

    xmlChar	      *URL;
    xmlDocPtr          doc;

    const char     *buffer;
    int               size;

    /*
     * Used to build complex element content models
     */
    xmlAutomataPtr     am;
    xmlAutomataStatePtr start;
    xmlAutomataStatePtr end;
    xmlAutomataStatePtr state;
};

#define FLAGS_IGNORABLE		1
#define FLAGS_NEGATIVE		2

/**
 * xmlRelaxNGValidState:
 *
 * A RelaxNGs validation state
 */
#define MAX_ATTR 20
typedef struct _xmlRelaxNGValidState xmlRelaxNGValidState;
typedef xmlRelaxNGValidState *xmlRelaxNGValidStatePtr;
struct _xmlRelaxNGValidState {
    xmlNodePtr node;		/* the current node */
    xmlNodePtr  seq;		/* the sequence of children left to validate */
    int     nbAttrs;		/* the number of attributes */
    xmlChar  *value;		/* the value when operating on string */
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
static void xmlRelaxNGFreeDefineList(xmlRelaxNGDefinePtr defines);
static void xmlRelaxNGFreeGrammar(xmlRelaxNGGrammarPtr grammar);
static void xmlRelaxNGFreeDefine(xmlRelaxNGDefinePtr define);

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

#if 0
    if (schema->elemDecl != NULL)
        xmlHashFree(schema->elemDecl,
                    (xmlHashDeallocator) xmlRelaxNGFreeElement);
    if (schema->typeDecl != NULL)
        xmlHashFree(schema->typeDecl,
                    (xmlHashDeallocator) xmlRelaxNGFreeType);
#endif

    if (schema->topgrammar != NULL)
	xmlRelaxNGFreeGrammar(schema->topgrammar);
    if (schema->doc != NULL)
	xmlFreeDoc(schema->doc);

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
 * xmlRelaxNGFreeDefineHash:
 * @defines:  a list of define structures
 *
 * Deallocate a RelaxNG definition in the hash table
 */
static void
xmlRelaxNGFreeDefineHash(xmlRelaxNGDefinePtr defines)
{
    xmlRelaxNGDefinePtr next;

    while (defines != NULL) {
	next = defines->nextHash;
	xmlRelaxNGFreeDefine(defines);
	defines = next;
    }
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

    if (grammar->start != NULL)
	xmlRelaxNGFreeDefine(grammar->start);
    if (grammar->refs != NULL) {
	xmlHashFree(grammar->refs, NULL);
    }
    if (grammar->defs != NULL) {
	xmlHashFree(grammar->defs, (xmlHashDeallocator)
		xmlRelaxNGFreeDefineHash);
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

    ret = (xmlRelaxNGDefinePtr) xmlMalloc(sizeof(xmlRelaxNGDefine));
    if (ret == NULL) {
        if ((ctxt != NULL) && (ctxt->error != NULL))
            ctxt->error(ctxt->userData, "Out of memory\n");
	ctxt->nbErrors++;
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlRelaxNGDefine));
    ret->node = node;

    return (ret);
}

/**
 * xmlRelaxNGFreeDefineList:
 * @defines:  a list of define structures
 *
 * Deallocate a RelaxNG define structures.
 */
static void
xmlRelaxNGFreeDefineList(xmlRelaxNGDefinePtr defines)
{
    xmlRelaxNGDefinePtr next;

    while (defines != NULL) {
	next = defines->next;
	xmlRelaxNGFreeDefine(defines);
	defines = next;
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

    if (define->name != NULL)
	xmlFree(define->name);
    if (define->ns != NULL)
	xmlFree(define->ns);
    if (define->attrs != NULL)
	xmlRelaxNGFreeDefineList(define->attrs);
    if ((define->content != NULL) &&
	(define->type != XML_RELAXNG_REF))
	xmlRelaxNGFreeDefineList(define->content);
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
 * 			Error functions					*
 * 									*
 ************************************************************************/

#define VALID_CTXT() 							\
    if (ctxt->flags == 0) xmlGenericError(xmlGenericErrorContext,	\
	    "error detected at %s:%d\n",				\
            __FILE__, __LINE__);
#define VALID_ERROR if (ctxt->flags == 0) printf

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
	                 const xmlChar *type ATTRIBUTE_UNUSED) {
    TODO
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
	                  const xmlChar *type ATTRIBUTE_UNUSED,
			  const xmlChar *value ATTRIBUTE_UNUSED) {
    TODO
    return(1);
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
    TODO
    return(1);
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
	if (IS_RELAXNG(node, "element")) {
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
    }
    return(NULL);
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
	    ctxt->error(ctxt->userData,
		"Internal error with type library '%s': no 'have'\n",
		        library);
	    ctxt->nbErrors++;
	} else {
	    tmp = lib->have(lib->data, def->name);
	    if (tmp != 1) {
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
	content = content->next;
    }

    return(def);
}


/**
 * xmlRelaxNGParseDefine:
 * @ctxt:  a Relax-NG parser context
 * @node:  the define node
 *
 * parse the content of a RelaxNG define element node.
 *
 * Returns the definition pointer or NULL in case of error.
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
	    def->content = xmlRelaxNGParsePatterns(ctxt,
					       node->children);
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
	    xmlRelaxNGFreeDefine(def);
	} else {
	    tmp = xmlHashAddEntry(ctxt->grammar->defs, name, def);
	    if (tmp < 0) {
		TODO
		/* store and implement 4.17 on combining */
		ctxt->nbErrors++;
		ret = -1;
		xmlRelaxNGFreeDefine(def);
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
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children);
    } else if (IS_RELAXNG(node, "oneOrMore")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_ZEROORMORE;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children);
    } else if (IS_RELAXNG(node, "optional")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_OPTIONAL;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children);
    } else if (IS_RELAXNG(node, "choice")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_CHOICE;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children);
    } else if (IS_RELAXNG(node, "group")) {
	def = xmlRelaxNGNewDefine(ctxt, node);
	if (def == NULL)
	    return(NULL);
	def->type = XML_RELAXNG_GROUP;
	def->content = xmlRelaxNGParsePatterns(ctxt, node->children);
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
	    xmlRelaxNGFreeDefine(def);
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
		    xmlRelaxNGFreeDefine(def);
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
    } else {
	TODO
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
    xmlChar *val;
    int old_flags;

    ret = xmlRelaxNGNewDefine(ctxt, node);
    if (ret == NULL)
	return(NULL);
    ret->type = XML_RELAXNG_ATTRIBUTE;
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
    if (IS_RELAXNG(child, "name")) {
	val = xmlNodeGetContent(child);
	ret->name = val;
	val = xmlGetProp(child, BAD_CAST "ns");
	ret->ns = val;
    } else if (IS_RELAXNG(child, "anyName")) {
	TODO
    } else if (IS_RELAXNG(child, "nsName")) {
	TODO
    } else if (IS_RELAXNG(child, "choice")) {
	TODO
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
    "element: expecting name, anyName, nsName or choice : got %s\n",
			child->name);
	ctxt->nbErrors++;
	ctxt->flags = old_flags;
	return(ret);
    }
    child = child->next;
    last = NULL;
    while (child != NULL) {
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
		    break;
		case XML_RELAXNG_ATTRIBUTE:
		    cur->next = ret->attrs;
		    ret->attrs = cur;
		    break;
	    }
	}
	child = child->next;
    }
    ctxt->flags = old_flags;
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
    xmlChar *val;
    const xmlChar *olddefine;

    ret = xmlRelaxNGNewDefine(ctxt, node);
    if (ret == NULL)
	return(NULL);
    ret->type = XML_RELAXNG_ELEMENT;
    child = node->children;
    if (child == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"xmlRelaxNGParseElement: element has no children\n");
	ctxt->nbErrors++;
	return(ret);
    } 
    if (IS_RELAXNG(child, "name")) {
	val = xmlNodeGetContent(child);
	ret->name = val;
	val = xmlGetProp(child, BAD_CAST "ns");
	ret->ns = val;
    } else if (IS_RELAXNG(child, "anyName")) {
	TODO
    } else if (IS_RELAXNG(child, "nsName")) {
	TODO
    } else if (IS_RELAXNG(child, "choice")) {
	TODO
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
    "element: expecting name, anyName, nsName or choice : got %s\n",
			child->name);
	ctxt->nbErrors++;
	return(ret);
    }
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
	    switch (cur->type) {
		case XML_RELAXNG_EMPTY:
		case XML_RELAXNG_NOT_ALLOWED:
		case XML_RELAXNG_TEXT:
		case XML_RELAXNG_ELEMENT:
		case XML_RELAXNG_DATATYPE:
		case XML_RELAXNG_VALUE:
		case XML_RELAXNG_LIST:
		case XML_RELAXNG_REF:
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
 *
 * parse the content of a RelaxNG start node.
 *
 * Returns the definition pointer or NULL in case of error.
 */
static xmlRelaxNGDefinePtr
xmlRelaxNGParsePatterns(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes) {
    xmlRelaxNGDefinePtr def = NULL, last = NULL, cur;

    while (nodes != NULL) {
	if (IS_RELAXNG(nodes, "element")) {
	    cur = xmlRelaxNGParseElement(ctxt, nodes);
	    if (def == NULL) {
		def = last = cur;
	    } else {
		if ((def->type == XML_RELAXNG_ELEMENT) && (def == last)) {
		    def = xmlRelaxNGNewDefine(ctxt, nodes);
		    def->type = XML_RELAXNG_GROUP;
		    def->content = last;
		}
		last->next = cur;
		last = cur;
	    }
	} else {
	    cur = xmlRelaxNGParsePattern(ctxt, nodes);
	    if (def == NULL) {
		def = last = cur;
	    } else {
		last->next = cur;
		last = cur;
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
	    xmlElemDump(stdout, nodes->doc, nodes);
	} else if (IS_RELAXNG(nodes, "notAllowed")) {
	    TODO
	    xmlElemDump(stdout, nodes->doc, nodes);
	} else {
	    def = xmlRelaxNGParsePatterns(ctxt, nodes);
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
xmlRelaxNGParseGrammarContent(xmlRelaxNGParserCtxtPtr ctxt
                              ATTRIBUTE_UNUSED, xmlNodePtr nodes)
{
    int ret = 0;

    if (nodes == NULL) {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"grammar has no children\n");
	ctxt->nbErrors++;
	return(-1);
    }
    if (IS_RELAXNG(nodes, "start")) {
	if (nodes->children == NULL) {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			    "grammar has no children\n");
	    ctxt->nbErrors++;
	} else {
	    xmlRelaxNGParseStart(ctxt, nodes->children);
	}
	nodes = nodes->next;
    } else {
	if (ctxt->error != NULL)
	    ctxt->error(ctxt->userData,
			"grammar first child must be a <start>\n");
	ctxt->nbErrors++;
	return(-1);
    }
    while (nodes != NULL) {
        if (IS_RELAXNG(nodes, "define")) {
	    ret = xmlRelaxNGParseDefine(ctxt, nodes);
        } else {
	    if (ctxt->error != NULL)
		ctxt->error(ctxt->userData,
			"grammar allows onlys <define> child after <start>\n");
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
	    } else if (xmlStrEqual(combine, BAD_CAST "choice")) {
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
	cur->type = XML_RELAXNG_CHOICE;
    else
	cur->type = XML_RELAXNG_INTERLEAVE;
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

    starts = grammar->start;
    if (starts->nextHash == NULL)
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
	ctxt->grammar = schema->topgrammar;
	xmlRelaxNGParseStart(ctxt, node);
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
	xmlFreeDoc(ctxt->doc);
    xmlFree(ctxt);
}


/**
 * xmlRelaxNGParse:
 * @ctxt:  a Relax-NG validation context
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
    xmlNodePtr root, cur, delete;

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
    ctxt->doc = doc;

    /*
     * Then extract the root and RelaxNG parse it
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
		    TODO
		} else if (xmlStrEqual(cur->name, BAD_CAST "include")) {
		    TODO
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
			if (text == NULL) {
			    if (ctxt->error != NULL)
				ctxt->error(ctxt->userData,
			    "xmlRelaxNGParse: attribute without name\n");
			    ctxt->nbErrors++;
			} else {
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
     * if there was a parsing error return NULL
     */
    if (ctxt->nbErrors > 0) {
	xmlRelaxNGFree(ret);
	return(NULL);
    }

    /*
     * Transfer the pointer for cleanup at the schema level.
     */
    ret->doc = doc;
    ctxt->doc = NULL;

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
        case XML_RELAXNG_DATATYPE:
        case XML_RELAXNG_VALUE:
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
	    ((node->type == XML_TEXT_NODE) &&
	     (IS_BLANK_NODE(node))))) {
	node = node->next;
    }
    return(node);
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
	VALID_ERROR("Internal: failed to validate type %s\n", define->name);
	return(-1);
    } else if (ret == 1) {
	ret = 0;
    } else {
	VALID_CTXT();
	VALID_ERROR("Type %s doesn't allow value %s\n", define->name, value);
	return(-1);
	ret = -1;
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
    int ret = 0;
    xmlChar *value;

    value = ctxt->state->value;
    switch (define->type) {
	case XML_RELAXNG_EMPTY:
	    if ((value != NULL) && (value[0] != '0'))
		ret = -1;
	    break;
	case XML_RELAXNG_TEXT:
	    break;
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
	    ret = xmlRelaxNGValidateValueContent(ctxt, define->content);
	    value = ctxt->state->value;
	    ctxt->state->value = oldvalue;
	    if (value != NULL)
		xmlFree(value);
	    if (ret == 0) {
		/*
		 * flag the attribute as processed
		 */
		ctxt->state->attrs[i] = NULL;
	    }
	} else {
	    ret = -1;
	}
#ifdef DEBUG
	xmlGenericError(xmlGenericErrorContext,
                    "xmlRelaxNGValidateAttribute(%s): %d\n", define->name, ret);
#endif
    } else {
	TODO
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
    switch (define->type) {
        case XML_RELAXNG_EMPTY:
	    if (node != NULL) {
		VALID_CTXT();
		VALID_ERROR("Expecting an empty element\n");
		return(-1);
	    }
#ifdef DEBUG
	    xmlGenericError(xmlGenericErrorContext,
                    "xmlRelaxNGValidateDefinition(): validated empty\n");
#endif
	    return(0);
        case XML_RELAXNG_NOT_ALLOWED:
	    TODO
	    break;
        case XML_RELAXNG_TEXT:
	    if (node == NULL)
		return(0);
	    while ((node != NULL) &&
		   ((node->type == XML_TEXT_NODE) ||
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
	    if ((node == NULL) || (node->type != XML_ELEMENT_NODE)) {
		VALID_CTXT();
		VALID_ERROR("Expecting an element\n");
		return(-1);
	    }
	    if (define->name != NULL) {
		if (!xmlStrEqual(node->name, define->name)) {
		    VALID_CTXT();
		    VALID_ERROR("Expecting element %s, got %s\n",
			        define->name, node->name);
		    return(-1);
		}
	    }
	    if ((define->ns != NULL) && (define->ns[0] != 0)) {
		if (node->ns == NULL) {
		    VALID_CTXT();
		    VALID_ERROR("Expecting a namespace for element %s\n",
			        node->name);
		    return(-1);
		} else if (!xmlStrEqual(node->ns->href, define->ns)) {
		    VALID_CTXT();
		    VALID_ERROR("Expecting element %s has wrong namespace: expecting %s\n",
			        node->name, define->ns);
		    return(-1);
		}
	    } else {
		if (node->ns != NULL) {
		    VALID_CTXT();
		    VALID_ERROR("Expecting no namespace for element %s\n",
			        node->name);
		    return(-1);
		}
	    }
	    
	    state = xmlRelaxNGNewValidState(ctxt, node);
	    if (state == NULL) {
		return(-1);
	    }

	    oldstate = ctxt->state;
	    ctxt->state = state;
	    if (define->attrs != NULL) {
		tmp = xmlRelaxNGValidateAttributeList(ctxt, define->attrs);
		if (tmp != 0)
		    ret = -1;
	    }
	    if (define->content != NULL) {
		tmp = xmlRelaxNGValidateElementContent(ctxt, define->content);
		if (tmp != 0)
		    ret = -1;
	    }
	    state = ctxt->state;
	    if (state->seq != NULL) {
		state->seq = xmlRelaxNGSkipIgnored(ctxt, state->seq);
		if (state->seq != NULL) {
		    VALID_CTXT();
		    VALID_ERROR("Extra content for element %s\n",
				node->name);
		    ret = -1;
		}
	    }
	    for (i = 0;i < state->nbAttrs;i++) {
		if (state->attrs[i] != NULL) {
		    VALID_CTXT();
		    VALID_ERROR("Extra attribute %s for element %s\n",
				state->attrs[i]->name, node->name);
		    ret = -1;
		}
	    }
	    ctxt->state = oldstate;
	    xmlRelaxNGFreeValidState(state);
	    if (oldstate != NULL)
		oldstate->seq = node->next;


#ifdef DEBUG
	    xmlGenericError(xmlGenericErrorContext,
                    "xmlRelaxNGValidateDefinition(): validated %s : %d\n",
		            node->name, ret);
#endif
	    break;
        case XML_RELAXNG_LIST:
	    TODO
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
            xmlNodePtr cur, temp;

	    oldflags = ctxt->flags;
	    ctxt->flags |= FLAGS_IGNORABLE;
	    cur = ctxt->state->seq;
	    temp = NULL;
	    while ((cur != NULL) && (temp != cur)) {
		temp = cur;
		oldstate = xmlRelaxNGCopyValidState(ctxt, ctxt->state);
		ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
		if (ret != 0) {
		    xmlRelaxNGFreeValidState(ctxt->state);
		    ctxt->state = oldstate;
		    ret = 0;
		    break;
		}
		xmlRelaxNGFreeValidState(oldstate);
		cur = ctxt->state->seq;
	    }
	    ctxt->flags = oldflags;
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
	    TODO
	    break;
        case XML_RELAXNG_ATTRIBUTE:
	    ret = xmlRelaxNGValidateAttribute(ctxt, define);
	    break;
        case XML_RELAXNG_REF:
	    ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
	    break;
        case XML_RELAXNG_DEF:
	    ret = xmlRelaxNGValidateDefinition(ctxt, define->content);
	    break;
        case XML_RELAXNG_DATATYPE: {
	    xmlChar *content;

	    content = xmlNodeGetContent(node);
	    ret = xmlRelaxNGValidateDatatype(ctxt, content, define);
	    if (ret == -1) {
		VALID_CTXT();
		VALID_ERROR("internal error validating %s\n", define->name);
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
		VALID_ERROR("The data does not cover the full element %s\n",
			    node->parent->name);
		ret = -1;
	    }
	    if (content != NULL)
		xmlFree(content);
	    break;
	}
        case XML_RELAXNG_VALUE:
	    TODO
	    break;
    }
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
    return(ret);
}

#endif /* LIBXML_SCHEMAS_ENABLED */

