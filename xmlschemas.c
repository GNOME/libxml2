/*
 * schemas.c : implementation of the XML Schema handling and
 *             schema validity checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

/*
 * TODO:
 *   - when types are redefined in includes, check that all
 *     types in the redef list are equal
 *     -> need a type equality operation.
 */
#define IN_LIBXML
#include "libxml.h"

#ifdef LIBXML_SCHEMAS_ENABLED

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/hash.h>
#include <libxml/uri.h>

#include <libxml/xmlschemas.h>
#include <libxml/schemasInternals.h>
#include <libxml/xmlschemastypes.h>
#include <libxml/xmlautomata.h>
#include <libxml/xmlregexp.h>
#include <libxml/dict.h>

/* #define DEBUG 1 */

/* #define DEBUG_CONTENT 1 */

/* #define DEBUG_TYPE 1 */

/* #define DEBUG_CONTENT_REGEXP 1 */

/* #define DEBUG_AUTOMATA 1 */

/* #define DEBUG_ATTR_VALIDATION 1 */

#define UNBOUNDED (1 << 30)
#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

#define XML_SCHEMAS_DEFAULT_NAMESPACE (const xmlChar *)"the default namespace"

/*
 * The XML Schemas namespaces
 */
static const xmlChar *xmlSchemaNs = (const xmlChar *)
    "http://www.w3.org/2001/XMLSchema";

static const xmlChar *xmlSchemaInstanceNs = (const xmlChar *)
    "http://www.w3.org/2001/XMLSchema-instance";

#define IS_SCHEMA(node, type)						\
   ((node != NULL) && (node->ns != NULL) &&				\
    (xmlStrEqual(node->name, (const xmlChar *) type)) &&		\
    (xmlStrEqual(node->ns->href, xmlSchemaNs)))

#define XML_SCHEMAS_PARSE_ERROR		1

#define SCHEMAS_PARSE_OPTIONS XML_PARSE_NOENT

struct _xmlSchemaParserCtxt {
    void *userData;             /* user specific data block */
    xmlSchemaValidityErrorFunc error;   /* the callback in case of errors */
    xmlSchemaValidityWarningFunc warning;       /* the callback in case of warning */
    xmlSchemaValidError err;
    int nberrors;
    xmlStructuredErrorFunc serror;

    xmlSchemaPtr topschema;	/* The main schema */
    xmlHashTablePtr namespaces;	/* Hash table of namespaces to schemas */

    xmlSchemaPtr schema;        /* The schema in use */
    const xmlChar *container;   /* the current element, group, ... */
    int counter;

    const xmlChar *URL;
    xmlDocPtr doc;
    int preserve;		/* Whether the doc should be freed  */

    const char *buffer;
    int size;

    /*
     * Used to build complex element content models
     */
    xmlAutomataPtr am;
    xmlAutomataStatePtr start;
    xmlAutomataStatePtr end;
    xmlAutomataStatePtr state;

    xmlDictPtr dict;		/* dictionnary for interned string names */
    int        includes;	/* the inclusion level, 0 for root or imports */
};


#define XML_SCHEMAS_ATTR_UNKNOWN 1
#define XML_SCHEMAS_ATTR_CHECKED 2
#define XML_SCHEMAS_ATTR_PROHIBITED 3
#define XML_SCHEMAS_ATTR_MISSING 4
#define XML_SCHEMAS_ATTR_INVALID_VALUE 5
#define XML_SCHEMAS_ATTR_TYPE_NOT_RESOLVED 6

typedef struct _xmlSchemaAttrState xmlSchemaAttrState;
typedef xmlSchemaAttrState *xmlSchemaAttrStatePtr;
struct _xmlSchemaAttrState {
    xmlSchemaAttrStatePtr next;
    xmlAttrPtr attr;
    int state;
    xmlSchemaAttributePtr decl;
};

/**
 * xmlSchemaValidCtxt:
 *
 * A Schemas validation context
 */

struct _xmlSchemaValidCtxt {
    void *userData;             /* user specific data block */
    xmlSchemaValidityErrorFunc error;   /* the callback in case of errors */
    xmlSchemaValidityWarningFunc warning;       /* the callback in case of warning */
    xmlStructuredErrorFunc serror;

    xmlSchemaPtr schema;        /* The schema in use */
    xmlDocPtr doc;
    xmlParserInputBufferPtr input;
    xmlCharEncoding enc;
    xmlSAXHandlerPtr sax;
    void *user_data;

    xmlDocPtr myDoc;
    int err;
    int nberrors;

    xmlNodePtr node;
    xmlNodePtr cur;
    xmlSchemaTypePtr type;

    xmlRegExecCtxtPtr regexp;
    xmlSchemaValPtr value;

    xmlSchemaAttrStatePtr attrTop;
    /* xmlSchemaAttrStatePtr attrBase; */
    /* int attrMax; */
    xmlSchemaAttrStatePtr attr;
};

/*
 * These are the entries in the schemas importSchemas hash table
 */
typedef struct _xmlSchemaImport xmlSchemaImport;
typedef xmlSchemaImport *xmlSchemaImportPtr;
struct _xmlSchemaImport {
    const xmlChar *schemaLocation;
    xmlSchemaPtr schema;
};

/*
 * These are the entries associated to includes in a schemas
 */
typedef struct _xmlSchemaInclude xmlSchemaInclude;
typedef xmlSchemaInclude *xmlSchemaIncludePtr;
struct _xmlSchemaInclude {
    xmlSchemaIncludePtr next;

    const xmlChar *schemaLocation;
    xmlDocPtr doc;
};

/************************************************************************
 * 									*
 * 			Some predeclarations				*
 * 									*
 ************************************************************************/
static int xmlSchemaValidateSimpleValue(xmlSchemaValidCtxtPtr ctxt,
                                        xmlSchemaTypePtr type,
                                        const xmlChar * value);

static int xmlSchemaParseInclude(xmlSchemaParserCtxtPtr ctxt,
                                 xmlSchemaPtr schema,
                                 xmlNodePtr node);
static int
xmlSchemaValidateSimpleValueInternal(xmlSchemaValidCtxtPtr ctxt,
                             xmlSchemaTypePtr type,
			     const xmlChar * value,
			     int fireErrors);

/************************************************************************
 *									*
 * 			Datatype error handlers				*
 *									*
 ************************************************************************/

/**
 * xmlSchemaPErrMemory:
 * @node: a context node
 * @extra:  extra informations
 *
 * Handle an out of memory condition
 */
static void
xmlSchemaPErrMemory(xmlSchemaParserCtxtPtr ctxt,
                    const char *extra, xmlNodePtr node)
{
    if (ctxt != NULL)
        ctxt->nberrors++;
    __xmlSimpleError(XML_FROM_SCHEMASP, XML_ERR_NO_MEMORY, node, NULL,
                     extra);
}

/**
 * xmlSchemaPErr:
 * @ctxt: the parsing context
 * @node: the context node
 * @error: the error code
 * @msg: the error message
 * @str1: extra data
 * @str2: extra data
 * 
 * Handle a parser error
 */
static void
xmlSchemaPErr(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node, int error,
              const char *msg, const xmlChar * str1, const xmlChar * str2)
{
    xmlGenericErrorFunc channel = NULL;
    xmlStructuredErrorFunc schannel = NULL;
    void *data = NULL;

    if (ctxt != NULL) {
        ctxt->nberrors++;
        channel = ctxt->error;
        data = ctxt->userData;
	schannel = ctxt->serror;
    }
    __xmlRaiseError(schannel, channel, data, ctxt, node, XML_FROM_SCHEMASP,
                    error, XML_ERR_ERROR, NULL, 0,
                    (const char *) str1, (const char *) str2, NULL, 0, 0,
                    msg, str1, str2);
}

/**
 * xmlSchemaPErr2:
 * @ctxt: the parsing context
 * @node: the context node
 * @node: the current child
 * @error: the error code
 * @msg: the error message
 * @str1: extra data
 * @str2: extra data
 * 
 * Handle a parser error
 */
static void
xmlSchemaPErr2(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node,
               xmlNodePtr child, int error,
               const char *msg, const xmlChar * str1, const xmlChar * str2)
{
    if (child != NULL)
        xmlSchemaPErr(ctxt, child, error, msg, str1, str2);
    else
        xmlSchemaPErr(ctxt, node, error, msg, str1, str2);
}

#if 0
/**
 * xmlSchemaPErrExt:
 * @ctxt: the parsing context
 * @node: the context node
 * @error: the error code 
 * @strData1: extra data
 * @strData2: extra data
 * @strData3: extra data
 * @msg: the message
 * @str1:  extra parameter for the message display
 * @str2:  extra parameter for the message display
 * @str3:  extra parameter for the message display
 * @str4:  extra parameter for the message display
 * @str5:  extra parameter for the message display
 * 
 * Handle a parser error
 */
static void
xmlSchemaPErrExt(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node, int error,
		const xmlChar * strData1, const xmlChar * strData2, 
		const xmlChar * strData3, const char *msg, const xmlChar * str1, 
		const xmlChar * str2, const xmlChar * str3, const xmlChar * str4,
		const xmlChar * str5)
{

    xmlGenericErrorFunc channel = NULL;
    xmlStructuredErrorFunc schannel = NULL;
    void *data = NULL;

    if (ctxt != NULL) {
        ctxt->nberrors++;
        channel = ctxt->error;
        data = ctxt->userData;
	schannel = ctxt->serror;
    }
    __xmlRaiseError(schannel, channel, data, ctxt, node, XML_FROM_SCHEMASP,
                    error, XML_ERR_ERROR, NULL, 0,
                    (const char *) strData1, (const char *) strData2, 
		    (const char *) strData3, 0, 0, msg, str1, str2, 
		    str3, str4, str5);
}
#endif

/**
 * xmlSchemaVTypeErrMemory:
 * @node: a context node
 * @extra:  extra informations
 *
 * Handle an out of memory condition
 */
static void
xmlSchemaVErrMemory(xmlSchemaValidCtxtPtr ctxt,
                    const char *extra, xmlNodePtr node)
{
    if (ctxt != NULL) {
        ctxt->nberrors++;
        ctxt->err = XML_SCHEMAS_ERR_INTERNAL;
    }
    __xmlSimpleError(XML_FROM_SCHEMASV, XML_ERR_NO_MEMORY, node, NULL,
                     extra);
}

/**
 * xmlSchemaVErr3:
 * @ctxt: the validation context
 * @node: the context node
 * @error: the error code
 * @msg: the error message
 * @str1: extra data
 * @str2: extra data
 * @str3: extra data
 * 
 * Handle a validation error
 */
static void
xmlSchemaVErr3(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node, int error,
               const char *msg, const xmlChar *str1, const xmlChar *str2,
	       const xmlChar *str3)
{
    xmlStructuredErrorFunc schannel = NULL;
    xmlGenericErrorFunc channel = NULL;
    void *data = NULL;

    if (ctxt != NULL) {
        ctxt->nberrors++;
	ctxt->err = error;
        channel = ctxt->error;
        schannel = ctxt->serror;
        data = ctxt->userData;
    }
    /* reajust to global error numbers */
    error += XML_SCHEMAV_NOROOT - XML_SCHEMAS_ERR_NOROOT;
    __xmlRaiseError(schannel, channel, data, ctxt, node, XML_FROM_SCHEMASV,
                    error, XML_ERR_ERROR, NULL, 0,
                    (const char *) str1, (const char *) str2,
		    (const char *) str3, 0, 0,
                    msg, str1, str2, str3);
}
/**
 * xmlSchemaVErr:
 * @ctxt: the validation context
 * @node: the context node
 * @error: the error code
 * @msg: the error message
 * @str1: extra data
 * @str2: extra data
 * 
 * Handle a validation error
 */
static void
xmlSchemaVErr(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node, int error,
              const char *msg, const xmlChar * str1, const xmlChar * str2)
{
    xmlStructuredErrorFunc schannel = NULL;
    xmlGenericErrorFunc channel = NULL;
    void *data = NULL;

    if (ctxt != NULL) {
        ctxt->nberrors++;
	ctxt->err = error;
        channel = ctxt->error;
        data = ctxt->userData;
        schannel = ctxt->serror;
    }
    /* reajust to global error numbers */
    error += XML_SCHEMAV_NOROOT - XML_SCHEMAS_ERR_NOROOT;
    __xmlRaiseError(schannel, channel, data, ctxt, node, XML_FROM_SCHEMASV,
                    error, XML_ERR_ERROR, NULL, 0,
                    (const char *) str1, (const char *) str2, NULL, 0, 0,
                    msg, str1, str2);
}

/************************************************************************
 * 									*
 * 			Allocation functions				*
 * 									*
 ************************************************************************/

/**
 * xmlSchemaNewSchema:
 * @ctxt:  a schema validation context
 *
 * Allocate a new Schema structure.
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlSchemaPtr
xmlSchemaNewSchema(xmlSchemaParserCtxtPtr ctxt)
{
    xmlSchemaPtr ret;

    ret = (xmlSchemaPtr) xmlMalloc(sizeof(xmlSchema));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating schema", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchema));
    ret->dict = ctxt->dict;
    xmlDictReference(ret->dict);

    return (ret);
}

/**
 * xmlSchemaNewFacet:
 *
 * Allocate a new Facet structure.
 *
 * Returns the newly allocated structure or NULL in case or error
 */
xmlSchemaFacetPtr
xmlSchemaNewFacet(void)
{
    xmlSchemaFacetPtr ret;

    ret = (xmlSchemaFacetPtr) xmlMalloc(sizeof(xmlSchemaFacet));
    if (ret == NULL) {
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaFacet));

    return (ret);
}

/**
 * xmlSchemaNewAnnot:
 * @ctxt:  a schema validation context
 * @node:  a node
 *
 * Allocate a new annotation structure.
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlSchemaAnnotPtr
xmlSchemaNewAnnot(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node)
{
    xmlSchemaAnnotPtr ret;

    ret = (xmlSchemaAnnotPtr) xmlMalloc(sizeof(xmlSchemaAnnot));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating annotation", node);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaAnnot));
    ret->content = node;
    return (ret);
}

/**
 * xmlSchemaFreeAnnot:
 * @annot:  a schema type structure
 *
 * Deallocate a annotation structure
 */
static void
xmlSchemaFreeAnnot(xmlSchemaAnnotPtr annot)
{
    if (annot == NULL)
        return;
    xmlFree(annot);
}

/**
 * xmlSchemaFreeImport:
 * @import:  a schema import structure
 *
 * Deallocate an import structure
 */
static void
xmlSchemaFreeImport(xmlSchemaImportPtr import)
{
    if (import == NULL)
        return;

    xmlSchemaFree(import->schema);
    xmlFree(import);
}

/**
 * xmlSchemaFreeInclude:
 * @include:  a schema include structure
 *
 * Deallocate an include structure
 */
static void
xmlSchemaFreeInclude(xmlSchemaIncludePtr include)
{
    if (include == NULL)
        return;

    xmlFreeDoc(include->doc);
    xmlFree(include);
}

/**
 * xmlSchemaFreeIncludeList:
 * @includes:  a schema include list
 *
 * Deallocate an include structure
 */
static void
xmlSchemaFreeIncludeList(xmlSchemaIncludePtr includes)
{
    xmlSchemaIncludePtr next;

    while (includes != NULL) {
        next = includes->next;
	xmlSchemaFreeInclude(includes);
	includes = next;
    }
}

/**
 * xmlSchemaFreeNotation:
 * @schema:  a schema notation structure
 *
 * Deallocate a Schema Notation structure.
 */
static void
xmlSchemaFreeNotation(xmlSchemaNotationPtr nota)
{
    if (nota == NULL)
        return;
    xmlFree(nota);
}

/**
 * xmlSchemaFreeAttribute:
 * @schema:  a schema attribute structure
 *
 * Deallocate a Schema Attribute structure.
 */
static void
xmlSchemaFreeAttribute(xmlSchemaAttributePtr attr)
{
    if (attr == NULL)
        return;
    xmlFree(attr);
}

/**
 * xmlSchemaFreeWildcardNsSet:
 * set:  a schema wildcard namespace
 *
 * Deallocate a list of wildcard constraint structures.
 */
static void
xmlSchemaFreeWildcardNsSet(xmlSchemaWildcardNsPtr set)
{
    xmlSchemaWildcardNsPtr next;

    while (set != NULL) {
	next = set->next;
	xmlFree(set);
	set = next;
    }
}

/**
 * xmlSchemaFreeWildcard:
 * @schema:  a schema attribute group structure
 *
 * Deallocate a Schema Attribute Group structure.
 */
static void
xmlSchemaFreeWildcard(xmlSchemaWildcardPtr wildcard)
{
    if (wildcard == NULL)
        return;
    if (wildcard->annot != NULL)
        xmlSchemaFreeAnnot(wildcard->annot);
    if (wildcard->nsSet != NULL) 
	xmlSchemaFreeWildcardNsSet(wildcard->nsSet);    
    if (wildcard->negNsSet != NULL) 
	xmlFree(wildcard->negNsSet);    
    xmlFree(wildcard);
}

/**
 * xmlSchemaFreeAttributeGroup:
 * @schema:  a schema attribute group structure
 *
 * Deallocate a Schema Attribute Group structure.
 */
static void
xmlSchemaFreeAttributeGroup(xmlSchemaAttributeGroupPtr attr)
{
    if (attr == NULL)
        return;
    if (attr->annot != NULL)
        xmlSchemaFreeAnnot(attr->annot);
    if ((attr->flags & XML_SCHEMAS_ATTRGROUP_GLOBAL) && 
	(attr->attributeWildcard != NULL))
	xmlSchemaFreeWildcard(attr->attributeWildcard);

    xmlFree(attr);
}

/**
 * xmlSchemaFreeAttributeUseList:
 * @attrUse:  a schema attribute link structure
 *
 * Deallocate a list of schema attribute uses.
 */
static void
xmlSchemaFreeAttributeUseList(xmlSchemaAttributeLinkPtr attrUse)
{
    xmlSchemaAttributeLinkPtr next;

    while (attrUse != NULL) {
	next = attrUse->next;
	xmlFree(attrUse);
	attrUse = next;
    }    
}

/**
 * xmlSchemaFreeElement:
 * @schema:  a schema element structure
 *
 * Deallocate a Schema Element structure.
 */
static void
xmlSchemaFreeElement(xmlSchemaElementPtr elem)
{
    if (elem == NULL)
        return;
    if (elem->annot != NULL)
        xmlSchemaFreeAnnot(elem->annot);
    if (elem->contModel != NULL)
        xmlRegFreeRegexp(elem->contModel);
    xmlFree(elem);
}

/**
 * xmlSchemaFreeFacet:
 * @facet:  a schema facet structure
 *
 * Deallocate a Schema Facet structure.
 */
void
xmlSchemaFreeFacet(xmlSchemaFacetPtr facet)
{
    if (facet == NULL)
        return;
    if (facet->val != NULL)
        xmlSchemaFreeValue(facet->val);
    if (facet->regexp != NULL)
        xmlRegFreeRegexp(facet->regexp);
    if (facet->annot != NULL)
        xmlSchemaFreeAnnot(facet->annot);
    xmlFree(facet);
}

/**
 * xmlSchemaFreeType:
 * @type:  a schema type structure
 *
 * Deallocate a Schema Type structure.
 */
void
xmlSchemaFreeType(xmlSchemaTypePtr type)
{
    if (type == NULL)
        return;
    if (type->annot != NULL)
        xmlSchemaFreeAnnot(type->annot);
    if (type->facets != NULL) {
        xmlSchemaFacetPtr facet, next;

        facet = type->facets;
        while (facet != NULL) {
            next = facet->next;
            xmlSchemaFreeFacet(facet);
            facet = next;
        }
    }
    if (type->type != XML_SCHEMA_TYPE_BASIC) {
	if (type->attributeUses != NULL)
	    xmlSchemaFreeAttributeUseList(type->attributeUses);
	if ((type->attributeWildcard != NULL) && 
	    ((type->type != XML_SCHEMA_TYPE_COMPLEX) ||
	    ((type->type == XML_SCHEMA_TYPE_COMPLEX) && 
	    (type->flags & XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD)))) { 
	    xmlSchemaFreeWildcard(type->attributeWildcard);
	}
    }
    xmlFree(type);
}

/**
 * xmlSchemaFreeTypeList:
 * @type:  a schema type structure
 *
 * Deallocate a Schema Type structure.
 */
static void
xmlSchemaFreeTypeList(xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr next;

    while (type != NULL) {
        next = type->redef;
	xmlSchemaFreeType(type);
	type = next;
    }
}

/**
 * xmlSchemaFree:
 * @schema:  a schema structure
 *
 * Deallocate a Schema structure.
 */
void
xmlSchemaFree(xmlSchemaPtr schema)
{
    if (schema == NULL)
        return;

    if (schema->notaDecl != NULL)
        xmlHashFree(schema->notaDecl,
                    (xmlHashDeallocator) xmlSchemaFreeNotation);
    if (schema->attrDecl != NULL)
        xmlHashFree(schema->attrDecl,
                    (xmlHashDeallocator) xmlSchemaFreeAttribute);
    if (schema->attrgrpDecl != NULL)
        xmlHashFree(schema->attrgrpDecl,
                    (xmlHashDeallocator) xmlSchemaFreeAttributeGroup);
    if (schema->elemDecl != NULL)
        xmlHashFree(schema->elemDecl,
                    (xmlHashDeallocator) xmlSchemaFreeElement);
    if (schema->typeDecl != NULL)
        xmlHashFree(schema->typeDecl,
                    (xmlHashDeallocator) xmlSchemaFreeTypeList);
    if (schema->groupDecl != NULL)
        xmlHashFree(schema->groupDecl,
                    (xmlHashDeallocator) xmlSchemaFreeType);
    if (schema->schemasImports != NULL)
	xmlHashFree(schema->schemasImports,
		    (xmlHashDeallocator) xmlSchemaFreeImport);
    if (schema->includes != NULL) {
        xmlSchemaFreeIncludeList((xmlSchemaIncludePtr) schema->includes);
    }
    if (schema->annot != NULL)
        xmlSchemaFreeAnnot(schema->annot);
    if (schema->doc != NULL && !schema->preserve)
        xmlFreeDoc(schema->doc);
    xmlDictFree(schema->dict);

    xmlFree(schema);
}

/************************************************************************
 * 									*
 * 			Debug functions					*
 * 									*
 ************************************************************************/

#ifdef LIBXML_OUTPUT_ENABLED

/**
 * xmlSchemaElementDump:
 * @elem:  an element
 * @output:  the file output
 *
 * Dump the element
 */
static void
xmlSchemaElementDump(xmlSchemaElementPtr elem, FILE * output,
                     const xmlChar * name ATTRIBUTE_UNUSED,
                     const xmlChar * context ATTRIBUTE_UNUSED,
                     const xmlChar * namespace ATTRIBUTE_UNUSED)
{
    if (elem == NULL)
        return;

    fprintf(output, "Element ");
    if (elem->flags & XML_SCHEMAS_ELEM_GLOBAL)
        fprintf(output, "global ");
    fprintf(output, ": %s ", elem->name);
    if (namespace != NULL)
        fprintf(output, "namespace '%s' ", namespace);

    if (elem->flags & XML_SCHEMAS_ELEM_NILLABLE)
        fprintf(output, "nillable ");
    if (elem->flags & XML_SCHEMAS_ELEM_DEFAULT)
        fprintf(output, "default ");
    if (elem->flags & XML_SCHEMAS_ELEM_FIXED)
        fprintf(output, "fixed ");
    if (elem->flags & XML_SCHEMAS_ELEM_ABSTRACT)
        fprintf(output, "abstract ");
    if (elem->flags & XML_SCHEMAS_ELEM_REF)
        fprintf(output, "ref '%s' ", elem->ref);
    if (elem->id != NULL)
        fprintf(output, "id '%s' ", elem->id);
    fprintf(output, "\n");
    if ((elem->minOccurs != 1) || (elem->maxOccurs != 1)) {
        fprintf(output, "  ");
        if (elem->minOccurs != 1)
            fprintf(output, "min: %d ", elem->minOccurs);
        if (elem->maxOccurs >= UNBOUNDED)
            fprintf(output, "max: unbounded\n");
        else if (elem->maxOccurs != 1)
            fprintf(output, "max: %d\n", elem->maxOccurs);
        else
            fprintf(output, "\n");
    }
    if (elem->namedType != NULL) {
        fprintf(output, "  type: %s", elem->namedType);
        if (elem->namedTypeNs != NULL)
            fprintf(output, " ns %s\n", elem->namedTypeNs);
        else
            fprintf(output, "\n");
    }
    if (elem->substGroup != NULL) {
        fprintf(output, "  substitutionGroup: %s", elem->substGroup);
        if (elem->substGroupNs != NULL)
            fprintf(output, " ns %s\n", elem->substGroupNs);
        else
            fprintf(output, "\n");
    }
    if (elem->value != NULL)
        fprintf(output, "  default: %s", elem->value);
}

/**
 * xmlSchemaAnnotDump:
 * @output:  the file output
 * @annot:  a annotation
 *
 * Dump the annotation
 */
static void
xmlSchemaAnnotDump(FILE * output, xmlSchemaAnnotPtr annot)
{
    xmlChar *content;

    if (annot == NULL)
        return;

    content = xmlNodeGetContent(annot->content);
    if (content != NULL) {
        fprintf(output, "  Annot: %s\n", content);
        xmlFree(content);
    } else
        fprintf(output, "  Annot: empty\n");
}

/**
 * xmlSchemaTypeDump:
 * @output:  the file output
 * @type:  a type structure
 *
 * Dump a SchemaType structure
 */
static void
xmlSchemaTypeDump(xmlSchemaTypePtr type, FILE * output)
{
    if (type == NULL) {
        fprintf(output, "Type: NULL\n");
        return;
    }
    fprintf(output, "Type: ");
    if (type->name != NULL)
        fprintf(output, "%s, ", type->name);
    else
        fprintf(output, "no name");
    switch (type->type) {
        case XML_SCHEMA_TYPE_BASIC:
            fprintf(output, "basic ");
            break;
        case XML_SCHEMA_TYPE_SIMPLE:
            fprintf(output, "simple ");
            break;
        case XML_SCHEMA_TYPE_COMPLEX:
            fprintf(output, "complex ");
            break;
        case XML_SCHEMA_TYPE_SEQUENCE:
            fprintf(output, "sequence ");
            break;
        case XML_SCHEMA_TYPE_CHOICE:
            fprintf(output, "choice ");
            break;
        case XML_SCHEMA_TYPE_ALL:
            fprintf(output, "all ");
            break;
        case XML_SCHEMA_TYPE_UR:
            fprintf(output, "ur ");
            break;
        case XML_SCHEMA_TYPE_RESTRICTION:
            fprintf(output, "restriction ");
            break;
        case XML_SCHEMA_TYPE_EXTENSION:
            fprintf(output, "extension ");
            break;
        default:
            fprintf(output, "unknowntype%d ", type->type);
            break;
    }
    if (type->base != NULL) {
        fprintf(output, "base %s, ", type->base);
    }
    switch (type->contentType) {
        case XML_SCHEMA_CONTENT_UNKNOWN:
            fprintf(output, "unknown ");
            break;
        case XML_SCHEMA_CONTENT_EMPTY:
            fprintf(output, "empty ");
            break;
        case XML_SCHEMA_CONTENT_ELEMENTS:
            fprintf(output, "element ");
            break;
        case XML_SCHEMA_CONTENT_MIXED:
            fprintf(output, "mixed ");
            break;
        case XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS:
            fprintf(output, "mixed_or_elems ");
            break;
        case XML_SCHEMA_CONTENT_BASIC:
            fprintf(output, "basic ");
            break;
        case XML_SCHEMA_CONTENT_SIMPLE:
            fprintf(output, "simple ");
            break;
        case XML_SCHEMA_CONTENT_ANY:
            fprintf(output, "any ");
            break;
    }
    fprintf(output, "\n");
    if ((type->minOccurs != 1) || (type->maxOccurs != 1)) {
        fprintf(output, "  ");
        if (type->minOccurs != 1)
            fprintf(output, "min: %d ", type->minOccurs);
        if (type->maxOccurs >= UNBOUNDED)
            fprintf(output, "max: unbounded\n");
        else if (type->maxOccurs != 1)
            fprintf(output, "max: %d\n", type->maxOccurs);
        else
            fprintf(output, "\n");
    }
    if (type->annot != NULL)
        xmlSchemaAnnotDump(output, type->annot);
    if (type->subtypes != NULL) {
        xmlSchemaTypePtr sub = type->subtypes;

        fprintf(output, "  subtypes: ");
        while (sub != NULL) {
            fprintf(output, "%s ", sub->name);
            sub = sub->next;
        }
        fprintf(output, "\n");
    }

}

/**
 * xmlSchemaDump:
 * @output:  the file output
 * @schema:  a schema structure
 *
 * Dump a Schema structure.
 */
void
xmlSchemaDump(FILE * output, xmlSchemaPtr schema)
{
    if (schema == NULL) {
        fprintf(output, "Schemas: NULL\n");
        return;
    }
    fprintf(output, "Schemas: ");
    if (schema->name != NULL)
        fprintf(output, "%s, ", schema->name);
    else
        fprintf(output, "no name, ");
    if (schema->targetNamespace != NULL)
        fprintf(output, "%s", (const char *) schema->targetNamespace);
    else
        fprintf(output, "no target namespace");
    fprintf(output, "\n");
    if (schema->annot != NULL)
        xmlSchemaAnnotDump(output, schema->annot);

    xmlHashScan(schema->typeDecl, (xmlHashScanner) xmlSchemaTypeDump,
                output);
    xmlHashScanFull(schema->elemDecl,
                    (xmlHashScannerFull) xmlSchemaElementDump, output);
}
#endif /* LIBXML_OUTPUT_ENABLED */

/************************************************************************
 *									*
 * 			Utilities					*
 *									*
 ************************************************************************/

/**
 * xmlSchemaGetProp:
 * @ctxt: the parser context
 * @node: the node
 * @name: the property name
 * 
 * Read a attribute value and internalize the string
 *
 * Returns the string or NULL if not present.
 */
static const xmlChar *
xmlSchemaGetProp(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node,
                 const char *name)
{
    xmlChar *val;
    const xmlChar *ret;

    val = xmlGetProp(node, BAD_CAST name);
    if (val == NULL)
        return(NULL);
    ret = xmlDictLookup(ctxt->dict, val, -1);
    xmlFree(val);
    return(ret);
}

#if 0
/**
 * xmlSchemaGetNamespace:
 * @ctxt: the parser context
 * @schema: the schemas containing the declaration
 * @node: the node
 * @qname: the QName to analyze
 * 
 * Find the namespace name for the given declaration.
 *
 * Returns the local name for that declaration, as well as the namespace name
 * NOTE: This function is no longer used (Buchcik, May '04) 
 */
static const xmlChar *
xmlSchemaGetNamespace(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
	              xmlNodePtr node, const xmlChar *qname,
	     const xmlChar **namespace) {
    int len;
    const xmlChar *name, *prefix, *def = NULL;
    xmlNsPtr ns;

    *namespace = NULL;
    
    /* TODO: The following seems to be not correct here:
     * 1. The name of a declaration is a NCName, not a QName.
     * 2. The attribute "targetNamespace" is allowed for the
     *    <schema> Element Information Item only.
     * 3. One cannot evaluate the target namespace, by the type
     *    of declaration, since it is dependant on the xxxFormDefault
     *    of <schema> and the form attribute of an <element> or <attribute>.
     */
   
    if (xmlStrEqual(node->name, BAD_CAST "element") ||
        xmlStrEqual(node->name, BAD_CAST "attribute") ||
	xmlStrEqual(node->name, BAD_CAST "simpleType") ||
	xmlStrEqual(node->name, BAD_CAST "complexType")) {
	def = xmlSchemaGetProp(ctxt, node, "targetNamespace");
    }


    qname = xmlDictLookup(ctxt->dict, qname, -1); /* intern the string */
    name = xmlSplitQName3(qname, &len);
    if (name == NULL) {
        if (def == NULL) {
	    if (xmlStrEqual(node->name, BAD_CAST "element")) {
		if (schema->flags & XML_SCHEMAS_QUALIF_ELEM)
		    *namespace = schema->targetNamespace;
	    } else if (xmlStrEqual(node->name, BAD_CAST "attribute")) {
		if (schema->flags & XML_SCHEMAS_QUALIF_ATTR)
		    *namespace = schema->targetNamespace;
	    } else if ((xmlStrEqual(node->name, BAD_CAST "simpleType")) ||
	               (xmlStrEqual(node->name, BAD_CAST "complexType"))) {
		*namespace = schema->targetNamespace;
	    }
	} else {
	    *namespace = def;
	}
	return(qname);
    }

    name = xmlDictLookup(ctxt->dict, name, -1);
    prefix = xmlDictLookup(ctxt->dict, qname, len);
    if (def != NULL) {
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_DEF_AND_PREFIX,
                      "%s: presence of both prefix %s and targetNamespace\n",
                      node->name, prefix);
    }
    ns = xmlSearchNs(node->doc, node, prefix);
    if (ns == NULL) {
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_PREFIX_UNDEFINED,
                      "%s: the QName prefix %s is undefined\n",
                      node->name, prefix);
	return(name);
    }
    *namespace = xmlDictLookup(ctxt->dict, ns->href, -1);
    return(name);
}
#endif

/************************************************************************
 * 									*
 * 			Parsing functions				*
 * 									*
 ************************************************************************/

/**
 * xmlSchemaGetElem:
 * @schema:  the schemas context
 * @name:  the element name
 * @ns:  the element namespace
 * @level: how deep is the request
 *
 * Lookup a an element in the schemas or the accessible schemas
 *
 * Returns the element definition or NULL if not found.
 */
static xmlSchemaElementPtr
xmlSchemaGetElem(xmlSchemaPtr schema, const xmlChar * name,
                 const xmlChar * namespace, int level)
{
    xmlSchemaElementPtr ret;
    xmlSchemaImportPtr import = NULL;

    if ((name == NULL) || (schema == NULL))
        return (NULL);
    
    
        ret = xmlHashLookup2(schema->elemDecl, name, namespace);
        if ((ret != NULL) &&
	((level == 0) || (ret->flags & XML_SCHEMAS_ELEM_GLOBAL))) {
            return (ret);
    } else
	ret = NULL;
    /*
     * This one was removed, since top level element declarations have
     * the target namespace specified in targetNamespace of the <schema>
     * information element, even if elementFormDefault is "unqualified".
     */
    
    /* else if ((schema->flags & XML_SCHEMAS_QUALIF_ELEM) == 0) {
        if (xmlStrEqual(namespace, schema->targetNamespace))
	    ret = xmlHashLookup2(schema->elemDecl, name, NULL);
	else
	    ret = xmlHashLookup2(schema->elemDecl, name, namespace);
        if ((ret != NULL) &&
	    ((level == 0) || (ret->flags & XML_SCHEMAS_ELEM_TOPLEVEL))) {
            return (ret);
	}
    */
    
    /* if (level > 0) */
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_DEFAULT_NAMESPACE);
    else
    import = xmlHashLookup(schema->schemasImports, namespace);
    if (import != NULL) {
	ret = xmlSchemaGetElem(import->schema, name, namespace, level + 1);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ELEM_GLOBAL)) {
	    return (ret);
	} else
	    ret = NULL;
    }
#ifdef DEBUG
    if (ret == NULL) {
        if (namespace == NULL)
            fprintf(stderr, "Unable to lookup type %s", name);
        else
            fprintf(stderr, "Unable to lookup type %s:%s", name,
                    namespace);
    }
#endif
    return (ret);
}

/**
 * xmlSchemaGetType:
 * @schema:  the schemas context
 * @name:  the type name
 * @ns:  the type namespace
 *
 * Lookup a type in the schemas or the predefined types
 *
 * Returns the group definition or NULL if not found.
 */
static xmlSchemaTypePtr
xmlSchemaGetType(xmlSchemaPtr schema, const xmlChar * name,
                 const xmlChar * namespace)
{
    xmlSchemaTypePtr ret;
    xmlSchemaImportPtr import;

    if (name == NULL)
        return (NULL);
    if (schema != NULL) {
        ret = xmlHashLookup2(schema->typeDecl, name, namespace);
        if ((ret != NULL) && (ret->flags & XML_SCHEMAS_TYPE_GLOBAL))
            return (ret);
    }
    ret = xmlSchemaGetPredefinedType(name, namespace);
    if (ret != NULL)
	return (ret);
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_DEFAULT_NAMESPACE);
    else
    import = xmlHashLookup(schema->schemasImports, namespace);
    if (import != NULL) {
	ret = xmlSchemaGetType(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_TYPE_GLOBAL)) {
	    return (ret);
	} else
	    ret = NULL;
    }
#ifdef DEBUG
    if (ret == NULL) {
        if (namespace == NULL)
            fprintf(stderr, "Unable to lookup type %s", name);
        else
            fprintf(stderr, "Unable to lookup type %s:%s", name,
                    namespace);
    }
#endif
    return (ret);
}

/**
 * xmlSchemaGetAttribute:
 * @schema:  the context of the schema 
 * @name:  the name of the attribute
 * @ns:  the target namespace of the attribute 
 *
 * Lookup a an attribute in the schema or imported schemas
 *
 * Returns the attribute declaration or NULL if not found.
 */
static xmlSchemaAttributePtr
xmlSchemaGetAttribute(xmlSchemaPtr schema, const xmlChar * name,
                 const xmlChar * namespace)
{
    xmlSchemaAttributePtr ret;
    xmlSchemaImportPtr import = NULL;

    if ((name == NULL) || (schema == NULL))
        return (NULL);
    
    
    ret = xmlHashLookup2(schema->attrDecl, name, namespace);
    if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTR_GLOBAL))
	return (ret); 
    else
	ret = NULL;
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_DEFAULT_NAMESPACE);
    else
	import = xmlHashLookup(schema->schemasImports, namespace);	
    if (import != NULL) {
	ret = xmlSchemaGetAttribute(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTR_GLOBAL)) {
	    return (ret);
	} else
	    ret = NULL;
    }
#ifdef DEBUG
    if (ret == NULL) {
        if (namespace == NULL)
            fprintf(stderr, "Unable to lookup attribute %s", name);
        else
            fprintf(stderr, "Unable to lookup attribute %s:%s", name,
                    namespace);
    }
#endif
    return (ret);
}

/**
 * xmlSchemaGetAttributeGroup:
 * @schema:  the context of the schema 
 * @name:  the name of the attribute group
 * @ns:  the target namespace of the attribute group 
 *
 * Lookup a an attribute group in the schema or imported schemas
 *
 * Returns the attribute group definition or NULL if not found.
 */
static xmlSchemaAttributeGroupPtr
xmlSchemaGetAttributeGroup(xmlSchemaPtr schema, const xmlChar * name,
                 const xmlChar * namespace)
{
    xmlSchemaAttributeGroupPtr ret;
    xmlSchemaImportPtr import = NULL;

    if ((name == NULL) || (schema == NULL))
        return (NULL);
    
    
    ret = xmlHashLookup2(schema->attrgrpDecl, name, namespace);
    if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTRGROUP_GLOBAL))
	return (ret);  
    else
	ret = NULL;
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_DEFAULT_NAMESPACE);
    else
	import = xmlHashLookup(schema->schemasImports, namespace);	
    if (import != NULL) {
	ret = xmlSchemaGetAttributeGroup(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTRGROUP_GLOBAL))
	    return (ret);
	else
	    ret = NULL;
    }
#ifdef DEBUG
    if (ret == NULL) {
        if (namespace == NULL)
            fprintf(stderr, "Unable to lookup attribute group %s", name);
        else
            fprintf(stderr, "Unable to lookup attribute group %s:%s", name,
                    namespace);
    }
#endif
    return (ret);
}

/**
 * xmlSchemaGetGroup:
 * @schema:  the context of the schema 
 * @name:  the name of the group
 * @ns:  the target namespace of the group 
 *
 * Lookup a group in the schema or imported schemas
 *
 * Returns the group definition or NULL if not found.
 */
static xmlSchemaTypePtr
xmlSchemaGetGroup(xmlSchemaPtr schema, const xmlChar * name,
                 const xmlChar * namespace)
{
    xmlSchemaTypePtr ret;
    xmlSchemaImportPtr import = NULL;

    if ((name == NULL) || (schema == NULL))
        return (NULL);
    
    
    ret = xmlHashLookup2(schema->groupDecl, name, namespace);
    if ((ret != NULL) && (ret->flags & XML_SCHEMAS_TYPE_GLOBAL))
	return (ret);  
    else
	ret = NULL;
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_DEFAULT_NAMESPACE);
    else
	import = xmlHashLookup(schema->schemasImports, namespace);	
    if (import != NULL) {
	ret = xmlSchemaGetGroup(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_TYPE_GLOBAL))
	    return (ret);
	else
	    ret = NULL;
    }
#ifdef DEBUG
    if (ret == NULL) {
        if (namespace == NULL)
            fprintf(stderr, "Unable to lookup group %s", name);
        else
            fprintf(stderr, "Unable to lookup group %s:%s", name,
                    namespace);
    }
#endif
    return (ret);
}

/************************************************************************
 * 									*
 * 			Parsing functions				*
 * 									*
 ************************************************************************/

#define IS_BLANK_NODE(n)						\
    (((n)->type == XML_TEXT_NODE) && (xmlSchemaIsBlank((n)->content)))

/**
 * xmlSchemaIsBlank:
 * @str:  a string
 *
 * Check if a string is ignorable
 *
 * Returns 1 if the string is NULL or made of blanks chars, 0 otherwise
 */
static int
xmlSchemaIsBlank(xmlChar * str)
{
    if (str == NULL)
        return (1);
    while (*str != 0) {
        if (!(IS_BLANK_CH(*str)))
            return (0);
        str++;
    }
    return (1);
}

/**
 * xmlSchemaAddNotation:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @name:  the item name
 *
 * Add an XML schema Attrribute declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaNotationPtr
xmlSchemaAddNotation(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                     const xmlChar * name)
{
    xmlSchemaNotationPtr ret = NULL;
    int val;

    if ((ctxt == NULL) || (schema == NULL) || (name == NULL))
        return (NULL);

    if (schema->notaDecl == NULL)
        schema->notaDecl = xmlHashCreate(10);
    if (schema->notaDecl == NULL)
        return (NULL);

    ret = (xmlSchemaNotationPtr) xmlMalloc(sizeof(xmlSchemaNotation));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "add annotation", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaNotation));
    ret->name = xmlDictLookup(ctxt->dict, name, -1);
    val = xmlHashAddEntry2(schema->notaDecl, name, schema->targetNamespace,
                           ret);
    if (val != 0) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
		      XML_SCHEMAP_REDEFINED_NOTATION,
                      "Notation %s already defined\n",
                      name, NULL);
        xmlFree(ret);
        return (NULL);
    }
    return (ret);
}


/**
 * xmlSchemaAddAttribute:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @name:  the item name
 * @namespace:  the namespace
 *
 * Add an XML schema Attrribute declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaAttributePtr
xmlSchemaAddAttribute(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                      const xmlChar * name, const xmlChar * namespace)
{
    xmlSchemaAttributePtr ret = NULL;
    int val;

    if ((ctxt == NULL) || (schema == NULL) || (name == NULL))
        return (NULL);

#ifdef DEBUG
    fprintf(stderr, "Adding attribute %s\n", name);
    if (namespace != NULL)
	fprintf(stderr, "  target namespace %s\n", namespace);
#endif

    if (schema->attrDecl == NULL)
        schema->attrDecl = xmlHashCreate(10);
    if (schema->attrDecl == NULL)
        return (NULL);

    ret = (xmlSchemaAttributePtr) xmlMalloc(sizeof(xmlSchemaAttribute));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating attribute", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaAttribute));
    ret->name = xmlDictLookup(ctxt->dict, name, -1);
    ret->targetNamespace = xmlDictLookup(ctxt->dict, namespace, -1);
    val = xmlHashAddEntry3(schema->attrDecl, name,
                           schema->targetNamespace, ctxt->container, ret);
    if (val != 0) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
		      XML_SCHEMAP_REDEFINED_ATTR,
                      "Attribute %s already defined\n",
                      name, NULL);
        xmlFree(ret);
        return (NULL);
    }
    return (ret);
}

/**
 * xmlSchemaAddAttributeGroup:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @name:  the item name
 *
 * Add an XML schema Attrribute Group declaration
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaAttributeGroupPtr
xmlSchemaAddAttributeGroup(xmlSchemaParserCtxtPtr ctxt,
                           xmlSchemaPtr schema, const xmlChar * name)
{
    xmlSchemaAttributeGroupPtr ret = NULL;
    int val;

    if ((ctxt == NULL) || (schema == NULL) || (name == NULL))
        return (NULL);

    if (schema->attrgrpDecl == NULL)
        schema->attrgrpDecl = xmlHashCreate(10);
    if (schema->attrgrpDecl == NULL)
        return (NULL);

    ret =
        (xmlSchemaAttributeGroupPtr)
        xmlMalloc(sizeof(xmlSchemaAttributeGroup));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating attribute group", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaAttributeGroup));
    ret->name = xmlDictLookup(ctxt->dict, name, -1);
    val = xmlHashAddEntry3(schema->attrgrpDecl, name,
                           schema->targetNamespace, ctxt->container, ret);
    if (val != 0) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
		      XML_SCHEMAP_REDEFINED_ATTRGROUP,
                      "Attribute group %s already defined\n",
                      name, NULL);
        xmlFree(ret);
        return (NULL);
    }
    return (ret);
}

/**
 * xmlSchemaAddElement:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @name:  the type name
 * @namespace:  the type namespace
 *
 * Add an XML schema Element declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaElementPtr
xmlSchemaAddElement(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                    const xmlChar * name, const xmlChar * namespace)
{
    xmlSchemaElementPtr ret = NULL;
    int val;

    if ((ctxt == NULL) || (schema == NULL) || (name == NULL))
        return (NULL);

#ifdef DEBUG
    fprintf(stderr, "Adding element %s\n", name);
    if (namespace != NULL)
	fprintf(stderr, "  target namespace %s\n", namespace);
#endif

    if (schema->elemDecl == NULL)
        schema->elemDecl = xmlHashCreate(10);
    if (schema->elemDecl == NULL)
        return (NULL);

    ret = (xmlSchemaElementPtr) xmlMalloc(sizeof(xmlSchemaElement));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating element", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaElement));
    ret->name = xmlDictLookup(ctxt->dict, name, -1);
    ret->targetNamespace = xmlDictLookup(ctxt->dict, namespace, -1);
    val = xmlHashAddEntry3(schema->elemDecl, name,
                           namespace, ctxt->container, ret);
    if (val != 0) {
        char buf[100];

        snprintf(buf, 99, "privatieelem %d", ctxt->counter++ + 1);
        val = xmlHashAddEntry3(schema->elemDecl, name, (xmlChar *) buf,
                               namespace, ret);
        if (val != 0) {
	    xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
			  XML_SCHEMAP_REDEFINED_ELEMENT,
			  "Element %s already defined\n",
			  name, NULL);
            xmlFree(ret);
            return (NULL);
        }
    }
    return (ret);
}

/**
 * xmlSchemaAddType:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @name:  the item name
 * @namespace:  the namespace
 *
 * Add an XML schema Simple Type definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaAddType(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                 const xmlChar * name, const xmlChar * namespace)
{
    xmlSchemaTypePtr ret = NULL;
    int val;

    if ((ctxt == NULL) || (schema == NULL) || (name == NULL))
        return (NULL);

#ifdef DEBUG
    fprintf(stderr, "Adding type %s\n", name);
    if (namespace != NULL)
	fprintf(stderr, "  target namespace %s\n", namespace);
#endif

    if (schema->typeDecl == NULL)
        schema->typeDecl = xmlHashCreate(10);
    if (schema->typeDecl == NULL)
        return (NULL);

    ret = (xmlSchemaTypePtr) xmlMalloc(sizeof(xmlSchemaType));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating type", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaType));
    ret->name = xmlDictLookup(ctxt->dict, name, -1);
    ret->redef = NULL;
    val = xmlHashAddEntry2(schema->typeDecl, name, namespace, ret);
    if (val != 0) {
        if (ctxt->includes == 0) {
	    xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
			  XML_SCHEMAP_REDEFINED_TYPE,
			  "Type %s already defined\n",
			  name, NULL);
	    xmlFree(ret);
	    return (NULL);
	} else {
	    xmlSchemaTypePtr prev;

	    prev = xmlHashLookup2(schema->typeDecl, name, namespace);
	    if (prev == NULL) {
		xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
			      XML_ERR_INTERNAL_ERROR,
			      "Internal error on type %s definition\n",
			      name, NULL);
		xmlFree(ret);
		return (NULL);
	    }
	    ret->redef = prev->redef;
	    prev->redef = ret;
	}
    }
    ret->minOccurs = 1;
    ret->maxOccurs = 1;
    ret->attributeUses = NULL;
    ret->attributeWildcard = NULL;

    return (ret);
}

/**
 * xmlSchemaAddGroup:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @name:  the group name
 *
 * Add an XML schema Group definition
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaAddGroup(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                  const xmlChar * name)
{
    xmlSchemaTypePtr ret = NULL;
    int val;

    if ((ctxt == NULL) || (schema == NULL) || (name == NULL))
        return (NULL);

    if (schema->groupDecl == NULL)
        schema->groupDecl = xmlHashCreate(10);
    if (schema->groupDecl == NULL)
        return (NULL);

    ret = (xmlSchemaTypePtr) xmlMalloc(sizeof(xmlSchemaType));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "adding group", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaType));
    ret->name = xmlDictLookup(ctxt->dict, name, -1);
    val =
        xmlHashAddEntry2(schema->groupDecl, name, schema->targetNamespace,
                         ret);
    if (val != 0) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
		      XML_SCHEMAP_REDEFINED_GROUP,
                      "Group %s already defined\n",
                      name, NULL);
        xmlFree(ret);
        return (NULL);
    }
    ret->minOccurs = 1;
    ret->maxOccurs = 1;

    return (ret);
}

/**
 * xmlSchemaNewWildcardNs:
 * @ctxt:  a schema validation context
 *
 * Creates a new wildcard namespace constraint.
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaWildcardNsPtr
xmlSchemaNewWildcardNsConstraint(xmlSchemaParserCtxtPtr ctxt)
{
    xmlSchemaWildcardNsPtr ret;

    ret = (xmlSchemaWildcardNsPtr) 
	xmlMalloc(sizeof(xmlSchemaWildcardNs));
    if (ret == NULL) {
	xmlSchemaPErrMemory(ctxt, "creating wildcard namespace constraint", NULL);
	return (NULL);    
    }
    ret->value = NULL;
    ret->next = NULL;
    return (ret);
}

/**
 * xmlSchemaAddWildcard:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @name:  the group name
 *
 * Add an XML schema Group definition
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaWildcardPtr
xmlSchemaAddWildcard(xmlSchemaParserCtxtPtr ctxt)
{
    xmlSchemaWildcardPtr ret = NULL;

    if (ctxt == NULL)
        return (NULL);

    ret = (xmlSchemaWildcardPtr) xmlMalloc(sizeof(xmlSchemaWildcard));
    if (ret == NULL) {
        xmlSchemaPErrMemory(ctxt, "adding wildcard", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaWildcard));
    ret->minOccurs = 1;
    ret->maxOccurs = 1;

    return (ret);
}

/************************************************************************
 * 									*
 *		Utilities for parsing					*
 * 									*
 ************************************************************************/

/**
 * xmlGetQNameProp:
 * @ctxt:  a schema validation context
 * @node:  a subtree containing XML Schema informations
 * @name:  the attribute name
 * @namespace:  the result namespace if any
 *
 * Extract a QName Attribute value
 *
 * Returns the NCName or NULL if not found, and also update @namespace
 *    with the namespace URI
 */
static const xmlChar *
xmlGetQNameProp(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node,
                const char *name, const xmlChar ** namespace)
{
    const xmlChar *val;
    xmlNsPtr ns;
    const xmlChar *ret, *prefix;
    int len;

    *namespace = NULL;
    val = xmlSchemaGetProp(ctxt, node, name);
    if (val == NULL)
        return (NULL);

    if (!strchr((char *) val, ':')) {
	ns = xmlSearchNs(node->doc, node, 0);
	if (ns) {
	    *namespace = xmlDictLookup(ctxt->dict, ns->href, -1);
	    return (val);
	}
    }
    ret = xmlSplitQName3(val, &len);
    if (ret == NULL) {
        return (val);
    }
    ret = xmlDictLookup(ctxt->dict, ret, -1);
    prefix = xmlDictLookup(ctxt->dict, val, len);

    ns = xmlSearchNs(node->doc, node, prefix);
    if (ns == NULL) {
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_PREFIX_UNDEFINED,
                      "Attribute %s: the QName prefix %s is undefined\n",
                      (const xmlChar *) name, prefix);
    } else {
        *namespace = xmlDictLookup(ctxt->dict, ns->href, -1);
    }
    return (ret);
}

/**
 * xmlGetMaxOccurs:
 * @ctxt:  a schema validation context
 * @node:  a subtree containing XML Schema informations
 *
 * Get the maxOccurs property
 *
 * Returns the default if not found, or the value
 */
static int
xmlGetMaxOccurs(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node)
{
    const xmlChar *val, *cur;
    int ret = 0;

    val = xmlSchemaGetProp(ctxt, node, "maxOccurs");
    if (val == NULL)
        return (1);

    if (xmlStrEqual(val, (const xmlChar *) "unbounded")) {
        return (UNBOUNDED);  /* encoding it with -1 might be another option */
    }

    cur = val;
    while (IS_BLANK_CH(*cur))
        cur++;
    while ((*cur >= '0') && (*cur <= '9')) {
        ret = ret * 10 + (*cur - '0');
        cur++;
    }
    while (IS_BLANK_CH(*cur))
        cur++;
    if (*cur != 0) {
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_INVALID_MAXOCCURS,
                      "invalid value for maxOccurs: %s\n", val, NULL);
        return (1);
    }
    return (ret);
}

/**
 * xmlGetMinOccurs:
 * @ctxt:  a schema validation context
 * @node:  a subtree containing XML Schema informations
 *
 * Get the minOccurs property
 *
 * Returns the default if not found, or the value
 */
static int
xmlGetMinOccurs(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node)
{
    const xmlChar *val, *cur;
    int ret = 0;

    val = xmlSchemaGetProp(ctxt, node, "minOccurs");
    if (val == NULL)
        return (1);

    cur = val;
    while (IS_BLANK_CH(*cur))
        cur++;
    while ((*cur >= '0') && (*cur <= '9')) {
        ret = ret * 10 + (*cur - '0');
        cur++;
    }
    while (IS_BLANK_CH(*cur))
        cur++;
    if (*cur != 0) {
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_INVALID_MINOCCURS,
                      "invalid value for minOccurs: %s\n", val, NULL);
        return (1);
    }
    return (ret);
}

/**
 * xmlGetBooleanProp:
 * @ctxt:  a schema validation context
 * @node:  a subtree containing XML Schema informations
 * @name:  the attribute name
 * @def:  the default value
 *
 * Get is a bolean property is set
 *
 * Returns the default if not found, 0 if found to be false,
 *         1 if found to be true
 */
static int
xmlGetBooleanProp(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node,
                  const char *name, int def)
{
    const xmlChar *val;

    val = xmlSchemaGetProp(ctxt, node, name);
    if (val == NULL)
        return (def);

    if (xmlStrEqual(val, BAD_CAST "true"))
        def = 1;
    else if (xmlStrEqual(val, BAD_CAST "false"))
        def = 0;
    else {
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_INVALID_BOOLEAN,
                      "Attribute %s: the value %s is not boolean\n",
                      (const xmlChar *) name, val);
    }
    return (def);
}

/************************************************************************
 * 									*
 *		Shema extraction from an Infoset			*
 * 									*
 ************************************************************************/
static xmlSchemaTypePtr xmlSchemaParseSimpleType(xmlSchemaParserCtxtPtr
                                                 ctxt, xmlSchemaPtr schema,
                                                 xmlNodePtr node,
						 int topLevel);
static xmlSchemaTypePtr xmlSchemaParseComplexType(xmlSchemaParserCtxtPtr
                                                  ctxt,
                                                  xmlSchemaPtr schema,
                                                  xmlNodePtr node, 
						  int topLevel);
static xmlSchemaTypePtr xmlSchemaParseRestriction(xmlSchemaParserCtxtPtr
                                                  ctxt,
                                                  xmlSchemaPtr schema,
                                                  xmlNodePtr node,
                                                  int simple);
static xmlSchemaTypePtr xmlSchemaParseSequence(xmlSchemaParserCtxtPtr ctxt,
                                               xmlSchemaPtr schema,
                                               xmlNodePtr node);
static xmlSchemaTypePtr xmlSchemaParseAll(xmlSchemaParserCtxtPtr ctxt,
                                          xmlSchemaPtr schema,
                                          xmlNodePtr node);
static xmlSchemaAttributePtr xmlSchemaParseAttribute(xmlSchemaParserCtxtPtr
                                                     ctxt,
                                                     xmlSchemaPtr schema,
                                                     xmlNodePtr node,
						     int topLevel);
static xmlSchemaAttributeGroupPtr
xmlSchemaParseAttributeGroup(xmlSchemaParserCtxtPtr ctxt,
                             xmlSchemaPtr schema, xmlNodePtr node,
			     int topLevel);
static xmlSchemaTypePtr xmlSchemaParseChoice(xmlSchemaParserCtxtPtr ctxt,
                                             xmlSchemaPtr schema,
                                             xmlNodePtr node);
static xmlSchemaTypePtr xmlSchemaParseList(xmlSchemaParserCtxtPtr ctxt,
                                           xmlSchemaPtr schema,
                                           xmlNodePtr node);
static xmlSchemaWildcardPtr
xmlSchemaParseAnyAttribute(xmlSchemaParserCtxtPtr ctxt,
                           xmlSchemaPtr schema, xmlNodePtr node);

/**
 * xmlSchemaParseAttrDecls:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 * @type:  the hosting type
 *
 * parse a XML schema attrDecls declaration corresponding to
 * <!ENTITY % attrDecls  
 *       '((%attribute;| %attributeGroup;)*,(%anyAttribute;)?)'>
 */
static xmlNodePtr
xmlSchemaParseAttrDecls(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                        xmlNodePtr child, xmlSchemaTypePtr type)
{
    xmlSchemaAttributePtr lastattr, attr;

    lastattr = NULL;
    while ((IS_SCHEMA(child, "attribute")) ||
           (IS_SCHEMA(child, "attributeGroup"))) {
        attr = NULL;
        if (IS_SCHEMA(child, "attribute")) {
            attr = xmlSchemaParseAttribute(ctxt, schema, child, 0);
        } else if (IS_SCHEMA(child, "attributeGroup")) {
            attr = (xmlSchemaAttributePtr)
                xmlSchemaParseAttributeGroup(ctxt, schema, child, 0);
        }
        if (attr != NULL) {
            if (lastattr == NULL) {
		if (type->type == XML_SCHEMA_TYPE_ATTRIBUTEGROUP)
		    ((xmlSchemaAttributeGroupPtr) type)->attributes = attr;
		else
                type->attributes = attr;
                lastattr = attr;
            } else {
                lastattr->next = attr;
                lastattr = attr;
            }
        }
        child = child->next;
    }
    if (IS_SCHEMA(child, "anyAttribute")) {
	xmlSchemaWildcardPtr wildcard;

        wildcard = xmlSchemaParseAnyAttribute(ctxt, schema, child);
        if (wildcard != NULL) {
	    if (type->type == XML_SCHEMA_TYPE_ATTRIBUTEGROUP)
		((xmlSchemaAttributeGroupPtr) type)->attributeWildcard = wildcard;
	    else
		type->attributeWildcard = wildcard;
        }
        child = child->next;
    }
    return (child);
}

/**
 * xmlSchemaParseAnnotation:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Attrribute declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaAnnotPtr
xmlSchemaParseAnnotation(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                         xmlNodePtr node)
{
    xmlSchemaAnnotPtr ret;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    ret = xmlSchemaNewAnnot(ctxt, node);

    return (ret);
}

/**
 * xmlSchemaParseFacet:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Facet declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the new type structure or NULL in case of error
 */
static xmlSchemaFacetPtr
xmlSchemaParseFacet(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                    xmlNodePtr node)
{
    xmlSchemaFacetPtr facet;
    xmlNodePtr child = NULL;
    const xmlChar *value;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    facet = xmlSchemaNewFacet();
    if (facet == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating facet", node);
        return (NULL);
    }
    facet->node = node;
    value = xmlSchemaGetProp(ctxt, node, "value");
    if (value == NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_FACET_NO_VALUE,
                       "Facet %s has no value\n", node->name, NULL);
        xmlSchemaFreeFacet(facet);
        return (NULL);
    }
    if (IS_SCHEMA(node, "minInclusive")) {
        facet->type = XML_SCHEMA_FACET_MININCLUSIVE;
    } else if (IS_SCHEMA(node, "minExclusive")) {
        facet->type = XML_SCHEMA_FACET_MINEXCLUSIVE;
    } else if (IS_SCHEMA(node, "maxInclusive")) {
        facet->type = XML_SCHEMA_FACET_MAXINCLUSIVE;
    } else if (IS_SCHEMA(node, "maxExclusive")) {
        facet->type = XML_SCHEMA_FACET_MAXEXCLUSIVE;
    } else if (IS_SCHEMA(node, "totalDigits")) {
        facet->type = XML_SCHEMA_FACET_TOTALDIGITS;
    } else if (IS_SCHEMA(node, "fractionDigits")) {
        facet->type = XML_SCHEMA_FACET_FRACTIONDIGITS;
    } else if (IS_SCHEMA(node, "pattern")) {
        facet->type = XML_SCHEMA_FACET_PATTERN;
    } else if (IS_SCHEMA(node, "enumeration")) {
        facet->type = XML_SCHEMA_FACET_ENUMERATION;
    } else if (IS_SCHEMA(node, "whiteSpace")) {
        facet->type = XML_SCHEMA_FACET_WHITESPACE;
    } else if (IS_SCHEMA(node, "length")) {
        facet->type = XML_SCHEMA_FACET_LENGTH;
    } else if (IS_SCHEMA(node, "maxLength")) {
        facet->type = XML_SCHEMA_FACET_MAXLENGTH;
    } else if (IS_SCHEMA(node, "minLength")) {
        facet->type = XML_SCHEMA_FACET_MINLENGTH;
    } else {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_FACET_TYPE,
                       "Unknown facet type %s\n", node->name, NULL);
        xmlSchemaFreeFacet(facet);
        return (NULL);
    }
    facet->id = xmlSchemaGetProp(ctxt, node, "id");
    facet->value = value;
    child = node->children;

    if (IS_SCHEMA(child, "annotation")) {
        facet->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_FACET_CHILD,
                       "Facet %s has unexpected child content\n",
                       node->name, NULL);
    }
    return (facet);
}

/**
 * xmlSchemaParseAny:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Any declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the new type structure or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaParseAny(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                  xmlNodePtr node)
{
    xmlSchemaTypePtr type;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    snprintf((char *) name, 30, "any %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_ANY;
    child = node->children;
    type->minOccurs = xmlGetMinOccurs(ctxt, node);
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node);

    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD,
                       "Sequence %s has unexpected content\n", type->name,
                       NULL);
    }

    return (type);
}

/**
 * xmlSchemaParseNotation:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Notation declaration
 *
 * Returns the new structure or NULL in case of error
 */
static xmlSchemaNotationPtr
xmlSchemaParseNotation(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                       xmlNodePtr node)
{
    const xmlChar *name;
    xmlSchemaNotationPtr ret;
    xmlNodePtr child = NULL;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_NOTATION_NO_NAME,
                       "Notation has no name\n", NULL, NULL);
        return (NULL);
    }
    ret = xmlSchemaAddNotation(ctxt, schema, name);
    if (ret == NULL) {
        return (NULL);
    }
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_NOTATION_CHILD,
                       "notation %s has unexpected content\n", name, NULL);
    }

    return (ret);
}

/**
 * xmlSchemaParseAnyAttribute:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema AnyAttrribute declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns an attribute def structure or NULL
 */
static xmlSchemaWildcardPtr
xmlSchemaParseAnyAttribute(xmlSchemaParserCtxtPtr ctxt,
                           xmlSchemaPtr schema, xmlNodePtr node)
{
    const xmlChar *processContents, *nsConstraint, *end, *cur, *dictMember;
    xmlChar *member;
    xmlSchemaWildcardPtr ret;
    xmlSchemaWildcardNsPtr tmp, lastNs = NULL;
    xmlNodePtr child = NULL;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    ret = xmlSchemaAddWildcard(ctxt);
    if (ret == NULL) {
        return (NULL);
    }
    ret->type = XML_SCHEMA_TYPE_ANY_ATTRIBUTE;
    ret->id = xmlSchemaGetProp(ctxt, node, "id");
    processContents = xmlSchemaGetProp(ctxt, node, "processContents");
    if ((processContents == NULL)
        || (xmlStrEqual(processContents, (const xmlChar *) "strict"))) {
        ret->processContents = XML_SCHEMAS_ANYATTR_STRICT;
    } else if (xmlStrEqual(processContents, (const xmlChar *) "skip")) {
        ret->processContents = XML_SCHEMAS_ANYATTR_SKIP;
    } else if (xmlStrEqual(processContents, (const xmlChar *) "lax")) {
        ret->processContents = XML_SCHEMAS_ANYATTR_LAX;
    } else {
        xmlSchemaPErr(ctxt, node, 
                       XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD,
                       "anyAttribute has unexpected content "
		       "for processContents: %s\n",
                       processContents, NULL);
        ret->processContents = XML_SCHEMAS_ANYATTR_STRICT;
    }
    /*
     * Build the namespace constraints.
     */
    nsConstraint = xmlSchemaGetProp(ctxt, node, "namespace");
    if ((nsConstraint == NULL) || (xmlStrEqual(nsConstraint, BAD_CAST "##any")))
	ret->any = 1;
    else if (xmlStrEqual(nsConstraint, BAD_CAST "##other")) {
	ret->negNsSet = xmlSchemaNewWildcardNsConstraint(ctxt);
	if (ret->negNsSet == NULL) {	    
	    xmlSchemaFreeWildcard(ret);
	    return (NULL);
	}
	ret->negNsSet->value = schema->targetNamespace; 
    } else {    
	cur = nsConstraint;
	do {
	    while (IS_BLANK_CH(*cur))
		cur++;
	    end = cur;
	    while ((*end != 0) && (!(IS_BLANK_CH(*end))))
		end++;
	    if (end == cur)
		break;
	    member = xmlStrndup(cur, end - cur);    	    
	    if ((xmlStrEqual(member, BAD_CAST "##other")) ||
		    (xmlStrEqual(member, BAD_CAST "##any"))) {
		xmlSchemaPErr(ctxt, ret->node, XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER,
		    "The namespace constraint of an anyAttribute "
		    "is a set and must not contain \"%s\"\n",
		    member, NULL);			    		    
	    } else {		
		/*
		* TODO: Validate the value (anyURI).
		*/		
		if (xmlStrEqual(member, BAD_CAST "##targetNamespace")) {
		    dictMember = schema->targetNamespace;
		} else if (xmlStrEqual(member, BAD_CAST "##local")) {
		    dictMember = NULL;
		} else
		    dictMember = xmlDictLookup(ctxt->dict, member, -1);
		/*
		* Avoid dublicate namespaces.
		*/
		tmp = ret->nsSet;
		while (tmp != NULL) {
		    if (dictMember == tmp->value)
			break;
		    tmp = tmp->next;
		}
		if (tmp == NULL) {
		    tmp = xmlSchemaNewWildcardNsConstraint(ctxt);
		    if (tmp == NULL) {
			xmlFree(member);
			xmlSchemaFreeWildcard(ret);
			return (NULL);
		    }
		    tmp->value = dictMember;
		    tmp->next = NULL;
		    if (ret->nsSet == NULL) 
			ret->nsSet = tmp;
		    else
			lastNs->next = tmp;
		    lastNs = tmp;
		}

	    }	
	    xmlFree(member);
	    cur = end;
	} while (*cur != 0);    
    }

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD,
                       "anyAttribute has unexpected content\n",
                       NULL, NULL);
    }

    return (ret);
}


/**
 * xmlSchemaParseAttribute:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Attrribute declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the attribute declaration.
 */
static xmlSchemaAttributePtr
xmlSchemaParseAttribute(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                        xmlNodePtr node, int topLevel)
{
    const xmlChar *name, *refNs = NULL, *ref = NULL, *attrVal;
    xmlSchemaAttributePtr ret;
    xmlNodePtr child = NULL;
    char buf[100];
    int hasRefType = 0;

    /*
     * Note that the w3c spec assumes the schema to be validated with schema
     * for schemas beforehand.
     *
     * 3.2.3 Constraints on XML Representations of Attribute Declarations
     *
     * TODO: Complete implementation of: 
     * 3.2.6 Schema Component Constraint: Attribute Declaration Properties
     *       Correct 
     */

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    
    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        ref = xmlGetQNameProp(ctxt, node, "ref", &refNs);
	/* 3.2.3 : 3.1
	 * One of ref or name must be present, but not both 
	 */
        if (ref == NULL) {	    
            xmlSchemaPErr(ctxt, node, 
			  XML_SCHEMAP_ATTR_NONAME_NOREF,
			  "Attribute declaration has no \"name\" or \"ref\"\n",
			  NULL, NULL);
	    return (NULL);
        }
	hasRefType = 1;
        snprintf(buf, 99, "anonattr %d", ctxt->counter++ + 1);
        name = (const xmlChar *) buf;
	ret = xmlSchemaAddAttribute(ctxt, schema, name, NULL);
	if (!topLevel) {
	    /* 3.2.3 : 3.2
	     * If ref is present, then all of <simpleType>,
	     * form and type must be absent. 
	     */
	    if (xmlSchemaGetProp(ctxt, node, "form") != NULL) {		
		xmlSchemaPErr(ctxt, node, 
		              XML_SCHEMAP_INVALID_ATTR_COMBINATION,
			      "Attribute declaration %s has \"ref\", thus "
			      "\"form\" must be absent\n", name, NULL);
	    }
	    if (xmlSchemaGetProp(ctxt, node, "type") != NULL) {
		xmlSchemaPErr(ctxt, node, 
		              XML_SCHEMAP_INVALID_ATTR_COMBINATION,
			      "Attribute declaration %s has \"ref\", thus "
			      "\"type\" must be absent\n", name, NULL);
	    }
	}
    } else {
        const xmlChar *ns = NULL;
	/* 3.2.3 : 3.1
	 * One of ref or name must be present, but not both 
	 */
	if ((!topLevel) && (xmlSchemaGetProp(ctxt, node, "ref") != NULL)) {	    
	    xmlSchemaPErr(ctxt, node, 
                          XML_SCHEMAP_INVALID_ATTR_COMBINATION,
                          "Attribute declaration \"%s\" has both, \"name\" and "
			  "\"ref\"\n", name, NULL);
	}

        /* local = xmlSchemaGetNamespace(ctxt, schema, node, name, &ns); */
	/* Evaluate the target namespace */
	if (schema->targetNamespace != NULL) {
	    if (topLevel) {
		ns = schema->targetNamespace;
	    } else if (xmlSchemaGetProp(ctxt, node, "form") != NULL) {
		if (xmlStrEqual( xmlSchemaGetProp(ctxt, node, "form"),
				 BAD_CAST "qualified")) {
		    ns = schema->targetNamespace;
		}
	    } else if (schema->flags & XML_SCHEMAS_QUALIF_ATTR) {
		ns = schema->targetNamespace;		
	    }
	}
	ret = xmlSchemaAddAttribute(ctxt, schema, name, ns);
	if (ret == NULL)
	    return (NULL);
	/* 3.2.6 Schema Component Constraint: xmlns Not Allowed */
	if (xmlStrEqual(name, BAD_CAST "xmlns")) {
	    xmlSchemaPErr(ctxt, node, 
                      XML_SCHEMAP_INVALID_ATTR_NAME,
                      "The name of an attribute declaration must not match "
		      "\"xmlns\".\n", NULL, NULL);
	}	
	
	/* 3.2.6 Schema Component Constraint: xsi: Not Allowed */	
	if (xmlStrEqual(ret->targetNamespace, xmlSchemaInstanceNs)) {
	    xmlSchemaPErr(ctxt, node, 
                          XML_SCHEMAP_INVALID_ATTR_NAME,
	                  "The target namespace of an attribute declaration, "
			  "must not match \"http://www.w3.org/2001/"
			  "XMLSchema-instance\"", NULL, NULL);
	}	
    }
    if (ret == NULL) {
        return (NULL);
    }
    ret->type = XML_SCHEMA_TYPE_ATTRIBUTE;
    if (topLevel) 
        ret->flags |= XML_SCHEMAS_ATTR_GLOBAL;
    
    /* Handle the "use" attribute. */
    attrVal = xmlSchemaGetProp(ctxt, node, "use");
    if (attrVal != NULL) {
	if (xmlStrEqual(attrVal, BAD_CAST "optional"))
	    ret->occurs = XML_SCHEMAS_ATTR_USE_OPTIONAL;
	else if (xmlStrEqual(attrVal, BAD_CAST "prohibited"))
	    ret->occurs = XML_SCHEMAS_ATTR_USE_PROHIBITED;
	else if (xmlStrEqual(attrVal, BAD_CAST "required"))
	    ret->occurs = XML_SCHEMAS_ATTR_USE_REQUIRED;
	else
	    xmlSchemaPErr(ctxt, node,
			  XML_SCHEMAP_INVALID_ATTR_USE,
			  "Attribute declaration %s has an invalid "
			  "value for \"use\"\n", name, NULL);
    } else
	ret->occurs = XML_SCHEMAS_ATTR_USE_OPTIONAL;

    
    if (xmlSchemaGetProp(ctxt, node, "default") != NULL) {
	/* 3.2.3 : 1
	 * default and fixed must not both be present. 
	 */
	if (xmlSchemaGetProp(ctxt, node, "fixed") != NULL) {
	    xmlSchemaPErr(ctxt, node, 
                          XML_SCHEMAP_INVALID_ATTR_COMBINATION,
                          "Attribute declaration has both, \"default\" "
			  "and \"fixed\"\n", NULL, NULL);
	}
	/* 3.2.3 : 2
	 * If default and use are both present, use must have
	 * the actual value optional.
	 */
	if (ret->occurs != XML_SCHEMAS_ATTR_USE_OPTIONAL) {
	    xmlSchemaPErr(ctxt, node, 
                          XML_SCHEMAP_INVALID_ATTR_COMBINATION,
                          "Attribute declaration has \"default\" but "
			  "\"use\" is not \"optional\"\n", NULL, NULL);
	}	
    }    

    ret->ref = ref;
    ret->refNs = refNs;
    /* 
     * The setting of XML_SCHEMAS_ATTR_NSDEFAULT is not needed anymore,
     * since the target namespace was already evaluated and took
     * attributeFormDefault into account.
     */
    /*
    if ((ret->targetNamespace != NULL) &&
        ((schema->flags & XML_SCHEMAS_QUALIF_ATTR) == 0) &&
	(xmlStrEqual(ret->targetNamespace, schema->targetNamespace)))
	ret->flags |= XML_SCHEMAS_ATTR_NSDEFAULT;
    */
    ret->typeName = xmlGetQNameProp(ctxt, node, "type", &(ret->typeNs));
    if (ret->typeName != NULL)
	hasRefType = 1;
    ret->node = node;
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (IS_SCHEMA(child, "simpleType")) {
	if (hasRefType) {
	    /* 3.2.3 : 4
	     * type and <simpleType> must not both be present. 
	     *
	     * TODO: XML_SCHEMAP_INVALID_ATTR_COMBINATION seems not to be
	     * a proper error type here. 
	     */
	    xmlSchemaPErr2(ctxt, node, child, 
	                   XML_SCHEMAP_INVALID_ATTR_COMBINATION,
                           "Attribute declaration %s has both (\"ref\" or "
			   "\"type\") and <simpleType>\n", name, NULL);
	} else
	    ret->subtypes = xmlSchemaParseSimpleType(ctxt, schema, child, 0);
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_ATTR_CHILD,
                       "attribute %s has unexpected content\n", name,
                       NULL);
    }

    return (ret);
}

/**
 * xmlSchemaParseAttributeGroup:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Attribute Group declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the attribute group or NULL in case of error.
 */
static xmlSchemaAttributeGroupPtr
xmlSchemaParseAttributeGroup(xmlSchemaParserCtxtPtr ctxt,
                             xmlSchemaPtr schema, xmlNodePtr node,
			     int topLevel)
{
    const xmlChar *name, *refNs = NULL, *ref = NULL;
    xmlSchemaAttributeGroupPtr ret;
    xmlNodePtr child = NULL;
    const xmlChar *oldcontainer;
    char buf[100];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    oldcontainer = ctxt->container;
    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        ref = xmlGetQNameProp(ctxt, node, "ref", &refNs);
        if (ref == NULL) {
            xmlSchemaPErr2(ctxt, node, child,
                           XML_SCHEMAP_ATTRGRP_NONAME_NOREF,
                           "AttributeGroup has no name nor ref\n", NULL,
                           NULL);
            return (NULL);
        }
        snprintf(buf, 99, "anonattrgroup %d", ctxt->counter++ + 1);
        name = (const xmlChar *) buf;
        if (name == NULL) {
	    xmlSchemaPErrMemory(ctxt, "creating attribute group", node);
            return (NULL);
        }
    }
    ret = xmlSchemaAddAttributeGroup(ctxt, schema, name);
    if (ret == NULL) {
        return (NULL);
    }
    ret->ref = ref;
    ret->refNs = refNs;
    ret->type = XML_SCHEMA_TYPE_ATTRIBUTEGROUP;
    if (topLevel) 
        ret->flags |= XML_SCHEMAS_ATTRGROUP_GLOBAL;
    ret->node = node;
    child = node->children;
    ctxt->container = name;
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    child = xmlSchemaParseAttrDecls(ctxt, schema, child, (xmlSchemaTypePtr) ret); 
    /* Seems that this can be removed. */
    /*
    while ((IS_SCHEMA(child, "attribute")) ||
           (IS_SCHEMA(child, "attributeGroup"))) {
        attr = NULL;
        if (IS_SCHEMA(child, "attribute")) {
            attr = xmlSchemaParseAttribute(ctxt, schema, child, 0);
        } else if (IS_SCHEMA(child, "attributeGroup")) {
            attr = (xmlSchemaAttributePtr)
                xmlSchemaParseAttributeGroup(ctxt, schema, child, 0);
        }
        if (attr != NULL) {
            if (last == NULL) {
                ret->attributes = attr;
                last = attr;
            } else {
                last->next = attr;
                last = attr;
            }
        }
        child = child->next;
    }
    if (IS_SCHEMA(child, "anyAttribute")) {
        TODO
	child = child->next;
    }
    */
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD,
                       "attribute group %s has unexpected content\n", name,
                       NULL);
    }
    ctxt->container = oldcontainer;
    return (ret);
}

/**
 * xmlSchemaParseElement:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Element declaration
 * *WARNING* this interface is highly subject to change
 *
 * Returns the parsed element declaration.
 */
static xmlSchemaElementPtr
xmlSchemaParseElement(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                      xmlNodePtr node, int topLevel)
{
    const xmlChar *name, *fixed;
    const xmlChar *refNs = NULL, *ref = NULL;
    xmlSchemaElementPtr ret;
    xmlNodePtr child = NULL;
    const xmlChar *oldcontainer;
    char buf[100];
    xmlAttrPtr attr;

    /* 3.3.3 Constraints on XML Representations of Element Declarations */
    /* TODO: Complete implementation of 3.3.6 */

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    oldcontainer = ctxt->container;
    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        ref = xmlGetQNameProp(ctxt, node, "ref", &refNs);
	/* 3.3.3 : 2.1
	 * One of ref or name must be present, but not both 
	 */
        if (ref == NULL) {
            xmlSchemaPErr(ctxt, node, 
                           XML_SCHEMAP_ELEM_NONAME_NOREF,
                           "Element declaration has no name nor ref\n", NULL, NULL);
            return (NULL);
        }	
        
        snprintf(buf, 99, "anonelem %d", ctxt->counter++ + 1);
        name = (const xmlChar *) buf;
	ret = xmlSchemaAddElement(ctxt, schema, name, NULL);
    } else {
	const xmlChar *ns = NULL;

	/* Evaluate the target namespace */
	if (schema->targetNamespace != NULL) {
	    if (topLevel) {
		ns = schema->targetNamespace;
	    } else if (xmlSchemaGetProp(ctxt, node, "form") != NULL) {
		if (xmlStrEqual( xmlSchemaGetProp(ctxt, node, "form"),
				 BAD_CAST "qualified")) {
		    ns = schema->targetNamespace;
		}
	    } else if (schema->flags & XML_SCHEMAS_QUALIF_ATTR) {
		ns = schema->targetNamespace;
	    }
	}
	/*local = xmlSchemaGetNamespace(ctxt, schema, node, name, &ns); */
	ret = xmlSchemaAddElement(ctxt, schema, name, ns);
	/* 3.3.3 : 2.1
	 * One of ref or name must be present, but not both 
	 */
	if ((!topLevel) && (xmlSchemaGetProp(ctxt, node, "ref") != NULL)) {	    
	    xmlSchemaPErr(ctxt, node, 
                          XML_SCHEMAP_INVALID_ATTR_COMBINATION,
                          "Element declaration has both, \"name\" and "
			  "\"ref\"\n", NULL, NULL);
	}
    }
    if (ret != NULL)
	ret->node = node;
    if (ret == NULL) {
        return (NULL);
    }
    ret->type = XML_SCHEMA_TYPE_ELEMENT;
    ret->ref = ref;
    ret->refNs = refNs;
    if (ref != NULL)
        ret->flags |= XML_SCHEMAS_ELEM_REF;

    /* 3.3.3 : 2.2 */     
    if ((!topLevel) && (ref != NULL)) {
	attr = node->properties;
	while (attr != NULL) {
	    if ((attr->ns == NULL) &&
		(!xmlStrEqual(attr->name, BAD_CAST "ref")) && 
		(!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "maxOccurs")) && 
		(!xmlStrEqual(attr->name, BAD_CAST "minOccurs"))) {

		xmlSchemaPErr(ctxt, node, XML_SCHEMAP_INVALID_ATTR_COMBINATION,
                       "Element declaration %s: only minOccurs, maxOccurs "
		       "and id are allowed in addition to ref\n",
		       ret->name, NULL);
	    }
	    attr = attr->next;
	}
    }

    if (topLevel) {
        ret->flags |= XML_SCHEMAS_ELEM_GLOBAL;
        ret->flags |= XML_SCHEMAS_ELEM_TOPLEVEL;
    }
    if (xmlGetBooleanProp(ctxt, node, "nillable", 0))
        ret->flags |= XML_SCHEMAS_ELEM_NILLABLE;
    if (xmlGetBooleanProp(ctxt, node, "abstract", 0))
        ret->flags |= XML_SCHEMAS_ELEM_ABSTRACT;
    ctxt->container = name;

    ret->id = xmlSchemaGetProp(ctxt, node, "id");
    ret->namedType =
        xmlGetQNameProp(ctxt, node, "type", &(ret->namedTypeNs)); 
    ret->substGroup =
        xmlGetQNameProp(ctxt, node, "substitutionGroup",
                        &(ret->substGroupNs));
    if ((ret->substGroup != NULL) && (!topLevel)) {
	/* 3.3.6 : 3 */
	/*
	 * TODO: This seems to be redundant, since the schema for schemas
	 * already prohibits the use of the "substitutionGroup" attribute
	 * in local element declarations.
	 */
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_INVALID_ATTR_COMBINATION,
	              "Element declaration %s: substitutionGroup is allowed "
		      "on top-level declarations only\n", ret->name, NULL);
	
    }
    fixed = xmlSchemaGetProp(ctxt, node, "fixed");
    ret->minOccurs = xmlGetMinOccurs(ctxt, node);
    ret->maxOccurs = xmlGetMaxOccurs(ctxt, node);

    ret->value = xmlSchemaGetProp(ctxt, node, "default");
    if ((ret->value != NULL) && (fixed != NULL)) {
	/* 3.3.3 : 1 
	 * default and fixed must not both be present. 
	 */
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_ELEM_DEFAULT_FIXED,
                       "Element %s has both default and fixed\n",
		       ret->name, NULL);
    } else if (fixed != NULL) {
        ret->flags |= XML_SCHEMAS_ELEM_FIXED;
        ret->value = fixed;
    }

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    
    if (ref != NULL) {
	/* 3.3.3 (2.2) */ 
	while (child != NULL) {
	    if ((IS_SCHEMA(child, "complexType")) ||
		(IS_SCHEMA(child, "simpleType")) ||
		(IS_SCHEMA(child, "unique")) ||
	        (IS_SCHEMA(child, "key")) || 
		(IS_SCHEMA(child, "keyref"))) {

		xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_REF_AND_CONTENT,
		               "Element declaration %s: only annotation is "
			       "allowed as content in addition to ref\n",
			       ret->name, NULL);
	    } else {
		xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_ELEM_CHILD,
		           "element %s has unexpected content\n", name, NULL);
	    }
	    child = child->next;
	}
    } else {
	if (IS_SCHEMA(child, "complexType")) {
	    /* 3.3.3 : 3 
	     * type and either <simpleType> or <complexType> are mutually
	     * exclusive 
	     */
	    if (ret->namedType != NULL) {
		xmlSchemaPErr2(ctxt, node, child,
			       XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION,
		               "Element declaration %s has both \"type\" "
			       "and a local complex type\n",
			       ret->name, NULL);
	    } else
		ret->subtypes = xmlSchemaParseComplexType(ctxt, schema, child, 0);
	    child = child->next;
	} else if (IS_SCHEMA(child, "simpleType")) {
	    /* 3.3.3 : 3 
	     * type and either <simpleType> or <complexType> are
	     * mutually exclusive 
	     */
	    if (ret->namedType != NULL) {
		xmlSchemaPErr2(ctxt, node, child,
			       XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION,
		               "Element declaration %s has both \"type\" "
			       "and a local simple type\n",
			       ret->name, NULL);
	    } else
		ret->subtypes = xmlSchemaParseSimpleType(ctxt, schema, child, 0);
	    child = child->next;
	}
    
	while ((IS_SCHEMA(child, "unique")) ||
	       (IS_SCHEMA(child, "key")) || (IS_SCHEMA(child, "keyref"))) {
	    TODO child = child->next;
	}
	if (child != NULL) {
	    xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_ELEM_CHILD,
		           "element %s has unexpected content\n", name, NULL);
	}
    }

    ctxt->container = oldcontainer;
    return (ret);
}

/**
 * xmlSchemaParseUnion:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Union definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseUnion(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                    xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype, last = NULL;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    snprintf((char *) name, 30, "union %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_UNION;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->ref = xmlSchemaGetProp(ctxt, node, "memberTypes");

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    while (IS_SCHEMA(child, "simpleType")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseSimpleType(ctxt, schema, child, 0);
        if (subtype != NULL) {
            if (last == NULL) {
                type->subtypes = subtype;
                last = subtype;
            } else {
                last->next = subtype;
                last = subtype;
            }
            last->next = NULL;
        }
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_UNION_CHILD,
                       "Union %s has unexpected content\n", type->name,
                       NULL);
    }
    return (type);
}

/**
 * xmlSchemaParseList:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema List definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseList(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                   xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    snprintf((char *) name, 30, "list %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_LIST;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->ref = xmlGetQNameProp(ctxt, node, "ref", &(type->refNs));

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    
    subtype = NULL;
    if (IS_SCHEMA(child, "simpleType")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseSimpleType(ctxt, schema, child, 0);
        child = child->next;
        type->subtypes = subtype;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_LIST_CHILD,
                       "List %s has unexpected content\n", type->name,
                       NULL);
    }
    return (type);
}

/**
 * xmlSchemaParseSimpleType:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Simple Type definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseSimpleType(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                         xmlNodePtr node, int topLevel)
{
    xmlSchemaTypePtr type, subtype;
    xmlNodePtr child = NULL;
    const xmlChar *name;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        char buf[100];

        snprintf(buf, 99, "simpleType %d", ctxt->counter++ + 1);
	type = xmlSchemaAddType(ctxt, schema, (const xmlChar *)buf, NULL);
    } else {	
        /* local = xmlSchemaGetNamespace(ctxt, schema, node, name, &ns); */
	type = xmlSchemaAddType(ctxt, schema, name, schema->targetNamespace);
    }
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_SIMPLE;
    if (topLevel) 
        type->flags |= XML_SCHEMAS_TYPE_GLOBAL;
    type->id = xmlSchemaGetProp(ctxt, node, "id");

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;
    if (IS_SCHEMA(child, "restriction")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseRestriction(ctxt, schema, child, 1);
        child = child->next;
    } else if (IS_SCHEMA(child, "list")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseList(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "union")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseUnion(ctxt, schema, child);
        child = child->next;
    }
    type->subtypes = subtype;
    if (subtype == NULL) {
	xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD,
                       "SimpleType %s does not define a variety\n",
                       type->name, NULL);
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD,
                       "SimpleType %s has unexpected content\n",
                       type->name, NULL);
    }

    return (type);
}


/**
 * xmlSchemaParseGroup:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Group definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseGroup(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                    xmlNodePtr node, int topLevel)
{
    xmlSchemaTypePtr type, subtype;
    xmlNodePtr child = NULL;
    const xmlChar *name;
    const xmlChar *ref = NULL, *refNs = NULL;
    char buf[100];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        ref = xmlGetQNameProp(ctxt, node, "ref", &refNs);
        if (ref == NULL) {
            xmlSchemaPErr2(ctxt, node, child,
                           XML_SCHEMAP_GROUP_NONAME_NOREF,
                           "Group has no name nor ref\n", NULL, NULL);
            return (NULL);
        }
	if (refNs == NULL)
	    refNs = schema->targetNamespace;
        snprintf(buf, 99, "anongroup %d", ctxt->counter++ + 1);
        name = (const xmlChar *) buf;
    }
    type = xmlSchemaAddGroup(ctxt, schema, name);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_GROUP;
    if (topLevel) 
        type->flags |= XML_SCHEMAS_TYPE_GLOBAL;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->ref = ref;
    type->refNs = refNs;
    type->minOccurs = xmlGetMinOccurs(ctxt, node);
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node);

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;
    if (IS_SCHEMA(child, "all")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseAll(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "choice")) {
        subtype = xmlSchemaParseChoice(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "sequence")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseSequence(ctxt, schema, child);
        child = child->next;
    }
    if (subtype != NULL)
        type->subtypes = subtype;
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_GROUP_CHILD,
                       "Group %s has unexpected content\n", type->name,
                       NULL);
    }

    return (type);
}

/**
 * xmlSchemaParseAll:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema All definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseAll(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                  xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype, last = NULL;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    snprintf((char *) name, 30, "all%d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_ALL;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->minOccurs = xmlGetMinOccurs(ctxt, node);
    if (type->minOccurs > 1)
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_INVALID_MINOCCURS,
	    "invalid value for minOccurs (must be 0 or 1)\n", NULL, NULL);
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node);
    if (type->maxOccurs > 1)
        xmlSchemaPErr(ctxt, node, XML_SCHEMAP_INVALID_MAXOCCURS,
	    "invalid value for maxOccurs (must be 0 or 1)\n", NULL, NULL);

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    while (IS_SCHEMA(child, "element")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseElement(ctxt, schema, child, 0);
        if (subtype != NULL) {
	    if (subtype->minOccurs > 1)
                xmlSchemaPErr(ctxt, child, XML_SCHEMAP_INVALID_MINOCCURS,
	             "invalid value for minOccurs (must be 0 or 1)\n",
		     NULL, NULL);
	    if (subtype->maxOccurs > 1)
	        xmlSchemaPErr(ctxt, child, XML_SCHEMAP_INVALID_MAXOCCURS,
	             "invalid value for maxOccurs (must be 0 or 1)\n",
		     NULL, NULL);
            if (last == NULL) {
                type->subtypes = subtype;
                last = subtype;
            } else {
                last->next = subtype;
                last = subtype;
            }
            last->next = NULL;
        }
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_ALL_CHILD,
                       "All %s has unexpected content\n", type->name,
                       NULL);
    }

    return (type);
}

/**
 * xmlSchemaImportSchema
 * 
 * @ctxt:  a schema validation context
 * @schemaLocation:  an URI defining where to find the imported schema
 *
 * import a XML schema
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error and 1 in case of success.
 */
static xmlSchemaImportPtr
xmlSchemaImportSchema(xmlSchemaParserCtxtPtr ctxt,
                      const xmlChar *schemaLocation)
{
    xmlSchemaImportPtr import;
    xmlSchemaParserCtxtPtr newctxt;

    newctxt = (xmlSchemaParserCtxtPtr) xmlMalloc(sizeof(xmlSchemaParserCtxt));
    if (newctxt == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating schema parser context",
                            NULL);
        return (NULL);
    }
    memset(newctxt, 0, sizeof(xmlSchemaParserCtxt));
    /* Keep the same dictionnary for parsing, really */
    xmlDictReference(ctxt->dict);
    newctxt->dict = ctxt->dict;
    newctxt->includes = 0;
    newctxt->URL = xmlDictLookup(newctxt->dict, schemaLocation, -1);

    xmlSchemaSetParserErrors(newctxt, ctxt->error, ctxt->warning,
	                     ctxt->userData);

    import = (xmlSchemaImport*) xmlMalloc(sizeof(xmlSchemaImport));
    if (import == NULL) {
        xmlSchemaPErrMemory(NULL, "allocating imported schema",
                            NULL);
	xmlSchemaFreeParserCtxt(newctxt);
        return (NULL);
    }

    memset(import, 0, sizeof(xmlSchemaImport));
    import->schemaLocation = xmlDictLookup(ctxt->dict, schemaLocation, -1);
    import->schema = xmlSchemaParse(newctxt);

    if (import->schema == NULL) {
        /* FIXME use another error enum here ? */
        xmlSchemaPErr(ctxt, NULL, XML_SCHEMAS_ERR_INTERNAL,
	              "failed to import schema at location %s\n",
		      schemaLocation, NULL);

	xmlSchemaFreeParserCtxt(newctxt);
	if (import->schemaLocation != NULL)
	    xmlFree((xmlChar *)import->schemaLocation);
	xmlFree(import);
	return NULL;
    }

    xmlSchemaFreeParserCtxt(newctxt);
    return import;
}


/**
 * xmlSchemaParseImport:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Import definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static int
xmlSchemaParseImport(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                     xmlNodePtr node)
{
    xmlNodePtr child = NULL;
    xmlSchemaImportPtr import = NULL;
    const xmlChar *namespace;
    const xmlChar *schemaLocation;
    const xmlChar *previous;
    xmlURIPtr check;


    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (-1);

    namespace = xmlSchemaGetProp(ctxt, node, "namespace");
    if (namespace != NULL) {
        check = xmlParseURI((const char *) namespace);
        if (check == NULL) {
            xmlSchemaPErr2(ctxt, node, child,
                           XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI,
                           "Import namespace attribute is not an URI: %s\n",
                           namespace, NULL);
            return (-1);
        } else {
            xmlFreeURI(check);
        }
    }
    schemaLocation = xmlSchemaGetProp(ctxt, node, "schemaLocation");
    if (schemaLocation != NULL) {
        xmlChar *base = NULL;
        xmlChar *URI = NULL;
        check = xmlParseURI((const char *) schemaLocation);
        if (check == NULL) {
            xmlSchemaPErr2(ctxt, node, child,
                           XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI,
                           "Import schemaLocation attribute is not an URI: %s\n",
                           schemaLocation, NULL);
            return (-1);
        } else {
            xmlFreeURI(check);
        }
	base = xmlNodeGetBase(node->doc, node);
	if (base == NULL) {
	    URI = xmlBuildURI(schemaLocation, node->doc->URL);
	} else {
	    URI = xmlBuildURI(schemaLocation, base);
	    xmlFree(base);
	}
	if (URI != NULL) {
	    schemaLocation = xmlDictLookup(ctxt->dict, URI, -1);
	    xmlFree(URI);
	}
    }
    if (schema->schemasImports == NULL) {
        schema->schemasImports = xmlHashCreate(10);
        if (schema->schemasImports == NULL) {
            xmlSchemaPErr2(ctxt, node, child,
                           XML_SCHEMAP_FAILED_BUILD_IMPORT,
                           "Internal: failed to build import table\n",
                           NULL, NULL);
            return (-1);
        }
    }
    if (namespace == NULL) {
        import = xmlHashLookup(schema->schemasImports,
	                               XML_SCHEMAS_DEFAULT_NAMESPACE);
	if (import != NULL)
            previous = import->schemaLocation;
	else
	    previous = NULL;

        if (schemaLocation != NULL) {
            if (previous != NULL) {
                if (!xmlStrEqual(schemaLocation, previous)) {
                    xmlSchemaPErr2(ctxt, node, child,
                                   XML_SCHEMAP_IMPORT_REDEFINE_NSNAME,
                                   "Redefining import for default namespace "
				   "with a different URI: %s\n",
                                   schemaLocation, NULL);
                }
            } else {
	        import = xmlSchemaImportSchema(ctxt, schemaLocation);
		if (import == NULL) {
		    return (-1);
		}
                xmlHashAddEntry(schema->schemasImports,
                                XML_SCHEMAS_DEFAULT_NAMESPACE,
                                import);
            }
        }
    } else {
        import = xmlHashLookup(schema->schemasImports, namespace);
	if (import != NULL)
	    previous = import->schemaLocation;
	else
	    previous = NULL;

        if (schemaLocation != NULL) {
            if (previous != NULL) {
                if (!xmlStrEqual(schemaLocation, previous)) {
                    xmlSchemaPErr2(ctxt, node, child,
                                   XML_SCHEMAP_IMPORT_REDEFINE_NSNAME,
                                   "Redefining import for namespace %s with "
				   "a different URI: %s\n",
                                   namespace, schemaLocation);
                }
            } else {
	        import = xmlSchemaImportSchema(ctxt, schemaLocation);
		if (import == NULL) {
		    return (-1);
		}
		if (!xmlStrEqual(import->schema->targetNamespace, namespace)) {
		    if (namespace == NULL) {
			if (import->schema->targetNamespace != NULL) {
			   xmlSchemaPErr(ctxt, node, XML_SCHRMAP_SRC_IMPORT_3_2,
			    "There is no namespace attribute on the <import> "
			    "element information item, so the imported document "
			    "must have no targetNamespace attribute.\n", 
			    NULL, NULL); 
			}
		    } else {
			if (import->schema->targetNamespace != NULL) {
			    xmlSchemaPErr(ctxt, node, XML_SCHRMAP_SRC_IMPORT_3_1,
				"The namespace attribute \"%s\" of an <import> "
				"element information item must be identical to the "
				"targetNamespace attribute \"%s\" of the "
				"imported document.\n", 
				namespace, import->schema->targetNamespace);
			} else {
			    xmlSchemaPErr(ctxt, node, XML_SCHRMAP_SRC_IMPORT_3_1,
				"The namespace attribute on the <import> "
				"element information item, requires the imported "
				"document to have a targetNamespace attribute "
				"with the value \"%s\".\n", 
				namespace, NULL);
			}
		    }
		    xmlSchemaFreeImport(import);
		    return (-1);
		}

                xmlHashAddEntry(schema->schemasImports,
                                namespace, import);
		
            }
        }
    }

    child = node->children;
    while (IS_SCHEMA(child, "annotation")) {
        /*
         * the annotations here are simply discarded ...
         */
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_IMPORT_CHILD,
                       "Import has unexpected content\n", NULL, NULL);
        return (-1);
    }
    return (1);
}

/**
 * xmlSchemaCleanupDoc:
 * @ctxt:  a schema validation context
 * @node:  the root of the document.
 *
 * removes unwanted nodes in a schemas document tree
 */
static void
xmlSchemaCleanupDoc(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr root)
{
    xmlNodePtr delete, cur;

    if ((ctxt == NULL) || (root == NULL)) return;

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
        if (cur->type == XML_TEXT_NODE) {
            if (IS_BLANK_NODE(cur)) {
                if (xmlNodeGetSpacePreserve(cur) != 1) {
                    delete = cur;
                }
            }
        } else if ((cur->type != XML_ELEMENT_NODE) &&
                   (cur->type != XML_CDATA_SECTION_NODE)) {
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
 * xmlSchemaParseSchemaTopLevel:
 * @ctxt:  a schema validation context
 * @schema:  the schemas
 * @nodes:  the list of top level nodes
 *
 * Returns the internal XML Schema structure built from the resource or
 *         NULL in case of error
 */
static void
xmlSchemaParseSchemaTopLevel(xmlSchemaParserCtxtPtr ctxt,
                             xmlSchemaPtr schema, xmlNodePtr nodes)
{
    xmlNodePtr child;
    xmlSchemaAnnotPtr annot;

    if ((ctxt == NULL) || (schema == NULL) || (nodes == NULL))
        return;

    child = nodes;
    while ((IS_SCHEMA(child, "include")) ||
	   (IS_SCHEMA(child, "import")) ||
	   (IS_SCHEMA(child, "redefine")) ||
	   (IS_SCHEMA(child, "annotation"))) {
	if (IS_SCHEMA(child, "annotation")) {
	    annot = xmlSchemaParseAnnotation(ctxt, schema, child);
	    if (schema->annot == NULL)
		schema->annot = annot;
	    else
		xmlSchemaFreeAnnot(annot);
	} else if (IS_SCHEMA(child, "import")) {
	    xmlSchemaParseImport(ctxt, schema, child);
	} else if (IS_SCHEMA(child, "include")) {
	    ctxt->includes++;
	    xmlSchemaParseInclude(ctxt, schema, child);
	    ctxt->includes--;
	} else if (IS_SCHEMA(child, "redefine")) {
	    TODO
	}
	child = child->next;
    }
    while (child != NULL) {
	if (IS_SCHEMA(child, "complexType")) {
	    xmlSchemaParseComplexType(ctxt, schema, child, 1);
	    child = child->next;
	} else if (IS_SCHEMA(child, "simpleType")) {
	    xmlSchemaParseSimpleType(ctxt, schema, child, 1);
	    child = child->next;
	} else if (IS_SCHEMA(child, "element")) {
	    xmlSchemaParseElement(ctxt, schema, child, 1);
	    child = child->next;
	} else if (IS_SCHEMA(child, "attribute")) {
	    xmlSchemaParseAttribute(ctxt, schema, child, 1);
	    child = child->next;
	} else if (IS_SCHEMA(child, "attributeGroup")) {
	    xmlSchemaParseAttributeGroup(ctxt, schema, child, 1);
	    child = child->next;
	} else if (IS_SCHEMA(child, "group")) {
	    xmlSchemaParseGroup(ctxt, schema, child, 1);
	    child = child->next;
	} else if (IS_SCHEMA(child, "notation")) {
	    xmlSchemaParseNotation(ctxt, schema, child);
	    child = child->next;
	} else {
	    xmlSchemaPErr2(ctxt, NULL, child,
			   XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD,
			   "Schemas: unexpected element %s here \n",
			   child->name, NULL);
	    child = child->next;
	}
	while (IS_SCHEMA(child, "annotation")) {
	    annot = xmlSchemaParseAnnotation(ctxt, schema, child);
	    if (schema->annot == NULL)
		schema->annot = annot;
	    else
		xmlSchemaFreeAnnot(annot);
	    child = child->next;
	}
    }
}

/**
 * xmlSchemaParseInclude:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Include definition
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static int
xmlSchemaParseInclude(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                      xmlNodePtr node)
{
    xmlNodePtr child = NULL;
    const xmlChar *schemaLocation;
    xmlURIPtr check;
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSchemaIncludePtr include;


    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (-1);

    /*
     * Preliminary step, extract the URI-Reference for the include and
     * make an URI from the base.
     */
    schemaLocation = xmlSchemaGetProp(ctxt, node, "schemaLocation");
    if (schemaLocation != NULL) {
        xmlChar *base = NULL;
        xmlChar *URI = NULL;
        check = xmlParseURI((const char *) schemaLocation);
        if (check == NULL) {
            xmlSchemaPErr2(ctxt, node, child,
                           XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI,
		       "Include schemaLocation attribute is not an URI: %s\n",
                           schemaLocation, NULL);
            return (-1);
        } else {
            xmlFreeURI(check);
        }
	base = xmlNodeGetBase(node->doc, node);
	if (base == NULL) {
	    URI = xmlBuildURI(schemaLocation, node->doc->URL);
	} else {
	    URI = xmlBuildURI(schemaLocation, base);
	    xmlFree(base);
	}
	if (URI != NULL) {
	    schemaLocation = xmlDictLookup(ctxt->dict, URI, -1);
	    xmlFree(URI);
	}
    } else {
	xmlSchemaPErr2(ctxt, node, child,
		       XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI,
		   "Include schemaLocation attribute missing\n",
		       NULL, NULL);
	return (-1);
    }

    child = node->children;
    while (IS_SCHEMA(child, "annotation")) {
        /*
         * the annotations here are simply discarded ...
         */
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD,
                       "Include has unexpected content\n", NULL, NULL);
        return (-1);
    }

    /*
     * First step is to parse the input document into an DOM/Infoset
     */
    doc = xmlReadFile((const char *) schemaLocation, NULL,
                      SCHEMAS_PARSE_OPTIONS);
    if (doc == NULL) {
	xmlSchemaPErr(ctxt, NULL,
		      XML_SCHEMAP_FAILED_LOAD,
		      "xmlSchemaParse: could not load %s\n",
		      ctxt->URL, NULL);
	return(-1);
    }

    /*
     * Then extract the root of the schema
     */
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) doc,
		      XML_SCHEMAP_NOROOT,
		      "schemas %s has no root", schemaLocation, NULL);
	xmlFreeDoc(doc);
        return (-1);
    }

    /*
     * Remove all the blank text nodes
     */
    xmlSchemaCleanupDoc(ctxt, root);

    /*
     * Check the schemas top level element
     */
    if (!IS_SCHEMA(root, "schema")) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) doc,
		      XML_SCHEMAP_NOT_SCHEMA,
		      "File %s is not a schemas", schemaLocation, NULL);
	xmlFreeDoc(doc);
        return (-1);
    }

    /*
     * register the include
     */
    include = (xmlSchemaIncludePtr) xmlMalloc(sizeof(xmlSchemaInclude));
    if (include == NULL) {
        xmlSchemaPErrMemory(ctxt, "allocating included schema", NULL);
	xmlFreeDoc(doc);
        return (-1);
    }

    memset(include, 0, sizeof(xmlSchemaInclude));
    include->schemaLocation = xmlDictLookup(ctxt->dict, schemaLocation, -1);
    include->doc = doc;
    include->next = schema->includes;
    schema->includes = include;


    /*
     * parse the declarations in the included file like if they
     * were in the original file.
     */
    xmlSchemaParseSchemaTopLevel(ctxt, schema, root->children);

    return (1);
}

/**
 * xmlSchemaParseChoice:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Choice definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseChoice(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                     xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype, last = NULL;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    snprintf((char *) name, 30, "choice %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_CHOICE;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->minOccurs = xmlGetMinOccurs(ctxt, node);
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node);

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    while ((IS_SCHEMA(child, "element")) ||
           (IS_SCHEMA(child, "group")) ||
           (IS_SCHEMA(child, "any")) ||
           (IS_SCHEMA(child, "choice")) ||
           (IS_SCHEMA(child, "sequence"))) {
        subtype = NULL;
        if (IS_SCHEMA(child, "element")) {
            subtype = (xmlSchemaTypePtr)
                xmlSchemaParseElement(ctxt, schema, child, 0);
        } else if (IS_SCHEMA(child, "group")) {
            subtype = xmlSchemaParseGroup(ctxt, schema, child, 0);
        } else if (IS_SCHEMA(child, "any")) {
            subtype = xmlSchemaParseAny(ctxt, schema, child);
        } else if (IS_SCHEMA(child, "sequence")) {
            subtype = xmlSchemaParseSequence(ctxt, schema, child);
        } else if (IS_SCHEMA(child, "choice")) {
            subtype = xmlSchemaParseChoice(ctxt, schema, child);
        }
        if (subtype != NULL) {
            if (last == NULL) {
                type->subtypes = subtype;
                last = subtype;
            } else {
                last->next = subtype;
                last = subtype;
            }
            last->next = NULL;
        }
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_UNKNOWN_CHOICE_CHILD,
                       "Choice %s has unexpected content\n", type->name,
                       NULL);
    }

    return (type);
}

/**
 * xmlSchemaParseSequence:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Sequence definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns -1 in case of error, 0 if the declaration is improper and
 *         1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseSequence(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                       xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype, last = NULL;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    snprintf((char *) name, 30, "sequence %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_SEQUENCE;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->minOccurs = xmlGetMinOccurs(ctxt, node);
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node);

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    while ((IS_SCHEMA(child, "element")) ||
           (IS_SCHEMA(child, "group")) ||
           (IS_SCHEMA(child, "any")) ||
           (IS_SCHEMA(child, "choice")) ||
           (IS_SCHEMA(child, "sequence"))) {
        subtype = NULL;
        if (IS_SCHEMA(child, "element")) {
            subtype = (xmlSchemaTypePtr)
                xmlSchemaParseElement(ctxt, schema, child, 0);
        } else if (IS_SCHEMA(child, "group")) {
            subtype = xmlSchemaParseGroup(ctxt, schema, child, 0);
        } else if (IS_SCHEMA(child, "any")) {
            subtype = xmlSchemaParseAny(ctxt, schema, child);
        } else if (IS_SCHEMA(child, "choice")) {
            subtype = xmlSchemaParseChoice(ctxt, schema, child);
        } else if (IS_SCHEMA(child, "sequence")) {
            subtype = xmlSchemaParseSequence(ctxt, schema, child);
        }
        if (subtype != NULL) {
            if (last == NULL) {
                type->subtypes = subtype;
                last = subtype;
            } else {
                last->next = subtype;
                last = subtype;
            }
            last->next = NULL;
        }
        child = child->next;
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD,
                       "Sequence %s has unexpected content\n", type->name,
                       NULL);
    }

    return (type);
}

/**
 * xmlSchemaParseRestriction:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 * @simple:  is that part of a simple type.
 *
 * parse a XML schema Restriction definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns the type definition or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaParseRestriction(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                          xmlNodePtr node, int simple)
{
    xmlSchemaTypePtr type, subtype;
    xmlSchemaFacetPtr facet, lastfacet = NULL;
    xmlNodePtr child = NULL;
    xmlChar name[30];
    const xmlChar *oldcontainer;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    oldcontainer = ctxt->container;

    snprintf((char *) name, 30, "restriction %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_RESTRICTION;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->base = xmlGetQNameProp(ctxt, node, "base", &(type->baseNs));
    if ((!simple) && (type->base == NULL)) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_RESTRICTION_NONAME_NOREF,
                       "Restriction %s has no base\n", type->name, NULL);
    }
    ctxt->container = name;

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;

    if (IS_SCHEMA(child, "all")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseAll(ctxt, schema, child);
        child = child->next;
        type->subtypes = subtype;
    } else if (IS_SCHEMA(child, "choice")) {
        subtype = xmlSchemaParseChoice(ctxt, schema, child);
        child = child->next;
        type->subtypes = subtype;
    } else if (IS_SCHEMA(child, "sequence")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseSequence(ctxt, schema, child);
        child = child->next;
        type->subtypes = subtype;
    } else if (IS_SCHEMA(child, "group")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseGroup(ctxt, schema, child, 0);
        child = child->next;
        type->subtypes = subtype;
    } else {
        if (IS_SCHEMA(child, "simpleType")) {
            subtype = (xmlSchemaTypePtr)
                xmlSchemaParseSimpleType(ctxt, schema, child, 0);
            child = child->next;
            type->baseType = subtype;
        }
        /*
         * Facets
         */
        while ((IS_SCHEMA(child, "minInclusive")) ||
               (IS_SCHEMA(child, "minExclusive")) ||
               (IS_SCHEMA(child, "maxInclusive")) ||
               (IS_SCHEMA(child, "maxExclusive")) ||
               (IS_SCHEMA(child, "totalDigits")) ||
               (IS_SCHEMA(child, "fractionDigits")) ||
               (IS_SCHEMA(child, "pattern")) ||
               (IS_SCHEMA(child, "enumeration")) ||
               (IS_SCHEMA(child, "whiteSpace")) ||
               (IS_SCHEMA(child, "length")) ||
               (IS_SCHEMA(child, "maxLength")) ||
               (IS_SCHEMA(child, "minLength"))) {
            facet = xmlSchemaParseFacet(ctxt, schema, child);
            if (facet != NULL) {
                if (lastfacet == NULL) {
                    type->facets = facet;
                    lastfacet = facet;
                } else {
                    lastfacet->next = facet;
                    lastfacet = facet;
                }
                lastfacet->next = NULL;
            }
            child = child->next;
        }
    }
    /* TODO: a restriction of simpleType does not contain any 
     * attribute declarations.
     */
    child = xmlSchemaParseAttrDecls(ctxt, schema, child, type);
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD,
                       "Restriction %s has unexpected content\n",
                       type->name, NULL);
    }
    ctxt->container = oldcontainer;
    return (type);
}

/**
 * xmlSchemaParseExtension:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Extension definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns the type definition or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaParseExtension(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                        xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype;
    xmlNodePtr child = NULL;
    xmlChar name[30];
    const xmlChar *oldcontainer;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    oldcontainer = ctxt->container;

    snprintf((char *) name, 30, "extension %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_EXTENSION;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    ctxt->container = name;

    type->base = xmlGetQNameProp(ctxt, node, "base", &(type->baseNs));
    if (type->base == NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_EXTENSION_NO_BASE,
                       "Extension %s has no base\n", type->name, NULL);
    }
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;

    if (IS_SCHEMA(child, "all")) {
        subtype = xmlSchemaParseAll(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "choice")) {
        subtype = xmlSchemaParseChoice(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "sequence")) {
        subtype = xmlSchemaParseSequence(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "group")) {
        subtype = xmlSchemaParseGroup(ctxt, schema, child, 0);
        child = child->next;
    }
    if (subtype != NULL)
        type->subtypes = subtype;
    child = xmlSchemaParseAttrDecls(ctxt, schema, child, type);
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD,
                       "Extension %s has unexpected content\n", type->name,
                       NULL);
    }
    ctxt->container = oldcontainer;
    return (type);
}

/**
 * xmlSchemaParseSimpleContent:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema SimpleContent definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns the type definition or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaParseSimpleContent(xmlSchemaParserCtxtPtr ctxt,
                            xmlSchemaPtr schema, xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    snprintf((char *) name, 30, "simpleContent %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_SIMPLE_CONTENT;
    type->id = xmlSchemaGetProp(ctxt, node, "id");

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;
    if (IS_SCHEMA(child, "restriction")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseRestriction(ctxt, schema, child, 0);
        child = child->next;
    } else if (IS_SCHEMA(child, "extension")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseExtension(ctxt, schema, child);
        child = child->next;
    }
    type->subtypes = subtype;
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD,
                       "SimpleContent %s has unexpected content\n",
                       type->name, NULL);
    }
    return (type);
}

/**
 * xmlSchemaParseComplexContent:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema ComplexContent definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns the type definition or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaParseComplexContent(xmlSchemaParserCtxtPtr ctxt,
                             xmlSchemaPtr schema, xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    snprintf((char *) name, 30, "complexContent %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_COMPLEX_CONTENT;
    type->id = xmlSchemaGetProp(ctxt, node, "id");

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;
    if (IS_SCHEMA(child, "restriction")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseRestriction(ctxt, schema, child, 0);
        child = child->next;
    } else if (IS_SCHEMA(child, "extension")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseExtension(ctxt, schema, child);
        child = child->next;
    }
    type->subtypes = subtype;
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD,
                       "ComplexContent %s has unexpected content\n",
                       type->name, NULL);
    }
    return (type);
}

/**
 * xmlSchemaParseComplexType:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Complex Type definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns the type definition or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaParseComplexType(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                          xmlNodePtr node, int topLevel)
{
    xmlSchemaTypePtr type, subtype;
    xmlNodePtr child = NULL;
    const xmlChar *name;
    const xmlChar *oldcontainer;    
    char buf[100];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    oldcontainer = ctxt->container;
    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        snprintf(buf, 99, "complexType %d", ctxt->counter++ + 1);
	name = (const xmlChar *)buf;
	type = xmlSchemaAddType(ctxt, schema, name, NULL);
    } else {

        /* local = xmlSchemaGetNamespace(ctxt, schema, node, name, &ns); */
	type = xmlSchemaAddType(ctxt, schema, name, schema->targetNamespace);
    }
    if (type == NULL) {
        return (NULL);
    }
    if (xmlGetBooleanProp(ctxt, node, "mixed", 0)) 
	type->flags |= XML_SCHEMAS_TYPE_MIXED;    

    type->node = node;
    type->type = XML_SCHEMA_TYPE_COMPLEX;
    if (topLevel) 
        type->flags |= XML_SCHEMAS_TYPE_GLOBAL;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    ctxt->container = name;

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (IS_SCHEMA(child, "simpleContent")) {
	/* 3.4.3 : 2.2  
	 * Specifying mixed='true' when the <simpleContent>
	 * alternative is chosen has no effect
	 */
	if (type->flags & XML_SCHEMAS_TYPE_MIXED)
	    type->flags ^= XML_SCHEMAS_TYPE_MIXED;
        type->subtypes = xmlSchemaParseSimpleContent(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "complexContent")) {
        type->subtypes = xmlSchemaParseComplexContent(ctxt, schema, child);
        child = child->next;
    } else {
        subtype = NULL;

        if (IS_SCHEMA(child, "all")) {
            subtype = xmlSchemaParseAll(ctxt, schema, child);
            child = child->next;
        } else if (IS_SCHEMA(child, "choice")) {
            subtype = xmlSchemaParseChoice(ctxt, schema, child);
            child = child->next;
        } else if (IS_SCHEMA(child, "sequence")) {
            subtype = xmlSchemaParseSequence(ctxt, schema, child);
            child = child->next;
        } else if (IS_SCHEMA(child, "group")) {
            subtype = xmlSchemaParseGroup(ctxt, schema, child, 0);
            child = child->next;
        }
        if (subtype != NULL)
            type->subtypes = subtype;
        child = xmlSchemaParseAttrDecls(ctxt, schema, child, type);
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
                       XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD,
                       "ComplexType %s has unexpected content\n",
                       type->name, NULL);
    }
    if (type->attributeWildcard != NULL)
	type->flags |= XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD;
    ctxt->container = oldcontainer;
    return (type);
}

/**
 * xmlSchemaParseSchema:
 * @ctxt:  a schema validation context
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema definition from a node set
 * *WARNING* this interface is highly subject to change
 *
 * Returns the internal XML Schema structure built from the resource or
 *         NULL in case of error
 */
static xmlSchemaPtr
xmlSchemaParseSchema(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node)
{
    xmlSchemaPtr schema = NULL;
    xmlNodePtr child = NULL;
    const xmlChar *val;
    int nberrors;

    if ((ctxt == NULL) || (node == NULL))
        return (NULL);
    
    nberrors = ctxt->nberrors;
    ctxt->nberrors = 0;
    if (IS_SCHEMA(node, "schema")) {
        schema = xmlSchemaNewSchema(ctxt);
        if (schema == NULL)
            return (NULL);
	val = xmlSchemaGetProp(ctxt, node, "targetNamespace");
	if (val != NULL) {
	    schema->targetNamespace = xmlDictLookup(ctxt->dict, val, -1);
	} else {
	    schema->targetNamespace = NULL;
	}
        schema->id = xmlSchemaGetProp(ctxt, node, "id");
        schema->version = xmlSchemaGetProp(ctxt, node, "version");
        val = xmlSchemaGetProp(ctxt, node, "elementFormDefault");
        if (val != NULL) {
            if (xmlStrEqual(val, BAD_CAST "qualified"))
                schema->flags |= XML_SCHEMAS_QUALIF_ELEM;
            else if (!xmlStrEqual(val, BAD_CAST "unqualified")) {
                xmlSchemaPErr2(ctxt, node, child,
                               XML_SCHEMAP_ELEMFORMDEFAULT_VALUE,
                               "Invalid value %s for elementFormDefault\n",
                               val, NULL);
            }
        } else {
	    schema->flags |= XML_SCHEMAS_QUALIF_ELEM;
	}
        val = xmlSchemaGetProp(ctxt, node, "attributeFormDefault");
        if (val != NULL) {
            if (xmlStrEqual(val, BAD_CAST "qualified"))
                schema->flags |= XML_SCHEMAS_QUALIF_ATTR;
            else if (!xmlStrEqual(val, BAD_CAST "unqualified")) {
                xmlSchemaPErr2(ctxt, node, child,
                               XML_SCHEMAP_ATTRFORMDEFAULT_VALUE,
                               "Invalid value %s for attributeFormDefault\n",
                               val, NULL);
            }
        } 

        xmlSchemaParseSchemaTopLevel(ctxt, schema, node->children);
    } else {
        xmlDocPtr doc;

	doc = node->doc;

        if ((doc != NULL) && (doc->URL != NULL)) {
	    xmlSchemaPErr(ctxt, (xmlNodePtr) doc,
		      XML_SCHEMAP_NOT_SCHEMA,
		      "File %s is not a schemas", doc->URL, NULL);
	} else {
	    xmlSchemaPErr(ctxt, (xmlNodePtr) doc,
		      XML_SCHEMAP_NOT_SCHEMA,
		      "File is not a schemas", NULL, NULL);
	}
	return(NULL);
    }
    if (ctxt->nberrors != 0) {
        if (schema != NULL) {
            xmlSchemaFree(schema);
            schema = NULL;
        }
    }
    ctxt->nberrors = nberrors;
#ifdef DEBUG
    if (schema == NULL)
        xmlGenericError(xmlGenericErrorContext,
                        "xmlSchemaParse() failed\n");
#endif
    return (schema);
}

/************************************************************************
 * 									*
 * 			Validating using Schemas			*
 * 									*
 ************************************************************************/

/************************************************************************
 * 									*
 * 			Reading/Writing Schemas				*
 * 									*
 ************************************************************************/

/**
 * xmlSchemaNewParserCtxt:
 * @URL:  the location of the schema
 *
 * Create an XML Schemas parse context for that file/resource expected
 * to contain an XML Schemas file.
 *
 * Returns the parser context or NULL in case of error
 */
xmlSchemaParserCtxtPtr
xmlSchemaNewParserCtxt(const char *URL)
{
    xmlSchemaParserCtxtPtr ret;

    if (URL == NULL)
        return (NULL);

    ret = (xmlSchemaParserCtxtPtr) xmlMalloc(sizeof(xmlSchemaParserCtxt));
    if (ret == NULL) {
        xmlSchemaPErrMemory(NULL, "allocating schama parser context",
                            NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaParserCtxt));
    ret->dict = xmlDictCreate();
    ret->URL = xmlDictLookup(ret->dict, (const xmlChar *) URL, -1);
    ret->includes = 0;
    return (ret);
}

/**
 * xmlSchemaNewMemParserCtxt:
 * @buffer:  a pointer to a char array containing the schemas
 * @size:  the size of the array
 *
 * Create an XML Schemas parse context for that memory buffer expected
 * to contain an XML Schemas file.
 *
 * Returns the parser context or NULL in case of error
 */
xmlSchemaParserCtxtPtr
xmlSchemaNewMemParserCtxt(const char *buffer, int size)
{
    xmlSchemaParserCtxtPtr ret;

    if ((buffer == NULL) || (size <= 0))
        return (NULL);

    ret = (xmlSchemaParserCtxtPtr) xmlMalloc(sizeof(xmlSchemaParserCtxt));
    if (ret == NULL) {
        xmlSchemaPErrMemory(NULL, "allocating schama parser context",
                            NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaParserCtxt));
    ret->buffer = buffer;
    ret->size = size;
    ret->dict = xmlDictCreate();
    return (ret);
}

/**
 * xmlSchemaNewDocParserCtxt:
 * @doc:  a preparsed document tree
 *
 * Create an XML Schemas parse context for that document.
 * NB. The document may be modified during the parsing process.
 *
 * Returns the parser context or NULL in case of error
 */
xmlSchemaParserCtxtPtr
xmlSchemaNewDocParserCtxt(xmlDocPtr doc)
{
    xmlSchemaParserCtxtPtr ret;

    if (doc == NULL)
      return (NULL);

    ret = (xmlSchemaParserCtxtPtr) xmlMalloc(sizeof(xmlSchemaParserCtxt));
    if (ret == NULL) {
      xmlSchemaPErrMemory(NULL, "allocating schema parser context",
			  NULL);
      return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaParserCtxt));
    ret->doc = doc;
    ret->dict = xmlDictCreate();
    /* The application has responsibility for the document */
    ret->preserve = 1;

    return (ret);
}

/**
 * xmlSchemaFreeParserCtxt:
 * @ctxt:  the schema parser context
 *
 * Free the resources associated to the schema parser context
 */
void
xmlSchemaFreeParserCtxt(xmlSchemaParserCtxtPtr ctxt)
{
    if (ctxt == NULL)
        return;
    if (ctxt->doc != NULL && !ctxt->preserve)
        xmlFreeDoc(ctxt->doc);
    xmlDictFree(ctxt->dict);
    xmlFree(ctxt);
}

/************************************************************************
 *									*
 *			Building the content models			*
 *									*
 ************************************************************************/

/**
 * xmlSchemaBuildAContentModel:
 * @type:  the schema type definition
 * @ctxt:  the schema parser context
 * @name:  the element name whose content is being built
 *
 * Generate the automata sequence needed for that type
 */
static void
xmlSchemaBuildAContentModel(xmlSchemaTypePtr type,
                            xmlSchemaParserCtxtPtr ctxt,
                            const xmlChar * name)
{
    if (type == NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "Found unexpected type = NULL in %s content model\n",
                        name);
        return;
    }
    switch (type->type) {
        case XML_SCHEMA_TYPE_ANY:
            /* TODO : handle the namespace too */
            /* TODO : make that a specific transition type */
            TODO ctxt->state =
                xmlAutomataNewTransition(ctxt->am, ctxt->state, NULL,
                                         BAD_CAST "*", NULL);
            break;
        case XML_SCHEMA_TYPE_ELEMENT:{
                xmlSchemaElementPtr elem = (xmlSchemaElementPtr) type;

                /* TODO : handle the namespace too */
                xmlAutomataStatePtr oldstate = ctxt->state;

                if (elem->maxOccurs >= UNBOUNDED) {
                    if (elem->minOccurs > 1) {
                        xmlAutomataStatePtr tmp;
                        int counter;

                        ctxt->state = xmlAutomataNewEpsilon(ctxt->am,
                                                            oldstate,
                                                            NULL);
                        oldstate = ctxt->state;

                        counter = xmlAutomataNewCounter(ctxt->am,
                                                        elem->minOccurs -
                                                        1, UNBOUNDED);

                        if (elem->refDecl != NULL) {
                            xmlSchemaBuildAContentModel((xmlSchemaTypePtr)
                                                        elem->refDecl,
                                                        ctxt,
                                                        elem->refDecl->
                                                        name);
                        } else {
                            ctxt->state =
                                xmlAutomataNewTransition(ctxt->am,
                                                         ctxt->state, NULL,
                                                         elem->name, type);
                        }
                        tmp = ctxt->state;
                        xmlAutomataNewCountedTrans(ctxt->am, tmp, oldstate,
                                                   counter);
                        ctxt->state =
                            xmlAutomataNewCounterTrans(ctxt->am, tmp, NULL,
                                                       counter);

                    } else {
                        if (elem->refDecl != NULL) {
                            xmlSchemaBuildAContentModel((xmlSchemaTypePtr)
                                                        elem->refDecl,
                                                        ctxt,
                                                        elem->refDecl->
                                                        name);
                        } else {
                            ctxt->state =
                                xmlAutomataNewTransition(ctxt->am,
                                                         ctxt->state, NULL,
                                                         elem->name, type);
                        }
                        xmlAutomataNewEpsilon(ctxt->am, ctxt->state,
                                              oldstate);
                        if (elem->minOccurs == 0) {
                            /* basically an elem* */
                            xmlAutomataNewEpsilon(ctxt->am, oldstate,
                                                  ctxt->state);
                        }
                    }
                } else if ((elem->maxOccurs > 1) || (elem->minOccurs > 1)) {
                    xmlAutomataStatePtr tmp;
                    int counter;

                    ctxt->state = xmlAutomataNewEpsilon(ctxt->am,
                                                        oldstate, NULL);
                    oldstate = ctxt->state;

                    counter = xmlAutomataNewCounter(ctxt->am,
                                                    elem->minOccurs - 1,
                                                    elem->maxOccurs - 1);

                    if (elem->refDecl != NULL) {
                        xmlSchemaBuildAContentModel((xmlSchemaTypePtr)
                                                    elem->refDecl, ctxt,
                                                    elem->refDecl->name);
                    } else {
                        ctxt->state = xmlAutomataNewTransition(ctxt->am,
                                                               ctxt->state,
                                                               NULL,
                                                               elem->name,
                                                               type);
                    }
                    tmp = ctxt->state;
                    xmlAutomataNewCountedTrans(ctxt->am, tmp, oldstate,
                                               counter);
                    ctxt->state = xmlAutomataNewCounterTrans(ctxt->am, tmp,
                                                             NULL,
                                                             counter);
                    if (elem->minOccurs == 0) {
                        /* basically an elem? */
                        xmlAutomataNewEpsilon(ctxt->am, oldstate,
                                              ctxt->state);
                    }

                } else {
                    if (elem->refDecl != NULL) {
                        xmlSchemaBuildAContentModel((xmlSchemaTypePtr)
                                                    elem->refDecl, ctxt,
                                                    elem->refDecl->name);
                    } else {
                        ctxt->state = xmlAutomataNewTransition(ctxt->am,
                                                               ctxt->state,
                                                               NULL,
                                                               elem->name,
                                                               type);
                    }
                    if (elem->minOccurs == 0) {
                        /* basically an elem? */
                        xmlAutomataNewEpsilon(ctxt->am, oldstate,
                                              ctxt->state);
                    }
                }
                break;
            }
        case XML_SCHEMA_TYPE_SEQUENCE:{
                xmlSchemaTypePtr subtypes;

                /*
                 * If max and min occurances are default (1) then
                 * simply iterate over the subtypes
                 */
                if ((type->minOccurs == 1) && (type->maxOccurs == 1)) {
                    subtypes = type->subtypes;
                    while (subtypes != NULL) {
                        xmlSchemaBuildAContentModel(subtypes, ctxt, name);
                        subtypes = subtypes->next;
                    }
                } else {
                    xmlAutomataStatePtr oldstate = ctxt->state;

                    if (type->maxOccurs >= UNBOUNDED) {
                        if (type->minOccurs > 1) {
                            xmlAutomataStatePtr tmp;
                            int counter;

                            ctxt->state = xmlAutomataNewEpsilon(ctxt->am,
                                                                oldstate,
                                                                NULL);
                            oldstate = ctxt->state;

                            counter = xmlAutomataNewCounter(ctxt->am,
                                                            type->
                                                            minOccurs - 1,
                                                            UNBOUNDED);

                            subtypes = type->subtypes;
                            while (subtypes != NULL) {
                                xmlSchemaBuildAContentModel(subtypes, ctxt,
                                                            name);
                                subtypes = subtypes->next;
                            }
                            tmp = ctxt->state;
                            xmlAutomataNewCountedTrans(ctxt->am, tmp,
                                                       oldstate, counter);
                            ctxt->state =
                                xmlAutomataNewCounterTrans(ctxt->am, tmp,
                                                           NULL, counter);

                        } else {
                            subtypes = type->subtypes;
                            while (subtypes != NULL) {
                                xmlSchemaBuildAContentModel(subtypes, ctxt,
                                                            name);
                                subtypes = subtypes->next;
                            }
                            xmlAutomataNewEpsilon(ctxt->am, ctxt->state,
                                                  oldstate);
                            if (type->minOccurs == 0) {
                                xmlAutomataNewEpsilon(ctxt->am, oldstate,
                                                      ctxt->state);
                            }
                        }
                    } else if ((type->maxOccurs > 1)
                               || (type->minOccurs > 1)) {
                        xmlAutomataStatePtr tmp;
                        int counter;

                        ctxt->state = xmlAutomataNewEpsilon(ctxt->am,
                                                            oldstate,
                                                            NULL);
                        oldstate = ctxt->state;

                        counter = xmlAutomataNewCounter(ctxt->am,
                                                        type->minOccurs -
                                                        1,
                                                        type->maxOccurs -
                                                        1);

                        subtypes = type->subtypes;
                        while (subtypes != NULL) {
                            xmlSchemaBuildAContentModel(subtypes, ctxt,
                                                        name);
                            subtypes = subtypes->next;
                        }
                        tmp = ctxt->state;
                        xmlAutomataNewCountedTrans(ctxt->am, tmp, oldstate,
                                                   counter);
                        ctxt->state =
                            xmlAutomataNewCounterTrans(ctxt->am, tmp, NULL,
                                                       counter);
                        if (type->minOccurs == 0) {
                            xmlAutomataNewEpsilon(ctxt->am, oldstate,
                                                  ctxt->state);
                        }

                    } else {
                        subtypes = type->subtypes;
                        while (subtypes != NULL) {
                            xmlSchemaBuildAContentModel(subtypes, ctxt,
                                                        name);
                            subtypes = subtypes->next;
                        }
                        if (type->minOccurs == 0) {
                            xmlAutomataNewEpsilon(ctxt->am, oldstate,
                                                  ctxt->state);
                        }
                    }
                }
                break;
            }
        case XML_SCHEMA_TYPE_CHOICE:{
                xmlSchemaTypePtr subtypes;
                xmlAutomataStatePtr start, end;

                start = ctxt->state;
                end = xmlAutomataNewState(ctxt->am);

                /*
                 * iterate over the subtypes and remerge the end with an
                 * epsilon transition
                 */
                if (type->maxOccurs == 1) {
                    subtypes = type->subtypes;
                    while (subtypes != NULL) {
                        ctxt->state = start;
                        xmlSchemaBuildAContentModel(subtypes, ctxt, name);
                        xmlAutomataNewEpsilon(ctxt->am, ctxt->state, end);
                        subtypes = subtypes->next;
                    }
                } else {
                    int counter;
                    xmlAutomataStatePtr hop;
                    int maxOccurs = type->maxOccurs == UNBOUNDED ?
                        UNBOUNDED : type->maxOccurs - 1;
                    int minOccurs =
                        type->minOccurs < 1 ? 0 : type->minOccurs - 1;

                    /*
                     * use a counter to keep track of the number of transtions
                     * which went through the choice.
                     */
                    counter =
                        xmlAutomataNewCounter(ctxt->am, minOccurs,
                                              maxOccurs);
                    hop = xmlAutomataNewState(ctxt->am);

                    subtypes = type->subtypes;
                    while (subtypes != NULL) {
                        ctxt->state = start;
                        xmlSchemaBuildAContentModel(subtypes, ctxt, name);
                        xmlAutomataNewEpsilon(ctxt->am, ctxt->state, hop);
                        subtypes = subtypes->next;
                    }
                    xmlAutomataNewCountedTrans(ctxt->am, hop, start,
                                               counter);
                    xmlAutomataNewCounterTrans(ctxt->am, hop, end,
                                               counter);
                }
                if (type->minOccurs == 0) {
                    xmlAutomataNewEpsilon(ctxt->am, start, end);
                }
                ctxt->state = end;
                break;
            }
        case XML_SCHEMA_TYPE_ALL:{
                xmlAutomataStatePtr start;
                xmlSchemaTypePtr subtypes;
		/* 
		 * Changed, since type in not an xmlSchemaElement here.
		 */
                /* xmlSchemaElementPtr elem = (xmlSchemaElementPtr) type; */
		xmlSchemaElementPtr elem;
                int lax;

                subtypes = type->subtypes;
                if (subtypes == NULL)
                    break;
                start = ctxt->state;
                while (subtypes != NULL) {
                    ctxt->state = start;
		    /*
		     * the following 'if' was needed to fix bug 139897
		     * not quite sure why it only needs to be done for
		     * elements with a 'ref', but it seems to work ok.
		     */
		    if (subtypes->ref != NULL)
		        xmlSchemaBuildAContentModel(subtypes, ctxt, name);
                    elem = (xmlSchemaElementPtr) subtypes;		    
                    /* TODO : handle the namespace too */
                    if ((elem->minOccurs == 1) && (elem->maxOccurs == 1)) {
                        xmlAutomataNewOnceTrans(ctxt->am, ctxt->state,
                                                ctxt->state, elem->name, 1,
                                                1, subtypes);
                    } else {
                        xmlAutomataNewCountTrans(ctxt->am, ctxt->state,
                                                 ctxt->state, elem->name,
                                                 elem->minOccurs,
                                                 elem->maxOccurs,
                                                 subtypes);
                    }
                    subtypes = subtypes->next;
                }
                lax = type->minOccurs == 0;
                ctxt->state =
                    xmlAutomataNewAllTrans(ctxt->am, ctxt->state, NULL,
                                           lax);
                break;
            }
        case XML_SCHEMA_TYPE_RESTRICTION:
            if (type->subtypes != NULL)
                xmlSchemaBuildAContentModel(type->subtypes, ctxt, name);
            break;
        case XML_SCHEMA_TYPE_EXTENSION:
            if (type->baseType != NULL) {
                xmlSchemaTypePtr subtypes;

		if (type->recurse) { 
		    xmlSchemaPErr(ctxt, type->node, 
		                  XML_SCHEMAP_UNKNOWN_BASE_TYPE, 
			    "Schemas: extension type %s is recursive\n", 
				  type->name, NULL); 
		    return; 
                }
                type->recurse = 1; 
                xmlSchemaBuildAContentModel(type->baseType, ctxt, name);
            	type->recurse = 0;
                subtypes = type->subtypes;
                while (subtypes != NULL) {
                    xmlSchemaBuildAContentModel(subtypes, ctxt, name);
                    subtypes = subtypes->next;
                }
            } else if (type->subtypes != NULL)
                xmlSchemaBuildAContentModel(type->subtypes, ctxt, name);
            break;
        case XML_SCHEMA_TYPE_GROUP:
            if (type->subtypes == NULL) {
	        xmlSchemaTypePtr rgroup;
		if (type->ref != NULL) {
		    rgroup = xmlSchemaGetGroup(ctxt->schema, type->ref,
		    			   type->refNs);
		    if (rgroup == NULL) {
		        xmlSchemaPErr(ctxt, type->node,
				      XML_SCHEMAP_UNKNOWN_REF,
				"Schemas: group %s reference %s is not found",
				name, type->ref);
			return;
		    }
		    xmlSchemaBuildAContentModel(rgroup, ctxt, name);
		    break;
		}
            }
        case XML_SCHEMA_TYPE_COMPLEX:
        case XML_SCHEMA_TYPE_COMPLEX_CONTENT:
            if (type->subtypes != NULL)
                xmlSchemaBuildAContentModel(type->subtypes, ctxt, name);
            break;
        default:
            xmlGenericError(xmlGenericErrorContext,
                            "Found unexpected type %d in %s content model\n",
                            type->type, name);
            return;
    }
}

/**
 * xmlSchemaBuildContentModel:
 * @elem:  the element
 * @ctxt:  the schema parser context
 * @name:  the element name
 *
 * Builds the content model of the element.
 */
static void
xmlSchemaBuildContentModel(xmlSchemaElementPtr elem,
                           xmlSchemaParserCtxtPtr ctxt,
                           const xmlChar * name)
{
    xmlAutomataStatePtr start;

    if (elem->contModel != NULL)
        return;
    if (elem->subtypes == NULL) {
        elem->contentType = XML_SCHEMA_CONTENT_ANY;
        return;
    }
    if (elem->subtypes->type != XML_SCHEMA_TYPE_COMPLEX)
        return;
    if ((elem->subtypes->contentType == XML_SCHEMA_CONTENT_BASIC) ||
        (elem->subtypes->contentType == XML_SCHEMA_CONTENT_SIMPLE))
        return;

#ifdef DEBUG_CONTENT
    xmlGenericError(xmlGenericErrorContext,
                    "Building content model for %s\n", name);
#endif

    ctxt->am = xmlNewAutomata();
    if (ctxt->am == NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "Cannot create automata for elem %s\n", name);
        return;
    }
    start = ctxt->state = xmlAutomataGetInitState(ctxt->am);
    xmlSchemaBuildAContentModel(elem->subtypes, ctxt, name);
    xmlAutomataSetFinalState(ctxt->am, ctxt->state);
    elem->contModel = xmlAutomataCompile(ctxt->am);
    if (elem->contModel == NULL) {
        xmlSchemaPErr(ctxt, elem->node, XML_SCHEMAS_ERR_INTERNAL,
                      "failed to compile %s content model\n", name, NULL);
    } else if (xmlRegexpIsDeterminist(elem->contModel) != 1) {
        xmlSchemaPErr(ctxt, elem->node, XML_SCHEMAS_ERR_NOTDETERMINIST,
                      "Content model of %s is not determinist:\n", name,
                      NULL);
    } else {
#ifdef DEBUG_CONTENT_REGEXP
        xmlGenericError(xmlGenericErrorContext,
                        "Content model of %s:\n", name);
        xmlRegexpPrint(stderr, elem->contModel);
#endif
    }
    ctxt->state = NULL;
    xmlFreeAutomata(ctxt->am);
    ctxt->am = NULL;
}

/**
 * xmlSchemaRefFixupCallback:
 * @elem:  the schema element context
 * @ctxt:  the schema parser context
 *
 * Free the resources associated to the schema parser context
 */
static void
xmlSchemaRefFixupCallback(xmlSchemaElementPtr elem,
                          xmlSchemaParserCtxtPtr ctxt,
                          const xmlChar * name,
                          const xmlChar * context ATTRIBUTE_UNUSED,
                          const xmlChar * namespace ATTRIBUTE_UNUSED)
{
    if ((ctxt == NULL) || (elem == NULL))
        return;

    if (elem->ref != NULL) {
        xmlSchemaElementPtr elemDecl;

        if (elem->subtypes != NULL) {
            xmlSchemaPErr(ctxt, elem->node,
                          XML_SCHEMAP_INVALID_REF_AND_SUBTYPE,
                          "Schemas: element %s has both ref and subtype\n",
                          name, NULL);
            return;
        }
        elemDecl = xmlSchemaGetElem(ctxt->schema, elem->ref, elem->refNs, 0);

        if (elemDecl == NULL) {
            xmlSchemaPErr(ctxt, elem->node, XML_SCHEMAP_UNKNOWN_REF,
                          "Schemas: element %s ref to %s not found\n",
                          name, elem->ref);
            return;
        }
        elem->refDecl = elemDecl;
    } else if (elem->namedType != NULL) {
        xmlSchemaTypePtr typeDecl;

        if (elem->subtypes != NULL) {
            xmlSchemaPErr(ctxt, elem->node, XML_SCHEMAP_TYPE_AND_SUBTYPE,
                          "Schemas: element %s has both type and subtype\n",
                          name, NULL);
            return;
        }
        typeDecl = xmlSchemaGetType(ctxt->schema, elem->namedType,
                                    elem->namedTypeNs);

        if (typeDecl == NULL) {
            xmlSchemaPErr(ctxt, elem->node, XML_SCHEMAP_UNKNOWN_TYPE,
                          "Schemas: element %s type %s not found\n", name,
                          elem->namedType);
            return;
        }
        elem->subtypes = typeDecl;
    }
}

/**
 * xmlSchemaParseListRefFixup:
 * @type:  the schema type definition
 * @ctxt:  the schema parser context
 *
 * Fixup of the itemType reference of the list type.
 */
static void
xmlSchemaParseListRefFixup(xmlSchemaTypePtr type, xmlSchemaParserCtxtPtr ctxt)
{
    const xmlChar *itemType, *namespace;
    xmlSchemaTypePtr subtype;
    
    /* Handle the "itemType" attribute. */
    itemType = xmlGetQNameProp(ctxt, type->node, "itemType", &namespace);
    if (itemType != NULL) {
        /* Do not allow more that one item type. */
        if (type->subtypes != NULL) {
            xmlSchemaPErr(ctxt, type->node,
	    		  XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE,
                          "List %s has more than one item type defined\n",
			  type->name, NULL);
        }
        subtype = xmlSchemaGetType(ctxt->schema, itemType, namespace);
        if (subtype == NULL) {
            xmlSchemaPErr(ctxt, type->node, XML_SCHEMAP_UNKNOWN_TYPE,
                          "List %s references an unknown item type: %s\n",
                          type->name, xmlSchemaGetProp(ctxt, type->node,
			  "itemType"));
        } else
            type->subtypes = subtype;
    }
}

/**
 * xmlSchemaParseUnionRefCheck:
 * @typeDecl:  the schema type definition
 * @ctxt:  the schema parser context
 *
 * Checks the memberTypes references of the union type.
 */
static void
xmlSchemaParseUnionRefCheck(xmlSchemaTypePtr type,
                   xmlSchemaParserCtxtPtr ctxt)
{
    const xmlChar *cur, *end, *prefix, *ncName, *namespace;
    xmlChar *tmp;
    xmlSchemaTypePtr subtype;
    xmlNsPtr ns;
    int len;

     if ((type->type != XML_SCHEMA_TYPE_UNION) || (type->ref == NULL))
        return;

    cur = type->ref;
    do {
        while (IS_BLANK_CH(*cur))
            cur++;
        end = cur;
        while ((*end != 0) && (!(IS_BLANK_CH(*end))))
            end++;
        if (end == cur)
            break;
        tmp = xmlStrndup(cur, end - cur);
        ncName = xmlSplitQName3(tmp, &len);
        if (ncName != NULL) {
            prefix = xmlDictLookup(ctxt->dict, tmp, len);
        } else {
            prefix = NULL;
            ncName = tmp;
        }
        ns = xmlSearchNs(type->node->doc, type->node, prefix);
        if (ns == NULL) {
            if (prefix != NULL) {
                xmlSchemaPErr(ctxt, type->node, XML_SCHEMAP_PREFIX_UNDEFINED,
                              "Union %s: the namespace prefix of member type "
			      "%s is undefined\n",
                              type->name, (const xmlChar *) tmp);
            }
            namespace = NULL;
        } else {
            namespace = xmlDictLookup(ctxt->dict, ns->href, -1);
        }
        /* Lookup the referenced type */
        subtype = xmlSchemaGetType(ctxt->schema, ncName, namespace);
        if (subtype == NULL) {
            xmlSchemaPErr(ctxt, type->node, XML_SCHEMAP_UNKNOWN_MEMBER_TYPE,
                       "Union %s references an unknown member type %s\n",
                       type->name,  (const xmlChar *) tmp);
        } 
        xmlFree(tmp);
        cur = end;
    } while (*cur != 0);    
}

/**
 * xmlSchemaGetOnymousTypeName:
 * @attr:  the attribute declaration/use
 *
 * Returns the name of the attribute; if the attribute
 * is a reference, the name of the referenced global type will be returned.
 */
static const xmlChar *
xmlSchemaGetOnymousAttrName(xmlSchemaAttributePtr attr) 
{
    if (attr->ref != NULL) 
	return(attr->ref);
    else
	return(attr->name);	
}

/**
 * xmlSchemaGetOnymousTargetNsURI:
 * @type:  the type (element or attribute)
 *
 * Returns the target namespace URI of the type; if the type is a reference,
 * the target namespace of the referenced type will be returned.
 */
static const xmlChar *
xmlSchemaGetOnymousTargetNsURI(xmlSchemaTypePtr type)
{
    if (type->type == XML_SCHEMA_TYPE_ELEMENT) {
	if (type->ref != NULL)
	    return(((xmlSchemaElementPtr)((xmlSchemaElementPtr) 
		type)->subtypes)->targetNamespace);
	else
	    return(((xmlSchemaElementPtr) type)->targetNamespace);
    } else if (type->type == XML_SCHEMA_TYPE_ATTRIBUTE) {
	if (type->ref != NULL)
	    return(((xmlSchemaAttributePtr)((xmlSchemaAttributePtr) 
		type)->subtypes)->targetNamespace);
	else
	    return(((xmlSchemaAttributePtr) type)->targetNamespace);
    } else 
	return (NULL);
}

/**
 * xmlSchemaIsDerivedFromBuiltInType:
 * @ctxt:  the schema parser context
 * @type:  the type definition
 * @valType: the value type
 * 
 *
 * Returns 1 if the type has the given value type, or
 * is derived from such a type.
 */
static int
xmlSchemaIsDerivedFromBuiltInType(xmlSchemaParserCtxtPtr ctxt, 
				  xmlSchemaTypePtr type, int valType)
{
    /* TODO: Check if this works in every case. */
	if ((type->type == XML_SCHEMA_TYPE_BASIC) &&
		(type->contentType == XML_SCHEMA_CONTENT_BASIC)) {
		if (type->flags == valType)
			return(1);
    } else if (type->type == XML_SCHEMA_TYPE_ATTRIBUTE) {
	if (((xmlSchemaAttributePtr) type)->subtypes != NULL) 
	    return(xmlSchemaIsDerivedFromBuiltInType(ctxt, 
		((xmlSchemaAttributePtr) type)->subtypes, valType));
    } else if ((type->type == XML_SCHEMA_TYPE_RESTRICTION) ||
	(type->type == XML_SCHEMA_TYPE_EXTENSION)) {
	if (type->baseType != NULL) 
	    return(xmlSchemaIsDerivedFromBuiltInType(ctxt, type->baseType, 
		valType));
    } else if ((type->subtypes != NULL) &&
	((type->subtypes->type == XML_SCHEMA_TYPE_COMPLEX) ||
	 (type->subtypes->type == XML_SCHEMA_TYPE_COMPLEX_CONTENT) ||
	 (type->subtypes->type == XML_SCHEMA_TYPE_SIMPLE) ||
	 (type->subtypes->type == XML_SCHEMA_TYPE_SIMPLE_CONTENT))) {
	return(xmlSchemaIsDerivedFromBuiltInType(ctxt, type->subtypes, 
	    valType));
    }

    return (0);
}

/**
 * xmlSchemaBuildAttributeUsesOwned:
 * @ctxt:  the schema parser context
 * @type:  the complex type definition
 * @cur: the attribute declaration list
 * @lastUse: the top of the attribute use list
 *
 * Builds the attribute uses list on the given complex type.
 * This one is supposed to be called by 
 * xmlSchemaBuildAttributeValidation only.
 */
static int
xmlSchemaBuildAttributeUsesOwned(xmlSchemaParserCtxtPtr ctxt, 
				 xmlSchemaAttributePtr cur,
				 xmlSchemaAttributeLinkPtr *uses,
				 xmlSchemaAttributeLinkPtr *lastUse)
{
    xmlSchemaAttributeLinkPtr tmp;
    while (cur != NULL) {
	if (cur->type == XML_SCHEMA_TYPE_ATTRIBUTEGROUP) {
	    /* 
	     * W3C: "2 The {attribute uses} of the attribute groups ·resolved· 
	     * to by the ·actual value·s of the ref [attribute] of the 
	     * <attributeGroup> [children], if any."
	     */
	    if (xmlSchemaBuildAttributeUsesOwned(ctxt, 
		((xmlSchemaAttributeGroupPtr) cur)->attributes, uses, 
		lastUse) == -1) {
		return (-1);	    
	    }
	} else {
	    /* W3C: "1 The set of attribute uses corresponding to the 
	     * <attribute> [children], if any."
	     */	    	    
	    tmp = (xmlSchemaAttributeLinkPtr) 
		xmlMalloc(sizeof(xmlSchemaAttributeLink));
	    if (tmp == NULL) {
		xmlSchemaPErrMemory(ctxt, "building attribute uses", NULL);
		return (-1);
	    }
	    tmp->attr = cur;
	    tmp->next = NULL;
	    if (*uses == NULL)
		*uses = tmp;		    
	    else 
		(*lastUse)->next = tmp;
	    *lastUse = tmp;	    
	}	
	cur = cur->next;
    }	
    return (0);
}

static int
xmlSchemaCloneWildcardNsConstraints(xmlSchemaParserCtxtPtr ctxt,
				    xmlSchemaWildcardPtr *dest,
				    xmlSchemaWildcardPtr source)				    
{
    xmlSchemaWildcardNsPtr cur, tmp, last;

    if ((source == NULL) || (*dest == NULL))
	return(-1);    
    (*dest)->any = source->any;
    cur = source->nsSet;
    last = NULL;
    while (cur != NULL) {
	tmp = xmlSchemaNewWildcardNsConstraint(ctxt);
	if (tmp == NULL)
	    return(-1);
	tmp->value = cur->value;
	if (last == NULL)
	    (*dest)->nsSet = tmp;
	else 
	    last->next = tmp;
	last = tmp;
	cur = cur->next;
    }    
    if ((*dest)->negNsSet != NULL)
	xmlSchemaFreeWildcardNsSet((*dest)->negNsSet);	   
    if (source->negNsSet != NULL) {
	(*dest)->negNsSet = xmlSchemaNewWildcardNsConstraint(ctxt);
	if ((*dest)->negNsSet == NULL)
	    return(-1);
	(*dest)->negNsSet->value = source->negNsSet->value;	    
    } else
	(*dest)->negNsSet = NULL;
    return(0);
}

static int
xmlSchemaUnionWildcards(xmlSchemaParserCtxtPtr ctxt, 			    
			    xmlSchemaWildcardPtr completeWild,
			    xmlSchemaWildcardPtr curWild)
{
    xmlSchemaWildcardNsPtr cur, curB, tmp;

    /*
    * 1 If O1 and O2 are the same value, then that value must be the 
    * value.
    */
    if ((completeWild->any == curWild->any) &&
	((completeWild->nsSet == NULL) == (curWild->nsSet == NULL)) &&
	((completeWild->negNsSet == NULL) == (curWild->negNsSet == NULL))) {
	
	if ((completeWild->negNsSet == NULL) ||
	    (completeWild->negNsSet->value == curWild->negNsSet->value)) {
	    
	    if (completeWild->nsSet != NULL) {
		int found = 0;
		
		/* 
		* Check equality of sets. 
		*/
		cur = completeWild->nsSet;
		while (cur != NULL) {
		    found = 0;
		    curB = curWild->nsSet;
		    while (curB != NULL) {
			if (cur->value == curB->value) {
			    found = 1;
			    break;
			}
			curB = curB->next;
		    }
		    if (!found)
			break;
		    cur = cur->next;
		}
		if (found)
		    return(0);
	    } else
		return(0);
	}
    }	        
    /*
    * 2 If either O1 or O2 is any, then any must be the value
    */
    if ((completeWild->any != curWild->any) && (completeWild->any)) {	
	if (completeWild->any == 0) {
	    completeWild->any = 1;
	    if (completeWild->nsSet != NULL) {
		xmlSchemaFreeWildcardNsSet(completeWild->nsSet);
		completeWild->nsSet = NULL;
	    }
	    if (completeWild->negNsSet != NULL) {
		xmlFree(completeWild->negNsSet);
		completeWild->negNsSet = NULL;
	    }
	}
    }
    /*
    * 3 If both O1 and O2 are sets of (namespace names or ·absent·), 
    * then the union of those sets must be the value.
    */
    if ((completeWild->nsSet != NULL) && (curWild->nsSet != NULL)) {		
	int found;
	xmlSchemaWildcardNsPtr start;
	
	cur = curWild->nsSet;
	start = completeWild->nsSet;
	while (cur != NULL) {
	    found = 0;
	    curB = start;
	    while (curB != NULL) {
		if (cur->value == curB->value) {
		    found = 1;
		    break;
		}
		curB = curB->next;
	    }
	    if (!found) {
		tmp = xmlSchemaNewWildcardNsConstraint(ctxt);
		if (tmp == NULL) 
		    return (-1);
		tmp->value = cur->value;
		tmp->next = completeWild->nsSet;		    		    
		completeWild->nsSet = tmp;
	    }
	    cur = cur->next;
	}	
		    		
	return(0);
    }    
    /*
    * 4 If the two are negations of different values (namespace names 
    * or ·absent·), then a pair of not and ·absent· must be the value.
    */
    if ((completeWild->negNsSet != NULL) && 
	(curWild->negNsSet != NULL) &&
	(completeWild->negNsSet->value != curWild->negNsSet->value)) {
	completeWild->negNsSet->value = NULL;
    }
    /* 
     * 5.
     */
    if (((completeWild->negNsSet != NULL) && 
	(completeWild->negNsSet->value != NULL) &&
	(curWild->nsSet != NULL)) ||
	((curWild->negNsSet != NULL) && 
	(curWild->negNsSet->value != NULL) &&
	(completeWild->nsSet != NULL))) {

	int nsFound, absentFound = 0;
	
	if (completeWild->nsSet != NULL) {
	    cur = completeWild->nsSet;
	    curB = curWild->negNsSet;
	} else {
	    cur = curWild->nsSet;
	    curB = completeWild->negNsSet;
	}
	nsFound = 0;
	while (cur != NULL) {
	    if (cur->value == NULL) 
		absentFound = 1;
	    else if (cur->value == curB->value)
		nsFound = 1;
	    if (nsFound && absentFound)
		break;
	    cur = cur->next;
	}	

	if (nsFound && absentFound) {
	    /*
	    * 5.1 If the set S includes both the negated namespace 
	    * name and ·absent·, then any must be the value.
	    */    
	    completeWild->any = 1;
	    if (completeWild->nsSet != NULL) {
		xmlSchemaFreeWildcardNsSet(completeWild->nsSet);
		completeWild->nsSet = NULL;
	    }
	    if (completeWild->negNsSet != NULL) {
		xmlFree(completeWild->negNsSet);
		completeWild->negNsSet = NULL;
	    }
	} else if (nsFound && (!absentFound)) {
	    /* 
	    * 5.2 If the set S includes the negated namespace name 
	    * but not ·absent·, then a pair of not and ·absent· must 
	    * be the value.
	    */
	    if (completeWild->nsSet != NULL) {
		xmlSchemaFreeWildcardNsSet(completeWild->nsSet);
		completeWild->nsSet = NULL;
	    }
	    if (completeWild->negNsSet == NULL) {
		completeWild->negNsSet = xmlSchemaNewWildcardNsConstraint(ctxt);
		if (completeWild->negNsSet == NULL)
		    return (-1);
	    }
	    completeWild->negNsSet->value = NULL;
	} else if ((!nsFound) && absentFound) {
	    /*
	    * 5.3 If the set S includes ·absent· but not the negated 
	    * namespace name, then the union is not expressible.
	    */
	    xmlSchemaPErr(ctxt, completeWild->node, 
		XML_SCHEMAP_UNION_NOT_EXPRESSIBLE,
		"The union of the wilcard is not expressible\n",
		NULL, NULL);	
	return(0);
	} else if ((!nsFound) && (!absentFound)) {
	    /* 
	    * 5.4 If the set S does not include either the negated namespace 
	    * name or ·absent·, then whichever of O1 or O2 is a pair of not 
	    * and a namespace name must be the value.
	    */
	    if (completeWild->negNsSet == NULL) {
		if (completeWild->nsSet != NULL) {
		    xmlSchemaFreeWildcardNsSet(completeWild->nsSet);
		    completeWild->nsSet = NULL;
		}
		completeWild->negNsSet = xmlSchemaNewWildcardNsConstraint(ctxt);
		if (completeWild->negNsSet == NULL)
		    return (-1);
		completeWild->negNsSet->value = curWild->negNsSet->value;
	    }
	}
	return (0);
    }
    /* 
     * 6.
     */
    if (((completeWild->negNsSet != NULL) && 
	(completeWild->negNsSet->value == NULL) &&
	(curWild->nsSet != NULL)) ||
	((curWild->negNsSet != NULL) && 
	(curWild->negNsSet->value == NULL) &&
	(completeWild->nsSet != NULL))) {

	if (completeWild->nsSet != NULL) {
	    cur = completeWild->nsSet;
	} else {
	    cur = curWild->nsSet;
	}	
	while (cur != NULL) {
	    if (cur->value == NULL) {
		/*
		* 6.1 If the set S includes ·absent·, then any must be the 
		* value.
		*/
		completeWild->any = 1;
		if (completeWild->nsSet != NULL) {
		    xmlSchemaFreeWildcardNsSet(completeWild->nsSet);
		    completeWild->nsSet = NULL;
		}
		if (completeWild->negNsSet != NULL) {
		    xmlFree(completeWild->negNsSet);
		    completeWild->negNsSet = NULL;
		}
		return (0);
	    }
	    cur = cur->next;
	}			
	if (completeWild->negNsSet == NULL) {
	    /*
	    * 6.2 If the set S does not include ·absent·, then a pair of not 
	    * and ·absent· must be the value.
	    */
	    if (completeWild->nsSet != NULL) {
		xmlSchemaFreeWildcardNsSet(completeWild->nsSet);
		completeWild->nsSet = NULL;
	    }
	    completeWild->negNsSet = xmlSchemaNewWildcardNsConstraint(ctxt);
	    if (completeWild->negNsSet == NULL)
		return (-1);
	    completeWild->negNsSet->value = NULL;
	}
	return (0);
    }
    return (0);

}

static int
xmlSchemaIntersectWildcards(xmlSchemaParserCtxtPtr ctxt, 			    
			    xmlSchemaWildcardPtr completeWild,
			    xmlSchemaWildcardPtr curWild)
{
    xmlSchemaWildcardNsPtr cur, curB, prev,  tmp;

    /*
    * 1 If O1 and O2 are the same value, then that value must be the 
    * value.
    */
    if ((completeWild->any == curWild->any) &&
	((completeWild->nsSet == NULL) == (curWild->nsSet == NULL)) &&
	((completeWild->negNsSet == NULL) == (curWild->negNsSet == NULL))) {
	
	if ((completeWild->negNsSet == NULL) ||
	    (completeWild->negNsSet->value == curWild->negNsSet->value)) {
	    
	    if (completeWild->nsSet != NULL) {
		int found = 0;
		
		/* 
		* Check equality of sets. 
		*/
		cur = completeWild->nsSet;
		while (cur != NULL) {
		    found = 0;
		    curB = curWild->nsSet;
		    while (curB != NULL) {
			if (cur->value == curB->value) {
			    found = 1;
			    break;
			}
			curB = curB->next;
		    }
		    if (!found)
			break;
		    cur = cur->next;
		}
		if (found)
		    return(0);
	    } else
		return(0);
	}
    }	        
    /*
    * 2 If either O1 or O2 is any, then the other must be the value.
    */
    if ((completeWild->any != curWild->any) && (completeWild->any)) {		    
	if (xmlSchemaCloneWildcardNsConstraints(ctxt, &completeWild, curWild) == -1)
	    return(-1);	    
	return(0);
    }	            
    /*
    * 3 If either O1 or O2 is a pair of not and a value (a namespace 
    * name or ·absent·) and the other is a set of (namespace names or 
    * ·absent·), then that set, minus the negated value if it was in 
    * the set, minus ·absent· if it was in the set, must be the value.
    */
    if (((completeWild->negNsSet != NULL) && (curWild->nsSet != NULL)) ||
	((curWild->negNsSet != NULL) && (completeWild->nsSet != NULL))) {
	const xmlChar *neg;
	
	if (completeWild->nsSet == NULL) {
	    neg = completeWild->negNsSet->value;
	    if (xmlSchemaCloneWildcardNsConstraints(ctxt, &completeWild, curWild) == -1)
		return(-1);
	} else
	    neg = curWild->negNsSet->value;
	/*
	* Remove absent and negated.
	*/
	prev = NULL;
	cur = completeWild->nsSet;
	while (cur != NULL) {
	    if (cur->value == NULL) {
		if (prev == NULL) 
		    completeWild->nsSet = cur->next;
		else 
		    prev->next = cur->next;
		xmlFree(cur);
		break;
	    }
	    prev = cur;
	    cur = cur->next;
	}
	if (neg != NULL) {
	    prev = NULL;
	    cur = completeWild->nsSet;
	    while (cur != NULL) {
		if (cur->value == neg) {
		    if (prev == NULL) 
			completeWild->nsSet = cur->next;
		    else 
			prev->next = cur->next;
		    xmlFree(cur);
		    break;
		}
		prev = cur;
		cur = cur->next;
	    }
	}

	return(0);
    }	        
    /*
    * 4 If both O1 and O2 are sets of (namespace names or ·absent·), 
    * then the intersection of those sets must be the value.
    */
    if ((completeWild->nsSet != NULL) && (curWild->nsSet != NULL)) {		
	int found;
	
	cur = completeWild->nsSet;
	prev = NULL;
	while (cur != NULL) {
	    found = 0;
	    curB = curWild->nsSet;
	    while (curB != NULL) {
		if (cur->value == curB->value) {
		    found = 1;
		    break;
		}
		curB = curB->next;
	    }
	    if (!found) {
		if (prev == NULL)
		    completeWild->nsSet = cur->next;
		else 
		    prev->next = cur->next;
		tmp = cur->next;
		xmlFree(cur);
		cur = tmp;		
		continue;
	    }
	    prev = cur;
	    cur = cur->next;
	}	
		    		
	return(0);
    }    
    /* 5 If the two are negations of different namespace names, 
    * then the intersection is not expressible
    */	    
    if ((completeWild->negNsSet != NULL) && 
	(curWild->negNsSet != NULL) &&
	(completeWild->negNsSet->value != curWild->negNsSet->value) &&
	(completeWild->negNsSet->value != NULL) && 
	(curWild->negNsSet->value != NULL)) {

	xmlSchemaPErr(ctxt, completeWild->node, XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE,
	    "The intersection of the wilcard is not expressible\n",
	    NULL, NULL);	
	return(0);
    }		    
    /* 
    * 6 If the one is a negation of a namespace name and the other 
    * is a negation of ·absent·, then the one which is the negation 
    * of a namespace name must be the value.
    */
    if ((completeWild->negNsSet != NULL) && (curWild->negNsSet != NULL) &&
	(completeWild->negNsSet->value != curWild->negNsSet->value) &&
	(completeWild->negNsSet->value == NULL)) {	
	completeWild->negNsSet->value =  curWild->negNsSet->value; 
    }
    return(0);
}


static xmlSchemaWildcardPtr
xmlSchemaBuildCompleteAttributeWildcard(xmlSchemaParserCtxtPtr ctxt, 				   
				   xmlSchemaAttributePtr attrs,				   
				   xmlSchemaWildcardPtr completeWild)					
{        
    while (attrs != NULL) {
	if (attrs->type == XML_SCHEMA_TYPE_ATTRIBUTEGROUP) {
	    xmlSchemaAttributeGroupPtr group;

	    group = (xmlSchemaAttributeGroupPtr) attrs;	  
	    if ((group->flags & XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED) == 0) {
		if (group->attributes != NULL) {
		    if (group->attributeWildcard != NULL)			
			xmlSchemaBuildCompleteAttributeWildcard(ctxt, 
			    group->attributes, group->attributeWildcard);
		    else
			group->attributeWildcard = 
			    xmlSchemaBuildCompleteAttributeWildcard(ctxt, 
				group->attributes, group->attributeWildcard);
		}
		group->flags |= XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED;
	    }		
	    if (group->attributeWildcard != NULL) {		
		if (completeWild == NULL) {
		    /*
		    * Copy the first encountered wildcard as context, except for the annotation.
		    */
		    completeWild = xmlSchemaAddWildcard(ctxt);
		    completeWild->type = XML_SCHEMA_TYPE_ANY_ATTRIBUTE;	   
		    if (!xmlSchemaCloneWildcardNsConstraints(ctxt, 
			&completeWild, group->attributeWildcard))
			return(NULL);
		    completeWild->processContents = group->attributeWildcard->processContents;
		    /*
		    * Although the complete wildcard might not correspond to any
		    * node in the schema, we will save this context node.
		    */
		    completeWild->node = group->attributeWildcard->node;  
		    return(completeWild);
		} 				
		if (xmlSchemaIntersectWildcards(ctxt, completeWild, group->attributeWildcard) == -1) {
		    xmlSchemaFreeWildcard(completeWild);
		    return(NULL);
		}		
	    }
	}
	attrs = attrs->next;
    }
   		                 
    return (completeWild);   
}

/**
 * xmlSchemaMatchesWildcardNs:
 * @wild:  the wildcard
 * @ns:  the namespace
 * 
 *
 * Returns 1 if the given namespace matches the wildcard,
 * 0 otherwise.
 */
static int
xmlSchemaMatchesWildcardNs(xmlSchemaWildcardPtr wild, const xmlChar* ns)
{
    if (wild == NULL)
	return(0);

    if (wild->any)
	return(1);
    else if (wild->nsSet != NULL) {
	xmlSchemaWildcardNsPtr cur;

	cur = wild->nsSet;
	while (cur != NULL) {
	    if (xmlStrEqual(cur->value, ns))
		return(1);
	    cur = cur->next;
	}
    } else if ((wild->negNsSet != NULL) && (ns != NULL) && 
	(!xmlStrEqual(wild->negNsSet->value, ns)))
	return(1);	
	
    return(0);
}

/**
 * xmlSchemaBuildAttributeValidation:
 * @ctxt:  the schema parser context
 * @type:  the complex type definition
 * 
 *
 * Builds the wildcard and the attribute uses on the given complex type.
 * Returns -1 if an internal error occurs, 0 otherwise.
 */
static int
xmlSchemaBuildAttributeValidation(xmlSchemaParserCtxtPtr ctxt, xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr baseType = NULL;
    xmlSchemaAttributeLinkPtr cur, base, tmp, id = NULL, prev = NULL, uses = NULL, 
	lastUse = NULL, lastBaseUse = NULL;
    xmlSchemaAttributePtr attrs;
    int baseIsAnyType = 0;    

    /* 
     * Complex Type Definition with complex content Schema Component.
     *
     * Attribute uses.
     */
    if (type->attributeUses != NULL) {
        xmlSchemaPErr(ctxt, type->node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaParseBuildAttributeUses: "
		      "attribute uses already builded.\n",
		      NULL, NULL);
        return (-1);
    }
    if ((type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) || 
	(type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION)) {	
	/*
	 * Inherit the attribute uses of the base type.
	 */
	baseType = type->subtypes->subtypes->baseType;
	/*
	 * TODO: URGENT: This is not nice, but currently 
	 * xmlSchemaTypeAnyTypeDef is static in xmlschematypes.c.
	 */
	if ((baseType->type == XML_SCHEMA_TYPE_BASIC) &&
	    xmlStrEqual(baseType->name, BAD_CAST "anyType")) {	    
	    baseIsAnyType = 1;
	}
	/*
	 * TODO: Does the spec state that it is an error to "extend" the 
	 * anyType?
	 */
	if (!baseIsAnyType) {
	    if (baseType != NULL) {
		for (cur = baseType->attributeUses; cur != NULL; cur = cur->next) {
		    tmp = (xmlSchemaAttributeLinkPtr) 
			xmlMalloc(sizeof(xmlSchemaAttributeLink));
		    if (tmp == NULL) {
			xmlSchemaPErrMemory(ctxt, 
			    "building attribute uses of complexType", NULL);
			return (-1);
		    }
		    tmp->attr = cur->attr;
		    tmp->next = NULL;
		    if (type->attributeUses == NULL) {
			type->attributeUses = tmp;
		    } else 
			lastBaseUse->next = tmp;
		    lastBaseUse = tmp; 
		}
	    }
	}
	attrs = type->subtypes->subtypes->attributes;	
	/*
	* Handle attribute wildcards.
	*/
	type->attributeWildcard = 
	    xmlSchemaBuildCompleteAttributeWildcard(ctxt, 
		attrs, 
		type->subtypes->subtypes->attributeWildcard);
	if ((type->attributeWildcard != NULL) &&
	    (type->attributeWildcard != type->subtypes->subtypes->attributeWildcard))
	    type->flags |= XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD;

	if ((type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) && 
	    (baseType != NULL) && (baseType->type == XML_SCHEMA_TYPE_COMPLEX) && 
	    (baseType->attributeWildcard != NULL)) {	    
	    if (type->attributeWildcard != NULL) {
		/*
		* Union the complete wildcard with the base wildcard.
		*/
		if (xmlSchemaUnionWildcards(ctxt, type->attributeWildcard, 
		    baseType->attributeWildcard) == -1)
		    return (-1);
	    } else {
		/*
		* Just inherit the wildcard.
		*/
		type->attributeWildcard = baseType->attributeWildcard;
	    }
	}
    } else {
	/*
	 * Although the complexType is implicitely derived by "restriction"
	 * from the ur-type, this is not (yet?) reflected by libxml2.
	 */
	baseType = NULL;
	attrs = type->attributes;
	if (attrs != NULL)
	    type->attributeWildcard =
		xmlSchemaBuildCompleteAttributeWildcard(ctxt, attrs, type->attributeWildcard);
    }
    /*
     * Gather attribute uses defined by this type.
     */
    if (attrs != NULL) {
	if (xmlSchemaBuildAttributeUsesOwned(ctxt, attrs, 
	    &uses, &lastUse) == -1) {
	    return (-1);
	}
    }
    /* 3.4.6 -> Complex Type Definition Properties Correct 4.
     * "Two distinct attribute declarations in the {attribute uses} must 
     * not have identical {name}s and {target namespace}s."
     *
     * For "extension" this is done further down.
     */
    if ((uses != NULL) && ((type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) == 0)) {
	cur = uses;
	while (cur != NULL) {
	    tmp = cur->next;
	    while (tmp != NULL) {	    
		if ((xmlStrEqual(xmlSchemaGetOnymousAttrName(cur->attr), 
		    xmlSchemaGetOnymousAttrName(tmp->attr))) &&
		    (xmlStrEqual(xmlSchemaGetOnymousTargetNsURI((xmlSchemaTypePtr) cur->attr ), 
		    xmlSchemaGetOnymousTargetNsURI((xmlSchemaTypePtr) tmp->attr)))) {
		    
		    xmlSchemaPErr(ctxt, cur->attr->node, XML_SCHEMAP_CT_PROPS_CORRECT_4,
			"ct-props-correct.4: Duplicate attribute use with the name \"%s\" specified\n",
			xmlSchemaGetOnymousAttrName(cur->attr),  NULL);
		    break;
		}
		tmp = tmp->next;
	    }
	    cur = cur->next;
	}
    }	
    if (type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION) {	
	/*
	 * Derive by restriction.
	 */
	if (baseIsAnyType) {
	    type->attributeUses = uses;
	} else {
	    int found;

	    cur = uses;
	    while (cur != NULL) {
		found = 0;
		base = type->attributeUses;
		while (base != NULL) {
		    if ((xmlStrEqual(xmlSchemaGetOnymousAttrName(cur->attr), 
			xmlSchemaGetOnymousAttrName(base->attr))) &&
			(xmlStrEqual(xmlSchemaGetOnymousTargetNsURI((xmlSchemaTypePtr) cur->attr), 
			xmlSchemaGetOnymousTargetNsURI((xmlSchemaTypePtr) base->attr)))) {
			
			found = 1;	    
			if ((cur->attr->occurs == XML_SCHEMAS_ATTR_USE_OPTIONAL) &&
			    (base->attr->occurs == XML_SCHEMAS_ATTR_USE_REQUIRED)) {
			    /*
			    * derivation-ok-restriction 2.1.1
			    */			
			    xmlSchemaPErr(ctxt, cur->attr->node, 
				XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1,
				"derivation-ok-restriction.2.1.1: "
				"The \"optional\" attribute "
				"use \"%s\" is inconsistent with a matching "
				"\"required\" attribute use of the base type\n",
				xmlSchemaGetOnymousAttrName(cur->attr), NULL);					
			} else if ((cur->attr->occurs == XML_SCHEMAS_ATTR_USE_PROHIBITED) &&
			    (base->attr->occurs == XML_SCHEMAS_ATTR_USE_REQUIRED)) {
			    /*
			    * derivation-ok-restriction 3 
			    */
			    xmlSchemaPErr(ctxt, cur->attr->node, XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3,
				"derivation-ok-restriction.3: "
				"The \"required\" attribute use \"%s\" of the base type "
				"does not have a matching attribute use in the derived type\n",		
				xmlSchemaGetOnymousAttrName(cur->attr), NULL);
			    
			} else {
			    /*
			    * Override the attribute use.
			    */
			    base->attr = cur->attr;
			}
			/*
			* TODO: derivation-ok-restriction  2.1.2 ({type definition} must be validly derived)
			*/
			break;
		    }				
		    base = base->next;
		}
		
		if (!found) {
		    if (cur->attr->occurs != XML_SCHEMAS_ATTR_USE_PROHIBITED) {
			/*
			* derivation-ok-restriction  2.2
			*/
			if ((type->attributeWildcard != NULL) &&
			    xmlSchemaMatchesWildcardNs(type->attributeWildcard,
				cur->attr->targetNamespace))
			    found = 1;

			if (!found) {
			    xmlSchemaPErr(ctxt, cur->attr->node, XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2,
				"derivation-ok-restriction.2.2: "
				"The attribute use \"%s\" has neither a matching attribute use, "
				"nor a matching wildcard in the base type\n",		
				xmlSchemaGetOnymousAttrName(cur->attr), NULL);
			} else {
			    /* 
			    * Add the attribute use.
			    *
			    * Note that this may lead to funny derivation error reports, if
			    * multiple equal attribute uses exist; but this is not
			    * allowed anyway, and it will be reported beforehand.
			    */
			    tmp = cur;
			    if (prev != NULL)
				prev->next = cur->next;
			    else 
				uses = cur->next;
			    cur = cur->next;    			
			    if (type->attributeUses == NULL) {
				type->attributeUses = tmp;
			    } else 
				lastBaseUse->next = tmp;
			    lastBaseUse = tmp;		
			    
			    continue;
			}
		    }
		}		    	    
		prev = cur;	
		cur = cur->next;
	    }
	    if (uses != NULL)
		xmlSchemaFreeAttributeUseList(uses);
	}
    } else if (type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) { 
	/*
	 * The spec allows only appending, and not other kinds of extensions.
	 *
	 * This ensures: Schema Component Constraint: Derivation Valid (Extension) : 1.2 
	 */
	if (uses != NULL) {
	    if (type->attributeUses == NULL) {
		type->attributeUses = uses;
	    } else 
		lastBaseUse->next = uses;
    }
    } else {
	/* 
	 * Derive implicitely from the ur-type.
	 */
	type->attributeUses = uses;
}
    /*
     * 3.4.6 -> Complex Type Definition Properties Correct
     */
    if (type->attributeUses != NULL) {
	cur = type->attributeUses;
	prev = NULL;
	while (cur != NULL) {
	    /*
	    * 4. Two distinct attribute declarations in the {attribute uses} must 
	    * not have identical {name}s and {target namespace}s.
 *
	    * Note that this was already done for "restriction" and types derived from
	    * the ur-type.
 */
	    if (type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) {
		tmp = cur->next;
		while (tmp != NULL) {	    
		    if ((xmlStrEqual(xmlSchemaGetOnymousAttrName(cur->attr), 
			xmlSchemaGetOnymousAttrName(tmp->attr))) &&
			(xmlStrEqual(xmlSchemaGetOnymousTargetNsURI((xmlSchemaTypePtr) cur->attr ), 
			xmlSchemaGetOnymousTargetNsURI((xmlSchemaTypePtr) tmp->attr)))) {

			xmlSchemaPErr(ctxt, cur->attr->node, XML_SCHEMAP_CT_PROPS_CORRECT_4,
			    "ct-props-correct.4: Duplicate attribute use with the name \"%s\" specified\n",
			    xmlSchemaGetOnymousAttrName(cur->attr),  NULL);
            break;
        }
		    tmp = tmp->next;
            }
        }
	    /*
	    * 5. Two distinct attribute declarations in the {attribute uses} must 
	    * not have {type definition}s which are or are derived from ID.
	    */
	    if ((cur->attr->subtypes != NULL) && 
		/*
		* TODO: FIXME: XML_SCHEMAS_ID should be used instead of "23" !!!, 
		* but the xmlSchemaValType is not made public yet.
		*/
		(xmlSchemaIsDerivedFromBuiltInType(ctxt, (xmlSchemaTypePtr) cur->attr, 23))) {
		if (id != NULL) {
		    xmlSchemaPErr(ctxt, cur->attr->node, XML_SCHEMAP_CT_PROPS_CORRECT_5, 
			"ct-props-correct.5: Two attribute declarations, "
			"\"%s\" and \"%s\" have types which derived from ID\n",
			xmlSchemaGetOnymousAttrName(id->attr), 
			xmlSchemaGetOnymousAttrName(cur->attr));
        } 
		id = cur;
	    }
	    /*
	    * Remove "prohibited" attribute uses. The reason this is done at this late 
	    * stage is to be able to catch dublicate attribute uses. So we had to keep
	    * prohibited uses in the list as well.
	    */
	    if (cur->attr->occurs == XML_SCHEMAS_ATTR_USE_PROHIBITED) {
		tmp = cur;
		if (prev == NULL)
		    type->attributeUses = cur->next;
		else
		    prev->next = cur->next;
		cur = cur->next;
        xmlFree(tmp);
	    } else {
		prev = cur;
		cur = cur->next;
	    }
	}    
    }
    /*	
     * TODO: This check should be removed if we are 100% sure of
     * the base type attribute uses already being built.
     */
    if ((baseType != NULL) && (!baseIsAnyType) &&
	(baseType->type == XML_SCHEMA_TYPE_COMPLEX) &&
	(baseType->contentType == XML_SCHEMA_CONTENT_UNKNOWN)) {
	xmlSchemaPErr(ctxt, baseType->node, XML_SCHEMAS_ERR_INTERNAL,
	    "Internal error: xmlSchemaParseBuildAttributeUses: "
	    "attribute uses not builded on base type \"%s\".\n",
	    baseType->name, NULL);
    }    
    return (0);
}

/**
 * xmlSchemaTypeFixup:
 * @typeDecl:  the schema type definition
 * @ctxt:  the schema parser context
 *
 * Fixes the content model of the type.
 */
static void
xmlSchemaTypeFixup(xmlSchemaTypePtr typeDecl,
                   xmlSchemaParserCtxtPtr ctxt, const xmlChar * name)
{
    if (typeDecl == NULL)
        return;
    if (name == NULL)
        name = typeDecl->name;
    if (typeDecl->contentType == XML_SCHEMA_CONTENT_UNKNOWN) {
        switch (typeDecl->type) {
            case XML_SCHEMA_TYPE_SIMPLE_CONTENT:{
                    xmlSchemaTypeFixup(typeDecl->subtypes, ctxt, NULL);
                    if (typeDecl->subtypes != NULL)
                        typeDecl->contentType =
                            typeDecl->subtypes->contentType;
                    break;
                }
            case XML_SCHEMA_TYPE_RESTRICTION:{
                    if (typeDecl->subtypes != NULL)
                        xmlSchemaTypeFixup(typeDecl->subtypes, ctxt, NULL);

                    if (typeDecl->base != NULL) {
                        xmlSchemaTypePtr baseType;

                        baseType =
                            xmlSchemaGetType(ctxt->schema, typeDecl->base,
                                             typeDecl->baseNs);
                        if (baseType == NULL) {
			    xmlSchemaPErr(ctxt, typeDecl->node,
			                  XML_SCHEMAP_UNKNOWN_BASE_TYPE,
				"Schemas: type %s base type %s not found\n",
                                          name, typeDecl->base);
                        } else if (baseType->contentType == 
			    XML_SCHEMA_CONTENT_UNKNOWN) {
			    /* 
			     * The base type might be not "type fixed" yet,
			     * so do it now. */
			    /* 
			     * TODO: Is a check for circular derivation already
			     * done?
			     */
			    xmlSchemaTypeFixup(baseType, ctxt, NULL);
                        }
                        typeDecl->baseType = baseType;
                    }
		    if (typeDecl->subtypes == NULL)
			if (typeDecl->baseType != NULL) {
			    typeDecl->contentType =
			             typeDecl->baseType->contentType;
			} else 
                            /* 1.1.1 */
                            typeDecl->contentType = XML_SCHEMA_CONTENT_EMPTY;
                    else if ((typeDecl->subtypes->subtypes == NULL) &&
                             ((typeDecl->subtypes->type ==
                               XML_SCHEMA_TYPE_ALL)
                              || (typeDecl->subtypes->type ==
                                  XML_SCHEMA_TYPE_SEQUENCE)))
                        /* 1.1.2 */
                        typeDecl->contentType = XML_SCHEMA_CONTENT_EMPTY;
                    else if ((typeDecl->subtypes->type ==
                              XML_SCHEMA_TYPE_CHOICE)
                             && (typeDecl->subtypes->subtypes == NULL))
                        /* 1.1.3 */
                        typeDecl->contentType = XML_SCHEMA_CONTENT_EMPTY;
                    else {
                        /* 1.2 and 2.X are applied at the other layer */
                        typeDecl->contentType =
                            XML_SCHEMA_CONTENT_ELEMENTS;
                    }
                    break;
                }
            case XML_SCHEMA_TYPE_EXTENSION:{
                    xmlSchemaContentType explicitContentType;
                    xmlSchemaTypePtr base;

                    if (typeDecl->base != NULL) {
                        xmlSchemaTypePtr baseType;

                        baseType =
                            xmlSchemaGetType(ctxt->schema, typeDecl->base,
                                             typeDecl->baseNs);
                        if (baseType == NULL) {
			    xmlSchemaPErr(ctxt, typeDecl->node,
			                  XML_SCHEMAP_UNKNOWN_BASE_TYPE,
				"Schemas: type %s base type %s not found\n",
                                          name, typeDecl->base);
                        } else if (baseType->contentType == 
			    XML_SCHEMA_CONTENT_UNKNOWN) {
			    /* 
			     * The base type might be not "type fixed" yet,
			     * so do it now. */
			    /* 
			     * TODO: Is a check for circular derivation already
			     * done?
			     */
			    xmlSchemaTypeFixup(baseType, ctxt, NULL);
                        }
                        typeDecl->baseType = baseType;
                    }
                    if (typeDecl->subtypes != NULL)
                        xmlSchemaTypeFixup(typeDecl->subtypes, ctxt, NULL);

                    explicitContentType = XML_SCHEMA_CONTENT_ELEMENTS;
                    if (typeDecl->subtypes == NULL)
                        /* 1.1.1 */
                        explicitContentType = XML_SCHEMA_CONTENT_EMPTY;
                    else if ((typeDecl->subtypes->subtypes == NULL) &&
                             ((typeDecl->subtypes->type ==
                               XML_SCHEMA_TYPE_ALL)
                              || (typeDecl->subtypes->type ==
                                  XML_SCHEMA_TYPE_SEQUENCE)))
                        /* 1.1.2 */
                        explicitContentType = XML_SCHEMA_CONTENT_EMPTY;
                    else if ((typeDecl->subtypes->type ==
                              XML_SCHEMA_TYPE_CHOICE)
                             && (typeDecl->subtypes->subtypes == NULL))
                        /* 1.1.3 */
                        explicitContentType = XML_SCHEMA_CONTENT_EMPTY;

                    base = xmlSchemaGetType(ctxt->schema, typeDecl->base,
                                            typeDecl->baseNs);
                    if (base == NULL) {
                        xmlSchemaPErr(ctxt, typeDecl->node,
                                      XML_SCHEMAP_UNKNOWN_BASE_TYPE,
                                      "Schemas: base type %s of type %s not found\n",
                                      typeDecl->base, name);
                        return;
                    }
                    if (typeDecl->recurse) {
			/* TODO: The word "recursive" should be changed to "circular" here. */
                        xmlSchemaPErr(ctxt, typeDecl->node,
                                      XML_SCHEMAP_UNKNOWN_BASE_TYPE,
				  "Schemas: extension type %s is recursive\n",
                                      name, NULL);
                        return;
		    }
		    typeDecl->recurse = 1;
                    xmlSchemaTypeFixup(base, ctxt, NULL);
		    typeDecl->recurse = 0;
                    if (explicitContentType == XML_SCHEMA_CONTENT_EMPTY) {
                        /* 2.1 */
                        typeDecl->contentType = base->contentType;
                    } else if (base->contentType ==
                               XML_SCHEMA_CONTENT_EMPTY) {
                        /* 2.2 imbitable ! */
                        typeDecl->contentType =
                            XML_SCHEMA_CONTENT_ELEMENTS;
                    } else {
                        /* 2.3 imbitable pareil ! */
                        typeDecl->contentType =
                            XML_SCHEMA_CONTENT_ELEMENTS;
                    }
                    break;
                }
            case XML_SCHEMA_TYPE_COMPLEX:{
                    if (typeDecl->subtypes == NULL) {
                        typeDecl->contentType = XML_SCHEMA_CONTENT_EMPTY;

                        if (typeDecl->flags & XML_SCHEMAS_TYPE_MIXED)
                            typeDecl->contentType =
                                XML_SCHEMA_CONTENT_MIXED;
                    } else {
                        if (typeDecl->flags & XML_SCHEMAS_TYPE_MIXED) {
                            typeDecl->contentType =
                                XML_SCHEMA_CONTENT_MIXED;
                        } else {
                            xmlSchemaTypeFixup(typeDecl->subtypes, ctxt,
                                               NULL);
                            if (typeDecl->subtypes != NULL)
                                typeDecl->contentType =
                                    typeDecl->subtypes->contentType;
                        }
			/* Evaluate the derivation method. */
			if ((typeDecl->subtypes != NULL) &&
			    ((typeDecl->subtypes->type == 
				XML_SCHEMA_TYPE_COMPLEX_CONTENT) ||
			    (typeDecl->subtypes->type == 
				XML_SCHEMA_TYPE_SIMPLE_CONTENT)) &&
			    (typeDecl->subtypes->subtypes != NULL)) {			    			    
			    if (typeDecl->subtypes->subtypes->type == 
				    XML_SCHEMA_TYPE_EXTENSION) {
				typeDecl->flags |= 
				    XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION;
			    } else if (typeDecl->subtypes->subtypes->type == 
				    XML_SCHEMA_TYPE_RESTRICTION) {
				typeDecl->flags |= 
				    XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION;
                    }
			}
                    }
		    xmlSchemaBuildAttributeValidation(ctxt, typeDecl);
                    break;
                }
            case XML_SCHEMA_TYPE_COMPLEX_CONTENT:{
                    if (typeDecl->subtypes == NULL) {
                        typeDecl->contentType = XML_SCHEMA_CONTENT_EMPTY;
                        if (typeDecl->flags & XML_SCHEMAS_TYPE_MIXED)
                            typeDecl->contentType =
                                XML_SCHEMA_CONTENT_MIXED;
                    } else {
                        if (typeDecl->flags & XML_SCHEMAS_TYPE_MIXED) {
                            typeDecl->contentType =
                                XML_SCHEMA_CONTENT_MIXED;
                        } else {
                            xmlSchemaTypeFixup(typeDecl->subtypes, ctxt,
                                               NULL);
                            if (typeDecl->subtypes != NULL)
                                typeDecl->contentType =
                                    typeDecl->subtypes->contentType;
                        }
			/* 
			 * Removed due to implementation of the build of attribute uses. 
			 */
			/*
			if (typeDecl->attributes == NULL)
			    typeDecl->attributes =
			        typeDecl->subtypes->attributes;
			*/
                    }
                    break;
                }
            case XML_SCHEMA_TYPE_SEQUENCE:
            case XML_SCHEMA_TYPE_GROUP:
            case XML_SCHEMA_TYPE_ALL:
            case XML_SCHEMA_TYPE_CHOICE:
                typeDecl->contentType = XML_SCHEMA_CONTENT_ELEMENTS;
                break;
            case XML_SCHEMA_TYPE_LIST:
		xmlSchemaParseListRefFixup(typeDecl, ctxt);
		/* no break on purpose */
            case XML_SCHEMA_TYPE_UNION:
		if (typeDecl->type == XML_SCHEMA_TYPE_UNION)
		    xmlSchemaParseUnionRefCheck(typeDecl, ctxt);
		/* no break on purpose */
            case XML_SCHEMA_TYPE_BASIC:
            case XML_SCHEMA_TYPE_ANY:
            case XML_SCHEMA_TYPE_FACET:
            case XML_SCHEMA_TYPE_SIMPLE:
            case XML_SCHEMA_TYPE_UR:
            case XML_SCHEMA_TYPE_ELEMENT:
            case XML_SCHEMA_TYPE_ATTRIBUTE:
            case XML_SCHEMA_TYPE_ATTRIBUTEGROUP:
            case XML_SCHEMA_TYPE_ANY_ATTRIBUTE:
            case XML_SCHEMA_TYPE_NOTATION:
            case XML_SCHEMA_FACET_MININCLUSIVE:
            case XML_SCHEMA_FACET_MINEXCLUSIVE:
            case XML_SCHEMA_FACET_MAXINCLUSIVE:
            case XML_SCHEMA_FACET_MAXEXCLUSIVE:
            case XML_SCHEMA_FACET_TOTALDIGITS:
            case XML_SCHEMA_FACET_FRACTIONDIGITS:
            case XML_SCHEMA_FACET_PATTERN:
            case XML_SCHEMA_FACET_ENUMERATION:
            case XML_SCHEMA_FACET_WHITESPACE:
            case XML_SCHEMA_FACET_LENGTH:
            case XML_SCHEMA_FACET_MAXLENGTH:
            case XML_SCHEMA_FACET_MINLENGTH:
                typeDecl->contentType = XML_SCHEMA_CONTENT_SIMPLE;
		if (typeDecl->subtypes != NULL)
		    xmlSchemaTypeFixup(typeDecl->subtypes, ctxt, NULL);
                break;
        }
    }
#ifdef DEBUG_TYPE
    if (typeDecl->node != NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "Type of %s : %s:%d :", name,
                        typeDecl->node->doc->URL,
                        xmlGetLineNo(typeDecl->node));
    } else {
        xmlGenericError(xmlGenericErrorContext, "Type of %s :", name);
    }
    switch (typeDecl->contentType) {
        case XML_SCHEMA_CONTENT_SIMPLE:
            xmlGenericError(xmlGenericErrorContext, "simple\n");
            break;
        case XML_SCHEMA_CONTENT_ELEMENTS:
            xmlGenericError(xmlGenericErrorContext, "elements\n");
            break;
        case XML_SCHEMA_CONTENT_UNKNOWN:
            xmlGenericError(xmlGenericErrorContext, "unknown !!!\n");
            break;
        case XML_SCHEMA_CONTENT_EMPTY:
            xmlGenericError(xmlGenericErrorContext, "empty\n");
            break;
        case XML_SCHEMA_CONTENT_MIXED:
            xmlGenericError(xmlGenericErrorContext, "mixed\n");
            break;
        case XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS:
            xmlGenericError(xmlGenericErrorContext, "mixed or elems\n");
            break;
        case XML_SCHEMA_CONTENT_BASIC:
            xmlGenericError(xmlGenericErrorContext, "basic\n");
            break;
        default:
            xmlGenericError(xmlGenericErrorContext,
                            "not registered !!!\n");
            break;
    }
#endif
}

/**
 * xmlSchemaCheckFacet:
 * @facet:  the facet
 * @typeDecl:  the schema type definition
 * @ctxt:  the schema parser context or NULL
 * @name: name of the type
 *
 * Checks the default values types, especially for facets 
 *
 * Returns 0 if okay or -1 in cae of error
 */
int
xmlSchemaCheckFacet(xmlSchemaFacetPtr facet,
                    xmlSchemaTypePtr typeDecl,
                    xmlSchemaParserCtxtPtr ctxt, const xmlChar * name)
{
    static xmlSchemaTypePtr nonNegativeIntegerType = NULL;
    int ret = 0;

    if (nonNegativeIntegerType == NULL) {
        nonNegativeIntegerType =
            xmlSchemaGetPredefinedType(BAD_CAST "nonNegativeInteger",
                                       xmlSchemaNs);
    }
    switch (facet->type) {
        case XML_SCHEMA_FACET_MININCLUSIVE:
        case XML_SCHEMA_FACET_MINEXCLUSIVE:
        case XML_SCHEMA_FACET_MAXINCLUSIVE:
        case XML_SCHEMA_FACET_MAXEXCLUSIVE:{
                /*
                 * Okay we need to validate the value
                 * at that point.
                 */
                xmlSchemaValidCtxtPtr vctxt;

                vctxt = xmlSchemaNewValidCtxt(NULL);
                if (vctxt == NULL)
                    break;
                xmlSchemaValidateSimpleValue(vctxt, typeDecl,
                                             facet->value);
                facet->val = vctxt->value;
                vctxt->value = NULL;
                if (facet->val == NULL) {
                    /* error code */
                    if (ctxt != NULL) {
                        xmlSchemaPErr(ctxt, facet->node,
                                      XML_SCHEMAP_INVALID_FACET,
                                      "Schemas: type %s facet value %s invalid\n",
                                      name, facet->value);
                    }
                    ret = -1;
                }
                xmlSchemaFreeValidCtxt(vctxt);
                break;
            }
        case XML_SCHEMA_FACET_ENUMERATION:{
                /*
                 * Okay we need to validate the value
                 * at that point.
                 */
                xmlSchemaValidCtxtPtr vctxt;
                int tmp;

                vctxt = xmlSchemaNewValidCtxt(NULL);
                if (vctxt == NULL)
                    break;
                tmp = xmlSchemaValidateSimpleValue(vctxt, typeDecl,
                                                   facet->value);
                if (tmp != 0) {
                    if (ctxt != NULL) {
                        xmlSchemaPErr(ctxt, facet->node,
                                      XML_SCHEMAP_INVALID_ENUM,
                                      "Schemas: type %s enumeration value %s invalid\n",
                                      name, facet->value);
                    }
                    ret = -1;
                }
                xmlSchemaFreeValidCtxt(vctxt);
                break;
            }
        case XML_SCHEMA_FACET_PATTERN:
            facet->regexp = xmlRegexpCompile(facet->value);
            if (facet->regexp == NULL) {
		xmlSchemaPErr(ctxt, typeDecl->node,
			      XML_SCHEMAP_REGEXP_INVALID,
                              "Schemas: type %s facet regexp %s invalid\n",
                              name, facet->value);
                ret = -1;
            }
            break;
        case XML_SCHEMA_FACET_TOTALDIGITS:
        case XML_SCHEMA_FACET_FRACTIONDIGITS:
        case XML_SCHEMA_FACET_LENGTH:
        case XML_SCHEMA_FACET_MAXLENGTH:
        case XML_SCHEMA_FACET_MINLENGTH:{
                int tmp;

                tmp =
                    xmlSchemaValidatePredefinedType(nonNegativeIntegerType,
                                                    facet->value,
                                                    &facet->val);
                if (tmp != 0) {
                    /* error code */
                    if (ctxt != NULL) {
                        xmlSchemaPErr(ctxt, facet->node,
                                      XML_SCHEMAP_INVALID_FACET_VALUE,
                                      "Schemas: type %s facet value %s invalid\n",
                                      name, facet->value);
                    }
                    ret = -1;
                }
                break;
            }
        case XML_SCHEMA_FACET_WHITESPACE:{
                if (xmlStrEqual(facet->value, BAD_CAST "preserve")) {
                    facet->whitespace = XML_SCHEMAS_FACET_PRESERVE;
                } else if (xmlStrEqual(facet->value, BAD_CAST "replace")) {
                    facet->whitespace = XML_SCHEMAS_FACET_REPLACE;
                } else if (xmlStrEqual(facet->value, BAD_CAST "collapse")) {
                    facet->whitespace = XML_SCHEMAS_FACET_COLLAPSE;
                } else {
                    if (ctxt != NULL) {
                        xmlSchemaPErr(ctxt, facet->node,
                                      XML_SCHEMAP_INVALID_WHITE_SPACE,
                                      "Schemas: type %s whiteSpace value %s invalid\n",
                                      name, facet->value);
                    }
                    ret = -1;
                }
            }
        default:
            break;
    }
    return (ret);
}

/**
 * xmlSchemaCheckDefaults:
 * @typeDecl:  the schema type definition
 * @ctxt:  the schema parser context
 *
 * Checks the default values types, especially for facets 
 */
static void
xmlSchemaCheckDefaults(xmlSchemaTypePtr typeDecl,
                       xmlSchemaParserCtxtPtr ctxt, const xmlChar * name)
{
    if (name == NULL)
        name = typeDecl->name;
    if (typeDecl->type == XML_SCHEMA_TYPE_RESTRICTION) {
        if (typeDecl->facets != NULL) {
            xmlSchemaFacetPtr facet = typeDecl->facets;

            while (facet != NULL) {
                xmlSchemaCheckFacet(facet, typeDecl, ctxt, name);
                facet = facet->next;
            }
        }
    }
}

/**
 * xmlSchemaAttrGrpFixup:
 * @attrgrpDecl:  the schema attribute definition
 * @ctxt:  the schema parser context
 * @name:  the attribute name
 *
 * Fixes finish doing the computations on the attributes definitions
 */
static void
xmlSchemaAttrGrpFixup(xmlSchemaAttributeGroupPtr attrgrp,
                      xmlSchemaParserCtxtPtr ctxt, const xmlChar * name)
{
    if (name == NULL)
        name = attrgrp->name;
    if (attrgrp->attributes != NULL)
        return;
    if (attrgrp->ref != NULL) {
        xmlSchemaAttributeGroupPtr ref;

        ref = xmlSchemaGetAttributeGroup(ctxt->schema, attrgrp->ref, attrgrp->refNs);
        if (ref == NULL) {
            xmlSchemaPErr(ctxt, attrgrp->node,
                          XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP,
                          "Schemas: attribute group %s reference %s not found\n",
                          name, attrgrp->ref);
            return;
        }
        xmlSchemaAttrGrpFixup(ref, ctxt, NULL);
        attrgrp->attributes = ref->attributes;
	attrgrp->attributeWildcard = ref->attributeWildcard;
    }
    /* 
    * Removed, since a global attribute group does not need to hold any
    * attributes or wildcard 
    */
    /*
    else {
        xmlSchemaPErr(ctxt, attrgrp->node, XML_SCHEMAP_NOATTR_NOREF,
                      "Schemas: attribute group %s has no attributes nor reference\n",
                      name, NULL);
    }
    */
}

/**
 * xmlSchemaAttrFixup:
 * @attrDecl:  the schema attribute definition
 * @ctxt:  the schema parser context
 * @name:  the attribute name
 *
 * Fixes finish doing the computations on the attributes definitions
 */
static void
xmlSchemaAttrFixup(xmlSchemaAttributePtr attrDecl,
                   xmlSchemaParserCtxtPtr ctxt, const xmlChar * name)
{
    if (name == NULL)
        name = attrDecl->name;
    if (attrDecl->subtypes != NULL)
        return;
    if (attrDecl->typeName != NULL) {
        xmlSchemaTypePtr type;

        type = xmlSchemaGetType(ctxt->schema, attrDecl->typeName,
                                attrDecl->typeNs);
        if (type == NULL) {
            xmlSchemaPErr(ctxt, attrDecl->node, XML_SCHEMAP_UNKNOWN_TYPE,
                          "Schemas: attribute %s type %s not found\n",
                          name, attrDecl->typeName);
        }
        attrDecl->subtypes = type;
    } else if (attrDecl->ref != NULL) {
        xmlSchemaAttributePtr ref;

	ref = xmlSchemaGetAttribute(ctxt->schema, attrDecl->ref, attrDecl->refNs);
        if (ref == NULL) {
            xmlSchemaPErr(ctxt, attrDecl->node, XML_SCHEMAP_UNKNOWN_REF,
                          "Schemas: attribute %s reference %s not found\n",
                          name, attrDecl->ref);
            return;
        }
        xmlSchemaAttrFixup(ref, ctxt, NULL);
        attrDecl->subtypes = ref->subtypes;
    } else {
        xmlSchemaPErr(ctxt, attrDecl->node, XML_SCHEMAP_NOTYPE_NOREF,
                      "Schemas: attribute %s has no type nor reference\n",
                      name, NULL);
    }
}

/**
 * xmlSchemaParse:
 * @ctxt:  a schema validation context
 *
 * parse a schema definition resource and build an internal
 * XML Shema struture which can be used to validate instances.
 * *WARNING* this interface is highly subject to change
 *
 * Returns the internal XML Schema structure built from the resource or
 *         NULL in case of error
 */
xmlSchemaPtr
xmlSchemaParse(xmlSchemaParserCtxtPtr ctxt)
{
    xmlSchemaPtr ret = NULL;
    xmlDocPtr doc;
    xmlNodePtr root;
    int nberrors;
    int preserve = 0;

    xmlSchemaInitTypes();

    if (ctxt == NULL)
        return (NULL);

    nberrors = ctxt->nberrors;
    ctxt->nberrors = 0;
    ctxt->counter = 0;
    ctxt->container = NULL;

    /*
     * First step is to parse the input document into an DOM/Infoset
     */
    if (ctxt->URL != NULL) {
        doc = xmlReadFile((const char *) ctxt->URL, NULL, 
	                  SCHEMAS_PARSE_OPTIONS);
        if (doc == NULL) {
	    xmlSchemaPErr(ctxt, NULL,
			  XML_SCHEMAP_FAILED_LOAD,
                          "xmlSchemaParse: could not load %s\n",
                          ctxt->URL, NULL);
            return (NULL);
        }
    } else if (ctxt->buffer != NULL) {
        doc = xmlReadMemory(ctxt->buffer, ctxt->size, NULL, NULL,
	                    SCHEMAS_PARSE_OPTIONS);
        if (doc == NULL) {
	    xmlSchemaPErr(ctxt, NULL,
			  XML_SCHEMAP_FAILED_PARSE,
                          "xmlSchemaParse: could not parse\n",
                          NULL, NULL);
            return (NULL);
        }
        doc->URL = xmlStrdup(BAD_CAST "in_memory_buffer");
        ctxt->URL = xmlDictLookup(ctxt->dict, BAD_CAST "in_memory_buffer", -1);
    } else if (ctxt->doc != NULL) {
        doc = ctxt->doc;
	preserve = 1;
    } else {
	xmlSchemaPErr(ctxt, NULL,
		      XML_SCHEMAP_NOTHING_TO_PARSE,
		      "xmlSchemaParse: could not parse\n",
		      NULL, NULL);
        return (NULL);
    }

    /*
     * Then extract the root and Schema parse it
     */
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) doc,
		      XML_SCHEMAP_NOROOT,
		      "schemas has no root", NULL, NULL);
	if (!preserve) {
	    xmlFreeDoc(doc);
	}
        return (NULL);
    }

    /*
     * Remove all the blank text nodes
     */
    xmlSchemaCleanupDoc(ctxt, root);

    /*
     * Then do the parsing for good
     */
    ret = xmlSchemaParseSchema(ctxt, root);
    if (ret == NULL) {
        if (!preserve) {
	    xmlFreeDoc(doc);
	}
        return (NULL);
    }
    ret->doc = doc;
    ret->preserve = preserve;

    /*
     * Then fix all the references.
     */
    ctxt->schema = ret;
    xmlHashScanFull(ret->elemDecl,
                    (xmlHashScannerFull) xmlSchemaRefFixupCallback, ctxt);

    /*
     * Then fixup all attributes declarations
     */
    xmlHashScan(ret->attrDecl, (xmlHashScanner) xmlSchemaAttrFixup, ctxt);

    /*
     * Then fixup all attributes group declarations
     */
    xmlHashScan(ret->attrgrpDecl, (xmlHashScanner) xmlSchemaAttrGrpFixup,
                ctxt);

    /*
     * Then fixup all types properties
     */
    xmlHashScan(ret->typeDecl, (xmlHashScanner) xmlSchemaTypeFixup, ctxt);

    /*
     * Then build the content model for all elements
     */
    xmlHashScan(ret->elemDecl,
                (xmlHashScanner) xmlSchemaBuildContentModel, ctxt);

    /*
     * Then check the defaults part of the type like facets values
     */
    xmlHashScan(ret->typeDecl, (xmlHashScanner) xmlSchemaCheckDefaults,
                ctxt);

    if (ctxt->nberrors != 0) {
        xmlSchemaFree(ret);
        ret = NULL;
    }
    return (ret);
}

/**
 * xmlSchemaSetParserErrors:
 * @ctxt:  a schema validation context
 * @err:  the error callback
 * @warn:  the warning callback
 * @ctx:  contextual data for the callbacks
 *
 * Set the callback functions used to handle errors for a validation context
 */
void
xmlSchemaSetParserErrors(xmlSchemaParserCtxtPtr ctxt,
                         xmlSchemaValidityErrorFunc err,
                         xmlSchemaValidityWarningFunc warn, void *ctx)
{
    if (ctxt == NULL)
        return;
    ctxt->error = err;
    ctxt->warning = warn;
    ctxt->userData = ctx;
}

/**
 * xmlSchemaFacetTypeToString:
 * @type:  the facet type
 *
 * Convert the xmlSchemaTypeType to a char string.
 *
 * Returns the char string representation of the facet type if the
 *     type is a facet and an "Internal Error" string otherwise.
 */
static const char *
xmlSchemaFacetTypeToString(xmlSchemaTypeType type)
{
    switch (type) {
        case XML_SCHEMA_FACET_PATTERN:
            return ("pattern");
        case XML_SCHEMA_FACET_MAXEXCLUSIVE:
            return ("maxExclusive");
        case XML_SCHEMA_FACET_MAXINCLUSIVE:
            return ("maxInclusive");
        case XML_SCHEMA_FACET_MINEXCLUSIVE:
            return ("minExclusive");
        case XML_SCHEMA_FACET_MININCLUSIVE:
            return ("minInclusive");
        case XML_SCHEMA_FACET_WHITESPACE:
            return ("whiteSpace");
        case XML_SCHEMA_FACET_ENUMERATION:
            return ("enumeration");
        case XML_SCHEMA_FACET_LENGTH:
            return ("length");
        case XML_SCHEMA_FACET_MAXLENGTH:
            return ("maxLength");
        case XML_SCHEMA_FACET_MINLENGTH:
            return ("minLength");
        case XML_SCHEMA_FACET_TOTALDIGITS:
            return ("totalDigits");
        case XML_SCHEMA_FACET_FRACTIONDIGITS:
            return ("fractionDigits");
        default:
            break;
    }
    return ("Internal Error");
}

/**
 * xmlSchemaValidateFacetsInternal:
 * @ctxt:  a schema validation context
 * @base:  the base type
 * @facets:  the list of facets to check
 * @value:  the lexical repr of the value to validate
 * @val:  the precomputed value
 * @fireErrors:  if 0, only internal errors will be fired;
 *		 otherwise all errors will be fired.
 *
 * Check a value against all facet conditions
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateFacetsInternal(xmlSchemaValidCtxtPtr ctxt,
                        xmlSchemaTypePtr base,
                        xmlSchemaFacetPtr facets,
			const xmlChar * value, int fireErrors)
{
    int ret = 0;
    int tmp = 0;
    xmlSchemaTypeType type;
    xmlSchemaFacetPtr facet = facets;

    while (facet != NULL) {
        type = facet->type;
        if (type == XML_SCHEMA_FACET_ENUMERATION) {
            tmp = 1;

            while (facet != NULL) {
                tmp =
                    xmlSchemaValidateFacet(base, facet, value,
                                           ctxt->value);
                if (tmp == 0) {
                    return 0;
                }
                facet = facet->next;
            }
        } else
            tmp = xmlSchemaValidateFacet(base, facet, value, ctxt->value);

        if (tmp != 0) {
            ret = tmp;
            if (fireErrors)
                xmlSchemaVErr(ctxt, ctxt->cur, XML_SCHEMAS_ERR_FACET,
			      "Failed to validate type with facet %s\n",
			      (const xmlChar *) xmlSchemaFacetTypeToString(type),
			      NULL);
        }
        if (facet != NULL)
            facet = facet->next;
    }
    return (ret);
}

/**
 * xmlSchemaValidateFacets:
 * @ctxt:  a schema validation context
 * @base:  the base type
 * @facets:  the list of facets to check
 * @value:  the lexical repr of the value to validate
 * @val:  the precomputed value
 *
 * Check a value against all facet conditions
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateFacets(xmlSchemaValidCtxtPtr ctxt,
                        xmlSchemaTypePtr base,
                        xmlSchemaFacetPtr facets, const xmlChar * value)
{
    return(xmlSchemaValidateFacetsInternal(ctxt, base, facets, value, 1));
}

/************************************************************************
 * 									*
 * 			Simple type validation				*
 * 									*
 ************************************************************************/

/**
 * xmlSchemaValidateSimpleValueUnion:
 * @ctxt:  a schema validation context
 * @type:  the type declaration
 * @value:  the value to validate
 *
 * Validates a value against a union.
 *
 * Returns 0 if the value is valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateSimpleValueUnion(xmlSchemaValidCtxtPtr ctxt,
                             xmlSchemaTypePtr type, const xmlChar * value)
{
    int ret = 0;
    const xmlChar *cur, *end, *prefix, *ncName;
    xmlChar *tmp;
    xmlSchemaTypePtr subtype;
    xmlNsPtr ns;
    int len;
   

    /* Process referenced memberTypes. */
    cur = type->ref;
    do {
        while (IS_BLANK_CH(*cur))
            cur++;
        end = cur;
        while ((*end != 0) && (!(IS_BLANK_CH(*end))))
            end++;
        if (end == cur)
            break;
        tmp = xmlStrndup(cur, end - cur);
         ncName = xmlSplitQName3(tmp, &len);
        if (ncName != NULL) {
            prefix = xmlStrndup(tmp, len);
            /* prefix = xmlDictLookup(ctxt->doc->dict, tmp, len); */
        } else {
            prefix = NULL;
            ncName = tmp;
        }
        /* We won't do additional checks here,
	 * since they have been performed during parsing. */
        ns = xmlSearchNs(type->node->doc, type->node, prefix);
        /* namespace = xmlDictLookup(ctxt->doc->dict, ns->href, -1); */
        subtype = xmlSchemaGetType(ctxt->schema, ncName, ns->href);
	if (tmp != NULL)
	    xmlFree(tmp);
	if (prefix != NULL)
	    xmlFree((void *)prefix);
        ret = xmlSchemaValidateSimpleValueInternal(ctxt, subtype, value, 0);
        if ((ret == 0) || (ret == -1)) {
            return (ret);
        }
        cur = end;
    } while (*cur != 0);

    if (type->subtypes != NULL) {
        subtype = type->subtypes;
        do {
            ret = xmlSchemaValidateSimpleValueInternal(ctxt, subtype, value, 0);
            if ((ret == 0) || (ret == -1)) {
                return (ret);
            }
            subtype = subtype->next;
        } while (subtype != NULL);
    }
    return (ret);
}

/**
 * xmlSchemaValidateSimpleValue:
 * @ctxt:  a schema validation context
 * @type:  the type declaration
 * @value:  the value to validate
 *
 * Validate a value against a simple type
 *
 * Returns 0 if the value is valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateSimpleValue(xmlSchemaValidCtxtPtr ctxt,
                             xmlSchemaTypePtr type, const xmlChar * value)
{
  return (xmlSchemaValidateSimpleValueInternal(ctxt, type, value, 1));
}

/**
 * xmlSchemaValidateSimpleValue:
 * @ctxt:  a schema validation context
 * @type:  the type declaration
 * @value:  the value to validate
 * @fireErrors:  if 0, only internal errors will be fired;
 *		 otherwise all errors will be fired.
 *
 * Validate a value against a simple type
 *
 * Returns 0 if the value is valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateSimpleValueInternal(xmlSchemaValidCtxtPtr ctxt,
                             xmlSchemaTypePtr type,
			     const xmlChar * value,
			     int fireErrors)
{
    int ret = 0;

    /*
     * First normalize the value accordingly to Schema Datatype
     * 4.3.6 whiteSpace definition of the whiteSpace facet of type
     *
     * Then check the normalized value against the lexical space of the
     * type.
     */
    if (type->type == XML_SCHEMA_TYPE_BASIC) {
        if (ctxt->value != NULL) {
            xmlSchemaFreeValue(ctxt->value);
            ctxt->value = NULL;
        }
        ret = xmlSchemaValPredefTypeNode(type, value, &(ctxt->value),
                                         ctxt->cur);
        if ((fireErrors) && (ret != 0)) {
            xmlSchemaVErr(ctxt, ctxt->cur, XML_SCHEMAS_ERR_VALUE,
	    		  "Failed to validate basic type %s\n",
			  type->name, NULL);
        }
    } else if (type->type == XML_SCHEMA_TYPE_RESTRICTION) {
        xmlSchemaTypePtr base;
        xmlSchemaFacetPtr facet;

        base = type->baseType;
        if (base != NULL) {
            ret = xmlSchemaValidateSimpleValueInternal(ctxt, base,
	    			value, fireErrors);
        } else if (type->subtypes != NULL) {
	    TODO
        }

        /*
         * Do not validate facets or attributes when working on
	 * building the Schemas
         */
        if (ctxt->schema != NULL) {
            if (ret == 0) {
                facet = type->facets;
                ret = xmlSchemaValidateFacetsInternal(ctxt, base, facet,
				value, fireErrors);
            }
        }
    } else if (type->type == XML_SCHEMA_TYPE_SIMPLE) {
        xmlSchemaTypePtr base;

        base = type->subtypes;
        if (base != NULL) {
            ret = xmlSchemaValidateSimpleValueInternal(ctxt, base,
	    			value, fireErrors);
        } else {
        TODO}
    } else if (type->type == XML_SCHEMA_TYPE_LIST) {
        xmlSchemaTypePtr base;
        const xmlChar *cur, *end;
	xmlChar *tmp;
        int ret2;

        base = type->subtypes;
        if (base == NULL) {
	    xmlSchemaVErr(ctxt, type->node, XML_SCHEMAS_ERR_INTERNAL,
			"Internal: List type %s has no base type\n",
			type->name, NULL);
            return (-1);
        }
        cur = value;
        do {
            while (IS_BLANK_CH(*cur))
                cur++;
            end = cur;
            while ((*end != 0) && (!(IS_BLANK_CH(*end))))
                end++;
            if (end == cur)
                break;
            tmp = xmlStrndup(cur, end - cur);
            ret2 = xmlSchemaValidateSimpleValueInternal(ctxt, base,
	    			tmp, fireErrors);
	    xmlFree(tmp);
            if (ret2 != 0)
                ret = 1;
            cur = end;
        } while (*cur != 0);
    }  else if (type->type == XML_SCHEMA_TYPE_UNION) {
        ret = xmlSchemaValidateSimpleValueUnion(ctxt, type, value);
        if ((fireErrors) && (ret != 0)) {
            xmlSchemaVErr(ctxt, ctxt->cur, XML_SCHEMAS_ERR_VALUE,
	    		  "Failed to validate type %s\n", type->name, NULL);
        }
    } else {
        TODO
    }
    return (ret);
}

/************************************************************************
 * 									*
 * 			DOM Validation code				*
 * 									*
 ************************************************************************/

static int xmlSchemaValidateContent(xmlSchemaValidCtxtPtr ctxt,
                                    xmlNodePtr node);
static int xmlSchemaValidateAttributes(xmlSchemaValidCtxtPtr ctxt,
                                       xmlNodePtr elem,
                                       xmlSchemaTypePtr type);
static int xmlSchemaValidateType(xmlSchemaValidCtxtPtr ctxt,
                                 xmlNodePtr elem,
                                 xmlSchemaElementPtr elemDecl,
                                 xmlSchemaTypePtr type);


/**
 * xmlSchemaFreeAttrStates:
 * @state:  a list of attribute states
 *
 * Free the given list of attribute states
 *
 */
static void
xmlSchemaFreeAttributeStates(xmlSchemaAttrStatePtr state)
{
    xmlSchemaAttrStatePtr tmp;
    while (state != NULL) {
	tmp = state;
	state = state->next;	
	xmlFree(tmp);
    }
}

/**
 * xmlSchemaRegisterAttributes:
 * @ctxt:  a schema validation context
 * @attrs:  a list of attributes
 *
 * Register the list of attributes as the set to be validated on that element
 *
 * Returns -1 in case of error, 0 otherwise
 */
static int
xmlSchemaRegisterAttributes(xmlSchemaValidCtxtPtr ctxt, xmlAttrPtr attrs)
{
    xmlSchemaAttrStatePtr tmp;

    ctxt->attr = NULL;
    ctxt->attrTop = NULL;
    while (attrs != NULL) {
        if ((attrs->ns != NULL) &&
            (xmlStrEqual(attrs->ns->href, xmlSchemaInstanceNs))) {
            attrs = attrs->next;
            continue;
        }
            tmp = (xmlSchemaAttrStatePtr)
	       xmlMalloc(sizeof(xmlSchemaAttrState));
            if (tmp == NULL) {
                xmlSchemaVErrMemory(ctxt, "registering attributes", NULL);
                return (-1);
            }
	tmp->attr = attrs;
	tmp->state = XML_SCHEMAS_ATTR_UNKNOWN;
	tmp->next = NULL;
	if (ctxt->attr == NULL) 
            ctxt->attr = tmp;
	else
	    ctxt->attrTop->next = tmp;
	ctxt->attrTop = tmp;
        attrs = attrs->next;
    }
    return (0);
}

/**
 * xmlSchemaCheckAttributes:
 * @ctxt:  a schema validation context
 * @node:  the node carrying it.
 *
 * Check that the registered set of attributes on the current node
 * has been properly validated.
 *
 * Returns 0 if validity constraints are met, 1 otherwise.
 */
static int
xmlSchemaCheckAttributes(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node)
{
    int ret = 0;
    xmlSchemaAttrStatePtr cur;    

    cur = ctxt->attr;
    while ((cur != NULL) && (cur != ctxt->attrTop->next)) {
	if (cur->state != XML_SCHEMAS_ATTR_CHECKED) {	    	    
            ret = 1;
	    if (cur->state == XML_SCHEMAS_ATTR_UNKNOWN)
            xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_ATTRUNKNOWN,
	    		  "Attribute %s on %s is unknown\n",
		    cur->attr->name, node->name);
	    else if (cur->state == XML_SCHEMAS_ATTR_PROHIBITED)
		xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_ATTRUNKNOWN,
		    "Attribute %s on %s is prohibited\n",
		    cur->attr->name, node->name);
	    else if (cur->state == XML_SCHEMAS_ATTR_INVALID_VALUE)
		xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_ATTRINVALID,
		    "Attribute %s on %s does not match type\n",
		    cur->attr->name, node->name);
	    else if (cur->state == XML_SCHEMAS_ATTR_MISSING) {
		if (cur->decl->ref != NULL)
		    xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_MISSING,
			"Attribute %s on %s is required but missing\n", 
			cur->decl->ref, node->name);
		else
		    xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_MISSING,
			"Attribute %s on %s is required but missing\n", 
			cur->decl->name, node->name);
        }
    }
	cur = cur->next;
    }

    return (ret);
}

#if 0		/* Not currently used - remove if ever needed */
/**
 * xmlSchemaValidateSimpleContent:
 * @ctxt:  a schema validation context
 * @elem:  an element
 * @type:  the type declaration
 *
 * Validate the content of an element expected to be a simple type
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateSimpleContent(xmlSchemaValidCtxtPtr ctxt,
                               xmlNodePtr node ATTRIBUTE_UNUSED)
{
    xmlNodePtr child;
    xmlSchemaTypePtr type, base;
    xmlChar *value;
    int ret = 0;

    child = ctxt->node;
    type = ctxt->type;

    /*
     * Validation Rule: Element Locally Valid (Type): 3.1.3
     */
    value = xmlNodeGetContent(child);
    /* xmlSchemaValidateSimpleValue(ctxt, type, value); */
    switch (type->type) {
        case XML_SCHEMA_TYPE_RESTRICTION:{
                xmlSchemaFacetPtr facet;

                base = type->baseType;
                if (base != NULL) {
                    ret = xmlSchemaValidateSimpleValue(ctxt, base, value);
                } else {
                TODO}
                if (ret == 0) {
                    facet = type->facets;
                    ret =
                        xmlSchemaValidateFacets(ctxt, base, facet, value);
                }
		/* 
		 * This should attempt to validate the attributes even
		 * when validation of the value failed.
		 */
		/*
		if (type->attributes != NULL) {
		    ret = xmlSchemaValidateAttributes(ctxt, node,
		                                      type->attributes);
		}
		*/
                break;
            }
        case XML_SCHEMA_TYPE_EXTENSION:{
	        TODO
                break;
            }
        default:
	    TODO
    }
    if (value != NULL)
        xmlFree(value);

    return (ret);
}
#endif

/**
 * xmlSchemaValidateCheckNodeList
 * @nodelist: the list of nodes
 *
 * Check the node list is only made of text nodes and entities pointing
 * to text nodes
 *
 * Returns 1 if true, 0 if false and -1 in case of error
 */
static int
xmlSchemaValidateCheckNodeList(xmlNodePtr nodelist)
{
    while (nodelist != NULL) {
        if (nodelist->type == XML_ENTITY_REF_NODE) {
            TODO                /* implement recursion in the entity content */
        }
        if ((nodelist->type != XML_TEXT_NODE) &&
            (nodelist->type != XML_COMMENT_NODE) &&
            (nodelist->type != XML_PI_NODE) &&
            (nodelist->type != XML_CDATA_SECTION_NODE)) {
            return (0);
        }
        nodelist = nodelist->next;
    }
    return (1);
}

/**
 * xmlSchemaSkipIgnored:
 * @ctxt:  a schema validation context
 * @type:  the current type context
 * @node:  the top node.
 *
 * Skip ignorable nodes in that context
 *
 * Returns the new sibling
 *     number otherwise and -1 in case of internal or API error.
 */
static xmlNodePtr
xmlSchemaSkipIgnored(xmlSchemaValidCtxtPtr ctxt ATTRIBUTE_UNUSED,
                     xmlSchemaTypePtr type, xmlNodePtr node)
{
    int mixed = 0;

    /*
     * TODO complete and handle entities
     */
    mixed = ((type->contentType == XML_SCHEMA_CONTENT_MIXED) ||
             (type->contentType == XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS));
    while ((node != NULL) &&
           ((node->type == XML_COMMENT_NODE) ||
            ((mixed == 1) && (node->type == XML_TEXT_NODE)) ||
            (((type->contentType == XML_SCHEMA_CONTENT_ELEMENTS) &&
              (node->type == XML_TEXT_NODE) && (IS_BLANK_NODE(node)))))) {
        node = node->next;
    }
    return (node);
}

/**
 * xmlSchemaValidateCallback:
 * @ctxt:  a schema validation context
 * @name:  the name of the element detected (might be NULL)
 * @type:  the type
 *
 * A transition has been made in the automata associated to an element
 * content model
 */
static void
xmlSchemaValidateCallback(xmlSchemaValidCtxtPtr ctxt,
                          const xmlChar * name ATTRIBUTE_UNUSED,
                          xmlSchemaTypePtr type, xmlNodePtr node)
{
    xmlSchemaTypePtr oldtype = ctxt->type;
    xmlNodePtr oldnode = ctxt->node;

#ifdef DEBUG_CONTENT
    xmlGenericError(xmlGenericErrorContext,
                    "xmlSchemaValidateCallback: %s, %s, %s\n",
                    name, type->name, node->name);
#endif
    ctxt->type = type;
    ctxt->node = node;
    xmlSchemaValidateContent(ctxt, node);
    ctxt->type = oldtype;
    ctxt->node = oldnode;
}


#if 0

/**
 * xmlSchemaValidateSimpleRestrictionType:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Validate the content of a restriction type.
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateSimpleRestrictionType(xmlSchemaValidCtxtPtr ctxt,
                                       xmlNodePtr node)
{
    xmlNodePtr child;
    xmlSchemaTypePtr type;
    int ret;

    child = ctxt->node;
    type = ctxt->type;

    if ((ctxt == NULL) || (type == NULL)) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaValidateSimpleRestrictionType %s\n",
		      node->name, NULL);
        return (-1);
    }
    /*
     * Only text and text based entities references shall be found there
     */
    ret = xmlSchemaValidateCheckNodeList(child);
    if (ret < 0) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaValidateSimpleType %s content\n",
		      node->name, NULL);
        return (-1);
    } else if (ret == 0) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_NOTSIMPLE,
		      "Element %s content is not a simple type\n",
		      node->name, NULL);
        return (-1);
    }
    ctxt->type = type->subtypes;
    xmlSchemaValidateContent(ctxt, node);
    ctxt->type = type;
    return (ret);
}
#endif

/**
 * xmlSchemaValidateSimpleType:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Validate the content of an simple type.
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateSimpleType(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node)
{
    xmlNodePtr child;
    xmlSchemaTypePtr type, base, variety;
    xmlAttrPtr attr;
    int ret;
    xmlChar *value;
    

    child = ctxt->node;
    type = ctxt->type;

    if ((ctxt == NULL) || (type == NULL)) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaValidateSimpleType %s\n",
		      node->name, NULL);
        return (-1);
    }
    /*
     * Only text and text based entities references shall be found there
     */
    ret = xmlSchemaValidateCheckNodeList(child);
    if (ret < 0) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaValidateSimpleType %s content\n",
		      node->name, NULL);
        return (-1);
    } else if (ret == 0) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_NOTSIMPLE,
		      "Element %s content is not a simple type\n",
		      node->name, NULL);
        return (-1);
    }
    /*
     * Validation Rule: Element Locally Valid (Type): 3.1.1
     */    
    
    attr = node->properties;
    while (attr != NULL) {
        if ((attr->ns == NULL) ||
            (!xmlStrEqual(attr->ns->href, xmlSchemaInstanceNs)) ||
            ((!xmlStrEqual(attr->name, BAD_CAST "type")) &&
             (!xmlStrEqual(attr->name, BAD_CAST "nil")) &&
             (!xmlStrEqual(attr->name, BAD_CAST "schemasLocation")) &&
             (!xmlStrEqual
              (attr->name, BAD_CAST "noNamespaceSchemaLocation")))) {
            xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INVALIDATTR,
	    		  "Element %s: attribute %s should not be present\n",
			  node->name, attr->name);
            return (ctxt->err);
        }
    }
    /* TODO:
     * If {variety} is ·atomic· then the {variety} of {base type definition}
     * must be ·atomic·. 
     * If {variety} is ·list· then the {variety} of {item type definition}
     * must be either ·atomic· or ·union·. 
     * If {variety} is ·union· then {member type definitions} must be a list
     * of datatype definitions. 
     */
    if (type->subtypes == NULL) {
	xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaValidateSimpleType; "
		      "simple type %s does not define a variety\n",
		      node->name, NULL);
	return (ctxt->err);
    }
    /* Varieties: Restriction or List or Union. */
    variety = type->subtypes;
    ctxt->type = variety;        
    value = xmlNodeGetContent(child);
    switch (variety->type) {
        case XML_SCHEMA_TYPE_RESTRICTION:{
                xmlSchemaFacetPtr facet;

                base = variety->baseType;
                if (base != NULL) {
                    ret = xmlSchemaValidateSimpleValue(ctxt, base, value);
                } else {
                TODO}
                if (ret == 0) {
                    facet = variety->facets;
                    ret =
                        xmlSchemaValidateFacets(ctxt, base, facet, value);
                }
		/* Removed due to changes of attribute validation:
		if ((ret == 0) && (variety->attributes != NULL)) {
		    ret = xmlSchemaValidateAttributes(ctxt, node,
		    		variety->attributes);
		}
		*/
                break;
            }
        case XML_SCHEMA_TYPE_LIST:
	case XML_SCHEMA_TYPE_UNION: {
	        ret = xmlSchemaValidateSimpleValue(ctxt, variety, value);
                break;
            }
        default:{
		xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
			      "Internal error: xmlSchemaValidateSimpleType; "
			      "simple type %s defines unknown content: %s\n",
			      variety->name, NULL);
		ret = ctxt->err;
	    }
    }
    if (value != NULL)
        xmlFree(value);

    /* This was removed, since a simple content is not a content of a
     * simple type, but of a complex type.
     * ret = xmlSchemaValidateSimpleContent(ctxt, node);
     */
    ctxt->type = type;
    return (ret);
}

/**
 * xmlSchemaValidateElementType:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Validate the content of an element type.
 * Validation Rule: Element Locally Valid (Complex Type)
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateElementType(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node)
{
    xmlNodePtr child;
    xmlSchemaTypePtr type;
    xmlRegExecCtxtPtr oldregexp;        /* cont model of the parent */
    xmlSchemaElementPtr decl;
    int ret;
    xmlSchemaAttrStatePtr attrs = NULL, attrTop = NULL;

    /* 
     * TODO: Look into "xmlSchemaValidateElement" for missing parts, which should
     * go in here as well.
     */

    /* TODO: Is this one called always with an element declaration as the 
     * context's type?
     */

    oldregexp = ctxt->regexp;

    child = ctxt->node;
    type = ctxt->type;

    if ((ctxt == NULL) || (type == NULL)) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaValidateElementType\n",
		      node->name, NULL);
        return (-1);
    }
    if (child == NULL) {
        if (type->minOccurs > 0) {
            xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_MISSING,
	    		  "Element %s: missing child %s\n",
			  node->name, type->name);
        }
        return (ctxt->err);
    }

    /*
     * Verify the element matches
     */
    if (!xmlStrEqual(child->name, type->name)) {
        xmlSchemaVErr3(ctxt, node, XML_SCHEMAS_ERR_WRONGELEM,
		       "Element %s: missing child %s found %s\n",
		       node->name, type->name, child->name);
        return (ctxt->err);
    }
    /*
     * Verify the attributes
     */
    
    attrs = ctxt->attr;    
    attrTop = ctxt->attrTop;
    
    xmlSchemaRegisterAttributes(ctxt, child->properties);
        
    /* 
     * An element declaration does not hold any information about
     * attributes; thus, the following was removed.
     */
    /* xmlSchemaValidateAttributes(ctxt, child, type->attributes); */

    /*
     * Verify the element content recursively
     */
    decl = (xmlSchemaElementPtr) type;
    oldregexp = ctxt->regexp;
    if (decl->contModel != NULL) {
        ctxt->regexp = xmlRegNewExecCtxt(decl->contModel,
                                         (xmlRegExecCallbacks)
                                         xmlSchemaValidateCallback, ctxt);
#ifdef DEBUG_AUTOMATA
        xmlGenericError(xmlGenericErrorContext, "====> %s\n", node->name);
#endif
    }
    xmlSchemaValidateType(ctxt, child, (xmlSchemaElementPtr) type,
                          type->subtypes);

    if (decl->contModel != NULL) {
        ret = xmlRegExecPushString(ctxt->regexp, NULL, NULL);
#ifdef DEBUG_AUTOMATA
        xmlGenericError(xmlGenericErrorContext,
                        "====> %s : %d\n", node->name, ret);
#endif
        if (ret == 0) {
            xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_ELEMCONT,
	    		  "Element %s content check failed\n",
			  node->name, NULL);
        } else if (ret < 0) {
            xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_ELEMCONT,
	    		  "Element %s content check failure\n",
			  node->name, NULL);
#ifdef DEBUG_CONTENT
        } else {
            xmlGenericError(xmlGenericErrorContext,
                            "Element %s content check succeeded\n",
                            node->name);

#endif
        }
        xmlRegFreeExecCtxt(ctxt->regexp);
    }
    /*
     * Verify that all attributes were Schemas-validated
     */
    xmlSchemaCheckAttributes(ctxt, node);
    if (ctxt->attr != NULL)
	xmlSchemaFreeAttributeStates(ctxt->attr);
    ctxt->attr = attrs;    
    ctxt->attrTop = attrTop;
    ctxt->regexp = oldregexp;
    ctxt->node = child;
    ctxt->type = type;
    return (ctxt->err);
}

/**
 * xmlSchemaValidateBasicType:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Validate the content of an element expected to be a basic type type
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateBasicType(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node)
{
    int ret;
    xmlNodePtr child, cur;
    xmlSchemaTypePtr type;
    xmlChar *value;             /* lexical representation */

    child = ctxt->node;
    type = ctxt->type;

    if ((ctxt == NULL) || (type == NULL)) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
		      "Internal error: xmlSchemaValidateBasicType\n",
		      node->name, NULL);
        return (-1);
    }
    /*
     * First check the content model of the node.
     */
    cur = child;
    while (cur != NULL) {
        switch (cur->type) {
            case XML_TEXT_NODE:
            case XML_CDATA_SECTION_NODE:
            case XML_PI_NODE:
            case XML_COMMENT_NODE:
            case XML_XINCLUDE_START:
            case XML_XINCLUDE_END:
                break;
            case XML_ENTITY_REF_NODE:
            case XML_ENTITY_NODE:
                TODO break;
            case XML_ELEMENT_NODE:
                xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INVALIDELEM,
			      "Element %s: child %s should not be present\n",
			      node->name, cur->name);
                return (ctxt->err);
            case XML_ATTRIBUTE_NODE:
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_NOTATION_NODE:
            case XML_HTML_DOCUMENT_NODE:
            case XML_DTD_NODE:
            case XML_ELEMENT_DECL:
            case XML_ATTRIBUTE_DECL:
            case XML_ENTITY_DECL:
            case XML_NAMESPACE_DECL:
#ifdef LIBXML_DOCB_ENABLED
            case XML_DOCB_DOCUMENT_NODE:
#endif
                xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INVALIDELEM,
			      "Element %s: node type of node unexpected here\n",
			      node->name, NULL);
                return (ctxt->err);
        }
        cur = cur->next;
    }
    if (child == NULL)
        value = NULL;
    else
        value = xmlNodeGetContent(child->parent);

    if (ctxt->value != NULL) {
        xmlSchemaFreeValue(ctxt->value);
        ctxt->value = NULL;
    }
    ret = xmlSchemaValidatePredefinedType(type, value, &(ctxt->value));
    if (value != NULL)
        xmlFree(value);
    if (ret != 0) {
        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_VALUE,
		      "Element %s: failed to validate basic type %s\n",
		      node->name, type->name);
    }
    return (ret);
}

/**
 * xmlSchemaValidateComplexType:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Validate the content of an element expected to be a complex type type
 * xmlschema-1.html#cvc-complex-type
 * Validation Rule: Element Locally Valid (Complex Type)
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateComplexType(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node)
{
    xmlNodePtr child;
    xmlSchemaTypePtr type, subtype;
    int ret;

    /* TODO: Handle xsd:restriction & xsd:extension */

    child = ctxt->node;
    type = ctxt->type;
    ctxt->cur = node;

    switch (type->contentType) {
        case XML_SCHEMA_CONTENT_EMPTY:
	    if (type->baseType != NULL) {
	    } else if (child != NULL) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_NOTEMPTY,
			      "Element %s is supposed to be empty\n",
			      node->name, NULL);
            }
	    /* Removed due to changes of attribute validation:
            if (type->attributes != NULL) {
                xmlSchemaValidateAttributes(ctxt, node, type->attributes);
            }
	    */
            subtype = type->subtypes;
            while (subtype != NULL) {
                ctxt->type = subtype;
                xmlSchemaValidateComplexType(ctxt, node);
                subtype = subtype->next;
            }
            break;
        case XML_SCHEMA_CONTENT_ELEMENTS:
        case XML_SCHEMA_CONTENT_MIXED:
        case XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS:
            /*
             * Skip ignorable nodes in that context
             */
	    /* ComplexType, ComplexContent */
	    if (child != NULL) {
            child = xmlSchemaSkipIgnored(ctxt, type, child);
            while (child != NULL) {
                if (child->type == XML_ELEMENT_NODE) {
                    ret = xmlRegExecPushString(ctxt->regexp,
                                               child->name, child);
#ifdef DEBUG_AUTOMATA
                    if (ret < 0)
                        xmlGenericError(xmlGenericErrorContext,
                                        "  --> %s Error\n", child->name);
                    else
                        xmlGenericError(xmlGenericErrorContext,
                                        "  --> %s\n", child->name);
#endif
                }
                child = child->next;
                /*
                 * Skip ignorable nodes in that context
                 */
                child = xmlSchemaSkipIgnored(ctxt, type, child);
            }
	    }
	    
	    if (((type->contentType == XML_SCHEMA_CONTENT_MIXED) ||
		(type->contentType == XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS)) &&
		(type->subtypes != NULL)) {
		TODO
	    }

	    /* Removed due to changes of attribute validation:
            if (type->attributes != NULL) {
                xmlSchemaValidateAttributes(ctxt, node, type->attributes);
            }
	    */
            break;
        case XML_SCHEMA_CONTENT_BASIC:{
                if (type->subtypes != NULL) {
                    ctxt->type = type->subtypes;
                    xmlSchemaValidateComplexType(ctxt, node);
                }
                if (type->baseType != NULL) {
                    ctxt->type = type->baseType;
		    if (type->baseType->type == XML_SCHEMA_TYPE_BASIC)
			xmlSchemaValidateBasicType(ctxt, node);
		    else if (type->baseType->type == XML_SCHEMA_TYPE_COMPLEX)
			xmlSchemaValidateComplexType(ctxt, node);
		    /* TODO: This might be incorrect. */
		    else if (type->baseType->type == XML_SCHEMA_TYPE_SIMPLE) 
			xmlSchemaValidateSimpleType(ctxt, node);
		    else
			xmlGenericError(xmlGenericErrorContext,
                                 "unexpected content type of base: %d\n",
                                 type->contentType);
                }
		/* Removed due to changes of attribute validation:
                if (type->attributes != NULL) {
                    xmlSchemaValidateAttributes(ctxt, node,
                                                type->attributes);
                }
		*/
                ctxt->type = type;
                break;
            }
        case XML_SCHEMA_CONTENT_SIMPLE:{
                if (type->subtypes != NULL) {
                    ctxt->type = type->subtypes;
                    xmlSchemaValidateComplexType(ctxt, node);
                }
                if (type->baseType != NULL) {
                    ctxt->type = type->baseType;
                    xmlSchemaValidateComplexType(ctxt, node);
                }
		/* Removed due to changes of attribute validation:
                if (type->attributes != NULL) {
                    xmlSchemaValidateAttributes(ctxt, node,
                                                type->attributes);
                }
		*/
                ctxt->type = type;
                break;
	}
        default:
            TODO xmlGenericError(xmlGenericErrorContext,
                                 "unimplemented content type %d\n",
                                 type->contentType);
    }
    if (type->type == XML_SCHEMA_TYPE_COMPLEX)
	xmlSchemaValidateAttributes(ctxt, node, type);
    return (ctxt->err);
}

/**
 * xmlSchemaValidateContent:
 * @ctxt:  a schema validation context
 * @elem:  an element
 * @type:  the type declaration
 *
 * Validate the content of an element against the type.
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateContent(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node)
{
    xmlNodePtr child;
    xmlSchemaTypePtr type;

    child = ctxt->node;
    type = ctxt->type;
    ctxt->cur = node;

    /* 
     * Removed, since redundant. 
     */
    /* xmlSchemaValidateAttributes(ctxt, node, type->attributes); */
    ctxt->cur = node;

    switch (type->type) {
        case XML_SCHEMA_TYPE_ANY:
            /* Any type will do it, fine */
            TODO                /* handle recursivity */
                break;
        case XML_SCHEMA_TYPE_COMPLEX:
            xmlSchemaValidateComplexType(ctxt, node);
            break;
        case XML_SCHEMA_TYPE_ELEMENT:{
                xmlSchemaElementPtr decl = (xmlSchemaElementPtr) type;

                /*
                 * Handle element reference here
                 */
                if (decl->ref != NULL) {
                    if (decl->refDecl == NULL) {
                        xmlSchemaVErr(ctxt, node, XML_SCHEMAS_ERR_INTERNAL,
				      "Internal error: element reference %s "
				      "not resolved\n", decl->ref, NULL);
                        return (-1);
                    }
                    ctxt->type = (xmlSchemaTypePtr) decl->refDecl;
                    decl = decl->refDecl;
                }
		/* TODO: Should "xmlSchemaValidateElement" be called instead? */
                xmlSchemaValidateElementType(ctxt, node);
                ctxt->type = type;
                break;
            }
        case XML_SCHEMA_TYPE_BASIC:
            xmlSchemaValidateBasicType(ctxt, node);
            break;
        case XML_SCHEMA_TYPE_FACET:
            TODO break;
        case XML_SCHEMA_TYPE_SIMPLE:
            xmlSchemaValidateSimpleType(ctxt, node);
            break;
        case XML_SCHEMA_TYPE_SEQUENCE:
            TODO break;
        case XML_SCHEMA_TYPE_CHOICE:
            TODO break;
        case XML_SCHEMA_TYPE_ALL:
            TODO break;
        case XML_SCHEMA_TYPE_SIMPLE_CONTENT:
            TODO break;
        case XML_SCHEMA_TYPE_COMPLEX_CONTENT:
            TODO break;
        case XML_SCHEMA_TYPE_UR:
            TODO break;
        case XML_SCHEMA_TYPE_RESTRICTION:
            /*xmlSchemaValidateRestrictionType(ctxt, node); */
            TODO break;
        case XML_SCHEMA_TYPE_EXTENSION:
            TODO break;
        case XML_SCHEMA_TYPE_ATTRIBUTE:
            TODO break;
        case XML_SCHEMA_TYPE_GROUP:
            TODO break;
        case XML_SCHEMA_TYPE_NOTATION:
            TODO break;
        case XML_SCHEMA_TYPE_LIST:
            TODO break;
        case XML_SCHEMA_TYPE_UNION:
            TODO break;
        case XML_SCHEMA_FACET_MININCLUSIVE:
            TODO break;
        case XML_SCHEMA_FACET_MINEXCLUSIVE:
            TODO break;
        case XML_SCHEMA_FACET_MAXINCLUSIVE:
            TODO break;
        case XML_SCHEMA_FACET_MAXEXCLUSIVE:
            TODO break;
        case XML_SCHEMA_FACET_TOTALDIGITS:
            TODO break;
        case XML_SCHEMA_FACET_FRACTIONDIGITS:
            TODO break;
        case XML_SCHEMA_FACET_PATTERN:
            TODO break;
        case XML_SCHEMA_FACET_ENUMERATION:
            TODO break;
        case XML_SCHEMA_FACET_WHITESPACE:
            TODO break;
        case XML_SCHEMA_FACET_LENGTH:
            TODO break;
        case XML_SCHEMA_FACET_MAXLENGTH:
            TODO break;
        case XML_SCHEMA_FACET_MINLENGTH:
            TODO break;
        case XML_SCHEMA_TYPE_ATTRIBUTEGROUP:
            TODO break;
        case XML_SCHEMA_TYPE_ANY_ATTRIBUTE:
            TODO break;
    }
    /* 
     * Removed, since redundant. 
     */
    /* xmlSchemaValidateAttributes(ctxt, node, type->attributes); */

    if (ctxt->node == NULL)
        return (ctxt->err);
    ctxt->node = ctxt->node->next;
    ctxt->type = type->next;
    return (ctxt->err);
}

/**
 * xmlSchemaValidateType:
 * @ctxt:  a schema validation context
 * @elem:  an element
 * @type:  the list of type declarations
 *
 * Validate the content of an element against the types.
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateType(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr elem,
                      xmlSchemaElementPtr elemDecl, xmlSchemaTypePtr type)
{
    xmlChar *nil;

    if ((elem == NULL) || (type == NULL) || (elemDecl == NULL))
        return (0);

    /* This one is called by "xmlSchemaValidateElementType" and
     * "xmlSchemaValidateElement".
     */

    /*
     * 3.3.4 : 2
     */
    if (elemDecl->flags & XML_SCHEMAS_ELEM_ABSTRACT) {
        xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_ISABSTRACT,
		      "Element declaration %s is abstract\n",
		      elemDecl->name, NULL);
	/* Changed, since the element declaration is abstract and not
	 * the element itself. */
	/* xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_ISABSTRACT,
			 "Element %s is abstract\n", elem->name, NULL); */
        return (ctxt->err);
    }
    /*
     * 3.3.4: 3
     */
    nil = xmlGetNsProp(elem, BAD_CAST "nil", xmlSchemaInstanceNs);
    if (elemDecl->flags & XML_SCHEMAS_ELEM_NILLABLE) {
        /* 3.3.4: 3.2 */
        if (xmlStrEqual(nil, BAD_CAST "true")) {
            if (elem->children != NULL) {
                xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_NOTEMPTY,
			      "Element %s is not empty\n", elem->name, NULL);
                return (ctxt->err);
            }
            if ((elemDecl->flags & XML_SCHEMAS_ELEM_FIXED) &&
                (elemDecl->value != NULL)) {
                xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_HAVEDEFAULT,
			      "Empty element %s cannot get a fixed value\n",
			      elem->name, NULL);
                return (ctxt->err);
            }
        }
    } else {
        /* 3.3.4: 3.1 */
        if (nil != NULL) {
            xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_NOTNILLABLE,
	    		  "Element %s with xs:nil but not nillable\n",
			  elem->name, NULL);
            xmlFree(nil);
            return (ctxt->err);
        }
    }

    /* TODO 3.3.4: 4 if the element carries xs:type */

    ctxt->type = elemDecl->subtypes;
    ctxt->node = elem->children;
    xmlSchemaValidateContent(ctxt, elem);
    /* Removed, since an element declaration does not hold any attribute
     * declarations */
    /* xmlSchemaValidateAttributes(ctxt, elem, elemDecl->attributes); */

    return (ctxt->err);
}


/**
 * xmlSchemaValidateAttributes:
 * @ctxt:  a schema validation context
 * @elem:  an element
 * @type:  the complexType holding the attribute uses
 *
 * Validate the attributes of an element.
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateAttributes(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr elem, xmlSchemaTypePtr type)
{
    int ret;
    xmlAttrPtr attr; /* An attribute on the element. */
    xmlChar *value;
    xmlSchemaAttributeLinkPtr attrUse;
    xmlSchemaAttributePtr attrDecl;
    int found;
    xmlSchemaAttrStatePtr curState, reqAttrStates = NULL, reqAttrStatesTop = NULL;
#ifdef DEBUG_ATTR_VALIDATION
    int redundant = 0;
#endif
    if (type->type != XML_SCHEMA_TYPE_COMPLEX) {
	xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_INTERNAL,
			      "Internal error: xmlSchemaValidateAttributes: "
			      "given type \"%s\"is not a complexType\n",
			      type->name, NULL);
	return(-1);
    }    

    if ((type->attributeUses == NULL) && (type->attributeWildcard == NULL))
        return (0);

    attrUse = type->attributeUses;

    while (attrUse != NULL) {
        found = 0;    
	attrDecl = attrUse->attr;
#ifdef DEBUG_ATTR_VALIDATION
	printf("attr use - name: %s\n", xmlSchemaGetOnymousAttrName(attrDecl));
	printf("attr use - use: %d\n", attrDecl->occurs);
#endif
        for (curState = ctxt->attr; curState != NULL; curState = curState->next) {		    

	    if (curState->decl == attrUse->attr) {
#ifdef DEBUG_ATTR_VALIDATION
		redundant = 1;
#endif
        }
	    attr = curState->attr;
#ifdef DEBUG_ATTR_VALIDATION
	    printf("attr - name: %s\n", attr->name);
	    if (attr->ns != NULL)
		printf("attr - ns: %s\n", attr->ns->href);
	    else
		printf("attr - ns: none\n");
#endif
	    /* TODO: Can this ever happen? */
            if (attr == NULL)
                continue;
            if (attrDecl->ref != NULL) {
                if (!xmlStrEqual(attr->name, attrDecl->ref))
                    continue;
                if (attr->ns != NULL) {
                    if ((attrDecl->refNs == NULL) ||
                        (!xmlStrEqual(attr->ns->href, attrDecl->refNs)))
                        continue;
                } else if (attrDecl->refNs != NULL) {
                    continue;
                }
            } else {
                if (!xmlStrEqual(attr->name, attrDecl->name))
                    continue;
                /*
                 * handle the namespaces checks here
                 */
                if (attr->ns == NULL) {
		    /*
		     * accept an unqualified attribute only if the target
		     * namespace of the declaration is absent.
		     */
		    if (attrDecl->targetNamespace != NULL)
			/* 
			 * This check was removed, since the target namespace
			 * was evaluated during parsing and already took
			 * "attributeFormDefault" into account.
			 */
		        /* ((attributes->flags & XML_SCHEMAS_ATTR_NSDEFAULT) == 0)) */
		        continue;
		} else {
		    if (attrDecl->targetNamespace == NULL)
		        continue;
		    if (!xmlStrEqual(attrDecl->targetNamespace,
		                     attr->ns->href))
			continue;
		}
            }
#ifdef DEBUG_ATTR_VALIDATION
	    printf("found\n");
#endif
            found = 1;
            ctxt->cur = (xmlNodePtr) attrDecl;

            if (attrDecl->subtypes == NULL) {
		curState->state = XML_SCHEMAS_ATTR_TYPE_NOT_RESOLVED;
		curState->decl = attrDecl;
		/* 
		 * This could be put into "xmlSchemaCheckAttributes" as well, but
		 * since it reports an internal error, it better stays here to ease
		 * debugging.
		 */
                xmlSchemaVErr(ctxt, (xmlNodePtr) attr, XML_SCHEMAS_ERR_INTERNAL,
			      "Internal error: attribute %s type not resolved\n",
			      attr->name, NULL);
                continue;
            }
            value = xmlNodeListGetString(elem->doc, attr->children, 1);
            ret = xmlSchemaValidateSimpleValue(ctxt, attrDecl->subtypes,
                                               value);
            if (ret != 0) 
		curState->state = XML_SCHEMAS_ATTR_INVALID_VALUE;   				
            else
                curState->state = XML_SCHEMAS_ATTR_CHECKED;
	    curState->decl = attrDecl;
            if (value != NULL) {
                xmlFree(value);
            }	    
        }
        if ((!found) && (attrDecl->occurs == XML_SCHEMAS_ATTR_USE_REQUIRED)) {
	    xmlSchemaAttrStatePtr tmp;

#ifdef DEBUG_ATTR_VALIDATION
	    printf("required attr not found\n");
#endif
	    /*
	     * Add a new dummy attribute state.
	     */	
	    tmp = (xmlSchemaAttrStatePtr) xmlMalloc(sizeof(xmlSchemaAttrState));
	    if (tmp == NULL) {
		xmlSchemaVErrMemory(ctxt, "registering required attributes", NULL);
		return (-1);
            }            
	    tmp->attr = NULL;
	    tmp->state = XML_SCHEMAS_ATTR_MISSING;
	    tmp->decl = attrDecl;
	    tmp->next = NULL;
         
	    if (reqAttrStates == NULL) {
		reqAttrStates = tmp;
		reqAttrStatesTop = tmp;
            } else {
		reqAttrStatesTop->next = tmp;
		reqAttrStatesTop = tmp;
            }
	
	}
        attrUse = attrUse->next;
    }
    /*
     * Add required attributes to the attribute states of the context.
     */
    if (reqAttrStates != NULL) {
	if (ctxt->attr == NULL) {
	    ctxt->attr = reqAttrStates;
	} else {		
	    ctxt->attrTop->next = reqAttrStates;
	}
	ctxt->attrTop = reqAttrStatesTop;
            }
    /*
    * Process wildcards.
    */
    if (type->attributeWildcard != NULL) {	
#ifdef DEBUG_ATTR_VALIDATION
	xmlSchemaWildcardNsPtr ns;	
	printf("matching wildcard: [%d] of complexType: %s\n", type->attributeWildcard, type->name);
	if (type->attributeWildcard->any)
	    printf("type: any\n");
	else if (type->attributeWildcard->negNsSet != NULL) {
	    printf("type: negated\n");
	    if (type->attributeWildcard->negNsSet->value == NULL)
		printf("ns: (absent)\n");
	    else
		printf("ns: %s\n", type->attributeWildcard->negNsSet->value);
	} else if (type->attributeWildcard->nsSet != NULL) {
	    printf("type: set\n");
	    ns = type->attributeWildcard->nsSet;
	    while (ns != NULL) {
		if (ns->value == NULL)
		    printf("ns: (absent)\n");
		else
		    printf("ns: %s\n", ns->value);
		ns = ns->next;
	    }	    
	} else
	    printf("empty\n");

#endif
	/*
	* TODO: Implement processContents.
	*/
	curState = ctxt->attr;
	while (curState != NULL) {
	    if ((curState->state == XML_SCHEMAS_ATTR_UNKNOWN) && 
		(curState->attr != NULL)) {
		if (curState->attr->ns != NULL) {
		    if (xmlSchemaMatchesWildcardNs(type->attributeWildcard, 
			curState->attr->ns->href))
			curState->state = XML_SCHEMAS_ATTR_CHECKED;
		} else if (xmlSchemaMatchesWildcardNs(type->attributeWildcard, 
		    NULL))
		    curState->state = XML_SCHEMAS_ATTR_CHECKED;		
        }
	    curState = curState->next;
        }
    }

#ifdef DEBUG_ATTR_VALIDATION
    if (redundant)
	xmlGenericError(xmlGenericErrorContext,
	                "xmlSchemaValidateAttributes: redundant call by type: %s\n",
	                type->name);
#endif
    return (ctxt->err);
}

/**
 * xmlSchemaValidateElement:
 * @ctxt:  a schema validation context
 * @elem:  an element
 *
 * Validate an element in a tree
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateElement(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr elem)
{
    xmlSchemaElementPtr elemDecl;
    int ret;
    xmlSchemaAttrStatePtr attrs, attrTop;

    if (elem->ns != NULL) {
        elemDecl = xmlHashLookup3(ctxt->schema->elemDecl,
                                  elem->name, elem->ns->href, NULL);
    } else {
        elemDecl = xmlHashLookup3(ctxt->schema->elemDecl,
                                  elem->name, NULL, NULL);
    }
    /*
     * special case whe elementFormDefault is unqualified for top-level elem.
     */
    /*
     * This was removed, since elementFormDefault does not apply to top-level
     * element declarations.
     */
    /*
    if ((elemDecl == NULL) && (elem->ns != NULL) &&
        (elem->parent != NULL) && (elem->parent->type != XML_ELEMENT_NODE) &&
        (xmlStrEqual(ctxt->schema->targetNamespace, elem->ns->href)) &&
	((ctxt->schema->flags & XML_SCHEMAS_QUALIF_ELEM) == 0)) {
        elemDecl = xmlHashLookup3(ctxt->schema->elemDecl,
                                  elem->name, NULL, NULL);
    }
    */

    /*
     * 3.3.4 : 1
     */
    if (elemDecl == NULL) {
        xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_UNDECLAREDELEM,
		      "Element %s not declared\n", elem->name, NULL);
        return (ctxt->err);
    }
    if (elemDecl->subtypes == NULL) {
        xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_NOTYPE,
		      "Element %s has no type\n", elem->name, NULL);
        return (ctxt->err);
    }
    /*
     * Verify the attributes
     */
    attrs = ctxt->attr;
    attrTop = ctxt->attrTop;
    xmlSchemaRegisterAttributes(ctxt, elem->properties);
    /*
     * Verify the element content recursively
     */
    if (elemDecl->contModel != NULL) {
        ctxt->regexp = xmlRegNewExecCtxt(elemDecl->contModel,
                                         (xmlRegExecCallbacks)
                                         xmlSchemaValidateCallback, ctxt);
#ifdef DEBUG_AUTOMATA
        xmlGenericError(xmlGenericErrorContext, "====> %s\n", elem->name);
#endif
    }
    xmlSchemaValidateType(ctxt, elem, elemDecl, elemDecl->subtypes);
    if (elemDecl->contModel != NULL) {
        ret = xmlRegExecPushString(ctxt->regexp, NULL, NULL);
#ifdef DEBUG_AUTOMATA
        xmlGenericError(xmlGenericErrorContext,
                        "====> %s : %d\n", elem->name, ret);
#endif
        if (ret == 0) {
            xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_ELEMCONT,
	    		  "Element %s content check failed\n",
			  elem->name, NULL);
        } else if (ret < 0) {
            xmlSchemaVErr(ctxt, elem, XML_SCHEMAS_ERR_ELEMCONT,
	    		  "Element %s content check failed\n",
			  elem->name, NULL);
#ifdef DEBUG_CONTENT
        } else {
            xmlGenericError(xmlGenericErrorContext,
                            "Element %s content check succeeded\n",
                            elem->name);

#endif
        }
        xmlRegFreeExecCtxt(ctxt->regexp);
    }
    /*
     * Verify that all attributes were Schemas-validated
     */
    xmlSchemaCheckAttributes(ctxt, elem);
    if (ctxt->attr != NULL)
	xmlSchemaFreeAttributeStates(ctxt->attr);
    ctxt->attr = attrs;
    ctxt->attrTop = attrTop;

    return (ctxt->err);
}

/**
 * xmlSchemaValidateDocument:
 * @ctxt:  a schema validation context
 * @doc:  a parsed document tree
 *
 * Validate a document tree in memory.
 *
 * Returns 0 if the document is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateDocument(xmlSchemaValidCtxtPtr ctxt, xmlDocPtr doc)
{
    xmlNodePtr root;
    xmlSchemaElementPtr elemDecl;

    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlSchemaVErr(ctxt, (xmlNodePtr) doc, XML_SCHEMAS_ERR_NOROOT,
		      "document has no root\n", NULL, NULL);
        return (ctxt->err);
    }
    
    if (root->ns != NULL)
        elemDecl = xmlHashLookup3(ctxt->schema->elemDecl,
                                  root->name, root->ns->href, NULL);
    else
        elemDecl = xmlHashLookup3(ctxt->schema->elemDecl,
                                  root->name, NULL, NULL);

    /*
     * special case whe elementFormDefault is unqualified for top-level elem.
     */
    /* Removed, since elementFormDefault does not apply to top level 
    * elements */
    /*
    if ((elemDecl == NULL) && (root->ns != NULL) &&
        (xmlStrEqual(ctxt->schema->targetNamespace, root->ns->href)) &&
	((ctxt->schema->flags & XML_SCHEMAS_QUALIF_ELEM) == 0)) {
        elemDecl = xmlHashLookup3(ctxt->schema->elemDecl,
                                  root->name, NULL, NULL);
    }
    */

    if (elemDecl == NULL) {
        xmlSchemaVErr(ctxt, root, XML_SCHEMAS_ERR_UNDECLAREDELEM,
		      "Element %s not declared\n", root->name, NULL);
    } else if ((elemDecl->flags & XML_SCHEMAS_ELEM_GLOBAL) == 0) {
        xmlSchemaVErr(ctxt, root, XML_SCHEMAS_ERR_NOTTOPLEVEL,
		      "Root element %s not global\n", root->name, NULL);
    }
    /*
     * Okay, start the recursive validation
     */
    xmlSchemaValidateElement(ctxt, root);

    return (ctxt->err);
}

/************************************************************************
 * 									*
 * 			SAX Validation code				*
 * 									*
 ************************************************************************/

/************************************************************************
 * 									*
 * 			Validation interfaces				*
 * 									*
 ************************************************************************/

/**
 * xmlSchemaNewValidCtxt:
 * @schema:  a precompiled XML Schemas
 *
 * Create an XML Schemas validation context based on the given schema
 *
 * Returns the validation context or NULL in case of error
 */
xmlSchemaValidCtxtPtr
xmlSchemaNewValidCtxt(xmlSchemaPtr schema)
{
    xmlSchemaValidCtxtPtr ret;

    ret = (xmlSchemaValidCtxtPtr) xmlMalloc(sizeof(xmlSchemaValidCtxt));
    if (ret == NULL) {
        xmlSchemaVErrMemory(NULL, "allocating validation context", NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaValidCtxt));
    ret->schema = schema;
    /* 
     * Removed due to changes of the attribute state list.
    */
    /* ret->attrNr = 0; */
    /* ret->attrMax = 10; */
    /* ret->attrBase = NULL; */
    ret->attrTop = NULL;
    ret->attr = NULL;
    /* 
     * Removed due to changes of the attribute state list.
     *
    ret->attr = (xmlSchemaAttrStatePtr) xmlMalloc(ret->attrMax *
                                                  sizeof
                                                  (xmlSchemaAttrState));
    if (ret->attr == NULL) {
        xmlSchemaVErrMemory(NULL, "allocating validation context", NULL);
        free(ret);
        return (NULL);
    }
    memset(ret->attr, 0, ret->attrMax * sizeof(xmlSchemaAttrState));
    */

    return (ret);
}

/**
 * xmlSchemaFreeValidCtxt:
 * @ctxt:  the schema validation context
 *
 * Free the resources associated to the schema validation context
 */
void
xmlSchemaFreeValidCtxt(xmlSchemaValidCtxtPtr ctxt)
{
    if (ctxt == NULL)
        return;
    if (ctxt->attr != NULL)
        xmlSchemaFreeAttributeStates(ctxt->attr);
    if (ctxt->value != NULL)
        xmlSchemaFreeValue(ctxt->value);
    xmlFree(ctxt);
}

/**
 * xmlSchemaSetValidErrors:
 * @ctxt:  a schema validation context
 * @err:  the error function
 * @warn: the warning function
 * @ctx: the functions context
 *
 * Set the error and warning callback informations
 */
void
xmlSchemaSetValidErrors(xmlSchemaValidCtxtPtr ctxt,
                        xmlSchemaValidityErrorFunc err,
                        xmlSchemaValidityWarningFunc warn, void *ctx)
{
    if (ctxt == NULL)
        return;
    ctxt->error = err;
    ctxt->warning = warn;
    ctxt->userData = ctx;
}

/**
 * xmlSchemaValidateDoc:
 * @ctxt:  a schema validation context
 * @doc:  a parsed document tree
 *
 * Validate a document tree in memory.
 *
 * Returns 0 if the document is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
int
xmlSchemaValidateDoc(xmlSchemaValidCtxtPtr ctxt, xmlDocPtr doc)
{
    int ret;

    if ((ctxt == NULL) || (doc == NULL))
        return (-1);

    ctxt->doc = doc;
    ret = xmlSchemaValidateDocument(ctxt, doc);
    return (ret);
}

/**
 * xmlSchemaValidateStream:
 * @ctxt:  a schema validation context
 * @input:  the input to use for reading the data
 * @enc:  an optional encoding information
 * @sax:  a SAX handler for the resulting events
 * @user_data:  the context to provide to the SAX handler.
 *
 * Validate a document tree in memory.
 *
 * Returns 0 if the document is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
int
xmlSchemaValidateStream(xmlSchemaValidCtxtPtr ctxt,
                        xmlParserInputBufferPtr input, xmlCharEncoding enc,
                        xmlSAXHandlerPtr sax, void *user_data)
{
    if ((ctxt == NULL) || (input == NULL))
        return (-1);
    ctxt->input = input;
    ctxt->enc = enc;
    ctxt->sax = sax;
    ctxt->user_data = user_data;
    TODO return (0);
}

#endif /* LIBXML_SCHEMAS_ENABLED */
