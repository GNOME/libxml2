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
 *   - if we don't intend to use the schema for schemas, we 
 *     need to validate all schema attributes (ref, type, name)
 *     against their types.
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

/* #define DEBUG_UNION_VALIDATION 1 */


#define UNBOUNDED (1 << 30)
#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

#define XML_SCHEMAS_NO_NAMESPACE (const xmlChar *) "##"

/*
 * The XML Schemas namespaces
 */
static const xmlChar *xmlSchemaNs = (const xmlChar *)
    "http://www.w3.org/2001/XMLSchema";

static const xmlChar *xmlSchemaInstanceNs = (const xmlChar *)
    "http://www.w3.org/2001/XMLSchema-instance";

static const xmlChar *xmlSchemaElemDesElemDecl = (const xmlChar *)
    "Element decl.";
static const xmlChar *xmlSchemaElemDesElemRef = (const xmlChar *)
    "Element ref.";
static const xmlChar *xmlSchemaElemDesAttrDecl = (const xmlChar *)
    "Attribute decl.";
static const xmlChar *xmlSchemaElemDesAttrRef = (const xmlChar *)
    "Attribute ref.";
static const xmlChar *xmlSchemaElemDesST = (const xmlChar *)
    "simple type";
static const xmlChar *xmlSchemaElemDesCT = (const xmlChar *)
    "complex type";

#define IS_SCHEMA(node, type)						\
   ((node != NULL) && (node->ns != NULL) &&				\
    (xmlStrEqual(node->name, (const xmlChar *) type)) &&		\
    (xmlStrEqual(node->ns->href, xmlSchemaNs)))

#define FREE_AND_NULL(str)						\
    if (str != NULL) {							\
	xmlFree(str);							\
	str = NULL;							\
    }

#define IS_ANYTYPE(item)                           \
    ((item->type == XML_SCHEMA_TYPE_BASIC) &&      \
     (item->builtInType == XML_SCHEMAS_ANYTYPE))   

#define IS_COMPLEX_TYPE(item)                      \
    ((item->type == XML_SCHEMA_TYPE_COMPLEX) ||    \
     (item->builtInType == XML_SCHEMAS_ANYTYPE))

#define IS_SIMPLE_TYPE(item)                       \
    ((item->type == XML_SCHEMA_TYPE_SIMPLE) ||     \
     ((item->type == XML_SCHEMA_TYPE_BASIC) &&     \
      (item->builtInType != XML_SCHEMAS_ANYTYPE))) 

#define XML_SCHEMAS_VAL_WTSP_PRESERVE 0
#define XML_SCHEMAS_VAL_WTSP_REPLACE  1
#define XML_SCHEMAS_VAL_WTSP_COLLAPSE 2

#define XML_SCHEMAS_PARSE_ERROR		1

#define SCHEMAS_PARSE_OPTIONS XML_PARSE_NOENT


/*
* XML_SCHEMA_VAL_XSI_ASSEMBLE_TNS_COMPOSE	 
* allow to assemble schemata with 
* the same target namespace from 
* different sources; otherwise, the first 
* encountered schema with a specific target 
* namespace will be used only *
   
* 
* XML_SCHEMA_VAL_LOCATE_BY_NSNAME = 1<<2
* locate schemata to be imported
* using the namespace name; otherwise
* the location URI will be used */

/*
* xmlSchemaParserOption:
*
* This is the set of XML Schema parser options.
*
typedef enum {
    XML_SCHEMA_PAR_LOCATE_BY_NSNAME	= 1<<0
	* locate schemata to be imported
	* using the namespace name; otherwise
	* the location URI will be used *
} xmlSchemaParserOption;
*/

/*
XMLPUBFUN int XMLCALL
	    xmlSchemaParserCtxtSetOptions(xmlSchemaParserCtxtPtr ctxt,
					  int options);
XMLPUBFUN int XMLCALL
	    xmlSchemaParserCtxtGetOptions(xmlSchemaParserCtxtPtr ctxt);

*/

typedef struct _xmlSchemaAssemble xmlSchemaAssemble;
typedef xmlSchemaAssemble *xmlSchemaAssemblePtr;
struct _xmlSchemaAssemble {
    void **items;  /* used for dynamic addition of schemata */
    int nbItems; /* used for dynamic addition of schemata */
    int sizeItems; /* used for dynamic addition of schemata */
};

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
    xmlSchemaTypePtr ctxtType; /* The current context simple/complex type */
    xmlSchemaTypePtr parentItem; /* The current parent schema item */
    xmlSchemaAssemblePtr assemble;
    int options;
    xmlSchemaValidCtxtPtr vctxt;
};


#define XML_SCHEMAS_ATTR_UNKNOWN 1
#define XML_SCHEMAS_ATTR_CHECKED 2
#define XML_SCHEMAS_ATTR_PROHIBITED 3
#define XML_SCHEMAS_ATTR_MISSING 4
#define XML_SCHEMAS_ATTR_INVALID_VALUE 5
#define XML_SCHEMAS_ATTR_TYPE_NOT_RESOLVED 6
#define XML_SCHEMAS_ATTR_INVALID_FIXED_VALUE 7
#define XML_SCHEMAS_ATTR_DEFAULT 8

typedef struct _xmlSchemaAttrState xmlSchemaAttrState;
typedef xmlSchemaAttrState *xmlSchemaAttrStatePtr;
struct _xmlSchemaAttrState {
    xmlSchemaAttrStatePtr next;
    xmlAttrPtr attr;
    int state;
    xmlSchemaAttributePtr decl;
    const xmlChar *value;
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
    xmlSchemaAttrStatePtr attr;
    /* xmlNodePtr scope; not used */
    int valueWS;
    int options;
    xmlNodePtr validationRoot;    
    xmlSchemaParserCtxtPtr pctxt;
    int xsiAssemble;
};

/*
 * These are the entries in the schemas importSchemas hash table
 */
typedef struct _xmlSchemaImport xmlSchemaImport;
typedef xmlSchemaImport *xmlSchemaImportPtr;
struct _xmlSchemaImport {
    const xmlChar *schemaLocation;
    xmlSchemaPtr schema; /* not used any more */
    xmlDocPtr doc;
    int isMain;
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

typedef struct _xmlSchemaParticle xmlSchemaParticle;
typedef xmlSchemaParticle *xmlSchemaParticlePtr;
struct _xmlSchemaParticle {
    xmlSchemaTypeType type;
    xmlSchemaParticlePtr next; /* the next particle if in a list */
    int minOccurs;
    int maxOccurs;
    xmlSchemaTypePtr term;
};


typedef struct _xmlSchemaModelGroup xmlSchemaModelGroup;
typedef xmlSchemaModelGroup *xmlSchemaModelGroupPtr;
struct _xmlSchemaModelGroup {
    xmlSchemaTypeType type;
    int compositor; /* one of all, choice or sequence */
    xmlSchemaParticlePtr particles; /* list of particles */
    xmlSchemaAnnotPtr annot;
};

typedef struct _xmlSchemaModelGroupDef xmlSchemaModelGroupDef;
typedef xmlSchemaModelGroupDef *xmlSchemaModelGroupDefPtr;
struct _xmlSchemaModelGroupDef {
    xmlSchemaTypeType type;
    const xmlChar *name;
    const xmlChar *targetNamespace;
    xmlSchemaModelGroupPtr modelGroup;
    xmlSchemaAnnotPtr annot;
};

/************************************************************************
 * 									*
 * 			Some predeclarations				*
 * 									*
 ************************************************************************/

static int xmlSchemaParseInclude(xmlSchemaParserCtxtPtr ctxt,
                                 xmlSchemaPtr schema,
                                 xmlNodePtr node);
static void
xmlSchemaTypeFixup(xmlSchemaTypePtr typeDecl,
                   xmlSchemaParserCtxtPtr ctxt, const xmlChar * name);
static const char *
xmlSchemaFacetTypeToString(xmlSchemaTypeType type);
static int
xmlSchemaValidateSimpleTypeValue(xmlSchemaValidCtxtPtr ctxt, 
				 xmlSchemaTypePtr type,
				 const xmlChar *value,
				 int fireErrors,				 
				 int applyFacets,
				 int normalize,
				 int checkNodes);
static int
xmlSchemaValidateElementByDeclaration(xmlSchemaValidCtxtPtr ctxt,
				      xmlSchemaElementPtr elemDecl); 
static int
xmlSchemaValidateElementByWildcard(xmlSchemaValidCtxtPtr ctxt,
				   xmlSchemaTypePtr type);
static int
xmlSchemaHasElemOrCharContent(xmlNodePtr node);
static int
xmlSchemaParseImport(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                     xmlNodePtr node);
static void
xmlSchemaCheckDefaults(xmlSchemaTypePtr typeDecl,
                       xmlSchemaParserCtxtPtr ctxt, const xmlChar * name);

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
        ctxt->err = XML_SCHEMAV_INTERNAL;
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
    /* Removed, since the old schema error codes have been 
    * substituted for the global error codes.
    *
    * error += XML_SCHEMAV_NOROOT - XML_SCHEMAS_ERR_NOROOT; 
    */
    __xmlRaiseError(schannel, channel, data, ctxt, node, XML_FROM_SCHEMASV,
                    error, XML_ERR_ERROR, NULL, 0,
                    (const char *) str1, (const char *) str2,
		    (const char *) str3, 0, 0,
                    msg, str1, str2, str3);
}

/**
 * xmlSchemaVErrExt:
 * @ctxt: the validation context
 * @node: the context node
 * @error: the error code 
 * @msg: the message
 * @str1:  extra parameter for the message display
 * @str2:  extra parameter for the message display
 * @str3:  extra parameter for the message display
 * @str4:  extra parameter for the message display
 * @str5:  extra parameter for the message display
 * 
 * Handle a validation error
 */
static void
xmlSchemaVErrExt(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr node, int error,
		 const char *msg, const xmlChar * str1, 
		 const xmlChar * str2, const xmlChar * str3, 
		 const xmlChar * str4, const xmlChar * str5)
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
     /* Removed, since the old schema error codes have been 
    * substituted for the global error codes.
    *
    * error += XML_SCHEMAV_NOROOT - XML_SCHEMAS_ERR_NOROOT;
    */
    __xmlRaiseError(schannel, channel, data, ctxt, node, XML_FROM_SCHEMASP,
                    error, XML_ERR_ERROR, NULL, 0, NULL, NULL, NULL, 0, 0, 
		    msg, str1, str2, str3, str4, str5);
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
    /* Removed, since the old schema error codes have been 
    * substituted for the global error codes.
    *
    * error += XML_SCHEMAV_NOROOT - XML_SCHEMAS_ERR_NOROOT;
    */
    __xmlRaiseError(schannel, channel, data, ctxt, node, XML_FROM_SCHEMASV,
                    error, XML_ERR_ERROR, NULL, 0,
                    (const char *) str1, (const char *) str2, NULL, 0, 0,
                    msg, str1, str2);
}

/**
 * xmlSchemaGetAttrName:
 * @attr:  the attribute declaration/use
 *
 * Returns the name of the attribute; if the attribute
 * is a reference, the name of the referenced global type will be returned.
 */
static const xmlChar *
xmlSchemaGetAttrName(xmlSchemaAttributePtr attr) 
{
    if (attr->ref != NULL) 
	return(attr->ref);
    else
	return(attr->name);	
}

/**
 * xmlSchemaGetAttrTargetNsURI:
 * @type:  the type (element or attribute)
 *
 * Returns the target namespace URI of the type; if the type is a reference,
 * the target namespace of the referenced type will be returned.
 */
static const xmlChar *
xmlSchemaGetAttrTargetNsURI(xmlSchemaAttributePtr attr)
{  
    if (attr->ref != NULL)
	return (attr->refNs);
    else
	return(attr->targetNamespace);  
}

/**
 * xmlSchemaFormatNsUriLocal:
 * @buf: the string buffer
 * @uri:  the namespace URI
 * @local: the local name
 *
 * Returns a representation of the given URI used
 * for error reports.
 *
 * Returns an empty string, if @ns is NULL, a formatted
 * string otherwise.
 */  
static const xmlChar*   
xmlSchemaFormatNsUriLocal(xmlChar **buf,
			   const xmlChar *uri, const xmlChar *local)
{
    if (*buf != NULL)
	xmlFree(*buf);
    if (uri == NULL) {
	*buf = xmlStrdup(BAD_CAST "{'");
	*buf = xmlStrcat(*buf, local);
    } else {
	*buf = xmlStrdup(BAD_CAST "{'");
	*buf = xmlStrcat(*buf, uri);
	*buf = xmlStrcat(*buf, BAD_CAST "', '");
	*buf = xmlStrcat(*buf, local);	
    }
    *buf = xmlStrcat(*buf, BAD_CAST "'}");
    return ((const xmlChar *) *buf);
}

/**
 * xmlSchemaFormatNsPrefixLocal:
 * @buf: the string buffer
 * @ns:  the namespace
 * @local: the local name
 *
 * Returns a representation of the given URI used
 * for error reports.
 *
 * Returns an empty string, if @ns is NULL, a formatted
 * string otherwise.
 */  
static const xmlChar*   
xmlSchemaFormatNsPrefixLocal(xmlChar **buf,
			      xmlNsPtr ns, const xmlChar *local)
{
    if (*buf != NULL) {
	xmlFree(*buf);
	*buf = NULL;
    }
    if ((ns == NULL) || (ns->prefix == NULL))
	return(local);
    else {
	*buf = xmlStrdup(ns->prefix);
	*buf = xmlStrcat(*buf, BAD_CAST ":");
	*buf = xmlStrcat(*buf, local);
    }
    return ((const xmlChar *) *buf);
}

/**
 * xmlSchemaFormatItemForReport:
 * @buf: the string buffer
 * @itemDes: the designation of the item
 * @itemName: the name of the item
 * @item: the item as an object 
 * @itemNode: the node of the item
 * @local: the local name
 * @parsing: if the function is used during the parse
 *
 * Returns a representation of the given item used
 * for error reports. 
 *
 * The following order is used to build the resulting 
 * designation if the arguments are not NULL:
 * 1a. If itemDes not NULL -> itemDes
 * 1b. If (itemDes not NULL) and (itemName not NULL)
 *     -> itemDes + itemName
 * 2. If the preceding was NULL and (item not NULL) -> item
 * 3. If the preceding was NULL and (itemNode not NULL) -> itemNode
 * 
 * If the itemNode is an attribute node, the name of the attribute
 * will be appended to the result.
 *
 * Returns the formatted string and sets @buf to the resulting value.
 */  
static xmlChar*   
xmlSchemaFormatItemForReport(xmlChar **buf,		     
		     const xmlChar *itemDes,
		     xmlSchemaTypePtr item,
		     xmlNodePtr itemNode,
		     int parsing)
{
    xmlChar *str = NULL;
    int named = 1;

    if (*buf != NULL) {
	xmlFree(*buf);
	*buf = NULL;
    }
            
    if (itemDes != NULL) {
	*buf = xmlStrdup(itemDes);	
    } else if (item != NULL) {
	if (item->type == XML_SCHEMA_TYPE_BASIC) {
	    if (item->builtInType == XML_SCHEMAS_ANYTYPE)
		*buf = xmlStrdup(BAD_CAST "'anyType'");
	    else if (item->builtInType == XML_SCHEMAS_ANYSIMPLETYPE)
		*buf = xmlStrdup(BAD_CAST "'anySimpleType'");
	    else {
		/* *buf = xmlStrdup(BAD_CAST "bi "); */
		/* *buf = xmlStrcat(*buf, xmlSchemaElemDesST); */
		*buf = xmlStrdup(BAD_CAST "'");
		*buf = xmlStrcat(*buf, item->name);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    }
	} else if (item->type == XML_SCHEMA_TYPE_SIMPLE) {
	    if (item->flags & XML_SCHEMAS_TYPE_GLOBAL) {
		*buf = xmlStrdup(xmlSchemaElemDesST);
		*buf = xmlStrcat(*buf, BAD_CAST " '");
		*buf = xmlStrcat(*buf, item->name);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    } else {
		*buf = xmlStrdup(xmlSchemaElemDesST);
		/* Local types will get to name
		*buf = xmlStrcat(*buf, BAD_CAST " ");
		*/
	    }
	} else if (item->type == XML_SCHEMA_TYPE_COMPLEX) {
	    if (item->flags & XML_SCHEMAS_TYPE_GLOBAL) {
		*buf = xmlStrdup(xmlSchemaElemDesCT);
		*buf = xmlStrcat(*buf, BAD_CAST " '");
		*buf = xmlStrcat(*buf, item->name);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    } else {
		*buf = xmlStrdup(xmlSchemaElemDesCT);
		/* Local types will get to name 
		*buf = xmlStrcat(*buf, BAD_CAST " ");
		*/
	    }
	} else if (item->type == XML_SCHEMA_TYPE_ATTRIBUTE) {
	    xmlSchemaAttributePtr attr;

	    attr = (xmlSchemaAttributePtr) item;	    
	    if ((attr->flags & XML_SCHEMAS_TYPE_GLOBAL) ||
		(attr->ref == NULL)) {
		*buf = xmlStrdup(xmlSchemaElemDesAttrDecl);
		*buf = xmlStrcat(*buf, BAD_CAST " '");
		*buf = xmlStrcat(*buf, attr->name);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    } else {
		*buf = xmlStrdup(xmlSchemaElemDesAttrRef);
		*buf = xmlStrcat(*buf, BAD_CAST " '");
		*buf = xmlStrcat(*buf, attr->refPrefix);
		*buf = xmlStrcat(*buf, BAD_CAST ":");
		*buf = xmlStrcat(*buf, attr->ref);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	   }		
	} else if (item->type == XML_SCHEMA_TYPE_ELEMENT) {
	    xmlSchemaElementPtr elem;

	    elem = (xmlSchemaElementPtr) item;	    
	    if ((elem->flags & XML_SCHEMAS_TYPE_GLOBAL) || 
		(elem->ref == NULL)) {
		*buf = xmlStrdup(xmlSchemaElemDesElemDecl);
		*buf = xmlStrcat(*buf, BAD_CAST " '");
		*buf = xmlStrcat(*buf, elem->name);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    } else {
		*buf = xmlStrdup(xmlSchemaElemDesElemRef);
		*buf = xmlStrcat(*buf, BAD_CAST " '");
		*buf = xmlStrcat(*buf, elem->refPrefix);
		*buf = xmlStrcat(*buf, BAD_CAST ":");
		*buf = xmlStrcat(*buf, elem->ref);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    }		
	} else
	    named = 0;
    } else 
	named = 0;

    if ((named == 0) && (itemNode != NULL)) {
	xmlNodePtr elem;

	if (itemNode->type == XML_ATTRIBUTE_NODE)
	    elem = itemNode->parent;
	else 
	    elem = itemNode;
	*buf = xmlStrdup(BAD_CAST "Element '");
	if (parsing)
	    *buf = xmlStrcat(*buf, elem->name);
	else
	    *buf = xmlStrcat(*buf, 
		xmlSchemaFormatNsPrefixLocal(&str, elem->ns, elem->name));
	*buf = xmlStrcat(*buf, BAD_CAST "'");
    }
    if ((itemNode != NULL) && (itemNode->type == XML_ATTRIBUTE_NODE)) {
	*buf = xmlStrcat(*buf, BAD_CAST ", attribute '");
	*buf = xmlStrcat(*buf, xmlSchemaFormatNsPrefixLocal(&str, 
	    itemNode->ns, itemNode->name));
	*buf = xmlStrcat(*buf, BAD_CAST "'");
    }
    FREE_AND_NULL(str);
    
    return (*buf);
}

/**
 * xmlSchemaPFormatItemDes:
 * @buf: the string buffer
 * @item: the item as a schema object
 * @itemNode: the item as a node
 *
 * If the pointer to @buf is not NULL and @but holds no value,
 * the value is set to a item designation using 
 * xmlSchemaFormatItemForReport. This one avoids adding
 * an attribute designation postfix.
 *
 * Returns a string of all enumeration elements.
 */
static void
xmlSchemaPRequestItemDes(xmlChar **buf,
		       xmlSchemaTypePtr item,
		       xmlNodePtr itemNode)
{
    if ((buf == 0) || (*buf != NULL)) 
	return;
    if (itemNode->type == XML_ATTRIBUTE_NODE)
	itemNode = itemNode->parent;
    xmlSchemaFormatItemForReport(buf, NULL, item, itemNode, 1);	
}

/**
 * xmlSchemaFormatFacetEnumSet:
 * @buf: the string buffer
 * @type: the type holding the enumeration facets
 *
 * Builds a string consisting of all enumeration elements.
 *
 * Returns a string of all enumeration elements.
 */
static const xmlChar *
xmlSchemaFormatFacetEnumSet(xmlChar **buf, xmlSchemaTypePtr type)
{
    xmlSchemaFacetLinkPtr link;

    if (*buf != NULL)
	xmlFree(*buf);    
    *buf = NULL;
    for (link = type->facetSet; link != NULL; link = link->next) {
	if (link->facet->type == XML_SCHEMA_FACET_ENUMERATION) {
	    if (*buf == NULL) {
		*buf = xmlStrdup(BAD_CAST "'");
		*buf = xmlStrcat(*buf, link->facet->value);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    } else {
		*buf = xmlStrcat(*buf, BAD_CAST ", '");
		*buf = xmlStrcat(*buf, link->facet->value);
		*buf = xmlStrcat(*buf, BAD_CAST "'");
	    }
	}
    }
    return ((const xmlChar *) *buf);
}

/**
 * xmlSchemaVFacetErr:
 * @ctxt:  the schema validation context
 * @error: the error code
 * @node: the node to be validated  
 * @value: the value of the node
 * @type: the type holding the facet
 * @facet: the facet
 * @message: the error message of NULL
 * @str1: extra data
 * @str2: extra data
 * @str3: extra data
 *
 * Reports a facet validation error.
 * TODO: Should this report the value of an element as well?
 */
static void
xmlSchemaVFacetErr(xmlSchemaValidCtxtPtr ctxt, 
		   xmlParserErrors error,
		   xmlNodePtr node,		   
		   const xmlChar *value,
		   unsigned long length,
		   xmlSchemaTypePtr type,
		   xmlSchemaFacetPtr facet,		   
		   const char *message,
		   const xmlChar *str1,
		   const xmlChar *str2,
		   const xmlChar *str3)
{
    xmlChar *str = NULL, *msg = NULL;
    xmlSchemaTypeType facetType;

    xmlSchemaFormatItemForReport(&msg, NULL, NULL, node, 0);
    msg = xmlStrcat(msg, BAD_CAST " [");
    msg = xmlStrcat(msg, xmlSchemaFormatItemForReport(&str, NULL, type, NULL, 0));
    msg = xmlStrcat(msg, BAD_CAST ", facet '");
    if (error == XML_SCHEMAV_CVC_ENUMERATION_VALID) {
	facetType = XML_SCHEMA_FACET_ENUMERATION;
	/*
	* If enumerations are validated, one must not expect the
	* facet to be given.
	*/	
    } else	
	facetType = facet->type;
    msg = xmlStrcat(msg, BAD_CAST xmlSchemaFacetTypeToString(facetType));
    msg = xmlStrcat(msg, BAD_CAST "']: ");
    if (message == NULL) {
	/*
	* Use a default message.
	*/
	if ((facetType == XML_SCHEMA_FACET_LENGTH) ||
	    (facetType == XML_SCHEMA_FACET_MINLENGTH) ||
	    (facetType == XML_SCHEMA_FACET_MAXLENGTH)) {

	    char len[25], actLen[25];

	    /* FIXME, TODO: What is the max expected string length of the
	    * this value?
	    */
	    if (node->type == XML_ATTRIBUTE_NODE)
		msg = xmlStrcat(msg, BAD_CAST "The value '%s' has a length of '%s'; ");
	    else
		msg = xmlStrcat(msg, BAD_CAST "The value has a length of '%s'; ");

	    snprintf(len, 24, "%lu", xmlSchemaGetFacetValueAsULong(facet));
	    snprintf(actLen, 24, "%lu", length);

	    if (facetType == XML_SCHEMA_FACET_LENGTH)
		msg = xmlStrcat(msg, 
		BAD_CAST "this differs from the allowed length of '%s'.\n");     
	    else if (facetType == XML_SCHEMA_FACET_MAXLENGTH)
		msg = xmlStrcat(msg, 
		BAD_CAST "this exceeds the allowed maximum length of '%s'.\n");
	    else if (facetType == XML_SCHEMA_FACET_MINLENGTH)
		msg = xmlStrcat(msg, 
		BAD_CAST "this underruns the allowed minimum length of '%s'.\n");
	    
	    if (node->type == XML_ATTRIBUTE_NODE)
		xmlSchemaVErrExt(ctxt, node, error,
		    (const char *) msg,
		    value, (const xmlChar *) actLen, (const xmlChar *) len,
		    NULL, NULL);
	    else 
		xmlSchemaVErr(ctxt, node, error,  
		    (const char *) msg,
		    (const xmlChar *) actLen, (const xmlChar *) len);
	
	} else if (facetType == XML_SCHEMA_FACET_ENUMERATION) {
	    msg = xmlStrcat(msg, BAD_CAST "The value '%s' is not an element "
		"of the set {%s}.\n");
	    xmlSchemaVErr(ctxt, node, error, (const char *) msg, value, 
		xmlSchemaFormatFacetEnumSet(&str, type));
	} else if (facetType == XML_SCHEMA_FACET_PATTERN) {
	    msg = xmlStrcat(msg, BAD_CAST "The value '%s' is not accepted "
		"by the pattern '%s'.\n");
	    xmlSchemaVErr(ctxt, node, error, (const char *) msg, value, 
		facet->value);	       
	} else if (node->type == XML_ATTRIBUTE_NODE) {		
	    msg = xmlStrcat(msg, BAD_CAST "The value '%s' is not facet-valid.\n");
	    xmlSchemaVErr(ctxt, node, error, (const char *) msg, value, NULL);
	} else {	    
	    msg = xmlStrcat(msg, BAD_CAST "The value is not facet-valid.\n");
	    xmlSchemaVErr(ctxt, node, error, (const char *) msg, NULL, NULL);
	}
    } else {
	msg = xmlStrcat(msg, (const xmlChar *) message);
	msg = xmlStrcat(msg, BAD_CAST ".\n");
	xmlSchemaVErr3(ctxt, node, error, (const char *) msg, str1, str2, str3);
    }        
    FREE_AND_NULL(str)
    xmlFree(msg);
}

/**
 * xmlSchemaVSimpleTypeErr:
 * @ctxt:  the schema validation context
 * @error: the error code
 * @type: the type used for validation
 * @node: the node containing the validated value
 * @value: the validated value
 *
 * Reports a simple type validation error.
 * TODO: Should this report the value of an element as well?
 */
static void
xmlSchemaVSimpleTypeErr(xmlSchemaValidCtxtPtr ctxt, 
			xmlParserErrors error,			
			xmlNodePtr node,
			const xmlChar *value,
			xmlSchemaTypePtr type)
{
    xmlChar *str = NULL, *msg = NULL;
    
    xmlSchemaFormatItemForReport(&msg, NULL,  NULL, node, 0);    
    msg = xmlStrcat(msg, BAD_CAST " [");
    msg = xmlStrcat(msg, xmlSchemaFormatItemForReport(&str, NULL, type, NULL, 0));
    if (node->type == XML_ATTRIBUTE_NODE) {
	msg = xmlStrcat(msg, BAD_CAST "]: The value '%s' is not valid.\n");
	xmlSchemaVErr(ctxt, node, error, (const char *) msg, value, NULL);
    } else {
	msg = xmlStrcat(msg, BAD_CAST "]: The character content is not valid.\n");
	xmlSchemaVErr(ctxt, node, error, (const char *) msg, NULL, NULL);
    }
    FREE_AND_NULL(str)	
    xmlFree(msg);
}

/**
 * xmlSchemaVComplexTypeErr:
 * @ctxt:  the schema validation context
 * @error: the error code
 * @node: the node containing the validated value
 * @type: the complex type used for validation
 * @message: the error message
 *
 * Reports a complex type validation error.
 */
static void
xmlSchemaVComplexTypeErr(xmlSchemaValidCtxtPtr ctxt, 
			xmlParserErrors error,
			xmlNodePtr node,
			xmlSchemaTypePtr type,			
			const char *message)
{
    xmlChar *str = NULL, *msg = NULL;
    
    xmlSchemaFormatItemForReport(&msg, NULL,  NULL, node, 0);
    /* Specify the complex type only if it is global. */
    if ((type != NULL) && (type->flags & XML_SCHEMAS_TYPE_GLOBAL)) {
	msg = xmlStrcat(msg, BAD_CAST " [");
	msg = xmlStrcat(msg, xmlSchemaFormatItemForReport(&str, NULL, type, NULL, 0));
	msg = xmlStrcat(msg, BAD_CAST "]");
    }
    msg = xmlStrcat(msg, BAD_CAST ": %s.\n");   
    xmlSchemaVErr(ctxt, node, error, (const char *) msg,
	(const xmlChar *) message, NULL);
    FREE_AND_NULL(str)	
    xmlFree(msg);
}

/**
 * xmlSchemaVComplexTypeElemErr:
 * @ctxt:  the schema validation context
 * @error: the error code
 * @node: the node containing the validated value
 * @type: the complex type used for validation
 * @message: the error message
 *
 * Reports a complex type validation error.
 */
static void
xmlSchemaVComplexTypeElemErr(xmlSchemaValidCtxtPtr ctxt, 
			xmlParserErrors error,
			xmlNodePtr node,
			xmlSchemaTypePtr type,			
			const char *message,
			int nbval,
			int nbneg,
			xmlChar **values)
{
    xmlChar *str = NULL, *msg = NULL;
    xmlChar *localName, *nsName;
    const xmlChar *cur, *end;
    int i;
    
    xmlSchemaFormatItemForReport(&msg, NULL,  NULL, node, 0);
    /* Specify the complex type only if it is global. */
    if ((type != NULL) && (type->flags & XML_SCHEMAS_TYPE_GLOBAL)) {
	msg = xmlStrcat(msg, BAD_CAST " [");
	msg = xmlStrcat(msg, xmlSchemaFormatItemForReport(&str, NULL, type, NULL, 0));
	msg = xmlStrcat(msg, BAD_CAST "]");
	FREE_AND_NULL(str)
    }
    msg = xmlStrcat(msg, BAD_CAST ": ");
    msg = xmlStrcat(msg, (const xmlChar *) message);
    /*
    * Note that is does not make sense to report that we have a
    * wildcard here, since the wildcard might be unfolded into
    * multiple transitions.
    */
    if (nbval + nbneg > 0) {
	if (nbval + nbneg > 1) {
	    str = xmlStrdup(BAD_CAST ". Expected is one of ( ");
	} else
	    str = xmlStrdup(BAD_CAST ". Expected is ( ");
	nsName = NULL;
    	    
	for (i = 0; i < nbval + nbneg; i++) {
	    cur = values[i];
	    /*
	    * Get the local name.
	    */
	    localName = NULL;
	    
	    end = cur;
	    if (*end == '*') {
		localName = xmlStrdup(BAD_CAST "*");
		*end++;
	    } else {
		while ((*end != 0) && (*end != '|'))
		    end++;
		localName = xmlStrncat(localName, BAD_CAST cur, end - cur);
	    }		
	    if (*end != 0) {		    
		*end++;
		/*
		* Skip "*|*" if they come with negated expressions, since
		* they represent the same negated wildcard.
		*/
		if ((nbneg == 0) || (*end != '*') || (*localName != '*')) {
		    /*
		    * Get the namespace name.
		    */
		    cur = end;
		    if (*end == '*') {
			nsName = xmlStrdup(BAD_CAST "{*}");
		    } else {
			while (*end != 0)
			    end++;
			
			if (i >= nbval)
			    nsName = xmlStrdup(BAD_CAST "{##other:");
			else
			    nsName = xmlStrdup(BAD_CAST "{");
			
			nsName = xmlStrncat(nsName, BAD_CAST cur, end - cur);
			nsName = xmlStrcat(nsName, BAD_CAST "}");
		    }
		    str = xmlStrcat(str, BAD_CAST nsName);
		    FREE_AND_NULL(nsName)
		} else {
		    FREE_AND_NULL(localName);
		    continue;
		}
	    }	        
	    str = xmlStrcat(str, BAD_CAST localName);
	    FREE_AND_NULL(localName);
		
	    if (i < nbval + nbneg -1)
		str = xmlStrcat(str, BAD_CAST ", ");
	}	
	str = xmlStrcat(str, BAD_CAST " )");
	msg = xmlStrcat(msg, BAD_CAST str);
	FREE_AND_NULL(str)
    }    
    msg = xmlStrcat(msg, BAD_CAST ".\n");
    xmlSchemaVErr(ctxt, node, error, (const char *) msg, NULL, NULL);    	
    xmlFree(msg);
}

/**
 * xmlSchemaPMissingAttrErr:
 * @ctxt: the schema validation context
 * @ownerDes: the designation of  the owner
 * @ownerName: the name of the owner
 * @ownerItem: the owner as a schema object
 * @ownerElem: the owner as an element node
 * @node: the parent element node of the missing attribute node
 * @type: the corresponding type of the attribute node
 *
 * Reports an illegal attribute.
 */
static void
xmlSchemaPMissingAttrErr(xmlSchemaParserCtxtPtr ctxt,
			 xmlParserErrors error,			 
			 xmlChar **ownerDes,
			 xmlSchemaTypePtr ownerItem,
			 xmlNodePtr ownerElem,
			 const char *name,
			 const char *message)
{
    xmlChar *des = NULL;

    if (ownerDes == NULL)
	xmlSchemaFormatItemForReport(&des, NULL, ownerItem, ownerElem, 1);
    else if (*ownerDes == NULL) {
	xmlSchemaFormatItemForReport(ownerDes, NULL, ownerItem, ownerElem, 1);
	des = *ownerDes;
    } else 
	des = *ownerDes;      
    if (message != NULL)
	xmlSchemaPErr(ctxt, ownerElem, error, "%s: %s.\n", BAD_CAST des, BAD_CAST message);
    else	
	xmlSchemaPErr(ctxt, ownerElem, error, 
	    "%s: The attribute '%s' is required but missing.\n", 
	    BAD_CAST des, BAD_CAST name);
    if (ownerDes == NULL)
	FREE_AND_NULL(des);
}

/**
 * xmlSchemaCompTypeToString:
 * @type: the type of the schema item
 *
 * Returns the component name of a schema item.
 */
static const char *
xmlSchemaCompTypeToString(xmlSchemaTypeType type)
{
    switch (type) {
	case XML_SCHEMA_TYPE_SIMPLE:
	    return("simple type definition");
	case XML_SCHEMA_TYPE_COMPLEX:
	    return("complex type definition");
	case XML_SCHEMA_TYPE_ELEMENT:
	    return("element declaration");
	case XML_SCHEMA_TYPE_ATTRIBUTE:
	    return("attribute declaration");
	case XML_SCHEMA_TYPE_GROUP:
	    return("model group definition");
	case XML_SCHEMA_TYPE_ATTRIBUTEGROUP:
	    return("attribute group definition");
	case XML_SCHEMA_TYPE_NOTATION:
	    return("notation declaration");
	default:
	    return("Not a schema component");
    }
}
/**
 * xmlSchemaPResCompAttrErr:
 * @ctxt: the schema validation context
 * @error: the error code
 * @ownerDes: the designation of  the owner
 * @ownerItem: the owner as a schema object
 * @ownerElem: the owner as an element node
 * @name: the name of the attribute holding the QName 
 * @refName: the referenced local name
 * @refURI: the referenced namespace URI
 * @message: optional message
 *
 * Used to report QName attribute values that failed to resolve
 * to schema components.
 */
static void
xmlSchemaPResCompAttrErr(xmlSchemaParserCtxtPtr ctxt,
			 xmlParserErrors error,			 
			 xmlChar **ownerDes,
			 xmlSchemaTypePtr ownerItem,
			 xmlNodePtr ownerElem,
			 const char *name,
			 const xmlChar *refName,
			 const xmlChar *refURI,
			 xmlSchemaTypeType refType,
			 const char *refTypeStr)
{
    xmlChar *des = NULL, *strA = NULL;

    if (ownerDes == NULL)
	xmlSchemaFormatItemForReport(&des, NULL, ownerItem, ownerElem, 1);
    else if (*ownerDes == NULL) {
	xmlSchemaFormatItemForReport(ownerDes, NULL, ownerItem, ownerElem, 1);
	des = *ownerDes;
    } else
	des = *ownerDes;
    if (refTypeStr == NULL)
	refTypeStr = xmlSchemaCompTypeToString(refType);    
	xmlSchemaPErrExt(ctxt, ownerElem, error, 
	    NULL, NULL, NULL,
	    "%s, attribute '%s': The QName value %s does not resolve to a(n) "
	    "%s.\n", BAD_CAST des, BAD_CAST name, 
	    xmlSchemaFormatNsUriLocal(&strA, refURI, refName), 
	    BAD_CAST refTypeStr, NULL);
    if (ownerDes == NULL)
	FREE_AND_NULL(des)
    FREE_AND_NULL(strA)
}

/**
 * xmlSchemaPCustomAttrErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @ownerDes: the designation of the owner
 * @ownerItem: the owner as a schema object
 * @attr: the illegal attribute node 
 *
 * Reports an illegal attribute during the parse.
 */
static void
xmlSchemaPCustomAttrErr(xmlSchemaParserCtxtPtr ctxt,
			xmlParserErrors error,	
			xmlChar **ownerDes,
			xmlSchemaTypePtr ownerItem,
			xmlAttrPtr attr,
			const char *msg)
{
    xmlChar *des = NULL;

    if (ownerDes == NULL)
	xmlSchemaFormatItemForReport(&des, NULL, ownerItem, attr->parent, 1);
    else if (*ownerDes == NULL) {
	xmlSchemaFormatItemForReport(ownerDes, NULL, ownerItem, attr->parent, 1);
	des = *ownerDes;
    } else 
	des = *ownerDes;    
    xmlSchemaPErrExt(ctxt, (xmlNodePtr) attr, error, NULL, NULL, NULL,
	"%s, attribute '%s': %s.\n", 
	BAD_CAST des, attr->name, (const xmlChar *) msg, NULL, NULL);
    if (ownerDes == NULL)
	FREE_AND_NULL(des);
}

/**
 * xmlSchemaPIllegalAttrErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @ownerDes: the designation of the attribute's owner
 * @ownerItem: the attribute's owner item
 * @attr: the illegal attribute node 
 *
 * Reports an illegal attribute during the parse.
 */
static void
xmlSchemaPIllegalAttrErr(xmlSchemaParserCtxtPtr ctxt,
			 xmlParserErrors error,	
			 xmlChar **ownerDes,
			 xmlSchemaTypePtr ownerItem,
			 xmlAttrPtr attr)
{
    xmlChar *des = NULL, *strA = NULL;

    if (ownerDes == NULL)
	xmlSchemaFormatItemForReport(&des, NULL, ownerItem, attr->parent, 1);
    else if (*ownerDes == NULL) {
	xmlSchemaFormatItemForReport(ownerDes, NULL, ownerItem, attr->parent, 1);
	des = *ownerDes;
    } else 
	des = *ownerDes;    
    xmlSchemaPErr(ctxt, (xmlNodePtr) attr, error, 
	"%s: The attribute '%s' is not allowed.\n", BAD_CAST des, 
	xmlSchemaFormatNsPrefixLocal(&strA, attr->ns, attr->name));
    if (ownerDes == NULL)
	FREE_AND_NULL(des);
    FREE_AND_NULL(strA);
}

/**
 * xmlSchemaPAquireDes:
 * @des: the first designation 
 * @itemDes: the second designation
 * @item: the schema item 
 * @itemElem: the node of the schema item
 *
 * Creates a designation for an item.
 */
static void
xmlSchemaPAquireDes(xmlChar **des,
		    xmlChar **itemDes, 
		    xmlSchemaTypePtr item,
		    xmlNodePtr itemElem)
{
    if (itemDes == NULL)
	xmlSchemaFormatItemForReport(des, NULL, item, itemElem, 1);
    else if (*itemDes == NULL) {
	xmlSchemaFormatItemForReport(itemDes, NULL, item, itemElem, 1);
	*des = *itemDes;
    } else 
	*des = *itemDes;  
}

/**
 * xmlSchemaPCustomErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @itemDes: the designation of the schema item
 * @item: the schema item
 * @itemElem: the node of the schema item
 * @message: the error message
 * @str1: an optional param for the error message
 * @str2: an optional param for the error message
 * @str3: an optional param for the error message
 *
 * Reports an error during parsing.
 */
static void
xmlSchemaPCustomErrExt(xmlSchemaParserCtxtPtr ctxt,
		    xmlParserErrors error,	
		    xmlChar **itemDes,
		    xmlSchemaTypePtr item,
		    xmlNodePtr itemElem,
		    const char *message,
		    const xmlChar *str1,
		    const xmlChar *str2,
		    const xmlChar *str3)
{
    xmlChar *des = NULL, *msg = NULL;

    xmlSchemaPAquireDes(&des, itemDes, item, itemElem);   
    msg = xmlStrdup(BAD_CAST "%s: ");
    msg = xmlStrcat(msg, (const xmlChar *) message);
    msg = xmlStrcat(msg, BAD_CAST ".\n");
    if ((itemElem == NULL) && (item != NULL))
	itemElem = item->node;
    xmlSchemaPErrExt(ctxt, itemElem, error, NULL, NULL, NULL, 
	(const char *) msg, BAD_CAST des, str1, str2, str3, NULL);
    if (itemDes == NULL)
	FREE_AND_NULL(des);
    FREE_AND_NULL(msg);
}

/**
 * xmlSchemaPCustomErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @itemDes: the designation of the schema item
 * @item: the schema item
 * @itemElem: the node of the schema item
 * @message: the error message
 * @str1: the optional param for the error message
 *
 * Reports an error during parsing.
 */
static void
xmlSchemaPCustomErr(xmlSchemaParserCtxtPtr ctxt,
		    xmlParserErrors error,	
		    xmlChar **itemDes,
		    xmlSchemaTypePtr item,
		    xmlNodePtr itemElem,
		    const char *message,
		    const xmlChar *str1)
{
    xmlSchemaPCustomErrExt(ctxt, error, itemDes, item, itemElem, message,
	str1, NULL, NULL);
}

/**
 * xmlSchemaPAttrUseErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @itemDes: the designation of the schema type
 * @item: the schema type
 * @itemElem: the node of the schema type
 * @attr: the invalid schema attribute
 * @message: the error message
 * @str1: the optional param for the error message
 *
 * Reports an attribute use error during parsing.
 */
static void
xmlSchemaPAttrUseErr(xmlSchemaParserCtxtPtr ctxt,
		    xmlParserErrors error,	
		    xmlChar **itemDes,
		    xmlSchemaTypePtr item,
		    xmlNodePtr itemElem,
		    const xmlSchemaAttributePtr attr,
		    const char *message,
		    const xmlChar *str1)
{
    xmlChar *des = NULL, *strA = NULL, *msg = NULL;

    xmlSchemaPAquireDes(&des, itemDes, item, itemElem);
    xmlSchemaFormatNsUriLocal(&strA, xmlSchemaGetAttrTargetNsURI(attr), 
	xmlSchemaGetAttrName(attr));
    msg = xmlStrdup(BAD_CAST "%s, attr. use %s: ");
    msg = xmlStrcat(msg, (const xmlChar *) message);
    msg = xmlStrcat(msg, BAD_CAST ".\n");
    if ((itemElem == NULL) && (item != NULL))
	itemElem = item->node;
    xmlSchemaPErrExt(ctxt, itemElem, error, NULL, NULL, NULL, 
	(const char *) msg, BAD_CAST des, BAD_CAST strA, str1, NULL, NULL);
    if (itemDes == NULL)
	FREE_AND_NULL(des);
    FREE_AND_NULL(strA);
    xmlFree(msg);
}

/**
 * xmlSchemaPIllegalFacetAtomicErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @itemDes: the designation of the type
 * @item: the schema type
 * @baseItem: the base type of type
 * @facet: the illegal facet
 *
 * Reports an illegal facet for atomic simple types.
 */
static void
xmlSchemaPIllegalFacetAtomicErr(xmlSchemaParserCtxtPtr ctxt,
			  xmlParserErrors error,	
			  xmlChar **itemDes,
			  xmlSchemaTypePtr item,
			  xmlSchemaTypePtr baseItem,
			  xmlSchemaFacetPtr facet)
{
    xmlChar *des = NULL, *strT = NULL;

    xmlSchemaPAquireDes(&des, itemDes, item, item->node);
    xmlSchemaPErrExt(ctxt, item->node, error, NULL, NULL, NULL,
	"%s: The facet '%s' is not allowed on types derived from the "
	"type %s.\n",
	BAD_CAST des, BAD_CAST xmlSchemaFacetTypeToString(facet->type),
	xmlSchemaFormatItemForReport(&strT, NULL, baseItem, NULL, 1),
	NULL, NULL);
    if (itemDes == NULL)
	FREE_AND_NULL(des);
    FREE_AND_NULL(strT);
}

/**
 * xmlSchemaPIllegalFacetListUnionErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @itemDes: the designation of the schema item involved
 * @item: the schema item involved
 * @facet: the illegal facet
 *
 * Reports an illegal facet for <list> and <union>.
 */
static void
xmlSchemaPIllegalFacetListUnionErr(xmlSchemaParserCtxtPtr ctxt,
			  xmlParserErrors error,	
			  xmlChar **itemDes,
			  xmlSchemaTypePtr item,
			  xmlSchemaFacetPtr facet)
{
    xmlChar *des = NULL, *strT = NULL;

    xmlSchemaPAquireDes(&des, itemDes, item, item->node);
    xmlSchemaPErr(ctxt, item->node, error, 
	"%s: The facet '%s' is not allowed.\n", 
	BAD_CAST des, BAD_CAST xmlSchemaFacetTypeToString(facet->type));
    if (itemDes == NULL)
	FREE_AND_NULL(des);
    FREE_AND_NULL(strT);
}

/**
 * xmlSchemaPMutualExclAttrErr:
 * @ctxt: the schema validation context
 * @error: the error code
 * @elemDes: the designation of the parent element node
 * @attr: the bad attribute node
 * @type: the corresponding type of the attribute node
 *
 * Reports an illegal attribute.
 */
static void
xmlSchemaPMutualExclAttrErr(xmlSchemaParserCtxtPtr ctxt,
			 xmlParserErrors error,
			 xmlChar **ownerDes,
			 xmlSchemaTypePtr ownerItem,
			 xmlAttrPtr attr,			 
			 const char *name1,
			 const char *name2)
{
    xmlChar *des = NULL;

    if (ownerDes == NULL)
	xmlSchemaFormatItemForReport(&des, NULL, ownerItem, attr->parent, 1);	
    else if (*ownerDes == NULL) {
	xmlSchemaFormatItemForReport(ownerDes, NULL, ownerItem, attr->parent, 1);
	des = *ownerDes;
    } else 
	des = *ownerDes;  
    xmlSchemaPErrExt(ctxt, (xmlNodePtr) attr, error, NULL, NULL, NULL,
	"%s: The attributes '%s' and '%s' are mutually exclusive.\n", 
	BAD_CAST des, BAD_CAST name1, BAD_CAST name2, NULL, NULL);
    if (ownerDes == NULL)
	FREE_AND_NULL(des)
}

/**
 * xmlSchemaPSimpleTypeErr:
 * @ctxt:  the schema validation context
 * @error: the error code
 * @type: the type specifier
 * @ownerDes: the designation of the owner
 * @ownerItem: the schema object if existent 
 * @node: the validated node
 * @value: the validated value
 *
 * Reports a simple type validation error.
 * TODO: Should this report the value of an element as well?
 */
static void
xmlSchemaPSimpleTypeErr(xmlSchemaParserCtxtPtr ctxt, 
			xmlParserErrors error,
			xmlChar **ownerDes,
			xmlSchemaTypePtr ownerItem,
			xmlNodePtr node,
			xmlSchemaTypePtr type,
			const char *typeDes,
			const xmlChar *value,
			const char *message,
			const xmlChar *str1,
			const xmlChar *str2)
{
    xmlChar *des = NULL, *strA = NULL, *strT = NULL;    
    
    if (ownerDes == NULL)
	xmlSchemaPRequestItemDes(&des, ownerItem, node);
    else if (*ownerDes == NULL) {
	xmlSchemaPRequestItemDes(ownerDes, ownerItem, node);
	des = *ownerDes;
    } else 
	des = *ownerDes;   
    if (type != NULL)
	typeDes = (const char *) xmlSchemaFormatItemForReport(&strT, NULL, type, NULL, 1);
    if (message == NULL) {
	/*
	* Use default messages.
	*/
	if (node->type == XML_ATTRIBUTE_NODE) {
	    xmlSchemaPErrExt(ctxt, node, error, NULL, NULL, NULL,
		"%s, attribute '%s' [%s]: The value '%s' is not "
		"valid.\n", 
		BAD_CAST des, xmlSchemaFormatNsPrefixLocal(&strA, node->ns, 
		node->name), BAD_CAST typeDes, value, NULL);
	} else {
	    xmlSchemaPErr(ctxt, node, error, 
		"%s [%s]: The character content is not valid.\n",
		BAD_CAST des, BAD_CAST typeDes);
	}
    } else {
	xmlChar *msg;

	msg = xmlStrdup(BAD_CAST "%s");
	if (node->type == XML_ATTRIBUTE_NODE)
	    msg = xmlStrcat(msg, BAD_CAST ", attribute '%s'");
	msg = xmlStrcat(msg, BAD_CAST " [%s]: ");
	msg = xmlStrcat(msg, (const xmlChar *) message);
	msg = xmlStrcat(msg, BAD_CAST ".\n");
	if (node->type == XML_ATTRIBUTE_NODE) {
	    xmlSchemaPErrExt(ctxt, node, error, NULL, NULL, NULL,
		(const char *) msg, 
		BAD_CAST des, xmlSchemaFormatNsPrefixLocal(&strA, 
		node->ns, node->name), BAD_CAST typeDes, str1, str2);
	} else {
	    xmlSchemaPErrExt(ctxt, node, error, NULL, NULL, NULL,
		(const char *) msg, 
		BAD_CAST des, BAD_CAST typeDes, str1, str2, NULL);
	}
	xmlFree(msg);
    }
    /* Cleanup. */
    FREE_AND_NULL(strA)
    FREE_AND_NULL(strT)
    if (ownerDes == NULL)
	FREE_AND_NULL(des)
}

/**
 * xmlSchemaPContentErr:
 * @ctxt: the schema parser context
 * @error: the error code
 * @onwerDes: the designation of the holder of the content
 * @ownerItem: the owner item of the holder of the content
 * @ownerElem: the node of the holder of the content
 * @child: the invalid child node
 * @message: the optional error message
 * @content: the optional string describing the correct content
 *
 * Reports an error concerning the content of a schema element.
 */
static void
xmlSchemaPContentErr(xmlSchemaParserCtxtPtr ctxt, 
		     xmlParserErrors error,
		     xmlChar **ownerDes,
		     xmlSchemaTypePtr ownerItem,
		     xmlNodePtr ownerElem,		     
		     xmlNodePtr child,
		     const char *message,
		     const char *content)
{
    xmlChar *des = NULL;
    
    if (ownerDes == NULL)
	xmlSchemaFormatItemForReport(&des, NULL, ownerItem, ownerElem, 1);
    else if (*ownerDes == NULL) {
	xmlSchemaFormatItemForReport(ownerDes, NULL, ownerItem, ownerElem, 1);
	des = *ownerDes;
    } else 
	des = *ownerDes;   
    if (message != NULL)
	xmlSchemaPErr2(ctxt, ownerElem, child, error, 
	    "%s: %s.\n", 
	    BAD_CAST des, BAD_CAST message);
    else {
	if (content != NULL) {
	    xmlSchemaPErr2(ctxt, ownerElem, child, error, 
		"%s: The content is not valid. Expected is %s.\n", 
		BAD_CAST des, BAD_CAST content);
	} else {
	    xmlSchemaPErr2(ctxt, ownerElem, child, error, 
		"%s: The content is not valid.\n", 
		BAD_CAST des, NULL);
	}
    }
    if (ownerDes == NULL)
	FREE_AND_NULL(des)
}   

/**
 * xmlSchemaVIllegalAttrErr:
 * @ctxt: the schema validation context
 * @error: the error code
 * @attr: the illegal attribute node
 *
 * Reports an illegal attribute.
 */
static void
xmlSchemaVIllegalAttrErr(xmlSchemaValidCtxtPtr ctxt,
			 xmlParserErrors error,
			 xmlAttrPtr attr)
{
    xmlChar *strE = NULL, *strA = NULL;
    
    xmlSchemaVErr(ctxt, (xmlNodePtr) attr, 	
	error,
	/* XML_SCHEMAS_ERR_ATTRUNKNOWN, */
	"%s: The attribute '%s' is not allowed.\n",
	xmlSchemaFormatItemForReport(&strE, NULL, NULL, attr->parent, 0),
	xmlSchemaFormatNsPrefixLocal(&strA, attr->ns, attr->name));
    FREE_AND_NULL(strE)
    FREE_AND_NULL(strA)
}


static int
xmlSchemaIsGlobalItem(xmlSchemaTypePtr item)
{
    switch (item->type) {
	case XML_SCHEMA_TYPE_COMPLEX:
	case XML_SCHEMA_TYPE_SIMPLE:
	case XML_SCHEMA_TYPE_GROUP:
	    if (item->flags & XML_SCHEMAS_TYPE_GLOBAL)
		return(1);
	    break;
	case XML_SCHEMA_TYPE_ELEMENT:
	    if ( ((xmlSchemaElementPtr) item)->flags & 
		XML_SCHEMAS_ELEM_GLOBAL)
		return(1);
	    break;
	case XML_SCHEMA_TYPE_ATTRIBUTE:
	    if ( ((xmlSchemaAttributePtr) item)->flags & 
		XML_SCHEMAS_ATTR_GLOBAL)
		return(1);
	    break;
	/* Note that attribute groups are always global. */
	default:
	    return(1);
    }
    return (0);
}

/**
 * xmlSchemaVCustomErr:
 * @ctxt: the schema validation context
 * @error: the error code
 * @node: the validated node
 * @type: the schema type of the validated node
 * @message: the error message
 * @str1: the optional param for the message
 *
 * Reports a validation error.
 */
static void
xmlSchemaVCustomErr(xmlSchemaValidCtxtPtr ctxt,
		    xmlParserErrors error,			    
		    xmlNodePtr node,
		    xmlSchemaTypePtr type,
		    const char *message,
		    const xmlChar *str1)
{
    xmlChar *msg = NULL, *str = NULL;
    
    if (node == NULL) {
	xmlSchemaVErr(ctxt, NULL,
	    XML_SCHEMAV_INTERNAL,
	    "Internal error: xmlSchemaVCustomErr, no node "
	    "given.\n", NULL, NULL);
	return;
    }
    /* TODO: Are the HTML and DOCB doc nodes expected here? */
    if (node->type != XML_DOCUMENT_NODE) {
	xmlSchemaFormatItemForReport(&msg, NULL, NULL, node, 0);
	if ((type != NULL) && (xmlSchemaIsGlobalItem(type))) {
	    msg = xmlStrcat(msg, BAD_CAST " [");
	    msg = xmlStrcat(msg, xmlSchemaFormatItemForReport(&str, NULL, type, NULL, 0));
	    msg = xmlStrcat(msg, BAD_CAST "]");
	}
	msg = xmlStrcat(msg, BAD_CAST ": ");
    } else
	msg = xmlStrdup((const xmlChar *) "");
    msg = xmlStrcat(msg, (const xmlChar *) message);
    msg = xmlStrcat(msg, BAD_CAST ".\n");   
    xmlSchemaVErr(ctxt, node, error, (const char *) msg, str1, NULL);
    FREE_AND_NULL(msg)
    FREE_AND_NULL(str)
}

/**
 * xmlSchemaWildcardPCToString:
 * @pc: the type of processContents
 *
 * Returns a string representation of the type of 
 * processContents.
 */
static const char *
xmlSchemaWildcardPCToString(int pc)
{
    switch (pc) {
	case XML_SCHEMAS_ANY_SKIP:
	    return ("skip");
	case XML_SCHEMAS_ANY_LAX:
	    return ("lax");
	case XML_SCHEMAS_ANY_STRICT:
	    return ("strict");
	default:
	    return ("invalid process contents");
    }
}

/**
 * xmlSchemaVWildcardErr:
 * @ctxt: the schema validation context
 * @error: the error code
 * @node: the validated node
 * @wild: the wildcard used
 * @message: the error message
 *
 * Reports an validation-by-wildcard error.
 */
static void
xmlSchemaVWildcardErr(xmlSchemaValidCtxtPtr ctxt,
		    xmlParserErrors error,			    
		    xmlNodePtr node,
		    xmlSchemaWildcardPtr wild,
		    const char *message)
{
    xmlChar *des = NULL, *msg = NULL;

    xmlSchemaFormatItemForReport(&des, NULL, NULL, node, 0);
    msg = xmlStrdup(BAD_CAST "%s, [");
    msg = xmlStrcat(msg, BAD_CAST xmlSchemaWildcardPCToString(wild->processContents));
    msg = xmlStrcat(msg, BAD_CAST " wildcard]: ");
    msg = xmlStrcat(msg, (const xmlChar *) message);
    msg = xmlStrcat(msg, BAD_CAST ".\n");
    xmlSchemaVErr(ctxt, node, error, (const char *) msg, BAD_CAST des, NULL);
    FREE_AND_NULL(des);
    FREE_AND_NULL(msg);
}

/**
 * xmlSchemaVMissingAttrErr:
 * @ctxt: the schema validation context
 * @node: the parent element node of the missing attribute node
 * @type: the corresponding type of the attribute node
 *
 * Reports an illegal attribute.
 */
static void
xmlSchemaVMissingAttrErr(xmlSchemaValidCtxtPtr ctxt,
			 xmlNodePtr elem,
			 xmlSchemaAttributePtr type)
{
    const xmlChar *name, *uri;
    xmlChar *strE = NULL, *strA = NULL;

    if (type->ref != NULL) {				
	name = type->ref;
	uri = type->refNs;
    } else {
	name = type->name;
	uri = type->targetNamespace;
    }			    
    xmlSchemaVErr(ctxt, elem, 
	XML_SCHEMAV_CVC_COMPLEX_TYPE_4,
	/* XML_SCHEMAS_ERR_MISSING, */
	"%s: The attribute %s is required but missing.\n",
	xmlSchemaFormatItemForReport(&strE, NULL, NULL, elem, 0),
	xmlSchemaFormatNsUriLocal(&strA, uri, name));
    FREE_AND_NULL(strE)
    FREE_AND_NULL(strA)
}

/************************************************************************
 * 									*
 * 			Allocation functions				*
 * 									*
 ************************************************************************/

/**
 * xmlSchemaNewSchemaForParserCtxt:
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
 * xmlSchemaNewSchema:
 * @ctxt:  a schema validation context
 *
 * Allocate a new Schema structure.
 *
 * Returns the newly allocated structure or NULL in case or error
 */
static xmlSchemaAssemblePtr
xmlSchemaNewAssemble(void)
{
    xmlSchemaAssemblePtr ret;

    ret = (xmlSchemaAssemblePtr) xmlMalloc(sizeof(xmlSchemaAssemble));
    if (ret == NULL) {
        /* xmlSchemaPErrMemory(ctxt, "allocating assemble info", NULL); */
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaAssemble));
    ret->items = NULL;
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
    xmlFreeDoc(import->doc);
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
    if (attr->annot != NULL) 
	xmlSchemaFreeAnnot(attr->annot);
    if (attr->defVal != NULL)
	xmlSchemaFreeValue(attr->defVal);
    xmlFree(attr);
}

/**
 * xmlSchemaFreeWildcardNsSet:
 * set:  a schema wildcard namespace
 *
 * Deallocates a list of wildcard constraint structures.
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
 * @wildcard:  a wildcard structure
 *
 * Deallocates a wildcard structure.
 */
void
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
 * @attrUse:  an attribute link
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
 * xmlSchemaFreeTypeLinkList:
 * @alink: a type link
 *
 * Deallocate a list of types.
 */
static void
xmlSchemaFreeTypeLinkList(xmlSchemaTypeLinkPtr link)
{
    xmlSchemaTypeLinkPtr next;

    while (link != NULL) {
	next = link->next;
	xmlFree(link);
	link = next;
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
    if (elem->defVal != NULL)
	xmlSchemaFreeValue(elem->defVal);
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
	    (type->flags & XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD))) {
	    /*
	    * NOTE: The only case where an attribute wildcard
	    * is not owned, is if a complex type inherits it
	    * from a base type.
	    */
	    xmlSchemaFreeWildcard(type->attributeWildcard);
	}
    }
    if (type->memberTypes != NULL)
	xmlSchemaFreeTypeLinkList(type->memberTypes);
    if (type->facetSet != NULL) {
	xmlSchemaFacetLinkPtr next, link;

	link = type->facetSet;
	do {
	    next = link->next;
	    xmlFree(link);
	    link = next;
	} while (link != NULL);
    }  
    if (type->contModel != NULL)
        xmlRegFreeRegexp(type->contModel);
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
	/* not used. */
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
    if (output == NULL)
        return;
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
 * xmlSchemaGetPropNode:
 * @node: the element node 
 * @name: the name of the attribute
 *
 * Seeks an attribute with a name of @name in
 * no namespace.
 *
 * Returns the attribute or NULL if not present. 
 */
static xmlAttrPtr
xmlSchemaGetPropNode(xmlNodePtr node, const char *name) 
{
    xmlAttrPtr prop;

    if ((node == NULL) || (name == NULL)) 
	return(NULL);
    prop = node->properties;
    while (prop != NULL) {
        if ((prop->ns == NULL) && xmlStrEqual(prop->name, BAD_CAST name))	    
	    return(prop);
	prop = prop->next;
    }
    return (NULL);
}

/**
 * xmlSchemaGetPropNodeNs:
 * @node: the element node 
 * @uri: the uri
 * @name: the name of the attribute
 *
 * Seeks an attribute with a local name of @name and
 * a namespace URI of @uri.
 *
 * Returns the attribute or NULL if not present. 
 */
static xmlAttrPtr
xmlSchemaGetPropNodeNs(xmlNodePtr node, const char *uri, const char *name) 
{
    xmlAttrPtr prop;

    if ((node == NULL) || (name == NULL)) 
	return(NULL);
    prop = node->properties;
    while (prop != NULL) {
	if ((prop->ns != NULL) &&
	    xmlStrEqual(prop->name, BAD_CAST name) &&
	    xmlStrEqual(prop->ns->href, BAD_CAST uri))
	    return(prop);
	prop = prop->next;
    }
    return (NULL);
}

static const xmlChar *
xmlSchemaGetNodeContent(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node)
{
    xmlChar *val;
    const xmlChar *ret;

    val = xmlNodeGetContent(node);
    if (val == NULL)
        return(NULL);
    ret = xmlDictLookup(ctxt->dict, val, -1);
    xmlFree(val);
    return(ret);    
}

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

/************************************************************************
 * 									*
 * 			Parsing functions				*
 * 									*
 ************************************************************************/

/**
 * xmlSchemaGetElem:
 * @schema:  the schema context
 * @name:  the element name
 * @ns:  the element namespace
 *
 * Lookup a global element declaration in the schema.
 *
 * Returns the element declaration or NULL if not found.
 */
static xmlSchemaElementPtr
xmlSchemaGetElem(xmlSchemaPtr schema, const xmlChar * name,
                 const xmlChar * namespace)
{
    xmlSchemaElementPtr ret;

    if ((name == NULL) || (schema == NULL))
        return (NULL);
        
        ret = xmlHashLookup2(schema->elemDecl, name, namespace);
        if ((ret != NULL) &&
	    (ret->flags & XML_SCHEMAS_ELEM_GLOBAL)) {
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
    
    /*
    * Removed since imported components will be hold by the main schema only.
    *
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_NO_NAMESPACE);
    else
    import = xmlHashLookup(schema->schemasImports, namespace);
    if (import != NULL) {
	ret = xmlSchemaGetElem(import->schema, name, namespace, level + 1);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ELEM_GLOBAL)) {
	    return (ret);
	} else
	    ret = NULL;
    }
    */
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
    /*
    * Removed, since the imported components will be grafted on the
    * main schema only.    
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_NO_NAMESPACE);
    else
    import = xmlHashLookup(schema->schemasImports, namespace);
    if (import != NULL) {
	ret = xmlSchemaGetType(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_TYPE_GLOBAL)) {
	    return (ret);
	} else
	    ret = NULL;
    }
    */
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

    if ((name == NULL) || (schema == NULL))
        return (NULL);
    
    
    ret = xmlHashLookup2(schema->attrDecl, name, namespace);
    if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTR_GLOBAL))
	return (ret); 
    else
	ret = NULL;
    /*
    * Removed, since imported components will be hold by the main schema only.
    *
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_NO_NAMESPACE);
    else
	import = xmlHashLookup(schema->schemasImports, namespace);	
    if (import != NULL) {
	ret = xmlSchemaGetAttribute(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTR_GLOBAL)) {
	    return (ret);
	} else
	    ret = NULL;
    }
    */
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

    if ((name == NULL) || (schema == NULL))
        return (NULL);
    
    
    ret = xmlHashLookup2(schema->attrgrpDecl, name, namespace);
    if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTRGROUP_GLOBAL))
	return (ret);  
    else
	ret = NULL;
    /*
    * Removed since imported components will be hold by the main schema only.
    *
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_NO_NAMESPACE);
    else
	import = xmlHashLookup(schema->schemasImports, namespace);	
    if (import != NULL) {
	ret = xmlSchemaGetAttributeGroup(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_ATTRGROUP_GLOBAL))
	    return (ret);
	else
	    ret = NULL;
    }
    */
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

    if ((name == NULL) || (schema == NULL))
        return (NULL);
    
    
    ret = xmlHashLookup2(schema->groupDecl, name, namespace);
    if ((ret != NULL) && (ret->flags & XML_SCHEMAS_TYPE_GLOBAL))
	return (ret);  
    else
	ret = NULL;
    /*
    * Removed since imported components will be hold by the main schema only.
    *
    if (namespace == NULL)
	import = xmlHashLookup(schema->schemasImports, XML_SCHEMAS_NO_NAMESPACE);
    else
	import = xmlHashLookup(schema->schemasImports, namespace);	
    if (import != NULL) {
	ret = xmlSchemaGetGroup(import->schema, name, namespace);
	if ((ret != NULL) && (ret->flags & XML_SCHEMAS_TYPE_GLOBAL))
	    return (ret);
	else
	    ret = NULL;
    }
    */
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
 * xmlSchemaAddAssembledItem:
 * @ctxt:  a schema parser context
 * @schema:  the schema being built
 * @item:  the item
 *
 * Add a item to the schema's list of current items.
 * This is used if the schema was already constructed and
 * new schemata need to be added to it.
 * *WARNING* this interface is highly subject to change.
 *
 * Returns 0 if suceeds and -1 if an internal error occurs.
 */
static int
xmlSchemaAddAssembledItem(xmlSchemaParserCtxtPtr ctxt,
			   xmlSchemaTypePtr item)
{
    static int growSize = 100;
    xmlSchemaAssemblePtr ass;

    ass = ctxt->assemble;
    if (ass->sizeItems < 0) {
	/* If disabled. */
	return (0);
    }
    if (ass->sizeItems <= 0) {
	ass->items = (void **) xmlMalloc(growSize * sizeof(xmlSchemaTypePtr));
	if (ass->items == NULL) {
	    xmlSchemaPErrMemory(ctxt,
		"allocating new item buffer", NULL);
	    return (-1);
	}	
	ass->sizeItems = growSize;
    } else if (ass->sizeItems <= ass->nbItems) {
	ass->sizeItems *= 2;
	ass->items = (void **) xmlRealloc(ass->items, 
	    ass->sizeItems * sizeof(xmlSchemaTypePtr));
	if (ass->items == NULL) {
	    xmlSchemaPErrMemory(ctxt,
		"growing item buffer", NULL);
	    ass->sizeItems = 0;
	    return (-1);
	}	
    }
    /* ass->items[ass->nbItems++] = (void *) item; */
    ((xmlSchemaTypePtr *) ass->items)[ass->nbItems++] = (void *) item;
    return (0);
}

/**
 * xmlSchemaAddNotation:
 * @ctxt:  a schema parser context
 * @schema:  the schema being built
 * @name:  the item name
 *
 * Add an XML schema annotation declaration
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
	/*
	* TODO: This should never happen, since a unique name will be computed.
	* If it fails, then an other internal error must have occured.
	*/
	xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
		      XML_SCHEMAP_REDEFINED_NOTATION,
                      "Annotation declaration '%s' is already declared.\n",
                      name, NULL);
        xmlFree(ret);
        return (NULL);
    }
    return (ret);
}


/**
 * xmlSchemaAddAttribute:
 * @ctxt:  a schema parser context
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
                      const xmlChar * name, const xmlChar * namespace,
		      xmlNodePtr node)
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
    ret->targetNamespace = namespace;
    val = xmlHashAddEntry3(schema->attrDecl, name,
                           namespace, ctxt->container, ret);
    if (val != 0) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_REDEFINED_ATTR,
	    NULL, NULL, node,
	    "A global attribute declaration with the name '%s' does already exist", name);
        xmlFree(ret);
        return (NULL);
    }
    if (ctxt->assemble != NULL)
	xmlSchemaAddAssembledItem(ctxt, (xmlSchemaTypePtr) ret); 
    return (ret);
}

/**
 * xmlSchemaAddAttributeGroup:
 * @ctxt:  a schema parser context
 * @schema:  the schema being built
 * @name:  the item name
 *
 * Add an XML schema Attrribute Group declaration
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaAttributeGroupPtr
xmlSchemaAddAttributeGroup(xmlSchemaParserCtxtPtr ctxt,
                           xmlSchemaPtr schema, const xmlChar * name,
			   xmlNodePtr node)
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
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_REDEFINED_ATTRGROUP,
	    NULL, NULL, node,
	    "A global attribute group definition with the name '%s' does already exist", name);
        xmlFree(ret);
        return (NULL);
    }
    if (ctxt->assemble != NULL)	
	xmlSchemaAddAssembledItem(ctxt, (xmlSchemaTypePtr) ret);
    return (ret);
}

/**
 * xmlSchemaAddElement:
 * @ctxt:  a schema parser context
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
                    const xmlChar * name, const xmlChar * namespace,
		    xmlNodePtr node, int topLevel)
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
    val = xmlHashAddEntry3(schema->elemDecl, name,
                           namespace, ctxt->container, ret);
    if (val != 0) {
	if (topLevel) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_REDEFINED_ELEMENT,
		NULL, NULL, node,
		"A global element declaration with the name '%s' does "
		"already exist", name);
            xmlFree(ret);
            return (NULL);
	} else {
	    char buf[30]; 

	    snprintf(buf, 29, "#eCont %d", ctxt->counter++ + 1);
	    val = xmlHashAddEntry3(schema->elemDecl, name, (xmlChar *) buf,
		namespace, ret);
	    if (val != 0) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_INTERNAL,
		    NULL, NULL, node,
		    "Internal error: xmlSchemaAddElement, "
		    "a dublicate element declaration with the name '%s' "
		    "could not be added to the hash.", name);
		xmlFree(ret);
		return (NULL);
	    }
	}
        
    }
    if (ctxt->assemble != NULL)	
	xmlSchemaAddAssembledItem(ctxt, (xmlSchemaTypePtr) ret);
    return (ret);
}

/**
 * xmlSchemaAddType:
 * @ctxt:  a schema parser context
 * @schema:  the schema being built
 * @name:  the item name
 * @namespace:  the namespace
 *
 * Add an XML schema item
 * *WARNING* this interface is highly subject to change
 *
 * Returns the new struture or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaAddType(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                 const xmlChar * name, const xmlChar * namespace,
		 xmlNodePtr node)
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
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_REDEFINED_TYPE,
		NULL, NULL, node, 
		"A global type definition with the name '%s' does already exist", name);            	    
	    xmlFree(ret);
	    return (NULL);
	} else {
	    xmlSchemaTypePtr prev;

	    prev = xmlHashLookup2(schema->typeDecl, name, namespace);
	    if (prev == NULL) {
		xmlSchemaPErr(ctxt, (xmlNodePtr) ctxt->doc,
		    XML_ERR_INTERNAL_ERROR,
		    "Internal error: xmlSchemaAddType, on type "
		    "'%s'.\n",
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
    if (ctxt->assemble != NULL)	
	xmlSchemaAddAssembledItem(ctxt,ret);
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
                  const xmlChar *name, const xmlChar *namespaceName,
		  xmlNodePtr node)
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
        xmlHashAddEntry2(schema->groupDecl, name, namespaceName,
                         ret);
    if (val != 0) {
	xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_REDEFINED_GROUP,
		NULL, NULL, node,
		"A global model group definition with the name '%s' does already exist", name);    
        xmlFree(ret);
        return (NULL);
    }
    ret->minOccurs = 1;
    ret->maxOccurs = 1;
    if (ctxt->assemble != NULL)	
	xmlSchemaAddAssembledItem(ctxt, (xmlSchemaTypePtr) ret);
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
 * Adds a wildcard. It corresponds to a 
 * xsd:anyAttribute and is used as storage for namespace 
 * constraints on a xsd:any.
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
    xmlAttrPtr attr;

    *namespace = NULL;
    attr = xmlSchemaGetPropNode(node, name);
    if (attr == NULL)
	return (NULL);
    val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);

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
        xmlSchemaPSimpleTypeErr(ctxt, XML_SCHEMAP_PREFIX_UNDEFINED, 
	    NULL, NULL, (xmlNodePtr) attr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_QNAME), NULL, val,
	    "The QName value '%s' has no corresponding namespace "
	    "declaration in scope", val, NULL);
    } else {
        *namespace = xmlDictLookup(ctxt->dict, ns->href, -1);
    }
    return (ret);
}

/**
 * xmlSchemaPValAttrNodeQNameValue:
 * @ctxt:  a schema parser context
 * @schema: the schema context
 * @ownerDes: the designation of the parent element
 * @ownerItem: the parent as a schema object
 * @value:  the QName value 
 * @local: the resulting local part if found, the attribute value otherwise
 * @uri:  the resulting namespace URI if found
 *
 * Extracts the local name and the URI of a QName value and validates it.
 * This one is intended to be used on attribute values that
 * should resolve to schema components.
 *
 * Returns 0, in case the QName is valid, a positive error code
 * if not valid and -1 if an internal error occurs.
 */
static int
xmlSchemaPValAttrNodeQNameValue(xmlSchemaParserCtxtPtr ctxt, 
				       xmlSchemaPtr schema,
				       xmlChar **ownerDes,
				       xmlSchemaTypePtr ownerItem,
				       xmlAttrPtr attr,
				       const xmlChar *value,
				       const xmlChar **uri,
				       const xmlChar **prefix,
				       const xmlChar **local)
{
    const xmlChar *pref;
    xmlNsPtr ns;
    int len, ret;
    
    *uri = NULL;
    *local = NULL;
    if (prefix != 0)
	*prefix = NULL;
    ret = xmlValidateQName(value, 1);
    if (ret > 0) {		
	xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE, 
	    ownerDes, ownerItem, (xmlNodePtr) attr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_QNAME), 
	    "QName", value, 
	    NULL, NULL, NULL);	
	*local = value;
	return (ctxt->err); 
    } else if (ret < 0)
	return (-1);
   
    if (!strchr((char *) value, ':')) {	
	ns = xmlSearchNs(attr->doc, attr->parent, 0);
	if (ns)
	    *uri = xmlDictLookup(ctxt->dict, ns->href, -1);
	else if (schema->flags & XML_SCHEMAS_INCLUDING_CONVERT_NS) {
	    /*
	    * This one takes care of included schemas with no
	    * target namespace.
	    */
	    *uri = schema->targetNamespace;
	}	
	*local = value;
	return (0);
    }
    /*
    * At this point xmlSplitQName3 has to return a local name.
    */
    *local = xmlSplitQName3(value, &len);
    *local = xmlDictLookup(ctxt->dict, *local, -1);
    pref = xmlDictLookup(ctxt->dict, value, len);
    if (prefix != 0)
	*prefix = pref;
    ns = xmlSearchNs(attr->doc, attr->parent, pref);
    if (ns == NULL) {
	xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
	    ownerDes, ownerItem, (xmlNodePtr) attr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_QNAME), "QName", value,
	    "The QName value '%s' has no corresponding namespace "
	    "declaration in scope", value, NULL);
	return (ctxt->err);
    } else {
        *uri = xmlDictLookup(ctxt->dict, ns->href, -1);
    }    
    return (0);
}

/**
 * xmlSchemaPValAttrNodeQName:
 * @ctxt:  a schema parser context
 * @schema: the schema context
 * @ownerDes: the designation of the owner element
 * @ownerItem: the owner as a schema object
 * @attr:  the attribute node
 * @local: the resulting local part if found, the attribute value otherwise
 * @uri:  the resulting namespace URI if found
 *
 * Extracts and validates the QName of an attribute value.
 * This one is intended to be used on attribute values that
 * should resolve to schema components.
 *
 * Returns 0, in case the QName is valid, a positive error code
 * if not valid and -1 if an internal error occurs.
 */
static int
xmlSchemaPValAttrNodeQName(xmlSchemaParserCtxtPtr ctxt, 
				       xmlSchemaPtr schema,
				       xmlChar **ownerDes,
				       xmlSchemaTypePtr ownerItem,
				       xmlAttrPtr attr,
				       const xmlChar **uri,
				       const xmlChar **prefix,
				       const xmlChar **local)
{
    const xmlChar *value;

    value = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
    return (xmlSchemaPValAttrNodeQNameValue(ctxt, schema, 
	ownerDes, ownerItem, attr, value, uri, prefix, local));
}

/**
 * xmlSchemaPValAttrQName:
 * @ctxt:  a schema parser context
 * @schema: the schema context
 * @ownerDes: the designation of the parent element
 * @ownerItem: the owner as a schema object
 * @ownerElem:  the parent node of the attribute
 * @name:  the name of the attribute
 * @local: the resulting local part if found, the attribute value otherwise
 * @uri:  the resulting namespace URI if found
 *
 * Extracts and validates the QName of an attribute value.
 *
 * Returns 0, in case the QName is valid, a positive error code
 * if not valid and -1 if an internal error occurs.
 */
static int
xmlSchemaPValAttrQName(xmlSchemaParserCtxtPtr ctxt, 
				   xmlSchemaPtr schema, 
				   xmlChar **ownerDes,
				   xmlSchemaTypePtr ownerItem,
				   xmlNodePtr ownerElem,
				   const char *name,
				   const xmlChar **uri,
				   const xmlChar **prefix,
				   const xmlChar **local)
{
    xmlAttrPtr attr;

    attr = xmlSchemaGetPropNode(ownerElem, name);
    if (attr == NULL) {
	*local = NULL;
	*uri = NULL;
	return (0);    
    }
    return (xmlSchemaPValAttrNodeQName(ctxt, schema, 
	ownerDes, ownerItem, attr, uri, prefix, local));
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
xmlGetMaxOccurs(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node,
		int min, int max, int def, const char *expected)
{
    const xmlChar *val, *cur;
    int ret = 0;
    xmlAttrPtr attr;

    attr = xmlSchemaGetPropNode(node, "maxOccurs");
    if (attr == NULL)
	return (def);
    val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);

    if (xmlStrEqual(val, (const xmlChar *) "unbounded")) {
	if (max != UNBOUNDED) {
	    xmlSchemaPSimpleTypeErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
		/* XML_SCHEMAP_INVALID_MINOCCURS, */
		NULL, NULL, (xmlNodePtr) attr, NULL, expected,
		val, NULL, NULL, NULL);
	    return (def);
	} else 
	    return (UNBOUNDED);  /* encoding it with -1 might be another option */
    }

    cur = val;
    while (IS_BLANK_CH(*cur))
        cur++;
    if (*cur == 0) {
        xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
	    /* XML_SCHEMAP_INVALID_MINOCCURS, */
	    NULL, NULL, (xmlNodePtr) attr, NULL, expected,
	    val, NULL, NULL, NULL);
	return (def);
    }
    while ((*cur >= '0') && (*cur <= '9')) {
        ret = ret * 10 + (*cur - '0');
        cur++;
    }
    while (IS_BLANK_CH(*cur))
        cur++;
    /*
    * TODO: Restrict the maximal value to Integer.
    */
    if ((*cur != 0) || (ret < min) || ((max != -1) && (ret > max))) {
	xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
	    /* XML_SCHEMAP_INVALID_MINOCCURS, */
	    NULL, NULL, (xmlNodePtr) attr, NULL, expected,
	    val, NULL, NULL, NULL);
        return (def);
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
xmlGetMinOccurs(xmlSchemaParserCtxtPtr ctxt, xmlNodePtr node, 
		int min, int max, int def, const char *expected)
{
    const xmlChar *val, *cur;
    int ret = 0;
    xmlAttrPtr attr;

    attr = xmlSchemaGetPropNode(node, "minOccurs");
    if (attr == NULL)
	return (def);
    val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
    cur = val;
    while (IS_BLANK_CH(*cur))
        cur++;
    if (*cur == 0) {
        xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
	    /* XML_SCHEMAP_INVALID_MINOCCURS, */
	    NULL, NULL, (xmlNodePtr) attr, NULL, expected,
	    val, NULL, NULL, NULL);
        return (def);
    }
    while ((*cur >= '0') && (*cur <= '9')) {
        ret = ret * 10 + (*cur - '0');
        cur++;
    }
    while (IS_BLANK_CH(*cur))
        cur++;
    /*
    * TODO: Restrict the maximal value to Integer.
    */
    if ((*cur != 0) || (ret < min) || ((max != -1) && (ret > max))) {
	xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
	    /* XML_SCHEMAP_INVALID_MINOCCURS, */
	    NULL, NULL, (xmlNodePtr) attr, NULL, expected,
	    val, NULL, NULL, NULL);
        return (def);
    }
    return (ret);
}

/**
 * xmlSchemaPGetBoolNodeValue:
 * @ctxt:  a schema validation context
 * @ownerDes:  owner designation
 * @ownerItem:  the owner as a schema item
 * @node: the node holding the value
 *
 * Converts a boolean string value into 1 or 0.
 *
 * Returns 0 or 1.
 */
static int
xmlSchemaPGetBoolNodeValue(xmlSchemaParserCtxtPtr ctxt,			   
			   xmlChar **ownerDes,
			   xmlSchemaTypePtr ownerItem,
			   xmlNodePtr node)
{
    xmlChar *value = NULL;
    int res = 0;
   
    value = xmlNodeGetContent(node);
    /* 
    * 3.2.2.1 Lexical representation
    * An instance of a datatype that is defined as ·boolean· 
    * can have the following legal literals {true, false, 1, 0}.
    */
    if (xmlStrEqual(BAD_CAST value, BAD_CAST "true"))
        res = 1;
    else if (xmlStrEqual(BAD_CAST value, BAD_CAST "false"))
        res = 0;
    else if (xmlStrEqual(BAD_CAST value, BAD_CAST "1"))
	res = 1;
    else if (xmlStrEqual(BAD_CAST value, BAD_CAST "0"))
        res = 0;    
    else {
        xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_INVALID_BOOLEAN,
	    ownerDes, ownerItem, node, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_BOOLEAN), 
	    "(1 | 0 | true | false)", BAD_CAST value, 
	    NULL, NULL, NULL);
    }
    if (value != NULL)
	xmlFree(value);
    return (res);
}

/**
 * xmlGetBooleanProp:
 * @ctxt:  a schema validation context
 * @node:  a subtree containing XML Schema informations
 * @name:  the attribute name
 * @def:  the default value
 *
 * Evaluate if a boolean property is set
 *
 * Returns the default if not found, 0 if found to be false,
 * 1 if found to be true
 */
static int
xmlGetBooleanProp(xmlSchemaParserCtxtPtr ctxt, 
		  xmlChar **ownerDes,
		  xmlSchemaTypePtr ownerItem,
		  xmlNodePtr node,
                  const char *name, int def)
{
    const xmlChar *val;

    val = xmlSchemaGetProp(ctxt, node, name);
    if (val == NULL)
        return (def);
    /* 
    * 3.2.2.1 Lexical representation
    * An instance of a datatype that is defined as ·boolean· 
    * can have the following legal literals {true, false, 1, 0}.
    */
    if (xmlStrEqual(val, BAD_CAST "true"))
        def = 1;
    else if (xmlStrEqual(val, BAD_CAST "false"))
        def = 0;
    else if (xmlStrEqual(val, BAD_CAST "1"))
	def = 1;
    else if (xmlStrEqual(val, BAD_CAST "0"))
        def = 0;    
    else {
        xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_INVALID_BOOLEAN,
	    ownerDes, ownerItem, node, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_BOOLEAN), 
	    "(1 | 0 | true | false)", val, NULL, NULL, NULL);
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
                                                  xmlNodePtr node);
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
 * xmlSchemaPValAttrNodeValue:
 * 
 * @ctxt:  a schema parser context
 * @ownerDes: the designation of the parent element
 * @ownerItem: the schema object owner if existent
 * @attr:  the schema attribute node being validated
 * @value: the value
 * @type: the built-in type to be validated against 
 *
 * Validates a value against the given built-in type.
 * This one is intended to be used internally for validation
 * of schema attribute values during parsing of the schema.
 *
 * Returns 0 if the value is valid, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaPValAttrNodeValue(xmlSchemaParserCtxtPtr ctxt,
			   xmlChar **ownerDes,
			   xmlSchemaTypePtr ownerItem,			   
			   xmlAttrPtr attr,
			   const xmlChar *value,
			   xmlSchemaTypePtr type)
{
    
    int ret = 0; 

    /*
    * NOTE: Should we move this to xmlschematypes.c? Hmm, but this
    * one is really meant to be used internally, so better not.
    */    
    if ((ctxt == NULL) || (type == NULL) || (attr == NULL))
	return (-1);   
    if (type->type != XML_SCHEMA_TYPE_BASIC) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) attr, 
	    XML_SCHEMAP_INTERNAL,
	    "Internal error: xmlSchemaPValAttrNodeValue, the given "
	    "type '%s' is not a built-in type.\n",
	    type->name, NULL);
	return (-1);
    }    
    switch (type->builtInType) {
	case XML_SCHEMAS_NCNAME:
	case XML_SCHEMAS_QNAME:
	case XML_SCHEMAS_ANYURI:
	case XML_SCHEMAS_TOKEN:
	case XML_SCHEMAS_LANGUAGE:
	    ret = xmlSchemaValPredefTypeNode(type, value, NULL, (xmlNodePtr) attr);
	    break;

	/*
	case XML_SCHEMAS_NCNAME:
	    ret = xmlValidateNCName(value, 1);
	    break;
	case XML_SCHEMAS_QNAME:
	    xmlSchemaPErr(ctxt, (xmlNodePtr) attr, 
		XML_SCHEMAP_INTERNAL,
		"Internal error: xmlSchemaPvalueAttrNode, use "
		"the function xmlSchemaExtractSchemaQNamePropvalueidated "
		"for extracting QName valueues instead.\n",
		NULL, NULL);
	    return (-1);
	case XML_SCHEMAS_ANYURI:
	    if (value != NULL) {
		xmlURIPtr uri = xmlParseURI((const char *) value);
		if (uri == NULL)
		    ret = 1;
		else
		    xmlFreeURI(uri);
	    }
	    break;
	case XML_SCHEMAS_TOKEN: {
	    const xmlChar *cur = value;

		if (IS_BLANK_CH(*cur)) {
                    ret = 1;		       
		} else while (*cur != 0) {
                    if ((*cur == 0xd) || (*cur == 0xa) || (*cur == 0x9)) {
                        ret = 1;
			break;
                    } else if (*cur == ' ') {
                        cur++;
                        if ((*cur == 0) || (*cur == ' ')) {
			    ret = 1;
			    break;
			}
                    } else {
                        cur++;
                    }
                }
	    }
	    break;
	case XML_SCHEMAS_LANGUAGE:
	    if (xmlCheckLanguageID(value) != 1) 
		ret = 1;
	    break;
	*/
	default: {
	    xmlSchemaPErr(ctxt, (xmlNodePtr) attr, 
		    XML_SCHEMAP_INTERNAL,
		    "Internal error: xmlSchemaPValAttrNodeValue, "
		    "valueidation using the type '%s' is not implemented "
		    "yet.\n",
		    type->name, NULL);
	    return (-1);
	}
    }              
    /*
    * TODO: Should we use the S4S error codes instead?
    */
    if (ret < 0) {
	xmlSchemaPErr(ctxt, (xmlNodePtr) attr, 
	    XML_SCHEMAP_INTERNAL,
	    "Internal error: xmlSchemaPValAttrNodeValue, "
	    "failed to validate a schema attribute value.\n",
	    NULL, NULL);
	return (-1);
    } else if (ret > 0) { 	
	if (type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) {	   
	    xmlSchemaPSimpleTypeErr(ctxt, 
		XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2, 
		ownerDes, ownerItem, (xmlNodePtr) attr, 
		type, NULL, value, 
		NULL, NULL, NULL);
	    return(XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2);
	} else {	    
	    xmlSchemaPSimpleTypeErr(ctxt, 
		XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1, 
		ownerDes, ownerItem, (xmlNodePtr) attr, 
		type, NULL, value, 
		NULL, NULL, NULL);
	    return(XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1);
	}	
    }    
    return (ret);
}

/**
 * xmlSchemaPValAttrNode:
 * 
 * @ctxt:  a schema parser context
 * @ownerDes: the designation of the parent element
 * @ownerItem: the schema object owner if existent
 * @attr:  the schema attribute node being validated
 * @type: the built-in type to be validated against
 * @value: the resulting value if any
 *
 * Extracts and validates a value against the given built-in type.
 * This one is intended to be used internally for validation
 * of schema attribute values during parsing of the schema.
 *
 * Returns 0 if the value is valid, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaPValAttrNode(xmlSchemaParserCtxtPtr ctxt,
			   xmlChar **ownerDes,
			   xmlSchemaTypePtr ownerItem,			   
			   xmlAttrPtr attr,			   
			   xmlSchemaTypePtr type,
			   const xmlChar **value)
{    
    const xmlChar *val;

    if ((ctxt == NULL) || (type == NULL) || (attr == NULL))
	return (-1);   
       
    val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
    if (value != NULL)
	*value = val;

    return (xmlSchemaPValAttrNodeValue(ctxt, ownerDes, ownerItem, attr,
	val, type));    
}

/**
 * xmlSchemaPValAttr:
 * 
 * @ctxt:  a schema parser context
 * @node: the element node of the attribute
 * @ownerDes: the designation of the parent element
 * @ownerItem: the schema object owner if existent
 * @ownerElem: the owner element node
 * @name:  the name of the schema attribute node
 * @type: the built-in type to be validated against
 * @value: the resulting value if any
 *
 * Extracts and validates a value against the given built-in type.
 * This one is intended to be used internally for validation
 * of schema attribute values during parsing of the schema.
 *
 * Returns 0 if the value is valid, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaPValAttr(xmlSchemaParserCtxtPtr ctxt,		       
		       xmlChar **ownerDes,
		       xmlSchemaTypePtr ownerItem,
		       xmlNodePtr ownerElem,
		       const char *name,
		       xmlSchemaTypePtr type,
		       const xmlChar **value)
{
    xmlAttrPtr attr;

    if ((ctxt == NULL) || (type == NULL)) {
	if (value != NULL)
	    *value = NULL;
	return (-1);   
    }
    if (type->type != XML_SCHEMA_TYPE_BASIC) {
	if (value != NULL)
	    *value = NULL;
	xmlSchemaPErr(ctxt, ownerElem, 
	    XML_SCHEMAP_INTERNAL,
	    "Internal error: xmlSchemaPValAttr, the given "
	    "type '%s' is not a built-in type.\n",
	    type->name, NULL);
	return (-1);
    }
    attr = xmlSchemaGetPropNode(ownerElem, name);
    if (attr == NULL) {
	if (value != NULL)
	    *value = NULL;
	return (0);
    }    
    return (xmlSchemaPValAttrNode(ctxt, ownerDes, ownerItem, attr, 
	type, value));
}
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
    xmlNodePtr child = NULL;
    xmlAttrPtr attr;
    int barked = 0;

    /*
    * INFO: S4S completed.
    */
    /*
    * id = ID
    * {any attributes with non-schema namespace . . .}>
    * Content: (appinfo | documentation)*
    */
    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    ret = xmlSchemaNewAnnot(ctxt, node);
    attr = node->properties;
    while (attr != NULL) {
	if (((attr->ns == NULL) && 
	    (!xmlStrEqual(attr->name, BAD_CAST "id"))) ||
	    ((attr->ns != NULL) && 
	    xmlStrEqual(attr->ns->href, xmlSchemaNs))) {
	    
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
		NULL, NULL, attr);
	}
	attr = attr->next;
    }
    /* TODO: Check id. */    
    
    /*
    * And now for the children...
    */
    child = node->children;
    while (child != NULL) {
	if (IS_SCHEMA(child, "appinfo")) {
	    /* TODO: make available the content of "appinfo". */
	    /* 
	    * source = anyURI
	    * {any attributes with non-schema namespace . . .}>
	    * Content: ({any})*
	    */
	    attr = child->properties;
	    while (attr != NULL) {
		if (((attr->ns == NULL) && 
		     (!xmlStrEqual(attr->name, BAD_CAST "source"))) ||
		     ((attr->ns != NULL) && 
		      xmlStrEqual(attr->ns->href, xmlSchemaNs))) {

		    xmlSchemaPIllegalAttrErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
			NULL, NULL, attr);
		}
		attr = attr->next;
	    }
	    xmlSchemaPValAttr(ctxt, NULL, NULL, child, "source", 
		xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI), NULL);	    
	    child = child->next;
	} else if (IS_SCHEMA(child, "documentation")) {
	    /* TODO: make available the content of "documentation". */
	    /*
	    * source = anyURI
	    * {any attributes with non-schema namespace . . .}>
	    * Content: ({any})*
	    */
	    attr = child->properties;
	    while (attr != NULL) {
		if (attr->ns == NULL) {
		    if (!xmlStrEqual(attr->name, BAD_CAST "source")) {
			xmlSchemaPIllegalAttrErr(ctxt, 
			    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
			    NULL, NULL, attr);
		    }
		} else {
		    if (xmlStrEqual(attr->ns->href, xmlSchemaNs) ||
			(xmlStrEqual(attr->name, BAD_CAST "lang") &&
			(!xmlStrEqual(attr->ns->href, XML_XML_NAMESPACE)))) {
			
			xmlSchemaPIllegalAttrErr(ctxt, 
			    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
			    NULL, NULL, attr);
		    }
		}
		attr = attr->next;
	    }
	    /*
	    * Attribute "xml:lang".
	    */
	    attr = xmlSchemaGetPropNodeNs(child, (const char *) XML_XML_NAMESPACE, "lang");
	    if (attr != NULL)
		xmlSchemaPValAttrNode(ctxt, NULL, NULL, attr,
		xmlSchemaGetBuiltInType(XML_SCHEMAS_LANGUAGE), NULL);	    
	    child = child->next;
	} else {
	    if (!barked)
		xmlSchemaPContentErr(ctxt, 
		    XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED, 
		    NULL, NULL, node, child, NULL, "(appinfo | documentation)*");
	    barked = 1;
	    child = child->next;
	}
    }
    
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
    if ((facet->type != XML_SCHEMA_FACET_PATTERN) &&
	(facet->type != XML_SCHEMA_FACET_ENUMERATION)) {
	const xmlChar *fixed;

	fixed = xmlSchemaGetProp(ctxt, node, "fixed");
	if (fixed != NULL) {
	    if (xmlStrEqual(fixed, BAD_CAST "true"))
		facet->fixed = 1;
	}
    }    
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
 * xmlSchemaParseWildcardNs:
 * @ctxt:  a schema parser context
 * @wildc:  the wildcard, already created
 * @node:  a subtree containing XML Schema informations
 *
 * Parses the attribute "processContents" and "namespace"
 * of a xsd:anyAttribute and xsd:any.
 * *WARNING* this interface is highly subject to change
 *
 * Returns 0 if everything goes fine, a positive error code
 * if something is not valid and -1 if an internal error occurs.
 */
static int
xmlSchemaParseWildcardNs(xmlSchemaParserCtxtPtr ctxt,
			 xmlSchemaPtr schema,
			 xmlSchemaWildcardPtr wildc,
			 xmlNodePtr node)
{
    const xmlChar *pc, *ns, *dictnsItem;
    int ret = 0;
    xmlChar *nsItem;
    xmlSchemaWildcardNsPtr tmp, lastNs = NULL;
    xmlAttrPtr attr;
    
    pc = xmlSchemaGetProp(ctxt, node, "processContents");
    if ((pc == NULL)
        || (xmlStrEqual(pc, (const xmlChar *) "strict"))) {
        wildc->processContents = XML_SCHEMAS_ANY_STRICT;
    } else if (xmlStrEqual(pc, (const xmlChar *) "skip")) {
        wildc->processContents = XML_SCHEMAS_ANY_SKIP;
    } else if (xmlStrEqual(pc, (const xmlChar *) "lax")) {
        wildc->processContents = XML_SCHEMAS_ANY_LAX;
    } else {
        xmlSchemaPSimpleTypeErr(ctxt, 
	    XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD,
	    NULL, NULL, node,
	    NULL, "(strict | skip | lax)", pc, 
	    NULL, NULL, NULL);
        wildc->processContents = XML_SCHEMAS_ANY_STRICT;
	ret = XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD;
    }
    /*
     * Build the namespace constraints.
     */
    attr = xmlSchemaGetPropNode(node, "namespace");
    ns = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
    if ((ns == NULL) || (xmlStrEqual(ns, BAD_CAST "##any")))
	wildc->any = 1;
    else if (xmlStrEqual(ns, BAD_CAST "##other")) {
	wildc->negNsSet = xmlSchemaNewWildcardNsConstraint(ctxt);
	if (wildc->negNsSet == NULL) {	    	    
	    return (-1);
	}
	wildc->negNsSet->value = schema->targetNamespace; 
    } else {    
	const xmlChar *end, *cur;

	cur = ns;
	do {
	    while (IS_BLANK_CH(*cur))
		cur++;
	    end = cur;
	    while ((*end != 0) && (!(IS_BLANK_CH(*end))))
		end++;
	    if (end == cur)
		break;
	    nsItem = xmlStrndup(cur, end - cur);    	    
	    if ((xmlStrEqual(nsItem, BAD_CAST "##other")) ||
		    (xmlStrEqual(nsItem, BAD_CAST "##any"))) {
		xmlSchemaPSimpleTypeErr(ctxt, 
		    XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER,
		    NULL, NULL, (xmlNodePtr) attr,
		    NULL, 
		    "((##any | ##other) | List of (anyURI | "
		    "(##targetNamespace | ##local)))", 
		    nsItem, NULL, NULL, NULL);
		ret = XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER;
	    } else {
		if (xmlStrEqual(nsItem, BAD_CAST "##targetNamespace")) {
		    dictnsItem = schema->targetNamespace;
		} else if (xmlStrEqual(nsItem, BAD_CAST "##local")) {
		    dictnsItem = NULL;
		} else {
		    /*
		    * Validate the item (anyURI).
		    */
		    xmlSchemaPValAttrNodeValue(ctxt, NULL, NULL, attr, 
			nsItem, xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI));
		    dictnsItem = xmlDictLookup(ctxt->dict, nsItem, -1);
		}
		/*
		* Avoid dublicate namespaces.
		*/
		tmp = wildc->nsSet;
		while (tmp != NULL) {
		    if (dictnsItem == tmp->value)
			break;
		    tmp = tmp->next;
		}
		if (tmp == NULL) {
		    tmp = xmlSchemaNewWildcardNsConstraint(ctxt);
		    if (tmp == NULL) {
			xmlFree(nsItem);			
			return (-1);
		    }
		    tmp->value = dictnsItem;
		    tmp->next = NULL;
		    if (wildc->nsSet == NULL) 
			wildc->nsSet = tmp;
		    else
			lastNs->next = tmp;
		    lastNs = tmp;
		}

	    }	
	    xmlFree(nsItem);
	    cur = end;
	} while (*cur != 0);    
    }
    return (ret);
}

static int
xmlSchemaPCheckParticleCorrect_2(xmlSchemaParserCtxtPtr ctxt, 
				 xmlSchemaTypePtr item, 
				 xmlNodePtr node,
				 int minOccurs,
				 int maxOccurs) {

    if (maxOccurs != UNBOUNDED) {
	/*
	* TODO: Maby we should better not create the particle, 
	* if min/max is invalid, since it could confuse the build of the 
	* content model.
	*/
	/* 
	* 3.9.6 Schema Component Constraint: Particle Correct
	*
	*/
	if (maxOccurs < 1) { 
	    /* 
	    * 2.2 {max occurs} must be greater than or equal to 1.
	    */
	    xmlSchemaPCustomAttrErr(ctxt,
		XML_SCHEMAP_P_PROPS_CORRECT_2_2,
		NULL, item, xmlSchemaGetPropNode(node, "maxOccurs"),
		"The value must be greater than or equal to 1");
	    return (XML_SCHEMAP_P_PROPS_CORRECT_2_2);
	} else if (minOccurs > maxOccurs) {
	    /*
	    * 2.1 {min occurs} must not be greater than {max occurs}.
	    */
	    xmlSchemaPCustomAttrErr(ctxt,
		XML_SCHEMAP_P_PROPS_CORRECT_2_1, 
		NULL, item, xmlSchemaGetPropNode(node, "minOccurs"),
		"The value must not be greater than the value of 'maxOccurs'");
	    return (XML_SCHEMAP_P_PROPS_CORRECT_2_1);
	}
    }	
    return (0);
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
    xmlSchemaWildcardPtr wildc;
    int minOccurs, maxOccurs;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    maxOccurs = xmlGetMaxOccurs(ctxt, node, 0, UNBOUNDED, 1, 
	"(nonNegativeInteger | unbounded)");
    minOccurs = xmlGetMinOccurs(ctxt, node, 0, -1, 1, 
	"nonNegativeInteger");
    if ((minOccurs == 0) && (maxOccurs == 0))
	return (NULL);

    snprintf((char *) name, 30, "any %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_ANY;    
    
    /*
    * TODO: Use a particle component here.
    */
    wildc = xmlSchemaAddWildcard(ctxt);
    /*
    * Check min/max sanity.
    */
    type->maxOccurs = maxOccurs;
    type->minOccurs = minOccurs;
    xmlSchemaPCheckParticleCorrect_2(ctxt, type, 
	    node, type->minOccurs, type->maxOccurs);    
    /*
    * This is not nice, since it is won't be used as a attribute wildcard,
    * but better than adding a field to the structure.
    */
    type->attributeWildcard = wildc;
    xmlSchemaParseWildcardNs(ctxt, schema, wildc, node);    
    child = node->children;    
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
    ret->targetNamespace = schema->targetNamespace;
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
 * Returns a wildcard or NULL.
 */
static xmlSchemaWildcardPtr
xmlSchemaParseAnyAttribute(xmlSchemaParserCtxtPtr ctxt,
                           xmlSchemaPtr schema, xmlNodePtr node)
{
    xmlSchemaWildcardPtr ret;
    xmlNodePtr child = NULL;
    xmlAttrPtr attr;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    ret = xmlSchemaAddWildcard(ctxt);
    if (ret == NULL) {
        return (NULL);
    }
    ret->type = XML_SCHEMA_TYPE_ANY_ATTRIBUTE;
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
	        (!xmlStrEqual(attr->name, BAD_CAST "namespace")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "processContents"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, NULL, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, NULL, attr);	
	}
	attr = attr->next;
    }
    /* ret->id = xmlSchemaGetProp(ctxt, node, "id"); */
    /*
    * Parse the namespace list.
    */
    if (xmlSchemaParseWildcardNs(ctxt, schema, ret, node) != 0) {
	xmlSchemaFreeWildcard(ret);
	return (NULL);
    }  
    /*
    * And now for the children...
    */
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (child != NULL) {
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED,
	    NULL, NULL, node, child, 
	    NULL, "(annotation?)");
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
    const xmlChar *name, *attrValue;
    xmlChar *repName = NULL; /* The reported designation. */
    xmlSchemaAttributePtr ret;
    xmlNodePtr child = NULL;    
    xmlAttrPtr attr, nameAttr;
    int isRef = 0;

    /*
     * Note that the w3c spec assumes the schema to be validated with schema
     * for schemas beforehand.
     *
     * 3.2.3 Constraints on XML Representations of Attribute Declarations
     */

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    attr = xmlSchemaGetPropNode(node, "ref");
    nameAttr = xmlSchemaGetPropNode(node, "name");

    if ((attr == NULL) && (nameAttr == NULL)) {
	/* 
	* 3.2.3 : 3.1
	* One of ref or name must be present, but not both 
	*/
	xmlSchemaPMissingAttrErr(ctxt, XML_SCHEMAP_SRC_ATTRIBUTE_3_1, 
	    (xmlChar **) &xmlSchemaElemDesAttrDecl, NULL, node, NULL, 
	    "One of the attributes 'ref' or 'name' must be present");
	return (NULL);
    }
    if ((topLevel) || (attr == NULL)) {
	if (nameAttr == NULL) {
	    xmlSchemaPMissingAttrErr(ctxt, XML_SCHEMAP_S4S_ATTR_MISSING, 
		(xmlChar **) &xmlSchemaElemDesAttrDecl, NULL, node, 
		"name", NULL);
	    return (NULL);
	}	
    } else
	isRef = 1;	
    
    if (isRef) {
	char buf[50]; 
	const xmlChar *refNs = NULL, *ref = NULL, *refPrefix = NULL; 

	/*
	* Parse as attribute reference.
	*/		
	if (xmlSchemaPValAttrNodeQName(ctxt, schema, 
	    (xmlChar **) &xmlSchemaElemDesAttrRef, NULL, attr, &refNs, 
	    &refPrefix, &ref) != 0) {
	    return (NULL);
	}	
        snprintf(buf, 49, "#aRef %d", ctxt->counter++ + 1);
        name = (const xmlChar *) buf;	
	ret = xmlSchemaAddAttribute(ctxt, schema, name, NULL, node);
	if (ret == NULL) {
	    if (repName != NULL)
		xmlFree(repName);
	    return (NULL);
	}
	ret->type = XML_SCHEMA_TYPE_ATTRIBUTE;
	ret->node = node;
	ret->refNs = refNs;
	ret->refPrefix = refPrefix;
	ret->ref = ref;		
	/*
	xmlSchemaFormatTypeRep(&repName, (xmlSchemaTypePtr) ret, NULL, NULL);
	*/
	if (nameAttr != NULL)
	    xmlSchemaPMutualExclAttrErr(ctxt, XML_SCHEMAP_SRC_ATTRIBUTE_3_1, 
		&repName, (xmlSchemaTypePtr) ret, nameAttr, 
		"ref", "name");
	/*
	* Check for illegal attributes.
	*/
	attr = node->properties;
	while (attr != NULL) {
	    if (attr->ns == NULL) {
		if (xmlStrEqual(attr->name, BAD_CAST "type") ||
		    xmlStrEqual(attr->name, BAD_CAST "form")) {
		    /* 
		    * 3.2.3 : 3.2
		    * If ref is present, then all of <simpleType>,
		    * form and type must be absent. 
		    */
		    xmlSchemaPIllegalAttrErr(ctxt, 
			XML_SCHEMAP_SRC_ATTRIBUTE_3_2, &repName, 
			(xmlSchemaTypePtr) ret, attr);
		} else if ((!xmlStrEqual(attr->name, BAD_CAST "ref")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "use")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "name")) && 
		    (!xmlStrEqual(attr->name, BAD_CAST "fixed")) && 
		    (!xmlStrEqual(attr->name, BAD_CAST "default"))) {
		    xmlSchemaPIllegalAttrErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
			&repName, (xmlSchemaTypePtr) ret, attr);		    
		}
	    } else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    &repName, (xmlSchemaTypePtr) ret, attr);		
	    }
	    attr = attr->next;
	}	
    } else {
        const xmlChar *ns = NULL;
	
	/*
	* Parse as attribute declaration.
	*/			
	if (xmlSchemaPValAttrNode(ctxt, 
	    (xmlChar **) &xmlSchemaElemDesAttrDecl, NULL, nameAttr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_NCNAME), &name) != 0) {
	    return (NULL);
	}
	/*
	xmlSchemaFormatTypeRep(&repName, NULL, xmlSchemaElemDesAttrDecl, name);
	*/
	/* 
	* 3.2.6 Schema Component Constraint: xmlns Not Allowed 
	*/
	if (xmlStrEqual(name, BAD_CAST "xmlns")) {
	    xmlSchemaPSimpleTypeErr(ctxt, 
		XML_SCHEMAP_NO_XMLNS, 
		&repName, NULL, (xmlNodePtr) nameAttr, 
		xmlSchemaGetBuiltInType(XML_SCHEMAS_NCNAME), "NCName", NULL,
		"The value must not match 'xmlns'", 
		NULL, NULL);	    
	    if (repName != NULL)
		xmlFree(repName);
	    return (NULL);
	}	    
	/* 
	* Evaluate the target namespace 
	*/	
	if (topLevel) {
	    ns = schema->targetNamespace;
	} else {
	    attr = xmlSchemaGetPropNode(node, "form");
	    if (attr != NULL) {
		attrValue = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
		if (xmlStrEqual(attrValue, BAD_CAST "qualified")) {
		    ns = schema->targetNamespace;
		} else if (!xmlStrEqual(attrValue, BAD_CAST "unqualified")) {
		    xmlSchemaPSimpleTypeErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_INVALID_VALUE, 
			&repName, NULL, (xmlNodePtr) attr, 
			NULL, "(qualified | unqualified)", 
			attrValue, NULL, NULL, NULL);			
		}
	    } else if (schema->flags & XML_SCHEMAS_QUALIF_ATTR)
		ns = schema->targetNamespace;		
	}				
	ret = xmlSchemaAddAttribute(ctxt, schema, name, ns, node);
	if (ret == NULL) {
	    if (repName != NULL)
		xmlFree(repName);
	    return (NULL);
	}
	ret->type = XML_SCHEMA_TYPE_ATTRIBUTE;
	ret->node = node;	
	if (topLevel)
	    ret->flags |= XML_SCHEMAS_ATTR_GLOBAL;
	/* 
	* 3.2.6 Schema Component Constraint: xsi: Not Allowed 
	*/	
	if (xmlStrEqual(ret->targetNamespace, xmlSchemaInstanceNs)) {
	    xmlSchemaPCustomErr(ctxt, 
		XML_SCHEMAP_NO_XSI,
		&repName, (xmlSchemaTypePtr) ret, node,
		"The target namespace must not match '%s'", 
		xmlSchemaInstanceNs);	        
	}
	/*
	* Check for illegal attributes. 
	*/	
	attr = node->properties;
	while (attr != NULL) {
	    if (attr->ns == NULL) {		
		if ((!xmlStrEqual(attr->name, BAD_CAST "id")) && 
		    (!xmlStrEqual(attr->name, BAD_CAST "default")) && 				
		    (!xmlStrEqual(attr->name, BAD_CAST "fixed")) &&		    
		    (!xmlStrEqual(attr->name, BAD_CAST "name")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "type"))) {
		    if ((topLevel) ||						    		
		        ((!xmlStrEqual(attr->name, BAD_CAST "form")) &&
			 (!xmlStrEqual(attr->name, BAD_CAST "use")))) {
			xmlSchemaPIllegalAttrErr(ctxt, 
			    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
			    &repName, (xmlSchemaTypePtr) ret, attr);	
		    }
		}
	    } else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
		xmlSchemaPIllegalAttrErr(ctxt, XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    &repName, (xmlSchemaTypePtr) ret, attr);	
	    }
	    attr = attr->next;
	}
	xmlSchemaPValAttrQName(ctxt, schema, &repName, (xmlSchemaTypePtr) ret,
	    node, "type", &ret->typeNs, NULL, &ret->typeName);
    }    
    /* TODO: Check ID. */
    ret->id = xmlSchemaGetProp(ctxt, node, "id");  
    /*
    * Attribute "fixed".
    */
    ret->defValue = xmlSchemaGetProp(ctxt, node, "fixed");
    if (ret->defValue != NULL)
	ret->flags |= XML_SCHEMAS_ATTR_FIXED;
    /* 
    * Attribute "default".
    */
    attr = xmlSchemaGetPropNode(node, "default");
    if (attr != NULL) {
	/* 
	* 3.2.3 : 1
	* default and fixed must not both be present. 
	*/
	if (ret->flags & XML_SCHEMAS_ATTR_FIXED) {
	    xmlSchemaPMutualExclAttrErr(ctxt, XML_SCHEMAP_SRC_ATTRIBUTE_1,
		&repName, (xmlSchemaTypePtr) ret, attr, "default", "fixed");
	} else
	    ret->defValue = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);		
    }    
    if (topLevel == 0) {
	/* 
	* Attribute "use". 
	*/
	attr = xmlSchemaGetPropNode(node, "use");
	if (attr != NULL) {
	    attrValue = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
	    if (xmlStrEqual(attrValue, BAD_CAST "optional"))
		ret->occurs = XML_SCHEMAS_ATTR_USE_OPTIONAL;
	    else if (xmlStrEqual(attrValue, BAD_CAST "prohibited"))
		ret->occurs = XML_SCHEMAS_ATTR_USE_PROHIBITED;
	    else if (xmlStrEqual(attrValue, BAD_CAST "required"))
		ret->occurs = XML_SCHEMAS_ATTR_USE_REQUIRED;
	    else
		xmlSchemaPSimpleTypeErr(ctxt, 
		    XML_SCHEMAP_INVALID_ATTR_USE, 
		    &repName, (xmlSchemaTypePtr) ret, (xmlNodePtr) attr, 
		    NULL, "(optional | prohibited | required)", 
		    attrValue, NULL, NULL, NULL);				
	} else
	    ret->occurs = XML_SCHEMAS_ATTR_USE_OPTIONAL;
	/* 
	* 3.2.3 : 2
	* If default and use are both present, use must have
	* the actual value optional.
	*/
	if ((ret->occurs != XML_SCHEMAS_ATTR_USE_OPTIONAL) && 
	    (ret->defValue != NULL) && 
	    ((ret->flags & XML_SCHEMAS_ATTR_FIXED) == 0)) {
	    xmlSchemaPSimpleTypeErr(ctxt, 
		XML_SCHEMAP_SRC_ATTRIBUTE_2, 
		&repName, (xmlSchemaTypePtr) ret, (xmlNodePtr) attr, 
		NULL, "(optional | prohibited | required)", NULL, 
		"The value must be 'optional' if the attribute "
		"'default' is present as well", NULL, NULL);	    
	}
    }                          
    /*
    * And now for the children...
    */
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }    
    if (isRef) {
	if (child != NULL) {	    
	    if (IS_SCHEMA(child, "simpleType"))
		/* 
		* 3.2.3 : 3.2
		* If ref is present, then all of <simpleType>,
		* form and type must be absent. 
		*/
		xmlSchemaPContentErr(ctxt, XML_SCHEMAP_SRC_ATTRIBUTE_3_2,
		    &repName, (xmlSchemaTypePtr) ret, node, child, NULL,
		    "(annotation?)");
	    else 
		xmlSchemaPContentErr(ctxt, XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED,
		    &repName, (xmlSchemaTypePtr) ret, node, child, NULL,
		    "(annotation?)");  
	}
    } else {
	if (IS_SCHEMA(child, "simpleType")) {
	    if (ret->typeName != NULL) {
		/* 
		* 3.2.3 : 4
		* type and <simpleType> must not both be present. 
		*/
		xmlSchemaPContentErr(ctxt, XML_SCHEMAP_SRC_ATTRIBUTE_4,
		    &repName,  (xmlSchemaTypePtr) ret, node, child,
		    "The attribute 'type' and the <simpleType> child "
		    "are mutually exclusive", NULL);
	    } else
		ret->subtypes = xmlSchemaParseSimpleType(ctxt, schema, child, 0);
	    child = child->next;
	}
	if (child != NULL)
	    xmlSchemaPContentErr(ctxt, XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED,
		&repName, (xmlSchemaTypePtr) ret, node, child, NULL,
		"(annotation?, simpleType?)");
    }
    /*
    * Cleanup.
    */
    if (repName != NULL)
	xmlFree(repName);
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
    const xmlChar *name;
    xmlSchemaAttributeGroupPtr ret;
    xmlNodePtr child = NULL;
    const xmlChar *oldcontainer;    
    xmlAttrPtr attr, nameAttr;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    nameAttr = xmlSchemaGetPropNode(node, "name");
    attr = xmlSchemaGetPropNode(node, "ref");   
    if ((topLevel) || (attr == NULL)) {
	/*
	* Parse as an attribute group definition.
	* Note that those are allowed at top level only.
	*/
	if (nameAttr == NULL) {
	    xmlSchemaPMissingAttrErr(ctxt,
		XML_SCHEMAP_S4S_ATTR_MISSING,
		NULL, NULL, node, "name", NULL);	    
	    return (NULL);
	}
	name = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) nameAttr);
	/*
	* The name is crucial, exit if invalid. 
	*/
	if (xmlSchemaPValAttrNode(ctxt,
	    NULL, NULL, nameAttr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_NCNAME), &name) != 0) {
	    return (NULL);
	}
	ret = xmlSchemaAddAttributeGroup(ctxt, schema, name, node);
	if (ret == NULL)
	    return (NULL);
	ret->type = XML_SCHEMA_TYPE_ATTRIBUTEGROUP;
	ret->flags |= XML_SCHEMAS_ATTRGROUP_GLOBAL;
	ret->node = node;
	ret->targetNamespace = schema->targetNamespace;
    } else {    
	char buf[50];
	const xmlChar *refNs = NULL, *ref = NULL, *refPrefix;

	/*
	* Parse as an attribute group definition reference.
	*/
	if (attr == NULL) {
	    xmlSchemaPMissingAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_MISSING, 
		NULL, NULL, node, "ref", NULL);
	}	
	xmlSchemaPValAttrNodeQName(ctxt, schema,
	    NULL, NULL, attr, &refNs, &refPrefix, &ref);
	 
        snprintf(buf, 49, "#aGrRef %d", ctxt->counter++ + 1);
	name = (const xmlChar *) buf;
	if (name == NULL) {
	    xmlSchemaPErrMemory(ctxt, "creating internal name for an "
		"attribute group definition reference", node);
            return (NULL);
        }
	ret = xmlSchemaAddAttributeGroup(ctxt, schema, name, node);
	if (ret == NULL)
	    return (NULL);
	ret->type = XML_SCHEMA_TYPE_ATTRIBUTEGROUP;
	ret->ref = ref;
	ret->refNs = refNs;
	/* TODO: Is @refPrefix currently used? */
	ret->refPrefix = refPrefix;
	ret->node = node;
    }    
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((((topLevel == 0) && (!xmlStrEqual(attr->name, BAD_CAST "ref"))) ||
		 (topLevel && (!xmlStrEqual(attr->name, BAD_CAST "name")))) &&
		(!xmlStrEqual(attr->name, BAD_CAST "id"))) 
	    {
		xmlSchemaPIllegalAttrErr(ctxt,
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
		    NULL, NULL, attr);
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt,
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
		NULL, NULL, attr);
	}
	attr = attr->next;
    }	
    /* TODO: Validate "id" ? */  
    /*
    * And now for the children...
    */
    oldcontainer = ctxt->container;
    ctxt->container = name;
    child = node->children;    
    if (IS_SCHEMA(child, "annotation")) {
        ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    if (topLevel) {
	child = xmlSchemaParseAttrDecls(ctxt, schema, child, (xmlSchemaTypePtr) ret); 
	if (IS_SCHEMA(child, "anyAttribute")) {
	    ret->attributeWildcard = xmlSchemaParseAnyAttribute(ctxt, schema, child);
	    child = child->next;
	}
    }
    if (child != NULL) {
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED, 
	    NULL, NULL, node, child, NULL, 
	    "(annotation?)");
    }
    ctxt->container = oldcontainer;
    return (ret);
}

/**
 * xmlSchemaPValAttrFormDefault:
 * @value:  the value
 * @flags: the flags to be modified
 * @flagQualified: the specific flag for "qualified"
 *
 * Returns 0 if the value is valid, 1 otherwise.
 */
static int
xmlSchemaPValAttrFormDefault(const xmlChar *value,
			     int *flags,
			     int flagQualified)
{
    if (xmlStrEqual(value, BAD_CAST "qualified")) {
	if  ((*flags & flagQualified) == 0)
	    *flags |= flagQualified;
    } else if (!xmlStrEqual(value, BAD_CAST "unqualified"))
	return (1);    
	
    return (0);
}

/**
 * xmlSchemaPValAttrBlockFinal:
 * @value:  the value
 * @flags: the flags to be modified
 * @flagAll: the specific flag for "#all"
 * @flagExtension: the specific flag for "extension"
 * @flagRestriction: the specific flag for "restriction"
 * @flagSubstitution: the specific flag for "substitution"
 * @flagList: the specific flag for "list"
 * @flagUnion: the specific flag for "union"
 *
 * Validates the value of the attribute "final" and "block". The value
 * is converted into the specified flag values and returned in @flags.
 *
 * Returns 0 if the value is valid, 1 otherwise.
 */

static int
xmlSchemaPValAttrBlockFinal(const xmlChar *value,
			    int *flags,			
			    int flagAll,
			    int flagExtension,
			    int flagRestriction,
			    int flagSubstitution,
			    int flagList,
			    int flagUnion)			
{
    int ret = 0;

    /*
    * TODO: This does not check for dublicate entries.
    */
    if (value == NULL)
	return (1);
    if (xmlStrEqual(value, BAD_CAST "#all")) {
	if (flagAll != -1)
	    *flags |= flagAll;
	else {
	    if (flagExtension != -1) 
		*flags |= flagExtension; 
	    if (flagRestriction != -1) 
		*flags |= flagRestriction;
	    if (flagSubstitution != -1) 
		*flags |= flagSubstitution;
	    if (flagList != -1) 
		*flags |= flagList;
	    if (flagUnion != -1) 
		*flags |= flagUnion;
	}
    } else {
	const xmlChar *end, *cur = value;
	xmlChar *item;
	
	do {
	    while (IS_BLANK_CH(*cur))
		cur++;
	    end = cur;
	    while ((*end != 0) && (!(IS_BLANK_CH(*end))))
		end++;
	    if (end == cur)
		break;
	    item = xmlStrndup(cur, end - cur);    	    
	    if (xmlStrEqual(item, BAD_CAST "extension")) {
		if (flagExtension != -1) {
		    if ((*flags & flagExtension) == 0)
			*flags |= flagExtension;
		} else 
		    ret = 1;
	    } else if (xmlStrEqual(item, BAD_CAST "restriction")) {
		if (flagRestriction != -1) {
		    if ((*flags & flagRestriction) == 0)
			*flags |= flagRestriction;
		} else 
		    ret = 1;
	    } else if (xmlStrEqual(item, BAD_CAST "substitution")) {
		if (flagSubstitution != -1) {
		    if ((*flags & flagSubstitution) == 0)
			*flags |= flagSubstitution;
		} else 
		    ret = 1;
	    } else if (xmlStrEqual(item, BAD_CAST "list")) {
		if (flagList != -1) {
		    if ((*flags & flagList) == 0)
			*flags |= flagList;
		} else 
		    ret = 1;
	    } else if (xmlStrEqual(item, BAD_CAST "union")) {
		if (flagUnion != -1) {
		    if ((*flags & flagUnion) == 0)
			*flags |= flagUnion;
		} else 
		    ret = 1;
	    } else 
		ret = 1;
	    if (item != NULL)
		xmlFree(item);
	    cur = end;
	} while ((ret == 0) && (*cur != 0)); 
    }    
    
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
    const xmlChar *name = NULL;    
    const xmlChar *attrValue;
    xmlChar *repName = NULL;
    xmlSchemaElementPtr ret;
    xmlNodePtr child = NULL;
    const xmlChar *oldcontainer;    
    xmlAttrPtr attr, nameAttr;
    int minOccurs, maxOccurs;
    int isRef = 0;

    /* 3.3.3 Constraints on XML Representations of Element Declarations */
    /* TODO: Complete implementation of 3.3.6 */
   
    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    oldcontainer = ctxt->container;
     
    nameAttr = xmlSchemaGetPropNode(node, "name");
    attr = xmlSchemaGetPropNode(node, "ref");   
    if ((topLevel) || (attr == NULL)) {
	if (nameAttr == NULL) {
	    xmlSchemaPMissingAttrErr(ctxt,
		XML_SCHEMAP_S4S_ATTR_MISSING,
		(xmlChar **) &xmlSchemaElemDesElemDecl, NULL, node,
		"name", NULL);	    
	    return (NULL);
	}
	name = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) nameAttr);		
    } else {
	isRef = 1;
	
    }
    /* 
    * ... unless minOccurs=maxOccurs=0, in which case the item corresponds 
    * to no component at all
    * TODO: It might be better to validate the element, even if it won't be 
    * used.
    */    
    minOccurs = xmlGetMinOccurs(ctxt, node, 0, -1, 1, "nonNegativeInteger");
    maxOccurs = xmlGetMaxOccurs(ctxt, node, 0, UNBOUNDED, 1, "(nonNegativeInteger | unbounded)");
    if ((minOccurs == 0) && (maxOccurs == 0))
	return (NULL);
    /*
    * If we get a "ref" attribute on a local <element> we will assume it's
    * a reference - even if there's a "name" attribute; this seems to be more 
    * robust.
    */
    if (isRef) {
	char buf[50];
	const xmlChar *refNs = NULL, *ref = NULL, *refPrefix;

	/*
	* Parse as a particle.
	*/
	xmlSchemaPValAttrNodeQName(ctxt, schema,
	    (xmlChar **) &xmlSchemaElemDesAttrRef, 
	    NULL, attr, &refNs, &refPrefix, &ref);			
	 
        snprintf(buf, 49, "#eRef %d", ctxt->counter++ + 1);
	ret = xmlSchemaAddElement(ctxt, schema, (const xmlChar *) buf, NULL, node, 0);
	if (ret == NULL) {
	    if (repName != NULL)
		xmlFree(repName);
	    return (NULL);
	}
	ret->type = XML_SCHEMA_TYPE_ELEMENT;
	ret->node = node;     		
	ret->ref = ref;
	ret->refNs = refNs;
	ret->refPrefix = refPrefix;
	ret->flags |= XML_SCHEMAS_ELEM_REF;
	/* 
	* Check for illegal attributes.
	*/
	/* 
	* 3.3.3 : 2.1
	* One of ref or name must be present, but not both 
	*/
	if (nameAttr != NULL) {
	    xmlSchemaPMutualExclAttrErr(ctxt, 
		XML_SCHEMAP_SRC_ELEMENT_2_1,
		&repName, (xmlSchemaTypePtr) ret, nameAttr,
		"ref", "name");
	}
	/* 3.3.3 : 2.2 */   
	attr = node->properties;
	while (attr != NULL) {
	    if (attr->ns == NULL) {
		if (xmlStrEqual(attr->name, BAD_CAST "ref") ||
		    xmlStrEqual(attr->name, BAD_CAST "name") ||
		    xmlStrEqual(attr->name, BAD_CAST "id") ||
		    xmlStrEqual(attr->name, BAD_CAST "maxOccurs") ||
		    xmlStrEqual(attr->name, BAD_CAST "minOccurs"))
		{
		    attr = attr->next;
		    continue;
		} else {
		    xmlSchemaPCustomAttrErr(ctxt, 
			XML_SCHEMAP_SRC_ELEMENT_2_2,
			&repName, (xmlSchemaTypePtr) ret, attr, 
			"Only the attributes 'minOccurs', 'maxOccurs' and "
			"'id' are allowed in addition to 'ref'");
		    break;
		}
	    } else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
		xmlSchemaPIllegalAttrErr(ctxt,
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
		    &repName, (xmlSchemaTypePtr) ret, attr);
	    }
	    attr = attr->next;
	}	      
    } else {
	const xmlChar *ns = NULL, *fixed;

	/*
	* Parse as an element declaration.
	*/
	if (xmlSchemaPValAttrNode(ctxt, 
	    (xmlChar **) &xmlSchemaElemDesElemDecl, NULL, nameAttr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_NCNAME), &name) != 0)
	    return (NULL);
	/* 
	* Evaluate the target namespace.
	*/
	if (topLevel) {
	    ns = schema->targetNamespace;
	} else {
	    attr = xmlSchemaGetPropNode(node, "form");
	    if (attr != NULL) {
		attrValue = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
		if (xmlStrEqual(attrValue, BAD_CAST "qualified")) {
		    ns = schema->targetNamespace;
		} else if (!xmlStrEqual(attrValue, BAD_CAST "unqualified")) {
		    xmlSchemaPSimpleTypeErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_INVALID_VALUE, 
			&repName, NULL, (xmlNodePtr) attr, 
			NULL, "(qualified | unqualified)", 
			attrValue, NULL, NULL, NULL);			
		}
	    } else if (schema->flags & XML_SCHEMAS_QUALIF_ELEM)
		ns = schema->targetNamespace;		
	}	
	ret = xmlSchemaAddElement(ctxt, schema, name, ns, node, topLevel);
	if (ret == NULL) {
	    if (repName != NULL)
		xmlFree(repName);
	    return (NULL);
	}
	ret->type = XML_SCHEMA_TYPE_ELEMENT;
	ret->node = node;
	ret->targetNamespace = ns;
	/* 
	* Check for illegal attributes.
	*/
	attr = node->properties;
	while (attr != NULL) {
	    if (attr->ns == NULL) {
		if ((!xmlStrEqual(attr->name, BAD_CAST "name")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "type")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "id")) &&		
		    (!xmlStrEqual(attr->name, BAD_CAST "default")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "fixed")) &&		
		    (!xmlStrEqual(attr->name, BAD_CAST "block")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "nillable"))) 
		{	
		    if (topLevel == 0) { 						
			if ((!xmlStrEqual(attr->name, BAD_CAST "maxOccurs")) &&
			    (!xmlStrEqual(attr->name, BAD_CAST "minOccurs")) &&
			    (!xmlStrEqual(attr->name, BAD_CAST "form"))) 
			{
			    if (xmlStrEqual(attr->name, BAD_CAST "substitutionGroup")) {
				/*
				* 3.3.6 : 3 If there is a non-·absent· {substitution 
				* group affiliation}, then {scope} must be global.
				* TODO: This one is redundant, since the S4S does 
				* prohibit this attribute on local declarations already; 
				* so why an explicit error code? Weird spec.
				* TODO: Move this to the proper constraint layer.
				* TODO: Or better wait for spec 1.1 to come.
				*/
				xmlSchemaPIllegalAttrErr(ctxt,
				    XML_SCHEMAP_E_PROPS_CORRECT_3,
				    &repName, (xmlSchemaTypePtr) ret, attr);
			    } else {
				xmlSchemaPIllegalAttrErr(ctxt,
				    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
				    &repName, (xmlSchemaTypePtr) ret, attr);
			    }
			}
		    } else if ((!xmlStrEqual(attr->name, BAD_CAST "final")) && 
			(!xmlStrEqual(attr->name, BAD_CAST "abstract")) && 
			(!xmlStrEqual(attr->name, BAD_CAST "substitutionGroup"))) {

			xmlSchemaPIllegalAttrErr(ctxt,
			    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
			    &repName, (xmlSchemaTypePtr) ret, attr);		    
		    }
		}
	    } else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
		
		xmlSchemaPIllegalAttrErr(ctxt,
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
		    &repName, (xmlSchemaTypePtr) ret, attr);
	    }
	    attr = attr->next;
	}		
	/*
	* Extract/validate attributes.
	*/
	if (topLevel) {
	    /* 
	    * Process top attributes of global element declarations here.
	    */
	    ret->flags |= XML_SCHEMAS_ELEM_GLOBAL;
	    ret->flags |= XML_SCHEMAS_ELEM_TOPLEVEL;
	    xmlSchemaPValAttrQName(ctxt, schema, &repName, 
		(xmlSchemaTypePtr) ret, node, "substitutionGroup", 
		&(ret->substGroupNs), NULL, &(ret->substGroup));
	    if (xmlGetBooleanProp(ctxt, &repName, (xmlSchemaTypePtr) ret,  
		node, "abstract", 0))
		ret->flags |= XML_SCHEMAS_ELEM_ABSTRACT; 
	    /*
	    * Attribute "final".
	    */
	    attr = xmlSchemaGetPropNode(node, "final");	    
	    if (attr == NULL) {
		ret->flags |= XML_SCHEMAS_ELEM_FINAL_ABSENT;
	    } else {
		attrValue = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);	    
		if (xmlSchemaPValAttrBlockFinal(attrValue, &(ret->flags), 
		    -1,
		    XML_SCHEMAS_ELEM_FINAL_EXTENSION,
		    XML_SCHEMAS_ELEM_FINAL_RESTRICTION, -1, -1, -1) != 0) {
		    xmlSchemaPSimpleTypeErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
			&repName, (xmlSchemaTypePtr) ret, (xmlNodePtr) attr, 
			NULL, "(#all | List of (extension | restriction))", 
			attrValue, NULL, NULL, NULL);
		}
	    }
	}    
	/*
	* Attribute "block".
	*/
	attr = xmlSchemaGetPropNode(node, "block");	
	if (attr == NULL) {
	    ret->flags |= XML_SCHEMAS_ELEM_BLOCK_ABSENT;
	} else {
	    attrValue = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);	    
	    if (xmlSchemaPValAttrBlockFinal(attrValue, &(ret->flags), 
		-1,
		XML_SCHEMAS_ELEM_BLOCK_EXTENSION,
		XML_SCHEMAS_ELEM_BLOCK_RESTRICTION, 
		XML_SCHEMAS_ELEM_BLOCK_SUBSTITUTION, -1, -1) != 0) {
		xmlSchemaPSimpleTypeErr(ctxt,
		    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
		    &repName, (xmlSchemaTypePtr) ret, (xmlNodePtr) attr,
		    NULL, "(#all | List of (extension | "
		    "restriction | substitution))", attrValue, 
		    NULL, NULL, NULL);		
	    }
	}
	if (xmlGetBooleanProp(ctxt, &repName, (xmlSchemaTypePtr) ret, 
	    node, "nillable", 0))
	    ret->flags |= XML_SCHEMAS_ELEM_NILLABLE;	

	xmlSchemaPValAttrQName(ctxt, schema, 
	    &repName, (xmlSchemaTypePtr) ret, node, 
	    "type", &(ret->namedTypeNs), NULL, &(ret->namedType));

	ret->value = xmlSchemaGetProp(ctxt, node, "default");    
	attr = xmlSchemaGetPropNode(node, "fixed");	
	if (attr != NULL) {
	    fixed = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
	    if (ret->value != NULL) {
		/* 
		* 3.3.3 : 1 
		* default and fixed must not both be present. 
		*/
		xmlSchemaPMutualExclAttrErr(ctxt,
		    XML_SCHEMAP_SRC_ELEMENT_1,
		    &repName, (xmlSchemaTypePtr) ret, attr,
		    "default", "fixed");
	    } else {
		ret->flags |= XML_SCHEMAS_ELEM_FIXED;
		ret->value = fixed;
	    }
	}	
    }     
    /*
    * Extract/validate common attributes.
    */    
    /* TODO: Check ID: */
    ret->id = xmlSchemaGetProp(ctxt, node, "id");
    ret->minOccurs = minOccurs;
    ret->maxOccurs = maxOccurs; 
    if (topLevel != 1)
	xmlSchemaPCheckParticleCorrect_2(ctxt, (xmlSchemaTypePtr) ret, 
	    node, minOccurs, maxOccurs);    
    /*
    * And now for the children...
    */
    ctxt->container = ret->name;
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
	ret->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
	child = child->next;
    }
    if (isRef) {
	if (child != NULL) {
	    xmlSchemaPContentErr(ctxt,
		XML_SCHEMAP_SRC_ELEMENT_2_2,
		&repName, (xmlSchemaTypePtr) ret, node, child, 
		NULL, "(annotation?)");
	}
    } else {			
	if (IS_SCHEMA(child, "complexType")) {
	    /* 
	    * 3.3.3 : 3 
	    * "type" and either <simpleType> or <complexType> are mutually
	    * exclusive 
	    */
	    if (ret->namedType != NULL) {
		xmlSchemaPContentErr(ctxt,
		    XML_SCHEMAP_SRC_ELEMENT_3,
		    &repName, (xmlSchemaTypePtr) ret, node, child, 
		    "The attribute 'type' and the <complexType> child are "
		    "mutually exclusive", NULL);		
	    } else
		ret->subtypes = xmlSchemaParseComplexType(ctxt, schema, child, 0);
	    child = child->next;
	} else if (IS_SCHEMA(child, "simpleType")) {
	    /* 
	    * 3.3.3 : 3 
	    * "type" and either <simpleType> or <complexType> are
	    * mutually exclusive 
	    */
	    if (ret->namedType != NULL) {
		xmlSchemaPContentErr(ctxt,
		    XML_SCHEMAP_SRC_ELEMENT_3,
		    &repName, (xmlSchemaTypePtr) ret, node, child, 
		    "The attribute 'type' and the <simpleType> child are "
		    "mutually exclusive", NULL);				
	    } else
		ret->subtypes = xmlSchemaParseSimpleType(ctxt, schema, child, 0);
	    child = child->next;
	}	
	while ((IS_SCHEMA(child, "unique")) ||
	    (IS_SCHEMA(child, "key")) || (IS_SCHEMA(child, "keyref"))) {
	    TODO child = child->next;
	}
	if (child != NULL) {
	    xmlSchemaPContentErr(ctxt,
		XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED,
		&repName, (xmlSchemaTypePtr) ret, node, child, 
		NULL, "(annotation?, ((simpleType | complexType)?, "
		"(unique | key | keyref)*))");
	}		

    }
    ctxt->container = oldcontainer;
    /*
    * Cleanup.
    */
    if (repName != NULL)
	xmlFree(repName);    
    /*
    * NOTE: Element Declaration Representation OK 4. will be checked at a 
    * different layer.
    */
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
    xmlAttrPtr attr;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    snprintf((char *) name, 30, "#union %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->type = XML_SCHEMA_TYPE_UNION;
    type->node = node;
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "memberTypes"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, type, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, type, attr);		
	}
	attr = attr->next;
    }	
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    /*
    * Attribute "memberTypes". This is a list of QNames.
    * TODO: Validate the QNames.
    */
    type->base = xmlSchemaGetProp(ctxt, node, "memberTypes");
    /*
    * And now for the children...
    */
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
	/* TODO: Think about the error code. */
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_UNKNOWN_UNION_CHILD, 
	    NULL, type, node, child, NULL, "(annotation?, simpleType*)");
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
    xmlAttrPtr attr;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    snprintf((char *) name, 30, "#list %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_LIST;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "itemType"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, type, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, type, attr);		
	}
	attr = attr->next;
    }	
    /*
    * Attribute "itemType".
    */
    xmlSchemaPValAttrQName(ctxt, schema, NULL, NULL,
	node, "itemType", &(type->baseNs), NULL, &(type->base));
    /*
    * And now for the children...
    */
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }    	
    subtype = NULL;
    if (IS_SCHEMA(child, "simpleType")) {
	if (type->base != NULL) {
	    xmlSchemaPCustomErr(ctxt, 
		XML_SCHEMAP_SRC_SIMPLE_TYPE_1,
		NULL, type, node, 
		"The attribute 'itemType' and the <simpleType> child "
		"are mutually exclusive", NULL);	    
	} else {	
	    subtype = (xmlSchemaTypePtr)
		xmlSchemaParseSimpleType(ctxt, schema, child, 0);
	    type->subtypes = subtype;
	}
        child = child->next;        
    }
    if (child != NULL) {
	/* TODO: Think about the error code. */
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_UNKNOWN_LIST_CHILD, 
	    NULL, type, node, child, NULL, "(annotation?, simpleType?)");
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
 * 1 in case of success.
 */
static xmlSchemaTypePtr
xmlSchemaParseSimpleType(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                         xmlNodePtr node, int topLevel)
{
    xmlSchemaTypePtr type, subtype, oldCtxtType, oldParentItem;
    xmlNodePtr child = NULL;
    const xmlChar *attrValue = NULL;
    xmlChar *des = NULL;
    xmlAttrPtr attr;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
   
    if (topLevel) {
	attr = xmlSchemaGetPropNode(node, "name");
	if (attr == NULL) {
	    xmlSchemaPMissingAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_MISSING, 
		(xmlChar **) &xmlSchemaElemDesST, NULL, node,
		"name", NULL);
	    return (NULL);
	} else if (xmlSchemaPValAttrNode(ctxt, 
	    (xmlChar **) &xmlSchemaElemDesST, NULL, attr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_NCNAME), &attrValue) != 0) {
	    return (NULL);
	}
    }
            
    if (topLevel == 0) {
        char buf[40];

	/*
	* Parse as local simple type definition.
	*/
        snprintf(buf, 39, "#ST %d", ctxt->counter++ + 1);
	type = xmlSchemaAddType(ctxt, schema, (const xmlChar *)buf, NULL, node);
	if (type == NULL)
	    return (NULL);
	type->node = node;
	type->type = XML_SCHEMA_TYPE_SIMPLE;
	/*
	* Check for illegal attributes.
	*/
	attr = node->properties;
	while (attr != NULL) {
	    if (attr->ns == NULL) {
		if (!xmlStrEqual(attr->name, BAD_CAST "id")) {
		    xmlSchemaPIllegalAttrErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
			&des, type, attr);		    
		}
	    } else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
		    xmlSchemaPIllegalAttrErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
			&des, type, attr);	
	    }
	    attr = attr->next;
	}
    } else {		
	/*
	* Parse as global simple type definition.
	*
	* Note that attrValue is the value of the attribute "name" here.
	*/	
	type = xmlSchemaAddType(ctxt, schema, attrValue, schema->targetNamespace, node);
	if (type == NULL)
	    return (NULL);
	type->node = node;
	type->type = XML_SCHEMA_TYPE_SIMPLE;
	type->flags |= XML_SCHEMAS_TYPE_GLOBAL;
	/*
	* Check for illegal attributes.
	*/
	attr = node->properties;
	while (attr != NULL) {
	    if (attr->ns == NULL) {
		if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "name")) &&
		    (!xmlStrEqual(attr->name, BAD_CAST "final"))) {
		    xmlSchemaPIllegalAttrErr(ctxt, 
			XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
			&des, type, attr);	
		}
	    } else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    &des, type, attr);	
	    }
	    attr = attr->next;
	}
	/*
	* Attribute "final".
	*/
	attr = xmlSchemaGetPropNode(node, "final");	
	if (attr == NULL) {
	    type->flags |= XML_SCHEMAS_TYPE_FINAL_DEFAULT;
	} else {
	    attrValue = xmlSchemaGetProp(ctxt, node, "final");
	    if (xmlSchemaPValAttrBlockFinal(attrValue, &(type->flags), 
		-1, -1, XML_SCHEMAS_TYPE_FINAL_RESTRICTION, -1,	    
		XML_SCHEMAS_TYPE_FINAL_LIST,
		XML_SCHEMAS_TYPE_FINAL_UNION) != 0) {

		xmlSchemaPSimpleTypeErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
		    &des, type, (xmlNodePtr) attr, 
		    NULL, "(#all | List of (list | union | restriction)", 
		    attrValue, NULL, NULL, NULL);
	    }
	}
    }   
    type->targetNamespace = schema->targetNamespace;
    /* TODO: Check id. */    
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    /*
    * And now for the children...
    */
    oldCtxtType = ctxt->ctxtType;
    oldParentItem = ctxt->parentItem;
    ctxt->ctxtType = type;
    ctxt->parentItem = type;
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;         
    if (IS_SCHEMA(child, "restriction")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseRestriction(ctxt, schema, child);
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
    if ((child != NULL) || (subtype == NULL)) {
	xmlSchemaPContentErr(ctxt, XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED, 
	    &des, type, node, child, NULL, 
	    "(annotation?, (restriction | list | union))");
    }
    ctxt->parentItem = oldParentItem;
    ctxt->ctxtType = oldCtxtType;
    FREE_AND_NULL(des)

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
    const xmlChar *name, *ns = NULL;
    const xmlChar *ref = NULL, *refNs = NULL;
    char buf[50];
    int minOccurs, maxOccurs;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);
    /*
    * TODO: Validate the element even if no item is created 
    * (i.e. min/maxOccurs == 0).
    */
    minOccurs = xmlGetMinOccurs(ctxt, node, 0, -1, 1, "nonNegativeInteger");
    maxOccurs = xmlGetMaxOccurs(ctxt, node, 0, UNBOUNDED, 1, "(nonNegativeInteger | unbounded)");
    if ((minOccurs == 0) && (maxOccurs == 0)) {
	return (NULL);
    }
    if (topLevel)
	ns = schema->targetNamespace;
    name = xmlSchemaGetProp(ctxt, node, "name");
    if (name == NULL) {
        ref = xmlGetQNameProp(ctxt, node, "ref", &refNs);
        if (ref == NULL) {
            xmlSchemaPErr2(ctxt, node, child,
		XML_SCHEMAP_GROUP_NONAME_NOREF,
		"Group definition or particle: One of the attributes \"name\" "
		"or \"ref\" must be present.\n", NULL, NULL);
            return (NULL);
        }
	if (refNs == NULL)
	    refNs = schema->targetNamespace;
        snprintf(buf, 49, "#GrRef %d", ctxt->counter++ + 1);
        name = (const xmlChar *) buf;
    }
    type = xmlSchemaAddGroup(ctxt, schema, name, ns, node);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_GROUP;
    if (topLevel)
        type->flags |= XML_SCHEMAS_TYPE_GLOBAL;    
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->ref = ref;
    type->refNs = refNs;
    type->minOccurs = minOccurs;
    type->maxOccurs = maxOccurs;
    xmlSchemaPCheckParticleCorrect_2(ctxt, type,
	node, type->minOccurs, type->maxOccurs);    

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
                       "Group definition \"%s\" has unexpected content.\n", type->name,
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
    const xmlChar *oldcontainer;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    snprintf((char *) name, 30, "all%d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_ALL;
    type->id = xmlSchemaGetProp(ctxt, node, "id");

    type->minOccurs = xmlGetMinOccurs(ctxt, node, 0, 1, 1, "(0 | 1)");
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node, 1, 1, 1, "1");    
    
    oldcontainer = ctxt->container;
    ctxt->container = (const xmlChar *) name;
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
	             "invalid value for minOccurs (must be 0 or 1).\n",
		     NULL, NULL);
	    if (subtype->maxOccurs > 1)
	        xmlSchemaPErr(ctxt, child, XML_SCHEMAP_INVALID_MAXOCCURS,
	             "invalid value for maxOccurs (must be 0 or 1).\n",
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
                       "<all> has unexpected content.\n", type->name,
                       NULL);
    }
    ctxt->container = oldcontainer;
    return (type);
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
#if 0
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
        xmlSchemaPErr(ctxt, NULL, XML_SCHEMAP_INTERNAL,
	              "Failed to import schema from location \"%s\".\n",
		      schemaLocation, NULL);

	xmlSchemaFreeParserCtxt(newctxt);
	/* The schemaLocation is held by the dictionary.
	if (import->schemaLocation != NULL)
	    xmlFree((xmlChar *)import->schemaLocation);
	*/
	xmlFree(import);
	return NULL;
    }

    xmlSchemaFreeParserCtxt(newctxt);
    return import;
}
#endif

static void
xmlSchemaClearSchemaDefaults(xmlSchemaPtr schema)
{
    if (schema->flags & XML_SCHEMAS_QUALIF_ELEM)
	schema->flags ^= XML_SCHEMAS_QUALIF_ELEM;

    if (schema->flags & XML_SCHEMAS_QUALIF_ATTR)
	schema->flags ^= XML_SCHEMAS_QUALIF_ATTR;

    if (schema->flags & XML_SCHEMAS_FINAL_DEFAULT_EXTENSION)
	schema->flags ^= XML_SCHEMAS_FINAL_DEFAULT_EXTENSION;
    if (schema->flags & XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION)
	schema->flags ^= XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION;
    if (schema->flags & XML_SCHEMAS_FINAL_DEFAULT_LIST)
	schema->flags ^= XML_SCHEMAS_FINAL_DEFAULT_LIST;
    if (schema->flags & XML_SCHEMAS_FINAL_DEFAULT_UNION)
	schema->flags ^= XML_SCHEMAS_FINAL_DEFAULT_UNION;

    if (schema->flags & XML_SCHEMAS_BLOCK_DEFAULT_EXTENSION)
	schema->flags ^= XML_SCHEMAS_BLOCK_DEFAULT_EXTENSION;
    if (schema->flags & XML_SCHEMAS_BLOCK_DEFAULT_RESTRICTION)
	schema->flags ^= XML_SCHEMAS_BLOCK_DEFAULT_RESTRICTION;
    if (schema->flags & XML_SCHEMAS_BLOCK_DEFAULT_SUBSTITUTION)
	schema->flags ^= XML_SCHEMAS_BLOCK_DEFAULT_SUBSTITUTION;
}

static void
xmlSchemaParseSchemaDefaults(xmlSchemaParserCtxtPtr ctxt, 
			     xmlSchemaPtr schema,
			     xmlNodePtr node)
{
    xmlAttrPtr attr;
    const xmlChar *val;

    attr = xmlSchemaGetPropNode(node, "elementFormDefault");     
    if (attr != NULL) {
	val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
	if (xmlSchemaPValAttrFormDefault(val, &schema->flags, 
	    XML_SCHEMAS_QUALIF_ELEM) != 0) {
	    xmlSchemaPSimpleTypeErr(ctxt, 
		XML_SCHEMAP_ELEMFORMDEFAULT_VALUE,
		NULL, NULL, (xmlNodePtr) attr, NULL, 
		"(qualified | unqualified)", val, NULL, NULL, NULL);
	}
    }
    
    attr = xmlSchemaGetPropNode(node, "attributeFormDefault");     
    if (attr != NULL) {
	val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
	if (xmlSchemaPValAttrFormDefault(val, &schema->flags, 
	    XML_SCHEMAS_QUALIF_ATTR) != 0) {
	    xmlSchemaPSimpleTypeErr(ctxt, 
		XML_SCHEMAP_ATTRFORMDEFAULT_VALUE,
		NULL, NULL, (xmlNodePtr) attr, NULL, 
		"(qualified | unqualified)", val, NULL, NULL, NULL);
	}
    }
    
    attr = xmlSchemaGetPropNode(node, "finalDefault");    
    if (attr != NULL) {
	val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
	if (xmlSchemaPValAttrBlockFinal(val, &(schema->flags), -1,
	    XML_SCHEMAS_FINAL_DEFAULT_EXTENSION,
	    XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION,
	    -1,
	    XML_SCHEMAS_FINAL_DEFAULT_LIST,
	    XML_SCHEMAS_FINAL_DEFAULT_UNION) != 0) {
	    xmlSchemaPSimpleTypeErr(ctxt,
		XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
		NULL, NULL, (xmlNodePtr) attr, NULL,
		"(#all | List of (extension | restriction | list | union))",
		val, NULL, NULL, NULL);
	}	    
    }
    
    attr = xmlSchemaGetPropNode(node, "blockDefault");     
    if (attr != NULL) {
	val = xmlSchemaGetNodeContent(ctxt, (xmlNodePtr) attr);
	if (xmlSchemaPValAttrBlockFinal(val, &(schema->flags), -1,
	    XML_SCHEMAS_BLOCK_DEFAULT_EXTENSION,
	    XML_SCHEMAS_BLOCK_DEFAULT_RESTRICTION,
	    XML_SCHEMAS_BLOCK_DEFAULT_SUBSTITUTION, -1, -1) != 0) {
	     xmlSchemaPSimpleTypeErr(ctxt,
		XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
		NULL, NULL, (xmlNodePtr) attr, NULL,
		"(#all | List of (extension | restriction | substitution))",
		val, NULL, NULL, NULL);
	}	    
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
			   "Unexpected element \"%s\" as child of <schema>.\n",
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
    ctxt->parentItem = NULL;
    ctxt->ctxtType = NULL;
}

static xmlSchemaImportPtr
xmlSchemaAddImport(xmlSchemaParserCtxtPtr ctxt, 
		   xmlHashTablePtr *imports,
		   const xmlChar *nsName)
{
    xmlSchemaImportPtr ret;

    if (*imports == NULL) {
	*imports = xmlHashCreate(10);
	if (*imports == NULL) {
	    xmlSchemaPCustomErr(ctxt, 
		XML_SCHEMAP_FAILED_BUILD_IMPORT,
		NULL, NULL, (xmlNodePtr) ctxt->doc,
		"Internal error: failed to build the import table",
		NULL);
	    return (NULL);
	}
    }
    ret = (xmlSchemaImport*) xmlMalloc(sizeof(xmlSchemaImport));
    if (ret == NULL) {
	xmlSchemaPErrMemory(NULL, "allocating import struct", NULL);
	return (NULL);
    }   
    memset(ret, 0, sizeof(xmlSchemaImport));
    if (nsName == NULL)
	nsName = XML_SCHEMAS_NO_NAMESPACE;
    xmlHashAddEntry(*imports, nsName, ret);  

    return (ret);
}

static int
xmlSchemaAcquireSchemaDoc(xmlSchemaParserCtxtPtr ctxt,
			  xmlSchemaPtr schema,
			  xmlNodePtr node,
			  const xmlChar *nsName,
			  const xmlChar *location,
			  xmlDocPtr *doc,
			  const xmlChar **targetNamespace,
			  int absolute)
{
    xmlParserCtxtPtr parserCtxt;
    xmlSchemaImportPtr import;
    const xmlChar *ns;
    xmlNodePtr root;

    /*
    * NOTE: This will be used for <import>, <xsi:schemaLocation> and
    * <xsi:noNamespaceSchemaLocation>.
    */
    *doc = NULL;
    /*
    * Given that the schemaLocation [attribute] is only a hint, it is open 
    * to applications to ignore all but the first <import> for a given 
    * namespace, regardless of the ·actual value· of schemaLocation, but
    * such a strategy risks missing useful information when new
    * schemaLocations are offered.
    *
    * XSV (ver 2.5-2) does use the first <import> which resolves to a valid schema.
    * Xerces-J (ver 2.5.1) ignores all but the first given <import> - regardless if
    * valid or not.
    * We will follow XSV here. 
    */
    if (location == NULL) {
	/*
	* Schema Document Location Strategy:
	*
	* 3 Based on the namespace name, identify an existing schema document,
	* either as a resource which is an XML document or a <schema> element 
	* information item, in some local schema repository; 
	*
	* 5 Attempt to resolve the namespace name to locate such a resource. 
	*
	* NOTE: Those stategies are not supported, so we will skip.
	*/
	return (0);
    }
    if (nsName == NULL) 
	ns = XML_SCHEMAS_NO_NAMESPACE;
    else
	ns = nsName;
    
    import = xmlHashLookup(schema->schemasImports, ns);
    if (import != NULL) {	
	/*
	* There was a valid resource for the specified namespace already
	* defined, so skip.
	* TODO: This might be changed someday to allow import of
	* components from multiple documents for a single target namespace.
	*/
	return (0);
    } 
   
    /*
    * Schema Document Location Strategy: 
    *
    * 2 Based on the location URI, identify an existing schema document, 
    * either as a resource which is an XML document or a <schema> element 
    * information item, in some local schema repository;   
    *
    * 4 Attempt to resolve the location URI, to locate a resource on the 
    * web which is or contains or references a <schema> element;
    * TODO: Hmm, I don't know if the reference stuff in 4. will work.
    *
    */
    if ((absolute == 0) && (node != NULL)) {
	xmlChar *base, *URI;

	base = xmlNodeGetBase(node->doc, node);
	if (base == NULL) {
	    URI = xmlBuildURI(location, node->doc->URL);
	} else {
	    URI = xmlBuildURI(location, base);
	    xmlFree(base);
	}
	if (URI != NULL) {
	    location = xmlDictLookup(ctxt->dict, URI, -1);
	    xmlFree(URI);
	}
    }
    parserCtxt = xmlNewParserCtxt();
    if (parserCtxt == NULL) {
	xmlSchemaPErrMemory(NULL, "xmlSchemaParseImport: "
	    "allocating a parser context", NULL);
	return(-1);
    }	   
    
    if ((ctxt->dict != NULL) && (parserCtxt->dict != NULL)) {
	xmlDictFree(parserCtxt->dict);
	parserCtxt->dict = ctxt->dict;
	xmlDictReference(parserCtxt->dict);
    }
    
    *doc = xmlCtxtReadFile(parserCtxt, (const char *) location, 
	    NULL, SCHEMAS_PARSE_OPTIONS);

    /*
    * 2.1 The referent is (a fragment of) a resource which is an 
    * XML document (see clause 1.1), which in turn corresponds to 
    * a <schema> element information item in a well-formed information 
    * set, which in turn corresponds to a valid schema.
    * TODO: What to do with the "fragment" stuff?
    *
    * 2.2 The referent is a <schema> element information item in 
    * a well-formed information set, which in turn corresponds 
    * to a valid schema.
    * NOTE: 2.2 won't apply, since only XML documents will be processed 
    * here.
    */       
    if (*doc == NULL) {	
	xmlErrorPtr lerr;
	/*
	* It is *not* an error for the application schema reference 
	* strategy to fail.
	* 
	* If the doc is NULL and the parser error is an IO error we
	* will assume that the resource could not be located or accessed.
	*
	* TODO: Try to find specific error codes to react only on
	* localisation failures.
	*
	* TODO, FIXME: Check the spec: is a namespace added to the imported
	* namespaces, even if the schemaLocation did not provide
	* a resource? I guess so, since omitting the "schemaLocation"
	* attribute, imports a namespace as well.
	*/
	lerr = xmlGetLastError();
	if ((lerr != NULL) && (lerr->domain == XML_FROM_IO)) {	
	    xmlFreeParserCtxt(parserCtxt);
	    return(0);
	}

	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_SRC_IMPORT_2_1,
	    NULL, NULL, node,
	    "Failed to parse the resource '%s' for import",
	    location);
	xmlFreeParserCtxt(parserCtxt);
	return(XML_SCHEMAP_SRC_IMPORT_2_1);
    }
    xmlFreeParserCtxt(parserCtxt);
    
    root = xmlDocGetRootElement(*doc);
    if (root == NULL) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_SRC_IMPORT_2_1,
	    NULL, NULL, node,
	    "The XML document '%s' to be imported has no document "
	    "element", location);	
	xmlFreeDoc(*doc);
	*doc = NULL;
	return (XML_SCHEMAP_SRC_IMPORT_2_1);
    }	
    
    xmlSchemaCleanupDoc(ctxt, root);	
    
    if (!IS_SCHEMA(root, "schema")) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_SRC_IMPORT_2_1,
	    NULL, NULL, node,
	    "The XML document '%s' to be imported is not a XML schema document",
	    location);	
	xmlFreeDoc(*doc);
	*doc = NULL;
	return (XML_SCHEMAP_SRC_IMPORT_2_1);
    }	
    *targetNamespace = xmlSchemaGetProp(ctxt, root, "targetNamespace");
    /*
    * Schema Representation Constraint: Import Constraints and Semantics
    */    
    if (nsName == NULL) {
	if (*targetNamespace != NULL) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_SRC_IMPORT_3_2,
		NULL, NULL, node,
		"The XML schema to be imported is not expected "
		"to have a target namespace; this differs from "
		"its target namespace of '%s'", *targetNamespace);
	    xmlFreeDoc(*doc);
	    *doc = NULL;
	    return (XML_SCHEMAP_SRC_IMPORT_3_2);
	}
    } else {
	if (*targetNamespace == NULL) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_SRC_IMPORT_3_1,
		NULL, NULL, node,
		"The XML schema to be imported is expected to have a target "
		"namespace of '%s'", nsName);
	    xmlFreeDoc(*doc);
	    *doc = NULL;
	    return (XML_SCHEMAP_SRC_IMPORT_3_1);
	} else if (!xmlStrEqual(*targetNamespace, nsName)) {
	    xmlSchemaPCustomErrExt(ctxt,
		XML_SCHEMAP_SRC_IMPORT_3_1,
		NULL, NULL, node,
		"The XML schema to be imported is expected to have a "
		"target namespace of '%s'; this differs from "
		"its target namespace of '%s'", 
		nsName, *targetNamespace, NULL);
	    xmlFreeDoc(*doc);
	    *doc = NULL;
	    return (XML_SCHEMAP_SRC_IMPORT_3_1);
	}
    }

    import = xmlSchemaAddImport(ctxt, &(schema->schemasImports), nsName);
    if (import == NULL) {
	xmlSchemaPCustomErr(ctxt, XML_SCHEMAP_FAILED_BUILD_IMPORT,
	    NULL, NULL, NULL,	    
	    "Internal error: xmlSchemaAcquireSchemaDoc, "
	    "failed to build import table", NULL);
	xmlFreeDoc(*doc);
	*doc = NULL;
	return (-1);
    }
    import->schemaLocation = location;
    import->doc = *doc;
    return (0);
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
 * Returns 0 in case of success, a positive error code if 
 * not valid and -1 in case of an internal error. 
 */
static int
xmlSchemaParseImport(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                     xmlNodePtr node)
{    
    xmlNodePtr child;
    const xmlChar *namespace = NULL;
    const xmlChar *schemaLocation = NULL;
    const xmlChar *targetNamespace, *oldTNS, *url;
    xmlAttrPtr attr;
    xmlDocPtr doc;
    xmlNodePtr root;
    int flags, ret = 0;


    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (-1);

    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "namespace")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "schemaLocation"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, NULL, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, NULL, attr);		
	}
	attr = attr->next;
    }	
    /*
    * Extract and validate attributes.
    */
    if (xmlSchemaPValAttr(ctxt, NULL, NULL, node, 
	"namespace", xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI), 
	&namespace) != 0) {
	xmlSchemaPSimpleTypeErr(ctxt,	    
	    XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI, 
	    NULL, NULL, node, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI), 
	    NULL, namespace, NULL, NULL, NULL);
	return (XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI);
    }

    if (xmlSchemaPValAttr(ctxt, NULL, NULL, node, 
	"schemaLocation", xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI), 
	&schemaLocation) != 0) {
	xmlSchemaPSimpleTypeErr(ctxt,	    
	    XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI, 
	    NULL, NULL, node, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI), 
	    NULL, namespace, NULL, NULL, NULL);
	return (XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI);
    }    
    /*
    * And now for the children...
    */
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        /*
         * the annotation here is simply discarded ...
         */
        child = child->next;
    }
    if (child != NULL) {
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_UNKNOWN_IMPORT_CHILD,
	    NULL, NULL, node, child, NULL,
	    "(annotation?)");
    }
    /*
    * Apply additional constraints.
    */
    if (namespace != NULL) {
	/*
	* 1.1 If the namespace [attribute] is present, then its ·actual value· 
	* must not match the ·actual value· of the enclosing <schema>'s 
	* targetNamespace [attribute].
	*/
	if (xmlStrEqual(schema->targetNamespace, namespace)) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_SRC_IMPORT_1_1,
		NULL, NULL, node,
		"The value of the attribute 'namespace' must not match "
		"the target namespace '%s' of the importing schema",
		schema->targetNamespace);
	    return (XML_SCHEMAP_SRC_IMPORT_1_1);
	}
    } else {
	/*
	* 1.2 If the namespace [attribute] is not present, then the enclosing 
	* <schema> must have a targetNamespace [attribute].
	*/
	if (schema->targetNamespace == NULL) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_SRC_IMPORT_1_2,
		NULL, NULL, node,
		"The attribute 'namespace' must be existent if "
		"the importing schema has no target namespace",
		NULL);
	    return (XML_SCHEMAP_SRC_IMPORT_1_2);
	}
    }
    /*
    * Locate and aquire the schema document.
    */
    ret = xmlSchemaAcquireSchemaDoc(ctxt, schema, node, namespace, 
	schemaLocation, &doc, &targetNamespace, 0);
    if (ret != 0) {
	if (doc != NULL)
	    xmlFreeDoc(doc);
	return (ret);
    } else if (doc != NULL) {       
	/*
	* Save and reset the context & schema.
	*/
	url = ctxt->URL;  
	/* TODO: Is using the doc->URL here correct? */
	ctxt->URL = doc->URL;
	flags = schema->flags;
	oldTNS = schema->targetNamespace;
	/*
	* Parse the schema.
	*/
	root = xmlDocGetRootElement(doc);
	xmlSchemaClearSchemaDefaults(schema);
	xmlSchemaParseSchemaDefaults(ctxt, schema, root);
	schema->targetNamespace = targetNamespace;
	xmlSchemaParseSchemaTopLevel(ctxt, schema, root->children);
	/*
	* Restore the context & schema.
	*/
	schema->flags = flags;
	schema->targetNamespace = oldTNS;
	ctxt->URL = url;
    }
    
    return (0);
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
    const xmlChar *schemaLocation, *targetNamespace;
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlSchemaIncludePtr include;
    int wasConvertingNs = 0;
    xmlAttrPtr attr;
    int saveFlags;
    xmlParserCtxtPtr parserCtxt;


    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (-1);

    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "schemaLocation"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, NULL, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, NULL, attr);		
	}
	attr = attr->next;
    }
    /*
    * Extract and validate attributes.
    */
    /*
     * Preliminary step, extract the URI-Reference for the include and
     * make an URI from the base.
     */
    attr = xmlSchemaGetPropNode(node, "schemaLocation");
    if (attr != NULL) {
        xmlChar *base = NULL;
        xmlChar *uri = NULL;

	if (xmlSchemaPValAttrNode(ctxt, NULL, NULL, attr,
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI), &schemaLocation) != 0)
	    return (-1);
	base = xmlNodeGetBase(node->doc, node);
	if (base == NULL) {
	    uri = xmlBuildURI(schemaLocation, node->doc->URL);
	} else {
	    uri = xmlBuildURI(schemaLocation, base);
	    xmlFree(base);
	}
	if (uri != NULL) {
	    schemaLocation = xmlDictLookup(ctxt->dict, uri, -1);
	    xmlFree(uri);
	}
    } else {
	xmlSchemaPMissingAttrErr(ctxt, 
	    XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI, 
	    NULL, NULL, node, "schemaLocation", NULL);
	return (-1);
    }
    /*
    * And now for the children...
    */
    child = node->children;
    while (IS_SCHEMA(child, "annotation")) {
        /*
         * the annotations here are simply discarded ...
         */
        child = child->next;
    }
    if (child != NULL) {
	xmlSchemaPContentErr(ctxt, 
	    XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD,
	    NULL, NULL, node, child, NULL,
	    "(annotation?)");
    }

    /*
     * First step is to parse the input document into an DOM/Infoset
     */
    /* 
    * TODO: Use xmlCtxtReadFile to share the dictionary.
    */
    parserCtxt = xmlNewParserCtxt();
    if (parserCtxt == NULL) {
	xmlSchemaPErrMemory(NULL, "xmlSchemaParseInclude: "
	    "allocating a parser context", NULL);
	return(-1);
    }	   
    
    if ((ctxt->dict != NULL) && (parserCtxt->dict != NULL)) {
	xmlDictFree(parserCtxt->dict);
	parserCtxt->dict = ctxt->dict;
	xmlDictReference(parserCtxt->dict);
    }
    
    doc = xmlCtxtReadFile(parserCtxt, (const char *) schemaLocation, 
	    NULL, SCHEMAS_PARSE_OPTIONS);
    xmlFreeParserCtxt(parserCtxt);
    if (doc == NULL) {
	/*
	* TODO: It is not an error for the ·actual value· of the 
	* schemaLocation [attribute] to fail to resolve it all, in which 
	* case no corresponding inclusion is performed. 
	* So do we need a warning report here?
	*/
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_FAILED_LOAD,
	    NULL, NULL, node, 
	    "Failed to load the document '%s' for inclusion", schemaLocation);
	return(-1);
    }

    /*
     * Then extract the root of the schema
     */
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_NOROOT,
	    NULL, NULL, node,
	    "The included document '%s' has no document "
	    "element", schemaLocation);		
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
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_NOT_SCHEMA,
	    NULL, NULL, node,
	    "The document '%s' to be included is not a schema document", 
	    schemaLocation);
	xmlFreeDoc(doc);
        return (-1);
    }
    
    targetNamespace = xmlSchemaGetProp(ctxt, root, "targetNamespace");
    /*
    * 2.1 SII has a targetNamespace [attribute], and its ·actual 
    * value· is identical to the ·actual value· of the targetNamespace 
    * [attribute] of SII’ (which must have such an [attribute]).
    */
    if (targetNamespace != NULL) {
	if (schema->targetNamespace == NULL) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_SRC_INCLUDE,
		NULL, NULL, node,
		"The target namespace of the included schema "
		"'%s' has to be absent, since the including schema "
		"has no target namespace", 
		schemaLocation);
	    xmlFreeDoc(doc);
	    return (-1);
	} else if (!xmlStrEqual(targetNamespace, schema->targetNamespace)) {
	    xmlSchemaPCustomErrExt(ctxt,
		XML_SCHEMAP_SRC_INCLUDE,
		NULL, NULL, node,
		"The target namespace '%s' of the included schema '%s' "
		"differs from '%s' of the including schema", 
		targetNamespace, schemaLocation, schema->targetNamespace);
	    xmlFreeDoc(doc);
	    return (-1);
	}
    } else if (schema->targetNamespace != NULL) {     	
	if ((schema->flags & XML_SCHEMAS_INCLUDING_CONVERT_NS) == 0) {
	    schema->flags |= XML_SCHEMAS_INCLUDING_CONVERT_NS;	    
	} else
	    wasConvertingNs = 1;
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
    /*
    * TODO: The complete validation of the <schema> element is not done.
    */
    /*    
    * The default values ("blockDefault", "elementFormDefault", etc.)
    * are set to the values of the included schema and restored afterwards.
    */    
    saveFlags = schema->flags;
    xmlSchemaClearSchemaDefaults(schema);
    xmlSchemaParseSchemaDefaults(ctxt, schema, root);
    xmlSchemaParseSchemaTopLevel(ctxt, schema, root->children);
    schema->flags = saveFlags;
    /*
    * Remove the converting flag.
    */
    if ((wasConvertingNs == 0) && 
	(schema->flags & XML_SCHEMAS_INCLUDING_CONVERT_NS))
	schema->flags ^= XML_SCHEMAS_INCLUDING_CONVERT_NS;
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
    xmlAttrPtr attr;
    const xmlChar *oldcontainer;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);


    snprintf((char *) name, 30, "choice %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_CHOICE;
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "maxOccurs")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "minOccurs"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, type, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, type, attr);		
	}
	attr = attr->next;
    }
    /*
    * Extract and validate attributes.
    */
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->minOccurs = xmlGetMinOccurs(ctxt, node, 0, -1, 1, "nonNegativeInteger");
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node, 0, UNBOUNDED, 1, 
	"(nonNegativeInteger | unbounded)");
    /*
    * And now for the children...
    */
    oldcontainer = ctxt->container;
    ctxt->container = (const xmlChar *) name;
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
	/* TODO: error code. */
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_UNKNOWN_CHOICE_CHILD,
	    NULL, type, node, child, NULL,
	    "(annotation?, (element | group | choice | sequence | any)*)");
    }
    ctxt->container = oldcontainer;
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
    xmlAttrPtr attr;
    const xmlChar *oldcontainer;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    oldcontainer = ctxt->container;
    snprintf((char *) name, 30, "#seq %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->node = node;
    type->type = XML_SCHEMA_TYPE_SEQUENCE;
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "maxOccurs")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "minOccurs"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, type, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, type, attr);		
	}
	attr = attr->next;
    }
    /*
    * Extract and validate attributes.
    */
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    type->minOccurs = xmlGetMinOccurs(ctxt, node, 0, -1, 1, "nonNegativeInteger");
    type->maxOccurs = xmlGetMaxOccurs(ctxt, node, 0, UNBOUNDED, 1, 
	"(nonNegativeInteger | unbounded)");
    /*
    * And now for the children...
    */
    ctxt->container = (const xmlChar *) name;
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
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD,
	    NULL, type, node, child, NULL,
	    "(annotation?, (element | group | choice | sequence | any)*)");
    }
    ctxt->container = oldcontainer;

    return (type);
}

/**
 * xmlSchemaParseRestriction:
 * @ctxt:  a schema validation context
 * @schema:  the schema being built
 * @node:  a subtree containing XML Schema informations
 *
 * parse a XML schema Restriction definition
 * *WARNING* this interface is highly subject to change
 *
 * Returns the type definition or NULL in case of error
 */
static xmlSchemaTypePtr
xmlSchemaParseRestriction(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
                          xmlNodePtr node)
{
    xmlSchemaTypePtr type, subtype;    
    xmlNodePtr child = NULL;
    xmlChar name[30];
    const xmlChar *oldcontainer;
    xmlAttrPtr attr;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    oldcontainer = ctxt->container;

    snprintf((char *) name, 30, "#restr %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->type = XML_SCHEMA_TYPE_RESTRICTION;
    type->node = node;
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "base"))) {
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    NULL, type, attr);		    
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		NULL, type, attr);		
	}
	attr = attr->next;
    }	
    /*
    * Extract and validate attributes.
    */
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    /*
    * Attribute "base".
    */
    type->base = xmlGetQNameProp(ctxt, node, "base", &(type->baseNs));
    if ((type->base == NULL) && 
	(ctxt->ctxtType->type == XML_SCHEMA_TYPE_COMPLEX)) {
	/* TODO: Think about the error code. */
	xmlSchemaPMissingAttrErr(ctxt,
	    XML_SCHEMAP_RESTRICTION_NONAME_NOREF, 
	    NULL, type, node, "base", NULL);
    }
    /*
    * And now for the children...
    */
    ctxt->container = name;
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    subtype = NULL;
    if (ctxt->parentItem->type == XML_SCHEMA_TYPE_COMPLEX_CONTENT) {
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
	}
    } else if (ctxt->ctxtType->type == XML_SCHEMA_TYPE_SIMPLE) {
	if (IS_SCHEMA(child, "simpleType")) {
	    if (type->base != NULL) {
		/* 
		* src-restriction-base-or-simpleType
		* Either the base [attribute] or the simpleType [child] of the 
		* <restriction> element must be present, but not both. 
		*/
		xmlSchemaPContentErr(ctxt, 
		    XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE,
		    NULL, NULL, type->node, child,
		    "The attribute 'base' and the <simpleType> child are "
		    "mutually exclusive", NULL);
	    } else {
		subtype = (xmlSchemaTypePtr)
		    xmlSchemaParseSimpleType(ctxt, schema, child, 0);
		type->baseType = subtype;
	    }	        
	    child = child->next;
	}
    } else if (ctxt->parentItem->type == XML_SCHEMA_TYPE_SIMPLE_CONTENT) {
	if (IS_SCHEMA(child, "simpleType")) {
	    subtype = (xmlSchemaTypePtr)
		xmlSchemaParseSimpleType(ctxt, schema, child, 0);
	    type->subtypes = subtype;
	    child = child->next;
	}	        	
    }
    if ((ctxt->ctxtType->type == XML_SCHEMA_TYPE_SIMPLE) ||
	(ctxt->parentItem->type == XML_SCHEMA_TYPE_SIMPLE_CONTENT)) {
	xmlSchemaFacetPtr facet, lastfacet = NULL;	
		
	/*
	* Add the facets to the parent simpleType/complexType.
	*/
	/*
	* TODO: Datatypes: 4.1.3 Constraints on XML Representation of 
	* Simple Type Definition Schema Representation Constraint: 
	* *Single Facet Value*
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
		if (lastfacet == NULL)
		    ctxt->ctxtType->facets = facet;			
		else
		    lastfacet->next = facet;
		lastfacet = facet;
		lastfacet->next = NULL;
	    }
	    child = child->next;
	}
	/*
	* Create links for derivation and validation.
	*/	    
	if (lastfacet != NULL) {
	    xmlSchemaFacetLinkPtr facetLink, lastFacetLink = NULL;

	    facet = ctxt->ctxtType->facets;
	    do {		    
		facetLink = (xmlSchemaFacetLinkPtr) xmlMalloc(sizeof(xmlSchemaFacetLink));
		if (facetLink == NULL) {
		    xmlSchemaPErrMemory(ctxt, "allocating a facet link", NULL);
		    xmlFree(facetLink);
		    return (NULL);
		}	
		facetLink->facet = facet;
		facetLink->next = NULL;
		if (lastFacetLink == NULL) 
		    ctxt->ctxtType->facetSet = facetLink;			                                         
		else
		    lastFacetLink->next = facetLink;
		lastFacetLink = facetLink;
		facet = facet->next;
	    } while (facet != NULL);
	}
    }    
    if (ctxt->ctxtType->type == XML_SCHEMA_TYPE_COMPLEX) {
	child = xmlSchemaParseAttrDecls(ctxt, schema, child, type);
	if (IS_SCHEMA(child, "anyAttribute")) {
	    ctxt->ctxtType->attributeWildcard = xmlSchemaParseAnyAttribute(ctxt, schema, child);
	    child = child->next;
	}
    }
    if (child != NULL) {
	/* TODO: Think about the error code. */
	if (ctxt->parentItem->type == XML_SCHEMA_TYPE_COMPLEX_CONTENT) {	    
	    xmlSchemaPContentErr(ctxt, 
		XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD, 
		NULL, type, node, child, NULL,
		"annotation?, (group | all | choice | sequence)?, "
		"((attribute | attributeGroup)*, anyAttribute?))");
	} else if (ctxt->parentItem->type == XML_SCHEMA_TYPE_SIMPLE_CONTENT) {
	     xmlSchemaPContentErr(ctxt, 
		XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD, 
		NULL, type, node, child, NULL,
		"(annotation?, (simpleType?, (minExclusive | minInclusive | "
		"maxExclusive | maxInclusive | totalDigits | fractionDigits | "
		"length | minLength | maxLength | enumeration | whiteSpace | "
		"pattern)*)?, ((attribute | attributeGroup)*, anyAttribute?))");
	} else {
	    /* Simple type */
	    xmlSchemaPContentErr(ctxt, 
		XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD, 
		NULL, type, node, child, NULL,
		"(annotation?, (simpleType?, (minExclusive | minInclusive | "
		"maxExclusive | maxInclusive | totalDigits | fractionDigits | "
		"length | minLength | maxLength | enumeration | whiteSpace | "
		"pattern)*))");
	}
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
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);    
    if (type == NULL)
        return (NULL);
    type->type = XML_SCHEMA_TYPE_EXTENSION;
    type->node = node;
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    ctxt->container = name;

    type->base = xmlGetQNameProp(ctxt, node, "base", &(type->baseNs));
    if (type->base == NULL) {
        xmlSchemaPErr2(ctxt, node, child, XML_SCHEMAP_EXTENSION_NO_BASE,
	    "<extension>: The attribute \"base\" is missing.\n", 
	    type->name, NULL);
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
    if ((ctxt->ctxtType != NULL) &&
	(ctxt->ctxtType->type == XML_SCHEMA_TYPE_COMPLEX)) {
	child = xmlSchemaParseAttrDecls(ctxt, schema, child, type);
	if (IS_SCHEMA(child, "anyAttribute")) {	    
	    ctxt->ctxtType->attributeWildcard = 
		xmlSchemaParseAnyAttribute(ctxt, schema, child);
	    child = child->next;
	}
    }
    if (child != NULL) {
        xmlSchemaPErr2(ctxt, node, child,
	    XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD,
	    "<extension> has unexpected content.\n", type->name,
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
    xmlSchemaTypePtr type, subtype, oldParentItem;
    xmlNodePtr child = NULL;
    xmlChar name[30];

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    snprintf((char *) name, 30, "simpleContent %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);    
    if (type == NULL)
        return (NULL);
    type->type = XML_SCHEMA_TYPE_SIMPLE_CONTENT;
    type->node = node;
    type->id = xmlSchemaGetProp(ctxt, node, "id");

    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    oldParentItem = ctxt->parentItem;
    ctxt->parentItem = type;
    subtype = NULL;    
    if (IS_SCHEMA(child, "restriction")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseRestriction(ctxt, schema, child);
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
	    "<simpleContent> has unexpected content.\n",
	    NULL, NULL);
    }
    ctxt->parentItem = oldParentItem;
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
    xmlSchemaTypePtr type, subtype, oldParentItem;
    xmlNodePtr child = NULL;
    xmlChar name[30];
    xmlAttrPtr attr;

    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    snprintf((char *) name, 30, "#CC %d", ctxt->counter++ + 1);
    type = xmlSchemaAddType(ctxt, schema, name, NULL, node);
    if (type == NULL)
        return (NULL);
    type->type = XML_SCHEMA_TYPE_COMPLEX_CONTENT;
    type->node = node;    
    /*
    * Check for illegal attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if ((!xmlStrEqual(attr->name, BAD_CAST "id")) &&
		(!xmlStrEqual(attr->name, BAD_CAST "mixed"))) 
	    {
		xmlSchemaPIllegalAttrErr(ctxt,
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
		    NULL, NULL, attr);
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt,
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED,
		NULL, NULL, attr);
	}
	attr = attr->next;
    }	
    type->id = xmlSchemaGetProp(ctxt, node, "id");
    /*
    * Handle attribute 'mixed'.
    */
    if (xmlGetBooleanProp(ctxt, NULL, type, node, "mixed", 0))  {
	if ((ctxt->ctxtType->flags & XML_SCHEMAS_TYPE_MIXED) == 0)
	    ctxt->ctxtType->flags |= XML_SCHEMAS_TYPE_MIXED;
    }
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    oldParentItem = ctxt->parentItem;
    ctxt->parentItem = type;
    subtype = NULL;
    if (IS_SCHEMA(child, "restriction")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseRestriction(ctxt, schema, child);
        child = child->next;
    } else if (IS_SCHEMA(child, "extension")) {
        subtype = (xmlSchemaTypePtr)
            xmlSchemaParseExtension(ctxt, schema, child);
        child = child->next;
    }
    type->subtypes = subtype;
    if (child != NULL) {
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED,
	    NULL, NULL, node, child,
	    NULL, "(annotation?, (restriction | extension))");
    }
    ctxt->parentItem = oldParentItem;
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
    xmlSchemaTypePtr type, subtype, ctxtType;
    xmlNodePtr child = NULL;
    const xmlChar *name = NULL;
    const xmlChar *oldcontainer;    
    xmlAttrPtr attr;
    const xmlChar *attrValue;
    xmlChar *des = NULL; /* The reported designation. */
    char buf[40];


    if ((ctxt == NULL) || (schema == NULL) || (node == NULL))
        return (NULL);

    ctxtType = ctxt->ctxtType;

    if (topLevel) {
	attr = xmlSchemaGetPropNode(node, "name");
	if (attr == NULL) {
	    xmlSchemaPMissingAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_MISSING, 
		(xmlChar **) &xmlSchemaElemDesCT, NULL, node,
		"name", NULL);
	    return (NULL);
	} else if (xmlSchemaPValAttrNode(ctxt, 
	    (xmlChar **) &xmlSchemaElemDesCT, NULL, attr, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_NCNAME), &name) != 0) {
	    return (NULL);
	}
    }
            
    if (topLevel == 0) {
	/*
	* Parse as local complex type definition.
	*/
        snprintf(buf, 39, "#CT %d", ctxt->counter++ + 1);
	type = xmlSchemaAddType(ctxt, schema, (const xmlChar *)buf, NULL, node);
	if (type == NULL)
	    return (NULL);
	name = (const xmlChar *) buf;
	type->node = node;
	type->type = XML_SCHEMA_TYPE_COMPLEX;
	/*
	* TODO: We need the target namespace.
	*/	
    } else {	
	/*
	* Parse as global complex type definition.
	*/	
	type = xmlSchemaAddType(ctxt, schema, name, schema->targetNamespace, node);
	if (type == NULL)
	    return (NULL);
	type->node = node;
	type->type = XML_SCHEMA_TYPE_COMPLEX;
	type->flags |= XML_SCHEMAS_TYPE_GLOBAL;	
	/* 
	* Set defaults.
	*/
	type->flags |= XML_SCHEMAS_TYPE_FINAL_DEFAULT;
	type->flags |= XML_SCHEMAS_TYPE_BLOCK_DEFAULT;
    }
    type->targetNamespace = schema->targetNamespace;
    /*
    * Handle attributes.
    */
    attr = node->properties;
    while (attr != NULL) {
	if (attr->ns == NULL) {
	    if (xmlStrEqual(attr->name, BAD_CAST "id")) {
		/*
		* Attribute "id".
		*/
		type->id = xmlSchemaGetProp(ctxt, node, "id");
	    } else if (xmlStrEqual(attr->name, BAD_CAST "mixed")) {
		/*
		* Attribute "mixed".
		*/
		if (xmlSchemaPGetBoolNodeValue(ctxt, &des, type, 
		    (xmlNodePtr) attr))
		    type->flags |= XML_SCHEMAS_TYPE_MIXED; 		
	    } else if (topLevel) {		
		/*
		* Attributes of global complex type definitions.
		*/
		if (xmlStrEqual(attr->name, BAD_CAST "name")) {
		    /* Pass. */
		} else if (xmlStrEqual(attr->name, BAD_CAST "abstract")) {
		    /*
		    * Attribute "abstract".
		    */
		    if (xmlSchemaPGetBoolNodeValue(ctxt, &des, type, 
			(xmlNodePtr) attr))		    
			type->flags |= XML_SCHEMAS_TYPE_ABSTRACT;
		} else if (xmlStrEqual(attr->name, BAD_CAST "final")) {
		    /*
		    * Attribute "final".
		    */
		    attrValue = xmlSchemaGetNodeContent(ctxt, 
			(xmlNodePtr) attr);
		    if (xmlSchemaPValAttrBlockFinal(attrValue, 
			&(type->flags), 
			-1, 
			XML_SCHEMAS_TYPE_FINAL_EXTENSION, 
			XML_SCHEMAS_TYPE_FINAL_RESTRICTION, 
			-1, -1, -1) != 0) 
		    {
			xmlSchemaPSimpleTypeErr(ctxt, 
			    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
			    &des, type, (xmlNodePtr) attr, 
			    NULL, 
			    "(#all | List of (extension | restriction))", 
			    attrValue, NULL, NULL, NULL);
		    }
		} else if (xmlStrEqual(attr->name, BAD_CAST "block")) {
		    /*
		    * Attribute "block".
		    */			
		    attrValue = xmlSchemaGetNodeContent(ctxt, 
			(xmlNodePtr) attr);	    
		    if (xmlSchemaPValAttrBlockFinal(attrValue, &(type->flags), 
			-1,
			XML_SCHEMAS_TYPE_BLOCK_EXTENSION,
			XML_SCHEMAS_TYPE_BLOCK_RESTRICTION, 
			-1, -1, -1) != 0) {
			xmlSchemaPSimpleTypeErr(ctxt,
			    XML_SCHEMAP_S4S_ATTR_INVALID_VALUE,
			    &des, type, (xmlNodePtr) attr,
			    NULL, 
			    "(#all | List of (extension | restriction)) ", 
			    attrValue, NULL, NULL, NULL);
		    }
		} else {
			xmlSchemaPIllegalAttrErr(ctxt, 
			    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
			    &des, type, attr);
		}
	    } else {	    
		xmlSchemaPIllegalAttrErr(ctxt, 
		    XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		    &des, type, attr);
	    }
	} else if (xmlStrEqual(attr->ns->href, xmlSchemaNs)) {
	    xmlSchemaPIllegalAttrErr(ctxt, 
		XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED, 
		&des, type, attr);	
	}
	attr = attr->next;
    }       
    /* 
    * Set as default for attribute wildcards.
    * This will be only changed if a complex type
    * inherits an attribute wildcard from a base type.
    */
    type->flags |= XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD;
    /*
    * And now for the children...
    */
    oldcontainer = ctxt->container;
    ctxt->container = name;    
    child = node->children;
    if (IS_SCHEMA(child, "annotation")) {
        type->annot = xmlSchemaParseAnnotation(ctxt, schema, child);
        child = child->next;
    }
    ctxt->ctxtType = type;
    if (IS_SCHEMA(child, "simpleContent")) {
	/* 
	* 3.4.3 : 2.2  
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
	/*
	* Parse model groups.
	*/
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
	/*
	* Parse attribute decls/refs.
	*/
        child = xmlSchemaParseAttrDecls(ctxt, schema, child, type);
	/*
	* Parse attribute wildcard.
	*/
	if (IS_SCHEMA(child, "anyAttribute")) {	    
	    type->attributeWildcard = xmlSchemaParseAnyAttribute(ctxt, schema, child);
	    child = child->next;
	}
    }
    if (child != NULL) {
	xmlSchemaPContentErr(ctxt,
	    XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED, 
	    &des, type, node, child,
	    NULL, "(annotation?, (simpleContent | complexContent | "
	    "((group | all | choice | sequence)?, ((attribute | "
	    "attributeGroup)*, anyAttribute?))))");
    }
    FREE_AND_NULL(des);
    ctxt->container = oldcontainer;
    ctxt->ctxtType = ctxtType;
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
    const xmlChar *val;
    int nberrors;
    xmlAttrPtr attr;

    /*
    * This one is called by xmlSchemaParse only and is used if
    * the schema to be parsed was specified via the API; i.e. not
    * automatically by the validated instance document.
    */
    if ((ctxt == NULL) || (node == NULL))
        return (NULL);
    nberrors = ctxt->nberrors;
    ctxt->nberrors = 0;
    if (IS_SCHEMA(node, "schema")) {
	xmlSchemaImportPtr import;

        schema = xmlSchemaNewSchema(ctxt);
        if (schema == NULL)
            return (NULL);
	/*
	* Disable build of list of items.
	*/
	attr = xmlSchemaGetPropNode(node, "targetNamespace"); 		
	if (attr != NULL) {
	    xmlSchemaPValAttrNode(ctxt, NULL, NULL, attr, 
		xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYURI), &val);
	    /*
	    * TODO: Should we proceed with an invalid target namespace?
	    */
	    schema->targetNamespace = xmlDictLookup(ctxt->dict, val, -1);
	} else {
	    schema->targetNamespace = NULL;
	}
	/*
	* Add the current ns name and location to the import table;
	* this is needed to have a consistent mechanism, regardless
	* if all schemata are constructed dynamically fired by the
	* instance or if the schema to be used was specified via
	* the API.
	*/
	import = xmlSchemaAddImport(ctxt, &(schema->schemasImports),
	    schema->targetNamespace);
	if (import == NULL) {
	    xmlSchemaPCustomErr(ctxt, XML_SCHEMAP_FAILED_BUILD_IMPORT,
		NULL, NULL, (xmlNodePtr) ctxt->doc,
		"Internal error: xmlSchemaParseSchema, "
		"failed to add an import entry", NULL);
	    xmlSchemaFree(schema);
	    schema = NULL;
	    return (NULL);
	}
	import->schemaLocation = ctxt->URL;
	/*
	* NOTE: We won't set the doc here, otherwise it will be freed
	* if the import struct is freed.
	* import->doc = ctxt->doc;
	*/

	/* TODO: Check id. */
        schema->id = xmlSchemaGetProp(ctxt, node, "id");
	xmlSchemaPValAttr(ctxt, NULL, NULL, node, "version", 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_TOKEN), &(schema->version));

	xmlSchemaParseSchemaDefaults(ctxt, schema, node);	
        xmlSchemaParseSchemaTopLevel(ctxt, schema, node->children);
    } else {
        xmlDocPtr doc;

	doc = node->doc;

        if ((doc != NULL) && (doc->URL != NULL)) {
	    xmlSchemaPErr(ctxt, (xmlNodePtr) doc,
		      XML_SCHEMAP_NOT_SCHEMA,
		      "The file \"%s\" is not a XML schema.\n", doc->URL, NULL);
	} else {
	    xmlSchemaPErr(ctxt, (xmlNodePtr) doc,
		      XML_SCHEMAP_NOT_SCHEMA,
		      "The file is not a XML schema.\n", NULL, NULL);
	}
	return(NULL);
    }
    if (ctxt->nberrors != 0) {
        if (schema != NULL) {
            xmlSchemaFree(schema);
            schema = NULL;
        }
    }
    if (schema != NULL)
	schema->counter = ctxt->counter;
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

#if 0 /* Will be enabled if it is clear what options are needed. */
/**
 * xmlSchemaParserCtxtSetOptions:
 * @ctxt:	a schema parser context
 * @options: a combination of xmlSchemaParserOption
 *
 * Sets the options to be used during the parse.
 *
 * Returns 0 in case of success, -1 in case of an
 * API error.
 */
static int
xmlSchemaParserCtxtSetOptions(xmlSchemaParserCtxtPtr ctxt,
			      int options)
					
{
    int i;

    if (ctxt == NULL)
	return (-1);
    /*
    * WARNING: Change the start value if adding to the
    * xmlSchemaParseOption.
    */
    for (i = 1; i < (int) sizeof(int) * 8; i++) {
        if (options & 1<<i) {
	    return (-1);   
        }	
    }
    ctxt->options = options;
    return (0);      
}

/**
 * xmlSchemaValidCtxtGetOptions:
 * @ctxt: a schema parser context 
 *
 * Returns the option combination of the parser context.
 */
static int
xmlSchemaParserCtxtGetOptions(xmlSchemaParserCtxtPtr ctxt)
					
{    
    if (ctxt == NULL)
	return (-1);
    else 
	return (ctxt->options);    
}

 void *curItems;  /* used for dynamic addition of schemata */
    int nbCurItems; /* used for dynamic addition of schemata */
    int sizeCurItems; /* used for dynamic addition of schemata */

#endif

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
        xmlSchemaPErrMemory(NULL, "allocating schema parser context",
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
 * xmlSchemaNewParserCtxtUseDict:
 * @URL:  the location of the schema
 * @dict: the dictionary to be used
 *
 * Create an XML Schemas parse context for that file/resource expected
 * to contain an XML Schemas file.
 *
 * Returns the parser context or NULL in case of error
 */
static xmlSchemaParserCtxtPtr
xmlSchemaNewParserCtxtUseDict(const char *URL, xmlDictPtr dict)
{
    xmlSchemaParserCtxtPtr ret;
    /*
    if (URL == NULL)
        return (NULL);
	*/

    ret = (xmlSchemaParserCtxtPtr) xmlMalloc(sizeof(xmlSchemaParserCtxt));
    if (ret == NULL) {
        xmlSchemaPErrMemory(NULL, "allocating schema parser context",
                            NULL);
        return (NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaParserCtxt));
    ret->dict = dict;
    xmlDictReference(dict);    
    if (URL != NULL)
	ret->URL = xmlDictLookup(dict, (const xmlChar *) URL, -1);
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
        xmlSchemaPErrMemory(NULL, "allocating schema parser context",
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
    if (ctxt->assemble != NULL) {
	xmlFree((xmlSchemaTypePtr *) ctxt->assemble->items);
	xmlFree(ctxt->assemble);
    }
    if (ctxt->vctxt != NULL) {
	xmlSchemaFreeValidCtxt(ctxt->vctxt);
    }
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
	case XML_SCHEMA_TYPE_ANY: {   
	    xmlAutomataStatePtr start, end;
	    xmlSchemaWildcardPtr wild;	    
	    xmlSchemaWildcardNsPtr ns;

	    wild = type->attributeWildcard;

	    if (wild == NULL) {
		xmlSchemaPErr(ctxt, type->node, XML_SCHEMAP_INTERNAL,
		    "Internal error: xmlSchemaBuildAContentModel, "
		    "no wildcard on xsd:any.\n", NULL, NULL);
		return;
	    }	     
	    
	    start = ctxt->state;
	    end = xmlAutomataNewState(ctxt->am);
	    
	    if (type->maxOccurs == 1) {		
		if (wild->any == 1) {
		    /*
		    * We need to add both transitions:
		    *
		    * 1. the {"*", "*"} for elements in a namespace.
		    */		    
		    ctxt->state = 
			xmlAutomataNewTransition2(ctxt->am,
			start, NULL, BAD_CAST "*", BAD_CAST "*", type);
		    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, end);
		    /*
		    * 2. the {"*"} for elements in no namespace.
		    */
		    ctxt->state = 
			xmlAutomataNewTransition2(ctxt->am,
			start, NULL, BAD_CAST "*", NULL, type);
		    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, end);

		} else if (wild->nsSet != NULL) {
		    ns = wild->nsSet;
		    do {
			ctxt->state = start;
			ctxt->state = xmlAutomataNewTransition2(ctxt->am,
			    ctxt->state, NULL, BAD_CAST "*", ns->value, type);
			xmlAutomataNewEpsilon(ctxt->am, ctxt->state, end);
			ns = ns->next;
		    } while (ns != NULL);

		} else if (wild->negNsSet != NULL) {
		    xmlAutomataStatePtr deadEnd;

		    deadEnd = xmlAutomataNewState(ctxt->am);
		    ctxt->state = xmlAutomataNewTransition2(ctxt->am,
			start, deadEnd, BAD_CAST "*", wild->negNsSet->value, type);
		    ctxt->state = xmlAutomataNewTransition2(ctxt->am,
			start, NULL, BAD_CAST "*", BAD_CAST "*", type);
		    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, end);
		}		
	    } else {
		int counter;
		xmlAutomataStatePtr hop;
		int maxOccurs = 
		    type->maxOccurs == UNBOUNDED ? UNBOUNDED : type->maxOccurs - 1;
		int minOccurs =
		    type->minOccurs < 1 ? 0 : type->minOccurs - 1;
		
		counter = xmlAutomataNewCounter(ctxt->am, minOccurs, maxOccurs);
		hop = xmlAutomataNewState(ctxt->am);		
		if (wild->any == 1) {		    
		    ctxt->state =
			xmlAutomataNewTransition2(ctxt->am,
			start, NULL, BAD_CAST "*", BAD_CAST "*", type);
		    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, hop);
		    ctxt->state = 
			xmlAutomataNewTransition2(ctxt->am,
			start, NULL, BAD_CAST "*", NULL, type);
		    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, hop);
		} else if (wild->nsSet != NULL) {		    
		    ns = wild->nsSet;
		    do {
			ctxt->state = 
			    xmlAutomataNewTransition2(ctxt->am,
				start, NULL, BAD_CAST "*", ns->value, type);
			xmlAutomataNewEpsilon(ctxt->am, ctxt->state, hop);
			ns = ns->next;
		    } while (ns != NULL);

		} else if (wild->negNsSet != NULL) {
		    xmlAutomataStatePtr deadEnd;

		    deadEnd = xmlAutomataNewState(ctxt->am);
		    ctxt->state = xmlAutomataNewTransition2(ctxt->am,
			start, deadEnd, BAD_CAST "*", wild->negNsSet->value, type);
		    ctxt->state = xmlAutomataNewTransition2(ctxt->am,
			start, NULL, BAD_CAST "*", BAD_CAST "*", type);
		    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, hop);
		}	
		xmlAutomataNewCountedTrans(ctxt->am, hop, start, counter);
		xmlAutomataNewCounterTrans(ctxt->am, hop, end, counter);
	    }
	    if (type->minOccurs == 0) {
		xmlAutomataNewEpsilon(ctxt->am, start, end);
	    }	    	    				            
	    ctxt->state = end;
            break;
	}
        case XML_SCHEMA_TYPE_ELEMENT:{
		xmlAutomataStatePtr oldstate;
                xmlSchemaElementPtr particle, elemDecl;

		/*
		* IMPORTANT: This puts element declarations
		* (and never element decl. references) into the
		* automaton. This is crucial and should not be changed, 
		* since validating functions rely now on it.
		*/
		particle = (xmlSchemaElementPtr) type;
		if (particle->ref != NULL) {
		    if (particle->refDecl == NULL) {
			/*
			* Skip content model creation if the reference
			* did not resolve to a declaration.
			*/
			break;
		    } else {
			/*
			* Referenced global element declaration.
			*/
			elemDecl = particle->refDecl;
		    }
		} else {
		    /*
		    * Anonymous element declaration.
		    */
		    elemDecl = particle;
		}
		
                oldstate = ctxt->state;

                if (particle->maxOccurs >= UNBOUNDED) {
                    if (particle->minOccurs > 1) {
                        xmlAutomataStatePtr tmp;
                        int counter;

                        ctxt->state = xmlAutomataNewEpsilon(ctxt->am,
			    oldstate, NULL);
                        oldstate = ctxt->state;
                        counter = xmlAutomataNewCounter(ctxt->am,
			    particle->minOccurs - 1, UNBOUNDED);                      
                        ctxt->state =
			    xmlAutomataNewTransition2(ctxt->am,
				ctxt->state, NULL, 
				elemDecl->name, 
				elemDecl->targetNamespace,
				(xmlSchemaTypePtr) elemDecl);
                        tmp = ctxt->state;
                        xmlAutomataNewCountedTrans(ctxt->am, tmp, oldstate,
			    counter);
                        ctxt->state =
                            xmlAutomataNewCounterTrans(ctxt->am, tmp, NULL,
				counter);

                    } else {                        
			ctxt->state =
			    xmlAutomataNewTransition2(ctxt->am,
			    ctxt->state, NULL,
			    elemDecl->name, 
			    elemDecl->targetNamespace,
			    (xmlSchemaTypePtr) elemDecl);
                        xmlAutomataNewEpsilon(ctxt->am, ctxt->state,
                                              oldstate);
                        if (particle->minOccurs == 0) {
                            /* basically an elem* */
                            xmlAutomataNewEpsilon(ctxt->am, oldstate,
                                                  ctxt->state);
                        }
                    }
                } else if ((particle->maxOccurs > 1) || (particle->minOccurs > 1)) {
                    xmlAutomataStatePtr tmp;
                    int counter;

                    ctxt->state = xmlAutomataNewEpsilon(ctxt->am,
                                                        oldstate, NULL);
                    oldstate = ctxt->state;
                    counter = xmlAutomataNewCounter(ctxt->am,
			particle->minOccurs - 1,
			particle->maxOccurs - 1);
                    ctxt->state = xmlAutomataNewTransition2(ctxt->am,
			ctxt->state,
			NULL,
			elemDecl->name,
			elemDecl->targetNamespace,
			(xmlSchemaTypePtr) elemDecl);
                    tmp = ctxt->state;
                    xmlAutomataNewCountedTrans(ctxt->am, tmp, oldstate,
			counter);
                    ctxt->state = xmlAutomataNewCounterTrans(ctxt->am, tmp,
			NULL, counter);
                    if (particle->minOccurs == 0) {
                        /* basically an elem? */
                        xmlAutomataNewEpsilon(ctxt->am, oldstate,
			    ctxt->state);
                    }

                } else {                    
		    ctxt->state = xmlAutomataNewTransition2(ctxt->am,
			ctxt->state,
			NULL,
			elemDecl->name,
			elemDecl->targetNamespace,
			(xmlSchemaTypePtr) elemDecl);
                    if (particle->minOccurs == 0) {
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
		    /*
		    * NOTE: The {max occurs} of all the particles in the 
		    * {particles} of the group must be 0 or 1.
		    */                    
                    if ((elem->minOccurs == 1) && (elem->maxOccurs == 1)) {
                        xmlAutomataNewOnceTrans2(ctxt->am, ctxt->state,
                                                ctxt->state, 
						elem->name, 
						elem->targetNamespace,
						1, 1, subtypes);
                    } else if ((elem->minOccurs == 0) &&
			(elem->maxOccurs == 1)) {
			
                        xmlAutomataNewCountTrans2(ctxt->am, ctxt->state,
                                                 ctxt->state, 
						 elem->name,
						 elem->targetNamespace,
                                                 0,
                                                 1,
                                                 subtypes);
                    }
		    /*
		    * NOTE: if maxOccurs == 0 then no transition will be
		    * created.
		    */
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
		
		/*
		* TODO: Circular definitions will be checked at the
		* constraint level. So remove this when the complex type
		* constraints are implemented.
		*/
		if (type->recurse) { 
		    /* TODO: Change the error code. */
		    xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_UNKNOWN_BASE_TYPE,
			    NULL, type, type->node,	
			    "This item is circular", NULL);		     
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
	    /*
	    * Handle model group definition references. 
	    * NOTE: type->subtypes is the referenced model grop definition;
	    * and type->subtypes->subtypes is the model group (i.e. <all> or 
	    * <choice> or <sequence>).
	    */
	    if ((type->ref != NULL) && (type->subtypes != NULL) &&
		(type->subtypes->subtypes != NULL)) {
		xmlSchemaTypePtr modelGr;
                xmlAutomataStatePtr start, end;

		modelGr = type->subtypes->subtypes;
                start = ctxt->state;
                end = xmlAutomataNewState(ctxt->am);		
                if (type->maxOccurs == 1) {
		    ctxt->state = start;
		    xmlSchemaBuildAContentModel(modelGr, ctxt, name);
		    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, end);
                } else {
                    int counter;
                    xmlAutomataStatePtr hop;
                    int maxOccurs = type->maxOccurs == UNBOUNDED ?
				    UNBOUNDED : type->maxOccurs - 1;
                    int minOccurs =
                        type->minOccurs < 1 ? 0 : type->minOccurs - 1;
		    
                    counter =
                        xmlAutomataNewCounter(ctxt->am, minOccurs, maxOccurs);
                    hop = xmlAutomataNewState(ctxt->am);		                        
                    ctxt->state = start;
                    xmlSchemaBuildAContentModel(modelGr, ctxt, name);
                    xmlAutomataNewEpsilon(ctxt->am, ctxt->state, hop);
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
	    break;
        case XML_SCHEMA_TYPE_COMPLEX:
        case XML_SCHEMA_TYPE_COMPLEX_CONTENT:
            if (type->subtypes != NULL)
                xmlSchemaBuildAContentModel(type->subtypes, ctxt, name);
            break;
	case XML_SCHEMA_TYPE_SIMPLE_CONTENT:
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
 * @type:  the type definition (or reference)
 * @ctxt:  the schema parser context
 * @name:  the element name
 *
 * Builds the content model of the complex type.
 */
static void
xmlSchemaBuildContentModel(xmlSchemaTypePtr type,
                           xmlSchemaParserCtxtPtr ctxt,
                           const xmlChar * name)
{
    xmlAutomataStatePtr start;

    if ((type->type != XML_SCHEMA_TYPE_COMPLEX) || (type->ref != NULL) ||
	(type->contentType == XML_SCHEMA_CONTENT_BASIC) ||
	(type->contentType == XML_SCHEMA_CONTENT_SIMPLE) ||
	(type->contModel != NULL))
	return;

#ifdef DEBUG_CONTENT
    xmlGenericError(xmlGenericErrorContext,
                    "Building content model for %s\n", name);
#endif

    ctxt->am = xmlNewAutomata();
    if (ctxt->am == NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "Cannot create automata for complex tpye %s\n", name);
        return;
    }
    start = ctxt->state = xmlAutomataGetInitState(ctxt->am);
    xmlSchemaBuildAContentModel(type, ctxt, name);
    xmlAutomataSetFinalState(ctxt->am, ctxt->state);
    type->contModel = xmlAutomataCompile(ctxt->am);
    if (type->contModel == NULL) {
        xmlSchemaPCustomErr(ctxt, 
	    XML_SCHEMAP_INTERNAL, 
	    NULL, type, type->node,	    
	    "Failed to compile the content model", NULL);
    } else if (xmlRegexpIsDeterminist(type->contModel) != 1) {
        xmlSchemaPCustomErr(ctxt, 
	    XML_SCHEMAP_NOT_DETERMINISTIC,
	    /* XML_SCHEMAS_ERR_NOTDETERMINIST, */
	    NULL, type, type->node,
	    "The content model is not determinist", NULL);
    } else {
#ifdef DEBUG_CONTENT_REGEXP
        xmlGenericError(xmlGenericErrorContext,
                        "Content model of %s:\n", name);
        xmlRegexpPrint(stderr, type->contModel);
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
 * Resolves the references of an element declaration
 * or particle, which has an element declaration as it's
 * term. 
 */
static void
xmlSchemaRefFixupCallback(xmlSchemaElementPtr elem,
                          xmlSchemaParserCtxtPtr ctxt,
                          const xmlChar * name ATTRIBUTE_UNUSED,
                          const xmlChar * context ATTRIBUTE_UNUSED,
                          const xmlChar * namespace ATTRIBUTE_UNUSED)
{
    if ((ctxt == NULL) || (elem == NULL) || 
	((elem != NULL) && (elem->flags & XML_SCHEMAS_ELEM_INTERNAL_RESOLVED)))
        return;
    elem->flags |= XML_SCHEMAS_ELEM_INTERNAL_RESOLVED;
    if (elem->ref != NULL) {
        xmlSchemaElementPtr elemDecl;

	/*
	* TODO: Evaluate, what errors could occur if the declaration is not
	* found. It might be possible that the "typefixup" might crash if
	* no ref declaration was found.
	*/
        elemDecl = xmlSchemaGetElem(ctxt->schema, elem->ref, elem->refNs);
        if (elemDecl == NULL) {	  
	    xmlSchemaPResCompAttrErr(ctxt,
		XML_SCHEMAP_SRC_RESOLVE,
		NULL, (xmlSchemaTypePtr) elem, elem->node,
		"ref", elem->ref, elem->refNs, 
		XML_SCHEMA_TYPE_ELEMENT, NULL);
        } else
	    elem->refDecl = elemDecl;	
    } else {	
	if ((elem->subtypes == NULL) && (elem->namedType != NULL)) {
	    xmlSchemaTypePtr type;
	    
	    /* (type definition) ... otherwise the type definition ·resolved· 
	    * to by the ·actual value· of the type [attribute] ...
	    */	    	    
	    type = xmlSchemaGetType(ctxt->schema, elem->namedType,
		elem->namedTypeNs);	    
	    if (type == NULL) {	
		xmlSchemaPResCompAttrErr(ctxt,
		    XML_SCHEMAP_SRC_RESOLVE,
		    NULL, (xmlSchemaTypePtr) elem, elem->node,
		    "type", elem->namedType, elem->namedTypeNs,
		    XML_SCHEMA_TYPE_BASIC, "type definition");
	    } else
		elem->subtypes = type;
	}
	if (elem->substGroup != NULL) {
	    xmlSchemaElementPtr substHead;
	    
	    /*
	    * FIXME TODO: Do we need a new field in _xmlSchemaElement for 
	    * substitutionGroup?
	    */
	    substHead = xmlSchemaGetElem(ctxt->schema, elem->substGroup, 
		elem->substGroupNs);	    
	    if (substHead == NULL) {
		xmlSchemaPResCompAttrErr(ctxt,
		    XML_SCHEMAP_SRC_RESOLVE,
		    NULL, (xmlSchemaTypePtr) elem, NULL,
		    "substitutionGroup", elem->substGroup, elem->substGroupNs,
		    XML_SCHEMA_TYPE_ELEMENT, NULL);
	    } else {
		xmlSchemaRefFixupCallback(substHead, ctxt, NULL, NULL, NULL);
		/*
		* (type definition)...otherwise the {type definition} of the 
		* element declaration ·resolved· to by the ·actual value· of 
		* the substitutionGroup [attribute], if present
		*/
		if (elem->subtypes == NULL) 
		    elem->subtypes = substHead->subtypes;
	    }
	}
	if ((elem->subtypes == NULL) && (elem->namedType == NULL) &&
	    (elem->substGroup == NULL))
	    elem->subtypes = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE);
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
    
    if (((type->base == NULL) && 
	 (type->subtypes == NULL)) ||
	((type->base != NULL) &&
	 (type->subtypes != NULL))) {	
	/*
	* src-list-itemType-or-simpleType
	* Either the itemType [attribute] or the <simpleType> [child] of 
	* the <list> element must be present, but not both. 
	*/
	/*
	* TODO: Move this to the parse function.
	*/
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE,
	    NULL, type, type->node, 
	    "The attribute 'itemType' and the <simpleType> child "
	    "are mutually exclusive", NULL);	
    } else if (type->base!= NULL) {        	
        type->subtypes = xmlSchemaGetType(ctxt->schema, type->base, type->baseNs);
        if (type->subtypes == NULL) {
	    xmlSchemaPResCompAttrErr(ctxt,	    
		XML_SCHEMAP_SRC_RESOLVE,
		NULL, type, type->node,
		"itemType", type->base, type->baseNs,
		XML_SCHEMA_TYPE_SIMPLE, NULL);
        }
    }               
    if ((type->subtypes != NULL) && 
	(type->subtypes->contentType == XML_SCHEMA_CONTENT_UNKNOWN))
	xmlSchemaTypeFixup(type->subtypes, ctxt, NULL);
}

/**
 * xmlSchemaParseUnionRefCheck:
 * @typeDecl:  the schema type definition
 * @ctxt:  the schema parser context
 *
 * Checks and builds the memberTypes of the union type.
 * Returns -1 in case of an internal error, 0 otherwise.
 */
static int
xmlSchemaParseUnionRefCheck(xmlSchemaTypePtr type,
                   xmlSchemaParserCtxtPtr ctxt)
{
    
    xmlSchemaTypeLinkPtr link, lastLink = NULL, prevLink, subLink, newLink;
    xmlSchemaTypePtr memberType, ctxtType;

    /* 1 If the <union> alternative is chosen, then [Definition:]  
    * define the explicit members as the type definitions ·resolved· 
    * to by the items in the ·actual value· of the memberTypes [attribute], 
    * if any, followed by the type definitions corresponding to the 
    * <simpleType>s among the [children] of <union>, if any. 
    */   

    if (type->type != XML_SCHEMA_TYPE_UNION)
        return (-1);
    if (ctxt->ctxtType == NULL) {
	xmlSchemaPErr(ctxt, type->node,
	    XML_SCHEMAP_INTERNAL,
	    "Internal error: xmlSchemaParseUnionRefCheck, no parent type "
	    "available", NULL, NULL);
	return (-1);
    }
    /*
    * src-union-memberTypes-or-simpleTypes
    * Either the memberTypes [attribute] of the <union> element must 
    * be non-empty or there must be at least one simpleType [child]. 
    */
    if ((type->base == NULL) && 
	(type->subtypes == NULL)) {
	xmlSchemaPCustomErr(ctxt, 
	    XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES,
	    NULL, NULL, type->node,	
	    "Either the attribute 'memberTypes' must be non-empty "
	    "or there must be at least one <simpleType> child", NULL);
    } 
	
    ctxtType = ctxt->ctxtType;
    if (type->base != NULL) {
	xmlAttrPtr attr;
	const xmlChar *cur, *end;
	xmlChar *tmp;
	const xmlChar *localName, *uri;

	attr = xmlSchemaGetPropNode(type->node, "memberTypes");
	cur = type->base;
	do {
	    while (IS_BLANK_CH(*cur))
		cur++;
	    end = cur;
	    while ((*end != 0) && (!(IS_BLANK_CH(*end))))
		end++;
	    if (end == cur)
		break;
	    tmp = xmlStrndup(cur, end - cur);
	    xmlSchemaPValAttrNodeQNameValue(ctxt, ctxt->schema, NULL, 
		NULL, attr, BAD_CAST tmp, &uri, NULL, &localName);	   
	    memberType = xmlSchemaGetType(ctxt->schema, localName, uri);
	    if (memberType == NULL) {
		xmlSchemaPResCompAttrErr(ctxt,
		    XML_SCHEMAP_UNKNOWN_MEMBER_TYPE,
		    NULL, NULL, type->node, "memberTypes", localName, uri,
		    XML_SCHEMA_TYPE_SIMPLE, NULL);
	    } else {
		if (memberType->contentType == XML_SCHEMA_CONTENT_UNKNOWN) 
		    xmlSchemaTypeFixup(memberType, ctxt, NULL);	    
		link = (xmlSchemaTypeLinkPtr) xmlMalloc(sizeof(xmlSchemaTypeLink));
		if (link == NULL) {
		    xmlSchemaPErrMemory(ctxt, "allocating a type link", NULL);
		    return (-1);
		}
		link->type = memberType;
		link->next = NULL;
		if (lastLink == NULL)
		    ctxtType->memberTypes = link;		    
		else 
		    lastLink->next = link;
		lastLink = link;	    
	    }
	    xmlFree(tmp);
	    cur = end;
	} while (*cur != 0); 
    }
    /*
    * Add local simple types,
    */    
    memberType = type->subtypes;
    while (memberType != NULL) {
	if (memberType->contentType == XML_SCHEMA_CONTENT_UNKNOWN)
	    xmlSchemaTypeFixup(memberType, ctxt, NULL);	    
	link = (xmlSchemaTypeLinkPtr) xmlMalloc(sizeof(xmlSchemaTypeLink));
	if (link == NULL) {
	    xmlSchemaPErrMemory(ctxt, "allocating a type link", NULL);
	    return (-1);
	}
	link->type = memberType;
	link->next = NULL;
	if (lastLink == NULL)
	    ctxtType->memberTypes = link;		    
	else 
	    lastLink->next = link;
	lastLink = link;
	memberType = memberType->next;
    }    
    /*
    * The actual value is then formed by replacing any union type 
    * definition in the ·explicit members· with the members of their 
    * {member type definitions}, in order.
    */
    link = ctxtType->memberTypes;
    while (link != NULL) {
	if (link->type->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) {
	    subLink = link->type->memberTypes;	    
	    if (subLink != NULL) {		
		link->type = subLink->type;
		if (subLink->next != NULL) {
		    lastLink = link->next;
		    subLink = subLink->next;		
		    prevLink = link;
		    while (subLink != NULL) {		    
			newLink = (xmlSchemaTypeLinkPtr) 
			    xmlMalloc(sizeof(xmlSchemaTypeLink));
			if (newLink == NULL) {
			    xmlSchemaPErrMemory(ctxt, "allocating a type link", 
				NULL);
			    return (-1);
			}
			newLink->type = memberType;	    
			prevLink->next = newLink;
			prevLink = newLink;
			newLink->next = lastLink;
			
			subLink = subLink->next;
		    }
		}
	    }
	}
	link = link->next;
    }    

    return (0);
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
		if (type->builtInType == valType)
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
 * xmlSchemaIsDerivedFromBuiltInType:
 * @type:  the simpleType definition
 *
 * Returns the primitive type of the given type or
 * NULL in case of error.
 */
static xmlSchemaTypePtr
xmlSchemaGetPrimitiveType(xmlSchemaTypePtr type)
{
    while (type != NULL) {
	if (type->flags & XML_SCHEMAS_TYPE_BUILTIN_PRIMITIVE)
	    return (type);
	type = type->baseType;
    }

    return (NULL);
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

/**
 * xmlSchemaCloneWildcardNsConstraints:
 * @ctxt:  the schema parser context
 * @dest:  the destination wildcard
 * @source: the source wildcard
 *
 * Clones the namespace constraints of source
 * and assignes them to dest.
 * Returns -1 on internal error, 0 otherwise.
 */
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

/**
 * xmlSchemaUnionWildcards:
 * @ctxt:  the schema parser context
 * @completeWild:  the first wildcard
 * @curWild: the second wildcard 
 *
 * Unions the namespace constraints of the given wildcards.
 * @completeWild will hold the resulting union.
 * Returns a positive error code on failure, -1 in case of an
 * internal error, 0 otherwise.
 */
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
    if (completeWild->any != curWild->any) {	
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
	return (0);
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

	return(0);
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
		"The union of the wilcard is not expressible.\n",
		NULL, NULL);	
	    return(XML_SCHEMAP_UNION_NOT_EXPRESSIBLE);
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

/**
 * xmlSchemaIntersectWildcards:
 * @ctxt:  the schema parser context
 * @completeWild:  the first wildcard
 * @curWild: the second wildcard 
 *
 * Intersects the namespace constraints of the given wildcards.
 * @completeWild will hold the resulting intersection.
 * Returns a positive error code on failure, -1 in case of an
 * internal error, 0 otherwise.
 */
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
	    "The intersection of the wilcard is not expressible.\n",
	    NULL, NULL);	
	return(XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE);
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

/**
 * xmlSchemaIsWildcardNsConstraintSubset:
 * @ctxt:  the schema parser context
 * @wildA:  the first wildcard
 * @wildB: the second wildcard 
 *
 * Returns 1 if the namespace constraint of @wildA is an intensional 
 * subset of @wildB, 0 otherwise.
 */
static int
xmlSchemaIsWildcardNsConstraintSubset(xmlSchemaWildcardPtr wildA,
				      xmlSchemaWildcardPtr wildB)
{    

    /*
    * Schema Component Constraint: Wildcard Subset 
    */
    /*
    * 1 super must be any. 
    */
    if (wildB->any)
	return (1);
    /*
    * 2.1 sub must be a pair of not and a namespace name or ·absent·.
    * 2.2 super must be a pair of not and the same value.
    */
    if ((wildA->negNsSet != NULL) &&
	(wildB->negNsSet != NULL) &&
	(wildA->negNsSet->value == wildA->negNsSet->value))
	return (1);    
    /* 
    * 3.1 sub must be a set whose members are either namespace names or ·absent·. 
    */
    if (wildA->nsSet != NULL) {
	/*
	* 3.2.1 super must be the same set or a superset thereof. 
	*/
	if (wildB->nsSet != NULL) {
	    xmlSchemaWildcardNsPtr cur, curB;
	    int found = 0;
	    
	    cur = wildA->nsSet;
	    while (cur != NULL) {
		found = 0;
		curB = wildB->nsSet;
		while (curB != NULL) {
		    if (cur->value == curB->value) {
			found = 1;
			break;
		    }
		    curB = curB->next;
		}
		if (!found)
		    return (0);
		cur = cur->next;
	    }
	    if (found)
		return (1); 
	} else if (wildB->negNsSet != NULL) {
	    xmlSchemaWildcardNsPtr cur;
	    /*
	    * 3.2.2 super must be a pair of not and a namespace name or 
	    * ·absent· and that value must not be in sub's set. 
	    */
	    cur = wildA->nsSet;
	    while (cur != NULL) {		
		if (cur->value == wildB->negNsSet->value)
		    return (0);
		cur = cur->next;
	    }  
	    return (1);
	}
    }
    return (0);
}

/**
 * xmlSchemaBuildCompleteAttributeWildcard:
 * @ctxt:  the schema parser context
 * @attrs: the attribute list 
 * @completeWild: the resulting complete wildcard
 *
 * Returns -1 in case of an internal error, 0 otherwise.
 */
static int
xmlSchemaBuildCompleteAttributeWildcard(xmlSchemaParserCtxtPtr ctxt, 				    
				   xmlSchemaAttributePtr attrs,
				   xmlSchemaWildcardPtr *completeWild)				
{        
    while (attrs != NULL) {
	if (attrs->type == XML_SCHEMA_TYPE_ATTRIBUTEGROUP) {
	    xmlSchemaAttributeGroupPtr group;

	    group = (xmlSchemaAttributeGroupPtr) attrs;
	    /*
	    * Handle attribute group references.
	    */
	    if (group->ref != NULL) {
		if (group->refItem == NULL) {
		    /*
		    * TODO: Should we raise a warning here?
		    */
		    /*
		    * The referenced attribute group definition could not
		    * be resolved beforehand, so skip.
		    */
		    attrs = attrs->next;
		    continue;
		} else
		    group = group->refItem;
	    }	    
	    /*
	    * For every attribute group definition, an intersected wildcard 
	    * will be created (assumed that a wildcard exists on the 
	    * particular attr. gr. def. or on any contained attr. gr. def 
	    * at all).
	    * The flag XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED ensures
	    * that the intersection will be performed only once.
	    */
	    if ((group->flags & XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED) == 0) {
		if (group->attributes != NULL) {
		    if (xmlSchemaBuildCompleteAttributeWildcard(ctxt, 
			group->attributes, &group->attributeWildcard) == -1)
			return (-1);
		}
		group->flags |= XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED;
	    }		
	    if (group->attributeWildcard != NULL) {		
		if (*completeWild == NULL) {
		    /*
		    * Copy the first encountered wildcard as context, except for the annotation.
		    */
		    *completeWild = xmlSchemaAddWildcard(ctxt);
		    (*completeWild)->type = XML_SCHEMA_TYPE_ANY_ATTRIBUTE;	   
		    if (xmlSchemaCloneWildcardNsConstraints(ctxt, 
			completeWild, group->attributeWildcard) == -1)
			return (-1);
		    (*completeWild)->processContents = group->attributeWildcard->processContents;
		    /*
		    * Although the complete wildcard might not correspond to any
		    * node in the schema, we will save this context node.
		    * TODO: Hmm, is this sane?
		    */
		    (*completeWild)->node = group->attributeWildcard->node;  
		    
		} else if (xmlSchemaIntersectWildcards(ctxt, *completeWild, group->attributeWildcard) == -1) {
		    xmlSchemaFreeWildcard(*completeWild);
		    return (-1);
		}		
	    }
	}
	attrs = attrs->next;
    }
   		                 
    return (0);   
}

static int
xmlSchemaGetEffectiveValueConstraint(xmlSchemaAttributePtr item,
				     int *fixed,
				     const xmlChar **value,
				     xmlSchemaValPtr *val)
{
    *fixed = 0;
    *value = NULL;
    if (val != 0) 
	*val = NULL;

    if (item->defValue == NULL)
	item = item->refDecl;

    if (item == NULL)
	return (0);

    if (item->defValue != NULL) {
	*value = item->defValue;
	if (val != 0)
	    *val = item->defVal;
	if (item->flags & XML_SCHEMAS_ATTR_FIXED)
	    *fixed = 1;
	return (1);
    }
    return (0);
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
    xmlSchemaTypePtr anyType;
    int baseIsAnyType = 0;
    xmlChar *str = NULL;
    int err = 0;

    anyType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE);
    /* 
     * Complex Type Definition with complex content Schema Component.
     *
     * Attribute uses.
     * TODO: Add checks for absent referenced attribute declarations and
     * simple types.
     */
    if (type->attributeUses != NULL) {
        xmlSchemaPErr(ctxt, type->node, XML_SCHEMAP_INTERNAL,
		      "Internal error: xmlSchemaBuildAttributeValidation: "
		      "attribute uses already builded.\n",
		      NULL, NULL);
        return (-1);
    }
    if (type->baseType == NULL) {
        xmlSchemaPErr(ctxt, type->node, XML_SCHEMAP_INTERNAL,
		      "Internal error: xmlSchemaBuildAttributeValidation: "
		      "complex type '%s' has no base type.\n",
		      type->name, NULL);
        return (-1);
    }
    baseType = type->baseType;
    if (baseType == anyType)
	baseIsAnyType = 1;
    /*
     * Inherit the attribute uses of the base type.
     */
    /*
     * NOTE: It is allowed to "extend" the anyType complex type.
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
    if ((type->subtypes != NULL) && 
	((type->subtypes->type == XML_SCHEMA_TYPE_COMPLEX_CONTENT) || 
	 (type->subtypes->type == XML_SCHEMA_TYPE_SIMPLE_CONTENT))) {
	/* 
	* type --> (<simpleContent>|<complexContent>) 
	*        --> (<restriction>|<extension>) --> attributes
	*/ 
	attrs = type->subtypes->subtypes->attributes;
    } else {
	/* Short hand form of the complexType. */
	attrs = type->attributes;
    }
    /*
    * Handle attribute wildcards.
    */	
    err = xmlSchemaBuildCompleteAttributeWildcard(ctxt, 
	attrs, &type->attributeWildcard);    
    /*
    * NOTE: During the parse time, the wildcard is created on the complexType
    * directly, if encountered in a <restriction> or <extension> element.
    */
    if (err == -1) {
	xmlSchemaPErr(ctxt, type->node, XML_SCHEMAP_INTERNAL,
	    "Internal error: xmlSchemaBuildAttributeValidation: "
	    "failed to build an intersected attribute wildcard.\n",
	    NULL, NULL);
	return (-1);
    }

    if ((type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) && 
	((baseIsAnyType) ||
	 ((baseType != NULL) && 	    
	  (baseType->type == XML_SCHEMA_TYPE_COMPLEX) &&	      
	  (baseType->attributeWildcard != NULL)))) {	    
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
	    /*
	    * NOTE: This is the only case where an attribute 
            * wildcard is shared.
            */
	    if (type->flags & XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD)
		type->flags ^= XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD;
	    type->attributeWildcard = baseType->attributeWildcard;
	}
    }
    
    if (type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION) {
	if (type->attributeWildcard != NULL) {
	    /* 
	    * Derivation Valid (Restriction, Complex) 	    
	    * 4.1 The {base type definition} must also have one. 
	    */
	    if (baseType->attributeWildcard == NULL) {	  
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1,
		    NULL, type, NULL, 
		    "The type has an attribute wildcard, "
		    "but the base type %s does not have one",
		    xmlSchemaFormatItemForReport(&str, NULL, baseType, NULL, 1));
		FREE_AND_NULL(str)
		return (1);
	    } else if (xmlSchemaIsWildcardNsConstraintSubset(
		type->attributeWildcard, baseType->attributeWildcard) == 0) {
		/* 4.2 */
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2,
		    NULL, type, NULL, 		
		    "The attribute wildcard is not a valid " 
		    "subset of the wildcard in the base type %s",
		    xmlSchemaFormatItemForReport(&str, NULL, baseType, NULL, 1));
		FREE_AND_NULL(str)	    
		return (1);
	    }
	    /* 4.3 Unless the {base type definition} is the ·ur-type 
	    * definition·, the complex type definition's {attribute 
	    * wildcard}'s {process contents} must be identical to or 
	    * stronger than the {base type definition}'s {attribute 
	    * wildcard}'s {process contents}, where strict is stronger 
	    * than lax is stronger than skip.
	    */
	    if ((type->baseType != anyType) && 
		(type->attributeWildcard->processContents < 
		baseType->attributeWildcard->processContents)) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3,
		    NULL, type, NULL, 		
		    "The 'process contents' of the attribute wildcard is weaker than "
		    "the one in the base type %s",
		    xmlSchemaFormatItemForReport(&str, NULL, baseType, NULL, 1));
		FREE_AND_NULL(str)
		return (1);
	    }
	}
    } else if (type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) {
	/*
	* Derivation Valid (Extension)
	* At this point the type and the base have both, either
	* no wildcard or a wildcard.
	*/
	if ((baseType->attributeWildcard != NULL) &&
	    (baseType->attributeWildcard != type->attributeWildcard)) {
	    /* 1.3 */
	    if (xmlSchemaIsWildcardNsConstraintSubset(
		baseType->attributeWildcard, type->attributeWildcard) == 0) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_CT_EXTENDS_1_3,
		    NULL, type, NULL, 		
		    "The attribute wildcard is not a valid " 
		    "superset of the one in the base type %s",
		    xmlSchemaFormatItemForReport(&str, NULL, baseType, NULL, 1));
		FREE_AND_NULL(str)		
		return (1);		
	    }
	}		
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
		if ((xmlStrEqual(xmlSchemaGetAttrName(cur->attr), 
		    xmlSchemaGetAttrName(tmp->attr))) &&
		    (xmlStrEqual(xmlSchemaGetAttrTargetNsURI(cur->attr ), 
		    xmlSchemaGetAttrTargetNsURI(tmp->attr)))) {

		    xmlSchemaPAttrUseErr(ctxt,
			XML_SCHEMAP_CT_PROPS_CORRECT_4, 
			NULL, type, NULL, cur->attr,			
			"Duplicate attribute use %s specified",
			xmlSchemaFormatNsUriLocal(&str, 
			    xmlSchemaGetAttrTargetNsURI(tmp->attr), 
			    xmlSchemaGetAttrName(tmp->attr))
		    );
		    FREE_AND_NULL(str)		    		    
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
	    const xmlChar *bEffValue;
	    int effFixed;

	    cur = uses;
	    while (cur != NULL) {
		found = 0;
		base = type->attributeUses;
		while (base != NULL) {
		    if (xmlStrEqual(xmlSchemaGetAttrName(cur->attr), 
			xmlSchemaGetAttrName(base->attr)) &&
			xmlStrEqual(xmlSchemaGetAttrTargetNsURI(cur->attr), 
			xmlSchemaGetAttrTargetNsURI(base->attr))) {
			
			found = 1;			
			
			if ((cur->attr->occurs == XML_SCHEMAS_ATTR_USE_OPTIONAL) &&
			    (base->attr->occurs == XML_SCHEMAS_ATTR_USE_REQUIRED)) {
			    /*
			    * derivation-ok-restriction 2.1.1
			    */	
			    xmlSchemaPAttrUseErr(ctxt,
				XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1,
				NULL, type, NULL, cur->attr,
				"The 'optional' use is inconsistent with a matching "
				"'required' use of the base type", NULL);				
			} else if ((cur->attr->occurs == XML_SCHEMAS_ATTR_USE_PROHIBITED) &&
			    (base->attr->occurs == XML_SCHEMAS_ATTR_USE_REQUIRED)) {
			    /*
			    * derivation-ok-restriction 3 
			    */
			    xmlSchemaPCustomErr(ctxt,
				XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3, 
				NULL, type, NULL, 		
				"A matching attribute use for the 'required' "
				"attribute use %s of the base type is missing",
				xmlSchemaFormatNsUriLocal(&str, 
				xmlSchemaGetAttrTargetNsURI(base->attr), 
				xmlSchemaGetAttrName(base->attr)));	
			    FREE_AND_NULL(str)
			} else {
			    /*
			    * 2.1.3 [Definition:]  Let the effective value 
			    * constraint of an attribute use be its {value 
			    * constraint}, if present, otherwise its {attribute 
			    * declaration}'s {value constraint} . 
			    */
			    xmlSchemaGetEffectiveValueConstraint(base->attr, &effFixed, 
				&bEffValue, 0);			   							    
			    /*
			    * 2.1.3 ... one of the following must be true
			    *
			    * 2.1.3.1 B's ·effective value constraint· is 
			    * ·absent· or default.
			    */
			    if ((bEffValue != NULL) &&
				(effFixed == 1)) {
				const xmlChar *rEffValue = NULL;

				xmlSchemaGetEffectiveValueConstraint(base->attr, &effFixed, 
				    &rEffValue, 0);	
				/*
				* 2.1.3.2 R's ·effective value constraint· is 
				* fixed with the same string as B's.
				*/
				if ((effFixed == 0) ||
				    (! xmlStrEqual(rEffValue, bEffValue))) {
				    xmlSchemaPAttrUseErr(ctxt,
					XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3, 
					NULL, type, NULL, cur->attr,		
					"The effective value constraint of the "
					"attribute use is inconsistent with "
					"its correspondent of the base type",
					NULL);					    
				}
			    }
			    /*
			    * TODO: derivation-ok-restriction  2.1.2 ({type definition} must be validly derived)
			    */
			    /*
			    * Override the attribute use.
			    */
			    base->attr = cur->attr;
			}
								
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
			    xmlSchemaPAttrUseErr(ctxt,
				XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2, 
				NULL, type, NULL, cur->attr,		
				"Neither a matching attribute use, "
				"nor a matching wildcard in the base type does exist",
				NULL);
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
		    if ((xmlStrEqual(xmlSchemaGetAttrName(cur->attr), 
			xmlSchemaGetAttrName(tmp->attr))) &&
			(xmlStrEqual(xmlSchemaGetAttrTargetNsURI(cur->attr ), 
			xmlSchemaGetAttrTargetNsURI(tmp->attr)))) {

			xmlSchemaPAttrUseErr(ctxt,
			    XML_SCHEMAP_CT_PROPS_CORRECT_4, 
			    NULL, type, NULL, tmp->attr,		
			    "Duplicate attribute use specified", NULL);
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
		(xmlSchemaIsDerivedFromBuiltInType(ctxt, (xmlSchemaTypePtr) cur->attr, XML_SCHEMAS_ID))) {
		if (id != NULL) {
		    xmlSchemaPAttrUseErr(ctxt,
			XML_SCHEMAP_CT_PROPS_CORRECT_5, 
			NULL, type, NULL, cur->attr,
			"There must not exist more than one attribute use, "
			"declared of type 'ID' or derived from it", 
			NULL);
		    FREE_AND_NULL(str)
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
	xmlSchemaPErr(ctxt, baseType->node, XML_SCHEMAP_INTERNAL,
	    "Internal error: xmlSchemaBuildAttributeValidation: "
	    "attribute uses not builded on base type '%s'.\n",
	    baseType->name, NULL);
    }    
    return (0);
}

/**
 * xmlSchemaTypeFinalContains:
 * @schema:  the schema
 * @type:  the type definition
 * @final: the final
 *
 * Evaluates if a type definition contains the given "final".
 * This does take "finalDefault" into account as well.
 *
 * Returns 1 if the type does containt the given "final",
 * 0 otherwise.
 */
static int
xmlSchemaTypeFinalContains(xmlSchemaPtr schema, xmlSchemaTypePtr type, int final)
{
    int tfinal = final, tflags = type->flags;

    if (type == NULL)
	return (0);    
    if (type->flags & XML_SCHEMAS_TYPE_FINAL_DEFAULT) {
	switch (final) {
	    case XML_SCHEMAS_TYPE_FINAL_RESTRICTION:
		tfinal = XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION;
		break;
	    case XML_SCHEMAS_TYPE_FINAL_EXTENSION:
		tfinal = XML_SCHEMAS_FINAL_DEFAULT_EXTENSION;
		break;
	    case XML_SCHEMAS_TYPE_FINAL_LIST:
		tfinal = XML_SCHEMAS_FINAL_DEFAULT_LIST;
		break;
	    case XML_SCHEMAS_TYPE_FINAL_UNION:
		tfinal = XML_SCHEMAS_FINAL_DEFAULT_UNION;
		break;
	}
	tflags = schema->flags;
    }
    if (tflags & tfinal) 
	return (1);
    else
	return (0);
    
}

/**
 * xmlSchemaGetUnionSimpleTypeMemberTypes:
 * @type:  the Union Simple Type
 *
 * Returns a list of member types of @type if existing, 
 * returns NULL otherwise.
 */
static xmlSchemaTypeLinkPtr
xmlSchemaGetUnionSimpleTypeMemberTypes(xmlSchemaTypePtr type)
{
    while (type != NULL) {
	if (type->memberTypes != NULL)
	    return (type->memberTypes);
	else
	    type = type->baseType;
    }
    return (NULL);
}

/**
 * xmlSchemaGetListSimpleTypeItemType:
 * @type:  the simple type definition
 *
 * Returns the item type definition of the list simple type.
 */ 
static xmlSchemaTypePtr
xmlSchemaGetListSimpleTypeItemType(xmlSchemaTypePtr type)
{    
    if ((type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) == 0)
	return (NULL);
    /*
    * Note: In libxml2, the built-in types do not reflect 
    * the datatype hierarchy (yet?) - we have to treat them
    * in a special way.
    */
    if (type->type == XML_SCHEMA_TYPE_BASIC) 
	return (xmlSchemaGetBuiltInListSimpleTypeItemType(type));
    if (type->subtypes->type == XML_SCHEMA_TYPE_LIST)
	/* 1 If the <list> alternative is chosen, then the type 
	* definition ·resolved· to by the ·actual value· of the 
	* itemType [attribute] of <list>, if present, otherwise 
	* the type definition corresponding to the <simpleType> 
	* among the [children] of <list>.
	*/
	return (type->subtypes->subtypes);
    else {
	/* 2 If the <restriction> option is chosen, then the 
	* {item type definition} of the {base type definition}.
	*/    
	return (xmlSchemaGetListSimpleTypeItemType(type->baseType));
    }    
}

/**
 * xmlSchemaCheckCOSSTDerivedOK:
 * @type:  the derived simple type definition
 * @baseType:  the base type definition
 *
 * Checks wheter @type can be validly 
 * derived from @baseType.
 *
 * Returns 0 on success, an positive error code otherwise.
 */ 
static int
xmlSchemaCheckCOSSTDerivedOK(xmlSchemaPtr schema,
				     xmlSchemaTypePtr type,
				     xmlSchemaTypePtr baseType,
				     int subset)
{   
    /*
    * Schema Component Constraint: Type Derivation OK (Simple)
    *
    *
    * 1 They are the same type definition.
    * TODO: The identy check might have to be more complex than this.
    */
    if (type == baseType)
	return (0);    
    /* 
    * 2.1 restriction is not in the subset, or in the {final}
    * of its own {base type definition};
    */
    if ((subset & XML_SCHEMAS_TYPE_FINAL_RESTRICTION) ||
	(xmlSchemaTypeFinalContains(schema, 
	    type->baseType, XML_SCHEMAS_TYPE_FINAL_RESTRICTION))) {
	return (XML_SCHEMAP_COS_ST_DERIVED_OK_2_1); 
    }
    /* 2.2 */
    if (type->baseType == baseType) {
	/*
	* 2.2.1 D's ·base type definition· is B.
	*/
	return (0);
    }   
    /* 
    * 2.2.2 D's ·base type definition· is not the ·ur-type definition· 
    * and is validly derived from B given the subset, as defined by this 
    * constraint.    
    */
    if ((type->baseType != xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE)) &&
	(xmlSchemaCheckCOSSTDerivedOK(schema, type->baseType, baseType, subset) == 0)) {
	return (0);		
    } 
    /* 
    * 2.2.3 D's {variety} is list or union and B is the ·simple ur-type 
    * definition·.
    */
    if (((type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) ||
	(type->flags & XML_SCHEMAS_TYPE_VARIETY_UNION)) &&
	(baseType == xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE))) {
	return (0);
    }    
    /* 
    * 2.2.4 B's {variety} is union and D is validly derived from a type 
    * definition in B's {member type definitions} given the subset, as 
    * defined by this constraint.
    *
    * NOTE: This seems not to involve built-in types, since there is no
    * built-in Union Simple Type.
    */
    if (baseType->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) {
	xmlSchemaTypeLinkPtr cur;

	cur = baseType->memberTypes;
	while (cur != NULL) {
	    if (xmlSchemaCheckCOSSTDerivedOK(schema, type, 
		cur->type, subset) == 0)
		return (0);
	    cur = cur->next;
	}	
    }
    
    return (XML_SCHEMAP_COS_ST_DERIVED_OK_2_2);
}


/**
 * xmlSchemaCheckSTPropsCorrect:
 * @ctxt:  the schema parser context
 * @type:  the simple type definition
 *
 * Checks st-props-correct.
 *
 * Returns 0 if the properties are correct,
 * if not, a positive error code and -1 on internal
 * errors.
 */
static int
xmlSchemaCheckSTPropsCorrect(xmlSchemaParserCtxtPtr ctxt, 
			     xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr baseType = type->baseType, anySimpleType,
	anyType;
    xmlChar *str = NULL;

    /* STATE: error funcs converted. */
    /*
    * Schema Component Constraint: Simple Type Definition Properties Correct
    *
    * NOTE: This is somehow redundant, since we actually built a simple type
    * to have all the needed information; this acts as an self test.
    */
    anySimpleType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE);
    anyType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE);
    /* 
    * TODO: 1 The values of the properties of a simple type definition must be as 
    * described in the property tableau in Datatype definition, modulo the 
    * impact of Missing Sub-components (§5.3).
    */
    /* Base type: If the datatype has been ·derived· by ·restriction· 
    * then the Simple Type Definition component from which it is ·derived·, 
    * otherwise the Simple Type Definition for anySimpleType (§4.1.6). 
    */
    if (baseType == NULL) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_ST_PROPS_CORRECT_1,
	    NULL, type, NULL,	
	    "No base type existent", NULL);
	return (XML_SCHEMAP_ST_PROPS_CORRECT_1);
    }
    if ((baseType->type != XML_SCHEMA_TYPE_SIMPLE) &&
	((baseType->type != XML_SCHEMA_TYPE_BASIC) ||
	 (baseType == anyType))) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_ST_PROPS_CORRECT_1,
	    NULL, type, NULL,	
	    "The base type %s is not a simple type", 
	    xmlSchemaFormatItemForReport(&str, NULL, baseType, NULL, 1));
	FREE_AND_NULL(str)	
	return (XML_SCHEMAP_ST_PROPS_CORRECT_1);
    }
    if ((baseType != anySimpleType) &&
	(type->subtypes->type != XML_SCHEMA_TYPE_RESTRICTION)) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_ST_PROPS_CORRECT_1,
	    NULL, type, NULL,	
	    "A type, derived by list or union, must have"
	    "the simple ur-type definition as base type, not %s",
	    xmlSchemaFormatItemForReport(&str, NULL, baseType, NULL, 1));
	FREE_AND_NULL(str)
	return (XML_SCHEMAP_ST_PROPS_CORRECT_1);
    }
    /* 
    * Variety: One of {atomic, list, union}. 
    */
    if (((type->flags & XML_SCHEMAS_TYPE_VARIETY_ATOMIC) == 0) &&
	((type->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) == 0) &&
	((type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) == 0)) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_ST_PROPS_CORRECT_1,
	    NULL, type, NULL,	
	    "The variety is absent", NULL);
	return (XML_SCHEMAP_ST_PROPS_CORRECT_1);
    }
    /* TODO: Finish this. Hmm, is this finished? */

    /*
    * 2 All simple type definitions must be derived ultimately from the ·simple 
    * ur-type definition (so· circular definitions are disallowed). That is, it 
    * must be possible to reach a built-in primitive datatype or the ·simple 
    * ur-type definition· by repeatedly following the {base type definition}.
    */    
    baseType = type->baseType;
    while ((baseType != NULL) && (baseType->type != XML_SCHEMA_TYPE_BASIC)) {
	if (baseType->contentType == XML_SCHEMA_CONTENT_UNKNOWN)
	    xmlSchemaTypeFixup(baseType, ctxt,  NULL);
	if (baseType == anySimpleType)
	    break;
	else if (baseType == type) {
	    xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_ST_PROPS_CORRECT_2,
	    NULL, type, NULL,	
	    "The definition is circular", NULL);
	    return (XML_SCHEMAP_ST_PROPS_CORRECT_2);
	}	   
	baseType = baseType->baseType;
    }   
    /*
    * 3 The {final} of the {base type definition} must not contain restriction.
    */
    if (xmlSchemaTypeFinalContains(ctxt->schema, baseType, 
	XML_SCHEMAS_TYPE_FINAL_RESTRICTION)) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_ST_PROPS_CORRECT_3,
	    NULL, type, NULL,	
	    "The 'final' of its base type %s must not contain "
	    "'restriction'",
	    xmlSchemaFormatItemForReport(&str, NULL, baseType, NULL, 1));
	FREE_AND_NULL(str)	
	return (XML_SCHEMAP_ST_PROPS_CORRECT_3);
    }    
    return (0);
}

/**
 * xmlSchemaCheckDerivationValidSimpleRestriction:
 * @ctxt:  the schema parser context
 * @type:  the simple type definition
 *
 * Checks if the given @type (simpleType) is derived 
 * validly by restriction.
 *
 * Returns -1 on internal errors, 0 if the type is validly derived, 
 * a positive error code otherwise.
 */
static int
xmlSchemaCheckCOSSTRestricts(xmlSchemaParserCtxtPtr ctxt, 
			     xmlSchemaTypePtr type)
{    
    xmlChar *str = NULL;

    /* STATE: error funcs converted. */

    if (type->type != XML_SCHEMA_TYPE_SIMPLE) {
	xmlSchemaPErr(ctxt, type->node,
	    XML_ERR_INTERNAL_ERROR,
	    "xmlSchemaCheckDerivationValidSimpleRestriction: The given "
	    "type '%s' is not a user-derived simpleType.\n",
	    type->name, NULL);
	return (-1);
    }

    if (type->flags & XML_SCHEMAS_TYPE_VARIETY_ATOMIC) {
	xmlSchemaTypePtr primitive;
	/* 
	* 1.1 The {base type definition} must be an atomic simple 
	* type definition or a built-in primitive datatype.
	*/	
	if ((type->baseType->flags & XML_SCHEMAS_TYPE_VARIETY_ATOMIC) == 0) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_COS_ST_RESTRICTS_1_1,
		NULL, type, NULL,	
		"The base type %s is not an atomic simple type",
		xmlSchemaFormatItemForReport(&str, NULL, type->baseType, NULL, 1));
	    FREE_AND_NULL(str)
	    return (XML_SCHEMAP_COS_ST_RESTRICTS_1_1);
	}
	/* 1.2 The {final} of the {base type definition} must not contain 
	* restriction.
	*/
	/* OPTIMIZE TODO : This is already done in xmlSchemaCheckStPropsCorrect */
	if (xmlSchemaTypeFinalContains(ctxt->schema, type->baseType, 
	    XML_SCHEMAS_TYPE_FINAL_RESTRICTION)) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_COS_ST_RESTRICTS_1_2,
		NULL, type, NULL,	
		"The final of its base type %s must not contain 'restriction'",
		xmlSchemaFormatItemForReport(&str, NULL, type->baseType, NULL, 1));
	    FREE_AND_NULL(str)
	    return (XML_SCHEMAP_COS_ST_RESTRICTS_1_2);
	}
	
	/* 
	* 1.3.1 DF must be an allowed constraining facet for the {primitive
	* type definition}, as specified in the appropriate subsection of 3.2 
	* Primitive datatypes.
	*/
	if (type->facets != NULL) {
	    xmlSchemaFacetPtr facet;
	    int ok = 1;
	    
	    primitive = xmlSchemaGetPrimitiveType(type);
	    if (primitive == NULL) {
		xmlSchemaPErr(ctxt, type->node,
		    XML_ERR_INTERNAL_ERROR,
		    "xmlSchemaCheckDerivationValidSimpleRestriction: failed "
		    "to get primitive type of type '%s'.\n",
		    type->name, NULL);
		return (-1);
	    }	    
	    facet = type->facets;
	    do {
		if (xmlSchemaIsBuiltInTypeFacet(primitive, facet->type) == 0) {
		    ok = 0;
		    xmlSchemaPIllegalFacetAtomicErr(ctxt,
			XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1,
			NULL, type, primitive, facet);		    		    		    
		}
		facet = facet->next;
	    } while (facet != NULL);	    
	    if (ok == 0)
		return (XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1);	    
	}
	/*
	* TODO: 1.3.2 (facet derivation)
	*/
    } else if (type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) {
	xmlSchemaTypePtr itemType = NULL;

	itemType = xmlSchemaGetListSimpleTypeItemType(type);
	if (itemType == NULL) {
	    xmlSchemaPErr(ctxt, type->node,
		XML_ERR_INTERNAL_ERROR,
		"Internal error: xmlSchemaCheckDerivationValidSimpleRestriction: "
		"failed to evaluate the item type of type '%s'.\n",
		type->name, NULL);
	    return (-1);
	}
	/*
	* 2.1 The {item type definition} must have a {variety} of atomic or 
	* union (in which case all the {member type definitions} 
	* must be atomic).
	*/
	if (((itemType->flags & XML_SCHEMAS_TYPE_VARIETY_ATOMIC) == 0) &&  
	    ((itemType->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) == 0)) {	    
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_COS_ST_RESTRICTS_2_1,
		NULL, type, NULL,	
		"The item type %s must have a variety of atomic or union",
		xmlSchemaFormatItemForReport(&str, NULL, itemType, NULL, 1));
	    FREE_AND_NULL(str)	    
	    return (XML_SCHEMAP_COS_ST_RESTRICTS_2_1);
	} else if (itemType->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) {
	    xmlSchemaTypeLinkPtr member;

	    member = itemType->memberTypes;
	    while (member != NULL) {
		if ((member->type->flags & 
		    XML_SCHEMAS_TYPE_VARIETY_ATOMIC) == 0) {
		    xmlSchemaPCustomErr(ctxt,
			XML_SCHEMAP_COS_ST_RESTRICTS_2_1,
			NULL, type, NULL,	
			"The item type is a union type, but the "
			"member type %s of this item type is not atomic",
			xmlSchemaFormatItemForReport(&str, NULL, member->type, NULL, 1));
		    FREE_AND_NULL(str)		    
		    return (XML_SCHEMAP_COS_ST_RESTRICTS_2_1);
		}
		member = member->next;
	    }
	}
	
	if (type->baseType == xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE)) {
	    xmlSchemaFacetPtr facet;
	    /*
	    * This is the case if we have: <simpleType><list ..
	    */
	    /*
	    * 2.3.1 
	    * 2.3.1.1 The {final} of the {item type definition} must not 
	    * contain list.
	    */
	    if (xmlSchemaTypeFinalContains(ctxt->schema, 
		itemType, XML_SCHEMAS_TYPE_FINAL_LIST)) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1,
		    NULL, type, NULL,	
		    "The final of its item type %s must not contain 'list'",
		    xmlSchemaFormatItemForReport(&str, NULL, itemType, NULL, 1));
		FREE_AND_NULL(str)			
		return (XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1);
	    }
	    /*
	    * 2.3.1.2 The {facets} must only contain the whiteSpace
	    * facet component.
	    */
	    if (type->facets != NULL) {
		facet = type->facets;
		do {
		    if (facet->type != XML_SCHEMA_FACET_WHITESPACE) {
			xmlSchemaPIllegalFacetListUnionErr(ctxt,
			    XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2,
			    NULL, type, facet);
			return (XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2);
		    }
		    facet = facet->next;
		} while (facet != NULL);
	    }
	    /*
	    * TODO: Datatypes states: 
	    * A ·list· datatype can be ·derived· from an ·atomic· datatype 
	    * whose ·lexical space· allows space (such as string or anyURI)or 
	    * a ·union· datatype any of whose {member type definitions}'s 
	    * ·lexical space· allows space.
	    */
	} else {
	    /*
	    * This is the case if we have: <simpleType><restriction ...
	    */
	    /*
	    * 2.3.2 
	    * 2.3.2.1 The {base type definition} must have a {variety} of list.
	    */
	    if ((type->baseType->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) == 0) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1,
		    NULL, type, NULL,	
		    "The base type %s must be a list type",
		    xmlSchemaFormatItemForReport(&str, NULL, type->baseType, NULL, 1));
		FREE_AND_NULL(str)					
		return (XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1);
	    }
	    /*
	    * 2.3.2.2 The {final} of the {base type definition} must not
	    * contain restriction.
	    */
	    if (xmlSchemaTypeFinalContains(ctxt->schema, type->baseType,
		XML_SCHEMAS_TYPE_FINAL_RESTRICTION)) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2,
		    NULL, type, NULL,	
		    "The final of the base type %s must not contain 'restriction'",
		    xmlSchemaFormatItemForReport(&str, NULL, type->baseType, NULL, 1));
		FREE_AND_NULL(str)				
		return (XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2);
	    }
	    /*
	    * 2.3.2.3 The {item type definition} must be validly derived 
	    * from the {base type definition}'s {item type definition} given
	    * the empty set, as defined in Type Derivation OK (Simple) (§3.14.6).
	    */
	    {
		xmlSchemaTypePtr baseItemType;

		baseItemType = xmlSchemaGetListSimpleTypeItemType(type->baseType);
		if (baseItemType == NULL) {
		    xmlSchemaPErr(ctxt, type->node,
			XML_ERR_INTERNAL_ERROR,
			"xmlSchemaCheckDerivationValidSimpleRestriction: "
			"List simple type '%s': Failed to "
			"evaluate the item type of its base type '%s'.\n",
			type->name, type->baseType->name);
		    return (-1);
		}
		if ((itemType != baseItemType) &&
		    (xmlSchemaCheckCOSSTDerivedOK(ctxt->schema, itemType,
		    baseItemType, 0) != 0)) {
		    xmlChar *strBIT = NULL, *strBT = NULL;
		    xmlSchemaPCustomErrExt(ctxt,
			XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3,
			NULL, type, NULL,	
			"The item type %s is not validly derived from the "
			"item type %s of the base type %s",
			xmlSchemaFormatItemForReport(&str, NULL, itemType, NULL, 1),
			xmlSchemaFormatItemForReport(&strBIT, NULL, baseItemType, NULL, 1),
			xmlSchemaFormatItemForReport(&strBT, NULL, type->baseType, NULL, 1));

		    FREE_AND_NULL(str)
		    FREE_AND_NULL(strBIT)
		    FREE_AND_NULL(strBT)		    
		    return (XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3);
		}
	    }
	    
	    if (type->facets != NULL) {
		xmlSchemaFacetPtr facet;
		int ok = 1;
		/* 
		* 2.3.2.4 Only length, minLength, maxLength, whiteSpace, pattern 
		* and enumeration facet components are allowed among the {facets}.
		*/
		facet = type->facets;
		do {
		    switch (facet->type) {
			case XML_SCHEMA_FACET_LENGTH:
			case XML_SCHEMA_FACET_MINLENGTH:
			case XML_SCHEMA_FACET_MAXLENGTH:
			case XML_SCHEMA_FACET_WHITESPACE:
			    /*
			    * TODO: 2.5.1.2 List datatypes
			    * The value of ·whiteSpace· is fixed to the value collapse. 
			    */
			case XML_SCHEMA_FACET_PATTERN:
			case XML_SCHEMA_FACET_ENUMERATION:
			    break;
			default: {
			    xmlSchemaPIllegalFacetListUnionErr(ctxt,
				XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4,
				NULL, type, facet);
			    /*
			    * We could return, but it's nicer to report all 
			    * invalid facets.
			    */
			    ok = 0;			    
			}
		    }		    
		    facet = facet->next;
		} while (facet != NULL);
		if (ok == 0)
		    return (XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4);
		/*
		* TODO: 2.3.2.5 For each facet in the {facets} (call this DF), if there
		* is a facet of the same kind in the {facets} of the {base type 
		* definition} (call this BF),then the DF's {value} must be a valid 
		* restriction of BF's {value} as defined in [XML Schemas: Datatypes].
		*/
	    }	    
	    

	}
    } else if (type->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) {
	/*
	* 3.1 The {member type definitions} must all have {variety} of 
	* atomic or list.
	*/
	xmlSchemaTypeLinkPtr member;

	member = type->memberTypes;
	while (member != NULL) {
	    if (((member->type->flags & 
		XML_SCHEMAS_TYPE_VARIETY_ATOMIC) == 0) && 
		((member->type->flags & 
		XML_SCHEMAS_TYPE_VARIETY_LIST) == 0)) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_ST_RESTRICTS_3_1,
		    NULL, type, NULL,
		    "The member type %s is neither an atomic, nor a list type",
		    xmlSchemaFormatItemForReport(&str, NULL, member->type, NULL, 1));
		FREE_AND_NULL(str)
		return (XML_SCHEMAP_COS_ST_RESTRICTS_3_1);
	    }
	    member = member->next;
	}
	/*
	* 3.3.1 If the {base type definition} is the ·simple ur-type 
	* definition· 
	*/
	if (type->baseType == xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE)) {
	    /*
	    * 3.3.1.1 All of the {member type definitions} must have a 
	    * {final} which does not contain union.
	    */
	    member = type->memberTypes;
	    while (member != NULL) {
		if (xmlSchemaTypeFinalContains(ctxt->schema, member->type, 
		    XML_SCHEMAS_TYPE_FINAL_UNION)) {
		    xmlSchemaPCustomErr(ctxt,
			XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1,
			NULL, type, NULL,
			"The final of member type %s contains 'union'",
			xmlSchemaFormatItemForReport(&str, NULL, member->type, NULL, 1));
		    FREE_AND_NULL(str)		   
		    return (XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1);
		}
		member = member->next;
	    }
	    /*
	    * 3.3.1.2 The {facets} must be empty.
	    */
	    if (type->facetSet != NULL) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2,
		    NULL, type, NULL, 
		    "No facets allowed", NULL);
		return (XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2);
	    }
	} else {
	    /*
	    * 3.3.2.1 The {base type definition} must have a {variety} of union.
	    */
	    if ((type->baseType->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) == 0) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1,
		    NULL, type, NULL,
		    "The base type %s is not a union type",
		    xmlSchemaFormatItemForReport(&str, NULL, type->baseType, NULL, 1));
		FREE_AND_NULL(str)			
		return (XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1);
	    }
	    /*
	    * 3.3.2.2 The {final} of the {base type definition} must not contain restriction.
	    */
	    if (xmlSchemaTypeFinalContains(ctxt->schema, type->baseType, 
		XML_SCHEMAS_TYPE_FINAL_RESTRICTION)) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2,
		    NULL, type, NULL,
		    "The final of its base type %s must not contain 'restriction'",
		    xmlSchemaFormatItemForReport(&str, NULL, type->baseType, NULL, 1));
		FREE_AND_NULL(str)		
		return (XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2);
	    }
	    /*
	    * 3.3.2.3 The {member type definitions}, in order, must be validly 
	    * derived from the corresponding type definitions in the {base 
	    * type definition}'s {member type definitions} given the empty set, 
	    * as defined in Type Derivation OK (Simple) (§3.14.6).
	    */
	    {
		xmlSchemaTypeLinkPtr baseMember;

		/*
		* OPTIMIZE: if the type is restricting, it has no local defined 
		* member types and inherits the member types of the base type; 
		* thus a check for equality can be skipped.
		*/
		/*
		* TODO: Even worse: I cannot see a scenario where a restricting
		* union simple type can have other member types as the member 
		* types of it's base type. This check seems not necessary with
		* respect to the derivation process in libxml2.
		*/
		if (type->memberTypes != NULL) {
		    member = type->memberTypes;
		    baseMember = xmlSchemaGetUnionSimpleTypeMemberTypes(type->baseType);
		    if ((member == NULL) && (baseMember != NULL)) {		   
			xmlSchemaPErr(ctxt, type->node,
			    XML_SCHEMAP_INTERNAL,
			    "Internal error: "
			    "xmlSchemaCheckDerivationValidSimpleRestriction "
			    "(3.3.2.3), union simple type '%s', unequal number "
			    "of member types in the base type\n",
			    type->name, NULL);
		    }		
		    while (member != NULL) {
			if (baseMember == NULL) {
			    xmlSchemaPErr(ctxt, type->node,
				XML_SCHEMAP_INTERNAL,
				"Internal error: "
				"xmlSchemaCheckDerivationValidSimpleRestriction "
				"(3.3.2.3), union simple type '%s', unequal number "
				"of member types in the base type.\n",
				type->name, NULL);
			}
			if ((member->type != baseMember->type) &&
			    (xmlSchemaCheckCOSSTDerivedOK(ctxt->schema, 
			    member->type, baseMember->type, 0) != 0)) {
			    xmlChar *strBMT = NULL, *strBT = NULL;

			    xmlSchemaPCustomErrExt(ctxt,
				XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3,
				NULL, type, NULL,
				"The member type %s is not validly derived from its "
				"corresponding member type %s of the base type %s",
				xmlSchemaFormatItemForReport(&str, NULL, member->type, NULL, 1),
				xmlSchemaFormatItemForReport(&strBMT, NULL, baseMember->type, NULL, 1),
				xmlSchemaFormatItemForReport(&strBT, NULL, type->baseType, NULL, 1));
			    FREE_AND_NULL(str)
			    FREE_AND_NULL(strBMT)
			    FREE_AND_NULL(strBT)
			    return (XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3);
			}		
			member = member->next;
			baseMember = baseMember->next;
		    }
		}
	    }
	    /*
	    * 3.3.2.4 Only pattern and enumeration facet components are 
	    * allowed among the {facets}.
	    */	    
	    if (type->facets != NULL) {
		xmlSchemaFacetPtr facet;
		int ok = 1;

		facet = type->facets;
		do {
		    if ((facet->type != XML_SCHEMA_FACET_PATTERN) &&
			(facet->type != XML_SCHEMA_FACET_ENUMERATION)) {
			xmlSchemaPIllegalFacetListUnionErr(ctxt,
				XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4,
				NULL, type, facet);			
			ok = 0;			    
		    }		    
		    facet = facet->next;
		} while (facet != NULL);
		if (ok == 0)
		    return (XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4);
		    
	    }
	    /*
	    * TODO: 3.3.2.5 (facet derivation)
	    */
	}
    }

    return (0);
}

/**
 * xmlSchemaCheckSRCSimpleType:
 * @ctxt:  the schema parser context
 * @type:  the simple type definition
 *
 * Checks crc-simple-type constraints.
 *
 * Returns 0 if the constraints are satisfied,
 * if not a positive error code and -1 on internal
 * errors.
 */
static int
xmlSchemaCheckSRCSimpleType(xmlSchemaParserCtxtPtr ctxt,
			    xmlSchemaTypePtr type)
{   
    /*
    * NOTE: src-simple-type 2-4 are redundant, since the checks
    * were are done for the corresponding <restriction>, <list> and <union>
    * elements, but W3C wants a <simpleType> error as well, so it gets one.
    * Maby this can be skipped in the future, if we get sure it's not needed.
    */
    if (type->subtypes == NULL) {
	xmlSchemaPErr(ctxt, type->node,
		XML_SCHEMAP_INTERNAL,
		"Internal error: xmlSchemaCheckSRCSimpleType, "
		"no subtype on simple type '%s'.\n",
		type->name, NULL);
	return (-1);
    }
    /* 
    * src-simple-type.1 The corresponding simple type definition, if any,
    * must satisfy the conditions set out in Constraints on Simple Type 
    * Definition Schema Components (§3.14.6).    
    */
    if ((xmlSchemaCheckSTPropsCorrect(ctxt, type) != 0) ||
	(xmlSchemaCheckCOSSTRestricts(ctxt, type) != 0)) {
	/*
	* TODO: Removed this, since it got annoying to get an
	* extra error report, if anything failed until now.
	* Enable this if needed.
	*/
	/*
	xmlSchemaPErr(ctxt, type->node,
	    XML_SCHEMAP_SRC_SIMPLE_TYPE_1,
	    "Simple type '%s' does not satisfy the constraints "
	    "on simple type definitions.\n",
	    type->name, NULL);
	*/
	return (XML_SCHEMAP_SRC_SIMPLE_TYPE_1);
    }

    if (type->subtypes->type == XML_SCHEMA_TYPE_RESTRICTION) {
	/*
	* src-simple-type.2 If the <restriction> alternative is chosen, 
	* either it must have a base [attribute] or a <simpleType> among its 
	* [children], but not both.
	*/	
	/*
	* XML_SCHEMAP_SRC_SIMPLE_TYPE_2
	* NOTE: This was removed, since this will be already handled
	* in the parse function for <restriction>. 
	*/	
    } else if (type->subtypes->type == XML_SCHEMA_TYPE_LIST) {
	/* src-simple-type.3 If the <list> alternative is chosen, either it must have 
	* an itemType [attribute] or a <simpleType> among its [children], 
	* but not both.
	* NOTE: baseType is set to the local simple type definiton,
	* if existent, at parse time. This is a hack and not nice.
	*/
	/*
	* TODO: Remove this, and add the check to the parse function of <list>.
	*/
	if (((type->subtypes->base == NULL) && 
	     (type->baseType == NULL)) ||	      
	    ((type->subtypes->base != NULL) &&
	     (type->subtypes->baseType != NULL))) {
	    xmlSchemaPCustomErr(ctxt, 
		XML_SCHEMAP_SRC_SIMPLE_TYPE_3,
		NULL, type, NULL,
		"Either the attribute 'itemType' or the <simpleType> child "
		"must be present on the <list> child ", NULL);	    
	    return (XML_SCHEMAP_SRC_SIMPLE_TYPE_3);
	}
    

    } else if (type->subtypes->type == XML_SCHEMA_TYPE_UNION) {
	xmlSchemaTypeLinkPtr member;
	xmlSchemaTypePtr ancestor, anySimpleType;

	anySimpleType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE);

	/* src-simple-type.4 Circular union type definition is disallowed. That is, if 
	* the <union> alternative is chosen, there must not be any entries 
	* in the memberTypes [attribute] at any depth which resolve to the 
	* component corresponding to the <simpleType>.
	*/	
	member = type->memberTypes;
	while (member != NULL) {
	    ancestor = member->type;
	    while ((ancestor != NULL) && (ancestor->type != XML_SCHEMA_TYPE_BASIC)) {
		if (ancestor->contentType == XML_SCHEMA_CONTENT_UNKNOWN)
		    xmlSchemaTypeFixup(ancestor, ctxt,  NULL);
		if (ancestor == anySimpleType)
		    break;
		else if (ancestor == type) {
		    xmlSchemaPCustomErr(ctxt, 
			XML_SCHEMAP_SRC_SIMPLE_TYPE_4,
			NULL, type, NULL,
			"The definition is circular", NULL);
		    return (XML_SCHEMAP_SRC_SIMPLE_TYPE_4);
		} else if (ancestor->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) {
		    /*
		    * TODO, FIXME: Although a list simple type must not have a union ST
		    * type as item type, which in turn has a list ST as member 
		    * type, we will assume this here as well, since this check 
		    * was not yet performed.
		    */

		}
		ancestor = ancestor->baseType;
	    }   
	    member = member->next;
	}
    }

    return (0);
}

#if 0 /* Not yet used code for CT schema validation */
static int
xmlSchemaCheckCVCSimpleType(xmlSchemaValidCtxtPtr ctxt,
			    const xmlChar * value,
			    xmlSchemaTypePtr type,
			    int fireErrors)
{
    int ret;
    /*
    * 3.14.4 Simple Type Definition Validation Rules
    * Validation Rule: String Valid
    */
    /*
    * 1 It is schema-valid with respect to that definition as defined 
    * by Datatype Valid in [XML Schemas: Datatypes].
    */
    ret = xmlSchemaValidateSimpleTypeValue(ctxt, type, value, 
	fireErrors, 1, 1, 1);
    return (ret);
    /*
    * 2.1 If The definition is ENTITY or is validly derived from ENTITY given 
    * the empty set, as defined in Type Derivation OK (Simple) (§3.14.6), then
    * the string must be a ·declared entity name·.
    */
    /*
    * 2.2 If The definition is ENTITIES or is validly derived from ENTITIES 
    * given the empty set, as defined in Type Derivation OK (Simple) (§3.14.6), 
    * then every whitespace-delimited substring of the string must be a ·declared 
    * entity name·.
    */
    /*
    * 2.3 otherwise no further condition applies.
    */

    return (0);
}
#endif


static int
xmlSchemaCreatePCtxtOnVCtxt(xmlSchemaValidCtxtPtr vctxt)
{
   if (vctxt->pctxt == NULL) {
        vctxt->pctxt =xmlSchemaNewParserCtxtUseDict("*", vctxt->schema->dict);
	/* vctxt->pctxt = xmlSchemaNewParserCtxt("*"); */
	if (vctxt->pctxt == NULL) {
	    xmlSchemaVErr(vctxt, NULL,
		XML_SCHEMAV_INTERNAL,
		"Internal error: xmlSchemaCreatePCtxtOnVCtxt, "
		"failed to create a temp. parser context.\n",
		NULL, NULL);
	    return (-1);
	}
	/* TODO: Pass user data. */
	xmlSchemaSetParserErrors(vctxt->pctxt, vctxt->error, vctxt->warning, NULL);	
    }
    return (0);
}

static int
xmlSchemaCreateVCtxtOnPCtxt(xmlSchemaParserCtxtPtr ctxt)
{
   if (ctxt->vctxt == NULL) {
	ctxt->vctxt = xmlSchemaNewValidCtxt(NULL);
	if (ctxt->vctxt == NULL) {
	    xmlSchemaPErr(ctxt, NULL,
		XML_SCHEMAP_INTERNAL,
		"Internal error: xmlSchemaCreatePCtxtOnVCtxt, "
		"failed to create a temp. validation context.\n",
		NULL, NULL);
	    return (-1);
	}
	/* TODO: Pass user data. */
	xmlSchemaSetValidErrors(ctxt->vctxt, ctxt->error, ctxt->warning, NULL);	
    }
    return (0);
}

/**
 * xmlSchemaCheckCOSValidDefault:
 * @ctxt:  the schema parser context
 * @type:  the simple type definition
 * @value: the default value
 * @node: an optional node (the holder of the value)
 *
 * Checks the "cos-valid-default" constraints.
 *
 * Returns 0 if the constraints are satisfied,
 * if not, a positive error code and -1 on internal
 * errors.
 */
static int
xmlSchemaCheckCOSValidDefault(xmlSchemaParserCtxtPtr pctxt,
			      xmlSchemaValidCtxtPtr vctxt,
			      xmlSchemaTypePtr type,
			      const xmlChar *value,
			      xmlNodePtr node)
{   
    int ret = 0;

    /*
    * cos-valid-default:
    * Schema Component Constraint: Element Default Valid (Immediate)
    * For a string to be a valid default with respect to a type 
    * definition the appropriate case among the following must be true:
    */
    /*
    * NOTE: This has to work without a given node (the holder of the
    * value), since it should work on the component, i.e. an underlying
    * DOM must not be mandatory.
    */     
    if ((pctxt == NULL) || (vctxt == NULL)) {
	xmlSchemaPErr(pctxt, node,
	    XML_SCHEMAP_INTERNAL,
	    "Internal error: xmlSchemaCheckCOSValidDefault, "
	    "bad arguments: the parser and/or validation context is "
	    "missing.\n",
	    NULL, NULL);
	return (-1);	
    }       
    if IS_COMPLEX_TYPE(type) {
	/*
	* Complex type.
	*
	* 2.1 its {content type} must be a simple type definition or mixed.
	*/
	/* 
	* TODO: Adjust this when the content type will be computed 
	* correctly. 
	*/
	if ((type->contentType != XML_SCHEMA_CONTENT_SIMPLE) &&
	    (type->contentType != XML_SCHEMA_CONTENT_BASIC) &&
	    (type->contentType != XML_SCHEMA_CONTENT_MIXED)) {
	    xmlSchemaPSimpleTypeErr(pctxt, 
		XML_SCHEMAP_COS_VALID_DEFAULT_2_1,
		NULL, NULL, node,
		type, NULL, NULL,
		"If the type of a constraint value is complex, its content "
		"type must be mixed or a simple type",
		NULL, NULL);
	    return(XML_SCHEMAP_COS_VALID_DEFAULT_2_1);
	}
	if (type->contentType == XML_SCHEMA_CONTENT_MIXED) {
	    /*
	    * 2.2.2 If the {content type} is mixed, then the {content type}'s 
	    * particle must be ·emptiable· as defined by Particle Emptiable 
	    * (§3.9.6).
	    */
	    
	    /*
	    * URGENT TODO: Implement this.
	    */
	    return (0);
	}
    }	
    /*
    * 1 If the type definition is a simple type definition, then the string 
    * must be ·valid· with respect to that definition as defined by String 
    * Valid (§3.14.4).
    *
    * AND
    *
    * 2.2.1 If the {content type} is a simple type definition, then the 
    * string must be ·valid· with respect to that simple type definition 
    * as defined by String Valid (§3.14.4).
    */    
    vctxt->node = node;
    vctxt->cur = NULL;
    ret = xmlSchemaValidateSimpleTypeValue(vctxt, type, value, 1, 1, 1, 0);
    /* ret = xmlSchemaCheckCVCSimpleType(vctxt, elemDecl->value, typeDef, 0); */   
    if (ret < 0) {
	xmlSchemaPErr(pctxt, node,
	/* NOTNICE: error code: This function will be used during
	* schema construction and xsi:type validation.
	*/
	XML_SCHEMAP_INTERNAL,
	"Internal error: xmlSchemaCheckCOSValidDefault, "
	"while validating a value constaint value.\n",
	NULL, NULL);

    }     	    
    return (ret);
}

#if 0 /* Not yet used code for CT schema validation */
/**
 * xmlSchemaGetSTContentOfCT:
 * @ctxt:  the schema parser context
 * @type:  the complex type definition
 *
 *
 * Returns the corresponding simple type for the content of
 * the complex type.
 */
static xmlSchemaTypePtr
xmlSchemaGetSTContentOfCT(xmlSchemaParserCtxtPtr ctxt,
			xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr orig = type, anyType;

    anyType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE);
    while ((type != NULL) && (type != anyType) && 
	(type->type == XML_SCHEMA_TYPE_COMPLEX)) {
	if (type->type == XML_SCHEMA_TYPE_SIMPLE)
	    return(type);
	type = type->baseType;
    }
    xmlSchemaPCustomErr(ctxt,
	XML_SCHEMAP_INTERNAL,
	NULL, orig, NULL,
	"Internal error: xmlSchemaGetSTContentTypeOfCT, "
	"no simple type for the content of complex type '%s' could be "
	"computed", orig->name);
    return (NULL);
}




/**
 * xmlSchemaCheckCOSCTExtends:
 * @ctxt:  the schema parser context
 * @type:  the complex type definition
 *
 * Schema Component Constraint: Derivation Valid (Extension)
 *
 * Returns 0 if the constraints are satisfied, a positive
 * error code if not and -1 if an internal error occured.
 */
static int
xmlSchemaCheckCOSCTExtends(xmlSchemaParserCtxtPtr ctxt,
			   xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr base;
    /* 
    * 1 If the {base type definition} is a complex type definition, 
    * then all of the following must be true:
    */
    base = type->baseType;
    if (base == NULL) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_INTERNAL,
	    NULL, type, NULL,
	    "Internal error: xmlSchemaCheckCOSCTExtends, "
	    "the complex type '%s' has no base type", type->name);
	return (-1);
    }
    if (base->type == XML_SCHEMA_TYPE_COMPLEX) {
	/*
	* 1.1 The {final} of the {base type definition} must not 
	* contain extension.
	*/
	if (base->flags & XML_SCHEMAS_TYPE_FINAL_EXTENSION) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_COS_CT_EXTENDS_1_1,
		NULL, type, NULL,
		"The 'final' of the base type definition "
		"contains extension", NULL);
	    return (XML_SCHEMAP_COS_CT_EXTENDS_1_1);
	}
	/*
	* 1.2 Its {attribute uses} must be a subset of the {attribute uses} 
	* of the complex type definition itself, that is, for every attribute 
	* use in the {attribute uses} of the {base type definition}, there 
	* must be an attribute use in the {attribute uses} of the complex 
	* type definition itself whose {attribute declaration} has the same 
	* {name}, {target namespace} and {type definition} as its attribute 
	* declaration
	*
	* NOTE: This will be already satisfied by the way the attribute uses
	* are extended in xmlSchemaBuildAttributeValidation; thus this check
	* is not needed.
	*/

	/*
	* 1.3 If it has an {attribute wildcard}, the complex type definition 
	* must also have one, and the base type definition's {attribute 
	* wildcard}'s {namespace constraint} must be a subset of the complex 
	* type definition's {attribute wildcard}'s {namespace constraint}, 
	* as defined by Wildcard Subset (§3.10.6).
	*
	* This is already checked in xmlSchemaBuildAttributeValidation; thus 
	* this check is not needed.
	*/
	
	/*
	* 1.4 One of the following must be true:
	*
	* 1.4.1 The {content type} of the {base type definition} and the 
	* {content type} of the complex type definition itself must be the same 
	* simple type definition
	*/


	
    } else {
	/*
	* 2 If the {base type definition} is a simple type definition, 
	* then all of the following must be true:
	*/
	/*
	* 2.1 The {content type} must be the same simple type definition.
	*/
	/*
	* 2.2 The {final} of the {base type definition} must not contain 
	* extension
	*/
    }

}

static int
xmlSchemaCheckSRCCT(xmlSchemaParserCtxtPtr ctxt, 
		    xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr base, content;
    int OK = 0;

    /*
    * TODO: Adjust the error codes here, as I used
    * XML_SCHEMAP_SRC_CT_1 only yet.
    */
    /*
    * Schema Representation Constraint: 
    * Complex Type Definition Representation OK
    */
    base = type->baseType;
    if (base == NULL) {
	xmlSchemaPCustomErr(ctxt, XML_SCHEMAP_INTERNAL, NULL, type, NULL,
	    "Internal error: xmlSchemaCheckSRCCT, '%s', no base type", 
	    type->name);
	return (-1);
    }
    
    if (type->subtypes != NULL) {
	if (type->subtypes->type == XML_SCHEMA_TYPE_COMPLEX_CONTENT) {
	    if IS_COMPLEX_TYPE(base) {
		/*
		* 1 If the <complexContent> alternative is chosen, the type definition
		* ·resolved· to by the ·actual value· of the base [attribute] 
		* must be a complex type definition;
		*/
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_SRC_CT_1,
		    NULL, type, NULL,
		    "The base type is not a complex type", NULL);
		return (XML_SCHEMAP_SRC_CT_1);
	    }
	} else if (type->subtypes->type == XML_SCHEMA_TYPE_SIMPLE_CONTENT) {

	    if IS_SIMPLE_TYPE(base) {
		if (type->flags & 
		    XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION) {
		    /* 
		    * 2.1.3 only if the <extension> alternative is also 
		    * chosen, a simple type definition.
		    */
		    /* TODO: Change error code to ..._SRC_CT_2_1_3. */
		    xmlSchemaPCustomErr(ctxt,
			XML_SCHEMAP_SRC_CT_1,
			NULL, type, NULL,
			"A complex type (simple content) cannot restrict "
			"an other simple type",
			NULL);
		    return (XML_SCHEMAP_SRC_CT_1);
		}
		OK = 1;

	    } else { /* if IS_SIMPLE_TYPE(base) */
		if (base->contentType = XML_SCHEMA_CONTENT_MIXED) {
		    /*
		    * 2.1.2 only if the <restriction> alternative is also 
		    * chosen, a complex type definition whose {content type} 
		    * is mixed and a particle emptyable.
		    */	
		    /*
		    * FIXME TODO: Check for *empiable particle* is missing. 
		    */
		    if ((type->flags & 
			XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION) == 0) {
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_SRC_CT_1,
			    NULL, type, NULL,
			    "A complex type (simple content) cannot "
			    "extend an other complex type which has a "
			    "content type of: 'mixed' and emptiable particle",
			    NULL);
			return (XML_SCHEMAP_SRC_CT_1);
		    }
		    /*
		    * NOTE: This will be fired as well, if the base type
		    * is *'anyType'*.
		    * NOTE: type->subtypes->subtypes will be the 
		    * <restriction> item.
		    */
		    if (type->subtypes->subtypes == NULL) {
			/* Yes, this is paranoid programming. */
			xmlSchemaPCustomErr(ctxt, XML_SCHEMAP_INTERNAL, 
			    NULL, type, NULL,
			    "Internal error: xmlSchemaCheckSRCCT, "
			    "'%s', <simpleContent> has no <restriction>", 
			    type->name);
			return (-1);
		    }
		    /*
		    * 2.2 If clause 2.1.2 above is satisfied, then there 
		    * must be a <simpleType> among the [children] of 
		    * <restriction>.
		    */
    		    if (type->subtypes->subtypes->type !=
			XML_SCHEMA_TYPE_SIMPLE) {
			/* TODO: Change error code to ..._SRC_CT_2_2. */
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_SRC_CT_1,
			    NULL, type, NULL,
			    "A <simpleType> is expected among the children "
			    "of <restriction>", NULL);
			return (XML_SCHEMAP_SRC_CT_1);
		    } 
		    OK = 1;
		} else { /* if (base->contentType = XML_SCHEMA_CONTENT_MIXED)*/
		    /*
		    * 2.1.1 a complex type definition whose {content type} is a 
		    * simple type definition;
		    */
		    if (base->contentType == XML_SCHEMA_CONTENT_ELEMENTS) {
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_SRC_CT_1,
			    NULL, type, NULL,
			    "A complex type (simple content) cannot "
			    "be derived from the complex type '%s'", 
			    base->name);
			return (XML_SCHEMAP_SRC_CT_1);
		    }
		    content = base->contentTypeDef;
		    if (content == NULL) {
			xmlSchemaPCustomErr(ctxt, XML_SCHEMAP_INTERNAL, 
			    NULL, type, NULL,
			    "Internal error: xmlSchemaCheckSRCCT, "
			    "'%s', base type has no content type", 
			    type->name);
			return (-1);
		    }
		    if (content->type != XML_SCHEMA_TYPE_SIMPLE) {
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_SRC_CT_1,
			    NULL, type, NULL,
			    "A complex type (simple content) cannot "
			    "be derived from the complex type '%s'", 
			    base->name);
			return (XML_SCHEMAP_SRC_CT_1);
		    }
		}
	    } 
	} 	    	
    }
    /*
    * TODO: 3 The corresponding complex type definition component must 
    * satisfy the conditions set out in Constraints on Complex Type 
    * Definition Schema Components (§3.4.6);
    *
    * TODO: 4 If clause 2.2.1 or clause 2.2.2 in the correspondence specification 
    * above for {attribute wildcard} is satisfied, the intensional 
    * intersection must be expressible, as defined in Attribute Wildcard 
    * Intersection (§3.10.6).
    */

}
#endif

/**
 * xmlSchemaGroupDefFixup:
 * @typeDecl:  the schema model group definition
 * @ctxt:  the schema parser context
 *
 * Fixes model group definitions.
 */
static void
xmlSchemaGroupDefFixup(xmlSchemaTypePtr group,
		       xmlSchemaParserCtxtPtr ctxt, 
		       const xmlChar * name ATTRIBUTE_UNUSED)
{    
    group->contentType = XML_SCHEMA_CONTENT_ELEMENTS;
    if ((group->ref != NULL) && (group->subtypes == NULL)) {
	xmlSchemaTypePtr groupDef;
	/*
	* Resolve the reference.
	*/
	groupDef = xmlSchemaGetGroup(ctxt->schema, group->ref,
	    group->refNs);
	if (groupDef == NULL) {
	    xmlSchemaPResCompAttrErr(ctxt, 
		XML_SCHEMAP_SRC_RESOLVE, 
		NULL, group, NULL,
		"ref", group->ref, group->refNs, 
		XML_SCHEMA_TYPE_GROUP, NULL);
	    return;
	}
	group->subtypes = groupDef;
    }		
}

#if 0 /* Enable when the content type will be computed. */
static int
xmlSchemaComputeContentType(xmlSchemaParserCtxtPtr ctxt,
			xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr base, res = NULL;

    base = type->baseType;
    if (base == NULL) {
	xmlSchemaPCustomErr(ctxt,
	    XML_SCHEMAP_INTERNAL,
	    NULL, type, NULL,
	    "Internal error: xmlSchemaGetContentType, "
	    "the complex type '%s' has no base type", type->name);
	return (-1);
    }   
    if (IS_ANYTYPE(base) || (type->subtypes->type == 
	    XML_SCHEMA_TYPE_COMPLEX_CONTENT)) {
	xmlSchemaTypePtr start;
	/*
	* Effective 'mixed'.
	*/
	if (type->flags & XML_SCHEMAS_TYPE_MIXED)
	     type->contentType = XML_SCHEMA_CONTENT_MIXED;
	/*
	* Effective content.
	*/
	if (IS_ANYTYPE(base)) 
	    start = type;
	else
	    start = type->subtypes;
	 
    } else { /* if XML_SCHEMA_TYPE_COMPLEX_CONTENT */
	xmlSchemaTypePtr baseContentItem;

	/*
	* Complex type with simple content.
	*/
	if IS_COMPLEX_TYPE(base) {
	    if (type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION) {	
		/*
		* Summary: a complex type (simple content) can *restrict*
		* a complex type with the following content type:
		* 1. 'mixed' and an emptiable particle
		* 2. simple type
		*/
		if (base->contentType == XML_SCHEMA_CONTENT_MIXED) {
		    /*
		    * 2 if the {content type} of the base type is mixed and a 
		    * particle which is ·emptiable·, 
		    * [...] 
		    * then starting from the simple type definition 
		    * corresponding to the <simpleType> among the [children] 
		    * of <restriction> (**which must be present**)
		    *
		    * FIXME TODO: Handle "emptiable particle".
		    */
		    res = type->subtypes->subtypes;
		    if (res == NULL) {
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_INTERNAL,
			    NULL, type, NULL,
			    "Internal error: xmlSchemaGetContentType, "
			    "CT '%s' (restricting): <simpleContent> has no "
			    "<restriction>",
			    type->name);
			return (-1);
		    }

		    res->subtypes;
		    if (res == NULL) {
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_INTERNAL,
			    NULL, type, NULL,
			    "Internal error: xmlSchemaGetContentType, "
			    "CT '%s' (restricting): <restriction> has no "
			    "mandatory <simpleType>",
			    type->name);
			return (-1);
		    }
		} else {
		    baseContentItem = base->contentTypeDef;
		    if (baseContentItem == NULL) {
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_INTERNAL,
			    NULL, type, NULL,
			    "Internal error: xmlSchemaGetContentType, "
			    "CT '%s' (restricting), the base type has no "
			    "content type", type->name);
			return (-1);
		    }
		    if IS_SIMPLE_TYPE(baseContentItem) {
			/*
			* 1 If the base type is a complex type whose own 
		    	* {content type} is a simple type and the <restriction> 
			* alternative is chosen
			*/
			/* type->subtypes->subtypes will be the restriction item.*/
			res = type->subtypes->subtypes;
			if (res == NULL) {
			    xmlSchemaPCustomErr(ctxt,
				XML_SCHEMAP_INTERNAL,
				NULL, type, NULL,
				"Internal error: xmlSchemaGetContentType, "
				"CT '%s' (restricting): <simpleType> has no "
				"<restriction>", type->name);
			    return (-1);
			}
			/*
			* 1.1 the simple type definition corresponding to the 
			* <simpleType> among the [children] of <restriction>if 
			* there is one;
			*/
			res = res->subtypes;
			if (res == NULL) {
			    /*
			    * 1.2 otherwise the {content type} 
			    * of the base type .
			    */
			    res = baseContentItem;
			}
		    }
		}
		/*
		* SPECIAL TODO: If *restricting* the spec wants us to 
		* create an *additional* simple type which restricts the 
		* located simple type; we won't do this yet, and look how 
		* far we get with it.
		*/
	    } else { /* if XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION */
		/*
		* Summary: a complex type (simple content) can *extend*
		* only a complex base with a simple type as content.
		*/		
		/*
		* 3 If the type definition ·resolved· to by the ·actual 
		* value· of the base [attribute] is a complex type 
		* definition (whose own {content type} *must be* a simple 
		* type definition, see below) and the *<extension>* 
		* alternative is chosen, then the {content type} of that 
		* complex type definition;
		*/
		res = base->contentTypeDef;
		if (res == NULL) {
		    xmlSchemaPCustomErr(ctxt,
			XML_SCHEMAP_INTERNAL,
			NULL, type, NULL,
			"Internal error: xmlSchemaGetContentType, "
			"CT '%s' (extending), the base type has no content "
			"type", type->name);
		    return (-1);
		}		
		if (! IS_SIMPLE_TYPE(res)) {
		    xmlSchemaPCustomErr(ctxt,
			XML_SCHEMAP_INTERNAL,
			NULL, type, NULL,
			"Internal error: xmlSchemaGetContentType, "
			"CT '%s' (extending), the content type of the "
			"base is not a simple type", type->name);
		    return (-1);
		}		
	    }	    	
	} else /* if IS_COMPLEX_TYPE(base) */
	    if (type->flags & XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION) {
	    /*
	    * 4 otherwise (the type definition ·resolved· to by the 
	    * ·actual value· of the base [attribute] is a simple type 
	    * definition and the <extension> alternative is chosen), 
	    * then that simple type definition.
	    */
	    res = base;
	}	
	type->contentTypeDef = res;
	if (res == NULL) {
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_INTERNAL,
		NULL, type, NULL,
		"Internal error: xmlSchemaGetContentType, "
		"'%s', the content type could not be determined", 
		type->name);
	    return (-1);
	}

    }
    
}
#endif

/**
 * xmlSchemaTypeFixup:
 * @typeDecl:  the schema type definition
 * @ctxt:  the schema parser context
 *
 * Fixes the content model of the type.
 */
static void
xmlSchemaTypeFixup(xmlSchemaTypePtr item,
                   xmlSchemaParserCtxtPtr ctxt, const xmlChar * name)
{
    xmlSchemaTypePtr ctxtType;

    if (item == NULL)
        return;
    /*
    * Do not allow the following types to be typefixed, prior to
    * the corresponding simple/complex types.
    */
    if (ctxt->ctxtType == NULL) {
	switch (item->type) {
	    case XML_SCHEMA_TYPE_SIMPLE_CONTENT:
	    case XML_SCHEMA_TYPE_COMPLEX_CONTENT:
	    case XML_SCHEMA_TYPE_UNION:
	    case XML_SCHEMA_TYPE_RESTRICTION:
	    case XML_SCHEMA_TYPE_EXTENSION:	    
		return;
	    default:
	        break;
	}
    }
    if (name == NULL)
        name = item->name;
    if (item->contentType == XML_SCHEMA_CONTENT_UNKNOWN) {
        switch (item->type) {
            case XML_SCHEMA_TYPE_SIMPLE_CONTENT:{		    
		    if (item->subtypes != NULL) {
			if (item->subtypes->contentType ==
			    XML_SCHEMA_CONTENT_UNKNOWN) {
			    xmlSchemaTypeFixup(item->subtypes, ctxt,
				NULL);
			}
                        item->contentType =
			    XML_SCHEMA_CONTENT_SIMPLE;
                            /* item->subtypes->contentType; */
		    }
                    break;
                }
            case XML_SCHEMA_TYPE_RESTRICTION:{
		    xmlSchemaTypePtr base = NULL;

		    ctxt->ctxtType->flags |= 
			XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION;
		    if (item->baseType != NULL)
			base = item->baseType;
                    else if (item->base != NULL) {
                        base =
                            xmlSchemaGetType(ctxt->schema, item->base,
                                             item->baseNs);
                        if (base == NULL) {
			    xmlSchemaPResCompAttrErr(ctxt, 
				XML_SCHEMAP_SRC_RESOLVE, 
				NULL, NULL, 
				(xmlNodePtr) xmlSchemaGetPropNode(item->node, "base"),
				"base", item->base, item->baseNs,
				XML_SCHEMA_TYPE_BASIC, "type definition");			    
                        } else if (base->contentType == 
			    XML_SCHEMA_CONTENT_UNKNOWN) {
			    xmlSchemaTypeFixup(base, ctxt, NULL);
                        }			
                    }	
		    ctxt->ctxtType->baseType = base;
		    if (ctxt->ctxtType->type == XML_SCHEMA_TYPE_COMPLEX) {
			/*
			* ComplexType restriction.
			*/			
			/*
			* Content type.
			*/
			if (item->subtypes == NULL)
			    /* 1.1.1 */
			    item->contentType = XML_SCHEMA_CONTENT_EMPTY;
			else if ((item->subtypes->subtypes == NULL) &&
			    ((item->subtypes->type ==
			    XML_SCHEMA_TYPE_ALL)
			    || (item->subtypes->type ==
			    XML_SCHEMA_TYPE_SEQUENCE)))
			    /* 1.1.2 */
			    item->contentType = XML_SCHEMA_CONTENT_EMPTY;
			else if ((item->subtypes->type ==
			    XML_SCHEMA_TYPE_CHOICE)
			    && (item->subtypes->subtypes == NULL))
			    /* 1.1.3 */
			    item->contentType = XML_SCHEMA_CONTENT_EMPTY;
			else {
			    /* 1.2 and 2.X are applied at the other layer */
			    item->contentType =
				XML_SCHEMA_CONTENT_ELEMENTS;
			}
		    } else {	
			/*
			* SimpleType restriction.
			*/
			/* TODO: Nothing? */
		    }
                    break;
                }
            case XML_SCHEMA_TYPE_EXTENSION:{
		    xmlSchemaTypePtr base = NULL;
		    xmlSchemaContentType explicitContentType;
		    
		    /*
		    * An extension does exist on a complexType only.
		    */
		    ctxt->ctxtType->flags |= 
			XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION;
		    if (item->recurse) {
			/* TODO: The word "recursive" should be changed to "circular" here. */
			xmlSchemaPCustomErr(ctxt,
			    XML_SCHEMAP_UNKNOWN_BASE_TYPE,
			    NULL, item, item->node,	
			    "This item is circular", NULL);
                        return;
		    }
		    if (item->base != NULL) {                        
                        base =
                            xmlSchemaGetType(ctxt->schema, item->base,
                                             item->baseNs);
                        if (base == NULL) {
			    xmlSchemaPResCompAttrErr(ctxt, 
				XML_SCHEMAP_SRC_RESOLVE, 
				NULL, item, item->node,
				"base", item->base, item->baseNs,
				XML_SCHEMA_TYPE_BASIC, "type definition");				   
                        } else if (base->contentType == 
			    XML_SCHEMA_CONTENT_UNKNOWN) {
			    item->recurse = 1;
			    xmlSchemaTypeFixup(base, ctxt, NULL);
			    item->recurse = 0;
                        }
			/*
			* The type definition ·resolved· to by the ·actual 
			* value· of the base [attribute]
			*/
			ctxt->ctxtType->baseType = base;
			/*
			* TODO: This one is still needed for computation of
			* the content model by xmlSchemaBuildAContentModel.
			* Try to get rid of it.
			*/
			item->baseType = base;			
                    }
		    if ((item->subtypes != NULL) &&
			(item->subtypes->contentType == XML_SCHEMA_CONTENT_UNKNOWN))
                        xmlSchemaTypeFixup(item->subtypes, ctxt, NULL);	    
		    
		    explicitContentType = XML_SCHEMA_CONTENT_ELEMENTS;
		    if (item->subtypes == NULL)
			/* 1.1.1 */
			explicitContentType = XML_SCHEMA_CONTENT_EMPTY;
		    else if ((item->subtypes->subtypes == NULL) &&
			((item->subtypes->type ==
			XML_SCHEMA_TYPE_ALL)
			|| (item->subtypes->type ==
			XML_SCHEMA_TYPE_SEQUENCE)))
			/* 1.1.2 */
			explicitContentType = XML_SCHEMA_CONTENT_EMPTY;
		    else if ((item->subtypes->type ==
			XML_SCHEMA_TYPE_CHOICE)
			&& (item->subtypes->subtypes == NULL))
			/* 1.1.3 */
			explicitContentType = XML_SCHEMA_CONTENT_EMPTY;
		    if (base != NULL) {
			/* It will be reported later, if the base is missing. */			    
			if (explicitContentType == XML_SCHEMA_CONTENT_EMPTY) {
			    /* 2.1 */
			    item->contentType = base->contentType;
			} else if (base->contentType ==
			    XML_SCHEMA_CONTENT_EMPTY) {
			    /* 2.2 imbitable ! */
			    item->contentType =
				XML_SCHEMA_CONTENT_ELEMENTS;
			} else {
			    /* 2.3 imbitable pareil ! */
			    item->contentType =
				XML_SCHEMA_CONTENT_ELEMENTS;
			}
		    }		                
                    break;
                }
            case XML_SCHEMA_TYPE_COMPLEX:{
		    ctxtType = ctxt->ctxtType;
		    ctxt->ctxtType = item;
		    /*
		    * Start with an empty content-type type.
		    */
		    if (item->subtypes == NULL)
			item->contentType = XML_SCHEMA_CONTENT_EMPTY;

		    if ((item->subtypes == NULL) || 
			((item->subtypes->type != 
			XML_SCHEMA_TYPE_SIMPLE_CONTENT) && 
			(item->subtypes->type != 
			XML_SCHEMA_TYPE_COMPLEX_CONTENT))) {
			/* 
			* This case is understood as shorthand for complex 
			* content restricting the ur-type definition, and 
			* the details of the mappings should be modified as 
			* necessary.
			*/			
			item->baseType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE);
			item->flags |= 
			    XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION;
			/*
			* Assume that we inherit the content-type type 
			* from 'anyType', which is 'mixed' and a particle
			* emptiable.
			*/
			item->contentType = item->baseType->contentType;
		    }
		    /*
		    * Fixup the sub components.
		    */
		    if ((item->subtypes != NULL) &&
			(item->subtypes->contentType ==
			XML_SCHEMA_CONTENT_UNKNOWN)) {			    
			xmlSchemaTypeFixup(item->subtypes, ctxt, NULL);
		    }	
		    if (item->flags & XML_SCHEMAS_TYPE_MIXED) {
			item->contentType = XML_SCHEMA_CONTENT_MIXED;			
		    } else if (item->subtypes != NULL) {
			/*
			* Use the content-type type of the model groups
			* defined, if 'mixed' is not set. If 'mixed' is set
			* it will expand the content-type by allowing character
			* content to appear.
			*/
			item->contentType =
			    item->subtypes->contentType;
		    }
		    xmlSchemaBuildAttributeValidation(ctxt, item);
		    xmlSchemaCheckDefaults(item, ctxt, item->name);
		    ctxt->ctxtType = ctxtType;
                    break;
                }
            case XML_SCHEMA_TYPE_COMPLEX_CONTENT:{
                    if (item->subtypes == NULL) {
                        item->contentType = XML_SCHEMA_CONTENT_EMPTY;
                        if (item->flags & XML_SCHEMAS_TYPE_MIXED)
                            item->contentType =
                                XML_SCHEMA_CONTENT_MIXED;
                    } else {
                        if (item->flags & XML_SCHEMAS_TYPE_MIXED) {
                            item->contentType =
                                XML_SCHEMA_CONTENT_MIXED;
                        } else {
                            xmlSchemaTypeFixup(item->subtypes, ctxt,
                                               NULL);
                            if (item->subtypes != NULL)
                                item->contentType =
                                    item->subtypes->contentType;
                        }
			/* 
			 * Removed due to implementation of the build of attribute uses. 
			 */
			/*
			if (item->attributes == NULL)
			    item->attributes =
			        item->subtypes->attributes;
			*/
                    }
                    break;
                }
	    case XML_SCHEMA_TYPE_SIMPLE:
		/*
		* Simple Type Definition Schema Component
		*
		*/
		ctxtType = ctxt->ctxtType;		
		item->contentType = XML_SCHEMA_CONTENT_SIMPLE;
		if (item->subtypes->contentType == 
		    XML_SCHEMA_CONTENT_UNKNOWN) {
		    ctxt->ctxtType = item;
		    xmlSchemaTypeFixup(item->subtypes, ctxt, NULL);
		}
		/* Fixup base type */		
		if ((item->baseType != NULL) && 
		    (item->baseType->contentType ==
		    XML_SCHEMA_CONTENT_UNKNOWN)) {
		    /* OPTIMIZE: Actually this one will never by hit, since
		    * the base type is already type-fixed in <restriction>.
		    */
		    ctxt->ctxtType = item;
		    xmlSchemaTypeFixup(item->baseType, ctxt, NULL);
		}
		/* Base type: 
		* 2 If the <list> or <union> alternative is chosen, 
		* then the ·simple ur-type definition·.
		*/
		if (item->subtypes->type ==
		    XML_SCHEMA_TYPE_LIST) {
		    item->baseType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE);
		    item->flags |= XML_SCHEMAS_TYPE_VARIETY_LIST;		    
		} else if (item->subtypes->type ==
		    XML_SCHEMA_TYPE_UNION) {
		    item->baseType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE);
		    item->flags |= XML_SCHEMAS_TYPE_VARIETY_UNION;
		} else if (item->subtypes->type ==
		    XML_SCHEMA_TYPE_RESTRICTION) {
		    xmlSchemaFacetLinkPtr facet, cur, last = NULL;
		    		    	    		   
		    /* 
		    * Variety
		    * If the <restriction> alternative is chosen, then the 
		    * {variety} of the {base type definition}.
		    */	
		    if (item->baseType != NULL) {
			if (item->baseType->flags & 
			    XML_SCHEMAS_TYPE_VARIETY_ATOMIC)
			    item->flags |= XML_SCHEMAS_TYPE_VARIETY_ATOMIC;
			else if (item->baseType->flags & 
			    XML_SCHEMAS_TYPE_VARIETY_LIST)
			    item->flags |= XML_SCHEMAS_TYPE_VARIETY_LIST;
			else if (item->baseType->flags & 
			    XML_SCHEMAS_TYPE_VARIETY_UNION)
			    item->flags |= XML_SCHEMAS_TYPE_VARIETY_UNION;		    		    		   
			/*
			* Schema Component Constraint: Simple Type Restriction 
			* (Facets)
			* NOTE: Satisfaction of 1 and 2 arise from the fixup 
			* applied beforehand.
			*			    
			* 3 The {facets} of R are the union of S and the {facets} 
			* of B, eliminating duplicates. To eliminate duplicates, 
			* when a facet of the same kind occurs in both S and the 
			* {facets} of B, the one in the {facets} of B is not 
			* included, with the exception of enumeration and pattern 
			* facets, for which multiple occurrences with distinct values 
			* are allowed.
			*/
			if (item->baseType->facetSet != NULL) {
			    last = item->facetSet;
			    if (last != NULL)
				while (last->next != NULL)
				    last = last->next;
				cur = item->baseType->facetSet;
				for (; cur != NULL; cur = cur->next) {
				    /* 
				    * Base patterns won't be add here:
				    * they are ORed in a type and
				    * ANDed in derived types. This will
				    * happed at validation level by
				    * walking the base axis of the type.
				    */
				    if (cur->facet->type == 
					XML_SCHEMA_FACET_PATTERN) 
					continue;
				    facet = NULL;
				    if ((item->facetSet != NULL) &&
					(cur->facet->type != 
					XML_SCHEMA_FACET_PATTERN) &&
					(cur->facet->type != 
					XML_SCHEMA_FACET_ENUMERATION)) {				
					facet = item->facetSet;
					do {
					    if (cur->facet->type == 
						facet->facet->type) 
						break;
					    facet = facet->next;
					} while (facet != NULL);
				    }
				    if (facet == NULL) {
					facet = (xmlSchemaFacetLinkPtr) 
					    xmlMalloc(sizeof(xmlSchemaFacetLink));
					if (facet == NULL) {
					    xmlSchemaPErrMemory(ctxt, 
						"fixing simpleType", NULL);
					    return;
					}
					facet->facet = cur->facet;
					facet->next = NULL;
					if (last == NULL)
					    item->facetSet = facet;		    
					else 
					    last->next = facet;
					last = facet;				
				    }				    
				}
			}
		    }
		}	
		/*
		* Check constraints.
		*/
		xmlSchemaCheckSRCSimpleType(ctxt, item);
		xmlSchemaCheckDefaults(item, ctxt, item->name);
		ctxt->ctxtType = ctxtType;
		break;
            case XML_SCHEMA_TYPE_SEQUENCE:            
            case XML_SCHEMA_TYPE_ALL:
            case XML_SCHEMA_TYPE_CHOICE:
                item->contentType = XML_SCHEMA_CONTENT_ELEMENTS;
                break;
	    case XML_SCHEMA_TYPE_GROUP:
		/*
		* TODO: Handling was moved to xmlSchemaGroupDefFixup.
		*/
		break;
            case XML_SCHEMA_TYPE_LIST: 
		xmlSchemaParseListRefFixup(item, ctxt);
		item->contentType = XML_SCHEMA_CONTENT_SIMPLE;
		break;
            case XML_SCHEMA_TYPE_UNION:		
		xmlSchemaParseUnionRefCheck(item, ctxt);
		item->contentType = XML_SCHEMA_CONTENT_SIMPLE;
		break;
            case XML_SCHEMA_TYPE_BASIC:
            case XML_SCHEMA_TYPE_ANY:
            case XML_SCHEMA_TYPE_FACET:
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
                item->contentType = XML_SCHEMA_CONTENT_SIMPLE;
		if (item->subtypes != NULL)
		    xmlSchemaTypeFixup(item->subtypes, ctxt, NULL);
                break;
        }
    }
#ifdef DEBUG_TYPE
    if (item->node != NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "Type of %s : %s:%d :", name,
                        item->node->doc->URL,
                        xmlGetLineNo(item->node));
    } else {
        xmlGenericError(xmlGenericErrorContext, "Type of %s :", name);
    }
    switch (item->contentType) {
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
	/* Removed, since not used. */
	/*
        case XML_SCHEMA_CONTENT_MIXED_OR_ELEMENTS:
            xmlGenericError(xmlGenericErrorContext, "mixed or elems\n");
            break;
	*/
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
    xmlSchemaTypePtr nonNegativeIntegerType = NULL;
    int ret = 0, reuseValCtxt = 0;

    if ((facet == NULL) || (typeDecl == NULL))
        return(-1);
    /* 
    * TODO: will the parser context be given if used from
    * the relaxNG module?
    */

    if (nonNegativeIntegerType == NULL) {
        nonNegativeIntegerType =
            xmlSchemaGetBuiltInType(XML_SCHEMAS_NNINTEGER);
    }
    switch (facet->type) {
        case XML_SCHEMA_FACET_MININCLUSIVE:
        case XML_SCHEMA_FACET_MINEXCLUSIVE:
        case XML_SCHEMA_FACET_MAXINCLUSIVE:
        case XML_SCHEMA_FACET_MAXEXCLUSIVE:
	case XML_SCHEMA_FACET_ENUMERATION: {
                /*
                 * Okay we need to validate the value
                 * at that point.
                 */
                xmlSchemaValidCtxtPtr vctxt;
		xmlSchemaTypePtr base;

		/* 4.3.5.5 Constraints on enumeration Schema Components
		* Schema Component Constraint: enumeration valid restriction
		* It is an ·error· if any member of {value} is not in the 
		* ·value space· of {base type definition}. 
		*
		* minInclusive, maxInclusive, minExclusive, maxExclusive:
		* The value ·must· be in the 
		* ·value space· of the ·base type·. 
		*/
		/*
		* This function is intended to deliver a compiled value
		* on the facet. In XML Schemas the type holding a facet, 
		* cannot be a built-in type. Thus to ensure that other API
		* calls (relaxng) do work, if the given type is a built-in 
		* type, we will assume that the given built-in type *is
		* already* the base type.		
		*/
		if (typeDecl->type != XML_SCHEMA_TYPE_BASIC) {
		    base = typeDecl->baseType;
		    if (base == NULL) {
			xmlSchemaPErr(ctxt, typeDecl->node,
			    XML_SCHEMAP_INTERNAL,
			    "Internal error: xmlSchemaCheckFacet, "
			    "the type '%s' has no base type.\n",
			    typeDecl->name, NULL);
			return (-1);
		    }		
		} else
		    base = typeDecl;
		/*
		* This avoids perseverative creation of the 
		* validation context if a parser context is
		* used.
		*/
		if (ctxt != NULL) {
		    reuseValCtxt = 1;
		    if (ctxt->vctxt == NULL) {
			if (xmlSchemaCreateVCtxtOnPCtxt(ctxt) == -1)
			    return (-1);
		    }
		    vctxt = ctxt->vctxt;
		} else {
		    vctxt = xmlSchemaNewValidCtxt(NULL);
		    if (vctxt == NULL) {
			xmlSchemaPErr(ctxt, typeDecl->node,
			    XML_SCHEMAP_INTERNAL,
			    "Internal error: xmlSchemaCheckFacet, "
			    "creating a new validation context.\n",
			    NULL, NULL);
			return (-1);	
		    }
		}
	                
		vctxt->node = facet->node;
		vctxt->cur = NULL;
		/*
		* NOTE: This call does not check the content nodes, 
		* since they are not available:
		* facet->node is just the node holding the facet 
		* definition, *not* the attribute holding the *value* 
		* of the facet.
		*/
		ret = xmlSchemaValidateSimpleTypeValue(vctxt, base, 
		    facet->value, 0, 1, 1, 0);
		facet->val = vctxt->value;
		vctxt->value = NULL;		
                if (ret > 0) {
                    /* error code */
                    if (ctxt != NULL) {
                        xmlSchemaPErrExt(ctxt, facet->node,
			    XML_SCHEMAP_INVALID_FACET, 
			    NULL, NULL, NULL,
			    "Type definition '%s': The value '%s' of the "
			    "facet '%s' is not valid.\n",
			    name, facet->value, 
			    BAD_CAST xmlSchemaFacetTypeToString(facet->type), 
			    NULL, NULL);
                    }
                    ret = -1;
                } else if (ret < 0) {
		    xmlSchemaPErrExt(ctxt, facet->node,
			XML_SCHEMAP_INTERNAL,
			NULL, NULL, NULL,
			"Internal error: xmlSchemaCheckFacet, "
			"failed to validate the value '%s' name of the "
			"facet '%s' against the base type '%s'.\n",
			facet->value, 
			BAD_CAST xmlSchemaFacetTypeToString(facet->type),
			base->name, NULL, NULL); 
		    ret = -1;
		}   
		if (reuseValCtxt == 0)
		    xmlSchemaFreeValidCtxt(vctxt);
                break;
            }
        case XML_SCHEMA_FACET_PATTERN:
            facet->regexp = xmlRegexpCompile(facet->value);
            if (facet->regexp == NULL) {
		xmlSchemaPErr(ctxt, typeDecl->node,
		    XML_SCHEMAP_REGEXP_INVALID,
		    "Type definition '%s': The value '%s' of the "
		    "facet 'pattern' is not valid.\n",
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
                                                    &(facet->val));
                if (tmp != 0) {
                    /* error code */
                    if (ctxt != NULL) {
                        xmlSchemaPErrExt(ctxt, facet->node,
			    XML_SCHEMAP_INVALID_FACET_VALUE,
			    NULL, NULL, NULL,
			    "Type definition '%s': The value '%s' of the "
			    "facet '%s' is not valid.\n",
			    name, facet->value, 
			    BAD_CAST xmlSchemaFacetTypeToString(facet->type),
			    NULL, NULL);
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
			    "Type definition '%s': The value '%s' of the "
			    "facet 'whiteSpace' is not valid.\n",
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
    /*
    * NOTE: It is intended to use the facets list, instead
    * of facetSet.
    */
    if (typeDecl->facets != NULL) {
	xmlSchemaFacetPtr facet = typeDecl->facets;
	
	while (facet != NULL) {
	    xmlSchemaCheckFacet(facet, typeDecl, ctxt, name);
	    facet = facet->next;
	}
    }    
}

/**
 * xmlSchemaGetCircModelGrDefRef:
 * @ctxtGr: the searched model group
 * @list: the list of model groups to be processed
 *
 * This one is intended to be used by
 * xmlSchemaCheckGroupDefCircular only.
 *
 * Returns the circular model group definition reference, otherwise NULL.
 */
static xmlSchemaTypePtr
xmlSchemaGetCircModelGrDefRef(xmlSchemaTypePtr ctxtGrDef,
			  xmlSchemaTypePtr gr)
{    
    xmlSchemaTypePtr circ = NULL;
    int marked;
    /*
    * We will search for an model group reference which
    * references the context model group definition.
    */        
    while (gr != NULL) {
	if (((gr->type == XML_SCHEMA_TYPE_GROUP) ||
	     (gr->type == XML_SCHEMA_TYPE_ALL) ||
	     (gr->type == XML_SCHEMA_TYPE_SEQUENCE) ||
	     (gr->type == XML_SCHEMA_TYPE_CHOICE)) &&
	    (gr->subtypes != NULL)) {		 
	    marked = 0;
	    if ((gr->type == XML_SCHEMA_TYPE_GROUP) &&
		(gr->ref != NULL)) {
		if (gr->subtypes == ctxtGrDef)
		    return (gr);
		else if (gr->subtypes->flags & 
		    XML_SCHEMAS_TYPE_MARKED) {
		    gr = gr->next;
		    continue;
		} else {
		    /*
		    * Mark to avoid infinite recursion on
		    * circular references not yet examined.
		    */
		    gr->subtypes->flags |= XML_SCHEMAS_TYPE_MARKED;
		    marked = 1;
		} 
		if (gr->subtypes->subtypes != NULL)
		    circ = xmlSchemaGetCircModelGrDefRef(ctxtGrDef, 
			gr->subtypes->subtypes);
		    /*
		    * Unmark the visited model group definition.
		*/
		if (marked)
		    gr->subtypes->flags ^= XML_SCHEMAS_TYPE_MARKED;
		if (circ != NULL)
		    return (circ);
	    } else {
		circ = xmlSchemaGetCircModelGrDefRef(ctxtGrDef, 
		    (xmlSchemaTypePtr) gr->subtypes);
		if (circ != NULL)
		    return (circ);
	    }

	}
	gr = gr->next;
    }
    return (NULL);
}

/**
 * xmlSchemaCheckGroupDefCircular:
 * attrGr:  the model group definition
 * @ctxt:  the parser context
 * @name:  the name
 *
 * Checks for circular references to model group definitions.
 */
static void
xmlSchemaCheckGroupDefCircular(xmlSchemaTypePtr modelGrDef,
			    xmlSchemaParserCtxtPtr ctxt, 
			    const xmlChar * name ATTRIBUTE_UNUSED)
{    
    /*
    * Schema Component Constraint: Model Group Correct
    * 2 Circular groups are disallowed. That is, within the {particles} 
    * of a group there must not be at any depth a particle whose {term} 
    * is the group itself.
    */
    /*
    * NOTE: "gr->subtypes" holds the referenced group.
    */
    if ((modelGrDef->type != XML_SCHEMA_TYPE_GROUP) || 
	((modelGrDef->flags & XML_SCHEMAS_TYPE_GLOBAL) == 0) ||
	(modelGrDef->subtypes == NULL))
	return;
    else {
	xmlSchemaTypePtr circ;

	circ = xmlSchemaGetCircModelGrDefRef(modelGrDef, modelGrDef->subtypes);
	if (circ != NULL) {
	    /*
	    * TODO: Report the referenced attr group as QName.
	    */
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_MG_PROPS_CORRECT_2,
		NULL, NULL, circ->node,
		"Circular reference to the model group definition '%s' "
		"defined", modelGrDef->name);
	    /*
	    * NOTE: We will cut the reference to avoid further
	    * confusion of the processor.
	    * TODO: SPEC: Does the spec define how to process here?
	    */
	    circ->subtypes = NULL;
	}
    }
}


/**
 * xmlSchemaGetCircAttrGrRef:
 * @ctxtGr: the searched attribute group
 * @attr: the current attribute list to be processed
 *
 * This one is intended to be used by
 * xmlSchemaCheckSRCAttributeGroupCircular only.
 *
 * Returns the circular attribute grou reference, otherwise NULL.
 */
static xmlSchemaAttributeGroupPtr
xmlSchemaGetCircAttrGrRef(xmlSchemaAttributeGroupPtr ctxtGr,
			  xmlSchemaAttributePtr attr)
{    
    xmlSchemaAttributeGroupPtr circ = NULL, gr;
    int marked;
    /*
    * We will search for an attribute group reference which
    * references the context attribute group.
    */    	
    while (attr != NULL) {
	marked = 0;
	if (attr->type == XML_SCHEMA_TYPE_ATTRIBUTEGROUP) {
	    gr = (xmlSchemaAttributeGroupPtr) attr;
	    if (gr->refItem != NULL)  {
		if (gr->refItem == ctxtGr)
		    return (gr);
		else if (gr->refItem->flags & 
		    XML_SCHEMAS_ATTRGROUP_MARKED) {
		    attr = attr->next;
		    continue;
		} else {
		    /*
		    * Mark as visited to avoid infinite recursion on
		    * circular references not yet examined.
		    */
		    gr->refItem->flags |= XML_SCHEMAS_ATTRGROUP_MARKED;
		    marked = 1;
		}
	    }
	    if (gr->attributes != NULL)
		circ = xmlSchemaGetCircAttrGrRef(ctxtGr, gr->attributes);
	    /*
	    * Unmark the visited group's attributes.
	    */
	    if (marked)
		gr->refItem->flags ^= XML_SCHEMAS_ATTRGROUP_MARKED;
	    if (circ != NULL)
		return (circ);
	}
	attr = attr->next;
    }
    return (NULL);
}
				
/**
 * xmlSchemaCheckSRCAttributeGroupCircular:
 * attrGr:  the attribute group definition
 * @ctxt:  the parser context
 * @name:  the name
 *
 * Checks for circular references of attribute groups.
 */
static void
xmlSchemaCheckAttributeGroupCircular(xmlSchemaAttributeGroupPtr attrGr,
					xmlSchemaParserCtxtPtr ctxt, 
					const xmlChar * name ATTRIBUTE_UNUSED)
{    
    /*
    * Schema Representation Constraint: 
    * Attribute Group Definition Representation OK
    * 3 Circular group reference is disallowed outside <redefine>. 
    * That is, unless this element information item's parent is 
    * <redefine>, then among the [children], if any, there must 
    * not be an <attributeGroup> with ref [attribute] which resolves 
    * to the component corresponding to this <attributeGroup>. Indirect 
    * circularity is also ruled out. That is, when QName resolution 
    * (Schema Document) (§3.15.3) is applied to a ·QName· arising from 
    * any <attributeGroup>s with a ref [attribute] among the [children], 
    * it must not be the case that a ·QName· is encountered at any depth 
    * which resolves to the component corresponding to this <attributeGroup>.
    */
    /*
    * Only global components can be referenced.
    */
    if (((attrGr->flags & XML_SCHEMAS_ATTRGROUP_GLOBAL) == 0) || 
	(attrGr->attributes == NULL))
	return;
    else {
	xmlSchemaAttributeGroupPtr circ;

	circ = xmlSchemaGetCircAttrGrRef(attrGr, attrGr->attributes);
	if (circ != NULL) {
	    /*
	    * TODO: Report the referenced attr group as QName.
	    */
	    xmlSchemaPCustomErr(ctxt,
		XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3,
		NULL, NULL, circ->node,
		"Circular reference to the attribute group '%s' "
		"defined", attrGr->name);
	    /*
	    * NOTE: We will cut the reference to avoid further
	    * confusion of the processor.
	    * BADSPEC: The spec should define how to process in this case.
	    */
	    circ->attributes = NULL;
	    circ->refItem = NULL;
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

        ref = xmlSchemaGetAttributeGroup(ctxt->schema, attrgrp->ref, 
	    attrgrp->refNs);
        if (ref == NULL) {
	    xmlSchemaPResCompAttrErr(ctxt, 
		XML_SCHEMAP_SRC_RESOLVE,
		NULL, (xmlSchemaTypePtr) attrgrp, attrgrp->node,
		"ref", attrgrp->ref, attrgrp->refNs, 
		XML_SCHEMA_TYPE_ATTRIBUTEGROUP, NULL);
            return;
        }
	attrgrp->refItem = ref;
	/*
	* Check for self reference!
	*/
        xmlSchemaAttrGrpFixup(ref, ctxt, NULL);
        attrgrp->attributes = ref->attributes;
	attrgrp->attributeWildcard = ref->attributeWildcard;
    }
}

/**
 * xmlSchemaAttrCheckValConstr:
 * @item:  an schema attribute declaration/use
 * @ctxt:  a schema parser context
 * @name:  the name of the attribute
 * 
 * Validates the value constraints of an attribute declaration/use.
 *
 * Fixes finish doing the computations on the attributes definitions
 */
static void
xmlSchemaCheckAttrValConstr(xmlSchemaAttributePtr item,
			    xmlSchemaParserCtxtPtr ctxt, 
			    const xmlChar * name ATTRIBUTE_UNUSED)
{

    /*
    * a-props-correct
    * Schema Component Constraint: Attribute Declaration Properties Correct
    *
    * 2 if there is a {value constraint}, the canonical lexical 
    * representation of its value must be ·valid· with respect 
    * to the {type definition} as defined in String Valid (§3.14.4). 
    */

    if (item->defValue != NULL) {
	int ret;
	xmlNodePtr node;
	xmlSchemaTypePtr type;

	if (item->subtypes == NULL) {
	    xmlSchemaPErr(ctxt, item->node,
		XML_SCHEMAP_INTERNAL,
		"Internal error: xmlSchemaCheckAttrValConstr, "
		"type is missing... skipping validation of "
		"value constraint", NULL, NULL);
	    return;
	}

	/*
	* TODO: Try to avoid creating a new context.
	* TODO: This all is not very performant.
	*/
	type = item->subtypes;
	/*
	* Ensure there's validation context.
	*/
	if (ctxt->vctxt == NULL) {
	    if (xmlSchemaCreateVCtxtOnPCtxt(ctxt) == -1) {
		xmlSchemaPErr(ctxt, item->node,
		    XML_SCHEMAP_INTERNAL,
		    "Internal error: xmlSchemaCheckAttrValConstr, "
		    "creating a new validation context.\n",
		    NULL, NULL);
		return;
	    }
	}

	if (item->flags & XML_SCHEMAS_ATTR_FIXED)
	    node = (xmlNodePtr) xmlHasProp(item->node, BAD_CAST "fixed");
	else
	    node = (xmlNodePtr) xmlHasProp(item->node, BAD_CAST "default");
	ctxt->vctxt->node = node;
	ctxt->vctxt->cur = NULL;
	/*
	* NOTE: This call does not check the content nodes, 
	* since they are not available:
	* facet->node is just the node holding the facet 
	* definition, *not* the attribute holding the *value* 
	* of the facet.
	*/
	ret = xmlSchemaValidateSimpleTypeValue(ctxt->vctxt, type, 
	    item->defValue, 0, 1, 1, 0);
	if (ret == 0) {
	    /*
	    * Store the computed value.
	    */
    	    item->defVal = ctxt->vctxt->value;
	    ctxt->vctxt->value = NULL;	
	} else if (ret > 0) {
	    if (ctxt != NULL) {
		xmlSchemaPSimpleTypeErr(ctxt, 
		    XML_SCHEMAP_A_PROPS_CORRECT_2, 
		    NULL, NULL, node, 
		    type, NULL, item->defValue,
		    NULL, NULL, NULL);
	    }
	} else if (ret < 0) {
	    xmlSchemaPCustomErr(ctxt, XML_SCHEMAP_INTERNAL,
		NULL, NULL, node,
		"Internal error: xmlSchemaAttrCheckValConstr, "
		"failed to validate the value constraint of the "
		"attribute decl/use against the type '%s'",
		type->name); 	    
	}	   	
    }    
}

#if 0 /* Not used yet. */
static int
xmlSchemaCheckElemPropsCorrect(xmlSchemaParserCtxtPtr ctxt,
			       xmlSchemaElementPtr edecl)
{
    /*
    * TODO: 1 The values of the properties of an element declaration must be as 
    * described in the property tableau in The Element Declaration Schema 
    * Component (§3.3.1), modulo the impact of Missing Sub-components (§5.3).
    */
    /*
    * 2 If there is a {value constraint}, the canonical lexical 
    * representation of its value must be ·valid· with respect to the {type 
    * definition} as defined in Element Default Valid (Immediate) (§3.3.6).
    *
    * NOTE: This is done in xmlSchemaCheckElemValConstr.
    */
    /*
    * 3 If there is a non-·absent· {substitution group affiliation}, 
    * then {scope} must be global.
    *
    * NOTE: This is done in xmlSchemaParseElement.
    * TODO: Move it to this layer here.
    */
    /*
    * TODO: 4 If there is a {substitution group affiliation}, the {type definition} 
    * of the element declaration must be validly derived from the {type 
    * definition} of the {substitution group affiliation}, given the value 
    * of the {substitution group exclusions} of the {substitution group 
    * affiliation}, as defined in Type Derivation OK (Complex) (§3.4.6) 
    * (if the {type definition} is complex) or as defined in 
    * Type Derivation OK (Simple) (§3.14.6) (if the {type definition} is 
    * simple). 
    */
    /*
    * TODO: 5 If the {type definition} or {type definition}'s {content type} 
    * is or is derived from ID then there must not be a {value constraint}.
    * Note: The use of ID as a type definition for elements goes beyond 
    * XML 1.0, and should be avoided if backwards compatibility is desired
    */
    /*
    * TODO: 6 Circular substitution groups are disallowed. That is, it must not 
    * be possible to return to an element declaration by repeatedly following 
    * the {substitution group affiliation} property.
    */
}
#endif

/**
 * xmlSchemaCheckElemValConstr:
 * @item:  an schema element declaration/particle
 * @ctxt:  a schema parser context
 * @name:  the name of the attribute
 * 
 * Validates the value constraints of an element declaration.
 *
 * Fixes finish doing the computations on the element declarations.
 */
static void
xmlSchemaCheckElemValConstr(xmlSchemaElementPtr decl,
			    xmlSchemaParserCtxtPtr ctxt, 
			    const xmlChar * name ATTRIBUTE_UNUSED)
{   
    if (decl->value != NULL) {
	int ret;
	xmlNodePtr node = NULL;
	xmlSchemaTypePtr type;

	/*
	* 2 If there is a {value constraint}, the canonical lexical 
	* representation of its value must be ·valid· with respect to the {type 
	* definition} as defined in Element Default Valid (Immediate) (§3.3.6).
	*/    
	if (decl->subtypes == NULL) {
	    xmlSchemaPErr(ctxt, decl->node,
		XML_SCHEMAP_INTERNAL,
		"Internal error: xmlSchemaCheckElemValConstr, "
		"type is missing... skipping validation of "
		"the value constraint", NULL, NULL);
	    return;
	}
	/*
	* Ensure there's a validation context.
	*/
	if (xmlSchemaCreateVCtxtOnPCtxt(ctxt) == -1)
	    return;

	type = decl->subtypes;

	if (decl->node != NULL) {
	    if (decl->flags & XML_SCHEMAS_ELEM_FIXED)
		node = (xmlNodePtr) xmlHasProp(decl->node, BAD_CAST "fixed");
	    else
		node = (xmlNodePtr) xmlHasProp(decl->node, BAD_CAST "default");
	}
	ctxt->vctxt->node = node;
	ctxt->vctxt->cur = NULL;
	ret = xmlSchemaCheckCOSValidDefault(ctxt, ctxt->vctxt, type, decl->value, 
	    node);
	if (ret == 0) {
	    /*
	    * Consume the computed value.
	    */
    	    decl->defVal = ctxt->vctxt->value;
	    ctxt->vctxt->value = NULL;	
	} else if (ret < 0) {
	    xmlSchemaPCustomErr(ctxt, XML_SCHEMAP_INTERNAL,
		NULL, NULL, node,
		"Internal error: xmlSchemaElemCheckValConstr, "
		"failed to validate the value constraint of the "
		"element declaration '%s'",
		decl->name); 	    
	}	   	
    }    
}

/**
 * xmlSchemaAttrFixup:
 * @item:  an schema attribute declaration/use.
 * @ctxt:  a schema parser context
 * @name:  the name of the attribute 
 *
 * Fixes finish doing the computations on attribute declarations/uses.
 */
static void
xmlSchemaAttrFixup(xmlSchemaAttributePtr item,
                   xmlSchemaParserCtxtPtr ctxt, 
		   const xmlChar * name ATTRIBUTE_UNUSED)
{
    /* 
    * TODO: If including this is done twice (!) for every attribute.
    *       -> Hmm, check if this is still done.
    */
    /*
    * The simple type definition corresponding to the <simpleType> element 
    * information item in the [children], if present, otherwise the simple 
    * type definition ·resolved· to by the ·actual value· of the type 
    * [attribute], if present, otherwise the ·simple ur-type definition·.
    */
    if (item->flags & XML_SCHEMAS_ATTR_INTERNAL_RESOLVED)
	return;
    item->flags |= XML_SCHEMAS_ATTR_INTERNAL_RESOLVED;
    if (item->subtypes != NULL)
        return;
    if (item->typeName != NULL) {
        xmlSchemaTypePtr type;

	type = xmlSchemaGetType(ctxt->schema, item->typeName,
	    item->typeNs);
	if ((type == NULL) || (! IS_SIMPLE_TYPE(type))) {
	    xmlSchemaPResCompAttrErr(ctxt,
		XML_SCHEMAP_SRC_RESOLVE,
		NULL, (xmlSchemaTypePtr) item, item->node,
		"type", item->typeName, item->typeNs, 
		XML_SCHEMA_TYPE_SIMPLE, NULL);
	} else
	    item->subtypes = type;
	
    } else if (item->ref != NULL) {
        xmlSchemaAttributePtr decl;

	/*
	* We have an attribute use here; assign the referenced 
	* attribute declaration.
	*/
	/*
	* TODO: Evaluate, what errors could occur if the declaration is not
	* found. It might be possible that the "typefixup" might crash if
	* no ref declaration was found.
	*/
	decl = xmlSchemaGetAttribute(ctxt->schema, item->ref, item->refNs);
        if (decl == NULL) {
	    xmlSchemaPResCompAttrErr(ctxt,
	    	XML_SCHEMAP_SRC_RESOLVE,
		NULL, (xmlSchemaTypePtr) item, item->node,
		"ref", item->ref, item->refNs, 
		XML_SCHEMA_TYPE_ATTRIBUTE, NULL);
            return;
        }
	item->refDecl = decl;
        xmlSchemaAttrFixup(decl, ctxt, NULL);
	
        item->subtypes = decl->subtypes;
	/*
	* Attribute Use Correct
	* au-props-correct.2: If the {attribute declaration} has a fixed 
	* {value constraint}, then if the attribute use itself has a 
	* {value constraint}, it must also be fixed and its value must match 
	* that of the {attribute declaration}'s {value constraint}.
	*/
	if ((decl->flags & XML_SCHEMAS_ATTR_FIXED) && 
	    (item->defValue != NULL)) {
	    if (((item->flags & XML_SCHEMAS_ATTR_FIXED) == 0) ||
		(!xmlStrEqual(item->defValue, decl->defValue))) {
		xmlSchemaPCustomErr(ctxt,
		    XML_SCHEMAP_AU_PROPS_CORRECT_2, 
		    NULL, NULL, item->node, 
		    "The value constraint must be fixed "
		    "and match the referenced attribute "
		    "declarations's value constraint '%s'",
		    decl->defValue);
	    }
	    /*
	    * FUTURE: One should change the values of the attr. use
	    * if ever validation should be attempted even if the
	    * schema itself was not fully valid.
	    */
	}
    } else {
	item->subtypes = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE);        
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
    int preserve = 0;

    /*
    * This one is used if the schema to be parsed was specified via 
    * the API; i.e. not automatically by the validated instance document.
    */

    xmlSchemaInitTypes();

    if (ctxt == NULL)
        return (NULL);

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
                          "xmlSchemaParse: could not load '%s'.\n",
                          ctxt->URL, NULL);
            return (NULL);
        }
    } else if (ctxt->buffer != NULL) {
        doc = xmlReadMemory(ctxt->buffer, ctxt->size, NULL, NULL,
	                    SCHEMAS_PARSE_OPTIONS);
        if (doc == NULL) {
	    xmlSchemaPErr(ctxt, NULL,
			  XML_SCHEMAP_FAILED_PARSE,
                          "xmlSchemaParse: could not parse.\n",
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
		      "xmlSchemaParse: could not parse.\n",
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
		      "The schema has no document element.\n", NULL, NULL);
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
    ctxt->schema = ret;
    ctxt->ctxtType = NULL;
    ctxt->parentItem = NULL;
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
    * Check attribute groups for circular references.
    */
    xmlHashScan(ret->attrgrpDecl, (xmlHashScanner) 
	xmlSchemaCheckAttributeGroupCircular, ctxt);

    /*
    * Then fixup all model group definitions.
    */    
    xmlHashScan(ret->groupDecl, (xmlHashScanner) xmlSchemaGroupDefFixup, ctxt);
    
    /*
     * Then fixup all types properties
     */    
    xmlHashScan(ret->typeDecl, (xmlHashScanner) xmlSchemaTypeFixup, ctxt);

    /*
     * Then fix references of element declaration; apply constraints.
     */    
    xmlHashScanFull(ret->elemDecl,
                    (xmlHashScannerFull) xmlSchemaRefFixupCallback, ctxt);

     /*
    * Check model groups defnitions for circular references.
    */
    xmlHashScan(ret->groupDecl, (xmlHashScanner) 
	xmlSchemaCheckGroupDefCircular, ctxt);

    /*
     * Then build the content model for all complex types
     */
    xmlHashScan(ret->typeDecl,
                (xmlHashScanner) xmlSchemaBuildContentModel, ctxt);

    /*
     * Then check the defaults part of the type like facets values
     */
    /* OLD: xmlHashScan(ret->typeDecl, (xmlHashScanner) xmlSchemaCheckDefaults, ctxt); */

    /*
    * Validate the value constraint of attribute declarations/uses.
    */
    xmlHashScan(ret->attrDecl, (xmlHashScanner) xmlSchemaCheckAttrValConstr, ctxt);

    /*
    * Validate the value constraint of element declarations.
    */
    xmlHashScan(ret->elemDecl, (xmlHashScanner) xmlSchemaCheckElemValConstr, ctxt);


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
 * xmlSchemaGetParserErrors:
 * @ctxt:  a XMl-Schema parser context
 * @err: the error callback result
 * @warn: the warning callback result
 * @ctx: contextual data for the callbacks result
 *
 * Get the callback information used to handle errors for a parser context
 *
 * Returns -1 in case of failure, 0 otherwise
 */
int 
xmlSchemaGetParserErrors(xmlSchemaParserCtxtPtr ctxt,
							 xmlSchemaValidityErrorFunc * err,
							 xmlSchemaValidityWarningFunc * warn, void **ctx)
{
	if (ctxt == NULL)
		return(-1);
	if (err != NULL)
		*err = ctxt->error;
	if (warn != NULL)
		*warn = ctxt->warning;
	if (ctx != NULL)
		*ctx = ctxt->userData;
	return(0);
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



static int
xmlSchemaGetWhiteSpaceFacetValue(xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr anc;

    /* 
    * The normalization type can be changed only for types which are derived 
    * from xsd:string.
    */
    if (type->type == XML_SCHEMA_TYPE_BASIC) {
	if (type->builtInType == XML_SCHEMAS_STRING)
	    return(XML_SCHEMAS_VAL_WTSP_PRESERVE);
	else if (type->builtInType == XML_SCHEMAS_NORMSTRING)
	    return(XML_SCHEMAS_VAL_WTSP_REPLACE);
	else {
	    /*
	    * For all ·atomic· datatypes other than string (and types ·derived· 
	    * by ·restriction· from it) the value of whiteSpace is fixed to 
	    * collapse
	    */
	    return(XML_SCHEMAS_VAL_WTSP_COLLAPSE);
	}		   	    
    } else if (type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) {
	/*
	* For list types the facet "whiteSpace" is fixed to "collapse". 
	*/
	return (XML_SCHEMAS_VAL_WTSP_COLLAPSE);
    } else if (type->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) {
	return (-1);
    } else if (type->facetSet != NULL) {
	xmlSchemaTypePtr anyST;
	xmlSchemaFacetLinkPtr lin;

	/*
	* Atomic types.
	*/
	anyST = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYSIMPLETYPE);
	anc = type->baseType;
	do {
	    /*
	    * For all ·atomic· datatypes other than string (and types ·derived· 
	    * by ·restriction· from it) the value of whiteSpace is fixed to 
	    * collapse
	    */
	    if ((anc->type == XML_SCHEMA_TYPE_BASIC) &&
		(anc->builtInType == XML_SCHEMAS_STRING)) {
		
		lin = type->facetSet;
		do {
		    if (lin->facet->type == XML_SCHEMA_FACET_WHITESPACE) {
			if (lin->facet->whitespace == 
			    XML_SCHEMAS_FACET_COLLAPSE) {
			    return(XML_SCHEMAS_VAL_WTSP_COLLAPSE);  
			} else if (lin->facet->whitespace == 
			    XML_SCHEMAS_FACET_REPLACE) { 
			    return(XML_SCHEMAS_VAL_WTSP_REPLACE);
			} else
			    return(XML_SCHEMAS_VAL_WTSP_PRESERVE);
			break;
		    }
		    lin = lin->next;
		} while (lin != NULL);	
		break;
	    }
	    anc = anc->baseType;
	} while (anc != anyST);
	return (XML_SCHEMAS_VAL_WTSP_COLLAPSE);	
    }  
    return (-1);
}

/**
 * xmlSchemaValidateFacetsInternal:
 * @ctxt:  a schema validation context
 * @type:  the type holding the facets
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
				xmlSchemaTypePtr type,
				const xmlChar * value,
				unsigned long length,
				int fireErrors)
{
    int ret = 0;
    xmlNodePtr node;
    xmlSchemaTypePtr  biType; /* The build-in type. */
    xmlSchemaTypePtr tmpType;
    xmlSchemaFacetLinkPtr facetLink;
    int retFacet;
    xmlSchemaFacetPtr facet;
    unsigned long len = 0;

#ifdef DEBUG_UNION_VALIDATION
    printf("Facets of type: '%s'\n", (const char *) type->name);
    printf("  fireErrors: %d\n", fireErrors);
#endif
        
    node = ctxt->node;
    /*
    * NOTE: Do not jump away, if the facetSet of the given type is
    * empty: until now, "pattern" facets of the *base types* need to
    * be checked as well.
    */
    biType = type->baseType;
    while ((biType != NULL) && (biType->type != XML_SCHEMA_TYPE_BASIC))
	biType = biType->baseType;
    if (biType == NULL) {
	xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,		    
	    "Internal error: xmlSchemaValidateFacetsInternal, "
	    "the base type axis of the given type '%s' does not resolve to "
	    "a built-in type.\n",
	    type->name, NULL);	
	return (-1);
    }    
    
    if (type->facetSet != NULL) {
	facetLink = type->facetSet;
	while (facetLink != NULL) {
	    facet = facetLink->facet;
	    /*
	    * Skip the pattern "whiteSpace": it is used to 
	    * format the character content beforehand.
	    */	    
	    switch (facet->type) {
		case XML_SCHEMA_FACET_WHITESPACE:
		case XML_SCHEMA_FACET_PATTERN:
		case XML_SCHEMA_FACET_ENUMERATION:
		    break;
		case XML_SCHEMA_FACET_LENGTH:
		case XML_SCHEMA_FACET_MINLENGTH:
		case XML_SCHEMA_FACET_MAXLENGTH: 
		    if (type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) {
			ret = xmlSchemaValidateListSimpleTypeFacet(facet,
			    value, length, 0);
			len = length;
		    } else
			ret = xmlSchemaValidateLengthFacet(biType, facet,
			    value, ctxt->value, &len);
		    break;
		default:
		    ret = xmlSchemaValidateFacet(biType, facet, value, 
			ctxt->value);
	    }
	    if (ret < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateFacetsInternal, "
		    "validating facet of type '%s'.\n",
		    type->name, NULL);
		break;
	    } else if ((ret > 0) && (fireErrors)) {
		xmlSchemaVFacetErr(ctxt, ret, node, value, len,
		    type, facet, NULL, NULL, NULL, NULL);
	    }

	    facetLink = facetLink->next;
	}
	if (ret >= 0) {
	    /*
	    * Process enumerations.
	    */
	    retFacet = 0;
	    facetLink = type->facetSet;
	    while (facetLink != NULL) {
		if (facetLink->facet->type == XML_SCHEMA_FACET_ENUMERATION) {
		    retFacet = xmlSchemaValidateFacet(biType, facetLink->facet, 
			value, ctxt->value);		
		    if (retFacet <= 0)
			break;
		}
		facetLink = facetLink->next;
	    }
	    if (retFacet > 0) {
		ret = XML_SCHEMAV_CVC_ENUMERATION_VALID;
		if (fireErrors)
		    xmlSchemaVFacetErr(ctxt, ret, node,
			value, 0, type, NULL, NULL, NULL, NULL, NULL);
	    } else if (retFacet < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateFacetsInternal, "
		    "validating facet of type '%s'.\n",
		    BAD_CAST "enumeration", NULL);
		    ret = -1;		
	    }		
	}
    }
    if (ret >= 0) {
	/*
	* Process patters. Pattern facets are ORed at type level 
	* and ANDed if derived. Walk the base type axis.
	*/
	tmpType = type;
	facet = NULL;
	do {
	    retFacet = 0;
	    for (facetLink = tmpType->facetSet; facetLink != NULL; 
		facetLink = facetLink->next) {
		if (facetLink->facet->type != XML_SCHEMA_FACET_PATTERN)
		    continue;
		retFacet = xmlSchemaValidateFacet(biType, facetLink->facet, 
		    value, ctxt->value);
		if (retFacet == 0) 
		    break;
		else if (retFacet < 0) {
		    xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
			"Internal error: xmlSchemaValidateFacetsInternal, "
			"validating 'pattern' facet '%s' of type '%s'.\n",
			facetLink->facet->value, tmpType->name);
		    ret = -1;
		    break;
		} else
		    /* Save the last non-validating facet. */
		    facet = facetLink->facet;
	    }
	    if (retFacet != 0)
		break;		    
	    tmpType = tmpType->baseType;
	} while ((tmpType != NULL) && (tmpType->type != XML_SCHEMA_TYPE_BASIC));
	if (retFacet > 0) {
	    ret = XML_SCHEMAV_CVC_PATTERN_VALID;
	    if (fireErrors) {
		xmlSchemaVFacetErr(ctxt, ret, node, value, 0, type, facet, 
		    NULL, NULL, NULL, NULL);
	    }
	}
    }	    
   
    return (ret);
}

/************************************************************************
 * 									*
 * 			Simple type validation				*
 * 									*
 ************************************************************************/


/************************************************************************
 * 									*
 * 			DOM Validation code				*
 * 									*
 ************************************************************************/

static int xmlSchemaValidateAttributes(xmlSchemaValidCtxtPtr ctxt,
                                       xmlNodePtr elem,
                                       xmlSchemaTypePtr type);
static int xmlSchemaValidateElementByType(xmlSchemaValidCtxtPtr ctxt,                                
					  xmlSchemaTypePtr type,
					  int valSimpleContent);


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
	tmp->decl = NULL;
	if (ctxt->attr == NULL) 
            ctxt->attr = tmp;
	else
	    ctxt->attrTop->next = tmp;
	ctxt->attrTop = tmp;
        attrs = attrs->next;
    }
    return (0);
}

#if 0 /* Currently not used */
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
#endif

static void
xmlSchemaPostSchemaAssembleFixup(xmlSchemaParserCtxtPtr ctxt)
{
    int i, nbItems;
    xmlSchemaTypePtr item, *items;


    /*
    * During the Assemble of the schema ctxt->curItems has
    * been filled with the relevant new items. Fix those up.
    */
    nbItems = ctxt->assemble->nbItems;
    items = (xmlSchemaTypePtr *) ctxt->assemble->items;
    
    for (i = 0; i < nbItems; i++) {
	item = items[i];
	switch (item->type) {
	    case XML_SCHEMA_TYPE_ATTRIBUTE:
		xmlSchemaAttrFixup((xmlSchemaAttributePtr) item, ctxt, NULL);
		break;
	    case XML_SCHEMA_TYPE_ELEMENT:
		xmlSchemaRefFixupCallback((xmlSchemaElementPtr) item, ctxt, 
		    NULL, NULL, NULL);
		break;
	    case XML_SCHEMA_TYPE_ATTRIBUTEGROUP:
		xmlSchemaAttrGrpFixup((xmlSchemaAttributeGroupPtr) item, 
		    ctxt, NULL);
		break;
	    case XML_SCHEMA_TYPE_GROUP:
		xmlSchemaGroupDefFixup(item, ctxt, NULL);            
	    default:
		break;
	}
    }
    /*
    * Circularity checks.
    */
    for (i = 0; i < nbItems; i++) {
	item = items[i];
	switch (item->type) {	    
	    case XML_SCHEMA_TYPE_GROUP:
		xmlSchemaCheckGroupDefCircular(item, ctxt, NULL);
		break;
	    case XML_SCHEMA_TYPE_ATTRIBUTEGROUP:
		xmlSchemaCheckAttributeGroupCircular(
		    (xmlSchemaAttributeGroupPtr) item, ctxt, NULL);
		break;
	    default:
		break;
	}
    }
    /*
    * Fixup for all other item. 
    * TODO: Hmm, not sure if starting from complex/simple types,
    * all subsequent items will be reached.
    */
    for (i = 0; i < nbItems; i++) {
	item = items[i];
	switch (item->type) {	    
            case XML_SCHEMA_TYPE_SIMPLE:
	    case XML_SCHEMA_TYPE_COMPLEX:
		xmlSchemaTypeFixup(item, ctxt, NULL);
		break;
	    default:
		break;
	}
    }
    /*
    * Check facet values. Note that facets are
    * hold by simple type components only (and
    * by complex types in the current implementation).
    */
    /* OLD: 
    for (i = 0; i < nbItems; i++) {
	item = items[i];
	switch (item->type) {	 
	    case XML_SCHEMA_TYPE_SIMPLE:
	    case XML_SCHEMA_TYPE_COMPLEX:
		xmlSchemaCheckDefaults(item, ctxt, NULL);
		break;
	    default:
		break;
	}
    }
    */
    /*
    * Build the content model for complex types.
    */
    for (i = 0; i < nbItems; i++) {
	item = items[i];
	switch (item->type) {	    
	    case XML_SCHEMA_TYPE_COMPLEX:
		xmlSchemaBuildContentModel(item, ctxt, NULL);
		break;
	    default:
		break;
	}
    } 
    /*
    * Validate value contraint values.
    */
    for (i = 0; i < nbItems; i++) {
	item = items[i];
	switch (item->type) {
	    case XML_SCHEMA_TYPE_ATTRIBUTE:
		xmlSchemaCheckAttrValConstr((xmlSchemaAttributePtr) item, ctxt, NULL);
		break;
	    case XML_SCHEMA_TYPE_ELEMENT:
		xmlSchemaCheckElemValConstr((xmlSchemaElementPtr) item, ctxt, NULL);
		break;
	    default:
		break;
	}
    }
}

/**
 * xmlSchemaAssembleByLocation:
 * @pctxt:  a schema parser context
 * @vctxt:  a schema validation context
 * @schema: the existing schema
 * @node: the node that fired the assembling
 * @nsName: the namespace name of the new schema
 * @location: the location of the schema
 *
 * Expands an existing schema by an additional schema.
 *
 * Returns 0 if the new schema is correct, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaAssembleByLocation(xmlSchemaValidCtxtPtr vctxt,			    
			    xmlSchemaPtr schema,
			    xmlNodePtr node,
			    const xmlChar *nsName,
			    const xmlChar *location)
{
    const xmlChar *targetNs, *oldtns; 
    xmlDocPtr doc, olddoc;
    int oldflags, ret = 0;
    xmlNodePtr docElem;
    xmlSchemaParserCtxtPtr pctxt;

    /*
    * This should be used:
    * 1. on <import>(s)
    * 2. if requested by the validated instance 
    * 3. if requested via the API
    */
    if ((vctxt == NULL) || (schema == NULL))
	return (-1);
    /*
    * Create a temporary parser context.
    */
    if ((vctxt->pctxt == NULL) &&
	(xmlSchemaCreatePCtxtOnVCtxt(vctxt) == -1)) {
	xmlSchemaVErr(vctxt, node,
	    XML_SCHEMAV_INTERNAL,
	    "Internal error: xmlSchemaAssembleByLocation, "
	    "failed to create a temp. parser context.\n", 
	    NULL, NULL);
	return (-1);		
    }            
    pctxt = vctxt->pctxt;
    /*
    * Set the counter to produce unique names for anonymous items.
    */
    pctxt->counter = schema->counter;    
    /*
    * Acquire the schema document.
    */
    ret = xmlSchemaAcquireSchemaDoc(pctxt, schema, node,
	nsName, location, &doc, &targetNs, 0);
    if (ret != 0) {
	if (doc != NULL)
	    xmlFreeDoc(doc);
    } else if (doc != NULL) {
	docElem = xmlDocGetRootElement(doc);
	/*
	* Create new assemble info.
	*/
	if (pctxt->assemble == NULL) {
	    pctxt->assemble = xmlSchemaNewAssemble();
	    if (pctxt->assemble == NULL) {
		xmlSchemaVErrMemory(vctxt, 
		    "Memory error: xmlSchemaAssembleByLocation, "
		    "allocating assemble info", NULL);
		xmlFreeDoc(doc);
		return (-1);
	    }
	}
	/*
	* Save and reset the context & schema.
	*/
	oldflags = schema->flags;
	oldtns = schema->targetNamespace;
	olddoc = schema->doc;
	
	xmlSchemaClearSchemaDefaults(schema);
	schema->targetNamespace = targetNs;
	/* schema->nbCurItems = 0; */
	pctxt->schema = schema;
	pctxt->ctxtType = NULL;
	pctxt->parentItem = NULL;
	
	xmlSchemaParseSchemaDefaults(pctxt, schema, docElem);		
	xmlSchemaParseSchemaTopLevel(pctxt, schema, docElem->children);
	xmlSchemaPostSchemaAssembleFixup(pctxt);
	/*
	* Set the counter of items.
	*/
	schema->counter = pctxt->counter;
	/*
	* Free the list of assembled components.
	*/
	pctxt->assemble->nbItems = 0;
	/*
	* Restore the context & schema.
	*/
	schema->flags = oldflags;
	schema->targetNamespace = oldtns;
	schema->doc = olddoc;
	ret = pctxt->err;
    }        
    return (ret);
}

/**
 * xmlSchemaAssembleByXSIAttr:
 * @vctxt:  a schema validation context
 * @xsiAttr: an xsi attribute
 * @noNamespace: whether a schema with no target namespace is exptected
 *
 * Expands an existing schema by an additional schema using
 * the xsi:schemaLocation or xsi:noNamespaceSchemaLocation attribute
 * of an instance. If xsi:noNamespaceSchemaLocation is used, @noNamespace
 * must be set to 1.
 *
 * Returns 0 if the new schema is correct, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaAssembleByXSIAttr(xmlSchemaValidCtxtPtr vctxt,
			 xmlAttrPtr xsiAttr,
			 int noNamespace)
{
    xmlChar *value;
    const xmlChar *cur, *end;
    const xmlChar *nsname = NULL, *location;
    int count = 0;
    int ret = 0;
    
    if (xsiAttr == NULL) {
	xmlSchemaVCustomErr(vctxt, XML_SCHEMAV_INTERNAL, 
	    NULL, NULL,
	    "Internal error: xmlSchemaAssembleByXSIAttr, "
	    "bad arguments", NULL);
	return (-1);
    }
    /*
    * Parse the value; we will assume an even number of values
    * to be given (this is how Xerces and XSV work).
    */
    value = xmlNodeGetContent((xmlNodePtr) xsiAttr);    
    cur = value;
    do {	
	if (noNamespace != 1) {
	    /*
	    * Get the namespace name.
	    */
	    while (IS_BLANK_CH(*cur))
		cur++;
	    end = cur;
	    while ((*end != 0) && (!(IS_BLANK_CH(*end))))
		end++;
	    if (end == cur)
		break;
	    count++;
	    nsname = xmlDictLookup(vctxt->schema->dict, cur, end - cur);		
	    cur = end;
	}
	/*
	* Get the URI.
	*/
	while (IS_BLANK_CH(*cur))
	    cur++;
	end = cur;
	while ((*end != 0) && (!(IS_BLANK_CH(*end))))
	    end++;
	if (end == cur)
	    break;
	count++;
	location = xmlDictLookup(vctxt->schema->dict, cur, end - cur);
	cur = end;	
	ret = xmlSchemaAssembleByLocation(vctxt, vctxt->schema, 
	    xsiAttr->parent, nsname, location);
	if (ret == -1) {
	    xmlSchemaVCustomErr(vctxt, 
		XML_SCHEMAV_INTERNAL,
		(xmlNodePtr) xsiAttr, NULL,
		"Internal error: xmlSchemaAssembleByXSIAttr, "
		"assembling schemata", NULL);
	    if (value != NULL)
		xmlFree(value);
	    return (-1);
	}
    } while (*cur != 0);
    if (value != NULL)
	xmlFree(value);
    return (ret);
}

/**
 * xmlSchemaAssembleByXSIElem:
 * @vctxt:  a schema validation context
 * @elem: an element node possibly holding xsi attributes
 * @noNamespace: whether a schema with no target namespace is exptected
 *
 * Assembles an existing schema by an additional schema using
 * the xsi:schemaLocation or xsi:noNamespaceSchemaLocation attributes
 * of the given @elem.
 *
 * Returns 0 if the new schema is correct, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaAssembleByXSIElem(xmlSchemaValidCtxtPtr vctxt,  
			 xmlNodePtr elem)
{    
    int ret = 0, retNs = 0;
    xmlAttrPtr attr;

    attr = xmlHasNsProp(elem, BAD_CAST "schemaLocation", xmlSchemaInstanceNs);
    if (attr != NULL) {
	retNs = xmlSchemaAssembleByXSIAttr(vctxt, attr, 0);
	if (retNs == -1)
	    return (-1);
    }
    attr = xmlHasNsProp(elem, BAD_CAST "noNamespaceSchemaLocation", xmlSchemaInstanceNs);
    if (attr != NULL) {
	ret = xmlSchemaAssembleByXSIAttr(vctxt, attr, 1);
	if (ret == -1)
	    return (-1);
    }
    if (retNs != 0)
	return (retNs);
    else
	return (ret);
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
    /*
    * @type->type will be XML_SCHEMA_TYPE_ANY or XML_SCHEMA_TYPE_ELEMENT.
    */
    ctxt->type = type;
    ctxt->node = node;    
    ctxt->cur = node->children;
    /*
    * Assemble new schemata using xsi.
    */
    if (ctxt->xsiAssemble) {
	int ret;

	ret = xmlSchemaAssembleByXSIElem(ctxt, ctxt->node);
	if (ret == -1) {
	    xmlSchemaVCustomErr(ctxt, 
		XML_SCHEMAV_INTERNAL,
		ctxt->node, NULL, 	
		"Internal error: xmlSchemaValidateElement, "
		"assembling schema by xsi", NULL);
	    return;
	}
	/*
	* NOTE: We won't react on schema parser errors here.
	* TODO: But a warning would be nice.
	*/
    }    
    switch (type->type) {
	case XML_SCHEMA_TYPE_ELEMENT: {
	    /*
	    * NOTE: The build of the content model 
	    * (xmlSchemaBuildAContentModel) ensures that the element 
	    * declaration (and not a reference to it) will be given.
	    */
	    if (((xmlSchemaElementPtr) ctxt->type)->ref != NULL) {
		/*
		* This is paranoid coding ;-)... it should not
		* happen here any more.
		*/
		xmlSchemaVCustomErr(ctxt, 
		    XML_SCHEMAV_INTERNAL, 
		    node, NULL,						
		    "Internal error: xmlSchemaValidateCallback, "
		    "element declaration 'reference' encountered, "
		    "but an element declaration was expected", 
		    NULL);
		return;
	    }
	    xmlSchemaValidateElementByDeclaration(ctxt, 
		(xmlSchemaElementPtr) type);
	    break;
	}
        case XML_SCHEMA_TYPE_ANY:
	    xmlSchemaValidateElementByWildcard(ctxt, type);
            break;
	default: 
	    break;
    }
    ctxt->type = oldtype;
    ctxt->node = oldnode;
}  

/**
 * xmlSchemaValidateSimpleTypeValue:
 * @ctxt:  a schema validation context
 * @value: the value to be validated
 * @fireErrors: shall errors be reported?
 * @applyFacets: shall facets be applied?
 * @normalize: shall the value be normalized?
 * @checkNodes: shall the content nodes be checked?
 *
 * Validates a value by the given type (user derived or built-in).
 *
 * Returns 0 if the value is valid, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaValidateSimpleTypeValue(xmlSchemaValidCtxtPtr ctxt, 
				 xmlSchemaTypePtr type,
				 const xmlChar *value,				 
				 int fireErrors,				 
				 int applyFacets,
				 int normalize,
				 int checkNodes)
{
    xmlNodePtr node;
    int ret = 0;  
    xmlChar *normValue = NULL;
    int wtsp;       
 
    node = ctxt->node;
    /* Save the current whitespace normalization type. */
    wtsp = ctxt->valueWS;
    /*
    * Normalize the value.
    */
    if (normalize && 
	(ctxt->valueWS != XML_SCHEMAS_VAL_WTSP_COLLAPSE)) {
	int norm = xmlSchemaGetWhiteSpaceFacetValue(type);
	
	if ((norm != -1) && (norm > ctxt->valueWS)) {
	    if (norm == XML_SCHEMAS_VAL_WTSP_COLLAPSE)
		normValue = xmlSchemaCollapseString(value);
	    else
		normValue = xmlSchemaWhiteSpaceReplace(value);
	    ctxt->valueWS = norm;
	    if (normValue != NULL)
		value = (const xmlChar *) normValue;
	}		
    }    
    /*
    * The nodes of a content must be checked only once,
    * this is not working since list types will fire this
    * multiple times.
    */
    if ((checkNodes == 1) && (ctxt->cur != NULL)) {
	xmlNodePtr cur = ctxt->cur;

	do {
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
		/* TODO: Scour the entities for illegal nodes. */
		TODO break;
	    case XML_ELEMENT_NODE: {
	    /* NOTE: Changed to an internal error, since the 
	    * existence of an element node will be already checked in
	    * xmlSchemaValidateElementBySimpleType and in
	    * xmlSchemaValidateElementByComplexType.
		*/
		xmlSchemaVCustomErr(ctxt, 
		    XML_SCHEMAV_INTERNAL,
		    /* XML_SCHEMAS_ERR_INVALIDELEM, */
		    node, type,
		    "Element '%s' found in simple type content", 
		    cur->name);
		return (XML_SCHEMAV_INTERNAL);
				   }
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
		xmlSchemaVCustomErr(ctxt, 
		    XML_SCHEMAV_INTERNAL,
		    /* XML_SCHEMAS_ERR_INVALIDELEM, */
		    node, NULL,
		    "Node of unexpected type found in simple type content",
		    NULL);
		return (XML_SCHEMAV_INTERNAL);
	    }
	    cur = cur->next;
	} while (cur != NULL);
    }

    if (type->type == XML_SCHEMA_TYPE_COMPLEX) {
	xmlSchemaTypePtr base, anyType;

	anyType = xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE);

	base = type->baseType;
	while ((base != NULL) && 
	    (base->type != XML_SCHEMA_TYPE_SIMPLE) &&
	    (base->type != XML_SCHEMA_TYPE_BASIC) &&
	    (base != anyType)) {
	    base = base->baseType;
	}
	ret = xmlSchemaValidateSimpleTypeValue(ctxt, base, value, 1, 0, 1, 0);
	if (ret < 0) {
	    xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		"Internal error: xmlSchemaValidateSimpleTypeValue, "
		"validating complex type '%s'\n",
		type->name, NULL);
	} else if ((ret == 0) && (applyFacets) && (type->facetSet != NULL)) {
	    /* 
	    * Check facets.
	    */	    
	    /*
	    * This is somehow not nice, since if an error occurs
	    * the reported type will be the complex type; the spec
	    * wants a simple type to be created on the complex type
	    * if it has a simple content. For now we have to live with
	    * it.
	    */
	    ret = xmlSchemaValidateFacetsInternal(ctxt, type, 
		value, 0, fireErrors);
	    if (ret < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateSimpleTypeValue, "
		    "validating facets of complex type '%s'\n",
		    type->name, NULL);
	    } else if (ret > 0) {
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1;
		if (fireErrors) 
		    xmlSchemaVSimpleTypeErr(ctxt, ret, node, value, type);
	    }	
	}	
    } else if (type->type == XML_SCHEMA_TYPE_BASIC) {

	if (ctxt->value != NULL) {
	    xmlSchemaFreeValue(ctxt->value);
	    ctxt->value = NULL;
	}
	/*
	* STREAM-READ-CHILDREN.
	*/	    		
	ret = xmlSchemaValPredefTypeNodeNoNorm(type, value, &(ctxt->value), node);
	if (ret > 0) {	    
	    if (type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) 
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2;
	    else
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1;	    
	    if (fireErrors)
		xmlSchemaVSimpleTypeErr(ctxt, ret, node, value, type);
	} else if (ret < 0) {
	    xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		"Internal error: xmlSchemaValidateSimpleTypeValue, "
		"validating built-in type '%s'\n", type->name, NULL);
	}
    } else if (type->flags & XML_SCHEMAS_TYPE_VARIETY_ATOMIC) {        
	/* 1.2.1 if {variety} is ·atomic· then the string must ·match· 
	* a literal in the ·lexical space· of {base type definition} 
	*/	
	ret = xmlSchemaValidateSimpleTypeValue(ctxt, type->baseType, value, 0, 0, 0, 0);
	if (ret < 0) {
	    xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		"Internal error: xmlSchemaValidateSimpleTypeValue, "
		"validating atomic simple type '%s'\n",
		type->name, NULL);
	} else if (ret > 0) {	    
	    ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1;
	    if (fireErrors)
		xmlSchemaVSimpleTypeErr(ctxt, ret, node, value, type);	
	} else if ((applyFacets) && (type->facetSet != NULL)) {
	    /* 
	    * Check facets.
	    */	    	    	    
	    ret = xmlSchemaValidateFacetsInternal(ctxt, type, 
		value, 0, fireErrors);
	    if (ret < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateSimpleTypeValue, "
		    "validating facets of atomic simple type '%s'\n",
		    type->name, NULL);
	    } else if (ret > 0) {
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1;
		/*
		 Disabled, since the facet validation already reports errors.
		if (fireErrors) 
		    xmlSchemaVSimpleTypeErr(ctxt, ret, ctxt->cur, value, type);
		*/
	    }	
	}
    } else if (type->flags & XML_SCHEMAS_TYPE_VARIETY_LIST) {
        
	xmlSchemaTypePtr tmpType;
	const xmlChar *cur, *end;
	xmlChar *tmp;
	unsigned long len = 0;

	/* 1.2.2 if {variety} is ·list· then the string must be a sequence 
	* of white space separated tokens, each of which ·match·es a literal 
	* in the ·lexical space· of {item type definition} 
	*/
	
	if (value == NULL)
	    value = BAD_CAST "";
	tmpType = xmlSchemaGetListSimpleTypeItemType(type);	
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
	    len++;
	    ret = xmlSchemaValidateSimpleTypeValue(ctxt, tmpType, tmp, 0, 1, 0, 0);
	    xmlFree(tmp);
	    if (ret < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateSimpleTypeValue, "
		    "validating an item of list simple type '%s'\n",
		    type->name, NULL);	
		break;
	    } else if (ret > 0) {
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2;
		if (fireErrors)
		    xmlSchemaVSimpleTypeErr(ctxt, ret, node, value, type);
		break;
	    }	
	    cur = end;
	} while (*cur != 0);
	/* 
	* Check facets.
	*/
	if (ret < 0) {
	    xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		"Internal error: xmlSchemaValidateSimpleTypeValue, "
		"validating list simple type '%s'\n",
		type->name, NULL);
	} else if ((ret == 0) && (applyFacets)) {
	    ret = xmlSchemaValidateFacetsInternal(ctxt, type, 
		value, len, fireErrors);
	    if (ret < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateSimpleTypeValue, "
		    "validating facets of list simple type '%s'\n",
		    type->name, NULL);
	    } else if (ret > 0) {
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2;
		/*
		 Disabled, since the facet validation already reports errors.
		if (fireErrors) 
		    xmlSchemaVSimpleTypeErr(ctxt, ret, ctxt->cur, value, type);
		*/
	    }	 	   
	   
	}
    } else if (type->flags & XML_SCHEMAS_TYPE_VARIETY_UNION) {
	xmlSchemaTypeLinkPtr memberLink;

	/*
	* TODO: For all datatypes ·derived· by ·union·  whiteSpace does 
	* not apply directly; however, the normalization behavior of ·union· 
	* types is controlled by the value of whiteSpace on that one of the 
	* ·memberTypes· against which the ·union· is successfully validated. 
	*
	* This means that the value is normalized by the first validating
	* member type, then the facets of the union type are applied. This
	* needs changing of the value!
	*/	
	
	/*
	* 1.2.3 if {variety} is ·union· then the string must ·match· a 
	* literal in the ·lexical space· of at least one member of 
	* {member type definitions} 
	*/
#ifdef DEBUG_UNION_VALIDATION
	printf("Union ST     : '%s'\n", (const char *) type->name);
	printf("  fireErrors : %d\n", fireErrors);
	printf("  applyFacets: %d\n", applyFacets);
#endif
	memberLink = xmlSchemaGetUnionSimpleTypeMemberTypes(type);
	if (memberLink == NULL) {
	    xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		"Internal error: xmlSchemaValidateSimpleTypeValue, "
		"union simple type '%s' has no member types\n",
		type->name, NULL);
	    ret = -1;
	} 
	if (ret == 0) {
	    while (memberLink != NULL) {
		ret = xmlSchemaValidateSimpleTypeValue(ctxt, memberLink->type, 
		    value, 0, 1, 1, 0);
		if ((ret <= 0) || (ret == 0))
		    break;	    
		memberLink = memberLink->next;
	    }     
	    if (ret < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateSimpleTypeValue, "
		    "validating members of union simple type '%s'\n",
		    type->name, NULL);
	    } else if (ret > 0) {
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3;
		if (fireErrors)
		    xmlSchemaVSimpleTypeErr(ctxt, ret, node, value, type);
	    }
	}
	/*
	* Apply facets (pattern, enumeration).	
	*/
	if ((ret == 0) && (applyFacets) && (type->facetSet != NULL)) {
	    int mws;
	    /*
	    * The normalization behavior of ·union· types is controlled by 
	    * the value of whiteSpace on that one of the ·memberTypes· 
	    * against which the ·union· is successfully validated. 
	    */		    
	    if (normValue != NULL) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateSimpleTypeValue, "
		    "the value was already normalized for the union simple "
		    "type '%s'.\n", type->name, NULL);
	    }
	    mws = xmlSchemaGetWhiteSpaceFacetValue(memberLink->type);
	    if (mws > ctxt->valueWS) {
		if (mws == XML_SCHEMAS_VAL_WTSP_COLLAPSE)
		    normValue = xmlSchemaCollapseString(value);
		else
		    normValue = xmlSchemaWhiteSpaceReplace(value);
		if (normValue != NULL)
		    value = (const xmlChar *) normValue;
	    }

	    ret = xmlSchemaValidateFacetsInternal(ctxt, type, 
		value, 0, fireErrors);
	    if (ret < 0) {
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateSimpleTypeValue, "
		    "validating facets of union simple type '%s'\n",
		    type->name, NULL);
	    } else if (ret > 0) {
		ret = XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3;
		/*
		if (fireErrors)
		    xmlSchemaVSimpleTypeErr(ctxt, ret, ctxt->cur, value, type);
		*/
	    }	
	}
    }           
    ctxt->valueWS = wtsp;
    if (normValue != NULL)
	xmlFree(normValue);
    return (ret);
}

/**
 * xmlSchemaValidateSimpleTypeElement:
 * @ctxt:  a schema validation context
 * @node:  the element node to be validated.
 *
 * Validate the element against a simple type.
 *
 * Returns 0 if the element is valid, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaValidateElementBySimpleType(xmlSchemaValidCtxtPtr ctxt, 
				     xmlSchemaTypePtr type,
				     int valSimpleContent)
{
    xmlSchemaTypePtr oldtype;
    xmlNodePtr node;
    xmlAttrPtr attr;
    xmlNodePtr cur;
    int ret = 0, retval = 0;
        
    if ((ctxt == NULL) || (type == NULL)) {
        xmlSchemaVCustomErr(ctxt, XML_SCHEMAV_INTERNAL, NULL, NULL,
	    "Internal error: xmlSchemaValidateElementBySimpleType, "
	    "bad arguments", NULL);
        return (-1);    
    }

    oldtype = ctxt->type;
    node = ctxt->node;
    /* 
    * cvc-type: 3.1.2 The element information item must have no element 
    * information item [children].
    */   
    /*
    * STREAM: Child nodes are processed.
    */
    cur = node->children;
    while (cur != NULL) {
	/*
	* TODO: Entities, will they produce elements as well?
	*/
	if (cur->type == XML_ELEMENT_NODE) {
	    xmlSchemaVCustomErr(ctxt,
		XML_SCHEMAV_CVC_TYPE_3_1_2,
		node, type,		
		"No element content allowed", NULL);
	    ret = XML_SCHEMAV_CVC_TYPE_3_1_2;
	}
	cur = cur->next;
    }
    
    /*
    * cvc-type 3.1.1:
    *
    * The attributes of must be empty, excepting those whose namespace name 
    * is identical to http://www.w3.org/2001/XMLSchema-instance and whose local 
    * name is one of type, nil, schemaLocation or noNamespaceSchemaLocation.
    */   
    /*
    * STREAM: Attribute nodes are processed.
    */
    attr = node->properties;
    while (attr != NULL) {
        if ((attr->ns == NULL) ||
            (!xmlStrEqual(attr->ns->href, xmlSchemaInstanceNs)) ||
            ((!xmlStrEqual(attr->name, BAD_CAST "type")) &&
             (!xmlStrEqual(attr->name, BAD_CAST "nil")) &&
             (!xmlStrEqual(attr->name, BAD_CAST "schemaLocation")) &&
             (!xmlStrEqual
              (attr->name, BAD_CAST "noNamespaceSchemaLocation")))) {
	    xmlSchemaVIllegalAttrErr(ctxt, 
		XML_SCHEMAV_CVC_TYPE_3_1_1, attr);
	    ret = XML_SCHEMAV_CVC_TYPE_3_1_1;
        }
	attr = attr->next;
    }
    /*
    * This will skip validation if the type is 'anySimpleType' and
    * if the value was already validated (e.g. default values).
    */
    if ((valSimpleContent == 1) &&
	((type->type != XML_SCHEMA_TYPE_BASIC) ||
	 (type->builtInType != XML_SCHEMAS_ANYSIMPLETYPE))) {
	xmlChar *value;	

	value = xmlNodeGetContent(node);
	/*
	* NOTE: This call will not check the content nodes, since
	* this should be checked here already.
	*/
	retval = xmlSchemaValidateSimpleTypeValue(ctxt, type, value, 
	    1, 1, 1, 0);
	if (value != NULL)
	    xmlFree(value);
	if (retval != 0)
	    ret = retval;
    }
    ctxt->type = oldtype;
    return (ret);
}

/**
 * xmlSchemaValQNameAcquire:
 * @value: the lexical represantation of the QName value
 * @node: the node to search for the corresponding namespace declaration
 * @nsName: the resulting namespace name if found
 *
 * Checks that a value conforms to the lexical space of the type QName;
 * if valid, the corresponding namespace name is searched and retured 
 * as a copy in @nsName. The local name is returned in @localName as
 * a copy.
 *
 * Returns 0 if valid, 1 if not valid by type, 2 if no corresponding 
 * namespace declaration was found in scope; -1 in case of an internal or 
 * API error.
 */
static int
xmlSchemaValQNameAcquire(const xmlChar *value, xmlNodePtr node,
			xmlChar **nsName, xmlChar **localName)
{
    int ret;
    xmlChar *local = NULL;

    if ((nsName == NULL) || (localName == NULL) || (node == NULL))
	return (-1);  
    *nsName = NULL;   
    *localName = NULL;
    ret = xmlValidateQName(value, 1);
    if (ret == 0) {
	xmlChar *prefix;
	xmlNsPtr ns;
	
	/*
	* NOTE: xmlSplitQName2 will return a duplicated
	* string.
	*/
	local = xmlSplitQName2(value, &prefix);
	if (local == NULL)
	    local = xmlStrdup(value);
	ns = xmlSearchNs(node->doc, node, prefix);
	/*
        * A namespace need not to be found if the prefix is NULL.
	*/
	if (ns != NULL) {
	    /*
	    * TODO: Is it necessary to duplicate the URI here?
	    */
	    *nsName = xmlStrdup(ns->href);
	} else if (prefix != NULL) {
	    xmlFree(prefix); 
	    if (local != NULL)
		xmlFree(local);
	    return (2);
	}		
	*localName = local;
	if (prefix != NULL)
	    xmlFree(prefix);    
    } else
	return (1);
    return (ret);
}

/**
 * xmlSchemaHasElemContent: 
 * @node:  the node
 *
 * Scours the content of the given node for element
 * nodes.
 *
 * Returns 1 if an element node is found,
 * 0 otherwise.
 */
static int
xmlSchemaHasElemContent(xmlNodePtr node)
{
    if (node == NULL)
	return (0);
    node = node->children;
    while (node != NULL) {
	if (node->type == XML_ELEMENT_NODE)
	    return (1);
	node = node->next;
    }
    return (0);
}
/**
 * xmlSchemaHasElemOrCharContent: 
 * @node:  the node
 *
 * Scours the content of the given node for element
 * and character nodes.
 *
 * Returns 1 if an element or character node is found,
 * 0 otherwise.
 */
static int
xmlSchemaHasElemOrCharContent(xmlNodePtr node)
{
    if (node == NULL)
	return (0);
    node = node->children;
    while (node != NULL) {
	switch (node->type) {
	    case XML_ELEMENT_NODE:	
	    /* 
	    * TODO: Ask Daniel if these are all character nodes.
	    */
	    case XML_TEXT_NODE:
	    case XML_CDATA_SECTION_NODE:
	    /*
	    * TODO: How XML_ENTITY_NODEs evaluated?
	    */
	    case XML_ENTITY_REF_NODE:
	    case XML_ENTITY_NODE:
		return (1);
		break;
	    default:
		break;
	}
	node = node->next;
    }
    return (0);
}


/**
 * xmlSchemaValidateElementByDeclaration:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Validate the content of an element type.
 * Validation Rule: Element Locally Valid (Element)
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateElementByDeclaration(xmlSchemaValidCtxtPtr ctxt,
				      xmlSchemaElementPtr elemDecl)
{
    xmlNodePtr elem;
    int ret = 0;
    xmlSchemaTypePtr actualType = NULL;
    xmlAttrPtr attr;
    xmlChar *attrValue; 
    int nilled = 0, elemHasContent = -1;

    /* 
    * This one is called by xmlSchemaValidateElementByWildcardInternal, 
    * xmlSchemaValidateElementByAnyType and xmlSchemaValidateElement.
    * Note that @elemDecl will be the declaration and never the
    * reference to a declaration.
    */

    if (ctxt == NULL) {
        xmlSchemaVErr(ctxt, NULL, XML_SCHEMAV_INTERNAL,
	    "Internal error: xmlSchemaValidateElementByDeclaration, "
	    "bad arguments.\n",
	    NULL, NULL);
        return (-1);
    }

    elem = ctxt->node;   

    /*
    * cvc-elt (3.3.4) : 1
    */
    if (elemDecl == NULL) {
	xmlSchemaVCustomErr(ctxt,
	    XML_SCHEMAV_CVC_ELT_1, 
	    elem, NULL,
	    "No matching declaration available", NULL);
        return (ctxt->err);
    }
    /*
    * cvc-elt (3.3.4) : 2
    */
    if (elemDecl->flags & XML_SCHEMAS_ELEM_ABSTRACT) {
	xmlSchemaVCustomErr(ctxt,
	    XML_SCHEMAV_CVC_ELT_2,
	    elem, NULL, 
	    "The element declaration is abstract", NULL);
        return (ctxt->err);
    }
     
    /*
    * cvc-elt (3.3.4) : 3
    * Handle 'xsi:nil'.
    */
    
    attr = xmlHasNsProp(elem, BAD_CAST "nil", xmlSchemaInstanceNs);
    if (attr != NULL) {
	attrValue = xmlNodeGetContent((xmlNodePtr) attr);	
	ctxt->node = (xmlNodePtr) attr;
	ctxt->cur = attr->children;	
	ret = xmlSchemaValidateSimpleTypeValue(ctxt, 
	    xmlSchemaGetBuiltInType(XML_SCHEMAS_BOOLEAN),
	    BAD_CAST attrValue, 1, 1, 1, 1);
	ctxt->node = elem;
	ctxt->type = (xmlSchemaTypePtr) elemDecl;
	if (ret < 0) {
	    xmlSchemaVCustomErr(ctxt,
		XML_SCHEMAV_INTERNAL, 
		(xmlNodePtr) attr, (xmlSchemaTypePtr) elemDecl,
		"Internal error: xmlSchemaValidateElementByDeclaration, "
		"validating the attribute 'xsi:nil'", NULL);
	    if (attrValue != NULL)
		xmlFree(attrValue);
	    return (-1);
	} 
	if ((elemDecl->flags & XML_SCHEMAS_ELEM_NILLABLE) == 0) {
	/* 
	* cvc-elt (3.3.4) : 3.1 
	    */
	    xmlSchemaVCustomErr(ctxt, 
		XML_SCHEMAV_CVC_ELT_3_1, 
		elem, NULL,
		"The element is not 'nillable'", NULL);	
	} else {		    
	    if (xmlStrEqual(BAD_CAST attrValue, BAD_CAST "true") ||
		xmlStrEqual(BAD_CAST attrValue, BAD_CAST "1")) {		
		ret = 0;
		/* 
		* cvc-elt (3.3.4) : 3.2.1 
		*/
		elemHasContent = xmlSchemaHasElemOrCharContent(elem);
		if (elemHasContent == 1) {
		    xmlSchemaVCustomErr(ctxt, 
			XML_SCHEMAV_CVC_ELT_3_2_1, 
			/* XML_SCHEMAS_ERR_NOTEMPTY, */
			elem, (xmlSchemaTypePtr) elemDecl,
			"The 'nilled' element must have no character or "
			"element content", NULL);
		    ret = XML_SCHEMAV_CVC_ELT_3_2_1;
		}
		/* 
		* cvc-elt (3.3.4) : 3.2.2 
		*/
		if ((elemDecl->flags & XML_SCHEMAS_ELEM_FIXED) &&
		    (elemDecl->value != NULL)) {
		    xmlSchemaVCustomErr(ctxt, XML_SCHEMAV_CVC_ELT_3_2_2, 
			/* XML_SCHEMAS_ERR_HAVEDEFAULT, */
			elem, (xmlSchemaTypePtr) elemDecl,
			"There is a fixed value constraint defined for "
			"the 'nilled' element", NULL);		    
		    ret = XML_SCHEMAV_CVC_ELT_3_2_2;
		}
		if (ret == 0)
		    nilled = 1;		
	    }
	}
	if (attrValue != NULL)
	    xmlFree(attrValue);
    }
    

    actualType = elemDecl->subtypes;
    /* 
    * cvc-elt (3.3.4) : 4 
    * Handle 'xsi:type'.
    */
    
    attr = xmlHasNsProp(elem, BAD_CAST "type",  xmlSchemaInstanceNs);
    if (attr != NULL) {	
	xmlChar *nsName = NULL, *local = NULL;
	
	/*
	* TODO: We should report a *warning* that the type was overriden
	* by the instance.
	*/
	
	/* 
	* cvc-elt (3.3.4) : 4.1 
	*/
	attrValue = xmlNodeGetContent((xmlNodePtr) attr);
	ret = xmlSchemaValQNameAcquire(attrValue, attr->parent,	
	    &nsName, &local);
	if (ret < 0) {
	    xmlSchemaVCustomErr(ctxt,
		XML_SCHEMAV_INTERNAL, 
		(xmlNodePtr) attr, (xmlSchemaTypePtr) elemDecl,
		"Internal error: xmlSchemaValidateElementByDeclaration, "
		"validating the attribute 'xsi:type'", NULL);;
	    FREE_AND_NULL(attrValue)
		FREE_AND_NULL(nsName)
		FREE_AND_NULL(local)
		return (-1);
	} else if (ret == 1) {
	    xmlSchemaVSimpleTypeErr(ctxt,
		XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1,
		(xmlNodePtr) attr, attrValue, 
		xmlSchemaGetBuiltInType(XML_SCHEMAS_QNAME));
	} else if (ret == 2) {
	    xmlSchemaVCustomErr(ctxt,
		XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1,
		(xmlNodePtr) attr, 
		xmlSchemaGetBuiltInType(XML_SCHEMAS_QNAME),
		"The QName value '%s' has no "
		"corresponding namespace declaration in scope", 
		attrValue);	    	    
	} else {
	    /*
	    * cvc-elt (3.3.4) : 4.2 
	    */
	    actualType = xmlSchemaGetType(ctxt->schema, local, nsName);
	    if (actualType == NULL) {	  
		xmlChar *strA = NULL;
		
		xmlSchemaVCustomErr(ctxt,
		    XML_SCHEMAV_CVC_ELT_4_2,
		    (xmlNodePtr) attr, 
		    xmlSchemaGetBuiltInType(XML_SCHEMAS_QNAME),
		    "The value %s does not resolve to a type "
		    "definition", 
		    xmlSchemaFormatNsUriLocal(&strA, nsName, local));
		FREE_AND_NULL(strA);    
	    } else {		
		/*
		* URGENT TODO: cvc-elt (3.3.4) : 4.3 (Type Derivation OK)
		*/		
	    }
	}
	FREE_AND_NULL(attrValue)
	FREE_AND_NULL(nsName)
	FREE_AND_NULL(local)
    }		
    /* TODO: Change the handling of missing types according to
    * the spec.
    */
    if (actualType == NULL) {
    	xmlSchemaVCustomErr(ctxt, 
    	    XML_SCHEMAV_CVC_TYPE_1,
    	    elem, (xmlSchemaTypePtr) elemDecl, 
    	    "The type definition is absent", NULL);
    	return (XML_SCHEMAV_CVC_TYPE_1);
    }
    
    /*
    * TODO: Since this should be already checked by the content model automaton,
    * and we want to get rid of the XML_SCHEMAS_ERR... types, the error code
    * has been changed to XML_SCHEMAV_INTERNAL.
    */
    /*
    if (child == NULL) {
        if (decl->minOccurs > 0) {
            xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		 XML_SCHEMAS_ERR_MISSING, 
		"Element %s: missing child %s\n",
		node->name, decl->name);
        }
        return (ctxt->err);
    } 
    */
    /*
     * Verify the element matches
     * TODO, FIXME: Can this still happen here? Isn't this already checked
     * by the content model automaton?         
    if (!xmlStrEqual(child->name, decl->name)) {
        xmlSchemaVErr3(ctxt, node, XML_SCHEMAV_INTERNAL,
	     XML_SCHEMAS_ERR_WRONGELEM, 
	    "Element %s: missing child %s found %s\n",
	    node->name, decl->name, child->name);
        return (ctxt->err);
    }
    */    
    if (elemHasContent == -1)
	elemHasContent = xmlSchemaHasElemOrCharContent(elem);
    /*
    * cvc-elt (3.3.4) : 5 
    * The appropriate case among the following must be true:
    */
    /*
    * cvc-elt (3.3.4) : 5.1 
    * If the declaration has a {value constraint}, 
    * the item has neither element nor character [children] and 
    * clause 3.2 has not applied, then all of the following must be true:
    */
    if ((elemHasContent == 0) && (nilled == 0) && (elemDecl->value != NULL)) {
	/*
	* cvc-elt (3.3.4) : 5.1.1 
	* If the ·actual type definition· is a ·local type definition·
	* then the canonical lexical representation of the {value constraint}
	* value must be a valid default for the ·actual type definition· as 
	* defined in Element Default Valid (Immediate) (§3.3.6). 
	*/
	/* 
	* NOTE: 'local' above means types aquired by xsi:type.
	*/
	ret = 0;
	if (actualType != elemDecl->subtypes) {
	    xmlSchemaCreatePCtxtOnVCtxt(ctxt);
	    ret = xmlSchemaCheckCOSValidDefault(ctxt->pctxt, ctxt, actualType, 
		elemDecl->value, NULL);
	    if (ret < 0) {
		xmlSchemaVCustomErr(ctxt, 
		    XML_SCHEMAV_INTERNAL, 
		    elem, actualType,
		    "Internal error: xmlSchemaValidateElementByDeclaration, "
		    "validating a default value", NULL);
		return (-1);
	    }
	}
	/*
	* cvc-elt (3.3.4) : 5.1.2 
	* The element information item with the canonical lexical 
	* representation of the {value constraint} value used as its 
	* ·normalized value· must be ·valid· with respect to the 
	* ·actual type definition· as defined by Element Locally Valid (Type)
	* (§3.3.4).
	*/
	/*
        * Disable validation of the simple content, since it was already
	* done above.
	*/
	if (ret == 0) {
	    if (actualType != elemDecl->subtypes)
		ret = xmlSchemaValidateElementByType(ctxt, actualType, 0);
	    else
		ret = xmlSchemaValidateElementByType(ctxt, actualType, 0);
	    ctxt->node = elem;
	    if (ret < 0) {
		xmlSchemaVCustomErr(ctxt, 
		    XML_SCHEMAV_INTERNAL, 
		    elem, actualType,
		    "Internal error: xmlSchemaValidateElementByDeclaration, "
		    "validating against the type", NULL);
		return (-1);
	    }
	    /*
	    * PSVI: Create a text node on the instance element.
	    */
	    if (ctxt->options & XML_SCHEMA_VAL_VC_I_CREATE) {
		xmlNodePtr textChild;
		
		textChild = xmlNewText(elemDecl->value);
		if (textChild == NULL) {
		    xmlSchemaVCustomErr(ctxt, 
			XML_SCHEMAV_INTERNAL, 
			elem, actualType,
			"Internal error: xmlSchemaValidateElementByDeclaration, "
			"could not create a default text node for the instance", 
			NULL);
		} else
		    xmlAddChild(elem, textChild);	    
	    }
	}

    } else {	
	/*
	* 5.2.1 The element information item must be ·valid· with respect 
	* to the ·actual type definition· as defined by Element Locally 
	* Valid (Type) (§3.3.4).
	*/
	ret = xmlSchemaValidateElementByType(ctxt, actualType, 1);
	ctxt->node = elem;
	if (ret < 0) {
	    xmlSchemaVCustomErr(ctxt, 
		XML_SCHEMAV_INTERNAL, 
		elem, actualType,
		"Internal error: xmlSchemaValidateElementByDeclaration, "
		"validating a default value", NULL);
	    return (-1);
	}
	/*
	* 5.2.2 If there is a fixed {value constraint} and clause 3.2 has 
	* not applied, all of the following must be true:
	*/

	if ((elemDecl->flags & XML_SCHEMAS_ELEM_FIXED) && (nilled == 0)) {
	    /*
	    * 5.2.2.1 The element information item must have no element 
	    * information item [children].
	    *
	    * TODO REDUNDANT: If the actual type exists, the above call  to 
	    * xmlSchemaValidateElementByType will already check for element 
	    * nodes.
	    */
	    if (xmlSchemaHasElemContent(elem)) {
		xmlSchemaVCustomErr(ctxt, 
		    XML_SCHEMAV_CVC_ELT_5_2_2_1, 
		    elem, (xmlSchemaTypePtr) elemDecl,
		    "Elements in the content are not allowed if it is "
		    "constrained by a fixed value", NULL);
	    } else {
		/*
		* 5.2.2.2 The appropriate case among the following must 
		* be true:
		*/
		
		if (actualType->contentType == XML_SCHEMA_CONTENT_MIXED) {
		    xmlChar *value;
		    /*
		    * 5.2.2.2.1 If the {content type} of the ·actual type 
		    * definition· is mixed, then the *initial value* of the 
		    * item must match the canonical lexical representation 
		    * of the {value constraint} value.
		    *
		    * ... the *initial value* of an element information 
		    * item is the string composed of, in order, the 
		    * [character code] of each character information item in 
		    * the [children] of that element information item.
		    */
		    value = xmlNodeListGetString(elem->doc, elem->children, 1);
		    if (! xmlStrEqual(BAD_CAST value, elemDecl->value)) {
			/* 
			* TODO: Report invalid & expected values as well.
			* TODO: Implement the cononical stuff.
			*/
			xmlSchemaVCustomErr(ctxt, 
			    XML_SCHEMAV_CVC_ELT_5_2_2_2_1, 
			    elem, (xmlSchemaTypePtr) elemDecl,
			    "The value does not match the cononical "
			    "lexical representation of the fixed constraint", 
			    NULL);
		    }
		    if (value != NULL)
			xmlFree(value);
		} else if ((actualType->contentType == 
		    XML_SCHEMA_CONTENT_SIMPLE) || 
		    (actualType->contentType == XML_SCHEMA_CONTENT_BASIC)) {
		    xmlChar *value;

		    /*
		    * 5.2.2.2.2 If the {content type} of the ·actual type 
		    * definition· is a simple type definition, then the 
		    * *actual value* of the item must match the canonical 
		    * lexical representation of the {value constraint} value.
		    */
		    /*
		    * TODO: *actual value* is the normalized value, impl. this.
		    * TODO: Report invalid & expected values as well.
		    * TODO: Implement the cononical stuff.
		    * 
		    */
		    value = xmlNodeListGetString(elem->doc, elem->children, 1);
		    if (! xmlStrEqual(BAD_CAST value, elemDecl->value)) {
			xmlSchemaVCustomErr(ctxt, 
			    XML_SCHEMAV_CVC_ELT_5_2_2_2_2, 
			    elem, (xmlSchemaTypePtr) elemDecl,
			    "The normalized value does not match the cononical "
			    "lexical representation of the fixed constraint", 
			    NULL);
		    }
		    if (value != NULL)
			xmlFree(value);
		    
		}
		/*
		* TODO: What if the content type is not 'mixed' or simple?
		*/

	    }
	    
	}
    }

    /*
    * TODO: 6 The element information item must be ·valid· with respect to each of 
    * the {identity-constraint definitions} as per Identity-constraint 
    * Satisfied (§3.11.4).
    */

    /*
    * TODO: 7 If the element information item is the ·validation root·, it must be 
    * ·valid· per Validation Root Valid (ID/IDREF) (§3.3.4).
    */
               
    return (ctxt->err);
}

/**
 * xmlSchemaValidateElementByWildcardInternal:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Represents the recursive portion of xmlSchemaValidateElementByWildcard. 
 * Not intended to be used by other functions.
 *
 * Returns 0 if the element is valid, a positive error code
 * number otherwise and -1 in case of an internal error.
 */
static int
xmlSchemaValidateElementByWildcardInternal(xmlSchemaValidCtxtPtr ctxt,
					   xmlSchemaWildcardPtr wild, 
					   xmlNodePtr node)
{        
    const xmlChar *uri;
    int ret = 0;
    xmlNodePtr child;

    if (ctxt->xsiAssemble) {	
	ret = xmlSchemaAssembleByXSIElem(ctxt, ctxt->node);
	if (ret == -1) {
	    xmlSchemaVCustomErr(ctxt, 
		XML_SCHEMAV_INTERNAL,
		ctxt->node, NULL, 	
		"Internal error: xmlSchemaValidateElement, "
		"assembling schema by xsi", NULL);
	    return (-1);
	}
	/*
	* NOTE: We won't react on schema parser errors here.
	* TODO: But a warning would be nice.
	*/
    }    
    if (wild->processContents != XML_SCHEMAS_ANY_SKIP) {
	xmlSchemaElementPtr decl = NULL;

	if (node->ns != NULL)
	    decl = xmlHashLookup3(ctxt->schema->elemDecl,
	    node->name, node->ns->href, NULL);
	else 
	    decl = xmlHashLookup3(ctxt->schema->elemDecl, node->name, NULL, NULL);
	if (decl != NULL) {		    
	    ctxt->node = node;	
	    ret = xmlSchemaValidateElementByDeclaration(ctxt, decl);
	    if (ret < 0) {		
		xmlSchemaVErr(ctxt, node, XML_SCHEMAV_INTERNAL,
		    "Internal error: xmlSchemaValidateAnyInternal, "
		    "validating an element in the context of a wildcard.",
		    NULL, NULL);
	    }
	    return (ret);
	} else if (wild->processContents == XML_SCHEMAS_ANY_STRICT) {
	    /* TODO: Change to proper error code. */
	    xmlSchemaVWildcardErr(ctxt, XML_SCHEMAV_CVC_ELT_1,
		node, wild, "No matching global declaration available");
	    return (ctxt->err);
	}
    }
    if (node->children != NULL) {	   
	child = node->children;
	do {
	    if (child->type == XML_ELEMENT_NODE) {
		if (child->ns != NULL)
		    uri = child->ns->href;
		else
		    uri = NULL;
		if (xmlSchemaMatchesWildcardNs(wild, uri) == 0) {
		    /* TODO: error code. */
		    xmlSchemaVWildcardErr(ctxt, XML_SCHEMAV_ELEMENT_CONTENT,
			child, wild, 
			"The namespace of the element is not allowed");
		    return (ctxt->err);  
		}
		ret = xmlSchemaValidateElementByWildcardInternal(ctxt, 
		    wild, child);
		if (ret != 0)
		    return (ret);		
	    }
	    child = child->next;
	} while  (child != NULL);
    }
    return (0);
}

/**
 * xmlSchemaValidateElementContByWildcard:
 * @ctxt:  a schema validation context
 *
 * Returns 0 if the element is valid, a positive error code
 * number otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaValidateElementByWildcard(xmlSchemaValidCtxtPtr ctxt, 
				   xmlSchemaTypePtr type)
{       
    if ((type == NULL) || (type->type != XML_SCHEMA_TYPE_ANY) ||
	(ctxt->node == NULL)) {
	xmlSchemaVCustomErr(ctxt,
	    XML_SCHEMAV_INTERNAL, ctxt->node, NULL,
	    "Internal error: xmlSchemaValidateElementByWildcard, "
	    "bad arguments", NULL);
	return (-1);
    }
    return(xmlSchemaValidateElementByWildcardInternal(ctxt, 
	    type->attributeWildcard, ctxt->node));
}

/**
 * xmlSchemaValidateAnyTypeContent:
 * @ctxt:  a schema validation context
 * @node: the current element
 *
 * This one validates the content of an element of the type
 * 'anyType'. The process contents of the wildcard of 'anyType' is "lax", 
 * thus elements in the subtree will be validated, if a corresponding
 * declaration in the schema exists.
 *
 * Returns 0 if the element and its subtree is valid, a positive error code
 * otherwise and -1 in case of an internal or API error.
 */
static int
xmlSchemaValidateElementByAnyType(xmlSchemaValidCtxtPtr ctxt, 
				  xmlSchemaTypePtr type)
{
    xmlSchemaTypePtr oldtype;
    xmlNodePtr top, cur;
    xmlSchemaElementPtr decl;
    int skipContent, ret;

    if ((type == NULL) || (ctxt->node == NULL))
	return (-1);

    if (ctxt->node->children == NULL) 
	return (0);

    oldtype = ctxt->type;
    top = ctxt->node;        
    /*
    * STREAM: Child nodes are processed.
    */
    cur = ctxt->node->children;
    while (cur != NULL) {
	skipContent = 0;
	if (cur->type == XML_ELEMENT_NODE) {
	    /*
	    * The process contents of the wildcard is "lax", thus
	    * we need to validate the element if a declaration
	    * exists.
	    */		
	    if (cur->ns != NULL)
		decl = xmlHashLookup3(ctxt->schema->elemDecl,
		    cur->name, cur->ns->href, NULL);
	    else 
		decl = xmlHashLookup3(ctxt->schema->elemDecl, cur->name, NULL, NULL);	    
	    if (decl != NULL) {		    
		ctxt->node = cur;
		ret = xmlSchemaValidateElementByDeclaration(ctxt, decl);
		ctxt->node = top;
		if (ret < 0) {		
		    xmlSchemaVErr(ctxt, cur, XML_SCHEMAV_INTERNAL,
			"Internal error: xmlSchemaValidateAnyTypeContent, "
			"validating an element in the context of a wildcard.",
			NULL, NULL);
		    return (ret);
		} else if (ret > 0)
		    return (ret);
		skipContent = 1;
	    }
	}   
	/*
	* Browse the full subtree, deep first.
	*/
        if ((skipContent == 0) && (cur->children != NULL)) {
	    /* deep first */
	    cur = cur->children;
	} else if ((cur != top) && (cur->next != NULL)) {
	    /* then siblings */
	    cur = cur->next;
	} else if (cur != top) {
	    /* go up to parents->next if needed */
	    while (cur != top) {
	        if (cur->parent != NULL)
		    cur = cur->parent;
		if ((cur != top) && (cur->next != NULL)) {
		    cur = cur->next;
		    break;
		}
		if (cur->parent == NULL) {
		    cur = NULL;
		    break;
		}
	    }
	    /* exit condition */
	    if (cur == top) 
	        cur = NULL;
	} else
	    break;
    }
    ctxt->type = oldtype;
    return (0);
}

/**
 * xmlSchemaValidateElementByComplexType:
 * @ctxt:  a schema validation context
 * @node:  the top node.
 *
 * Validate the content of an element expected to be a complex type type
 * xmlschema-1.html#cvc-complex-type
 * Validation Rule: Element Locally Valid (Complex Type)
 *
 * Returns 0 if the element is schemas valid, a positive error code
 * number otherwise and -1 in case of internal or API error.
 * Note on reported errors: Although it might be nice to report
 * the name of the simple/complex type, used to validate the content
 * of a node, it is quite unnecessary: for global defined types
 * the local name of the element is equal to the NCName of the type,
 * for local defined types it makes no sense to output the internal
 * computed name of the type. TODO: Instead, one should attach the 
 * struct of the type involved to the error handler - this allows
 * the report of any additional information by the user.
 */
static int
xmlSchemaValidateElementByComplexType(xmlSchemaValidCtxtPtr ctxt, 
				      xmlSchemaTypePtr type,
				      int valSimpleContent)
{
    xmlSchemaTypePtr oldtype;    
    xmlNodePtr elem, child;
    int ret = 0;
    const xmlChar *nsUri;    
    xmlSchemaAttrStatePtr attrs = NULL, attrTop = NULL;

    if ((ctxt == NULL) || (type->type != XML_SCHEMA_TYPE_COMPLEX))
	return (-1);

    oldtype = ctxt->type;
    ctxt->type = type;
    elem = ctxt->node;

    /*
    * Verify the attributes
    */
    /*
    * TODO: This "attrTop" thing is not needed any more.
    */  
    /* NOTE: removed, since a check for abstract is
    * done in the cvc-type constraint.
    *
    *
    * if (type->flags & XML_SCHEMAS_TYPE_ABSTRACT) {
    *	xmlSchemaVComplexTypeErr(ctxt, 
    *	    XML_SCHEMAV_CVC_COMPLEX_TYPE_1,
    *	    elem, type, 
    *	    "The type definition is abstract");
    *	return (XML_SCHEMAV_CVC_COMPLEX_TYPE_1);
    *}
    */
    
    attrs = ctxt->attr;    
    attrTop = ctxt->attrTop;   
    /*
    * STREAM: Attribute nodes are processed.
    */
    xmlSchemaRegisterAttributes(ctxt, elem->properties);     
    xmlSchemaValidateAttributes(ctxt, elem, type);
    if (ctxt->attr != NULL)
	xmlSchemaFreeAttributeStates(ctxt->attr);
    ctxt->attr = attrs;    
    ctxt->attrTop = attrTop;    

    /*
    * TODO: This one creates a regexp even if no content
    * model was defined. Somehow ->contModel is always not NULL
    * for complex types, even if they are empty.
    * TODO: Check if the obove still occurs.
    */              
    switch (type->contentType) {
	case XML_SCHEMA_CONTENT_EMPTY: {
	    /*
	    * 1 If the {content type} is empty, then the element information 
	    * item has no character or element information item [children].
	    */
	    /*
	    * TODO: Is the entity stuff correct?
	    */
	    if (xmlSchemaHasElemOrCharContent(elem) == 1) {	    	    
		xmlSchemaVComplexTypeErr(ctxt, 
		    XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1,
		    elem, type, 
		    "Character or element content is not allowed, "
		    "because the content type is empty");
            }	 
            break;
	}
	case XML_SCHEMA_CONTENT_MIXED:
	    if ((type->subtypes == NULL) && 
		(type->baseType->builtInType == XML_SCHEMAS_ANYTYPE)) {
		/*
		* The type has 'anyType' as its base and no content model
		* is defined -> use 'anyType' as the type to validate
		* against.
		*/
		ret = xmlSchemaValidateElementByAnyType(ctxt, type->baseType);
		/* TODO: Handle -1. */
		break;
	    }
	    /* No break on purpose. */
        case XML_SCHEMA_CONTENT_ELEMENTS:
        {
	    xmlRegExecCtxtPtr oldregexp = NULL;
	    xmlChar *values[10];
	    int terminal, nbval = 10, nbneg;
	    
	    /*
	    * Content model check initialization.
	    */
	    if (type->contModel != NULL) {					
		oldregexp = ctxt->regexp;
		ctxt->regexp = xmlRegNewExecCtxt(type->contModel,
		    (xmlRegExecCallbacks)
		    xmlSchemaValidateCallback, ctxt);
#ifdef DEBUG_AUTOMATA
		xmlGenericError(xmlGenericErrorContext, "====> %s\n", elem->name);
#endif
	    }
	    /*
	    * STREAM: Children are processed.
	    */
	    child = elem->children;
	    while (child != NULL) {		
		if (child->type == XML_ELEMENT_NODE) {
		    if (child->ns != NULL)
			nsUri = child->ns->href;
		    else
			nsUri = NULL;
		    ret = xmlRegExecPushString2(ctxt->regexp,
			child->name, nsUri, child);		    
		    /*
		    * URGENT TODO: Could we anchor an error report
		    * here to notify of invalid elements?
		    * TODO: Perhaps it would be better to report 
		    * only the first erroneous element and then break.
		    */
#ifdef DEBUG_AUTOMATA
		    if (ret < 0)
			xmlGenericError(xmlGenericErrorContext,
			"  --> %s Error\n", child->name);
		    else
			xmlGenericError(xmlGenericErrorContext,
			"  --> %s\n", child->name);
#endif
		    if (ret < 0) {
			xmlRegExecErrInfo(ctxt->regexp, NULL, &nbval, &nbneg,
			    &values[0], &terminal);
			xmlSchemaVComplexTypeElemErr(ctxt, 
			    XML_SCHEMAV_ELEMENT_CONTENT,
			    child, NULL/* type */, 
			    "This element is not expected",
			    nbval, nbneg, values);
			ret = 1;
			/*
			* Note that this will skip further validation of the
			* content.
			*/
			break;
		    }
		} else if ((type->contentType == XML_SCHEMA_CONTENT_ELEMENTS) && 
		    /* 
		    * TODO: Ask Daniel if this are all character nodes.
		    */
		    (((child->type == XML_TEXT_NODE) && (!IS_BLANK_NODE(child))) ||
		     (child->type == XML_ENTITY_NODE) ||		    		    
		     (child->type == XML_ENTITY_REF_NODE) ||		    
		     (child->type == XML_CDATA_SECTION_NODE))) {		    
		    /* 
		    * 2.3 If the {content type} is element-only, then the 
		    * element information item has no character information 
		    * item [children] other than those whose [character 
		    * code] is defined as a white space in [XML 1.0 (Second 
		    * Edition)].
		    */			
		    xmlSchemaVComplexTypeErr(ctxt, 
			XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3,
			elem, type, 
			"Character content is not allowed, "
			"because the content type is element-only");
		    ret = 1;
		    break;
		}
		child = child->next;		    
	    }    
	    /*
	    * Content model check finalization.
	    */
       	    if (type->contModel != NULL) {
		if (ret == 0) {
		    xmlRegExecNextValues(ctxt->regexp, &nbval, &nbneg,
			&values[0], &terminal);
		    if (nbval + nbneg != 0) {
			/*
			* If a next value still exists, I does not have to
			* mean that there's an element missing, since it
			* might be an optional element. So double check it.
			*/
			ret = xmlRegExecPushString(ctxt->regexp,
			    NULL, NULL);
			if (ret <= 0) {
			    ret = 1;
    			    xmlSchemaVComplexTypeElemErr(ctxt,
				XML_SCHEMAV_ELEMENT_CONTENT,
				elem, type, "Missing child element(s)",
				nbval, nbneg, values);			    
			} else
			    ret = 0;			
#ifdef DEBUG_AUTOMATA
			xmlGenericError(xmlGenericErrorContext,
			    "====> %s : %d\n", elem->name, ret);
#endif
		    }		    
#ifdef DEBUG_CONTENT
		    if (ret == 0)
			xmlGenericError(xmlGenericErrorContext,
			    "Element %s content check succeeded\n",
			    elem->name);
#endif
		}
		xmlRegFreeExecCtxt(ctxt->regexp);
		ctxt->regexp = oldregexp;
	    }
	}
            break;
	case XML_SCHEMA_CONTENT_SIMPLE:
        case XML_SCHEMA_CONTENT_BASIC:
	    /*
	    * If the simple content was already validated 
	    * (e.g. a default value), the content need not
	    * to be validated again.
	    */
	if (valSimpleContent == 1) {
	    xmlChar *value = NULL;
	    /*
	    * We hit a complexType with a simpleContent resolving
	    * to a user derived or built-in simple type.
	    */
	    /* 
	    * 2.2 If the {content type} is a simple type definition, 
	    * then the element information item has no element 
	    * information item [children], and the ·normalized value· 
	    * of the element information item is ·valid· with respect 
	    * to that simple type definition as defined by String 
	    * Valid (§3.14.4).
	    */	  
	    /*
	    * STREAM: Children are processed.
	    */
	    child = elem->children;
	    while (child != NULL) {
		/*
		* TODO: Could the entity stuff produce elements
		* as well?
		*/
                if (child->type == XML_ELEMENT_NODE) {
		    xmlSchemaVComplexTypeErr(ctxt,
			XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2,
			elem, type, 
			"Element content is not allowed, because "
			"the content type is a simple type");
		    ret = XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2;
		    break;
		}
		child = child->next;		    
	    }	
	    ctxt->node = elem;
	    ctxt->cur = elem->children;
	    if (ret == 0) {
		/*
		* Validate the character content against a simple type.
		*/
		/*
		* STREAM: Children are processed.
		*/
		if (elem->children == NULL)
		    value = NULL;
		else
		    value = xmlNodeGetContent(elem); 
		/*
		* URGENT TODO: Should facets for the simple type validation be 
		* disabled, if the derivation of facets for complex types 
		* is implemented?
		*/
		/*
		* NOTE: This call won't check the correct types of the
		* content nodes, since this should be done here.
		*/
		ret = xmlSchemaValidateSimpleTypeValue(ctxt, type, value, 1, 1, 1, 0);
		if (ret > 0) {	
		    /*
		    * NOTE: Although an error will be reported by 
		    * xmlSchemaValidateSimpleTypeValue, the spec wants
		    * a specific complex type error to be reported 
		    * additionally.
		    */
		    xmlSchemaVComplexTypeErr(ctxt, 
			XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2,
			elem, type,  
			"The character content is not valid");
		    ret = XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2;
		} else if (ret < 0) {
		    xmlSchemaVErr(ctxt, elem, XML_SCHEMAV_INTERNAL,
			"Internal error: xmlSchemaValidateComplexType, "
			"Element '%s': Error while validating character "
			"content against complex type '%s'.\n",
			elem->name, type->name);
		    if (value != NULL)
			xmlFree(value); 
		    ctxt->type = oldtype;
		    return (-1);
		}
	    }	    
	    if (ret == 0) {
		/* 
		* Apply facets of the complexType. Be sure to pass the 
		* built-in type to xmlSchemaValidateFacetsInternal.
		*/	    
		/* URGENT TODO: I don't know yet if the facets of the simple type
		* are used, or if the facets, defined by this complex type,
		* are to be used only. This here applies both facet sets.
		*/	    

		ret = xmlSchemaValidateFacetsInternal(ctxt, 
		    type, value, 0, 1);
		if (ret > 0) {
		    xmlSchemaVComplexTypeErr(ctxt, 
			XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2,
			elem, type, 
			"The character content is not valid");
		    ret = XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2;
		} else if (ret < 0) {
		    xmlSchemaVErr(ctxt, elem, XML_SCHEMAV_INTERNAL,
			"Internal error: xmlSchemaValidateComplexType, "
			"Element '%s': Error while validating character "
			"content against complex type '%s'; failed to "
			"apply facets.\n",
			type->name, NULL);
		    if (value != NULL)
			xmlFree(value); 
		    ctxt->type = oldtype;
		    return (-1);
		}
	    }
	    if (value != NULL)
		xmlFree(value);

	}
	    break;
        default:
            TODO xmlGenericError(xmlGenericErrorContext,
                                 "unimplemented content type %d\n",
                                 type->contentType);
    }
    ctxt->type = oldtype;
    return (ctxt->err);
}

/**
 * xmlSchemaValidateElementByType:
 * @ctxt:  a schema validation context
 * @elem:  an element
 * @type:  the list of type declarations
 *
 * Validation Rule: Element Locally Valid (Type).
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateElementByType(xmlSchemaValidCtxtPtr ctxt,
			       xmlSchemaTypePtr type,
			       int valSimpleContent)
{
    int ret;

   
    if ((ctxt == NULL) || (type == NULL)) {
        xmlSchemaVCustomErr(ctxt, XML_SCHEMAV_INTERNAL, NULL, NULL,
	    "Internal error: xmlSchemaValidateElementByType, "
	    "bad arguments", NULL);
        return (-1);    
    }    	
    /* 
    * This one is called by "xmlSchemaValidateElementByDeclaration".
    * It will forward to the proper validation 
    * procedures for the given type.
    */        
    if (type == NULL) {
    	xmlSchemaVCustomErr(ctxt, 
    	    XML_SCHEMAV_CVC_TYPE_1,
    	    ctxt->node, NULL, 
    	    "The type definition is absent", NULL);
    	return (XML_SCHEMAV_CVC_TYPE_1);
    }
    
    if (type->flags & XML_SCHEMAS_TYPE_ABSTRACT) {
    	xmlSchemaVCustomErr(ctxt, 
    	    XML_SCHEMAV_CVC_TYPE_2,
    	    ctxt->node, type, 
    	    "The type definition is abstract", NULL);
    	return (XML_SCHEMAV_CVC_TYPE_2);
    }

    switch (type->type) {
	case XML_SCHEMA_TYPE_COMPLEX:
            ret = xmlSchemaValidateElementByComplexType(ctxt, type,
		valSimpleContent);
            break;
	case XML_SCHEMA_TYPE_SIMPLE:
            ret = xmlSchemaValidateElementBySimpleType(ctxt, type,
		valSimpleContent);
            break;
	case XML_SCHEMA_TYPE_BASIC:
	    if (type->builtInType == XML_SCHEMAS_ANYTYPE)
		ret = xmlSchemaValidateElementByAnyType(ctxt, type);
	    else
		ret = xmlSchemaValidateElementBySimpleType(ctxt, type,
		    valSimpleContent);
	    break;
	default:
	    ret = -1;
	    break;
    }	
    if (ret == -1)
	return (-1);
    else
	return (ret);
}


static int
xmlSchemaCheckAttrLocallyValid(xmlSchemaValidCtxtPtr ctxt,
			       xmlSchemaAttributePtr decl,
			       xmlSchemaAttrStatePtr state,
			       xmlAttrPtr attr)
{
    xmlChar *value;
    const xmlChar *defValue;
    xmlSchemaValPtr defVal;
    int fixed;
    int ret;

    if (decl->subtypes == NULL) {
	state->state = XML_SCHEMAS_ATTR_TYPE_NOT_RESOLVED;
	return (XML_SCHEMAS_ATTR_TYPE_NOT_RESOLVED);
    }
    value = xmlNodeListGetString(attr->doc, attr->children, 1);
    ctxt->node = (xmlNodePtr) attr;
    ctxt->cur = attr->children;
    /*
    * NOTE: This call also checks the content nodes for correct type.
    */
    ret = xmlSchemaValidateSimpleTypeValue(ctxt, decl->subtypes,
	value, 1, 1, 1, 1);
    	    
    /*
    * Handle 'fixed' attributes.
    */
    if (ret > 0) {
	state->state = XML_SCHEMAS_ATTR_INVALID_VALUE;
	/*
	* NOTE: Fixed value constraints will be not
	* applied if the value was invalid, because: 
	* 1. The validation process does not return a precomputed 
	*    value.
	* 2. An invalid value implies a violation of a fixed 
	*    value constraint.
	*/
    } else if (ret == 0) {
	state->state = XML_SCHEMAS_ATTR_CHECKED;
	if (xmlSchemaGetEffectiveValueConstraint(decl, 
	    &fixed, &defValue, &defVal) && (fixed == 1)) {
	    /*
	    * cvc-au : Attribute Locally Valid (Use)
	    * For an attribute information item to be·valid· 
	    * with respect to an attribute use its ·normalized 
	    * value· must match the canonical lexical representation
	    * of the attribute use's {value constraint} value, if it 
	    * is present and fixed.
	    */
	    /* 
	    * NOTE: the validation context holds in ctxt->value the
	    * precomputed value of the attribute; well for some types,
	    * fallback to string comparison if no computed value 
	    * exists.
	    */
	    if (((ctxt->value != NULL) && 
		(xmlSchemaCompareValues(ctxt->value, defVal) != 0)) ||
		((ctxt->value == NULL) &&
		(! xmlStrEqual(defValue, BAD_CAST value)))) {
		state->state = 
		    XML_SCHEMAS_ATTR_INVALID_FIXED_VALUE;			
	    }
	}
    }  
    if (value != NULL) {
	xmlFree(value);
    }
    return (ret);
}

/**
 * xmlSchemaValidateAttributes:
 * @ctxt:  a schema validation context
 * @elem:  an element
 * @type:  the complexType holding the attribute uses
 *
 * Validate the attributes of an element.
 *
 * 1. Existent, invalid attributes are reported in the form 
 *    "prefix:localName". 
 *    Reason: readability - it is easier to find the actual XML 
 *    representation of the attributes QName.
 * 2. Missing attributes are reported in the form 
 *    {"URI", "localName"}.
 *    This is necessary, since the the prefix need not to be declared
 *    at all, and thus is not computable.
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateAttributes(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr elem, xmlSchemaTypePtr type)
{
    const xmlChar *nsURI;
    int ret;
    xmlAttrPtr attr; /* An attribute on the element. */
    const xmlChar *defValue;
    xmlSchemaValPtr defVal;
    int fixed;
    xmlSchemaAttributeLinkPtr attrUse = NULL;
    xmlSchemaAttributePtr attrDecl;
    int found;
    xmlSchemaAttrStatePtr curState, reqAttrStates = NULL, reqAttrStatesTop = NULL;
    xmlSchemaAttrStatePtr defAttrStates = NULL, defAttrStatesTop = NULL;
    xmlNodePtr oldnode;
#ifdef DEBUG_ATTR_VALIDATION
    int redundant = 0;
#endif

      
    /*
    * Allow all attributes if the type is anyType.
    */
    if (type == xmlSchemaGetBuiltInType(XML_SCHEMAS_ANYTYPE))
	return (0);

    oldnode = ctxt->node;
    if (type != NULL)
	attrUse = type->attributeUses;
    while (attrUse != NULL) {
        found = 0;    
	attrDecl = attrUse->attr;
#ifdef DEBUG_ATTR_VALIDATION
	printf("attr use - name: %s\n", xmlSchemaGetAttrName(attrDecl));
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
	    curState->decl = attrDecl;
	    ret = xmlSchemaCheckAttrLocallyValid(ctxt, attrDecl, curState, attr);
        }
        if (!found) {
	    if (attrDecl->occurs == XML_SCHEMAS_ATTR_USE_REQUIRED) {
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
		    ctxt->node = oldnode;
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
	    } else if ((attrDecl->occurs == XML_SCHEMAS_ATTR_USE_OPTIONAL) &&
		    (xmlSchemaGetEffectiveValueConstraint(attrDecl, 
			&fixed, &defValue, &defVal))) {
		xmlSchemaAttrStatePtr tmp;
		/*
		* Handle non existent default/fixed attributes.
		*/	
		tmp = (xmlSchemaAttrStatePtr) 
		    xmlMalloc(sizeof(xmlSchemaAttrState));
		if (tmp == NULL) {
		    xmlSchemaVErrMemory(ctxt, 
			"registering schema specified attributes", NULL);
		    ctxt->node = oldnode;
		    return (-1);
		}            
		tmp->attr = NULL;
		tmp->state = XML_SCHEMAS_ATTR_DEFAULT;
		tmp->decl = attrDecl;
		tmp->value = defValue;
		tmp->next = NULL;
		
		if (defAttrStates == NULL) {
		    defAttrStates = tmp;
		    defAttrStates = tmp;
		} else {
		    defAttrStates->next = tmp;
		    defAttrStatesTop = tmp;
		}				
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
    
    if ((type != NULL) && (type->attributeWildcard != NULL)) {	
#ifdef DEBUG_ATTR_VALIDATION
	xmlSchemaWildcardNsPtr ns;	
	printf("matching wildcard: [%d] of complexType: %s\n", type->attributeWildcard, type->name);
	if (type->attributeWildcard->processContents == 
	    XML_SCHEMAS_ANY_LAX)
	    printf("processContents: lax\n");
	else if (type->attributeWildcard->processContents == 
	    XML_SCHEMAS_ANY_STRICT)
	    printf("processContents: strict\n");
	else
	    printf("processContents: skip\n");
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
	curState = ctxt->attr;
	while (curState != NULL) {
	    if (curState->state == XML_SCHEMAS_ATTR_UNKNOWN) {		
		if (curState->attr->ns != NULL) 
		    nsURI = curState->attr->ns->href;
		else
		    nsURI = NULL;		
		if (xmlSchemaMatchesWildcardNs(type->attributeWildcard, 
		    nsURI)) {
		    /*
		    * Handle processContents.
		    */
		    if ((type->attributeWildcard->processContents == 
			XML_SCHEMAS_ANY_LAX) ||
			(type->attributeWildcard->processContents == 
			XML_SCHEMAS_ANY_STRICT)) {
			
			attr = curState->attr;						
			attrDecl = xmlSchemaGetAttribute(ctxt->schema, 
			    attr->name, nsURI);
			curState->decl = attrDecl;
			if (attrDecl != NULL) {
			    curState->decl = attrDecl;
			    ret = xmlSchemaCheckAttrLocallyValid(ctxt, attrDecl, curState, attr);			    
			} else if (type->attributeWildcard->processContents == 
			    XML_SCHEMAS_ANY_LAX) {
			    curState->state = XML_SCHEMAS_ATTR_CHECKED;
			}											
		    } else
			curState->state = XML_SCHEMAS_ATTR_CHECKED;
		}		
	    }
	    curState = curState->next;
        }
    }

    /*
    * Report missing and illegal attributes.
    */
    if (ctxt->attr != NULL) {
	curState = ctxt->attr;
	while ((curState != NULL) && (curState != ctxt->attrTop->next)) {    
	    if (curState->state != XML_SCHEMAS_ATTR_CHECKED) {
		attr = curState->attr;
		if (curState->decl != NULL) {
		    if (curState->decl->ref != NULL)
			attrDecl = curState->decl->refDecl;
		    else 
			attrDecl = curState->decl;
		} else
		    attrDecl = NULL;
		if (curState->state == XML_SCHEMAS_ATTR_MISSING) {
		    xmlSchemaVMissingAttrErr(ctxt, elem, attrDecl);
		} else if (curState->state == 
		    XML_SCHEMAS_ATTR_TYPE_NOT_RESOLVED) {
		    xmlSchemaVCustomErr(ctxt,
			XML_SCHEMAV_CVC_ATTRIBUTE_2,
			(xmlNodePtr) attr,
			(xmlSchemaTypePtr) attrDecl,
			"The type definition is absent",
			NULL);
		} else if (curState->state == 
		    XML_SCHEMAS_ATTR_INVALID_FIXED_VALUE) {			
			xmlSchemaVCustomErr(ctxt,
			    XML_SCHEMAV_CVC_AU, 
			    (xmlNodePtr) attr, (xmlSchemaTypePtr) attrDecl,
			    "The value does not match the fixed value "
			    "constraint", NULL);
		} else if (curState->state == XML_SCHEMAS_ATTR_UNKNOWN) {
		    /* TODO: "prohibited" won't ever be touched here!. 
		      (curState->state == XML_SCHEMAS_ATTR_PROHIBITED))
		    */
		    /*
		    * TODO: One might report different error messages 
		    * for the following errors.
		    */
		    if ((type == NULL) || (type->attributeWildcard == NULL)) {
			xmlSchemaVIllegalAttrErr(ctxt, 
			    XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1, attr);
		    } else {
			xmlSchemaVIllegalAttrErr(ctxt, 
			    XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2, attr);
		    }
		}
	    }	
	    curState = curState->next;
	}  
    }    
    
    /*
    * Add missing default/fixed attributes.
    */
    if (ctxt->options & XML_SCHEMA_VAL_VC_I_CREATE) {
	curState = defAttrStates;
	while (curState != NULL) { 
	    attrDecl = curState->decl;
	    if (attrDecl->ref != NULL)
		attrDecl = attrDecl->refDecl;
	    /*
	    * PSVI: Add a new attribute node to the current element.
	    */
	    if (attrDecl->targetNamespace == NULL) {
		xmlNewProp(elem, attrDecl->name, curState->value);
	    } else {
		xmlNsPtr ns;
		
		ns = xmlSearchNsByHref(elem->doc, elem, 
		    attrDecl->targetNamespace);
		if (ns == NULL) {
		    xmlChar prefix[12];
		    int counter = 1;

		    attr = curState->attr;
		    /*
		    * Create a namespace declaration on the validation 
		    * root node if no namespace declaration is in scope.
		    */		    
		    snprintf((char *) prefix, sizeof(prefix), "p");
		    /*
		    * This is somehow not performant, since the ancestor 
		    * axis beyond @elem will be searched as well.
		    */
		    ns = xmlSearchNs(elem->doc, elem, BAD_CAST prefix);
		    while (ns != NULL) {
			if (counter > 1000) {
			    xmlSchemaVErr(ctxt, (xmlNodePtr) attr, 
				XML_SCHEMAV_INTERNAL,
				"Internal error: xmlSchemaValidateAttributes, "
				"could not compute a ns prefix for "
				"default/fixed attribute '%s'.\n",
				attrDecl->name, NULL);
			    
			    break;
			}
			snprintf((char *) prefix, 
			    sizeof(prefix), "p%d", counter++);
			ns = xmlSearchNs(elem->doc, elem, 
			    BAD_CAST prefix);
		    }
		    if (ns == NULL) {
			ns = xmlNewNs(ctxt->validationRoot, 
			    attrDecl->targetNamespace, BAD_CAST prefix);
			xmlNewNsProp(elem, ns, attrDecl->name, 
			    curState->value);
		    }
		} else {
		    xmlNewNsProp(elem, ns, attrDecl->name, 
			curState->value);
		}
	    }
	    curState = curState->next;
	}
    }
    if (defAttrStates != NULL) 
	xmlSchemaFreeAttributeStates(defAttrStates);
		
#ifdef DEBUG_ATTR_VALIDATION
    if (redundant)
	xmlGenericError(xmlGenericErrorContext,
	                "xmlSchemaValidateAttributes: redundant call by type: %s\n",
	                type->name);
#endif
    ctxt->node = oldnode;
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
xmlSchemaValidateElement(xmlSchemaValidCtxtPtr ctxt)
{
    xmlSchemaElementPtr elemDecl;    
    int ret = 0;

    /* 
    * This one is called by xmlSchemaValidateDocument and
    * xmlSchemaValidateOneElement.
    */  
    if (ctxt->schema == NULL) {
	/*
	* No schema was specified at time of creation of the validation
	* context. Use xsi:schemaLocation and xsi:noNamespaceSchemaLocation
	* of the instance to build a schema.
	*/
	if (ctxt->pctxt == NULL) 
	    ctxt->pctxt = xmlSchemaNewParserCtxt("*");
	if (ctxt->pctxt == NULL)
	    return (-1);
	ctxt->schema = xmlSchemaNewSchema(ctxt->pctxt);
	if (ctxt->schema == NULL)
	    return (-1);
	/* TODO: assign user data. */
	ctxt->pctxt->error = ctxt->error;
	ctxt->pctxt->warning = ctxt->warning;	
	ctxt->xsiAssemble = 1;
    } else
	ctxt->xsiAssemble = 0;
    /* ctxt->options |= XML_SCHEMA_VAL_VC_I_CREATE;
    * ctxt->xsiAssemble = 1;
    */
    /*
    * Assemble new schemata using xsi.
    */
    if (ctxt->xsiAssemble) {	
	ret = xmlSchemaAssembleByXSIElem(ctxt, ctxt->node);
	if (ret == -1) {
	    xmlSchemaVCustomErr(ctxt, 
		XML_SCHEMAV_INTERNAL,
		ctxt->node, NULL, 	
		"Internal error: xmlSchemaValidateElement, "
		"assembling schema by xsi", NULL);	    
	}
	/*
	* NOTE: We won't react on schema parser errors here.
	* TODO: But a warning would be nice.
	*/
    }
    if (ret != -1) {	    
	if (ctxt->node->ns != NULL)
	    elemDecl = xmlSchemaGetElem(ctxt->schema, ctxt->node->name, 
		ctxt->node->ns->href);
	else
	    elemDecl = xmlSchemaGetElem(ctxt->schema, ctxt->node->name, NULL);
	
	if (elemDecl == NULL) {
	    xmlSchemaVCustomErr(ctxt, 
		XML_SCHEMAV_CVC_ELT_1,
		ctxt->node, NULL, 	  
		"No matching global declaration available", NULL);
	    ret = XML_SCHEMAV_CVC_ELT_1;
	} else { 
	    ret = xmlSchemaValidateElementByDeclaration(ctxt, elemDecl);    
	    if (ret < 0) {
		xmlSchemaVCustomErr(ctxt,
		    XML_SCHEMAV_INTERNAL, ctxt->node, NULL,
		    "Internal error: xmlSchemaValidateElement, "
		    "calling validation by declaration", NULL);
	    }
	}
    }
    /* ctxt->xsiAssemble = 0; */
    if (ctxt->xsiAssemble) {
	if (ctxt->schema != NULL) {
	    xmlSchemaFree(ctxt->schema);
	    ctxt->schema = NULL;
	}
    }
    return (ret);   
}


/**
 * xmlSchemaValidateOneElement:
 * @ctxt:  a schema validation context
 * @elem:  an element node
 *
 * Validate a branch of a tree, starting with the given @elem.
 *
 * Returns 0 if the element and its subtree is valid, a positive error 
 * code number otherwise and -1 in case of an internal or API error.
 */
int
xmlSchemaValidateOneElement(xmlSchemaValidCtxtPtr ctxt, xmlNodePtr elem)
{
    if ((ctxt == NULL) || (elem == NULL) || (elem->type != XML_ELEMENT_NODE))
	return (-1);

     if (ctxt->schema == NULL) {
	xmlSchemaVErr(ctxt, NULL,
	    XML_SCHEMAV_INTERNAL,
	    "API error: xmlSchemaValidateOneElement, "
	    "no schema specified.\n", NULL, NULL);
	return (-1);
    }

    ctxt->doc = elem->doc;
    ctxt->err = 0;
    ctxt->nberrors = 0;
    ctxt->node = elem;
    ctxt->validationRoot = elem;
    return (xmlSchemaValidateElement(ctxt));
}

/**
 * xmlSchemaValidateDocument:
 * @ctxt:  a schema validation context
 * @doc:  a parsed document tree
 * @xsiAssemble: should schemata be added if requested by the instance?
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
     
    root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlSchemaVCustomErr(ctxt, 
	    XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING,
	    (xmlNodePtr) doc, NULL,
	    "The document has no document element", NULL);
        return (ctxt->err);
    }    
    /* ctxt->options |= XML_SCHEMA_VAL_XSI_ASSEMBLE; */
    /*
     * Okay, start the recursive validation
     */
    ctxt->node = root;
    ctxt->validationRoot = root;
    xmlSchemaValidateElement(ctxt);

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
    ret->attrTop = NULL;
    ret->attr = NULL;
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
    if (ctxt->pctxt != NULL) {
	xmlSchemaFreeParserCtxt(ctxt->pctxt);
    }
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
    if (ctxt->pctxt != NULL)
	xmlSchemaSetParserErrors(ctxt->pctxt, err, warn, ctx);
}

/**
 * xmlSchemaGetValidErrors:
 * @ctxt:	a XML-Schema validation context
 * @err: the error function result
 * @warn: the warning function result
 * @ctx: the functions context result
 *
 * Get the error and warning callback informations
 *
 * Returns -1 in case of error and 0 otherwise
 */
int
xmlSchemaGetValidErrors(xmlSchemaValidCtxtPtr ctxt,
						xmlSchemaValidityErrorFunc * err,
						xmlSchemaValidityWarningFunc * warn, void **ctx)
{
	if (ctxt == NULL)
		return (-1);
	if (err != NULL)
		*err = ctxt->error;
	if (warn != NULL)
		*warn = ctxt->warning;
	if (ctx != NULL)
		*ctx = ctxt->userData;
	return (0);
}


/**
 * xmlSchemaSetValidOptions:
 * @ctxt:	a schema validation context
 * @options: a combination of xmlSchemaValidOption
 *
 * Sets the options to be used during the validation.
 *
 * Returns 0 in case of success, -1 in case of an
 * API error.
 */
int
xmlSchemaSetValidOptions(xmlSchemaValidCtxtPtr ctxt,
			 int options)
					
{
    int i;

    if (ctxt == NULL)
	return (-1);
    /*
    * WARNING: Change the start value if adding to the
    * xmlSchemaValidOption.
    * TODO: Is there an other, more easy to maintain,
    * way?
    */
    for (i = 1; i < (int) sizeof(int) * 8; i++) {
        if (options & 1<<i) {
	    xmlSchemaVErr(ctxt, NULL,
		XML_SCHEMAV_INTERNAL,
		"Internal error: xmlSchemaSetValidOptions, "
		"invalid option argument.\n", NULL, NULL);
	    return (-1);   
        }	
    }
    ctxt->options = options;
    return (0);      
}

/**
 * xmlSchemaValidCtxtGetOptions:
 * @ctxt:	a schema validation context 
 *
 * Get the validation context options.
 * 
 * Returns the option combination or -1 on error.
 */
int
xmlSchemaValidCtxtGetOptions(xmlSchemaValidCtxtPtr ctxt)
					
{    
    if (ctxt == NULL)
	return (-1);
    else 
	return (ctxt->options);    
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
    ctxt->err = 0; 
    ctxt->nberrors = 0;
    
    /*
    if (ctxt->schema == NULL) {
	xmlSchemaVErr(ctxt, NULL,
	    XML_SCHEMAV_INTERNAL,
	    "API error: xmlSchemaValidateDoc, "
	    "no schema specified and assembling of schemata "
	    "using xsi:schemaLocation and xsi:noNamespaceSchemaLocation "
	    "is not enabled.\n", NULL, NULL);
	return (-1);
    }
    */
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
