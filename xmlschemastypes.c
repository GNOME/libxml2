/*
 * schemastypes.c : implementation of the XML Schema Datatypes
 *             definition and validity checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#define IN_LIBXML
#include "libxml.h"

#ifdef LIBXML_SCHEMAS_ENABLED

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/hash.h>
#include <libxml/valid.h>

#include <libxml/xmlschemas.h>
#include <libxml/schemasInternals.h>
#include <libxml/xmlschemastypes.h>

#define DEBUG

#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

#define XML_SCHEMAS_NAMESPACE_NAME \
    (const xmlChar *)"http://www.w3.org/2001/XMLSchema"

typedef enum {
    XML_SCHEMAS_UNKNOWN = 0,
    XML_SCHEMAS_STRING,
    XML_SCHEMAS_NMTOKEN,
    XML_SCHEMAS_DECIMAL,
    XML_SCHEMAS_,
    XML_SCHEMAS_XXX
} xmlSchemaValType;

unsigned long powten[10] = {
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000L,
    100000000L, 1000000000L
};

typedef struct _xmlSchemaValDecimal xmlSchemaValDecimal;
typedef xmlSchemaValDecimal *xmlSchemaValDecimalPtr;
struct _xmlSchemaValDecimal {
    /* would use long long but not portable */
    unsigned long base;
    unsigned int extra;
    int sign:1;
    int frac:7;
    int total:8;
};

struct _xmlSchemaVal {
    xmlSchemaValType type;
    union {
	xmlSchemaValDecimal decimal;
    } value;
};

static int xmlSchemaTypesInitialized = 0;
static xmlHashTablePtr xmlSchemaTypesBank = NULL;

static xmlSchemaTypePtr xmlSchemaTypeStringDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeAnyTypeDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeAnySimpleTypeDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeDecimalDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeDateDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypePositiveIntegerDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNonNegativeIntegerDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNmtoken = NULL;

/*
 * xmlSchemaInitBasicType:
 * @name:  the type name
 *
 * Initialize one default type
 */
static xmlSchemaTypePtr
xmlSchemaInitBasicType(const char *name) {
    xmlSchemaTypePtr ret;

    ret = (xmlSchemaTypePtr) xmlMalloc(sizeof(xmlSchemaType));
    if (ret == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"Could not initilize type %s: out of memory\n", name);
	return(NULL);
    }
    memset(ret, 0, sizeof(xmlSchemaType));
    ret->name = xmlStrdup((const xmlChar *)name);
    ret->type = XML_SCHEMA_TYPE_BASIC;
    ret->contentType = XML_SCHEMA_CONTENT_BASIC;
    xmlHashAddEntry2(xmlSchemaTypesBank, ret->name,
	             XML_SCHEMAS_NAMESPACE_NAME, ret);
    return(ret);
}

/*
 * xmlSchemaInitTypes:
 *
 * Initialize the default XML Schemas type library
 */
void
xmlSchemaInitTypes(void) {
    if (xmlSchemaTypesInitialized != 0)
	return;
    xmlSchemaTypesBank = xmlHashCreate(40);
    
    xmlSchemaTypeStringDef = xmlSchemaInitBasicType("string");
    xmlSchemaTypeAnyTypeDef = xmlSchemaInitBasicType("anyType");
    xmlSchemaTypeAnySimpleTypeDef = xmlSchemaInitBasicType("anySimpleType");
    xmlSchemaTypeDecimalDef = xmlSchemaInitBasicType("decimal");
    xmlSchemaTypeDateDef = xmlSchemaInitBasicType("date");
    xmlSchemaTypePositiveIntegerDef = xmlSchemaInitBasicType("positiveInteger");
    xmlSchemaTypeNonNegativeIntegerDef =
	xmlSchemaInitBasicType("nonNegativeInteger");
    xmlSchemaTypeNmtoken = xmlSchemaInitBasicType("NMTOKEN");

    xmlSchemaTypesInitialized = 1;
}

/**
 * xmlSchemaCleanupTypes:
 *
 * Cleanup the default XML Schemas type library
 */
void	
xmlSchemaCleanupTypes(void) {
    if (xmlSchemaTypesInitialized == 0)
	return;
    xmlHashFree(xmlSchemaTypesBank, (xmlHashDeallocator) xmlSchemaFreeType);
    xmlSchemaTypesInitialized = 0;
}

/**
 * xmlSchemaNewValue:
 * @type:  the value type
 *
 * Allocate a new simple type value
 *
 * Returns a pointer to the new value or NULL in case of error
 */
static xmlSchemaValPtr
xmlSchemaNewValue(xmlSchemaValType type) {
    xmlSchemaValPtr value;

    value = (xmlSchemaValPtr) xmlMalloc(sizeof(xmlSchemaVal));
    if (value == NULL) {
	return(NULL);
    }
    memset(value, 0, sizeof(xmlSchemaVal));
    value->type = type;
    return(value);
}

/**
 * xmlSchemaFreeValue:
 * @value:  the value to free
 *
 * Cleanup the default XML Schemas type library
 */
void	
xmlSchemaFreeValue(xmlSchemaValPtr value) {
    if (value == NULL)
	return;
    xmlFree(value);
}

/**
 * xmlSchemaGetPredefinedType:
 * @name: the type name
 * @ns:  the URI of the namespace usually "http://www.w3.org/2001/XMLSchema"
 *
 * Lookup a type in the default XML Schemas type library
 *
 * Returns the type if found, NULL otherwise
 */
xmlSchemaTypePtr
xmlSchemaGetPredefinedType(const xmlChar *name, const xmlChar *ns) {
    if (xmlSchemaTypesInitialized == 0)
	xmlSchemaInitTypes();
    if (name == NULL)
	return(NULL);
    return((xmlSchemaTypePtr) xmlHashLookup2(xmlSchemaTypesBank, name, ns));
}
/**
 * xmlSchemaValidatePredefinedType:
 * @type: the predefined type
 * @value: the value to check
 * @val:  the return computed value
 *
 * Check that a value conforms to the lexical space of the predefined type.
 * if true a value is computed and returned in @val.
 *
 * Returns 0 if this validates, a positive error code number otherwise
 *         and -1 in case of internal or API error.
 */
int
xmlSchemaValidatePredefinedType(xmlSchemaTypePtr type, const xmlChar *value,
	                        xmlSchemaValPtr *val) {
    xmlSchemaValPtr v;

    if (xmlSchemaTypesInitialized == 0)
	return(-1);
    if (type == NULL)
	return(-1);
    if (val != NULL)
	*val = NULL;
    if (type == xmlSchemaTypeStringDef) { 
	return(0);
    } else if (type == xmlSchemaTypeAnyTypeDef) {
	return(0);
    } else if (type == xmlSchemaTypeAnySimpleTypeDef) {
	return(0);
    } else if (type == xmlSchemaTypeNmtoken) {
	if (xmlValidateNmtokenValue(value))
	    return(0);
	return(1);
    } else if (type == xmlSchemaTypeDecimalDef) {
	const xmlChar *cur = value, *tmp;
	int frac = 0, main, neg = 0;
	unsigned long base = 0;
	if (cur == NULL)
	    return(1);
	if (*cur == '+')
	    cur++;
	else if (*cur == '-') {
	    neg = 1;
	    cur++;
	}
	tmp = cur;
	while ((*cur >= '0') && (*cur <= '9')) {
	    base = base * 10 + (*cur - '0');
	    cur++;
	}
	main = cur - tmp;
	if (*cur == '.') {
	    cur++;
	    tmp = cur;
	    while ((*cur >= '0') && (*cur <= '9')) {
		base = base * 10 + (*cur - '0');
		cur++;
	    }
	    frac = cur - tmp;
	}
	if (*cur != 0)
	    return(1);
	if (val != NULL) {
	    v = xmlSchemaNewValue(XML_SCHEMAS_DECIMAL);
	    if (v != NULL) {
		v->value.decimal.base = base;
		v->value.decimal.sign = neg;
		v->value.decimal.frac = frac;
		v->value.decimal.total = frac + main;
		*val = v;
	    }
	}
	return(0);
    } else if (type == xmlSchemaTypeDateDef) {
	const xmlChar *cur = value;
	if (cur == NULL)
	    return(1);
	if (*cur == '-')
	    cur++;
	if ((*cur < '0') || (*cur > '9'))
	    return(1);
	if ((*cur < '0') || (*cur > '9'))
	    return(1);
	if ((*cur < '0') || (*cur > '9'))
	    return(1);
	if ((*cur < '0') || (*cur > '9'))
	    return(1);
	while ((*cur >= '0') && (*cur <= '9'))
	    cur++;
	if (*cur != '-')
	    return(1);
	cur++;
	if ((*cur != '0') && (*cur != '1'))
	    return(1);
	if ((*cur == '0') && (cur[1] == '0'))
	    return(1);
	if ((*cur == '1') && ((cur[1] < '0') || (cur[1] > '2')))
	    return(1);
	cur += 2;
	if (*cur != '-')
	    return(1);
	cur++;
	if ((*cur < '0') || (*cur > '3'))
	    return(1);
	if ((*cur == '0') && (cur[1] == '0'))
	    return(1);
	if ((*cur == '3') && ((cur[1] < '0') || (cur[1] > '1')))
	    return(1);
	cur += 2;
	if (*cur != 0)
	    return(1);
	return(0);
    } else if (type == xmlSchemaTypePositiveIntegerDef) {
	const xmlChar *cur = value;
	unsigned long base = 0;
	int total = 0;
	if (cur == NULL)
	    return(1);
	if (*cur == '+')
	    cur++;
	while ((*cur >= '0') && (*cur <= '9')) {
	    base = base * 10 + (*cur - '0');
	    total++;
	    cur++;
	}
	if (*cur != 0)
	    return(1);
	if (val != NULL) {
	    v = xmlSchemaNewValue(XML_SCHEMAS_DECIMAL);
	    if (v != NULL) {
		v->value.decimal.base = base;
		v->value.decimal.sign = 0;
		v->value.decimal.frac = 0;
		v->value.decimal.total = total;
		*val = v;
	    }
	}
	return(0);
    } else if (type == xmlSchemaTypeNonNegativeIntegerDef) {
	const xmlChar *cur = value;
	unsigned long base = 0;
	int total = 0;
	int sign = 0;
	if (cur == NULL)
	    return(1);
	if (*cur == '-') {
	    sign = 1;
	    cur++;
	} else if (*cur == '+')
	    cur++;
	while ((*cur >= '0') && (*cur <= '9')) {
	    base = base * 10 + (*cur - '0');
	    total++;
	    cur++;
	}
	if (*cur != 0)
	    return(1);
	if ((sign == 1) && (base != 0))
	    return(1);
	if (val != NULL) {
	    v = xmlSchemaNewValue(XML_SCHEMAS_DECIMAL);
	    if (v != NULL) {
		v->value.decimal.base = base;
		v->value.decimal.sign = 0;
		v->value.decimal.frac = 0;
		v->value.decimal.total = total;
		*val = v;
	    }
	}
	return(0);
    } else {
	TODO
	return(0);
    }
}

/**
 * xmlSchemaCompareDecimals:
 * @x:  a first decimal value
 * @y:  a second decimal value
 *
 * Compare 2 decimals
 *
 * Returns -1 if x < y, 0 if x == y, 1 if x > y and -2 in case of error
 */
static int
xmlSchemaCompareDecimals(xmlSchemaValPtr x, xmlSchemaValPtr y)
{
    xmlSchemaValPtr swp;
    int order = 1;
    unsigned long tmp;

    if ((x->value.decimal.sign) && (x->value.decimal.sign))
        order = -1;
    else if (x->value.decimal.sign)
        return (-1);
    else if (y->value.decimal.sign)
        return (1);
    if (x->value.decimal.frac == y->value.decimal.frac) {
        if (x->value.decimal.base < y->value.decimal.base)
            return (-1);
        return (x->value.decimal.base > y->value.decimal.base);
    }
    if (y->value.decimal.frac > x->value.decimal.frac) {
        swp = y;
        y = x;
        x = swp;
        order = -order;
    }
    tmp =
        x->value.decimal.base / powten[x->value.decimal.frac -
                                       y->value.decimal.frac];
    if (tmp > y->value.decimal.base)
        return (order);
    if (tmp < y->value.decimal.base)
        return (-order);
    tmp =
        y->value.decimal.base * powten[x->value.decimal.frac -
                                       y->value.decimal.frac];
    if (x->value.decimal.base < tmp)
        return (-order);
    if (x->value.decimal.base == tmp)
        return (0);
    return (order);
}

/**
 * xmlSchemaCompareValues:
 * @x:  a first value
 * @y:  a second value
 *
 * Compare 2 values
 *
 * Returns -1 if x < y, 0 if x == y, 1 if x > y and -2 in case of error
 */
static int
xmlSchemaCompareValues(xmlSchemaValPtr x, xmlSchemaValPtr y) {
    if ((x == NULL) || (y == NULL))
	return(-2);

    switch (x->type) {
	case XML_SCHEMAS_STRING:
	    TODO
	case XML_SCHEMAS_DECIMAL:
	    if (y->type == XML_SCHEMAS_DECIMAL)
		return(xmlSchemaCompareDecimals(x, y));
	    else
		return(-2);
	default:
	    TODO
    }
}

/**
 * xmlSchemaValidateFacet:
 * @type:  the type declaration
 * @facet:  the facet to check
 * @value:  the lexical repr of the value to validate
 * @val:  the precomputed value
 *
 * Check a value against a facet condition
 *
 * Returns 0 if the element is schemas valid, a positive error code
 *     number otherwise and -1 in case of internal or API error.
 */
int
xmlSchemaValidateFacet(xmlSchemaTypePtr base, xmlSchemaFacetPtr facet,
	               const xmlChar *value, xmlSchemaValPtr val)
{
    int ret;

    switch (facet->type) {
	case XML_SCHEMA_FACET_PATTERN:
	    ret = xmlRegexpExec(facet->regexp, value);
	    if (ret == 1)
		return(0);
	    if (ret == 0) {
		TODO /* error code */
		return(1);
	    }
	    return(ret);
	case XML_SCHEMA_FACET_MAXEXCLUSIVE:
	    ret = xmlSchemaCompareValues(val, facet->val);
	    if (ret == -2) {
		TODO /* error code */
		return(-1);
	    }
	    if (ret == -1)
		return(0);
	    TODO /* error code */
	    return(1);
	case XML_SCHEMA_FACET_WHITESPACE:
	    TODO /* whitespaces */
	    return(0);
	case XML_SCHEMA_FACET_MAXLENGTH:
	    if ((facet->val != NULL) &&
		(facet->val->type == XML_SCHEMAS_DECIMAL) &&
		(facet->val->value.decimal.frac == 0)) {
		int len;

		if (facet->val->value.decimal.sign == 1)
		    return(1);
                len = xmlUTF8Strlen(value);
		if (len > facet->val->value.decimal.base)
		    return(1);
		return(0);
	    }
	    TODO /* error code */
	    return(1);
	case  XML_SCHEMA_FACET_ENUMERATION:
	    if ((facet->value != NULL) &&
		(xmlStrEqual(facet->value, value)))
		return(0);
	    return(1);
	default:
	    TODO
    }
    return(0);
}

#endif /* LIBXML_SCHEMAS_ENABLED */
