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
#include <libxml/xpath.h>
#include <libxml/uri.h>

#include <libxml/xmlschemas.h>
#include <libxml/schemasInternals.h>
#include <libxml/xmlschemastypes.h>

#ifdef HAVE_MATH_H
#include <math.h>
#endif

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
    XML_SCHEMAS_NORMSTRING,
    XML_SCHEMAS_DECIMAL,
    XML_SCHEMAS_TIME,
    XML_SCHEMAS_GDAY,
    XML_SCHEMAS_GMONTH,
    XML_SCHEMAS_GMONTHDAY,
    XML_SCHEMAS_GYEAR,
    XML_SCHEMAS_GYEARMONTH,
    XML_SCHEMAS_DATE,
    XML_SCHEMAS_DATETIME,
    XML_SCHEMAS_DURATION,
    XML_SCHEMAS_FLOAT,
    XML_SCHEMAS_DOUBLE,
    XML_SCHEMAS_BOOLEAN,
    XML_SCHEMAS_TOKEN,
    XML_SCHEMAS_LANGUAGE,
    XML_SCHEMAS_NMTOKEN,
    XML_SCHEMAS_NMTOKENS,
    XML_SCHEMAS_NAME,
    XML_SCHEMAS_QNAME,
    XML_SCHEMAS_NCNAME,
    XML_SCHEMAS_ID,
    XML_SCHEMAS_IDREF,
    XML_SCHEMAS_IDREFS,
    XML_SCHEMAS_ENTITY,
    XML_SCHEMAS_ENTITIES,
    XML_SCHEMAS_NOTATION,
    XML_SCHEMAS_ANYURI,
    XML_SCHEMAS_INTEGER,
    XML_SCHEMAS_NPINTEGER,
    XML_SCHEMAS_NINTEGER,
    XML_SCHEMAS_NNINTEGER,
    XML_SCHEMAS_PINTEGER,
    XML_SCHEMAS_INT,
    XML_SCHEMAS_UINT,
    XML_SCHEMAS_LONG,
    XML_SCHEMAS_ULONG,
    XML_SCHEMAS_SHORT,
    XML_SCHEMAS_USHORT,
    XML_SCHEMAS_BYTE,
    XML_SCHEMAS_UBYTE,
    XML_SCHEMAS_HEXBINARY
} xmlSchemaValType;

static unsigned long powten[10] = {
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000L,
    100000000L, 1000000000L
};

/* Date value */
typedef struct _xmlSchemaValDate xmlSchemaValDate;
typedef xmlSchemaValDate *xmlSchemaValDatePtr;
struct _xmlSchemaValDate {
    long		year;
    unsigned int	mon	:4;	/* 1 <=  mon    <= 12   */
    unsigned int	day	:5;	/* 1 <=  day    <= 31   */
    unsigned int	hour	:5;	/* 0 <=  hour   <= 23   */
    unsigned int	min	:6;	/* 0 <=  min    <= 59	*/
    double		sec;
    unsigned int	tz_flag	:1;	/* is tzo explicitely set? */
    int			tzo	:11;	/* -1440 <= tzo <= 1440 */
};

/* Duration value */
typedef struct _xmlSchemaValDuration xmlSchemaValDuration;
typedef xmlSchemaValDuration *xmlSchemaValDurationPtr;
struct _xmlSchemaValDuration {
    long	        mon;		/* mon stores years also */
    long        	day;
    double		sec;            /* sec stores min and hour also */
};

typedef struct _xmlSchemaValDecimal xmlSchemaValDecimal;
typedef xmlSchemaValDecimal *xmlSchemaValDecimalPtr;
struct _xmlSchemaValDecimal {
    /* would use long long but not portable */
    unsigned long lo;
    unsigned long mi;
    unsigned long hi;
    unsigned int extra;
    unsigned int sign:1;
    int frac:7;
    int total:8;
};

typedef struct _xmlSchemaValQName xmlSchemaValQName;
typedef xmlSchemaValQName *xmlSchemaValQNamePtr;
struct _xmlSchemaValQName {
    xmlChar *name;
    xmlChar *uri;
};

struct _xmlSchemaVal {
    xmlSchemaValType type;
    union {
	xmlSchemaValDecimal     decimal;
        xmlSchemaValDate        date;
        xmlSchemaValDuration    dur;
	xmlSchemaValQName	qname;
	float			f;
	double			d;
	int			b;
	xmlChar                *str;
    } value;
};

static int xmlSchemaTypesInitialized = 0;
static xmlHashTablePtr xmlSchemaTypesBank = NULL;

/*
 * Basic types
 */
static xmlSchemaTypePtr xmlSchemaTypeStringDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeAnyTypeDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeAnySimpleTypeDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeDecimalDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeDatetimeDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeDateDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeTimeDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeGYearDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeGYearMonthDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeGDayDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeGMonthDayDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeGMonthDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeDurationDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeFloatDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeBooleanDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeDoubleDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeHexBinaryDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeAnyURIDef = NULL;

/*
 * Derived types
 */
static xmlSchemaTypePtr xmlSchemaTypePositiveIntegerDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNonPositiveIntegerDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNegativeIntegerDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNonNegativeIntegerDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeIntegerDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeLongDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeIntDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeShortDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeByteDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeUnsignedLongDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeUnsignedIntDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeUnsignedShortDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeUnsignedByteDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNormStringDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeTokenDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeLanguageDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNameDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeQNameDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNCNameDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeIdDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeIdrefDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeIdrefsDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeEntityDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeEntitiesDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNotationDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNmtokenDef = NULL;
static xmlSchemaTypePtr xmlSchemaTypeNmtokensDef = NULL;

/*
 * xmlSchemaInitBasicType:
 * @name:  the type name
 * @type:  the value type associated
 *
 * Initialize one default type
 */
static xmlSchemaTypePtr
xmlSchemaInitBasicType(const char *name, xmlSchemaValType type) {
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
    ret->flags = type;
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
xmlSchemaInitTypes(void)
{
    if (xmlSchemaTypesInitialized != 0)
        return;
    xmlSchemaTypesBank = xmlHashCreate(40);

    /*
     * primitive datatypes
     */
    xmlSchemaTypeStringDef = xmlSchemaInitBasicType("string",
                                                    XML_SCHEMAS_STRING);
    xmlSchemaTypeAnyTypeDef = xmlSchemaInitBasicType("anyType",
                                                     XML_SCHEMAS_UNKNOWN);
    xmlSchemaTypeAnySimpleTypeDef = xmlSchemaInitBasicType("anySimpleType",
                                                           XML_SCHEMAS_UNKNOWN);
    xmlSchemaTypeDecimalDef = xmlSchemaInitBasicType("decimal",
                                                     XML_SCHEMAS_DECIMAL);
    xmlSchemaTypeDateDef = xmlSchemaInitBasicType("date",
                                                  XML_SCHEMAS_DATE);
    xmlSchemaTypeDatetimeDef = xmlSchemaInitBasicType("dateTime",
                                                      XML_SCHEMAS_DATETIME);
    xmlSchemaTypeTimeDef = xmlSchemaInitBasicType("time",
                                                  XML_SCHEMAS_TIME);
    xmlSchemaTypeGYearDef = xmlSchemaInitBasicType("gYear",
                                                   XML_SCHEMAS_GYEAR);
    xmlSchemaTypeGYearMonthDef = xmlSchemaInitBasicType("gYearMonth",
                                                        XML_SCHEMAS_GYEARMONTH);
    xmlSchemaTypeGMonthDef = xmlSchemaInitBasicType("gMonth",
                                                    XML_SCHEMAS_GMONTH);
    xmlSchemaTypeGMonthDayDef = xmlSchemaInitBasicType("gMonthDay",
                                                       XML_SCHEMAS_GMONTHDAY);
    xmlSchemaTypeGDayDef = xmlSchemaInitBasicType("gDay",
                                                  XML_SCHEMAS_GDAY);
    xmlSchemaTypeDurationDef = xmlSchemaInitBasicType("duration",
                                                      XML_SCHEMAS_DURATION);
    xmlSchemaTypeFloatDef = xmlSchemaInitBasicType("float",
                                                   XML_SCHEMAS_FLOAT);
    xmlSchemaTypeDoubleDef = xmlSchemaInitBasicType("double",
                                                    XML_SCHEMAS_DOUBLE);
    xmlSchemaTypeBooleanDef = xmlSchemaInitBasicType("boolean",
                                                     XML_SCHEMAS_BOOLEAN);
    xmlSchemaTypeAnyURIDef = xmlSchemaInitBasicType("anyURI",
                                                    XML_SCHEMAS_ANYURI);
    xmlSchemaTypeHexBinaryDef = xmlSchemaInitBasicType("hexBinary",
                                                     XML_SCHEMAS_HEXBINARY);

    /*
     * derived datatypes
     */
    xmlSchemaTypeIntegerDef = xmlSchemaInitBasicType("integer",
                                                     XML_SCHEMAS_INTEGER);;
    xmlSchemaTypeNonPositiveIntegerDef =
        xmlSchemaInitBasicType("nonPositiveInteger",
                               XML_SCHEMAS_NPINTEGER);;
    xmlSchemaTypeNegativeIntegerDef =
        xmlSchemaInitBasicType("negativeInteger", XML_SCHEMAS_NINTEGER);;
    xmlSchemaTypeLongDef =
        xmlSchemaInitBasicType("long", XML_SCHEMAS_LONG);;
    xmlSchemaTypeIntDef = xmlSchemaInitBasicType("int", XML_SCHEMAS_INT);;
    xmlSchemaTypeShortDef = xmlSchemaInitBasicType("short",
                                                   XML_SCHEMAS_SHORT);;
    xmlSchemaTypeByteDef = xmlSchemaInitBasicType("byte",
                                                  XML_SCHEMAS_BYTE);;
    xmlSchemaTypeNonNegativeIntegerDef =
        xmlSchemaInitBasicType("nonNegativeInteger",
                               XML_SCHEMAS_NNINTEGER);
    xmlSchemaTypeUnsignedLongDef =
        xmlSchemaInitBasicType("unsignedLong", XML_SCHEMAS_ULONG);;
    xmlSchemaTypeUnsignedIntDef =
        xmlSchemaInitBasicType("unsignedInt", XML_SCHEMAS_UINT);;
    xmlSchemaTypeUnsignedShortDef =
        xmlSchemaInitBasicType("unsignedShort", XML_SCHEMAS_USHORT);;
    xmlSchemaTypeUnsignedByteDef =
        xmlSchemaInitBasicType("unsignedByte", XML_SCHEMAS_UBYTE);;
    xmlSchemaTypePositiveIntegerDef =
        xmlSchemaInitBasicType("positiveInteger", XML_SCHEMAS_PINTEGER);

    xmlSchemaTypeNormStringDef = xmlSchemaInitBasicType("normalizedString",
                                                        XML_SCHEMAS_NORMSTRING);
    xmlSchemaTypeTokenDef = xmlSchemaInitBasicType("token",
                                                   XML_SCHEMAS_TOKEN);
    xmlSchemaTypeLanguageDef = xmlSchemaInitBasicType("language",
                                                      XML_SCHEMAS_LANGUAGE);
    xmlSchemaTypeIdDef = xmlSchemaInitBasicType("ID", XML_SCHEMAS_ID);
    xmlSchemaTypeIdrefDef = xmlSchemaInitBasicType("IDREF",
                                                   XML_SCHEMAS_IDREF);
    xmlSchemaTypeIdrefsDef = xmlSchemaInitBasicType("IDREFS",
                                                    XML_SCHEMAS_IDREFS);
    xmlSchemaTypeEntityDef = xmlSchemaInitBasicType("ENTITY",
                                                    XML_SCHEMAS_ENTITY);
    xmlSchemaTypeEntitiesDef = xmlSchemaInitBasicType("ENTITIES",
                                                      XML_SCHEMAS_ENTITIES);
    xmlSchemaTypeNotationDef = xmlSchemaInitBasicType("NOTATION",
                                                    XML_SCHEMAS_NOTATION);
    xmlSchemaTypeNameDef = xmlSchemaInitBasicType("Name",
                                                  XML_SCHEMAS_NAME);
    xmlSchemaTypeQNameDef = xmlSchemaInitBasicType("QName",
                                                   XML_SCHEMAS_QNAME);
    xmlSchemaTypeNCNameDef = xmlSchemaInitBasicType("NCName",
                                                    XML_SCHEMAS_NCNAME);
    xmlSchemaTypeNmtokenDef = xmlSchemaInitBasicType("NMTOKEN",
                                                     XML_SCHEMAS_NMTOKEN);
    xmlSchemaTypeNmtokensDef = xmlSchemaInitBasicType("NMTOKENS",
                                                      XML_SCHEMAS_NMTOKENS);
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
    switch (value->type) {
        case XML_SCHEMAS_STRING:
        case XML_SCHEMAS_NORMSTRING:
        case XML_SCHEMAS_TOKEN:
        case XML_SCHEMAS_LANGUAGE:
        case XML_SCHEMAS_NMTOKEN:
        case XML_SCHEMAS_NMTOKENS:
        case XML_SCHEMAS_NAME:
        case XML_SCHEMAS_NCNAME:
        case XML_SCHEMAS_ID:
        case XML_SCHEMAS_IDREF:
        case XML_SCHEMAS_IDREFS:
        case XML_SCHEMAS_ENTITY:
        case XML_SCHEMAS_ENTITIES:
        case XML_SCHEMAS_NOTATION:
        case XML_SCHEMAS_ANYURI:
	    if (value->value.str != NULL)
		xmlFree(value->value.str);
	    break;
        case XML_SCHEMAS_QNAME:
	    if (value->value.qname.uri != NULL)
		xmlFree(value->value.qname.uri);
	    if (value->value.qname.name != NULL)
		xmlFree(value->value.qname.name);
	    break;
	default:
	    break;
    }
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

/****************************************************************
 *								*
 *		Convenience macros and functions		*
 *								*
 ****************************************************************/

#define IS_TZO_CHAR(c)						\
	((c == 0) || (c == 'Z') || (c == '+') || (c == '-'))

#define VALID_YEAR(yr)          (yr != 0)
#define VALID_MONTH(mon)        ((mon >= 1) && (mon <= 12))
/* VALID_DAY should only be used when month is unknown */
#define VALID_DAY(day)          ((day >= 1) && (day <= 31))
#define VALID_HOUR(hr)          ((hr >= 0) && (hr <= 23))
#define VALID_MIN(min)          ((min >= 0) && (min <= 59))
#define VALID_SEC(sec)          ((sec >= 0) && (sec < 60))
#define VALID_TZO(tzo)          ((tzo > -1440) && (tzo < 1440))
#define IS_LEAP(y)						\
	(((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0))

static const long daysInMonth[12] =
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static const long daysInMonthLeap[12] =
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

#define MAX_DAYINMONTH(yr,mon)                                  \
        (IS_LEAP(yr) ? daysInMonthLeap[mon - 1] : daysInMonth[mon - 1])

#define VALID_MDAY(dt)						\
	(IS_LEAP(dt->year) ?				        \
	    (dt->day <= daysInMonthLeap[dt->mon - 1]) :	        \
	    (dt->day <= daysInMonth[dt->mon - 1]))

#define VALID_DATE(dt)						\
	(VALID_YEAR(dt->year) && VALID_MONTH(dt->mon) && VALID_MDAY(dt))

#define VALID_TIME(dt)						\
	(VALID_HOUR(dt->hour) && VALID_MIN(dt->min) &&		\
	 VALID_SEC(dt->sec) && VALID_TZO(dt->tzo))

#define VALID_DATETIME(dt)					\
	(VALID_DATE(dt) && VALID_TIME(dt))

#define SECS_PER_MIN            (60)
#define SECS_PER_HOUR           (60 * SECS_PER_MIN)
#define SECS_PER_DAY            (24 * SECS_PER_HOUR)

static const long dayInYearByMonth[12] =
	{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
static const long dayInLeapYearByMonth[12] =
	{ 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335 };

#define DAY_IN_YEAR(day, month, year)				\
        ((IS_LEAP(year) ?					\
                dayInLeapYearByMonth[month - 1] :		\
                dayInYearByMonth[month - 1]) + day)

#ifdef DEBUG
#define DEBUG_DATE(dt)                                                  \
    xmlGenericError(xmlGenericErrorContext,                             \
        "type=%o %04ld-%02u-%02uT%02u:%02u:%03f",                       \
        dt->type,dt->value.date.year,dt->value.date.mon,                \
        dt->value.date.day,dt->value.date.hour,dt->value.date.min,      \
        dt->value.date.sec);                                            \
    if (dt->value.date.tz_flag)                                         \
        if (dt->value.date.tzo != 0)                                    \
            xmlGenericError(xmlGenericErrorContext,                     \
                "%+05d\n",dt->value.date.tzo);                          \
        else                                                            \
            xmlGenericError(xmlGenericErrorContext, "Z\n");             \
    else                                                                \
        xmlGenericError(xmlGenericErrorContext,"\n")
#else
#define DEBUG_DATE(dt)
#endif

/**
 * _xmlSchemaParseGYear:
 * @dt:  pointer to a date structure
 * @str: pointer to the string to analyze
 *
 * Parses a xs:gYear without time zone and fills in the appropriate
 * field of the @dt structure. @str is updated to point just after the
 * xs:gYear. It is supposed that @dt->year is big enough to contain
 * the year.
 *
 * Returns 0 or the error code
 */
static int
_xmlSchemaParseGYear (xmlSchemaValDatePtr dt, const xmlChar **str) {
    const xmlChar *cur = *str, *firstChar;
    int isneg = 0, digcnt = 0;

    if (((*cur < '0') || (*cur > '9')) &&
	(*cur != '-') && (*cur != '+'))
	return -1;

    if (*cur == '-') {
	isneg = 1;
	cur++;
    }

    firstChar = cur;

    while ((*cur >= '0') && (*cur <= '9')) {
	dt->year = dt->year * 10 + (*cur - '0');
	cur++;
	digcnt++;
    }

    /* year must be at least 4 digits (CCYY); over 4
     * digits cannot have a leading zero. */
    if ((digcnt < 4) || ((digcnt > 4) && (*firstChar == '0')))
	return 1;

    if (isneg)
	dt->year = - dt->year;

    if (!VALID_YEAR(dt->year))
	return 2;

    *str = cur;
    return 0;
}

/**
 * PARSE_2_DIGITS:
 * @num:  the integer to fill in
 * @cur:  an #xmlChar *
 * @invalid: an integer
 *
 * Parses a 2-digits integer and updates @num with the value. @cur is
 * updated to point just after the integer.
 * In case of error, @invalid is set to %TRUE, values of @num and
 * @cur are undefined.
 */
#define PARSE_2_DIGITS(num, cur, invalid)			\
	if ((cur[0] < '0') || (cur[0] > '9') ||			\
	    (cur[1] < '0') || (cur[1] > '9'))			\
	    invalid = 1;					\
	else							\
	    num = (cur[0] - '0') * 10 + (cur[1] - '0');		\
	cur += 2;

/**
 * PARSE_FLOAT:
 * @num:  the double to fill in
 * @cur:  an #xmlChar *
 * @invalid: an integer
 *
 * Parses a float and updates @num with the value. @cur is
 * updated to point just after the float. The float must have a
 * 2-digits integer part and may or may not have a decimal part.
 * In case of error, @invalid is set to %TRUE, values of @num and
 * @cur are undefined.
 */
#define PARSE_FLOAT(num, cur, invalid)				\
	PARSE_2_DIGITS(num, cur, invalid);			\
	if (!invalid && (*cur == '.')) {			\
	    double mult = 1;				        \
	    cur++;						\
	    if ((*cur < '0') || (*cur > '9'))			\
		invalid = 1;					\
	    while ((*cur >= '0') && (*cur <= '9')) {		\
		mult /= 10;					\
		num += (*cur - '0') * mult;			\
		cur++;						\
	    }							\
	}

/**
 * _xmlSchemaParseGMonth:
 * @dt:  pointer to a date structure
 * @str: pointer to the string to analyze
 *
 * Parses a xs:gMonth without time zone and fills in the appropriate
 * field of the @dt structure. @str is updated to point just after the
 * xs:gMonth.
 *
 * Returns 0 or the error code
 */
static int
_xmlSchemaParseGMonth (xmlSchemaValDatePtr dt, const xmlChar **str) {
    const xmlChar *cur = *str;
    int ret = 0;

    PARSE_2_DIGITS(dt->mon, cur, ret);
    if (ret != 0)
	return ret;

    if (!VALID_MONTH(dt->mon))
	return 2;

    *str = cur;
    return 0;
}

/**
 * _xmlSchemaParseGDay:
 * @dt:  pointer to a date structure
 * @str: pointer to the string to analyze
 *
 * Parses a xs:gDay without time zone and fills in the appropriate
 * field of the @dt structure. @str is updated to point just after the
 * xs:gDay.
 *
 * Returns 0 or the error code
 */
static int
_xmlSchemaParseGDay (xmlSchemaValDatePtr dt, const xmlChar **str) {
    const xmlChar *cur = *str;
    int ret = 0;

    PARSE_2_DIGITS(dt->day, cur, ret);
    if (ret != 0)
	return ret;

    if (!VALID_DAY(dt->day))
	return 2;

    *str = cur;
    return 0;
}

/**
 * _xmlSchemaParseTime:
 * @dt:  pointer to a date structure
 * @str: pointer to the string to analyze
 *
 * Parses a xs:time without time zone and fills in the appropriate
 * fields of the @dt structure. @str is updated to point just after the
 * xs:time.
 * In case of error, values of @dt fields are undefined.
 *
 * Returns 0 or the error code
 */
static int
_xmlSchemaParseTime (xmlSchemaValDatePtr dt, const xmlChar **str) {
    const xmlChar *cur = *str;
    unsigned int hour = 0; /* use temp var in case str is not xs:time */
    int ret = 0;

    PARSE_2_DIGITS(hour, cur, ret);
    if (ret != 0)
	return ret;

    if (*cur != ':')
	return 1;
    cur++;

    /* the ':' insures this string is xs:time */
    dt->hour = hour;

    PARSE_2_DIGITS(dt->min, cur, ret);
    if (ret != 0)
	return ret;

    if (*cur != ':')
	return 1;
    cur++;

    PARSE_FLOAT(dt->sec, cur, ret);
    if (ret != 0)
	return ret;

    if (!VALID_TIME(dt))
	return 2;

    *str = cur;
    return 0;
}

/**
 * _xmlSchemaParseTimeZone:
 * @dt:  pointer to a date structure
 * @str: pointer to the string to analyze
 *
 * Parses a time zone without time zone and fills in the appropriate
 * field of the @dt structure. @str is updated to point just after the
 * time zone.
 *
 * Returns 0 or the error code
 */
static int
_xmlSchemaParseTimeZone (xmlSchemaValDatePtr dt, const xmlChar **str) {
    const xmlChar *cur = *str;
    int ret = 0;

    if (str == NULL)
	return -1;

    switch (*cur) {
    case 0:
	dt->tz_flag = 0;
	dt->tzo = 0;
	break;

    case 'Z':
	dt->tz_flag = 1;
	dt->tzo = 0;
	cur++;
	break;

    case '+':
    case '-': {
	int isneg = 0, tmp = 0;
	isneg = (*cur == '-');

	cur++;

	PARSE_2_DIGITS(tmp, cur, ret);
	if (ret != 0)
	    return ret;
	if (!VALID_HOUR(tmp))
	    return 2;

	if (*cur != ':')
	    return 1;
	cur++;

	dt->tzo = tmp * 60;

	PARSE_2_DIGITS(tmp, cur, ret);
	if (ret != 0)
	    return ret;
	if (!VALID_MIN(tmp))
	    return 2;

	dt->tzo += tmp;
	if (isneg)
	    dt->tzo = - dt->tzo;

	if (!VALID_TZO(dt->tzo))
	    return 2;

	dt->tz_flag = 1;
	break;
      }
    default:
	return 1;
    }

    *str = cur;
    return 0;
}

/****************************************************************
 *								*
 *	XML Schema Dates/Times Datatypes Handling		*
 *								*
 ****************************************************************/

/**
 * PARSE_DIGITS:
 * @num:  the integer to fill in
 * @cur:  an #xmlChar *
 * @num_type: an integer flag
 *
 * Parses a digits integer and updates @num with the value. @cur is
 * updated to point just after the integer.
 * In case of error, @num_type is set to -1, values of @num and
 * @cur are undefined.
 */
#define PARSE_DIGITS(num, cur, num_type)	                \
	if ((*cur < '0') || (*cur > '9'))			\
	    num_type = -1;					\
        else                                                    \
	    while ((*cur >= '0') && (*cur <= '9')) {		\
	        num = num * 10 + (*cur - '0');		        \
	        cur++;                                          \
            }

/**
 * PARSE_NUM:
 * @num:  the double to fill in
 * @cur:  an #xmlChar *
 * @num_type: an integer flag
 *
 * Parses a float or integer and updates @num with the value. @cur is
 * updated to point just after the number. If the number is a float,
 * then it must have an integer part and a decimal part; @num_type will
 * be set to 1. If there is no decimal part, @num_type is set to zero.
 * In case of error, @num_type is set to -1, values of @num and
 * @cur are undefined.
 */
#define PARSE_NUM(num, cur, num_type)				\
        num = 0;                                                \
	PARSE_DIGITS(num, cur, num_type);	                \
	if (!num_type && (*cur == '.')) {			\
	    double mult = 1;				        \
	    cur++;						\
	    if ((*cur < '0') || (*cur > '9'))			\
		num_type = -1;					\
            else                                                \
                num_type = 1;                                   \
	    while ((*cur >= '0') && (*cur <= '9')) {		\
		mult /= 10;					\
		num += (*cur - '0') * mult;			\
		cur++;						\
	    }							\
	}

/**
 * xmlSchemaValidateDates:
 * @type: the expected type or XML_SCHEMAS_UNKNOWN
 * @dateTime:  string to analyze
 * @val:  the return computed value
 *
 * Check that @dateTime conforms to the lexical space of one of the date types.
 * if true a value is computed and returned in @val.
 *
 * Returns 0 if this validates, a positive error code number otherwise
 *         and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateDates (xmlSchemaValType type,
	                const xmlChar *dateTime, xmlSchemaValPtr *val) {
    xmlSchemaValPtr dt;
    int ret;
    const xmlChar *cur = dateTime;

#define RETURN_TYPE_IF_VALID(t)					\
    if (IS_TZO_CHAR(*cur)) {					\
	ret = _xmlSchemaParseTimeZone(&(dt->value.date), &cur);	\
	if (ret == 0) {						\
	    if (*cur != 0)					\
		goto error;					\
	    dt->type = t;					\
	    goto done;						\
	}							\
    }

    if (dateTime == NULL)
	return -1;

    if ((*cur != '-') && (*cur < '0') && (*cur > '9'))
	return 1;

    dt = xmlSchemaNewValue(XML_SCHEMAS_UNKNOWN);
    if (dt == NULL)
	return -1;

    if ((cur[0] == '-') && (cur[1] == '-')) {
	/*
	 * It's an incomplete date (xs:gMonthDay, xs:gMonth or
	 * xs:gDay)
	 */
	cur += 2;

	/* is it an xs:gDay? */
	if (*cur == '-') {
	    if (type == XML_SCHEMAS_GMONTH)
		goto error;
	  ++cur;
	    ret = _xmlSchemaParseGDay(&(dt->value.date), &cur);
	    if (ret != 0)
		goto error;

	    RETURN_TYPE_IF_VALID(XML_SCHEMAS_GDAY);

	    goto error;
	}

	/*
	 * it should be an xs:gMonthDay or xs:gMonth
	 */
	ret = _xmlSchemaParseGMonth(&(dt->value.date), &cur);
	if (ret != 0)
	    goto error;

        /*
         * a '-' char could indicate this type is xs:gMonthDay or
         * a negative time zone offset. Check for xs:gMonthDay first.
         * Also the first three char's of a negative tzo (-MM:SS) can
         * appear to be a valid day; so even if the day portion
         * of the xs:gMonthDay verifies, we must insure it was not
         * a tzo.
         */
        if (*cur == '-') {
            const xmlChar *rewnd = cur;
            cur++;

  	    ret = _xmlSchemaParseGDay(&(dt->value.date), &cur);
            if ((ret == 0) && ((*cur == 0) || (*cur != ':'))) {

                /*
                 * we can use the VALID_MDAY macro to validate the month
                 * and day because the leap year test will flag year zero
                 * as a leap year (even though zero is an invalid year).
                 */
                if (VALID_MDAY((&(dt->value.date)))) {

	            RETURN_TYPE_IF_VALID(XML_SCHEMAS_GMONTHDAY);

                    goto error;
                }
            }

            /*
             * not xs:gMonthDay so rewind and check if just xs:gMonth
             * with an optional time zone.
             */
            cur = rewnd;
        }

	RETURN_TYPE_IF_VALID(XML_SCHEMAS_GMONTH);

	goto error;
    }

    /*
     * It's a right-truncated date or an xs:time.
     * Try to parse an xs:time then fallback on right-truncated dates.
     */
    if ((*cur >= '0') && (*cur <= '9')) {
	ret = _xmlSchemaParseTime(&(dt->value.date), &cur);
	if (ret == 0) {
	    /* it's an xs:time */
	    RETURN_TYPE_IF_VALID(XML_SCHEMAS_TIME);
	}
    }

    /* fallback on date parsing */
    cur = dateTime;

    ret = _xmlSchemaParseGYear(&(dt->value.date), &cur);
    if (ret != 0)
	goto error;

    /* is it an xs:gYear? */
    RETURN_TYPE_IF_VALID(XML_SCHEMAS_GYEAR);

    if (*cur != '-')
	goto error;
    cur++;

    ret = _xmlSchemaParseGMonth(&(dt->value.date), &cur);
    if (ret != 0)
	goto error;

    /* is it an xs:gYearMonth? */
    RETURN_TYPE_IF_VALID(XML_SCHEMAS_GYEARMONTH);

    if (*cur != '-')
	goto error;
    cur++;

    ret = _xmlSchemaParseGDay(&(dt->value.date), &cur);
    if ((ret != 0) || !VALID_DATE((&(dt->value.date))))
	goto error;

    /* is it an xs:date? */
    RETURN_TYPE_IF_VALID(XML_SCHEMAS_DATE);

    if (*cur != 'T')
	goto error;
    cur++;

    /* it should be an xs:dateTime */
    ret = _xmlSchemaParseTime(&(dt->value.date), &cur);
    if (ret != 0)
	goto error;

    ret = _xmlSchemaParseTimeZone(&(dt->value.date), &cur);
    if ((ret != 0) || (*cur != 0) || !VALID_DATETIME((&(dt->value.date))))
	goto error;


    dt->type = XML_SCHEMAS_DATETIME;

done:
#if 1
    if ((type != XML_SCHEMAS_UNKNOWN) && (type != dt->type))
        goto error;
#else
    /*
     * insure the parsed type is equal to or less significant (right
     * truncated) than the desired type.
     */
    if ((type != XML_SCHEMAS_UNKNOWN) && (type != dt->type)) {

        /* time only matches time */
        if ((type == XML_SCHEMAS_TIME) && (dt->type == XML_SCHEMAS_TIME))
            goto error;

        if ((type == XML_SCHEMAS_DATETIME) &&
            ((dt->type != XML_SCHEMAS_DATE) ||
             (dt->type != XML_SCHEMAS_GYEARMONTH) ||
             (dt->type != XML_SCHEMAS_GYEAR)))
            goto error;

        if ((type == XML_SCHEMAS_DATE) &&
            ((dt->type != XML_SCHEMAS_GYEAR) ||
             (dt->type != XML_SCHEMAS_GYEARMONTH)))
            goto error;

        if ((type == XML_SCHEMAS_GYEARMONTH) && (dt->type != XML_SCHEMAS_GYEAR))
            goto error;

        if ((type == XML_SCHEMAS_GMONTHDAY) && (dt->type != XML_SCHEMAS_GMONTH))
            goto error;
    }
#endif

    if (val != NULL)
        *val = dt;
    else
	xmlSchemaFreeValue(dt);

    return 0;

error:
    if (dt != NULL)
	xmlSchemaFreeValue(dt);
    return 1;
}

/**
 * xmlSchemaValidateDuration:
 * @type: the predefined type
 * @duration:  string to analyze
 * @val:  the return computed value
 *
 * Check that @duration conforms to the lexical space of the duration type.
 * if true a value is computed and returned in @val.
 *
 * Returns 0 if this validates, a positive error code number otherwise
 *         and -1 in case of internal or API error.
 */
static int
xmlSchemaValidateDuration (xmlSchemaTypePtr type ATTRIBUTE_UNUSED,
	                   const xmlChar *duration, xmlSchemaValPtr *val) {
    const xmlChar  *cur = duration;
    xmlSchemaValPtr dur;
    int isneg = 0;
    unsigned int seq = 0;
    double         num;
    int            num_type = 0;  /* -1 = invalid, 0 = int, 1 = floating */
    const xmlChar  desig[]  = {'Y', 'M', 'D', 'H', 'M', 'S'};
    const double   multi[]  = { 0.0, 0.0, 86400.0, 3600.0, 60.0, 1.0, 0.0};

    if (duration == NULL)
	return -1;

    if (*cur == '-') {
        isneg = 1;
        cur++;
    }

    /* duration must start with 'P' (after sign) */
    if (*cur++ != 'P')
	return 1;

    if (*cur == 0)
	return 1;

    dur = xmlSchemaNewValue(XML_SCHEMAS_DURATION);
    if (dur == NULL)
	return -1;

    while (*cur != 0) {

        /* input string should be empty or invalid date/time item */
        if (seq >= sizeof(desig))
            goto error;

        /* T designator must be present for time items */
        if (*cur == 'T') {
            if (seq <= 3) {
                seq = 3;
                cur++;
            } else
                return 1;
        } else if (seq == 3)
            goto error;

        /* parse the number portion of the item */
        PARSE_NUM(num, cur, num_type);

        if ((num_type == -1) || (*cur == 0))
            goto error;

        /* update duration based on item type */
        while (seq < sizeof(desig)) {
            if (*cur == desig[seq]) {

                /* verify numeric type; only seconds can be float */
                if ((num_type != 0) && (seq < (sizeof(desig)-1)))
                    goto error;

                switch (seq) {
                    case 0:
                        dur->value.dur.mon = (long)num * 12;
                        break;
                    case 1:
                        dur->value.dur.mon += (long)num;
                        break;
                    default:
                        /* convert to seconds using multiplier */
                        dur->value.dur.sec += num * multi[seq];
                        seq++;
                        break;
                }

                break;          /* exit loop */
            }
            /* no date designators found? */
            if (++seq == 3)
                goto error;
        }
        cur++;
    }

    if (isneg) {
        dur->value.dur.mon = -dur->value.dur.mon;
        dur->value.dur.day = -dur->value.dur.day;
        dur->value.dur.sec = -dur->value.dur.sec;
    }

    if (val != NULL)
        *val = dur;
    else
	xmlSchemaFreeValue(dur);

    return 0;

error:
    if (dur != NULL)
	xmlSchemaFreeValue(dur);
    return 1;
}

/**
 * xmlSchemaStrip:
 * @value: a value
 *
 * Removes the leading and ending spaces of a string
 *
 * Returns the new string or NULL if no change was required.
 */
static xmlChar *
xmlSchemaStrip(const xmlChar *value) {
    const xmlChar *start = value, *end, *f;

    if (value == NULL) return(NULL);
    while ((*start != 0) && (IS_BLANK(*start))) start++;
    end = start;
    while (*end != 0) end++;
    f = end;
    end--;
    while ((end > start) && (IS_BLANK(*end))) end--;
    end++;
    if ((start == value) && (f == end)) return(NULL);
    return(xmlStrndup(start, end - start));
}

/**
 * xmlSchemaCollapseString:
 * @value: a value
 *
 * Removes and normalize white spaces in the string
 *
 * Returns the new string or NULL if no change was required.
 */
static xmlChar *
xmlSchemaCollapseString(const xmlChar *value) {
    const xmlChar *start = value, *end, *f;
    xmlChar *g;
    int col = 0;

    if (value == NULL) return(NULL);
    while ((*start != 0) && (IS_BLANK(*start))) start++;
    end = start;
    while (*end != 0) {
	if ((*end == ' ') && (IS_BLANK(end[1]))) {
	    col = end - start;
	    break;
	} else if ((*end == 0xa) || (*end == 0x9) || (*end == 0xd)) {
	    col = end - start;
	    break;
	}
	end++;
    }
    if (col == 0) {
	f = end;
	end--;
	while ((end > start) && (IS_BLANK(*end))) end--;
	end++;
	if ((start == value) && (f == end)) return(NULL);
	return(xmlStrndup(start, end - start));
    }
    start = xmlStrdup(start);
    if (start == NULL) return(NULL);
    g = (xmlChar *) (start + col);
    end = g;
    while (*end != 0) {
	if (IS_BLANK(*end)) {
	    end++;
	    while (IS_BLANK(*end)) end++;
	    if (*end != 0)
		*g++ = ' ';
	} else
	    *g++ = *end++;
    }
    *g = 0;
    return((xmlChar *) start);
}

/**
 * xmlSchemaValAtomicListNode:
 * @type: the predefined atomic type for a token in the list
 * @value: the list value to check
 * @ret:  the return computed value
 * @node:  the node containing the value
 *
 * Check that a value conforms to the lexical space of the predefined
 * list type. if true a value is computed and returned in @ret.
 *
 * Returns the number of items if this validates, a negative error code
 *         number otherwise
 */
static int
xmlSchemaValAtomicListNode(xmlSchemaTypePtr type, const xmlChar *value,
	                   xmlSchemaValPtr *ret, xmlNodePtr node) {
    xmlChar *val, *cur, *endval;
    int nb_values = 0;
    int tmp = 0;

    if (value == NULL) {
	return(-1);
    }
    val = xmlStrdup(value);
    if (val == NULL) {
	return(-1);
    }
    cur = val;
    /*
     * Split the list
     */
    while (IS_BLANK(*cur)) *cur++ = 0;
    while (*cur != 0) {
	if (IS_BLANK(*cur)) {
	    *cur = 0;
	    cur++;
	    while (IS_BLANK(*cur)) *cur++ = 0;
	} else {
	    nb_values++;
	    cur++;
	    while ((*cur != 0) && (!IS_BLANK(*cur))) cur++;
	}
    }
    if (nb_values == 0) {
	if (ret != NULL) {
	    TODO
	}
	xmlFree(val);
	return(nb_values);
    }
    endval = cur;
    cur = val;
    while ((*cur == 0) && (cur != endval)) cur++;
    while (cur != endval) {
	tmp = xmlSchemaValPredefTypeNode(type, cur, NULL, node);
	if (tmp != 0)
	    break;
	while (*cur != 0) cur++;
	while ((*cur == 0) && (cur != endval)) cur++;
    }
    xmlFree(val);
    if (ret != NULL) {
	TODO
    }
    if (tmp == 0)
	return(nb_values);
    return(-1);
}

/**
 * xmlSchemaParseUInt:
 * @str: pointer to the string R/W
 * @llo: pointer to the low result
 * @lmi: pointer to the mid result
 * @lhi: pointer to the high result
 *
 * Parse an unsigned long into 3 fields.
 *
 * Returns the number of chars parsed or -1 if overflow of the capacity
 */
static int
xmlSchemaParseUInt(const xmlChar **str, unsigned long *llo,
	           unsigned long *lmi, unsigned long *lhi) {
    unsigned long lo = 0, mi = 0, hi = 0;
    const xmlChar *tmp, *cur = *str;
    int ret = 0, i = 0;

    while (*cur == '0') {
	ret++;
	cur++;
    }
    tmp = cur;
    while ((*tmp != 0) && (*tmp >= '0') && (*tmp <= '9')) {
	i++;tmp++;ret++;
    }
    if (i > 24) {
	*str = tmp;
	return(-1);
    }
    while (i > 16) {
	hi = hi * 10 + (*cur++ - '0');
	i--;
    }
    while (i > 8) {
	mi = mi * 10 + (*cur++ - '0');
	i--;
    }
    while (i > 0) {
	lo = lo * 10 + (*cur++ - '0');
	i--;
    }

    *str = cur;
    *llo = lo;
    *lmi = mi;
    *lhi = hi;
    return(ret);
}

/**
 * xmlSchemaValAtomicType:
 * @type: the predefined type
 * @value: the value to check
 * @val:  the return computed value
 * @node:  the node containing the value
 * flags:  flags to control the vlidation
 *
 * Check that a value conforms to the lexical space of the atomic type.
 * if true a value is computed and returned in @val.
 *
 * Returns 0 if this validates, a positive error code number otherwise
 *         and -1 in case of internal or API error.
 */
static int
xmlSchemaValAtomicType(xmlSchemaTypePtr type, const xmlChar *value,
	               xmlSchemaValPtr *val, xmlNodePtr node, int flags) {
    xmlSchemaValPtr v;
    xmlChar *norm = NULL;
    int ret = 0;

    if (xmlSchemaTypesInitialized == 0)
	return(-1);
    if (type == NULL)
	return(-1);

    if (val != NULL)
	*val = NULL;
    if ((flags == 0) && (value != NULL)) {
	if ((type->flags != XML_SCHEMAS_STRING) &&
	    (type->flags != XML_SCHEMAS_NORMSTRING)) {
	    norm = xmlSchemaCollapseString(value);
	    if (norm != NULL)
		value = norm;
	}
    }

    switch (type->flags) {
        case XML_SCHEMAS_UNKNOWN:
	    if (type == xmlSchemaTypeAnyTypeDef)
		goto return0;
	    goto error;
        case XML_SCHEMAS_STRING:
	    goto return0;
        case XML_SCHEMAS_NORMSTRING:
	    TODO
	    goto return0;
        case XML_SCHEMAS_DECIMAL: {
	    const xmlChar *cur = value, *tmp;
	    int frac = 0, len, neg = 0;
	    unsigned long base = 0;
	    if (cur == NULL)
		goto return1;
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
	    len = cur - tmp;
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
		goto return1;
	    if (val != NULL) {
		v = xmlSchemaNewValue(XML_SCHEMAS_DECIMAL);
		if (v != NULL) {
		    v->value.decimal.lo = base;
		    v->value.decimal.sign = neg;
		    v->value.decimal.frac = frac;
		    v->value.decimal.total = frac + len;
		    *val = v;
		}
	    }
	    goto return0;
	}
        case XML_SCHEMAS_TIME:
        case XML_SCHEMAS_GDAY:
        case XML_SCHEMAS_GMONTH:
        case XML_SCHEMAS_GMONTHDAY:
        case XML_SCHEMAS_GYEAR:
        case XML_SCHEMAS_GYEARMONTH:
        case XML_SCHEMAS_DATE:
        case XML_SCHEMAS_DATETIME:
	    ret = xmlSchemaValidateDates(type->flags, value, val);
	    break;
        case XML_SCHEMAS_DURATION:
	    ret = xmlSchemaValidateDuration(type, value, val);
	    break;
        case XML_SCHEMAS_FLOAT:
        case XML_SCHEMAS_DOUBLE: {
	    const xmlChar *cur = value;
	    int neg = 0;
	    if (cur == NULL)
		goto return1;
	    if ((cur[0] == 'N') && (cur[1] == 'a') && (cur[2] == 'N')) {
		cur += 3;
		if (*cur != 0)
		    goto return1;
		if (val != NULL) {
		    if (type == xmlSchemaTypeFloatDef) {
			v = xmlSchemaNewValue(XML_SCHEMAS_FLOAT);
			if (v != NULL) {
			    v->value.f = (float) xmlXPathNAN;
			} else {
			    xmlSchemaFreeValue(v);
			    goto error;
			}
		    } else {
			v = xmlSchemaNewValue(XML_SCHEMAS_DOUBLE);
			if (v != NULL) {
			    v->value.d = xmlXPathNAN;
			} else {
			    xmlSchemaFreeValue(v);
			    goto error;
			}
		    }
		    *val = v;
		}
		goto return0;
	    }
	    if (*cur == '-') {
		neg = 1;
		cur++;
	    }
	    if ((cur[0] == 'I') && (cur[1] == 'N') && (cur[2] == 'F')) {
		cur += 3;
		if (*cur != 0)
		    goto return1;
		if (val != NULL) {
		    if (type == xmlSchemaTypeFloatDef) {
			v = xmlSchemaNewValue(XML_SCHEMAS_FLOAT);
			if (v != NULL) {
			    if (neg)
				v->value.f = (float) xmlXPathNINF;
			    else
				v->value.f = (float) xmlXPathPINF;
			} else {
			    xmlSchemaFreeValue(v);
			    goto error;
			}
		    } else {
			v = xmlSchemaNewValue(XML_SCHEMAS_DOUBLE);
			if (v != NULL) {
			    if (neg)
				v->value.d = xmlXPathNINF;
			    else
				v->value.d = xmlXPathPINF;
			} else {
			    xmlSchemaFreeValue(v);
			    goto error;
			}
		    }
		    *val = v;
		}
		goto return0;
	    }
	    if ((neg == 0) && (*cur == '+'))
		cur++;
	    if ((cur[0] == 0) || (cur[0] == '+') || (cur[0] == '-'))
		goto return1;
	    while ((*cur >= '0') && (*cur <= '9')) {
		cur++;
	    }
	    if (*cur == '.') {
		cur++;
		while ((*cur >= '0') && (*cur <= '9')) 
		    cur++;
	    }
	    if ((*cur == 'e') || (*cur == 'E')) {
		cur++;
		if ((*cur == '-') || (*cur == '+'))
		    cur++;
		while ((*cur >= '0') && (*cur <= '9')) 
		    cur++;
	    }
	    if (*cur != 0)
		goto return1;
	    if (val != NULL) {
		if (type == xmlSchemaTypeFloatDef) {
		    v = xmlSchemaNewValue(XML_SCHEMAS_FLOAT);
		    if (v != NULL) {
			if (sscanf((const char *)value, "%f", &(v->value.f))==1) {
			    *val = v;
			} else {
			    xmlGenericError(xmlGenericErrorContext,
				    "failed to scanf float %s\n", value);
			    xmlSchemaFreeValue(v);
			    goto return1;
			}
		    } else {
			goto error;
		    }
		} else {
		    v = xmlSchemaNewValue(XML_SCHEMAS_DOUBLE);
		    if (v != NULL) {
			if (sscanf((const char *)value, "%lf", &(v->value.d))==1) {
			    *val = v;
			} else {
			    xmlGenericError(xmlGenericErrorContext,
				    "failed to scanf double %s\n", value);
			    xmlSchemaFreeValue(v);
			    goto return1;
			}
		    } else {
			goto error;
		    }
		}
	    }
	    goto return0;
	}
        case XML_SCHEMAS_BOOLEAN: {
	    const xmlChar *cur = value;

	    if ((cur[0] == '0') && (cur[1] == 0))
		ret = 0;
	    else if ((cur[0] == '1') && (cur[1] == 0))
		ret = 1;
	    else if ((cur[0] == 't') && (cur[1] == 'r') && (cur[2] == 'u') &&
		     (cur[3] == 'e') && (cur[4] == 0))
		ret = 1;
	    else if ((cur[0] == 'f') && (cur[1] == 'a') && (cur[2] == 'l') &&
		     (cur[3] == 's') && (cur[4] == 'e') && (cur[5] == 0))
		ret = 0;
	    else 
		goto return1;
	    if (val != NULL) {
		v = xmlSchemaNewValue(XML_SCHEMAS_BOOLEAN);
		if (v != NULL) {
		    v->value.b = ret;
		    *val = v;
		} else {
		    goto error;
		}
	    }
	    goto return0;
	}
        case XML_SCHEMAS_TOKEN: {
	    const xmlChar *cur = value;

	    if (IS_BLANK(*cur))
		goto return1;

	    while (*cur != 0) {
		if ((*cur == 0xd) || (*cur == 0xa) || (*cur == 0x9)) {
		    goto return1;
		} else if (*cur == ' ') {
		    cur++;
		    if (*cur == 0)
			goto return1;
		    if (*cur == ' ')
			goto return1;
		} else {
		    cur++;
		}
	    }
	    if (val != NULL) {
		v = xmlSchemaNewValue(XML_SCHEMAS_TOKEN);
		if (v != NULL) {
		    v->value.str = xmlStrdup(value);
		    *val = v;
		} else {
		    goto error;
		}
	    }
	    goto return0;
	}
        case XML_SCHEMAS_LANGUAGE:
	    if (xmlCheckLanguageID(value) == 1) {
		if (val != NULL) {
		    v = xmlSchemaNewValue(XML_SCHEMAS_LANGUAGE);
		    if (v != NULL) {
			v->value.str = xmlStrdup(value);
			*val = v;
		    } else {
			goto error;
		    }
		}
		goto return0;
	    }
	    goto return1;
        case XML_SCHEMAS_NMTOKEN:
	    if (xmlValidateNMToken(value, 1) == 0) {
		if (val != NULL) {
		    v = xmlSchemaNewValue(XML_SCHEMAS_NMTOKEN);
		    if (v != NULL) {
			v->value.str = xmlStrdup(value);
			*val = v;
		    } else {
			goto error;
		    }
		}
		goto return0;
	    }
	    goto return1;
        case XML_SCHEMAS_NMTOKENS:
	    ret = xmlSchemaValAtomicListNode(xmlSchemaTypeNmtokenDef,
					     value, val, node);
	    if (ret > 0)
		ret = 0;
	    else
		ret = 1;
	    goto done;
        case XML_SCHEMAS_NAME:
	    ret = xmlValidateName(value, 1);
	    if ((ret == 0) && (val != NULL)) {
		TODO;
	    }
	    goto done;
        case XML_SCHEMAS_QNAME: {
	    xmlChar *uri = NULL;
	    xmlChar *local = NULL;

	    ret = xmlValidateQName(value, 1);
	    if ((ret == 0) && (node != NULL)) {
		xmlChar *prefix;
		local = xmlSplitQName2(value, &prefix);
		if (prefix != NULL) {
		    xmlNsPtr ns;

		    ns = xmlSearchNs(node->doc, node, prefix);
		    if (ns == NULL)
			ret = 1;
		    else if (val != NULL)
			uri = xmlStrdup(ns->href);
		}
		if ((local != NULL) && ((val == NULL) || (ret != 0)))
		    xmlFree(local);
		if (prefix != NULL)
		    xmlFree(prefix);
	    }
	    if ((ret == 0) && (val != NULL)) {
		v = xmlSchemaNewValue(XML_SCHEMAS_QNAME);
		if (v != NULL) {
		    if (local != NULL)
			v->value.qname.name = local;
		    else
			v->value.qname.name = xmlStrdup(value);
		    if (uri != NULL)
			v->value.qname.uri = uri;
		    
		    *val = v;
		} else {
		    if (local != NULL)
			xmlFree(local);
		    if (uri != NULL)
			xmlFree(uri);
		    goto error;
		}
	    }
	    goto done;
	}
        case XML_SCHEMAS_NCNAME:
	    ret = xmlValidateNCName(value, 1);
	    if ((ret == 0) && (val != NULL)) {
		v = xmlSchemaNewValue(XML_SCHEMAS_NCNAME);
		if (v != NULL) {
		    v->value.str = xmlStrdup(value);
		    *val = v;
		} else {
		    goto error;
		}
	    }
	    goto done;
        case XML_SCHEMAS_ID:
	    ret = xmlValidateNCName(value, 1);
	    if ((ret == 0) && (val != NULL)) {
		v = xmlSchemaNewValue(XML_SCHEMAS_ID);
		if (v != NULL) {
		    v->value.str = xmlStrdup(value);
		    *val = v;
		} else {
		    goto error;
		}
	    }
	    if ((ret == 0) && (node != NULL) &&
		(node->type == XML_ATTRIBUTE_NODE)) {
		xmlAttrPtr attr = (xmlAttrPtr) node;
		/*
		 * NOTE: the IDness might have already be declared in the DTD
		 */
		if (attr->atype != XML_ATTRIBUTE_ID) {
		    xmlIDPtr res;
		    xmlChar *strip;

		    strip = xmlSchemaStrip(value);
		    if (strip != NULL) {
			res = xmlAddID(NULL, node->doc, strip, attr);
			xmlFree(strip);
		    } else
			res = xmlAddID(NULL, node->doc, value, attr);
		    if (res == NULL) {
			ret = 2;
		    } else {
			attr->atype = XML_ATTRIBUTE_ID;
		    }
		}
	    }
	    goto done;
        case XML_SCHEMAS_IDREF:
	    ret = xmlValidateNCName(value, 1);
	    if ((ret == 0) && (val != NULL)) {
		TODO;
	    }
	    if ((ret == 0) && (node != NULL) &&
		(node->type == XML_ATTRIBUTE_NODE)) {
		xmlAttrPtr attr = (xmlAttrPtr) node;
		xmlChar *strip;

		strip = xmlSchemaStrip(value);
		if (strip != NULL) {
		    xmlAddRef(NULL, node->doc, strip, attr);
		    xmlFree(strip);
		} else
		    xmlAddRef(NULL, node->doc, value, attr);
		attr->atype = XML_ATTRIBUTE_IDREF;
	    }
	    goto done;
        case XML_SCHEMAS_IDREFS:
	    ret = xmlSchemaValAtomicListNode(xmlSchemaTypeIdrefDef,
					     value, val, node);
	    if (ret < 0)
		ret = 2;
	    else
		ret = 0;
	    if ((ret == 0) && (node != NULL) &&
		(node->type == XML_ATTRIBUTE_NODE)) {
		xmlAttrPtr attr = (xmlAttrPtr) node;

		attr->atype = XML_ATTRIBUTE_IDREFS;
	    }
	    goto done;
        case XML_SCHEMAS_ENTITY: {
	    xmlChar *strip;
	    ret = xmlValidateNCName(value, 1);
	    if ((node == NULL) || (node->doc == NULL))
		ret = 3;
	    if (ret == 0) {
		xmlEntityPtr ent;

		strip = xmlSchemaStrip(value);
		if (strip != NULL) {
		    ent = xmlGetDocEntity(node->doc, strip);
		    xmlFree(strip);
		} else {
		    ent = xmlGetDocEntity(node->doc, value);
		}
		if ((ent == NULL) ||
		    (ent->etype != XML_EXTERNAL_GENERAL_UNPARSED_ENTITY))
		    ret = 4;
	    }
	    if ((ret == 0) && (val != NULL)) {
		TODO;
	    }
	    if ((ret == 0) && (node != NULL) &&
		(node->type == XML_ATTRIBUTE_NODE)) {
		xmlAttrPtr attr = (xmlAttrPtr) node;

		attr->atype = XML_ATTRIBUTE_ENTITY;
	    }
	    goto done;
	}
        case XML_SCHEMAS_ENTITIES:
	    if ((node == NULL) || (node->doc == NULL))
		goto return3;
	    ret = xmlSchemaValAtomicListNode(xmlSchemaTypeEntityDef,
					     value, val, node);
	    if (ret <= 0)
		ret = 1;
	    else
		ret = 0;
	    if ((ret == 0) && (node != NULL) &&
		(node->type == XML_ATTRIBUTE_NODE)) {
		xmlAttrPtr attr = (xmlAttrPtr) node;

		attr->atype = XML_ATTRIBUTE_ENTITIES;
	    }
	    goto done;
        case XML_SCHEMAS_NOTATION: {
	    xmlChar *uri = NULL;
	    xmlChar *local = NULL;

	    ret = xmlValidateQName(value, 1);
	    if ((ret == 0) && (node != NULL)) {
		xmlChar *prefix;
		local = xmlSplitQName2(value, &prefix);
		if (prefix != NULL) {
		    xmlNsPtr ns;

		    ns = xmlSearchNs(node->doc, node, prefix);
		    if (ns == NULL)
			ret = 1;
		    else if (val != NULL)
			uri = xmlStrdup(ns->href);
		}
		if ((local != NULL) && ((val == NULL) || (ret != 0)))
		    xmlFree(local);
		if (prefix != NULL)
		    xmlFree(prefix);
	    }
	    if ((node == NULL) || (node->doc == NULL))
		ret = 3;
	    if (ret == 0) {
		ret = xmlValidateNotationUse(NULL, node->doc, value);
		if (ret == 1)
		    ret = 0;
		else
		    ret = 1;
	    }
	    if ((ret == 0) && (val != NULL)) {
		v = xmlSchemaNewValue(XML_SCHEMAS_NOTATION);
		if (v != NULL) {
		    if (local != NULL)
			v->value.qname.name = local;
		    else
			v->value.qname.name = xmlStrdup(value);
		    if (uri != NULL)
			v->value.qname.uri = uri;
		    
		    *val = v;
		} else {
		    if (local != NULL)
			xmlFree(local);
		    if (uri != NULL)
			xmlFree(uri);
		    goto error;
		}
	    }
	    goto done;
	}
        case XML_SCHEMAS_ANYURI: {
	    xmlURIPtr uri;

	    uri = xmlParseURI((const char *) value);
	    if (uri == NULL)
		goto return1;
	    if (val != NULL) {
		TODO;
	    }
	    xmlFreeURI(uri);
	    goto return0;
	}
        case XML_SCHEMAS_HEXBINARY: {
	    const xmlChar *tmp, *cur = value;
            int total, i = 0;
            unsigned long lo = 0, mi = 0, hi = 0;
	    unsigned long *base;

            tmp = cur;
            while (((*tmp >= '0') && (*tmp <= '9')) ||
                   ((*tmp >= 'A') && (*tmp <= 'F')) ||
                   ((*tmp >= 'a') && (*tmp <= 'f'))) {
	        i++;tmp++;
            }

	    if (*tmp != 0)
		goto return1;
            if (i > 24)
		goto return1;
            if ((i % 2) != 0)
		goto return1;

            total = i / 2;		/* number of octets */

	    if (i >= 16)
	        base = &hi;
	    else if (i >= 8)
	        base = &mi;
	    else
	        base = &lo;

            while (i > 0) {
                if ((*cur >= '0') && (*cur <= '9')) {
                    *base = *base * 16 + (*cur - '0');
                } else if ((*cur >= 'A') && (*cur <= 'F')) {
                    *base = *base * 16 + (*cur - 'A') + 10;
                } else if ((*cur >= 'a') && (*cur <= 'f')) {
                    *base = *base * 16 + (*cur - 'a') + 10;
                } else
            	    break;

                cur++;
                i--;
		if (i == 16)
		    base = &mi;
		else if (i == 8)
		    base = &lo;
            }

	    if (val != NULL) {
		v = xmlSchemaNewValue(XML_SCHEMAS_HEXBINARY);
		if (v != NULL) {
		    v->value.decimal.lo = lo;
		    v->value.decimal.mi = mi;
		    v->value.decimal.hi = hi;
		    v->value.decimal.total = total;
		    *val = v;
		} else {
		    goto error;
		}
	    }
	    goto return0;
        }
        case XML_SCHEMAS_INTEGER:
        case XML_SCHEMAS_PINTEGER:
        case XML_SCHEMAS_NPINTEGER:
        case XML_SCHEMAS_NINTEGER:
        case XML_SCHEMAS_NNINTEGER: {
	    const xmlChar *cur = value;
	    unsigned long lo, mi, hi;
	    int sign = 0;
	    if (cur == NULL)
		goto return1;
	    if (*cur == '-') {
		sign = 1;
		cur++;
	    } else if (*cur == '+')
		cur++;
	    ret = xmlSchemaParseUInt(&cur, &lo, &mi, &hi);
	    if (ret == 0)
	        goto return1;
	    if (*cur != 0)
		goto return1;
	    if (type->flags == XML_SCHEMAS_NPINTEGER) {
		if ((sign == 0) &&
		    ((hi != 0) || (mi != 0) || (lo != 0)))
		    goto return1;
	    } else if (type->flags == XML_SCHEMAS_PINTEGER) {
		if (sign == 1)
		    goto return1;
		if ((hi == 0) && (mi == 0) && (lo == 0))
		    goto return1;
	    } else if (type->flags == XML_SCHEMAS_NINTEGER) {
		if (sign == 0)
		    goto return1;
		if ((hi == 0) && (mi == 0) && (lo == 0))
		    goto return1;
	    } else if (type->flags == XML_SCHEMAS_NNINTEGER) {
		if ((sign == 1) &&
		    ((hi != 0) || (mi != 0) || (lo != 0)))
		    goto return1;
	    }
	    /*
	     * We can store a value only if no overflow occured
	     */
	    if ((ret > 0) && (val != NULL)) {
		v = xmlSchemaNewValue(type->flags);
		if (v != NULL) {
		    v->value.decimal.lo = lo;
		    v->value.decimal.mi = lo;
		    v->value.decimal.hi = lo;
		    v->value.decimal.sign = sign;
		    v->value.decimal.frac = 0;
		    v->value.decimal.total = cur - value;
		    *val = v;
		}
	    }
	    goto return0;
	}
        case XML_SCHEMAS_LONG:
        case XML_SCHEMAS_BYTE:
        case XML_SCHEMAS_SHORT:
        case XML_SCHEMAS_INT: {
	    const xmlChar *cur = value;
	    unsigned long lo, mi, hi;
	    int total = 0;
	    int sign = 0;
	    if (cur == NULL)
		goto return1;
	    if (*cur == '-') {
		sign = 1;
		cur++;
	    } else if (*cur == '+')
		cur++;
	    ret = xmlSchemaParseUInt(&cur, &lo, &mi, &hi);
	    if (ret <= 0)
	        goto return1;
	    if (*cur != 0)
		goto return1;
	    if (type->flags == XML_SCHEMAS_LONG) {
		if (hi >= 922) {
		    if (hi > 922)
			goto return1;
		    if (mi >= 33720368) {
			if (mi > 33720368)
			    goto return1;
		        if ((sign == 0) && (lo > 54775807))
			    goto return1;
		        if ((sign == 1) && (lo > 54775808))
			    goto return1;
		    }
		}
	    } else if (type->flags == XML_SCHEMAS_INT) {
		if (hi != 0)
		    goto return1;
		if (mi >= 21) {
		    if (mi > 21)
			goto return1;
		    if ((sign == 0) && (lo > 47483647))
			goto return1;
		    if ((sign == 1) && (lo > 47483648))
			goto return1;
		}
	    } else if (type->flags == XML_SCHEMAS_SHORT) {
		if ((mi != 0) || (hi != 0))
		    goto return1;
		if ((sign == 1) && (lo > 32768))
		    goto return1;
		if ((sign == 0) && (lo > 32767))
		    goto return1;
	    } else if (type->flags == XML_SCHEMAS_BYTE) {
		if ((mi != 0) || (hi != 0))
		    goto return1;
		if ((sign == 1) && (lo > 128))
		    goto return1;
		if ((sign == 0) && (lo > 127))
		    goto return1;
	    }
	    if (val != NULL) {
		v = xmlSchemaNewValue(type->flags);
		if (v != NULL) {
		    v->value.decimal.lo = lo;
		    v->value.decimal.mi = lo;
		    v->value.decimal.hi = lo;
		    v->value.decimal.sign = sign;
		    v->value.decimal.frac = 0;
		    v->value.decimal.total = total;
		    *val = v;
		}
	    }
	    goto return0;
	}
        case XML_SCHEMAS_UINT:
        case XML_SCHEMAS_ULONG:
        case XML_SCHEMAS_USHORT:
        case XML_SCHEMAS_UBYTE: {
	    const xmlChar *cur = value;
	    unsigned long lo, mi, hi;
	    int total = 0;
	    if (cur == NULL)
		goto return1;
	    ret = xmlSchemaParseUInt(&cur, &lo, &mi, &hi);
	    if (ret <= 0)
	        goto return1;
	    if (*cur != 0)
		goto return1;
	    if (type->flags == XML_SCHEMAS_ULONG) {
		if (hi >= 1844) {
		    if (hi > 1844)
			goto return1;
		    if (mi >= 67440737) {
			if (mi > 67440737)
			    goto return1;
			if (lo > 9551615)
			    goto return1;
		    }
		}
	    } else if (type->flags == XML_SCHEMAS_UINT) {
		if (hi != 0)
		    goto return1;
		if (mi >= 42) {
		    if (mi > 42)
			goto return1;
		    if (lo > 94967295)
			goto return1;
		}
	    } else if (type->flags == XML_SCHEMAS_USHORT) {
		if ((mi != 0) || (hi != 0))
		    goto return1;
		if (lo > 65535)
		    goto return1;
	    } else if (type->flags == XML_SCHEMAS_UBYTE) {
		if ((mi != 0) || (hi != 0))
		    goto return1;
		if (lo > 255)
		    goto return1;
	    }
	    if (val != NULL) {
		v = xmlSchemaNewValue(type->flags);
		if (v != NULL) {
		    v->value.decimal.lo = lo;
		    v->value.decimal.mi = mi;
		    v->value.decimal.hi = hi;
		    v->value.decimal.sign = 0;
		    v->value.decimal.frac = 0;
		    v->value.decimal.total = total;
		    *val = v;
		}
	    }
	    goto return0;
	}
    }

done:
    if (norm != NULL) xmlFree(norm);
    return(ret);
return3:
    if (norm != NULL) xmlFree(norm);
    return(3);
return1:
    if (norm != NULL) xmlFree(norm);
    return(1);
return0:
    if (norm != NULL) xmlFree(norm);
    return(0);
error:
    if (norm != NULL) xmlFree(norm);
    return(-1);
}

/**
 * xmlSchemaValPredefTypeNode:
 * @type: the predefined type
 * @value: the value to check
 * @val:  the return computed value
 * @node:  the node containing the value
 *
 * Check that a value conforms to the lexical space of the predefined type.
 * if true a value is computed and returned in @val.
 *
 * Returns 0 if this validates, a positive error code number otherwise
 *         and -1 in case of internal or API error.
 */
int
xmlSchemaValPredefTypeNode(xmlSchemaTypePtr type, const xmlChar *value,
	                   xmlSchemaValPtr *val, xmlNodePtr node) {
    return(xmlSchemaValAtomicType(type, value, val, node, 0));
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
    return(xmlSchemaValPredefTypeNode(type, value, val, NULL));
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
    int order = 1, p;
    unsigned long tmp;

    if ((x->value.decimal.sign) && 
	((x->value.decimal.lo != 0) ||
	 (x->value.decimal.mi != 0) ||
	 (x->value.decimal.hi != 0))) {
	if ((y->value.decimal.sign) &&
	    ((y->value.decimal.lo != 0) ||
	     (y->value.decimal.mi != 0) ||
	     (y->value.decimal.hi != 0)))
	    order = -1;
	else
	    return (-1);
    } else if ((y->value.decimal.sign) &&
	       ((y->value.decimal.lo != 0) ||
		(y->value.decimal.mi != 0) ||
		(y->value.decimal.hi != 0))) {
        return (1);
    }
    if (x->value.decimal.frac == y->value.decimal.frac) {
	if (x->value.decimal.hi < y->value.decimal.hi)
	    return (-order);
	if (x->value.decimal.hi < y->value.decimal.hi)
	    return (order);
	if (x->value.decimal.mi < y->value.decimal.mi)
	    return (-order);
	if (x->value.decimal.mi < y->value.decimal.mi)
	    return (order);
        if (x->value.decimal.lo < y->value.decimal.lo)
            return (-order);
        if (x->value.decimal.lo > y->value.decimal.lo)
	    return(order);
	return(0);
    }
    if (y->value.decimal.frac > x->value.decimal.frac) {
        swp = y;
        y = x;
        x = swp;
        order = -order;
    }
    p = powten[x->value.decimal.frac - y->value.decimal.frac];
    tmp = x->value.decimal.lo / p;
    if (tmp > y->value.decimal.lo)
        return (order);
    if (tmp < y->value.decimal.lo)
        return (-order);
    tmp = y->value.decimal.lo * p;
    if (x->value.decimal.lo < tmp)
        return (-order);
    if (x->value.decimal.lo == tmp)
        return (0);
    return (order);
}

/**
 * xmlSchemaCompareDurations:
 * @x:  a first duration value
 * @y:  a second duration value
 *
 * Compare 2 durations
 *
 * Returns -1 if x < y, 0 if x == y, 1 if x > y, 2 if x <> y, and -2 in
 * case of error
 */
static int
xmlSchemaCompareDurations(xmlSchemaValPtr x, xmlSchemaValPtr y)
{
    long carry, mon, day;
    double sec;
    int invert = 1;
    long xmon, xday, myear, minday, maxday;
    static const long dayRange [2][12] = {
        { 0, 28, 59, 89, 120, 150, 181, 212, 242, 273, 303, 334, },
        { 0, 31, 62, 92, 123, 153, 184, 215, 245, 276, 306, 337} };

    if ((x == NULL) || (y == NULL))
        return -2;

    /* months */
    mon = x->value.dur.mon - y->value.dur.mon;

    /* seconds */
    sec = x->value.dur.sec - y->value.dur.sec;
    carry = (long)sec / SECS_PER_DAY;
    sec -= (double)(carry * SECS_PER_DAY);

    /* days */
    day = x->value.dur.day - y->value.dur.day + carry;

    /* easy test */
    if (mon == 0) {
        if (day == 0)
            if (sec == 0.0)
                return 0;
            else if (sec < 0.0)
                return -1;
            else
                return 1;
        else if (day < 0)
            return -1;
        else
            return 1;
    }

    if (mon > 0) {
        if ((day >= 0) && (sec >= 0.0))
            return 1;
        else {
            xmon = mon;
            xday = -day;
        }
    } else if ((day <= 0) && (sec <= 0.0)) {
        return -1;
    } else {
	invert = -1;
        xmon = -mon;
        xday = day;
    }

    myear = xmon / 12;
    if (myear == 0) {
	minday = 0;
	maxday = 0;
    } else {
	maxday = 366 * ((myear + 3) / 4) +
	         365 * ((myear - 1) % 4);
	minday = maxday - 1;
    }

    xmon = xmon % 12;
    minday += dayRange[0][xmon];
    maxday += dayRange[1][xmon];

    if ((maxday == minday) && (maxday == xday))
	return(0); /* can this really happen ? */
    if (maxday < xday)
        return(-invert);
    if (minday > xday)
        return(invert);

    /* indeterminate */
    return 2;
}

/*
 * macros for adding date/times and durations
 */
#define FQUOTIENT(a,b)                  (floor(((double)a/(double)b)))
#define MODULO(a,b)                     (a - FQUOTIENT(a,b) * b)
#define FQUOTIENT_RANGE(a,low,high)     (FQUOTIENT((a-low),(high-low)))
#define MODULO_RANGE(a,low,high)        ((MODULO((a-low),(high-low)))+low)

/**
 * _xmlSchemaDateAdd:
 * @dt: an #xmlSchemaValPtr
 * @dur: an #xmlSchemaValPtr of type #XS_DURATION
 *
 * Compute a new date/time from @dt and @dur. This function assumes @dt
 * is either #XML_SCHEMAS_DATETIME, #XML_SCHEMAS_DATE, #XML_SCHEMAS_GYEARMONTH,
 * or #XML_SCHEMAS_GYEAR.
 *
 * Returns date/time pointer or NULL.
 */
static xmlSchemaValPtr
_xmlSchemaDateAdd (xmlSchemaValPtr dt, xmlSchemaValPtr dur)
{
    xmlSchemaValPtr ret;
    long carry, tempdays, temp;
    xmlSchemaValDatePtr r, d;
    xmlSchemaValDurationPtr u;

    if ((dt == NULL) || (dur == NULL))
        return NULL;

    ret = xmlSchemaNewValue(dt->type);
    if (ret == NULL)
        return NULL;

    r = &(ret->value.date);
    d = &(dt->value.date);
    u = &(dur->value.dur);

    /* normalization */
    if (d->mon == 0)
        d->mon = 1;

    /* normalize for time zone offset */
    u->sec -= (d->tzo * 60);
    d->tzo = 0;

    /* normalization */
    if (d->day == 0)
        d->day = 1;

    /* month */
    carry  = d->mon + u->mon;
    r->mon = MODULO_RANGE(carry, 1, 13);
    carry  = FQUOTIENT_RANGE(carry, 1, 13);

    /* year (may be modified later) */
    r->year = d->year + carry;
    if (r->year == 0) {
        if (d->year > 0)
            r->year--;
        else
            r->year++;
    }

    /* time zone */
    r->tzo     = d->tzo;
    r->tz_flag = d->tz_flag;

    /* seconds */
    r->sec = d->sec + u->sec;
    carry  = FQUOTIENT((long)r->sec, 60);
    if (r->sec != 0.0) {
        r->sec = MODULO(r->sec, 60.0);
    }

    /* minute */
    carry += d->min;
    r->min = MODULO(carry, 60);
    carry  = FQUOTIENT(carry, 60);

    /* hours */
    carry  += d->hour;
    r->hour = MODULO(carry, 24);
    carry   = FQUOTIENT(carry, 24);

    /*
     * days
     * Note we use tempdays because the temporary values may need more
     * than 5 bits
     */
    if ((VALID_YEAR(r->year)) && (VALID_MONTH(r->mon)) &&
                  (d->day > MAX_DAYINMONTH(r->year, r->mon)))
        tempdays = MAX_DAYINMONTH(r->year, r->mon);
    else if (d->day < 1)
        tempdays = 1;
    else
        tempdays = d->day;

    tempdays += u->day + carry;

    while (1) {
        if (tempdays < 1) {
            long tmon = MODULO_RANGE(r->mon-1, 1, 13);
            long tyr  = r->year + FQUOTIENT_RANGE(r->mon-1, 1, 13);
            if (tyr == 0)
                tyr--;
            tempdays += MAX_DAYINMONTH(tyr, tmon);
            carry = -1;
        } else if (tempdays > MAX_DAYINMONTH(r->year, r->mon)) {
            tempdays = tempdays - MAX_DAYINMONTH(r->year, r->mon);
            carry = 1;
        } else
            break;

        temp = r->mon + carry;
        r->mon = MODULO_RANGE(temp, 1, 13);
        r->year = r->year + FQUOTIENT_RANGE(temp, 1, 13);
        if (r->year == 0) {
            if (temp < 1)
                r->year--;
            else
                r->year++;
	}
    }
    
    r->day = tempdays;

    /*
     * adjust the date/time type to the date values
     */
    if (ret->type != XML_SCHEMAS_DATETIME) {
        if ((r->hour) || (r->min) || (r->sec))
            ret->type = XML_SCHEMAS_DATETIME;
        else if (ret->type != XML_SCHEMAS_DATE) {
            if ((r->mon != 1) && (r->day != 1))
                ret->type = XML_SCHEMAS_DATE;
            else if ((ret->type != XML_SCHEMAS_GYEARMONTH) && (r->mon != 1))
                ret->type = XML_SCHEMAS_GYEARMONTH;
        }
    }

    return ret;
}

/**
 * xmlSchemaDupVal:
 * @v: value to duplicate
 *
 * returns a duplicated value.
 */
static xmlSchemaValPtr
xmlSchemaDupVal (xmlSchemaValPtr v)
{
    xmlSchemaValPtr ret = xmlSchemaNewValue(v->type);
    if (ret == NULL)
        return ret;
    
    memcpy(ret, v, sizeof(xmlSchemaVal));
    return ret;
}

/**
 * xmlSchemaDateNormalize:
 * @dt: an #xmlSchemaValPtr
 *
 * Normalize @dt to GMT time.
 *
 */
static xmlSchemaValPtr
xmlSchemaDateNormalize (xmlSchemaValPtr dt, double offset)
{
    xmlSchemaValPtr dur, ret;

    if (dt == NULL)
        return NULL;

    if (((dt->type != XML_SCHEMAS_TIME) &&
         (dt->type != XML_SCHEMAS_DATETIME)) || (dt->value.date.tzo == 0))
        return xmlSchemaDupVal(dt);

    dur = xmlSchemaNewValue(XML_SCHEMAS_DURATION);
    if (dur == NULL)
        return NULL;

    dur->value.date.sec -= offset;

    ret = _xmlSchemaDateAdd(dt, dur);
    if (ret == NULL)
        return NULL;

    xmlSchemaFreeValue(dur);

    /* ret->value.date.tzo = 0; */
    return ret;
}

/**
 * _xmlSchemaDateCastYMToDays:
 * @dt: an #xmlSchemaValPtr
 *
 * Convert mon and year of @dt to total number of days. Take the 
 * number of years since (or before) 1 AD and add the number of leap
 * years. This is a function  because negative
 * years must be handled a little differently and there is no zero year.
 *
 * Returns number of days.
 */
static long
_xmlSchemaDateCastYMToDays (const xmlSchemaValPtr dt)
{
    long ret;

    if (dt->value.date.year < 0)
        ret = (dt->value.date.year * 365) +
              (((dt->value.date.year+1)/4)-((dt->value.date.year+1)/100)+
               ((dt->value.date.year+1)/400)) +
              DAY_IN_YEAR(0, dt->value.date.mon, dt->value.date.year);
    else
        ret = ((dt->value.date.year-1) * 365) +
              (((dt->value.date.year-1)/4)-((dt->value.date.year-1)/100)+
               ((dt->value.date.year-1)/400)) +
              DAY_IN_YEAR(0, dt->value.date.mon, dt->value.date.year);

    return ret;
}

/**
 * TIME_TO_NUMBER:
 * @dt:  an #xmlSchemaValPtr
 *
 * Calculates the number of seconds in the time portion of @dt.
 *
 * Returns seconds.
 */
#define TIME_TO_NUMBER(dt)                              \
    ((double)((dt->value.date.hour * SECS_PER_HOUR) +   \
              (dt->value.date.min * SECS_PER_MIN) +	\
              (dt->value.date.tzo * SECS_PER_MIN)) +	\
               dt->value.date.sec)

/**
 * xmlSchemaCompareDates:
 * @x:  a first date/time value
 * @y:  a second date/time value
 *
 * Compare 2 date/times
 *
 * Returns -1 if x < y, 0 if x == y, 1 if x > y, 2 if x <> y, and -2 in
 * case of error
 */
static int
xmlSchemaCompareDates (xmlSchemaValPtr x, xmlSchemaValPtr y)
{
    unsigned char xmask, ymask, xor_mask, and_mask;
    xmlSchemaValPtr p1, p2, q1, q2;
    long p1d, p2d, q1d, q2d;

    if ((x == NULL) || (y == NULL))
        return -2;

    if (x->value.date.tz_flag) {

        if (!y->value.date.tz_flag) {
            p1 = xmlSchemaDateNormalize(x, 0);
            p1d = _xmlSchemaDateCastYMToDays(p1) + p1->value.date.day;
            /* normalize y + 14:00 */
            q1 = xmlSchemaDateNormalize(y, (14 * SECS_PER_HOUR));

            q1d = _xmlSchemaDateCastYMToDays(q1) + q1->value.date.day;
            if (p1d < q1d) {
		xmlSchemaFreeValue(p1);
		xmlSchemaFreeValue(q1);
                return -1;
	    } else if (p1d == q1d) {
                double sec;

                sec = TIME_TO_NUMBER(p1) - TIME_TO_NUMBER(q1);
                if (sec < 0.0) {
		    xmlSchemaFreeValue(p1);
		    xmlSchemaFreeValue(q1);
                    return -1;
		} else {
                    /* normalize y - 14:00 */
                    q2 = xmlSchemaDateNormalize(y, -(14 * SECS_PER_HOUR));
                    q2d = _xmlSchemaDateCastYMToDays(q2) + q2->value.date.day;
		    xmlSchemaFreeValue(p1);
		    xmlSchemaFreeValue(q1);
		    xmlSchemaFreeValue(q2);
                    if (p1d > q2d)
                        return 1;
                    else if (p1d == q2d) {
                        sec = TIME_TO_NUMBER(p1) - TIME_TO_NUMBER(q2);
                        if (sec > 0.0)
                            return 1;
                        else
                            return 2; /* indeterminate */
                    }
                }
            } else {
		xmlSchemaFreeValue(p1);
		xmlSchemaFreeValue(q1);
	    }
        }
    } else if (y->value.date.tz_flag) {
        q1 = xmlSchemaDateNormalize(y, 0);
        q1d = _xmlSchemaDateCastYMToDays(q1) + q1->value.date.day;

        /* normalize x - 14:00 */
        p1 = xmlSchemaDateNormalize(x, -(14 * SECS_PER_HOUR));
        p1d = _xmlSchemaDateCastYMToDays(p1) + p1->value.date.day;

        if (p1d < q1d) {
	    xmlSchemaFreeValue(p1);
	    xmlSchemaFreeValue(q1);
            return -1;
	} else if (p1d == q1d) {
            double sec;

            sec = TIME_TO_NUMBER(p1) - TIME_TO_NUMBER(q1);
            if (sec < 0.0) {
		xmlSchemaFreeValue(p1);
		xmlSchemaFreeValue(q1);
                return -1;
	    } else {
                /* normalize x + 14:00 */
                p2 = xmlSchemaDateNormalize(x, (14 * SECS_PER_HOUR));
                p2d = _xmlSchemaDateCastYMToDays(p2) + p2->value.date.day;

                if (p2d > q1d) {
		    xmlSchemaFreeValue(p1);
		    xmlSchemaFreeValue(q1);
		    xmlSchemaFreeValue(p2);
                    return 1;
		} else if (p2d == q1d) {
                    sec = TIME_TO_NUMBER(p2) - TIME_TO_NUMBER(q1);
		    xmlSchemaFreeValue(p1);
		    xmlSchemaFreeValue(q1);
		    xmlSchemaFreeValue(p2);
                    if (sec > 0.0)
                        return 1;
                    else
                        return 2; /* indeterminate */
                }
		xmlSchemaFreeValue(p1);
		xmlSchemaFreeValue(q1);
		xmlSchemaFreeValue(p2);
            }
	} else {
	    xmlSchemaFreeValue(p1);
	    xmlSchemaFreeValue(q1);
        }
    }

    /*
     * if the same type then calculate the difference
     */
    if (x->type == y->type) {
        q1 = xmlSchemaDateNormalize(y, 0);
        q1d = _xmlSchemaDateCastYMToDays(q1) + q1->value.date.day;

        p1 = xmlSchemaDateNormalize(x, 0);
        p1d = _xmlSchemaDateCastYMToDays(p1) + p1->value.date.day;

        if (p1d < q1d) {
	    xmlSchemaFreeValue(p1);
	    xmlSchemaFreeValue(q1);
            return -1;
	} else if (p1d > q1d) {
	    xmlSchemaFreeValue(p1);
	    xmlSchemaFreeValue(q1);
            return 1;
	} else {
            double sec;

            sec = TIME_TO_NUMBER(p1) - TIME_TO_NUMBER(q1);
	    xmlSchemaFreeValue(p1);
	    xmlSchemaFreeValue(q1);
            if (sec < 0.0)
                return -1;
            else if (sec > 0.0)
                return 1;
            
        }
        return 0;
    }

    switch (x->type) {
        case XML_SCHEMAS_DATETIME:
            xmask = 0xf;
            break;
        case XML_SCHEMAS_DATE:
            xmask = 0x7;
            break;
        case XML_SCHEMAS_GYEAR:
            xmask = 0x1;
            break;
        case XML_SCHEMAS_GMONTH:
            xmask = 0x2;
            break;
        case XML_SCHEMAS_GDAY:
            xmask = 0x3;
            break;
        case XML_SCHEMAS_GYEARMONTH:
            xmask = 0x3;
            break;
        case XML_SCHEMAS_GMONTHDAY:
            xmask = 0x6;
            break;
        case XML_SCHEMAS_TIME:
            xmask = 0x8;
            break;
        default:
            xmask = 0;
            break;
    }

    switch (y->type) {
        case XML_SCHEMAS_DATETIME:
            ymask = 0xf;
            break;
        case XML_SCHEMAS_DATE:
            ymask = 0x7;
            break;
        case XML_SCHEMAS_GYEAR:
            ymask = 0x1;
            break;
        case XML_SCHEMAS_GMONTH:
            ymask = 0x2;
            break;
        case XML_SCHEMAS_GDAY:
            ymask = 0x3;
            break;
        case XML_SCHEMAS_GYEARMONTH:
            ymask = 0x3;
            break;
        case XML_SCHEMAS_GMONTHDAY:
            ymask = 0x6;
            break;
        case XML_SCHEMAS_TIME:
            ymask = 0x8;
            break;
        default:
            ymask = 0;
            break;
    }

    xor_mask = xmask ^ ymask;           /* mark type differences */
    and_mask = xmask & ymask;           /* mark field specification */

    /* year */
    if (xor_mask & 1)
        return 2; /* indeterminate */
    else if (and_mask & 1) {
        if (x->value.date.year < y->value.date.year)
            return -1;
        else if (x->value.date.year > y->value.date.year)
            return 1;
    }

    /* month */
    if (xor_mask & 2)
        return 2; /* indeterminate */
    else if (and_mask & 2) {
        if (x->value.date.mon < y->value.date.mon)
            return -1;
        else if (x->value.date.mon > y->value.date.mon)
            return 1;
    }

    /* day */
    if (xor_mask & 4)
        return 2; /* indeterminate */
    else if (and_mask & 4) {
        if (x->value.date.day < y->value.date.day)
            return -1;
        else if (x->value.date.day > y->value.date.day)
            return 1;
    }

    /* time */
    if (xor_mask & 8)
        return 2; /* indeterminate */
    else if (and_mask & 8) {
        if (x->value.date.hour < y->value.date.hour)
            return -1;
        else if (x->value.date.hour > y->value.date.hour)
            return 1;
        else if (x->value.date.min < y->value.date.min)
            return -1;
        else if (x->value.date.min > y->value.date.min)
            return 1;
        else if (x->value.date.sec < y->value.date.sec)
            return -1;
        else if (x->value.date.sec > y->value.date.sec)
            return 1;
    }

    return 0;
}

/**
 * xmlSchemaCompareNormStrings:
 * @x:  a first string value
 * @y:  a second string value
 *
 * Compare 2 string for their normalized values.
 *
 * Returns -1 if x < y, 0 if x == y, 1 if x > y, and -2 in
 * case of error
 */
static int
xmlSchemaCompareNormStrings(xmlSchemaValPtr x, xmlSchemaValPtr y) {
    const xmlChar *utf1;
    const xmlChar *utf2;
    int tmp;

    if ((x == NULL) || (y == NULL))
	return(-2);
    utf1 = x->value.str;
    utf2 = y->value.str;
    
    while (IS_BLANK(*utf1)) utf1++;
    while (IS_BLANK(*utf2)) utf2++;
    while ((*utf1 != 0) && (*utf2 != 0)) {
	if (IS_BLANK(*utf1)) {
	    if (!IS_BLANK(*utf2)) {
		tmp = *utf1 - *utf2;
		return(tmp);
	    }
	    while (IS_BLANK(*utf1)) utf1++;
	    while (IS_BLANK(*utf2)) utf2++;
	} else {
	    tmp = *utf1++ - *utf2++;
	    if (tmp < 0)
		return(-1);
	    if (tmp > 0)
		return(1);
	}
    }
    if (*utf1 != 0) {
	while (IS_BLANK(*utf1)) utf1++;
	if (*utf1 != 0)
	    return(1);
    }
    if (*utf2 != 0) {
	while (IS_BLANK(*utf2)) utf2++;
	if (*utf2 != 0)
	    return(-1);
    }
    return(0);
}

/**
 * xmlSchemaCompareFloats:
 * @x:  a first float or double value
 * @y:  a second float or double value
 *
 * Compare 2 values
 *
 * Returns -1 if x < y, 0 if x == y, 1 if x > y, 2 if x <> y, and -2 in
 * case of error
 */
static int
xmlSchemaCompareFloats(xmlSchemaValPtr x, xmlSchemaValPtr y) {
    double d1, d2;

    if ((x == NULL) || (y == NULL))
	return(-2);

    /*
     * Cast everything to doubles.
     */
    if (x->type == XML_SCHEMAS_DOUBLE)
	d1 = x->value.d;
    else if (x->type == XML_SCHEMAS_FLOAT)
	d1 = x->value.f;
    else
	return(-2);

    if (y->type == XML_SCHEMAS_DOUBLE)
	d2 = y->value.d;
    else if (y->type == XML_SCHEMAS_FLOAT)
	d2 = y->value.f;
    else
	return(-2);

    /*
     * Check for special cases.
     */
    if (xmlXPathIsNaN(d1)) {
	if (xmlXPathIsNaN(d2))
	    return(0);
	return(1);
    }
    if (xmlXPathIsNaN(d2))
	return(-1);
    if (d1 == xmlXPathPINF) {
	if (d2 == xmlXPathPINF)
	    return(0);
        return(1);
    }
    if (d2 == xmlXPathPINF)
        return(-1);
    if (d1 == xmlXPathNINF) {
	if (d2 == xmlXPathNINF)
	    return(0);
        return(-1);
    }
    if (d2 == xmlXPathNINF)
        return(1);

    /*
     * basic tests, the last one we should have equality, but
     * portability is more important than speed and handling
     * NaN or Inf in a portable way is always a challenge, so ...
     */
    if (d1 < d2)
	return(-1);
    if (d1 > d2)
	return(1);
    if (d1 == d2)
	return(0);
    return(2);
}

/**
 * xmlSchemaCompareValues:
 * @x:  a first value
 * @y:  a second value
 *
 * Compare 2 values
 *
 * Returns -1 if x < y, 0 if x == y, 1 if x > y, 2 if x <> y, and -2 in
 * case of error
 */
int
xmlSchemaCompareValues(xmlSchemaValPtr x, xmlSchemaValPtr y) {
    if ((x == NULL) || (y == NULL))
	return(-2);

    switch (x->type) {
	case XML_SCHEMAS_UNKNOWN:
	    return(-2);
        case XML_SCHEMAS_INTEGER:
        case XML_SCHEMAS_NPINTEGER:
        case XML_SCHEMAS_NINTEGER:
        case XML_SCHEMAS_NNINTEGER:
        case XML_SCHEMAS_PINTEGER:
        case XML_SCHEMAS_INT:
        case XML_SCHEMAS_UINT:
        case XML_SCHEMAS_LONG:
        case XML_SCHEMAS_ULONG:
        case XML_SCHEMAS_SHORT:
        case XML_SCHEMAS_USHORT:
        case XML_SCHEMAS_BYTE:
        case XML_SCHEMAS_UBYTE:
	case XML_SCHEMAS_DECIMAL:
	    if (y->type == x->type)
		return(xmlSchemaCompareDecimals(x, y));
	    if ((y->type == XML_SCHEMAS_DECIMAL) ||
		(y->type == XML_SCHEMAS_INTEGER) ||
		(y->type == XML_SCHEMAS_NPINTEGER) ||
		(y->type == XML_SCHEMAS_NINTEGER) ||
		(y->type == XML_SCHEMAS_NNINTEGER) ||
		(y->type == XML_SCHEMAS_PINTEGER) ||
		(y->type == XML_SCHEMAS_INT) ||
		(y->type == XML_SCHEMAS_UINT) ||
		(y->type == XML_SCHEMAS_LONG) ||
		(y->type == XML_SCHEMAS_ULONG) ||
		(y->type == XML_SCHEMAS_SHORT) ||
		(y->type == XML_SCHEMAS_USHORT) ||
		(y->type == XML_SCHEMAS_BYTE) ||
		(y->type == XML_SCHEMAS_UBYTE))
		return(xmlSchemaCompareDecimals(x, y));
	    return(-2);
        case XML_SCHEMAS_DURATION:
	    if (y->type == XML_SCHEMAS_DURATION)
                return(xmlSchemaCompareDurations(x, y));
            return(-2);
        case XML_SCHEMAS_TIME:
        case XML_SCHEMAS_GDAY:
        case XML_SCHEMAS_GMONTH:
        case XML_SCHEMAS_GMONTHDAY:
        case XML_SCHEMAS_GYEAR:
        case XML_SCHEMAS_GYEARMONTH:
        case XML_SCHEMAS_DATE:
        case XML_SCHEMAS_DATETIME:
            if ((y->type == XML_SCHEMAS_DATETIME)  ||
                (y->type == XML_SCHEMAS_TIME)      ||
                (y->type == XML_SCHEMAS_GDAY)      ||
                (y->type == XML_SCHEMAS_GMONTH)    ||
                (y->type == XML_SCHEMAS_GMONTHDAY) ||
                (y->type == XML_SCHEMAS_GYEAR)     ||
                (y->type == XML_SCHEMAS_DATE)      ||
                (y->type == XML_SCHEMAS_GYEARMONTH))
                return (xmlSchemaCompareDates(x, y));
            return (-2);
        case XML_SCHEMAS_NORMSTRING:
        case XML_SCHEMAS_TOKEN:
        case XML_SCHEMAS_LANGUAGE:
        case XML_SCHEMAS_NMTOKEN:
        case XML_SCHEMAS_NAME:
        case XML_SCHEMAS_NCNAME:
        case XML_SCHEMAS_ID:
        case XML_SCHEMAS_IDREF:
        case XML_SCHEMAS_ENTITY:
        case XML_SCHEMAS_NOTATION:
        case XML_SCHEMAS_ANYURI:
            if ((y->type == XML_SCHEMAS_NORMSTRING) ||
                (y->type == XML_SCHEMAS_TOKEN) ||
                (y->type == XML_SCHEMAS_LANGUAGE) ||
                (y->type == XML_SCHEMAS_NMTOKEN) ||
                (y->type == XML_SCHEMAS_NAME) ||
                (y->type == XML_SCHEMAS_QNAME) ||
                (y->type == XML_SCHEMAS_NCNAME) ||
                (y->type == XML_SCHEMAS_ID) ||
                (y->type == XML_SCHEMAS_IDREF) ||
                (y->type == XML_SCHEMAS_ENTITY) ||
                (y->type == XML_SCHEMAS_NOTATION) ||
                (y->type == XML_SCHEMAS_ANYURI))
                return (xmlSchemaCompareNormStrings(x, y));
            return (-2);
        case XML_SCHEMAS_QNAME:
            if (y->type == XML_SCHEMAS_QNAME) {
		if ((xmlStrEqual(x->value.qname.name, y->value.qname.name)) &&
		    (xmlStrEqual(x->value.qname.uri, y->value.qname.uri)))
		    return(0);
		return(2);
	    }
	    return (-2);
        case XML_SCHEMAS_FLOAT:
        case XML_SCHEMAS_DOUBLE:
            if ((y->type == XML_SCHEMAS_FLOAT) ||
                (y->type == XML_SCHEMAS_DOUBLE))
                return (xmlSchemaCompareFloats(x, y));
            return (-2);
        case XML_SCHEMAS_BOOLEAN:
            if (y->type == XML_SCHEMAS_BOOLEAN) {
		if (x->value.b == y->value.b)
		    return(0);
		if (x->value.b == 0)
		    return(-1);
		return(1);
	    }
	    return (-2);
        case XML_SCHEMAS_HEXBINARY:
            if (y->type == XML_SCHEMAS_HEXBINARY)
                return (xmlSchemaCompareDecimals(x, y));
            return (-2);
        case XML_SCHEMAS_STRING:
        case XML_SCHEMAS_IDREFS:
        case XML_SCHEMAS_ENTITIES:
        case XML_SCHEMAS_NMTOKENS:
	    TODO
	    break;
    }
    return -2;
}

/**
 * xmlSchemaNormLen:
 * @value:  a string
 *
 * Computes the UTF8 length of the normalized value of the string
 *
 * Returns the length or -1 in case of error.
 */
static int
xmlSchemaNormLen(const xmlChar *value) {
    const xmlChar *utf;
    int ret = 0;

    if (value == NULL)
	return(-1);
    utf = value;
    while (IS_BLANK(*utf)) utf++;
    while (*utf != 0) {
	if (utf[0] & 0x80) {
	    if ((utf[1] & 0xc0) != 0x80)
		return(-1);
	    if ((utf[0] & 0xe0) == 0xe0) {
		if ((utf[2] & 0xc0) != 0x80)
		    return(-1);
		if ((utf[0] & 0xf0) == 0xf0) {
		    if ((utf[0] & 0xf8) != 0xf0 || (utf[3] & 0xc0) != 0x80)
			return(-1);
		    utf += 4;
		} else {
		    utf += 3;
		}
	    } else {
		utf += 2;
	    }
	} else if (IS_BLANK(*utf)) {
	    while (IS_BLANK(*utf)) utf++;
	    if (*utf == 0)
		break;
	} else {
	    utf++;
	}
	ret++;
    }
    return(ret);
}

/**
 * xmlSchemaValidateFacet:
 * @base:  the base type
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
xmlSchemaValidateFacet(xmlSchemaTypePtr base ATTRIBUTE_UNUSED,
	               xmlSchemaFacetPtr facet,
	               const xmlChar *value, xmlSchemaValPtr val)
{
    int ret;

    switch (facet->type) {
	case XML_SCHEMA_FACET_PATTERN:
	    ret = xmlRegexpExec(facet->regexp, value);
	    if (ret == 1)
		return(0);
	    if (ret == 0) {
		/* TODO error code */
		return(1);
	    }
	    return(ret);
	case XML_SCHEMA_FACET_MAXEXCLUSIVE:
	    ret = xmlSchemaCompareValues(val, facet->val);
	    if (ret == -2) {
		/* TODO error code */
		return(-1);
	    }
	    if (ret == -1)
		return(0);
	    /* error code */
	    return(1);
	case XML_SCHEMA_FACET_MAXINCLUSIVE:
	    ret = xmlSchemaCompareValues(val, facet->val);
	    if (ret == -2) {
		/* TODO error code */
		return(-1);
	    }
	    if ((ret == -1) || (ret == 0))
		return(0);
	    /* error code */
	    return(1);
	case XML_SCHEMA_FACET_MINEXCLUSIVE:
	    ret = xmlSchemaCompareValues(val, facet->val);
	    if (ret == -2) {
		/* TODO error code */
		return(-1);
	    }
	    if (ret == 1)
		return(0);
	    /* error code */
	    return(1);
	case XML_SCHEMA_FACET_MININCLUSIVE:
	    ret = xmlSchemaCompareValues(val, facet->val);
	    if (ret == -2) {
		/* TODO error code */
		return(-1);
	    }
	    if ((ret == 1) || (ret == 0))
		return(0);
	    /* error code */
	    return(1);
	case XML_SCHEMA_FACET_WHITESPACE:
	    /* TODO whitespaces */
	    return(0);
	case  XML_SCHEMA_FACET_ENUMERATION:
	    if ((facet->value != NULL) &&
		(xmlStrEqual(facet->value, value)))
		return(0);
	    return(1);
	case XML_SCHEMA_FACET_LENGTH:
	case XML_SCHEMA_FACET_MAXLENGTH:
	case XML_SCHEMA_FACET_MINLENGTH: {
	    unsigned int len = 0;

	    if ((facet->val == NULL) ||
		((facet->val->type != XML_SCHEMAS_DECIMAL) &&
		 (facet->val->type != XML_SCHEMAS_NNINTEGER)) ||
		(facet->val->value.decimal.frac != 0)) {
		return(-1);
	    }
	    if ((val != NULL) && (val->type == XML_SCHEMAS_HEXBINARY))
	        len = val->value.decimal.total;
	    else { 
	        switch (base->flags) {
	    	    case XML_SCHEMAS_IDREF:
		    case XML_SCHEMAS_NORMSTRING:
		    case XML_SCHEMAS_TOKEN:
		    case XML_SCHEMAS_LANGUAGE:
		    case XML_SCHEMAS_NMTOKEN:
		    case XML_SCHEMAS_NAME:
		    case XML_SCHEMAS_NCNAME:
		    case XML_SCHEMAS_ID:
		        len = xmlSchemaNormLen(value);
		        break;
		    case XML_SCHEMAS_STRING:
		        len = xmlUTF8Strlen(value);
		        break;
		    default:
		        TODO
	        }
	    }
	    if (facet->type == XML_SCHEMA_FACET_LENGTH) {
		if (len != facet->val->value.decimal.lo)
		    return(1);
	    } else if (facet->type == XML_SCHEMA_FACET_MINLENGTH) {
		if (len < facet->val->value.decimal.lo)
		    return(1);
	    } else {
		if (len > facet->val->value.decimal.lo)
		    return(1);
	    }
	    break;
	}
	case XML_SCHEMA_FACET_TOTALDIGITS:
	case XML_SCHEMA_FACET_FRACTIONDIGITS:

	    if ((facet->val == NULL) ||
		((facet->val->type != XML_SCHEMAS_DECIMAL) &&
		 (facet->val->type != XML_SCHEMAS_NNINTEGER)) ||
		(facet->val->value.decimal.frac != 0)) {
		return(-1);
	    }
	    if ((val == NULL) ||
		((val->type != XML_SCHEMAS_DECIMAL) &&
		 (val->type != XML_SCHEMAS_INTEGER) &&
		 (val->type != XML_SCHEMAS_NPINTEGER) &&
		 (val->type != XML_SCHEMAS_NINTEGER) &&
		 (val->type != XML_SCHEMAS_NNINTEGER) &&
		 (val->type != XML_SCHEMAS_PINTEGER) &&
		 (val->type != XML_SCHEMAS_INT) &&
		 (val->type != XML_SCHEMAS_UINT) &&
		 (val->type != XML_SCHEMAS_LONG) &&
		 (val->type != XML_SCHEMAS_ULONG) &&
		 (val->type != XML_SCHEMAS_SHORT) &&
		 (val->type != XML_SCHEMAS_USHORT) &&
		 (val->type != XML_SCHEMAS_BYTE) &&
		 (val->type != XML_SCHEMAS_UBYTE))) {
		return(-1);
	    }
	    if (facet->type == XML_SCHEMA_FACET_TOTALDIGITS) {
	        if (val->value.decimal.total > facet->val->value.decimal.lo)
	            return(1);

	    } else if (facet->type == XML_SCHEMA_FACET_FRACTIONDIGITS) {
	        if (val->value.decimal.frac > facet->val->value.decimal.lo)
		    return(1);
	    }
	    break;
	default:
	    TODO
    }
    return(0);

}

#endif /* LIBXML_SCHEMAS_ENABLED */
