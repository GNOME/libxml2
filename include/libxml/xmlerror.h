#include <libxml/parser.h>

#ifndef __XML_ERROR_H__
#define __XML_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xmlErrorLevel:
 *
 * Indicates the level of an error
 */
typedef enum {
    XML_ERR_NONE = 0,
    XML_ERR_WARNING = 1,	/* A simple warning */
    XML_ERR_ERROR = 2,		/* A recoverable error */
    XML_ERR_FATAL = 3		/* A fatal error */
} xmlErrorLevel;

/**
 * xmlErrorDomain:
 *
 * Indicates where an error may have come from
 */
typedef enum {
    XML_FROM_NONE = 0,
    XML_FROM_PARSER,	/* The XML parser */
    XML_FROM_NAMESPACE,	/* The XML Namespace module */
    XML_FROM_DTD,	/* The XML DTD validation */
    XML_FROM_HTML,	/* The HTML parser */
    XML_FROM_MEMORY,	/* The memory allocator */
    XML_FROM_OUTPUT,	/* The serialization code */
    XML_FROM_IO,		/* The Input/Output stack */
    XML_FROM_XINCLUDE,	/* The XInclude processing */
    XML_FROM_XPATH,	/* The XPath module */
    XML_FROM_XPOINTER,	/* The XPointer module */
    XML_FROM_REGEXP,	/* The regular expressions module */
    XML_FROM_SCHEMAS,	/* The W3C XML Schemas module */
    XML_FROM_RELAXNG,	/* The Relax-NG module */
    XML_FROM_CATALOG,	/* The Catalog module */
    XML_FROM_C14N,	/* The Canonicalization module */
    XML_FROM_XSLT	/* The XSLT engine from libxslt */
} xmlErrorDomain;

/**
 * xmlError:
 *
 * An XML Error instance.
 */

typedef struct _xmlError xmlError;
typedef xmlError *xmlErrorPtr;
struct _xmlError {
    int		domain;	/* What part of the library raised this error */
    int		code;	/* The error code, e.g. an xmlParserError */
    char       *message;/* human-readable informative error message */
    xmlErrorLevel level;/* how consequent is the error */
    char       *file;	/* the filename */
    int		line;	/* the line number if available */
    char       *str1;	/* extra string information */
    char       *str2;	/* extra string information */
    char       *str3;	/* extra string information */
    int		int1;	/* extra number information */
    int		int2;	/* extra number information */
};

/**
 * xmlParserError:
 *
 * This is an error that the XML (or HTML) parser can generate
 */
typedef enum {
    XML_ERR_OK = 0,
    XML_ERR_INTERNAL_ERROR,
    XML_ERR_NO_MEMORY,
    
    XML_ERR_DOCUMENT_START, /* 3 */
    XML_ERR_DOCUMENT_EMPTY,
    XML_ERR_DOCUMENT_END,

    XML_ERR_INVALID_HEX_CHARREF, /* 6 */
    XML_ERR_INVALID_DEC_CHARREF,
    XML_ERR_INVALID_CHARREF,
    XML_ERR_INVALID_CHAR,

    XML_ERR_CHARREF_AT_EOF, /* 10 */
    XML_ERR_CHARREF_IN_PROLOG,
    XML_ERR_CHARREF_IN_EPILOG,
    XML_ERR_CHARREF_IN_DTD,
    XML_ERR_ENTITYREF_AT_EOF,
    XML_ERR_ENTITYREF_IN_PROLOG,
    XML_ERR_ENTITYREF_IN_EPILOG,
    XML_ERR_ENTITYREF_IN_DTD,
    XML_ERR_PEREF_AT_EOF,
    XML_ERR_PEREF_IN_PROLOG,
    XML_ERR_PEREF_IN_EPILOG,
    XML_ERR_PEREF_IN_INT_SUBSET,

    XML_ERR_ENTITYREF_NO_NAME, /* 22 */
    XML_ERR_ENTITYREF_SEMICOL_MISSING,

    XML_ERR_PEREF_NO_NAME, /* 24 */
    XML_ERR_PEREF_SEMICOL_MISSING,

    XML_ERR_UNDECLARED_ENTITY, /* 26 */
    XML_WAR_UNDECLARED_ENTITY,
    XML_ERR_UNPARSED_ENTITY,
    XML_ERR_ENTITY_IS_EXTERNAL,
    XML_ERR_ENTITY_IS_PARAMETER,

    XML_ERR_UNKNOWN_ENCODING, /* 31 */
    XML_ERR_UNSUPPORTED_ENCODING,

    XML_ERR_STRING_NOT_STARTED, /* 33 */
    XML_ERR_STRING_NOT_CLOSED,
    XML_ERR_NS_DECL_ERROR,

    XML_ERR_ENTITY_NOT_STARTED, /* 36 */
    XML_ERR_ENTITY_NOT_FINISHED,
    
    XML_ERR_LT_IN_ATTRIBUTE, /* 38 */
    XML_ERR_ATTRIBUTE_NOT_STARTED,
    XML_ERR_ATTRIBUTE_NOT_FINISHED,
    XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
    XML_ERR_ATTRIBUTE_REDEFINED,

    XML_ERR_LITERAL_NOT_STARTED, /* 43 */
    XML_ERR_LITERAL_NOT_FINISHED,
    
    XML_ERR_COMMENT_NOT_FINISHED, /* 45 */

    XML_ERR_PI_NOT_STARTED, /* 46 */
    XML_ERR_PI_NOT_FINISHED,

    XML_ERR_NOTATION_NOT_STARTED, /* 48 */
    XML_ERR_NOTATION_NOT_FINISHED,

    XML_ERR_ATTLIST_NOT_STARTED, /* 50 */
    XML_ERR_ATTLIST_NOT_FINISHED,

    XML_ERR_MIXED_NOT_STARTED, /* 52 */
    XML_ERR_MIXED_NOT_FINISHED,

    XML_ERR_ELEMCONTENT_NOT_STARTED, /* 54 */
    XML_ERR_ELEMCONTENT_NOT_FINISHED,

    XML_ERR_XMLDECL_NOT_STARTED, /* 56 */
    XML_ERR_XMLDECL_NOT_FINISHED,

    XML_ERR_CONDSEC_NOT_STARTED, /* 58 */
    XML_ERR_CONDSEC_NOT_FINISHED,

    XML_ERR_EXT_SUBSET_NOT_FINISHED, /* 60 */

    XML_ERR_DOCTYPE_NOT_FINISHED, /* 61 */

    XML_ERR_MISPLACED_CDATA_END, /* 62 */
    XML_ERR_CDATA_NOT_FINISHED,

    XML_ERR_RESERVED_XML_NAME, /* 64 */

    XML_ERR_SPACE_REQUIRED, /* 65 */
    XML_ERR_SEPARATOR_REQUIRED,
    XML_ERR_NMTOKEN_REQUIRED,
    XML_ERR_NAME_REQUIRED,
    XML_ERR_PCDATA_REQUIRED,
    XML_ERR_URI_REQUIRED,
    XML_ERR_PUBID_REQUIRED,
    XML_ERR_LT_REQUIRED,
    XML_ERR_GT_REQUIRED,
    XML_ERR_LTSLASH_REQUIRED,
    XML_ERR_EQUAL_REQUIRED,

    XML_ERR_TAG_NAME_MISMATCH, /* 76 */
    XML_ERR_TAG_NOT_FINISHED,

    XML_ERR_STANDALONE_VALUE, /* 78 */

    XML_ERR_ENCODING_NAME, /* 79 */

    XML_ERR_HYPHEN_IN_COMMENT, /* 80 */

    XML_ERR_INVALID_ENCODING, /* 81 */

    XML_ERR_EXT_ENTITY_STANDALONE, /* 82 */

    XML_ERR_CONDSEC_INVALID, /* 83 */

    XML_ERR_VALUE_REQUIRED, /* 84 */

    XML_ERR_NOT_WELL_BALANCED, /* 85 */
    XML_ERR_EXTRA_CONTENT, /* 86 */
    XML_ERR_ENTITY_CHAR_ERROR, /* 87 */
    XML_ERR_ENTITY_PE_INTERNAL, /* 88 */
    XML_ERR_ENTITY_LOOP, /* 89 */
    XML_ERR_ENTITY_BOUNDARY, /* 90 */
    XML_ERR_INVALID_URI, /* 91 */
    XML_ERR_URI_FRAGMENT, /* 92 */
    XML_WAR_CATALOG_PI, /* 93 */
    XML_ERR_NO_DTD,  /* 94 */
    XML_NS_ERR_XML_NAMESPACE,
    XML_NS_ERR_UNDEFINED_NAMESPACE,
    XML_NS_ERR_QNAME,
    XML_NS_ERR_ATTRIBUTE_REDEFINED,
    XML_ERR_CONDSEC_INVALID_KEYWORD,
    XML_ERR_VERSION_MISSING,
    XML_DTD_ATTRIBUTE_DEFAULT,
    XML_DTD_ATTRIBUTE_REDEFINED,
    XML_DTD_ATTRIBUTE_VALUE,
    XML_DTD_CONTENT_ERROR,
    XML_DTD_CONTENT_MODEL,
    XML_DTD_CONTENT_NOT_DETERMINIST,
    XML_DTD_DIFFERENT_PREFIX,
    XML_DTD_ELEM_DEFAULT_NAMESPACE,
    XML_DTD_ELEM_NAMESPACE,
    XML_DTD_ELEM_REDEFINED,
    XML_DTD_EMPTY_NOTATION,
    XML_DTD_ENTITY_TYPE,
    XML_DTD_ID_FIXED,
    XML_DTD_ID_REDEFINED,
    XML_DTD_ID_SUBSET,
    XML_DTD_INVALID_CHILD,
    XML_DTD_INVALID_DEFAULT,
    XML_DTD_LOAD_ERROR,
    XML_DTD_MISSING_ATTRIBUTE,
    XML_DTD_MIXED_CORRUPT,
    XML_DTD_MULTIPLE_ID,
    XML_DTD_NO_DOC,
    XML_DTD_NO_DTD,
    XML_DTD_NO_ELEM_NAME,
    XML_DTD_NO_PREFIX,
    XML_DTD_NO_ROOT,
    XML_DTD_NOTATION_REDEFINED,
    XML_DTD_NOTATION_VALUE,
    XML_DTD_NOT_EMPTY,
    XML_DTD_NOT_PCDATA,
    XML_DTD_NOT_STANDALONE,
    XML_DTD_ROOT_NAME,
    XML_DTD_STANDALONE_WHITE_SPACE,
    XML_DTD_UNKNOWN_ATTRIBUTE,
    XML_DTD_UNKNOWN_ELEM,
    XML_DTD_UNKNOWN_ENTITY,
    XML_DTD_UNKNOWN_ID,
    XML_DTD_UNKNOWN_NOTATION,
    XML_WAR_UNKNOWN_VERSION,
    XML_WAR_LANG_VALUE,
    XML_WAR_NS_URI,
    XML_WAR_NS_URI_RELATIVE,
    XML_HTML_STRUCURE_ERROR,
    XML_HTML_UNKNOWN_TAG
} xmlParserErrors;

/**
 * xmlGenericErrorFunc:
 * @ctx:  a parsing context
 * @msg:  the message
 * @...:  the extra arguments of the varags to format the message
 *
 * Signature of the function to use when there is an error and
 * no parsing or validity context available .
 */
typedef void (*xmlGenericErrorFunc) (void *ctx,
				 const char *msg,
				 ...);

/*
 * Use the following function to reset the two global variables
 * xmlGenericError and xmlGenericErrorContext.
 */
XMLPUBFUN void XMLCALL	
    xmlSetGenericErrorFunc	(void *ctx,
				 xmlGenericErrorFunc handler);
XMLPUBFUN void XMLCALL	
    initGenericErrorDefaultFunc	(xmlGenericErrorFunc *handler);

/*
 * Default message routines used by SAX and Valid context for error
 * and warning reporting.
 */
XMLPUBFUN void XMLCALL	
    xmlParserError		(void *ctx,
				 const char *msg,
				 ...);
XMLPUBFUN void XMLCALL	
    xmlParserWarning		(void *ctx,
				 const char *msg,
				 ...);
XMLPUBFUN void XMLCALL	
    xmlParserValidityError	(void *ctx,
				 const char *msg,
				 ...);
XMLPUBFUN void XMLCALL	
    xmlParserValidityWarning	(void *ctx,
				 const char *msg,
				 ...);
XMLPUBFUN void XMLCALL	
    xmlParserPrintFileInfo	(xmlParserInputPtr input);
XMLPUBFUN void XMLCALL	
    xmlParserPrintFileContext	(xmlParserInputPtr input);

/*
 * Extended error information routines
 */
XMLPUBFUN xmlErrorPtr XMLCALL
    xmlGetLastError		(void);
XMLPUBFUN void XMLCALL
    xmlResetLastError		(void);
XMLPUBFUN xmlErrorPtr XMLCALL
    xmlCtxtGetLastError		(void *ctx);
XMLPUBFUN void XMLCALL
    xmlCtxtResetLastError	(void *ctx);
XMLPUBFUN void XMLCALL
    xmlResetError		(xmlErrorPtr err);
XMLPUBFUN int XMLCALL
    xmlCopyError		(xmlErrorPtr from,
    				 xmlErrorPtr to);

#ifdef IN_LIBXML
/*
 * Internal callback reporting routine
 */
XMLPUBFUN void XMLCALL 
    __xmlRaiseError		(xmlGenericErrorFunc channel,
    				 void *data,
                                 void *ctx,
    				 void *node,
    				 int domain,
				 int code,
				 xmlErrorLevel level,
				 const char *file,
				 int line,
				 const char *str1,
				 const char *str2,
				 const char *str3,
				 int int1,
				 int int2,
				 const char *msg,
				 ...);
#endif
#ifdef __cplusplus
}
#endif
#endif /* __XML_ERROR_H__ */
