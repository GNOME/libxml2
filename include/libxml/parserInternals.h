/*
 * Summary: internals routines and limits exported by the parser.
 * Description: this module exports a number of internal parsing routines
 *              they are not really all intended for applications but
 *              can prove useful doing low level processing.
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Daniel Veillard
 */

#ifndef __XML_PARSER_INTERNALS_H__
#define __XML_PARSER_INTERNALS_H__

#include <libxml/xmlversion.h>
#include <libxml/parser.h>
#include <libxml/HTMLparser.h>
#include <libxml/chvalid.h>
#include <libxml/SAX2.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xmlParserMaxDepth:
 *
 * DEPRECATED: has no effect
 *
 * arbitrary depth limit for the XML documents that we allow to
 * process. This is not a limitation of the parser but a safety
 * boundary feature, use XML_PARSE_HUGE option to override it.
 */
XML_DEPRECATED
XMLPUBVAR const unsigned int xmlParserMaxDepth;

/**
 * XML_MAX_TEXT_LENGTH:
 *
 * Maximum size allowed for a single text node when building a tree.
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Introduced in 2.9.0
 */
#define XML_MAX_TEXT_LENGTH 10000000

/**
 * XML_MAX_HUGE_LENGTH:
 *
 * Maximum size allowed when XML_PARSE_HUGE is set.
 */
#define XML_MAX_HUGE_LENGTH 1000000000

/**
 * XML_MAX_NAME_LENGTH:
 *
 * Maximum size allowed for a markup identifier.
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Note that with the use of parsing dictionaries overriding the limit
 * may result in more runtime memory usage in face of "unfriendly' content
 * Introduced in 2.9.0
 */
#define XML_MAX_NAME_LENGTH 50000

/**
 * XML_MAX_DICTIONARY_LIMIT:
 *
 * Maximum size allowed by the parser for a dictionary by default
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Introduced in 2.9.0
 */
#define XML_MAX_DICTIONARY_LIMIT 100000000

/**
 * XML_MAX_LOOKUP_LIMIT:
 *
 * Maximum size allowed by the parser for ahead lookup
 * This is an upper boundary enforced by the parser to avoid bad
 * behaviour on "unfriendly' content
 * Introduced in 2.9.0
 */
#define XML_MAX_LOOKUP_LIMIT 10000000

/**
 * XML_MAX_NAMELEN:
 *
 * Identifiers can be longer, but this will be more costly
 * at runtime.
 */
#define XML_MAX_NAMELEN 100

/**
 * IS_BLANK:
 * @c:  an UNICODE value (int)
 *
 * Macro to check the following production in the XML spec:
 *
 * [3] S ::= (#x20 | #x9 | #xD | #xA)+
 */
#define IS_BLANK(c)  xmlIsBlankQ(c)

/**
 * IS_BLANK_CH:
 * @c:  an xmlChar value (normally unsigned char)
 *
 * Behaviour same as IS_BLANK
 */
#define IS_BLANK_CH(c)  xmlIsBlank_ch(c)

/**
 * Global variables used for predefined strings.
 */
XMLPUBVAR const xmlChar xmlStringText[];
XMLPUBVAR const xmlChar xmlStringTextNoenc[];
XML_DEPRECATED
XMLPUBVAR const xmlChar xmlStringComment[];

XML_DEPRECATED
XMLPUBFUN int                   xmlIsLetter     (int c);

/**
 * Parser context.
 */
XMLPUBFUN xmlParserCtxtPtr
			xmlCreateFileParserCtxt	(const char *filename);
XMLPUBFUN xmlParserCtxtPtr
			xmlCreateURLParserCtxt	(const char *filename,
						 int options);
XMLPUBFUN xmlParserCtxtPtr
			xmlCreateMemoryParserCtxt(const char *buffer,
						 int size);
XML_DEPRECATED
XMLPUBFUN xmlParserCtxtPtr
			xmlCreateEntityParserCtxt(const xmlChar *URL,
						 const xmlChar *ID,
						 const xmlChar *base);
XMLPUBFUN void
			xmlCtxtErrMemory	(xmlParserCtxtPtr ctxt);
XMLPUBFUN int
			xmlSwitchEncoding	(xmlParserCtxtPtr ctxt,
						 xmlCharEncoding enc);
XMLPUBFUN int
			xmlSwitchEncodingName	(xmlParserCtxtPtr ctxt,
						 const char *encoding);
XMLPUBFUN int
			xmlSwitchToEncoding	(xmlParserCtxtPtr ctxt,
					 xmlCharEncodingHandlerPtr handler);
XML_DEPRECATED
XMLPUBFUN int
			xmlSwitchInputEncoding	(xmlParserCtxtPtr ctxt,
						 xmlParserInputPtr input,
					 xmlCharEncodingHandlerPtr handler);

/**
 * Input Streams.
 */
XMLPUBFUN xmlParserInputPtr
			xmlNewStringInputStream	(xmlParserCtxtPtr ctxt,
						 const xmlChar *buffer);
XML_DEPRECATED
XMLPUBFUN xmlParserInputPtr
			xmlNewEntityInputStream	(xmlParserCtxtPtr ctxt,
						 xmlEntityPtr entity);
XMLPUBFUN int
			xmlCtxtPushInput	(xmlParserCtxtPtr ctxt,
						 xmlParserInputPtr input);
XMLPUBFUN xmlParserInputPtr
			xmlCtxtPopInput		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int
			xmlPushInput		(xmlParserCtxtPtr ctxt,
						 xmlParserInputPtr input);
XML_DEPRECATED
XMLPUBFUN xmlChar
			xmlPopInput		(xmlParserCtxtPtr ctxt);
XMLPUBFUN void
			xmlFreeInputStream	(xmlParserInputPtr input);
XMLPUBFUN xmlParserInputPtr
			xmlNewInputFromFile	(xmlParserCtxtPtr ctxt,
						 const char *filename);
XMLPUBFUN xmlParserInputPtr
			xmlNewInputStream	(xmlParserCtxtPtr ctxt);

/**
 * Namespaces.
 */
XMLPUBFUN xmlChar *
			xmlSplitQName		(xmlParserCtxtPtr ctxt,
						 const xmlChar *name,
						 xmlChar **prefix);

/**
 * Generic production rules.
 */
XML_DEPRECATED
XMLPUBFUN const xmlChar *
			xmlParseName		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseNmtoken		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseEntityValue	(xmlParserCtxtPtr ctxt,
						 xmlChar **orig);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseAttValue	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseSystemLiteral	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParsePubidLiteral	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseCharData	(xmlParserCtxtPtr ctxt,
						 int cdata);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseExternalID	(xmlParserCtxtPtr ctxt,
						 xmlChar **publicID,
						 int strict);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseComment		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN const xmlChar *
			xmlParsePITarget	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParsePI		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseNotationDecl	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseEntityDecl	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int
			xmlParseDefaultDecl	(xmlParserCtxtPtr ctxt,
						 xmlChar **value);
XML_DEPRECATED
XMLPUBFUN xmlEnumerationPtr
			xmlParseNotationType	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlEnumerationPtr
			xmlParseEnumerationType	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int
			xmlParseEnumeratedType	(xmlParserCtxtPtr ctxt,
						 xmlEnumerationPtr *tree);
XML_DEPRECATED
XMLPUBFUN int
			xmlParseAttributeType	(xmlParserCtxtPtr ctxt,
						 xmlEnumerationPtr *tree);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseAttributeListDecl(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlElementContentPtr
			xmlParseElementMixedContentDecl
						(xmlParserCtxtPtr ctxt,
						 int inputchk);
XML_DEPRECATED
XMLPUBFUN xmlElementContentPtr
			xmlParseElementChildrenContentDecl
						(xmlParserCtxtPtr ctxt,
						 int inputchk);
XML_DEPRECATED
XMLPUBFUN int
			xmlParseElementContentDecl(xmlParserCtxtPtr ctxt,
						 const xmlChar *name,
						 xmlElementContentPtr *result);
XML_DEPRECATED
XMLPUBFUN int
			xmlParseElementDecl	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseMarkupDecl	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int
			xmlParseCharRef		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlEntityPtr
			xmlParseEntityRef	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseReference	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParsePEReference	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseDocTypeDecl	(xmlParserCtxtPtr ctxt);
#ifdef LIBXML_SAX1_ENABLED
XML_DEPRECATED
XMLPUBFUN const xmlChar *
			xmlParseAttribute	(xmlParserCtxtPtr ctxt,
						 xmlChar **value);
XML_DEPRECATED
XMLPUBFUN const xmlChar *
			xmlParseStartTag	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseEndTag		(xmlParserCtxtPtr ctxt);
#endif /* LIBXML_SAX1_ENABLED */
XML_DEPRECATED
XMLPUBFUN void
			xmlParseCDSect		(xmlParserCtxtPtr ctxt);
XMLPUBFUN void
			xmlParseContent		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseElement		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseVersionNum	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseVersionInfo	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN xmlChar *
			xmlParseEncName		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN const xmlChar *
			xmlParseEncodingDecl	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int
			xmlParseSDDecl		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseXMLDecl		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseTextDecl	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseMisc		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
			xmlParseExternalSubset	(xmlParserCtxtPtr ctxt,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID);
/**
 * XML_SUBSTITUTE_NONE:
 *
 * If no entities need to be substituted.
 */
#define XML_SUBSTITUTE_NONE	0
/**
 * XML_SUBSTITUTE_REF:
 *
 * Whether general entities need to be substituted.
 */
#define XML_SUBSTITUTE_REF	1
/**
 * XML_SUBSTITUTE_PEREF:
 *
 * Whether parameter entities need to be substituted.
 */
#define XML_SUBSTITUTE_PEREF	2
/**
 * XML_SUBSTITUTE_BOTH:
 *
 * Both general and parameter entities need to be substituted.
 */
#define XML_SUBSTITUTE_BOTH	3

XML_DEPRECATED
XMLPUBFUN xmlChar *
		xmlStringDecodeEntities		(xmlParserCtxtPtr ctxt,
						 const xmlChar *str,
						 int what,
						 xmlChar end,
						 xmlChar  end2,
						 xmlChar end3);
XML_DEPRECATED
XMLPUBFUN xmlChar *
		xmlStringLenDecodeEntities	(xmlParserCtxtPtr ctxt,
						 const xmlChar *str,
						 int len,
						 int what,
						 xmlChar end,
						 xmlChar  end2,
						 xmlChar end3);

/*
 * Generated by MACROS on top of parser.c c.f. PUSH_AND_POP.
 */
XML_DEPRECATED
XMLPUBFUN int			nodePush		(xmlParserCtxtPtr ctxt,
						 xmlNodePtr value);
XML_DEPRECATED
XMLPUBFUN xmlNodePtr		nodePop			(xmlParserCtxtPtr ctxt);
XMLPUBFUN int			inputPush		(xmlParserCtxtPtr ctxt,
						 xmlParserInputPtr value);
XMLPUBFUN xmlParserInputPtr	inputPop		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN const xmlChar *	namePop			(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int			namePush		(xmlParserCtxtPtr ctxt,
						 const xmlChar *value);

/*
 * other commodities shared between parser.c and parserInternals.
 */
XML_DEPRECATED
XMLPUBFUN int			xmlSkipBlankChars	(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int			xmlStringCurrentChar	(xmlParserCtxtPtr ctxt,
						 const xmlChar *cur,
						 int *len);
XML_DEPRECATED
XMLPUBFUN void			xmlParserHandlePEReference(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN int			xmlCheckLanguageID	(const xmlChar *lang);

/*
 * Really core function shared with HTML parser.
 */
XML_DEPRECATED
XMLPUBFUN int			xmlCurrentChar		(xmlParserCtxtPtr ctxt,
						 int *len);
XML_DEPRECATED
XMLPUBFUN int		xmlCopyCharMultiByte	(xmlChar *out,
						 int val);
XML_DEPRECATED
XMLPUBFUN int			xmlCopyChar		(int len,
						 xmlChar *out,
						 int val);
XML_DEPRECATED
XMLPUBFUN void			xmlNextChar		(xmlParserCtxtPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void			xmlParserInputShrink	(xmlParserInputPtr in);

#ifdef __cplusplus
}
#endif
#endif /* __XML_PARSER_INTERNALS_H__ */
