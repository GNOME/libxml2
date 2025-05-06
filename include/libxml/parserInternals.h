/**
 * @file
 * 
 * @brief Internals routines and limits exported by the parser.
 * 
 * Except for some I/O-related functions, most of these macros and
 * functions are deprecated.
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
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

/*
 * Backward compatibility
 */
#define inputPush xmlCtxtPushInput
#define inputPop xmlCtxtPopInput
#define xmlParserMaxDepth 256

/**
 * Maximum size allowed for a single text node when building a tree.
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Introduced in 2.9.0
 */
#define XML_MAX_TEXT_LENGTH 10000000

/**
 * Maximum size allowed when XML_PARSE_HUGE is set.
 */
#define XML_MAX_HUGE_LENGTH 1000000000

/**
 * Maximum size allowed for a markup identifier.
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Note that with the use of parsing dictionaries overriding the limit
 * may result in more runtime memory usage in face of "unfriendly' content
 * Introduced in 2.9.0
 */
#define XML_MAX_NAME_LENGTH 50000

/**
 * Maximum size allowed by the parser for a dictionary by default
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Introduced in 2.9.0
 */
#define XML_MAX_DICTIONARY_LIMIT 100000000

/**
 * Maximum size allowed by the parser for ahead lookup
 * This is an upper boundary enforced by the parser to avoid bad
 * behaviour on "unfriendly' content
 * Introduced in 2.9.0
 */
#define XML_MAX_LOOKUP_LIMIT 10000000

/**
 * Identifiers can be longer, but this will be more costly
 * at runtime.
 */
#define XML_MAX_NAMELEN 100

/************************************************************************
 *									*
 * UNICODE version of the macros.					*
 *									*
 ************************************************************************/
/**
 * Macro to check the following production in the XML spec:
 *
 *     [2] Char ::= #x9 | #xA | #xD | [#x20...]
 *
 * any byte character in the accepted range
 * @param c  an byte value (int)
 */
#define IS_BYTE_CHAR(c)	 xmlIsChar_ch(c)

/**
 * Macro to check the following production in the XML spec:
 *
 *     [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
 *                      | [#x10000-#x10FFFF]
 *
 * any Unicode character, excluding the surrogate blocks, FFFE, and FFFF.
 * @param c  an UNICODE value (int)
 */
#define IS_CHAR(c)   xmlIsCharQ(c)

/**
 * Behaves like IS_CHAR on single-byte value
 *
 * @param c  an xmlChar (usually an unsigned char)
 */
#define IS_CHAR_CH(c)  xmlIsChar_ch(c)

/**
 * Macro to check the following production in the XML spec:
 *
 *     [3] S ::= (#x20 | #x9 | #xD | #xA)+
 * @param c  an UNICODE value (int)
 */
#define IS_BLANK(c)  xmlIsBlankQ(c)

/**
 * Behaviour same as IS_BLANK
 *
 * @param c  an xmlChar value (normally unsigned char)
 */
#define IS_BLANK_CH(c)  xmlIsBlank_ch(c)

/**
 * Macro to check the following production in the XML spec:
 *
 *     [85] BaseChar ::= ... long list see REC ...
 * @param c  an UNICODE value (int)
 */
#define IS_BASECHAR(c) xmlIsBaseCharQ(c)

/**
 * Macro to check the following production in the XML spec:
 *
 *     [88] Digit ::= ... long list see REC ...
 * @param c  an UNICODE value (int)
 */
#define IS_DIGIT(c) xmlIsDigitQ(c)

/**
 * Behaves like IS_DIGIT but with a single byte argument
 *
 * @param c  an xmlChar value (usually an unsigned char)
 */
#define IS_DIGIT_CH(c)  xmlIsDigit_ch(c)

/**
 * Macro to check the following production in the XML spec:
 *
 *     [87] CombiningChar ::= ... long list see REC ...
 * @param c  an UNICODE value (int)
 */
#define IS_COMBINING(c) xmlIsCombiningQ(c)

/**
 * Always false (all combining chars > 0xff)
 *
 * @param c  an xmlChar (usually an unsigned char)
 */
#define IS_COMBINING_CH(c) 0

/**
 * Macro to check the following production in the XML spec:
 *
 *     [89] Extender ::= #x00B7 | #x02D0 | #x02D1 | #x0387 | #x0640 |
 *                       #x0E46 | #x0EC6 | #x3005 | [#x3031-#x3035] |
 *                       [#x309D-#x309E] | [#x30FC-#x30FE]
 * @param c  an UNICODE value (int)
 */
#define IS_EXTENDER(c) xmlIsExtenderQ(c)

/**
 * Behaves like IS_EXTENDER but with a single-byte argument
 *
 * @param c  an xmlChar value (usually an unsigned char)
 */
#define IS_EXTENDER_CH(c)  xmlIsExtender_ch(c)

/**
 * Macro to check the following production in the XML spec:
 *
 *     [86] Ideographic ::= [#x4E00-#x9FA5] | #x3007 | [#x3021-#x3029]
 * @param c  an UNICODE value (int)
 */
#define IS_IDEOGRAPHIC(c) xmlIsIdeographicQ(c)

/**
 * Macro to check the following production in the XML spec:
 *
 *     [84] Letter ::= BaseChar | Ideographic
 * @param c  an UNICODE value (int)
 */
#define IS_LETTER(c) (IS_BASECHAR(c) || IS_IDEOGRAPHIC(c))

/**
 * Macro behaves like IS_LETTER, but only check base chars
 *
 * @param c  an xmlChar value (normally unsigned char)
 */
#define IS_LETTER_CH(c) xmlIsBaseChar_ch(c)

/**
 * Macro to check [a-zA-Z]
 *
 * @param c  an xmlChar value
 */
#define IS_ASCII_LETTER(c)	((0x61 <= ((c) | 0x20)) && \
                                 (((c) | 0x20) <= 0x7a))

/**
 * Macro to check [0-9]
 *
 * @param c  an xmlChar value
 */
#define IS_ASCII_DIGIT(c)	((0x30 <= (c)) && ((c) <= 0x39))

/**
 * Macro to check the following production in the XML spec:
 *
 *     [13] PubidChar ::= #x20 | #xD | #xA | [a-zA-Z0-9] |
 *                        [-'()+,./:=?;!*#@$_%]
 * @param c  an UNICODE value (int)
 */
#define IS_PUBIDCHAR(c)	xmlIsPubidCharQ(c)

/**
 * Same as IS_PUBIDCHAR but for single-byte value
 *
 * @param c  an xmlChar value (normally unsigned char)
 */
#define IS_PUBIDCHAR_CH(c) xmlIsPubidChar_ch(c)

/*
 * Global variables used for predefined strings.
 */
XMLPUBVAR const xmlChar xmlStringText[];
XMLPUBVAR const xmlChar xmlStringTextNoenc[];
XML_DEPRECATED
XMLPUBVAR const xmlChar xmlStringComment[];

XML_DEPRECATED
XMLPUBFUN int                   xmlIsLetter     (int c);

/*
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

/*
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

/*
 * Namespaces.
 */
XMLPUBFUN xmlChar *
			xmlSplitQName		(xmlParserCtxtPtr ctxt,
						 const xmlChar *name,
						 xmlChar **prefix);

/*
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

#define XML_SUBSTITUTE_NONE	0
#define XML_SUBSTITUTE_REF	1
#define XML_SUBSTITUTE_PEREF	2
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
