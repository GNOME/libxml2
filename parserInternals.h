/*
 * parserInternals.h : internals routines exported by the parser.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_PARSER_INTERNALS_H__
#define __XML_PARSER_INTERNALS_H__

#include "parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parser context
 */
xmlParserCtxtPtr
xmlCreateDocParserCtxt(CHAR *cur);
xmlParserCtxtPtr
xmlCreateFileParserCtxt(const char *filename);
xmlParserCtxtPtr
xmlCreateMemoryParserCtxt(char *buffer, int size);
void
xmlFreeParserCtxt(xmlParserCtxtPtr ctxt);

/*
 * Entities
 */
void
xmlHandleEntity(xmlParserCtxtPtr ctxt, xmlEntityPtr entity);

/*
 * Namespaces.
 */
CHAR *
xmlNamespaceParseNCName(xmlParserCtxtPtr ctxt);
CHAR *
xmlNamespaceParseQName(xmlParserCtxtPtr ctxt, CHAR **prefix);
CHAR *
xmlNamespaceParseNSDef(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseQuotedString(xmlParserCtxtPtr ctxt);
void
xmlParseNamespace(xmlParserCtxtPtr ctxt);

/*
 * Generic production rules
 */
CHAR *
xmlParseName(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseNmtoken(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseEntityValue(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseAttValue(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseSystemLiteral(xmlParserCtxtPtr ctxt);
CHAR *
xmlParsePubidLiteral(xmlParserCtxtPtr ctxt);
void
xmlParseCharData(xmlParserCtxtPtr ctxt, int cdata);
CHAR *
xmlParseExternalID(xmlParserCtxtPtr ctxt, CHAR **publicID, int strict);
xmlNodePtr 
xmlParseComment(xmlParserCtxtPtr ctxt, int create);
CHAR *
xmlParsePITarget(xmlParserCtxtPtr ctxt);
void
xmlParsePI(xmlParserCtxtPtr ctxt);
void
xmlParseNotationDecl(xmlParserCtxtPtr ctxt);
void
xmlParseEntityDecl(xmlParserCtxtPtr ctxt);
int
xmlParseDefaultDecl(xmlParserCtxtPtr ctxt, CHAR **value);
xmlEnumerationPtr
xmlParseNotationType(xmlParserCtxtPtr ctxt);
xmlEnumerationPtr
xmlParseEnumerationType(xmlParserCtxtPtr ctxt);
int
xmlParseEnumeratedType(xmlParserCtxtPtr ctxt, xmlEnumerationPtr *tree);
int
xmlParseAttributeType(xmlParserCtxtPtr ctxt, xmlEnumerationPtr *tree);
void
xmlParseAttributeListDecl(xmlParserCtxtPtr ctxt);
xmlElementContentPtr
xmlParseElementMixedContentDecl(xmlParserCtxtPtr ctxt);
xmlElementContentPtr
xmlParseElementChildrenContentDecl(xmlParserCtxtPtr ctxt);
int
xmlParseElementContentDecl(xmlParserCtxtPtr ctxt, CHAR *name,
                           xmlElementContentPtr *result);
int
xmlParseElementDecl(xmlParserCtxtPtr ctxt);
void
xmlParseMarkupDecl(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseCharRef(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseEntityRef(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseReference(xmlParserCtxtPtr ctxt);
CHAR *
xmlParsePEReference(xmlParserCtxtPtr ctxt);
void
xmlParseDocTypeDecl(xmlParserCtxtPtr ctxt);
xmlAttrPtr 
xmlParseAttribute(xmlParserCtxtPtr ctxt, xmlNodePtr node);
xmlNodePtr 
xmlParseStartTag(xmlParserCtxtPtr ctxt);
void
xmlParseEndTag(xmlParserCtxtPtr ctxt, xmlNsPtr *nsPtr, CHAR **tagPtr);
void
xmlParseCDSect(xmlParserCtxtPtr ctxt);
void
xmlParseContent(xmlParserCtxtPtr ctxt);
xmlNodePtr 
xmlParseElement(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseVersionNum(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseVersionInfo(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseEncName(xmlParserCtxtPtr ctxt);
CHAR *
xmlParseEncodingDecl(xmlParserCtxtPtr ctxt);
int
xmlParseSDDecl(xmlParserCtxtPtr ctxt);
void
xmlParseXMLDecl(xmlParserCtxtPtr ctxt);
void
xmlParseMisc(xmlParserCtxtPtr ctxt);


#endif /* __XML_PARSER_INTERNALS_H__ */
