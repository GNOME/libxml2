/*
 * SAX.h : Default SAX2 handler interfaces to build a tree.
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <daniel@veillard.com>
 */


#ifndef __XML_SAX2_H__
#define __XML_SAX2_H__

#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/xlink.h>

#ifdef __cplusplus
extern "C" {
#endif
const xmlChar *	xmlSAX2GetPublicId		(void *ctx);
const xmlChar *	xmlSAX2GetSystemId		(void *ctx);
void		xmlSAX2SetDocumentLocator	(void *ctx,
						 xmlSAXLocatorPtr loc);
    
int		xmlSAX2GetLineNumber		(void *ctx);
int		xmlSAX2GetColumnNumber		(void *ctx);

int		xmlSAX2IsStandalone		(void *ctx);
int		xmlSAX2HasInternalSubset	(void *ctx);
int		xmlSAX2HasExternalSubset	(void *ctx);

void		xmlSAX2InternalSubset		(void *ctx,
						 const xmlChar *name,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID);
void		xmlSAX2ExternalSubset		(void *ctx,
						 const xmlChar *name,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID);
xmlEntityPtr	xmlSAX2GetEntity		(void *ctx,
						 const xmlChar *name);
xmlEntityPtr	xmlSAX2GetParameterEntity	(void *ctx,
						 const xmlChar *name);
xmlParserInputPtr xmlSAX2ResolveEntity		(void *ctx,
						 const xmlChar *publicId,
						 const xmlChar *systemId);

void		xmlSAX2EntityDecl		(void *ctx,
						 const xmlChar *name,
						 int type,
						 const xmlChar *publicId,
						 const xmlChar *systemId,
						 xmlChar *content);
void		xmlSAX2AttributeDecl		(void *ctx,
						 const xmlChar *elem,
						 const xmlChar *fullname,
						 int type,
						 int def,
						 const xmlChar *defaultValue,
						 xmlEnumerationPtr tree);
void		xmlSAX2ElementDecl		(void *ctx,
						 const xmlChar *name,
						 int type,
						 xmlElementContentPtr content);
void		xmlSAX2NotationDecl		(void *ctx,
						 const xmlChar *name,
						 const xmlChar *publicId,
						 const xmlChar *systemId);
void		xmlSAX2UnparsedEntityDecl	(void *ctx,
						 const xmlChar *name,
						 const xmlChar *publicId,
						 const xmlChar *systemId,
						 const xmlChar *notationName);

void		xmlSAX2StartDocument		(void *ctx);
void		xmlSAX2EndDocument		(void *ctx);
void		xmlSAX2StartElement		(void *ctx,
						 const xmlChar *fullname,
						 const xmlChar **atts);
void		xmlSAX2EndElement		(void *ctx,
						 const xmlChar *name);
void		xmlSAX2Reference		(void *ctx,
						 const xmlChar *name);
void		xmlSAX2Characters		(void *ctx,
						 const xmlChar *ch,
						 int len);
void		xmlSAX2IgnorableWhitespace	(void *ctx,
						 const xmlChar *ch,
						 int len);
void		xmlSAX2ProcessingInstruction	(void *ctx,
						 const xmlChar *target,
						 const xmlChar *data);
void		xmlSAX2GlobalNamespace		(void *ctx,
						 const xmlChar *href,
						 const xmlChar *prefix);
void		xmlSAX2SetNamespace		(void *ctx,
						 const xmlChar *name);
xmlNsPtr	xmlSAX2GetNamespace		(void *ctx);
int		xmlSAX2CheckNamespace		(void *ctx,
						 xmlChar *nameSpace);
void		xmlSAX2NamespaceDecl		(void *ctx,
						 const xmlChar *href,
						 const xmlChar *prefix);
void		xmlSAX2Comment			(void *ctx,
						 const xmlChar *value);
void		xmlSAX2CDataBlock		(void *ctx,
						 const xmlChar *value,
						 int len);

void		xmlSAX2InitDefaultSAXHandler    (xmlSAXHandler *hdlr,
						 int warning);
#ifdef LIBXML_HTML_ENABLED
void		xmlSAX2InitHtmlDefaultSAXHandler(xmlSAXHandler *hdlr);
#endif
#ifdef LIBXML_DOCB_ENABLED
void		xmlSAX2InitDocbDefaultSAXHandler(xmlSAXHandler *hdlr);
#endif
void		xmlDefaultSAXHandlerInit	(void);
void		htmlDefaultSAXHandlerInit	(void);
void		docbDefaultSAXHandlerInit	(void);
#ifdef __cplusplus
}
#endif
#endif /* __XML_SAX2_H__ */
