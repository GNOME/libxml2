/*
 * SAX.c : Old SAX v1 handlers to build a tree.
 *         Deprecated except for compatibility
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <daniel@veillard.com>
 */


#define IN_LIBXML
#include "libxml.h"
#include <stdlib.h>
#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/valid.h>
#include <libxml/entities.h>
#include <libxml/xmlerror.h>
#include <libxml/debugXML.h>
#include <libxml/xmlIO.h>
#include <libxml/SAX.h>
#include <libxml/uri.h>
#include <libxml/valid.h>
#include <libxml/HTMLtree.h>
#include <libxml/globals.h>
#include <libxml/SAX2.h>

/* #define DEBUG_SAX */
/* #define DEBUG_SAX_TREE */

/**
 * getPublicId:
 * @ctx: the user data (XML parser context)
 *
 * Provides the public ID e.g. "-//SGMLSOURCE//DTD DEMO//EN"
 * DEPRECATED: use xmlSAX2GetPublicId()
 *
 * Returns a xmlChar *
 */
const xmlChar *
getPublicId(void *ctx)
{
    return(xmlSAX2GetPublicId(ctx));
}

/**
 * getSystemId:
 * @ctx: the user data (XML parser context)
 *
 * Provides the system ID, basically URL or filename e.g.
 * http://www.sgmlsource.com/dtds/memo.dtd
 * DEPRECATED: use xmlSAX2GetSystemId()
 *
 * Returns a xmlChar *
 */
const xmlChar *
getSystemId(void *ctx)
{
    return(xmlSAX2GetSystemId(ctx)); 
}

/**
 * getLineNumber:
 * @ctx: the user data (XML parser context)
 *
 * Provide the line number of the current parsing point.
 * DEPRECATED: use xmlSAX2GetLineNumber()
 *
 * Returns an int
 */
int
getLineNumber(void *ctx)
{
    return(xmlSAX2GetLineNumber(ctx));
}

/**
 * getColumnNumber:
 * @ctx: the user data (XML parser context)
 *
 * Provide the column number of the current parsing point.
 * DEPRECATED: use xmlSAX2GetColumnNumber()
 *
 * Returns an int
 */
int
getColumnNumber(void *ctx)
{
    return(xmlSAX2GetColumnNumber(ctx));
}

/**
 * isStandalone:
 * @ctx: the user data (XML parser context)
 *
 * Is this document tagged standalone ?
 * DEPRECATED: use xmlSAX2IsStandalone()
 *
 * Returns 1 if true
 */
int
isStandalone(void *ctx)
{
    return(xmlSAX2IsStandalone(ctx));
}

/**
 * hasInternalSubset:
 * @ctx: the user data (XML parser context)
 *
 * Does this document has an internal subset
 * DEPRECATED: use xmlSAX2HasInternalSubset()
 *
 * Returns 1 if true
 */
int
hasInternalSubset(void *ctx)
{
    return(xmlSAX2HasInternalSubset(ctx));
}

/**
 * hasExternalSubset:
 * @ctx: the user data (XML parser context)
 *
 * Does this document has an external subset
 * DEPRECATED: use xmlSAX2HasExternalSubset()
 *
 * Returns 1 if true
 */
int
hasExternalSubset(void *ctx)
{
    return(xmlSAX2HasExternalSubset(ctx));
}

/**
 * internalSubset:
 * @ctx:  the user data (XML parser context)
 * @name:  the root element name
 * @ExternalID:  the external ID
 * @SystemID:  the SYSTEM ID (e.g. filename or URL)
 *
 * Callback on internal subset declaration.
 * DEPRECATED: use xmlSAX2InternalSubset()
 */
void
internalSubset(void *ctx, const xmlChar *name,
	       const xmlChar *ExternalID, const xmlChar *SystemID)
{
    xmlSAX2InternalSubset(ctx, name, ExternalID, SystemID);
}

/**
 * externalSubset:
 * @ctx: the user data (XML parser context)
 * @name:  the root element name
 * @ExternalID:  the external ID
 * @SystemID:  the SYSTEM ID (e.g. filename or URL)
 *
 * Callback on external subset declaration.
 * DEPRECATED: use xmlSAX2ExternalSubset()
 */
void
externalSubset(void *ctx, const xmlChar *name,
	       const xmlChar *ExternalID, const xmlChar *SystemID)
{
    xmlSAX2ExternalSubset(ctx, name, ExternalID, SystemID);
}

/**
 * resolveEntity:
 * @ctx: the user data (XML parser context)
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * The entity loader, to control the loading of external entities,
 * the application can either:
 *    - override this resolveEntity() callback in the SAX block
 *    - or better use the xmlSetExternalEntityLoader() function to
 *      set up it's own entity resolution routine
 * DEPRECATED: use xmlSAX2ResolveEntity()
 *
 * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
 */
xmlParserInputPtr
resolveEntity(void *ctx, const xmlChar *publicId, const xmlChar *systemId)
{
    return(xmlSAX2ResolveEntity(ctx, publicId, systemId));
}

/**
 * getEntity:
 * @ctx: the user data (XML parser context)
 * @name: The entity name
 *
 * Get an entity by name
 * DEPRECATED: use xmlSAX2GetEntity()
 *
 * Returns the xmlEntityPtr if found.
 */
xmlEntityPtr
getEntity(void *ctx, const xmlChar *name)
{
    return(xmlSAX2GetEntity(ctx, name));
}

/**
 * getParameterEntity:
 * @ctx: the user data (XML parser context)
 * @name: The entity name
 *
 * Get a parameter entity by name
 * DEPRECATED: use xmlSAX2GetParameterEntity()
 *
 * Returns the xmlEntityPtr if found.
 */
xmlEntityPtr
getParameterEntity(void *ctx, const xmlChar *name)
{
    return(xmlSAX2GetParameterEntity(ctx, name));
}


/**
 * entityDecl:
 * @ctx: the user data (XML parser context)
 * @name:  the entity name 
 * @type:  the entity type 
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 * @content: the entity value (without processing).
 *
 * An entity definition has been parsed
 * DEPRECATED: use xmlSAX2EntityDecl()
 */
void
entityDecl(void *ctx, const xmlChar *name, int type,
          const xmlChar *publicId, const xmlChar *systemId, xmlChar *content)
{
    xmlSAX2EntityDecl(ctx, name, type, publicId, systemId, content);
}

/**
 * attributeDecl:
 * @ctx: the user data (XML parser context)
 * @elem:  the name of the element
 * @fullname:  the attribute name 
 * @type:  the attribute type 
 * @def:  the type of default value
 * @defaultValue: the attribute default value
 * @tree:  the tree of enumerated value set
 *
 * An attribute definition has been parsed
 * DEPRECATED: use xmlSAX2AttributeDecl()
 */
void
attributeDecl(void *ctx, const xmlChar *elem, const xmlChar *fullname,
              int type, int def, const xmlChar *defaultValue,
	      xmlEnumerationPtr tree)
{
    xmlSAX2AttributeDecl(ctx, elem, fullname, type, def, defaultValue, tree);
}

/**
 * elementDecl:
 * @ctx: the user data (XML parser context)
 * @name:  the element name 
 * @type:  the element type 
 * @content: the element value tree
 *
 * An element definition has been parsed
 * DEPRECATED: use xmlSAX2ElementDecl()
 */
void
elementDecl(void *ctx, const xmlChar * name, int type,
            xmlElementContentPtr content)
{
    xmlSAX2ElementDecl(ctx, name, type, content);
}

/**
 * notationDecl:
 * @ctx: the user data (XML parser context)
 * @name: The name of the notation
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * What to do when a notation declaration has been parsed.
 * DEPRECATED: use xmlSAX2NotationDecl()
 */
void
notationDecl(void *ctx, const xmlChar *name,
	     const xmlChar *publicId, const xmlChar *systemId)
{
    xmlSAX2NotationDecl(ctx, name, publicId, systemId);
}

/**
 * unparsedEntityDecl:
 * @ctx: the user data (XML parser context)
 * @name: The name of the entity
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 * @notationName: the name of the notation
 *
 * What to do when an unparsed entity declaration is parsed
 * DEPRECATED: use xmlSAX2UnparsedEntityDecl()
 */
void
unparsedEntityDecl(void *ctx, const xmlChar *name,
		   const xmlChar *publicId, const xmlChar *systemId,
		   const xmlChar *notationName)
{
    xmlSAX2UnparsedEntityDecl(ctx, name, publicId, systemId, notationName);
}

/**
 * setDocumentLocator:
 * @ctx: the user data (XML parser context)
 * @loc: A SAX Locator
 *
 * Receive the document locator at startup, actually xmlDefaultSAXLocator
 * Everything is available on the context, so this is useless in our case.
 * DEPRECATED
 */
void
setDocumentLocator(void *ctx ATTRIBUTE_UNUSED, xmlSAXLocatorPtr loc ATTRIBUTE_UNUSED)
{
}

/**
 * startDocument:
 * @ctx: the user data (XML parser context)
 *
 * called when the document start being processed.
 * DEPRECATED: use xmlSAX2StartDocument()
 */
void
startDocument(void *ctx)
{
    xmlSAX2StartDocument(ctx);
}

/**
 * endDocument:
 * @ctx: the user data (XML parser context)
 *
 * called when the document end has been detected.
 * DEPRECATED: use xmlSAX2EndDocument()
 */
void
endDocument(void *ctx)
{
    xmlSAX2EndDocument(ctx);
}

/**
 * attribute:
 * @ctx: the user data (XML parser context)
 * @fullname:  The attribute name, including namespace prefix
 * @value:  The attribute value
 *
 * Handle an attribute that has been read by the parser.
 * The default handling is to convert the attribute into an
 * DOM subtree and past it in a new xmlAttr element added to
 * the element.
 * DEPRECATED: use xmlSAX2Attribute()
 */
void
attribute(void *ctx ATTRIBUTE_UNUSED, const xmlChar *fullname ATTRIBUTE_UNUSED, const xmlChar *value ATTRIBUTE_UNUSED)
{
}

/**
 * startElement:
 * @ctx: the user data (XML parser context)
 * @fullname:  The element name, including namespace prefix
 * @atts:  An array of name/value attributes pairs, NULL terminated
 *
 * called when an opening tag has been processed.
 * DEPRECATED: use xmlSAX2StartElement()
 */
void
startElement(void *ctx, const xmlChar *fullname, const xmlChar **atts)
{
    xmlSAX2StartElement(ctx, fullname, atts);
}

/**
 * endElement:
 * @ctx: the user data (XML parser context)
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 * DEPRECATED: use xmlSAX2EndElement()
 */
void
endElement(void *ctx, const xmlChar *name ATTRIBUTE_UNUSED)
{
    xmlSAX2EndElement(ctx, name);
}

/**
 * reference:
 * @ctx: the user data (XML parser context)
 * @name:  The entity name
 *
 * called when an entity reference is detected. 
 * DEPRECATED: use xmlSAX2Reference()
 */
void
reference(void *ctx, const xmlChar *name)
{
    xmlSAX2Reference(ctx, name);
}

/**
 * characters:
 * @ctx: the user data (XML parser context)
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some chars from the parser.
 * DEPRECATED: use xmlSAX2Characters()
 */
void
characters(void *ctx, const xmlChar *ch, int len)
{
    xmlSAX2Characters(ctx, ch, len);
}

/**
 * ignorableWhitespace:
 * @ctx: the user data (XML parser context)
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some ignorable whitespaces from the parser.
 * UNUSED: by default the DOM building will use characters
 * DEPRECATED: use xmlSAX2IgnorableWhitespace()
 */
void
ignorableWhitespace(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch ATTRIBUTE_UNUSED, int len ATTRIBUTE_UNUSED)
{
}

/**
 * processingInstruction:
 * @ctx: the user data (XML parser context)
 * @target:  the target name
 * @data: the PI data's
 *
 * A processing instruction has been parsed.
 * DEPRECATED: use xmlSAX2ProcessingInstruction()
 */
void
processingInstruction(void *ctx, const xmlChar *target,
                      const xmlChar *data)
{
    xmlSAX2ProcessingInstruction(ctx, target, data);
}

/**
 * globalNamespace:
 * @ctx: the user data (XML parser context)
 * @href:  the namespace associated URN
 * @prefix: the namespace prefix
 *
 * An old global namespace has been parsed.
 * DEPRECATED
 */
void
globalNamespace(void *ctx ATTRIBUTE_UNUSED, const xmlChar *href ATTRIBUTE_UNUSED, const xmlChar *prefix ATTRIBUTE_UNUSED)
{
}

/**
 * setNamespace:
 * @ctx: the user data (XML parser context)
 * @name:  the namespace prefix
 *
 * Set the current element namespace.
 * DEPRECATED
 */

void
setNamespace(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name ATTRIBUTE_UNUSED)
{
}

/**
 * getNamespace:
 * @ctx: the user data (XML parser context)
 *
 * Get the current element namespace.
 * DEPRECATED
 *
 * Returns the xmlNsPtr or NULL if none
 */

xmlNsPtr
getNamespace(void *ctx ATTRIBUTE_UNUSED)
{
    return(NULL);
}

/**
 * checkNamespace:
 * @ctx: the user data (XML parser context)
 * @namespace: the namespace to check against
 *
 * Check that the current element namespace is the same as the
 * one read upon parsing.
 * DEPRECATED
 *
 * Returns 1 if true 0 otherwise
 */

int
checkNamespace(void *ctx ATTRIBUTE_UNUSED, xmlChar *namespace ATTRIBUTE_UNUSED)
{
    return(0);
}

/**
 * namespaceDecl:
 * @ctx: the user data (XML parser context)
 * @href:  the namespace associated URN
 * @prefix: the namespace prefix
 *
 * A namespace has been parsed.
 * DEPRECATED
 */
void
namespaceDecl(void *ctx ATTRIBUTE_UNUSED, const xmlChar *href ATTRIBUTE_UNUSED, const xmlChar *prefix ATTRIBUTE_UNUSED)
{
}

/**
 * comment:
 * @ctx: the user data (XML parser context)
 * @value:  the comment content
 *
 * A comment has been parsed.
 * DEPRECATED: use xmlSAX2Comment()
 */
void
comment(void *ctx, const xmlChar *value)
{
    xmlSAX2Comment(ctx, value);
}

/**
 * cdataBlock:
 * @ctx: the user data (XML parser context)
 * @value:  The pcdata content
 * @len:  the block length
 *
 * called when a pcdata block has been parsed
 * DEPRECATED: use xmlSAX2CDataBlock()
 */
void
cdataBlock(void *ctx, const xmlChar *value, int len)
{
    xmlSAX2CDataBlock(ctx, value, len);
}

/**
 * initxmlDefaultSAXHandler:
 * @hdlr:  the SAX handler
 * @warning:  flag if non-zero sets the handler warning procedure
 *
 * Initialize the default XML SAX version 1 handler
 * DEPRECATED: use xmlSAX2InitDefaultSAXHandler() for the new SAX2 blocks
 */
void
initxmlDefaultSAXHandler(xmlSAXHandler *hdlr, int warning)
{
    
    if(hdlr->initialized == 1)
	return;

    hdlr->internalSubset = xmlSAX2InternalSubset;
    hdlr->externalSubset = xmlSAX2ExternalSubset;
    hdlr->isStandalone = xmlSAX2IsStandalone;
    hdlr->hasInternalSubset = xmlSAX2HasInternalSubset;
    hdlr->hasExternalSubset = xmlSAX2HasExternalSubset;
    hdlr->resolveEntity = xmlSAX2ResolveEntity;
    hdlr->getEntity = xmlSAX2GetEntity;
    hdlr->getParameterEntity = xmlSAX2GetParameterEntity;
    hdlr->entityDecl = xmlSAX2EntityDecl;
    hdlr->attributeDecl = xmlSAX2AttributeDecl;
    hdlr->elementDecl = xmlSAX2ElementDecl;
    hdlr->notationDecl = xmlSAX2NotationDecl;
    hdlr->unparsedEntityDecl = xmlSAX2UnparsedEntityDecl;
    hdlr->setDocumentLocator = xmlSAX2SetDocumentLocator;
    hdlr->startDocument = xmlSAX2StartDocument;
    hdlr->endDocument = xmlSAX2EndDocument;
    hdlr->startElement = xmlSAX2StartElement;
    hdlr->endElement = xmlSAX2EndElement;
    hdlr->reference = xmlSAX2Reference;
    hdlr->characters = xmlSAX2Characters;
    hdlr->cdataBlock = xmlSAX2CDataBlock;
    hdlr->ignorableWhitespace = xmlSAX2Characters;
    hdlr->processingInstruction = xmlSAX2ProcessingInstruction;
    if (warning == 0)
	hdlr->warning = NULL;
    else
	hdlr->warning = xmlParserWarning;
    hdlr->error = xmlParserError;
    hdlr->fatalError = xmlParserError;

    hdlr->initialized = 1;
}

#ifdef LIBXML_HTML_ENABLED

/**
 * inithtmlDefaultSAXHandler:
 * @hdlr:  the SAX handler
 *
 * Initialize the default HTML SAX version 1 handler
 * DEPRECATED: use xmlSAX2InitHtmlDefaultSAXHandler() for the new SAX2 blocks
 */
void
inithtmlDefaultSAXHandler(xmlSAXHandler *hdlr)
{
    if(hdlr->initialized == 1)
	return;

    hdlr->internalSubset = xmlSAX2InternalSubset;
    hdlr->externalSubset = NULL;
    hdlr->isStandalone = NULL;
    hdlr->hasInternalSubset = NULL;
    hdlr->hasExternalSubset = NULL;
    hdlr->resolveEntity = NULL;
    hdlr->getEntity = xmlSAX2GetEntity;
    hdlr->getParameterEntity = NULL;
    hdlr->entityDecl = NULL;
    hdlr->attributeDecl = NULL;
    hdlr->elementDecl = NULL;
    hdlr->notationDecl = NULL;
    hdlr->unparsedEntityDecl = NULL;
    hdlr->setDocumentLocator = xmlSAX2SetDocumentLocator;
    hdlr->startDocument = xmlSAX2StartDocument;
    hdlr->endDocument = xmlSAX2EndDocument;
    hdlr->startElement = xmlSAX2StartElement;
    hdlr->endElement = xmlSAX2EndElement;
    hdlr->reference = NULL;
    hdlr->characters = xmlSAX2Characters;
    hdlr->cdataBlock = xmlSAX2CDataBlock;
    hdlr->ignorableWhitespace = xmlSAX2IgnorableWhitespace;
    hdlr->processingInstruction = NULL;
    hdlr->comment = xmlSAX2Comment;
    hdlr->warning = xmlParserWarning;
    hdlr->error = xmlParserError;
    hdlr->fatalError = xmlParserError;

    hdlr->initialized = 1;
}

#endif /* LIBXML_HTML_ENABLED */

#ifdef LIBXML_DOCB_ENABLED

/**
 * initdocbDefaultSAXHandler:
 * @hdlr:  the SAX handler
 *
 * Initialize the default DocBook SAX version 1 handler
 * DEPRECATED: use xmlSAX2InitDocbDefaultSAXHandler() for the new SAX2 blocks
 */
void
initdocbDefaultSAXHandler(xmlSAXHandler *hdlr)
{
    if(hdlr->initialized == 1)
	return;

    hdlr->internalSubset = xmlSAX2InternalSubset;
    hdlr->externalSubset = NULL;
    hdlr->isStandalone = xmlSAX2IsStandalone;
    hdlr->hasInternalSubset = xmlSAX2HasInternalSubset;
    hdlr->hasExternalSubset = xmlSAX2HasExternalSubset;
    hdlr->resolveEntity = xmlSAX2ResolveEntity;
    hdlr->getEntity = xmlSAX2GetEntity;
    hdlr->getParameterEntity = NULL;
    hdlr->entityDecl = xmlSAX2EntityDecl;
    hdlr->attributeDecl = NULL;
    hdlr->elementDecl = NULL;
    hdlr->notationDecl = NULL;
    hdlr->unparsedEntityDecl = NULL;
    hdlr->setDocumentLocator = xmlSAX2SetDocumentLocator;
    hdlr->startDocument = xmlSAX2StartDocument;
    hdlr->endDocument = xmlSAX2EndDocument;
    hdlr->startElement = xmlSAX2StartElement;
    hdlr->endElement = xmlSAX2EndElement;
    hdlr->reference = xmlSAX2Reference;
    hdlr->characters = xmlSAX2Characters;
    hdlr->cdataBlock = NULL;
    hdlr->ignorableWhitespace = xmlSAX2IgnorableWhitespace;
    hdlr->processingInstruction = NULL;
    hdlr->comment = xmlSAX2Comment;
    hdlr->warning = xmlParserWarning;
    hdlr->error = xmlParserError;
    hdlr->fatalError = xmlParserError;

    hdlr->initialized = 1;
}

#endif /* LIBXML_DOCB_ENABLED */
