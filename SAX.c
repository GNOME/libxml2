/*
 * SAX.c : Default SAX handler to build a tree.
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include "tree.h"
#include "parser.h"
#include "entities.h"
#include "error.h"

/* #define DEBUG_SAX */

/**
 * getPublicId:
 * @ctxt:  An XML parser context
 *
 * Return the public ID e.g. "-//SGMLSOURCE//DTD DEMO//EN"
 *
 * Returns a CHAR *
 */
const CHAR *
getPublicId(xmlParserCtxtPtr ctxt)
{
    return(NULL);
}

/**
 * getSystemId:
 * @ctxt:  An XML parser context
 *
 * Return the system ID, basically URI or filename e.g.
 * http://www.sgmlsource.com/dtds/memo.dtd
 *
 * Returns a CHAR *
 */
const CHAR *
getSystemId(xmlParserCtxtPtr ctxt)
{
    return(ctxt->input->filename); 
}

/**
 * getLineNumber:
 * @ctxt:  An XML parser context
 *
 * Return the line number of the current parsing point.
 *
 * Returns an int
 */
int
getLineNumber(xmlParserCtxtPtr ctxt)
{
    return(ctxt->input->line);
}

/**
 * getColumnNumber:
 * @ctxt:  An XML parser context
 *
 * Return the column number of the current parsing point.
 *
 * Returns an int
 */
int
getColumnNumber(xmlParserCtxtPtr ctxt)
{
    return(ctxt->input->col);
}

/*
 * The default SAX Locator.
 */

xmlSAXLocator xmlDefaultSAXLocator = {
    getPublicId, getSystemId, getLineNumber, getColumnNumber
};

/**
 * resolveEntity:
 * @ctxt:  An XML parser context
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * Special entity resolver, better left to the parser, it has
 * more context than the application layer.
 * The default behaviour is to NOT resolve the entities, in that case
 * the ENTITY_REF nodes are built in the structure (and the parameter
 * values).
 *
 * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
 */
xmlParserInputPtr
resolveEntity(xmlParserCtxtPtr ctxt, const CHAR *publicId, const CHAR *systemId)
{

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.resolveEntity(%s, %s)\n", publicId, systemId);
#endif

    return(NULL);
}

/**
 * notationDecl:
 * @ctxt:  An XML parser context
 * @name: The name of the notation
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * What to do when a notation declaration has been parsed.
 * TODO Not handled currently.
 */
void
notationDecl(xmlParserCtxtPtr ctxt, const CHAR *name,
	     const CHAR *publicId, const CHAR *systemId)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.notationDecl(%s, %s, %s)\n", name, publicId, systemId);
#endif
}

/**
 * unparsedEntityDecl:
 * @ctxt:  An XML parser context
 * @name: The name of the entity
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 * @notationName: the name of the notation
 *
 * What to do when an unparsed entity declaration is parsed
 * TODO Create an Entity node.
 */
void
unparsedEntityDecl(xmlParserCtxtPtr ctxt, const CHAR *name,
		   const CHAR *publicId, const CHAR *systemId,
		   const CHAR *notationName)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.unparsedEntityDecl(%s, %s, %s, %s)\n",
            name, publicId, systemId, notationName);
#endif
}

/**
 * setDocumentLocator:
 * @ctxt:  An XML parser context
 * @loc: A SAX Locator
 *
 * Receive the document locator at startup, actually xmlDefaultSAXLocator
 * Everything is available on the context, so this is useless in our case.
 */
void
setDocumentLocator(xmlParserCtxtPtr ctxt, xmlSAXLocatorPtr loc)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.setDocumentLocator()\n");
#endif
}

/**
 * startDocument:
 * @ctxt:  An XML parser context
 *
 * called when the document start being processed.
 */
void
startDocument(xmlParserCtxtPtr ctxt)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startDocument()\n");
#endif
}

/**
 * endDocument:
 * @ctxt:  An XML parser context
 *
 * called when the document end has been detected.
 */
void
endDocument(xmlParserCtxtPtr ctxt)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.endDocument()\n");
#endif
}

/**
 * startElement:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 * TODO We currently have a small pblm with the arguments ...
 */
void
startElement(xmlParserCtxtPtr ctxt, const CHAR *name)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startElement(%s)\n", name);
#endif
}

/**
 * endElement:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
void
endElement(xmlParserCtxtPtr ctxt, const CHAR *name)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.endElement(%s)\n", name);
#endif
}

/**
 * attribute:
 * @ctxt:  An XML parser context
 * @name:  The attribute name
 * @value:  The attribute value
 *
 * called when an attribute has been read by the parser.
 * The default handling is to convert the attribute into an
 * DOM subtree and past it in a new xmlAttr element added to
 * the element.
 */
void
attribute(xmlParserCtxtPtr ctxt, const CHAR *name, const CHAR *value)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.attribute(%s, %s)\n", name, value);
#endif
}

/**
 * characters:
 * @ctxt:  An XML parser context
 * @ch:  a CHAR string
 * @start: the first char in the string
 * @len: the number of CHAR
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
void
characters(xmlParserCtxtPtr ctxt, const CHAR *ch, int start, int len)
{
    xmlNodePtr lastChild;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.characters(%.30s, %d, %d)\n", ch, start, len);
#endif
    /*
     * Handle the data if any. If there is no child
     * add it as content, otherwise if the last child is text,
     * concatenate it, else create a new node of type text.
     */

    lastChild = xmlGetLastChild(ctxt->node);
    if (lastChild == NULL)
	xmlNodeAddContentLen(ctxt->node, &ch[start], len);
    else {
	if (xmlNodeIsText(lastChild))
	    xmlTextConcat(lastChild, &ch[start], len);
	else {
	    lastChild = xmlNewTextLen(&ch[start], len);
	    xmlAddChild(ctxt->node, lastChild);
	}
    }
}

/**
 * ignorableWhitespace:
 * @ctxt:  An XML parser context
 * @ch:  a CHAR string
 * @start: the first char in the string
 * @len: the number of CHAR
 *
 * receiving some ignorable whitespaces from the parser.
 * Question: how much at a time ???
 */
void
ignorableWhitespace(xmlParserCtxtPtr ctxt, const CHAR *ch, int start, int len)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.ignorableWhitespace(%.30s, %d, %d)\n", ch, start, len);
#endif
}

/**
 * processingInstruction:
 * @ctxt:  An XML parser context
 * @target:  the target name
 * @data: the PI data's
 * @len: the number of CHAR
 *
 * A processing instruction has been parsed.
 */
void
processingInstruction(xmlParserCtxtPtr ctxt, const CHAR *target,
                      const CHAR *data)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.processingInstruction(%s, %s)\n", target, data);
#endif
}

xmlSAXHandler xmlDefaultSAXHandler = {
    resolveEntity,
    notationDecl,
    unparsedEntityDecl,
    setDocumentLocator,
    startDocument,
    endDocument,
    startElement,
    endElement,
    attribute,
    characters,
    ignorableWhitespace,
    processingInstruction,
    xmlParserWarning,
    xmlParserError,
    xmlParserError,
};

/**
 * xmlDefaultSAXHandlerInit:
 *
 * Initialize the default SAX handler
 */
void
xmlDefaultSAXHandlerInit(void)
{
    xmlDefaultSAXHandler.resolveEntity = resolveEntity;
    xmlDefaultSAXHandler.notationDecl = notationDecl;
    xmlDefaultSAXHandler.unparsedEntityDecl = unparsedEntityDecl;
    xmlDefaultSAXHandler.setDocumentLocator = setDocumentLocator;
    xmlDefaultSAXHandler.startDocument = startDocument;
    xmlDefaultSAXHandler.endDocument = endDocument;
    xmlDefaultSAXHandler.startElement = startElement;
    xmlDefaultSAXHandler.endElement = endElement;
    xmlDefaultSAXHandler.attribute = attribute;
    xmlDefaultSAXHandler.characters = characters;
    xmlDefaultSAXHandler.ignorableWhitespace = ignorableWhitespace;
    xmlDefaultSAXHandler.processingInstruction = processingInstruction;
    xmlDefaultSAXHandler.warning = xmlParserWarning;
    xmlDefaultSAXHandler.error = xmlParserError;
    xmlDefaultSAXHandler.fatalError = xmlParserError;
}
