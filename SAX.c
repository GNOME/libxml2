/*
 * SAX.c : Default SAX handler to build a tree.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include "tree.h"
#include "parser.h"
#include "error.h"

/* #define DEBUG_SAX */

/**
 * getPublicId:
 * @ctxt:  An XML parser context
 *
 * Return the public ID e.g. "-//SGMLSOURCE//DTD DEMO//EN"
 *
 * return values: a CHAR *
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
 * return values: a CHAR *
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
 * return values: an int
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
 * return values: an int
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
 *
 * return values: an int
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
 *
 * return values: 
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
 *
 * return values: 
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
 *
 * return values: 
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
 *
 * return values: 
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
 *
 * return values: 
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
 *
 * return values: 
 */
void
startElement(xmlParserCtxtPtr ctxt, const CHAR *name)
{
    xmlNodePtr parent;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startElement(%s)\n", name);
#endif
    if (ctxt->nodeNr < 2) return;
    parent = ctxt->nodeTab[ctxt->nodeNr - 2];
    if (parent != NULL)
	xmlAddChild(parent, ctxt->node);
    
}

/**
 * endElement:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 *
 * return values: 
 */
void
endElement(xmlParserCtxtPtr ctxt, const CHAR *name)
{
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.endElement(%s)\n", name);
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
 *
 * return values: 
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
 *
 * return values: 
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
 *
 * return values: 
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
 *
 * return values: 
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
    xmlDefaultSAXHandler.characters = characters;
    xmlDefaultSAXHandler.ignorableWhitespace = ignorableWhitespace;
    xmlDefaultSAXHandler.processingInstruction = processingInstruction;
    xmlDefaultSAXHandler.warning = xmlParserWarning;
    xmlDefaultSAXHandler.error = xmlParserError;
    xmlDefaultSAXHandler.fatalError = xmlParserError;
}
