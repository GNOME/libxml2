/*
 * SAX.c : Default SAX handler to build a tree.
 */

#include <stdio.h>
#include <malloc.h>
#include "tree.h"
#include "parser.h"
#include "error.h"

/* #define DEBUG_SAX */

/*
 * Return the public ID e.g. "-//SGMLSOURCE//DTD DEMO//EN"
 */
const CHAR *getPublicId(xmlParserCtxtPtr ctxt) {
    return(NULL);
}

/*
 * Return the system ID, basically URI or filename e.g.
 *  http://www.sgmlsource.com/dtds/memo.dtd
 */
const CHAR *getSystemId(xmlParserCtxtPtr ctxt) {
    return(ctxt->input->filename); 
}

/*
 * Return the line number of the current parsing point.
 */
int getLineNumber(xmlParserCtxtPtr ctxt) {
    return(ctxt->input->line);
}
/*
 * Return the column number of the current parsing point.
 */
int getColumnNumber(xmlParserCtxtPtr ctxt) {
    return(ctxt->input->col);
}

/*
 * The default SAX Locator.
 */

xmlSAXLocator xmlDefaultSAXLocator = {
    getPublicId, getSystemId, getLineNumber, getColumnNumber
};

/*
 * Special entity resolver, better left to the parser, it has
 * more context than the application layer.
 */
xmlParserInputPtr resolveEntity(xmlParserCtxtPtr ctxt, 
			    const CHAR *publicId, const CHAR *systemId) {

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.resolveEntity(%s, %s)\n", publicId, systemId);
#endif
    return(NULL);
}

/*
 * What to do when a notation declaration has been parsed.
 * TODO Not handled currently.
 */
void notationDecl(xmlParserCtxtPtr ctxt, const CHAR *name,
		  const CHAR *publicId, const CHAR *systemId) {
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.notationDecl(%s, %s, %s)\n", name, publicId, systemId);
#endif
}

/*
 * What to do when an unparsed entity declaration is parsed
 * TODO Create an Entity node.
 */
void unparsedEntityDecl(xmlParserCtxtPtr ctxt, const CHAR *name,
			const CHAR *publicId, const CHAR *systemId,
			const CHAR *notationName) {
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.unparsedEntityDecl(%s, %s, %s, %s)\n",
            name, publicId, systemId, notationName);
#endif
}

/*
 * Receive the document locator at startup, actually xmlDefaultSAXLocator
 * Everything is available on the context, so this is useless in our case.
 */
void setDocumentLocator(xmlParserCtxtPtr ctxt, xmlSAXLocatorPtr loc) {
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.setDocumentLocator()\n");
#endif
}

/*
 * called when the document start being processed.
 */
void startDocument(xmlParserCtxtPtr ctxt) {
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startDocument()\n");
#endif
}

/*
 * called when the document end has been detected.
 */
void endDocument(xmlParserCtxtPtr ctxt) {
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.endDocument()\n");
#endif
}

/*
 * called when an opening tag has been processed.
 * TODO We currently have a small pblm with the arguments ...
 */
void startElement(xmlParserCtxtPtr ctxt, const CHAR *name) {
    xmlNodePtr parent;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startElement(%s)\n", name);
#endif
    if (ctxt->nodeNr < 2) return;
    parent = ctxt->nodeTab[ctxt->nodeNr - 2];
    if (parent != NULL)
	xmlAddChild(parent, ctxt->node);
    
}

/*
 * called when the end of an element has been detected.
 */
void endElement(xmlParserCtxtPtr ctxt, const CHAR *name) {
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.endElement(%s)\n", name);
#endif
}

/*
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
void characters(xmlParserCtxtPtr ctxt, const CHAR *ch,
                       int start, int len) {
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

/*
 * receiving some ignorable whitespaces from the parser.
 * Question: how much at a time ???
 */
void ignorableWhitespace(xmlParserCtxtPtr ctxt, const CHAR *ch,
                         int start, int len) {
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.ignorableWhitespace(%.30s, %d, %d)\n", ch, start, len);
#endif
}

/*
 * A processing instruction has beem parsed.
 */
void processingInstruction(xmlParserCtxtPtr ctxt, const CHAR *target,
			   const CHAR *data) {
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

void xmlDefaultSAXHandlerInit(void) {
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
