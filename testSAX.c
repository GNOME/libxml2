/*
 * tester.c : a small tester program for parsing using the SAX API.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#define HAVE_FCNTL_H
#include <io.h>
#else
#include <config.h>
#endif
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "parser.h"
#include "parserInternals.h" /* only for xmlNewInputFromFile() */
#include "tree.h"
#include "debugXML.h"

static int debug = 0;
static int copy = 0;
static int recovery = 0;

xmlSAXHandler emptySAXHandlerStruct = {
    NULL, /* internalSubset */
    NULL, /* isStandalone */
    NULL, /* hasInternalSubset */
    NULL, /* hasExternalSubset */
    NULL, /* resolveEntity */
    NULL, /* getEntity */
    NULL, /* entityDecl */
    NULL, /* notationDecl */
    NULL, /* attributeDecl */
    NULL, /* elementDecl */
    NULL, /* unparsedEntityDecl */
    NULL, /* setDocumentLocator */
    NULL, /* startDocument */
    NULL, /* endDocument */
    NULL, /* startElement */
    NULL, /* endElement */
    NULL, /* reference */
    NULL, /* characters */
    NULL, /* ignorableWhitespace */
    NULL, /* processingInstruction */
    NULL, /* comment */
    NULL, /* xmlParserWarning */
    NULL, /* xmlParserError */
    NULL, /* xmlParserError */
};

xmlSAXHandlerPtr emptySAXHandler = &emptySAXHandlerStruct;
extern xmlSAXHandlerPtr debugSAXHandler;

/*
 * Note: there is a couple of errors introduced on purpose.
 */
static CHAR buffer[] = 
"<?xml version=\"1.0\"?>\n\
<?xml:namespace ns = \"http://www.ietf.org/standards/dav/\" prefix = \"D\"?>\n\
<?xml:namespace ns = \"http://www.w3.com/standards/z39.50/\" prefix = \"Z\"?>\n\
<D:propertyupdate>\n\
<D:set a=\"'toto'\" b>\n\
       <D:prop>\n\
            <Z:authors>\n\
                 <Z:Author>Jim Whitehead</Z:Author>\n\
                 <Z:Author>Roy Fielding</Z:Author>\n\
            </Z:authors>\n\
       </D:prop>\n\
  </D:set>\n\
  <D:remove>\n\
       <D:prop><Z:Copyright-Owner/></D:prop>\n\
  </D:remove>\n\
</D:propertyupdate>\n\
\n\
";

/************************************************************************
 *									*
 *				Debug Handlers				*
 *									*
 ************************************************************************/

/**
 * isStandaloneDebug:
 * @ctxt:  An XML parser context
 *
 * Is this document tagged standalone ?
 *
 * Returns 1 if true
 */
int
isStandaloneDebug(xmlParserCtxtPtr ctxt)
{
    fprintf(stdout, "SAX.isStandalone()\n");
    return(0);
}

/**
 * hasInternalSubsetDebug:
 * @ctxt:  An XML parser context
 *
 * Does this document has an internal subset
 *
 * Returns 1 if true
 */
int
hasInternalSubsetDebug(xmlParserCtxtPtr ctxt)
{
    fprintf(stdout, "SAX.hasInternalSubset()\n");
    return(0);
}

/**
 * hasExternalSubsetDebug:
 * @ctxt:  An XML parser context
 *
 * Does this document has an external subset
 *
 * Returns 1 if true
 */
int
hasExternalSubsetDebug(xmlParserCtxtPtr ctxt)
{
    fprintf(stdout, "SAX.hasExternalSubset()\n");
    return(0);
}

/**
 * hasInternalSubsetDebug:
 * @ctxt:  An XML parser context
 *
 * Does this document has an internal subset
 */
void
internalSubsetDebug(xmlParserCtxtPtr ctxt, const CHAR *name,
	       const CHAR *ExternalID, const CHAR *SystemID)
{
    xmlDtdPtr externalSubset;

    fprintf(stdout, "SAX.internalSubset(%s, %s, %s)\n",
            name, ExternalID, SystemID);

    if ((ExternalID != NULL) || (SystemID != NULL)) {
        externalSubset = xmlSAXParseDTD(debugSAXHandler, ExternalID, SystemID);
    }
}

/**
 * resolveEntityDebug:
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
resolveEntityDebug(xmlParserCtxtPtr ctxt, const CHAR *publicId, const CHAR *systemId)
{
    fprintf(stdout, "SAX.resolveEntity(%s, %s)\n",
            (char *)publicId, (char *)systemId);
    if (systemId != NULL) {
        return(xmlNewInputFromFile(ctxt, systemId));
    }
    return(NULL);
}

/**
 * getEntityDebug:
 * @ctxt:  An XML parser context
 * @name: The entity name
 *
 * Get an entity by name
 *
 * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
 */
xmlEntityPtr
getEntityDebug(xmlParserCtxtPtr ctxt, const CHAR *name)
{
    fprintf(stdout, "SAX.getEntity(%s)\n", name);
    return(NULL);
}


/**
 * entityDeclDebug:
 * @ctxt:  An XML parser context
 * @name:  the entity name 
 * @type:  the entity type 
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 * @content: the entity value (without processing).
 *
 * An entity definition has been parsed
 */
void
entityDeclDebug(xmlParserCtxtPtr ctxt, const CHAR *name, int type,
          const CHAR *publicId, const CHAR *systemId, CHAR *content)
{
    fprintf(stdout, "SAX.entityDecl(%s, %d, %s, %s, %s)\n",
            name, type, publicId, systemId, content);
}

/**
 * attributeDeclDebug:
 * @ctxt:  An XML parser context
 * @name:  the attribute name 
 * @type:  the attribute type 
 *
 * An attribute definition has been parsed
 */
void
attributeDeclDebug(xmlParserCtxtPtr ctxt, const CHAR *elem, const CHAR *name,
              int type, int def, const CHAR *defaultValue,
	      xmlEnumerationPtr tree)
{
    fprintf(stdout, "SAX.attributeDecl(%s, %s, %d, %d, %s, ...)\n",
            elem, name, type, def, defaultValue);
}

/**
 * elementDeclDebug:
 * @ctxt:  An XML parser context
 * @name:  the element name 
 * @type:  the element type 
 * @content: the element value (without processing).
 *
 * An element definition has been parsed
 */
void
elementDeclDebug(xmlParserCtxtPtr ctxt, const CHAR *name, int type,
	    xmlElementContentPtr content)
{
    fprintf(stdout, "SAX.elementDecl(%s, %d, ...)\n",
            name, type);
}

/**
 * notationDeclDebug:
 * @ctxt:  An XML parser context
 * @name: The name of the notation
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * What to do when a notation declaration has been parsed.
 * TODO Not handled currently.
 */
void
notationDeclDebug(xmlParserCtxtPtr ctxt, const CHAR *name,
	     const CHAR *publicId, const CHAR *systemId)
{
    fprintf(stdout, "SAX.notationDecl(%s, %s, %s)\n",
            (char *) name, (char *) publicId, (char *) systemId);
}

/**
 * unparsedEntityDeclDebug:
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
unparsedEntityDeclDebug(xmlParserCtxtPtr ctxt, const CHAR *name,
		   const CHAR *publicId, const CHAR *systemId,
		   const CHAR *notationName)
{
    fprintf(stdout, "SAX.unparsedEntityDecl(%s, %s, %s, %s)\n",
            (char *) name, (char *) publicId, (char *) systemId,
	    (char *) notationName);
}

/**
 * setDocumentLocatorDebug:
 * @ctxt:  An XML parser context
 * @loc: A SAX Locator
 *
 * Receive the document locator at startup, actually xmlDefaultSAXLocator
 * Everything is available on the context, so this is useless in our case.
 */
void
setDocumentLocatorDebug(xmlParserCtxtPtr ctxt, xmlSAXLocatorPtr loc)
{
    fprintf(stdout, "SAX.setDocumentLocator()\n");
}

/**
 * startDocumentDebug:
 * @ctxt:  An XML parser context
 *
 * called when the document start being processed.
 */
void
startDocumentDebug(xmlParserCtxtPtr ctxt)
{
    fprintf(stdout, "SAX.startDocument()\n");
}

/**
 * endDocumentDebug:
 * @ctxt:  An XML parser context
 *
 * called when the document end has been detected.
 */
void
endDocumentDebug(xmlParserCtxtPtr ctxt)
{
    fprintf(stdout, "SAX.endDocument()\n");
}

/**
 * startElementDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 * TODO We currently have a small pblm with the arguments ...
 */
void
startElementDebug(xmlParserCtxtPtr ctxt, const CHAR *name, const CHAR **atts)
{
    int i;

    fprintf(stdout, "SAX.startElement(%s", (char *) name);
    if (atts != NULL) {
        for (i = 0;(atts[i] != NULL);i++) {
	    fprintf(stdout, ", %s='", atts[i++]);
	    fprintf(stdout, "%s'", atts[i]);
	}
    }
    fprintf(stdout, ")\n");
}

/**
 * endElementDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
void
endElementDebug(xmlParserCtxtPtr ctxt, const CHAR *name)
{
    fprintf(stdout, "SAX.endElement(%s)\n", (char *) name);
}

/**
 * charactersDebug:
 * @ctxt:  An XML parser context
 * @ch:  a CHAR string
 * @len: the number of CHAR
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
void
charactersDebug(xmlParserCtxtPtr ctxt, const CHAR *ch, int len)
{
    fprintf(stdout, "SAX.characters(%.30s, %d)\n", (char *) ch, len);
}

/**
 * referenceDebug:
 * @ctxt:  An XML parser context
 * @name:  The entity name
 *
 * called when an entity reference is detected. 
 */
void
referenceDebug(xmlParserCtxtPtr ctxt, const CHAR *name)
{
    fprintf(stdout, "SAX.reference(%s)\n", name);
}

/**
 * ignorableWhitespaceDebug:
 * @ctxt:  An XML parser context
 * @ch:  a CHAR string
 * @start: the first char in the string
 * @len: the number of CHAR
 *
 * receiving some ignorable whitespaces from the parser.
 * Question: how much at a time ???
 */
void
ignorableWhitespaceDebug(xmlParserCtxtPtr ctxt, const CHAR *ch, int len)
{
    fprintf(stdout, "SAX.ignorableWhitespace(%.30s, %d)\n",
            (char *) ch, len);
}

/**
 * processingInstructionDebug:
 * @ctxt:  An XML parser context
 * @target:  the target name
 * @data: the PI data's
 * @len: the number of CHAR
 *
 * A processing instruction has been parsed.
 */
void
processingInstructionDebug(xmlParserCtxtPtr ctxt, const CHAR *target,
                      const CHAR *data)
{
    fprintf(stdout, "SAX.processingInstruction(%s, %s)\n",
            (char *) target, (char *) data);
}

/**
 * commentDebug:
 * @ctxt:  An XML parser context
 * @value:  the comment content
 *
 * A comment has been parsed.
 */
void
commentDebug(xmlParserCtxtPtr ctxt, const CHAR *value)
{
    fprintf(stdout, "SAX.comment(%s)\n", value);
}

/**
 * warningDebug:
 * @ctxt:  An XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format a warning messages, gives file, line, position and
 * extra parameters.
 */
void
warningDebug(xmlParserCtxtPtr ctxt, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    fprintf(stdout, "SAX.warning: ");
    vfprintf(stdout, msg, args);
    va_end(args);
}

/**
 * errorDebug:
 * @ctxt:  An XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format a error messages, gives file, line, position and
 * extra parameters.
 */
void
errorDebug(xmlParserCtxtPtr ctxt, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    fprintf(stdout, "SAX.error: ");
    vfprintf(stdout, msg, args);
    va_end(args);
}

/**
 * fatalErrorDebug:
 * @ctxt:  An XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format a fatalError messages, gives file, line, position and
 * extra parameters.
 */
void
fatalErrorDebug(xmlParserCtxtPtr ctxt, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    fprintf(stdout, "SAX.fatalError: ");
    vfprintf(stdout, msg, args);
    va_end(args);
}

xmlSAXHandler debugSAXHandlerStruct = {
    internalSubsetDebug,
    isStandaloneDebug,
    hasInternalSubsetDebug,
    hasExternalSubsetDebug,
    resolveEntityDebug,
    getEntityDebug,
    entityDeclDebug,
    notationDeclDebug,
    attributeDeclDebug,
    elementDeclDebug,
    unparsedEntityDeclDebug,
    setDocumentLocatorDebug,
    startDocumentDebug,
    endDocumentDebug,
    startElementDebug,
    endElementDebug,
    referenceDebug,
    charactersDebug,
    ignorableWhitespaceDebug,
    processingInstructionDebug,
    commentDebug,
    warningDebug,
    errorDebug,
    fatalErrorDebug,
};

xmlSAXHandlerPtr debugSAXHandler = &debugSAXHandlerStruct;

/************************************************************************
 *									*
 *				Debug					*
 *									*
 ************************************************************************/

void parseAndPrintFile(char *filename) {
    xmlDocPtr doc;

    /*
     * Empty callbacks for checking
     */
    doc = xmlSAXParseFile(emptySAXHandler, filename, 0);
    if (doc != NULL) {
        fprintf(stdout, "xmlSAXParseFile returned non-NULL\n");
	xmlDocDump(stdout, doc);
    }

    /*
     * Debug callback
     */
    doc = xmlSAXParseFile(debugSAXHandler, filename, 0);
    if (doc != NULL) {
        fprintf(stderr, "xmlSAXParseFile returned non-NULL\n");
	xmlDocDump(stdout, doc);
    }
}

void parseAndPrintBuffer(CHAR *buf) {
    xmlDocPtr doc;

    /*
     * Empty callbacks for checking
     */
    doc = xmlSAXParseDoc(emptySAXHandler, buf, 0);
    if (doc != NULL) {
        fprintf(stderr, "xmlSAXParseDoc returned non-NULL\n");
	xmlDocDump(stdout, doc);
    }

    /*
     * Debug callback
     */
    doc = xmlSAXParseDoc(debugSAXHandler, buf, 0);
    if (doc != NULL) {
        fprintf(stderr, "xmlSAXParseDoc returned non-NULL\n");
	xmlDocDump(stdout, doc);
    }
}

int main(int argc, char **argv) {
    int i;
    int files = 0;

    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	else if ((!strcmp(argv[i], "-copy")) || (!strcmp(argv[i], "--copy")))
	    copy++;
	else if ((!strcmp(argv[i], "-recover")) ||
	         (!strcmp(argv[i], "--recover")))
	    recovery++;
    }
    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
	    parseAndPrintFile(argv[i]);
	    files ++;
	}
    }
    if (files == 0) {
	printf("\nFirst test for the parser, with errors\n");
        parseAndPrintBuffer(buffer);
    }

    return(0);
}
