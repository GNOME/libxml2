/*
 * testHTML.c : a small tester program for HTML input.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "xmlmemory.h"
#include "HTMLparser.h"
#include "HTMLtree.h"
#include "debugXML.h"

static int debug = 0;
static int copy = 0;
static int sax = 0;
static int repeat = 0;
static int noout = 0;
static int push = 0;

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
    NULL, /* getParameterEntity */
};

xmlSAXHandlerPtr emptySAXHandler = &emptySAXHandlerStruct;
extern xmlSAXHandlerPtr debugSAXHandler;

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
isStandaloneDebug(void *ctx)
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
hasInternalSubsetDebug(void *ctx)
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
hasExternalSubsetDebug(void *ctx)
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
internalSubsetDebug(void *ctx, const xmlChar *name,
	       const xmlChar *ExternalID, const xmlChar *SystemID)
{
    /* xmlDtdPtr externalSubset; */

    fprintf(stdout, "SAX.internalSubset(%s, %s, %s)\n",
            name, ExternalID, SystemID);

/***********
    if ((ExternalID != NULL) || (SystemID != NULL)) {
        externalSubset = xmlParseDTD(ExternalID, SystemID);
	if (externalSubset != NULL) {
	    xmlFreeDtd(externalSubset);
	}
    }
 ***********/
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
resolveEntityDebug(void *ctx, const xmlChar *publicId, const xmlChar *systemId)
{
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */

    
    fprintf(stdout, "SAX.resolveEntity(");
    if (publicId != NULL)
	fprintf(stdout, "%s", (char *)publicId);
    else
	fprintf(stdout, " ");
    if (systemId != NULL)
	fprintf(stdout, ", %s)\n", (char *)systemId);
    else
	fprintf(stdout, ", )\n");
/*********
    if (systemId != NULL) {
        return(xmlNewInputFromFile(ctxt, (char *) systemId));
    }
 *********/
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
getEntityDebug(void *ctx, const xmlChar *name)
{
    fprintf(stdout, "SAX.getEntity(%s)\n", name);
    return(NULL);
}

/**
 * getParameterEntityDebug:
 * @ctxt:  An XML parser context
 * @name: The entity name
 *
 * Get a parameter entity by name
 *
 * Returns the xmlParserInputPtr
 */
xmlEntityPtr
getParameterEntityDebug(void *ctx, const xmlChar *name)
{
    fprintf(stdout, "SAX.getParameterEntity(%s)\n", name);
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
entityDeclDebug(void *ctx, const xmlChar *name, int type,
          const xmlChar *publicId, const xmlChar *systemId, xmlChar *content)
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
attributeDeclDebug(void *ctx, const xmlChar *elem, const xmlChar *name,
              int type, int def, const xmlChar *defaultValue,
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
elementDeclDebug(void *ctx, const xmlChar *name, int type,
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
 */
void
notationDeclDebug(void *ctx, const xmlChar *name,
	     const xmlChar *publicId, const xmlChar *systemId)
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
 */
void
unparsedEntityDeclDebug(void *ctx, const xmlChar *name,
		   const xmlChar *publicId, const xmlChar *systemId,
		   const xmlChar *notationName)
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
setDocumentLocatorDebug(void *ctx, xmlSAXLocatorPtr loc)
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
startDocumentDebug(void *ctx)
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
endDocumentDebug(void *ctx)
{
    fprintf(stdout, "SAX.endDocument()\n");
}

/**
 * startElementDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 */
void
startElementDebug(void *ctx, const xmlChar *name, const xmlChar **atts)
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
endElementDebug(void *ctx, const xmlChar *name)
{
    fprintf(stdout, "SAX.endElement(%s)\n", (char *) name);
}

/**
 * charactersDebug:
 * @ctxt:  An XML parser context
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
void
charactersDebug(void *ctx, const xmlChar *ch, int len)
{
    int i;

    fprintf(stdout, "SAX.characters(");
    for (i = 0;(i < len) && (i < 30);i++)
	fprintf(stdout, "%c", ch[i]);
    fprintf(stdout, ", %d)\n", len);
}

/**
 * referenceDebug:
 * @ctxt:  An XML parser context
 * @name:  The entity name
 *
 * called when an entity reference is detected. 
 */
void
referenceDebug(void *ctx, const xmlChar *name)
{
    fprintf(stdout, "SAX.reference(%s)\n", name);
}

/**
 * ignorableWhitespaceDebug:
 * @ctxt:  An XML parser context
 * @ch:  a xmlChar string
 * @start: the first char in the string
 * @len: the number of xmlChar
 *
 * receiving some ignorable whitespaces from the parser.
 * Question: how much at a time ???
 */
void
ignorableWhitespaceDebug(void *ctx, const xmlChar *ch, int len)
{
    fprintf(stdout, "SAX.ignorableWhitespace(%.30s, %d)\n",
            (char *) ch, len);
}

/**
 * processingInstructionDebug:
 * @ctxt:  An XML parser context
 * @target:  the target name
 * @data: the PI data's
 * @len: the number of xmlChar
 *
 * A processing instruction has been parsed.
 */
void
processingInstructionDebug(void *ctx, const xmlChar *target,
                      const xmlChar *data)
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
commentDebug(void *ctx, const xmlChar *value)
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
warningDebug(void *ctx, const char *msg, ...)
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
errorDebug(void *ctx, const char *msg, ...)
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
fatalErrorDebug(void *ctx, const char *msg, ...)
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
    getParameterEntityDebug,
};

xmlSAXHandlerPtr debugSAXHandler = &debugSAXHandlerStruct;
/************************************************************************
 *									*
 *				Debug					*
 *									*
 ************************************************************************/

void parseSAXFile(char *filename) {
    htmlDocPtr doc;
    /*
     * Empty callbacks for checking
     */
    doc = htmlSAXParseFile(filename, NULL, emptySAXHandler, NULL);
    if (doc != NULL) {
        fprintf(stdout, "htmlSAXParseFile returned non-NULL\n");
	xmlFreeDoc(doc);
    }

    if (!noout) {
	/*
	 * Debug callback
	 */
	doc = htmlSAXParseFile(filename, NULL, debugSAXHandler, NULL);
	if (doc != NULL) {
	    fprintf(stdout, "htmlSAXParseFile returned non-NULL\n");
	    xmlFreeDoc(doc);
	}
    }
}

void parseAndPrintFile(char *filename) {
    htmlDocPtr doc = NULL, tmp;

    /*
     * build an HTML tree from a string;
     */
    if (push) {
	FILE *f;

	f = fopen(filename, "r");
	if (f != NULL) {
	    int res, size = 3;
	    char chars[1024];
	    htmlParserCtxtPtr ctxt;

	    if (repeat)
		size = 1024;
	    res = fread(chars, 1, 4, f);
	    if (res > 0) {
		ctxt = htmlCreatePushParserCtxt(NULL, NULL,
			    chars, res, filename, 0);
		while ((res = fread(chars, 1, size, f)) > 0) {
		    htmlParseChunk(ctxt, chars, res, 0);
		}
		htmlParseChunk(ctxt, chars, 0, 1);
		doc = ctxt->myDoc;
		htmlFreeParserCtxt(ctxt);
	    }
	}
    } else {	
	doc = htmlParseFile(filename, NULL);
    }
    if (doc == NULL) {
        fprintf(stderr, "Could not parse %s\n", filename);
    }

    /*
     * test intermediate copy if needed.
     */
    if (copy) {
        tmp = doc;
	doc = xmlCopyDoc(doc, 1);
	xmlFreeDoc(tmp);
    }

    /*
     * print it.
     */
    if (!noout) { 
	if (!debug)
	    htmlDocDump(stdout, doc);
	else
	    xmlDebugDumpDocument(stdout, doc);
    }	

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

int main(int argc, char **argv) {
    int i, count;
    int files = 0;

    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	else if ((!strcmp(argv[i], "-copy")) || (!strcmp(argv[i], "--copy")))
	    copy++;
	else if ((!strcmp(argv[i], "-push")) || (!strcmp(argv[i], "--push")))
	    push++;
	else if ((!strcmp(argv[i], "-sax")) || (!strcmp(argv[i], "--sax")))
	    sax++;
	else if ((!strcmp(argv[i], "-noout")) || (!strcmp(argv[i], "--noout")))
	    noout++;
	else if ((!strcmp(argv[i], "-repeat")) ||
	         (!strcmp(argv[i], "--repeat")))
	    repeat++;
    }
    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
	    if (repeat) {
		for (count = 0;count < 100 * repeat;count++) {
		    if (sax)
			parseSAXFile(argv[i]);
		    else   
			parseAndPrintFile(argv[i]);
		}    
	    } else {
		if (sax)
		    parseSAXFile(argv[i]);
		else   
		    parseAndPrintFile(argv[i]);
	    }
	    files ++;
	}
    }
    if (files == 0) {
	printf("Usage : %s [--debug] [--copy] [--copy] HTMLfiles ...\n",
	       argv[0]);
	printf("\tParse the HTML files and output the result of the parsing\n");
	printf("\t--debug : dump a debug tree of the in-memory document\n");
	printf("\t--copy : used to test the internal copy implementation\n");
	printf("\t--sax : debug the sequence of SAX callbacks\n");
	printf("\t--repeat : parse the file 100 times, for timing\n");
	printf("\t--noout : do not print the result\n");
	printf("\t--push : use the push mode parser\n");
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(0);
}
