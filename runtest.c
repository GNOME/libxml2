/*
 * runtest.c: C program to run libxml2 regression tests without
 *            requiring make or Python, and reducing platform dependancies
 *            to a strict minimum.
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/uri.h>
#ifdef LIBXML_READER_ENABLED
#include <libxml/xmlreader.h>
#endif

#ifdef LIBXML_XINCLUDE_ENABLED
#include <libxml/xinclude.h>
#endif

#ifdef LIBXML_XPATH_ENABLED
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#ifdef LIBXML_XPTR_ENABLED
#include <libxml/xpointer.h>
#endif
#endif

#ifdef LIBXML_HTML_ENABLED
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

/*
 * pseudo flag for the unification of HTML and XML tests
 */
#define XML_PARSE_HTML 1 << 24
#endif

typedef int (*functest) (const char *filename, const char *result,
                         const char *error, int options);

typedef struct testDesc testDesc;
typedef testDesc *testDescPtr;
struct testDesc {
    const char *desc; /* descripton of the test */
    functest    func; /* function implementing the test */
    const char *in;   /* glob to path for input files */
    const char *out;  /* output directory */
    const char *suffix;/* suffix for output files */
    const char *err;  /* suffix for error output files */
    int     options;  /* parser options for the test */
};

static int checkTestFile(const char *filename);
/************************************************************************
 *									*
 *		Libxml2 specific routines				*
 *									*
 ************************************************************************/

static long libxmlMemoryAllocatedBase = 0;
static int extraMemoryFromResolver = 0;

static int
fatalError(void) {
    fprintf(stderr, "Exitting tests on fatal error\n");
    exit(1);
}

/*
 * We need to trap calls to the resolver to not account memory for the catalog
 * which is shared to the current running test. We also don't want to have
 * network downloads modifying tests.
 */
static xmlParserInputPtr 
testExternalEntityLoader(const char *URL, const char *ID,
			 xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr ret;

    if (checkTestFile(URL)) {
	ret = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
    } else {
	int memused = xmlMemUsed();
	ret = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
	extraMemoryFromResolver += xmlMemUsed() - memused;
    }
      
    return(ret);
}

/*
 * Trapping the error messages at the generic level to grab the equivalent of
 * stderr messages on CLI tools.
 */
static char testErrors[32769];
static int testErrorsSize = 0;

static void
testErrorHandler(void *ctx  ATTRIBUTE_UNUSED, const char *msg, ...) {
    va_list args;
    int res;

    if (testErrorsSize >= 32768)
        return;
    va_start(args, msg);
    res = vsnprintf(&testErrors[testErrorsSize],
                    32768 - testErrorsSize,
		    msg, args);
    va_end(args);
    if (testErrorsSize + res >= 32768) {
        /* buffer is full */
	testErrorsSize = 32768;
	testErrors[testErrorsSize] = 0;
    } else {
        testErrorsSize += res;
    }
    testErrors[testErrorsSize] = 0;
}

static void
initializeLibxml2(void) {
    xmlGetWarningsDefaultValue = 0;
    xmlPedanticParserDefault(0);

    xmlMemSetup(xmlMemFree, xmlMemMalloc, xmlMemRealloc, xmlMemoryStrdup);
    xmlInitParser();
    xmlSetExternalEntityLoader(testExternalEntityLoader);
    xmlSetGenericErrorFunc(NULL, testErrorHandler);
    libxmlMemoryAllocatedBase = xmlMemUsed();
}


/************************************************************************
 *									*
 *		File name and path utilities				*
 *									*
 ************************************************************************/

static const char *baseFilename(const char *filename) {
    const char *cur;
    if (filename == NULL)
        return(NULL);
    cur = &filename[strlen(filename)];
    while ((cur > filename) && (*cur != '/'))
        cur--;
    if (*cur == '/')
        return(cur + 1);
    return(cur);
}

static char *resultFilename(const char *filename, const char *out,
                            const char *suffix) {
    const char *base;
    char res[500];

/*************
    if ((filename[0] == 't') && (filename[1] == 'e') &&
        (filename[2] == 's') && (filename[3] == 't') &&
	(filename[4] == '/'))
	filename = &filename[5];
 *************/
    
    base = baseFilename(filename);
    if (suffix == NULL)
        suffix = ".tmp";
    if (out == NULL)
        out = "";
    snprintf(res, 499, "%s%s%s", out, base, suffix);
    res[499] = 0;
    return(strdup(res));
}

static int checkTestFile(const char *filename) {
    struct stat buf;

    if (stat(filename, &buf) == -1)
        return(0);

    if (!S_ISREG(buf.st_mode))
        return(0);

    return(1);
}

static int compareFiles(const char *r1, const char *r2) {
    int res1, res2;
    int fd1, fd2;
    char bytes1[4096];
    char bytes2[4096];

    fd1 = open(r1, O_RDONLY);
    if (fd1 < 0)
        return(-1);
    fd2 = open(r2, O_RDONLY);
    if (fd2 < 0) {
        close(fd1);
        return(-1);
    }
    while (1) {
        res1 = read(fd1, bytes1, 4096);
        res2 = read(fd2, bytes2, 4096);
	if (res1 != res2) {
	    close(fd1);
	    close(fd2);
	    return(1);
	}
	if (res1 == 0)
	    break;
	if (memcmp(bytes1, bytes2, res1) != 0) {
	    close(fd1);
	    close(fd2);
	    return(1);
	}
    }
    close(fd1);
    close(fd2);
    return(0);
}

static int compareFileMem(const char *filename, const char *mem, int size) {
    int res;
    int fd;
    char bytes[4096];
    int idx = 0;
    struct stat info;

    if (stat(filename, &info) < 0) 
	return(-1);
    if (info.st_size != size)
        return(-1);
    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return(-1);
    while (idx < size) {
        res = read(fd, bytes, 4096);
	if (res <= 0)
	    break;
	if (res + idx > size) 
	    break;
	if (memcmp(bytes, &mem[idx], res) != 0) {
	    close(fd);
	    return(1);
	}
	idx += res;
    }
    close(fd);
    return(idx != size);
}

static int loadMem(const char *filename, const char **mem, int *size) {
    int fd, res;
    struct stat info;
    char *base;
    int siz = 0;
    if (stat(filename, &info) < 0) 
	return(-1);
    base = malloc(info.st_size + 1);
    if (base == NULL)
	return(-1);
    if ((fd = open(filename, O_RDONLY)) < 0) {
        free(base);
	return(-1);
    }
    while ((res = read(fd, &base[siz], info.st_size - siz)) > 0) {
        siz += res;
    }
    close(fd);
    if (siz != info.st_size) {
        free(base);
	return(-1);
    }
    base[siz] = 0;
    *mem = base;
    *size = siz;
    return(0);
}

static int unloadMem(const char *mem) {
    free((char *)mem);
    return(0);
}

/************************************************************************
 *									*
 *		Tests implementations					*
 *									*
 ************************************************************************/

/************************************************************************
 *									*
 *		Parse to SAX based tests				*
 *									*
 ************************************************************************/

FILE *SAXdebug = NULL;

/*
 * empty SAX block
 */
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
    NULL, /* cdataBlock; */
    NULL, /* externalSubset; */
    1,
    NULL,
    NULL, /* startElementNs */
    NULL, /* endElementNs */
    NULL  /* xmlStructuredErrorFunc */
};

static xmlSAXHandlerPtr emptySAXHandler = &emptySAXHandlerStruct;
int callbacks = 0;
int quiet = 0;

/**
 * isStandaloneDebug:
 * @ctxt:  An XML parser context
 *
 * Is this document tagged standalone ?
 *
 * Returns 1 if true
 */
static int
isStandaloneDebug(void *ctx ATTRIBUTE_UNUSED)
{
    callbacks++;
    if (quiet)
	return(0);
    fprintf(SAXdebug, "SAX.isStandalone()\n");
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
static int
hasInternalSubsetDebug(void *ctx ATTRIBUTE_UNUSED)
{
    callbacks++;
    if (quiet)
	return(0);
    fprintf(SAXdebug, "SAX.hasInternalSubset()\n");
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
static int
hasExternalSubsetDebug(void *ctx ATTRIBUTE_UNUSED)
{
    callbacks++;
    if (quiet)
	return(0);
    fprintf(SAXdebug, "SAX.hasExternalSubset()\n");
    return(0);
}

/**
 * internalSubsetDebug:
 * @ctxt:  An XML parser context
 *
 * Does this document has an internal subset
 */
static void
internalSubsetDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
	       const xmlChar *ExternalID, const xmlChar *SystemID)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.internalSubset(%s,", name);
    if (ExternalID == NULL)
	fprintf(SAXdebug, " ,");
    else
	fprintf(SAXdebug, " %s,", ExternalID);
    if (SystemID == NULL)
	fprintf(SAXdebug, " )\n");
    else
	fprintf(SAXdebug, " %s)\n", SystemID);
}

/**
 * externalSubsetDebug:
 * @ctxt:  An XML parser context
 *
 * Does this document has an external subset
 */
static void
externalSubsetDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
	       const xmlChar *ExternalID, const xmlChar *SystemID)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.externalSubset(%s,", name);
    if (ExternalID == NULL)
	fprintf(SAXdebug, " ,");
    else
	fprintf(SAXdebug, " %s,", ExternalID);
    if (SystemID == NULL)
	fprintf(SAXdebug, " )\n");
    else
	fprintf(SAXdebug, " %s)\n", SystemID);
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
static xmlParserInputPtr
resolveEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *publicId, const xmlChar *systemId)
{
    callbacks++;
    if (quiet)
	return(NULL);
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */

    
    fprintf(SAXdebug, "SAX.resolveEntity(");
    if (publicId != NULL)
	fprintf(SAXdebug, "%s", (char *)publicId);
    else
	fprintf(SAXdebug, " ");
    if (systemId != NULL)
	fprintf(SAXdebug, ", %s)\n", (char *)systemId);
    else
	fprintf(SAXdebug, ", )\n");
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
static xmlEntityPtr
getEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
{
    callbacks++;
    if (quiet)
	return(NULL);
    fprintf(SAXdebug, "SAX.getEntity(%s)\n", name);
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
static xmlEntityPtr
getParameterEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
{
    callbacks++;
    if (quiet)
	return(NULL);
    fprintf(SAXdebug, "SAX.getParameterEntity(%s)\n", name);
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
static void
entityDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, int type,
          const xmlChar *publicId, const xmlChar *systemId, xmlChar *content)
{
const xmlChar *nullstr = BAD_CAST "(null)";
    /* not all libraries handle printing null pointers nicely */
    if (publicId == NULL)
        publicId = nullstr;
    if (systemId == NULL)
        systemId = nullstr;
    if (content == NULL)
        content = (xmlChar *)nullstr;
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.entityDecl(%s, %d, %s, %s, %s)\n",
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
static void
attributeDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar * elem,
                   const xmlChar * name, int type, int def,
                   const xmlChar * defaultValue, xmlEnumerationPtr tree)
{
    callbacks++;
    if (quiet)
        return;
    if (defaultValue == NULL)
        fprintf(SAXdebug, "SAX.attributeDecl(%s, %s, %d, %d, NULL, ...)\n",
                elem, name, type, def);
    else
        fprintf(SAXdebug, "SAX.attributeDecl(%s, %s, %d, %d, %s, ...)\n",
                elem, name, type, def, defaultValue);
    xmlFreeEnumeration(tree);
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
static void
elementDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, int type,
	    xmlElementContentPtr content ATTRIBUTE_UNUSED)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.elementDecl(%s, %d, ...)\n",
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
static void
notationDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
	     const xmlChar *publicId, const xmlChar *systemId)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.notationDecl(%s, %s, %s)\n",
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
static void
unparsedEntityDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
		   const xmlChar *publicId, const xmlChar *systemId,
		   const xmlChar *notationName)
{
const xmlChar *nullstr = BAD_CAST "(null)";

    if (publicId == NULL)
        publicId = nullstr;
    if (systemId == NULL)
        systemId = nullstr;
    if (notationName == NULL)
        notationName = nullstr;
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.unparsedEntityDecl(%s, %s, %s, %s)\n",
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
static void
setDocumentLocatorDebug(void *ctx ATTRIBUTE_UNUSED, xmlSAXLocatorPtr loc ATTRIBUTE_UNUSED)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.setDocumentLocator()\n");
}

/**
 * startDocumentDebug:
 * @ctxt:  An XML parser context
 *
 * called when the document start being processed.
 */
static void
startDocumentDebug(void *ctx ATTRIBUTE_UNUSED)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.startDocument()\n");
}

/**
 * endDocumentDebug:
 * @ctxt:  An XML parser context
 *
 * called when the document end has been detected.
 */
static void
endDocumentDebug(void *ctx ATTRIBUTE_UNUSED)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.endDocument()\n");
}

/**
 * startElementDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 */
static void
startElementDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, const xmlChar **atts)
{
    int i;

    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.startElement(%s", (char *) name);
    if (atts != NULL) {
        for (i = 0;(atts[i] != NULL);i++) {
	    fprintf(SAXdebug, ", %s='", atts[i++]);
	    if (atts[i] != NULL)
	        fprintf(SAXdebug, "%s'", atts[i]);
	}
    }
    fprintf(SAXdebug, ")\n");
}

/**
 * endElementDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
static void
endElementDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.endElement(%s)\n", (char *) name);
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
static void
charactersDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
{
    char output[40];
    int i;

    callbacks++;
    if (quiet)
	return;
    for (i = 0;(i<len) && (i < 30);i++)
	output[i] = ch[i];
    output[i] = 0;

    fprintf(SAXdebug, "SAX.characters(%s, %d)\n", output, len);
}

/**
 * referenceDebug:
 * @ctxt:  An XML parser context
 * @name:  The entity name
 *
 * called when an entity reference is detected. 
 */
static void
referenceDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.reference(%s)\n", name);
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
static void
ignorableWhitespaceDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
{
    char output[40];
    int i;

    callbacks++;
    if (quiet)
	return;
    for (i = 0;(i<len) && (i < 30);i++)
	output[i] = ch[i];
    output[i] = 0;
    fprintf(SAXdebug, "SAX.ignorableWhitespace(%s, %d)\n", output, len);
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
static void
processingInstructionDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *target,
                      const xmlChar *data)
{
    callbacks++;
    if (quiet)
	return;
    if (data != NULL)
	fprintf(SAXdebug, "SAX.processingInstruction(%s, %s)\n",
		(char *) target, (char *) data);
    else
	fprintf(SAXdebug, "SAX.processingInstruction(%s, NULL)\n",
		(char *) target);
}

/**
 * cdataBlockDebug:
 * @ctx: the user data (XML parser context)
 * @value:  The pcdata content
 * @len:  the block length
 *
 * called when a pcdata block has been parsed
 */
static void
cdataBlockDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value, int len)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.pcdata(%.20s, %d)\n",
	    (char *) value, len);
}

/**
 * commentDebug:
 * @ctxt:  An XML parser context
 * @value:  the comment content
 *
 * A comment has been parsed.
 */
static void
commentDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.comment(%s)\n", value);
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
static void
warningDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
{
    va_list args;

    callbacks++;
    if (quiet)
	return;
    va_start(args, msg);
    fprintf(SAXdebug, "SAX.warning: ");
    vfprintf(SAXdebug, msg, args);
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
static void
errorDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
{
    va_list args;

    callbacks++;
    if (quiet)
	return;
    va_start(args, msg);
    fprintf(SAXdebug, "SAX.error: ");
    vfprintf(SAXdebug, msg, args);
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
static void
fatalErrorDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
{
    va_list args;

    callbacks++;
    if (quiet)
	return;
    va_start(args, msg);
    fprintf(SAXdebug, "SAX.fatalError: ");
    vfprintf(SAXdebug, msg, args);
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
    cdataBlockDebug,
    externalSubsetDebug,
    1,
    NULL,
    NULL,
    NULL,
    NULL
};

xmlSAXHandlerPtr debugSAXHandler = &debugSAXHandlerStruct;

/*
 * SAX2 specific callbacks
 */
/**
 * startElementNsDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 */
static void
startElementNsDebug(void *ctx ATTRIBUTE_UNUSED,
                    const xmlChar *localname,
                    const xmlChar *prefix,
                    const xmlChar *URI,
		    int nb_namespaces,
		    const xmlChar **namespaces,
		    int nb_attributes,
		    int nb_defaulted,
		    const xmlChar **attributes)
{
    int i;

    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.startElementNs(%s", (char *) localname);
    if (prefix == NULL)
	fprintf(SAXdebug, ", NULL");
    else
	fprintf(SAXdebug, ", %s", (char *) prefix);
    if (URI == NULL)
	fprintf(SAXdebug, ", NULL");
    else
	fprintf(SAXdebug, ", '%s'", (char *) URI);
    fprintf(SAXdebug, ", %d", nb_namespaces);
    
    if (namespaces != NULL) {
        for (i = 0;i < nb_namespaces * 2;i++) {
	    fprintf(SAXdebug, ", xmlns");
	    if (namespaces[i] != NULL)
	        fprintf(SAXdebug, ":%s", namespaces[i]);
	    i++;
	    fprintf(SAXdebug, "='%s'", namespaces[i]);
	}
    }
    fprintf(SAXdebug, ", %d, %d", nb_attributes, nb_defaulted);
    if (attributes != NULL) {
        for (i = 0;i < nb_attributes * 5;i += 5) {
	    if (attributes[i + 1] != NULL)
		fprintf(SAXdebug, ", %s:%s='", attributes[i + 1], attributes[i]);
	    else
		fprintf(SAXdebug, ", %s='", attributes[i]);
	    fprintf(SAXdebug, "%.4s...', %d", attributes[i + 3],
		    (int)(attributes[i + 4] - attributes[i + 3]));
	}
    }
    fprintf(SAXdebug, ")\n");
}

/**
 * endElementDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
static void
endElementNsDebug(void *ctx ATTRIBUTE_UNUSED,
                  const xmlChar *localname,
                  const xmlChar *prefix,
                  const xmlChar *URI)
{
    callbacks++;
    if (quiet)
	return;
    fprintf(SAXdebug, "SAX.endElementNs(%s", (char *) localname);
    if (prefix == NULL)
	fprintf(SAXdebug, ", NULL");
    else
	fprintf(SAXdebug, ", %s", (char *) prefix);
    if (URI == NULL)
	fprintf(SAXdebug, ", NULL)\n");
    else
	fprintf(SAXdebug, ", '%s')\n", (char *) URI);
}

xmlSAXHandler debugSAX2HandlerStruct = {
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
    NULL,
    NULL,
    referenceDebug,
    charactersDebug,
    ignorableWhitespaceDebug,
    processingInstructionDebug,
    commentDebug,
    warningDebug,
    errorDebug,
    fatalErrorDebug,
    getParameterEntityDebug,
    cdataBlockDebug,
    externalSubsetDebug,
    XML_SAX2_MAGIC,
    NULL,
    startElementNsDebug,
    endElementNsDebug,
    NULL
};

xmlSAXHandlerPtr debugSAX2Handler = &debugSAX2HandlerStruct;

/**
 * htmlstartElementDebug:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 */
static void
htmlstartElementDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, const xmlChar **atts)
{
    int i;

    fprintf(SAXdebug, "SAX.startElement(%s", (char *) name);
    if (atts != NULL) {
        for (i = 0;(atts[i] != NULL);i++) {
	    fprintf(SAXdebug, ", %s", atts[i++]);
	    if (atts[i] != NULL) {
		unsigned char output[40];
		const unsigned char *att = atts[i];
		int outlen, attlen;
	        fprintf(SAXdebug, "='");
		while ((attlen = strlen((char*)att)) > 0) {
		    outlen = sizeof output - 1;
		    htmlEncodeEntities(output, &outlen, att, &attlen, '\'');
		    output[outlen] = 0;
		    fprintf(SAXdebug, "%s", (char *) output);
		    att += attlen;
		}
		fprintf(SAXdebug, "'");
	    }
	}
    }
    fprintf(SAXdebug, ")\n");
}

/**
 * htmlcharactersDebug:
 * @ctxt:  An XML parser context
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
static void
htmlcharactersDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
{
    unsigned char output[40];
    int inlen = len, outlen = 30;

    htmlEncodeEntities(output, &outlen, ch, &inlen, 0);
    output[outlen] = 0;

    fprintf(SAXdebug, "SAX.characters(%s, %d)\n", output, len);
}

/**
 * htmlcdataDebug:
 * @ctxt:  An XML parser context
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some cdata chars from the parser.
 * Question: how much at a time ???
 */
static void
htmlcdataDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
{
    unsigned char output[40];
    int inlen = len, outlen = 30;

    htmlEncodeEntities(output, &outlen, ch, &inlen, 0);
    output[outlen] = 0;

    fprintf(SAXdebug, "SAX.cdata(%s, %d)\n", output, len);
}

xmlSAXHandler debugHTMLSAXHandlerStruct = {
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
    htmlstartElementDebug,
    endElementDebug,
    referenceDebug,
    htmlcharactersDebug,
    ignorableWhitespaceDebug,
    processingInstructionDebug,
    commentDebug,
    warningDebug,
    errorDebug,
    fatalErrorDebug,
    getParameterEntityDebug,
    htmlcdataDebug,
    externalSubsetDebug,
    1,
    NULL,
    NULL,
    NULL,
    NULL
};

xmlSAXHandlerPtr debugHTMLSAXHandler = &debugHTMLSAXHandlerStruct;
/**
 * saxParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the SAX API and check for errors.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
saxParseTest(const char *filename, const char *result,
             const char *err ATTRIBUTE_UNUSED,
             int options) {
    int ret;
    char *temp;

    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "out of memory\n");
        fatalError();
    }
    SAXdebug = fopen(temp, "w");
    if (SAXdebug == NULL) {
        fprintf(stderr, "Failed to write to %s\n", temp);
	free(temp);
	return(-1);
    }

#ifdef LIBXML_HTML_ENABLED
    if (options & XML_PARSE_HTML) {
	htmlSAXParseFile(filename, NULL, emptySAXHandler, NULL);
	ret = 0;
    } else
#endif
    ret = xmlSAXUserParseFile(emptySAXHandler, NULL, filename);
    if (ret == XML_WAR_UNDECLARED_ENTITY) {
        fprintf(SAXdebug, "xmlSAXUserParseFile returned error %d\n", ret);
        ret = 0;
    }
    if (ret != 0) {
        fprintf(stderr, "Failed to parse %s\n", filename);
	return(1);
    }
#ifdef LIBXML_HTML_ENABLED
    if (options & XML_PARSE_HTML) {
	htmlSAXParseFile(filename, NULL, debugHTMLSAXHandler, NULL);
	ret = 0;
    } else
#endif
    if (options & XML_PARSE_SAX1) {
	ret = xmlSAXUserParseFile(debugSAXHandler, NULL, filename);
    } else {
	ret = xmlSAXUserParseFile(debugSAX2Handler, NULL, filename);
    }
    if (ret == XML_WAR_UNDECLARED_ENTITY) {
        fprintf(SAXdebug, "xmlSAXUserParseFile returned error %d\n", ret);
        ret = 0;
    }
    fclose(SAXdebug);
    if (compareFiles(temp, result)) {
        ret = 1;
    }
    unlink(temp);
    free(temp);
    
    return(ret);
}

/************************************************************************
 *									*
 *		Parse to tree based tests				*
 *									*
 ************************************************************************/
/**
 * oldParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages: unused
 *
 * Parse a file using the old xmlParseFile API, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
oldParseTest(const char *filename, const char *result,
             const char *err ATTRIBUTE_UNUSED,
	     int options ATTRIBUTE_UNUSED) {
    xmlDocPtr doc;
    char *temp;
    int res = 0;

    /*
     * base of the test, parse with the old API
     */
    doc = xmlParseFile(filename);
    if (doc == NULL)
        return(1);
    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "out of memory\n");
        fatalError();
    }
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    /*
     * Parse the saved result to make sure the round trip is okay
     */
    doc = xmlParseFile(temp);
    if (doc == NULL)
        return(1);
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    unlink(temp);
    free(temp);
    return(res);
}

#ifdef LIBXML_PUSH_ENABLED
/**
 * pushParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages: unused
 *
 * Parse a file using the Push API, then serialize back
 * to check for content.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
pushParseTest(const char *filename, const char *result,
             const char *err ATTRIBUTE_UNUSED,
	     int options) {
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;
    const char *base;
    int size, res;
    int cur = 0;

    /*
     * load the document in memory and work from there.
     */
    if (loadMem(filename, &base, &size) != 0) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }
    
#ifdef LIBXML_HTML_ENABLED
    if (options & XML_PARSE_HTML)
	ctxt = htmlCreatePushParserCtxt(NULL, NULL, base + cur, 4, filename,
	                                XML_CHAR_ENCODING_NONE);
    else
#endif
    ctxt = xmlCreatePushParserCtxt(NULL, NULL, base + cur, 4, filename);
    xmlCtxtUseOptions(ctxt, options);
    cur += 4;
    while (cur < size) {
        if (cur + 1024 >= size) {
#ifdef LIBXML_HTML_ENABLED
	    if (options & XML_PARSE_HTML)
		htmlParseChunk(ctxt, base + cur, size - cur, 1);
	    else
#endif
	    xmlParseChunk(ctxt, base + cur, size - cur, 1);
	    break;
	} else {
#ifdef LIBXML_HTML_ENABLED
	    if (options & XML_PARSE_HTML)
		htmlParseChunk(ctxt, base + cur, 1024, 0);
	    else
#endif
	    xmlParseChunk(ctxt, base + cur, 1024, 0);
	    cur += 1024;
	}
    }
    doc = ctxt->myDoc;
#ifdef LIBXML_HTML_ENABLED
    if (options & XML_PARSE_HTML)
        res = 1;
    else
#endif
    res = ctxt->wellFormed;
    xmlFreeParserCtxt(ctxt);
    free((char *)base);
    if (!res) {
	xmlFreeDoc(doc);
	fprintf(stderr, "Failed to parse %s\n", filename);
	return(-1);
    }
#ifdef LIBXML_HTML_ENABLED
    if (options & XML_PARSE_HTML)
	htmlDocDumpMemory(doc, (xmlChar **) &base, &size);
    else
#endif
    xmlDocDumpMemory(doc, (xmlChar **) &base, &size);
    xmlFreeDoc(doc);
    res = compareFileMem(result, base, size);
    if ((base == NULL) || (res != 0)) {
	if (base != NULL)
	    xmlFree((char *)base);
        fprintf(stderr, "Result for %s failed\n", filename);
	return(-1);
    }
    xmlFree((char *)base);
    if (err != NULL) {
	res = compareFileMem(err, testErrors, testErrorsSize);
	if (res != 0) {
	    fprintf(stderr, "Error for %s failed\n", filename);
	    return(-1);
	}
    }
    return(0);
}
#endif

/**
 * memParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages: unused
 *
 * Parse a file using the old xmlReadMemory API, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
memParseTest(const char *filename, const char *result,
             const char *err ATTRIBUTE_UNUSED,
	     int options ATTRIBUTE_UNUSED) {
    xmlDocPtr doc;
    const char *base;
    int size, res;

    /*
     * load and parse the memory
     */
    if (loadMem(filename, &base, &size) != 0) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }
    
    doc = xmlReadMemory(base, size, filename, NULL, 0);
    unloadMem(base);
    if (doc == NULL) {
        return(1);
    }
    xmlDocDumpMemory(doc, (xmlChar **) &base, &size);
    xmlFreeDoc(doc);
    res = compareFileMem(result, base, size);
    if ((base == NULL) || (res != 0)) {
	if (base != NULL)
	    xmlFree((char *)base);
        fprintf(stderr, "Result for %s failed\n", filename);
	return(-1);
    }
    xmlFree((char *)base);
    return(0);
}

/**
 * noentParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages: unused
 *
 * Parse a file with entity resolution, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
noentParseTest(const char *filename, const char *result,
               const char *err  ATTRIBUTE_UNUSED,
	       int options) {
    xmlDocPtr doc;
    char *temp;
    int res = 0;

    /*
     * base of the test, parse with the old API
     */
    doc = xmlReadFile(filename, NULL, options);
    if (doc == NULL)
        return(1);
    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "Out of memory\n");
        fatalError();
    }
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    /*
     * Parse the saved result to make sure the round trip is okay
     */
    doc = xmlReadFile(filename, NULL, options);
    if (doc == NULL)
        return(1);
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    unlink(temp);
    free(temp);
    return(res);
}

/**
 * errParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the xmlReadFile API and check for errors.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
errParseTest(const char *filename, const char *result, const char *err,
             int options) {
    xmlDocPtr doc;
    const char *base = NULL;
    int size, res = 0;

#ifdef LIBXML_HTML_ENABLED
    if (options & XML_PARSE_HTML) {
        doc = htmlReadFile(filename, NULL, options);
    } else
#endif
#ifdef LIBXML_XINCLUDE_ENABLED
    if (options & XML_PARSE_XINCLUDE) {
	doc = xmlReadFile(filename, NULL, options);
	xmlXIncludeProcessFlags(doc, options);
    } else
#endif
    {
	xmlGetWarningsDefaultValue = 1;
	doc = xmlReadFile(filename, NULL, options);
    }
    xmlGetWarningsDefaultValue = 0;
    if (result) {
	if (doc == NULL) {
	    base = "";
	    size = 0;
	} else {
#ifdef LIBXML_HTML_ENABLED
	    if (options & XML_PARSE_HTML) {
		htmlDocDumpMemory(doc, (xmlChar **) &base, &size);
	    } else
#endif
	    xmlDocDumpMemory(doc, (xmlChar **) &base, &size);
	}
	res = compareFileMem(result, base, size);
    }
    if (doc != NULL) {
	if (base != NULL)
	    xmlFree((char *)base);
	xmlFreeDoc(doc);
    }
    if (res != 0) {
        fprintf(stderr, "Result for %s failed\n", filename);
	return(-1);
    }
    if (err != NULL) {
	res = compareFileMem(err, testErrors, testErrorsSize);
	if (res != 0) {
	    fprintf(stderr, "Error for %s failed\n", filename);
	    return(-1);
	}
    } else if (options & XML_PARSE_DTDVALID) {
        if (testErrorsSize != 0)
	    fprintf(stderr, "Validation for %s failed\n", filename);
    }

    return(0);
}

#ifdef LIBXML_READER_ENABLED
/************************************************************************
 *									*
 *		Reader based tests					*
 *									*
 ************************************************************************/

static void processNode(FILE *out, xmlTextReaderPtr reader) {
    const xmlChar *name, *value;
    int type, empty;

    type = xmlTextReaderNodeType(reader);
    empty = xmlTextReaderIsEmptyElement(reader);

    name = xmlTextReaderConstName(reader);
    if (name == NULL)
	name = BAD_CAST "--";

    value = xmlTextReaderConstValue(reader);

    
    fprintf(out, "%d %d %s %d %d", 
	    xmlTextReaderDepth(reader),
	    type,
	    name,
	    empty,
	    xmlTextReaderHasValue(reader));
    if (value == NULL)
	fprintf(out, "\n");
    else {
	fprintf(out, " %s\n", value);
    }
#if 0
#ifdef LIBXML_PATTERN_ENABLED
    if (patternc) {
        xmlChar *path = NULL;
        int match = -1;
	
	if (type == XML_READER_TYPE_ELEMENT) {
	    /* do the check only on element start */
	    match = xmlPatternMatch(patternc, xmlTextReaderCurrentNode(reader));

	    if (match) {
		path = xmlGetNodePath(xmlTextReaderCurrentNode(reader));
		fprintf(out, "Node %s matches pattern %s\n", path, pattern);
	    }
	}
	if (patstream != NULL) {
	    int ret;

	    if (type == XML_READER_TYPE_ELEMENT) {
		ret = xmlStreamPush(patstream,
		                    xmlTextReaderConstLocalName(reader),
				    xmlTextReaderConstNamespaceUri(reader));
		if (ret < 0) {
		    fprintf(stderr, "xmlStreamPush() failure\n");
                    xmlFreeStreamCtxt(patstream);
		    patstream = NULL;
		} else if (ret != match) {
		    if (path == NULL) {
		        path = xmlGetNodePath(
		                       xmlTextReaderCurrentNode(reader));
		    }
		    fprintf(stderr,
		            "xmlPatternMatch and xmlStreamPush disagree\n");
		    fprintf(stderr,
		            "  pattern %s node %s\n",
			    pattern, path);
		}
		

	    } 
	    if ((type == XML_READER_TYPE_END_ELEMENT) ||
	        ((type == XML_READER_TYPE_ELEMENT) && (empty))) {
	        ret = xmlStreamPop(patstream);
		if (ret < 0) {
		    fprintf(stderr, "xmlStreamPop() failure\n");
                    xmlFreeStreamCtxt(patstream);
		    patstream = NULL;
		}
	    }
	}
	if (path != NULL)
	    xmlFree(path);
    }
#endif
#endif
}
static int
streamProcessTest(const char *filename, const char *result, const char *err,
                  xmlTextReaderPtr reader) {
    int ret;
    char *temp = NULL;
    FILE *t = NULL;

    if (reader == NULL)
        return(-1);

    if (result != NULL) {
	temp = resultFilename(filename, "", ".res");
	if (temp == NULL) {
	    fprintf(stderr, "Out of memory\n");
	    fatalError();
	}
	t = fopen(temp, "w");
	if (t == NULL) {
	    fprintf(stderr, "Can't open temp file %s\n", temp);
	    free(temp);
	    return(-1);
	}
    }
    xmlGetWarningsDefaultValue = 1;
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
	if (t != NULL)
	    processNode(t, reader);
        ret = xmlTextReaderRead(reader);
    }
    if (ret != 0) {
        testErrorHandler(NULL, "%s : failed to parse\n", filename);
    }
    xmlGetWarningsDefaultValue = 0;
    if (t != NULL) {
        fclose(t);
	ret = compareFiles(temp, result);
	unlink(temp);
	free(temp);
	if (ret) {
	    fprintf(stderr, "Result for %s failed\n", filename);
	    return(-1);
	}
    }
    if (err != NULL) {
	ret = compareFileMem(err, testErrors, testErrorsSize);
	if (ret != 0) {
	    fprintf(stderr, "Error for %s failed\n", filename);
	    return(-1);
	}
    }

    return(0);
}

/**
 * streamParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the reader API and check for errors.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
streamParseTest(const char *filename, const char *result, const char *err,
                int options) {
    xmlTextReaderPtr reader;
    int ret;

    reader = xmlReaderForFile(filename, NULL, options);
    ret = streamProcessTest(filename, result, err, reader);
    xmlFreeTextReader(reader);
    return(ret);
}

/**
 * walkerParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the walker, i.e. a reader built from a atree.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
walkerParseTest(const char *filename, const char *result, const char *err,
                int options) {
    xmlDocPtr doc;
    xmlTextReaderPtr reader;
    int ret;

    doc = xmlReadFile(filename, NULL, options);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", filename);
	return(-1);
    }
    reader = xmlReaderWalker(doc);
    ret = streamProcessTest(filename, result, err, reader);
    xmlFreeTextReader(reader);
    xmlFreeDoc(doc);
    return(ret);
}

/**
 * streamMemParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the reader API from memory and check for errors.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
streamMemParseTest(const char *filename, const char *result, const char *err,
                   int options) {
    xmlTextReaderPtr reader;
    int ret;
    const char *base;
    int size;

    /*
     * load and parse the memory
     */
    if (loadMem(filename, &base, &size) != 0) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }
    reader = xmlReaderForMemory(base, size, filename, NULL, options);
    ret = streamProcessTest(filename, result, err, reader);
    free((char *)base);
    xmlFreeTextReader(reader);
    return(ret);
}
#endif

#ifdef LIBXML_XPATH_ENABLED
/************************************************************************
 *									*
 *		XPath and XPointer based tests				*
 *									*
 ************************************************************************/

FILE *xpathOutput;
xmlDocPtr xpathDocument;

static void
testXPath(const char *str, int xptr, int expr) {
    xmlXPathObjectPtr res;
    xmlXPathContextPtr ctxt;
    
#if defined(LIBXML_XPTR_ENABLED)
    if (xptr) {
	ctxt = xmlXPtrNewContext(xpathDocument, NULL, NULL);
	res = xmlXPtrEval(BAD_CAST str, ctxt);
    } else {
#endif
	ctxt = xmlXPathNewContext(xpathDocument);
	ctxt->node = xmlDocGetRootElement(xpathDocument);
	if (expr)
	    res = xmlXPathEvalExpression(BAD_CAST str, ctxt);
	else {
	    /* res = xmlXPathEval(BAD_CAST str, ctxt); */
	    xmlXPathCompExprPtr comp;

	    comp = xmlXPathCompile(BAD_CAST str);
	    if (comp != NULL) {
		res = xmlXPathCompiledEval(comp, ctxt);
		xmlXPathFreeCompExpr(comp);
	    } else
		res = NULL;
	}
#if defined(LIBXML_XPTR_ENABLED)
    }
#endif
    xmlXPathDebugDumpObject(xpathOutput, res, 0);
    xmlXPathFreeObject(res);
    xmlXPathFreeContext(ctxt);
}

/**
 * xpathExprTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing XPath standalone expressions and evaluate them
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
xpathCommonTest(const char *filename, const char *result,
                int xptr, int expr) {
    FILE *input;
    char expression[5000];
    int len, ret = 0;
    char *temp;

    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "Out of memory\n");
        fatalError();
    }
    xpathOutput = fopen(temp, "w");
    if (xpathOutput == NULL) {
	fprintf(stderr, "failed to open output file %s\n", temp);
        free(temp);
	return(-1);
    }

    input = fopen(filename, "r");
    if (input == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"Cannot open %s for reading\n", filename);
        free(temp);
	return(-1);
    }
    while (fgets(expression, 4500, input) != NULL) {
	len = strlen(expression);
	len--;
	while ((len >= 0) && 
	       ((expression[len] == '\n') || (expression[len] == '\t') ||
		(expression[len] == '\r') || (expression[len] == ' '))) len--;
	expression[len + 1] = 0;      
	if (len >= 0) {
	    fprintf(xpathOutput,
	            "\n========================\nExpression: %s\n",
		    expression) ;
	    testXPath(expression, xptr, expr);
	}
    }

    fclose(input);
    fclose(xpathOutput);
    if (result != NULL) {
	ret = compareFiles(temp, result);
	if (ret) {
	    fprintf(stderr, "Result for %s failed\n", filename);
	}
    }

    unlink(temp);
    free(temp);
    return(ret);
}

/**
 * xpathExprTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing XPath standalone expressions and evaluate them
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
xpathExprTest(const char *filename, const char *result,
              const char *err ATTRIBUTE_UNUSED,
              int options ATTRIBUTE_UNUSED) {
    return(xpathCommonTest(filename, result, 0, 1));
}

/**
 * xpathDocTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing XPath expressions and evaluate them against
 * a set of corresponding documents.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
xpathDocTest(const char *filename,
             const char *resul ATTRIBUTE_UNUSED,
             const char *err ATTRIBUTE_UNUSED,
             int options) {

    char pattern[500];
    char result[500];
    glob_t globbuf;
    size_t i;
    int ret = 0, res;

    xpathDocument = xmlReadFile(filename, NULL,
                                options | XML_PARSE_DTDATTR | XML_PARSE_NOENT);
    if (xpathDocument == NULL) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }

    snprintf(pattern, 499, "./test/XPath/tests/%s*", baseFilename(filename));
    pattern[499] = 0;
    globbuf.gl_offs = 0;
    glob(pattern, GLOB_DOOFFS, NULL, &globbuf);
    for (i = 0;i < globbuf.gl_pathc;i++) {
        snprintf(result, 499, "result/XPath/tests/%s",
	         baseFilename(globbuf.gl_pathv[i]));
	res = xpathCommonTest(globbuf.gl_pathv[i], &result[0], 0, 0);
	if (res != 0)
	    ret = res;
    }
    globfree(&globbuf);

    xmlFreeDoc(xpathDocument);
    return(ret);
}

#ifdef LIBXML_XPTR_ENABLED
/**
 * xptrDocTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing XPath expressions and evaluate them against
 * a set of corresponding documents.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
xptrDocTest(const char *filename,
            const char *resul ATTRIBUTE_UNUSED,
            const char *err ATTRIBUTE_UNUSED,
            int options) {

    char pattern[500];
    char result[500];
    glob_t globbuf;
    size_t i;
    int ret = 0, res;

    xpathDocument = xmlReadFile(filename, NULL,
                                options | XML_PARSE_DTDATTR | XML_PARSE_NOENT);
    if (xpathDocument == NULL) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }

    snprintf(pattern, 499, "./test/XPath/xptr/%s*", baseFilename(filename));
    pattern[499] = 0;
    globbuf.gl_offs = 0;
    glob(pattern, GLOB_DOOFFS, NULL, &globbuf);
    for (i = 0;i < globbuf.gl_pathc;i++) {
        snprintf(result, 499, "result/XPath/xptr/%s",
	         baseFilename(globbuf.gl_pathv[i]));
	res = xpathCommonTest(globbuf.gl_pathv[i], &result[0], 1, 0);
	if (res != 0)
	    ret = res;
    }
    globfree(&globbuf);

    xmlFreeDoc(xpathDocument);
    return(ret);
}
#endif /* LIBXML_XPTR_ENABLED */

/**
 * xmlidDocTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing xml:id and check for errors and verify
 * that XPath queries will work on them as expected.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
xmlidDocTest(const char *filename,
             const char *result,
             const char *err,
             int options) {

    int res = 0;
    int ret = 0;
    char *temp;

    xpathDocument = xmlReadFile(filename, NULL,
                                options | XML_PARSE_DTDATTR | XML_PARSE_NOENT);
    if (xpathDocument == NULL) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }

    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "Out of memory\n");
        fatalError();
    }
    xpathOutput = fopen(temp, "w");
    if (xpathOutput == NULL) {
	fprintf(stderr, "failed to open output file %s\n", temp);
        xmlFreeDoc(xpathDocument);
        free(temp);
	return(-1);
    }

    testXPath("id('bar')", 0, 0);

    fclose(xpathOutput);
    if (result != NULL) {
	ret = compareFiles(temp, result);
	if (ret) {
	    fprintf(stderr, "Result for %s failed\n", filename);
	    res = 1;
	}
    }

    unlink(temp);
    free(temp);
    xmlFreeDoc(xpathDocument);

    if (err != NULL) {
	ret = compareFileMem(err, testErrors, testErrorsSize);
	if (ret != 0) {
	    fprintf(stderr, "Error for %s failed\n", filename);
	    res = 1;
	}
    }
    return(res);
}

#endif /* XPATH */
/************************************************************************
 *									*
 *			URI based tests					*
 *									*
 ************************************************************************/

static void
handleURI(const char *str, const char *base, FILE *o) {
    int ret;
    xmlURIPtr uri;
    xmlChar *res = NULL, *parsed = NULL;

    uri = xmlCreateURI();

    if (base == NULL) {
	ret = xmlParseURIReference(uri, str);
	if (ret != 0)
	    fprintf(o, "%s : error %d\n", str, ret);
	else {
	    xmlNormalizeURIPath(uri->path);
	    xmlPrintURI(o, uri);
	    fprintf(o, "\n");
	}
    } else {
	res = xmlBuildURI((xmlChar *)str, (xmlChar *) base);
	if (res != NULL) {
	    fprintf(o, "%s\n", (char *) res);
	}
	else
	    fprintf(o, "::ERROR::\n");
    }
    if (res != NULL)
	xmlFree(res);
    if (parsed != NULL)
	xmlFree(parsed);
    xmlFreeURI(uri);
}

/**
 * uriCommonTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing URI and check for errors
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
uriCommonTest(const char *filename,
             const char *result,
             const char *err,
             const char *base) {
    char *temp;
    FILE *o, *f;
    char str[1024];
    int res = 0, i, ret;

    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "Out of memory\n");
        fatalError();
    }
    o = fopen(temp, "w");
    if (o == NULL) {
	fprintf(stderr, "failed to open output file %s\n", temp);
        free(temp);
	return(-1);
    }
    f = fopen(filename, "r");
    if (f == NULL) {
	fprintf(stderr, "failed to open input file %s\n", filename);
	fclose(o);
	unlink(temp);
        free(temp);
	return(-1);
    }

    while (1) {
	/*
	 * read one line in string buffer.
	 */
	if (fgets (&str[0], sizeof (str) - 1, f) == NULL)
	   break;

	/*
	 * remove the ending spaces
	 */
	i = strlen(str);
	while ((i > 0) &&
	       ((str[i - 1] == '\n') || (str[i - 1] == '\r') ||
		(str[i - 1] == ' ') || (str[i - 1] == '\t'))) {
	    i--;
	    str[i] = 0;
	}
	handleURI(str, base, o);
    }

    fclose(f);
    fclose(o);

    if (result != NULL) {
	ret = compareFiles(temp, result);
	if (ret) {
	    fprintf(stderr, "Result for %s failed\n", filename);
	    res = 1;
	}
    }
    if (err != NULL) {
	ret = compareFileMem(err, testErrors, testErrorsSize);
	if (ret != 0) {
	    fprintf(stderr, "Error for %s failed\n", filename);
	    res = 1;
	}
    }

    unlink(temp);
    free(temp);
    return(res);
}

/**
 * uriParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing URI and check for errors
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
uriParseTest(const char *filename,
             const char *result,
             const char *err,
             int options ATTRIBUTE_UNUSED) {
    return(uriCommonTest(filename, result, err, NULL));
}

/**
 * uriBaseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file containing URI, compose them against a fixed base and
 * check for errors
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
uriBaseTest(const char *filename,
             const char *result,
             const char *err,
             int options ATTRIBUTE_UNUSED) {
    return(uriCommonTest(filename, result, err,
                         "http://foo.com/path/to/index.html?orig#help"));
}

/************************************************************************
 *									*
 *			Tests Descriptions				*
 *									*
 ************************************************************************/

static
testDesc testDescriptions[] = {
    { "XML regression tests" ,
      oldParseTest, "./test/*", "result/", "", NULL,
      0 },
    { "XML regression tests on memory" ,
      memParseTest, "./test/*", "result/", "", NULL,
      0 },
    { "XML entity subst regression tests" ,
      noentParseTest, "./test/*", "result/noent/", "", NULL,
      XML_PARSE_NOENT },
    { "XML Namespaces regression tests",
      errParseTest, "./test/namespaces/*", "result/namespaces/", "", ".err",
      0 },
    { "Error cases regression tests",
      errParseTest, "./test/errors/*.xml", "result/errors/", "", ".err",
      0 },
#ifdef LIBXML_READER_ENABLED
    { "Error cases stream regression tests",
      streamParseTest, "./test/errors/*.xml", "result/errors/", NULL, ".str",
      0 },
    { "Reader regression tests",
      streamParseTest, "./test/*", "result/", ".rdr", NULL,
      0 },
    { "Reader entities substitution regression tests",
      streamParseTest, "./test/*", "result/", ".rde", NULL,
      XML_PARSE_NOENT },
    { "Reader on memory regression tests",
      streamMemParseTest, "./test/*", "result/", ".rdr", NULL,
      0 },
    { "Walker regression tests",
      walkerParseTest, "./test/*", "result/", ".rdr", NULL,
      0 },
#endif
    { "SAX1 callbacks regression tests" ,
      saxParseTest, "./test/*", "result/", ".sax", NULL,
      XML_PARSE_SAX1 },
    { "SAX2 callbacks regression tests" ,
      saxParseTest, "./test/*", "result/", ".sax2", NULL,
      0 },
#ifdef LIBXML_PUSH_ENABLED
    { "XML push regression tests" ,
      pushParseTest, "./test/*", "result/", "", NULL,
      0 },
#endif
#ifdef LIBXML_HTML_ENABLED
    { "HTML regression tests" ,
      errParseTest, "./test/HTML/*", "result/HTML/", "", ".err",
      XML_PARSE_HTML },
#ifdef LIBXML_PUSH_ENABLED
    { "Push HTML regression tests" ,
      pushParseTest, "./test/HTML/*", "result/HTML/", "", ".err",
      XML_PARSE_HTML },
#endif
    { "HTML SAX regression tests" ,
      saxParseTest, "./test/HTML/*", "result/HTML/", ".sax", NULL,
      XML_PARSE_HTML },
#endif
#ifdef LIBXML_VALID_ENABLED
    { "Valid documents regression tests" ,
      errParseTest, "./test/VCM/*", NULL, NULL, NULL,
      XML_PARSE_DTDVALID },
    { "Validity checking regression tests" ,
      errParseTest, "./test/VC/*", "result/VC/", NULL, "",
      XML_PARSE_DTDVALID },
    { "General documents valid regression tests" ,
      errParseTest, "./test/valid/*", "result/valid/", "", ".err",
      XML_PARSE_DTDVALID },
#endif
#ifdef LIBXML_XINCLUDE_ENABLED
    { "XInclude regression tests" ,
      errParseTest, "./test/XInclude/docs/*", "result/XInclude/", "", NULL,
      /* Ignore errors at this point ".err", */
      XML_PARSE_XINCLUDE },
    { "XInclude xmlReader regression tests",
      streamParseTest, "./test/XInclude/docs/*", "result/XInclude/", ".rdr",
      /* Ignore errors at this point ".err", */
      NULL, XML_PARSE_XINCLUDE },
    { "XInclude regression tests stripping include nodes" ,
      errParseTest, "./test/XInclude/docs/*", "result/XInclude/", "", NULL,
      /* Ignore errors at this point ".err", */
      XML_PARSE_XINCLUDE | XML_PARSE_NOXINCNODE },
    { "XInclude xmlReader regression tests stripping include nodes",
      streamParseTest, "./test/XInclude/docs/*", "result/XInclude/", ".rdr",
      /* Ignore errors at this point ".err", */
      NULL, XML_PARSE_XINCLUDE | XML_PARSE_NOXINCNODE },
#endif
#ifdef LIBXML_XPATH_ENABLED
    { "XPath expressions regression tests" ,
      xpathExprTest, "./test/XPath/expr/*", "result/XPath/expr/", "", NULL,
      0 },
    { "XPath document queries regression tests" ,
      xpathDocTest, "./test/XPath/docs/*", NULL, NULL, NULL,
      0 },
#ifdef LIBXML_XPTR_ENABLED
    { "XPointer document queries regression tests" ,
      xptrDocTest, "./test/XPath/docs/*", NULL, NULL, NULL,
      0 },
#endif
    { "xml:id regression tests" ,
      xmlidDocTest, "./test/xmlid/*", "result/xmlid/", "", ".err",
      0 },
#endif
    { "URI parsing tests" ,
      uriParseTest, "./test/URI/*.uri", "result/URI/", "", NULL,
      0 },
    { "URI base composition tests" ,
      uriBaseTest, "./test/URI/*.data", "result/URI/", "", NULL,
      0 },
    {NULL, NULL, NULL, NULL, NULL, NULL, 0}
};

/************************************************************************
 *									*
 *		The main code driving the tests				*
 *									*
 ************************************************************************/

static int
launchTests(testDescPtr tst) {
    int res = 0, err = 0;
    size_t i;
    char *result;
    char *error;
    int mem, leak;

    if (tst == NULL) return(-1);
    if (tst->in != NULL) {
	glob_t globbuf;

	globbuf.gl_offs = 0;
	glob(tst->in, GLOB_DOOFFS, NULL, &globbuf);
	for (i = 0;i < globbuf.gl_pathc;i++) {
	    if (!checkTestFile(globbuf.gl_pathv[i]))
	        continue;
	    if (tst->suffix != NULL) {
		result = resultFilename(globbuf.gl_pathv[i], tst->out,
					tst->suffix);
		if (result == NULL) {
		    fprintf(stderr, "Out of memory !\n");
		    fatalError();
		}
	    } else {
	        result = NULL;
	    }
	    if (tst->err != NULL) {
		error = resultFilename(globbuf.gl_pathv[i], tst->out,
		                        tst->err);
		if (error == NULL) {
		    fprintf(stderr, "Out of memory !\n");
		    fatalError();
		}
	    } else {
	        error = NULL;
	    }
	    if ((result) &&(!checkTestFile(result))) {
	        fprintf(stderr, "Missing result file %s\n", result);
	    } else if ((error) &&(!checkTestFile(error))) {
	        fprintf(stderr, "Missing error file %s\n", error);
	    } else {
		mem = xmlMemUsed();
		extraMemoryFromResolver = 0;
		testErrorsSize = 0;
		testErrors[0] = 0;
		res = tst->func(globbuf.gl_pathv[i], result, error,
		                tst->options);
		xmlResetLastError();
		if (res != 0) {
		    fprintf(stderr, "File %s generated an error\n",
		            globbuf.gl_pathv[i]);
		    err++;
		}
		else if (xmlMemUsed() != mem) {
		    if ((xmlMemUsed() != mem) &&
		        (extraMemoryFromResolver == 0)) {
			fprintf(stderr, "File %s leaked %d bytes\n",
				globbuf.gl_pathv[i], xmlMemUsed() - mem);
			leak++;
			err++;
		    }
		}
		testErrorsSize = 0;
	    }
	    if (result)
		free(result);
	    if (error)
		free(error);
	}
	globfree(&globbuf);
    } else {
        testErrorsSize = 0;
	testErrors[0] = 0;
	extraMemoryFromResolver = 0;
        res = tst->func(NULL, NULL, NULL, tst->options);
	if (res != 0)
	    err++;
    }
    return(err);
}

int
main(int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED) {
    int i = 0, res, ret = 0;

    initializeLibxml2();

    for (i = 0; testDescriptions[i].func != NULL; i++) {
        if (testDescriptions[i].desc != NULL)
	    printf("## %s\n", testDescriptions[i].desc);
	res = launchTests(&testDescriptions[i]);
	if (res != 0)
	    ret++;
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(ret);
}
