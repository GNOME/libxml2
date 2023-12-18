/*
 * testparser.c: Additional parser tests
 *
 * See Copyright for the status of this software.
 */

#include <libxml/parser.h>
#include <libxml/xmlreader.h>

#include <string.h>

#ifdef LIBXML_PUSH_ENABLED
static int
testHugePush(void) {
    xmlParserCtxtPtr ctxt;
    int err, i;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);

    /*
     * Push parse a document larger than XML_MAX_LOOKUP_LIMIT
     * (10,000,000 bytes). This mainly tests whether shrinking the
     * buffer works when push parsing.
     */
    xmlParseChunk(ctxt, "<doc>", 5, 0);
    for (i = 0; i < 1000000; i++)
        xmlParseChunk(ctxt, "<elem>text</elem>", 17, 0);
    xmlParseChunk(ctxt, "</doc>", 6, 1);

    err = ctxt->wellFormed ? 0 : 1;
    xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);

    return err;
}

static int
testHugeEncodedChunk(void) {
    xmlBufferPtr buf;
    xmlChar *chunk;
    xmlParserCtxtPtr ctxt;
    int err, i;

    /*
     * Test the push parser with a built-in encoding handler like ISO-8859-1
     * and a chunk larger than the initial decoded buffer (currently 4 KB).
     */
    buf = xmlBufferCreate();
    xmlBufferCat(buf,
            BAD_CAST "<?xml version='1.0' encoding='ISO-8859-1'?>\n");
    xmlBufferCat(buf, BAD_CAST "<doc><!-- ");
    for (i = 0; i < 2000; i++)
        xmlBufferCat(buf, BAD_CAST "0123456789");
    xmlBufferCat(buf, BAD_CAST " --></doc>");
    chunk = xmlBufferDetach(buf);
    xmlBufferFree(buf);

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);

    xmlParseChunk(ctxt, (char *) chunk, xmlStrlen(chunk), 0);
    xmlParseChunk(ctxt, NULL, 0, 1);

    err = ctxt->wellFormed ? 0 : 1;
    xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
    xmlFree(chunk);

    return err;
}
#endif

#if defined(LIBXML_READER_ENABLED) && defined(LIBXML_XINCLUDE_ENABLED)
typedef struct {
    char *message;
    int code;
} testReaderErrorCtxt;

static void
testReaderError(void *arg, const char *msg,
                xmlParserSeverities severity ATTRIBUTE_UNUSED,
                xmlTextReaderLocatorPtr locator ATTRIBUTE_UNUSED) {
    testReaderErrorCtxt *ctxt = arg;

    if (ctxt->message != NULL)
        xmlFree(ctxt->message);
    ctxt->message = xmlMemStrdup(msg);
}

static void
testStructuredReaderError(void *arg, const xmlError *error) {
    testReaderErrorCtxt *ctxt = arg;

    if (ctxt->message != NULL)
        xmlFree(ctxt->message);
    ctxt->message = xmlMemStrdup(error->message);
    ctxt->code = error->code;
}

static int
testReaderXIncludeError(void) {
    /*
     * Test whether XInclude errors are reported to the custom error
     * handler of a reader.
     */
    const char *doc =
        "<doc xmlns:xi='http://www.w3.org/2001/XInclude'>\n"
        "  <xi:include/>\n"
        "</doc>\n";
    xmlTextReader *reader;
    testReaderErrorCtxt errorCtxt;
    int err = 0;

    reader = xmlReaderForDoc(BAD_CAST doc, NULL, NULL, XML_PARSE_XINCLUDE);
    xmlTextReaderSetErrorHandler(reader, testReaderError, &errorCtxt);
    errorCtxt.message = NULL;
    errorCtxt.code = 0;
    while (xmlTextReaderRead(reader) > 0)
        ;

    if (errorCtxt.message == NULL ||
        strstr(errorCtxt.message, "failed") == NULL) {
        fprintf(stderr, "xmlTextReaderSetErrorHandler failed\n");
        err = 1;
    }

    xmlFree(errorCtxt.message);
    xmlFreeTextReader(reader);

    reader = xmlReaderForDoc(BAD_CAST doc, NULL, NULL, XML_PARSE_XINCLUDE);
    xmlTextReaderSetStructuredErrorHandler(reader, testStructuredReaderError,
                                           &errorCtxt);
    errorCtxt.message = NULL;
    errorCtxt.code = 0;
    while (xmlTextReaderRead(reader) > 0)
        ;

    if (errorCtxt.code != XML_XINCLUDE_HREF_URI ||
        errorCtxt.message == NULL ||
        strstr(errorCtxt.message, "failed") == NULL) {
        fprintf(stderr, "xmlTextReaderSetStructuredErrorHandler failed\n");
        err = 1;
    }

    xmlFree(errorCtxt.message);
    xmlFreeTextReader(reader);

    return err;
}
#endif

int
main(void) {
    int err = 0;

#ifdef LIBXML_PUSH_ENABLED
    err |= testHugePush();
    err |= testHugeEncodedChunk();
#endif
#if defined(LIBXML_READER_ENABLED) && defined(LIBXML_XINCLUDE_ENABLED)
    err |= testReaderXIncludeError();
#endif

    return err;
}

