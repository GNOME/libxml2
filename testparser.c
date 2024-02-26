/*
 * testparser.c: Additional parser tests
 *
 * See Copyright for the status of this software.
 */

#include <libxml/parser.h>
#include <libxml/HTMLparser.h>

static int
testStandaloneWithEncoding(void) {
    xmlDocPtr doc;
    const char *str =
        "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
        "<doc></doc>\n";
    int err = 0;

    xmlResetLastError();

    doc = xmlReadDoc(BAD_CAST str, NULL, "UTF-8", 0);
    if (doc == NULL) {
        fprintf(stderr, "xmlReadDoc failed\n");
        err = 1;
    }
    xmlFreeDoc(doc);

    return err;
}

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

#if defined(LIBXML_HTML_ENABLED) && defined(LIBXML_PUSH_ENABLED)
static int
testHtmlPushWithEncoding(void) {
    htmlParserCtxtPtr ctxt;
    htmlDocPtr doc;
    htmlNodePtr node;
    int err = 0;

    ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL,
                                    XML_CHAR_ENCODING_UTF8);
    htmlParseChunk(ctxt, "-\xC3\xA4-", 4, 1);

    doc = ctxt->myDoc;
    if (!xmlStrEqual(doc->encoding, BAD_CAST "UTF-8")) {
        fprintf(stderr, "testHtmlPushWithEncoding failed\n");
        err = 1;
    }

    node = xmlDocGetRootElement(doc)->children->children->children;
    if (!xmlStrEqual(node->content, BAD_CAST "-\xC3\xA4-")) {
        fprintf(stderr, "testHtmlPushWithEncoding failed\n");
        err = 1;
    }

    xmlFreeDoc(doc);
    htmlFreeParserCtxt(ctxt);
    return err;
}
#endif

int
main(void) {
    int err = 0;

    err |= testStandaloneWithEncoding();
#ifdef LIBXML_PUSH_ENABLED
    err |= testHugePush();
    err |= testHugeEncodedChunk();
#endif
#if defined(LIBXML_HTML_ENABLED) && defined(LIBXML_PUSH_ENABLED)
    err |= testHtmlPushWithEncoding();
#endif

    return err;
}

