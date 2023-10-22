/*
 * testparser.c: Additional parser tests
 *
 * See Copyright for the status of this software.
 */

#include <libxml/parser.h>

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
#endif

int
main(void) {
    int err = 0;

#ifdef LIBXML_PUSH_ENABLED
    err |= testHugePush();
#endif

    return err;
}

