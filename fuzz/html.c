/*
 * html.c: a libFuzzer target to test several HTML parser interfaces.
 *
 * See Copyright for the status of this software.
 */

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/catalog.h>
#include "fuzz.h"

int
LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
                     char ***argv ATTRIBUTE_UNUSED) {
    xmlFuzzMemSetup();
    xmlInitParser();
#ifdef LIBXML_CATALOG_ENABLED
    xmlInitializeCatalog();
    xmlCatalogSetDefaults(XML_CATA_ALLOW_NONE);
#endif

    return 0;
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {
    xmlParserCtxtPtr ctxt;
    htmlDocPtr doc;
    const char *docBuffer;
    size_t failurePos, docSize;
    int opts;

    xmlFuzzDataInit(data, size);
    opts = (int) xmlFuzzReadInt(4);
    failurePos = xmlFuzzReadInt(4) % (size + 100);

    docBuffer = xmlFuzzReadRemaining(&docSize);
    if (docBuffer == NULL) {
        xmlFuzzDataCleanup();
        return(0);
    }

    /* Pull parser */

    xmlFuzzInjectFailure(failurePos);
    ctxt = htmlNewParserCtxt();
    if (ctxt != NULL) {
        xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
        doc = htmlCtxtReadMemory(ctxt, docBuffer, docSize, NULL, NULL, opts);
        xmlFuzzCheckFailureReport("htmlCtxtReadMemory",
                                  ctxt->errNo == XML_ERR_NO_MEMORY,
                                  ctxt->errNo == XML_IO_EIO);

        if (doc != NULL) {
            xmlDocPtr copy;

#ifdef LIBXML_OUTPUT_ENABLED
            xmlOutputBufferPtr out;
            const xmlChar *content;

            /*
             * Also test the serializer. Call htmlDocContentDumpOutput with our
             * own buffer to avoid encoding the output. The HTML encoding is
             * excruciatingly slow (see htmlEntityValueLookup).
             */
            out = xmlAllocOutputBuffer(NULL);
            htmlDocContentDumpOutput(out, doc, NULL);
            content = xmlOutputBufferGetContent(out);
            xmlOutputBufferClose(out);
            xmlFuzzCheckFailureReport("htmlDocContentDumpOutput",
                                      content == NULL, 0);
#endif

            copy = xmlCopyDoc(doc, 1);
            xmlFuzzCheckFailureReport("xmlCopyNode", copy == NULL, 0);
            xmlFreeDoc(copy);

            xmlFreeDoc(doc);
        }

        htmlFreeParserCtxt(ctxt);
    }


    /* Push parser */

#ifdef LIBXML_PUSH_ENABLED
    {
        static const size_t maxChunkSize = 128;
        size_t consumed, chunkSize;

        xmlFuzzInjectFailure(failurePos);
        ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL,
                                        XML_CHAR_ENCODING_NONE);

        if (ctxt != NULL) {
            xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
            htmlCtxtUseOptions(ctxt, opts);

            for (consumed = 0; consumed < docSize; consumed += chunkSize) {
                chunkSize = docSize - consumed;
                if (chunkSize > maxChunkSize)
                    chunkSize = maxChunkSize;
                htmlParseChunk(ctxt, docBuffer + consumed, chunkSize, 0);
            }

            htmlParseChunk(ctxt, NULL, 0, 1);
            xmlFuzzCheckFailureReport("htmlParseChunk",
                                      ctxt->errNo == XML_ERR_NO_MEMORY,
                                      ctxt->errNo == XML_IO_EIO);
            xmlFreeDoc(ctxt->myDoc);
            htmlFreeParserCtxt(ctxt);
        }
    }
#endif

    /* Cleanup */

    xmlFuzzInjectFailure(0);
    xmlFuzzDataCleanup();
    xmlResetLastError();

    return(0);
}

