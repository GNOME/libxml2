/*
 * valid.c: a libFuzzer target to test DTD validation.
 *
 * See Copyright for the status of this software.
 */

#include <libxml/catalog.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
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
    xmlDocPtr doc;
    const char *docBuffer, *docUrl;
    size_t maxAlloc, docSize;
    int opts;

    xmlFuzzDataInit(data, size);
    opts = (int) xmlFuzzReadInt(4);
    opts &= ~XML_PARSE_XINCLUDE;
    opts |= XML_PARSE_DTDVALID;
    maxAlloc = xmlFuzzReadInt(4) % (size + 100);

    xmlFuzzReadEntities();
    docBuffer = xmlFuzzMainEntity(&docSize);
    docUrl = xmlFuzzMainUrl();
    if (docBuffer == NULL)
        goto exit;

    /* Pull parser */

    xmlFuzzMemSetLimit(maxAlloc);
    ctxt = xmlNewParserCtxt();
    if (ctxt != NULL) {
        xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
        xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
        doc = xmlCtxtReadMemory(ctxt, docBuffer, docSize, docUrl, NULL, opts);
        xmlFuzzCheckMallocFailure("xmlCtxtReadMemory",
                                  ctxt->errNo == XML_ERR_NO_MEMORY);
        xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
    }

    /* Post validation */

    xmlFuzzMemSetLimit(maxAlloc);
    ctxt = xmlNewParserCtxt();
    if (ctxt != NULL) {
        xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
        xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
        doc = xmlCtxtReadMemory(ctxt, docBuffer, docSize, docUrl, NULL,
                                opts & ~XML_PARSE_DTDVALID);
        xmlFuzzCheckMallocFailure("xmlCtxtReadMemory",
                                  ctxt->errNo == XML_ERR_NO_MEMORY);
        if (doc != NULL) {
            xmlCtxtValidateDocument(ctxt, doc);
            xmlFuzzCheckMallocFailure("xmlCtxtValidateDocument",
                                      ctxt->errNo == XML_ERR_NO_MEMORY);
        }
        xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
    }

    /* Push parser */

#ifdef LIBXML_PUSH_ENABLED
    {
        static const size_t maxChunkSize = 128;
        size_t consumed, chunkSize;

        xmlFuzzMemSetLimit(maxAlloc);
        /*
         * FIXME: xmlCreatePushParserCtxt can still report OOM errors
         * to stderr.
         */
        xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, docUrl);
        xmlSetGenericErrorFunc(NULL, NULL);
        if (ctxt != NULL) {
            xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
            xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
            xmlCtxtUseOptions(ctxt, opts);

            for (consumed = 0; consumed < docSize; consumed += chunkSize) {
                chunkSize = docSize - consumed;
                if (chunkSize > maxChunkSize)
                    chunkSize = maxChunkSize;
                xmlParseChunk(ctxt, docBuffer + consumed, chunkSize, 0);
            }

            xmlParseChunk(ctxt, NULL, 0, 1);
            xmlFuzzCheckMallocFailure("xmlParseChunk",
                                      ctxt->errNo == XML_ERR_NO_MEMORY);
            xmlFreeDoc(ctxt->myDoc);
            xmlFreeParserCtxt(ctxt);
        }
    }
#endif

exit:
    xmlFuzzMemSetLimit(0);
    xmlFuzzDataCleanup();
    xmlResetLastError();
    return(0);
}

