/*
 * xmlSeed.c: Generate the XML seed corpus for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#include <stdio.h>
#include <libxml/xinclude.h>
#include "fuzz.h"

int
main(int argc, char **argv) {
    int opts = XML_PARSE_NOENT | XML_PARSE_DTDLOAD;
    xmlDocPtr doc;

    if (argc != 2) {
        fprintf(stderr, "Usage: xmlSeed [FILE]\n");
        return(1);
    }

    fwrite(&opts, sizeof(opts), 1, stdout);

    xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
    xmlSetExternalEntityLoader(xmlFuzzEntityRecorder);
    doc = xmlReadFile(argv[1], NULL, opts);
    xmlXIncludeProcessFlags(doc, opts);
    xmlFreeDoc(doc);
    xmlFuzzDataCleanup();

    return(0);
}

