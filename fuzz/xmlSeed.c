/*
 * xmlSeed.c: Generate the XML seed corpus for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#include <stdio.h>
#include "fuzz.h"

int
main(int argc, char **argv) {
    int opts = XML_PARSE_NOENT | XML_PARSE_DTDLOAD;

    if (argc != 2) {
        fprintf(stderr, "Usage: xmlSeed [FILE]\n");
    }

    fwrite(&opts, sizeof(opts), 1, stdout);

    xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
    xmlSetExternalEntityLoader(xmlFuzzEntityRecorder);
    xmlFreeDoc(xmlReadFile(argv[1], NULL, opts));
    xmlFuzzDataCleanup();

    return(0);
}

