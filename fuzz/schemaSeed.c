/*
 * xmlSeed.c: Generate the XML seed corpus for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#include <stdio.h>
#include <libxml/xmlschemas.h>
#include "fuzz.h"

int
main(int argc, char **argv) {
    xmlSchemaPtr schema;
    xmlSchemaParserCtxtPtr pctxt;

    if (argc != 2) {
        fprintf(stderr, "Usage: schemaSeed [XSD]\n");
        return(1);
    }

    xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
    xmlSetExternalEntityLoader(xmlFuzzEntityRecorder);

    pctxt = xmlSchemaNewParserCtxt(argv[1]);
    xmlSchemaSetParserErrors(pctxt, xmlFuzzErrorFunc, xmlFuzzErrorFunc, NULL);
    schema = xmlSchemaParse(pctxt);
    xmlSchemaFreeParserCtxt(pctxt);

    xmlSchemaFree(schema);
    xmlFuzzDataCleanup();

    return(0);
}

