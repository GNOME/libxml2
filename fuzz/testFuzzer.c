/*
 * testFuzzer.c: Test program for the custom entity loader used to fuzz
 * with multiple inputs.
 *
 * See Copyright for the status of this software.
 */

#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>
#include "fuzz.h"

int
main() {
    static const char data[] =
        "doc.xml\\\n"
        "<!DOCTYPE doc SYSTEM \"doc.dtd\">\n"
        "<doc>&ent;</doc>\\\n"
        "doc.dtd\\\n"
        "<!ELEMENT doc (#PCDATA)>\n"
        "<!ENTITY ent SYSTEM \"ent.txt\">\\\n"
        "ent.txt\\\n"
        "Hello, world!\\\n";
    static xmlChar expected[] =
        "<?xml version=\"1.0\"?>\n"
        "<!DOCTYPE doc SYSTEM \"doc.dtd\">\n"
        "<doc>Hello, world!</doc>\n";
    const char *docBuffer;
    size_t docSize;
    xmlDocPtr doc;
    xmlChar *out;
    int ret = 0;

    xmlSetExternalEntityLoader(xmlFuzzEntityLoader);

    xmlFuzzDataInit(data, sizeof(data) - 1);
    xmlFuzzReadEntities();
    docBuffer = xmlFuzzMainEntity(&docSize);
    doc = xmlReadMemory(docBuffer, docSize, NULL, NULL,
                        XML_PARSE_NOENT | XML_PARSE_DTDLOAD);

    xmlDocDumpMemory(doc, &out, NULL);
    if (xmlStrcmp(out, expected) != 0) {
        fprintf(stderr, "Expected:\n%sGot:\n%s", expected, out);
        ret = 1;
    }

    xmlFree(out);
    xmlFreeDoc(doc);
    xmlFuzzDataCleanup();

    return(ret);
}

