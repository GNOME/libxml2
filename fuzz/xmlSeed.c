/*
 * xmlSeed.c: Generate the XML seed corpus for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#include <stdio.h>
#include <string.h>
#include <libxml/hash.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlerror.h>
#include "fuzz.h"

static xmlHashTablePtr entities;

static void
errorFunc(void *ctx ATTRIBUTE_UNUSED, const char *msg ATTRIBUTE_UNUSED, ...) {
    /* Discard error messages. */
}

/*
 * Write a random-length string in a format similar to FuzzedDataProvider.
 * Backslash followed by newline marks the end of the string. Two
 * backslashes are used to escape a backslash.
 */
static void
writeEscaped(const char *str) {
    for (; *str; str++) {
        int c = (unsigned char) *str;
        putchar(c);
        if (c == '\\')
            putchar(c);
    }
    putchar('\\');
    putchar('\n');
}

/*
 * A custom entity loader that writes all external DTDs or entities to a
 * single file in the format expected by xmlFuzzEntityLoader.
 */
static xmlParserInputPtr
entityLoader(const char *URL, const char *ID, xmlParserCtxtPtr context) {
    xmlParserInputPtr in;
    static const int chunkSize = 16384;
    int len;

    in = xmlNoNetExternalEntityLoader(URL, ID, context);
    if (in == NULL)
        return(NULL);

    if (xmlHashLookup(entities, (const xmlChar *) URL) != NULL)
        return(in);

    do {
        len = xmlParserInputBufferGrow(in->buf, chunkSize);
        if (len < 0) {
            fprintf(stderr, "Error reading %s\n", URL);
            xmlFreeInputStream(in);
            return(NULL);
        }
    } while (len > 0);

    writeEscaped(URL);
    writeEscaped((char *) xmlBufContent(in->buf->buffer));

    xmlFreeInputStream(in);

    xmlHashAddEntry(entities, (const xmlChar *) URL, "seen");

    return(xmlNoNetExternalEntityLoader(URL, ID, context));
}

int
main(int argc, char **argv) {
    int opts = XML_PARSE_NOENT | XML_PARSE_DTDLOAD;

    if (argc != 2) {
        fprintf(stderr, "Usage: xmlSeed [FILE]\n");
    }

    fwrite(&opts, sizeof(opts), 1, stdout);

    entities = xmlHashCreate(4);
    xmlSetGenericErrorFunc(NULL, errorFunc);
    xmlSetExternalEntityLoader(entityLoader);
    xmlFreeDoc(xmlReadFile(argv[1], NULL, opts));
    xmlHashFree(entities, NULL);

    return(0);
}

