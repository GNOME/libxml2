/*
 * fuzz.c: Common functions for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#include <stdlib.h>
#include <string.h>
#include <libxml/hash.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>
#include "fuzz.h"

typedef struct {
    const char *data;
    size_t size;
} xmlFuzzEntityInfo;

/* Single static instance for now */
static struct {
    /* Original data */
    const char *data;
    size_t size;

    /* Remaining data */
    const char *ptr;
    size_t remaining;

    /* Buffer for unescaped strings */
    char *outBuf;
    char *outPtr; /* Free space at end of buffer */

    xmlHashTablePtr entities; /* Maps URLs to xmlFuzzEntityInfos */

    /* The first entity is the main entity. */
    const char *mainUrl;
    xmlFuzzEntityInfo *mainEntity;
} fuzzData;

/**
 * xmlFuzzErrorFunc:
 *
 * An error function that simply discards all errors.
 */
void
xmlFuzzErrorFunc(void *ctx ATTRIBUTE_UNUSED, const char *msg ATTRIBUTE_UNUSED,
                 ...) {
}

/**
 * xmlFuzzDataInit:
 *
 * Initialize fuzz data provider.
 */
void
xmlFuzzDataInit(const char *data, size_t size) {
    fuzzData.data = data;
    fuzzData.size = size;
    fuzzData.ptr = data;
    fuzzData.remaining = size;

    fuzzData.outBuf = xmlMalloc(size + 1);
    fuzzData.outPtr = fuzzData.outBuf;

    fuzzData.entities = xmlHashCreate(8);
    fuzzData.mainUrl = NULL;
    fuzzData.mainEntity = NULL;
}

static void
xmlFreeEntityEntry(void *value, const xmlChar *name) {
    xmlFree(value);
}

/**
 * xmlFuzzDataFree:
 *
 * Cleanup fuzz data provider.
 */
void
xmlFuzzDataCleanup(void) {
    xmlFree(fuzzData.outBuf);
    xmlHashFree(fuzzData.entities, xmlFreeEntityEntry);
}

/**
 * xmlFuzzReadInt:
 * @size:  size of string in bytes
 *
 * Read an integer from the fuzz data.
 */
int
xmlFuzzReadInt() {
    int ret;

    if (fuzzData.remaining < sizeof(int))
        return(0);
    memcpy(&ret, fuzzData.ptr, sizeof(int));
    fuzzData.ptr += sizeof(int);
    fuzzData.remaining -= sizeof(int);

    return ret;
}

/**
 * xmlFuzzReadRemaining:
 * @size:  size of string in bytes
 *
 * Read remaining bytes from fuzz data.
 */
const char *
xmlFuzzReadRemaining(size_t *size) {
    const char *ret = fuzzData.ptr;

    *size = fuzzData.remaining;
    fuzzData.ptr += fuzzData.remaining;
    fuzzData.remaining = 0;

    return(ret);
}

/*
 * Write a random-length string to stdout in a format similar to
 * FuzzedDataProvider. Backslash followed by newline marks the end of the
 * string. Two backslashes are used to escape a backslash.
 */
static void
xmlFuzzWriteString(const char *str) {
    for (; *str; str++) {
        int c = (unsigned char) *str;
        putchar(c);
        if (c == '\\')
            putchar(c);
    }
    putchar('\\');
    putchar('\n');
}

/**
 * xmlFuzzReadString:
 * @size:  size of string in bytes
 *
 * Read a random-length string from the fuzz data.
 *
 * The format is similar to libFuzzer's FuzzedDataProvider but treats
 * backslash followed by newline as end of string. This makes the fuzz data
 * more readable. A backslash character is escaped with another backslash.
 *
 * Returns a zero-terminated string or NULL if the fuzz data is exhausted.
 */
static const char *
xmlFuzzReadString(size_t *size) {
    const char *out = fuzzData.outPtr;

    while (fuzzData.remaining > 0) {
        int c = *fuzzData.ptr++;
        fuzzData.remaining--;

        if ((c == '\\') && (fuzzData.remaining > 0)) {
            int c2 = *fuzzData.ptr;

            if (c2 == '\n') {
                fuzzData.ptr++;
                fuzzData.remaining--;
                *size = fuzzData.outPtr - out;
                *fuzzData.outPtr++ = '\0';
                return(out);
            }
            if (c2 == '\\') {
                fuzzData.ptr++;
                fuzzData.remaining--;
            }
        }

        *fuzzData.outPtr++ = c;
    }

    if (fuzzData.outPtr > out) {
        *size = fuzzData.outPtr - out;
        *fuzzData.outPtr++ = '\0';
        return(out);
    }

    return(NULL);
}

/*
 * A custom entity loader that writes all external DTDs or entities to a
 * single file in the format expected by xmlFuzzEntityLoader.
 */
xmlParserInputPtr
xmlFuzzEntityRecorder(const char *URL, const char *ID,
                      xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr in;
    static const int chunkSize = 16384;
    int len;

    in = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
    if (in == NULL)
        return(NULL);

    if (fuzzData.entities == NULL) {
        fuzzData.entities = xmlHashCreate(4);
    } else if (xmlHashLookup(fuzzData.entities,
                             (const xmlChar *) URL) != NULL) {
        return(in);
    }

    do {
        len = xmlParserInputBufferGrow(in->buf, chunkSize);
        if (len < 0) {
            fprintf(stderr, "Error reading %s\n", URL);
            xmlFreeInputStream(in);
            return(NULL);
        }
    } while (len > 0);

    xmlFuzzWriteString(URL);
    xmlFuzzWriteString((char *) xmlBufContent(in->buf->buffer));

    xmlFreeInputStream(in);

    xmlHashAddEntry(fuzzData.entities, (const xmlChar *) URL, NULL);

    return(xmlNoNetExternalEntityLoader(URL, ID, ctxt));
}

/**
 * xmlFuzzReadEntities:
 *
 * Read entities like the main XML file, external DTDs, external parsed
 * entities from fuzz data.
 */
void
xmlFuzzReadEntities(void) {
    size_t num = 0;

    while (1) {
        const char *url, *entity;
        size_t urlSize, entitySize;
        xmlFuzzEntityInfo *entityInfo;
        
        url = xmlFuzzReadString(&urlSize);
        if (url == NULL) break;

        entity = xmlFuzzReadString(&entitySize);
        if (entity == NULL) break;

        if (xmlHashLookup(fuzzData.entities, (xmlChar *)url) == NULL) {
            entityInfo = xmlMalloc(sizeof(xmlFuzzEntityInfo));
            entityInfo->data = entity;
            entityInfo->size = entitySize;

            xmlHashAddEntry(fuzzData.entities, (xmlChar *)url, entityInfo);

            if (num == 0) {
                fuzzData.mainUrl = url;
                fuzzData.mainEntity = entityInfo;
            }

            num++;
        }
    }
}

/**
 * xmlFuzzMainUrl:
 *
 * Returns the main URL.
 */
const char *
xmlFuzzMainUrl(void) {
    return(fuzzData.mainUrl);
}

/**
 * xmlFuzzMainEntity:
 * @size:  size of the main entity in bytes
 *
 * Returns the main entity.
 */
const char *
xmlFuzzMainEntity(size_t *size) {
    if (fuzzData.mainEntity == NULL)
        return(NULL);
    *size = fuzzData.mainEntity->size;
    return(fuzzData.mainEntity->data);
}

/**
 * xmlFuzzEntityLoader:
 *
 * The entity loader for fuzz data.
 */
xmlParserInputPtr
xmlFuzzEntityLoader(const char *URL, const char *ID ATTRIBUTE_UNUSED,
                    xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr input;
    xmlFuzzEntityInfo *entity;

    if (URL == NULL)
        return(NULL);
    entity = xmlHashLookup(fuzzData.entities, (xmlChar *) URL);
    if (entity == NULL)
        return(NULL);

    input = xmlNewInputStream(ctxt);
    input->filename = NULL;
    input->buf = xmlParserInputBufferCreateMem(entity->data, entity->size,
                                               XML_CHAR_ENCODING_NONE);
    input->base = input->cur = xmlBufContent(input->buf->buffer);
    input->end = input->base + entity->size;

    return input;
}

/**
 * xmlFuzzExtractStrings:
 *
 * Extract C strings from input data. Use exact-size allocations to detect
 * potential memory errors.
 */
size_t
xmlFuzzExtractStrings(const char *data, size_t size, char **strings,
                      size_t numStrings) {
    const char *start = data;
    const char *end = data + size;
    size_t i = 0, ret;

    while (i < numStrings) {
        size_t strSize = end - start;
        const char *zero = memchr(start, 0, strSize);

        if (zero != NULL)
            strSize = zero - start;

        strings[i] = xmlMalloc(strSize + 1);
        memcpy(strings[i], start, strSize);
        strings[i][strSize] = '\0';

        i++;
        if (zero != NULL)
            start = zero + 1;
        else
            break;
    }

    ret = i;

    while (i < numStrings) {
        strings[i] = NULL;
        i++;
    }

    return(ret);
}

