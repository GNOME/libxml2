/*
 * xpathSeed.c: Generate the XPath and XPointer seed corpus for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#include <glob.h>
#include <libgen.h>
#include <stdio.h>
#include <sys/stat.h>
#include "fuzz.h"

#define PATH_SIZE 256
#define EXPR_SIZE 4500

typedef struct  {
    const char *name;
    const char *prefix;
    char *data;
    int counter;
} xpathTestXml;

static int
processXml(const char *testDir, xpathTestXml *xml, const char *subdir,
           int xptr);

int
main(int argc, char **argv) {
    xpathTestXml xml;
    char pattern[PATH_SIZE];
    glob_t globbuf;
    size_t i, size;
    int ret = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: xpathSeed [TESTDIR]\n");
        return(1);
    }

    xml.name = "expr";
    xml.prefix = "";
    xml.data = "<d></d>";
    xml.counter = 1;
    if (processXml(argv[1], &xml, "expr", 0) != 0)
        ret = 1;

    size = snprintf(pattern, sizeof(pattern), "%s/docs/*", argv[1]);
    if (size >= PATH_SIZE)
        return(1);
    if (glob(pattern, 0, NULL, &globbuf) != 0)
        return(1);

    for (i = 0; i < globbuf.gl_pathc; i++) {
        char *path = globbuf.gl_pathv[i];
        FILE *xmlFile;
        struct stat statbuf;

        if ((stat(path, &statbuf) != 0) || (!S_ISREG(statbuf.st_mode)))
            continue;
        size = statbuf.st_size;
        xmlFile = fopen(path, "rb");
        if (xmlFile == NULL) {
            ret = 1;
            continue;
        }
        xml.data = xmlMalloc(size + 1);
        if (xml.data == NULL) {
            ret = 1;
            goto close;
        }
        if (fread(xml.data, 1, size, xmlFile) != size) {
            ret = 1;
            goto free;
        }
        xml.data[size] = 0;
        xml.name = basename(path);
        xml.prefix = xml.name;
        xml.counter = 1;

        if (processXml(argv[1], &xml, "tests", 0) != 0)
            ret = 1;
        if (processXml(argv[1], &xml, "xptr", 1) != 0)
            ret = 1;

free:
        xmlFree(xml.data);
close:
        fclose(xmlFile);
    }

    globfree(&globbuf);

    return(ret);
}

static int
processXml(const char *testDir, xpathTestXml *xml, const char *subdir,
           int xptr) {
    char pattern[PATH_SIZE];
    glob_t globbuf;
    size_t i, size;
    int ret = 0;

    size = snprintf(pattern, sizeof(pattern), "%s/%s/%s*",
                    testDir, subdir, xml->prefix);
    if (size >= PATH_SIZE)
        return(-1);
    if (glob(pattern, 0, NULL, &globbuf) != 0)
        return(-1);

    for (i = 0; i < globbuf.gl_pathc; i++) {
        char *path = globbuf.gl_pathv[i];
        struct stat statbuf;
        FILE *in;
        char expr[EXPR_SIZE];

        if ((stat(path, &statbuf) != 0) || (!S_ISREG(statbuf.st_mode)))
            continue;

        printf("## Processing %s\n", path);
        in = fopen(path, "rb");
        if (in == NULL) {
            ret = -1;
            continue;
        }

        while (fgets(expr, EXPR_SIZE, in) > 0) {
            char outPath[PATH_SIZE];
            FILE *out;
            int j;

            for (j = 0; expr[j] != 0; j++)
                if (expr[j] == '\r' || expr[j] == '\n')
                    break;
            expr[j] = 0;

            size = snprintf(outPath, sizeof(outPath), "seed/xpath/%s-%d",
                            xml->name, xml->counter);
            if (size >= PATH_SIZE) {
                ret = -1;
                continue;
            }
            out = fopen(outPath, "wb");
            if (out == NULL) {
                ret = -1;
                continue;
            }

            if (xptr) {
                xmlFuzzWriteString(out, expr);
            } else {
                char xptrExpr[EXPR_SIZE+100];

                snprintf(xptrExpr, sizeof(xptrExpr), "xpointer(%s)", expr);
                xmlFuzzWriteString(out, xptrExpr);
            }

            xmlFuzzWriteString(out, xml->data);

            fclose(out);
            xml->counter++;
        }

        fclose(in);
    }

    globfree(&globbuf);

    return(ret);
}

