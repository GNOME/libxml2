/*
 * runtest.c: C program to run libxml2 regression tests without
 *            requiring make or Python, and reducing platform dependancies
 *            to a strict minimum.
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

typedef int (*functest) (const char *filename, const char *result);

typedef struct testDesc testDesc;
typedef testDesc *testDescPtr;
struct testDesc {
    const char *desc; /* descripton of the test */
    functest    func; /* function implementing the test */
    const char *in;   /* glob to path for input files */
    const char *out;  /* output directory */
    const char *suffix;/* suffix for output files */
};

static int checkTestFile(const char *filename);
/************************************************************************
 *									*
 *		Libxml2 specific routines				*
 *									*
 ************************************************************************/

static long libxmlMemoryAllocatedBase = 0;
static int extraMemoryFromResolver = 0;

static int
fatalError(void) {
    fprintf(stderr, "Exitting tests on fatal error\n");
    exit(1);
}

/*
 * We need to trap calls to the resolver to not account memory for the catalog
 * which is shared to the current running test. We also don't want to have
 * network downloads modifying tests.
 */
static xmlParserInputPtr 
testExternalEntityLoader(const char *URL, const char *ID,
			 xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr ret;

    if (checkTestFile(URL)) {
	ret = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
    } else {
	int memused = xmlMemUsed();
	ret = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
	extraMemoryFromResolver += xmlMemUsed() - memused;
    }
      
    return(ret);
}

static void
initializeLibxml2(void) {
    xmlGetWarningsDefaultValue = 0;
    xmlPedanticParserDefault(0);

    xmlMemSetup(xmlMemFree, xmlMemMalloc, xmlMemRealloc, xmlMemoryStrdup);
    xmlInitParser();
    xmlSetExternalEntityLoader(testExternalEntityLoader);
    libxmlMemoryAllocatedBase = xmlMemUsed();
}


/************************************************************************
 *									*
 *		File name and path utilities				*
 *									*
 ************************************************************************/

static const char *baseFilename(const char *filename) {
    const char *cur;
    if (filename == NULL)
        return(NULL);
    cur = &filename[strlen(filename)];
    while ((cur > filename) && (*cur != '/'))
        cur--;
    if (*cur == '/')
        return(cur + 1);
    return(cur);
}

static char *resultFilename(const char *filename, const char *out,
                            const char *suffix) {
    const char *base;
    char res[500];

/*************
    if ((filename[0] == 't') && (filename[1] == 'e') &&
        (filename[2] == 's') && (filename[3] == 't') &&
	(filename[4] == '/'))
	filename = &filename[5];
 *************/
    
    base = baseFilename(filename);
    if (suffix == NULL)
        suffix = ".tmp";
    if (out == NULL)
        out = "";
    snprintf(res, 499, "%s%s%s", out, base, suffix);
    res[499] = 0;
    return(strdup(res));
}

static int checkTestFile(const char *filename) {
    struct stat buf;

    if (stat(filename, &buf) == -1)
        return(0);

    if (!S_ISREG(buf.st_mode))
        return(0);

    return(1);
}

static int compareFiles(const char *r1, const char *r2) {
    int res1, res2;
    int fd1, fd2;
    char bytes1[4096];
    char bytes2[4096];

    fd1 = open(r1, O_RDONLY);
    if (fd1 < 0)
        return(-1);
    fd2 = open(r2, O_RDONLY);
    if (fd2 < 0) {
        close(fd1);
        return(-1);
    }
    while (1) {
        res1 = read(fd1, bytes1, 4096);
        res2 = read(fd2, bytes2, 4096);
	if (res1 != res2) {
	    close(fd1);
	    close(fd2);
	    return(1);
	}
	if (res1 == 0)
	    break;
	if (memcmp(bytes1, bytes2, res1) != 0) {
	    close(fd1);
	    close(fd2);
	    return(1);
	}
    }
    close(fd1);
    close(fd2);
    return(0);
}

static int loadMem(const char *filename, const char **mem, int *size) {
    int fd, res;
    struct stat info;
    char *base;
    int siz = 0;
    if (stat(filename, &info) < 0) 
	return(-1);
    base = malloc(info.st_size + 1);
    if (base == NULL)
	return(-1);
    if ((fd = open(filename, O_RDONLY)) < 0) {
        free(base);
	return(-1);
    }
    while ((res = read(fd, &base[siz], info.st_size - siz)) > 0) {
        siz += res;
    }
    close(fd);
    if (siz != info.st_size) {
        free(base);
	return(-1);
    }
    base[siz] = 0;
    *mem = base;
    *size = siz;
    return(0);
}

static int unloadMem(const char *mem) {
    free((char *)mem);
    return(0);
}

/************************************************************************
 *									*
 *		Tests implementations					*
 *									*
 ************************************************************************/

/**
 * oldParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 *
 * Parse a file using the old xmlParseFile API, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
oldParseTest(const char *filename, const char *result) {
    xmlDocPtr doc;
    char *temp;
    int res = 0;

    /*
     * base of the test, parse with the old API
     */
    doc = xmlParseFile(filename);
    if (doc == NULL)
        return(1);
    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "Out of memory\n");
        fatalError();
    }
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    /*
     * Parse the saved result to make sure the round trip is okay
     */
    doc = xmlParseFile(temp);
    if (doc == NULL)
        return(1);
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    unlink(temp);
    free(temp);
    return(res);
}

/**
 * memParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 *
 * Parse a file using the old xmlReadMemory API, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
memParseTest(const char *filename, const char *result) {
    xmlDocPtr doc;
    const char *base;
    int size;
    const char *base2;
    int size2;

    /*
     * load and parse the memory
     */
    if (loadMem(filename, &base, &size) != 0) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }
    
    doc = xmlReadMemory(base, size, filename, NULL, 0);
    unloadMem(base);
    if (doc == NULL) {
        return(1);
    }
    if (loadMem(result, &base, &size) != 0) {
        fprintf(stderr, "Failed to load %s\n", result);
	return(-1);
    }
    xmlDocDumpMemory(doc, (xmlChar **) &base2, &size2);
    xmlFreeDoc(doc);
    if ((base2 == NULL) || (size != size2) ||
        (memcmp(base, base2, size) != 0)) {
	unloadMem(base);
	if (base2 != NULL)
	    xmlFree((char *)base2);
        fprintf(stderr, "Result for %s failed\n", filename);
	return(-1);
    }
    unloadMem(base);
    xmlFree((char *)base2);
    return(0);
}

/**
 * noentParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 *
 * Parse a file with entity resolution, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
noentParseTest(const char *filename, const char *result) {
    xmlDocPtr doc;
    char *temp;
    int res = 0;

    /*
     * base of the test, parse with the old API
     */
    doc = xmlReadFile(filename, NULL, XML_PARSE_NOENT);
    if (doc == NULL)
        return(1);
    temp = resultFilename(filename, "", ".res");
    if (temp == NULL) {
        fprintf(stderr, "Out of memory\n");
        fatalError();
    }
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    /*
     * Parse the saved result to make sure the round trip is okay
     */
    doc = xmlReadFile(filename, NULL, XML_PARSE_NOENT);
    if (doc == NULL)
        return(1);
    xmlSaveFile(temp, doc);
    if (compareFiles(temp, result)) {
        res = 1;
    }
    xmlFreeDoc(doc);

    unlink(temp);
    free(temp);
    return(res);
}

/************************************************************************
 *									*
 *		Tests Descriptions					*
 *									*
 ************************************************************************/

static
testDesc testDescriptions[] = {
    { "XML regression tests" , oldParseTest, "test/*", "result/", "" },
    { "XML regression tests on memory" , memParseTest, "test/*", "result/", "" },
    { "XML entity subst regression tests" , noentParseTest, "test/*", "result/noent/", "" },
    {NULL, NULL, NULL, NULL, NULL}
};

/************************************************************************
 *									*
 *		The main driving the tests				*
 *									*
 ************************************************************************/

static int
launchTests(testDescPtr tst) {
    int res = 0, err = 0;
    size_t i;
    char *result;
    int mem, leak;

    if (tst == NULL) return(-1);
    if (tst->in != NULL) {
	glob_t globbuf;

	globbuf.gl_offs = 0;
	glob(tst->in, GLOB_DOOFFS, NULL, &globbuf);
	for (i = 0;i < globbuf.gl_pathc;i++) {
	    if (!checkTestFile(globbuf.gl_pathv[i]))
	        continue;
	    result = resultFilename(globbuf.gl_pathv[i], tst->out, tst->suffix);
	    if (result == NULL) {
	        fprintf(stderr, "Out of memory !\n");
		fatalError();
	    }
	    if (!checkTestFile(result)) {
	        fprintf(stderr, "Missing result file %s\n", result);
	    } else {
		mem = xmlMemUsed();
		extraMemoryFromResolver = 0;
		res = tst->func(globbuf.gl_pathv[i], result);
		if (res != 0) {
		    fprintf(stderr, "File %s generated an error\n",
		            globbuf.gl_pathv[i]);
		    err++;
		}
		else if (xmlMemUsed() != mem) {
		    if (extraMemoryFromResolver == 0) {
			fprintf(stderr, "File %s leaked %d bytes\n",
				globbuf.gl_pathv[i], xmlMemUsed() - mem);
			leak++;
			err++;
		    }
		}
	    }
	    free(result);
	}
    } else {
        res = tst->func(NULL, NULL);
	if (res != 0)
	    err++;
    }
    return(err);
}

int
main(int argc, char **argv) {
    int i = 0, res, ret = 0;

    initializeLibxml2();

    for (i = 0; testDescriptions[i].func != NULL; i++) {
        if (testDescriptions[i].desc != NULL)
	    printf("## %s\n", testDescriptions[i].desc);
	res = launchTests(&testDescriptions[i]);
	if (res != 0)
	    ret++;
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(ret);
}
