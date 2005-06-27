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
#ifdef LIBXML_READER_ENABLED
#include <libxml/xmlreader.h>
#endif

typedef int (*functest) (const char *filename, const char *result,
                         const char *error, int options);

typedef struct testDesc testDesc;
typedef testDesc *testDescPtr;
struct testDesc {
    const char *desc; /* descripton of the test */
    functest    func; /* function implementing the test */
    const char *in;   /* glob to path for input files */
    const char *out;  /* output directory */
    const char *suffix;/* suffix for output files */
    const char *err;  /* suffix for error output files */
    int     options;  /* parser options for the test */
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

/*
 * Trapping the error messages at the generic level to grab the equivalent of
 * stderr messages on CLI tools.
 */
static char testErrors[32769];
static int testErrorsSize = 0;

static void
testErrorHandler(void *ctx  ATTRIBUTE_UNUSED, const char *msg, ...) {
    va_list args;
    int res;

    if (testErrorsSize >= 32768)
        return;
    va_start(args, msg);
    res = vsnprintf(&testErrors[testErrorsSize],
                    32768 - testErrorsSize,
		    msg, args);
    va_end(args);
    if (testErrorsSize + res >= 32768) {
        /* buffer is full */
	testErrorsSize = 32768;
	testErrors[testErrorsSize] = 0;
    } else {
        testErrorsSize += res;
    }
    testErrors[testErrorsSize] = 0;
}

static void
initializeLibxml2(void) {
    xmlGetWarningsDefaultValue = 0;
    xmlPedanticParserDefault(0);

    xmlMemSetup(xmlMemFree, xmlMemMalloc, xmlMemRealloc, xmlMemoryStrdup);
    xmlInitParser();
    xmlSetExternalEntityLoader(testExternalEntityLoader);
    xmlSetGenericErrorFunc(NULL, testErrorHandler);
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

static int compareFileMem(const char *filename, const char *mem, int size) {
    int res;
    int fd;
    char bytes[4096];
    int idx = 0;
    struct stat info;

    if (stat(filename, &info) < 0) 
	return(-1);
    if (info.st_size != size)
        return(-1);
    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return(-1);
    while (idx < size) {
        res = read(fd, bytes, 4096);
	if (res <= 0)
	    break;
	if (res + idx > size) 
	    break;
	if (memcmp(bytes, &mem[idx], res) != 0) {
	    close(fd);
	    return(1);
	}
	idx += res;
    }
    close(fd);
    return(idx != size);
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
 * @err: the file with error messages: unused
 *
 * Parse a file using the old xmlParseFile API, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
oldParseTest(const char *filename, const char *result,
             const char *err ATTRIBUTE_UNUSED,
	     int options ATTRIBUTE_UNUSED) {
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
 * @err: the file with error messages: unused
 *
 * Parse a file using the old xmlReadMemory API, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
memParseTest(const char *filename, const char *result,
             const char *err ATTRIBUTE_UNUSED,
	     int options ATTRIBUTE_UNUSED) {
    xmlDocPtr doc;
    const char *base;
    int size, res;

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
    xmlDocDumpMemory(doc, (xmlChar **) &base, &size);
    xmlFreeDoc(doc);
    res = compareFileMem(result, base, size);
    if ((base == NULL) || (res != 0)) {
	if (base != NULL)
	    xmlFree((char *)base);
        fprintf(stderr, "Result for %s failed\n", filename);
	return(-1);
    }
    xmlFree((char *)base);
    return(0);
}

/**
 * noentParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages: unused
 *
 * Parse a file with entity resolution, then serialize back
 * reparse the result and serialize again, then check for deviation
 * in serialization.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
noentParseTest(const char *filename, const char *result,
               const char *err  ATTRIBUTE_UNUSED,
	       int options ATTRIBUTE_UNUSED) {
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

/**
 * errParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the xmlReadFile API and check for errors.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
errParseTest(const char *filename, const char *result, const char *err,
             int options ATTRIBUTE_UNUSED) {
    xmlDocPtr doc;
    const char *base;
    int size, res;

    xmlGetWarningsDefaultValue = 1;
    doc = xmlReadFile(filename, NULL, 0);
    if (doc == NULL) {
        base = "";
	size = 0;
    } else {
	xmlDocDumpMemory(doc, (xmlChar **) &base, &size);
    }
    xmlGetWarningsDefaultValue = 0;
    res = compareFileMem(result, base, size);
    if (doc != NULL) {
	if (base != NULL)
	    xmlFree((char *)base);
	xmlFreeDoc(doc);
    }
    if (res != 0) {
        fprintf(stderr, "Result for %s failed\n", filename);
	return(-1);
    }
    res = compareFileMem(err, testErrors, testErrorsSize);
    if (res != 0) {
        fprintf(stderr, "Error for %s failed\n", filename);
	return(-1);
    }

    return(0);
}

#ifdef LIBXML_READER_ENABLED
static void processNode(FILE *out, xmlTextReaderPtr reader) {
    const xmlChar *name, *value;
    int type, empty;

    type = xmlTextReaderNodeType(reader);
    empty = xmlTextReaderIsEmptyElement(reader);

    name = xmlTextReaderConstName(reader);
    if (name == NULL)
	name = BAD_CAST "--";

    value = xmlTextReaderConstValue(reader);

    
    fprintf(out, "%d %d %s %d %d", 
	    xmlTextReaderDepth(reader),
	    type,
	    name,
	    empty,
	    xmlTextReaderHasValue(reader));
    if (value == NULL)
	fprintf(out, "\n");
    else {
	fprintf(out, " %s\n", value);
    }
#if 0
#ifdef LIBXML_PATTERN_ENABLED
    if (patternc) {
        xmlChar *path = NULL;
        int match = -1;
	
	if (type == XML_READER_TYPE_ELEMENT) {
	    /* do the check only on element start */
	    match = xmlPatternMatch(patternc, xmlTextReaderCurrentNode(reader));

	    if (match) {
		path = xmlGetNodePath(xmlTextReaderCurrentNode(reader));
		fprintf(out, "Node %s matches pattern %s\n", path, pattern);
	    }
	}
	if (patstream != NULL) {
	    int ret;

	    if (type == XML_READER_TYPE_ELEMENT) {
		ret = xmlStreamPush(patstream,
		                    xmlTextReaderConstLocalName(reader),
				    xmlTextReaderConstNamespaceUri(reader));
		if (ret < 0) {
		    fprintf(stderr, "xmlStreamPush() failure\n");
                    xmlFreeStreamCtxt(patstream);
		    patstream = NULL;
		} else if (ret != match) {
		    if (path == NULL) {
		        path = xmlGetNodePath(
		                       xmlTextReaderCurrentNode(reader));
		    }
		    fprintf(stderr,
		            "xmlPatternMatch and xmlStreamPush disagree\n");
		    fprintf(stderr,
		            "  pattern %s node %s\n",
			    pattern, path);
		}
		

	    } 
	    if ((type == XML_READER_TYPE_END_ELEMENT) ||
	        ((type == XML_READER_TYPE_ELEMENT) && (empty))) {
	        ret = xmlStreamPop(patstream);
		if (ret < 0) {
		    fprintf(stderr, "xmlStreamPop() failure\n");
                    xmlFreeStreamCtxt(patstream);
		    patstream = NULL;
		}
	    }
	}
	if (path != NULL)
	    xmlFree(path);
    }
#endif
#endif
}
static int
streamProcessTest(const char *filename, const char *result, const char *err,
                  xmlTextReaderPtr reader) {
    int ret;
    char *temp = NULL;
    FILE *t = NULL;

    if (reader == NULL)
        return(-1);

    if (result != NULL) {
	temp = resultFilename(filename, "", ".res");
	if (temp == NULL) {
	    fprintf(stderr, "Out of memory\n");
	    fatalError();
	}
	t = fopen(temp, "w");
	if (t == NULL) {
	    fprintf(stderr, "Can't open temp file %s\n", temp);
	    free(temp);
	    return(-1);
	}
    }
    xmlGetWarningsDefaultValue = 1;
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
	if (t != NULL)
	    processNode(t, reader);
        ret = xmlTextReaderRead(reader);
    }
    if (ret != 0) {
        testErrorHandler(NULL, "%s : failed to parse\n", filename);
    }
    xmlGetWarningsDefaultValue = 0;
    if (t != NULL) {
        fclose(t);
	ret = compareFiles(temp, result);
	unlink(temp);
	free(temp);
	if (ret) {
	    fprintf(stderr, "Result for %s failed\n", filename);
	    return(-1);
	}
    }
    if (err != NULL) {
	ret = compareFileMem(err, testErrors, testErrorsSize);
	if (ret != 0) {
	    fprintf(stderr, "Error for %s failed\n", filename);
	    return(-1);
	}
    }

    return(0);
}

/**
 * streamParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the reader API and check for errors.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
streamParseTest(const char *filename, const char *result, const char *err,
                int options) {
    xmlTextReaderPtr reader;
    int ret;

    reader = xmlReaderForFile(filename, NULL, options);
    ret = streamProcessTest(filename, result, err, reader);
    xmlFreeTextReader(reader);
    return(ret);
}

/**
 * walkerParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the walker, i.e. a reader built from a atree.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
walkerParseTest(const char *filename, const char *result, const char *err,
                int options) {
    xmlDocPtr doc;
    xmlTextReaderPtr reader;
    int ret;

    doc = xmlReadFile(filename, NULL, options);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", filename);
	return(-1);
    }
    reader = xmlReaderWalker(doc);
    ret = streamProcessTest(filename, result, err, reader);
    xmlFreeTextReader(reader);
    xmlFreeDoc(doc);
    return(ret);
}

/**
 * streamMemParseTest:
 * @filename: the file to parse
 * @result: the file with expected result
 * @err: the file with error messages
 *
 * Parse a file using the reader API from memory and check for errors.
 *
 * Returns 0 in case of success, an error code otherwise
 */
static int
streamMemParseTest(const char *filename, const char *result, const char *err,
                   int options) {
    xmlTextReaderPtr reader;
    int ret;
    const char *base;
    int size;

    /*
     * load and parse the memory
     */
    if (loadMem(filename, &base, &size) != 0) {
        fprintf(stderr, "Failed to load %s\n", filename);
	return(-1);
    }
    reader = xmlReaderForMemory(base, size, filename, NULL, options);
    ret = streamProcessTest(filename, result, err, reader);
    free((char *)base);
    xmlFreeTextReader(reader);
    return(ret);
}
#endif

/************************************************************************
 *									*
 *		Tests Descriptions					*
 *									*
 ************************************************************************/

static
testDesc testDescriptions[] = {
    { "XML regression tests" ,
      oldParseTest, "./test/*", "result/", "", NULL,
      0 },
    { "XML regression tests on memory" ,
      memParseTest, "./test/*", "result/", "", NULL,
      0 },
    { "XML entity subst regression tests" ,
      noentParseTest, "./test/*", "result/noent/", "", NULL,
      0 },
    { "XML Namespaces regression tests",
      errParseTest, "./test/namespaces/*", "result/namespaces/", "", ".err",
      0 },
    { "Error cases regression tests",
      errParseTest, "./test/errors/*.xml", "result/errors/", "", ".err",
      0 },
#ifdef LIBXML_READER_ENABLED
    { "Error cases stream regression tests",
      streamParseTest, "./test/errors/*.xml", "result/errors/", NULL, ".str",
      0 },
    { "Reader regression tests",
      streamParseTest, "./test/*", "result/", ".rdr", NULL,
      0 },
    { "Reader entities substitution regression tests",
      streamParseTest, "./test/*", "result/", ".rde", NULL,
      XML_PARSE_NOENT },
    { "Reader on memory regression tests",
      streamMemParseTest, "./test/*", "result/", ".rdr", NULL,
      0 },
    { "Walker regression tests",
      walkerParseTest, "./test/*", "result/", ".rdr", NULL,
      0 },
#endif
    {NULL, NULL, NULL, NULL, NULL, NULL, 0}
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
    char *error;
    int mem, leak;

    if (tst == NULL) return(-1);
    if (tst->in != NULL) {
	glob_t globbuf;

	globbuf.gl_offs = 0;
	glob(tst->in, GLOB_DOOFFS, NULL, &globbuf);
	for (i = 0;i < globbuf.gl_pathc;i++) {
	    if (!checkTestFile(globbuf.gl_pathv[i]))
	        continue;
	    if (tst->suffix != NULL) {
		result = resultFilename(globbuf.gl_pathv[i], tst->out,
					tst->suffix);
		if (result == NULL) {
		    fprintf(stderr, "Out of memory !\n");
		    fatalError();
		}
	    } else {
	        result = NULL;
	    }
	    if (tst->err != NULL) {
		error = resultFilename(globbuf.gl_pathv[i], tst->out,
		                        tst->err);
		if (error == NULL) {
		    fprintf(stderr, "Out of memory !\n");
		    fatalError();
		}
	    } else {
	        error = NULL;
	    }
	    if ((result) &&(!checkTestFile(result))) {
	        fprintf(stderr, "Missing result file %s\n", result);
	    } else if ((error) &&(!checkTestFile(error))) {
	        fprintf(stderr, "Missing error file %s\n", error);
	    } else {
		mem = xmlMemUsed();
		extraMemoryFromResolver = 0;
		testErrorsSize = 0;
		testErrors[0] = 0;
		res = tst->func(globbuf.gl_pathv[i], result, error,
		                tst->options);
		if (res != 0) {
		    fprintf(stderr, "File %s generated an error\n",
		            globbuf.gl_pathv[i]);
		    err++;
		}
		else if (xmlMemUsed() != mem) {
		    xmlResetLastError();
		    if ((xmlMemUsed() != mem) &&
		        (extraMemoryFromResolver == 0)) {
			fprintf(stderr, "File %s leaked %d bytes\n",
				globbuf.gl_pathv[i], xmlMemUsed() - mem);
			leak++;
			err++;
		    }
		}
		testErrorsSize = 0;
	    }
	    if (result)
		free(result);
	    if (error)
		free(error);
	}
    } else {
        testErrorsSize = 0;
	testErrors[0] = 0;
	extraMemoryFromResolver = 0;
        res = tst->func(NULL, NULL, NULL, tst->options);
	if (res != 0)
	    err++;
    }
    return(err);
}

int
main(int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED) {
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
