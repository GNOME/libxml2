/*
 * runsuite.c: C program to run libxml2 againts published testsuites
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#ifdef HAVE_CONFIG_H
#include "libxml.h"
#else
#include <stdio.h>
#endif

#if !defined(_WIN32) || defined(__CYGWIN__)
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/uri.h>
#include <libxml/xmlreader.h>

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define LOGFILE "runsuite.log"
static FILE *logfile = NULL;
static int verbose = 0;



#if defined(_WIN32) && !defined(__CYGWIN__)

#define vsnprintf _vsnprintf

#define snprintf _snprintf

#endif

/************************************************************************
 *									*
 *		File name and path utilities				*
 *									*
 ************************************************************************/

static int checkTestFile(const char *filename) {
    struct stat buf;

    if (stat(filename, &buf) == -1)
        return(0);

#if defined(_WIN32) && !defined(__CYGWIN__)
    if (!(buf.st_mode & _S_IFREG))
        return(0);
#else
    if (!S_ISREG(buf.st_mode))
        return(0);
#endif

    return(1);
}

static xmlChar *composeDir(const xmlChar *dir, const xmlChar *path) {
    char buf[500];

    if (dir == NULL) return(xmlStrdup(path));
    if (path == NULL) return(NULL);

    snprintf(buf, 500, "%s/%s", (const char *) dir, (const char *) path);
    return(xmlStrdup((const xmlChar *) buf));
}

/************************************************************************
 *									*
 *		Libxml2 specific routines				*
 *									*
 ************************************************************************/

static int nb_skipped = 0;
static int nb_tests = 0;
static int nb_errors = 0;
static int nb_leaks = 0;
static int extraMemoryFromResolver = 0;

static int
fatalError(void) {
    fprintf(stderr, "Exitting tests on fatal error\n");
    exit(1);
}

/*
 * that's needed to implement <resource>
 */
#define MAX_ENTITIES 20
static char *testEntitiesName[MAX_ENTITIES];
static char *testEntitiesValue[MAX_ENTITIES];
static int nb_entities = 0;
static void resetEntities(void) {
    int i;

    for (i = 0;i < nb_entities;i++) {
        if (testEntitiesName[i] != NULL)
	    xmlFree(testEntitiesName[i]);
        if (testEntitiesValue[i] != NULL)
	    xmlFree(testEntitiesValue[i]);
    }
    nb_entities = 0;
}
static int addEntity(char *name, char *content) {
    if (nb_entities >= MAX_ENTITIES) {
	fprintf(stderr, "Too many entities defined\n");
	return(-1);
    }
    testEntitiesName[nb_entities] = name;
    testEntitiesValue[nb_entities] = content;
    nb_entities++;
    return(0);
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
    int i;

    for (i = 0;i < nb_entities;i++) {
        if (!strcmp(testEntitiesName[i], URL)) {
	    ret = xmlNewStringInputStream(ctxt,
	                (const xmlChar *) testEntitiesValue[i]);
	    if (ret != NULL) {
	        ret->filename = (const char *)
		                xmlStrdup((xmlChar *)testEntitiesName[i]);
	    }
	    return(ret);
	}
    }
    if (checkTestFile(URL)) {
	ret = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
    } else {
	int memused = xmlMemUsed();
	ret = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
	extraMemoryFromResolver += xmlMemUsed() - memused;
    }
#if 0
    if (ret == NULL) {
        fprintf(stderr, "Failed to find resource %s\n", URL);
    }
#endif

    return(ret);
}

/*
 * Trapping the error messages at the generic level to grab the equivalent of
 * stderr messages on CLI tools.
 */
static char testErrors[32769];
static int testErrorsSize = 0;

static void test_log(const char *msg, ...) {
    va_list args;
    if (logfile != NULL) {
        fprintf(logfile, "\n------------\n");
	va_start(args, msg);
	vfprintf(logfile, msg, args);
	va_end(args);
	fprintf(logfile, "%s", testErrors);
	testErrorsSize = 0; testErrors[0] = 0;
    }
    if (verbose) {
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
    }
}

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

static xmlXPathContextPtr ctxtXPath;

static void
initializeLibxml2(void) {
    xmlGetWarningsDefaultValue = 0;
    xmlPedanticParserDefault(0);

    xmlMemSetup(xmlMemFree, xmlMemMalloc, xmlMemRealloc, xmlMemoryStrdup);
    xmlInitParser();
    xmlSetExternalEntityLoader(testExternalEntityLoader);
    ctxtXPath = xmlXPathNewContext(NULL);
    /*
    * Deactivate the cache if created; otherwise we have to create/free it
    * for every test, since it will confuse the memory leak detection.
    * Note that normally this need not be done, since the cache is not
    * created until set explicitely with xmlXPathContextSetCache();
    * but for test purposes it is sometimes usefull to activate the
    * cache by default for the whole library.
    */
    if (ctxtXPath->cache != NULL)
	xmlXPathContextSetCache(ctxtXPath, 0, -1, 0);
    xmlSetGenericErrorFunc(NULL, testErrorHandler);
}

/************************************************************************
 *									*
 *		Run the xmlconf test if found				*
 *									*
 ************************************************************************/

static int
xmlconfTestNotNSWF(const char *id, const char *filename, int options) {
    xmlDocPtr doc;
    int ret = 1;

    /*
     * In case of Namespace errors, libxml2 will still parse the document
     * but log a Namesapce error.
     */
    doc = xmlReadFile(filename, NULL, options);
    if (doc == NULL) {
        test_log("test %s : %s failed to parse the XML\n",
	         id, filename);
        nb_errors++;
	ret = 0;
    } else {
	if ((xmlLastError.code == XML_ERR_OK) ||
	    (xmlLastError.domain != XML_FROM_NAMESPACE)) {
	    test_log("test %s : %s failed to detect namespace error\n",
		     id, filename);
	    nb_errors++;
	    ret = 0;
	}
	xmlFreeDoc(doc);
    }
    return(ret);
}

static int
xmlconfTestNotWF(const char *id, const char *filename, int options) {
    xmlDocPtr doc;
    int ret = 1;

    doc = xmlReadFile(filename, NULL, options);
    if (doc != NULL) {
        test_log("test %s : %s failed to detect not well formedness\n",
	         id, filename);
        nb_errors++;
	xmlFreeDoc(doc);
	ret = 0;
    }
    return(ret);
}

static int
xmlconfTestItem(xmlDocPtr doc, xmlNodePtr cur) {
    int ret = -1;
    xmlChar *type = NULL;
    xmlChar *filename = NULL;
    xmlChar *uri = NULL;
    xmlChar *base = NULL;
    xmlChar *id = NULL;
    xmlChar *rec = NULL;
    xmlChar *entities = NULL;
    xmlChar *edition = NULL;
    int options = 0;
    int nstest = 0;
    int mem, final;

    id = xmlGetProp(cur, BAD_CAST "ID");
    if (id == NULL) {
        test_log("test missing ID, line %ld\n", xmlGetLineNo(cur));
	goto error;
    }
    type = xmlGetProp(cur, BAD_CAST "TYPE");
    if (type == NULL) {
        test_log("test %s missing TYPE\n", (char *) id);
	goto error;
    }
    uri = xmlGetProp(cur, BAD_CAST "URI");
    if (uri == NULL) {
        test_log("test %s missing URI\n", (char *) id);
	goto error;
    }
    base = xmlNodeGetBase(doc, cur);
    filename = composeDir(base, uri);
    if (!checkTestFile((char *) filename)) {
        test_log("test %s missing file %s \n", id,
	         (filename ? (char *)filename : "NULL"));
	goto error;
    }

    entities = xmlGetProp(cur, BAD_CAST "ENTITIES");
    if (!xmlStrEqual(entities, BAD_CAST "none")) {
        options |= XML_PARSE_DTDLOAD;
    }
    rec = xmlGetProp(cur, BAD_CAST "RECOMMENDATION");
    if ((rec == NULL) ||
        (xmlStrEqual(rec, BAD_CAST "XML1.0")) ||
	(xmlStrEqual(rec, BAD_CAST "XML1.0-errata2e")) ||
	(xmlStrEqual(rec, BAD_CAST "XML1.0-errata3e")) ||
	(xmlStrEqual(rec, BAD_CAST "XML1.0-errata4e"))) {
	ret = 1;
    } else if ((xmlStrEqual(rec, BAD_CAST "NS1.0")) ||
	       (xmlStrEqual(rec, BAD_CAST "NS1.0-errata1e"))) {
	ret = 1;
	nstest = 1;
    } else {
        test_log("Skipping test %s for REC %s\n", (char *) id, (char *) rec);
	ret = 0;
	nb_skipped++;
	goto error;
    }
    edition = xmlGetProp(cur, BAD_CAST "EDITION");
    if ((edition != NULL) && (xmlStrchr(edition, '5') == NULL)) {
        /* test limited to all versions before 5th */
	options |= XML_PARSE_OLD10;
    }

    /*
     * Reset errors and check memory usage before the test
     */
    xmlResetLastError();
    testErrorsSize = 0; testErrors[0] = 0;
    mem = xmlMemUsed();

    if (xmlStrEqual(type, BAD_CAST "not-wf")) {
        if (nstest == 0)
	    xmlconfTestNotWF((char *) id, (char *) filename, options);
        else 
	    xmlconfTestNotNSWF((char *) id, (char *) filename, options);
    } else if (xmlStrEqual(type, BAD_CAST "valid")) {
    } else if (xmlStrEqual(type, BAD_CAST "invalid")) {
    } else if (xmlStrEqual(type, BAD_CAST "error")) {
    } else {
        test_log("test %s unknown TYPE value %s\n", (char *) id, (char *)type);
	ret = -1;
	goto error;
    }

    /*
     * Reset errors and check memory usage after the test
     */
    xmlResetLastError();
    final = xmlMemUsed();
    if (final > mem) {
        test_log("test %s : %s leaked %d bytes\n",
	         id, filename, final - mem);
        nb_leaks++;
    }
    nb_tests++;

error:
    if (type != NULL)
        xmlFree(type);
    if (entities != NULL)
        xmlFree(entities);
    if (edition != NULL)
        xmlFree(edition);
    if (filename != NULL)
        xmlFree(filename);
    if (uri != NULL)
        xmlFree(uri);
    if (base != NULL)
        xmlFree(base);
    if (id != NULL)
        xmlFree(id);
    if (rec != NULL)
        xmlFree(rec);
    return(ret);
}

static int
xmlconfTestCases(xmlDocPtr doc, xmlNodePtr cur) {
    xmlChar *profile;
    int ret = 0;
    int tests = 0;

    profile = xmlGetProp(cur, BAD_CAST "PROFILE");
    if (profile != NULL) {
        printf("Test cases: %s\n", (char *) profile);
	xmlFree(profile);
    }
    cur = cur->children;
    while (cur != NULL) {
        /* look only at elements we ignore everything else */
        if (cur->type == XML_ELEMENT_NODE) {
	    if (xmlStrEqual(cur->name, BAD_CAST "TESTCASES")) {
	        ret += xmlconfTestCases(doc, cur);
	    } else if (xmlStrEqual(cur->name, BAD_CAST "TEST")) {
	        if (xmlconfTestItem(doc, cur) >= 0)
		    ret++;
		tests++;
	    } else {
	        fprintf(stderr, "Unhandled element %s\n", (char *)cur->name);
	    }
	}
        cur = cur->next;
    }
    if (tests > 0)
	printf("Test cases: %d tests\n", tests);
    return(ret);
}

static int
xmlconfTestSuite(xmlDocPtr doc, xmlNodePtr cur) {
    xmlChar *profile;
    int ret = 0;

    profile = xmlGetProp(cur, BAD_CAST "PROFILE");
    if (profile != NULL) {
        printf("Test suite: %s\n", (char *) profile);
	xmlFree(profile);
    } else
        printf("Test suite\n");
    cur = cur->children;
    while (cur != NULL) {
        /* look only at elements we ignore everything else */
        if (cur->type == XML_ELEMENT_NODE) {
	    if (xmlStrEqual(cur->name, BAD_CAST "TESTCASES")) {
	        ret += xmlconfTestCases(doc, cur);
	    } else {
	        fprintf(stderr, "Unhandled element %s\n", (char *)cur->name);
	    }
	}
        cur = cur->next;
    }
    return(ret);
}

static void
xmlconfInfo(void) {
    fprintf(stderr, "  you need to fetch and extract the\n");
    fprintf(stderr, "  latest XML Conformance Test Suites\n");
    fprintf(stderr, "  http://www.w3.org/XML/Test/xmlts20080205.tar.gz\n");
    fprintf(stderr, "  see http://www.w3.org/XML/Test/ for informations\n");
}

static int
xmlconfTest(void) {
    const char *confxml = "xmlconf/xmlconf.xml";
    xmlDocPtr doc;
    xmlNodePtr cur;
    int ret = 0;

    if (!checkTestFile(confxml)) {
        fprintf(stderr, "%s is missing \n", confxml);
	xmlconfInfo();
	return(-1);
    }
    doc = xmlReadFile(confxml, NULL, XML_PARSE_NOENT);
    if (doc == NULL) {
        fprintf(stderr, "%s is corrupted \n", confxml);
	xmlconfInfo();
	return(-1);
    }

    cur = xmlDocGetRootElement(doc);
    if ((cur == NULL) || (!xmlStrEqual(cur->name, BAD_CAST "TESTSUITE"))) {
        fprintf(stderr, "Unexpected format %s\n", confxml);
	xmlconfInfo();
	ret = -1;
    } else {
        ret = xmlconfTestSuite(doc, cur);
    }
    xmlFreeDoc(doc);
    return(ret);
}

/************************************************************************
 *									*
 *		The driver for the tests				*
 *									*
 ************************************************************************/

int
main(int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED) {
    int ret = 0;
    int old_errors, old_tests, old_leaks;

    logfile = fopen(LOGFILE, "w");
    if (logfile == NULL) {
        fprintf(stderr,
	        "Could not open the log file, running in verbose mode\n");
	verbose = 1;
    }
    initializeLibxml2();

    if ((argc >= 2) && (!strcmp(argv[1], "-v")))
        verbose = 1;


    old_errors = nb_errors;
    old_tests = nb_tests;
    old_leaks = nb_leaks;
    xmlconfTest();
    if ((nb_errors == old_errors) && (nb_leaks == old_leaks))
	printf("Ran %d tests, no errors\n", nb_tests - old_tests);
    else
	printf("Ran %d tests, %d errors, %d leaks\n",
	       nb_tests - old_tests,
	       nb_errors - old_errors,
	       nb_leaks - old_leaks);
    if ((nb_errors == 0) && (nb_leaks == 0)) {
        ret = 0;
	printf("Total %d tests, no errors\n",
	       nb_tests);
    } else {
        ret = 1;
	printf("Total %d tests, %d errors, %d leaks\n",
	       nb_tests, nb_errors, nb_leaks);
    }
    xmlXPathFreeContext(ctxtXPath);
    xmlCleanupParser();
    xmlMemoryDump();

    if (logfile != NULL)
        fclose(logfile);
    return(ret);
}
