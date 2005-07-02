/*
 * runsuite.c: C program to run libxml2 againts external published testsuites 
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
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/uri.h>
#include <libxml/xmlreader.h>

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <libxml/relaxng.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlschemastypes.h>

/************************************************************************
 *									*
 *		File name and path utilities				*
 *									*
 ************************************************************************/

static int checkTestFile(const char *filename) {
    struct stat buf;

    if (stat(filename, &buf) == -1)
        return(0);

    if (!S_ISREG(buf.st_mode))
        return(0);

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

static int nb_tests = 0;
static int nb_errors = 0;
static int nb_leaks = 0;
static long libxmlMemoryAllocatedBase = 0;
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
char *testEntitiesName[MAX_ENTITIES];
char *testEntitiesValue[MAX_ENTITIES];
int nb_entities = 0;
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
    if (ret == NULL) {
        fprintf(stderr, "Failed to find resource %s\n", URL);
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
#ifdef LIBXML_SCHEMAS_ENABLED
    xmlSchemaInitTypes();
    xmlRelaxNGInitTypes();
#endif
    libxmlMemoryAllocatedBase = xmlMemUsed();
}

static xmlNodePtr
getNext(xmlNodePtr cur, const char *xpath) {
    xmlNodePtr ret = NULL;
    xmlXPathObjectPtr res;
    xmlXPathContextPtr ctxt;
    xmlXPathCompExprPtr comp;

    if ((cur == NULL)  || (cur->doc == NULL) || (xpath == NULL))
        return(NULL);
    ctxt = xmlXPathNewContext(cur->doc);
    ctxt->node = cur;
    comp = xmlXPathCompile(BAD_CAST xpath);
    if (comp == NULL) {
        fprintf(stderr, "Failed to compile %s\n", xpath);
	xmlXPathFreeContext(ctxt);
	return(NULL);
    }
    res = xmlXPathCompiledEval(comp, ctxt);
    xmlXPathFreeCompExpr(comp);
    xmlXPathFreeContext(ctxt);
    if (res == NULL)
        return(NULL);
    if ((res->type == XPATH_NODESET) &&
        (res->nodesetval != NULL) &&
	(res->nodesetval->nodeNr > 0) &&
	(res->nodesetval->nodeTab != NULL))
	ret = res->nodesetval->nodeTab[0];
    xmlXPathFreeObject(res);
    return(ret);
}

static xmlChar *
getString(xmlNodePtr cur, const char *xpath) {
    xmlChar *ret = NULL;
    xmlXPathObjectPtr res;
    xmlXPathContextPtr ctxt;
    xmlXPathCompExprPtr comp;

    if ((cur == NULL)  || (cur->doc == NULL) || (xpath == NULL))
        return(NULL);
    ctxt = xmlXPathNewContext(cur->doc);
    ctxt->node = cur;
    comp = xmlXPathCompile(BAD_CAST xpath);
    if (comp == NULL) {
        fprintf(stderr, "Failed to compile %s\n", xpath);
	return(NULL);
    }
    res = xmlXPathCompiledEval(comp, ctxt);
    xmlXPathFreeCompExpr(comp);
    xmlXPathFreeContext(ctxt);
    if (res == NULL)
        return(NULL);
    if (res->type == XPATH_STRING) {
        ret = res->stringval;
	res->stringval = NULL;
    }
    xmlXPathFreeObject(res);
    return(ret);
}

/************************************************************************
 *									*
 *		Test test/xsdtest/xsdtestsuite.xml			*
 *									*
 ************************************************************************/

static int 
xsdIncorectTestCase(int verbose, xmlNodePtr cur) {
    xmlNodePtr test;
    xmlBufferPtr buf;
    xmlRelaxNGParserCtxtPtr pctxt;
    xmlRelaxNGPtr rng = NULL;
    int ret = 0, memt;

    cur = getNext(cur, "./incorrect[1]");
    if (cur == NULL) {
        return(0);
    }
    
    test = getNext(cur, "./*");
    if (test == NULL) {
        fprintf(stderr, "Failed to find test in correct line %ld\n",
	        xmlGetLineNo(cur));
        return(1);
    }

    memt = xmlMemUsed();
    extraMemoryFromResolver = 0;
    /*
     * dump the schemas to a buffer, then reparse it and compile the schemas
     */
    buf = xmlBufferCreate();
    if (buf == NULL) {
        fprintf(stderr, "out of memory !\n");
	fatalError();
    }
    xmlNodeDump(buf, test->doc, test, 0, 0);
    pctxt = xmlRelaxNGNewMemParserCtxt((const char *)buf->content, buf->use);
    xmlRelaxNGSetParserErrors(pctxt,
         (xmlRelaxNGValidityErrorFunc) testErrorHandler,
         (xmlRelaxNGValidityWarningFunc) testErrorHandler,
	 pctxt);
    rng = xmlRelaxNGParse(pctxt);
    xmlRelaxNGFreeParserCtxt(pctxt);
    if (rng != NULL) {
        fprintf(stderr, "Failed to detect incorect RNG line %ld\n",
	        xmlGetLineNo(test));
        ret = 1;
	goto done;
    }

done:
    if (buf != NULL)
	xmlBufferFree(buf);
    if (rng != NULL)
        xmlRelaxNGFree(rng);
    xmlResetLastError();
    if ((memt != xmlMemUsed()) && (extraMemoryFromResolver == 0)) {
	fprintf(stderr, "Validation of tests starting line %ld leaked %d\n",
		xmlGetLineNo(cur), xmlMemUsed() - memt);
	nb_leaks++;
    }
    return(ret);
}

static void
installResources(xmlNodePtr tst, const xmlChar *base) {
    xmlNodePtr test;
    xmlBufferPtr buf;
    xmlChar *name, *content, *res;
    buf = xmlBufferCreate();
    if (buf == NULL) {
        fprintf(stderr, "out of memory !\n");
	fatalError();
    }
    xmlNodeDump(buf, tst->doc, tst, 0, 0);

    while (tst != NULL) {
	test = getNext(tst, "./*");
	if (test != NULL) {
	    xmlBufferEmpty(buf);
	    xmlNodeDump(buf, test->doc, test, 0, 0);
	    name = getString(tst, "string(@name)");
	    content = xmlStrdup(buf->content);
	    if ((name != NULL) && (content != NULL)) {
	        res = composeDir(base, name);
		xmlFree(name);
	        addEntity((char *) res, (char *) content);
	    } else {
	        if (name != NULL) xmlFree(name);
	        if (content != NULL) xmlFree(content);
	    }
	}
	tst = getNext(tst, "following-sibling::resource[1]");
    }
    if (buf != NULL)
	xmlBufferFree(buf);
}

static void
installDirs(xmlNodePtr tst, const xmlChar *base) {
    xmlNodePtr test;
    xmlChar *name, *res;

    name = getString(tst, "string(@name)");
    if (name == NULL)
        return;
    res = composeDir(base, name);
    xmlFree(name);
    if (res == NULL) {
	return;
    }
    /* Now process resources and subdir recursively */
    test = getNext(tst, "./resource[1]");
    if (test != NULL) {
        installResources(test, res);
    }
    test = getNext(tst, "./dir[1]");
    while (test != NULL) {
        installDirs(test, res);
	test = getNext(test, "following-sibling::dir[1]");
    }
}

static int 
xsdTestCase(int verbose, xmlNodePtr tst) {
    xmlNodePtr test, tmp, cur;
    xmlBufferPtr buf;
    xmlDocPtr doc = NULL;
    xmlRelaxNGParserCtxtPtr pctxt;
    xmlRelaxNGValidCtxtPtr ctxt;
    xmlRelaxNGPtr rng = NULL;
    int ret = 0, mem, memt;
    xmlChar *dtd;

    resetEntities();

    tmp = getNext(tst, "./dir[1]");
    if (tmp != NULL) {
        installDirs(tmp, NULL);
    }
    tmp = getNext(tst, "./resource[1]");
    if (tmp != NULL) {
        installResources(tmp, NULL);
    }

    cur = getNext(tst, "./correct[1]");
    if (cur == NULL) {
        return(xsdIncorectTestCase(verbose, tst));
    }
    
    test = getNext(cur, "./*");
    if (test == NULL) {
        fprintf(stderr, "Failed to find test in correct line %ld\n",
	        xmlGetLineNo(cur));
        return(1);
    }

    memt = xmlMemUsed();
    extraMemoryFromResolver = 0;
    /*
     * dump the schemas to a buffer, then reparse it and compile the schemas
     */
    buf = xmlBufferCreate();
    if (buf == NULL) {
        fprintf(stderr, "out of memory !\n");
	fatalError();
    }
    xmlNodeDump(buf, test->doc, test, 0, 0);
    pctxt = xmlRelaxNGNewMemParserCtxt((const char *)buf->content, buf->use);
    xmlRelaxNGSetParserErrors(pctxt,
         (xmlRelaxNGValidityErrorFunc) testErrorHandler,
         (xmlRelaxNGValidityWarningFunc) testErrorHandler,
	 pctxt);
    rng = xmlRelaxNGParse(pctxt);
    xmlRelaxNGFreeParserCtxt(pctxt);
    if (extraMemoryFromResolver)
        memt = 0;

    if (rng == NULL) {
        fprintf(stderr, "Failed to parse RNGtest line %ld\n",
	        xmlGetLineNo(test));
	nb_errors++;
        ret = 1;
	goto done;
    }
    /*
     * now scan all the siblings of correct to process the <valid> tests
     */
    tmp = getNext(cur, "following-sibling::valid[1]");
    while (tmp != NULL) {
	dtd = xmlGetProp(tmp, BAD_CAST "dtd");
	test = getNext(tmp, "./*");
	if (test == NULL) {
	    fprintf(stderr, "Failed to find test in <valid> line %ld\n",
		    xmlGetLineNo(tmp));
	    
	} else {
	    xmlBufferEmpty(buf);
	    if (dtd != NULL)
		xmlBufferAdd(buf, dtd, -1);
	    xmlNodeDump(buf, test->doc, test, 0, 0);

	    /*
	     * We are ready to run the test
	     */
	    mem = xmlMemUsed();
	    extraMemoryFromResolver = 0;
            doc = xmlReadMemory((const char *)buf->content, buf->use,
	                        "test", NULL, 0);
	    if (doc == NULL) {
		fprintf(stderr,
			"Failed to parse valid instance line %ld\n",
			xmlGetLineNo(tmp));
		nb_errors++;
	    } else {
		nb_tests++;
	        ctxt = xmlRelaxNGNewValidCtxt(rng);
		xmlRelaxNGSetValidErrors(ctxt,
		     (xmlRelaxNGValidityErrorFunc) testErrorHandler,
		     (xmlRelaxNGValidityWarningFunc) testErrorHandler,
		     ctxt);
		ret = xmlRelaxNGValidateDoc(ctxt, doc);
		xmlRelaxNGFreeValidCtxt(ctxt);
		if (ret > 0) {
		    fprintf(stderr,
		            "Failed to validate valid instance line %ld\n",
			    xmlGetLineNo(tmp));
		    nb_errors++;
		} else if (ret < 0) {
		    fprintf(stderr,
		            "Internal error validating instance line %ld\n",
			    xmlGetLineNo(tmp));
		    nb_errors++;
		}
		xmlFreeDoc(doc);
	    }
	    xmlResetLastError();
	    if ((mem != xmlMemUsed()) && (extraMemoryFromResolver == 0)) {
	        fprintf(stderr, "Validation of instance line %ld leaked %d\n",
		        xmlGetLineNo(tmp), xmlMemUsed() - mem);
		xmlMemoryDump();
	        nb_leaks++;
	    }
	}
	if (dtd != NULL)
	    xmlFree(dtd);
	tmp = getNext(tmp, "following-sibling::valid[1]");
    }
    /*
     * now scan all the siblings of correct to process the <invalid> tests
     */
    tmp = getNext(cur, "following-sibling::invalid[1]");
    while (tmp != NULL) {
	test = getNext(tmp, "./*");
	if (test == NULL) {
	    fprintf(stderr, "Failed to find test in <invalid> line %ld\n",
		    xmlGetLineNo(tmp));
	    
	} else {
	    xmlBufferEmpty(buf);
	    xmlNodeDump(buf, test->doc, test, 0, 0);

	    /*
	     * We are ready to run the test
	     */
	    mem = xmlMemUsed();
	    extraMemoryFromResolver = 0;
            doc = xmlReadMemory((const char *)buf->content, buf->use,
	                        "test", NULL, 0);
	    if (doc == NULL) {
		fprintf(stderr,
			"Failed to parse valid instance line %ld\n",
			xmlGetLineNo(tmp));
		nb_errors++;
	    } else {
		nb_tests++;
	        ctxt = xmlRelaxNGNewValidCtxt(rng);
		xmlRelaxNGSetValidErrors(ctxt,
		     (xmlRelaxNGValidityErrorFunc) testErrorHandler,
		     (xmlRelaxNGValidityWarningFunc) testErrorHandler,
		     ctxt);
		ret = xmlRelaxNGValidateDoc(ctxt, doc);
		xmlRelaxNGFreeValidCtxt(ctxt);
		if (ret == 0) {
		    fprintf(stderr,
		            "Failed to detect invalid instance line %ld\n",
			    xmlGetLineNo(tmp));
		    nb_errors++;
		} else if (ret < 0) {
		    fprintf(stderr,
		            "Internal error validating instance line %ld\n",
			    xmlGetLineNo(tmp));
		    nb_errors++;
		}
		xmlFreeDoc(doc);
	    }
	    xmlResetLastError();
	    if ((mem != xmlMemUsed()) && (extraMemoryFromResolver == 0)) {
	        fprintf(stderr, "Validation of instance line %ld leaked %d\n",
		        xmlGetLineNo(tmp), xmlMemUsed() - mem);
		xmlMemoryDump();
	        nb_leaks++;
	    }
	}
	tmp = getNext(tmp, "following-sibling::invalid[1]");
    }

done:
    if (buf != NULL)
	xmlBufferFree(buf);
    if (rng != NULL)
        xmlRelaxNGFree(rng);
    xmlResetLastError();
    if ((memt != xmlMemUsed()) && (memt != 0)) {
	fprintf(stderr, "Validation of tests starting line %ld leaked %d\n",
		xmlGetLineNo(cur), xmlMemUsed() - memt);
	nb_leaks++;
    }
    return(ret);
}

static int 
xsdTestSuite(int verbose, xmlNodePtr cur) {
    if (verbose) {
	xmlChar *doc = getString(cur, "string(documentation)");

	if (doc != NULL) {
	    printf("Suite %s\n", doc);
	    xmlFree(doc);
	}
    }
    cur = getNext(cur, "./testCase[1]");
    while (cur != NULL) {
        xsdTestCase(verbose, cur);
	cur = getNext(cur, "following-sibling::testCase[1]");
    }
        
    return(0);
}

static int 
xsdTest(int verbose) {
    xmlDocPtr doc;
    xmlNodePtr cur;
    const char *filename = "test/xsdtest/xsdtestsuite.xml";
    int ret = 0;

    doc = xmlReadFile(filename, NULL, XML_PARSE_NOENT);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", filename);
	return(-1);
    }
    printf("## XML Schemas datatypes test suite from James Clark\n");

    cur = xmlDocGetRootElement(doc);
    if ((cur == NULL) || (!xmlStrEqual(cur->name, BAD_CAST "testSuite"))) {
        fprintf(stderr, "Unexpected format %s\n", filename);
	ret = -1;
	goto done;
    }

    cur = getNext(cur, "./testSuite[1]");
    if ((cur == NULL) || (!xmlStrEqual(cur->name, BAD_CAST "testSuite"))) {
        fprintf(stderr, "Unexpected format %s\n", filename);
	ret = -1;
	goto done;
    }
    while (cur != NULL) {
        xsdTestSuite(verbose, cur);
	cur = getNext(cur, "following-sibling::testSuite[1]");
    }

done:
    if (doc != NULL)
	xmlFreeDoc(doc);
    return(ret);
}

static int 
rngTestSuite(int verbose, xmlNodePtr cur) {
    if (verbose) {
	xmlChar *doc = getString(cur, "string(documentation)");

	if (doc != NULL) {
	    printf("Suite %s\n", doc);
	    xmlFree(doc);
	} else {
	    doc = getString(cur, "string(section)");
	    if (doc != NULL) {
		printf("Section %s\n", doc);
		xmlFree(doc);
	    }
	}
    }
    cur = getNext(cur, "./testSuite[1]");
    while (cur != NULL) {
        xsdTestSuite(verbose, cur);
	cur = getNext(cur, "following-sibling::testSuite[1]");
    }
        
    return(0);
}

static int 
rngTest1(int verbose) {
    xmlDocPtr doc;
    xmlNodePtr cur;
    const char *filename = "test/relaxng/OASIS/spectest.xml";
    int ret = 0;

    doc = xmlReadFile(filename, NULL, XML_PARSE_NOENT);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", filename);
	return(-1);
    }
    printf("## Relax NG test suite from James Clark\n");

    cur = xmlDocGetRootElement(doc);
    if ((cur == NULL) || (!xmlStrEqual(cur->name, BAD_CAST "testSuite"))) {
        fprintf(stderr, "Unexpected format %s\n", filename);
	ret = -1;
	goto done;
    }

    cur = getNext(cur, "./testSuite[1]");
    if ((cur == NULL) || (!xmlStrEqual(cur->name, BAD_CAST "testSuite"))) {
        fprintf(stderr, "Unexpected format %s\n", filename);
	ret = -1;
	goto done;
    }
    while (cur != NULL) {
        rngTestSuite(verbose, cur);
	cur = getNext(cur, "following-sibling::testSuite[1]");
    }

done:
    if (doc != NULL)
	xmlFreeDoc(doc);
    return(ret);
}

static int 
rngTest2(int verbose) {
    xmlDocPtr doc;
    xmlNodePtr cur;
    const char *filename = "test/relaxng/testsuite.xml";
    int ret = 0;

    doc = xmlReadFile(filename, NULL, XML_PARSE_NOENT);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", filename);
	return(-1);
    }
    printf("## Relax NG test suite for libxml2\n");

    cur = xmlDocGetRootElement(doc);
    if ((cur == NULL) || (!xmlStrEqual(cur->name, BAD_CAST "testSuite"))) {
        fprintf(stderr, "Unexpected format %s\n", filename);
	ret = -1;
	goto done;
    }

    cur = getNext(cur, "./testSuite[1]");
    if ((cur == NULL) || (!xmlStrEqual(cur->name, BAD_CAST "testSuite"))) {
        fprintf(stderr, "Unexpected format %s\n", filename);
	ret = -1;
	goto done;
    }
    while (cur != NULL) {
        xsdTestSuite(verbose, cur);
	cur = getNext(cur, "following-sibling::testSuite[1]");
    }

done:
    if (doc != NULL)
	xmlFreeDoc(doc);
    return(ret);
}

/************************************************************************
 *									*
 *		Libxml2 specific routines				*
 *									*
 ************************************************************************/

int
main(int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED) {
    int res, ret = 0;
    int verbose = 0;
    int old_errors, old_tests, old_leaks;

    initializeLibxml2();

    if ((argc >= 2) && (!strcmp(argv[1], "-v")))
        verbose = 1;


    old_errors = nb_errors;
    old_tests = nb_tests;
    old_leaks = nb_leaks;
    res = xsdTest(verbose);
    if ((nb_errors == old_errors) && (nb_leaks == old_leaks))
	printf("Ran %d tests, no errors\n", nb_tests - old_tests);
    else
	printf("Ran %d tests, %d errors, %d leaks\n",
	       nb_tests - old_tests,
	       nb_errors - old_errors,
	       nb_leaks - old_leaks);
    old_errors = nb_errors;
    old_tests = nb_tests;
    old_leaks = nb_leaks;
    res = rngTest1(verbose);
    if ((nb_errors == old_errors) && (nb_leaks == old_leaks))
	printf("Ran %d tests, no errors\n", nb_tests - old_tests);
    else
	printf("Ran %d tests, %d errors, %d leaks\n",
	       nb_tests - old_tests,
	       nb_errors - old_errors,
	       nb_leaks - old_leaks);
    old_errors = nb_errors;
    old_tests = nb_tests;
    old_leaks = nb_leaks;
    res = rngTest2(verbose);
    if ((nb_errors == old_errors) && (nb_leaks == old_leaks))
	printf("Ran %d tests, no errors\n", nb_tests - old_tests);
    else
	printf("Ran %d tests, %d errors, %d leaks\n",
	       nb_tests - old_tests,
	       nb_errors - old_errors,
	       nb_leaks - old_leaks);
    old_errors = nb_errors;
    old_tests = nb_tests;
    old_leaks = nb_leaks;

    if ((nb_errors == 0) && (nb_leaks == 0)) {
        ret = 0;
	printf("Total %d tests, no errors\n",
	       nb_tests);
    } else {
        ret = 1;
	printf("Total %d tests, %d errors, %d leaks\n",
	       nb_tests, nb_errors, nb_leaks);
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(ret);
}
