/*
 * testparser.c: Additional parser tests
 *
 * See Copyright for the status of this software.
 */

#define XML_DEPRECATED

#include <libxml/parser.h>
#include <libxml/uri.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>
#include <libxml/HTMLparser.h>

#include <string.h>

static int
testNewDocNode(void) {
    xmlNodePtr node;
    int err = 0;

    node = xmlNewDocNode(NULL, NULL, BAD_CAST "c", BAD_CAST "");
    if (node->children != NULL) {
        fprintf(stderr, "empty node has children\n");
        err = 1;
    }
    xmlFreeNode(node);

    return err;
}

static int
testStandaloneWithEncoding(void) {
    xmlDocPtr doc;
    const char *str =
        "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
        "<doc></doc>\n";
    int err = 0;

    xmlResetLastError();

    doc = xmlReadDoc(BAD_CAST str, NULL, "UTF-8", 0);
    if (doc == NULL) {
        fprintf(stderr, "xmlReadDoc failed\n");
        err = 1;
    }
    xmlFreeDoc(doc);

    return err;
}

static int
testUnsupportedEncoding(void) {
    xmlDocPtr doc;
    const xmlError *error;
    int err = 0;

    xmlResetLastError();

    doc = xmlReadDoc(BAD_CAST "<doc/>", NULL, "#unsupported",
                     XML_PARSE_NOWARNING);
    if (doc == NULL) {
        fprintf(stderr, "xmlReadDoc failed with unsupported encoding\n");
        err = 1;
    }
    xmlFreeDoc(doc);

    error = xmlGetLastError();
    if (error == NULL ||
        error->code != XML_ERR_UNSUPPORTED_ENCODING ||
        error->level != XML_ERR_WARNING ||
        strcmp(error->message, "Unsupported encoding: #unsupported\n") != 0)
    {
        fprintf(stderr, "xmlReadDoc failed to raise correct error\n");
        err = 1;
    }

    return err;
}

static int
testNodeGetContent(void) {
    xmlDocPtr doc;
    xmlChar *content;
    int err = 0;

    doc = xmlReadDoc(BAD_CAST "<doc/>", NULL, NULL, 0);
    xmlAddChild(doc->children, xmlNewReference(doc, BAD_CAST "lt"));
    content = xmlNodeGetContent((xmlNodePtr) doc);
    if (strcmp((char *) content, "<") != 0) {
        fprintf(stderr, "xmlNodeGetContent failed\n");
        err = 1;
    }
    xmlFree(content);
    xmlFreeDoc(doc);

    return err;
}

static int
testCFileIO(void) {
    xmlDocPtr doc;
    int err = 0;

    /* Deprecated FILE-based API */
    xmlRegisterInputCallbacks(xmlFileMatch, xmlFileOpen, xmlFileRead,
                              xmlFileClose);
    doc = xmlReadFile("test/ent1", NULL, 0);

    if (doc == NULL) {
        err = 1;
    } else {
        xmlNodePtr root = xmlDocGetRootElement(doc);

        if (root == NULL || !xmlStrEqual(root->name, BAD_CAST "EXAMPLE"))
            err = 1;
    }

    xmlFreeDoc(doc);
    xmlPopInputCallbacks();

    if (err)
        fprintf(stderr, "xmlReadFile failed with FILE input callbacks\n");

    return err;
}

#ifdef LIBXML_VALID_ENABLED
static void
testSwitchDtdExtSubset(void *vctxt, const xmlChar *name ATTRIBUTE_UNUSED,
                       const xmlChar *externalId ATTRIBUTE_UNUSED,
                       const xmlChar *systemId ATTRIBUTE_UNUSED) {
    xmlParserCtxtPtr ctxt = vctxt;

    ctxt->myDoc->extSubset = ctxt->_private;
}

static int
testSwitchDtd(void) {
    const char dtdContent[] =
        "<!ENTITY test '<elem1/><elem2/>'>\n";
    const char docContent[] =
        "<!DOCTYPE doc SYSTEM 'entities.dtd'>\n"
        "<doc>&test;</doc>\n";
    xmlParserInputBufferPtr input;
    xmlParserCtxtPtr ctxt;
    xmlDtdPtr dtd;
    xmlDocPtr doc;
    xmlEntityPtr ent;
    int err = 0;

    input = xmlParserInputBufferCreateStatic(dtdContent,
                                             sizeof(dtdContent) - 1,
                                             XML_CHAR_ENCODING_NONE);
    dtd = xmlIOParseDTD(NULL, input, XML_CHAR_ENCODING_NONE);

    ctxt = xmlNewParserCtxt();
    ctxt->_private = dtd;
    ctxt->sax->externalSubset = testSwitchDtdExtSubset;
    doc = xmlCtxtReadMemory(ctxt, docContent, sizeof(docContent) - 1, NULL,
                            NULL, XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
    xmlFreeParserCtxt(ctxt);

    ent = xmlGetDocEntity(doc, BAD_CAST "test");
    if (ent->children->doc != NULL) {
        fprintf(stderr, "Entity content should have NULL doc\n");
        err = 1;
    }

    /* Free doc before DTD */
    doc->extSubset = NULL;
    xmlFreeDoc(doc);
    xmlFreeDtd(dtd);

    return err;
}
#endif /* LIBXML_VALID_ENABLED */

#ifdef LIBXML_SAX1_ENABLED
static int
testBalancedChunk(void) {
    xmlNodePtr list;
    xmlNodePtr elem;
    int ret;
    int err = 0;

    ret = xmlParseBalancedChunkMemory(NULL, NULL, NULL, 0,
            BAD_CAST "start <node xml:lang='en'>abc</node> end", &list);

    if ((ret != XML_ERR_OK) ||
        (list == NULL) ||
        ((elem = list->next) == NULL) ||
        (elem->type != XML_ELEMENT_NODE) ||
        (elem->nsDef == NULL) ||
        (!xmlStrEqual(elem->nsDef->href, XML_XML_NAMESPACE))) {
        fprintf(stderr, "xmlParseBalancedChunkMemory failed\n");
        err = 1;
    }

    xmlFreeNodeList(list);

    return(err);
}
#endif

#ifdef LIBXML_PUSH_ENABLED
static int
testHugePush(void) {
    xmlParserCtxtPtr ctxt;
    int err, i;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);

    /*
     * Push parse a document larger than XML_MAX_LOOKUP_LIMIT
     * (10,000,000 bytes). This mainly tests whether shrinking the
     * buffer works when push parsing.
     */
    xmlParseChunk(ctxt, "<doc>", 5, 0);
    for (i = 0; i < 1000000; i++)
        xmlParseChunk(ctxt, "<elem>text</elem>", 17, 0);
    xmlParseChunk(ctxt, "</doc>", 6, 1);

    err = ctxt->wellFormed ? 0 : 1;
    xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);

    return err;
}

static int
testHugeEncodedChunk(void) {
    xmlBufferPtr buf;
    xmlChar *chunk;
    xmlParserCtxtPtr ctxt;
    int err, i;

    /*
     * Test the push parser with a built-in encoding handler like ISO-8859-1
     * and a chunk larger than the initial decoded buffer (currently 4 KB).
     */
    buf = xmlBufferCreate();
    xmlBufferCat(buf,
            BAD_CAST "<?xml version='1.0' encoding='ISO-8859-1'?>\n");
    xmlBufferCat(buf, BAD_CAST "<doc><!-- ");
    for (i = 0; i < 2000; i++)
        xmlBufferCat(buf, BAD_CAST "0123456789");
    xmlBufferCat(buf, BAD_CAST " --></doc>");
    chunk = xmlBufferDetach(buf);
    xmlBufferFree(buf);

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);

    xmlParseChunk(ctxt, (char *) chunk, xmlStrlen(chunk), 0);
    xmlParseChunk(ctxt, NULL, 0, 1);

    err = ctxt->wellFormed ? 0 : 1;
    xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
    xmlFree(chunk);

    return err;
}

#ifdef LIBXML_HTML_ENABLED
static int
testHtmlPushWithEncoding(void) {
    htmlParserCtxtPtr ctxt;
    htmlDocPtr doc;
    htmlNodePtr node;
    int err = 0;

    ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL,
                                    XML_CHAR_ENCODING_UTF8);
    htmlParseChunk(ctxt, "-\xC3\xA4-", 4, 1);

    doc = ctxt->myDoc;
    if (!xmlStrEqual(doc->encoding, BAD_CAST "UTF-8")) {
        fprintf(stderr, "testHtmlPushWithEncoding failed\n");
        err = 1;
    }

    node = xmlDocGetRootElement(doc)->children->children->children;
    if (!xmlStrEqual(node->content, BAD_CAST "-\xC3\xA4-")) {
        fprintf(stderr, "testHtmlPushWithEncoding failed\n");
        err = 1;
    }

    xmlFreeDoc(doc);
    htmlFreeParserCtxt(ctxt);
    return err;
}
#endif
#endif

#ifdef LIBXML_READER_ENABLED
static int
testReaderEncoding(void) {
    xmlBuffer *buf;
    xmlTextReader *reader;
    xmlChar *xml;
    const xmlChar *encoding;
    int err = 0;
    int i;

    buf = xmlBufferCreate();
    xmlBufferCCat(buf, "<?xml version='1.0' encoding='ISO-8859-1'?>\n");
    xmlBufferCCat(buf, "<doc>");
    for (i = 0; i < 8192; i++)
        xmlBufferCCat(buf, "x");
    xmlBufferCCat(buf, "</doc>");
    xml = xmlBufferDetach(buf);
    xmlBufferFree(buf);

    reader = xmlReaderForDoc(BAD_CAST xml, NULL, NULL, 0);
    xmlTextReaderRead(reader);
    encoding = xmlTextReaderConstEncoding(reader);

    if (!xmlStrEqual(encoding, BAD_CAST "ISO-8859-1")) {
        fprintf(stderr, "testReaderEncoding failed\n");
        err = 1;
    }

    xmlFreeTextReader(reader);
    xmlFree(xml);
    return err;
}

static int
testReaderContent(void) {
    xmlTextReader *reader;
    const xmlChar *xml = BAD_CAST "<d>x<e>y</e><f>z</f></d>";
    xmlChar *string;
    int err = 0;

    reader = xmlReaderForDoc(xml, NULL, NULL, 0);
    xmlTextReaderRead(reader);

    string = xmlTextReaderReadOuterXml(reader);
    if (!xmlStrEqual(string, xml)) {
        fprintf(stderr, "xmlTextReaderReadOuterXml failed\n");
        err = 1;
    }
    xmlFree(string);

    string = xmlTextReaderReadInnerXml(reader);
    if (!xmlStrEqual(string, BAD_CAST "x<e>y</e><f>z</f>")) {
        fprintf(stderr, "xmlTextReaderReadInnerXml failed\n");
        err = 1;
    }
    xmlFree(string);

    string = xmlTextReaderReadString(reader);
    if (!xmlStrEqual(string, BAD_CAST "xyz")) {
        fprintf(stderr, "xmlTextReaderReadString failed\n");
        err = 1;
    }
    xmlFree(string);

    xmlFreeTextReader(reader);
    return err;
}

static int
testReaderNode(xmlTextReader *reader) {
    xmlChar *string;
    int type;
    int err = 0;

    type = xmlTextReaderNodeType(reader);
    string = xmlTextReaderReadString(reader);

    if (type == XML_READER_TYPE_ELEMENT) {
        xmlNodePtr node = xmlTextReaderCurrentNode(reader);

        if ((node->children == NULL) != (string == NULL))
            err = 1;
    } else if (type == XML_READER_TYPE_TEXT ||
               type == XML_READER_TYPE_CDATA ||
               type == XML_READER_TYPE_WHITESPACE ||
               type == XML_READER_TYPE_SIGNIFICANT_WHITESPACE) {
        if (string == NULL)
            err = 1;
    } else {
        if (string != NULL)
            err = 1;
    }

    if (err)
        fprintf(stderr, "xmlTextReaderReadString failed for %d\n", type);

    xmlFree(string);

    return err;
}

static int
testReader(void) {
    xmlTextReader *reader;
    const xmlChar *xml = BAD_CAST
        "<d>\n"
        "  x<e a='v'>y</e><f>z</f>\n"
        "  <![CDATA[cdata]]>\n"
        "  <!-- comment -->\n"
        "  <?pi content?>\n"
        "  <empty/>\n"
        "</d>";
    int err = 0;

    reader = xmlReaderForDoc(xml, NULL, NULL, 0);

    while (xmlTextReaderRead(reader) > 0) {
        if (testReaderNode(reader) > 0) {
            err = 1;
            break;
        }

        if (xmlTextReaderMoveToFirstAttribute(reader) > 0) {
            do {
                if (testReaderNode(reader) > 0) {
                    err = 1;
                    break;
                }
            } while (xmlTextReaderMoveToNextAttribute(reader) > 0);

            xmlTextReaderMoveToElement(reader);
        }
    }

    xmlFreeTextReader(reader);
    return err;
}

#ifdef LIBXML_XINCLUDE_ENABLED
typedef struct {
    char *message;
    int code;
} testReaderErrorCtxt;

static void
testReaderError(void *arg, const char *msg,
                xmlParserSeverities severity ATTRIBUTE_UNUSED,
                xmlTextReaderLocatorPtr locator ATTRIBUTE_UNUSED) {
    testReaderErrorCtxt *ctxt = arg;

    if (ctxt->message != NULL)
        xmlFree(ctxt->message);
    ctxt->message = xmlMemStrdup(msg);
}

static void
testStructuredReaderError(void *arg, const xmlError *error) {
    testReaderErrorCtxt *ctxt = arg;

    if (ctxt->message != NULL)
        xmlFree(ctxt->message);
    ctxt->message = xmlMemStrdup(error->message);
    ctxt->code = error->code;
}

static int
testReaderXIncludeError(void) {
    /*
     * Test whether XInclude errors are reported to the custom error
     * handler of a reader.
     */
    const char *doc =
        "<doc xmlns:xi='http://www.w3.org/2001/XInclude'>\n"
        "  <xi:include/>\n"
        "</doc>\n";
    xmlTextReader *reader;
    testReaderErrorCtxt errorCtxt;
    int err = 0;

    reader = xmlReaderForDoc(BAD_CAST doc, NULL, NULL, XML_PARSE_XINCLUDE);
    xmlTextReaderSetErrorHandler(reader, testReaderError, &errorCtxt);
    errorCtxt.message = NULL;
    errorCtxt.code = 0;
    while (xmlTextReaderRead(reader) > 0)
        ;

    if (errorCtxt.message == NULL ||
        strstr(errorCtxt.message, "href or xpointer") == NULL) {
        fprintf(stderr, "xmlTextReaderSetErrorHandler failed\n");
        err = 1;
    }

    xmlFree(errorCtxt.message);
    xmlFreeTextReader(reader);

    reader = xmlReaderForDoc(BAD_CAST doc, NULL, NULL, XML_PARSE_XINCLUDE);
    xmlTextReaderSetStructuredErrorHandler(reader, testStructuredReaderError,
                                           &errorCtxt);
    errorCtxt.message = NULL;
    errorCtxt.code = 0;
    while (xmlTextReaderRead(reader) > 0)
        ;

    if (errorCtxt.code != XML_XINCLUDE_NO_HREF ||
        errorCtxt.message == NULL ||
        strstr(errorCtxt.message, "href or xpointer") == NULL) {
        fprintf(stderr, "xmlTextReaderSetStructuredErrorHandler failed\n");
        err = 1;
    }

    xmlFree(errorCtxt.message);
    xmlFreeTextReader(reader);

    return err;
}
#endif
#endif

#ifdef LIBXML_WRITER_ENABLED
static int
testWriterIOWrite(void *ctxt, const char *data, int len) {
    (void) ctxt;
    (void) data;

    return len;
}

static int
testWriterIOClose(void *ctxt) {
    (void) ctxt;

    return XML_IO_ENAMETOOLONG;
}

static int
testWriterClose(void){
    xmlOutputBufferPtr out;
    xmlTextWriterPtr writer;
    int err = 0;
    int result;

    out = xmlOutputBufferCreateIO(testWriterIOWrite, testWriterIOClose,
                                  NULL, NULL);
    writer = xmlNewTextWriter(out);
    xmlTextWriterStartDocument(writer, "1.0", "UTF-8", NULL);
    xmlTextWriterStartElement(writer, BAD_CAST "elem");
    xmlTextWriterEndElement(writer);
    xmlTextWriterEndDocument(writer);
    result = xmlTextWriterClose(writer);

    if (result != XML_IO_ENAMETOOLONG) {
        fprintf(stderr, "xmlTextWriterClose reported wrong error %d\n",
                result);
        err = 1;
    }

    xmlFreeTextWriter(writer);
    return err;
}
#endif

typedef struct {
    const char *uri;
    const char *base;
    const char *result;
} xmlRelativeUriTest;

static int
testBuildRelativeUri(void) {
    xmlChar *res;
    int err = 0;
    int i;

    static const xmlRelativeUriTest tests[] = {
        {
            "/a/b1/c1",
            "/a/b2/c2",
            "../b1/c1"
        }, {
            "a/b1/c1",
            "a/b2/c2",
            "../b1/c1"
        }, {
            "a/././b1/x/y/../z/../.././c1",
            "./a/./b2/././b2",
            "../b1/c1"
        }, {
            "file:///a/b1/c1",
            "/a/b2/c2",
            NULL
        }, {
            "/a/b1/c1",
            "file:///a/b2/c2",
            NULL
        }, {
            "a/b1/c1",
            "/a/b2/c2",
            NULL
        }, {
            "/a/b1/c1",
            "a/b2/c2",
            NULL
        }, {
            "http://example.org/a/b1/c1",
            "http://example.org/a/b2/c2",
            "../b1/c1"
        }, {
            "http://example.org/a/b1/c1",
            "https://example.org/a/b2/c2",
            NULL
        }, {
            "http://example.org/a/b1/c1",
            "http://localhost/a/b2/c2",
            NULL
        }, {
            "with space/x x/y y",
            "with space/b2/c2",
            "../x%20x/y%20y"
        }, {
            "with space/x x/y y",
            "/b2/c2",
            "with%20space/x%20x/y%20y"
        }
#if defined(_WIN32) || defined(__CYGWIN__)
        , {
            "\\a\\b1\\c1",
            "\\a\\b2\\c2",
            "../b1/c1"
        }, {
            "\\a\\b1\\c1",
            "/a/b2/c2",
            "../b1/c1"
        }, {
            "a\\b1\\c1",
            "a/b2/c2",
            "../b1/c1"
        }, {
            "file://server/a/b1/c1",
            "\\\\?\\UNC\\server\\a\\b2\\c2",
            "../b1/c1"
        }, {
            "file://server/a/b1/c1",
            "\\\\server\\a\\b2\\c2",
            "../b1/c1"
        }, {
            "file:///x:/a/b1/c1",
            "x:\\a\\b2\\c2",
            "../b1/c1"
        }, {
            "file:///x:/a/b1/c1",
            "\\\\?\\x:\\a\\b2\\c2",
            "../b1/c1"
        }, {
            "file:///x:/a/b1/c1",
            "file:///y:/a/b2/c2",
            NULL
        }, {
            "x:/a/b1/c1",
            "y:/a/b2/c2",
            "file:///x:/a/b1/c1"
        }, {
            "/a/b1/c1",
            "y:/a/b2/c2",
            NULL
        }, {
            "\\\\server\\a\\b1\\c1",
            "a/b2/c2",
            "file://server/a/b1/c1"
        }
#endif
    };

    for (i = 0; (size_t) i < sizeof(tests) / sizeof(tests[0]); i++) {
        const xmlRelativeUriTest *test = tests + i;
        const char *expect;

        res = xmlBuildRelativeURI(BAD_CAST test->uri, BAD_CAST test->base);
        expect = test->result ? test->result : test->uri;
        if (!xmlStrEqual(res, BAD_CAST expect)) {
            fprintf(stderr, "xmlBuildRelativeURI failed uri=%s base=%s "
                    "result=%s expected=%s\n", test->uri, test->base,
                    res, expect);
            err = 1;
        }
        xmlFree(res);
    }

    return err;
}

#if defined(_WIN32) || defined(__CYGWIN__)
static int
testWindowsUri(void) {
    const char *url = "c:/a%20b/file.txt";
    xmlURIPtr uri;
    xmlChar *res;
    int err = 0;
    int i;

    static const xmlRelativeUriTest tests[] = {
        {
            "c:/a%20b/file.txt",
            "base.xml",
            "c:/a b/file.txt"
        }, {
            "file:///c:/a%20b/file.txt",
            "base.xml",
            "file:///c:/a%20b/file.txt"
        }, {
            "Z:/a%20b/file.txt",
            "http://example.com/",
            "Z:/a b/file.txt"
        }, {
            "a%20b/b1/c1",
            "C:/a/b2/c2",
            "C:/a/b2/a b/b1/c1"
        }, {
            "a%20b/b1/c1",
            "\\a\\b2\\c2",
            "/a/b2/a b/b1/c1"
        }, {
            "a%20b/b1/c1",
            "\\\\?\\a\\b2\\c2",
            "//?/a/b2/a b/b1/c1"
        }, {
            "a%20b/b1/c1",
            "\\\\\\\\server\\b2\\c2",
            "//server/b2/a b/b1/c1"
        }
    };

    uri = xmlParseURI(url);
    if (uri == NULL) {
        fprintf(stderr, "xmlParseURI failed\n");
        err = 1;
    } else {
        if (uri->scheme != NULL) {
            fprintf(stderr, "invalid scheme: %s\n", uri->scheme);
            err = 1;
        }
        if (uri->path == NULL || strcmp(uri->path, "c:/a b/file.txt") != 0) {
            fprintf(stderr, "invalid path: %s\n", uri->path);
            err = 1;
        }

        xmlFreeURI(uri);
    }

    for (i = 0; (size_t) i < sizeof(tests) / sizeof(tests[0]); i++) {
        const xmlRelativeUriTest *test = tests + i;

        res = xmlBuildURI(BAD_CAST test->uri, BAD_CAST test->base);
        if (res == NULL || !xmlStrEqual(res, BAD_CAST test->result)) {
            fprintf(stderr, "xmlBuildURI failed uri=%s base=%s "
                    "result=%s expected=%s\n", test->uri, test->base,
                    res, test->result);
            err = 1;
        }
        xmlFree(res);
    }

    return err;
}
#endif /* WIN32 */

int
main(void) {
    int err = 0;

    err |= testNewDocNode();
    err |= testStandaloneWithEncoding();
    err |= testUnsupportedEncoding();
    err |= testNodeGetContent();
    err |= testCFileIO();
#ifdef LIBXML_VALID_ENABLED
    err |= testSwitchDtd();
#endif
#ifdef LIBXML_SAX1_ENABLED
    err |= testBalancedChunk();
#endif
#ifdef LIBXML_PUSH_ENABLED
    err |= testHugePush();
    err |= testHugeEncodedChunk();
#ifdef LIBXML_HTML_ENABLED
    err |= testHtmlPushWithEncoding();
#endif
#endif
#ifdef LIBXML_READER_ENABLED
    err |= testReaderEncoding();
    err |= testReaderContent();
    err |= testReader();
#ifdef LIBXML_XINCLUDE_ENABLED
    err |= testReaderXIncludeError();
#endif
#endif
#ifdef LIBXML_WRITER_ENABLED
    err |= testWriterClose();
#endif
    err |= testBuildRelativeUri();
#if defined(_WIN32) || defined(__CYGWIN__)
    err |= testWindowsUri();
#endif

    return err;
}

