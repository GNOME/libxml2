/*
 * xmllint.c : a small tester program for XML input.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_LIBREADLINE
#include <readline/readline.h>
#ifdef HAVE_LIBHISTORY
#include <readline/history.h>
#endif
#endif

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/debugXML.h>

#ifdef LIBXML_DEBUG_ENABLED
static int debug = 0;
static int shell = 0;
static int debugent = 0;
#endif
static int copy = 0;
static int recovery = 0;
static int noent = 0;
static int noout = 0;
static int nowrap = 0;
static int valid = 0;
static int postvalid = 0;
static int repeat = 0;
static int insert = 0;
static int compress = 0;
static int html = 0;
static int htmlout = 0;
static int push = 0;
static int noblanks = 0;
static int testIO = 0;

extern int xmlDoValidityCheckingDefaultValue;
extern int xmlGetWarningsDefaultValue;

/************************************************************************
 * 									*
 * 			HTML ouput					*
 * 									*
 ************************************************************************/
char buffer[50000];

void
xmlHTMLEncodeSend(void) {
    char *result;

    result = (char *) xmlEncodeEntitiesReentrant(NULL, BAD_CAST buffer);
    if (result) {
	fprintf(stderr, "%s", result);
	xmlFree(result);
    }
    buffer[0] = 0;
}

/**
 * xmlHTMLPrintFileInfo:
 * @input:  an xmlParserInputPtr input
 * 
 * Displays the associated file and line informations for the current input
 */

void
xmlHTMLPrintFileInfo(xmlParserInputPtr input) {
    fprintf(stderr, "<p>");
    if (input != NULL) {
	if (input->filename) {
	    sprintf(&buffer[strlen(buffer)], "%s:%d: ", input->filename,
		    input->line);
	} else {
	    sprintf(&buffer[strlen(buffer)], "Entity: line %d: ", input->line);
	}
    }
    xmlHTMLEncodeSend();
}

/**
 * xmlHTMLPrintFileContext:
 * @input:  an xmlParserInputPtr input
 * 
 * Displays current context within the input content for error tracking
 */

void
xmlHTMLPrintFileContext(xmlParserInputPtr input) {
    const xmlChar *cur, *base;
    int n;

    if (input == NULL) return;
    fprintf(stderr, "<pre>\n");
    cur = input->cur;
    base = input->base;
    while ((cur > base) && ((*cur == '\n') || (*cur == '\r'))) {
	cur--;
    }
    n = 0;
    while ((n++ < 80) && (cur > base) && (*cur != '\n') && (*cur != '\r'))
        cur--;
    if ((*cur == '\n') || (*cur == '\r')) cur++;
    base = cur;
    n = 0;
    while ((*cur != 0) && (*cur != '\n') && (*cur != '\r') && (n < 79)) {
        sprintf(&buffer[strlen(buffer)], "%c", (unsigned char) *cur++);
	n++;
    }
    sprintf(&buffer[strlen(buffer)], "\n");
    cur = input->cur;
    while ((*cur == '\n') || (*cur == '\r'))
	cur--;
    n = 0;
    while ((cur != base) && (n++ < 80)) {
        sprintf(&buffer[strlen(buffer)], " ");
        base++;
    }
    sprintf(&buffer[strlen(buffer)],"^\n");
    xmlHTMLEncodeSend();
    fprintf(stderr, "</pre>");
}

/**
 * xmlHTMLError:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format an error messages, gives file, line, position and
 * extra parameters.
 */
void
xmlHTMLError(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input;
    xmlParserInputPtr cur = NULL;
    va_list args;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input != NULL) && (input->filename == NULL) && (ctxt->inputNr > 1)) {
	cur = input;
        input = ctxt->inputTab[ctxt->inputNr - 2];
    }
        
    xmlHTMLPrintFileInfo(input);

    fprintf(stderr, "<b>error</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    fprintf(stderr, "</p>\n");

    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}

/**
 * xmlHTMLWarning:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format a warning messages, gives file, line, position and
 * extra parameters.
 */
void
xmlHTMLWarning(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input;
    xmlParserInputPtr cur = NULL;
    va_list args;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input != NULL) && (input->filename == NULL) && (ctxt->inputNr > 1)) {
	cur = input;
        input = ctxt->inputTab[ctxt->inputNr - 2];
    }
        

    xmlHTMLPrintFileInfo(input);
        
    fprintf(stderr, "<b>warning</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    fprintf(stderr, "</p>\n");

    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}

/**
 * xmlHTMLValidityError:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format an validity error messages, gives file,
 * line, position and extra parameters.
 */
void
xmlHTMLValidityError(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input;
    va_list args;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];
        
    xmlHTMLPrintFileInfo(input);

    fprintf(stderr, "<b>validity error</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    fprintf(stderr, "</p>\n");

    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}

/**
 * xmlHTMLValidityWarning:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format a validity warning messages, gives file, line,
 * position and extra parameters.
 */
void
xmlHTMLValidityWarning(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input;
    va_list args;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];

    xmlHTMLPrintFileInfo(input);
        
    fprintf(stderr, "<b>validity warning</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    fprintf(stderr, "</p>\n");

    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}

/************************************************************************
 * 									*
 * 			Shell Interface					*
 * 									*
 ************************************************************************/
/**
 * xmlShellReadline:
 * @prompt:  the prompt value
 *
 * Read a string
 * 
 * Returns a pointer to it or NULL on EOF the caller is expected to
 *     free the returned string.
 */
char *
xmlShellReadline(char *prompt) {
#ifdef HAVE_LIBREADLINE
    char *line_read;

    /* Get a line from the user. */
    line_read = readline (prompt);

    /* If the line has any text in it, save it on the history. */
    if (line_read && *line_read)
	add_history (line_read);

    return (line_read);
#else
    char line_read[501];

    if (prompt != NULL)
	fprintf(stdout, "%s", prompt);
    if (!fgets(line_read, 500, stdin))
        return(NULL);
    line_read[500] = 0;
    return(strdup(line_read));
#endif
}

/************************************************************************
 * 									*
 * 			I/O Interfaces					*
 * 									*
 ************************************************************************/

int myRead(FILE *f, char * buffer, int len) {
    return(fread(buffer, 1, len, f));
}
void myClose(FILE *f) {
    fclose(f);
}

/************************************************************************
 * 									*
 * 			Test processing					*
 * 									*
 ************************************************************************/
void parseAndPrintFile(char *filename) {
    xmlDocPtr doc = NULL, tmp;

#ifdef LIBXML_HTML_ENABLED
    if (html) {
	doc = htmlParseFile(filename, NULL);
    } else {
#endif /* LIBXML_HTML_ENABLED */
	/*
	 * build an XML tree from a string;
	 */
	if (push) {
	    FILE *f;

	    f = fopen(filename, "r");
	    if (f != NULL) {
	        int res, size = 3;
	        char chars[1024];
                xmlParserCtxtPtr ctxt;

		if (repeat)
		    size = 1024;
		res = fread(chars, 1, 4, f);
		if (res > 0) {
		    ctxt = xmlCreatePushParserCtxt(NULL, NULL,
		                chars, res, filename);
		    while ((res = fread(chars, 1, size, f)) > 0) {
			xmlParseChunk(ctxt, chars, res, 0);
		    }
		    xmlParseChunk(ctxt, chars, 0, 1);
		    doc = ctxt->myDoc;
		    xmlFreeParserCtxt(ctxt);
	        }
	    }
	} else if (testIO) {
	    int ret;
	    FILE *f;

	    f = fopen(filename, "r");
	    if (f != NULL) {
                xmlParserCtxtPtr ctxt;

		ctxt = xmlCreateIOParserCtxt(NULL, NULL,
			    (xmlInputReadCallback) myRead,
			    (xmlInputCloseCallback) myClose,
			    f, XML_CHAR_ENCODING_NONE);
		xmlParseDocument(ctxt);

		ret = ctxt->wellFormed;
		doc = ctxt->myDoc;
		xmlFreeParserCtxt(ctxt);
		if (!ret) {
		    xmlFreeDoc(doc);
		    doc = NULL;
		}
	    }
	} else if (recovery) {
	    doc = xmlRecoverFile(filename);
	} else if (htmlout) {
	    int ret;
	    xmlParserCtxtPtr ctxt;
	    xmlSAXHandler silent, *old;

	    ctxt = xmlCreateFileParserCtxt(filename);
	    memcpy(&silent, ctxt->sax, sizeof(silent));
	    old = ctxt->sax;
	    silent.error = xmlHTMLError;
	    if (xmlGetWarningsDefaultValue)
		silent.warning = xmlHTMLWarning;
	    else 
		silent.warning = NULL;
	    silent.fatalError = xmlHTMLError;
            ctxt->sax = &silent;
	    ctxt->vctxt.error = xmlHTMLValidityError;
	    if (xmlGetWarningsDefaultValue)
		ctxt->vctxt.warning = xmlHTMLValidityWarning;
	    else 
		ctxt->vctxt.warning = NULL;

	    xmlParseDocument(ctxt);

	    ret = ctxt->wellFormed;
	    doc = ctxt->myDoc;
	    ctxt->sax = old;
	    xmlFreeParserCtxt(ctxt);
	    if (!ret) {
		xmlFreeDoc(doc);
		doc = NULL;
	    }
	} else
	    doc = xmlParseFile(filename);
#ifdef LIBXML_HTML_ENABLED
    }
#endif

#ifdef LIBXML_DEBUG_ENABLED
    /*
     * shell interraction
     */
    if (shell)  
        xmlShell(doc, filename, xmlShellReadline, stdout);
#endif

    /*
     * test intermediate copy if needed.
     */
    if (copy) {
        tmp = doc;
	doc = xmlCopyDoc(doc, 1);
	xmlFreeDoc(tmp);
    }

    if ((insert) && (!html)) {
        const xmlChar* list[256];
	int nb, i;
	xmlNodePtr node;

	if (doc->children != NULL) {
	    node = doc->children;
	    while ((node != NULL) && (node->last == NULL)) node = node->next;
	    if (node != NULL) {
		nb = xmlValidGetValidElements(node->last, NULL, list, 256);
		if (nb < 0) {
		    printf("could not get valid list of elements\n");
		} else if (nb == 0) {
		    printf("No element can be indersted under root\n");
		} else {
		    printf("%d element types can be indersted under root:\n",
		           nb);
		    for (i = 0;i < nb;i++) {
			 printf("%s\n", list[i]);
		    }
		}
	    }
	}    
    }else if (noout == 0) {
	/*
	 * print it.
	 */
#ifdef LIBXML_DEBUG_ENABLED
	if (!debug) {
#endif
	    if (compress)
		xmlSaveFile("-", doc);
	    else
		xmlDocDump(stdout, doc);
#ifdef LIBXML_DEBUG_ENABLED
	} else
	    xmlDebugDumpDocument(stdout, doc);
#endif
    }

    /*
     * A posteriori validation test
     */
    if (postvalid) {
	xmlValidCtxt cvp;
	cvp.userData = (void *) stderr;                                                 cvp.error    = (xmlValidityErrorFunc) fprintf;                                  cvp.warning  = (xmlValidityWarningFunc) fprintf;
	xmlValidateDocument(&cvp, doc);
    }

#ifdef LIBXML_DEBUG_ENABLED
    if ((debugent) && (!html))
	xmlDebugDumpEntities(stdout, doc);
#endif

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

int main(int argc, char **argv) {
    int i, count;
    int files = 0;

    for (i = 1; i < argc ; i++) {
#ifdef LIBXML_DEBUG_ENABLED
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	else if ((!strcmp(argv[i], "-debugent")) || (!strcmp(argv[i], "--debugent")))
	    debugent++;
	else if ((!strcmp(argv[i], "-shell")) ||
	         (!strcmp(argv[i], "--shell"))) {
	    shell++;
            noout = 1;
        } else 
#endif
	if ((!strcmp(argv[i], "-copy")) || (!strcmp(argv[i], "--copy")))
	    copy++;
	else if ((!strcmp(argv[i], "-recover")) ||
	         (!strcmp(argv[i], "--recover")))
	    recovery++;
	else if ((!strcmp(argv[i], "-noent")) ||
	         (!strcmp(argv[i], "--noent")))
	    noent++;
	else if ((!strcmp(argv[i], "-noout")) ||
	         (!strcmp(argv[i], "--noout")))
	    noout++;
	else if ((!strcmp(argv[i], "-htmlout")) ||
	         (!strcmp(argv[i], "--htmlout")))
	    htmlout++;
#ifdef LIBXML_HTML_ENABLED
	else if ((!strcmp(argv[i], "-html")) ||
	         (!strcmp(argv[i], "--html"))) {
	    html++;
        }
#endif /* LIBXML_HTML_ENABLED */
	else if ((!strcmp(argv[i], "-nowrap")) ||
	         (!strcmp(argv[i], "--nowrap")))
	    nowrap++;
	else if ((!strcmp(argv[i], "-valid")) ||
	         (!strcmp(argv[i], "--valid")))
	    valid++;
	else if ((!strcmp(argv[i], "-postvalid")) ||
	         (!strcmp(argv[i], "--postvalid")))
	    postvalid++;
	else if ((!strcmp(argv[i], "-insert")) ||
	         (!strcmp(argv[i], "--insert")))
	    insert++;
	else if ((!strcmp(argv[i], "-repeat")) ||
	         (!strcmp(argv[i], "--repeat")))
	    repeat++;
	else if ((!strcmp(argv[i], "-push")) ||
	         (!strcmp(argv[i], "--push")))
	    push++;
	else if ((!strcmp(argv[i], "-testIO")) ||
	         (!strcmp(argv[i], "--testIO")))
	    testIO++;
	else if ((!strcmp(argv[i], "-compress")) ||
	         (!strcmp(argv[i], "--compress"))) {
	    compress++;
	    xmlSetCompressMode(9);
        }
	else if ((!strcmp(argv[i], "-nowarning")) ||
	         (!strcmp(argv[i], "--nowarning"))) {
	    xmlGetWarningsDefaultValue = 0;
        }
	else if ((!strcmp(argv[i], "-noblanks")) ||
	         (!strcmp(argv[i], "--noblanks"))) {
	     noblanks++;
	     xmlKeepBlanksDefault(0);
        }
    }
    if (noent != 0) xmlSubstituteEntitiesDefault(1);
    if (valid != 0) xmlDoValidityCheckingDefaultValue = 1;
    if ((htmlout) && (!nowrap)) {
	fprintf(stderr,
         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"\n");
	fprintf(stderr, "\t\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n");
	fprintf(stderr,
	 "<html><head><title>%s output</title></head>\n",
		argv[0]);
	fprintf(stderr, 
	 "<body bgcolor=\"#ffffff\"><h1 align=\"center\">%s output</h1>\n",
		argv[0]);
    }
    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
	    if (repeat) {
		for (count = 0;count < 100 * repeat;count++)
		    parseAndPrintFile(argv[i]);
	    } else
		parseAndPrintFile(argv[i]);
	    files ++;
	}
    }
    if ((htmlout) && (!nowrap)) {
	fprintf(stderr, "</body></html>\n");
    }
    if (files == 0) {
	printf("Usage : %s [--debug] [--debugent] [--copy] [--recover] [--noent] [--noout] [--valid] [--repeat] XMLfiles ...\n",
	       argv[0]);
	printf("\tParse the XML files and output the result of the parsing\n");
#ifdef LIBXML_DEBUG_ENABLED
	printf("\t--debug : dump a debug tree of the in-memory document\n");
	printf("\t--shell : run a navigating shell\n");
	printf("\t--debugent : debug the entities defined in the document\n");
#endif
	printf("\t--copy : used to test the internal copy implementation\n");
	printf("\t--recover : output what was parsable on broken XML documents\n");
	printf("\t--noent : substitute entity references by their value\n");
	printf("\t--noout : don't output the result tree\n");
	printf("\t--htmlout : output results as HTML\n");
	printf("\t--nowarp : do not put HTML doc wrapper\n");
	printf("\t--valid : validate the document in addition to std well-formed check\n");
	printf("\t--postvalid : do a posteriori validation, i.e after parsing\n");
	printf("\t--repeat : repeat 100 times, for timing or profiling\n");
	printf("\t--insert : ad-hoc test for valid insertions\n");
	printf("\t--compress : turn on gzip compression of output\n");
#ifdef LIBXML_HTML_ENABLED
	printf("\t--html : use the HTML parser\n");
#endif
	printf("\t--push : use the push mode of the parser\n");
	printf("\t--nowarning : do not emit warnings from parser/validator\n");
	printf("\t--noblanks : drop (ignorable?) blanks spaces\n");
	printf("\t--testIO : test user I/O support\n");
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(0);
}
