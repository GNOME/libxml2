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
#include <sys/time.h>


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
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
/* seems needed for Solaris */
#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif
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
#include <libxml/xmlerror.h>
#ifdef LIBXML_XINCLUDE_ENABLED
#include <libxml/xinclude.h>
#endif

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
static char * dtdvalid = NULL;
static int repeat = 0;
static int insert = 0;
static int compress = 0;
static int html = 0;
static int htmlout = 0;
static int push = 0;
#ifdef HAVE_SYS_MMAN_H
static int memory = 0;
#endif
static int noblanks = 0;
static int testIO = 0;
static char *encoding = NULL;
#ifdef LIBXML_XINCLUDE_ENABLED
static int xinclude = 0;
#endif
static int progresult = 0;
static int timing = 0;
static struct timeval begin, end;


#ifdef VMS
extern int xmlDoValidityCheckingDefaultVal;
#define xmlDoValidityCheckingDefaultValue xmlDoValidityCheckingDefaultVal
#else
extern int xmlDoValidityCheckingDefaultValue;
#endif
extern int xmlGetWarningsDefaultValue;

/************************************************************************
 * 									*
 * 			HTML ouput					*
 * 									*
 ************************************************************************/
char buffer[50000];

static void
xmlHTMLEncodeSend(void) {
    char *result;

    result = (char *) xmlEncodeEntitiesReentrant(NULL, BAD_CAST buffer);
    if (result) {
	xmlGenericError(xmlGenericErrorContext, "%s", result);
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

static void
xmlHTMLPrintFileInfo(xmlParserInputPtr input) {
    xmlGenericError(xmlGenericErrorContext, "<p>");
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

static void
xmlHTMLPrintFileContext(xmlParserInputPtr input) {
    const xmlChar *cur, *base;
    int n;

    if (input == NULL) return;
    xmlGenericError(xmlGenericErrorContext, "<pre>\n");
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
    xmlGenericError(xmlGenericErrorContext, "</pre>");
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
static void
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

    xmlGenericError(xmlGenericErrorContext, "<b>error</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    xmlGenericError(xmlGenericErrorContext, "</p>\n");

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
static void
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
        
    xmlGenericError(xmlGenericErrorContext, "<b>warning</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    xmlGenericError(xmlGenericErrorContext, "</p>\n");

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
static void
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

    xmlGenericError(xmlGenericErrorContext, "<b>validity error</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    xmlGenericError(xmlGenericErrorContext, "</p>\n");

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
static void
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
        
    xmlGenericError(xmlGenericErrorContext, "<b>validity warning</b>: ");
    va_start(args, msg);
    vsprintf(&buffer[strlen(buffer)], msg, args);
    va_end(args);
    xmlHTMLEncodeSend();
    xmlGenericError(xmlGenericErrorContext, "</p>\n");

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
static char *
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

static int myRead(FILE *f, char * buf, int len) {
    return(fread(buf, 1, len, f));
}
static void myClose(FILE *f) {
  if (f != stdin) {
    fclose(f);
  }
}

/************************************************************************
 * 									*
 * 			Test processing					*
 * 									*
 ************************************************************************/
static void parseAndPrintFile(char *filename) {
    xmlDocPtr doc = NULL, tmp;

    if ((timing) && (!repeat))
	gettimeofday(&begin, NULL);
    

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

	    /* '-' Usually means stdin -<sven@zen.org> */
	    if ((filename[0] == '-') && (filename[1] == 0)) {
	      f = stdin;
	    } else {
	      f = fopen(filename, "r");
	    }
	    if (f != NULL) {
		int ret;
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
		    ret = ctxt->wellFormed;
		    xmlFreeParserCtxt(ctxt);
		    if (!ret) {
			xmlFreeDoc(doc);
			doc = NULL;
		    }
	        }
	    }
	} else if (testIO) {
	    int ret;
	    FILE *f;

	    /* '-' Usually means stdin -<sven@zen.org> */
	    if ((filename[0] == '-') && (filename[1] == 0)) {
	      f = stdin;
	    } else {
	      f = fopen(filename, "r");
	    }
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

	    if (ctxt == NULL) {	      
	      /* If xmlCreateFileParseCtxt() return NULL something
		 strange happened so we don't want to do anything.  Do
		 we want to print an error message here?
		 <sven@zen.org> */
	      doc = NULL;
	    } else {
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
	    }
#ifdef HAVE_SYS_MMAN_H
	} else if (memory) {
	    int fd;
	    struct stat info;
	    const char *base;
	    if (stat(filename, &info) < 0) 
		return;
	    if ((fd = open(filename, O_RDONLY)) < 0)
		return;
	    base = mmap(NULL, info.st_size, PROT_READ, MAP_SHARED, fd, 0) ;
	    if (base == (void *) MAP_FAILED)
	        return;

	    doc = xmlParseMemory((char *) base, info.st_size);
	    munmap((char *) base, info.st_size);
#endif
	} else
	    doc = xmlParseFile(filename);
#ifdef LIBXML_HTML_ENABLED
    }
#endif

    /*
     * If we don't have a document we might as well give up.  Do we
     * want an error message here?  <sven@zen.org> */
    if (doc == NULL) {
	progresult = 1;
	return;
    }

    if ((timing) && (!repeat)) {
	long msec;
	gettimeofday(&end, NULL);
	msec = end.tv_sec - begin.tv_sec;
	msec *= 1000;
	msec += (end.tv_usec - begin.tv_usec) / 1000;
	fprintf(stderr, "Parsing took %ld ms\n", msec);
    }

#ifdef LIBXML_XINCLUDE_ENABLED
    if (xinclude) {
	if ((timing) && (!repeat)) {
	    gettimeofday(&begin, NULL);
	}
	xmlXIncludeProcess(doc);
	if ((timing) && (!repeat)) {
	    long msec;
	    gettimeofday(&end, NULL);
	    msec = end.tv_sec - begin.tv_sec;
	    msec *= 1000;
	    msec += (end.tv_usec - begin.tv_usec) / 1000;
	    fprintf(stderr, "Xinclude processing took %ld ms\n", msec);
	}
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
	    if ((timing) && (!repeat)) {
		gettimeofday(&begin, NULL);
	    }
#ifdef HAVE_SYS_MMAN_H
	    if (memory) {
		xmlChar *result;
		int len;

		if (encoding != NULL) {
		    xmlDocDumpMemoryEnc(doc, &result, &len, encoding);
		} else {
		    xmlDocDumpMemory(doc, &result, &len);
		}
		if (result == NULL) {
		    fprintf(stderr, "Failed to save\n");
		} else {
		    write(1, result, len);
		    xmlFree(result);
		}
	    } else
#endif /* HAVE_SYS_MMAN_H */
	    if (compress)
		xmlSaveFile("-", doc);
	    else if (encoding != NULL)
	        xmlSaveFileEnc("-", doc, encoding);
	    else
		xmlDocDump(stdout, doc);
	    if ((timing) && (!repeat)) {
		long msec;
		gettimeofday(&end, NULL);
		msec = end.tv_sec - begin.tv_sec;
		msec *= 1000;
		msec += (end.tv_usec - begin.tv_usec) / 1000;
		fprintf(stderr, "Saving took %ld ms\n", msec);
	    }
#ifdef LIBXML_DEBUG_ENABLED
	} else {
	    xmlDebugDumpDocument(stdout, doc);
	}
#endif
    }

    /*
     * A posteriori validation test
     */
    if (dtdvalid != NULL) {
	xmlDtdPtr dtd;

	if ((timing) && (!repeat)) {
	    gettimeofday(&begin, NULL);
	}
	dtd = xmlParseDTD(NULL, (const xmlChar *)dtdvalid); 
	if ((timing) && (!repeat)) {
	    long msec;
	    gettimeofday(&end, NULL);
	    msec = end.tv_sec - begin.tv_sec;
	    msec *= 1000;
	    msec += (end.tv_usec - begin.tv_usec) / 1000;
	    fprintf(stderr, "Parsing DTD took %ld ms\n", msec);
	}
	if (dtd == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "Could not parse DTD %s\n", dtdvalid);
	    progresult = 2;
	} else {
	    xmlValidCtxt cvp;
	    if ((timing) && (!repeat)) {
		gettimeofday(&begin, NULL);
	    }
	    cvp.userData = (void *) stderr;                                                 cvp.error    = (xmlValidityErrorFunc) fprintf;                                  cvp.warning  = (xmlValidityWarningFunc) fprintf;
	    if (!xmlValidateDtd(&cvp, doc, dtd)) {
		xmlGenericError(xmlGenericErrorContext,
			"Document %s does not validate against %s\n",
			filename, dtdvalid);
		progresult = 3;
	    }
	    if ((timing) && (!repeat)) {
		long msec;
		gettimeofday(&end, NULL);
		msec = end.tv_sec - begin.tv_sec;
		msec *= 1000;
		msec += (end.tv_usec - begin.tv_usec) / 1000;
		fprintf(stderr, "Validating against DTD took %ld ms\n", msec);
	    }
	    xmlFreeDtd(dtd);
	}
    } else if (postvalid) {
	xmlValidCtxt cvp;
	if ((timing) && (!repeat)) {
	    gettimeofday(&begin, NULL);
	}
	cvp.userData = (void *) stderr;                                                 cvp.error    = (xmlValidityErrorFunc) fprintf;                                  cvp.warning  = (xmlValidityWarningFunc) fprintf;
	if (!xmlValidateDocument(&cvp, doc)) {
	    xmlGenericError(xmlGenericErrorContext,
		    "Document %s does not validate\n", filename);
	    progresult = 3;
	}
	if ((timing) && (!repeat)) {
	    long msec;
	    gettimeofday(&end, NULL);
	    msec = end.tv_sec - begin.tv_sec;
	    msec *= 1000;
	    msec += (end.tv_usec - begin.tv_usec) / 1000;
	    fprintf(stderr, "Validating took %ld ms\n", msec);
	}
    }

#ifdef LIBXML_DEBUG_ENABLED
    if ((debugent) && (!html))
	xmlDebugDumpEntities(stderr, doc);
#endif

    /*
     * free it.
     */
    if ((timing) && (!repeat)) {
	gettimeofday(&begin, NULL);
    }
    xmlFreeDoc(doc);
    if ((timing) && (!repeat)) {
	long msec;
	gettimeofday(&end, NULL);
	msec = end.tv_sec - begin.tv_sec;
	msec *= 1000;
	msec += (end.tv_usec - begin.tv_usec) / 1000;
	fprintf(stderr, "Freeing took %ld ms\n", msec);
    }
}

int
main(int argc, char **argv) {
    int i, count;
    int files = 0;

    LIBXML_TEST_VERSION
    for (i = 1; i < argc ; i++) {
#ifdef LIBXML_DEBUG_ENABLED
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
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
	else if ((!strcmp(argv[i], "-dtdvalid")) ||
	         (!strcmp(argv[i], "--dtdvalid"))) {
	    i++;
	    dtdvalid = argv[i];
        }
	else if ((!strcmp(argv[i], "-insert")) ||
	         (!strcmp(argv[i], "--insert")))
	    insert++;
	else if ((!strcmp(argv[i], "-timing")) ||
	         (!strcmp(argv[i], "--timing")))
	    timing++;
	else if ((!strcmp(argv[i], "-repeat")) ||
	         (!strcmp(argv[i], "--repeat")))
	    repeat++;
	else if ((!strcmp(argv[i], "-push")) ||
	         (!strcmp(argv[i], "--push")))
	    push++;
#ifdef HAVE_SYS_MMAN_H
	else if ((!strcmp(argv[i], "-memory")) ||
	         (!strcmp(argv[i], "--memory")))
	    memory++;
#endif
	else if ((!strcmp(argv[i], "-testIO")) ||
	         (!strcmp(argv[i], "--testIO")))
	    testIO++;
#ifdef LIBXML_XINCLUDE_ENABLED
	else if ((!strcmp(argv[i], "-xinclude")) ||
	         (!strcmp(argv[i], "--xinclude")))
	    xinclude++;
#endif
	else if ((!strcmp(argv[i], "-compress")) ||
	         (!strcmp(argv[i], "--compress"))) {
	    compress++;
	    xmlSetCompressMode(9);
        }
	else if ((!strcmp(argv[i], "-nowarning")) ||
	         (!strcmp(argv[i], "--nowarning"))) {
	    xmlGetWarningsDefaultValue = 0;
	    xmlPedanticParserDefault(0);
        }
	else if ((!strcmp(argv[i], "-pedantic")) ||
	         (!strcmp(argv[i], "--pedantic"))) {
	    xmlGetWarningsDefaultValue = 1;
	    xmlPedanticParserDefault(1);
        }
#ifdef LIBXML_DEBUG_ENABLED
	else if ((!strcmp(argv[i], "-debugent")) ||
		 (!strcmp(argv[i], "--debugent"))) {
	    debugent++;
	    xmlParserDebugEntities = 1;
	} 
#endif
	else if ((!strcmp(argv[i], "-encode")) ||
	         (!strcmp(argv[i], "--encode"))) {
	    i++;
	    encoding = argv[i];
	    /*
	     * OK it's for testing purposes
	     */
	    xmlAddEncodingAlias("UTF-8", "DVEnc");
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
	xmlGenericError(xmlGenericErrorContext,
         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"\n");
	xmlGenericError(xmlGenericErrorContext,
		"\t\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n");
	xmlGenericError(xmlGenericErrorContext,
	 "<html><head><title>%s output</title></head>\n",
		argv[0]);
	xmlGenericError(xmlGenericErrorContext, 
	 "<body bgcolor=\"#ffffff\"><h1 align=\"center\">%s output</h1>\n",
		argv[0]);
    }
    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-encode")) ||
	         (!strcmp(argv[i], "--encode"))) {
	    i++;
	    continue;
        }
	if ((!strcmp(argv[i], "-dtdvalid")) ||
	         (!strcmp(argv[i], "--dtdvalid"))) {
	    i++;
	    continue;
        }
	if ((timing) && (repeat))
	    gettimeofday(&begin, NULL);
	/* Remember file names.  "-" means stding.  <sven@zen.org> */
	if ((argv[i][0] != '-') || (strcmp(argv[i], "-") == 0)) {
	    if (repeat) {
		for (count = 0;count < 100 * repeat;count++)
		    parseAndPrintFile(argv[i]);
	    } else
		parseAndPrintFile(argv[i]);
	    files ++;
	}
	if ((timing) && (repeat)) {
	    long msec;
	    gettimeofday(&end, NULL);
	    msec = end.tv_sec - begin.tv_sec;
	    msec *= 1000;
	    msec += (end.tv_usec - begin.tv_usec) / 1000;
	    fprintf(stderr, "100 iteration took %ld ms\n", msec);
	}
    }
    if ((htmlout) && (!nowrap)) {
	xmlGenericError(xmlGenericErrorContext, "</body></html>\n");
    }
    if (files == 0) {
	printf("Usage : %s [options] XMLfiles ...\n",
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
	printf("\t--dtdvalid URL : do a posteriori validation against a given DTD\n");
	printf("\t--timing : print some timings\n");
	printf("\t--repeat : repeat 100 times, for timing or profiling\n");
	printf("\t--insert : ad-hoc test for valid insertions\n");
	printf("\t--compress : turn on gzip compression of output\n");
#ifdef LIBXML_HTML_ENABLED
	printf("\t--html : use the HTML parser\n");
#endif
	printf("\t--push : use the push mode of the parser\n");
#ifdef HAVE_SYS_MMAN_H
	printf("\t--memory : parse from memory\n");
#endif
	printf("\t--nowarning : do not emit warnings from parser/validator\n");
	printf("\t--noblanks : drop (ignorable?) blanks spaces\n");
	printf("\t--testIO : test user I/O support\n");
	printf("\t--encode encoding : output in the given encoding\n");
#ifdef LIBXML_XINCLUDE_ENABLED
	printf("\t--xinclude : do XInclude processing\n");
#endif
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(progresult);
}

