/*
 * xmllint.c : a small tester program for XML input.
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#include "libxml.h"

#include <string.h>
#include <stdarg.h>

#if defined (_WIN32) && !defined(__CYGWIN__)
#ifdef _MSC_VER
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#define gettimeofday(p1,p2)
#include <time.h>
#else /* _MSC_VER */
#include <sys/time.h>
#endif /* _MSC_VER */
#else /* _WIN32 */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#endif /* _WIN32 */

#ifdef HAVE_SYS_TIMEB_H
#include <sys/timeb.h>
#endif

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
#ifdef LIBXML_CATALOG_ENABLED
#include <libxml/catalog.h>
#endif
#ifdef LIBXML_DOCB_ENABLED
#include <libxml/DOCBparser.h>
#endif
#include <libxml/globals.h>

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
#ifdef LIBXML_DOCB_ENABLED
static int sgml = 0;
#endif
static int html = 0;
static int htmlout = 0;
static int push = 0;
#ifdef HAVE_SYS_MMAN_H
static int memory = 0;
#endif
static int noblanks = 0;
static int format = 0;
static int testIO = 0;
static char *encoding = NULL;
#ifdef LIBXML_XINCLUDE_ENABLED
static int xinclude = 0;
#endif
static int dtdattrs = 0;
static int loaddtd = 0;
static int progresult = 0;
static int timing = 0;
static int generate = 0;
static int dropdtd = 0;
#ifdef LIBXML_CATALOG_ENABLED
static int catalogs = 0;
static int nocatalogs = 0;
#endif
static const char *output = NULL;


/*
 * Internal timing routines to remove the necessity to have unix-specific
 * function calls
 */

#ifndef HAVE_GETTIMEOFDAY 
#ifdef HAVE_SYS_TIMEB_H
#ifdef HAVE_SYS_TIME_H
#ifdef HAVE_FTIME

int
my_gettimeofday(struct timeval *tvp, void *tzp)
{
	struct timeb timebuffer;

	ftime(&timebuffer);
	if (tvp) {
		tvp->tv_sec = timebuffer.time;
		tvp->tv_usec = timebuffer.millitm * 1000L;
	}
	return (0);
}
#define HAVE_GETTIMEOFDAY 1
#define gettimeofday my_gettimeofday

#endif /* HAVE_FTIME */
#endif /* HAVE_SYS_TIME_H */
#endif /* HAVE_SYS_TIMEB_H */
#endif /* !HAVE_GETTIMEOFDAY */

#if defined(HAVE_GETTIMEOFDAY)
static struct timeval begin, end;

/*
 * startTimer: call where you want to start timing
 */
static void
startTimer(void)
{
    gettimeofday(&begin, NULL);
}

/*
 * endTimer: call where you want to stop timing and to print out a
 *           message about the timing performed; format is a printf
 *           type argument
 */
static void
endTimer(const char *fmt, ...)
{
    long msec;
    va_list ap;

    gettimeofday(&end, NULL);
    msec = end.tv_sec - begin.tv_sec;
    msec *= 1000;
    msec += (end.tv_usec - begin.tv_usec) / 1000;

#ifndef HAVE_STDARG_H
#error "endTimer required stdarg functions"
#endif
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, " took %ld ms\n", msec);
}
#elif defined(HAVE_TIME_H)
/*
 * No gettimeofday function, so we have to make do with calling clock.
 * This is obviously less accurate, but there's little we can do about
 * that.
 */
#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC 100
#endif

static clock_t begin, end;
static void
startTimer(void)
{
    begin = clock();
}
static void
endTimer(const char *fmt, ...)
{
    long msec;
    va_list ap;

    end = clock();
    msec = ((end - begin) * 1000) / CLOCKS_PER_SEC;

#ifndef HAVE_STDARG_H
#error "endTimer required stdarg functions"
#endif
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, " took %ld ms\n", msec);
}
#else

/*
 * We don't have a gettimeofday or time.h, so we just don't do timing
 */
static void
startTimer(void)
{
    /*
     * Do nothing
     */
}
static void
endTimer(char *format, ...)
{
    /*
     * We cannot do anything because we don't have a timing function
     */
#ifdef HAVE_STDARG_H
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fprintf(stderr, " was not timed\n", msec);
#else
    /* We don't have gettimeofday, time or stdarg.h, what crazy world is
     * this ?!
     */
#endif
}
#endif
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
    int len;
    xmlGenericError(xmlGenericErrorContext, "<p>");

    len = strlen(buffer);
    if (input != NULL) {
	if (input->filename) {
	    snprintf(&buffer[len], sizeof(buffer) - len, "%s:%d: ", input->filename,
		    input->line);
	} else {
	    snprintf(&buffer[len], sizeof(buffer) - len, "Entity: line %d: ", input->line);
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
    int len;
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
	len = strlen(buffer);
        snprintf(&buffer[len], sizeof(buffer) - len, "%c", 
		    (unsigned char) *cur++);
	n++;
    }
    len = strlen(buffer);
    snprintf(&buffer[len], sizeof(buffer) - len, "\n");
    cur = input->cur;
    while ((*cur == '\n') || (*cur == '\r'))
	cur--;
    n = 0;
    while ((cur != base) && (n++ < 80)) {
	len = strlen(buffer);
        snprintf(&buffer[len], sizeof(buffer) - len, " ");
        base++;
    }
    len = strlen(buffer);
    snprintf(&buffer[len], sizeof(buffer) - len, "^\n");
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
    int len;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input != NULL) && (input->filename == NULL) && (ctxt->inputNr > 1)) {
	cur = input;
        input = ctxt->inputTab[ctxt->inputNr - 2];
    }
        
    xmlHTMLPrintFileInfo(input);

    xmlGenericError(xmlGenericErrorContext, "<b>error</b>: ");
    va_start(args, msg);
    len = strlen(buffer);
    vsnprintf(&buffer[len],  sizeof(buffer) - len, msg, args);
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
    int len;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input != NULL) && (input->filename == NULL) && (ctxt->inputNr > 1)) {
	cur = input;
        input = ctxt->inputTab[ctxt->inputNr - 2];
    }
        

    xmlHTMLPrintFileInfo(input);
        
    xmlGenericError(xmlGenericErrorContext, "<b>warning</b>: ");
    va_start(args, msg);
    len = strlen(buffer);    
    vsnprintf(&buffer[len],  sizeof(buffer) - len, msg, args);
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
    int len;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];
        
    xmlHTMLPrintFileInfo(input);

    xmlGenericError(xmlGenericErrorContext, "<b>validity error</b>: ");
    len = strlen(buffer);
    va_start(args, msg);
    vsnprintf(&buffer[len],  sizeof(buffer) - len, msg, args);
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
    int len;

    buffer[0] = 0;
    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];

    xmlHTMLPrintFileInfo(input);
        
    xmlGenericError(xmlGenericErrorContext, "<b>validity warning</b>: ");
    va_start(args, msg);
    len = strlen(buffer); 
    vsnprintf(&buffer[len],  sizeof(buffer) - len, msg, args);
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
    char *ret;
    int len;

    if (prompt != NULL)
	fprintf(stdout, "%s", prompt);
    if (!fgets(line_read, 500, stdin))
        return(NULL);
    line_read[500] = 0;
    len = strlen(line_read);
    ret = (char *) malloc(len + 1);
    if (ret != NULL) {
	memcpy (ret, line_read, len + 1);
    }
    return(ret);
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
	startTimer();
    

    if (filename == NULL) {
	if (generate) {
	    xmlNodePtr n;

	    doc = xmlNewDoc(BAD_CAST "1.0");
	    n = xmlNewNode(NULL, BAD_CAST "info");
	    xmlNodeSetContent(n, BAD_CAST "abc");
	    xmlDocSetRootElement(doc, n);
	}
    }
#ifdef LIBXML_DOCB_ENABLED
    /*
     * build an SGML tree from a string;
     */
    else if ((sgml) && (push)) {
	FILE *f;

	f = fopen(filename, "r");
	if (f != NULL) {
	    int res, size = 3;
	    char chars[4096];
	    docbParserCtxtPtr ctxt;

	    /* if (repeat) */
		size = 4096;
	    res = fread(chars, 1, 4, f);
	    if (res > 0) {
		ctxt = docbCreatePushParserCtxt(NULL, NULL,
			    chars, res, filename, 0);
		while ((res = fread(chars, 1, size, f)) > 0) {
		    docbParseChunk(ctxt, chars, res, 0);
		}
		docbParseChunk(ctxt, chars, 0, 1);
		doc = ctxt->myDoc;
		docbFreeParserCtxt(ctxt);
	    }
	    fclose(f);
	}
    } else if (sgml) {	
	doc = docbParseFile(filename, NULL);
    }
#endif
#ifdef LIBXML_HTML_ENABLED
    else if (html) {
	doc = htmlParseFile(filename, NULL);
    }
#endif /* LIBXML_HTML_ENABLED */
    else {
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
	      /* If xmlCreateFileParserCtxt() return NULL something
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
    }

    /*
     * If we don't have a document we might as well give up.  Do we
     * want an error message here?  <sven@zen.org> */
    if (doc == NULL) {
	progresult = 1;
	return;
    }

    if ((timing) && (!repeat)) {
	endTimer("Parsing");
    }

    /*
     * Remove DOCTYPE nodes
     */
    if (dropdtd) {
	xmlDtdPtr dtd;

	dtd = xmlGetIntSubset(doc);
	if (dtd != NULL) {
	    xmlUnlinkNode((xmlNodePtr)dtd);
	    xmlFreeDtd(dtd);
	}
    }

#ifdef LIBXML_XINCLUDE_ENABLED
    if (xinclude) {
	if ((timing) && (!repeat)) {
	    startTimer();
	}
	xmlXIncludeProcess(doc);
	if ((timing) && (!repeat)) {
	    endTimer("Xinclude processing");
	}
    }
#endif

#ifdef LIBXML_DEBUG_ENABLED
    /*
     * shell interaction
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
		    printf("No element can be inserted under root\n");
		} else {
		    printf("%d element types can be inserted under root:\n",
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
		startTimer();
	    }
#ifdef HAVE_SYS_MMAN_H
	    if (memory) {
		xmlChar *result;
		int len;

		if (encoding != NULL) {
		    if ( format ) {
		        xmlDocDumpFormatMemoryEnc(doc, &result, &len, encoding, 1);
		    } else { 
			xmlDocDumpMemoryEnc(doc, &result, &len, encoding);
		    }
		} else {
		    if (format)
			xmlDocDumpFormatMemory(doc, &result, &len, 1);
		    else
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
	    if (compress) {
		xmlSaveFile(output ? output : "-", doc);
	    }
	    else if (encoding != NULL) {
	        if ( format ) {
		    xmlSaveFormatFileEnc(output ? output : "-", doc, encoding, 1);
		}
		else {
		    xmlSaveFileEnc(output ? output : "-", doc, encoding);
		}
	    }
	    else if (format) {
		xmlSaveFormatFile(output ? output : "-", doc, 1);
	    }
	    else {
		FILE *out;
		if (output == NULL)
		    out = stdout;
		else {
		    out = fopen(output,"wb");
		}
		xmlDocDump(out, doc);

		if (output)
		    fclose(out);
	    }
	    if ((timing) && (!repeat)) {
		endTimer("Saving");
	    }
#ifdef LIBXML_DEBUG_ENABLED
	} else {
	    FILE *out;
	    if (output == NULL)
	        out = stdout;
	    else {
		out = fopen(output,"wb");
	    }
	    xmlDebugDumpDocument(out, doc);

	    if (output)
		fclose(out);
	}
#endif
    }

    /*
     * A posteriori validation test
     */
    if (dtdvalid != NULL) {
	xmlDtdPtr dtd;

	if ((timing) && (!repeat)) {
	    startTimer();
	}
	dtd = xmlParseDTD(NULL, (const xmlChar *)dtdvalid); 
	if ((timing) && (!repeat)) {
	    endTimer("Parsing DTD");
	}
	if (dtd == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "Could not parse DTD %s\n", dtdvalid);
	    progresult = 2;
	} else {
	    xmlValidCtxt cvp;
	    if ((timing) && (!repeat)) {
		startTimer();
	    }
	    cvp.userData = (void *) stderr;
	    cvp.error    = (xmlValidityErrorFunc) fprintf;
	    cvp.warning  = (xmlValidityWarningFunc) fprintf;
	    if (!xmlValidateDtd(&cvp, doc, dtd)) {
		xmlGenericError(xmlGenericErrorContext,
			"Document %s does not validate against %s\n",
			filename, dtdvalid);
		progresult = 3;
	    }
	    if ((timing) && (!repeat)) {
		endTimer("Validating against DTD");
	    }
	    xmlFreeDtd(dtd);
	}
    } else if (postvalid) {
	xmlValidCtxt cvp;
	if ((timing) && (!repeat)) {
	    startTimer();
	}
	cvp.userData = (void *) stderr;
	cvp.error    = (xmlValidityErrorFunc) fprintf;
	cvp.warning  = (xmlValidityWarningFunc) fprintf;
	if (!xmlValidateDocument(&cvp, doc)) {
	    xmlGenericError(xmlGenericErrorContext,
		    "Document %s does not validate\n", filename);
	    progresult = 3;
	}
	if ((timing) && (!repeat)) {
	    endTimer("Validating");
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
	startTimer();
    }
    xmlFreeDoc(doc);
    if ((timing) && (!repeat)) {
	endTimer("Freeing");
    }
}

/************************************************************************
 * 									*
 * 			Usage and Main					*
 * 									*
 ************************************************************************/

static void showVersion(const char *name) {
    fprintf(stderr, "%s: using libxml version %s\n", name, xmlParserVersion);
    fprintf(stderr, "   compiled with: ");
#ifdef LIBXML_FTP_ENABLED
    fprintf(stderr, "FTP ");
#endif
#ifdef LIBXML_HTTP_ENABLED
    fprintf(stderr, "HTTP ");
#endif
#ifdef LIBXML_HTML_ENABLED
    fprintf(stderr, "HTML ");
#endif
#ifdef LIBXML_C14N_ENABLED
    fprintf(stderr, "C14N ");
#endif
#ifdef LIBXML_CATALOG_ENABLED
    fprintf(stderr, "Catalog ");
#endif
#ifdef LIBXML_DOCB_ENABLED
    fprintf(stderr, "DocBook ");
#endif
#ifdef LIBXML_XPATH_ENABLED
    fprintf(stderr, "XPath ");
#endif
#ifdef LIBXML_XPTR_ENABLED
    fprintf(stderr, "XPointer ");
#endif
#ifdef LIBXML_XINCLUDE_ENABLED
    fprintf(stderr, "XInclude ");
#endif
#ifdef LIBXML_ICONV_ENABLED
    fprintf(stderr, "Iconv ");
#endif
#ifdef DEBUG_MEMORY_LOCATION
    fprintf(stderr, "MemDebug ");
#endif
#ifdef LIBXML_UNICODE_ENABLED
    fprintf(stderr, "Unicode ");
#endif
#ifdef LIBXML_REGEXP_ENABLED
    fprintf(stderr, "Regexps ");
#endif
#ifdef LIBXML_AUTOMATA_ENABLED
    fprintf(stderr, "Automata ");
#endif
#ifdef LIBXML_SCHEMAS_ENABLED
    fprintf(stderr, "Schemas ");
#endif
    fprintf(stderr, "\n");
}

static void usage(const char *name) {
    printf("Usage : %s [options] XMLfiles ...\n", name);
    printf("\tParse the XML files and output the result of the parsing\n");
    printf("\t--version : display the version of the XML library used\n");
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
    printf("\t--nowrap : do not put HTML doc wrapper\n");
    printf("\t--valid : validate the document in addition to std well-formed check\n");
    printf("\t--postvalid : do a posteriori validation, i.e after parsing\n");
    printf("\t--dtdvalid URL : do a posteriori validation against a given DTD\n");
    printf("\t--timing : print some timings\n");
    printf("\t--output file or -o file: save to a given file\n");
    printf("\t--repeat : repeat 100 times, for timing or profiling\n");
    printf("\t--insert : ad-hoc test for valid insertions\n");
#ifdef HAVE_ZLIB_H
    printf("\t--compress : turn on gzip compression of output\n");
#endif
#ifdef LIBXML_DOCB_ENABLED
    printf("\t--sgml : use the DocBook SGML parser\n");
#endif
#ifdef LIBXML_HTML_ENABLED
    printf("\t--html : use the HTML parser\n");
#endif
    printf("\t--push : use the push mode of the parser\n");
#ifdef HAVE_SYS_MMAN_H
    printf("\t--memory : parse from memory\n");
#endif
    printf("\t--nowarning : do not emit warnings from parser/validator\n");
    printf("\t--noblanks : drop (ignorable?) blanks spaces\n");
    printf("\t--format : reformat/reindent the input\n");
    printf("\t--testIO : test user I/O support\n");
    printf("\t--encode encoding : output in the given encoding\n");
#ifdef LIBXML_CATALOG_ENABLED
    printf("\t--catalogs : use SGML catalogs from $SGML_CATALOG_FILES\n");
    printf("\t             otherwise XML Catalogs starting from \n");
    printf("\t         file:///etc/xml/catalog are activated by default\n");
    printf("\t--nocatalogs: deactivate all catalogs\n");
#endif
    printf("\t--auto : generate a small doc on the fly\n");
#ifdef LIBXML_XINCLUDE_ENABLED
    printf("\t--xinclude : do XInclude processing\n");
#endif
    printf("\t--loaddtd : fetch external DTD\n");
    printf("\t--dtdattr : loaddtd + populate the tree with inherited attributes \n");
    printf("\t--dropdtd : remove the DOCTYPE of the input docs\n");
    printf("\nLibxml project home page: http://xmlsoft.org/\n");
    printf("To report bugs or get some help check: http://xmlsoft.org/bugs.html\n");
}
int
main(int argc, char **argv) {
    int i, count;
    int files = 0;
    int version = 0;

    if (argc <= 1) {
	usage(argv[0]);
	return(1);
    }
    LIBXML_TEST_VERSION
    for (i = 1; i < argc ; i++) {
	if (!strcmp(argv[i], "-"))
	    break;

	if (argv[i][0] != '-')
	    continue;
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
	else if ((!strcmp(argv[i], "-version")) ||
	         (!strcmp(argv[i], "--version"))) {
	    showVersion(argv[0]);
	    version = 1;
	} else if ((!strcmp(argv[i], "-noout")) ||
	         (!strcmp(argv[i], "--noout")))
	    noout++;
	else if ((!strcmp(argv[i], "-o")) ||
	         (!strcmp(argv[i], "-output")) ||
	         (!strcmp(argv[i], "--output"))) {
	    i++;
	    output = argv[i];
	}
	else if ((!strcmp(argv[i], "-htmlout")) ||
	         (!strcmp(argv[i], "--htmlout")))
	    htmlout++;
#ifdef LIBXML_DOCB_ENABLED
        else if ((!strcmp(argv[i], "-sgml")) ||
		 (!strcmp(argv[i], "--sgml"))) {
	    sgml++;
	}
#endif
#ifdef LIBXML_HTML_ENABLED
	else if ((!strcmp(argv[i], "-html")) ||
	         (!strcmp(argv[i], "--html"))) {
	    html++;
        }
#endif /* LIBXML_HTML_ENABLED */
	else if ((!strcmp(argv[i], "-nowrap")) ||
	         (!strcmp(argv[i], "--nowrap")))
	    nowrap++;
	else if ((!strcmp(argv[i], "-loaddtd")) ||
	         (!strcmp(argv[i], "--loaddtd")))
	    loaddtd++;
	else if ((!strcmp(argv[i], "-dtdattr")) ||
	         (!strcmp(argv[i], "--dtdattr"))) {
	    loaddtd++;
	    dtdattrs++;
	} else if ((!strcmp(argv[i], "-valid")) ||
	         (!strcmp(argv[i], "--valid")))
	    valid++;
	else if ((!strcmp(argv[i], "-postvalid")) ||
	         (!strcmp(argv[i], "--postvalid"))) {
	    postvalid++;
	    loaddtd++;
	} else if ((!strcmp(argv[i], "-dtdvalid")) ||
	         (!strcmp(argv[i], "--dtdvalid"))) {
	    i++;
	    dtdvalid = argv[i];
	    loaddtd++;
        }
	else if ((!strcmp(argv[i], "-dropdtd")) ||
	         (!strcmp(argv[i], "--dropdtd")))
	    dropdtd++;
	else if ((!strcmp(argv[i], "-insert")) ||
	         (!strcmp(argv[i], "--insert")))
	    insert++;
	else if ((!strcmp(argv[i], "-timing")) ||
	         (!strcmp(argv[i], "--timing")))
	    timing++;
	else if ((!strcmp(argv[i], "-auto")) ||
	         (!strcmp(argv[i], "--auto")))
	    generate++;
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
#ifdef HAVE_ZLIB_H
	else if ((!strcmp(argv[i], "-compress")) ||
	         (!strcmp(argv[i], "--compress"))) {
	    compress++;
	    xmlSetCompressMode(9);
        }
#endif
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
#ifdef LIBXML_CATALOG_ENABLED
	else if ((!strcmp(argv[i], "-catalogs")) ||
		 (!strcmp(argv[i], "--catalogs"))) {
	    catalogs++;
	} else if ((!strcmp(argv[i], "-nocatalogs")) ||
		 (!strcmp(argv[i], "--nocatalogs"))) {
	    nocatalogs++;
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
	else if ((!strcmp(argv[i], "-format")) ||
	         (!strcmp(argv[i], "--format"))) {
	     noblanks++;
	     format++;
	     xmlKeepBlanksDefault(0);
	} else {
	    fprintf(stderr, "Unknown option %s\n", argv[i]);
	    usage(argv[0]);
	    return(1);
	}
    }

#ifdef LIBXML_CATALOG_ENABLED
    if (nocatalogs == 0) {
	if (catalogs) {
	    const char *catal;

	    catal = getenv("SGML_CATALOG_FILES");
	    if (catal != NULL) {
		xmlLoadCatalogs(catal);
	    } else {
		fprintf(stderr, "Variable $SGML_CATALOG_FILES not set\n");
	    }
	}
    }
#endif
    xmlLineNumbersDefault(1);
    if (loaddtd != 0)
	xmlLoadExtDtdDefaultValue |= XML_DETECT_IDS;
    if (dtdattrs)
	xmlLoadExtDtdDefaultValue |= XML_COMPLETE_ATTRS;
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
        } else if ((!strcmp(argv[i], "-o")) ||
                   (!strcmp(argv[i], "-output")) ||
                   (!strcmp(argv[i], "--output"))) {
            i++;
	    continue;
        }
	if ((!strcmp(argv[i], "-dtdvalid")) ||
	         (!strcmp(argv[i], "--dtdvalid"))) {
	    i++;
	    continue;
        }
	if ((timing) && (repeat))
	    startTimer();
	/* Remember file names.  "-" means stdin.  <sven@zen.org> */
	if ((argv[i][0] != '-') || (strcmp(argv[i], "-") == 0)) {
	    if (repeat) {
		for (count = 0;count < 100 * repeat;count++)
		    parseAndPrintFile(argv[i]);
	    } else
		parseAndPrintFile(argv[i]);
	    files ++;
	    if ((timing) && (repeat)) {
		endTimer("100 iterations");
	    }
	}
    }
    if (generate) 
	parseAndPrintFile(NULL);
    if ((htmlout) && (!nowrap)) {
	xmlGenericError(xmlGenericErrorContext, "</body></html>\n");
    }
    if ((files == 0) && (!generate) && (version == 0)) {
	usage(argv[0]);
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(progresult);
}

