/*
 * error.c: module displaying/handling XML parser errors
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <libxml/parser.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlmemory.h>

/************************************************************************
 * 									*
 * 			Handling of out of context errors		*
 * 									*
 ************************************************************************/

/**
 * xmlGenericErrorDefaultFunc:
 * @ctx:  an error context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Default handler for out of context error messages.
 */
void
xmlGenericErrorDefaultFunc(void *ctx, const char *msg, ...) {
    va_list args;

    if (xmlGenericErrorContext == NULL)
	xmlGenericErrorContext = (void *) stderr;

    va_start(args, msg);
    vfprintf((FILE *)xmlGenericErrorContext, msg, args);
    va_end(args);
}

xmlGenericErrorFunc xmlGenericError = xmlGenericErrorDefaultFunc;
void *xmlGenericErrorContext = NULL;


/**
 * xmlSetGenericErrorFunc:
 * @ctx:  the new error handling context
 * @handler:  the new handler function
 *
 * Function to reset the handler and the error context for out of
 * context error messages.
 * This simply means that @handler will be called for subsequent
 * error messages while not parsing nor validating. And @ctx will
 * be passed as first argument to @handler
 * One can simply force messages to be emitted to another FILE * than
 * stderr by setting @ctx to this file handle and @handler to NULL.
 */
void
xmlSetGenericErrorFunc(void *ctx, xmlGenericErrorFunc handler) {
    xmlGenericErrorContext = ctx;
    if (handler != NULL)
	xmlGenericError = handler;
    else
	xmlGenericError = xmlGenericErrorDefaultFunc;
}

/************************************************************************
 * 									*
 * 			Handling of parsing errors			*
 * 									*
 ************************************************************************/

/**
 * xmlParserPrintFileInfo:
 * @input:  an xmlParserInputPtr input
 * 
 * Displays the associated file and line informations for the current input
 */

void
xmlParserPrintFileInfo(xmlParserInputPtr input) {
    if (input != NULL) {
	if (input->filename)
	    xmlGenericError(xmlGenericErrorContext,
		    "%s:%d: ", input->filename,
		    input->line);
	else
	    xmlGenericError(xmlGenericErrorContext,
		    "Entity: line %d: ", input->line);
    }
}

/**
 * xmlParserPrintFileContext:
 * @input:  an xmlParserInputPtr input
 * 
 * Displays current context within the input content for error tracking
 */

void
xmlParserPrintFileContext(xmlParserInputPtr input) {
    const xmlChar *cur, *base;
    int n;

    if (input == NULL) return;
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
        xmlGenericError(xmlGenericErrorContext,
		"%c", (unsigned char) *cur++);
	n++;
    }
    xmlGenericError(xmlGenericErrorContext, "\n");
    cur = input->cur;
    while ((*cur == '\n') || (*cur == '\r'))
	cur--;
    n = 0;
    while ((cur != base) && (n++ < 80)) {
        xmlGenericError(xmlGenericErrorContext, " ");
        base++;
    }
    xmlGenericError(xmlGenericErrorContext,"^\n");
}

/**
 * xmlGetVarStr:
 * @msg:  the message format
 * @args:  a va_list argument list
 *
 * SGS contribution
 * Get an arbitrary-sized string for an error argument
 * The caller must free() the returned string
 */
char *
xmlGetVarStr(const char * msg, va_list args) {
    int       size;
    int       length;
    int       chars, left;
    char      *str, *larger;

    str = (char *) xmlMalloc(100);
    if (str == NULL)
      return(NULL);

    size = 100;
    length = 0;

    while (1) {
	left = size - length;
		    /* Try to print in the allocated space. */
	chars = vsnprintf(str + length, left, msg, args);
			  /* If that worked, we're done. */
	if ((chars > -1) && (chars < left ))
	    break;
			  /* Else try again with more space. */
	if (chars > -1)         /* glibc 2.1 */
	    size += chars + 1;  /* precisely what is needed */
	else                    /* glibc 2.0 */
	    size += 100;
	if ((larger = (char *) xmlRealloc(str, size)) == NULL) {
	    xmlFree(str);
	    return(NULL);
	}
	str = larger;
    }
    return(str);
}

/**
 * xmlParserError:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format an error messages, gives file, line, position and
 * extra parameters.
 */
void
xmlParserError(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input = NULL;
    xmlParserInputPtr cur = NULL;
    char * str;
    va_list args;

    if (ctxt != NULL) {
	input = ctxt->input;
	if ((input != NULL) && (input->filename == NULL) &&
	    (ctxt->inputNr > 1)) {
	    cur = input;
	    input = ctxt->inputTab[ctxt->inputNr - 2];
	}
	xmlParserPrintFileInfo(input);
    }

    xmlGenericError(xmlGenericErrorContext, "error: ");
    va_start(args, msg);
    str = xmlGetVarStr(msg, args);
    va_end(args);
    xmlGenericError(xmlGenericErrorContext, str);
    if (str != NULL)
	xmlFree(str);

    if (ctxt != NULL) {
	xmlParserPrintFileContext(input);
	if (cur != NULL) {
	    xmlParserPrintFileInfo(cur);
	    xmlGenericError(xmlGenericErrorContext, "\n");
	    xmlParserPrintFileContext(cur);
	}
    }
}

/**
 * xmlParserWarning:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format a warning messages, gives file, line, position and
 * extra parameters.
 */
void
xmlParserWarning(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input = NULL;
    xmlParserInputPtr cur = NULL;
    char * str;
    va_list args;

    if (ctxt != NULL) {
	input = ctxt->input;
	if ((input != NULL) && (input->filename == NULL) &&
	    (ctxt->inputNr > 1)) {
	    cur = input;
	    input = ctxt->inputTab[ctxt->inputNr - 2];
	}
	xmlParserPrintFileInfo(input);
    }
        
    xmlGenericError(xmlGenericErrorContext, "warning: ");
    va_start(args, msg);
    str = xmlGetVarStr(msg, args);
    va_end(args);
    xmlGenericError(xmlGenericErrorContext, str);
    if (str != NULL)
	xmlFree(str);

    if (ctxt != NULL) {
	xmlParserPrintFileContext(input);
	if (cur != NULL) {
	    xmlParserPrintFileInfo(cur);
	    xmlGenericError(xmlGenericErrorContext, "\n");
	    xmlParserPrintFileContext(cur);
	}
    }
}

/************************************************************************
 * 									*
 * 			Handling of validation errors			*
 * 									*
 ************************************************************************/

/**
 * xmlParserValidityError:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format an validity error messages, gives file,
 * line, position and extra parameters.
 */
void
xmlParserValidityError(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input = NULL;
    char * str;
    va_list args;

    if (ctxt != NULL) {
	input = ctxt->input;
	if ((input->filename == NULL) && (ctxt->inputNr > 1))
	    input = ctxt->inputTab[ctxt->inputNr - 2];
	    
	xmlParserPrintFileInfo(input);
    }

    xmlGenericError(xmlGenericErrorContext, "validity error: ");
    va_start(args, msg);
    str = xmlGetVarStr(msg, args);
    va_end(args);
    xmlGenericError(xmlGenericErrorContext, str);
    if (str != NULL)
	xmlFree(str);

    if (ctxt != NULL) {
	xmlParserPrintFileContext(input);
    }
}

/**
 * xmlParserValidityWarning:
 * @ctx:  an XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 * 
 * Display and format a validity warning messages, gives file, line,
 * position and extra parameters.
 */
void
xmlParserValidityWarning(void *ctx, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserInputPtr input = NULL;
    char * str;
    va_list args;

    if (ctxt != NULL) {
	input = ctxt->input;
	if ((input->filename == NULL) && (ctxt->inputNr > 1))
	    input = ctxt->inputTab[ctxt->inputNr - 2];

	xmlParserPrintFileInfo(input);
    }
        
    xmlGenericError(xmlGenericErrorContext, "validity warning: ");
    va_start(args, msg);
    str = xmlGetVarStr(msg, args);
    va_end(args);
    xmlGenericError(xmlGenericErrorContext, str);
    if (str != NULL)
	xmlFree(str);

    if (ctxt != NULL) {
	xmlParserPrintFileContext(input);
    }
}


