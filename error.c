/*
 * error.c: module displaying/handling XML parser errors
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#include <stdio.h>
#include <stdarg.h>
#include "parser.h"

static void
xmlParserPrintFileInfo(xmlParserInputPtr input) {
    if (input != NULL) {
	if (input->filename)
	    fprintf(stderr, "%s:%d: ", input->filename,
		    input->line);
	else
	    fprintf(stderr, "line %d: ", input->line);
    }
}

static void
xmlParserPrintFileContext(xmlParserInputPtr input) {
    const CHAR *cur, *base;
    int n;

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
        fprintf(stderr, "%c", (unsigned char) *cur++);
	n++;
    }
    fprintf(stderr, "\n");
    cur = input->cur;
    while ((*cur == '\n') || (*cur == '\r'))
	cur--;
    n = 0;
    while ((cur != base) && (n++ < 80)) {
        fprintf(stderr, " ");
        base++;
    }
    fprintf(stderr,"^\n");
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
    xmlParserInputPtr input;
    va_list args;

    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];
        
    xmlParserPrintFileInfo(input);

    fprintf(stderr, "error: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    xmlParserPrintFileContext(input);
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
    xmlParserInputPtr input;
    va_list args;

    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];

    xmlParserPrintFileInfo(input);
        
    fprintf(stderr, "warning: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    xmlParserPrintFileContext(input);
}

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
    xmlParserInputPtr input;
    va_list args;

    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];
        
    xmlParserPrintFileInfo(input);

    fprintf(stderr, "validity error: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    xmlParserPrintFileContext(input);
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
    xmlParserInputPtr input;
    va_list args;

    input = ctxt->input;
    if ((input->filename == NULL) && (ctxt->inputNr > 1))
        input = ctxt->inputTab[ctxt->inputNr - 2];

    xmlParserPrintFileInfo(input);
        
    fprintf(stderr, "validity warning: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    xmlParserPrintFileContext(input);
}

