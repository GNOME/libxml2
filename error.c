/*
 * error.c: module displaying errors
 */

#include <stdio.h>
#include <stdarg.h>
#include "parser.h"

/*
 * Display and format error messages.
 */
void xmlParserError(xmlParserCtxtPtr ctxt, const char *msg, ...) {
    const CHAR *cur, *base;
    va_list args;
    int n;

    va_start(args, msg);
    if (ctxt->input->filename)
        fprintf(stderr, "%s:%d: ", ctxt->input->filename,
	        ctxt->input->line);
    else
        fprintf(stderr, "line %d: ", ctxt->input->line);
        
    fprintf(stderr, "error: ");
    vfprintf(stderr, msg, args);
    va_end(ap);
    cur = ctxt->input->cur;
    base = ctxt->input->base;
    while ((*cur == '\n') || (*cur == '\r')) {
	cur--;
	base--;
    }
    n = 0;
    while ((n++ < 60) && (cur >= base) && (*cur != '\n') && (*cur != '\r'))
        cur--;
    if ((*cur == '\n') || (*cur == '\r')) cur++;
    base = cur;
    n = 0;
    while ((*cur != 0) && (*cur != '\n') && (*cur != '\r') && (n < 79)) {
        fprintf(stderr, "%c", (unsigned char) *cur++);
	n++;
    }
    fprintf(stderr, "\n");
    cur = ctxt->input->cur;
    while ((*cur == '\n') || (*cur == '\r'))
	cur--;
    n = 0;
    while ((cur != base) && (n++ < 60)) {
        fprintf(stderr, " ");
        base++;
    }
    fprintf(stderr,"^\n");
}

/*
 * Display and format error messages.
 */
void xmlParserWarning(xmlParserCtxtPtr ctxt, const char *msg, ...) {
    const CHAR *cur, *base;
    va_list args;
    int n;

    va_start(args, msg);
    if (ctxt->input->filename)
        fprintf(stderr, "%s:%d: ", ctxt->input->filename,
	        ctxt->input->line);
    else
        fprintf(stderr, "line %d: ", ctxt->input->line);
        
    fprintf(stderr, "warning: ");
    vfprintf(stderr, msg, args);
    va_end(ap);
    cur = ctxt->input->cur;
    base = ctxt->input->base;
    n = 0;
    while ((n++ < 60) && (cur >= base) && (*cur != '\n') && (*cur != '\r'))
        cur--;
    if ((*cur != '\n') || (*cur != '\r')) cur++;
    base = cur;
    n = 0;
    while ((*cur != 0) && (*cur != '\n') && (*cur != '\r') && (n < 79)) {
        fprintf(stderr, "%c", (unsigned char) *cur++);
	n++;
    }
    fprintf(stderr, "\n");
    cur = ctxt->input->cur;
    n = 0;
    while ((cur != base) && (n++ < 60)) {
        fprintf(stderr, " ");
        base++;
    }
    fprintf(stderr,"^\n");
}
