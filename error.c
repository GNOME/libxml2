/*
 * error.c: module displaying/handling XML parser errors
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <daniel@veillard.com>
 */

#define IN_LIBXML
#include "libxml.h"

#include <string.h>
#include <stdarg.h>
#include <libxml/parser.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlmemory.h>

#include "private/error.h"
#include "private/string.h"

/************************************************************************
 *									*
 *			Error struct					*
 *									*
 ************************************************************************/

static int
xmlVSetError(xmlError *err,
             void *ctxt, xmlNodePtr node,
             int domain, int code, xmlErrorLevel level,
             const char *file, int line,
             const char *str1, const char *str2, const char *str3,
             int int1, int col,
             const char *fmt, va_list ap)
{
    char *message = NULL;
    char *fileCopy = NULL;
    char *str1Copy = NULL;
    char *str2Copy = NULL;
    char *str3Copy = NULL;

    if (code == XML_ERR_OK) {
        xmlResetError(err);
        return(0);
    }

    /*
     * Formatting the message
     */
    if (fmt == NULL) {
        message = xmlMemStrdup("No error message provided");
    } else {
        xmlChar *tmp;
        int res;

        res = xmlStrVASPrintf(&tmp, MAX_ERR_MSG_SIZE, fmt, ap);
        if (res < 0)
            goto err_memory;
        message = (char *) tmp;
    }
    if (message == NULL)
        goto err_memory;

    if (file != NULL) {
        fileCopy = (char *) xmlStrdup((const xmlChar *) file);
        if (fileCopy == NULL)
            goto err_memory;
    }
    if (str1 != NULL) {
        str1Copy = (char *) xmlStrdup((const xmlChar *) str1);
        if (str1Copy == NULL)
            goto err_memory;
    }
    if (str2 != NULL) {
        str2Copy = (char *) xmlStrdup((const xmlChar *) str2);
        if (str2Copy == NULL)
            goto err_memory;
    }
    if (str3 != NULL) {
        str3Copy = (char *) xmlStrdup((const xmlChar *) str3);
        if (str3Copy == NULL)
            goto err_memory;
    }

    xmlResetError(err);

    err->domain = domain;
    err->code = code;
    err->message = message;
    err->level = level;
    err->file = fileCopy;
    err->line = line;
    err->str1 = str1Copy;
    err->str2 = str2Copy;
    err->str3 = str3Copy;
    err->int1 = int1;
    err->int2 = col;
    err->node = node;
    err->ctxt = ctxt;

    return(0);

err_memory:
    xmlFree(message);
    xmlFree(fileCopy);
    xmlFree(str1Copy);
    xmlFree(str2Copy);
    xmlFree(str3Copy);
    return(-1);
}

static int LIBXML_ATTR_FORMAT(14,15)
xmlSetError(xmlError *err,
            void *ctxt, xmlNodePtr node,
            int domain, int code, xmlErrorLevel level,
            const char *file, int line,
            const char *str1, const char *str2, const char *str3,
            int int1, int col,
            const char *fmt, ...)
{
    va_list ap;
    int res;

    va_start(ap, fmt);
    res = xmlVSetError(err, ctxt, node, domain, code, level, file, line,
                       str1, str2, str3, int1, col, fmt, ap);
    va_end(ap);

    return(res);
}

static int
xmlVUpdateError(xmlError *err,
                void *ctxt, xmlNodePtr node,
                int domain, int code, xmlErrorLevel level,
                const char *file, int line,
                const char *str1, const char *str2, const char *str3,
                int int1, int col,
                const char *fmt, va_list ap)
{
    int res;

    /*
     * Find first element parent.
     */
    if (node != NULL) {
        int i;

        for (i = 0; i < 10; i++) {
            if ((node->type == XML_ELEMENT_NODE) ||
                (node->parent == NULL))
                break;
            node = node->parent;
        }
    }

    /*
     * Get file and line from node.
     */
    if (node != NULL) {
        if ((file == NULL) && (node->doc != NULL))
            file = (const char *) node->doc->URL;

        if (line == 0) {
            if (node->type == XML_ELEMENT_NODE)
                line = node->line;
            if ((line == 0) || (line == 65535))
                line = xmlGetLineNo(node);
        }
    }

    res = xmlVSetError(err, ctxt, node, domain, code, level, file, line,
                       str1, str2, str3, int1, col, fmt, ap);

    return(res);
}

/************************************************************************
 *									*
 *			Handling of out of context errors		*
 *									*
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
xmlGenericErrorDefaultFunc(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...) {
    va_list args;

    if (xmlGenericErrorContext == NULL)
	xmlGenericErrorContext = (void *) stderr;

    va_start(args, msg);
    vfprintf((FILE *)xmlGenericErrorContext, msg, args);
    va_end(args);
}

/**
 * initGenericErrorDefaultFunc:
 * @handler:  the handler
 *
 * DEPRECATED: Use xmlSetGenericErrorFunc.
 *
 * Set or reset (if NULL) the default handler for generic errors
 * to the builtin error function.
 */
void
initGenericErrorDefaultFunc(xmlGenericErrorFunc * handler)
{
    if (handler == NULL)
        xmlGenericError = xmlGenericErrorDefaultFunc;
    else
        xmlGenericError = (*handler);
}

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
 * For multi-threaded applications, this must be set separately for each thread.
 */
void
xmlSetGenericErrorFunc(void *ctx, xmlGenericErrorFunc handler) {
    xmlGenericErrorContext = ctx;
    if (handler != NULL)
	xmlGenericError = handler;
    else
	xmlGenericError = xmlGenericErrorDefaultFunc;
}

/**
 * xmlSetStructuredErrorFunc:
 * @ctx:  the new error handling context
 * @handler:  the new handler function
 *
 * Function to reset the handler and the error context for out of
 * context structured error messages.
 * This simply means that @handler will be called for subsequent
 * error messages while not parsing nor validating. And @ctx will
 * be passed as first argument to @handler
 * For multi-threaded applications, this must be set separately for each thread.
 */
void
xmlSetStructuredErrorFunc(void *ctx, xmlStructuredErrorFunc handler) {
    xmlStructuredErrorContext = ctx;
    xmlStructuredError = handler;
}

/************************************************************************
 *									*
 *			Handling of parsing errors			*
 *									*
 ************************************************************************/

/**
 * xmlParserPrintFileInfo:
 * @input:  an xmlParserInputPtr input
 *
 * Displays the associated file and line information for the current input
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
 * xmlParserPrintFileContextInternal:
 * @input:  an xmlParserInputPtr input
 *
 * Displays current context within the input content for error tracking
 */

static void
xmlParserPrintFileContextInternal(xmlParserInputPtr input ,
		xmlGenericErrorFunc channel, void *data ) {
    const xmlChar *cur, *base, *start;
    unsigned int n, col;	/* GCC warns if signed, because compared with sizeof() */
    xmlChar  content[81]; /* space for 80 chars + line terminator */
    xmlChar *ctnt;

    if ((input == NULL) || (input->cur == NULL))
        return;

    cur = input->cur;
    base = input->base;
    /* skip backwards over any end-of-lines */
    while ((cur > base) && ((*(cur) == '\n') || (*(cur) == '\r'))) {
	cur--;
    }
    n = 0;
    /* search backwards for beginning-of-line (to max buff size) */
    while ((n < sizeof(content) - 1) && (cur > base) &&
	   (*cur != '\n') && (*cur != '\r')) {
        cur--;
        n++;
    }
    if ((n > 0) && ((*cur == '\n') || (*cur == '\r'))) {
        cur++;
    } else {
        /* skip over continuation bytes */
        while ((cur < input->cur) && ((*cur & 0xC0) == 0x80))
            cur++;
    }
    /* calculate the error position in terms of the current position */
    col = input->cur - cur;
    /* search forward for end-of-line (to max buff size) */
    n = 0;
    start = cur;
    /* copy selected text to our buffer */
    while ((*cur != 0) && (*(cur) != '\n') && (*(cur) != '\r')) {
        int len = input->end - cur;
        int c = xmlGetUTF8Char(cur, &len);

        if ((c < 0) || (n + len > sizeof(content)-1))
            break;
        cur += len;
	n += len;
    }
    memcpy(content, start, n);
    content[n] = 0;
    /* print out the selected text */
    channel(data ,"%s\n", content);
    /* create blank line with problem pointer */
    n = 0;
    ctnt = content;
    /* (leave buffer space for pointer + line terminator) */
    while ((n<col) && (n++ < sizeof(content)-2) && (*ctnt != 0)) {
	if (*(ctnt) != '\t')
	    *(ctnt) = ' ';
	ctnt++;
    }
    *ctnt++ = '^';
    *ctnt = 0;
    channel(data ,"%s\n", content);
}

/**
 * xmlParserPrintFileContext:
 * @input:  an xmlParserInputPtr input
 *
 * Displays current context within the input content for error tracking
 */
void
xmlParserPrintFileContext(xmlParserInputPtr input) {
   xmlParserPrintFileContextInternal(input, xmlGenericError,
                                     xmlGenericErrorContext);
}

/**
 * xmlReportError:
 * @err: the error
 * @ctx: the parser context or NULL
 * @str: the formatted error message
 *
 * Report an error with its context, replace the 4 old error/warning
 * routines.
 */
static void
xmlReportError(xmlParserCtxtPtr ctxt, const xmlError *err)
{
    xmlGenericErrorFunc channel;
    void *data;
    const char *message;
    const char *file;
    int line;
    int code;
    int domain;
    const xmlChar *name = NULL;
    xmlNodePtr node;
    xmlErrorLevel level;
    xmlParserInputPtr input = NULL;
    xmlParserInputPtr cur = NULL;

    if (err == NULL) {
        if (ctxt == NULL)
            return;
        err = &ctxt->lastError;
    }

    channel = xmlGenericError;
    data = xmlGenericErrorContext;

    message = err->message;
    file = err->file;
    line = err->line;
    code = err->code;
    domain = err->domain;
    level = err->level;
    node = err->node;

    if (code == XML_ERR_OK)
        return;

    if ((node != NULL) && (node->type == XML_ELEMENT_NODE))
        name = node->name;

    /*
     * Maintain the compatibility with the legacy error handling
     */
    if ((ctxt != NULL) && (ctxt->input != NULL)) {
        input = ctxt->input;
        if ((input->filename == NULL) &&
            (ctxt->inputNr > 1)) {
            cur = input;
            input = ctxt->inputTab[ctxt->inputNr - 2];
        }
        if (input->filename)
            channel(data, "%s:%d: ", input->filename, input->line);
        else if ((line != 0) && (domain == XML_FROM_PARSER))
            channel(data, "Entity: line %d: ", input->line);
    } else {
        if (file != NULL)
            channel(data, "%s:%d: ", file, line);
        else if ((line != 0) &&
	         ((domain == XML_FROM_PARSER) || (domain == XML_FROM_SCHEMASV)||
		  (domain == XML_FROM_SCHEMASP)||(domain == XML_FROM_DTD) ||
		  (domain == XML_FROM_RELAXNGP)||(domain == XML_FROM_RELAXNGV)))
            channel(data, "Entity: line %d: ", line);
    }
    if (name != NULL) {
        channel(data, "element %s: ", name);
    }
    switch (domain) {
        case XML_FROM_PARSER:
            channel(data, "parser ");
            break;
        case XML_FROM_NAMESPACE:
            channel(data, "namespace ");
            break;
        case XML_FROM_DTD:
        case XML_FROM_VALID:
            channel(data, "validity ");
            break;
        case XML_FROM_HTML:
            channel(data, "HTML parser ");
            break;
        case XML_FROM_MEMORY:
            channel(data, "memory ");
            break;
        case XML_FROM_OUTPUT:
            channel(data, "output ");
            break;
        case XML_FROM_IO:
            channel(data, "I/O ");
            break;
        case XML_FROM_XINCLUDE:
            channel(data, "XInclude ");
            break;
        case XML_FROM_XPATH:
            channel(data, "XPath ");
            break;
        case XML_FROM_XPOINTER:
            channel(data, "parser ");
            break;
        case XML_FROM_REGEXP:
            channel(data, "regexp ");
            break;
        case XML_FROM_MODULE:
            channel(data, "module ");
            break;
        case XML_FROM_SCHEMASV:
            channel(data, "Schemas validity ");
            break;
        case XML_FROM_SCHEMASP:
            channel(data, "Schemas parser ");
            break;
        case XML_FROM_RELAXNGP:
            channel(data, "Relax-NG parser ");
            break;
        case XML_FROM_RELAXNGV:
            channel(data, "Relax-NG validity ");
            break;
        case XML_FROM_CATALOG:
            channel(data, "Catalog ");
            break;
        case XML_FROM_C14N:
            channel(data, "C14N ");
            break;
        case XML_FROM_XSLT:
            channel(data, "XSLT ");
            break;
        case XML_FROM_I18N:
            channel(data, "encoding ");
            break;
        case XML_FROM_SCHEMATRONV:
            channel(data, "schematron ");
            break;
        case XML_FROM_BUFFER:
            channel(data, "internal buffer ");
            break;
        case XML_FROM_URI:
            channel(data, "URI ");
            break;
        default:
            break;
    }
    switch (level) {
        case XML_ERR_NONE:
            channel(data, ": ");
            break;
        case XML_ERR_WARNING:
            channel(data, "warning : ");
            break;
        case XML_ERR_ERROR:
            channel(data, "error : ");
            break;
        case XML_ERR_FATAL:
            channel(data, "error : ");
            break;
    }
    if (message != NULL) {
        int len;
	len = xmlStrlen((const xmlChar *) message);
	if ((len > 0) && (message[len - 1] != '\n'))
	    channel(data, "%s\n", message);
	else
	    channel(data, "%s", message);
    } else {
        channel(data, "%s\n", "No error message provided");
    }

    if (ctxt != NULL) {
        xmlParserPrintFileContextInternal(input, channel, data);
        if (cur != NULL) {
            if (cur->filename)
                channel(data, "%s:%d: \n", cur->filename, cur->line);
            else if ((line != 0) && (domain == XML_FROM_PARSER))
                channel(data, "Entity: line %d: \n", cur->line);
            xmlParserPrintFileContextInternal(cur, channel, data);
        }
    }
    if ((domain == XML_FROM_XPATH) && (err->str1 != NULL) &&
        (err->int1 < 100) &&
	(err->int1 < xmlStrlen((const xmlChar *)err->str1))) {
	xmlChar buf[150];
	int i;

	channel(data, "%s\n", err->str1);
	for (i=0;i < err->int1;i++)
	     buf[i] = ' ';
	buf[i++] = '^';
	buf[i] = 0;
	channel(data, "%s\n", buf);
    }
}

/**
 * xmlRaiseMemoryError:
 * @schannel: the structured callback channel
 * @channel: the old callback channel
 * @data: the callback data
 * @domain: the domain for the error
 * @error: optional error struct to be filled
 *
 * Update the global and optional error structure, then forward the
 * error to an error handler.
 *
 * This function doesn't make memory allocations which are likely
 * to fail after an OOM error.
 */
void
xmlRaiseMemoryError(xmlStructuredErrorFunc schannel, xmlGenericErrorFunc channel,
                    void *data, int domain, xmlError *error)
{
    xmlError *lastError = &xmlLastError;

    xmlResetLastError();
    lastError->domain = domain;
    lastError->code = XML_ERR_NO_MEMORY;
    lastError->level = XML_ERR_FATAL;

    if (error != NULL) {
        xmlResetError(error);
        error->domain = domain;
        error->code = XML_ERR_NO_MEMORY;
        error->level = XML_ERR_FATAL;
    }

    if (schannel != NULL) {
        schannel(data, lastError);
    } else if (xmlStructuredError != NULL) {
        xmlStructuredError(xmlStructuredErrorContext, lastError);
    } else if (channel != NULL) {
        channel(data, "libxml2: out of memory\n");
    }
}

/**
 * xmlVRaiseError:
 * @schannel: the structured callback channel
 * @channel: the old callback channel
 * @data: the callback data
 * @ctx: the parser context or NULL
 * @ctx: the parser context or NULL
 * @domain: the domain for the error
 * @code: the code for the error
 * @level: the xmlErrorLevel for the error
 * @file: the file source of the error (or NULL)
 * @line: the line of the error or 0 if N/A
 * @str1: extra string info
 * @str2: extra string info
 * @str3: extra string info
 * @int1: extra int info
 * @col: column number of the error or 0 if N/A
 * @msg:  the message to display/transmit
 * @ap:  extra parameters for the message display
 *
 * Update the appropriate global or contextual error structure,
 * then forward the error message down the parser or generic
 * error callback handler
 *
 * Returns 0 on success, -1 if a memory allocation failed.
 */
int
xmlVRaiseError(xmlStructuredErrorFunc schannel,
               xmlGenericErrorFunc channel, void *data, void *ctx,
               xmlNode *node, int domain, int code, xmlErrorLevel level,
               const char *file, int line, const char *str1,
               const char *str2, const char *str3, int int1, int col,
               const char *msg, va_list ap)
{
    xmlParserCtxtPtr ctxt = NULL;
    /* xmlLastError is a macro retrieving the per-thread global. */
    xmlErrorPtr lastError = &xmlLastError;
    xmlErrorPtr to = lastError;

    if (code == XML_ERR_OK)
        return(0);
    if ((xmlGetWarningsDefaultValue == 0) && (level == XML_ERR_WARNING))
        return(0);

    if ((domain == XML_FROM_PARSER) || (domain == XML_FROM_HTML) ||
        (domain == XML_FROM_DTD) || (domain == XML_FROM_NAMESPACE) ||
	(domain == XML_FROM_IO) || (domain == XML_FROM_VALID)) {
	ctxt = (xmlParserCtxtPtr) ctx;

        if (ctxt != NULL)
            to = &ctxt->lastError;
    }

    if (xmlVUpdateError(to, ctxt, node, domain, code, level, file, line,
                        str1, str2, str3, int1, col, msg, ap))
        return(-1);

    if (to != lastError) {
        if (xmlCopyError(to, lastError) < 0)
            return(-1);
    }

    if (schannel != NULL) {
	schannel(data, to);
    } else if (xmlStructuredError != NULL) {
        xmlStructuredError(xmlStructuredErrorContext, to);
    } else if ((ctxt == NULL) && (channel == NULL)) {
	xmlGenericError(xmlGenericErrorContext, "%s", to->message);
    } else if (channel != NULL) {
	channel(data, "%s", to->message);
    }

    return(0);
}

/**
 * __xmlRaiseError:
 * @schannel: the structured callback channel
 * @channel: the old callback channel
 * @data: the callback data
 * @ctx: the parser context or NULL
 * @nod: the node or NULL
 * @domain: the domain for the error
 * @code: the code for the error
 * @level: the xmlErrorLevel for the error
 * @file: the file source of the error (or NULL)
 * @line: the line of the error or 0 if N/A
 * @str1: extra string info
 * @str2: extra string info
 * @str3: extra string info
 * @int1: extra int info
 * @col: column number of the error or 0 if N/A
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Update the appropriate global or contextual error structure,
 * then forward the error message down the parser or generic
 * error callback handler
 *
 * Returns 0 on success, -1 if a memory allocation failed.
 */
int
__xmlRaiseError(xmlStructuredErrorFunc schannel,
                xmlGenericErrorFunc channel, void *data, void *ctx,
                xmlNode *node, int domain, int code, xmlErrorLevel level,
                const char *file, int line, const char *str1,
                const char *str2, const char *str3, int int1, int col,
                const char *msg, ...)
{
    va_list ap;
    int res;

    va_start(ap, msg);
    res = xmlVRaiseError(schannel, channel, data, ctx, node, domain, code,
                         level, file, line, str1, str2, str3, int1, col, msg,
                         ap);
    va_end(ap);

    return(res);
}

/**
 * __xmlSimpleError:
 * @domain: where the error comes from
 * @code: the error code
 * @node: the context node
 * @extra:  extra information
 *
 * Handle an out of memory condition
 */
void
__xmlSimpleError(int domain, int code, xmlNodePtr node,
                 const char *msg, const char *extra)
{

    if (code == XML_ERR_NO_MEMORY) {
	if (extra)
	    __xmlRaiseError(NULL, NULL, NULL, NULL, node, domain,
			    XML_ERR_NO_MEMORY, XML_ERR_FATAL, NULL, 0, extra,
			    NULL, NULL, 0, 0,
			    "Memory allocation failed : %s\n", extra);
	else
	    __xmlRaiseError(NULL, NULL, NULL, NULL, node, domain,
			    XML_ERR_NO_MEMORY, XML_ERR_FATAL, NULL, 0, NULL,
			    NULL, NULL, 0, 0, "Memory allocation failed\n");
    } else {
	__xmlRaiseError(NULL, NULL, NULL, NULL, node, domain,
			code, XML_ERR_ERROR, NULL, 0, extra,
			NULL, NULL, 0, 0, msg, extra);
    }
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
xmlParserError(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlReportError(ctx, NULL);
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
xmlParserWarning(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlReportError(ctx, NULL);
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
xmlParserValidityError(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlReportError(ctx, NULL);
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
xmlParserValidityWarning(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlReportError(ctx, NULL);
}


/************************************************************************
 *									*
 *			Extended Error Handling				*
 *									*
 ************************************************************************/

/**
 * xmlGetLastError:
 *
 * Get the last global error registered. This is per thread if compiled
 * with thread support.
 *
 * Returns a pointer to the error
 */
const xmlError *
xmlGetLastError(void)
{
    if (xmlLastError.code == XML_ERR_OK)
        return (NULL);
    return (&xmlLastError);
}

/**
 * xmlResetError:
 * @err: pointer to the error.
 *
 * Cleanup the error.
 */
void
xmlResetError(xmlErrorPtr err)
{
    if (err == NULL)
        return;
    if (err->code == XML_ERR_OK)
        return;
    if (err->message != NULL)
        xmlFree(err->message);
    if (err->file != NULL)
        xmlFree(err->file);
    if (err->str1 != NULL)
        xmlFree(err->str1);
    if (err->str2 != NULL)
        xmlFree(err->str2);
    if (err->str3 != NULL)
        xmlFree(err->str3);
    memset(err, 0, sizeof(xmlError));
    err->code = XML_ERR_OK;
}

/**
 * xmlResetLastError:
 *
 * Cleanup the last global error registered. For parsing error
 * this does not change the well-formedness result.
 */
void
xmlResetLastError(void)
{
    if (xmlLastError.code == XML_ERR_OK)
        return;
    xmlResetError(&xmlLastError);
}

/**
 * xmlCtxtGetLastError:
 * @ctx:  an XML parser context
 *
 * Get the last parsing error registered.
 *
 * Returns NULL if no error occurred or a pointer to the error
 */
const xmlError *
xmlCtxtGetLastError(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt == NULL)
        return (NULL);
    if (ctxt->lastError.code == XML_ERR_OK)
        return (NULL);
    return (&ctxt->lastError);
}

/**
 * xmlCtxtResetLastError:
 * @ctx:  an XML parser context
 *
 * Cleanup the last global error registered. For parsing error
 * this does not change the well-formedness result.
 */
void
xmlCtxtResetLastError(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt == NULL)
        return;
    ctxt->errNo = XML_ERR_OK;
    if (ctxt->lastError.code == XML_ERR_OK)
        return;
    xmlResetError(&ctxt->lastError);
}

/**
 * xmlCopyError:
 * @from:  a source error
 * @to:  a target error
 *
 * Save the original error to the new place.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
xmlCopyError(const xmlError *from, xmlErrorPtr to) {
    const char *fmt = NULL;

    if ((from == NULL) || (to == NULL))
        return(-1);

    if (from->message != NULL)
        fmt = "%s";

    return(xmlSetError(to, from->ctxt, from->node,
                       from->domain, from->code, from->level,
                       from->file, from->line,
                       from->str1, from->str2, from->str3,
                       from->int1, from->int2,
                       fmt, from->message));
}

