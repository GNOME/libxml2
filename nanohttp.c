/*
 * nanohttp.c: ABI compatibility stubs for removed HTTP client
 *
 * See Copyright for the status of this software.
 */

#define IN_LIBXML
#include "libxml.h"

#ifdef LIBXML_HTTP_STUBS_ENABLED

#include <stddef.h>

#include <libxml/nanohttp.h>
#include <libxml/xmlIO.h>

/**
 * xmlNanoHTTPInit:
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPInit(void) {
}

/**
 * xmlNanoHTTPCleanup:
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPCleanup(void) {
}

/**
 * xmlNanoHTTPScanProxy:
 * @URL:  The proxy URL used to initialize the proxy context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPScanProxy(const char *URL ATTRIBUTE_UNUSED) {
}

/**
 * xmlNanoHTTPOpen:
 * @URL:  The URL to load
 * @contentType:  if available the Content-Type information will be
 *                returned at that location
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
void*
xmlNanoHTTPOpen(const char *URL ATTRIBUTE_UNUSED, char **contentType) {
    if (contentType != NULL) *contentType = NULL;
    return(NULL);
}

/**
 * xmlNanoHTTPOpenRedir:
 * @URL:  The URL to load
 * @contentType:  if available the Content-Type information will be
 *                returned at that location
 * @redir: if available the redirected URL will be returned
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
void*
xmlNanoHTTPOpenRedir(const char *URL ATTRIBUTE_UNUSED, char **contentType,
                     char **redir) {
    if (contentType != NULL) *contentType = NULL;
    if (redir != NULL) *redir = NULL;
    return(NULL);
}

/**
 * xmlNanoHTTPRead:
 * @ctx:  the HTTP context
 * @dest:  a buffer
 * @len:  the buffer length
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns -1.
 */
int
xmlNanoHTTPRead(void *ctx ATTRIBUTE_UNUSED, void *dest ATTRIBUTE_UNUSED,
                int len ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * xmlNanoHTTPClose:
 * @ctx:  the HTTP context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPClose(void *ctx ATTRIBUTE_UNUSED) {
}

/**
 * xmlNanoHTTPMethodRedir:
 * @URL:  The URL to load
 * @method:  the HTTP method to use
 * @input:  the input string if any
 * @contentType:  the Content-Type information IN and OUT
 * @redir:  the redirected URL OUT
 * @headers:  the extra headers
 * @ilen:  input length
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
void*
xmlNanoHTTPMethodRedir(const char *URL ATTRIBUTE_UNUSED,
                       const char *method ATTRIBUTE_UNUSED,
                       const char *input ATTRIBUTE_UNUSED,
                       char **contentType, char **redir,
                       const char *headers ATTRIBUTE_UNUSED,
                       int ilen ATTRIBUTE_UNUSED) {
    if (contentType != NULL) *contentType = NULL;
    if (redir != NULL) *redir = NULL;
    return(NULL);
}

/**
 * xmlNanoHTTPMethod:
 * @URL:  The URL to load
 * @method:  the HTTP method to use
 * @input:  the input string if any
 * @contentType:  the Content-Type information IN and OUT
 * @headers:  the extra headers
 * @ilen:  input length
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
void*
xmlNanoHTTPMethod(const char *URL ATTRIBUTE_UNUSED,
                  const char *method ATTRIBUTE_UNUSED,
                  const char *input ATTRIBUTE_UNUSED,
                  char **contentType, const char *headers ATTRIBUTE_UNUSED,
                  int ilen ATTRIBUTE_UNUSED) {
    if (contentType != NULL) *contentType = NULL;
    return(NULL);
}

/**
 * xmlNanoHTTPFetch:
 * @URL:  The URL to load
 * @filename:  the filename where the content should be saved
 * @contentType:  if available the Content-Type information will be
 *                returned at that location
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns -1.
 */
int
xmlNanoHTTPFetch(const char *URL ATTRIBUTE_UNUSED,
                 const char *filename ATTRIBUTE_UNUSED, char **contentType) {
    if (contentType != NULL) *contentType = NULL;
    return(-1);
}

#ifdef LIBXML_OUTPUT_ENABLED
/**
 * xmlNanoHTTPSave:
 * @ctxt:  the HTTP context
 * @filename:  the filename where the content should be saved
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns -1.
 */
int
xmlNanoHTTPSave(void *ctxt ATTRIBUTE_UNUSED,
                const char *filename ATTRIBUTE_UNUSED) {
    return(-1);
}
#endif /* LIBXML_OUTPUT_ENABLED */

/**
 * xmlNanoHTTPReturnCode:
 * @ctx:  the HTTP context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns -1.
 */
int
xmlNanoHTTPReturnCode(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * xmlNanoHTTPAuthHeader:
 * @ctx:  the HTTP context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
const char *
xmlNanoHTTPAuthHeader(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * xmlNanoHTTPContentLength:
 * @ctx:  the HTTP context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns -1.
 */
int
xmlNanoHTTPContentLength(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * xmlNanoHTTPRedir:
 * @ctx:  the HTTP context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
const char *
xmlNanoHTTPRedir(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * xmlNanoHTTPEncoding:
 * @ctx:  the HTTP context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
const char *
xmlNanoHTTPEncoding(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * xmlNanoHTTPMimeType:
 * @ctx:  the HTTP context
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
const char *
xmlNanoHTTPMimeType(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * xmlIOHTTPMatch:
 * @filename:  the URI for matching
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns 0.
 */
int
xmlIOHTTPMatch(const char *filename ATTRIBUTE_UNUSED) {
    return(0);
}

/**
 * xmlIOHTTPOpen:
 * @filename:  the URI for matching
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
void *
xmlIOHTTPOpen(const char *filename ATTRIBUTE_UNUSED) {
    return(NULL);
}

#ifdef LIBXML_OUTPUT_ENABLED
/**
 * xmlIOHTTPOpenW:
 * @post_uri:  The destination URI for the document
 * @compression:  The compression desired for the document.
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns NULL.
 */
void *
xmlIOHTTPOpenW(const char *post_uri ATTRIBUTE_UNUSED,
               int compression ATTRIBUTE_UNUSED)
{
    return(NULL);
}
#endif /* LIBXML_OUTPUT_ENABLED */

/**
 * xmlIOHTTPRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 *
 * Returns -1.
 */
int
xmlIOHTTPRead(void *context ATTRIBUTE_UNUSED, char *buffer ATTRIBUTE_UNUSED,
              int len ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * xmlIOHTTPClose:
 * @context:  the I/O context
 *
 * DEPRECATED: Internal function, don't use.
 *
 * Returns 0
 */
int
xmlIOHTTPClose (void *context ATTRIBUTE_UNUSED) {
    return 0;
}

/**
 * xmlRegisterHTTPPostCallbacks:
 *
 * DEPRECATED: HTTP support was removed in 2.15.
 */
void
xmlRegisterHTTPPostCallbacks(void) {
    xmlRegisterDefaultOutputCallbacks();
}

#endif /* LIBXML_HTTP_STUBS_ENABLED */
