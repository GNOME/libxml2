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
 * @deprecated HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPInit(void) {
}

/**
 * @deprecated HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPCleanup(void) {
}

/**
 * @param URL  The proxy URL used to initialize the proxy context
 *
 * @deprecated HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPScanProxy(const char *URL ATTRIBUTE_UNUSED) {
}

/**
 * @param URL  The URL to load
 * @param contentType  if available the Content-Type information will be
 *                returned at that location
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
void*
xmlNanoHTTPOpen(const char *URL ATTRIBUTE_UNUSED, char **contentType) {
    if (contentType != NULL) *contentType = NULL;
    return(NULL);
}

/**
 * @param URL  The URL to load
 * @param contentType  if available the Content-Type information will be
 *                returned at that location
 * @param redir  if available the redirected URL will be returned
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
void*
xmlNanoHTTPOpenRedir(const char *URL ATTRIBUTE_UNUSED, char **contentType,
                     char **redir) {
    if (contentType != NULL) *contentType = NULL;
    if (redir != NULL) *redir = NULL;
    return(NULL);
}

/**
 * @param ctx  the HTTP context
 * @param dest  a buffer
 * @param len  the buffer length
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns -1.
 */
int
xmlNanoHTTPRead(void *ctx ATTRIBUTE_UNUSED, void *dest ATTRIBUTE_UNUSED,
                int len ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * @param ctx  the HTTP context
 *
 * @deprecated HTTP support was removed in 2.15.
 */
void
xmlNanoHTTPClose(void *ctx ATTRIBUTE_UNUSED) {
}

/**
 * @param URL  The URL to load
 * @param method  the HTTP method to use
 * @param input  the input string if any
 * @param contentType  the Content-Type information IN and OUT
 * @param redir  the redirected URL OUT
 * @param headers  the extra headers
 * @param ilen  input length
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
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
 * @param URL  The URL to load
 * @param method  the HTTP method to use
 * @param input  the input string if any
 * @param contentType  the Content-Type information IN and OUT
 * @param headers  the extra headers
 * @param ilen  input length
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
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
 * @param URL  The URL to load
 * @param filename  the filename where the content should be saved
 * @param contentType  if available the Content-Type information will be
 *                returned at that location
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns -1.
 */
int
xmlNanoHTTPFetch(const char *URL ATTRIBUTE_UNUSED,
                 const char *filename ATTRIBUTE_UNUSED, char **contentType) {
    if (contentType != NULL) *contentType = NULL;
    return(-1);
}

#ifdef LIBXML_OUTPUT_ENABLED
/**
 * @param ctxt  the HTTP context
 * @param filename  the filename where the content should be saved
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns -1.
 */
int
xmlNanoHTTPSave(void *ctxt ATTRIBUTE_UNUSED,
                const char *filename ATTRIBUTE_UNUSED) {
    return(-1);
}
#endif /* LIBXML_OUTPUT_ENABLED */

/**
 * @param ctx  the HTTP context
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns -1.
 */
int
xmlNanoHTTPReturnCode(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * @param ctx  the HTTP context
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
const char *
xmlNanoHTTPAuthHeader(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * @param ctx  the HTTP context
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns -1.
 */
int
xmlNanoHTTPContentLength(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * @param ctx  the HTTP context
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
const char *
xmlNanoHTTPRedir(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * @param ctx  the HTTP context
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
const char *
xmlNanoHTTPEncoding(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * @param ctx  the HTTP context
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
const char *
xmlNanoHTTPMimeType(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

/**
 * @param filename  the URI for matching
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns 0.
 */
int
xmlIOHTTPMatch(const char *filename ATTRIBUTE_UNUSED) {
    return(0);
}

/**
 * @param filename  the URI for matching
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
void *
xmlIOHTTPOpen(const char *filename ATTRIBUTE_UNUSED) {
    return(NULL);
}

#ifdef LIBXML_OUTPUT_ENABLED
/**
 * @param post_uri  The destination URI for the document
 * @param compression  The compression desired for the document.
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns NULL.
 */
void *
xmlIOHTTPOpenW(const char *post_uri ATTRIBUTE_UNUSED,
               int compression ATTRIBUTE_UNUSED)
{
    return(NULL);
}
#endif /* LIBXML_OUTPUT_ENABLED */

/**
 * @param context  the I/O context
 * @param buffer  where to drop data
 * @param len  number of bytes to write
 *
 * @deprecated HTTP support was removed in 2.15.
 *
 * @returns -1.
 */
int
xmlIOHTTPRead(void *context ATTRIBUTE_UNUSED, char *buffer ATTRIBUTE_UNUSED,
              int len ATTRIBUTE_UNUSED) {
    return(-1);
}

/**
 * @param context  the I/O context
 *
 * @deprecated Internal function, don't use.
 *
 * @returns 0
 */
int
xmlIOHTTPClose (void *context ATTRIBUTE_UNUSED) {
    return 0;
}

/**
 * @deprecated HTTP support was removed in 2.15.
 */
void
xmlRegisterHTTPPostCallbacks(void) {
    xmlRegisterDefaultOutputCallbacks();
}

#endif /* LIBXML_HTTP_STUBS_ENABLED */
