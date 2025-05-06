/**
 * @file
 * 
 * @brief I/O interfaces used by the parser
 * 
 * Functions and datatypes for parser input and output.
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
 */

#ifndef __XML_IO_H__
#define __XML_IO_H__

#include <stdio.h>
#include <libxml/xmlversion.h>
#include <libxml/encoding.h>
#define XML_TREE_INTERNALS
#include <libxml/tree.h>
#undef XML_TREE_INTERNALS

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback used in the I/O Input API to detect if the current handler
 * can provide input functionality for this resource.
 *
 * @param filename  the filename or URI
 * @returns 1 if yes and 0 if another Input module should be used
 */
typedef int (*xmlInputMatchCallback) (char const *filename);
/**
 * Callback used in the I/O Input API to open the resource
 *
 * @param filename  the filename or URI
 * @returns an Input context or NULL in case or error
 */
typedef void * (*xmlInputOpenCallback) (char const *filename);
/**
 * Callback used in the I/O Input API to read the resource
 *
 * @param context  an Input context
 * @param buffer  the buffer to store data read
 * @param len  the length of the buffer in bytes
 * @returns the number of bytes read or -1 in case of error
 */
typedef int (*xmlInputReadCallback) (void * context, char * buffer, int len);
/**
 * Callback used in the I/O Input API to close the resource
 *
 * @param context  an Input context
 * @returns 0 or -1 in case of error
 */
typedef int (*xmlInputCloseCallback) (void * context);

#ifdef LIBXML_OUTPUT_ENABLED
/**
 * Callback used in the I/O Output API to detect if the current handler
 * can provide output functionality for this resource.
 *
 * @param filename  the filename or URI
 * @returns 1 if yes and 0 if another Output module should be used
 */
typedef int (*xmlOutputMatchCallback) (char const *filename);
/**
 * Callback used in the I/O Output API to open the resource
 *
 * @param filename  the filename or URI
 * @returns an Output context or NULL in case or error
 */
typedef void * (*xmlOutputOpenCallback) (char const *filename);
/**
 * Callback used in the I/O Output API to write to the resource
 *
 * @param context  an Output context
 * @param buffer  the buffer of data to write
 * @param len  the length of the buffer in bytes
 * @returns the number of bytes written or -1 in case of error
 */
typedef int (*xmlOutputWriteCallback) (void * context, const char * buffer,
                                       int len);
/**
 * Callback used in the I/O Output API to close the resource
 *
 * @param context  an Output context
 * @returns 0 or -1 in case of error
 */
typedef int (*xmlOutputCloseCallback) (void * context);
#endif /* LIBXML_OUTPUT_ENABLED */

/**
 * Signature for the function doing the lookup for a suitable input method
 * corresponding to an URI.
 *
 * @param URI  the URI to read from
 * @param enc  the requested source encoding
 * @returns the new xmlParserInputBufferPtr in case of success or NULL if no
 *         method was found.
 */
typedef xmlParserInputBufferPtr
(*xmlParserInputBufferCreateFilenameFunc)(const char *URI, xmlCharEncoding enc);

/**
 * Signature for the function doing the lookup for a suitable output method
 * corresponding to an URI.
 *
 * @param URI  the URI to write to
 * @param encoder  the requested target encoding
 * @param compression  compression level
 * @returns the new xmlOutputBufferPtr in case of success or NULL if no
 *         method was found.
 */
typedef xmlOutputBufferPtr
(*xmlOutputBufferCreateFilenameFunc)(const char *URI,
        xmlCharEncodingHandlerPtr encoder, int compression);

/*
 * This struct and all related functions should be ultimately
 * be removed from the public interface.
 */
struct _xmlParserInputBuffer {
    void*                  context;
    xmlInputReadCallback   readcallback;
    xmlInputCloseCallback  closecallback;

    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */

    xmlBufPtr buffer;    /* Local buffer encoded in UTF-8 */
    xmlBufPtr raw;       /* if encoder != NULL buffer for raw input */
    int	compressed;	    /* -1=unknown, 0=not compressed, 1=compressed */
    int error;
    unsigned long rawconsumed;/* amount consumed from raw */
};


#ifdef LIBXML_OUTPUT_ENABLED
/**
 * Output buffer
 */
struct _xmlOutputBuffer {
    void*                   context;
    xmlOutputWriteCallback  writecallback;
    xmlOutputCloseCallback  closecallback;

    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */

    xmlBufPtr buffer;    /* Local buffer encoded in UTF-8 or ISOLatin */
    xmlBufPtr conv;      /* if encoder != NULL buffer for output */
    int written;            /* total number of byte written */
    int error;
};
#endif /* LIBXML_OUTPUT_ENABLED */

XML_DEPRECATED
XMLPUBFUN xmlParserInputBufferCreateFilenameFunc *
__xmlParserInputBufferCreateFilenameValue(void);
XML_DEPRECATED
XMLPUBFUN xmlOutputBufferCreateFilenameFunc *
__xmlOutputBufferCreateFilenameValue(void);

#ifndef XML_GLOBALS_NO_REDEFINITION
  #define xmlParserInputBufferCreateFilenameValue \
    (*__xmlParserInputBufferCreateFilenameValue())
  #define xmlOutputBufferCreateFilenameValue \
    (*__xmlOutputBufferCreateFilenameValue())
#endif

/*
 * Interfaces for input
 */
XMLPUBFUN void
	xmlCleanupInputCallbacks		(void);

XMLPUBFUN int
	xmlPopInputCallbacks			(void);

XMLPUBFUN void
	xmlRegisterDefaultInputCallbacks	(void);
XMLPUBFUN xmlParserInputBufferPtr
	xmlAllocParserInputBuffer		(xmlCharEncoding enc);

XMLPUBFUN xmlParserInputBufferPtr
	xmlParserInputBufferCreateFilename	(const char *URI,
                                                 xmlCharEncoding enc);
XML_DEPRECATED
XMLPUBFUN xmlParserInputBufferPtr
	xmlParserInputBufferCreateFile		(FILE *file,
                                                 xmlCharEncoding enc);
XMLPUBFUN xmlParserInputBufferPtr
	xmlParserInputBufferCreateFd		(int fd,
	                                         xmlCharEncoding enc);
XMLPUBFUN xmlParserInputBufferPtr
	xmlParserInputBufferCreateMem		(const char *mem, int size,
	                                         xmlCharEncoding enc);
XMLPUBFUN xmlParserInputBufferPtr
	xmlParserInputBufferCreateStatic	(const char *mem, int size,
	                                         xmlCharEncoding enc);
XMLPUBFUN xmlParserInputBufferPtr
	xmlParserInputBufferCreateIO		(xmlInputReadCallback   ioread,
						 xmlInputCloseCallback  ioclose,
						 void *ioctx,
	                                         xmlCharEncoding enc);
XML_DEPRECATED
XMLPUBFUN int
	xmlParserInputBufferRead		(xmlParserInputBufferPtr in,
						 int len);
XML_DEPRECATED
XMLPUBFUN int
	xmlParserInputBufferGrow		(xmlParserInputBufferPtr in,
						 int len);
XML_DEPRECATED
XMLPUBFUN int
	xmlParserInputBufferPush		(xmlParserInputBufferPtr in,
						 int len,
						 const char *buf);
XMLPUBFUN void
	xmlFreeParserInputBuffer		(xmlParserInputBufferPtr in);
XMLPUBFUN char *
	xmlParserGetDirectory			(const char *filename);

XMLPUBFUN int
	xmlRegisterInputCallbacks		(xmlInputMatchCallback matchFunc,
						 xmlInputOpenCallback openFunc,
						 xmlInputReadCallback readFunc,
						 xmlInputCloseCallback closeFunc);

XMLPUBFUN xmlParserInputBufferPtr
	__xmlParserInputBufferCreateFilename(const char *URI,
						xmlCharEncoding enc);

#ifdef LIBXML_OUTPUT_ENABLED
/*
 * Interfaces for output
 */
XMLPUBFUN void
	xmlCleanupOutputCallbacks		(void);
XMLPUBFUN int
	xmlPopOutputCallbacks			(void);
XMLPUBFUN void
	xmlRegisterDefaultOutputCallbacks(void);
XMLPUBFUN xmlOutputBufferPtr
	xmlAllocOutputBuffer		(xmlCharEncodingHandlerPtr encoder);

XMLPUBFUN xmlOutputBufferPtr
	xmlOutputBufferCreateFilename	(const char *URI,
					 xmlCharEncodingHandlerPtr encoder,
					 int compression);

XMLPUBFUN xmlOutputBufferPtr
	xmlOutputBufferCreateFile	(FILE *file,
					 xmlCharEncodingHandlerPtr encoder);

XMLPUBFUN xmlOutputBufferPtr
	xmlOutputBufferCreateBuffer	(xmlBufferPtr buffer,
					 xmlCharEncodingHandlerPtr encoder);

XMLPUBFUN xmlOutputBufferPtr
	xmlOutputBufferCreateFd		(int fd,
					 xmlCharEncodingHandlerPtr encoder);

XMLPUBFUN xmlOutputBufferPtr
	xmlOutputBufferCreateIO		(xmlOutputWriteCallback   iowrite,
					 xmlOutputCloseCallback  ioclose,
					 void *ioctx,
					 xmlCharEncodingHandlerPtr encoder);

/* Couple of APIs to get the output without digging into the buffers */
XMLPUBFUN const xmlChar *
        xmlOutputBufferGetContent       (xmlOutputBufferPtr out);
XMLPUBFUN size_t
        xmlOutputBufferGetSize          (xmlOutputBufferPtr out);

XMLPUBFUN int
	xmlOutputBufferWrite		(xmlOutputBufferPtr out,
					 int len,
					 const char *buf);
XMLPUBFUN int
	xmlOutputBufferWriteString	(xmlOutputBufferPtr out,
					 const char *str);
XMLPUBFUN int
	xmlOutputBufferWriteEscape	(xmlOutputBufferPtr out,
					 const xmlChar *str,
					 xmlCharEncodingOutputFunc escaping);

XMLPUBFUN int
	xmlOutputBufferFlush		(xmlOutputBufferPtr out);
XMLPUBFUN int
	xmlOutputBufferClose		(xmlOutputBufferPtr out);

XMLPUBFUN int
	xmlRegisterOutputCallbacks	(xmlOutputMatchCallback matchFunc,
					 xmlOutputOpenCallback openFunc,
					 xmlOutputWriteCallback writeFunc,
					 xmlOutputCloseCallback closeFunc);

XMLPUBFUN xmlOutputBufferPtr
	__xmlOutputBufferCreateFilename(const char *URI,
                              xmlCharEncodingHandlerPtr encoder,
                              int compression);
#endif /* LIBXML_OUTPUT_ENABLED */

XML_DEPRECATED
XMLPUBFUN xmlParserInputPtr
	xmlCheckHTTPInput		(xmlParserCtxtPtr ctxt,
					 xmlParserInputPtr ret);

XML_DEPRECATED
XMLPUBFUN xmlParserInputPtr
	xmlNoNetExternalEntityLoader	(const char *URL,
					 const char *ID,
					 xmlParserCtxtPtr ctxt);

XML_DEPRECATED
XMLPUBFUN xmlChar *
	xmlNormalizeWindowsPath		(const xmlChar *path);

XML_DEPRECATED
XMLPUBFUN int
	xmlCheckFilename		(const char *path);

XML_DEPRECATED
XMLPUBFUN int
	xmlFileMatch			(const char *filename);
XML_DEPRECATED
XMLPUBFUN void *
	xmlFileOpen			(const char *filename);
XML_DEPRECATED
XMLPUBFUN int
	xmlFileRead			(void * context,
					 char * buffer,
					 int len);
XML_DEPRECATED
XMLPUBFUN int
	xmlFileClose			(void * context);

#ifdef LIBXML_HTTP_STUBS_ENABLED
/** @cond IGNORE */
XML_DEPRECATED
XMLPUBFUN int
	xmlIOHTTPMatch			(const char *filename);
XML_DEPRECATED
XMLPUBFUN void *
	xmlIOHTTPOpen			(const char *filename);
#ifdef LIBXML_OUTPUT_ENABLED
XML_DEPRECATED
XMLPUBFUN void
	xmlRegisterHTTPPostCallbacks	(void );
XML_DEPRECATED
XMLPUBFUN void *
	xmlIOHTTPOpenW			(const char * post_uri,
					 int   compression );
#endif /* LIBXML_OUTPUT_ENABLED */
XML_DEPRECATED
XMLPUBFUN int
	xmlIOHTTPRead			(void * context,
					 char * buffer,
					 int len);
XML_DEPRECATED
XMLPUBFUN int
	xmlIOHTTPClose			(void * context);
/** @endcond */
#endif /* LIBXML_HTTP_STUBS_ENABLED */

XMLPUBFUN xmlParserInputBufferCreateFilenameFunc
	xmlParserInputBufferCreateFilenameDefault(
		xmlParserInputBufferCreateFilenameFunc func);
XMLPUBFUN xmlOutputBufferCreateFilenameFunc
	xmlOutputBufferCreateFilenameDefault(
		xmlOutputBufferCreateFilenameFunc func);
XML_DEPRECATED
XMLPUBFUN xmlOutputBufferCreateFilenameFunc
	xmlThrDefOutputBufferCreateFilenameDefault(
		xmlOutputBufferCreateFilenameFunc func);
XML_DEPRECATED
XMLPUBFUN xmlParserInputBufferCreateFilenameFunc
	xmlThrDefParserInputBufferCreateFilenameDefault(
		xmlParserInputBufferCreateFilenameFunc func);

#ifdef __cplusplus
}
#endif

#endif /* __XML_IO_H__ */
