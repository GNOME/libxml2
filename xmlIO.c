/*
 * xmlIO.c : implementation of the I/O interfaces used by the parser
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 *
 * 14 Nov 2000 ht - for VMS, truncated name of long functions to under 32 char
 */

#include "libxml.h"

#include <string.h>
#include <errno.h>

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
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

/* Figure a portable way to know if a file is a directory. */
#ifndef HAVE_STAT
#  ifdef HAVE__STAT
#    define stat(x,y) _stat(x,y)
#    define HAVE_STAT
#  endif
#endif
#ifdef HAVE_STAT
#  ifndef S_ISDIR
#    ifdef _S_ISDIR
#      define S_ISDIR(x) _S_ISDIR(x)
#    else
#      ifdef S_IFDIR
#        ifndef S_IFMT
#          ifdef _S_IFMT
#            define S_IFMT _S_IFMT
#          endif
#        endif
#        ifdef S_IFMT
#          define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#        endif
#      endif
#    endif
#  endif
#endif

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>
#include <libxml/nanohttp.h>
#include <libxml/nanoftp.h>
#include <libxml/xmlerror.h>
#ifdef LIBXML_CATALOG_ENABLED
#include <libxml/catalog.h>
#endif

#ifdef VMS
#define xmlRegisterDefaultInputCallbacks xmlRegisterDefInputCallbacks
#define xmlRegisterDefaultOutputCallbacks xmlRegisterDefOutputCallbacks
#endif

/* #define VERBOSE_FAILURE */
/* #define DEBUG_EXTERNAL_ENTITIES */
/* #define DEBUG_INPUT */

#ifdef DEBUG_INPUT
#define MINLEN 40
#else
#define MINLEN 4000
#endif

/*
 * Input I/O callback sets
 */
typedef struct _xmlInputCallback {
    xmlInputMatchCallback matchcallback;
    xmlInputOpenCallback opencallback;
    xmlInputReadCallback readcallback;
    xmlInputCloseCallback closecallback;
} xmlInputCallback;

#define MAX_INPUT_CALLBACK 15

xmlInputCallback xmlInputCallbackTable[MAX_INPUT_CALLBACK];
int xmlInputCallbackNr = 0;
int xmlInputCallbackInitialized = 0;

/*
 * Output I/O callback sets
 */
typedef struct _xmlOutputCallback {
    xmlOutputMatchCallback matchcallback;
    xmlOutputOpenCallback opencallback;
    xmlOutputWriteCallback writecallback;
    xmlOutputCloseCallback closecallback;
} xmlOutputCallback;

#define MAX_OUTPUT_CALLBACK 15

xmlOutputCallback xmlOutputCallbackTable[MAX_OUTPUT_CALLBACK];
int xmlOutputCallbackNr = 0;
int xmlOutputCallbackInitialized = 0;

/************************************************************************
 *									*
 *		Standard I/O for file accesses				*
 *									*
 ************************************************************************/

/**
 * xmlCheckFilename
 * @path:  the path to check
 *
 * function checks to see if @path is a valid source
 * (file, socket...) for XML.
 *
 * if stat is not available on the target machine,
 * returns 1.  if stat fails, returns 0 (if calling
 * stat on the filename fails, it can't be right).
 * if stat succeeds and the file is a directory,
 * sets errno to EISDIR and returns 0.  otherwise
 * returns 1.
 */

static int
xmlCheckFilename (const char *path)
{
#ifdef HAVE_STAT
#ifdef S_ISDIR
    struct stat stat_buffer;

    if (stat(path, &stat_buffer) == -1)
        return 0;

    if (S_ISDIR(stat_buffer.st_mode)) {
        errno = EISDIR;
        return 0;
    }

#endif
#endif
    return 1;
}

static int
xmlNop(void) {
    return(0);
}

/**
 * xmlFdRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to read
 *
 * Read @len bytes to @buffer from the I/O channel.
 *
 * Returns the number of bytes written
 */
static int
xmlFdRead (void * context, char * buffer, int len) {
    return(read((int) context, &buffer[0], len));
}

/**
 * xmlFdWrite:
 * @context:  the I/O context
 * @buffer:  where to get data
 * @len:  number of bytes to write
 *
 * Write @len bytes from @buffer to the I/O channel.
 *
 * Returns the number of bytes written
 */
static int
xmlFdWrite (void * context, const char * buffer, int len) {
    return(write((int) context, &buffer[0], len));
}

/**
 * xmlFdClose:
 * @context:  the I/O context
 *
 * Close an I/O channel
 */
static void
xmlFdClose (void * context) {
    close((int) context);
}

/**
 * xmlFileMatch:
 * @filename:  the URI for matching
 *
 * input from FILE *
 *
 * Returns 1 if matches, 0 otherwise
 */
static int
xmlFileMatch (const char *filename ATTRIBUTE_UNUSED) {
    return(1);
}

/**
 * xmlFileOpen:
 * @filename:  the URI for matching
 *
 * input from FILE *, supports compressed input
 * if @filename is " " then the standard input is used
 *
 * Returns an I/O context or NULL in case of error
 */
static void *
xmlFileOpen (const char *filename) {
    const char *path = NULL;
    FILE *fd;

    if (!strcmp(filename, "-")) {
	fd = stdin;
	return((void *) fd);
    }

    if (!strncmp(filename, "file://localhost", 16))
	path = &filename[16];
    else if (!strncmp(filename, "file:///", 8))
	path = &filename[7];
    else 
	path = filename;

    if (path == NULL)
	return(NULL);
    if (!xmlCheckFilename(path))
        return(NULL);

#ifdef WIN32
    fd = fopen(path, "rb");
#else
    fd = fopen(path, "r");
#endif /* WIN32 */
    return((void *) fd);
}

/**
 * xmlFileOpenW:
 * @filename:  the URI for matching
 *
 * output to from FILE *,
 * if @filename is "-" then the standard output is used
 *
 * Returns an I/O context or NULL in case of error
 */
static void *
xmlFileOpenW (const char *filename) {
    const char *path = NULL;
    FILE *fd;

    if (!strcmp(filename, "-")) {
	fd = stdout;
	return((void *) fd);
    }

    if (!strncmp(filename, "file://localhost", 16))
	path = &filename[16];
    else if (!strncmp(filename, "file:///", 8))
	path = &filename[7];
    else 
	path = filename;

    if (path == NULL)
	return(NULL);

    fd = fopen(path, "w");
    return((void *) fd);
}

/**
 * xmlFileRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Read @len bytes to @buffer from the I/O channel.
 *
 * Returns the number of bytes written
 */
static int
xmlFileRead (void * context, char * buffer, int len) {
    return(fread(&buffer[0], 1,  len, (FILE *) context));
}

/**
 * xmlFileWrite:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Write @len bytes from @buffer to the I/O channel.
 *
 * Returns the number of bytes written
 */
static int
xmlFileWrite (void * context, const char * buffer, int len) {
    return(fwrite(&buffer[0], 1,  len, (FILE *) context));
}

/**
 * xmlFileClose:
 * @context:  the I/O context
 *
 * Close an I/O channel
 */
static void
xmlFileClose (void * context) {
    fclose((FILE *) context);
}

/**
 * xmlFileFlush:
 * @context:  the I/O context
 *
 * Flush an I/O channel
 */
static void
xmlFileFlush (void * context) {
    fflush((FILE *) context);
}

#ifdef HAVE_ZLIB_H
/************************************************************************
 *									*
 *		I/O for compressed file accesses			*
 *									*
 ************************************************************************/
/**
 * xmlGzfileMatch:
 * @filename:  the URI for matching
 *
 * input from compressed file test
 *
 * Returns 1 if matches, 0 otherwise
 */
static int
xmlGzfileMatch (const char *filename ATTRIBUTE_UNUSED) {
    return(1);
}

/**
 * xmlGzfileOpen:
 * @filename:  the URI for matching
 *
 * input from compressed file open
 * if @filename is " " then the standard input is used
 *
 * Returns an I/O context or NULL in case of error
 */
static void *
xmlGzfileOpen (const char *filename) {
    const char *path = NULL;
    gzFile fd;

    if (!strcmp(filename, "-")) {
        fd = gzdopen(fileno(stdin), "rb");
	return((void *) fd);
    }

    if (!strncmp(filename, "file://localhost", 16))
	path = &filename[16];
    else if (!strncmp(filename, "file:///", 8))
	path = &filename[7];
    else 
	path = filename;

    if (path == NULL)
	return(NULL);
    if (!xmlCheckFilename(path))
        return(NULL);

    fd = gzopen(path, "rb");
    return((void *) fd);
}

/**
 * xmlGzfileOpenW:
 * @filename:  the URI for matching
 * @compression:  the compression factor (0 - 9 included)
 *
 * input from compressed file open
 * if @filename is " " then the standard input is used
 *
 * Returns an I/O context or NULL in case of error
 */
static void *
xmlGzfileOpenW (const char *filename, int compression) {
    const char *path = NULL;
    char mode[15];
    gzFile fd;

    sprintf(mode, "wb%d", compression);
    if (!strcmp(filename, "-")) {
        fd = gzdopen(1, mode);
	return((void *) fd);
    }

    if (!strncmp(filename, "file://localhost", 16))
	path = &filename[16];
    else if (!strncmp(filename, "file:///", 8))
	path = &filename[7];
    else 
	path = filename;

    if (path == NULL)
	return(NULL);

    fd = gzopen(path, mode);
    return((void *) fd);
}

/**
 * xmlGzfileRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Read @len bytes to @buffer from the compressed I/O channel.
 *
 * Returns the number of bytes written
 */
static int
xmlGzfileRead (void * context, char * buffer, int len) {
    return(gzread((gzFile) context, &buffer[0], len));
}

/**
 * xmlGzfileWrite:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Write @len bytes from @buffer to the compressed I/O channel.
 *
 * Returns the number of bytes written
 */
static int
xmlGzfileWrite (void * context, const char * buffer, int len) {
    return(gzwrite((gzFile) context, (char *) &buffer[0], len));
}

/**
 * xmlGzfileClose:
 * @context:  the I/O context
 *
 * Close a compressed I/O channel
 */
static void
xmlGzfileClose (void * context) {
    gzclose((gzFile) context);
}
#endif /* HAVE_ZLIB_H */

#ifdef LIBXML_HTTP_ENABLED
/************************************************************************
 *									*
 *			I/O for HTTP file accesses			*
 *									*
 ************************************************************************/
/**
 * xmlIOHTTPMatch:
 * @filename:  the URI for matching
 *
 * check if the URI matches an HTTP one
 *
 * Returns 1 if matches, 0 otherwise
 */
static int
xmlIOHTTPMatch (const char *filename) {
    if (!strncmp(filename, "http://", 7))
	return(1);
    return(0);
}

/**
 * xmlIOHTTPOpen:
 * @filename:  the URI for matching
 *
 * open an HTTP I/O channel
 *
 * Returns an I/O context or NULL in case of error
 */
static void *
xmlIOHTTPOpen (const char *filename) {
    return(xmlNanoHTTPOpen(filename, NULL));
}

/**
 * xmlIOHTTPRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Read @len bytes to @buffer from the I/O channel.
 *
 * Returns the number of bytes written
 */
static int 
xmlIOHTTPRead(void * context, char * buffer, int len) {
    return(xmlNanoHTTPRead(context, &buffer[0], len));
}

/**
 * xmlIOHTTPClose:
 * @context:  the I/O context
 *
 * Close an HTTP I/O channel
 */
static void
xmlIOHTTPClose (void * context) {
    xmlNanoHTTPClose(context);
}
#endif /* LIBXML_HTTP_ENABLED */

#ifdef LIBXML_FTP_ENABLED
/************************************************************************
 *									*
 *			I/O for FTP file accesses			*
 *									*
 ************************************************************************/
/**
 * xmlIOFTPMatch:
 * @filename:  the URI for matching
 *
 * check if the URI matches an FTP one
 *
 * Returns 1 if matches, 0 otherwise
 */
static int
xmlIOFTPMatch (const char *filename) {
    if (!strncmp(filename, "ftp://", 6))
	return(1);
    return(0);
}

/**
 * xmlIOFTPOpen:
 * @filename:  the URI for matching
 *
 * open an FTP I/O channel
 *
 * Returns an I/O context or NULL in case of error
 */
static void *
xmlIOFTPOpen (const char *filename) {
    return(xmlNanoFTPOpen(filename));
}

/**
 * xmlIOFTPRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Read @len bytes to @buffer from the I/O channel.
 *
 * Returns the number of bytes written
 */
static int 
xmlIOFTPRead(void * context, char * buffer, int len) {
    return(xmlNanoFTPRead(context, &buffer[0], len));
}

/**
 * xmlIOFTPClose:
 * @context:  the I/O context
 *
 * Close an FTP I/O channel
 */
static void
xmlIOFTPClose (void * context) {
    xmlNanoFTPClose(context);
}
#endif /* LIBXML_FTP_ENABLED */


/**
 * xmlRegisterInputCallbacks:
 * @matchFunc:  the xmlInputMatchCallback
 * @openFunc:  the xmlInputOpenCallback
 * @readFunc:  the xmlInputReadCallback
 * @closeFunc:  the xmlInputCloseCallback
 *
 * Register a new set of I/O callback for handling parser input.
 *
 * Returns the registered handler number or -1 in case of error
 */
int
xmlRegisterInputCallbacks(xmlInputMatchCallback matchFunc,
	xmlInputOpenCallback openFunc, xmlInputReadCallback readFunc,
	xmlInputCloseCallback closeFunc) {
    if (xmlInputCallbackNr >= MAX_INPUT_CALLBACK) {
	return(-1);
    }
    xmlInputCallbackTable[xmlInputCallbackNr].matchcallback = matchFunc;
    xmlInputCallbackTable[xmlInputCallbackNr].opencallback = openFunc;
    xmlInputCallbackTable[xmlInputCallbackNr].readcallback = readFunc;
    xmlInputCallbackTable[xmlInputCallbackNr].closecallback = closeFunc;
    return(xmlInputCallbackNr++);
}

/**
 * xmlRegisterOutputCallbacks:
 * @matchFunc:  the xmlOutputMatchCallback
 * @openFunc:  the xmlOutputOpenCallback
 * @writeFunc:  the xmlOutputWriteCallback
 * @closeFunc:  the xmlOutputCloseCallback
 *
 * Register a new set of I/O callback for handling output.
 *
 * Returns the registered handler number or -1 in case of error
 */
int
xmlRegisterOutputCallbacks(xmlOutputMatchCallback matchFunc,
	xmlOutputOpenCallback openFunc, xmlOutputWriteCallback writeFunc,
	xmlOutputCloseCallback closeFunc) {
    if (xmlOutputCallbackNr >= MAX_INPUT_CALLBACK) {
	return(-1);
    }
    xmlOutputCallbackTable[xmlOutputCallbackNr].matchcallback = matchFunc;
    xmlOutputCallbackTable[xmlOutputCallbackNr].opencallback = openFunc;
    xmlOutputCallbackTable[xmlOutputCallbackNr].writecallback = writeFunc;
    xmlOutputCallbackTable[xmlOutputCallbackNr].closecallback = closeFunc;
    return(xmlOutputCallbackNr++);
}

/**
 * xmlRegisterDefaultInputCallbacks:
 *
 * Registers the default compiled-in I/O handlers.
 */
void
#ifdef VMS
xmlRegisterDefInputCallbacks
#else
xmlRegisterDefaultInputCallbacks
#endif
(void) {
    if (xmlInputCallbackInitialized)
	return;

    xmlRegisterInputCallbacks(xmlFileMatch, xmlFileOpen,
	                      xmlFileRead, xmlFileClose);
#ifdef HAVE_ZLIB_H
    xmlRegisterInputCallbacks(xmlGzfileMatch, xmlGzfileOpen,
	                      xmlGzfileRead, xmlGzfileClose);
#endif /* HAVE_ZLIB_H */

#ifdef LIBXML_HTTP_ENABLED
    xmlRegisterInputCallbacks(xmlIOHTTPMatch, xmlIOHTTPOpen,
	                      xmlIOHTTPRead, xmlIOHTTPClose);
#endif /* LIBXML_HTTP_ENABLED */

#ifdef LIBXML_FTP_ENABLED
    xmlRegisterInputCallbacks(xmlIOFTPMatch, xmlIOFTPOpen,
	                      xmlIOFTPRead, xmlIOFTPClose);
#endif /* LIBXML_FTP_ENABLED */
    xmlInputCallbackInitialized = 1;
}

/**
 * xmlRegisterDefaultOutputCallbacks:
 *
 * Registers the default compiled-in I/O handlers.
 */
void
#ifdef VMS
xmlRegisterDefOutputCallbacks
#else
xmlRegisterDefaultOutputCallbacks
#endif
(void) {
    if (xmlOutputCallbackInitialized)
	return;

    xmlRegisterOutputCallbacks(xmlFileMatch, xmlFileOpenW,
	                      xmlFileWrite, xmlFileClose);
/*********************************
 No way a-priori to distinguish between gzipped files from
 uncompressed ones except opening if existing then closing
 and saving with same compression ratio ... a pain.

#ifdef HAVE_ZLIB_H
    xmlRegisterOutputCallbacks(xmlGzfileMatch, xmlGzfileOpen,
	                       xmlGzfileWrite, xmlGzfileClose);
#endif
 No HTTP PUT support yet, patches welcome

#ifdef LIBXML_HTTP_ENABLED
    xmlRegisterOutputCallbacks(xmlIOHTTPMatch, xmlIOHTTPOpen,
	                       xmlIOHTTPWrite, xmlIOHTTPClose);
#endif

 Nor FTP PUT ....
#ifdef LIBXML_FTP_ENABLED
    xmlRegisterOutputCallbacks(xmlIOFTPMatch, xmlIOFTPOpen,
	                       xmlIOFTPWrite, xmlIOFTPClose);
#endif
 **********************************/
    xmlOutputCallbackInitialized = 1;
}

/**
 * xmlAllocParserInputBuffer:
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for progressive parsing
 *
 * Returns the new parser input or NULL
 */
xmlParserInputBufferPtr
xmlAllocParserInputBuffer(xmlCharEncoding enc) {
    xmlParserInputBufferPtr ret;

    ret = (xmlParserInputBufferPtr) xmlMalloc(sizeof(xmlParserInputBuffer));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlAllocParserInputBuffer : out of memory!\n");
	return(NULL);
    }
    memset(ret, 0, (size_t) sizeof(xmlParserInputBuffer));
    ret->buffer = xmlBufferCreate();
    if (ret->buffer == NULL) {
        xmlFree(ret);
	return(NULL);
    }
    ret->buffer->alloc = XML_BUFFER_ALLOC_DOUBLEIT;
    ret->encoder = xmlGetCharEncodingHandler(enc);
    if (ret->encoder != NULL)
        ret->raw = xmlBufferCreate();
    else
        ret->raw = NULL;
    ret->readcallback = NULL;
    ret->closecallback = NULL;
    ret->context = NULL;

    return(ret);
}

/**
 * xmlAllocOutputBuffer:
 * @encoder:  the encoding converter or NULL
 *
 * Create a buffered parser output
 *
 * Returns the new parser output or NULL
 */
xmlOutputBufferPtr
xmlAllocOutputBuffer(xmlCharEncodingHandlerPtr encoder) {
    xmlOutputBufferPtr ret;

    ret = (xmlOutputBufferPtr) xmlMalloc(sizeof(xmlOutputBuffer));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlAllocOutputBuffer : out of memory!\n");
	return(NULL);
    }
    memset(ret, 0, (size_t) sizeof(xmlOutputBuffer));
    ret->buffer = xmlBufferCreate();
    if (ret->buffer == NULL) {
        xmlFree(ret);
	return(NULL);
    }
    ret->buffer->alloc = XML_BUFFER_ALLOC_DOUBLEIT;
    ret->encoder = encoder;
    if (encoder != NULL) {
        ret->conv = xmlBufferCreateSize(4000);
	/*
	 * This call is designed to initiate the encoder state
	 */
	xmlCharEncOutFunc(encoder, ret->conv, NULL); 
    } else
        ret->conv = NULL;
    ret->writecallback = NULL;
    ret->closecallback = NULL;
    ret->context = NULL;
    ret->written = 0;

    return(ret);
}

/**
 * xmlFreeParserInputBuffer:
 * @in:  a buffered parser input
 *
 * Free up the memory used by a buffered parser input
 */
void
xmlFreeParserInputBuffer(xmlParserInputBufferPtr in) {
    if (in->raw) {
        xmlBufferFree(in->raw);
	in->raw = NULL;
    }
    if (in->encoder != NULL) {
        xmlCharEncCloseFunc(in->encoder);
    }
    if (in->closecallback != NULL) {
	in->closecallback(in->context);
    }
    if (in->buffer != NULL) {
        xmlBufferFree(in->buffer);
	in->buffer = NULL;
    }

    xmlFree(in);
}

/**
 * xmlOutputBufferClose:
 * @out:  a buffered output
 *
 * flushes and close the output I/O channel
 * and free up all the associated resources
 *
 * Returns the number of byte written or -1 in case of error.
 */
int
xmlOutputBufferClose(xmlOutputBufferPtr out) {
    int written;

    if (out == NULL)
        return(-1);
    if (out->writecallback != NULL)
	xmlOutputBufferFlush(out);
    if (out->closecallback != NULL) {
	out->closecallback(out->context);
    }
    written = out->written;
    if (out->conv) {
        xmlBufferFree(out->conv);
	out->conv = NULL;
    }
    if (out->encoder != NULL) {
        xmlCharEncCloseFunc(out->encoder);
    }
    if (out->buffer != NULL) {
        xmlBufferFree(out->buffer);
	out->buffer = NULL;
    }

    xmlFree(out);
    return(written);
}

/**
 * xmlParserInputBufferCreateFilename:
 * @URI:  a C string containing the URI or filename
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for the progressive parsing of a file
 * If filename is "-' then we use stdin as the input.
 * Automatic support for ZLIB/Compress compressed document is provided
 * by default if found at compile-time.
 * Do an encoding check if enc == XML_CHAR_ENCODING_NONE
 *
 * Returns the new parser input or NULL
 */
xmlParserInputBufferPtr
#ifdef VMS
xmlParserInputBufferCreateFname
#else
xmlParserInputBufferCreateFilename
#endif
(const char *URI, xmlCharEncoding enc) {
    xmlParserInputBufferPtr ret;
    int i;
    void *context = NULL;

    if (xmlInputCallbackInitialized == 0)
	xmlRegisterDefaultInputCallbacks();

    if (URI == NULL) return(NULL);

    /*
     * Try to find one of the input accept method accepting taht scheme
     * Go in reverse to give precedence to user defined handlers.
     */
    for (i = xmlInputCallbackNr - 1;i >= 0;i--) {
	if ((xmlInputCallbackTable[i].matchcallback != NULL) &&
	    (xmlInputCallbackTable[i].matchcallback(URI) != 0)) {
	    context = xmlInputCallbackTable[i].opencallback(URI);
	    if (context != NULL)
		break;
	}
    }
    if (context == NULL) {
	return(NULL);
    }

    /*
     * Allocate the Input buffer front-end.
     */
    ret = xmlAllocParserInputBuffer(enc);
    if (ret != NULL) {
	ret->context = context;
	ret->readcallback = xmlInputCallbackTable[i].readcallback;
	ret->closecallback = xmlInputCallbackTable[i].closecallback;
    }
    return(ret);
}

/**
 * xmlOutputBufferCreateFilename:
 * @URI:  a C string containing the URI or filename
 * @encoder:  the encoding converter or NULL
 * @compression:  the compression ration (0 none, 9 max).
 *
 * Create a buffered  output for the progressive saving of a file
 * If filename is "-' then we use stdout as the output.
 * Automatic support for ZLIB/Compress compressed document is provided
 * by default if found at compile-time.
 * TODO: currently if compression is set, the library only support
 *       writing to a local file.
 *
 * Returns the new output or NULL
 */
xmlOutputBufferPtr
xmlOutputBufferCreateFilename(const char *URI,
                              xmlCharEncodingHandlerPtr encoder,
			      int compression) {
    xmlOutputBufferPtr ret;
    int i;
    void *context = NULL;

    if (xmlOutputCallbackInitialized == 0)
	xmlRegisterDefaultOutputCallbacks();

    if (URI == NULL) return(NULL);

#ifdef HAVE_ZLIB_H
    if ((compression > 0) && (compression <= 9)) {
        context = xmlGzfileOpenW(URI, compression);
	if (context != NULL) {
	    ret = xmlAllocOutputBuffer(encoder);
	    if (ret != NULL) {
		ret->context = context;
		ret->writecallback = xmlGzfileWrite;
		ret->closecallback = xmlGzfileClose;
	    }
	    return(ret);
	}
    }
#endif

    /*
     * Try to find one of the output accept method accepting taht scheme
     * Go in reverse to give precedence to user defined handlers.
     */
    for (i = xmlOutputCallbackNr - 1;i >= 0;i--) {
	if ((xmlOutputCallbackTable[i].matchcallback != NULL) &&
	    (xmlOutputCallbackTable[i].matchcallback(URI) != 0)) {
	    context = xmlOutputCallbackTable[i].opencallback(URI);
	    if (context != NULL)
		break;
	}
    }
    if (context == NULL) {
	return(NULL);
    }

    /*
     * Allocate the Output buffer front-end.
     */
    ret = xmlAllocOutputBuffer(encoder);
    if (ret != NULL) {
	ret->context = context;
	ret->writecallback = xmlOutputCallbackTable[i].writecallback;
	ret->closecallback = xmlOutputCallbackTable[i].closecallback;
    }
    return(ret);
}

/**
 * xmlParserInputBufferCreateFile:
 * @file:  a FILE* 
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for the progressive parsing of a FILE *
 * buffered C I/O
 *
 * Returns the new parser input or NULL
 */
xmlParserInputBufferPtr
xmlParserInputBufferCreateFile(FILE *file, xmlCharEncoding enc) {
    xmlParserInputBufferPtr ret;

    if (xmlInputCallbackInitialized == 0)
	xmlRegisterDefaultInputCallbacks();

    if (file == NULL) return(NULL);

    ret = xmlAllocParserInputBuffer(enc);
    if (ret != NULL) {
        ret->context = file;
	ret->readcallback = xmlFileRead;
	ret->closecallback = xmlFileFlush;
    }

    return(ret);
}

/**
 * xmlOutputBufferCreateFile:
 * @file:  a FILE* 
 * @encoder:  the encoding converter or NULL
 *
 * Create a buffered output for the progressive saving to a FILE *
 * buffered C I/O
 *
 * Returns the new parser output or NULL
 */
xmlOutputBufferPtr
xmlOutputBufferCreateFile(FILE *file, xmlCharEncodingHandlerPtr encoder) {
    xmlOutputBufferPtr ret;

    if (xmlOutputCallbackInitialized == 0)
	xmlRegisterDefaultOutputCallbacks();

    if (file == NULL) return(NULL);

    ret = xmlAllocOutputBuffer(encoder);
    if (ret != NULL) {
        ret->context = file;
	ret->writecallback = xmlFileWrite;
	ret->closecallback = xmlFileFlush;
    }

    return(ret);
}

/**
 * xmlParserInputBufferCreateFd:
 * @fd:  a file descriptor number
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for the progressive parsing for the input
 * from a file descriptor
 *
 * Returns the new parser input or NULL
 */
xmlParserInputBufferPtr
xmlParserInputBufferCreateFd(int fd, xmlCharEncoding enc) {
    xmlParserInputBufferPtr ret;

    if (fd < 0) return(NULL);

    ret = xmlAllocParserInputBuffer(enc);
    if (ret != NULL) {
        ret->context = (void *) fd;
	ret->readcallback = xmlFdRead;
	ret->closecallback = xmlFdClose;
    }

    return(ret);
}

/**
 * xmlParserInputBufferCreateMem:
 * @mem:  the memory input
 * @size:  the length of the memory block
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for the progressive parsing for the input
 * from a memory area.
 *
 * Returns the new parser input or NULL
 */
xmlParserInputBufferPtr
xmlParserInputBufferCreateMem(const char *mem, int size, xmlCharEncoding enc) {
    xmlParserInputBufferPtr ret;

    if (size <= 0) return(NULL);
    if (mem == NULL) return(NULL);

    ret = xmlAllocParserInputBuffer(enc);
    if (ret != NULL) {
        ret->context = (void *) mem;
	ret->readcallback = (xmlInputReadCallback) xmlNop;
	ret->closecallback = NULL;
	xmlBufferAdd(ret->buffer, (const xmlChar *) mem, size);
    }

    return(ret);
}

/**
 * xmlOutputBufferCreateFd:
 * @fd:  a file descriptor number
 * @encoder:  the encoding converter or NULL
 *
 * Create a buffered output for the progressive saving 
 * to a file descriptor
 *
 * Returns the new parser output or NULL
 */
xmlOutputBufferPtr
xmlOutputBufferCreateFd(int fd, xmlCharEncodingHandlerPtr encoder) {
    xmlOutputBufferPtr ret;

    if (fd < 0) return(NULL);

    ret = xmlAllocOutputBuffer(encoder);
    if (ret != NULL) {
        ret->context = (void *) fd;
	ret->writecallback = xmlFdWrite;
	ret->closecallback = xmlFdClose;
    }

    return(ret);
}

/**
 * xmlParserInputBufferCreateIO:
 * @ioread:  an I/O read function
 * @ioclose:  an I/O close function
 * @ioctx:  an I/O handler
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for the progressive parsing for the input
 * from an I/O handler
 *
 * Returns the new parser input or NULL
 */
xmlParserInputBufferPtr
xmlParserInputBufferCreateIO(xmlInputReadCallback   ioread,
	 xmlInputCloseCallback  ioclose, void *ioctx, xmlCharEncoding enc) {
    xmlParserInputBufferPtr ret;

    if (ioread == NULL) return(NULL);

    ret = xmlAllocParserInputBuffer(enc);
    if (ret != NULL) {
        ret->context = (void *) ioctx;
	ret->readcallback = ioread;
	ret->closecallback = ioclose;
    }

    return(ret);
}

/**
 * xmlOutputBufferCreateIO:
 * @iowrite:  an I/O write function
 * @ioclose:  an I/O close function
 * @ioctx:  an I/O handler
 * @enc:  the charset encoding if known
 *
 * Create a buffered output for the progressive saving
 * to an I/O handler
 *
 * Returns the new parser output or NULL
 */
xmlOutputBufferPtr
xmlOutputBufferCreateIO(xmlOutputWriteCallback   iowrite,
	 xmlOutputCloseCallback  ioclose, void *ioctx,
	 xmlCharEncodingHandlerPtr encoder) {
    xmlOutputBufferPtr ret;

    if (iowrite == NULL) return(NULL);

    ret = xmlAllocOutputBuffer(encoder);
    if (ret != NULL) {
        ret->context = (void *) ioctx;
	ret->writecallback = iowrite;
	ret->closecallback = ioclose;
    }

    return(ret);
}

/**
 * xmlParserInputBufferPush:
 * @in:  a buffered parser input
 * @len:  the size in bytes of the array.
 * @buf:  an char array
 *
 * Push the content of the arry in the input buffer
 * This routine handle the I18N transcoding to internal UTF-8
 * This is used when operating the parser in progressive (push) mode.
 *
 * Returns the number of chars read and stored in the buffer, or -1
 *         in case of error.
 */
int
xmlParserInputBufferPush(xmlParserInputBufferPtr in,
	                 int len, const char *buf) {
    int nbchars = 0;

    if (len < 0) return(0);
    if (in->encoder != NULL) {
        /*
	 * Store the data in the incoming raw buffer
	 */
        if (in->raw == NULL) {
	    in->raw = xmlBufferCreate();
	}
	xmlBufferAdd(in->raw, (const xmlChar *) buf, len);

	/*
	 * convert as much as possible to the parser reading buffer.
	 */
	nbchars = xmlCharEncInFunc(in->encoder, in->buffer, in->raw);
	if (nbchars < 0) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlParserInputBufferPush: encoder error\n");
	    return(-1);
	}
    } else {
	nbchars = len;
        xmlBufferAdd(in->buffer, (xmlChar *) buf, nbchars);
    }
#ifdef DEBUG_INPUT
    xmlGenericError(xmlGenericErrorContext,
	    "I/O: pushed %d chars, buffer %d/%d\n",
            nbchars, in->buffer->use, in->buffer->size);
#endif
    return(nbchars);
}

/**
 * xmlParserInputBufferGrow:
 * @in:  a buffered parser input
 * @len:  indicative value of the amount of chars to read
 *
 * Grow up the content of the input buffer, the old data are preserved
 * This routine handle the I18N transcoding to internal UTF-8
 * This routine is used when operating the parser in normal (pull) mode
 *
 * TODO: one should be able to remove one extra copy by copying directy
 *       onto in->buffer or in->raw
 *
 * Returns the number of chars read and stored in the buffer, or -1
 *         in case of error.
 */
int
xmlParserInputBufferGrow(xmlParserInputBufferPtr in, int len) {
    char *buffer = NULL;
    int res = 0;
    int nbchars = 0;
    int buffree;

    if ((len <= MINLEN) && (len != 4)) 
        len = MINLEN;
    buffree = in->buffer->size - in->buffer->use;
    if (buffree <= 0) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlParserInputBufferGrow : buffer full !\n");
	return(0);
    }
    if (len > buffree) 
        len = buffree;

    buffer = (char *) xmlMalloc((len + 1) * sizeof(char));
    if (buffer == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlParserInputBufferGrow : out of memory !\n");
	return(-1);
    }

    /*
     * Call the read method for this I/O type.
     */
    if (in->readcallback != NULL) {
	res = in->readcallback(in->context, &buffer[0], len);
    } else {
        xmlGenericError(xmlGenericErrorContext,
		"xmlParserInputBufferGrow : no input !\n");
	xmlFree(buffer);
	return(-1);
    }
    if (res < 0) {
	perror ("read error");
	xmlFree(buffer);
	return(-1);
    }
    len = res;
    if (in->encoder != NULL) {
        /*
	 * Store the data in the incoming raw buffer
	 */
        if (in->raw == NULL) {
	    in->raw = xmlBufferCreate();
	}
	xmlBufferAdd(in->raw, (const xmlChar *) buffer, len);

	/*
	 * convert as much as possible to the parser reading buffer.
	 */
	nbchars = xmlCharEncInFunc(in->encoder, in->buffer, in->raw);
	if (nbchars < 0) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlParserInputBufferGrow: encoder error\n");
	    return(-1);
	}
    } else {
	nbchars = len;
        buffer[nbchars] = 0;
        xmlBufferAdd(in->buffer, (xmlChar *) buffer, nbchars);
    }
#ifdef DEBUG_INPUT
    xmlGenericError(xmlGenericErrorContext,
	    "I/O: read %d chars, buffer %d/%d\n",
            nbchars, in->buffer->use, in->buffer->size);
#endif
    xmlFree(buffer);
    return(nbchars);
}

/**
 * xmlParserInputBufferRead:
 * @in:  a buffered parser input
 * @len:  indicative value of the amount of chars to read
 *
 * Refresh the content of the input buffer, the old data are considered
 * consumed
 * This routine handle the I18N transcoding to internal UTF-8
 *
 * Returns the number of chars read and stored in the buffer, or -1
 *         in case of error.
 */
int
xmlParserInputBufferRead(xmlParserInputBufferPtr in, int len) {
    /* xmlBufferEmpty(in->buffer); */
    if (in->readcallback != NULL)
	return(xmlParserInputBufferGrow(in, len));
    else
        return(-1);
}

/**
 * xmlOutputBufferWrite:
 * @out:  a buffered parser output
 * @len:  the size in bytes of the array.
 * @buf:  an char array
 *
 * Write the content of the array in the output I/O buffer
 * This routine handle the I18N transcoding from internal UTF-8
 * The buffer is lossless, i.e. will store in case of partial
 * or delayed writes.
 *
 * Returns the number of chars immediately written, or -1
 *         in case of error.
 */
int
xmlOutputBufferWrite(xmlOutputBufferPtr out, int len, const char *buf) {
    int nbchars = 0; /* number of chars to output to I/O */
    int ret;         /* return from function call */
    int written = 0; /* number of char written to I/O so far */
    int chunk;       /* number of byte curreent processed from buf */

    if (len < 0) return(0);

    do {
	chunk = len;
	if (chunk > 4 * MINLEN)
	    chunk = 4 * MINLEN;

	/*
	 * first handle encoding stuff.
	 */
	if (out->encoder != NULL) {
	    /*
	     * Store the data in the incoming raw buffer
	     */
	    if (out->conv == NULL) {
		out->conv = xmlBufferCreate();
	    }
	    xmlBufferAdd(out->buffer, (const xmlChar *) buf, chunk);

	    if ((out->buffer->use < MINLEN) && (chunk == len))
		goto done;

	    /*
	     * convert as much as possible to the parser reading buffer.
	     */
	    ret = xmlCharEncOutFunc(out->encoder, out->conv, out->buffer);
	    if (ret < 0) {
		xmlGenericError(xmlGenericErrorContext,
			"xmlOutputBufferWrite: encoder error\n");
		return(-1);
	    }
	    nbchars = out->conv->use;
	} else {
	    xmlBufferAdd(out->buffer, (const xmlChar *) buf, chunk);
	    nbchars = out->buffer->use;
	}
	buf += chunk;
	len -= chunk;

	if ((nbchars < MINLEN) && (len <= 0))
	    goto done;

	if (out->writecallback) {
	    /*
	     * second write the stuff to the I/O channel
	     */
	    if (out->encoder != NULL) {
		ret = out->writecallback(out->context, 
				 (const char *)out->conv->content, nbchars);
		if (ret >= 0)
		    xmlBufferShrink(out->conv, ret);
	    } else {
		ret = out->writecallback(out->context, 
				 (const char *)out->buffer->content, nbchars);
		if (ret >= 0)
		    xmlBufferShrink(out->buffer, ret);
	    }
	    if (ret < 0) {
		xmlGenericError(xmlGenericErrorContext,
			"I/O: error %d writing %d bytes\n", ret, nbchars);
		return(ret);
	    }
	    out->written += ret;
	}
	written += nbchars;
    } while (len > 0);

done:
#ifdef DEBUG_INPUT
    xmlGenericError(xmlGenericErrorContext,
	    "I/O: wrote %d chars\n", written);
#endif
    return(written);
}

/**
 * xmlOutputBufferWriteString:
 * @out:  a buffered parser output
 * @str:  a zero terminated C string
 *
 * Write the content of the string in the output I/O buffer
 * This routine handle the I18N transcoding from internal UTF-8
 * The buffer is lossless, i.e. will store in case of partial
 * or delayed writes.
 *
 * Returns the number of chars immediately written, or -1
 *         in case of error.
 */
int
xmlOutputBufferWriteString(xmlOutputBufferPtr out, const char *str) {
    int len;
    
    if (str == NULL)
        return(-1);
    len = strlen(str);

    if (len > 0)
	return(xmlOutputBufferWrite(out, len, str));
    return(len);
}

/**
 * xmlOutputBufferFlush:
 * @out:  a buffered output
 *
 * flushes the output I/O channel
 *
 * Returns the number of byte written or -1 in case of error.
 */
int
xmlOutputBufferFlush(xmlOutputBufferPtr out) {
    int nbchars = 0, ret = 0;

    /*
     * first handle encoding stuff.
     */
    if ((out->conv != NULL) && (out->encoder != NULL)) {
	/*
	 * convert as much as possible to the parser reading buffer.
	 */
	nbchars = xmlCharEncOutFunc(out->encoder, out->conv, out->buffer);
	if (nbchars < 0) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlOutputBufferWrite: encoder error\n");
	    return(-1);
	}
    }

    /*
     * second flush the stuff to the I/O channel
     */
    if ((out->conv != NULL) && (out->encoder != NULL) &&
	(out->writecallback != NULL)) {
	ret = out->writecallback(out->context,
	           (const char *)out->conv->content, out->conv->use);
	if (ret >= 0)
	    xmlBufferShrink(out->conv, ret);
    } else if (out->writecallback != NULL) {
	ret = out->writecallback(out->context,
	           (const char *)out->buffer->content, out->buffer->use);
	if (ret >= 0)
	    xmlBufferShrink(out->buffer, ret);
    }
    if (ret < 0) {
        xmlGenericError(xmlGenericErrorContext,
		"I/O: error %d flushing %d bytes\n", ret, nbchars);
	return(ret);
    }
    out->written += ret;

#ifdef DEBUG_INPUT
    xmlGenericError(xmlGenericErrorContext,
	    "I/O: flushed %d chars\n", ret);
#endif
    return(ret);
}

/*
 * xmlParserGetDirectory:
 * @filename:  the path to a file
 *
 * lookup the directory for that file
 *
 * Returns a new allocated string containing the directory, or NULL.
 */
char *
xmlParserGetDirectory(const char *filename) {
    char *ret = NULL;
    char dir[1024];
    char *cur;
    char sep = '/';

    if (xmlInputCallbackInitialized == 0)
	xmlRegisterDefaultInputCallbacks();

    if (filename == NULL) return(NULL);
#ifdef WIN32
    sep = '\\';
#endif

    strncpy(dir, filename, 1023);
    dir[1023] = 0;
    cur = &dir[strlen(dir)];
    while (cur > dir) {
         if (*cur == sep) break;
	 cur --;
    }
    if (*cur == sep) {
        if (cur == dir) dir[1] = 0;
	else *cur = 0;
	ret = xmlMemStrdup(dir);
    } else {
        if (getcwd(dir, 1024) != NULL) {
	    dir[1023] = 0;
	    ret = xmlMemStrdup(dir);
	}
    }
    return(ret);
}

/****************************************************************
 *								*
 *		External entities loading			*
 *								*
 ****************************************************************/

/*
 * xmlDefaultExternalEntityLoader:
 * @URL:  the URL for the entity to load
 * @ID:  the System ID for the entity to load
 * @ctxt:  the context in which the entity is called or NULL
 *
 * By default we don't load external entitites, yet.
 *
 * Returns a new allocated xmlParserInputPtr, or NULL.
 */
static
xmlParserInputPtr
xmlDefaultExternalEntityLoader(const char *URL, const char *ID,
                               xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr ret = NULL;
    const xmlChar *resource = NULL;

#ifdef DEBUG_EXTERNAL_ENTITIES
    xmlGenericError(xmlGenericErrorContext,
	    "xmlDefaultExternalEntityLoader(%s, xxx)\n", URL);
#endif
#ifdef LIBXML_CATALOG_ENABLED
    /*
     * Try to load it from the resource pointed in the catalog
     */
    if (ID != NULL)
	resource = xmlCatalogGetPublic((const xmlChar *)ID);
    if ((resource == NULL) && (URL != NULL))
	resource = xmlCatalogGetSystem((const xmlChar *)URL);
#endif

    if (resource == NULL)
	resource = (const xmlChar *)URL;

    if (resource == NULL) {
	if ((ctxt->validate) && (ctxt->sax != NULL) && 
            (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
		    "failed to load external entity \"%s\"\n", ID);
	else if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
	    ctxt->sax->warning(ctxt,
		    "failed to load external entity \"%s\"\n", ID);
        return(NULL);
    }
    ret = xmlNewInputFromFile(ctxt, (const char *)resource);
    if (ret == NULL) {
	if ((ctxt->validate) && (ctxt->sax != NULL) && 
            (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
		    "failed to load external entity \"%s\"\n", resource);
	else if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
	    ctxt->sax->warning(ctxt,
		    "failed to load external entity \"%s\"\n", resource);
    }
    return(ret);
}

static xmlExternalEntityLoader xmlCurrentExternalEntityLoader =
       xmlDefaultExternalEntityLoader;

/*
 * xmlSetExternalEntityLoader:
 * @f:  the new entity resolver function
 *
 * Changes the defaultexternal entity resolver function for the application
 */
void
xmlSetExternalEntityLoader(xmlExternalEntityLoader f) {
    xmlCurrentExternalEntityLoader = f;
}

/*
 * xmlGetExternalEntityLoader:
 *
 * Get the default external entity resolver function for the application
 *
 * Returns the xmlExternalEntityLoader function pointer
 */
xmlExternalEntityLoader
xmlGetExternalEntityLoader(void) {
    return(xmlCurrentExternalEntityLoader);
}

/*
 * xmlLoadExternalEntity:
 * @URL:  the URL for the entity to load
 * @ID:  the System ID for the entity to load
 * @ctxt:  the context in which the entity is called or NULL
 *
 * Load an external entity, note that the use of this function for
 * unparsed entities may generate problems
 * TODO: a more generic External entitiy API must be designed
 *
 * Returns the xmlParserInputPtr or NULL
 */
xmlParserInputPtr
xmlLoadExternalEntity(const char *URL, const char *ID,
                      xmlParserCtxtPtr ctxt) {
    return(xmlCurrentExternalEntityLoader(URL, ID, ctxt));
}

