/*
 * xmlIO.c : implementation of the I/O interfaces used by the parser
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

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>
#include <libxml/nanohttp.h>
#include <libxml/nanoftp.h>

/* #define DEBUG_INPUT */
/* #define VERBOSE_FAILURE */
/* #define DEBUG_EXTERNAL_ENTITIES */

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

/************************************************************************
 *									*
 *		Standard I/O for file accesses				*
 *									*
 ************************************************************************/

/**
 * xmlFdMatch:
 * @filename:  the URI for matching
 *
 * input from file descriptor
 *
 * Returns 1 if matches, 0 otherwise
 */
int
xmlFdMatch (const char *filename) {
    return(1);
}

/**
 * xmlFdOpen:
 * @filename:  the URI for matching
 *
 * input from file descriptor, supports compressed input
 * if @filename is " " then the standard input is used
 *
 * Returns an I/O context or NULL in case of error
 */
void *
xmlFdOpen (const char *filename) {
    const char *path = NULL;
    int fd;

    if (!strcmp(filename, "-")) {
	fd = 0;
	return((void *) fd);
    }

    if (!strncmp(filename, "file://localhost", 16))
	path = &filename[16];
    else if (!strncmp(filename, "file:///", 8))
	path = &filename[8];
    else if (filename[0] == '/')
	path = filename;
    if (path == NULL)
	return(NULL);

#ifdef WIN32
    fd = _open (filename, O_RDONLY | _O_BINARY);
#else
    fd = open (filename, O_RDONLY);
#endif

    return((void *) fd);
}

/**
 * xmlFdRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Read @len bytes to @buffer from the I/O channel.
 *
 * Returns the number of bytes written
 */
int
xmlFdRead (void * context, char * buffer, int len) {
    return(read((int) context, &buffer[0], len));
}

/**
 * xmlFdClose:
 * @context:  the I/O context
 *
 * Close an I/O channel
 */
void
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
int
xmlFileMatch (const char *filename) {
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
void *
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
	path = &filename[8];
    else 
	path = filename;
    if (path == NULL)
	return(NULL);

#ifdef WIN32
    fd = fopen(path, "rb");
#else
    fd = fopen(path, "r");
#endif /* WIN32 */
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
int
xmlFileRead (void * context, char * buffer, int len) {
    return(fread(&buffer[0], 1,  len, (FILE *) context));
}

/**
 * xmlFileClose:
 * @context:  the I/O context
 *
 * Close an I/O channel
 */
void
xmlFileClose (void * context) {
    fclose((FILE *) context);
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
int
xmlGzfileMatch (const char *filename) {
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
void *
xmlGzfileOpen (const char *filename) {
    const char *path = NULL;
    gzFile fd;

    if (!strcmp(filename, "-")) {
        fd = gzdopen (fileno(stdin), "r");
	return((void *) fd);
    }

    if (!strncmp(filename, "file://localhost", 16))
	path = &filename[16];
    else if (!strncmp(filename, "file:///", 8))
	path = &filename[8];
    else 
	path = filename;

    fd = gzopen(filename, "r");
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
int
xmlGzfileRead (void * context, char * buffer, int len) {
    return(gzread((gzFile) context, &buffer[0], len));
}

/**
 * xmlGzfileClose:
 * @context:  the I/O context
 *
 * Close a compressed I/O channel
 */
void
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
int
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
void *
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
int 
xmlIOHTTPRead(void * context, char * buffer, int len) {
    return(xmlNanoHTTPRead(context, &buffer[0], len));
}

/**
 * xmlIOHTTPClose:
 * @context:  the I/O context
 *
 * Close an HTTP I/O channel
 */
void
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
int
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
void *
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
int 
xmlIOFTPRead(void * context, char * buffer, int len) {
    return(xmlNanoFTPRead(context, &buffer[0], len));
}

/**
 * xmlIOFTPClose:
 * @context:  the I/O context
 *
 * Close an FTP I/O channel
 */
void
xmlIOFTPClose (void * context) {
    xmlNanoFTPClose(context);
}
#endif /* LIBXML_FTP_ENABLED */


/**
 * xmlRegisterInputCallbacks:
 * @match:  the xmlInputMatchCallback
 * @open:  the xmlInputOpenCallback
 * @read:  the xmlInputReadCallback
 * @close:  the xmlInputCloseCallback
 *
 * Register a new set of I/O callback for handling parser input.
 *
 * Returns the registered handler number or -1 in case of error
 */
int
xmlRegisterInputCallbacks(xmlInputMatchCallback match,
	xmlInputOpenCallback open, xmlInputReadCallback read,
	xmlInputCloseCallback close) {
    if (xmlInputCallbackNr >= MAX_INPUT_CALLBACK) {
	return(-1);
    }
    xmlInputCallbackTable[xmlInputCallbackNr].matchcallback = match;
    xmlInputCallbackTable[xmlInputCallbackNr].opencallback = open;
    xmlInputCallbackTable[xmlInputCallbackNr].readcallback = read;
    xmlInputCallbackTable[xmlInputCallbackNr].closecallback = close;
    return(xmlInputCallbackNr++);
}

/**
 * xmlRegisterDefaultInputCallbacks:
 *
 * Registers the default compiled-in I/O handlers.
 */
void
xmlRegisterDefaultInputCallbacks(void) {
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
        fprintf(stderr, "xmlAllocParserInputBuffer : out of memory!\n");
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
    ret->readcallback = NULL;
    ret->closecallback = NULL;
    ret->context = NULL;

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
    if (in->buffer != NULL) {
        xmlBufferFree(in->buffer);
	in->buffer = NULL;
    }
    if (in->closecallback != NULL) {
	in->closecallback(in->context);
    }

    memset(in, 0xbe, (size_t) sizeof(xmlParserInputBuffer));
    xmlFree(in);
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
xmlParserInputBufferCreateFilename(const char *URI, xmlCharEncoding enc) {
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
#ifdef DEBUG_INPUT
	fprintf(stderr, "No input filter matching \"%s\"\n", URI);
#endif
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
	ret->closecallback = xmlFileClose;
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
 * xmlParserInputBufferCreateIO:
 * @ioread:  an I/O read function
 * @ioclose:  an I/O close function
 * @ioctx:  an I/O handler
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for the progressive parsing for the input
 * from a file descriptor
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
 * xmlParserInputBufferPush:
 * @in:  a buffered parser input
 * @buf:  an char array
 * @len:  the size in bytes of the array.
 *
 * Push the content of the arry in the input buffer
 * This routine handle the I18N transcoding to internal UTF-8
 * This is used when operating the parser in progressive (push) mode.
 *
 * Returns the number of chars read and stored in the buffer, or -1
 *         in case of error.
 */
int
xmlParserInputBufferPush(xmlParserInputBufferPtr in, int len, const char *buf) {
    int nbchars = 0;

    if (len < 0) return(0);
    if (in->encoder != NULL) {
        xmlChar *buffer;
	int processed = len;

	buffer = (xmlChar *) xmlMalloc((len + 1) * 2 * sizeof(xmlChar));
	if (buffer == NULL) {
	    fprintf(stderr, "xmlParserInputBufferGrow : out of memory !\n");
	    return(-1);
	}
	nbchars = in->encoder->input(buffer, (len + 1) * 2 * sizeof(xmlChar),
	                             (xmlChar *) buf, &processed);
	/*
	 * TODO : we really need to have something atomic or the 
	 *        encoder must report the number of bytes read
	 */
	if (nbchars < 0) {
	    fprintf(stderr, "xmlParserInputBufferPush: encoder error\n");
	    xmlFree(buffer);
	    return(-1);
	}
	if (processed  != len) {
	    fprintf(stderr,
	            "TODO xmlParserInputBufferPush: processed  != len\n");
	    xmlFree(buffer);
	    return(-1);
	}
        buffer[nbchars] = 0;
        xmlBufferAdd(in->buffer, (xmlChar *) buffer, nbchars);
	xmlFree(buffer);
    } else {
	nbchars = len;
        xmlBufferAdd(in->buffer, (xmlChar *) buf, nbchars);
    }
#ifdef DEBUG_INPUT
    fprintf(stderr, "I/O: pushed %d chars, buffer %d/%d\n",
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
 * TODO: one should be able to remove one extra copy
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
        fprintf(stderr, "xmlParserInputBufferGrow : buffer full !\n");
	return(0);
    }
    if (len > buffree) 
        len = buffree;

    buffer = xmlMalloc((len + 1) * sizeof(char));
    if (buffer == NULL) {
        fprintf(stderr, "xmlParserInputBufferGrow : out of memory !\n");
	return(-1);
    }

    /*
     * Call the read method for this I/O type.
     */
    if (in->readcallback != NULL) {
	res = in->readcallback(in->context, &buffer[0], len);
    } else {
        fprintf(stderr, "xmlParserInputBufferGrow : no input !\n");
	xmlFree(buffer);
	return(-1);
    }

    if (res == 0) {
	xmlFree(buffer);
        return(0);
    }
    if (res < 0) {
	perror ("read error");
	xmlFree(buffer);
	return(-1);
    }
    if (in->encoder != NULL) {
        xmlChar *buf;
	int wrote = res;

	buf = (xmlChar *) xmlMalloc((res + 1) * 2 * sizeof(xmlChar));
	if (buf == NULL) {
	    fprintf(stderr, "xmlParserInputBufferGrow : out of memory !\n");
	    xmlFree(buffer);
	    return(-1);
	}
	nbchars = in->encoder->input(buf, (res + 1) * 2 * sizeof(xmlChar),
	                             BAD_CAST buffer, &wrote);
        buf[nbchars] = 0;
        xmlBufferAdd(in->buffer, (xmlChar *) buf, nbchars);
	xmlFree(buf);

	/*
	 * Check that the encoder was able to process the full input
	 */
	if (wrote != res) {
	    fprintf(stderr, 
	        "TODO : xmlParserInputBufferGrow wrote %d != res %d\n",
		wrote, res);
	    /*
	     * TODO !!!
	     * Need to keep the unprocessed input in a buffer in->unprocessed
	     */
	}

    } else {
	nbchars = res;
        buffer[nbchars] = 0;
        xmlBufferAdd(in->buffer, (xmlChar *) buffer, nbchars);
    }
#ifdef DEBUG_INPUT
    fprintf(stderr, "I/O: read %d chars, buffer %d/%d\n",
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
        return(0);
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
#ifdef DEBUG_EXTERNAL_ENTITIES
    fprintf(stderr, "xmlDefaultExternalEntityLoader(%s, xxx)\n", URL);
#endif
    if (URL == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
	    ctxt->sax->warning(ctxt, "failed to load external entity \"%s\"\n",
	                       ID);
        return(NULL);
    }
    ret = xmlNewInputFromFile(ctxt, URL);
    if (ret == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
	    ctxt->sax->warning(ctxt, "failed to load external entity \"%s\"\n",
	                       URL);
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

