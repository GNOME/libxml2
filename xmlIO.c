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

#include "xmlmemory.h"
#include "parser.h"
#include "parserInternals.h"
#include "xmlIO.h"
#include "nanohttp.h"
#include "nanoftp.h"

/* #define DEBUG_INPUT */
/* #define VERBOSE_FAILURE */
/* #define DEBUG_EXTERNAL_ENTITIES */

#ifdef DEBUG_INPUT
#define MINLEN 40
#else
#define MINLEN 4000
#endif

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
    ret->fd = -1;
    ret->httpIO = NULL;
    ret->ftpIO = NULL;
    /* 2.3.5 */
    ret->raw = NULL;

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
#ifdef HAVE_ZLIB_H
    if (in->gzfile != NULL)
        gzclose(in->gzfile);
#endif
    if (in->httpIO != NULL)
        xmlNanoHTTPClose(in->httpIO);
    if (in->ftpIO != NULL)
        xmlNanoFTPClose(in->ftpIO);
    if (in->fd >= 0)
        close(in->fd);
    /* 2.3.5 */
    if (in->raw) {
        xmlBufferFree(in->raw);
	in->raw = NULL;
    }
    memset(in, 0xbe, (size_t) sizeof(xmlParserInputBuffer));
    xmlFree(in);
}

/**
 * xmlParserInputBufferCreateFilename:
 * @filename:  a C string containing the filename
 * @enc:  the charset encoding if known
 *
 * Create a buffered parser input for the progressive parsing of a file
 * If filename is "-' then we use stdin as the input.
 * Automatic support for ZLIB/Compress compressed document is provided
 * by default if found at compile-time.
 *
 * Returns the new parser input or NULL
 */
xmlParserInputBufferPtr
xmlParserInputBufferCreateFilename(const char *filename, xmlCharEncoding enc) {
    xmlParserInputBufferPtr ret;
#ifdef HAVE_ZLIB_H
    gzFile input = 0;
#else
    int input = -1;
#endif
    void *httpIO = NULL;
    void *ftpIO = NULL;

    if (filename == NULL) return(NULL);

    if (!strncmp(filename, "http://", 7)) {
        httpIO = xmlNanoHTTPOpen(filename, NULL);
        if (httpIO == NULL) {
#ifdef VERBOSE_FAILURE
            fprintf (stderr, "Cannot read URL %s\n", filename);
            perror ("xmlNanoHTTPOpen failed");
#endif
            return(NULL);
	}
    } else if (!strncmp(filename, "ftp://", 6)) {
        ftpIO = xmlNanoFTPOpen(filename);
        if (ftpIO == NULL) {
#ifdef VERBOSE_FAILURE
            fprintf (stderr, "Cannot read URL %s\n", filename);
            perror ("xmlNanoFTPOpen failed");
#endif
            return(NULL);
	}
    } else if (!strcmp(filename, "-")) {
#ifdef HAVE_ZLIB_H
        input = gzdopen (fileno(stdin), "r");
        if (input == NULL) {
#ifdef VERBOSE_FAILURE
            fprintf (stderr, "Cannot read from stdin\n");
            perror ("gzdopen failed");
#endif
            return(NULL);
	}
#else
#ifdef WIN32
        input = -1;
#else
        input = fileno(stdin);
#endif
        if (input < 0) {
#ifdef VERBOSE_FAILURE
            fprintf (stderr, "Cannot read from stdin\n");
            perror ("open failed");
#endif
	    return(NULL);
	}
#endif
    } else {
#ifdef HAVE_ZLIB_H
	input = gzopen (filename, "r");
	if (input == NULL) {
#ifdef VERBOSE_FAILURE
	    fprintf (stderr, "Cannot read file %s :\n", filename);
	    perror ("gzopen failed");
#endif
	    return(NULL);
	}
#else
#ifdef WIN32
	input = _open (filename, O_RDONLY | _O_BINARY);
#else
	input = open (filename, O_RDONLY);
#endif
	if (input < 0) {
#ifdef VERBOSE_FAILURE
	    fprintf (stderr, "Cannot read file %s :\n", filename);
	    perror ("open failed");
#endif
	    return(NULL);
	}
#endif
    }
    /* 
     * TODO : get the 4 first bytes and decode the charset
     * if enc == XML_CHAR_ENCODING_NONE
     * plug some encoding conversion routines here. !!!
     * enc = xmlDetectCharEncoding(buffer);
     */

    ret = xmlAllocParserInputBuffer(enc);
    if (ret != NULL) {
#ifdef HAVE_ZLIB_H
        ret->gzfile = input;
#else
        ret->fd = input;
#endif
        ret->httpIO = httpIO;
        ret->ftpIO = ftpIO;
    }
    xmlParserInputBufferRead(ret, 4);

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

    if (file == NULL) return(NULL);

    ret = xmlAllocParserInputBuffer(enc);
    if (ret != NULL)
        ret->file = file;

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
    if (ret != NULL)
        ret->fd = fd;

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

	buffer = (xmlChar *) xmlMalloc((len + 1) * 2 * sizeof(xmlChar));
	if (buffer == NULL) {
	    fprintf(stderr, "xmlParserInputBufferGrow : out of memory !\n");
	    xmlFree(buffer);
	    return(-1);
	}
	nbchars = in->encoder->input(buffer, (len + 1) * 2 * sizeof(xmlChar),
	                             (xmlChar *) buf, len);
	/*
	 * TODO : we really need to have something atomic or the 
	 *        encoder must report the number of bytes read
	 */
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
#ifdef HAVE_ZLIB_H
    gzFile input = (gzFile) in->gzfile;
#endif
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
    if (in->httpIO != NULL) {
        res = xmlNanoHTTPRead(in->httpIO, &buffer[0], len);
    } else if (in->ftpIO != NULL) {
        res = xmlNanoFTPRead(in->ftpIO, &buffer[0], len);
    } else if (in->file != NULL) {
	res = fread(&buffer[0], 1, len, in->file);
#ifdef HAVE_ZLIB_H
    } else if (in->gzfile != NULL) {
    	res = gzread(input, &buffer[0], len);
#endif
    } else if (in->fd >= 0) {
	res = read(in->fd, &buffer[0], len);
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

	buf = (xmlChar *) xmlMalloc((res + 1) * 2 * sizeof(xmlChar));
	if (buf == NULL) {
	    fprintf(stderr, "xmlParserInputBufferGrow : out of memory !\n");
	    xmlFree(buffer);
	    return(-1);
	}
	nbchars = in->encoder->input(buf, (res + 1) * 2 * sizeof(xmlChar),
	                             BAD_CAST buffer, res);
        buf[nbchars] = 0;
        xmlBufferAdd(in->buffer, (xmlChar *) buf, nbchars);
	xmlFree(buf);
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
    if ((in->httpIO != NULL) || (in->ftpIO != NULL) || (in->file != NULL) ||
#ifdef HAVE_ZLIB_H
        (in->gzfile != NULL) ||
#endif
        (in->fd >= 0))
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

