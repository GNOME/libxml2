/*
 * xmlIO.c : implementation of the I/O interfaces used by the parser
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#include <string.h>

#include "parser.h"
#include "xmlIO.h"

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

    ret = (xmlParserInputBufferPtr) malloc(sizeof(xmlParserInputBuffer));
    if (ret == NULL) {
        fprintf(stderr, "xmlAllocParserInputBuffer : out of memory!\n");
	return(NULL);
    }
    memset(ret, 0, (size_t) sizeof(xmlParserInputBuffer));
    ret->buffer = xmlBufferCreate();
    ret->encoder = xmlGetCharEncodingHandler(enc);
    ret->fd = -1;

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
    if (in->fd >= 0)
        close(in->fd);
    memset(in, 0xbe, (size_t) sizeof(xmlParserInputBuffer));
    free(in);
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
    gzFile input;
#else
    int input = -1;
#endif

    if (filename == NULL) return(NULL);

    if (!strcmp(filename, "-")) {
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
 * xmlParserInputBufferGrow:
 * @in:  a buffered parser input
 * @len:  indicative value of the amount of chars to read
 *
 * Grow up the content of the input buffer, the old data are preserved
 * This routine handle the I18N transcoding to internal UTF-8
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

    buffer = malloc((len + 1) * sizeof(char));
    if (buffer == NULL) {
        fprintf(stderr, "xmlParserInputBufferGrow : out of memory !\n");
	return(-1);
    }
    if (in->file != NULL) {
	res = fread(&buffer[0], 1, len, in->file);
#ifdef HAVE_ZLIB_H
    } else if (in->gzfile != NULL) {
    	res = gzread(input, &buffer[0], len);
#endif
    } else if (in->fd >= 0) {
	res = read(in->fd, &buffer[0], len);
    } else {
        fprintf(stderr, "xmlParserInputBufferGrow : no input !\n");
	free(buffer);
	return(-1);
    }
    if (res == 0) {
	free(buffer);
        return(0);
    }
    if (res < 0) {
	perror ("read error");
	free(buffer);
	return(-1);
    }
    if (in->encoder != NULL) {
        CHAR *buf;

	buf = (CHAR *) malloc((res + 1) * 2 * sizeof(CHAR));
	if (buf == NULL) {
	    fprintf(stderr, "xmlParserInputBufferGrow : out of memory !\n");
	    free(buffer);
	    return(-1);
	}
	nbchars = in->encoder->input(buf, (res + 1) * 2 * sizeof(CHAR),
	                             BAD_CAST buffer, res);
        buf[nbchars] = 0;
        xmlBufferAdd(in->buffer, (CHAR *) buf, nbchars);
	free(buf);
    } else {
	nbchars = res;
        buffer[nbchars] = 0;
        xmlBufferAdd(in->buffer, (CHAR *) buffer, nbchars);
    }
#ifdef DEBUG_INPUT
    fprintf(stderr, "I/O: read %d chars, buffer %d/%d\n",
            nbchars, in->buffer->use, in->buffer->size);
#endif
    free(buffer);
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
    return(xmlParserInputBufferGrow(in, len));
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
	ret = strdup(dir);
    } else {
        if (getcwd(dir, 1024) != NULL) {
	    dir[1023] = 0;
	    ret = strdup(dir);
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
 * @context:  the context in which the entity is called or NULL
 *
 * By default we don't load external entitites, yet.
 * TODO: get a sample http implementation and scan for existing one
 *       at compile time.
 *
 * Returns a new allocated xmlParserInputPtr, or NULL.
 */
static
xmlParserInputPtr
xmlDefaultExternalEntityLoader(const char *URL, const char *ID,
                               xmlParserInputPtr context) {
#ifdef DEBUG_EXTERNAL_ENTITIES
    fprintf(stderr, "xmlDefaultExternalEntityLoader(%s, xxx)\n", URL);
#endif
    return(NULL);
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
 * @context:  the context in which the entity is called or NULL
 *
 * Load an external entity, note that the use of this function for
 * unparsed entities may generate problems
 * TODO: a more generic External entitiy API must be designed
 *
 * Returns the xmlParserInputPtr or NULL
 */
xmlParserInputPtr
xmlLoadExternalEntity(const char *URL, const char *ID,
                      xmlParserInputPtr context) {
    return(xmlCurrentExternalEntityLoader(URL, ID, context));
}

