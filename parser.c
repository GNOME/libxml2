/*
 * parser.c : an XML 1.0 non-verifying parser
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#define HAVE_FCNTL_H
#include <io.h>
#else
#include <config.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <string.h> /* for memset() only */
#include <stdlib.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "tree.h"
#include "parser.h"
#include "entities.h"
#include "encoding.h"
#include "valid.h"
#include "parserInternals.h"

const char *xmlParserVersion = LIBXML_VERSION;

/************************************************************************
 *									*
 * 		Parser stacks related functions and macros		*
 *									*
 ************************************************************************/

int xmlSubstituteEntitiesDefaultValue = 0;

/*
 * Generic function for accessing stacks in the Parser Context
 */

#define PUSH_AND_POP(type, name)					\
extern int name##Push(xmlParserCtxtPtr ctxt, type value) {		\
    if (ctxt->name##Nr >= ctxt->name##Max) {				\
	ctxt->name##Max *= 2;						\
        ctxt->name##Tab = (void *) realloc(ctxt->name##Tab,		\
	             ctxt->name##Max * sizeof(ctxt->name##Tab[0]));	\
        if (ctxt->name##Tab == NULL) {					\
	    fprintf(stderr, "realloc failed !\n");			\
	    exit(1);							\
	}								\
    }									\
    ctxt->name##Tab[ctxt->name##Nr] = value;				\
    ctxt->name = value;							\
    return(ctxt->name##Nr++);						\
}									\
extern type name##Pop(xmlParserCtxtPtr ctxt) {				\
    type ret;								\
    if (ctxt->name##Nr <= 0) return(0);					\
    ctxt->name##Nr--;							\
    if (ctxt->name##Nr > 0)						\
	ctxt->name = ctxt->name##Tab[ctxt->name##Nr - 1];		\
    else								\
        ctxt->name = NULL;						\
    ret = ctxt->name##Tab[ctxt->name##Nr];				\
    ctxt->name##Tab[ctxt->name##Nr] = 0;				\
    return(ret);							\
}									\

PUSH_AND_POP(xmlParserInputPtr, input)
PUSH_AND_POP(xmlNodePtr, node)

/*
 * Macros for accessing the content. Those should be used only by the parser,
 * and not exported.
 *
 * Dirty macros, i.e. one need to make assumption on the context to use them
 *
 *   CUR_PTR return the current pointer to the CHAR to be parsed.
 *   CUR     returns the current CHAR value, i.e. a 8 bit value if compiled
 *           in ISO-Latin or UTF-8, and the current 16 bit value if compiled
 *           in UNICODE mode. This should be used internally by the parser
 *           only to compare to ASCII values otherwise it would break when
 *           running with UTF-8 encoding.
 *   NXT(n)  returns the n'th next CHAR. Same as CUR is should be used only
 *           to compare on ASCII based substring.
 *   SKIP(n) Skip n CHAR, and must also be used only to skip ASCII defined
 *           strings within the parser.
 *
 * Clean macros, not dependent of an ASCII context, expect UTF-8 encoding
 *
 *   CURRENT Returns the current char value, with the full decoding of
 *           UTF-8 if we are using this mode. It returns an int.
 *   NEXT    Skip to the next character, this does the proper decoding
 *           in UTF-8 mode. It also pop-up unfinished entities on the fly.
 *           It returns the pointer to the current CHAR.
 *   COPY(to) copy one char to *to, increment CUR_PTR and to accordingly
 */

#define CUR (*ctxt->input->cur)
#define SKIP(val) ctxt->input->cur += (val)
#define NXT(val) ctxt->input->cur[(val)]
#define CUR_PTR ctxt->input->cur

#define SKIP_BLANKS 							\
    while (IS_BLANK(*(ctxt->input->cur))) NEXT

#ifndef USE_UTF_8
#define CURRENT (*ctxt->input->cur)
#define NEXT ((*ctxt->input->cur) ?					\
                (((*(ctxt->input->cur) == '\n') ?			\
		    (ctxt->input->line++, ctxt->input->col = 1) :	\
		    (ctxt->input->col++)), ctxt->input->cur++) :	\
		(xmlPopInput(ctxt), ctxt->input->cur))
#else
#endif


/**
 * xmlPopInput:
 * @ctxt:  an XML parser context
 *
 * xmlPopInput: the current input pointed by ctxt->input came to an end
 *          pop it and return the next char.
 *
 * TODO A deallocation of the popped Input structure is needed
 *
 * Returns the current CHAR in the parser context
 */
CHAR
xmlPopInput(xmlParserCtxtPtr ctxt) {
    if (ctxt->inputNr == 1) return(0); /* End of main Input */
    xmlFreeInputStream(inputPop(ctxt));
    return(CUR);
}

/**
 * xmlPushInput:
 * @ctxt:  an XML parser context
 * @input:  an XML parser input fragment (entity, XML fragment ...).
 *
 * xmlPushInput: switch to a new input stream which is stacked on top
 *               of the previous one(s).
 */
void
xmlPushInput(xmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
    if (input == NULL) return;
    inputPush(ctxt, input);
}

/**
 * xmlFreeInputStream:
 * @input:  an xmlParserInputPtr
 *
 * Free up an input stream.
 */
void
xmlFreeInputStream(xmlParserInputPtr input) {
    if (input == NULL) return;

    if (input->filename != NULL) free((char *) input->filename);
    if ((input->free != NULL) && (input->base != NULL))
        input->free((char *) input->base);
    memset(input, -1, sizeof(xmlParserInput));
    free(input);
}

/**
 * xmlNewEntityInputStream:
 * @ctxt:  an XML parser context
 * @entity:  an Entity pointer
 *
 * Create a new input stream based on an xmlEntityPtr
 * Returns the new input stream
 */
xmlParserInputPtr
xmlNewEntityInputStream(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
    xmlParserInputPtr input;

    if (entity == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	      "internal: xmlNewEntityInputStream entity = NULL\n");
	return(NULL);
    }
    if (entity->content == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	      "internal: xmlNewEntityInputStream entity->input = NULL\n");
	return(NULL);
    }
    input = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (input == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "malloc: couldn't allocate a new input stream\n");
	return(NULL);
    }
    input->filename = entity->SystemID; /* TODO !!! char <- CHAR */
    input->base = entity->content;
    input->cur = entity->content;
    input->line = 1;
    input->col = 1;
    input->free = NULL;
    return(input);
}

/**
 * xmlNewStringInputStream:
 * @ctxt:  an XML parser context
 * @entity:  an Entity memory buffer
 *
 * Create a new input stream based on a memory buffer.
 * Returns the new input stream
 */
xmlParserInputPtr
xmlNewStringInputStream(xmlParserCtxtPtr ctxt, CHAR *entity) {
    xmlParserInputPtr input;

    if (entity == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	      "internal: xmlNewStringInputStream string = NULL\n");
	return(NULL);
    }
    input = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (input == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "malloc: couldn't allocate a new input stream\n");
	return(NULL);
    }
    input->filename = NULL;
    input->base = entity;
    input->cur = entity;
    input->line = 1;
    input->col = 1;
    input->free = NULL;
    return(input);
}

/**
 * xmlNewInputFromFile:
 * @ctxt:  an XML parser context
 * @filename:  the filename to use as entity
 *
 * Create a new input stream based on a file.
 *
 * Returns the new input stream or NULL in case of error
 */
xmlParserInputPtr
xmlNewInputFromFile(xmlParserCtxtPtr ctxt, const char *filename) {
#ifdef HAVE_ZLIB_H
    gzFile input;
#else
    int input;
#endif
    int res;
    int len;
    int cnt;
    struct stat buf;
    char *buffer, *nbuf;
    xmlParserInputPtr inputStream;
    /* xmlCharEncoding enc; */

#define MINLEN 40000

    if (strcmp(filename,"-") == 0) {
#ifdef HAVE_ZLIB_H
        input = gzdopen (fileno(stdin), "r");
        if (input == NULL) {
            fprintf (stderr, "Cannot read from stdin\n");
            perror ("gzdopen failed");
            return(NULL);
	}
#else
#ifdef WIN32
        input = -1;
#else
        input = fileno(stdin);
#endif
        if (input < 0) {
            fprintf (stderr, "Cannot read from stdin\n");
            perror ("open failed");
        return(NULL);
    }
#endif
		len = MINLEN;
    } else {
#ifdef HAVE_ZLIB_H
	input = gzopen (filename, "r");
	if (input == NULL) {
	    fprintf (stderr, "Cannot read file %s :\n", filename);
	    perror ("gzopen failed");
	    return(NULL);
	}
#else
#ifdef WIN32
	input = _open (filename, O_RDONLY | _O_BINARY);
#else
	input = open (filename, O_RDONLY);
#endif
	if (input < 0) {
	    fprintf (stderr, "Cannot read file %s :\n", filename);
	    perror ("open failed");
	    return(NULL);
	}
#endif
	res = stat(filename, &buf);
	if (res < 0) 
		return(NULL);
	len = buf.st_size;
	if (len < MINLEN)
		len = MINLEN;
    }
    buffer = (char *)malloc((len+1)*sizeof(char));
    if (buffer == NULL) {
		fprintf (stderr, "Cannot malloc\n");
		perror ("malloc failed");
		return(NULL);
    }

    cnt = 0;
#ifdef HAVE_ZLIB_H
    while(!gzeof(input)) {
#else
    while(1) {
#endif
	if (cnt >= len) {
	    len *= 2;
	    nbuf =  (char *)realloc(buffer,(len+1)*sizeof(char));
	    if (nbuf == NULL) {
		    fprintf(stderr,"Cannot realloc\n");
		    free(buffer);
		    perror ("realloc failed");
		    return(NULL);
	    }
	    buffer = nbuf;
	}
#ifdef HAVE_ZLIB_H
    	res = gzread(input, &buffer[cnt], len-cnt);
#else
	res = read(input, &buffer[cnt], len-cnt);
#endif
	if (res < 0) {
	    fprintf (stderr, "Cannot read file %s :\n", filename);
#ifdef HAVE_ZLIB_H
	    perror ("gzread failed");
#else
	    perror ("read failed");
#endif
	    return(NULL);
	}
	if (res == 0) 
	    break;
	cnt += res;
    }
#ifdef HAVE_ZLIB_H
    gzclose(input);
#else
    close(input);
#endif

    buffer[cnt] = '\0';

    inputStream = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (inputStream == NULL) {
        perror("malloc");
	free(ctxt);
	return(NULL);
    }

    inputStream->filename = strdup(filename);
    inputStream->line = 1;
    inputStream->col = 1;

    /*
     * plug some encoding conversion routines here. !!!
    enc = xmlDetectCharEncoding(buffer);
    xmlSwitchEncoding(ctxt, enc);
     */

    inputStream->base = buffer;
    inputStream->cur = buffer;
    inputStream->free = (xmlParserInputDeallocate) free;

    return(inputStream);
}

/************************************************************************
 *									*
 *		Commodity functions to handle entities			*
 *									*
 ************************************************************************/

/*
 * Macro used to grow the current buffer.
 */
#define growBuffer(buffer) {						\
    buffer##_size *= 2;							\
    buffer = (CHAR *) realloc(buffer, buffer##_size * sizeof(CHAR));	\
    if (buffer == NULL) {						\
	perror("realloc failed");					\
	exit(1);							\
    }									\
}


/**
 * xmlDecodeEntities:
 * @ctxt:  the parser context
 * @what:  combination of XML_SUBSTITUTE_REF and XML_SUBSTITUTE_PEREF
 * @len:  the len to decode (in bytes !), -1 for no size limit
 * @end:  an end marker CHAR, 0 if none
 * @end2:  an end marker CHAR, 0 if none
 * @end3:  an end marker CHAR, 0 if none
 * 
 * [67] Reference ::= EntityRef | CharRef
 *
 * [69] PEReference ::= '%' Name ';'
 *
 * Returns A newly allocated string with the substitution done. The caller
 *      must deallocate it !
 */
CHAR *
xmlDecodeEntities(xmlParserCtxtPtr ctxt, int len, int what,
                  CHAR end, CHAR  end2, CHAR end3) {
    CHAR *buffer = NULL;
    int buffer_size = 0;
    CHAR *out = NULL;

    CHAR *cur = NULL;
    xmlEntityPtr ent;
    const CHAR *start = CUR_PTR;
    unsigned int max = (unsigned int) len;

    /*
     * allocate a translation buffer.
     */
    buffer_size = 1000;
    buffer = (CHAR *) malloc(buffer_size * sizeof(CHAR));
    if (buffer == NULL) {
	perror("xmlDecodeEntities: malloc failed");
	return(NULL);
    }
    out = buffer;

    /*
     * Ok loop until we reach one of the ending char or a size limit.
     */
    while ((CUR_PTR - start < max) && (CUR != end) &&
           (CUR != end2) && (CUR != end3)) {

        if (CUR == '&' && (what & XML_SUBSTITUTE_REF)) {
	    if (NXT(1) == '#') {
		int val = xmlParseCharRef(ctxt);
		/* TODO: invalid for UTF-8 variable encoding !!! */
		*out++ = val;
	    } else {
		ent = xmlParseEntityRef(ctxt);
		if (ent != NULL) {
		    cur = ent->content;
		    while (*cur != 0) {
		        *out++ = *cur++;
			if (out - buffer > buffer_size - 100) {
			    int index = out - buffer;

			    growBuffer(buffer);
			    out = &buffer[index];
			}
		    }
		}
	    }
	} else if (CUR == '%' && (what & XML_SUBSTITUTE_PEREF)) {
	    /*
	     * a PEReference induce to switch the entity flow,
	     * we break here to flush the current set of chars
	     * parsed if any. We will be called back later.
	     */
	    if (CUR_PTR != start) break;

	    xmlParsePEReference(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

            break;
	} else {
	    /*  TODO: invalid for UTF-8 , use COPY(out); */
	    *out++ = CUR;
	    if (out - buffer > buffer_size - 100) {
	      int index = out - buffer;
	      
	      growBuffer(buffer);
	      out = &buffer[index];
	    }
	    NEXT;
	}
    }
    *out++ = 0;
    return(buffer);
}


/************************************************************************
 *									*
 *		Commodity functions to handle encodings			*
 *									*
 ************************************************************************/

/**
 * xmlSwitchEncoding:
 * @ctxt:  the parser context
 * @len:  the len of @cur
 *
 * change the input functions when discovering the character encoding
 * of a given entity.
 *
 */
void
xmlSwitchEncoding(xmlParserCtxtPtr ctxt, xmlCharEncoding enc)
{
    switch (enc) {
        case XML_CHAR_ENCODING_ERROR:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "encoding unknown\n");
	    ctxt->wellFormed = 0;
            break;
        case XML_CHAR_ENCODING_NONE:
	    /* let's assume it's UTF-8 without the XML decl */
            return;
        case XML_CHAR_ENCODING_UTF8:
	    /* default encoding, no conversion should be needed */
            return;
        case XML_CHAR_ENCODING_UTF16LE:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UTF16 little endian not supported\n");
            break;
        case XML_CHAR_ENCODING_UTF16BE:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UTF16 big endian not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4LE:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding USC4 little endian not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4BE:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding USC4 big endian not supported\n");
            break;
        case XML_CHAR_ENCODING_EBCDIC:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding EBCDIC not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4_2143:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UCS4 2143 not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4_3412:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UCS4 3412 not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS2:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UCS2 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_1:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_1 ISO Latin 1 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_2:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_2 ISO Latin 2 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_3:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_3 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_4:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_4 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_5:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_5 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_6:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_6 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_7:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_7 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_8:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_8 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_9:
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_9 not supported\n");
            break;
        case XML_CHAR_ENCODING_2022_JP:
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
                  "char encoding ISO-2022-JPnot supported\n");
            break;
        case XML_CHAR_ENCODING_SHIFT_JIS:
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
                  "char encoding Shift_JISnot supported\n");
            break;
        case XML_CHAR_ENCODING_EUC_JP:
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
                  "char encoding EUC-JPnot supported\n");
            break;
    }
}

/************************************************************************
 *									*
 *		Commodity functions to handle CHARs			*
 *									*
 ************************************************************************/

/**
 * xmlStrndup:
 * @cur:  the input CHAR *
 * @len:  the len of @cur
 *
 * a strndup for array of CHAR's
 *
 * Returns a new CHAR * or NULL
 */
CHAR *
xmlStrndup(const CHAR *cur, int len) {
    CHAR *ret = malloc((len + 1) * sizeof(CHAR));

    if (ret == NULL) {
        fprintf(stderr, "malloc of %ld byte failed\n",
	        (len + 1) * (long)sizeof(CHAR));
        return(NULL);
    }
    memcpy(ret, cur, len * sizeof(CHAR));
    ret[len] = 0;
    return(ret);
}

/**
 * xmlStrdup:
 * @cur:  the input CHAR *
 *
 * a strdup for array of CHAR's
 *
 * Returns a new CHAR * or NULL
 */
CHAR *
xmlStrdup(const CHAR *cur) {
    const CHAR *p = cur;

    while (IS_CHAR(*p)) p++;
    return(xmlStrndup(cur, p - cur));
}

/**
 * xmlCharStrndup:
 * @cur:  the input char *
 * @len:  the len of @cur
 *
 * a strndup for char's to CHAR's
 *
 * Returns a new CHAR * or NULL
 */

CHAR *
xmlCharStrndup(const char *cur, int len) {
    int i;
    CHAR *ret = malloc((len + 1) * sizeof(CHAR));

    if (ret == NULL) {
        fprintf(stderr, "malloc of %ld byte failed\n",
	        (len + 1) * (long)sizeof(CHAR));
        return(NULL);
    }
    for (i = 0;i < len;i++)
        ret[i] = (CHAR) cur[i];
    ret[len] = 0;
    return(ret);
}

/**
 * xmlCharStrdup:
 * @cur:  the input char *
 * @len:  the len of @cur
 *
 * a strdup for char's to CHAR's
 *
 * Returns a new CHAR * or NULL
 */

CHAR *
xmlCharStrdup(const char *cur) {
    const char *p = cur;

    while (*p != '\0') p++;
    return(xmlCharStrndup(cur, p - cur));
}

/**
 * xmlStrcmp:
 * @str1:  the first CHAR *
 * @str2:  the second CHAR *
 *
 * a strcmp for CHAR's
 *
 * Returns the integer result of the comparison
 */

int
xmlStrcmp(const CHAR *str1, const CHAR *str2) {
    register int tmp;

    do {
        tmp = *str1++ - *str2++;
	if (tmp != 0) return(tmp);
    } while ((*str1 != 0) && (*str2 != 0));
    return (*str1 - *str2);
}

/**
 * xmlStrncmp:
 * @str1:  the first CHAR *
 * @str2:  the second CHAR *
 * @len:  the max comparison length
 *
 * a strncmp for CHAR's
 *
 * Returns the integer result of the comparison
 */

int
xmlStrncmp(const CHAR *str1, const CHAR *str2, int len) {
    register int tmp;

    if (len <= 0) return(0);
    do {
        tmp = *str1++ - *str2++;
	if (tmp != 0) return(tmp);
	len--;
        if (len <= 0) return(0);
    } while ((*str1 != 0) && (*str2 != 0));
    return (*str1 - *str2);
}

/**
 * xmlStrchr:
 * @str:  the CHAR * array
 * @val:  the CHAR to search
 *
 * a strchr for CHAR's
 *
 * Returns the CHAR * for the first occurence or NULL.
 */

CHAR *
xmlStrchr(const CHAR *str, CHAR val) {
    while (*str != 0) {
        if (*str == val) return((CHAR *) str);
	str++;
    }
    return(NULL);
}

/**
 * xmlStrlen:
 * @str:  the CHAR * array
 *
 * lenght of a CHAR's string
 *
 * Returns the number of CHAR contained in the ARRAY.
 */

int
xmlStrlen(const CHAR *str) {
    int len = 0;

    if (str == NULL) return(0);
    while (*str != 0) {
	str++;
	len++;
    }
    return(len);
}

/**
 * xmlStrncat:
 * @cur:  the original CHAR * array
 * @add:  the CHAR * array added
 * @len:  the length of @add
 *
 * a strncat for array of CHAR's
 *
 * Returns a new CHAR * containing the concatenated string.
 */

CHAR *
xmlStrncat(CHAR *cur, const CHAR *add, int len) {
    int size;
    CHAR *ret;

    if ((add == NULL) || (len == 0))
        return(cur);
    if (cur == NULL)
        return(xmlStrndup(add, len));

    size = xmlStrlen(cur);
    ret = realloc(cur, (size + len + 1) * sizeof(CHAR));
    if (ret == NULL) {
        fprintf(stderr, "xmlStrncat: realloc of %ld byte failed\n",
	        (size + len + 1) * (long)sizeof(CHAR));
        return(cur);
    }
    memcpy(&ret[size], add, len * sizeof(CHAR));
    ret[size + len] = 0;
    return(ret);
}

/**
 * xmlStrcat:
 * @cur:  the original CHAR * array
 * @add:  the CHAR * array added
 *
 * a strcat for array of CHAR's
 *
 * Returns a new CHAR * containing the concatenated string.
 */
CHAR *
xmlStrcat(CHAR *cur, const CHAR *add) {
    const CHAR *p = add;

    if (add == NULL) return(cur);
    if (cur == NULL) 
        return(xmlStrdup(add));

    while (IS_CHAR(*p)) p++;
    return(xmlStrncat(cur, add, p - add));
}

/************************************************************************
 *									*
 *		Commodity functions, cleanup needed ?			*
 *									*
 ************************************************************************/

/**
 * areBlanks:
 * @ctxt:  an XML parser context
 * @str:  a CHAR *
 * @len:  the size of @str
 *
 * Is this a sequence of blank chars that one can ignore ?
 *
 * TODO: to be corrected accodingly to DTD information if available
 *
 * Returns 1 if ignorable 0 otherwise.
 */

static int areBlanks(xmlParserCtxtPtr ctxt, const CHAR *str, int len) {
    int i;
    xmlNodePtr lastChild;

    for (i = 0;i < len;i++)
        if (!(IS_BLANK(str[i]))) return(0);

    if (CUR != '<') return(0);
    if (ctxt->node == NULL) return(0);
    lastChild = xmlGetLastChild(ctxt->node);
    if (lastChild == NULL) {
        if (ctxt->node->content != NULL) return(0);
    } else if (xmlNodeIsText(lastChild))
        return(0);
    return(1);
}

/**
 * xmlHandleEntity:
 * @ctxt:  an XML parser context
 * @entity:  an XML entity pointer.
 *
 * Default handling of defined entities, when should we define a new input
 * stream ? When do we just handle that as a set of chars ?
 * TODO: we should call the SAX handler here and have it resolve the issue
 */

void
xmlHandleEntity(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
    int len;
    xmlParserInputPtr input;

    if (entity->content == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlHandleEntity %s: content == NULL\n",
	               entity->name);
	ctxt->wellFormed = 0;
        return;
    }
    len = xmlStrlen(entity->content);
    if (len <= 2) goto handle_as_char;

    /*
     * Redefine its content as an input stream.
     */
    input = xmlNewEntityInputStream(ctxt, entity);
    xmlPushInput(ctxt, input);
    return;

handle_as_char:
    /*
     * Just handle the content as a set of chars.
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	ctxt->sax->characters(ctxt->userData, entity->content, len);

}

/*
 * Forward definition for recusive behaviour.
 */
void xmlParsePEReference(xmlParserCtxtPtr ctxt);
void xmlParseReference(xmlParserCtxtPtr ctxt);

/************************************************************************
 *									*
 *		Extra stuff for namespace support			*
 *	Relates to http://www.w3.org/TR/WD-xml-names			*
 *									*
 ************************************************************************/

/**
 * xmlNamespaceParseNCName:
 * @ctxt:  an XML parser context
 *
 * parse an XML namespace name.
 *
 * [NS 3] NCName ::= (Letter | '_') (NCNameChar)*
 *
 * [NS 4] NCNameChar ::= Letter | Digit | '.' | '-' | '_' |
 *                       CombiningChar | Extender
 *
 * Returns the namespace name or NULL
 */

CHAR *
xmlNamespaceParseNCName(xmlParserCtxtPtr ctxt) {
    const CHAR *q;
    CHAR *ret = NULL;

    if (!IS_LETTER(CUR) && (CUR != '_')) return(NULL);
    q = NEXT;

    while ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)) ||
           (CUR == '.') || (CUR == '-') ||
	   (CUR == '_') ||
	   (IS_COMBINING(CUR)) ||
	   (IS_EXTENDER(CUR)))
	NEXT;
    
    ret = xmlStrndup(q, CUR_PTR - q);

    return(ret);
}

/**
 * xmlNamespaceParseQName:
 * @ctxt:  an XML parser context
 * @prefix:  a CHAR ** 
 *
 * parse an XML qualified name
 *
 * [NS 5] QName ::= (Prefix ':')? LocalPart
 *
 * [NS 6] Prefix ::= NCName
 *
 * [NS 7] LocalPart ::= NCName
 *
 * Returns the function returns the local part, and prefix is updated
 *   to get the Prefix if any.
 */

CHAR *
xmlNamespaceParseQName(xmlParserCtxtPtr ctxt, CHAR **prefix) {
    CHAR *ret = NULL;

    *prefix = NULL;
    ret = xmlNamespaceParseNCName(ctxt);
    if (CUR == ':') {
        *prefix = ret;
	NEXT;
	ret = xmlNamespaceParseNCName(ctxt);
    }

    return(ret);
}

/**
 * xmlSplitQName:
 * @name:  an XML parser context
 * @prefix:  a CHAR ** 
 *
 * parse an XML qualified name string
 *
 * [NS 5] QName ::= (Prefix ':')? LocalPart
 *
 * [NS 6] Prefix ::= NCName
 *
 * [NS 7] LocalPart ::= NCName
 *
 * Returns the function returns the local part, and prefix is updated
 *   to get the Prefix if any.
 */

CHAR *
xmlSplitQName(const CHAR *name, CHAR **prefix) {
    CHAR *ret = NULL;
    const CHAR *q;
    const CHAR *cur = name;

    *prefix = NULL;
    if (!IS_LETTER(*cur) && (*cur != '_')) return(NULL);
    q = cur++;

    while ((IS_LETTER(*cur)) || (IS_DIGIT(*cur)) ||
           (*cur == '.') || (*cur == '-') ||
	   (*cur == '_') ||
	   (IS_COMBINING(*cur)) ||
	   (IS_EXTENDER(*cur)))
	cur++;
    
    ret = xmlStrndup(q, cur - q);

    if (*cur == ':') {
	cur++;
	if (!IS_LETTER(*cur) && (*cur != '_')) return(ret);
        *prefix = ret;

	q = cur++;

	while ((IS_LETTER(*cur)) || (IS_DIGIT(*cur)) ||
	       (*cur == '.') || (*cur == '-') ||
	       (*cur == '_') ||
	       (IS_COMBINING(*cur)) ||
	       (IS_EXTENDER(*cur)))
	    cur++;
	
	ret = xmlStrndup(q, cur - q);
    }

    return(ret);
}
/**
 * xmlNamespaceParseNSDef:
 * @ctxt:  an XML parser context
 *
 * parse a namespace prefix declaration
 *
 * [NS 1] NSDef ::= PrefixDef Eq SystemLiteral
 *
 * [NS 2] PrefixDef ::= 'xmlns' (':' NCName)?
 *
 * Returns the namespace name
 */

CHAR *
xmlNamespaceParseNSDef(xmlParserCtxtPtr ctxt) {
    CHAR *name = NULL;

    if ((CUR == 'x') && (NXT(1) == 'm') &&
        (NXT(2) == 'l') && (NXT(3) == 'n') &&
	(NXT(4) == 's')) {
	SKIP(5);
	if (CUR == ':') {
	    NEXT;
	    name = xmlNamespaceParseNCName(ctxt);
	}
    }
    return(name);
}

/**
 * xmlParseQuotedString:
 * @ctxt:  an XML parser context
 *
 * [OLD] Parse and return a string between quotes or doublequotes
 *
 * Returns the string parser or NULL.
 */
CHAR *
xmlParseQuotedString(xmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL;
    const CHAR *q;

    if (CUR == '"') {
        NEXT;
	q = CUR_PTR;
	while (IS_CHAR(CUR) && (CUR != '"')) NEXT;
	if (CUR != '"') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "String not closed \"%.50s\"\n", q);
	    ctxt->wellFormed = 0;
        } else {
            ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
	}
    } else if (CUR == '\''){
        NEXT;
	q = CUR_PTR;
	while (IS_CHAR(CUR) && (CUR != '\'')) NEXT;
	if (CUR != '\'') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "String not closed \"%.50s\"\n", q);
	    ctxt->wellFormed = 0;
        } else {
            ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
	}
    }
    return(ret);
}

/**
 * xmlParseNamespace:
 * @ctxt:  an XML parser context
 *
 * [OLD] xmlParseNamespace: parse specific PI '<?namespace ...' constructs.
 *
 * This is what the older xml-name Working Draft specified, a bunch of
 * other stuff may still rely on it, so support is still here as
 * if ot was declared on the root of the Tree:-(
 */

void
xmlParseNamespace(xmlParserCtxtPtr ctxt) {
    CHAR *href = NULL;
    CHAR *prefix = NULL;
    int garbage = 0;

    /*
     * We just skipped "namespace" or "xml:namespace"
     */
    SKIP_BLANKS;

    while (IS_CHAR(CUR) && (CUR != '>')) {
	/*
	 * We can have "ns" or "prefix" attributes
	 * Old encoding as 'href' or 'AS' attributes is still supported
	 */
	if ((CUR == 'n') && (NXT(1) == 's')) {
	    garbage = 0;
	    SKIP(2);
	    SKIP_BLANKS;

	    if (CUR != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    href = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((CUR == 'h') && (NXT(1) == 'r') &&
	    (NXT(2) == 'e') && (NXT(3) == 'f')) {
	    garbage = 0;
	    SKIP(4);
	    SKIP_BLANKS;

	    if (CUR != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    href = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((CUR == 'p') && (NXT(1) == 'r') &&
	           (NXT(2) == 'e') && (NXT(3) == 'f') &&
	           (NXT(4) == 'i') && (NXT(5) == 'x')) {
	    garbage = 0;
	    SKIP(6);
	    SKIP_BLANKS;

	    if (CUR != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    prefix = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((CUR == 'A') && (NXT(1) == 'S')) {
	    garbage = 0;
	    SKIP(2);
	    SKIP_BLANKS;

	    if (CUR != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    prefix = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((CUR == '?') && (NXT(1) == '>')) {
	    garbage = 0;
	    CUR_PTR ++;
	} else {
            /*
	     * Found garbage when parsing the namespace
	     */
	    if (!garbage)
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "xmlParseNamespace found garbage\n");
	    ctxt->wellFormed = 0;
            NEXT;
        }
    }

    MOVETO_ENDTAG(CUR_PTR);
    NEXT;

    /*
     * Register the DTD.
    if (href != NULL)
	if ((ctxt->sax != NULL) && (ctxt->sax->globalNamespace != NULL))
	    ctxt->sax->globalNamespace(ctxt->userData, href, prefix);
     */

    if (prefix != NULL) free(prefix);
    if (href != NULL) free(href);
}

/************************************************************************
 *									*
 *			The parser itself				*
 *	Relates to http://www.w3.org/TR/REC-xml				*
 *									*
 ************************************************************************/

/**
 * xmlParseName:
 * @ctxt:  an XML parser context
 *
 * parse an XML name.
 *
 * [4] NameChar ::= Letter | Digit | '.' | '-' | '_' | ':' |
 *                  CombiningChar | Extender
 *
 * [5] Name ::= (Letter | '_' | ':') (NameChar)*
 *
 * [6] Names ::= Name (S Name)*
 *
 * Returns the Name parsed or NULL
 */

CHAR *
xmlParseName(xmlParserCtxtPtr ctxt) {
    const CHAR *q;
    CHAR *ret = NULL;

    if (!IS_LETTER(CUR) && (CUR != '_') &&
        (CUR != ':')) return(NULL);
    q = NEXT;

    while ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)) ||
           (CUR == '.') || (CUR == '-') ||
	   (CUR == '_') || (CUR == ':') || 
	   (IS_COMBINING(CUR)) ||
	   (IS_EXTENDER(CUR)))
	NEXT;
    
    ret = xmlStrndup(q, CUR_PTR - q);

    return(ret);
}

/**
 * xmlParseNmtoken:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Nmtoken.
 *
 * [7] Nmtoken ::= (NameChar)+
 *
 * [8] Nmtokens ::= Nmtoken (S Nmtoken)*
 *
 * Returns the Nmtoken parsed or NULL
 */

CHAR *
xmlParseNmtoken(xmlParserCtxtPtr ctxt) {
    const CHAR *q;
    CHAR *ret = NULL;

    q = NEXT;

    while ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)) ||
           (CUR == '.') || (CUR == '-') ||
	   (CUR == '_') || (CUR == ':') || 
	   (IS_COMBINING(CUR)) ||
	   (IS_EXTENDER(CUR)))
	NEXT;
    
    ret = xmlStrndup(q, CUR_PTR - q);

    return(ret);
}

/**
 * xmlParseEntityValue:
 * @ctxt:  an XML parser context
 * @orig:  if non-NULL store a copy of the original entity value
 *
 * parse a value for ENTITY decl.
 *
 * [9] EntityValue ::= '"' ([^%&"] | PEReference | Reference)* '"' |
 *	               "'" ([^%&'] | PEReference | Reference)* "'"
 *
 * Returns the EntityValue parsed with reference substitued or NULL
 */

CHAR *
xmlParseEntityValue(xmlParserCtxtPtr ctxt, CHAR **orig) {
    CHAR *ret = NULL;
    const CHAR *org = NULL;
    const CHAR *tst = NULL;
    const CHAR *temp = NULL;

    if (CUR == '"') {
        NEXT;
	org = CUR_PTR;
	while (CUR != '"') {
	    tst = CUR_PTR;
	    temp = xmlDecodeEntities(ctxt, -1, XML_SUBSTITUTE_BOTH, '"', 0, 0);
	    if ((temp == NULL) && (tst == CUR_PTR)) break;
	    ret = xmlStrcat(ret, temp);
	    if (temp != NULL) free((char *)temp);
	}
        if (CUR != '"') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, "EntityValue: \" expected\n");
	    ctxt->wellFormed = 0;
	} else {
	    if (orig != NULL)
	        *orig = xmlStrndup(org, CUR_PTR - org);
	    NEXT;
	}
    } else if (CUR == '\'') {
        NEXT;
	org = CUR_PTR;
	while (CUR != '\'') {
	    tst = CUR_PTR;
	    temp = xmlDecodeEntities(ctxt, -1, XML_SUBSTITUTE_BOTH, '\'', 0, 0);
	    if ((temp == NULL) && (tst == CUR_PTR)) break;
	    ret = xmlStrcat(ret, temp);
	    if (temp != NULL) free((char *)temp);
	}
        if (CUR != '\'') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, "EntityValue: ' expected\n");
	    ctxt->wellFormed = 0;
	} else {
	    if (orig != NULL)
	        *orig = xmlStrndup(org, CUR_PTR - org);
	    NEXT;
	}
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "EntityValue: \" or ' expected\n");
	ctxt->wellFormed = 0;
    }
    
    return(ret);
}

/**
 * xmlParseAttValue:
 * @ctxt:  an XML parser context
 *
 * parse a value for an attribute
 * Note: the parser won't do substitution of entities here, this
 * will be handled later in xmlStringGetNodeList, unless it was
 * asked for ctxt->replaceEntities != 0 
 *
 * [10] AttValue ::= '"' ([^<&"] | Reference)* '"' |
 *                   "'" ([^<&'] | Reference)* "'"
 *
 * Returns the AttValue parsed or NULL.
 */

CHAR *
xmlParseAttValue(xmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL;

    if (CUR == '"') {
        NEXT;
	if (ctxt->replaceEntities != 0)
	    ret = xmlDecodeEntities(ctxt, -1, XML_SUBSTITUTE_REF, '"', '<', 0);
	else
	    ret = xmlDecodeEntities(ctxt, -1, XML_SUBSTITUTE_NONE, '"', '<', 0);
	if (CUR == '<') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		   "Unescaped '<' not allowed in attributes values\n");
	    ctxt->wellFormed = 0;
	}
        if (CUR != '"') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, "AttValue: ' expected\n");
	    ctxt->wellFormed = 0;
	} else
	    NEXT;
    } else if (CUR == '\'') {
        NEXT;
	if (ctxt->replaceEntities != 0)
	    ret = xmlDecodeEntities(ctxt, -1, XML_SUBSTITUTE_REF, '\'', '<', 0);
	else
	    ret = xmlDecodeEntities(ctxt, -1, XML_SUBSTITUTE_NONE, '\'', '<', 0);
	if (CUR == '<') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		   "Unescaped '<' not allowed in attributes values\n");
	    ctxt->wellFormed = 0;
	}
        if (CUR != '\'') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, "AttValue: ' expected\n");
	    ctxt->wellFormed = 0;
	} else
	    NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "AttValue: \" or ' expected\n");
	ctxt->wellFormed = 0;
    }
    
    return(ret);
}

/**
 * xmlParseSystemLiteral:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Literal
 *
 * [11] SystemLiteral ::= ('"' [^"]* '"') | ("'" [^']* "'")
 *
 * Returns the SystemLiteral parsed or NULL
 */

CHAR *
xmlParseSystemLiteral(xmlParserCtxtPtr ctxt) {
    const CHAR *q;
    CHAR *ret = NULL;

    if (CUR == '"') {
        NEXT;
	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '"'))
	    NEXT;
	if (!IS_CHAR(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Unfinished SystemLiteral\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
        }
    } else if (CUR == '\'') {
        NEXT;
	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '\''))
	    NEXT;
	if (!IS_CHAR(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Unfinished SystemLiteral\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
        }
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "SystemLiteral \" or ' expected\n");
	ctxt->wellFormed = 0;
    }
    
    return(ret);
}

/**
 * xmlParsePubidLiteral:
 * @ctxt:  an XML parser context
 *
 * parse an XML public literal
 *
 * [12] PubidLiteral ::= '"' PubidChar* '"' | "'" (PubidChar - "'")* "'"
 *
 * Returns the PubidLiteral parsed or NULL.
 */

CHAR *
xmlParsePubidLiteral(xmlParserCtxtPtr ctxt) {
    const CHAR *q;
    CHAR *ret = NULL;
    /*
     * Name ::= (Letter | '_') (NameChar)*
     */
    if (CUR == '"') {
        NEXT;
	q = CUR_PTR;
	while (IS_PUBIDCHAR(CUR)) NEXT;
	if (CUR != '"') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Unfinished PubidLiteral\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
	}
    } else if (CUR == '\'') {
        NEXT;
	q = CUR_PTR;
	while ((IS_LETTER(CUR)) && (CUR != '\''))
	    NEXT;
	if (!IS_LETTER(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Unfinished PubidLiteral\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
	}
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "SystemLiteral \" or ' expected\n");
	ctxt->wellFormed = 0;
    }
    
    return(ret);
}

/**
 * xmlParseCharData:
 * @ctxt:  an XML parser context
 * @cdata:  int indicating whether we are within a CDATA section
 *
 * parse a CharData section.
 * if we are within a CDATA section ']]>' marks an end of section.
 *
 * [14] CharData ::= [^<&]* - ([^<&]* ']]>' [^<&]*)
 */

void
xmlParseCharData(xmlParserCtxtPtr ctxt, int cdata) {
    const CHAR *q;

    q = CUR_PTR;
    while ((IS_CHAR(CUR)) && (CUR != '<') &&
           (CUR != '&')) {
	if ((CUR == ']') && (NXT(1) == ']') &&
	    (NXT(2) == '>')) {
	    if (cdata) break;
	    else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		       "Sequence ']]>' not allowed in content\n");
		ctxt->wellFormed = 0;
	    }
	}
        NEXT;
    }
    if (q == CUR_PTR) return;

    /*
     * Ok the segment [q CUR_PTR] is to be consumed as chars.
     */
    if (ctxt->sax != NULL) {
	if (areBlanks(ctxt, q, CUR_PTR - q)) {
	    if (ctxt->sax->ignorableWhitespace != NULL)
		ctxt->sax->ignorableWhitespace(ctxt->userData, q, CUR_PTR - q);
	} else {
	    if (ctxt->sax->characters != NULL)
		ctxt->sax->characters(ctxt->userData, q, CUR_PTR - q);
        }
    }
}

/**
 * xmlParseExternalID:
 * @ctxt:  an XML parser context
 * @publicID:  a CHAR** receiving PubidLiteral
 * @strict: indicate whether we should restrict parsing to only
 *          production [75], see NOTE below
 *
 * Parse an External ID or a Public ID
 *
 * NOTE: Productions [75] and [83] interract badly since [75] can generate
 *       'PUBLIC' S PubidLiteral S SystemLiteral
 *
 * [75] ExternalID ::= 'SYSTEM' S SystemLiteral
 *                   | 'PUBLIC' S PubidLiteral S SystemLiteral
 *
 * [83] PublicID ::= 'PUBLIC' S PubidLiteral
 *
 * Returns the function returns SystemLiteral and in the second
 *                case publicID receives PubidLiteral, is strict is off
 *                it is possible to return NULL and have publicID set.
 */

CHAR *
xmlParseExternalID(xmlParserCtxtPtr ctxt, CHAR **publicID, int strict) {
    CHAR *URI = NULL;

    if ((CUR == 'S') && (NXT(1) == 'Y') &&
         (NXT(2) == 'S') && (NXT(3) == 'T') &&
	 (NXT(4) == 'E') && (NXT(5) == 'M')) {
        SKIP(6);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Space required after 'SYSTEM'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
	URI = xmlParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
	          "xmlParseExternalID: SYSTEM, no URI\n");
	    ctxt->wellFormed = 0;
        }
    } else if ((CUR == 'P') && (NXT(1) == 'U') &&
	       (NXT(2) == 'B') && (NXT(3) == 'L') &&
	       (NXT(4) == 'I') && (NXT(5) == 'C')) {
        SKIP(6);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Space required after 'PUBLIC'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
	*publicID = xmlParsePubidLiteral(ctxt);
	if (*publicID == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "xmlParseExternalID: PUBLIC, no Public Identifier\n");
	    ctxt->wellFormed = 0;
	}
	if (strict) {
	    /*
	     * We don't handle [83] so "S SystemLiteral" is required.
	     */
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
			"Space required after the Public Identifier\n");
		ctxt->wellFormed = 0;
	    }
	} else {
	    /*
	     * We handle [83] so we return immediately, if 
	     * "S SystemLiteral" is not detected. From a purely parsing
	     * point of view that's a nice mess.
	     */
	    const CHAR *ptr = CUR_PTR;
	    if (!IS_BLANK(*ptr)) return(NULL);
	    
	    while (IS_BLANK(*ptr)) ptr++;
	    if ((*ptr != '\'') || (*ptr != '"')) return(NULL);
	}
        SKIP_BLANKS;
	URI = xmlParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	           "xmlParseExternalID: PUBLIC, no URI\n");
	    ctxt->wellFormed = 0;
        }
    }
    return(URI);
}

/**
 * xmlParseComment:
 * @ctxt:  an XML parser context
 * @create: should we create a node, or just skip the content
 *
 * Skip an XML (SGML) comment <!-- .... -->
 *  This may or may not create a node (depending on the context)
 *  The spec says that "For compatibility, the string "--" (double-hyphen)
 *  must not occur within comments. "
 *
 * [15] Comment ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
 */
void
xmlParseComment(xmlParserCtxtPtr ctxt, int create) {
    const CHAR *q, *start;
    const CHAR *r;
    CHAR *val;

    /*
     * Check that there is a comment right here.
     */
    if ((CUR != '<') || (NXT(1) != '!') ||
        (NXT(2) != '-') || (NXT(3) != '-')) return;

    SKIP(4);
    start = q = CUR_PTR;
    NEXT;
    r = CUR_PTR;
    NEXT;
    while (IS_CHAR(CUR) &&
           ((CUR == ':') || (CUR != '>') ||
	    (*r != '-') || (*q != '-'))) {
	if ((*r == '-') && (*q == '-')) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
	       "Comment must not contain '--' (double-hyphen)`\n");
	    ctxt->wellFormed = 0;
	}
        NEXT;r++;q++;
    }
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Comment not terminated \n<!--%.50s\n", start);
	ctxt->wellFormed = 0;
    } else {
        NEXT;
	if (create) {
	    val = xmlStrndup(start, q - start);
	    if ((ctxt->sax != NULL) && (ctxt->sax->comment != NULL))
		ctxt->sax->comment(ctxt->userData, val);
	    free(val);
	}
    }
}

/**
 * xmlParsePITarget:
 * @ctxt:  an XML parser context
 * 
 * parse the name of a PI
 *
 * [17] PITarget ::= Name - (('X' | 'x') ('M' | 'm') ('L' | 'l'))
 *
 * Returns the PITarget name or NULL
 */

CHAR *
xmlParsePITarget(xmlParserCtxtPtr ctxt) {
    CHAR *name;

    name = xmlParseName(ctxt);
    if ((name != NULL) && (name[3] == 0) &&
        ((name[0] == 'x') || (name[0] == 'X')) &&
        ((name[1] == 'm') || (name[1] == 'M')) &&
        ((name[2] == 'l') || (name[2] == 'L'))) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlParsePItarget: invalid name prefix 'xml'\n");
	return(NULL);
    }
    return(name);
}

/**
 * xmlParsePI:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Processing Instruction.
 *
 * [16] PI ::= '<?' PITarget (S (Char* - (Char* '?>' Char*)))? '?>'
 *
 * The processing is transfered to SAX once parsed.
 */

void
xmlParsePI(xmlParserCtxtPtr ctxt) {
    CHAR *target;

    if ((CUR == '<') && (NXT(1) == '?')) {
	/*
	 * this is a Processing Instruction.
	 */
	SKIP(2);

	/*
	 * Parse the target name and check for special support like
	 * namespace.
	 *
	 * TODO : PI handling should be dynamically redefinable using an
	 *        API. Only namespace should be in the code IMHO ...
	 */
        target = xmlParsePITarget(ctxt);
	if (target != NULL) {
	    const CHAR *q = CUR_PTR;

	    while (IS_CHAR(CUR) &&
		   ((CUR != '?') || (NXT(1) != '>')))
		NEXT;
	    if (!IS_CHAR(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		      "xmlParsePI: PI %s never end ...\n", target);
		ctxt->wellFormed = 0;
	    } else {
		CHAR *data;

		data = xmlStrndup(q, CUR_PTR - q);
		SKIP(2);

		/*
		 * SAX: PI detected.
		 */
		if ((ctxt->sax) &&
		    (ctxt->sax->processingInstruction != NULL))
		    ctxt->sax->processingInstruction(ctxt->userData, target, data);
		free(data);
	    }
	    free(target);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "xmlParsePI : no target name\n");
	    ctxt->wellFormed = 0;

	    /********* Should we try to complete parsing the PI ???
	    while (IS_CHAR(CUR) &&
		   (CUR != '?') && (CUR != '>'))
		NEXT;
	    if (!IS_CHAR(CUR)) {
		fprintf(stderr, "xmlParsePI: PI %s never end ...\n",
			target);
	    }
	     ********************************************************/
	}
    }
}

/**
 * xmlParseNotationDecl:
 * @ctxt:  an XML parser context
 *
 * parse a notation declaration
 *
 * [82] NotationDecl ::= '<!NOTATION' S Name S (ExternalID |  PublicID) S? '>'
 *
 * Hence there is actually 3 choices:
 *     'PUBLIC' S PubidLiteral
 *     'PUBLIC' S PubidLiteral S SystemLiteral
 * and 'SYSTEM' S SystemLiteral
 *
 * See the NOTE on xmlParseExternalID().
 */

void
xmlParseNotationDecl(xmlParserCtxtPtr ctxt) {
    CHAR *name;
    CHAR *Pubid;
    CHAR *Systemid;
    
    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'N') && (NXT(3) == 'O') &&
        (NXT(4) == 'T') && (NXT(5) == 'A') &&
        (NXT(6) == 'T') && (NXT(7) == 'I') &&
        (NXT(8) == 'O') && (NXT(9) == 'N')) {
	SKIP(10);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, "Space required after '<!NOTATION'\n");
	    ctxt->wellFormed = 0;
	    return;
	}
	SKIP_BLANKS;

        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "NOTATION: Name expected here\n");
	    ctxt->wellFormed = 0;
	    return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		     "Space required after the NOTATION name'\n");
	    ctxt->wellFormed = 0;
	    return;
	}
	SKIP_BLANKS;

	/*
	 * Parse the IDs.
	 */
	Systemid = xmlParseExternalID(ctxt, &Pubid, 1);
	SKIP_BLANKS;

	if (CUR == '>') {
	    NEXT;
	    if ((ctxt->sax != NULL) && (ctxt->sax->notationDecl != NULL))
		ctxt->sax->notationDecl(ctxt->userData, name, Pubid, Systemid);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		       "'>' required to close NOTATION declaration\n");
	    ctxt->wellFormed = 0;
	}
	free(name);
	if (Systemid != NULL) free(Systemid);
	if (Pubid != NULL) free(Pubid);
    }
}

/**
 * xmlParseEntityDecl:
 * @ctxt:  an XML parser context
 *
 * parse <!ENTITY declarations
 *
 * [70] EntityDecl ::= GEDecl | PEDecl
 *
 * [71] GEDecl ::= '<!ENTITY' S Name S EntityDef S? '>'
 *
 * [72] PEDecl ::= '<!ENTITY' S '%' S Name S PEDef S? '>'
 *
 * [73] EntityDef ::= EntityValue | (ExternalID NDataDecl?)
 *
 * [74] PEDef ::= EntityValue | ExternalID
 *
 * [76] NDataDecl ::= S 'NDATA' S Name
 */

void
xmlParseEntityDecl(xmlParserCtxtPtr ctxt) {
    CHAR *name = NULL;
    CHAR *value = NULL;
    CHAR *URI = NULL, *literal = NULL;
    CHAR *ndata = NULL;
    int isParameter = 0;
    CHAR *orig = NULL;
    
    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'E') && (NXT(3) == 'N') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
        (NXT(6) == 'T') && (NXT(7) == 'Y')) {
	SKIP(8);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, "Space required after '<!ENTITY'\n");
	    ctxt->wellFormed = 0;
	}
	SKIP_BLANKS;

	if (CUR == '%') {
	    NEXT;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "Space required after '%'\n");
		ctxt->wellFormed = 0;
	    }
	    SKIP_BLANKS;
	    isParameter = 1;
	}

        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "xmlParseEntityDecl: no name\n");
	    ctxt->wellFormed = 0;
            return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		     "Space required after the entity name\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;

	/*
	 * handle the various case of definitions...
	 */
	if (isParameter) {
	    if ((CUR == '"') || (CUR == '\''))
	        value = xmlParseEntityValue(ctxt, &orig);
		if (value) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
		                    XML_INTERNAL_PARAMETER_ENTITY,
				    NULL, NULL, value);
		}
	    else {
	        URI = xmlParseExternalID(ctxt, &literal, 1);
		if (URI) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
		                    XML_EXTERNAL_PARAMETER_ENTITY,
				    literal, URI, NULL);
		}
	    }
	} else {
	    if ((CUR == '"') || (CUR == '\'')) {
	        value = xmlParseEntityValue(ctxt, &orig);
		if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
		    ctxt->sax->entityDecl(ctxt->userData, name,
				XML_INTERNAL_GENERAL_ENTITY,
				NULL, NULL, value);
	    } else {
	        URI = xmlParseExternalID(ctxt, &literal, 1);
		if ((CUR != '>') && (!IS_BLANK(CUR))) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			    "Space required before 'NDATA'\n");
		    ctxt->wellFormed = 0;
		}
		SKIP_BLANKS;
		if ((CUR == 'N') && (NXT(1) == 'D') &&
		    (NXT(2) == 'A') && (NXT(3) == 'T') &&
		    (NXT(4) == 'A')) {
		    SKIP(5);
		    if (!IS_BLANK(CUR)) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
			        "Space required after 'NDATA'\n");
			ctxt->wellFormed = 0;
		    }
		    SKIP_BLANKS;
		    ndata = xmlParseName(ctxt);
		    if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
				    XML_EXTERNAL_GENERAL_UNPARSED_ENTITY,
				    literal, URI, ndata);
		} else {
		    if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
				    XML_EXTERNAL_GENERAL_PARSED_ENTITY,
				    literal, URI, NULL);
		}
	    }
	}
	SKIP_BLANKS;
	if (CUR != '>') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	            "xmlParseEntityDecl: entity %s not terminated\n", name);
	    ctxt->wellFormed = 0;
	} else
	    NEXT;
	if (orig != NULL) {
	    /*
	     * TODO: somwhat unclean, extending the SAx API would be better !
	     */
	    xmlEntityPtr cur = NULL;

	    if ((ctxt->sax != NULL) && (ctxt->sax->getEntity != NULL))
	        cur = ctxt->sax->getEntity(ctxt, name);
            if (cur != NULL)
	        cur->orig = orig;
	    else
		free(orig);
	}
	if (name != NULL) free(name);
	if (value != NULL) free(value);
	if (URI != NULL) free(URI);
	if (literal != NULL) free(literal);
	if (ndata != NULL) free(ndata);
    }
}

/**
 * xmlParseDefaultDecl:
 * @ctxt:  an XML parser context
 * @value:  Receive a possible fixed default value for the attribute
 *
 * Parse an attribute default declaration
 *
 * [60] DefaultDecl ::= '#REQUIRED' | '#IMPLIED' | (('#FIXED' S)? AttValue)
 *
 * returns: XML_ATTRIBUTE_NONE, XML_ATTRIBUTE_REQUIRED, XML_ATTRIBUTE_IMPLIED
 *          or XML_ATTRIBUTE_FIXED. 
 */

int
xmlParseDefaultDecl(xmlParserCtxtPtr ctxt, CHAR **value) {
    int val;
    CHAR *ret;

    *value = NULL;
    if ((CUR == '#') && (NXT(1) == 'R') &&
        (NXT(2) == 'E') && (NXT(3) == 'Q') &&
        (NXT(4) == 'U') && (NXT(5) == 'I') &&
        (NXT(6) == 'R') && (NXT(7) == 'E') &&
        (NXT(8) == 'D')) {
	SKIP(9);
	return(XML_ATTRIBUTE_REQUIRED);
    }
    if ((CUR == '#') && (NXT(1) == 'I') &&
        (NXT(2) == 'M') && (NXT(3) == 'P') &&
        (NXT(4) == 'L') && (NXT(5) == 'I') &&
        (NXT(6) == 'E') && (NXT(7) == 'D')) {
	SKIP(8);
	return(XML_ATTRIBUTE_IMPLIED);
    }
    val = XML_ATTRIBUTE_NONE;
    if ((CUR == '#') && (NXT(1) == 'F') &&
        (NXT(2) == 'I') && (NXT(3) == 'X') &&
        (NXT(4) == 'E') && (NXT(5) == 'D')) {
	SKIP(6);
	val = XML_ATTRIBUTE_FIXED;
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Space required after '#FIXED'\n");
	    ctxt->wellFormed = 0;
	}
	SKIP_BLANKS;
    }
    ret = xmlParseAttValue(ctxt);
    if (ret == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "Attribute default value declaration error\n");
	ctxt->wellFormed = 0;
    } else
        *value = ret;
    return(val);
}

/**
 * xmlParseNotationType:
 * @ctxt:  an XML parser context
 *
 * parse an Notation attribute type.
 *
 * [58] NotationType ::= 'NOTATION' S '(' S? Name (S? '|' S? Name)* S? ')'
 *
 * Note: the leading 'NOTATION' S part has already being parsed...
 *
 * Returns: the notation attribute tree built while parsing
 */

xmlEnumerationPtr
xmlParseNotationType(xmlParserCtxtPtr ctxt) {
    CHAR *name;
    xmlEnumerationPtr ret = NULL, last = NULL, cur;

    if (CUR != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "'(' required to start 'NOTATION'\n");
	ctxt->wellFormed = 0;
	return(NULL);
    }
    do {
        NEXT;
	SKIP_BLANKS;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		                 "Name expected in NOTATION declaration\n");
	    ctxt->wellFormed = 0;
	    return(ret);
	}
	cur = xmlCreateEnumeration(name);
	free(name);
	if (cur == NULL) return(ret);
	if (last == NULL) ret = last = cur;
	else {
	    last->next = cur;
	    last = cur;
	}
	SKIP_BLANKS;
    } while (CUR == '|');
    if (CUR != ')') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "')' required to finish NOTATION declaration\n");
	ctxt->wellFormed = 0;
	return(ret);
    }
    NEXT;
    return(ret);
}

/**
 * xmlParseEnumerationType:
 * @ctxt:  an XML parser context
 *
 * parse an Enumeration attribute type.
 *
 * [59] Enumeration ::= '(' S? Nmtoken (S? '|' S? Nmtoken)* S? ')'
 *
 * Returns: the enumeration attribute tree built while parsing
 */

xmlEnumerationPtr
xmlParseEnumerationType(xmlParserCtxtPtr ctxt) {
    CHAR *name;
    xmlEnumerationPtr ret = NULL, last = NULL, cur;

    if (CUR != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "'(' required to start ATTLIST enumeration\n");
	ctxt->wellFormed = 0;
	return(NULL);
    }
    do {
        NEXT;
	SKIP_BLANKS;
        name = xmlParseNmtoken(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		                 "NmToken expected in ATTLIST enumeration\n");
	    ctxt->wellFormed = 0;
	    return(ret);
	}
	cur = xmlCreateEnumeration(name);
	free(name);
	if (cur == NULL) return(ret);
	if (last == NULL) ret = last = cur;
	else {
	    last->next = cur;
	    last = cur;
	}
	SKIP_BLANKS;
    } while (CUR == '|');
    if (CUR != ')') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "')' required to finish ATTLIST enumeration\n");
	ctxt->wellFormed = 0;
	return(ret);
    }
    NEXT;
    return(ret);
}

/**
 * xmlParseEnumeratedType:
 * @ctxt:  an XML parser context
 * @tree:  the enumeration tree built while parsing
 *
 * parse an Enumerated attribute type.
 *
 * [57] EnumeratedType ::= NotationType | Enumeration
 *
 * [58] NotationType ::= 'NOTATION' S '(' S? Name (S? '|' S? Name)* S? ')'
 *
 *
 * Returns: XML_ATTRIBUTE_ENUMERATION or XML_ATTRIBUTE_NOTATION
 */

int
xmlParseEnumeratedType(xmlParserCtxtPtr ctxt, xmlEnumerationPtr *tree) {
    if ((CUR == 'N') && (NXT(1) == 'O') &&
        (NXT(2) == 'T') && (NXT(3) == 'A') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
	(NXT(6) == 'O') && (NXT(7) == 'N')) {
	SKIP(8);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Space required after 'NOTATION'\n");
	    ctxt->wellFormed = 0;
	    return(0);
	}
        SKIP_BLANKS;
	*tree = xmlParseNotationType(ctxt);
	if (*tree == NULL) return(0);
	return(XML_ATTRIBUTE_NOTATION);
    }
    *tree = xmlParseEnumerationType(ctxt);
    if (*tree == NULL) return(0);
    return(XML_ATTRIBUTE_ENUMERATION);
}

/**
 * xmlParseAttributeType:
 * @ctxt:  an XML parser context
 * @tree:  the enumeration tree built while parsing
 *
 * parse the Attribute list def for an element
 *
 * [54] AttType ::= StringType | TokenizedType | EnumeratedType
 *
 * [55] StringType ::= 'CDATA'
 *
 * [56] TokenizedType ::= 'ID' | 'IDREF' | 'IDREFS' | 'ENTITY' |
 *                        'ENTITIES' | 'NMTOKEN' | 'NMTOKENS'
 *
 * Returns the attribute type
 */
int 
xmlParseAttributeType(xmlParserCtxtPtr ctxt, xmlEnumerationPtr *tree) {
    if ((CUR == 'C') && (NXT(1) == 'D') &&
        (NXT(2) == 'A') && (NXT(3) == 'T') &&
        (NXT(4) == 'A')) {
	SKIP(5);
	return(XML_ATTRIBUTE_CDATA);
     } else if ((CUR == 'I') && (NXT(1) == 'D') &&
        (NXT(2) == 'R') && (NXT(3) == 'E') &&
        (NXT(4) == 'F')) {
	SKIP(5);
	return(XML_ATTRIBUTE_IDREF);
     } else if ((CUR == 'I') && (NXT(1) == 'D')) {
        SKIP(2);
	return(XML_ATTRIBUTE_ID);
     } else if ((CUR == 'I') && (NXT(1) == 'D') &&
        (NXT(2) == 'R') && (NXT(3) == 'E') &&
        (NXT(4) == 'F') && (NXT(5) == 'S')) {
	SKIP(6);
	return(XML_ATTRIBUTE_IDREFS);
     } else if ((CUR == 'E') && (NXT(1) == 'N') &&
        (NXT(2) == 'T') && (NXT(3) == 'I') &&
        (NXT(4) == 'T') && (NXT(5) == 'Y')) {
	SKIP(6);
	return(XML_ATTRIBUTE_ENTITY);
     } else if ((CUR == 'E') && (NXT(1) == 'N') &&
        (NXT(2) == 'T') && (NXT(3) == 'I') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
        (NXT(6) == 'E') && (NXT(7) == 'S')) {
	SKIP(8);
	return(XML_ATTRIBUTE_ENTITIES);
     } else if ((CUR == 'N') && (NXT(1) == 'M') &&
        (NXT(2) == 'T') && (NXT(3) == 'O') &&
        (NXT(4) == 'K') && (NXT(5) == 'E') &&
        (NXT(6) == 'N') && (NXT(7) == 'S')) {
	SKIP(8);
	return(XML_ATTRIBUTE_NMTOKENS);
     } else if ((CUR == 'N') && (NXT(1) == 'M') &&
        (NXT(2) == 'T') && (NXT(3) == 'O') &&
        (NXT(4) == 'K') && (NXT(5) == 'E') &&
        (NXT(6) == 'N')) {
	SKIP(7);
	return(XML_ATTRIBUTE_NMTOKEN);
     }
     return(xmlParseEnumeratedType(ctxt, tree));
}

/**
 * xmlParseAttributeListDecl:
 * @ctxt:  an XML parser context
 *
 * : parse the Attribute list def for an element
 *
 * [52] AttlistDecl ::= '<!ATTLIST' S Name AttDef* S? '>'
 *
 * [53] AttDef ::= S Name S AttType S DefaultDecl
 *
 */
void
xmlParseAttributeListDecl(xmlParserCtxtPtr ctxt) {
    CHAR *elemName;
    CHAR *attrName;
    xmlEnumerationPtr tree = NULL;

    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'A') && (NXT(3) == 'T') &&
        (NXT(4) == 'T') && (NXT(5) == 'L') &&
        (NXT(6) == 'I') && (NXT(7) == 'S') &&
        (NXT(8) == 'T')) {
	SKIP(9);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Space required after '<!ATTLIST'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
        elemName = xmlParseName(ctxt);
	if (elemName == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "ATTLIST: no name for Element\n");
	    ctxt->wellFormed = 0;
	    return;
	}
	SKIP_BLANKS;
	while (CUR != '>') {
	    const CHAR *check = CUR_PTR;
	    int type;
	    int def;
	    CHAR *defaultValue = NULL;

	    attrName = xmlParseName(ctxt);
	    if (attrName == NULL) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "ATTLIST: no name for Attribute\n");
		ctxt->wellFormed = 0;
		break;
	    }
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		        "Space required after the attribute name\n");
		ctxt->wellFormed = 0;
		break;
	    }
	    SKIP_BLANKS;

	    type = xmlParseAttributeType(ctxt, &tree);
	    if (type <= 0) break;

	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		        "Space required after the attribute type\n");
		ctxt->wellFormed = 0;
		break;
	    }
	    SKIP_BLANKS;

	    def = xmlParseDefaultDecl(ctxt, &defaultValue);
	    if (def <= 0) break;

            if (CUR != '>') {
		if (!IS_BLANK(CUR)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
			"Space required after the attribute default value\n");
		    ctxt->wellFormed = 0;
		    break;
		}
		SKIP_BLANKS;
	    }
	    if (check == CUR_PTR) {
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		    "xmlParseAttributeListDecl: detected internal error\n");
		break;
	    }
	    if ((ctxt->sax != NULL) && (ctxt->sax->attributeDecl != NULL))
		ctxt->sax->attributeDecl(ctxt->userData, elemName, attrName,
	                        type, def, defaultValue, tree);
	    if (attrName != NULL)
		free(attrName);
	    if (defaultValue != NULL)
	        free(defaultValue);
	}
	if (CUR == '>')
	    NEXT;

	free(elemName);
    }
}

/**
 * xmlParseElementMixedContentDecl:
 * @ctxt:  an XML parser context
 *
 * parse the declaration for a Mixed Element content
 * The leading '(' and spaces have been skipped in xmlParseElementContentDecl
 * 
 * [51] Mixed ::= '(' S? '#PCDATA' (S? '|' S? Name)* S? ')*' |
 *                '(' S? '#PCDATA' S? ')'
 *
 * returns: the list of the xmlElementContentPtr describing the element choices
 */
xmlElementContentPtr
xmlParseElementMixedContentDecl(xmlParserCtxtPtr ctxt) {
    xmlElementContentPtr ret = NULL, cur = NULL, n;
    CHAR *elem = NULL;

    if ((CUR == '#') && (NXT(1) == 'P') &&
        (NXT(2) == 'C') && (NXT(3) == 'D') &&
        (NXT(4) == 'A') && (NXT(5) == 'T') &&
        (NXT(6) == 'A')) {
	SKIP(7);
	SKIP_BLANKS;
	if (CUR == ')') {
	    NEXT;
	    ret = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_PCDATA);
	    return(ret);
	}
	if ((CUR == '(') || (CUR == '|')) {
	    ret = cur = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_PCDATA);
	    if (ret == NULL) return(NULL);
	} /********** else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "xmlParseElementMixedContentDecl : '|' or ')' expected\n");
	    ctxt->wellFormed = 0;
	    return(NULL);
	} **********/
	while (CUR == '|') {
	    NEXT;
	    if (elem == NULL) {
	        ret = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_OR);
		if (ret == NULL) return(NULL);
		ret->c1 = cur;
		cur = ret;
	    } else {
	        n = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_OR);
		if (n == NULL) return(NULL);
		n->c1 = xmlNewElementContent(elem, XML_ELEMENT_CONTENT_ELEMENT);
	        cur->c2 = n;
		cur = n;
		free(elem);
	    }
	    SKIP_BLANKS;
	    elem = xmlParseName(ctxt);
	    if (elem == NULL) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
			"xmlParseElementMixedContentDecl : Name expected\n");
		ctxt->wellFormed = 0;
		xmlFreeElementContent(cur);
		return(NULL);
	    }
	    SKIP_BLANKS;
	}
	if ((CUR == ')') && (NXT(1) == '*')) {
	    if (elem != NULL) {
		cur->c2 = xmlNewElementContent(elem,
		                               XML_ELEMENT_CONTENT_ELEMENT);
	        free(elem);
            }
	    ret->ocur = XML_ELEMENT_CONTENT_MULT;
	    SKIP(2);
	} else {
	    if (elem != NULL) free(elem);
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "xmlParseElementMixedContentDecl : '|' or ')*' expected\n");
	    ctxt->wellFormed = 0;
	    xmlFreeElementContent(ret);
	    return(NULL);
	}

    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementMixedContentDecl : '#PCDATA' expected\n");
	ctxt->wellFormed = 0;
    }
    return(ret);
}

/**
 * xmlParseElementChildrenContentDecl:
 * @ctxt:  an XML parser context
 *
 * parse the declaration for a Mixed Element content
 * The leading '(' and spaces have been skipped in xmlParseElementContentDecl
 * 
 *
 * [47] children ::= (choice | seq) ('?' | '*' | '+')?
 *
 * [48] cp ::= (Name | choice | seq) ('?' | '*' | '+')?
 *
 * [49] choice ::= '(' S? cp ( S? '|' S? cp )* S? ')'
 *
 * [50] seq ::= '(' S? cp ( S? ',' S? cp )* S? ')'
 *
 * returns: the tree of xmlElementContentPtr describing the element 
 *          hierarchy.
 */
xmlElementContentPtr
xmlParseElementChildrenContentDecl(xmlParserCtxtPtr ctxt) {
    xmlElementContentPtr ret = NULL, cur = NULL, last = NULL, op = NULL;
    CHAR *elem;
    CHAR type = 0;

    SKIP_BLANKS;
    if (CUR == '(') {
        /* Recurse on first child */
	NEXT;
	SKIP_BLANKS;
        cur = ret = xmlParseElementChildrenContentDecl(ctxt);
	SKIP_BLANKS;
    } else {
	elem = xmlParseName(ctxt);
	if (elem == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		"xmlParseElementChildrenContentDecl : Name or '(' expected\n");
	    ctxt->wellFormed = 0;
	    return(NULL);
	}
        cur = ret = xmlNewElementContent(elem, XML_ELEMENT_CONTENT_ELEMENT);
	if (CUR == '?') {
	    ret->ocur = XML_ELEMENT_CONTENT_OPT;
	    NEXT;
	} else if (CUR == '*') {
	    ret->ocur = XML_ELEMENT_CONTENT_MULT;
	    NEXT;
	} else if (CUR == '+') {
	    ret->ocur = XML_ELEMENT_CONTENT_PLUS;
	    NEXT;
	} else {
	    ret->ocur = XML_ELEMENT_CONTENT_ONCE;
	}
	free(elem);
    }
    SKIP_BLANKS;
    while (CUR != ')') {
        /*
	 * Each loop we parse one separator and one element.
	 */
        if (CUR == ',') {
	    if (type == 0) type = CUR;

	    /*
	     * Detect "Name | Name , Name" error
	     */
	    else if (type != CUR) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		    "xmlParseElementChildrenContentDecl : '%c' expected\n",
		    type);
		ctxt->wellFormed = 0;
		xmlFreeElementContent(ret);
		return(NULL);
	    }
	    NEXT;

	    op = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_SEQ);
	    if (op == NULL) {
	        xmlFreeElementContent(ret);
		return(NULL);
	    }
	    if (last == NULL) {
		op->c1 = ret;
		ret = cur = op;
	    } else {
	        cur->c2 = op;
		op->c1 = last;
		cur =op;
		last = NULL;
	    }
	} else if (CUR == '|') {
	    if (type == 0) type = CUR;

	    /*
	     * Detect "Name , Name | Name" error
	     */
	    else if (type != CUR) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		    "xmlParseElementChildrenContentDecl : '%c' expected\n",
		    type);
		ctxt->wellFormed = 0;
		xmlFreeElementContent(ret);
		return(NULL);
	    }
	    NEXT;

	    op = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_OR);
	    if (op == NULL) {
	        xmlFreeElementContent(ret);
		return(NULL);
	    }
	    if (last == NULL) {
		op->c1 = ret;
		ret = cur = op;
	    } else {
	        cur->c2 = op;
		op->c1 = last;
		cur =op;
		last = NULL;
	    }
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
	    "xmlParseElementChildrenContentDecl : ',' '|' or ')' expected\n");
	    ctxt->wellFormed = 0;
	    xmlFreeElementContent(ret);
	    return(NULL);
	}
	SKIP_BLANKS;
	if (CUR == '(') {
	    /* Recurse on second child */
	    NEXT;
	    SKIP_BLANKS;
	    last = xmlParseElementChildrenContentDecl(ctxt);
	    SKIP_BLANKS;
	} else {
	    elem = xmlParseName(ctxt);
	    if (elem == NULL) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		    "xmlParseElementChildrenContentDecl : Name or '(' expected\n");
		ctxt->wellFormed = 0;
		return(NULL);
	    }
	    last = xmlNewElementContent(elem, XML_ELEMENT_CONTENT_ELEMENT);
	    free(elem);
	}
	if (CUR == '?') {
	    ret->ocur = XML_ELEMENT_CONTENT_OPT;
	    NEXT;
	} else if (CUR == '*') {
	    ret->ocur = XML_ELEMENT_CONTENT_MULT;
	    NEXT;
	} else if (CUR == '+') {
	    ret->ocur = XML_ELEMENT_CONTENT_PLUS;
	    NEXT;
	} else {
	    ret->ocur = XML_ELEMENT_CONTENT_ONCE;
	}
	SKIP_BLANKS;
    }
    if ((cur != NULL) && (last != NULL)) {
        cur->c2 = last;
    }
    NEXT;
    if (CUR == '?') {
        ret->ocur = XML_ELEMENT_CONTENT_OPT;
	NEXT;
    } else if (CUR == '*') {
        ret->ocur = XML_ELEMENT_CONTENT_MULT;
	NEXT;
    } else if (CUR == '+') {
        ret->ocur = XML_ELEMENT_CONTENT_PLUS;
	NEXT;
    } else {
        ret->ocur = XML_ELEMENT_CONTENT_ONCE;
    }
    return(ret);
}

/**
 * xmlParseElementContentDecl:
 * @ctxt:  an XML parser context
 * @name:  the name of the element being defined.
 * @result:  the Element Content pointer will be stored here if any
 *
 * parse the declaration for an Element content either Mixed or Children,
 * the cases EMPTY and ANY are handled directly in xmlParseElementDecl
 * 
 * [46] contentspec ::= 'EMPTY' | 'ANY' | Mixed | children
 *
 * returns: the type of element content XML_ELEMENT_TYPE_xxx
 */

int
xmlParseElementContentDecl(xmlParserCtxtPtr ctxt, CHAR *name,
                           xmlElementContentPtr *result) {

    xmlElementContentPtr tree = NULL;
    int res;

    *result = NULL;

    if (CUR != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementContentDecl : '(' expected\n");
	ctxt->wellFormed = 0;
	return(-1);
    }
    NEXT;
    SKIP_BLANKS;
    if ((CUR == '#') && (NXT(1) == 'P') &&
        (NXT(2) == 'C') && (NXT(3) == 'D') &&
        (NXT(4) == 'A') && (NXT(5) == 'T') &&
        (NXT(6) == 'A')) {
        tree = xmlParseElementMixedContentDecl(ctxt);
	res = XML_ELEMENT_TYPE_MIXED;
    } else {
        tree = xmlParseElementChildrenContentDecl(ctxt);
	res = XML_ELEMENT_TYPE_ELEMENT;
    }
    SKIP_BLANKS;
    /****************************
    if (CUR != ')') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementContentDecl : ')' expected\n");
	ctxt->wellFormed = 0;
	return(-1);
    }
     ****************************/
    *result = tree;
    return(res);
}

/**
 * xmlParseElementDecl:
 * @ctxt:  an XML parser context
 *
 * parse an Element declaration.
 *
 * [45] elementdecl ::= '<!ELEMENT' S Name S contentspec S? '>'
 *
 * TODO There is a check [ VC: Unique Element Type Declaration ]
 *
 * Returns the type of the element, or -1 in case of error
 */
int
xmlParseElementDecl(xmlParserCtxtPtr ctxt) {
    CHAR *name;
    int ret = -1;
    xmlElementContentPtr content  = NULL;

    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'E') && (NXT(3) == 'L') &&
        (NXT(4) == 'E') && (NXT(5) == 'M') &&
        (NXT(6) == 'E') && (NXT(7) == 'N') &&
        (NXT(8) == 'T')) {
	SKIP(9);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "Space required after 'ELEMENT'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		   "xmlParseElementDecl: no name for Element\n");
	    ctxt->wellFormed = 0;
	    return(-1);
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "Space required after the element name\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
	if ((CUR == 'E') && (NXT(1) == 'M') &&
	    (NXT(2) == 'P') && (NXT(3) == 'T') &&
	    (NXT(4) == 'Y')) {
	    SKIP(5);
	    /*
	     * Element must always be empty.
	     */
	    ret = XML_ELEMENT_TYPE_EMPTY;
	} else if ((CUR == 'A') && (NXT(1) == 'N') &&
	           (NXT(2) == 'Y')) {
	    SKIP(3);
	    /*
	     * Element is a generic container.
	     */
	    ret = XML_ELEMENT_TYPE_ANY;
	} else if (CUR == '(') {
	    ret = xmlParseElementContentDecl(ctxt, name, &content);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "xmlParseElementDecl: 'EMPTY', 'ANY' or '(' expected\n");
	    ctxt->wellFormed = 0;
	    if (name != NULL) free(name);
	    return(-1);
	}
	SKIP_BLANKS;
	if (CUR != '>') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "xmlParseElementDecl: expected '>' at the end\n");
	    ctxt->wellFormed = 0;
	} else {
	    NEXT;
	    if ((ctxt->sax != NULL) && (ctxt->sax->elementDecl != NULL))
	        ctxt->sax->elementDecl(ctxt->userData, name, ret,
		                       content);
	}
	if (content != NULL) {
	    xmlFreeElementContent(content);
	}
	if (name != NULL) {
	    free(name);
	}
    }
    return(ret);
}

/**
 * xmlParseMarkupDecl:
 * @ctxt:  an XML parser context
 * 
 * parse Markup declarations
 *
 * [29] markupdecl ::= elementdecl | AttlistDecl | EntityDecl |
 *                     NotationDecl | PI | Comment
 *
 * TODO There is a check [ VC: Proper Declaration/PE Nesting ]
 */
void
xmlParseMarkupDecl(xmlParserCtxtPtr ctxt) {
    xmlParseElementDecl(ctxt);
    xmlParseAttributeListDecl(ctxt);
    xmlParseEntityDecl(ctxt);
    xmlParseNotationDecl(ctxt);
    xmlParsePI(ctxt);
    xmlParseComment(ctxt, 0);
}

/**
 * xmlParseTextDecl:
 * @ctxt:  an XML parser context
 * 
 * parse an XML declaration header for external entities
 *
 * [77] TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
 *
 * Returns the only valuable info for an external parsed entity, the encoding
 */

CHAR *
xmlParseTextDecl(xmlParserCtxtPtr ctxt) {
    CHAR *version;
    CHAR *encoding = NULL;

    /*
     * We know that '<?xml' is here.
     */
    SKIP(5);

    if (!IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed after '<?xml'\n");
	ctxt->wellFormed = 0;
    }
    SKIP_BLANKS;

    /*
     * We may have the VersionInfo here.
     */
    version = xmlParseVersionInfo(ctxt);
    /* TODO: we should actually inherit from the referencing doc if absent
    if (version == NULL)
	version = xmlCharStrdup(XML_DEFAULT_VERSION);
    ctxt->version = xmlStrdup(version);
     */
    if (version != NULL)
	free(version);

    /*
     * We must have the encoding declaration
     */
    if (!IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed here\n");
	ctxt->wellFormed = 0;
    }
    encoding = xmlParseEncodingDecl(ctxt);

    SKIP_BLANKS;
    if ((CUR == '?') && (NXT(1) == '>')) {
        SKIP(2);
    } else if (CUR == '>') {
        /* Deprecated old WD ... */
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "XML declaration must end-up with '?>'\n");
	ctxt->wellFormed = 0;
	NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "parsing XML declaration: '?>' expected\n");
	ctxt->wellFormed = 0;
	MOVETO_ENDTAG(CUR_PTR);
	NEXT;
    }
    return(encoding);
}

/*
 * xmlParseConditionalSections
 * @ctxt:  an XML parser context
 *
 * TODO : Conditionnal section are not yet supported !
 *
 * [61] conditionalSect ::= includeSect | ignoreSect 
 * [62] includeSect ::= '<![' S? 'INCLUDE' S? '[' extSubsetDecl ']]>' 
 * [63] ignoreSect ::= '<![' S? 'IGNORE' S? '[' ignoreSectContents* ']]>'
 * [64] ignoreSectContents ::= Ignore ('<![' ignoreSectContents ']]>' Ignore)*
 * [65] Ignore ::= Char* - (Char* ('<![' | ']]>') Char*)
 */

void
xmlParseConditionalSections(xmlParserCtxtPtr ctxt) {
    if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
	ctxt->sax->warning(ctxt->userData,
                           "XML conditional section not supported\n");
    /*
     * Skip up to the end of the conditionnal section.
     */
    while ((CUR != 0) && ((CUR != ']') || (NXT(1) != ']') || (NXT(2) != '>')))
	NEXT;
    if (CUR == 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	        "XML conditional section not closed\n");
	ctxt->wellFormed = 0;
    }
}

/**
 * xmlParseExternalSubset
 * @ctxt:  an XML parser context
 * 
 * parse Markup declarations from an external subset
 *
 * [30] extSubset ::= textDecl? extSubsetDecl
 *
 * [31] extSubsetDecl ::= (markupdecl | conditionalSect | PEReference | S) *
 *
 * TODO There is a check [ VC: Proper Declaration/PE Nesting ]
 */
void
xmlParseExternalSubset(xmlParserCtxtPtr ctxt, const CHAR *ExternalID,
                       const CHAR *SystemID) {
    if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l')) {
	xmlParseTextDecl(ctxt);
    }
    if (ctxt->myDoc == NULL) {
        ctxt->myDoc = xmlNewDoc("1.0");
    }
    if ((ctxt->myDoc != NULL) && (ctxt->myDoc->intSubset == NULL))
        xmlCreateIntSubset(ctxt->myDoc, NULL, ExternalID, SystemID);

    while (((CUR == '<') && (NXT(1) == '?')) ||
           ((CUR == '<') && (NXT(1) == '!')) ||
           IS_BLANK(CUR)) {
        if ((CUR == '<') && (NXT(1) == '!') && (NXT(2) == '[')) {
	    xmlParseConditionalSections(ctxt);
	} else if (IS_BLANK(CUR)) {
	    NEXT;
	} else if (CUR == '%') {
            xmlParsePEReference(ctxt);
	} else
	    xmlParseMarkupDecl(ctxt);

	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);

    }
    
    if (CUR != 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	        "Extra content at the end of the document\n");
	ctxt->wellFormed = 0;
    }

}

/**
 * xmlParseCharRef:
 * @ctxt:  an XML parser context
 *
 * parse Reference declarations
 *
 * [66] CharRef ::= '&#' [0-9]+ ';' |
 *                  '&#x' [0-9a-fA-F]+ ';'
 *
 * Returns the value parsed (as an int)
 */
int
xmlParseCharRef(xmlParserCtxtPtr ctxt) {
    int val = 0;

    if ((CUR == '&') && (NXT(1) == '#') &&
        (NXT(2) == 'x')) {
	SKIP(3);
	while (CUR != ';') {
	    if ((CUR >= '0') && (CUR <= '9')) 
	        val = val * 16 + (CUR - '0');
	    else if ((CUR >= 'a') && (CUR <= 'f'))
	        val = val * 16 + (CUR - 'a') + 10;
	    else if ((CUR >= 'A') && (CUR <= 'F'))
	        val = val * 16 + (CUR - 'A') + 10;
	    else {
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		         "xmlParseCharRef: invalid hexadecimal value\n");
		ctxt->wellFormed = 0;
		val = 0;
		break;
	    }
	    NEXT;
	}
	if (CUR == ';')
	    NEXT;
    } else if  ((CUR == '&') && (NXT(1) == '#')) {
	SKIP(2);
	while (CUR != ';') {
	    if ((CUR >= '0') && (CUR <= '9')) 
	        val = val * 10 + (CUR - '0');
	    else {
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		         "xmlParseCharRef: invalid decimal value\n");
		ctxt->wellFormed = 0;
		val = 0;
		break;
	    }
	    NEXT;
	}
	if (CUR == ';')
	    NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlParseCharRef: invalid value\n");
	ctxt->wellFormed = 0;
    }
    /*
     * Check the value IS_CHAR ...
     */
    if (IS_CHAR(val)) {
        return(val);
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlParseCharRef: invalid CHAR value %d\n",
	                     val);
	ctxt->wellFormed = 0;
    }
    return(0);
}

/**
 * xmlParseReference:
 * @ctxt:  an XML parser context
 * 
 * parse and handle entity references in content, depending on the SAX
 * interface, this may end-up in a call to character() if this is a
 * CharRef, a predefined entity, if there is no reference() callback.
 * or if the parser was asked to switch to that mode.
 *
 * [67] Reference ::= EntityRef | CharRef
 */
void
xmlParseReference(xmlParserCtxtPtr ctxt) {
    xmlEntityPtr ent;
    CHAR *val;
    if (CUR != '&') return;

    if (NXT(1) == '#') {
	CHAR out[2];
	int val = xmlParseCharRef(ctxt);
	/* TODO: invalid for UTF-8 variable encoding !!! */
	out[0] = val;
	out[1] = 0;
	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	    ctxt->sax->characters(ctxt->userData, out, 1);
    } else {
	ent = xmlParseEntityRef(ctxt);
	if (ent == NULL) return;
	if ((ent->name != NULL) && 
	    (ent->type != XML_INTERNAL_PREDEFINED_ENTITY) &&
	    (ctxt->sax != NULL) && (ctxt->sax->reference != NULL) &&
	    (ctxt->replaceEntities == 0)) {

	    /*
	     * Create a node.
	     */
	    ctxt->sax->reference(ctxt->userData, ent->name);
	    return;
	}
	val = ent->content;
	if (val == NULL) return;
	/*
	 * inline the entity.
	 */
	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	    ctxt->sax->characters(ctxt->userData, val, xmlStrlen(val));
    }
}

/**
 * xmlParseEntityRef:
 * @ctxt:  an XML parser context
 *
 * parse ENTITY references declarations
 *
 * [68] EntityRef ::= '&' Name ';'
 *
 * Returns the xmlEntityPtr if found, or NULL otherwise.
 */
xmlEntityPtr
xmlParseEntityRef(xmlParserCtxtPtr ctxt) {
    const CHAR *q; /* !!!!!!!!!!! Unused !!!!!!!!!! */
    CHAR *name;
    xmlEntityPtr ent = NULL;

    q = CUR_PTR;
    if (CUR == '&') {
        NEXT;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "xmlParseEntityRef: no name\n");
	    ctxt->wellFormed = 0;
	} else {
	    if (CUR == ';') {
	        NEXT;
		/*
		 * Ask first SAX for entity resolution, otherwise try the
		 * predefined set.
		 */
		if (ctxt->sax != NULL) {
		    if (ctxt->sax->getEntity != NULL)
			ent = ctxt->sax->getEntity(ctxt->userData, name);
		    if (ent == NULL)
		        ent = xmlGetPredefinedEntity(name);
		}

		/*
		 * Well Formedness Constraint if:
		 *   - standalone
		 * or
		 *   - no external subset and no external parameter entities
		 *     referenced
		 * then
		 *   the entity referenced must have been declared
		 *
		 * TODO: to be double checked !!! This is wrong !
		 */
		if (ent == NULL) {
		    if (ctxt->sax != NULL) {
		    if (((ctxt->sax->isStandalone != NULL) &&
			 ctxt->sax->isStandalone(ctxt->userData) == 1) ||
			(((ctxt->sax->hasInternalSubset == NULL) ||
			  ctxt->sax->hasInternalSubset(ctxt->userData) == 0) &&
			 ((ctxt->sax->hasExternalSubset == NULL) ||
			  ctxt->sax->hasExternalSubset(ctxt->userData) == 0))) {
			if (ctxt->sax->error != NULL)
			    ctxt->sax->error(ctxt->userData, 
				 "Entity '%s' not defined\n", name);
			ctxt->wellFormed = 0;
		    }
		    } else {
		        fprintf(stderr, "Entity '%s' not defined\n", name);
			ctxt->wellFormed = 0;
		    }
		}

		/*
		 * Well Formedness Constraint :
		 *   The referenced entity must be a parsed entity.
		 */
		if (ent != NULL) {
		    switch (ent->type) {
			case XML_INTERNAL_PARAMETER_ENTITY:
			case XML_EXTERNAL_PARAMETER_ENTITY:
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
		     "Attempt to reference the parameter entity '%s'\n", name);
			ctxt->wellFormed = 0;
			break;
                        
			case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
		     "Attempt to reference unparsed entity '%s'\n", name);
			ctxt->wellFormed = 0;
			break;
		    }
		}

		/*
		 * TODO: !!!
		 * Well Formedness Constraint :
		 *   The referenced entity must not lead to recursion !
		 */
		 

	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParseEntityRef: expecting ';'\n");
		ctxt->wellFormed = 0;
	    }
	    free(name);
	}
    }
    return(ent);
}

/**
 * xmlParsePEReference:
 * @ctxt:  an XML parser context
 *
 * parse PEReference declarations
 * The entity content is handled directly by pushing it's content as
 * a new input stream.
 *
 * [69] PEReference ::= '%' Name ';'
 *
 */
void
xmlParsePEReference(xmlParserCtxtPtr ctxt) {
    CHAR *name;
    xmlEntityPtr entity = NULL;
    xmlParserInputPtr input;

    if (CUR == '%') {
        NEXT;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "xmlParsePEReference: no name\n");
	    ctxt->wellFormed = 0;
	} else {
	    if (CUR == ';') {
	        NEXT;
		if ((ctxt->sax != NULL) && (ctxt->sax->getEntity != NULL))
		    entity = ctxt->sax->getEntity(ctxt->userData, name);
		/* TODO !!!! Must check that it's of the proper type !!! */
		if (entity == NULL) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
		        ctxt->sax->warning(ctxt->userData,
		         "xmlParsePEReference: %%%s; not found\n", name);
		} else {
		    input = xmlNewEntityInputStream(ctxt, entity);
		    xmlPushInput(ctxt, input);
		}
	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParsePEReference: expecting ';'\n");
		ctxt->wellFormed = 0;
	    }
	    free(name);
	}
    }
}

/**
 * xmlParseDocTypeDecl :
 * @ctxt:  an XML parser context
 *
 * parse a DOCTYPE declaration
 *
 * [28] doctypedecl ::= '<!DOCTYPE' S Name (S ExternalID)? S? 
 *                      ('[' (markupdecl | PEReference | S)* ']' S?)? '>'
 */

void
xmlParseDocTypeDecl(xmlParserCtxtPtr ctxt) {
    CHAR *name;
    CHAR *ExternalID = NULL;
    CHAR *URI = NULL;

    /*
     * We know that '<!DOCTYPE' has been detected.
     */
    SKIP(9);

    SKIP_BLANKS;

    /*
     * Parse the DOCTYPE name.
     */
    name = xmlParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlParseDocTypeDecl : no DOCTYPE name !\n");
	ctxt->wellFormed = 0;
    }

    SKIP_BLANKS;

    /*
     * Check for SystemID and ExternalID
     */
    URI = xmlParseExternalID(ctxt, &ExternalID, 1);
    SKIP_BLANKS;

    /*
     * NOTE: the SAX callback may try to fetch the external subset
     *       entity and fill it up !
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->internalSubset != NULL))
	ctxt->sax->internalSubset(ctxt->userData, name, ExternalID, URI);

    /*
     * Is there any DTD definition ?
     */
    if (CUR == '[') {
        NEXT;
	/*
	 * Parse the succession of Markup declarations and 
	 * PEReferences.
	 * Subsequence (markupdecl | PEReference | S)*
	 */
	while (CUR != ']') {
	    const CHAR *check = CUR_PTR;

	    SKIP_BLANKS;
	    xmlParseMarkupDecl(ctxt);
	    xmlParsePEReference(ctxt);

	    if (CUR_PTR == check) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		 "xmlParseDocTypeDecl: error detected in Markup declaration\n");
		ctxt->wellFormed = 0;
		break;
	    }

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

	}
	if (CUR == ']') NEXT;
    }

    /*
     * We should be at the end of the DOCTYPE declaration.
     */
    if (CUR != '>') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "DOCTYPE unproperly terminated\n");
	ctxt->wellFormed = 0;
        /* We shouldn't try to resynchronize ... */
    }
    NEXT;

    /*
     * Cleanup, since we don't use all those identifiers
     * TODO : the DOCTYPE if available should be stored !
     */
    if (URI != NULL) free(URI);
    if (ExternalID != NULL) free(ExternalID);
    if (name != NULL) free(name);
}

/**
 * xmlParseAttribute:
 * @ctxt:  an XML parser context
 * @value:  a CHAR ** used to store the value of the attribute
 *
 * parse an attribute
 *
 * [41] Attribute ::= Name Eq AttValue
 *
 * [25] Eq ::= S? '=' S?
 *
 * With namespace:
 *
 * [NS 11] Attribute ::= QName Eq AttValue
 *
 * Also the case QName == xmlns:??? is handled independently as a namespace
 * definition.
 *
 * Returns the attribute name, and the value in *value.
 */

CHAR *
xmlParseAttribute(xmlParserCtxtPtr ctxt, CHAR **value) {
    CHAR *name, *val;

    *value = NULL;
    name = xmlParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "error parsing attribute name\n");
	ctxt->wellFormed = 0;
        return(NULL);
    }

    /*
     * read the value
     */
    SKIP_BLANKS;
    if (CUR == '=') {
        NEXT;
	SKIP_BLANKS;
	val = xmlParseAttValue(ctxt);
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "Specification mandate value for attribute %s\n", name);
	ctxt->wellFormed = 0;
	return(NULL);
    }

    *value = val;
    return(name);
}

/**
 * xmlParseStartTag:
 * @ctxt:  an XML parser context
 * 
 * parse a start of tag either for rule element or
 * EmptyElement. In both case we don't parse the tag closing chars.
 *
 * [40] STag ::= '<' Name (S Attribute)* S? '>'
 *
 * [44] EmptyElemTag ::= '<' Name (S Attribute)* S? '/>'
 *
 * With namespace:
 *
 * [NS 8] STag ::= '<' QName (S Attribute)* S? '>'
 *
 * [NS 10] EmptyElement ::= '<' QName (S Attribute)* S? '/>'
 *
 * Returns the element name parsed
 */

CHAR *
xmlParseStartTag(xmlParserCtxtPtr ctxt) {
    CHAR *name;
    CHAR *attname;
    CHAR *attvalue;
    const CHAR **atts = NULL;
    int nbatts = 0;
    int maxatts = 0;
    int i;

    if (CUR != '<') return(NULL);
    NEXT;

    name = xmlParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	     "xmlParseStartTag: invalid element name\n");
	ctxt->wellFormed = 0;
        return(NULL);
    }

    /*
     * Now parse the attributes, it ends up with the ending
     *
     * (S Attribute)* S?
     */
    SKIP_BLANKS;
    while ((IS_CHAR(CUR)) &&
           (CUR != '>') && 
	   ((CUR != '/') || (NXT(1) != '>'))) {
	const CHAR *q = CUR_PTR;

	attname = xmlParseAttribute(ctxt, &attvalue);
        if ((attname != NULL) && (attvalue != NULL)) {
	    /*
	     * Well formedness requires at most one declaration of an attribute
	     */
	    for (i = 0; i < nbatts;i += 2) {
	        if (!xmlStrcmp(atts[i], attname)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, "Attribute %s redefined\n",
			                 name);
		    ctxt->wellFormed = 0;
		    free(attname);
		    free(attvalue);
		    break;
		}
	    }

	    /*
	     * Add the pair to atts
	     */
	    if (atts == NULL) {
	        maxatts = 10;
	        atts = (const CHAR **) malloc(maxatts * sizeof(CHAR *));
		if (atts == NULL) {
		    fprintf(stderr, "malloc of %ld byte failed\n",
			    maxatts * (long)sizeof(CHAR *));
		    return(NULL);
		}
	    } else if (nbatts + 2 < maxatts) {
	        maxatts *= 2;
	        atts = (const CHAR **) realloc(atts, maxatts * sizeof(CHAR *));
		if (atts == NULL) {
		    fprintf(stderr, "realloc of %ld byte failed\n",
			    maxatts * (long)sizeof(CHAR *));
		    return(NULL);
		}
	    }
	    atts[nbatts++] = attname;
	    atts[nbatts++] = attvalue;
	    atts[nbatts] = NULL;
	    atts[nbatts + 1] = NULL;
	}

	SKIP_BLANKS;
        if (q == CUR_PTR) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	         "xmlParseStartTag: problem parsing attributes\n");
	    ctxt->wellFormed = 0;
	    break;
	}
    }

    /*
     * SAX: Start of Element !
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->startElement != NULL))
        ctxt->sax->startElement(ctxt->userData, name, atts);

    if (atts != NULL) {
        for (i = 0;i < nbatts;i++) free((CHAR *) atts[i]);
	free(atts);
    }
    return(name);
}

/**
 * xmlParseEndTag:
 * @ctxt:  an XML parser context
 * @tagname:  the tag name as parsed in the opening tag.
 *
 * parse an end of tag
 *
 * [42] ETag ::= '</' Name S? '>'
 *
 * With namespace
 *
 * [NS 9] ETag ::= '</' QName S? '>'
 */

void
xmlParseEndTag(xmlParserCtxtPtr ctxt, CHAR *tagname) {
    CHAR *name;

    if ((CUR != '<') || (NXT(1) != '/')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlParseEndTag: '</' not found\n");
	ctxt->wellFormed = 0;
	return;
    }
    SKIP(2);

    name = xmlParseName(ctxt);

    /*
     * We should definitely be at the ending "S? '>'" part
     */
    SKIP_BLANKS;
    if ((!IS_CHAR(CUR)) || (CUR != '>')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "End tag : expected '>'\n");
	ctxt->wellFormed = 0;
    } else
	NEXT;

    /*
     * Well formedness constraints, opening and closing must match.
     */
    if (xmlStrcmp(name, tagname)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	     "Opening and ending tag mismatch: %s and %s\n", tagname, name);
	ctxt->wellFormed = 0;
    }

    /*
     * SAX: End of Tag
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL))
        ctxt->sax->endElement(ctxt->userData, name);

    if (name != NULL)
	free(name);

    return;
}

/**
 * xmlParseCDSect:
 * @ctxt:  an XML parser context
 * 
 * Parse escaped pure raw content.
 *
 * [18] CDSect ::= CDStart CData CDEnd
 *
 * [19] CDStart ::= '<![CDATA['
 *
 * [20] Data ::= (Char* - (Char* ']]>' Char*))
 *
 * [21] CDEnd ::= ']]>'
 */
void
xmlParseCDSect(xmlParserCtxtPtr ctxt) {
    const CHAR *r, *s, *base;

    if ((CUR == '<') && (NXT(1) == '!') &&
	(NXT(2) == '[') && (NXT(3) == 'C') &&
	(NXT(4) == 'D') && (NXT(5) == 'A') &&
	(NXT(6) == 'T') && (NXT(7) == 'A') &&
	(NXT(8) == '[')) {
	SKIP(9);
    } else
        return;
    base = CUR_PTR;
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "CData section not finished\n%.50s\n", base);
	ctxt->wellFormed = 0;
        return;
    }
    r = NEXT;
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "CData section not finished\n%.50s\n", base);
	ctxt->wellFormed = 0;
        return;
    }
    s = NEXT;
    while (IS_CHAR(CUR) &&
           ((*r != ']') || (*s != ']') || (CUR != '>'))) {
        r++;s++;NEXT;
    }
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "CData section not finished\n%.50s\n", base);
	ctxt->wellFormed = 0;
        return;
    }

    /*
     * Ok the segment [base CUR_PTR] is to be consumed as chars.
     */
    if (ctxt->sax != NULL) {
	if (areBlanks(ctxt, base, CUR_PTR - base)) {
	    if (ctxt->sax->ignorableWhitespace != NULL)
		ctxt->sax->ignorableWhitespace(ctxt->userData, base,
		                               (CUR_PTR - base) - 2);
	 } else {
	    if (ctxt->sax->characters != NULL)
		ctxt->sax->characters(ctxt->userData, base, (CUR_PTR - base) - 2);
	 }
    }
}

/**
 * xmlParseContent:
 * @ctxt:  an XML parser context
 *
 * Parse a content:
 *
 * [43] content ::= (element | CharData | Reference | CDSect | PI | Comment)*
 */

void
xmlParseContent(xmlParserCtxtPtr ctxt) {
    while ((CUR != '<') || (NXT(1) != '/')) {
	const CHAR *test = CUR_PTR;

	/*
	 * First case : a Processing Instruction.
	 */
	if ((CUR == '<') && (NXT(1) == '?')) {
	    xmlParsePI(ctxt);
	}

	/*
	 * Second case : a CDSection
	 */
	else if ((CUR == '<') && (NXT(1) == '!') &&
	    (NXT(2) == '[') && (NXT(3) == 'C') &&
	    (NXT(4) == 'D') && (NXT(5) == 'A') &&
	    (NXT(6) == 'T') && (NXT(7) == 'A') &&
	    (NXT(8) == '[')) {
	    xmlParseCDSect(ctxt);
	}

	/*
	 * Third case :  a comment
	 */
	else if ((CUR == '<') && (NXT(1) == '!') &&
		 (NXT(2) == '-') && (NXT(3) == '-')) {
	    xmlParseComment(ctxt, 1);
	}

	/*
	 * Fourth case :  a sub-element.
	 */
	else if (CUR == '<') {
	    xmlParseElement(ctxt);
	}

	/*
	 * Fifth case : a reference. If if has not been resolved,
	 *    parsing returns it's Name, create the node 
	 */
	else if (CUR == '&') {
	    xmlParseReference(ctxt);
	}

	/*
	 * Last case, text. Note that References are handled directly.
	 */
	else {
	    xmlParseCharData(ctxt, 0);
	}

	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);

	if (test == CUR_PTR) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		     "detected an error in element content\n");
	    ctxt->wellFormed = 0;
            break;
	}
    }
}

/**
 * xmlParseElement:
 * @ctxt:  an XML parser context
 *
 * parse an XML element, this is highly recursive
 *
 * [39] element ::= EmptyElemTag | STag content ETag
 *
 * [41] Attribute ::= Name Eq AttValue
 */

void
xmlParseElement(xmlParserCtxtPtr ctxt) {
    const CHAR *openTag = CUR_PTR;
    CHAR *name;
    xmlParserNodeInfo node_info;

    /* Capture start position */
    node_info.begin_pos = CUR_PTR - ctxt->input->base;
    node_info.begin_line = ctxt->input->line;

    name = xmlParseStartTag(ctxt);
    if (name == NULL) {
        return;
    }

    /*
     * Check for an Empty Element.
     */
    if ((CUR == '/') && (NXT(1) == '>')) {
        SKIP(2);
	if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL))
	    ctxt->sax->endElement(ctxt->userData, name);
	free(name);
	return;
    }
    if (CUR == '>') NEXT;
    else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Couldn't find end of Start Tag\n%.30s\n",
	                     openTag);
	ctxt->wellFormed = 0;

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);
	free(name);
	return;
    }

    /*
     * Parse the content of the element:
     */
    xmlParseContent(ctxt);
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	         "Premature end of data in tag %.30s\n", openTag);
	ctxt->wellFormed = 0;

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);
	free(name);
	return;
    }

    /*
     * parse the end of tag: '</' should be here.
     */
    xmlParseEndTag(ctxt, name);
    free(name);
}

/**
 * xmlParseVersionNum:
 * @ctxt:  an XML parser context
 *
 * parse the XML version value.
 *
 * [26] VersionNum ::= ([a-zA-Z0-9_.:] | '-')+
 *
 * Returns the string giving the XML version number, or NULL
 */
CHAR *
xmlParseVersionNum(xmlParserCtxtPtr ctxt) {
    const CHAR *q = CUR_PTR;
    CHAR *ret;

    while (IS_CHAR(CUR) &&
           (((CUR >= 'a') && (CUR <= 'z')) ||
            ((CUR >= 'A') && (CUR <= 'Z')) ||
            ((CUR >= '0') && (CUR <= '9')) ||
            (CUR == '_') || (CUR == '.') ||
	    (CUR == ':') || (CUR == '-'))) NEXT;
    ret = xmlStrndup(q, CUR_PTR - q);
    return(ret);
}

/**
 * xmlParseVersionInfo:
 * @ctxt:  an XML parser context
 * 
 * parse the XML version.
 *
 * [24] VersionInfo ::= S 'version' Eq (' VersionNum ' | " VersionNum ")
 * 
 * [25] Eq ::= S? '=' S?
 *
 * Returns the version string, e.g. "1.0"
 */

CHAR *
xmlParseVersionInfo(xmlParserCtxtPtr ctxt) {
    CHAR *version = NULL;
    const CHAR *q;

    if ((CUR == 'v') && (NXT(1) == 'e') &&
        (NXT(2) == 'r') && (NXT(3) == 's') &&
	(NXT(4) == 'i') && (NXT(5) == 'o') &&
	(NXT(6) == 'n')) {
	SKIP(7);
	SKIP_BLANKS;
	if (CUR != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "xmlParseVersionInfo : expected '='\n");
	    ctxt->wellFormed = 0;
	    return(NULL);
        }
	NEXT;
	SKIP_BLANKS;
	if (CUR == '"') {
	    NEXT;
	    q = CUR_PTR;
	    version = xmlParseVersionNum(ctxt);
	    if (CUR != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else if (CUR == '\''){
	    NEXT;
	    q = CUR_PTR;
	    version = xmlParseVersionNum(ctxt);
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		      "xmlParseVersionInfo : expected ' or \"\n");
		ctxt->wellFormed = 0;
	}
    }
    return(version);
}

/**
 * xmlParseEncName:
 * @ctxt:  an XML parser context
 *
 * parse the XML encoding name
 *
 * [81] EncName ::= [A-Za-z] ([A-Za-z0-9._] | '-')*
 *
 * Returns the encoding name value or NULL
 */
CHAR *
xmlParseEncName(xmlParserCtxtPtr ctxt) {
    const CHAR *q = CUR_PTR;
    CHAR *ret = NULL;

    if (((CUR >= 'a') && (CUR <= 'z')) ||
        ((CUR >= 'A') && (CUR <= 'Z'))) {
	NEXT;
	while (IS_CHAR(CUR) &&
	       (((CUR >= 'a') && (CUR <= 'z')) ||
		((CUR >= 'A') && (CUR <= 'Z')) ||
		((CUR >= '0') && (CUR <= '9')) ||
		(CUR == '-'))) NEXT;
	ret = xmlStrndup(q, CUR_PTR - q);
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Invalid XML encoding name\n");
	ctxt->wellFormed = 0;
    }
    return(ret);
}

/**
 * xmlParseEncodingDecl:
 * @ctxt:  an XML parser context
 * 
 * parse the XML encoding declaration
 *
 * [80] EncodingDecl ::= S 'encoding' Eq ('"' EncName '"' |  "'" EncName "'")
 *
 * TODO: this should setup the conversion filters.
 *
 * Returns the encoding value or NULL
 */

CHAR *
xmlParseEncodingDecl(xmlParserCtxtPtr ctxt) {
    CHAR *encoding = NULL;
    const CHAR *q;

    SKIP_BLANKS;
    if ((CUR == 'e') && (NXT(1) == 'n') &&
        (NXT(2) == 'c') && (NXT(3) == 'o') &&
	(NXT(4) == 'd') && (NXT(5) == 'i') &&
	(NXT(6) == 'n') && (NXT(7) == 'g')) {
	SKIP(8);
	SKIP_BLANKS;
	if (CUR != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "xmlParseEncodingDecl : expected '='\n");
	    ctxt->wellFormed = 0;
	    return(NULL);
        }
	NEXT;
	SKIP_BLANKS;
	if (CUR == '"') {
	    NEXT;
	    q = CUR_PTR;
	    encoding = xmlParseEncName(ctxt);
	    if (CUR != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else if (CUR == '\''){
	    NEXT;
	    q = CUR_PTR;
	    encoding = xmlParseEncName(ctxt);
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else if (CUR == '"'){
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		     "xmlParseEncodingDecl : expected ' or \"\n");
	    ctxt->wellFormed = 0;
	}
    }
    return(encoding);
}

/**
 * xmlParseSDDecl:
 * @ctxt:  an XML parser context
 *
 * parse the XML standalone declaration
 *
 * [32] SDDecl ::= S 'standalone' Eq
 *                 (("'" ('yes' | 'no') "'") | ('"' ('yes' | 'no')'"')) 
 *
 * Returns 1 if standalone, 0 otherwise
 */

int
xmlParseSDDecl(xmlParserCtxtPtr ctxt) {
    int standalone = -1;

    SKIP_BLANKS;
    if ((CUR == 's') && (NXT(1) == 't') &&
        (NXT(2) == 'a') && (NXT(3) == 'n') &&
	(NXT(4) == 'd') && (NXT(5) == 'a') &&
	(NXT(6) == 'l') && (NXT(7) == 'o') &&
	(NXT(8) == 'n') && (NXT(9) == 'e')) {
	SKIP(10);
        SKIP_BLANKS;
	if (CUR != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		    "XML standalone declaration : expected '='\n");
	    ctxt->wellFormed = 0;
	    return(standalone);
        }
	NEXT;
	SKIP_BLANKS;
        if (CUR == '\''){
	    NEXT;
	    if ((CUR == 'n') && (NXT(1) == 'o')) {
	        standalone = 0;
                SKIP(2);
	    } else if ((CUR == 'y') && (NXT(1) == 'e') &&
	               (NXT(2) == 's')) {
	        standalone = 1;
		SKIP(3);
            } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "standalone accepts only 'yes' or 'no'\n");
		ctxt->wellFormed = 0;
	    }
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n");
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else if (CUR == '"'){
	    NEXT;
	    if ((CUR == 'n') && (NXT(1) == 'o')) {
	        standalone = 0;
		SKIP(2);
	    } else if ((CUR == 'y') && (NXT(1) == 'e') &&
	               (NXT(2) == 's')) {
	        standalone = 1;
                SKIP(3);
            } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		        "standalone accepts only 'yes' or 'no'\n");
		ctxt->wellFormed = 0;
	    }
	    if (CUR != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n");
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else {
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Standalone value not found\n");
	    ctxt->wellFormed = 0;
        }
    }
    return(standalone);
}

/**
 * xmlParseXMLDecl:
 * @ctxt:  an XML parser context
 * 
 * parse an XML declaration header
 *
 * [23] XMLDecl ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
 */

void
xmlParseXMLDecl(xmlParserCtxtPtr ctxt) {
    CHAR *version;

    /*
     * We know that '<?xml' is here.
     */
    SKIP(5);

    if (!IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed after '<?xml'\n");
	ctxt->wellFormed = 0;
    }
    SKIP_BLANKS;

    /*
     * We should have the VersionInfo here.
     */
    version = xmlParseVersionInfo(ctxt);
    if (version == NULL)
	version = xmlCharStrdup(XML_DEFAULT_VERSION);
    ctxt->version = xmlStrdup(version);
    free(version);

    /*
     * We may have the encoding declaration
     */
    if (!IS_BLANK(CUR)) {
        if ((CUR == '?') && (NXT(1) == '>')) {
	    SKIP(2);
	    return;
	}
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed here\n");
	ctxt->wellFormed = 0;
    }
    ctxt->encoding = xmlParseEncodingDecl(ctxt);

    /*
     * We may have the standalone status.
     */
    if ((ctxt->encoding != NULL) && (!IS_BLANK(CUR))) {
        if ((CUR == '?') && (NXT(1) == '>')) {
	    SKIP(2);
	    return;
	}
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed here\n");
	ctxt->wellFormed = 0;
    }
    SKIP_BLANKS;
    ctxt->standalone = xmlParseSDDecl(ctxt);

    SKIP_BLANKS;
    if ((CUR == '?') && (NXT(1) == '>')) {
        SKIP(2);
    } else if (CUR == '>') {
        /* Deprecated old WD ... */
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "XML declaration must end-up with '?>'\n");
	ctxt->wellFormed = 0;
	NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "parsing XML declaration: '?>' expected\n");
	ctxt->wellFormed = 0;
	MOVETO_ENDTAG(CUR_PTR);
	NEXT;
    }
}

/**
 * xmlParseMisc:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Misc* optionnal field.
 *
 * [27] Misc ::= Comment | PI |  S
 */

void
xmlParseMisc(xmlParserCtxtPtr ctxt) {
    while (((CUR == '<') && (NXT(1) == '?')) ||
           ((CUR == '<') && (NXT(1) == '!') &&
	    (NXT(2) == '-') && (NXT(3) == '-')) ||
           IS_BLANK(CUR)) {
        if ((CUR == '<') && (NXT(1) == '?')) {
	    xmlParsePI(ctxt);
	} else if (IS_BLANK(CUR)) {
	    NEXT;
	} else
	    xmlParseComment(ctxt, 0);
    }
}

/**
 * xmlParseDocument :
 * @ctxt:  an XML parser context
 * 
 * parse an XML document (and build a tree if using the standard SAX
 * interface).
 *
 * [1] document ::= prolog element Misc*
 *
 * [22] prolog ::= XMLDecl? Misc* (doctypedecl Misc*)?
 *
 * Returns 0, -1 in case of error. the parser context is augmented
 *                as a result of the parsing.
 */

int
xmlParseDocument(xmlParserCtxtPtr ctxt) {
    xmlDefaultSAXHandlerInit();

    /*
     * SAX: beginning of the document processing.
     */
    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
        ctxt->sax->setDocumentLocator(ctxt->userData, &xmlDefaultSAXLocator);

    /*
     * We should check for encoding here and plug-in some
     * conversion code TODO !!!!
     */

    /*
     * Wipe out everything which is before the first '<'
     */
    if (IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	    "Extra spaces at the beginning of the document are not allowed\n");
	ctxt->wellFormed = 0;
	SKIP_BLANKS;
    }

    if (CUR == 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Document is empty\n");
	ctxt->wellFormed = 0;
    }

    /*
     * Check for the XMLDecl in the Prolog.
     */
    if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l')) {
	xmlParseXMLDecl(ctxt);
	/* SKIP_EOL(cur); */
	SKIP_BLANKS;
    } else if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'X') && (NXT(3) == 'M') &&
	(NXT(4) == 'L')) {
	/*
	 * The first drafts were using <?XML and the final W3C REC
	 * now use <?xml ...
	 */
	xmlParseXMLDecl(ctxt);
	/* SKIP_EOL(cur); */
	SKIP_BLANKS;
    } else {
	ctxt->version = xmlCharStrdup(XML_DEFAULT_VERSION);
    }
    if ((ctxt->sax) && (ctxt->sax->startDocument))
        ctxt->sax->startDocument(ctxt->userData);

    /*
     * The Misc part of the Prolog
     */
    xmlParseMisc(ctxt);

    /*
     * Then possibly doc type declaration(s) and more Misc
     * (doctypedecl Misc*)?
     */
    if ((CUR == '<') && (NXT(1) == '!') &&
	(NXT(2) == 'D') && (NXT(3) == 'O') &&
	(NXT(4) == 'C') && (NXT(5) == 'T') &&
	(NXT(6) == 'Y') && (NXT(7) == 'P') &&
	(NXT(8) == 'E')) {
	xmlParseDocTypeDecl(ctxt);
	xmlParseMisc(ctxt);
    }

    /*
     * Time to start parsing the tree itself
     */
    xmlParseElement(ctxt);

    /*
     * The Misc part at the end
     */
    xmlParseMisc(ctxt);

    if (CUR != 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	        "Extra content at the end of the document\n");
	ctxt->wellFormed = 0;
    }

    /*
     * SAX: end of the document processing.
     */
    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
        ctxt->sax->endDocument(ctxt->userData);
    if (! ctxt->wellFormed) return(-1);
    return(0);
}

/**
 * xmlCreateDocParserCtxt :
 * @cur:  a pointer to an array of CHAR
 *
 * Create a parser context for an XML in-memory document.
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreateDocParserCtxt(CHAR *cur) {
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr input;
    xmlCharEncoding enc;

    ctxt = (xmlParserCtxtPtr) malloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }
    xmlInitParserCtxt(ctxt);
    input = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (input == NULL) {
        perror("malloc");
	free(ctxt);
	return(NULL);
    }

    /*
     * plug some encoding conversion routines here. !!!
     */
    enc = xmlDetectCharEncoding(cur);
    xmlSwitchEncoding(ctxt, enc);

    input->filename = NULL;
    input->line = 1;
    input->col = 1;
    input->base = cur;
    input->cur = cur;
    input->free = NULL;

    inputPush(ctxt, input);
    return(ctxt);
}

/**
 * xmlSAXParseDoc :
 * @sax:  the SAX handler block
 * @cur:  a pointer to an array of CHAR
 * @recovery:  work in recovery mode, i.e. tries to read no Well Formed
 *             documents
 *
 * parse an XML in-memory document and build a tree.
 * It use the given SAX function block to handle the parsing callback.
 * If sax is NULL, fallback to the default DOM tree building routines.
 * 
 * Returns the resulting document tree
 */

xmlDocPtr
xmlSAXParseDoc(xmlSAXHandlerPtr sax, CHAR *cur, int recovery) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    if (cur == NULL) return(NULL);


    ctxt = xmlCreateDocParserCtxt(cur);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) { 
        ctxt->sax = sax;
        ctxt->userData = NULL;
    }

    xmlParseDocument(ctxt);
    if ((ctxt->wellFormed) || recovery) ret = ctxt->myDoc;
    else {
       ret = NULL;
       xmlFreeDoc(ctxt->myDoc);
       ctxt->myDoc = NULL;
    }
    if (sax != NULL) 
	ctxt->sax = NULL;
    xmlFreeParserCtxt(ctxt);
    
    return(ret);
}

/**
 * xmlParseDoc :
 * @cur:  a pointer to an array of CHAR
 *
 * parse an XML in-memory document and build a tree.
 * 
 * Returns the resulting document tree
 */

xmlDocPtr
xmlParseDoc(CHAR *cur) {
    return(xmlSAXParseDoc(NULL, cur, 0));
}

/**
 * xmlSAXParseDTD :
 * @sax:  the SAX handler block
 * @ExternalID:  a NAME* containing the External ID of the DTD
 * @SystemID:  a NAME* containing the URL to the DTD
 *
 * Load and parse an external subset.
 * 
 * Returns the resulting xmlDtdPtr or NULL in case of error.
 */

xmlDtdPtr
xmlSAXParseDTD(xmlSAXHandlerPtr sax, const CHAR *ExternalID,
                          const CHAR *SystemID) {
    xmlDtdPtr ret = NULL;
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr input = NULL;
    xmlCharEncoding enc;

    if ((ExternalID == NULL) && (SystemID == NULL)) return(NULL);

    ctxt = (xmlParserCtxtPtr) malloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }
    xmlInitParserCtxt(ctxt);

    /*
     * Set-up the SAX context
     */
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) { 
        ctxt->sax = sax;
        ctxt->userData = NULL;
    }

    /*
     * Ask the Entity resolver to load the damn thing
     */

    if ((ctxt->sax != NULL) && (ctxt->sax->resolveEntity != NULL))
	input = ctxt->sax->resolveEntity(ctxt->userData, ExternalID, SystemID);
    if (input == NULL) {
        if (sax != NULL) ctxt->sax = NULL;
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    /*
     * plug some encoding conversion routines here. !!!
     */
    xmlPushInput(ctxt, input);
    enc = xmlDetectCharEncoding(ctxt->input->cur);
    xmlSwitchEncoding(ctxt, enc);

    input->filename = xmlStrdup(SystemID);
    input->line = 1;
    input->col = 1;
    input->base = ctxt->input->cur;
    input->cur = ctxt->input->cur;
    input->free = NULL;

    /*
     * let's parse that entity knowing it's an external subset.
     */
    xmlParseExternalSubset(ctxt, ExternalID, SystemID);

    if (ctxt->myDoc != NULL) {
	if (ctxt->wellFormed) {
	    ret = ctxt->myDoc->intSubset;
	    ctxt->myDoc->intSubset = NULL;
	} else {
	    ret = NULL;
	}
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }
    if (sax != NULL) ctxt->sax = NULL;
    xmlFreeParserCtxt(ctxt);
    
    return(ret);
}

/**
 * xmlParseDTD :
 * @ExternalID:  a NAME* containing the External ID of the DTD
 * @SystemID:  a NAME* containing the URL to the DTD
 *
 * Load and parse an external subset.
 * 
 * Returns the resulting xmlDtdPtr or NULL in case of error.
 */

xmlDtdPtr
xmlParseDTD(const CHAR *ExternalID, const CHAR *SystemID) {
    return(xmlSAXParseDTD(NULL, ExternalID, SystemID));
}

/**
 * xmlRecoverDoc :
 * @cur:  a pointer to an array of CHAR
 *
 * parse an XML in-memory document and build a tree.
 * In the case the document is not Well Formed, a tree is built anyway
 * 
 * Returns the resulting document tree
 */

xmlDocPtr
xmlRecoverDoc(CHAR *cur) {
    return(xmlSAXParseDoc(NULL, cur, 1));
}

/**
 * xmlCreateFileParserCtxt :
 * @filename:  the filename
 *
 * Create a parser context for a file content. 
 * Automatic support for ZLIB/Compress compressed document is provided
 * by default if found at compile-time.
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreateFileParserCtxt(const char *filename)
{
    xmlParserCtxtPtr ctxt;
#ifdef HAVE_ZLIB_H
    gzFile input;
#else
    int input;
#endif
    int res;
    int len;
	int cnt;
    struct stat buf;
    char *buffer, *nbuf;
    xmlParserInputPtr inputStream;
    xmlCharEncoding enc;

#define MINLEN 40000

	if (strcmp(filename,"-") == 0) {
#ifdef HAVE_ZLIB_H
        input = gzdopen (fileno(stdin), "r");
        if (input == NULL) {
            fprintf (stderr, "Cannot read from stdin\n");
            perror ("gzdopen failed");
            return(NULL);
	    }
#else
#ifdef WIN32
        input = -1;
#else
        input = fileno(stdin);
#endif
        if (input < 0) {
            fprintf (stderr, "Cannot read from stdin\n");
            perror ("open failed");
        return(NULL);
    }
#endif
		len = MINLEN;
    } else {
#ifdef HAVE_ZLIB_H
    input = gzopen (filename, "r");
    if (input == NULL) {
        fprintf (stderr, "Cannot read file %s :\n", filename);
	perror ("gzopen failed");
	return(NULL);
    }
#else
#ifdef WIN32
    input = _open (filename, O_RDONLY | _O_BINARY);
#else
    input = open (filename, O_RDONLY);
#endif
    if (input < 0) {
        fprintf (stderr, "Cannot read file %s :\n", filename);
	perror ("open failed");
	return(NULL);
    }
#endif
		res = stat(filename, &buf);
		if (res < 0) 
			return(NULL);
		len = buf.st_size;
		if (len < MINLEN)
			len = MINLEN;
    }
	buffer = (char *)malloc((len+1)*sizeof(char));
    if (buffer == NULL) {
		fprintf (stderr, "Cannot malloc\n");
		perror ("malloc failed");
		return(NULL);
	}

	cnt = 0;
#ifdef HAVE_ZLIB_H
	while(!gzeof(input)) {
#else
	while(1) {
#endif
		if (cnt == len) {
			len *= 2;
			nbuf =  (char *)realloc(buffer,(len+1)*sizeof(char));
			if (nbuf == NULL) {
				fprintf(stderr,"Cannot realloc\n");
				free(buffer);
				perror ("realloc failed");
				return(NULL);
			}
			buffer = nbuf;
		}
#ifdef HAVE_ZLIB_H
    	res = gzread(input, &buffer[cnt], len-cnt);
#else
   		res = read(input, &buffer[cnt], len-cnt);
#endif
    if (res < 0) {
        fprintf (stderr, "Cannot read file %s :\n", filename);
#ifdef HAVE_ZLIB_H
	perror ("gzread failed");
#else
	perror ("read failed");
#endif
	return(NULL);
    }
   		if (res == 0) 
			break;
		cnt += res;
	}
#ifdef HAVE_ZLIB_H
    gzclose(input);
#else
    close(input);
#endif

    buffer[cnt] = '\0';

    ctxt = (xmlParserCtxtPtr) malloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }
    xmlInitParserCtxt(ctxt);
    inputStream = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (inputStream == NULL) {
        perror("malloc");
	free(ctxt);
	return(NULL);
    }

    inputStream->filename = strdup(filename);
    inputStream->line = 1;
    inputStream->col = 1;

    /*
     * plug some encoding conversion routines here. !!!
     */
    enc = xmlDetectCharEncoding(buffer);
    xmlSwitchEncoding(ctxt, enc);

    inputStream->base = buffer;
    inputStream->cur = buffer;
    inputStream->free = (xmlParserInputDeallocate) free;

    inputPush(ctxt, inputStream);
    return(ctxt);
}

/**
 * xmlSAXParseFile :
 * @sax:  the SAX handler block
 * @filename:  the filename
 * @recovery:  work in recovery mode, i.e. tries to read no Well Formed
 *             documents
 *
 * parse an XML file and build a tree. Automatic support for ZLIB/Compress
 * compressed document is provided by default if found at compile-time.
 * It use the given SAX function block to handle the parsing callback.
 * If sax is NULL, fallback to the default DOM tree building routines.
 *
 * Returns the resulting document tree
 */

xmlDocPtr
xmlSAXParseFile(xmlSAXHandlerPtr sax, const char *filename,
                          int recovery) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreateFileParserCtxt(filename);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) {
        ctxt->sax = sax;
        ctxt->userData = NULL;
    }

    xmlParseDocument(ctxt);

    if ((ctxt->wellFormed) || recovery) ret = ctxt->myDoc;
    else {
       ret = NULL;
       xmlFreeDoc(ctxt->myDoc);
       ctxt->myDoc = NULL;
    }
    if (sax != NULL)
        ctxt->sax = NULL;
    xmlFreeParserCtxt(ctxt);
    
    return(ret);
}

/**
 * xmlParseFile :
 * @filename:  the filename
 *
 * parse an XML file and build a tree. Automatic support for ZLIB/Compress
 * compressed document is provided by default if found at compile-time.
 *
 * Returns the resulting document tree
 */

xmlDocPtr
xmlParseFile(const char *filename) {
    return(xmlSAXParseFile(NULL, filename, 0));
}

/**
 * xmlRecoverFile :
 * @filename:  the filename
 *
 * parse an XML file and build a tree. Automatic support for ZLIB/Compress
 * compressed document is provided by default if found at compile-time.
 * In the case the document is not Well Formed, a tree is built anyway
 *
 * Returns the resulting document tree
 */

xmlDocPtr
xmlRecoverFile(const char *filename) {
    return(xmlSAXParseFile(NULL, filename, 1));
}

/**
 * xmlSubstituteEntitiesDefault :
 * @val:  int 0 or 1 
 *
 * Set and return the previous value for default entity support.
 * Initially the parser always keep entity references instead of substituting
 * entity values in the output. This function has to be used to change the
 * default parser behaviour
 * SAX::subtituteEntities() has to be used for changing that on a file by
 * file basis.
 *
 * Returns the last value for 0 for no substitution, 1 for substitution.
 */

int
xmlSubstituteEntitiesDefault(int val) {
    int old = xmlSubstituteEntitiesDefaultValue;

    xmlSubstituteEntitiesDefaultValue = val;
    return(old);
}

/**
 * xmlCreateMemoryParserCtxt :
 * @buffer:  an pointer to a char array
 * @size:  the siwe of the array
 *
 * Create a parser context for an XML in-memory document.
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreateMemoryParserCtxt(char *buffer, int size) {
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr input;
    xmlCharEncoding enc;

    buffer[size - 1] = '\0';

    ctxt = (xmlParserCtxtPtr) malloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }
    xmlInitParserCtxt(ctxt);
    input = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (input == NULL) {
        perror("malloc");
        free(ctxt->nodeTab);
	free(ctxt->inputTab);
	free(ctxt);
	return(NULL);
    }

    input->filename = NULL;
    input->line = 1;
    input->col = 1;

    /*
     * plug some encoding conversion routines here. !!!
     */
    enc = xmlDetectCharEncoding(buffer);
    xmlSwitchEncoding(ctxt, enc);

    input->base = buffer;
    input->cur = buffer;
    input->free = NULL;

    inputPush(ctxt, input);
    return(ctxt);
}

/**
 * xmlSAXParseMemory :
 * @sax:  the SAX handler block
 * @buffer:  an pointer to a char array
 * @size:  the siwe of the array
 * @recovery:  work in recovery mode, i.e. tries to read no Well Formed
 *             documents
 *
 * parse an XML in-memory block and use the given SAX function block
 * to handle the parsing callback. If sax is NULL, fallback to the default
 * DOM tree building routines.
 * 
 * Returns the resulting document tree
 */
xmlDocPtr
xmlSAXParseMemory(xmlSAXHandlerPtr sax, char *buffer, int size, int recovery) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) {
        ctxt->sax = sax;
        ctxt->userData = NULL;
    }

    xmlParseDocument(ctxt);

    if ((ctxt->wellFormed) || recovery) ret = ctxt->myDoc;
    else {
       ret = NULL;
       xmlFreeDoc(ctxt->myDoc);
       ctxt->myDoc = NULL;
    }
    if (sax != NULL) 
	ctxt->sax = NULL;
    xmlFreeParserCtxt(ctxt);
    
    return(ret);
}

/**
 * xmlParseMemory :
 * @buffer:  an pointer to a char array
 * @size:  the size of the array
 *
 * parse an XML in-memory block and build a tree.
 * 
 * Returns the resulting document tree
 */

xmlDocPtr xmlParseMemory(char *buffer, int size) {
   return(xmlSAXParseMemory(NULL, buffer, size, 0));
}

/**
 * xmlRecoverMemory :
 * @buffer:  an pointer to a char array
 * @size:  the size of the array
 *
 * parse an XML in-memory block and build a tree.
 * In the case the document is not Well Formed, a tree is built anyway
 * 
 * Returns the resulting document tree
 */

xmlDocPtr xmlRecoverMemory(char *buffer, int size) {
   return(xmlSAXParseMemory(NULL, buffer, size, 1));
}

/**
 * xmlInitParserCtxt:
 * @ctxt:  an XML parser context
 *
 * Initialize a parser context
 */

void
xmlInitParserCtxt(xmlParserCtxtPtr ctxt)
{
    xmlSAXHandler *sax;

    sax = (xmlSAXHandler *) malloc(sizeof(xmlSAXHandler));
    if (sax == NULL) {
        fprintf(stderr, "xmlInitParserCtxt: out of memory\n");
    }

    /* Allocate the Input stack */
    ctxt->inputTab = (xmlParserInputPtr *) malloc(5 * sizeof(xmlParserInputPtr));
    ctxt->inputNr = 0;
    ctxt->inputMax = 5;
    ctxt->input = NULL;
    ctxt->version = NULL;
    ctxt->encoding = NULL;
    ctxt->standalone = -1;

    /* Allocate the Node stack */
    ctxt->nodeTab = (xmlNodePtr *) malloc(10 * sizeof(xmlNodePtr));
    ctxt->nodeNr = 0;
    ctxt->nodeMax = 10;
    ctxt->node = NULL;

    if (sax == NULL) ctxt->sax = &xmlDefaultSAXHandler;
    else {
        ctxt->sax = sax;
	memcpy(sax, &xmlDefaultSAXHandler, sizeof(xmlSAXHandler));
    }
    ctxt->userData = ctxt;
    ctxt->myDoc = NULL;
    ctxt->wellFormed = 1;
    ctxt->replaceEntities = xmlSubstituteEntitiesDefaultValue;
    ctxt->record_info = 0;
    xmlInitNodeInfoSeq(&ctxt->node_seq);
}

/**
 * xmlFreeParserCtxt:
 * @ctxt:  an XML parser context
 *
 * Free all the memory used by a parser context. However the parsed
 * document in ctxt->myDoc is not freed.
 */

void
xmlFreeParserCtxt(xmlParserCtxtPtr ctxt)
{
    xmlParserInputPtr input;

    if (ctxt == NULL) return;

    while ((input = inputPop(ctxt)) != NULL) {
        xmlFreeInputStream(input);
    }

    if (ctxt->nodeTab != NULL) free(ctxt->nodeTab);
    if (ctxt->inputTab != NULL) free(ctxt->inputTab);
    if (ctxt->version != NULL) free((char *) ctxt->version);
    if ((ctxt->sax != NULL) && (ctxt->sax != &xmlDefaultSAXHandler))
        free(ctxt->sax);
    free(ctxt);
}

/**
 * xmlClearParserCtxt:
 * @ctxt:  an XML parser context
 *
 * Clear (release owned resources) and reinitialize a parser context
 */

void
xmlClearParserCtxt(xmlParserCtxtPtr ctxt)
{
  xmlClearNodeInfoSeq(&ctxt->node_seq);
  xmlInitParserCtxt(ctxt);
}


/**
 * xmlSetupParserForBuffer:
 * @ctxt:  an XML parser context
 * @buffer:  a CHAR * buffer
 * @filename:  a file name
 *
 * Setup the parser context to parse a new buffer; Clears any prior
 * contents from the parser context. The buffer parameter must not be
 * NULL, but the filename parameter can be
 */
void
xmlSetupParserForBuffer(xmlParserCtxtPtr ctxt, const CHAR* buffer,
                             const char* filename)
{
  xmlParserInputPtr input;

  input = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
  if (input == NULL) {
      perror("malloc");
      free(ctxt);
      exit(1);
  }

  xmlClearParserCtxt(ctxt);
  if (input->filename != NULL)
      input->filename = strdup(filename);
  else
      input->filename = NULL;
  input->line = 1;
  input->col = 1;
  input->base = buffer;
  input->cur = buffer;

  inputPush(ctxt, input);
}


/**
 * xmlParserFindNodeInfo:
 * @ctxt:  an XML parser context
 * @node:  an XML node within the tree
 *
 * Find the parser node info struct for a given node
 * 
 * Returns an xmlParserNodeInfo block pointer or NULL
 */
const xmlParserNodeInfo* xmlParserFindNodeInfo(const xmlParserCtxt* ctx,
                                               const xmlNode* node)
{
  unsigned long pos;

  /* Find position where node should be at */
  pos = xmlParserFindNodeInfoIndex(&ctx->node_seq, node);
  if ( ctx->node_seq.buffer[pos].node == node )
    return &ctx->node_seq.buffer[pos];
  else
    return NULL;
}


/**
 * xmlInitNodeInfoSeq :
 * @seq:  a node info sequence pointer
 *
 * -- Initialize (set to initial state) node info sequence
 */
void
xmlInitNodeInfoSeq(xmlParserNodeInfoSeqPtr seq)
{
  seq->length = 0;
  seq->maximum = 0;
  seq->buffer = NULL;
}

/**
 * xmlClearNodeInfoSeq :
 * @seq:  a node info sequence pointer
 *
 * -- Clear (release memory and reinitialize) node
 *   info sequence
 */
void
xmlClearNodeInfoSeq(xmlParserNodeInfoSeqPtr seq)
{
  if ( seq->buffer != NULL )
    free(seq->buffer);
  xmlInitNodeInfoSeq(seq);
}


/**
 * xmlParserFindNodeInfoIndex:
 * @seq:  a node info sequence pointer
 * @node:  an XML node pointer
 *
 * 
 * xmlParserFindNodeInfoIndex : Find the index that the info record for
 *   the given node is or should be at in a sorted sequence
 *
 * Returns a long indicating the position of the record
 */
unsigned long xmlParserFindNodeInfoIndex(const xmlParserNodeInfoSeq* seq,
                                         const xmlNode* node)
{
  unsigned long upper, lower, middle;
  int found = 0;

  /* Do a binary search for the key */
  lower = 1;
  upper = seq->length;
  middle = 0;
  while ( lower <= upper && !found) {
    middle = lower + (upper - lower) / 2;
    if ( node == seq->buffer[middle - 1].node )
      found = 1;
    else if ( node < seq->buffer[middle - 1].node )
      upper = middle - 1;
    else
      lower = middle + 1;
  }

  /* Return position */
  if ( middle == 0 || seq->buffer[middle - 1].node < node )
    return middle;
  else 
    return middle - 1;
}


/**
 * xmlParserAddNodeInfo:
 * @ctxt:  an XML parser context
 * @info:  a node info sequence pointer
 *
 * Insert node info record into the sorted sequence
 */
void
xmlParserAddNodeInfo(xmlParserCtxtPtr ctxt, 
                     const xmlParserNodeInfo* info)
{
  unsigned long pos;
  static unsigned int block_size = 5;

  /* Find pos and check to see if node is already in the sequence */
  pos = xmlParserFindNodeInfoIndex(&ctxt->node_seq, info->node);
  if ( pos < ctxt->node_seq.length
       && ctxt->node_seq.buffer[pos].node == info->node ) {
    ctxt->node_seq.buffer[pos] = *info;
  }

  /* Otherwise, we need to add new node to buffer */
  else {
    /* Expand buffer by 5 if needed */
    if ( ctxt->node_seq.length + 1 > ctxt->node_seq.maximum ) {
      xmlParserNodeInfo* tmp_buffer;
      unsigned int byte_size = (sizeof(*ctxt->node_seq.buffer)
                                *(ctxt->node_seq.maximum + block_size));

      if ( ctxt->node_seq.buffer == NULL )
        tmp_buffer = (xmlParserNodeInfo*)malloc(byte_size);
      else 
        tmp_buffer = (xmlParserNodeInfo*)realloc(ctxt->node_seq.buffer, byte_size);

      if ( tmp_buffer == NULL ) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Out of memory\n");
        return;
      }
      ctxt->node_seq.buffer = tmp_buffer;
      ctxt->node_seq.maximum += block_size;
    }

    /* If position is not at end, move elements out of the way */
    if ( pos != ctxt->node_seq.length ) {
      unsigned long i;

      for ( i = ctxt->node_seq.length; i > pos; i-- )
        ctxt->node_seq.buffer[i] = ctxt->node_seq.buffer[i - 1];
    }
  
    /* Copy element and increase length */
    ctxt->node_seq.buffer[pos] = *info;
    ctxt->node_seq.length++;
  }   
}


