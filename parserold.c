/*
 * parserold.c : the 1.8.11 XML parser core added for compatibility
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
#include <string.h> /* for memset() only */
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "xmlmemory.h"
#include "tree.h"
#include "parser.h"
#include "entities.h"
#include "encoding.h"
#include "valid.h"
#include "parserInternals.h"
#include "xmlIO.h"
#include "xml-error.h"

#define XML_PARSER_BIG_BUFFER_SIZE 1000
#define XML_PARSER_BUFFER_SIZE 100

/*
 * List of XML prefixed PI allowed by W3C specs
 */

static const char *xmlW3CPIs[] = {
    "xml-stylesheet",
    NULL
};

/************************************************************************
 *									*
 * 		Tweaks for plugging in the old parser			*
 *									*
 ************************************************************************/

static void xmlOldFreeInputStream(xmlParserInputPtr input);
static xmlChar * xmlOldParseName(xmlParserCtxtPtr ctxt);
static xmlEntityPtr xmlOldParseEntityRef(xmlParserCtxtPtr ctxt);
static void xmlOldParsePEReference(xmlParserCtxtPtr ctxt);
static void xmlOldParseReference(xmlParserCtxtPtr ctxt);
static xmlChar * xmlOldParseVersionInfo(xmlParserCtxtPtr ctxt);
static xmlChar * xmlOldParseEncodingDecl(xmlParserCtxtPtr ctxt);
static void xmlOldParseElement(xmlParserCtxtPtr ctxt);
static xmlChar * xmlOldScanName(xmlParserCtxtPtr ctxt);
static xmlEntityPtr
xmlOldParseStringEntityRef(xmlParserCtxtPtr ctxt, const xmlChar ** str);
static xmlEntityPtr
xmlOldParseStringPEReference(xmlParserCtxtPtr ctxt, const xmlChar **str);

extern xmlChar * xmlCharStrdup(const char *cur);

/************************************************************************
 *									*
 * 		Input handling functions for progressive parsing	*
 *									*
 ************************************************************************/

/* #define DEBUG_INPUT */
/* #define DEBUG_STACK */
/* #define DEBUG_PUSH */


#define INPUT_CHUNK	250
/* we need to keep enough input to show errors in context */
#define LINE_LEN        80

#ifdef DEBUG_INPUT
#define CHECK_BUFFER(in) check_buffer(in)

static void old_check_buffer(xmlParserInputPtr in) {
    if (in->base != in->buf->buffer->content) {
        fprintf(stderr, "xmlParserInput: base mismatch problem\n");
    }
    if (in->cur < in->base) {
        fprintf(stderr, "xmlParserInput: cur < base problem\n");
    }
    if (in->cur > in->base + in->buf->buffer->use) {
        fprintf(stderr, "xmlParserInput: cur > base + use problem\n");
    }
    fprintf(stderr,"buffer %x : content %x, cur %d, use %d, size %d\n",
            (int) in, (int) in->buf->buffer->content, in->cur - in->base,
	    in->buf->buffer->use, in->buf->buffer->size);
}

#else
#define CHECK_BUFFER(in) 
#endif


/**
 * xmlOldParserInputRead:
 * @in:  an XML parser input
 * @len:  an indicative size for the lookahead
 *
 * This function refresh the input for the parser. It doesn't try to
 * preserve pointers to the input buffer, and discard already read data
 *
 * Returns the number of xmlChars read, or -1 in case of error, 0 indicate the
 * end of this entity
 */
static int
xmlOldParserInputRead(xmlParserInputPtr in, int len) {
    int ret;
    int used;
    int index;

#ifdef DEBUG_INPUT
    fprintf(stderr, "Read\n");
#endif
    if (in->buf == NULL) return(-1);
    if (in->base == NULL) return(-1);
    if (in->cur == NULL) return(-1);
    if (in->buf->buffer == NULL) return(-1);

    CHECK_BUFFER(in);

    used = in->cur - in->buf->buffer->content;
    ret = xmlBufferShrink(in->buf->buffer, used);
    if (ret > 0) {
	in->cur -= ret;
	in->consumed += ret;
    }
    ret = xmlParserInputBufferRead(in->buf, len);
    if (in->base != in->buf->buffer->content) {
        /*
	 * the buffer has been realloced
	 */
	index = in->cur - in->base;
	in->base = in->buf->buffer->content;
	in->cur = &in->buf->buffer->content[index];
    }

    CHECK_BUFFER(in);

    return(ret);
}

/**
 * xmlOldParserInputGrow:
 * @in:  an XML parser input
 * @len:  an indicative size for the lookahead
 *
 * This function increase the input for the parser. It tries to
 * preserve pointers to the input buffer, and keep already read data
 *
 * Returns the number of xmlChars read, or -1 in case of error, 0 indicate the
 * end of this entity
 */
static int
xmlOldParserInputGrow(xmlParserInputPtr in, int len) {
    int ret;
    int index;

#ifdef DEBUG_INPUT
    fprintf(stderr, "Grow\n");
#endif
    if (in->buf == NULL) return(-1);
    if (in->base == NULL) return(-1);
    if (in->cur == NULL) return(-1);
    if (in->buf->buffer == NULL) return(-1);

    CHECK_BUFFER(in);

    index = in->cur - in->base;
    if (in->buf->buffer->use > index + INPUT_CHUNK) {

	CHECK_BUFFER(in);

        return(0);
    }
    if ((in->buf->httpIO != NULL) || (in->buf->ftpIO != NULL) ||
	(in->buf->file != NULL) ||
#ifdef HAVE_ZLIB_H
        (in->buf->gzfile != NULL) ||
#endif
        (in->buf->fd >= 0))
	ret = xmlParserInputBufferGrow(in->buf, len);
    else	
        return(0);

    /*
     * NOTE : in->base may be a "dandling" i.e. freed pointer in this
     *        block, but we use it really as an integer to do some
     *        pointer arithmetic. Insure will raise it as a bug but in
     *        that specific case, that's not !
     */
    if (in->base != in->buf->buffer->content) {
        /*
	 * the buffer has been realloced
	 */
	index = in->cur - in->base;
	in->base = in->buf->buffer->content;
	in->cur = &in->buf->buffer->content[index];
    }

    CHECK_BUFFER(in);

    return(ret);
}

/**
 * xmlOldParserInputShrink:
 * @in:  an XML parser input
 *
 * This function removes used input for the parser.
 */
static void
xmlOldParserInputShrink(xmlParserInputPtr in) {
    int used;
    int ret;
    int index;

#ifdef DEBUG_INPUT
    fprintf(stderr, "Shrink\n");
#endif
    if (in->buf == NULL) return;
    if (in->base == NULL) return;
    if (in->cur == NULL) return;
    if (in->buf->buffer == NULL) return;

    CHECK_BUFFER(in);

    used = in->cur - in->buf->buffer->content;
    if (used > INPUT_CHUNK) {
	ret = xmlBufferShrink(in->buf->buffer, used - LINE_LEN);
	if (ret > 0) {
	    in->cur -= ret;
	    in->consumed += ret;
	}
    }

    CHECK_BUFFER(in);

    if (in->buf->buffer->use > INPUT_CHUNK) {
        return;
    }
    xmlParserInputBufferRead(in->buf, 2 * INPUT_CHUNK);
    if (in->base != in->buf->buffer->content) {
        /*
	 * the buffer has been realloced
	 */
	index = in->cur - in->base;
	in->base = in->buf->buffer->content;
	in->cur = &in->buf->buffer->content[index];
    }

    CHECK_BUFFER(in);
}

/************************************************************************
 *									*
 * 		Parser stacks related functions and macros		*
 *									*
 ************************************************************************/

extern int xmlSubstituteEntitiesDefaultValue;
extern int xmlDoValidityCheckingDefaultValue;
extern int xmlKeepBlanksDefaultValue;
xmlEntityPtr xmlOldParseStringEntityRef(xmlParserCtxtPtr ctxt,
                                     const xmlChar ** str);

/*
 * Generic function for accessing stacks in the Parser Context
 */

#define PUSH_AND_POP(scope, type, name)					\
scope int name##OldPush(xmlParserCtxtPtr ctxt, type value) {		\
    if (ctxt->name##Nr >= ctxt->name##Max) {				\
	ctxt->name##Max *= 2;						\
        ctxt->name##Tab = (void *) xmlRealloc(ctxt->name##Tab,		\
	             ctxt->name##Max * sizeof(ctxt->name##Tab[0]));	\
        if (ctxt->name##Tab == NULL) {					\
	    fprintf(stderr, "realloc failed !\n");			\
	    return(0);							\
	}								\
    }									\
    ctxt->name##Tab[ctxt->name##Nr] = value;				\
    ctxt->name = value;							\
    return(ctxt->name##Nr++);						\
}									\
scope type name##OldPop(xmlParserCtxtPtr ctxt) {			\
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

PUSH_AND_POP(static, xmlParserInputPtr, input)
PUSH_AND_POP(static, xmlNodePtr, node)
PUSH_AND_POP(static, xmlChar*, name)

/*
 * Macros for accessing the content. Those should be used only by the parser,
 * and not exported.
 *
 * Dirty macros, i.e. one need to make assumption on the context to use them
 *
 *   CUR_PTR return the current pointer to the xmlChar to be parsed.
 *   CUR     returns the current xmlChar value, i.e. a 8 bit value if compiled
 *           in ISO-Latin or UTF-8, and the current 16 bit value if compiled
 *           in UNICODE mode. This should be used internally by the parser
 *           only to compare to ASCII values otherwise it would break when
 *           running with UTF-8 encoding.
 *   NXT(n)  returns the n'th next xmlChar. Same as CUR is should be used only
 *           to compare on ASCII based substring.
 *   SKIP(n) Skip n xmlChar, and must also be used only to skip ASCII defined
 *           strings within the parser.
 *
 * Clean macros, not dependent of an ASCII context, expect UTF-8 encoding
 *
 *   CURRENT Returns the current char value, with the full decoding of
 *           UTF-8 if we are using this mode. It returns an int.
 *   NEXT    Skip to the next character, this does the proper decoding
 *           in UTF-8 mode. It also pop-up unfinished entities on the fly.
 *   COPY(to) copy one char to *to, increment CUR_PTR and to accordingly
 */

#define RAW (ctxt->token ? -1 : (*ctxt->input->cur))
#define CUR (ctxt->token ? ctxt->token : (*ctxt->input->cur))
#define SKIP(val) ctxt->nbChars += (val),ctxt->input->cur += (val)
#define NXT(val) ctxt->input->cur[(val)]
#define CUR_PTR ctxt->input->cur
#define SHRINK  xmlOldParserInputShrink(ctxt->input);			\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlOldParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))		\
	    xmlOldPopInput(ctxt)

#define GROW  xmlOldParserInputGrow(ctxt->input, INPUT_CHUNK);		\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlOldParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))		\
	    xmlOldPopInput(ctxt)

#define SKIP_BLANKS 							\
    do { 								\
	while (IS_BLANK(CUR)) NEXT;					\
	while ((CUR == 0) && (ctxt->inputNr > 1))			\
	    xmlOldPopInput(ctxt);						\
	if (*ctxt->input->cur == '%') xmlOldParserHandlePEReference(ctxt);	\
	if (*ctxt->input->cur == '&') xmlOldParserHandleReference(ctxt);	\
    } while (IS_BLANK(CUR));

#define CURRENT (*ctxt->input->cur)
#define NEXT {								\
    if (ctxt->token != 0) ctxt->token = 0;				\
    else {								\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlOldParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0)) {		\
	    xmlOldPopInput(ctxt);						\
    } else {								\
        if (*(ctxt->input->cur) == '\n') {				\
	    ctxt->input->line++; ctxt->input->col = 1;			\
	} else ctxt->input->col++;					\
	ctxt->input->cur++;						\
	ctxt->nbChars++;						\
        if (*ctxt->input->cur == 0)					\
	    xmlOldParserInputGrow(ctxt->input, INPUT_CHUNK);		\
    }									\
    if (*ctxt->input->cur == '%') xmlOldParserHandlePEReference(ctxt);	\
    if (*ctxt->input->cur == '&') xmlOldParserHandleReference(ctxt);	\
}}


/************************************************************************
 *									*
 *	Commodity functions to handle entities processing		*
 *									*
 ************************************************************************/

/**
 * xmlOldPopInput:
 * @ctxt:  an XML parser context
 *
 * xmlOldPopInput: the current input pointed by ctxt->input came to an end
 *          pop it and return the next char.
 *
 * Returns the current xmlChar in the parser context
 */
static xmlChar
xmlOldPopInput(xmlParserCtxtPtr ctxt) {
    if (ctxt->inputNr == 1) return(0); /* End of main Input */
    xmlOldFreeInputStream(inputOldPop(ctxt));
    if ((*ctxt->input->cur == 0) &&
        (xmlOldParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))
	    return(xmlOldPopInput(ctxt));
    return(CUR);
}

/**
 * xmlOldPushInput:
 * @ctxt:  an XML parser context
 * @input:  an XML parser input fragment (entity, XML fragment ...).
 *
 * xmlOldPushInput: switch to a new input stream which is stacked on top
 *               of the previous one(s).
 */
void
xmlOldPushInput(xmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
    if (input == NULL) return;
    inputOldPush(ctxt, input);
}

/**
 * xmlOldFreeInputStream:
 * @input:  an xmlParserInputPtr
 *
 * Free up an input stream.
 */
static void
xmlOldFreeInputStream(xmlParserInputPtr input) {
    if (input == NULL) return;

    if (input->filename != NULL) xmlFree((char *) input->filename);
    if (input->directory != NULL) xmlFree((char *) input->directory);
    if ((input->free != NULL) && (input->base != NULL))
        input->free((xmlChar *) input->base);
    if (input->buf != NULL) 
        xmlFreeParserInputBuffer(input->buf);
    memset(input, -1, sizeof(xmlParserInput));
    xmlFree(input);
}

/**
 * xmlOldNewInputStream:
 * @ctxt:  an XML parser context
 *
 * Create a new input stream structure
 * Returns the new input stream or NULL
 */
static xmlParserInputPtr
xmlOldNewInputStream(xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr input;

    input = (xmlParserInputPtr) xmlMalloc(sizeof(xmlParserInput));
    if (input == NULL) {
        ctxt->errNo = XML_ERR_NO_MEMORY;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	                     "malloc: couldn't allocate a new input stream\n");
	ctxt->errNo = XML_ERR_NO_MEMORY;
	return(NULL);
    }
    input->filename = NULL;
    input->directory = NULL;
    input->base = NULL;
    input->cur = NULL;
    input->buf = NULL;
    input->line = 1;
    input->col = 1;
    input->buf = NULL;
    input->free = NULL;
    input->consumed = 0;
    input->length = 0;
    return(input);
}

/**
 * xmlOldNewEntityInputStream:
 * @ctxt:  an XML parser context
 * @entity:  an Entity pointer
 *
 * Create a new input stream based on an xmlEntityPtr
 *
 * Returns the new input stream or NULL
 */
static xmlParserInputPtr
xmlOldNewEntityInputStream(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
    xmlParserInputPtr input;

    if (entity == NULL) {
        ctxt->errNo = XML_ERR_INTERNAL_ERROR;
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	      "internal: xmlOldNewEntityInputStream entity = NULL\n");
	ctxt->errNo = XML_ERR_INTERNAL_ERROR;
	return(NULL);
    }
    if (entity->content == NULL) {
	switch (entity->type) {
            case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
	        ctxt->errNo = XML_ERR_UNPARSED_ENTITY;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		      "xmlNewEntityInputStream unparsed entity !\n");
                break;
            case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
            case XML_EXTERNAL_PARAMETER_ENTITY:
		return(xmlLoadExternalEntity((char *) entity->SystemID,
		       (char *) entity->ExternalID, ctxt));
            case XML_INTERNAL_GENERAL_ENTITY:
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
	  "Internal entity %s without content !\n", entity->name);
                break;
            case XML_INTERNAL_PARAMETER_ENTITY:
		ctxt->errNo = XML_ERR_INTERNAL_ERROR;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
	  "Internal parameter entity %s without content !\n", entity->name);
                break;
            case XML_INTERNAL_PREDEFINED_ENTITY:
		ctxt->errNo = XML_ERR_INTERNAL_ERROR;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
	      "Predefined entity %s without content !\n", entity->name);
                break;
	}
	return(NULL);
    }
    input = xmlOldNewInputStream(ctxt);
    if (input == NULL) {
	return(NULL);
    }
    input->filename = (char *) entity->SystemID; /* TODO !!! char <- xmlChar */
    input->base = entity->content;
    input->cur = entity->content;
    input->length = entity->length;
    return(input);
}

/**
 * xmlOldNewStringInputStream:
 * @ctxt:  an XML parser context
 * @buffer:  an memory buffer
 *
 * Create a new input stream based on a memory buffer.
 * Returns the new input stream
 */
static xmlParserInputPtr
xmlOldNewStringInputStream(xmlParserCtxtPtr ctxt, const xmlChar *buffer) {
    xmlParserInputPtr input;

    if (buffer == NULL) {
	ctxt->errNo = XML_ERR_INTERNAL_ERROR;
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	      "internal: xmlOldNewStringInputStream string = NULL\n");
	return(NULL);
    }
    input = xmlOldNewInputStream(ctxt);
    if (input == NULL) {
	return(NULL);
    }
    input->base = buffer;
    input->cur = buffer;
    input->length = xmlStrlen(buffer);
    return(input);
}

/**
 * xmlOldNewInputFromFile:
 * @ctxt:  an XML parser context
 * @filename:  the filename to use as entity
 *
 * Create a new input stream based on a file.
 *
 * Returns the new input stream or NULL in case of error
 */
static xmlParserInputPtr
xmlOldNewInputFromFile(xmlParserCtxtPtr ctxt, const char *filename) {
    xmlParserInputBufferPtr buf;
    xmlParserInputPtr inputStream;
    char *directory = NULL;

    if (ctxt == NULL) return(NULL);
    buf = xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE);
    if (buf == NULL) {
	char name[XML_PARSER_BIG_BUFFER_SIZE];

        if ((ctxt->input != NULL) && (ctxt->input->directory != NULL)) {
#ifdef WIN32
            sprintf(name, "%s\\%s", ctxt->input->directory, filename);
#else
            sprintf(name, "%s/%s", ctxt->input->directory, filename);
#endif
            buf = xmlParserInputBufferCreateFilename(name,
	                                             XML_CHAR_ENCODING_NONE);
	    if (buf != NULL)
		directory = xmlParserGetDirectory(name);
	}
	if ((buf == NULL) && (ctxt->directory != NULL)) {
#ifdef WIN32
            sprintf(name, "%s\\%s", ctxt->directory, filename);
#else
            sprintf(name, "%s/%s", ctxt->directory, filename);
#endif
            buf = xmlParserInputBufferCreateFilename(name,
	                                             XML_CHAR_ENCODING_NONE);
	    if (buf != NULL)
		directory = xmlParserGetDirectory(name);
	}
	if (buf == NULL)
	    return(NULL);
    }
    if (directory == NULL)
        directory = xmlParserGetDirectory(filename);

    inputStream = xmlOldNewInputStream(ctxt);
    if (inputStream == NULL) {
	if (directory != NULL) xmlFree((char *) directory);
	return(NULL);
    }

    inputStream->filename = xmlMemStrdup(filename);
    inputStream->directory = directory;
    inputStream->buf = buf;

    inputStream->base = inputStream->buf->buffer->content;
    inputStream->cur = inputStream->buf->buffer->content;
    if ((ctxt->directory == NULL) && (directory != NULL))
        ctxt->directory = (char *) xmlStrdup((const xmlChar *) directory);
    return(inputStream);
}

/************************************************************************
 *									*
 *		Commodity functions to handle entities			*
 *									*
 ************************************************************************/

static void xmlOldParserHandleReference(xmlParserCtxtPtr ctxt);
static void xmlOldParserHandlePEReference(xmlParserCtxtPtr ctxt);
xmlEntityPtr xmlOldParseStringPEReference(xmlParserCtxtPtr ctxt,
                                       const xmlChar **str);

/**
 * xmlOldParseCharRef:
 * @ctxt:  an XML parser context
 *
 * parse Reference declarations
 *
 * [66] CharRef ::= '&#' [0-9]+ ';' |
 *                  '&#x' [0-9a-fA-F]+ ';'
 *
 * [ WFC: Legal Character ]
 * Characters referred to using character references must match the
 * production for Char. 
 *
 * Returns the value parsed (as an int), 0 in case of error
 */
static int
xmlOldParseCharRef(xmlParserCtxtPtr ctxt) {
    int val = 0;

    if (ctxt->token != 0) {
	val = ctxt->token;
        ctxt->token = 0;
        return(val);
    }
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
		ctxt->errNo = XML_ERR_INVALID_HEX_CHARREF;
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
	    SKIP(1); /* on purpose to avoid reentrancy problems with NEXT */
    } else if  ((CUR == '&') && (NXT(1) == '#')) {
	SKIP(2);
	while (CUR != ';') {
	    if ((CUR >= '0') && (CUR <= '9')) 
	        val = val * 10 + (CUR - '0');
	    else {
		ctxt->errNo = XML_ERR_INVALID_DEC_CHARREF;
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
	    SKIP(1); /* on purpose to avoid reentrancy problems with NEXT */
    } else {
	ctxt->errNo = XML_ERR_INVALID_CHARREF;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "xmlParseCharRef: invalid value\n");
	ctxt->wellFormed = 0;
    }

    /*
     * [ WFC: Legal Character ]
     * Characters referred to using character references must match the
     * production for Char. 
     */
    if (IS_CHAR(val)) {
        return(val);
    } else {
	ctxt->errNo = XML_ERR_INVALID_CHAR;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "CharRef: invalid xmlChar value %d\n",
	                     val);
	ctxt->wellFormed = 0;
    }
    return(0);
}

/**
 * xmlOldParseStringCharRef:
 * @ctxt:  an XML parser context
 * @str:  a pointer to an index in the string
 *
 * parse Reference declarations, variant parsing from a string rather
 * than an an input flow.
 *
 * [66] CharRef ::= '&#' [0-9]+ ';' |
 *                  '&#x' [0-9a-fA-F]+ ';'
 *
 * [ WFC: Legal Character ]
 * Characters referred to using character references must match the
 * production for Char. 
 *
 * Returns the value parsed (as an int), 0 in case of error, str will be
 *         updated to the current value of the index
 */
static int
xmlOldParseStringCharRef(xmlParserCtxtPtr ctxt, const xmlChar **str) {
    const xmlChar *ptr;
    xmlChar cur;
    int val = 0;

    if ((str == NULL) || (*str == NULL)) return(0);
    ptr = *str;
    cur = *ptr;
    if ((cur == '&') && (ptr[1] == '#') && (ptr[2] == 'x')) {
	ptr += 3;
	cur = *ptr;
	while (cur != ';') {
	    if ((cur >= '0') && (cur <= '9')) 
	        val = val * 16 + (cur - '0');
	    else if ((cur >= 'a') && (cur <= 'f'))
	        val = val * 16 + (cur - 'a') + 10;
	    else if ((cur >= 'A') && (cur <= 'F'))
	        val = val * 16 + (cur - 'A') + 10;
	    else {
		ctxt->errNo = XML_ERR_INVALID_HEX_CHARREF;
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		         "xmlParseCharRef: invalid hexadecimal value\n");
		ctxt->wellFormed = 0;
		val = 0;
		break;
	    }
	    ptr++;
	    cur = *ptr;
	}
	if (cur == ';')
	    ptr++;
    } else if  ((cur == '&') && (ptr[1] == '#')){
	ptr += 2;
	cur = *ptr;
	while (cur != ';') {
	    if ((cur >= '0') && (cur <= '9')) 
	        val = val * 10 + (cur - '0');
	    else {
		ctxt->errNo = XML_ERR_INVALID_DEC_CHARREF;
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		         "xmlParseCharRef: invalid decimal value\n");
		ctxt->wellFormed = 0;
		val = 0;
		break;
	    }
	    ptr++;
	    cur = *ptr;
	}
	if (cur == ';')
	    ptr++;
    } else {
	ctxt->errNo = XML_ERR_INVALID_CHARREF;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "xmlParseCharRef: invalid value\n");
	ctxt->wellFormed = 0;
	return(0);
    }
    *str = ptr;

    /*
     * [ WFC: Legal Character ]
     * Characters referred to using character references must match the
     * production for Char. 
     */
    if (IS_CHAR(val)) {
        return(val);
    } else {
	ctxt->errNo = XML_ERR_INVALID_CHAR;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		             "CharRef: invalid xmlChar value %d\n", val);
	ctxt->wellFormed = 0;
    }
    return(0);
}

/**
 * xmlOldParserHandleReference:
 * @ctxt:  the parser context
 * 
 * [67] Reference ::= EntityRef | CharRef
 *
 * [68] EntityRef ::= '&' Name ';'
 *
 * [ WFC: Entity Declared ]
 * the Name given in the entity reference must match that in an entity
 * declaration, except that well-formed documents need not declare any
 * of the following entities: amp, lt, gt, apos, quot. 
 *
 * [ WFC: Parsed Entity ]
 * An entity reference must not contain the name of an unparsed entity
 *
 * [66] CharRef ::= '&#' [0-9]+ ';' |
 *                  '&#x' [0-9a-fA-F]+ ';'
 *
 * A PEReference may have been detectect in the current input stream
 * the handling is done accordingly to 
 *      http://www.w3.org/TR/REC-xml#entproc
 */
static void
xmlOldParserHandleReference(xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr input;
    xmlChar *name;
    xmlEntityPtr ent = NULL;

    if (ctxt->token != 0) {
        return;
    }	
    if (CUR != '&') return;
    GROW;
    if ((CUR == '&') && (NXT(1) == '#')) {
	switch(ctxt->instate) {
	    case XML_PARSER_ENTITY_DECL:
	    case XML_PARSER_PI:
	    case XML_PARSER_CDATA_SECTION:
	    case XML_PARSER_COMMENT:
		/* we just ignore it there */
		return;
	    case XML_PARSER_START_TAG:
		return;
	    case XML_PARSER_END_TAG:
		return;
	    case XML_PARSER_EOF:
		ctxt->errNo = XML_ERR_CHARREF_AT_EOF;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "CharRef at EOF\n");
		ctxt->wellFormed = 0;
		return;
	    case XML_PARSER_PROLOG:
	    case XML_PARSER_START:
	    case XML_PARSER_MISC:
		ctxt->errNo = XML_ERR_CHARREF_IN_PROLOG;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "CharRef in prolog!\n");
		ctxt->wellFormed = 0;
		return;
	    case XML_PARSER_EPILOG:
		ctxt->errNo = XML_ERR_CHARREF_IN_EPILOG;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "CharRef in epilog!\n");
		ctxt->wellFormed = 0;
		return;
	    case XML_PARSER_DTD:
		ctxt->errNo = XML_ERR_CHARREF_IN_DTD;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		           "CharRef are forbiden in DTDs!\n");
		ctxt->wellFormed = 0;
		return;
	    case XML_PARSER_ENTITY_VALUE:
	        /*
		 * NOTE: in the case of entity values, we don't do the
		 *       substitution here since we need the literal
		 *       entity value to be able to save the internal
		 *       subset of the document.
		 *       This will be handled by xmlOldDecodeEntities
		 */
		return;
	    case XML_PARSER_CONTENT:
	    case XML_PARSER_ATTRIBUTE_VALUE:
	        /* !!! this may not be Ok for UTF-8, multibyte sequence */
		ctxt->token = xmlOldParseCharRef(ctxt);
		return;
	}
	return;
    }

    switch(ctxt->instate) {
	case XML_PARSER_CDATA_SECTION:
	    return;
	case XML_PARSER_PI:
        case XML_PARSER_COMMENT:
	    return;
	case XML_PARSER_START_TAG:
	    return;
	case XML_PARSER_END_TAG:
	    return;
        case XML_PARSER_EOF:
	    ctxt->errNo = XML_ERR_ENTITYREF_AT_EOF;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Reference at EOF\n");
	    ctxt->wellFormed = 0;
	    return;
        case XML_PARSER_PROLOG:
	case XML_PARSER_START:
	case XML_PARSER_MISC:
	    ctxt->errNo = XML_ERR_ENTITYREF_IN_PROLOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Reference in prolog!\n");
	    ctxt->wellFormed = 0;
	    return;
        case XML_PARSER_EPILOG:
	    ctxt->errNo = XML_ERR_ENTITYREF_IN_EPILOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Reference in epilog!\n");
	    ctxt->wellFormed = 0;
	    return;
	case XML_PARSER_ENTITY_VALUE:
	    /*
	     * NOTE: in the case of entity values, we don't do the
	     *       substitution here since we need the literal
	     *       entity value to be able to save the internal
	     *       subset of the document.
	     *       This will be handled by xmlOldDecodeEntities
	     */
	    return;
        case XML_PARSER_ATTRIBUTE_VALUE:
	    /*
	     * NOTE: in the case of attributes values, we don't do the
	     *       substitution here unless we are in a mode where
	     *       the parser is explicitely asked to substitute
	     *       entities. The SAX callback is called with values
	     *       without entity substitution.
	     *       This will then be handled by xmlOldDecodeEntities
	     */
	    return;
	case XML_PARSER_ENTITY_DECL:
	    /*
	     * we just ignore it there
	     * the substitution will be done once the entity is referenced
	     */
	    return;
        case XML_PARSER_DTD:
	    ctxt->errNo = XML_ERR_ENTITYREF_IN_DTD;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		       "Entity references are forbiden in DTDs!\n");
	    ctxt->wellFormed = 0;
	    return;
        case XML_PARSER_CONTENT:
	    return;
    }

    NEXT;
    name = xmlOldScanName(ctxt);
    if (name == NULL) {
	ctxt->errNo = XML_ERR_ENTITYREF_NO_NAME;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Entity reference: no name\n");
	ctxt->wellFormed = 0;
	ctxt->token = '&';
	return;
    }
    if (NXT(xmlStrlen(name)) != ';') {
	ctxt->errNo = XML_ERR_ENTITYREF_SEMICOL_MISSING;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	                     "Entity reference: ';' expected\n");
	ctxt->wellFormed = 0;
	ctxt->token = '&';
	xmlFree(name);
	return;
    }
    SKIP(xmlStrlen(name) + 1);
    if (ctxt->sax != NULL) {
	if (ctxt->sax->getEntity != NULL)
	    ent = ctxt->sax->getEntity(ctxt->userData, name);
    }

    /*
     * [ WFC: Entity Declared ]
     * the Name given in the entity reference must match that in an entity
     * declaration, except that well-formed documents need not declare any
     * of the following entities: amp, lt, gt, apos, quot. 
     */
    if (ent == NULL)
	ent = xmlGetPredefinedEntity(name);
    if (ent == NULL) {
        ctxt->errNo = XML_ERR_UNDECLARED_ENTITY;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
			     "Entity reference: entity %s not declared\n",
			     name);
	ctxt->wellFormed = 0;
	xmlFree(name);
	return;
    }

    /*
     * [ WFC: Parsed Entity ]
     * An entity reference must not contain the name of an unparsed entity
     */
    if (ent->type == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY) {
        ctxt->errNo = XML_ERR_UNPARSED_ENTITY;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
			 "Entity reference to unparsed entity %s\n", name);
	ctxt->wellFormed = 0;
    }

    if (ent->type == XML_INTERNAL_PREDEFINED_ENTITY) {
        ctxt->token = ent->content[0];
	xmlFree(name);
	return;
    }
    input = xmlOldNewEntityInputStream(ctxt, ent);
    xmlOldPushInput(ctxt, input);
    xmlFree(name);
    return;
}

/**
 * xmlOldParserHandlePEReference:
 * @ctxt:  the parser context
 * 
 * [69] PEReference ::= '%' Name ';'
 *
 * [ WFC: No Recursion ]
 * TODO A parsed entity must not contain a recursive
 * reference to itself, either directly or indirectly. 
 *
 * [ WFC: Entity Declared ]
 * In a document without any DTD, a document with only an internal DTD
 * subset which contains no parameter entity references, or a document
 * with "standalone='yes'", ...  ... The declaration of a parameter
 * entity must precede any reference to it...
 *
 * [ VC: Entity Declared ]
 * In a document with an external subset or external parameter entities
 * with "standalone='no'", ...  ... The declaration of a parameter entity
 * must precede any reference to it...
 *
 * [ WFC: In DTD ]
 * Parameter-entity references may only appear in the DTD.
 * NOTE: misleading but this is handled.
 *
 * A PEReference may have been detected in the current input stream
 * the handling is done accordingly to 
 *      http://www.w3.org/TR/REC-xml#entproc
 * i.e. 
 *   - Included in literal in entity values
 *   - Included as Paraemeter Entity reference within DTDs
 */
static void
xmlOldParserHandlePEReference(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEntityPtr entity = NULL;
    xmlParserInputPtr input;

    if (ctxt->token != 0) {
        return;
    }	
    if (CUR != '%') return;
    switch(ctxt->instate) {
	case XML_PARSER_CDATA_SECTION:
	    return;
        case XML_PARSER_COMMENT:
	    return;
	case XML_PARSER_START_TAG:
	    return;
	case XML_PARSER_END_TAG:
	    return;
        case XML_PARSER_EOF:
	    ctxt->errNo = XML_ERR_PEREF_AT_EOF;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "PEReference at EOF\n");
	    ctxt->wellFormed = 0;
	    return;
        case XML_PARSER_PROLOG:
	case XML_PARSER_START:
	case XML_PARSER_MISC:
	    ctxt->errNo = XML_ERR_PEREF_IN_PROLOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "PEReference in prolog!\n");
	    ctxt->wellFormed = 0;
	    return;
	case XML_PARSER_ENTITY_DECL:
        case XML_PARSER_CONTENT:
        case XML_PARSER_ATTRIBUTE_VALUE:
        case XML_PARSER_PI:
	    /* we just ignore it there */
	    return;
        case XML_PARSER_EPILOG:
	    ctxt->errNo = XML_ERR_PEREF_IN_EPILOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "PEReference in epilog!\n");
	    ctxt->wellFormed = 0;
	    return;
	case XML_PARSER_ENTITY_VALUE:
	    /*
	     * NOTE: in the case of entity values, we don't do the
	     *       substitution here since we need the literal
	     *       entity value to be able to save the internal
	     *       subset of the document.
	     *       This will be handled by xmlOldDecodeEntities
	     */
	    return;
        case XML_PARSER_DTD:
	    /*
	     * [WFC: Well-Formedness Constraint: PEs in Internal Subset]
	     * In the internal DTD subset, parameter-entity references
	     * can occur only where markup declarations can occur, not
	     * within markup declarations.
	     * In that case this is handled in xmlOldParseMarkupDecl
	     */
	    if ((ctxt->external == 0) && (ctxt->inputNr == 1))
		return;
    }

    NEXT;
    name = xmlOldParseName(ctxt);
    if (name == NULL) {
        ctxt->errNo = XML_ERR_PEREF_NO_NAME;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlHandlePEReference: no name\n");
	ctxt->wellFormed = 0;
    } else {
	if (CUR == ';') {
	    NEXT;
	    if ((ctxt->sax != NULL) && (ctxt->sax->getParameterEntity != NULL))
		entity = ctxt->sax->getParameterEntity(ctxt->userData, name);
	    if (entity == NULL) {
	        
		/*
		 * [ WFC: Entity Declared ]
		 * In a document without any DTD, a document with only an
		 * internal DTD subset which contains no parameter entity
		 * references, or a document with "standalone='yes'", ...
		 * ... The declaration of a parameter entity must precede
		 * any reference to it...
		 */
		if ((ctxt->standalone == 1) ||
		    ((ctxt->hasExternalSubset == 0) &&
		     (ctxt->hasPErefs == 0))) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			 "PEReference: %%%s; not found\n", name);
		    ctxt->wellFormed = 0;
	        } else {
		    /*
		     * [ VC: Entity Declared ]
		     * In a document with an external subset or external
		     * parameter entities with "standalone='no'", ...
		     * ... The declaration of a parameter entity must precede
		     * any reference to it...
		     */
		    if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			ctxt->sax->warning(ctxt->userData,
			 "PEReference: %%%s; not found\n", name);
		    ctxt->valid = 0;
		}
	    } else {
	        if ((entity->type == XML_INTERNAL_PARAMETER_ENTITY) ||
		    (entity->type == XML_EXTERNAL_PARAMETER_ENTITY)) {
		    /*
		     * TODO !!!! handle the extra spaces added before and after
		     * c.f. http://www.w3.org/TR/REC-xml#as-PE
		     * TODO !!!! Avoid quote processing in parameters value
		     * c.f. http://www.w3.org/TR/REC-xml#inliteral
		     */
		    input = xmlOldNewEntityInputStream(ctxt, entity);
		    xmlOldPushInput(ctxt, input);
		} else {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			 "xmlHandlePEReference: %s is not a parameter entity\n",
			                 name);
		    ctxt->wellFormed = 0;
		}
	    }
	} else {
	    ctxt->errNo = XML_ERR_PEREF_SEMICOL_MISSING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
				 "xmlHandlePEReference: expecting ';'\n");
	    ctxt->wellFormed = 0;
	}
	xmlFree(name);
    }
}

/*
 * Macro used to grow the current buffer.
 */
#define growBuffer(buffer) {						\
    buffer##_size *= 2;							\
    buffer = (xmlChar *)						\
    		xmlRealloc(buffer, buffer##_size * sizeof(xmlChar));	\
    if (buffer == NULL) {						\
	perror("realloc failed");					\
	return(NULL);							\
    }									\
}

/**
 * xmlOldDecodeEntities:
 * @ctxt:  the parser context
 * @what:  combination of XML_SUBSTITUTE_REF and XML_SUBSTITUTE_PEREF
 * @len:  the len to decode (in bytes !), -1 for no size limit
 * @end:  an end marker xmlChar, 0 if none
 * @end2:  an end marker xmlChar, 0 if none
 * @end3:  an end marker xmlChar, 0 if none
 * 
 * [67] Reference ::= EntityRef | CharRef
 *
 * [69] PEReference ::= '%' Name ';'
 *
 * Returns A newly allocated string with the substitution done. The caller
 *      must deallocate it !
 */
static xmlChar *
xmlOldDecodeEntities(xmlParserCtxtPtr ctxt, int len, int what,
                  xmlChar end, xmlChar  end2, xmlChar end3) {
    xmlChar *buffer = NULL;
    int buffer_size = 0;
    xmlChar *out = NULL;

    xmlChar *current = NULL;
    xmlEntityPtr ent;
    int nbchars = 0;
    unsigned int max = (unsigned int) len;
    xmlChar cur;

    /*
     * allocate a translation buffer.
     */
    buffer_size = XML_PARSER_BIG_BUFFER_SIZE;
    buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
	perror("xmlDecodeEntities: malloc failed");
	return(NULL);
    }
    out = buffer;

    /*
     * Ok loop until we reach one of the ending char or a size limit.
     */
    cur = CUR;
    while ((nbchars < max) && (cur != end) &&
           (cur != end2) && (cur != end3)) {

	if (cur == 0) break;
        if ((cur == '&') && (NXT(1) == '#')) {
	    int val = xmlOldParseCharRef(ctxt);
	    *out++ = val;
	    nbchars += 3; 
	} else if ((cur == '&') && (what & XML_SUBSTITUTE_REF)) {
	    ent = xmlOldParseEntityRef(ctxt);
	    if ((ent != NULL) && 
		(ctxt->replaceEntities != 0)) {
		current = ent->content;
		while (*current != 0) {
		    *out++ = *current++;
		    if (out - buffer > buffer_size - XML_PARSER_BUFFER_SIZE) {
			int index = out - buffer;

			growBuffer(buffer);
			out = &buffer[index];
		    }
		}
		nbchars += 3 + xmlStrlen(ent->name);
	    } else if (ent != NULL) {
		int i = xmlStrlen(ent->name);
		const xmlChar *cur = ent->name;

		nbchars += i + 2;
		*out++ = '&';
		if (out - buffer > buffer_size - i - XML_PARSER_BUFFER_SIZE) {
		    int index = out - buffer;

		    growBuffer(buffer);
		    out = &buffer[index];
		}
		for (;i > 0;i--)
		    *out++ = *cur++;
		*out++ = ';';
	    }
	} else if (cur == '%' && (what & XML_SUBSTITUTE_PEREF)) {
	    /*
	     * a PEReference induce to switch the entity flow,
	     * we break here to flush the current set of chars
	     * parsed if any. We will be called back later.
	     */
	    if (nbchars != 0) break;

	    xmlOldParsePEReference(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1))
		xmlOldPopInput(ctxt);

	    break;
	} else {
	    /*  invalid for UTF-8 , use COPY(out); !!!!!! */
	    *out++ = cur;
	    nbchars++;
	    if (out - buffer > buffer_size - XML_PARSER_BUFFER_SIZE) {
	      int index = out - buffer;
	      
	      growBuffer(buffer);
	      out = &buffer[index];
	    }
	    NEXT;
	}
	cur = CUR;
    }
    *out++ = 0;
    return(buffer);
}

/**
 * xmlOldStringDecodeEntities:
 * @ctxt:  the parser context
 * @str:  the input string
 * @what:  combination of XML_SUBSTITUTE_REF and XML_SUBSTITUTE_PEREF
 * @end:  an end marker xmlChar, 0 if none
 * @end2:  an end marker xmlChar, 0 if none
 * @end3:  an end marker xmlChar, 0 if none
 * 
 * [67] Reference ::= EntityRef | CharRef
 *
 * [69] PEReference ::= '%' Name ';'
 *
 * Returns A newly allocated string with the substitution done. The caller
 *      must deallocate it !
 */
static xmlChar *
xmlOldStringDecodeEntities(xmlParserCtxtPtr ctxt, const xmlChar *str, int what,
		        xmlChar end, xmlChar  end2, xmlChar end3) {
    xmlChar *buffer = NULL;
    int buffer_size = 0;
    xmlChar *out = NULL;

    xmlChar *current = NULL;
    xmlEntityPtr ent;
    xmlChar cur;

    /*
     * allocate a translation buffer.
     */
    buffer_size = XML_PARSER_BIG_BUFFER_SIZE;
    buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
	perror("xmlStringDecodeEntities: malloc failed");
	return(NULL);
    }
    out = buffer;

    /*
     * Ok loop until we reach one of the ending char or a size limit.
     */
    cur = *str;
    while ((cur != 0) && (cur != end) &&
           (cur != end2) && (cur != end3)) {

	if (cur == 0) break;
        if ((cur == '&') && (str[1] == '#')) {
	    int val = xmlOldParseStringCharRef(ctxt, &str);
	    if (val != 0)
		*out++ = val;
	} else if ((cur == '&') && (what & XML_SUBSTITUTE_REF)) {
	    ent = xmlOldParseStringEntityRef(ctxt, &str);
	    if ((ent != NULL) && 
		(ctxt->replaceEntities != 0)) {
		current = ent->content;
		while (*current != 0) {
		    *out++ = *current++;
		    if (out - buffer > buffer_size - XML_PARSER_BUFFER_SIZE) {
			int index = out - buffer;

			growBuffer(buffer);
			out = &buffer[index];
		    }
		}
	    } else if (ent != NULL) {
		int i = xmlStrlen(ent->name);
		const xmlChar *cur = ent->name;

		*out++ = '&';
		if (out - buffer > buffer_size - i - XML_PARSER_BUFFER_SIZE) {
		    int index = out - buffer;

		    growBuffer(buffer);
		    out = &buffer[index];
		}
		for (;i > 0;i--)
		    *out++ = *cur++;
		*out++ = ';';
	    }
	} else if (cur == '%' && (what & XML_SUBSTITUTE_PEREF)) {
	    ent = xmlOldParseStringPEReference(ctxt, &str);
	    if (ent != NULL) {
		current = ent->content;
		while (*current != 0) {
		    *out++ = *current++;
		    if (out - buffer > buffer_size - XML_PARSER_BUFFER_SIZE) {
			int index = out - buffer;

			growBuffer(buffer);
			out = &buffer[index];
		    }
		}
	    }
	} else {
	    /*  invalid for UTF-8 , use COPY(out); !!!!!! */
	    *out++ = cur;
	    if (out - buffer > buffer_size - XML_PARSER_BUFFER_SIZE) {
	      int index = out - buffer;
	      
	      growBuffer(buffer);
	      out = &buffer[index];
	    }
	    str++;
	}
	cur = *str;
    }
    *out = 0;
    return(buffer);
}

/************************************************************************
 *									*
 *		Commodity functions, cleanup needed ?			*
 *									*
 ************************************************************************/

/**
 * areBlanksOld:
 * @ctxt:  an XML parser context
 * @str:  a xmlChar *
 * @len:  the size of @str
 *
 * Is this a sequence of blank chars that one can ignore ?
 *
 * Returns 1 if ignorable 0 otherwise.
 */

static int areBlanksOld(xmlParserCtxtPtr ctxt, const xmlChar *str, int len) {
    int i, ret;
    xmlNodePtr lastChild;

    /*
     * Check that the string is made of blanks
     */
    for (i = 0;i < len;i++)
        if (!(IS_BLANK(str[i]))) return(0);

    /*
     * Look if the element is mixed content in the Dtd if available
     */
    if (ctxt->myDoc != NULL) {
	ret = xmlIsMixedElement(ctxt->myDoc, ctxt->node->name);
        if (ret == 0) return(1);
        if (ret == 1) return(0);
    }

    /*
     * Do we allow an heuristic on white space
     */
    if (ctxt->keepBlanks)
	return(0);
    if (CUR != '<') return(0);
    if (ctxt->node == NULL) return(0);
    if ((ctxt->node->childs == NULL) &&
	(CUR == '<') && (NXT(1) == '/')) return(0);

    lastChild = xmlGetLastChild(ctxt->node);
    if (lastChild == NULL) {
        if (ctxt->node->content != NULL) return(0);
    } else if (xmlNodeIsText(lastChild))
        return(0);
    else if ((ctxt->node->childs != NULL) &&
             (xmlNodeIsText(ctxt->node->childs)))
        return(0);
    return(1);
}

/**
 * xmlOldHandleEntity:
 * @ctxt:  an XML parser context
 * @entity:  an XML entity pointer.
 *
 * Default handling of defined entities, when should we define a new input
 * stream ? When do we just handle that as a set of chars ?
 *
 * OBSOLETE: to be removed at some point.
 */

static void
xmlOldHandleEntity(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
    int len;
    xmlParserInputPtr input;

    if (entity->content == NULL) {
	ctxt->errNo = XML_ERR_INTERNAL_ERROR;
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
    input = xmlOldNewEntityInputStream(ctxt, entity);
    xmlOldPushInput(ctxt, input);
    return;

handle_as_char:
    /*
     * Just handle the content as a set of chars.
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	ctxt->sax->characters(ctxt->userData, entity->content, len);

}

/************************************************************************
 *									*
 *		Extra stuff for namespace support			*
 *	Relates to http://www.w3.org/TR/WD-xml-names			*
 *									*
 ************************************************************************/

/**
 * xmlOldNamespaceParseNCName:
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

static xmlChar *
xmlOldNamespaceParseNCName(xmlParserCtxtPtr ctxt) {
    xmlChar buf[XML_MAX_NAMELEN];
    int len = 0;

    if (!IS_LETTER(CUR) && (CUR != '_')) return(NULL);

    while ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)) ||
           (CUR == '.') || (CUR == '-') ||
	   (CUR == '_') ||
	   (IS_COMBINING(CUR)) ||
	   (IS_EXTENDER(CUR))) {
	buf[len++] = CUR;
	NEXT;
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlNamespaceParseNCName: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)) ||
		   (CUR == '.') || (CUR == '-') ||
		   (CUR == '_') ||
		   (IS_COMBINING(CUR)) ||
		   (IS_EXTENDER(CUR)))
		 NEXT;
	    break;
	}
    }
    return(xmlStrndup(buf, len));
}

/**
 * xmlOldNamespaceParseQName:
 * @ctxt:  an XML parser context
 * @prefix:  a xmlChar ** 
 *
 * parse an XML qualified name
 *
 * [NS 5] QName ::= (Prefix ':')? LocalPart
 *
 * [NS 6] Prefix ::= NCName
 *
 * [NS 7] LocalPart ::= NCName
 *
 * Returns the local part, and prefix is updated
 *   to get the Prefix if any.
 */

static xmlChar *
xmlOldNamespaceParseQName(xmlParserCtxtPtr ctxt, xmlChar **prefix) {
    xmlChar *ret = NULL;

    *prefix = NULL;
    ret = xmlOldNamespaceParseNCName(ctxt);
    if (CUR == ':') {
        *prefix = ret;
	NEXT;
	ret = xmlOldNamespaceParseNCName(ctxt);
    }

    return(ret);
}

/**
 * xmlOldParseQuotedString:
 * @ctxt:  an XML parser context
 *
 * [OLD] Parse and return a string between quotes or doublequotes
 * To be removed at next drop of binary compatibility
 *
 * Returns the string parser or NULL.
 */
static xmlChar *
xmlOldParseQuotedString(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = XML_PARSER_BUFFER_SIZE;
    xmlChar c;

    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return(NULL);
    }
    if (CUR == '"') {
        NEXT;
	c = CUR;
	while (IS_CHAR(c) && (c != '"')) {
	    if (len + 1 >= size) {
		size *= 2;
		buf = xmlRealloc(buf, size * sizeof(xmlChar));
		if (buf == NULL) {
		    fprintf(stderr, "realloc of %d byte failed\n", size);
		    return(NULL);
		}
	    }
	    buf[len++] = c;
	    NEXT;
	    c = CUR;
	}
	if (c != '"') {
	    ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
			         "String not closed \"%.50s\"\n", buf);
	    ctxt->wellFormed = 0;
        } else {
	    NEXT;
	}
    } else if (CUR == '\''){
        NEXT;
	c = CUR;
	while (IS_CHAR(c) && (c != '\'')) {
	    if (len + 1 >= size) {
		size *= 2;
		buf = xmlRealloc(buf, size * sizeof(xmlChar));
		if (buf == NULL) {
		    fprintf(stderr, "realloc of %d byte failed\n", size);
		    return(NULL);
		}
	    }
	    buf[len++] = c;
	    NEXT;
	    c = CUR;
	}
	if (CUR != '\'') {
	    ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
			         "String not closed \"%.50s\"\n", buf);
	    ctxt->wellFormed = 0;
        } else {
	    NEXT;
	}
    }
    return(buf);
}

/**
 * xmlOldParseNamespace:
 * @ctxt:  an XML parser context
 *
 * [OLD] xmlOldParseNamespace: parse specific PI '<?namespace ...' constructs.
 *
 * This is what the older xml-name Working Draft specified, a bunch of
 * other stuff may still rely on it, so support is still here as
 * if it was declared on the root of the Tree:-(
 *
 * To be removed at next drop of binary compatibility
 */

static void
xmlOldParseNamespace(xmlParserCtxtPtr ctxt) {
    xmlChar *href = NULL;
    xmlChar *prefix = NULL;
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

	    href = xmlOldParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((CUR == 'h') && (NXT(1) == 'r') &&
	    (NXT(2) == 'e') && (NXT(3) == 'f')) {
	    garbage = 0;
	    SKIP(4);
	    SKIP_BLANKS;

	    if (CUR != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    href = xmlOldParseQuotedString(ctxt);
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

	    prefix = xmlOldParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((CUR == 'A') && (NXT(1) == 'S')) {
	    garbage = 0;
	    SKIP(2);
	    SKIP_BLANKS;

	    if (CUR != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    prefix = xmlOldParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((CUR == '?') && (NXT(1) == '>')) {
	    garbage = 0;
	    NEXT;
	} else {
            /*
	     * Found garbage when parsing the namespace
	     */
	    if (!garbage) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParseNamespace found garbage\n");
	    }
	    ctxt->errNo = XML_ERR_NS_DECL_ERROR;
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

    if (prefix != NULL) xmlFree(prefix);
    if (href != NULL) xmlFree(href);
}

/************************************************************************
 *									*
 *			The parser itself				*
 *	Relates to http://www.w3.org/TR/REC-xml				*
 *									*
 ************************************************************************/

/**
 * xmlOldScanName:
 * @ctxt:  an XML parser context
 *
 * Trickery: parse an XML name but without consuming the input flow
 * Needed for rollback cases.
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

static xmlChar *
xmlOldScanName(xmlParserCtxtPtr ctxt) {
    xmlChar buf[XML_MAX_NAMELEN];
    int len = 0;

    GROW;
    if (!IS_LETTER(CUR) && (CUR != '_') &&
        (CUR != ':')) {
	return(NULL);
    }

    while ((IS_LETTER(NXT(len))) || (IS_DIGIT(NXT(len))) ||
           (NXT(len) == '.') || (NXT(len) == '-') ||
	   (NXT(len) == '_') || (NXT(len) == ':') || 
	   (IS_COMBINING(NXT(len))) ||
	   (IS_EXTENDER(NXT(len)))) {
	buf[len] = NXT(len);
	len++;
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlScanName: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(NXT(len))) || (IS_DIGIT(NXT(len))) ||
		   (NXT(len) == '.') || (NXT(len) == '-') ||
		   (NXT(len) == '_') || (NXT(len) == ':') || 
		   (IS_COMBINING(NXT(len))) ||
		   (IS_EXTENDER(NXT(len))))
		 len++;
	    break;
	}
    }
    return(xmlStrndup(buf, len));
}

/**
 * xmlOldParseName:
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

static xmlChar *
xmlOldParseName(xmlParserCtxtPtr ctxt) {
    xmlChar buf[XML_MAX_NAMELEN];
    int len = 0;
    xmlChar cur;

    GROW;
    cur = CUR;
    if (!IS_LETTER(cur) && (cur != '_') &&
        (cur != ':')) {
	return(NULL);
    }

    while ((IS_LETTER(cur)) || (IS_DIGIT(cur)) ||
           (cur == '.') || (cur == '-') ||
	   (cur == '_') || (cur == ':') || 
	   (IS_COMBINING(cur)) ||
	   (IS_EXTENDER(cur))) {
	buf[len++] = cur;
	NEXT;
	cur = CUR;
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlParseName: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(cur)) || (IS_DIGIT(cur)) ||
		   (cur == '.') || (cur == '-') ||
		   (cur == '_') || (cur == ':') || 
		   (IS_COMBINING(cur)) ||
		   (IS_EXTENDER(cur))) {
		NEXT;
		cur = CUR;
	    }
	    break;
	}
    }
    return(xmlStrndup(buf, len));
}

/**
 * xmlOldParseStringName:
 * @ctxt:  an XML parser context
 * @str:  a pointer to an index in the string
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
 * Returns the Name parsed or NULL. The str pointer 
 * is updated to the current location in the string.
 */

static xmlChar *
xmlOldParseStringName(xmlParserCtxtPtr ctxt, const xmlChar** str) {
    const xmlChar *ptr;
    const xmlChar *start;
    xmlChar cur;

    if ((str == NULL) || (*str == NULL)) return(NULL);

    start = ptr = *str;
    cur = *ptr;
    if (!IS_LETTER(cur) && (cur != '_') &&
        (cur != ':')) {
	return(NULL);
    }

    while ((IS_LETTER(cur)) || (IS_DIGIT(cur)) ||
           (cur == '.') || (cur == '-') ||
	   (cur == '_') || (cur == ':') || 
	   (IS_COMBINING(cur)) ||
	   (IS_EXTENDER(cur))) {
	ptr++;
	cur = *ptr;
    }
    *str = ptr;
    return(xmlStrndup(start, ptr - start ));
}

/**
 * xmlOldParseNmtoken:
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

static xmlChar *
xmlOldParseNmtoken(xmlParserCtxtPtr ctxt) {
    xmlChar buf[XML_MAX_NAMELEN];
    int len = 0;

    GROW;
    while ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)) ||
           (CUR == '.') || (CUR == '-') ||
	   (CUR == '_') || (CUR == ':') || 
	   (IS_COMBINING(CUR)) ||
	   (IS_EXTENDER(CUR))) {
	buf[len++] = CUR;
	NEXT;
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlParseNmtoken: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)) ||
		   (CUR == '.') || (CUR == '-') ||
		   (CUR == '_') || (CUR == ':') || 
		   (IS_COMBINING(CUR)) ||
		   (IS_EXTENDER(CUR)))
		 NEXT;
	    break;
	}
    }
    return(xmlStrndup(buf, len));
}

/**
 * xmlOldParseEntityValue:
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

static xmlChar *
xmlOldParseEntityValue(xmlParserCtxtPtr ctxt, xmlChar **orig) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = XML_PARSER_BUFFER_SIZE;
    xmlChar c;
    xmlChar stop;
    xmlChar *ret = NULL;
    xmlParserInputPtr input;

    if (CUR == '"') stop = '"';
    else if (CUR == '\'') stop = '\'';
    else {
	ctxt->errNo = XML_ERR_ENTITY_NOT_STARTED;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "EntityValue: \" or ' expected\n");
	ctxt->wellFormed = 0;
	return(NULL);
    }
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return(NULL);
    }

    /*
     * The content of the entity definition is copied in a buffer.
     */

    ctxt->instate = XML_PARSER_ENTITY_VALUE;
    input = ctxt->input;
    GROW;
    NEXT;
    c = CUR;
    /*
     * NOTE: 4.4.5 Included in Literal
     * When a parameter entity reference appears in a literal entity
     * value, ... a single or double quote character in the replacement
     * text is always treated as a normal data character and will not
     * terminate the literal. 
     * In practice it means we stop the loop only when back at parsing
     * the initial entity and the quote is found
     */
    while (IS_CHAR(c) && ((c != stop) || (ctxt->input != input))) {
	if (len + 1 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		return(NULL);
	    }
	}
	buf[len++] = c;
	NEXT;
	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlOldPopInput(ctxt);
	c = CUR;
	if (c == 0) {
	    GROW;
	    c = CUR;
	}
    }
    buf[len] = 0;

    /*
     * Then PEReference entities are substituted.
     */
    if (c != stop) {
	ctxt->errNo = XML_ERR_ENTITY_NOT_FINISHED;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "EntityValue: \" expected\n");
	ctxt->wellFormed = 0;
    } else {
	NEXT;
	/*
	 * NOTE: 4.4.7 Bypassed
	 * When a general entity reference appears in the EntityValue in
	 * an entity declaration, it is bypassed and left as is.
	 * so XML_SUBSTITUTE_REF is not set.
	 */
	ret = xmlOldStringDecodeEntities(ctxt, buf, XML_SUBSTITUTE_PEREF,
				      0, 0, 0);
	if (orig != NULL) 
	    *orig = buf;
	else
	    xmlFree(buf);
    }
    
    return(ret);
}

/**
 * xmlOldParseAttValue:
 * @ctxt:  an XML parser context
 *
 * parse a value for an attribute
 * Note: the parser won't do substitution of entities here, this
 * will be handled later in xmlStringGetNodeList
 *
 * [10] AttValue ::= '"' ([^<&"] | Reference)* '"' |
 *                   "'" ([^<&'] | Reference)* "'"
 *
 * 3.3.3 Attribute-Value Normalization:
 * Before the value of an attribute is passed to the application or
 * checked for validity, the XML processor must normalize it as follows: 
 * - a character reference is processed by appending the referenced
 *   character to the attribute value
 * - an entity reference is processed by recursively processing the
 *   replacement text of the entity 
 * - a whitespace character (#x20, #xD, #xA, #x9) is processed by
 *   appending #x20 to the normalized value, except that only a single
 *   #x20 is appended for a "#xD#xA" sequence that is part of an external
 *   parsed entity or the literal entity value of an internal parsed entity 
 * - other characters are processed by appending them to the normalized value 
 * If the declared value is not CDATA, then the XML processor must further
 * process the normalized attribute value by discarding any leading and
 * trailing space (#x20) characters, and by replacing sequences of space
 * (#x20) characters by a single space (#x20) character.  
 * All attributes for which no declaration has been read should be treated
 * by a non-validating parser as if declared CDATA.
 *
 * Returns the AttValue parsed or NULL. The value has to be freed by the caller.
 */

static xmlChar *
xmlOldParseAttValue(xmlParserCtxtPtr ctxt) {
    xmlChar limit = 0;
    xmlChar *buffer = NULL;
    int buffer_size = 0;
    xmlChar *out = NULL;

    xmlChar *current = NULL;
    xmlEntityPtr ent;
    xmlChar cur;


    SHRINK;
    if (CUR == '"') {
	ctxt->instate = XML_PARSER_ATTRIBUTE_VALUE;
	limit = '"';
        NEXT;
    } else if (CUR == '\'') {
	limit = '\'';
	ctxt->instate = XML_PARSER_ATTRIBUTE_VALUE;
        NEXT;
    } else {
	ctxt->errNo = XML_ERR_ATTRIBUTE_NOT_STARTED;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "AttValue: \" or ' expected\n");
	ctxt->wellFormed = 0;
	return(NULL);
    }
    
    /*
     * allocate a translation buffer.
     */
    buffer_size = XML_PARSER_BUFFER_SIZE;
    buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
	perror("xmlParseAttValue: malloc failed");
	return(NULL);
    }
    out = buffer;

    /*
     * Ok loop until we reach one of the ending char or a size limit.
     */
    cur = CUR;
    while ((ctxt->token != 0) ||
	   ((cur != limit) && (cur != '<'))) {
	if (cur == 0) break;
	if (cur == '&') { GROW; }
	if (ctxt->token == '&') {
	    /*
	     * The reparsing will be done in xmlStringGetNodeList()
	     * called by the attribute() function in SAX.c
	     */
	    static xmlChar quote[6] = "&#38;";

	    if (out - buffer > buffer_size - 10) {
		int index = out - buffer;

		growBuffer(buffer);
		out = &buffer[index];
	    }
	    current = &quote[0];
	    while (*current != 0) { /* non input consuming */
		*out++ = *current++;
	    }
	    NEXT;
	} else if ((cur == '&') && (NXT(1) == '#')) {
	    int val = xmlOldParseCharRef(ctxt);
	    *out++ = val;
	    if (out - buffer > buffer_size - 10) {
		int index = out - buffer;

		growBuffer(buffer);
		out = &buffer[index];
	    }
	} else if (cur == '&') {
	    ent = xmlOldParseEntityRef(ctxt);
	    if ((ent != NULL) && 
		(ctxt->replaceEntities != 0)) {
		current = ent->content;
		while (*current != 0) {
		    *out++ = *current++;
		    if (out - buffer > buffer_size - 10) {
			int index = out - buffer;

			growBuffer(buffer);
			out = &buffer[index];
		    }
		}
	    } else if (ent != NULL) {
		int i = xmlStrlen(ent->name);
		const xmlChar *cur = ent->name;

		*out++ = '&';
		while (out - buffer > buffer_size - i - 10) {
		    int index = out - buffer;

		    growBuffer(buffer);
		    out = &buffer[index];
		}
		for (;i > 0;i--)
		    *out++ = *cur++;
		*out++ = ';';
	    }
	} else {
	    /*  invalid for UTF-8 , use COPY(out); !!!!!! */
	    if ((ctxt->token == 0) && ((cur == 0x20) || (cur == 0xD) || (cur == 0xA) || (cur == 0x9))) {
		*out++ = 0x20;
		if (out - buffer > buffer_size - 10) {
		  int index = out - buffer;
		  
		  growBuffer(buffer);
		  out = &buffer[index];
		}
	    } else {
		*out++ = cur;
		if (out - buffer > buffer_size - 10) {
		  int index = out - buffer;
		  
		  growBuffer(buffer);
		  out = &buffer[index];
		}
	    }
	    NEXT;
	}
	cur = CUR;
    }
    *out++ = 0;
    if (CUR == '<') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "Unescaped '<' not allowed in attributes values\n");
	ctxt->errNo = XML_ERR_LT_IN_ATTRIBUTE;
	ctxt->wellFormed = 0;
    } else if (CUR != limit) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "AttValue: ' expected\n");
	ctxt->errNo = XML_ERR_ATTRIBUTE_NOT_FINISHED;
	ctxt->wellFormed = 0;
    } else
	NEXT;
    return(buffer);
}

/**
 * xmlOldParseSystemLiteral:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Literal
 *
 * [11] SystemLiteral ::= ('"' [^"]* '"') | ("'" [^']* "'")
 *
 * Returns the SystemLiteral parsed or NULL
 */

static xmlChar *
xmlOldParseSystemLiteral(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = XML_PARSER_BUFFER_SIZE;
    xmlChar cur;
    xmlChar stop;

    SHRINK;
    if (CUR == '"') {
        NEXT;
	stop = '"';
    } else if (CUR == '\'') {
        NEXT;
	stop = '\'';
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "SystemLiteral \" or ' expected\n");
	ctxt->errNo = XML_ERR_LITERAL_NOT_STARTED;
	ctxt->wellFormed = 0;
	return(NULL);
    }
    
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return(NULL);
    }
    cur = CUR;
    while ((IS_CHAR(cur)) && (cur != stop)) {
	if (len + 1 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		return(NULL);
	    }
	}
	buf[len++] = cur;
	NEXT;
	cur = CUR;
	if (cur == 0) {
	    GROW;
	    SHRINK;
	    cur = CUR;
	}
    }
    buf[len] = 0;
    if (!IS_CHAR(cur)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Unfinished SystemLiteral\n");
	ctxt->errNo = XML_ERR_LITERAL_NOT_FINISHED;
	ctxt->wellFormed = 0;
    } else {
	NEXT;
    }
    return(buf);
}

/**
 * xmlOldParsePubidLiteral:
 * @ctxt:  an XML parser context
 *
 * parse an XML public literal
 *
 * [12] PubidLiteral ::= '"' PubidChar* '"' | "'" (PubidChar - "'")* "'"
 *
 * Returns the PubidLiteral parsed or NULL.
 */

static xmlChar *
xmlOldParsePubidLiteral(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = XML_PARSER_BUFFER_SIZE;
    xmlChar cur;
    xmlChar stop;

    SHRINK;
    if (CUR == '"') {
        NEXT;
	stop = '"';
    } else if (CUR == '\'') {
        NEXT;
	stop = '\'';
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "SystemLiteral \" or ' expected\n");
	ctxt->errNo = XML_ERR_LITERAL_NOT_STARTED;
	ctxt->wellFormed = 0;
	return(NULL);
    }
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return(NULL);
    }
    cur = CUR;
    while ((IS_PUBIDCHAR(cur)) && (cur != stop)) {
	if (len + 1 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		return(NULL);
	    }
	}
	buf[len++] = cur;
	NEXT;
	cur = CUR;
	if (cur == 0) {
	    GROW;
	    SHRINK;
	    cur = CUR;
	}
    }
    buf[len] = 0;
    if (cur != stop) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Unfinished PubidLiteral\n");
	ctxt->errNo = XML_ERR_LITERAL_NOT_FINISHED;
	ctxt->wellFormed = 0;
    } else {
	NEXT;
    }
    return(buf);
}

/**
 * xmlOldParseCharData:
 * @ctxt:  an XML parser context
 * @cdata:  int indicating whether we are within a CDATA section
 *
 * parse a CharData section.
 * if we are within a CDATA section ']]>' marks an end of section.
 *
 * [14] CharData ::= [^<&]* - ([^<&]* ']]>' [^<&]*)
 */

static void
xmlOldParseCharData(xmlParserCtxtPtr ctxt, int cdata) {
    xmlChar buf[XML_PARSER_BIG_BUFFER_SIZE];
    int nbchar = 0;
    xmlChar cur;

    SHRINK;
    cur = CUR;
    while (((cur != '<') || (ctxt->token == '<')) &&
           ((cur != '&') || (ctxt->token == '&')) && 
	   (IS_CHAR(cur))) {
	if ((cur == ']') && (NXT(1) == ']') &&
	    (NXT(2) == '>')) {
	    if (cdata) break;
	    else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->warning(ctxt->userData,
		       "Sequence ']]>' not allowed in content\n");
		ctxt->errNo = XML_ERR_MISPLACED_CDATA_END;
	    }
	}
	buf[nbchar++] = CUR;
	if (nbchar == XML_PARSER_BIG_BUFFER_SIZE) {
	    /*
	     * Ok the segment is to be consumed as chars.
	     */
	    if (ctxt->sax != NULL) {
		if (areBlanksOld(ctxt, buf, nbchar)) {
		    if (ctxt->sax->ignorableWhitespace != NULL)
			ctxt->sax->ignorableWhitespace(ctxt->userData,
			                               buf, nbchar);
		} else {
		    if (ctxt->sax->characters != NULL)
			ctxt->sax->characters(ctxt->userData, buf, nbchar);
		}
	    }
	    nbchar = 0;
	}
        NEXT;
	cur = CUR;
    }
    if (nbchar != 0) {
	/*
	 * Ok the segment is to be consumed as chars.
	 */
	if (ctxt->sax != NULL) {
	    if (areBlanksOld(ctxt, buf, nbchar)) {
		if (ctxt->sax->ignorableWhitespace != NULL)
		    ctxt->sax->ignorableWhitespace(ctxt->userData, buf, nbchar);
	    } else {
		if (ctxt->sax->characters != NULL)
		    ctxt->sax->characters(ctxt->userData, buf, nbchar);
	    }
	}
    }
}

/**
 * xmlOldParseExternalID:
 * @ctxt:  an XML parser context
 * @publicID:  a xmlChar** receiving PubidLiteral
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

static xmlChar *
xmlOldParseExternalID(xmlParserCtxtPtr ctxt, xmlChar **publicID, int strict) {
    xmlChar *URI = NULL;

    SHRINK;
    if ((CUR == 'S') && (NXT(1) == 'Y') &&
         (NXT(2) == 'S') && (NXT(3) == 'T') &&
	 (NXT(4) == 'E') && (NXT(5) == 'M')) {
        SKIP(6);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Space required after 'SYSTEM'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
	URI = xmlOldParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
	          "xmlParseExternalID: SYSTEM, no URI\n");
	    ctxt->errNo = XML_ERR_URI_REQUIRED;
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
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
	*publicID = xmlOldParsePubidLiteral(ctxt);
	if (*publicID == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "xmlParseExternalID: PUBLIC, no Public Identifier\n");
	    ctxt->errNo = XML_ERR_PUBID_REQUIRED;
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
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
	    }
	} else {
	    /*
	     * We handle [83] so we return immediately, if 
	     * "S SystemLiteral" is not detected. From a purely parsing
	     * point of view that's a nice mess.
	     */
	    const xmlChar *ptr;
	    GROW;

	    ptr = CUR_PTR;
	    if (!IS_BLANK(*ptr)) return(NULL);
	    
	    while (IS_BLANK(*ptr)) ptr++;
	    if ((*ptr != '\'') || (*ptr != '"')) return(NULL);
	}
        SKIP_BLANKS;
	URI = xmlOldParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	           "xmlParseExternalID: PUBLIC, no URI\n");
	    ctxt->errNo = XML_ERR_URI_REQUIRED;
	    ctxt->wellFormed = 0;
        }
    }
    return(URI);
}

/**
 * xmlOldParseComment:
 * @ctxt:  an XML parser context
 *
 * Skip an XML (SGML) comment <!-- .... -->
 *  The spec says that "For compatibility, the string "--" (double-hyphen)
 *  must not occur within comments. "
 *
 * [15] Comment ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
 */
static void
xmlOldParseComment(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = XML_PARSER_BUFFER_SIZE;
    xmlChar q;
    xmlChar r;
    xmlChar cur;
    xmlParserInputState state;

    /*
     * Check that there is a comment right here.
     */
    if ((CUR != '<') || (NXT(1) != '!') ||
        (NXT(2) != '-') || (NXT(3) != '-')) return;

    state = ctxt->instate;
    ctxt->instate = XML_PARSER_COMMENT;
    SHRINK;
    SKIP(4);
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	ctxt->instate = state;
	return;
    }
    q = CUR;
    NEXT;
    r = CUR;
    NEXT;
    cur = CUR;
    while (IS_CHAR(cur) &&
           ((cur != '>') ||
	    (r != '-') || (q != '-'))) {
	if ((r == '-') && (q == '-')) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
	       "Comment must not contain '--' (double-hyphen)`\n");
	    ctxt->errNo = XML_ERR_HYPHEN_IN_COMMENT;
	    ctxt->wellFormed = 0;
	}
	if (len + 1 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		ctxt->instate = state;
		return;
	    }
	}
	buf[len++] = q;
	q = r;
	r = cur;
        NEXT;
	cur = CUR;
	if (cur == 0) {
	    SHRINK;
	    GROW;
	    cur = CUR;
	}
    }
    buf[len] = 0;
    if (!IS_CHAR(cur)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "Comment not terminated \n<!--%.50s\n", buf);
	ctxt->errNo = XML_ERR_COMMENT_NOT_FINISHED;
	ctxt->wellFormed = 0;
    } else {
        NEXT;
	if ((ctxt->sax != NULL) && (ctxt->sax->comment != NULL))
	    ctxt->sax->comment(ctxt->userData, buf);
	xmlFree(buf);
    }
    ctxt->instate = state;
}

/**
 * xmlOldParsePITarget:
 * @ctxt:  an XML parser context
 * 
 * parse the name of a PI
 *
 * [17] PITarget ::= Name - (('X' | 'x') ('M' | 'm') ('L' | 'l'))
 *
 * Returns the PITarget name or NULL
 */

static xmlChar *
xmlOldParsePITarget(xmlParserCtxtPtr ctxt) {
    xmlChar *name;

    name = xmlOldParseName(ctxt);
    if ((name != NULL) &&
        ((name[0] == 'x') || (name[0] == 'X')) &&
        ((name[1] == 'm') || (name[1] == 'M')) &&
        ((name[2] == 'l') || (name[2] == 'L'))) {
	int i;
	for (i = 0;;i++) {
	    if (xmlW3CPIs[i] == NULL) break;
	    if (!xmlStrcmp(name, (const xmlChar *)xmlW3CPIs[i]))
	        return(name);
	}
	if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL)) {
	    ctxt->sax->warning(ctxt->userData,
	         "xmlParsePItarget: invalid name prefix 'xml'\n");
	    ctxt->errNo = XML_ERR_RESERVED_XML_NAME;
	}
    }
    return(name);
}

/**
 * xmlOldParsePI:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Processing Instruction.
 *
 * [16] PI ::= '<?' PITarget (S (Char* - (Char* '?>' Char*)))? '?>'
 *
 * The processing is transfered to SAX once parsed.
 */

static void
xmlOldParsePI(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = XML_PARSER_BUFFER_SIZE;
    xmlChar cur;
    xmlChar *target;
    xmlParserInputState state;

    if ((CUR == '<') && (NXT(1) == '?')) {
	state = ctxt->instate;
        ctxt->instate = XML_PARSER_PI;
	/*
	 * this is a Processing Instruction.
	 */
	SKIP(2);
	SHRINK;

	/*
	 * Parse the target name and check for special support like
	 * namespace.
	 */
        target = xmlOldParsePITarget(ctxt);
	if (target != NULL) {
	    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "malloc of %d byte failed\n", size);
		ctxt->instate = state;
		return;
	    }
	    cur = CUR;
	    if (!IS_BLANK(cur)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		      "xmlParsePI: PI %s space expected\n", target);
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
	    }
            SKIP_BLANKS;
	    cur = CUR;
	    while (IS_CHAR(cur) &&
		   ((cur != '?') || (NXT(1) != '>'))) {
		if (len + 1 >= size) {
		    size *= 2;
		    buf = xmlRealloc(buf, size * sizeof(xmlChar));
		    if (buf == NULL) {
			fprintf(stderr, "realloc of %d byte failed\n", size);
			ctxt->instate = state;
			return;
		    }
		}
		buf[len++] = cur;
		NEXT;
		cur = CUR;
		if (cur == 0) {
		    SHRINK;
		    GROW;
		    cur = CUR;
		}
	    }
	    buf[len] = 0;
	    if (!IS_CHAR(cur)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		      "xmlParsePI: PI %s never end ...\n", target);
		ctxt->errNo = XML_ERR_PI_NOT_FINISHED;
		ctxt->wellFormed = 0;
	    } else {
		SKIP(2);

		/*
		 * SAX: PI detected.
		 */
		if ((ctxt->sax) &&
		    (ctxt->sax->processingInstruction != NULL))
		    ctxt->sax->processingInstruction(ctxt->userData,
		                                     target, buf);
	    }
	    xmlFree(buf);
	    xmlFree(target);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		       "xmlParsePI : no target name\n");
	    ctxt->errNo = XML_ERR_PI_NOT_STARTED;
	    ctxt->wellFormed = 0;
	}
	ctxt->instate = state;
    }
}

/**
 * xmlOldParseNotationDecl:
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
 * See the NOTE on xmlOldParseExternalID().
 */

static void
xmlOldParseNotationDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlChar *Pubid;
    xmlChar *Systemid;
    
    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'N') && (NXT(3) == 'O') &&
        (NXT(4) == 'T') && (NXT(5) == 'A') &&
        (NXT(6) == 'T') && (NXT(7) == 'I') &&
        (NXT(8) == 'O') && (NXT(9) == 'N')) {
	SHRINK;
	SKIP(10);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		                 "Space required after '<!NOTATION'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    return;
	}
	SKIP_BLANKS;

        name = xmlOldParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "NOTATION: Name expected here\n");
	    ctxt->errNo = XML_ERR_NOTATION_NOT_STARTED;
	    ctxt->wellFormed = 0;
	    return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		     "Space required after the NOTATION name'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    return;
	}
	SKIP_BLANKS;

	/*
	 * Parse the IDs.
	 */
	Systemid = xmlOldParseExternalID(ctxt, &Pubid, 1);
	SKIP_BLANKS;

	if (CUR == '>') {
	    NEXT;
	    if ((ctxt->sax != NULL) && (ctxt->sax->notationDecl != NULL))
		ctxt->sax->notationDecl(ctxt->userData, name, Pubid, Systemid);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		       "'>' required to close NOTATION declaration\n");
	    ctxt->errNo = XML_ERR_NOTATION_NOT_FINISHED;
	    ctxt->wellFormed = 0;
	}
	xmlFree(name);
	if (Systemid != NULL) xmlFree(Systemid);
	if (Pubid != NULL) xmlFree(Pubid);
    }
}

/**
 * xmlOldParseEntityDecl:
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
 *
 * [ VC: Notation Declared ]
 * The Name must match the declared name of a notation.
 */

static void
xmlOldParseEntityDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *name = NULL;
    xmlChar *value = NULL;
    xmlChar *URI = NULL, *literal = NULL;
    xmlChar *ndata = NULL;
    int isParameter = 0;
    xmlChar *orig = NULL;
    
    GROW;
    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'E') && (NXT(3) == 'N') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
        (NXT(6) == 'T') && (NXT(7) == 'Y')) {
	ctxt->instate = XML_PARSER_ENTITY_DECL;
	SHRINK;
	SKIP(8);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		                 "Space required after '<!ENTITY'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	}
	SKIP_BLANKS;

	if (CUR == '%') {
	    NEXT;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "Space required after '%'\n");
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
	    }
	    SKIP_BLANKS;
	    isParameter = 1;
	}

        name = xmlOldParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "xmlParseEntityDecl: no name\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
            return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		     "Space required after the entity name\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;

	/*
	 * handle the various case of definitions...
	 */
	if (isParameter) {
	    if ((CUR == '"') || (CUR == '\''))
	        value = xmlOldParseEntityValue(ctxt, &orig);
		if (value) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
		                    XML_INTERNAL_PARAMETER_ENTITY,
				    NULL, NULL, value);
		}
	    else {
	        URI = xmlOldParseExternalID(ctxt, &literal, 1);
		if (URI) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
		                    XML_EXTERNAL_PARAMETER_ENTITY,
				    literal, URI, NULL);
		}
	    }
	} else {
	    if ((CUR == '"') || (CUR == '\'')) {
	        value = xmlOldParseEntityValue(ctxt, &orig);
		if ((ctxt->sax != NULL) && (ctxt->sax->entityDecl != NULL))
		    ctxt->sax->entityDecl(ctxt->userData, name,
				XML_INTERNAL_GENERAL_ENTITY,
				NULL, NULL, value);
	    } else {
	        URI = xmlOldParseExternalID(ctxt, &literal, 1);
		if ((CUR != '>') && (!IS_BLANK(CUR))) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			    "Space required before 'NDATA'\n");
		    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
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
			ctxt->errNo = XML_ERR_SPACE_REQUIRED;
			ctxt->wellFormed = 0;
		    }
		    SKIP_BLANKS;
		    ndata = xmlOldParseName(ctxt);
		    if ((ctxt->sax != NULL) &&
		        (ctxt->sax->unparsedEntityDecl != NULL))
			ctxt->sax->unparsedEntityDecl(ctxt->userData, name,
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
	    ctxt->errNo = XML_ERR_ENTITY_NOT_FINISHED;
	    ctxt->wellFormed = 0;
	} else
	    NEXT;
	if (orig != NULL) {
	    /*
	     * Ugly mechanism to save the raw entity value.
	     */
	    xmlEntityPtr cur = NULL;

	    if (isParameter) {
	        if ((ctxt->sax != NULL) &&
		    (ctxt->sax->getParameterEntity != NULL))
		    cur = ctxt->sax->getParameterEntity(ctxt->userData, name);
	    } else {
	        if ((ctxt->sax != NULL) &&
		    (ctxt->sax->getEntity != NULL))
		    cur = ctxt->sax->getEntity(ctxt->userData, name);
	    }
            if (cur != NULL) {
	        if (cur->orig != NULL)
		    xmlFree(orig);
		else
		    cur->orig = orig;
	    } else
		xmlFree(orig);
	}
	if (name != NULL) xmlFree(name);
	if (value != NULL) xmlFree(value);
	if (URI != NULL) xmlFree(URI);
	if (literal != NULL) xmlFree(literal);
	if (ndata != NULL) xmlFree(ndata);
    }
}

/**
 * xmlOldParseDefaultDecl:
 * @ctxt:  an XML parser context
 * @value:  Receive a possible fixed default value for the attribute
 *
 * Parse an attribute default declaration
 *
 * [60] DefaultDecl ::= '#REQUIRED' | '#IMPLIED' | (('#FIXED' S)? AttValue)
 *
 * [ VC: Required Attribute ]
 * if the default declaration is the keyword #REQUIRED, then the
 * attribute must be specified for all elements of the type in the
 * attribute-list declaration.
 *
 * [ VC: Attribute Default Legal ]
 * The declared default value must meet the lexical constraints of
 * the declared attribute type c.f. xmlValidateAttributeDecl()
 *
 * [ VC: Fixed Attribute Default ]
 * if an attribute has a default value declared with the #FIXED
 * keyword, instances of that attribute must match the default value. 
 *
 * [ WFC: No < in Attribute Values ]
 * handled in xmlOldParseAttValue()
 *
 * returns: XML_ATTRIBUTE_NONE, XML_ATTRIBUTE_REQUIRED, XML_ATTRIBUTE_IMPLIED
 *          or XML_ATTRIBUTE_FIXED. 
 */

static int
xmlOldParseDefaultDecl(xmlParserCtxtPtr ctxt, xmlChar **value) {
    int val;
    xmlChar *ret;

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
	        ctxt->sax->error(ctxt->userData,
		                 "Space required after '#FIXED'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	}
	SKIP_BLANKS;
    }
    ret = xmlOldParseAttValue(ctxt);
    ctxt->instate = XML_PARSER_DTD;
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
 * xmlOldParseNotationType:
 * @ctxt:  an XML parser context
 *
 * parse an Notation attribute type.
 *
 * Note: the leading 'NOTATION' S part has already being parsed...
 *
 * [58] NotationType ::= 'NOTATION' S '(' S? Name (S? '|' S? Name)* S? ')'
 *
 * [ VC: Notation Attributes ]
 * Values of this type must match one of the notation names included
 * in the declaration; all notation names in the declaration must be declared. 
 *
 * Returns: the notation attribute tree built while parsing
 */

static xmlEnumerationPtr
xmlOldParseNotationType(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEnumerationPtr ret = NULL, last = NULL, cur;

    if (CUR != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "'(' required to start 'NOTATION'\n");
	ctxt->errNo = XML_ERR_NOTATION_NOT_STARTED;
	ctxt->wellFormed = 0;
	return(NULL);
    }
    SHRINK;
    do {
        NEXT;
	SKIP_BLANKS;
        name = xmlOldParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		                 "Name expected in NOTATION declaration\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	    return(ret);
	}
	cur = xmlCreateEnumeration(name);
	xmlFree(name);
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
	ctxt->errNo = XML_ERR_NOTATION_NOT_FINISHED;
	ctxt->wellFormed = 0;
	return(ret);
    }
    NEXT;
    return(ret);
}

/**
 * xmlOldParseEnumerationType:
 * @ctxt:  an XML parser context
 *
 * parse an Enumeration attribute type.
 *
 * [59] Enumeration ::= '(' S? Nmtoken (S? '|' S? Nmtoken)* S? ')'
 *
 * [ VC: Enumeration ]
 * Values of this type must match one of the Nmtoken tokens in
 * the declaration
 *
 * Returns: the enumeration attribute tree built while parsing
 */

static xmlEnumerationPtr
xmlOldParseEnumerationType(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEnumerationPtr ret = NULL, last = NULL, cur;

    if (CUR != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "'(' required to start ATTLIST enumeration\n");
	ctxt->errNo = XML_ERR_ATTLIST_NOT_STARTED;
	ctxt->wellFormed = 0;
	return(NULL);
    }
    SHRINK;
    do {
        NEXT;
	SKIP_BLANKS;
        name = xmlOldParseNmtoken(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		                 "NmToken expected in ATTLIST enumeration\n");
	    ctxt->errNo = XML_ERR_NMTOKEN_REQUIRED;
	    ctxt->wellFormed = 0;
	    return(ret);
	}
	cur = xmlCreateEnumeration(name);
	xmlFree(name);
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
	ctxt->errNo = XML_ERR_ATTLIST_NOT_FINISHED;
	ctxt->wellFormed = 0;
	return(ret);
    }
    NEXT;
    return(ret);
}

/**
 * xmlOldParseEnumeratedType:
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

static int
xmlOldParseEnumeratedType(xmlParserCtxtPtr ctxt, xmlEnumerationPtr *tree) {
    if ((CUR == 'N') && (NXT(1) == 'O') &&
        (NXT(2) == 'T') && (NXT(3) == 'A') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
	(NXT(6) == 'O') && (NXT(7) == 'N')) {
	SKIP(8);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "Space required after 'NOTATION'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    return(0);
	}
        SKIP_BLANKS;
	*tree = xmlOldParseNotationType(ctxt);
	if (*tree == NULL) return(0);
	return(XML_ATTRIBUTE_NOTATION);
    }
    *tree = xmlOldParseEnumerationType(ctxt);
    if (*tree == NULL) return(0);
    return(XML_ATTRIBUTE_ENUMERATION);
}

/**
 * xmlOldParseAttributeType:
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
 * Validity constraints for attribute values syntax are checked in
 * xmlValidateAttributeValue()
 *
 * [ VC: ID ]
 * Values of type ID must match the Name production. A name must not
 * appear more than once in an XML document as a value of this type;
 * i.e., ID values must uniquely identify the elements which bear them.
 *
 * [ VC: One ID per Element Type ]
 * No element type may have more than one ID attribute specified.
 *
 * [ VC: ID Attribute Default ]
 * An ID attribute must have a declared default of #IMPLIED or #REQUIRED.
 *
 * [ VC: IDREF ]
 * Values of type IDREF must match the Name production, and values
 * of type IDREFS must match Names; each IDREF Name must match the value
 * of an ID attribute on some element in the XML document; i.e. IDREF
 * values must match the value of some ID attribute.
 *
 * [ VC: Entity Name ]
 * Values of type ENTITY must match the Name production, values
 * of type ENTITIES must match Names; each Entity Name must match the
 * name of an unparsed entity declared in the DTD.  
 *
 * [ VC: Name Token ]
 * Values of type NMTOKEN must match the Nmtoken production; values
 * of type NMTOKENS must match Nmtokens. 
 *
 * Returns the attribute type
 */
static int 
xmlOldParseAttributeType(xmlParserCtxtPtr ctxt, xmlEnumerationPtr *tree) {
    SHRINK;
    if ((CUR == 'C') && (NXT(1) == 'D') &&
        (NXT(2) == 'A') && (NXT(3) == 'T') &&
        (NXT(4) == 'A')) {
	SKIP(5);
	return(XML_ATTRIBUTE_CDATA);
     } else if ((CUR == 'I') && (NXT(1) == 'D') &&
        (NXT(2) == 'R') && (NXT(3) == 'E') &&
        (NXT(4) == 'F') && (NXT(5) == 'S')) {
	SKIP(6);
	return(XML_ATTRIBUTE_IDREFS);
     } else if ((CUR == 'I') && (NXT(1) == 'D') &&
        (NXT(2) == 'R') && (NXT(3) == 'E') &&
        (NXT(4) == 'F')) {
	SKIP(5);
	return(XML_ATTRIBUTE_IDREF);
     } else if ((CUR == 'I') && (NXT(1) == 'D')) {
        SKIP(2);
	return(XML_ATTRIBUTE_ID);
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
     return(xmlOldParseEnumeratedType(ctxt, tree));
}

/**
 * xmlOldParseAttributeListDecl:
 * @ctxt:  an XML parser context
 *
 * : parse the Attribute list def for an element
 *
 * [52] AttlistDecl ::= '<!ATTLIST' S Name AttDef* S? '>'
 *
 * [53] AttDef ::= S Name S AttType S DefaultDecl
 *
 */
static void
xmlOldParseAttributeListDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *elemName;
    xmlChar *attrName;
    xmlEnumerationPtr tree;

    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'A') && (NXT(3) == 'T') &&
        (NXT(4) == 'T') && (NXT(5) == 'L') &&
        (NXT(6) == 'I') && (NXT(7) == 'S') &&
        (NXT(8) == 'T')) {
	SKIP(9);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "Space required after '<!ATTLIST'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
        elemName = xmlOldParseName(ctxt);
	if (elemName == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "ATTLIST: no name for Element\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	    return;
	}
	SKIP_BLANKS;
	while (CUR != '>') {
	    const xmlChar *check = CUR_PTR;
	    int type;
	    int def;
	    xmlChar *defaultValue = NULL;

            tree = NULL;
	    attrName = xmlOldParseName(ctxt);
	    if (attrName == NULL) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "ATTLIST: no name for Attribute\n");
		ctxt->errNo = XML_ERR_NAME_REQUIRED;
		ctxt->wellFormed = 0;
		break;
	    }
	    GROW;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		        "Space required after the attribute name\n");
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
		break;
	    }
	    SKIP_BLANKS;

	    type = xmlOldParseAttributeType(ctxt, &tree);
	    if (type <= 0) break;

	    GROW;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		        "Space required after the attribute type\n");
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
		break;
	    }
	    SKIP_BLANKS;

	    def = xmlOldParseDefaultDecl(ctxt, &defaultValue);
	    if (def <= 0) break;

	    GROW;
            if (CUR != '>') {
		if (!IS_BLANK(CUR)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
			"Space required after the attribute default value\n");
		    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		    ctxt->wellFormed = 0;
		    break;
		}
		SKIP_BLANKS;
	    }
	    if (check == CUR_PTR) {
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		    "xmlParseAttributeListDecl: detected internal error\n");
		ctxt->errNo = XML_ERR_INTERNAL_ERROR;
		break;
	    }
	    if ((ctxt->sax != NULL) && (ctxt->sax->attributeDecl != NULL))
		ctxt->sax->attributeDecl(ctxt->userData, elemName, attrName,
	                        type, def, defaultValue, tree);
	    if (attrName != NULL)
		xmlFree(attrName);
	    if (defaultValue != NULL)
	        xmlFree(defaultValue);
	    GROW;
	}
	if (CUR == '>')
	    NEXT;

	xmlFree(elemName);
    }
}

/**
 * xmlOldParseElementMixedContentDecl:
 * @ctxt:  an XML parser context
 *
 * parse the declaration for a Mixed Element content
 * The leading '(' and spaces have been skipped in xmlOldParseElementContentDecl
 * 
 * [51] Mixed ::= '(' S? '#PCDATA' (S? '|' S? Name)* S? ')*' |
 *                '(' S? '#PCDATA' S? ')'
 *
 * [ VC: Proper Group/PE Nesting ] applies to [51] too (see [49])
 *
 * [ VC: No Duplicate Types ]
 * The same name must not appear more than once in a single
 * mixed-content declaration. 
 *
 * returns: the list of the xmlElementContentPtr describing the element choices
 */
static xmlElementContentPtr
xmlOldParseElementMixedContentDecl(xmlParserCtxtPtr ctxt) {
    xmlElementContentPtr ret = NULL, cur = NULL, n;
    xmlChar *elem = NULL;

    GROW;
    if ((CUR == '#') && (NXT(1) == 'P') &&
        (NXT(2) == 'C') && (NXT(3) == 'D') &&
        (NXT(4) == 'A') && (NXT(5) == 'T') &&
        (NXT(6) == 'A')) {
	SKIP(7);
	SKIP_BLANKS;
	SHRINK;
	if (CUR == ')') {
	    NEXT;
	    ret = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_PCDATA);
	    if (CUR == '*') {
		ret->ocur = XML_ELEMENT_CONTENT_MULT;
		NEXT;
	    }
	    return(ret);
	}
	if ((CUR == '(') || (CUR == '|')) {
	    ret = cur = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_PCDATA);
	    if (ret == NULL) return(NULL);
	}
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
		xmlFree(elem);
	    }
	    SKIP_BLANKS;
	    elem = xmlOldParseName(ctxt);
	    if (elem == NULL) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
			"xmlParseElementMixedContentDecl : Name expected\n");
		ctxt->errNo = XML_ERR_NAME_REQUIRED;
		ctxt->wellFormed = 0;
		xmlFreeElementContent(cur);
		return(NULL);
	    }
	    SKIP_BLANKS;
	    GROW;
	}
	if ((CUR == ')') && (NXT(1) == '*')) {
	    if (elem != NULL) {
		cur->c2 = xmlNewElementContent(elem,
		                               XML_ELEMENT_CONTENT_ELEMENT);
	        xmlFree(elem);
            }
	    ret->ocur = XML_ELEMENT_CONTENT_MULT;
	    SKIP(2);
	} else {
	    if (elem != NULL) xmlFree(elem);
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "xmlParseElementMixedContentDecl : '|' or ')*' expected\n");
	    ctxt->errNo = XML_ERR_MIXED_NOT_STARTED;
	    ctxt->wellFormed = 0;
	    xmlFreeElementContent(ret);
	    return(NULL);
	}

    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementMixedContentDecl : '#PCDATA' expected\n");
	ctxt->errNo = XML_ERR_PCDATA_REQUIRED;
	ctxt->wellFormed = 0;
    }
    return(ret);
}

/**
 * xmlOldParseElementChildrenContentDecl:
 * @ctxt:  an XML parser context
 *
 * parse the declaration for a Mixed Element content
 * The leading '(' and spaces have been skipped in xmlOldParseElementContentDecl
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
 * [ VC: Proper Group/PE Nesting ] applies to [49] and [50]
 * TODO Parameter-entity replacement text must be properly nested
 *	with parenthetized groups. That is to say, if either of the
 *	opening or closing parentheses in a choice, seq, or Mixed
 *	construct is contained in the replacement text for a parameter
 *	entity, both must be contained in the same replacement text. For
 *	interoperability, if a parameter-entity reference appears in a
 *	choice, seq, or Mixed construct, its replacement text should not
 *	be empty, and neither the first nor last non-blank character of
 *	the replacement text should be a connector (| or ,).
 *
 * returns: the tree of xmlElementContentPtr describing the element 
 *          hierarchy.
 */
static xmlElementContentPtr
xmlOldParseElementChildrenContentDecl(xmlParserCtxtPtr ctxt) {
    xmlElementContentPtr ret = NULL, cur = NULL, last = NULL, op = NULL;
    xmlChar *elem;
    xmlChar type = 0;

    SKIP_BLANKS;
    GROW;
    if (CUR == '(') {
        /* Recurse on first child */
	NEXT;
	SKIP_BLANKS;
        cur = ret = xmlOldParseElementChildrenContentDecl(ctxt);
	SKIP_BLANKS;
	GROW;
    } else {
	elem = xmlOldParseName(ctxt);
	if (elem == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		"xmlParseElementChildrenContentDecl : Name or '(' expected\n");
	    ctxt->errNo = XML_ERR_ELEMCONTENT_NOT_STARTED;
	    ctxt->wellFormed = 0;
	    return(NULL);
	}
        cur = ret = xmlNewElementContent(elem, XML_ELEMENT_CONTENT_ELEMENT);
	GROW;
	if (CUR == '?') {
	    cur->ocur = XML_ELEMENT_CONTENT_OPT;
	    NEXT;
	} else if (CUR == '*') {
	    cur->ocur = XML_ELEMENT_CONTENT_MULT;
	    NEXT;
	} else if (CUR == '+') {
	    cur->ocur = XML_ELEMENT_CONTENT_PLUS;
	    NEXT;
	} else {
	    cur->ocur = XML_ELEMENT_CONTENT_ONCE;
	}
	xmlFree(elem);
	GROW;
    }
    SKIP_BLANKS;
    SHRINK;
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
		ctxt->errNo = XML_ERR_SEPARATOR_REQUIRED;
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
		ctxt->errNo = XML_ERR_SEPARATOR_REQUIRED;
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
	    ctxt->errNo = XML_ERR_ELEMCONTENT_NOT_FINISHED;
	    xmlFreeElementContent(ret);
	    return(NULL);
	}
	GROW;
	SKIP_BLANKS;
	GROW;
	if (CUR == '(') {
	    /* Recurse on second child */
	    NEXT;
	    SKIP_BLANKS;
	    last = xmlOldParseElementChildrenContentDecl(ctxt);
	    SKIP_BLANKS;
	} else {
	    elem = xmlOldParseName(ctxt);
	    if (elem == NULL) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementChildrenContentDecl : Name or '(' expected\n");
		ctxt->errNo = XML_ERR_ELEMCONTENT_NOT_STARTED;
		ctxt->wellFormed = 0;
		return(NULL);
	    }
	    last = xmlNewElementContent(elem, XML_ELEMENT_CONTENT_ELEMENT);
	    xmlFree(elem);
	    if (CUR == '?') {
		last->ocur = XML_ELEMENT_CONTENT_OPT;
		NEXT;
	    } else if (CUR == '*') {
		last->ocur = XML_ELEMENT_CONTENT_MULT;
		NEXT;
	    } else if (CUR == '+') {
		last->ocur = XML_ELEMENT_CONTENT_PLUS;
		NEXT;
	    } else {
		last->ocur = XML_ELEMENT_CONTENT_ONCE;
	    }
	}
	SKIP_BLANKS;
	GROW;
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
    }
    return(ret);
}

/**
 * xmlOldParseElementContentDecl:
 * @ctxt:  an XML parser context
 * @name:  the name of the element being defined.
 * @result:  the Element Content pointer will be stored here if any
 *
 * parse the declaration for an Element content either Mixed or Children,
 * the cases EMPTY and ANY are handled directly in xmlOldParseElementDecl
 * 
 * [46] contentspec ::= 'EMPTY' | 'ANY' | Mixed | children
 *
 * returns: the type of element content XML_ELEMENT_TYPE_xxx
 */

static int
xmlOldParseElementContentDecl(xmlParserCtxtPtr ctxt, xmlChar *name,
                           xmlElementContentPtr *result) {

    xmlElementContentPtr tree = NULL;
    int res;

    *result = NULL;

    if (CUR != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementContentDecl : '(' expected\n");
	ctxt->errNo = XML_ERR_ELEMCONTENT_NOT_STARTED;
	ctxt->wellFormed = 0;
	return(-1);
    }
    NEXT;
    GROW;
    SKIP_BLANKS;
    if ((CUR == '#') && (NXT(1) == 'P') &&
        (NXT(2) == 'C') && (NXT(3) == 'D') &&
        (NXT(4) == 'A') && (NXT(5) == 'T') &&
        (NXT(6) == 'A')) {
        tree = xmlOldParseElementMixedContentDecl(ctxt);
	res = XML_ELEMENT_TYPE_MIXED;
    } else {
        tree = xmlOldParseElementChildrenContentDecl(ctxt);
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
 * xmlOldParseElementDecl:
 * @ctxt:  an XML parser context
 *
 * parse an Element declaration.
 *
 * [45] elementdecl ::= '<!ELEMENT' S Name S contentspec S? '>'
 *
 * [ VC: Unique Element Type Declaration ]
 * No element type may be declared more than once
 *
 * Returns the type of the element, or -1 in case of error
 */
static int
xmlOldParseElementDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    int ret = -1;
    xmlElementContentPtr content  = NULL;

    GROW;
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
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
        name = xmlOldParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		   "xmlParseElementDecl: no name for Element\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	    return(-1);
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "Space required after the element name\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
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
	    ret = xmlOldParseElementContentDecl(ctxt, name, &content);
	} else {
	    /*
	     * [ WFC: PEs in Internal Subset ] error handling.
	     */
	    if ((CUR == '%') && (ctxt->external == 0) &&
	        (ctxt->inputNr == 1)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
	  "PEReference: forbidden within markup decl in internal subset\n");
		ctxt->errNo = XML_ERR_PEREF_IN_INT_SUBSET;
	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		      "xmlParseElementDecl: 'EMPTY', 'ANY' or '(' expected\n");
		ctxt->errNo = XML_ERR_ELEMCONTENT_NOT_STARTED;
            }
	    ctxt->wellFormed = 0;
	    if (name != NULL) xmlFree(name);
	    return(-1);
	}

	SKIP_BLANKS;
	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlOldPopInput(ctxt);
	SKIP_BLANKS;

	if (CUR != '>') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "xmlParseElementDecl: expected '>' at the end\n");
	    ctxt->errNo = XML_ERR_GT_REQUIRED;
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
	    xmlFree(name);
	}
    }
    return(ret);
}

/**
 * xmlOldParseMarkupDecl:
 * @ctxt:  an XML parser context
 * 
 * parse Markup declarations
 *
 * [29] markupdecl ::= elementdecl | AttlistDecl | EntityDecl |
 *                     NotationDecl | PI | Comment
 *
 * [ VC: Proper Declaration/PE Nesting ]
 * TODO Parameter-entity replacement text must be properly nested with
 * markup declarations. That is to say, if either the first character
 * or the last character of a markup declaration (markupdecl above) is
 * contained in the replacement text for a parameter-entity reference,
 * both must be contained in the same replacement text.
 *
 * [ WFC: PEs in Internal Subset ]
 * In the internal DTD subset, parameter-entity references can occur
 * only where markup declarations can occur, not within markup declarations.
 * (This does not apply to references that occur in external parameter
 * entities or to the external subset.) 
 */
static void
xmlOldParseMarkupDecl(xmlParserCtxtPtr ctxt) {
    GROW;
    xmlOldParseElementDecl(ctxt);
    xmlOldParseAttributeListDecl(ctxt);
    xmlOldParseEntityDecl(ctxt);
    xmlOldParseNotationDecl(ctxt);
    xmlOldParsePI(ctxt);
    xmlOldParseComment(ctxt);
    /*
     * This is only for internal subset. On external entities,
     * the replacement is done before parsing stage
     */
    if ((ctxt->external == 0) && (ctxt->inputNr == 1))
	xmlOldParsePEReference(ctxt);
    ctxt->instate = XML_PARSER_DTD;
}

/**
 * xmlOldParseTextDecl:
 * @ctxt:  an XML parser context
 * 
 * parse an XML declaration header for external entities
 *
 * [77] TextDecl ::= '<?xml' VersionInfo? EncodingDecl S? '?>'
 *
 * Returns the only valuable info for an external parsed entity, the encoding
 */

static xmlChar *
xmlOldParseTextDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *version;
    xmlChar *encoding = NULL;

    /*
     * We know that '<?xml' is here.
     */
    SKIP(5);

    if (!IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "Space needed after '<?xml'\n");
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	ctxt->wellFormed = 0;
    }
    SKIP_BLANKS;

    /*
     * We may have the VersionInfo here.
     */
    version = xmlOldParseVersionInfo(ctxt);
    if (version == NULL)
	version = xmlCharStrdup(XML_DEFAULT_VERSION);
    ctxt->version = xmlStrdup(version);
    xmlFree(version);

    /*
     * We must have the encoding declaration
     */
    if (!IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Space needed here\n");
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	ctxt->wellFormed = 0;
    }
    encoding = xmlOldParseEncodingDecl(ctxt);

    SKIP_BLANKS;
    if ((CUR == '?') && (NXT(1) == '>')) {
        SKIP(2);
    } else if (CUR == '>') {
        /* Deprecated old WD ... */
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "XML declaration must end-up with '?>'\n");
	ctxt->errNo = XML_ERR_XMLDECL_NOT_FINISHED;
	ctxt->wellFormed = 0;
	NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "parsing XML declaration: '?>' expected\n");
	ctxt->errNo = XML_ERR_XMLDECL_NOT_FINISHED;
	ctxt->wellFormed = 0;
	MOVETO_ENDTAG(CUR_PTR);
	NEXT;
    }
    return(encoding);
}

/*
 * xmlOldParseConditionalSections
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

static void
xmlOldParseConditionalSections(xmlParserCtxtPtr ctxt) {
    if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
	ctxt->sax->warning(ctxt->userData,
                           "XML conditional section not supported\n");
    /*
     * Skip up to the end of the conditionnal section.
     */
    while ((CUR != 0) && ((CUR != ']') || (NXT(1) != ']') || (NXT(2) != '>'))) {
	NEXT;
	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlOldPopInput(ctxt);

	if (CUR == 0)
	    GROW;
    }

    if (CUR == 0)
        SHRINK;

    if (CUR == 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	        "XML conditional section not closed\n");
	ctxt->errNo = XML_ERR_CONDSEC_NOT_FINISHED;
	ctxt->wellFormed = 0;
    } else {
        SKIP(3);
    }
}

/**
 * xmlOldParseExternalSubset:
 * @ctxt:  an XML parser context
 * @ExternalID: the external identifier
 * @SystemID: the system identifier (or URL)
 * 
 * parse Markup declarations from an external subset
 *
 * [30] extSubset ::= textDecl? extSubsetDecl
 *
 * [31] extSubsetDecl ::= (markupdecl | conditionalSect | PEReference | S) *
 */
void
xmlOldParseExternalSubset(xmlParserCtxtPtr ctxt, const xmlChar *ExternalID,
                       const xmlChar *SystemID) {
    GROW;
    if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l')) {
	xmlChar *decl;

	decl = xmlOldParseTextDecl(ctxt);
	if (decl != NULL)
	    xmlFree(decl);
    }
    if (ctxt->myDoc == NULL) {
        ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
    }
    if ((ctxt->myDoc != NULL) && (ctxt->myDoc->intSubset == NULL))
        xmlCreateIntSubset(ctxt->myDoc, NULL, ExternalID, SystemID);

    ctxt->instate = XML_PARSER_DTD;
    ctxt->external = 1;
    while (((CUR == '<') && (NXT(1) == '?')) ||
           ((CUR == '<') && (NXT(1) == '!')) ||
           IS_BLANK(CUR)) {
	const xmlChar *check = CUR_PTR;
	int cons = ctxt->input->consumed;

        if ((CUR == '<') && (NXT(1) == '!') && (NXT(2) == '[')) {
	    xmlOldParseConditionalSections(ctxt);
	} else if (IS_BLANK(CUR)) {
	    NEXT;
	} else if (CUR == '%') {
            xmlOldParsePEReference(ctxt);
	} else
	    xmlOldParseMarkupDecl(ctxt);

	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlOldPopInput(ctxt);

	if ((CUR_PTR == check) && (cons == ctxt->input->consumed)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Content error in the external subset\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_EXT_SUBSET_NOT_FINISHED;
	    break;
	}
    }
    
    if (CUR != 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	        "Extra content at the end of the document\n");
	ctxt->errNo = XML_ERR_EXT_SUBSET_NOT_FINISHED;
	ctxt->wellFormed = 0;
    }

}

/**
 * xmlOldParseReference:
 * @ctxt:  an XML parser context
 * 
 * parse and handle entity references in content, depending on the SAX
 * interface, this may end-up in a call to character() if this is a
 * CharRef, a predefined entity, if there is no reference() callback.
 * or if the parser was asked to switch to that mode.
 *
 * [67] Reference ::= EntityRef | CharRef
 */
static void
xmlOldParseReference(xmlParserCtxtPtr ctxt) {
    xmlEntityPtr ent;
    xmlChar *val;
    if (CUR != '&') return;
#if 0
    if (ctxt->inputNr > 1) {
        xmlChar cur[2] = { '&' , 0 } ;

	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	    ctxt->sax->characters(ctxt->userData, cur, 1);
	if (ctxt->token == '&')
	    ctxt->token = 0;
        else {
	    SKIP(1);
	}
	return;
    }
#endif
    if (NXT(1) == '#') {
	xmlChar out[2];
	int val = xmlOldParseCharRef(ctxt);
	/* invalid for UTF-8 variable encoding !!!!! */
	out[0] = val;
	out[1] = 0;
	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	    ctxt->sax->characters(ctxt->userData, out, 1);
    } else {
	ent = xmlOldParseEntityRef(ctxt);
	if (ent == NULL) return;
	if ((ent->name != NULL) && 
	    (ent->type != XML_INTERNAL_PREDEFINED_ENTITY)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->reference != NULL) &&
		(ctxt->replaceEntities == 0)) {
		/*
		 * Create a node.
		 */
		ctxt->sax->reference(ctxt->userData, ent->name);
		return;
	    } else if (ctxt->replaceEntities) {
		xmlParserInputPtr input;

		input = xmlOldNewEntityInputStream(ctxt, ent);
		xmlOldPushInput(ctxt, input);
		return;
	    }
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
 * xmlOldParseEntityRef:
 * @ctxt:  an XML parser context
 *
 * parse ENTITY references declarations
 *
 * [68] EntityRef ::= '&' Name ';'
 *
 * [ WFC: Entity Declared ]
 * In a document without any DTD, a document with only an internal DTD
 * subset which contains no parameter entity references, or a document
 * with "standalone='yes'", the Name given in the entity reference
 * must match that in an entity declaration, except that well-formed
 * documents need not declare any of the following entities: amp, lt,
 * gt, apos, quot.  The declaration of a parameter entity must precede
 * any reference to it.  Similarly, the declaration of a general entity
 * must precede any reference to it which appears in a default value in an
 * attribute-list declaration. Note that if entities are declared in the
 * external subset or in external parameter entities, a non-validating
 * processor is not obligated to read and process their declarations;
 * for such documents, the rule that an entity must be declared is a
 * well-formedness constraint only if standalone='yes'.
 *
 * [ WFC: Parsed Entity ]
 * An entity reference must not contain the name of an unparsed entity
 *
 * Returns the xmlEntityPtr if found, or NULL otherwise.
 */
static xmlEntityPtr
xmlOldParseEntityRef(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEntityPtr ent = NULL;

    GROW;
    
    if (CUR == '&') {
        NEXT;
        name = xmlOldParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseEntityRef: no name\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
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
		 * [ WFC: Entity Declared ]
		 * In a document without any DTD, a document with only an
		 * internal DTD subset which contains no parameter entity
		 * references, or a document with "standalone='yes'", the
		 * Name given in the entity reference must match that in an
		 * entity declaration, except that well-formed documents
		 * need not declare any of the following entities: amp, lt,
		 * gt, apos, quot.
		 * The declaration of a parameter entity must precede any
		 * reference to it.
		 * Similarly, the declaration of a general entity must
		 * precede any reference to it which appears in a default
		 * value in an attribute-list declaration. Note that if
		 * entities are declared in the external subset or in
		 * external parameter entities, a non-validating processor
		 * is not obligated to read and process their declarations;
		 * for such documents, the rule that an entity must be
		 * declared is a well-formedness constraint only if
		 * standalone='yes'. 
		 */
		if (ent == NULL) {
		    if ((ctxt->standalone == 1) ||
		        ((ctxt->hasExternalSubset == 0) &&
			 (ctxt->hasPErefs == 0))) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
				 "Entity '%s' not defined\n", name);
			ctxt->errNo = XML_ERR_UNDECLARED_ENTITY;
			ctxt->wellFormed = 0;
		    } else {
			if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			    ctxt->sax->warning(ctxt->userData, 
				 "Entity '%s' not defined\n", name);
			ctxt->errNo = XML_WAR_UNDECLARED_ENTITY;
		    }
		}

		/*
		 * [ WFC: Parsed Entity ]
		 * An entity reference must not contain the name of an
		 * unparsed entity
		 */
		else if (ent->type == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
			     "Entity reference to unparsed entity %s\n", name);
		    ctxt->errNo = XML_ERR_UNPARSED_ENTITY;
		    ctxt->wellFormed = 0;
		}

		/*
		 * [ WFC: No External Entity References ]
		 * Attribute values cannot contain direct or indirect
		 * entity references to external entities.
		 */
		else if ((ctxt->instate == XML_PARSER_ATTRIBUTE_VALUE) &&
		         (ent->type == XML_EXTERNAL_GENERAL_PARSED_ENTITY)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
		     "Attribute references external entity '%s'\n", name);
		    ctxt->errNo = XML_ERR_ENTITY_IS_EXTERNAL;
		    ctxt->wellFormed = 0;
		}
		/*
		 * [ WFC: No < in Attribute Values ]
		 * The replacement text of any entity referred to directly or
		 * indirectly in an attribute value (other than "&lt;") must
		 * not contain a <. 
		 */
		else if ((ctxt->instate == XML_PARSER_ATTRIBUTE_VALUE) &&
		         (ent != NULL) &&
			 (xmlStrcmp(ent->name, BAD_CAST "lt")) &&
		         (ent->content != NULL) &&
			 (xmlStrchr(ent->content, '<'))) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
	 "'<' in entity '%s' is not allowed in attributes values\n", name);
		    ctxt->errNo = XML_ERR_LT_IN_ATTRIBUTE;
		    ctxt->wellFormed = 0;
		}

		/*
		 * Internal check, no parameter entities here ...
		 */
		else {
		    switch (ent->type) {
			case XML_INTERNAL_PARAMETER_ENTITY:
			case XML_EXTERNAL_PARAMETER_ENTITY:
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
		     "Attempt to reference the parameter entity '%s'\n", name);
			ctxt->errNo = XML_ERR_ENTITY_IS_PARAMETER;
			ctxt->wellFormed = 0;
			break;
		    }
		}

		/*
		 * [ WFC: No Recursion ]
		 * TODO A parsed entity must not contain a recursive reference
		 * to itself, either directly or indirectly. 
		 */

	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParseEntityRef: expecting ';'\n");
		ctxt->errNo = XML_ERR_ENTITYREF_SEMICOL_MISSING;
		ctxt->wellFormed = 0;
	    }
	    xmlFree(name);
	}
    }
    return(ent);
}
/**
 * xmlOldParseStringEntityRef:
 * @ctxt:  an XML parser context
 * @str:  a pointer to an index in the string
 *
 * parse ENTITY references declarations, but this version parses it from
 * a string value.
 *
 * [68] EntityRef ::= '&' Name ';'
 *
 * [ WFC: Entity Declared ]
 * In a document without any DTD, a document with only an internal DTD
 * subset which contains no parameter entity references, or a document
 * with "standalone='yes'", the Name given in the entity reference
 * must match that in an entity declaration, except that well-formed
 * documents need not declare any of the following entities: amp, lt,
 * gt, apos, quot.  The declaration of a parameter entity must precede
 * any reference to it.  Similarly, the declaration of a general entity
 * must precede any reference to it which appears in a default value in an
 * attribute-list declaration. Note that if entities are declared in the
 * external subset or in external parameter entities, a non-validating
 * processor is not obligated to read and process their declarations;
 * for such documents, the rule that an entity must be declared is a
 * well-formedness constraint only if standalone='yes'.
 *
 * [ WFC: Parsed Entity ]
 * An entity reference must not contain the name of an unparsed entity
 *
 * Returns the xmlEntityPtr if found, or NULL otherwise. The str pointer
 * is updated to the current location in the string.
 */
static xmlEntityPtr
xmlOldParseStringEntityRef(xmlParserCtxtPtr ctxt, const xmlChar ** str) {
    xmlChar *name;
    const xmlChar *ptr;
    xmlChar cur;
    xmlEntityPtr ent = NULL;

    GROW;
    
    if ((str == NULL) || (*str == NULL)) return(NULL); /* !!! */
    ptr = *str;
    cur = *ptr;
    if (cur == '&') {
        ptr++;
	cur = *ptr;
        name = xmlOldParseStringName(ctxt, &ptr);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseEntityRef: no name\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
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
		 * [ WFC: Entity Declared ]
		 * In a document without any DTD, a document with only an
		 * internal DTD subset which contains no parameter entity
		 * references, or a document with "standalone='yes'", the
		 * Name given in the entity reference must match that in an
		 * entity declaration, except that well-formed documents
		 * need not declare any of the following entities: amp, lt,
		 * gt, apos, quot.
		 * The declaration of a parameter entity must precede any
		 * reference to it.
		 * Similarly, the declaration of a general entity must
		 * precede any reference to it which appears in a default
		 * value in an attribute-list declaration. Note that if
		 * entities are declared in the external subset or in
		 * external parameter entities, a non-validating processor
		 * is not obligated to read and process their declarations;
		 * for such documents, the rule that an entity must be
		 * declared is a well-formedness constraint only if
		 * standalone='yes'. 
		 */
		if (ent == NULL) {
		    if ((ctxt->standalone == 1) ||
		        ((ctxt->hasExternalSubset == 0) &&
			 (ctxt->hasPErefs == 0))) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
				 "Entity '%s' not defined\n", name);
			ctxt->errNo = XML_ERR_UNDECLARED_ENTITY;
			ctxt->wellFormed = 0;
		    } else {
			if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			    ctxt->sax->warning(ctxt->userData, 
				 "Entity '%s' not defined\n", name);
			ctxt->errNo = XML_WAR_UNDECLARED_ENTITY;
		    }
		}

		/*
		 * [ WFC: Parsed Entity ]
		 * An entity reference must not contain the name of an
		 * unparsed entity
		 */
		else if (ent->type == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
			     "Entity reference to unparsed entity %s\n", name);
		    ctxt->errNo = XML_ERR_UNPARSED_ENTITY;
		    ctxt->wellFormed = 0;
		}

		/*
		 * [ WFC: No External Entity References ]
		 * Attribute values cannot contain direct or indirect
		 * entity references to external entities.
		 */
		else if ((ctxt->instate == XML_PARSER_ATTRIBUTE_VALUE) &&
		         (ent->type == XML_EXTERNAL_GENERAL_PARSED_ENTITY)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
		     "Attribute references external entity '%s'\n", name);
		    ctxt->errNo = XML_ERR_ENTITY_IS_EXTERNAL;
		    ctxt->wellFormed = 0;
		}
		/*
		 * [ WFC: No < in Attribute Values ]
		 * The replacement text of any entity referred to directly or
		 * indirectly in an attribute value (other than "&lt;") must
		 * not contain a <. 
		 */
		else if ((ctxt->instate == XML_PARSER_ATTRIBUTE_VALUE) &&
		         (ent != NULL) &&
			 (xmlStrcmp(ent->name, BAD_CAST "lt")) &&
		         (ent->content != NULL) &&
			 (xmlStrchr(ent->content, '<'))) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
	 "'<' in entity '%s' is not allowed in attributes values\n", name);
		    ctxt->errNo = XML_ERR_LT_IN_ATTRIBUTE;
		    ctxt->wellFormed = 0;
		}

		/*
		 * Internal check, no parameter entities here ...
		 */
		else {
		    switch (ent->type) {
			case XML_INTERNAL_PARAMETER_ENTITY:
			case XML_EXTERNAL_PARAMETER_ENTITY:
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
		     "Attempt to reference the parameter entity '%s'\n", name);
			ctxt->errNo = XML_ERR_ENTITY_IS_PARAMETER;
			ctxt->wellFormed = 0;
			break;
		    }
		}

		/*
		 * [ WFC: No Recursion ]
		 * TODO A parsed entity must not contain a recursive reference
		 * to itself, either directly or indirectly. 
		 */

	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParseEntityRef: expecting ';'\n");
		ctxt->errNo = XML_ERR_ENTITYREF_SEMICOL_MISSING;
		ctxt->wellFormed = 0;
	    }
	    xmlFree(name);
	}
    }
    return(ent);
}

/**
 * xmlOldParsePEReference:
 * @ctxt:  an XML parser context
 *
 * parse PEReference declarations
 * The entity content is handled directly by pushing it's content as
 * a new input stream.
 *
 * [69] PEReference ::= '%' Name ';'
 *
 * [ WFC: No Recursion ]
 * TODO A parsed entity must not contain a recursive
 * reference to itself, either directly or indirectly. 
 *
 * [ WFC: Entity Declared ]
 * In a document without any DTD, a document with only an internal DTD
 * subset which contains no parameter entity references, or a document
 * with "standalone='yes'", ...  ... The declaration of a parameter
 * entity must precede any reference to it...
 *
 * [ VC: Entity Declared ]
 * In a document with an external subset or external parameter entities
 * with "standalone='no'", ...  ... The declaration of a parameter entity
 * must precede any reference to it...
 *
 * [ WFC: In DTD ]
 * Parameter-entity references may only appear in the DTD.
 * NOTE: misleading but this is handled.
 */
static void
xmlOldParsePEReference(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEntityPtr entity = NULL;
    xmlParserInputPtr input;

    if (CUR == '%') {
        NEXT;
        name = xmlOldParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParsePEReference: no name\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	} else {
	    if (CUR == ';') {
	        NEXT;
		if ((ctxt->sax != NULL) &&
		    (ctxt->sax->getParameterEntity != NULL))
		    entity = ctxt->sax->getParameterEntity(ctxt->userData,
		                                           name);
		if (entity == NULL) {
		    /*
		     * [ WFC: Entity Declared ]
		     * In a document without any DTD, a document with only an
		     * internal DTD subset which contains no parameter entity
		     * references, or a document with "standalone='yes'", ...
		     * ... The declaration of a parameter entity must precede
		     * any reference to it...
		     */
		    if ((ctxt->standalone == 1) ||
			((ctxt->hasExternalSubset == 0) &&
			 (ctxt->hasPErefs == 0))) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
			     "PEReference: %%%s; not found\n", name);
			ctxt->errNo = XML_ERR_UNDECLARED_ENTITY;
			ctxt->wellFormed = 0;
		    } else {
			/*
			 * [ VC: Entity Declared ]
			 * In a document with an external subset or external
			 * parameter entities with "standalone='no'", ...
			 * ... The declaration of a parameter entity must precede
			 * any reference to it...
			 */
			if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			    ctxt->sax->warning(ctxt->userData,
			     "PEReference: %%%s; not found\n", name);
			ctxt->valid = 0;
		    }
		} else {
		    /*
		     * Internal checking in case the entity quest barfed
		     */
		    if ((entity->type != XML_INTERNAL_PARAMETER_ENTITY) &&
		        (entity->type != XML_EXTERNAL_PARAMETER_ENTITY)) {
			if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			    ctxt->sax->warning(ctxt->userData,
			 "Internal: %%%s; is not a parameter entity\n", name);
		    } else {
			input = xmlOldNewEntityInputStream(ctxt, entity);
			xmlOldPushInput(ctxt, input);
		    }
		}
		ctxt->hasPErefs = 1;
	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParsePEReference: expecting ';'\n");
		ctxt->errNo = XML_ERR_ENTITYREF_SEMICOL_MISSING;
		ctxt->wellFormed = 0;
	    }
	    xmlFree(name);
	}
    }
}

/**
 * xmlOldParseStringPEReference:
 * @ctxt:  an XML parser context
 * @str:  a pointer to an index in the string
 *
 * parse PEReference declarations
 *
 * [69] PEReference ::= '%' Name ';'
 *
 * [ WFC: No Recursion ]
 * TODO A parsed entity must not contain a recursive
 * reference to itself, either directly or indirectly. 
 *
 * [ WFC: Entity Declared ]
 * In a document without any DTD, a document with only an internal DTD
 * subset which contains no parameter entity references, or a document
 * with "standalone='yes'", ...  ... The declaration of a parameter
 * entity must precede any reference to it...
 *
 * [ VC: Entity Declared ]
 * In a document with an external subset or external parameter entities
 * with "standalone='no'", ...  ... The declaration of a parameter entity
 * must precede any reference to it...
 *
 * [ WFC: In DTD ]
 * Parameter-entity references may only appear in the DTD.
 * NOTE: misleading but this is handled.
 *
 * Returns the string of the entity content.
 *         str is updated to the current value of the index
 */
static xmlEntityPtr
xmlOldParseStringPEReference(xmlParserCtxtPtr ctxt, const xmlChar **str) {
    const xmlChar *ptr;
    xmlChar cur;
    xmlChar *name;
    xmlEntityPtr entity = NULL;

    if ((str == NULL) || (*str == NULL)) return(NULL);
    ptr = *str;
    cur = *ptr;
    if (cur == '%') {
        ptr++;
	cur = *ptr;
        name = xmlOldParseStringName(ctxt, &ptr);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseStringPEReference: no name\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	} else {
	    cur = *ptr;
	    if (cur == ';') {
		ptr++;
		cur = *ptr;
		if ((ctxt->sax != NULL) &&
		    (ctxt->sax->getParameterEntity != NULL))
		    entity = ctxt->sax->getParameterEntity(ctxt->userData,
		                                           name);
		if (entity == NULL) {
		    /*
		     * [ WFC: Entity Declared ]
		     * In a document without any DTD, a document with only an
		     * internal DTD subset which contains no parameter entity
		     * references, or a document with "standalone='yes'", ...
		     * ... The declaration of a parameter entity must precede
		     * any reference to it...
		     */
		    if ((ctxt->standalone == 1) ||
			((ctxt->hasExternalSubset == 0) &&
			 (ctxt->hasPErefs == 0))) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
			     "PEReference: %%%s; not found\n", name);
			ctxt->errNo = XML_ERR_UNDECLARED_ENTITY;
			ctxt->wellFormed = 0;
		    } else {
			/*
			 * [ VC: Entity Declared ]
			 * In a document with an external subset or external
			 * parameter entities with "standalone='no'", ...
			 * ... The declaration of a parameter entity must
			 * precede any reference to it...
			 */
			if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			    ctxt->sax->warning(ctxt->userData,
			     "PEReference: %%%s; not found\n", name);
			ctxt->valid = 0;
		    }
		} else {
		    /*
		     * Internal checking in case the entity quest barfed
		     */
		    if ((entity->type != XML_INTERNAL_PARAMETER_ENTITY) &&
		        (entity->type != XML_EXTERNAL_PARAMETER_ENTITY)) {
			if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			    ctxt->sax->warning(ctxt->userData,
			 "Internal: %%%s; is not a parameter entity\n", name);
		    }
		}
		ctxt->hasPErefs = 1;
	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParseStringPEReference: expecting ';'\n");
		ctxt->errNo = XML_ERR_ENTITYREF_SEMICOL_MISSING;
		ctxt->wellFormed = 0;
	    }
	    xmlFree(name);
	}
    }
    *str = ptr;
    return(entity);
}

/**
 * xmlOldParseDocTypeDecl :
 * @ctxt:  an XML parser context
 *
 * parse a DOCTYPE declaration
 *
 * [28] doctypedecl ::= '<!DOCTYPE' S Name (S ExternalID)? S? 
 *                      ('[' (markupdecl | PEReference | S)* ']' S?)? '>'
 *
 * [ VC: Root Element Type ]
 * The Name in the document type declaration must match the element
 * type of the root element. 
 */

static void
xmlOldParseDocTypeDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlChar *ExternalID = NULL;
    xmlChar *URI = NULL;

    /*
     * We know that '<!DOCTYPE' has been detected.
     */
    SKIP(9);

    SKIP_BLANKS;

    /*
     * Parse the DOCTYPE name.
     */
    name = xmlOldParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	        "xmlParseDocTypeDecl : no DOCTYPE name !\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_NAME_REQUIRED;
    }

    SKIP_BLANKS;

    /*
     * Check for SystemID and ExternalID
     */
    URI = xmlOldParseExternalID(ctxt, &ExternalID, 1);

    if ((URI != NULL) || (ExternalID != NULL)) {
        ctxt->hasExternalSubset = 1;
    }

    SKIP_BLANKS;

    /*
     * NOTE: the SAX callback may try to fetch the external subset
     *       entity and fill it up !
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->internalSubset != NULL))
	ctxt->sax->internalSubset(ctxt->userData, name, ExternalID, URI);

    /*
     * Cleanup
     */
    if (URI != NULL) xmlFree(URI);
    if (ExternalID != NULL) xmlFree(ExternalID);
    if (name != NULL) xmlFree(name);

    /*
     * Is there any internal subset declarations ?
     * they are handled separately in xmlOldParseInternalSubset()
     */
    if (CUR == '[')
	return;

    /*
     * We should be at the end of the DOCTYPE declaration.
     */
    if (CUR != '>') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "DOCTYPE unproperly terminated\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_DOCTYPE_NOT_FINISHED;
    }
    NEXT;
}

/**
 * xmlOldParseInternalsubset :
 * @ctxt:  an XML parser context
 *
 * parse the internal subset declaration
 *
 * [28 end] ('[' (markupdecl | PEReference | S)* ']' S?)? '>'
 */

static void
xmlOldParseInternalSubset(xmlParserCtxtPtr ctxt) {
    /*
     * Is there any DTD definition ?
     */
    if (CUR == '[') {
        ctxt->instate = XML_PARSER_DTD;
        NEXT;
	/*
	 * Parse the succession of Markup declarations and 
	 * PEReferences.
	 * Subsequence (markupdecl | PEReference | S)*
	 */
	while (CUR != ']') {
	    const xmlChar *check = CUR_PTR;
	    int cons = ctxt->input->consumed;

	    SKIP_BLANKS;
	    xmlOldParseMarkupDecl(ctxt);
	    xmlOldParsePEReference(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1))
		xmlOldPopInput(ctxt);

	    if ((CUR_PTR == check) && (cons == ctxt->input->consumed)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
	     "xmlParseInternalSubset: error detected in Markup declaration\n");
		ctxt->wellFormed = 0;
		ctxt->errNo = XML_ERR_INTERNAL_ERROR;
		break;
	    }
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
	ctxt->errNo = XML_ERR_DOCTYPE_NOT_FINISHED;
    }
    NEXT;
}

/**
 * xmlOldParseAttribute:
 * @ctxt:  an XML parser context
 * @value:  a xmlChar ** used to store the value of the attribute
 *
 * parse an attribute
 *
 * [41] Attribute ::= Name Eq AttValue
 *
 * [ WFC: No External Entity References ]
 * Attribute values cannot contain direct or indirect entity references
 * to external entities.
 *
 * [ WFC: No < in Attribute Values ]
 * The replacement text of any entity referred to directly or indirectly in
 * an attribute value (other than "&lt;") must not contain a <. 
 * 
 * [ VC: Attribute Value Type ]
 * The attribute must have been declared; the value must be of the type
 * declared for it.
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

static xmlChar *
xmlOldParseAttribute(xmlParserCtxtPtr ctxt, xmlChar **value) {
    xmlChar *name, *val;

    *value = NULL;
    name = xmlOldParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "error parsing attribute name\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_NAME_REQUIRED;
        return(NULL);
    }

    /*
     * read the value
     */
    SKIP_BLANKS;
    if (CUR == '=') {
        NEXT;
	SKIP_BLANKS;
	val = xmlOldParseAttValue(ctxt);
	ctxt->instate = XML_PARSER_CONTENT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "Specification mandate value for attribute %s\n", name);
	ctxt->errNo = XML_ERR_ATTRIBUTE_WITHOUT_VALUE;
	ctxt->wellFormed = 0;
	return(NULL);
    }

    *value = val;
    return(name);
}

/**
 * xmlOldParseStartTag:
 * @ctxt:  an XML parser context
 * 
 * parse a start of tag either for rule element or
 * EmptyElement. In both case we don't parse the tag closing chars.
 *
 * [40] STag ::= '<' Name (S Attribute)* S? '>'
 *
 * [ WFC: Unique Att Spec ]
 * No attribute name may appear more than once in the same start-tag or
 * empty-element tag. 
 *
 * [44] EmptyElemTag ::= '<' Name (S Attribute)* S? '/>'
 *
 * [ WFC: Unique Att Spec ]
 * No attribute name may appear more than once in the same start-tag or
 * empty-element tag. 
 *
 * With namespace:
 *
 * [NS 8] STag ::= '<' QName (S Attribute)* S? '>'
 *
 * [NS 10] EmptyElement ::= '<' QName (S Attribute)* S? '/>'
 *
 * Returne the element name parsed
 */

static xmlChar *
xmlOldParseStartTag(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlChar *attname;
    xmlChar *attvalue;
    const xmlChar **atts = NULL;
    int nbatts = 0;
    int maxatts = 0;
    int i;

    if (CUR != '<') return(NULL);
    NEXT;

    name = xmlOldParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	     "xmlParseStartTag: invalid element name\n");
	ctxt->errNo = XML_ERR_NAME_REQUIRED;
	ctxt->wellFormed = 0;
        return(NULL);
    }

    /*
     * Now parse the attributes, it ends up with the ending
     *
     * (S Attribute)* S?
     */
    SKIP_BLANKS;
    GROW;
    while ((IS_CHAR(CUR)) &&
           (CUR != '>') && 
	   ((CUR != '/') || (NXT(1) != '>'))) {
	const xmlChar *q = CUR_PTR;
	int cons = ctxt->input->consumed;

	attname = xmlOldParseAttribute(ctxt, &attvalue);
        if ((attname != NULL) && (attvalue != NULL)) {
	    /*
	     * [ WFC: Unique Att Spec ]
	     * No attribute name may appear more than once in the same
	     * start-tag or empty-element tag. 
	     */
	    for (i = 0; i < nbatts;i += 2) {
	        if (!xmlStrcmp(atts[i], attname)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			        "Attribute %s redefined\n",
			                 attname);
		    ctxt->wellFormed = 0;
		    ctxt->errNo = XML_ERR_ATTRIBUTE_REDEFINED;
		    xmlFree(attname);
		    xmlFree(attvalue);
		    goto failed;
		}
	    }

	    /*
	     * Add the pair to atts
	     */
	    if (atts == NULL) {
	        maxatts = 10;
	        atts = (const xmlChar **) xmlMalloc(maxatts * sizeof(xmlChar *));
		if (atts == NULL) {
		    fprintf(stderr, "malloc of %ld byte failed\n",
			    maxatts * (long)sizeof(xmlChar *));
		    return(NULL);
		}
	    } else if (nbatts + 4 > maxatts) {
	        maxatts *= 2;
	        atts = (const xmlChar **) xmlRealloc(atts,
		                                  maxatts * sizeof(xmlChar *));
		if (atts == NULL) {
		    fprintf(stderr, "realloc of %ld byte failed\n",
			    maxatts * (long)sizeof(xmlChar *));
		    return(NULL);
		}
	    }
	    atts[nbatts++] = attname;
	    atts[nbatts++] = attvalue;
	    atts[nbatts] = NULL;
	    atts[nbatts + 1] = NULL;
	}

failed:     
	SKIP_BLANKS;
        if ((cons == ctxt->input->consumed) && (q == CUR_PTR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	         "xmlParseStartTag: problem parsing attributes\n");
	    ctxt->errNo = XML_ERR_INTERNAL_ERROR;
	    ctxt->wellFormed = 0;
	    break;
	}
        GROW;
    }

    /*
     * SAX: Start of Element !
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->startElement != NULL))
        ctxt->sax->startElement(ctxt->userData, name, atts);

    if (atts != NULL) {
        for (i = 0;i < nbatts;i++) xmlFree((xmlChar *) atts[i]);
	xmlFree(atts);
    }
    return(name);
}

/**
 * xmlOldParseEndTag:
 * @ctxt:  an XML parser context
 *
 * parse an end of tag
 *
 * [42] ETag ::= '</' Name S? '>'
 *
 * With namespace
 *
 * [NS 9] ETag ::= '</' QName S? '>'
 */

static void
xmlOldParseEndTag(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlChar *oldname;

    GROW;
    if ((CUR != '<') || (NXT(1) != '/')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlParseEndTag: '</' not found\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_LTSLASH_REQUIRED;
	return;
    }
    SKIP(2);

    name = xmlOldParseName(ctxt);

    /*
     * We should definitely be at the ending "S? '>'" part
     */
    GROW;
    SKIP_BLANKS;
    if ((!IS_CHAR(CUR)) || (CUR != '>')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "End tag : expected '>'\n");
	ctxt->errNo = XML_ERR_GT_REQUIRED;
	ctxt->wellFormed = 0;
    } else
	NEXT;

    /*
     * [ WFC: Element Type Match ]
     * The Name in an element's end-tag must match the element type in the
     * start-tag. 
     *
     */
    if ((name == NULL) || (ctxt->name == NULL) ||
        (xmlStrcmp(name, ctxt->name))) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL)) {
	    if ((name != NULL) && (ctxt->name != NULL)) {
		ctxt->sax->error(ctxt->userData,
		     "Opening and ending tag mismatch: %s and %s\n",
		                 ctxt->name, name);
            } else if (ctxt->name != NULL) {
		ctxt->sax->error(ctxt->userData,
		     "Ending tag eror for: %s\n", ctxt->name);
	    } else {
		ctxt->sax->error(ctxt->userData,
		     "Ending tag error: internal error ???\n");
	    }

	}     
	ctxt->errNo = XML_ERR_TAG_NAME_MISMATCH;
	ctxt->wellFormed = 0;
    }

    /*
     * SAX: End of Tag
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL))
        ctxt->sax->endElement(ctxt->userData, name);

    if (name != NULL)
	xmlFree(name);
    oldname = nameOldPop(ctxt);
    if (oldname != NULL) {
#ifdef DEBUG_STACK
	fprintf(stderr,"Close: popped %s\n", oldname);
#endif
	xmlFree(oldname);
    }
    return;
}

/**
 * xmlOldParseCDSect:
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
static void
xmlOldParseCDSect(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = XML_PARSER_BUFFER_SIZE;
    xmlChar r, s;
    xmlChar cur;

    if ((NXT(0) == '<') && (NXT(1) == '!') &&
	(NXT(2) == '[') && (NXT(3) == 'C') &&
	(NXT(4) == 'D') && (NXT(5) == 'A') &&
	(NXT(6) == 'T') && (NXT(7) == 'A') &&
	(NXT(8) == '[')) {
	SKIP(9);
    } else
        return;

    ctxt->instate = XML_PARSER_CDATA_SECTION;
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "CData section not finished\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_CDATA_NOT_FINISHED;
	ctxt->instate = XML_PARSER_CONTENT;
        return;
    }
    r = CUR;
    NEXT;
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "CData section not finished\n");
	ctxt->errNo = XML_ERR_CDATA_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->instate = XML_PARSER_CONTENT;
        return;
    }
    s = CUR;
    NEXT;
    cur = CUR;
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return;
    }
    while (IS_CHAR(cur) &&
           ((r != ']') || (s != ']') || (cur != '>'))) {
	if (len + 1 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		return;
	    }
	}
	buf[len++] = r;
	r = s;
	s = cur;
        NEXT;
	cur = CUR;
    }
    buf[len] = 0;
    ctxt->instate = XML_PARSER_CONTENT;
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "CData section not finished\n%.50s\n", buf);
	ctxt->errNo = XML_ERR_CDATA_NOT_FINISHED;
	ctxt->wellFormed = 0;
	xmlFree(buf);
        return;
    }
    NEXT;

    /*
     * Ok the buffer is to be consumed as cdata.
     */
    if (ctxt->sax != NULL) {
	if (ctxt->sax->cdataBlock != NULL)
	    ctxt->sax->cdataBlock(ctxt->userData, buf, len);
    }
    xmlFree(buf);
}

/**
 * xmlOldParseContent:
 * @ctxt:  an XML parser context
 *
 * Parse a content:
 *
 * [43] content ::= (element | CharData | Reference | CDSect | PI | Comment)*
 */

static void
xmlOldParseContent(xmlParserCtxtPtr ctxt) {
    GROW;
    while ((CUR != '<') || (NXT(1) != '/')) {
	const xmlChar *test = CUR_PTR;
	int cons = ctxt->input->consumed;
	int tok = ctxt->token;

	/*
	 * Handle  possible processed charrefs.
	 */
	if (ctxt->token != 0) {
	    xmlOldParseCharData(ctxt, 0);
	}

	/*
	 * First case : a Processing Instruction.
	 */
	else if ((RAW == '<') && (NXT(1) == '?')) {
	    xmlOldParsePI(ctxt);
	}

	/*
	 * Second case : a CDSection
	 */
	else if ((RAW == '<') && (NXT(1) == '!') &&
	    (NXT(2) == '[') && (NXT(3) == 'C') &&
	    (NXT(4) == 'D') && (NXT(5) == 'A') &&
	    (NXT(6) == 'T') && (NXT(7) == 'A') &&
	    (NXT(8) == '[')) {
	    xmlOldParseCDSect(ctxt);
	}

	/*
	 * Third case :  a comment
	 */
	else if ((RAW == '<') && (NXT(1) == '!') &&
		 (NXT(2) == '-') && (NXT(3) == '-')) {
	    xmlOldParseComment(ctxt);
	    ctxt->instate = XML_PARSER_CONTENT;
	}

	/*
	 * Fourth case :  a sub-element.
	 */
	else if (RAW == '<') {
	    xmlOldParseElement(ctxt);
	}

	/*
	 * Fifth case : a reference. If if has not been resolved,
	 *    parsing returns it's Name, create the node 
	 */

	else if (RAW == '&') {
	    xmlOldParseReference(ctxt);
	}

	/*
	 * Last case, text. Note that References are handled directly.
	 */
	else {
	    xmlOldParseCharData(ctxt, 0);
	}

	GROW;
	/*
	 * Pop-up of finished entities.
	 */
	while ((RAW == 0) && (ctxt->inputNr > 1))
	    xmlOldPopInput(ctxt);
	SHRINK;

	if ((cons == ctxt->input->consumed) && (test == CUR_PTR) &&
	    (tok == ctxt->token)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		     "detected an error in element content\n");
	    ctxt->errNo = XML_ERR_INTERNAL_ERROR;
	    ctxt->wellFormed = 0;
            break;
	}
    }
}

/**
 * xmlOldParseElement:
 * @ctxt:  an XML parser context
 *
 * parse an XML element, this is highly recursive
 *
 * [39] element ::= EmptyElemTag | STag content ETag
 *
 * [ WFC: Element Type Match ]
 * The Name in an element's end-tag must match the element type in the
 * start-tag. 
 *
 * [ VC: Element Valid ]
 * An element is valid if there is a declaration matching elementdecl
 * where the Name matches the element type and one of the following holds:
 *  - The declaration matches EMPTY and the element has no content.
 *  - The declaration matches children and the sequence of child elements
 *    belongs to the language generated by the regular expression in the
 *    content model, with optional white space (characters matching the
 *    nonterminal S) between each pair of child elements. 
 *  - The declaration matches Mixed and the content consists of character
 *    data and child elements whose types match names in the content model. 
 *  - The declaration matches ANY, and the types of any child elements have
 *    been declared.
 */

static void
xmlOldParseElement(xmlParserCtxtPtr ctxt) {
    const xmlChar *openTag = CUR_PTR;
    xmlChar *name;
    xmlChar *oldname;
    xmlParserNodeInfo node_info;
    xmlNodePtr ret;

    /* Capture start position */
    if (ctxt->record_info) {
        node_info.begin_pos = ctxt->input->consumed +
                          (CUR_PTR - ctxt->input->base);
	node_info.begin_line = ctxt->input->line;
    }

    name = xmlOldParseStartTag(ctxt);
    if (name == NULL) {
        return;
    }
    nameOldPush(ctxt, name);
    ret = ctxt->node;

    /*
     * [ VC: Root Element Type ]
     * The Name in the document type declaration must match the element
     * type of the root element. 
     */
    if (ctxt->validate && ctxt->wellFormed && ctxt->myDoc &&
        ctxt->node && (ctxt->node == ctxt->myDoc->root))
        ctxt->valid &= xmlValidateRoot(&ctxt->vctxt, ctxt->myDoc);

    /*
     * Check for an Empty Element.
     */
    if ((CUR == '/') && (NXT(1) == '>')) {
        SKIP(2);
	if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL))
	    ctxt->sax->endElement(ctxt->userData, name);
	oldname = nameOldPop(ctxt);
	if (oldname != NULL) {
#ifdef DEBUG_STACK
	    fprintf(stderr,"Close: popped %s\n", oldname);
#endif
	    xmlFree(oldname);
	}
	return;
    }
    if (CUR == '>') {
        NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "Couldn't find end of Start Tag\n%.30s\n",
	                     openTag);
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_GT_REQUIRED;

	/*
	 * end of parsing of this node.
	 */
	nodeOldPop(ctxt);
	oldname = nameOldPop(ctxt);
	if (oldname != NULL) {
#ifdef DEBUG_STACK
	    fprintf(stderr,"Close: popped %s\n", oldname);
#endif
	    xmlFree(oldname);
	}

	/*
	 * Capture end position and add node
	 */
	if ( ret != NULL && ctxt->record_info ) {
	   node_info.end_pos = ctxt->input->consumed +
			      (CUR_PTR - ctxt->input->base);
	   node_info.end_line = ctxt->input->line;
	   node_info.node = ret;
	   xmlParserAddNodeInfo(ctxt, &node_info);
	}
	return;
    }

    /*
     * Parse the content of the element:
     */
    xmlOldParseContent(ctxt);
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	         "Premature end of data in tag %.30s\n", openTag);
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_TAG_NOT_FINISED;

	/*
	 * end of parsing of this node.
	 */
	nodeOldPop(ctxt);
	oldname = nameOldPop(ctxt);
	if (oldname != NULL) {
#ifdef DEBUG_STACK
	    fprintf(stderr,"Close: popped %s\n", oldname);
#endif
	    xmlFree(oldname);
	}
	return;
    }

    /*
     * parse the end of tag: '</' should be here.
     */
    xmlOldParseEndTag(ctxt);

    /*
     * Capture end position and add node
     */
    if ( ret != NULL && ctxt->record_info ) {
       node_info.end_pos = ctxt->input->consumed +
                          (CUR_PTR - ctxt->input->base);
       node_info.end_line = ctxt->input->line;
       node_info.node = ret;
       xmlParserAddNodeInfo(ctxt, &node_info);
    }
}

/**
 * xmlOldParseVersionNum:
 * @ctxt:  an XML parser context
 *
 * parse the XML version value.
 *
 * [26] VersionNum ::= ([a-zA-Z0-9_.:] | '-')+
 *
 * Returns the string giving the XML version number, or NULL
 */
static xmlChar *
xmlOldParseVersionNum(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = 10;
    xmlChar cur;

    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return(NULL);
    }
    cur = CUR;
    while (IS_CHAR(cur) &&
           (((cur >= 'a') && (cur <= 'z')) ||
            ((cur >= 'A') && (cur <= 'Z')) ||
            ((cur >= '0') && (cur <= '9')) ||
            (cur == '_') || (cur == '.') ||
	    (cur == ':') || (cur == '-'))) {
	if (len + 1 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		return(NULL);
	    }
	}
	buf[len++] = cur;
	NEXT;
	cur=CUR;
    }
    buf[len] = 0;
    return(buf);
}

/**
 * xmlOldParseVersionInfo:
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

static xmlChar *
xmlOldParseVersionInfo(xmlParserCtxtPtr ctxt) {
    xmlChar *version = NULL;
    const xmlChar *q;

    if ((CUR == 'v') && (NXT(1) == 'e') &&
        (NXT(2) == 'r') && (NXT(3) == 's') &&
	(NXT(4) == 'i') && (NXT(5) == 'o') &&
	(NXT(6) == 'n')) {
	SKIP(7);
	SKIP_BLANKS;
	if (CUR != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseVersionInfo : expected '='\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_EQUAL_REQUIRED;
	    return(NULL);
        }
	NEXT;
	SKIP_BLANKS;
	if (CUR == '"') {
	    NEXT;
	    q = CUR_PTR;
	    version = xmlOldParseVersionNum(ctxt);
	    if (CUR != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		                     "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else if (CUR == '\''){
	    NEXT;
	    q = CUR_PTR;
	    version = xmlOldParseVersionNum(ctxt);
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "String not closed\n%.50s\n", q);
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		      "xmlParseVersionInfo : expected ' or \"\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_STRING_NOT_STARTED;
	}
    }
    return(version);
}

/**
 * xmlOldParseEncName:
 * @ctxt:  an XML parser context
 *
 * parse the XML encoding name
 *
 * [81] EncName ::= [A-Za-z] ([A-Za-z0-9._] | '-')*
 *
 * Returns the encoding name value or NULL
 */
static xmlChar *
xmlOldParseEncName(xmlParserCtxtPtr ctxt) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = 10;
    xmlChar cur;

    cur = CUR;
    if (((cur >= 'a') && (cur <= 'z')) ||
        ((cur >= 'A') && (cur <= 'Z'))) {
	buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
	if (buf == NULL) {
	    fprintf(stderr, "malloc of %d byte failed\n", size);
	    return(NULL);
	}
	
	buf[len++] = cur;
	NEXT;
	cur = CUR;
	while (IS_CHAR(cur) &&
	       (((cur >= 'a') && (cur <= 'z')) ||
		((cur >= 'A') && (cur <= 'Z')) ||
		((cur >= '0') && (cur <= '9')) ||
		(cur == '.') || (cur == '_') ||
		(cur == '-'))) {
	    if (len + 1 >= size) {
		size *= 2;
		buf = xmlRealloc(buf, size * sizeof(xmlChar));
		if (buf == NULL) {
		    fprintf(stderr, "realloc of %d byte failed\n", size);
		    return(NULL);
		}
	    }
	    buf[len++] = cur;
	    NEXT;
	    cur = CUR;
	    if (cur == 0) {
	        SHRINK;
		GROW;
		cur = CUR;
	    }
        }
	buf[len] = 0;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Invalid XML encoding name\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_ENCODING_NAME;
    }
    return(buf);
}

/**
 * xmlOldParseEncodingDecl:
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

static xmlChar *
xmlOldParseEncodingDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *encoding = NULL;
    const xmlChar *q;

    SKIP_BLANKS;
    if ((CUR == 'e') && (NXT(1) == 'n') &&
        (NXT(2) == 'c') && (NXT(3) == 'o') &&
	(NXT(4) == 'd') && (NXT(5) == 'i') &&
	(NXT(6) == 'n') && (NXT(7) == 'g')) {
	SKIP(8);
	SKIP_BLANKS;
	if (CUR != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseEncodingDecl : expected '='\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_EQUAL_REQUIRED;
	    return(NULL);
        }
	NEXT;
	SKIP_BLANKS;
	if (CUR == '"') {
	    NEXT;
	    q = CUR_PTR;
	    encoding = xmlOldParseEncName(ctxt);
	    if (CUR != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		                     "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else if (CUR == '\''){
	    NEXT;
	    q = CUR_PTR;
	    encoding = xmlOldParseEncName(ctxt);
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else if (CUR == '"'){
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		     "xmlParseEncodingDecl : expected ' or \"\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_STRING_NOT_STARTED;
	}
    }
    return(encoding);
}

/**
 * xmlOldParseSDDecl:
 * @ctxt:  an XML parser context
 *
 * parse the XML standalone declaration
 *
 * [32] SDDecl ::= S 'standalone' Eq
 *                 (("'" ('yes' | 'no') "'") | ('"' ('yes' | 'no')'"')) 
 *
 * [ VC: Standalone Document Declaration ]
 * TODO The standalone document declaration must have the value "no"
 * if any external markup declarations contain declarations of:
 *  - attributes with default values, if elements to which these
 *    attributes apply appear in the document without specifications
 *    of values for these attributes, or
 *  - entities (other than amp, lt, gt, apos, quot), if references
 *    to those entities appear in the document, or
 *  - attributes with values subject to normalization, where the
 *    attribute appears in the document with a value which will change
 *    as a result of normalization, or
 *  - element types with element content, if white space occurs directly
 *    within any instance of those types.
 *
 * Returns 1 if standalone, 0 otherwise
 */

static int
xmlOldParseSDDecl(xmlParserCtxtPtr ctxt) {
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
	    ctxt->errNo = XML_ERR_EQUAL_REQUIRED;
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
		    ctxt->sax->error(ctxt->userData,
		                     "standalone accepts only 'yes' or 'no'\n");
		ctxt->errNo = XML_ERR_STANDALONE_VALUE;
		ctxt->wellFormed = 0;
	    }
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n");
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
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
		ctxt->errNo = XML_ERR_STANDALONE_VALUE;
		ctxt->wellFormed = 0;
	    }
	    if (CUR != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n");
		ctxt->wellFormed = 0;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else {
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "Standalone value not found\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_STRING_NOT_STARTED;
        }
    }
    return(standalone);
}

/**
 * xmlOldParseXMLDecl:
 * @ctxt:  an XML parser context
 * 
 * parse an XML declaration header
 *
 * [23] XMLDecl ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
 */

static void
xmlOldParseXMLDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *version;

    /*
     * We know that '<?xml' is here.
     */
    SKIP(5);

    if (!IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed after '<?xml'\n");
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	ctxt->wellFormed = 0;
    }
    SKIP_BLANKS;

    /*
     * We should have the VersionInfo here.
     */
    version = xmlOldParseVersionInfo(ctxt);
    if (version == NULL)
	version = xmlCharStrdup(XML_DEFAULT_VERSION);
    ctxt->version = xmlStrdup(version);
    xmlFree(version);

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
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	ctxt->wellFormed = 0;
    }
    ctxt->encoding = xmlOldParseEncodingDecl(ctxt);

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
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
    }
    SKIP_BLANKS;
    ctxt->standalone = xmlOldParseSDDecl(ctxt);

    SKIP_BLANKS;
    if ((CUR == '?') && (NXT(1) == '>')) {
        SKIP(2);
    } else if (CUR == '>') {
        /* Deprecated old WD ... */
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	                     "XML declaration must end-up with '?>'\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_XMLDECL_NOT_FINISHED;
	NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "parsing XML declaration: '?>' expected\n");
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_XMLDECL_NOT_FINISHED;
	MOVETO_ENDTAG(CUR_PTR);
	NEXT;
    }
}

/**
 * xmlOldParseMisc:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Misc* optionnal field.
 *
 * [27] Misc ::= Comment | PI |  S
 */

static void
xmlOldParseMisc(xmlParserCtxtPtr ctxt) {
    while (((CUR == '<') && (NXT(1) == '?')) ||
           ((CUR == '<') && (NXT(1) == '!') &&
	    (NXT(2) == '-') && (NXT(3) == '-')) ||
           IS_BLANK(CUR)) {
        if ((CUR == '<') && (NXT(1) == '?')) {
	    xmlOldParsePI(ctxt);
	} else if (IS_BLANK(CUR)) {
	    NEXT;
	} else
	    xmlOldParseComment(ctxt);
    }
}

/**
 * xmlOldParseDocument :
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
xmlOldParseDocument(xmlParserCtxtPtr ctxt) {
    xmlDefaultSAXHandlerInit();

    GROW;

    ctxt->pedantic = 0; /* we run the old 1.8.11 parser */

    /*
     * SAX: beginning of the document processing.
     */
    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
        ctxt->sax->setDocumentLocator(ctxt->userData, &xmlDefaultSAXLocator);

    /*
     * TODO We should check for encoding here and plug-in some
     * conversion code !!!!
     */

    /*
     * Wipe out everything which is before the first '<'
     */
    if (IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	    "Extra spaces at the beginning of the document are not allowed\n");
	ctxt->errNo = XML_ERR_DOCUMENT_START;
	ctxt->wellFormed = 0;
	SKIP_BLANKS;
    }

    if (CUR == 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Document is empty\n");
	ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
	ctxt->wellFormed = 0;
    }

    /*
     * Check for the XMLDecl in the Prolog.
     */
    GROW;
    if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l') && (IS_BLANK(NXT(5)))) {
	xmlOldParseXMLDecl(ctxt);
	SKIP_BLANKS;
    } else if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'X') && (NXT(3) == 'M') &&
	(NXT(4) == 'L') && (IS_BLANK(NXT(5)))) {
	/*
	 * The first drafts were using <?XML and the final W3C REC
	 * now use <?xml ...
	 */
	xmlOldParseXMLDecl(ctxt);
	SKIP_BLANKS;
    } else {
	ctxt->version = xmlCharStrdup(XML_DEFAULT_VERSION);
    }
    if ((ctxt->sax) && (ctxt->sax->startDocument))
        ctxt->sax->startDocument(ctxt->userData);

    /*
     * The Misc part of the Prolog
     */
    GROW;
    xmlOldParseMisc(ctxt);

    /*
     * Then possibly doc type declaration(s) and more Misc
     * (doctypedecl Misc*)?
     */
    GROW;
    if ((CUR == '<') && (NXT(1) == '!') &&
	(NXT(2) == 'D') && (NXT(3) == 'O') &&
	(NXT(4) == 'C') && (NXT(5) == 'T') &&
	(NXT(6) == 'Y') && (NXT(7) == 'P') &&
	(NXT(8) == 'E')) {
	xmlOldParseDocTypeDecl(ctxt);
	if (CUR == '[') {
	    ctxt->instate = XML_PARSER_DTD;
	    xmlOldParseInternalSubset(ctxt);
	}
	ctxt->instate = XML_PARSER_PROLOG;
	xmlOldParseMisc(ctxt);
    }

    /*
     * Time to start parsing the tree itself
     */
    GROW;
    if (CUR != '<') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		    "Start tag expect, '<' not found\n");
	ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
	ctxt->wellFormed = 0;
	ctxt->instate = XML_PARSER_EOF;
    } else {
	ctxt->instate = XML_PARSER_CONTENT;
	xmlOldParseElement(ctxt);
	ctxt->instate = XML_PARSER_EPILOG;


	/*
	 * The Misc part at the end
	 */
	xmlOldParseMisc(ctxt);

	if (CUR != 0) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Extra content at the end of the document\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_DOCUMENT_END;
	}
	ctxt->instate = XML_PARSER_EOF;
    }

    /*
     * SAX: end of the document processing.
     */
    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
        ctxt->sax->endDocument(ctxt->userData);
    if (! ctxt->wellFormed) return(-1);
    return(0);
}

/************************************************************************
 *									*
 * 		Progressive parsing interfaces				*
 *									*
 ************************************************************************/

/**
 * xmlOldParseLookupSequence:
 * @ctxt:  an XML parser context
 * @first:  the first char to lookup
 * @next:  the next char to lookup or zero
 * @third:  the next char to lookup or zero
 *
 * Try to find if a sequence (first, next, third) or  just (first next) or
 * (first) is available in the input stream.
 * This function has a side effect of (possibly) incrementing ctxt->checkIndex
 * to avoid rescanning sequences of bytes, it DOES change the state of the
 * parser, do not use liberally.
 *
 * Returns the index to the current parsing point if the full sequence
 *      is available, -1 otherwise.
 */
static int
xmlOldParseLookupSequence(xmlParserCtxtPtr ctxt, xmlChar first,
                       xmlChar next, xmlChar third) {
    int base, len;
    xmlParserInputPtr in;
    const xmlChar *buf;

    in = ctxt->input;
    if (in == NULL) return(-1);
    base = in->cur - in->base;
    if (base < 0) return(-1);
    if (ctxt->checkIndex > base)
        base = ctxt->checkIndex;
    if (in->buf == NULL) {
	buf = in->base;
	len = in->length;
    } else {
	buf = in->buf->buffer->content;
	len = in->buf->buffer->use;
    }
    /* take into account the sequence length */
    if (third) len -= 2;
    else if (next) len --;
    for (;base < len;base++) {
        if (buf[base] == first) {
	    if (third != 0) {
		if ((buf[base + 1] != next) ||
		    (buf[base + 2] != third)) continue;
	    } else if (next != 0) {
		if (buf[base + 1] != next) continue;
	    }
	    ctxt->checkIndex = 0;
#ifdef DEBUG_PUSH
	    if (next == 0)
		fprintf(stderr, "PP: lookup '%c' found at %d\n",
			first, base);
	    else if (third == 0)
		fprintf(stderr, "PP: lookup '%c%c' found at %d\n",
			first, next, base);
	    else 
		fprintf(stderr, "PP: lookup '%c%c%c' found at %d\n",
			first, next, third, base);
#endif
	    return(base - (in->cur - in->base));
	}
    }
    ctxt->checkIndex = base;
#ifdef DEBUG_PUSH
    if (next == 0)
	fprintf(stderr, "PP: lookup '%c' failed\n", first);
    else if (third == 0)
	fprintf(stderr, "PP: lookup '%c%c' failed\n", first, next);
    else	
	fprintf(stderr, "PP: lookup '%c%c%c' failed\n", first, next, third);
#endif
    return(-1);
}

/**
 * xmlOldParseTryOrFinish:
 * @ctxt:  an XML parser context
 * @terminate:  last chunk indicator
 *
 * Try to progress on parsing
 *
 * Returns zero if no parsing was possible
 */
static int
xmlOldParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
    int ret = 0;
    xmlParserInputPtr in;
    int avail;
    xmlChar cur, next;

#ifdef DEBUG_PUSH
    switch (ctxt->instate) {
	case XML_PARSER_EOF:
	    fprintf(stderr, "PP: try EOF\n"); break;
	case XML_PARSER_START:
	    fprintf(stderr, "PP: try START\n"); break;
	case XML_PARSER_MISC:
	    fprintf(stderr, "PP: try MISC\n");break;
	case XML_PARSER_COMMENT:
	    fprintf(stderr, "PP: try COMMENT\n");break;
	case XML_PARSER_PROLOG:
	    fprintf(stderr, "PP: try PROLOG\n");break;
	case XML_PARSER_START_TAG:
	    fprintf(stderr, "PP: try START_TAG\n");break;
	case XML_PARSER_CONTENT:
	    fprintf(stderr, "PP: try CONTENT\n");break;
	case XML_PARSER_CDATA_SECTION:
	    fprintf(stderr, "PP: try CDATA_SECTION\n");break;
	case XML_PARSER_END_TAG:
	    fprintf(stderr, "PP: try END_TAG\n");break;
	case XML_PARSER_ENTITY_DECL:
	    fprintf(stderr, "PP: try ENTITY_DECL\n");break;
	case XML_PARSER_ENTITY_VALUE:
	    fprintf(stderr, "PP: try ENTITY_VALUE\n");break;
	case XML_PARSER_ATTRIBUTE_VALUE:
	    fprintf(stderr, "PP: try ATTRIBUTE_VALUE\n");break;
	case XML_PARSER_DTD:
	    fprintf(stderr, "PP: try DTD\n");break;
	case XML_PARSER_EPILOG:
	    fprintf(stderr, "PP: try EPILOG\n");break;
	case XML_PARSER_PI:
	    fprintf(stderr, "PP: try PI\n");break;
    }
#endif

    while (1) {
	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlOldPopInput(ctxt);

	in = ctxt->input;
	if (in == NULL) break;
	if (in->buf == NULL)
	    avail = in->length - (in->cur - in->base);
	else
	    avail = in->buf->buffer->use - (in->cur - in->base);
        if (avail < 1)
	    goto done;
        switch (ctxt->instate) {
            case XML_PARSER_EOF:
	        /*
		 * Document parsing is done !
		 */
	        goto done;
            case XML_PARSER_START:
	        /*
		 * Very first chars read from the document flow.
		 */
		cur = in->cur[0];
		if (IS_BLANK(cur)) {
		    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
			ctxt->sax->setDocumentLocator(ctxt->userData,
						      &xmlDefaultSAXLocator);
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
	    "Extra spaces at the beginning of the document are not allowed\n");
		    ctxt->errNo = XML_ERR_DOCUMENT_START;
		    ctxt->wellFormed = 0;
		    SKIP_BLANKS;
		    ret++;
		    if (in->buf == NULL)
			avail = in->length - (in->cur - in->base);
		    else
			avail = in->buf->buffer->use - (in->cur - in->base);
		}
		if (avail < 2)
		    goto done;

		cur = in->cur[0];
		next = in->cur[1];
		if (cur == 0) {
		    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
			ctxt->sax->setDocumentLocator(ctxt->userData,
						      &xmlDefaultSAXLocator);
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, "Document is empty\n");
		    ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
		    ctxt->wellFormed = 0;
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
			ctxt->sax->endDocument(ctxt->userData);
		    goto done;
		}
	        if ((cur == '<') && (next == '?')) {
		    /* PI or XML decl */
		    if (avail < 5) return(ret);
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '?', '>', 0) < 0))
			return(ret);
		    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
			ctxt->sax->setDocumentLocator(ctxt->userData,
						      &xmlDefaultSAXLocator);
		    if ((in->cur[2] == 'x') &&
			(in->cur[3] == 'm') &&
			(in->cur[4] == 'l') &&
			(IS_BLANK(in->cur[5]))) {
			ret += 5;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: Parsing XML Decl\n");
#endif
			xmlOldParseXMLDecl(ctxt);
			if ((ctxt->sax) && (ctxt->sax->startDocument))
			    ctxt->sax->startDocument(ctxt->userData);
			ctxt->instate = XML_PARSER_MISC;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering MISC\n");
#endif
		    } else {
			ctxt->version = xmlCharStrdup(XML_DEFAULT_VERSION);
			if ((ctxt->sax) && (ctxt->sax->startDocument))
			    ctxt->sax->startDocument(ctxt->userData);
			ctxt->instate = XML_PARSER_MISC;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering MISC\n");
#endif
		    }
		} else {
		    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
			ctxt->sax->setDocumentLocator(ctxt->userData,
						      &xmlDefaultSAXLocator);
		    ctxt->version = xmlCharStrdup(XML_DEFAULT_VERSION);
		    if ((ctxt->sax) && (ctxt->sax->startDocument))
			ctxt->sax->startDocument(ctxt->userData);
		    ctxt->instate = XML_PARSER_MISC;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering MISC\n");
#endif
		}
		break;
            case XML_PARSER_MISC:
		SKIP_BLANKS;
		if (in->buf == NULL)
		    avail = in->length - (in->cur - in->base);
		else
		    avail = in->buf->buffer->use - (in->cur - in->base);
		if (avail < 2)
		    goto done;
		cur = in->cur[0];
		next = in->cur[1];
	        if ((cur == '<') && (next == '?')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlOldParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlOldParseComment(ctxt);
		    ctxt->instate = XML_PARSER_MISC;
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == 'D') && (in->cur[3] == 'O') &&
		    (in->cur[4] == 'C') && (in->cur[5] == 'T') &&
		    (in->cur[6] == 'Y') && (in->cur[7] == 'P') &&
		    (in->cur[8] == 'E')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '>', 0, 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing internal subset\n");
#endif
		    xmlOldParseDocTypeDecl(ctxt);
		    if (CUR == '[') {
			ctxt->instate = XML_PARSER_DTD;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering DTD\n");
#endif
		    } else {
			ctxt->instate = XML_PARSER_PROLOG;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering PROLOG\n");
#endif
		    }
		} else if ((cur == '<') && (next == '!') &&
		           (avail < 9)) {
		    goto done;
		} else {
		    ctxt->instate = XML_PARSER_START_TAG;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering START_TAG\n");
#endif
		}
		break;
            case XML_PARSER_PROLOG:
		SKIP_BLANKS;
		if (in->buf == NULL)
		    avail = in->length - (in->cur - in->base);
		else
		    avail = in->buf->buffer->use - (in->cur - in->base);
		if (avail < 2) 
		    goto done;
		cur = in->cur[0];
		next = in->cur[1];
	        if ((cur == '<') && (next == '?')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlOldParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlOldParseComment(ctxt);
		    ctxt->instate = XML_PARSER_PROLOG;
		} else if ((cur == '<') && (next == '!') &&
		           (avail < 4)) {
		    goto done;
		} else {
		    ctxt->instate = XML_PARSER_START_TAG;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering START_TAG\n");
#endif
		}
		break;
            case XML_PARSER_EPILOG:
		SKIP_BLANKS;
		if (in->buf == NULL)
		    avail = in->length - (in->cur - in->base);
		else
		    avail = in->buf->buffer->use - (in->cur - in->base);
		if (avail < 2)
		    goto done;
		cur = in->cur[0];
		next = in->cur[1];
	        if ((cur == '<') && (next == '?')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlOldParsePI(ctxt);
		    ctxt->instate = XML_PARSER_EPILOG;
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlOldParseComment(ctxt);
		    ctxt->instate = XML_PARSER_EPILOG;
		} else if ((cur == '<') && (next == '!') &&
		           (avail < 4)) {
		    goto done;
		} else {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			    "Extra content at the end of the document\n");
		    ctxt->wellFormed = 0;
		    ctxt->errNo = XML_ERR_DOCUMENT_END;
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
			ctxt->sax->endDocument(ctxt->userData);
		    goto done;
		}
		break;
            case XML_PARSER_START_TAG: {
	        xmlChar *name, *oldname;

		if (avail < 2)
		    goto done;
		cur = in->cur[0];
	        if (cur != '<') {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
				"Start tag expect, '<' not found\n");
		    ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
		    ctxt->wellFormed = 0;
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
			ctxt->sax->endDocument(ctxt->userData);
		    goto done;
		}
		if ((!terminate) &&
		    (xmlOldParseLookupSequence(ctxt, '>', 0, 0) < 0))
		    goto done;
		name = xmlOldParseStartTag(ctxt);
		if (name == NULL) {
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
			ctxt->sax->endDocument(ctxt->userData);
		    goto done;
		}
		nameOldPush(ctxt, xmlStrdup(name));

		/*
		 * [ VC: Root Element Type ]
		 * The Name in the document type declaration must match
		 * the element type of the root element. 
		 */
		if (ctxt->validate && ctxt->wellFormed && ctxt->myDoc &&
		    ctxt->node && (ctxt->node == ctxt->myDoc->root))
		    ctxt->valid &= xmlValidateRoot(&ctxt->vctxt, ctxt->myDoc);

		/*
		 * Check for an Empty Element.
		 */
		if ((CUR == '/') && (NXT(1) == '>')) {
		    SKIP(2);
		    if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL))
			ctxt->sax->endElement(ctxt->userData, name);
		    xmlFree(name);
		    oldname = nameOldPop(ctxt);
		    if (oldname != NULL) {
#ifdef DEBUG_STACK
			fprintf(stderr,"Close: popped %s\n", oldname);
#endif
			xmlFree(oldname);
		    }
		    if (ctxt->name == NULL) {
			ctxt->instate = XML_PARSER_EPILOG;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering EPILOG\n");
#endif
		    } else {
			ctxt->instate = XML_PARSER_CONTENT;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering CONTENT\n");
#endif
		    }
		    break;
		}
		if (CUR == '>') {
		    NEXT;
		} else {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
					 "Couldn't find end of Start Tag %s\n",
					 name);
		    ctxt->wellFormed = 0;
		    ctxt->errNo = XML_ERR_GT_REQUIRED;

		    /*
		     * end of parsing of this node.
		     */
		    nodeOldPop(ctxt);
		    oldname = nameOldPop(ctxt);
		    if (oldname != NULL) {
#ifdef DEBUG_STACK
			fprintf(stderr,"Close: popped %s\n", oldname);
#endif
			xmlFree(oldname);
		    }
		}
		xmlFree(name);
		ctxt->instate = XML_PARSER_CONTENT;
#ifdef DEBUG_PUSH
		fprintf(stderr, "PP: entering CONTENT\n");
#endif
                break;
	    }
            case XML_PARSER_CONTENT:
                /*
		 * Handle preparsed entities and charRef
		 */
		if (ctxt->token != 0) {
		    xmlChar cur[2] = { 0 , 0 } ;

		    cur[0] = (xmlChar) ctxt->token;
		    if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
			ctxt->sax->characters(ctxt->userData, cur, 1);
		    ctxt->token = 0;
		}
		if (avail < 2)
		    goto done;
		cur = in->cur[0];
		next = in->cur[1];
	        if ((cur == '<') && (next == '?')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlOldParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		           (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlOldParseComment(ctxt);
		    ctxt->instate = XML_PARSER_CONTENT;
		} else if ((cur == '<') && (in->cur[1] == '!') &&
		    (in->cur[2] == '[') && (NXT(3) == 'C') &&
		    (in->cur[4] == 'D') && (NXT(5) == 'A') &&
		    (in->cur[6] == 'T') && (NXT(7) == 'A') &&
		    (in->cur[8] == '[')) {
		    SKIP(9);
		    ctxt->instate = XML_PARSER_CDATA_SECTION;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering CDATA_SECTION\n");
#endif
		    break;
		} else if ((cur == '<') && (next == '!') &&
		           (avail < 9)) {
		    goto done;
		} else if ((cur == '<') && (next == '/')) {
		    ctxt->instate = XML_PARSER_END_TAG;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering END_TAG\n");
#endif
		    break;
		} else if (cur == '<') {
		    ctxt->instate = XML_PARSER_START_TAG;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering START_TAG\n");
#endif
		    break;
		} else if (cur == '&') {
		    if ((!terminate) &&
		        (xmlOldParseLookupSequence(ctxt, ';', 0, 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Reference\n");
#endif
		    /* TODO: check generation of subtrees if noent !!! */
		    xmlOldParseReference(ctxt);
		} else {
		    /* TODO Avoid the extra copy, handle directly !!!!!! */
		    /*
		     * Goal of the following test is :
		     *  - minimize calls to the SAX 'character' callback
		     *    when they are mergeable
		     *  - handle an problem for isBlank when we only parse
		     *    a sequence of blank chars and the next one is
		     *    not available to check against '<' presence.
		     *  - tries to homogenize the differences in SAX
		     *    callbacks beween the push and pull versions
		     *    of the parser.
		     */
		    if ((ctxt->inputNr == 1) &&
		        (avail < XML_PARSER_BIG_BUFFER_SIZE)) {
			if ((!terminate) &&
			    (xmlOldParseLookupSequence(ctxt, '<', 0, 0) < 0))
			    goto done;
                    }
		    ctxt->checkIndex = 0;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing char data\n");
#endif
		    xmlOldParseCharData(ctxt, 0);
		}
		/*
		 * Pop-up of finished entities.
		 */
		while ((CUR == 0) && (ctxt->inputNr > 1))
		    xmlOldPopInput(ctxt);
		break;
            case XML_PARSER_CDATA_SECTION: {
	        /*
		 * The Push mode need to have the SAX callback for 
		 * cdataBlock merge back contiguous callbacks.
		 */
		int base;

		in = ctxt->input;
		base = xmlOldParseLookupSequence(ctxt, ']', ']', '>');
		if (base < 0) {
		    if (avail >= XML_PARSER_BIG_BUFFER_SIZE + 2) {
			if (ctxt->sax != NULL) {
			    if (ctxt->sax->cdataBlock != NULL)
				ctxt->sax->cdataBlock(ctxt->userData, in->cur,
					  XML_PARSER_BIG_BUFFER_SIZE);
			}
			SKIP(XML_PARSER_BIG_BUFFER_SIZE);
			ctxt->checkIndex = 0;
		    }
		    goto done;
		} else {
		    if ((ctxt->sax != NULL) && (base > 0)) {
			if (ctxt->sax->cdataBlock != NULL)
			    ctxt->sax->cdataBlock(ctxt->userData,
						  in->cur, base);
		    }
		    SKIP(base + 3);
		    ctxt->checkIndex = 0;
		    ctxt->instate = XML_PARSER_CONTENT;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering CONTENT\n");
#endif
		}
		break;
	    }
            case XML_PARSER_END_TAG:
		if (avail < 2)
		    goto done;
		if ((!terminate) &&
		    (xmlOldParseLookupSequence(ctxt, '>', 0, 0) < 0))
		    goto done;
		xmlOldParseEndTag(ctxt);
		if (ctxt->name == NULL) {
		    ctxt->instate = XML_PARSER_EPILOG;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EPILOG\n");
#endif
		} else {
		    ctxt->instate = XML_PARSER_CONTENT;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering CONTENT\n");
#endif
		}
		break;
            case XML_PARSER_DTD: {
	        /*
		 * Sorry but progressive parsing of the internal subset
		 * is not expected to be supported. We first check that
		 * the full content of the internal subset is available and
		 * the parsing is launched only at that point.
		 * Internal subset ends up with "']' S? '>'" in an unescaped
		 * section and not in a ']]>' sequence which are conditional
		 * sections (whoever argued to keep that crap in XML deserve
		 * a place in hell !).
		 */
		int base, i;
		xmlChar *buf;
	        xmlChar quote = 0;

		base = in->cur - in->base;
		if (base < 0) return(0);
		if (ctxt->checkIndex > base)
		    base = ctxt->checkIndex;
		buf = in->buf->buffer->content;
		for (;base < in->buf->buffer->use;base++) {
		    if (quote != 0) {
		        if (buf[base] == quote)
			    quote = 0;
			continue;    
		    }
		    if (buf[base] == '"') {
		        quote = '"';
			continue;
		    }
		    if (buf[base] == '\'') {
		        quote = '\'';
			continue;
		    }
		    if (buf[base] == ']') {
		        if (base +1 >= in->buf->buffer->use)
			    break;
			if (buf[base + 1] == ']') {
			    /* conditional crap, skip both ']' ! */
			    base++;
			    continue;
			}
		        for (i = 0;base + i < in->buf->buffer->use;i++) {
			    if (buf[base + i] == '>')
			        goto found_end_int_subset;
			}
		        break;
		    }
		}
		/*
		 * We didn't found the end of the Internal subset
		 */
		if (quote == 0) 
		    ctxt->checkIndex = base;
#ifdef DEBUG_PUSH
		if (next == 0)
		    fprintf(stderr, "PP: lookup of int subset end filed\n");
#endif
	        goto done;

found_end_int_subset:
		xmlOldParseInternalSubset(ctxt);
		ctxt->instate = XML_PARSER_PROLOG;
		ctxt->checkIndex = 0;
#ifdef DEBUG_PUSH
		fprintf(stderr, "PP: entering PROLOG\n");
#endif
                break;
	    }
            case XML_PARSER_COMMENT:
		fprintf(stderr, "PP: internal error, state == COMMENT\n");
		ctxt->instate = XML_PARSER_CONTENT;
#ifdef DEBUG_PUSH
		fprintf(stderr, "PP: entering CONTENT\n");
#endif
		break;
            case XML_PARSER_PI:
		fprintf(stderr, "PP: internal error, state == PI\n");
		ctxt->instate = XML_PARSER_CONTENT;
#ifdef DEBUG_PUSH
		fprintf(stderr, "PP: entering CONTENT\n");
#endif
		break;
            case XML_PARSER_ENTITY_DECL:
		fprintf(stderr, "PP: internal error, state == ENTITY_DECL\n");
		ctxt->instate = XML_PARSER_DTD;
#ifdef DEBUG_PUSH
		fprintf(stderr, "PP: entering DTD\n");
#endif
		break;
            case XML_PARSER_ENTITY_VALUE:
		fprintf(stderr, "PP: internal error, state == ENTITY_VALUE\n");
		ctxt->instate = XML_PARSER_CONTENT;
#ifdef DEBUG_PUSH
		fprintf(stderr, "PP: entering DTD\n");
#endif
		break;
            case XML_PARSER_ATTRIBUTE_VALUE:
		fprintf(stderr, "PP: internal error, state == ATTRIBUTE_VALUE\n");
		ctxt->instate = XML_PARSER_START_TAG;
#ifdef DEBUG_PUSH
		fprintf(stderr, "PP: entering START_TAG\n");
#endif
		break;
	}
    }
done:    
#ifdef DEBUG_PUSH
    fprintf(stderr, "PP: done %d\n", ret);
#endif
    return(ret);
}

/**
 * xmlOldParseChunk:
 * @ctxt:  an XML parser context
 * @chunk:  an char array
 * @size:  the size in byte of the chunk
 * @terminate:  last chunk indicator
 *
 * Parse a Chunk of memory
 *
 * Returns zero if no error, the xmlParserErrors otherwise.
 */
int
xmlOldParseChunk(xmlParserCtxtPtr ctxt, const char *chunk, int size,
              int terminate) {
    if ((size > 0) && (chunk != NULL) && (ctxt->input != NULL) &&
        (ctxt->input->buf != NULL) && (ctxt->instate != XML_PARSER_EOF))  {
	int base = ctxt->input->base - ctxt->input->buf->buffer->content;
	int cur = ctxt->input->cur - ctxt->input->base;
	
	xmlParserInputBufferPush(ctxt->input->buf, size, chunk);	      
	ctxt->input->base = ctxt->input->buf->buffer->content + base;
	ctxt->input->cur = ctxt->input->base + cur;
#ifdef DEBUG_PUSH
	fprintf(stderr, "PP: pushed %d\n", size);
#endif

	if ((terminate) || (ctxt->input->buf->buffer->use > 80))
	    xmlOldParseTryOrFinish(ctxt, terminate);
    } else if (ctxt->instate != XML_PARSER_EOF)
        xmlOldParseTryOrFinish(ctxt, terminate);
    if (terminate) {
	if ((ctxt->instate != XML_PARSER_EOF) &&
	    (ctxt->instate != XML_PARSER_EPILOG)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Extra content at the end of the document\n");
	    ctxt->wellFormed = 0;
	    ctxt->errNo = XML_ERR_DOCUMENT_END;
	} 
	if (ctxt->instate != XML_PARSER_EOF) {
	    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
		ctxt->sax->endDocument(ctxt->userData);
	}
	ctxt->instate = XML_PARSER_EOF;
    }
    return((xmlParserErrors) ctxt->errNo);	      
}

