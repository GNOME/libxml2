/*
 * parser.c : an XML 1.0 non-verifying parser
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

const char *xmlParserVersion = LIBXML_VERSION;

/*
 * List of XML prefixed PI allowed by W3C specs
 */

const char *xmlW3CPIs[] = {
    "xml-stylesheet",
    NULL
};

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

void check_buffer(xmlParserInputPtr in) {
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
 * xmlParserInputRead:
 * @in:  an XML parser input
 * @len:  an indicative size for the lookahead
 *
 * This function refresh the input for the parser. It doesn't try to
 * preserve pointers to the input buffer, and discard already read data
 *
 * Returns the number of xmlChars read, or -1 in case of error, 0 indicate the
 * end of this entity
 */
int
xmlParserInputRead(xmlParserInputPtr in, int len) {
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
 * xmlParserInputGrow:
 * @in:  an XML parser input
 * @len:  an indicative size for the lookahead
 *
 * This function increase the input for the parser. It tries to
 * preserve pointers to the input buffer, and keep already read data
 *
 * Returns the number of xmlChars read, or -1 in case of error, 0 indicate the
 * end of this entity
 */
int
xmlParserInputGrow(xmlParserInputPtr in, int len) {
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
    if ((in->buf->netIO != NULL) || (in->buf->file != NULL) ||
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
 * xmlParserInputShrink:
 * @in:  an XML parser input
 *
 * This function removes used input for the parser.
 */
void
xmlParserInputShrink(xmlParserInputPtr in) {
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

int xmlSubstituteEntitiesDefaultValue = 0;
int xmlDoValidityCheckingDefaultValue = 0;
xmlEntityPtr xmlParseStringEntityRef(xmlParserCtxtPtr ctxt,
                                     const xmlChar ** str);

/*
 * Generic function for accessing stacks in the Parser Context
 */

#define PUSH_AND_POP(scope, type, name)					\
scope int name##Push(xmlParserCtxtPtr ctxt, type value) {		\
    if (ctxt->name##Nr >= ctxt->name##Max) {				\
	ctxt->name##Max *= 2;						\
        ctxt->name##Tab = (void *) xmlRealloc(ctxt->name##Tab,		\
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
scope type name##Pop(xmlParserCtxtPtr ctxt) {				\
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

PUSH_AND_POP(extern, xmlParserInputPtr, input)
PUSH_AND_POP(extern, xmlNodePtr, node)
PUSH_AND_POP(extern, xmlChar*, name)

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

#define CUR (ctxt->token ? ctxt->token : (*ctxt->input->cur))
#define SKIP(val) ctxt->nbChars += (val),ctxt->input->cur += (val)
#define NXT(val) ctxt->input->cur[(val)]
#define CUR_PTR ctxt->input->cur
#define SHRINK  xmlParserInputShrink(ctxt->input);			\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))		\
	    xmlPopInput(ctxt)

#define GROW  xmlParserInputGrow(ctxt->input, INPUT_CHUNK);		\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))		\
	    xmlPopInput(ctxt)

#define SKIP_BLANKS 							\
    do { 								\
	while (IS_BLANK(CUR)) NEXT;					\
	while ((CUR == 0) && (ctxt->inputNr > 1))			\
	    xmlPopInput(ctxt);						\
	if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);	\
	if (*ctxt->input->cur == '&') xmlParserHandleReference(ctxt);	\
    } while (IS_BLANK(CUR));

#define CURRENT (*ctxt->input->cur)
#define NEXT {								\
    if (ctxt->token != 0) ctxt->token = 0;				\
    else {								\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0)) {		\
	    xmlPopInput(ctxt);						\
    } else {								\
        if (*(ctxt->input->cur) == '\n') {				\
	    ctxt->input->line++; ctxt->input->col = 1;			\
	} else ctxt->input->col++;					\
	ctxt->input->cur++;						\
	ctxt->nbChars++;						\
        if (*ctxt->input->cur == 0)					\
	    xmlParserInputGrow(ctxt->input, INPUT_CHUNK);		\
    }									\
    if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);	\
    if (*ctxt->input->cur == '&') xmlParserHandleReference(ctxt);	\
}}


/************************************************************************
 *									*
 *	Commodity functions to handle entities processing		*
 *									*
 ************************************************************************/

/**
 * xmlPopInput:
 * @ctxt:  an XML parser context
 *
 * xmlPopInput: the current input pointed by ctxt->input came to an end
 *          pop it and return the next char.
 *
 * Returns the current xmlChar in the parser context
 */
xmlChar
xmlPopInput(xmlParserCtxtPtr ctxt) {
    if (ctxt->inputNr == 1) return(0); /* End of main Input */
    xmlFreeInputStream(inputPop(ctxt));
    if ((*ctxt->input->cur == 0) &&
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))
	    return(xmlPopInput(ctxt));
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
 * xmlNewInputStream:
 * @ctxt:  an XML parser context
 *
 * Create a new input stream structure
 * Returns the new input stream or NULL
 */
xmlParserInputPtr
xmlNewInputStream(xmlParserCtxtPtr ctxt) {
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
 * xmlNewEntityInputStream:
 * @ctxt:  an XML parser context
 * @entity:  an Entity pointer
 *
 * Create a new input stream based on an xmlEntityPtr
 *
 * Returns the new input stream or NULL
 */
xmlParserInputPtr
xmlNewEntityInputStream(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
    xmlParserInputPtr input;

    if (entity == NULL) {
        ctxt->errNo = XML_ERR_INTERNAL_ERROR;
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	      "internal: xmlNewEntityInputStream entity = NULL\n");
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
    input = xmlNewInputStream(ctxt);
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
 * xmlNewStringInputStream:
 * @ctxt:  an XML parser context
 * @buffer:  an memory buffer
 *
 * Create a new input stream based on a memory buffer.
 * Returns the new input stream
 */
xmlParserInputPtr
xmlNewStringInputStream(xmlParserCtxtPtr ctxt, const xmlChar *buffer) {
    xmlParserInputPtr input;

    if (buffer == NULL) {
	ctxt->errNo = XML_ERR_INTERNAL_ERROR;
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	      "internal: xmlNewStringInputStream string = NULL\n");
	return(NULL);
    }
    input = xmlNewInputStream(ctxt);
    if (input == NULL) {
	return(NULL);
    }
    input->base = buffer;
    input->cur = buffer;
    input->length = xmlStrlen(buffer);
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

    inputStream = xmlNewInputStream(ctxt);
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
 *		Commodity functions to handle parser contexts		*
 *									*
 ************************************************************************/

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

    sax = (xmlSAXHandler *) xmlMalloc(sizeof(xmlSAXHandler));
    if (sax == NULL) {
        fprintf(stderr, "xmlInitParserCtxt: out of memory\n");
    }

    /* Allocate the Input stack */
    ctxt->inputTab = (xmlParserInputPtr *) xmlMalloc(5 * sizeof(xmlParserInputPtr));
    ctxt->inputNr = 0;
    ctxt->inputMax = 5;
    ctxt->input = NULL;
    ctxt->version = NULL;
    ctxt->encoding = NULL;
    ctxt->standalone = -1;
    ctxt->hasExternalSubset = 0;
    ctxt->hasPErefs = 0;
    ctxt->html = 0;
    ctxt->external = 0;
    ctxt->instate = XML_PARSER_START;
    ctxt->token = 0;
    ctxt->directory = NULL;

    /* Allocate the Node stack */
    ctxt->nodeTab = (xmlNodePtr *) xmlMalloc(10 * sizeof(xmlNodePtr));
    ctxt->nodeNr = 0;
    ctxt->nodeMax = 10;
    ctxt->node = NULL;

    /* Allocate the Name stack */
    ctxt->nameTab = (xmlChar **) xmlMalloc(10 * sizeof(xmlChar *));
    ctxt->nameNr = 0;
    ctxt->nameMax = 10;
    ctxt->name = NULL;

    if (sax == NULL) ctxt->sax = &xmlDefaultSAXHandler;
    else {
        ctxt->sax = sax;
	memcpy(sax, &xmlDefaultSAXHandler, sizeof(xmlSAXHandler));
    }
    ctxt->userData = ctxt;
    ctxt->myDoc = NULL;
    ctxt->wellFormed = 1;
    ctxt->valid = 1;
    ctxt->validate = xmlDoValidityCheckingDefaultValue;
    ctxt->vctxt.userData = ctxt;
    ctxt->vctxt.error = xmlParserValidityError;
    ctxt->vctxt.warning = xmlParserValidityWarning;
    ctxt->replaceEntities = xmlSubstituteEntitiesDefaultValue;
    ctxt->record_info = 0;
    ctxt->nbChars = 0;
    ctxt->checkIndex = 0;
    ctxt->errNo = XML_ERR_OK;
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
    xmlChar *oldname;

    if (ctxt == NULL) return;

    while ((input = inputPop(ctxt)) != NULL) {
        xmlFreeInputStream(input);
    }
    while ((oldname = namePop(ctxt)) != NULL) {
	xmlFree(oldname);
    }
    if (ctxt->nameTab != NULL) xmlFree(ctxt->nameTab);
    if (ctxt->nodeTab != NULL) xmlFree(ctxt->nodeTab);
    if (ctxt->inputTab != NULL) xmlFree(ctxt->inputTab);
    if (ctxt->version != NULL) xmlFree((char *) ctxt->version);
    if (ctxt->encoding != NULL) xmlFree((char *) ctxt->encoding);
    if ((ctxt->sax != NULL) && (ctxt->sax != &xmlDefaultSAXHandler))
        xmlFree(ctxt->sax);
    if (ctxt->directory != NULL) xmlFree((char *) ctxt->directory);
    xmlFree(ctxt);
}

/**
 * xmlNewParserCtxt:
 *
 * Allocate and initialize a new parser context.
 *
 * Returns the xmlParserCtxtPtr or NULL
 */

xmlParserCtxtPtr
xmlNewParserCtxt()
{
    xmlParserCtxtPtr ctxt;

    ctxt = (xmlParserCtxtPtr) xmlMalloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        fprintf(stderr, "xmlNewParserCtxt : cannot allocate context\n");
        perror("malloc");
	return(NULL);
    }
    xmlInitParserCtxt(ctxt);
    return(ctxt);
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

/************************************************************************
 *									*
 *		Commodity functions to handle entities			*
 *									*
 ************************************************************************/

void xmlParserHandleReference(xmlParserCtxtPtr ctxt);
void xmlParserHandlePEReference(xmlParserCtxtPtr ctxt);
xmlEntityPtr xmlParseStringPEReference(xmlParserCtxtPtr ctxt,
                                       const xmlChar **str);

/**
 * xmlParseCharRef:
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
int
xmlParseCharRef(xmlParserCtxtPtr ctxt) {
    int val = 0;

    if (ctxt->token != 0) {
fprintf(stderr, "xmlParseCharRef : ctxt->token != 0\n");    
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
 * xmlParseStringCharRef:
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
int
xmlParseStringCharRef(xmlParserCtxtPtr ctxt, const xmlChar **str) {
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
    } else if  ((cur = '&') && (ptr[1] == '#')){
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
 * xmlParserHandleReference:
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
void
xmlParserHandleReference(xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr input;
    xmlChar *name;
    xmlEntityPtr ent = NULL;

    if (ctxt->token != 0) {
fprintf(stderr, "xmlParserHandleReference : ctxt->token != 0\n");
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
		 *       This will be handled by xmlDecodeEntities
		 */
		return;
	    case XML_PARSER_CONTENT:
	    case XML_PARSER_ATTRIBUTE_VALUE:
	        /* !!! this may not be Ok for UTF-8, multibyte sequence */
		ctxt->token = xmlParseCharRef(ctxt);
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
	     *       This will be handled by xmlDecodeEntities
	     */
	    return;
        case XML_PARSER_ATTRIBUTE_VALUE:
	    /*
	     * NOTE: in the case of attributes values, we don't do the
	     *       substitution here unless we are in a mode where
	     *       the parser is explicitely asked to substitute
	     *       entities. The SAX callback is called with values
	     *       without entity substitution.
	     *       This will then be handled by xmlDecodeEntities
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
    name = xmlScanName(ctxt);
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
    input = xmlNewEntityInputStream(ctxt, ent);
    xmlPushInput(ctxt, input);
    xmlFree(name);
    return;
}

/**
 * xmlParserHandlePEReference:
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
void
xmlParserHandlePEReference(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEntityPtr entity = NULL;
    xmlParserInputPtr input;

    if (ctxt->token != 0) {
fprintf(stderr, "xmlParserHandlePEReference : ctxt->token != 0\n");
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
	     *       This will be handled by xmlDecodeEntities
	     */
	    return;
        case XML_PARSER_DTD:
	    /*
	     * [WFC: Well-Formedness Constraint: PEs in Internal Subset]
	     * In the internal DTD subset, parameter-entity references
	     * can occur only where markup declarations can occur, not
	     * within markup declarations.
	     * In that case this is handled in xmlParseMarkupDecl
	     */
	    if ((ctxt->external == 0) && (ctxt->inputNr == 1))
		return;
    }

    NEXT;
    name = xmlParseName(ctxt);
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
		    input = xmlNewEntityInputStream(ctxt, entity);
		    xmlPushInput(ctxt, input);
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
    buffer = (xmlChar *) xmlRealloc(buffer, buffer##_size * sizeof(xmlChar));	\
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
xmlChar *
xmlDecodeEntities(xmlParserCtxtPtr ctxt, int len, int what,
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
	    int val = xmlParseCharRef(ctxt);
	    *out++ = val;
	    nbchars += 3; 
	} else if ((cur == '&') && (what & XML_SUBSTITUTE_REF)) {
	    ent = xmlParseEntityRef(ctxt);
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

	    xmlParsePEReference(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

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
 * xmlStringDecodeEntities:
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
xmlChar *
xmlStringDecodeEntities(xmlParserCtxtPtr ctxt, const xmlChar *str, int what,
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
	perror("xmlDecodeEntities: malloc failed");
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
	    int val = xmlParseStringCharRef(ctxt, &str);
	    if (val != 0)
		*out++ = val;
	} else if ((cur == '&') && (what & XML_SUBSTITUTE_REF)) {
	    ent = xmlParseStringEntityRef(ctxt, &str);
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
	    ent = xmlParseStringPEReference(ctxt, &str);
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
 *		Commodity functions to handle encodings			*
 *									*
 ************************************************************************/

/**
 * xmlSwitchEncoding:
 * @ctxt:  the parser context
 * @enc:  the encoding value (number)
 *
 * change the input functions when discovering the character encoding
 * of a given entity.
 */
void
xmlSwitchEncoding(xmlParserCtxtPtr ctxt, xmlCharEncoding enc)
{
    switch (enc) {
        case XML_CHAR_ENCODING_ERROR:
	    ctxt->errNo = XML_ERR_UNKNOWN_ENCODING;
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
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UTF16 little endian not supported\n");
            break;
        case XML_CHAR_ENCODING_UTF16BE:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UTF16 big endian not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4LE:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding USC4 little endian not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4BE:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding USC4 big endian not supported\n");
            break;
        case XML_CHAR_ENCODING_EBCDIC:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding EBCDIC not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4_2143:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UCS4 2143 not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS4_3412:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UCS4 3412 not supported\n");
            break;
        case XML_CHAR_ENCODING_UCS2:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding UCS2 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_1:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_1 ISO Latin 1 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_2:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_2 ISO Latin 2 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_3:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_3 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_4:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_4 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_5:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_5 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_6:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_6 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_7:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_7 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_8:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_8 not supported\n");
            break;
        case XML_CHAR_ENCODING_8859_9:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
		  "char encoding ISO_8859_9 not supported\n");
            break;
        case XML_CHAR_ENCODING_2022_JP:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
                  "char encoding ISO-2022-JPnot supported\n");
            break;
        case XML_CHAR_ENCODING_SHIFT_JIS:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
                  "char encoding Shift_JISnot supported\n");
            break;
        case XML_CHAR_ENCODING_EUC_JP:
	    ctxt->errNo = XML_ERR_UNSUPPORTED_ENCODING;
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
                ctxt->sax->error(ctxt->userData,
                  "char encoding EUC-JPnot supported\n");
            break;
    }
}

/************************************************************************
 *									*
 *		Commodity functions to handle xmlChars			*
 *									*
 ************************************************************************/

/**
 * xmlStrndup:
 * @cur:  the input xmlChar *
 * @len:  the len of @cur
 *
 * a strndup for array of xmlChar's
 *
 * Returns a new xmlChar * or NULL
 */
xmlChar *
xmlStrndup(const xmlChar *cur, int len) {
    xmlChar *ret;
    
    if ((cur == NULL) || (len < 0)) return(NULL);
    ret = xmlMalloc((len + 1) * sizeof(xmlChar));
    if (ret == NULL) {
        fprintf(stderr, "malloc of %ld byte failed\n",
	        (len + 1) * (long)sizeof(xmlChar));
        return(NULL);
    }
    memcpy(ret, cur, len * sizeof(xmlChar));
    ret[len] = 0;
    return(ret);
}

/**
 * xmlStrdup:
 * @cur:  the input xmlChar *
 *
 * a strdup for array of xmlChar's
 *
 * Returns a new xmlChar * or NULL
 */
xmlChar *
xmlStrdup(const xmlChar *cur) {
    const xmlChar *p = cur;

    if (cur == NULL) return(NULL);
    while (IS_CHAR(*p)) p++;
    return(xmlStrndup(cur, p - cur));
}

/**
 * xmlCharStrndup:
 * @cur:  the input char *
 * @len:  the len of @cur
 *
 * a strndup for char's to xmlChar's
 *
 * Returns a new xmlChar * or NULL
 */

xmlChar *
xmlCharStrndup(const char *cur, int len) {
    int i;
    xmlChar *ret;
    
    if ((cur == NULL) || (len < 0)) return(NULL);
    ret = xmlMalloc((len + 1) * sizeof(xmlChar));
    if (ret == NULL) {
        fprintf(stderr, "malloc of %ld byte failed\n",
	        (len + 1) * (long)sizeof(xmlChar));
        return(NULL);
    }
    for (i = 0;i < len;i++)
        ret[i] = (xmlChar) cur[i];
    ret[len] = 0;
    return(ret);
}

/**
 * xmlCharStrdup:
 * @cur:  the input char *
 * @len:  the len of @cur
 *
 * a strdup for char's to xmlChar's
 *
 * Returns a new xmlChar * or NULL
 */

xmlChar *
xmlCharStrdup(const char *cur) {
    const char *p = cur;

    if (cur == NULL) return(NULL);
    while (*p != '\0') p++;
    return(xmlCharStrndup(cur, p - cur));
}

/**
 * xmlStrcmp:
 * @str1:  the first xmlChar *
 * @str2:  the second xmlChar *
 *
 * a strcmp for xmlChar's
 *
 * Returns the integer result of the comparison
 */

int
xmlStrcmp(const xmlChar *str1, const xmlChar *str2) {
    register int tmp;

    if ((str1 == NULL) && (str2 == NULL)) return(0);
    if (str1 == NULL) return(-1);
    if (str2 == NULL) return(1);
    do {
        tmp = *str1++ - *str2++;
	if (tmp != 0) return(tmp);
    } while ((*str1 != 0) && (*str2 != 0));
    return (*str1 - *str2);
}

/**
 * xmlStrncmp:
 * @str1:  the first xmlChar *
 * @str2:  the second xmlChar *
 * @len:  the max comparison length
 *
 * a strncmp for xmlChar's
 *
 * Returns the integer result of the comparison
 */

int
xmlStrncmp(const xmlChar *str1, const xmlChar *str2, int len) {
    register int tmp;

    if (len <= 0) return(0);
    if ((str1 == NULL) && (str2 == NULL)) return(0);
    if (str1 == NULL) return(-1);
    if (str2 == NULL) return(1);
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
 * @str:  the xmlChar * array
 * @val:  the xmlChar to search
 *
 * a strchr for xmlChar's
 *
 * Returns the xmlChar * for the first occurence or NULL.
 */

const xmlChar *
xmlStrchr(const xmlChar *str, xmlChar val) {
    if (str == NULL) return(NULL);
    while (*str != 0) {
        if (*str == val) return((xmlChar *) str);
	str++;
    }
    return(NULL);
}

/**
 * xmlStrstr:
 * @str:  the xmlChar * array (haystack)
 * @val:  the xmlChar to search (needle)
 *
 * a strstr for xmlChar's
 *
 * Returns the xmlChar * for the first occurence or NULL.
 */

const xmlChar *
xmlStrstr(const xmlChar *str, xmlChar *val) {
    int n;
    
    if (str == NULL) return(NULL);
    if (val == NULL) return(NULL);
    n = xmlStrlen(val);

    if (n == 0) return(str);
    while (*str != 0) {
        if (*str == *val) {
	    if (!xmlStrncmp(str, val, n)) return((const xmlChar *) str);
	}
	str++;
    }
    return(NULL);
}

/**
 * xmlStrsub:
 * @str:  the xmlChar * array (haystack)
 * @start:  the index of the first char (zero based)
 * @len:  the length of the substring
 *
 * Extract a substring of a given string
 *
 * Returns the xmlChar * for the first occurence or NULL.
 */

xmlChar *
xmlStrsub(const xmlChar *str, int start, int len) {
    int i;
    
    if (str == NULL) return(NULL);
    if (start < 0) return(NULL);
    if (len < 0) return(NULL);

    for (i = 0;i < start;i++) {
        if (*str == 0) return(NULL);
	str++;
    }
    if (*str == 0) return(NULL);
    return(xmlStrndup(str, len));
}

/**
 * xmlStrlen:
 * @str:  the xmlChar * array
 *
 * length of a xmlChar's string
 *
 * Returns the number of xmlChar contained in the ARRAY.
 */

int
xmlStrlen(const xmlChar *str) {
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
 * @cur:  the original xmlChar * array
 * @add:  the xmlChar * array added
 * @len:  the length of @add
 *
 * a strncat for array of xmlChar's
 *
 * Returns a new xmlChar * containing the concatenated string.
 */

xmlChar *
xmlStrncat(xmlChar *cur, const xmlChar *add, int len) {
    int size;
    xmlChar *ret;

    if ((add == NULL) || (len == 0))
        return(cur);
    if (cur == NULL)
        return(xmlStrndup(add, len));

    size = xmlStrlen(cur);
    ret = xmlRealloc(cur, (size + len + 1) * sizeof(xmlChar));
    if (ret == NULL) {
        fprintf(stderr, "xmlStrncat: realloc of %ld byte failed\n",
	        (size + len + 1) * (long)sizeof(xmlChar));
        return(cur);
    }
    memcpy(&ret[size], add, len * sizeof(xmlChar));
    ret[size + len] = 0;
    return(ret);
}

/**
 * xmlStrcat:
 * @cur:  the original xmlChar * array
 * @add:  the xmlChar * array added
 *
 * a strcat for array of xmlChar's
 *
 * Returns a new xmlChar * containing the concatenated string.
 */
xmlChar *
xmlStrcat(xmlChar *cur, const xmlChar *add) {
    const xmlChar *p = add;

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
 * @str:  a xmlChar *
 * @len:  the size of @str
 *
 * Is this a sequence of blank chars that one can ignore ?
 *
 * Returns 1 if ignorable 0 otherwise.
 */

static int areBlanks(xmlParserCtxtPtr ctxt, const xmlChar *str, int len) {
    int i, ret;
    xmlNodePtr lastChild;

    for (i = 0;i < len;i++)
        if (!(IS_BLANK(str[i]))) return(0);

    if (CUR != '<') return(0);
    if (ctxt->node == NULL) return(0);
    if (ctxt->myDoc != NULL) {
	ret = xmlIsMixedElement(ctxt->myDoc, ctxt->node->name);
        if (ret == 0) return(1);
        if (ret == 1) return(0);
    }
    /*
     * heuristic
     */
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
 * xmlHandleEntity:
 * @ctxt:  an XML parser context
 * @entity:  an XML entity pointer.
 *
 * Default handling of defined entities, when should we define a new input
 * stream ? When do we just handle that as a set of chars ?
 *
 * OBSOLETE: to be removed at some point.
 */

void
xmlHandleEntity(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
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

xmlChar *
xmlNamespaceParseNCName(xmlParserCtxtPtr ctxt) {
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
 * xmlNamespaceParseQName:
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

xmlChar *
xmlNamespaceParseQName(xmlParserCtxtPtr ctxt, xmlChar **prefix) {
    xmlChar *ret = NULL;

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
 * @prefix:  a xmlChar ** 
 *
 * parse an XML qualified name string
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

xmlChar *
xmlSplitQName(const xmlChar *name, xmlChar **prefix) {
    xmlChar *ret = NULL;
    const xmlChar *q;
    const xmlChar *cur = name;

    *prefix = NULL;

    /* xml: prefix is not really a namespace */
    if ((cur[0] == 'x') && (cur[1] == 'm') &&
        (cur[2] == 'l') && (cur[3] == ':'))
	return(xmlStrdup(name));

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

xmlChar *
xmlNamespaceParseNSDef(xmlParserCtxtPtr ctxt) {
    xmlChar *name = NULL;

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
 * To be removed at next drop of binary compatibility
 *
 * Returns the string parser or NULL.
 */
xmlChar *
xmlParseQuotedString(xmlParserCtxtPtr ctxt) {
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
 * xmlParseNamespace:
 * @ctxt:  an XML parser context
 *
 * [OLD] xmlParseNamespace: parse specific PI '<?namespace ...' constructs.
 *
 * This is what the older xml-name Working Draft specified, a bunch of
 * other stuff may still rely on it, so support is still here as
 * if it was declared on the root of the Tree:-(
 *
 * To be removed at next drop of binary compatibility
 */

void
xmlParseNamespace(xmlParserCtxtPtr ctxt) {
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
 * xmlScanName:
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

xmlChar *
xmlScanName(xmlParserCtxtPtr ctxt) {
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

xmlChar *
xmlParseName(xmlParserCtxtPtr ctxt) {
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
 * xmlParseStringName:
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

xmlChar *
xmlParseStringName(xmlParserCtxtPtr ctxt, const xmlChar** str) {
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

xmlChar *
xmlParseNmtoken(xmlParserCtxtPtr ctxt) {
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

xmlChar *
xmlParseEntityValue(xmlParserCtxtPtr ctxt, xmlChar **orig) {
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
	    xmlPopInput(ctxt);
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
	ret = xmlStringDecodeEntities(ctxt, buf, XML_SUBSTITUTE_PEREF,
				      0, 0, 0);
	if (orig != NULL) 
	    *orig = buf;
	else
	    xmlFree(buf);
    }
    
    return(ret);
}

/**
 * xmlParseAttValue:
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

xmlChar *
xmlParseAttValue(xmlParserCtxtPtr ctxt) {
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
    while ((cur != limit) && (cur != '<')) {
	if (cur == 0) break;
        if ((cur == '&') && (NXT(1) == '#')) {
	    int val = xmlParseCharRef(ctxt);
	    *out++ = val;
	} else if (cur == '&') {
	    ent = xmlParseEntityRef(ctxt);
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
		if (out - buffer > buffer_size - i - 10) {
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
	    if ((cur == 0x20) || (cur == 0xD) || (cur == 0xA) || (cur == 0x9)) {
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
 * xmlParseSystemLiteral:
 * @ctxt:  an XML parser context
 * 
 * parse an XML Literal
 *
 * [11] SystemLiteral ::= ('"' [^"]* '"') | ("'" [^']* "'")
 *
 * Returns the SystemLiteral parsed or NULL
 */

xmlChar *
xmlParseSystemLiteral(xmlParserCtxtPtr ctxt) {
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
 * xmlParsePubidLiteral:
 * @ctxt:  an XML parser context
 *
 * parse an XML public literal
 *
 * [12] PubidLiteral ::= '"' PubidChar* '"' | "'" (PubidChar - "'")* "'"
 *
 * Returns the PubidLiteral parsed or NULL.
 */

xmlChar *
xmlParsePubidLiteral(xmlParserCtxtPtr ctxt) {
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
    xmlChar buf[XML_PARSER_BIG_BUFFER_SIZE];
    int nbchar = 0;
    xmlChar cur;

    SHRINK;
    cur = CUR;
    while ((IS_CHAR(cur)) && (cur != '<') &&
           (cur != '&')) {
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
		if (areBlanks(ctxt, buf, nbchar)) {
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
	    if (areBlanks(ctxt, buf, nbchar)) {
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
 * xmlParseExternalID:
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

xmlChar *
xmlParseExternalID(xmlParserCtxtPtr ctxt, xmlChar **publicID, int strict) {
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
	URI = xmlParseSystemLiteral(ctxt);
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
	*publicID = xmlParsePubidLiteral(ctxt);
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
	URI = xmlParseSystemLiteral(ctxt);
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
 * xmlParseComment:
 * @ctxt:  an XML parser context
 *
 * Skip an XML (SGML) comment <!-- .... -->
 *  The spec says that "For compatibility, the string "--" (double-hyphen)
 *  must not occur within comments. "
 *
 * [15] Comment ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
 */
void
xmlParseComment(xmlParserCtxtPtr ctxt) {
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
 * xmlParsePITarget:
 * @ctxt:  an XML parser context
 * 
 * parse the name of a PI
 *
 * [17] PITarget ::= Name - (('X' | 'x') ('M' | 'm') ('L' | 'l'))
 *
 * Returns the PITarget name or NULL
 */

xmlChar *
xmlParsePITarget(xmlParserCtxtPtr ctxt) {
    xmlChar *name;

    name = xmlParseName(ctxt);
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
        target = xmlParsePITarget(ctxt);
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

        name = xmlParseName(ctxt);
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
	    ctxt->errNo = XML_ERR_NOTATION_NOT_FINISHED;
	    ctxt->wellFormed = 0;
	}
	xmlFree(name);
	if (Systemid != NULL) xmlFree(Systemid);
	if (Pubid != NULL) xmlFree(Pubid);
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
 *
 * [ VC: Notation Declared ]
 * The Name must match the declared name of a notation.
 */

void
xmlParseEntityDecl(xmlParserCtxtPtr ctxt) {
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

        name = xmlParseName(ctxt);
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
		    ndata = xmlParseName(ctxt);
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
 * xmlParseDefaultDecl:
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
 * handled in xmlParseAttValue()
 *
 * returns: XML_ATTRIBUTE_NONE, XML_ATTRIBUTE_REQUIRED, XML_ATTRIBUTE_IMPLIED
 *          or XML_ATTRIBUTE_FIXED. 
 */

int
xmlParseDefaultDecl(xmlParserCtxtPtr ctxt, xmlChar **value) {
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
    ret = xmlParseAttValue(ctxt);
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
 * xmlParseNotationType:
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

xmlEnumerationPtr
xmlParseNotationType(xmlParserCtxtPtr ctxt) {
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
        name = xmlParseName(ctxt);
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
 * xmlParseEnumerationType:
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

xmlEnumerationPtr
xmlParseEnumerationType(xmlParserCtxtPtr ctxt) {
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
        name = xmlParseNmtoken(ctxt);
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
	        ctxt->sax->error(ctxt->userData,
		                 "Space required after 'NOTATION'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
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
int 
xmlParseAttributeType(xmlParserCtxtPtr ctxt, xmlEnumerationPtr *tree) {
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
        elemName = xmlParseName(ctxt);
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
	    attrName = xmlParseName(ctxt);
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

	    type = xmlParseAttributeType(ctxt, &tree);
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

	    def = xmlParseDefaultDecl(ctxt, &defaultValue);
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
 * xmlParseElementMixedContentDecl:
 * @ctxt:  an XML parser context
 *
 * parse the declaration for a Mixed Element content
 * The leading '(' and spaces have been skipped in xmlParseElementContentDecl
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
xmlElementContentPtr
xmlParseElementMixedContentDecl(xmlParserCtxtPtr ctxt) {
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
	    elem = xmlParseName(ctxt);
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
xmlElementContentPtr
xmlParseElementChildrenContentDecl(xmlParserCtxtPtr ctxt) {
    xmlElementContentPtr ret = NULL, cur = NULL, last = NULL, op = NULL;
    xmlChar *elem;
    xmlChar type = 0;

    SKIP_BLANKS;
    GROW;
    if (CUR == '(') {
        /* Recurse on first child */
	NEXT;
	SKIP_BLANKS;
        cur = ret = xmlParseElementChildrenContentDecl(ctxt);
	SKIP_BLANKS;
	GROW;
    } else {
	elem = xmlParseName(ctxt);
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
	    last = xmlParseElementChildrenContentDecl(ctxt);
	    SKIP_BLANKS;
	} else {
	    elem = xmlParseName(ctxt);
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
xmlParseElementContentDecl(xmlParserCtxtPtr ctxt, xmlChar *name,
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
 * [ VC: Unique Element Type Declaration ]
 * No element type may be declared more than once
 *
 * Returns the type of the element, or -1 in case of error
 */
int
xmlParseElementDecl(xmlParserCtxtPtr ctxt) {
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
        name = xmlParseName(ctxt);
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
	    ret = xmlParseElementContentDecl(ctxt, name, &content);
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
	    xmlPopInput(ctxt);
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
 * xmlParseMarkupDecl:
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
void
xmlParseMarkupDecl(xmlParserCtxtPtr ctxt) {
    GROW;
    xmlParseElementDecl(ctxt);
    xmlParseAttributeListDecl(ctxt);
    xmlParseEntityDecl(ctxt);
    xmlParseNotationDecl(ctxt);
    xmlParsePI(ctxt);
    xmlParseComment(ctxt);
    /*
     * This is only for internal subset. On external entities,
     * the replacement is done before parsing stage
     */
    if ((ctxt->external == 0) && (ctxt->inputNr == 1))
	xmlParsePEReference(ctxt);
    ctxt->instate = XML_PARSER_DTD;
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

xmlChar *
xmlParseTextDecl(xmlParserCtxtPtr ctxt) {
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
    version = xmlParseVersionInfo(ctxt);
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
    encoding = xmlParseEncodingDecl(ctxt);

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
    while ((CUR != 0) && ((CUR != ']') || (NXT(1) != ']') || (NXT(2) != '>'))) {
	NEXT;
	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);

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
 * xmlParseExternalSubset:
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
xmlParseExternalSubset(xmlParserCtxtPtr ctxt, const xmlChar *ExternalID,
                       const xmlChar *SystemID) {
    GROW;
    if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l')) {
	xmlChar *decl;

	decl = xmlParseTextDecl(ctxt);
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
    xmlChar *val;
    if (CUR != '&') return;

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
    if (NXT(1) == '#') {
	xmlChar out[2];
	int val = xmlParseCharRef(ctxt);
	/* invalid for UTF-8 variable encoding !!!!! */
	out[0] = val;
	out[1] = 0;
	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	    ctxt->sax->characters(ctxt->userData, out, 1);
    } else {
	ent = xmlParseEntityRef(ctxt);
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

		input = xmlNewEntityInputStream(ctxt, ent);
		xmlPushInput(ctxt, input);
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
 * xmlParseEntityRef:
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
xmlEntityPtr
xmlParseEntityRef(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEntityPtr ent = NULL;

    GROW;
    
    if (CUR == '&') {
        NEXT;
        name = xmlParseName(ctxt);
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
 * xmlParseStringEntityRef:
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
xmlEntityPtr
xmlParseStringEntityRef(xmlParserCtxtPtr ctxt, const xmlChar ** str) {
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
        name = xmlParseStringName(ctxt, &ptr);
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
 * xmlParsePEReference:
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
void
xmlParsePEReference(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlEntityPtr entity = NULL;
    xmlParserInputPtr input;

    if (CUR == '%') {
        NEXT;
        name = xmlParseName(ctxt);
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
			input = xmlNewEntityInputStream(ctxt, entity);
			xmlPushInput(ctxt, input);
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
 * xmlParseStringPEReference:
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
xmlEntityPtr
xmlParseStringPEReference(xmlParserCtxtPtr ctxt, const xmlChar **str) {
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
        name = xmlParseStringName(ctxt, &ptr);
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
 * xmlParseDocTypeDecl :
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

void
xmlParseDocTypeDecl(xmlParserCtxtPtr ctxt) {
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
    name = xmlParseName(ctxt);
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
    URI = xmlParseExternalID(ctxt, &ExternalID, 1);

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
     * they are handled separately in xmlParseInternalSubset()
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
 * xmlParseInternalsubset :
 * @ctxt:  an XML parser context
 *
 * parse the internal subset declaration
 *
 * [28 end] ('[' (markupdecl | PEReference | S)* ']' S?)? '>'
 */

void
xmlParseInternalSubset(xmlParserCtxtPtr ctxt) {
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
	    xmlParseMarkupDecl(ctxt);
	    xmlParsePEReference(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

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
 * xmlParseAttribute:
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

xmlChar *
xmlParseAttribute(xmlParserCtxtPtr ctxt, xmlChar **value) {
    xmlChar *name, *val;

    *value = NULL;
    name = xmlParseName(ctxt);
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
	val = xmlParseAttValue(ctxt);
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
 * xmlParseStartTag:
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

xmlChar *
xmlParseStartTag(xmlParserCtxtPtr ctxt) {
    xmlChar *name;
    xmlChar *attname;
    xmlChar *attvalue;
    const xmlChar **atts = NULL;
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

	attname = xmlParseAttribute(ctxt, &attvalue);
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
 * xmlParseEndTag:
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

void
xmlParseEndTag(xmlParserCtxtPtr ctxt) {
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

    name = xmlParseName(ctxt);

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
    if (xmlStrcmp(name, ctxt->name)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	     "Opening and ending tag mismatch: %s and %s\n", ctxt->name, name);

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
    oldname = namePop(ctxt);
    if (oldname != NULL) {
#ifdef DEBUG_STACK
	fprintf(stderr,"Close: popped %s\n", oldname);
#endif
	xmlFree(oldname);
    }
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
 * xmlParseContent:
 * @ctxt:  an XML parser context
 *
 * Parse a content:
 *
 * [43] content ::= (element | CharData | Reference | CDSect | PI | Comment)*
 */

void
xmlParseContent(xmlParserCtxtPtr ctxt) {
    GROW;
    while ((CUR != '<') || (NXT(1) != '/')) {
	const xmlChar *test = CUR_PTR;
	int cons = ctxt->input->consumed;
	xmlChar tok = ctxt->token;

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
	    xmlParseComment(ctxt);
	    ctxt->instate = XML_PARSER_CONTENT;
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

	GROW;
	/*
	 * Pop-up of finished entities.
	 */
	while ((CUR == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);
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
 * xmlParseElement:
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

void
xmlParseElement(xmlParserCtxtPtr ctxt) {
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

    name = xmlParseStartTag(ctxt);
    if (name == NULL) {
        return;
    }
    namePush(ctxt, name);
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
	oldname = namePop(ctxt);
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
	nodePop(ctxt);
	oldname = namePop(ctxt);
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
    xmlParseContent(ctxt);
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	         "Premature end of data in tag %.30s\n", openTag);
	ctxt->wellFormed = 0;
	ctxt->errNo = XML_ERR_TAG_NOT_FINISED;

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);
	oldname = namePop(ctxt);
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
    xmlParseEndTag(ctxt);

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
 * xmlParseVersionNum:
 * @ctxt:  an XML parser context
 *
 * parse the XML version value.
 *
 * [26] VersionNum ::= ([a-zA-Z0-9_.:] | '-')+
 *
 * Returns the string giving the XML version number, or NULL
 */
xmlChar *
xmlParseVersionNum(xmlParserCtxtPtr ctxt) {
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

xmlChar *
xmlParseVersionInfo(xmlParserCtxtPtr ctxt) {
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
	    version = xmlParseVersionNum(ctxt);
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
	    version = xmlParseVersionNum(ctxt);
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
 * xmlParseEncName:
 * @ctxt:  an XML parser context
 *
 * parse the XML encoding name
 *
 * [81] EncName ::= [A-Za-z] ([A-Za-z0-9._] | '-')*
 *
 * Returns the encoding name value or NULL
 */
xmlChar *
xmlParseEncName(xmlParserCtxtPtr ctxt) {
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

xmlChar *
xmlParseEncodingDecl(xmlParserCtxtPtr ctxt) {
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
	    encoding = xmlParseEncName(ctxt);
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
	    encoding = xmlParseEncName(ctxt);
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
 * xmlParseSDDecl:
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
 * xmlParseXMLDecl:
 * @ctxt:  an XML parser context
 * 
 * parse an XML declaration header
 *
 * [23] XMLDecl ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
 */

void
xmlParseXMLDecl(xmlParserCtxtPtr ctxt) {
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
    version = xmlParseVersionInfo(ctxt);
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
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
    }
    SKIP_BLANKS;
    ctxt->standalone = xmlParseSDDecl(ctxt);

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
	    xmlParseComment(ctxt);
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

    GROW;

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
	xmlParseXMLDecl(ctxt);
	SKIP_BLANKS;
    } else if ((CUR == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'X') && (NXT(3) == 'M') &&
	(NXT(4) == 'L') && (IS_BLANK(NXT(5)))) {
	/*
	 * The first drafts were using <?XML and the final W3C REC
	 * now use <?xml ...
	 */
	xmlParseXMLDecl(ctxt);
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
    xmlParseMisc(ctxt);

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
	xmlParseDocTypeDecl(ctxt);
	if (CUR == '[') {
	    ctxt->instate = XML_PARSER_DTD;
	    xmlParseInternalSubset(ctxt);
	}
	ctxt->instate = XML_PARSER_PROLOG;
	xmlParseMisc(ctxt);
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
	xmlParseElement(ctxt);
	ctxt->instate = XML_PARSER_EPILOG;


	/*
	 * The Misc part at the end
	 */
	xmlParseMisc(ctxt);

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
 * xmlParseLookupSequence:
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
int
xmlParseLookupSequence(xmlParserCtxtPtr ctxt, xmlChar first,
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
 * xmlParseTryOrFinish:
 * @ctxt:  an XML parser context
 * @terminate:  last chunk indicator
 *
 * Try to progress on parsing
 *
 * Returns zero if no parsing was possible
 */
int
xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
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
	    xmlPopInput(ctxt);

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
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
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
			xmlParseXMLDecl(ctxt);
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
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlParseComment(ctxt);
		    ctxt->instate = XML_PARSER_MISC;
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == 'D') && (in->cur[3] == 'O') &&
		    (in->cur[4] == 'C') && (in->cur[5] == 'T') &&
		    (in->cur[6] == 'Y') && (in->cur[7] == 'P') &&
		    (in->cur[8] == 'E')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '>', 0, 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing internal subset\n");
#endif
		    xmlParseDocTypeDecl(ctxt);
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
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlParseComment(ctxt);
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
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlParsePI(ctxt);
		    ctxt->instate = XML_PARSER_EPILOG;
		} else if ((cur == '<') && (next == '!') &&
		    (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlParseComment(ctxt);
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
		    (xmlParseLookupSequence(ctxt, '>', 0, 0) < 0))
		    goto done;
		name = xmlParseStartTag(ctxt);
		if (name == NULL) {
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
			ctxt->sax->endDocument(ctxt->userData);
		    goto done;
		}
		namePush(ctxt, xmlStrdup(name));

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
		    oldname = namePop(ctxt);
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
		    nodePop(ctxt);
		    oldname = namePop(ctxt);
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
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		           (in->cur[2] == '-') && (in->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlParseComment(ctxt);
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
		        (xmlParseLookupSequence(ctxt, ';', 0, 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Reference\n");
#endif
		    /* TODO: check generation of subtrees if noent !!! */
		    xmlParseReference(ctxt);
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
			    (xmlParseLookupSequence(ctxt, '<', 0, 0) < 0))
			    goto done;
                    }
		    ctxt->checkIndex = 0;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing char data\n");
#endif
		    xmlParseCharData(ctxt, 0);
		}
		/*
		 * Pop-up of finished entities.
		 */
		while ((CUR == 0) && (ctxt->inputNr > 1))
		    xmlPopInput(ctxt);
		break;
            case XML_PARSER_CDATA_SECTION: {
	        /*
		 * The Push mode need to have the SAX callback for 
		 * cdataBlock merge back contiguous callbacks.
		 */
		int base;

		in = ctxt->input;
		base = xmlParseLookupSequence(ctxt, ']', ']', '>');
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
		    (xmlParseLookupSequence(ctxt, '>', 0, 0) < 0))
		    goto done;
		xmlParseEndTag(ctxt);
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
		xmlParseInternalSubset(ctxt);
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
 * xmlParseTry:
 * @ctxt:  an XML parser context
 *
 * Try to progress on parsing
 *
 * Returns zero if no parsing was possible
 */
int
xmlParseTry(xmlParserCtxtPtr ctxt) {
    return(xmlParseTryOrFinish(ctxt, 0));
}

/**
 * xmlParseChunk:
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
xmlParseChunk(xmlParserCtxtPtr ctxt, const char *chunk, int size,
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

        xmlParseTryOrFinish(ctxt, terminate);
    } else if (ctxt->instate != XML_PARSER_EOF)
        xmlParseTryOrFinish(ctxt, terminate);
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

/************************************************************************
 *									*
 * 		I/O front end functions to the parser			*
 *									*
 ************************************************************************/

/**
 * xmlCreatePushParserCtxt :
 * @sax:  a SAX handler
 * @user_data:  The user data returned on SAX callbacks
 * @chunk:  a pointer to an array of chars
 * @size:  number of chars in the array
 * @filename:  an optional file name or URI
 *
 * Create a parser context for using the XML parser in push mode
 * To allow content encoding detection, @size should be >= 4
 * The value of @filename is used for fetching external entities
 * and error/warning reports.
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreatePushParserCtxt(xmlSAXHandlerPtr sax, void *user_data, 
                        const char *chunk, int size, const char *filename) {
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr inputStream;
    xmlParserInputBufferPtr buf;
    xmlCharEncoding enc = XML_CHAR_ENCODING_NONE;

    /*
     * plug some encoding conversion routines here. !!!
     */
    if ((chunk != NULL) && (size >= 4))
	enc = xmlDetectCharEncoding((const xmlChar *) chunk);

    buf = xmlAllocParserInputBuffer(enc);
    if (buf == NULL) return(NULL);

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	xmlFree(buf);
	return(NULL);
    }
    if (sax != NULL) {
	if (ctxt->sax != &xmlDefaultSAXHandler)
	    xmlFree(ctxt->sax);
	ctxt->sax = (xmlSAXHandlerPtr) xmlMalloc(sizeof(xmlSAXHandler));
	if (ctxt->sax == NULL) {
	    xmlFree(buf);
	    xmlFree(ctxt);
	    return(NULL);
	}
	memcpy(ctxt->sax, sax, sizeof(xmlSAXHandler));
	if (user_data != NULL)
	    ctxt->userData = user_data;
    }	
    if (filename == NULL) {
	ctxt->directory = NULL;
    } else {
        ctxt->directory = xmlParserGetDirectory(filename);
    }

    inputStream = xmlNewInputStream(ctxt);
    if (inputStream == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    if (filename == NULL)
	inputStream->filename = NULL;
    else
	inputStream->filename = xmlMemStrdup(filename);
    inputStream->buf = buf;
    inputStream->base = inputStream->buf->buffer->content;
    inputStream->cur = inputStream->buf->buffer->content;

    inputPush(ctxt, inputStream);

    if ((size > 0) && (chunk != NULL) && (ctxt->input != NULL) &&
        (ctxt->input->buf != NULL))  {	      
	xmlParserInputBufferPush(ctxt->input->buf, size, chunk);	      
#ifdef DEBUG_PUSH
	fprintf(stderr, "PP: pushed %d\n", size);
#endif
    }

    return(ctxt);
}

/**
 * xmlCreateDocParserCtxt :
 * @cur:  a pointer to an array of xmlChar
 *
 * Create a parser context for an XML in-memory document.
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreateDocParserCtxt(xmlChar *cur) {
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr input;
    xmlCharEncoding enc;

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	return(NULL);
    }
    input = xmlNewInputStream(ctxt);
    if (input == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    /*
     * plug some encoding conversion routines here. !!!
     */
    enc = xmlDetectCharEncoding(cur);
    xmlSwitchEncoding(ctxt, enc);

    input->base = cur;
    input->cur = cur;

    inputPush(ctxt, input);
    return(ctxt);
}

/**
 * xmlSAXParseDoc :
 * @sax:  the SAX handler block
 * @cur:  a pointer to an array of xmlChar
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
xmlSAXParseDoc(xmlSAXHandlerPtr sax, xmlChar *cur, int recovery) {
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
 * @cur:  a pointer to an array of xmlChar
 *
 * parse an XML in-memory document and build a tree.
 * 
 * Returns the resulting document tree
 */

xmlDocPtr
xmlParseDoc(xmlChar *cur) {
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
xmlSAXParseDTD(xmlSAXHandlerPtr sax, const xmlChar *ExternalID,
                          const xmlChar *SystemID) {
    xmlDtdPtr ret = NULL;
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr input = NULL;
    xmlCharEncoding enc;

    if ((ExternalID == NULL) && (SystemID == NULL)) return(NULL);

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	return(NULL);
    }

    /*
     * Set-up the SAX context
     */
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) { 
	if (ctxt->sax != NULL)
	    xmlFree(ctxt->sax);
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

    if (input->filename == NULL)
	input->filename = (char *) xmlStrdup(SystemID); /* !!!!!!! */
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
xmlParseDTD(const xmlChar *ExternalID, const xmlChar *SystemID) {
    return(xmlSAXParseDTD(NULL, ExternalID, SystemID));
}

/**
 * xmlRecoverDoc :
 * @cur:  a pointer to an array of xmlChar
 *
 * parse an XML in-memory document and build a tree.
 * In the case the document is not Well Formed, a tree is built anyway
 * 
 * Returns the resulting document tree
 */

xmlDocPtr
xmlRecoverDoc(xmlChar *cur) {
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
    xmlParserInputPtr inputStream;
    xmlParserInputBufferPtr buf;
    char *directory = NULL;

    buf = xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE);
    if (buf == NULL) return(NULL);

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	return(NULL);
    }

    inputStream = xmlNewInputStream(ctxt);
    if (inputStream == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    inputStream->filename = xmlMemStrdup(filename);
    inputStream->buf = buf;
    inputStream->base = inputStream->buf->buffer->content;
    inputStream->cur = inputStream->buf->buffer->content;

    inputPush(ctxt, inputStream);
    if ((ctxt->directory == NULL) && (directory == NULL))
        directory = xmlParserGetDirectory(filename);
    if ((ctxt->directory == NULL) && (directory != NULL))
        ctxt->directory = directory;

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
    char *directory = NULL;

    ctxt = xmlCreateFileParserCtxt(filename);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) {
	if (ctxt->sax != NULL)
	    xmlFree(ctxt->sax);
        ctxt->sax = sax;
        ctxt->userData = NULL;
    }

    if ((ctxt->directory == NULL) && (directory == NULL))
        directory = xmlParserGetDirectory(filename);
    if ((ctxt->directory == NULL) && (directory != NULL))
        ctxt->directory = (char *) xmlStrdup((xmlChar *) directory); /* !!!!!!! */

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
 * xmlCreateMemoryParserCtxt :
 * @buffer:  an pointer to a char array
 * @size:  the size of the array
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

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	return(NULL);
    }

    input = xmlNewInputStream(ctxt);
    if (input == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    input->filename = NULL;
    input->line = 1;
    input->col = 1;
    input->buf = NULL;
    input->consumed = 0;

    /*
     * plug some encoding conversion routines here. !!!
     */
    enc = xmlDetectCharEncoding(BAD_CAST buffer);
    xmlSwitchEncoding(ctxt, enc);

    input->base = BAD_CAST buffer;
    input->cur = BAD_CAST buffer;
    input->free = NULL;

    inputPush(ctxt, input);
    return(ctxt);
}

/**
 * xmlSAXParseMemory :
 * @sax:  the SAX handler block
 * @buffer:  an pointer to a char array
 * @size:  the size of the array
 * @recovery:  work in recovery mode, i.e. tries to read not Well Formed
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
 * xmlSetupParserForBuffer:
 * @ctxt:  an XML parser context
 * @buffer:  a xmlChar * buffer
 * @filename:  a file name
 *
 * Setup the parser context to parse a new buffer; Clears any prior
 * contents from the parser context. The buffer parameter must not be
 * NULL, but the filename parameter can be
 */
void
xmlSetupParserForBuffer(xmlParserCtxtPtr ctxt, const xmlChar* buffer,
                             const char* filename)
{
    xmlParserInputPtr input;

    input = xmlNewInputStream(ctxt);
    if (input == NULL) {
        perror("malloc");
        xmlFree(ctxt);
        exit(1);
    }
  
    xmlClearParserCtxt(ctxt);
    if (filename != NULL)
        input->filename = xmlMemStrdup(filename);
    input->base = buffer;
    input->cur = buffer;
    inputPush(ctxt, input);
}

/**
 * xmlSAXUserParseFile:
 * @sax:  a SAX handler
 * @user_data:  The user data returned on SAX callbacks
 * @filename:  a file name
 *
 * parse an XML file and call the given SAX handler routines.
 * Automatic support for ZLIB/Compress compressed document is provided
 * 
 * Returns 0 in case of success or a error number otherwise
 */
int
xmlSAXUserParseFile(xmlSAXHandlerPtr sax, void *user_data,
                    const char *filename) {
    int ret = 0;
    xmlParserCtxtPtr ctxt;
    
    ctxt = xmlCreateFileParserCtxt(filename);
    if (ctxt == NULL) return -1;
    if (ctxt->sax != &xmlDefaultSAXHandler)
	xmlFree(ctxt->sax);
    ctxt->sax = sax;
    if (user_data != NULL)
	ctxt->userData = user_data;
    
    xmlParseDocument(ctxt);
    
    if (ctxt->wellFormed)
	ret = 0;
    else {
        if (ctxt->errNo != 0)
	    ret = ctxt->errNo;
	else
	    ret = -1;
    }
    if (sax != NULL)
	ctxt->sax = NULL;
    xmlFreeParserCtxt(ctxt);
    
    return ret;
}

/**
 * xmlSAXUserParseMemory:
 * @sax:  a SAX handler
 * @user_data:  The user data returned on SAX callbacks
 * @buffer:  an in-memory XML document input
 * @size:  the length of the XML document in bytes
 *
 * A better SAX parsing routine.
 * parse an XML in-memory buffer and call the given SAX handler routines.
 * 
 * Returns 0 in case of success or a error number otherwise
 */
int xmlSAXUserParseMemory(xmlSAXHandlerPtr sax, void *user_data,
			  char *buffer, int size) {
    int ret = 0;
    xmlParserCtxtPtr ctxt;
    
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if (ctxt == NULL) return -1;
    ctxt->sax = sax;
    ctxt->userData = user_data;
    
    xmlParseDocument(ctxt);
    
    if (ctxt->wellFormed)
	ret = 0;
    else {
        if (ctxt->errNo != 0)
	    ret = ctxt->errNo;
	else
	    ret = -1;
    }
    if (sax != NULL)
	ctxt->sax = NULL;
    xmlFreeParserCtxt(ctxt);
    
    return ret;
}


/************************************************************************
 *									*
 * 				Miscellaneous				*
 *									*
 ************************************************************************/

/**
 * xmlCleanupParser:
 *
 * Cleanup function for the XML parser. It tries to reclaim all
 * parsing related global memory allocated for the parser processing.
 * It doesn't deallocate any document related memory. Calling this
 * function should not prevent reusing the parser.
 */

void
xmlCleanupParser(void) {
    xmlCleanupCharEncodingHandlers();
    xmlCleanupPredefinedEntities();
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
    xmlFree(seq->buffer);
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
        tmp_buffer = (xmlParserNodeInfo*) xmlMalloc(byte_size);
      else 
        tmp_buffer = (xmlParserNodeInfo*) xmlRealloc(ctxt->node_seq.buffer, byte_size);

      if ( tmp_buffer == NULL ) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Out of memory\n");
	ctxt->errNo = XML_ERR_NO_MEMORY;
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

