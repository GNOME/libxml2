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

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/entities.h>
#include <libxml/encoding.h>
#include <libxml/valid.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>
#include "xml-error.h"

#define XML_PARSER_BIG_BUFFER_SIZE 1000
#define XML_PARSER_BUFFER_SIZE 100

const char *xmlParserVersion = LIBXML_VERSION_STRING;
int xmlGetWarningsDefaultValue = 1;

/*
 * List of XML prefixed PI allowed by W3C specs
 */

const char *xmlW3CPIs[] = {
    "xml-stylesheet",
    NULL
};

void xmlParserHandleReference(xmlParserCtxtPtr ctxt);
void xmlParserHandlePEReference(xmlParserCtxtPtr ctxt);
xmlEntityPtr xmlParseStringPEReference(xmlParserCtxtPtr ctxt,
                                       const xmlChar **str);
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
    if (in->buf->readcallback != NULL)
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
int xmlKeepBlanksDefaultValue = 1;
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
	    return(0);							\
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

int spacePush(xmlParserCtxtPtr ctxt, int val) {
    if (ctxt->spaceNr >= ctxt->spaceMax) {
	ctxt->spaceMax *= 2;
        ctxt->spaceTab = (void *) xmlRealloc(ctxt->spaceTab,
	             ctxt->spaceMax * sizeof(ctxt->spaceTab[0]));
        if (ctxt->spaceTab == NULL) {
	    fprintf(stderr, "realloc failed !\n");
	    return(0);
	}
    }
    ctxt->spaceTab[ctxt->spaceNr] = val;
    ctxt->space = &ctxt->spaceTab[ctxt->spaceNr];
    return(ctxt->spaceNr++);
}

int spacePop(xmlParserCtxtPtr ctxt) {
    int ret;
    if (ctxt->spaceNr <= 0) return(0);
    ctxt->spaceNr--;
    if (ctxt->spaceNr > 0)
	ctxt->space = &ctxt->spaceTab[ctxt->spaceNr - 1];
    else
        ctxt->space = NULL;
    ret = ctxt->spaceTab[ctxt->spaceNr];
    ctxt->spaceTab[ctxt->spaceNr] = -1;
    return(ret);
}

/*
 * Macros for accessing the content. Those should be used only by the parser,
 * and not exported.
 *
 * Dirty macros, i.e. one need to make assumption on the context to use them
 *
 *   CUR_PTR return the current pointer to the xmlChar to be parsed.
 *           To be used with extreme caution since operations consuming
 *           characters may move the input buffer to a different location !
 *   CUR     returns the current xmlChar value, i.e. a 8 bit value if compiled
 *           in ISO-Latin or UTF-8. 
 *           This should be used internally by the parser
 *           only to compare to ASCII values otherwise it would break when
 *           running with UTF-8 encoding.
 *   NXT(n)  returns the n'th next xmlChar. Same as CUR is should be used only
 *           to compare on ASCII based substring.
 *   SKIP(n) Skip n xmlChar, and must also be used only to skip ASCII defined
 *           strings within the parser.
 *
 * Clean macros, not dependent of an ASCII context, expect UTF-8 encoding
 *
 *   NEXT    Skip to the next character, this does the proper decoding
 *           in UTF-8 mode. It also pop-up unfinished entities on the fly.
 *   COPY(to) copy one char to *to, increment CUR_PTR and to accordingly
 *   CUR_CHAR Return the current char as an int as well as its lenght.
 */

#define RAW (ctxt->token ? -1 : (*ctxt->input->cur))
#define CUR (ctxt->token ? ctxt->token : (*ctxt->input->cur))
#define NXT(val) ctxt->input->cur[(val)]
#define CUR_PTR ctxt->input->cur

#define SKIP(val) ctxt->nbChars += (val),ctxt->input->cur += (val);	\
    if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);	\
    if (*ctxt->input->cur == '&') xmlParserHandleReference(ctxt);	\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))		\
	    xmlPopInput(ctxt)

#define SHRINK  xmlParserInputShrink(ctxt->input);			\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))		\
	    xmlPopInput(ctxt)

#define GROW  xmlParserInputGrow(ctxt->input, INPUT_CHUNK);		\
    if ((*ctxt->input->cur == 0) &&					\
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))		\
	    xmlPopInput(ctxt)

#define SKIP_BLANKS xmlSkipBlankChars(ctxt);

#define NEXT xmlNextChar(ctxt);

#define NEXTL(l)							\
    if (*(ctxt->input->cur) == '\n') {					\
	ctxt->input->line++; ctxt->input->col = 1;			\
    } else ctxt->input->col++;						\
    ctxt->token = 0; ctxt->input->cur += l;				\
    if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);	\
    if (*ctxt->input->cur == '&') xmlParserHandleReference(ctxt);

#define CUR_CHAR(l) xmlCurrentChar(ctxt, &l);
#define CUR_SCHAR(s, l) xmlStringCurrentChar(ctxt, s, &l);

#define COPY_BUF(l,b,i,v)						\
    if (l == 1) b[i++] = (xmlChar) v;					\
    else i += xmlCopyChar(l,&b[i],v);

/**
 * xmlNextChar:
 * @ctxt:  the XML parser context
 *
 * Skip to the next char input char.
 */

void
xmlNextChar(xmlParserCtxtPtr ctxt) {
    /*
     * TODO: 2.11 End-of-Line Handling
     *   the literal two-character sequence "#xD#xA" or a standalone
     *   literal #xD, an XML processor must pass to the application
     *   the single character #xA. 
     */
    if (ctxt->token != 0) ctxt->token = 0;
    else {
	if ((*ctxt->input->cur == 0) &&
	    (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0) &&
	    (ctxt->instate != XML_PARSER_COMMENT)) {
	        /*
		 * If we are at the end of the current entity and
		 * the context allows it, we pop consumed entities
		 * automatically.
		 * TODO: the auto closing should be blocked in other cases
		 */
		xmlPopInput(ctxt);
	} else {
	    if (*(ctxt->input->cur) == '\n') {
		ctxt->input->line++; ctxt->input->col = 1;
	    } else ctxt->input->col++;
	    if (ctxt->encoding == NULL) {
		/*
		 * We are supposed to handle UTF8, check it's valid
		 * From rfc2044: encoding of the Unicode values on UTF-8:
		 *
		 * UCS-4 range (hex.)           UTF-8 octet sequence (binary)
		 * 0000 0000-0000 007F   0xxxxxxx
		 * 0000 0080-0000 07FF   110xxxxx 10xxxxxx
		 * 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx 
		 *
		 * Check for the 0x110000 limit too
		 */
		const unsigned char *cur = ctxt->input->cur;
		unsigned char c;

		c = *cur;
		if (c & 0x80) {
		    if (cur[1] == 0)
			xmlParserInputGrow(ctxt->input, INPUT_CHUNK);
		    if ((cur[1] & 0xc0) != 0x80)
			goto encoding_error;
		    if ((c & 0xe0) == 0xe0) {
			unsigned int val;

			if (cur[2] == 0)
			    xmlParserInputGrow(ctxt->input, INPUT_CHUNK);
			if ((cur[2] & 0xc0) != 0x80)
			    goto encoding_error;
			if ((c & 0xf0) == 0xf0) {
			    if (cur[3] == 0)
				xmlParserInputGrow(ctxt->input, INPUT_CHUNK);
			    if (((c & 0xf8) != 0xf0) ||
				((cur[3] & 0xc0) != 0x80))
				goto encoding_error;
			    /* 4-byte code */
			    ctxt->input->cur += 4;
			    val = (cur[0] & 0x7) << 18;
			    val |= (cur[1] & 0x3f) << 12;
			    val |= (cur[2] & 0x3f) << 6;
			    val |= cur[3] & 0x3f;
			} else {
			  /* 3-byte code */
			    ctxt->input->cur += 3;
			    val = (cur[0] & 0xf) << 12;
			    val |= (cur[1] & 0x3f) << 6;
			    val |= cur[2] & 0x3f;
			}
			if (((val > 0xd7ff) && (val < 0xe000)) ||
			    ((val > 0xfffd) && (val < 0x10000)) ||
			    (val >= 0x110000)) {
			    if ((ctxt->sax != NULL) &&
				(ctxt->sax->error != NULL))
				ctxt->sax->error(ctxt->userData, 
				 "Char out of allowed range\n");
			    ctxt->errNo = XML_ERR_INVALID_ENCODING;
			    ctxt->wellFormed = 0;
			    ctxt->disableSAX = 1;
			}    
		    } else
		      /* 2-byte code */
		        ctxt->input->cur += 2;
		} else
		    /* 1-byte code */
		    ctxt->input->cur++;
	    } else {
		/*
		 * Assume it's a fixed lenght encoding (1) with
		 * a compatibke encoding for the ASCII set, since
		 * XML constructs only use < 128 chars
		 */
	        ctxt->input->cur++;
	    }
	    ctxt->nbChars++;
	    if (*ctxt->input->cur == 0)
		xmlParserInputGrow(ctxt->input, INPUT_CHUNK);
	}
    }
    if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);
    if (*ctxt->input->cur == '&') xmlParserHandleReference(ctxt);
    if ((*ctxt->input->cur == 0) &&
        (xmlParserInputGrow(ctxt->input, INPUT_CHUNK) <= 0))
	    xmlPopInput(ctxt);
    return;
encoding_error:
    /*
     * If we detect an UTF8 error that probably mean that the
     * input encoding didn't get properly advertized in the
     * declaration header. Report the error and switch the encoding
     * to ISO-Latin-1 (if you don't like this policy, just declare the
     * encoding !)
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	ctxt->sax->error(ctxt->userData, 
			 "Input is not proper UTF-8, indicate encoding !\n");
    ctxt->errNo = XML_ERR_INVALID_ENCODING;

    ctxt->encoding = xmlStrdup(BAD_CAST "ISO-8859-1"); 
    ctxt->input->cur++;
    return;
}

/**
 * xmlCurrentChar:
 * @ctxt:  the XML parser context
 * @len:  pointer to the length of the char read
 *
 * The current char value, if using UTF-8 this may actaully span multiple
 * bytes in the input buffer. Implement the end of line normalization:
 * 2.11 End-of-Line Handling
 * Wherever an external parsed entity or the literal entity value
 * of an internal parsed entity contains either the literal two-character
 * sequence "#xD#xA" or a standalone literal #xD, an XML processor
 * must pass to the application the single character #xA.
 * This behavior can conveniently be produced by normalizing all
 * line breaks to #xA on input, before parsing.)
 *
 * Returns the current char value and its lenght
 */

int
xmlCurrentChar(xmlParserCtxtPtr ctxt, int *len) {
    if (ctxt->token != 0) {
	*len = 0;
	return(ctxt->token);
    }	
    if (ctxt->encoding == NULL) {
	/*
	 * We are supposed to handle UTF8, check it's valid
	 * From rfc2044: encoding of the Unicode values on UTF-8:
	 *
	 * UCS-4 range (hex.)           UTF-8 octet sequence (binary)
	 * 0000 0000-0000 007F   0xxxxxxx
	 * 0000 0080-0000 07FF   110xxxxx 10xxxxxx
	 * 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx 
	 *
	 * Check for the 0x110000 limit too
	 */
	const unsigned char *cur = ctxt->input->cur;
	unsigned char c;
	unsigned int val;

	c = *cur;
	if (c & 0x80) {
	    if (cur[1] == 0)
		xmlParserInputGrow(ctxt->input, INPUT_CHUNK);
	    if ((cur[1] & 0xc0) != 0x80)
		goto encoding_error;
	    if ((c & 0xe0) == 0xe0) {

		if (cur[2] == 0)
		    xmlParserInputGrow(ctxt->input, INPUT_CHUNK);
		if ((cur[2] & 0xc0) != 0x80)
		    goto encoding_error;
		if ((c & 0xf0) == 0xf0) {
		    if (cur[3] == 0)
			xmlParserInputGrow(ctxt->input, INPUT_CHUNK);
		    if (((c & 0xf8) != 0xf0) ||
			((cur[3] & 0xc0) != 0x80))
			goto encoding_error;
		    /* 4-byte code */
		    *len = 4;
		    val = (cur[0] & 0x7) << 18;
		    val |= (cur[1] & 0x3f) << 12;
		    val |= (cur[2] & 0x3f) << 6;
		    val |= cur[3] & 0x3f;
		} else {
		  /* 3-byte code */
		    *len = 3;
		    val = (cur[0] & 0xf) << 12;
		    val |= (cur[1] & 0x3f) << 6;
		    val |= cur[2] & 0x3f;
		}
	    } else {
	      /* 2-byte code */
		*len = 2;
		val = (cur[0] & 0x1f) << 6;
		val |= cur[1] & 0x3f;
	    }
	    if (!IS_CHAR(val)) {
		if ((ctxt->sax != NULL) &&
		    (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
				     "Char out of allowed range\n");
		ctxt->errNo = XML_ERR_INVALID_ENCODING;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }    
	    return(val);
	} else {
	    /* 1-byte code */
	    *len = 1;
	    if (*ctxt->input->cur == 0xD) {
		if (ctxt->input->cur[1] == 0xA) {
		    ctxt->nbChars++;
		    ctxt->input->cur++;
		}
		return(0xA);
	    }
	    return((int) *ctxt->input->cur);
	}
    }
    /*
     * Assume it's a fixed lenght encoding (1) with
     * a compatibke encoding for the ASCII set, since
     * XML constructs only use < 128 chars
     */
    *len = 1;
    if (*ctxt->input->cur == 0xD) {
	if (ctxt->input->cur[1] == 0xA) {
	    ctxt->nbChars++;
	    ctxt->input->cur++;
	}
	return(0xA);
    }
    return((int) *ctxt->input->cur);
encoding_error:
    /*
     * If we detect an UTF8 error that probably mean that the
     * input encoding didn't get properly advertized in the
     * declaration header. Report the error and switch the encoding
     * to ISO-Latin-1 (if you don't like this policy, just declare the
     * encoding !)
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	ctxt->sax->error(ctxt->userData, 
			 "Input is not proper UTF-8, indicate encoding !\n");
    ctxt->errNo = XML_ERR_INVALID_ENCODING;

    ctxt->encoding = xmlStrdup(BAD_CAST "ISO-8859-1"); 
    *len = 1;
    return((int) *ctxt->input->cur);
}

/**
 * xmlStringCurrentChar:
 * @ctxt:  the XML parser context
 * @cur:  pointer to the beginning of the char
 * @len:  pointer to the length of the char read
 *
 * The current char value, if using UTF-8 this may actaully span multiple
 * bytes in the input buffer.
 *
 * Returns the current char value and its lenght
 */

int
xmlStringCurrentChar(xmlParserCtxtPtr ctxt, const xmlChar *cur, int *len) {
    if (ctxt->encoding == NULL) {
	/*
	 * We are supposed to handle UTF8, check it's valid
	 * From rfc2044: encoding of the Unicode values on UTF-8:
	 *
	 * UCS-4 range (hex.)           UTF-8 octet sequence (binary)
	 * 0000 0000-0000 007F   0xxxxxxx
	 * 0000 0080-0000 07FF   110xxxxx 10xxxxxx
	 * 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx 
	 *
	 * Check for the 0x110000 limit too
	 */
	unsigned char c;
	unsigned int val;

	c = *cur;
	if (c & 0x80) {
	    if ((cur[1] & 0xc0) != 0x80)
		goto encoding_error;
	    if ((c & 0xe0) == 0xe0) {

		if ((cur[2] & 0xc0) != 0x80)
		    goto encoding_error;
		if ((c & 0xf0) == 0xf0) {
		    if (((c & 0xf8) != 0xf0) ||
			((cur[3] & 0xc0) != 0x80))
			goto encoding_error;
		    /* 4-byte code */
		    *len = 4;
		    val = (cur[0] & 0x7) << 18;
		    val |= (cur[1] & 0x3f) << 12;
		    val |= (cur[2] & 0x3f) << 6;
		    val |= cur[3] & 0x3f;
		} else {
		  /* 3-byte code */
		    *len = 3;
		    val = (cur[0] & 0xf) << 12;
		    val |= (cur[1] & 0x3f) << 6;
		    val |= cur[2] & 0x3f;
		}
	    } else {
	      /* 2-byte code */
		*len = 2;
		val = (cur[0] & 0x1f) << 6;
		val |= cur[2] & 0x3f;
	    }
	    if (!IS_CHAR(val)) {
		if ((ctxt->sax != NULL) &&
		    (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
				     "Char out of allowed range\n");
		ctxt->errNo = XML_ERR_INVALID_ENCODING;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }    
	    return(val);
	} else {
	    /* 1-byte code */
	    *len = 1;
	    return((int) *cur);
	}
    }
    /*
     * Assume it's a fixed lenght encoding (1) with
     * a compatibke encoding for the ASCII set, since
     * XML constructs only use < 128 chars
     */
    *len = 1;
    return((int) *cur);
encoding_error:
    /*
     * If we detect an UTF8 error that probably mean that the
     * input encoding didn't get properly advertized in the
     * declaration header. Report the error and switch the encoding
     * to ISO-Latin-1 (if you don't like this policy, just declare the
     * encoding !)
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	ctxt->sax->error(ctxt->userData, 
			 "Input is not proper UTF-8, indicate encoding !\n");
    ctxt->errNo = XML_ERR_INVALID_ENCODING;

    *len = 1;
    return((int) *cur);
}

/**
 * xmlCopyChar:
 * @len:  pointer to the length of the char read (or zero)
 * @array:  pointer to an arry of xmlChar
 * @val:  the char value
 *
 * append the char value in the array 
 *
 * Returns the number of xmlChar written
 */

int
xmlCopyChar(int len, xmlChar *out, int val) {
    /*
     * We are supposed to handle UTF8, check it's valid
     * From rfc2044: encoding of the Unicode values on UTF-8:
     *
     * UCS-4 range (hex.)           UTF-8 octet sequence (binary)
     * 0000 0000-0000 007F   0xxxxxxx
     * 0000 0080-0000 07FF   110xxxxx 10xxxxxx
     * 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx 
     */
    if (len == 0) {
	if (val < 0) len = 0;
	else if (val < 0x80) len = 1;
	else if (val < 0x800) len = 2;
	else if (val < 0x10000) len = 3;
	else if (val < 0x110000) len = 4;
	if (len == 0) {
	    fprintf(stderr, "Internal error, xmlCopyChar 0x%X out of bound\n",
		    val);
	    return(0);
	}
    }
    if (len > 1) {
	int bits; 

        if      (val <    0x80) {  *out++=  val;                bits= -6; }
        else if (val <   0x800) {  *out++= (val >>  6) | 0xC0;  bits=  0; }
        else if (val < 0x10000) {  *out++= (val >> 12) | 0xE0;  bits=  6; }
        else                  {    *out++= (val >> 18) | 0xF0;  bits= 12; }
 
        for ( ; bits >= 0; bits-= 6)
            *out++= ((val >> bits) & 0x3F) | 0x80 ;

        return(len);
    }
    *out = (xmlChar) val;
    return(1);
}

/**
 * xmlSkipBlankChars:
 * @ctxt:  the XML parser context
 *
 * skip all blanks character found at that point in the input streams.
 * It pops up finished entities in the process if allowable at that point.
 *
 * Returns the number of space chars skipped
 */

int
xmlSkipBlankChars(xmlParserCtxtPtr ctxt) {
    int cur, res = 0;

    do {
	cur = CUR;
	while (IS_BLANK(cur)) {
	    NEXT;
	    cur = CUR;
	    res++;
	}
	while ((cur == 0) && (ctxt->inputNr > 1) &&
	       (ctxt->instate != XML_PARSER_COMMENT)) {
	    xmlPopInput(ctxt);
	    cur = CUR;
	}
	if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);
	if (*ctxt->input->cur == '&') xmlParserHandleReference(ctxt);
    } while (IS_BLANK(cur));
    return(res);
}

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
    GROW;
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
    if (input->encoding != NULL) xmlFree((char *) input->encoding);
    if (input->version != NULL) xmlFree((char *) input->version);
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
	if (ctxt != NULL) {
	    ctxt->errNo = XML_ERR_NO_MEMORY;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
			 "malloc: couldn't allocate a new input stream\n");
	    ctxt->errNo = XML_ERR_NO_MEMORY;
	}
	return(NULL);
    }
    memset(input, 0, sizeof(xmlParserInput));
    input->line = 1;
    input->col = 1;
    input->standalone = -1;
    return(input);
}

/**
 * xmlNewIOInputStream:
 * @ctxt:  an XML parser context
 * @input:  an I/O Input
 * @enc:  the charset encoding if known
 *
 * Create a new input stream structure encapsulating the @input into
 * a stream suitable for the parser.
 *
 * Returns the new input stream or NULL
 */
xmlParserInputPtr
xmlNewIOInputStream(xmlParserCtxtPtr ctxt, xmlParserInputBufferPtr input,
	            xmlCharEncoding enc) {
    xmlParserInputPtr inputStream;

    inputStream = xmlNewInputStream(ctxt);
    if (inputStream == NULL) {
	return(NULL);
    }
    inputStream->filename = NULL;
    inputStream->buf = input;
    inputStream->base = inputStream->buf->buffer->content;
    inputStream->cur = inputStream->buf->buffer->content;
    if (enc != XML_CHAR_ENCODING_NONE) {
        xmlSwitchEncoding(ctxt, enc);
    }

    return(inputStream);
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
	switch (entity->etype) {
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
    input->filename = (char *) entity->SystemID;
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

    xmlDefaultSAXHandlerInit();

    sax = (xmlSAXHandler *) xmlMalloc(sizeof(xmlSAXHandler));
    if (sax == NULL) {
        fprintf(stderr, "xmlInitParserCtxt: out of memory\n");
    }
    memset(sax, 0, sizeof(xmlSAXHandler));

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

    /* Allocate the space stack */
    ctxt->spaceTab = (int *) xmlMalloc(10 * sizeof(int));
    ctxt->spaceNr = 1;
    ctxt->spaceMax = 10;
    ctxt->spaceTab[0] = -1;
    ctxt->space = &ctxt->spaceTab[0];

    if (sax == NULL) {
	ctxt->sax = &xmlDefaultSAXHandler;
    } else {
        ctxt->sax = sax;
	memcpy(sax, &xmlDefaultSAXHandler, sizeof(xmlSAXHandler));
    }
    ctxt->userData = ctxt;
    ctxt->myDoc = NULL;
    ctxt->wellFormed = 1;
    ctxt->valid = 1;
    ctxt->validate = xmlDoValidityCheckingDefaultValue;
    ctxt->keepBlanks = xmlKeepBlanksDefaultValue;
    ctxt->vctxt.userData = ctxt;
    if (ctxt->validate) {
	ctxt->vctxt.error = xmlParserValidityError;
	if (xmlGetWarningsDefaultValue == 0)
	    ctxt->vctxt.warning = NULL;
	else
	    ctxt->vctxt.warning = xmlParserValidityWarning;
	/* Allocate the Node stack */
	ctxt->vctxt.nodeTab = (xmlNodePtr *) xmlMalloc(4 * sizeof(xmlNodePtr));
	ctxt->vctxt.nodeNr = 0;
	ctxt->vctxt.nodeMax = 4;
	ctxt->vctxt.node = NULL;
    } else {
	ctxt->vctxt.error = NULL;
	ctxt->vctxt.warning = NULL;
    }
    ctxt->replaceEntities = xmlSubstituteEntitiesDefaultValue;
    ctxt->record_info = 0;
    ctxt->nbChars = 0;
    ctxt->checkIndex = 0;
    ctxt->inSubset = 0;
    ctxt->errNo = XML_ERR_OK;
    ctxt->depth = 0;
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
    if (ctxt->spaceTab != NULL) xmlFree(ctxt->spaceTab);
    if (ctxt->nameTab != NULL) xmlFree(ctxt->nameTab);
    if (ctxt->nodeTab != NULL) xmlFree(ctxt->nodeTab);
    if (ctxt->inputTab != NULL) xmlFree(ctxt->inputTab);
    if (ctxt->version != NULL) xmlFree((char *) ctxt->version);
    if (ctxt->encoding != NULL) xmlFree((char *) ctxt->encoding);
    if (ctxt->intSubName != NULL) xmlFree((char *) ctxt->intSubName);
    if (ctxt->extSubURI != NULL) xmlFree((char *) ctxt->extSubURI);
    if (ctxt->extSubSystem != NULL) xmlFree((char *) ctxt->extSubSystem);
    if (ctxt->vctxt.nodeTab != NULL) xmlFree(ctxt->vctxt.nodeTab);
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
    memset(ctxt, 0, sizeof(xmlParserCtxt));
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

/**
 * xmlCheckEntity:
 * @ctxt:  an XML parser context
 * @content:  the entity content string
 *
 * Parse an entity content and checks the WF constraints
 *
 */

void
xmlCheckEntity(xmlParserCtxtPtr ctxt, const xmlChar *content) {
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
	val = ctxt->token;
        ctxt->token = 0;
        return(val);
    }
    if ((RAW == '&') && (NXT(1) == '#') &&
        (NXT(2) == 'x')) {
	SKIP(3);
	while (RAW != ';') {
	    if ((RAW >= '0') && (RAW <= '9')) 
	        val = val * 16 + (CUR - '0');
	    else if ((RAW >= 'a') && (RAW <= 'f'))
	        val = val * 16 + (CUR - 'a') + 10;
	    else if ((RAW >= 'A') && (RAW <= 'F'))
	        val = val * 16 + (CUR - 'A') + 10;
	    else {
		ctxt->errNo = XML_ERR_INVALID_HEX_CHARREF;
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		         "xmlParseCharRef: invalid hexadecimal value\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		val = 0;
		break;
	    }
	    NEXT;
	}
	if (RAW == ';') {
	    /* on purpose to avoid reentrancy problems with NEXT and SKIP */
	    ctxt->nbChars ++;
	    ctxt->input->cur++;
	}
    } else if  ((RAW == '&') && (NXT(1) == '#')) {
	SKIP(2);
	while (RAW != ';') {
	    if ((RAW >= '0') && (RAW <= '9')) 
	        val = val * 10 + (CUR - '0');
	    else {
		ctxt->errNo = XML_ERR_INVALID_DEC_CHARREF;
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		         "xmlParseCharRef: invalid decimal value\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		val = 0;
		break;
	    }
	    NEXT;
	}
	if (RAW == ';') {
	    /* on purpose to avoid reentrancy problems with NEXT and SKIP */
	    ctxt->nbChars ++;
	    ctxt->input->cur++;
	}
    } else {
	ctxt->errNo = XML_ERR_INVALID_CHARREF;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "xmlParseCharRef: invalid value\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
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
		ctxt->disableSAX = 1;
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
		ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
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
        return;
    }	
    if (RAW != '&') return;
    GROW;
    if ((RAW == '&') && (NXT(1) == '#')) {
	switch(ctxt->instate) {
	    case XML_PARSER_ENTITY_DECL:
	    case XML_PARSER_PI:
	    case XML_PARSER_CDATA_SECTION:
	    case XML_PARSER_COMMENT:
	    case XML_PARSER_SYSTEM_LITERAL:
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
		ctxt->disableSAX = 1;
		return;
	    case XML_PARSER_PROLOG:
	    case XML_PARSER_START:
	    case XML_PARSER_MISC:
		ctxt->errNo = XML_ERR_CHARREF_IN_PROLOG;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "CharRef in prolog!\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		return;
	    case XML_PARSER_EPILOG:
		ctxt->errNo = XML_ERR_CHARREF_IN_EPILOG;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "CharRef in epilog!\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		return;
	    case XML_PARSER_DTD:
		ctxt->errNo = XML_ERR_CHARREF_IN_DTD;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		           "CharRef are forbiden in DTDs!\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
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
	case XML_PARSER_SYSTEM_LITERAL:
        case XML_PARSER_CONTENT:
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
	    ctxt->disableSAX = 1;
	    return;
        case XML_PARSER_PROLOG:
	case XML_PARSER_START:
	case XML_PARSER_MISC:
	    ctxt->errNo = XML_ERR_ENTITYREF_IN_PROLOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Reference in prolog!\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return;
        case XML_PARSER_EPILOG:
	    ctxt->errNo = XML_ERR_ENTITYREF_IN_EPILOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "Reference in epilog!\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
	    ctxt->disableSAX = 1;
	    return;
    }

    NEXT;
    name = xmlScanName(ctxt);
    if (name == NULL) {
	ctxt->errNo = XML_ERR_ENTITYREF_NO_NAME;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Entity reference: no name\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->token = '&';
	return;
    }
    if (NXT(xmlStrlen(name)) != ';') {
	ctxt->errNo = XML_ERR_ENTITYREF_SEMICOL_MISSING;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	                     "Entity reference: ';' expected\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
	xmlFree(name);
	return;
    }

    /*
     * [ WFC: Parsed Entity ]
     * An entity reference must not contain the name of an unparsed entity
     */
    if (ent->etype == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY) {
        ctxt->errNo = XML_ERR_UNPARSED_ENTITY;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
			 "Entity reference to unparsed entity %s\n", name);
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
    }

    if (ent->etype == XML_INTERNAL_PREDEFINED_ENTITY) {
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
        return;
    }	
    if (RAW != '%') return;
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
	    ctxt->disableSAX = 1;
	    return;
        case XML_PARSER_PROLOG:
	case XML_PARSER_START:
	case XML_PARSER_MISC:
	    ctxt->errNo = XML_ERR_PEREF_IN_PROLOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "PEReference in prolog!\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return;
	case XML_PARSER_ENTITY_DECL:
        case XML_PARSER_CONTENT:
        case XML_PARSER_ATTRIBUTE_VALUE:
        case XML_PARSER_PI:
	case XML_PARSER_SYSTEM_LITERAL:
	    /* we just ignore it there */
	    return;
        case XML_PARSER_EPILOG:
	    ctxt->errNo = XML_ERR_PEREF_IN_EPILOG;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "PEReference in epilog!\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
    } else {
	if (RAW == ';') {
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
		    ctxt->disableSAX = 1;
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
	        if ((entity->etype == XML_INTERNAL_PARAMETER_ENTITY) ||
		    (entity->etype == XML_EXTERNAL_PARAMETER_ENTITY)) {
		    /*
		     * TODO !!! handle the extra spaces added before and after
		     * c.f. http://www.w3.org/TR/REC-xml#as-PE
		     */
		    input = xmlNewEntityInputStream(ctxt, entity);
		    xmlPushInput(ctxt, input);
		    if ((entity->etype == XML_EXTERNAL_PARAMETER_ENTITY) &&
			(RAW == '<') && (NXT(1) == '?') &&
			(NXT(2) == 'x') && (NXT(3) == 'm') &&
			(NXT(4) == 'l') && (IS_BLANK(NXT(5)))) {
			xmlParseTextDecl(ctxt);
		    }
		    if (ctxt->token == 0)
			ctxt->token = ' ';
		} else {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			 "xmlHandlePEReference: %s is not a parameter entity\n",
			                 name);
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}
	    }
	} else {
	    ctxt->errNo = XML_ERR_PEREF_SEMICOL_MISSING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
				 "xmlHandlePEReference: expecting ';'\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
    int nbchars = 0;

    xmlChar *current = NULL;
    xmlEntityPtr ent;
    unsigned int max = (unsigned int) len;
    int c,l;

    if (ctxt->depth > 40) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"Detected entity reference loop\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_ENTITY_LOOP;
	return(NULL);
    }

    /*
     * allocate a translation buffer.
     */
    buffer_size = XML_PARSER_BIG_BUFFER_SIZE;
    buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
	perror("xmlDecodeEntities: malloc failed");
	return(NULL);
    }

    /*
     * Ok loop until we reach one of the ending char or a size limit.
     */
    c = CUR_CHAR(l);
    while ((nbchars < max) && (c != end) &&
           (c != end2) && (c != end3)) {

	if (c == 0) break;
        if (((c == '&') && (ctxt->token != '&')) && (NXT(1) == '#')) {
	    int val = xmlParseCharRef(ctxt);
	    COPY_BUF(0,buffer,nbchars,val);
	    NEXTL(l);
	} else if ((c == '&') && (ctxt->token != '&') &&
		   (what & XML_SUBSTITUTE_REF)) {
	    ent = xmlParseEntityRef(ctxt);
	    if ((ent != NULL) && 
		(ctxt->replaceEntities != 0)) {
		current = ent->content;
		while (*current != 0) {
		    buffer[nbchars++] = *current++;
		    if (nbchars > buffer_size - XML_PARSER_BUFFER_SIZE) {
			growBuffer(buffer);
		    }
		}
	    } else if (ent != NULL) {
		const xmlChar *cur = ent->name;

		buffer[nbchars++] = '&';
		if (nbchars > buffer_size - XML_PARSER_BUFFER_SIZE) {
		    growBuffer(buffer);
		}
		while (*cur != 0) {
		    buffer[nbchars++] = *cur++;
		}
		buffer[nbchars++] = ';';
	    }
	} else if (c == '%' && (what & XML_SUBSTITUTE_PEREF)) {
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
	    while ((RAW == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

	    break;
	} else {
	    COPY_BUF(l,buffer,nbchars,c);
	    NEXTL(l);
	    if (nbchars > buffer_size - XML_PARSER_BUFFER_SIZE) {
	      growBuffer(buffer);
	    }
	}
	c = CUR_CHAR(l);
    }
    buffer[nbchars++] = 0;
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

    xmlChar *current = NULL;
    xmlEntityPtr ent;
    int c,l;
    int nbchars = 0;

    if (ctxt->depth > 40) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"Detected entity reference loop\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_ENTITY_LOOP;
	return(NULL);
    }

    /*
     * allocate a translation buffer.
     */
    buffer_size = XML_PARSER_BIG_BUFFER_SIZE;
    buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
	perror("xmlDecodeEntities: malloc failed");
	return(NULL);
    }

    /*
     * Ok loop until we reach one of the ending char or a size limit.
     */
    c = CUR_SCHAR(str, l);
    while ((c != 0) && (c != end) && (c != end2) && (c != end3)) {

	if (c == 0) break;
        if ((c == '&') && (str[1] == '#')) {
	    int val = xmlParseStringCharRef(ctxt, &str);
	    if (val != 0) {
		COPY_BUF(0,buffer,nbchars,val);
	    }
	} else if ((c == '&') && (what & XML_SUBSTITUTE_REF)) {
	    ent = xmlParseStringEntityRef(ctxt, &str);
	    if ((ent != NULL) && (ent->content != NULL)) {
		xmlChar *rep;

		ctxt->depth++;
		rep = xmlStringDecodeEntities(ctxt, ent->content, what,
			                      0, 0, 0);
		ctxt->depth--;
		if (rep != NULL) {
		    current = rep;
		    while (*current != 0) {
			buffer[nbchars++] = *current++;
			if (nbchars >
		            buffer_size - XML_PARSER_BUFFER_SIZE) {
			    growBuffer(buffer);
			}
		    }
		    xmlFree(rep);
		}
	    } else if (ent != NULL) {
		int i = xmlStrlen(ent->name);
		const xmlChar *cur = ent->name;

		buffer[nbchars++] = '&';
		if (nbchars > buffer_size - i - XML_PARSER_BUFFER_SIZE) {
		    growBuffer(buffer);
		}
		for (;i > 0;i--)
		    buffer[nbchars++] = *cur++;
		buffer[nbchars++] = ';';
	    }
	} else if (c == '%' && (what & XML_SUBSTITUTE_PEREF)) {
	    ent = xmlParseStringPEReference(ctxt, &str);
	    if (ent != NULL) {
		xmlChar *rep;

		ctxt->depth++;
		rep = xmlStringDecodeEntities(ctxt, ent->content, what,
			                      0, 0, 0);
		ctxt->depth--;
		if (rep != NULL) {
		    current = rep;
		    while (*current != 0) {
			buffer[nbchars++] = *current++;
			if (nbchars >
		            buffer_size - XML_PARSER_BUFFER_SIZE) {
			    growBuffer(buffer);
			}
		    }
		    xmlFree(rep);
		}
	    }
	} else {
	    COPY_BUF(l,buffer,nbchars,c);
	    str += l;
	    if (nbchars > buffer_size - XML_PARSER_BUFFER_SIZE) {
	      growBuffer(buffer);
	    }
	}
	c = CUR_SCHAR(str, l);
    }
    buffer[nbchars++] = 0;
    return(buffer);
}


/************************************************************************
 *									*
 *		Commodity functions to handle encodings			*
 *									*
 ************************************************************************/

/*
 * xmlCheckLanguageID
 * @lang:  pointer to the string value
 *
 * Checks that the value conforms to the LanguageID production:
 *
 * [33] LanguageID ::= Langcode ('-' Subcode)*
 * [34] Langcode ::= ISO639Code |  IanaCode |  UserCode
 * [35] ISO639Code ::= ([a-z] | [A-Z]) ([a-z] | [A-Z])
 * [36] IanaCode ::= ('i' | 'I') '-' ([a-z] | [A-Z])+
 * [37] UserCode ::= ('x' | 'X') '-' ([a-z] | [A-Z])+
 * [38] Subcode ::= ([a-z] | [A-Z])+
 *
 * Returns 1 if correct 0 otherwise
 **/
int
xmlCheckLanguageID(const xmlChar *lang) {
    const xmlChar *cur = lang;

    if (cur == NULL)
	return(0);
    if (((cur[0] == 'i') && (cur[1] == '-')) ||
	((cur[0] == 'I') && (cur[1] == '-'))) {
	/*
	 * IANA code
	 */
	cur += 2;
        while (((cur[0] >= 'A') && (cur[0] <= 'Z')) ||
	       ((cur[0] >= 'a') && (cur[0] <= 'z')))
	    cur++;
    } else if (((cur[0] == 'x') && (cur[1] == '-')) ||
	       ((cur[0] == 'X') && (cur[1] == '-'))) {
	/*
	 * User code
	 */
	cur += 2;
        while (((cur[0] >= 'A') && (cur[0] <= 'Z')) ||
	       ((cur[0] >= 'a') && (cur[0] <= 'z')))
	    cur++;
    } else if (((cur[0] >= 'A') && (cur[0] <= 'Z')) ||
	       ((cur[0] >= 'a') && (cur[0] <= 'z'))) {
	/*
	 * ISO639
	 */
	cur++;
        if (((cur[0] >= 'A') && (cur[0] <= 'Z')) ||
	    ((cur[0] >= 'a') && (cur[0] <= 'z')))
	    cur++;
	else
	    return(0);
    } else
	return(0);
    while (cur[0] != 0) {
	if (cur[0] != '-')
	    return(0);
	cur++;
        if (((cur[0] >= 'A') && (cur[0] <= 'Z')) ||
	    ((cur[0] >= 'a') && (cur[0] <= 'z')))
	    cur++;
	else
	    return(0);
        while (((cur[0] >= 'A') && (cur[0] <= 'Z')) ||
	       ((cur[0] >= 'a') && (cur[0] <= 'z')))
	    cur++;
    }
    return(1);
}

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
    xmlCharEncodingHandlerPtr handler;

    handler = xmlGetCharEncodingHandler(enc);
    if (handler != NULL) {
        if (ctxt->input != NULL) {
	    if (ctxt->input->buf != NULL) {
	        if (ctxt->input->buf->encoder != NULL) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			     "xmlSwitchEncoding : encoder already regitered\n");
		    return;
		}
		ctxt->input->buf->encoder = handler;

	        /*
		 * Is there already some content down the pipe to convert
		 */
	        if ((ctxt->input->buf->buffer != NULL) &&
		    (ctxt->input->buf->buffer->use > 0)) {
		    xmlChar *buf;
		    int res, len, size;
		    int processed;

		    /*
		     * Specific handling of the Byte Order Mark for 
		     * UTF-16
		     */
		    if ((enc == XML_CHAR_ENCODING_UTF16LE) && 
		        (ctxt->input->cur[0] == 0xFF) &&
		        (ctxt->input->cur[1] == 0xFE)) {
			SKIP(2);
		    }
		    if ((enc == XML_CHAR_ENCODING_UTF16BE) && 
		        (ctxt->input->cur[0] == 0xFE) &&
		        (ctxt->input->cur[1] == 0xFF)) {
			SKIP(2);
		    }

		    /*
		     * convert the non processed part
		     */
		    processed = ctxt->input->cur - ctxt->input->base;
                    len = ctxt->input->buf->buffer->use - processed;

		    if (len <= 0) {
		        return;
		    }
		    size = ctxt->input->buf->buffer->use * 4;
		    if (size < 4000)
		        size = 4000;
retry_larger:			
		    buf = (xmlChar *) xmlMalloc(size + 1);
		    if (buf == NULL) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				 "xmlSwitchEncoding : out of memory\n");
		        return;
		    }
		    /* TODO !!! Handling of buf too small */
		    res = handler->input(buf, size, ctxt->input->cur, &len);
		    if (res == -1) {
		        size *= 2;
			xmlFree(buf);
			goto retry_larger;
		    }
		    if ((res < 0) ||
		        (len != ctxt->input->buf->buffer->use - processed)) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				 "xmlSwitchEncoding : conversion failed\n");
                        xmlFree(buf);
		        return;
		    }

		    /*
		     * Conversion succeeded, get rid of the old buffer
		     */
		    xmlFree(ctxt->input->buf->buffer->content);
		    ctxt->input->buf->buffer->content = buf;
		    ctxt->input->base = buf;
		    ctxt->input->cur = buf;
		    ctxt->input->buf->buffer->size = size;
		    ctxt->input->buf->buffer->use = res;
                    buf[res] = 0;
		}
		return;
	    } else {
	        if (ctxt->input->length == 0) {
		    /*
		     * When parsing a static memory array one must know the
		     * size to be able to convert the buffer.
		     */
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
					 "xmlSwitchEncoding : no input\n");
		    return;
		} else {
		    xmlChar *buf;
		    int res, len;
		    int processed = ctxt->input->cur - ctxt->input->base;

		    /*
		     * convert the non processed part
		     */
                    len = ctxt->input->length - processed;
		    if (len <= 0) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				 "xmlSwitchEncoding : input fully consumed?\n");
		        return;
		    }
		    buf = (xmlChar *) xmlMalloc(ctxt->input->length * 4);
		    if (buf == NULL) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				 "xmlSwitchEncoding : out of memory\n");
		        return;
		    }
		    res = handler->input(buf, ctxt->input->length * 4,
		                         ctxt->input->cur, &len);
		    if ((res < 0) ||
		        (len != ctxt->input->length - processed)) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				 "xmlSwitchEncoding : conversion failed\n");
                        xmlFree(buf);
		        return;
		    }
		    /*
		     * Conversion succeeded, get rid of the old buffer
		     */
		    if ((ctxt->input->free != NULL) &&
		        (ctxt->input->base != NULL))
			ctxt->input->free((xmlChar *) ctxt->input->base);
		    ctxt->input->base = ctxt->input->cur = buf;
		    ctxt->input->length = res;
		}
	    }
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlSwitchEncoding : no input\n");
	}
    }

    switch (enc) {
        case XML_CHAR_ENCODING_ERROR:
	    ctxt->errNo = XML_ERR_UNKNOWN_ENCODING;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "encoding unknown\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
 * a strdup for array of xmlChar's. Since they are supposed to be
 * encoded in UTF-8 or an encoding with 8bit based chars, we assume
 * a termination mark of '0'.
 *
 * Returns a new xmlChar * or NULL
 */
xmlChar *
xmlStrdup(const xmlChar *cur) {
    const xmlChar *p = cur;

    if (cur == NULL) return(NULL);
    while (*p != 0) p++;
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
 * a strcat for array of xmlChar's. Since they are supposed to be
 * encoded in UTF-8 or an encoding with 8bit based chars, we assume
 * a termination mark of '0'.
 *
 * Returns a new xmlChar * containing the concatenated string.
 */
xmlChar *
xmlStrcat(xmlChar *cur, const xmlChar *add) {
    const xmlChar *p = add;

    if (add == NULL) return(cur);
    if (cur == NULL) 
        return(xmlStrdup(add));

    while (*p != 0) p++;
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

    /*
     * Check for xml:space value.
     */
    if (*(ctxt->space) == 1)
	return(0);

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
     * Otherwise, heuristic :-\
     */
    if (ctxt->keepBlanks)
	return(0);
    if (RAW != '<') return(0);
    if (ctxt->node == NULL) return(0);
    if ((ctxt->node->children == NULL) &&
	(RAW == '<') && (NXT(1) == '/')) return(0);

    lastChild = xmlGetLastChild(ctxt->node);
    if (lastChild == NULL) {
        if (ctxt->node->content != NULL) return(0);
    } else if (xmlNodeIsText(lastChild))
        return(0);
    else if ((ctxt->node->children != NULL) &&
             (xmlNodeIsText(ctxt->node->children)))
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
	ctxt->disableSAX = 1;
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
    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
	(ctxt->sax->characters != NULL))
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
    xmlChar buf[XML_MAX_NAMELEN + 5];
    int len = 0, l;
    int cur = CUR_CHAR(l);

    /* load first the value of the char !!! */
    if (!IS_LETTER(cur) && (cur != '_')) return(NULL);

    while ((IS_LETTER(cur)) || (IS_DIGIT(cur)) ||
           (cur == '.') || (cur == '-') ||
	   (cur == '_') ||
	   (IS_COMBINING(cur)) ||
	   (IS_EXTENDER(cur))) {
	COPY_BUF(l,buf,len,cur);
	NEXTL(l);
	cur = CUR_CHAR(l);
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlNamespaceParseNCName: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(cur)) || (IS_DIGIT(cur)) ||
		   (cur == '.') || (cur == '-') ||
		   (cur == '_') ||
		   (IS_COMBINING(cur)) ||
		   (IS_EXTENDER(cur))) {
		NEXTL(l);
		cur = CUR_CHAR(l);
	    }
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
    if (RAW == ':') {
        *prefix = ret;
	NEXT;
	ret = xmlNamespaceParseNCName(ctxt);
    }

    return(ret);
}

/**
 * xmlSplitQName:
 * @ctxt:  an XML parser context
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
xmlSplitQName(xmlParserCtxtPtr ctxt, const xmlChar *name, xmlChar **prefix) {
    xmlChar buf[XML_MAX_NAMELEN + 5];
    int len = 0;
    xmlChar *ret = NULL;
    const xmlChar *cur = name;
    int c,l;

    *prefix = NULL;

    /* xml: prefix is not really a namespace */
    if ((cur[0] == 'x') && (cur[1] == 'm') &&
        (cur[2] == 'l') && (cur[3] == ':'))
	return(xmlStrdup(name));

    /* nasty but valid */
    if (cur[0] == ':')
	return(xmlStrdup(name));

    c = CUR_SCHAR(cur, l);
    if (!IS_LETTER(c) && (c != '_')) return(NULL);

    while ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
           (c == '.') || (c == '-') ||
	   (c == '_') ||
	   (IS_COMBINING(c)) ||
	   (IS_EXTENDER(c))) {
	COPY_BUF(l,buf,len,c);
	cur += l;
	c = CUR_SCHAR(cur, l);
    }
    
    ret = xmlStrndup(buf, len);

    if (c == ':') {
	cur += l;
	c = CUR_SCHAR(cur, l);
	if (!IS_LETTER(c) && (c != '_')) return(ret);
        *prefix = ret;
	len = 0;

	while ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
	       (c == '.') || (c == '-') ||
	       (c == '_') ||
	       (IS_COMBINING(c)) ||
	       (IS_EXTENDER(c))) {
	    COPY_BUF(l,buf,len,c);
	    cur += l;
	    c = CUR_SCHAR(cur, l);
	}
	
	ret = xmlStrndup(buf, len);
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

    if ((RAW == 'x') && (NXT(1) == 'm') &&
        (NXT(2) == 'l') && (NXT(3) == 'n') &&
	(NXT(4) == 's')) {
	SKIP(5);
	if (RAW == ':') {
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
    int len = 0,l;
    int size = XML_PARSER_BUFFER_SIZE;
    int c;

    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return(NULL);
    }
    if (RAW == '"') {
        NEXT;
	c = CUR_CHAR(l);
	while (IS_CHAR(c) && (c != '"')) {
	    if (len + 5 >= size) {
		size *= 2;
		buf = xmlRealloc(buf, size * sizeof(xmlChar));
		if (buf == NULL) {
		    fprintf(stderr, "realloc of %d byte failed\n", size);
		    return(NULL);
		}
	    }
	    COPY_BUF(l,buf,len,c);
	    NEXTL(l);
	    c = CUR_CHAR(l);
	}
	if (c != '"') {
	    ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
			         "String not closed \"%.50s\"\n", buf);
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
        } else {
	    NEXT;
	}
    } else if (RAW == '\''){
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
	if (RAW != '\'') {
	    ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
			         "String not closed \"%.50s\"\n", buf);
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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

    while (IS_CHAR(RAW) && (RAW != '>')) {
	/*
	 * We can have "ns" or "prefix" attributes
	 * Old encoding as 'href' or 'AS' attributes is still supported
	 */
	if ((RAW == 'n') && (NXT(1) == 's')) {
	    garbage = 0;
	    SKIP(2);
	    SKIP_BLANKS;

	    if (RAW != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    href = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((RAW == 'h') && (NXT(1) == 'r') &&
	    (NXT(2) == 'e') && (NXT(3) == 'f')) {
	    garbage = 0;
	    SKIP(4);
	    SKIP_BLANKS;

	    if (RAW != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    href = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((RAW == 'p') && (NXT(1) == 'r') &&
	           (NXT(2) == 'e') && (NXT(3) == 'f') &&
	           (NXT(4) == 'i') && (NXT(5) == 'x')) {
	    garbage = 0;
	    SKIP(6);
	    SKIP_BLANKS;

	    if (RAW != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    prefix = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((RAW == 'A') && (NXT(1) == 'S')) {
	    garbage = 0;
	    SKIP(2);
	    SKIP_BLANKS;

	    if (RAW != '=') continue;
	    NEXT;
	    SKIP_BLANKS;

	    prefix = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS;
	} else if ((RAW == '?') && (NXT(1) == '>')) {
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
	    ctxt->disableSAX = 1;
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
    if (!IS_LETTER(RAW) && (RAW != '_') &&
        (RAW != ':')) {
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
    xmlChar buf[XML_MAX_NAMELEN + 5];
    int len = 0, l;
    int c;

    GROW;
    c = CUR_CHAR(l);
    if ((c == ' ') || (c == '>') || (c == '/') || /* accelerators */
	(!IS_LETTER(c) && (c != '_') &&
         (c != ':'))) {
	return(NULL);
    }

    while ((c != ' ') && (c != '>') && (c != '/') && /* accelerators */
	   ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
            (c == '.') || (c == '-') ||
	    (c == '_') || (c == ':') || 
	    (IS_COMBINING(c)) ||
	    (IS_EXTENDER(c)))) {
	COPY_BUF(l,buf,len,c);
	NEXTL(l);
	c = CUR_CHAR(l);
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlParseName: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
		   (c == '.') || (c == '-') ||
		   (c == '_') || (c == ':') || 
		   (IS_COMBINING(c)) ||
		   (IS_EXTENDER(c))) {
		NEXTL(l);
		c = CUR_CHAR(l);
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
    xmlChar buf[XML_MAX_NAMELEN + 5];
    const xmlChar *cur = *str;
    int len = 0, l;
    int c;

    c = CUR_SCHAR(cur, l);
    if (!IS_LETTER(c) && (c != '_') &&
        (c != ':')) {
	return(NULL);
    }

    while ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
           (c == '.') || (c == '-') ||
	   (c == '_') || (c == ':') || 
	   (IS_COMBINING(c)) ||
	   (IS_EXTENDER(c))) {
	COPY_BUF(l,buf,len,c);
	cur += l;
	c = CUR_SCHAR(cur, l);
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlParseName: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
		   (c == '.') || (c == '-') ||
		   (c == '_') || (c == ':') || 
		   (IS_COMBINING(c)) ||
		   (IS_EXTENDER(c))) {
		cur += l;
		c = CUR_SCHAR(cur, l);
	    }
	    break;
	}
    }
    *str = cur;
    return(xmlStrndup(buf, len));
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
    int c,l;

    GROW;
    c = CUR_CHAR(l);
    while ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
           (c == '.') || (c == '-') ||
	   (c == '_') || (c == ':') || 
	   (IS_COMBINING(c)) ||
	   (IS_EXTENDER(c))) {
	COPY_BUF(l,buf,len,c);
	NEXTL(l);
	c = CUR_CHAR(l);
	if (len >= XML_MAX_NAMELEN) {
	    fprintf(stderr, 
	       "xmlParseNmtoken: reached XML_MAX_NAMELEN limit\n");
	    while ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
		   (c == '.') || (c == '-') ||
		   (c == '_') || (c == ':') || 
		   (IS_COMBINING(c)) ||
		   (IS_EXTENDER(c))) {
		NEXTL(l);
		c = CUR_CHAR(l);
	    }
	    break;
	}
    }
    if (len == 0)
        return(NULL);
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
    int c, l;
    xmlChar stop;
    xmlChar *ret = NULL;
    const xmlChar *cur = NULL;
    xmlParserInputPtr input;

    if (RAW == '"') stop = '"';
    else if (RAW == '\'') stop = '\'';
    else {
	ctxt->errNo = XML_ERR_ENTITY_NOT_STARTED;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "EntityValue: \" or ' expected\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    c = CUR_CHAR(l);
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
	if (len + 5 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		return(NULL);
	    }
	}
	COPY_BUF(l,buf,len,c);
	NEXTL(l);
	/*
	 * Pop-up of finished entities.
	 */
	while ((RAW == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);

	c = CUR_CHAR(l);
	if (c == 0) {
	    GROW;
	    c = CUR_CHAR(l);
	}
    }
    buf[len] = 0;

    /*
     * Raise problem w.r.t. '&' and '%' being used in non-entities
     * reference constructs. Note Charref will be handled in
     * xmlStringDecodeEntities()
     */
    cur = buf;
    while (*cur != 0) {
	if ((*cur == '%') || ((*cur == '&') && (cur[1] != '#'))) {
	    xmlChar *name;
	    xmlChar tmp = *cur;

	    cur++;
	    name = xmlParseStringName(ctxt, &cur);
            if ((name == NULL) || (*cur != ';')) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
	    "EntityValue: '%c' forbidden except for entities references\n",
	                             tmp);
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_ENTITY_CHAR_ERROR;
	    }
	    if ((ctxt->inSubset == 1) && (tmp == '%')) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
	    "EntityValue: PEReferences forbidden in internal subset\n",
	                             tmp);
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_ENTITY_PE_INTERNAL;
	    }
	    if (name != NULL)
		xmlFree(name);
	}
	cur++;
    }

    /*
     * Then PEReference entities are substituted.
     */
    if (c != stop) {
	ctxt->errNo = XML_ERR_ENTITY_NOT_FINISHED;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "EntityValue: \" expected\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	xmlFree(buf);
    } else {
	NEXT;
	/*
	 * NOTE: 4.4.7 Bypassed
	 * When a general entity reference appears in the EntityValue in
	 * an entity declaration, it is bypassed and left as is.
	 * so XML_SUBSTITUTE_REF is not set here.
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
    if (NXT(0) == '"') {
	ctxt->instate = XML_PARSER_ATTRIBUTE_VALUE;
	limit = '"';
        NEXT;
    } else if (NXT(0) == '\'') {
	limit = '\'';
	ctxt->instate = XML_PARSER_ATTRIBUTE_VALUE;
        NEXT;
    } else {
	ctxt->errNo = XML_ERR_ATTRIBUTE_NOT_STARTED;
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "AttValue: \" or ' expected\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    while (((NXT(0) != limit) && (cur != '<')) || (ctxt->token != 0)) {
	if (cur == 0) break;
        if ((cur == '&') && (NXT(1) == '#')) {
	    int val = xmlParseCharRef(ctxt);
	    *out++ = val;
	} else if (cur == '&') {
	    ent = xmlParseEntityRef(ctxt);
	    if ((ent != NULL) && 
		(ctxt->replaceEntities != 0)) {
		xmlChar *rep;

		if (ent->etype != XML_INTERNAL_PREDEFINED_ENTITY) {
		    rep = xmlStringDecodeEntities(ctxt, ent->content,
					      XML_SUBSTITUTE_REF, 0, 0, 0);
		    if (rep != NULL) {
			current = rep;
			while (*current != 0) {
			    *out++ = *current++;
			    if (out - buffer > buffer_size - 10) {
				int index = out - buffer;

				growBuffer(buffer);
				out = &buffer[index];
			    }
			}
			xmlFree(rep);
		    }
		} else {
		    if (ent->content != NULL)
			*out++ = ent->content[0];
		}
	    } else if (ent != NULL) {
		int i = xmlStrlen(ent->name);
		const xmlChar *cur = ent->name;

		/*
		 * This may look absurd but is needed to detect
		 * entities problems
		 */
		if (ent->etype != XML_INTERNAL_PREDEFINED_ENTITY) {
		    xmlChar *rep;
		    rep = xmlStringDecodeEntities(ctxt, ent->content,
					      XML_SUBSTITUTE_REF, 0, 0, 0);
		    if (rep != NULL)
			xmlFree(rep);
		}

		/*
		 * Just output the reference
		 */
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
	    /*  invalid for UTF-8 , use COPY(out); !!! */
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
    if (RAW == '<') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	       "Unescaped '<' not allowed in attributes values\n");
	ctxt->errNo = XML_ERR_LT_IN_ATTRIBUTE;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
    } else if (RAW != limit) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "AttValue: ' expected\n");
	ctxt->errNo = XML_ERR_ATTRIBUTE_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    int cur, l;
    xmlChar stop;
    int state = ctxt->instate;

    SHRINK;
    if (RAW == '"') {
        NEXT;
	stop = '"';
    } else if (RAW == '\'') {
        NEXT;
	stop = '\'';
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "SystemLiteral \" or ' expected\n");
	ctxt->errNo = XML_ERR_LITERAL_NOT_STARTED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	return(NULL);
    }
    
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return(NULL);
    }
    ctxt->instate = XML_PARSER_SYSTEM_LITERAL;
    cur = CUR_CHAR(l);
    while ((IS_CHAR(cur)) && (cur != stop)) {
	if (len + 5 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		ctxt->instate = state;
		return(NULL);
	    }
	}
	COPY_BUF(l,buf,len,cur);
	NEXTL(l);
	cur = CUR_CHAR(l);
	if (cur == 0) {
	    GROW;
	    SHRINK;
	    cur = CUR_CHAR(l);
	}
    }
    buf[len] = 0;
    ctxt->instate = state;
    if (!IS_CHAR(cur)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Unfinished SystemLiteral\n");
	ctxt->errNo = XML_ERR_LITERAL_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if (RAW == '"') {
        NEXT;
	stop = '"';
    } else if (RAW == '\'') {
        NEXT;
	stop = '\'';
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "SystemLiteral \" or ' expected\n");
	ctxt->errNo = XML_ERR_LITERAL_NOT_STARTED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
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
 * The right angle bracket (>) may be represented using the string "&gt;",
 * and must, for compatibility, be escaped using "&gt;" or a character
 * reference when it appears in the string "]]>" in content, when that
 * string is not marking the end of a CDATA section. 
 *
 * [14] CharData ::= [^<&]* - ([^<&]* ']]>' [^<&]*)
 */

void
xmlParseCharData(xmlParserCtxtPtr ctxt, int cdata) {
    xmlChar buf[XML_PARSER_BIG_BUFFER_SIZE + 5];
    int nbchar = 0;
    int cur, l;

    SHRINK;
    cur = CUR_CHAR(l);
    while (((cur != '<') || (ctxt->token == '<')) &&
           ((cur != '&') || (ctxt->token == '&')) && 
	   (IS_CHAR(cur))) {
	if ((cur == ']') && (NXT(1) == ']') &&
	    (NXT(2) == '>')) {
	    if (cdata) break;
	    else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		       "Sequence ']]>' not allowed in content\n");
		ctxt->errNo = XML_ERR_MISPLACED_CDATA_END;
		/* Should this be relaxed ??? I see a "must here */
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }
	}
	COPY_BUF(l,buf,nbchar,cur);
	if (nbchar >= XML_PARSER_BIG_BUFFER_SIZE) {
	    /*
	     * Ok the segment is to be consumed as chars.
	     */
	    if ((ctxt->sax != NULL) && (!ctxt->disableSAX)) {
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
	NEXTL(l);
	cur = CUR_CHAR(l);
    }
    if (nbchar != 0) {
	/*
	 * Ok the segment is to be consumed as chars.
	 */
	if ((ctxt->sax != NULL) && (!ctxt->disableSAX)) {
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
    if ((RAW == 'S') && (NXT(1) == 'Y') &&
         (NXT(2) == 'S') && (NXT(3) == 'T') &&
	 (NXT(4) == 'E') && (NXT(5) == 'M')) {
        SKIP(6);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Space required after 'SYSTEM'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
        SKIP_BLANKS;
	URI = xmlParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
	          "xmlParseExternalID: SYSTEM, no URI\n");
	    ctxt->errNo = XML_ERR_URI_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
        }
    } else if ((RAW == 'P') && (NXT(1) == 'U') &&
	       (NXT(2) == 'B') && (NXT(3) == 'L') &&
	       (NXT(4) == 'I') && (NXT(5) == 'C')) {
        SKIP(6);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Space required after 'PUBLIC'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
        SKIP_BLANKS;
	*publicID = xmlParsePubidLiteral(ctxt);
	if (*publicID == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "xmlParseExternalID: PUBLIC, no Public Identifier\n");
	    ctxt->errNo = XML_ERR_PUBID_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
		ctxt->disableSAX = 1;
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
	    if ((*ptr != '\'') && (*ptr != '"')) return(NULL);
	}
        SKIP_BLANKS;
	URI = xmlParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	           "xmlParseExternalID: PUBLIC, no URI\n");
	    ctxt->errNo = XML_ERR_URI_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
    int q, ql;
    int r, rl;
    int cur, l;
    xmlParserInputState state;
    xmlParserInputPtr input = ctxt->input;

    /*
     * Check that there is a comment right here.
     */
    if ((RAW != '<') || (NXT(1) != '!') ||
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
    q = CUR_CHAR(ql);
    NEXTL(ql);
    r = CUR_CHAR(rl);
    NEXTL(rl);
    cur = CUR_CHAR(l);
    while (IS_CHAR(cur) &&
           ((cur != '>') ||
	    (r != '-') || (q != '-'))) {
	if ((r == '-') && (q == '-')) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
	       "Comment must not contain '--' (double-hyphen)`\n");
	    ctxt->errNo = XML_ERR_HYPHEN_IN_COMMENT;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
	if (len + 5 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		ctxt->instate = state;
		return;
	    }
	}
	COPY_BUF(ql,buf,len,q);
	q = r;
	ql = rl;
	r = cur;
	rl = l;
	NEXTL(l);
	cur = CUR_CHAR(l);
	if (cur == 0) {
	    SHRINK;
	    GROW;
	    cur = CUR_CHAR(l);
	}
    }
    buf[len] = 0;
    if (!IS_CHAR(cur)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "Comment not terminated \n<!--%.50s\n", buf);
	ctxt->errNo = XML_ERR_COMMENT_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	xmlFree(buf);
    } else {
	if (input != ctxt->input) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
"Comment doesn't start and stop in the same entity\n");
	    ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
        NEXT;
	if ((ctxt->sax != NULL) && (ctxt->sax->comment != NULL) &&
	    (!ctxt->disableSAX))
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
	if ((name[0] == 'x') && (name[1] == 'm') &&
	    (name[2] == 'l') && (name[3] == 0)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		 "XML declaration allowed only at the start of the document\n");
	    ctxt->errNo = XML_ERR_RESERVED_XML_NAME;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return(name);
	} else if (name[3] == 0) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, "Invalid PI name\n");
	    ctxt->errNo = XML_ERR_RESERVED_XML_NAME;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return(name);
	}
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
    int cur, l;
    xmlChar *target;
    xmlParserInputState state;

    if ((RAW == '<') && (NXT(1) == '?')) {
	xmlParserInputPtr input = ctxt->input;
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
	    if ((RAW == '?') && (NXT(1) == '>')) {
		if (input != ctxt->input) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
    "PI declaration doesn't start and stop in the same entity\n");
		    ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}
		SKIP(2);

		/*
		 * SAX: PI detected.
		 */
		if ((ctxt->sax) && (!ctxt->disableSAX) &&
		    (ctxt->sax->processingInstruction != NULL))
		    ctxt->sax->processingInstruction(ctxt->userData,
		                                     target, NULL);
		ctxt->instate = state;
		xmlFree(target);
		return;
	    }
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
		ctxt->disableSAX = 1;
	    }
            SKIP_BLANKS;
	    cur = CUR_CHAR(l);
	    while (IS_CHAR(cur) &&
		   ((cur != '?') || (NXT(1) != '>'))) {
		if (len + 5 >= size) {
		    size *= 2;
		    buf = xmlRealloc(buf, size * sizeof(xmlChar));
		    if (buf == NULL) {
			fprintf(stderr, "realloc of %d byte failed\n", size);
			ctxt->instate = state;
			return;
		    }
		}
		COPY_BUF(l,buf,len,cur);
		NEXTL(l);
		cur = CUR_CHAR(l);
		if (cur == 0) {
		    SHRINK;
		    GROW;
		    cur = CUR_CHAR(l);
		}
	    }
	    buf[len] = 0;
	    if (cur != '?') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		      "xmlParsePI: PI %s never end ...\n", target);
		ctxt->errNo = XML_ERR_PI_NOT_FINISHED;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    } else {
		if (input != ctxt->input) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
    "PI declaration doesn't start and stop in the same entity\n");
		    ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}
		SKIP(2);

		/*
		 * SAX: PI detected.
		 */
		if ((ctxt->sax) && (!ctxt->disableSAX) &&
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
	    ctxt->disableSAX = 1;
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
    
    if ((RAW == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'N') && (NXT(3) == 'O') &&
        (NXT(4) == 'T') && (NXT(5) == 'A') &&
        (NXT(6) == 'T') && (NXT(7) == 'I') &&
        (NXT(8) == 'O') && (NXT(9) == 'N')) {
	xmlParserInputPtr input = ctxt->input;
	SHRINK;
	SKIP(10);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		                 "Space required after '<!NOTATION'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
	    ctxt->disableSAX = 1;
	    return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		     "Space required after the NOTATION name'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return;
	}
	SKIP_BLANKS;

	/*
	 * Parse the IDs.
	 */
	Systemid = xmlParseExternalID(ctxt, &Pubid, 0);
	SKIP_BLANKS;

	if (RAW == '>') {
	    if (input != ctxt->input) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
"Notation declaration doesn't start and stop in the same entity\n");
		ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }
	    NEXT;
	    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
		(ctxt->sax->notationDecl != NULL))
		ctxt->sax->notationDecl(ctxt->userData, name, Pubid, Systemid);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		       "'>' required to close NOTATION declaration\n");
	    ctxt->errNo = XML_ERR_NOTATION_NOT_FINISHED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
    if ((RAW == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'E') && (NXT(3) == 'N') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
        (NXT(6) == 'T') && (NXT(7) == 'Y')) {
	xmlParserInputPtr input = ctxt->input;
	ctxt->instate = XML_PARSER_ENTITY_DECL;
	SHRINK;
	SKIP(8);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		                 "Space required after '<!ENTITY'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
	SKIP_BLANKS;

	if (RAW == '%') {
	    NEXT;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "Space required after '%'\n");
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
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
	    ctxt->disableSAX = 1;
            return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		     "Space required after the entity name\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
        SKIP_BLANKS;

	/*
	 * handle the various case of definitions...
	 */
	if (isParameter) {
	    if ((RAW == '"') || (RAW == '\''))
	        value = xmlParseEntityValue(ctxt, &orig);
		if (value) {
		    if ((ctxt->sax != NULL) &&
			(!ctxt->disableSAX) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
		                    XML_INTERNAL_PARAMETER_ENTITY,
				    NULL, NULL, value);
		}
	    else {
	        URI = xmlParseExternalID(ctxt, &literal, 1);
		if ((URI == NULL) && (literal == NULL)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			    "Entity value required\n");
		    ctxt->errNo = XML_ERR_VALUE_REQUIRED;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}
		if (URI) {
		    if ((ctxt->sax != NULL) &&
			(!ctxt->disableSAX) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
		                    XML_EXTERNAL_PARAMETER_ENTITY,
				    literal, URI, NULL);
		}
	    }
	} else {
	    if ((RAW == '"') || (RAW == '\'')) {
	        value = xmlParseEntityValue(ctxt, &orig);
		if ((ctxt->sax != NULL) &&
		    (!ctxt->disableSAX) && (ctxt->sax->entityDecl != NULL))
		    ctxt->sax->entityDecl(ctxt->userData, name,
				XML_INTERNAL_GENERAL_ENTITY,
				NULL, NULL, value);
	    } else {
	        URI = xmlParseExternalID(ctxt, &literal, 1);
		if ((URI == NULL) && (literal == NULL)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			    "Entity value required\n");
		    ctxt->errNo = XML_ERR_VALUE_REQUIRED;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}
		if ((RAW != '>') && (!IS_BLANK(CUR))) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
			    "Space required before 'NDATA'\n");
		    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}
		SKIP_BLANKS;
		if ((RAW == 'N') && (NXT(1) == 'D') &&
		    (NXT(2) == 'A') && (NXT(3) == 'T') &&
		    (NXT(4) == 'A')) {
		    SKIP(5);
		    if (!IS_BLANK(CUR)) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
			        "Space required after 'NDATA'\n");
			ctxt->errNo = XML_ERR_SPACE_REQUIRED;
			ctxt->wellFormed = 0;
			ctxt->disableSAX = 1;
		    }
		    SKIP_BLANKS;
		    ndata = xmlParseName(ctxt);
		    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
		        (ctxt->sax->unparsedEntityDecl != NULL))
			ctxt->sax->unparsedEntityDecl(ctxt->userData, name,
				    literal, URI, ndata);
		} else {
		    if ((ctxt->sax != NULL) &&
		        (!ctxt->disableSAX) && (ctxt->sax->entityDecl != NULL))
			ctxt->sax->entityDecl(ctxt->userData, name,
				    XML_EXTERNAL_GENERAL_PARSED_ENTITY,
				    literal, URI, NULL);
		}
	    }
	}
	SKIP_BLANKS;
	if (RAW != '>') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	            "xmlParseEntityDecl: entity %s not terminated\n", name);
	    ctxt->errNo = XML_ERR_ENTITY_NOT_FINISHED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	} else {
	    if (input != ctxt->input) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
"Entity declaration doesn't start and stop in the same entity\n");
		ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }
	    NEXT;
	}
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
    if ((RAW == '#') && (NXT(1) == 'R') &&
        (NXT(2) == 'E') && (NXT(3) == 'Q') &&
        (NXT(4) == 'U') && (NXT(5) == 'I') &&
        (NXT(6) == 'R') && (NXT(7) == 'E') &&
        (NXT(8) == 'D')) {
	SKIP(9);
	return(XML_ATTRIBUTE_REQUIRED);
    }
    if ((RAW == '#') && (NXT(1) == 'I') &&
        (NXT(2) == 'M') && (NXT(3) == 'P') &&
        (NXT(4) == 'L') && (NXT(5) == 'I') &&
        (NXT(6) == 'E') && (NXT(7) == 'D')) {
	SKIP(8);
	return(XML_ATTRIBUTE_IMPLIED);
    }
    val = XML_ATTRIBUTE_NONE;
    if ((RAW == '#') && (NXT(1) == 'F') &&
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
	    ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
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

    if (RAW != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "'(' required to start 'NOTATION'\n");
	ctxt->errNo = XML_ERR_NOTATION_NOT_STARTED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
	    ctxt->disableSAX = 1;
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
    } while (RAW == '|');
    if (RAW != ')') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "')' required to finish NOTATION declaration\n");
	ctxt->errNo = XML_ERR_NOTATION_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	if ((last != NULL) && (last != ret))
	    xmlFreeEnumeration(last);
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

    if (RAW != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "'(' required to start ATTLIST enumeration\n");
	ctxt->errNo = XML_ERR_ATTLIST_NOT_STARTED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
	    ctxt->disableSAX = 1;
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
    } while (RAW == '|');
    if (RAW != ')') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "')' required to finish ATTLIST enumeration\n");
	ctxt->errNo = XML_ERR_ATTLIST_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if ((RAW == 'N') && (NXT(1) == 'O') &&
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
	    ctxt->disableSAX = 1;
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
    if ((RAW == 'C') && (NXT(1) == 'D') &&
        (NXT(2) == 'A') && (NXT(3) == 'T') &&
        (NXT(4) == 'A')) {
	SKIP(5);
	return(XML_ATTRIBUTE_CDATA);
     } else if ((RAW == 'I') && (NXT(1) == 'D') &&
        (NXT(2) == 'R') && (NXT(3) == 'E') &&
        (NXT(4) == 'F') && (NXT(5) == 'S')) {
	SKIP(6);
	return(XML_ATTRIBUTE_IDREFS);
     } else if ((RAW == 'I') && (NXT(1) == 'D') &&
        (NXT(2) == 'R') && (NXT(3) == 'E') &&
        (NXT(4) == 'F')) {
	SKIP(5);
	return(XML_ATTRIBUTE_IDREF);
     } else if ((RAW == 'I') && (NXT(1) == 'D')) {
        SKIP(2);
	return(XML_ATTRIBUTE_ID);
     } else if ((RAW == 'E') && (NXT(1) == 'N') &&
        (NXT(2) == 'T') && (NXT(3) == 'I') &&
        (NXT(4) == 'T') && (NXT(5) == 'Y')) {
	SKIP(6);
	return(XML_ATTRIBUTE_ENTITY);
     } else if ((RAW == 'E') && (NXT(1) == 'N') &&
        (NXT(2) == 'T') && (NXT(3) == 'I') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
        (NXT(6) == 'E') && (NXT(7) == 'S')) {
	SKIP(8);
	return(XML_ATTRIBUTE_ENTITIES);
     } else if ((RAW == 'N') && (NXT(1) == 'M') &&
        (NXT(2) == 'T') && (NXT(3) == 'O') &&
        (NXT(4) == 'K') && (NXT(5) == 'E') &&
        (NXT(6) == 'N') && (NXT(7) == 'S')) {
	SKIP(8);
	return(XML_ATTRIBUTE_NMTOKENS);
     } else if ((RAW == 'N') && (NXT(1) == 'M') &&
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

    if ((RAW == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'A') && (NXT(3) == 'T') &&
        (NXT(4) == 'T') && (NXT(5) == 'L') &&
        (NXT(6) == 'I') && (NXT(7) == 'S') &&
        (NXT(8) == 'T')) {
	xmlParserInputPtr input = ctxt->input;

	SKIP(9);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "Space required after '<!ATTLIST'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
        SKIP_BLANKS;
        elemName = xmlParseName(ctxt);
	if (elemName == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "ATTLIST: no name for Element\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return;
	}
	SKIP_BLANKS;
	while (RAW != '>') {
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
		ctxt->disableSAX = 1;
		break;
	    }
	    GROW;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		        "Space required after the attribute name\n");
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
                if (attrName != NULL)
		    xmlFree(attrName);
                if (defaultValue != NULL)
		    xmlFree(defaultValue);
		break;
	    }
	    SKIP_BLANKS;

	    type = xmlParseAttributeType(ctxt, &tree);
	    if (type <= 0) {
                if (attrName != NULL)
		    xmlFree(attrName);
                if (defaultValue != NULL)
		    xmlFree(defaultValue);
	        break;
	    }

	    GROW;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		        "Space required after the attribute type\n");
		ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
                if (attrName != NULL)
		    xmlFree(attrName);
                if (defaultValue != NULL)
		    xmlFree(defaultValue);
	        if (tree != NULL)
		    xmlFreeEnumeration(tree);
		break;
	    }
	    SKIP_BLANKS;

	    def = xmlParseDefaultDecl(ctxt, &defaultValue);
	    if (def <= 0) {
                if (attrName != NULL)
		    xmlFree(attrName);
                if (defaultValue != NULL)
		    xmlFree(defaultValue);
	        if (tree != NULL)
		    xmlFreeEnumeration(tree);
	        break;
	    }

	    GROW;
            if (RAW != '>') {
		if (!IS_BLANK(CUR)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
			"Space required after the attribute default value\n");
		    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		    if (attrName != NULL)
			xmlFree(attrName);
		    if (defaultValue != NULL)
			xmlFree(defaultValue);
		    if (tree != NULL)
			xmlFreeEnumeration(tree);
		    break;
		}
		SKIP_BLANKS;
	    }
	    if (check == CUR_PTR) {
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		    "xmlParseAttributeListDecl: detected internal error\n");
		ctxt->errNo = XML_ERR_INTERNAL_ERROR;
		if (attrName != NULL)
		    xmlFree(attrName);
		if (defaultValue != NULL)
		    xmlFree(defaultValue);
	        if (tree != NULL)
		    xmlFreeEnumeration(tree);
		break;
	    }
	    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
		(ctxt->sax->attributeDecl != NULL))
		ctxt->sax->attributeDecl(ctxt->userData, elemName, attrName,
	                        type, def, defaultValue, tree);
	    if (attrName != NULL)
		xmlFree(attrName);
	    if (defaultValue != NULL)
	        xmlFree(defaultValue);
	    GROW;
	}
	if (RAW == '>') {
	    if (input != ctxt->input) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
"Attribute list declaration doesn't start and stop in the same entity\n");
		ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }
	    NEXT;
	}

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
    if ((RAW == '#') && (NXT(1) == 'P') &&
        (NXT(2) == 'C') && (NXT(3) == 'D') &&
        (NXT(4) == 'A') && (NXT(5) == 'T') &&
        (NXT(6) == 'A')) {
	SKIP(7);
	SKIP_BLANKS;
	SHRINK;
	if (RAW == ')') {
	    ctxt->entity = ctxt->input;
	    NEXT;
	    ret = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_PCDATA);
	    if (RAW == '*') {
		ret->ocur = XML_ELEMENT_CONTENT_MULT;
		NEXT;
	    }
	    return(ret);
	}
	if ((RAW == '(') || (RAW == '|')) {
	    ret = cur = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_PCDATA);
	    if (ret == NULL) return(NULL);
	}
	while (RAW == '|') {
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
		ctxt->disableSAX = 1;
		xmlFreeElementContent(cur);
		return(NULL);
	    }
	    SKIP_BLANKS;
	    GROW;
	}
	if ((RAW == ')') && (NXT(1) == '*')) {
	    if (elem != NULL) {
		cur->c2 = xmlNewElementContent(elem,
		                               XML_ELEMENT_CONTENT_ELEMENT);
	        xmlFree(elem);
            }
	    ret->ocur = XML_ELEMENT_CONTENT_MULT;
	    ctxt->entity = ctxt->input;
	    SKIP(2);
	} else {
	    if (elem != NULL) xmlFree(elem);
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "xmlParseElementMixedContentDecl : '|' or ')*' expected\n");
	    ctxt->errNo = XML_ERR_MIXED_NOT_STARTED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    xmlFreeElementContent(ret);
	    return(NULL);
	}

    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementMixedContentDecl : '#PCDATA' expected\n");
	ctxt->errNo = XML_ERR_PCDATA_REQUIRED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if (RAW == '(') {
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
	    ctxt->disableSAX = 1;
	    return(NULL);
	}
        cur = ret = xmlNewElementContent(elem, XML_ELEMENT_CONTENT_ELEMENT);
	GROW;
	if (RAW == '?') {
	    cur->ocur = XML_ELEMENT_CONTENT_OPT;
	    NEXT;
	} else if (RAW == '*') {
	    cur->ocur = XML_ELEMENT_CONTENT_MULT;
	    NEXT;
	} else if (RAW == '+') {
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
    while (RAW != ')') {
        /*
	 * Each loop we parse one separator and one element.
	 */
        if (RAW == ',') {
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
		ctxt->disableSAX = 1;
		if ((op != NULL) && (op != ret))
		    xmlFreeElementContent(op);
		if ((last != NULL) && (last != ret))
		    xmlFreeElementContent(last);
		if (ret != NULL)
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
	} else if (RAW == '|') {
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
		ctxt->disableSAX = 1;
		if ((op != NULL) && (op != ret))
		    xmlFreeElementContent(op);
		if ((last != NULL) && (last != ret))
		    xmlFreeElementContent(last);
		if (ret != NULL)
		    xmlFreeElementContent(ret);
		return(NULL);
	    }
	    NEXT;

	    op = xmlNewElementContent(NULL, XML_ELEMENT_CONTENT_OR);
	    if (op == NULL) {
		if ((op != NULL) && (op != ret))
		    xmlFreeElementContent(op);
		if ((last != NULL) && (last != ret))
		    xmlFreeElementContent(last);
		if (ret != NULL)
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
	    ctxt->disableSAX = 1;
	    ctxt->errNo = XML_ERR_ELEMCONTENT_NOT_FINISHED;
	    if ((op != NULL) && (op != ret))
		xmlFreeElementContent(op);
	    if ((last != NULL) && (last != ret))
		xmlFreeElementContent(last);
	    if (ret != NULL)
		xmlFreeElementContent(ret);
	    return(NULL);
	}
	GROW;
	SKIP_BLANKS;
	GROW;
	if (RAW == '(') {
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
		ctxt->disableSAX = 1;
		if ((op != NULL) && (op != ret))
		    xmlFreeElementContent(op);
		if ((last != NULL) && (last != ret))
		    xmlFreeElementContent(last);
		if (ret != NULL)
		    xmlFreeElementContent(ret);
		return(NULL);
	    }
	    last = xmlNewElementContent(elem, XML_ELEMENT_CONTENT_ELEMENT);
	    xmlFree(elem);
	    if (RAW == '?') {
		last->ocur = XML_ELEMENT_CONTENT_OPT;
		NEXT;
	    } else if (RAW == '*') {
		last->ocur = XML_ELEMENT_CONTENT_MULT;
		NEXT;
	    } else if (RAW == '+') {
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
    ctxt->entity = ctxt->input;
    NEXT;
    if (RAW == '?') {
        ret->ocur = XML_ELEMENT_CONTENT_OPT;
	NEXT;
    } else if (RAW == '*') {
        ret->ocur = XML_ELEMENT_CONTENT_MULT;
	NEXT;
    } else if (RAW == '+') {
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
    xmlParserInputPtr input = ctxt->input;
    int res;

    *result = NULL;

    if (RAW != '(') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementContentDecl : '(' expected\n");
	ctxt->errNo = XML_ERR_ELEMCONTENT_NOT_STARTED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	return(-1);
    }
    NEXT;
    GROW;
    SKIP_BLANKS;
    if ((RAW == '#') && (NXT(1) == 'P') &&
        (NXT(2) == 'C') && (NXT(3) == 'D') &&
        (NXT(4) == 'A') && (NXT(5) == 'T') &&
        (NXT(6) == 'A')) {
        tree = xmlParseElementMixedContentDecl(ctxt);
	res = XML_ELEMENT_TYPE_MIXED;
    } else {
        tree = xmlParseElementChildrenContentDecl(ctxt);
	res = XML_ELEMENT_TYPE_ELEMENT;
    }
    if ((ctxt->entity != NULL) && (input != ctxt->entity)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
"Element content declaration doesn't start and stop in the same entity\n");
	ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
    }
    SKIP_BLANKS;
    /****************************
    if (RAW != ')') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
		"xmlParseElementContentDecl : ')' expected\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if ((RAW == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'E') && (NXT(3) == 'L') &&
        (NXT(4) == 'E') && (NXT(5) == 'M') &&
        (NXT(6) == 'E') && (NXT(7) == 'N') &&
        (NXT(8) == 'T')) {
	xmlParserInputPtr input = ctxt->input;

	SKIP(9);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "Space required after 'ELEMENT'\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
        SKIP_BLANKS;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		   "xmlParseElementDecl: no name for Element\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return(-1);
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData, 
		    "Space required after the element name\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
        SKIP_BLANKS;
	if ((RAW == 'E') && (NXT(1) == 'M') &&
	    (NXT(2) == 'P') && (NXT(3) == 'T') &&
	    (NXT(4) == 'Y')) {
	    SKIP(5);
	    /*
	     * Element must always be empty.
	     */
	    ret = XML_ELEMENT_TYPE_EMPTY;
	} else if ((RAW == 'A') && (NXT(1) == 'N') &&
	           (NXT(2) == 'Y')) {
	    SKIP(3);
	    /*
	     * Element is a generic container.
	     */
	    ret = XML_ELEMENT_TYPE_ANY;
	} else if (RAW == '(') {
	    ret = xmlParseElementContentDecl(ctxt, name, &content);
	} else {
	    /*
	     * [ WFC: PEs in Internal Subset ] error handling.
	     */
	    if ((RAW == '%') && (ctxt->external == 0) &&
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
	    ctxt->disableSAX = 1;
	    if (name != NULL) xmlFree(name);
	    return(-1);
	}

	SKIP_BLANKS;
	/*
	 * Pop-up of finished entities.
	 */
	while ((RAW == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);
	SKIP_BLANKS;

	if (RAW != '>') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "xmlParseElementDecl: expected '>' at the end\n");
	    ctxt->errNo = XML_ERR_GT_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	} else {
	    if (input != ctxt->input) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
"Element declaration doesn't start and stop in the same entity\n");
		ctxt->errNo = XML_ERR_ENTITY_BOUNDARY;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }
		
	    NEXT;
	    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
		(ctxt->sax->elementDecl != NULL))
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
 * Question: Seems that EncodingDecl is mandatory ? Is that a typo ?
 */

void
xmlParseTextDecl(xmlParserCtxtPtr ctxt) {
    xmlChar *version;

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
	ctxt->disableSAX = 1;
    }
    SKIP_BLANKS;

    /*
     * We may have the VersionInfo here.
     */
    version = xmlParseVersionInfo(ctxt);
    if (version == NULL)
	version = xmlCharStrdup(XML_DEFAULT_VERSION);
    ctxt->input->version = version;

    /*
     * We must have the encoding declaration
     */
    if (!IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Space needed here\n");
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
    }
    ctxt->input->encoding = xmlParseEncodingDecl(ctxt);

    SKIP_BLANKS;
    if ((RAW == '?') && (NXT(1) == '>')) {
        SKIP(2);
    } else if (RAW == '>') {
        /* Deprecated old WD ... */
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "XML declaration must end-up with '?>'\n");
	ctxt->errNo = XML_ERR_XMLDECL_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "parsing XML declaration: '?>' expected\n");
	ctxt->errNo = XML_ERR_XMLDECL_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	MOVETO_ENDTAG(CUR_PTR);
	NEXT;
    }
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
    SKIP(3);
    SKIP_BLANKS;
    if ((RAW == 'I') && (NXT(1) == 'N') && (NXT(2) == 'C') &&
        (NXT(3) == 'L') && (NXT(4) == 'U') && (NXT(5) == 'D') &&
        (NXT(6) == 'E')) {
	SKIP(7);
	SKIP_BLANKS;
	if (RAW != '[') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
	    "XML conditional section '[' expected\n");
	    ctxt->errNo = XML_ERR_CONDSEC_INVALID;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	} else {
	    NEXT;
	}
	while ((RAW != 0) && ((RAW != ']') || (NXT(1) != ']') ||
	       (NXT(2) != '>'))) {
	    const xmlChar *check = CUR_PTR;
	    int cons = ctxt->input->consumed;
	    int tok = ctxt->token;

	    if ((RAW == '<') && (NXT(1) == '!') && (NXT(2) == '[')) {
		xmlParseConditionalSections(ctxt);
	    } else if (IS_BLANK(CUR)) {
		NEXT;
	    } else if (RAW == '%') {
		xmlParsePEReference(ctxt);
	    } else
		xmlParseMarkupDecl(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((RAW == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

	    if ((CUR_PTR == check) && (cons == ctxt->input->consumed) &&
		(tok == ctxt->token)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
			"Content error in the external subset\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_EXT_SUBSET_NOT_FINISHED;
		break;
	    }
	}
    } else if ((RAW == 'I') && (NXT(1) == 'G') && (NXT(2) == 'N') &&
            (NXT(3) == 'O') && (NXT(4) == 'R') && (NXT(5) == 'E')) {
	int state;

	SKIP(6);
	SKIP_BLANKS;
	if (RAW != '[') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
	    "XML conditional section '[' expected\n");
	    ctxt->errNo = XML_ERR_CONDSEC_INVALID;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	} else {
	    NEXT;
	}

	/*
	 * Parse up to the end of the conditionnal section
	 * But disable SAX event generating DTD building in the meantime
	 */
	state = ctxt->disableSAX;
	while ((RAW != 0) && ((RAW != ']') || (NXT(1) != ']') ||
	       (NXT(2) != '>'))) {
	    const xmlChar *check = CUR_PTR;
	    int cons = ctxt->input->consumed;
	    int tok = ctxt->token;

	    if ((RAW == '<') && (NXT(1) == '!') && (NXT(2) == '[')) {
		xmlParseConditionalSections(ctxt);
	    } else if (IS_BLANK(CUR)) {
		NEXT;
	    } else if (RAW == '%') {
		xmlParsePEReference(ctxt);
	    } else
		xmlParseMarkupDecl(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((RAW == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

	    if ((CUR_PTR == check) && (cons == ctxt->input->consumed) &&
		(tok == ctxt->token)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
			"Content error in the external subset\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_EXT_SUBSET_NOT_FINISHED;
		break;
	    }
	}
	ctxt->disableSAX = state;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	"XML conditional section INCLUDE or IGNORE keyword expected\n");
	ctxt->errNo = XML_ERR_CONDSEC_INVALID;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
    }

    if (RAW == 0)
        SHRINK;

    if (RAW == 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	        "XML conditional section not closed\n");
	ctxt->errNo = XML_ERR_CONDSEC_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if ((RAW == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l')) {
	xmlParseTextDecl(ctxt);
    }
    if (ctxt->myDoc == NULL) {
        ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
    }
    if ((ctxt->myDoc != NULL) && (ctxt->myDoc->intSubset == NULL))
        xmlCreateIntSubset(ctxt->myDoc, NULL, ExternalID, SystemID);

    ctxt->instate = XML_PARSER_DTD;
    ctxt->external = 1;
    while (((RAW == '<') && (NXT(1) == '?')) ||
           ((RAW == '<') && (NXT(1) == '!')) ||
           IS_BLANK(CUR)) {
	const xmlChar *check = CUR_PTR;
	int cons = ctxt->input->consumed;
	int tok = ctxt->token;

        if ((RAW == '<') && (NXT(1) == '!') && (NXT(2) == '[')) {
	    xmlParseConditionalSections(ctxt);
	} else if (IS_BLANK(CUR)) {
	    NEXT;
	} else if (RAW == '%') {
            xmlParsePEReference(ctxt);
	} else
	    xmlParseMarkupDecl(ctxt);

	/*
	 * Pop-up of finished entities.
	 */
	while ((RAW == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);

	if ((CUR_PTR == check) && (cons == ctxt->input->consumed) &&
	    (tok == ctxt->token)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Content error in the external subset\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    ctxt->errNo = XML_ERR_EXT_SUBSET_NOT_FINISHED;
	    break;
	}
    }
    
    if (RAW != 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	        "Extra content at the end of the document\n");
	ctxt->errNo = XML_ERR_EXT_SUBSET_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if (RAW != '&') return;

    if (ctxt->inputNr > 1) {
        xmlChar cur[2] = { '&' , 0 } ;

	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL) &&
	    (!ctxt->disableSAX))
	    ctxt->sax->characters(ctxt->userData, cur, 1);
	if (ctxt->token == '&')
	    ctxt->token = 0;
        else {
	    SKIP(1);
	}
	return;
    }
    if (NXT(1) == '#') {
	int i = 0;
	xmlChar out[10];
	int hex = NXT(2);
	int val = xmlParseCharRef(ctxt);
	
	if (ctxt->encoding != NULL) {
	    /*
	     * So we are using non-UTF-8 buffers
	     * Check that the char fit on 8bits, if not
	     * generate a CharRef.
	     */
	    if (val <= 0xFF) {
		out[0] = val;
		out[1] = 0;
		if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL) &&
		    (!ctxt->disableSAX))
		    ctxt->sax->characters(ctxt->userData, out, 1);
	    } else {
		if ((hex == 'x') || (hex == 'X'))
		    sprintf((char *)out, "#x%X", val);
		else
		    sprintf((char *)out, "#%d", val);
		if ((ctxt->sax != NULL) && (ctxt->sax->reference != NULL) &&
		    (!ctxt->disableSAX))
		    ctxt->sax->reference(ctxt->userData, out);
	    }
	} else {
	    /*
	     * Just encode the value in UTF-8
	     */
	    COPY_BUF(0 ,out, i, val);
	    out[i] = 0;
	    if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL) &&
		(!ctxt->disableSAX))
		ctxt->sax->characters(ctxt->userData, out, i);
	}
    } else {
	ent = xmlParseEntityRef(ctxt);
	if (ent == NULL) return;
	if ((ent->name != NULL) && 
	    (ent->etype != XML_INTERNAL_PREDEFINED_ENTITY)) {
	    xmlNodePtr list = NULL;
	    int ret;


	    /*
	     * The first reference to the entity trigger a parsing phase
	     * where the ent->children is filled with the result from
	     * the parsing.
	     */
	    if (ent->children == NULL) {
		xmlChar *value;
		value = ent->content;

		/*
		 * Check that this entity is well formed
		 */
		if ((value != NULL) &&
		    (value[1] == 0) && (value[0] == '<') &&
		    (!xmlStrcmp(ent->name, BAD_CAST "lt"))) {
		    /*
		     * TODO: get definite answer on this !!!
		     * Lots of entity decls are used to declare a single
		     * char 
		     *    <!ENTITY lt     "<">
		     * Which seems to be valid since
		     * 2.4: The ampersand character (&) and the left angle
		     * bracket (<) may appear in their literal form only
		     * when used ... They are also legal within the literal
		     * entity value of an internal entity declaration;i
		     * see "4.3.2 Well-Formed Parsed Entities". 
		     * IMHO 2.4 and 4.3.2 are directly in contradiction.
		     * Looking at the OASIS test suite and James Clark 
		     * tests, this is broken. However the XML REC uses
		     * it. Is the XML REC not well-formed ????
		     * This is a hack to avoid this problem
		     */
		    list = xmlNewDocText(ctxt->myDoc, value);
		    if (list != NULL) {
			if ((ent->etype == XML_INTERNAL_GENERAL_ENTITY) &&
			    (ent->children == NULL)) {
			    ent->children = list;
			    ent->last = list;
			    list->parent = (xmlNodePtr) ent;
			} else {
			    xmlFreeNodeList(list);
			}
		    } else if (list != NULL) {
			xmlFreeNodeList(list);
		    }
		} else {
		    /*
		     * 4.3.2: An internal general parsed entity is well-formed
		     * if its replacement text matches the production labeled
		     * content.
		     */
		    if (ent->etype == XML_INTERNAL_GENERAL_ENTITY) {
			ctxt->depth++;
			ret = xmlParseBalancedChunkMemory(ctxt->myDoc,
				           ctxt->sax, NULL, ctxt->depth,
					   value, &list);
			ctxt->depth--;
		    } else if (ent->etype ==
			       XML_EXTERNAL_GENERAL_PARSED_ENTITY) {
			ctxt->depth++;
			ret = xmlParseExternalEntity(ctxt->myDoc,
				   ctxt->sax, NULL, ctxt->depth,
				   ent->SystemID, ent->ExternalID, &list);
			ctxt->depth--;
		    } else {
			ret = -1;
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				"Internal: invalid entity type\n");
		    }
		    if (ret == XML_ERR_ENTITY_LOOP) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				"Detected entity reference loop\n");
			ctxt->wellFormed = 0;
			ctxt->disableSAX = 1;
			ctxt->errNo = XML_ERR_ENTITY_LOOP;
		    } else if ((ret == 0) && (list != NULL)) {
			if ((ent->etype == XML_INTERNAL_GENERAL_ENTITY) &&
			    (ent->children == NULL)) {
			    ent->children = list;
			    while (list != NULL) {
				list->parent = (xmlNodePtr) ent;
				if (list->next == NULL)
				    ent->last = list;
				list = list->next;
			    }
			} else {
			    xmlFreeNodeList(list);
			}
		    } else if (ret > 0) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
				"Entity value required\n");
			ctxt->errNo = ret;
			ctxt->wellFormed = 0;
			ctxt->disableSAX = 1;
		    } else if (list != NULL) {
			xmlFreeNodeList(list);
		    }
		}
	    }
	    if ((ctxt->sax != NULL) && (ctxt->sax->reference != NULL) &&
		(ctxt->replaceEntities == 0) && (!ctxt->disableSAX)) {
		/*
		 * Create a node.
		 */
		ctxt->sax->reference(ctxt->userData, ent->name);
		return;
	    } else if (ctxt->replaceEntities) {
		xmlParserInputPtr input;

		input = xmlNewEntityInputStream(ctxt, ent);
		xmlPushInput(ctxt, input);
		if ((ent->etype == XML_EXTERNAL_GENERAL_PARSED_ENTITY) &&
		    (RAW == '<') && (NXT(1) == '?') &&
		    (NXT(2) == 'x') && (NXT(3) == 'm') &&
		    (NXT(4) == 'l') && (IS_BLANK(NXT(5)))) {
		    xmlParseTextDecl(ctxt);
		    if (input->standalone) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData,
			    "external parsed entities cannot be standalone\n");
			ctxt->errNo = XML_ERR_EXT_ENTITY_STANDALONE;
			ctxt->wellFormed = 0;
			ctxt->disableSAX = 1;
		    }
		}
		/*
		 * !!! TODO: build the tree under the entity first
		 * 1234
		 */
		return;
	    }
	}
	val = ent->content;
	if (val == NULL) return;
	/*
	 * inline the entity.
	 */
	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL) &&
	    (!ctxt->disableSAX))
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
    
    if (RAW == '&') {
        NEXT;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseEntityRef: no name\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	} else {
	    if (RAW == ';') {
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
			ctxt->disableSAX = 1;
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
		else if (ent->etype == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
			     "Entity reference to unparsed entity %s\n", name);
		    ctxt->errNo = XML_ERR_UNPARSED_ENTITY;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}

		/*
		 * [ WFC: No External Entity References ]
		 * Attribute values cannot contain direct or indirect
		 * entity references to external entities.
		 */
		else if ((ctxt->instate == XML_PARSER_ATTRIBUTE_VALUE) &&
		         (ent->etype == XML_EXTERNAL_GENERAL_PARSED_ENTITY)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
		     "Attribute references external entity '%s'\n", name);
		    ctxt->errNo = XML_ERR_ENTITY_IS_EXTERNAL;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
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
		    ctxt->disableSAX = 1;
		}

		/*
		 * Internal check, no parameter entities here ...
		 */
		else {
		    switch (ent->etype) {
			case XML_INTERNAL_PARAMETER_ENTITY:
			case XML_EXTERNAL_PARAMETER_ENTITY:
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
		     "Attempt to reference the parameter entity '%s'\n", name);
			ctxt->errNo = XML_ERR_ENTITY_IS_PARAMETER;
			ctxt->wellFormed = 0;
			ctxt->disableSAX = 1;
			break;
			default:
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
		ctxt->disableSAX = 1;
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

    if ((str == NULL) || (*str == NULL))
        return(NULL);
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
	    ctxt->disableSAX = 1;
	} else {
	    if (*ptr == ';') {
	        ptr++;
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
			ctxt->disableSAX = 1;
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
		else if (ent->etype == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
			     "Entity reference to unparsed entity %s\n", name);
		    ctxt->errNo = XML_ERR_UNPARSED_ENTITY;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		}

		/*
		 * [ WFC: No External Entity References ]
		 * Attribute values cannot contain direct or indirect
		 * entity references to external entities.
		 */
		else if ((ctxt->instate == XML_PARSER_ATTRIBUTE_VALUE) &&
		         (ent->etype == XML_EXTERNAL_GENERAL_PARSED_ENTITY)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, 
		     "Attribute references external entity '%s'\n", name);
		    ctxt->errNo = XML_ERR_ENTITY_IS_EXTERNAL;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
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
		    ctxt->disableSAX = 1;
		}

		/*
		 * Internal check, no parameter entities here ...
		 */
		else {
		    switch (ent->etype) {
			case XML_INTERNAL_PARAMETER_ENTITY:
			case XML_EXTERNAL_PARAMETER_ENTITY:
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt->userData, 
		     "Attempt to reference the parameter entity '%s'\n", name);
			ctxt->errNo = XML_ERR_ENTITY_IS_PARAMETER;
			ctxt->wellFormed = 0;
			ctxt->disableSAX = 1;
			break;
			default:
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
		ctxt->disableSAX = 1;
	    }
	    xmlFree(name);
	}
    }
    *str = ptr;
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

    if (RAW == '%') {
        NEXT;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParsePEReference: no name\n");
	    ctxt->errNo = XML_ERR_NAME_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	} else {
	    if (RAW == ';') {
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
			ctxt->disableSAX = 1;
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
		    if ((entity->etype != XML_INTERNAL_PARAMETER_ENTITY) &&
		        (entity->etype != XML_EXTERNAL_PARAMETER_ENTITY)) {
			if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
			    ctxt->sax->warning(ctxt->userData,
			 "Internal: %%%s; is not a parameter entity\n", name);
		    } else {
			/*
			 * TODO !!!
			 * handle the extra spaces added before and after
			 * c.f. http://www.w3.org/TR/REC-xml#as-PE
			 */
			input = xmlNewEntityInputStream(ctxt, entity);
			xmlPushInput(ctxt, input);
			if ((entity->etype == XML_EXTERNAL_PARAMETER_ENTITY) &&
			    (RAW == '<') && (NXT(1) == '?') &&
			    (NXT(2) == 'x') && (NXT(3) == 'm') &&
			    (NXT(4) == 'l') && (IS_BLANK(NXT(5)))) {
			    xmlParseTextDecl(ctxt);
			}
			if (ctxt->token == 0)
			    ctxt->token = ' ';
		    }
		}
		ctxt->hasPErefs = 1;
	    } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "xmlParsePEReference: expecting ';'\n");
		ctxt->errNo = XML_ERR_ENTITYREF_SEMICOL_MISSING;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
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
	    ctxt->disableSAX = 1;
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
			ctxt->disableSAX = 1;
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
		    if ((entity->etype != XML_INTERNAL_PARAMETER_ENTITY) &&
		        (entity->etype != XML_EXTERNAL_PARAMETER_ENTITY)) {
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
		ctxt->disableSAX = 1;
	    }
	    xmlFree(name);
	}
    }
    *str = ptr;
    return(entity);
}

/**
 * xmlParseDocTypeDecl:
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
    xmlChar *name = NULL;
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
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_NAME_REQUIRED;
    }
    ctxt->intSubName = name;

    SKIP_BLANKS;

    /*
     * Check for SystemID and ExternalID
     */
    URI = xmlParseExternalID(ctxt, &ExternalID, 1);

    if ((URI != NULL) || (ExternalID != NULL)) {
        ctxt->hasExternalSubset = 1;
    }
    ctxt->extSubURI = URI;
    ctxt->extSubSystem = ExternalID;

    SKIP_BLANKS;

    /*
     * Create and update the internal subset.
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->internalSubset != NULL) &&
	(!ctxt->disableSAX))
	ctxt->sax->internalSubset(ctxt->userData, name, ExternalID, URI);

    /*
     * Is there any internal subset declarations ?
     * they are handled separately in xmlParseInternalSubset()
     */
    if (RAW == '[')
	return;

    /*
     * We should be at the end of the DOCTYPE declaration.
     */
    if (RAW != '>') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "DOCTYPE unproperly terminated\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_DOCTYPE_NOT_FINISHED;
    }
    NEXT;
}

/**
 * xmlParseInternalsubset:
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
    if (RAW == '[') {
        ctxt->instate = XML_PARSER_DTD;
        NEXT;
	/*
	 * Parse the succession of Markup declarations and 
	 * PEReferences.
	 * Subsequence (markupdecl | PEReference | S)*
	 */
	while (RAW != ']') {
	    const xmlChar *check = CUR_PTR;
	    int cons = ctxt->input->consumed;

	    SKIP_BLANKS;
	    xmlParseMarkupDecl(ctxt);
	    xmlParsePEReference(ctxt);

	    /*
	     * Pop-up of finished entities.
	     */
	    while ((RAW == 0) && (ctxt->inputNr > 1))
		xmlPopInput(ctxt);

	    if ((CUR_PTR == check) && (cons == ctxt->input->consumed)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
	     "xmlParseInternalSubset: error detected in Markup declaration\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_INTERNAL_ERROR;
		break;
	    }
	}
	if (RAW == ']') NEXT;
    }

    /*
     * We should be at the end of the DOCTYPE declaration.
     */
    if (RAW != '>') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "DOCTYPE unproperly terminated\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_NAME_REQUIRED;
        return(NULL);
    }

    /*
     * read the value
     */
    SKIP_BLANKS;
    if (RAW == '=') {
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
	ctxt->disableSAX = 1;
	xmlFree(name);
	return(NULL);
    }

    /*
     * Check that xml:lang conforms to the specification
     */
    if (!xmlStrcmp(name, BAD_CAST "xml:lang")) {
	if (!xmlCheckLanguageID(val)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		   "Invalid value for xml:lang : %s\n", val);
	    ctxt->errNo = XML_ERR_ATTRIBUTE_WITHOUT_VALUE;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
    }

    /*
     * Check that xml:space conforms to the specification
     */
    if (!xmlStrcmp(name, BAD_CAST "xml:space")) {
	if (!xmlStrcmp(val, BAD_CAST "default"))
	    *(ctxt->space) = 0;
	else if (!xmlStrcmp(val, BAD_CAST "preserve"))
	    *(ctxt->space) = 1;
	else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
"Invalid value for xml:space : \"%s\", \"default\" or \"preserve\" expected\n",
                                 val);
	    ctxt->errNo = XML_ERR_ATTRIBUTE_WITHOUT_VALUE;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
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

    if (RAW != '<') return(NULL);
    NEXT;

    name = xmlParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	     "xmlParseStartTag: invalid element name\n");
	ctxt->errNo = XML_ERR_NAME_REQUIRED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
        return(NULL);
    }

    /*
     * Now parse the attributes, it ends up with the ending
     *
     * (S Attribute)* S?
     */
    SKIP_BLANKS;
    GROW;

    while ((IS_CHAR(RAW)) &&
           (RAW != '>') && 
	   ((RAW != '/') || (NXT(1) != '>'))) {
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
		    ctxt->disableSAX = 1;
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
	} else {
	    if (attname != NULL)
		xmlFree(attname);
	    if (attvalue != NULL)
		xmlFree(attvalue);
	}

failed:     

	if ((RAW == '>') || (((RAW == '/') && (NXT(1) == '>'))))
	    break;
	if (!IS_BLANK(RAW)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "attributes construct error\n");
	    ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	}
	SKIP_BLANKS;
        if ((cons == ctxt->input->consumed) && (q == CUR_PTR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	         "xmlParseStartTag: problem parsing attributes\n");
	    ctxt->errNo = XML_ERR_INTERNAL_ERROR;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    break;
	}
        GROW;
    }

    /*
     * SAX: Start of Element !
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->startElement != NULL) &&
	(!ctxt->disableSAX))
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
    if ((RAW != '<') || (NXT(1) != '/')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "xmlParseEndTag: '</' not found\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if ((!IS_CHAR(RAW)) || (RAW != '>')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "End tag : expected '>'\n");
	ctxt->errNo = XML_ERR_GT_REQUIRED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
	ctxt->disableSAX = 1;
    }

    /*
     * SAX: End of Tag
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL) &&
	(!ctxt->disableSAX))
        ctxt->sax->endElement(ctxt->userData, name);

    if (name != NULL)
	xmlFree(name);
    oldname = namePop(ctxt);
    spacePop(ctxt);
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
    int r, rl;
    int	s, sl;
    int cur, l;

    if ((NXT(0) == '<') && (NXT(1) == '!') &&
	(NXT(2) == '[') && (NXT(3) == 'C') &&
	(NXT(4) == 'D') && (NXT(5) == 'A') &&
	(NXT(6) == 'T') && (NXT(7) == 'A') &&
	(NXT(8) == '[')) {
	SKIP(9);
    } else
        return;

    ctxt->instate = XML_PARSER_CDATA_SECTION;
    r = CUR_CHAR(rl);
    if (!IS_CHAR(r)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "CData section not finished\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_CDATA_NOT_FINISHED;
	ctxt->instate = XML_PARSER_CONTENT;
        return;
    }
    NEXTL(rl);
    s = CUR_CHAR(sl);
    if (!IS_CHAR(s)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "CData section not finished\n");
	ctxt->errNo = XML_ERR_CDATA_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->instate = XML_PARSER_CONTENT;
        return;
    }
    NEXTL(sl);
    cur = CUR_CHAR(l);
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n", size);
	return;
    }
    while (IS_CHAR(cur) &&
           ((r != ']') || (s != ']') || (cur != '>'))) {
	if (len + 5 >= size) {
	    size *= 2;
	    buf = xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		fprintf(stderr, "realloc of %d byte failed\n", size);
		return;
	    }
	}
	COPY_BUF(rl,buf,len,r);
	r = s;
	rl = sl;
	s = cur;
	sl = l;
	NEXTL(l);
	cur = CUR_CHAR(l);
    }
    buf[len] = 0;
    ctxt->instate = XML_PARSER_CONTENT;
    if (cur != '>') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "CData section not finished\n%.50s\n", buf);
	ctxt->errNo = XML_ERR_CDATA_NOT_FINISHED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	xmlFree(buf);
        return;
    }
    NEXTL(l);

    /*
     * Ok the buffer is to be consumed as cdata.
     */
    if ((ctxt->sax != NULL) && (!ctxt->disableSAX)) {
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
    while (((RAW != 0) || (ctxt->token != 0)) &&
	   ((RAW != '<') || (NXT(1) != '/'))) {
	const xmlChar *test = CUR_PTR;
	int cons = ctxt->input->consumed;
	xmlChar tok = ctxt->token;

	/*
	 * Handle  possible processed charrefs.
	 */
	if (ctxt->token != 0) {
	    xmlParseCharData(ctxt, 0);
	}
	/*
	 * First case : a Processing Instruction.
	 */
	else if ((RAW == '<') && (NXT(1) == '?')) {
	    xmlParsePI(ctxt);
	}

	/*
	 * Second case : a CDSection
	 */
	else if ((RAW == '<') && (NXT(1) == '!') &&
	    (NXT(2) == '[') && (NXT(3) == 'C') &&
	    (NXT(4) == 'D') && (NXT(5) == 'A') &&
	    (NXT(6) == 'T') && (NXT(7) == 'A') &&
	    (NXT(8) == '[')) {
	    xmlParseCDSect(ctxt);
	}

	/*
	 * Third case :  a comment
	 */
	else if ((RAW == '<') && (NXT(1) == '!') &&
		 (NXT(2) == '-') && (NXT(3) == '-')) {
	    xmlParseComment(ctxt);
	    ctxt->instate = XML_PARSER_CONTENT;
	}

	/*
	 * Fourth case :  a sub-element.
	 */
	else if (RAW == '<') {
	    xmlParseElement(ctxt);
	}

	/*
	 * Fifth case : a reference. If if has not been resolved,
	 *    parsing returns it's Name, create the node 
	 */

	else if (RAW == '&') {
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
	while ((RAW == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);
	SHRINK;

	if ((cons == ctxt->input->consumed) && (test == CUR_PTR) &&
	    (tok == ctxt->token)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		     "detected an error in element content\n");
	    ctxt->errNo = XML_ERR_INTERNAL_ERROR;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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

    if (ctxt->spaceNr == 0)
	spacePush(ctxt, -1);
    else
	spacePush(ctxt, *ctxt->space);

    name = xmlParseStartTag(ctxt);
    if (name == NULL) {
	spacePop(ctxt);
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
        ctxt->node && (ctxt->node == ctxt->myDoc->children))
        ctxt->valid &= xmlValidateRoot(&ctxt->vctxt, ctxt->myDoc);

    /*
     * Check for an Empty Element.
     */
    if ((RAW == '/') && (NXT(1) == '>')) {
        SKIP(2);
	if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL) &&
	    (!ctxt->disableSAX))
	    ctxt->sax->endElement(ctxt->userData, name);
	oldname = namePop(ctxt);
	spacePop(ctxt);
	if (oldname != NULL) {
#ifdef DEBUG_STACK
	    fprintf(stderr,"Close: popped %s\n", oldname);
#endif
	    xmlFree(oldname);
	}
	return;
    }
    if (RAW == '>') {
        NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "Couldn't find end of Start Tag\n%.30s\n",
	                     openTag);
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_GT_REQUIRED;

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);
	oldname = namePop(ctxt);
	spacePop(ctxt);
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
    if (!IS_CHAR(RAW)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	         "Premature end of data in tag %.30s\n", openTag);
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_TAG_NOT_FINISED;

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);
	oldname = namePop(ctxt);
	spacePop(ctxt);
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
    while (((cur >= 'a') && (cur <= 'z')) ||
           ((cur >= 'A') && (cur <= 'Z')) ||
           ((cur >= '0') && (cur <= '9')) ||
           (cur == '_') || (cur == '.') ||
	   (cur == ':') || (cur == '-')) {
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

    if ((RAW == 'v') && (NXT(1) == 'e') &&
        (NXT(2) == 'r') && (NXT(3) == 's') &&
	(NXT(4) == 'i') && (NXT(5) == 'o') &&
	(NXT(6) == 'n')) {
	SKIP(7);
	SKIP_BLANKS;
	if (RAW != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseVersionInfo : expected '='\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    ctxt->errNo = XML_ERR_EQUAL_REQUIRED;
	    return(NULL);
        }
	NEXT;
	SKIP_BLANKS;
	if (RAW == '"') {
	    NEXT;
	    q = CUR_PTR;
	    version = xmlParseVersionNum(ctxt);
	    if (RAW != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		                     "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else if (RAW == '\''){
	    NEXT;
	    q = CUR_PTR;
	    version = xmlParseVersionNum(ctxt);
	    if (RAW != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "String not closed\n%.50s\n", q);
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    } else
	        NEXT;
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		      "xmlParseVersionInfo : expected ' or \"\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
	while (((cur >= 'a') && (cur <= 'z')) ||
	       ((cur >= 'A') && (cur <= 'Z')) ||
	       ((cur >= '0') && (cur <= '9')) ||
	       (cur == '.') || (cur == '_') ||
	       (cur == '-')) {
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
	ctxt->disableSAX = 1;
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
    if ((RAW == 'e') && (NXT(1) == 'n') &&
        (NXT(2) == 'c') && (NXT(3) == 'o') &&
	(NXT(4) == 'd') && (NXT(5) == 'i') &&
	(NXT(6) == 'n') && (NXT(7) == 'g')) {
	SKIP(8);
	SKIP_BLANKS;
	if (RAW != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "xmlParseEncodingDecl : expected '='\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    ctxt->errNo = XML_ERR_EQUAL_REQUIRED;
	    return(NULL);
        }
	NEXT;
	SKIP_BLANKS;
	if (RAW == '"') {
	    NEXT;
	    q = CUR_PTR;
	    encoding = xmlParseEncName(ctxt);
	    if (RAW != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
		                     "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else if (RAW == '\''){
	    NEXT;
	    q = CUR_PTR;
	    encoding = xmlParseEncName(ctxt);
	    if (RAW != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else if (RAW == '"'){
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		     "xmlParseEncodingDecl : expected ' or \"\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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
    if ((RAW == 's') && (NXT(1) == 't') &&
        (NXT(2) == 'a') && (NXT(3) == 'n') &&
	(NXT(4) == 'd') && (NXT(5) == 'a') &&
	(NXT(6) == 'l') && (NXT(7) == 'o') &&
	(NXT(8) == 'n') && (NXT(9) == 'e')) {
	SKIP(10);
        SKIP_BLANKS;
	if (RAW != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		    "XML standalone declaration : expected '='\n");
	    ctxt->errNo = XML_ERR_EQUAL_REQUIRED;
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    return(standalone);
        }
	NEXT;
	SKIP_BLANKS;
        if (RAW == '\''){
	    NEXT;
	    if ((RAW == 'n') && (NXT(1) == 'o')) {
	        standalone = 0;
                SKIP(2);
	    } else if ((RAW == 'y') && (NXT(1) == 'e') &&
	               (NXT(2) == 's')) {
	        standalone = 1;
		SKIP(3);
            } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		                     "standalone accepts only 'yes' or 'no'\n");
		ctxt->errNo = XML_ERR_STANDALONE_VALUE;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }
	    if (RAW != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n");
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    } else
	        NEXT;
	} else if (RAW == '"'){
	    NEXT;
	    if ((RAW == 'n') && (NXT(1) == 'o')) {
	        standalone = 0;
		SKIP(2);
	    } else if ((RAW == 'y') && (NXT(1) == 'e') &&
	               (NXT(2) == 's')) {
	        standalone = 1;
                SKIP(3);
            } else {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData,
		        "standalone accepts only 'yes' or 'no'\n");
		ctxt->errNo = XML_ERR_STANDALONE_VALUE;
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
	    }
	    if (RAW != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, "String not closed\n");
		ctxt->wellFormed = 0;
		ctxt->disableSAX = 1;
		ctxt->errNo = XML_ERR_STRING_NOT_CLOSED;
	    } else
	        NEXT;
	} else {
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
		                 "Standalone value not found\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
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

    if (!IS_BLANK(RAW)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed after '<?xml'\n");
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    if (!IS_BLANK(RAW)) {
        if ((RAW == '?') && (NXT(1) == '>')) {
	    SKIP(2);
	    return;
	}
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed here\n");
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
    }
    ctxt->input->encoding = xmlParseEncodingDecl(ctxt);

    /*
     * We may have the standalone status.
     */
    if ((ctxt->input->encoding != NULL) && (!IS_BLANK(RAW))) {
        if ((RAW == '?') && (NXT(1) == '>')) {
	    SKIP(2);
	    return;
	}
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Blank needed here\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_SPACE_REQUIRED;
    }
    SKIP_BLANKS;
    ctxt->input->standalone = xmlParseSDDecl(ctxt);

    SKIP_BLANKS;
    if ((RAW == '?') && (NXT(1) == '>')) {
        SKIP(2);
    } else if (RAW == '>') {
        /* Deprecated old WD ... */
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	                     "XML declaration must end-up with '?>'\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_XMLDECL_NOT_FINISHED;
	NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
	                     "parsing XML declaration: '?>' expected\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
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
    while (((RAW == '<') && (NXT(1) == '?')) ||
           ((RAW == '<') && (NXT(1) == '!') &&
	    (NXT(2) == '-') && (NXT(3) == '-')) ||
           IS_BLANK(CUR)) {
        if ((RAW == '<') && (NXT(1) == '?')) {
	    xmlParsePI(ctxt);
	} else if (IS_BLANK(CUR)) {
	    NEXT;
	} else
	    xmlParseComment(ctxt);
    }
}

/**
 * xmlParseDocument:
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
    xmlChar start[4];
    xmlCharEncoding enc;

    xmlDefaultSAXHandlerInit();

    GROW;

    /*
     * SAX: beginning of the document processing.
     */
    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
        ctxt->sax->setDocumentLocator(ctxt->userData, &xmlDefaultSAXLocator);

    /* 
     * Get the 4 first bytes and decode the charset
     * if enc != XML_CHAR_ENCODING_NONE
     * plug some encoding conversion routines.
     */
    start[0] = RAW;
    start[1] = NXT(1);
    start[2] = NXT(2);
    start[3] = NXT(3);
    enc = xmlDetectCharEncoding(start, 4);
    if (enc != XML_CHAR_ENCODING_NONE) {
        xmlSwitchEncoding(ctxt, enc);
    }


    if (CUR == 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Document is empty\n");
	ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
    }

    /*
     * Check for the XMLDecl in the Prolog.
     */
    GROW;
    if ((RAW == '<') && (NXT(1) == '?') &&
        (NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l') && (IS_BLANK(NXT(5)))) {
	xmlParseXMLDecl(ctxt);
	ctxt->standalone = ctxt->input->standalone;
	SKIP_BLANKS;
	if ((ctxt->encoding == NULL) && (ctxt->input->encoding != NULL))
	    ctxt->encoding = xmlStrdup(ctxt->input->encoding);

    } else {
	ctxt->version = xmlCharStrdup(XML_DEFAULT_VERSION);
    }
    if ((ctxt->sax) && (ctxt->sax->startDocument) && (!ctxt->disableSAX))
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
    if ((RAW == '<') && (NXT(1) == '!') &&
	(NXT(2) == 'D') && (NXT(3) == 'O') &&
	(NXT(4) == 'C') && (NXT(5) == 'T') &&
	(NXT(6) == 'Y') && (NXT(7) == 'P') &&
	(NXT(8) == 'E')) {

	ctxt->inSubset = 1;
	xmlParseDocTypeDecl(ctxt);
	if (RAW == '[') {
	    ctxt->instate = XML_PARSER_DTD;
	    xmlParseInternalSubset(ctxt);
	}

	/*
	 * Create and update the external subset.
	 */
	ctxt->inSubset = 2;
	if ((ctxt->sax != NULL) && (ctxt->sax->externalSubset != NULL) &&
	    (!ctxt->disableSAX))
	    ctxt->sax->externalSubset(ctxt->userData, ctxt->intSubName,
	                              ctxt->extSubSystem, ctxt->extSubURI);
	ctxt->inSubset = 0;


	ctxt->instate = XML_PARSER_PROLOG;
	xmlParseMisc(ctxt);
    }

    /*
     * Time to start parsing the tree itself
     */
    GROW;
    if (RAW != '<') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		    "Start tag expected, '<' not found\n");
	ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->instate = XML_PARSER_EOF;
    } else {
	ctxt->instate = XML_PARSER_CONTENT;
	xmlParseElement(ctxt);
	ctxt->instate = XML_PARSER_EPILOG;


	/*
	 * The Misc part at the end
	 */
	xmlParseMisc(ctxt);

	if (RAW != 0) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Extra content at the end of the document\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    ctxt->errNo = XML_ERR_DOCUMENT_END;
	}
	ctxt->instate = XML_PARSER_EOF;
    }

    /*
     * SAX: end of the document processing.
     */
    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL) &&
	(!ctxt->disableSAX))
        ctxt->sax->endDocument(ctxt->userData);

    /*
     * Grab the encoding if it was added on-the-fly
     */
    if ((ctxt->encoding != NULL) && (ctxt->myDoc != NULL) &&
	(ctxt->myDoc->encoding == NULL)) {
	ctxt->myDoc->encoding = ctxt->encoding;
	ctxt->encoding = NULL;
    }
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
	while ((RAW == 0) && (ctxt->inputNr > 1))
	    xmlPopInput(ctxt);

	if (ctxt->input ==NULL) break;
	if (ctxt->input->buf == NULL)
	    avail = ctxt->input->length - (ctxt->input->cur - ctxt->input->base);
	else
	    avail = ctxt->input->buf->buffer->use - (ctxt->input->cur - ctxt->input->base);
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
		cur = ctxt->input->cur[0];
		if (IS_BLANK(cur)) {
		    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
			ctxt->sax->setDocumentLocator(ctxt->userData,
						      &xmlDefaultSAXLocator);
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
	    "Extra spaces at the beginning of the document are not allowed\n");
		    ctxt->errNo = XML_ERR_DOCUMENT_START;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		    SKIP_BLANKS;
		    ret++;
		    if (ctxt->input->buf == NULL)
			avail = ctxt->input->length - (ctxt->input->cur - ctxt->input->base);
		    else
			avail = ctxt->input->buf->buffer->use - (ctxt->input->cur - ctxt->input->base);
		}
		if (avail < 2)
		    goto done;

		cur = ctxt->input->cur[0];
		next = ctxt->input->cur[1];
		if (cur == 0) {
		    if ((ctxt->sax) && (ctxt->sax->setDocumentLocator))
			ctxt->sax->setDocumentLocator(ctxt->userData,
						      &xmlDefaultSAXLocator);
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData, "Document is empty\n");
		    ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
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
		    if ((ctxt->input->cur[2] == 'x') &&
			(ctxt->input->cur[3] == 'm') &&
			(ctxt->input->cur[4] == 'l') &&
			(IS_BLANK(ctxt->input->cur[5]))) {
			ret += 5;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: Parsing XML Decl\n");
#endif
			xmlParseXMLDecl(ctxt);
			ctxt->standalone = ctxt->input->standalone;
			if ((ctxt->encoding == NULL) &&
			    (ctxt->input->encoding != NULL))
			    ctxt->encoding = xmlStrdup(ctxt->input->encoding);
			if ((ctxt->sax) && (ctxt->sax->startDocument) &&
			    (!ctxt->disableSAX))
			    ctxt->sax->startDocument(ctxt->userData);
			ctxt->instate = XML_PARSER_MISC;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering MISC\n");
#endif
		    } else {
			ctxt->version = xmlCharStrdup(XML_DEFAULT_VERSION);
			if ((ctxt->sax) && (ctxt->sax->startDocument) &&
			    (!ctxt->disableSAX))
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
		    if ((ctxt->sax) && (ctxt->sax->startDocument) &&
		        (!ctxt->disableSAX))
			ctxt->sax->startDocument(ctxt->userData);
		    ctxt->instate = XML_PARSER_MISC;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering MISC\n");
#endif
		}
		break;
            case XML_PARSER_MISC:
		SKIP_BLANKS;
		if (ctxt->input->buf == NULL)
		    avail = ctxt->input->length - (ctxt->input->cur - ctxt->input->base);
		else
		    avail = ctxt->input->buf->buffer->use - (ctxt->input->cur - ctxt->input->base);
		if (avail < 2)
		    goto done;
		cur = ctxt->input->cur[0];
		next = ctxt->input->cur[1];
	        if ((cur == '<') && (next == '?')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		    (ctxt->input->cur[2] == '-') && (ctxt->input->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlParseComment(ctxt);
		    ctxt->instate = XML_PARSER_MISC;
		} else if ((cur == '<') && (next == '!') &&
		    (ctxt->input->cur[2] == 'D') && (ctxt->input->cur[3] == 'O') &&
		    (ctxt->input->cur[4] == 'C') && (ctxt->input->cur[5] == 'T') &&
		    (ctxt->input->cur[6] == 'Y') && (ctxt->input->cur[7] == 'P') &&
		    (ctxt->input->cur[8] == 'E')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '>', 0, 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing internal subset\n");
#endif
		    ctxt->inSubset = 1;
		    xmlParseDocTypeDecl(ctxt);
		    if (RAW == '[') {
			ctxt->instate = XML_PARSER_DTD;
#ifdef DEBUG_PUSH
			fprintf(stderr, "PP: entering DTD\n");
#endif
		    } else {
			/*
			 * Create and update the external subset.
			 */
			ctxt->inSubset = 2;
			if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
			    (ctxt->sax->externalSubset != NULL))
			    ctxt->sax->externalSubset(ctxt->userData,
				    ctxt->intSubName, ctxt->extSubSystem,
				    ctxt->extSubURI);
			ctxt->inSubset = 0;
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
		if (ctxt->input->buf == NULL)
		    avail = ctxt->input->length - (ctxt->input->cur - ctxt->input->base);
		else
		    avail = ctxt->input->buf->buffer->use - (ctxt->input->cur - ctxt->input->base);
		if (avail < 2) 
		    goto done;
		cur = ctxt->input->cur[0];
		next = ctxt->input->cur[1];
	        if ((cur == '<') && (next == '?')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		    (ctxt->input->cur[2] == '-') && (ctxt->input->cur[3] == '-')) {
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
		if (ctxt->input->buf == NULL)
		    avail = ctxt->input->length - (ctxt->input->cur - ctxt->input->base);
		else
		    avail = ctxt->input->buf->buffer->use - (ctxt->input->cur - ctxt->input->base);
		if (avail < 2)
		    goto done;
		cur = ctxt->input->cur[0];
		next = ctxt->input->cur[1];
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
		    (ctxt->input->cur[2] == '-') && (ctxt->input->cur[3] == '-')) {
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
		    ctxt->disableSAX = 1;
		    ctxt->errNo = XML_ERR_DOCUMENT_END;
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL) &&
			(!ctxt->disableSAX))
			ctxt->sax->endDocument(ctxt->userData);
		    goto done;
		}
		break;
            case XML_PARSER_START_TAG: {
	        xmlChar *name, *oldname;

		if ((avail < 2) && (ctxt->inputNr == 1))
		    goto done;
		cur = ctxt->input->cur[0];
	        if (cur != '<') {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
				"Start tag expect, '<' not found\n");
		    ctxt->errNo = XML_ERR_DOCUMENT_EMPTY;
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL) &&
			(!ctxt->disableSAX))
			ctxt->sax->endDocument(ctxt->userData);
		    goto done;
		}
		if ((!terminate) &&
		    (xmlParseLookupSequence(ctxt, '>', 0, 0) < 0))
		    goto done;
		if (ctxt->spaceNr == 0)
		    spacePush(ctxt, -1);
		else
		    spacePush(ctxt, *ctxt->space);
		name = xmlParseStartTag(ctxt);
		if (name == NULL) {
		    spacePop(ctxt);
		    ctxt->instate = XML_PARSER_EOF;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: entering EOF\n");
#endif
		    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL) &&
			(!ctxt->disableSAX))
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
		    ctxt->node && (ctxt->node == ctxt->myDoc->children))
		    ctxt->valid &= xmlValidateRoot(&ctxt->vctxt, ctxt->myDoc);

		/*
		 * Check for an Empty Element.
		 */
		if ((RAW == '/') && (NXT(1) == '>')) {
		    SKIP(2);
		    if ((ctxt->sax != NULL) &&
			(ctxt->sax->endElement != NULL) && (!ctxt->disableSAX))
			ctxt->sax->endElement(ctxt->userData, name);
		    xmlFree(name);
		    oldname = namePop(ctxt);
		    spacePop(ctxt);
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
		if (RAW == '>') {
		    NEXT;
		} else {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt->userData,
					 "Couldn't find end of Start Tag %s\n",
					 name);
		    ctxt->wellFormed = 0;
		    ctxt->disableSAX = 1;
		    ctxt->errNo = XML_ERR_GT_REQUIRED;

		    /*
		     * end of parsing of this node.
		     */
		    nodePop(ctxt);
		    oldname = namePop(ctxt);
		    spacePop(ctxt);
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
		    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
			(ctxt->sax->characters != NULL))
			ctxt->sax->characters(ctxt->userData, cur, 1);
		    ctxt->token = 0;
		}
		if ((avail < 2) && (ctxt->inputNr == 1))
		    goto done;
		cur = ctxt->input->cur[0];
		next = ctxt->input->cur[1];
	        if ((cur == '<') && (next == '?')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '?', '>', 0) < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing PI\n");
#endif
		    xmlParsePI(ctxt);
		} else if ((cur == '<') && (next == '!') &&
		           (ctxt->input->cur[2] == '-') && (ctxt->input->cur[3] == '-')) {
		    if ((!terminate) &&
		        (xmlParseLookupSequence(ctxt, '-', '-', '>') < 0))
			goto done;
#ifdef DEBUG_PUSH
		    fprintf(stderr, "PP: Parsing Comment\n");
#endif
		    xmlParseComment(ctxt);
		    ctxt->instate = XML_PARSER_CONTENT;
		} else if ((cur == '<') && (ctxt->input->cur[1] == '!') &&
		    (ctxt->input->cur[2] == '[') && (NXT(3) == 'C') &&
		    (ctxt->input->cur[4] == 'D') && (NXT(5) == 'A') &&
		    (ctxt->input->cur[6] == 'T') && (NXT(7) == 'A') &&
		    (ctxt->input->cur[8] == '[')) {
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
		    /* TODO Avoid the extra copy, handle directly !!! */
		    /*
		     * Goal of the following test is:
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
		while ((RAW == 0) && (ctxt->inputNr > 1))
		    xmlPopInput(ctxt);
		break;
            case XML_PARSER_CDATA_SECTION: {
	        /*
		 * The Push mode need to have the SAX callback for 
		 * cdataBlock merge back contiguous callbacks.
		 */
		int base;

		base = xmlParseLookupSequence(ctxt, ']', ']', '>');
		if (base < 0) {
		    if (avail >= XML_PARSER_BIG_BUFFER_SIZE + 2) {
			if ((ctxt->sax != NULL) && (!ctxt->disableSAX)) {
			    if (ctxt->sax->cdataBlock != NULL)
				ctxt->sax->cdataBlock(ctxt->userData, ctxt->input->cur,
					  XML_PARSER_BIG_BUFFER_SIZE);
			}
			SKIP(XML_PARSER_BIG_BUFFER_SIZE);
			ctxt->checkIndex = 0;
		    }
		    goto done;
		} else {
		    if ((ctxt->sax != NULL) && (base > 0) &&
			(!ctxt->disableSAX)) {
			if (ctxt->sax->cdataBlock != NULL)
			    ctxt->sax->cdataBlock(ctxt->userData,
						  ctxt->input->cur, base);
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

		base = ctxt->input->cur - ctxt->input->base;
		if (base < 0) return(0);
		if (ctxt->checkIndex > base)
		    base = ctxt->checkIndex;
		buf = ctxt->input->buf->buffer->content;
		for (;base < ctxt->input->buf->buffer->use;base++) {
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
		        if (base +1 >= ctxt->input->buf->buffer->use)
			    break;
			if (buf[base + 1] == ']') {
			    /* conditional crap, skip both ']' ! */
			    base++;
			    continue;
			}
		        for (i = 0;base + i < ctxt->input->buf->buffer->use;i++) {
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
		ctxt->inSubset = 2;
		if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
		    (ctxt->sax->externalSubset != NULL))
		    ctxt->sax->externalSubset(ctxt->userData, ctxt->intSubName,
			    ctxt->extSubSystem, ctxt->extSubURI);
		ctxt->inSubset = 0;
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
            case XML_PARSER_SYSTEM_LITERAL:
		fprintf(stderr, "PP: internal error, state == SYSTEM_LITERAL\n");
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

	if ((terminate) || (ctxt->input->buf->buffer->use > 80))
	    xmlParseTryOrFinish(ctxt, terminate);
    } else if (ctxt->instate != XML_PARSER_EOF)
        xmlParseTryOrFinish(ctxt, terminate);
    if (terminate) {
	/*
	 * Grab the encoding if it was added on-the-fly
	 */
	if ((ctxt->encoding != NULL) && (ctxt->myDoc != NULL) &&
	    (ctxt->myDoc->encoding == NULL)) {
	    ctxt->myDoc->encoding = ctxt->encoding;
	    ctxt->encoding = NULL;
	}

	/*
	 * Check for termination
	 */
	if ((ctxt->instate != XML_PARSER_EOF) &&
	    (ctxt->instate != XML_PARSER_EPILOG)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt->userData,
		    "Extra content at the end of the document\n");
	    ctxt->wellFormed = 0;
	    ctxt->disableSAX = 1;
	    ctxt->errNo = XML_ERR_DOCUMENT_END;
	} 
	if (ctxt->instate != XML_PARSER_EOF) {
	    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL) &&
		(!ctxt->disableSAX))
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
 * xmlCreatePushParserCtxt:
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
     * plug some encoding conversion routines
     */
    if ((chunk != NULL) && (size >= 4))
	enc = xmlDetectCharEncoding((const xmlChar *) chunk, size);

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
    if (enc != XML_CHAR_ENCODING_NONE) {
        xmlSwitchEncoding(ctxt, enc);
    }

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
 * xmlCreateIOParserCtxt:
 * @sax:  a SAX handler
 * @user_data:  The user data returned on SAX callbacks
 * @ioread:  an I/O read function
 * @ioclose:  an I/O close function
 * @ioctx:  an I/O handler
 * @enc:  the charset encoding if known
 *
 * Create a parser context for using the XML parser with an existing
 * I/O stream
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreateIOParserCtxt(xmlSAXHandlerPtr sax, void *user_data,
	xmlInputReadCallback   ioread, xmlInputCloseCallback  ioclose,
	void *ioctx, xmlCharEncoding enc) {
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr inputStream;
    xmlParserInputBufferPtr buf;

    buf = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, enc);
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

    inputStream = xmlNewIOInputStream(ctxt, buf, enc);
    if (inputStream == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }
    inputPush(ctxt, inputStream);

    return(ctxt);
}

/**
 * xmlCreateDocParserCtxt:
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

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	return(NULL);
    }
    input = xmlNewInputStream(ctxt);
    if (input == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    input->base = cur;
    input->cur = cur;

    inputPush(ctxt, input);
    return(ctxt);
}

/**
 * xmlSAXParseDoc:
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
 * xmlParseDoc:
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
 * xmlSAXParseDTD:
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
     * plug some encoding conversion routines here.
     */
    xmlPushInput(ctxt, input);
    enc = xmlDetectCharEncoding(ctxt->input->cur, 4);
    xmlSwitchEncoding(ctxt, enc);

    if (input->filename == NULL)
	input->filename = (char *) xmlStrdup(SystemID);
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
 * xmlParseDTD:
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
 * xmlSAXParseBalancedChunk:
 * @ctx:  an XML parser context (possibly NULL)
 * @sax:  the SAX handler bloc (possibly NULL)
 * @user_data:  The user data returned on SAX callbacks (possibly NULL)
 * @input:  a parser input stream
 * @enc:  the encoding
 *
 * Parse a well-balanced chunk of an XML document
 * The user has to provide SAX callback block whose routines will be
 * called by the parser
 * The allowed sequence for the Well Balanced Chunk is the one defined by
 * the content production in the XML grammar:
 *
 * [43] content ::= (element | CharData | Reference | CDSect | PI | Comment)*
 *
 * Returns 0 if the chunk is well balanced, -1 in case of args problem and
 *    the error code otherwise
 */

int
xmlSAXParseBalancedChunk(xmlParserCtxtPtr ctx, xmlSAXHandlerPtr sax,
                         void *user_data, xmlParserInputPtr input,
			 xmlCharEncoding enc) {
    xmlParserCtxtPtr ctxt;
    int ret;

    if (input == NULL) return(-1);

    if (ctx != NULL)
        ctxt = ctx;
    else {	
	ctxt = xmlNewParserCtxt();
	if (ctxt == NULL)
	    return(-1);
        if (sax == NULL)
	    ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
    }	

    /*
     * Set-up the SAX context
     */
    if (sax != NULL) {
	if (ctxt->sax != NULL)
	    xmlFree(ctxt->sax);
	ctxt->sax = sax;
	ctxt->userData = user_data;
    }

    /*
     * plug some encoding conversion routines here.
     */
    xmlPushInput(ctxt, input);
    if (enc != XML_CHAR_ENCODING_NONE)
	xmlSwitchEncoding(ctxt, enc);

    /*
     * let's parse that entity knowing it's an external subset.
     */
    xmlParseContent(ctxt);
    ret = ctxt->errNo;

    if (ctx == NULL) {
	if (sax != NULL) 
	    ctxt->sax = NULL;
	else
	    xmlFreeDoc(ctxt->myDoc);
	xmlFreeParserCtxt(ctxt);
    }
    return(ret);
}

/**
 * xmlParseExternalEntity:
 * @doc:  the document the chunk pertains to
 * @sax:  the SAX handler bloc (possibly NULL)
 * @user_data:  The user data returned on SAX callbacks (possibly NULL)
 * @depth:  Used for loop detection, use 0
 * @URL:  the URL for the entity to load
 * @ID:  the System ID for the entity to load
 * @list:  the return value for the set of parsed nodes
 *
 * Parse an external general entity
 * An external general parsed entity is well-formed if it matches the
 * production labeled extParsedEnt.
 *
 * [78] extParsedEnt ::= TextDecl? content
 *
 * Returns 0 if the entity is well formed, -1 in case of args problem and
 *    the parser error code otherwise
 */

int
xmlParseExternalEntity(xmlDocPtr doc, xmlSAXHandlerPtr sax, void *user_data,
	  int depth, const xmlChar *URL, const xmlChar *ID, xmlNodePtr *list) {
    xmlParserCtxtPtr ctxt;
    xmlDocPtr newDoc;
    xmlSAXHandlerPtr oldsax = NULL;
    int ret = 0;

    if (depth > 40) {
	return(XML_ERR_ENTITY_LOOP);
    }



    if (list != NULL)
        *list = NULL;
    if ((URL == NULL) && (ID == NULL))
	return(-1);


    ctxt = xmlCreateEntityParserCtxt(URL, ID, doc->URL);
    if (ctxt == NULL) return(-1);
    ctxt->userData = ctxt;
    if (sax != NULL) {
	oldsax = ctxt->sax;
        ctxt->sax = sax;
	if (user_data != NULL)
	    ctxt->userData = user_data;
    }
    newDoc = xmlNewDoc(BAD_CAST "1.0");
    if (newDoc == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(-1);
    }
    if (doc != NULL) {
	newDoc->intSubset = doc->intSubset;
	newDoc->extSubset = doc->extSubset;
    }
    if (doc->URL != NULL) {
	newDoc->URL = xmlStrdup(doc->URL);
    }
    newDoc->children = xmlNewDocNode(newDoc, NULL, BAD_CAST "pseudoroot", NULL);
    if (newDoc->children == NULL) {
	if (sax != NULL)
	    ctxt->sax = oldsax;
	xmlFreeParserCtxt(ctxt);
	newDoc->intSubset = NULL;
	newDoc->extSubset = NULL;
        xmlFreeDoc(newDoc);
	return(-1);
    }
    nodePush(ctxt, newDoc->children);
    if (doc == NULL) {
	ctxt->myDoc = newDoc;
    } else {
	ctxt->myDoc = doc;
	newDoc->children->doc = doc;
    }

    /*
     * Parse a possible text declaration first
     */
    GROW;
    if ((RAW == '<') && (NXT(1) == '?') &&
	(NXT(2) == 'x') && (NXT(3) == 'm') &&
	(NXT(4) == 'l') && (IS_BLANK(NXT(5)))) {
	xmlParseTextDecl(ctxt);
    }

    /*
     * Doing validity checking on chunk doesn't make sense
     */
    ctxt->instate = XML_PARSER_CONTENT;
    ctxt->validate = 0;
    ctxt->depth = depth;

    xmlParseContent(ctxt);
   
    if ((RAW == '<') && (NXT(1) == '/')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"chunk is not well balanced\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_NOT_WELL_BALANCED;
    } else if (RAW != 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"extra content at the end of well balanced chunk\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_EXTRA_CONTENT;
    }
    if (ctxt->node != newDoc->children) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"chunk is not well balanced\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_NOT_WELL_BALANCED;
    }

    if (!ctxt->wellFormed) {
        if (ctxt->errNo == 0)
	    ret = 1;
	else
	    ret = ctxt->errNo;
    } else {
	if (list != NULL) {
	    xmlNodePtr cur;

	    /*
	     * Return the newly created nodeset after unlinking it from
	     * they pseudo parent.
	     */
	    cur = newDoc->children->children;
	    *list = cur;
	    while (cur != NULL) {
		cur->parent = NULL;
		cur = cur->next;
	    }
            newDoc->children->children = NULL;
	}
	ret = 0;
    }
    if (sax != NULL) 
	ctxt->sax = oldsax;
    xmlFreeParserCtxt(ctxt);
    newDoc->intSubset = NULL;
    newDoc->extSubset = NULL;
    xmlFreeDoc(newDoc);
    
    return(ret);
}

/**
 * xmlParseBalancedChunk:
 * @doc:  the document the chunk pertains to
 * @sax:  the SAX handler bloc (possibly NULL)
 * @user_data:  The user data returned on SAX callbacks (possibly NULL)
 * @depth:  Used for loop detection, use 0
 * @string:  the input string in UTF8 or ISO-Latin (zero terminated)
 * @list:  the return value for the set of parsed nodes
 *
 * Parse a well-balanced chunk of an XML document
 * called by the parser
 * The allowed sequence for the Well Balanced Chunk is the one defined by
 * the content production in the XML grammar:
 *
 * [43] content ::= (element | CharData | Reference | CDSect | PI | Comment)*
 *
 * Returns 0 if the chunk is well balanced, -1 in case of args problem and
 *    the parser error code otherwise
 */

int
xmlParseBalancedChunkMemory(xmlDocPtr doc, xmlSAXHandlerPtr sax,
     void *user_data, int depth, const xmlChar *string, xmlNodePtr *list) {
    xmlParserCtxtPtr ctxt;
    xmlDocPtr newDoc;
    xmlSAXHandlerPtr oldsax = NULL;
    int size;
    int ret = 0;

    if (depth > 40) {
	return(XML_ERR_ENTITY_LOOP);
    }


    if (list != NULL)
        *list = NULL;
    if (string == NULL)
        return(-1);

    size = xmlStrlen(string);

    ctxt = xmlCreateMemoryParserCtxt((char *) string, size);
    if (ctxt == NULL) return(-1);
    ctxt->userData = ctxt;
    if (sax != NULL) {
	oldsax = ctxt->sax;
        ctxt->sax = sax;
	if (user_data != NULL)
	    ctxt->userData = user_data;
    }
    newDoc = xmlNewDoc(BAD_CAST "1.0");
    if (newDoc == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(-1);
    }
    if (doc != NULL) {
	newDoc->intSubset = doc->intSubset;
	newDoc->extSubset = doc->extSubset;
    }
    newDoc->children = xmlNewDocNode(newDoc, NULL, BAD_CAST "pseudoroot", NULL);
    if (newDoc->children == NULL) {
	if (sax != NULL)
	    ctxt->sax = oldsax;
	xmlFreeParserCtxt(ctxt);
	newDoc->intSubset = NULL;
	newDoc->extSubset = NULL;
        xmlFreeDoc(newDoc);
	return(-1);
    }
    nodePush(ctxt, newDoc->children);
    if (doc == NULL) {
	ctxt->myDoc = newDoc;
    } else {
	ctxt->myDoc = doc;
	newDoc->children->doc = doc;
    }
    ctxt->instate = XML_PARSER_CONTENT;
    ctxt->depth = depth;

    /*
     * Doing validity checking on chunk doesn't make sense
     */
    ctxt->validate = 0;

    xmlParseContent(ctxt);
   
    if ((RAW == '<') && (NXT(1) == '/')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"chunk is not well balanced\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_NOT_WELL_BALANCED;
    } else if (RAW != 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"extra content at the end of well balanced chunk\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_EXTRA_CONTENT;
    }
    if (ctxt->node != newDoc->children) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData,
		"chunk is not well balanced\n");
	ctxt->wellFormed = 0;
	ctxt->disableSAX = 1;
	ctxt->errNo = XML_ERR_NOT_WELL_BALANCED;
    }

    if (!ctxt->wellFormed) {
        if (ctxt->errNo == 0)
	    ret = 1;
	else
	    ret = ctxt->errNo;
    } else {
	if (list != NULL) {
	    xmlNodePtr cur;

	    /*
	     * Return the newly created nodeset after unlinking it from
	     * they pseudo parent.
	     */
	    cur = newDoc->children->children;
	    *list = cur;
	    while (cur != NULL) {
		cur->parent = NULL;
		cur = cur->next;
	    }
            newDoc->children->children = NULL;
	}
	ret = 0;
    }
    if (sax != NULL) 
	ctxt->sax = oldsax;
    xmlFreeParserCtxt(ctxt);
    newDoc->intSubset = NULL;
    newDoc->extSubset = NULL;
    xmlFreeDoc(newDoc);
    
    return(ret);
}

/**
 * xmlParseBalancedChunkFile:
 * @doc:  the document the chunk pertains to
 *
 * Parse a well-balanced chunk of an XML document contained in a file
 * 
 * Returns the resulting list of nodes resulting from the parsing,
 *     they are not added to @node
 */

xmlNodePtr
xmlParseBalancedChunkFile(xmlDocPtr doc, xmlNodePtr node) {
    /* TODO !!! */
    return(NULL);
}

/**
 * xmlRecoverDoc:
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
 * xmlCreateEntityParserCtxt:
 * @URL:  the entity URL
 * @ID:  the entity PUBLIC ID
 * @base:  a posible base for the target URI
 *
 * Create a parser context for an external entity
 * Automatic support for ZLIB/Compress compressed document is provided
 * by default if found at compile-time.
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreateEntityParserCtxt(const xmlChar *URL, const xmlChar *ID,
	                  const xmlChar *base) {
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr inputStream;
    char *directory = NULL;

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
	return(NULL);
    }

    inputStream = xmlLoadExternalEntity((char *)URL, (char *)ID, ctxt);
    if (inputStream == NULL) {
	xmlFreeParserCtxt(ctxt);
	return(NULL);
    }

    inputPush(ctxt, inputStream);

    if ((ctxt->directory == NULL) && (directory == NULL))
        directory = xmlParserGetDirectory((char *)URL);
    if ((ctxt->directory == NULL) && (directory != NULL))
        ctxt->directory = directory;

    return(ctxt);
}

/**
 * xmlCreateFileParserCtxt:
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
 * xmlSAXParseFile:
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
        ctxt->directory = (char *) xmlStrdup((xmlChar *) directory);

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
 * xmlParseFile:
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
 * xmlRecoverFile:
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
 * xmlCreateMemoryParserCtxt:
 * @buffer:  a pointer to a zero terminated char array
 * @size:  the size of the array (without the trailing 0)
 *
 * Create a parser context for an XML in-memory document.
 *
 * Returns the new parser context or NULL
 */
xmlParserCtxtPtr
xmlCreateMemoryParserCtxt(char *buffer, int size) {
    xmlParserCtxtPtr ctxt;
    xmlParserInputPtr input;

    if (buffer[size] != 0)
	return(NULL);

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
	return(NULL);

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

    input->base = BAD_CAST buffer;
    input->cur = BAD_CAST buffer;
    input->free = NULL;

    inputPush(ctxt, input);
    return(ctxt);
}

/**
 * xmlSAXParseMemory:
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
 * xmlParseMemory:
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
 * xmlRecoverMemory:
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
        return;
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
 * xmlInitNodeInfoSeq:
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
 * xmlClearNodeInfoSeq:
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
 * xmlSubstituteEntitiesDefault:
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
 * xmlKeepBlanksDefault:
 * @val:  int 0 or 1 
 *
 * Set and return the previous value for default blanks text nodes support.
 * The 1.x version of the parser used an heuristic to try to detect
 * ignorable white spaces. As a result the SAX callback was generating
 * ignorableWhitespace() callbacks instead of characters() one, and when
 * using the DOM output text nodes containing those blanks were not generated.
 * The 2.x and later version will switch to the XML standard way and
 * ignorableWhitespace() are only generated when running the parser in
 * validating mode and when the current element doesn't allow CDATA or
 * mixed content.
 * This function is provided as a way to force the standard behaviour 
 * on 1.X libs and to switch back to the old mode for compatibility when
 * running 1.X client code on 2.X . Upgrade of 1.X code should be done
 * by using xmlIsBlankNode() commodity function to detect the "empty"
 * nodes generated.
 * This value also affect autogeneration of indentation when saving code
 * if blanks sections are kept, indentation is not generated.
 *
 * Returns the last value for 0 for no substitution, 1 for substitution.
 */

int
xmlKeepBlanksDefault(int val) {
    int old = xmlKeepBlanksDefaultValue;

    xmlKeepBlanksDefaultValue = val;
    xmlIndentTreeOutput = !val;
    return(old);
}

