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
#include "valid.h"
#include "parserInternals.h"

/************************************************************************
 *									*
 * 		Parser stacks related functions and macros		*
 *									*
 ************************************************************************/
/*
 * Generic function for accessing stacks in the Parser Context
 */

#define PUSH_AND_POP(type, name)					\
int name##Push(xmlParserCtxtPtr ctxt, type value) {			\
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
type name##Pop(xmlParserCtxtPtr ctxt) {					\
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
 * Clean macros, not dependent of an ASCII context.
 *
 *   CURRENT Returns the current char value, with the full decoding of
 *           UTF-8 if we are using this mode. It returns an int.
 *   NEXT    Skip to the next character, this does the proper decoding
 *           in UTF-8 mode. It also pop-up unfinished entities on the fly.
 *           It returns the pointer to the current CHAR.
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
    inputPop(ctxt);
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

    if (input->filename != NULL) return;
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
 * Create a new input stream based on a memory buffer.
 * Returns the new input stream
 */
xmlParserInputPtr
xmlNewEntityInputStream(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
    xmlParserInputPtr input;

    if (entity == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
	      "internal: xmlNewEntityInputStream entity = NULL\n");
	return(NULL);
    }
    if (entity->content == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
	      "internal: xmlNewEntityInputStream entity->input = NULL\n");
	return(NULL);
    }
    input = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (input == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "malloc: couldn't allocate a new input stream\n");
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
 * @entity:  an Entity pointer
 *
 * Create a new input stream based on a memory buffer.
 * Returns the new input stream
 */
xmlParserInputPtr
xmlNewStringInputStream(xmlParserCtxtPtr ctxt, CHAR *string) {
    xmlParserInputPtr input;

    if (string == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
	      "internal: xmlNewStringInputStream string = NULL\n");
	return(NULL);
    }
    input = (xmlParserInputPtr) malloc(sizeof(xmlParserInput));
    if (input == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "malloc: couldn't allocate a new input stream\n");
	return(NULL);
    }
    input->filename = NULL;
    input->base = string;
    input->cur = string;
    input->line = 1;
    input->col = 1;
    input->free = NULL;
    return(input);
}

/*
 * A few macros needed to help building the parser.
 */

#ifdef UNICODE
/************************************************************************
 *									*
 * UNICODE version of the macros.      					*
 *									*
 ************************************************************************/
/*
 * [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
 *                  | [#x10000-#x10FFFF]
 * any Unicode character, excluding the surrogate blocks, FFFE, and FFFF.
 */
#define IS_CHAR(c)							\
    ((((c) == 0x09) || ((c) == 0x0a) || ((c) == 0x0d) ||		\
      (((c) >= 0x20) && ((c) != 0xFFFE) && ((c) != 0xFFFF))) &&		\
      (((c) <= 0xD7FF) || ((c) >= 0xE000)) && ((c) >= 0) &&		\
      ((c) <= 0x10FFFF))

/*
 * [3] S ::= (#x20 | #x9 | #xD | #xA)+
 */
#define IS_BLANK(c) (((c) == 0x20) || ((c) == 0x09) || ((c) == 0xa) ||	\
                     ((c) == 0x0D))

/*
 * [85] BaseChar ::= ... long list see REC ...
 *
 * VI is your friend !
 * :1,$ s/\[#x\([0-9A-Z]*\)-#x\([0-9A-Z]*\)\]/     (((c) >= 0x\1) \&\& ((c) <= 0x\2)) ||/
 * and 
 * :1,$ s/#x\([0-9A-Z]*\)/     ((c) == 0x\1) ||/
 */
#define IS_BASECHAR(c)							\
     ((((c) >= 0x0041) && ((c) <= 0x005A)) ||				\
      (((c) >= 0x0061) && ((c) <= 0x007A)) ||				\
      (((c) >= 0x00C0) && ((c) <= 0x00D6)) ||				\
      (((c) >= 0x00D8) && ((c) <= 0x00F6)) ||				\
      (((c) >= 0x00F8) && ((c) <= 0x00FF)) ||				\
      (((c) >= 0x0100) && ((c) <= 0x0131)) ||				\
      (((c) >= 0x0134) && ((c) <= 0x013E)) ||				\
      (((c) >= 0x0141) && ((c) <= 0x0148)) ||				\
      (((c) >= 0x014A) && ((c) <= 0x017E)) ||				\
      (((c) >= 0x0180) && ((c) <= 0x01C3)) ||				\
      (((c) >= 0x01CD) && ((c) <= 0x01F0)) ||				\
      (((c) >= 0x01F4) && ((c) <= 0x01F5)) ||				\
      (((c) >= 0x01FA) && ((c) <= 0x0217)) ||				\
      (((c) >= 0x0250) && ((c) <= 0x02A8)) ||				\
      (((c) >= 0x02BB) && ((c) <= 0x02C1)) ||				\
      ((c) == 0x0386) ||						\
      (((c) >= 0x0388) && ((c) <= 0x038A)) ||				\
      ((c) == 0x038C) ||						\
      (((c) >= 0x038E) && ((c) <= 0x03A1)) ||				\
      (((c) >= 0x03A3) && ((c) <= 0x03CE)) ||				\
      (((c) >= 0x03D0) && ((c) <= 0x03D6)) ||				\
      ((c) == 0x03DA) ||						\
      ((c) == 0x03DC) ||						\
      ((c) == 0x03DE) ||						\
      ((c) == 0x03E0) ||						\
      (((c) >= 0x03E2) && ((c) <= 0x03F3)) ||				\
      (((c) >= 0x0401) && ((c) <= 0x040C)) ||				\
      (((c) >= 0x040E) && ((c) <= 0x044F)) ||				\
      (((c) >= 0x0451) && ((c) <= 0x045C)) ||				\
      (((c) >= 0x045E) && ((c) <= 0x0481)) ||				\
      (((c) >= 0x0490) && ((c) <= 0x04C4)) ||				\
      (((c) >= 0x04C7) && ((c) <= 0x04C8)) ||				\
      (((c) >= 0x04CB) && ((c) <= 0x04CC)) ||				\
      (((c) >= 0x04D0) && ((c) <= 0x04EB)) ||				\
      (((c) >= 0x04EE) && ((c) <= 0x04F5)) ||				\
      (((c) >= 0x04F8) && ((c) <= 0x04F9)) ||				\
      (((c) >= 0x0531) && ((c) <= 0x0556)) ||				\
      ((c) == 0x0559) ||						\
      (((c) >= 0x0561) && ((c) <= 0x0586)) ||				\
      (((c) >= 0x05D0) && ((c) <= 0x05EA)) ||				\
      (((c) >= 0x05F0) && ((c) <= 0x05F2)) ||				\
      (((c) >= 0x0621) && ((c) <= 0x063A)) ||				\
      (((c) >= 0x0641) && ((c) <= 0x064A)) ||				\
      (((c) >= 0x0671) && ((c) <= 0x06B7)) ||				\
      (((c) >= 0x06BA) && ((c) <= 0x06BE)) ||				\
      (((c) >= 0x06C0) && ((c) <= 0x06CE)) ||				\
      (((c) >= 0x06D0) && ((c) <= 0x06D3)) ||				\
      ((c) == 0x06D5) ||						\
      (((c) >= 0x06E5) && ((c) <= 0x06E6)) ||				\
      (((c) >= 0x0905) && ((c) <= 0x0939)) ||				\
      ((c) == 0x093D) ||						\
      (((c) >= 0x0958) && ((c) <= 0x0961)) ||				\
      (((c) >= 0x0985) && ((c) <= 0x098C)) ||				\
      (((c) >= 0x098F) && ((c) <= 0x0990)) ||				\
      (((c) >= 0x0993) && ((c) <= 0x09A8)) ||				\
      (((c) >= 0x09AA) && ((c) <= 0x09B0)) ||				\
      ((c) == 0x09B2) ||						\
      (((c) >= 0x09B6) && ((c) <= 0x09B9)) ||				\
      (((c) >= 0x09DC) && ((c) <= 0x09DD)) ||				\
      (((c) >= 0x09DF) && ((c) <= 0x09E1)) ||				\
      (((c) >= 0x09F0) && ((c) <= 0x09F1)) ||				\
      (((c) >= 0x0A05) && ((c) <= 0x0A0A)) ||				\
      (((c) >= 0x0A0F) && ((c) <= 0x0A10)) ||				\
      (((c) >= 0x0A13) && ((c) <= 0x0A28)) ||				\
      (((c) >= 0x0A2A) && ((c) <= 0x0A30)) ||				\
      (((c) >= 0x0A32) && ((c) <= 0x0A33)) ||				\
      (((c) >= 0x0A35) && ((c) <= 0x0A36)) ||				\
      (((c) >= 0x0A38) && ((c) <= 0x0A39)) ||				\
      (((c) >= 0x0A59) && ((c) <= 0x0A5C)) ||				\
      ((c) == 0x0A5E) ||						\
      (((c) >= 0x0A72) && ((c) <= 0x0A74)) ||				\
      (((c) >= 0x0A85) && ((c) <= 0x0A8B)) ||				\
      ((c) == 0x0A8D) ||						\
      (((c) >= 0x0A8F) && ((c) <= 0x0A91)) ||				\
      (((c) >= 0x0A93) && ((c) <= 0x0AA8)) ||				\
      (((c) >= 0x0AAA) && ((c) <= 0x0AB0)) ||				\
      (((c) >= 0x0AB2) && ((c) <= 0x0AB3)) ||				\
      (((c) >= 0x0AB5) && ((c) <= 0x0AB9)) ||				\
      ((c) == 0x0ABD) ||						\
      ((c) == 0x0AE0) ||						\
      (((c) >= 0x0B05) && ((c) <= 0x0B0C)) ||				\
      (((c) >= 0x0B0F) && ((c) <= 0x0B10)) ||				\
      (((c) >= 0x0B13) && ((c) <= 0x0B28)) ||				\
      (((c) >= 0x0B2A) && ((c) <= 0x0B30)) ||				\
      (((c) >= 0x0B32) && ((c) <= 0x0B33)) ||				\
      (((c) >= 0x0B36) && ((c) <= 0x0B39)) ||				\
      ((c) == 0x0B3D) ||						\
      (((c) >= 0x0B5C) && ((c) <= 0x0B5D)) ||				\
      (((c) >= 0x0B5F) && ((c) <= 0x0B61)) ||				\
      (((c) >= 0x0B85) && ((c) <= 0x0B8A)) ||				\
      (((c) >= 0x0B8E) && ((c) <= 0x0B90)) ||				\
      (((c) >= 0x0B92) && ((c) <= 0x0B95)) ||				\
      (((c) >= 0x0B99) && ((c) <= 0x0B9A)) ||				\
      ((c) == 0x0B9C) ||						\
      (((c) >= 0x0B9E) && ((c) <= 0x0B9F)) ||				\
      (((c) >= 0x0BA3) && ((c) <= 0x0BA4)) ||				\
      (((c) >= 0x0BA8) && ((c) <= 0x0BAA)) ||				\
      (((c) >= 0x0BAE) && ((c) <= 0x0BB5)) ||				\
      (((c) >= 0x0BB7) && ((c) <= 0x0BB9)) ||				\
      (((c) >= 0x0C05) && ((c) <= 0x0C0C)) ||				\
      (((c) >= 0x0C0E) && ((c) <= 0x0C10)) ||				\
      (((c) >= 0x0C12) && ((c) <= 0x0C28)) ||				\
      (((c) >= 0x0C2A) && ((c) <= 0x0C33)) ||				\
      (((c) >= 0x0C35) && ((c) <= 0x0C39)) ||				\
      (((c) >= 0x0C60) && ((c) <= 0x0C61)) ||				\
      (((c) >= 0x0C85) && ((c) <= 0x0C8C)) ||				\
      (((c) >= 0x0C8E) && ((c) <= 0x0C90)) ||				\
      (((c) >= 0x0C92) && ((c) <= 0x0CA8)) ||				\
      (((c) >= 0x0CAA) && ((c) <= 0x0CB3)) ||				\
      (((c) >= 0x0CB5) && ((c) <= 0x0CB9)) ||				\
      ((c) == 0x0CDE) ||						\
      (((c) >= 0x0CE0) && ((c) <= 0x0CE1)) ||				\
      (((c) >= 0x0D05) && ((c) <= 0x0D0C)) ||				\
      (((c) >= 0x0D0E) && ((c) <= 0x0D10)) ||				\
      (((c) >= 0x0D12) && ((c) <= 0x0D28)) ||				\
      (((c) >= 0x0D2A) && ((c) <= 0x0D39)) ||				\
      (((c) >= 0x0D60) && ((c) <= 0x0D61)) ||				\
      (((c) >= 0x0E01) && ((c) <= 0x0E2E)) ||				\
      ((c) == 0x0E30) ||						\
      (((c) >= 0x0E32) && ((c) <= 0x0E33)) ||				\
      (((c) >= 0x0E40) && ((c) <= 0x0E45)) ||				\
      (((c) >= 0x0E81) && ((c) <= 0x0E82)) ||				\
      ((c) == 0x0E84) ||						\
      (((c) >= 0x0E87) && ((c) <= 0x0E88)) ||				\
      ((c) == 0x0E8A) ||						\
      ((c) == 0x0E8D) ||						\
      (((c) >= 0x0E94) && ((c) <= 0x0E97)) ||				\
      (((c) >= 0x0E99) && ((c) <= 0x0E9F)) ||				\
      (((c) >= 0x0EA1) && ((c) <= 0x0EA3)) ||				\
      ((c) == 0x0EA5) ||						\
      ((c) == 0x0EA7) ||						\
      (((c) >= 0x0EAA) && ((c) <= 0x0EAB)) ||				\
      (((c) >= 0x0EAD) && ((c) <= 0x0EAE)) ||				\
      ((c) == 0x0EB0) ||						\
      (((c) >= 0x0EB2) && ((c) <= 0x0EB3)) ||				\
      ((c) == 0x0EBD) ||						\
      (((c) >= 0x0EC0) && ((c) <= 0x0EC4)) ||				\
      (((c) >= 0x0F40) && ((c) <= 0x0F47)) ||				\
      (((c) >= 0x0F49) && ((c) <= 0x0F69)) ||				\
      (((c) >= 0x10A0) && ((c) <= 0x10C5)) ||				\
      (((c) >= 0x10D0) && ((c) <= 0x10F6)) ||				\
      ((c) == 0x1100) ||						\
      (((c) >= 0x1102) && ((c) <= 0x1103)) ||				\
      (((c) >= 0x1105) && ((c) <= 0x1107)) ||				\
      ((c) == 0x1109) ||						\
      (((c) >= 0x110B) && ((c) <= 0x110C)) ||				\
      (((c) >= 0x110E) && ((c) <= 0x1112)) ||				\
      ((c) == 0x113C) ||						\
      ((c) == 0x113E) ||						\
      ((c) == 0x1140) ||						\
      ((c) == 0x114C) ||						\
      ((c) == 0x114E) ||						\
      ((c) == 0x1150) ||						\
      (((c) >= 0x1154) && ((c) <= 0x1155)) ||				\
      ((c) == 0x1159) ||						\
      (((c) >= 0x115F) && ((c) <= 0x1161)) ||				\
      ((c) == 0x1163) ||						\
      ((c) == 0x1165) ||						\
      ((c) == 0x1167) ||						\
      ((c) == 0x1169) ||						\
      (((c) >= 0x116D) && ((c) <= 0x116E)) ||				\
      (((c) >= 0x1172) && ((c) <= 0x1173)) ||				\
      ((c) == 0x1175) ||						\
      ((c) == 0x119E) ||						\
      ((c) == 0x11A8) ||						\
      ((c) == 0x11AB) ||						\
      (((c) >= 0x11AE) && ((c) <= 0x11AF)) ||				\
      (((c) >= 0x11B7) && ((c) <= 0x11B8)) ||				\
      ((c) == 0x11BA) ||						\
      (((c) >= 0x11BC) && ((c) <= 0x11C2)) ||				\
      ((c) == 0x11EB) ||						\
      ((c) == 0x11F0) ||						\
      ((c) == 0x11F9) ||						\
      (((c) >= 0x1E00) && ((c) <= 0x1E9B)) ||				\
      (((c) >= 0x1EA0) && ((c) <= 0x1EF9)) ||				\
      (((c) >= 0x1F00) && ((c) <= 0x1F15)) ||				\
      (((c) >= 0x1F18) && ((c) <= 0x1F1D)) ||				\
      (((c) >= 0x1F20) && ((c) <= 0x1F45)) ||				\
      (((c) >= 0x1F48) && ((c) <= 0x1F4D)) ||				\
      (((c) >= 0x1F50) && ((c) <= 0x1F57)) ||				\
      ((c) == 0x1F59) ||						\
      ((c) == 0x1F5B) ||						\
      ((c) == 0x1F5D) ||						\
      (((c) >= 0x1F5F) && ((c) <= 0x1F7D)) ||				\
      (((c) >= 0x1F80) && ((c) <= 0x1FB4)) ||				\
      (((c) >= 0x1FB6) && ((c) <= 0x1FBC)) ||				\
      ((c) == 0x1FBE) ||						\
      (((c) >= 0x1FC2) && ((c) <= 0x1FC4)) ||				\
      (((c) >= 0x1FC6) && ((c) <= 0x1FCC)) ||				\
      (((c) >= 0x1FD0) && ((c) <= 0x1FD3)) ||				\
      (((c) >= 0x1FD6) && ((c) <= 0x1FDB)) ||				\
      (((c) >= 0x1FE0) && ((c) <= 0x1FEC)) ||				\
      (((c) >= 0x1FF2) && ((c) <= 0x1FF4)) ||				\
      (((c) >= 0x1FF6) && ((c) <= 0x1FFC)) ||				\
      ((c) == 0x2126) ||						\
      (((c) >= 0x212A) && ((c) <= 0x212B)) ||				\
      ((c) == 0x212E) ||						\
      (((c) >= 0x2180) && ((c) <= 0x2182)) ||				\
      (((c) >= 0x3041) && ((c) <= 0x3094)) ||				\
      (((c) >= 0x30A1) && ((c) <= 0x30FA)) ||				\
      (((c) >= 0x3105) && ((c) <= 0x312C)) ||				\
      (((c) >= 0xAC00) && ((c) <= 0xD7A3)))

/*
 * [88] Digit ::= ... long list see REC ...
 */
#define IS_DIGIT(c) 							\
     ((((c) >= 0x0030) && ((c) <= 0x0039)) ||				\
      (((c) >= 0x0660) && ((c) <= 0x0669)) ||				\
      (((c) >= 0x06F0) && ((c) <= 0x06F9)) ||				\
      (((c) >= 0x0966) && ((c) <= 0x096F)) ||				\
      (((c) >= 0x09E6) && ((c) <= 0x09EF)) ||				\
      (((c) >= 0x0A66) && ((c) <= 0x0A6F)) ||				\
      (((c) >= 0x0AE6) && ((c) <= 0x0AEF)) ||				\
      (((c) >= 0x0B66) && ((c) <= 0x0B6F)) ||				\
      (((c) >= 0x0BE7) && ((c) <= 0x0BEF)) ||				\
      (((c) >= 0x0C66) && ((c) <= 0x0C6F)) ||				\
      (((c) >= 0x0CE6) && ((c) <= 0x0CEF)) ||				\
      (((c) >= 0x0D66) && ((c) <= 0x0D6F)) ||				\
      (((c) >= 0x0E50) && ((c) <= 0x0E59)) ||				\
      (((c) >= 0x0ED0) && ((c) <= 0x0ED9)) ||				\
      (((c) >= 0x0F20) && ((c) <= 0x0F29)))

/*
 * [87] CombiningChar ::= ... long list see REC ...
 */
#define IS_COMBINING(c) 						\
     ((((c) >= 0x0300) && ((c) <= 0x0345)) ||				\
      (((c) >= 0x0360) && ((c) <= 0x0361)) ||				\
      (((c) >= 0x0483) && ((c) <= 0x0486)) ||				\
      (((c) >= 0x0591) && ((c) <= 0x05A1)) ||				\
      (((c) >= 0x05A3) && ((c) <= 0x05B9)) ||				\
      (((c) >= 0x05BB) && ((c) <= 0x05BD)) ||				\
      ((c) == 0x05BF) ||						\
      (((c) >= 0x05C1) && ((c) <= 0x05C2)) ||				\
      ((c) == 0x05C4) ||						\
      (((c) >= 0x064B) && ((c) <= 0x0652)) ||				\
      ((c) == 0x0670) ||						\
      (((c) >= 0x06D6) && ((c) <= 0x06DC)) ||				\
      (((c) >= 0x06DD) && ((c) <= 0x06DF)) ||				\
      (((c) >= 0x06E0) && ((c) <= 0x06E4)) ||				\
      (((c) >= 0x06E7) && ((c) <= 0x06E8)) ||				\
      (((c) >= 0x06EA) && ((c) <= 0x06ED)) ||				\
      (((c) >= 0x0901) && ((c) <= 0x0903)) ||				\
      ((c) == 0x093C) ||						\
      (((c) >= 0x093E) && ((c) <= 0x094C)) ||				\
      ((c) == 0x094D) ||						\
      (((c) >= 0x0951) && ((c) <= 0x0954)) ||				\
      (((c) >= 0x0962) && ((c) <= 0x0963)) ||				\
      (((c) >= 0x0981) && ((c) <= 0x0983)) ||				\
      ((c) == 0x09BC) ||						\
      ((c) == 0x09BE) ||						\
      ((c) == 0x09BF) ||						\
      (((c) >= 0x09C0) && ((c) <= 0x09C4)) ||				\
      (((c) >= 0x09C7) && ((c) <= 0x09C8)) ||				\
      (((c) >= 0x09CB) && ((c) <= 0x09CD)) ||				\
      ((c) == 0x09D7) ||						\
      (((c) >= 0x09E2) && ((c) <= 0x09E3)) ||				\
      ((c) == 0x0A02) ||						\
      ((c) == 0x0A3C) ||						\
      ((c) == 0x0A3E) ||						\
      ((c) == 0x0A3F) ||						\
      (((c) >= 0x0A40) && ((c) <= 0x0A42)) ||				\
      (((c) >= 0x0A47) && ((c) <= 0x0A48)) ||				\
      (((c) >= 0x0A4B) && ((c) <= 0x0A4D)) ||				\
      (((c) >= 0x0A70) && ((c) <= 0x0A71)) ||				\
      (((c) >= 0x0A81) && ((c) <= 0x0A83)) ||				\
      ((c) == 0x0ABC) ||						\
      (((c) >= 0x0ABE) && ((c) <= 0x0AC5)) ||				\
      (((c) >= 0x0AC7) && ((c) <= 0x0AC9)) ||				\
      (((c) >= 0x0ACB) && ((c) <= 0x0ACD)) ||				\
      (((c) >= 0x0B01) && ((c) <= 0x0B03)) ||				\
      ((c) == 0x0B3C) ||						\
      (((c) >= 0x0B3E) && ((c) <= 0x0B43)) ||				\
      (((c) >= 0x0B47) && ((c) <= 0x0B48)) ||				\
      (((c) >= 0x0B4B) && ((c) <= 0x0B4D)) ||				\
      (((c) >= 0x0B56) && ((c) <= 0x0B57)) ||				\
      (((c) >= 0x0B82) && ((c) <= 0x0B83)) ||				\
      (((c) >= 0x0BBE) && ((c) <= 0x0BC2)) ||				\
      (((c) >= 0x0BC6) && ((c) <= 0x0BC8)) ||				\
      (((c) >= 0x0BCA) && ((c) <= 0x0BCD)) ||				\
      ((c) == 0x0BD7) ||						\
      (((c) >= 0x0C01) && ((c) <= 0x0C03)) ||				\
      (((c) >= 0x0C3E) && ((c) <= 0x0C44)) ||				\
      (((c) >= 0x0C46) && ((c) <= 0x0C48)) ||				\
      (((c) >= 0x0C4A) && ((c) <= 0x0C4D)) ||				\
      (((c) >= 0x0C55) && ((c) <= 0x0C56)) ||				\
      (((c) >= 0x0C82) && ((c) <= 0x0C83)) ||				\
      (((c) >= 0x0CBE) && ((c) <= 0x0CC4)) ||				\
      (((c) >= 0x0CC6) && ((c) <= 0x0CC8)) ||				\
      (((c) >= 0x0CCA) && ((c) <= 0x0CCD)) ||				\
      (((c) >= 0x0CD5) && ((c) <= 0x0CD6)) ||				\
      (((c) >= 0x0D02) && ((c) <= 0x0D03)) ||				\
      (((c) >= 0x0D3E) && ((c) <= 0x0D43)) ||				\
      (((c) >= 0x0D46) && ((c) <= 0x0D48)) ||				\
      (((c) >= 0x0D4A) && ((c) <= 0x0D4D)) ||				\
      ((c) == 0x0D57) ||						\
      ((c) == 0x0E31) ||						\
      (((c) >= 0x0E34) && ((c) <= 0x0E3A)) ||				\
      (((c) >= 0x0E47) && ((c) <= 0x0E4E)) ||				\
      ((c) == 0x0EB1) ||						\
      (((c) >= 0x0EB4) && ((c) <= 0x0EB9)) ||				\
      (((c) >= 0x0EBB) && ((c) <= 0x0EBC)) ||				\
      (((c) >= 0x0EC8) && ((c) <= 0x0ECD)) ||				\
      (((c) >= 0x0F18) && ((c) <= 0x0F19)) ||				\
      ((c) == 0x0F35) ||						\
      ((c) == 0x0F37) ||						\
      ((c) == 0x0F39) ||						\
      ((c) == 0x0F3E) ||						\
      ((c) == 0x0F3F) ||						\
      (((c) >= 0x0F71) && ((c) <= 0x0F84)) ||				\
      (((c) >= 0x0F86) && ((c) <= 0x0F8B)) ||				\
      (((c) >= 0x0F90) && ((c) <= 0x0F95)) ||				\
      ((c) == 0x0F97) ||						\
      (((c) >= 0x0F99) && ((c) <= 0x0FAD)) ||				\
      (((c) >= 0x0FB1) && ((c) <= 0x0FB7)) ||				\
      ((c) == 0x0FB9) ||						\
      (((c) >= 0x20D0) && ((c) <= 0x20DC)) ||				\
      ((c) == 0x20E1) ||						\
      (((c) >= 0x302A) && ((c) <= 0x302F)) ||				\
      ((c) == 0x3099) ||						\
      ((c) == 0x309A))

/*
 * [89] Extender ::= #x00B7 | #x02D0 | #x02D1 | #x0387 | #x0640 |
 *                   #x0E46 | #x0EC6 | #x3005 | [#x3031-#x3035] |
 *                   [#x309D-#x309E] | [#x30FC-#x30FE]
 */
#define IS_EXTENDER(c)							\
    (((c) == 0xb7) || ((c) == 0x2d0) || ((c) == 0x2d1) ||		\
     ((c) == 0x387) || ((c) == 0x640) || ((c) == 0xe46) ||		\
     ((c) == 0xec6) || ((c) == 0x3005)					\
     (((c) >= 0x3031) && ((c) <= 0x3035)) ||				\
     (((c) >= 0x309b) && ((c) <= 0x309e)) ||				\
     (((c) >= 0x30fc) && ((c) <= 0x30fe)))

/*
 * [86] Ideographic ::= [#x4E00-#x9FA5] | #x3007 | [#x3021-#x3029]
 */
#define IS_IDEOGRAPHIC(c)						\
    ((((c) >= 0x4e00) && ((c) <= 0x9fa5)) ||				\
     (((c) >= 0xf900) && ((c) <= 0xfa2d)) ||				\
     (((c) >= 0x3021) && ((c) <= 0x3029)) ||				\
      ((c) == 0x3007))

/*
 * [84] Letter ::= BaseChar | Ideographic 
 */
#define IS_LETTER(c) (IS_BASECHAR(c) || IS_IDEOGRAPHIC(c))

#else
#ifndef USE_UTF_8
/************************************************************************
 *									*
 * 8bits / ISO-Latin version of the macros.				*
 *									*
 ************************************************************************/
/*
 * [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
 *                  | [#x10000-#x10FFFF]
 * any Unicode character, excluding the surrogate blocks, FFFE, and FFFF.
 */
#define IS_CHAR(c)							\
    ((((c) == 0x09) || ((c) == 0x0a) || ((c) == 0x0d) ||		\
      (((c) >= 0x20) && ((c) != 0xFFFE) && ((c) != 0xFFFF))) &&		\
      (((c) <= 0xD7FF) || ((c) >= 0xE000)) && ((c) <= 0x10FFFF))

/*
 * [85] BaseChar ::= ... long list see REC ...
 */
#define IS_BASECHAR(c)							\
    ((((c) >= 0x41) && ((c) <= 0x5a)) ||				\
     (((c) >= 0x61) && ((c) <= 0x7a)) ||				\
     (((c) >= 0xaa) && ((c) <= 0x5b)) ||				\
     (((c) >= 0xc0) && ((c) <= 0xd6)) ||				\
     (((c) >= 0xd8) && ((c) <= 0xf6)) ||				\
     (((c) >= 0xf8) && ((c) <= 0xff)) ||				\
      ((c) == 0xba))

/*
 * [88] Digit ::= ... long list see REC ...
 */
#define IS_DIGIT(c) (((c) >= 0x30) && ((c) <= 0x39))

/*
 * [84] Letter ::= BaseChar | Ideographic 
 */
#define IS_LETTER(c) IS_BASECHAR(c)


/*
 * [87] CombiningChar ::= ... long list see REC ...
 */
#define IS_COMBINING(c) 0

/*
 * [89] Extender ::= #x00B7 | #x02D0 | #x02D1 | #x0387 | #x0640 |
 *                   #x0E46 | #x0EC6 | #x3005 | [#x3031-#x3035] |
 *                   [#x309D-#x309E] | [#x30FC-#x30FE]
 */
#define IS_EXTENDER(c) ((c) == 0xb7)

#else /* USE_UTF_8 */
/************************************************************************
 *									*
 * 8bits / UTF-8 version of the macros.					*
 *									*
 ************************************************************************/

TODO !!!
#endif /* USE_UTF_8 */
#endif /* !UNICODE */

/*
 * Blank chars.
 *
 * [3] S ::= (#x20 | #x9 | #xD | #xA)+
 */
#define IS_BLANK(c) (((c) == 0x20) || ((c) == 0x09) || ((c) == 0xa) ||	\
                     ((c) == 0x0D))

/*
 * [13] PubidChar ::= #x20 | #xD | #xA | [a-zA-Z0-9] | [-'()+,./:=?;!*#@$_%]
 */
#define IS_PUBIDCHAR(c)							\
    (((c) == 0x20) || ((c) == 0x0D) || ((c) == 0x0A) ||			\
     (((c) >= 'a') && ((c) <= 'z')) ||					\
     (((c) >= 'A') && ((c) <= 'Z')) ||					\
     (((c) >= '0') && ((c) <= '9')) ||					\
     ((c) == '-') || ((c) == '\'') || ((c) == '(') || ((c) == ')') ||	\
     ((c) == '+') || ((c) == ',') || ((c) == '.') || ((c) == '/') ||	\
     ((c) == ':') || ((c) == '=') || ((c) == '?') || ((c) == ';') ||	\
     ((c) == '!') || ((c) == '*') || ((c) == '#') || ((c) == '@') ||	\
     ((c) == '$') || ((c) == '_') || ((c) == '%'))

#define SKIP_EOL(p) 							\
    if (*(p) == 0x13) { p++ ; if (*(p) == 0x10) p++; }			\
    if (*(p) == 0x10) { p++ ; if (*(p) == 0x13) p++; }

#define MOVETO_ENDTAG(p)						\
    while (IS_CHAR(*p) && (*(p) != '>')) (p)++

#define MOVETO_STARTTAG(p)						\
    while (IS_CHAR(*p) && (*(p) != '<')) (p)++

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
        fprintf(stderr, "malloc of %d byte failed\n",
	        (len + 1) * sizeof(CHAR));
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
        fprintf(stderr, "malloc of %d byte failed\n",
	        (len + 1) * sizeof(CHAR));
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
        fprintf(stderr, "xmlStrncat: realloc of %d byte failed\n",
	        (size + len + 1) * sizeof(CHAR));
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
	    ctxt->sax->error(ctxt, "xmlHandleEntity %s: content == NULL\n",
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
    if (ctxt->sax != NULL)
	ctxt->sax->characters(ctxt, entity->content, 0, len);

}

/*
 * Forward definition for recusive behaviour.
 */
xmlNodePtr xmlParseElement(xmlParserCtxtPtr ctxt);
CHAR *xmlParsePEReference(xmlParserCtxtPtr ctxt);
CHAR *xmlParseReference(xmlParserCtxtPtr ctxt);

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
	        ctxt->sax->error(ctxt, "String not closed \"%.50s\"\n", q);
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
	        ctxt->sax->error(ctxt, "String not closed \"%.50s\"\n", q);
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
		    ctxt->sax->error(ctxt, "xmlParseNamespace found garbage\n");
	    ctxt->wellFormed = 0;
            NEXT;
        }
    }

    MOVETO_ENDTAG(CUR_PTR);
    NEXT;

    /*
     * Register the DTD.
     */
    if (href != NULL)
        xmlNewGlobalNs(ctxt->doc, href, prefix);

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
 *
 * parse a value for ENTITY decl.
 *
 * [9] EntityValue ::= '"' ([^%&"] | PEReference | Reference)* '"' |
 *	               "'" ([^%&'] | PEReference | Reference)* "'"
 *
 * Returns the EntityValue parsed or NULL
 */

CHAR *
xmlParseEntityValue(xmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL, *cur;
    const CHAR *q;

    if (CUR == '"') {
        NEXT;

	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '"')) {
	    if (CUR == '%') {
	        ret = xmlStrncat(ret, q, CUR_PTR - q);
	        cur = xmlParsePEReference(ctxt);
		ret = xmlStrcat(ret, cur);
		q = CUR_PTR;
	    } else if (CUR == '&') {
	        ret = xmlStrncat(ret, q, CUR_PTR - q);
	        cur = xmlParseReference(ctxt);
		if (cur != NULL) {
		    CHAR buf[2];
		    buf[0] = '&';
		    buf[1] = 0;
		    ret = xmlStrncat(ret, buf, 1);
		    ret = xmlStrcat(ret, cur);
		    buf[0] = ';';
		    buf[1] = 0;
		    ret = xmlStrncat(ret, buf, 1);
		}
		q = CUR_PTR;
	    } else 
	        NEXT;
	}
	if (!IS_CHAR(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "Unfinished EntityValue\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrncat(ret, q, CUR_PTR - q);
	    NEXT;
        }
    } else if (CUR == '\'') {
        NEXT;
	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '\'')) {
	    if (CUR == '%') {
	        ret = xmlStrncat(ret, q, CUR_PTR - q);
	        cur = xmlParsePEReference(ctxt);
		ret = xmlStrcat(ret, cur);
		q = CUR_PTR;
	    } else if (CUR == '&') {
	        ret = xmlStrncat(ret, q, CUR_PTR - q);
	        cur = xmlParseReference(ctxt);
		if (cur != NULL) {
		    CHAR buf[2];
		    buf[0] = '&';
		    buf[1] = 0;
		    ret = xmlStrncat(ret, buf, 1);
		    ret = xmlStrcat(ret, cur);
		    buf[0] = ';';
		    buf[1] = 0;
		    ret = xmlStrncat(ret, buf, 1);
		}
		q = CUR_PTR;
	    } else 
	        NEXT;
	}
	if (!IS_CHAR(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "Unfinished EntityValue\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrncat(ret, q, CUR_PTR - q);
	    NEXT;
        }
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "xmlParseEntityValue \" or ' expected\n");
	ctxt->wellFormed = 0;
    }
    
    return(ret);
}

/**
 * xmlParseAttValue:
 * @ctxt:  an XML parser context
 *
 * parse a value for an attribute
 *
 * [10] AttValue ::= '"' ([^<&"] | Reference)* '"' |
 *                   "'" ([^<&'] | Reference)* "'"
 *
 * Returns the AttValue parsed or NULL.
 */

CHAR *
xmlParseAttValue(xmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL, *cur;
    const CHAR *q;

    if (CUR == '"') {
        NEXT;

	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '"')) {
	    if (CUR == '<') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt,
		       "Unescaped '<' not allowed in attributes values\n");
		ctxt->wellFormed = 0;
	    }
	    if (CUR == '&') {
	        ret = xmlStrncat(ret, q, CUR_PTR - q);
	        cur = xmlParseReference(ctxt);
		if (cur != NULL) {
		    /*
		     * Special case for '&amp;', we don't want to
		     * resolve it here since it will break later
		     * when searching entities in the string.
		     */
		    if ((cur[0] == '&') && (cur[1] == 0)) {
		        CHAR buf[6] = { '&', 'a', 'm', 'p', ';', 0 };
		        ret = xmlStrncat(ret, buf, 5);
		    } else
		        ret = xmlStrcat(ret, cur);
		    free(cur);
		}
		q = CUR_PTR;
	    } else 
	        NEXT;
	    /*
	     * Pop out finished entity references.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1)) {
		if (CUR_PTR != q)
		    ret = xmlStrncat(ret, q, CUR_PTR - q);
	        xmlPopInput(ctxt);
		q = CUR_PTR;
	    }
	}
	if (!IS_CHAR(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "Unfinished AttValue\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrncat(ret, q, CUR_PTR - q);
	    NEXT;
        }
    } else if (CUR == '\'') {
        NEXT;
	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '\'')) {
	    if (CUR == '<') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt,
		       "Unescaped '<' not allowed in attributes values\n");
		ctxt->wellFormed = 0;
	    }
	    if (CUR == '&') {
	        ret = xmlStrncat(ret, q, CUR_PTR - q);
	        cur = xmlParseReference(ctxt);
		if (cur != NULL) {
		    /*
		     * Special case for '&amp;', we don't want to
		     * resolve it here since it will break later
		     * when searching entities in the string.
		     */
		    if ((cur[0] == '&') && (cur[1] == 0)) {
		        CHAR buf[6] = { '&', 'a', 'm', 'p', ';', 0 };
		        ret = xmlStrncat(ret, buf, 5);
		    } else
		        ret = xmlStrcat(ret, cur);
		    free(cur);
		}
		q = CUR_PTR;
	    } else 
	        NEXT;
	    /*
	     * Pop out finished entity references.
	     */
	    while ((CUR == 0) && (ctxt->inputNr > 1)) {
		if (CUR_PTR != q)
		    ret = xmlStrncat(ret, q, CUR_PTR - q);
	        xmlPopInput(ctxt);
		q = CUR_PTR;
	    }
	}
	if (!IS_CHAR(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "Unfinished AttValue\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrncat(ret, q, CUR_PTR - q);
	    NEXT;
        }
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "AttValue: \" or ' expected\n");
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
	        ctxt->sax->error(ctxt, "Unfinished SystemLiteral\n");
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
	        ctxt->sax->error(ctxt, "Unfinished SystemLiteral\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
        }
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "SystemLiteral \" or ' expected\n");
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
	        ctxt->sax->error(ctxt, "Unfinished PubidLiteral\n");
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
	        ctxt->sax->error(ctxt, "Unfinished PubidLiteral\n");
	    ctxt->wellFormed = 0;
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
	}
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "SystemLiteral \" or ' expected\n");
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
		    ctxt->sax->error(ctxt,
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
	if (areBlanks(ctxt, q, CUR_PTR - q))
	    ctxt->sax->ignorableWhitespace(ctxt, q, 0, CUR_PTR - q);
	else
	    ctxt->sax->characters(ctxt, q, 0, CUR_PTR - q);
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
		ctxt->sax->error(ctxt,
		    "Space required after 'SYSTEM'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
	URI = xmlParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt,
	          "xmlParseExternalID: SYSTEM, no URI\n");
	    ctxt->wellFormed = 0;
        }
    } else if ((CUR == 'P') && (NXT(1) == 'U') &&
	       (NXT(2) == 'B') && (NXT(3) == 'L') &&
	       (NXT(4) == 'I') && (NXT(5) == 'C')) {
        SKIP(6);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt,
		    "Space required after 'PUBLIC'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
	*publicID = xmlParsePubidLiteral(ctxt);
	if (*publicID == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, 
	          "xmlParseExternalID: PUBLIC, no Public Identifier\n");
	    ctxt->wellFormed = 0;
	}
	if (strict) {
	    /*
	     * We don't handle [83] so "S SystemLiteral" is required.
	     */
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt,
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
	        ctxt->sax->error(ctxt, 
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
 *
 * TODO: this should call a SAX function which will handle (or not) the
 *       creation of the comment !
 *
 * Returns the comment node, or NULL
 */
xmlNodePtr
xmlParseComment(xmlParserCtxtPtr ctxt, int create) {
    xmlNodePtr ret = NULL;
    const CHAR *q, *start;
    const CHAR *r;
    CHAR *val;

    /*
     * Check that there is a comment right here.
     */
    if ((CUR != '<') || (NXT(1) != '!') ||
        (NXT(2) != '-') || (NXT(3) != '-')) return(NULL);

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
	        ctxt->sax->error(ctxt,
	       "Comment must not contain '--' (double-hyphen)`\n");
	    ctxt->wellFormed = 0;
	}
        NEXT;r++;q++;
    }
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "Comment not terminated \n<!--%.50s\n", start);
	ctxt->wellFormed = 0;
    } else {
        NEXT;
	if (create) {
	    val = xmlStrndup(start, q - start);
	    ret = xmlNewDocComment(ctxt->doc, val);
	    free(val);
	}
    }
    return(ret);
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
	    ctxt->sax->error(ctxt, "xmlParsePItarget: invalid name prefix 'xml'\n");
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
	    /*
	     * Support for the old Processing Instruction related to namespace.
	     */
	    if ((target[0] == 'n') && (target[1] == 'a') &&
		(target[2] == 'm') && (target[3] == 'e') &&
		(target[4] == 's') && (target[5] == 'p') &&
		(target[6] == 'a') && (target[7] == 'c') &&
		(target[8] == 'e')) {
		xmlParseNamespace(ctxt);
	    } else if ((target[0] == 'x') && (target[1] == 'm') &&
		       (target[2] == 'l') && (target[3] == ':') &&
		       (target[4] == 'n') && (target[5] == 'a') &&
		       (target[6] == 'm') && (target[7] == 'e') &&
		       (target[8] == 's') && (target[9] == 'p') &&
		       (target[10] == 'a') && (target[11] == 'c') &&
		       (target[12] == 'e')) {
		xmlParseNamespace(ctxt);
	    } else {
	        const CHAR *q = CUR_PTR;

		while (IS_CHAR(CUR) &&
		       ((CUR != '?') || (NXT(1) != '>')))
		    NEXT;
		if (!IS_CHAR(CUR)) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		        ctxt->sax->error(ctxt,
			  "xmlParsePI: PI %s never end ...\n", target);
		    ctxt->wellFormed = 0;
		} else {
		    CHAR *data;

		    data = xmlStrndup(CUR_PTR, CUR_PTR - q);
		    SKIP(2);

		    /*
		     * SAX: PI detected.
		     */
		    if (ctxt->sax) 
			ctxt->sax->processingInstruction(ctxt, target, data);
		    /*
		     * Unknown PI, ignore it !
		     */
		    else 
			xmlParserWarning(ctxt,
		           "xmlParsePI : skipping unknown PI %s\n",
				         target);
	            free(data);
                }
	    }
	    free(target);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "xmlParsePI : no target name\n");
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
		ctxt->sax->error(ctxt, "Space required after '<!NOTATION'\n");
	    ctxt->wellFormed = 0;
	    return;
	}
	SKIP_BLANKS;

        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "NOTATION: Name expected here\n");
	    ctxt->wellFormed = 0;
	    return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
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
	    xmlAddNotationDecl(ctxt->doc->intSubset, name, Pubid, Systemid);
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt,
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
    
    if ((CUR == '<') && (NXT(1) == '!') &&
        (NXT(2) == 'E') && (NXT(3) == 'N') &&
        (NXT(4) == 'T') && (NXT(5) == 'I') &&
        (NXT(6) == 'T') && (NXT(7) == 'Y')) {
	SKIP(8);
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, "Space required after '<!ENTITY'\n");
	    ctxt->wellFormed = 0;
	}
	SKIP_BLANKS;

	if (CUR == '%') {
	    NEXT;
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, "Space required after '%'\n");
		ctxt->wellFormed = 0;
	    }
	    SKIP_BLANKS;
	    isParameter = 1;
	}

        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "xmlParseEntityDecl: no name\n");
	    ctxt->wellFormed = 0;
            return;
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt,
		     "Space required after the entity name\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;

	/*
	 * handle the various case of definitions...
	 */
	if (isParameter) {
	    if ((CUR == '"') || (CUR == '\''))
	        value = xmlParseEntityValue(ctxt);
		if (value) {
		    xmlAddDocEntity(ctxt->doc, name,
		                    XML_INTERNAL_PARAMETER_ENTITY,
				    NULL, NULL, value);
		}
	    else {
	        URI = xmlParseExternalID(ctxt, &literal, 1);
		if (URI) {
		    xmlAddDocEntity(ctxt->doc, name,
		                    XML_EXTERNAL_PARAMETER_ENTITY,
				    literal, URI, NULL);
		}
	    }
	} else {
	    if ((CUR == '"') || (CUR == '\'')) {
	        value = xmlParseEntityValue(ctxt);
		xmlAddDocEntity(ctxt->doc, name,
				XML_INTERNAL_GENERAL_ENTITY,
				NULL, NULL, value);
	    } else {
	        URI = xmlParseExternalID(ctxt, &literal, 1);
		if ((CUR != '>') && (!IS_BLANK(CUR))) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			ctxt->sax->error(ctxt,
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
			    ctxt->sax->error(ctxt,
			        "Space required after 'NDATA'\n");
			ctxt->wellFormed = 0;
		    }
		    SKIP_BLANKS;
		    ndata = xmlParseName(ctxt);
		    xmlAddDocEntity(ctxt->doc, name,
				    XML_EXTERNAL_GENERAL_UNPARSED_ENTITY,
				    literal, URI, ndata);
		} else {
		    xmlAddDocEntity(ctxt->doc, name,
				    XML_EXTERNAL_GENERAL_PARSED_ENTITY,
				    literal, URI, NULL);
		}
	    }
	}
	SKIP_BLANKS;
	if (CUR != '>') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, 
	            "xmlParseEntityDecl: entity %s not terminated\n", name);
	    ctxt->wellFormed = 0;
	} else
	    NEXT;
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
	        ctxt->sax->error(ctxt, "Space required after '#FIXED'\n");
	    ctxt->wellFormed = 0;
	}
	SKIP_BLANKS;
    }
    ret = xmlParseAttValue(ctxt);
    if (ret == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
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
	    ctxt->sax->error(ctxt, "'(' required to start 'NOTATION'\n");
	ctxt->wellFormed = 0;
	return(NULL);
    }
    do {
        NEXT;
	SKIP_BLANKS;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
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
	    ctxt->sax->error(ctxt,
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
	    ctxt->sax->error(ctxt,
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
		ctxt->sax->error(ctxt, 
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
	    ctxt->sax->error(ctxt,
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
	        ctxt->sax->error(ctxt, "Space required after 'NOTATION'\n");
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
	        ctxt->sax->error(ctxt, "Space required after '<!ATTLIST'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
        elemName = xmlParseName(ctxt);
	if (elemName == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "ATTLIST: no name for Element\n");
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
		    ctxt->sax->error(ctxt, "ATTLIST: no name for Attribute\n");
		ctxt->wellFormed = 0;
		break;
	    }
	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, 
		        "Space required after the attribute name\n");
		ctxt->wellFormed = 0;
		break;
	    }
	    SKIP_BLANKS;

	    type = xmlParseAttributeType(ctxt, &tree);
	    if (type <= 0) break;

	    if (!IS_BLANK(CUR)) {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, 
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
			ctxt->sax->error(ctxt, 
			"Space required after the attribute default value\n");
		    ctxt->wellFormed = 0;
		    break;
		}
		SKIP_BLANKS;
	    }
	    if (check == CUR_PTR) {
	        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, 
		    "xmlParseAttributeListDecl: detected internal error\n");
		break;
	    }
	    xmlAddAttributeDecl(ctxt->doc->intSubset, elemName, attrName,
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
		ctxt->sax->error(ctxt, 
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
		    ctxt->sax->error(ctxt, 
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
		ctxt->sax->error(ctxt, 
		    "xmlParseElementMixedContentDecl : '|' or ')*' expected\n");
	    ctxt->wellFormed = 0;
	    xmlFreeElementContent(ret);
	    return(NULL);
	}

    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, 
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
		ctxt->sax->error(ctxt, 
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
		    ctxt->sax->error(ctxt, 
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
		    ctxt->sax->error(ctxt, 
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
		ctxt->sax->error(ctxt, 
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
		    ctxt->sax->error(ctxt, 
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
	    ctxt->sax->error(ctxt, 
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
	    ctxt->sax->error(ctxt, 
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
		ctxt->sax->error(ctxt, 
		    "Space required after 'ELEMENT'\n");
	    ctxt->wellFormed = 0;
	}
        SKIP_BLANKS;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt,
		   "xmlParseElementDecl: no name for Element\n");
	    ctxt->wellFormed = 0;
	    return(-1);
	}
	if (!IS_BLANK(CUR)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
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
	        ctxt->sax->error(ctxt, 
	          "xmlParseElementDecl: 'EMPTY', 'ANY' or '(' expected\n");
	    ctxt->wellFormed = 0;
	    if (name != NULL) free(name);
	    return(-1);
	}
	SKIP_BLANKS;
	if (CUR != '>') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, 
	          "xmlParseElementDecl: expected '>' at the end\n");
	    ctxt->wellFormed = 0;
	} else {
	    NEXT;
	    xmlAddElementDecl(ctxt->doc->intSubset, name, ret, content);
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
 * xmlParseCharRef:
 * @ctxt:  an XML parser context
 *
 * parse Reference declarations
 *
 * [66] CharRef ::= '&#' [0-9]+ ';' |
 *                  '&#x' [0-9a-fA-F]+ ';'
 *
 * Returns the value parsed
 */
CHAR *
xmlParseCharRef(xmlParserCtxtPtr ctxt) {
    int val = 0;
    CHAR buf[2];

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
		    ctxt->sax->error(ctxt, 
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
		    ctxt->sax->error(ctxt, 
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
	    ctxt->sax->error(ctxt, "xmlParseCharRef: invalid value\n");
	ctxt->wellFormed = 0;
    }
    /*
     * Check the value IS_CHAR ...
     */
    if (IS_CHAR(val)) {
        buf[0] = (CHAR) val;
	buf[1] = 0;
	return(xmlStrndup(buf, 1));
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "xmlParseCharRef: invalid CHAR value %d\n",
	                     val);
	ctxt->wellFormed = 0;
    }
    return(NULL);
}

/**
 * xmlParseEntityRef:
 * @ctxt:  an XML parser context
 *
 * parse ENTITY references declarations
 *
 * [68] EntityRef ::= '&' Name ';'
 *
 * Returns the entity ref string or NULL if directly as input stream.
 */
CHAR *
xmlParseEntityRef(xmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL;
    const CHAR *q;
    CHAR *name;
    xmlEntityPtr ent;
    xmlParserInputPtr input = NULL;

    q = CUR_PTR;
    if (CUR == '&') {
        NEXT;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "xmlParseEntityRef: no name\n");
	    ctxt->wellFormed = 0;
	} else {
	    if (CUR == ';') {
	        NEXT;
		/*
		 * Well Formedness Constraint if:
		 *   - standalone
		 * or
		 *   - no external subset and no external parameter entities
		 *     referenced
		 * then
		 *   the entity referenced must have been declared
		 *
		 * TODO: to be double checked !!!
		 */
		ent = xmlGetDocEntity(ctxt->doc, name);
		if ((ctxt->doc->standalone) ||
		    ((ctxt->doc->intSubset == NULL) &&
		     (ctxt->doc->extSubset == NULL))) {
		    if (ent == NULL) {
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt, 
			         "Entity '%s' not defined\n", name);
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
			    ctxt->sax->error(ctxt, 
		     "Attempt to reference the parameter entity '%s'\n", name);
			ctxt->wellFormed = 0;
			break;
                        
			case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
			if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
			    ctxt->sax->error(ctxt, 
		     "Attempt to reference unparsed entity '%s'\n", name);
			ctxt->wellFormed = 0;
			break;
		    }
		}

		/*
		 * Well Formedness Constraint :
		 *   The referenced entity must not lead to recursion !
		 */
		 
		/*
		 * We parsed the entity reference correctly, call SAX
		 * interface for the proper behaviour:
		 *   - get a new input stream
		 *   - or keep the reference inline
		 */
		if (ctxt->sax)
		    input = ctxt->sax->resolveEntity(ctxt, NULL, name);
		if (input != NULL)
		    xmlPushInput(ctxt, input);
		else {
		    ret = xmlStrndup(q, CUR_PTR - q);
		}
	    } else {
		char cst[2] = { '&', 0 };

		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt,
		                     "xmlParseEntityRef: expecting ';'\n");
		ctxt->wellFormed = 0;
		ret = xmlStrndup(cst, 1);
		ret = xmlStrcat(ret, name);
	    }
	    free(name);
	}
    }
    return(ret);
}

/**
 * xmlParseReference:
 * @ctxt:  an XML parser context
 * 
 * parse Reference declarations
 *
 * [67] Reference ::= EntityRef | CharRef
 *
 * Returns the entity string or NULL if handled directly by pushing
 *      the entity value as the input.
 */
CHAR *
xmlParseReference(xmlParserCtxtPtr ctxt) {
    if ((CUR == '&') && (NXT(1) == '#')) {
        CHAR *val = xmlParseCharRef(ctxt);
	xmlParserInputPtr in;

	if (val != NULL) {
	    in = xmlNewStringInputStream(ctxt, val);
	    xmlPushInput(ctxt, in);
	}
	return(NULL);
    } else if (CUR == '&') {
        return(xmlParseEntityRef(ctxt));
    }
    return(NULL);
}

/**
 * xmlParsePEReference:
 * @ctxt:  an XML parser context
 *
 * parse PEReference declarations
 *
 * [69] PEReference ::= '%' Name ';'
 *
 * Returns the entity content or NULL if handled directly.
 */
CHAR *
xmlParsePEReference(xmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL;
    CHAR *name;
    xmlEntityPtr entity;
    xmlParserInputPtr input;

    if (CUR == '%') {
        NEXT;
        name = xmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "xmlParsePEReference: no name\n");
	    ctxt->wellFormed = 0;
	} else {
	    if (CUR == ';') {
	        NEXT;
		entity = xmlGetDtdEntity(ctxt->doc, name);
		if (entity == NULL) {
		    if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
		        ctxt->sax->warning(ctxt,
		         "xmlParsePEReference: %%%s; not found\n", name);
		} else {
		    input = xmlNewEntityInputStream(ctxt, entity);
		    xmlPushInput(ctxt, input);
		}
	    } else {
		char cst[2] = { '%', 0 };

		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt,
		                     "xmlParsePEReference: expecting ';'\n");
		ctxt->wellFormed = 0;
		ret = xmlStrndup(cst, 1);
		ret = xmlStrcat(ret, name);
	    }
	    free(name);
	}
    }
    return(ret);
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
    xmlDtdPtr dtd;
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
	    ctxt->sax->error(ctxt, "xmlParseDocTypeDecl : no DOCTYPE name !\n");
	ctxt->wellFormed = 0;
    }

    SKIP_BLANKS;

    /*
     * Check for SystemID and ExternalID
     */
    URI = xmlParseExternalID(ctxt, &ExternalID, 1);
    SKIP_BLANKS;

    dtd = xmlCreateIntSubset(ctxt->doc, name, ExternalID, URI);

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
		    ctxt->sax->error(ctxt, 
		 "xmlParseDocTypeDecl: error detected in Markup declaration\n");
		ctxt->wellFormed = 0;
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
	    ctxt->sax->error(ctxt, "DOCTYPE unproperly terminated\n");
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
 * @node:  the node carrying the attribute
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
 * Returns the attribute just parsed of NULL in case of error.
 */

xmlAttrPtr
xmlParseAttribute(xmlParserCtxtPtr ctxt, xmlNodePtr node) {
    CHAR *name, *val;
    CHAR *ns;
    CHAR *value = NULL;
    xmlAttrPtr ret;

    name = xmlNamespaceParseQName(ctxt, &ns);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "error parsing attribute name\n");
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
	value = xmlParseAttValue(ctxt);
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
	       "Specification mandate value for attribute %s\n", name);
	ctxt->wellFormed = 0;
    }

    /*
     * Check whether it's a namespace definition
     */
    if ((ns == NULL) &&
        (name[0] == 'x') && (name[1] == 'm') && (name[2] == 'l') &&
        (name[3] == 'n') && (name[4] == 's') && (name[5] == 0)) {
	/* a default namespace definition */
	xmlNewNs(node, value, NULL);
	if (name != NULL) 
	    free(name);
	if (value != NULL)
	    free(value);
	return(NULL);
    }
    if ((ns != NULL) && (ns[0] == 'x') && (ns[1] == 'm') && (ns[2] == 'l') &&
        (ns[3] == 'n') && (ns[4] == 's') && (ns[5] == 0)) {
	/* a standard namespace definition */
	xmlNewNs(node, value, name);
	free(ns);
	if (name != NULL) 
	    free(name);
	if (value != NULL)
	    free(value);
	return(NULL);
    }

    /*
     * Well formedness requires at most one declaration of an attribute
     */
    if ((val = xmlGetProp(ctxt->node, name)) != NULL) {
        free(val);
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "Attribute %s redefined\n", name);
	ctxt->wellFormed = 0;
	ret = NULL;
    } else {
	ret = xmlNewProp(ctxt->node, name, NULL);
	if (ret != NULL)
	    ret->val = xmlStringGetNodeList(ctxt->doc, value);
    }

    if (ns != NULL)
      free(ns);
    if (value != NULL)
	free(value);
    free(name);
    return(ret);
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
 * Returns the XML new node or NULL.
 */

xmlNodePtr
xmlParseStartTag(xmlParserCtxtPtr ctxt) {
    CHAR *namespace, *name;
    xmlNsPtr ns = NULL;
    xmlNodePtr ret = NULL;
    xmlNodePtr parent = ctxt->node;

    if (CUR != '<') return(NULL);
    NEXT;

    name = xmlNamespaceParseQName(ctxt, &namespace);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, 
	     "xmlParseStartTag: invalid element name\n");
	ctxt->wellFormed = 0;
        return(NULL);
    }

    /*
     * Note : the namespace resolution is deferred until the end of the
     *        attributes parsing, since local namespace can be defined as
     *        an attribute at this level.
     */
    ret = xmlNewDocNode(ctxt->doc, ns, name, NULL);
    if (ret == NULL) {
	if (namespace != NULL)
	    free(namespace);
	free(name);
        return(NULL);
    }

    /*
     * We are parsing a new node.
     */
    nodePush(ctxt, ret);

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

	xmlParseAttribute(ctxt, ret);
	SKIP_BLANKS;

        if (q == CUR_PTR) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, 
	         "xmlParseStartTag: problem parsing attributes\n");
	    ctxt->wellFormed = 0;
	    break;
	}
    }

    /*
     * Search the namespace
     */
    ns = xmlSearchNs(ctxt->doc, ret, namespace);
    if (ns == NULL) /* ret still doesn't have a parent yet ! */
	ns = xmlSearchNs(ctxt->doc, parent, namespace);
    xmlSetNs(ret, ns);
    if (namespace != NULL)
	free(namespace);

    /*
     * SAX: Start of Element !
     */
    if (ctxt->sax != NULL)
        ctxt->sax->startElement(ctxt, name);
    free(name);

    /*
     * Link the child element
     */
    if (ctxt->nodeNr < 2) return(ret);
    parent = ctxt->nodeTab[ctxt->nodeNr - 2];
    if (parent != NULL)
	xmlAddChild(parent, ctxt->node);

    return(ret);
}

/**
 * xmlParseEndTag:
 * @ctxt:  an XML parser context
 * @nsPtr:  the current node namespace definition
 * @tagPtr:  CHAR** receive the tag value
 *
 * parse an end of tag
 *
 * [42] ETag ::= '</' Name S? '>'
 *
 * With namespace
 *
 * [9] ETag ::= '</' QName S? '>'
 *    
 * tagPtr receive the tag name just read
 */

void
xmlParseEndTag(xmlParserCtxtPtr ctxt, xmlNsPtr *nsPtr, CHAR **tagPtr) {
    CHAR *namespace, *name;
    xmlNsPtr ns = NULL;

    *nsPtr = NULL;
    *tagPtr = NULL;

    if ((CUR != '<') || (NXT(1) != '/')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "xmlParseEndTag: '</' not found\n");
	ctxt->wellFormed = 0;
	return;
    }
    SKIP(2);

    name = xmlNamespaceParseQName(ctxt, &namespace);

    /*
     * Search the namespace
     */
    ns = xmlSearchNs(ctxt->doc, ctxt->node, namespace);
    if (namespace != NULL)
	free(namespace);

    *nsPtr = ns;
    *tagPtr = name;

    /*
     * We should definitely be at the ending "S? '>'" part
     */
    SKIP_BLANKS;
    if ((!IS_CHAR(CUR)) || (CUR != '>')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "End tag : expected '>'\n");
	ctxt->wellFormed = 0;
    } else
	NEXT;

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
	    ctxt->sax->error(ctxt, "CData section not finished\n%.50s\n", base);
	ctxt->wellFormed = 0;
        return;
    }
    r = NEXT;
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "CData section not finished\n%.50s\n", base);
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
	    ctxt->sax->error(ctxt, "CData section not finished\n%.50s\n", base);
	ctxt->wellFormed = 0;
        return;
    }

    /*
     * Ok the segment [base CUR_PTR] is to be consumed as chars.
     */
    if (ctxt->sax != NULL) {
	if (areBlanks(ctxt, base, CUR_PTR - base))
	    ctxt->sax->ignorableWhitespace(ctxt, base, 0, (CUR_PTR - base) - 2);
	else
	    ctxt->sax->characters(ctxt, base, 0, (CUR_PTR - base) - 2);
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
    xmlNodePtr ret = NULL;

    while ((CUR != '<') || (NXT(1) != '/')) {
	const CHAR *test = CUR_PTR;
        ret = NULL;

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
	    ret = xmlParseComment(ctxt, 1);
	}
	/*
	 * Fourth case :  a sub-element.
	 */
	else if (CUR == '<') {
	    ret = xmlParseElement(ctxt);
	}
	/*
	 * Fifth case : a reference. If if has not been resolved,
	 *    parsing returns it's Name, create the node 
	 */
	else if (CUR == '&') {
	    CHAR *val = xmlParseReference(ctxt);
	    if (val != NULL) {
	        if (val[0] != '&') {
		    /*
		     * inline predefined entity.
		     */
                    if (ctxt->sax != NULL)
			ctxt->sax->characters(ctxt, val, 0, xmlStrlen(val));
		} else {
		    /*
		     * user defined entity, create a node.
		     */
		    ret = xmlNewReference(ctxt->doc, val);
		    xmlAddChild(ctxt->node, ret);
		}
		free(val);
	    }
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
	while ((CUR == 0) && (ctxt->inputNr > 1)) xmlPopInput(ctxt);

	if (test == CUR_PTR) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt,
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
 *
 * Returns the XML new node or NULL
 */


xmlNodePtr
xmlParseElement(xmlParserCtxtPtr ctxt) {
    xmlNodePtr ret;
    const CHAR *openTag = CUR_PTR;
    xmlParserNodeInfo node_info;
    CHAR *endTag;
    xmlNsPtr endNs;

    /* Capture start position */
    node_info.begin_pos = CUR_PTR - ctxt->input->base;
    node_info.begin_line = ctxt->input->line;

    ret = xmlParseStartTag(ctxt);
    if (ret == NULL) {
        return(NULL);
    }

    /*
     * Check for an Empty Element.
     */
    if ((CUR == '/') && (NXT(1) == '>')) {
        SKIP(2);
	if (ctxt->sax != NULL)
	    ctxt->sax->endElement(ctxt, ret->name);

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);

	return(ret);
    }
    if (CUR == '>') NEXT;
    else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "Couldn't find end of Start Tag\n%.30s\n",
	                     openTag);
	ctxt->wellFormed = 0;

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);

	return(NULL);
    }

    /*
     * Parse the content of the element:
     */
    xmlParseContent(ctxt);
    if (!IS_CHAR(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
	         "Premature end of data in tag %.30s\n", openTag);
	ctxt->wellFormed = 0;

	/*
	 * end of parsing of this node.
	 */
	nodePop(ctxt);

	return(NULL);
    }

    /*
     * parse the end of tag: '</' should be here.
     */
    xmlParseEndTag(ctxt, &endNs, &endTag);

    /*
     * Check that the Name in the ETag is the same as in the STag.
     */
    if (endNs != ret->ns) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, 
	    "Start and End tags don't use the same namespace\n%.30s\n%.30s\n",
	               openTag, endTag);
	ctxt->wellFormed = 0;
    }
    if (endTag == NULL ) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "The End tag has no name\n%.30s\n", openTag);
	ctxt->wellFormed = 0;
    } else if (xmlStrcmp(ret->name, endTag)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, 
	    "Start and End tags don't use the same name\n%.30s\n%.30s\n",
	               openTag, endTag);
	ctxt->wellFormed = 0;
    }
    /*
     * SAX: End of Tag
     */
    else if (ctxt->sax != NULL)
        ctxt->sax->endElement(ctxt, endTag);

    if (endTag != NULL)
	free(endTag);

    /* Capture end position and add node */
    if ( ret != NULL && ctxt->record_info ) {
      node_info.end_pos = CUR_PTR - ctxt->input->base;
      node_info.end_line = ctxt->input->line;
      node_info.node = ret;
      xmlParserAddNodeInfo(ctxt, &node_info);
    }

    /*
     * end of parsing of this node.
     */
    nodePop(ctxt);

    return(ret);
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
	        ctxt->sax->error(ctxt, "xmlParseVersionInfo : expected '='\n");
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
		    ctxt->sax->error(ctxt, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else if (CUR == '\''){
	    NEXT;
	    q = CUR_PTR;
	    version = xmlParseVersionNum(ctxt);
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt,
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
	    ctxt->sax->error(ctxt, "Invalid XML encoding name\n");
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
	        ctxt->sax->error(ctxt, "xmlParseEncodingDecl : expected '='\n");
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
		    ctxt->sax->error(ctxt, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else if (CUR == '\''){
	    NEXT;
	    q = CUR_PTR;
	    encoding = xmlParseEncName(ctxt);
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, "String not closed\n%.50s\n", q);
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else if (CUR == '"'){
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt,
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
	if (CUR != '=') {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt,
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
		    ctxt->sax->error(ctxt, "standalone accepts only 'yes' or 'no'\n");
		ctxt->wellFormed = 0;
	    }
	    if (CUR != '\'') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, "String not closed\n");
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
		    ctxt->sax->error(ctxt,
		        "standalone accepts only 'yes' or 'no'\n");
		ctxt->wellFormed = 0;
	    }
	    if (CUR != '"') {
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt, "String not closed\n");
		ctxt->wellFormed = 0;
	    } else
	        NEXT;
	} else {
            if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt, "Standalone value not found\n");
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
	    ctxt->sax->error(ctxt, "Blank needed after '<?xml'\n");
	ctxt->wellFormed = 0;
    }
    SKIP_BLANKS;

    /*
     * We should have the VersionInfo here.
     */
    version = xmlParseVersionInfo(ctxt);
    if (version == NULL)
	version = xmlCharStrdup(XML_DEFAULT_VERSION);
    ctxt->doc = xmlNewDoc(version);
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
	    ctxt->sax->error(ctxt, "Blank needed here\n");
	ctxt->wellFormed = 0;
    }
    ctxt->doc->encoding = xmlParseEncodingDecl(ctxt);

    /*
     * We may have the standalone status.
     */
    if ((ctxt->doc->encoding != NULL) && (!IS_BLANK(CUR))) {
        if ((CUR == '?') && (NXT(1) == '>')) {
	    SKIP(2);
	    return;
	}
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "Blank needed here\n");
	ctxt->wellFormed = 0;
    }
    SKIP_BLANKS;
    ctxt->doc->standalone = xmlParseSDDecl(ctxt);

    SKIP_BLANKS;
    if ((CUR == '?') && (NXT(1) == '>')) {
        SKIP(2);
    } else if (CUR == '>') {
        /* Deprecated old WD ... */
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "XML declaration must end-up with '?>'\n");
	ctxt->wellFormed = 0;
	NEXT;
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "parsing XML declaration: '?>' expected\n");
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
    if (ctxt->sax) 
        ctxt->sax->setDocumentLocator(ctxt, &xmlDefaultSAXLocator);
    if (ctxt->sax)
        ctxt->sax->startDocument(ctxt);

    /*
     * We should check for encoding here and plug-in some
     * conversion code TODO !!!!
     */

    /*
     * Wipe out everything which is before the first '<'
     */
    if (IS_BLANK(CUR)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
	    "Extra spaces at the beginning of the document are not allowed\n");
	ctxt->wellFormed = 0;
	SKIP_BLANKS;
    }

    if (CUR == 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt, "Document is empty\n");
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
	CHAR *version;

	version = xmlCharStrdup(XML_DEFAULT_VERSION);
	ctxt->doc = xmlNewDoc(version);
	free(version);
    }

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
    ctxt->doc->root = xmlParseElement(ctxt);

    /*
     * The Misc part at the end
     */
    xmlParseMisc(ctxt);

    if (CUR != 0) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt,
	        "Extra content at the end of the document\n");
	ctxt->wellFormed = 0;
    }

    /*
     * SAX: end of the document processing.
     */
    if (ctxt->sax) 
        ctxt->sax->endDocument(ctxt);
    if (! ctxt->wellFormed) return(-1);
    return(0);
}

/**
 * xmlCreateFileParserCtxt :
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
    if (sax != NULL) ctxt->sax = sax;

    xmlParseDocument(ctxt);
    if ((ctxt->wellFormed) || recovery) ret = ctxt->doc;
    else {
       ret = NULL;
       xmlFreeDoc(ctxt->doc);
       ctxt->doc = NULL;
    }
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
    struct stat buf;
    char *buffer;
    xmlParserInputPtr inputStream;

    res = stat(filename, &buf);
    if (res < 0) return(NULL);

#ifdef HAVE_ZLIB_H
    len = (buf.st_size * 8) + 1000;
retry_bigger:
    buffer = malloc(len);
#else
    len = buf.st_size + 100;
    buffer = malloc(len);
#endif
    if (buffer == NULL) {
	perror("malloc");
        return(NULL);
    }

    memset(buffer, 0, len);
#ifdef HAVE_ZLIB_H
    input = gzopen (filename, "r");
    if (input == NULL) {
        fprintf (stderr, "Cannot read file %s :\n", filename);
	perror ("gzopen failed");
	return(NULL);
    }
#else
    input = open (filename, O_RDONLY);
    if (input < 0) {
        fprintf (stderr, "Cannot read file %s :\n", filename);
	perror ("open failed");
	return(NULL);
    }
#endif
#ifdef HAVE_ZLIB_H
    res = gzread(input, buffer, len);
#else
    res = read(input, buffer, buf.st_size);
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
#ifdef HAVE_ZLIB_H
    gzclose(input);
    if (res >= len) {
        free(buffer);
	len *= 2;
	goto retry_bigger;
    }
    buf.st_size = res;
#else
    close(input);
#endif

    buffer[buf.st_size] = '\0';

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
     * TODO : plug some encoding conversion routines here. !!!
     */
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

xmlDocPtr xmlSAXParseFile(xmlSAXHandlerPtr sax, const char *filename,
                          int recovery) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreateFileParserCtxt(filename);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) ctxt->sax = sax;

    xmlParseDocument(ctxt);

    if ((ctxt->wellFormed) || recovery) ret = ctxt->doc;
    else {
       ret = NULL;
       xmlFreeDoc(ctxt->doc);
       ctxt->doc = NULL;
    }
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

xmlDocPtr xmlParseFile(const char *filename) {
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

xmlDocPtr xmlRecoverFile(const char *filename) {
    return(xmlSAXParseFile(NULL, filename, 1));
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
     * TODO : plug some encoding conversion routines here. !!!
     */
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
 * TODO : plug some encoding conversion routines here. !!!
 *
 * Returns the resulting document tree
 */
xmlDocPtr
xmlSAXParseMemory(xmlSAXHandlerPtr sax, char *buffer, int size, int recovery) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) ctxt->sax = sax;

    xmlParseDocument(ctxt);

    if ((ctxt->wellFormed) || recovery) ret = ctxt->doc;
    else {
       ret = NULL;
       xmlFreeDoc(ctxt->doc);
       ctxt->doc = NULL;
    }
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
    /* Allocate the Input stack */
    ctxt->inputTab = (xmlParserInputPtr *) malloc(5 * sizeof(xmlParserInputPtr));
    ctxt->inputNr = 0;
    ctxt->inputMax = 5;
    ctxt->input = NULL;

    /* Allocate the Node stack */
    ctxt->nodeTab = (xmlNodePtr *) malloc(10 * sizeof(xmlNodePtr));
    ctxt->nodeNr = 0;
    ctxt->nodeMax = 10;
    ctxt->node = NULL;

    ctxt->sax = &xmlDefaultSAXHandler;
    ctxt->doc = NULL;
    ctxt->wellFormed = 1;
    ctxt->record_info = 0;
    xmlInitNodeInfoSeq(&ctxt->node_seq);
}

/**
 * xmlFreeParserCtxt:
 * @ctxt:  an XML parser context
 *
 * Free all the memory used by a parser context. However the parsed
 * document in ctxt->doc is not freed.
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
	    ctxt->sax->error(ctxt, "Out of memory\n");
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
