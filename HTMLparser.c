/*
 * HTMLparser.c : an HTML 4.0 non-verifying parser
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
#include "HTMLparser.h"
#include "entities.h"
#include "encoding.h"
#include "valid.h"
#include "parserInternals.h"

#define DEBUG

/************************************************************************
 *									*
 * 		The list of HTML elements and their properties		*
 *									*
 ************************************************************************/

typedef struct htmlElemDesc {
    const CHAR *name;	/* The tag name */
    int startTag;       /* Whether the start tag can be implied */
    int endTag;         /* Whether the end tag can be implied */
    int empty;          /* Is this an empty element ? */
    int depr;           /* Is this a deprecated element ? */
    int dtd;            /* 1: only in Loose DTD, 2: only Frameset one */
    const char *desc;   /* the description */
} htmlElemDesc, *htmlElemDescPtr;

/*
 * Name	Start Tag End Tag   Empty   Depr.     DTD  Description
 */
htmlElemDesc  html40ElementTable[] = {
{ "A",		0,	0,	0,	0,	0, "anchor " },
{ "ABBR",	0,	0,	0,	0,	0, "abbreviated form" },
{ "ACRONYM",	0,	0,	0,	0,	0, "" },
{ "ADDRESS",	0,	0,	0,	0,	0, "information on author " },
{ "APPLET",	0,	0,	0,	1,	1, "Java applet " },
{ "AREA",	0,	2,	1,	0,	0, "client-side image map area " },
{ "B",		0,	0,	0,	0,	0, "bold text style" },
{ "BASE",	0,	2,	1,	0,	0, "document base URI " },
{ "BASEFONT",	0,	2,	1,	1,	1, "base font size " },
{ "BDO",	0,	0,	0,	0,	0, "I18N BiDi over-ride " },
{ "BIG",	0,	0,	0,	0,	0, "large text style" },
{ "BLOCKQUOTE",	0,	0,	0,	0,	0, "long quotation " },
{ "BODY",	1,	1,	0,	0,	0, "document body " },
{ "BR",		0,	2,	1,	0,	0, "forced line break " },
{ "BUTTON",	0,	0,	0,	0,	0, "push button " },
{ "CAPTION",	0,	0,	0,	0,	0, "table caption " },
{ "CENTER",	0,	0,	0,	1,	1, "shorthand for DIV align=center " },
{ "CITE",	0,	0,	0,	0,	0, "citation" },
{ "CODE",	0,	0,	0,	0,	0, "computer code fragment" },
{ "COL",	0,	2,	1,	0,	0, "table column " },
{ "COLGROUP",	0,	1,	0,	0,	0, "table column group " },
{ "DD",		0,	1,	0,	0,	0, "definition description " },
{ "DEL",	0,	0,	0,	0,	0, "deleted text " },
{ "DFN",	0,	0,	0,	0,	0, "instance definition" },
{ "DIR",	0,	0,	0,	1,	1, "directory list" },
{ "DIV",	0,	0,	0,	0,	0, "generic language/style container"},
{ "DL",		0,	0,	0,	0,	0, "definition list " },
{ "DT",		0,	1,	0,	0,	0, "definition term " },
{ "EM",		0,	0,	0,	0,	0, "emphasis" },
{ "FIELDSET",	0,	0,	0,	0,	0, "form control group " },
{ "FONT",	0,	0,	0,	1,	1, "local change to font " },
{ "FORM",	0,	0,	0,	0,	0, "interactive form " },
{ "FRAME",	0,	2,	1,	0,	2, "subwindow " },
{ "FRAMESET",	0,	0,	0,	0,	2, "window subdivision" },
{ "H1",		0,	0,	0,	0,	0, "heading " },
{ "H2",		0,	0,	0,	0,	0, "heading " },
{ "H3",		0,	0,	0,	0,	0, "heading " },
{ "H4",		0,	0,	0,	0,	0, "heading " },
{ "H5",		0,	0,	0,	0,	0, "heading " },
{ "H6",		0,	0,	0,	0,	0, "heading " },
{ "HEAD",	1,	1,	0,	0,	0, "document head " },
{ "HR",		0,	2,	1,	0,	0, "horizontal rule " },
{ "HTML",	1,	1,	0,	0,	0, "document root element " },
{ "I",		0,	0,	0,	0,	0, "italic text style" },
{ "IFRAME",	0,	0,	0,	0,	1, "inline subwindow " },
{ "IMG",	0,	2,	1,	0,	0, "Embedded image " },
{ "INPUT",	0,	2,	1,	0,	0, "form control " },
{ "INS",	0,	0,	0,	0,	0, "inserted text" },
{ "ISINDEX",	0,	2,	1,	1,	1, "single line prompt " },
{ "KBD",	0,	0,	0,	0,	0, "text to be entered by the user" },
{ "LABEL",	0,	0,	0,	0,	0, "form field label text " },
{ "LEGEND",	0,	0,	0,	0,	0, "fieldset legend " },
{ "LI",		0,	1,	0,	0,	0, "list item " },
{ "LINK",	0,	2,	1,	0,	0, "a media-independent link " },
{ "MAP",	0,	0,	0,	0,	0, "client-side image map " },
{ "MENU",	0,	0,	0,	1,	1, "menu list " },
{ "META",	0,	2,	1,	0,	0, "generic metainformation " },
{ "NOFRAMES",	0,	0,	0,	0,	2, "alternate content container for non frame-based rendering " },
{ "NOSCRIPT",	0,	0,	0,	0,	0, "alternate content container for non script-based rendering " },
{ "OBJECT",	0,	0,	0,	0,	0, "generic embedded object " },
{ "OL",		0,	0,	0,	0,	0, "ordered list " },
{ "OPTGROUP",	0,	0,	0,	0,	0, "option group " },
{ "OPTION",	0,	1,	0,	0,	0, "selectable choice " },
{ "P",		0,	1,	0,	0,	0, "paragraph " },
{ "PARAM",	0,	2,	1,	0,	0, "named property value " },
{ "PRE",	0,	0,	0,	0,	0, "preformatted text " },
{ "Q",		0,	0,	0,	0,	0, "short inline quotation " },
{ "S",		0,	0,	0,	1,	1, "strike-through text style" },
{ "SAMP",	0,	0,	0,	0,	0, "sample program output, scripts, etc." },
{ "SCRIPT",	0,	0,	0,	0,	0, "script statements " },
{ "SELECT",	0,	0,	0,	0,	0, "option selector " },
{ "SMALL",	0,	0,	0,	0,	0, "small text style" },
{ "SPAN",	0,	0,	0,	0,	0, "generic language/style container " },
{ "STRIKE",	0,	0,	0,	1,	1, "strike-through text" },
{ "STRONG",	0,	0,	0,	0,	0, "strong emphasis" },
{ "STYLE",	0,	0,	0,	0,	0, "style info " },
{ "SUB",	0,	0,	0,	0,	0, "subscript" },
{ "SUP",	0,	0,	0,	0,	0, "superscript " },
{ "TABLE",	0,	0,	0,	0,	0, "&#160;" },
{ "TBODY",	1,	1,	0,	0,	0, "table body " },
{ "TD",		0,	1,	0,	0,	0, "table data cell" },
{ "TEXTAREA",	0,	0,	0,	0,	0, "multi-line text field " },
{ "TFOOT",	0,	1,	0,	0,	0, "table footer " },
{ "TH",		0,	1,	0,	0,	0, "table header cell" },
{ "THEAD",	0,	1,	0,	0,	0, "table header " },
{ "TITLE",	0,	0,	0,	0,	0, "document title " },
{ "TR",		0,	1,	0,	0,	0, "table row " },
{ "TT",		0,	0,	0,	0,	0, "teletype or monospaced text style" },
{ "U",		0,	0,	0,	1,	1, "underlined text style" },
{ "UL",		0,	0,	0,	0,	0, "unordered list " },
{ "VAR",	0,	0,	0,	0,	0, "instance of a variable or program argument" },
};

/*
 * start tags that imply the end of a current element
 * any tag of each line implies the end of the current element if the type of
 * that element is in the same line
 */
CHAR *htmlEquEnd[] = {
"DT", "DD", "LI", "OPTION", NULL,
"H1", "H2", "H3", "H4", "H5", "H6", NULL,
"OL", "MENU", "DIR", "ADDRESS", "PRE", "LISTING", "XMP", NULL,
NULL
};
/*
 * acording the HTML DTD, HR should be added to the 2nd line above, as it
 * is not allowed within a H1, H2, H3, etc. But we should tolerate that case
 * because many documents contain rules in headings...
 */

/*
 * start tags that imply the end of current element
 */
CHAR *htmlStartClose[] = {
"FORM",		"FORM", "P", "HR", "H1", "H2", "H3", "H4", "H5", "H6",
		"DL", "UL", "OL", "MENU", "DIR", "ADDRESS", "PRE",
		"LISTING", "XMP", "HEAD", NULL,
"HEAD",		"P", NULL,
"TITLE",	"P", NULL,
"BODY",		"HEAD", "STYLE", "LINK", "TITLE", "P", NULL,
"LI",		"P", "H1", "H2", "H3", "H4", "H5", "H6", "DL", "ADDRESS",
		"PRE", "LISTING", "XMP", "HEAD", NULL,
"HR",		"P", "HEAD", NULL,
"H1",		"P", "HEAD", NULL,
"H2",		"P", "HEAD", NULL,
"H3",		"P", "HEAD", NULL,
"H4",		"P", "HEAD", NULL,
"H5",		"P", "HEAD", NULL,
"H6",		"P", "HEAD", NULL,
"DIR",		"P", "HEAD", NULL,
"ADDRESS",	"P", "HEAD", "UL", NULL,
"PRE",		"P", "HEAD", "UL", NULL,
"LISTING",	"P", "HEAD", NULL,
"XMP",		"P", "HEAD", NULL,
"BLOCKQUOTE",	"P", "HEAD", NULL,
"DL",		"P", "DT", "MENU", "DIR", "ADDRESS", "PRE", "LISTING",
		"XMP", "HEAD", NULL,
"DT",		"P", "MENU", "DIR", "ADDRESS", "PRE", "LISTING", "XMP", "HEAD", NULL,
"DD",		"P", "MENU", "DIR", "ADDRESS", "PRE", "LISTING", "XMP", "HEAD", NULL,
"UL",		"P", "HEAD", "OL", "MENU", "DIR", "ADDRESS", "PRE",
		"LISTING", "XMP", NULL,
"OL",		"P", "HEAD", "UL", NULL,
"MENU",		"P", "HEAD", "UL", NULL,
"P",		"P", "HEAD", "H1", "H2", "H3", "H4", "H5", "H6", NULL,
"DIV",		"P", "HEAD", NULL,
"NOSCRIPT",	"P", "HEAD", NULL,
"CENTER",	"FONT", "B", "I", "P", "HEAD", NULL,
"A",		"A", NULL,
"CAPTION",	"P", NULL,
"COLGROUP",	"CAPTION", "COLGROUP", "COL", "P", NULL,
"COL",		"CAPTION", "COL", "P", NULL,
"TABLE",	"P", "HEAD", "H1", "H2", "H3", "H4", "H5", "H6", "PRE",
		"LISTING", "XMP", "A", NULL,
"TH",		"TH", "TD", NULL,
"TD",		"TH", "TD", NULL,
"TR",		"TH", "TD", "TR", "CAPTION", "COL", "COLGROUP", NULL,
"THEAD",	"CAPTION", "COL", "COLGROUP", NULL,
"TFOOT",	"TH", "TD", "TR", "CAPTION", "COL", "COLGROUP", "THEAD",
		"TBODY", NULL,
"TBODY",	"TH", "TD", "TR", "CAPTION", "COL", "COLGROUP", "THEAD",
		"TFOOT", "TBODY", NULL,
"OPTGROUP",	"OPTION", NULL,
"FIELDSET",	"LEGEND", "P", "HEAD", "H1", "H2", "H3", "H4", "H5", "H6",
		"PRE", "LISTING", "XMP", "A", NULL,
NULL
};

static CHAR** htmlStartCloseIndex[100];
static int htmlStartCloseIndexinitialized = 0;

/************************************************************************
 *									*
 * 		functions to handle HTML specific data			*
 *									*
 ************************************************************************/

/**
 * htmlInitAutoClose:
 *
 * Initialize the htmlStartCloseIndex for fast lookup of closing tags names.
 *
 */
void
htmlInitAutoClose(void) {
    int index, i = 0;

    if (htmlStartCloseIndexinitialized) return;

    for (index = 0;index < 100;index ++) htmlStartCloseIndex[index] = NULL;
    index = 0;
    while ((htmlStartClose[i] != NULL) && (index < 100 - 1)) {
        htmlStartCloseIndex[index++] = &htmlStartClose[i];
	while (htmlStartClose[i] != NULL) i++;
	i++;
    }
}

/**
 * htmlTagLookup:
 * @tag:  The tag name
 *
 * Lookup the HTML tag in the ElementTable
 *
 * Returns the related htmlElemDescPtr or NULL if not found.
 */
htmlElemDescPtr
htmlTagLookup(const CHAR *tag) {
    int i = 0;

    for (i = 0; i < (sizeof(html40ElementTable) /
                     sizeof(html40ElementTable[0]));i++) {
        if (!xmlStrcmp(tag, html40ElementTable[i].name))
	    return(&html40ElementTable[i]);
    }
    return(NULL);
}

/**
 * htmlCheckAutoClose:
 * @new:  The new tag name
 * @old:  The old tag name
 *
 * Checks wether the new tag is one of the registered valid tags for closing old.
 * Initialize the htmlStartCloseIndex for fast lookup of closing tags names.
 *
 * Returns 0 if no, 1 if yes.
 */
int
htmlCheckAutoClose(const CHAR *new, const CHAR *old) {
    int i, index;
    CHAR **close;

    if (htmlStartCloseIndexinitialized == 0) htmlInitAutoClose();

    /* inefficient, but not a big deal */
    for (index = 0; index < 100;index++) {
        close = htmlStartCloseIndex[index];
	if (close == NULL) return(0);
	if (!xmlStrcmp(*close, new)) break;
    }

    i = close - htmlStartClose;
    i++;
    while (htmlStartClose[i] != NULL) {
        if (!xmlStrcmp(htmlStartClose[i], old)) {
#ifdef DEBUG
            printf("htmlCheckAutoClose: %s closes %s\n", new, old);
#endif
	    return(1);
	}
	i++;
    }
    return(0);
}

/**
 * htmlAutoClose:
 * @ctxt:  an HTML parser context
 * @new:  The new tag name
 *
 * The HTmL DtD allows a tag to implicitely close other tags.
 * The list is kept in htmlStartClose array. This function is
 * called when a new tag has been detected and generates the
 * appropriates closes if possible/needed.
 */
void
htmlAutoClose(htmlParserCtxtPtr ctxt, const CHAR *new) {
    const CHAR *old;

    while ((ctxt->node != NULL) && 
           (htmlCheckAutoClose(new, ctxt->node->name))) {
	if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL))
	    ctxt->sax->endElement(ctxt->userData, ctxt->node->name);
    }
}


/************************************************************************
 *									*
 * 		Parser stacks related functions and macros		*
 *									*
 ************************************************************************/

/*
 * Generic function for accessing stacks in the Parser Context
 */

#define PUSH_AND_POP(type, name)					\
int html##name##Push(htmlParserCtxtPtr ctxt, type value) {		\
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
type html##name##Pop(htmlParserCtxtPtr ctxt) {				\
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
		(ctxt->input->cur))
#else
#endif


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
 * htmlDecodeEntities:
 * @ctxt:  the parser context
 * @len:  the len to decode (in bytes !), -1 for no size limit
 * @end:  an end marker CHAR, 0 if none
 * @end2:  an end marker CHAR, 0 if none
 * @end3:  an end marker CHAR, 0 if none
 *
 * Subtitute the HTML entitis by their value
 *
 * Returns A newly allocated string with the substitution done. The caller
 *      must deallocate it !
 */
CHAR *
htmlDecodeEntities(htmlParserCtxtPtr ctxt, int len,
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

        if (CUR == '&') {
	    if (NXT(1) == '#') {
		int val = htmlParseCharRef(ctxt);
		/* TODO: invalid for UTF-8 variable encoding !!! */
		*out++ = val;
	    } else {
		ent = htmlParseEntityRef(ctxt);
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
 * htmlSwitchEncoding:
 * @ctxt:  the parser context
 * @len:  the len of @cur
 *
 * change the input functions when discovering the character encoding
 * of a given entity.
 *
 */
void
htmlSwitchEncoding(htmlParserCtxtPtr ctxt, xmlCharEncoding enc)
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
 *		Commodity functions, cleanup needed ?			*
 *									*
 ************************************************************************/

/**
 * areBlanks:
 * @ctxt:  an HTML parser context
 * @str:  a CHAR *
 * @len:  the size of @str
 *
 * Is this a sequence of blank chars that one can ignore ?
 *
 * TODO: to be corrected accodingly to DTD information if available
 *
 * Returns 1 if ignorable 0 otherwise.
 */

static int areBlanks(htmlParserCtxtPtr ctxt, const CHAR *str, int len) {
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
 * htmlHandleEntity:
 * @ctxt:  an HTML parser context
 * @entity:  an XML entity pointer.
 *
 * Default handling of an HTML entity, call the parser with the
 * substitution string
 */

void
htmlHandleEntity(htmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
    int len;

    if (entity->content == NULL) {
        if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "htmlHandleEntity %s: content == NULL\n",
	               entity->name);
	ctxt->wellFormed = 0;
        return;
    }
    len = xmlStrlen(entity->content);

    /*
     * Just handle the content as a set of chars.
     */
    if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	ctxt->sax->characters(ctxt->userData, entity->content, len);

}

/**
 * htmlNewDoc:
 * @URI:  URI for the dtd, or NULL
 * @ExternalID:  the external ID of the DTD, or NULL
 *
 * Returns a new document
 */
htmlDocPtr
htmlNewDoc(const CHAR *URI, const CHAR *ExternalID) {
    xmlDocPtr cur;

    /*
     * Allocate a new document and fill the fields.
     */
    cur = (xmlDocPtr) malloc(sizeof(xmlDoc));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDoc : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_DOCUMENT_NODE;
    cur->version = NULL;
    if (ExternalID != NULL) cur->ID = xmlStrdup(ExternalID); 
    else cur->ID = NULL;
    if (URI != NULL) cur->DTD = xmlStrdup(URI); 
    else cur->DTD = NULL;
    cur->name = NULL;
    cur->root = NULL; 
    cur->intSubset = NULL;
    cur->extSubset = NULL;
    cur->oldNs = NULL;
    cur->encoding = NULL;
    cur->standalone = 1;
    cur->compression = 0;
#ifndef XML_WITHOUT_CORBA
    cur->_private = NULL;
    cur->vepv = NULL;
#endif
    return(cur);
}


/************************************************************************
 *									*
 *			The parser itself				*
 *	Relates to http://www.w3.org/TR/html40				*
 *									*
 ************************************************************************/

/************************************************************************
 *									*
 *			The parser itself				*
 *									*
 ************************************************************************/

/**
 * htmlParseHTMLName:
 * @ctxt:  an HTML parser context
 *
 * parse an HTML tag or attribute name, note that we convert it to uppercase
 * since HTML names are not case-sensitive.
 *
 * Returns the Tag Name parsed or NULL
 */

CHAR *
htmlParseHTMLName(htmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL;
    int i = 0;
    CHAR loc[100];

    if (!IS_LETTER(CUR) && (CUR != '_') &&
        (CUR != ':')) return(NULL);

    while ((i < 100) && ((IS_LETTER(CUR)) || (IS_DIGIT(CUR)))) {
	if ((CUR >= 0x61) && (CUR <= 0x7a)) loc[i] = CUR - 0x20;
        else loc[i] = CUR;
	i++;
	
	NEXT;
    }
    
    ret = xmlStrndup(loc, i);

    return(ret);
}

/**
 * htmlParseName:
 * @ctxt:  an HTML parser context
 *
 * parse an HTML name, this routine is case sensistive.
 *
 * Returns the Name parsed or NULL
 */

CHAR *
htmlParseName(htmlParserCtxtPtr ctxt) {
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
 * htmlParseNmtoken:
 * @ctxt:  an HTML parser context
 * 
 * parse an HTML Nmtoken.
 *
 * Returns the Nmtoken parsed or NULL
 */

CHAR *
htmlParseNmtoken(htmlParserCtxtPtr ctxt) {
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
 * htmlParseEntityRef:
 * @ctxt:  an HTML parser context
 *
 * parse ENTITY references declarations
 *
 * [68] EntityRef ::= '&' Name ';'
 *
 * Returns the xmlEntityPtr if found, or NULL otherwise.
 */
xmlEntityPtr
htmlParseEntityRef(htmlParserCtxtPtr ctxt) {
    const CHAR *q; /* !!!!!!!!!!! Unused !!!!!!!!!! */
    CHAR *name;
    xmlEntityPtr ent = NULL;

    q = CUR_PTR;
    if (CUR == '&') {
        NEXT;
        name = htmlParseName(ctxt);
	if (name == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, "htmlParseEntityRef: no name\n");
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
		                     "htmlParseEntityRef: expecting ';'\n");
		ctxt->wellFormed = 0;
	    }
	    free(name);
	}
    }
    return(ent);
}

/**
 * htmlParseAttValue:
 * @ctxt:  an HTML parser context
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
htmlParseAttValue(htmlParserCtxtPtr ctxt) {
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
 * htmlParseSystemLiteral:
 * @ctxt:  an HTML parser context
 * 
 * parse an HTML Literal
 *
 * [11] SystemLiteral ::= ('"' [^"]* '"') | ("'" [^']* "'")
 *
 * Returns the SystemLiteral parsed or NULL
 */

CHAR *
htmlParseSystemLiteral(htmlParserCtxtPtr ctxt) {
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
 * htmlParsePubidLiteral:
 * @ctxt:  an HTML parser context
 *
 * parse an HTML public literal
 *
 * [12] PubidLiteral ::= '"' PubidChar* '"' | "'" (PubidChar - "'")* "'"
 *
 * Returns the PubidLiteral parsed or NULL.
 */

CHAR *
htmlParsePubidLiteral(htmlParserCtxtPtr ctxt) {
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
 * htmlParseCharData:
 * @ctxt:  an HTML parser context
 * @cdata:  int indicating whether we are within a CDATA section
 *
 * parse a CharData section.
 * if we are within a CDATA section ']]>' marks an end of section.
 *
 * [14] CharData ::= [^<&]* - ([^<&]* ']]>' [^<&]*)
 */

void
htmlParseCharData(htmlParserCtxtPtr ctxt, int cdata) {
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
 * htmlParseExternalID:
 * @ctxt:  an HTML parser context
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
htmlParseExternalID(htmlParserCtxtPtr ctxt, CHAR **publicID, int strict) {
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
	URI = htmlParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData,
	          "htmlParseExternalID: SYSTEM, no URI\n");
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
	*publicID = htmlParsePubidLiteral(ctxt);
	if (*publicID == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	          "htmlParseExternalID: PUBLIC, no Public Identifier\n");
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
	URI = htmlParseSystemLiteral(ctxt);
	if (URI == NULL) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	        ctxt->sax->error(ctxt->userData, 
	           "htmlParseExternalID: PUBLIC, no URI\n");
	    ctxt->wellFormed = 0;
        }
    }
    return(URI);
}

/**
 * htmlParseComment:
 * @ctxt:  an HTML parser context
 * @create: should we create a node, or just skip the content
 *
 * Parse an XML (SGML) comment <!-- .... -->
 *
 * [15] Comment ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
 */
void
htmlParseComment(htmlParserCtxtPtr ctxt, int create) {
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
 * htmlParseCharRef:
 * @ctxt:  an HTML parser context
 *
 * parse Reference declarations
 *
 * [66] CharRef ::= '&#' [0-9]+ ';' |
 *                  '&#x' [0-9a-fA-F]+ ';'
 *
 * Returns the value parsed (as an int)
 */
int
htmlParseCharRef(htmlParserCtxtPtr ctxt) {
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
		         "htmlParseCharRef: invalid hexadecimal value\n");
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
		         "htmlParseCharRef: invalid decimal value\n");
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
	    ctxt->sax->error(ctxt->userData, "htmlParseCharRef: invalid value\n");
	ctxt->wellFormed = 0;
    }
    /*
     * Check the value IS_CHAR ...
     */
    if (IS_CHAR(val)) {
        return(val);
    } else {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "htmlParseCharRef: invalid CHAR value %d\n",
	                     val);
	ctxt->wellFormed = 0;
    }
    return(0);
}


/**
 * htmlParseDocTypeDecl :
 * @ctxt:  an HTML parser context
 *
 * parse a DOCTYPE declaration
 *
 * [28] doctypedecl ::= '<!DOCTYPE' S Name (S ExternalID)? S? 
 *                      ('[' (markupdecl | PEReference | S)* ']' S?)? '>'
 */

void
htmlParseDocTypeDecl(htmlParserCtxtPtr ctxt) {
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
    name = htmlParseName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "htmlParseDocTypeDecl : no DOCTYPE name !\n");
	ctxt->wellFormed = 0;
    }

    SKIP_BLANKS;

    /*
     * Check for SystemID and ExternalID
     */
    URI = htmlParseExternalID(ctxt, &ExternalID, 1);
    SKIP_BLANKS;

    /*
     * We should be at the end of the DOCTYPE declaration.
     */
    if (CUR != '>') {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "DOCTYPE unproperly terminated\n");
	ctxt->wellFormed = 0;
        /* We shouldn't try to resynchronize ... */
    } else {
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
 * htmlParseAttribute:
 * @ctxt:  an HTML parser context
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
htmlParseAttribute(htmlParserCtxtPtr ctxt, CHAR **value) {
    CHAR *name, *val;

    *value = NULL;
    name = htmlParseName(ctxt);
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
	val = htmlParseAttValue(ctxt);
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
 * htmlParseStartTag:
 * @ctxt:  an HTML parser context
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
htmlParseStartTag(htmlParserCtxtPtr ctxt) {
    CHAR *name;
    CHAR *attname;
    CHAR *attvalue;
    const CHAR **atts = NULL;
    int nbatts = 0;
    int maxatts = 0;
    int i;

    if (CUR != '<') return(NULL);
    NEXT;

    name = htmlParseHTMLName(ctxt);
    if (name == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, 
	     "htmlParseStartTag: invalid element name\n");
	ctxt->wellFormed = 0;
        return(NULL);
    }

    /*
     * Check for auto-closure of HTML elements.
     */
    htmlAutoClose(ctxt, name);

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

	attname = htmlParseAttribute(ctxt, &attvalue);
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
			    maxatts * sizeof(CHAR *));
		    return(NULL);
		}
	    } else if (nbatts + 2 < maxatts) {
	        maxatts *= 2;
	        atts = (const CHAR **) realloc(atts, maxatts * sizeof(CHAR *));
		if (atts == NULL) {
		    fprintf(stderr, "realloc of %ld byte failed\n",
			    maxatts * sizeof(CHAR *));
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
	         "htmlParseStartTag: problem parsing attributes\n");
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
 * htmlParseEndTag:
 * @ctxt:  an HTML parser context
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
htmlParseEndTag(htmlParserCtxtPtr ctxt, CHAR *tagname) {
    CHAR *name;

    if ((CUR != '<') || (NXT(1) != '/')) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "htmlParseEndTag: '</' not found\n");
	ctxt->wellFormed = 0;
	return;
    }
    SKIP(2);

    name = htmlParseHTMLName(ctxt);

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
 * htmlParseReference:
 * @ctxt:  an HTML parser context
 * 
 * parse and handle entity references in content,
 * this will end-up in a call to character() since this is either a
 * CharRef, or a predefined entity.
 */
void
htmlParseReference(htmlParserCtxtPtr ctxt) {
    xmlEntityPtr ent;
    CHAR *val;
    if (CUR != '&') return;

    if (NXT(1) == '#') {
	CHAR out[2];
	int val = htmlParseCharRef(ctxt);
	/* TODO: invalid for UTF-8 variable encoding !!! */
	out[0] = val;
	out[1] = 0;
	if ((ctxt->sax != NULL) && (ctxt->sax->characters != NULL))
	    ctxt->sax->characters(ctxt->userData, out, 1);
    } else {
	ent = htmlParseEntityRef(ctxt);
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
 * htmlParseContent:
 * @ctxt:  an HTML parser context
 *
 * Parse a content: comment, sub-element, reference or text.
 *
 */

void
htmlParseContent(htmlParserCtxtPtr ctxt) {
    while ((CUR != '<') || (NXT(1) != '/')) {
	const CHAR *test = CUR_PTR;

	/*
	 * First case :  a comment
	 */
	if ((CUR == '<') && (NXT(1) == '!') &&
		 (NXT(2) == '-') && (NXT(3) == '-')) {
	    htmlParseComment(ctxt, 1);
	}

	/*
	 * Second case :  a sub-element.
	 */
	else if (CUR == '<') {
	    htmlParseElement(ctxt);
	}

	/*
	 * Third case : a reference. If if has not been resolved,
	 *    parsing returns it's Name, create the node 
	 */
	else if (CUR == '&') {
	    htmlParseReference(ctxt);
	}

	/*
	 * Last case, text. Note that References are handled directly.
	 */
	else {
	    htmlParseCharData(ctxt, 0);
	}

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
 * htmlParseElement:
 * @ctxt:  an HTML parser context
 *
 * parse an HTML element, this is highly recursive
 *
 * [39] element ::= EmptyElemTag | STag content ETag
 *
 * [41] Attribute ::= Name Eq AttValue
 */

void
htmlParseElement(htmlParserCtxtPtr ctxt) {
    const CHAR *openTag = CUR_PTR;
    CHAR *name;
    htmlParserNodeInfo node_info;
    htmlNodePtr currentNode;
    htmlElemDescPtr info;

    /* Capture start position */
    node_info.begin_pos = CUR_PTR - ctxt->input->base;
    node_info.begin_line = ctxt->input->line;

    name = htmlParseStartTag(ctxt);
    if (name == NULL) {
        return;
    }

    /*
     * Lookup the info for that element.
     */
    info = htmlTagLookup(name);
    if (info == NULL) {
	if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
	    ctxt->sax->error(ctxt->userData, "Tag %s invalid\n",
			     name);
	ctxt->wellFormed = 0;
    } else if (info->depr) {
	if ((ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
	    ctxt->sax->warning(ctxt->userData, "Tag %s is deprecated\n",
			       name);
    }

    /*
     * Check for an Empty Element labelled the XML/SGML way
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
     * Check for an Empty Element from DTD definition
     */
    if ((info != NULL) && (info->empty)) {
	if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL))
	    ctxt->sax->endElement(ctxt->userData, name);
	free(name);
	return;
    }

    /*
     * Parse the content of the element:
     */
    currentNode = ctxt->node;
    htmlParseContent(ctxt);

    /*
     * check whether the element get popped due to auto closure
     * on start tag
     */
    if (currentNode != ctxt->node) {
	free(name);
        return;
    }

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
    htmlParseEndTag(ctxt, name);
    free(name);
}

/**
 * htmlParseDocument :
 * @ctxt:  an HTML parser context
 * 
 * parse an HTML document (and build a tree if using the standard SAX
 * interface).
 *
 * Returns 0, -1 in case of error. the parser context is augmented
 *                as a result of the parsing.
 */

int
htmlParseDocument(htmlParserCtxtPtr ctxt) {
    htmlDefaultSAXHandlerInit();
    ctxt->html = 1;

    /*
     * SAX: beginning of the document processing TODO: update for HTML.
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
     * Then possibly doc type declaration(s) and more Misc
     * (doctypedecl Misc*)?
     */
    if ((CUR == '<') && (NXT(1) == '!') &&
	(NXT(2) == 'D') && (NXT(3) == 'O') &&
	(NXT(4) == 'C') && (NXT(5) == 'T') &&
	(NXT(6) == 'Y') && (NXT(7) == 'P') &&
	(NXT(8) == 'E')) {
	htmlParseDocTypeDecl(ctxt);
    }
    SKIP_BLANKS;

    /*
     * Create the document if not done already.
     */
    if (ctxt->myDoc == NULL) {
        ctxt->myDoc = htmlNewDoc(NULL, NULL);
    }

    /*
     * Time to start parsing the tree itself
     */
    htmlParseElement(ctxt);

    /*
     * SAX: end of the document processing.
     */
    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
        ctxt->sax->endDocument(ctxt->userData);
    if (! ctxt->wellFormed) return(-1);
    return(0);
}


/********************************************************************************
 *										*
 *				Parser contexts handling			*
 *										*
 ********************************************************************************/

/**
 * xmlInitParserCtxt:
 * @ctxt:  an HTML parser context
 *
 * Initialize a parser context
 */

void
htmlInitParserCtxt(htmlParserCtxtPtr ctxt)
{
    htmlSAXHandler *sax;

    sax = (htmlSAXHandler *) malloc(sizeof(htmlSAXHandler));
    if (sax == NULL) {
        fprintf(stderr, "htmlInitParserCtxt: out of memory\n");
    }

    /* Allocate the Input stack */
    ctxt->inputTab = (htmlParserInputPtr *) malloc(5 * sizeof(htmlParserInputPtr));
    ctxt->inputNr = 0;
    ctxt->inputMax = 5;
    ctxt->input = NULL;
    ctxt->version = NULL;
    ctxt->encoding = NULL;
    ctxt->standalone = -1;

    /* Allocate the Node stack */
    ctxt->nodeTab = (htmlNodePtr *) malloc(10 * sizeof(htmlNodePtr));
    ctxt->nodeNr = 0;
    ctxt->nodeMax = 10;
    ctxt->node = NULL;

    if (sax == NULL) ctxt->sax = &htmlDefaultSAXHandler;
    else {
        ctxt->sax = sax;
	memcpy(sax, &htmlDefaultSAXHandler, sizeof(htmlSAXHandler));
    }
    ctxt->userData = ctxt;
    ctxt->myDoc = NULL;
    ctxt->wellFormed = 1;
    ctxt->replaceEntities = 1;
    ctxt->html = 1;
    ctxt->record_info = 0;
    xmlInitNodeInfoSeq(&ctxt->node_seq);
}

/**
 * htmlFreeParserCtxt:
 * @ctxt:  an HTML parser context
 *
 * Free all the memory used by a parser context. However the parsed
 * document in ctxt->myDoc is not freed.
 */

void
htmlFreeParserCtxt(htmlParserCtxtPtr ctxt)
{
    htmlParserInputPtr input;

    if (ctxt == NULL) return;

    while ((input = inputPop(ctxt)) != NULL) {
        xmlFreeInputStream(input);
    }

    if (ctxt->nodeTab != NULL) free(ctxt->nodeTab);
    if (ctxt->inputTab != NULL) free(ctxt->inputTab);
    if (ctxt->version != NULL) free((char *) ctxt->version);
    if ((ctxt->sax != NULL) && (ctxt->sax != &htmlDefaultSAXHandler))
        free(ctxt->sax);
    free(ctxt);
}

/**
 * htmlCreateDocParserCtxt :
 * @cur:  a pointer to an array of CHAR
 * @encoding:  a free form C string describing the HTML document encoding, or NULL
 *
 * Create a parser context for an HTML document.
 *
 * Returns the new parser context or NULL
 */
htmlParserCtxtPtr
htmlCreateDocParserCtxt(CHAR *cur, const char *encoding) {
    htmlParserCtxtPtr ctxt;
    htmlParserInputPtr input;
    /* htmlCharEncoding enc; */

    ctxt = (htmlParserCtxtPtr) malloc(sizeof(htmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }
    htmlInitParserCtxt(ctxt);
    input = (htmlParserInputPtr) malloc(sizeof(htmlParserInput));
    if (input == NULL) {
        perror("malloc");
	free(ctxt);
	return(NULL);
    }

    /*
     * plug some encoding conversion routines here. !!!
    if (encoding != NULL) {
	enc = htmlDetectCharEncoding(cur);
	htmlSwitchEncoding(ctxt, enc);
    }
     */

    input->filename = NULL;
    input->line = 1;
    input->col = 1;
    input->base = cur;
    input->cur = cur;
    input->free = NULL;

    inputPush(ctxt, input);
    return(ctxt);
}

/********************************************************************************
 *										*
 *				User entry points				*
 *										*
 ********************************************************************************/

/**
 * htmlSAXParseDoc :
 * @cur:  a pointer to an array of CHAR
 * @encoding:  a free form C string describing the HTML document encoding, or NULL
 * @sax:  the SAX handler block
 * @userData: if using SAX, this pointer will be provided on callbacks. 
 *
 * parse an HTML in-memory document and build a tree.
 * It use the given SAX function block to handle the parsing callback.
 * If sax is NULL, fallback to the default DOM tree building routines.
 * 
 * Returns the resulting document tree
 */

htmlDocPtr
htmlSAXParseDoc(CHAR *cur, const char *encoding, htmlSAXHandlerPtr sax, void *userData) {
    htmlDocPtr ret;
    htmlParserCtxtPtr ctxt;

    if (cur == NULL) return(NULL);


    ctxt = htmlCreateDocParserCtxt(cur, encoding);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) { 
        ctxt->sax = sax;
        ctxt->userData = userData;
    }

    htmlParseDocument(ctxt);
    ret = ctxt->myDoc;
    if (sax != NULL) {
	ctxt->sax = NULL;
	ctxt->userData = NULL;
    }
    htmlFreeParserCtxt(ctxt);
    
    return(ret);
}

/**
 * htmlParseDoc :
 * @cur:  a pointer to an array of CHAR
 * @encoding:  a free form C string describing the HTML document encoding, or NULL
 *
 * parse an HTML in-memory document and build a tree.
 * 
 * Returns the resulting document tree
 */

htmlDocPtr
htmlParseDoc(CHAR *cur, const char *encoding) {
    return(htmlSAXParseDoc(cur, encoding, NULL, NULL));
}


/**
 * htmlCreateFileParserCtxt :
 * @filename:  the filename
 * @encoding:  a free form C string describing the HTML document encoding, or NULL
 *
 * Create a parser context for a file content. 
 * Automatic support for ZLIB/Compress compressed document is provided
 * by default if found at compile-time.
 *
 * Returns the new parser context or NULL
 */
htmlParserCtxtPtr
htmlCreateFileParserCtxt(const char *filename, const char *encoding)
{
    htmlParserCtxtPtr ctxt;
#ifdef HAVE_ZLIB_H
    gzFile input;
#else
    int input;
#endif
    int res;
    int len;
    struct stat buf;
    char *buffer;
    htmlParserInputPtr inputStream;
    /* htmlCharEncoding enc; */

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

    buffer[res] = '\0';

    ctxt = (htmlParserCtxtPtr) malloc(sizeof(htmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }
    htmlInitParserCtxt(ctxt);
    inputStream = (htmlParserInputPtr) malloc(sizeof(htmlParserInput));
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
    if (encoding != NULL) {
	enc = htmlDetectCharEncoding(buffer);
	htmlSwitchEncoding(ctxt, enc);
    }
     */

    inputStream->base = buffer;
    inputStream->cur = buffer;
    inputStream->free = (xmlParserInputDeallocate) free;

    inputPush(ctxt, inputStream);
    return(ctxt);
}

/**
 * htmlSAXParseFile :
 * @filename:  the filename
 * @encoding:  a free form C string describing the HTML document encoding, or NULL
 * @sax:  the SAX handler block
 * @userData: if using SAX, this pointer will be provided on callbacks. 
 *
 * parse an HTML file and build a tree. Automatic support for ZLIB/Compress
 * compressed document is provided by default if found at compile-time.
 * It use the given SAX function block to handle the parsing callback.
 * If sax is NULL, fallback to the default DOM tree building routines.
 *
 * Returns the resulting document tree
 */

htmlDocPtr
htmlSAXParseFile(const char *filename, const char *encoding, htmlSAXHandlerPtr sax, 
                 void *userData) {
    htmlDocPtr ret;
    htmlParserCtxtPtr ctxt;

    ctxt = htmlCreateFileParserCtxt(filename, encoding);
    if (ctxt == NULL) return(NULL);
    if (sax != NULL) {
        ctxt->sax = sax;
        ctxt->userData = userData;
    }

    htmlParseDocument(ctxt);

    ret = ctxt->myDoc;
    if (sax != NULL) {
        ctxt->sax = NULL;
        ctxt->userData = NULL;
    }
    htmlFreeParserCtxt(ctxt);
    
    return(ret);
}

/**
 * htmlParseFile :
 * @filename:  the filename
 * @encoding:  a free form C string describing the HTML document encoding, or NULL
 *
 * parse an HTML file and build a tree. Automatic support for ZLIB/Compress
 * compressed document is provided by default if found at compile-time.
 *
 * Returns the resulting document tree
 */

htmlDocPtr
htmlParseFile(const char *filename, const char *encoding) {
    return(htmlSAXParseFile(filename, encoding, NULL, NULL));
}
