/*
 * parser.c : an XML 1.0 non-verifying parser
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#include <config.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h> /* for memset() only */
#include <malloc.h>
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

#include "xml_tree.h"
#include "xml_parser.h"
#include "xml_entities.h"

/*
 * A few macros needed to help building the parser.
 */

#ifdef UNICODE
/*
 * UNICODE version of the macros. Incomplete now TODO !!!!
 */
#define IS_CHAR(c)							\
    (((c) == 0x09) || ((c) == 0x0a) || ((c) == 0x0d) ||			\
     (((c) >= 0x20) && ((c) != 0xFFFE) && ((c) != 0xFFFF)))

#define SKIP_BLANKS(p) 							\
    while ((*(p) == 0x20) || (*(p) == 0x09) || (*(p) == 0xa) ||		\
           (*(p) == 0x3000)) (p)++;

/* I'm too lazy to complete this one TODO !!!! */
#define IS_BASECHAR(c)							\
    ((((c) >= 0x41) && ((c) <= 0x5a)) ||				\		
     (((c) >= 0x61) && ((c) <= 0x7a)) ||				\
     (((c) >= 0xaa) && ((c) <= 0x5b)) ||				\
     (((c) >= 0xc0) && ((c) <= 0xd6)) ||				\
     (((c) >= 0xd8) && ((c) <= 0xf6)) ||				\
     (((c) >= 0xf8) && ((c) <= 0xff)) ||				\
      ((c) == 0xba))

/* I'm too lazy to complete this one TODO !!!! */
#define IS_DIGIT(c) (((c) >= 0x30) && ((c) <= 0x39))

/* I'm too lazy to complete this one TODO !!!! */
#define IS_COMBINING(c) 0

#define IS_IGNORABLE(c)							\
    ((((c) >= 0x200c) && ((c) <= 0x200f)) ||				\
     (((c) >= 0x202a) && ((c) <= 0x202e)) ||				\
     (((c) >= 0x206a) && ((c) <= 0x206f)) ||				\
      ((c) == 0xfeff))

#define IS_EXTENDER(c)							\
    (((c) == 0xb7) || ((c) == 0x2d0) || ((c) == 0x2d1) ||		\
     ((c) == 0x387) || ((c) == 0x640) || ((c) == 0xe46) ||		\
     ((c) == 0xec6) || ((c) == 0x3005)					\
     (((c) >= 0x3031) && ((c) <= 0x3035)) ||				\
     (((c) >= 0x309b) && ((c) <= 0x309e)) ||				\
     (((c) >= 0x30fc) && ((c) <= 0x30fe)) ||				\
     (((c) >= 0xff70) && ((c) <= 0xff9e)) ||				\
      ((c) == 0xff9f))

#define IS_IDEOGRAPHIC(c)						\
    ((((c) >= 0x4e00) && ((c) <= 0x9fa5)) ||				\
     (((c) >= 0xf900) && ((c) <= 0xfa2d)) ||				\
     (((c) >= 0x3021) && ((c) <= 0x3029)) ||				\
      ((c) == 0x3007))

#define IS_LETTER(c) (IS_BASECHAR(c) || IS_IDEOGRAPHIC(c))

/* I'm too lazy to complete this one ! */
#define IS_BLANK(c) (((c) == 0x20) || ((c) == 0x09) || ((c) == 0xa))
#else
/*
 * 8bits / ASCII version of the macros.
 */
#define IS_CHAR(c)							\
    (((c) == 0x09) || ((c) == 0x0a) || ((c) == 0x0d) || ((c) >= 0x20))

#define IS_BASECHAR(c)							\
    ((((c) >= 0x41) && ((c) <= 0x5a)) ||				\
     (((c) >= 0x61) && ((c) <= 0x7a)) ||				\
     (((c) >= 0xaa) && ((c) <= 0x5b)) ||				\
     (((c) >= 0xc0) && ((c) <= 0xd6)) ||				\
     (((c) >= 0xd8) && ((c) <= 0xf6)) ||				\
     (((c) >= 0xf8) && ((c) <= 0xff)) ||				\
      ((c) == 0xba))

#define IS_DIGIT(c) (((c) >= 0x30) && ((c) <= 0x39))

#define IS_LETTER(c) IS_BASECHAR(c)

#define IS_COMBINING(c) 0

#define IS_IGNORABLE(c) 0

#define IS_EXTENDER(c) ((c) == 0xb7)

#define IS_BLANK(c) (((c) == 0x20) || ((c) == 0x09) || ((c) == 0xa))
#endif


#define SKIP_EOL(p) 							\
    if (*(p) == 0x13) { p++ ; if (*(p) == 0x10) p++; }			\
    if (*(p) == 0x10) { p++ ; if (*(p) == 0x13) p++; }

#define SKIP_BLANKS(p) 							\
    while (IS_BLANK(*(p))) (p)++;

#define MOVETO_ENDTAG(p)						\
    while (IS_CHAR(*p) && (*(p) != '>')) (p)++;

#define MOVETO_STARTTAG(p)						\
    while (IS_CHAR(*p) && (*(p) != '<')) (p)++;

/*
 * Forward definition for recusive behaviour.
 */
xmlNodePtr xmlParseElement(xmlParserCtxtPtr ctxt);

/*
 * xmlHandleData : this routine represent's the specific application
 *    behaviour when reading a piece of text.
 *
 * For example in WebDav, any piece made only of blanks is eliminated
 */

CHAR *xmlHandleData(CHAR *in) {
    CHAR *cur;

    if (in == NULL) return(NULL);
    cur = in;
    while (IS_CHAR(*cur)) {
        if (!IS_BLANK(*cur)) goto not_blank;
	cur++;
    }
    free(in);
    return(NULL);

not_blank:
    return(in);
}

/*
 * xmlStrndup : a strdup for array of CHAR's
 */

CHAR *xmlStrndup(const CHAR *cur, int len) {
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

/*
 * xmlStrdup : a strdup for CHAR's
 */

CHAR *xmlStrdup(const CHAR *cur) {
    const CHAR *p = cur;

    while (IS_CHAR(*p)) p++;
    return(xmlStrndup(cur, p - cur));
}

/*
 * xmlStrcmp : a strcmp for CHAR's
 */

int xmlStrcmp(const CHAR *str1, const CHAR *str2) {
    register int tmp;

    do {
        tmp = *str1++ - *str2++;
	if (tmp != 0) return(tmp);
    } while ((*str1 != 0) && (*str2 != 0));
    return (*str1 - *str2);
}

/*
 * xmlStrncmp : a strncmp for CHAR's
 */

int xmlStrncmp(const CHAR *str1, const CHAR *str2, int len) {
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

/*
 * xmlStrchr : a strchr for CHAR's
 */

CHAR *xmlStrchr(const CHAR *str, CHAR val) {
    while (*str != 0) {
        if (*str == val) return((CHAR *) str);
	str++;
    }
    return(NULL);
}

/*
 * xmlParseName : parse an XML name.
 */

CHAR *xmlParseName(xmlParserCtxtPtr ctxt) {
    const CHAR *q;
    CHAR *ret = NULL;

    /*
     * Name ::= (Letter | '_') (NameChar)*
     */
    if (!IS_LETTER(ctxt->cur[0]) && (ctxt->cur[0] != '_')) return(NULL);
    q = ctxt->cur++;
    while ((IS_LETTER(ctxt->cur[0])) || (IS_DIGIT(ctxt->cur[0])) ||
           (ctxt->cur[0] == '.') || (ctxt->cur[0] == '-') || (ctxt->cur[0] == '_') ||
	   (ctxt->cur[0] == ':') || 
	   (IS_COMBINING(ctxt->cur[0])) || (IS_IGNORABLE(ctxt->cur[0])) ||
	   (IS_EXTENDER(ctxt->cur[0])))
	ctxt->cur++;
    
    ret = xmlStrndup(q, ctxt->cur - q);

    return(ret);
}

/*
 * Parse and return a string between quotes or doublequotes
 */
CHAR *xmlParseQuotedString(xmlParserCtxtPtr ctxt) {
    CHAR *ret = NULL;
    const CHAR *q;

    if (ctxt->cur[0] == '"') {
        ctxt->cur++;
	q = ctxt->cur;
	while (IS_CHAR(ctxt->cur[0]) && (ctxt->cur[0] != '"')) ctxt->cur++;
	if (ctxt->cur[0] != '"')
	    fprintf(stderr, "String not closed \"%.50s\n", q);
        else {
            ret = xmlStrndup(q, ctxt->cur - q);
	    ctxt->cur++;
	}
    } else if (ctxt->cur[0] == '\''){
        ctxt->cur++;
	q = ctxt->cur;
	while (IS_CHAR(ctxt->cur[0]) && (ctxt->cur[0] != '\'')) ctxt->cur++;
	if (ctxt->cur[0] != '\'')
	    fprintf(stderr, "String not closed '%.50s\n", q);
        else {
            ret = xmlStrndup(q, ctxt->cur - q);
	    ctxt->cur++;
	}
    }
    return(ret);
}

/*
 * Skip an XML (SGML) comment <!-- .... -->
 *
 * TODO !!!! Save the comment in the tree !!!
 */
void xmlParserSkipComment(xmlParserCtxtPtr ctxt) {
    const CHAR *q, *start;
    const CHAR *r;

    /*
     * An extra check may avoid errors and isn't that costly !
     */
    if ((ctxt->cur[0] != '<') || (ctxt->cur[1] != '!') ||
        (ctxt->cur[2] != '-') || (ctxt->cur[3] != '-')) return;

    ctxt->cur += 4;
    start = q = ctxt->cur;
    ctxt->cur++;
    r = ctxt->cur;
    ctxt->cur++;
    while (IS_CHAR(ctxt->cur[0]) &&
           ((ctxt->cur[0] == ':') || (ctxt->cur[0] != '>') ||
	    (*r != '-') || (*q != '-'))) {
        ctxt->cur++;r++;q++;
    }
    if (!IS_CHAR(ctxt->cur[0])) {
        fprintf(stderr, "Comment not terminated <!--%.50s\n", start);
	ctxt->cur = start; /* !!! We shouldn't really try to recover !!! */
    } else {
        ctxt->cur++;
    }
}

/*
 * xmlParseNamespace: parse specific '<?namespace ...' constructs.
 */

void xmlParseNamespace(xmlParserCtxtPtr ctxt) {
    CHAR *href = NULL;
    CHAR *AS = NULL;
    int garbage = 0;

    /*
     * We just skipped "namespace" or "xml:namespace"
     */
    SKIP_BLANKS(ctxt->cur);

    while (IS_CHAR(ctxt->cur[0]) && (ctxt->cur[0] != '>')) {
	/*
	 * We can have "ns" or "prefix" attributes
	 * Old encoding as 'href' or 'AS' attributes is still supported
	 */
	if ((ctxt->cur[0] == 'n') && (ctxt->cur[1] == 's')) {
	    garbage = 0;
	    ctxt->cur += 2;
	    SKIP_BLANKS(ctxt->cur);

	    if (ctxt->cur[0] != '=') continue;
	    ctxt->cur++;
	    SKIP_BLANKS(ctxt->cur);

	    href = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS(ctxt->cur);
	} else if ((ctxt->cur[0] == 'h') && (ctxt->cur[1] == 'r') &&
	    (ctxt->cur[2] == 'e') && (ctxt->cur[3] == 'f')) {
	    garbage = 0;
	    ctxt->cur += 4;
	    SKIP_BLANKS(ctxt->cur);

	    if (ctxt->cur[0] != '=') continue;
	    ctxt->cur++;
	    SKIP_BLANKS(ctxt->cur);

	    href = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS(ctxt->cur);
	} else if ((ctxt->cur[0] == 'p') && (ctxt->cur[1] == 'r') &&
	           (ctxt->cur[2] == 'e') && (ctxt->cur[3] == 'f') &&
	           (ctxt->cur[4] == 'i') && (ctxt->cur[5] == 'x')) {
	    garbage = 0;
	    ctxt->cur += 6;
	    SKIP_BLANKS(ctxt->cur);

	    if (ctxt->cur[0] != '=') continue;
	    ctxt->cur++;
	    SKIP_BLANKS(ctxt->cur);

	    AS = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS(ctxt->cur);
	} else if ((ctxt->cur[0] == 'A') && (ctxt->cur[1] == 'S')) {
	    garbage = 0;
	    ctxt->cur += 2;
	    SKIP_BLANKS(ctxt->cur);

	    if (ctxt->cur[0] != '=') continue;
	    ctxt->cur++;
	    SKIP_BLANKS(ctxt->cur);

	    AS = xmlParseQuotedString(ctxt);
	    SKIP_BLANKS(ctxt->cur);
	} else if ((ctxt->cur[0] == '?') && (ctxt->cur[1] == '>')) {
	    garbage = 0;
	    ctxt->cur ++;
	} else {
            /*
	     * Found garbage when parsing the namespace
	     */
	    if (!garbage) fprintf(stderr,
	          "\nxmlParseNamespace found garbage: ");
            fprintf(stderr, "%c", ctxt->cur[0]);
            ctxt->cur++;
        }
    }

    MOVETO_ENDTAG(ctxt->cur);
    ctxt->cur++;

    /*
     * Register the DTD.
     */
    if (href != NULL)
        xmlNewDtd(ctxt->doc, href, AS);

    if (AS != NULL) free(AS);
    if (href != NULL) free(href);
}

/*
 * xmlParsePI: parse an XML Processing Instruction.
 */

void xmlParsePI(xmlParserCtxtPtr ctxt) {
    if ((ctxt->cur[0] == '<') && (ctxt->cur[1] == '?')) {
	/*
	 * this is a Processing Instruction.
	 */
	ctxt->cur += 2;

	/*
	 * Special for WebDav, support for the Processing Instruction
	 * '<?namespace ...' contruct in the header of the XML document.
	 */
	if ((ctxt->cur[0] == 'n') && (ctxt->cur[1] == 'a') &&
	    (ctxt->cur[2] == 'm') && (ctxt->cur[3] == 'e') &&
	    (ctxt->cur[4] == 's') && (ctxt->cur[5] == 'p') &&
	    (ctxt->cur[6] == 'a') && (ctxt->cur[7] == 'c') &&
	    (ctxt->cur[8] == 'e')) {
	    ctxt->cur += 9;
	    xmlParseNamespace(ctxt);
	} else if ((ctxt->cur[0] == 'x') && (ctxt->cur[1] == 'm') &&
	           (ctxt->cur[2] == 'l') && (ctxt->cur[3] == ':') &&
	           (ctxt->cur[4] == 'n') && (ctxt->cur[5] == 'a') &&
	           (ctxt->cur[6] == 'm') && (ctxt->cur[7] == 'e') &&
	           (ctxt->cur[8] == 's') && (ctxt->cur[9] == 'p') &&
	           (ctxt->cur[10] == 'a') && (ctxt->cur[11] == 'c') &&
	           (ctxt->cur[12] == 'e')) {
	    ctxt->cur += 13;
	    xmlParseNamespace(ctxt);
	} else {
	    /* Unknown PI, ignore it ! */
	    fprintf(stderr, "xmlParsePI : skipping unknown PI %30s\n",
	            ctxt->cur);
	    MOVETO_ENDTAG(ctxt->cur);
	    ctxt->cur++;
	}
    }
}

/*
 * xmlParseAttribute: parse a start of tag.
 *
 * Attribute ::= Name Eq AttValue
 */

void xmlParseAttribute(xmlParserCtxtPtr ctxt, xmlNodePtr node) {
    const CHAR *q;
    CHAR *name, *value = NULL;

    if (!IS_LETTER(ctxt->cur[0]) && (ctxt->cur[0] != '_')) {
        return;
    }
    q = ctxt->cur++;
    while ((IS_LETTER(ctxt->cur[0])) || (IS_DIGIT(ctxt->cur[0])) ||
           (ctxt->cur[0] == '.') || (ctxt->cur[0] == '-') ||
	   (ctxt->cur[0] == '_') || (ctxt->cur[0] == ':') || 
	   (IS_COMBINING(ctxt->cur[0])) || (IS_IGNORABLE(ctxt->cur[0])) ||
	   (IS_EXTENDER(ctxt->cur[0])))
	ctxt->cur++;
    name = xmlStrndup(q, ctxt->cur - q);

    /*
     * We should have the equal, we are laxist here and allow attributes
     * without values and extra spaces.
     */
    SKIP_BLANKS(ctxt->cur);
    if (ctxt->cur[0] == '=') {
        ctxt->cur++;
	SKIP_BLANKS(ctxt->cur);
	if ((ctxt->cur[0] != '\'') && (ctxt->cur[0] != '"')) {
	    fprintf(stderr, "Quotes were expected for attribute value %.20s\n",
	            q);
	} else
	    value = xmlParseQuotedString(ctxt);
    }

    /*
     * Add the attribute to the node.
     */
    if (name != NULL) {
	xmlNewProp(node, name, value);
        free(name);
    }
    if ( value != NULL )
      free(value);
}

/*
 * xmlParseStartTag: parse a start of tag.
 */

xmlNodePtr xmlParseStartTag(xmlParserCtxtPtr ctxt) {
    const CHAR *q;
    CHAR *ns, *name;
    xmlDtdPtr dtd = NULL;
    xmlNodePtr ret = NULL;

    /*
     * Theorically one should just parse a Name, but with the addition
     * of the namespace needed for WebDav, it's a bit more complicated
     * since the element name may be prefixed by a namespace prefix.
     *
     * QName ::= (NSPart ':')? LocalPart
     * NSPart ::= Name
     * LocalPart ::= Name
     * STag ::= '<' QName (S Attribute)* S? '>'
     *
     * instead of :
     *
     * STag ::= '<' QName (S Attribute)* S? '>'
     */
    if (ctxt->cur[0] != '<') return(NULL);
    ctxt->cur++;

    if (!IS_LETTER(ctxt->cur[0]) && (ctxt->cur[0] != '_')) return(NULL);
    q = ctxt->cur++;
    while ((IS_LETTER(ctxt->cur[0])) || (IS_DIGIT(ctxt->cur[0])) ||
           (ctxt->cur[0] == '.') || (ctxt->cur[0] == '-') ||
	   (ctxt->cur[0] == '_') ||
	   (IS_COMBINING(ctxt->cur[0])) || (IS_IGNORABLE(ctxt->cur[0])) ||
	   (IS_EXTENDER(ctxt->cur[0])))
	ctxt->cur++;

    if (ctxt->cur[0] == ':') {
        ns = xmlStrndup(q, ctxt->cur - q);
        
	ctxt->cur++; /* skip the column */
	if (!IS_LETTER(ctxt->cur[0]) && (ctxt->cur[0] != '_')) {
	    fprintf(stderr,
	       "Start tag : no element name after namespace identifier %.20s\n",
	            q);
            free(ns);
	    return(NULL);
	}
	q = ctxt->cur++;
	while ((IS_LETTER(ctxt->cur[0])) || (IS_DIGIT(ctxt->cur[0])) ||
	       (ctxt->cur[0] == '.') || (ctxt->cur[0] == '-') ||
	       (ctxt->cur[0] == '_') || (ctxt->cur[0] == ':') || 
	       (IS_COMBINING(ctxt->cur[0])) || (IS_IGNORABLE(ctxt->cur[0])) ||
	       (IS_EXTENDER(ctxt->cur[0])))
	    ctxt->cur++;
        name = xmlStrndup(q, ctxt->cur - q);

	/*
	 * Search the DTD associated to ns.
	 */
	dtd = xmlSearchDtd(ctxt->doc, ns);
	if (dtd == NULL)
	    fprintf(stderr, "Start tag : Couldn't find namespace %s\n", ns);
	free(ns);
    } else
        name = xmlStrndup(q, ctxt->cur - q);

    ret = xmlNewNode(dtd, name, NULL);

    /*
     * Now parse the attributes, it ends up with the ending
     *
     * (S Attribute)* S?
     */
    SKIP_BLANKS(ctxt->cur);
    while ((IS_CHAR(ctxt->cur[0])) &&
           (ctxt->cur[0] != '>') && 
	   ((ctxt->cur[0] != '/') || (ctxt->cur[1] != '>'))) {
	if (IS_LETTER(ctxt->cur[0]) || (ctxt->cur[0] == '_'))
	    xmlParseAttribute(ctxt, ret);
	else {
	    /* We should warn TODO !!! */
	    ctxt->cur++;
	}
	SKIP_BLANKS(ctxt->cur);
    }

    return(ret);
}

/*
 * xmlParseEndTag: parse an end of tag, note that the '</' part has
 * already been read.
 */

void xmlParseEndTag(xmlParserCtxtPtr ctxt, xmlDtdPtr *dtdPtr, CHAR **tagPtr) {
    const CHAR *q;
    CHAR *ns, *name;
    xmlDtdPtr dtd = NULL;

    *dtdPtr = NULL;
    *tagPtr = NULL;

    /*
     * Theorically one should just parse a Name, but with the addition
     * of the namespace needed for WebDav, it's a bit more complicated
     * since the element name may be prefixed by a namespace prefix.
     *
     * QName ::= (NSPart ':')? LocalPart
     * NSPart ::= Name
     * LocalPart ::= Name
     * ETag ::= '</' QName S? '>'
     *
     * instead of :
     *
     * ETag ::= '</' Name S? '>'
     */
    if (!IS_LETTER(ctxt->cur[0]) && (ctxt->cur[0] != '_')) return;
    q = ctxt->cur++;
    while ((IS_LETTER(ctxt->cur[0])) || (IS_DIGIT(ctxt->cur[0])) ||
           (ctxt->cur[0] == '.') || (ctxt->cur[0] == '-') ||
	   (ctxt->cur[0] == '_') ||
	   (IS_COMBINING(ctxt->cur[0])) || (IS_IGNORABLE(ctxt->cur[0])) ||
	   (IS_EXTENDER(ctxt->cur[0])))
	ctxt->cur++;

    if (ctxt->cur[0] == ':') {
        ns = xmlStrndup(q, ctxt->cur - q);
        
	ctxt->cur++; /* skip the column */
	if (!IS_LETTER(ctxt->cur[0]) && (ctxt->cur[0] != '_')) {
	    fprintf(stderr,
	        "End tag : no element name after namespace identifier %.20s\n",
	            q);
            free(ns);
	    return;
	}
	q = ctxt->cur++;
	while ((IS_LETTER(ctxt->cur[0])) || (IS_DIGIT(ctxt->cur[0])) ||
	       (ctxt->cur[0] == '.') || (ctxt->cur[0] == '-') ||
	       (ctxt->cur[0] == '_') || (ctxt->cur[0] == ':') || 
	       (IS_COMBINING(ctxt->cur[0])) || (IS_IGNORABLE(ctxt->cur[0])) ||
	       (IS_EXTENDER(ctxt->cur[0])))
	    ctxt->cur++;
        name = xmlStrndup(q, ctxt->cur - q);

	/*
	 * Search the DTD associated to ns.
	 */
	dtd = xmlSearchDtd(ctxt->doc, ns);
	if (dtd == NULL)
	    fprintf(stderr, "End tag : Couldn't find namespace %s\n", ns);
	free(ns);
    } else
        name = xmlStrndup(q, ctxt->cur - q);

    *dtdPtr = dtd;
    *tagPtr = name;

    /*
     * We should definitely be at the ending "S? '>'" part
     */
    SKIP_BLANKS(ctxt->cur);
    if ((!IS_CHAR(ctxt->cur[0])) || (ctxt->cur[0] != '>')) {
        fprintf(stderr, "End tag : expected '>', got %.20s\n", ctxt->cur);
	/*
	 * Note : skipping to the next '>' is probably otherkill,
	 * especially in case the '>' is hust missing.
	 *
	 * Otherwise add:
	 *  MOVETO_ENDTAG(ctxt->cur);
	 */
    } else
	ctxt->cur++;

    return;
}

/*
 * xmlParseCDSect: escaped pure raw content.
 */
CHAR *xmlParseCDSect(xmlParserCtxtPtr ctxt) {
    const CHAR *r, *s, *base;
    CHAR *ret;

    base = ctxt->cur;
    if (!IS_CHAR(ctxt->cur[0])) {
        fprintf(stderr, "CData section not finished : %.20s\n", base);
        return(NULL);
    }
    r = ctxt->cur++;
    if (!IS_CHAR(ctxt->cur[0])) {
        fprintf(stderr, "CData section not finished : %.20s\n", base);
        return(NULL);
    }
    s = ctxt->cur++;
    while (IS_CHAR(ctxt->cur[0]) &&
           ((*r != ']') || (*s != ']') || (ctxt->cur[0] != '>'))) {
        r++;s++;ctxt->cur++;
    }
    if (!IS_CHAR(ctxt->cur[0])) {
        fprintf(stderr, "CData section not finished : %.20s\n", base);
        return(NULL);
    }
    ret = xmlStrndup(base, ctxt->cur-base);

    return(ret);
}

/*
 * xmlParseContent: a content is
 * (element | PCData | Reference | CDSect | PI | Comment)
 *
 * element : starts by '<'
 * PCData : any CHAR but '&' or '<'
 * Reference : starts by '&'
 * CDSect : starts by '<![CDATA['
 * PI : starts by '<?'
 */

xmlNodePtr xmlParseContent(xmlParserCtxtPtr ctxt, xmlNodePtr node) {
    const CHAR *q;
    CHAR *data = NULL;
    xmlNodePtr ret = NULL;

    /*
     * First case : a Processing Instruction.
     */
    if ((ctxt->cur[0] == '<') && (ctxt->cur[1] == '?')) {
	xmlParsePI(ctxt);
    }
    /*
     * Second case : a CDSection
     */
    if ((ctxt->cur[0] == '<') && (ctxt->cur[1] == '!') &&
        (ctxt->cur[2] == '[') && (ctxt->cur[3] == 'C') &&
	(ctxt->cur[4] == 'D') && (ctxt->cur[5] == 'A') &&
	(ctxt->cur[6] == 'T') && (ctxt->cur[7] == 'A') &&
	(ctxt->cur[8] == '[')) {
	ctxt->cur += 9;
	data = xmlParseCDSect(ctxt);
    }
    /*
     * Third case :  a sub-element.
     */
    else if (ctxt->cur[0] == '<') {
        ret = xmlParseElement(ctxt);
    }
    /*
     * Last case, text. Note that References are handled directly.
     */
    else {
        q = ctxt->cur;
	while (IS_CHAR(ctxt->cur[0]) && (ctxt->cur[0] != '<')) ctxt->cur++;

	if (!IS_CHAR(ctxt->cur[0])) {
	    fprintf(stderr, "Truncated content : %.50s\n", q);
	    return(NULL);
	}

	/*
	 * Do the Entities decoding...
	 */
	data = xmlStrdup(xmlDecodeEntities(ctxt->doc, q, ctxt->cur - q));
    }

    /*
     * Handle the data if any. If there is no child
     * add it as content, otherwise create a new node of type text.
     */
    if (data != NULL)
	data = xmlHandleData(data);
    if (data != NULL) {
	if (node->childs == NULL)
	    xmlNodeSetContent(node, data); 
	else 
	    ret = xmlNewText(data);
        free(data);
    }

    return(ret);
}

/*
 * xmlParseElement: parse an XML element
 */

xmlNodePtr xmlParseElement(xmlParserCtxtPtr ctxt) {
    xmlNodePtr ret, child;
    const CHAR *openTag = ctxt->cur;
    const CHAR *closeTag = ctxt->cur;

    ret = xmlParseStartTag(ctxt);
    if (ret == NULL) {
        return(NULL);
    }

    /*
     * Check for an Empty Element.
     */
    if ((ctxt->cur[0] == '/') && (ctxt->cur[1] == '>')) {
        ctxt->cur += 2;
	return(ret);
    }
    if (ctxt->cur[0] == '>') ctxt->cur++;
    else {
        fprintf(stderr, "Couldn't find end of Start Tag %.30s\n", openTag);
	return(NULL);
    }

    /*
     * Parse the content of the element:
     * (element | PCData | Reference | CDSect | PI | Comment) *
     *
     * element : starts by '<'
     * PCData : any CHAR but '&' or '<'
     * Reference : starts by '&'
     * CDSect : starts by '<![CDATA['
     * PI : starts by '<?'
     *
     * The loop stops upon detection of an end of tag '</'
     */
    while ((IS_CHAR(ctxt->cur[0])) &&
           ((ctxt->cur[0] != '<') || (ctxt->cur[1] != '/'))) {
        child = xmlParseContent(ctxt, ret);
	if (child != NULL)
	    xmlAddChild(ret, child);
    }
    if (!IS_CHAR(ctxt->cur[0])) {
        fprintf(stderr, "Premature end of data in tag %.30s\n", openTag);
	return(NULL);
    }

    /*
     * parse the end of tag : '</' has been detected.
     */
    ctxt->cur += 2;
    if (ctxt->cur[0] == '>') ctxt->cur++; /* simplified closing </> */
    else {
        CHAR *endTag;
	xmlDtdPtr endDtd;

	xmlParseEndTag(ctxt, &endDtd, &endTag);

        /*
	 * Check that the Name in the ETag is the same as in the STag.
	 */
	if (endDtd != ret->dtd) {
	    fprintf(stderr, "Start and End tags don't use the same DTD:\n");
	    fprintf(stderr, "\t%.30s\n\t%.30s\n", openTag, closeTag);
	}
	if (strcmp(ret->name, endTag)) {
	    fprintf(stderr, "Start and End tags don't use the same name:\n");
	    fprintf(stderr, "\t%.30s\n\t%.30s\n", openTag, closeTag);
	}

        if ( endTag != NULL )
          free(endTag);
    }

    return(ret);
}

/*
 * xmlParseXMLDecl: parse an XML declaration header
 */

void xmlParseXMLDecl(xmlParserCtxtPtr ctxt) {
    CHAR *version;

    /*
     * We know that '<?xml' is here.
     */
    ctxt->cur += 5;

    /*
     * Parse the version info
     */
    SKIP_BLANKS(ctxt->cur);

    /*
     * We should have 'version=' here !
     */
    if ((ctxt->cur[0] == 'v') && (ctxt->cur[1] == 'e') &&
        (ctxt->cur[2] == 'r') && (ctxt->cur[3] == 's') &&
	(ctxt->cur[4] == 'i') && (ctxt->cur[5] == 'o') &&
	(ctxt->cur[6] == 'n') && (ctxt->cur[7] == '=')) {
	ctxt->cur += 8;
	version = xmlParseQuotedString(ctxt);
	if (version == NULL)
	    ctxt->doc = xmlNewDoc(XML_DEFAULT_VERSION);
	else {
	    ctxt->doc = xmlNewDoc(version);
	    free(version);
	}
    } else {
        ctxt->doc = xmlNewDoc(XML_DEFAULT_VERSION);
    }

    /*
     * We should check for Required Markup Declaration TODO !!!!
     */
    MOVETO_ENDTAG(ctxt->cur);
    ctxt->cur++;

}

/*
 * xmlParseMisc: parse an XML Misc optionnal field.
 * (Comment | PI | S)*
 */

void xmlParseMisc(xmlParserCtxtPtr ctxt) {
    while (((ctxt->cur[0] == '<') && (ctxt->cur[1] == '?')) ||
           ((ctxt->cur[0] == '<') && (ctxt->cur[1] == '!') &&
	    (ctxt->cur[2] == '-') && (ctxt->cur[2] == '-')) ||
           IS_BLANK(ctxt->cur[0])) {
        if ((ctxt->cur[0] == '<') && (ctxt->cur[1] == '?')) {
	    xmlParsePI(ctxt);
	} else if (IS_BLANK(ctxt->cur[0])) {
	    ctxt->cur++;
	} else
	    xmlParserSkipComment(ctxt);
    }
}

/*
 * xmlParseDocument : parse an XML document and build a tree.
 */

int xmlParseDocument(xmlParserCtxtPtr ctxt) {
    /*
     * We should check for encoding here and plug-in some
     * conversion code TODO !!!!
     */

    /*
     * Wipe out everything which is before the first '<'
     */
    SKIP_BLANKS(ctxt->cur);

    /*
     * Check for the XMLDecl in the Prolog.
     */
    if ((ctxt->cur[0] == '<') && (ctxt->cur[1] == '?') &&
        (ctxt->cur[2] == 'x') && (ctxt->cur[3] == 'm') &&
	(ctxt->cur[4] == 'l')) {
	xmlParseXMLDecl(ctxt);
	/* SKIP_EOL(cur); */
	SKIP_BLANKS(ctxt->cur);
    } else if ((ctxt->cur[0] == '<') && (ctxt->cur[1] == '?') &&
        (ctxt->cur[2] == 'X') && (ctxt->cur[3] == 'M') &&
	(ctxt->cur[4] == 'L')) {
	/*
	 * The first drafts were using <?XML and the final W3C REC
	 * now use <?xml ...
	 */
	xmlParseXMLDecl(ctxt);
	/* SKIP_EOL(cur); */
	SKIP_BLANKS(ctxt->cur);
    } else {
        ctxt->doc = xmlNewDoc(XML_DEFAULT_VERSION);
    }

    /*
     * The Misc part of the Prolog
     * (Comment | PI | S) *
     */
    xmlParseMisc(ctxt);

    /*
     * Time to start parsing 
     */
    ctxt->doc->root = xmlParseElement(ctxt);

    return(0);
}

/*
 * xmlParseDoc : parse an XML in-memory document and build a tree.
 */

xmlDocPtr xmlParseDoc(CHAR *cur) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    if (cur == NULL) return(NULL);

    ctxt = (xmlParserCtxtPtr) malloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }

    xmlInitParserCtxt(ctxt);
    ctxt->base = cur;
    ctxt->cur = cur;

    xmlParseDocument(ctxt);
    ret = ctxt->doc;
    free(ctxt->nodes);
    free(ctxt);
    
    return(ret);
}

/*
 * xmlParseFile : parse an XML file and build a tree.
 */

xmlDocPtr xmlParseFile(const char *filename) {
    xmlDocPtr ret;
#ifdef HAVE_ZLIB_H
    gzFile input;
#else
    int input;
#endif
    int res;
    struct stat buf;
    char *buffer;
    xmlParserCtxtPtr ctxt;

    res = stat(filename, &buf);
    if (res < 0) return(NULL);

#ifdef HAVE_ZLIB_H
retry_bigger:
    buffer = malloc((buf.st_size * 20) + 100);
#else
    buffer = malloc(buf.st_size + 100);
#endif
    if (buffer == NULL) {
	perror("malloc");
        return(NULL);
    }

    memset(buffer, 0, sizeof(buffer));
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
    res = gzread(input, buffer, 20 * buf.st_size);
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
    if (res >= 20 * buf.st_size) {
        free(buffer);
	buf.st_size *= 2;
	goto retry_bigger;
    }
    buf.st_size = res;
#else
    close(input);
#endif


    ctxt = (xmlParserCtxtPtr) malloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }
    buffer[buf.st_size] = '\0';

    xmlInitParserCtxt(ctxt);
    ctxt->filename = filename;
    ctxt->base = buffer;
    ctxt->cur = buffer;

    xmlParseDocument(ctxt);
    ret = ctxt->doc;
    free(buffer);
    free(ctxt->nodes);
    free(ctxt);
    
    return(ret);
}

/*
 * xmlParseFile : parse an XML memory block and build a tree.
 */

xmlDocPtr xmlParseMemory(char *buffer, int size) {
    xmlDocPtr ret;
    xmlParserCtxtPtr ctxt;

    ctxt = (xmlParserCtxtPtr) malloc(sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        perror("malloc");
	return(NULL);
    }

    buffer[size - 1] = '\0';

    xmlInitParserCtxt(ctxt);
    ctxt->base = buffer;
    ctxt->cur = buffer;

    xmlParseDocument(ctxt);
    ret = ctxt->doc;
    free(ctxt->nodes);
    free(ctxt);
    
    return(ret);
}




/* Initialize parser context */
void xmlInitParserCtxt(xmlParserCtxtPtr ctxt)
{
    int i;

    ctxt->filename = NULL;
    ctxt->base = NULL;
    ctxt->cur = NULL;
    ctxt->line = 1;
    ctxt->col = 1;
    ctxt->doc = NULL;
    ctxt->depth = 0;
    ctxt->max_depth = 10;
    ctxt->nodes = (xmlNodePtr *) malloc(ctxt->max_depth * sizeof(xmlNodePtr));
    if (ctxt->nodes == NULL) {
	fprintf(stderr, "malloc of %d byte failed\n",
		ctxt->max_depth * sizeof(xmlNodePtr));
	ctxt->max_depth = 0;
    } else {
        for (i = 0;i < ctxt->max_depth;i++) 
	    ctxt->nodes[i] = NULL;
    }
}


/*
 * Clear (release owned resources) and reinitialize context
 */
void xmlClearParserCtxt(xmlParserCtxtPtr ctx)
{
    xmlInitParserCtxt(ctx);
}


/*
 * Setup the parser context to parse a new buffer; Clears any prior
 * contents from the parser context. The buffer parameter must not be
 * NULL, but the filename parameter can be
 */
void xmlSetupParserForBuffer(xmlParserCtxtPtr ctxt, const CHAR* buffer,
                             const char* filename)
{
  xmlClearParserCtxt(ctxt);
  ctxt->base = buffer;
  ctxt->cur = buffer;
  ctxt->filename = filename;
}



void xmlReportError(xmlParserCtxtPtr ctx, const CHAR* msg)
{
  fputs(msg, stderr);
}
