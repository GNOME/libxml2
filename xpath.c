/*
 * xpath.c: XML Path Language implementation
 *          XPath is a language for addressing parts of an XML document,
 *          designed to be used by both XSLT and XPointer
 *
 * Reference: W3C Recommendation 16 November 1999
 *     http://www.w3.org/TR/1999/REC-xpath-19991116
 * Public reference:
 *     http://www.w3.org/TR/xpath
 *
 * See COPYRIGHT for the status of this software
 *
 * Author: Daniel.Veillard@w3.org
 *
 * 14 Nov 2000 ht - truncated declaration of xmlXPathEvalRelativeLocationPath
 * for VMS
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <libxml/xmlversion.h>
#ifdef LIBXML_XPATH_ENABLED

#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_MATH_H
#include <math.h>
#endif
#ifdef HAVE_FLOAT_H
#include <float.h>
#endif
#ifdef HAVE_IEEEFP_H
#include <ieeefp.h>
#endif
#ifdef HAVE_NAN_H
#include <nan.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/valid.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/parserInternals.h>
#include <libxml/hash.h>
#ifdef LIBXML_XPTR_ENABLED
#include <libxml/xpointer.h>
#endif
#ifdef LIBXML_DEBUG_ENABLED
#include <libxml/debugXML.h>
#endif
#include <libxml/xmlerror.h>

/* #define DEBUG */
/* #define DEBUG_STEP */
/* #define DEBUG_EXPR */

void xmlXPathStringFunction(xmlXPathParserContextPtr ctxt, int nargs);
double xmlXPathStringEvalNumber(const xmlChar *str);

/*
 * Setup stuff for floating point
 * The lack of portability of this section of the libc is annoying !
 */
double xmlXPathNAN = 0;
double xmlXPathPINF = 1;
double xmlXPathNINF = -1;

#ifndef isinf
#ifndef HAVE_ISINF

#if HAVE_FPCLASS

int isinf(double d) {
    fpclass_t	type = fpclass(d);
    switch (type) {
	case FP_NINF:
	    return(-1);
	case FP_PINF:
	    return(1);
    }
    return(0);
}

#elif defined(HAVE_FP_CLASS) || defined(HAVE_FP_CLASS_D)

#if HAVE_FP_CLASS_H
#include <fp_class.h>
#endif

int isinf(double d) {
#if HAVE_FP_CLASS
    int	fpclass = fp_class(d);
#else
    int	fpclass = fp_class_d(d);
#endif
    if (fpclass == FP_POS_INF)
	return(1);
    if (fpclass == FP_NEG_INF)
	return(-1);
    return(0);
}

#elif defined(HAVE_CLASS)

int isinf(double d) {
    int	fpclass = class(d);
    if (fpclass == FP_PLUS_INF)
	return(1);
    if (fpclass == FP_MINUS_INF)
	return(-1);
    return(0);
}
#elif defined(finite) || defined(HAVE_FINITE)
int isinf(double x) { return !finite(x) && x==x; }
#elif defined(HUGE_VAL)
int isinf(double x)
{
    if (x == HUGE_VAL)
        return(1);
    if (x == -HUGE_VAL)
        return(-1);
    return(0);
}
#endif 

#endif /* ! HAVE_ISINF */
#endif /* ! defined(isinf) */

#ifndef isnan
#ifndef HAVE_ISNAN

#ifdef HAVE_ISNAND
#define isnan(f) isnand(f)
#endif /* HAVE_iSNAND */

#endif /* ! HAVE_iSNAN */
#endif /* ! defined(isnan) */

/**
 * xmlXPathInit:
 *
 * Initialize the XPath environment
 */
void
xmlXPathInit(void) {
    static int initialized = 0;

    if (initialized) return;

    xmlXPathNAN = 0;
    xmlXPathNAN /= 0;

    xmlXPathPINF = 1;
    xmlXPathPINF /= 0;

    xmlXPathNINF = -1;
    xmlXPathNINF /= 0;

    initialized = 1;
}

/************************************************************************
 *									*
 * 		Debugging related functions				*
 *									*
 ************************************************************************/

#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

#define STRANGE 							\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Internal error at %s:%d\n",				\
            __FILE__, __LINE__);

#ifdef LIBXML_DEBUG_ENABLED
void xmlXPathDebugDumpNode(FILE *output, xmlNodePtr cur, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;
    if (cur == NULL) {
	fprintf(output, shift);
	fprintf(output, "Node is NULL !\n");
	return;
        
    }

    if ((cur->type == XML_DOCUMENT_NODE) ||
	     (cur->type == XML_HTML_DOCUMENT_NODE)) {
	fprintf(output, shift);
	fprintf(output, " /\n");
    } else if (cur->type == XML_ATTRIBUTE_NODE)
	xmlDebugDumpAttr(output, (xmlAttrPtr)cur, depth);
    else
	xmlDebugDumpOneNode(output, cur, depth);
}
void xmlXPathDebugDumpNodeList(FILE *output, xmlNodePtr cur, int depth) {
    xmlNodePtr tmp;
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;
    if (cur == NULL) {
	fprintf(output, shift);
	fprintf(output, "Node is NULL !\n");
	return;
        
    }

    while (cur != NULL) {
	tmp = cur;
	cur = cur->next;
	xmlDebugDumpOneNode(output, tmp, depth);
    }
}

void xmlXPathDebugDumpNodeSet(FILE *output, xmlNodeSetPtr cur, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    if (cur == NULL) {
	fprintf(output, shift);
	fprintf(output, "NodeSet is NULL !\n");
	return;
        
    }

    fprintf(output, "Set contains %d nodes:\n", cur->nodeNr);
    for (i = 0;i < cur->nodeNr;i++) {
	fprintf(output, shift);
        fprintf(output, "%d", i + 1);
	xmlXPathDebugDumpNode(output, cur->nodeTab[i], depth + 1);
    }
}

void xmlXPathDebugDumpValueTree(FILE *output, xmlNodeSetPtr cur, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    if ((cur == NULL) || (cur->nodeNr == 0) || (cur->nodeTab[0] == NULL)) {
	fprintf(output, shift);
	fprintf(output, "Value Tree is NULL !\n");
	return;
        
    }

    fprintf(output, shift);
    fprintf(output, "%d", i + 1);
    xmlXPathDebugDumpNodeList(output, cur->nodeTab[0]->children, depth + 1);
}
#if defined(LIBXML_XPTR_ENABLED)
void xmlXPathDebugDumpObject(FILE *output, xmlXPathObjectPtr cur, int depth);
void xmlXPathDebugDumpLocationSet(FILE *output, xmlLocationSetPtr cur, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    if (cur == NULL) {
	fprintf(output, shift);
	fprintf(output, "LocationSet is NULL !\n");
	return;
        
    }

    for (i = 0;i < cur->locNr;i++) {
	fprintf(output, shift);
        fprintf(output, "%d : ", i + 1);
	xmlXPathDebugDumpObject(output, cur->locTab[i], depth + 1);
    }
}
#endif

void xmlXPathDebugDumpObject(FILE *output, xmlXPathObjectPtr cur, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);

    if (cur == NULL) {
        fprintf(output, "Object is empty (NULL)\n");
	return;
    }
    switch(cur->type) {
        case XPATH_UNDEFINED:
	    fprintf(output, "Object is uninitialized\n");
	    break;
        case XPATH_NODESET:
	    fprintf(output, "Object is a Node Set :\n");
	    xmlXPathDebugDumpNodeSet(output, cur->nodesetval, depth);
	    break;
	case XPATH_XSLT_TREE:
	    fprintf(output, "Object is an XSLT value tree :\n");
	    xmlXPathDebugDumpValueTree(output, cur->nodesetval, depth);
	    break;
        case XPATH_BOOLEAN:
	    fprintf(output, "Object is a Boolean : ");
	    if (cur->boolval) fprintf(output, "true\n");
	    else fprintf(output, "false\n");
	    break;
        case XPATH_NUMBER:
	    fprintf(output, "Object is a number : %0g\n", cur->floatval);
	    break;
        case XPATH_STRING:
	    fprintf(output, "Object is a string : ");
	    xmlDebugDumpString(output, cur->stringval);
	    fprintf(output, "\n");
	    break;
	case XPATH_POINT:
	    fprintf(output, "Object is a point : index %d in node", cur->index);
	    xmlXPathDebugDumpNode(output, (xmlNodePtr) cur->user, depth + 1);
	    fprintf(output, "\n");
	    break;
	case XPATH_RANGE:
	    if ((cur->user2 == NULL) ||
		((cur->user2 == cur->user) && (cur->index == cur->index2))) {
		fprintf(output, "Object is a collapsed range :\n");
		fprintf(output, shift);
		if (cur->index >= 0)
		    fprintf(output, "index %d in ", cur->index);
		fprintf(output, "node\n");
		xmlXPathDebugDumpNode(output, (xmlNodePtr) cur->user,
			              depth + 1);
	    } else  {
		fprintf(output, "Object is a range :\n");
		fprintf(output, shift);
		fprintf(output, "From ");
		if (cur->index >= 0)
		    fprintf(output, "index %d in ", cur->index);
		fprintf(output, "node\n");
		xmlXPathDebugDumpNode(output, (xmlNodePtr) cur->user,
			              depth + 1);
		fprintf(output, shift);
		fprintf(output, "To ");
		if (cur->index2 >= 0)
		    fprintf(output, "index %d in ", cur->index2);
		fprintf(output, "node\n");
		xmlXPathDebugDumpNode(output, (xmlNodePtr) cur->user2,
			              depth + 1);
		fprintf(output, "\n");
	    }
	    break;
	case XPATH_LOCATIONSET:
#if defined(LIBXML_XPTR_ENABLED)
	    fprintf(output, "Object is a Location Set:\n");
	    xmlXPathDebugDumpLocationSet(output,
		    (xmlLocationSetPtr) cur->user, depth);
#endif
	    break;
	case XPATH_USERS:
	    fprintf(output, "Object is user defined\n");
	    break;
    }
}
#endif

/************************************************************************
 *									*
 * 		Parser stacks related functions and macros		*
 *									*
 ************************************************************************/

/*
 * Generic function for accessing stacks in the Parser Context
 */

#define PUSH_AND_POP(type, name)					\
extern int name##Push(xmlXPathParserContextPtr ctxt, type value) {	\
    if (ctxt->name##Nr >= ctxt->name##Max) {				\
	ctxt->name##Max *= 2;						\
        ctxt->name##Tab = (type *) xmlRealloc(ctxt->name##Tab,		\
	             ctxt->name##Max * sizeof(ctxt->name##Tab[0]));	\
        if (ctxt->name##Tab == NULL) {					\
	    xmlGenericError(xmlGenericErrorContext,			\
		    "realloc failed !\n");				\
	    return(0);							\
	}								\
    }									\
    ctxt->name##Tab[ctxt->name##Nr] = value;				\
    ctxt->name = value;							\
    return(ctxt->name##Nr++);						\
}									\
extern type name##Pop(xmlXPathParserContextPtr ctxt) {			\
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

PUSH_AND_POP(xmlXPathObjectPtr, value)

/*
 * Macros for accessing the content. Those should be used only by the parser,
 * and not exported.
 *
 * Dirty macros, i.e. one need to make assumption on the context to use them
 *
 *   CUR_PTR return the current pointer to the xmlChar to be parsed.
 *   CUR     returns the current xmlChar value, i.e. a 8 bit value
 *           in ISO-Latin or UTF-8.
 *           This should be used internally by the parser
 *           only to compare to ASCII values otherwise it would break when
 *           running with UTF-8 encoding.
 *   NXT(n)  returns the n'th next xmlChar. Same as CUR is should be used only
 *           to compare on ASCII based substring.
 *   SKIP(n) Skip n xmlChar, and must also be used only to skip ASCII defined
 *           strings within the parser.
 *   CURRENT Returns the current char value, with the full decoding of
 *           UTF-8 if we are using this mode. It returns an int.
 *   NEXT    Skip to the next character, this does the proper decoding
 *           in UTF-8 mode. It also pop-up unfinished entities on the fly.
 *           It returns the pointer to the current xmlChar.
 */

#define CUR (*ctxt->cur)
#define SKIP(val) ctxt->cur += (val)
#define NXT(val) ctxt->cur[(val)]
#define CUR_PTR ctxt->cur

#define SKIP_BLANKS 							\
    while (IS_BLANK(*(ctxt->cur))) NEXT

#define CURRENT (*ctxt->cur)
#define NEXT ((*ctxt->cur) ?  ctxt->cur++: ctxt->cur)


#ifndef DBL_DIG
#define DBL_DIG 16
#endif
#ifndef DBL_EPSILON
#define DBL_EPSILON 1E-9
#endif

#define UPPER_DOUBLE 1E9
#define LOWER_DOUBLE 1E-5

#define INTEGER_DIGITS DBL_DIG
#define FRACTION_DIGITS (DBL_DIG + 1)
#define EXPONENT_DIGITS (3 + 2)

/**
 * xmlXPathFormatNumber:
 * @number:     number to format
 * @buffer:     output buffer
 * @buffersize: size of output buffer
 *
 * Convert the number into a string representation.
 */
static void
xmlXPathFormatNumber(double number, char buffer[], int buffersize)
{
    switch (isinf(number)) {
    case 1:
	if (buffersize > (int)sizeof("+Infinity"))
	    sprintf(buffer, "+Infinity");
	break;
    case -1:
	if (buffersize > (int)sizeof("-Infinity"))
	    sprintf(buffer, "-Infinity");
	break;
    default:
	if (isnan(number)) {
	    if (buffersize > (int)sizeof("NaN"))
		sprintf(buffer, "NaN");
	} else {
	    char work[INTEGER_DIGITS + FRACTION_DIGITS + EXPONENT_DIGITS + 1];
	    char *pointer;
	    char *start;
	    int i;
	    int digits;
	    int is_negative;
	    int use_scientific;
	    int exponent;
	    int index;
	    int count;
	    double n;

	    i = digits = 0;
	    is_negative = (number < 0.0);
	    if (is_negative)
		number = -number;

	    /* Scale number */
	    n = log10(number);
	    exponent = (isinf(n) == -1) ? 0 : (int)n;
	    use_scientific = (((number <= LOWER_DOUBLE) ||
			       (number > UPPER_DOUBLE)) &&
			      (number != 0));
	    if (use_scientific) {
		number /= pow(10.0, (double)exponent);
		while (number < 1.0) {
		    number *= 10.0;
		    exponent--;
		}
	    }
	    
	    /* Integer part is build from back */
	    pointer = &work[INTEGER_DIGITS + 1];
	    if (number < 1.0) {
		*(--pointer) = '0';
		digits++;
	    } else {
		n = number;
		for (i = 1; i < INTEGER_DIGITS - 1; i++) {
		    index = (int)n % 10;
		    *(--pointer) = "0123456789"[index];
		    n /= 10.0;
		    if (n < 1.0)
			break;
		}
		digits += i;
	    }
	    if (is_negative) {
		*(--pointer) = '-';
		digits++;
	    }
	    start = pointer;

	    /* Fraction part is build from front */
	    i = 0;
	    pointer = &work[INTEGER_DIGITS + 1];
	    if (number - floor(number) > DBL_EPSILON) {
		*(pointer++) = '.';
		i++;
		n = number;
		count = 0;
		while (i < FRACTION_DIGITS) {
		    n -= floor(n);
		    n *= 10.0;
		    index = (int)n % 10;
		    *(pointer++) = "0123456789"[index];
		    i++;
		    if ((index != 0) || (count > 0))
			count++;
		    if ((n > 10.0) || (count > FRACTION_DIGITS / 2))
			break;
		}
	    }
	    /* Remove trailing zeroes */
	    while ((pointer[-1] == '0') && (i > 0)) {
		pointer--;
		i--;
	    }
	    digits += i;
	    
	    if (use_scientific) {
		*(pointer++) = 'e';
		digits++;
		if (exponent < 0) {
		    *(pointer++) = '-';
		    exponent = -exponent;
		} else {
		    *(pointer++) = '+';
		}
		digits++;
		if (exponent >= 100)
		    pointer += 2;
		else if (exponent >= 10)
		    pointer += 1;
		while (exponent >= 1) {
		    *(pointer--) = "0123456789"[exponent % 10];
		    exponent /= 10;
		    digits++;
		}
	    }

	    if (digits >= buffersize)
		digits = buffersize - 1;
	    
	    memcpy(buffer, start, digits);
	    buffer[digits] = 0;
	}
	break;
    }
}

/************************************************************************
 *									*
 *			Error handling routines				*
 *									*
 ************************************************************************/


const char *xmlXPathErrorMessages[] = {
    "Ok",
    "Number encoding",
    "Unfinished litteral",
    "Start of litteral",
    "Expected $ for variable reference",
    "Undefined variable",
    "Invalid predicate",
    "Invalid expression",
    "Missing closing curly brace",
    "Unregistered function",
    "Invalid operand",
    "Invalid type",
    "Invalid number of arguments",
    "Invalid context size",
    "Invalid context position",
    "Memory allocation error",
    "Syntax error",
    "Resource error",
    "Sub resource error",
    "Undefined namespace prefix"
};

/**
 * xmlXPathError:
 * @ctxt:  the XPath Parser context
 * @file:  the file name
 * @line:  the line number
 * @no:  the error number
 *
 * Create a new xmlNodeSetPtr of type double and of value @val
 *
 * Returns the newly created object.
 */
void
xmlXPatherror(xmlXPathParserContextPtr ctxt, const char *file,
              int line, int no) {
    int n;
    const xmlChar *cur;
    const xmlChar *base;

    xmlGenericError(xmlGenericErrorContext,
	    "Error %s:%d: %s\n", file, line,
            xmlXPathErrorMessages[no]);

    cur = ctxt->cur;
    base = ctxt->base;
    while ((cur > base) && ((*cur == '\n') || (*cur == '\r'))) {
	cur--;
    }
    n = 0;
    while ((n++ < 80) && (cur > base) && (*cur != '\n') && (*cur != '\r'))
        cur--;
    if ((*cur == '\n') || (*cur == '\r')) cur++;
    base = cur;
    n = 0;
    while ((*cur != 0) && (*cur != '\n') && (*cur != '\r') && (n < 79)) {
        xmlGenericError(xmlGenericErrorContext, "%c", (unsigned char) *cur++);
	n++;
    }
    xmlGenericError(xmlGenericErrorContext, "\n");
    cur = ctxt->cur;
    while ((*cur == '\n') || (*cur == '\r'))
	cur--;
    n = 0;
    while ((cur != base) && (n++ < 80)) {
        xmlGenericError(xmlGenericErrorContext, " ");
        base++;
    }
    xmlGenericError(xmlGenericErrorContext,"^\n");
}


/************************************************************************
 *									*
 *			Routines to handle NodeSets			*
 *									*
 ************************************************************************/

/**
 * xmlXPathCmpNodes:
 * @node1:  the first node
 * @node2:  the second node
 *
 * Compare two nodes w.r.t document order
 *
 * Returns -2 in case of error 1 if first point < second point, 0 if
 *         that's the same node, -1 otherwise
 */
int
xmlXPathCmpNodes(xmlNodePtr node1, xmlNodePtr node2) {
    int depth1, depth2;
    xmlNodePtr cur, root;

    if ((node1 == NULL) || (node2 == NULL))
	return(-2);
    /*
     * a couple of optimizations which will avoid computations in most cases
     */
    if (node1 == node2)
	return(0);
    if (node1 == node2->prev)
	return(1);
    if (node1 == node2->next)
	return(-1);

    /*
     * compute depth to root
     */
    for (depth2 = 0, cur = node2;cur->parent != NULL;cur = cur->parent) {
	if (cur == node1)
	    return(1);
	depth2++;
    }
    root = cur;
    for (depth1 = 0, cur = node1;cur->parent != NULL;cur = cur->parent) {
	if (cur == node2)
	    return(-1);
	depth1++;
    }
    /*
     * Distinct document (or distinct entities :-( ) case.
     */
    if (root != cur) {
	return(-2);
    }
    /*
     * get the nearest common ancestor.
     */
    while (depth1 > depth2) {
	depth1--;
	node1 = node1->parent;
    }
    while (depth2 > depth1) {
	depth2--;
	node2 = node2->parent;
    }
    while (node1->parent != node2->parent) {
	node1 = node1->parent;
	node2 = node2->parent;
	/* should not happen but just in case ... */
	if ((node1 == NULL) || (node2 == NULL))
	    return(-2);
    }
    /*
     * Find who's first.
     */
    if (node1 == node2->next)
	return(-1);
    for (cur = node1->next;cur != NULL;cur = cur->next)
	if (cur == node2)
	    return(1);
    return(-1); /* assume there is no sibling list corruption */
}

/**
 * xmlXPathNodeSetSort:
 * @set:  the node set
 *
 * Sort the node set in document order
 */
void
xmlXPathNodeSetSort(xmlNodeSetPtr set) {
    int i, j, incr, len;
    xmlNodePtr tmp;

    if (set == NULL)
	return;

    /* Use Shell's sort to sort the node-set */
    len = set->nodeNr;
    for (incr = len / 2; incr > 0; incr /= 2) {
	for (i = incr; i < len; i++) {
	    j = i - incr;
	    while (j >= 0) {
		if (xmlXPathCmpNodes(set->nodeTab[j],
				     set->nodeTab[j + incr]) == -1) {
		    tmp = set->nodeTab[j];
		    set->nodeTab[j] = set->nodeTab[j + incr];
		    set->nodeTab[j + incr] = tmp;
		    j -= incr;
		} else
		    break;
	    }
	}
    }
}

#define XML_NODESET_DEFAULT	10
/**
 * xmlXPathNodeSetCreate:
 * @val:  an initial xmlNodePtr, or NULL
 *
 * Create a new xmlNodeSetPtr of type double and of value @val
 *
 * Returns the newly created object.
 */
xmlNodeSetPtr
xmlXPathNodeSetCreate(xmlNodePtr val) {
    xmlNodeSetPtr ret;

    ret = (xmlNodeSetPtr) xmlMalloc(sizeof(xmlNodeSet));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewNodeSet: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlNodeSet));
    if (val != NULL) {
        ret->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
					     sizeof(xmlNodePtr));
	if (ret->nodeTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathNewNodeSet: out of memory\n");
	    return(NULL);
	}
	memset(ret->nodeTab, 0 ,
	       XML_NODESET_DEFAULT * (size_t) sizeof(xmlNodePtr));
        ret->nodeMax = XML_NODESET_DEFAULT;
	ret->nodeTab[ret->nodeNr++] = val;
    }
    return(ret);
}

/**
 * xmlXPathNodeSetAdd:
 * @cur:  the initial node set
 * @val:  a new xmlNodePtr
 *
 * add a new xmlNodePtr ot an existing NodeSet
 */
void
xmlXPathNodeSetAdd(xmlNodeSetPtr cur, xmlNodePtr val) {
    int i;

    if (val == NULL) return;

    /*
     * check against doublons
     */
    for (i = 0;i < cur->nodeNr;i++)
        if (cur->nodeTab[i] == val) return;

    /*
     * grow the nodeTab if needed
     */
    if (cur->nodeMax == 0) {
        cur->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
					     sizeof(xmlNodePtr));
	if (cur->nodeTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathNodeSetAdd: out of memory\n");
	    return;
	}
	memset(cur->nodeTab, 0 ,
	       XML_NODESET_DEFAULT * (size_t) sizeof(xmlNodePtr));
        cur->nodeMax = XML_NODESET_DEFAULT;
    } else if (cur->nodeNr == cur->nodeMax) {
        xmlNodePtr *temp;

        cur->nodeMax *= 2;
	temp = (xmlNodePtr *) xmlRealloc(cur->nodeTab, cur->nodeMax *
				      sizeof(xmlNodePtr));
	if (temp == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathNodeSetAdd: out of memory\n");
	    return;
	}
	cur->nodeTab = temp;
    }
    cur->nodeTab[cur->nodeNr++] = val;
}

/**
 * xmlXPathNodeSetAddUnique:
 * @cur:  the initial node set
 * @val:  a new xmlNodePtr
 *
 * add a new xmlNodePtr ot an existing NodeSet, optimized version
 * when we are sure the node is not already in the set.
 */
void
xmlXPathNodeSetAddUnique(xmlNodeSetPtr cur, xmlNodePtr val) {
    if (val == NULL) return;

    /*
     * grow the nodeTab if needed
     */
    if (cur->nodeMax == 0) {
        cur->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
					     sizeof(xmlNodePtr));
	if (cur->nodeTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathNodeSetAddUnique: out of memory\n");
	    return;
	}
	memset(cur->nodeTab, 0 ,
	       XML_NODESET_DEFAULT * (size_t) sizeof(xmlNodePtr));
        cur->nodeMax = XML_NODESET_DEFAULT;
    } else if (cur->nodeNr == cur->nodeMax) {
        xmlNodePtr *temp;

        cur->nodeMax *= 2;
	temp = (xmlNodePtr *) xmlRealloc(cur->nodeTab, cur->nodeMax *
				      sizeof(xmlNodePtr));
	if (temp == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathNodeSetAddUnique: out of memory\n");
	    return;
	}
	cur->nodeTab = temp;
    }
    cur->nodeTab[cur->nodeNr++] = val;
}

/**
 * xmlXPathNodeSetMerge:
 * @val1:  the first NodeSet or NULL
 * @val2:  the second NodeSet
 *
 * Merges two nodesets, all nodes from @val2 are added to @val1
 * if @val1 is NULL, a new set is created and copied from @val2
 *
 * Returns val1 once extended or NULL in case of error.
 */
xmlNodeSetPtr
xmlXPathNodeSetMerge(xmlNodeSetPtr val1, xmlNodeSetPtr val2) {
    int i, j, initNr;

    if (val2 == NULL) return(val1);
    if (val1 == NULL) {
	val1 = xmlXPathNodeSetCreate(NULL);
    }

    initNr = val1->nodeNr;

    for (i = 0;i < val2->nodeNr;i++) {
	/*
	 * check against doublons
	 */
	for (j = 0; j < initNr; j++)
	    if (val1->nodeTab[j] == val2->nodeTab[i]) continue;

	/*
	 * grow the nodeTab if needed
	 */
	if (val1->nodeMax == 0) {
	    val1->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
						    sizeof(xmlNodePtr));
	    if (val1->nodeTab == NULL) {
		xmlGenericError(xmlGenericErrorContext,
				"xmlXPathNodeSetMerge: out of memory\n");
		return(NULL);
	    }
	    memset(val1->nodeTab, 0 ,
		   XML_NODESET_DEFAULT * (size_t) sizeof(xmlNodePtr));
	    val1->nodeMax = XML_NODESET_DEFAULT;
	} else if (val1->nodeNr == val1->nodeMax) {
	    xmlNodePtr *temp;

	    val1->nodeMax *= 2;
	    temp = (xmlNodePtr *) xmlRealloc(val1->nodeTab, val1->nodeMax *
					     sizeof(xmlNodePtr));
	    if (temp == NULL) {
		xmlGenericError(xmlGenericErrorContext,
				"xmlXPathNodeSetMerge: out of memory\n");
		return(NULL);
	    }
	    val1->nodeTab = temp;
	}
	val1->nodeTab[val1->nodeNr++] = val2->nodeTab[i];
    }

    return(val1);
}

/**
 * xmlXPathNodeSetDel:
 * @cur:  the initial node set
 * @val:  an xmlNodePtr
 *
 * Removes an xmlNodePtr from an existing NodeSet
 */
void
xmlXPathNodeSetDel(xmlNodeSetPtr cur, xmlNodePtr val) {
    int i;

    if (cur == NULL) return;
    if (val == NULL) return;

    /*
     * check against doublons
     */
    for (i = 0;i < cur->nodeNr;i++)
        if (cur->nodeTab[i] == val) break;

    if (i >= cur->nodeNr) {
#ifdef DEBUG
        xmlGenericError(xmlGenericErrorContext, 
	        "xmlXPathNodeSetDel: Node %s wasn't found in NodeList\n",
		val->name);
#endif
        return;
    }
    cur->nodeNr--;
    for (;i < cur->nodeNr;i++)
        cur->nodeTab[i] = cur->nodeTab[i + 1];
    cur->nodeTab[cur->nodeNr] = NULL;
}

/**
 * xmlXPathNodeSetRemove:
 * @cur:  the initial node set
 * @val:  the index to remove
 *
 * Removes an entry from an existing NodeSet list.
 */
void
xmlXPathNodeSetRemove(xmlNodeSetPtr cur, int val) {
    if (cur == NULL) return;
    if (val >= cur->nodeNr) return;
    cur->nodeNr--;
    for (;val < cur->nodeNr;val++)
        cur->nodeTab[val] = cur->nodeTab[val + 1];
    cur->nodeTab[cur->nodeNr] = NULL;
}

/**
 * xmlXPathFreeNodeSet:
 * @obj:  the xmlNodeSetPtr to free
 *
 * Free the NodeSet compound (not the actual nodes !).
 */
void
xmlXPathFreeNodeSet(xmlNodeSetPtr obj) {
    if (obj == NULL) return;
    if (obj->nodeTab != NULL) {
	MEM_CLEANUP(obj->nodeTab, (size_t) sizeof(xmlNodePtr) * obj->nodeMax);
	xmlFree(obj->nodeTab);
    }
    MEM_CLEANUP(obj, (size_t) sizeof(xmlNodeSet));
    xmlFree(obj);
}

/**
 * xmlXPathFreeValueTree:
 * @obj:  the xmlNodeSetPtr to free
 *
 * Free the NodeSet compound and the actual tree, this is different
 * from xmlXPathFreeNodeSet()
 */
void
xmlXPathFreeValueTree(xmlNodeSetPtr obj) {
    int i;

    if (obj == NULL) return;
    for (i = 0;i < obj->nodeNr;i++)
        if (obj->nodeTab[i] != NULL)
	    xmlFreeNodeList(obj->nodeTab[i]);

    if (obj->nodeTab != NULL) {
	MEM_CLEANUP(obj->nodeTab, (size_t) sizeof(xmlNodePtr) * obj->nodeMax);
	xmlFree(obj->nodeTab);
    }
    MEM_CLEANUP(obj, (size_t) sizeof(xmlNodeSet));
    xmlFree(obj);
}

#if defined(DEBUG) || defined(DEBUG_STEP)
/**
 * xmlGenericErrorContextNodeSet:
 * @output:  a FILE * for the output
 * @obj:  the xmlNodeSetPtr to free
 *
 * Quick display of a NodeSet
 */
void
xmlGenericErrorContextNodeSet(FILE *output, xmlNodeSetPtr obj) {
    int i;

    if (output == NULL) output = xmlGenericErrorContext;
    if (obj == NULL)  {
        fprintf(output, "NodeSet == NULL !\n");
	return;
    }
    if (obj->nodeNr == 0) {
        fprintf(output, "NodeSet is empty\n");
	return;
    }
    if (obj->nodeTab == NULL) {
	fprintf(output, " nodeTab == NULL !\n");
	return;
    }
    for (i = 0; i < obj->nodeNr; i++) {
        if (obj->nodeTab[i] == NULL) {
	    fprintf(output, " NULL !\n");
	    return;
        }
	if ((obj->nodeTab[i]->type == XML_DOCUMENT_NODE) ||
	    (obj->nodeTab[i]->type == XML_HTML_DOCUMENT_NODE))
	    fprintf(output, " /");
	else if (obj->nodeTab[i]->name == NULL)
	    fprintf(output, " noname!");
	else fprintf(output, " %s", obj->nodeTab[i]->name);
    }
    fprintf(output, "\n");
}
#endif

/**
 * xmlXPathNewNodeSet:
 * @val:  the NodePtr value
 *
 * Create a new xmlXPathObjectPtr of type NodeSet and initialize
 * it with the single Node @val
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathNewNodeSet(xmlNodePtr val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewNodeSet: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_NODESET;
    ret->boolval = 0;
    ret->nodesetval = xmlXPathNodeSetCreate(val);
    return(ret);
}

/**
 * xmlXPathNewValueTree:
 * @val:  the NodePtr value
 *
 * Create a new xmlXPathObjectPtr of type Value Tree (XSLT) and initialize
 * it with the tree root @val
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathNewValueTree(xmlNodePtr val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewNodeSet: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_XSLT_TREE;
    ret->nodesetval = xmlXPathNodeSetCreate(val);
    return(ret);
}

/**
 * xmlXPathNewNodeSetList:
 * @val:  an existing NodeSet
 *
 * Create a new xmlXPathObjectPtr of type NodeSet and initialize
 * it with the Nodeset @val
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathNewNodeSetList(xmlNodeSetPtr val) {
    xmlXPathObjectPtr ret;
    int i;

    if (val == NULL)
    	ret = NULL;
    else if (val->nodeTab == NULL)
	    ret = xmlXPathNewNodeSet(NULL);
    else
    	{
	    ret = xmlXPathNewNodeSet(val->nodeTab[0]);
	    for (i = 1; i < val->nodeNr; ++i)
	    	xmlXPathNodeSetAddUnique(ret->nodesetval, val->nodeTab[i]);
	    }

    return(ret);
}

/**
 * xmlXPathWrapNodeSet:
 * @val:  the NodePtr value
 *
 * Wrap the Nodeset @val in a new xmlXPathObjectPtr
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathWrapNodeSet(xmlNodeSetPtr val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathWrapNodeSet: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_NODESET;
    ret->nodesetval = val;
    return(ret);
}

/**
 * xmlXPathFreeNodeSetList:
 * @obj:  an existing NodeSetList object
 *
 * Free up the xmlXPathObjectPtr @obj but don't deallocate the objects in
 * the list contrary to xmlXPathFreeObject().
 */
void
xmlXPathFreeNodeSetList(xmlXPathObjectPtr obj) {
    if (obj == NULL) return;
    MEM_CLEANUP(obj, (size_t) sizeof(xmlXPathObject));
    xmlFree(obj);
}

/************************************************************************
 *									*
 *		Routines to handle extra functions			*
 *									*
 ************************************************************************/

/**
 * xmlXPathRegisterFunc:
 * @ctxt:  the XPath context
 * @name:  the function name
 * @f:  the function implementation or NULL
 *
 * Register a new function. If @f is NULL it unregisters the function
 *
 * Returns 0 in case of success, -1 in case of error
 */
int		  
xmlXPathRegisterFunc(xmlXPathContextPtr ctxt, const xmlChar *name,
		     xmlXPathFunction f) {
    return(xmlXPathRegisterFuncNS(ctxt, name, NULL, f));
}

/**
 * xmlXPathRegisterFuncNS:
 * @ctxt:  the XPath context
 * @name:  the function name
 * @ns_uri:  the function namespace URI
 * @f:  the function implementation or NULL
 *
 * Register a new function. If @f is NULL it unregisters the function
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xmlXPathRegisterFuncNS(xmlXPathContextPtr ctxt, const xmlChar *name,
		       const xmlChar *ns_uri, xmlXPathFunction f) {
    if (ctxt == NULL)
	return(-1);
    if (name == NULL)
	return(-1);

    if (ctxt->funcHash == NULL)
	ctxt->funcHash = xmlHashCreate(0);
    if (ctxt->funcHash == NULL)
	return(-1);
    return(xmlHashAddEntry2(ctxt->funcHash, name, ns_uri, (void *) f));
}

/**
 * xmlXPathFunctionLookup:
 * @ctxt:  the XPath context
 * @name:  the function name
 *
 * Search in the Function array of the context for the given
 * function.
 *
 * Returns the xmlXPathFunction or NULL if not found
 */
xmlXPathFunction
xmlXPathFunctionLookup(xmlXPathContextPtr ctxt, const xmlChar *name) {
    return(xmlXPathFunctionLookupNS(ctxt, name, NULL));
}

/**
 * xmlXPathFunctionLookupNS:
 * @ctxt:  the XPath context
 * @name:  the function name
 * @ns_uri:  the function namespace URI
 *
 * Search in the Function array of the context for the given
 * function.
 *
 * Returns the xmlXPathFunction or NULL if not found
 */
xmlXPathFunction
xmlXPathFunctionLookupNS(xmlXPathContextPtr ctxt, const xmlChar *name,
			 const xmlChar *ns_uri) {
    if (ctxt == NULL)
	return(NULL);
    if (ctxt->funcHash == NULL)
	return(NULL);
    if (name == NULL)
	return(NULL);

    return((xmlXPathFunction) xmlHashLookup2(ctxt->funcHash, name, ns_uri));
}

/**
 * xmlXPathRegisteredFuncsCleanup:
 * @ctxt:  the XPath context
 *
 * Cleanup the XPath context data associated to registered functions
 */
void
xmlXPathRegisteredFuncsCleanup(xmlXPathContextPtr ctxt) {
    if (ctxt == NULL)
	return;

    xmlHashFree(ctxt->funcHash, NULL);
    ctxt->funcHash = NULL;
}

/************************************************************************
 *									*
 *			Routines to handle Variable			*
 *									*
 ************************************************************************/

/**
 * xmlXPathRegisterVariable:
 * @ctxt:  the XPath context
 * @name:  the variable name
 * @value:  the variable value or NULL
 *
 * Register a new variable value. If @value is NULL it unregisters
 * the variable
 *
 * Returns 0 in case of success, -1 in case of error
 */
int		  
xmlXPathRegisterVariable(xmlXPathContextPtr ctxt, const xmlChar *name,
			 xmlXPathObjectPtr value) {
    return(xmlXPathRegisterVariableNS(ctxt, name, NULL, value));
}

/**
 * xmlXPathRegisterVariableNS:
 * @ctxt:  the XPath context
 * @name:  the variable name
 * @ns_uri:  the variable namespace URI
 * @value:  the variable value or NULL
 *
 * Register a new variable value. If @value is NULL it unregisters
 * the variable
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xmlXPathRegisterVariableNS(xmlXPathContextPtr ctxt, const xmlChar *name,
			   const xmlChar *ns_uri,
			   xmlXPathObjectPtr value) {
    if (ctxt == NULL)
	return(-1);
    if (name == NULL)
	return(-1);

    if (ctxt->varHash == NULL)
	ctxt->varHash = xmlHashCreate(0);
    if (ctxt->varHash == NULL)
	return(-1);
    return(xmlHashUpdateEntry2(ctxt->varHash, name, ns_uri,
			       (void *) value,
			       (xmlHashDeallocator)xmlXPathFreeObject));
}

/**
 * xmlXPathRegisterVariableLookup:
 * @ctxt:  the XPath context
 * @f:  the lookup function
 * @data:  the lookup data
 *
 * register an external mechanism to do variable lookup
 */
void
xmlXPathRegisterVariableLookup(xmlXPathContextPtr ctxt,
	 xmlXPathVariableLookupFunc f, void *data) {
    if (ctxt == NULL)
	return;
    ctxt->varLookupFunc = (void *) f;
    ctxt->varLookupData = data;
}

/**
 * xmlXPathVariableLookup:
 * @ctxt:  the XPath context
 * @name:  the variable name
 *
 * Search in the Variable array of the context for the given
 * variable value.
 *
 * Returns the value or NULL if not found
 */
xmlXPathObjectPtr
xmlXPathVariableLookup(xmlXPathContextPtr ctxt, const xmlChar *name) {
    if (ctxt == NULL)
	return(NULL);

    if (ctxt->varLookupFunc != NULL) {
	xmlXPathObjectPtr ret;

	ret = ((xmlXPathVariableLookupFunc)ctxt->varLookupFunc)
	        (ctxt->varLookupData, name, NULL);
	if (ret != NULL) return(ret);
    }
    return(xmlXPathVariableLookupNS(ctxt, name, NULL));
}

/**
 * xmlXPathVariableLookupNS:
 * @ctxt:  the XPath context
 * @name:  the variable name
 * @ns_uri:  the variable namespace URI
 *
 * Search in the Variable array of the context for the given
 * variable value.
 *
 * Returns the value or NULL if not found
 */
xmlXPathObjectPtr
xmlXPathVariableLookupNS(xmlXPathContextPtr ctxt, const xmlChar *name,
			 const xmlChar *ns_uri) {
    if (ctxt == NULL)
	return(NULL);

    if (ctxt->varLookupFunc != NULL) {
	xmlXPathObjectPtr ret;

	ret = ((xmlXPathVariableLookupFunc)ctxt->varLookupFunc)
	        (ctxt->varLookupData, name, ns_uri);
	if (ret != NULL) return(ret);
    }

    if (ctxt->varHash == NULL)
	return(NULL);
    if (name == NULL)
	return(NULL);

    return((xmlXPathObjectPtr) xmlHashLookup2(ctxt->varHash, name, ns_uri));
}

/**
 * xmlXPathRegisteredVariablesCleanup:
 * @ctxt:  the XPath context
 *
 * Cleanup the XPath context data associated to registered variables
 */
void
xmlXPathRegisteredVariablesCleanup(xmlXPathContextPtr ctxt) {
    if (ctxt == NULL)
	return;

    xmlHashFree(ctxt->varHash, NULL);
    ctxt->varHash = NULL;
}

/**
 * xmlXPathRegisterNs:
 * @ctxt:  the XPath context
 * @prefix:  the namespace prefix
 * @ns_uri:  the namespace name
 *
 * Register a new namespace. If @ns_uri is NULL it unregisters
 * the namespace
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xmlXPathRegisterNs(xmlXPathContextPtr ctxt, const xmlChar *prefix,
			   const xmlChar *ns_uri) {
    if (ctxt == NULL)
	return(-1);
    if (prefix == NULL)
	return(-1);

    if (ctxt->nsHash == NULL)
	ctxt->nsHash = xmlHashCreate(10);
    if (ctxt->nsHash == NULL)
	return(-1);
    return(xmlHashUpdateEntry(ctxt->nsHash, prefix, (void *) ns_uri,
			      (xmlHashDeallocator)xmlFree));
}

/**
 * xmlXPathNsLookup:
 * @ctxt:  the XPath context
 * @prefix:  the namespace prefix value
 *
 * Search in the namespace declaration array of the context for the given
 * namespace name associated to the given prefix
 *
 * Returns the value or NULL if not found
 */
const xmlChar *
xmlXPathNsLookup(xmlXPathContextPtr ctxt, const xmlChar *prefix) {
    if (ctxt == NULL)
	return(NULL);
    if (prefix == NULL)
	return(NULL);

#ifdef XML_XML_NAMESPACE
    if (xmlStrEqual(prefix, (const xmlChar *) "xml"))
	return(XML_XML_NAMESPACE);
#endif

    if (ctxt->nsHash == NULL)
	return(NULL);

    return((const xmlChar *) xmlHashLookup(ctxt->nsHash, prefix));
}

/**
 * xmlXPathRegisteredVariablesCleanup:
 * @ctxt:  the XPath context
 *
 * Cleanup the XPath context data associated to registered variables
 */
void
xmlXPathRegisteredNsCleanup(xmlXPathContextPtr ctxt) {
    if (ctxt == NULL)
	return;

    xmlHashFree(ctxt->nsHash, NULL);
    ctxt->nsHash = NULL;
}

/************************************************************************
 *									*
 *			Routines to handle Values			*
 *									*
 ************************************************************************/

/* Allocations are terrible, one need to optimize all this !!! */

/**
 * xmlXPathNewFloat:
 * @val:  the double value
 *
 * Create a new xmlXPathObjectPtr of type double and of value @val
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathNewFloat(double val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewFloat: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_NUMBER;
    ret->floatval = val;
    return(ret);
}

/**
 * xmlXPathNewBoolean:
 * @val:  the boolean value
 *
 * Create a new xmlXPathObjectPtr of type boolean and of value @val
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathNewBoolean(int val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewBoolean: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_BOOLEAN;
    ret->boolval = (val != 0);
    return(ret);
}

/**
 * xmlXPathNewString:
 * @val:  the xmlChar * value
 *
 * Create a new xmlXPathObjectPtr of type string and of value @val
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathNewString(const xmlChar *val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewString: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_STRING;
    if (val != NULL)
	ret->stringval = xmlStrdup(val);
    else
	ret->stringval = xmlStrdup((const xmlChar *)"");
    return(ret);
}

/**
 * xmlXPathNewCString:
 * @val:  the char * value
 *
 * Create a new xmlXPathObjectPtr of type string and of value @val
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathNewCString(const char *val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewCString: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_STRING;
    ret->stringval = xmlStrdup(BAD_CAST val);
    return(ret);
}

/**
 * xmlXPathObjectCopy:
 * @val:  the original object
 *
 * allocate a new copy of a given object
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPathObjectCopy(xmlXPathObjectPtr val) {
    xmlXPathObjectPtr ret;

    if (val == NULL)
	return(NULL);

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathObjectCopy: out of memory\n");
	return(NULL);
    }
    memcpy(ret, val , (size_t) sizeof(xmlXPathObject));
    switch (val->type) {
	case XPATH_BOOLEAN:
	case XPATH_NUMBER:
	case XPATH_POINT:
	case XPATH_RANGE:
	    break;
	case XPATH_STRING:
	    ret->stringval = xmlStrdup(val->stringval);
	    break;
	case XPATH_XSLT_TREE:
	    if ((val->nodesetval != NULL) &&
		(val->nodesetval->nodeTab != NULL))
		ret->nodesetval = xmlXPathNodeSetCreate(
			xmlCopyNode(val->nodesetval->nodeTab[0], 1));
	    else
		ret->nodesetval = xmlXPathNodeSetCreate(NULL);
	    break;
	case XPATH_NODESET:
	    ret->nodesetval = xmlXPathNodeSetMerge(NULL, val->nodesetval);
	    break;
	case XPATH_LOCATIONSET:
#ifdef LIBXML_XPTR_ENABLED
	{
	    xmlLocationSetPtr loc = val->user;
	    ret->user = (void *) xmlXPtrLocationSetMerge(NULL, loc);
	    break;
	}
#endif
	case XPATH_UNDEFINED:
	case XPATH_USERS:
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathObjectCopy: unsupported type %d\n",
		    val->type);
	    break;
    }
    return(ret);
}

/**
 * xmlXPathFreeObject:
 * @obj:  the object to free
 *
 * Free up an xmlXPathObjectPtr object.
 */
void
xmlXPathFreeObject(xmlXPathObjectPtr obj) {
    if (obj == NULL) return;
    if (obj->type == XPATH_NODESET) {
	if (obj->boolval) {
	    obj->type = XPATH_XSLT_TREE;
	    if (obj->nodesetval != NULL)
		xmlXPathFreeValueTree(obj->nodesetval);
	} else {
	    if (obj->nodesetval != NULL)
		xmlXPathFreeNodeSet(obj->nodesetval);
	}
#ifdef LIBXML_XPTR_ENABLED
    } else if (obj->type == XPATH_LOCATIONSET) {
	if (obj->user != NULL)
	    xmlXPtrFreeLocationSet(obj->user);
#endif
    } else if (obj->type == XPATH_STRING) {
	if (obj->stringval != NULL)
	    xmlFree(obj->stringval);
    } else if (obj->type == XPATH_XSLT_TREE) {
	if (obj->nodesetval != NULL)
	    xmlXPathFreeValueTree(obj->nodesetval);
    }

    MEM_CLEANUP(obj, (size_t) sizeof(xmlXPathObject));
    xmlFree(obj);
}

/************************************************************************
 *									*
 *		Routines to handle XPath contexts			*
 *									*
 ************************************************************************/

/**
 * xmlXPathNewContext:
 * @doc:  the XML document
 *
 * Create a new xmlXPathContext
 *
 * Returns the xmlXPathContext just allocated.
 */
xmlXPathContextPtr
xmlXPathNewContext(xmlDocPtr doc) {
    xmlXPathContextPtr ret;

    ret = (xmlXPathContextPtr) xmlMalloc(sizeof(xmlXPathContext));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewContext: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathContext));
    ret->doc = doc;
    ret->node = NULL;

    ret->varHash = NULL;

    ret->nb_types = 0;
    ret->max_types = 0;
    ret->types = NULL;

    ret->funcHash = xmlHashCreate(0);

    ret->nb_axis = 0;
    ret->max_axis = 0;
    ret->axis = NULL;

    ret->nsHash = NULL;
    ret->user = NULL;

    ret->contextSize = -1;
    ret->proximityPosition = -1;

    xmlXPathRegisterAllFunctions(ret);
    
    return(ret);
}

/**
 * xmlXPathFreeContext:
 * @ctxt:  the context to free
 *
 * Free up an xmlXPathContext
 */
void
xmlXPathFreeContext(xmlXPathContextPtr ctxt) {
    xmlXPathRegisteredNsCleanup(ctxt);
    xmlXPathRegisteredFuncsCleanup(ctxt);
    xmlXPathRegisteredVariablesCleanup(ctxt);
    MEM_CLEANUP(ctxt, (size_t) sizeof(xmlXPathContext));
    xmlFree(ctxt);
}

/************************************************************************
 *									*
 *		Routines to handle XPath parser contexts		*
 *									*
 ************************************************************************/

#define CHECK_CTXT(ctxt)						\
    if (ctxt == NULL) { 						\
        xmlGenericError(xmlGenericErrorContext,				\
		"%s:%d Internal error: ctxt == NULL\n",			\
	        __FILE__, __LINE__);					\
    }									\


#define CHECK_CONTEXT(ctxt)						\
    if (ctxt == NULL) { 						\
        xmlGenericError(xmlGenericErrorContext,				\
		"%s:%d Internal error: no context\n",			\
	        __FILE__, __LINE__);					\
    }									\
    else if (ctxt->doc == NULL) { 					\
        xmlGenericError(xmlGenericErrorContext,				\
		"%s:%d Internal error: no document\n",			\
	        __FILE__, __LINE__);					\
    }									\
    else if (ctxt->doc->children == NULL) { 				\
        xmlGenericError(xmlGenericErrorContext,				\
	        "%s:%d Internal error: document without root\n",	\
	        __FILE__, __LINE__);					\
    }									\


/**
 * xmlXPathNewParserContext:
 * @str:  the XPath expression
 * @ctxt:  the XPath context
 *
 * Create a new xmlXPathParserContext
 *
 * Returns the xmlXPathParserContext just allocated.
 */
xmlXPathParserContextPtr
xmlXPathNewParserContext(const xmlChar *str, xmlXPathContextPtr ctxt) {
    xmlXPathParserContextPtr ret;

    ret = (xmlXPathParserContextPtr) xmlMalloc(sizeof(xmlXPathParserContext));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewParserContext: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathParserContext));
    ret->cur = ret->base = str;
    ret->context = ctxt;

    /* Allocate the value stack */
    ret->valueTab = (xmlXPathObjectPtr *) 
                     xmlMalloc(10 * sizeof(xmlXPathObjectPtr));
    ret->valueNr = 0;
    ret->valueMax = 10;
    ret->value = NULL;
    return(ret);
}

/**
 * xmlXPathFreeParserContext:
 * @ctxt:  the context to free
 *
 * Free up an xmlXPathParserContext
 */
void
xmlXPathFreeParserContext(xmlXPathParserContextPtr ctxt) {
    if (ctxt->valueTab != NULL) {
        MEM_CLEANUP(ctxt->valueTab, 10 * (size_t) sizeof(xmlXPathObjectPtr));
        xmlFree(ctxt->valueTab);
    }
    MEM_CLEANUP(ctxt, (size_t) sizeof(xmlXPathParserContext));
    xmlFree(ctxt);
}

/************************************************************************
 *									*
 *		The implicit core function library			*
 *									*
 ************************************************************************/

/*
 * Auto-pop and cast to a number
 */
void xmlXPathNumberFunction(xmlXPathParserContextPtr ctxt, int nargs);


#define POP_FLOAT						\
    arg = valuePop(ctxt);					\
    if (arg == NULL) {						\
	XP_ERROR(XPATH_INVALID_OPERAND);				\
    }								\
    if (arg->type != XPATH_NUMBER) {				\
        valuePush(ctxt, arg);					\
        xmlXPathNumberFunction(ctxt, 1);			\
	arg = valuePop(ctxt);					\
    }

/**
 * xmlXPathCompareNodeSetFloat:
 * @ctxt:  the XPath Parser context
 * @inf:  less than (1) or greater than (0)
 * @strict:  is the comparison strict
 * @arg:  the node set
 * @f:  the value
 *
 * Implement the compare operation between a nodeset and a number
 *     @ns < @val    (1, 1, ...
 *     @ns <= @val   (1, 0, ...
 *     @ns > @val    (0, 1, ...
 *     @ns >= @val   (0, 0, ...
 *
 * If one object to be compared is a node-set and the other is a number,
 * then the comparison will be true if and only if there is a node in the
 * node-set such that the result of performing the comparison on the number
 * to be compared and on the result of converting the string-value of that
 * node to a number using the number function is true.
 *
 * Returns 0 or 1 depending on the results of the test.
 */
int
xmlXPathCompareNodeSetFloat(xmlXPathParserContextPtr ctxt, int inf, int strict,
	                    xmlXPathObjectPtr arg, xmlXPathObjectPtr f) {
    int i, ret = 0;
    xmlNodeSetPtr ns;
    xmlChar *str2;

    if ((f == NULL) || (arg == NULL) ||
	((arg->type != XPATH_NODESET) && (arg->type != XPATH_XSLT_TREE))) {
	xmlXPathFreeObject(arg);
	xmlXPathFreeObject(f);
        return(0);
    }
    ns = arg->nodesetval;
    for (i = 0;i < ns->nodeNr;i++) {
         str2 = xmlNodeGetContent(ns->nodeTab[i]);
	 if (str2 != NULL) {
	     valuePush(ctxt,
		       xmlXPathNewString(str2));
	     xmlFree(str2);
	     xmlXPathNumberFunction(ctxt, 1);
	     valuePush(ctxt, xmlXPathObjectCopy(f));
	     ret = xmlXPathCompareValues(ctxt, inf, strict);
	     if (ret)
		 break;
	 }
    }
    xmlXPathFreeObject(arg);
    xmlXPathFreeObject(f);
    return(ret);
}

/**
 * xmlXPathCompareNodeSetString:
 * @ctxt:  the XPath Parser context
 * @inf:  less than (1) or greater than (0)
 * @strict:  is the comparison strict
 * @arg:  the node set
 * @s:  the value
 *
 * Implement the compare operation between a nodeset and a string
 *     @ns < @val    (1, 1, ...
 *     @ns <= @val   (1, 0, ...
 *     @ns > @val    (0, 1, ...
 *     @ns >= @val   (0, 0, ...
 *
 * If one object to be compared is a node-set and the other is a string,
 * then the comparison will be true if and only if there is a node in
 * the node-set such that the result of performing the comparison on the
 * string-value of the node and the other string is true.
 *
 * Returns 0 or 1 depending on the results of the test.
 */
int
xmlXPathCompareNodeSetString(xmlXPathParserContextPtr ctxt, int inf, int strict,
	                    xmlXPathObjectPtr arg, xmlXPathObjectPtr s) {
    int i, ret = 0;
    xmlNodeSetPtr ns;
    xmlChar *str2;

    if ((s == NULL) || (arg == NULL) ||
	((arg->type != XPATH_NODESET) && (arg->type != XPATH_XSLT_TREE))) {
	xmlXPathFreeObject(arg);
	xmlXPathFreeObject(s);
        return(0);
    }
    ns = arg->nodesetval;
    for (i = 0;i < ns->nodeNr;i++) {
         str2 = xmlNodeGetContent(ns->nodeTab[i]);
	 if (str2 != NULL) {
	     valuePush(ctxt,
		       xmlXPathNewString(str2));
	     xmlFree(str2);
	     valuePush(ctxt, xmlXPathObjectCopy(s));
	     ret = xmlXPathCompareValues(ctxt, inf, strict);
	     if (ret)
		 break;
	 }
    }
    xmlXPathFreeObject(arg);
    xmlXPathFreeObject(s);
    return(ret);
}

/**
 * xmlXPathCompareNodeSets:
 * @ctxt:  the XPath Parser context
 * @op:  less than (-1), equal (0) or greater than (1)
 * @strict:  is the comparison strict
 * @arg1:  the fist node set object
 * @arg2:  the second node set object
 *
 * Implement the compare operation on nodesets:
 *
 * If both objects to be compared are node-sets, then the comparison
 * will be true if and only if there is a node in the first node-set
 * and a node in the second node-set such that the result of performing
 * the comparison on the string-values of the two nodes is true. 
 * ....
 * When neither object to be compared is a node-set and the operator
 * is <=, <, >= or >, then the objects are compared by converting both
 * objects to numbers and comparing the numbers according to IEEE 754.
 * ....
 * The number function converts its argument to a number as follows:
 *  - a string that consists of optional whitespace followed by an
 *    optional minus sign followed by a Number followed by whitespace
 *    is converted to the IEEE 754 number that is nearest (according
 *    to the IEEE 754 round-to-nearest rule) to the mathematical value
 *    represented by the string; any other string is converted to NaN
 *
 * Conclusion all nodes need to be converted first to their string value
 * and then the comparison must be done when possible 
 */
int
xmlXPathCompareNodeSets(xmlXPathParserContextPtr ctxt, int inf, int strict,
	                xmlXPathObjectPtr arg1, xmlXPathObjectPtr arg2) {
    int i, j, init = 0;
    double val1;
    double *values2;
    int ret = 0;
    xmlChar *str;
    xmlNodeSetPtr ns1;
    xmlNodeSetPtr ns2;

    if ((arg1 == NULL) ||
	((arg1->type != XPATH_NODESET) && (arg1->type != XPATH_XSLT_TREE)))
        return(0);
    if ((arg2 == NULL) ||
	((arg2->type != XPATH_NODESET) && (arg2->type != XPATH_XSLT_TREE)))
        return(0);

    ns1 = arg1->nodesetval;
    ns2 = arg2->nodesetval;

    if (ns1->nodeNr <= 0)
	return(0);
    if (ns2->nodeNr <= 0)
	return(0);

    values2 = (double *) xmlMalloc(ns2->nodeNr * sizeof(double));
    if (values2 == NULL) {
	return(0);
    }
    for (i = 0;i < ns1->nodeNr;i++) {
	str = xmlNodeGetContent(ns1->nodeTab[i]);
	if (str == NULL)
	    continue;
	val1 = xmlXPathStringEvalNumber(str);
	xmlFree(str);
	if (isnan(val1))
	    continue;
	for (j = 0;j < ns2->nodeNr;j++) {
	    if (init == 0) {
		str = xmlNodeGetContent(ns2->nodeTab[j]);
		if (str == NULL) {
		    values2[j] = xmlXPathNAN;
		} else {
		    values2[j] = xmlXPathStringEvalNumber(str);
		    xmlFree(str);
		}
	    }
	    if (isnan(values2[j]))
		continue;
	    if (inf && strict) 
		ret = (val1 < values2[j]);
	    else if (inf && !strict)
		ret = (val1 <= values2[j]);
	    else if (!inf && strict)
		ret = (val1 > values2[j]);
	    else if (!inf && !strict)
		ret = (val1 >= values2[j]);
	    if (ret)
		break;
	}
	if (ret)
	    break;
	init = 1;
    }
    xmlFree(values2);
    return(ret);
    return(0);
}

/**
 * xmlXPathCompareNodeSetValue:
 * @ctxt:  the XPath Parser context
 * @inf:  less than (1) or greater than (0)
 * @strict:  is the comparison strict
 * @arg:  the node set
 * @val:  the value
 *
 * Implement the compare operation between a nodeset and a value
 *     @ns < @val    (1, 1, ...
 *     @ns <= @val   (1, 0, ...
 *     @ns > @val    (0, 1, ...
 *     @ns >= @val   (0, 0, ...
 *
 * If one object to be compared is a node-set and the other is a boolean,
 * then the comparison will be true if and only if the result of performing
 * the comparison on the boolean and on the result of converting
 * the node-set to a boolean using the boolean function is true.
 *
 * Returns 0 or 1 depending on the results of the test.
 */
int
xmlXPathCompareNodeSetValue(xmlXPathParserContextPtr ctxt, int inf, int strict,
	                    xmlXPathObjectPtr arg, xmlXPathObjectPtr val) {
    if ((val == NULL) || (arg == NULL) ||
	((arg->type != XPATH_NODESET) && (arg->type != XPATH_XSLT_TREE)))
        return(0);

    switch(val->type) {
        case XPATH_NUMBER:
	    return(xmlXPathCompareNodeSetFloat(ctxt, inf, strict, arg, val));
        case XPATH_NODESET:
        case XPATH_XSLT_TREE:
	    return(xmlXPathCompareNodeSets(ctxt, inf, strict, arg, val));
        case XPATH_STRING:
	    return(xmlXPathCompareNodeSetString(ctxt, inf, strict, arg, val));
        case XPATH_BOOLEAN:
	    valuePush(ctxt, arg);
	    xmlXPathBooleanFunction(ctxt, 1);
	    valuePush(ctxt, val);
	    return(xmlXPathCompareValues(ctxt, inf, strict));
	default:
	    TODO
	    return(0);
    }
    return(0);
}

/**
 * xmlXPathEqualNodeSetString
 * @arg:  the nodeset object argument
 * @str:  the string to compare to.
 *
 * Implement the equal operation on XPath objects content: @arg1 == @arg2
 * If one object to be compared is a node-set and the other is a string,
 * then the comparison will be true if and only if there is a node in
 * the node-set such that the result of performing the comparison on the
 * string-value of the node and the other string is true.
 *
 * Returns 0 or 1 depending on the results of the test.
 */
int
xmlXPathEqualNodeSetString(xmlXPathObjectPtr arg, const xmlChar *str) {
    int i;
    xmlNodeSetPtr ns;
    xmlChar *str2;

    if ((str == NULL) || (arg == NULL) ||
	((arg->type != XPATH_NODESET) && (arg->type != XPATH_XSLT_TREE)))
        return(0);
    ns = arg->nodesetval;
    if (ns->nodeNr <= 0)
	return(0);
    for (i = 0;i < ns->nodeNr;i++) {
         str2 = xmlNodeGetContent(ns->nodeTab[i]);
	 if ((str2 != NULL) && (xmlStrEqual(str, str2))) {
	     xmlFree(str2);
	     return(1);
	 }
	 if (str2 != NULL)
	     xmlFree(str2);
    }
    return(0);
}

/**
 * xmlXPathEqualNodeSetFloat
 * @arg:  the nodeset object argument
 * @f:  the float to compare to
 *
 * Implement the equal operation on XPath objects content: @arg1 == @arg2
 * If one object to be compared is a node-set and the other is a number,
 * then the comparison will be true if and only if there is a node in
 * the node-set such that the result of performing the comparison on the
 * number to be compared and on the result of converting the string-value
 * of that node to a number using the number function is true.
 *
 * Returns 0 or 1 depending on the results of the test.
 */
int
xmlXPathEqualNodeSetFloat(xmlXPathObjectPtr arg, double f) {
    char buf[100] = "";

    if ((arg == NULL) ||
	((arg->type != XPATH_NODESET) && (arg->type != XPATH_XSLT_TREE)))
        return(0);

    xmlXPathFormatNumber(f, buf, sizeof(buf));
    return(xmlXPathEqualNodeSetString(arg, BAD_CAST buf));
}


/**
 * xmlXPathEqualNodeSets
 * @arg1:  first nodeset object argument
 * @arg2:  second nodeset object argument
 *
 * Implement the equal operation on XPath nodesets: @arg1 == @arg2
 * If both objects to be compared are node-sets, then the comparison
 * will be true if and only if there is a node in the first node-set and
 * a node in the second node-set such that the result of performing the
 * comparison on the string-values of the two nodes is true.
 *
 * (needless to say, this is a costly operation)
 *
 * Returns 0 or 1 depending on the results of the test.
 */
int
xmlXPathEqualNodeSets(xmlXPathObjectPtr arg1, xmlXPathObjectPtr arg2) {
    int i, j;
    xmlChar **values1;
    xmlChar **values2;
    int ret = 0;
    xmlNodeSetPtr ns1;
    xmlNodeSetPtr ns2;

    if ((arg1 == NULL) ||
	((arg1->type != XPATH_NODESET) && (arg1->type != XPATH_XSLT_TREE)))
        return(0);
    if ((arg2 == NULL) ||
	((arg2->type != XPATH_NODESET) && (arg2->type != XPATH_XSLT_TREE)))
        return(0);

    ns1 = arg1->nodesetval;
    ns2 = arg2->nodesetval;

    if (ns1->nodeNr <= 0)
	return(0);
    if (ns2->nodeNr <= 0)
	return(0);

    /*
     * check if there is a node pertaining to both sets
     */
    for (i = 0;i < ns1->nodeNr;i++)
	for (j = 0;j < ns2->nodeNr;j++)
	    if (ns1->nodeTab[i] == ns2->nodeTab[j])
		return(1);

    values1 = (xmlChar **) xmlMalloc(ns1->nodeNr * sizeof(xmlChar *));
    if (values1 == NULL)
	return(0);
    memset(values1, 0, ns1->nodeNr * sizeof(xmlChar *));
    values2 = (xmlChar **) xmlMalloc(ns2->nodeNr * sizeof(xmlChar *));
    if (values2 == NULL) {
	xmlFree(values1);
	return(0);
    }
    memset(values2, 0, ns2->nodeNr * sizeof(xmlChar *));
    for (i = 0;i < ns1->nodeNr;i++) {
	values1[i] = xmlNodeGetContent(ns1->nodeTab[i]);
	for (j = 0;j < ns2->nodeNr;j++) {
	    if (i == 0)
		values2[j] = xmlNodeGetContent(ns2->nodeTab[j]);
	    ret = xmlStrEqual(values1[i], values2[j]);
	    if (ret)
		break;
	}
	if (ret)
	    break;
    }
    for (i = 0;i < ns1->nodeNr;i++)
	if (values1[i] != NULL)
	    xmlFree(values1[i]);
    for (j = 0;j < ns2->nodeNr;j++)
	if (values2[j] != NULL)
	    xmlFree(values2[j]);
    xmlFree(values1);
    xmlFree(values2);
    return(ret);
}

/**
 * xmlXPathEqualValues:
 * @ctxt:  the XPath Parser context
 *
 * Implement the equal operation on XPath objects content: @arg1 == @arg2
 *
 * Returns 0 or 1 depending on the results of the test.
 */
int
xmlXPathEqualValues(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg1, arg2;
    int ret = 0;

    arg1 = valuePop(ctxt);
    if (arg1 == NULL)
	XP_ERROR0(XPATH_INVALID_OPERAND);

    arg2 = valuePop(ctxt);
    if (arg2 == NULL) {
	xmlXPathFreeObject(arg1);
	XP_ERROR0(XPATH_INVALID_OPERAND);
    }
  
    if (arg1 == arg2) {
#ifdef DEBUG_EXPR
        xmlGenericError(xmlGenericErrorContext,
		"Equal: by pointer\n");
#endif
        return(1);
    }

    switch (arg1->type) {
        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
	    xmlGenericError(xmlGenericErrorContext,
		    "Equal: undefined\n");
#endif
	    break;
        case XPATH_XSLT_TREE:
        case XPATH_NODESET:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    xmlGenericError(xmlGenericErrorContext,
			    "Equal: undefined\n");
#endif
		    break;
		case XPATH_XSLT_TREE:
		case XPATH_NODESET:
		    ret = xmlXPathEqualNodeSets(arg1, arg2);
		    break;
		case XPATH_BOOLEAN:
		    if ((arg1->nodesetval == NULL) ||
			(arg1->nodesetval->nodeNr == 0)) ret = 0;
		    else 
			ret = 1;
		    ret = (ret == arg2->boolval);
		    break;
		case XPATH_NUMBER:
		    ret = xmlXPathEqualNodeSetFloat(arg1, arg2->floatval);
		    break;
		case XPATH_STRING:
		    ret = xmlXPathEqualNodeSetString(arg1, arg2->stringval);
		    break;
		case XPATH_USERS:
		case XPATH_POINT:
		case XPATH_RANGE:
		case XPATH_LOCATIONSET:
		    TODO
		    break;
	    }
	    break;
        case XPATH_BOOLEAN:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    xmlGenericError(xmlGenericErrorContext,
			    "Equal: undefined\n");
#endif
		    break;
		case XPATH_NODESET:
		case XPATH_XSLT_TREE:
		    if ((arg2->nodesetval == NULL) ||
			(arg2->nodesetval->nodeNr == 0)) ret = 0;
		    else 
			ret = 1;
		    break;
		case XPATH_BOOLEAN:
#ifdef DEBUG_EXPR
		    xmlGenericError(xmlGenericErrorContext,
			    "Equal: %d boolean %d \n",
			    arg1->boolval, arg2->boolval);
#endif
		    ret = (arg1->boolval == arg2->boolval);
		    break;
		case XPATH_NUMBER:
		    if (arg2->floatval) ret = 1;
		    else ret = 0;
		    ret = (arg1->boolval == ret);
		    break;
		case XPATH_STRING:
		    if ((arg2->stringval == NULL) ||
			(arg2->stringval[0] == 0)) ret = 0;
		    else 
			ret = 1;
		    ret = (arg1->boolval == ret);
		    break;
		case XPATH_USERS:
		case XPATH_POINT:
		case XPATH_RANGE:
		case XPATH_LOCATIONSET:
		    TODO
		    break;
	    }
	    break;
        case XPATH_NUMBER:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    xmlGenericError(xmlGenericErrorContext,
			    "Equal: undefined\n");
#endif
		    break;
		case XPATH_NODESET:
		case XPATH_XSLT_TREE:
		    ret = xmlXPathEqualNodeSetFloat(arg2, arg1->floatval);
		    break;
		case XPATH_BOOLEAN:
		    if (arg1->floatval) ret = 1;
		    else ret = 0;
		    ret = (arg2->boolval == ret);
		    break;
		case XPATH_STRING:
		    valuePush(ctxt, arg2);
		    xmlXPathNumberFunction(ctxt, 1);
		    arg2 = valuePop(ctxt);
		    /* no break on purpose */
		case XPATH_NUMBER:
		    ret = (arg1->floatval == arg2->floatval);
		    break;
		case XPATH_USERS:
		case XPATH_POINT:
		case XPATH_RANGE:
		case XPATH_LOCATIONSET:
		    TODO
		    break;
	    }
	    break;
        case XPATH_STRING:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    xmlGenericError(xmlGenericErrorContext,
			    "Equal: undefined\n");
#endif
		    break;
		case XPATH_NODESET:
		case XPATH_XSLT_TREE:
		    ret = xmlXPathEqualNodeSetString(arg2, arg1->stringval);
		    break;
		case XPATH_BOOLEAN:
		    if ((arg1->stringval == NULL) ||
			(arg1->stringval[0] == 0)) ret = 0;
		    else 
			ret = 1;
		    ret = (arg2->boolval == ret);
		    break;
		case XPATH_STRING:
		    ret = xmlStrEqual(arg1->stringval, arg2->stringval);
		    break;
		case XPATH_NUMBER:
		    valuePush(ctxt, arg1);
		    xmlXPathNumberFunction(ctxt, 1);
		    arg1 = valuePop(ctxt);
		    ret = (arg1->floatval == arg2->floatval);
		    break;
		case XPATH_USERS:
		case XPATH_POINT:
		case XPATH_RANGE:
		case XPATH_LOCATIONSET:
		    TODO
		    break;
	    }
	    break;
        case XPATH_USERS:
	case XPATH_POINT:
	case XPATH_RANGE:
	case XPATH_LOCATIONSET:
	    TODO
	    break;
    }
    xmlXPathFreeObject(arg1);
    xmlXPathFreeObject(arg2);
    return(ret);
}


/**
 * xmlXPathCompareValues:
 * @ctxt:  the XPath Parser context
 * @inf:  less than (1) or greater than (0)
 * @strict:  is the comparison strict
 *
 * Implement the compare operation on XPath objects: 
 *     @arg1 < @arg2    (1, 1, ...
 *     @arg1 <= @arg2   (1, 0, ...
 *     @arg1 > @arg2    (0, 1, ...
 *     @arg1 >= @arg2   (0, 0, ...
 *
 * When neither object to be compared is a node-set and the operator is
 * <=, <, >=, >, then the objects are compared by converted both objects
 * to numbers and comparing the numbers according to IEEE 754. The <
 * comparison will be true if and only if the first number is less than the
 * second number. The <= comparison will be true if and only if the first
 * number is less than or equal to the second number. The > comparison
 * will be true if and only if the first number is greater than the second
 * number. The >= comparison will be true if and only if the first number
 * is greater than or equal to the second number.
 *
 * Returns 1 if the comparaison succeeded, 0 if it failed
 */
int
xmlXPathCompareValues(xmlXPathParserContextPtr ctxt, int inf, int strict) {
    int ret = 0;
    xmlXPathObjectPtr arg1, arg2;

    arg2 = valuePop(ctxt);
    if (arg2 == NULL) {
	XP_ERROR0(XPATH_INVALID_OPERAND);
    }
  
    arg1 = valuePop(ctxt);
    if (arg1 == NULL) {
	xmlXPathFreeObject(arg2);
	XP_ERROR0(XPATH_INVALID_OPERAND);
    }

    if ((arg2->type == XPATH_NODESET) || (arg1->type == XPATH_NODESET)) {
	if ((arg2->type == XPATH_NODESET) && (arg1->type == XPATH_NODESET)) {
	    ret = xmlXPathCompareNodeSets(ctxt, inf, strict, arg1, arg2);
	} else {
	    if (arg1->type == XPATH_NODESET) {
		ret = xmlXPathCompareNodeSetValue(ctxt, inf, strict, arg1, arg2);
	    } else {
		ret = xmlXPathCompareNodeSetValue(ctxt, !inf, !strict, arg2, arg1);
	    }
	}
	return(ret);
    }

    if (arg1->type != XPATH_NUMBER) {
	valuePush(ctxt, arg1);
	xmlXPathNumberFunction(ctxt, 1);
	arg1 = valuePop(ctxt);
    }
    if (arg1->type != XPATH_NUMBER) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
	XP_ERROR0(XPATH_INVALID_OPERAND);
    }
    if (arg2->type != XPATH_NUMBER) {
	valuePush(ctxt, arg2);
	xmlXPathNumberFunction(ctxt, 1);
	arg2 = valuePop(ctxt);
    }
    if (arg2->type != XPATH_NUMBER) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
	XP_ERROR0(XPATH_INVALID_OPERAND);
    }
    /*
     * Add tests for infinity and nan
     * => feedback on 3.4 for Inf and NaN
     */
    if (inf && strict) 
        ret = (arg1->floatval < arg2->floatval);
    else if (inf && !strict)
        ret = (arg1->floatval <= arg2->floatval);
    else if (!inf && strict)
        ret = (arg1->floatval > arg2->floatval);
    else if (!inf && !strict)
        ret = (arg1->floatval >= arg2->floatval);
    xmlXPathFreeObject(arg1);
    xmlXPathFreeObject(arg2);
    return(ret);
}

/**
 * xmlXPathValueFlipSign:
 * @ctxt:  the XPath Parser context
 *
 * Implement the unary - operation on an XPath object
 * The numeric operators convert their operands to numbers as if
 * by calling the number function.
 */
void
xmlXPathValueFlipSign(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg;
    
    POP_FLOAT
    arg->floatval = -arg->floatval;
    valuePush(ctxt, arg);
}

/**
 * xmlXPathAddValues:
 * @ctxt:  the XPath Parser context
 *
 * Implement the add operation on XPath objects:
 * The numeric operators convert their operands to numbers as if
 * by calling the number function.
 */
void
xmlXPathAddValues(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg;
    double val;

    POP_FLOAT
    val = arg->floatval;
    xmlXPathFreeObject(arg);

    POP_FLOAT
    arg->floatval += val;
    valuePush(ctxt, arg);
}

/**
 * xmlXPathSubValues:
 * @ctxt:  the XPath Parser context
 *
 * Implement the substraction operation on XPath objects:
 * The numeric operators convert their operands to numbers as if
 * by calling the number function.
 */
void
xmlXPathSubValues(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg;
    double val;

    POP_FLOAT
    val = arg->floatval;
    xmlXPathFreeObject(arg);

    POP_FLOAT
    arg->floatval -= val;
    valuePush(ctxt, arg);
}

/**
 * xmlXPathMultValues:
 * @ctxt:  the XPath Parser context
 *
 * Implement the multiply operation on XPath objects:
 * The numeric operators convert their operands to numbers as if
 * by calling the number function.
 */
void
xmlXPathMultValues(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg;
    double val;

    POP_FLOAT
    val = arg->floatval;
    xmlXPathFreeObject(arg);

    POP_FLOAT
    arg->floatval *= val;
    valuePush(ctxt, arg);
}

/**
 * xmlXPathDivValues:
 * @ctxt:  the XPath Parser context
 *
 * Implement the div operation on XPath objects @arg1 / @arg2:
 * The numeric operators convert their operands to numbers as if
 * by calling the number function.
 */
void
xmlXPathDivValues(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg;
    double val;

    POP_FLOAT
    val = arg->floatval;
    xmlXPathFreeObject(arg);

    POP_FLOAT
    arg->floatval /= val;
    valuePush(ctxt, arg);
}

/**
 * xmlXPathModValues:
 * @ctxt:  the XPath Parser context
 *
 * Implement the mod operation on XPath objects: @arg1 / @arg2
 * The numeric operators convert their operands to numbers as if
 * by calling the number function.
 */
void
xmlXPathModValues(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg;
    int arg1, arg2;

    POP_FLOAT
    arg2 = (int) arg->floatval;
    xmlXPathFreeObject(arg);

    POP_FLOAT
    arg1 = (int) arg->floatval;
    arg->floatval = arg1 % arg2;
    valuePush(ctxt, arg);
}

/************************************************************************
 *									*
 *		The traversal functions					*
 *									*
 ************************************************************************/

typedef enum {
    AXIS_ANCESTOR = 1,
    AXIS_ANCESTOR_OR_SELF,
    AXIS_ATTRIBUTE,
    AXIS_CHILD,
    AXIS_DESCENDANT,
    AXIS_DESCENDANT_OR_SELF,
    AXIS_FOLLOWING,
    AXIS_FOLLOWING_SIBLING,
    AXIS_NAMESPACE,
    AXIS_PARENT,
    AXIS_PRECEDING,
    AXIS_PRECEDING_SIBLING,
    AXIS_SELF
} xmlXPathAxisVal;

/*
 * A traversal function enumerates nodes along an axis.
 * Initially it must be called with NULL, and it indicates
 * termination on the axis by returning NULL.
 */
typedef xmlNodePtr (*xmlXPathTraversalFunction)
                    (xmlXPathParserContextPtr ctxt, xmlNodePtr cur);

/**
 * xmlXPathNextSelf:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "self" direction
 * The self axis contains just the context node itself
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextSelf(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (cur == NULL)
        return(ctxt->context->node);
    return(NULL);
}

/**
 * xmlXPathNextChild:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "child" direction
 * The child axis contains the children of the context node in document order.
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextChild(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (cur == NULL) {
	if (ctxt->context->node == NULL) return(NULL);
	switch (ctxt->context->node->type) {
            case XML_ELEMENT_NODE:
            case XML_TEXT_NODE:
            case XML_CDATA_SECTION_NODE:
            case XML_ENTITY_REF_NODE:
            case XML_ENTITY_NODE:
            case XML_PI_NODE:
            case XML_COMMENT_NODE:
            case XML_NOTATION_NODE:
            case XML_DTD_NODE:
		return(ctxt->context->node->children);
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_SGML_ENABLED
	    case XML_SGML_DOCUMENT_NODE:
#endif
		return(((xmlDocPtr) ctxt->context->node)->children);
	    case XML_ELEMENT_DECL:
	    case XML_ATTRIBUTE_DECL:
	    case XML_ENTITY_DECL:
            case XML_ATTRIBUTE_NODE:
	    case XML_NAMESPACE_DECL:
	    case XML_XINCLUDE_START:
	    case XML_XINCLUDE_END:
		return(NULL);
	}
	return(NULL);
    }
    if ((cur->type == XML_DOCUMENT_NODE) ||
        (cur->type == XML_HTML_DOCUMENT_NODE))
	return(NULL);
    return(cur->next);
}

/**
 * xmlXPathNextDescendant:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "descendant" direction
 * the descendant axis contains the descendants of the context node in document
 * order; a descendant is a child or a child of a child and so on.
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextDescendant(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (cur == NULL) {
	if (ctxt->context->node == NULL)
	    return(NULL);
	if ((ctxt->context->node->type == XML_ATTRIBUTE_NODE) ||
	    (ctxt->context->node->type == XML_NAMESPACE_DECL))
	    return(NULL);

        if (ctxt->context->node == (xmlNodePtr) ctxt->context->doc)
	    return(ctxt->context->doc->children);
        return(ctxt->context->node->children);
    }

    if (cur->children != NULL)
    	{
    	if (cur->children->type != XML_ENTITY_DECL)
		   	return(cur->children);
    	}
    if (cur->next != NULL) return(cur->next);
    
    do {
        cur = cur->parent;
	if (cur == NULL) return(NULL);
	if (cur == ctxt->context->node) return(NULL);
	if (cur->next != NULL) {
	    cur = cur->next;
	    return(cur);
	}
    } while (cur != NULL);
    return(cur);
}

/**
 * xmlXPathNextDescendantOrSelf:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "descendant-or-self" direction
 * the descendant-or-self axis contains the context node and the descendants
 * of the context node in document order; thus the context node is the first
 * node on the axis, and the first child of the context node is the second node
 * on the axis
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextDescendantOrSelf(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (cur == NULL) {
	if (ctxt->context->node == NULL)
	    return(NULL);
	if ((ctxt->context->node->type == XML_ATTRIBUTE_NODE) ||
	    (ctxt->context->node->type == XML_NAMESPACE_DECL))
	    return(NULL);
        return(ctxt->context->node);
    }

    return(xmlXPathNextDescendant(ctxt, cur));
}

/**
 * xmlXPathNextParent:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "parent" direction
 * The parent axis contains the parent of the context node, if there is one.
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextParent(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    /*
     * the parent of an attribute or namespace node is the element
     * to which the attribute or namespace node is attached
     * Namespace handling !!!
     */
    if (cur == NULL) {
	if (ctxt->context->node == NULL) return(NULL);
	switch (ctxt->context->node->type) {
            case XML_ELEMENT_NODE:
            case XML_TEXT_NODE:
            case XML_CDATA_SECTION_NODE:
            case XML_ENTITY_REF_NODE:
            case XML_ENTITY_NODE:
            case XML_PI_NODE:
            case XML_COMMENT_NODE:
            case XML_NOTATION_NODE:
            case XML_DTD_NODE:
	    case XML_ELEMENT_DECL:
	    case XML_ATTRIBUTE_DECL:
	    case XML_XINCLUDE_START:
	    case XML_XINCLUDE_END:
	    case XML_ENTITY_DECL:
		if (ctxt->context->node->parent == NULL)
		    return((xmlNodePtr) ctxt->context->doc);
		return(ctxt->context->node->parent);
            case XML_ATTRIBUTE_NODE: {
		xmlAttrPtr att = (xmlAttrPtr) ctxt->context->node;

		return(att->parent);
	    }
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_SGML_ENABLED
	    case XML_SGML_DOCUMENT_NODE:
#endif
                return(NULL);
	    case XML_NAMESPACE_DECL:
		/*
		 * TODO !!! may require extending struct _xmlNs with
		 * parent field
		 * C.f. Infoset case...
		 */
                return(NULL);
	}
    }
    return(NULL);
}

/**
 * xmlXPathNextAncestor:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "ancestor" direction
 * the ancestor axis contains the ancestors of the context node; the ancestors
 * of the context node consist of the parent of context node and the parent's
 * parent and so on; the nodes are ordered in reverse document order; thus the
 * parent is the first node on the axis, and the parent's parent is the second
 * node on the axis
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextAncestor(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    /*
     * the parent of an attribute or namespace node is the element
     * to which the attribute or namespace node is attached
     * !!!!!!!!!!!!!
     */
    if (cur == NULL) {
	if (ctxt->context->node == NULL) return(NULL);
	switch (ctxt->context->node->type) {
            case XML_ELEMENT_NODE:
            case XML_TEXT_NODE:
            case XML_CDATA_SECTION_NODE:
            case XML_ENTITY_REF_NODE:
            case XML_ENTITY_NODE:
            case XML_PI_NODE:
            case XML_COMMENT_NODE:
	    case XML_DTD_NODE:
	    case XML_ELEMENT_DECL:
	    case XML_ATTRIBUTE_DECL:
	    case XML_ENTITY_DECL:
            case XML_NOTATION_NODE:
	    case XML_XINCLUDE_START:
	    case XML_XINCLUDE_END:
		if (ctxt->context->node->parent == NULL)
		    return((xmlNodePtr) ctxt->context->doc);
		return(ctxt->context->node->parent);
            case XML_ATTRIBUTE_NODE: {
		xmlAttrPtr cur = (xmlAttrPtr) ctxt->context->node;

		return(cur->parent);
	    }
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_SGML_ENABLED
	    case XML_SGML_DOCUMENT_NODE:
#endif
                return(NULL);
	    case XML_NAMESPACE_DECL:
		/*
		 * TODO !!! may require extending struct _xmlNs with
		 * parent field
		 * C.f. Infoset case...
		 */
                return(NULL);
	}
	return(NULL);
    }
    if (cur == ctxt->context->doc->children)
	return((xmlNodePtr) ctxt->context->doc);
    if (cur == (xmlNodePtr) ctxt->context->doc)
	return(NULL);
    switch (cur->type) {
	case XML_ELEMENT_NODE:
	case XML_TEXT_NODE:
	case XML_CDATA_SECTION_NODE:
	case XML_ENTITY_REF_NODE:
	case XML_ENTITY_NODE:
	case XML_PI_NODE:
	case XML_COMMENT_NODE:
	case XML_NOTATION_NODE:
	case XML_DTD_NODE:
        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
	case XML_XINCLUDE_START:
	case XML_XINCLUDE_END:
	    return(cur->parent);
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr att = (xmlAttrPtr) ctxt->context->node;

	    return(att->parent);
	}
	case XML_DOCUMENT_NODE:
	case XML_DOCUMENT_TYPE_NODE:
	case XML_DOCUMENT_FRAG_NODE:
	case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_SGML_ENABLED
	case XML_SGML_DOCUMENT_NODE:
#endif
	    return(NULL);
	case XML_NAMESPACE_DECL:
	    /*
	     * TODO !!! may require extending struct _xmlNs with
	     * parent field
	     * C.f. Infoset case...
	     */
	    return(NULL);
    }
    return(NULL);
}

/**
 * xmlXPathNextAncestorOrSelf:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "ancestor-or-self" direction
 * he ancestor-or-self axis contains the context node and ancestors of
 * the context node in reverse document order; thus the context node is
 * the first node on the axis, and the context node's parent the second;
 * parent here is defined the same as with the parent axis.
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextAncestorOrSelf(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (cur == NULL)
        return(ctxt->context->node);
    return(xmlXPathNextAncestor(ctxt, cur));
}

/**
 * xmlXPathNextFollowingSibling:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "following-sibling" direction
 * The following-sibling axis contains the following siblings of the context
 * node in document order.
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextFollowingSibling(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if ((ctxt->context->node->type == XML_ATTRIBUTE_NODE) ||
	(ctxt->context->node->type == XML_NAMESPACE_DECL))
	return(NULL);
    if (cur == (xmlNodePtr) ctxt->context->doc)
        return(NULL);
    if (cur == NULL)
        return(ctxt->context->node->next);
    return(cur->next);
}

/**
 * xmlXPathNextPrecedingSibling:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "preceding-sibling" direction
 * The preceding-sibling axis contains the preceding siblings of the context
 * node in reverse document order; the first preceding sibling is first on the
 * axis; the sibling preceding that node is the second on the axis and so on.
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextPrecedingSibling(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if ((ctxt->context->node->type == XML_ATTRIBUTE_NODE) ||
	(ctxt->context->node->type == XML_NAMESPACE_DECL))
	return(NULL);
    if (cur == (xmlNodePtr) ctxt->context->doc)
        return(NULL);
    if (cur == NULL)
        return(ctxt->context->node->prev);
    return(cur->prev);
}

/**
 * xmlXPathNextFollowing:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "following" direction
 * The following axis contains all nodes in the same document as the context
 * node that are after the context node in document order, excluding any
 * descendants and excluding attribute nodes and namespace nodes; the nodes
 * are ordered in document order
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextFollowing(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (cur != NULL && cur->children != NULL)
        return cur->children ;
    if (cur == NULL) cur = ctxt->context->node;
    if (cur == NULL) return(NULL) ; /* ERROR */
    if (cur->next != NULL) return(cur->next) ;
    do {
        cur = cur->parent;
        if (cur == NULL) return(NULL);
        if (cur == (xmlNodePtr) ctxt->context->doc) return(NULL);
        if (cur->next != NULL) return(cur->next);
    } while (cur != NULL);
    return(cur);
}

/*
 * xmlXPathIsAncestor:
 * @ancestor:  the ancestor node
 * @node:  the current node
 *
 * Check that @ancestor is a @node's ancestor
 *
 * returns 1 if @ancestor is a @node's ancestor, 0 otherwise.
 */
static int
xmlXPathIsAncestor(xmlNodePtr ancestor, xmlNodePtr node) {
    if ((ancestor == NULL) || (node == NULL)) return(0);
    /* nodes need to be in the same document */
    if (ancestor->doc != node->doc) return(0);
    /* avoid searching if ancestor or node is the root node */
    if (ancestor == (xmlNodePtr) node->doc) return(1);
    if (node == (xmlNodePtr) ancestor->doc) return(0);
    while (node->parent != NULL) {
        if (node->parent == ancestor)
            return(1);
	node = node->parent;
    }
    return(0);
}

/**
 * xmlXPathNextPreceding:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "preceding" direction
 * the preceding axis contains all nodes in the same document as the context
 * node that are before the context node in document order, excluding any
 * ancestors and excluding attribute nodes and namespace nodes; the nodes are
 * ordered in reverse document order
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextPreceding(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (cur == NULL)
        cur = ctxt->context->node ;
    do {
        if (cur->prev != NULL) {
            for (cur = cur->prev ; cur->last != NULL ; cur = cur->last)
                ;
            return(cur) ;
        }

        cur = cur->parent;
        if (cur == NULL) return(NULL);
        if (cur == ctxt->context->doc->children) return(NULL);
    } while (xmlXPathIsAncestor(cur, ctxt->context->node));
    return(cur);
}

/**
 * xmlXPathNextNamespace:
 * @ctxt:  the XPath Parser context
 * @cur:  the current attribute in the traversal
 *
 * Traversal function for the "namespace" direction
 * the namespace axis contains the namespace nodes of the context node;
 * the order of nodes on this axis is implementation-defined; the axis will
 * be empty unless the context node is an element
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextNamespace(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (ctxt->context->node->type != XML_ELEMENT_NODE) return(NULL);
    if ((cur == NULL) || (ctxt->context->namespaces == NULL)) {
        if (ctxt->context->namespaces != NULL)
	    xmlFree(ctxt->context->namespaces);
	ctxt->context->namespaces = 
	    xmlGetNsList(ctxt->context->doc, ctxt->context->node);
	if (ctxt->context->namespaces == NULL) return(NULL);
	ctxt->context->nsNr = 0;
    }
    return((xmlNodePtr)ctxt->context->namespaces[ctxt->context->nsNr++]);
}

/**
 * xmlXPathNextAttribute:
 * @ctxt:  the XPath Parser context
 * @cur:  the current attribute in the traversal
 *
 * Traversal function for the "attribute" direction
 * TODO: support DTD inherited default attributes
 *
 * Returns the next element following that axis
 */
xmlNodePtr
xmlXPathNextAttribute(xmlXPathParserContextPtr ctxt, xmlNodePtr cur) {
    if (ctxt->context->node->type != XML_ELEMENT_NODE) return(NULL);
    if (cur == NULL) {
        if (ctxt->context->node == (xmlNodePtr) ctxt->context->doc)
	    return(NULL);
        return((xmlNodePtr)ctxt->context->node->properties);
    }
    return((xmlNodePtr)cur->next);
}

/************************************************************************
 *									*
 *		NodeTest Functions					*
 *									*
 ************************************************************************/

typedef enum {
    NODE_TEST_NONE = 0,
    NODE_TEST_TYPE = 1,
    NODE_TEST_PI = 2,
    NODE_TEST_ALL = 3,
    NODE_TEST_NS = 4,
    NODE_TEST_NAME = 5
} xmlXPathTestVal;

typedef enum {
    NODE_TYPE_NODE = 0,
    NODE_TYPE_COMMENT = XML_COMMENT_NODE,
    NODE_TYPE_TEXT = XML_TEXT_NODE,
    NODE_TYPE_PI = XML_PI_NODE
} xmlXPathTypeVal;

#define IS_FUNCTION			200

/**
 * xmlXPathNodeCollectAndTest:
 * @ctxt:  the XPath Parser context
 * @axis:  the XPath axis
 * @test:  the XPath test
 * @type:  the XPath type
 * @prefix:  the namesapce prefix if any
 * @name:  the name used in the search if any
 *
 * This is the function implementing a step: based on the current list
 * of nodes, it builds up a new list, looking at all nodes under that
 * axis and selecting them.
 *
 * Returns the new NodeSet resulting from the search.
 */
void
xmlXPathNodeCollectAndTest(xmlXPathParserContextPtr ctxt, xmlXPathAxisVal axis,
                           xmlXPathTestVal test, xmlXPathTypeVal type,
			   const xmlChar *prefix, const xmlChar *name) {
#ifdef DEBUG_STEP
    int n = 0, t = 0;
#endif
    int i;
    xmlNodeSetPtr ret;
    xmlXPathTraversalFunction next = NULL;
    void (*addNode)(xmlNodeSetPtr, xmlNodePtr);
    xmlNodePtr cur = NULL;
    xmlXPathObjectPtr obj;
    xmlNodeSetPtr nodelist;
    xmlNodePtr tmp;

    CHECK_TYPE(XPATH_NODESET);
    obj = valuePop(ctxt);
    addNode = xmlXPathNodeSetAdd;

#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext,
	    "new step : ");
#endif
    switch (axis) {
        case AXIS_ANCESTOR:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'ancestors' ");
#endif
	    next = xmlXPathNextAncestor; break;
        case AXIS_ANCESTOR_OR_SELF:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'ancestors-or-self' ");
#endif
	    next = xmlXPathNextAncestorOrSelf; break;
        case AXIS_ATTRIBUTE:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'attributes' ");
#endif
	    next = xmlXPathNextAttribute; break;
	    break;
        case AXIS_CHILD:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'child' ");
#endif
	    next = xmlXPathNextChild; break;
        case AXIS_DESCENDANT:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'descendant' ");
#endif
	    next = xmlXPathNextDescendant; break;
        case AXIS_DESCENDANT_OR_SELF:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'descendant-or-self' ");
#endif
	    next = xmlXPathNextDescendantOrSelf; break;
        case AXIS_FOLLOWING:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'following' ");
#endif
	    next = xmlXPathNextFollowing; break;
        case AXIS_FOLLOWING_SIBLING:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'following-siblings' ");
#endif
	    next = xmlXPathNextFollowingSibling; break;
        case AXIS_NAMESPACE:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'namespace' ");
#endif
	    next = (xmlXPathTraversalFunction) xmlXPathNextNamespace; break;
	    break;
        case AXIS_PARENT:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'parent' ");
#endif
	    next = xmlXPathNextParent; break;
        case AXIS_PRECEDING:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'preceding' ");
#endif
	    next = xmlXPathNextPreceding; break;
        case AXIS_PRECEDING_SIBLING:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'preceding-sibling' ");
#endif
	    next = xmlXPathNextPrecedingSibling; break;
        case AXIS_SELF:
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "axis 'self' ");
#endif
	    next = xmlXPathNextSelf; break;
    }
    if (next == NULL)
	return;

    nodelist = obj->nodesetval;
    if ((nodelist != NULL) &&
	(nodelist->nodeNr <= 1))
	addNode = xmlXPathNodeSetAddUnique;
    else
	addNode = xmlXPathNodeSetAdd;
    ret = xmlXPathNodeSetCreate(NULL);
#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext,
	    " context contains %d nodes\n",
            nodelist->nodeNr);
    switch (test) {
	case NODE_TEST_NODE:
	    xmlGenericError(xmlGenericErrorContext,
		    "           searching all nodes\n");
	    break;
	case NODE_TEST_NONE:
	    xmlGenericError(xmlGenericErrorContext,
		    "           searching for none !!!\n");
	    break;
	case NODE_TEST_TYPE:
	    xmlGenericError(xmlGenericErrorContext,
		    "           searching for type %d\n", type);
	    break;
	case NODE_TEST_PI:
	    xmlGenericError(xmlGenericErrorContext,
		    "           searching for PI !!!\n");
	    break;
	case NODE_TEST_ALL:
	    xmlGenericError(xmlGenericErrorContext,
		    "           searching for *\n");
	    break;
	case NODE_TEST_NS:
	    xmlGenericError(xmlGenericErrorContext,
		    "           searching for namespace %s\n",
	            prefix);
	    break;
	case NODE_TEST_NAME:
	    xmlGenericError(xmlGenericErrorContext,
		    "           searching for name %s\n", name);
	    if (prefix != NULL)
		xmlGenericError(xmlGenericErrorContext,
			"           with namespace %s\n",
		        prefix);
	    break;
    }
    xmlGenericError(xmlGenericErrorContext, "Testing : ");
#endif
    /*
     * 2.3 Node Tests
     *  - For the attribute axis, the principal node type is attribute. 
     *  - For the namespace axis, the principal node type is namespace. 
     *  - For other axes, the principal node type is element. 
     *
     * A node test * is true for any node of the
     * principal node type. For example, child::* willi
     * select all element children of the context node
     */
    tmp = ctxt->context->node;
    for (i = 0;i < nodelist->nodeNr; i++) {
        ctxt->context->node = nodelist->nodeTab[i];

	cur = NULL;
	do {
	    cur = next(ctxt, cur);
	    if (cur == NULL) break;
#ifdef DEBUG_STEP
            t++;
            xmlGenericError(xmlGenericErrorContext, " %s", cur->name);
#endif
	    switch (test) {
                case NODE_TEST_NONE:
		    ctxt->context->node = tmp;
		    STRANGE
		    return;
                case NODE_TEST_TYPE:
		    if ((cur->type == type) ||
		        ((type == NODE_TYPE_NODE) && 
			 ((cur->type == XML_DOCUMENT_NODE) ||
			  (cur->type == XML_HTML_DOCUMENT_NODE) ||
			  (cur->type == XML_ELEMENT_NODE) ||
			  (cur->type == XML_PI_NODE) ||
			  (cur->type == XML_COMMENT_NODE) ||
			  (cur->type == XML_CDATA_SECTION_NODE) ||
			  (cur->type == XML_TEXT_NODE)))) {
#ifdef DEBUG_STEP
                        n++;
#endif
		        addNode(ret, cur);
		    }
		    break;
                case NODE_TEST_PI:
		    if (cur->type == XML_PI_NODE) {
		        if ((name != NULL) &&
			    (!xmlStrEqual(name, cur->name)))
			    break;
#ifdef DEBUG_STEP
			n++;
#endif
			addNode(ret, cur);
		    }
		    break;
                case NODE_TEST_ALL:
		    if (axis == AXIS_ATTRIBUTE) {
			if (cur->type == XML_ATTRIBUTE_NODE) {
#ifdef DEBUG_STEP
			    n++;
#endif
			    addNode(ret, cur);
			}
		    } else if (axis == AXIS_NAMESPACE) {
			if (cur->type == XML_NAMESPACE_DECL) {
#ifdef DEBUG_STEP
			    n++;
#endif
			    addNode(ret, cur);
			}
		    } else {
			if ((cur->type == XML_ELEMENT_NODE) ||
			    (cur->type == XML_DOCUMENT_NODE) ||
			    (cur->type == XML_HTML_DOCUMENT_NODE)) {
			    if (prefix == NULL) {
#ifdef DEBUG_STEP
				n++;
#endif
				addNode(ret, cur);
			    } else if ((cur->ns != NULL) && 
				(xmlStrEqual(prefix,
					     cur->ns->href))) {
#ifdef DEBUG_STEP
				n++;
#endif
				addNode(ret, cur);
			    }
			}
		    }
		    break;
                case NODE_TEST_NS: {
		    TODO;
		    break;
		}
                case NODE_TEST_NAME:
		    switch (cur->type) {
		        case XML_ELEMENT_NODE:
			    if (xmlStrEqual(name, cur->name)) {
				if (prefix == NULL) {
				    if ((cur->ns == NULL) ||
					(cur->ns->prefix == NULL)) {
#ifdef DEBUG_STEP
					n++;
#endif
					addNode(ret, cur);
				    }
				} else {
				    if ((cur->ns != NULL) && 
				        (xmlStrEqual(prefix,
						     cur->ns->href))) {
#ifdef DEBUG_STEP
					n++;
#endif
					addNode(ret, cur);
				    }
				}
			    }
			    break;
		        case XML_ATTRIBUTE_NODE: {
			    xmlAttrPtr attr = (xmlAttrPtr) cur;
			    if (xmlStrEqual(name, attr->name)) {
				if (prefix == NULL) {
				    if ((attr->ns == NULL) ||
					(attr->ns->prefix == NULL)) {
#ifdef DEBUG_STEP
					n++;
#endif
					addNode(ret, (xmlNodePtr) attr);
				    }
				} else {
				    if ((attr->ns != NULL) && 
				        (xmlStrEqual(prefix,
						     attr->ns->href))) {
#ifdef DEBUG_STEP
					n++;
#endif
					addNode(ret, (xmlNodePtr) attr);
				    }
				}
			    }
			    break;
			}
			case XML_NAMESPACE_DECL: {
			    TODO;
			    break;
			}
			default:
			    break;
		    }
	            break;
	    }
	} while (cur != NULL);
    }
    ctxt->context->node = tmp;
#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext,
            "\nExamined %d nodes, found %d nodes at that step\n", t, n);
#endif
    xmlXPathFreeObject(obj);
    valuePush(ctxt, xmlXPathWrapNodeSet(ret));
}


/************************************************************************
 *									*
 *		Implicit tree core function library			*
 *									*
 ************************************************************************/

/**
 * xmlXPathRoot:
 * @ctxt:  the XPath Parser context
 *
 * Initialize the context to the root of the document
 */
void
xmlXPathRoot(xmlXPathParserContextPtr ctxt) {
    ctxt->context->node = (xmlNodePtr) ctxt->context->doc;
    valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
}

/************************************************************************
 *									*
 *		The explicit core function library			*
 *http://www.w3.org/Style/XSL/Group/1999/07/xpath-19990705.html#corelib	*
 *									*
 ************************************************************************/


/**
 * xmlXPathLastFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the last() XPath function
 *    number last()
 * The last function returns the number of nodes in the context node list.
 */
void
xmlXPathLastFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);
    if (ctxt->context->contextSize >= 0) {
	valuePush(ctxt, xmlXPathNewFloat((double) ctxt->context->contextSize));
#ifdef DEBUG_EXPR
	xmlGenericError(xmlGenericErrorContext,
		"last() : %d\n", ctxt->context->contextSize);
#endif
    } else {
	XP_ERROR(XPATH_INVALID_CTXT_SIZE);
    }
}

/**
 * xmlXPathPositionFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the position() XPath function
 *    number position()
 * The position function returns the position of the context node in the
 * context node list. The first position is 1, and so the last positionr
 * will be equal to last().
 */
void
xmlXPathPositionFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);
    if (ctxt->context->proximityPosition >= 0) {
	valuePush(ctxt,
	      xmlXPathNewFloat((double) ctxt->context->proximityPosition));
#ifdef DEBUG_EXPR
	xmlGenericError(xmlGenericErrorContext, "position() : %d\n",
		ctxt->context->proximityPosition);
#endif
    } else {
	XP_ERROR(XPATH_INVALID_CTXT_POSITION);
    }
}

/**
 * xmlXPathCountFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the count() XPath function
 *    number count(node-set)
 */
void
xmlXPathCountFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    CHECK_ARITY(1);
    if ((ctxt->value == NULL) || 
	((ctxt->value->type != XPATH_NODESET) &&
	 (ctxt->value->type != XPATH_XSLT_TREE)))
	XP_ERROR(XPATH_INVALID_TYPE);
    cur = valuePop(ctxt);

    valuePush(ctxt, xmlXPathNewFloat((double) cur->nodesetval->nodeNr));
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathIdFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the id() XPath function
 *    node-set id(object)
 * The id function selects elements by their unique ID
 * (see [5.2.1 Unique IDs]). When the argument to id is of type node-set,
 * then the result is the union of the result of applying id to the
 * string value of each of the nodes in the argument node-set. When the
 * argument to id is of any other type, the argument is converted to a
 * string as if by a call to the string function; the string is split
 * into a whitespace-separated list of tokens (whitespace is any sequence
 * of characters matching the production S); the result is a node-set
 * containing the elements in the same document as the context node that
 * have a unique ID equal to any of the tokens in the list.
 */
void
xmlXPathIdFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    const xmlChar *tokens;
    const xmlChar *cur;
    xmlChar *ID;
    xmlAttrPtr attr;
    xmlNodePtr elem = NULL;
    xmlXPathObjectPtr ret, obj;

    CHECK_ARITY(1);
    obj = valuePop(ctxt);
    if (obj == NULL) XP_ERROR(XPATH_INVALID_OPERAND);
    if (obj->type == XPATH_NODESET) {
	xmlXPathObjectPtr newobj;
	int i;

	ret = xmlXPathNewNodeSet(NULL);

	for (i = 0; i < obj->nodesetval->nodeNr; i++) {
	    valuePush(ctxt,
		      xmlXPathNewNodeSet(obj->nodesetval->nodeTab[i]));
	    xmlXPathStringFunction(ctxt, 1);
	    xmlXPathIdFunction(ctxt, 1);
	    newobj = valuePop(ctxt);
	    ret->nodesetval = xmlXPathNodeSetMerge(ret->nodesetval,
						   newobj->nodesetval);
	    xmlXPathFreeObject(newobj);
	}

	xmlXPathFreeObject(obj);
	valuePush(ctxt, ret);
	return;
    }
    if (obj->type != XPATH_STRING) {
        valuePush(ctxt, obj);
	xmlXPathStringFunction(ctxt, 1);
	obj = valuePop(ctxt);
	if (obj->type != XPATH_STRING) {
	    xmlXPathFreeObject(obj);
	    return;
	}
    }
    tokens = obj->stringval;

    ret = xmlXPathNewNodeSet(NULL);
    valuePush(ctxt, ret);
    if (tokens == NULL) {
	xmlXPathFreeObject(obj);
        return;
    }

    cur = tokens;
    
    while (IS_BLANK(*cur)) cur++;
    while (*cur != 0) {
	while ((IS_LETTER(*cur)) || (IS_DIGIT(*cur)) ||
	       (*cur == '.') || (*cur == '-') ||
	       (*cur == '_') || (*cur == ':') || 
	       (IS_COMBINING(*cur)) ||
	       (IS_EXTENDER(*cur)))
	       cur++;

	if ((!IS_BLANK(*cur)) && (*cur != 0)) break;

        ID = xmlStrndup(tokens, cur - tokens);
	attr = xmlGetID(ctxt->context->doc, ID);
	if (attr != NULL) {
	    elem = attr->parent;
            xmlXPathNodeSetAdd(ret->nodesetval, elem);
        }
	if (ID != NULL)
	    xmlFree(ID);

	while (IS_BLANK(*cur)) cur++;
	tokens = cur;
    }
    xmlXPathFreeObject(obj);
    return;
}

/**
 * xmlXPathLocalNameFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the local-name() XPath function
 *    string local-name(node-set?)
 * The local-name function returns a string containing the local part
 * of the name of the node in the argument node-set that is first in
 * document order. If the node-set is empty or the first node has no
 * name, an empty string is returned. If the argument is omitted it
 * defaults to the context node.
 */
void
xmlXPathLocalNameFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    if (nargs == 0) {
	valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
	nargs = 1;
    }

    CHECK_ARITY(1);
    if ((ctxt->value == NULL) || 
	((ctxt->value->type != XPATH_NODESET) &&
	 (ctxt->value->type != XPATH_XSLT_TREE)))
	XP_ERROR(XPATH_INVALID_TYPE);
    cur = valuePop(ctxt);

    if (cur->nodesetval->nodeNr == 0) {
	valuePush(ctxt, xmlXPathNewCString(""));
    } else {
	int i = 0; /* Should be first in document order !!!!! */
	switch (cur->nodesetval->nodeTab[i]->type) {
	case XML_ELEMENT_NODE:
	case XML_ATTRIBUTE_NODE:
	case XML_PI_NODE:
	    valuePush(ctxt,
		      xmlXPathNewString(cur->nodesetval->nodeTab[i]->name));
	    break;
	case XML_NAMESPACE_DECL:
	    valuePush(ctxt, xmlXPathNewString(
			((xmlNsPtr)cur->nodesetval->nodeTab[i])->prefix));
	    break;
	default:
	    valuePush(ctxt, xmlXPathNewCString(""));
	}
    }
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathNamespaceURIFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the namespace-uri() XPath function
 *    string namespace-uri(node-set?)
 * The namespace-uri function returns a string containing the
 * namespace URI of the expanded name of the node in the argument
 * node-set that is first in document order. If the node-set is empty,
 * the first node has no name, or the expanded name has no namespace
 * URI, an empty string is returned. If the argument is omitted it
 * defaults to the context node.
 */
void
xmlXPathNamespaceURIFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    if (nargs == 0) {
        valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
	nargs = 1;
    }
    CHECK_ARITY(1);
    if ((ctxt->value == NULL) || 
	((ctxt->value->type != XPATH_NODESET) &&
	 (ctxt->value->type != XPATH_XSLT_TREE)))
	XP_ERROR(XPATH_INVALID_TYPE);
    cur = valuePop(ctxt);

    if (cur->nodesetval->nodeNr == 0) {
	valuePush(ctxt, xmlXPathNewCString(""));
    } else {
	int i = 0; /* Should be first in document order !!!!! */
	switch (cur->nodesetval->nodeTab[i]->type) {
	case XML_ELEMENT_NODE:
	case XML_ATTRIBUTE_NODE:
	    if (cur->nodesetval->nodeTab[i]->ns == NULL)
		valuePush(ctxt, xmlXPathNewCString(""));
	    else
		valuePush(ctxt, xmlXPathNewString(
			  cur->nodesetval->nodeTab[i]->ns->href));
	    break;
	default:
	    valuePush(ctxt, xmlXPathNewCString(""));
	}
    }
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathNameFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the name() XPath function
 *    string name(node-set?)
 * The name function returns a string containing a QName representing
 * the name of the node in the argument node-set that is first in documenti
 * order. The QName must represent the name with respect to the namespace
 * declarations in effect on the node whose name is being represented.
 * Typically, this will be the form in which the name occurred in the XML
 * source. This need not be the case if there are namespace declarations
 * in effect on the node that associate multiple prefixes with the same
 * namespace. However, an implementation may include information about
 * the original prefix in its representation of nodes; in this case, an
 * implementation can ensure that the returned string is always the same
 * as the QName used in the XML source. If the argument it omitted it
 * defaults to the context node.
 * Libxml keep the original prefix so the "real qualified name" used is
 * returned.
 */
void
xmlXPathNameFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    if (nargs == 0) {
	valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
	nargs = 1;
    }

    CHECK_ARITY(1);
    if ((ctxt->value == NULL) || 
	((ctxt->value->type != XPATH_NODESET) &&
	 (ctxt->value->type != XPATH_XSLT_TREE)))
	XP_ERROR(XPATH_INVALID_TYPE);
    cur = valuePop(ctxt);

    if (cur->nodesetval->nodeNr == 0) {
	valuePush(ctxt, xmlXPathNewCString(""));
    } else {
	int i = 0; /* Should be first in document order !!!!! */

	switch (cur->nodesetval->nodeTab[i]->type) {
	case XML_ELEMENT_NODE:
	case XML_ATTRIBUTE_NODE:
	    if (cur->nodesetval->nodeTab[i]->ns == NULL)
		valuePush(ctxt, xmlXPathNewString(
			    cur->nodesetval->nodeTab[i]->name));
	    
	    else {
		char name[2000];
#ifdef HAVE_SNPRINTF
		snprintf(name, sizeof(name), "%s:%s", 
			 (char *) cur->nodesetval->nodeTab[i]->ns->prefix,
			 (char *) cur->nodesetval->nodeTab[i]->name);
#else
		sprintf(name, "%s:%s", 
			(char *) cur->nodesetval->nodeTab[i]->ns->prefix,
			(char *) cur->nodesetval->nodeTab[i]->name);
#endif
		name[sizeof(name) - 1] = 0;
		valuePush(ctxt, xmlXPathNewCString(name));
	    }
	    break;
	default:
	    valuePush(ctxt,
		      xmlXPathNewNodeSet(cur->nodesetval->nodeTab[i]));
	    xmlXPathLocalNameFunction(ctxt, 1);
	}
    }
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathStringFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the string() XPath function
 *    string string(object?)
 * he string function converts an object to a string as follows:
 *    - A node-set is converted to a string by returning the value of
 *      the node in the node-set that is first in document order.
 *      If the node-set is empty, an empty string is returned.
 *    - A number is converted to a string as follows
 *      + NaN is converted to the string NaN 
 *      + positive zero is converted to the string 0 
 *      + negative zero is converted to the string 0 
 *      + positive infinity is converted to the string Infinity 
 *      + negative infinity is converted to the string -Infinity 
 *      + if the number is an integer, the number is represented in
 *        decimal form as a Number with no decimal point and no leading
 *        zeros, preceded by a minus sign (-) if the number is negative
 *      + otherwise, the number is represented in decimal form as a
 *        Number including a decimal point with at least one digit
 *        before the decimal point and at least one digit after the
 *        decimal point, preceded by a minus sign (-) if the number
 *        is negative; there must be no leading zeros before the decimal
 *        point apart possibly from the one required digit immediatelyi
 *        before the decimal point; beyond the one required digit
 *        after the decimal point there must be as many, but only as
 *        many, more digits as are needed to uniquely distinguish the
 *        number from all other IEEE 754 numeric values.
 *    - The boolean false value is converted to the string false.
 *      The boolean true value is converted to the string true.
 *
 * If the argument is omitted, it defaults to a node-set with the
 * context node as its only member.
 */
void
xmlXPathStringFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    if (nargs == 0) {
	valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
	nargs = 1;
    }

    CHECK_ARITY(1);
    cur = valuePop(ctxt);
    if (cur == NULL) XP_ERROR(XPATH_INVALID_OPERAND);
    switch (cur->type) {
	case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
	    xmlGenericError(xmlGenericErrorContext, "String: undefined\n");
#endif
	    valuePush(ctxt, xmlXPathNewCString(""));
	    break;
        case XPATH_XSLT_TREE:
        case XPATH_NODESET:
	    if (cur->nodesetval == NULL)
		valuePush(ctxt, xmlXPathNewCString(""));
	    else if (cur->nodesetval->nodeNr == 0) {
		valuePush(ctxt, xmlXPathNewCString(""));
	    } else {
		xmlChar *res;
	        int i = 0; /* Should be first in document order !!!!! */
		res = xmlNodeGetContent(cur->nodesetval->nodeTab[i]);
		valuePush(ctxt, xmlXPathNewString(res));
		if (res != NULL)
		    xmlFree(res);
	    }
	    xmlXPathFreeObject(cur);
	    return;
	case XPATH_STRING:
	    valuePush(ctxt, cur);
	    return;
        case XPATH_BOOLEAN:
	    if (cur->boolval) valuePush(ctxt, xmlXPathNewCString("true"));
	    else valuePush(ctxt, xmlXPathNewCString("false"));
	    xmlXPathFreeObject(cur);
	    return;
	case XPATH_NUMBER: {
	    char buf[100];

	    xmlXPathFormatNumber(cur->floatval, buf, sizeof(buf));
	    valuePush(ctxt, xmlXPathNewCString(buf));
	    xmlXPathFreeObject(cur);
	    return;
	}
	case XPATH_USERS:
	case XPATH_POINT:
	case XPATH_RANGE:
	case XPATH_LOCATIONSET:
	    TODO
	    valuePush(ctxt, xmlXPathNewCString(""));
	    break;
    }
    STRANGE
}

/**
 * xmlXPathStringLengthFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the string-length() XPath function
 *    number string-length(string?)
 * The string-length returns the number of characters in the string
 * (see [3.6 Strings]). If the argument is omitted, it defaults to
 * the context node converted to a string, in other words the value
 * of the context node.
 */
void
xmlXPathStringLengthFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    if (nargs == 0) {
	if (ctxt->context->node == NULL) {
	    valuePush(ctxt, xmlXPathNewFloat(0));
	} else {
	    xmlChar *content;

	    content = xmlNodeGetContent(ctxt->context->node);
	    valuePush(ctxt, xmlXPathNewFloat(xmlStrlen(content)));
	    xmlFree(content);
	}
	return;
    }
    CHECK_ARITY(1);
    CAST_TO_STRING;
    CHECK_TYPE(XPATH_STRING);
    cur = valuePop(ctxt);
    valuePush(ctxt, xmlXPathNewFloat(xmlStrlen(cur->stringval)));
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathConcatFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the concat() XPath function
 *    string concat(string, string, string*)
 * The concat function returns the concatenation of its arguments.
 */
void
xmlXPathConcatFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur, newobj;
    xmlChar *tmp;

    if (nargs < 2) {
	CHECK_ARITY(2);
    }

    CAST_TO_STRING;
    cur = valuePop(ctxt);
    if ((cur == NULL) || (cur->type != XPATH_STRING)) {
        xmlXPathFreeObject(cur);
	return;
    }
    nargs--;

    while (nargs > 0) {
	CAST_TO_STRING;
	newobj = valuePop(ctxt);
	if ((newobj == NULL) || (newobj->type != XPATH_STRING)) {
	    xmlXPathFreeObject(newobj);
	    xmlXPathFreeObject(cur);
	    XP_ERROR(XPATH_INVALID_TYPE);
	}
	tmp = xmlStrcat(newobj->stringval, cur->stringval);
	newobj->stringval = cur->stringval;
	cur->stringval = tmp;

	xmlXPathFreeObject(newobj);
	nargs--;
    }
    valuePush(ctxt, cur);
}

/**
 * xmlXPathContainsFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the contains() XPath function
 *    boolean contains(string, string)
 * The contains function returns true if the first argument string
 * contains the second argument string, and otherwise returns false.
 */
void
xmlXPathContainsFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr hay, needle;

    CHECK_ARITY(2);
    CAST_TO_STRING;
    CHECK_TYPE(XPATH_STRING);
    needle = valuePop(ctxt);
    CAST_TO_STRING;
    hay = valuePop(ctxt);
    if ((hay == NULL) || (hay->type != XPATH_STRING)) {
        xmlXPathFreeObject(hay);
        xmlXPathFreeObject(needle);
	XP_ERROR(XPATH_INVALID_TYPE);
    }
    if (xmlStrstr(hay->stringval, needle->stringval))
        valuePush(ctxt, xmlXPathNewBoolean(1));
    else
        valuePush(ctxt, xmlXPathNewBoolean(0));
    xmlXPathFreeObject(hay);
    xmlXPathFreeObject(needle);
}

/**
 * xmlXPathStartsWithFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the starts-with() XPath function
 *    boolean starts-with(string, string)
 * The starts-with function returns true if the first argument string
 * starts with the second argument string, and otherwise returns false.
 */
void
xmlXPathStartsWithFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr hay, needle;
    int n;

    CHECK_ARITY(2);
    CAST_TO_STRING;
    CHECK_TYPE(XPATH_STRING);
    needle = valuePop(ctxt);
    CAST_TO_STRING;
    hay = valuePop(ctxt);
    if ((hay == NULL) || (hay->type != XPATH_STRING)) {
        xmlXPathFreeObject(hay);
        xmlXPathFreeObject(needle);
	XP_ERROR(XPATH_INVALID_TYPE);
    }
    n = xmlStrlen(needle->stringval);
    if (xmlStrncmp(hay->stringval, needle->stringval, n))
        valuePush(ctxt, xmlXPathNewBoolean(0));
    else
        valuePush(ctxt, xmlXPathNewBoolean(1));
    xmlXPathFreeObject(hay);
    xmlXPathFreeObject(needle);
}

/**
 * xmlXPathSubstringFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the substring() XPath function
 *    string substring(string, number, number?)
 * The substring function returns the substring of the first argument
 * starting at the position specified in the second argument with
 * length specified in the third argument. For example,
 * substring("12345",2,3) returns "234". If the third argument is not
 * specified, it returns the substring starting at the position specified
 * in the second argument and continuing to the end of the string. For
 * example, substring("12345",2) returns "2345".  More precisely, each
 * character in the string (see [3.6 Strings]) is considered to have a
 * numeric position: the position of the first character is 1, the position
 * of the second character is 2 and so on. The returned substring contains
 * those characters for which the position of the character is greater than
 * or equal to the second argument and, if the third argument is specified,
 * less than the sum of the second and third arguments; the comparisons
 * and addition used for the above follow the standard IEEE 754 rules. Thus:
 *  - substring("12345", 1.5, 2.6) returns "234" 
 *  - substring("12345", 0, 3) returns "12" 
 *  - substring("12345", 0 div 0, 3) returns "" 
 *  - substring("12345", 1, 0 div 0) returns "" 
 *  - substring("12345", -42, 1 div 0) returns "12345" 
 *  - substring("12345", -1 div 0, 1 div 0) returns "" 
 */
void
xmlXPathSubstringFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr str, start, len;
    double le, in;
    int i, l;
    xmlChar *ret;

    /* 
     * Conformance needs to be checked !!!!!
     */
    if (nargs < 2) {
	CHECK_ARITY(2);
    }
    if (nargs > 3) {
	CHECK_ARITY(3);
    }
    if (nargs == 3) {
	CAST_TO_NUMBER;
	CHECK_TYPE(XPATH_NUMBER);
	len = valuePop(ctxt);
	le = len->floatval;
        xmlXPathFreeObject(len);
    } else {
	le = 2000000000;
    }
    CAST_TO_NUMBER;
    CHECK_TYPE(XPATH_NUMBER);
    start = valuePop(ctxt);
    in = start->floatval;
    xmlXPathFreeObject(start);
    CAST_TO_STRING;
    CHECK_TYPE(XPATH_STRING);
    str = valuePop(ctxt);
    le += in;

    /* integer index of the first char */
    i = (int) in;
    if (((double)i) != in) i++;
    
    /* integer index of the last char */
    l = (int) le;
    if (((double)l) != le) l++;

    /* back to a zero based len */
    i--;
    l--;

    /* check against the string len */
    if (l > 1024) {
        l = xmlStrlen(str->stringval);
    }
    if (i < 0) {
        i = 0;
    }

    /* number of chars to copy */
    l -= i;

    ret = xmlStrsub(str->stringval, i, l);
    if (ret == NULL)
	valuePush(ctxt, xmlXPathNewCString(""));
    else {
	valuePush(ctxt, xmlXPathNewString(ret));
	xmlFree(ret);
    }
    xmlXPathFreeObject(str);
}

/**
 * xmlXPathSubstringBeforeFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the substring-before() XPath function
 *    string substring-before(string, string)
 * The substring-before function returns the substring of the first
 * argument string that precedes the first occurrence of the second
 * argument string in the first argument string, or the empty string
 * if the first argument string does not contain the second argument
 * string. For example, substring-before("1999/04/01","/") returns 1999.
 */
void
xmlXPathSubstringBeforeFunction(xmlXPathParserContextPtr ctxt, int nargs) {
  xmlXPathObjectPtr str;
  xmlXPathObjectPtr find;
  xmlBufferPtr target;
  const xmlChar *point;
  int offset;
  
  CHECK_ARITY(2);
  CAST_TO_STRING;
  find = valuePop(ctxt);
  CAST_TO_STRING;
  str = valuePop(ctxt);
  
  target = xmlBufferCreate();
  if (target) {
    point = xmlStrstr(str->stringval, find->stringval);
    if (point) {
      offset = (int)(point - str->stringval);
      xmlBufferAdd(target, str->stringval, offset);
    }
    valuePush(ctxt, xmlXPathNewString(xmlBufferContent(target)));
    xmlBufferFree(target);
  }
  
  xmlXPathFreeObject(str);
  xmlXPathFreeObject(find);
}

/**
 * xmlXPathSubstringAfterFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the substring-after() XPath function
 *    string substring-after(string, string)
 * The substring-after function returns the substring of the first
 * argument string that follows the first occurrence of the second
 * argument string in the first argument string, or the empty stringi
 * if the first argument string does not contain the second argument
 * string. For example, substring-after("1999/04/01","/") returns 04/01,
 * and substring-after("1999/04/01","19") returns 99/04/01.
 */
void
xmlXPathSubstringAfterFunction(xmlXPathParserContextPtr ctxt, int nargs) {
  xmlXPathObjectPtr str;
  xmlXPathObjectPtr find;
  xmlBufferPtr target;
  const xmlChar *point;
  int offset;
  
  CHECK_ARITY(2);
  CAST_TO_STRING;
  find = valuePop(ctxt);
  CAST_TO_STRING;
  str = valuePop(ctxt);
  
  target = xmlBufferCreate();
  if (target) {
    point = xmlStrstr(str->stringval, find->stringval);
    if (point) {
      offset = (int)(point - str->stringval) + xmlStrlen(find->stringval);
      xmlBufferAdd(target, &str->stringval[offset],
		   xmlStrlen(str->stringval) - offset);
    }
    valuePush(ctxt, xmlXPathNewString(xmlBufferContent(target)));
    xmlBufferFree(target);
  }
  
  xmlXPathFreeObject(str);
  xmlXPathFreeObject(find);
}

/**
 * xmlXPathNormalizeFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the normalize-space() XPath function
 *    string normalize-space(string?)
 * The normalize-space function returns the argument string with white
 * space normalized by stripping leading and trailing whitespace
 * and replacing sequences of whitespace characters by a single
 * space. Whitespace characters are the same allowed by the S production
 * in XML. If the argument is omitted, it defaults to the context
 * node converted to a string, in other words the value of the context node.
 */
void
xmlXPathNormalizeFunction(xmlXPathParserContextPtr ctxt, int nargs) {
  xmlXPathObjectPtr obj = NULL;
  xmlChar *source = NULL;
  xmlBufferPtr target;
  xmlChar blank;
  
  if (nargs == 0) {
    /* Use current context node */
    valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
    xmlXPathStringFunction(ctxt, 1);
    nargs = 1;
  }

  CHECK_ARITY(1);
  CAST_TO_STRING;
  CHECK_TYPE(XPATH_STRING);
  obj = valuePop(ctxt);
  source = obj->stringval;

  target = xmlBufferCreate();
  if (target && source) {
    
    /* Skip leading whitespaces */
    while (IS_BLANK(*source))
      source++;
  
    /* Collapse intermediate whitespaces, and skip trailing whitespaces */
    blank = 0;
    while (*source) {
      if (IS_BLANK(*source)) {
	blank = *source;
      } else {
	if (blank) {
	  xmlBufferAdd(target, &blank, 1);
	  blank = 0;
	}
	xmlBufferAdd(target, source, 1);
      }
      source++;
    }
  
    valuePush(ctxt, xmlXPathNewString(xmlBufferContent(target)));
    xmlBufferFree(target);
  }
  xmlXPathFreeObject(obj);
}

/**
 * xmlXPathTranslateFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the translate() XPath function
 *    string translate(string, string, string)
 * The translate function returns the first argument string with
 * occurrences of characters in the second argument string replaced
 * by the character at the corresponding position in the third argument
 * string. For example, translate("bar","abc","ABC") returns the string
 * BAr. If there is a character in the second argument string with no
 * character at a corresponding position in the third argument string
 * (because the second argument string is longer than the third argument
 * string), then occurrences of that character in the first argument
 * string are removed. For example, translate("--aaa--","abc-","ABC")
 * returns "AAA". If a character occurs more than once in second
 * argument string, then the first occurrence determines the replacement
 * character. If the third argument string is longer than the second
 * argument string, then excess characters are ignored.
 */
void
xmlXPathTranslateFunction(xmlXPathParserContextPtr ctxt, int nargs) {
  xmlXPathObjectPtr str;
  xmlXPathObjectPtr from;
  xmlXPathObjectPtr to;
  xmlBufferPtr target;
  int i, offset, max;
  xmlChar ch;
  const xmlChar *point;

  CHECK_ARITY(3);

  CAST_TO_STRING;
  to = valuePop(ctxt);
  CAST_TO_STRING;
  from = valuePop(ctxt);
  CAST_TO_STRING;
  str = valuePop(ctxt);

  target = xmlBufferCreate();
  if (target) {
    max = xmlStrlen(to->stringval);
    for (i = 0; (ch = str->stringval[i]); i++) {
      point = xmlStrchr(from->stringval, ch);
      if (point) {
	/* Warning: This may not work with UTF-8 */
	offset = (int)(point - from->stringval);
	if (offset < max)
	  xmlBufferAdd(target, &to->stringval[offset], 1);
      } else
	xmlBufferAdd(target, &ch, 1);
    }
  }
  valuePush(ctxt, xmlXPathNewString(xmlBufferContent(target)));
  xmlBufferFree(target);
  xmlXPathFreeObject(str);
  xmlXPathFreeObject(from);
  xmlXPathFreeObject(to);
}

/**
 * xmlXPathBooleanFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the boolean() XPath function
 *    boolean boolean(object)
 * he boolean function converts its argument to a boolean as follows:
 *    - a number is true if and only if it is neither positive or
 *      negative zero nor NaN
 *    - a node-set is true if and only if it is non-empty
 *    - a string is true if and only if its length is non-zero
 */
void
xmlXPathBooleanFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;
    int res = 0;

    CHECK_ARITY(1);
    cur = valuePop(ctxt);
    if (cur == NULL) XP_ERROR(XPATH_INVALID_OPERAND);
    switch (cur->type) {
        case XPATH_NODESET:
        case XPATH_XSLT_TREE:
	    if ((cur->nodesetval == NULL) ||
	        (cur->nodesetval->nodeNr == 0)) res = 0;
	    else 
	        res = 1;
	    break;
	case XPATH_STRING:
	    if ((cur->stringval == NULL) ||
	        (cur->stringval[0] == 0)) res = 0;
	    else 
	        res = 1;
	    break;
        case XPATH_BOOLEAN:
	    valuePush(ctxt, cur);
	    return;
	case XPATH_NUMBER:
	    if (cur->floatval) res = 1;
	    break;
	default:
	    STRANGE
    }
    xmlXPathFreeObject(cur);
    valuePush(ctxt, xmlXPathNewBoolean(res));
}

/**
 * xmlXPathNotFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the not() XPath function
 *    boolean not(boolean)
 * The not function returns true if its argument is false,
 * and false otherwise.
 */
void
xmlXPathNotFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(1);
    CAST_TO_BOOLEAN;
    CHECK_TYPE(XPATH_BOOLEAN);
    ctxt->value->boolval = ! ctxt->value->boolval;
}

/**
 * xmlXPathTrueFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the true() XPath function
 *    boolean true()
 */
void
xmlXPathTrueFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);
    valuePush(ctxt, xmlXPathNewBoolean(1));
}

/**
 * xmlXPathFalseFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the false() XPath function
 *    boolean false()
 */
void
xmlXPathFalseFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);
    valuePush(ctxt, xmlXPathNewBoolean(0));
}

/**
 * xmlXPathLangFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the lang() XPath function
 *    boolean lang(string)
 * The lang function returns true or false depending on whether the
 * language of the context node as specified by xml:lang attributes
 * is the same as or is a sublanguage of the language specified by
 * the argument string. The language of the context node is determined
 * by the value of the xml:lang attribute on the context node, or, if
 * the context node has no xml:lang attribute, by the value of the
 * xml:lang attribute on the nearest ancestor of the context node that
 * has an xml:lang attribute. If there is no such attribute, then lang
 * returns false. If there is such an attribute, then lang returns
 * true if the attribute value is equal to the argument ignoring case,
 * or if there is some suffix starting with - such that the attribute
 * value is equal to the argument ignoring that suffix of the attribute
 * value and ignoring case.
 */
void
xmlXPathLangFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr val;
    const xmlChar *theLang;
    const xmlChar *lang;
    int ret = 0;
    int i;

    CHECK_ARITY(1);
    CAST_TO_STRING;
    CHECK_TYPE(XPATH_STRING);
    val = valuePop(ctxt);
    lang = val->stringval;
    theLang = xmlNodeGetLang(ctxt->context->node);
    if ((theLang != NULL) && (lang != NULL)) {
        for (i = 0;lang[i] != 0;i++)
	    if (toupper(lang[i]) != toupper(theLang[i]))
	        goto not_equal;
        ret = 1;
    }
not_equal:
    xmlXPathFreeObject(val);
    valuePush(ctxt, xmlXPathNewBoolean(ret));
}

/**
 * xmlXPathNumberFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the number() XPath function
 *    number number(object?)
 */
void
xmlXPathNumberFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;
    double res;

    if (nargs == 0) {
	if (ctxt->context->node == NULL) {
	    valuePush(ctxt, xmlXPathNewFloat(0.0));
	} else {
	    xmlChar* content = xmlNodeGetContent(ctxt->context->node);

	    res = xmlXPathStringEvalNumber(content);
	    valuePush(ctxt, xmlXPathNewFloat(res));
	    xmlFree(content);
	}
	return;
    }

    CHECK_ARITY(1);
    cur = valuePop(ctxt);
    switch (cur->type) {
	case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
	    xmlGenericError(xmlGenericErrorContext, "NUMBER: undefined\n");
#endif
	    valuePush(ctxt, xmlXPathNewFloat(0.0));
	    break;
        case XPATH_XSLT_TREE:
        case XPATH_NODESET:
	    valuePush(ctxt, cur);
	    xmlXPathStringFunction(ctxt, 1);
	    cur = valuePop(ctxt);
	case XPATH_STRING:
	    res = xmlXPathStringEvalNumber(cur->stringval);
	    valuePush(ctxt, xmlXPathNewFloat(res));
	    xmlXPathFreeObject(cur);
	    return;
        case XPATH_BOOLEAN:
	    if (cur->boolval) valuePush(ctxt, xmlXPathNewFloat(1.0));
	    else valuePush(ctxt, xmlXPathNewFloat(0.0));
	    xmlXPathFreeObject(cur);
	    return;
	case XPATH_NUMBER:
	    valuePush(ctxt, cur);
	    return;
	case XPATH_USERS:
	case XPATH_POINT:
	case XPATH_RANGE:
	case XPATH_LOCATIONSET:
	    TODO
	    valuePush(ctxt, xmlXPathNewFloat(0.0));
	    break;
    }
    STRANGE
}

/**
 * xmlXPathSumFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the sum() XPath function
 *    number sum(node-set)
 * The sum function returns the sum of the values of the nodes in
 * the argument node-set.
 */
void
xmlXPathSumFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;
    int i;

    CHECK_ARITY(1);
    if ((ctxt->value == NULL) || 
	((ctxt->value->type != XPATH_NODESET) &&
	 (ctxt->value->type != XPATH_XSLT_TREE)))
	XP_ERROR(XPATH_INVALID_TYPE);
    cur = valuePop(ctxt);

    if (cur->nodesetval->nodeNr == 0) {
	valuePush(ctxt, xmlXPathNewFloat(0.0));
    } else {
	valuePush(ctxt,
		  xmlXPathNewNodeSet(cur->nodesetval->nodeTab[0]));
	xmlXPathNumberFunction(ctxt, 1);
	for (i = 1; i < cur->nodesetval->nodeNr; i++) {
	    valuePush(ctxt,
		      xmlXPathNewNodeSet(cur->nodesetval->nodeTab[i]));
	    xmlXPathAddValues(ctxt);
	}
    }
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathFloorFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the floor() XPath function
 *    number floor(number)
 * The floor function returns the largest (closest to positive infinity)
 * number that is not greater than the argument and that is an integer.
 */
void
xmlXPathFloorFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(1);
    CAST_TO_NUMBER;
    CHECK_TYPE(XPATH_NUMBER);
#if 0
    ctxt->value->floatval = floor(ctxt->value->floatval);
#else
    /* floor(0.999999999999) => 1.0 !!!!!!!!!!! */
    ctxt->value->floatval = (double)((int) ctxt->value->floatval);
#endif
}

/**
 * xmlXPathCeilingFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the ceiling() XPath function
 *    number ceiling(number)
 * The ceiling function returns the smallest (closest to negative infinity)
 * number that is not less than the argument and that is an integer.
 */
void
xmlXPathCeilingFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    double f;

    CHECK_ARITY(1);
    CAST_TO_NUMBER;
    CHECK_TYPE(XPATH_NUMBER);

#if 0
    ctxt->value->floatval = ceil(ctxt->value->floatval);
#else
    f = (double)((int) ctxt->value->floatval);
    if (f != ctxt->value->floatval)
	ctxt->value->floatval = f + 1;
#endif
}

/**
 * xmlXPathRoundFunction:
 * @ctxt:  the XPath Parser context
 * @nargs:  the number of arguments
 *
 * Implement the round() XPath function
 *    number round(number)
 * The round function returns the number that is closest to the
 * argument and that is an integer. If there are two such numbers,
 * then the one that is even is returned.
 */
void
xmlXPathRoundFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    double f;

    CHECK_ARITY(1);
    CAST_TO_NUMBER;
    CHECK_TYPE(XPATH_NUMBER);

    if ((ctxt->value->floatval == xmlXPathNAN) ||
	(ctxt->value->floatval == xmlXPathPINF) ||
	(ctxt->value->floatval == xmlXPathNINF) ||
	(ctxt->value->floatval == 0.0))
	return;

#if 0
    f = floor(ctxt->value->floatval);
#else
    f = (double)((int) ctxt->value->floatval);
#endif
    if (ctxt->value->floatval < f + 0.5)
        ctxt->value->floatval = f;
    else 
        ctxt->value->floatval = f + 1;
}

/************************************************************************
 *									*
 *			The Parser					*
 *									*
 ************************************************************************/

/*
 * a couple of forward declarations since we use a recursive call based
 * implementation.
 */
void xmlXPathEvalExpr(xmlXPathParserContextPtr ctxt);
void xmlXPathEvalPredicate(xmlXPathParserContextPtr ctxt);
void xmlXPathEvalLocationPath(xmlXPathParserContextPtr ctxt);
#ifdef VMS
void xmlXPathEvalRelLocationPath(xmlXPathParserContextPtr ctxt);
#define xmlXPathEvalRelativeLocationPath xmlXPathEvalRelLocationPath 
#else 
void xmlXPathEvalRelativeLocationPath(xmlXPathParserContextPtr ctxt);
#endif

/**
 * xmlXPathParseNCName:
 * @ctxt:  the XPath Parser context
 *
 * parse an XML namespace non qualified name.
 *
 * [NS 3] NCName ::= (Letter | '_') (NCNameChar)*
 *
 * [NS 4] NCNameChar ::= Letter | Digit | '.' | '-' | '_' |
 *                       CombiningChar | Extender
 *
 * Returns the namespace name or NULL
 */

xmlChar *
xmlXPathParseNCName(xmlXPathParserContextPtr ctxt) {
    const xmlChar *q;
    xmlChar *ret = NULL;

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
 * xmlXPathParseQName:
 * @ctxt:  the XPath Parser context
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
 * Returns the function returns the local part, and prefix is updated
 *   to get the Prefix if any.
 */

xmlChar *
xmlXPathParseQName(xmlXPathParserContextPtr ctxt, xmlChar **prefix) {
    xmlChar *ret = NULL;

    *prefix = NULL;
    ret = xmlXPathParseNCName(ctxt);
    if (CUR == ':') {
        *prefix = ret;
	NEXT;
	ret = xmlXPathParseNCName(ctxt);
    }
    return(ret);
}

/**
 * xmlXPathParseName:
 * @ctxt:  the XPath Parser context
 *
 * parse an XML name
 *
 * [4] NameChar ::= Letter | Digit | '.' | '-' | '_' | ':' |
 *                  CombiningChar | Extender
 *
 * [5] Name ::= (Letter | '_' | ':') (NameChar)*
 *
 * Returns the namespace name or NULL
 */

xmlChar *
xmlXPathParseName(xmlXPathParserContextPtr ctxt) {
    const xmlChar *q;
    xmlChar *ret = NULL;

    if (!IS_LETTER(CUR) && (CUR != '_')) return(NULL);
    q = NEXT;

    /* TODO Make this UTF8 compliant !!! */
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
 * xmlXPathStringEvalNumber:
 * @str:  A string to scan
 *
 *  [30]   Number ::=   Digits ('.' Digits?)?
 *                    | '.' Digits 
 *  [31]   Digits ::=   [0-9]+
 *
 * Parse and evaluate a Number in the string
 * In complement of the Number expression, this function also handles
 * negative values : '-' Number.
 *
 * Returns the double value.
 */
double
xmlXPathStringEvalNumber(const xmlChar *str) {
    const xmlChar *cur = str;
    double ret = 0.0;
    double mult = 1;
    int ok = 0;
    int isneg = 0;

    while (IS_BLANK(*cur)) cur++;
    if ((*cur != '.') && ((*cur < '0') || (*cur > '9')) && (*cur != '-')) {
        return(xmlXPathNAN);
    }
    if (*cur == '-') {
	isneg = 1;
	cur++;
    }
    while ((*cur >= '0') && (*cur <= '9')) {
        ret = ret * 10 + (*cur - '0');
	ok = 1;
	cur++;
    }
    if (*cur == '.') {
        cur++;
	if (((*cur < '0') || (*cur > '9')) && (!ok)) {
	    return(xmlXPathNAN);
	}
	while ((*cur >= '0') && (*cur <= '9')) {
	    mult /= 10;
	    ret = ret  + (*cur - '0') * mult;
	    cur++;
	}
    }
    while (IS_BLANK(*cur)) cur++;
    if (*cur != 0) return(xmlXPathNAN);
    if (isneg) ret = -ret;
    return(ret);
}

/**
 * xmlXPathEvalNumber:
 * @ctxt:  the XPath Parser context
 *
 *  [30]   Number ::=   Digits ('.' Digits?)?
 *                    | '.' Digits 
 *  [31]   Digits ::=   [0-9]+
 *
 * Parse and evaluate a Number, then push it on the stack
 *
 */
void
xmlXPathEvalNumber(xmlXPathParserContextPtr ctxt) {
    double ret = 0.0;
    double mult = 1;
    int ok = 0;

    CHECK_ERROR;
    if ((CUR != '.') && ((CUR < '0') || (CUR > '9'))) {
        XP_ERROR(XPATH_NUMBER_ERROR);
    }
    while ((CUR >= '0') && (CUR <= '9')) {
        ret = ret * 10 + (CUR - '0');
	ok = 1;
	NEXT;
    }
    if (CUR == '.') {
        NEXT;
	if (((CUR < '0') || (CUR > '9')) && (!ok)) {
	     XP_ERROR(XPATH_NUMBER_ERROR);
	}
	while ((CUR >= '0') && (CUR <= '9')) {
	    mult /= 10;
	    ret = ret  + (CUR - '0') * mult;
	    NEXT;
	}
    }
    valuePush(ctxt, xmlXPathNewFloat(ret));
}

/**
 * xmlXPathEvalLiteral:
 * @ctxt:  the XPath Parser context
 *
 * Parse a Literal and push it on the stack.
 *
 *  [29]   Literal ::=   '"' [^"]* '"'
 *                    | "'" [^']* "'"
 *
 * TODO: xmlXPathEvalLiteral memory allocation could be improved.
 */
void
xmlXPathEvalLiteral(xmlXPathParserContextPtr ctxt) {
    const xmlChar *q;
    xmlChar *ret = NULL;

    if (CUR == '"') {
        NEXT;
	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '"'))
	    NEXT;
	if (!IS_CHAR(CUR)) {
	    XP_ERROR(XPATH_UNFINISHED_LITERAL_ERROR);
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
	    XP_ERROR(XPATH_UNFINISHED_LITERAL_ERROR);
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
        }
    } else {
	XP_ERROR(XPATH_START_LITERAL_ERROR);
    }
    if (ret == NULL) return;
    valuePush(ctxt, xmlXPathNewString(ret));
    xmlFree(ret);
}

/**
 * xmlXPathEvalVariableReference:
 * @ctxt:  the XPath Parser context
 *
 * Parse a VariableReference, evaluate it and push it on the stack.
 *
 * The variable bindings consist of a mapping from variable names
 * to variable values. The value of a variable is an object, which
 * of any of the types that are possible for the value of an expression,
 * and may also be of additional types not specified here.
 *
 * Early evaluation is possible since:
 * The variable bindings [...] used to evaluate a subexpression are
 * always the same as those used to evaluate the containing expression. 
 *
 *  [36]   VariableReference ::=   '$' QName 
 */
void
xmlXPathEvalVariableReference(xmlXPathParserContextPtr ctxt) {
    xmlChar *name;
    xmlChar *prefix;
    xmlXPathObjectPtr value;

    SKIP_BLANKS;
    if (CUR != '$') {
	XP_ERROR(XPATH_VARIABLE_REF_ERROR);
    }
    NEXT;
    name = xmlXPathParseQName(ctxt, &prefix);
    if (name == NULL) {
	XP_ERROR(XPATH_VARIABLE_REF_ERROR);
    }
    if (prefix == NULL) {
	value = xmlXPathVariableLookup(ctxt->context, name);
    } else {
	TODO;
	value = NULL;
    }
    xmlFree(name);
    if (prefix != NULL) xmlFree(prefix);
    if (value == NULL) {
	XP_ERROR(XPATH_UNDEF_VARIABLE_ERROR);
    }
    valuePush(ctxt, value);
    SKIP_BLANKS;
}

/**
 * xmlXPathIsNodeType:
 * @ctxt:  the XPath Parser context
 * @name:  a name string
 *
 * Is the name given a NodeType one.
 *
 *  [38]   NodeType ::=   'comment'
 *                    | 'text'
 *                    | 'processing-instruction'
 *                    | 'node'
 *
 * Returns 1 if true 0 otherwise
 */
int
xmlXPathIsNodeType(const xmlChar *name) {
    if (name == NULL)
	return(0);

    if (xmlStrEqual(name, BAD_CAST "comment"))
	return(1);
    if (xmlStrEqual(name, BAD_CAST "text"))
	return(1);
    if (xmlStrEqual(name, BAD_CAST "processing-instruction"))
	return(1);
    if (xmlStrEqual(name, BAD_CAST "node"))
	return(1);
    return(0);
}

/**
 * xmlXPathEvalFunctionCall:
 * @ctxt:  the XPath Parser context
 *
 *  [16]   FunctionCall ::=   FunctionName '(' ( Argument ( ',' Argument)*)? ')'
 *  [17]   Argument ::=   Expr 
 *
 * Parse and evaluate a function call, the evaluation of all arguments are
 * pushed on the stack
 */
void
xmlXPathEvalFunctionCall(xmlXPathParserContextPtr ctxt) {
    xmlChar *name;
    xmlChar *prefix;
    xmlXPathFunction func;
    int nbargs = 0;

    name = xmlXPathParseQName(ctxt, &prefix);
    if (name == NULL) {
	XP_ERROR(XPATH_EXPR_ERROR);
    }
    SKIP_BLANKS;
    if (prefix == NULL) {
	func = xmlXPathFunctionLookup(ctxt->context, name);
    } else {
	TODO;
	func = NULL;
    }
    if (func == NULL) {
        xmlFree(name);
	if (prefix != NULL) xmlFree(prefix);
	XP_ERROR(XPATH_UNKNOWN_FUNC_ERROR);
    }
#ifdef DEBUG_EXPR
    if (prefix == NULL)
	xmlGenericError(xmlGenericErrorContext, "Calling function %s\n",
			name);
    else
	xmlGenericError(xmlGenericErrorContext, "Calling function %s:%s\n",
			prefix, name);
#endif

    xmlFree(name);
    if (prefix != NULL) xmlFree(prefix);

    if (CUR != '(') {
	XP_ERROR(XPATH_EXPR_ERROR);
    }
    NEXT;
    SKIP_BLANKS;

    while (CUR != ')') {
        xmlXPathEvalExpr(ctxt);
	nbargs++;
	if (CUR == ')') break;
	if (CUR != ',') {
	    XP_ERROR(XPATH_EXPR_ERROR);
	}
	NEXT;
	SKIP_BLANKS;
    }
    NEXT;
    SKIP_BLANKS;
    func(ctxt, nbargs);
}

/**
 * xmlXPathEvalPrimaryExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [15]   PrimaryExpr ::=   VariableReference 
 *                | '(' Expr ')'
 *                | Literal 
 *                | Number 
 *                | FunctionCall 
 *
 * Parse and evaluate a primary expression, then push the result on the stack
 */
void
xmlXPathEvalPrimaryExpr(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if (CUR == '$') xmlXPathEvalVariableReference(ctxt);
    else if (CUR == '(') {
	NEXT;
	SKIP_BLANKS;
	xmlXPathEvalExpr(ctxt);
	if (CUR != ')') {
	    XP_ERROR(XPATH_EXPR_ERROR);
	}
	NEXT;
	SKIP_BLANKS;
    } else if (IS_DIGIT(CUR)) {
	xmlXPathEvalNumber(ctxt);
    } else if ((CUR == '\'') || (CUR == '"')) {
	xmlXPathEvalLiteral(ctxt);
    } else {
	xmlXPathEvalFunctionCall(ctxt);
    }
    SKIP_BLANKS;
}

/**
 * xmlXPathEvalFilterExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [20]   FilterExpr ::=   PrimaryExpr 
 *               | FilterExpr Predicate 
 *
 * Parse and evaluate a filter expression, then push the result on the stack
 * Square brackets are used to filter expressions in the same way that
 * they are used in location paths. It is an error if the expression to
 * be filtered does not evaluate to a node-set. The context node list
 * used for evaluating the expression in square brackets is the node-set
 * to be filtered listed in document order.
 */

void
xmlXPathEvalFilterExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathEvalPrimaryExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    
    while (CUR == '[') {
	if ((ctxt->value == NULL) || 
	    ((ctxt->value->type != XPATH_NODESET) &&
	     (ctxt->value->type != XPATH_LOCATIONSET)))
	    XP_ERROR(XPATH_INVALID_TYPE)

	if (ctxt->value->type == XPATH_NODESET)
	    xmlXPathEvalPredicate(ctxt);
        else
	    xmlXPtrEvalRangePredicate(ctxt);
	SKIP_BLANKS;
    }

    
}

/**
 * xmlXPathScanName:
 * @ctxt:  the XPath Parser context
 *
 * Trickery: parse an XML name but without consuming the input flow
 * Needed to avoid insanity in the parser state.
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
xmlXPathScanName(xmlXPathParserContextPtr ctxt) {
    xmlChar buf[XML_MAX_NAMELEN];
    int len = 0;

    SKIP_BLANKS;
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
	    xmlGenericError(xmlGenericErrorContext, 
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
 * xmlXPathEvalPathExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [19]   PathExpr ::=   LocationPath 
 *               | FilterExpr 
 *               | FilterExpr '/' RelativeLocationPath 
 *               | FilterExpr '//' RelativeLocationPath 
 *
 * Parse and evaluate a path expression, then push the result on the stack
 * The / operator and // operators combine an arbitrary expression
 * and a relative location path. It is an error if the expression
 * does not evaluate to a node-set.
 * The / operator does composition in the same way as when / is
 * used in a location path. As in location paths, // is short for
 * /descendant-or-self::node()/.
 */

void
xmlXPathEvalPathExpr(xmlXPathParserContextPtr ctxt) {
    int lc = 1;           /* Should we branch to LocationPath ?         */
    xmlChar *name = NULL; /* we may have to preparse a name to find out */

    SKIP_BLANKS;
    if ((CUR == '$') || (CUR == '(') || (IS_DIGIT(CUR)) ||
        (CUR == '\'') || (CUR == '"')) {
	lc = 0;
    } else if (CUR == '*') {
	/* relative or absolute location path */
	lc = 1;
    } else if (CUR == '/') {
	/* relative or absolute location path */
	lc = 1;
    } else if (CUR == '@') {
	/* relative abbreviated attribute location path */
	lc = 1;
    } else if (CUR == '.') {
	/* relative abbreviated attribute location path */
	lc = 1;
    } else {
	/*
	 * Problem is finding if we have a name here whether it's:
	 *   - a nodetype
	 *   - a function call in which case it's followed by '('
	 *   - an axis in which case it's followed by ':'
	 *   - a element name
	 * We do an a priori analysis here rather than having to
	 * maintain parsed token content through the recursive function
	 * calls. This looks uglier but makes the code quite easier to
	 * read/write/debug.
	 */
	SKIP_BLANKS;
	name = xmlXPathScanName(ctxt);
	if ((name != NULL) && (xmlStrstr(name, (xmlChar *) "::") != NULL)) {
#ifdef DEBUG_STEP
	    xmlGenericError(xmlGenericErrorContext,
		    "PathExpr: Axis\n");
#endif
	    lc = 1;
	    xmlFree(name);
	} else if (name != NULL) {
	    int len =xmlStrlen(name);
	    int blank = 0;

	    
	    while (NXT(len) != 0) {
		if (NXT(len) == '/') {
		    /* element name */
#ifdef DEBUG_STEP
		    xmlGenericError(xmlGenericErrorContext,
			    "PathExpr: AbbrRelLocation\n");
#endif
		    lc = 1;
		    break;
		} else if (IS_BLANK(NXT(len))) {
		    /* skip to next */
		    blank = 1;
		} else if (NXT(len) == ':') {
#ifdef DEBUG_STEP
		    xmlGenericError(xmlGenericErrorContext,
			    "PathExpr: AbbrRelLocation\n");
#endif
		    lc = 1;
		    break;
		} else if ((NXT(len) == '(')) {
		    /* Note Type or Function */
		    if (xmlXPathIsNodeType(name)) {
#ifdef DEBUG_STEP
		        xmlGenericError(xmlGenericErrorContext,
				"PathExpr: Type search\n");
#endif
			lc = 1;
		    } else {
#ifdef DEBUG_STEP
		        xmlGenericError(xmlGenericErrorContext,
				"PathExpr: function call\n");
#endif
			lc = 0;
		    }
                    break;
		} else if ((NXT(len) == '[')) {
		    /* element name */
#ifdef DEBUG_STEP
		    xmlGenericError(xmlGenericErrorContext,
			    "PathExpr: AbbrRelLocation\n");
#endif
		    lc = 1;
		    break;
		} else if ((NXT(len) == '<') || (NXT(len) == '>') ||
			   (NXT(len) == '=')) {
		    lc = 1;
		    break;
		} else {
		    lc = 1;
		    break;
		}
		len++;
	    }
	    if (NXT(len) == 0) {
#ifdef DEBUG_STEP
		xmlGenericError(xmlGenericErrorContext,
			"PathExpr: AbbrRelLocation\n");
#endif
		/* element name */
		lc = 1;
	    }
	    xmlFree(name);
	} else {
	    /* make sure all cases are covered explicitely */
	    XP_ERROR(XPATH_EXPR_ERROR);
	}
    } 

    if (lc) {
	if (CUR == '/')
	    xmlXPathRoot(ctxt);
	else {
	    /* TAG:9999 */
	    valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
	}
	xmlXPathEvalLocationPath(ctxt);
    } else {
	xmlXPathEvalFilterExpr(ctxt);
	CHECK_ERROR;
	if ((CUR == '/') && (NXT(1) == '/')) {
	    SKIP(2);
	    SKIP_BLANKS;
	    xmlXPathNodeCollectAndTest(ctxt, AXIS_DESCENDANT_OR_SELF,
			     NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
	    ctxt->context->node = NULL;
	    xmlXPathEvalRelativeLocationPath(ctxt);
	} else if (CUR == '/') {
	    xmlXPathEvalRelativeLocationPath(ctxt);
	}
    }
    SKIP_BLANKS;
}

/**
 * xmlXPathEvalUnionExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [18]   UnionExpr ::=   PathExpr 
 *               | UnionExpr '|' PathExpr 
 *
 * Parse and evaluate an union expression, then push the result on the stack
 */

void
xmlXPathEvalUnionExpr(xmlXPathParserContextPtr ctxt) {
    int sort = 0;
    xmlXPathEvalPathExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while (CUR == '|') {
	xmlXPathObjectPtr obj1,obj2, tmp;

	sort = 1;
	CHECK_TYPE(XPATH_NODESET);
	obj1 = valuePop(ctxt);
	tmp = xmlXPathNewNodeSet(ctxt->context->node);
	valuePush(ctxt, tmp);

	NEXT;
	SKIP_BLANKS;
	xmlXPathEvalPathExpr(ctxt);

	CHECK_TYPE(XPATH_NODESET);
	obj2 = valuePop(ctxt);
	obj1->nodesetval = xmlXPathNodeSetMerge(obj1->nodesetval,
		                                obj2->nodesetval);
	if (ctxt->value == tmp) {
	    tmp = valuePop(ctxt);
	    xmlXPathFreeObject(tmp);
	}
	valuePush(ctxt, obj1);
	xmlXPathFreeObject(obj2);
	SKIP_BLANKS;
    }
    if (sort) {
    }
}

/**
 * xmlXPathEvalUnaryExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [27]   UnaryExpr ::=   UnionExpr 
 *                   | '-' UnaryExpr 
 *
 * Parse and evaluate an unary expression, then push the result on the stack
 */

void
xmlXPathEvalUnaryExpr(xmlXPathParserContextPtr ctxt) {
    int minus = 0;

    SKIP_BLANKS;
    if (CUR == '-') {
        minus = 1;
	NEXT;
	SKIP_BLANKS;
    }
    xmlXPathEvalUnionExpr(ctxt);
    CHECK_ERROR;
    if (minus) {
        xmlXPathValueFlipSign(ctxt);
    }
}

/**
 * xmlXPathEvalMultiplicativeExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [26]   MultiplicativeExpr ::=   UnaryExpr 
 *                   | MultiplicativeExpr MultiplyOperator UnaryExpr 
 *                   | MultiplicativeExpr 'div' UnaryExpr 
 *                   | MultiplicativeExpr 'mod' UnaryExpr 
 *  [34]   MultiplyOperator ::=   '*'
 *
 * Parse and evaluate an Additive expression, then push the result on the stack
 */

void
xmlXPathEvalMultiplicativeExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathEvalUnaryExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '*') || 
           ((CUR == 'd') && (NXT(1) == 'i') && (NXT(2) == 'v')) ||
           ((CUR == 'm') && (NXT(1) == 'o') && (NXT(2) == 'd'))) {
	int op = -1;

        if (CUR == '*') {
	    op = 0;
	    NEXT;
	} else if (CUR == 'd') {
	    op = 1;
	    SKIP(3);
	} else if (CUR == 'm') {
	    op = 2;
	    SKIP(3);
	}
	SKIP_BLANKS;
        xmlXPathEvalUnaryExpr(ctxt);
	CHECK_ERROR;
	switch (op) {
	    case 0:
	        xmlXPathMultValues(ctxt);
		break;
	    case 1:
	        xmlXPathDivValues(ctxt);
		break;
	    case 2:
	        xmlXPathModValues(ctxt);
		break;
	}
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathEvalAdditiveExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [25]   AdditiveExpr ::=   MultiplicativeExpr 
 *                   | AdditiveExpr '+' MultiplicativeExpr 
 *                   | AdditiveExpr '-' MultiplicativeExpr 
 *
 * Parse and evaluate an Additive expression, then push the result on the stack
 */

void
xmlXPathEvalAdditiveExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathEvalMultiplicativeExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '+') || (CUR == '-')) {
	int plus;

        if (CUR == '+') plus = 1;
	else plus = 0;
	NEXT;
	SKIP_BLANKS;
        xmlXPathEvalMultiplicativeExpr(ctxt);
	CHECK_ERROR;
	if (plus) xmlXPathAddValues(ctxt);
	else xmlXPathSubValues(ctxt);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathEvalRelationalExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [24]   RelationalExpr ::=   AdditiveExpr 
 *                 | RelationalExpr '<' AdditiveExpr 
 *                 | RelationalExpr '>' AdditiveExpr 
 *                 | RelationalExpr '<=' AdditiveExpr 
 *                 | RelationalExpr '>=' AdditiveExpr 
 *
 *  A <= B > C is allowed ? Answer from James, yes with
 *  (AdditiveExpr <= AdditiveExpr) > AdditiveExpr
 *  which is basically what got implemented.
 *
 * Parse and evaluate a Relational expression, then push the result
 * on the stack
 */

void
xmlXPathEvalRelationalExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathEvalAdditiveExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '<') ||
           (CUR == '>') ||
           ((CUR == '<') && (NXT(1) == '=')) ||
           ((CUR == '>') && (NXT(1) == '='))) {
	int inf, strict, ret;

        if (CUR == '<') inf = 1;
	else inf = 0;
	if (NXT(1) == '=') strict = 0;
	else strict = 1;
	NEXT;
	if (!strict) NEXT;
	SKIP_BLANKS;
        xmlXPathEvalAdditiveExpr(ctxt);
	CHECK_ERROR;
	ret = xmlXPathCompareValues(ctxt, inf, strict);
	valuePush(ctxt, xmlXPathNewBoolean(ret));
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathEvalEqualityExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [23]   EqualityExpr ::=   RelationalExpr 
 *                 | EqualityExpr '=' RelationalExpr 
 *                 | EqualityExpr '!=' RelationalExpr 
 *
 *  A != B != C is allowed ? Answer from James, yes with
 *  (RelationalExpr = RelationalExpr) = RelationalExpr
 *  (RelationalExpr != RelationalExpr) != RelationalExpr
 *  which is basically what got implemented.
 *
 * Parse and evaluate an Equality expression, then push the result on the stack
 *
 */
void
xmlXPathEvalEqualityExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathEvalRelationalExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '=') || ((CUR == '!') && (NXT(1) == '='))) {
	xmlXPathObjectPtr res;
	int eq, equal;

        if (CUR == '=') eq = 1;
	else eq = 0;
	NEXT;
	if (!eq) NEXT;
	SKIP_BLANKS;
        xmlXPathEvalRelationalExpr(ctxt);
	CHECK_ERROR;
	equal = xmlXPathEqualValues(ctxt);
	if (eq) res = xmlXPathNewBoolean(equal);
	else res = xmlXPathNewBoolean(!equal);
	valuePush(ctxt, res);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathEvalAndExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [22]   AndExpr ::=   EqualityExpr 
 *                 | AndExpr 'and' EqualityExpr 
 *
 * Parse and evaluate an AND expression, then push the result on the stack
 *
 */
void
xmlXPathEvalAndExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathEvalEqualityExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == 'a') && (NXT(1) == 'n') && (NXT(2) == 'd')) {
	xmlXPathObjectPtr arg1, arg2;

        SKIP(3);
	SKIP_BLANKS;
        xmlXPathEvalEqualityExpr(ctxt);
	CHECK_ERROR;
	xmlXPathBooleanFunction(ctxt, 1);
	arg2 = valuePop(ctxt);
	xmlXPathBooleanFunction(ctxt, 1);
	arg1 = valuePop(ctxt);
	arg1->boolval &= arg2->boolval;
	valuePush(ctxt, arg1);
	xmlXPathFreeObject(arg2);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathEvalExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [14]   Expr ::=   OrExpr 
 *  [21]   OrExpr ::=   AndExpr 
 *                 | OrExpr 'or' AndExpr 
 *
 * Parse and evaluate an expression, then push the result on the stack
 *
 */
void
xmlXPathEvalExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathEvalAndExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == 'o') && (NXT(1) == 'r')) {
	xmlXPathObjectPtr arg1, arg2;

        SKIP(2);
	SKIP_BLANKS;
        xmlXPathEvalAndExpr(ctxt);
	CHECK_ERROR;
	xmlXPathBooleanFunction(ctxt, 1);
	arg2 = valuePop(ctxt);
	xmlXPathBooleanFunction(ctxt, 1);
	arg1 = valuePop(ctxt);
	arg1->boolval |= arg2->boolval;
	valuePush(ctxt, arg1);
	xmlXPathFreeObject(arg2);
	SKIP_BLANKS;
    }
    if ((ctxt->value != NULL) && (ctxt->value->type == XPATH_NODESET) &&
	(ctxt->value->nodesetval != NULL))
	xmlXPathNodeSetSort(ctxt->value->nodesetval);
}

/**
 * xmlXPathEvaluatePredicateResult:
 * @ctxt:  the XPath Parser context
 * @res:  the Predicate Expression evaluation result
 *
 * Evaluate a predicate result for the current node.
 * A PredicateExpr is evaluated by evaluating the Expr and converting
 * the result to a boolean. If the result is a number, the result will
 * be converted to true if the number is equal to the position of the
 * context node in the context node list (as returned by the position
 * function) and will be converted to false otherwise; if the result
 * is not a number, then the result will be converted as if by a call
 * to the boolean function. 
 *
 * Return 1 if predicate is true, 0 otherwise
 */
int
xmlXPathEvaluatePredicateResult(xmlXPathParserContextPtr ctxt, 
                                xmlXPathObjectPtr res) {
    if (res == NULL) return(0);
    switch (res->type) {
        case XPATH_BOOLEAN:
	    return(res->boolval);
        case XPATH_NUMBER:
	    return(res->floatval == ctxt->context->proximityPosition);
        case XPATH_NODESET:
        case XPATH_XSLT_TREE:
	    return(res->nodesetval->nodeNr != 0);
        case XPATH_STRING:
	    return((res->stringval != NULL) &&
	           (xmlStrlen(res->stringval) != 0));
        default:
	    STRANGE
    }
    return(0);
}

/**
 * xmlXPathEvalPredicate:
 * @ctxt:  the XPath Parser context
 *
 *  [8]   Predicate ::=   '[' PredicateExpr ']'
 *  [9]   PredicateExpr ::=   Expr 
 *
 * ---------------------
 * For each node in the node-set to be filtered, the PredicateExpr is
 * evaluated with that node as the context node, with the number of nodes
 * in the node-set as the context size, and with the proximity position
 * of the node in the node-set with respect to the axis as the context
 * position; if PredicateExpr evaluates to true for that node, the node
 * is included in the new node-set; otherwise, it is not included.
 * ---------------------
 *
 * Parse and evaluate a predicate for all the elements of the
 * current node list. Then refine the list by removing all
 * nodes where the predicate is false.
 */
void
xmlXPathEvalPredicate(xmlXPathParserContextPtr ctxt) {
    const xmlChar *cur;
    xmlXPathObjectPtr res;
    xmlXPathObjectPtr obj, tmp;
    xmlNodeSetPtr newset = NULL;
    xmlNodeSetPtr oldset;
    xmlNodePtr oldnode;
    int i;

    SKIP_BLANKS;
    if (CUR != '[') {
	XP_ERROR(XPATH_INVALID_PREDICATE_ERROR);
    }
    NEXT;
    SKIP_BLANKS;

    /*
     * Extract the old set, and then evaluate the result of the
     * expression for all the element in the set. use it to grow
     * up a new set.
     */
    CHECK_TYPE(XPATH_NODESET);
    obj = valuePop(ctxt);
    oldset = obj->nodesetval;
    oldnode = ctxt->context->node;
    ctxt->context->node = NULL;

    if ((oldset == NULL) || (oldset->nodeNr == 0)) {
	ctxt->context->contextSize = 0;
	ctxt->context->proximityPosition = 0;
	xmlXPathEvalExpr(ctxt);
	res = valuePop(ctxt);
	if (res != NULL)
	    xmlXPathFreeObject(res);
	valuePush(ctxt, obj);
	CHECK_ERROR;
    } else {
	/*
	 * Save the expression pointer since we will have to evaluate
	 * it multiple times. Initialize the new set.
	 */
        cur = ctxt->cur;
	newset = xmlXPathNodeSetCreate(NULL);
	
        for (i = 0; i < oldset->nodeNr; i++) {
	    ctxt->cur = cur;

	    /*
	     * Run the evaluation with a node list made of a single item
	     * in the nodeset.
	     */
	    ctxt->context->node = oldset->nodeTab[i];
	    tmp = xmlXPathNewNodeSet(ctxt->context->node);
	    valuePush(ctxt, tmp);
	    ctxt->context->contextSize = oldset->nodeNr;
	    ctxt->context->proximityPosition = i + 1;

	    xmlXPathEvalExpr(ctxt);
	    CHECK_ERROR;

	    /*
	     * The result of the evaluation need to be tested to
	     * decided whether the filter succeeded or not
	     */
	    res = valuePop(ctxt);
	    if (xmlXPathEvaluatePredicateResult(ctxt, res)) {
	        xmlXPathNodeSetAdd(newset, oldset->nodeTab[i]);
	    }

	    /*
	     * Cleanup
	     */
	    if (res != NULL)
		xmlXPathFreeObject(res);
	    if (ctxt->value == tmp) {
		res = valuePop(ctxt);
		xmlXPathFreeObject(res);
	    }
	    
	    ctxt->context->node = NULL;
	}

	/*
	 * The result is used as the new evaluation set.
	 */
	xmlXPathFreeObject(obj);
	ctxt->context->node = NULL;
	ctxt->context->contextSize = -1;
	ctxt->context->proximityPosition = -1;
	valuePush(ctxt, xmlXPathWrapNodeSet(newset));
    }
    if (CUR != ']') {
	XP_ERROR(XPATH_INVALID_PREDICATE_ERROR);
    }

    NEXT;
    SKIP_BLANKS;
#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext, "After predicate : ");
    xmlGenericErrorContextNodeSet(xmlGenericErrorContext,
	    ctxt->value->nodesetval);
#endif
    ctxt->context->node = oldnode;
}

/**
 * xmlXPathEvalNodeTest:
 * @ctxt:  the XPath Parser context
 * @test:  pointer to a xmlXPathTestVal
 * @type:  pointer to a xmlXPathTypeVal
 * @prefix:  placeholder for a possible name prefix
 *
 * [7] NodeTest ::=   NameTest
 *		    | NodeType '(' ')'
 *		    | 'processing-instruction' '(' Literal ')'
 *
 * [37] NameTest ::=  '*'
 *		    | NCName ':' '*'
 *		    | QName
 * [38] NodeType ::= 'comment'
 *		   | 'text'
 *		   | 'processing-instruction'
 *		   | 'node'
 *
 * Returns the name found and update @test, @type and @prefix appropriately
 */
xmlChar *
xmlXPathEvalNodeTest(xmlXPathParserContextPtr ctxt, xmlXPathTestVal *test,
	             xmlXPathTypeVal *type, const xmlChar **prefix, xmlChar *name) {
    int blanks;

    if ((test == NULL) || (type == NULL) || (prefix == NULL)) {
	STRANGE;
	return(NULL);
    }
    *type = 0;
    *test = 0;
    *prefix = NULL;
    SKIP_BLANKS;

    if ((name == NULL) && (CUR == '*')) {
	/*
	 * All elements
	 */
	NEXT;
	*test = NODE_TEST_ALL;
	return(NULL);
    }

    if (name == NULL)
	name = xmlXPathParseNCName(ctxt);
    if (name == NULL) {
	XP_ERROR0(XPATH_EXPR_ERROR);
    }

    blanks = IS_BLANK(CUR);
    SKIP_BLANKS;
    if (CUR == '(') {
	NEXT;
	/*
	 * NodeType or PI search
	 */
	if (xmlStrEqual(name, BAD_CAST "comment"))
	    *type = NODE_TYPE_COMMENT;
	else if (xmlStrEqual(name, BAD_CAST "node"))
	    *type = NODE_TYPE_NODE;
	else if (xmlStrEqual(name, BAD_CAST "processing-instruction"))
	    *type = NODE_TYPE_PI;
	else if (xmlStrEqual(name, BAD_CAST "text"))
	    *type = NODE_TYPE_TEXT;
	else {
	    if (name != NULL)
		xmlFree(name);
	    XP_ERROR0(XPATH_EXPR_ERROR);
	}

	*test = NODE_TEST_TYPE;
	
	SKIP_BLANKS;
	if (*type == NODE_TYPE_PI) {
	    /*
	     * Specific case: search a PI by name.
	     */
	    xmlXPathObjectPtr cur;

	    if (name != NULL)
		xmlFree(name);

	    xmlXPathEvalLiteral(ctxt);
	    CHECK_ERROR 0;
	    xmlXPathStringFunction(ctxt, 1);
	    CHECK_ERROR0;
	    cur = valuePop(ctxt);
	    name = xmlStrdup(cur->stringval);
	    xmlXPathFreeObject(cur);
	    SKIP_BLANKS;
	}
	if (CUR != ')') {
	    if (name != NULL)
		xmlFree(name);
	    XP_ERROR0(XPATH_UNCLOSED_ERROR);
	}
	NEXT;
	return(name);
    }
    *test = NODE_TEST_NAME;
    if ((!blanks) && (CUR == ':')) {
	NEXT;

	/*
	 * get the namespace name for this prefix
	 */
	*prefix = xmlXPathNsLookup(ctxt->context, name);
	if (name != NULL)
	    xmlFree(name);
	if (*prefix == NULL) {
	    XP_ERROR0(XPATH_UNDEF_PREFIX_ERROR);
	}

	if (CUR == '*') {
	    /*
	     * All elements
	     */
	    NEXT;
	    *test = NODE_TEST_ALL;
	    return(NULL);
	}

	name = xmlXPathParseNCName(ctxt);
	if (name == NULL) {
	    XP_ERROR0(XPATH_EXPR_ERROR);
	}
    }
    return(name);
}

/**
 * xmlXPathIsAxisName:
 * @name:  a preparsed name token
 *
 * [6] AxisName ::=   'ancestor'
 *                  | 'ancestor-or-self'
 *                  | 'attribute'
 *                  | 'child'
 *                  | 'descendant'
 *                  | 'descendant-or-self'
 *                  | 'following'
 *                  | 'following-sibling'
 *                  | 'namespace'
 *                  | 'parent'
 *                  | 'preceding'
 *                  | 'preceding-sibling'
 *                  | 'self'
 *
 * Returns the axis or 0
 */
xmlXPathAxisVal
xmlXPathIsAxisName(const xmlChar *name) {
    xmlXPathAxisVal ret = 0;
    switch (name[0]) {
	case 'a':
	    if (xmlStrEqual(name, BAD_CAST "ancestor"))
		ret = AXIS_ANCESTOR;
	    if (xmlStrEqual(name, BAD_CAST "ancestor-or-self"))
		ret = AXIS_ANCESTOR_OR_SELF;
	    if (xmlStrEqual(name, BAD_CAST "attribute"))
		ret = AXIS_ATTRIBUTE;
	    break;
	case 'c':
	    if (xmlStrEqual(name, BAD_CAST "child"))
		ret = AXIS_CHILD;
	    break;
	case 'd':
	    if (xmlStrEqual(name, BAD_CAST "descendant"))
		ret = AXIS_DESCENDANT;
	    if (xmlStrEqual(name, BAD_CAST "descendant-or-self"))
		ret = AXIS_DESCENDANT_OR_SELF;
	    break;
	case 'f':
	    if (xmlStrEqual(name, BAD_CAST "following"))
		ret = AXIS_FOLLOWING;
	    if (xmlStrEqual(name, BAD_CAST "following-sibling"))
		ret = AXIS_FOLLOWING_SIBLING;
	    break;
	case 'n':
	    if (xmlStrEqual(name, BAD_CAST "namespace"))
		ret = AXIS_NAMESPACE;
	    break;
	case 'p':
	    if (xmlStrEqual(name, BAD_CAST "parent"))
		ret = AXIS_PARENT;
	    if (xmlStrEqual(name, BAD_CAST "preceding"))
		ret = AXIS_PRECEDING;
	    if (xmlStrEqual(name, BAD_CAST "preceding-sibling"))
		ret = AXIS_PRECEDING_SIBLING;
	    break;
	case 's':
	    if (xmlStrEqual(name, BAD_CAST "self"))
		ret = AXIS_SELF;
	    break;
    }
    return(ret);
}

/**
 * xmlXPathEvalAxisSpecifier:
 * @ctxt:  the XPath Parser context
 *
 *
 * Returns the axis found
 */
xmlXPathAxisVal
xmlXPathEvalAxisSpecifier(xmlXPathParserContextPtr ctxt) {
    xmlXPathAxisVal ret = AXIS_CHILD;
    int blank = 0;
    xmlChar *name;

    if (CUR == '@') {
	NEXT;
	return(AXIS_ATTRIBUTE);
    } else {
	name = xmlXPathParseNCName(ctxt);
	if (name == NULL) {
	    XP_ERROR0(XPATH_EXPR_ERROR);
	}
	if (IS_BLANK(CUR))
	    blank = 1;
	SKIP_BLANKS;
	if ((CUR == ':') && (NXT(1) == ':')) {
	    ret = xmlXPathIsAxisName(name);
	} else if ((blank) && (CUR == ':'))
	    XP_ERROR0(XPATH_EXPR_ERROR);

	xmlFree(name);
    }
    return(ret);
}

/**
 * xmlXPathEvalStep:
 * @ctxt:  the XPath Parser context
 *
 * [4] Step ::=   AxisSpecifier NodeTest Predicate*
 *                  | AbbreviatedStep 
 *
 * [12] AbbreviatedStep ::=   '.' | '..'
 *
 * [5] AxisSpecifier ::= AxisName '::'
 *                  | AbbreviatedAxisSpecifier
 *
 * [13] AbbreviatedAxisSpecifier ::= '@'?
 *
 * Modified for XPtr range support as:
 *
 *  [4xptr] Step ::= AxisSpecifier NodeTest Predicate*
 *                     | AbbreviatedStep
 *                     | 'range-to' '(' Expr ')' Predicate*
 *
 * Evaluate one step in a Location Path
 * A location step of . is short for self::node(). This is
 * particularly useful in conjunction with //. For example, the
 * location path .//para is short for
 * self::node()/descendant-or-self::node()/child::para
 * and so will select all para descendant elements of the context
 * node.
 * Similarly, a location step of .. is short for parent::node().
 * For example, ../title is short for parent::node()/child::title
 * and so will select the title children of the parent of the context
 * node.
 */
void
xmlXPathEvalStep(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if ((CUR == '.') && (NXT(1) == '.')) {
	SKIP(2);
	SKIP_BLANKS;
	xmlXPathNodeCollectAndTest(ctxt, AXIS_PARENT,
			 NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
    } else if (CUR == '.') {
	NEXT;
	SKIP_BLANKS;
    } else {
	xmlChar *name = NULL;
	const xmlChar *prefix = NULL;
	xmlXPathTestVal test;
	xmlXPathAxisVal axis;
	xmlXPathTypeVal type;

	/*
	 * The modification needed for XPointer change to the production
	 */
#ifdef LIBXML_XPTR_ENABLED
	if (ctxt->context->xptr) {
	    name = xmlXPathParseNCName(ctxt);
	    if ((name != NULL) && (xmlStrEqual(name, BAD_CAST "range-to"))) {
		xmlFree(name);
		SKIP_BLANKS;
		if (CUR != '(') {
		    XP_ERROR(XPATH_EXPR_ERROR);
		}
		NEXT;
		SKIP_BLANKS;

		xmlXPtrRangeToFunction(ctxt, 1);
		CHECK_ERROR;

		SKIP_BLANKS;
		if (CUR != ')') {
		    XP_ERROR(XPATH_EXPR_ERROR);
		}
		NEXT;
		goto eval_predicates;
	    }
	}
#endif
	if (name == NULL)
	    name = xmlXPathParseNCName(ctxt);
	if (name != NULL) {
	    axis = xmlXPathIsAxisName(name);
	    if (axis != 0) {
		SKIP_BLANKS;
		if ((CUR == ':') && (NXT(1) == ':')) {
		    SKIP(2);
		    xmlFree(name);
		    name = NULL;
		} else {
		    /* an element name can conflict with an axis one :-\ */
		    axis = AXIS_CHILD;
		}
	    } else {
	        axis = AXIS_CHILD;
	    }
	} else if (CUR == '@') {
	    NEXT;
	    axis = AXIS_ATTRIBUTE;
	} else {
	    axis = AXIS_CHILD;
	}

	CHECK_ERROR;

	name = xmlXPathEvalNodeTest(ctxt, &test, &type, &prefix, name);
	if (test == 0)
	    return;

#ifdef DEBUG_STEP
	xmlGenericError(xmlGenericErrorContext,
		"Basis : computing new set\n");
#endif
	xmlXPathNodeCollectAndTest(ctxt, axis, test, type, prefix, name);
#ifdef DEBUG_STEP
	xmlGenericError(xmlGenericErrorContext, "Basis : ");
	xmlGenericErrorContextNodeSet(stdout, ctxt->value->nodesetval);
#endif
	if (name != NULL)
	    xmlFree(name);

eval_predicates:
	SKIP_BLANKS;
	while (CUR == '[') {
	    xmlXPathEvalPredicate(ctxt);
	}
    }
#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext, "Step : ");
    xmlGenericErrorContextNodeSet(xmlGenericErrorContext,
	    ctxt->value->nodesetval);
#endif
}

/**
 * xmlXPathEvalRelativeLocationPath:
 * @ctxt:  the XPath Parser context
 *
 *  [3]   RelativeLocationPath ::=   Step 
 *                     | RelativeLocationPath '/' Step 
 *                     | AbbreviatedRelativeLocationPath 
 *  [11]  AbbreviatedRelativeLocationPath ::=   RelativeLocationPath '//' Step 
 *
 */
void
#ifdef VMS
xmlXPathEvalRelLocationPath
#else
xmlXPathEvalRelativeLocationPath
#endif
(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if ((CUR == '/') && (NXT(1) == '/')) {
	SKIP(2);
	SKIP_BLANKS;
	xmlXPathNodeCollectAndTest(ctxt, AXIS_DESCENDANT_OR_SELF,
			 NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
    } else if (CUR == '/') {
	    NEXT;
	SKIP_BLANKS;
    }
    xmlXPathEvalStep(ctxt);
    SKIP_BLANKS;
    while (CUR == '/') {
	if ((CUR == '/') && (NXT(1) == '/')) {
	    SKIP(2);
	    SKIP_BLANKS;
	    xmlXPathNodeCollectAndTest(ctxt, AXIS_DESCENDANT_OR_SELF,
			     NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
	    xmlXPathEvalStep(ctxt);
	} else if (CUR == '/') {
	    NEXT;
	    SKIP_BLANKS;
	    xmlXPathEvalStep(ctxt);
	}
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathEvalLocationPath:
 * @ctxt:  the XPath Parser context
 *
 *  [1]   LocationPath ::=   RelativeLocationPath 
 *                     | AbsoluteLocationPath 
 *  [2]   AbsoluteLocationPath ::=   '/' RelativeLocationPath?
 *                     | AbbreviatedAbsoluteLocationPath 
 *  [10]   AbbreviatedAbsoluteLocationPath ::=   
 *                           '//' RelativeLocationPath 
 *
 * // is short for /descendant-or-self::node()/. For example,
 * //para is short for /descendant-or-self::node()/child::para and
 * so will select any para element in the document (even a para element
 * that is a document element will be selected by //para since the
 * document element node is a child of the root node); div//para is
 * short for div/descendant-or-self::node()/child::para and so will
 * select all para descendants of div children.
 */
void
xmlXPathEvalLocationPath(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if (CUR != '/') {
        xmlXPathEvalRelativeLocationPath(ctxt);
    } else {
	while (CUR == '/') {
	    if ((CUR == '/') && (NXT(1) == '/')) {
		SKIP(2);
		SKIP_BLANKS;
		xmlXPathNodeCollectAndTest(ctxt,
		                 AXIS_DESCENDANT_OR_SELF, NODE_TEST_TYPE,
				 NODE_TYPE_NODE, NULL, NULL);
		xmlXPathEvalRelativeLocationPath(ctxt);
	    } else if (CUR == '/') {
		NEXT;
		SKIP_BLANKS;
		if (CUR != 0)
		    xmlXPathEvalRelativeLocationPath(ctxt);
	    }
	}
    }
}

/**
 * xmlXPathEval:
 * @str:  the XPath expression
 * @ctx:  the XPath context
 *
 * Evaluate the XPath Location Path in the given context.
 *
 * Returns the xmlXPathObjectPtr resulting from the eveluation or NULL.
 *         the caller has to free the object.
 */
xmlXPathObjectPtr
xmlXPathEval(const xmlChar *str, xmlXPathContextPtr ctx) {
    xmlXPathParserContextPtr ctxt;
    xmlXPathObjectPtr res, tmp, init = NULL;
    int stack = 0;

    xmlXPathInit();

    CHECK_CONTEXT(ctx)

    ctxt = xmlXPathNewParserContext(str, ctx);
    /**** TAG:9999
    if (ctx->node != NULL) {
	init = xmlXPathNewNodeSet(ctx->node);
	valuePush(ctxt, init);
    }
     ****/
    xmlXPathEvalExpr(ctxt);

    if (ctxt->value == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"xmlXPathEval: evaluation failed\n");
	res = NULL;
    } else if (*ctxt->cur != 0) {
	xmlXPatherror(ctxt, __FILE__, __LINE__, XPATH_EXPR_ERROR);
	res = NULL;
    } else {
	res = valuePop(ctxt);
    }

    do {
        tmp = valuePop(ctxt);
	if (tmp != NULL) {
	    if (tmp != init)
		stack++;    
	    xmlXPathFreeObject(tmp);
        }
    } while (tmp != NULL);
    if ((stack != 0) && (res != NULL)) {
	xmlGenericError(xmlGenericErrorContext,
		"xmlXPathEval: %d object left on the stack\n",
	        stack);
    }
    if (ctxt->error != XPATH_EXPRESSION_OK) {
	xmlXPathFreeObject(res);
	res = NULL;
    }
        
    xmlXPathFreeParserContext(ctxt);
    return(res);
}

/**
 * xmlXPathEvalExpression:
 * @str:  the XPath expression
 * @ctxt:  the XPath context
 *
 * Evaluate the XPath expression in the given context.
 *
 * Returns the xmlXPathObjectPtr resulting from the evaluation or NULL.
 *         the caller has to free the object.
 */
xmlXPathObjectPtr
xmlXPathEvalExpression(const xmlChar *str, xmlXPathContextPtr ctxt) {
    xmlXPathParserContextPtr pctxt;
    xmlXPathObjectPtr res, tmp;
    int stack = 0;

    xmlXPathInit();

    CHECK_CONTEXT(ctxt)

    pctxt = xmlXPathNewParserContext(str, ctxt);
    xmlXPathEvalExpr(pctxt);

    if (*pctxt->cur != 0) {
	xmlXPatherror(pctxt, __FILE__, __LINE__, XPATH_EXPR_ERROR);
	res = NULL;
    } else {
	res = valuePop(pctxt);
    }
    do {
        tmp = valuePop(pctxt);
	if (tmp != NULL) {
	    xmlXPathFreeObject(tmp);
	    stack++;
	}
    } while (tmp != NULL);
    if ((stack != 0) && (res != NULL)) {
	xmlGenericError(xmlGenericErrorContext,
		"xmlXPathEvalExpression: %d object left on the stack\n",
	        stack);
    }
    xmlXPathFreeParserContext(pctxt);
    return(res);
}

/**
 * xmlXPathRegisterAllFunctions:
 * @ctxt:  the XPath context
 *
 * Registers all default XPath functions in this context
 */
void
xmlXPathRegisterAllFunctions(xmlXPathContextPtr ctxt)
{
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"boolean",
                         xmlXPathBooleanFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"ceiling",
                         xmlXPathCeilingFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"count",
                         xmlXPathCountFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"concat",
                         xmlXPathConcatFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"contains",
                         xmlXPathContainsFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"id",
                         xmlXPathIdFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"false",
                         xmlXPathFalseFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"floor",
                         xmlXPathFloorFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"last",
                         xmlXPathLastFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"lang",
                         xmlXPathLangFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"local-name",
                         xmlXPathLocalNameFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"not",
                         xmlXPathNotFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"name",
                         xmlXPathNameFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"namespace-uri",
                         xmlXPathNamespaceURIFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"normalize-space",
                         xmlXPathNormalizeFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"number",
                         xmlXPathNumberFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"position",
                         xmlXPathPositionFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"round",
                         xmlXPathRoundFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"string",
                         xmlXPathStringFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"string-length",
                         xmlXPathStringLengthFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"starts-with",
                         xmlXPathStartsWithFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"substring",
                         xmlXPathSubstringFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"substring-before",
                         xmlXPathSubstringBeforeFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"substring-after",
                         xmlXPathSubstringAfterFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"sum",
                         xmlXPathSumFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"true",
                         xmlXPathTrueFunction);
    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"translate",
                         xmlXPathTranslateFunction);
}

#endif /* LIBXML_XPATH_ENABLED */
