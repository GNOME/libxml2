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

#include "libxml.h"
#ifdef LIBXML_XPATH_ENABLED

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
#ifdef HAVE_SIGNAL_H
#include <signal.h>
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
double xmlXPathDivideBy(double f, double fzero);

/************************************************************************
 * 									*
 * 			Floating point stuff				*
 * 									*
 ************************************************************************/

/*
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
 * xmlXPathDivideBy:
 *
 * The best way found so far to generate the NAN, +-INF
 * without hitting a compiler bug or optimization :-\
 *
 * Returns the double resulting from the division
 */
double
xmlXPathDivideBy(double f, double fzero) {
    float ret;
#ifdef HAVE_SIGNAL
#ifdef SIGFPE
#ifdef SIG_IGN
    void (*sighandler)(int);
    sighandler = signal(SIGFPE, SIG_IGN);
#endif
#endif
#endif
    ret = f / fzero;
#ifdef HAVE_SIGNAL
#ifdef SIGFPE
#ifdef SIG_IGN
    signal(SIGFPE, sighandler);
#endif
#endif
#endif
    return(ret);
}

/**
 * xmlXPathInit:
 *
 * Initialize the XPath environment
 */
void
xmlXPathInit(void) {
    static int initialized = 0;

    if (initialized) return;

    xmlXPathNAN = xmlXPathDivideBy(0.0, 0.0);
    xmlXPathPINF = xmlXPathDivideBy(1.0, 0.0);
    xmlXPathPINF = xmlXPathDivideBy(-1.0, 0.0);

    initialized = 1;
}

/************************************************************************
 * 									*
 * 			Parser Types					*
 * 									*
 ************************************************************************/

/*
 * Types are private:
 */

typedef enum {
    XPATH_OP_END=0,
    XPATH_OP_AND,
    XPATH_OP_OR,
    XPATH_OP_EQUAL,
    XPATH_OP_CMP,
    XPATH_OP_PLUS,
    XPATH_OP_MULT,
    XPATH_OP_UNION,
    XPATH_OP_ROOT,
    XPATH_OP_NODE,
    XPATH_OP_RESET,
    XPATH_OP_COLLECT,
    XPATH_OP_VALUE,
    XPATH_OP_VARIABLE,
    XPATH_OP_FUNCTION,
    XPATH_OP_ARG,
    XPATH_OP_PREDICATE,
    XPATH_OP_FILTER,
    XPATH_OP_SORT
#ifdef LIBXML_XPTR_ENABLED
    ,XPATH_OP_RANGETO
#endif
} xmlXPathOp;

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


typedef struct _xmlXPathStepOp xmlXPathStepOp;
typedef xmlXPathStepOp *xmlXPathStepOpPtr;
struct _xmlXPathStepOp {
    xmlXPathOp op;
    int ch1;
    int ch2;
    int value;
    int value2;
    int value3;
    void *value4;
    void *value5;
    void *cache;
};

struct _xmlXPathCompExpr {
    int nbStep;
    int maxStep;
    xmlXPathStepOp *steps;        /* ops for computation */
    int last;
};

/************************************************************************
 * 									*
 * 			Parser Type functions 				*
 * 									*
 ************************************************************************/

/**
 * xmlXPathNewCompExpr:
 *
 * Create a new Xpath component
 *
 * Returns the newly allocated xmlXPathCompExprPtr or NULL in case of error
 */
static xmlXPathCompExprPtr
xmlXPathNewCompExpr(void) {
    xmlXPathCompExprPtr cur;

    cur = (xmlXPathCompExprPtr) xmlMalloc(sizeof(xmlXPathCompExpr));
    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewCompExpr : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlXPathCompExpr));
    cur->maxStep = 10;
    cur->nbStep = 0;
    cur->steps = (xmlXPathStepOp *) xmlMalloc(cur->maxStep *
	                                   sizeof(xmlXPathStepOp));
    if (cur->steps == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewCompExpr : malloc failed\n");
	xmlFree(cur);
	return(NULL);
    }
    memset(cur->steps, 0, cur->maxStep * sizeof(xmlXPathStepOp));
    cur->last = -1;
    return(cur);
}

/**
 * xmlXPathFreeCompExpr:
 * @comp:  an XPATH comp
 *
 * Free up the memory allocated by @comp
 */
void
xmlXPathFreeCompExpr(xmlXPathCompExprPtr comp) {
    xmlXPathStepOpPtr op;
    int i;

    if (comp == NULL)
	return;
    for (i = 0;i < comp->nbStep;i++) {
	op = &comp->steps[i];
	if (op->value4 != NULL) {
	    if (op->op == XPATH_OP_VALUE)
		xmlXPathFreeObject(op->value4);
	    else
		xmlFree(op->value4);
	}
	if (op->value5 != NULL)
	    xmlFree(op->value5);
    }
    if (comp->steps != NULL) {
	xmlFree(comp->steps);
    }
    xmlFree(comp);
}

/**
 * xmlXPathCompExprAdd:
 * @comp:  the compiled expression
 * @ch1: first child index
 * @ch2: second child index
 * @op:  an op
 * @value:  the first int value
 * @value2:  the second int value
 * @value3:  the third int value
 * @value4:  the first string value
 * @value5:  the second string value
 *
 * Add an step to an XPath Compiled Expression
 *
 * Returns -1 in case of failure, the index otherwise
 */
static int
xmlXPathCompExprAdd(xmlXPathCompExprPtr comp, int ch1, int ch2,
   xmlXPathOp op, int value,
   int value2, int value3, void *value4, void *value5) {
    if (comp->nbStep >= comp->maxStep) {
	xmlXPathStepOp *real;

	comp->maxStep *= 2;
	real = (xmlXPathStepOp *) xmlRealloc(comp->steps,
		                      comp->maxStep * sizeof(xmlXPathStepOp));
	if (real == NULL) {
	    comp->maxStep /= 2;
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathCompExprAdd : realloc failed\n");
	    return(-1);
	}
	comp->steps = real;
    }
    comp->last = comp->nbStep;
    comp->steps[comp->nbStep].ch1 = ch1;
    comp->steps[comp->nbStep].ch2 = ch2;
    comp->steps[comp->nbStep].op = op;
    comp->steps[comp->nbStep].value = value;
    comp->steps[comp->nbStep].value2 = value2;
    comp->steps[comp->nbStep].value3 = value3;
    comp->steps[comp->nbStep].value4 = value4;
    comp->steps[comp->nbStep].value5 = value5;
    comp->steps[comp->nbStep].cache = NULL;
    return(comp->nbStep++);
}

#define PUSH_FULL_EXPR(op, op1, op2, val, val2, val3, val4, val5)	\
    xmlXPathCompExprAdd(ctxt->comp, (op1), (op2),			\
	                (op), (val), (val2), (val3), (val4), (val5))
#define PUSH_LONG_EXPR(op, val, val2, val3, val4, val5)			\
    xmlXPathCompExprAdd(ctxt->comp, ctxt->comp->last, -1,		\
	                (op), (val), (val2), (val3), (val4), (val5))

#define PUSH_LEAVE_EXPR(op, val, val2) 					\
xmlXPathCompExprAdd(ctxt->comp, -1, -1, (op), (val), (val2), 0 ,NULL ,NULL)

#define PUSH_UNARY_EXPR(op, ch, val, val2) 				\
xmlXPathCompExprAdd(ctxt->comp, (ch), -1, (op), (val), (val2), 0 ,NULL ,NULL)

#define PUSH_BINARY_EXPR(op, ch1, ch2, val, val2) 			\
xmlXPathCompExprAdd(ctxt->comp, (ch1), (ch2), (op), (val), (val2), 0 ,NULL ,NULL)

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
static void
xmlXPathDebugDumpNode(FILE *output, xmlNodePtr cur, int depth) {
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
static void
xmlXPathDebugDumpNodeList(FILE *output, xmlNodePtr cur, int depth) {
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

static void
xmlXPathDebugDumpNodeSet(FILE *output, xmlNodeSetPtr cur, int depth) {
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

    if (cur != NULL) {
	fprintf(output, "Set contains %d nodes:\n", cur->nodeNr);
	for (i = 0;i < cur->nodeNr;i++) {
	    fprintf(output, shift);
	    fprintf(output, "%d", i + 1);
	    xmlXPathDebugDumpNode(output, cur->nodeTab[i], depth + 1);
	}
    }
}

static void
xmlXPathDebugDumpValueTree(FILE *output, xmlNodeSetPtr cur, int depth) {
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
static void
xmlXPathDebugDumpLocationSet(FILE *output, xmlLocationSetPtr cur, int depth) {
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

/**
 * xmlXPathDebugDumpObject:
 * @output:  the FILE * to dump the output
 * @cur:  the object to inspect
 * @depth:  indentation level
 *
 * Dump the content of the object for debugging purposes
 */
void
xmlXPathDebugDumpObject(FILE *output, xmlXPathObjectPtr cur, int depth) {
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
	    switch (isinf(cur->floatval)) {
	    case 1:
		fprintf(output, "Object is a number : +Infinity\n");
		break;
	    case -1:
		fprintf(output, "Object is a number : -Infinity\n");
		break;
	    default:
		if (isnan(cur->floatval)) {
		    fprintf(output, "Object is a number : NaN\n");
		} else {
		    fprintf(output, "Object is a number : %0g\n", cur->floatval);
		}
	    }
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

static void
xmlXPathDebugDumpStepOp(FILE *output, xmlXPathCompExprPtr comp,
	                     xmlXPathStepOpPtr op, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);
    if (op == NULL) {
	fprintf(output, "Step is NULL\n");
	return;
    }
    switch (op->op) {
        case XPATH_OP_END:
	    fprintf(output, "END"); break;
        case XPATH_OP_AND:
	    fprintf(output, "AND"); break;
        case XPATH_OP_OR:
	    fprintf(output, "OR"); break;
        case XPATH_OP_EQUAL:
	     if (op->value)
		 fprintf(output, "EQUAL =");
	     else
		 fprintf(output, "EQUAL !=");
	     break;
        case XPATH_OP_CMP:
	     if (op->value)
		 fprintf(output, "CMP <");
	     else
		 fprintf(output, "CMP >");
	     if (!op->value2)
		 fprintf(output, "=");
	     break;
        case XPATH_OP_PLUS:
	     if (op->value == 0)
		 fprintf(output, "PLUS -");
	     else if (op->value == 1)
		 fprintf(output, "PLUS +");
	     else if (op->value == 2)
		 fprintf(output, "PLUS unary -");
	     else if (op->value == 3)
		 fprintf(output, "PLUS unary - -");
	     break;
        case XPATH_OP_MULT:
	     if (op->value == 0)
		 fprintf(output, "MULT *");
	     else if (op->value == 1)
		 fprintf(output, "MULT div");
	     else
		 fprintf(output, "MULT mod");
	     break;
        case XPATH_OP_UNION:
	     fprintf(output, "UNION"); break;
        case XPATH_OP_ROOT:
	     fprintf(output, "ROOT"); break;
        case XPATH_OP_NODE:
	     fprintf(output, "NODE"); break;
        case XPATH_OP_RESET:
	     fprintf(output, "RESET"); break;
        case XPATH_OP_SORT:
	     fprintf(output, "SORT"); break;
        case XPATH_OP_COLLECT: {
	    xmlXPathAxisVal axis = op->value;
	    xmlXPathTestVal test = op->value2;
	    xmlXPathTypeVal type = op->value3;
	    const xmlChar *prefix = op->value4;
	    const xmlChar *name = op->value5;

	    fprintf(output, "COLLECT ");
	    switch (axis) {
		case AXIS_ANCESTOR:
		    fprintf(output, " 'ancestors' "); break;
		case AXIS_ANCESTOR_OR_SELF:
		    fprintf(output, " 'ancestors-or-self' "); break;
		case AXIS_ATTRIBUTE:
		    fprintf(output, " 'attributes' "); break;
		case AXIS_CHILD:
		    fprintf(output, " 'child' "); break;
		case AXIS_DESCENDANT:
		    fprintf(output, " 'descendant' "); break;
		case AXIS_DESCENDANT_OR_SELF:
		    fprintf(output, " 'descendant-or-self' "); break;
		case AXIS_FOLLOWING:
		    fprintf(output, " 'following' "); break;
		case AXIS_FOLLOWING_SIBLING:
		    fprintf(output, " 'following-siblings' "); break;
		case AXIS_NAMESPACE:
		    fprintf(output, " 'namespace' "); break;
		case AXIS_PARENT:
		    fprintf(output, " 'parent' "); break;
		case AXIS_PRECEDING:
		    fprintf(output, " 'preceding' "); break;
		case AXIS_PRECEDING_SIBLING:
		    fprintf(output, " 'preceding-sibling' "); break;
		case AXIS_SELF:
		    fprintf(output, " 'self' "); break;
	    }
	    switch (test) {
                case NODE_TEST_NONE:
		    fprintf(output, "'none' "); break;
                case NODE_TEST_TYPE:
		    fprintf(output, "'type' "); break;
                case NODE_TEST_PI:
		    fprintf(output, "'PI' "); break;
                case NODE_TEST_ALL:
		    fprintf(output, "'all' "); break;
                case NODE_TEST_NS:
		    fprintf(output, "'namespace' "); break;
                case NODE_TEST_NAME:
		    fprintf(output, "'name' "); break;
	    }
	    switch (type) {
                case NODE_TYPE_NODE:
		    fprintf(output, "'node' "); break;
                case NODE_TYPE_COMMENT:
		    fprintf(output, "'comment' "); break;
                case NODE_TYPE_TEXT:
		    fprintf(output, "'text' "); break;
                case NODE_TYPE_PI:
		    fprintf(output, "'PI' "); break;
	    }
	    if (prefix != NULL)
		fprintf(output, "%s:", prefix);
	    if (name != NULL)
		fprintf(output, "%s", name);
	    break;

        }
	case XPATH_OP_VALUE: {
	    xmlXPathObjectPtr object = (xmlXPathObjectPtr) op->value4;

	    fprintf(output, "ELEM ");
	    xmlXPathDebugDumpObject(output, object, 0);
	    goto finish;
	}
	case XPATH_OP_VARIABLE: {
	    const xmlChar *prefix = op->value5;
	    const xmlChar *name = op->value4;

	    if (prefix != NULL)
		fprintf(output, "VARIABLE %s:%s", prefix, name);
	    else
		fprintf(output, "VARIABLE %s", name);
	    break;
	}
	case XPATH_OP_FUNCTION: {
	    int nbargs = op->value;
	    const xmlChar *prefix = op->value5;
	    const xmlChar *name = op->value4;

	    if (prefix != NULL)
		fprintf(output, "FUNCTION %s:%s(%d args)",
			prefix, name, nbargs);
	    else
		fprintf(output, "FUNCTION %s(%d args)", name, nbargs);
	    break;
	}
        case XPATH_OP_ARG: fprintf(output, "ARG"); break;
        case XPATH_OP_PREDICATE: fprintf(output, "PREDICATE"); break;
        case XPATH_OP_FILTER: fprintf(output, "FILTER"); break;
#ifdef LIBXML_XPTR_ENABLED
        case XPATH_OP_RANGETO: fprintf(output, "RANGETO"); break;
#endif
	default:
        fprintf(output, "UNKNOWN %d\n", op->op); return;
    }
    fprintf(output, "\n");
finish:
    if (op->ch1 >= 0)
	xmlXPathDebugDumpStepOp(output, comp, &comp->steps[op->ch1], depth + 1);
    if (op->ch2 >= 0)
	xmlXPathDebugDumpStepOp(output, comp, &comp->steps[op->ch2], depth + 1);
}

void
xmlXPathDebugDumpCompExpr(FILE *output, xmlXPathCompExprPtr comp,
	                  int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);

    if (comp == NULL) {
	fprintf(output, "Compiled Expression is NULL\n");
	return;
    }
    fprintf(output, "Compiled Expression : %d elements\n",
	    comp->nbStep);
    i = comp->last;
    xmlXPathDebugDumpStepOp(output, comp, &comp->steps[i], depth + 1);
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
#define CUR_CHAR(l) xmlXPathCurrentChar(ctxt, &l)

#define COPY_BUF(l,b,i,v)                                              \
    if (l == 1) b[i++] = (xmlChar) v;                                  \
    else i += xmlCopyChar(l,&b[i],v)

#define NEXTL(l)  ctxt->cur += l

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
	    /* 3 is sign, decimal point, and terminating zero */
	    char work[DBL_DIG + EXPONENT_DIGITS + 3];
	    int integer_place, fraction_place;
	    char *ptr;
	    char *after_fraction;
	    double absolute_value;
	    int size;

	    absolute_value = fabs(number);

	    /*
	     * First choose format - scientific or regular floating point.
	     * In either case, result is in work, and after_fraction points
	     * just past the fractional part.
	    */
	    if ( ((absolute_value > UPPER_DOUBLE) ||
		  (absolute_value < LOWER_DOUBLE)) &&
		 (absolute_value != 0.0) ) {
		/* Use scientific notation */
		integer_place = DBL_DIG + EXPONENT_DIGITS + 1;
		fraction_place = DBL_DIG - 1;
		snprintf(work, sizeof(work),"%*.*e",
			 integer_place, fraction_place, number);
		after_fraction = strchr(work + DBL_DIG, 'e');
	    }
	    else {
		/* Use regular notation */
		integer_place = 1 + (int)log10(absolute_value);
		fraction_place = (integer_place > 0)
		    ? DBL_DIG - integer_place
		    : DBL_DIG;
		size = snprintf(work, sizeof(work), "%0.*f",
				fraction_place, number);
		after_fraction = work + size;
	    }

	    /* Remove fractional trailing zeroes */
	    ptr = after_fraction;
	    while (*(--ptr) == '0')
		;
	    if (*ptr != '.')
	        ptr++;
	    strcpy(ptr, after_fraction);

	    /* Finally copy result back to caller */
	    size = strlen(work) + 1;
	    if (size > buffersize) {
		work[buffersize - 1] = 0;
		size = buffersize;
	    }
	    memcpy(buffer, work, size);
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
    "Undefined namespace prefix",
    "Encoding error",
    "Char out of XML range"
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
    if ((cur == NULL) || (base == NULL))
	return;

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
    if ((node1->type == XML_NAMESPACE_DECL) ||
        (node2->type == XML_NAMESPACE_DECL))
	return(1);
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
    int i, j, initNr, skip;

    if (val2 == NULL) return(val1);
    if (val1 == NULL) {
	val1 = xmlXPathNodeSetCreate(NULL);
    }

    initNr = val1->nodeNr;

    for (i = 0;i < val2->nodeNr;i++) {
	/*
	 * check against doublons
	 */
	skip = 0;
	for (j = 0; j < initNr; j++) {
	    if (val1->nodeTab[j] == val2->nodeTab[i]) {
		skip = 1;
		break;
	    }
	}
	if (skip)
	    continue;

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
	xmlFree(obj->nodeTab);
    }
    xmlFree(obj);
}

/**
 * xmlXPathFreeValueTree:
 * @obj:  the xmlNodeSetPtr to free
 *
 * Free the NodeSet compound and the actual tree, this is different
 * from xmlXPathFreeNodeSet()
 */
static void
xmlXPathFreeValueTree(xmlNodeSetPtr obj) {
    int i;

    if (obj == NULL) return;
    for (i = 0;i < obj->nodeNr;i++)
        if (obj->nodeTab[i] != NULL)
	    xmlFreeNodeList(obj->nodeTab[i]);

    if (obj->nodeTab != NULL) {
	xmlFree(obj->nodeTab);
    }
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

    if (ctxt->namespaces != NULL) {
	int i;

	for (i = 0;i < ctxt->nsNr;i++) {
	    if ((ctxt->namespaces[i] != NULL) &&
		(xmlStrEqual(ctxt->namespaces[i]->prefix, prefix)))
		return(ctxt->namespaces[i]->href);
	}
    }

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

    ret->comp = xmlXPathNewCompExpr();
    if (ret->comp == NULL) {
	xmlFree(ret->valueTab);
	xmlFree(ret);
	return(NULL);
    }

    return(ret);
}

/**
 * xmlXPathCompParserContext:
 * @comp:  the XPath compiled expression
 * @ctxt:  the XPath context
 *
 * Create a new xmlXPathParserContext when processing a compiled expression
 *
 * Returns the xmlXPathParserContext just allocated.
 */
static xmlXPathParserContextPtr
xmlXPathCompParserContext(xmlXPathCompExprPtr comp, xmlXPathContextPtr ctxt) {
    xmlXPathParserContextPtr ret;

    ret = (xmlXPathParserContextPtr) xmlMalloc(sizeof(xmlXPathParserContext));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewParserContext: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathParserContext));

    /* Allocate the value stack */
    ret->valueTab = (xmlXPathObjectPtr *) 
                     xmlMalloc(10 * sizeof(xmlXPathObjectPtr));
    if (ret->valueTab == NULL) {
	xmlFree(ret);
        xmlGenericError(xmlGenericErrorContext,
		"xmlXPathNewParserContext: out of memory\n");
	return(NULL);
    }
    ret->valueNr = 0;
    ret->valueMax = 10;
    ret->value = NULL;

    ret->context = ctxt;
    ret->comp = comp;

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
        xmlFree(ctxt->valueTab);
    }
    if (ctxt->comp)
	xmlXPathFreeCompExpr(ctxt->comp);
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
static int
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
    if (ns != NULL) {
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
static int
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
    if (ns != NULL) {
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
    }
    xmlXPathFreeObject(arg);
    xmlXPathFreeObject(s);
    return(ret);
}

/**
 * xmlXPathCompareNodeSets:
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
static int
xmlXPathCompareNodeSets(int inf, int strict,
	                xmlXPathObjectPtr arg1, xmlXPathObjectPtr arg2) {
    int i, j, init = 0;
    double val1;
    double *values2;
    int ret = 0;
    xmlChar *str;
    xmlNodeSetPtr ns1;
    xmlNodeSetPtr ns2;

    if ((arg1 == NULL) ||
	((arg1->type != XPATH_NODESET) && (arg1->type != XPATH_XSLT_TREE))) {
	xmlXPathFreeObject(arg2);
        return(0);
    }
    if ((arg2 == NULL) ||
	((arg2->type != XPATH_NODESET) && (arg2->type != XPATH_XSLT_TREE))) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
        return(0);
    }

    ns1 = arg1->nodesetval;
    ns2 = arg2->nodesetval;

    if ((ns1 == NULL) || (ns1->nodeNr <= 0)) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
	return(0);
    }
    if ((ns2 == NULL) || (ns2->nodeNr <= 0)) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
	return(0);
    }

    values2 = (double *) xmlMalloc(ns2->nodeNr * sizeof(double));
    if (values2 == NULL) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
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
    xmlXPathFreeObject(arg1);
    xmlXPathFreeObject(arg2);
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
static int
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
	    return(xmlXPathCompareNodeSets(inf, strict, arg, val));
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
static int
xmlXPathEqualNodeSetString(xmlXPathObjectPtr arg, const xmlChar *str) {
    int i;
    xmlNodeSetPtr ns;
    xmlChar *str2;

    if ((str == NULL) || (arg == NULL) ||
	((arg->type != XPATH_NODESET) && (arg->type != XPATH_XSLT_TREE)))
        return(0);
    ns = arg->nodesetval;
    if (ns == NULL)
	return(0);
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
static int
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
static int
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

    if ((ns1 == NULL) || (ns1->nodeNr <= 0))
	return(0);
    if ((ns2 == NULL) || (ns2->nodeNr <= 0))
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
	    ret = xmlXPathCompareNodeSets(inf, strict, arg1, arg2);
	} else {
	    if (arg1->type == XPATH_NODESET) {
		ret = xmlXPathCompareNodeSetValue(ctxt, inf, strict,
			                          arg1, arg2);
	    } else {
		ret = xmlXPathCompareNodeSetValue(ctxt, !inf, strict,
			                          arg2, arg1);
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
#ifdef LIBXML_DOCB_ENABLED
	    case XML_DOCB_DOCUMENT_NODE:
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
#ifdef LIBXML_DOCB_ENABLED
	    case XML_DOCB_DOCUMENT_NODE:
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
		xmlAttrPtr tmp = (xmlAttrPtr) ctxt->context->node;

		return(tmp->parent);
	    }
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	    case XML_DOCB_DOCUMENT_NODE:
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
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
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
    if (ctxt->context->node == NULL)
	return(NULL);
    if (ctxt->context->node->type != XML_ELEMENT_NODE)
	return(NULL);
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

#define IS_FUNCTION			200


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

    if ((cur == NULL) || (cur->nodesetval == NULL))
	valuePush(ctxt, xmlXPathNewFloat((double) 0));
    else
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

	if (obj->nodesetval != NULL) {
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

    if ((cur->nodesetval == NULL) || (cur->nodesetval->nodeNr == 0)) {
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

    if ((cur->nodesetval == NULL) || (cur->nodesetval->nodeNr == 0)) {
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
static void
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

    if ((cur->nodesetval == NULL) || (cur->nodesetval->nodeNr == 0)) {
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
		snprintf(name, sizeof(name), "%s:%s", 
			 (char *) cur->nodesetval->nodeTab[i]->ns->prefix,
			 (char *) cur->nodesetval->nodeTab[i]->name);
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
 * xmlXPathConvertString:
 * @val:  an XPath object
 *
 * Converts an existing object to its string() equivalent
 *
 * Returns the new object, the old one is freed (or the operation
 *         is done directly on @val)
 */
xmlXPathObjectPtr
xmlXPathConvertString(xmlXPathObjectPtr val) {
    xmlXPathObjectPtr ret = NULL;

    if (val == NULL)
	return(xmlXPathNewCString(""));
    switch (val->type) {
	case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
	    xmlGenericError(xmlGenericErrorContext, "String: undefined\n");
#endif
	    ret = xmlXPathNewCString("");
	    break;
        case XPATH_XSLT_TREE:
        case XPATH_NODESET:
	    if ((val->nodesetval == NULL) || (val->nodesetval->nodeNr == 0)) {
		ret = xmlXPathNewCString("");
	    } else {
		xmlChar *res;

		xmlXPathNodeSetSort(val->nodesetval);
		res = xmlNodeGetContent(val->nodesetval->nodeTab[0]);
		/* TODO: avoid allocating res to free it */
		ret = xmlXPathNewString(res);
		if (res != NULL)
		    xmlFree(res);
	    }
	    break;
	case XPATH_STRING:
	    return(val);
        case XPATH_BOOLEAN:
	    if (val->boolval) ret = xmlXPathNewCString("true");
	    else ret = xmlXPathNewCString("false");
	    break;
	case XPATH_NUMBER: {
	    char buf[100];

	    xmlXPathFormatNumber(val->floatval, buf, sizeof(buf));
	    ret = xmlXPathNewCString(buf);
	    break;
	}
	case XPATH_USERS:
	case XPATH_POINT:
	case XPATH_RANGE:
	case XPATH_LOCATIONSET:
	    TODO
	    ret = xmlXPathNewCString("");
	    break;
    }
    xmlXPathFreeObject(val);
    return(ret);
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
    cur = xmlXPathConvertString(cur);
    valuePush(ctxt, cur);
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
	    valuePush(ctxt, xmlXPathNewFloat(xmlUTF8Strlen(content)));
	    xmlFree(content);
	}
	return;
    }
    CHECK_ARITY(1);
    CAST_TO_STRING;
    CHECK_TYPE(XPATH_STRING);
    cur = valuePop(ctxt);
    valuePush(ctxt, xmlXPathNewFloat(xmlUTF8Strlen(cur->stringval)));
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
     * TODO: need to be converted to UTF8 strings
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

    /* 
     * TODO: need to be converted to UTF8 strings
     */
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
 * xmlXPathConvertBoolean:
 * @val:  an XPath object
 *
 * Converts an existing object to its boolean() equivalent
 *
 * Returns the new object, the old one is freed (or the operation
 *         is done directly on @val)
 */
xmlXPathObjectPtr
xmlXPathConvertBoolean(xmlXPathObjectPtr val) {
    int res = 0;

    if (val == NULL)
	return(NULL);
    switch (val->type) {
        case XPATH_NODESET:
        case XPATH_XSLT_TREE:
	    if ((val->nodesetval == NULL) ||
	        (val->nodesetval->nodeNr == 0)) res = 0;
	    else 
	        res = 1;
	    break;
	case XPATH_STRING:
	    if ((val->stringval == NULL) ||
	        (val->stringval[0] == 0)) res = 0;
	    else 
	        res = 1;
	    break;
        case XPATH_BOOLEAN:
	    return(val);
	case XPATH_NUMBER:
	    if (val->floatval) res = 1;
	    break;
	default:
	    STRANGE
    }
    xmlXPathFreeObject(val);
    return(xmlXPathNewBoolean(res));
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

    CHECK_ARITY(1);
    cur = valuePop(ctxt);
    if (cur == NULL) XP_ERROR(XPATH_INVALID_OPERAND);
    cur = xmlXPathConvertBoolean(cur);
    valuePush(ctxt, cur);
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
 * xmlXPathConvertNumber:
 * @val:  an XPath object
 *
 * Converts an existing object to its number() equivalent
 *
 * Returns the new object, the old one is freed (or the operation
 *         is done directly on @val)
 */
xmlXPathObjectPtr
xmlXPathConvertNumber(xmlXPathObjectPtr val) {
    xmlXPathObjectPtr ret = NULL;
    double res;

    if (val == NULL)
	return(xmlXPathNewFloat(0.0));
    switch (val->type) {
	case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
	    xmlGenericError(xmlGenericErrorContext, "NUMBER: undefined\n");
#endif
	    ret = xmlXPathNewFloat(0.0);
	    break;
        case XPATH_XSLT_TREE:
        case XPATH_NODESET:
	    val = xmlXPathConvertString(val);
	    /* no break on purpose */
	case XPATH_STRING:
	    res = xmlXPathStringEvalNumber(val->stringval);
	    ret = xmlXPathNewFloat(res);
	    break;
        case XPATH_BOOLEAN:
	    if (val->boolval) ret = xmlXPathNewFloat(1.0);
	    else ret = xmlXPathNewFloat(0.0);
	    break;
	case XPATH_NUMBER:
	    return(val);
	case XPATH_USERS:
	case XPATH_POINT:
	case XPATH_RANGE:
	case XPATH_LOCATIONSET:
	    TODO
	    ret = xmlXPathNewFloat(0.0);
	    break;
    }
    xmlXPathFreeObject(val);
    return(ret);
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
    cur = xmlXPathConvertNumber(cur);
    valuePush(ctxt, cur);
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

    if ((cur->nodesetval == NULL) || (cur->nodesetval->nodeNr == 0)) {
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
static void xmlXPathCompileExpr(xmlXPathParserContextPtr ctxt);
static void xmlXPathCompPredicate(xmlXPathParserContextPtr ctxt, int filter);
static void xmlXPathCompLocationPath(xmlXPathParserContextPtr ctxt);
#ifdef VMS
static void xmlXPathCompRelLocationPath(xmlXPathParserContextPtr ctxt);
#define xmlXPathCompRelativeLocationPath xmlXPathCompRelLocationPath 
#else 
static void xmlXPathCompRelativeLocationPath(xmlXPathParserContextPtr ctxt);
#endif
static xmlChar * xmlXPathParseNameComplex(xmlXPathParserContextPtr ctxt,
	                                  int qualified);

/**
 * xmlXPathCurrentChar:
 * @ctxt:  the XPath parser context
 * @cur:  pointer to the beginning of the char
 * @len:  pointer to the length of the char read
 *
 * The current char value, if using UTF-8 this may actaully span multiple
 * bytes in the input buffer.
 *
 * Returns the current char value and its lenght
 */

static int
xmlXPathCurrentChar(xmlXPathParserContextPtr ctxt, int *len) {
    unsigned char c;
    unsigned int val;
    const xmlChar *cur;

    if (ctxt == NULL)
	return(0);
    cur = ctxt->cur;

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
	    val |= cur[1] & 0x3f;
	}
	if (!IS_CHAR(val)) {
	    XP_ERROR0(XPATH_INVALID_CHAR_ERROR);
	}    
	return(val);
    } else {
	/* 1-byte code */
	*len = 1;
	return((int) *cur);
    }
encoding_error:
    /*
     * If we detect an UTF8 error that probably mean that the
     * input encoding didn't get properly advertized in the
     * declaration header. Report the error and switch the encoding
     * to ISO-Latin-1 (if you don't like this policy, just declare the
     * encoding !)
     */
    XP_ERROR0(XPATH_ENCODING_ERROR);
    *len = 1;
    return((int) *cur);
}

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
    const xmlChar *in;
    xmlChar *ret;
    int count = 0;

    /*
     * Accelerator for simple ASCII names
     */
    in = ctxt->cur;
    if (((*in >= 0x61) && (*in <= 0x7A)) ||
	((*in >= 0x41) && (*in <= 0x5A)) ||
	(*in == '_')) {
	in++;
	while (((*in >= 0x61) && (*in <= 0x7A)) ||
	       ((*in >= 0x41) && (*in <= 0x5A)) ||
	       ((*in >= 0x30) && (*in <= 0x39)) ||
	       (*in == '_'))
	    in++;
	if ((*in == ' ') || (*in == '>') || (*in == '/') ||
            (*in == '[') || (*in == ']') || (*in == ':') ||
            (*in == '@') || (*in == '*')) {
	    count = in - ctxt->cur;
	    if (count == 0)
		return(NULL);
	    ret = xmlStrndup(ctxt->cur, count);
	    ctxt->cur = in;
	    return(ret);
	}
    }
    return(xmlXPathParseNameComplex(ctxt, 0));
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

static xmlChar *
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
    const xmlChar *in;
    xmlChar *ret;
    int count = 0;

    /*
     * Accelerator for simple ASCII names
     */
    in = ctxt->cur;
    if (((*in >= 0x61) && (*in <= 0x7A)) ||
	((*in >= 0x41) && (*in <= 0x5A)) ||
	(*in == '_') || (*in == ':')) {
	in++;
	while (((*in >= 0x61) && (*in <= 0x7A)) ||
	       ((*in >= 0x41) && (*in <= 0x5A)) ||
	       ((*in >= 0x30) && (*in <= 0x39)) ||
	       (*in == '_') || (*in == ':'))
	    in++;
	if ((*in == ' ') || (*in == '>') || (*in == '/')) {
	    count = in - ctxt->cur;
	    ret = xmlStrndup(ctxt->cur, count);
	    ctxt->cur = in;
	    return(ret);
	}
    }
    return(xmlXPathParseNameComplex(ctxt, 1));
}

static xmlChar *
xmlXPathParseNameComplex(xmlXPathParserContextPtr ctxt, int qualified) {
    xmlChar buf[XML_MAX_NAMELEN + 5];
    int len = 0, l;
    int c;

    /*
     * Handler for more complex cases
     */
    c = CUR_CHAR(l);
    if ((c == ' ') || (c == '>') || (c == '/') || /* accelerators */
        (c == '[') || (c == ']') || (c == '@') || /* accelerators */
        (c == '*') || /* accelerators */
	(!IS_LETTER(c) && (c != '_') &&
         ((qualified) && (c != ':')))) {
	return(NULL);
    }

    while ((c != ' ') && (c != '>') && (c != '/') && /* test bigname.xml */
	   ((IS_LETTER(c)) || (IS_DIGIT(c)) ||
            (c == '.') || (c == '-') ||
	    (c == '_') || ((qualified) && (c == ':')) || 
	    (IS_COMBINING(c)) ||
	    (IS_EXTENDER(c)))) {
	COPY_BUF(l,buf,len,c);
	NEXTL(l);
	c = CUR_CHAR(l);
	if (len >= XML_MAX_NAMELEN) {
	    /*
	     * Okay someone managed to make a huge name, so he's ready to pay
	     * for the processing speed.
	     */
	    xmlChar *buffer;
	    int max = len * 2;
	    
	    buffer = (xmlChar *) xmlMalloc(max * sizeof(xmlChar));
	    if (buffer == NULL) {
		XP_ERROR0(XPATH_MEMORY_ERROR);
	    }
	    memcpy(buffer, buf, len);
	    while ((IS_LETTER(c)) || (IS_DIGIT(c)) || /* test bigname.xml */
		   (c == '.') || (c == '-') ||
		   (c == '_') || ((qualified) && (c == ':')) || 
		   (IS_COMBINING(c)) ||
		   (IS_EXTENDER(c))) {
		if (len + 10 > max) {
		    max *= 2;
		    buffer = (xmlChar *) xmlRealloc(buffer,
			                            max * sizeof(xmlChar));
		    XP_ERROR0(XPATH_MEMORY_ERROR);
		    if (buffer == NULL) {
			XP_ERROR0(XPATH_MEMORY_ERROR);
		    }
		}
		COPY_BUF(l,buffer,len,c);
		NEXTL(l);
		c = CUR_CHAR(l);
	    }
	    buffer[len] = 0;
	    return(buffer);
	}
    }
    if (len == 0)
	return(NULL);
    return(xmlStrndup(buf, len));
}
/**
 * xmlXPathStringEvalNumber:
 * @str:  A string to scan
 *
 *  [30a]  Float  ::= Number ('e' Digits?)?
 *
 *  [30]   Number ::=   Digits ('.' Digits?)?
 *                    | '.' Digits 
 *  [31]   Digits ::=   [0-9]+
 *
 * Compile a Number in the string
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
    int exponent = 0;
    int is_exponent_negative = 0;
    
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
    if ((*cur == 'e') || (*cur == 'E')) {
      cur++;
      if (*cur == '-') {
	is_exponent_negative = 1;
	cur++;
      }
      while ((*cur >= '0') && (*cur <= '9')) {
	exponent = exponent * 10 + (*cur - '0');
	cur++;
      }
    }
    while (IS_BLANK(*cur)) cur++;
    if (*cur != 0) return(xmlXPathNAN);
    if (isneg) ret = -ret;
    if (is_exponent_negative) exponent = -exponent;
    ret *= pow(10.0, (double)exponent);
    return(ret);
}

/**
 * xmlXPathCompNumber:
 * @ctxt:  the XPath Parser context
 *
 *  [30]   Number ::=   Digits ('.' Digits?)?
 *                    | '.' Digits 
 *  [31]   Digits ::=   [0-9]+
 *
 * Compile a Number, then push it on the stack
 *
 */
static void
xmlXPathCompNumber(xmlXPathParserContextPtr ctxt) {
    double ret = 0.0;
    double mult = 1;
    int ok = 0;
    int exponent = 0;
    int is_exponent_negative = 0;

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
    if ((CUR == 'e') || (CUR == 'E')) {
      NEXT;
      if (CUR == '-') {
	is_exponent_negative = 1;
	NEXT;
      }
      while ((CUR >= '0') && (CUR <= '9')) {
	exponent = exponent * 10 + (CUR - '0');
	NEXT;
      }
    }
    if (is_exponent_negative)
      exponent = -exponent;
    ret *= pow(10.0, (double)exponent);
    PUSH_LONG_EXPR(XPATH_OP_VALUE, XPATH_NUMBER, 0, 0,
	           xmlXPathNewFloat(ret), NULL);
}

/**
 * xmlXPathParseLiteral:
 * @ctxt:  the XPath Parser context
 *
 * Parse a Literal
 *
 *  [29]   Literal ::=   '"' [^"]* '"'
 *                    | "'" [^']* "'"
 *
 * Returns the value found or NULL in case of error
 */
static xmlChar *
xmlXPathParseLiteral(xmlXPathParserContextPtr ctxt) {
    const xmlChar *q;
    xmlChar *ret = NULL;

    if (CUR == '"') {
        NEXT;
	q = CUR_PTR;
	while ((IS_CHAR(CUR)) && (CUR != '"'))
	    NEXT;
	if (!IS_CHAR(CUR)) {
	    XP_ERROR0(XPATH_UNFINISHED_LITERAL_ERROR);
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
	    XP_ERROR0(XPATH_UNFINISHED_LITERAL_ERROR);
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
        }
    } else {
	XP_ERROR0(XPATH_START_LITERAL_ERROR);
    }
    return(ret);
}

/**
 * xmlXPathCompLiteral:
 * @ctxt:  the XPath Parser context
 *
 * Parse a Literal and push it on the stack.
 *
 *  [29]   Literal ::=   '"' [^"]* '"'
 *                    | "'" [^']* "'"
 *
 * TODO: xmlXPathCompLiteral memory allocation could be improved.
 */
static void
xmlXPathCompLiteral(xmlXPathParserContextPtr ctxt) {
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
    PUSH_LONG_EXPR(XPATH_OP_VALUE, XPATH_STRING, 0, 0,
	           xmlXPathNewString(ret), NULL);
    xmlFree(ret);
}

/**
 * xmlXPathCompVariableReference:
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
static void
xmlXPathCompVariableReference(xmlXPathParserContextPtr ctxt) {
    xmlChar *name;
    xmlChar *prefix;

    SKIP_BLANKS;
    if (CUR != '$') {
	XP_ERROR(XPATH_VARIABLE_REF_ERROR);
    }
    NEXT;
    name = xmlXPathParseQName(ctxt, &prefix);
    if (name == NULL) {
	XP_ERROR(XPATH_VARIABLE_REF_ERROR);
    }
    ctxt->comp->last = -1;
    PUSH_LONG_EXPR(XPATH_OP_VARIABLE, 0, 0, 0,
	           name, prefix);
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
 * xmlXPathCompFunctionCall:
 * @ctxt:  the XPath Parser context
 *
 *  [16]   FunctionCall ::=   FunctionName '(' ( Argument ( ',' Argument)*)? ')'
 *  [17]   Argument ::=   Expr 
 *
 * Compile a function call, the evaluation of all arguments are
 * pushed on the stack
 */
static void
xmlXPathCompFunctionCall(xmlXPathParserContextPtr ctxt) {
    xmlChar *name;
    xmlChar *prefix;
    int nbargs = 0;

    name = xmlXPathParseQName(ctxt, &prefix);
    if (name == NULL) {
	XP_ERROR(XPATH_EXPR_ERROR);
    }
    SKIP_BLANKS;
#ifdef DEBUG_EXPR
    if (prefix == NULL)
	xmlGenericError(xmlGenericErrorContext, "Calling function %s\n",
			name);
    else
	xmlGenericError(xmlGenericErrorContext, "Calling function %s:%s\n",
			prefix, name);
#endif

    if (CUR != '(') {
	XP_ERROR(XPATH_EXPR_ERROR);
    }
    NEXT;
    SKIP_BLANKS;

    ctxt->comp->last = -1;
    while (CUR != ')') {
	int op1 = ctxt->comp->last;
	ctxt->comp->last = -1;
        xmlXPathCompileExpr(ctxt);
	PUSH_BINARY_EXPR(XPATH_OP_ARG, op1, ctxt->comp->last, 0, 0);
	nbargs++;
	if (CUR == ')') break;
	if (CUR != ',') {
	    XP_ERROR(XPATH_EXPR_ERROR);
	}
	NEXT;
	SKIP_BLANKS;
    }
    PUSH_LONG_EXPR(XPATH_OP_FUNCTION, nbargs, 0, 0,
	           name, prefix);
    NEXT;
    SKIP_BLANKS;
}

/**
 * xmlXPathCompPrimaryExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [15]   PrimaryExpr ::=   VariableReference 
 *                | '(' Expr ')'
 *                | Literal 
 *                | Number 
 *                | FunctionCall 
 *
 * Compile a primary expression.
 */
static void
xmlXPathCompPrimaryExpr(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if (CUR == '$') xmlXPathCompVariableReference(ctxt);
    else if (CUR == '(') {
	NEXT;
	SKIP_BLANKS;
	xmlXPathCompileExpr(ctxt);
	if (CUR != ')') {
	    XP_ERROR(XPATH_EXPR_ERROR);
	}
	NEXT;
	SKIP_BLANKS;
    } else if (IS_DIGIT(CUR)) {
	xmlXPathCompNumber(ctxt);
    } else if ((CUR == '\'') || (CUR == '"')) {
	xmlXPathCompLiteral(ctxt);
    } else {
	xmlXPathCompFunctionCall(ctxt);
    }
    SKIP_BLANKS;
}

/**
 * xmlXPathCompFilterExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [20]   FilterExpr ::=   PrimaryExpr 
 *               | FilterExpr Predicate 
 *
 * Compile a filter expression.
 * Square brackets are used to filter expressions in the same way that
 * they are used in location paths. It is an error if the expression to
 * be filtered does not evaluate to a node-set. The context node list
 * used for evaluating the expression in square brackets is the node-set
 * to be filtered listed in document order.
 */

static void
xmlXPathCompFilterExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompPrimaryExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    
    while (CUR == '[') {
	xmlXPathCompPredicate(ctxt, 1);
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

static xmlChar *
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
 * xmlXPathCompPathExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [19]   PathExpr ::=   LocationPath 
 *               | FilterExpr 
 *               | FilterExpr '/' RelativeLocationPath 
 *               | FilterExpr '//' RelativeLocationPath 
 *
 * Compile a path expression.
 * The / operator and // operators combine an arbitrary expression
 * and a relative location path. It is an error if the expression
 * does not evaluate to a node-set.
 * The / operator does composition in the same way as when / is
 * used in a location path. As in location paths, // is short for
 * /descendant-or-self::node()/.
 */

static void
xmlXPathCompPathExpr(xmlXPathParserContextPtr ctxt) {
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
	if (CUR == '/') {
	    PUSH_LEAVE_EXPR(XPATH_OP_ROOT, 0, 0);
	} else {
	    PUSH_LEAVE_EXPR(XPATH_OP_NODE, 0, 0);
	}
	xmlXPathCompLocationPath(ctxt);
    } else {
	xmlXPathCompFilterExpr(ctxt);
	CHECK_ERROR;
	if ((CUR == '/') && (NXT(1) == '/')) {
	    SKIP(2);
	    SKIP_BLANKS;

	    PUSH_LONG_EXPR(XPATH_OP_COLLECT, AXIS_DESCENDANT_OR_SELF,
		    NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
	    PUSH_UNARY_EXPR(XPATH_OP_RESET, ctxt->comp->last, 1, 0);

	    xmlXPathCompRelativeLocationPath(ctxt);
	} else if (CUR == '/') {
	    xmlXPathCompRelativeLocationPath(ctxt);
	}
    }
    SKIP_BLANKS;
}

/**
 * xmlXPathCompUnionExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [18]   UnionExpr ::=   PathExpr 
 *               | UnionExpr '|' PathExpr 
 *
 * Compile an union expression.
 */

static void
xmlXPathCompUnionExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompPathExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while (CUR == '|') {
	int op1 = ctxt->comp->last;
	PUSH_LEAVE_EXPR(XPATH_OP_NODE, 0, 0);

	NEXT;
	SKIP_BLANKS;
	xmlXPathCompPathExpr(ctxt);

	PUSH_BINARY_EXPR(XPATH_OP_UNION, op1, ctxt->comp->last, 0, 0);

	SKIP_BLANKS;
    }
}

/**
 * xmlXPathCompUnaryExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [27]   UnaryExpr ::=   UnionExpr 
 *                   | '-' UnaryExpr 
 *
 * Compile an unary expression.
 */

static void
xmlXPathCompUnaryExpr(xmlXPathParserContextPtr ctxt) {
    int minus = 0;
    int found = 0;

    SKIP_BLANKS;
    while (CUR == '-') {
        minus = 1 - minus;
	found = 1;
	NEXT;
	SKIP_BLANKS;
    }

    xmlXPathCompUnionExpr(ctxt);
    CHECK_ERROR;
    if (found) {
	if (minus)
	    PUSH_UNARY_EXPR(XPATH_OP_PLUS, ctxt->comp->last, 2, 0);
	else
	    PUSH_UNARY_EXPR(XPATH_OP_PLUS, ctxt->comp->last, 3, 0);
    }
}

/**
 * xmlXPathCompMultiplicativeExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [26]   MultiplicativeExpr ::=   UnaryExpr 
 *                   | MultiplicativeExpr MultiplyOperator UnaryExpr 
 *                   | MultiplicativeExpr 'div' UnaryExpr 
 *                   | MultiplicativeExpr 'mod' UnaryExpr 
 *  [34]   MultiplyOperator ::=   '*'
 *
 * Compile an Additive expression.
 */

static void
xmlXPathCompMultiplicativeExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompUnaryExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '*') || 
           ((CUR == 'd') && (NXT(1) == 'i') && (NXT(2) == 'v')) ||
           ((CUR == 'm') && (NXT(1) == 'o') && (NXT(2) == 'd'))) {
	int op = -1;
	int op1 = ctxt->comp->last;

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
        xmlXPathCompUnaryExpr(ctxt);
	CHECK_ERROR;
	PUSH_BINARY_EXPR(XPATH_OP_MULT, op1, ctxt->comp->last, op, 0);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathCompAdditiveExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [25]   AdditiveExpr ::=   MultiplicativeExpr 
 *                   | AdditiveExpr '+' MultiplicativeExpr 
 *                   | AdditiveExpr '-' MultiplicativeExpr 
 *
 * Compile an Additive expression.
 */

static void
xmlXPathCompAdditiveExpr(xmlXPathParserContextPtr ctxt) {

    xmlXPathCompMultiplicativeExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '+') || (CUR == '-')) {
	int plus;
	int op1 = ctxt->comp->last;

        if (CUR == '+') plus = 1;
	else plus = 0;
	NEXT;
	SKIP_BLANKS;
        xmlXPathCompMultiplicativeExpr(ctxt);
	CHECK_ERROR;
	PUSH_BINARY_EXPR(XPATH_OP_PLUS, op1, ctxt->comp->last, plus, 0);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathCompRelationalExpr:
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
 * Compile a Relational expression, then push the result
 * on the stack
 */

static void
xmlXPathCompRelationalExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompAdditiveExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '<') ||
           (CUR == '>') ||
           ((CUR == '<') && (NXT(1) == '=')) ||
           ((CUR == '>') && (NXT(1) == '='))) {
	int inf, strict;
	int op1 = ctxt->comp->last;

        if (CUR == '<') inf = 1;
	else inf = 0;
	if (NXT(1) == '=') strict = 0;
	else strict = 1;
	NEXT;
	if (!strict) NEXT;
	SKIP_BLANKS;
        xmlXPathCompAdditiveExpr(ctxt);
	CHECK_ERROR;
	PUSH_BINARY_EXPR(XPATH_OP_CMP, op1, ctxt->comp->last, inf, strict);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathCompEqualityExpr:
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
 * Compile an Equality expression.
 *
 */
static void
xmlXPathCompEqualityExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompRelationalExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == '=') || ((CUR == '!') && (NXT(1) == '='))) {
	int eq;
	int op1 = ctxt->comp->last;

        if (CUR == '=') eq = 1;
	else eq = 0;
	NEXT;
	if (!eq) NEXT;
	SKIP_BLANKS;
        xmlXPathCompRelationalExpr(ctxt);
	CHECK_ERROR;
	PUSH_BINARY_EXPR(XPATH_OP_EQUAL, op1, ctxt->comp->last, eq, 0);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathCompAndExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [22]   AndExpr ::=   EqualityExpr 
 *                 | AndExpr 'and' EqualityExpr 
 *
 * Compile an AND expression.
 *
 */
static void
xmlXPathCompAndExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompEqualityExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == 'a') && (NXT(1) == 'n') && (NXT(2) == 'd')) {
	int op1 = ctxt->comp->last;
        SKIP(3);
	SKIP_BLANKS;
        xmlXPathCompEqualityExpr(ctxt);
	CHECK_ERROR;
	PUSH_BINARY_EXPR(XPATH_OP_AND, op1, ctxt->comp->last, 0, 0);
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathCompExpr:
 * @ctxt:  the XPath Parser context
 *
 *  [14]   Expr ::=   OrExpr 
 *  [21]   OrExpr ::=   AndExpr 
 *                 | OrExpr 'or' AndExpr 
 *
 * Parse and compile an expression
 */
static void
xmlXPathCompileExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompAndExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    while ((CUR == 'o') && (NXT(1) == 'r')) {
	int op1 = ctxt->comp->last;
        SKIP(2);
	SKIP_BLANKS;
        xmlXPathCompAndExpr(ctxt);
	CHECK_ERROR;
	PUSH_BINARY_EXPR(XPATH_OP_OR, op1, ctxt->comp->last, 0, 0);
	op1 = ctxt->comp->nbStep;
	SKIP_BLANKS;
    }
    if (ctxt->comp->steps[ctxt->comp->last].op != XPATH_OP_VALUE) {
	/* more ops could be optimized too */
	PUSH_UNARY_EXPR(XPATH_OP_SORT, ctxt->comp->last , 0, 0);
    }
}

/**
 * xmlXPathCompPredicate:
 * @ctxt:  the XPath Parser context
 * @filter:  act as a filter
 *
 *  [8]   Predicate ::=   '[' PredicateExpr ']'
 *  [9]   PredicateExpr ::=   Expr 
 *
 * Compile a predicate expression
 */
static void
xmlXPathCompPredicate(xmlXPathParserContextPtr ctxt, int filter) {
    int op1 = ctxt->comp->last;

    SKIP_BLANKS;
    if (CUR != '[') {
	XP_ERROR(XPATH_INVALID_PREDICATE_ERROR);
    }
    NEXT;
    SKIP_BLANKS;

    ctxt->comp->last = -1;
    xmlXPathCompileExpr(ctxt);
    CHECK_ERROR;

    if (CUR != ']') {
	XP_ERROR(XPATH_INVALID_PREDICATE_ERROR);
    }

    if (filter)
	PUSH_BINARY_EXPR(XPATH_OP_FILTER, op1, ctxt->comp->last, 0, 0);
    else
	PUSH_BINARY_EXPR(XPATH_OP_PREDICATE, op1, ctxt->comp->last, 0, 0);

    NEXT;
    SKIP_BLANKS;
}

/**
 * xmlXPathCompNodeTest:
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
static xmlChar *
xmlXPathCompNodeTest(xmlXPathParserContextPtr ctxt, xmlXPathTestVal *test,
	             xmlXPathTypeVal *type, const xmlChar **prefix,
		     xmlChar *name) {
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
	    if (name != NULL)
		xmlFree(name);
	    name = NULL;
	    if (CUR != ')') {
		name = xmlXPathParseLiteral(ctxt);
		CHECK_ERROR 0;
		SKIP_BLANKS;
	    }
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
	 * Since currently the parser context don't have a
	 * namespace list associated:
	 * The namespace name for this prefix can be computed
	 * only at evaluation time. The compilation is done
	 * outside of any context.
	 */
#if 0
	*prefix = xmlXPathNsLookup(ctxt->context, name);
	if (name != NULL)
	    xmlFree(name);
	if (*prefix == NULL) {
	    XP_ERROR0(XPATH_UNDEF_PREFIX_ERROR);
	}
#else
	*prefix = name;
#endif

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
static xmlXPathAxisVal
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
 * xmlXPathCompStep:
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
 * Compile one step in a Location Path
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
static void
xmlXPathCompStep(xmlXPathParserContextPtr ctxt) {
#ifdef LIBXML_XPTR_ENABLED
    int rangeto = 0;
    int op2 = -1;
#endif

    SKIP_BLANKS;
    if ((CUR == '.') && (NXT(1) == '.')) {
	SKIP(2);
	SKIP_BLANKS;
	PUSH_LONG_EXPR(XPATH_OP_COLLECT, AXIS_PARENT,
		    NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
    } else if (CUR == '.') {
	NEXT;
	SKIP_BLANKS;
    } else {
	xmlChar *name = NULL;
	const xmlChar *prefix = NULL;
	xmlXPathTestVal test;
	xmlXPathAxisVal axis = 0;
	xmlXPathTypeVal type;
	int op1;

	/*
	 * The modification needed for XPointer change to the production
	 */
#ifdef LIBXML_XPTR_ENABLED
	if (ctxt->xptr) {
	    name = xmlXPathParseNCName(ctxt);
	    if ((name != NULL) && (xmlStrEqual(name, BAD_CAST "range-to"))) {
                op2 = ctxt->comp->last;
		xmlFree(name);
		SKIP_BLANKS;
		if (CUR != '(') {
		    XP_ERROR(XPATH_EXPR_ERROR);
		}
		NEXT;
		SKIP_BLANKS;

		xmlXPathCompileExpr(ctxt);
		/* PUSH_BINARY_EXPR(XPATH_OP_RANGETO, op2, ctxt->comp->last, 0, 0); */
		CHECK_ERROR;

		SKIP_BLANKS;
		if (CUR != ')') {
		    XP_ERROR(XPATH_EXPR_ERROR);
		}
		NEXT;
		rangeto = 1;
		goto eval_predicates;
	    }
	}
#endif
	if (CUR == '*') {
	    axis = AXIS_CHILD;
	} else {
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
	}

	CHECK_ERROR;

	name = xmlXPathCompNodeTest(ctxt, &test, &type, &prefix, name);
	if (test == 0)
	    return;

#ifdef DEBUG_STEP
	xmlGenericError(xmlGenericErrorContext,
		"Basis : computing new set\n");
#endif

#ifdef DEBUG_STEP
	xmlGenericError(xmlGenericErrorContext, "Basis : ");
	if (ctxt->value == NULL)
	    xmlGenericError(xmlGenericErrorContext, "no value\n");
	else if (ctxt->value->nodesetval == NULL)
	    xmlGenericError(xmlGenericErrorContext, "Empty\n");
	else
	    xmlGenericErrorContextNodeSet(stdout, ctxt->value->nodesetval);
#endif

eval_predicates:
	op1 = ctxt->comp->last;
	ctxt->comp->last = -1;

	SKIP_BLANKS;
	while (CUR == '[') {
	    xmlXPathCompPredicate(ctxt, 0);
	}

#ifdef LIBXML_XPTR_ENABLED
	if (rangeto) {
	    PUSH_BINARY_EXPR(XPATH_OP_RANGETO, op2, op1, 0, 0);
	} else
#endif
	    PUSH_FULL_EXPR(XPATH_OP_COLLECT, op1, ctxt->comp->last, axis,
			   test, type, (void *)prefix, (void *)name);

    }
#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext, "Step : ");
    if (ctxt->value == NULL)
	xmlGenericError(xmlGenericErrorContext, "no value\n");
    else if (ctxt->value->nodesetval == NULL)
	xmlGenericError(xmlGenericErrorContext, "Empty\n");
    else
	xmlGenericErrorContextNodeSet(xmlGenericErrorContext,
		ctxt->value->nodesetval);
#endif
}

/**
 * xmlXPathCompRelativeLocationPath:
 * @ctxt:  the XPath Parser context
 *
 *  [3]   RelativeLocationPath ::=   Step 
 *                     | RelativeLocationPath '/' Step 
 *                     | AbbreviatedRelativeLocationPath 
 *  [11]  AbbreviatedRelativeLocationPath ::=   RelativeLocationPath '//' Step 
 *
 * Compile a relative location path.
 */
static void
#ifdef VMS
xmlXPathCompRelLocationPath
#else
xmlXPathCompRelativeLocationPath
#endif
(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if ((CUR == '/') && (NXT(1) == '/')) {
	SKIP(2);
	SKIP_BLANKS;
	PUSH_LONG_EXPR(XPATH_OP_COLLECT, AXIS_DESCENDANT_OR_SELF,
		         NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
    } else if (CUR == '/') {
	    NEXT;
	SKIP_BLANKS;
    }
    xmlXPathCompStep(ctxt);
    SKIP_BLANKS;
    while (CUR == '/') {
	if ((CUR == '/') && (NXT(1) == '/')) {
	    SKIP(2);
	    SKIP_BLANKS;
	    PUSH_LONG_EXPR(XPATH_OP_COLLECT, AXIS_DESCENDANT_OR_SELF,
			     NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
	    xmlXPathCompStep(ctxt);
	} else if (CUR == '/') {
	    NEXT;
	    SKIP_BLANKS;
	    xmlXPathCompStep(ctxt);
	}
	SKIP_BLANKS;
    }
}

/**
 * xmlXPathCompLocationPath:
 * @ctxt:  the XPath Parser context
 *
 *  [1]   LocationPath ::=   RelativeLocationPath 
 *                     | AbsoluteLocationPath 
 *  [2]   AbsoluteLocationPath ::=   '/' RelativeLocationPath?
 *                     | AbbreviatedAbsoluteLocationPath 
 *  [10]   AbbreviatedAbsoluteLocationPath ::=   
 *                           '//' RelativeLocationPath 
 *
 * Compile a location path
 *
 * // is short for /descendant-or-self::node()/. For example,
 * //para is short for /descendant-or-self::node()/child::para and
 * so will select any para element in the document (even a para element
 * that is a document element will be selected by //para since the
 * document element node is a child of the root node); div//para is
 * short for div/descendant-or-self::node()/child::para and so will
 * select all para descendants of div children.
 */
static void
xmlXPathCompLocationPath(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if (CUR != '/') {
        xmlXPathCompRelativeLocationPath(ctxt);
    } else {
	while (CUR == '/') {
	    if ((CUR == '/') && (NXT(1) == '/')) {
		SKIP(2);
		SKIP_BLANKS;
		PUSH_LONG_EXPR(XPATH_OP_COLLECT, AXIS_DESCENDANT_OR_SELF,
			     NODE_TEST_TYPE, NODE_TYPE_NODE, NULL, NULL);
		xmlXPathCompRelativeLocationPath(ctxt);
	    } else if (CUR == '/') {
		NEXT;
		SKIP_BLANKS;
		if (CUR != 0)
		    xmlXPathCompRelativeLocationPath(ctxt);
	    }
	}
    }
}

/************************************************************************
 *									*
 * 		XPath precompiled expression evaluation			*
 *									*
 ************************************************************************/

static void
xmlXPathCompOpEval(xmlXPathParserContextPtr ctxt, xmlXPathStepOpPtr op);

/**
 * xmlXPathNodeCollectAndTest:
 * @ctxt:  the XPath Parser context
 * @op:  the XPath precompiled step operation
 *
 * This is the function implementing a step: based on the current list
 * of nodes, it builds up a new list, looking at all nodes under that
 * axis and selecting them it also do the predicate filtering
 *
 * Pushes the new NodeSet resulting from the search.
 */
static void
xmlXPathNodeCollectAndTest(xmlXPathParserContextPtr ctxt,
	                   xmlXPathStepOpPtr op) {
    xmlXPathAxisVal axis = op->value;
    xmlXPathTestVal test = op->value2;
    xmlXPathTypeVal type = op->value3;
    const xmlChar *prefix = op->value4;
    const xmlChar *name = op->value5;
    const xmlChar *URI = NULL;

#ifdef DEBUG_STEP
    int n = 0, t = 0;
#endif
    int i;
    xmlNodeSetPtr ret, list;
    xmlXPathTraversalFunction next = NULL;
    void (*addNode)(xmlNodeSetPtr, xmlNodePtr);
    xmlNodePtr cur = NULL;
    xmlXPathObjectPtr obj;
    xmlNodeSetPtr nodelist;
    xmlNodePtr tmp;

    CHECK_TYPE(XPATH_NODESET);
    obj = valuePop(ctxt);
    addNode = xmlXPathNodeSetAdd;
    if (prefix != NULL) {
	URI = xmlXPathNsLookup(ctxt->context, prefix);
	if (URI == NULL)
	    XP_ERROR(XPATH_UNDEF_PREFIX_ERROR);
    }

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
    if (nodelist == NULL) {
	xmlXPathFreeObject(obj);
	valuePush(ctxt, xmlXPathWrapNodeSet(NULL));
	return;
    }
    addNode = xmlXPathNodeSetAddUnique;
    ret = NULL;
#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext,
	    " context contains %d nodes\n",
            nodelist->nodeNr);
    switch (test) {
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
	list = xmlXPathNodeSetCreate(NULL);
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
		        addNode(list, cur);
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
			addNode(list, cur);
		    }
		    break;
                case NODE_TEST_ALL:
		    if (axis == AXIS_ATTRIBUTE) {
			if (cur->type == XML_ATTRIBUTE_NODE) {
#ifdef DEBUG_STEP
			    n++;
#endif
			    addNode(list, cur);
			}
		    } else if (axis == AXIS_NAMESPACE) {
			if (cur->type == XML_NAMESPACE_DECL) {
#ifdef DEBUG_STEP
			    n++;
#endif
			    addNode(list, cur);
			}
		    } else {
			if ((cur->type == XML_ELEMENT_NODE) ||
			    (cur->type == XML_DOCUMENT_NODE) ||
			    (cur->type == XML_HTML_DOCUMENT_NODE)) {
			    if (prefix == NULL) {
#ifdef DEBUG_STEP
				n++;
#endif
				addNode(list, cur);
			    } else if ((cur->ns != NULL) && 
				(xmlStrEqual(URI,
					     cur->ns->href))) {
#ifdef DEBUG_STEP
				n++;
#endif
				addNode(list, cur);
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
					addNode(list, cur);
				    }
				} else {
				    if ((cur->ns != NULL) && 
				        (xmlStrEqual(URI,
						     cur->ns->href))) {
#ifdef DEBUG_STEP
					n++;
#endif
					addNode(list, cur);
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
					addNode(list, (xmlNodePtr) attr);
				    }
				} else {
				    if ((attr->ns != NULL) && 
				        (xmlStrEqual(URI,
						     attr->ns->href))) {
#ifdef DEBUG_STEP
					n++;
#endif
					addNode(list, (xmlNodePtr) attr);
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

	/*
	 * If there is some predicate filtering do it now
	 */
	if (op->ch2 != -1) {
	    xmlXPathObjectPtr obj2;

	    valuePush(ctxt, xmlXPathWrapNodeSet(list));
	    xmlXPathCompOpEval(ctxt, &ctxt->comp->steps[op->ch2]);
	    CHECK_TYPE(XPATH_NODESET);
	    obj2 = valuePop(ctxt);
	    list = obj2->nodesetval;
	    obj2->nodesetval = NULL;
	    xmlXPathFreeObject(obj2);
	}
	if (ret == NULL) {
	    ret = list;
	} else {
	    ret = xmlXPathNodeSetMerge(ret, list);
	    xmlXPathFreeNodeSet(list);
	}
    }
    ctxt->context->node = tmp;
#ifdef DEBUG_STEP
    xmlGenericError(xmlGenericErrorContext,
            "\nExamined %d nodes, found %d nodes at that step\n", t, n);
#endif
    xmlXPathFreeObject(obj);
    valuePush(ctxt, xmlXPathWrapNodeSet(ret));
}

/**
 * xmlXPathCompOpEval:
 * @ctxt:  the XPath parser context with the compiled expression
 * @op:  an XPath compiled operation
 *
 * Evaluate the Precompiled XPath operation
 */
static void
xmlXPathCompOpEval(xmlXPathParserContextPtr ctxt, xmlXPathStepOpPtr op) {
    int equal, ret;
    xmlXPathCompExprPtr comp;
    xmlXPathObjectPtr arg1, arg2;

    comp = ctxt->comp;
    switch (op->op) {
	case XPATH_OP_END:
	    return;
	case XPATH_OP_AND:
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    xmlXPathBooleanFunction(ctxt, 1);
	    if (ctxt->value->boolval == 0)
		return;
	    arg2 = valuePop(ctxt);
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    xmlXPathBooleanFunction(ctxt, 1);
	    arg1 = valuePop(ctxt);
	    arg1->boolval &= arg2->boolval;
	    valuePush(ctxt, arg1);
	    xmlXPathFreeObject(arg2);
	    return;
	case XPATH_OP_OR:
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    xmlXPathBooleanFunction(ctxt, 1);
	    if (ctxt->value->boolval == 1)
		return;
	    arg2 = valuePop(ctxt);
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    xmlXPathBooleanFunction(ctxt, 1);
	    arg1 = valuePop(ctxt);
	    arg1->boolval |= arg2->boolval;
	    valuePush(ctxt, arg1);
	    xmlXPathFreeObject(arg2);
	    return;
	case XPATH_OP_EQUAL:
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    equal = xmlXPathEqualValues(ctxt);
	    if (op->value) valuePush(ctxt, xmlXPathNewBoolean(equal));
	    else valuePush(ctxt, xmlXPathNewBoolean(!equal));
	    return;
	case XPATH_OP_CMP:
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    ret = xmlXPathCompareValues(ctxt, op->value, op->value2);
	    valuePush(ctxt, xmlXPathNewBoolean(ret));
	    return;
	case XPATH_OP_PLUS:
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->ch2 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    if (op->value == 0) xmlXPathSubValues(ctxt);
	    else if (op->value == 1) xmlXPathAddValues(ctxt);
	    else if (op->value == 2) xmlXPathValueFlipSign(ctxt);
	    else if (op->value == 3) {
		xmlXPathObjectPtr arg;
		
		POP_FLOAT
		valuePush(ctxt, arg);
	    }
	    return;
	case XPATH_OP_MULT:
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    if (op->value == 0) xmlXPathMultValues(ctxt);
	    else if (op->value == 1) xmlXPathDivValues(ctxt);
	    else if (op->value == 2) xmlXPathModValues(ctxt);
	    return;
	case XPATH_OP_UNION:
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    CHECK_TYPE(XPATH_NODESET);
	    arg2 = valuePop(ctxt);

	    CHECK_TYPE(XPATH_NODESET);
	    arg1 = valuePop(ctxt);

	    arg1->nodesetval = xmlXPathNodeSetMerge(arg1->nodesetval,
						    arg2->nodesetval);
	    valuePush(ctxt, arg1);
	    xmlXPathFreeObject(arg2);
	    return;
	case XPATH_OP_ROOT:
	    xmlXPathRoot(ctxt);
	    return;
	case XPATH_OP_NODE:
	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->ch2 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
	    return;
	case XPATH_OP_RESET:
	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->ch2 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    ctxt->context->node = NULL;
	    return;
	case XPATH_OP_COLLECT: {
	    if (op->ch1 == -1)
		return;

	    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    xmlXPathNodeCollectAndTest(ctxt, op);
	    return;
        }
	case XPATH_OP_VALUE:
	    valuePush(ctxt,
		    xmlXPathObjectCopy((xmlXPathObjectPtr) op->value4));
	    return;
	case XPATH_OP_VARIABLE: {
	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->value5 == NULL)
		valuePush(ctxt,
		    xmlXPathVariableLookup(ctxt->context, op->value4));
	    else {
		const xmlChar *URI;
		URI = xmlXPathNsLookup(ctxt->context, op->value5);
		if (URI == NULL) {
		    xmlGenericError(xmlGenericErrorContext,
	   "xmlXPathRunEval: variable %s bound to undefined prefix %s\n",
				    op->value4, op->value5);
		    return;
		}
		valuePush(ctxt,
		    xmlXPathVariableLookupNS(ctxt->context,
					     op->value4, URI));
	    }
	    return;
	}
	case XPATH_OP_FUNCTION: {
	    xmlXPathFunction func;

	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->cache != NULL) 
		func = (xmlXPathFunction) op->cache;
	    else {
		if (op->value5 == NULL) 
		    func = xmlXPathFunctionLookup(ctxt->context, op->value4);
		else {
		    const xmlChar *URI;
		    URI = xmlXPathNsLookup(ctxt->context, op->value5);
		    if (URI == NULL) {
			xmlGenericError(xmlGenericErrorContext,
	       "xmlXPathRunEval: function %s bound to undefined prefix %s\n",
					op->value4, op->value5);
			return;
		    }
		    func = xmlXPathFunctionLookupNS(ctxt->context,
						    op->value4, URI);
		}
		if (func == NULL) {
		    xmlGenericError(xmlGenericErrorContext,
			   "xmlXPathRunEval: function %s not found\n",
				    op->value4);
		    XP_ERROR(XPATH_UNKNOWN_FUNC_ERROR);
		    return;
		}
		op->cache = (void *) func;
	    }
	    func(ctxt, op->value);
	    return;
	}
	case XPATH_OP_ARG:
	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->ch2 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
	    return;
	case XPATH_OP_PREDICATE:
	case XPATH_OP_FILTER: {
	    xmlXPathObjectPtr res;
	    xmlXPathObjectPtr obj, tmp;
	    xmlNodeSetPtr newset = NULL;
	    xmlNodeSetPtr oldset;
	    xmlNodePtr oldnode;
	    int i;

	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->ch2 == -1)
		return;

	    oldnode = ctxt->context->node;

#ifdef LIBXML_XPTR_ENABLED
	    /*
	     * Hum are we filtering the result of an XPointer expression
	     */
	    if (ctxt->value->type == XPATH_LOCATIONSET) {
		xmlLocationSetPtr newlocset = NULL;
		xmlLocationSetPtr oldlocset;

		/*
		 * Extract the old locset, and then evaluate the result of the
		 * expression for all the element in the locset. use it to grow
		 * up a new locset.
		 */
		CHECK_TYPE(XPATH_LOCATIONSET);
		obj = valuePop(ctxt);
		oldlocset = obj->user;
		ctxt->context->node = NULL;

		if ((oldlocset == NULL) || (oldlocset->locNr == 0)) {
		    ctxt->context->contextSize = 0;
		    ctxt->context->proximityPosition = 0;
		    if (op->ch2 != -1)
			xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
		    res = valuePop(ctxt);
		    if (res != NULL)
			xmlXPathFreeObject(res);
		    valuePush(ctxt, obj);
		    CHECK_ERROR;
		    return;
		}
		newlocset = xmlXPtrLocationSetCreate(NULL);
		
		for (i = 0; i < oldlocset->locNr; i++) {
		    /*
		     * Run the evaluation with a node list made of a
		     * single item in the nodelocset.
		     */
		    ctxt->context->node = oldlocset->locTab[i]->user;
		    tmp = xmlXPathNewNodeSet(ctxt->context->node);
		    valuePush(ctxt, tmp);
		    ctxt->context->contextSize = oldlocset->locNr;
		    ctxt->context->proximityPosition = i + 1;

		    if (op->ch2 != -1)
			xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
		    CHECK_ERROR;

		    /*
		     * The result of the evaluation need to be tested to
		     * decided whether the filter succeeded or not
		     */
		    res = valuePop(ctxt);
		    if (xmlXPathEvaluatePredicateResult(ctxt, res)) {
			xmlXPtrLocationSetAdd(newlocset,
				xmlXPathObjectCopy(oldlocset->locTab[i]));
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
		 * The result is used as the new evaluation locset.
		 */
		xmlXPathFreeObject(obj);
		ctxt->context->node = NULL;
		ctxt->context->contextSize = -1;
		ctxt->context->proximityPosition = -1;
		valuePush(ctxt, xmlXPtrWrapLocationSet(newlocset));
		ctxt->context->node = oldnode;
		return;
	    }
#endif /* LIBXML_XPTR_ENABLED */

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
		if (op->ch2 != -1)
		    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
		res = valuePop(ctxt);
		if (res != NULL)
		    xmlXPathFreeObject(res);
		valuePush(ctxt, obj);
		ctxt->context->node = oldnode;
		CHECK_ERROR;
	    } else {
		/*
		 * Initialize the new set.
		 */
		newset = xmlXPathNodeSetCreate(NULL);

		for (i = 0; i < oldset->nodeNr; i++) {
		    /*
		     * Run the evaluation with a node list made of
		     * a single item in the nodeset.
		     */
		    ctxt->context->node = oldset->nodeTab[i];
		    tmp = xmlXPathNewNodeSet(ctxt->context->node);
		    valuePush(ctxt, tmp);
		    ctxt->context->contextSize = oldset->nodeNr;
		    ctxt->context->proximityPosition = i + 1;

		    if (op->ch2 != -1)
			xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
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
	    ctxt->context->node = oldnode;
	    return;
	}
	case XPATH_OP_SORT:
	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if ((ctxt->value != NULL) &&
		(ctxt->value->type == XPATH_NODESET) &&
		(ctxt->value->nodesetval != NULL))
		xmlXPathNodeSetSort(ctxt->value->nodesetval);
	    return;
#ifdef LIBXML_XPTR_ENABLED
	case XPATH_OP_RANGETO: {
	    xmlXPathObjectPtr range;
	    xmlXPathObjectPtr res, obj;
	    xmlXPathObjectPtr tmp;
	    xmlLocationSetPtr newset = NULL;
	    xmlNodeSetPtr oldset;
	    int i;

	    if (op->ch1 != -1)
		xmlXPathCompOpEval(ctxt, &comp->steps[op->ch1]);
	    if (op->ch2 == -1)
		return;

	    CHECK_TYPE(XPATH_NODESET);
	    obj = valuePop(ctxt);
	    oldset = obj->nodesetval;
	    ctxt->context->node = NULL;

	    newset = xmlXPtrLocationSetCreate(NULL);
	    
	    if (oldset != NULL) {
	    for (i = 0; i < oldset->nodeNr; i++) {
		/*
		 * Run the evaluation with a node list made of a single item
		 * in the nodeset.
		 */
		ctxt->context->node = oldset->nodeTab[i];
		tmp = xmlXPathNewNodeSet(ctxt->context->node);
		valuePush(ctxt, tmp);

		if (op->ch2 != -1)
		    xmlXPathCompOpEval(ctxt, &comp->steps[op->ch2]);
		CHECK_ERROR;

		/*
		 * The result of the evaluation need to be tested to
		 * decided whether the filter succeeded or not
		 */
		res = valuePop(ctxt);
		range = xmlXPtrNewRangeNodeObject(oldset->nodeTab[i], res);
		if (range != NULL) {
		    xmlXPtrLocationSetAdd(newset, range);
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
	    }

	    /*
	     * The result is used as the new evaluation set.
	     */
	    xmlXPathFreeObject(obj);
	    ctxt->context->node = NULL;
	    ctxt->context->contextSize = -1;
	    ctxt->context->proximityPosition = -1;
	    valuePush(ctxt, xmlXPtrWrapLocationSet(newset));
	    return;
	}
#endif /* LIBXML_XPTR_ENABLED */
    }
    xmlGenericError(xmlGenericErrorContext,
       "XPath: unknown precompiled operation %d\n",
		    op->op);
    return;
}

/**
 * xmlXPathRunEval:
 * @ctxt:  the XPath parser context with the compiled expression
 *
 * Evaluate the Precompiled XPath expression in the given context.
 */
static void
xmlXPathRunEval(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompExprPtr comp;

    if ((ctxt == NULL) || (ctxt->comp == NULL))
	return;

    if (ctxt->valueTab == NULL) {
	/* Allocate the value stack */
	ctxt->valueTab = (xmlXPathObjectPtr *) 
			 xmlMalloc(10 * sizeof(xmlXPathObjectPtr));
	if (ctxt->valueTab == NULL) {
	    xmlFree(ctxt);
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlXPathRunEval: out of memory\n");
	    return;
	}
	ctxt->valueNr = 0;
	ctxt->valueMax = 10;
	ctxt->value = NULL;
    }
    comp = ctxt->comp;
    xmlXPathCompOpEval(ctxt, &comp->steps[comp->last]);
}

/************************************************************************
 *									*
 * 			Public interfaces				*
 *									*
 ************************************************************************/

/**
 * xmlXPathEvalPredicate:
 * @ctxt:  the XPath context
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
xmlXPathEvalPredicate(xmlXPathContextPtr ctxt, xmlXPathObjectPtr res) {
    if (res == NULL) return(0);
    switch (res->type) {
        case XPATH_BOOLEAN:
	    return(res->boolval);
        case XPATH_NUMBER:
	    return(res->floatval == ctxt->proximityPosition);
        case XPATH_NODESET:
        case XPATH_XSLT_TREE:
	    if (res->nodesetval == NULL)
		return(0);
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
	    if (res->nodesetval == NULL)
		return(0);
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
 * xmlXPathCompile:
 * @str:  the XPath expression
 *
 * Compile an XPath expression
 *
 * Returns the xmlXPathObjectPtr resulting from the eveluation or NULL.
 *         the caller has to free the object.
 */
xmlXPathCompExprPtr
xmlXPathCompile(const xmlChar *str) {
    xmlXPathParserContextPtr ctxt;
    xmlXPathCompExprPtr comp;

    xmlXPathInit();

    ctxt = xmlXPathNewParserContext(str, NULL);
    xmlXPathCompileExpr(ctxt);

    if (*ctxt->cur != 0) {
	xmlXPatherror(ctxt, __FILE__, __LINE__, XPATH_EXPR_ERROR);
	comp = NULL;
    } else {
	comp = ctxt->comp;
	ctxt->comp = NULL;
    }
    xmlXPathFreeParserContext(ctxt);
    return(comp);
}

/**
 * xmlXPathCompiledEval:
 * @comp:  the compiled XPath expression
 * @ctx:  the XPath context
 *
 * Evaluate the Precompiled XPath expression in the given context.
 *
 * Returns the xmlXPathObjectPtr resulting from the eveluation or NULL.
 *         the caller has to free the object.
 */
xmlXPathObjectPtr
xmlXPathCompiledEval(xmlXPathCompExprPtr comp, xmlXPathContextPtr ctx) {
    xmlXPathParserContextPtr ctxt;
    xmlXPathObjectPtr res, tmp, init = NULL;
    int stack = 0;

    if ((comp == NULL) || (ctx == NULL))
	return(NULL);
    xmlXPathInit();

    CHECK_CONTEXT(ctx)

    ctxt = xmlXPathCompParserContext(comp, ctx);
    xmlXPathRunEval(ctxt);

    if (ctxt->value == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"xmlXPathEval: evaluation failed\n");
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
        

    ctxt->comp = NULL;
    xmlXPathFreeParserContext(ctxt);
    return(res);
}

/**
 * xmlXPathEvalExpr:
 * @ctxt:  the XPath Parser context
 *
 * Parse and evaluate an XPath expression in the given context,
 * then push the result on the context stack
 */
void
xmlXPathEvalExpr(xmlXPathParserContextPtr ctxt) {
    xmlXPathCompileExpr(ctxt);
    xmlXPathRunEval(ctxt);
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
