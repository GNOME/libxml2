/*
 * xpath.c: XML Path Language implementation
 *          XPath is a language for addressing parts of an XML document,
 *          designed to be used by both XSLT and XPointer.
 *
 * Reference: W3C Working Draft internal 5 July 1999
 *     http://www.w3.org/Style/XSL/Group/1999/07/xpath-19990705.html
 * Public reference:
 *     http://www.w3.org/TR/WD-xpath/
 *
 * See COPYRIGHT for the status of this software
 *
 * Author: Daniel.Veillard@w3.org
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_MATH_H
#include <math.h>
#endif
#ifdef HAVE_MATH_H
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

#include "xmlmemory.h"
#include "tree.h"
#include "valid.h"
#include "xpath.h"
#include "parserInternals.h"

/* #define DEBUG */
/* #define DEBUG_STEP */
/* #define DEBUG_EXPR */

/*
 * Setup stuff for floating point
 * The lack of portability of this section of the libc is annoying !
 */
double xmlXPathNAN = 0;
double xmlXPathPINF = 1;
double xmlXPathMINF = -1;

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
static int isinf(double x)
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

    xmlXPathMINF = -1;
    xmlXPathMINF /= 0;

    initialized = 1;
}

FILE *xmlXPathDebug = NULL;

#define TODO 								\
    fprintf(xmlXPathDebug, "Unimplemented block at %s:%d\n",		\
            __FILE__, __LINE__);

#define STRANGE 							\
    fprintf(xmlXPathDebug, "Internal error at %s:%d\n",			\
            __FILE__, __LINE__);

double xmlXPathStringEvalNumber(const xmlChar *str);
void xmlXPathStringFunction(xmlXPathParserContextPtr ctxt, int nargs);

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
        ctxt->name##Tab = (void *) xmlRealloc(ctxt->name##Tab,		\
	             ctxt->name##Max * sizeof(ctxt->name##Tab[0]));	\
        if (ctxt->name##Tab == NULL) {					\
	    fprintf(xmlXPathDebug, "realloc failed !\n");		\
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
 *   CUR     returns the current xmlChar value, i.e. a 8 bit value if compiled
 *           in ISO-Latin or UTF-8, and the current 16 bit value if compiled
 *           in UNICODE mode. This should be used internally by the parser
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

#ifndef USE_UTF_8
#define CURRENT (*ctxt->cur)
#define NEXT ((*ctxt->cur) ?  ctxt->cur++: ctxt->cur)
#else
#endif

/************************************************************************
 *									*
 *			Error handling routines				*
 *									*
 ************************************************************************/

#define XPATH_EXPRESSION_OK		0
#define XPATH_NUMBER_ERROR		1
#define XPATH_UNFINISHED_LITERAL_ERROR	2
#define XPATH_START_LITERAL_ERROR	3
#define XPATH_VARIABLE_REF_ERROR	4
#define XPATH_UNDEF_VARIABLE_ERROR	5
#define XPATH_INVALID_PREDICATE_ERROR	6
#define XPATH_EXPR_ERROR		7
#define XPATH_UNCLOSED_ERROR		8
#define XPATH_UNKNOWN_FUNC_ERROR	9
#define XPATH_INVALID_OPERAND		10
#define XPATH_INVALID_TYPE		11
#define XPATH_INVALID_ARITY		12

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

    fprintf(xmlXPathDebug, "Error %s:%d: %s\n", file, line,
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
        fprintf(xmlXPathDebug, "%c", (unsigned char) *cur++);
	n++;
    }
    fprintf(xmlXPathDebug, "\n");
    cur = ctxt->cur;
    while ((*cur == '\n') || (*cur == '\r'))
	cur--;
    n = 0;
    while ((cur != base) && (n++ < 80)) {
        fprintf(xmlXPathDebug, " ");
        base++;
    }
    fprintf(xmlXPathDebug,"^\n");
}

#define CHECK_ERROR							\
    if (ctxt->error != XPATH_EXPRESSION_OK) return

#define ERROR(X)							\
    { xmlXPatherror(ctxt, __FILE__, __LINE__, X);			\
      ctxt->error = (X); return; }

#define ERROR0(X)							\
    { xmlXPatherror(ctxt, __FILE__, __LINE__, X);			\
      ctxt->error = (X); return(0); }

#define CHECK_TYPE(typeval)						\
    if ((ctxt->value == NULL) || (ctxt->value->type != typeval))	\
        ERROR(XPATH_INVALID_TYPE)					\


/************************************************************************
 *									*
 *			Routines to handle NodeSets			*
 *									*
 ************************************************************************/

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
        fprintf(xmlXPathDebug, "xmlXPathNewNodeSet: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlNodeSet));
    if (val != NULL) {
        ret->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
					     sizeof(xmlNodePtr));
	if (ret->nodeTab == NULL) {
	    fprintf(xmlXPathDebug, "xmlXPathNewNodeSet: out of memory\n");
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
	    fprintf(xmlXPathDebug, "xmlXPathNodeSetAdd: out of memory\n");
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
	    fprintf(xmlXPathDebug, "xmlXPathNodeSetAdd: out of memory\n");
	    return;
	}
	cur->nodeTab = temp;
    }
    cur->nodeTab[cur->nodeNr++] = val;
}

/**
 * xmlXPathNodeSetMerge:
 * @val1:  the first NodeSet
 * @val2:  the second NodeSet
 *
 * Merges two nodesets, all nodes from @val2 are added to @val1
 *
 * Returns val1 once extended or NULL in case of error.
 */
xmlNodeSetPtr
xmlXPathNodeSetMerge(xmlNodeSetPtr val1, xmlNodeSetPtr val2) {
    int i;

    if (val1 == NULL) return(NULL);
    if (val2 == NULL) return(val1);

    /*
     * !!!!! this can be optimized a lot, knowing that both
     *       val1 and val2 already have unicity of their values.
     */

    for (i = 0;i < val2->nodeNr;i++)
        xmlXPathNodeSetAdd(val1, val2->nodeTab[i]);

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
        fprintf(xmlXPathDebug, 
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
#ifdef DEBUG
	memset(obj->nodeTab, 0xB , (size_t) sizeof(xmlNodePtr) * obj->nodeMax);
#endif
	xmlFree(obj->nodeTab);
    }
#ifdef DEBUG
    memset(obj, 0xB , (size_t) sizeof(xmlNodeSet));
#endif
    xmlFree(obj);
}

#if defined(DEBUG) || defined(DEBUG_STEP)
/**
 * xmlXPathDebugNodeSet:
 * @output:  a FILE * for the output
 * @obj:  the xmlNodeSetPtr to free
 *
 * Quick display of a NodeSet
 */
void
xmlXPathDebugNodeSet(FILE *output, xmlNodeSetPtr obj) {
    int i;

    if (output == NULL) output = xmlXPathDebug;
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

/************************************************************************
 *									*
 *			Routines to handle Variable			*
 *									*
 *			UNIMPLEMENTED CURRENTLY				*
 *									*
 ************************************************************************/

/**
 * xmlXPathVariablelookup:
 * @ctxt:  the XPath Parser context
 * @prefix:  the variable name namespace if any
 * @name:  the variable name
 *
 * Search in the Variable array of the context for the given
 * variable value.
 *
 * UNIMPLEMENTED: always return NULL.
 *
 * Returns the value or NULL if not found
 */
xmlXPathObjectPtr
xmlXPathVariablelookup(xmlXPathParserContextPtr ctxt,
                       const xmlChar *prefix, const xmlChar *name) {
    return(NULL);
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
        fprintf(xmlXPathDebug, "xmlXPathNewFloat: out of memory\n");
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
        fprintf(xmlXPathDebug, "xmlXPathNewFloat: out of memory\n");
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
        fprintf(xmlXPathDebug, "xmlXPathNewFloat: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_STRING;
    ret->stringval = xmlStrdup(val);
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
        fprintf(xmlXPathDebug, "xmlXPathNewFloat: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_STRING;
    ret->stringval = xmlStrdup(BAD_CAST val);
    return(ret);
}

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
        fprintf(xmlXPathDebug, "xmlXPathNewFloat: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_NODESET;
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

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPathNewFloat: out of memory\n");
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
#ifdef DEBUG
    memset(obj, 0xB , (size_t) sizeof(xmlXPathObject));
#endif
    xmlFree(obj);
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
    if (obj->nodesetval != NULL)
        xmlXPathFreeNodeSet(obj->nodesetval);
    if (obj->stringval != NULL)
        xmlFree(obj->stringval);
#ifdef DEBUG
    memset(obj, 0xB , (size_t) sizeof(xmlXPathObject));
#endif
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
        fprintf(xmlXPathDebug, "xmlXPathNewContext: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathContext));
    ret->doc = doc;
 /***********   
    ret->node = (xmlNodePtr) doc;
    ret->nodelist = xmlXPathNodeSetCreate(ret->node);
  ***********/  
    ret->node = NULL;
    ret->nodelist = NULL;

    ret->nb_variables = 0;
    ret->max_variables = 0;
    ret->variables = NULL;

    ret->nb_types = 0;
    ret->max_types = 0;
    ret->types = NULL;

    ret->nb_funcs = 0;
    ret->max_funcs = 0;
    ret->funcs = NULL;

    ret->nb_axis = 0;
    ret->max_axis = 0;
    ret->axis = NULL;

    ret->namespaces = NULL;
    ret->user = NULL;
    ret->nsNr = 0;
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
    if (ctxt->namespaces != NULL)
        xmlFree(ctxt->namespaces);

 /***********   
    if (ctxt->nodelist != NULL) 
        xmlXPathFreeNodeSet(ctxt->nodelist);
  ***********/  
#ifdef DEBUG
    memset(ctxt, 0xB , (size_t) sizeof(xmlXPathContext));
#endif
    xmlFree(ctxt);
}

/************************************************************************
 *									*
 *		Routines to handle XPath parser contexts		*
 *									*
 ************************************************************************/

#define CHECK_CTXT							\
    if (ctxt == NULL) { 						\
        fprintf(xmlXPathDebug, "%s:%d Internal error: ctxt == NULL\n",	\
	        __FILE__, __LINE__);					\
    }									\


#define CHECK_CONTEXT							\
    if (ctxt == NULL) { 						\
        fprintf(xmlXPathDebug, "%s:%d Internal error: no context\n",	\
	        __FILE__, __LINE__);					\
    }									\
    if (ctxt->doc == NULL) { 						\
        fprintf(xmlXPathDebug, "%s:%d Internal error: no document\n",	\
	        __FILE__, __LINE__);					\
    }									\
    if (ctxt->doc->root == NULL) { 					\
        fprintf(xmlXPathDebug,						\
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
        fprintf(xmlXPathDebug, "xmlXPathNewParserContext: out of memory\n");
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
#ifdef DEBUG
        memset(ctxt->valueTab, 0xB , 10 * (size_t) sizeof(xmlXPathObjectPtr));
#endif
        xmlFree(ctxt->valueTab);
    }
#ifdef DEBUG
    memset(ctxt, 0xB , (size_t) sizeof(xmlXPathParserContext));
#endif
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

#define CHECK_ARITY(x)						\
    if (nargs != (x)) {						\
        ERROR(XPATH_INVALID_ARITY);				\
    }								\


#define POP_FLOAT						\
    arg = valuePop(ctxt);					\
    if (arg == NULL) {						\
	ERROR(XPATH_INVALID_OPERAND);				\
    }								\
    if (arg->type != XPATH_NUMBER) {				\
        valuePush(ctxt, arg);					\
        xmlXPathNumberFunction(ctxt, 1);			\
	arg = valuePop(ctxt);					\
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

    if ((str == NULL) || (arg == NULL) || (arg->type != XPATH_NODESET))
        return(0);
    ns = arg->nodesetval;
    for (i = 0;i < ns->nodeNr;i++) {
         str2 = xmlNodeGetContent(ns->nodeTab[i]);
	 if ((str2 != NULL) && (!xmlStrcmp(str, str2))) {
	     xmlFree(str2);
	     return(1);
	 }
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
xmlXPathEqualNodeSetFloat(xmlXPathObjectPtr arg, float f) {
    char buf[100] = "";

    if ((arg == NULL) || (arg->type != XPATH_NODESET))
        return(0);

    if (isnan(f))
	sprintf(buf, "NaN");
    else if (isinf(f) > 0)
	sprintf(buf, "+Infinity");
    else if (isinf(f) < 0)
	sprintf(buf, "-Infinity");
    else
	sprintf(buf, "%0g", f);

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
    int i;
    xmlNodeSetPtr ns;
    xmlChar *str;

    if ((arg1 == NULL) || (arg1->type != XPATH_NODESET))
        return(0);
    if ((arg2 == NULL) || (arg2->type != XPATH_NODESET))
        return(0);

    ns = arg1->nodesetval;
    for (i = 0;i < ns->nodeNr;i++) {
         str = xmlNodeGetContent(ns->nodeTab[i]);
	 if ((str != NULL) && (xmlXPathEqualNodeSetString(arg2, str))) {
	     xmlFree(str);
	     return(1);
	 }
	 xmlFree(str);
    }
    return(0);
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
	ERROR0(XPATH_INVALID_OPERAND);

    arg2 = valuePop(ctxt);
    if (arg2 == NULL) {
	xmlXPathFreeObject(arg1);
	ERROR0(XPATH_INVALID_OPERAND);
    }
  
    if (arg1 == arg2) {
#ifdef DEBUG_EXPR
        fprintf(xmlXPathDebug, "Equal: by pointer\n");
#endif
        return(1);
    }

    switch (arg1->type) {
        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
	    fprintf(xmlXPathDebug, "Equal: undefined\n");
#endif
	    break;
        case XPATH_NODESET:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    fprintf(xmlXPathDebug, "Equal: undefined\n");
#endif
		    break;
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
	    }
	    break;
        case XPATH_BOOLEAN:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    fprintf(xmlXPathDebug, "Equal: undefined\n");
#endif
		    break;
		case XPATH_NODESET:
		    if ((arg2->nodesetval == NULL) ||
			(arg2->nodesetval->nodeNr == 0)) ret = 0;
		    else 
			ret = 1;
		    break;
		case XPATH_BOOLEAN:
#ifdef DEBUG_EXPR
		    fprintf(xmlXPathDebug, "Equal: %d boolean %d \n",
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
	    }
	    break;
        case XPATH_NUMBER:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    fprintf(xmlXPathDebug, "Equal: undefined\n");
#endif
		    break;
		case XPATH_NODESET:
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
	    }
	    break;
        case XPATH_STRING:
	    switch (arg2->type) {
	        case XPATH_UNDEFINED:
#ifdef DEBUG_EXPR
		    fprintf(xmlXPathDebug, "Equal: undefined\n");
#endif
		    break;
		case XPATH_NODESET:
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
		    ret = !xmlStrcmp(arg1->stringval, arg2->stringval);
		    break;
		case XPATH_NUMBER:
		    valuePush(ctxt, arg1);
		    xmlXPathNumberFunction(ctxt, 1);
		    arg1 = valuePop(ctxt);
		    ret = (arg1->floatval == arg2->floatval);
		    break;
	    }
	    break;
    }
    xmlXPathFreeObject(arg1);
    xmlXPathFreeObject(arg2);
    return(ret);
}

/**
 * xmlXPathCompareValues:
 * @ctxt:  the XPath Parser context
 * @inf:  less than (1) or greater than (2)
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
 */
int
xmlXPathCompareValues(xmlXPathParserContextPtr ctxt, int inf, int strict) {
    int ret = 0;
    xmlXPathObjectPtr arg1, arg2;

    arg2 = valuePop(ctxt);
    if ((arg2 == NULL) || (arg2->type == XPATH_NODESET)) {
        if (arg2 != NULL)
	    xmlXPathFreeObject(arg2);
	ERROR0(XPATH_INVALID_OPERAND);
    }
  
    arg1 = valuePop(ctxt);
    if ((arg1 == NULL) || (arg1->type == XPATH_NODESET)) {
        if (arg1 != NULL)
	    xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
	ERROR0(XPATH_INVALID_OPERAND);
    }

    if (arg1->type != XPATH_NUMBER) {
	valuePush(ctxt, arg1);
	xmlXPathNumberFunction(ctxt, 1);
	arg1 = valuePop(ctxt);
    }
    if (arg1->type != XPATH_NUMBER) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
	ERROR0(XPATH_INVALID_OPERAND);
    }
    if (arg2->type != XPATH_NUMBER) {
	valuePush(ctxt, arg2);
	xmlXPathNumberFunction(ctxt, 1);
	arg2 = valuePop(ctxt);
    }
    if (arg2->type != XPATH_NUMBER) {
	xmlXPathFreeObject(arg1);
	xmlXPathFreeObject(arg2);
	ERROR0(XPATH_INVALID_OPERAND);
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
 * Implement the div operation on XPath objects:
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
 * Implement the div operation on XPath objects: @arg1 / @arg2
 * The numeric operators convert their operands to numbers as if
 * by calling the number function.
 */
void
xmlXPathModValues(xmlXPathParserContextPtr ctxt) {
    xmlXPathObjectPtr arg;
    double val;

    POP_FLOAT
    val = arg->floatval;
    xmlXPathFreeObject(arg);

    POP_FLOAT
    arg->floatval /= val;
    valuePush(ctxt, arg);
}

/************************************************************************
 *									*
 *		The traversal functions					*
 *									*
 ************************************************************************/

#define AXIS_ANCESTOR			1
#define AXIS_ANCESTOR_OR_SELF		2
#define AXIS_ATTRIBUTE			3
#define AXIS_CHILD			4
#define AXIS_DESCENDANT			5
#define AXIS_DESCENDANT_OR_SELF		6
#define AXIS_FOLLOWING			7
#define AXIS_FOLLOWING_SIBLING		8
#define AXIS_NAMESPACE			9
#define AXIS_PARENT			10
#define AXIS_PRECEDING			11
#define AXIS_PRECEDING_SIBLING		12
#define AXIS_SELF			13

/*
 * A traversal function enumerates nodes along an axis.
 * Initially it must be called with NULL, and it indicates
 * termination on the axis by returning NULL.
 */
typedef xmlNodePtr (*xmlXPathTraversalFunction)
                    (xmlXPathParserContextPtr ctxt, xmlNodePtr cur);

/**
 * mlXPathNextSelf:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node in the traversal
 *
 * Traversal function for the "self" direction
 * he self axis contains just the context node itself
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
 * mlXPathNextChild:
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
		return(ctxt->context->node->childs);
            case XML_ATTRIBUTE_NODE:
		return(NULL);
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_HTML_DOCUMENT_NODE:
		return(((xmlDocPtr) ctxt->context->node)->root);
	}
	return(NULL);
    }
    if ((cur->type == XML_DOCUMENT_NODE) ||
        (cur->type == XML_HTML_DOCUMENT_NODE))
	return(NULL);
    return(cur->next);
}

/**
 * mlXPathNextDescendant:
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
	if (ctxt->context->node->type == XML_ATTRIBUTE_NODE)
	    return(NULL);

        if (ctxt->context->node == (xmlNodePtr) ctxt->context->doc)
	    return(ctxt->context->doc->root);
        return(ctxt->context->node->childs);
    }

    if (cur->childs != NULL) return(cur->childs);
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
 * mlXPathNextDescendantOrSelf:
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
	if (ctxt->context->node->type == XML_ATTRIBUTE_NODE)
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
		if (ctxt->context->node->parent == NULL)
		    return((xmlNodePtr) ctxt->context->doc);
		return(ctxt->context->node->parent);
            case XML_ATTRIBUTE_NODE: {
		xmlAttrPtr att = (xmlAttrPtr) ctxt->context->node;

		return(att->node);
	    }
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_HTML_DOCUMENT_NODE:
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
            case XML_NOTATION_NODE:
		if (ctxt->context->node->parent == NULL)
		    return((xmlNodePtr) ctxt->context->doc);
		return(ctxt->context->node->parent);
            case XML_ATTRIBUTE_NODE: {
		xmlAttrPtr cur = (xmlAttrPtr) ctxt->context->node;

		return(cur->node);
	    }
            case XML_DOCUMENT_NODE:
            case XML_DOCUMENT_TYPE_NODE:
            case XML_DOCUMENT_FRAG_NODE:
            case XML_HTML_DOCUMENT_NODE:
                return(NULL);
	}
	return(NULL);
    }
    if (cur == ctxt->context->doc->root)
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
	    return(cur->parent);
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr att = (xmlAttrPtr) ctxt->context->node;

	    return(att->node);
	}
	case XML_DOCUMENT_NODE:
	case XML_DOCUMENT_TYPE_NODE:
	case XML_DOCUMENT_FRAG_NODE:
	case XML_HTML_DOCUMENT_NODE:
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
    if (cur == (xmlNodePtr) ctxt->context->doc)
        return(NULL);
    if (cur == NULL)
        return(ctxt->context->node->next);; /* !!!!!!!!! */
    if (cur->childs != NULL) return(cur->childs);
    if (cur->next != NULL) return(cur->next);
    
    do {
        cur = cur->parent;
	if (cur == NULL) return(NULL);
	if (cur == ctxt->context->doc->root) return(NULL);
	if (cur->next != NULL) {
	    cur = cur->next;
	    return(cur);
	}
    } while (cur != NULL);
    return(cur);
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
    if (cur == (xmlNodePtr) ctxt->context->doc)
        return(NULL);
    if (cur == NULL)
        return(ctxt->context->node->prev); /* !!!!!!!!! */
    if (cur->last != NULL) return(cur->last);
    if (cur->prev != NULL) return(cur->prev);
    
    do {
        cur = cur->parent;
	if (cur == NULL) return(NULL);
	if (cur == ctxt->context->doc->root) return(NULL);
	if (cur->prev != NULL) {
	    cur = cur->prev;
	    return(cur);
	}
    } while (cur != NULL);
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
xmlNsPtr
xmlXPathNextNamespace(xmlXPathParserContextPtr ctxt, xmlAttrPtr cur) {
    if ((cur == NULL) || (ctxt->context->namespaces == NULL)) {
        if (ctxt->context->namespaces != NULL)
	    xmlFree(ctxt->context->namespaces);
	ctxt->context->namespaces = 
	    xmlGetNsList(ctxt->context->doc, ctxt->context->node);
	if (ctxt->context->namespaces == NULL) return(NULL);
	ctxt->context->nsNr = 0;
    }
    return(ctxt->context->namespaces[ctxt->context->nsNr++]);
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
xmlAttrPtr
xmlXPathNextAttribute(xmlXPathParserContextPtr ctxt, xmlAttrPtr cur) {
    if (cur == NULL) {
        if (ctxt->context->node == (xmlNodePtr) ctxt->context->doc)
	    return(NULL);
        return(ctxt->context->node->properties);
    }
    return(cur->next);
}

/************************************************************************
 *									*
 *		NodeTest Functions					*
 *									*
 ************************************************************************/

#define NODE_TEST_NONE	0
#define NODE_TEST_TYPE	1
#define NODE_TEST_PI	2
#define NODE_TEST_ALL	3
#define NODE_TEST_NS	4
#define NODE_TEST_NAME	5

#define NODE_TYPE_COMMENT		50
#define NODE_TYPE_TEXT			51
#define NODE_TYPE_PI			52
#define NODE_TYPE_NODE			53

#define IS_FUNCTION			200

/**
 * xmlXPathNodeCollectAndTest:
 * @ctxt:  the XPath Parser context
 * @cur:  the current node to test
 *
 * This is the function implementing a step: based on the current list
 * of nodes, it builds up a new list, looking at all nodes under that
 * axis and selecting them.
 *
 * Returns the new NodeSet resulting from the search.
 */
xmlNodeSetPtr
xmlXPathNodeCollectAndTest(xmlXPathParserContextPtr ctxt, int axis,
                 int test, int type, const xmlChar *prefix, const xmlChar *name) {
#ifdef DEBUG_STEP
    int n = 0, t = 0;
#endif
    int i;
    xmlNodeSetPtr ret;
    xmlXPathTraversalFunction next = NULL;
    xmlNodePtr cur = NULL;

    if (ctxt->context->nodelist == NULL) {
	if (ctxt->context->node == NULL) {
	    fprintf(xmlXPathDebug,
	     "xmlXPathNodeCollectAndTest %s:%d : nodelist and node are NULL\n",
	            __FILE__, __LINE__);
	    return(NULL);
	}
        STRANGE
        return(NULL);
    }
#ifdef DEBUG_STEP
    fprintf(xmlXPathDebug, "new step : ");
#endif
    switch (axis) {
        case AXIS_ANCESTOR:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'ancestors' ");
#endif
	    next = xmlXPathNextAncestor; break;
        case AXIS_ANCESTOR_OR_SELF:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'ancestors-or-self' ");
#endif
	    next = xmlXPathNextAncestorOrSelf; break;
        case AXIS_ATTRIBUTE:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'attributes' ");
#endif
	    next = (xmlXPathTraversalFunction) xmlXPathNextAttribute; break;
	    break;
        case AXIS_CHILD:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'child' ");
#endif
	    next = xmlXPathNextChild; break;
        case AXIS_DESCENDANT:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'descendant' ");
#endif
	    next = xmlXPathNextDescendant; break;
        case AXIS_DESCENDANT_OR_SELF:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'descendant-or-self' ");
#endif
	    next = xmlXPathNextDescendantOrSelf; break;
        case AXIS_FOLLOWING:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'following' ");
#endif
	    next = xmlXPathNextFollowing; break;
        case AXIS_FOLLOWING_SIBLING:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'following-siblings' ");
#endif
	    next = xmlXPathNextFollowingSibling; break;
        case AXIS_NAMESPACE:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'namespace' ");
#endif
	    next = (xmlXPathTraversalFunction) xmlXPathNextNamespace; break;
	    break;
        case AXIS_PARENT:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'parent' ");
#endif
	    next = xmlXPathNextParent; break;
        case AXIS_PRECEDING:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'preceding' ");
#endif
	    next = xmlXPathNextPreceding; break;
        case AXIS_PRECEDING_SIBLING:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'preceding-sibling' ");
#endif
	    next = xmlXPathNextPrecedingSibling; break;
        case AXIS_SELF:
#ifdef DEBUG_STEP
	    fprintf(xmlXPathDebug, "axis 'self' ");
#endif
	    next = xmlXPathNextSelf; break;
    }
    if (next == NULL) return(NULL);
    ret = xmlXPathNodeSetCreate(NULL);
#ifdef DEBUG_STEP
    fprintf(xmlXPathDebug, " context contains %d nodes\n",
            ctxt->context->nodelist->nodeNr);
    switch (test) {
	case NODE_TEST_NONE:
	    fprintf(xmlXPathDebug, "           searching for none !!!\n");
	    break;
	case NODE_TEST_TYPE:
	    fprintf(xmlXPathDebug, "           searching for type %d\n", type);
	    break;
	case NODE_TEST_PI:
	    fprintf(xmlXPathDebug, "           searching for PI !!!\n");
	    break;
	case NODE_TEST_ALL:
	    fprintf(xmlXPathDebug, "           searching for *\n");
	    break;
	case NODE_TEST_NS:
	    fprintf(xmlXPathDebug, "           searching for namespace %s\n",
	            prefix);
	    break;
	case NODE_TEST_NAME:
	    fprintf(xmlXPathDebug, "           searching for name %s\n", name);
	    if (prefix != NULL)
		fprintf(xmlXPathDebug, "           with namespace %s\n",
		        prefix);
	    break;
    }
    fprintf(xmlXPathDebug, "Testing : ");
#endif
    for (i = 0;i < ctxt->context->nodelist->nodeNr; i++) {
        ctxt->context->node = ctxt->context->nodelist->nodeTab[i];

	cur = NULL;
	do {
	    cur = next(ctxt, cur);
	    if (cur == NULL) break;
#ifdef DEBUG_STEP
            t++;
            fprintf(xmlXPathDebug, " %s", cur->name);
#endif
	    switch (test) {
                case NODE_TEST_NONE:
		    STRANGE
		    return(NULL);
                case NODE_TEST_TYPE:
		    if ((cur->type == type) ||
		        ((type == XML_ELEMENT_NODE) && 
			 ((cur->type == XML_DOCUMENT_NODE) ||
			  (cur->type == XML_HTML_DOCUMENT_NODE)))) {
#ifdef DEBUG_STEP
                        n++;
#endif
		        xmlXPathNodeSetAdd(ret, cur);
		    }
		    break;
                case NODE_TEST_PI:
		    if (cur->type == XML_PI_NODE) {
		        if ((name != NULL) &&
			    (xmlStrcmp(name, cur->name)))
			    break;
#ifdef DEBUG_STEP
			n++;
#endif
			xmlXPathNodeSetAdd(ret, cur);
		    }
		    break;
                case NODE_TEST_ALL:
		    if ((cur->type == XML_ELEMENT_NODE) ||
		        (cur->type == XML_ATTRIBUTE_NODE)) {
			/* !!! || (cur->type == XML_TEXT_NODE)) { */
#ifdef DEBUG_STEP
                        n++;
#endif
		        xmlXPathNodeSetAdd(ret, cur);
		    }
		    break;
                case NODE_TEST_NS: {
		    TODO /* namespace search */
		    break;
		}
                case NODE_TEST_NAME:
		    switch (cur->type) {
		        case XML_ELEMENT_NODE:
			    if (!xmlStrcmp(name, cur->name) && 
				(((prefix == NULL) ||
				  ((cur->ns != NULL) && 
				   (!xmlStrcmp(prefix, cur->ns->href)))))) {
#ifdef DEBUG_STEP
			    n++;
#endif
				xmlXPathNodeSetAdd(ret, cur);
			    }
			    break;
		        case XML_ATTRIBUTE_NODE: {
			    xmlAttrPtr attr = (xmlAttrPtr) cur;
			    if (!xmlStrcmp(name, attr->name)) {
#ifdef DEBUG_STEP
			    n++;
#endif
				xmlXPathNodeSetAdd(ret, cur);
			    }
			    break;
			}
			default:
			    break;
		    }
	            break;
		    
	    }
	} while (cur != NULL);
    }
#ifdef DEBUG_STEP
    fprintf(xmlXPathDebug,
            "\nExamined %d nodes, found %d nodes at that step\n", t, n);
#endif
    return(ret);
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
    if (ctxt->context->nodelist != NULL)
        xmlXPathFreeNodeSet(ctxt->context->nodelist);
    ctxt->context->node = (xmlNodePtr) ctxt->context->doc;
    ctxt->context->nodelist = xmlXPathNodeSetCreate(ctxt->context->node);
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
 *
 * Implement the last() XPath function
 * The last function returns the number of nodes in the context node list.
 */
void
xmlXPathLastFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);
    if ((ctxt->context->nodelist == NULL) ||
        (ctxt->context->node == NULL) ||
        (ctxt->context->nodelist->nodeNr == 0)) {
	valuePush(ctxt, xmlXPathNewFloat((double) 0));
    } else {
	valuePush(ctxt, 
	          xmlXPathNewFloat((double) ctxt->context->nodelist->nodeNr));
    }
}

/**
 * xmlXPathPositionFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the position() XPath function
 * The position function returns the position of the context node in the
 * context node list. The first position is 1, and so the last positionr
 * will be equal to last().
 */
void
xmlXPathPositionFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    int i;

    CHECK_ARITY(0);
    if ((ctxt->context->nodelist == NULL) ||
        (ctxt->context->node == NULL) ||
        (ctxt->context->nodelist->nodeNr == 0)) {
	valuePush(ctxt, xmlXPathNewFloat((double) 0));
    }
    for (i = 0; i < ctxt->context->nodelist->nodeNr;i++) {
        if (ctxt->context->node == ctxt->context->nodelist->nodeTab[i]) {
	    valuePush(ctxt, xmlXPathNewFloat((double) i + 1));
	    return;
	}
    }
    valuePush(ctxt, xmlXPathNewFloat((double) 0));
}

/**
 * xmlXPathCountFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the count() XPath function
 */
void
xmlXPathCountFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_NODESET);
    cur = valuePop(ctxt);

    valuePush(ctxt, xmlXPathNewFloat((double) cur->nodesetval->nodeNr));
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathIdFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the id() XPath function
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
    if (obj == NULL) ERROR(XPATH_INVALID_OPERAND);
    if (obj->type == XPATH_NODESET) {
        TODO /* ID function in case of NodeSet */
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
	    elem = attr->node;
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
 * xmlXPathLocalPartFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the local-part() XPath function
 * The local-part function returns a string containing the local part
 * of the name of the node in the argument node-set that is first in
 * document order. If the node-set is empty or the first node has no
 * name, an empty string is returned. If the argument is omitted it
 * defaults to the context node.
 */
void
xmlXPathLocalPartFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_NODESET);
    cur = valuePop(ctxt);

    if (cur->nodesetval->nodeNr == 0) {
	valuePush(ctxt, xmlXPathNewCString(""));
    } else {
	int i = 0; /* Should be first in document order !!!!! */
	valuePush(ctxt, xmlXPathNewString(cur->nodesetval->nodeTab[i]->name));
    }
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathNamespaceFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the namespace() XPath function
 * The namespace function returns a string containing the namespace URI
 * of the expanded name of the node in the argument node-set that is
 * first in document order. If the node-set is empty, the first node has
 * no name, or the expanded name has no namespace URI, an empty string
 * is returned. If the argument is omitted it defaults to the context node.
 */
void
xmlXPathNamespaceFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    if (nargs == 0) {
        valuePush(ctxt, xmlXPathNewNodeSet(ctxt->context->node));
	nargs = 1;
    }
    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_NODESET);
    cur = valuePop(ctxt);

    if (cur->nodesetval->nodeNr == 0) {
	valuePush(ctxt, xmlXPathNewCString(""));
    } else {
	int i = 0; /* Should be first in document order !!!!! */

	if (cur->nodesetval->nodeTab[i]->ns == NULL)
	    valuePush(ctxt, xmlXPathNewCString(""));
	else
	    valuePush(ctxt, xmlXPathNewString(
		      cur->nodesetval->nodeTab[i]->ns->href));
    }
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathNameFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the name() XPath function
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

    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_NODESET);
    cur = valuePop(ctxt);

    if (cur->nodesetval->nodeNr == 0) {
	valuePush(ctxt, xmlXPathNewCString(""));
    } else {
	int i = 0; /* Should be first in document order !!!!! */

	if (cur->nodesetval->nodeTab[i]->ns == NULL)
	    valuePush(ctxt, xmlXPathNewString(
	                cur->nodesetval->nodeTab[i]->name));
	    
	else {
	    char name[2000];
	    sprintf(name, "%s:%s", 
	            (char *) cur->nodesetval->nodeTab[i]->ns->prefix,
	            (char *) cur->nodesetval->nodeTab[i]->name);
	    valuePush(ctxt, xmlXPathNewCString(name));
        }
    }
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathStringFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the string() XPath function
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
 */
void
xmlXPathStringFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;

    CHECK_ARITY(1);
    cur = valuePop(ctxt);
    if (cur == NULL) ERROR(XPATH_INVALID_OPERAND);
    switch (cur->type) {
        case XPATH_NODESET:
	    if (cur->nodesetval->nodeNr == 0) {
		valuePush(ctxt, xmlXPathNewCString(""));
	    } else {
		xmlChar *res;
	        int i = 0; /* Should be first in document order !!!!! */
		res = xmlNodeGetContent(cur->nodesetval->nodeTab[i]);
		valuePush(ctxt, xmlXPathNewString(res));
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

	    if (isnan(cur->floatval))
	        sprintf(buf, "NaN");
	    else if (isinf(cur->floatval) > 0)
	        sprintf(buf, "+Infinity");
	    else if (isinf(cur->floatval) < 0)
	        sprintf(buf, "-Infinity");
	    else
		sprintf(buf, "%0g", cur->floatval);
	    valuePush(ctxt, xmlXPathNewCString(buf));
	    xmlXPathFreeObject(cur);
	    return;
	}
    }
    STRANGE
}

/**
 * xmlXPathStringLengthFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the string-length() XPath function
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
    CHECK_TYPE(XPATH_STRING);
    cur = valuePop(ctxt);
    valuePush(ctxt, xmlXPathNewFloat(xmlStrlen(cur->stringval)));
    xmlXPathFreeObject(cur);
}

/**
 * xmlXPathConcatFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the concat() XPath function
 * The concat function returns the concatenation of its arguments.
 */
void
xmlXPathConcatFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur, new;
    xmlChar *tmp;

    if (nargs < 2) {
	CHECK_ARITY(2);
    }

    cur = valuePop(ctxt);
    if ((cur == NULL) || (cur->type != XPATH_STRING)) {
        xmlXPathFreeObject(cur);
	return;
    }
    nargs--;

    while (nargs > 0) {
	new = valuePop(ctxt);
	if ((new == NULL) || (new->type != XPATH_STRING)) {
	    xmlXPathFreeObject(new);
	    xmlXPathFreeObject(cur);
	    ERROR(XPATH_INVALID_TYPE);
	}
	tmp = xmlStrcat(new->stringval, cur->stringval);
	new->stringval = cur->stringval;
	cur->stringval = tmp;

	xmlXPathFreeObject(new);
	nargs--;
    }
    valuePush(ctxt, cur);
}

/**
 * xmlXPathContainsFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the contains() XPath function
 * The contains function returns true if the first argument string
 * contains the second argument string, and otherwise returns false.
 */
void
xmlXPathContainsFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr hay, needle;

    CHECK_ARITY(2);
    CHECK_TYPE(XPATH_STRING);
    needle = valuePop(ctxt);
    hay = valuePop(ctxt);
    if ((hay == NULL) || (hay->type != XPATH_STRING)) {
        xmlXPathFreeObject(hay);
        xmlXPathFreeObject(needle);
	ERROR(XPATH_INVALID_TYPE);
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
 *
 * Implement the starts-with() XPath function
 * The starts-with function returns true if the first argument string
 * starts with the second argument string, and otherwise returns false.
 */
void
xmlXPathStartsWithFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr hay, needle;
    int n;

    CHECK_ARITY(2);
    CHECK_TYPE(XPATH_STRING);
    needle = valuePop(ctxt);
    hay = valuePop(ctxt);
    if ((hay == NULL) || (hay->type != XPATH_STRING)) {
        xmlXPathFreeObject(hay);
        xmlXPathFreeObject(needle);
	ERROR(XPATH_INVALID_TYPE);
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
 *
 * Implement the substring() XPath function
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
	CHECK_TYPE(XPATH_NUMBER);
	len = valuePop(ctxt);
	le = len->floatval;
        xmlXPathFreeObject(len);
    } else {
	le = 2000000000;
    }
    CHECK_TYPE(XPATH_NUMBER);
    start = valuePop(ctxt);
    in = start->floatval;
    xmlXPathFreeObject(start);
    CHECK_TYPE(XPATH_STRING);
    str = valuePop(ctxt);
    le += in;

    /* integer index of the first char */
    i = in;
    if (((double)i) != in) i++;
    
    /* integer index of the last char */
    l = le;
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
 *
 * Implement the substring-before() XPath function
 * The substring-before function returns the substring of the first
 * argument string that precedes the first occurrence of the second
 * argument string in the first argument string, or the empty string
 * if the first argument string does not contain the second argument
 * string. For example, substring-before("1999/04/01","/") returns 1999.
 */
void
xmlXPathSubstringBeforeFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(2);
    TODO /* substring before */
}

/**
 * xmlXPathSubstringAfterFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the substring-after() XPath function
 * The substring-after function returns the substring of the first
 * argument string that follows the first occurrence of the second
 * argument string in the first argument string, or the empty stringi
 * if the first argument string does not contain the second argument
 * string. For example, substring-after("1999/04/01","/") returns 04/01,
 * and substring-after("1999/04/01","19") returns 99/04/01.
 */
void
xmlXPathSubstringAfterFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(2);
    TODO /* substring after */
}

/**
 * xmlXPathNormalizeFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the normalize() XPath function
 * The normalize function returns the argument string with white
 * space normalized by stripping leading and trailing whitespace
 * and replacing sequences of whitespace characters by a single
 * space. Whitespace characters are the same allowed by the S production
 * in XML. If the argument is omitted, it defaults to the context
 * node converted to a string, in other words the value of the context node.
 */
void
xmlXPathNormalizeFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(1);
    TODO /* normalize isn't as boring as translate, but pretty much */
}

/**
 * xmlXPathTranslateFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the translate() XPath function
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
    CHECK_ARITY(3);
    TODO /* translate is boring, waiting for UTF-8 representation too */
}

/**
 * xmlXPathBooleanFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the boolean() XPath function
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
    if (cur == NULL) ERROR(XPATH_INVALID_OPERAND);
    switch (cur->type) {
        case XPATH_NODESET:
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
 *
 * Implement the not() XPath function
 * The not function returns true if its argument is false,
 * and false otherwise.
 */
void
xmlXPathNotFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_BOOLEAN);
    ctxt->value->boolval = ! ctxt->value->boolval;
}

/**
 * xmlXPathTrueFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the true() XPath function
 */
void
xmlXPathTrueFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);
    valuePush(ctxt, xmlXPathNewBoolean(1));
}

/**
 * xmlXPathFalseFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the false() XPath function
 */
void
xmlXPathFalseFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(0);
    valuePush(ctxt, xmlXPathNewBoolean(0));
}

/**
 * xmlXPathLangFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the lang() XPath function
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
 *
 * Implement the number() XPath function
 */
void
xmlXPathNumberFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr cur;
    double res;

    CHECK_ARITY(1);
    cur = valuePop(ctxt);
    switch (cur->type) {
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
    }
    STRANGE
}

/**
 * xmlXPathSumFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the sum() XPath function
 * The sum function returns the sum of the values of the nodes in
 * the argument node-set.
 */
void
xmlXPathSumFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(1);
    TODO /* BUG Sum : don't understand the definition */
}

/**
 * xmlXPathFloorFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the floor() XPath function
 * The floor function returns the largest (closest to positive infinity)
 * number that is not greater than the argument and that is an integer.
 */
void
xmlXPathFloorFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_NUMBER);
    /* floor(0.999999999999) => 1.0 !!!!!!!!!!! */
    ctxt->value->floatval = (double)((int) ctxt->value->floatval);
}

/**
 * xmlXPathCeilingFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the ceiling() XPath function
 * The ceiling function returns the smallest (closest to negative infinity)
 * number that is not less than the argument and that is an integer.
 */
void
xmlXPathCeilingFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    double f;

    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_NUMBER);
    f = (double)((int) ctxt->value->floatval);
    if (f != ctxt->value->floatval)
	ctxt->value->floatval = f + 1;
}

/**
 * xmlXPathRoundFunction:
 * @ctxt:  the XPath Parser context
 *
 * Implement the round() XPath function
 * The round function returns the number that is closest to the
 * argument and that is an integer. If there are two such numbers,
 * then the one that is even is returned.
 */
void
xmlXPathRoundFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    double f;

    CHECK_ARITY(1);
    CHECK_TYPE(XPATH_NUMBER);
    /* round(0.50000001) => 0  !!!!! */
    f = (double)((int) ctxt->value->floatval);
    if (ctxt->value->floatval < f + 0.5)
        ctxt->value->floatval = f;
    else if (ctxt->value->floatval == f + 0.5)
        ctxt->value->floatval = f; /* !!!! Not following the spec here */
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
void xmlXPathEvalRelativeLocationPath(xmlXPathParserContextPtr ctxt);

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
 * xmlXPathStringEvalNumber:
 * @str:  A string to scan
 *
 *  [30]   Number ::=   Digits ('.' Digits)?
 *                    | '.' Digits 
 *  [31]   Digits ::=   [0-9]+
 *
 * Parse and evaluate a Number in the string
 *
 * BUG: "1.' is not valid ... James promised correction
 *       as Digits ('.' Digits?)?
 *
 * Returns the double value.
 */
double
xmlXPathStringEvalNumber(const xmlChar *str) {
    const xmlChar *cur = str;
    double ret = 0.0;
    double mult = 1;
    int ok = 0;

    while (*cur == ' ') cur++;
    if ((*cur != '.') && ((*cur < '0') || (*cur > '9'))) {
        return(xmlXPathNAN);
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
    while (*cur == ' ') cur++;
    if (*cur != 0) return(xmlXPathNAN);
    return(ret);
}

/**
 * xmlXPathEvalNumber:
 * @ctxt:  the XPath Parser context
 *
 *  [30]   Number ::=   Digits ('.' Digits)?
 *                    | '.' Digits 
 *  [31]   Digits ::=   [0-9]+
 *
 * Parse and evaluate a Number, then push it on the stack
 *
 * BUG: "1.' is not valid ... James promised correction
 *       as Digits ('.' Digits?)?
 */
void
xmlXPathEvalNumber(xmlXPathParserContextPtr ctxt) {
    double ret = 0.0;
    double mult = 1;
    int ok = 0;

    CHECK_ERROR;
    if ((CUR != '.') && ((CUR < '0') || (CUR > '9'))) {
        ERROR(XPATH_NUMBER_ERROR);
    }
    while ((CUR >= '0') && (CUR <= '9')) {
        ret = ret * 10 + (CUR - '0');
	ok = 1;
	NEXT;
    }
    if (CUR == '.') {
        NEXT;
	if (((CUR < '0') || (CUR > '9')) && (!ok)) {
	     ERROR(XPATH_NUMBER_ERROR);
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
	    ERROR(XPATH_UNFINISHED_LITERAL_ERROR);
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
	    ERROR(XPATH_UNFINISHED_LITERAL_ERROR);
	} else {
	    ret = xmlStrndup(q, CUR_PTR - q);
	    NEXT;
        }
    } else {
	ERROR(XPATH_START_LITERAL_ERROR);
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

    if (CUR != '$') {
	ERROR(XPATH_VARIABLE_REF_ERROR);
    }
    name = xmlXPathParseQName(ctxt, &prefix);
    if (name == NULL) {
	ERROR(XPATH_VARIABLE_REF_ERROR);
    }
    value = xmlXPathVariablelookup(ctxt, prefix, name);
    if (value == NULL) {
	ERROR(XPATH_UNDEF_VARIABLE_ERROR);
    }
    valuePush(ctxt, value);
    if (prefix != NULL) xmlFree(prefix);
    xmlFree(name);
}

 
/**
 * xmlXPathFunctionLookup:
 * @ctxt:  the XPath Parser context
 * @name:  a name string
 *
 * Search for a function of the given name
 *
 *  [35]   FunctionName ::=   QName - NodeType 
 *
 * TODO: for the moment the function list is hardcoded from the spec !!!!
 *
 * Returns the xmlXPathFunction if found, or NULL otherwise
 */
xmlXPathFunction
xmlXPathIsFunction(xmlXPathParserContextPtr ctxt, const xmlChar *name) {
    switch (name[0]) {
        case 'b':
	    if (!xmlStrcmp(name, BAD_CAST "boolean"))
	        return(xmlXPathBooleanFunction);
	    break;
        case 'c':
	    if (!xmlStrcmp(name, BAD_CAST "ceiling"))
	        return(xmlXPathCeilingFunction);
	    if (!xmlStrcmp(name, BAD_CAST "count"))
	        return(xmlXPathCountFunction);
	    if (!xmlStrcmp(name, BAD_CAST "concat"))
	        return(xmlXPathConcatFunction);
	    if (!xmlStrcmp(name, BAD_CAST "contains"))
	        return(xmlXPathContainsFunction);
	    break;
        case 'i':
	    if (!xmlStrcmp(name, BAD_CAST "id"))
	        return(xmlXPathIdFunction);
	    break;
        case 'f':
	    if (!xmlStrcmp(name, BAD_CAST "false"))
	        return(xmlXPathFalseFunction);
	    if (!xmlStrcmp(name, BAD_CAST "floor"))
	        return(xmlXPathFloorFunction);
	    break;
        case 'l':
	    if (!xmlStrcmp(name, BAD_CAST "last"))
	        return(xmlXPathLastFunction);
	    if (!xmlStrcmp(name, BAD_CAST "lang"))
	        return(xmlXPathLangFunction);
	    if (!xmlStrcmp(name, BAD_CAST "local-part"))
	        return(xmlXPathLocalPartFunction);
	    break;
        case 'n':
	    if (!xmlStrcmp(name, BAD_CAST "not"))
	        return(xmlXPathNotFunction);
	    if (!xmlStrcmp(name, BAD_CAST "name"))
	        return(xmlXPathNameFunction);
	    if (!xmlStrcmp(name, BAD_CAST "namespace"))
	        return(xmlXPathNamespaceFunction);
	    if (!xmlStrcmp(name, BAD_CAST "normalize-space"))
	        return(xmlXPathNormalizeFunction);
	    if (!xmlStrcmp(name, BAD_CAST "normalize"))
	        return(xmlXPathNormalizeFunction);
	    if (!xmlStrcmp(name, BAD_CAST "number"))
	        return(xmlXPathNumberFunction);
	    break;
        case 'p':
	    if (!xmlStrcmp(name, BAD_CAST "position"))
	        return(xmlXPathPositionFunction);
	    break;
        case 'r':
	    if (!xmlStrcmp(name, BAD_CAST "round"))
	        return(xmlXPathRoundFunction);
	    break;
        case 's':
	    if (!xmlStrcmp(name, BAD_CAST "string"))
	        return(xmlXPathStringFunction);
	    if (!xmlStrcmp(name, BAD_CAST "string-length"))
	        return(xmlXPathStringLengthFunction);
	    if (!xmlStrcmp(name, BAD_CAST "starts-with"))
	        return(xmlXPathStartsWithFunction);
	    if (!xmlStrcmp(name, BAD_CAST "substring"))
	        return(xmlXPathSubstringFunction);
	    if (!xmlStrcmp(name, BAD_CAST "substring-before"))
	        return(xmlXPathSubstringBeforeFunction);
	    if (!xmlStrcmp(name, BAD_CAST "substring-after"))
	        return(xmlXPathSubstringAfterFunction);
	    if (!xmlStrcmp(name, BAD_CAST "sum"))
	        return(xmlXPathSumFunction);
	    break;
        case 't':
	    if (!xmlStrcmp(name, BAD_CAST "true"))
	        return(xmlXPathTrueFunction);
	    if (!xmlStrcmp(name, BAD_CAST "translate"))
	        return(xmlXPathTranslateFunction);
	    break;
    }
    return(NULL);
}

/**
 * xmlXPathEvalLocationPathName:
 * @ctxt:  the XPath Parser context
 * @name:  a name string
 *
 * Various names in the beginning of a LocationPath expression
 * indicate whether that's an Axis, a node type, 
 *
 *  [6]   AxisName ::=   'ancestor'
 *               | 'ancestor-or-self'
 *               | 'attribute'
 *               | 'child'
 *               | 'descendant'
 *               | 'descendant-or-self'
 *               | 'following'
 *               | 'following-sibling'
 *               | 'namespace'
 *               | 'parent'
 *               | 'preceding'
 *               | 'preceding-sibling'
 *               | 'self'
 *  [38]   NodeType ::=   'comment'
 *                    | 'text'
 *                    | 'processing-instruction'
 *                    | 'node'
 */
int
xmlXPathGetNameType(xmlXPathParserContextPtr ctxt, const xmlChar *name) {
    switch (name[0]) {
        case 'a':
	    if (!xmlStrcmp(name, BAD_CAST "ancestor")) return(AXIS_ANCESTOR);
	    if (!xmlStrcmp(name, BAD_CAST "ancestor-or-self"))
	        return(AXIS_ANCESTOR_OR_SELF);
            if (!xmlStrcmp(name, BAD_CAST "attribute")) return(AXIS_ATTRIBUTE);
	    break;
        case 'c':
            if (!xmlStrcmp(name, BAD_CAST "child")) return(AXIS_CHILD);
            if (!xmlStrcmp(name, BAD_CAST "comment")) return(NODE_TYPE_COMMENT);
	    break;
        case 'd':
            if (!xmlStrcmp(name, BAD_CAST "descendant"))
	        return(AXIS_DESCENDANT);
            if (!xmlStrcmp(name, BAD_CAST "descendant-or-self"))
	        return(AXIS_DESCENDANT_OR_SELF);
	    break;
        case 'f':
            if (!xmlStrcmp(name, BAD_CAST "following")) return(AXIS_FOLLOWING);
            if (!xmlStrcmp(name, BAD_CAST "following-sibling"))
	        return(AXIS_FOLLOWING_SIBLING);
	    break;
        case 'n':
            if (!xmlStrcmp(name, BAD_CAST "namespace")) return(AXIS_NAMESPACE);
            if (!xmlStrcmp(name, BAD_CAST "node")) return(NODE_TYPE_NODE);
	    break;
        case 'p':
            if (!xmlStrcmp(name, BAD_CAST "parent")) return(AXIS_PARENT);
            if (!xmlStrcmp(name, BAD_CAST "preceding")) return(AXIS_PRECEDING);
            if (!xmlStrcmp(name, BAD_CAST "preceding-sibling"))
	        return(AXIS_PRECEDING_SIBLING);
            if (!xmlStrcmp(name, BAD_CAST "processing-instruction"))
	        return(NODE_TYPE_PI);
	    break;
        case 's':
            if (!xmlStrcmp(name, BAD_CAST "self")) return(AXIS_SELF);
	    break;
        case 't':
            if (!xmlStrcmp(name, BAD_CAST "text")) return(NODE_TYPE_TEXT);
	    break;
    }
    if (xmlXPathIsFunction(ctxt, name)) return(IS_FUNCTION);
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
	ERROR(XPATH_EXPR_ERROR);
    }
    SKIP_BLANKS;
    func = xmlXPathIsFunction(ctxt, name);
    if (func == NULL) {
        xmlFree(name);
	ERROR(XPATH_UNKNOWN_FUNC_ERROR);
    }
#ifdef DEBUG_EXPR
    fprintf(xmlXPathDebug, "Calling function %s\n", name);
#endif

    if (CUR != '(') {
        xmlFree(name);
	ERROR(XPATH_EXPR_ERROR);
    }
    NEXT;
    SKIP_BLANKS;

    while (CUR != ')') {
        xmlXPathEvalExpr(ctxt);
	nbargs++;
	if (CUR == ')') break;
	if (CUR != ',') {
	    xmlFree(name);
	    ERROR(XPATH_EXPR_ERROR);
	}
	NEXT;
	SKIP_BLANKS;
    }
    NEXT;
    SKIP_BLANKS;
    xmlFree(name);
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
	    ERROR(XPATH_EXPR_ERROR);
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
    /****
    xmlNodeSetPtr oldset = NULL;
    xmlXPathObjectPtr arg;
     ****/

    xmlXPathEvalPrimaryExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    
    if (CUR != '[') return;

    CHECK_TYPE(XPATH_NODESET);

    while (CUR == '[') {
	xmlXPathEvalPredicate(ctxt);
	SKIP_BLANKS;
    }

    
}

/**
 * xmlXPathScanName:
 * @ctxt:  the XPath Parser context
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
    xmlNodeSetPtr newset = NULL;

    SKIP_BLANKS;
    if ((CUR == '$') || (CUR == '(') || (IS_DIGIT(CUR)) ||
        (CUR == '\'') || (CUR == '"')) {
	xmlXPathEvalFilterExpr(ctxt);
	CHECK_ERROR;
	if ((CUR == '/') && (NXT(1) == '/')) {
	    SKIP(2);
	    SKIP_BLANKS;
	    if (ctxt->context->nodelist == NULL) {
		STRANGE
		xmlXPathRoot(ctxt);
	    }
	    newset = xmlXPathNodeCollectAndTest(ctxt, AXIS_DESCENDANT_OR_SELF,
			     NODE_TEST_TYPE, XML_ELEMENT_NODE, NULL, NULL);
	    if (ctxt->context->nodelist != NULL)
		xmlXPathFreeNodeSet(ctxt->context->nodelist);
	    ctxt->context->nodelist = newset;
	    ctxt->context->node = NULL;
	    xmlXPathEvalRelativeLocationPath(ctxt);
	} else if (CUR == '/') {
	    xmlXPathEvalRelativeLocationPath(ctxt);
	}
    } else {
        /******* !!!!!!!!!! @attname */
        xmlChar *name;

	name = xmlXPathScanName(ctxt);
	if ((name == NULL) || (!xmlXPathIsFunction(ctxt, name)))
	    xmlXPathEvalLocationPath(ctxt);
	else
	    xmlXPathEvalFilterExpr(ctxt);
	if (name != NULL)
	    xmlFree(name);
    }
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
    xmlXPathEvalPathExpr(ctxt);
    CHECK_ERROR;
    SKIP_BLANKS;
    if (CUR == '|') {
	xmlNodeSetPtr old = ctxt->context->nodelist;

	NEXT;
	SKIP_BLANKS;
	xmlXPathEvalPathExpr(ctxt);

	if (ctxt->context->nodelist == NULL)
	    ctxt->context->nodelist = old;
	else {
	    ctxt->context->nodelist = 
	        xmlXPathNodeSetMerge(ctxt->context->nodelist, old);
	    xmlXPathFreeNodeSet(old);
	}
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
    while ((CUR == 'a') && (NXT(1) == 'n') && (NXT(2) == 'n')) {
	xmlXPathObjectPtr arg1, arg2;

        SKIP(3);
	SKIP_BLANKS;
        xmlXPathEvalEqualityExpr(ctxt);
	CHECK_ERROR;
	arg2 = valuePop(ctxt);
	arg1 = valuePop(ctxt);
	arg1->boolval &= arg2->boolval;
	valuePush(ctxt, arg1);
	xmlXPathFreeObject(arg2);
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
	arg2 = valuePop(ctxt);
	arg1 = valuePop(ctxt);
	arg1->boolval |= arg2->boolval;
	valuePush(ctxt, arg1);
	xmlXPathFreeObject(arg2);
    }
}

/**
 * xmlXPathEvaluatePredicateResult:
 * @ctxt:  the XPath Parser context
 * @res:  the Predicate Expression evaluation result
 * @index:  index of the current node in the current list
 *
 * Evaluate a predicate result for the current node.
 * A PredicateExpr is evaluated by evaluating the Expr and converting
 * the result to a boolean. If the result is a number, the result will
 * be converted to true if the number is equal to the position of the
 * context node in the context node list (as returned by the position
 * function) and will be converted to false otherwise; if the result
 * is not a number, then the result will be converted as if by a call
 * to the boolean function. 
 */
int
xmlXPathEvaluatePredicateResult(xmlXPathParserContextPtr ctxt, 
                                xmlXPathObjectPtr res, int index) {
    if (res == NULL) return(0);
    switch (res->type) {
        case XPATH_BOOLEAN:
	    return(res->boolval);
        case XPATH_NUMBER:
	    return(res->floatval == index);
        case XPATH_NODESET:
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
 * Parse and evaluate a predicate for all the elements of the
 * current node list. Then refine the list by removing all
 * nodes where the predicate is false.
 */
void
xmlXPathEvalPredicate(xmlXPathParserContextPtr ctxt) {
    const xmlChar *cur;
    xmlXPathObjectPtr res;
    xmlNodeSetPtr newset = NULL;
    int i;

    SKIP_BLANKS;
    if (CUR != '[') {
	ERROR(XPATH_INVALID_PREDICATE_ERROR);
    }
    NEXT;
    SKIP_BLANKS;
    if ((ctxt->context->nodelist == NULL) ||
        (ctxt->context->nodelist->nodeNr == 0)) {
        ctxt->context->node = NULL;
	xmlXPathEvalExpr(ctxt);
	CHECK_ERROR;
	res = valuePop(ctxt);
	if (res != NULL)
	    xmlXPathFreeObject(res);
    } else {
        cur = ctxt->cur;
	newset = xmlXPathNodeSetCreate(NULL);
        for (i = 0; i < ctxt->context->nodelist->nodeNr; i++) {
	    ctxt->cur = cur;
	    ctxt->context->node = ctxt->context->nodelist->nodeTab[i];
	    xmlXPathEvalExpr(ctxt);
	    CHECK_ERROR;
	    res = valuePop(ctxt);
	    if (xmlXPathEvaluatePredicateResult(ctxt, res, i + 1))
	        xmlXPathNodeSetAdd(newset,
		                   ctxt->context->nodelist->nodeTab[i]);
	    if (res != NULL)
	    xmlXPathFreeObject(res);
	}
	if (ctxt->context->nodelist != NULL)
	    xmlXPathFreeNodeSet(ctxt->context->nodelist);
	ctxt->context->nodelist = newset;
	ctxt->context->node = NULL;
    }
    if (CUR != ']') {
	ERROR(XPATH_INVALID_PREDICATE_ERROR);
    }
    NEXT;
    SKIP_BLANKS;
#ifdef DEBUG_STEP
    fprintf(xmlXPathDebug, "After predicate : ");
    xmlXPathDebugNodeSet(xmlXPathDebug, ctxt->context->nodelist);
#endif
}

/**
 * xmlXPathEvalBasis:
 * @ctxt:  the XPath Parser context
 *
 *  [5]   Basis ::=   AxisName '::' NodeTest 
 *            | AbbreviatedBasis 
 *  [13]   AbbreviatedBasis ::=   NodeTest 
 *                           | '@' NodeTest 
 *  [7]   NodeTest ::=   WildcardName 
 *              | NodeType '(' ')'
 *              | 'processing-instruction' '(' Literal ')'
 *  [37]   WildcardName ::=   '*'
 *                    | NCName ':' '*'
 *                    | QName 
 *
 * Evaluate one step in a Location Path
 */
void
xmlXPathEvalBasis(xmlXPathParserContextPtr ctxt) {
    xmlChar *name = NULL;
    xmlChar *prefix = NULL;
    int type = 0;
    int axis = AXIS_CHILD; /* the default on abbreviated syntax */
    int nodetest = NODE_TEST_NONE;
    int nodetype = 0;
    xmlNodeSetPtr newset = NULL;

    if (CUR == '@') {
        NEXT;
	axis = AXIS_ATTRIBUTE;
	goto parse_NodeTest;
    } else if (CUR == '*') {
        NEXT;
        nodetest = NODE_TEST_ALL;
    } else {
        name = xmlXPathParseNCName(ctxt);
	if (name == NULL) {
	    ERROR(XPATH_EXPR_ERROR);
	}
	type = xmlXPathGetNameType(ctxt, name);
	switch (type) {
	    case IS_FUNCTION: {
		xmlXPathFunction func;
		int nbargs = 0;
		xmlXPathObjectPtr top;

                top = ctxt->value;
		func = xmlXPathIsFunction(ctxt, name);
		if (func == NULL) {
		    xmlFree(name);
		    ERROR(XPATH_UNKNOWN_FUNC_ERROR);
		}
#ifdef DEBUG_EXPR
		fprintf(xmlXPathDebug, "Calling function %s\n", name);
#endif

		if (CUR != '(') {
		    xmlFree(name);
		    ERROR(XPATH_EXPR_ERROR);
		}
		NEXT;

		while (CUR != ')') {
		    xmlXPathEvalExpr(ctxt);
		    nbargs++;
		    if (CUR == ')') break;
		    if (CUR != ',') {
			xmlFree(name);
			ERROR(XPATH_EXPR_ERROR);
		    }
		    NEXT;
		}
		NEXT;
		xmlFree(name);
		func(ctxt, nbargs);
		if ((ctxt->value != top) &&
		    (ctxt->value != NULL) &&
		    (ctxt->value->type == XPATH_NODESET)) {
		    xmlXPathObjectPtr cur;

		    cur = valuePop(ctxt);
		    ctxt->context->nodelist = cur->nodesetval;
		    ctxt->context->node = NULL;
		    cur->nodesetval = NULL;
                    xmlXPathFreeObject(cur);
		}
	        return;
	    }
	    /*
	     * Simple case: no axis seach all given node types.
	     */
            case NODE_TYPE_COMMENT:
	        if ((CUR != '(') || (NXT(1) != ')')) break;
		SKIP(2);
		nodetest = NODE_TEST_TYPE;
		nodetype = XML_COMMENT_NODE;
		goto search_nodes;
            case NODE_TYPE_TEXT:
	        if ((CUR != '(') || (NXT(1) != ')')) break;
		SKIP(2);
		nodetest = NODE_TEST_TYPE;
		nodetype = XML_TEXT_NODE;
		goto search_nodes;
            case NODE_TYPE_NODE:
	        if ((CUR != '(') || (NXT(1) != ')')) {
		    nodetest = NODE_TEST_NAME;
		    break;
		}
		SKIP(2);
		nodetest = NODE_TEST_TYPE;
		nodetype = XML_ELEMENT_NODE;
		goto search_nodes;
            case NODE_TYPE_PI:
	        if (CUR != '(') break;
		if (name != NULL) xmlFree(name);
		name = NULL;
		if (NXT(1) != ')') {
		    xmlXPathObjectPtr cur;

		    /*
		     * Specific case: search a PI by name.
		     */
                    NEXT;
		    nodetest = NODE_TEST_PI;
		    xmlXPathEvalLiteral(ctxt);
		    CHECK_ERROR;
		    if (CUR != ')')
			ERROR(XPATH_UNCLOSED_ERROR);
                    NEXT;
		    xmlXPathStringFunction(ctxt, 1);
		    CHECK_ERROR;
		    cur = valuePop(ctxt);
		    name = xmlStrdup(cur->stringval);
		    xmlXPathFreeObject(cur);
		} else
		    SKIP(2);
		nodetest = NODE_TEST_PI;
		goto search_nodes;
	
	    /*
	     * Handling of the compund form: got the axis.
	     */
            case AXIS_ANCESTOR:
            case AXIS_ANCESTOR_OR_SELF:
            case AXIS_ATTRIBUTE:
            case AXIS_CHILD:
            case AXIS_DESCENDANT:
            case AXIS_DESCENDANT_OR_SELF:
            case AXIS_FOLLOWING:
            case AXIS_FOLLOWING_SIBLING:
            case AXIS_NAMESPACE:
            case AXIS_PARENT:
            case AXIS_PRECEDING:
            case AXIS_PRECEDING_SIBLING:
            case AXIS_SELF:
	        if ((CUR != ':') || (NXT(1) != ':')) {
		    nodetest = NODE_TEST_NAME;
		    break;
		}
		SKIP(2);
		axis = type;
		break;
	
	    /*
	     * Default: abbreviated syntax the axis is AXIS_CHILD
	     */
	    default:
	        nodetest = NODE_TEST_NAME;
	}
parse_NodeTest:
	if (nodetest == NODE_TEST_NONE) {
	    if (CUR == '*') {
		NEXT;
		nodetest = NODE_TEST_ALL;
	    } else {
		if (name != NULL) 
		    xmlFree(name);
		name = xmlXPathParseQName(ctxt, &prefix);
		if (name == NULL) {
		    ERROR(XPATH_EXPR_ERROR);
		}
		type = xmlXPathGetNameType(ctxt, name);
		switch (type) {
		    /*
		     * Simple case: no axis seach all given node types.
		     */
		    case NODE_TYPE_COMMENT:
			if ((CUR != '(') || (NXT(1) != ')')) break;
			SKIP(2);
			nodetest = NODE_TEST_TYPE;
			nodetype = XML_COMMENT_NODE;
			goto search_nodes;
		    case NODE_TYPE_TEXT:
			if ((CUR != '(') || (NXT(1) != ')')) break;
			SKIP(2);
			nodetest = NODE_TEST_TYPE;
			nodetype = XML_TEXT_NODE;
			goto search_nodes;
		    case NODE_TYPE_NODE:
			if ((CUR != '(') || (NXT(1) != ')')) {
			    nodetest = NODE_TEST_NAME;
			    break;
			}
			SKIP(2);
			nodetest = NODE_TEST_TYPE;
			nodetype = XML_ELEMENT_NODE;
			goto search_nodes;
		    case NODE_TYPE_PI:
			if (CUR != '(') break;
			if (name != NULL) xmlFree(name);
			name = NULL;
			if (NXT(1) != ')') {
			    xmlXPathObjectPtr cur;

			    /*
			     * Specific case: search a PI by name.
			     */
			    NEXT;
			    nodetest = NODE_TEST_PI;
			    xmlXPathEvalLiteral(ctxt);
			    CHECK_ERROR;
			    if (CUR != ')')
				ERROR(XPATH_UNCLOSED_ERROR);
			    NEXT;
			    xmlXPathStringFunction(ctxt, 1);
			    CHECK_ERROR;
			    cur = valuePop(ctxt);
			    name = xmlStrdup(cur->stringval);
			    xmlXPathFreeObject(cur);
			} else
			    SKIP(2);
			nodetest = NODE_TEST_PI;
			goto search_nodes;
		}
		nodetest = NODE_TEST_NAME;
	    }
	} else if ((CUR == ':') && (nodetest == NODE_TEST_NAME)) {
	    NEXT;
	    prefix = name;
	    if (CUR == '*') {
	        NEXT;
		nodetest = NODE_TEST_ALL;
	    } else 
		name = xmlXPathParseNCName(ctxt);
	} else if (name == NULL)
	    ERROR(XPATH_EXPR_ERROR);
    }

search_nodes:
        
#ifdef DEBUG_STEP
    fprintf(xmlXPathDebug, "Basis : computing new set\n");
#endif
    newset = xmlXPathNodeCollectAndTest(ctxt, axis, nodetest, nodetype,
                                        prefix, name);
    if (ctxt->context->nodelist != NULL)
	xmlXPathFreeNodeSet(ctxt->context->nodelist);
    ctxt->context->nodelist = newset;
    ctxt->context->node = NULL;
#ifdef DEBUG_STEP
    fprintf(xmlXPathDebug, "Basis : ");
    xmlXPathDebugNodeSet(stdout, ctxt->context->nodelist);
#endif
    if (name != NULL) xmlFree(name);
    if (prefix != NULL) xmlFree(prefix);
}

/**
 * xmlXPathEvalStep:
 * @ctxt:  the XPath Parser context
 *
 *  [4]   Step ::=   Basis Predicate*
 *                     | AbbreviatedStep 
 *  [12]   AbbreviatedStep ::=   '.'
 *                           | '..'
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
    xmlNodeSetPtr newset = NULL;

    SKIP_BLANKS;
    if ((CUR == '.') && (NXT(1) == '.')) {
	SKIP(2);
	SKIP_BLANKS;
	if (ctxt->context->nodelist == NULL) {
	    STRANGE
	    xmlXPathRoot(ctxt);
	}
	newset = xmlXPathNodeCollectAndTest(ctxt, AXIS_PARENT,
			 NODE_TEST_TYPE, XML_ELEMENT_NODE, NULL, NULL);
	if (ctxt->context->nodelist != NULL)
	    xmlXPathFreeNodeSet(ctxt->context->nodelist);
	ctxt->context->nodelist = newset;
	ctxt->context->node = NULL;
    } else if (CUR == '.') {
	NEXT;
	SKIP_BLANKS;
    } else {
	xmlXPathEvalBasis(ctxt);
	SKIP_BLANKS;
	while (CUR == '[') {
	    xmlXPathEvalPredicate(ctxt);
	}
    }
#ifdef DEBUG_STEP
    fprintf(xmlXPathDebug, "Step : ");
    xmlXPathDebugNodeSet(xmlXPathDebug, ctxt->context->nodelist);
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
xmlXPathEvalRelativeLocationPath(xmlXPathParserContextPtr ctxt) {
    xmlNodeSetPtr newset = NULL;

    SKIP_BLANKS;
    xmlXPathEvalStep(ctxt);
    SKIP_BLANKS;
    while (CUR == '/') {
	if ((CUR == '/') && (NXT(1) == '/')) {
	    SKIP(2);
	    SKIP_BLANKS;
	    if (ctxt->context->nodelist == NULL) {
		STRANGE
		xmlXPathRoot(ctxt);
	    }
	    newset = xmlXPathNodeCollectAndTest(ctxt, AXIS_DESCENDANT_OR_SELF,
			     NODE_TEST_TYPE, XML_ELEMENT_NODE, NULL, NULL);
	    if (ctxt->context->nodelist != NULL)
		xmlXPathFreeNodeSet(ctxt->context->nodelist);
	    ctxt->context->nodelist = newset;
	    ctxt->context->node = NULL;
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
    xmlNodeSetPtr newset = NULL;

    SKIP_BLANKS;
    if (CUR != '/') {
        xmlXPathEvalRelativeLocationPath(ctxt);
    } else {
	while (CUR == '/') {
	    if ((CUR == '/') && (NXT(1) == '/')) {
		SKIP(2);
		SKIP_BLANKS;
		if (ctxt->context->nodelist == NULL)
		    xmlXPathRoot(ctxt);
		newset = xmlXPathNodeCollectAndTest(ctxt,
		                 AXIS_DESCENDANT_OR_SELF, NODE_TEST_TYPE,
				 XML_ELEMENT_NODE, NULL, NULL);
		if (ctxt->context->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->context->nodelist);
		ctxt->context->nodelist = newset;
		ctxt->context->node = NULL;
		xmlXPathEvalRelativeLocationPath(ctxt);
	    } else if (CUR == '/') {
		NEXT;
		SKIP_BLANKS;
		xmlXPathRoot(ctxt);
		if (CUR != 0)
		    xmlXPathEvalRelativeLocationPath(ctxt);
	    } else {
		xmlXPathEvalRelativeLocationPath(ctxt);
	    }
	}
    }
}

/**
 * xmlXPathEval:
 * @str:  the XPath expression
 * @ctxt:  the XPath context
 *
 * Evaluate the XPath Location Path in the given context.
 *
 * Returns the xmlXPathObjectPtr resulting from the eveluation or NULL.
 *         the caller has to free the object.
 */
xmlXPathObjectPtr
xmlXPathEval(const xmlChar *str, xmlXPathContextPtr ctxt) {
    xmlXPathParserContextPtr pctxt;
    xmlXPathObjectPtr res = NULL, tmp;
    int stack = 0;

    xmlXPathInit();

    CHECK_CONTEXT

    if (xmlXPathDebug == NULL)
        xmlXPathDebug = stderr;
    pctxt = xmlXPathNewParserContext(str, ctxt);
    if (str[0] == '/')
        xmlXPathRoot(pctxt);
    xmlXPathEvalLocationPath(pctxt);

    /* TODO: cleanup nodelist, res = valuePop(pctxt); */
    do {
        tmp = valuePop(pctxt);
	if (tmp != NULL) {
	    xmlXPathFreeObject(tmp);
	    stack++;    
        }
    } while (tmp != NULL);
    if (stack != 0) {
	fprintf(xmlXPathDebug, "xmlXPathEval: %d object left on the stack\n",
	        stack);
    }
    if (pctxt->error == XPATH_EXPRESSION_OK)
	res = xmlXPathNewNodeSetList(pctxt->context->nodelist);
    else
        res = NULL;
    xmlXPathFreeParserContext(pctxt);
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

    CHECK_CONTEXT

    if (xmlXPathDebug == NULL)
        xmlXPathDebug = stderr;
    pctxt = xmlXPathNewParserContext(str, ctxt);
    xmlXPathEvalExpr(pctxt);

    res = valuePop(pctxt);
    do {
        tmp = valuePop(pctxt);
	if (tmp != NULL) {
	    xmlXPathFreeObject(tmp);
	    stack++;
	}
    } while (tmp != NULL);
    if (stack != 0) {
	fprintf(xmlXPathDebug, "xmlXPathEval: %d object left on the stack\n",
	        stack);
    }
    xmlXPathFreeParserContext(pctxt);
    return(res);
}

