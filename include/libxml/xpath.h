/*
 * xpath.c: interface for XML Path Language implementation
 *
 * Reference: W3C Working Draft 5 July 1999
 *            http://www.w3.org/Style/XSL/Group/1999/07/xpath-19990705.html
 *
 * See COPYRIGHT for the status of this software
 *
 * Author: Daniel.Veillard@w3.org
 */

#ifndef __XML_XPATH_H__
#define __XML_XPATH_H__

#include "tree.h"

/*
 * A node-set (an unordered collection of nodes without duplicates) 
 */
typedef struct xmlNodeSet {
    int nodeNr;			/* # of node in the set */
    int nodeMax;		/* allocated space */
    xmlNodePtr *nodeTab;	/* array of nodes in no particular order */
} xmlNodeSet, *xmlNodeSetPtr;

/*
 * An expression is evaluated to yield an object, which
 * has one of the following four basic types:
 *   - node-set
 *   - boolean
 *   - number
 *   - string
 */

#define XPATH_UNDEFINED	0
#define XPATH_NODESET	1
#define XPATH_BOOLEAN	2
#define XPATH_NUMBER	3
#define XPATH_STRING	4
#define XPATH_MARKER	5  /* used for func call checks */

typedef struct xmlXPathObject {
    int type;
    xmlNodeSetPtr nodesetval;
    int boolval;
    float floatval;
    CHAR *stringval;
} xmlXPathObject, *xmlXPathObjectPtr;

/* 
 * Expression evaluation occurs with respect to a context.
 * he context consists of:
 *    - a node (the context node) 
 *    - a node list (the context node list) 
 *    - a set of variable bindings 
 *    - a function library 
 *    - the set of namespace declarations in scope for the expression 
 */

typedef struct xmlXPathContext {
    xmlDocPtr doc;			/* The current document */
    xmlNodePtr node;			/* The current node */
    xmlNodeSetPtr nodelist;		/* The current node list */
    void *variables; /* TODO !!!! */
    void *functions; /* TODO !!!! */
    void *namespaces; /* TODO !!!! */
} xmlXPathContext, *xmlXPathContextPtr;

/*
 * An XPath parser context, it contains pure parsing informations,
 * an xmlXPathContext, and the stack of objects.
 */
typedef struct xmlXPathParserContext {
    const CHAR *cur;			/* the current char being parsed */
    const CHAR *base;			/* the full expression */

    int error;				/* error code */

    xmlXPathContextPtr  context;	/* the evaluation context */
    xmlXPathObjectPtr     value;	/* the current value */
    int                 valueNr;	/* number of values stacked */
    int                valueMax;	/* max number of values stacked */
    xmlXPathObjectPtr *valueTab;	/* stack of values */
} xmlXPathParserContext, *xmlXPathParserContextPtr;

/*
 * An XPath function
 * The arguments (if any) are popped out of the context stack
 * and the result is pushed on the stack.
 */

typedef void (*xmlXPathFunction) (xmlXPathParserContextPtr ctxt, int nargs);

/************************************************************************
 *									*
 *			Public API					*
 *									*
 ************************************************************************/

xmlXPathContextPtr xmlXPathNewContext(xmlDocPtr doc, void *variables,
                                      void *functions, void *namespaces);
void xmlXPathFreeContext(xmlXPathContextPtr ctxt);
xmlXPathObjectPtr xmlXPathEval(const CHAR *str, xmlXPathContextPtr ctxt);
void xmlXPathFreeObject(xmlXPathObjectPtr obj);
xmlXPathObjectPtr xmlXPathEvalExpression(const CHAR *str,
                                         xmlXPathContextPtr ctxt);

#endif /* ! __XML_XPATH_H__ */
