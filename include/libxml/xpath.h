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

#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _xmlXPathContext xmlXPathContext;
typedef xmlXPathContext *xmlXPathContextPtr;
typedef struct _xmlXPathParserContext xmlXPathParserContext;
typedef xmlXPathParserContext *xmlXPathParserContextPtr;

/*
 * A node-set (an unordered collection of nodes without duplicates) 
 */
typedef struct _xmlNodeSet xmlNodeSet;
typedef xmlNodeSet *xmlNodeSetPtr;
struct _xmlNodeSet {
    int nodeNr;			/* # of node in the set */
    int nodeMax;		/* allocated space */
    xmlNodePtr *nodeTab;	/* array of nodes in no particular order */
};

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
#define XPATH_USERS	5

typedef struct _xmlXPathObject xmlXPathObject;
typedef xmlXPathObject *xmlXPathObjectPtr;
struct _xmlXPathObject {
    int type;
    xmlNodeSetPtr nodesetval;
    int boolval;
    double floatval;
    xmlChar *stringval;
    void *user;
};

/*
 * A conversion function is associated to a type and used to cast
 * the new type to primitive values.
 */
typedef int (*xmlXPathConvertFunc) (xmlXPathObjectPtr obj, int type);

/*
 * Extra type: a name and a conversion function.
 */

typedef struct _xmlXPathType xmlXPathType;
typedef xmlXPathType *xmlXPathTypePtr;
struct _xmlXPathType {
    const xmlChar         *name;		/* the type name */
    xmlXPathConvertFunc func;		/* the conversion function */
};

/*
 * Extra variable: a name and a value.
 */

typedef struct _xmlXPathVariable xmlXPathVariable;
typedef xmlXPathVariable *xmlXPathVariablePtr;
struct _xmlXPathVariable {
    const xmlChar       *name;		/* the variable name */
    xmlXPathObjectPtr value;		/* the value */
};

/*
 * an evaluation function, the parameters are on the context stack
 */

typedef void (*xmlXPathEvalFunc)(xmlXPathParserContextPtr ctxt, int nargs);

/*
 * Extra function: a name and a evaluation function.
 */

typedef struct _xmlXPathFunct xmlXPathFunct;
typedef xmlXPathFunct *xmlXPathFuncPtr;
struct _xmlXPathFunct {
    const xmlChar      *name;		/* the function name */
    xmlXPathEvalFunc func;		/* the evaluation function */
};

/*
 * An axis traversal function. To traverse an axis, the engine calls
 * the first time with cur == NULL and repeat until the function returns
 * NULL indicating the end of the axis traversal.
 */

typedef xmlXPathObjectPtr (*xmlXPathAxisFunc)	(xmlXPathParserContextPtr ctxt,
						 xmlXPathObjectPtr cur);

/*
 * Extra axis: a name and an axis function.
 */

typedef struct _xmlXPathAxis xmlXPathAxis;
typedef xmlXPathAxis *xmlXPathAxisPtr;
struct _xmlXPathAxis {
    const xmlChar      *name;		/* the axis name */
    xmlXPathAxisFunc func;		/* the search function */
};

/* 
 * Expression evaluation occurs with respect to a context.
 * he context consists of:
 *    - a node (the context node) 
 *    - a node list (the context node list) 
 *    - a set of variable bindings 
 *    - a function library 
 *    - the set of namespace declarations in scope for the expression 
 */

struct _xmlXPathContext {
    xmlDocPtr doc;			/* The current document */
    xmlNodePtr node;			/* The current node */
    xmlNodeSetPtr nodelist;		/* The current node list */

    int nb_variables;			/* number of defined variables */
    int max_variables;			/* max number of variables */
    xmlXPathVariablePtr *variables;	/* Array of defined variables */

    int nb_types;			/* number of defined types */
    int max_types;			/* max number of types */
    xmlXPathTypePtr *types;		/* Array of defined types */

    int nb_funcs;			/* number of defined funcs */
    int max_funcs;			/* max number of funcs */
    xmlXPathFuncPtr *funcs;		/* Array of defined funcs */

    int nb_axis;			/* number of defined axis */
    int max_axis;			/* max number of axis */
    xmlXPathAxisPtr *axis;		/* Array of defined axis */

    /* Namespace traversal should be implemented with user */
    xmlNsPtr *namespaces;		/* The namespaces lookup */
    int nsNr;				/* the current Namespace index */
    void *user;				/* user defined extra info */
};

/*
 * An XPath parser context, it contains pure parsing informations,
 * an xmlXPathContext, and the stack of objects.
 */
struct _xmlXPathParserContext {
    const xmlChar *cur;			/* the current char being parsed */
    const xmlChar *base;			/* the full expression */

    int error;				/* error code */

    xmlXPathContextPtr  context;	/* the evaluation context */
    xmlXPathObjectPtr     value;	/* the current value */
    int                 valueNr;	/* number of values stacked */
    int                valueMax;	/* max number of values stacked */
    xmlXPathObjectPtr *valueTab;	/* stack of values */
};

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

/**
 * Registering extensions to the expression language
 */
/* TODO */ int	   xmlXPathRegisterType		(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
                                                 xmlXPathConvertFunc f);
/* TODO */ int	   xmlXPathRegisterAxis		(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 xmlXPathAxisFunc f);
/* TODO */ int	   xmlXPathRegisterFunc		(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 xmlXPathFunction f);
/* TODO */ int	   xmlXPathRegisterVariable	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 xmlXPathObject value);

/**
 * Evaluation functions.
 */
xmlXPathContextPtr xmlXPathNewContext		(xmlDocPtr doc);
void		   xmlXPathFreeContext		(xmlXPathContextPtr ctxt);
xmlXPathObjectPtr  xmlXPathEval			(const xmlChar *str,
						 xmlXPathContextPtr ctxt);
void		   xmlXPathFreeObject		(xmlXPathObjectPtr obj);
xmlXPathObjectPtr  xmlXPathEvalExpression	(const xmlChar *str,
						 xmlXPathContextPtr ctxt);
xmlNodeSetPtr	   xmlXPathNodeSetCreate	(xmlNodePtr val);
void		   xmlXPathFreeNodeSetList	(xmlXPathObjectPtr obj);
void		   xmlXPathFreeNodeSet		(xmlNodeSetPtr obj);

#ifdef __cplusplus
}
#endif
#endif /* ! __XML_XPATH_H__ */
