/*
 * pattern.c: Implemetation of selectors for nodes
 *
 * Reference:
 *   http://www.w3.org/TR/2001/REC-xmlschema-1-20010502/
 *   to some extent 
 *   http://www.w3.org/TR/1999/REC-xml-19991116
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#define IN_LIBXML
#include "libxml.h"

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/hash.h>
#include <libxml/dict.h>
#include <libxml/xmlerror.h>
#include <libxml/parserInternals.h>
#include <libxml/pattern.h>

#ifdef LIBXML_PATTERN_ENABLED

#define ERROR(a, b, c, d)
#define ERROR5(a, b, c, d, e)

/*
 * Types are private:
 */

typedef enum {
    XML_OP_END=0,
    XML_OP_ROOT,
    XML_OP_ELEM,
    XML_OP_CHILD,
    XML_OP_ATTR,
    XML_OP_PARENT,
    XML_OP_ANCESTOR,
    XML_OP_NS,
    XML_OP_ALL
} xmlPatOp;


typedef struct _xmlStepOp xmlStepOp;
typedef xmlStepOp *xmlStepOpPtr;
struct _xmlStepOp {
    xmlPatOp op;
    const xmlChar *value;
    const xmlChar *value2;
};

struct _xmlPattern {
    void *data;    		/* the associated template */
    struct _xmlPattern *next; /* siblings */
    const xmlChar *pattern;	/* the pattern */

    int nbStep;
    int maxStep;
    xmlStepOpPtr steps;        /* ops for computation */
};

typedef struct _xmlPatParserContext xmlPatParserContext;
typedef xmlPatParserContext *xmlPatParserContextPtr;
struct _xmlPatParserContext {
    const xmlChar *cur;			/* the current char being parsed */
    const xmlChar *base;		/* the full expression */
    int	           error;		/* error code */
    xmlDictPtr     dict;		/* the dictionnary if any */
    xmlPatternPtr  comp;		/* the result */
    xmlNodePtr     elem;		/* the current node if any */    
    const xmlChar **namespaces;		/* the namespaces definitions */
    int   nb_namespaces;		/* the number of namespaces */
};

/************************************************************************
 * 									*
 * 			Type functions 					*
 * 									*
 ************************************************************************/

/**
 * xmlNewPattern:
 *
 * Create a new XSLT Pattern
 *
 * Returns the newly allocated xmlPatternPtr or NULL in case of error
 */
static xmlPatternPtr
xmlNewPattern(void) {
    xmlPatternPtr cur;

    cur = (xmlPatternPtr) xmlMalloc(sizeof(xmlPattern));
    if (cur == NULL) {
	ERROR(NULL, NULL, NULL,
		"xmlNewPattern : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlPattern));
    cur->maxStep = 10;
    cur->steps = (xmlStepOpPtr) xmlMalloc(cur->maxStep * sizeof(xmlStepOp));
    if (cur->steps == NULL) {
        xmlFree(cur);
	ERROR(NULL, NULL, NULL,
		"xmlNewPattern : malloc failed\n");
	return(NULL);
    }
    return(cur);
}

/**
 * xmlFreePattern:
 * @comp:  an XSLT comp
 *
 * Free up the memory allocated by @comp
 */
void
xmlFreePattern(xmlPatternPtr comp) {
    xmlStepOpPtr op;
    int i;

    if (comp == NULL)
	return;
    if (comp->pattern != NULL)
	xmlFree((xmlChar *)comp->pattern);
    if (comp->steps != NULL) {
	for (i = 0;i < comp->nbStep;i++) {
	    op = &comp->steps[i];
	    if (op->value != NULL)
		xmlFree((xmlChar *) op->value);
	    if (op->value2 != NULL)
		xmlFree((xmlChar *) op->value2);
	}
	xmlFree(comp->steps);
    }
    memset(comp, -1, sizeof(xmlPattern));
    xmlFree(comp);
}

/**
 * xmlFreePatternList:
 * @comp:  an XSLT comp list
 *
 * Free up the memory allocated by all the elements of @comp
 */
void
xmlFreePatternList(xmlPatternPtr comp) {
    xmlPatternPtr cur;

    while (comp != NULL) {
	cur = comp;
	comp = comp->next;
	xmlFreePattern(cur);
    }
}

/**
 * xmlNewPatParserContext:
 * @pattern:  the pattern context
 * @dict:  the inherited dictionnary or NULL
 * @namespaces: the prefix definitions, array of [URI, prefix] or NULL
 *
 * Create a new XML pattern parser context
 *
 * Returns the newly allocated xmlPatParserContextPtr or NULL in case of error
 */
static xmlPatParserContextPtr
xmlNewPatParserContext(const xmlChar *pattern, xmlDictPtr dict,
                       const xmlChar **namespaces) {
    xmlPatParserContextPtr cur;

    if (pattern == NULL)
        return(NULL);

    cur = (xmlPatParserContextPtr) xmlMalloc(sizeof(xmlPatParserContext));
    if (cur == NULL) {
	ERROR(NULL, NULL, NULL,
		"xmlNewPatParserContext : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlPatParserContext));
    cur->dict = dict;
    cur->cur = pattern;
    cur->base = pattern;
    if (namespaces != NULL) {
        int i;
	for (i = 0;namespaces[2 * i] != NULL;i++);
        cur->nb_namespaces = i;
    } else {
        cur->nb_namespaces = 0;
    }
    cur->namespaces = namespaces;
    return(cur);
}

/**
 * xmlFreePatParserContext:
 * @ctxt:  an XSLT parser context
 *
 * Free up the memory allocated by @ctxt
 */
static void
xmlFreePatParserContext(xmlPatParserContextPtr ctxt) {
    if (ctxt == NULL)
	return;
    memset(ctxt, -1, sizeof(xmlPatParserContext));
    xmlFree(ctxt);
}

/**
 * xmlPatternAdd:
 * @comp:  the compiled match expression
 * @op:  an op
 * @value:  the first value
 * @value2:  the second value
 *
 * Add an step to an XSLT Compiled Match
 *
 * Returns -1 in case of failure, 0 otherwise.
 */
static int
xmlPatternAdd(xmlPatParserContextPtr ctxt ATTRIBUTE_UNUSED,
                xmlPatternPtr comp,
                xmlPatOp op, xmlChar * value, xmlChar * value2)
{
    if (comp->nbStep >= comp->maxStep) {
        xmlStepOpPtr temp;
	temp = (xmlStepOpPtr) xmlRealloc(comp->steps, comp->maxStep * 2 *
	                                 sizeof(xmlStepOp));
        if (temp == NULL) {
	    ERROR(ctxt, NULL, NULL,
			     "xmlPatternAdd: realloc failed\n");
	    return (-1);
	}
	comp->steps = temp;
	comp->maxStep *= 2;
    }
    comp->steps[comp->nbStep].op = op;
    comp->steps[comp->nbStep].value = value;
    comp->steps[comp->nbStep].value2 = value2;
    comp->nbStep++;
    return (0);
}

#if 0
/**
 * xsltSwapTopPattern:
 * @comp:  the compiled match expression
 *
 * reverse the two top steps.
 */
static void
xsltSwapTopPattern(xmlPatternPtr comp) {
    int i;
    int j = comp->nbStep - 1;

    if (j > 0) {
	register const xmlChar *tmp;
	register xmlPatOp op;
	i = j - 1;
	tmp = comp->steps[i].value;
	comp->steps[i].value = comp->steps[j].value;
	comp->steps[j].value = tmp;
	tmp = comp->steps[i].value2;
	comp->steps[i].value2 = comp->steps[j].value2;
	comp->steps[j].value2 = tmp;
	op = comp->steps[i].op;
	comp->steps[i].op = comp->steps[j].op;
	comp->steps[j].op = op;
    }
}
#endif

/**
 * xmlReversePattern:
 * @comp:  the compiled match expression
 *
 * reverse all the stack of expressions
 *
 * returns 0 in case of success and -1 in case of error.
 */
static int
xmlReversePattern(xmlPatternPtr comp) {
    int i = 0;
    int j = comp->nbStep - 1;

    if (comp->nbStep >= comp->maxStep) {
        xmlStepOpPtr temp;
	temp = (xmlStepOpPtr) xmlRealloc(comp->steps, comp->maxStep * 2 *
	                                 sizeof(xmlStepOp));
        if (temp == NULL) {
	    ERROR(ctxt, NULL, NULL,
			     "xmlReversePattern: realloc failed\n");
	    return (-1);
	}
	comp->steps = temp;
	comp->maxStep *= 2;
    }
    while (j > i) {
	register const xmlChar *tmp;
	register xmlPatOp op;
	tmp = comp->steps[i].value;
	comp->steps[i].value = comp->steps[j].value;
	comp->steps[j].value = tmp;
	tmp = comp->steps[i].value2;
	comp->steps[i].value2 = comp->steps[j].value2;
	comp->steps[j].value2 = tmp;
	op = comp->steps[i].op;
	comp->steps[i].op = comp->steps[j].op;
	comp->steps[j].op = op;
	j--;
	i++;
    }
    comp->steps[comp->nbStep].value = NULL;
    comp->steps[comp->nbStep].value2 = NULL;
    comp->steps[comp->nbStep++].op = XML_OP_END;
    return(0);
}

/************************************************************************
 * 									*
 * 		The interpreter for the precompiled patterns		*
 * 									*
 ************************************************************************/

/**
 * xmlPatMatch:
 * @comp: the precompiled pattern
 * @node: a node
 *
 * Test wether the node matches the pattern
 *
 * Returns 1 if it matches, 0 if it doesn't and -1 in case of failure
 */
static int
xmlPatMatch(xmlPatternPtr comp, xmlNodePtr node) {
    int i;
    xmlStepOpPtr step;

    if ((comp == NULL) || (node == NULL)) return(-1);
    for (i = 0;i < comp->nbStep;i++) {
	step = &comp->steps[i];
	switch (step->op) {
            case XML_OP_END:
		return(1);
            case XML_OP_ROOT:
		if ((node->type == XML_DOCUMENT_NODE) ||
#ifdef LIBXML_DOCB_ENABLED
		    (node->type == XML_DOCB_DOCUMENT_NODE) ||
#endif
		    (node->type == XML_HTML_DOCUMENT_NODE))
		    continue;
		return(0);
            case XML_OP_ELEM:
		if (node->type != XML_ELEMENT_NODE)
		    return(0);
		if (step->value == NULL)
		    continue;
		if (step->value[0] != node->name[0])
		    return(0);
		if (!xmlStrEqual(step->value, node->name))
		    return(0);

		/* Namespace test */
		if (node->ns == NULL) {
		    if (step->value2 != NULL)
			return(0);
		} else if (node->ns->href != NULL) {
		    if (step->value2 == NULL)
			return(0);
		    if (!xmlStrEqual(step->value2, node->ns->href))
			return(0);
		}
		continue;
            case XML_OP_CHILD: {
		xmlNodePtr lst;

		if ((node->type != XML_ELEMENT_NODE) &&
		    (node->type != XML_DOCUMENT_NODE) &&
#ifdef LIBXML_DOCB_ENABLED
		    (node->type != XML_DOCB_DOCUMENT_NODE) &&
#endif
		    (node->type != XML_HTML_DOCUMENT_NODE))
		    return(0);

		lst = node->children;

		if (step->value != NULL) {
		    while (lst != NULL) {
			if ((lst->type == XML_ELEMENT_NODE) &&
			    (step->value[0] == lst->name[0]) &&
			    (xmlStrEqual(step->value, lst->name)))
			    break;
			lst = lst->next;
		    }
		    if (lst != NULL)
			continue;
		}
		return(0);
	    }
            case XML_OP_ATTR:
		if (node->type != XML_ATTRIBUTE_NODE)
		    return(0);
		if (step->value != NULL) {
		    if (step->value[0] != node->name[0])
			return(0);
		    if (!xmlStrEqual(step->value, node->name))
			return(0);
		}
		/* Namespace test */
		if (node->ns == NULL) {
		    if (step->value2 != NULL)
			return(0);
		} else if (step->value2 != NULL) {
		    if (!xmlStrEqual(step->value2, node->ns->href))
			return(0);
		}
		continue;
            case XML_OP_PARENT:
		if ((node->type == XML_DOCUMENT_NODE) ||
		    (node->type == XML_HTML_DOCUMENT_NODE) ||
#ifdef LIBXML_DOCB_ENABLED
		    (node->type == XML_DOCB_DOCUMENT_NODE) ||
#endif
		    (node->type == XML_NAMESPACE_DECL))
		    return(0);
		node = node->parent;
		if (node == NULL)
		    return(0);
		if (step->value == NULL)
		    continue;
		if (step->value[0] != node->name[0])
		    return(0);
		if (!xmlStrEqual(step->value, node->name))
		    return(0);
		/* Namespace test */
		if (node->ns == NULL) {
		    if (step->value2 != NULL)
			return(0);
		} else if (node->ns->href != NULL) {
		    if (step->value2 == NULL)
			return(0);
		    if (!xmlStrEqual(step->value2, node->ns->href))
			return(0);
		}
		continue;
            case XML_OP_ANCESTOR:
		/* TODO: implement coalescing of ANCESTOR/NODE ops */
		if (step->value == NULL) {
		    i++;
		    step = &comp->steps[i];
		    if (step->op == XML_OP_ROOT)
			return(1);
		    if (step->op != XML_OP_ELEM)
			return(0);
		    if (step->value == NULL)
			return(-1);
		}
		if (node == NULL)
		    return(0);
		if ((node->type == XML_DOCUMENT_NODE) ||
		    (node->type == XML_HTML_DOCUMENT_NODE) ||
#ifdef LIBXML_DOCB_ENABLED
		    (node->type == XML_DOCB_DOCUMENT_NODE) ||
#endif
		    (node->type == XML_NAMESPACE_DECL))
		    return(0);
		node = node->parent;
		while (node != NULL) {
		    if (node == NULL)
			return(0);
		    if ((node->type == XML_ELEMENT_NODE) &&
			(step->value[0] == node->name[0]) &&
			(xmlStrEqual(step->value, node->name))) {
			/* Namespace test */
			if (node->ns == NULL) {
			    if (step->value2 == NULL)
				break;
			} else if (node->ns->href != NULL) {
			    if ((step->value2 != NULL) &&
			        (xmlStrEqual(step->value2, node->ns->href)))
				break;
			}
		    }
		    node = node->parent;
		}
		if (node == NULL)
		    return(0);
		continue;
            case XML_OP_NS:
		if (node->type != XML_ELEMENT_NODE)
		    return(0);
		if (node->ns == NULL) {
		    if (step->value != NULL)
			return(0);
		} else if (node->ns->href != NULL) {
		    if (step->value == NULL)
			return(0);
		    if (!xmlStrEqual(step->value, node->ns->href))
			return(0);
		}
		break;
            case XML_OP_ALL:
		if (node->type != XML_ELEMENT_NODE)
		    return(0);
		break;
	}
    }
    return(1);
}

/************************************************************************
 *									*
 *			Dedicated parser for templates			*
 *									*
 ************************************************************************/

#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);
#define CUR (*ctxt->cur)
#define SKIP(val) ctxt->cur += (val)
#define NXT(val) ctxt->cur[(val)]
#define CUR_PTR ctxt->cur

#define SKIP_BLANKS 							\
    while (IS_BLANK_CH(CUR)) NEXT

#define CURRENT (*ctxt->cur)
#define NEXT ((*ctxt->cur) ?  ctxt->cur++: ctxt->cur)


#define PUSH(op, val, val2) 						\
    if (xmlPatternAdd(ctxt, ctxt->comp, (op), (val), (val2))) goto error;

#define XSLT_ERROR(X)							\
    { xsltError(ctxt, __FILE__, __LINE__, X);			\
      ctxt->error = (X); return; }

#define XSLT_ERROR0(X)							\
    { xsltError(ctxt, __FILE__, __LINE__, X);			\
      ctxt->error = (X); return(0); }

#if 0
/**
 * xmlPatScanLiteral:
 * @ctxt:  the XPath Parser context
 *
 * Parse an XPath Litteral:
 *
 * [29] Literal ::= '"' [^"]* '"'
 *                | "'" [^']* "'"
 *
 * Returns the Literal parsed or NULL
 */

static xmlChar *
xmlPatScanLiteral(xmlPatParserContextPtr ctxt) {
    const xmlChar *q, *cur;
    xmlChar *ret = NULL;
    int val, len;

    SKIP_BLANKS;
    if (CUR == '"') {
        NEXT;
	cur = q = CUR_PTR;
	val = xmlStringCurrentChar(NULL, cur, &len);
	while ((IS_CHAR(val)) && (val != '"')) {
	    cur += len;
	    val = xmlStringCurrentChar(NULL, cur, &len);
	}
	if (!IS_CHAR(val)) {
	    ctxt->error = 1;
	    return(NULL);
	} else {
	    ret = xmlStrndup(q, cur - q);
        }
	cur += len;
	CUR_PTR = cur;
    } else if (CUR == '\'') {
        NEXT;
	cur = q = CUR_PTR;
	val = xmlStringCurrentChar(NULL, cur, &len);
	while ((IS_CHAR(val)) && (val != '\'')) {
	    cur += len;
	    val = xmlStringCurrentChar(NULL, cur, &len);
	}
	if (!IS_CHAR(val)) {
	    ctxt->error = 1;
	    return(NULL);
	} else {
	    ret = xmlStrndup(q, cur - q);
        }
	cur += len;
	CUR_PTR = cur;
    } else {
	/* XP_ERROR(XPATH_START_LITERAL_ERROR); */
	ctxt->error = 1;
	return(NULL);
    }
    return(ret);
}
#endif

/**
 * xmlPatScanName:
 * @ctxt:  the XPath Parser context
 *
 * [4] NameChar ::= Letter | Digit | '.' | '-' | '_' | 
 *                  CombiningChar | Extender
 *
 * [5] Name ::= (Letter | '_' | ':') (NameChar)*
 *
 * [6] Names ::= Name (S Name)*
 *
 * Returns the Name parsed or NULL
 */

static xmlChar *
xmlPatScanName(xmlPatParserContextPtr ctxt) {
    const xmlChar *q, *cur;
    xmlChar *ret = NULL;
    int val, len;

    SKIP_BLANKS;

    cur = q = CUR_PTR;
    val = xmlStringCurrentChar(NULL, cur, &len);
    if (!IS_LETTER(val) && (val != '_') && (val != ':'))
	return(NULL);

    while ((IS_LETTER(val)) || (IS_DIGIT(val)) ||
           (val == '.') || (val == '-') ||
	   (val == '_') || 
	   (IS_COMBINING(val)) ||
	   (IS_EXTENDER(val))) {
	cur += len;
	val = xmlStringCurrentChar(NULL, cur, &len);
    }
    ret = xmlStrndup(q, cur - q);
    CUR_PTR = cur;
    return(ret);
}

/**
 * xmlPatScanNCName:
 * @ctxt:  the XPath Parser context
 *
 * Parses a non qualified name
 *
 * Returns the Name parsed or NULL
 */

static xmlChar *
xmlPatScanNCName(xmlPatParserContextPtr ctxt) {
    const xmlChar *q, *cur;
    xmlChar *ret = NULL;
    int val, len;

    SKIP_BLANKS;

    cur = q = CUR_PTR;
    val = xmlStringCurrentChar(NULL, cur, &len);
    if (!IS_LETTER(val) && (val != '_'))
	return(NULL);

    while ((IS_LETTER(val)) || (IS_DIGIT(val)) ||
           (val == '.') || (val == '-') ||
	   (val == '_') ||
	   (IS_COMBINING(val)) ||
	   (IS_EXTENDER(val))) {
	cur += len;
	val = xmlStringCurrentChar(NULL, cur, &len);
    }
    ret = xmlStrndup(q, cur - q);
    CUR_PTR = cur;
    return(ret);
}

#if 0
/**
 * xmlPatScanQName:
 * @ctxt:  the XPath Parser context
 * @prefix:  the place to store the prefix
 *
 * Parse a qualified name
 *
 * Returns the Name parsed or NULL
 */

static xmlChar *
xmlPatScanQName(xmlPatParserContextPtr ctxt, xmlChar **prefix) {
    xmlChar *ret = NULL;

    *prefix = NULL;
    ret = xmlPatScanNCName(ctxt);
    if (CUR == ':') {
        *prefix = ret;
	NEXT;
	ret = xmlPatScanNCName(ctxt);
    }
    return(ret);
}
#endif

/**
 * xmlCompileStepPattern:
 * @ctxt:  the compilation context
 *
 * Compile the Step Pattern and generates a precompiled
 * form suitable for fast matching.
 *
 * [3]    Step    ::=    '.' | NameTest
 * [4]    NameTest    ::=    QName | '*' | NCName ':' '*' 
 */

static void
xmlCompileStepPattern(xmlPatParserContextPtr ctxt) {
    xmlChar *token = NULL;
    xmlChar *name = NULL;
    const xmlChar *URI = NULL;
    xmlChar *URL = NULL;

    SKIP_BLANKS;
    if (CUR == '.') {
	NEXT;
	PUSH(XML_OP_ELEM, NULL, NULL);
	return;
    }
    name = xmlPatScanNCName(ctxt);
    if (name == NULL) {
	if (CUR == '*') {
	    NEXT;
	    PUSH(XML_OP_ALL, NULL, NULL);
	    return;
	} else {
	    ERROR(NULL, NULL, NULL,
		    "xmlCompileStepPattern : Name expected\n");
	    ctxt->error = 1;
	    return;
	}
    }
    SKIP_BLANKS;
    if (CUR == ':') {
	NEXT;
	if (CUR != ':') {
	    xmlChar *prefix = name;
	    xmlNsPtr ns;

	    /*
	     * This is a namespace match
	     */
	    token = xmlPatScanName(ctxt);
	    ns = xmlSearchNs(NULL, ctxt->elem, prefix);
	    if (ns == NULL) {
		ERROR5(NULL, NULL, NULL,
	    "xmlCompileStepPattern : no namespace bound to prefix %s\n",
				 prefix);
		ctxt->error = 1;
		goto error;
	    } else {
		URL = xmlStrdup(ns->href);
	    }
	    xmlFree(prefix);
	    if (token == NULL) {
		if (CUR == '*') {
		    NEXT;
		    PUSH(XML_OP_NS, URL, NULL);
		} else {
		    ERROR(NULL, NULL, NULL,
			    "xmlCompileStepPattern : Name expected\n");
		    ctxt->error = 1;
		    goto error;
		}
	    } else {
		PUSH(XML_OP_ELEM, token, URL);
	    }
	} else {
	    NEXT;
	    if (xmlStrEqual(token, (const xmlChar *) "child")) {
		xmlFree(token);
		token = xmlPatScanName(ctxt);
		if (token == NULL) {
	            if (CUR == '*') {
            	        NEXT;
	                PUSH(XML_OP_ALL, token, NULL);
	                return;
	            } else {
		        ERROR(NULL, NULL, NULL,
			    "xmlCompileStepPattern : QName expected\n");
		        ctxt->error = 1;
		        goto error;
		    }
		}
		TODO
		/* URI = xsltGetQNameURI(ctxt->elem, &token); */
		if (token == NULL) {
		    ctxt->error = 1;
		    goto error;
		} else {
		    name = xmlStrdup(token);
		    if (URI != NULL)
			URL = xmlStrdup(URI);
		}
		PUSH(XML_OP_CHILD, name, URL);
	    } else if (xmlStrEqual(token, (const xmlChar *) "attribute")) {
		xmlFree(token);
		token = xmlPatScanName(ctxt);
		if (token == NULL) {
		    ERROR(NULL, NULL, NULL,
			    "xmlCompileStepPattern : QName expected\n");
		    ctxt->error = 1;
		    goto error;
		}
		TODO
		/* URI = xsltGetQNameURI(ctxt->elem, &token); */
		if (token == NULL) {
		    ctxt->error = 1;
		    goto error;
		} else {
		    name = xmlStrdup(token);
		    if (URI != NULL)
			URL = xmlStrdup(URI);
		}
		PUSH(XML_OP_ATTR, name, URL);
	    } else {
		ERROR(NULL, NULL, NULL,
		    "xmlCompileStepPattern : 'child' or 'attribute' expected\n");
		ctxt->error = 1;
		goto error;
	    }
	    xmlFree(token);
	}
    } else if (CUR == '*') {
	NEXT;
	PUSH(XML_OP_ALL, token, NULL);
    } else {
	if (name == NULL) {
	    ctxt->error = 1;
	    goto error;
	}
	PUSH(XML_OP_ELEM, name, NULL);
    }
    return;
error:
    if (token != NULL)
	xmlFree(token);
    if (name != NULL)
	xmlFree(name);
}

/**
 * xmlCompilePathPattern:
 * @ctxt:  the compilation context
 *
 * Compile the Path Pattern and generates a precompiled
 * form suitable for fast matching.
 *
 * [5]    Path    ::=    ('.//')? ( Step '/' )* ( Step | '@' NameTest ) 
 */
static void
xmlCompilePathPattern(xmlPatParserContextPtr ctxt) {
    SKIP_BLANKS;
    if ((CUR == '/') && (NXT(1) == '/')) {
	/*
	 * since we reverse the query
	 * a leading // can be safely ignored
	 */
	NEXT;
	NEXT;
    } else if ((CUR == '.') && (NXT(1) == '/') && (NXT(2) == '/')) {
	/*
	 * a leading .// can be safely ignored
	 */
	NEXT;
	NEXT;
	NEXT;
    }
    if (CUR == '@') {
	TODO
    } else {
	xmlCompileStepPattern(ctxt);
	SKIP_BLANKS;
	while (CUR == '/') {
	    if ((CUR == '/') && (NXT(1) == '/')) {
	        PUSH(XML_OP_ANCESTOR, NULL, NULL);
		NEXT;
		NEXT;
		SKIP_BLANKS;
		xmlCompileStepPattern(ctxt);
	    } else {
	        PUSH(XML_OP_PARENT, NULL, NULL);
		NEXT;
		SKIP_BLANKS;
		if ((CUR != 0) || (CUR == '|')) {
		    xmlCompileStepPattern(ctxt);
		}
	    }
	}
    }
error:
    return;
}
/************************************************************************
 *									*
 *			The public interfaces				*
 *									*
 ************************************************************************/

/**
 * xmlPatterncompile:
 * @pattern: the pattern to compile
 * @dict: an optional dictionnary for interned strings
 * @flags: compilation flags, undefined yet
 * @namespaces: the prefix definitions, array of [URI, prefix] or NULL
 *
 * Compile a pattern.
 *
 * Returns the compiled for of the pattern or NULL in case of error
 */
xmlPatternPtr
xmlPatterncompile(const xmlChar *pattern, xmlDict *dict,
                  int flags ATTRIBUTE_UNUSED,
                  const xmlChar **namespaces) {
    xmlPatternPtr ret = NULL;
    xmlPatParserContextPtr ctxt = NULL;

    ctxt = xmlNewPatParserContext(pattern, dict, namespaces);
    if (ctxt == NULL) goto error;
    ret = xmlNewPattern();
    if (ret == NULL) goto error;
    ctxt->comp = ret;

    xmlCompilePathPattern(ctxt);
    xmlFreePatParserContext(ctxt);

    if (xmlReversePattern(ret) < 0)
        goto error;
    return(ret);
error:
    if (ctxt != NULL) xmlFreePatParserContext(ctxt);
    if (ret != NULL) xmlFreePattern(ret);
    return(NULL);
}

/**
 * xmlPatternMatch:
 * @comp: the precompiled pattern
 * @node: a node
 *
 * Test wether the node matches the pattern
 *
 * Returns 1 if it matches, 0 if it doesn't and -1 in case of failure
 */
int
xmlPatternMatch(xmlPatternPtr comp, xmlNodePtr node)
{
    if ((comp == NULL) || (node == NULL))
        return(-1);
    return(xmlPatMatch(comp, node));
}

#endif /* LIBXML_PATTERN_ENABLED */
