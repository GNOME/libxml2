/*
 * xpointer.c : Code to handle XML Pointer
 *
 * World Wide Web Consortium Working Draft 03-March-1998 
 * http://www.w3.org/TR/2000/CR-xptr-20000607
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

/**
 * TODO: better handling of error cases, the full expression should
 *       be parsed beforehand instead of a progressive evaluation
 */

#include <stdio.h>
#include <libxml/xpointer.h>
#include <libxml/xmlmemory.h>
#include <libxml/parserInternals.h>
#include <libxml/xpath.h>

#ifdef LIBXML_XPTR_ENABLED
extern FILE *xmlXPathDebug;

#define TODO 								\
    fprintf(xmlXPathDebug, "Unimplemented block at %s:%d\n",		\
            __FILE__, __LINE__);

#define STRANGE 							\
    fprintf(xmlXPathDebug, "Internal error at %s:%d\n",			\
            __FILE__, __LINE__);

/************************************************************************
 *									*
 *		Handling of XPointer specific types			*
 *									*
 ************************************************************************/

/**
 * xmlXPtrNewPoint:
 * @node:  the xmlNodePtr
 * @index:  the index within the node
 *
 * Create a new xmlXPathObjectPtr of type point
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewPoint(xmlNodePtr node, int index) {
    xmlXPathObjectPtr ret;

    if (node == NULL)
	return(NULL);
    if (index < 0)
	return(NULL);

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewPoint: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_POINT;
    ret->user = (void *) node;
    ret->index = index;
    return(ret);
}

/**
 * xmlXPtrNewRangePoints:
 * @start:  the starting point
 * @end:  the ending point
 *
 * Create a new xmlXPathObjectPtr of type range using 2 Points
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewRangePoints(xmlXPathObjectPtr start, xmlXPathObjectPtr end) {
    xmlXPathObjectPtr ret;

    if (start == NULL)
	return(NULL);
    if (end == NULL)
	return(NULL);
    if (start->type != XPATH_POINT)
	return(NULL);
    if (end->type != XPATH_POINT)
	return(NULL);

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewRangePoints: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_RANGE;
    ret->user = start->user;
    ret->index = start->index;
    ret->user2 = end->user;
    ret->index2 = end->index;
    return(ret);
}

/**
 * xmlXPtrNewRangePointNode:
 * @start:  the starting point
 * @end:  the ending node
 *
 * Create a new xmlXPathObjectPtr of type range from a point to a node
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewRangePointNode(xmlXPathObjectPtr start, xmlNodePtr end) {
    xmlXPathObjectPtr ret;

    if (start == NULL)
	return(NULL);
    if (end == NULL)
	return(NULL);
    if (start->type != XPATH_POINT)
	return(NULL);

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewRangePointNode: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_RANGE;
    ret->user = start->user;
    ret->index = start->index;
    ret->user2 = end;
    ret->index2 = -1;
    return(ret);
}

/**
 * xmlXPtrNewRangeNodePoint:
 * @start:  the starting node
 * @end:  the ending point
 *
 * Create a new xmlXPathObjectPtr of type range from a node to a point
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewRangeNodePoint(xmlNodePtr start, xmlXPathObjectPtr end) {
    xmlXPathObjectPtr ret;

    if (start == NULL)
	return(NULL);
    if (end == NULL)
	return(NULL);
    if (start->type != XPATH_POINT)
	return(NULL);
    if (end->type != XPATH_POINT)
	return(NULL);

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewRangeNodePoint: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_RANGE;
    ret->user = start;
    ret->index = -1;
    ret->user2 = end->user;
    ret->index2 = end->index;
    return(ret);
}

/**
 * xmlXPtrNewRangeNodes:
 * @start:  the starting node
 * @end:  the ending node
 *
 * Create a new xmlXPathObjectPtr of type range using 2 nodes
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewRangeNodes(xmlNodePtr start, xmlNodePtr end) {
    xmlXPathObjectPtr ret;

    if (start == NULL)
	return(NULL);
    if (end == NULL)
	return(NULL);

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewRangeNodes: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_RANGE;
    ret->user = start;
    ret->index = -1;
    ret->user2 = end;
    ret->index2 = -1;
    return(ret);
}

/**
 * xmlXPtrNewCollapsedRange:
 * @start:  the starting and ending node
 *
 * Create a new xmlXPathObjectPtr of type range using a single nodes
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewCollapsedRange(xmlNodePtr start) {
    xmlXPathObjectPtr ret;

    if (start == NULL)
	return(NULL);

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewRangeNodes: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_RANGE;
    ret->user = start;
    ret->index = -1;
    ret->user2 = NULL;
    ret->index2 = -1;
    return(ret);
}

/**
 * xmlXPtrNewRangeNodeObject:
 * @start:  the starting node
 * @end:  the ending object
 *
 * Create a new xmlXPathObjectPtr of type range from a not to an object
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewRangeNodeObject(xmlNodePtr start, xmlXPathObjectPtr end) {
    xmlXPathObjectPtr ret;

    if (start == NULL)
	return(NULL);
    if (end == NULL)
	return(NULL);
    switch (end->type) {
	case XPATH_POINT:
	    break;
	case XPATH_NODESET:
	    /*
	     * Empty set ... 
	     */
	    if (end->nodesetval->nodeNr <= 0)
		return(NULL);
	    break;
	default:
	    TODO
	    return(NULL);
    }

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewRangeNodeObject: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_RANGE;
    ret->user = start;
    ret->index = -1;
    switch (end->type) {
	case XPATH_POINT:
	    ret->user2 = end->user;
	    ret->index2 = end->index;
	case XPATH_NODESET: {
	    ret->user2 = end->nodesetval->nodeTab[end->nodesetval->nodeNr - 1];
	    ret->index2 = -1;
	    break;
	}
	default:
	    STRANGE
	    return(NULL);
    }
    return(ret);
}

#define XML_RANGESET_DEFAULT	10

/**
 * xmlXPtrLocationSetCreate:
 * @val:  an initial xmlXPathObjectPtr, or NULL
 *
 * Create a new xmlLocationSetPtr of type double and of value @val
 *
 * Returns the newly created object.
 */
xmlLocationSetPtr
xmlXPtrLocationSetCreate(xmlXPathObjectPtr val) {
    xmlLocationSetPtr ret;

    ret = (xmlLocationSetPtr) xmlMalloc(sizeof(xmlLocationSet));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrLocationSetCreate: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlLocationSet));
    if (val != NULL) {
        ret->locTab = (xmlXPathObjectPtr *) xmlMalloc(XML_RANGESET_DEFAULT *
					     sizeof(xmlXPathObjectPtr));
	if (ret->locTab == NULL) {
	    fprintf(xmlXPathDebug, "xmlXPtrLocationSetCreate: out of memory\n");
	    return(NULL);
	}
	memset(ret->locTab, 0 ,
	       XML_RANGESET_DEFAULT * (size_t) sizeof(xmlXPathObjectPtr));
        ret->locMax = XML_RANGESET_DEFAULT;
	ret->locTab[ret->locNr++] = val;
    }
    return(ret);
}

/**
 * xmlXPtrLocationSetAdd:
 * @cur:  the initial range set
 * @val:  a new xmlXPathObjectPtr
 *
 * add a new xmlXPathObjectPtr ot an existing LocationSet
 */
void
xmlXPtrLocationSetAdd(xmlLocationSetPtr cur, xmlXPathObjectPtr val) {
    int i;

    if (val == NULL) return;

    /*
     * check against doublons
     */
    for (i = 0;i < cur->locNr;i++)
        if (cur->locTab[i] == val) return;

    /*
     * grow the locTab if needed
     */
    if (cur->locMax == 0) {
        cur->locTab = (xmlXPathObjectPtr *) xmlMalloc(XML_RANGESET_DEFAULT *
					     sizeof(xmlXPathObjectPtr));
	if (cur->locTab == NULL) {
	    fprintf(xmlXPathDebug, "xmlXPtrLocationSetAdd: out of memory\n");
	    return;
	}
	memset(cur->locTab, 0 ,
	       XML_RANGESET_DEFAULT * (size_t) sizeof(xmlXPathObjectPtr));
        cur->locMax = XML_RANGESET_DEFAULT;
    } else if (cur->locNr == cur->locMax) {
        xmlXPathObjectPtr *temp;

        cur->locMax *= 2;
	temp = (xmlXPathObjectPtr *) xmlRealloc(cur->locTab, cur->locMax *
				      sizeof(xmlXPathObjectPtr));
	if (temp == NULL) {
	    fprintf(xmlXPathDebug, "xmlXPtrLocationSetAdd: out of memory\n");
	    return;
	}
	cur->locTab = temp;
    }
    cur->locTab[cur->locNr++] = val;
}

/**
 * xmlXPtrLocationSetMerge:
 * @val1:  the first LocationSet
 * @val2:  the second LocationSet
 *
 * Merges two rangesets, all ranges from @val2 are added to @val1
 *
 * Returns val1 once extended or NULL in case of error.
 */
xmlLocationSetPtr
xmlXPtrLocationSetMerge(xmlLocationSetPtr val1, xmlLocationSetPtr val2) {
    int i;

    if (val1 == NULL) return(NULL);
    if (val2 == NULL) return(val1);

    /*
     * !!!!! this can be optimized a lot, knowing that both
     *       val1 and val2 already have unicity of their values.
     */

    for (i = 0;i < val2->locNr;i++)
        xmlXPtrLocationSetAdd(val1, val2->locTab[i]);

    return(val1);
}

/**
 * xmlXPtrLocationSetDel:
 * @cur:  the initial range set
 * @val:  an xmlXPathObjectPtr
 *
 * Removes an xmlXPathObjectPtr from an existing LocationSet
 */
void
xmlXPtrLocationSetDel(xmlLocationSetPtr cur, xmlXPathObjectPtr val) {
    int i;

    if (cur == NULL) return;
    if (val == NULL) return;

    /*
     * check against doublons
     */
    for (i = 0;i < cur->locNr;i++)
        if (cur->locTab[i] == val) break;

    if (i >= cur->locNr) {
#ifdef DEBUG
        fprintf(xmlXPathDebug, 
	        "xmlXPtrLocationSetDel: Range %s wasn't found in RangeList\n",
		val->name);
#endif
        return;
    }
    cur->locNr--;
    for (;i < cur->locNr;i++)
        cur->locTab[i] = cur->locTab[i + 1];
    cur->locTab[cur->locNr] = NULL;
}

/**
 * xmlXPtrLocationSetRemove:
 * @cur:  the initial range set
 * @val:  the index to remove
 *
 * Removes an entry from an existing LocationSet list.
 */
void
xmlXPtrLocationSetRemove(xmlLocationSetPtr cur, int val) {
    if (cur == NULL) return;
    if (val >= cur->locNr) return;
    cur->locNr--;
    for (;val < cur->locNr;val++)
        cur->locTab[val] = cur->locTab[val + 1];
    cur->locTab[cur->locNr] = NULL;
}

/**
 * xmlXPtrFreeLocationSet:
 * @obj:  the xmlLocationSetPtr to free
 *
 * Free the LocationSet compound (not the actual ranges !).
 */
void
xmlXPtrFreeLocationSet(xmlLocationSetPtr obj) {
    int i;

    if (obj == NULL) return;
    if (obj->locTab != NULL) {
	for (i = 0;i < obj->locNr; i++) {
            xmlXPathFreeObject(obj->locTab[i]);
	}
#ifdef DEBUG
	memset(obj->locTab, 0xB ,
	       (size_t) sizeof(xmlXPathObjectPtr) * obj->locMax);
#endif
	xmlFree(obj->locTab);
    }
#ifdef DEBUG
    memset(obj, 0xB , (size_t) sizeof(xmlLocationSet));
#endif
    xmlFree(obj);
}

#if defined(DEBUG) || defined(DEBUG_STEP)
/**
 * xmlXPtrDebugLocationSet:
 * @output:  a FILE * for the output
 * @obj:  the xmlLocationSetPtr to free
 *
 * Quick display of a LocationSet
 */
void
xmlXPtrDebugLocationSet(FILE *output, xmlLocationSetPtr obj) {
    int i;

    if (output == NULL) output = xmlXPathDebug;
    if (obj == NULL)  {
        fprintf(output, "LocationSet == NULL !\n");
	return;
    }
    if (obj->locNr == 0) {
        fprintf(output, "LocationSet is empty\n");
	return;
    }
    if (obj->locTab == NULL) {
	fprintf(output, " locTab == NULL !\n");
	return;
    }
    for (i = 0; i < obj->locNr; i++) {
        if (obj->locTab[i] == NULL) {
	    fprintf(output, " NULL !\n");
	    return;
        }
	if ((obj->locTab[i]->type == XML_DOCUMENT_NODE) ||
	    (obj->locTab[i]->type == XML_HTML_DOCUMENT_NODE))
	    fprintf(output, " /");
	/******* TODO 
	else if (obj->locTab[i]->name == NULL)
	    fprintf(output, " noname!");
	else fprintf(output, " %s", obj->locTab[i]->name);
	 ********/
    }
    fprintf(output, "\n");
}
#endif


/**
 * xmlXPtrNewLocationSetNodes:
 * @start:  the start NodePtr value
 * @end:  the end NodePtr value or NULL
 *
 * Create a new xmlXPathObjectPtr of type LocationSet and initialize
 * it with the single range made of the two nodes @start and @end
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewLocationSetNodes(xmlNodePtr start, xmlNodePtr end) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewLocationSetNodes: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_LOCATIONSET;
    if (end == NULL)
	ret->user = xmlXPtrLocationSetCreate(xmlXPtrNewCollapsedRange(start));
    else
	ret->user = xmlXPtrLocationSetCreate(xmlXPtrNewRangeNodes(start,end));
    return(ret);
}

/**
 * xmlXPtrNewLocationSetNodeSet:
 * @set:  a node set
 *
 * Create a new xmlXPathObjectPtr of type LocationSet and initialize
 * it with all the nodes from @set
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrNewLocationSetNodeSet(xmlNodeSetPtr set) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrNewLocationSetNodes: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_LOCATIONSET;
    if (set != NULL) {
	int i;
	xmlLocationSetPtr newset;

	newset = xmlXPtrLocationSetCreate(NULL);
	if (newset == NULL)
	    return(ret);

	for (i = 0;i < set->nodeNr;i++)
	    xmlXPtrLocationSetAdd(newset,
		        xmlXPtrNewCollapsedRange(set->nodeTab[i]));

	ret->user = (void *) newset;
    }
    return(ret);
}

/**
 * xmlXPtrWrapLocationSet:
 * @val:  the LocationSet value
 *
 * Wrap the LocationSet @val in a new xmlXPathObjectPtr
 *
 * Returns the newly created object.
 */
xmlXPathObjectPtr
xmlXPtrWrapLocationSet(xmlLocationSetPtr val) {
    xmlXPathObjectPtr ret;

    ret = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (ret == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrWrapLocationSet: out of memory\n");
	return(NULL);
    }
    memset(ret, 0 , (size_t) sizeof(xmlXPathObject));
    ret->type = XPATH_LOCATIONSET;
    ret->user = (void *) val;
    return(ret);
}

/************************************************************************
 *									*
 *			The parser					*
 *									*
 ************************************************************************/

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

/*
 * xmlXPtrGetChildNo:
 * @ctxt:  the XPointer Parser context
 * @index:  the child number
 *
 * Move the current node of the nodeset on the stack to the
 * given child if found
 */
void
xmlXPtrGetChildNo(xmlXPathParserContextPtr ctxt, int index) {
    xmlNodePtr cur = NULL;
    xmlXPathObjectPtr obj;
    xmlNodeSetPtr oldset;
    int i;

    CHECK_TYPE(XPATH_NODESET);
    obj = valuePop(ctxt);
    oldset = obj->nodesetval;
    if ((index <= 0) || (oldset == NULL) || (oldset->nodeNr != 1)) {
	xmlXPathFreeObject(obj);
	valuePush(ctxt, xmlXPathNewNodeSet(NULL));
	return;
    }
    cur = oldset->nodeTab[0];
    if (cur == NULL) 
	goto done;
    cur = cur->children;
    for (i = 0;i <= index;cur = cur->next) {
	if (cur == NULL) 
	    goto done;
	if ((cur->type == XML_ELEMENT_NODE) ||
	    (cur->type == XML_DOCUMENT_NODE) ||
	    (cur->type == XML_HTML_DOCUMENT_NODE)) {
	    i++;
	    if (i == index)
		break;
	}
    }

done:
    if (cur == NULL) {
	xmlXPathFreeObject(obj);
	valuePush(ctxt, xmlXPathNewNodeSet(NULL));
	return;
    }
    oldset->nodeTab[0] = cur;
    valuePush(ctxt, obj);
}

/**
 * xmlXPtrEvalXPtrPart:
 * @ctxt:  the XPointer Parser context
 * @name:  the preparsed Scheme for the XPtrPart
 * 
 * XPtrPart ::= 'xpointer' '(' XPtrExpr ')'
 *            | Scheme '(' SchemeSpecificExpr ')'
 *
 * Scheme   ::=  NCName - 'xpointer' [VC: Non-XPointer schemes]
 *
 * SchemeSpecificExpr ::= StringWithBalancedParens
 *
 * StringWithBalancedParens ::=  
 *              [^()]* ('(' StringWithBalancedParens ')' [^()]*)*
 *              [VC: Parenthesis escaping]
 *
 * XPtrExpr ::= Expr [VC: Parenthesis escaping]
 *
 * VC: Parenthesis escaping:
 *   The end of an XPointer part is signaled by the right parenthesis ")"
 *   character that is balanced with the left parenthesis "(" character
 *   that began the part. Any unbalanced parenthesis character inside the
 *   expression, even within literals, must be escaped with a circumflex (^)
 *   character preceding it. If the expression contains any literal
 *   occurrences of the circumflex, each must be escaped with an additional
 *   circumflex (that is, ^^). If the unescaped parentheses in the expression
 *   are not balanced, a syntax error results.
 *
 * Parse and evaluate an XPtrPart. Basically it generates the unescaped
 * string and if the scheme is 'xpointer' it will call the XPath interprter.
 * 
 * TODO: there is no new scheme registration mechanism
 */

void
xmlXPtrEvalXPtrPart(xmlXPathParserContextPtr ctxt, xmlChar *name) {
    xmlChar *buffer, *cur;
    int len;
    int level;

    if (name == NULL)
    name = xmlXPathParseName(ctxt);
    if (name == NULL)
	XP_ERROR(XPATH_EXPR_ERROR);

    if (CUR != '(')
	XP_ERROR(XPATH_EXPR_ERROR);
    NEXT;
    level = 1;

    len = xmlStrlen(ctxt->cur);
    len++;
    buffer = (xmlChar *) xmlMalloc(len * sizeof (xmlChar));
    if (buffer == NULL) {
        fprintf(xmlXPathDebug, "xmlXPtrEvalXPtrPart: out of memory\n");
	return;
    }

    cur = buffer;
    while (CUR != '0') {
	if (CUR == ')') {
	    level--;
	    if (level == 0) {
		NEXT;
		break;
	    }
	    *cur++ = CUR;
	} else if (CUR == '(') {
	    level++;
	    *cur++ = CUR;
	} else if (CUR == '^') {
	    NEXT;
	    if ((CUR == ')') || (CUR == '(') || (CUR == '^')) {
		*cur++ = CUR;
	    } else {
		*cur++ = '^';
		*cur++ = CUR;
	    }
	} else {
	    *cur++ = CUR;
	}
	NEXT;
    }
    *cur = 0;

    if ((level != 0) && (CUR == 0)) {
	xmlFree(buffer);
	XP_ERROR(XPTR_SYNTAX_ERROR);
    }

    if (xmlStrEqual(name, (xmlChar *) "xpointer")) {
	const xmlChar *left = CUR_PTR;
	xmlXPathObjectPtr root = NULL;

	CUR_PTR = buffer;
	if (buffer[0] == '/') {
	    xmlXPathRoot(ctxt);
	    root = ctxt->value;
	}
	xmlXPathEvalExpr(ctxt);
	CUR_PTR=left;
    } else {
        fprintf(xmlXPathDebug, "unsupported scheme '%s'\n", name);
    }
    xmlFree(buffer);
    xmlFree(name);
}

/**
 * xmlXPtrEvalFullXPtr:
 * @ctxt:  the XPointer Parser context
 * @name:  the preparsed Scheme for the first XPtrPart
 *
 * FullXPtr ::= XPtrPart (S? XPtrPart)*
 *
 * As the specs says:
 * -----------
 * When multiple XPtrParts are provided, they must be evaluated in
 * left-to-right order. If evaluation of one part fails, the nexti
 * is evaluated. The following conditions cause XPointer part failure:
 *
 * - An unknown scheme
 * - A scheme that does not locate any sub-resource present in the resource
 * - A scheme that is not applicable to the media type of the resource
 *
 * The XPointer application must consume a failed XPointer part and
 * attempt to evaluate the next one, if any. The result of the first
 * XPointer part whose evaluation succeeds is taken to be the fragment
 * located by the XPointer as a whole. If all the parts fail, the result
 * for the XPointer as a whole is a sub-resource error.
 * -----------
 *
 * Parse and evaluate a Full XPtr i.e. possibly a cascade of XPath based
 * expressions or other shemes.
 */
void
xmlXPtrEvalFullXPtr(xmlXPathParserContextPtr ctxt, xmlChar *name) {
    if (name == NULL)
    name = xmlXPathParseName(ctxt);
    if (name == NULL)
	XP_ERROR(XPATH_EXPR_ERROR);
    while (name != NULL) {
	xmlXPtrEvalXPtrPart(ctxt, name);

	/* in case of syntax error, break here */
	if (ctxt->error != XPATH_EXPRESSION_OK)
	    return;

	/*
	 * If the returned value is a non-empty nodeset
	 * or location set, return here.
	 */
	if (ctxt->value != NULL) {
	    xmlXPathObjectPtr obj = ctxt->value;

	    switch (obj->type) {
		case XPATH_LOCATIONSET: {
		    xmlLocationSetPtr loc = ctxt->value->user;
		    if ((loc != NULL) && (loc->locNr > 0))
			return;
		    break;
		}
		case XPATH_NODESET: {
		    xmlNodeSetPtr loc = ctxt->value->nodesetval;
		    if ((loc != NULL) && (loc->nodeNr > 0))
			return;
		    break;
		}
		default:
		    break;
	    }

	    /*
	     * Evaluating to improper values is equivalent to
	     * a sub-resource error, clean-up the stack
	     */
	    do {
		obj = valuePop(ctxt);
		if (obj != NULL) {
		    xmlXPathFreeObject(obj);
		}
	    } while (obj != NULL);
	}

	/*
	 * Is there another XPoointer part.
	 */
	SKIP_BLANKS;
	name = xmlXPathParseName(ctxt);
    }
}

/**
 * xmlXPtrEvalChildSeq:
 * @ctxt:  the XPointer Parser context
 * @name:  a possible ID name of the child sequence
 *
 *  ChildSeq ::= '/1' ('/' [0-9]*)*
 *             | Name ('/' [0-9]*)+
 *
 * Parse and evaluate a Child Sequence. This routine also handle the
 * case of a Bare Name used to get a document ID.
 */
void
xmlXPtrEvalChildSeq(xmlXPathParserContextPtr ctxt, xmlChar *name) {
    /*
     * XPointer don't allow by syntax to adress in mutirooted trees
     * this might prove useful in some cases, warn about it.
     */
    if ((name == NULL) && (CUR == '/') && (NXT(1) != '1')) {
	fprintf(xmlXPathDebug, "warning: ChildSeq not starting by /1\n");
    }

    if (name != NULL) {
	valuePush(ctxt, xmlXPathNewString(name));
	xmlFree(name);
	xmlXPathIdFunction(ctxt, 1);
	CHECK_ERROR;
    }

    while (CUR == '/') {
	int child = 0;
	NEXT;
        
	while ((CUR >= '0') && (CUR <= '9')) {
	    child = child * 10 + (CUR - '0');
	    NEXT;
	}
	xmlXPtrGetChildNo(ctxt, child);
    }
}


/**
 * xmlXPtrEvalXPointer:
 * @ctxt:  the XPointer Parser context
 *
 *  XPointer ::= Name
 *             | ChildSeq
 *             | FullXPtr
 *
 * Parse and evaluate an XPointer
 */
void
xmlXPtrEvalXPointer(xmlXPathParserContextPtr ctxt) {
    SKIP_BLANKS;
    if (CUR == '/') {
	xmlXPathRoot(ctxt);
        xmlXPtrEvalChildSeq(ctxt, NULL);
    } else {
	xmlChar *name;

	name = xmlXPathParseName(ctxt);
	if (name == NULL)
	    XP_ERROR(XPATH_EXPR_ERROR);
	if (CUR == '(') {
	    xmlXPtrEvalFullXPtr(ctxt, name);
	    /* Short evaluation */
	    return;
	} else {
	    /* this handle both Bare Names and Child Sequences */
	    xmlXPtrEvalChildSeq(ctxt, name);
	}
    }
    SKIP_BLANKS;
    if (CUR != 0)
	XP_ERROR(XPATH_EXPR_ERROR);
}


/************************************************************************
 *									*
 *			General routines				*
 *									*
 ************************************************************************/

/**
 * xmlXPtrNewContext:
 * @doc:  the XML document
 * @here:  the node that directly contains the XPointer being evaluated or NULL
 * @origin:  the element from which a user or program initiated traversal of
 *           the link, or NULL.
 *
 * Create a new XPointer context
 *
 * Returns the xmlXPathContext just allocated.
 */
xmlXPathContextPtr
xmlXPtrNewContext(xmlDocPtr doc, xmlNodePtr here, xmlNodePtr origin) {
    xmlXPathContextPtr ret;

    ret = xmlXPathNewContext(doc);
    if (ret == NULL)
	return(ret);
    ret->xptr = 1;
    ret->here = here;
    ret->origin = origin;

    return(ret);
}

/**
 * xmlXPtrEval:
 * @str:  the XPointer expression
 * @ctx:  the XPointer context
 *
 * Evaluate the XPath Location Path in the given context.
 *
 * Returns the xmlXPathObjectPtr resulting from the eveluation or NULL.
 *         the caller has to free the object.
 */
xmlXPathObjectPtr
xmlXPtrEval(const xmlChar *str, xmlXPathContextPtr ctx) {
    xmlXPathParserContextPtr ctxt;
    xmlXPathObjectPtr res = NULL, tmp;
    xmlXPathObjectPtr init = NULL;
    int stack = 0;

    xmlXPathInit();

    if ((ctx == NULL) || (str == NULL))
	return(NULL);

    if (xmlXPathDebug == NULL)
        xmlXPathDebug = stderr;
    ctxt = xmlXPathNewParserContext(str, ctx);
    if (ctx->node != NULL) {
	init = xmlXPathNewNodeSet(ctx->node);
	valuePush(ctxt, init);
    }
    xmlXPtrEvalXPointer(ctxt);

    if ((ctxt->value != NULL) &&
	(ctxt->value->type != XPATH_NODESET) &&
	(ctxt->value->type != XPATH_LOCATIONSET)) {
	fprintf(xmlXPathDebug,
		"xmlXPtrEval: evaluation failed to return a node set\n");
    } else {
	res = valuePop(ctxt);
    }

    do {
        tmp = valuePop(ctxt);
	if (tmp != NULL) {
	    xmlXPathFreeObject(tmp);
	    if (tmp != init)
		stack++;    
        }
    } while (tmp != NULL);
    if (stack != 0) {
	fprintf(xmlXPathDebug, "xmlXPtrEval: %d object left on the stack\n",
	        stack);
    }
    if (ctxt->error != XPATH_EXPRESSION_OK) {
	xmlXPathFreeObject(res);
	res = NULL;
    }
        
    xmlXPathFreeParserContext(ctxt);
    return(res);
}


/************************************************************************
 *									*
 *			XPointer functions				*
 *									*
 ************************************************************************/

/**
 * xmlXPtrNbLocChildren:
 * @node:  an xmlNodePtr
 *
 * Count the number of location children of @node or the lenght of the
 * string value in case of text/PI/Comments nodes
 *
 * Returns the number of location children
 */
int
xmlXPtrNbLocChildren(xmlNodePtr node) {
    int ret = 0;
    if (node == NULL)
	return(-1);
    switch (node->type) {
        case XML_HTML_DOCUMENT_NODE:
        case XML_DOCUMENT_NODE:
        case XML_ELEMENT_NODE:
	    node = node->children;
	    while (node != NULL) {
		if (node->type == XML_ELEMENT_NODE)
		    ret++;
		node = node->next;
	    }
	    break;
        case XML_ATTRIBUTE_NODE:
	    return(-1);

        case XML_PI_NODE:
        case XML_COMMENT_NODE:
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_ENTITY_REF_NODE:
#ifndef XML_USE_BUFFER_CONTENT
	    ret = xmlStrlen(node->content);
#else
	    ret = xmlBufferLength(node->content);
#endif
	    break;
	default:
	    return(-1);
    }
    return(ret);
}

/**
 * xmlXPtrHere:
 * @ctxt:  the XPointer Parser context
 *
 * Function implementing here() operation 
 * as described in 5.4.3
 */
void
xmlXPtrHere(xmlXPathParserContextPtr ctxt, int nargs) {
    if (ctxt->context->here == NULL)
	XP_ERROR(XPTR_SYNTAX_ERROR);
    
    valuePush(ctxt, xmlXPtrNewLocationSetNodes(ctxt->context->here, NULL));
}

/**
 * xmlXPtrOrigin:
 * @ctxt:  the XPointer Parser context
 *
 * Function implementing origin() operation 
 * as described in 5.4.3
 */
void
xmlXPtrOrigin(xmlXPathParserContextPtr ctxt, int nargs) {
    if (ctxt->context->origin == NULL)
	XP_ERROR(XPTR_SYNTAX_ERROR);
    
    valuePush(ctxt, xmlXPtrNewLocationSetNodes(ctxt->context->origin, NULL));
}

/**
 * xmlXPtrStartPoint:
 * @ctxt:  the XPointer Parser context
 *
 * Function implementing start-point() operation 
 * as described in 5.4.3
 * ----------------
 * location-set start-point(location-set)
 *
 * For each location x in the argument location-set, start-point adds a
 * location of type point to the result location-set. That point represents
 * the start point of location x and is determined by the following rules:
 *
 * - If x is of type point, the start point is x.
 * - If x is of type range, the start point is the start point of x.
 * - If x is of type root, element, text, comment, or processing instruction,
 * - the container node of the start point is x and the index is 0.
 * - If x is of type attribute or namespace, the function must signal a
 *   syntax error.
 * ----------------
 *
 */
void
xmlXPtrStartPoint(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr tmp, obj, point;
    xmlLocationSetPtr newset = NULL;
    xmlLocationSetPtr oldset = NULL;

    CHECK_ARITY(1);
    if ((ctxt->value == NULL) ||
	((ctxt->value->type != XPATH_LOCATIONSET) &&
	 (ctxt->value->type != XPATH_NODESET)))
        XP_ERROR(XPATH_INVALID_TYPE)

    obj = valuePop(ctxt);
    if (obj->type == XPATH_NODESET) {
	/*
	 * First convert to a location set
	 */
	tmp = xmlXPtrNewLocationSetNodeSet(obj->nodesetval);
	xmlXPathFreeObject(obj);
	obj = tmp;
    }

    newset = xmlXPtrLocationSetCreate(NULL);
    oldset = (xmlLocationSetPtr) obj->user;
    if (oldset != NULL) {
	int i;

	for (i = 0; i < oldset->locNr; i++) {
	    tmp = oldset->locTab[i];
	    if (tmp == NULL)
		continue;
	    point = NULL;
	    switch (tmp->type) {
		case XPATH_POINT:
		    point = xmlXPtrNewPoint(tmp->user, tmp->index);
		    break;
		case XPATH_RANGE: {
		    xmlNodePtr node = tmp->user;
		    if (node != NULL) {
			if (node->type == XML_ATTRIBUTE_NODE) {
			    /* TODO: Namespace Nodes ??? */
			    xmlXPathFreeObject(obj);
			    xmlXPtrFreeLocationSet(newset);
			    XP_ERROR(XPTR_SYNTAX_ERROR);
			}
			point = xmlXPtrNewPoint(node, tmp->index);
		    }
		    if (tmp->user2 == NULL) {
			point = xmlXPtrNewPoint(node, 0);
		    } else
			point = xmlXPtrNewPoint(node, tmp->index);
		    break;
	        }
		default:
		    /*** Should we raise an error ?
		    xmlXPathFreeObject(obj);
		    xmlXPathFreeObject(newset);
		    XP_ERROR(XPATH_INVALID_TYPE)
		    ***/
		    break;
	    }
            if (point != NULL)
		xmlXPtrLocationSetAdd(newset, point);
	}
    }
    xmlXPathFreeObject(obj);
}

/**
 * xmlXPtrEndPoint:
 * @ctxt:  the XPointer Parser context
 *
 * Function implementing end-point() operation 
 * as described in 5.4.3
 * ----------------------------
 * location-set end-point(location-set)
 *
 * For each location x in the argument location-set, end-point adds a
 * location of type point to the result location-set. That point representsi
 * the end point of location x and is determined by the following rules:
 *
 * - If x is of type point, the resulting point is x.
 * - If x is of type range, the resulting point is the end point of x.
 * - If x is of type root or element, the container node of the resulting
 *   point is x and the index is the number of location children of x.
 * - If x is of type text, comment, or processing instruction, the container
 *   node of the resulting point is x and the index is the length of thei
 *   string-value of x.
 * - If x is of type attribute or namespace, the function must signal a
 *   syntax error.
 * ----------------------------
 */
void
xmlXPtrEndPoint(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr tmp, obj, point;
    xmlLocationSetPtr newset = NULL;
    xmlLocationSetPtr oldset = NULL;

    CHECK_ARITY(1);
    if ((ctxt->value == NULL) ||
	((ctxt->value->type != XPATH_LOCATIONSET) &&
	 (ctxt->value->type != XPATH_NODESET)))
        XP_ERROR(XPATH_INVALID_TYPE)

    obj = valuePop(ctxt);
    if (obj->type == XPATH_NODESET) {
	/*
	 * First convert to a location set
	 */
	tmp = xmlXPtrNewLocationSetNodeSet(obj->nodesetval);
	xmlXPathFreeObject(obj);
	obj = tmp;
    }

    newset = xmlXPtrLocationSetCreate(NULL);
    oldset = (xmlLocationSetPtr) obj->user;
    if (oldset != NULL) {
	int i;

	for (i = 0; i < oldset->locNr; i++) {
	    tmp = oldset->locTab[i];
	    if (tmp == NULL)
		continue;
	    point = NULL;
	    switch (tmp->type) {
		case XPATH_POINT:
		    point = xmlXPtrNewPoint(tmp->user, tmp->index);
		    break;
		case XPATH_RANGE: {
		    xmlNodePtr node = tmp->user;
		    if (node != NULL) {
			if (node->type == XML_ATTRIBUTE_NODE) {
			    /* TODO: Namespace Nodes ??? */
			    xmlXPathFreeObject(obj);
			    xmlXPtrFreeLocationSet(newset);
			    XP_ERROR(XPTR_SYNTAX_ERROR);
			}
			point = xmlXPtrNewPoint(node, tmp->index);
		    }
		    if (tmp->user2 == NULL) {
			point = xmlXPtrNewPoint(node,
				       xmlXPtrNbLocChildren(node));
		    } else
			point = xmlXPtrNewPoint(node, tmp->index);
		    break;
	        }
		default:
		    /*** Should we raise an error ?
		    xmlXPathFreeObject(obj);
		    xmlXPathFreeObject(newset);
		    XP_ERROR(XPATH_INVALID_TYPE)
		    ***/
		    break;
	    }
            if (point != NULL)
		xmlXPtrLocationSetAdd(newset, point);
	}
    }
    xmlXPathFreeObject(obj);
}

/**
 * xmlXPtrCoveringRange:
 * @ctxt:  the XPointer Parser context
 *
 * Function implementing the range() operation of computing a covering
 * range as described in 5.3.3 Covering Ranges for All Location Types.
 */
void
xmlXPtrRange(xmlXPathParserContextPtr ctxt, int nargs) {
    CHECK_ARITY(1);
    TODO
}

/**
 * xmlXPtrRangeToFunction:
 * @ctxt:  the XPointer Parser context
 *
 * Implement the range-to() XPointer function
 */
void
xmlXPtrRangeToFunction(xmlXPathParserContextPtr ctxt, int nargs) {
    xmlXPathObjectPtr range;
    const xmlChar *cur;
    xmlXPathObjectPtr res, obj;
    xmlXPathObjectPtr tmp;
    xmlLocationSetPtr newset = NULL;
    xmlNodeSetPtr oldset;
    int i;

    CHECK_ARITY(1);
    /*
     * Save the expression pointer since we will have to evaluate
     * it multiple times. Initialize the new set.
     */
    CHECK_TYPE(XPATH_NODESET);
    obj = valuePop(ctxt);
    oldset = obj->nodesetval;
    ctxt->context->node = NULL;

    cur = ctxt->cur;
    newset = xmlXPtrLocationSetCreate(NULL);
    
    for (i = 0; i < oldset->nodeNr; i++) {
	ctxt->cur = cur;

	/*
	 * Run the evaluation with a node list made of a single item
	 * in the nodeset.
	 */
	ctxt->context->node = oldset->nodeTab[i];
	tmp = xmlXPathNewNodeSet(ctxt->context->node);
	valuePush(ctxt, tmp);

	xmlXPathEvalExpr(ctxt);
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

    /*
     * The result is used as the new evaluation set.
     */
    xmlXPathFreeObject(obj);
    ctxt->context->node = NULL;
    ctxt->context->contextSize = -1;
    ctxt->context->proximityPosition = -1;
    valuePush(ctxt, xmlXPtrWrapLocationSet(newset));
}

#else
#endif

