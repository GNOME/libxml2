/**
 * @file
 * 
 * @brief internal interfaces for XML Path Language implementation
 * 
 * internal interfaces for XML Path Language implementation
 *              used to build new modules on top of XPath like XPointer and
 *              XSLT
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
 */

#ifndef __XML_XPATH_INTERNALS_H__
#define __XML_XPATH_INTERNALS_H__

#include <stdio.h>
#include <libxml/xmlversion.h>
#include <libxml/xpath.h>

#ifdef LIBXML_XPATH_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Backward compatibility
 */
#define valuePush xmlXPathValuePush
#define valuePop xmlXPathValuePop

/************************************************************************
 *									*
 *			Helpers						*
 *									*
 ************************************************************************/

/*
 * Many of these macros may later turn into functions. They
 * shouldn't be used in \#ifdef's preprocessor instructions.
 */
/**
 * Raises an error.
 *
 * @param ctxt  an XPath parser context
 * @param err  an xmlXPathError code
 */
#define xmlXPathSetError(ctxt, err)					\
    { xmlXPatherror((ctxt), __FILE__, __LINE__, (err));			\
      if ((ctxt) != NULL) (ctxt)->error = (err); }

/**
 * Raises an XPATH_INVALID_ARITY error.
 *
 * @param ctxt  an XPath parser context
 */
#define xmlXPathSetArityError(ctxt)					\
    xmlXPathSetError((ctxt), XPATH_INVALID_ARITY)

/**
 * Raises an XPATH_INVALID_TYPE error.
 *
 * @param ctxt  an XPath parser context
 */
#define xmlXPathSetTypeError(ctxt)					\
    xmlXPathSetError((ctxt), XPATH_INVALID_TYPE)

/**
 * Get the error code of an XPath context.
 *
 * @param ctxt  an XPath parser context
 * @returns the context error.
 */
#define xmlXPathGetError(ctxt)	  ((ctxt)->error)

/**
 * Check if an XPath error was raised.
 *
 * @param ctxt  an XPath parser context
 * @returns true if an error has been raised, false otherwise.
 */
#define xmlXPathCheckError(ctxt)  ((ctxt)->error != XPATH_EXPRESSION_OK)

/**
 * Get the document of an XPath context.
 *
 * @param ctxt  an XPath parser context
 * @returns the context document.
 */
#define xmlXPathGetDocument(ctxt)	((ctxt)->context->doc)

/**
 * Get the context node of an XPath context.
 *
 * @param ctxt  an XPath parser context
 * @returns the context node.
 */
#define xmlXPathGetContextNode(ctxt)	((ctxt)->context->node)

XMLPUBFUN int
		xmlXPathPopBoolean	(xmlXPathParserContextPtr ctxt);
XMLPUBFUN double
		xmlXPathPopNumber	(xmlXPathParserContextPtr ctxt);
XMLPUBFUN xmlChar *
		xmlXPathPopString	(xmlXPathParserContextPtr ctxt);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathPopNodeSet	(xmlXPathParserContextPtr ctxt);
XMLPUBFUN void *
		xmlXPathPopExternal	(xmlXPathParserContextPtr ctxt);

/**
 * Pushes the boolean `val` on the context stack.
 *
 * @param ctxt  an XPath parser context
 * @param val  a boolean
 */
#define xmlXPathReturnBoolean(ctxt, val)				\
    valuePush((ctxt), xmlXPathNewBoolean(val))

/**
 * Pushes true on the context stack.
 *
 * @param ctxt  an XPath parser context
 */
#define xmlXPathReturnTrue(ctxt)   xmlXPathReturnBoolean((ctxt), 1)

/**
 * Pushes false on the context stack.
 *
 * @param ctxt  an XPath parser context
 */
#define xmlXPathReturnFalse(ctxt)  xmlXPathReturnBoolean((ctxt), 0)

/**
 * Pushes the double `val` on the context stack.
 *
 * @param ctxt  an XPath parser context
 * @param val  a double
 */
#define xmlXPathReturnNumber(ctxt, val)					\
    valuePush((ctxt), xmlXPathNewFloat(val))

/**
 * Pushes the string `str` on the context stack.
 *
 * @param ctxt  an XPath parser context
 * @param str  a string
 */
#define xmlXPathReturnString(ctxt, str)					\
    valuePush((ctxt), xmlXPathWrapString(str))

/**
 * Pushes an empty string on the stack.
 *
 * @param ctxt  an XPath parser context
 */
#define xmlXPathReturnEmptyString(ctxt)					\
    valuePush((ctxt), xmlXPathNewCString(""))

/**
 * Pushes the node-set `ns` on the context stack.
 *
 * @param ctxt  an XPath parser context
 * @param ns  a node-set
 */
#define xmlXPathReturnNodeSet(ctxt, ns)					\
    valuePush((ctxt), xmlXPathWrapNodeSet(ns))

/**
 * Pushes an empty node-set on the context stack.
 *
 * @param ctxt  an XPath parser context
 */
#define xmlXPathReturnEmptyNodeSet(ctxt)				\
    valuePush((ctxt), xmlXPathNewNodeSet(NULL))

/**
 * Pushes user data on the context stack.
 *
 * @param ctxt  an XPath parser context
 * @param val  user data
 */
#define xmlXPathReturnExternal(ctxt, val)				\
    valuePush((ctxt), xmlXPathWrapExternal(val))

/**
 * Check if the current value on the XPath stack is a node set or
 * an XSLT value tree.
 *
 * @param ctxt  an XPath parser context
 * @returns true if the current object on the stack is a node-set.
 */
#define xmlXPathStackIsNodeSet(ctxt)					\
    (((ctxt)->value != NULL)						\
     && (((ctxt)->value->type == XPATH_NODESET)				\
         || ((ctxt)->value->type == XPATH_XSLT_TREE)))

/**
 * Checks if the current value on the XPath stack is an external
 * object.
 *
 * @param ctxt  an XPath parser context
 * @returns true if the current object on the stack is an external
 * object.
 */
#define xmlXPathStackIsExternal(ctxt)					\
	((ctxt->value != NULL) && (ctxt->value->type == XPATH_USERS))

/**
 * Empties a node-set.
 *
 * @param ns  a node-set
 */
#define xmlXPathEmptyNodeSet(ns)					\
    { while ((ns)->nodeNr > 0) (ns)->nodeTab[--(ns)->nodeNr] = NULL; }

/**
 * Macro to return from the function if an XPath error was detected.
 */
#define CHECK_ERROR							\
    if (ctxt->error != XPATH_EXPRESSION_OK) return

/**
 * Macro to return 0 from the function if an XPath error was detected.
 */
#define CHECK_ERROR0							\
    if (ctxt->error != XPATH_EXPRESSION_OK) return(0)

/**
 * Macro to raise an XPath error and return.
 *
 * @param X  the error code
 */
#define XP_ERROR(X)							\
    { xmlXPathErr(ctxt, X); return; }

/**
 * Macro to raise an XPath error and return 0.
 *
 * @param X  the error code
 */
#define XP_ERROR0(X)							\
    { xmlXPathErr(ctxt, X); return(0); }

/**
 * Macro to check that the value on top of the XPath stack is of a given
 * type.
 *
 * @param typeval  the XPath type
 */
#define CHECK_TYPE(typeval)						\
    if ((ctxt->value == NULL) || (ctxt->value->type != typeval))	\
        XP_ERROR(XPATH_INVALID_TYPE)

/**
 * Macro to check that the value on top of the XPath stack is of a given
 * type. Return(0) in case of failure
 *
 * @param typeval  the XPath type
 */
#define CHECK_TYPE0(typeval)						\
    if ((ctxt->value == NULL) || (ctxt->value->type != typeval))	\
        XP_ERROR0(XPATH_INVALID_TYPE)

/**
 * Macro to check that the number of args passed to an XPath function matches.
 *
 * @param x  the number of expected args
 */
#define CHECK_ARITY(x)							\
    if (ctxt == NULL) return;						\
    if (nargs != (x))							\
        XP_ERROR(XPATH_INVALID_ARITY);					\
    if (ctxt->valueNr < (x))						\
        XP_ERROR(XPATH_STACK_ERROR);

/**
 * Macro to try to cast the value on the top of the XPath stack to a string.
 */
#define CAST_TO_STRING							\
    if ((ctxt->value != NULL) && (ctxt->value->type != XPATH_STRING))	\
        xmlXPathStringFunction(ctxt, 1);

/**
 * Macro to try to cast the value on the top of the XPath stack to a number.
 */
#define CAST_TO_NUMBER							\
    if ((ctxt->value != NULL) && (ctxt->value->type != XPATH_NUMBER))	\
        xmlXPathNumberFunction(ctxt, 1);

/**
 * Macro to try to cast the value on the top of the XPath stack to a boolean.
 */
#define CAST_TO_BOOLEAN							\
    if ((ctxt->value != NULL) && (ctxt->value->type != XPATH_BOOLEAN))	\
        xmlXPathBooleanFunction(ctxt, 1);

/*
 * Variable Lookup forwarding.
 */

XMLPUBFUN void
	xmlXPathRegisterVariableLookup	(xmlXPathContextPtr ctxt,
					 xmlXPathVariableLookupFunc f,
					 void *data);

/*
 * Function Lookup forwarding.
 */

XMLPUBFUN void
	    xmlXPathRegisterFuncLookup	(xmlXPathContextPtr ctxt,
					 xmlXPathFuncLookupFunc f,
					 void *funcCtxt);

/*
 * Error reporting.
 */
XMLPUBFUN void
		xmlXPatherror	(xmlXPathParserContextPtr ctxt,
				 const char *file,
				 int line,
				 int no);

XMLPUBFUN void
		xmlXPathErr	(xmlXPathParserContextPtr ctxt,
				 int error);

#ifdef LIBXML_DEBUG_ENABLED
XMLPUBFUN void
		xmlXPathDebugDumpObject	(FILE *output,
					 xmlXPathObjectPtr cur,
					 int depth);
XMLPUBFUN void
	    xmlXPathDebugDumpCompExpr(FILE *output,
					 xmlXPathCompExprPtr comp,
					 int depth);
#endif
/**
 * NodeSet handling.
 */
XMLPUBFUN int
		xmlXPathNodeSetContains		(xmlNodeSetPtr cur,
						 xmlNodePtr val);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathDifference		(xmlNodeSetPtr nodes1,
						 xmlNodeSetPtr nodes2);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathIntersection		(xmlNodeSetPtr nodes1,
						 xmlNodeSetPtr nodes2);

XMLPUBFUN xmlNodeSetPtr
		xmlXPathDistinctSorted		(xmlNodeSetPtr nodes);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathDistinct		(xmlNodeSetPtr nodes);

XMLPUBFUN int
		xmlXPathHasSameNodes		(xmlNodeSetPtr nodes1,
						 xmlNodeSetPtr nodes2);

XMLPUBFUN xmlNodeSetPtr
		xmlXPathNodeLeadingSorted	(xmlNodeSetPtr nodes,
						 xmlNodePtr node);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathLeadingSorted		(xmlNodeSetPtr nodes1,
						 xmlNodeSetPtr nodes2);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathNodeLeading		(xmlNodeSetPtr nodes,
						 xmlNodePtr node);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathLeading			(xmlNodeSetPtr nodes1,
						 xmlNodeSetPtr nodes2);

XMLPUBFUN xmlNodeSetPtr
		xmlXPathNodeTrailingSorted	(xmlNodeSetPtr nodes,
						 xmlNodePtr node);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathTrailingSorted		(xmlNodeSetPtr nodes1,
						 xmlNodeSetPtr nodes2);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathNodeTrailing		(xmlNodeSetPtr nodes,
						 xmlNodePtr node);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathTrailing		(xmlNodeSetPtr nodes1,
						 xmlNodeSetPtr nodes2);


/**
 * Extending a context.
 */

XMLPUBFUN int
		xmlXPathRegisterNs		(xmlXPathContextPtr ctxt,
						 const xmlChar *prefix,
						 const xmlChar *ns_uri);
XMLPUBFUN const xmlChar *
		xmlXPathNsLookup		(xmlXPathContextPtr ctxt,
						 const xmlChar *prefix);
XMLPUBFUN void
		xmlXPathRegisteredNsCleanup	(xmlXPathContextPtr ctxt);

XMLPUBFUN int
		xmlXPathRegisterFunc		(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 xmlXPathFunction f);
XMLPUBFUN int
		xmlXPathRegisterFuncNS		(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri,
						 xmlXPathFunction f);
XMLPUBFUN int
		xmlXPathRegisterVariable	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 xmlXPathObjectPtr value);
XMLPUBFUN int
		xmlXPathRegisterVariableNS	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri,
						 xmlXPathObjectPtr value);
XMLPUBFUN xmlXPathFunction
		xmlXPathFunctionLookup		(xmlXPathContextPtr ctxt,
						 const xmlChar *name);
XMLPUBFUN xmlXPathFunction
		xmlXPathFunctionLookupNS	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri);
XMLPUBFUN void
		xmlXPathRegisteredFuncsCleanup	(xmlXPathContextPtr ctxt);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathVariableLookup		(xmlXPathContextPtr ctxt,
						 const xmlChar *name);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathVariableLookupNS	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri);
XMLPUBFUN void
		xmlXPathRegisteredVariablesCleanup(xmlXPathContextPtr ctxt);

/**
 * Utilities to extend XPath.
 */
XMLPUBFUN xmlXPathParserContextPtr
		  xmlXPathNewParserContext	(const xmlChar *str,
						 xmlXPathContextPtr ctxt);
XMLPUBFUN void
		xmlXPathFreeParserContext	(xmlXPathParserContextPtr ctxt);

XMLPUBFUN xmlXPathObjectPtr
		xmlXPathValuePop		(xmlXPathParserContextPtr ctxt);
XMLPUBFUN int
		xmlXPathValuePush		(xmlXPathParserContextPtr ctxt,
						 xmlXPathObjectPtr value);

XMLPUBFUN xmlXPathObjectPtr
		xmlXPathNewString		(const xmlChar *val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathNewCString		(const char *val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathWrapString		(xmlChar *val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathWrapCString		(char * val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathNewFloat		(double val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathNewBoolean		(int val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathNewNodeSet		(xmlNodePtr val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathNewValueTree		(xmlNodePtr val);
XMLPUBFUN int
		xmlXPathNodeSetAdd		(xmlNodeSetPtr cur,
						 xmlNodePtr val);
XMLPUBFUN int
		xmlXPathNodeSetAddUnique	(xmlNodeSetPtr cur,
						 xmlNodePtr val);
XMLPUBFUN int
		xmlXPathNodeSetAddNs		(xmlNodeSetPtr cur,
						 xmlNodePtr node,
						 xmlNsPtr ns);
XMLPUBFUN void
		xmlXPathNodeSetSort		(xmlNodeSetPtr set);

XMLPUBFUN void
		xmlXPathRoot			(xmlXPathParserContextPtr ctxt);
XML_DEPRECATED
XMLPUBFUN void
		xmlXPathEvalExpr		(xmlXPathParserContextPtr ctxt);
XMLPUBFUN xmlChar *
		xmlXPathParseName		(xmlXPathParserContextPtr ctxt);
XMLPUBFUN xmlChar *
		xmlXPathParseNCName		(xmlXPathParserContextPtr ctxt);

/*
 * Existing functions.
 */
XMLPUBFUN double
		xmlXPathStringEvalNumber	(const xmlChar *str);
XMLPUBFUN int
		xmlXPathEvaluatePredicateResult (xmlXPathParserContextPtr ctxt,
						 xmlXPathObjectPtr res);
XMLPUBFUN void
		xmlXPathRegisterAllFunctions	(xmlXPathContextPtr ctxt);
XMLPUBFUN xmlNodeSetPtr
		xmlXPathNodeSetMerge		(xmlNodeSetPtr val1,
						 xmlNodeSetPtr val2);
XMLPUBFUN void
		xmlXPathNodeSetDel		(xmlNodeSetPtr cur,
						 xmlNodePtr val);
XMLPUBFUN void
		xmlXPathNodeSetRemove		(xmlNodeSetPtr cur,
						 int val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathNewNodeSetList		(xmlNodeSetPtr val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathWrapNodeSet		(xmlNodeSetPtr val);
XMLPUBFUN xmlXPathObjectPtr
		xmlXPathWrapExternal		(void *val);

XMLPUBFUN int xmlXPathEqualValues(xmlXPathParserContextPtr ctxt);
XMLPUBFUN int xmlXPathNotEqualValues(xmlXPathParserContextPtr ctxt);
XMLPUBFUN int xmlXPathCompareValues(xmlXPathParserContextPtr ctxt, int inf, int strict);
XMLPUBFUN void xmlXPathValueFlipSign(xmlXPathParserContextPtr ctxt);
XMLPUBFUN void xmlXPathAddValues(xmlXPathParserContextPtr ctxt);
XMLPUBFUN void xmlXPathSubValues(xmlXPathParserContextPtr ctxt);
XMLPUBFUN void xmlXPathMultValues(xmlXPathParserContextPtr ctxt);
XMLPUBFUN void xmlXPathDivValues(xmlXPathParserContextPtr ctxt);
XMLPUBFUN void xmlXPathModValues(xmlXPathParserContextPtr ctxt);

XMLPUBFUN int xmlXPathIsNodeType(const xmlChar *name);

/*
 * Some of the axis navigation routines.
 */
XMLPUBFUN xmlNodePtr xmlXPathNextSelf(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextChild(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextDescendant(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextDescendantOrSelf(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextParent(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextAncestorOrSelf(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextFollowingSibling(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextFollowing(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextNamespace(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextAttribute(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextPreceding(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextAncestor(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
XMLPUBFUN xmlNodePtr xmlXPathNextPrecedingSibling(xmlXPathParserContextPtr ctxt,
			xmlNodePtr cur);
/*
 * The official core of XPath functions.
 */
XMLPUBFUN void xmlXPathLastFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathPositionFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathCountFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathIdFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathLocalNameFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathNamespaceURIFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathStringFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathStringLengthFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathConcatFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathContainsFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathStartsWithFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathSubstringFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathSubstringBeforeFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathSubstringAfterFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathNormalizeFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathTranslateFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathNotFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathTrueFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathFalseFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathLangFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathNumberFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathSumFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathFloorFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathCeilingFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathRoundFunction(xmlXPathParserContextPtr ctxt, int nargs);
XMLPUBFUN void xmlXPathBooleanFunction(xmlXPathParserContextPtr ctxt, int nargs);

/**
 * Really internal functions
 */
XMLPUBFUN void xmlXPathNodeSetFreeNs(xmlNsPtr ns);

#ifdef __cplusplus
}
#endif

#endif /* LIBXML_XPATH_ENABLED */
#endif /* ! __XML_XPATH_INTERNALS_H__ */
