/*
 * xpath.c: internal interfaces for XML Path Language implementation
 *          used to build new modules on top of XPath
 *
 * See COPYRIGHT for the status of this software
 *
 * Author: Daniel.Veillard@w3.org
 */

#ifndef __XML_XPATH_INTERNALS_H__
#define __XML_XPATH_INTERNALS_H__

#include <libxml/xpath.h>

#ifdef __cplusplus
extern "C" {
#endif

/************************************************************************
 *									*
 *			Helpers						*
 *									*
 ************************************************************************/

#define CHECK_ERROR							\
    if (ctxt->error != XPATH_EXPRESSION_OK) return

#define CHECK_ERROR0							\
    if (ctxt->error != XPATH_EXPRESSION_OK) return(0)

#define XP_ERROR(X)							\
    { xmlXPatherror(ctxt, __FILE__, __LINE__, X);			\
      ctxt->error = (X); return; }

#define XP_ERROR0(X)							\
    { xmlXPatherror(ctxt, __FILE__, __LINE__, X);			\
      ctxt->error = (X); return(0); }

#define CHECK_TYPE(typeval)						\
    if ((ctxt->value == NULL) || (ctxt->value->type != typeval))	\
        XP_ERROR(XPATH_INVALID_TYPE)

#define CHECK_ARITY(x)							\
    if (nargs != (x))							\
        XP_ERROR(XPATH_INVALID_ARITY);

#define CAST_TO_STRING							\
    if ((ctxt->value != NULL) && (ctxt->value->type != XPATH_STRING))	\
        xmlXPathStringFunction(ctxt, 1);

#define CAST_TO_NUMBER							\
    if ((ctxt->value != NULL) && (ctxt->value->type != XPATH_NUMBER))	\
        xmlXPathNumberFunction(ctxt, 1);

#define CAST_TO_BOOLEAN							\
    if ((ctxt->value != NULL) && (ctxt->value->type != XPATH_BOOLEAN))	\
        xmlXPathBooleanFunction(ctxt, 1);

void		xmlXPatherror	(xmlXPathParserContextPtr ctxt,
				 const char *file,
				 int line,
				 int no);

void		xmlXPathDebugDumpObject	(FILE *output,
					 xmlXPathObjectPtr cur,
					 int depth);

/**
 * Extending a context
 */
int		   xmlXPathRegisterFunc		(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 xmlXPathFunction f);
int		   xmlXPathRegisterFuncNS	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri,
						 xmlXPathFunction f);
int		   xmlXPathRegisterVariable	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 xmlXPathObjectPtr value);
int		   xmlXPathRegisterVariableNS	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri,
						 xmlXPathObjectPtr value);
xmlXPathFunction   xmlXPathFunctionLookup	(xmlXPathContextPtr ctxt,
						 const xmlChar *name);
xmlXPathFunction   xmlXPathFunctionLookupNS	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri);
void		   xmlXPathRegisteredFuncsCleanup(xmlXPathContextPtr ctxt);
xmlXPathObjectPtr  xmlXPathVariableLookup	(xmlXPathContextPtr ctxt,
						 const xmlChar *name);
xmlXPathObjectPtr  xmlXPathVariableLookupNS	(xmlXPathContextPtr ctxt,
						 const xmlChar *name,
						 const xmlChar *ns_uri);
void		   xmlXPathRegisteredVariablesCleanup(xmlXPathContextPtr ctxt);

/**
 * Utilities to extend XPath
 */
xmlXPathParserContextPtr
		  xmlXPathNewParserContext	(const xmlChar *str,
			  			 xmlXPathContextPtr ctxt);
void		  xmlXPathFreeParserContext	(xmlXPathParserContextPtr ctxt);

xmlXPathObjectPtr valuePop			(xmlXPathParserContextPtr ctxt);
int		  valuePush			(xmlXPathParserContextPtr ctxt,
					 	xmlXPathObjectPtr value);

xmlXPathObjectPtr xmlXPathNewString		(const xmlChar *val);
xmlXPathObjectPtr xmlXPathNewCString		(const char *val);
xmlXPathObjectPtr xmlXPathNewFloat		(double val);
xmlXPathObjectPtr xmlXPathNewBoolean		(int val);
xmlXPathObjectPtr xmlXPathNewNodeSet		(xmlNodePtr val);
void		  xmlXPathNodeSetAdd		(xmlNodeSetPtr cur,
						 xmlNodePtr val);


void		  xmlXPathIdFunction		(xmlXPathParserContextPtr ctxt,
					 	int nargs);
void		  xmlXPathRoot			(xmlXPathParserContextPtr ctxt);
void		  xmlXPathEvalExpr		(xmlXPathParserContextPtr ctxt);
xmlChar *	  xmlXPathParseName		(xmlXPathParserContextPtr ctxt);

/*
 * Debug
 */
#ifdef LIBXML_DEBUG_ENABLED
double xmlXPathStringEvalNumber(const xmlChar *str);
void xmlXPathDebugDumpObject(FILE *output, xmlXPathObjectPtr cur, int depth);
#endif
/*
 * Existing functions
 */

int xmlXPathEvaluatePredicateResult(xmlXPathParserContextPtr ctxt, 
                                    xmlXPathObjectPtr res);
void xmlXPathInit(void);
void xmlXPathStringFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathRegisterAllFunctions(xmlXPathContextPtr ctxt);
xmlNodeSetPtr xmlXPathNodeSetCreate(xmlNodePtr val);
void xmlXPathNodeSetAdd(xmlNodeSetPtr cur, xmlNodePtr val);
xmlNodeSetPtr xmlXPathNodeSetMerge(xmlNodeSetPtr val1, xmlNodeSetPtr val2);
void xmlXPathNodeSetDel(xmlNodeSetPtr cur, xmlNodePtr val);
void xmlXPathNodeSetRemove(xmlNodeSetPtr cur, int val);
void xmlXPathFreeNodeSet(xmlNodeSetPtr obj);
xmlXPathObjectPtr xmlXPathNewNodeSet(xmlNodePtr val);
xmlXPathObjectPtr xmlXPathNewNodeSetList(xmlNodeSetPtr val);
xmlXPathObjectPtr xmlXPathWrapNodeSet(xmlNodeSetPtr val);
void xmlXPathFreeNodeSetList(xmlXPathObjectPtr obj);


xmlXPathObjectPtr xmlXPathNewFloat(double val);
xmlXPathObjectPtr xmlXPathNewBoolean(int val);
xmlXPathObjectPtr xmlXPathNewString(const xmlChar *val);
xmlXPathObjectPtr xmlXPathNewCString(const char *val);
void xmlXPathFreeObject(xmlXPathObjectPtr obj);
xmlXPathContextPtr xmlXPathNewContext(xmlDocPtr doc);
void xmlXPathFreeContext(xmlXPathContextPtr ctxt);

int xmlXPathEqualValues(xmlXPathParserContextPtr ctxt);
int xmlXPathCompareValues(xmlXPathParserContextPtr ctxt, int inf, int strict);
void xmlXPathValueFlipSign(xmlXPathParserContextPtr ctxt);
void xmlXPathAddValues(xmlXPathParserContextPtr ctxt);
void xmlXPathSubValues(xmlXPathParserContextPtr ctxt);
void xmlXPathMultValues(xmlXPathParserContextPtr ctxt);
void xmlXPathDivValues(xmlXPathParserContextPtr ctxt);
void xmlXPathModValues(xmlXPathParserContextPtr ctxt);

/*
 * The official core of XPath functions
 */
void xmlXPathRoot(xmlXPathParserContextPtr ctxt);
void xmlXPathLastFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathPositionFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathCountFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathIdFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathLocalNameFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathNamespaceURIFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathStringFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathStringLengthFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathConcatFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathContainsFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathStartsWithFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathSubstringFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathSubstringBeforeFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathSubstringAfterFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathNormalizeFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathTranslateFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathNotFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathTrueFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathFalseFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathLangFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathNumberFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathSumFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathFloorFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathCeilingFunction(xmlXPathParserContextPtr ctxt, int nargs);
void xmlXPathRoundFunction(xmlXPathParserContextPtr ctxt, int nargs);
#ifdef __cplusplus
}
#endif
#endif /* ! __XML_XPATH_INTERNALS_H__ */
