/*
 * Summary: regular expressions handling
 * Description: basic API for libxml regular expressions handling used
 *              for XML Schemas and validation.
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Daniel Veillard
 */

#ifndef __XML_REGEXP_H__
#define __XML_REGEXP_H__

#include <libxml/xmlversion.h>

#ifdef LIBXML_REGEXP_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xmlRegexpPtr:
 *
 * A libxml regular expression, they can actually be far more complex
 * thank the POSIX regex expressions.
 */
typedef struct _xmlRegexp xmlRegexp;
typedef xmlRegexp *xmlRegexpPtr;

/**
 * xmlRegExecCtxtPtr:
 *
 * A libxml progressive regular expression evaluation context
 */
typedef struct _xmlRegExecCtxt xmlRegExecCtxt;
typedef xmlRegExecCtxt *xmlRegExecCtxtPtr;

#ifdef __cplusplus
}
#endif 
#include <libxml/tree.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * The POSIX like API
 */
XMLPUBFUN xmlRegexpPtr XMLCALL
		    xmlRegexpCompile	(const xmlChar *regexp);
XMLPUBFUN void XMLCALL			 xmlRegFreeRegexp(xmlRegexpPtr regexp);
XMLPUBFUN int XMLCALL			
		    xmlRegexpExec	(xmlRegexpPtr comp,
					 const xmlChar *value);
XMLPUBFUN void XMLCALL			
    		    xmlRegexpPrint	(FILE *output,
					 xmlRegexpPtr regexp);
XMLPUBFUN int XMLCALL			
		    xmlRegexpIsDeterminist(xmlRegexpPtr comp);

/*
 * Callback function when doing a transition in the automata
 */
typedef void (*xmlRegExecCallbacks) (xmlRegExecCtxtPtr exec,
	                             const xmlChar *token,
				     void *transdata,
				     void *inputdata);

/*
 * The progressive API
 */
XMLPUBFUN xmlRegExecCtxtPtr XMLCALL	
    		    xmlRegNewExecCtxt	(xmlRegexpPtr comp,
					 xmlRegExecCallbacks callback,
					 void *data);
XMLPUBFUN void XMLCALL			
		    xmlRegFreeExecCtxt	(xmlRegExecCtxtPtr exec);
XMLPUBFUN int XMLCALL			
    		    xmlRegExecPushString(xmlRegExecCtxtPtr exec,
					 const xmlChar *value,
					 void *data);
XMLPUBFUN int XMLCALL			
		    xmlRegExecPushString2(xmlRegExecCtxtPtr exec,
					 const xmlChar *value,
					 const xmlChar *value2,
					 void *data);

XMLPUBFUN int XMLCALL
		    xmlRegExecNextValues(xmlRegExecCtxtPtr exec,
		    			 int *nbval,
		    			 int *nbneg,
					 xmlChar **values,
					 int *terminal);
XMLPUBFUN int XMLCALL
		    xmlRegExecErrInfo	(xmlRegExecCtxtPtr exec,
		    			 const xmlChar **string,
					 int *nbval,
		    			 int *nbneg,
					 xmlChar **values,
					 int *terminal);
#ifdef LIBXML_EXPR_ENABLED
/*
 * Formal regular expression handling
 * Its goal is to do some formal work on content models
 */

/* expressions are used within a context */
typedef struct _xmlExpCtxt xmlExpCtxt;
typedef xmlExpCtxt *xmlExpCtxtPtr;

XMLPUBFUN void XMLCALL
			xmlExpFreeCtxt	(xmlExpCtxtPtr ctxt);
XMLPUBFUN xmlExpCtxtPtr XMLCALL
			xmlExpNewCtxt	(int maxNodes,
					 xmlDictPtr dict);

/* Expressions are trees but the tree is opaque */
typedef struct _xmlExpNode xmlExpNode;
typedef xmlExpNode *xmlExpNodePtr;

/*
 * 2 core expressions shared by all for the empty language set 
 * and for the set with just the empty token
 */
XMLPUBVAR xmlExpNodePtr forbiddenExp;
XMLPUBVAR xmlExpNodePtr emptyExp;

/*
 * Expressions are reference counted internally
 */
XMLPUBFUN void XMLCALL
			xmlExpFree	(xmlExpCtxtPtr ctxt,
					 xmlExpNodePtr exp);
XMLPUBFUN void XMLCALL
			xmlExpRef	(xmlExpNodePtr exp);
XMLPUBFUN int XMLCALL
			xmlExpIsNillable(xmlExpNodePtr exp);
XMLPUBFUN int XMLCALL
			xmlExpGetLanguage(xmlExpCtxtPtr ctxt,
					 xmlExpNodePtr exp,
					 const xmlChar**list,
					 int len);
XMLPUBFUN int XMLCALL
			xmlExpGetStart	(xmlExpCtxtPtr ctxt,
					 xmlExpNodePtr exp,
					 const xmlChar**list,
					 int len);
XMLPUBFUN xmlExpNodePtr XMLCALL
			xmlExpStringDerive(xmlExpCtxtPtr ctxt,
					 xmlExpNodePtr exp,
					 const xmlChar *str,
					 int len);
XMLPUBFUN int XMLCALL
			xmlExpSubsume	(xmlExpCtxtPtr ctxt,
					 xmlExpNodePtr exp,
					 xmlExpNodePtr sub);
#endif /* LIBXML_EXPR_ENABLED */
#ifdef __cplusplus
}
#endif 

#endif /* LIBXML_REGEXP_ENABLED */

#endif /*__XML_REGEXP_H__ */
