/*
 * regexp.h : describes the basic API for libxml regular expressions handling
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __XML_REGEXP_H__
#define __XML_REGEXP_H__

#if defined(WIN32) && defined(_MSC_VER)
#include <libxml/xmlwin32version.h>
#else
#include <libxml/xmlversion.h>
#endif
#ifdef LIBXML_REGEXP_ENABLED

#include <libxml/tree.h>

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

/*
 * The POSIX like API
 */
xmlRegexpPtr		xmlRegexpCompile(const xmlChar *regexp);
void			xmlRegFreeRegexp(xmlRegexpPtr regexp);
int			xmlRegexpExec	(xmlRegexpPtr comp,
					 const xmlChar *value);
void			xmlRegexpPrint	(FILE *output,
					 xmlRegexpPtr regexp);

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
xmlRegExecCtxtPtr	xmlRegNewExecCtxt	(xmlRegexpPtr comp,
						 xmlRegExecCallbacks callback,
						 void *data);
void			xmlRegFreeExecCtxt	(xmlRegExecCtxtPtr exec);
int			xmlRegExecPushString	(xmlRegExecCtxtPtr exec,
						 const xmlChar *value,
						 void *data);

#ifdef __cplusplus
}
#endif 

#endif /* LIBXML_REGEXP_ENABLED */

#endif /*__XML_REGEXP_H__ */
