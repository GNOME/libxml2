/*
 * debugXML.h : Interfaces to a set of routines used for debugging the tree
 *              produced by the XML parser.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#ifndef __DEBUG_XML__
#define __DEBUG_XML__
#include <stdio.h>
#include <libxml/tree.h>

#ifdef LIBXML_DEBUG_ENABLED

#include <libxml/xpath.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The standard Dump routines
 */
void	xmlDebugDumpString	(FILE *output,
				 const xmlChar *str);
void	xmlDebugDumpAttr	(FILE *output,
				 xmlAttrPtr attr,
				 int depth);
void	xmlDebugDumpAttrList	(FILE *output,
				 xmlAttrPtr attr,
				 int depth);
void	xmlDebugDumpOneNode	(FILE *output,
				 xmlNodePtr node,
				 int depth);
void	xmlDebugDumpNode	(FILE *output,
				 xmlNodePtr node,
				 int depth);
void	xmlDebugDumpNodeList	(FILE *output,
				 xmlNodePtr node,
				 int depth);
void	xmlDebugDumpDocumentHead(FILE *output,
				 xmlDocPtr doc);
void	xmlDebugDumpDocument	(FILE *output,
				 xmlDocPtr doc);
void	xmlDebugDumpEntities	(FILE *output,
				 xmlDocPtr doc);
void	xmlLsOneNode		(FILE *output,
				 xmlNodePtr node);

/****************************************************************
 *								*
 *	 The XML shell related structures and functions		*
 *								*
 ****************************************************************/

/**
 * xmlShellReadlineFunc:
 * @prompt:  a string prompt
 *
 * This is a generic signature for the XML shell input function
 *
 * Returns a string which will be freed by the Shell
 */
typedef char * (* xmlShellReadlineFunc)(char *prompt);

/*
 * The shell context itself
 * TODO: add the defined function tables.
 */
typedef struct _xmlShellCtxt xmlShellCtxt;
typedef xmlShellCtxt *xmlShellCtxtPtr;
struct _xmlShellCtxt {
    char *filename;
    xmlDocPtr doc;
    xmlNodePtr node;
    xmlXPathContextPtr pctxt;
    int loaded;
    FILE *output;
    xmlShellReadlineFunc input;
};

/**
 * xmlShellCmd:
 * @ctxt:  a shell context
 * @arg:  a string argument
 * @node:  a first node
 * @node2:  a second node
 *
 * This is a generic signature for the XML shell functions
 *
 * Returns an int, negative returns indicating errors
 */
typedef int (* xmlShellCmd) (xmlShellCtxtPtr ctxt,
                             char *arg,
			     xmlNodePtr node,
			     xmlNodePtr node2);

/*
 * The Shell interface.
 */
void	xmlShell	(xmlDocPtr doc,
			 char *filename,
			 xmlShellReadlineFunc input,
			 FILE *output);
			 
#ifdef __cplusplus
}
#endif

#endif /* LIBXML_DEBUG_ENABLED */
#endif /* __DEBUG_XML__ */
