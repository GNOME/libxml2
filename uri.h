/**
 * uri.c: library of generic URI related routines 
 *
 * Reference: RFC 2396
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_URI_H__
#define __XML_URI_H__

#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 */
typedef struct _xmlURI xmlURI;
typedef xmlURI *xmlURIPtr;
struct _xmlURI {
    char *scheme;
    char *opaque;
    char *authority;
    char *server;
    char *user;
    int port;
    char *path;
    char *query;
    char *fragment;
};

/*
 * This function is in tree.h:
 * xmlChar *	xmlNodeGetBase	(xmlDocPtr doc,
 *                               xmlNodePtr cur);
 */
xmlURIPtr	xmlCreateURI		(void);
xmlChar *	xmlBuildURI		(const xmlChar *URI,
	                        	 const xmlChar *base);
xmlURIPtr	xmlParseURI		(const char *URI);
xmlChar *	xmlSaveUri		(xmlURIPtr uri);
void		xmlPrintURI		(FILE *stream,
					 xmlURIPtr uri);
char *		xmlURIUnescapeString	(const char *str,
					 int len,
					 char *target);
int		xmlNormalizeURIPath	(char *path);
void		xmlFreeURI		(xmlURIPtr uri);

#ifdef __cplusplus
}
#endif
#endif /* __XML_URI_H__ */
