/**
 * uri.c: interfaces of the Catalog handling system
 *
 * Reference:  SGML Open Technical Resolution TR9401:1997.
 *             http://www.jclark.com/sp/catalog.htm
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_CATALOG_H__
#define __XML_CATALOG_H__

#include <stdio.h>

#include <libxml/xmlversion.h>
#ifdef LIBXML_CATALOG_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

int		xmlLoadCatalog		(const char *URL);
void		xmlLoadCatalogs		(const char *paths);
void		xmlCatalogCleanup	(void);
void		xmlCatalogDump		(FILE *out);
const xmlChar *	xmlCatalogGetSystem	(const xmlChar *sysID);
const xmlChar *	xmlCatalogGetPublic	(const xmlChar *pubID);

#ifdef __cplusplus
}
#endif
#endif /* LIBXML_CATALOG_ENABLED */
#endif /* __XML_CATALOG_H__ */
