/**
 * uri.c: interfaces of the Catalog handling system
 *
 * Reference:  SGML Open Technical Resolution TR9401:1997.
 *             http://www.jclark.com/sp/catalog.htm
 *
 *             XML Catalogs Working Draft 12 Jun 2001
 *             http://www.oasis-open.org/committees/entity/spec-2001-06-12.html
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#ifndef __XML_CATALOG_H__
#define __XML_CATALOG_H__

#include <stdio.h>

#if defined(WIN32) && defined(_MSC_VER)
#include <libxml/xmlwin32version.h>
#else
#include <libxml/xmlversion.h>
#endif
#ifdef LIBXML_CATALOG_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

/**
 * XML_CATALOGS_NAMESPACE:
 *
 * The namespace for the XML Catalogs elements
 */
#define XML_CATALOGS_NAMESPACE		\
    (const xmlChar *) "urn:oasis:names:tc:entity:xmlns:xml:catalog"

int		xmlLoadCatalog		(const char *filename);
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
