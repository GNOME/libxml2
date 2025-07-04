/**
 * @file
 *
 * @brief interfaces to the Catalog handling system
 * 
 * the catalog module implements the support for
 * XML Catalogs and SGML catalogs
 *
 * SGML Open Technical Resolution TR9401:1997.
 * http://www.jclark.com/sp/catalog.htm
 *
 * XML Catalogs Working Draft 06 August 2001
 * http://www.oasis-open.org/committees/entity/spec-2001-08-06.html
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
 */

#ifndef __XML_CATALOG_H__
#define __XML_CATALOG_H__

#include <stdio.h>

#include <libxml/xmlversion.h>
#include <libxml/xmlstring.h>
#include <libxml/tree.h>

#ifdef LIBXML_CATALOG_ENABLED

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The namespace for the XML Catalogs elements.
 */
#define XML_CATALOGS_NAMESPACE					\
    (const xmlChar *) "urn:oasis:names:tc:entity:xmlns:xml:catalog"
/**
 * The specific XML Catalog Processing Instruction name.
 */
#define XML_CATALOG_PI						\
    (const xmlChar *) "oasis-xml-catalog"

/** @cond ignore */

/*
 * The API is voluntarily limited to general cataloging.
 */
typedef enum {
    XML_CATA_PREFER_NONE = 0,
    XML_CATA_PREFER_PUBLIC = 1,
    XML_CATA_PREFER_SYSTEM
} xmlCatalogPrefer;

typedef enum {
    XML_CATA_ALLOW_NONE = 0,
    XML_CATA_ALLOW_GLOBAL = 1,
    XML_CATA_ALLOW_DOCUMENT = 2,
    XML_CATA_ALLOW_ALL = 3
} xmlCatalogAllow;

/** @endcond */

/** XML catalog */
typedef struct _xmlCatalog xmlCatalog;
typedef xmlCatalog *xmlCatalogPtr;

/*
 * Operations on a given catalog.
 */
XMLPUBFUN xmlCatalog *
		xmlNewCatalog		(int sgml);
XMLPUBFUN xmlCatalog *
		xmlLoadACatalog		(const char *filename);
XMLPUBFUN xmlCatalog *
		xmlLoadSGMLSuperCatalog	(const char *filename);
XMLPUBFUN int
		xmlConvertSGMLCatalog	(xmlCatalog *catal);
XMLPUBFUN int
		xmlACatalogAdd		(xmlCatalog *catal,
					 const xmlChar *type,
					 const xmlChar *orig,
					 const xmlChar *replace);
XMLPUBFUN int
		xmlACatalogRemove	(xmlCatalog *catal,
					 const xmlChar *value);
XMLPUBFUN xmlChar *
		xmlACatalogResolve	(xmlCatalog *catal,
					 const xmlChar *pubID,
	                                 const xmlChar *sysID);
XMLPUBFUN xmlChar *
		xmlACatalogResolveSystem(xmlCatalog *catal,
					 const xmlChar *sysID);
XMLPUBFUN xmlChar *
		xmlACatalogResolvePublic(xmlCatalog *catal,
					 const xmlChar *pubID);
XMLPUBFUN xmlChar *
		xmlACatalogResolveURI	(xmlCatalog *catal,
					 const xmlChar *URI);
#ifdef LIBXML_OUTPUT_ENABLED
XMLPUBFUN void
		xmlACatalogDump		(xmlCatalog *catal,
					 FILE *out);
#endif /* LIBXML_OUTPUT_ENABLED */
XMLPUBFUN void
		xmlFreeCatalog		(xmlCatalog *catal);
XMLPUBFUN int
		xmlCatalogIsEmpty	(xmlCatalog *catal);

/*
 * Global operations.
 */
XMLPUBFUN void
		xmlInitializeCatalog	(void);
XMLPUBFUN int
		xmlLoadCatalog		(const char *filename);
XMLPUBFUN void
		xmlLoadCatalogs		(const char *paths);
XMLPUBFUN void
		xmlCatalogCleanup	(void);
#ifdef LIBXML_OUTPUT_ENABLED
XMLPUBFUN void
		xmlCatalogDump		(FILE *out);
#endif /* LIBXML_OUTPUT_ENABLED */
XMLPUBFUN xmlChar *
		xmlCatalogResolve	(const xmlChar *pubID,
	                                 const xmlChar *sysID);
XMLPUBFUN xmlChar *
		xmlCatalogResolveSystem	(const xmlChar *sysID);
XMLPUBFUN xmlChar *
		xmlCatalogResolvePublic	(const xmlChar *pubID);
XMLPUBFUN xmlChar *
		xmlCatalogResolveURI	(const xmlChar *URI);
XMLPUBFUN int
		xmlCatalogAdd		(const xmlChar *type,
					 const xmlChar *orig,
					 const xmlChar *replace);
XMLPUBFUN int
		xmlCatalogRemove	(const xmlChar *value);
XML_DEPRECATED
XMLPUBFUN xmlDoc *
		xmlParseCatalogFile	(const char *filename);
XMLPUBFUN int
		xmlCatalogConvert	(void);

/*
 * Strictly minimal interfaces for per-document catalogs used
 * by the parser.
 */
XMLPUBFUN void
		xmlCatalogFreeLocal	(void *catalogs);
XMLPUBFUN void *
		xmlCatalogAddLocal	(void *catalogs,
					 const xmlChar *URL);
XMLPUBFUN xmlChar *
		xmlCatalogLocalResolve	(void *catalogs,
					 const xmlChar *pubID,
	                                 const xmlChar *sysID);
XMLPUBFUN xmlChar *
		xmlCatalogLocalResolveURI(void *catalogs,
					 const xmlChar *URI);
/*
 * Preference settings.
 */
XMLPUBFUN int
		xmlCatalogSetDebug	(int level);
XML_DEPRECATED
XMLPUBFUN xmlCatalogPrefer
		xmlCatalogSetDefaultPrefer(xmlCatalogPrefer prefer);
XMLPUBFUN void
		xmlCatalogSetDefaults	(xmlCatalogAllow allow);
XMLPUBFUN xmlCatalogAllow
		xmlCatalogGetDefaults	(void);


/* DEPRECATED interfaces */
XML_DEPRECATED
XMLPUBFUN const xmlChar *
		xmlCatalogGetSystem	(const xmlChar *sysID);
XML_DEPRECATED
XMLPUBFUN const xmlChar *
		xmlCatalogGetPublic	(const xmlChar *pubID);

#ifdef __cplusplus
}
#endif
#endif /* LIBXML_CATALOG_ENABLED */
#endif /* __XML_CATALOG_H__ */
