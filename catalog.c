/**
 * catalog.c: set of generic Catalog related routines 
 *
 * Reference:  SGML Open Technical Resolution TR9401:1997.
 *             http://www.jclark.com/sp/catalog.htm
 *
 *             XML Catalogs Working Draft 06 August 2001
 *             http://www.oasis-open.org/committees/entity/spec-2001-08-06.html
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@imag.fr
 */

#include "libxml.h"

#ifdef LIBXML_CATALOG_ENABLED
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/hash.h>
#include <libxml/uri.h>
#include <libxml/parserInternals.h>
#include <libxml/catalog.h>
#include <libxml/xmlerror.h>

/**
 * TODO:
 *
 * macro to flag unimplemented blocks
 */
#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

#define XML_URN_PUBID "urn:publicid:"

/************************************************************************
 *									*
 *			Types, all private				*
 *									*
 ************************************************************************/

typedef enum {
    XML_CATA_PREFER_PUBLIC = 1,
    XML_CATA_PREFER_SYSTEM
} xmlCatalogPrefer;

typedef enum {
    XML_CATA_NONE = 0,
    XML_CATA_CATALOG,
    XML_CATA_NEXT_CATALOG,
    XML_CATA_PUBLIC,
    XML_CATA_SYSTEM,
    XML_CATA_REWRITE_SYSTEM,
    XML_CATA_DELEGATE_PUBLIC,
    XML_CATA_DELEGATE_SYSTEM,
    XML_CATA_URI,
    XML_CATA_REWRITE_URI,
    XML_CATA_DELEGATE_URI,
    SGML_CATA_SYSTEM,
    SGML_CATA_PUBLIC,
    SGML_CATA_ENTITY,
    SGML_CATA_PENTITY,
    SGML_CATA_DOCTYPE,
    SGML_CATA_LINKTYPE,
    SGML_CATA_NOTATION,
    SGML_CATA_DELEGATE,
    SGML_CATA_BASE,
    SGML_CATA_CATALOG,
    SGML_CATA_DOCUMENT,
    SGML_CATA_SGMLDECL
} xmlCatalogEntryType;

typedef struct _xmlCatalogEntry xmlCatalogEntry;
typedef xmlCatalogEntry *xmlCatalogEntryPtr;
struct _xmlCatalogEntry {
    struct _xmlCatalogEntry *next;
    struct _xmlCatalogEntry *parent;
    struct _xmlCatalogEntry *children;
    xmlCatalogEntryType type;
    xmlChar *name;
    xmlChar *value;
    /* TODO : 1234 xmlCatalogPrefer prefer */
};

static xmlHashTablePtr xmlDefaultCatalog;
static xmlCatalogEntryPtr xmlDefaultXMLCatalogList = NULL;

/* Catalog stack */
static const char * catalTab[10];  /* stack of catals */
static int          catalNr = 0;   /* Number of current catal streams */
static int          catalMax = 10; /* Max number of catal streams */

static int xmlDebugCatalogs = 0;   /* used for debugging */

/************************************************************************
 *									*
 *			alloc or dealloc				*
 *									*
 ************************************************************************/

static xmlCatalogEntryPtr
xmlNewCatalogEntry(xmlCatalogEntryType type, const xmlChar *name,
	           const xmlChar *value) {
    xmlCatalogEntryPtr ret;

    ret = (xmlCatalogEntryPtr) xmlMalloc(sizeof(xmlCatalogEntry));
    if (ret == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"malloc of %d byte failed\n", sizeof(xmlCatalogEntry));
	return(NULL);
    }
    ret->next = NULL;
    ret->parent = NULL;
    ret->children = NULL;
    ret->type = type;
    if (name != NULL)
	ret->name = xmlStrdup(name);
    else
	ret->name = NULL;
    if (value != NULL)
	ret->value = xmlStrdup(value);
    else
	ret->value = NULL;
    return(ret);
}

static void
xmlFreeCatalogEntryList(xmlCatalogEntryPtr ret);

static void
xmlFreeCatalogEntry(xmlCatalogEntryPtr ret) {
    if (ret == NULL)
	return;
    if (ret->children != NULL)
	xmlFreeCatalogEntryList(ret->children);
    if (ret->name != NULL)
	xmlFree(ret->name);
    if (ret->value != NULL)
	xmlFree(ret->value);
    xmlFree(ret);
}

static void
xmlFreeCatalogEntryList(xmlCatalogEntryPtr ret) {
    xmlCatalogEntryPtr next;

    while (ret != NULL) {
	next = ret->next;
	xmlFreeCatalogEntry(ret);
	ret = next;
    }
}

/**
 * xmlCatalogDumpEntry:
 * @entry:  the 
 * @out:  the file.
 *
 * Free up all the memory associated with catalogs
 */
static void
xmlCatalogDumpEntry(xmlCatalogEntryPtr entry, FILE *out) {
    if ((entry == NULL) || (out == NULL))
	return;
    switch (entry->type) {
	case SGML_CATA_ENTITY:
	    fprintf(out, "ENTITY "); break;
	case SGML_CATA_PENTITY:
	    fprintf(out, "ENTITY %%"); break;
	case SGML_CATA_DOCTYPE:
	    fprintf(out, "DOCTYPE "); break;
	case SGML_CATA_LINKTYPE:
	    fprintf(out, "LINKTYPE "); break;
	case SGML_CATA_NOTATION:
	    fprintf(out, "NOTATION "); break;
	case SGML_CATA_PUBLIC:
	    fprintf(out, "PUBLIC "); break;
	case SGML_CATA_SYSTEM:
	    fprintf(out, "SYSTEM "); break;
	case SGML_CATA_DELEGATE:
	    fprintf(out, "DELEGATE "); break;
	case SGML_CATA_BASE:
	    fprintf(out, "BASE "); break;
	case SGML_CATA_CATALOG:
	    fprintf(out, "CATALOG "); break;
	case SGML_CATA_DOCUMENT:
	    fprintf(out, "DOCUMENT "); break;
	case SGML_CATA_SGMLDECL:
	    fprintf(out, "SGMLDECL "); break;
	default:
	    return;
    }
    switch (entry->type) {
	case SGML_CATA_ENTITY:
	case SGML_CATA_PENTITY:
	case SGML_CATA_DOCTYPE:
	case SGML_CATA_LINKTYPE:
	case SGML_CATA_NOTATION:
	    fprintf(out, "%s", entry->name); break;
	case SGML_CATA_PUBLIC:
	case SGML_CATA_SYSTEM:
	case SGML_CATA_SGMLDECL:
	case SGML_CATA_DOCUMENT:
	case SGML_CATA_CATALOG:
	case SGML_CATA_BASE:
	case SGML_CATA_DELEGATE:
	    fprintf(out, "\"%s\"", entry->name); break;
	default:
	    break;
    }
    switch (entry->type) {
	case SGML_CATA_ENTITY:
	case SGML_CATA_PENTITY:
	case SGML_CATA_DOCTYPE:
	case SGML_CATA_LINKTYPE:
	case SGML_CATA_NOTATION:
	case SGML_CATA_PUBLIC:
	case SGML_CATA_SYSTEM:
	case SGML_CATA_DELEGATE:
	    fprintf(out, " \"%s\"", entry->value); break;
	default:
	    break;
    }
    fprintf(out, "\n");
}

/************************************************************************
 *									*
 *			The XML Catalog parser				*
 *									*
 ************************************************************************/

static xmlCatalogEntryPtr
xmlParseXMLCatalogFile(xmlCatalogPrefer prefer, const xmlChar *filename);

static xmlCatalogEntryPtr
xmlParseXMLCatalog(const xmlChar *value, xmlCatalogPrefer prefer,
	           const char *file);
static void
xmlParseXMLCatalogNodeList(xmlNodePtr cur, xmlCatalogPrefer prefer,
	                   xmlCatalogEntryPtr parent);
static xmlChar *
xmlCatalogListXMLResolve(xmlCatalogEntryPtr catal, const xmlChar *pubID,
	              const xmlChar *sysID);

static xmlCatalogEntryType
xmlGetXMLCatalogEntryType(const xmlChar *name) {
    xmlCatalogEntryType type = XML_CATA_NONE;
    if (xmlStrEqual(name, (const xmlChar *) "system"))
	type = XML_CATA_SYSTEM;
    else if (xmlStrEqual(name, (const xmlChar *) "public"))
	type = XML_CATA_PUBLIC;
    else if (xmlStrEqual(name, (const xmlChar *) "rewriteSystem"))
	type = XML_CATA_REWRITE_SYSTEM;
    else if (xmlStrEqual(name, (const xmlChar *) "delegatePublic"))
	type = XML_CATA_DELEGATE_PUBLIC;
    else if (xmlStrEqual(name, (const xmlChar *) "delegateSystem"))
	type = XML_CATA_DELEGATE_SYSTEM;
    else if (xmlStrEqual(name, (const xmlChar *) "uri"))
	type = XML_CATA_URI;
    else if (xmlStrEqual(name, (const xmlChar *) "rewriteURI"))
	type = XML_CATA_REWRITE_URI;
    else if (xmlStrEqual(name, (const xmlChar *) "delegateURI"))
	type = XML_CATA_DELEGATE_URI;
    else if (xmlStrEqual(name, (const xmlChar *) "nextCatalog"))
	type = XML_CATA_NEXT_CATALOG;
    else if (xmlStrEqual(name, (const xmlChar *) "catalog"))
	type = XML_CATA_CATALOG;
    return(type);
}

static xmlCatalogEntryPtr
xmlParseXMLCatalogOneNode(xmlNodePtr cur, xmlCatalogEntryType type,
			  const xmlChar *name, const xmlChar *attrName,
			  const xmlChar *uriAttrName) {
    int ok = 1;
    xmlChar *uriValue;
    xmlChar *nameValue = NULL;
    xmlChar *base = NULL;
    xmlChar *URL = NULL;
    xmlCatalogEntryPtr ret = NULL;

    if (attrName != NULL) {
	nameValue = xmlGetProp(cur, attrName);
	if (nameValue == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "%s entry lacks '%s'\n", name, attrName);
	    ok = 0;
	}
    }
    uriValue = xmlGetProp(cur, uriAttrName);
    if (uriValue == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"%s entry lacks '%s'\n", name, uriAttrName);
	ok = 0;
    }
    if (!ok) {
	if (nameValue != NULL)
	    xmlFree(nameValue);
	if (uriValue != NULL)
	    xmlFree(uriValue);
	return(NULL);
    }

    base = xmlNodeGetBase(cur->doc, cur);
    URL = xmlBuildURI(uriValue, base);
    if (URL != NULL) {
	if (xmlDebugCatalogs) {
	    if (nameValue != NULL)
		printf("Found %s: '%s' '%s'\n", name, nameValue, URL);
	    else
		printf("Found %s: '%s'\n", name, URL);
	}
	ret = xmlNewCatalogEntry(type, nameValue, URL);
    } else {
	xmlGenericError(xmlGenericErrorContext,
		"%s entry '%s' broken ?: %s\n", name, uriAttrName, uriValue);
    }
    if (nameValue != NULL)
	xmlFree(nameValue);
    if (uriValue != NULL)
	xmlFree(uriValue);
    if (base != NULL)
	xmlFree(base);
    if (URL != NULL)
	xmlFree(URL);
    return(ret);
}

static void
xmlParseXMLCatalogNode(xmlNodePtr cur, xmlCatalogPrefer prefer,
	               xmlCatalogEntryPtr parent)
{
    xmlChar *uri = NULL;
    xmlChar *URL = NULL;
    xmlChar *base = NULL;
    xmlCatalogEntryPtr entry = NULL;

    if (cur == NULL)
        return;
    if (xmlStrEqual(cur->name, BAD_CAST "group")) {
        xmlChar *prop;

        prop = xmlGetProp(cur, BAD_CAST "prefer");
        if (prop != NULL) {
            if (xmlStrEqual(prop, BAD_CAST "system")) {
                prefer = XML_CATA_PREFER_SYSTEM;
            } else if (xmlStrEqual(prop, BAD_CAST "public")) {
                prefer = XML_CATA_PREFER_PUBLIC;
            } else {
                xmlGenericError(xmlGenericErrorContext,
                                "Invalid value for prefer: '%s'\n", prop);
            }
            xmlFree(prop);
        }
	/*
	 * Recurse to propagate prefer to the subtree
	 * (xml:base handling is automated)
	 */
        xmlParseXMLCatalogNodeList(cur->children, prefer, parent);
    } else if (xmlStrEqual(cur->name, BAD_CAST "public")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_PUBLIC,
		BAD_CAST "public", BAD_CAST "publicId", BAD_CAST "uri");
    } else if (xmlStrEqual(cur->name, BAD_CAST "system")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_SYSTEM,
		BAD_CAST "system", BAD_CAST "systemId", BAD_CAST "uri");
    } else if (xmlStrEqual(cur->name, BAD_CAST "rewriteSystem")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_REWRITE_SYSTEM,
		BAD_CAST "rewriteSystem", BAD_CAST "systemIdStartString",
		BAD_CAST "rewritePrefix");
    } else if (xmlStrEqual(cur->name, BAD_CAST "delegatePublic")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_DELEGATE_PUBLIC,
		BAD_CAST "delegatePublic", BAD_CAST "publicIdStartString",
		BAD_CAST "catalog");
    } else if (xmlStrEqual(cur->name, BAD_CAST "delegateSystem")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_DELEGATE_SYSTEM,
		BAD_CAST "delegateSystem", BAD_CAST "systemIdStartString",
		BAD_CAST "catalog");
    } else if (xmlStrEqual(cur->name, BAD_CAST "uri")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_URI,
		BAD_CAST "uri", BAD_CAST "name",
		BAD_CAST "uri");
    } else if (xmlStrEqual(cur->name, BAD_CAST "rewriteURI")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_REWRITE_URI,
		BAD_CAST "rewriteURI", BAD_CAST "uriStartString",
		BAD_CAST "rewritePrefix");
    } else if (xmlStrEqual(cur->name, BAD_CAST "delegateURI")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_DELEGATE_URI,
		BAD_CAST "delegateURI", BAD_CAST "uriStartString",
		BAD_CAST "catalog");
    } else if (xmlStrEqual(cur->name, BAD_CAST "nextCatalog")) {
	entry = xmlParseXMLCatalogOneNode(cur, XML_CATA_NEXT_CATALOG,
		BAD_CAST "nextCatalog", NULL,
		BAD_CAST "catalog");
    }
    if ((entry != NULL) && (parent != NULL)) {
	entry->parent = parent;
	if (parent->children == NULL)
	    parent->children = entry;
	else {
	    xmlCatalogEntryPtr prev;

	    prev = parent->children;
	    while (prev->next != NULL)
		prev = prev->next;
	    prev->next = entry;
	}
    }
    if (base != NULL)
	xmlFree(base);
    if (uri != NULL)
	xmlFree(uri);
    if (URL != NULL)
	xmlFree(URL);
}

static void
xmlParseXMLCatalogNodeList(xmlNodePtr cur, xmlCatalogPrefer prefer,
	                   xmlCatalogEntryPtr parent) {
    while (cur != NULL) {
	if ((cur->ns != NULL) && (cur->ns->href != NULL) &&
	    (xmlStrEqual(cur->ns->href, XML_CATALOGS_NAMESPACE))) {
	    xmlParseXMLCatalogNode(cur, prefer, parent);
	}
	cur = cur->next;
    }
    /* TODO: sort the list according to REWRITE lengths and prefer value */
}

static xmlCatalogEntryPtr
xmlParseXMLCatalog(const xmlChar *value, xmlCatalogPrefer prefer,
	           const char *file) {
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlChar *prop;
    xmlCatalogEntryPtr parent = NULL;

    if ((value == NULL) || (file == NULL))
        return(NULL);

    doc = xmlParseDoc((xmlChar *) value);
    if (doc == NULL) 
	return(NULL);
    doc->URL = xmlStrdup((const xmlChar *) file);

    cur = xmlDocGetRootElement(doc);
    if ((cur != NULL) && (xmlStrEqual(cur->name, BAD_CAST "catalog")) &&
	(cur->ns != NULL) && (cur->ns->href != NULL) &&
	(xmlStrEqual(cur->ns->href, XML_CATALOGS_NAMESPACE))) {

	parent = xmlNewCatalogEntry(XML_CATA_CATALOG,
		                    (const xmlChar *)file, NULL);
        if (parent == NULL) {
	    xmlFreeDoc(doc);
	    return(NULL);
	}

	prop = xmlGetProp(cur, BAD_CAST "prefer");
	if (prop != NULL) {
	    if (xmlStrEqual(prop, BAD_CAST "system")) {
		prefer = XML_CATA_PREFER_SYSTEM;
	    } else if (xmlStrEqual(prop, BAD_CAST "public")) {
		prefer = XML_CATA_PREFER_PUBLIC;
	    } else {
		xmlGenericError(xmlGenericErrorContext,
			"Invalid value for prefer: '%s'\n",
			        prop);
	    }
	    xmlFree(prop);
	}
	cur = cur->children;
	xmlParseXMLCatalogNodeList(cur, prefer, parent);
    } else {
	xmlGenericError(xmlGenericErrorContext,
			"File %s is not an XML Catalog\n", file);
	xmlFreeDoc(doc);
	return(NULL);
    }
    xmlFreeDoc(doc);
    return(parent);
}

static xmlCatalogEntryPtr
xmlParseXMLCatalogFile(xmlCatalogPrefer prefer, const xmlChar *filename) {
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlChar *prop;
    xmlCatalogEntryPtr parent = NULL;

    if (filename == NULL)
        return(NULL);

    doc = xmlParseFile((const char *) filename);
    if (doc == NULL) 
	return(NULL);

    cur = xmlDocGetRootElement(doc);
    if ((cur != NULL) && (xmlStrEqual(cur->name, BAD_CAST "catalog")) &&
	(cur->ns != NULL) && (cur->ns->href != NULL) &&
	(xmlStrEqual(cur->ns->href, XML_CATALOGS_NAMESPACE))) {

	parent = xmlNewCatalogEntry(XML_CATA_CATALOG,
		                    (const xmlChar *)filename, NULL);
        if (parent == NULL) {
	    xmlFreeDoc(doc);
	    return(NULL);
	}

	prop = xmlGetProp(cur, BAD_CAST "prefer");
	if (prop != NULL) {
	    if (xmlStrEqual(prop, BAD_CAST "system")) {
		prefer = XML_CATA_PREFER_SYSTEM;
	    } else if (xmlStrEqual(prop, BAD_CAST "public")) {
		prefer = XML_CATA_PREFER_PUBLIC;
	    } else {
		xmlGenericError(xmlGenericErrorContext,
			"Invalid value for prefer: '%s'\n",
			        prop);
	    }
	    xmlFree(prop);
	}
	cur = cur->children;
	xmlParseXMLCatalogNodeList(cur, prefer, parent);
    } else {
	xmlGenericError(xmlGenericErrorContext,
			"File %s is not an XML Catalog\n", filename);
	xmlFreeDoc(doc);
	return(NULL);
    }
    xmlFreeDoc(doc);
    return(parent);
}

/**
 * xmlFetchXMLCatalogFile:
 * @catal:  an existing but incomplete catalog entry
 *
 * Fetch and parse the subcatalog referenced by an entry
 * It tries to be thread safe but by lack of an atomic test and
 * set there is a risk of loosing memory.
 * 
 * Returns 0 in case of success, -1 otherwise
 */
static int
xmlFetchXMLCatalogFile(xmlCatalogEntryPtr catal) {
    xmlCatalogEntryPtr children;

    if (catal == NULL) 
	return(-1);
    if (catal->value == NULL)
	return(-1);
    if (catal->children != NULL)
	return(-1);

    /*
     * Fetch and parse
     */
    /* TODO : 1234 s/XML_CATA_PREFER_PUBLIC/catal->prefer */
    children = xmlParseXMLCatalogFile(XML_CATA_PREFER_PUBLIC, catal->value);
    if (children == NULL)
	return(-1);

    /*
     * Where a real test and set would be needed !
     */
    if (catal->children == NULL) {
	catal->children = children;
    } else {
	/*
	 * Another thread filled it before us
	 */
	xmlFreeCatalogEntryList(children);
    }
    return(0);
}

static int
xmlDumpXMLCatalog(FILE *out, xmlCatalogEntryPtr catal) {
    int ret;
    xmlDocPtr doc;
    xmlNsPtr ns;
    xmlDtdPtr dtd;
    xmlNodePtr node, catalog;
    xmlOutputBufferPtr buf;
    xmlCatalogEntryPtr cur;

    /*
     * Rebuild a catalog
     */
    doc = xmlNewDoc(NULL);
    if (doc == NULL)
	return(-1);
    dtd = xmlNewDtd(doc, BAD_CAST "catalog",
	       BAD_CAST "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN",
BAD_CAST "http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd");

    xmlAddChild((xmlNodePtr) doc, (xmlNodePtr) dtd);

    ns = xmlNewNs(NULL, XML_CATALOGS_NAMESPACE, NULL);
    if (ns == NULL) {
	xmlFreeDoc(doc);
	return(-1);
    }
    catalog = xmlNewDocNode(doc, ns, BAD_CAST "catalog", NULL);
    if (catalog == NULL) {
	xmlFreeNs(ns);
	xmlFreeDoc(doc);
	return(-1);
    }
    catalog->nsDef = ns;
    xmlAddChild((xmlNodePtr) doc, catalog);

    /*
     * add all the catalog entries
     */
    cur = catal;
    while (cur != NULL) {
	switch (cur->type) {
	    case XML_CATA_CATALOG:
		if (cur == catal) {
		    cur = cur->children;
		    continue;
		}
                break;
	    case XML_CATA_NEXT_CATALOG:
		node = xmlNewDocNode(doc, ns, BAD_CAST "nextCatalog", NULL);
		xmlSetProp(node, BAD_CAST "catalog", cur->value);
		xmlAddChild(catalog, node);
                break;
	    case XML_CATA_NONE:
		break;
	    case XML_CATA_PUBLIC:
		node = xmlNewDocNode(doc, ns, BAD_CAST "public", NULL);
		xmlSetProp(node, BAD_CAST "publicId", cur->name);
		xmlSetProp(node, BAD_CAST "uri", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case XML_CATA_SYSTEM:
		node = xmlNewDocNode(doc, ns, BAD_CAST "system", NULL);
		xmlSetProp(node, BAD_CAST "systemId", cur->name);
		xmlSetProp(node, BAD_CAST "uri", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case XML_CATA_REWRITE_SYSTEM:
		node = xmlNewDocNode(doc, ns, BAD_CAST "rewriteSystem", NULL);
		xmlSetProp(node, BAD_CAST "systemIdStartString", cur->name);
		xmlSetProp(node, BAD_CAST "rewritePrefix", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case XML_CATA_DELEGATE_PUBLIC:
		node = xmlNewDocNode(doc, ns, BAD_CAST "delegatePublic", NULL);
		xmlSetProp(node, BAD_CAST "publicIdStartString", cur->name);
		xmlSetProp(node, BAD_CAST "catalog", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case XML_CATA_DELEGATE_SYSTEM:
		node = xmlNewDocNode(doc, ns, BAD_CAST "delegateSystem", NULL);
		xmlSetProp(node, BAD_CAST "systemIdStartString", cur->name);
		xmlSetProp(node, BAD_CAST "catalog", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case XML_CATA_URI:
		node = xmlNewDocNode(doc, ns, BAD_CAST "uri", NULL);
		xmlSetProp(node, BAD_CAST "name", cur->name);
		xmlSetProp(node, BAD_CAST "uri", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case XML_CATA_REWRITE_URI:
		node = xmlNewDocNode(doc, ns, BAD_CAST "rewriteURI", NULL);
		xmlSetProp(node, BAD_CAST "uriStartString", cur->name);
		xmlSetProp(node, BAD_CAST "rewritePrefix", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case XML_CATA_DELEGATE_URI:
		node = xmlNewDocNode(doc, ns, BAD_CAST "delegateURI", NULL);
		xmlSetProp(node, BAD_CAST "uriStartString", cur->name);
		xmlSetProp(node, BAD_CAST "catalog", cur->value);
		xmlAddChild(catalog, node);
		break;
	    case SGML_CATA_SYSTEM:
	    case SGML_CATA_PUBLIC:
	    case SGML_CATA_ENTITY:
	    case SGML_CATA_PENTITY:
	    case SGML_CATA_DOCTYPE:
	    case SGML_CATA_LINKTYPE:
	    case SGML_CATA_NOTATION:
	    case SGML_CATA_DELEGATE:
	    case SGML_CATA_BASE:
	    case SGML_CATA_CATALOG:
	    case SGML_CATA_DOCUMENT:
	    case SGML_CATA_SGMLDECL:
		break;
	}
	cur = cur->next;
    }

    /*
     * reserialize it
     */
    buf = xmlOutputBufferCreateFile(out, NULL);
    if (buf == NULL) {
	xmlFreeDoc(doc);
	return(-1);
    }
    ret = xmlSaveFormatFileTo(buf, doc, NULL, 1);

    /*
     * Free it
     */
    xmlFreeDoc(doc);

    return(ret);
}

/**
 * xmlAddXMLCatalog:
 * @catal:  top of an XML catalog
 * @type:  the type of record to add to the catalog
 * @orig:  the system, public or prefix to match (or NULL)
 * @replace:  the replacement value for the match
 *
 * Add an entry in the XML catalog, it may overwrite existing but
 * different entries.
 *
 * Returns 0 if successful, -1 otherwise
 */
static int
xmlAddXMLCatalog(xmlCatalogEntryPtr catal, const xmlChar *type,
	      const xmlChar *orig, const xmlChar *replace) {
    xmlCatalogEntryPtr cur;
    xmlCatalogEntryType typ;

    if ((catal == NULL) || (catal->type != XML_CATA_CATALOG))
	return(-1);
    typ = xmlGetXMLCatalogEntryType(type);
    if (typ == XML_CATA_NONE)
	return(-1);

    cur = catal->children;
    /*
     * Might be a simple "update in place"
     */
    if (cur != NULL) {
	while (cur != NULL) {
	    if ((orig != NULL) && (cur->type == typ) &&
		(xmlStrEqual(orig, cur->name))) {
		if (cur->value != NULL)
		    xmlFree(cur->value);
		cur->value = xmlStrdup(replace);
		return(0);
	    }
	    if (cur->next == NULL)
		break;
	    cur = cur->next;
	}
    }
    if (cur == NULL)
	catal->children = xmlNewCatalogEntry(typ, orig, replace);
    else
	cur->next = xmlNewCatalogEntry(typ, orig, replace);
    return(0);
}

/**
 * xmlDelXMLCatalog:
 * @catal:  top of an XML catalog
 * @value:  the value to remove from teh catalog
 *
 * Remove entries in the XML catalog where the value or the URI
 * is equal to @value
 *
 * Returns the number of entries removed if successful, -1 otherwise
 */
static int
xmlDelXMLCatalog(xmlCatalogEntryPtr catal, const xmlChar *value) {
    xmlCatalogEntryPtr cur, prev, tmp;
    int ret = 0;

    if ((catal == NULL) || (catal->type != XML_CATA_CATALOG))
	return(-1);
    if (value == NULL)
	return(-1);

    /*
     * Scan the children
     */
    cur = catal->children;
    prev = NULL;
    while (cur != NULL) {
	if (((cur->name != NULL) && (xmlStrEqual(value, cur->name))) ||
	    (xmlStrEqual(value, cur->value))) {
	    ret++;
	    tmp = cur;
	    cur = tmp->next;
	    if (prev == NULL) {
		catal->children = cur;
	    } else {
		prev->next = cur;
	    }
            xmlFreeCatalogEntry(tmp);
	    continue;
	}
	prev = cur;
	cur = cur->next;
    }
    return(ret);
}

/**
 * xmlCatalogGetXMLPublic:
 * @catal:  an XML catalog
 * @pubId:  the public ID string
 *
 * Try to lookup the system ID associated to a public ID
 *
 * Returns the system ID if found or NULL otherwise.
 */
static const xmlChar *
xmlCatalogGetXMLPublic(xmlCatalogEntryPtr catal, const xmlChar *pubID) {
    const xmlChar *ret;
    while (catal != NULL) {
	switch (catal->type) {
            case XML_CATA_CATALOG:
		if (catal->children == NULL) {
		    if (xmlFetchXMLCatalogFile(catal))
			break;
		}
		ret = xmlCatalogGetXMLPublic(catal->children, pubID);
		if (ret != NULL)
		    return(ret);
		break;
            case XML_CATA_NEXT_CATALOG:
		if (catal->children == NULL) {
		    if (xmlFetchXMLCatalogFile(catal))
			break;
		}
            case XML_CATA_PUBLIC:
		if (xmlStrEqual(pubID, catal->name))
		    return(catal->value);
		break;
            case XML_CATA_SYSTEM:
            case XML_CATA_REWRITE_SYSTEM:
            case XML_CATA_DELEGATE_PUBLIC:
            case XML_CATA_DELEGATE_SYSTEM:
            case XML_CATA_URI:
            case XML_CATA_REWRITE_URI:
            case XML_CATA_DELEGATE_URI:
		TODO;
		break;

            case XML_CATA_NONE:
            case SGML_CATA_SYSTEM:
            case SGML_CATA_PUBLIC:
            case SGML_CATA_ENTITY:
            case SGML_CATA_PENTITY:
            case SGML_CATA_DOCTYPE:
            case SGML_CATA_LINKTYPE:
            case SGML_CATA_NOTATION:
            case SGML_CATA_DELEGATE:
            case SGML_CATA_BASE:
            case SGML_CATA_CATALOG:
            case SGML_CATA_DOCUMENT:
            case SGML_CATA_SGMLDECL:
		/* Ignored entries */
		break;
	}
	catal = catal->next;
    }
    return(NULL);
}

/**
 * xmlCatalogXMLResolve:
 * @catal:  a catalog list
 * @pubId:  the public ID string
 * @sysId:  the system ID string
 *
 * Do a complete resolution lookup of an External Identifier for a
 * list of catalog entries.
 *
 * Implements (or tries to) 7.1. External Identifier Resolution
 * from http://www.oasis-open.org/committees/entity/spec-2001-08-06.html
 *
 * Returns the URI of the resource or NULL if not found
 */
static xmlChar *
xmlCatalogXMLResolve(xmlCatalogEntryPtr catal, const xmlChar *pubID,
	              const xmlChar *sysID) {
    xmlChar *ret = NULL;
    xmlCatalogEntryPtr cur;
    int haveDelegate = 0;
    int haveNext = 0;

    /*
     * First tries steps 2/ 3/ 4/ if a system ID is provided.
     */
    if (sysID != NULL) {
	xmlCatalogEntryPtr rewrite = NULL;
	int lenrewrite = 0, len;
	cur = catal;
	haveDelegate = 0;
	while (cur != NULL) {
	    switch (cur->type) {
		case XML_CATA_SYSTEM:
		    if (xmlStrEqual(sysID, cur->name))
			return(xmlStrdup(cur->value));
		    break;
		case XML_CATA_REWRITE_SYSTEM:
		    len = xmlStrlen(cur->name);
		    if ((len > lenrewrite) &&
			(!xmlStrncmp(sysID, cur->name, len))) {
			lenrewrite = len;
			rewrite = cur;
		    }
		    break;
		case XML_CATA_DELEGATE_SYSTEM:
		    if (!xmlStrncmp(sysID, cur->name, xmlStrlen(cur->name)))
			haveDelegate++;
		    break;
		case XML_CATA_NEXT_CATALOG:
		    haveNext++;
		    break;
		default:
		    break;
	    }
	    cur = cur->next;
	}
	if (rewrite != NULL) {
	    ret = xmlStrdup(rewrite->value);
	    if (ret != NULL)
		ret = xmlStrcat(ret, &sysID[lenrewrite]);
	    return(ret);
	}
	if (haveDelegate) {
	    /*
	     * Assume the entries have been sorted by decreasing subscting
	     * matches when the list was produced.
	     */
	    cur = catal;
	    while (cur != NULL) {
		if ((cur->type == XML_CATA_DELEGATE_SYSTEM) &&
		    (!xmlStrncmp(sysID, cur->name, xmlStrlen(cur->name)))) {
		    if (cur->children == NULL) {
			xmlFetchXMLCatalogFile(cur);
		    }
		    if (cur->children != NULL) {
			TODO /* handle a delegate system entry */
		    }
		}
		cur = cur->next;
	    }
	}
    }
    /*
     * Then tries 5/ 6/ if a public ID is provided
     */
    if (pubID != NULL) {
	cur = catal;
	haveDelegate = 0;
	while (cur != NULL) {
	    switch (cur->type) {
		case XML_CATA_PUBLIC:
		    if (xmlStrEqual(pubID, cur->name))
			return(xmlStrdup(cur->value));
		    break;
		case XML_CATA_DELEGATE_PUBLIC:
		    if (!xmlStrncmp(pubID, cur->name, xmlStrlen(cur->name)))
			haveDelegate++;
		    break;
		case XML_CATA_NEXT_CATALOG:
		    if (sysID == NULL)
			haveNext++;
		    break;
		default:
		    break;
	    }
	    cur = cur->next;
	}
	if (haveDelegate) {
	    /*
	     * Assume the entries have been sorted by decreasing subscting
	     * matches when the list was produced.
	     */
	    cur = catal;
	    while (cur != NULL) {
		if ((cur->type == XML_CATA_DELEGATE_PUBLIC) &&
		    (!xmlStrncmp(sysID, cur->name, xmlStrlen(cur->name)))) {
		    if (cur->children == NULL) {
			xmlFetchXMLCatalogFile(cur);
		    }
		    if (cur->children != NULL) {
			TODO /* handle a delegate public entry */
		    }
		}
		cur = cur->next;
	    }
	}
    }
    if (haveNext) {
	cur = catal;
	while (cur != NULL) {
	    if (cur->type == XML_CATA_NEXT_CATALOG) {
		if (cur->children == NULL) {
		    xmlFetchXMLCatalogFile(cur);
		}
		if (cur->children != NULL) {
		    xmlCatalogListXMLResolve(cur->children, pubID, sysID);
		}
	    }
	    cur = cur->next;
	}
    }

    return(NULL);
}

/**
 * xmlCatalogListXMLResolve:
 * @catal:  a catalog list
 * @pubId:  the public ID string
 * @sysId:  the system ID string
 *
 * Do a complete resolution lookup of an External Identifier for a
 * list of catalogs
 *
 * Implements (or tries to) 7.1. External Identifier Resolution
 * from http://www.oasis-open.org/committees/entity/spec-2001-08-06.html
 *
 * Returns the URI of the resource or NULL if not found
 */
static xmlChar *
xmlCatalogListXMLResolve(xmlCatalogEntryPtr catal, const xmlChar *pubID,
	              const xmlChar *sysID) {
    xmlChar *ret = NULL;
    if (!xmlStrncmp(pubID, BAD_CAST XML_URN_PUBID, sizeof(XML_URN_PUBID))) {
	TODO /* convert to PublicId */
    }
    if (!xmlStrncmp(sysID, BAD_CAST XML_URN_PUBID, sizeof(XML_URN_PUBID))) {
	TODO /* convert to PublicId and check */
    }
    while (catal != NULL) {
	if (catal->type == XML_CATA_CATALOG) {
	    if (catal->children == NULL) {
		/*
		 * Construct the list on the fly, then double check
		 * in case of threaded program that it hasn't already
		 * being built by a concurrent thread.
		xmlCatalogEntryPtr list;

		list = 
		 */
		TODO
	    }
	    ret = xmlCatalogXMLResolve(catal->children, pubID, sysID);
	    if (ret != NULL)
		return(ret);
	}
	catal = catal->next;
    }
    return(ret);
}

/************************************************************************
 *									*
 *			The SGML Catalog parser				*
 *									*
 ************************************************************************/


#define RAW *cur
#define NEXT cur++;
#define SKIP(x) cur += x;

#define SKIP_BLANKS while (IS_BLANK(*cur)) NEXT;

static const xmlChar *
xmlParseSGMLCatalogComment(const xmlChar *cur) {
    if ((cur[0] != '-') || (cur[1] != '-')) 
	return(cur);
    SKIP(2);
    while ((cur[0] != 0) && ((cur[0] != '-') || ((cur[1] != '-'))))
	NEXT;
    if (cur[0] == 0) {
	return(NULL);
    }
    return(cur + 2);
}

static const xmlChar *
xmlParseSGMLCatalogPubid(const xmlChar *cur, xmlChar **id) {
    xmlChar *buf = NULL;
    int len = 0;
    int size = 50;
    xmlChar stop;
    int count = 0;

    *id = NULL;

    if (RAW == '"') {
        NEXT;
	stop = '"';
    } else if (RAW == '\'') {
        NEXT;
	stop = '\'';
    } else {
	stop = ' ';
    }
    buf = (xmlChar *) xmlMalloc(size * sizeof(xmlChar));
    if (buf == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"malloc of %d byte failed\n", size);
	return(NULL);
    }
    while (xmlIsPubidChar(*cur)) {
	if ((*cur == stop) && (stop != ' '))
	    break;
	if ((stop == ' ') && (IS_BLANK(*cur)))
	    break;
	if (len + 1 >= size) {
	    size *= 2;
	    buf = (xmlChar *) xmlRealloc(buf, size * sizeof(xmlChar));
	    if (buf == NULL) {
		xmlGenericError(xmlGenericErrorContext,
			"realloc of %d byte failed\n", size);
		return(NULL);
	    }
	}
	buf[len++] = *cur;
	count++;
	NEXT;
    }
    buf[len] = 0;
    if (stop == ' ') {
	if (!IS_BLANK(*cur)) {
	    xmlFree(buf);
	    return(NULL);
	}
    } else {
	if (*cur != stop) {
	    xmlFree(buf);
	    return(NULL);
	}
	NEXT;
    }
    *id = buf;
    return(cur);
}

static const xmlChar *
xmlParseSGMLCatalogName(const xmlChar *cur, xmlChar **name) {
    xmlChar buf[XML_MAX_NAMELEN + 5];
    int len = 0;
    int c;

    *name = NULL;

    /*
     * Handler for more complex cases
     */
    c = *cur;
    if ((!IS_LETTER(c) && (c != '_') && (c != ':'))) {
	return(NULL);
    }

    while (((IS_LETTER(c)) || (IS_DIGIT(c)) ||
            (c == '.') || (c == '-') ||
	    (c == '_') || (c == ':'))) {
	buf[len++] = c;
	cur++;
	c = *cur;
	if (len >= XML_MAX_NAMELEN)
	    return(NULL);
    }
    *name = xmlStrndup(buf, len);
    return(cur);
}

static xmlCatalogEntryType
xmlGetSGMLCatalogEntryType(const xmlChar *name) {
    xmlCatalogEntryType type = XML_CATA_NONE;
    if (xmlStrEqual(name, (const xmlChar *) "SYSTEM"))
	type = SGML_CATA_SYSTEM;
    else if (xmlStrEqual(name, (const xmlChar *) "PUBLIC"))
	type = SGML_CATA_PUBLIC;
    else if (xmlStrEqual(name, (const xmlChar *) "DELEGATE"))
	type = SGML_CATA_DELEGATE;
    else if (xmlStrEqual(name, (const xmlChar *) "ENTITY"))
	type = SGML_CATA_ENTITY;
    else if (xmlStrEqual(name, (const xmlChar *) "DOCTYPE"))
	type = SGML_CATA_DOCTYPE;
    else if (xmlStrEqual(name, (const xmlChar *) "LINKTYPE"))
	type = SGML_CATA_LINKTYPE;
    else if (xmlStrEqual(name, (const xmlChar *) "NOTATION"))
	type = SGML_CATA_NOTATION;
    else if (xmlStrEqual(name, (const xmlChar *) "SGMLDECL"))
	type = SGML_CATA_SGMLDECL;
    else if (xmlStrEqual(name, (const xmlChar *) "DOCUMENT"))
	type = SGML_CATA_DOCUMENT;
    else if (xmlStrEqual(name, (const xmlChar *) "CATALOG"))
	type = SGML_CATA_CATALOG;
    else if (xmlStrEqual(name, (const xmlChar *) "BASE"))
	type = SGML_CATA_BASE;
    else if (xmlStrEqual(name, (const xmlChar *) "DELEGATE"))
	type = SGML_CATA_DELEGATE;
    return(type);
}

static int
xmlParseSGMLCatalog(const xmlChar *value, const char *file) {
    const xmlChar *cur = value;
    xmlChar *base = NULL;
    int res;

    if ((cur == NULL) || (file == NULL))
        return(-1);
    base = xmlStrdup((const xmlChar *) file);

    while ((cur != NULL) && (cur[0] != '0')) {
	SKIP_BLANKS;
	if ((cur[0] == '-') && (cur[1] == '-')) {
	    cur = xmlParseSGMLCatalogComment(cur);
	    if (cur == NULL) {
		/* error */
		break;
	    }
	} else {
	    xmlChar *sysid = NULL;
	    xmlChar *name = NULL;
	    xmlCatalogEntryType type = XML_CATA_NONE;

	    cur = xmlParseSGMLCatalogName(cur, &name);
	    if (name == NULL) {
		/* error */
		break;
	    }
	    if (!IS_BLANK(*cur)) {
		/* error */
		break;
	    }
	    SKIP_BLANKS;
	    if (xmlStrEqual(name, (const xmlChar *) "SYSTEM"))
                type = SGML_CATA_SYSTEM;
	    else if (xmlStrEqual(name, (const xmlChar *) "PUBLIC"))
                type = SGML_CATA_PUBLIC;
	    else if (xmlStrEqual(name, (const xmlChar *) "DELEGATE"))
                type = SGML_CATA_DELEGATE;
	    else if (xmlStrEqual(name, (const xmlChar *) "ENTITY"))
                type = SGML_CATA_ENTITY;
	    else if (xmlStrEqual(name, (const xmlChar *) "DOCTYPE"))
                type = SGML_CATA_DOCTYPE;
	    else if (xmlStrEqual(name, (const xmlChar *) "LINKTYPE"))
                type = SGML_CATA_LINKTYPE;
	    else if (xmlStrEqual(name, (const xmlChar *) "NOTATION"))
                type = SGML_CATA_NOTATION;
	    else if (xmlStrEqual(name, (const xmlChar *) "SGMLDECL"))
                type = SGML_CATA_SGMLDECL;
	    else if (xmlStrEqual(name, (const xmlChar *) "DOCUMENT"))
                type = SGML_CATA_DOCUMENT;
	    else if (xmlStrEqual(name, (const xmlChar *) "CATALOG"))
                type = SGML_CATA_CATALOG;
	    else if (xmlStrEqual(name, (const xmlChar *) "BASE"))
                type = SGML_CATA_BASE;
	    else if (xmlStrEqual(name, (const xmlChar *) "DELEGATE"))
                type = SGML_CATA_DELEGATE;
	    else if (xmlStrEqual(name, (const xmlChar *) "OVERRIDE")) {
		xmlFree(name);
		cur = xmlParseSGMLCatalogName(cur, &name);
		if (name == NULL) {
		    /* error */
		    break;
		}
		xmlFree(name);
		continue;
	    }
	    xmlFree(name);
	    name = NULL;

	    switch(type) {
		case SGML_CATA_ENTITY:
		    if (*cur == '%')
			type = SGML_CATA_PENTITY;
		case SGML_CATA_PENTITY:
		case SGML_CATA_DOCTYPE:
		case SGML_CATA_LINKTYPE:
		case SGML_CATA_NOTATION:
		    cur = xmlParseSGMLCatalogName(cur, &name);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    if (!IS_BLANK(*cur)) {
			/* error */
			break;
		    }
		    SKIP_BLANKS;
		    cur = xmlParseSGMLCatalogPubid(cur, &sysid);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    break;
		case SGML_CATA_PUBLIC:
		case SGML_CATA_SYSTEM:
		case SGML_CATA_DELEGATE:
		    cur = xmlParseSGMLCatalogPubid(cur, &name);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    if (!IS_BLANK(*cur)) {
			/* error */
			break;
		    }
		    SKIP_BLANKS;
		    cur = xmlParseSGMLCatalogPubid(cur, &sysid);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    break;
		case SGML_CATA_BASE:
		case SGML_CATA_CATALOG:
		case SGML_CATA_DOCUMENT:
		case SGML_CATA_SGMLDECL:
		    cur = xmlParseSGMLCatalogPubid(cur, &sysid);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    break;
		default:
		    break;
	    }
	    if (cur == NULL) {
		if (name != NULL)
		    xmlFree(name);
		if (sysid != NULL)
		    xmlFree(sysid);
		break;
	    } else if (type == SGML_CATA_BASE) {
		if (base != NULL)
		    xmlFree(base);
		base = xmlStrdup(sysid);
	    } else if ((type == SGML_CATA_PUBLIC) ||
		       (type == SGML_CATA_SYSTEM)) {
		xmlChar *filename;

		filename = xmlBuildURI(sysid, base);
		if (filename != NULL) {
		    xmlCatalogEntryPtr entry;

		    entry = xmlNewCatalogEntry(type, name, filename);
		    res = xmlHashAddEntry(xmlDefaultCatalog, name, entry);
		    if (res < 0) {
			xmlFreeCatalogEntry(entry);
		    }
		    xmlFree(filename);
		}

	    } else if (type == SGML_CATA_CATALOG) {
		xmlChar *filename;

		filename = xmlBuildURI(sysid, base);
		if (filename != NULL) {
		    xmlLoadCatalog((const char *)filename);
		    xmlFree(filename);
		}
	    }
	    /*
	     * drop anything else we won't handle it
	     */
	    if (name != NULL)
		xmlFree(name);
	    if (sysid != NULL)
		xmlFree(sysid);
	}
    }
    if (base != NULL)
	xmlFree(base);
    if (cur == NULL)
	return(-1);
    return(0);
}

/**
 * xmlCatalogGetSGMLPublic:
 * @catal:  an SGML catalog hash
 * @pubId:  the public ID string
 *
 * Try to lookup the system ID associated to a public ID
 *
 * Returns the system ID if found or NULL otherwise.
 */
static const xmlChar *
xmlCatalogGetSGMLPublic(xmlHashTablePtr catal, const xmlChar *pubID) {
    xmlCatalogEntryPtr entry;

    if (catal == NULL)
	return(NULL);

    entry = (xmlCatalogEntryPtr) xmlHashLookup(catal, pubID);
    if (entry == NULL)
	return(NULL);
    if (entry->type == SGML_CATA_PUBLIC)
	return(entry->value);
    return(NULL);
}

/**
 * xmlCatalogSGMLResolve:
 * @pubId:  the public ID string
 * @sysId:  the system ID string
 *
 * Do a complete resolution lookup of an External Identifier
 *
 * Returns the URI of the resource or NULL if not found
 */
static const xmlChar *
xmlCatalogSGMLResolve(const xmlChar *pubID, const xmlChar *sysID) {
    TODO
    return(NULL);
}

/************************************************************************
 *									*
 *			Public interfaces				*
 *									*
 ************************************************************************/

/**
 * xmlLoadCatalog:
 * @filename:  a file path
 *
 * Load the catalog and makes its definitions effective for the default
 * external entity loader. It will recuse in CATALOG entries.
 * TODO: this function is not thread safe, catalog initialization should
 *       be done once at startup
 *
 * Returns 0 in case of success -1 in case of error
 */
int
xmlLoadCatalog(const char *filename) {
    int fd, len, ret, i;
    struct stat info;
    xmlChar *content;

    if (filename == NULL)
	return(-1);

    if (xmlDefaultCatalog == NULL)
	xmlDefaultCatalog = xmlHashCreate(20);
    if (xmlDefaultCatalog == NULL)
	return(-1);
    
    if (stat(filename, &info) < 0) 
	return(-1);

    /*
     * Prevent loops
     */
    for (i = 0;i < catalNr;i++) {
	if (xmlStrEqual((const xmlChar *)catalTab[i],
		        (const xmlChar *)filename)) {
	    xmlGenericError(xmlGenericErrorContext,
		"xmlLoadCatalog: %s seems to induce a loop\n",
		            filename);
	    return(-1);
	}
    }
    if (catalNr >= catalMax) {
	xmlGenericError(xmlGenericErrorContext,
	    "xmlLoadCatalog: %s catalog list too deep\n",
			filename);
	    return(-1);
    }
    catalTab[catalNr++] = filename;

    if ((fd = open(filename, O_RDONLY)) < 0) {
	catalNr--;
	return(-1);
    }

    content = xmlMalloc(info.st_size + 10);
    if (content == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"realloc of %d byte failed\n", info.st_size + 10);
	catalNr--;
	return(-1);
    }
    len = read(fd, content, info.st_size);
    if (len < 0) {
	xmlFree(content);
	catalNr--;
	return(-1);
    }
    content[len] = 0;
    close(fd);

    if ((content[0] == ' ') || (content[0] == '-') ||
	((content[0] >= 'A') && (content[0] <= 'Z')) ||
	((content[0] >= 'a') && (content[0] <= 'z')))
	ret = xmlParseSGMLCatalog(content, filename);
    else {
	xmlCatalogEntryPtr catal, tmp;
	/* TODO: allow to switch the default preference */
	catal = xmlParseXMLCatalog(content, XML_CATA_PREFER_PUBLIC, filename);
	if (catal != NULL) {
	    if (xmlDefaultXMLCatalogList == NULL)
		xmlDefaultXMLCatalogList = catal;
	    else {
		tmp = xmlDefaultXMLCatalogList;
		while (tmp->next != NULL)
		    tmp = tmp->next;
		tmp->next = catal;
	    }
	    ret = 0;
	} else
	    ret = -1;
    }
    xmlFree(content);
    catalNr--;
    return(ret);
}

/**
 * xmlLoadCatalogs:
 * @paths:  a list of file path separated by ':' or spaces
 *
 * Load the catalogs and makes their definitions effective for the default
 * external entity loader.
 * TODO: this function is not thread safe, catalog initialization should
 *       be done once at startup
 */
void
xmlLoadCatalogs(const char *pathss) {
    const char *cur;
    const char *paths;
    xmlChar *path;

    cur = pathss;
    while ((cur != NULL) && (*cur != 0)) {
	while (IS_BLANK(*cur)) cur++;
	if (*cur != 0) {
	    paths = cur;
	    while ((*cur != 0) && (*cur != ':') && (!IS_BLANK(*cur)))
		cur++;
	    path = xmlStrndup((const xmlChar *)paths, cur - paths);
	    if (path != NULL) {
		xmlLoadCatalog((const char *) path);
		xmlFree(path);
	    }
	}
	while (*cur == ':')
	    cur++;
    }
}

/**
 * xmlCatalogCleanup:
 *
 * Free up all the memory associated with catalogs
 */
void
xmlCatalogCleanup(void) {
    if (xmlDefaultXMLCatalogList != NULL)
	xmlFreeCatalogEntryList(xmlDefaultXMLCatalogList);
    if (xmlDefaultCatalog != NULL)
	xmlHashFree(xmlDefaultCatalog,
		    (xmlHashDeallocator) xmlFreeCatalogEntry);
    xmlDefaultCatalog = NULL;
}

/**
 * xmlCatalogGetSystem:
 * @sysId:  the system ID string
 *
 * Try to lookup the resource associated to a system ID
 *
 * Returns the resource name if found or NULL otherwise.
 */
const xmlChar *
xmlCatalogGetSystem(const xmlChar *sysID) {
    xmlCatalogEntryPtr entry;

    if ((sysID == NULL) || (xmlDefaultCatalog == NULL))
	return(NULL);
    entry = (xmlCatalogEntryPtr) xmlHashLookup(xmlDefaultCatalog, sysID);
    if (entry == NULL)
	return(NULL);
    if (entry->type == SGML_CATA_SYSTEM)
	return(entry->value);
    return(NULL);
}

/**
 * xmlCatalogGetPublic:
 * @pubId:  the public ID string
 *
 * Try to lookup the system ID associated to a public ID
 *
 * Returns the system ID if found or NULL otherwise.
 */
const xmlChar *
xmlCatalogGetPublic(const xmlChar *pubID) {
    xmlCatalogEntryPtr catal;
    const xmlChar *ret;

    if (pubID == NULL)
	return(NULL);
    
    /*
     * Check first the XML catalogs
     */
    catal = xmlDefaultXMLCatalogList;
    if (catal != NULL) {
	ret = xmlCatalogGetXMLPublic(catal, pubID);
	if (ret != NULL)
	    return(ret);
    }

    if (xmlDefaultCatalog != NULL)
	return(xmlCatalogGetSGMLPublic(xmlDefaultCatalog, pubID));
    return(NULL);
}

/**
 * xmlCatalogResolve:
 * @pubId:  the public ID string
 * @sysId:  the system ID string
 *
 * Do a complete resolution lookup of an External Identifier
 *
 * Returns the URI of the resource or NULL if not found, it must be freed
 *      by the caller.
 */
xmlChar *
xmlCatalogResolve(const xmlChar *pubID, const xmlChar *sysID) {
    if (xmlDefaultXMLCatalogList != NULL) {
	return(xmlCatalogListXMLResolve(xmlDefaultXMLCatalogList, pubID, sysID));
    } else {
	return(xmlCatalogSGMLResolve(pubID, sysID));
    }
}

/**
 * xmlCatalogDump:
 * @out:  the file.
 *
 * Free up all the memory associated with catalogs
 */
void
xmlCatalogDump(FILE *out) {
    if (out == NULL)
	return;

    if (xmlDefaultXMLCatalogList != NULL) {
	xmlDumpXMLCatalog(out, xmlDefaultXMLCatalogList);
    } else if (xmlDefaultCatalog != NULL) {
	xmlHashScan(xmlDefaultCatalog,
		    (xmlHashScanner) xmlCatalogDumpEntry, out);
    } 
}

/**
 * xmlCatalogAdd:
 * @type:  the type of record to add to the catalog
 * @orig:  the system, public or prefix to match 
 * @replace:  the replacement value for the match
 *
 * Add an entry in the catalog, it may overwrite existing but
 * different entries.
 *
 * Returns 0 if successful, -1 otherwise
 */
int
xmlCatalogAdd(const xmlChar *type, const xmlChar *orig, const xmlChar *replace) {
    int res = -1;

    if (xmlDefaultXMLCatalogList != NULL) {
	res = xmlAddXMLCatalog(xmlDefaultXMLCatalogList, type, orig, replace);
    } else if (xmlDefaultCatalog != NULL) {
	xmlCatalogEntryType typ;

	typ = xmlGetSGMLCatalogEntryType(type);
	if (type != XML_CATA_NONE) {
	    xmlCatalogEntryPtr entry;
	    entry = xmlNewCatalogEntry(typ, orig, replace);
	    res = xmlHashAddEntry(xmlDefaultCatalog, orig, entry);
	}
    } 
    return(res);
}

/**
 * xmlCatalogRemove:
 * @value:  the value to remove
 *
 * Remove an entry from the catalog
 *
 * Returns 0 if successful, -1 otherwise
 */
int
xmlCatalogRemove(const xmlChar *value) {
    int res = -1;

    if (xmlDefaultXMLCatalogList != NULL) {
	res = xmlDelXMLCatalog(xmlDefaultXMLCatalogList, value);
    } else if (xmlDefaultCatalog != NULL) {
	TODO
    } 
    return(res);
}

/**
 * xmlCatalogSetDebug:
 * @level:  the debug level of catalogs required
 *
 * Used to set the debug level for catalog operation, 0 disable
 * debugging, 1 enable it
 *
 * Returns the previous value of the catalog debugging level
 */
int
xmlCatalogSetDebug(int level) {
    int ret = xmlDebugCatalogs;

    if (level <= 0)
        xmlDebugCatalogs = 0;
    else
	xmlDebugCatalogs = level;
    return(ret);
}
#endif /* LIBXML_CATALOG_ENABLED */
