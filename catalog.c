/**
 * catalog.c: set of generic Catalog related routines 
 *
 * Reference:  SGML Open Technical Resolution TR9401:1997.
 *             http://www.jclark.com/sp/catalog.htm
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

/************************************************************************
 *									*
 *			Types, all private				*
 *									*
 ************************************************************************/

typedef enum {
    XML_CATA_NONE = 0,
    XML_CATA_SYSTEM,
    XML_CATA_PUBLIC,
    XML_CATA_ENTITY,
    XML_CATA_PENTITY,
    XML_CATA_DOCTYPE,
    XML_CATA_LINKTYPE,
    XML_CATA_NOTATION,
    XML_CATA_DELEGATE,
    XML_CATA_BASE,
    XML_CATA_CATALOG,
    XML_CATA_DOCUMENT,
    XML_CATA_SGMLDECL
} xmlCatalogEntryType;

typedef struct _xmlCatalogEntry xmlCatalogEntry;
typedef xmlCatalogEntry *xmlCatalogEntryPtr;
struct _xmlCatalogEntry {
    xmlCatalogEntryType type;
    xmlChar *name;
    xmlChar *value;
};

static xmlHashTablePtr xmlDefaultCatalog;

/* Catalog stack */
static const char * catalTab[10];  /* stack of catals */
static int          catalNr = 0;   /* Number of current catal streams */
static int          catalMax = 10; /* Max number of catal streams */

/************************************************************************
 *									*
 *			alloc or dealloc				*
 *									*
 ************************************************************************/

static xmlCatalogEntryPtr
xmlNewCatalogEntry(int type, xmlChar *name, xmlChar *value) {
    xmlCatalogEntryPtr ret;

    ret = (xmlCatalogEntryPtr) xmlMalloc(sizeof(xmlCatalogEntry));
    if (ret == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"malloc of %d byte failed\n", sizeof(xmlCatalogEntry));
	return(NULL);
    }
    ret->type = type;
    ret->name = xmlStrdup(name);
    ret->value = xmlStrdup(value);
    return(ret);
}

static void
xmlFreeCatalogEntry(xmlCatalogEntryPtr ret) {
    if (ret == NULL)
	return;
    if (ret->name != NULL)
	xmlFree(ret->name);
    if (ret->value != NULL)
	xmlFree(ret->value);
    xmlFree(ret);
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
	case XML_CATA_ENTITY:
	    fprintf(out, "ENTITY "); break;
	case XML_CATA_PENTITY:
	    fprintf(out, "ENTITY %%"); break;
	case XML_CATA_DOCTYPE:
	    fprintf(out, "DOCTYPE "); break;
	case XML_CATA_LINKTYPE:
	    fprintf(out, "LINKTYPE "); break;
	case XML_CATA_NOTATION:
	    fprintf(out, "NOTATION "); break;
	case XML_CATA_PUBLIC:
	    fprintf(out, "PUBLIC "); break;
	case XML_CATA_SYSTEM:
	    fprintf(out, "SYSTEM "); break;
	case XML_CATA_DELEGATE:
	    fprintf(out, "DELEGATE "); break;
	case XML_CATA_BASE:
	    fprintf(out, "BASE "); break;
	case XML_CATA_CATALOG:
	    fprintf(out, "CATALOG "); break;
	case XML_CATA_DOCUMENT:
	    fprintf(out, "DOCUMENT "); break;
	case XML_CATA_SGMLDECL:
	    fprintf(out, "SGMLDECL "); break;
	default:
	    return;
    }
    switch (entry->type) {
	case XML_CATA_ENTITY:
	case XML_CATA_PENTITY:
	case XML_CATA_DOCTYPE:
	case XML_CATA_LINKTYPE:
	case XML_CATA_NOTATION:
	    fprintf(out, "%s", entry->name); break;
	case XML_CATA_PUBLIC:
	case XML_CATA_SYSTEM:
	case XML_CATA_SGMLDECL:
	case XML_CATA_DOCUMENT:
	case XML_CATA_CATALOG:
	case XML_CATA_BASE:
	case XML_CATA_DELEGATE:
	    fprintf(out, "\"%s\"", entry->name); break;
	default:
	    break;
    }
    switch (entry->type) {
	case XML_CATA_ENTITY:
	case XML_CATA_PENTITY:
	case XML_CATA_DOCTYPE:
	case XML_CATA_LINKTYPE:
	case XML_CATA_NOTATION:
	case XML_CATA_PUBLIC:
	case XML_CATA_SYSTEM:
	case XML_CATA_DELEGATE:
	    fprintf(out, " \"%s\"", entry->value); break;
	default:
	    break;
    }
    fprintf(out, "\n");
}

/************************************************************************
 *									*
 *			The parser					*
 *									*
 ************************************************************************/


#define RAW *cur
#define NEXT cur++;
#define SKIP(x) cur += x;

#define SKIP_BLANKS while (IS_BLANK(*cur)) NEXT;

static const xmlChar *
xmlParseCatalogComment(const xmlChar *cur) {
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
xmlParseCatalogPubid(const xmlChar *cur, xmlChar **id) {
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
xmlParseCatalogName(const xmlChar *cur, xmlChar **name) {
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

static int
xmlParseCatalog(const xmlChar *value, const char *file) {
    const xmlChar *cur = value;
    xmlChar *base = NULL;
    int res;

    if ((cur == NULL) || (file == NULL))
        return(-1);
    base = xmlStrdup((const xmlChar *) file);

    while ((cur != NULL) && (cur[0] != '0')) {
	SKIP_BLANKS;
	if ((cur[0] == '-') && (cur[1] == '-')) {
	    cur = xmlParseCatalogComment(cur);
	    if (cur == NULL) {
		/* error */
		break;
	    }
	} else {
	    xmlChar *sysid = NULL;
	    xmlChar *name = NULL;
	    xmlCatalogEntryType type = XML_CATA_NONE;

	    cur = xmlParseCatalogName(cur, &name);
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
                type = XML_CATA_SYSTEM;
	    else if (xmlStrEqual(name, (const xmlChar *) "PUBLIC"))
                type = XML_CATA_PUBLIC;
	    else if (xmlStrEqual(name, (const xmlChar *) "DELEGATE"))
                type = XML_CATA_DELEGATE;
	    else if (xmlStrEqual(name, (const xmlChar *) "ENTITY"))
                type = XML_CATA_ENTITY;
	    else if (xmlStrEqual(name, (const xmlChar *) "DOCTYPE"))
                type = XML_CATA_DOCTYPE;
	    else if (xmlStrEqual(name, (const xmlChar *) "LINKTYPE"))
                type = XML_CATA_LINKTYPE;
	    else if (xmlStrEqual(name, (const xmlChar *) "NOTATION"))
                type = XML_CATA_NOTATION;
	    else if (xmlStrEqual(name, (const xmlChar *) "SGMLDECL"))
                type = XML_CATA_SGMLDECL;
	    else if (xmlStrEqual(name, (const xmlChar *) "DOCUMENT"))
                type = XML_CATA_DOCUMENT;
	    else if (xmlStrEqual(name, (const xmlChar *) "CATALOG"))
                type = XML_CATA_CATALOG;
	    else if (xmlStrEqual(name, (const xmlChar *) "BASE"))
                type = XML_CATA_BASE;
	    else if (xmlStrEqual(name, (const xmlChar *) "DELEGATE"))
                type = XML_CATA_DELEGATE;
	    else if (xmlStrEqual(name, (const xmlChar *) "OVERRIDE")) {
		xmlFree(name);
		cur = xmlParseCatalogName(cur, &name);
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
		case XML_CATA_ENTITY:
		    if (*cur == '%')
			type = XML_CATA_PENTITY;
		case XML_CATA_PENTITY:
		case XML_CATA_DOCTYPE:
		case XML_CATA_LINKTYPE:
		case XML_CATA_NOTATION:
		    cur = xmlParseCatalogName(cur, &name);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    if (!IS_BLANK(*cur)) {
			/* error */
			break;
		    }
		    SKIP_BLANKS;
		    cur = xmlParseCatalogPubid(cur, &sysid);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    break;
		case XML_CATA_PUBLIC:
		case XML_CATA_SYSTEM:
		case XML_CATA_DELEGATE:
		    cur = xmlParseCatalogPubid(cur, &name);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    if (!IS_BLANK(*cur)) {
			/* error */
			break;
		    }
		    SKIP_BLANKS;
		    cur = xmlParseCatalogPubid(cur, &sysid);
		    if (cur == NULL) {
			/* error */
			break;
		    }
		    break;
		case XML_CATA_BASE:
		case XML_CATA_CATALOG:
		case XML_CATA_DOCUMENT:
		case XML_CATA_SGMLDECL:
		    cur = xmlParseCatalogPubid(cur, &sysid);
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
	    } else if (type == XML_CATA_BASE) {
		if (base != NULL)
		    xmlFree(base);
		base = xmlStrdup(sysid);
	    } else if ((type == XML_CATA_PUBLIC) ||
		       (type == XML_CATA_SYSTEM)) {
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

	    } else if (type == XML_CATA_CATALOG) {
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

/************************************************************************
 *									*
 *			Public interfaces				*
 *									*
 ************************************************************************/

/*
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

    ret = xmlParseCatalog(content, filename);
    xmlFree(content);
    catalNr--;
    return(ret);
}

/*
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
    if (entry->type == XML_CATA_SYSTEM)
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
    xmlCatalogEntryPtr entry;

    if ((pubID == NULL) || (xmlDefaultCatalog == NULL))
	return(NULL);
    entry = (xmlCatalogEntryPtr) xmlHashLookup(xmlDefaultCatalog, pubID);
    if (entry == NULL)
	return(NULL);
    if (entry->type == XML_CATA_PUBLIC)
	return(entry->value);
    return(NULL);
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
    if (xmlDefaultCatalog != NULL) {
	xmlHashScan(xmlDefaultCatalog,
		    (xmlHashScanner) xmlCatalogDumpEntry, out);
    }
}
#endif /* LIBXML_CATALOG_ENABLED */
