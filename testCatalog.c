/*
 * testCatalog.c : a small tester program for Catalog loading
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#include "libxml.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <libxml/xmlversion.h>
#include <libxml/xmlmemory.h>
#include <libxml/uri.h>
#include <libxml/catalog.h>

int main(int argc, char **argv) {
#ifdef LIBXML_CATALOG_ENABLED
    int i;

    for (i = 1; i < argc; i++)
	xmlLoadCatalog(argv[i]);

    xmlCatalogDump(stdout);
    xmlCatalogCleanup();
    xmlCleanupParser();
    xmlMemoryDump();
#endif
    return(0);
}
