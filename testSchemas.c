/*
 * testSchemas.c : a small tester program for Schema validation
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#include "libxml.h"
#ifdef LIBXML_SCHEMAS_ENABLED

#include <libxml/xmlversion.h>
#include <libxml/parser.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <libxml/xmlmemory.h>
#include <libxml/debugXML.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlschemastypes.h>

#ifdef LIBXML_DEBUG_ENABLED
static int debug = 0;
#endif
static int noout = 0;


int main(int argc, char **argv) {
    int i;
    int files = 0;
    xmlSchemaPtr schema = NULL;

    for (i = 1; i < argc ; i++) {
#ifdef LIBXML_DEBUG_ENABLED
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	else
#endif
	if ((!strcmp(argv[i], "-noout")) || (!strcmp(argv[i], "--noout"))) {
	    noout++;
        }
    }
    xmlLineNumbersDefault(1);
    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
	    if (schema == NULL) {
		xmlSchemaParserCtxtPtr ctxt;

		ctxt = xmlSchemaNewParserCtxt(argv[i]);
		xmlSchemaSetParserErrors(ctxt,
			(xmlSchemaValidityErrorFunc) fprintf,
			(xmlSchemaValidityWarningFunc) fprintf,
			stderr);
		schema = xmlSchemaParse(ctxt);
		xmlSchemaFreeParserCtxt(ctxt);
#ifdef LIBXML_DEBUG_ENABLED
		if (debug)
		    xmlSchemaDump(stdout, schema);
#endif
	    } else {
		xmlDocPtr doc;

		doc = xmlParseFile(argv[i]);

		if (doc == NULL) {
		    fprintf(stderr, "Could not parse %s\n", argv[i]);
		} else {
		    xmlSchemaValidCtxtPtr ctxt;
		    int ret;

		    ctxt = xmlSchemaNewValidCtxt(schema);
		    xmlSchemaSetValidErrors(ctxt,
			    (xmlSchemaValidityErrorFunc) fprintf,
			    (xmlSchemaValidityWarningFunc) fprintf,
			    stderr);
		    ret = xmlSchemaValidateDoc(ctxt, doc);
		    if (ret == 0) {
			printf("%s validates\n", argv[i]);
		    } else if (ret > 0) {
			printf("%s fails to validate\n", argv[i]);
		    } else {
			printf("%s validation generated an internal error\n",
			       argv[i]);
		    }
		    xmlSchemaFreeValidCtxt(ctxt);
		    xmlFreeDoc(doc);
		}
	    }
	    files ++;
	}
    }
    if (schema != NULL)
	xmlSchemaFree(schema);
    if (files == 0) {
	printf("Usage : %s [--debug] [--noout] schemas XMLfiles ...\n",
	       argv[0]);
	printf("\tParse the HTML files and output the result of the parsing\n");
#ifdef LIBXML_DEBUG_ENABLED
	printf("\t--debug : dump a debug tree of the in-memory document\n");
#endif
	printf("\t--noout : do not print the result\n");
    }
    xmlSchemaCleanupTypes();
    xmlCleanupParser();
    xmlMemoryDump();

    return(0);
}

#else
#include <stdio.h>
int main(int argc, char **argv) {
    printf("%s : Schemas support not compiled in\n", argv[0]);
    return(0);
}
#endif /* LIBXML_SCHEMAS_ENABLED */
