/*
 * testURI.c : a small tester program for XML input.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <libxml/xmlversion.h>
#include <libxml/xmlmemory.h>
#include <libxml/uri.h>

int main(int argc, char **argv) {
    int i, ret, arg = 1;
    xmlURIPtr uri;
    const char *base = NULL;
    xmlChar *composite;

    if (argv[arg] == NULL) {
	printf("Usage: %s [-base URI] URI ...\n", argv[0]);
	exit(0);
    }
    if ((!strcmp(argv[arg], "-base")) || (!strcmp(argv[arg], "--base"))) {
	arg++;
	base = argv[arg];
	if (base != NULL)
	    arg++;
    }
    uri = xmlCreateURI();
    if (argv[arg] == NULL) {
	char str[1024];

        while (1) {
	    /*
	     * read one line in string buffer.
	     */
	    if (fgets (&str[0], sizeof (str) - 1, stdin) == NULL)
	       break;

	    /*
	     * remove the ending spaces
	     */
	    i = strlen(str);
	    while ((i > 0) &&
		   ((str[i - 1] == '\n') || (str[i - 1] == '\r') ||
		    (str[i - 1] == ' ') || (str[i - 1] == '\t'))) {
		i--;
		str[i] = 0;
	    }

	    if (base == NULL) {
		ret = xmlParseURIReference(uri, str);
		if (ret != 0)
		    printf("%s : error %d\n", str, ret);
		else {
		    xmlPrintURI(stdout, uri);
		    printf("\n");
		}
	    } else {
		composite = xmlBuildURI((xmlChar *)str, (xmlChar *) base);
		if (composite != NULL) {
		    printf("%s\n", composite);
		    xmlFree(composite);
		}
		else
		    printf("::ERROR::\n");
	    }
        }
    } else {
	while (argv[arg] != NULL) {
	    if (base == NULL) {
		ret = xmlParseURIReference(uri, argv[arg]);
		if (ret != 0)
		    printf("%s : error %d\n", argv[arg], ret);
		else {
		    xmlPrintURI(stdout, uri);
		    printf("\n");
		}
	    } else {
		composite = xmlBuildURI((xmlChar *)argv[arg], (xmlChar *) base);
		if (composite != NULL) {
		    printf("%s\n", composite);
		    xmlFree(composite);
		}
	    }
	    arg++;
	}
    }
    xmlFreeURI(uri);
    xmlMemoryDump();
    exit(0);
}
