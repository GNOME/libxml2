/*
 * testHTML.c : a small tester program for HTML input.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#define HAVE_FCNTL_H
#include <io.h>
#else
#include <config.h>
#endif
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "HTMLparser.h"
#include "HTMLtree.h"
#include "debugXML.h"

static int debug = 0;
static int copy = 0;

/*
 * Note: this is perfectly clean HTML, i.e. not a useful test.
 */
static CHAR buffer[] = 
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"\n\
                      \"http://www.w3.org/TR/REC-html40/loose.dtd\">\n\
<html>\n\
<head>\n\
  <title>This service is temporary down</title>\n\
</head>\n\
\n\
<body bgcolor=\"#FFFFFF\">\n\
<h1 align=\"center\">Sorry, this service is temporary down</h1>\n\
We are doing our best to get it back on-line,\n\
\n\
<p>The W3C system administrators</p>\n\
</body>\n\
</html>\n\
";

/************************************************************************
 *									*
 *				Debug					*
 *									*
 ************************************************************************/

void parseAndPrintFile(char *filename) {
    htmlDocPtr doc, tmp;

    /*
     * build an HTML tree from a string;
     */
    doc = htmlParseFile(filename, NULL);

    /*
     * test intermediate copy if needed.
     */
    if (copy) {
        tmp = doc;
	doc = xmlCopyDoc(doc, 1);
	xmlFreeDoc(tmp);
    }

    /*
     * print it.
     */
    if (!debug)
	htmlDocDump(stdout, doc);
    else
        xmlDebugDumpDocument(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

void parseAndPrintBuffer(CHAR *buf) {
    htmlDocPtr doc, tmp;

    /*
     * build an HTML tree from a string;
     */
    doc = htmlParseDoc(buf, NULL);

    /*
     * test intermediate copy if needed.
     */
    if (copy) {
        tmp = doc;
	doc = xmlCopyDoc(doc, 1);
	xmlFreeDoc(tmp);
    }

    /*
     * print it.
     */
    if (!debug)
	htmlDocDump(stdout, doc);
    else
        xmlDebugDumpDocument(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

int main(int argc, char **argv) {
    int i;
    int files = 0;

    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	else if ((!strcmp(argv[i], "-copy")) || (!strcmp(argv[i], "--copy")))
	    copy++;
    }
    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
	    parseAndPrintFile(argv[i]);
	    files ++;
	}
    }
    if (files == 0) {
	printf("Usage : %s [--debug] [--copy] HTMLfiles ...\n",
	       argv[0]);
	printf("\tParse the HTML files and output the result of the parsing\n");
	printf("\t--debug : dump a debug tree of the in-memory document\n");
	printf("\t--copy : used to test the internal copy implementation\n");
    }

    return(0);
}
