/*
 * tester.c : a small tester program for XML input.
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
#ifdef HAVE_LIBREADLINE
#include <readline/readline.h>
#ifdef HAVE_LIBHISTORY
#include <readline/history.h>
#endif
#endif

#include "xmlmemory.h"
#include "parser.h"
#include "HTMLparser.h"
#include "HTMLtree.h"
#include "tree.h"
#include "xpath.h"
#include "debugXML.h"

static int debug = 0;
static int debugent = 0;
static int copy = 0;
static int recovery = 0;
static int noent = 0;
static int noout = 0;
static int valid = 0;
static int postvalid = 0;
static int repeat = 0;
static int insert = 0;
static int compress = 0;
static int html = 0;
static int shell = 0;
static int push = 0;
static int blanks = 0;
static int oldparser = 0;

extern int xmlDoValidityCheckingDefaultValue;

/**
 * xmlShellReadline:
 * @prompt:  the prompt value
 *
 * Read a string
 * 
 * Returns a pointer to it or NULL on EOF the caller is expected to
 *     free the returned string.
 */
char *
xmlShellReadline(char *prompt) {
#ifdef HAVE_LIBREADLINE
    char *line_read;

    /* Get a line from the user. */
    line_read = readline (prompt);

    /* If the line has any text in it, save it on the history. */
    if (line_read && *line_read)
	add_history (line_read);

    return (line_read);
#else
    char line_read[501];

    if (prompt != NULL)
	fprintf(stdout, "%s", prompt);
    if (!fgets(line_read, 500, stdin))
        return(NULL);
    line_read[500] = 0;
    return(strdup(line_read));
#endif
}

void parseAndPrintFile(char *filename) {
    xmlDocPtr doc = NULL, tmp;

    if (html) {
	doc = htmlParseFile(filename, NULL);
    } else {
	/*
	 * build an XML tree from a string;
	 */
	if (push) {
	    FILE *f;

	    f = fopen(filename, "r");
	    if (f != NULL) {
	        int res, size = 3;
	        char chars[1024];
                xmlParserCtxtPtr ctxt;

		if (repeat)
		    size = 1024;
		res = fread(chars, 1, 4, f);
		if (res > 0) {
		    ctxt = xmlCreatePushParserCtxt(NULL, NULL,
		                chars, res, filename);
		    while ((res = fread(chars, 1, size, f)) > 0) {
			xmlParseChunk(ctxt, chars, res, 0);
		    }
		    xmlParseChunk(ctxt, chars, 0, 1);
		    doc = ctxt->myDoc;
		    xmlFreeParserCtxt(ctxt);
	        }
	    }
	} else if (recovery)
	    doc = xmlRecoverFile(filename);
	else
	    doc = xmlParseFile(filename);
    }

    /*
     * shell interraction
     */
    if (shell)  
        xmlShell(doc, filename, xmlShellReadline, stdout);

    /*
     * test intermediate copy if needed.
     */
    if (copy) {
        tmp = doc;
	doc = xmlCopyDoc(doc, 1);
	xmlFreeDoc(tmp);
    }

    if ((insert) && (!html)) {
        const xmlChar* list[256];
	int nb, i;
	xmlNodePtr node;

	if (doc->root != NULL) {
	    node = doc->root;
	    while ((node != NULL) && (node->last == NULL)) node = node->next;
	    if (node != NULL) {
		nb = xmlValidGetValidElements(node->last, NULL, list, 256);
		if (nb < 0) {
		    printf("could not get valid list of elements\n");
		} else if (nb == 0) {
		    printf("No element can be indersted under root\n");
		} else {
		    printf("%d element types can be indersted under root:\n",
		           nb);
		    for (i = 0;i < nb;i++) {
			 printf("%s\n", list[i]);
		    }
		}
	    }
	}    
    }else if (noout == 0) {
	/*
	 * print it.
	 */
	if (!debug) {
	    if (compress)
		xmlSaveFile("-", doc);
	    else
		xmlDocDump(stdout, doc);
	} else
	    xmlDebugDumpDocument(stdout, doc);
    }

    /*
     * A posteriori validation test
     */
    if (postvalid) {
	xmlValidCtxt cvp;
	cvp.userData = (void *) stderr;                                                 cvp.error    = (xmlValidityErrorFunc) fprintf;                                  cvp.warning  = (xmlValidityWarningFunc) fprintf;
	xmlValidateDocument(&cvp, doc);
    }

    if ((debugent) && (!html))
	xmlDebugDumpEntities(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

int main(int argc, char **argv) {
    int i, count;
    int files = 0;

    LIBXML_TEST_VERSION
    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	if ((!strcmp(argv[i], "-debugent")) || (!strcmp(argv[i], "--debugent")))
	    debugent++;
	else if ((!strcmp(argv[i], "-copy")) || (!strcmp(argv[i], "--copy")))
	    copy++;
	else if ((!strcmp(argv[i], "-recover")) ||
	         (!strcmp(argv[i], "--recover")))
	    recovery++;
	else if ((!strcmp(argv[i], "-noent")) ||
	         (!strcmp(argv[i], "--noent")))
	    noent++;
	else if ((!strcmp(argv[i], "-noout")) ||
	         (!strcmp(argv[i], "--noout")))
	    noout++;
	else if ((!strcmp(argv[i], "-valid")) ||
	         (!strcmp(argv[i], "--valid")))
	    valid++;
	else if ((!strcmp(argv[i], "-postvalid")) ||
	         (!strcmp(argv[i], "--postvalid")))
	    postvalid++;
	else if ((!strcmp(argv[i], "-insert")) ||
	         (!strcmp(argv[i], "--insert")))
	    insert++;
	else if ((!strcmp(argv[i], "-repeat")) ||
	         (!strcmp(argv[i], "--repeat")))
	    repeat++;
	else if ((!strcmp(argv[i], "-push")) ||
	         (!strcmp(argv[i], "--push")))
	    push++;
	else if ((!strcmp(argv[i], "-compress")) ||
	         (!strcmp(argv[i], "--compress"))) {
	    compress++;
	    xmlSetCompressMode(9);
        }
	else if ((!strcmp(argv[i], "-blanks")) ||
	         (!strcmp(argv[i], "--blanks"))) {
	    blanks++;
	    xmlKeepBlanksDefault(1);
        }
	else if ((!strcmp(argv[i], "-html")) ||
	         (!strcmp(argv[i], "--html"))) {
	    html++;
        }
	else if ((!strcmp(argv[i], "-oldparser")) ||
	         (!strcmp(argv[i], "--oldparser"))) {
	    oldparser++;
        }
	else if ((!strcmp(argv[i], "-shell")) ||
	         (!strcmp(argv[i], "--shell"))) {
	    shell++;
            noout = 1;
        }
    }
    if (noent != 0) xmlSubstituteEntitiesDefault(1);
    if (valid != 0) xmlDoValidityCheckingDefaultValue = 1;

    xmlInitParser();
    if ((!oldparser) && (!getenv("LIBXML_USE_OLD_PARSER")))
	xmlUseNewParser(1);

    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
	    if (repeat) {
		for (count = 0;count < 100 * repeat;count++)
		    parseAndPrintFile(argv[i]);
	    } else
		parseAndPrintFile(argv[i]);
	    files ++;
	}
    }
    if (files == 0) {
	printf("Usage : %s [--debug] [--shell] [--debugent] [--copy] [--recover] [--noent] [--noout] [--valid] [--repeat] XMLfiles ...\n",
	       argv[0]);
	printf("\tParse the XML files and output the result of the parsing\n");
	printf("\t--debug : dump a debug tree of the in-memory document\n");
	printf("\t--debugent : debug the entities defined in the document\n");
	printf("\t--copy : used to test the internal copy implementation\n");
	printf("\t--recover : output what was parsable on broken XML documents\n");
	printf("\t--noent : substitute entity references by their value\n");
	printf("\t--noout : don't output the result tree\n");
	printf("\t--valid : validate the document in addition to std well-formed check\n");
	printf("\t--postvalid : do a posteriori validation, i.e after parsing\n");
	printf("\t--repeat : repeat 100 times, for timing or profiling\n");
	printf("\t--insert : ad-hoc test for valid insertions\n");
	printf("\t--compress : turn on gzip compression of output\n");
	printf("\t--html : use the HTML parser\n");
	printf("\t--shell : run a navigating shell\n");
	printf("\t--blanks : keep blank text node\n");
	printf("\t--push : use the push mode of the parser\n");
	printf("\t--oldparser : use the old 1.8.11 parser\n");
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(0);
}
