/*
 * tester.c : a small tester program for XML input.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#define HAVE_FCNTL_H
#include <io.h>
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

#include "xmlmemory.h"
#include "parser.h"
#include "tree.h"
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

extern int xmlDoValidityCheckingDefaultValue;


void parseAndPrintFile(char *filename) {
    xmlDocPtr doc, tmp;

    /*
     * build an XML tree from a string;
     */
    if (recovery)
	doc = xmlRecoverFile(filename);
    else
	doc = xmlParseFile(filename);

    /*
     * test intermediate copy if needed.
     */
    if (copy) {
        tmp = doc;
	doc = xmlCopyDoc(doc, 1);
	xmlFreeDoc(tmp);
    }

    if (insert) {
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

    if (debugent)	
	xmlDebugDumpEntities(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

int main(int argc, char **argv) {
    int i, count;
    int files = 0;

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
	else if ((!strcmp(argv[i], "-compress")) ||
	         (!strcmp(argv[i], "--compress"))) {
	    compress++;
	    xmlSetCompressMode(9);
        }
    }
    if (noent != 0) xmlSubstituteEntitiesDefault(1);
    if (valid != 0) xmlDoValidityCheckingDefaultValue = 1;
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
	printf("Usage : %s [--debug] [--debugent] [--copy] [--recover] [--noent] [--noout] [--valid] [--repeat] XMLfiles ...\n",
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
    }
    xmlCleanupParser();
    xmlMemoryDump();

    return(0);
}
