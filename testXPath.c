/*
 * testXPath.c : a small tester program for XPath.
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


#include "xpath.h"
#include "tree.h"
#include "parser.h"
#include "debugXML.h"
#include "xmlmemory.h"

static int debug = 0;
static int expr = 0;
static xmlDocPtr document = NULL;

/*
 * Default document
 */
static xmlChar buffer[] = 
"<?xml version=\"1.0\"?>\n\
<EXAMPLE prop1=\"gnome is great\" prop2=\"&amp; linux too\">\n\
  <head>\n\
   <title>Welcome to Gnome</title>\n\
  </head>\n\
  <chapter>\n\
   <title>The Linux adventure</title>\n\
   <p>bla bla bla ...</p>\n\
   <image href=\"linus.gif\"/>\n\
   <p>...</p>\n\
  </chapter>\n\
  <chapter>\n\
   <title>Chapter 2</title>\n\
   <p>this is chapter 2 ...</p>\n\
  </chapter>\n\
  <chapter>\n\
   <title>Chapter 3</title>\n\
   <p>this is chapter 3 ...</p>\n\
  </chapter>\n\
  <chapter>\n\
   <title>Chapter 4</title>\n\
   <p>this is chapter 4 ...</p>\n\
  </chapter>\n\
  <chapter>\n\
   <title>Chapter 5</title>\n\
   <p>this is chapter 5 ...</p>\n\
  </chapter>\n\
</EXAMPLE>\n\
";

void xmlXPAthDebugDumpNodeSet(FILE *output, xmlNodeSetPtr cur) {
    int i;

    if (cur == NULL) {
	fprintf(output, "NodeSet is NULL !\n");
	return;
        
    }

    fprintf(output, "Set contains %d nodes:\n", cur->nodeNr);
    for (i = 0;i < cur->nodeNr;i++) {
        fprintf(output, "%d", i + 1);
	if (cur->nodeTab[i] == NULL)
	    fprintf(output, " NULL\n");
	else if ((cur->nodeTab[i]->type == XML_DOCUMENT_NODE) ||
	         (cur->nodeTab[i]->type == XML_HTML_DOCUMENT_NODE))
	    fprintf(output, " /\n");
	else if (cur->nodeTab[i]->type == XML_ATTRIBUTE_NODE)
	    xmlDebugDumpAttr(output, (xmlAttrPtr)cur->nodeTab[i], 2);
	else
	    xmlDebugDumpOneNode(output, cur->nodeTab[i], 2);
    }
}

void xmlXPAthDebugDumpObject(FILE *output, xmlXPathObjectPtr cur) {
    if (cur == NULL) {
        fprintf(output, "Object is empty (NULL)\n");
	return;
    }
    switch(cur->type) {
        case XPATH_UNDEFINED:
	    fprintf(output, "Object is uninitialized\n");
	    break;
        case XPATH_NODESET:
	    fprintf(output, "Object is a Node Set :\n");
	    xmlXPAthDebugDumpNodeSet(output, cur->nodesetval);
	    break;
        case XPATH_BOOLEAN:
	    fprintf(output, "Object is a Boolean : ");
	    if (cur->boolval) fprintf(output, "true\n");
	    else fprintf(output, "false\n");
	    break;
        case XPATH_NUMBER:
	    fprintf(output, "Object is a number : %0g\n", cur->floatval);
	    break;
        case XPATH_STRING:
	    fprintf(output, "Object is a string : ");
	    xmlDebugDumpString(output, cur->stringval);
	    fprintf(output, "\n");
	    break;
    }
}

void testXPath(const char *str) {
    xmlXPathObjectPtr res;
    xmlXPathContextPtr ctxt;
    
    ctxt = xmlXPathNewContext(document);
    if (expr)
	res = xmlXPathEvalExpression(BAD_CAST str, ctxt);
    else
	res = xmlXPathEval(BAD_CAST str, ctxt);
    xmlXPAthDebugDumpObject(stdout, res);
    xmlXPathFreeObject(res);
    xmlXPathFreeContext(ctxt);
}

void testXPathFile(const char *filename) {
    FILE *input;
    char expr[5000];

    input = fopen(filename, "r");
    if (input == NULL) {
        fprintf(stderr, "Cannot open %s for reading\n", filename);
	return;
    }
    while (fscanf(input, "%s", expr) != EOF) {
        testXPath(expr);
    }

    fclose(input);
}

int main(int argc, char **argv) {
    int i;
    int strings = 0;
    int usefile = 0;
    char *filename = NULL;

    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	if ((!strcmp(argv[i], "-expr")) || (!strcmp(argv[i], "--expr")))
	    expr++;
	if ((!strcmp(argv[i], "-i")) || (!strcmp(argv[i], "--input")))
	    filename = argv[++i];
	if ((!strcmp(argv[i], "-f")) || (!strcmp(argv[i], "--file")))
	    usefile++;
    }
    if (document == NULL) {
        if (filename == NULL)
	    document = xmlParseDoc(buffer);
	else
	    document = xmlParseFile(filename);
    }
    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-i")) || (!strcmp(argv[i], "--input"))) {
	    i++; continue;
	}
	if (argv[i][0] != '-') {
	    if (usefile)
	        testXPathFile(argv[i]);
	    else
		testXPath(argv[i]);
	    strings ++;
	}
    }
    if (strings == 0) {
	printf("Usage : %s [--debug] [--copy] stringsorfiles ...\n",
	       argv[0]);
	printf("\tParse the XPath strings and output the result of the parsing\n");
	printf("\t--debug : dump a debug version of the result\n");
	printf("\t--expr : debug XPath expressions only\n");
	printf("\t--input filename : or\n");
	printf("\t-i filename      : read the document from filename\n");
	printf("\t--file : or\n");
	printf("\t-f     : read queries from files, args\n");
    }
    if (document != NULL) 
	xmlFreeDoc(document);
    xmlCleanupParser();
    xmlMemoryDump();

    return(0);
}
