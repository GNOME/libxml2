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

#include "parser.h"
#include "tree.h"
#include "debugXML.h"

static int debug = 0;
static int copy = 0;
static int recovery = 0;
static int noent = 0;
static int noout = 0;

/*
 * Note: there is a couple of errors introduced on purpose.
static CHAR buffer[] = 
"<?xml version=\"1.0\"?>\n\
<?xml:namespace ns = \"http://www.ietf.org/standards/dav/\" prefix = \"D\"?>\n\
<?xml:namespace ns = \"http://www.w3.com/standards/z39.50/\" prefix = \"Z\"?>\n\
<D:propertyupdate>\n\
<D:set a=\"'toto'\" b>\n\
       <D:prop>\n\
            <Z:authors>\n\
                 <Z:Author>Jim Whitehead</Z:Author>\n\
                 <Z:Author>Roy Fielding</Z:Author>\n\
            </Z:authors>\n\
       </D:prop>\n\
  </D:set>\n\
  <D:remove>\n\
       <D:prop><Z:Copyright-Owner/></D:prop>\n\
  </D:remove>\n\
</D:propertyupdate>\n\
\n\
";
 */

/************************************************************************
 *									*
 *				Debug					*
 *									*
 ************************************************************************/

int treeTest(void) {
    xmlDocPtr doc, tmp;
    xmlNodePtr tree, subtree;

    /*
     * build a fake XML document
     */
    doc = xmlNewDoc("1.0");
    doc->root = xmlNewDocNode(doc, NULL, "EXAMPLE", NULL);
    xmlSetProp(doc->root, "prop1", "gnome is great");
    xmlSetProp(doc->root, "prop2", "&linux; too");
    xmlSetProp(doc->root, "emptyprop", "");
    tree = xmlNewChild(doc->root, NULL, "head", NULL);
    subtree = xmlNewChild(tree, NULL, "title", "Welcome to Gnome");
    tree = xmlNewChild(doc->root, NULL, "chapter", NULL);
    subtree = xmlNewChild(tree, NULL, "title", "The Linux adventure");
    subtree = xmlNewChild(tree, NULL, "p", "bla bla bla ...");
    subtree = xmlNewChild(tree, NULL, "image", NULL);
    xmlSetProp(subtree, "href", "linus.gif");

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
    if (noout == 0)
	xmlDocDump(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
    return(0);
}

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

    /*
     * print it.
     */
    if (noout == 0) {
	if (!debug)
	    xmlDocDump(stdout, doc);
	else
	    xmlDebugDumpDocument(stdout, doc);
    }

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

void parseAndPrintBuffer(CHAR *buf) {
    xmlDocPtr doc, tmp;

    /*
     * build an XML tree from a string;
     */
    if (recovery)
	doc = xmlRecoverDoc(buf);
    else
	doc = xmlParseDoc(buf);

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
	xmlDocDump(stdout, doc);
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
	else if ((!strcmp(argv[i], "-recover")) ||
	         (!strcmp(argv[i], "--recover")))
	    recovery++;
	else if ((!strcmp(argv[i], "-noent")) ||
	         (!strcmp(argv[i], "--noent")))
	    noent++;
	else if ((!strcmp(argv[i], "-noout")) ||
	         (!strcmp(argv[i], "--noout")))
	    noout++;
    }
    if (noent != 0) xmlSubstituteEntitiesDefault(1);
    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
	    parseAndPrintFile(argv[i]);
	    files ++;
	}
    }
    if (files == 0) {
	printf("Usage : %s [--debug] [--copy] [--recover] [--noent] [--noout] XMLfiles ...\n",
	       argv[0]);
	printf("\tParse the XML files and output the result of the parsing\n");
	printf("\t--debug : dump a debug tree of the in-memory document\n");
	printf("\t--copy : used to test the internal copy implementation\n");
	printf("\t--recover : output what is parsable on broken XmL documents\n");
	printf("\t--noent : substitute entity references by their value\n");
	printf("\t--noout : don't output the result\n");
    }

    return(0);
}
