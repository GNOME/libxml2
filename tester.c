/*
 * tester.c : a small tester program for XML input.
 *
 * See Copyright for the status of this software.
 *
 * $Id$
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

/*
 * Note: there is a couple of errors introduced on purpose.
 */
static CHAR buffer[] = 
"\n\
<?xml version=\"1.0\">\n\
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


void parseAndPrintFile(char *filename) {
    xmlDocPtr doc;

    /*
     * build an XML tree from a string;
     */
    doc = xmlParseFile(filename);

    /*
     * print it.
     */
    xmlDocDump(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

void parseAndPrintBuffer(CHAR *buf) {
    xmlDocPtr doc;

    /*
     * build an XML tree from a string;
     */
    doc = xmlParseDoc(buf);

    /*
     * print it.
     */
    xmlDocDump(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
}

int main(int argc, char **argv) {
    int i;

    if (argc > 1) {
        for (i = 1; i < argc ; i++) {
	    parseAndPrintFile(argv[i]);
	}
    } else
        parseAndPrintBuffer(buffer);

    return(0);
}
