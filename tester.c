/*
 * tester.c : a small tester program for XML input.
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "xml_parser.h"
#include "xml_tree.h"

#define MAX_BUF	500000

static CHAR buffer[MAX_BUF] = 
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

int readFile(char *filename) {
    int input;
    int res;

    memset(buffer, 0, sizeof(buffer));
    input = open (filename, O_RDONLY);
    if (input < 0) {
        fprintf (stderr, "Cannot read file %s :\n", filename);
	perror ("open failed");
	return(-1);
    }
    res = read(input, buffer, sizeof(buffer));
    if (res < 0) {
        fprintf (stderr, "Cannot read file %s :\n", filename);
	perror ("read failed");
	return(-1);
    }
    if (res >= MAX_BUF) {
        fprintf (stderr, "Read only %d byte of %s, increase MAX_BUF\n",
	         res, filename);
        return(-1);
    }
    close(input);
    return(res);
}

void parseAndPrint(CHAR *buf) {
    xmlDocPtr doc;

    /*
     * build a fake XML document from a string;
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
	    if (readFile(argv[i]) >= 0) {
	        printf("\n\n------- %s -----------\n", argv[i]);
	        parseAndPrint(buffer);
	    }
	}
    } else
        parseAndPrint(buffer);

    return(0);
}
