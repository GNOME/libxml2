/**
 * section: InputOutput
 * synopsis: Output to char buffer
 * purpose: Demonstrate the use of xmlDocDumpMemory
 *          to output document to a character buffer
 * usage: io2
 * test: io2 > io2.tmp ; diff io2.tmp io2.res ; rm -f io2.tmp
 * author: John Fleck
 * copy: see Copyright for the status of this software.
 */

#include <libxml/parser.h>

int
main(void) {

	xmlNodePtr n;
	xmlDocPtr doc;
	xmlChar *xmlbuff;
	int buffersize;

	/*
	 * Create the document.
	 */
	doc = xmlNewDoc(BAD_CAST "1.0");
	n = xmlNewNode(NULL, BAD_CAST "root");
	xmlNodeSetContent(n, BAD_CAST "content");
	xmlDocSetRootElement(doc,n);

	/*
	 * Dump the document to a buffer and print it
	 * for demonstration purposes.
	 */
	xmlDocDumpFormatMemory (doc, &xmlbuff, &buffersize, 1);
	printf ((char *)xmlbuff);

	/*
	 * Free associated memory.
	 */
     	xmlFree (xmlbuff);
	xmlFreeDoc(doc);

	return(0);

}
