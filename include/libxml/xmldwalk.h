/*
 * xmldwalk.h : Interfaces, constants and types of the document traversing API.for XML
 *
 * this is heavily based upon the xmlTextReader streaming node API
 * of libxml2 by Daniel Veillard (daniel@veillard.com). In fact I
 * just copied and modified xmlreader.h
 *
 * So for license and disclaimer see the license and disclaimer of
 * libxml2.
 *
 * alfred@mickautsch.de
 */

#ifndef __XML_XMLDWALK_H__
#define __XML_XMLDWALK_H__

#include <libxml/xmlversion.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    XML_DWALK_NONE = 0,
    XML_DWALK_START,
    XML_DWALK_BACKTRACK,
    XML_DWALK_END
} xmlDocWalkerState;

typedef struct _xmlDocWalker xmlDocWalker;
typedef xmlDocWalker *xmlDocWalkerPtr;

/*
 * Constructor & Destructor
 */
XMLPUBFUN xmlDocWalkerPtr XMLCALL
		xmlNewDocWalker			(xmlDocPtr doc);
XMLPUBFUN void XMLCALL
		xmlFreeDocWalker		(xmlDocWalkerPtr iter);

/*
 * Iterator Functions
 */
XMLPUBFUN int XMLCALL
		xmlDocWalkerRewind		(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerStep		(xmlDocWalkerPtr iter);

XMLPUBFUN int XMLCALL
		xmlDocWalkerAttributeCount	(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerDepth		(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerHasAttributes	(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerHasValue		(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerIsEmptyElement	(xmlDocWalkerPtr iter);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerLocalName		(xmlDocWalkerPtr iter);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerName		(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerNodeType		(xmlDocWalkerPtr iter);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerPrefix		(xmlDocWalkerPtr iter);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerNamespaceUri	(xmlDocWalkerPtr iter);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerBaseUri		(xmlDocWalkerPtr iter);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerValue		(xmlDocWalkerPtr iter);

XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerGetAttributeNo	(xmlDocWalkerPtr iter,
						 int no);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerGetAttribute	(xmlDocWalkerPtr iter,
						 const xmlChar *name);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerGetAttributeNs	(xmlDocWalkerPtr iter,
						 const xmlChar *localName,
						 				 const xmlChar *namespaceURI);
XMLPUBFUN xmlChar * XMLCALL
		xmlDocWalkerLookupNamespace	(xmlDocWalkerPtr iter,
						 const xmlChar *prefix);
XMLPUBFUN int XMLCALL
		xmlDocWalkerMoveToAttributeNo	(xmlDocWalkerPtr iter,
						 int no);
XMLPUBFUN int XMLCALL
		xmlDocWalkerMoveToAttribute	(xmlDocWalkerPtr iter,
						 const xmlChar *name);
XMLPUBFUN int XMLCALL
		xmlDocWalkerMoveToAttributeNs	(xmlDocWalkerPtr iter,
						 const xmlChar *localName,
						 const xmlChar *namespaceURI);
XMLPUBFUN int XMLCALL
		xmlDocWalkerMoveToFirstAttribute(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerMoveToNextAttribute	(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerMoveToElement	(xmlDocWalkerPtr iter);

xmlNodePtr
		xmlDocWalkerCurrentNode		(xmlDocWalkerPtr iter);
xmlDocPtr
		xmlDocWalkerCurrentDoc		(xmlDocWalkerPtr iter);
XMLPUBFUN int XMLCALL
		xmlDocWalkerNext		(xmlDocWalkerPtr iter);

#ifdef __cplusplus
}
#endif

#endif /* __XML_XMLDWALK_H__ */
