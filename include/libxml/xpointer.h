/*
 * xpointer.h : API to handle XML Pointers
 *
 * World Wide Web Consortium Working Draft 03-March-1998 
 * http://www.w3.org/TR/1998/WD-xptr-19980303
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_XPTR_H__
#define __XML_XPTR_H__

#include <libxml/tree.h>
#include <libxml/xpath.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A Location Set
 */
typedef struct _xmlLocationSet xmlLocationSet;
typedef xmlLocationSet *xmlLocationSetPtr;
struct _xmlLocationSet {
    int locNr;		      /* number of locations in the set */
    int locMax;		      /* size of the array as allocated */
    xmlXPathObjectPtr *locTab;/* array of locations */
};

/*
 * Handling of location sets
 */

void			xmlXPtrFreeLocationSet	(xmlLocationSetPtr obj);
xmlLocationSetPtr	xmlXPtrLocationSetMerge	(xmlLocationSetPtr val1,
						 xmlLocationSetPtr val2);

/*
 * Functions
 */
xmlXPathContextPtr	xmlXPtrNewContext	(xmlDocPtr doc,
						 xmlNodePtr here,
						 xmlNodePtr origin);
xmlXPathObjectPtr	xmlXPtrEval		(const xmlChar *str,
						 xmlXPathContextPtr ctx);
void			xmlXPtrRangeToFunction	(xmlXPathParserContextPtr ctxt,
       						 int nargs);

#ifdef __cplusplus
}
#endif
#endif /* __XML_XPTR_H__ */
