/*
 * valid.h : interface to the DTD handling and the validity checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */


#ifndef __XML_VALID_H__
#define __XML_VALID_H__
#include "tree.h"

/*
 * ALl element declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_ELEMENT_TABLE	32

typedef struct xmlElementTable {
    int nb_elements;		/* number of elements stored */
    int max_elements;		/* maximum number of elements */
    xmlElementPtr table;	/* the table of entities */
} xmlElementTable, *xmlElementTablePtr;

extern xmlElementPtr xmlAddElementDecl(xmlDtdPtr dtd, char *name, int type, 
                                       xmlElementContentPtr content);
extern xmlElementContentPtr xmlNewElementContent(CHAR *name, int type);
extern xmlElementContentPtr xmlCopyElementContent(xmlElementContentPtr content);
extern void xmlFreeElementContent(xmlElementContentPtr cur);

extern xmlElementTablePtr xmlCopyElementTable(xmlElementTablePtr table);
extern void xmlFreeElementTable(xmlElementTablePtr table);
extern void xmlDumpElementTable(xmlElementTablePtr table);
#endif /* __XML_VALID_H__ */
