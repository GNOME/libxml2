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
 * ALl notation declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_NOTATION_TABLE	32

typedef struct xmlNotationTable {
    int nb_notations;		/* number of notations stored */
    int max_notations;		/* maximum number of notations */
    xmlNotationPtr table;	/* the table of attributes */
} xmlNotationTable;
typedef xmlNotationTable *xmlNotationTablePtr;

/*
 * ALl element declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_ELEMENT_TABLE	32

typedef struct xmlElementTable {
    int nb_elements;		/* number of elements stored */
    int max_elements;		/* maximum number of elements */
    xmlElementPtr table;	/* the table of elements */
} xmlElementTable;
typedef xmlElementTable *xmlElementTablePtr;

/*
 * ALl attribute declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_ATTRIBUTE_TABLE	32

typedef struct xmlAttributeTable {
    int nb_attributes;		/* number of attributes stored */
    int max_attributes;		/* maximum number of attributes */
    xmlAttributePtr table;	/* the table of attributes */
} xmlAttributeTable;
typedef xmlAttributeTable *xmlAttributeTablePtr;

/* Notation */
xmlNotationPtr xmlAddNotationDecl(xmlDtdPtr dtd, CHAR *name,
	       CHAR *PublicID, CHAR *SystemID);
xmlNotationTablePtr xmlCopyNotationTable(xmlNotationTablePtr table);
void xmlFreeNotationTable(xmlNotationTablePtr table);
void xmlDumpNotationTable(xmlNotationTablePtr table);

/* Element Content */
xmlElementContentPtr xmlNewElementContent(CHAR *name, int type);
xmlElementContentPtr xmlCopyElementContent(xmlElementContentPtr content);
void xmlFreeElementContent(xmlElementContentPtr cur);

/* Element */
xmlElementPtr xmlAddElementDecl(xmlDtdPtr dtd, CHAR *name, int type, 
                                       xmlElementContentPtr content);
xmlElementTablePtr xmlCopyElementTable(xmlElementTablePtr table);
void xmlFreeElementTable(xmlElementTablePtr table);
void xmlDumpElementTable(xmlElementTablePtr table);

/* Enumeration */
xmlEnumerationPtr xmlCreateEnumeration(CHAR *name);
void xmlFreeEnumeration(xmlEnumerationPtr cur);
xmlEnumerationPtr xmlCopyEnumeration(xmlEnumerationPtr cur);

/* Attribute */
xmlAttributePtr xmlAddAttributeDecl(xmlDtdPtr dtd, CHAR *elem,
	       CHAR *name, int type, int def,
	       CHAR *defaultValue, xmlEnumerationPtr tree);
xmlAttributeTablePtr xmlCopyAttributeTable(xmlAttributeTablePtr table);
void xmlFreeAttributeTable(xmlAttributeTablePtr table);
void xmlDumpAttributeTable(xmlAttributeTablePtr table);

#endif /* __XML_VALID_H__ */
