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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * an xmlValidCtxt is used for error reporting when validating
 */

typedef void (*xmlValidityErrorFunc) (void *ctx, const char *msg, ...);
typedef void (*xmlValidityWarningFunc) (void *ctx, const char *msg, ...);

typedef struct _xmlValidCtxt xmlValidCtxt;
typedef xmlValidCtxt *xmlValidCtxtPtr;
struct _xmlValidCtxt {
    void *userData;			/* user specific data block */
    xmlValidityErrorFunc error;		/* the callback in case of errors */
    xmlValidityWarningFunc warning;	/* the callback in case of warning */
};

/*
 * ALl notation declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_NOTATION_TABLE	32

typedef struct _xmlNotationTable xmlNotationTable;
typedef xmlNotationTable *xmlNotationTablePtr;
struct _xmlNotationTable {
    int nb_notations;		/* number of notations stored */
    int max_notations;		/* maximum number of notations */
    xmlNotationPtr *table;	/* the table of attributes */
};

/*
 * ALl element declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_ELEMENT_TABLE	32

typedef struct _xmlElementTable xmlElementTable;
typedef xmlElementTable *xmlElementTablePtr;
struct _xmlElementTable {
    int nb_elements;		/* number of elements stored */
    int max_elements;		/* maximum number of elements */
    xmlElementPtr *table;	/* the table of elements */
};

/*
 * ALl attribute declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_ATTRIBUTE_TABLE	32

typedef struct _xmlAttributeTable xmlAttributeTable;
typedef xmlAttributeTable *xmlAttributeTablePtr;
struct _xmlAttributeTable {
    int nb_attributes;		/* number of attributes stored */
    int max_attributes;		/* maximum number of attributes */
    xmlAttributePtr *table;	/* the table of attributes */
};

/*
 * ALl IDs attributes are stored in a table
 * there is one table per document
 */

#define XML_MIN_ID_TABLE	32

typedef struct _xmlIDTable xmlIDTable;
typedef xmlIDTable *xmlIDTablePtr;
struct _xmlIDTable {
    int nb_ids;			/* number of ids stored */
    int max_ids;		/* maximum number of ids */
    xmlIDPtr *table;		/* the table of ids */
};

/*
 * ALl Refs attributes are stored in a table
 * there is one table per document
 */

#define XML_MIN_REF_TABLE	32

typedef struct _xmlRefTable xmlRefTable;
typedef xmlRefTable *xmlRefTablePtr;
struct _xmlRefTable {
    int nb_refs;			/* number of refs stored */
    int max_refs;		/* maximum number of refs */
    xmlRefPtr *table;		/* the table of refs */
};

/* Notation */
xmlNotationPtr	    xmlAddNotationDecl	(xmlValidCtxtPtr ctxt,
					 xmlDtdPtr dtd,
					 const xmlChar *name,
					 const xmlChar *PublicID,
					 const xmlChar *SystemID);
xmlNotationTablePtr xmlCopyNotationTable(xmlNotationTablePtr table);
void		    xmlFreeNotationTable(xmlNotationTablePtr table);
void		    xmlDumpNotationTable(xmlBufferPtr buf,
					 xmlNotationTablePtr table);

/* Element Content */
xmlElementContentPtr xmlNewElementContent (xmlChar *name,
					   xmlElementContentType type);
xmlElementContentPtr xmlCopyElementContent(xmlElementContentPtr content);
void		     xmlFreeElementContent(xmlElementContentPtr cur);

/* Element */
xmlElementPtr	   xmlAddElementDecl	(xmlValidCtxtPtr ctxt,
					 xmlDtdPtr dtd,
					 const xmlChar *name,
					 xmlElementTypeVal type,
					 xmlElementContentPtr content);
xmlElementTablePtr xmlCopyElementTable	(xmlElementTablePtr table);
void		   xmlFreeElementTable	(xmlElementTablePtr table);
void		   xmlDumpElementTable	(xmlBufferPtr buf,
					 xmlElementTablePtr table);

/* Enumeration */
xmlEnumerationPtr  xmlCreateEnumeration	(xmlChar *name);
void		   xmlFreeEnumeration	(xmlEnumerationPtr cur);
xmlEnumerationPtr  xmlCopyEnumeration	(xmlEnumerationPtr cur);

/* Attribute */
xmlAttributePtr	    xmlAddAttributeDecl	    (xmlValidCtxtPtr ctxt,
					     xmlDtdPtr dtd,
					     const xmlChar *elem,
					     const xmlChar *name,
					     xmlAttributeType type,
					     xmlAttributeDefault def,
					     const xmlChar *defaultValue,
					     xmlEnumerationPtr tree);
xmlAttributeTablePtr xmlCopyAttributeTable  (xmlAttributeTablePtr table);
void		     xmlFreeAttributeTable  (xmlAttributeTablePtr table);
void		     xmlDumpAttributeTable  (xmlBufferPtr buf,
					     xmlAttributeTablePtr table);

/* IDs */
xmlIDPtr	xmlAddID	(xmlValidCtxtPtr ctxt,
				 xmlDocPtr doc,
				 const xmlChar *value,
				 xmlAttrPtr attr);
xmlIDTablePtr	xmlCopyIDTable	(xmlIDTablePtr table);
void		xmlFreeIDTable	(xmlIDTablePtr table);
xmlAttrPtr	xmlGetID	(xmlDocPtr doc,
				 const xmlChar *ID);
int		xmlIsID		(xmlDocPtr doc,
				 xmlNodePtr elem,
				 xmlAttrPtr attr);
int		xmlRemoveID	(xmlDocPtr doc, xmlAttrPtr attr);

/* IDREFs */
xmlRefPtr	xmlAddRef	(xmlValidCtxtPtr ctxt,
				 xmlDocPtr doc,
				 const xmlChar *value,
				 xmlAttrPtr attr);
xmlRefTablePtr	xmlCopyRefTable	(xmlRefTablePtr table);
void		xmlFreeRefTable	(xmlRefTablePtr table);
int		xmlIsRef	(xmlDocPtr doc,
				 xmlNodePtr elem,
				 xmlAttrPtr attr);
int		xmlRemoveRef	(xmlDocPtr doc, xmlAttrPtr attr);

/**
 * The public function calls related to validity checking
 */

int		xmlValidateRoot		(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc);
int		xmlValidateElementDecl	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
		                         xmlElementPtr elem);
int		xmlValidateAttributeDecl(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
		                         xmlAttributePtr attr);
int		xmlValidateAttributeValue(xmlAttributeType type,
					 const xmlChar *value);
int		xmlValidateNotationDecl	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
		                         xmlNotationPtr nota);
int		xmlValidateDtd		(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 xmlDtdPtr dtd);
int		xmlValidateDocument	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc);
int		xmlValidateElement	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 xmlNodePtr elem);
int		xmlValidateOneElement	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
		                         xmlNodePtr elem);
int		xmlValidateOneAttribute	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 xmlNodePtr	elem,
					 xmlAttrPtr attr,
					 const xmlChar *value);
int		xmlValidateDocumentFinal(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc);
int		xmlValidateNotationUse	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 const xmlChar *notationName);
int		xmlIsMixedElement	(xmlDocPtr doc,
					 const xmlChar *name);
xmlAttributePtr	xmlGetDtdAttrDesc	(xmlDtdPtr dtd,
					 const xmlChar *elem,
					 const xmlChar *name);
xmlNotationPtr	xmlGetDtdNotationDesc	(xmlDtdPtr dtd,
					 const xmlChar *name);
xmlElementPtr	xmlGetDtdElementDesc	(xmlDtdPtr dtd,
					 const xmlChar *name);

int		xmlValidGetValidElements(xmlNode *prev,
					 xmlNode *next,
					 const xmlChar **list,
					 int max);
int		xmlValidGetPotentialChildren(xmlElementContent *ctree,
					 const xmlChar **list,
					 int *len,
					 int max);
#ifdef __cplusplus
}
#endif
#endif /* __XML_VALID_H__ */
