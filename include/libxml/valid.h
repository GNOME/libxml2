/*
 * valid.h : interface to the DTD handling and the validity checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */


#ifndef __XML_VALID_H__
#define __XML_VALID_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "tree.h"

/**
 * an xmlValidCtxt is used for error reporting when validating
 */

typedef void (*xmlValidityErrorFunc) (void *ctx, const char *msg, ...);
typedef void (*xmlValidityWarningFunc) (void *ctx, const char *msg, ...);

typedef struct xmlValidCtxt {
    void *userData;			/* user specific data block */
    xmlValidityErrorFunc error;		/* the callback in case of errors */
    xmlValidityWarningFunc warning;	/* the callback in case of warning */
} xmlValidCtxt, *xmlValidCtxtPtr;

extern void xmlParserValidityError(void *ctx, const char *msg, ...);
extern void xmlParserValidityWarning(void *ctx, const char *msg, ...);

/*
 * ALl notation declarations are stored in a table
 * there is one table per DTD
 */

#define XML_MIN_NOTATION_TABLE	32

typedef struct xmlNotationTable {
    int nb_notations;		/* number of notations stored */
    int max_notations;		/* maximum number of notations */
    xmlNotationPtr *table;	/* the table of attributes */
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
    xmlElementPtr *table;	/* the table of elements */
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
    xmlAttributePtr *table;	/* the table of attributes */
} xmlAttributeTable;
typedef xmlAttributeTable *xmlAttributeTablePtr;

/*
 * ALl IDs attributes are stored in a table
 * there is one table per document
 */

#define XML_MIN_ID_TABLE	32

typedef struct xmlIDTable {
    int nb_ids;			/* number of ids stored */
    int max_ids;		/* maximum number of ids */
    xmlIDPtr *table;		/* the table of ids */
} xmlIDTable;
typedef xmlIDTable *xmlIDTablePtr;

/*
 * ALl Refs attributes are stored in a table
 * there is one table per document
 */

#define XML_MIN_REF_TABLE	32

typedef struct xmlRefTable {
    int nb_refs;			/* number of refs stored */
    int max_refs;		/* maximum number of refs */
    xmlRefPtr *table;		/* the table of refs */
} xmlRefTable;
typedef xmlRefTable *xmlRefTablePtr;

/* Notation */
xmlNotationPtr	    xmlAddNotationDecl	(xmlValidCtxtPtr ctxt,
					 xmlDtdPtr dtd,
					 const CHAR *name,
					 const CHAR *PublicID,
					 const CHAR *SystemID);
xmlNotationTablePtr xmlCopyNotationTable(xmlNotationTablePtr table);
void		    xmlFreeNotationTable(xmlNotationTablePtr table);
void		    xmlDumpNotationTable(xmlBufferPtr buf,
					 xmlNotationTablePtr table);

/* Element Content */
xmlElementContentPtr xmlNewElementContent (CHAR *name,
					   xmlElementContentType type);
xmlElementContentPtr xmlCopyElementContent(xmlElementContentPtr content);
void		     xmlFreeElementContent(xmlElementContentPtr cur);

/* Element */
xmlElementPtr	   xmlAddElementDecl	(xmlValidCtxtPtr ctxt,
					 xmlDtdPtr dtd,
					 const CHAR *name,
					 xmlElementContentType type,
					 xmlElementContentPtr content);
xmlElementTablePtr xmlCopyElementTable	(xmlElementTablePtr table);
void		   xmlFreeElementTable	(xmlElementTablePtr table);
void		   xmlDumpElementTable	(xmlBufferPtr buf,
					 xmlElementTablePtr table);

/* Enumeration */
xmlEnumerationPtr  xmlCreateEnumeration	(CHAR *name);
void		   xmlFreeEnumeration	(xmlEnumerationPtr cur);
xmlEnumerationPtr  xmlCopyEnumeration	(xmlEnumerationPtr cur);

/* Attribute */
xmlAttributePtr	    xmlAddAttributeDecl	    (xmlValidCtxtPtr ctxt,
					     xmlDtdPtr dtd,
					     const CHAR *elem,
					     const CHAR *name,
					     xmlAttributeType type,
					     xmlAttributeDefault def,
					     const CHAR *defaultValue,
					     xmlEnumerationPtr tree);
xmlAttributeTablePtr xmlCopyAttributeTable  (xmlAttributeTablePtr table);
void		     xmlFreeAttributeTable  (xmlAttributeTablePtr table);
void		     xmlDumpAttributeTable  (xmlBufferPtr buf,
					     xmlAttributeTablePtr table);

/* IDs */
xmlIDPtr	xmlAddID	(xmlValidCtxtPtr ctxt,
				 xmlDocPtr doc,
				 const CHAR *value,
				 xmlAttrPtr attr);
xmlIDTablePtr	xmlCopyIDTable	(xmlIDTablePtr table);
void		xmlFreeIDTable	(xmlIDTablePtr table);
xmlAttrPtr	xmlGetID	(xmlDocPtr doc,
				 const CHAR *ID);
int		xmlIsID		(xmlDocPtr doc,
				 xmlNodePtr elem,
				 xmlAttrPtr attr);

/* IDREFs */
xmlRefPtr	xmlAddRef	(xmlValidCtxtPtr ctxt,
				 xmlDocPtr doc,
				 const CHAR *value,
				 xmlAttrPtr attr);
xmlRefTablePtr	xmlCopyRefTable	(xmlRefTablePtr table);
void		xmlFreeRefTable	(xmlRefTablePtr table);
int		xmlIsRef	(xmlDocPtr doc,
				 xmlNodePtr elem,
				 xmlAttrPtr attr);

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
					 const CHAR *value);
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
					 const CHAR *value);
int		xmlValidateDocumentFinal(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc);
int		xmlValidateNotationUse	(xmlValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 const CHAR *notationName);
int		xmlIsMixedElement	(xmlDocPtr doc,
					 const CHAR *name);
xmlAttributePtr	xmlGetDtdAttrDesc	(xmlDtdPtr dtd,
					 const CHAR *elem,
					 const CHAR *name);
xmlNotationPtr	xmlGetDtdNotationDesc	(xmlDtdPtr dtd,
					 const CHAR *name);
xmlElementPtr	xmlGetDtdElementDesc	(xmlDtdPtr dtd,
					 const CHAR *name);

#ifdef __cplusplus
}
#endif
#endif /* __XML_VALID_H__ */
