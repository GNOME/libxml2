/*
 * entities.h : interface for the XML entities handking
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_ENTITIES_H__
#define __XML_ENTITIES_H__

#include "tree.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XML_INTERNAL_GENERAL_ENTITY		1
#define XML_EXTERNAL_GENERAL_PARSED_ENTITY	2
#define XML_EXTERNAL_GENERAL_UNPARSED_ENTITY	3
#define XML_INTERNAL_PARAMETER_ENTITY		4
#define XML_EXTERNAL_PARAMETER_ENTITY		5
#define XML_INTERNAL_PREDEFINED_ENTITY		6

/*
 * An unit of storage for an entity, contains the string, the value
 * and the linkind data needed for the linking in the hash table.
 */

typedef struct _xmlEntity xmlEntity;
typedef xmlEntity *xmlEntityPtr;
struct _xmlEntity {
    int type;			/* The entity type */
    int len;			/* The lenght of the name */
    const xmlChar  *name;	/* Name of the entity */
    const xmlChar  *ExternalID;	/* External identifier for PUBLIC Entity */
    const xmlChar  *SystemID;	/* URI for a SYSTEM or PUBLIC Entity */
    xmlChar *content;		/* The entity content or ndata if unparsed */
    int length;			/* the content length */
    xmlChar *orig;		/* The entity cont without ref substitution */
    /* Extended when merging 2,3,5 */
    struct _xmlNode    *children;/* NULL */
    struct _xmlNode    *last;	/* NULL */
    const xmlChar      *URI;	/* the full URI as computed */
};

/*
 * ALl entities are stored in a table there is one table per DTD
 * and one extra per document.
 */

#define XML_MIN_ENTITIES_TABLE	32

typedef struct _xmlEntitiesTable xmlEntitiesTable;
typedef xmlEntitiesTable *xmlEntitiesTablePtr;
struct _xmlEntitiesTable {
    int nb_entities;		/* number of elements stored */
    int max_entities;		/* maximum number of elements */
    xmlEntityPtr table;	        /* the table of entities */
};


/*
 * External functions :
 */

void			xmlAddDocEntity		(xmlDocPtr doc,
						 const xmlChar *name,
						 int type,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID,
						 const xmlChar *content);
void			xmlAddDtdEntity		(xmlDocPtr doc,
						 const xmlChar *name,
						 int type,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID,
						 const xmlChar *content);
xmlEntityPtr		xmlGetPredefinedEntity	(const xmlChar *name);
xmlEntityPtr		xmlGetDocEntity		(xmlDocPtr doc,
						 const xmlChar *name);
xmlEntityPtr		xmlGetDtdEntity		(xmlDocPtr doc,
						 const xmlChar *name);
xmlEntityPtr		xmlGetParameterEntity	(xmlDocPtr doc,
						 const xmlChar *name);
const xmlChar *		xmlEncodeEntities	(xmlDocPtr doc,
						 const xmlChar *input);
xmlChar *		xmlEncodeEntitiesReentrant(xmlDocPtr doc,
						 const xmlChar *input);
xmlEntitiesTablePtr	xmlCreateEntitiesTable	(void);
xmlEntitiesTablePtr	xmlCopyEntitiesTable	(xmlEntitiesTablePtr table);
void			xmlFreeEntitiesTable	(xmlEntitiesTablePtr table);
void			xmlDumpEntitiesTable	(xmlBufferPtr buf,
						 xmlEntitiesTablePtr table);
xmlEntitiesTablePtr	xmlCopyEntitiesTable	(xmlEntitiesTablePtr table);
void			xmlCleanupPredefinedEntities(void);

#ifdef __cplusplus
}
#endif

# endif /* __XML_ENTITIES_H__ */
