/*
 * entities.h : interface for the XML entities handking
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_ENTITIES_H__
#define __XML_ENTITIES_H__

#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The different valid entity types
 */
typedef enum {
    XML_INTERNAL_GENERAL_ENTITY = 1,
    XML_EXTERNAL_GENERAL_PARSED_ENTITY = 2,
    XML_EXTERNAL_GENERAL_UNPARSED_ENTITY = 3,
    XML_INTERNAL_PARAMETER_ENTITY = 4,
    XML_EXTERNAL_PARAMETER_ENTITY = 5,
    XML_INTERNAL_PREDEFINED_ENTITY = 6
} xmlEntityType;

/*
 * An unit of storage for an entity, contains the string, the value
 * and the linkind data needed for the linking in the hash table.
 */

typedef struct _xmlEntity xmlEntity;
typedef xmlEntity *xmlEntityPtr;
struct _xmlEntity {
#ifndef XML_WITHOUT_CORBA
    void           *_private;	        /* for Corba, must be first ! */
#endif
    xmlElementType          type;       /* XML_ENTITY_DECL, must be second ! */
    const xmlChar          *name;	/* Attribute name */
    struct _xmlNode    *children;	/* NULL */
    struct _xmlNode        *last;	/* NULL */
    struct _xmlDtd       *parent;	/* -> DTD */
    struct _xmlNode        *next;	/* next sibling link  */
    struct _xmlNode        *prev;	/* previous sibling link  */
    struct _xmlDoc          *doc;       /* the containing document */

    xmlChar                *orig;	/* content without ref substitution */
    xmlChar             *content;	/* content or ndata if unparsed */
    int                   length;	/* the content length */
    xmlEntityType          etype;	/* The entity type */
    const xmlChar    *ExternalID;	/* External identifier for PUBLIC */
    const xmlChar      *SystemID;	/* URI for a SYSTEM or PUBLIC Entity */

#ifdef WITH_EXTRA_ENT_DETECT
    /* Referenced entities name stack */
    xmlChar           *ent;             /* Current parsed Node */
    int                entNr;           /* Depth of the parsing stack */
    int                entMax;          /* Max depth of the parsing stack */
    xmlChar *         *entTab;          /* array of nodes */
#endif
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
    xmlEntityPtr *table;	/* the table of entities */
};


/*
 * External functions :
 */

xmlEntityPtr		xmlAddDocEntity		(xmlDocPtr doc,
						 const xmlChar *name,
						 int type,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID,
						 const xmlChar *content);
xmlEntityPtr		xmlAddDtdEntity		(xmlDocPtr doc,
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
void			xmlDumpEntityDecl	(xmlBufferPtr buf,
						 xmlEntityPtr ent);
xmlEntitiesTablePtr	xmlCopyEntitiesTable	(xmlEntitiesTablePtr table);
void			xmlCleanupPredefinedEntities(void);

#ifdef WITH_EXTRA_ENT_DETECT
int			xmlEntityAddReference	(xmlEntityPtr ent,
						 const xmlChar *to);
#endif

#ifdef __cplusplus
}
#endif

# endif /* __XML_ENTITIES_H__ */
