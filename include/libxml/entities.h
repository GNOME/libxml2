/*
 * entities.h : interface for the XML entities handking
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#ifndef __XML_ENTITIES_H__
#define __XML_ENTITIES_H__
#include "parser.h"


#ifdef __cplusplus
extern "C" {
#endif

#define XML_INTERNAL_GENERAL_ENTITY		1
#define XML_EXTERNAL_GENERAL_PARSED_ENTITY	2
#define XML_EXTERNAL_GENERAL_UNPARSED_ENTITY	3
#define XML_INTERNAL_PARAMETER_ENTITY		4
#define XML_EXTERNAL_PARAMETER_ENTITY		5

/*
 * An unit of storage for an entity, contains the string, the value
 * and the linkind data needed for the linking in the hash table.
 */

typedef struct xmlEntity {
    int type;			/* The entity type */
    int len;			/* The lenght of the name */
    const CHAR    *name;	/* Name of the entity */
    const CHAR    *ExternalID;	/* External identifier for PUBLIC Entity */
    const CHAR    *SystemID;	/* URI for a SYSTEM or PUBLIC Entity */
    CHAR *content;		/* The entity content or ndata if unparsed */
} xmlEntity, *xmlEntityPtr;

/*
 * ALl entities are stored in a table there is one table per DTD
 * and one extra per document.
 */

#define XML_MIN_ENTITIES_TABLE	32

typedef struct xmlEntitiesTable {
    int nb_entities;		/* number of elements stored */
    int max_entities;		/* maximum number of elements */
    xmlEntityPtr table;		/* the table of entities */
} xmlEntitiesTable, *xmlEntitiesTablePtr;

/*
 * External functions :
 */

extern void xmlAddDocEntity(xmlDocPtr doc, const CHAR *name, int type,
              const CHAR *ExternalID, const CHAR *SystemID, CHAR *content);
extern void xmlAddDtdEntity(xmlDocPtr doc, const CHAR *name, int type,
              const CHAR *ExternalID, const CHAR *SystemID, CHAR *content);
extern xmlEntityPtr xmlGetDocEntity(xmlDocPtr doc, const CHAR *name);
extern xmlEntityPtr xmlGetDtdEntity(xmlDocPtr doc, const CHAR *name);
extern CHAR *xmlEncodeEntities(xmlDocPtr doc, const CHAR *input);
extern xmlEntitiesTablePtr xmlCreateEntitiesTable(void);
extern void xmlFreeEntitiesTable(xmlEntitiesTablePtr table);
extern void xmlDumpEntitiesTable(xmlEntitiesTablePtr table);

#ifdef __cplusplus
}
#endif

# endif /* __XML_ENTITIES_H__ */
