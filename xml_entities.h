/*
 * entities.h : interface for the XML entities handking
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#ifndef __XML_ENTITIES_H__
#define __XML_ENTITIES_H__
#include "xml_parser.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
 * An unit of storage for an entity, contains the string, the value
 * and the linkind data needed for the linking in the hash table.
 */

typedef struct xmlEntity {
    const CHAR *id;		/* The entity name */
    CHAR *value;		/* The entity CHAR equivalent */
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

extern void xmlAddDocEntity(xmlDocPtr doc, CHAR *value, const CHAR *id);
extern void xmlAddDtdEntity(xmlDtdPtr dtd, CHAR *value, const CHAR *id);
extern CHAR *xmlGetEntity(xmlDocPtr doc, const CHAR *id);
extern CHAR *xmlSubstituteEntities(xmlDocPtr doc, const CHAR *input);
extern CHAR *xmlEncodeEntities(xmlDocPtr doc, const CHAR *input);
extern CHAR *xmlDecodeEntities(xmlDocPtr doc, const CHAR *input, int len);
extern xmlEntitiesTablePtr xmlCreateEntitiesTable(void);
extern void xmlFreeEntitiesTable(xmlEntitiesTablePtr table);

#ifdef __cplusplus
}
#endif

# endif /* __XML_ENTITIES_H__ */
