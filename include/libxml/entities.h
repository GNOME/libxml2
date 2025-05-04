/**
 * @file
 * 
 * @brief XML entities
 * 
 * This module provides an API to work with XML entities.
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Daniel Veillard
 */

#ifndef __XML_ENTITIES_H__
#define __XML_ENTITIES_H__

#include <libxml/xmlversion.h>
#define XML_TREE_INTERNALS
#include <libxml/tree.h>
#undef XML_TREE_INTERNALS

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The different entity types.
 */
typedef enum {
    /** internal general entity */
    XML_INTERNAL_GENERAL_ENTITY = 1,
    /** external general parsed entity */
    XML_EXTERNAL_GENERAL_PARSED_ENTITY = 2,
    /** external general unparsed entity */
    XML_EXTERNAL_GENERAL_UNPARSED_ENTITY = 3,
    /** internal parameter entity */
    XML_INTERNAL_PARAMETER_ENTITY = 4,
    /** external parameter entity */
    XML_EXTERNAL_PARAMETER_ENTITY = 5,
    /** internal predefined entity */
    XML_INTERNAL_PREDEFINED_ENTITY = 6
} xmlEntityType;

/**
 * An entity declaration
 */
struct _xmlEntity {
    /** application data */
    void           *_private;
    /** XML_ENTITY_DECL, must be second ! */
    xmlElementType          type;
    /** Entity name */
    const xmlChar          *name;
    /** First child link */
    struct _xmlNode    *children;
    /** Last child link */
    struct _xmlNode        *last;
    /** -> DTD */
    struct _xmlDtd       *parent;
    /** next sibling link  */
    struct _xmlNode        *next;
    /** previous sibling link  */
    struct _xmlNode        *prev;
    /** the containing document */
    struct _xmlDoc          *doc;

    /** content without ref substitution */
    xmlChar                *orig;
    /** content or ndata if unparsed */
    xmlChar             *content;
    /** the content length */
    int                   length;
    /** The entity type */
    xmlEntityType          etype;
    /** External identifier for PUBLIC */
    const xmlChar    *ExternalID;
    /** URI for a SYSTEM or PUBLIC Entity */
    const xmlChar      *SystemID;

    /** unused */
    struct _xmlEntity     *nexte;
    /** the full URI as computed */
    const xmlChar           *URI;
    /** unused */
    int                    owner;
    /** various flags */
    int                    flags;
    /** expanded size */
    unsigned long   expandedSize;
};

typedef struct _xmlHashTable xmlEntitiesTable;
typedef xmlEntitiesTable *xmlEntitiesTablePtr;

XMLPUBFUN xmlEntityPtr
			xmlNewEntity		(xmlDocPtr doc,
						 const xmlChar *name,
						 int type,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID,
						 const xmlChar *content);
XMLPUBFUN void
			xmlFreeEntity		(xmlEntityPtr entity);
XMLPUBFUN int
			xmlAddEntity		(xmlDocPtr doc,
						 int extSubset,
						 const xmlChar *name,
						 int type,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID,
						 const xmlChar *content,
						 xmlEntityPtr *out);
XMLPUBFUN xmlEntityPtr
			xmlAddDocEntity		(xmlDocPtr doc,
						 const xmlChar *name,
						 int type,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID,
						 const xmlChar *content);
XMLPUBFUN xmlEntityPtr
			xmlAddDtdEntity		(xmlDocPtr doc,
						 const xmlChar *name,
						 int type,
						 const xmlChar *ExternalID,
						 const xmlChar *SystemID,
						 const xmlChar *content);
XMLPUBFUN xmlEntityPtr
			xmlGetPredefinedEntity	(const xmlChar *name);
XMLPUBFUN xmlEntityPtr
			xmlGetDocEntity		(const xmlDoc *doc,
						 const xmlChar *name);
XMLPUBFUN xmlEntityPtr
			xmlGetDtdEntity		(xmlDocPtr doc,
						 const xmlChar *name);
XMLPUBFUN xmlEntityPtr
			xmlGetParameterEntity	(xmlDocPtr doc,
						 const xmlChar *name);
XMLPUBFUN xmlChar *
			xmlEncodeEntitiesReentrant(xmlDocPtr doc,
						 const xmlChar *input);
XMLPUBFUN xmlChar *
			xmlEncodeSpecialChars	(const xmlDoc *doc,
						 const xmlChar *input);
XMLPUBFUN xmlEntitiesTablePtr
			xmlCreateEntitiesTable	(void);
XMLPUBFUN xmlEntitiesTablePtr
			xmlCopyEntitiesTable	(xmlEntitiesTablePtr table);
XMLPUBFUN void
			xmlFreeEntitiesTable	(xmlEntitiesTablePtr table);
#ifdef LIBXML_OUTPUT_ENABLED
XMLPUBFUN void
			xmlDumpEntitiesTable	(xmlBufferPtr buf,
						 xmlEntitiesTablePtr table);
XMLPUBFUN void
			xmlDumpEntityDecl	(xmlBufferPtr buf,
						 xmlEntityPtr ent);
#endif /* LIBXML_OUTPUT_ENABLED */

#ifdef __cplusplus
}
#endif

# endif /* __XML_ENTITIES_H__ */
