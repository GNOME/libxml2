/*
 * entities.c : implementation for the XML entities handking
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <libxml/xmlmemory.h>
#include <libxml/entities.h>
#include <libxml/parser.h>

#define DEBUG_ENT_REF /* debugging of cross entities dependancies */

/*
 * The XML predefined entities.
 */

struct xmlPredefinedEntityValue {
    const char *name;
    const char *value;
};
struct xmlPredefinedEntityValue xmlPredefinedEntityValues[] = {
    { "lt", "<" },
    { "gt", ">" },
    { "apos", "'" },
    { "quot", "\"" },
    { "amp", "&" }
};

xmlEntitiesTablePtr xmlPredefinedEntities = NULL;

/*
 * xmlFreeEntity : clean-up an entity record.
 */
void xmlFreeEntity(xmlEntityPtr entity) {
    if (entity == NULL) return;

    if (entity->children)
	xmlFreeNodeList(entity->children);
    if (entity->name != NULL)
	xmlFree((char *) entity->name);
    if (entity->ExternalID != NULL)
        xmlFree((char *) entity->ExternalID);
    if (entity->SystemID != NULL)
        xmlFree((char *) entity->SystemID);
    if (entity->content != NULL)
        xmlFree((char *) entity->content);
    if (entity->orig != NULL)
        xmlFree((char *) entity->orig);
#ifdef WITH_EXTRA_ENT_DETECT
    if (entity->entTab != NULL) {
	int i;

	for (i = 0; i < entity->entNr; i++)
	    xmlFree(entity->entTab[i]);
	xmlFree(entity->entTab);
    }
#endif
    memset(entity, -1, sizeof(xmlEntity));
    xmlFree(entity);
}

/*
 * xmlAddEntity : register a new entity for an entities table.
 */
static xmlEntityPtr
xmlAddEntity(xmlEntitiesTablePtr table, const xmlChar *name, int type,
	  const xmlChar *ExternalID, const xmlChar *SystemID, const xmlChar *content) {
    int i;
    xmlEntityPtr ret;

    for (i = 0;i < table->nb_entities;i++) {
        ret = table->table[i];
	if (!xmlStrcmp(ret->name, name)) {
	    /*
	     * The entity is already defined in this Dtd, the spec says to NOT
	     * override it ... Is it worth a Warning ??? !!!
	     * Not having a cprinting context this seems hard ...
	     */
	    if (((type == XML_INTERNAL_PARAMETER_ENTITY) ||
	         (type == XML_EXTERNAL_PARAMETER_ENTITY)) &&
	        ((ret->etype == XML_INTERNAL_PARAMETER_ENTITY) ||
	         (ret->etype == XML_EXTERNAL_PARAMETER_ENTITY)))
		return(NULL);
	    else
	    if (((type != XML_INTERNAL_PARAMETER_ENTITY) &&
	         (type != XML_EXTERNAL_PARAMETER_ENTITY)) &&
	        ((ret->etype != XML_INTERNAL_PARAMETER_ENTITY) &&
	         (ret->etype != XML_EXTERNAL_PARAMETER_ENTITY)))
		return(NULL);
	}
    }
    if (table->nb_entities >= table->max_entities) {
        /*
	 * need more elements.
	 */
	table->max_entities *= 2;
	table->table = (xmlEntityPtr *) 
	    xmlRealloc(table->table,
		       table->max_entities * sizeof(xmlEntityPtr));
	if (table->table == NULL) {
	    perror("realloc failed");
	    return(NULL);
	}
    }
    ret = (xmlEntityPtr) xmlMalloc(sizeof(xmlEntity));
    if (ret == NULL) {
	fprintf(stderr, "xmlAddEntity: out of memory\n");
	return(NULL);
    }
    memset(ret, 0, sizeof(xmlEntity));
    ret->type = XML_ENTITY_DECL;
    table->table[table->nb_entities] = ret;

    /*
     * fill the structure.
     */
    ret->name = xmlStrdup(name);
    ret->etype = type;
    if (ExternalID != NULL)
	ret->ExternalID = xmlStrdup(ExternalID);
    if (SystemID != NULL)
	ret->SystemID = xmlStrdup(SystemID);
    if (content != NULL) {
        ret->length = xmlStrlen(content);
	ret->content = xmlStrndup(content, ret->length);
     } else {
        ret->length = 0;
        ret->content = NULL;
    }
    ret->orig = NULL;
    table->nb_entities++;

    return(ret);
}

/**
 * xmlInitializePredefinedEntities:
 *
 * Set up the predefined entities.
 */
void xmlInitializePredefinedEntities(void) {
    int i;
    xmlChar name[50];
    xmlChar value[50];
    const char *in;
    xmlChar *out;

    if (xmlPredefinedEntities != NULL) return;

    xmlPredefinedEntities = xmlCreateEntitiesTable();
    for (i = 0;i < sizeof(xmlPredefinedEntityValues) / 
                   sizeof(xmlPredefinedEntityValues[0]);i++) {
        in = xmlPredefinedEntityValues[i].name;
	out = &name[0];
	for (;(*out++ = (xmlChar) *in);)in++;
        in = xmlPredefinedEntityValues[i].value;
	out = &value[0];
	for (;(*out++ = (xmlChar) *in);)in++;
        xmlAddEntity(xmlPredefinedEntities, (const xmlChar *) &name[0],
	             XML_INTERNAL_PREDEFINED_ENTITY, NULL, NULL,
		     &value[0]);
    }
}

/**
 * xmlCleanupPredefinedEntities:
 *
 * Cleanup up the predefined entities table.
 */
void xmlCleanupPredefinedEntities(void) {
    if (xmlPredefinedEntities == NULL) return;

    xmlFreeEntitiesTable(xmlPredefinedEntities);
    xmlPredefinedEntities = NULL;
}

/**
 * xmlGetPredefinedEntity:
 * @name:  the entity name
 *
 * Check whether this name is an predefined entity.
 *
 * Returns NULL if not, othervise the entity
 */
xmlEntityPtr
xmlGetPredefinedEntity(const xmlChar *name) {
    int i;
    xmlEntityPtr cur;

    if (xmlPredefinedEntities == NULL)
        xmlInitializePredefinedEntities();
    for (i = 0;i < xmlPredefinedEntities->nb_entities;i++) {
	cur = xmlPredefinedEntities->table[i];
	if (!xmlStrcmp(cur->name, name)) return(cur);
    }
    return(NULL);
}

/**
 * xmlAddDtdEntity:
 * @doc:  the document
 * @name:  the entity name
 * @type:  the entity type XML_xxx_yyy_ENTITY
 * @ExternalID:  the entity external ID if available
 * @SystemID:  the entity system ID if available
 * @content:  the entity content
 *
 * Register a new entity for this document DTD external subset.
 *
 * Returns a pointer to the entity or NULL in case of error
 */
xmlEntityPtr
xmlAddDtdEntity(xmlDocPtr doc, const xmlChar *name, int type,
	        const xmlChar *ExternalID, const xmlChar *SystemID,
		const xmlChar *content) {
    xmlEntitiesTablePtr table;
    xmlEntityPtr ret;
    xmlDtdPtr dtd;

    if (doc == NULL) {
        fprintf(stderr,
	        "xmlAddDtdEntity: doc == NULL !\n");
	return(NULL);
    }
    if (doc->extSubset == NULL) {
        fprintf(stderr,
	        "xmlAddDtdEntity: document without external subset !\n");
	return(NULL);
    }
    dtd = doc->extSubset;
    table = (xmlEntitiesTablePtr) dtd->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	dtd->entities = table;
    }
    ret = xmlAddEntity(table, name, type, ExternalID, SystemID, content);
    if (ret == NULL) return(NULL);

    /*
     * Link it to the Dtd
     */
    ret->parent = dtd;
    ret->doc = dtd->doc;
    if (dtd->last == NULL) {
	dtd->children = dtd->last = (xmlNodePtr) ret;
    } else {
        dtd->last->next = (xmlNodePtr) ret;
	ret->prev = dtd->last;
	dtd->last = (xmlNodePtr) ret;
    }
    return(ret);
}

/**
 * xmlAddDocEntity:
 * @doc:  the document
 * @name:  the entity name
 * @type:  the entity type XML_xxx_yyy_ENTITY
 * @ExternalID:  the entity external ID if available
 * @SystemID:  the entity system ID if available
 * @content:  the entity content
 *
 * Register a new entity for this document.
 *
 * Returns a pointer to the entity or NULL in case of error
 */
xmlEntityPtr
xmlAddDocEntity(xmlDocPtr doc, const xmlChar *name, int type,
	        const xmlChar *ExternalID, const xmlChar *SystemID,
	        const xmlChar *content) {
    xmlEntitiesTablePtr table;
    xmlEntityPtr ret;
    xmlDtdPtr dtd;

    if (doc == NULL) {
        fprintf(stderr,
	        "xmlAddDocEntity: document is NULL !\n");
	return(NULL);
    }
    if (doc->intSubset == NULL) {
        fprintf(stderr,
	        "xmlAddDtdEntity: document without internal subset !\n");
	return(NULL);
    }
    dtd = doc->intSubset;
    table = (xmlEntitiesTablePtr) doc->intSubset->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	doc->intSubset->entities = table;
    }
    ret = xmlAddEntity(table, name, type, ExternalID, SystemID, content);
    if (ret == NULL) return(NULL);

    /*
     * Link it to the Dtd
     */
    ret->parent = dtd;
    ret->doc = dtd->doc;
    if (dtd->last == NULL) {
	dtd->children = dtd->last = (xmlNodePtr) ret;
    } else {
	dtd->last->next = (xmlNodePtr) ret;
	ret->prev = dtd->last;
	dtd->last = (xmlNodePtr) ret;
    }
    return(ret);
}

#ifdef WITH_EXTRA_ENT_DETECT
/**
 * xmlEntityCheckReference:
 * @ent:  an existing entity
 * @to:  the entity name it's referencing
 *
 * Function to keep track of references and detect cycles (well formedness 
 * errors !).
 *
 * Returns: 0 if Okay, -1 in case of general error, 1 in case of loop 
 *      detection.
 */
int
xmlEntityCheckReference(xmlEntityPtr ent, const xmlChar *to) {
    int i;
    xmlDocPtr doc;

    if (ent == NULL) return(-1);
    if (to == NULL) return(-1);

    doc = ent->doc;
    if (doc == NULL) return(-1);

#ifdef DEBUG_ENT_REF
    printf("xmlEntityCheckReference(%s to %s)\n", ent->name, to);
#endif


    /*
     * Do a recursive checking
     */
    for (i = 0;i < ent->entNr;i++) {
	xmlEntityPtr indir = NULL;

	if (!xmlStrcmp(to, ent->entTab[i]))
	    return(1);

	switch (ent->etype) {
            case XML_INTERNAL_GENERAL_ENTITY:
            case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
		indir = xmlGetDocEntity(doc, ent->entTab[i]);
		break;
            case XML_INTERNAL_PARAMETER_ENTITY:
            case XML_EXTERNAL_PARAMETER_ENTITY:
		indir = xmlGetDtdEntity(doc, ent->entTab[i]);
		break;
            case XML_INTERNAL_PREDEFINED_ENTITY:
            case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
		break;
	}
	if (xmlEntityCheckReference(indir, to) == 1)
	    return(1);
    }
    return(0);
}

/**
 * xmlEntityAddReference:
 * @ent:  an existing entity
 * @to:  the entity name it's referencing
 *
 * Function to register reuse of an existing entity from a (new) one
 * Used to keep track of references and detect cycles (well formedness 
 * errors !).
 *
 * Returns: 0 if Okay, -1 in case of general error, 1 in case of loop 
 *      detection.
 */
int
xmlEntityAddReference(xmlEntityPtr ent, const xmlChar *to) {
    int i;
    xmlDocPtr doc;
    xmlEntityPtr indir = NULL;

    if (ent == NULL) return(-1);
    if (to == NULL) return(-1);

    doc = ent->doc;
    if (doc == NULL) return(-1);

#ifdef DEBUG_ENT_REF
    printf("xmlEntityAddReference(%s to %s)\n", ent->name, to);
#endif
    if (ent->entTab == NULL) {
	ent->entNr = 0;
	ent->entMax = 5;
	ent->entTab = (xmlChar **) xmlMalloc(ent->entMax * sizeof(xmlChar *));
	if (ent->entTab == NULL) {
	    fprintf(stderr, "xmlEntityAddReference: out of memory !\n");
	    return(-1);
	}
    }

    for (i = 0;i < ent->entNr;i++) {
	if (!xmlStrcmp(to, ent->entTab[i]))
	    return(0);
    }

    /*
     * Do a recursive checking
     */

    switch (ent->etype) {
	case XML_INTERNAL_GENERAL_ENTITY:
	case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
	    indir = xmlGetDocEntity(doc, to);
	    break;
	case XML_INTERNAL_PARAMETER_ENTITY:
	case XML_EXTERNAL_PARAMETER_ENTITY:
	    indir = xmlGetDtdEntity(doc, to);
	    break;
	case XML_INTERNAL_PREDEFINED_ENTITY:
	case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
	    break;
    }
    if ((indir != NULL) &&
	(xmlEntityCheckReference(indir, ent->name) == 1))
	return(1);

    /*
     * Add this to the list
     */
    if (ent->entMax <= ent->entNr) {
	ent->entMax *= 2;
	ent->entTab = (xmlChar **) xmlRealloc(ent->entTab,
		                              ent->entMax * sizeof(xmlChar *));
	if (ent->entTab == NULL) {
	    fprintf(stderr, "xmlEntityAddReference: out of memory !\n");
	    return(-1);
	}
    }
    ent->entTab[ent->entNr++] = xmlStrdup(to);
    return(0);
}
#endif

/**
 * xmlGetParameterEntity:
 * @doc:  the document referencing the entity
 * @name:  the entity name
 *
 * Do an entity lookup in the internal and external subsets and
 * returns the corresponding parameter entity, if found.
 * 
 * Returns A pointer to the entity structure or NULL if not found.
 */
xmlEntityPtr
xmlGetParameterEntity(xmlDocPtr doc, const xmlChar *name) {
    int i;
    xmlEntityPtr cur;
    xmlEntitiesTablePtr table;

    if ((doc->intSubset != NULL) && (doc->intSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->intSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = table->table[i];
	    if (((cur->etype ==  XML_INTERNAL_PARAMETER_ENTITY) ||
	         (cur->etype ==  XML_EXTERNAL_PARAMETER_ENTITY)) &&
		(!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = table->table[i];
	    if (((cur->etype ==  XML_INTERNAL_PARAMETER_ENTITY) ||
	         (cur->etype ==  XML_EXTERNAL_PARAMETER_ENTITY)) &&
		(!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = table->table[i];
	    if (((cur->etype ==  XML_INTERNAL_PARAMETER_ENTITY) ||
	         (cur->etype ==  XML_EXTERNAL_PARAMETER_ENTITY)) &&
		(!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    return(NULL);
}

/**
 * xmlGetDtdEntity:
 * @doc:  the document referencing the entity
 * @name:  the entity name
 *
 * Do an entity lookup in the Dtd entity hash table and
 * returns the corresponding entity, if found.
 * 
 * Returns A pointer to the entity structure or NULL if not found.
 */
xmlEntityPtr
xmlGetDtdEntity(xmlDocPtr doc, const xmlChar *name) {
    int i;
    xmlEntityPtr cur;
    xmlEntitiesTablePtr table;

    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = table->table[i];
	    if ((cur->etype !=  XML_INTERNAL_PARAMETER_ENTITY) &&
	        (cur->etype !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
	        (!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    return(NULL);
}

/**
 * xmlGetDocEntity:
 * @doc:  the document referencing the entity
 * @name:  the entity name
 *
 * Do an entity lookup in the document entity hash table and
 * returns the corrsponding entity, otherwise a lookup is done
 * in the predefined entities too.
 * 
 * Returns A pointer to the entity structure or NULL if not found.
 */
xmlEntityPtr
xmlGetDocEntity(xmlDocPtr doc, const xmlChar *name) {
    int i;
    xmlEntityPtr cur;
    xmlEntitiesTablePtr table;

    if ((doc->intSubset != NULL) && (doc->intSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->intSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = table->table[i];
	    if ((cur->etype !=  XML_INTERNAL_PARAMETER_ENTITY) &&
	        (cur->etype !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
	        (!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = table->table[i];
	    if ((cur->etype !=  XML_INTERNAL_PARAMETER_ENTITY) &&
	        (cur->etype !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
	        (!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    if (xmlPredefinedEntities == NULL)
        xmlInitializePredefinedEntities();
    table = xmlPredefinedEntities;
    for (i = 0;i < table->nb_entities;i++) {
	cur = table->table[i];
	if ((cur->etype !=  XML_INTERNAL_PARAMETER_ENTITY) &&
	    (cur->etype !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
	    (!xmlStrcmp(cur->name, name))) return(cur);
    }

    return(NULL);
}

/*
 * [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
 *                  | [#x10000-#x10FFFF]
 * any Unicode character, excluding the surrogate blocks, FFFE, and FFFF.
 */
#define IS_CHAR(c)							\
    (((c) == 0x09) || ((c) == 0x0a) || ((c) == 0x0d) ||			\
     (((c) >= 0x20) && ((c) != 0xFFFE) && ((c) != 0xFFFF)))

/*
 * A buffer used for converting entities to their equivalent and back.
 */
static int buffer_size = 0;
static xmlChar *buffer = NULL;

int growBuffer(void) {
    buffer_size *= 2;
    buffer = (xmlChar *) xmlRealloc(buffer, buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
        perror("realloc failed");
	return(-1);
    }
    return(0);
}


/**
 * xmlEncodeEntities:
 * @doc:  the document containing the string
 * @input:  A string to convert to XML.
 *
 * Do a global encoding of a string, replacing the predefined entities
 * and non ASCII values with their entities and CharRef counterparts.
 *
 * TODO: remove xmlEncodeEntities, once we are not afraid of breaking binary
 *       compatibility
 *
 * People must migrate their code to xmlEncodeEntitiesReentrant !
 * This routine will issue a warning when encountered.
 * 
 * Returns A newly allocated string with the substitution done.
 */
const xmlChar *
xmlEncodeEntities(xmlDocPtr doc, const xmlChar *input) {
    const xmlChar *cur = input;
    xmlChar *out = buffer;
    static int warning = 1;
    int html = 0;


    if (warning) {
    fprintf(stderr, "Deprecated API xmlEncodeEntities() used\n");
    fprintf(stderr, "   change code to use xmlEncodeEntitiesReentrant()\n");
    warning = 0;
    }

    if (input == NULL) return(NULL);
    if (doc != NULL)
        html = (doc->type == XML_HTML_DOCUMENT_NODE);

    if (buffer == NULL) {
        buffer_size = 1000;
        buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
	if (buffer == NULL) {
	    perror("malloc failed");
            return(NULL);
	}
	out = buffer;
    }
    while (*cur != '\0') {
        if (out - buffer > buffer_size - 100) {
	    int index = out - buffer;

	    growBuffer();
	    out = &buffer[index];
	}

	/*
	 * By default one have to encode at least '<', '>', '"' and '&' !
	 */
	if (*cur == '<') {
	    *out++ = '&';
	    *out++ = 'l';
	    *out++ = 't';
	    *out++ = ';';
	} else if (*cur == '>') {
	    *out++ = '&';
	    *out++ = 'g';
	    *out++ = 't';
	    *out++ = ';';
	} else if (*cur == '&') {
	    *out++ = '&';
	    *out++ = 'a';
	    *out++ = 'm';
	    *out++ = 'p';
	    *out++ = ';';
	} else if (*cur == '"') {
	    *out++ = '&';
	    *out++ = 'q';
	    *out++ = 'u';
	    *out++ = 'o';
	    *out++ = 't';
	    *out++ = ';';
	} else if ((*cur == '\'') && (!html)) {
	    *out++ = '&';
	    *out++ = 'a';
	    *out++ = 'p';
	    *out++ = 'o';
	    *out++ = 's';
	    *out++ = ';';
	} else if (((*cur >= 0x20) && (*cur < 0x80)) ||
	    (*cur == '\n') || (*cur == '\r') || (*cur == '\t')) {
	    /*
	     * default case, just copy !
	     */
	    *out++ = *cur;
#ifndef USE_UTF_8
	} else if ((sizeof(xmlChar) == 1) && (*cur >= 0x80)) {
	    char buf[10], *ptr;
#ifdef HAVE_SNPRINTF
	    snprintf(buf, 9, "&#%d;", *cur);
#else
	    sprintf(buf, "&#%d;", *cur);
#endif
            ptr = buf;
	    while (*ptr != 0) *out++ = *ptr++;
#endif
	} else if (IS_CHAR(*cur)) {
	    char buf[10], *ptr;

#ifdef HAVE_SNPRINTF
	    snprintf(buf, 9, "&#%d;", *cur);
#else
	    sprintf(buf, "&#%d;", *cur);
#endif
            ptr = buf;
	    while (*ptr != 0) *out++ = *ptr++;
	}
#if 0
	else {
	    /*
	     * default case, this is not a valid char !
	     * Skip it...
	     */
	    fprintf(stderr, "xmlEncodeEntities: invalid char %d\n", (int) *cur);
	}
#endif
	cur++;
    }
    *out++ = 0;
    return(buffer);
}

/*
 * Macro used to grow the current buffer.
 */
#define growBufferReentrant() {						\
    buffer_size *= 2;							\
    buffer = (xmlChar *)						\
    		xmlRealloc(buffer, buffer_size * sizeof(xmlChar));	\
    if (buffer == NULL) {						\
	perror("realloc failed");					\
	return(NULL);							\
    }									\
}


/**
 * xmlEncodeEntitiesReentrant:
 * @doc:  the document containing the string
 * @input:  A string to convert to XML.
 *
 * Do a global encoding of a string, replacing the predefined entities
 * and non ASCII values with their entities and CharRef counterparts.
 * Contrary to xmlEncodeEntities, this routine is reentrant, and result
 * must be deallocated.
 *
 * TODO !!!! Once moved to UTF-8 internal encoding, the encoding of non-ascii
 *           get erroneous.
 *
 * Returns A newly allocated string with the substitution done.
 */
xmlChar *
xmlEncodeEntitiesReentrant(xmlDocPtr doc, const xmlChar *input) {
    const xmlChar *cur = input;
    xmlChar *buffer = NULL;
    xmlChar *out = NULL;
    int buffer_size = 0;
    int html = 0;

    if (input == NULL) return(NULL);
    if (doc != NULL)
        html = (doc->type == XML_HTML_DOCUMENT_NODE);

    /*
     * allocate an translation buffer.
     */
    buffer_size = 1000;
    buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
	perror("malloc failed");
	return(NULL);
    }
    out = buffer;

    while (*cur != '\0') {
        if (out - buffer > buffer_size - 100) {
	    int index = out - buffer;

	    growBufferReentrant();
	    out = &buffer[index];
	}

	/*
	 * By default one have to encode at least '<', '>', '"' and '&' !
	 */
	if (*cur == '<') {
	    *out++ = '&';
	    *out++ = 'l';
	    *out++ = 't';
	    *out++ = ';';
	} else if (*cur == '>') {
	    *out++ = '&';
	    *out++ = 'g';
	    *out++ = 't';
	    *out++ = ';';
	} else if (*cur == '&') {
	    *out++ = '&';
	    *out++ = 'a';
	    *out++ = 'm';
	    *out++ = 'p';
	    *out++ = ';';
	} else if (*cur == '"') {
	    *out++ = '&';
	    *out++ = 'q';
	    *out++ = 'u';
	    *out++ = 'o';
	    *out++ = 't';
	    *out++ = ';';
#if 0
	} else if ((*cur == '\'') && (!html)) {
	    *out++ = '&';
	    *out++ = 'a';
	    *out++ = 'p';
	    *out++ = 'o';
	    *out++ = 's';
	    *out++ = ';';
#endif
	} else if (((*cur >= 0x20) && (*cur < 0x80)) ||
	    (*cur == '\n') || (*cur == '\r') || (*cur == '\t')) {
	    /*
	     * default case, just copy !
	     */
	    *out++ = *cur;
	} else if (*cur >= 0x80) {
	    if (html) {
		char buf[15], *ptr;

		/*
		 * TODO: improve by searching in html40EntitiesTable
		 */
#ifdef HAVE_SNPRINTF
		snprintf(buf, 9, "&#%d;", *cur);
#else
		sprintf(buf, "&#%d;", *cur);
#endif
		ptr = buf;
		while (*ptr != 0) *out++ = *ptr++;
	    } else if (doc->encoding != NULL) {
		/*
		 * TODO !!!
		 */
		*out++ = *cur;
	    } else {
		/*
		 * We assume we have UTF-8 input.
		 */
		char buf[10], *ptr;
		int val = 0, l = 1;

		if (*cur < 0xC0) {
		    fprintf(stderr,
			    "xmlEncodeEntitiesReentrant : input not UTF-8\n");
		    doc->encoding = xmlStrdup(BAD_CAST "ISO-8859-1");
#ifdef HAVE_SNPRINTF
		    snprintf(buf, 9, "&#%d;", *cur);
#else
		    sprintf(buf, "&#%d;", *cur);
#endif
		    ptr = buf;
		    while (*ptr != 0) *out++ = *ptr++;
		    continue;
		} else if (*cur < 0xE0) {
                    val = (cur[0]) & 0x1F;
		    val <<= 6;
		    val |= (cur[1]) & 0x3F;
		    l = 2;
		} else if (*cur < 0xF0) {
                    val = (cur[0]) & 0x0F;
		    val <<= 6;
		    val |= (cur[1]) & 0x3F;
		    val <<= 6;
		    val |= (cur[2]) & 0x3F;
		    l = 3;
		} else if (*cur < 0xF8) {
                    val = (cur[0]) & 0x07;
		    val <<= 6;
		    val |= (cur[1]) & 0x3F;
		    val <<= 6;
		    val |= (cur[2]) & 0x3F;
		    val <<= 6;
		    val |= (cur[3]) & 0x3F;
		    l = 4;
		}
		if ((l == 1) || (!IS_CHAR(val))) {
		    fprintf(stderr,
			"xmlEncodeEntitiesReentrant : char out of range\n");
		    doc->encoding = xmlStrdup(BAD_CAST "ISO-8859-1");
#ifdef HAVE_SNPRINTF
		    snprintf(buf, 9, "&#%d;", *cur);
#else
		    sprintf(buf, "&#%d;", *cur);
#endif
		    ptr = buf;
		    while (*ptr != 0) *out++ = *ptr++;
		    cur++;
		    continue;
		}
		/*
		 * We could do multiple things here. Just save as a char ref
		 */
#ifdef HAVE_SNPRINTF
		snprintf(buf, 14, "&#x%X;", val);
#else
		sprintf(buf, "&#x%X;", val);
#endif
		buf[14] = 0;
		ptr = buf;
		while (*ptr != 0) *out++ = *ptr++;
		cur += l;
		continue;
	    }
	} else if (IS_CHAR(*cur)) {
	    char buf[10], *ptr;

#ifdef HAVE_SNPRINTF
	    snprintf(buf, 9, "&#%d;", *cur);
#else
	    sprintf(buf, "&#%d;", *cur);
#endif
            ptr = buf;
	    while (*ptr != 0) *out++ = *ptr++;
	}
#if 0
	else {
	    /*
	     * default case, this is not a valid char !
	     * Skip it...
	     */
	    fprintf(stderr, "xmlEncodeEntities: invalid char %d\n", (int) *cur);
	}
#endif
	cur++;
    }
    *out++ = 0;
    return(buffer);
}

/**
 * xmlCreateEntitiesTable:
 *
 * create and initialize an empty entities hash table.
 *
 * Returns the xmlEntitiesTablePtr just created or NULL in case of error.
 */
xmlEntitiesTablePtr
xmlCreateEntitiesTable(void) {
    xmlEntitiesTablePtr ret;

    ret = (xmlEntitiesTablePtr) 
         xmlMalloc(sizeof(xmlEntitiesTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateEntitiesTable : xmlMalloc(%ld) failed\n",
	        (long)sizeof(xmlEntitiesTable));
        return(NULL);
    }
    ret->max_entities = XML_MIN_ENTITIES_TABLE;
    ret->nb_entities = 0;
    ret->table = (xmlEntityPtr *) 
         xmlMalloc(ret->max_entities * sizeof(xmlEntityPtr));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateEntitiesTable : xmlMalloc(%ld) failed\n",
	        ret->max_entities * (long)sizeof(xmlEntityPtr));
	xmlFree(ret);
        return(NULL);
    }
    return(ret);
}

/**
 * xmlFreeEntitiesTable:
 * @table:  An entity table
 *
 * Deallocate the memory used by an entities hash table.
 */
void
xmlFreeEntitiesTable(xmlEntitiesTablePtr table) {
    int i;

    if (table == NULL) return;

    for (i = 0;i < table->nb_entities;i++) {
        xmlFreeEntity(table->table[i]);
    }
    xmlFree(table->table);
    xmlFree(table);
}

/**
 * xmlCopyEntitiesTable:
 * @table:  An entity table
 *
 * Build a copy of an entity table.
 * 
 * Returns the new xmlEntitiesTablePtr or NULL in case of error.
 */
xmlEntitiesTablePtr
xmlCopyEntitiesTable(xmlEntitiesTablePtr table) {
    xmlEntitiesTablePtr ret;
    xmlEntityPtr cur, ent;
    int i;

    ret = (xmlEntitiesTablePtr) xmlMalloc(sizeof(xmlEntitiesTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCopyEntitiesTable: out of memory !\n");
	return(NULL);
    }
    ret->table = (xmlEntityPtr *) xmlMalloc(table->max_entities *
                                            sizeof(xmlEntityPtr));
    if (ret->table == NULL) {
        fprintf(stderr, "xmlCopyEntitiesTable: out of memory !\n");
	xmlFree(ret);
	return(NULL);
    }
    ret->max_entities = table->max_entities;
    ret->nb_entities = table->nb_entities;
    for (i = 0;i < ret->nb_entities;i++) {
	cur = (xmlEntityPtr) xmlMalloc(sizeof(xmlEntity));
	if (cur == NULL) {
	    fprintf(stderr, "xmlCopyEntityTable: out of memory !\n");
	    xmlFree(ret);
	    xmlFree(ret->table);
	    return(NULL);
	}
	memset(cur, 0, sizeof(xmlEntity));
	cur->type = XML_ELEMENT_DECL;
	ret->table[i] = cur;
	ent = table->table[i];

	cur->etype = ent->etype;
	if (ent->name != NULL)
	    cur->name = xmlStrdup(ent->name);
	if (ent->ExternalID != NULL)
	    cur->ExternalID = xmlStrdup(ent->ExternalID);
	if (ent->SystemID != NULL)
	    cur->SystemID = xmlStrdup(ent->SystemID);
	if (ent->content != NULL)
	    cur->content = xmlStrdup(ent->content);
	if (ent->orig != NULL)
	    cur->orig = xmlStrdup(ent->orig);
    }
    return(ret);
}

/**
 * xmlDumpEntityDecl:
 * @buf:  An XML buffer.
 * @ent:  An entity table
 *
 * This will dump the content of the entity table as an XML DTD definition
 */
void
xmlDumpEntityDecl(xmlBufferPtr buf, xmlEntityPtr ent) {
    switch (ent->etype) {
	case XML_INTERNAL_GENERAL_ENTITY:
	    xmlBufferWriteChar(buf, "<!ENTITY ");
	    xmlBufferWriteCHAR(buf, ent->name);
	    xmlBufferWriteChar(buf, " ");
	    if (ent->orig != NULL)
		xmlBufferWriteQuotedString(buf, ent->orig);
	    else
		xmlBufferWriteQuotedString(buf, ent->content);
	    xmlBufferWriteChar(buf, ">\n");
	    break;
	case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
	    xmlBufferWriteChar(buf, "<!ENTITY ");
	    xmlBufferWriteCHAR(buf, ent->name);
	    if (ent->ExternalID != NULL) {
		 xmlBufferWriteChar(buf, " PUBLIC ");
		 xmlBufferWriteQuotedString(buf, ent->ExternalID);
		 xmlBufferWriteChar(buf, " ");
		 xmlBufferWriteQuotedString(buf, ent->SystemID);
	    } else {
		 xmlBufferWriteChar(buf, " SYSTEM ");
		 xmlBufferWriteQuotedString(buf, ent->SystemID);
	    }
	    xmlBufferWriteChar(buf, ">\n");
	    break;
	case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
	    xmlBufferWriteChar(buf, "<!ENTITY ");
	    xmlBufferWriteCHAR(buf, ent->name);
	    if (ent->ExternalID != NULL) {
		 xmlBufferWriteChar(buf, " PUBLIC ");
		 xmlBufferWriteQuotedString(buf, ent->ExternalID);
		 xmlBufferWriteChar(buf, " ");
		 xmlBufferWriteQuotedString(buf, ent->SystemID);
	    } else {
		 xmlBufferWriteChar(buf, " SYSTEM ");
		 xmlBufferWriteQuotedString(buf, ent->SystemID);
	    }
	    if (ent->content != NULL) { /* Should be true ! */
		xmlBufferWriteChar(buf, " NDATA ");
		if (ent->orig != NULL)
		    xmlBufferWriteCHAR(buf, ent->orig);
		else
		    xmlBufferWriteCHAR(buf, ent->content);
	    }
	    xmlBufferWriteChar(buf, ">\n");
	    break;
	case XML_INTERNAL_PARAMETER_ENTITY:
	    xmlBufferWriteChar(buf, "<!ENTITY % ");
	    xmlBufferWriteCHAR(buf, ent->name);
	    xmlBufferWriteChar(buf, " ");
	    if (ent->orig == NULL)
		xmlBufferWriteQuotedString(buf, ent->content);
	    else
		xmlBufferWriteQuotedString(buf, ent->orig);
	    xmlBufferWriteChar(buf, ">\n");
	    break;
	case XML_EXTERNAL_PARAMETER_ENTITY:
	    xmlBufferWriteChar(buf, "<!ENTITY % ");
	    xmlBufferWriteCHAR(buf, ent->name);
	    if (ent->ExternalID != NULL) {
		 xmlBufferWriteChar(buf, " PUBLIC ");
		 xmlBufferWriteQuotedString(buf, ent->ExternalID);
		 xmlBufferWriteChar(buf, " ");
		 xmlBufferWriteQuotedString(buf, ent->SystemID);
	    } else {
		 xmlBufferWriteChar(buf, " SYSTEM ");
		 xmlBufferWriteQuotedString(buf, ent->SystemID);
	    }
	    xmlBufferWriteChar(buf, ">\n");
	    break;
	default:
	    fprintf(stderr,
		"xmlDumpEntitiesTable: internal: unknown type %d\n",
		    ent->etype);
    }
}

/**
 * xmlDumpEntitiesTable:
 * @buf:  An XML buffer.
 * @table:  An entity table
 *
 * This will dump the content of the entity table as an XML DTD definition
 */
void
xmlDumpEntitiesTable(xmlBufferPtr buf, xmlEntitiesTablePtr table) {
    int i;
    xmlEntityPtr cur;

    if (table == NULL) return;

    for (i = 0;i < table->nb_entities;i++) {
        cur = table->table[i];
	xmlDumpEntityDecl(buf, cur);
    }
}
