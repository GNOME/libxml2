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
#include "xmlmemory.h"
#include "entities.h"
#include "parser.h"

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
    /* 2.3.5 */
    if (entity->children != NULL)
	xmlFreeNodeList(entity->children);
    if (entity->URI != NULL)
	xmlFree((char *)entity->URI);
    memset(entity, -1, sizeof(xmlEntity));
}

/*
 * xmlAddEntity : register a new entity for an entities table.
 */
static void
xmlAddEntity(xmlEntitiesTablePtr table, const xmlChar *name, int type,
	  const xmlChar *ExternalID, const xmlChar *SystemID, const xmlChar *content) {
    int i;
    xmlEntityPtr cur;
    int len;

    for (i = 0;i < table->nb_entities;i++) {
        cur = &table->table[i];
	if (!xmlStrcmp(cur->name, name)) {
	    /*
	     * The entity is already defined in this Dtd, the spec says to NOT
	     * override it ... Is it worth a Warning ??? !!!
	     * Not having a cprinting context this seems hard ...
	     */
	    if (((type == XML_INTERNAL_PARAMETER_ENTITY) ||
	         (type == XML_EXTERNAL_PARAMETER_ENTITY)) &&
	        ((cur->type == XML_INTERNAL_PARAMETER_ENTITY) ||
	         (cur->type == XML_EXTERNAL_PARAMETER_ENTITY)))
		return;
	    else
	    if (((type != XML_INTERNAL_PARAMETER_ENTITY) &&
	         (type != XML_EXTERNAL_PARAMETER_ENTITY)) &&
	        ((cur->type != XML_INTERNAL_PARAMETER_ENTITY) &&
	         (cur->type != XML_EXTERNAL_PARAMETER_ENTITY)))
		return;
	}
    }
    if (table->nb_entities >= table->max_entities) {
        /*
	 * need more elements.
	 */
	table->max_entities *= 2;
	table->table = (xmlEntityPtr) 
	    xmlRealloc(table->table, table->max_entities * sizeof(xmlEntity));
	if (table->table == NULL) {
	    perror("realloc failed");
	    return;
	}
    }
    cur = &table->table[table->nb_entities];
    cur->name = xmlStrdup(name);
    for (len = 0;name[0] != 0;name++)len++;
    cur->len = len;
    cur->type = type;
    if (ExternalID != NULL)
	cur->ExternalID = xmlStrdup(ExternalID);
    else
        cur->ExternalID = NULL;
    if (SystemID != NULL)
	cur->SystemID = xmlStrdup(SystemID);
    else
        cur->SystemID = NULL;
    if (content != NULL) {
        cur->length = xmlStrlen(content);
	cur->content = xmlStrndup(content, cur->length);
     } else {
        cur->length = 0;
        cur->content = NULL;
    }
    cur->orig = NULL;

    /* 2.3.5 */
    cur->children = NULL;
    cur->last = NULL;
    cur->URI = NULL;
    table->nb_entities++;
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
	cur = &xmlPredefinedEntities->table[i];
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
 * Register a new entity for this document DTD.
 */
void
xmlAddDtdEntity(xmlDocPtr doc, const xmlChar *name, int type,
	  const xmlChar *ExternalID, const xmlChar *SystemID, const xmlChar *content) {
    xmlEntitiesTablePtr table;

    if (doc->extSubset == NULL) {
        fprintf(stderr,
	        "xmlAddDtdEntity: document without external subset !\n");
	return;
    }
    table = (xmlEntitiesTablePtr) doc->extSubset->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	doc->extSubset->entities = table;
    }
    xmlAddEntity(table, name, type, ExternalID, SystemID, content);
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
 */
void
xmlAddDocEntity(xmlDocPtr doc, const xmlChar *name, int type,
	  const xmlChar *ExternalID, const xmlChar *SystemID, const xmlChar *content) {
    xmlEntitiesTablePtr table;

    if (doc == NULL) {
        fprintf(stderr,
	        "xmlAddDocEntity: document is NULL !\n");
	return;
    }
    if (doc->intSubset == NULL) {
        fprintf(stderr,
	        "xmlAddDtdEntity: document without internal subset !\n");
	return;
    }
    table = (xmlEntitiesTablePtr) doc->intSubset->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	doc->intSubset->entities = table;
    }
    xmlAddEntity(table, name, type, ExternalID, SystemID, content);
}

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

    if (doc == NULL)
	return(NULL);

    if ((doc->intSubset != NULL) && (doc->intSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->intSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    if (((cur->type ==  XML_INTERNAL_PARAMETER_ENTITY) ||
	         (cur->type ==  XML_EXTERNAL_PARAMETER_ENTITY)) &&
		(!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    if (((cur->type ==  XML_INTERNAL_PARAMETER_ENTITY) ||
	         (cur->type ==  XML_EXTERNAL_PARAMETER_ENTITY)) &&
		(!xmlStrcmp(cur->name, name))) return(cur);
	}
    }
    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    if (((cur->type ==  XML_INTERNAL_PARAMETER_ENTITY) ||
	         (cur->type ==  XML_EXTERNAL_PARAMETER_ENTITY)) &&
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

    if (doc == NULL)
	return(NULL);

    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    if ((cur->type !=  XML_INTERNAL_PARAMETER_ENTITY) &&
	        (cur->type !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
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

    if (doc != NULL) {
	if ((doc->intSubset != NULL) && (doc->intSubset->entities != NULL)) {
	    table = (xmlEntitiesTablePtr) doc->intSubset->entities;
	    for (i = 0;i < table->nb_entities;i++) {
		cur = &table->table[i];
		if ((cur->type !=  XML_INTERNAL_PARAMETER_ENTITY) &&
		    (cur->type !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
		    (!xmlStrcmp(cur->name, name))) return(cur);
	    }
	}
	if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
	    table = (xmlEntitiesTablePtr) doc->extSubset->entities;
	    for (i = 0;i < table->nb_entities;i++) {
		cur = &table->table[i];
		if ((cur->type !=  XML_INTERNAL_PARAMETER_ENTITY) &&
		    (cur->type !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
		    (!xmlStrcmp(cur->name, name))) return(cur);
	    }
	}
    }
    if (xmlPredefinedEntities == NULL)
        xmlInitializePredefinedEntities();
    table = xmlPredefinedEntities;
    for (i = 0;i < table->nb_entities;i++) {
	cur = &table->table[i];
	if ((cur->type !=  XML_INTERNAL_PARAMETER_ENTITY) &&
	    (cur->type !=  XML_EXTERNAL_PARAMETER_ENTITY) &&
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
    fprintf(stderr,
	    "Deprecated API xmlEncodeEntities() used\n");
    fprintf(stderr,
	    "   change code to use xmlEncodeEntitiesReentrant()\n");
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
	    snprintf(buf, sizeof(buf), "&#%d;", *cur);
#else
	    sprintf(buf, "&#%d;", *cur);
#endif
            buf[sizeof(buf) - 1] = 0;
            ptr = buf;
	    while (*ptr != 0) *out++ = *ptr++;
#endif
	} else if (IS_CHAR(*cur)) {
	    char buf[10], *ptr;

#ifdef HAVE_SNPRINTF
	    snprintf(buf, sizeof(buf), "&#%d;", *cur);
#else
	    sprintf(buf, "&#%d;", *cur);
#endif
            buf[sizeof(buf) - 1] = 0;
            ptr = buf;
	    while (*ptr != 0) *out++ = *ptr++;
	}
#if 0
	else {
	    /*
	     * default case, this is not a valid char !
	     * Skip it...
	     */
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlEncodeEntities: invalid char %d\n", (int) *cur);
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
		char buf[10], *ptr;

#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf), "&#%d;", *cur);
#else
		sprintf(buf, "&#%d;", *cur);
#endif
		buf[sizeof(buf) - 1] = 0;
		ptr = buf;
		while (*ptr != 0) *out++ = *ptr++;
	    } else if ((doc != NULL) && (doc->encoding != NULL) &&
		       (xmlStrEqual(doc->encoding, "UTF-8"))) {
		/*
		 * We assume we have UTF-8 input.
		 */
		char buf[10], *ptr;
		int val = 0, l = 1;

		if (*cur < 0xC0) {
		    fprintf(stderr,
			    "xmlEncodeEntitiesReentrant : input not UTF-8\n");
#ifdef HAVE_SNPRINTF
		    snprintf(buf, sizeof(buf), "&#%d;", *cur);
#else
		    sprintf(buf, "&#%d;", *cur);
#endif
		    buf[sizeof(buf) - 1] = 0;
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
#ifdef HAVE_SNPRINTF
		    snprintf(buf, sizeof(buf), "&#%d;", *cur);
#else
		    sprintf(buf, "&#%d;", *cur);
#endif
		    buf[sizeof(buf) - 1] = 0;
		    ptr = buf;
		    while (*ptr != 0) *out++ = *ptr++;
		    cur++;
		    continue;
		}
		/*
		 * We could do multiple things here. Just save as a char ref
		 */
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf), "&#%d;", val);
#else
		sprintf(buf, "&#%d;", val);
#endif
		buf[sizeof(buf) - 1] = 0;
		ptr = buf;
		while (*ptr != 0) *out++ = *ptr++;
		cur += l;
		continue;
	    } else {
		/*
		 * We are using the old parser
		 */
		char buf[10], *ptr;

#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf), "&#%d;", *cur);
#else
		sprintf(buf, "&#%d;", *cur);
#endif
		buf[sizeof(buf) - 1] = 0;
		ptr = buf;
		while (*ptr != 0) *out++ = *ptr++;
	    }
	} else if (IS_CHAR(*cur)) {
	    char buf[10], *ptr;

#ifdef HAVE_SNPRINTF
	    snprintf(buf, sizeof(buf), "&#%d;", *cur);
#else
	    sprintf(buf, "&#%d;", *cur);
#endif
	    buf[sizeof(buf) - 1] = 0;
            ptr = buf;
	    while (*ptr != 0) *out++ = *ptr++;
	}
#if 0
	else {
	    /*
	     * default case, this is not a valid char !
	     * Skip it...
	     */
	    xmlGenericError(xmlGenericErrorContext,
		    "xmlEncodeEntities: invalid char %d\n", (int) *cur);
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
    ret->table = (xmlEntityPtr ) 
         xmlMalloc(ret->max_entities * sizeof(xmlEntity));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateEntitiesTable : xmlMalloc(%ld) failed\n",
	        ret->max_entities * (long)sizeof(xmlEntity));
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
        xmlFreeEntity(&table->table[i]);
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
    ret->table = (xmlEntityPtr) xmlMalloc(table->max_entities *
                                         sizeof(xmlEntity));
    if (ret->table == NULL) {
        fprintf(stderr, "xmlCopyEntitiesTable: out of memory !\n");
	xmlFree(ret);
	return(NULL);
    }
    ret->max_entities = table->max_entities;
    ret->nb_entities = table->nb_entities;
    for (i = 0;i < ret->nb_entities;i++) {
	cur = &ret->table[i];
	ent = &table->table[i];
	cur->len = ent->len;
	cur->type = ent->type;
	if (ent->name != NULL)
	    cur->name = xmlStrdup(ent->name);
	else
	    cur->name = NULL;
	if (ent->ExternalID != NULL)
	    cur->ExternalID = xmlStrdup(ent->ExternalID);
	else
	    cur->ExternalID = NULL;
	if (ent->SystemID != NULL)
	    cur->SystemID = xmlStrdup(ent->SystemID);
	else
	    cur->SystemID = NULL;
	if (ent->content != NULL)
	    cur->content = xmlStrdup(ent->content);
	else
	    cur->content = NULL;
	if (ent->orig != NULL)
	    cur->orig = xmlStrdup(ent->orig);
	else
	    cur->orig = NULL;
    }
    return(ret);
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
        cur = &table->table[i];
        switch (cur->type) {
	    case XML_INTERNAL_GENERAL_ENTITY:
	        xmlBufferWriteChar(buf, "<!ENTITY ");
		xmlBufferWriteCHAR(buf, cur->name);
		xmlBufferWriteChar(buf, " ");
		if (cur->orig != NULL)
		    xmlBufferWriteQuotedString(buf, cur->orig);
		else
		    xmlBufferWriteQuotedString(buf, cur->content);
		xmlBufferWriteChar(buf, ">\n");
	        break;
	    case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
	        xmlBufferWriteChar(buf, "<!ENTITY ");
		xmlBufferWriteCHAR(buf, cur->name);
		if (cur->ExternalID != NULL) {
		     xmlBufferWriteChar(buf, " PUBLIC ");
		     xmlBufferWriteQuotedString(buf, cur->ExternalID);
		     xmlBufferWriteChar(buf, " ");
		     xmlBufferWriteQuotedString(buf, cur->SystemID);
		} else {
		     xmlBufferWriteChar(buf, " SYSTEM ");
		     xmlBufferWriteQuotedString(buf, cur->SystemID);
		}
		xmlBufferWriteChar(buf, ">\n");
	        break;
	    case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
	        xmlBufferWriteChar(buf, "<!ENTITY ");
		xmlBufferWriteCHAR(buf, cur->name);
		if (cur->ExternalID != NULL) {
		     xmlBufferWriteChar(buf, " PUBLIC ");
		     xmlBufferWriteQuotedString(buf, cur->ExternalID);
		     xmlBufferWriteChar(buf, " ");
		     xmlBufferWriteQuotedString(buf, cur->SystemID);
		} else {
		     xmlBufferWriteChar(buf, " SYSTEM ");
		     xmlBufferWriteQuotedString(buf, cur->SystemID);
		}
		if (cur->content != NULL) { /* Should be true ! */
		    xmlBufferWriteChar(buf, " NDATA ");
		    if (cur->orig != NULL)
			xmlBufferWriteCHAR(buf, cur->orig);
		    else
			xmlBufferWriteCHAR(buf, cur->content);
		}
		xmlBufferWriteChar(buf, ">\n");
	        break;
	    case XML_INTERNAL_PARAMETER_ENTITY:
	        xmlBufferWriteChar(buf, "<!ENTITY % ");
		xmlBufferWriteCHAR(buf, cur->name);
		xmlBufferWriteChar(buf, " ");
		if (cur->orig == NULL)
		    xmlBufferWriteQuotedString(buf, cur->content);
		else
		    xmlBufferWriteQuotedString(buf, cur->orig);
		xmlBufferWriteChar(buf, ">\n");
	        break;
	    case XML_EXTERNAL_PARAMETER_ENTITY:
	        xmlBufferWriteChar(buf, "<!ENTITY % ");
		xmlBufferWriteCHAR(buf, cur->name);
		if (cur->ExternalID != NULL) {
		     xmlBufferWriteChar(buf, " PUBLIC ");
		     xmlBufferWriteQuotedString(buf, cur->ExternalID);
		     xmlBufferWriteChar(buf, " ");
		     xmlBufferWriteQuotedString(buf, cur->SystemID);
		} else {
		     xmlBufferWriteChar(buf, " SYSTEM ");
		     xmlBufferWriteQuotedString(buf, cur->SystemID);
		}
		xmlBufferWriteChar(buf, ">\n");
	        break;
	    default:
	        fprintf(stderr,
		    "xmlDumpEntitiesTable: internal: unknown type %d\n",
		        cur->type);
	}
    }
}
