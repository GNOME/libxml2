/*
 * entities.c : implementation for the XML entities handking
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "entities.h"

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
 * A buffer used for converting entities to their equivalent and back.
 */
static int buffer_size = 0;
static CHAR *buffer = NULL;

void growBuffer(void) {
    buffer_size *= 2;
    buffer = (CHAR *) realloc(buffer, buffer_size * sizeof(CHAR));
    if (buffer == NULL) {
	perror("realloc failed");
	exit(1);
    }
}

/*
 * xmlFreeEntity : clean-up an entity record.
 */

void xmlFreeEntity(xmlEntityPtr entity) {
    if (entity == NULL) return;

    if (entity->name != NULL)
	free((char *) entity->name);
    if (entity->ExternalID != NULL)
        free((char *) entity->ExternalID);
    if (entity->SystemID != NULL)
        free((char *) entity->SystemID);
    if (entity->content != NULL)
        free((char *) entity->content);
    memset(entity, -1, sizeof(xmlEntity));
}

/*
 * xmlAddDocEntity : register a new entity for an entities table.
 *
 * TODO !!! We should check here that the combination of type
 *          ExternalID and SystemID is valid.
 */
static void xmlAddEntity(xmlEntitiesTablePtr table, const CHAR *name, int type,
              const CHAR *ExternalID, const CHAR *SystemID, CHAR *content) {
    int i;
    xmlEntityPtr cur;
    int len;

    for (i = 0;i < table->nb_entities;i++) {
        cur = &table->table[i];
	if (!xmlStrcmp(cur->name, name)) {
	    /*
	     * The entity is already defined in this Dtd, the spec says to NOT
	     * override it ... Is it worth a Warning ??? !!!
	     */
	    return;
	}
    }
    if (table->nb_entities >= table->max_entities) {
        /*
	 * need more elements.
	 */
	table->max_entities *= 2;
	table->table = (xmlEntityPtr) 
	    realloc(table->table, table->max_entities * sizeof(xmlEntity));
	if (table->table) {
	    perror("realloc failed");
	    exit(1);
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
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else
        cur->content = NULL;
    table->nb_entities++;
}

/*
 * Set up xmlPredefinedEntities from xmlPredefinedEntityValues.
 */
void xmlInitializePredefinedEntities(void) {
    int i;
    CHAR name[50];
    CHAR value[50];
    const char *in;
    CHAR *out;

    if (xmlPredefinedEntities != NULL) return;

    xmlPredefinedEntities = xmlCreateEntitiesTable();
    for (i = 0;i < sizeof(xmlPredefinedEntityValues) / 
                   sizeof(xmlPredefinedEntityValues[0]);i++) {
        in = xmlPredefinedEntityValues[i].name;
	out = &name[0];
	for (;(*out++ = (CHAR) *in);)in++;
        in = xmlPredefinedEntityValues[i].value;
	out = &value[0];
	for (;(*out++ = (CHAR) *in);)in++;
        xmlAddEntity(xmlPredefinedEntities, (const CHAR *) &name[0],
	             XML_INTERNAL_PREDEFINED_ENTITY, NULL, NULL,
		     &value[0]);
    }
}

/**
 * xmlGetPredefinedEntity:
 * @name:  the entity name
 *
 * Check whether this name is an predefined entity.
 *
 * return values: NULL if not, othervise the entity
 */
xmlEntityPtr
xmlGetPredefinedEntity(const CHAR *name) {
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



/*
 * xmlAddDtdEntity : register a new entity for this DTD.
 */
void xmlAddDtdEntity(xmlDocPtr doc, const CHAR *name, int type,
              const CHAR *ExternalID, const CHAR *SystemID, CHAR *content) {
    xmlEntitiesTablePtr table;

    if (doc->dtd == NULL) {
        fprintf(stderr, "xmlAddDtdEntity: document without Dtd !\n");
	return;
    }
    table = (xmlEntitiesTablePtr) doc->dtd->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	doc->dtd->entities = table;
    }
    xmlAddEntity(table, name, type, ExternalID, SystemID, content);
}

/*
 * xmlAddDocEntity : register a new entity for this document.
 */
void xmlAddDocEntity(xmlDocPtr doc, const CHAR *name, int type,
              const CHAR *ExternalID, const CHAR *SystemID, CHAR *content) {
    xmlEntitiesTablePtr table;

    table = (xmlEntitiesTablePtr) doc->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	doc->entities = table;
    }
    xmlAddEntity(doc->entities, name, type, ExternalID, SystemID, content);
}

/*
 * xmlGetDtdEntity : do an entity lookup in the Dtd entity hash table and
 *       returns the corrsponding entity, if found, NULL otherwise.
 */
xmlEntityPtr xmlGetDtdEntity(xmlDocPtr doc, const CHAR *name) {
    int i;
    xmlEntityPtr cur;
    xmlEntitiesTablePtr table;

    if ((doc->dtd != NULL) && (doc->dtd->entities != NULL)) {
	table = (xmlEntitiesTablePtr) doc->dtd->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    if (!xmlStrcmp(cur->name, name)) return(cur);
	}
    }
    return(NULL);
}

/*
 * xmlGetDocEntity : do an entity lookup in the document entity hash table and
 *       returns the corrsponding entity, otherwise a lookup is done
 *       in the predefined entities too.
 */
xmlEntityPtr xmlGetDocEntity(xmlDocPtr doc, const CHAR *name) {
    int i;
    xmlEntityPtr cur;
    xmlEntitiesTablePtr table;

    if (doc->entities != NULL) {
	table = (xmlEntitiesTablePtr) doc->entities;
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    if (!xmlStrcmp(cur->name, name)) return(cur);
	}
    }
    if (xmlPredefinedEntities == NULL)
        xmlInitializePredefinedEntities();
    table = xmlPredefinedEntities;
    for (i = 0;i < table->nb_entities;i++) {
	cur = &table->table[i];
	if (!xmlStrcmp(cur->name, name)) return(cur);
    }

    return(NULL);
}

/*
 * xmlEncodeEntities : do a global encoding of a string, replacing the
 *                     predefined entities and non ASCII values with their
 *                     entities and CharRef counterparts.
 * TODO !!!! Once moved to UTF-8 internal encoding, the encoding of non-ascii
 *           get erroneous.
 */
CHAR *xmlEncodeEntities(xmlDocPtr doc, const CHAR *input) {
    const CHAR *cur = input;
    CHAR *out = buffer;

    if (buffer == NULL) {
        buffer_size = 1000;
        buffer = (CHAR *) malloc(buffer_size * sizeof(CHAR));
	if (buffer == NULL) {
	    perror("malloc failed");
            exit(1);
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
	} else if (*cur == '\'') {
	    *out++ = '&';
	    *out++ = 'a';
	    *out++ = 'p';
	    *out++ = 'o';
	    *out++ = 's';
	    *out++ = ';';
#ifndef USE_UTF_8
	} else if ((sizeof(CHAR) == 1) && (*cur >= 0x80)) {
	    char buf[10], *ptr;
	    g_snprintf(buf, 9, "&#%d;", *cur);
            ptr = buf;
	    while (*ptr != 0) *out++ = *ptr++;
#endif
	} else {
	    /*
	     * default case, just copy !
	     */
	    *out++ = *cur;
	}
	cur++;
    }
    *out++ = 0;
    return(buffer);
}

/*
 * xmlCreateEntitiesTable : create and initialize an enmpty hash table
 */
xmlEntitiesTablePtr xmlCreateEntitiesTable(void) {
    xmlEntitiesTablePtr ret;

    ret = (xmlEntitiesTablePtr) 
         malloc(sizeof(xmlEntitiesTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateEntitiesTable : malloc(%d) failed\n",
	        sizeof(xmlEntitiesTable));
        return(NULL);
    }
    ret->max_entities = XML_MIN_ENTITIES_TABLE;
    ret->nb_entities = 0;
    ret->table = (xmlEntityPtr ) 
         malloc(ret->max_entities * sizeof(xmlEntity));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateEntitiesTable : malloc(%d) failed\n",
	        ret->max_entities * sizeof(xmlEntity));
	free(ret);
        return(NULL);
    }
    return(ret);
}

/*
 * xmlFreeEntitiesTable : clean up and free an entities hash table.
 */
void xmlFreeEntitiesTable(xmlEntitiesTablePtr table) {
    int i;

    if (table == NULL) return;

    for (i = 0;i < table->nb_entities;i++) {
        xmlFreeEntity(&table->table[i]);
    }
    free(table->table);
    free(table);
}

/*
 * Dump the content of an entity table to the document output.
 */
void xmlDumpEntitiesTable(xmlEntitiesTablePtr table) {
    int i;
    xmlEntityPtr cur;

    if (table == NULL) return;

    for (i = 0;i < table->nb_entities;i++) {
        cur = &table->table[i];
        switch (cur->type) {
	    case XML_INTERNAL_GENERAL_ENTITY:
	        xmlBufferWriteChar("<!ENTITY ");
		xmlBufferWriteCHAR(cur->name);
		xmlBufferWriteChar(" \"");
		xmlBufferWriteCHAR(cur->content);
		xmlBufferWriteChar("\">\n");
	        break;
	    case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
	        xmlBufferWriteChar("<!ENTITY ");
		xmlBufferWriteCHAR(cur->name);
		if (cur->ExternalID != NULL) {
		     xmlBufferWriteChar(" PUBLIC \"");
		     xmlBufferWriteCHAR(cur->ExternalID);
		     xmlBufferWriteChar("\" \"");
		     xmlBufferWriteCHAR(cur->SystemID);
		     xmlBufferWriteChar("\"");
		} else {
		     xmlBufferWriteChar(" SYSTEM \"");
		     xmlBufferWriteCHAR(cur->SystemID);
		     xmlBufferWriteChar("\"");
		}
		xmlBufferWriteChar(">\n");
	        break;
	    case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
	        xmlBufferWriteChar("<!ENTITY ");
		xmlBufferWriteCHAR(cur->name);
		if (cur->ExternalID != NULL) {
		     xmlBufferWriteChar(" PUBLIC \"");
		     xmlBufferWriteCHAR(cur->ExternalID);
		     xmlBufferWriteChar("\" \"");
		     xmlBufferWriteCHAR(cur->SystemID);
		     xmlBufferWriteChar("\"");
		} else {
		     xmlBufferWriteChar(" SYSTEM \"");
		     xmlBufferWriteCHAR(cur->SystemID);
		     xmlBufferWriteChar("\"");
		}
		if (cur->content != NULL) { /* Should be true ! */
		    xmlBufferWriteChar(" NDATA ");
		    xmlBufferWriteCHAR(cur->content);
		}
		xmlBufferWriteChar(">\n");
	        break;
	    case XML_INTERNAL_PARAMETER_ENTITY:
	        xmlBufferWriteChar("<!ENTITY % ");
		xmlBufferWriteCHAR(cur->name);
		xmlBufferWriteChar(" \"");
		xmlBufferWriteCHAR(cur->content);
		xmlBufferWriteChar("\">\n");
	        break;
	    case XML_EXTERNAL_PARAMETER_ENTITY:
	        xmlBufferWriteChar("<!ENTITY % ");
		xmlBufferWriteCHAR(cur->name);
		if (cur->ExternalID != NULL) {
		     xmlBufferWriteChar(" PUBLIC \"");
		     xmlBufferWriteCHAR(cur->ExternalID);
		     xmlBufferWriteChar("\" \"");
		     xmlBufferWriteCHAR(cur->SystemID);
		     xmlBufferWriteChar("\"");
		} else {
		     xmlBufferWriteChar(" SYSTEM \"");
		     xmlBufferWriteCHAR(cur->SystemID);
		     xmlBufferWriteChar("\"");
		}
		xmlBufferWriteChar(">\n");
	        break;
	    default:
	        fprintf(stderr,
		    "xmlDumpEntitiesTable: internal: unknown type %d\n",
		        cur->type);
	}
    }
}
