/*
 * entities.c : implementation for the XML entities handking
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#include <stdio.h>
#include <malloc.h>
#include <strings.h>
#include "xml_entities.h"

/*
 * A buffer used for converting entities to their equivalent and back.
 */
static CHAR *buffer = NULL;
static int buffer_size = 0;

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

    if (entity->value != NULL) free(entity->value);
    entity->value = NULL;
    if (entity->id != NULL)
	free((char *) entity->id);
}

/*
 * xmlAddDocEntity : register a new entity for an entities table.
 */
static void xmlAddEntity(xmlEntitiesTablePtr table, CHAR *value,
                         const CHAR *id) {
    int i;
    xmlEntityPtr cur;

    for (i = 0;i < table->nb_entities;i++) {
        cur = &table->table[i];
	if (!xmlStrcmp(cur->id, id)) {
	    free(cur->value);
	    cur->value = xmlStrdup(value);
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
    cur->value = xmlStrdup(value);
    cur->id = xmlStrdup(id);
    table->nb_entities++;
}


/*
 * xmlAddDtdEntity : register a new entity for this document.
 */
void xmlAddDtdEntity(xmlDtdPtr dtd, CHAR *value, const CHAR *id) {
    xmlEntitiesTablePtr table;

    table = (xmlEntitiesTablePtr) dtd->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	dtd->entities = table;
    }
    xmlAddEntity(table, value, id);
}

/*
 * xmlAddDocEntity : register a new entity for this document.
 */
void xmlAddDocEntity(xmlDocPtr doc, CHAR *value, const CHAR *id) {
    xmlEntitiesTablePtr table;

    table = (xmlEntitiesTablePtr) doc->entities;
    if (table == NULL) {
        table = xmlCreateEntitiesTable();
	doc->entities = table;
    }
    xmlAddEntity(table, value, id);
}

/*
 * xmlGetEntity : do an entity lookup in the hash table and
 *       returns the corrsponding CHAR *, if found, zero otherwise.
 */
CHAR *xmlGetEntity(xmlDocPtr doc, const CHAR *id) {
    int i;
    xmlEntityPtr cur;
    xmlEntitiesTablePtr table;

    if (doc->entities == NULL) return(0);
    table = (xmlEntitiesTablePtr) doc->entities;
    for (i = 0;i < table->nb_entities;i++) {
        cur = &table->table[i];
	if (!xmlStrcmp(cur->id, id)) return(cur->value);
    }
    return(NULL);
}

/*
 * xmlReadEntities : read an entity.
 */
const CHAR *xmlReadEntity(xmlDocPtr doc, const CHAR **input) {
    static CHAR *entity = NULL;
    static int entity_size = 100;
    const CHAR *cur = *input;

    if (entity == NULL) {
        entity = (CHAR *) malloc(entity_size * sizeof(CHAR));
	if (entity == NULL) {
	    fprintf(stderr, "xmlReadEntity : cannot allocate %d bytes\n",
	            entity_size * sizeof(CHAR));
            return(NULL);
	}
    }
    if (*cur == '&') {
        cur++;
	if (*cur == '#') {
	    /* TODO !!!! 
	    fprintf(stderr, "Character reference not yet implemented\n"); */
	} else {
	    /* TODO !!!! 
	    fprintf(stderr, "Entity search not yet implemented\n"); */
	}
    }

    /*
     * The few predefined entities.
     */
    if ((cur[0] == 'a') && (cur[1] == 'm') && (cur[2] == 'p') &&
        (cur[3] == ';')) {
        entity[0] = '%';
        entity[1] = 0;
	cur += 3;
	*input = cur;
        return(entity);
    } else if ((cur[0] == 'q') && (cur[1] == 'u') && (cur[2] == 'o') &&
        (cur[3] == 't') && (cur[4] == ';')) {
        entity[0] = '"';
        entity[1] = 0;
	cur += 4;
	*input = cur;
        return(entity);
    } else if ((cur[0] == 'a') && (cur[1] == 'p') && (cur[2] == 'o') &&
        (cur[3] == 's') && (cur[4] == ';')) {
        entity[0] = '\'';
        entity[1] = 0;
	cur += 4;
	*input = cur;
        return(entity);
    } else if ((cur[0] == 'l') && (cur[1] == 't') && (cur[2] == ';')) {
        entity[0] = '<';
        entity[1] = 0;
	cur += 2;
	*input = cur;
        return(entity);
    } else if ((cur[0] == 'g') && (cur[1] == 't') && (cur[2] == ';')) {
        entity[0] = '>';
        entity[1] = 0;
	cur += 2;
	*input = cur;
        return(entity);
    }

    return(NULL);
}

/*
 * xmlDecodeEntities : do a global entities lookup on a input string
 *        and returns a duplicate after the entities substitution.
 */
CHAR *xmlDecodeEntities(xmlDocPtr doc, const CHAR *input, int len) {
    const CHAR *cur = input;
    CHAR *out = buffer;
    int i;

    if (buffer == NULL) {
        buffer_size = 1000;
        buffer = (CHAR *) malloc(buffer_size * sizeof(CHAR));
	if (buffer == NULL) {
	    perror("malloc failed");
            exit(1);
	}
	out = buffer;
    }
    for (i = 0;(*cur != 0) && (cur - input < len);cur++) {
        if (*cur == '&') {
            const CHAR *entity = xmlReadEntity(doc, &cur);
	    if (entity != NULL)
	        while (*entity != 0) { 
		    *out++ = *entity++;
		    i++;
		    if (i + 10 > buffer_size) {
			int index = out - buffer;

			growBuffer();
			out = &buffer[index];
		    }
		}
	} else if (*cur == '%') {
	    /* TODO !!!!!
	    fprintf(stderr, " \n"); */
	} else {
	    *out++ = *cur;
	    i++;
	}

	if (i + 10 > buffer_size) {
	    int index = out - buffer;

	    growBuffer();
	    out = &buffer[index];
	}
    }
    *out++ = 0;
    return(buffer);
}

/*
 * xmlEncodeEntities : do a global encoding of a string, replacing the
 *                     basic values with their entities form.
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
	 * One could try a better encoding using the entities defined and
	 * used as a compression code !!!.
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

