/*
 * valid.c : part of the code use to do the DTD handling and the validity
 *           checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "valid.h"
#include "parser.h"

/****************************************************************
 *								*
 *	Util functions for data allocation/deallocation		*
 *								*
 ****************************************************************/

/**
 * xmlNewElementContent:
 * @name:  the subelement name or NULL
 * @type:  the type of element content decl
 *
 * Allocate an element content structure.
 *
 * return values: NULL if not, othervise the new element content structure
 */
xmlElementContentPtr
xmlNewElementContent(CHAR *name, int type) {
    xmlElementContentPtr ret;

    switch(type) {
	case XML_ELEMENT_CONTENT_ELEMENT:
	    if (name == NULL) {
	        fprintf(stderr, "xmlNewElementContent : name == NULL !\n");
	    }
	    break;
        case XML_ELEMENT_CONTENT_PCDATA:
	case XML_ELEMENT_CONTENT_SEQ:
	case XML_ELEMENT_CONTENT_OR:
	    if (name != NULL) {
	        fprintf(stderr, "xmlNewElementContent : name != NULL !\n");
	    }
	    break;
	default:
	    fprintf(stderr, "xmlNewElementContent: unknown type %d\n", type);
	    exit(1);
    }
    ret = (xmlElementContentPtr) malloc(sizeof(xmlElementContent));
    if (ret == NULL) {
	fprintf(stderr, "xmlNewElementContent : out of memory!\n");
	return(NULL);
    }
    ret->type = type;
    ret->ocur = XML_ELEMENT_CONTENT_ONCE;
    if (name != NULL)
        ret->name = xmlStrdup(name);
    else
        ret->name = NULL;
    return(ret);
}

/**
 * xmlCopyElementContent:
 * @content:  An element content pointer.
 *
 * Build a copy of an element content description.
 * 
 * return values: the new xmlElementContentPtr or NULL in case of error.
 */
xmlElementContentPtr
xmlCopyElementContent(xmlElementContentPtr content) {
/* TODO !!! */
    return(NULL);
}

/**
 * xmlNewElementContent:
 * @name:  the subelement name or NULL
 * @type:  the type of element content decl
 *
 * Free an element content structure. This is a recursive call !
 */
void
xmlFreeElementContent(xmlElementContentPtr cur) {
/* TODO !!! */
}

/****************************************************************
 *								*
 *	Registration of DTD declarations			*
 *								*
 ****************************************************************/

/**
 * xmlCreateElementTable:
 *
 * create and initialize an empty element hash table.
 *
 * return values: the xmlElementTablePtr just created or NULL in case of error.
 */
xmlElementTablePtr
xmlCreateElementTable(void) {
    xmlElementTablePtr ret;

    ret = (xmlElementTablePtr) 
         malloc(sizeof(xmlElementTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateElementTable : malloc(%d) failed\n",
	        sizeof(xmlElementTable));
        return(NULL);
    }
    ret->max_elements = XML_MIN_ENTITIES_TABLE;
    ret->nb_elements = 0;
    ret->table = (xmlElementPtr ) 
         malloc(ret->max_elements * sizeof(xmlElement));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateElementTable : malloc(%d) failed\n",
	        ret->max_elements * sizeof(xmlElement));
	free(ret);
        return(NULL);
    }
    return(ret);
}


/**
 * xmlAddElementDecl:
 * @name:  the entity name
 *
 * Register a new element declaration
 *
 * return values: NULL if not, othervise the entity
 */
xmlElementPtr
xmlAddElementDecl(xmlDtdPtr dtd, char *name, int type, 
                  xmlElementContentPtr content) {
    xmlElementPtr ret, cur;
    xmlElementTablePtr table;
    int i;

    if (dtd == NULL) {
        fprintf(stderr, "xmlAddElementDecl: dtd == NULL\n");
	return(NULL);
    }
    if (name == NULL) {
        fprintf(stderr, "xmlAddElementDecl: name == NULL\n");
	return(NULL);
    }
    switch (type) {
        case XML_ELEMENT_TYPE_EMPTY:
	    if (content != NULL) {
	        fprintf(stderr,
		        "xmlAddElementDecl: content != NULL for EMPTY\n");
		return(NULL);
	    }
	    break;
	case XML_ELEMENT_TYPE_ANY:
	    if (content != NULL) {
	        fprintf(stderr,
		        "xmlAddElementDecl: content != NULL for ANY\n");
		return(NULL);
	    }
	    break;
	case XML_ELEMENT_TYPE_MIXED:
	    if (content == NULL) {
	        fprintf(stderr,
		        "xmlAddElementDecl: content == NULL for MIXED\n");
		return(NULL);
	    }
	    break;
	case XML_ELEMENT_TYPE_ELEMENT:
	    if (content == NULL) {
	        fprintf(stderr,
		        "xmlAddElementDecl: content == NULL for ELEMENT\n");
		return(NULL);
	    }
	    break;
	default:
	    fprintf(stderr, "xmlAddElementDecl: unknown type %d\n", type);
	    return(NULL);
    }

    /*
     * Create the Element table if needed.
     */
    table = dtd->elements;
    if (table == NULL) 
        table = dtd->elements = xmlCreateElementTable();
    if (table == NULL) {
	fprintf(stderr, "xmlAddElementDecl: Table creation failed!\n");
        return(NULL);
    }

    /*
     * Validity Check:
     * Search the DTD for previous declarations of the ELEMENT
     */
    for (i = 0;i < table->nb_elements;i++) {
        cur = &table->table[i];
	if (!xmlStrcmp(cur->name, name)) {
	    /*
	     * The element is already defined in this Dtd.
	     */
	    fprintf(stderr,
		    "xmlAddElementDecl: %s already defined\n", name);
	    return(NULL);
	}
    }

    /*
     * Grow the table, if needed.
     */
    if (table->nb_elements >= table->max_elements) {
        /*
	 * need more elements.
	 */
	table->max_elements *= 2;
	table->table = (xmlElementPtr) 
	    realloc(table->table, table->max_elements * sizeof(xmlElement));
	if (table->table) {
	    fprintf(stderr, "xmlAddElementDecl: out of memory\n");
	    return(NULL);
	}
    }
    ret = &table->table[table->nb_elements];

    /*
     * fill the structure.
     */
    ret->type = type;
    ret->name = xmlStrdup(name);
    ret->content = content;
    table->nb_elements++;

    return(ret);
}

/**
 * xmlFreeElement:
 * @elem:  An element
 *
 * Deallocate the memory used by an element definition
 */
void
xmlFreeElement(xmlElementPtr elem) {
    if (elem == NULL) return;
    xmlFreeElementContent(elem->content);
    if (elem->name != NULL)
	free((CHAR *) elem->name);
    memset(elem, -1, sizeof(xmlElement));
    free(elem);
}

/**
 * xmlFreeElementTable:
 * @table:  An element table
 *
 * Deallocate the memory used by an entities hash table.
 */
void
xmlFreeElementTable(xmlElementTablePtr table) {
    int i;

    if (table == NULL) return;

    for (i = 0;i < table->nb_elements;i++) {
        xmlFreeElement(&table->table[i]);
    }
    free(table->table);
    free(table);
}

/**
 * xmlCopyElementTable:
 * @table:  An element table
 *
 * Build a copy of an element table.
 * 
 * return values: the new xmlElementTablePtr or NULL in case of error.
 */
xmlElementTablePtr
xmlCopyElementTable(xmlElementTablePtr table) {
    xmlElementTablePtr ret;
    xmlElementPtr cur, ent;
    int i;

    ret = (xmlElementTablePtr) malloc(sizeof(xmlElementTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCopyElementTable: out of memory !\n");
	return(NULL);
    }
    ret->table = (xmlElementPtr) malloc(table->max_elements *
                                         sizeof(xmlElement));
    if (ret->table == NULL) {
        fprintf(stderr, "xmlCopyElementTable: out of memory !\n");
	free(ret);
	return(NULL);
    }
    ret->max_elements = table->max_elements;
    ret->nb_elements = table->nb_elements;
    for (i = 0;i < ret->nb_elements;i++) {
	cur = &ret->table[i];
	ent = &table->table[i];
	cur->type = ent->type;
	if (ent->name != NULL)
	    cur->name = xmlStrdup(ent->name);
	else
	    cur->name = NULL;
	cur->content = xmlCopyElementContent(ent->content);
    }
    return(ret);
}

/**
 * xmlDumpElementTable:
 * @table:  An element table
 *
 * This will dump the content of the element table as an XML DTD definition
 *
 * NOTE: TODO an extra parameter allowing a reentant implementation will
 *       be added.
 */
void
xmlDumpElementTable(xmlElementTablePtr table) {
    int i;
    xmlElementPtr cur;

    if (table == NULL) return;

    for (i = 0;i < table->nb_elements;i++) {
        cur = &table->table[i];
        switch (cur->type) {
	    case XML_ELEMENT_TYPE_EMPTY:
	        xmlBufferWriteChar("<!ELEMENT ");
		xmlBufferWriteCHAR(cur->name);
		xmlBufferWriteChar(" EMPTY>");
	        break;
	    case XML_ELEMENT_TYPE_ANY:
	        xmlBufferWriteChar("<!ELEMENT ");
		xmlBufferWriteCHAR(cur->name);
		xmlBufferWriteChar(" ANY>");
	        break;
	    case XML_ELEMENT_TYPE_MIXED:
		/* TODO !!! */
	        break;
	    case XML_ELEMENT_TYPE_ELEMENT:
		/* TODO !!! */
	        break;
	    default:
	        fprintf(stderr,
		    "xmlDumpElementTable: internal: unknown type %d\n",
		        cur->type);
	}
    }
}
