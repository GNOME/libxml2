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
    ret->name = xmlStrdup(name);
    return(ret);
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
    xmlElementPtr ret;

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
     * Validity Check:
     * Search the DTD for previous declarations of the ELEMENT
     */
    /* TODO */

    /*
     * Create and fill the structure.
     */
    ret = (xmlElementPtr) malloc(sizeof(xmlElement));
    if (ret == NULL) {
        fprintf(stderr, "xmlAddElementDecl: out of memory\n");
	return(NULL);
    }
    ret->type = type;
    ret->name = xmlStrdup(name);
    ret->content = content;

    /*
     * Insert the structure in the DTD Element table
     */
    /* TODO */

    return(ret);
}

