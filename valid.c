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
 * Returns NULL if not, othervise the new element content structure
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
    ret->c1 = ret->c2 = NULL;
    return(ret);
}

/**
 * xmlCopyElementContent:
 * @content:  An element content pointer.
 *
 * Build a copy of an element content description.
 * 
 * Returns the new xmlElementContentPtr or NULL in case of error.
 */
xmlElementContentPtr
xmlCopyElementContent(xmlElementContentPtr cur) {
    xmlElementContentPtr ret;

    if (cur == NULL) return(NULL);
    ret = xmlNewElementContent((CHAR *) cur->name, cur->type);
    if (cur->c1 != NULL) cur->c1 = xmlCopyElementContent(cur->c1);
    if (cur->c2 != NULL) cur->c2 = xmlCopyElementContent(cur->c2);
    return(ret);
}

/**
 * xmlFreeElementContent:
 * @cur:  the element content tree to free
 *
 * Free an element content structure. This is a recursive call !
 */
void
xmlFreeElementContent(xmlElementContentPtr cur) {
    if (cur == NULL) return;
    if (cur->c1 != NULL) xmlFreeElementContent(cur->c1);
    if (cur->c2 != NULL) xmlFreeElementContent(cur->c2);
    if (cur->name != NULL) free((CHAR *) cur->name);
    memset(cur, -1, sizeof(xmlElementContent));
    free(cur);
}

/**
 * xmlDumpElementContent:
 * @buf:  An XML buffer
 * @content:  An element table
 * @glob: 1 if one must print the englobing parenthesis, 0 otherwise
 *
 * This will dump the content of the element table as an XML DTD definition
 */
void
xmlDumpElementContent(xmlBufferPtr buf, xmlElementContentPtr content, int glob) {
    if (content == NULL) return;

    if (glob) xmlBufferWriteChar(buf, "(");
    switch (content->type) {
        case XML_ELEMENT_CONTENT_PCDATA:
            xmlBufferWriteChar(buf, "#PCDATA");
	    break;
	case XML_ELEMENT_CONTENT_ELEMENT:
	    xmlBufferWriteCHAR(buf, content->name);
	    break;
	case XML_ELEMENT_CONTENT_SEQ:
	    if ((content->c1->type == XML_ELEMENT_CONTENT_OR) ||
	        (content->c1->type == XML_ELEMENT_CONTENT_SEQ))
		xmlDumpElementContent(buf, content->c1, 1);
	    else
		xmlDumpElementContent(buf, content->c1, 0);
            xmlBufferWriteChar(buf, " , ");
	    if (content->c2->type == XML_ELEMENT_CONTENT_OR)
		xmlDumpElementContent(buf, content->c2, 1);
	    else
		xmlDumpElementContent(buf, content->c2, 0);
	    break;
	case XML_ELEMENT_CONTENT_OR:
	    if ((content->c1->type == XML_ELEMENT_CONTENT_OR) ||
	        (content->c1->type == XML_ELEMENT_CONTENT_SEQ))
		xmlDumpElementContent(buf, content->c1, 1);
	    else
		xmlDumpElementContent(buf, content->c1, 0);
            xmlBufferWriteChar(buf, " | ");
	    if (content->c2->type == XML_ELEMENT_CONTENT_SEQ)
		xmlDumpElementContent(buf, content->c2, 1);
	    else
		xmlDumpElementContent(buf, content->c2, 0);
	    break;
	default:
	    fprintf(stderr, "xmlDumpElementContent: unknown type %d\n",
	            content->type);
    }
    if (glob)
        xmlBufferWriteChar(buf, ")");
    switch (content->ocur) {
        case XML_ELEMENT_CONTENT_ONCE:
	    break;
        case XML_ELEMENT_CONTENT_OPT:
	    xmlBufferWriteChar(buf, "?");
	    break;
        case XML_ELEMENT_CONTENT_MULT:
	    xmlBufferWriteChar(buf, "*");
	    break;
        case XML_ELEMENT_CONTENT_PLUS:
	    xmlBufferWriteChar(buf, "+");
	    break;
    }
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
 * Returns the xmlElementTablePtr just created or NULL in case of error.
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
    ret->max_elements = XML_MIN_ELEMENT_TABLE;
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
 * @dtd:  pointer to the DTD
 * @name:  the entity name
 * @type:  the element type
 * @content:  the element content tree or NULL
 *
 * Register a new element declaration
 *
 * Returns NULL if not, othervise the entity
 */
xmlElementPtr
xmlAddElementDecl(xmlDtdPtr dtd, const CHAR *name, int type, 
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
}

/**
 * xmlFreeElementTable:
 * @table:  An element table
 *
 * Deallocate the memory used by an element hash table.
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
 * Returns the new xmlElementTablePtr or NULL in case of error.
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
 * @buf:  the XML buffer output
 * @table:  An element table
 *
 * This will dump the content of the element table as an XML DTD definition
 */
void
xmlDumpElementTable(xmlBufferPtr buf, xmlElementTablePtr table) {
    int i;
    xmlElementPtr cur;

    if (table == NULL) return;

    for (i = 0;i < table->nb_elements;i++) {
        cur = &table->table[i];
        switch (cur->type) {
	    case XML_ELEMENT_TYPE_EMPTY:
	        xmlBufferWriteChar(buf, "<!ELEMENT ");
		xmlBufferWriteCHAR(buf, cur->name);
		xmlBufferWriteChar(buf, " EMPTY>\n");
	        break;
	    case XML_ELEMENT_TYPE_ANY:
	        xmlBufferWriteChar(buf, "<!ELEMENT ");
		xmlBufferWriteCHAR(buf, cur->name);
		xmlBufferWriteChar(buf, " ANY>\n");
	        break;
	    case XML_ELEMENT_TYPE_MIXED:
	        xmlBufferWriteChar(buf, "<!ELEMENT ");
		xmlBufferWriteCHAR(buf, cur->name);
		xmlBufferWriteChar(buf, " ");
		xmlDumpElementContent(buf, cur->content, 1);
		xmlBufferWriteChar(buf, ">\n");
	        break;
	    case XML_ELEMENT_TYPE_ELEMENT:
	        xmlBufferWriteChar(buf, "<!ELEMENT ");
		xmlBufferWriteCHAR(buf, cur->name);
		xmlBufferWriteChar(buf, " ");
		xmlDumpElementContent(buf, cur->content, 1);
		xmlBufferWriteChar(buf, ">\n");
	        break;
	    default:
	        fprintf(stderr,
		    "xmlDumpElementTable: internal: unknown type %d\n",
		        cur->type);
	}
    }
}

/**
 * xmlCreateEnumeration:
 * @name:  the enumeration name or NULL
 *
 * create and initialize an enumeration attribute node.
 *
 * Returns the xmlEnumerationPtr just created or NULL in case
 *                of error.
 */
xmlEnumerationPtr
xmlCreateEnumeration(CHAR *name) {
    xmlEnumerationPtr ret;

    ret = (xmlEnumerationPtr) malloc(sizeof(xmlEnumeration));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateEnumeration : malloc(%d) failed\n",
	        sizeof(xmlEnumeration));
        return(NULL);
    }

    if (name != NULL)
        ret->name = xmlStrdup(name);
    else
        ret->name = NULL;
    ret->next = NULL;
    return(ret);
}

/**
 * xmlFreeEnumeration:
 * @cur:  the tree to free.
 *
 * free an enumeration attribute node (recursive).
 */
void
xmlFreeEnumeration(xmlEnumerationPtr cur) {
    if (cur == NULL) return;

    if (cur->next != NULL) xmlFreeEnumeration(cur->next);

    if (cur->name != NULL) free((CHAR *) cur->name);
    memset(cur, -1, sizeof(xmlEnumeration));
    free(cur);
}

/**
 * xmlCopyEnumeration:
 * @cur:  the tree to copy.
 *
 * Copy an enumeration attribute node (recursive).
 *
 * Returns the xmlEnumerationPtr just created or NULL in case
 *                of error.
 */
xmlEnumerationPtr
xmlCopyEnumeration(xmlEnumerationPtr cur) {
    xmlEnumerationPtr ret;

    if (cur == NULL) return(NULL);
    ret = xmlCreateEnumeration((CHAR *) cur->name);

    if (cur->next != NULL) ret->next = xmlCopyEnumeration(cur->next);
    else ret->next = NULL;

    return(ret);
}

/**
 * xmlCreateAttributeTable:
 *
 * create and initialize an empty attribute hash table.
 *
 * Returns the xmlAttributeTablePtr just created or NULL in case
 *                of error.
 */
xmlAttributeTablePtr
xmlCreateAttributeTable(void) {
    xmlAttributeTablePtr ret;

    ret = (xmlAttributeTablePtr) 
         malloc(sizeof(xmlAttributeTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateAttributeTable : malloc(%d) failed\n",
	        sizeof(xmlAttributeTable));
        return(NULL);
    }
    ret->max_attributes = XML_MIN_ATTRIBUTE_TABLE;
    ret->nb_attributes = 0;
    ret->table = (xmlAttributePtr ) 
         malloc(ret->max_attributes * sizeof(xmlAttribute));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateAttributeTable : malloc(%d) failed\n",
	        ret->max_attributes * sizeof(xmlAttribute));
	free(ret);
        return(NULL);
    }
    return(ret);
}


/**
 * xmlAddAttributeDecl:
 * @dtd:  pointer to the DTD
 * @elem:  the element name
 * @name:  the attribute name
 * @type:  the attribute type
 * @def:  the attribute default type
 * @defaultValue:  the attribute default value
 * @tree:  if it's an enumeration, the associated list
 *
 * Register a new attribute declaration
 *
 * Returns NULL if not, othervise the entity
 */
xmlAttributePtr
xmlAddAttributeDecl(xmlDtdPtr dtd, const CHAR *elem, const CHAR *name,
                    int type, int def, const CHAR *defaultValue,
		    xmlEnumerationPtr tree) {
    xmlAttributePtr ret, cur;
    xmlAttributeTablePtr table;
    int i;

    if (dtd == NULL) {
        fprintf(stderr, "xmlAddAttributeDecl: dtd == NULL\n");
	return(NULL);
    }
    if (name == NULL) {
        fprintf(stderr, "xmlAddAttributeDecl: name == NULL\n");
	return(NULL);
    }
    if (elem == NULL) {
        fprintf(stderr, "xmlAddAttributeDecl: elem == NULL\n");
	return(NULL);
    }
    /* TODO: Lacks verifications !!! */
    switch (type) {
        case XML_ATTRIBUTE_CDATA:
	    break;
        case XML_ATTRIBUTE_ID:
	    break;
        case XML_ATTRIBUTE_IDREF:
	    break;
        case XML_ATTRIBUTE_IDREFS:
	    break;
        case XML_ATTRIBUTE_ENTITY:
	    break;
        case XML_ATTRIBUTE_ENTITIES:
	    break;
        case XML_ATTRIBUTE_NMTOKEN:
	    break;
        case XML_ATTRIBUTE_NMTOKENS:
	    break;
        case XML_ATTRIBUTE_ENUMERATION:
	    break;
        case XML_ATTRIBUTE_NOTATION:
	    break;
	default:
	    fprintf(stderr, "xmlAddAttributeDecl: unknown type %d\n", type);
	    return(NULL);
    }

    /*
     * Create the Attribute table if needed.
     */
    table = dtd->attributes;
    if (table == NULL) 
        table = dtd->attributes = xmlCreateAttributeTable();
    if (table == NULL) {
	fprintf(stderr, "xmlAddAttributeDecl: Table creation failed!\n");
        return(NULL);
    }

    /*
     * Validity Check:
     * Search the DTD for previous declarations of the ATTLIST
     */
    for (i = 0;i < table->nb_attributes;i++) {
        cur = &table->table[i];
	if ((!xmlStrcmp(cur->name, name)) && (!xmlStrcmp(cur->elem, elem))) {
	    /*
	     * The attribute is already defined in this Dtd.
	     */
	    fprintf(stderr,
		    "xmlAddAttributeDecl: %s already defined\n", name);
	}
    }

    /*
     * Grow the table, if needed.
     */
    if (table->nb_attributes >= table->max_attributes) {
        /*
	 * need more attributes.
	 */
	table->max_attributes *= 2;
	table->table = (xmlAttributePtr) 
	    realloc(table->table, table->max_attributes * sizeof(xmlAttribute));
	if (table->table) {
	    fprintf(stderr, "xmlAddAttributeDecl: out of memory\n");
	    return(NULL);
	}
    }
    ret = &table->table[table->nb_attributes];

    /*
     * fill the structure.
     */
    ret->type = type;
    ret->name = xmlStrdup(name);
    ret->elem = xmlStrdup(elem);
    ret->def = def;
    ret->tree = tree;
    if (defaultValue != NULL)
	ret->defaultValue = xmlStrdup(defaultValue);
    else
        ret->defaultValue = NULL;
    table->nb_attributes++;

    return(ret);
}

/**
 * xmlFreeAttribute:
 * @elem:  An attribute
 *
 * Deallocate the memory used by an attribute definition
 */
void
xmlFreeAttribute(xmlAttributePtr attr) {
    if (attr == NULL) return;
    if (attr->tree != NULL)
        xmlFreeEnumeration(attr->tree);
    if (attr->elem != NULL)
	free((CHAR *) attr->elem);
    if (attr->name != NULL)
	free((CHAR *) attr->name);
    if (attr->defaultValue != NULL)
	free((CHAR *) attr->defaultValue);
    memset(attr, -1, sizeof(xmlAttribute));
}

/**
 * xmlFreeAttributeTable:
 * @table:  An attribute table
 *
 * Deallocate the memory used by an entities hash table.
 */
void
xmlFreeAttributeTable(xmlAttributeTablePtr table) {
    int i;

    if (table == NULL) return;

    for (i = 0;i < table->nb_attributes;i++) {
        xmlFreeAttribute(&table->table[i]);
    }
    free(table->table);
    free(table);
}

/**
 * xmlCopyAttributeTable:
 * @table:  An attribute table
 *
 * Build a copy of an attribute table.
 * 
 * Returns the new xmlAttributeTablePtr or NULL in case of error.
 */
xmlAttributeTablePtr
xmlCopyAttributeTable(xmlAttributeTablePtr table) {
    xmlAttributeTablePtr ret;
    xmlAttributePtr cur, attr;
    int i;

    ret = (xmlAttributeTablePtr) malloc(sizeof(xmlAttributeTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCopyAttributeTable: out of memory !\n");
	return(NULL);
    }
    ret->table = (xmlAttributePtr) malloc(table->max_attributes *
                                         sizeof(xmlAttribute));
    if (ret->table == NULL) {
        fprintf(stderr, "xmlCopyAttributeTable: out of memory !\n");
	free(ret);
	return(NULL);
    }
    ret->max_attributes = table->max_attributes;
    ret->nb_attributes = table->nb_attributes;
    for (i = 0;i < ret->nb_attributes;i++) {
	cur = &ret->table[i];
	attr = &table->table[i];
	cur->type = attr->type;
	cur->def = attr->def;
	cur->tree = xmlCopyEnumeration(attr->tree);
	if (attr->elem != NULL)
	    cur->elem = xmlStrdup(attr->elem);
	else
	    cur->elem = NULL;
	if (attr->name != NULL)
	    cur->name = xmlStrdup(attr->name);
	else
	    cur->name = NULL;
	if (attr->defaultValue != NULL)
	    cur->defaultValue = xmlStrdup(attr->defaultValue);
	else
	    cur->defaultValue = NULL;
    }
    return(ret);
}

/**
 * xmlDumpAttributeTable:
 * @buf:  the XML buffer output
 * @table:  An attribute table
 *
 * This will dump the content of the attribute table as an XML DTD definition
 */
void
xmlDumpAttributeTable(xmlBufferPtr buf, xmlAttributeTablePtr table) {
    int i;
    xmlAttributePtr cur;

    if (table == NULL) return;

    for (i = 0;i < table->nb_attributes;i++) {
        cur = &table->table[i];
	xmlBufferWriteChar(buf, "<!ATTLIST ");
	xmlBufferWriteCHAR(buf, cur->elem);
	xmlBufferWriteChar(buf, " ");
	xmlBufferWriteCHAR(buf, cur->name);
        switch (cur->type) {
            case XML_ATTRIBUTE_CDATA:
		xmlBufferWriteChar(buf, " CDATA");
                break;
            case XML_ATTRIBUTE_ID:
		xmlBufferWriteChar(buf, " ID");
                break;
            case XML_ATTRIBUTE_IDREF:
		xmlBufferWriteChar(buf, " IDREF");
                break;
            case XML_ATTRIBUTE_IDREFS:
		xmlBufferWriteChar(buf, " IDREFS");
                break;
            case XML_ATTRIBUTE_ENTITY:
		xmlBufferWriteChar(buf, " ENTITY");
                break;
            case XML_ATTRIBUTE_ENTITIES:
		xmlBufferWriteChar(buf, " ENTITIES");
                break;
            case XML_ATTRIBUTE_NMTOKEN:
		xmlBufferWriteChar(buf, " NMTOKEN");
                break;
            case XML_ATTRIBUTE_NMTOKENS:
		xmlBufferWriteChar(buf, " NMTOKENS");
                break;
            case XML_ATTRIBUTE_ENUMERATION:
                xmlBufferWriteChar(buf, " (pbm)");
                break;
            case XML_ATTRIBUTE_NOTATION:
                xmlBufferWriteChar(buf, " NOTATION (pbm)");
                break;
	    default:
	        fprintf(stderr,
		    "xmlDumpAttributeTable: internal: unknown type %d\n",
		        cur->type);
	}
        switch (cur->def) {
            case XML_ATTRIBUTE_NONE:
                break;
            case XML_ATTRIBUTE_REQUIRED:
		xmlBufferWriteChar(buf, " #REQUIRED");
                break;
            case XML_ATTRIBUTE_IMPLIED:
		xmlBufferWriteChar(buf, " #IMPLIED");
		if (cur->defaultValue != NULL) {
		    xmlBufferWriteChar(buf, " ");
		    xmlBufferWriteQuotedString(buf, cur->defaultValue);
		}
                break;
            case XML_ATTRIBUTE_FIXED:
		xmlBufferWriteChar(buf, " #FIXED ");
		xmlBufferWriteQuotedString(buf, cur->defaultValue);
                break;
	    default:
	        fprintf(stderr,
		    "xmlDumpAttributeTable: internal: unknown default %d\n",
		        cur->def);
        }
        xmlBufferWriteChar(buf, ">\n");
    }
}

/************************************************************************
 *									*
 *				NOTATIONs				*
 *									*
 ************************************************************************/
/**
 * xmlCreateNotationTable:
 *
 * create and initialize an empty notation hash table.
 *
 * Returns the xmlNotationTablePtr just created or NULL in case
 *                of error.
 */
xmlNotationTablePtr
xmlCreateNotationTable(void) {
    xmlNotationTablePtr ret;

    ret = (xmlNotationTablePtr) 
         malloc(sizeof(xmlNotationTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateNotationTable : malloc(%d) failed\n",
	        sizeof(xmlNotationTable));
        return(NULL);
    }
    ret->max_notations = XML_MIN_NOTATION_TABLE;
    ret->nb_notations = 0;
    ret->table = (xmlNotationPtr ) 
         malloc(ret->max_notations * sizeof(xmlNotation));
    if (ret == NULL) {
        fprintf(stderr, "xmlCreateNotationTable : malloc(%d) failed\n",
	        ret->max_notations * sizeof(xmlNotation));
	free(ret);
        return(NULL);
    }
    return(ret);
}


/**
 * xmlAddNotationDecl:
 * @dtd:  pointer to the DTD
 * @name:  the entity name
 * @PublicID:  the public identifier or NULL
 * @SystemID:  the system identifier or NULL
 *
 * Register a new notation declaration
 *
 * Returns NULL if not, othervise the entity
 */
xmlNotationPtr
xmlAddNotationDecl(xmlDtdPtr dtd, const CHAR *name, const CHAR *PublicID,
                   const CHAR *SystemID) {
    xmlNotationPtr ret, cur;
    xmlNotationTablePtr table;
    int i;

    if (dtd == NULL) {
        fprintf(stderr, "xmlAddNotationDecl: dtd == NULL\n");
	return(NULL);
    }
    if (name == NULL) {
        fprintf(stderr, "xmlAddNotationDecl: name == NULL\n");
	return(NULL);
    }
    if ((PublicID == NULL) && (SystemID == NULL)) {
        fprintf(stderr, "xmlAddNotationDecl: no PUBLIC ID nor SYSTEM ID\n");
    }

    /*
     * Create the Notation table if needed.
     */
    table = dtd->notations;
    if (table == NULL) 
        table = dtd->notations = xmlCreateNotationTable();
    if (table == NULL) {
	fprintf(stderr, "xmlAddNotationDecl: Table creation failed!\n");
        return(NULL);
    }

    /*
     * Validity Check:
     * Search the DTD for previous declarations of the ATTLIST
     */
    for (i = 0;i < table->nb_notations;i++) {
        cur = &table->table[i];
	if (!xmlStrcmp(cur->name, name)) {
	    /*
	     * The notation is already defined in this Dtd.
	     */
	    fprintf(stderr,
		    "xmlAddNotationDecl: %s already defined\n", name);
	}
    }

    /*
     * Grow the table, if needed.
     */
    if (table->nb_notations >= table->max_notations) {
        /*
	 * need more notations.
	 */
	table->max_notations *= 2;
	table->table = (xmlNotationPtr) 
	    realloc(table->table, table->max_notations * sizeof(xmlNotation));
	if (table->table) {
	    fprintf(stderr, "xmlAddNotationDecl: out of memory\n");
	    return(NULL);
	}
    }
    ret = &table->table[table->nb_notations];

    /*
     * fill the structure.
     */
    ret->name = xmlStrdup(name);
    if (SystemID != NULL)
        ret->SystemID = xmlStrdup(SystemID);
    else
        ret->SystemID = NULL;
    if (PublicID != NULL)
        ret->PublicID = xmlStrdup(PublicID);
    else
        ret->PublicID = NULL;
    table->nb_notations++;

    return(ret);
}

/**
 * xmlFreeNotation:
 * @not:  A notation
 *
 * Deallocate the memory used by an notation definition
 */
void
xmlFreeNotation(xmlNotationPtr nota) {
    if (nota == NULL) return;
    if (nota->name != NULL)
	free((CHAR *) nota->name);
    if (nota->PublicID != NULL)
	free((CHAR *) nota->PublicID);
    if (nota->SystemID != NULL)
	free((CHAR *) nota->SystemID);
    memset(nota, -1, sizeof(xmlNotation));
}

/**
 * xmlFreeNotationTable:
 * @table:  An notation table
 *
 * Deallocate the memory used by an entities hash table.
 */
void
xmlFreeNotationTable(xmlNotationTablePtr table) {
    int i;

    if (table == NULL) return;

    for (i = 0;i < table->nb_notations;i++) {
        xmlFreeNotation(&table->table[i]);
    }
    free(table->table);
    free(table);
}

/**
 * xmlCopyNotationTable:
 * @table:  A notation table
 *
 * Build a copy of a notation table.
 * 
 * Returns the new xmlNotationTablePtr or NULL in case of error.
 */
xmlNotationTablePtr
xmlCopyNotationTable(xmlNotationTablePtr table) {
    xmlNotationTablePtr ret;
    xmlNotationPtr cur, nota;
    int i;

    ret = (xmlNotationTablePtr) malloc(sizeof(xmlNotationTable));
    if (ret == NULL) {
        fprintf(stderr, "xmlCopyNotationTable: out of memory !\n");
	return(NULL);
    }
    ret->table = (xmlNotationPtr) malloc(table->max_notations *
                                         sizeof(xmlNotation));
    if (ret->table == NULL) {
        fprintf(stderr, "xmlCopyNotationTable: out of memory !\n");
	free(ret);
	return(NULL);
    }
    ret->max_notations = table->max_notations;
    ret->nb_notations = table->nb_notations;
    for (i = 0;i < ret->nb_notations;i++) {
	cur = &ret->table[i];
	nota = &table->table[i];
	if (nota->name != NULL)
	    cur->name = xmlStrdup(nota->name);
	else
	    cur->name = NULL;
	if (nota->PublicID != NULL)
	    cur->PublicID = xmlStrdup(nota->PublicID);
	else
	    cur->PublicID = NULL;
	if (nota->SystemID != NULL)
	    cur->SystemID = xmlStrdup(nota->SystemID);
	else
	    cur->SystemID = NULL;
    }
    return(ret);
}

/**
 * xmlDumpNotationTable:
 * @buf:  the XML buffer output
 * @table:  A notation table
 *
 * This will dump the content of the notation table as an XML DTD definition
 */
void
xmlDumpNotationTable(xmlBufferPtr buf, xmlNotationTablePtr table) {
    int i;
    xmlNotationPtr cur;

    if (table == NULL) return;

    for (i = 0;i < table->nb_notations;i++) {
        cur = &table->table[i];
	xmlBufferWriteChar(buf, "<!NOTATION ");
	xmlBufferWriteCHAR(buf, cur->name);
	if (cur->PublicID != NULL) {
	    xmlBufferWriteChar(buf, " PUBLIC ");
	    xmlBufferWriteQuotedString(buf, cur->PublicID);
	    if (cur->SystemID != NULL) {
		xmlBufferWriteChar(buf, " ");
		xmlBufferWriteCHAR(buf, cur->SystemID);
	    }
	} else {
	    xmlBufferWriteChar(buf, " SYSTEM ");
	    xmlBufferWriteCHAR(buf, cur->SystemID);
	}
        xmlBufferWriteChar(buf, " >\n");
    }
}
