/*
 * tree.c : implemetation of access function for an XML tree.
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#include <stdio.h>
#include <ctype.h>
#include <malloc.h>
#include <string.h> /* for memset() only ! */

#include "xml_tree.h"
#include "xml_entities.h"

static CHAR xmlStringText[] = { 't', 'e', 'x', 't', 0 };
int oldXMLWDcompatibility = 0;

/************************************************************************
 *									*
 *		Allocation and deallocation of basic structures		*
 *									*
 ************************************************************************/
 
/*
 * Creation of a new DTD.
 */
xmlDtdPtr xmlNewDtd(xmlDocPtr doc, const CHAR *href, const CHAR *AS) {
    xmlDtdPtr cur;

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlDtdPtr) malloc(sizeof(xmlDtd));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDtd : malloc failed\n");
	return(NULL);
    }

    cur->next = NULL;
    if (href != NULL)
	cur->href = xmlStrdup(href); 
    else
        cur->href = NULL;
    if (AS != NULL)
	cur->AS = xmlStrdup(AS); 
    else
        cur->AS = NULL;
    if (doc != NULL) {
	cur->next = doc->dtds;
        doc->dtds = cur;
    }

    return(cur);
}

/*
 * Freeing a DTD
 */
void xmlFreeDtd(xmlDtdPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeDtd : DTD == NULL\n");
	return;
    }
    if (cur->href != NULL) free((char *) cur->href);
    if (cur->AS != NULL) free((char *) cur->AS);
    memset(cur, -1, sizeof(xmlDtd));
    free(cur);
}

/*
 * Freeing a DTD list
 */
void xmlFreeDtdList(xmlDtdPtr cur) {
    xmlDtdPtr next;
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeDtdList : dtd == NULL\n");
	return;
    }
    while (cur != NULL) {
        next = cur->next;
        xmlFreeDtd(cur);
	cur = next;
    }
}

/*
 * Creation of a new document
 */
xmlDocPtr xmlNewDoc(const CHAR *version) {
    xmlDocPtr cur;

    if (version == NULL) {
        fprintf(stderr, "xmlNewDoc : version == NULL\n");
	return(NULL);
    }

    /*
     * Allocate a new document and fill the fields.
     */
    cur = (xmlDocPtr) malloc(sizeof(xmlDoc));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDoc : malloc failed\n");
	return(NULL);
    }

    cur->version = xmlStrdup(version); 
    cur->root = NULL; 
    cur->dtds = NULL;
    return(cur);
}

/*
 * Freeing a document : all the tree is freed too.
 */
void xmlFreeDoc(xmlDocPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeDoc : document == NULL\n");
	return;
    }
    free((char *) cur->version);
    if (cur->root != NULL) xmlFreeNode(cur->root);
    if (cur->dtds != NULL) xmlFreeDtdList(cur->dtds);
    memset(cur, -1, sizeof(xmlDoc));
    free(cur);
}

/*
 * Creation of a new property element in a given DTD.
 */
xmlPropPtr xmlNewProp(xmlNodePtr node, const CHAR *name, const CHAR *value) {
    xmlPropPtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewProp : name == NULL\n");
	return(NULL);
    }

    /*
     * Allocate a new property and fill the fields.
     */
    cur = (xmlPropPtr) malloc(sizeof(xmlProp));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewProp : malloc failed\n");
	return(NULL);
    }

    cur->node = node; 
    cur->name = xmlStrdup(name);
    if (value != NULL)
	cur->value = xmlStrdup(value);
    else 
	cur->value = NULL;
    if (node != NULL) {
	cur->next = node->properties;
        node->properties = cur;
    } else
	cur->next = NULL; 
    return(cur);
}

/*
 * Freeing a property list : Free a property and all its siblings,
 *                       this is a recursive behaviour, all the childs
 *                       are freed too.
 */
void xmlFreePropList(xmlPropPtr cur) {
    xmlPropPtr next;
    if (cur == NULL) {
        fprintf(stderr, "xmlFreePropList : property == NULL\n");
	return;
    }
    while (cur != NULL) {
        next = cur->next;
        xmlFreeProp(cur);
	cur = next;
    }
}

/*
 * Freeing a property.
 */
void xmlFreeProp(xmlPropPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeProp : property == NULL\n");
	return;
    }
    if (cur->name != NULL) free((char *) cur->name);
    if (cur->value != NULL) free((char *) cur->value);
    memset(cur, -1, sizeof(xmlProp));
    free(cur);
}

/*
 * Creation of a new node element in a given DTD.
 * We assume that the "name" has already being strdup'd !
 */
xmlNodePtr xmlNewNode(xmlDtdPtr dtd, const CHAR *name, CHAR *content) {
    xmlNodePtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewNode : name == NULL\n");
	return(NULL);
    }

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewNode : malloc failed\n");
	return(NULL);
    }

    cur->parent = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->properties = NULL; 
    cur->type = 0;
    cur->name = name;
    cur->dtd = dtd;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
    return(cur);
}

/*
 * Creation of a new node contening text.
 */
xmlNodePtr xmlNewText(CHAR *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewNode : malloc failed\n");
	return(NULL);
    }

    cur->parent = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->properties = NULL; 
    cur->type = XML_TYPE_TEXT;
    cur->name = xmlStrdup(xmlStringText);;
    cur->dtd = NULL;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
    return(cur);
}

/*
 * Creation of a new child element, added at the end.
 */
xmlNodePtr xmlNewChild(xmlNodePtr parent, xmlDtdPtr dtd,
                       const CHAR *name, CHAR *content) {
    xmlNodePtr cur, prev;

    if (parent == NULL) {
        fprintf(stderr, "xmlNewChild : parent == NULL\n");
	return(NULL);
    }

    if (name == NULL) {
        fprintf(stderr, "xmlNewChild : name == NULL\n");
	return(NULL);
    }

    /*
     * Allocate a new node
     */
    if (dtd == NULL)
	cur = xmlNewNode(parent->dtd, name, content);
    else
	cur = xmlNewNode(dtd, name, content);
    if (cur == NULL) return(NULL);

    /*
     * add the new element at the end of the childs list.
     */
    cur->parent = parent;
    if (parent->childs == NULL) {
        parent->childs = cur;
    } else {
        prev = parent->childs;
	while (prev->next != NULL) prev = prev->next;
	prev->next = cur;
    }

    return(cur);
}

/*
 * Add a new child element, added at the end.
 */
xmlNodePtr xmlAddChild(xmlNodePtr parent, xmlNodePtr cur) {
    xmlNodePtr prev;

    if (parent == NULL) {
        fprintf(stderr, "xmladdChild : parent == NULL\n");
	return(NULL);
    }

    if (cur == NULL) {
        fprintf(stderr, "xmladdChild : child == NULL\n");
	return(NULL);
    }

    /*
     * add the new element at the end of the childs list.
     */
    cur->parent = parent;
    if (parent->childs == NULL) {
        parent->childs = cur;
    } else {
        prev = parent->childs;
	while (prev->next != NULL) prev = prev->next;
	prev->next = cur;
    }

    return(cur);
}

/*
 * Freeing a node list : Free a node and all its siblings,
 *                       this is a recursive behaviour, all the childs
 *                       are freed too.
 */
void xmlFreeNodeList(xmlNodePtr cur) {
    xmlNodePtr next;
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeNodeList : node == NULL\n");
	return;
    }
    while (cur != NULL) {
        next = cur->next;
        xmlFreeNode(cur);
	cur = next;
    }
}

/*
 * Freeing a node : this is a recursive behaviour, all the childs
 *                  are freed too.
 */
void xmlFreeNode(xmlNodePtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeNode : node == NULL\n");
	return;
    }
    if (cur->properties != NULL) xmlFreePropList(cur->properties);
    if (cur->childs != NULL) xmlFreeNodeList(cur->childs);
    if (cur->content != NULL) free(cur->content);
    if (cur->name != NULL) free((char *) cur->name);
    memset(cur, -1, sizeof(xmlNode));
    free(cur);
}

/************************************************************************
 *									*
 *		Content access functions				*
 *									*
 ************************************************************************/
 
/*
 * Changing the content of a node.
 */
void xmlNodeSetContent(xmlNodePtr cur, CHAR *content) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeSetContent : node == NULL\n");
	return;
    }
    if (cur->content != NULL) free(cur->content);
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
}

/*
 * Search a Dtd registered under a given name space for a document.
 */
xmlDtdPtr xmlSearchDtd(xmlDocPtr doc, CHAR *nameSpace) {
    xmlDtdPtr cur;

    if ((doc == NULL) || (nameSpace == NULL)) return(NULL);

    cur = doc->dtds;
    while (cur != NULL) {
        if ((cur->AS != NULL) && (!xmlStrcmp(cur->AS, nameSpace)))
	    return(cur);
	cur = cur->next;
    }
    return(NULL);
}

/*
 * Reading the content of a given property.
 */
const CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name) {
    xmlPropPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name)) return(prop->value);
	prop = prop->next;
    }
    return(NULL);
}

/************************************************************************
 *									*
 *			Output : to a FILE or in memory			*
 *									*
 ************************************************************************/

/*
 * routine which manage and grows an output buffer. One can write
 * standard char array's (8 bits char) or CHAR's arrays.
 */
static CHAR *buffer = NULL;
static int buffer_index = 0;
static int buffer_size = 0;

static void xmlBufferWriteCHAR(const CHAR *string) {
    const CHAR *cur;

    if (buffer == NULL) {
        buffer_size = 50000;
        buffer = (CHAR *) malloc(buffer_size * sizeof(CHAR));
	if (buffer == NULL) {
	    fprintf(stderr, "xmlBufferWrite : out of memory!\n");
	    exit(1);
	}
    }
    
    if (string == NULL) return;
    for (cur = string;*cur != 0;cur++) {
        if (buffer_index  + 10 >= buffer_size) {
	    buffer_size *= 2;
	    buffer = (CHAR *) realloc(buffer, buffer_size * sizeof(CHAR));
	    if (buffer == NULL) {
	        fprintf(stderr, "xmlBufferWrite : out of memory!\n");
		exit(1);
	    }
	}
        buffer[buffer_index++] = *cur;
    }
    buffer[buffer_index] = 0;
}

static void xmlBufferWriteChar(const char *string) {
    const CHAR *cur;

    if (buffer == NULL) {
        buffer_size = 50000;
        buffer = (CHAR *) malloc(buffer_size * sizeof(CHAR));
	if (buffer == NULL) {
	    fprintf(stderr, "xmlBufferWrite : out of memory!\n");
	    exit(1);
	}
    }
    
    if (string == NULL) return;
    for (cur = string;*cur != 0;cur++) {
        if (buffer_index  + 10 >= buffer_size) {
	    buffer_size *= 2;
	    buffer = (CHAR *) realloc(buffer, buffer_size * sizeof(CHAR));
	    if (buffer == NULL) {
	        fprintf(stderr, "xmlBufferWrite : out of memory!\n");
		exit(1);
	    }
	}
        buffer[buffer_index++] = *cur;
    }
    buffer[buffer_index] = 0;
}

/*
 * Dump a DTD to the given FD
 */
static void xmlDtdDump(xmlDtdPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlDtdDump : DTD == NULL\n");
	return;
    }
    if (oldXMLWDcompatibility) {
	xmlBufferWriteChar("<?namespace");
	if (cur->href != NULL) {
	    xmlBufferWriteChar(" href=\"");
	    xmlBufferWriteCHAR(cur->href);
	    xmlBufferWriteChar("\"");
	}
	if (cur->AS != NULL) {
	    xmlBufferWriteChar(" AS=\"");
	    xmlBufferWriteCHAR(cur->AS);
	    xmlBufferWriteChar("\"");
	}
	xmlBufferWriteChar("?>\n");
    } else {
	xmlBufferWriteChar("<?xml:namespace");
	if (cur->href != NULL) {
	    xmlBufferWriteChar(" ns=\"");
	    xmlBufferWriteCHAR(cur->href);
	    xmlBufferWriteChar("\"");
	}
	if (cur->AS != NULL) {
	    xmlBufferWriteChar(" prefix=\"");
	    xmlBufferWriteCHAR(cur->AS);
	    xmlBufferWriteChar("\"");
	}
	xmlBufferWriteChar("?>\n");
    }
}

/*
 * Dump an XML property to the given FD
 */

static void xmlPropDump(xmlDocPtr doc, xmlPropPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlPropDump : property == NULL\n");
	return;
    }
    xmlBufferWriteChar(" ");
    xmlBufferWriteCHAR(cur->name);
    if (cur->value) {
	xmlBufferWriteChar("=\"");
	xmlBufferWriteCHAR(xmlEncodeEntities(doc, cur->value));
	xmlBufferWriteChar("\"");
    }
}

/*
 * Dump an XML property list to the given FD
 */

static void xmlPropListDump(xmlDocPtr doc, xmlPropPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlPropListDump : property == NULL\n");
	return;
    }
    while (cur != NULL) {
        xmlPropDump(doc, cur);
	cur = cur->next;
    }
}

/*
 * Dump an XML node list to the given FD
 */

static void xmlNodeDump(xmlDocPtr doc, xmlNodePtr cur, int level);
static void xmlNodeListDump(xmlDocPtr doc, xmlNodePtr cur, int level) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeListDump : node == NULL\n");
	return;
    }
    while (cur != NULL) {
        xmlNodeDump(doc, cur, level);
	cur = cur->next;
    }
}

/*
 * Dump an XML node to the given FD
 */

static void xmlNodeDump(xmlDocPtr doc, xmlNodePtr cur, int level) {
    int i;

    if (cur == NULL) {
        fprintf(stderr, "xmlNodeDump : node == NULL\n");
	return;
    }
    if (cur->type == XML_TYPE_TEXT) {
	if (cur->content != NULL)
	    xmlBufferWriteCHAR(xmlEncodeEntities(doc, cur->content));
	return;
    }
    for (i = 0;i < level;i++)
        xmlBufferWriteChar("  ");

    xmlBufferWriteChar("<");
    if ((cur->dtd != NULL) && (cur->dtd->AS != NULL)) {
        xmlBufferWriteCHAR(cur->dtd->AS);
	xmlBufferWriteChar(":");
    }

    xmlBufferWriteCHAR(cur->name);
    if (cur->properties != NULL)
        xmlPropListDump(doc, cur->properties);

    if ((cur->content == NULL) && (cur->childs == NULL)) {
        xmlBufferWriteChar("/>\n");
	return;
    }
    xmlBufferWriteChar(">");
    if (cur->content != NULL)
	xmlBufferWriteCHAR(xmlEncodeEntities(doc, cur->content));
    if (cur->childs != NULL) {
	xmlBufferWriteChar("\n");
	xmlNodeListDump(doc, cur->childs, level + 1);
	for (i = 0;i < level;i++)
	    xmlBufferWriteChar("  ");
    }
    xmlBufferWriteChar("</");
    if ((cur->dtd != NULL) && (cur->dtd->AS != NULL)) {
        xmlBufferWriteCHAR(cur->dtd->AS);
	xmlBufferWriteChar(":");
    }

    xmlBufferWriteCHAR(cur->name);
    xmlBufferWriteChar(">\n");
}

/*
 * Dump an XML DTD list to the given FD
 */

static void xmlDtdListDump(xmlDtdPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlDtdListDump : DTD == NULL\n");
	return;
    }
    while (cur != NULL) {
        xmlDtdDump(cur);
	cur = cur->next;
    }
}

/*
 * Dump an XML document to memory.
 */

void xmlDocDumpMemory(xmlDocPtr cur, CHAR**mem, int *size) {
    if (cur == NULL) {
        fprintf(stderr, "xmlDocDump : document == NULL\n");
	*mem = NULL;
	*size = 0;
	return;
    }
    buffer_index = 0;
    if (oldXMLWDcompatibility)
	xmlBufferWriteChar("<?XML version=\"");
    else 
	xmlBufferWriteChar("<?xml version=\"");
    xmlBufferWriteCHAR(cur->version);
    xmlBufferWriteChar("\"?>\n");
    if (cur->dtds != NULL)
        xmlDtdListDump(cur->dtds);
    if (cur->root != NULL)
        xmlNodeDump(cur, cur->root, 0);

    *mem = buffer;
    *size = buffer_index;
}

/*
 * Dump an XML document to the given FD
 */

void xmlDocDump(FILE *f, xmlDocPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlDocDump : document == NULL\n");
	return;
    }
    buffer_index = 0;
    if (oldXMLWDcompatibility)
	xmlBufferWriteChar("<?XML version=\"");
    else 
	xmlBufferWriteChar("<?xml version=\"");
    xmlBufferWriteCHAR(cur->version);
    xmlBufferWriteChar("\"?>\n");
    if (cur->dtds != NULL)
        xmlDtdListDump(cur->dtds);
    if (cur->root != NULL)
        xmlNodeDump(cur, cur->root, 0);

    fwrite(buffer, sizeof(CHAR), buffer_index, f);
}

/************************************************************************
 *									*
 *				Debug					*
 *									*
 ************************************************************************/

#ifdef DEBUG_TREE
int main(void) {
    xmlDocPtr doc;
    xmlNodePtr tree, subtree;
    xmlDtdPtr dtd1;
    xmlDtdPtr dtd2;

    /*
     * build a fake XML document
     */
    doc = xmlNewDoc("1.0");
    dtd1 = xmlNewDtd(doc, "http://www.ietf.org/standards/dav/", "D");
    dtd2 = xmlNewDtd(doc, "http://www.w3.com/standards/z39.50/", "Z");
    doc->root = xmlNewNode(dtd1, "multistatus", NULL);
    tree = xmlNewChild(doc->root, NULL, "response", NULL);
    subtree = xmlNewChild(tree, NULL, "prop", NULL);
    xmlNewChild(subtree, dtd2, "Authors", NULL);
    subtree = xmlNewChild(tree, NULL, "status", "HTTP/1.1 420 Method Failure");
    tree = xmlNewChild(doc->root, NULL, "response", NULL);
    subtree = xmlNewChild(tree, NULL, "prop", NULL);
    xmlNewChild(subtree, dtd2, "Copyright-Owner", NULL);
    subtree = xmlNewChild(tree, NULL, "status", "HTTP/1.1 409 Conflict");
    tree = xmlNewChild(doc->root, NULL, "responsedescription",
                       "Copyright Owner can not be deleted or altered");

    /*
     * print it.
     */
    xmlDocDump(stdout, doc);

    /*
     * free it.
     */
    xmlFreeDoc(doc);
    return(0);
}
#endif
