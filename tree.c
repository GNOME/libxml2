/*
 * tree.c : implemetation of access function for an XML tree.
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 *
 * TODO Cleanup the Dump mechanism.
 */

#include "config.h"
#include <stdio.h>
#include <ctype.h>
#include <malloc.h>
#include <string.h> /* for memset() only ! */

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "tree.h"
#include "entities.h"

static CHAR xmlStringText[] = { 't', 'e', 'x', 't', 0 };
int oldXMLWDcompatibility = 0;
int xmlIndentTreeOutput = 1;

static int xmlCompressMode = 0;

/************************************************************************
 *									*
 *		Allocation and deallocation of basic structures		*
 *									*
 ************************************************************************/
 
/*
 * Upgrade old Namespace and move them to the root of the document.
 */

void xmlUpgradeOldNs(xmlDocPtr doc) {
    xmlNsPtr cur;

    if ((doc == NULL) || (doc->oldNs == NULL)) return;
    if (doc->root == NULL) {
        fprintf(stderr, "xmlUpgradeOldNs: failed no root !\n");
	return;
    }

    cur = doc->oldNs;
    while (cur->next != NULL) {
	cur->type = XML_LOCAL_NAMESPACE;
        cur = cur->next;
    }
    cur->type = XML_LOCAL_NAMESPACE;
    cur->next = doc->root->nsDef;
    doc->root->nsDef = doc->oldNs;
    doc->oldNs = NULL;
}

/*
 * Creation of a new Namespace.
 */
xmlNsPtr xmlNewNs(xmlNodePtr node, const CHAR *href, const CHAR *prefix) {
    xmlNsPtr cur;

    if (href == NULL) {
        fprintf(stderr, "xmlNewNs: href == NULL !\n");
	return(NULL);
    }

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlNsPtr) malloc(sizeof(xmlNs));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewNs : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_LOCAL_NAMESPACE;
    if (href != NULL)
	cur->href = xmlStrdup(href); 
    else
        cur->href = NULL;
    if (prefix != NULL)
	cur->prefix = xmlStrdup(prefix); 
    else
        cur->prefix = NULL;

    /*
     * Add it at the end to preserve parsing order ...
     */
    cur->next = NULL;
    if (node != NULL) {
	if (node->nsDef == NULL) {
	    node->nsDef = cur;
	} else {
	    xmlNsPtr prev = node->nsDef;

	    while (prev->next != NULL) prev = prev->next;
	    prev->next = cur;
	}
    }

    return(cur);
}

/*
 * Creation of a new global namespace (the old way ...).
 */
xmlNsPtr xmlNewGlobalNs(xmlDocPtr doc, const CHAR *href, const CHAR *prefix) {
    xmlNsPtr cur;

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlNsPtr) malloc(sizeof(xmlNs));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewNs : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_GLOBAL_NAMESPACE;
    if (href != NULL)
	cur->href = xmlStrdup(href); 
    else
        cur->href = NULL;
    if (prefix != NULL)
	cur->prefix = xmlStrdup(prefix); 
    else
        cur->prefix = NULL;

    /*
     * Add it at the end to preserve parsing order ...
     */
    cur->next = NULL;
    if (doc != NULL) {
	if (doc->oldNs == NULL) {
	    doc->oldNs = cur;
	} else {
	    xmlNsPtr prev = doc->oldNs;

	    while (prev->next != NULL) prev = prev->next;
	    prev->next = cur;
	}
    }

    return(cur);
}

/*
 * Set the node namespace a posteriori
 */
void xmlSetNs(xmlNodePtr node, xmlNsPtr ns) {
    if (node == NULL) {
        fprintf(stderr, "xmlSetNs: node == NULL\n");
	return;
    }
    node->ns = ns;
}

/*
 * Freeing a Namespace
 */
void xmlFreeNs(xmlNsPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeNs : ns == NULL\n");
	return;
    }
    if (cur->href != NULL) free((char *) cur->href);
    if (cur->prefix != NULL) free((char *) cur->prefix);
    memset(cur, -1, sizeof(xmlNs));
    free(cur);
}

/*
 * Freeing a Namespace list
 */
void xmlFreeNsList(xmlNsPtr cur) {
    xmlNsPtr next;
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeNsList : ns == NULL\n");
	return;
    }
    while (cur != NULL) {
        next = cur->next;
        xmlFreeNs(cur);
	cur = next;
    }
}

/*
 * Creation of a new DTD.
 */
xmlDtdPtr xmlNewDtd(xmlDocPtr doc, const CHAR *name,
                    const CHAR *ExternalID, const CHAR *SystemID) {
    xmlDtdPtr cur;

    if (doc->dtd != NULL) {
        fprintf(stderr, "xmlNewDtd(%s): document %s already have a DTD %s\n",
	/* !!! */ (char *) name, doc->name, /* !!! */ (char *)doc->dtd->name);
    }

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlDtdPtr) malloc(sizeof(xmlDtd));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewNs : malloc failed\n");
	return(NULL);
    }

    if (name != NULL)
	cur->name = xmlStrdup(name); 
    else
        cur->name = NULL;
    if (ExternalID != NULL)
	cur->ExternalID = xmlStrdup(ExternalID); 
    else
        cur->ExternalID = NULL;
    if (SystemID != NULL)
	cur->SystemID = xmlStrdup(SystemID); 
    else
        cur->SystemID = NULL;
    cur->elements = NULL;
    cur->entities = NULL;
    doc->dtd = cur;

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
    if (cur->name != NULL) free((char *) cur->name);
    if (cur->SystemID != NULL) free((char *) cur->SystemID);
    if (cur->ExternalID != NULL) free((char *) cur->ExternalID);
    if (cur->elements != NULL)
        fprintf(stderr, "xmlFreeDtd: cur->elements != NULL !!! \n");
    if (cur->entities != NULL)
        xmlFreeEntitiesTable((xmlEntitiesTablePtr) cur->entities);
    memset(cur, -1, sizeof(xmlDtd));
    free(cur);
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
    cur->name = NULL;
    cur->root = NULL; 
    cur->dtd = NULL;
    cur->oldNs = NULL;
    cur->encoding = NULL;
    cur->entities = NULL;
    cur->standalone = -1;
    cur->compression = xmlCompressMode;
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
    if (cur->name != NULL) free((char *) cur->name);
    if (cur->encoding != NULL) free((char *) cur->encoding);
    if (cur->root != NULL) xmlFreeNode(cur->root);
    if (cur->dtd != NULL) xmlFreeDtd(cur->dtd);
    if (cur->entities != NULL)
        xmlFreeEntitiesTable((xmlEntitiesTablePtr) cur->entities);
    memset(cur, -1, sizeof(xmlDoc));
    free(cur);
}

/*
 * Creation of a new property of a node.
 */
xmlAttrPtr xmlNewProp(xmlNodePtr node, const CHAR *name, const CHAR *value) {
    xmlAttrPtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewProp : name == NULL\n");
	return(NULL);
    }

    /*
     * Allocate a new property and fill the fields.
     */
    cur = (xmlAttrPtr) malloc(sizeof(xmlAttr));
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

    /*
     * Add it at the end to preserve parsing order ...
     */
    cur->next = NULL;
    if (node != NULL) {
	if (node->properties == NULL) {
	    node->properties = cur;
	} else {
	    xmlAttrPtr prev = node->properties;

	    while (prev->next != NULL) prev = prev->next;
	    prev->next = cur;
	}
    }
    return(cur);
}

/*
 * Freeing a property list : Free a property and all its siblings,
 *                       this is a recursive behaviour, all the childs
 *                       are freed too.
 */
void xmlFreePropList(xmlAttrPtr cur) {
    xmlAttrPtr next;
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
void xmlFreeProp(xmlAttrPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeProp : property == NULL\n");
	return;
    }
    if (cur->name != NULL) free((char *) cur->name);
    if (cur->value != NULL) free((char *) cur->value);
    memset(cur, -1, sizeof(xmlAttr));
    free(cur);
}

/*
 * Creation of a new node element in a given DTD.
 * We assume that the "name" has already being strdup'd !
 */
xmlNodePtr xmlNewNode(xmlNsPtr ns, const CHAR *name, CHAR *content) {
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
    cur->name = xmlStrdup(name);
    cur->ns = ns;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
    return(cur);
}

/*
 * Creation of a new node contening text.
 */
xmlNodePtr xmlNewText(const CHAR *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }

    cur->parent = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->properties = NULL; 
    cur->type = XML_TYPE_TEXT;
    cur->name = xmlStrdup(xmlStringText);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
    return(cur);
}

/*
 * Creation of a new node contening text.
 */
xmlNodePtr xmlNewTextLen(const CHAR *content, int len) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }

    cur->parent = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->properties = NULL; 
    cur->type = XML_TYPE_TEXT;
    cur->name = xmlStrdup(xmlStringText);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrndup(content, len);
    else 
	cur->content = NULL;
    return(cur);
}

/*
 * Creation of a new node contening a comment.
 */
xmlNodePtr xmlNewComment(CHAR *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewComment : malloc failed\n");
	return(NULL);
    }

    cur->parent = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->properties = NULL; 
    cur->type = XML_TYPE_COMMENT;
    cur->name = xmlStrdup(xmlStringText);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
    return(cur);
}

/*
 * Creation of a new child element, added at the end.
 */
xmlNodePtr xmlNewChild(xmlNodePtr parent, xmlNsPtr ns,
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
    if (ns == NULL)
	cur = xmlNewNode(parent->ns, name, content);
    else
	cur = xmlNewNode(ns, name, content);
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
 * Search the last child, if any.
 */
xmlNodePtr xmlGetLastChild(xmlNodePtr parent) {
    xmlNodePtr last;

    if (parent == NULL) {
        fprintf(stderr, "xmlGetLastChild : parent == NULL\n");
	return(NULL);
    }

    /*
     * add the new element at the end of the childs list.
     */
    if (parent->childs == NULL) {
        return(NULL);
    } else {
        last = parent->childs;
	while (last->next != NULL) last = last->next;
    }
    return(last);
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
    if (cur->nsDef != NULL) xmlFreeNsList(cur->nsDef);
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
void xmlNodeSetContent(xmlNodePtr cur, const CHAR *content) {
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
 * Changing the content of a node.
 */
void xmlNodeSetContentLen(xmlNodePtr cur, const CHAR *content, int len) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeSetContent : node == NULL\n");
	return;
    }
    if (cur->content != NULL) free(cur->content);
    if (content != NULL)
	cur->content = xmlStrndup(content, len);
    else 
	cur->content = NULL;
}

/*
 * Adding content to a node.
 */
void xmlNodeAddContent(xmlNodePtr cur, const CHAR *content) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeAddContent : node == NULL\n");
	return;
    }
    cur->content = xmlStrcat(cur->content, content);
}

/*
 * Adding content to a node.
 */
void xmlNodeAddContentLen(xmlNodePtr cur, const CHAR *content, int len) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeAddContent : node == NULL\n");
	return;
    }
    cur->content = xmlStrncat(cur->content, content, len);
}

/*
 * Search a Ns registered under a given name space for a document.
 *      recurse on the parents until it finds the defined namespace
 *      or return NULL otherwise.
 *
 * Note : nameSpace == NULL is valid, this is a search for the default
 *        namespace.
 */
xmlNsPtr xmlSearchNs(xmlDocPtr doc, xmlNodePtr node, const CHAR *nameSpace) {
    xmlNsPtr cur;

    while (node != NULL) {
	cur = node->nsDef;
	while (cur != NULL) {
	    if ((cur->prefix == NULL) && (nameSpace == NULL))
	        return(cur);
	    if ((cur->prefix != NULL) && (nameSpace != NULL) &&
	        (!xmlStrcmp(cur->prefix, nameSpace)))
		return(cur);
	    cur = cur->next;
	}
	node = node->parent;
    }
    if (doc != NULL) {
        cur = doc->oldNs;
	while (cur != NULL) {
	    if ((cur->prefix != NULL) && (nameSpace != NULL) &&
	        (!xmlStrcmp(cur->prefix, nameSpace)))
		return(cur);
	    cur = cur->next;
	}
    }
    return(NULL);
}

/*
 * Search a Ns aliasing a given URI
 *      recurse on the parents until it finds the defined namespace
 *      or return NULL otherwise.
 */
xmlNsPtr xmlSearchNsByHref(xmlDocPtr doc, xmlNodePtr node, const CHAR *href) {
    xmlNsPtr cur;

    while (node != NULL) {
	cur = node->nsDef;
	while (cur != NULL) {
	    if ((cur->href != NULL) && (href != NULL) &&
	        (!xmlStrcmp(cur->href, href)))
		return(cur);
	    cur = cur->next;
	}
	node = node->parent;
    }
    if (doc != NULL) {
        cur = doc->oldNs;
	while (cur != NULL) {
	    if ((cur->href != NULL) && (href != NULL) &&
	        (!xmlStrcmp(cur->href, href)))
		return(cur);
	    cur = cur->next;
	}
    }
    return(NULL);
}

/*
 * Reading the content of a given property.
 */
const CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name) {
    xmlAttrPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name)) return(prop->value);
	prop = prop->next;
    }
    return(NULL);
}

/*
 * Setting the content of a given property.
 */
xmlAttrPtr xmlSetProp(xmlNodePtr node, const CHAR *name, const CHAR *value) {
    xmlAttrPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name)) {
	    if (prop->value != NULL) 
	        free((char *) prop->value);
	    prop->value = NULL;
	    if (value != NULL)
		prop->value = xmlStrdup(value);
	    return(prop);
	}
	prop = prop->next;
    }
    prop = xmlNewProp(node, name, value);
    return(prop);
}

/*
 * Is this node a piece of text
 */
int xmlNodeIsText(xmlNodePtr node) {
    if (node == NULL) return(0);

    if (node->type == XML_TYPE_TEXT) return(1);
    return(0);
}

/*
 * Concat a piece of text to an existing text node
 *
 * TODO !!! Should be optimized with a bit of preallocation.
 */
void xmlTextConcat(xmlNodePtr node, const CHAR *content, int len) {
    if (node == NULL) return;

    if (node->type != XML_TYPE_TEXT) {
	fprintf(stderr, "xmlTextConcat: node is not text\n");
        return;
    }
    node->content = xmlStrncat(node->content, content, len);
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

void xmlBufferWriteCHAR(const CHAR *string) {
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

void xmlBufferWriteChar(const char *string) {
    const char *cur;

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
 * Dump the global Namespace inherited from the old WD.
 * Within the context of the document header.
 */
static void xmlGlobalNsDump(xmlNsPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlGlobalNsDump : Ns == NULL\n");
	return;
    }
    if (cur->type == XML_GLOBAL_NAMESPACE) {
	xmlBufferWriteChar("<?namespace");
	if (cur->href != NULL) {
	    xmlBufferWriteChar(" href=\"");
	    xmlBufferWriteCHAR(cur->href);
	    xmlBufferWriteChar("\"");
	}
	if (cur->prefix != NULL) {
	    xmlBufferWriteChar(" AS=\"");
	    xmlBufferWriteCHAR(cur->prefix);
	    xmlBufferWriteChar("\"");
	}
	xmlBufferWriteChar("?>\n");
    }
}

/*
 * Dump an old global XML Namespace list
 */

static void xmlGlobalNsListDump(xmlNsPtr cur) {
    while (cur != NULL) {
        xmlGlobalNsDump(cur);
	cur = cur->next;
    }
}

/*
 * Dump a local Namespace definition.
 * Within the context of an element attributes.
 */
static void xmlNsDump(xmlNsPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNsDump : Ns == NULL\n");
	return;
    }
    if (cur->type == XML_LOCAL_NAMESPACE) {
        /* Within the context of an element attributes */
	if (cur->prefix != NULL) {
	    xmlBufferWriteChar(" xmlns:");
	    xmlBufferWriteCHAR(cur->prefix);
	} else
	    xmlBufferWriteChar(" xmlns");
	xmlBufferWriteChar("=\"");
	xmlBufferWriteCHAR(cur->href);
	xmlBufferWriteChar("\"");
    }
}

/*
 * Dump an XML Namespace list
 */

static void xmlNsListDump(xmlNsPtr cur) {
    while (cur != NULL) {
        xmlNsDump(cur);
	cur = cur->next;
    }
}

/*
 * Dump an XML DTD
 */

static void xmlDtdDump(xmlDocPtr doc) {
    xmlDtdPtr cur = doc->dtd;

    if (cur == NULL) {
        fprintf(stderr, "xmlDtdDump : DTD == NULL\n");
	return;
    }
    xmlBufferWriteChar("<!DOCTYPE ");
    xmlBufferWriteCHAR(cur->name);
    if (cur->ExternalID != NULL) {
	xmlBufferWriteChar(" PUBLIC \"");
	xmlBufferWriteCHAR(cur->ExternalID);
	xmlBufferWriteChar("\" \"");
	xmlBufferWriteCHAR(cur->SystemID);
	xmlBufferWriteChar("\"");
    }  else if (cur->SystemID != NULL) {
	xmlBufferWriteChar(" SYSTEM \"");
	xmlBufferWriteCHAR(cur->SystemID);
	xmlBufferWriteChar("\"");
    }
    if ((cur->entities == NULL) && (doc->entities == NULL)) {
	xmlBufferWriteChar(">\n");
	return;
    }
    xmlBufferWriteChar(" [\n");
    if (cur->entities != NULL)
	xmlDumpEntitiesTable((xmlEntitiesTablePtr) cur->entities);
    if (doc->entities != NULL)
	xmlDumpEntitiesTable((xmlEntitiesTablePtr) doc->entities);
    xmlBufferWriteChar("]");

    /* TODO !!! a lot more things to dump ... */
    xmlBufferWriteChar(">\n");
}

/*
 * Dump an XML property
 */

static void xmlAttrDump(xmlDocPtr doc, xmlAttrPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlAttrDump : property == NULL\n");
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
 * Dump an XML property list
 */

static void xmlAttrListDump(xmlDocPtr doc, xmlAttrPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlAttrListDump : property == NULL\n");
	return;
    }
    while (cur != NULL) {
        xmlAttrDump(doc, cur);
	cur = cur->next;
    }
}

/*
 * Dump an XML node list
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
 * Dump an XML node
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
    if (cur->type == XML_TYPE_COMMENT) {
	if (cur->content != NULL) {
	    xmlBufferWriteChar("<!--");
	    xmlBufferWriteCHAR(cur->content);
	    xmlBufferWriteChar("-->");
	}
	return;
    }
    if (xmlIndentTreeOutput)
	for (i = 0;i < level;i++)
	    xmlBufferWriteChar("  ");

    xmlBufferWriteChar("<");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(cur->ns->prefix);
	xmlBufferWriteChar(":");
    }

    xmlBufferWriteCHAR(cur->name);
    if (cur->nsDef)
        xmlNsListDump(cur->nsDef);
    if (cur->properties != NULL)
        xmlAttrListDump(doc, cur->properties);

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
	if (xmlIndentTreeOutput)
	    for (i = 0;i < level;i++)
		xmlBufferWriteChar("  ");
    }
    xmlBufferWriteChar("</");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(cur->ns->prefix);
	xmlBufferWriteChar(":");
    }

    xmlBufferWriteCHAR(cur->name);
    xmlBufferWriteChar(">\n");
}

/*
 * Dump an XML document
 */
static void xmlDocContentDump(xmlDocPtr cur) {
    if (oldXMLWDcompatibility)
	xmlBufferWriteChar("<?XML version=\"");
    else 
	xmlBufferWriteChar("<?xml version=\"");
    xmlBufferWriteCHAR(cur->version);
    xmlBufferWriteChar("\"");
    if (cur->encoding != NULL) {
        xmlBufferWriteChar(" encoding=\"");
	xmlBufferWriteCHAR(cur->encoding);
	xmlBufferWriteChar("\"");
    }
    switch (cur->standalone) {
        case 0:
	    xmlBufferWriteChar(" standalone=\"no\"");
	    break;
        case 1:
	    xmlBufferWriteChar(" standalone=\"yes\"");
	    break;
    }
    xmlBufferWriteChar("?>\n");
    if ((cur->dtd != NULL) || (cur->entities != NULL))
        xmlDtdDump(cur);
    if (cur->root != NULL) {
	/* global namespace definitions, the old way */
	if (oldXMLWDcompatibility)
	    xmlGlobalNsListDump(cur->oldNs);
	else 
	    xmlUpgradeOldNs(cur);
        xmlNodeDump(cur, cur->root, 0);
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
    xmlDocContentDump(cur);

    *mem = buffer;
    *size = buffer_index;
}

/*
 * Get/Set a document compression mode.
 */

int  xmlGetDocCompressMode (xmlDocPtr doc) {
    if (doc == NULL) return(-1);
    return(doc->compression);
}

void xmlSetDocCompressMode (xmlDocPtr doc, int mode) {
    if (doc == NULL) return;
    if (mode < 0) doc->compression = 0;
    else if (mode > 9) doc->compression = 9;
    else doc->compression = mode;
}

/*
 * Get/Set the global compression mode
 */

int  xmlGetCompressMode(void) {
    return(xmlCompressMode);
}
void xmlSetCompressMode(int mode) {
    if (mode < 0) xmlCompressMode = 0;
    else if (mode > 9) xmlCompressMode = 9;
    else xmlCompressMode = mode;
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
    xmlDocContentDump(cur);

    fwrite(buffer, sizeof(CHAR), buffer_index, f);
}

/*
 * Dump an XML document to a file.
 */

int xmlSaveFile(const char *filename, xmlDocPtr cur) {
#ifdef HAVE_ZLIB_H
    gzFile zoutput = NULL;
    char mode[15];
#endif
    FILE *output;
    int ret;

#ifdef HAVE_ZLIB_H
    if ((cur->compression > 0) && (cur->compression <= 9)) {
        sprintf(mode, "w%d", cur->compression);
	zoutput = gzopen(filename, mode);
    }
    if (zoutput == NULL) {
#endif
        output = fopen(filename, "w");
	if (output == NULL) return(-1);
#ifdef HAVE_ZLIB_H
    }
#endif

    /* 
     * save the content to a temp buffer.
     */
    buffer_index = 0;
    xmlDocContentDump(cur);

#ifdef HAVE_ZLIB_H
    if (zoutput != NULL) {
        ret = gzwrite(zoutput, buffer, sizeof(CHAR) * buffer_index);
	gzclose(zoutput);
	return(ret);
    }
#endif
    ret = fwrite(buffer, sizeof(CHAR), buffer_index, output);
    fclose(output);
    return(ret * sizeof(CHAR));
}

/************************************************************************
 *									*
 *				Debug					*
 *									*
 ************************************************************************/

#ifdef STANDALONE
int main(void) {
    xmlDocPtr doc;
    xmlNodePtr tree, subtree;
    xmlNsPtr ns1;
    xmlNsPtr ns2;

    /*
     * build a fake XML document
     */
    doc = xmlNewDoc("1.0");
    ns1 = xmlNewNs(doc, "http://www.ietf.org/standards/dav/", "D");
    ns2 = xmlNewNs(doc, "http://www.w3.com/standards/z39.50/", "Z");
    doc->root = xmlNewNode(ns1, "multistatus", NULL);
    tree = xmlNewChild(doc->root, NULL, "response", NULL);
    subtree = xmlNewChild(tree, NULL, "prop", NULL);
    xmlNewChild(subtree, ns2, "Authors", NULL);
    subtree = xmlNewChild(tree, NULL, "status", "HTTP/1.1 420 Method Failure");
    tree = xmlNewChild(doc->root, NULL, "response", NULL);
    subtree = xmlNewChild(tree, NULL, "prop", NULL);
    xmlNewChild(subtree, ns2, "Copyright-Owner", NULL);
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
