/*
 * tree.c : implemetation of access function for an XML tree.
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
#include <string.h> /* for memset() only ! */

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/entities.h>
#include <libxml/valid.h>

static xmlChar xmlStringText[] = { 't', 'e', 'x', 't', 0 };
static xmlChar xmlStringComment[] = { 'c', 'o', 'm', 'm', 'e', 'n', 't', 0 };
int oldXMLWDcompatibility = 0;
int xmlIndentTreeOutput = 0;
xmlBufferAllocationScheme xmlBufferAllocScheme = XML_BUFFER_ALLOC_EXACT;

static int xmlCompressMode = 0;
static int xmlCheckDTD = 1;
int xmlSaveNoEmptyTags = 0;

#define IS_BLANK(c)							\
  (((c) == '\n') || ((c) == '\r') || ((c) == '\t') || ((c) == ' '))

#define UPDATE_LAST_CHILD(n) if ((n) != NULL) {				\
    xmlNodePtr ulccur = (n)->children;					\
    if (ulccur == NULL) {						\
        (n)->last = NULL;						\
    } else {								\
        while (ulccur->next != NULL) ulccur = ulccur->next;		\
	(n)->last = ulccur;						\
}}

/* #define DEBUG_BUFFER */
/* #define DEBUG_TREE */

/************************************************************************
 *									*
 *		Allocation and deallocation of basic structures		*
 *									*
 ************************************************************************/
 
/**
 * xmlSetBufferAllocationScheme:
 * @scheme:  allocation method to use
 * 
 * Set the buffer allocation method.  Types are
 * XML_BUFFER_ALLOC_EXACT - use exact sizes, keeps memory usage down
 * XML_BUFFER_ALLOC_DOUBLEIT - double buffer when extra needed, 
 *                             improves performance
 */
void
xmlSetBufferAllocationScheme(xmlBufferAllocationScheme scheme) {
    xmlBufferAllocScheme = scheme;
}

/**
 * xmlGetBufferAllocationScheme:
 *
 * Types are
 * XML_BUFFER_ALLOC_EXACT - use exact sizes, keeps memory usage down
 * XML_BUFFER_ALLOC_DOUBLEIT - double buffer when extra needed, 
 *                             improves performance
 * 
 * Returns the current allocation scheme
 */
xmlBufferAllocationScheme
xmlGetBufferAllocationScheme() {
    return xmlBufferAllocScheme;
}

/**
 * xmlUpgradeOldNs:
 * @doc:  a document pointer
 * 
 * Upgrade old style Namespaces (PI) and move them to the root of the document.
 */
void
xmlUpgradeOldNs(xmlDocPtr doc) {
    xmlNsPtr cur;

    if ((doc == NULL) || (doc->oldNs == NULL)) return;
    if (doc->children == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlUpgradeOldNs: failed no root !\n");
#endif
	return;
    }

    cur = doc->oldNs;
    while (cur->next != NULL) {
	cur->type = XML_LOCAL_NAMESPACE;
        cur = cur->next;
    }
    cur->type = XML_LOCAL_NAMESPACE;
    cur->next = doc->children->nsDef;
    doc->children->nsDef = doc->oldNs;
    doc->oldNs = NULL;
}

/**
 * xmlNewNs:
 * @node:  the element carrying the namespace
 * @href:  the URI associated
 * @prefix:  the prefix for the namespace
 *
 * Creation of a new Namespace. This function will refuse to create
 * a namespace with a similar prefix than an existing one present on this
 * node.
 * Returns returns a new namespace pointer or NULL
 */
xmlNsPtr
xmlNewNs(xmlNodePtr node, const xmlChar *href, const xmlChar *prefix) {
    xmlNsPtr cur;

    if (href == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewNs: href == NULL !\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new Namespace and fill the fields.
     */
    cur = (xmlNsPtr) xmlMalloc(sizeof(xmlNs));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewNs : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNs));
    cur->type = XML_LOCAL_NAMESPACE;

    if (href != NULL)
	cur->href = xmlStrdup(href); 
    if (prefix != NULL)
	cur->prefix = xmlStrdup(prefix); 

    /*
     * Add it at the end to preserve parsing order ...
     * and checks for existing use of the prefix
     */
    if (node != NULL) {
	if (node->nsDef == NULL) {
	    node->nsDef = cur;
	} else {
	    xmlNsPtr prev = node->nsDef;

	    if (((prev->prefix == NULL) && (cur->prefix == NULL)) ||
		(!xmlStrcmp(prev->prefix, cur->prefix))) {
		xmlFreeNs(cur);
		return(NULL);
	    }    
	    while (prev->next != NULL) {
	        prev = prev->next;
		if (((prev->prefix == NULL) && (cur->prefix == NULL)) ||
		    (!xmlStrcmp(prev->prefix, cur->prefix))) {
		    xmlFreeNs(cur);
		    return(NULL);
		}    
	    }
	    prev->next = cur;
	}
    }
    return(cur);
}

/**
 * xmlNewGlobalNs:
 * @doc:  the document carrying the namespace
 * @href:  the URI associated
 * @prefix:  the prefix for the namespace
 *
 * Creation of a Namespace, the old way using PI and without scoping
 *   DEPRECATED !!!
 * It now create a namespace on the root element of the document if found.
 * Returns NULL this functionnality had been removed
 */
xmlNsPtr
xmlNewGlobalNs(xmlDocPtr doc, const xmlChar *href, const xmlChar *prefix) {
    xmlNodePtr root;

    xmlNsPtr cur;
 
    root = xmlDocGetRootElement(doc);
    if (root != NULL)
	return(xmlNewNs(root, href, prefix));
	
    /*
     * if there is no root element yet, create an old Namespace type
     * and it will be moved to the root at save time.
     */
    cur = (xmlNsPtr) xmlMalloc(sizeof(xmlNs));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewGlobalNs : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNs));
    cur->type = XML_GLOBAL_NAMESPACE;

    if (href != NULL)
	cur->href = xmlStrdup(href); 
    if (prefix != NULL)
	cur->prefix = xmlStrdup(prefix); 

    /*
     * Add it at the end to preserve parsing order ...
     */
    if (doc != NULL) {
	if (doc->oldNs == NULL) {
	    doc->oldNs = cur;
	} else {
	    xmlNsPtr prev = doc->oldNs;

	    while (prev->next != NULL) prev = prev->next;
	    prev->next = cur;
	}
    }

  return(NULL);
}

/**
 * xmlSetNs:
 * @node:  a node in the document
 * @ns:  a namespace pointer
 *
 * Associate a namespace to a node, a posteriori.
 */
void
xmlSetNs(xmlNodePtr node, xmlNsPtr ns) {
    if (node == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlSetNs: node == NULL\n");
#endif
	return;
    }
    node->ns = ns;
}

/**
 * xmlFreeNs:
 * @cur:  the namespace pointer
 *
 * Free up the structures associated to a namespace
 */
void
xmlFreeNs(xmlNsPtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreeNs : ns == NULL\n");
#endif
	return;
    }
    if (cur->href != NULL) xmlFree((char *) cur->href);
    if (cur->prefix != NULL) xmlFree((char *) cur->prefix);
    memset(cur, -1, sizeof(xmlNs));
    xmlFree(cur);
}

/**
 * xmlFreeNsList:
 * @cur:  the first namespace pointer
 *
 * Free up all the structures associated to the chained namespaces.
 */
void
xmlFreeNsList(xmlNsPtr cur) {
    xmlNsPtr next;
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreeNsList : ns == NULL\n");
#endif
	return;
    }
    while (cur != NULL) {
        next = cur->next;
        xmlFreeNs(cur);
	cur = next;
    }
}

/**
 * xmlNewDtd:
 * @doc:  the document pointer
 * @name:  the DTD name
 * @ExternalID:  the external ID
 * @SystemID:  the system ID
 *
 * Creation of a new DTD for the external subset. To create an
 * internal subset, use xmlCreateIntSubset().
 *
 * Returns a pointer to the new DTD structure
 */
xmlDtdPtr
xmlNewDtd(xmlDocPtr doc, const xmlChar *name,
                    const xmlChar *ExternalID, const xmlChar *SystemID) {
    xmlDtdPtr cur;

    if ((doc != NULL) && (doc->extSubset != NULL)) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewDtd(%s): document %s already have a DTD %s\n",
	    /* !!! */ (char *) name, doc->name,
	    /* !!! */ (char *)doc->extSubset->name);
#endif
	return(NULL);
    }

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlDtdPtr) xmlMalloc(sizeof(xmlDtd));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDtd : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0 , sizeof(xmlDtd));
    cur->type = XML_DTD_NODE;

    if (name != NULL)
	cur->name = xmlStrdup(name); 
    if (ExternalID != NULL)
	cur->ExternalID = xmlStrdup(ExternalID); 
    if (SystemID != NULL)
	cur->SystemID = xmlStrdup(SystemID); 
    if (doc != NULL)
	doc->extSubset = cur;
    cur->doc = doc;

    return(cur);
}

/**
 * xmlGetIntSubset:
 * @doc:  the document pointer
 *
 * Get the internal subset of a document
 * Returns a pointer to the DTD structure or NULL if not found
 */

xmlDtdPtr
xmlGetIntSubset(xmlDocPtr doc) {
    xmlNodePtr cur;

    if (doc == NULL)
	return(NULL);
    cur = doc->children;
    while (cur != NULL) {
	if (cur->type == XML_DTD_NODE)
	    return((xmlDtdPtr) cur);
	cur = cur->next;
    }
    return((xmlDtdPtr) doc->intSubset);
}

/**
 * xmlCreateIntSubset:
 * @doc:  the document pointer
 * @name:  the DTD name
 * @ExternalID:  the external ID
 * @SystemID:  the system ID
 *
 * Create the internal subset of a document
 * Returns a pointer to the new DTD structure
 */
xmlDtdPtr
xmlCreateIntSubset(xmlDocPtr doc, const xmlChar *name,
                   const xmlChar *ExternalID, const xmlChar *SystemID) {
    xmlDtdPtr cur;

    if ((doc != NULL) && (xmlGetIntSubset(doc) != NULL)) {
#ifdef DEBUG_TREE
        fprintf(stderr, 
     "xmlCreateIntSubset(): document %s already have an internal subset\n",
	    doc->name);
#endif
	return(NULL);
    }

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlDtdPtr) xmlMalloc(sizeof(xmlDtd));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDtd : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlDtd));
    cur->type = XML_DTD_NODE;

    if (name != NULL)
	cur->name = xmlStrdup(name); 
    if (ExternalID != NULL)
	cur->ExternalID = xmlStrdup(ExternalID); 
    if (SystemID != NULL)
	cur->SystemID = xmlStrdup(SystemID); 
    if (doc != NULL) {
	doc->intSubset = cur;
	cur->parent = doc;
	cur->doc = doc;
	if (doc->children == NULL) {
	    doc->children = (xmlNodePtr) cur;
	    doc->last = (xmlNodePtr) cur;
	} else {
	    xmlNodePtr prev;

	    prev = doc->last;
	    prev->next = (xmlNodePtr) cur;
	    cur->prev = prev;
	    doc->last = (xmlNodePtr) cur;
	}
    }
    return(cur);
}

/**
 * xmlFreeDtd:
 * @cur:  the DTD structure to free up
 *
 * Free a DTD structure.
 */
void
xmlFreeDtd(xmlDtdPtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreeDtd : DTD == NULL\n");
#endif
	return;
    }
    if (cur->children != NULL) {
	xmlNodePtr next, c = cur->children;

	/*
	 * Cleanup all the DTD comments they are not in the Dtd
	 * indexes.
	 */
        while (c != NULL) {
	    next = c->next;
	    if (c->type == XML_COMMENT_NODE) {
		xmlUnlinkNode(c);
		xmlFreeNode(c);
	    }
	    c = next;
	}
    }
    if (cur->name != NULL) xmlFree((char *) cur->name);
    if (cur->SystemID != NULL) xmlFree((char *) cur->SystemID);
    if (cur->ExternalID != NULL) xmlFree((char *) cur->ExternalID);
    /* TODO !!! */
    if (cur->notations != NULL)
        xmlFreeNotationTable((xmlNotationTablePtr) cur->notations);
    
    if (cur->elements != NULL)
        xmlFreeElementTable((xmlElementTablePtr) cur->elements);
    if (cur->attributes != NULL)
        xmlFreeAttributeTable((xmlAttributeTablePtr) cur->attributes);
    if (cur->entities != NULL)
        xmlFreeEntitiesTable((xmlEntitiesTablePtr) cur->entities);

    memset(cur, -1, sizeof(xmlDtd));
    xmlFree(cur);
}

/**
 * xmlNewDoc:
 * @version:  xmlChar string giving the version of XML "1.0"
 *
 * Returns a new document
 */
xmlDocPtr
xmlNewDoc(const xmlChar *version) {
    xmlDocPtr cur;

    if (version == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewDoc : version == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new document and fill the fields.
     */
    cur = (xmlDocPtr) xmlMalloc(sizeof(xmlDoc));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDoc : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlDoc));
    cur->type = XML_DOCUMENT_NODE;

    cur->version = xmlStrdup(version); 
    cur->standalone = -1;
    cur->compression = -1; /* not initialized */
    cur->doc = cur;
    return(cur);
}

/**
 * xmlFreeDoc:
 * @cur:  pointer to the document
 * @:  
 *
 * Free up all the structures used by a document, tree included.
 */
void
xmlFreeDoc(xmlDocPtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreeDoc : document == NULL\n");
#endif
	return;
    }
    if (cur->version != NULL) xmlFree((char *) cur->version);
    if (cur->name != NULL) xmlFree((char *) cur->name);
    if (cur->encoding != NULL) xmlFree((char *) cur->encoding);
    if (cur->children != NULL) xmlFreeNodeList(cur->children);
    if (cur->intSubset != NULL) xmlFreeDtd(cur->intSubset);
    if (cur->extSubset != NULL) xmlFreeDtd(cur->extSubset);
    if (cur->oldNs != NULL) xmlFreeNsList(cur->oldNs);
    if (cur->ids != NULL) xmlFreeIDTable((xmlIDTablePtr) cur->ids);
    if (cur->refs != NULL) xmlFreeRefTable((xmlRefTablePtr) cur->refs);
    if (cur->URL != NULL) xmlFree((char *) cur->URL);
    memset(cur, -1, sizeof(xmlDoc));
    xmlFree(cur);
}

/**
 * xmlStringLenGetNodeList:
 * @doc:  the document
 * @value:  the value of the text
 * @len:  the length of the string value
 *
 * Parse the value string and build the node list associated. Should
 * produce a flat tree with only TEXTs and ENTITY_REFs.
 * Returns a pointer to the first child
 */
xmlNodePtr
xmlStringLenGetNodeList(xmlDocPtr doc, const xmlChar *value, int len) {
    xmlNodePtr ret = NULL, last = NULL;
    xmlNodePtr node;
    xmlChar *val;
    const xmlChar *cur = value;
    const xmlChar *q;
    xmlEntityPtr ent;

    if (value == NULL) return(NULL);

    q = cur;
    while ((*cur != 0) && (cur - value < len)) {
	if (*cur == '&') {
	    /*
	     * Save the current text.
	     */
            if (cur != q) {
		if ((last != NULL) && (last->type == XML_TEXT_NODE)) {
		    xmlNodeAddContentLen(last, q, cur - q);
		} else {
		    node = xmlNewDocTextLen(doc, q, cur - q);
		    if (node == NULL) return(ret);
		    if (last == NULL)
			last = ret = node;
		    else {
			last->next = node;
			node->prev = last;
			last = node;
		    }
		}
	    }
	    /*
	     * Read the entity string
	     */
	    cur++;
	    q = cur;
	    while ((*cur != 0) && (cur - value < len) && (*cur != ';')) cur++;
	    if ((*cur == 0) || (cur - value >= len)) {
#ifdef DEBUG_TREE
	        fprintf(stderr,
		    "xmlStringLenGetNodeList: unterminated entity %30s\n", q);
#endif
	        return(ret);
	    }
            if (cur != q) {
		/*
		 * Predefined entities don't generate nodes
		 */
		val = xmlStrndup(q, cur - q);
		ent = xmlGetDocEntity(doc, val);
		if ((ent != NULL) &&
		    (ent->etype == XML_INTERNAL_PREDEFINED_ENTITY)) {
		    if (last == NULL) {
		        node = xmlNewDocText(doc, ent->content);
			last = ret = node;
		    } else
		        xmlNodeAddContent(last, ent->content);
		        
		} else {
		    /*
		     * Create a new REFERENCE_REF node
		     */
		    node = xmlNewReference(doc, val);
		    if (node == NULL) {
			if (val != NULL) xmlFree(val);
		        return(ret);
		    }
		    if (last == NULL)
			last = ret = node;
		    else {
			last->next = node;
			node->prev = last;
			last = node;
		    }
		}
		xmlFree(val);
	    }
	    cur++;
	    q = cur;
	} else 
	    cur++;
    }
    if (cur != q) {
        /*
	 * Handle the last piece of text.
	 */
	if ((last != NULL) && (last->type == XML_TEXT_NODE)) {
	    xmlNodeAddContentLen(last, q, cur - q);
	} else {
	    node = xmlNewDocTextLen(doc, q, cur - q);
	    if (node == NULL) return(ret);
	    if (last == NULL)
		last = ret = node;
	    else {
		last->next = node;
		node->prev = last;
		last = node;
	    }
	}
    }
    return(ret);
}

/**
 * xmlStringGetNodeList:
 * @doc:  the document
 * @value:  the value of the attribute
 *
 * Parse the value string and build the node list associated. Should
 * produce a flat tree with only TEXTs and ENTITY_REFs.
 * Returns a pointer to the first child
 */
xmlNodePtr
xmlStringGetNodeList(xmlDocPtr doc, const xmlChar *value) {
    xmlNodePtr ret = NULL, last = NULL;
    xmlNodePtr node;
    xmlChar *val;
    const xmlChar *cur = value;
    const xmlChar *q;
    xmlEntityPtr ent;

    if (value == NULL) return(NULL);

    q = cur;
    while (*cur != 0) {
	if (*cur == '&') {
	    /*
	     * Save the current text.
	     */
            if (cur != q) {
		if ((last != NULL) && (last->type == XML_TEXT_NODE)) {
		    xmlNodeAddContentLen(last, q, cur - q);
		} else {
		    node = xmlNewDocTextLen(doc, q, cur - q);
		    if (node == NULL) return(ret);
		    if (last == NULL)
			last = ret = node;
		    else {
			last->next = node;
			node->prev = last;
			last = node;
		    }
		}
	    }
	    /*
	     * Read the entity string
	     */
	    cur++;
	    q = cur;
	    while ((*cur != 0) && (*cur != ';')) cur++;
	    if (*cur == 0) {
#ifdef DEBUG_TREE
	        fprintf(stderr,
		        "xmlStringGetNodeList: unterminated entity %30s\n", q);
#endif
	        return(ret);
	    }
            if (cur != q) {
		/*
		 * Predefined entities don't generate nodes
		 */
		val = xmlStrndup(q, cur - q);
		ent = xmlGetDocEntity(doc, val);
		if ((ent != NULL) &&
		    (ent->etype == XML_INTERNAL_PREDEFINED_ENTITY)) {
		    if (last == NULL) {
		        node = xmlNewDocText(doc, ent->content);
			last = ret = node;
		    } else
		        xmlNodeAddContent(last, ent->content);
		        
		} else {
		    /*
		     * Create a new REFERENCE_REF node
		     */
		    node = xmlNewReference(doc, val);
		    if (node == NULL) {
			if (val != NULL) xmlFree(val);
		        return(ret);
		    }
		    if (last == NULL)
			last = ret = node;
		    else {
			last->next = node;
			node->prev = last;
			last = node;
		    }
		}
		xmlFree(val);
	    }
	    cur++;
	    q = cur;
	} else 
	    cur++;
    }
    if (cur != q) {
        /*
	 * Handle the last piece of text.
	 */
	if ((last != NULL) && (last->type == XML_TEXT_NODE)) {
	    xmlNodeAddContentLen(last, q, cur - q);
	} else {
	    node = xmlNewDocTextLen(doc, q, cur - q);
	    if (node == NULL) return(ret);
	    if (last == NULL)
		last = ret = node;
	    else {
		last->next = node;
		node->prev = last;
		last = node;
	    }
	}
    }
    return(ret);
}

/**
 * xmlNodeListGetString:
 * @doc:  the document
 * @list:  a Node list
 * @inLine:  should we replace entity contents or show their external form
 *
 * Returns the string equivalent to the text contained in the Node list
 * made of TEXTs and ENTITY_REFs
 * Returns a pointer to the string copy, the calller must free it.
 */
xmlChar *
xmlNodeListGetString(xmlDocPtr doc, xmlNodePtr list, int inLine) {
    xmlNodePtr node = list;
    xmlChar *ret = NULL;
    xmlEntityPtr ent;

    if (list == NULL) return(NULL);

    while (node != NULL) {
        if (node->type == XML_TEXT_NODE) {
	    if (inLine) {
#ifndef XML_USE_BUFFER_CONTENT
		ret = xmlStrcat(ret, node->content);
#else
		ret = xmlStrcat(ret, xmlBufferContent(node->content));
#endif
	    } else {
	        xmlChar *buffer;

#ifndef XML_USE_BUFFER_CONTENT
		buffer = xmlEncodeEntitiesReentrant(doc, node->content);
#else
		buffer = xmlEncodeEntitiesReentrant(doc,
					    xmlBufferContent(node->content));
#endif
		if (buffer != NULL) {
		    ret = xmlStrcat(ret, buffer);
		    xmlFree(buffer);
		}
            }
	} else if (node->type == XML_ENTITY_REF_NODE) {
	    if (inLine) {
		ent = xmlGetDocEntity(doc, node->name);
		if (ent != NULL)
		    ret = xmlStrcat(ret, ent->content);
		else {
#ifndef XML_USE_BUFFER_CONTENT
		    ret = xmlStrcat(ret, node->content);
#else
		    ret = xmlStrcat(ret, xmlBufferContent(node->content));
#endif
		}    
            } else {
	        xmlChar buf[2];
		buf[0] = '&'; buf[1] = 0;
		ret = xmlStrncat(ret, buf, 1);
		ret = xmlStrcat(ret, node->name);
		buf[0] = ';'; buf[1] = 0;
		ret = xmlStrncat(ret, buf, 1);
	    }
	}
#if 0
	else {
	    fprintf(stderr, "xmlGetNodeListString : invalide node type %d\n",
	            node->type);
	}
#endif
	node = node->next;
    }
    return(ret);
}

/**
 * xmlNewProp:
 * @node:  the holding node
 * @name:  the name of the attribute
 * @value:  the value of the attribute
 *
 * Create a new property carried by a node.
 * Returns a pointer to the attribute
 */
xmlAttrPtr
xmlNewProp(xmlNodePtr node, const xmlChar *name, const xmlChar *value) {
    xmlAttrPtr cur;

    if (name == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewProp : name == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new property and fill the fields.
     */
    cur = (xmlAttrPtr) xmlMalloc(sizeof(xmlAttr));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewProp : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlAttr));
    cur->type = XML_ATTRIBUTE_NODE;

    cur->parent = node; 
    cur->name = xmlStrdup(name);
    if (value != NULL) {
	xmlChar *buffer;
	xmlNodePtr tmp;

	buffer = xmlEncodeEntitiesReentrant(node->doc, value);
	cur->children = xmlStringGetNodeList(node->doc, buffer);
	tmp = cur->children;
	while (tmp != NULL) {
	    tmp->parent = (xmlNodePtr) cur;
	    if (tmp->next == NULL)
		cur->last = tmp;
	    tmp = tmp->next;
	}
	xmlFree(buffer);
    }	

    /*
     * Add it at the end to preserve parsing order ...
     */
    if (node != NULL) {
	if (node->properties == NULL) {
	    node->properties = cur;
	} else {
	    xmlAttrPtr prev = node->properties;

	    while (prev->next != NULL) prev = prev->next;
	    prev->next = cur;
	    cur->prev = prev;
	}
    }
    return(cur);
}

/**
 * xmlNewNsProp:
 * @node:  the holding node
 * @ns:  the namespace
 * @name:  the name of the attribute
 * @value:  the value of the attribute
 *
 * Create a new property tagged with a namespace and carried by a node.
 * Returns a pointer to the attribute
 */
xmlAttrPtr
xmlNewNsProp(xmlNodePtr node, xmlNsPtr ns, const xmlChar *name,
           const xmlChar *value) {
    xmlAttrPtr cur;

    if (name == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewProp : name == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new property and fill the fields.
     */
    cur = (xmlAttrPtr) xmlMalloc(sizeof(xmlAttr));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewProp : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlAttr));
    cur->type = XML_ATTRIBUTE_NODE;

    cur->parent = node; 
    if (node != NULL)
	cur->doc = node->doc; 
    cur->ns = ns;
    cur->name = xmlStrdup(name);
    if (value != NULL) {
	xmlChar *buffer;
	xmlNodePtr tmp;

	buffer = xmlEncodeEntitiesReentrant(node->doc, value);
	cur->children = xmlStringGetNodeList(node->doc, buffer);
	tmp = cur->children;
	while (tmp != NULL) {
	    tmp->parent = (xmlNodePtr) cur;
	    if (tmp->next == NULL)
		cur->last = tmp;
	    tmp = tmp->next;
	}
	xmlFree(buffer);
    }

    /*
     * Add it at the end to preserve parsing order ...
     */
    if (node != NULL) {
	if (node->properties == NULL) {
	    node->properties = cur;
	} else {
	    xmlAttrPtr prev = node->properties;

	    while (prev->next != NULL) prev = prev->next;
	    prev->next = cur;
	    cur->prev = prev;
	}
    }
    return(cur);
}

/**
 * xmlNewDocProp:
 * @doc:  the document
 * @name:  the name of the attribute
 * @value:  the value of the attribute
 *
 * Create a new property carried by a document.
 * Returns a pointer to the attribute
 */
xmlAttrPtr
xmlNewDocProp(xmlDocPtr doc, const xmlChar *name, const xmlChar *value) {
    xmlAttrPtr cur;

    if (name == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewProp : name == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new property and fill the fields.
     */
    cur = (xmlAttrPtr) xmlMalloc(sizeof(xmlAttr));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewProp : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlAttr));
    cur->type = XML_ATTRIBUTE_NODE;

    cur->name = xmlStrdup(name);
    cur->doc = doc; 
    if (value != NULL)
	cur->children = xmlStringGetNodeList(doc, value);
    return(cur);
}

/**
 * xmlFreePropList:
 * @cur:  the first property in the list
 *
 * Free a property and all its siblings, all the children are freed too.
 */
void
xmlFreePropList(xmlAttrPtr cur) {
    xmlAttrPtr next;
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreePropList : property == NULL\n");
#endif
	return;
    }
    while (cur != NULL) {
        next = cur->next;
        xmlFreeProp(cur);
	cur = next;
    }
}

/**
 * xmlFreeProp:
 * @cur:  an attribute
 *
 * Free one attribute, all the content is freed too
 */
void
xmlFreeProp(xmlAttrPtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreeProp : property == NULL\n");
#endif
	return;
    }
    /* Check for ID removal -> leading to invalid references ! */
    if ((cur->parent != NULL) && 
        (xmlIsID(cur->parent->doc, cur->parent, cur)))
        xmlRemoveID(cur->parent->doc, cur);
    if (cur->name != NULL) xmlFree((char *) cur->name);
    if (cur->children != NULL) xmlFreeNodeList(cur->children);
    memset(cur, -1, sizeof(xmlAttr));
    xmlFree(cur);
}

/**
 * xmlRemoveProp:
 * @cur:  an attribute
 *
 * Unlink and free one attribute, all the content is freed too
 * Note this doesn't work for namespace definition attributes
 *
 * Returns 0 if success and -1 in case of error.
 */
int
xmlRemoveProp(xmlAttrPtr cur) {
    xmlAttrPtr tmp;
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlRemoveProp : cur == NULL\n");
#endif
	return(-1);
    }
    if (cur->parent == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlRemoveProp : cur->parent == NULL\n");
#endif
	return(-1);
    }
    tmp = cur->parent->properties;
    if (tmp == cur) {
        cur->parent->properties = cur->next;
	xmlFreeProp(cur);
	return(0);
    }
    while (tmp != NULL) {
	if (tmp->next == cur) {
	    tmp->next = cur->next;
	    if (tmp->next != NULL)
		tmp->next->prev = tmp;
	    xmlFreeProp(cur);
	    return(0);
	}
        tmp = tmp->next;
    }
#ifdef DEBUG_TREE
    fprintf(stderr, "xmlRemoveProp : attribute not owned by its node\n");
#endif
    return(-1);
}

/**
 * xmlNewPI:
 * @name:  the processing instruction name
 * @content:  the PI content
 *
 * Creation of a processing instruction element.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewPI(const xmlChar *name, const xmlChar *content) {
    xmlNodePtr cur;

    if (name == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewPI : name == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewPI : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_PI_NODE;

    cur->name = xmlStrdup(name);
    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	cur->content = xmlStrdup(content);
#else
	cur->content = xmlBufferCreateSize(0);
	xmlBufferSetAllocationScheme(cur->content,
		                     xmlGetBufferAllocationScheme());
	xmlBufferAdd(cur->content, content, -1);
#endif
    }
    return(cur);
}

/**
 * xmlNewNode:
 * @ns:  namespace if any
 * @name:  the node name
 *
 * Creation of a new node element. @ns and @content are optionnal (NULL).
 * If content is non NULL, a child list containing the TEXTs and
 * ENTITY_REFs node will be created.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewNode(xmlNsPtr ns, const xmlChar *name) {
    xmlNodePtr cur;

    if (name == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewNode : name == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewNode : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_ELEMENT_NODE;
    
    cur->name = xmlStrdup(name);
    cur->ns = ns;
    return(cur);
}

/**
 * xmlNewDocNode:
 * @doc:  the document
 * @ns:  namespace if any
 * @name:  the node name
 * @content:  the XML text content if any
 *
 * Creation of a new node element within a document. @ns and @content
 * are optionnal (NULL).
 * NOTE: @content is supposed to be a piece of XML CDATA, so it allow entities
 *       references, but XML special chars need to be escaped first by using
 *       xmlEncodeEntitiesReentrant(). Use xmlNewDocRawNode() if you don't
 *       need entities support.
 *
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocNode(xmlDocPtr doc, xmlNsPtr ns,
              const xmlChar *name, const xmlChar *content) {
    xmlNodePtr cur;

    cur = xmlNewNode(ns, name);
    if (cur != NULL) {
        cur->doc = doc;
	if (content != NULL) {
	    cur->children = xmlStringGetNodeList(doc, content);
	    UPDATE_LAST_CHILD(cur)
	}
    }
    return(cur);
}


/**
 * xmlNewDocRawNode:
 * @doc:  the document
 * @ns:  namespace if any
 * @name:  the node name
 * @content:  the text content if any
 *
 * Creation of a new node element within a document. @ns and @content
 * are optionnal (NULL).
 *
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocRawNode(xmlDocPtr doc, xmlNsPtr ns,
                 const xmlChar *name, const xmlChar *content) {
    xmlNodePtr cur;

    cur = xmlNewNode(ns, name);
    if (cur != NULL) {
        cur->doc = doc;
	if (content != NULL) {
	    cur->children = xmlNewDocText(doc, content);
	    UPDATE_LAST_CHILD(cur)
	}
    }
    return(cur);
}

/**
 * xmlNewDocFragment:
 * @doc:  the document owning the fragment
 *
 * Creation of a new Fragment node.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocFragment(xmlDocPtr doc) {
    xmlNodePtr cur;

    /*
     * Allocate a new DocumentFragment node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDocFragment : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_DOCUMENT_FRAG_NODE;

    cur->doc = doc;
    return(cur);
}

/**
 * xmlNewText:
 * @content:  the text content
 *
 * Creation of a new text node.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewText(const xmlChar *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_TEXT_NODE;

    cur->name = xmlStrdup(xmlStringText);
    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	cur->content = xmlStrdup(content);
#else
	cur->content = xmlBufferCreateSize(0);
	xmlBufferSetAllocationScheme(cur->content,
		                     xmlGetBufferAllocationScheme());
	xmlBufferAdd(cur->content, content, -1);
#endif
    }
    return(cur);
}

/**
 * xmlNewTextChild:
 * @parent:  the parent node
 * @ns:  a namespace if any
 * @name:  the name of the child
 * @content:  the text content of the child if any.
 *
 * Creation of a new child element, added at the end of @parent children list.
 * @ns and @content parameters are optionnal (NULL). If content is non NULL,
 * a child TEXT node will be created containing the string content.
 *
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewTextChild(xmlNodePtr parent, xmlNsPtr ns,
            const xmlChar *name, const xmlChar *content) {
    xmlNodePtr cur, prev;

    if (parent == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewTextChild : parent == NULL\n");
#endif
	return(NULL);
    }

    if (name == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewTextChild : name == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new node
     */
    if (ns == NULL)
	cur = xmlNewDocRawNode(parent->doc, parent->ns, name, content);
    else
	cur = xmlNewDocRawNode(parent->doc, ns, name, content);
    if (cur == NULL) return(NULL);

    /*
     * add the new element at the end of the children list.
     */
    cur->type = XML_ELEMENT_NODE;
    cur->parent = parent;
    cur->doc = parent->doc;
    if (parent->children == NULL) {
        parent->children = cur;
	parent->last = cur;
    } else {
        prev = parent->last;
	prev->next = cur;
	cur->prev = prev;
	parent->last = cur;
    }

    return(cur);
}

/**
 * xmlNewCharRef:
 * @doc: the document
 * @name:  the char ref string, starting with # or "&# ... ;"
 *
 * Creation of a new character reference node.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewCharRef(xmlDocPtr doc, const xmlChar *name) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_ENTITY_REF_NODE;

    cur->doc = doc;
    if (name[0] == '&') {
        int len;
        name++;
	len = xmlStrlen(name);
	if (name[len - 1] == ';')
	    cur->name = xmlStrndup(name, len - 1);
	else
	    cur->name = xmlStrndup(name, len);
    } else
	cur->name = xmlStrdup(name);
    return(cur);
}

/**
 * xmlNewReference:
 * @doc: the document
 * @name:  the reference name, or the reference string with & and ;
 *
 * Creation of a new reference node.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewReference(xmlDocPtr doc, const xmlChar *name) {
    xmlNodePtr cur;
    xmlEntityPtr ent;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_ENTITY_REF_NODE;

    cur->doc = doc;
    if (name[0] == '&') {
        int len;
        name++;
	len = xmlStrlen(name);
	if (name[len - 1] == ';')
	    cur->name = xmlStrndup(name, len - 1);
	else
	    cur->name = xmlStrndup(name, len);
    } else
	cur->name = xmlStrdup(name);

    ent = xmlGetDocEntity(doc, cur->name);
    if (ent != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	cur->content = ent->content;
#else
	/*
	 * CJN 11.18.99 this might be a problem, since the xmlBuffer gets
	 * a copy of this pointer.  Let's hope we don't manipulate it
	 * later 
	 */
	cur->content = xmlBufferCreateSize(0);
	xmlBufferSetAllocationScheme(cur->content,
		                     xmlGetBufferAllocationScheme());
	if (ent->content != NULL)
	    xmlBufferAdd(cur->content, ent->content, -1);
#endif
	cur->children = (xmlNodePtr) ent;
    }
    return(cur);
}

/**
 * xmlNewDocText:
 * @doc: the document
 * @content:  the text content
 *
 * Creation of a new text node within a document.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocText(xmlDocPtr doc, const xmlChar *content) {
    xmlNodePtr cur;

    cur = xmlNewText(content);
    if (cur != NULL) cur->doc = doc;
    return(cur);
}

/**
 * xmlNewTextLen:
 * @content:  the text content
 * @len:  the text len.
 *
 * Creation of a new text node with an extra parameter for the content's lenght
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewTextLen(const xmlChar *content, int len) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_TEXT_NODE;

    cur->name = xmlStrdup(xmlStringText);
    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	cur->content = xmlStrndup(content, len);
#else
	cur->content = xmlBufferCreateSize(len);
	xmlBufferSetAllocationScheme(cur->content,
		                     xmlGetBufferAllocationScheme());
	xmlBufferAdd(cur->content, content, len);
#endif
    }
    return(cur);
}

/**
 * xmlNewDocTextLen:
 * @doc: the document
 * @content:  the text content
 * @len:  the text len.
 *
 * Creation of a new text node with an extra content lenght parameter. The
 * text node pertain to a given document.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocTextLen(xmlDocPtr doc, const xmlChar *content, int len) {
    xmlNodePtr cur;

    cur = xmlNewTextLen(content, len);
    if (cur != NULL) cur->doc = doc;
    return(cur);
}

/**
 * xmlNewComment:
 * @content:  the comment content
 *
 * Creation of a new node containing a comment.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewComment(const xmlChar *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewComment : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_COMMENT_NODE;

    cur->name = xmlStrdup(xmlStringComment);
    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	cur->content = xmlStrdup(content);
#else
	cur->content = xmlBufferCreateSize(0);
	xmlBufferSetAllocationScheme(cur->content,
		                     xmlGetBufferAllocationScheme());
	xmlBufferAdd(cur->content, content, -1);
#endif
    }
    return(cur);
}

/**
 * xmlNewCDataBlock:
 * @doc:  the document
 * @content:  the CData block content content
 * @len:  the length of the block
 *
 * Creation of a new node containing a CData block.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewCDataBlock(xmlDocPtr doc, const xmlChar *content, int len) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewCDataBlock : malloc failed\n");
	return(NULL);
    }
    memset(cur, 0, sizeof(xmlNode));
    cur->type = XML_CDATA_SECTION_NODE;

    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	cur->content = xmlStrndup(content, len);
#else
	cur->content = xmlBufferCreateSize(len);
	xmlBufferSetAllocationScheme(cur->content,
		                     xmlGetBufferAllocationScheme());
	xmlBufferAdd(cur->content, content, len);
#endif
    }
    return(cur);
}

/**
 * xmlNewDocComment:
 * @doc:  the document
 * @content:  the comment content
 *
 * Creation of a new node containing a commentwithin a document.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocComment(xmlDocPtr doc, const xmlChar *content) {
    xmlNodePtr cur;

    cur = xmlNewComment(content);
    if (cur != NULL) cur->doc = doc;
    return(cur);
}


/**
 * xmlNewChild:
 * @parent:  the parent node
 * @ns:  a namespace if any
 * @name:  the name of the child
 * @content:  the XML content of the child if any.
 *
 * Creation of a new child element, added at the end of @parent children list.
 * @ns and @content parameters are optionnal (NULL). If content is non NULL,
 * a child list containing the TEXTs and ENTITY_REFs node will be created.
 * NOTE: @content is supposed to be a piece of XML CDATA, so it allow entities
 *       references, but XML special chars need to be escaped first by using
 *       xmlEncodeEntitiesReentrant(). Use xmlNewTextChild() if entities
 *       support is not needed.
 *
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewChild(xmlNodePtr parent, xmlNsPtr ns,
            const xmlChar *name, const xmlChar *content) {
    xmlNodePtr cur, prev;

    if (parent == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewChild : parent == NULL\n");
#endif
	return(NULL);
    }

    if (name == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewChild : name == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Allocate a new node
     */
    if (ns == NULL)
	cur = xmlNewDocNode(parent->doc, parent->ns, name, content);
    else
	cur = xmlNewDocNode(parent->doc, ns, name, content);
    if (cur == NULL) return(NULL);

    /*
     * add the new element at the end of the children list.
     */
    cur->type = XML_ELEMENT_NODE;
    cur->parent = parent;
    cur->doc = parent->doc;
    if (parent->children == NULL) {
        parent->children = cur;
	parent->last = cur;
    } else {
        prev = parent->last;
	prev->next = cur;
	cur->prev = prev;
	parent->last = cur;
    }

    return(cur);
}

/**
 * xmlAddNextSibling:
 * @cur:  the child node
 * @elem:  the new node
 *
 * Add a new element @elem as the next siblings of @cur
 * If the new element was already inserted in a document it is
 * first unlinked from its existing context.
 *
 * Returns the new element or NULL in case of error.
 */
xmlNodePtr
xmlAddNextSibling(xmlNodePtr cur, xmlNodePtr elem) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddNextSibling : cur == NULL\n");
#endif
	return(NULL);
    }
    if (elem == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddNextSibling : elem == NULL\n");
#endif
	return(NULL);
    }

    xmlUnlinkNode(elem);
    elem->doc = cur->doc;
    elem->parent = cur->parent;
    elem->prev = cur;
    elem->next = cur->next;
    cur->next = elem;
    if (elem->next != NULL)
	elem->next->prev = elem;
    if ((elem->parent != NULL) && (elem->parent->last == cur))
	elem->parent->last = elem;
    return(elem);
}

/**
 * xmlAddPrevSibling:
 * @cur:  the child node
 * @elem:  the new node
 *
 * Add a new element @elem as the previous siblings of @cur
 * If the new element was already inserted in a document it is
 * first unlinked from its existing context.
 *
 * Returns the new element or NULL in case of error.
 */
xmlNodePtr
xmlAddPrevSibling(xmlNodePtr cur, xmlNodePtr elem) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddPrevSibling : cur == NULL\n");
#endif
	return(NULL);
    }
    if (elem == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddPrevSibling : elem == NULL\n");
#endif
	return(NULL);
    }

    xmlUnlinkNode(elem);
    elem->doc = cur->doc;
    elem->parent = cur->parent;
    elem->next = cur;
    elem->prev = cur->prev;
    cur->prev = elem;
    if (elem->prev != NULL)
	elem->prev->next = elem;
    if ((elem->parent != NULL) && (elem->parent->children == cur))
	elem->parent->children = elem;
    return(elem);
}

/**
 * xmlAddSibling:
 * @cur:  the child node
 * @elem:  the new node
 *
 * Add a new element @elem to the list of siblings of @cur
 * If the new element was already inserted in a document it is
 * first unlinked from its existing context.
 *
 * Returns the new element or NULL in case of error.
 */
xmlNodePtr
xmlAddSibling(xmlNodePtr cur, xmlNodePtr elem) {
    xmlNodePtr parent;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddSibling : cur == NULL\n");
#endif
	return(NULL);
    }

    if (elem == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddSibling : elem == NULL\n");
#endif
	return(NULL);
    }

    /*
     * Constant time is we can rely on the ->parent->last to find
     * the last sibling.
     */
    if ((cur->parent != NULL) && 
	(cur->parent->children != NULL) &&
	(cur->parent->last != NULL) &&
	(cur->parent->last->next == NULL)) {
	cur = cur->parent->last;
    } else {
	while (cur->next != NULL) cur = cur->next;
    }

    xmlUnlinkNode(elem);
    if (elem->doc == NULL)
	elem->doc = cur->doc; /* the parent may not be linked to a doc ! */

    parent = cur->parent;
    elem->prev = cur;
    elem->next = NULL;
    elem->parent = parent;
    cur->next = elem;
    if (parent != NULL)
	parent->last = elem;

    return(elem);
}

/**
 * xmlAddChild:
 * @parent:  the parent node
 * @cur:  the child node
 *
 * Add a new child element, to @parent, at the end of the child list.
 * Returns the child or NULL in case of error.
 */
xmlNodePtr
xmlAddChild(xmlNodePtr parent, xmlNodePtr cur) {
    xmlNodePtr prev;

    if (parent == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddChild : parent == NULL\n");
#endif
	return(NULL);
    }

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAddChild : child == NULL\n");
#endif
	return(NULL);
    }

    if ((cur->doc != NULL) && (parent->doc != NULL) &&
        (cur->doc != parent->doc)) {
#ifdef DEBUG_TREE
	fprintf(stderr, "Elements moved to a different document\n");
#endif
    }

    /*
     * add the new element at the end of the children list.
     */
    cur->parent = parent;
    cur->doc = parent->doc; /* the parent may not be linked to a doc ! */

    /*
     * Handle the case where parent->content != NULL, in that case it will
     * create a intermediate TEXT node.
     */
    if (((parent->type == XML_ELEMENT_NODE) || (parent->type == XML_TEXT_NODE)) &&
	(parent->content != NULL)) {
        xmlNodePtr text;
	
#ifndef XML_USE_BUFFER_CONTENT
	text = xmlNewDocText(parent->doc, parent->content);
#else
	text = xmlNewDocText(parent->doc, xmlBufferContent(parent->content));
#endif
	if (text != NULL) {
	    text->next = parent->children;
	    if (text->next != NULL)
		text->next->prev = text;
	    parent->children = text;
	    UPDATE_LAST_CHILD(parent)
#ifndef XML_USE_BUFFER_CONTENT
	    xmlFree(parent->content);
#else
	    xmlBufferFree(parent->content);
#endif
	    parent->content = NULL;
	}
    }
    if (parent->children == NULL) {
        parent->children = cur;
	parent->last = cur;
    } else {
        prev = parent->last;
	prev->next = cur;
	cur->prev = prev;
	parent->last = cur;
    }

    return(cur);
}

/**
 * xmlGetLastChild:
 * @parent:  the parent node
 *
 * Search the last child of a node.
 * Returns the last child or NULL if none.
 */
xmlNodePtr
xmlGetLastChild(xmlNodePtr parent) {
    if (parent == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlGetLastChild : parent == NULL\n");
#endif
	return(NULL);
    }
    return(parent->last);
}

/**
 * xmlFreeNodeList:
 * @cur:  the first node in the list
 *
 * Free a node and all its siblings, this is a recursive behaviour, all
 * the children are freed too.
 */
void
xmlFreeNodeList(xmlNodePtr cur) {
    xmlNodePtr next;
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreeNodeList : node == NULL\n");
#endif
	return;
    }
    while (cur != NULL) {
        next = cur->next;
        xmlFreeNode(cur);
	cur = next;
    }
}

/**
 * xmlFreeNode:
 * @cur:  the node
 *
 * Free a node, this is a recursive behaviour, all the children are freed too.
 * This doesn't unlink the child from the list, use xmlUnlinkNode() first.
 */
void
xmlFreeNode(xmlNodePtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlFreeNode : node == NULL\n");
#endif
	return;
    }
    if (cur->type == XML_DTD_NODE)
	return;
    cur->doc = NULL;
    cur->parent = NULL;
    cur->next = NULL;
    cur->prev = NULL;
    if ((cur->children != NULL) &&
	(cur->type != XML_ENTITY_REF_NODE))
	xmlFreeNodeList(cur->children);
    if (cur->properties != NULL) xmlFreePropList(cur->properties);
    if (cur->type != XML_ENTITY_REF_NODE)
#ifndef XML_USE_BUFFER_CONTENT
	if (cur->content != NULL) xmlFree(cur->content);
#else
    	if (cur->content != NULL) xmlBufferFree(cur->content);
#endif
    if (cur->name != NULL) xmlFree((char *) cur->name);
    if (cur->nsDef != NULL) xmlFreeNsList(cur->nsDef);
    memset(cur, -1, sizeof(xmlNode));
    xmlFree(cur);
}

/**
 * xmlUnlinkNode:
 * @cur:  the node
 *
 * Unlink a node from it's current context, the node is not freed
 */
void
xmlUnlinkNode(xmlNodePtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlUnlinkNode : node == NULL\n");
#endif
	return;
    }
    if ((cur->parent != NULL) && (cur->parent->children == cur))
        cur->parent->children = cur->next;
    if ((cur->parent != NULL) && (cur->parent->last == cur))
        cur->parent->last = cur->prev;
    if (cur->next != NULL)
        cur->next->prev = cur->prev;
    if (cur->prev != NULL)
        cur->prev->next = cur->next;
    cur->next = cur->prev = NULL;
    cur->parent = NULL;
}

/**
 * xmlReplaceNode:
 * @old:  the old node
 * @cur:  the node
 *
 * Unlink the old node from it's current context, prune the new one
 * at the same place. If cur was already inserted in a document it is
 * first unlinked from its existing context.
 *
 * Returns the old node
 */
xmlNodePtr
xmlReplaceNode(xmlNodePtr old, xmlNodePtr cur) {
    if (old == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlReplaceNode : old == NULL\n");
#endif
	return(NULL);
    }
    if (cur == NULL) {
	xmlUnlinkNode(old);
	return(old);
    }
    xmlUnlinkNode(cur);
    cur->doc = old->doc;
    cur->parent = old->parent;
    cur->next = old->next;
    if (cur->next != NULL)
	cur->next->prev = cur;
    cur->prev = old->prev;
    if (cur->prev != NULL)
	cur->prev->next = cur;
    if (cur->parent != NULL) {
	if (cur->parent->children == old)
	    cur->parent->children = cur;
	if (cur->parent->last == old)
	    cur->parent->last = cur;
    }
    old->next = old->prev = NULL;
    old->parent = NULL;
    return(old);
}

/************************************************************************
 *									*
 *		Copy operations						*
 *									*
 ************************************************************************/
 
/**
 * xmlCopyNamespace:
 * @cur:  the namespace
 *
 * Do a copy of the namespace.
 *
 * Returns: a new xmlNsPtr, or NULL in case of error.
 */
xmlNsPtr
xmlCopyNamespace(xmlNsPtr cur) {
    xmlNsPtr ret;

    if (cur == NULL) return(NULL);
    switch (cur->type) {
        case XML_GLOBAL_NAMESPACE:
	    ret = xmlNewGlobalNs(NULL, cur->href, cur->prefix);
	    break;
	case XML_LOCAL_NAMESPACE:
	    ret = xmlNewNs(NULL, cur->href, cur->prefix);
	    break;
	default:
#ifdef DEBUG_TREE
	    fprintf(stderr, "xmlCopyNamespace: unknown type %d\n", cur->type);
#endif
	    return(NULL);
    }
    return(ret);
}

/**
 * xmlCopyNamespaceList:
 * @cur:  the first namespace
 *
 * Do a copy of an namespace list.
 *
 * Returns: a new xmlNsPtr, or NULL in case of error.
 */
xmlNsPtr
xmlCopyNamespaceList(xmlNsPtr cur) {
    xmlNsPtr ret = NULL;
    xmlNsPtr p = NULL,q;

    while (cur != NULL) {
        q = xmlCopyNamespace(cur);
	if (p == NULL) {
	    ret = p = q;
	} else {
	    p->next = q;
	    p = q;
	}
	cur = cur->next;
    }
    return(ret);
}

/**
 * xmlCopyProp:
 * @target:  the element where the attribute will be grafted
 * @cur:  the attribute
 *
 * Do a copy of the attribute.
 *
 * Returns: a new xmlAttrPtr, or NULL in case of error.
 */
xmlAttrPtr
xmlCopyProp(xmlNodePtr target, xmlAttrPtr cur) {
    xmlAttrPtr ret;

    if (cur == NULL) return(NULL);
    if (cur->parent != NULL)
	ret = xmlNewDocProp(cur->parent->doc, cur->name, NULL);
    else if (cur->children != NULL)
	ret = xmlNewDocProp(cur->children->doc, cur->name, NULL);
    else
	ret = xmlNewDocProp(NULL, cur->name, NULL);
    if (ret == NULL) return(NULL);
    ret->parent = target;
    
    if ((cur->ns != NULL) && (target != NULL)) {
        xmlNsPtr ns;

	ns = xmlSearchNs(target->doc, target, cur->ns->prefix);
	ret->ns = ns;
    } else
        ret->ns = NULL;

    if (cur->children != NULL)
	ret->children = xmlCopyNodeList(cur->children);
    return(ret);
}

/**
 * xmlCopyPropList:
 * @target:  the element where the attributes will be grafted
 * @cur:  the first attribute
 *
 * Do a copy of an attribute list.
 *
 * Returns: a new xmlAttrPtr, or NULL in case of error.
 */
xmlAttrPtr
xmlCopyPropList(xmlNodePtr target, xmlAttrPtr cur) {
    xmlAttrPtr ret = NULL;
    xmlAttrPtr p = NULL,q;

    while (cur != NULL) {
        q = xmlCopyProp(target, cur);
	if (p == NULL) {
	    ret = p = q;
	} else {
	    p->next = q;
	    q->prev = p;
	    p = q;
	}
	cur = cur->next;
    }
    return(ret);
}

/*
 * NOTE abeut the CopyNode operations !
 *
 * They are splitted into external and internal parts for one
 * tricky reason: namespaces. Doing a direct copy of a node
 * say RPM:Copyright without changing the namespace pointer to
 * something else can produce stale links. One way to do it is
 * to keep a reference counter but this doesn't work as soon
 * as one move the element or the subtree out of the scope of
 * the existing namespace. The actual solution seems to add
 * a copy of the namespace at the top of the copied tree if
 * not available in the subtree.
 * Hence two functions, the public front-end call the inner ones
 */

static xmlNodePtr
xmlStaticCopyNodeList(xmlNodePtr node, xmlDocPtr doc, xmlNodePtr parent);

static xmlNodePtr
xmlStaticCopyNode(xmlNodePtr node, xmlDocPtr doc, xmlNodePtr parent,
                  int recursive) {
    xmlNodePtr ret;

    if (node == NULL) return(NULL);
    /*
     * Allocate a new node and fill the fields.
     */
    ret = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (ret == NULL) {
        fprintf(stderr, "xmlStaticCopyNode : malloc failed\n");
	return(NULL);
    }
    memset(ret, 0, sizeof(xmlNode));
    ret->type = node->type;

    ret->doc = doc;
    ret->parent = parent; 
    if (node->name != NULL)
	ret->name = xmlStrdup(node->name);
    if ((node->content != NULL) && (node->type != XML_ENTITY_REF_NODE)) {
#ifndef XML_USE_BUFFER_CONTENT
	ret->content = xmlStrdup(node->content);
#else
	ret->content = xmlBufferCreateSize(xmlBufferLength(node->content));
	xmlBufferSetAllocationScheme(ret->content,
		                     xmlGetBufferAllocationScheme());
	xmlBufferAdd(ret->content,
		     xmlBufferContent(node->content),
		     xmlBufferLength(node->content));
#endif
    }
    if (parent != NULL)
        xmlAddChild(parent, ret);
    
    if (!recursive) return(ret);
    if (node->nsDef != NULL)
        ret->nsDef = xmlCopyNamespaceList(node->nsDef);

    if (node->ns != NULL) {
        xmlNsPtr ns;

	ns = xmlSearchNs(doc, ret, node->ns->prefix);
	if (ns == NULL) {
	    /*
	     * Humm, we are copying an element whose namespace is defined
	     * out of the new tree scope. Search it in the original tree
	     * and add it at the top of the new tree
	     */
	    ns = xmlSearchNs(node->doc, node, node->ns->prefix);
	    if (ns != NULL) {
	        xmlNodePtr root = ret;

		while (root->parent != NULL) root = root->parent;
		xmlNewNs(root, ns->href, ns->prefix);
	    }
	} else {
	    /*
	     * reference the existing namespace definition in our own tree.
	     */
	    ret->ns = ns;
	}
    }
    if (node->properties != NULL)
        ret->properties = xmlCopyPropList(ret, node->properties);
    if (node->children != NULL)
        ret->children = xmlStaticCopyNodeList(node->children, doc, ret);
    UPDATE_LAST_CHILD(ret)
    return(ret);
}

static xmlNodePtr
xmlStaticCopyNodeList(xmlNodePtr node, xmlDocPtr doc, xmlNodePtr parent) {
    xmlNodePtr ret = NULL;
    xmlNodePtr p = NULL,q;

    while (node != NULL) {
        q = xmlStaticCopyNode(node, doc, parent, 1);
	if (parent == NULL) {
	    if (ret == NULL) ret = q;
	} else {
	    if (ret == NULL) {
		q->prev = NULL;
		ret = p = q;
	    } else {
		p->next = q;
		q->prev = p;
		p = q;
	    }
	}
	node = node->next;
    }
    return(ret);
}

/**
 * xmlCopyNode:
 * @node:  the node
 * @recursive:  if 1 do a recursive copy.
 *
 * Do a copy of the node.
 *
 * Returns: a new xmlNodePtr, or NULL in case of error.
 */
xmlNodePtr
xmlCopyNode(xmlNodePtr node, int recursive) {
    xmlNodePtr ret;

    ret = xmlStaticCopyNode(node, NULL, NULL, recursive);
    return(ret);
}

/**
 * xmlCopyNodeList:
 * @node:  the first node in the list.
 *
 * Do a recursive copy of the node list.
 *
 * Returns: a new xmlNodePtr, or NULL in case of error.
 */
xmlNodePtr xmlCopyNodeList(xmlNodePtr node) {
    xmlNodePtr ret = xmlStaticCopyNodeList(node, NULL, NULL);
    return(ret);
}

/**
 * xmlCopyElement:
 * @elem:  the element
 *
 * Do a copy of the element definition.
 *
 * Returns: a new xmlElementPtr, or NULL in case of error.
xmlElementPtr
xmlCopyElement(xmlElementPtr elem) {
    xmlElementPtr ret;

    if (elem == NULL) return(NULL);
    ret = xmlNewDocElement(elem->doc, elem->ns, elem->name, elem->content);
    if (ret == NULL) return(NULL);
    if (!recursive) return(ret);
    if (elem->properties != NULL)
        ret->properties = xmlCopyPropList(elem->properties);
    
    if (elem->nsDef != NULL)
        ret->nsDef = xmlCopyNamespaceList(elem->nsDef);
    if (elem->children != NULL)
        ret->children = xmlCopyElementList(elem->children);
    return(ret);
}
 */

/**
 * xmlCopyDtd:
 * @dtd:  the dtd
 *
 * Do a copy of the dtd.
 *
 * Returns: a new xmlDtdPtr, or NULL in case of error.
 */
xmlDtdPtr
xmlCopyDtd(xmlDtdPtr dtd) {
    xmlDtdPtr ret;

    if (dtd == NULL) return(NULL);
    ret = xmlNewDtd(NULL, dtd->name, dtd->ExternalID, dtd->SystemID);
    if (ret == NULL) return(NULL);
    if (dtd->entities != NULL)
        ret->entities = (void *) xmlCopyEntitiesTable(
	                    (xmlEntitiesTablePtr) dtd->entities);
    if (dtd->notations != NULL)
        ret->notations = (void *) xmlCopyNotationTable(
	                    (xmlNotationTablePtr) dtd->notations);
    if (dtd->elements != NULL)
        ret->elements = (void *) xmlCopyElementTable(
	                    (xmlElementTablePtr) dtd->elements);
    if (dtd->attributes != NULL)
        ret->attributes = (void *) xmlCopyAttributeTable(
	                    (xmlAttributeTablePtr) dtd->attributes);
    return(ret);
}

/**
 * xmlCopyDoc:
 * @doc:  the document
 * @recursive:  if 1 do a recursive copy.
 *
 * Do a copy of the document info. If recursive, the content tree will
 * be copied too as well as Dtd, namespaces and entities.
 *
 * Returns: a new xmlDocPtr, or NULL in case of error.
 */
xmlDocPtr
xmlCopyDoc(xmlDocPtr doc, int recursive) {
    xmlDocPtr ret;

    if (doc == NULL) return(NULL);
    ret = xmlNewDoc(doc->version);
    if (ret == NULL) return(NULL);
    if (doc->name != NULL)
        ret->name = xmlMemStrdup(doc->name);
    if (doc->encoding != NULL)
        ret->encoding = xmlStrdup(doc->encoding);
    ret->compression = doc->compression;
    ret->standalone = doc->standalone;
    if (!recursive) return(ret);

    if (doc->intSubset != NULL)
        ret->intSubset = xmlCopyDtd(doc->intSubset);
    if (doc->oldNs != NULL)
        ret->oldNs = xmlCopyNamespaceList(doc->oldNs);
    if (doc->children != NULL)
        ret->children = xmlStaticCopyNodeList(doc->children, ret, NULL);
    return(ret);
}

/************************************************************************
 *									*
 *		Content access functions				*
 *									*
 ************************************************************************/
 
/**
 * xmlDocGetRootElement:
 * @doc:  the document
 *
 * Get the root element of the document (doc->children is a list
 * containing possibly comments, PIs, etc ...).
 *
 * Returns the xmlNodePtr for the root or NULL
 */
xmlNodePtr
xmlDocGetRootElement(xmlDocPtr doc) {
    xmlNodePtr ret;

    if (doc == NULL) return(NULL);
    ret = doc->children;
    while (ret != NULL) {
	if (ret->type == XML_ELEMENT_NODE)
	    return(ret);
        ret = ret->next;
    }
    return(ret);
}
 
/**
 * xmlDocSetRootElement:
 * @doc:  the document
 * @root:  the new document root element
 *
 * Set the root element of the document (doc->children is a list
 * containing possibly comments, PIs, etc ...).
 *
 * Returns the old root element if any was found
 */
xmlNodePtr
xmlDocSetRootElement(xmlDocPtr doc, xmlNodePtr root) {
    xmlNodePtr old = NULL;

    if (doc == NULL) return(NULL);
    old = doc->children;
    while (old != NULL) {
	if (old->type == XML_ELEMENT_NODE)
	    break;
        old = old->next;
    }
    if (old == NULL) {
	if (doc->children == NULL) {
	    doc->children = root;
	} else {
	    xmlAddSibling(doc->children, root);
	}
    } else {
	xmlReplaceNode(old, root);
    }
    return(old);
}
 
/**
 * xmlNodeSetLang:
 * @cur:  the node being changed
 * @lang:  the langage description
 *
 * Set the language of a node, i.e. the values of the xml:lang
 * attribute.
 */
void
xmlNodeSetLang(xmlNodePtr cur, const xmlChar *lang) {
    if (cur == NULL) return;
    switch(cur->type) {
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_COMMENT_NODE:
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
        case XML_DOCUMENT_FRAG_NODE:
        case XML_NOTATION_NODE:
        case XML_HTML_DOCUMENT_NODE:
        case XML_DTD_NODE:
        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
	    return;
        case XML_ELEMENT_NODE:
        case XML_ATTRIBUTE_NODE:
        case XML_PI_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
	    break;
    }
    xmlSetProp(cur, BAD_CAST "xml:lang", lang);
}
 
/**
 * xmlNodeGetLang:
 * @cur:  the node being checked
 *
 * Searches the language of a node, i.e. the values of the xml:lang
 * attribute or the one carried by the nearest ancestor.
 *
 * Returns a pointer to the lang value, or NULL if not found
 *     It's up to the caller to free the memory.
 */
xmlChar *
xmlNodeGetLang(xmlNodePtr cur) {
    xmlChar *lang;

    while (cur != NULL) {
        lang = xmlGetProp(cur, BAD_CAST "xml:lang");
	if (lang != NULL)
	    return(lang);
	cur = cur->parent;
    }
    return(NULL);
}
 
/**
 * xmlNodeGetSpacePreserve:
 * @cur:  the node being checked
 *
 * Searches the language of a node, i.e. the values of the xml:space
 * attribute or the one carried by the nearest ancestor.
 *
 * Returns -1 if xml:space is not inheried, 0 if "default", 1 if "preserve"
 */
int
xmlNodeGetSpacePreserve(xmlNodePtr cur) {
    xmlChar *space;

    while (cur != NULL) {
        space = xmlGetProp(cur, BAD_CAST "xml:space");
	if (space != NULL) {
	    if (!xmlStrcmp(space, BAD_CAST "preserve")) {
		xmlFree(space);
		return(1);
	    }
	    if (!xmlStrcmp(space, BAD_CAST "default")) {
		xmlFree(space);
		return(0);
	    }
	    xmlFree(space);
	}
	cur = cur->parent;
    }
    return(-1);
}
 
/**
 * xmlNodeSetName:
 * @cur:  the node being changed
 * @name:  the new tag name
 *
 * Searches the language of a node, i.e. the values of the xml:lang
 * attribute or the one carried by the nearest ancestor.
 */
void
xmlNodeSetName(xmlNodePtr cur, const xmlChar *name) {
    if (cur == NULL) return;
    if (name == NULL) return;
    switch(cur->type) {
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_COMMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
        case XML_DOCUMENT_FRAG_NODE:
        case XML_NOTATION_NODE:
        case XML_HTML_DOCUMENT_NODE:
	    return;
        case XML_ELEMENT_NODE:
        case XML_ATTRIBUTE_NODE:
        case XML_PI_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_DTD_NODE:
        case XML_DOCUMENT_NODE:
        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
	    break;
    }
    if (cur->name != NULL) xmlFree((xmlChar *) cur->name);
    cur->name = xmlStrdup(name);
}
 
/**
 * xmlNodeGetBase:
 * @doc:  the document the node pertains to
 * @cur:  the node being checked
 *
 * Searches for the BASE URL. The code should work on both XML
 * and HTML document even if base mechanisms are completely different.
 *
 * Returns a pointer to the base URL, or NULL if not found
 *     It's up to the caller to free the memory.
 */
xmlChar *
xmlNodeGetBase(xmlDocPtr doc, xmlNodePtr cur) {
    xmlChar *base;

    if ((cur == NULL) && (doc == NULL)) 
        return(NULL);
    if (doc == NULL) doc = cur->doc;	
    if ((doc != NULL) && (doc->type == XML_HTML_DOCUMENT_NODE)) {
        cur = doc->children;
	while ((cur != NULL) && (cur->name != NULL)) {
	    if (cur->type != XML_ELEMENT_NODE) {
	        cur = cur->next;
		continue;
	    }
	    if ((!xmlStrcmp(cur->name, BAD_CAST "html")) ||
	        (!xmlStrcmp(cur->name, BAD_CAST "HTML"))) {
	        cur = cur->children;
		continue;
	    }
	    if ((!xmlStrcmp(cur->name, BAD_CAST "head")) ||
	        (!xmlStrcmp(cur->name, BAD_CAST "HEAD"))) {
	        cur = cur->children;
		continue;
	    }
	    if ((!xmlStrcmp(cur->name, BAD_CAST "base")) ||
	        (!xmlStrcmp(cur->name, BAD_CAST "BASE"))) {
                base = xmlGetProp(cur, BAD_CAST "href");
		if (base != NULL) return(base);
                return(xmlGetProp(cur, BAD_CAST "HREF"));
	    }
	    cur = cur->next;
	}
	if ((doc != NULL) && (doc->URL != NULL))
	    return(xmlStrdup(doc->URL));
	return(NULL);
    }
    while (cur != NULL) {
        base = xmlGetProp(cur, BAD_CAST "xml:base");
	if (base != NULL)
	    return(base);
	cur = cur->parent;
    }
    if ((doc != NULL) && (doc->URL != NULL))
	return(xmlStrdup(doc->URL));
    return(NULL);
}
 
/**
 * xmlNodeGetContent:
 * @cur:  the node being read
 *
 * Read the value of a node, this can be either the text carried
 * directly by this node if it's a TEXT node or the aggregate string
 * of the values carried by this node child's (TEXT and ENTITY_REF).
 * Entity references are substitued.
 * Returns a new xmlChar * or NULL if no content is available.
 *     It's up to the caller to free the memory.
 */
xmlChar *
xmlNodeGetContent(xmlNodePtr cur) {
    if (cur == NULL) return(NULL);
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE:
            return(xmlNodeListGetString(cur->doc, cur->children, 1));
	    break;
        case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    if (attr->parent != NULL)
		return(xmlNodeListGetString(attr->parent->doc, attr->children, 1));
	    else
		return(xmlNodeListGetString(NULL, attr->children, 1));
	    break;
	}
        case XML_COMMENT_NODE:
        case XML_PI_NODE:
	    if (cur->content != NULL)
#ifndef XML_USE_BUFFER_CONTENT
	        return(xmlStrdup(cur->content));
#else
	        return(xmlStrdup(xmlBufferContent(cur->content)));
#endif
	    return(NULL);
        case XML_ENTITY_REF_NODE:
	    /*
	     * Locate the entity, and get it's content
	     * @@@
	     */
            return(NULL);
        case XML_ENTITY_NODE:
        case XML_DOCUMENT_NODE:
        case XML_HTML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
        case XML_NOTATION_NODE:
        case XML_DTD_NODE:
	    return(NULL);
        case XML_ELEMENT_DECL:
	    /* TODO !!! */
	    return(NULL);
        case XML_ATTRIBUTE_DECL:
	    /* TODO !!! */
	    return(NULL);
        case XML_ENTITY_DECL:
	    /* TODO !!! */
	    return(NULL);
        case XML_CDATA_SECTION_NODE:
        case XML_TEXT_NODE:
	    if (cur->content != NULL)
#ifndef XML_USE_BUFFER_CONTENT
		return(xmlStrdup(cur->content));
#else
	        return(xmlStrdup(xmlBufferContent(cur->content)));
#endif
            return(NULL);
    }
    return(NULL);
}
 
/**
 * xmlNodeSetContent:
 * @cur:  the node being modified
 * @content:  the new value of the content
 *
 * Replace the content of a node.
 */
void
xmlNodeSetContent(xmlNodePtr cur, const xmlChar *content) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNodeSetContent : node == NULL\n");
#endif
	return;
    }
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE:
	    if (cur->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	        xmlFree(cur->content);
#else
		xmlBufferFree(cur->content);
#endif
		cur->content = NULL;
	    }
	    if (cur->children != NULL) xmlFreeNodeList(cur->children);
	    cur->children = xmlStringGetNodeList(cur->doc, content);
	    UPDATE_LAST_CHILD(cur)
	    break;
        case XML_ATTRIBUTE_NODE:
	    break;
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
	    if (cur->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
		xmlFree(cur->content);
#else
	        xmlBufferFree(cur->content);
#endif
	    }	
	    if (cur->children != NULL) xmlFreeNodeList(cur->children);
	    cur->last = cur->children = NULL;
	    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
		cur->content = xmlStrdup(content);
#else
		cur->content = xmlBufferCreateSize(0);
		xmlBufferSetAllocationScheme(cur->content,
			                     xmlGetBufferAllocationScheme());
		xmlBufferAdd(cur->content, content, -1);
#endif
	    } else 
		cur->content = NULL;
	    break;
        case XML_DOCUMENT_NODE:
        case XML_HTML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
	    break;
        case XML_NOTATION_NODE:
	    break;
        case XML_DTD_NODE:
	    break;
        case XML_ELEMENT_DECL:
	    /* TODO !!! */
	    break;
        case XML_ATTRIBUTE_DECL:
	    /* TODO !!! */
	    break;
        case XML_ENTITY_DECL:
	    /* TODO !!! */
	    break;
    }
}

/**
 * xmlNodeSetContentLen:
 * @cur:  the node being modified
 * @content:  the new value of the content
 * @len:  the size of @content
 *
 * Replace the content of a node.
 */
void
xmlNodeSetContentLen(xmlNodePtr cur, const xmlChar *content, int len) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNodeSetContentLen : node == NULL\n");
#endif
	return;
    }
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE:
	    if (cur->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	        xmlFree(cur->content);
#else
		xmlBufferFree(cur->content);
#endif
		cur->content = NULL;
	    }
	    if (cur->children != NULL) xmlFreeNodeList(cur->children);
	    cur->children = xmlStringLenGetNodeList(cur->doc, content, len);
	    UPDATE_LAST_CHILD(cur)
	    break;
        case XML_ATTRIBUTE_NODE:
	    break;
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
        case XML_NOTATION_NODE:
	    if (cur->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
		xmlFree(cur->content);
#else
	        xmlBufferFree(cur->content);
#endif
	    }	
	    if (cur->children != NULL) xmlFreeNodeList(cur->children);
	    cur->children = cur->last = NULL;
	    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
		cur->content = xmlStrndup(content, len);
#else
		cur->content = xmlBufferCreateSize(len);
		xmlBufferSetAllocationScheme(cur->content,
			                     xmlGetBufferAllocationScheme());
		xmlBufferAdd(cur->content, content, len);
#endif
	    } else 
		cur->content = NULL;
	    break;
        case XML_DOCUMENT_NODE:
        case XML_DTD_NODE:
        case XML_HTML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
	    break;
        case XML_ELEMENT_DECL:
	    /* TODO !!! */
	    break;
        case XML_ATTRIBUTE_DECL:
	    /* TODO !!! */
	    break;
        case XML_ENTITY_DECL:
	    /* TODO !!! */
	    break;
    }
}

/**
 * xmlNodeAddContentLen:
 * @cur:  the node being modified
 * @content:  extra content
 * @len:  the size of @content
 * 
 * Append the extra substring to the node content.
 */
void
xmlNodeAddContentLen(xmlNodePtr cur, const xmlChar *content, int len) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNodeAddContentLen : node == NULL\n");
#endif
	return;
    }
    if (len <= 0) return;
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE: {
	    xmlNodePtr last = NULL, new;

	    if (cur->children != NULL) {
		last = cur->last;
	    } else {
	        if (cur->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
		    cur->children = xmlStringGetNodeList(cur->doc, cur->content);
#else
		    cur->children = xmlStringGetNodeList(cur->doc,
			                       xmlBufferContent(cur->content));
#endif
		    UPDATE_LAST_CHILD(cur)
#ifndef XML_USE_BUFFER_CONTENT
		    xmlFree(cur->content);
#else
		    xmlBufferFree(cur->content);
#endif
		    cur->content = NULL;
		    last = cur->last;
		}
	    }
	    new = xmlNewTextLen(content, len);
	    if (new != NULL) {
		xmlAddChild(cur, new);
	        if ((last != NULL) && (last->next == new)) {
		    xmlTextMerge(last, new);
		}
	    }
	    break;
	}
        case XML_ATTRIBUTE_NODE:
	    break;
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
        case XML_NOTATION_NODE:
	    if (content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
		cur->content = xmlStrncat(cur->content, content, len);
#else
		xmlBufferAdd(cur->content, content, len);
#endif
            }
        case XML_DOCUMENT_NODE:
        case XML_DTD_NODE:
        case XML_HTML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
	    break;
        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
	    break;
    }
}

/**
 * xmlNodeAddContent:
 * @cur:  the node being modified
 * @content:  extra content
 * 
 * Append the extra substring to the node content.
 */
void
xmlNodeAddContent(xmlNodePtr cur, const xmlChar *content) {
    int len;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNodeAddContent : node == NULL\n");
#endif
	return;
    }
    if (content == NULL) return;
    len = xmlStrlen(content);
    xmlNodeAddContentLen(cur, content, len);
}

/**
 * xmlTextMerge:
 * @first:  the first text node
 * @second:  the second text node being merged
 * 
 * Merge two text nodes into one
 * Returns the first text node augmented
 */
xmlNodePtr
xmlTextMerge(xmlNodePtr first, xmlNodePtr second) {
    if (first == NULL) return(second);
    if (second == NULL) return(first);
    if (first->type != XML_TEXT_NODE) return(first);
    if (second->type != XML_TEXT_NODE) return(first);
#ifndef XML_USE_BUFFER_CONTENT
    xmlNodeAddContent(first, second->content);
#else
    xmlNodeAddContent(first, xmlBufferContent(second->content));
#endif
    xmlUnlinkNode(second);
    xmlFreeNode(second);
    return(first);
}

/**
 * xmlGetNsList:
 * @doc:  the document
 * @node:  the current node
 *
 * Search all the namespace applying to a given element.
 * Returns an NULL terminated array of all the xmlNsPtr found
 *         that need to be freed by the caller or NULL if no
 *         namespace if defined
 */
xmlNsPtr *
xmlGetNsList(xmlDocPtr doc, xmlNodePtr node) {
    xmlNsPtr cur;
    xmlNsPtr *ret = NULL;
    int nbns = 0;
    int maxns = 10;
    int i;

    while (node != NULL) {
	cur = node->nsDef;
	while (cur != NULL) {
	    if (ret == NULL) {
	        ret = (xmlNsPtr *) xmlMalloc((maxns + 1) * sizeof(xmlNsPtr));
		if (ret == NULL) {
		    fprintf(stderr, "xmlGetNsList : out of memory!\n");
		    return(NULL);
		}
		ret[nbns] = NULL;
	    }
	    for (i = 0;i < nbns;i++) {
	        if ((cur->prefix == ret[i]->prefix) ||
		    (!xmlStrcmp(cur->prefix, ret[i]->prefix))) break;
	    }
	    if (i >= nbns) {
	        if (nbns >= maxns) {
		    maxns *= 2;
		    ret = (xmlNsPtr *) xmlRealloc(ret,
		                         (maxns + 1) * sizeof(xmlNsPtr));
		    if (ret == NULL) {
			fprintf(stderr, "xmlGetNsList : realloc failed!\n");
			return(NULL);
		    }
		}
		ret[nbns++] = cur;
		ret[nbns] = NULL;
	    }

	    cur = cur->next;
	}
	node = node->parent;
    }
    return(ret);
}

/**
 * xmlSearchNs:
 * @doc:  the document
 * @node:  the current node
 * @nameSpace:  the namespace string
 *
 * Search a Ns registered under a given name space for a document.
 * recurse on the parents until it finds the defined namespace
 * or return NULL otherwise.
 * @nameSpace can be NULL, this is a search for the default namespace.
 * Returns the namespace pointer or NULL.
 */
xmlNsPtr
xmlSearchNs(xmlDocPtr doc, xmlNodePtr node, const xmlChar *nameSpace) {
    xmlNsPtr cur;

    if (node == NULL) return(NULL);
    while (node != NULL) {
	if (node->type == XML_ELEMENT_NODE) {
	    cur = node->nsDef;
	    while (cur != NULL) {
		if ((cur->prefix == NULL) && (nameSpace == NULL))
		    return(cur);
		if ((cur->prefix != NULL) && (nameSpace != NULL) &&
		    (!xmlStrcmp(cur->prefix, nameSpace)))
		    return(cur);
		cur = cur->next;
	    }
	}
	node = node->parent;
    }
    return(NULL);
}

/**
 * xmlSearchNsByHref:
 * @doc:  the document
 * @node:  the current node
 * @href:  the namespace value
 *
 * Search a Ns aliasing a given URI. Recurse on the parents until it finds
 * the defined namespace or return NULL otherwise.
 * Returns the namespace pointer or NULL.
 */
xmlNsPtr
xmlSearchNsByHref(xmlDocPtr doc, xmlNodePtr node, const xmlChar *href) {
    xmlNsPtr cur;
    xmlNodePtr orig = node;

    if ((node == NULL) || (href == NULL)) return(NULL);
    while (node != NULL) {
	cur = node->nsDef;
	while (cur != NULL) {
	    if ((cur->href != NULL) && (href != NULL) &&
	        (!xmlStrcmp(cur->href, href))) {
		/*
		 * Check that the prefix is not shadowed between orig and node
		 */
		xmlNodePtr check = orig;
		xmlNsPtr tst;

		while (check != node) {
		    tst = check->nsDef;
		    while (tst != NULL) {
			if ((tst->prefix == NULL) && (cur->prefix == NULL))
	                    goto shadowed;
			if ((tst->prefix != NULL) && (cur->prefix != NULL) &&
			    (!xmlStrcmp(tst->prefix, cur->prefix)))
	                    goto shadowed;
		        tst = tst->next;
		    }
		}
		return(cur);
	    }
shadowed:		    
	    cur = cur->next;
	}
	node = node->parent;
    }
    return(NULL);
}

/**
 * xmlNewReconciliedNs
 * @doc:  the document
 * @tree:  a node expected to hold the new namespace
 * @ns:  the original namespace
 *
 * This function tries to locate a namespace definition in a tree
 * ancestors, or create a new namespace definition node similar to
 * @ns trying to reuse the same prefix. However if the given prefix is
 * null (default namespace) or reused within the subtree defined by
 * @tree or on one of its ancestors then a new prefix is generated.
 * Returns the (new) namespace definition or NULL in case of error
 */
xmlNsPtr
xmlNewReconciliedNs(xmlDocPtr doc, xmlNodePtr tree, xmlNsPtr ns) {
    xmlNsPtr def;
    xmlChar prefix[50];
    int counter = 1;

    if (tree == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewReconciliedNs : tree == NULL\n");
#endif
	return(NULL);
    }
    if (ns == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNewReconciliedNs : ns == NULL\n");
#endif
	return(NULL);
    }
    /*
     * Search an existing namespace definition inherited.
     */
    def = xmlSearchNsByHref(doc, tree, ns->href);
    if (def != NULL)
        return(def);

    /*
     * Find a close prefix which is not already in use.
     * Let's strip namespace prefixes longer than 20 chars !
     */
    sprintf((char *) prefix, "%.20s", ns->prefix);
    def = xmlSearchNs(doc, tree, prefix);
    while (def != NULL) {
        if (counter > 1000) return(NULL);
        sprintf((char *) prefix, "%.20s%d", ns->prefix, counter++);
	def = xmlSearchNs(doc, tree, prefix);
    }

    /*
     * Ok, now we are ready to create a new one.
     */
    def = xmlNewNs(tree, ns->href, prefix);
    return(def);
}

/**
 * xmlReconciliateNs
 * @doc:  the document
 * @tree:  a node defining the subtree to reconciliate
 *
 * This function checks that all the namespaces declared within the given
 * tree are properly declared. This is needed for example after Copy or Cut
 * and then paste operations. The subtree may still hold pointers to
 * namespace declarations outside the subtree or invalid/masked. As much
 * as possible the function try tu reuse the existing namespaces found in
 * the new environment. If not possible the new namespaces are redeclared
 * on @tree at the top of the given subtree.
 * Returns the number of namespace declarations created or -1 in case of error.
 */
int
xmlReconciliateNs(xmlDocPtr doc, xmlNodePtr tree) {
    xmlNsPtr *oldNs = NULL;
    xmlNsPtr *newNs = NULL;
    int sizeCache = 0;
    int nbCache = 0;

    xmlNsPtr n;
    xmlNodePtr node = tree;
    xmlAttrPtr attr;
    int ret = 0, i;

    while (node != NULL) {
        /*
	 * Reconciliate the node namespace
	 */
	if (node->ns != NULL) {
	    /*
	     * initialize the cache if needed
	     */
	    if (sizeCache == 0) {
		sizeCache = 10;
		oldNs = (xmlNsPtr *) xmlMalloc(sizeCache *
					       sizeof(xmlNsPtr));
		if (oldNs == NULL) {
		    fprintf(stderr, "xmlReconciliateNs : memory pbm\n");
		    return(-1);
		}
		newNs = (xmlNsPtr *) xmlMalloc(sizeCache *
					       sizeof(xmlNsPtr));
		if (newNs == NULL) {
		    fprintf(stderr, "xmlReconciliateNs : memory pbm\n");
		    xmlFree(oldNs);
		    return(-1);
		}
	    }
	    for (i = 0;i < nbCache;i++) {
	        if (oldNs[i] == node->ns) {
		    node->ns = newNs[i];
		    break;
		}
	    }
	    if (i == nbCache) {
	        /*
		 * Ok we need to recreate a new namespace definition
		 */
		n = xmlNewReconciliedNs(doc, tree, node->ns);
		if (n != NULL) { /* :-( what if else ??? */
		    /*
		     * check if we need to grow the cache buffers.
		     */
		    if (sizeCache <= nbCache) {
		        sizeCache *= 2;
			oldNs = (xmlNsPtr *) xmlRealloc(oldNs, sizeCache *
			                               sizeof(xmlNsPtr));
		        if (oldNs == NULL) {
			    fprintf(stderr, "xmlReconciliateNs : memory pbm\n");
			    xmlFree(newNs);
			    return(-1);
			}
			newNs = (xmlNsPtr *) xmlRealloc(newNs, sizeCache *
			                               sizeof(xmlNsPtr));
		        if (newNs == NULL) {
			    fprintf(stderr, "xmlReconciliateNs : memory pbm\n");
			    xmlFree(oldNs);
			    return(-1);
			}
		    }
		    newNs[nbCache] = n;
		    oldNs[nbCache++] = node->ns;
		    node->ns = n;
                }
	    }
	}
	/*
	 * now check for namespace hold by attributes on the node.
	 */
	attr = node->properties;
	while (attr != NULL) {
	    if (attr->ns != NULL) {
		/*
		 * initialize the cache if needed
		 */
		if (sizeCache == 0) {
		    sizeCache = 10;
		    oldNs = (xmlNsPtr *) xmlMalloc(sizeCache *
						   sizeof(xmlNsPtr));
		    if (oldNs == NULL) {
			fprintf(stderr, "xmlReconciliateNs : memory pbm\n");
			return(-1);
		    }
		    newNs = (xmlNsPtr *) xmlMalloc(sizeCache *
						   sizeof(xmlNsPtr));
		    if (newNs == NULL) {
			fprintf(stderr, "xmlReconciliateNs : memory pbm\n");
			xmlFree(oldNs);
			return(-1);
		    }
		}
		for (i = 0;i < nbCache;i++) {
		    if (oldNs[i] == attr->ns) {
			node->ns = newNs[i];
			break;
		    }
		}
		if (i == nbCache) {
		    /*
		     * Ok we need to recreate a new namespace definition
		     */
		    n = xmlNewReconciliedNs(doc, tree, attr->ns);
		    if (n != NULL) { /* :-( what if else ??? */
			/*
			 * check if we need to grow the cache buffers.
			 */
			if (sizeCache <= nbCache) {
			    sizeCache *= 2;
			    oldNs = (xmlNsPtr *) xmlRealloc(oldNs, sizeCache *
							   sizeof(xmlNsPtr));
			    if (oldNs == NULL) {
				fprintf(stderr,
				        "xmlReconciliateNs : memory pbm\n");
				xmlFree(newNs);
				return(-1);
			    }
			    newNs = (xmlNsPtr *) xmlRealloc(newNs, sizeCache *
							   sizeof(xmlNsPtr));
			    if (newNs == NULL) {
				fprintf(stderr,
				        "xmlReconciliateNs : memory pbm\n");
				xmlFree(oldNs);
				return(-1);
			    }
			}
			newNs[nbCache] = n;
			oldNs[nbCache++] = attr->ns;
			attr->ns = n;
		    }
		}
	    }
	    attr = attr->next;
	}

	/*
	 * Browse the full subtree, deep first
	 */
        if (node->children != NULL) {
	    /* deep first */
	    node = node->children;
	} else if ((node != tree) && (node->next != NULL)) {
	    /* then siblings */
	    node = node->next;
	} else if (node != tree) {
	    /* go up to parents->next if needed */
	    while (node != tree) {
	        if (node->parent != NULL)
		    node = node->parent;
		if ((node != tree) && (node->next != NULL)) {
		    node = node->next;
		    break;
		}
		if (node->parent == NULL) {
		    node = NULL;
		    break;
		}
	    }
	    /* exit condition */
	    if (node == tree) 
	        node = NULL;
	}
    }
    return(ret);
}

/**
 * xmlGetProp:
 * @node:  the node
 * @name:  the attribute name
 *
 * Search and get the value of an attribute associated to a node
 * This does the entity substitution.
 * This function looks in DTD attribute declaration for #FIXED or
 * default declaration values unless DTD use has been turned off.
 *
 * Returns the attribute value or NULL if not found.
 *     It's up to the caller to free the memory.
 */
xmlChar *
xmlGetProp(xmlNodePtr node, const xmlChar *name) {
    xmlAttrPtr prop;
    xmlDocPtr doc;

    if ((node == NULL) || (name == NULL)) return(NULL);
    /*
     * Check on the properties attached to the node
     */
    prop = node->properties;
    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name))  {
	    xmlChar *ret;

	    ret = xmlNodeListGetString(node->doc, prop->children, 1);
	    if (ret == NULL) return(xmlStrdup((xmlChar *)""));
	    return(ret);
        }
	prop = prop->next;
    }
    if (!xmlCheckDTD) return(NULL);

    /*
     * Check if there is a default declaration in the internal
     * or external subsets
     */
    doc =  node->doc;
    if (doc != NULL) {
        xmlAttributePtr attrDecl;
        if (doc->intSubset != NULL) {
	    attrDecl = xmlGetDtdAttrDesc(doc->intSubset, node->name, name);
	    if ((attrDecl == NULL) && (doc->extSubset != NULL))
		attrDecl = xmlGetDtdAttrDesc(doc->extSubset, node->name, name);
	    if (attrDecl != NULL)
		return(xmlStrdup(attrDecl->defaultValue));
	}
    }
    return(NULL);
}

/**
 * xmlGetNsProp:
 * @node:  the node
 * @name:  the attribute name
 * @namespace:  the URI of the namespace
 *
 * Search and get the value of an attribute associated to a node
 * This attribute has to be anchored in the namespace specified.
 * This does the entity substitution.
 * This function looks in DTD attribute declaration for #FIXED or
 * default declaration values unless DTD use has been turned off.
 *
 * Returns the attribute value or NULL if not found.
 *     It's up to the caller to free the memory.
 */
xmlChar *
xmlGetNsProp(xmlNodePtr node, const xmlChar *name, const xmlChar *namespace) {
    xmlAttrPtr prop = node->properties;
    xmlDocPtr doc;
    xmlNsPtr ns;

    if (namespace == NULL)
	return(xmlGetProp(node, name));
    while (prop != NULL) {
	/*
	 * One need to have
	 *   - same attribute names
	 *   - and the attribute carrying that namespace
	 *         or
	 *         no namespace on the attribute and the element carrying it
	 */
        if ((!xmlStrcmp(prop->name, name)) &&
	    (((prop->ns == NULL) && (node->ns != NULL) &&
	      (!xmlStrcmp(node->ns->href, namespace))) ||
	     ((prop->ns != NULL) && (!xmlStrcmp(prop->ns->href, namespace))))) {
	    xmlChar *ret;

	    ret = xmlNodeListGetString(node->doc, prop->children, 1);
	    if (ret == NULL) return(xmlStrdup((xmlChar *)""));
	    return(ret);
        }
	prop = prop->next;
    }
    if (!xmlCheckDTD) return(NULL);

    /*
     * Check if there is a default declaration in the internal
     * or external subsets
     */
    doc =  node->doc;
    if (doc != NULL) {
        xmlAttributePtr attrDecl;
        if (doc->intSubset != NULL) {
	    attrDecl = xmlGetDtdAttrDesc(doc->intSubset, node->name, name);
	    if ((attrDecl == NULL) && (doc->extSubset != NULL))
		attrDecl = xmlGetDtdAttrDesc(doc->extSubset, node->name, name);
		
	    if (attrDecl->prefix != NULL) {
	        /*
		 * The DTD declaration only allows a prefix search
		 */
		ns = xmlSearchNs(doc, node, attrDecl->prefix);
		if ((ns != NULL) && (!xmlStrcmp(ns->href, namespace)))
		    return(xmlStrdup(attrDecl->defaultValue));
	    }
	}
    }
    return(NULL);
}

/**
 * xmlSetProp:
 * @node:  the node
 * @name:  the attribute name
 * @value:  the attribute value
 *
 * Set (or reset) an attribute carried by a node.
 * Returns the attribute pointer.
 */
xmlAttrPtr
xmlSetProp(xmlNodePtr node, const xmlChar *name, const xmlChar *value) {
    xmlAttrPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name)) {
	    if (prop->children != NULL) 
	        xmlFreeNodeList(prop->children);
	    prop->children = NULL;
	    if (value != NULL) {
	        xmlChar *buffer;
		xmlNodePtr tmp;

		buffer = xmlEncodeEntitiesReentrant(node->doc, value);
		prop->children = xmlStringGetNodeList(node->doc, buffer);
		tmp = prop->children;
		while (tmp != NULL) {
		    tmp->parent = (xmlNodePtr) prop;
		    if (tmp->next == NULL)
			prop->last = tmp;
		    tmp = tmp->next;
		}
		xmlFree(buffer);
	    }	
	    return(prop);
	}
	prop = prop->next;
    }
    prop = xmlNewProp(node, name, value);
    return(prop);
}

/**
 * xmlNodeIsText:
 * @node:  the node
 * 
 * Is this node a Text node ?
 * Returns 1 yes, 0 no
 */
int
xmlNodeIsText(xmlNodePtr node) {
    if (node == NULL) return(0);

    if (node->type == XML_TEXT_NODE) return(1);
    return(0);
}

/**
 * xmlIsBlankNode:
 * @node:  the node
 * 
 * Is this node a Text node ?
 * Returns 1 yes, 0 no
 */
int
xmlIsBlankNode(xmlNodePtr node) {
    xmlChar *cur;
    if (node == NULL) return(0);

    if (node->type != XML_TEXT_NODE) return(0);
    if (node->content == NULL) return(0);
    cur = node->content;
    while (*cur != 0) {
	if (!IS_BLANK(*cur)) return(0);
	cur++;
    }

    return(1);
}

/**
 * xmlTextConcat:
 * @node:  the node
 * @content:  the content
 * @len:  @content lenght
 * 
 * Concat the given string at the end of the existing node content
 */

void
xmlTextConcat(xmlNodePtr node, const xmlChar *content, int len) {
    if (node == NULL) return;

    if ((node->type != XML_TEXT_NODE) &&
        (node->type != XML_CDATA_SECTION_NODE)) {
#ifdef DEBUG_TREE
	fprintf(stderr, "xmlTextConcat: node is not text nor cdata\n");
#endif
        return;
    }
#ifndef XML_USE_BUFFER_CONTENT
    node->content = xmlStrncat(node->content, content, len);
#else
    xmlBufferAdd(node->content, content, len);
#endif
}

/************************************************************************
 *									*
 *			Output : to a FILE or in memory			*
 *									*
 ************************************************************************/

#define BASE_BUFFER_SIZE 4000

/**
 * xmlBufferCreate:
 *
 * routine to create an XML buffer.
 * returns the new structure.
 */
xmlBufferPtr
xmlBufferCreate(void) {
    xmlBufferPtr ret;

    ret = (xmlBufferPtr) xmlMalloc(sizeof(xmlBuffer));
    if (ret == NULL) {
	fprintf(stderr, "xmlBufferCreate : out of memory!\n");
        return(NULL);
    }
    ret->use = 0;
    ret->size = BASE_BUFFER_SIZE;
    ret->alloc = xmlBufferAllocScheme;
    ret->content = (xmlChar *) xmlMalloc(ret->size * sizeof(xmlChar));
    if (ret->content == NULL) {
	fprintf(stderr, "xmlBufferCreate : out of memory!\n");
	xmlFree(ret);
        return(NULL);
    }
    ret->content[0] = 0;
    return(ret);
}

/**
 * xmlBufferCreateSize:
 * @size: initial size of buffer
 *
 * routine to create an XML buffer.
 * returns the new structure.
 */
xmlBufferPtr
xmlBufferCreateSize(size_t size) {
    xmlBufferPtr ret;

    ret = (xmlBufferPtr) xmlMalloc(sizeof(xmlBuffer));
    if (ret == NULL) {
        fprintf(stderr, "xmlBufferCreate : out of memory!\n");
        return(NULL);
    }
    ret->use = 0;
    ret->alloc = xmlBufferAllocScheme;
    ret->size = (size ? size+2 : 0);         /* +1 for ending null */
    if (ret->size){
        ret->content = (xmlChar *) xmlMalloc(ret->size * sizeof(xmlChar));
        if (ret->content == NULL) {
            fprintf(stderr, "xmlBufferCreate : out of memory!\n");
            xmlFree(ret);
            return(NULL);
        }
        ret->content[0] = 0;
    } else
	ret->content = NULL;
    return(ret);
}

/**
 * xmlBufferAllocationScheme:
 * @buf:  the buffer to free
 * @scheme:  allocation scheme to use
 *
 * Sets the allocation scheme for this buffer
 */
void
xmlBufferSetAllocationScheme(xmlBufferPtr buf, 
                             xmlBufferAllocationScheme scheme) {
    if (buf == NULL) {
#ifdef DEBUG_BUFFER
        fprintf(stderr, "xmlBufferSetAllocationScheme: buf == NULL\n");
#endif
        return;
    }

    buf->alloc = scheme;
}

/**
 * xmlBufferFree:
 * @buf:  the buffer to free
 *
 * Frees an XML buffer.
 */
void
xmlBufferFree(xmlBufferPtr buf) {
    if (buf == NULL) {
#ifdef DEBUG_BUFFER
        fprintf(stderr, "xmlBufferFree: buf == NULL\n");
#endif
	return;
    }
    if (buf->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
        memset(buf->content, -1, BASE_BUFFER_SIZE);
#else
        memset(buf->content, -1, buf->size);
#endif
        xmlFree(buf->content);
    }
    memset(buf, -1, sizeof(xmlBuffer));
    xmlFree(buf);
}

/**
 * xmlBufferEmpty:
 * @buf:  the buffer
 *
 * empty a buffer.
 */
void
xmlBufferEmpty(xmlBufferPtr buf) {
    buf->use = 0;
    memset(buf->content, -1, buf->size);/* just for debug */
}

/**
 * xmlBufferShrink:
 * @buf:  the buffer to dump
 * @len:  the number of xmlChar to remove
 *
 * Remove the beginning of an XML buffer.
 *
 * Returns the number of xmlChar removed, or -1 in case of failure.
 */
int
xmlBufferShrink(xmlBufferPtr buf, int len) {
    if (len == 0) return(0);
    if (len > buf->use) return(-1);

    buf->use -= len;
    memmove(buf->content, &buf->content[len], buf->use * sizeof(xmlChar));

    buf->content[buf->use] = 0;
    return(len);
}

/**
 * xmlBufferDump:
 * @file:  the file output
 * @buf:  the buffer to dump
 *
 * Dumps an XML buffer to  a FILE *.
 * Returns the number of xmlChar written
 */
int
xmlBufferDump(FILE *file, xmlBufferPtr buf) {
    int ret;

    if (buf == NULL) {
#ifdef DEBUG_BUFFER
        fprintf(stderr, "xmlBufferDump: buf == NULL\n");
#endif
	return(0);
    }
    if (buf->content == NULL) {
#ifdef DEBUG_BUFFER
        fprintf(stderr, "xmlBufferDump: buf->content == NULL\n");
#endif
	return(0);
    }
    if (file == NULL) file = stdout;
    ret = fwrite(buf->content, sizeof(xmlChar), buf->use, file);
    return(ret);
}

/**
 * xmlBufferContent:
 * @buf:  the buffer to resize
 *
 * Returns the internal content
 */

const xmlChar* 
xmlBufferContent(const xmlBufferPtr buf)
{
    if(!buf)
        return NULL;

    return buf->content;
}

/**
 * xmlBufferLength:
 * @buf:  the buffer 
 *
 * Returns the length of data in the internal content
 */

int
xmlBufferLength(const xmlBufferPtr buf)
{
    if(!buf)
        return 0;

    return buf->use;
}

/**
 * xmlBufferResize:
 * @buf:  the buffer to resize
 * @len:  the desired size
 *
 * Resize a buffer to accomodate minimum size of <len>.
 *
 * Returns  0 in case of problems, 1 otherwise
 */
int
xmlBufferResize(xmlBufferPtr buf, int size)
{
    int newSize = (buf->size ? buf->size*2 : size);/*take care of empty case*/
    xmlChar* rebuf = NULL;

    /* Don't resize if we don't have to */
    if(size < buf->size)
        return 1;

    /* figure out new size */
    switch(buf->alloc){
    case XML_BUFFER_ALLOC_DOUBLEIT:
        while(size > newSize) newSize *= 2;
        break;
    case XML_BUFFER_ALLOC_EXACT:
        newSize = size+10;
        break;
    default:
        newSize = size+10;
        break;
    }

    if (buf->content == NULL)
	rebuf = (xmlChar *) xmlMalloc(newSize * sizeof(xmlChar));
    else
	rebuf = (xmlChar *) xmlRealloc(buf->content, 
				       newSize * sizeof(xmlChar));
    if (rebuf == NULL) {
        fprintf(stderr, "xmlBufferAdd : out of memory!\n");
        return 0;
    }
    buf->content = rebuf;
    buf->size = newSize;

    return 1;
}
/**
 * xmlBufferAdd:
 * @buf:  the buffer to dump
 * @str:  the xmlChar string
 * @len:  the number of xmlChar to add
 *
 * Add a string range to an XML buffer. if len == -1, the lenght of
 * str is recomputed.
 */
void
xmlBufferAdd(xmlBufferPtr buf, const xmlChar *str, int len) {
    int needSize;

    if (str == NULL) {
#ifdef DEBUG_BUFFER
        fprintf(stderr, "xmlBufferAdd: str == NULL\n");
#endif
	return;
    }
    if (len < -1) {
#ifdef DEBUG_BUFFER
        fprintf(stderr, "xmlBufferAdd: len < 0\n");
#endif
	return;
    }
    if (len == 0) return;

    if (len < 0)
        len = xmlStrlen(str);

    if (len <= 0) return;

    needSize = buf->use + len + 2;
    if(needSize > buf->size){
        if(!xmlBufferResize(buf, needSize)){
            fprintf(stderr, "xmlBufferAdd : out of memory!\n");
            return;
        }
    }

    memmove(&buf->content[buf->use], str, len*sizeof(xmlChar));
    buf->use += len;
    buf->content[buf->use] = 0;
}

/**
 * xmlBufferCat:
 * @buf:  the buffer to dump
 * @str:  the xmlChar string
 *
 * Append a zero terminated string to an XML buffer.
 */
void
xmlBufferCat(xmlBufferPtr buf, const xmlChar *str) {
    if (str != NULL)
	xmlBufferAdd(buf, str, -1);
}

/**
 * xmlBufferCCat:
 * @buf:  the buffer to dump
 * @str:  the C char string
 *
 * Append a zero terminated C string to an XML buffer.
 */
void
xmlBufferCCat(xmlBufferPtr buf, const char *str) {
    const char *cur;

    if (str == NULL) {
#ifdef DEBUG_BUFFER
        fprintf(stderr, "xmlBufferAdd: str == NULL\n");
#endif
	return;
    }
    for (cur = str;*cur != 0;cur++) {
        if (buf->use  + 10 >= buf->size) {
            if(!xmlBufferResize(buf, buf->use+10)){
                fprintf(stderr, "xmlBufferCCat : out of memory!\n");
                return;
            }
        }
        buf->content[buf->use++] = *cur;
    }
}

/**
 * xmlBufferWriteCHAR:
 * @buf:  the XML buffer
 * @string:  the string to add
 *
 * routine which manage and grows an output buffer. This one add
 * xmlChars at the end of the buffer.
 */
void
xmlBufferWriteCHAR(xmlBufferPtr buf, const xmlChar *string) {
    xmlBufferCat(buf, string);
}

/**
 * xmlBufferWriteChar:
 * @buf:  the XML buffer output
 * @string:  the string to add
 *
 * routine which manage and grows an output buffer. This one add
 * C chars at the end of the array.
 */
void
xmlBufferWriteChar(xmlBufferPtr buf, const char *string) {
    xmlBufferCCat(buf, string);
}


/**
 * xmlBufferWriteQuotedString:
 * @buf:  the XML buffer output
 * @string:  the string to add
 *
 * routine which manage and grows an output buffer. This one writes
 * a quoted or double quoted xmlChar string, checking first if it holds
 * quote or double-quotes internally
 */
void
xmlBufferWriteQuotedString(xmlBufferPtr buf, const xmlChar *string) {
    if (xmlStrchr(string, '"')) {
        if (xmlStrchr(string, '\'')) {
#ifdef DEBUG_BUFFER
	    fprintf(stderr,
 "xmlBufferWriteQuotedString: string contains quote and double-quotes !\n");
#endif
	}
        xmlBufferCCat(buf, "'");
        xmlBufferCat(buf, string);
        xmlBufferCCat(buf, "'");
    } else {
        xmlBufferCCat(buf, "\"");
        xmlBufferCat(buf, string);
        xmlBufferCCat(buf, "\"");
    }
}


static void
xmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level,
            int format);
static void
xmlNodeListDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level,
                int format);
void
htmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur);

/**
 * xmlGlobalNsDump:
 * @buf:  the XML buffer output
 * @cur:  a namespace
 *
 * Dump a global Namespace, this is the old version based on PIs.
 */
static void
xmlGlobalNsDump(xmlBufferPtr buf, xmlNsPtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlGlobalNsDump : Ns == NULL\n");
#endif
	return;
    }
    if (cur->type == XML_GLOBAL_NAMESPACE) {
	xmlBufferWriteChar(buf, "<?namespace");
	if (cur->href != NULL) {
	    xmlBufferWriteChar(buf, " href=");
	    xmlBufferWriteQuotedString(buf, cur->href);
	}
	if (cur->prefix != NULL) {
	    xmlBufferWriteChar(buf, " AS=");
	    xmlBufferWriteQuotedString(buf, cur->prefix);
	}
	xmlBufferWriteChar(buf, "?>\n");
    }
}

/**
 * xmlGlobalNsListDump:
 * @buf:  the XML buffer output
 * @cur:  the first namespace
 *
 * Dump a list of global Namespace, this is the old version based on PIs.
 */
static void
xmlGlobalNsListDump(xmlBufferPtr buf, xmlNsPtr cur) {
    while (cur != NULL) {
        xmlGlobalNsDump(buf, cur);
	cur = cur->next;
    }
}

/**
 * xmlNsDump:
 * @buf:  the XML buffer output
 * @cur:  a namespace
 *
 * Dump a local Namespace definition.
 * Should be called in the context of attributes dumps.
 */
static void
xmlNsDump(xmlBufferPtr buf, xmlNsPtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNsDump : Ns == NULL\n");
#endif
	return;
    }
    if (cur->type == XML_LOCAL_NAMESPACE) {
        /* Within the context of an element attributes */
	if (cur->prefix != NULL) {
	    xmlBufferWriteChar(buf, " xmlns:");
	    xmlBufferWriteCHAR(buf, cur->prefix);
	} else
	    xmlBufferWriteChar(buf, " xmlns");
	xmlBufferWriteChar(buf, "=");
	xmlBufferWriteQuotedString(buf, cur->href);
    }
}

/**
 * xmlNsListDump:
 * @buf:  the XML buffer output
 * @cur:  the first namespace
 *
 * Dump a list of local Namespace definitions.
 * Should be called in the context of attributes dumps.
 */
static void
xmlNsListDump(xmlBufferPtr buf, xmlNsPtr cur) {
    while (cur != NULL) {
        xmlNsDump(buf, cur);
	cur = cur->next;
    }
}

/**
 * xmlDtdDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * 
 * Dump the XML document DTD, if any.
 */
static void
xmlDtdDump(xmlBufferPtr buf, xmlDtdPtr dtd) {
    if (dtd == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlDtdDump : no internal subset\n");
#endif
	return;
    }
    xmlBufferWriteChar(buf, "<!DOCTYPE ");
    xmlBufferWriteCHAR(buf, dtd->name);
    if (dtd->ExternalID != NULL) {
	xmlBufferWriteChar(buf, " PUBLIC ");
	xmlBufferWriteQuotedString(buf, dtd->ExternalID);
	xmlBufferWriteChar(buf, " ");
	xmlBufferWriteQuotedString(buf, dtd->SystemID);
    }  else if (dtd->SystemID != NULL) {
	xmlBufferWriteChar(buf, " SYSTEM ");
	xmlBufferWriteQuotedString(buf, dtd->SystemID);
    }
    if ((dtd->entities == NULL) && (dtd->elements == NULL) &&
        (dtd->attributes == NULL) && (dtd->notations == NULL)) {
	xmlBufferWriteChar(buf, ">");
	return;
    }
    xmlBufferWriteChar(buf, " [\n");
    xmlNodeListDump(buf, dtd->doc, dtd->children, -1, 0);
#if 0
    if (dtd->entities != NULL)
	xmlDumpEntitiesTable(buf, (xmlEntitiesTablePtr) dtd->entities);
    if (dtd->notations != NULL)
	xmlDumpNotationTable(buf, (xmlNotationTablePtr) dtd->notations);
    if (dtd->elements != NULL)
	xmlDumpElementTable(buf, (xmlElementTablePtr) dtd->elements);
    if (dtd->attributes != NULL)
	xmlDumpAttributeTable(buf, (xmlAttributeTablePtr) dtd->attributes);
#endif
    xmlBufferWriteChar(buf, "]>");
}

/**
 * xmlAttrDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * @cur:  the attribute pointer
 *
 * Dump an XML attribute
 */
static void
xmlAttrDump(xmlBufferPtr buf, xmlDocPtr doc, xmlAttrPtr cur) {
    xmlChar *value;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAttrDump : property == NULL\n");
#endif
	return;
    }
    xmlBufferWriteChar(buf, " ");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(buf, cur->ns->prefix);
	xmlBufferWriteChar(buf, ":");
    }
    xmlBufferWriteCHAR(buf, cur->name);
    value = xmlNodeListGetString(doc, cur->children, 0);
    if (value) {
	xmlBufferWriteChar(buf, "=");
	xmlBufferWriteQuotedString(buf, value);
	xmlFree(value);
    } else  {
	xmlBufferWriteChar(buf, "=\"\"");
    }
}

/**
 * xmlAttrListDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * @cur:  the first attribute pointer
 *
 * Dump a list of XML attributes
 */
static void
xmlAttrListDump(xmlBufferPtr buf, xmlDocPtr doc, xmlAttrPtr cur) {
    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlAttrListDump : property == NULL\n");
#endif
	return;
    }
    while (cur != NULL) {
        xmlAttrDump(buf, doc, cur);
	cur = cur->next;
    }
}



/**
 * xmlNodeListDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * @cur:  the first node
 * @level: the imbrication level for indenting
 * @format: is formatting allowed
 *
 * Dump an XML node list, recursive behaviour,children are printed too.
 */
static void
xmlNodeListDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level,
                int format) {
    int i;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNodeListDump : node == NULL\n");
#endif
	return;
    }
    while (cur != NULL) {
	if ((format) && (xmlIndentTreeOutput) &&
	    (cur->type == XML_ELEMENT_NODE))
	    for (i = 0;i < level;i++)
		xmlBufferWriteChar(buf, "  ");
        xmlNodeDump(buf, doc, cur, level, format);
	if (format) {
	    xmlBufferWriteChar(buf, "\n");
	}
	cur = cur->next;
    }
}

/**
 * xmlNodeDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * @cur:  the current node
 * @level: the imbrication level for indenting
 * @format: is formatting allowed
 *
 * Dump an XML node, recursive behaviour,children are printed too.
 */
static void
xmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level,
            int format) {
    int i;
    xmlNodePtr tmp;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlNodeDump : node == NULL\n");
#endif
	return;
    }
    if (cur->type == XML_DTD_NODE) {
        xmlDtdDump(buf, (xmlDtdPtr) cur);
	return;
    }
    if (cur->type == XML_ELEMENT_DECL) {
        xmlDumpElementDecl(buf, (xmlElementPtr) cur);
	return;
    }
    if (cur->type == XML_ATTRIBUTE_DECL) {
        xmlDumpAttributeDecl(buf, (xmlAttributePtr) cur);
	return;
    }
    if (cur->type == XML_ENTITY_DECL) {
        xmlDumpEntityDecl(buf, (xmlEntityPtr) cur);
	return;
    }
    if (cur->type == XML_TEXT_NODE) {
	if (cur->content != NULL) {
            xmlChar *buffer;

#ifndef XML_USE_BUFFER_CONTENT
            buffer = xmlEncodeEntitiesReentrant(doc, cur->content);
#else
	    buffer = xmlEncodeEntitiesReentrant(doc, 
					    xmlBufferContent(cur->content));
#endif
	    if (buffer != NULL) {
		xmlBufferWriteCHAR(buf, buffer);
		xmlFree(buffer);
	    }
	}
	return;
    }
    if (cur->type == XML_PI_NODE) {
	if (cur->content != NULL) {
	    xmlBufferWriteChar(buf, "<?");
	    xmlBufferWriteCHAR(buf, cur->name);
	    if (cur->content != NULL) {
		xmlBufferWriteChar(buf, " ");
#ifndef XML_USE_BUFFER_CONTENT
		xmlBufferWriteCHAR(buf, cur->content);
#else
		xmlBufferWriteCHAR(buf, xmlBufferContent(cur->content));
#endif
	    }
	    xmlBufferWriteChar(buf, "?>");
	} else {
	    xmlBufferWriteChar(buf, "<?");
	    xmlBufferWriteCHAR(buf, cur->name);
	    xmlBufferWriteChar(buf, "?>");
	}
	return;
    }
    if (cur->type == XML_COMMENT_NODE) {
	if (cur->content != NULL) {
	    xmlBufferWriteChar(buf, "<!--");
#ifndef XML_USE_BUFFER_CONTENT
	    xmlBufferWriteCHAR(buf, cur->content);
#else
	    xmlBufferWriteCHAR(buf, xmlBufferContent(cur->content));
#endif
	    xmlBufferWriteChar(buf, "-->");
	}
	return;
    }
    if (cur->type == XML_ENTITY_REF_NODE) {
        xmlBufferWriteChar(buf, "&");
	xmlBufferWriteCHAR(buf, cur->name);
        xmlBufferWriteChar(buf, ";");
	return;
    }
    if (cur->type == XML_CDATA_SECTION_NODE) {
        xmlBufferWriteChar(buf, "<![CDATA[");
	if (cur->content != NULL)
#ifndef XML_USE_BUFFER_CONTENT
	    xmlBufferWriteCHAR(buf, cur->content);
#else
	    xmlBufferWriteCHAR(buf, xmlBufferContent(cur->content));
#endif
        xmlBufferWriteChar(buf, "]]>");
	return;
    }

    if (format == 1) {
	tmp = cur->children;
	while (tmp != NULL) {
	    if ((tmp->type == XML_TEXT_NODE) || 
		(tmp->type == XML_ENTITY_REF_NODE)) {
		format = 0;
		break;
	    }
	    tmp = tmp->next;
	}
    }
    xmlBufferWriteChar(buf, "<");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(buf, cur->ns->prefix);
	xmlBufferWriteChar(buf, ":");
    }

    xmlBufferWriteCHAR(buf, cur->name);
    if (cur->nsDef)
        xmlNsListDump(buf, cur->nsDef);
    if (cur->properties != NULL)
        xmlAttrListDump(buf, doc, cur->properties);

    if ((cur->content == NULL) && (cur->children == NULL) &&
	(!xmlSaveNoEmptyTags)) {
        xmlBufferWriteChar(buf, "/>");
	return;
    }
    xmlBufferWriteChar(buf, ">");
    if (cur->content != NULL) {
	xmlChar *buffer;

#ifndef XML_USE_BUFFER_CONTENT
	buffer = xmlEncodeEntitiesReentrant(doc, cur->content);
#else
	buffer = xmlEncodeEntitiesReentrant(doc, 
		                            xmlBufferContent(cur->content));
#endif
	if (buffer != NULL) {
	    xmlBufferWriteCHAR(buf, buffer);
	    xmlFree(buffer);
	}
    }
    if (cur->children != NULL) {
	if (format) xmlBufferWriteChar(buf, "\n");
	xmlNodeListDump(buf, doc, cur->children,
		        (level >= 0?level+1:-1), format);
	if ((xmlIndentTreeOutput) && (format))
	    for (i = 0;i < level;i++)
		xmlBufferWriteChar(buf, "  ");
    }
    xmlBufferWriteChar(buf, "</");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(buf, cur->ns->prefix);
	xmlBufferWriteChar(buf, ":");
    }

    xmlBufferWriteCHAR(buf, cur->name);
    xmlBufferWriteChar(buf, ">");
}

/**
 * xmlElemDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * @cur:  the current node
 *
 * Dump an XML/HTML node, recursive behaviour,children are printed too.
 */
void
xmlElemDump(FILE *f, xmlDocPtr doc, xmlNodePtr cur) {
    xmlBufferPtr buf;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlElemDump : cur == NULL\n");
#endif
	return;
    }
    if (doc == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlElemDump : doc == NULL\n");
#endif
    }
    buf = xmlBufferCreate();
    if (buf == NULL) return;
    if ((doc != NULL) && 
        (doc->type == XML_HTML_DOCUMENT_NODE)) {
#ifdef LIBXML_HTML_ENABLED
        htmlNodeDump(buf, doc, cur);
#else	
	printf("HTML support not compiled in\n");
#endif /* LIBXML_HTML_ENABLED */
    } else
        xmlNodeDump(buf, doc, cur, 0, 1);
    xmlBufferDump(f, buf);
    xmlBufferFree(buf);
}

/**
 * xmlDocContentDump:
 * @buf:  the XML buffer output
 * @cur:  the document
 *
 * Dump an XML document.
 */
static void
xmlDocContentDump(xmlBufferPtr buf, xmlDocPtr cur) {
    xmlBufferWriteChar(buf, "<?xml version=");
    if (cur->version != NULL) 
	xmlBufferWriteQuotedString(buf, cur->version);
    else
	xmlBufferWriteChar(buf, "\"1.0\"");
    if (cur->encoding != NULL) {
        xmlBufferWriteChar(buf, " encoding=");
	xmlBufferWriteQuotedString(buf, cur->encoding);
    }
    switch (cur->standalone) {
        case 0:
	    xmlBufferWriteChar(buf, " standalone=\"no\"");
	    break;
        case 1:
	    xmlBufferWriteChar(buf, " standalone=\"yes\"");
	    break;
    }
    xmlBufferWriteChar(buf, "?>\n");
    if (cur->children != NULL) {
        xmlNodePtr child = cur->children;

	/* global namespace definitions, the old way */
	if (oldXMLWDcompatibility)
	    xmlGlobalNsListDump(buf, cur->oldNs);
	else 
	    xmlUpgradeOldNs(cur);
	
	while (child != NULL) {
	    xmlNodeDump(buf, cur, child, 0, 1);
	    xmlBufferWriteChar(buf, "\n");
	    child = child->next;
	}
    }
}

/**
 * xmlDocDumpMemory:
 * @cur:  the document
 * @mem:  OUT: the memory pointer
 * @size:  OUT: the memory lenght
 *
 * Dump an XML document in memory and return the xmlChar * and it's size.
 * It's up to the caller to free the memory.
 */
void
xmlDocDumpMemory(xmlDocPtr cur, xmlChar**mem, int *size) {
    xmlBufferPtr buf;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlDocDumpMemory : document == NULL\n");
#endif
	*mem = NULL;
	*size = 0;
	return;
    }
    buf = xmlBufferCreate();
    if (buf == NULL) {
	*mem = NULL;
	*size = 0;
	return;
    }
    xmlDocContentDump(buf, cur);
    *mem = xmlStrndup(buf->content, buf->use);
    *size = buf->use;
    xmlBufferFree(buf);
}

/**
 * xmlGetDocCompressMode:
 * @doc:  the document
 *
 * get the compression ratio for a document, ZLIB based
 * Returns 0 (uncompressed) to 9 (max compression)
 */
int
xmlGetDocCompressMode (xmlDocPtr doc) {
    if (doc == NULL) return(-1);
    return(doc->compression);
}

/**
 * xmlSetDocCompressMode:
 * @doc:  the document
 * @mode:  the compression ratio
 *
 * set the compression ratio for a document, ZLIB based
 * Correct values: 0 (uncompressed) to 9 (max compression)
 */
void
xmlSetDocCompressMode (xmlDocPtr doc, int mode) {
    if (doc == NULL) return;
    if (mode < 0) doc->compression = 0;
    else if (mode > 9) doc->compression = 9;
    else doc->compression = mode;
}

/**
 * xmlGetCompressMode:
 *
 * get the default compression mode used, ZLIB based.
 * Returns 0 (uncompressed) to 9 (max compression)
 */
int
 xmlGetCompressMode(void) {
    return(xmlCompressMode);
}

/**
 * xmlSetCompressMode:
 * @mode:  the compression ratio
 *
 * set the default compression mode used, ZLIB based
 * Correct values: 0 (uncompressed) to 9 (max compression)
 */
void
xmlSetCompressMode(int mode) {
    if (mode < 0) xmlCompressMode = 0;
    else if (mode > 9) xmlCompressMode = 9;
    else xmlCompressMode = mode;
}

/**
 * xmlDocDump:
 * @f:  the FILE*
 * @cur:  the document
 *
 * Dump an XML document to an open FILE.
 */
void
xmlDocDump(FILE *f, xmlDocPtr cur) {
    xmlBufferPtr buf;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "xmlDocDump : document == NULL\n");
#endif
	return;
    }
    buf = xmlBufferCreate();
    if (buf == NULL) return;
    xmlDocContentDump(buf, cur);
    xmlBufferDump(f, buf);
    xmlBufferFree(buf);
}

/**
 * xmlSaveFile:
 * @filename:  the filename
 * @cur:  the document
 *
 * Dump an XML document to a file. Will use compression if
 * compiled in and enabled. If @filename is "-" the stdout file is
 * used.
 * returns: the number of file written or -1 in case of failure.
 */
int
xmlSaveFile(const char *filename, xmlDocPtr cur) {
    xmlBufferPtr buf;
#ifdef HAVE_ZLIB_H
    gzFile zoutput = NULL;
    char mode[15];
#endif
    FILE *output = NULL;
    int ret;

    /* 
     * save the content to a temp buffer.
     */
    buf = xmlBufferCreate();
    if (buf == NULL) return(0);
    xmlDocContentDump(buf, cur);

#ifdef HAVE_ZLIB_H
    if (cur->compression < 0) cur->compression = xmlCompressMode;
    if ((cur->compression > 0) && (cur->compression <= 9)) {
        sprintf(mode, "w%d", cur->compression);
	if (!strcmp(filename, "-")) 
	    zoutput = gzdopen(1, mode);
	else
	    zoutput = gzopen(filename, mode);
    }
    if (zoutput == NULL) {
#endif
        output = fopen(filename, "w");
	if (output == NULL) {
	    xmlBufferFree(buf);
	    return(-1);
	}
#ifdef HAVE_ZLIB_H
    }

    if (zoutput != NULL) {
        ret = gzwrite(zoutput, buf->content, sizeof(xmlChar) * buf->use);
	gzclose(zoutput);
    } else {
#endif
        ret = xmlBufferDump(output, buf);
	fclose(output);
#ifdef HAVE_ZLIB_H
    }
#endif
    xmlBufferFree(buf);
    return(ret * sizeof(xmlChar));
}

