/*
 * tree.c : implemetation of access function for an XML tree.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#include "config.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h> /* for memset() only ! */

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "xmlmemory.h"
#include "tree.h"
#include "entities.h"
#include "valid.h"

static CHAR xmlStringText[] = { 't', 'e', 'x', 't', 0 };
int oldXMLWDcompatibility = 0;
int xmlIndentTreeOutput = 1;

static int xmlCompressMode = 0;

#define UPDATE_LAST_CHILD(n) if ((n) != NULL) {				\
    xmlNodePtr ulccur = (n)->childs;					\
    if (ulccur == NULL) {						\
        (n)->last = NULL;						\
    } else {								\
        while (ulccur->next != NULL) ulccur = ulccur->next;		\
	(n)->last = ulccur;						\
}}

/************************************************************************
 *									*
 *		Allocation and deallocation of basic structures		*
 *									*
 ************************************************************************/
 
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

/**
 * xmlNewNs:
 * @node:  the element carrying the namespace
 * @href:  the URI associated
 * @prefix:  the prefix for the namespace
 *
 * Creation of a new Namespace.
 * Returns returns a new namespace pointer
 */
xmlNsPtr
xmlNewNs(xmlNodePtr node, const CHAR *href, const CHAR *prefix) {
    xmlNsPtr cur;

    if (href == NULL) {
        fprintf(stderr, "xmlNewNs: href == NULL !\n");
	return(NULL);
    }

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlNsPtr) xmlMalloc(sizeof(xmlNs));
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

/**
 * xmlNewGlobalNs:
 * @doc:  the document carrying the namespace
 * @href:  the URI associated
 * @prefix:  the prefix for the namespace
 *
 * Creation of a Namespace, the old way using PI and without scoping, to AVOID.
 * Returns returns a new namespace pointer
 */
xmlNsPtr
xmlNewGlobalNs(xmlDocPtr doc, const CHAR *href, const CHAR *prefix) {
    xmlNsPtr cur;

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlNsPtr) xmlMalloc(sizeof(xmlNs));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewGlobalNs : malloc failed\n");
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
        fprintf(stderr, "xmlSetNs: node == NULL\n");
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
        fprintf(stderr, "xmlFreeNs : ns == NULL\n");
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
        fprintf(stderr, "xmlFreeNsList : ns == NULL\n");
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
 * Creation of a new DTD.
 * Returns a pointer to the new DTD structure
 */
xmlDtdPtr
xmlNewDtd(xmlDocPtr doc, const CHAR *name,
                    const CHAR *ExternalID, const CHAR *SystemID) {
    xmlDtdPtr cur;

    if ((doc != NULL) && (doc->extSubset != NULL)) {
        fprintf(stderr, "xmlNewDtd(%s): document %s already have a DTD %s\n",
	    /* !!! */ (char *) name, doc->name,
	    /* !!! */ (char *)doc->extSubset->name);
    }

    /*
     * Allocate a new DTD and fill the fields.
     */
    cur = (xmlDtdPtr) xmlMalloc(sizeof(xmlDtd));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDtd : malloc failed\n");
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
    cur->notations = NULL;
    cur->elements = NULL;
    cur->attributes = NULL;
    cur->entities = NULL;
    if (doc != NULL)
	doc->extSubset = cur;

    return(cur);
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
xmlCreateIntSubset(xmlDocPtr doc, const CHAR *name,
                   const CHAR *ExternalID, const CHAR *SystemID) {
    xmlDtdPtr cur;

    if ((doc != NULL) && (doc->intSubset != NULL)) {
        fprintf(stderr, 
     "xmlCreateIntSubset(): document %s already have an internal subset\n",
	    doc->name);
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
    cur->notations = NULL;
    cur->elements = NULL;
    cur->attributes = NULL;
    cur->entities = NULL;
    if (doc != NULL)
	doc->intSubset = cur;

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
        fprintf(stderr, "xmlFreeDtd : DTD == NULL\n");
	return;
    }
    if (cur->name != NULL) xmlFree((char *) cur->name);
    if (cur->SystemID != NULL) xmlFree((char *) cur->SystemID);
    if (cur->ExternalID != NULL) xmlFree((char *) cur->ExternalID);
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
 * @version:  CHAR string giving the version of XML "1.0"
 *
 * Returns a new document
 */
xmlDocPtr
xmlNewDoc(const CHAR *version) {
    xmlDocPtr cur;

    if (version == NULL) {
        fprintf(stderr, "xmlNewDoc : version == NULL\n");
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

    cur->type = XML_DOCUMENT_NODE;
    cur->version = xmlStrdup(version); 
    cur->name = NULL;
    cur->root = NULL; 
    cur->intSubset = NULL;
    cur->extSubset = NULL;
    cur->oldNs = NULL;
    cur->encoding = NULL;
    cur->standalone = -1;
    cur->compression = xmlCompressMode;
    cur->ids = NULL;
    cur->refs = NULL;
#ifndef XML_WITHOUT_CORBA
    cur->_private = NULL;
    cur->vepv = NULL;
#endif
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
    if (cur->root != NULL) xmlFreeNodeList(cur->root);
    if (cur->intSubset != NULL) xmlFreeDtd(cur->intSubset);
    if (cur->extSubset != NULL) xmlFreeDtd(cur->extSubset);
    if (cur->oldNs != NULL) xmlFreeNsList(cur->oldNs);
    if (cur->ids != NULL) xmlFreeIDTable((xmlIDTablePtr) cur->ids);
    if (cur->refs != NULL) xmlFreeRefTable((xmlRefTablePtr) cur->refs);
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
xmlStringLenGetNodeList(xmlDocPtr doc, const CHAR *value, int len) {
    xmlNodePtr ret = NULL, last = NULL;
    xmlNodePtr node;
    CHAR *val;
    const CHAR *cur = value;
    const CHAR *q;
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
	        fprintf(stderr,
		    "xmlStringLenGetNodeList: unterminated entity %30s\n", q);
	        return(ret);
	    }
            if (cur != q) {
		/*
		 * Predefined entities don't generate nodes
		 */
		val = xmlStrndup(q, cur - q);
		ent = xmlGetDocEntity(doc, val);
		if ((ent != NULL) &&
		    (ent->type == XML_INTERNAL_PREDEFINED_ENTITY)) {
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
xmlStringGetNodeList(xmlDocPtr doc, const CHAR *value) {
    xmlNodePtr ret = NULL, last = NULL;
    xmlNodePtr node;
    CHAR *val;
    const CHAR *cur = value;
    const CHAR *q;
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
	        fprintf(stderr,
		        "xmlStringGetNodeList: unterminated entity %30s\n", q);
	        return(ret);
	    }
            if (cur != q) {
		/*
		 * Predefined entities don't generate nodes
		 */
		val = xmlStrndup(q, cur - q);
		ent = xmlGetDocEntity(doc, val);
		if ((ent != NULL) &&
		    (ent->type == XML_INTERNAL_PREDEFINED_ENTITY)) {
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
CHAR *
xmlNodeListGetString(xmlDocPtr doc, xmlNodePtr list, int inLine) {
    xmlNodePtr node = list;
    CHAR *ret = NULL;
    xmlEntityPtr ent;

    if (list == NULL) return(NULL);

    while (node != NULL) {
        if (node->type == XML_TEXT_NODE) {
	    if (inLine)
		ret = xmlStrcat(ret, node->content);
	    else {
	        CHAR *buffer;

		buffer = xmlEncodeEntitiesReentrant(doc, node->content);
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
		else
		    ret = xmlStrcat(ret, node->content);
            } else {
	        CHAR buf[2];
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
xmlNewProp(xmlNodePtr node, const CHAR *name, const CHAR *value) {
    xmlAttrPtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewProp : name == NULL\n");
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

    cur->type = XML_ATTRIBUTE_NODE;
    cur->node = node; 
    cur->ns = NULL;
    cur->name = xmlStrdup(name);
    if (value != NULL)
	cur->val = xmlStringGetNodeList(node->doc, value);
    else 
	cur->val = NULL;
#ifndef XML_WITHOUT_CORBA
    cur->_private = NULL;
    cur->vepv = NULL;
#endif

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
xmlNewNsProp(xmlNodePtr node, xmlNsPtr ns, const CHAR *name,
           const CHAR *value) {
    xmlAttrPtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewProp : name == NULL\n");
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

    cur->type = XML_ATTRIBUTE_NODE;
    cur->node = node; 
    cur->ns = ns;
    cur->name = xmlStrdup(name);
    if (value != NULL)
	cur->val = xmlStringGetNodeList(node->doc, value);
    else 
	cur->val = NULL;
#ifndef XML_WITHOUT_CORBA
    cur->_private = NULL;
    cur->vepv = NULL;
#endif

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
xmlNewDocProp(xmlDocPtr doc, const CHAR *name, const CHAR *value) {
    xmlAttrPtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewProp : name == NULL\n");
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

    cur->type = XML_ATTRIBUTE_NODE;
    cur->node = NULL; 
    cur->name = xmlStrdup(name);
    if (value != NULL)
	cur->val = xmlStringGetNodeList(doc, value);
    else 
	cur->val = NULL;
#ifndef XML_WITHOUT_CORBA
    cur->_private = NULL;
    cur->vepv = NULL;
#endif

    cur->next = NULL;
    return(cur);
}

/**
 * xmlFreePropList:
 * @cur:  the first property in the list
 *
 * Free a property and all its siblings, all the childs are freed too.
 */
void
xmlFreePropList(xmlAttrPtr cur) {
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

/**
 * xmlFreeProp:
 * @cur:  the first property in the list
 *
 * Free one property, all the childs are freed too.
 */
void
xmlFreeProp(xmlAttrPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeProp : property == NULL\n");
	return;
    }
    if (cur->name != NULL) xmlFree((char *) cur->name);
    if (cur->val != NULL) xmlFreeNodeList(cur->val);
    memset(cur, -1, sizeof(xmlAttr));
    xmlFree(cur);
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
xmlNewPI(const CHAR *name, const CHAR *content) {
    xmlNodePtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewPI : name == NULL\n");
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

    cur->type = XML_PI_NODE;
    cur->doc = NULL;
    cur->parent = NULL; 
    cur->next = NULL;
    cur->prev = NULL;
    cur->childs = NULL;
    cur->last = NULL;
    cur->properties = NULL;
    cur->name = xmlStrdup(name);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else
	cur->content = NULL;
#ifndef XML_WITHOUT_CORBA
    cur->_private = NULL;
    cur->vepv = NULL;
#endif
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
xmlNewNode(xmlNsPtr ns, const CHAR *name) {
    xmlNodePtr cur;

    if (name == NULL) {
        fprintf(stderr, "xmlNewNode : name == NULL\n");
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

    cur->type = XML_ELEMENT_NODE;
    cur->doc = NULL;
    cur->parent = NULL; 
    cur->next = NULL;
    cur->prev = NULL;
    cur->childs = NULL;
    cur->last = NULL;
    cur->properties = NULL;
    cur->name = xmlStrdup(name);
    cur->ns = ns;
    cur->nsDef = NULL;
    cur->content = NULL;
#ifndef XML_WITHOUT_CORBA
    cur->_private = NULL;
    cur->vepv = NULL;
#endif
    return(cur);
}

/**
 * xmlNewDocNode:
 * @doc:  the document
 * @ns:  namespace if any
 * @name:  the node name
 * @content:  the text content if any
 *
 * Creation of a new node element within a document. @ns and @content
 * are optionnal (NULL).
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocNode(xmlDocPtr doc, xmlNsPtr ns,
                         const CHAR *name, const CHAR *content) {
    xmlNodePtr cur;

    cur = xmlNewNode(ns, name);
    if (cur != NULL) {
        cur->doc = doc;
	if (content != NULL) {
	    cur->childs = xmlStringGetNodeList(doc, content);
	    UPDATE_LAST_CHILD(cur)
	}
    }
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
xmlNewText(const CHAR *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_TEXT_NODE;
    cur->doc = NULL;
    cur->parent = NULL; 
    cur->next = NULL; 
    cur->prev = NULL; 
    cur->childs = NULL; 
    cur->last = NULL; 
    cur->properties = NULL; 
    cur->type = XML_TEXT_NODE;
    cur->name = xmlStrdup(xmlStringText);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
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
xmlNewReference(xmlDocPtr doc, const CHAR *name) {
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

    cur->type = XML_ENTITY_REF_NODE;
    cur->doc = doc;
    cur->parent = NULL; 
    cur->next = NULL; 
    cur->prev = NULL; 
    cur->childs = NULL; 
    cur->last = NULL; 
    cur->properties = NULL; 
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
    cur->ns = NULL;
    cur->nsDef = NULL;

    ent = xmlGetDocEntity(doc, cur->name);
    if (ent != NULL)
	cur->content = ent->content;
    else
        cur->content = NULL;
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
xmlNewDocText(xmlDocPtr doc, const CHAR *content) {
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
xmlNewTextLen(const CHAR *content, int len) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewText : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_TEXT_NODE;
    cur->doc = NULL; 
    cur->parent = NULL; 
    cur->prev = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->last = NULL; 
    cur->properties = NULL; 
    cur->type = XML_TEXT_NODE;
    cur->name = xmlStrdup(xmlStringText);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrndup(content, len);
    else 
	cur->content = NULL;
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
xmlNewDocTextLen(xmlDocPtr doc, const CHAR *content, int len) {
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
xmlNewComment(const CHAR *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewComment : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_COMMENT_NODE;
    cur->doc = NULL; 
    cur->parent = NULL; 
    cur->prev = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->last = NULL; 
    cur->properties = NULL; 
    cur->type = XML_COMMENT_NODE;
    cur->name = xmlStrdup(xmlStringText);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if (content != NULL)
	cur->content = xmlStrdup(content);
    else 
	cur->content = NULL;
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
xmlNewCDataBlock(xmlDocPtr doc, const CHAR *content, int len) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewCDataBlock : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_CDATA_SECTION_NODE;
    cur->doc = NULL; 
    cur->parent = NULL; 
    cur->prev = NULL; 
    cur->next = NULL; 
    cur->childs = NULL; 
    cur->last = NULL; 
    cur->properties = NULL; 
    cur->name = xmlStrdup(xmlStringText);
    cur->ns = NULL;
    cur->nsDef = NULL;
    if ((content != NULL) && (len > 0)) {
	cur->content = xmlStrndup(content, len);
    } else 
	cur->content = NULL;
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
xmlNewDocComment(xmlDocPtr doc, const CHAR *content) {
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
 * @content:  the content of the child if any.
 *
 * 
 * Creation of a new child element, added at the end of @parent childs list.
 * @ns and @content parameters are optionnal (NULL). If content is non NULL,
 * a child list containing the TEXTs and ENTITY_REFs node will be created.
 * Returns a pointer to the new node object.
 */
xmlNodePtr
xmlNewChild(xmlNodePtr parent, xmlNsPtr ns,
                       const CHAR *name, const CHAR *content) {
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
	cur = xmlNewDocNode(parent->doc, parent->ns, name, content);
    else
	cur = xmlNewDocNode(parent->doc, ns, name, content);
    if (cur == NULL) return(NULL);

    /*
     * add the new element at the end of the childs list.
     */
    cur->type = XML_ELEMENT_NODE;
    cur->parent = parent;
    cur->doc = parent->doc;
    if (parent->childs == NULL) {
        parent->childs = cur;
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
 * xmlAddSibling:
 * @cur:  the child node
 * @elem:  the new node
 *
 * Add a new element to the list of siblings of @cur
 * Returns the element or NULL in case of error.
 */
xmlNodePtr
xmlAddSibling(xmlNodePtr cur, xmlNodePtr elem) {
    xmlNodePtr parent;

    if (cur == NULL) {
        fprintf(stderr, "xmlAddSibling : cur == NULL\n");
	return(NULL);
    }

    if (elem == NULL) {
        fprintf(stderr, "xmlAddSibling : elem == NULL\n");
	return(NULL);
    }

    if ((cur->doc != NULL) && (elem->doc != NULL) &&
        (cur->doc != elem->doc)) {
	fprintf(stderr, 
	        "xmlAddSibling: Elements moved to a different document\n");
    }

    while (cur->next != NULL) cur = cur->next;

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
        fprintf(stderr, "xmladdChild : parent == NULL\n");
	return(NULL);
    }

    if (cur == NULL) {
        fprintf(stderr, "xmladdChild : child == NULL\n");
	return(NULL);
    }

    if ((cur->doc != NULL) && (parent->doc != NULL) &&
        (cur->doc != parent->doc)) {
	fprintf(stderr, "Elements moved to a different document\n");
    }

    /*
     * add the new element at the end of the childs list.
     */
    cur->parent = parent;
    cur->doc = parent->doc; /* the parent may not be linked to a doc ! */

    /*
     * Handle the case where parent->content != NULL, in that case it will
     * create a intermediate TEXT node.
     */
    if (parent->content != NULL) {
        xmlNodePtr text;
	
	text = xmlNewDocText(parent->doc, parent->content);
	if (text != NULL) {
	    text->next = parent->childs;
	    if (text->next != NULL)
		text->next->prev = text;
	    parent->childs = text;
	    UPDATE_LAST_CHILD(parent)
	    xmlFree(parent->content);
	    parent->content = NULL;
	}
    }
    if (parent->childs == NULL) {
        parent->childs = cur;
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
        fprintf(stderr, "xmlGetLastChild : parent == NULL\n");
	return(NULL);
    }
    return(parent->last);
}

/**
 * xmlFreeNodeList:
 * @cur:  the first node in the list
 *
 * Free a node and all its siblings, this is a recursive behaviour, all
 * the childs are freed too.
 */
void
xmlFreeNodeList(xmlNodePtr cur) {
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

/**
 * xmlFreeNode:
 * @cur:  the node
 *
 * Free a node, this is a recursive behaviour, all the childs are freed too.
 */
void
xmlFreeNode(xmlNodePtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlFreeNode : node == NULL\n");
	return;
    }
    cur->doc = NULL;
    cur->parent = NULL;
    cur->next = NULL;
    cur->prev = NULL;
    if (cur->childs != NULL) xmlFreeNodeList(cur->childs);
    if (cur->properties != NULL) xmlFreePropList(cur->properties);
    if (cur->type != XML_ENTITY_REF_NODE)
	if (cur->content != NULL) xmlFree(cur->content);
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
        fprintf(stderr, "xmlUnlinkNode : node == NULL\n");
	return;
    }
    if ((cur->parent != NULL) && (cur->parent->childs == cur))
        cur->parent->childs = cur->next;
    if ((cur->parent != NULL) && (cur->parent->last == cur))
        cur->parent->last = cur->prev;
    if (cur->next != NULL)
        cur->next->prev = cur->prev;
    if (cur->prev != NULL)
        cur->prev->next = cur->next;
    cur->next = cur->prev = NULL;
    cur->parent = NULL;
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
	    fprintf(stderr, "xmlCopyNamespace: unknown type %d\n", cur->type);
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
    if (cur->val != NULL)
	ret = xmlNewDocProp(cur->val->doc, cur->name, NULL);
    else
	ret = xmlNewDocProp(NULL, cur->name, NULL);
    if (ret == NULL) return(NULL);
    
    if ((cur->ns != NULL) && (target != NULL)) {
        xmlNsPtr ns;

	ns = xmlSearchNs(target->doc, target, cur->ns->prefix);
	ret->ns = ns;
    } else
        ret->ns = NULL;

    if (cur->val != NULL)
	ret->val = xmlCopyNodeList(cur->val);
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
	    p = q;
	}
	cur = cur->next;
    }
    return(ret);
}

/*
 * NOTE about the CopyNode operations !
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

    ret->type = node->type;
    ret->doc = doc;
    ret->parent = parent; 
    ret->next = NULL;
    ret->prev = NULL;
    ret->childs = NULL;
    ret->last = NULL;
    ret->properties = NULL;
    if (node->name != NULL)
	ret->name = xmlStrdup(node->name);
    else
        ret->name = NULL;
    ret->ns = NULL;
    ret->nsDef = NULL;
    if ((node->content != NULL) && (node->type != XML_ENTITY_REF_NODE))
	ret->content = xmlStrdup(node->content);
    else
	ret->content = NULL;
#ifndef XML_WITHOUT_CORBA
    ret->_private = NULL;
    ret->vepv = NULL;
#endif
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
    if (node->childs != NULL)
        ret->childs = xmlStaticCopyNodeList(node->childs, doc, ret);
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
    if (elem->childs != NULL)
        ret->childs = xmlCopyElementList(elem->childs);
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
    if (doc->root != NULL)
        ret->root = xmlStaticCopyNodeList(doc->root, ret, NULL);
    return(ret);
}

/************************************************************************
 *									*
 *		Content access functions				*
 *									*
 ************************************************************************/
 
/**
 * xmlNodeSetLang:
 * @cur:  the node being changed
 * @lang:  the langage description
 *
 * Searches the language of a node, i.e. the values of the xml:lang
 * attribute or the one carried by the nearest ancestor.
 *
 * Returns a pointer to the lang value, or NULL if not found
 */
void
xmlNodeSetLang(xmlNodePtr cur, const CHAR *lang) {
    /* TODO xmlNodeSetLang check against the production [33] LanguageID */
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
 */
const CHAR *
xmlNodeGetLang(xmlNodePtr cur) {
    const CHAR *lang;

    while (cur != NULL) {
        lang = xmlGetProp(cur, BAD_CAST "xml:lang");
	if (lang != NULL)
	    return(lang);
	cur = cur->parent;
    }
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
 * Returns a new CHAR * or NULL if no content is available.
 *     It's up to the caller to free the memory.
 */
CHAR *
xmlNodeGetContent(xmlNodePtr cur) {
    if (cur == NULL) return(NULL);
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE:
            return(xmlNodeListGetString(cur->doc, cur->childs, 1));
	    break;
        case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    if (attr->node != NULL)
		return(xmlNodeListGetString(attr->node->doc, attr->val, 1));
	    else
		return(xmlNodeListGetString(NULL, attr->val, 1));
	    break;
	}
        case XML_PI_NODE:
	    if (cur->content != NULL)
	        return(xmlStrdup(cur->content));
	    return(NULL);
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_COMMENT_NODE:
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
        case XML_NOTATION_NODE:
	    return(NULL);
        case XML_CDATA_SECTION_NODE:
        case XML_TEXT_NODE:
	    if (cur->content != NULL)
		return(xmlStrdup(cur->content));
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
xmlNodeSetContent(xmlNodePtr cur, const CHAR *content) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeSetContent : node == NULL\n");
	return;
    }
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE:
	    if (cur->content != NULL) {
	        xmlFree(cur->content);
		cur->content = NULL;
	    }
	    if (cur->childs != NULL) xmlFreeNodeList(cur->childs);
	    cur->childs = xmlStringGetNodeList(cur->doc, content);
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
	    if (cur->content != NULL) xmlFree(cur->content);
	    if (cur->childs != NULL) xmlFreeNodeList(cur->childs);
	    cur->last = cur->childs = NULL;
	    if (content != NULL)
		cur->content = xmlStrdup(content);
	    else 
		cur->content = NULL;
	    break;
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
	    break;
        case XML_NOTATION_NODE:
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
xmlNodeSetContentLen(xmlNodePtr cur, const CHAR *content, int len) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeSetContentLen : node == NULL\n");
	return;
    }
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE:
	    if (cur->content != NULL) {
	        xmlFree(cur->content);
		cur->content = NULL;
	    }
	    if (cur->childs != NULL) xmlFreeNodeList(cur->childs);
	    cur->childs = xmlStringLenGetNodeList(cur->doc, content, len);
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
	    if (cur->content != NULL) xmlFree(cur->content);
	    if (cur->childs != NULL) xmlFreeNodeList(cur->childs);
	    cur->childs = cur->last = NULL;
	    if (content != NULL)
		cur->content = xmlStrndup(content, len);
	    else 
		cur->content = NULL;
	    break;
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
	    break;
        case XML_NOTATION_NODE:
	    if (cur->content != NULL) xmlFree(cur->content);
	    if (cur->childs != NULL) xmlFreeNodeList(cur->childs);
	    cur->childs = cur->last = NULL;
	    if (content != NULL)
		cur->content = xmlStrndup(content, len);
	    else 
		cur->content = NULL;
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
xmlNodeAddContentLen(xmlNodePtr cur, const CHAR *content, int len) {
    if (cur == NULL) {
        fprintf(stderr, "xmlNodeAddContentLen : node == NULL\n");
	return;
    }
    if (len <= 0) return;
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE: {
	    xmlNodePtr last = NULL, new;

	    if (cur->childs != NULL) {
		last = cur->last;
	    } else {
	        if (cur->content != NULL) {
		    cur->childs = xmlStringGetNodeList(cur->doc, cur->content);
		    UPDATE_LAST_CHILD(cur)
		    xmlFree(cur->content);
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
	    if (content != NULL)
		cur->content = xmlStrncat(cur->content, content, len);
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
	    break;
        case XML_NOTATION_NODE:
	    if (content != NULL)
		cur->content = xmlStrncat(cur->content, content, len);
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
xmlNodeAddContent(xmlNodePtr cur, const CHAR *content) {
    int len;

    if (cur == NULL) {
        fprintf(stderr, "xmlNodeAddContent : node == NULL\n");
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
    xmlNodeAddContent(first, second->content);
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
xmlSearchNs(xmlDocPtr doc, xmlNodePtr node, const CHAR *nameSpace) {
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
xmlSearchNsByHref(xmlDocPtr doc, xmlNodePtr node, const CHAR *href) {
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

/**
 * xmlGetProp:
 * @node:  the node
 * @name:  the attribute name
 *
 * Search and get the value of an attribute associated to a node
 * This does the entity substitution.
 * Returns the attribute value or NULL if not found.
 */
CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name) {
    xmlAttrPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name))  {
	    CHAR *ret;

	    ret = xmlNodeListGetString(node->doc, prop->val, 1);
	    if (ret == NULL) return(xmlStrdup((CHAR *)""));
	    return(ret);
        }
	prop = prop->next;
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
xmlSetProp(xmlNodePtr node, const CHAR *name, const CHAR *value) {
    xmlAttrPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name)) {
	    if (prop->val != NULL) 
	        xmlFreeNodeList(prop->val);
	    prop->val = NULL;
	    if (value != NULL)
		prop->val = xmlStringGetNodeList(node->doc, value);
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
 * xmlTextConcat:
 * @node:  the node
 * @content:  the content
 * @len:  @content lenght
 * 
 * Concat the given string at the end of the existing node content
 */

void
xmlTextConcat(xmlNodePtr node, const CHAR *content, int len) {
    if (node == NULL) return;

    if (node->type != XML_TEXT_NODE) {
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
    ret->content = (CHAR *) xmlMalloc(ret->size * sizeof(CHAR));
    if (ret->content == NULL) {
	fprintf(stderr, "xmlBufferCreate : out of memory!\n");
	xmlFree(ret);
        return(NULL);
    }
    ret->content[0] = 0;
    return(ret);
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
        fprintf(stderr, "xmlBufferFree: buf == NULL\n");
	return;
    }
    if (buf->content == NULL) {
        fprintf(stderr, "xmlBufferFree: buf->content == NULL\n");
    } else {
        memset(buf->content, -1, BASE_BUFFER_SIZE);
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
 * @len:  the number of CHAR to remove
 *
 * Remove the beginning of an XML buffer.
 *
 * Returns the number of CHAR removed, or -1 in case of failure.
 */
int
xmlBufferShrink(xmlBufferPtr buf, int len) {
    if (len == 0) return(0);
    if (len > buf->use) return(-1);

    buf->use -= len;
    memmove(buf->content, &buf->content[len], buf->use * sizeof(CHAR));

    buf->content[buf->use] = 0;
    return(len);
}

/**
 * xmlBufferDump:
 * @file:  the file output
 * @buf:  the buffer to dump
 *
 * Dumps an XML buffer to  a FILE *.
 * Returns the number of CHAR written
 */
int
xmlBufferDump(FILE *file, xmlBufferPtr buf) {
    int ret;

    if (buf == NULL) {
        fprintf(stderr, "xmlBufferDump: buf == NULL\n");
	return(0);
    }
    if (buf->content == NULL) {
        fprintf(stderr, "xmlBufferDump: buf->content == NULL\n");
	return(0);
    }
    if (file == NULL) file = stdout;
    ret = fwrite(buf->content, sizeof(CHAR), buf->use, file);
    return(ret);
}

/**
 * xmlBufferAdd:
 * @buf:  the buffer to dump
 * @str:  the CHAR string
 * @len:  the number of CHAR to add
 *
 * Add a string range to an XML buffer.
 */
void
xmlBufferAdd(xmlBufferPtr buf, const CHAR *str, int len) {
    int l;

    if (str == NULL) {
        fprintf(stderr, "xmlBufferAdd: str == NULL\n");
	return;
    }
    l = xmlStrlen(str);
    if (l < len) len = l;
    if (len <= 0) return;

    if (buf->use + len + 10 >= buf->size) {
	CHAR *rebuf;

        buf->size *= 2;
	if (buf->use + len + 10 > buf->size)
	    buf->size = buf->use + len + 10;
	rebuf = (CHAR *) xmlRealloc(buf->content, buf->size * sizeof(CHAR));
	if (rebuf == NULL) {
	    fprintf(stderr, "xmlBufferAdd : out of memory!\n");
	    return;
	}
	buf->content = rebuf;
    }
    memmove(&buf->content[buf->use], str, len);
    buf->use += len;
    buf->content[buf->use] = 0;
}

/**
 * xmlBufferCat:
 * @buf:  the buffer to dump
 * @str:  the CHAR string
 *
 * Append a zero terminated string to an XML buffer.
 */
void
xmlBufferCat(xmlBufferPtr buf, const CHAR *str) {
    const CHAR *cur;

    if (str == NULL) {
        fprintf(stderr, "xmlBufferAdd: str == NULL\n");
	return;
    }
    for (cur = str;*cur != 0;cur++) {
        if (buf->use  + 10 >= buf->size) {
	    CHAR *rebuf;

	    buf->size *= 2;
	    rebuf = (CHAR *) xmlRealloc(buf->content, buf->size * sizeof(CHAR));
	    if (rebuf == NULL) {
	        fprintf(stderr, "xmlBufferAdd : out of memory!\n");
		return;
	    }
	    buf->content = rebuf;
	}
        buf->content[buf->use++] = *cur;
    }
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
        fprintf(stderr, "xmlBufferAdd: str == NULL\n");
	return;
    }
    for (cur = str;*cur != 0;cur++) {
        if (buf->use  + 10 >= buf->size) {
	    CHAR *rebuf;

	    buf->size *= 2;
	    rebuf = (CHAR *) xmlRealloc(buf->content, buf->size * sizeof(CHAR));
	    if (rebuf == NULL) {
	        fprintf(stderr, "xmlBufferAdd : out of memory!\n");
		return;
	    }
	    buf->content = rebuf;
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
 * CHARs at the end of the buffer.
 */
void
xmlBufferWriteCHAR(xmlBufferPtr buf, const CHAR *string) {
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
 * a quoted or double quoted CHAR string, checking first if it holds
 * quote or double-quotes internally
 */
void
xmlBufferWriteQuotedString(xmlBufferPtr buf, const CHAR *string) {
    if (xmlStrchr(string, '"')) {
        if (xmlStrchr(string, '\'')) {
	    fprintf(stderr,
 "xmlBufferWriteQuotedString: string contains quote and double-quotes !\n");
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
        fprintf(stderr, "xmlGlobalNsDump : Ns == NULL\n");
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
        fprintf(stderr, "xmlNsDump : Ns == NULL\n");
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
xmlDtdDump(xmlBufferPtr buf, xmlDocPtr doc) {
    xmlDtdPtr cur = doc->intSubset;

    if (cur == NULL) {
        fprintf(stderr, "xmlDtdDump : no internal subset\n");
	return;
    }
    xmlBufferWriteChar(buf, "<!DOCTYPE ");
    xmlBufferWriteCHAR(buf, cur->name);
    if (cur->ExternalID != NULL) {
	xmlBufferWriteChar(buf, " PUBLIC ");
	xmlBufferWriteQuotedString(buf, cur->ExternalID);
	xmlBufferWriteChar(buf, " ");
	xmlBufferWriteQuotedString(buf, cur->SystemID);
    }  else if (cur->SystemID != NULL) {
	xmlBufferWriteChar(buf, " SYSTEM ");
	xmlBufferWriteQuotedString(buf, cur->SystemID);
    }
    if ((cur->entities == NULL) && (cur->elements == NULL) &&
        (cur->attributes == NULL) && (cur->notations == NULL)) {
	xmlBufferWriteChar(buf, ">\n");
	return;
    }
    xmlBufferWriteChar(buf, " [\n");
    if (cur->entities != NULL)
	xmlDumpEntitiesTable(buf, (xmlEntitiesTablePtr) cur->entities);
    if (cur->notations != NULL)
	xmlDumpNotationTable(buf, (xmlNotationTablePtr) cur->notations);
    if (cur->elements != NULL)
	xmlDumpElementTable(buf, (xmlElementTablePtr) cur->elements);
    if (cur->attributes != NULL)
	xmlDumpAttributeTable(buf, (xmlAttributeTablePtr) cur->attributes);
    xmlBufferWriteChar(buf, "]");

    xmlBufferWriteChar(buf, ">\n");
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
    CHAR *value;

    if (cur == NULL) {
        fprintf(stderr, "xmlAttrDump : property == NULL\n");
	return;
    }
    xmlBufferWriteChar(buf, " ");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(buf, cur->ns->prefix);
	xmlBufferWriteChar(buf, ":");
    }
    xmlBufferWriteCHAR(buf, cur->name);
    value = xmlNodeListGetString(doc, cur->val, 0);
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
        fprintf(stderr, "xmlAttrListDump : property == NULL\n");
	return;
    }
    while (cur != NULL) {
        xmlAttrDump(buf, doc, cur);
	cur = cur->next;
    }
}


static void
xmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level);
/**
 * xmlNodeListDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * @cur:  the first node
 * @level: the imbrication level for indenting
 *
 * Dump an XML node list, recursive behaviour,children are printed too.
 */
static void
xmlNodeListDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level) {
    int needIndent = 0, i;

    if (cur == NULL) {
        fprintf(stderr, "xmlNodeListDump : node == NULL\n");
	return;
    }
    while (cur != NULL) {
        if ((cur->type != XML_TEXT_NODE) &&
	    (cur->type != XML_ENTITY_REF_NODE)) {
	    if (!needIndent) {
	        needIndent = 1;
		xmlBufferWriteChar(buf, "\n");
	    }
	}
        xmlNodeDump(buf, doc, cur, level);
	cur = cur->next;
    }
    if ((xmlIndentTreeOutput) && (needIndent))
	for (i = 1;i < level;i++)
	    xmlBufferWriteChar(buf, "  ");
}

/**
 * xmlNodeDump:
 * @buf:  the XML buffer output
 * @doc:  the document
 * @cur:  the current node
 * @level: the imbrication level for indenting
 *
 * Dump an XML node, recursive behaviour,children are printed too.
 */
static void
xmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level) {
    int i;

    if (cur == NULL) {
        fprintf(stderr, "xmlNodeDump : node == NULL\n");
	return;
    }
    if (cur->type == XML_TEXT_NODE) {
	if (cur->content != NULL) {
            CHAR *buffer;

            buffer = xmlEncodeEntitiesReentrant(doc, cur->content);
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
		xmlBufferWriteCHAR(buf, cur->content);
	    }
	    xmlBufferWriteChar(buf, "?>\n");
	}
	return;
    }
    if (cur->type == XML_COMMENT_NODE) {
	if (cur->content != NULL) {
	    xmlBufferWriteChar(buf, "<!--");
	    xmlBufferWriteCHAR(buf, cur->content);
	    xmlBufferWriteChar(buf, "-->\n");
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
	    xmlBufferWriteCHAR(buf, cur->content);
        xmlBufferWriteChar(buf, "]]>");
	return;
    }
    if (xmlIndentTreeOutput)
	for (i = 0;i < level;i++)
	    xmlBufferWriteChar(buf, "  ");

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

    if ((cur->content == NULL) && (cur->childs == NULL)) {
        xmlBufferWriteChar(buf, "/>\n");
	return;
    }
    xmlBufferWriteChar(buf, ">");
    if (cur->content != NULL) {
	CHAR *buffer;

	buffer = xmlEncodeEntitiesReentrant(doc, cur->content);
	if (buffer != NULL) {
	    xmlBufferWriteCHAR(buf, buffer);
	    xmlFree(buffer);
	}
    }
    if (cur->childs != NULL) {
	xmlNodeListDump(buf, doc, cur->childs, level + 1);
    }
    xmlBufferWriteChar(buf, "</");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(buf, cur->ns->prefix);
	xmlBufferWriteChar(buf, ":");
    }

    xmlBufferWriteCHAR(buf, cur->name);
    xmlBufferWriteChar(buf, ">\n");
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
    if (cur->intSubset != NULL)
        xmlDtdDump(buf, cur);
    if (cur->root != NULL) {
        xmlNodePtr child = cur->root;

	/* global namespace definitions, the old way */
	if (oldXMLWDcompatibility)
	    xmlGlobalNsListDump(buf, cur->oldNs);
	else 
	    xmlUpgradeOldNs(cur);
	
	while (child != NULL) {
	    xmlNodeDump(buf, cur, child, 0);
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
 * Dump an XML document in memory and return the CHAR * and it's size.
 * It's up to the caller to free the memory.
 */
void
xmlDocDumpMemory(xmlDocPtr cur, CHAR**mem, int *size) {
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
 * compiled in and enabled.
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

    if (zoutput != NULL) {
        ret = gzwrite(zoutput, buf->content, sizeof(CHAR) * buf->use);
	gzclose(zoutput);
    } else {
#endif
        ret = xmlBufferDump(output, buf);
	fclose(output);
#ifdef HAVE_ZLIB_H
    }
#endif
    xmlBufferFree(buf);
    return(ret * sizeof(CHAR));
}

