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
#include <stdlib.h>
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
 * return values: returns a new namespace pointer
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

/**
 * xmlNewGlobalNs:
 * @doc:  the document carrying the namespace
 * @href:  the URI associated
 * @prefix:  the prefix for the namespace
 *
 * Creation of a Namespace, the old way using PI and without scoping, to AVOID.
 * return values: returns a new namespace pointer
 */
xmlNsPtr
xmlNewGlobalNs(xmlDocPtr doc, const CHAR *href, const CHAR *prefix) {
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
    if (cur->href != NULL) free((char *) cur->href);
    if (cur->prefix != NULL) free((char *) cur->prefix);
    memset(cur, -1, sizeof(xmlNs));
    free(cur);
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
 * return values: a pointer to the new DTD structure
 */
xmlDtdPtr
xmlNewDtd(xmlDocPtr doc, const CHAR *name,
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

/**
 * xmlNewDoc:
 * @version:  CHAR string giving the version of XML "1.0"
 *
 * Create a new document
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
    cur = (xmlDocPtr) malloc(sizeof(xmlDoc));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewDoc : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_DOCUMENT_NODE;
    cur->version = xmlStrdup(version); 
    cur->name = NULL;
    cur->root = NULL; 
    cur->dtd = NULL;
    cur->oldNs = NULL;
    cur->encoding = NULL;
    cur->entities = NULL;
    cur->standalone = -1;
    cur->compression = xmlCompressMode;
#ifndef WITHOUT_CORBA
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

/**
 * xmlStringLenGetNodeList:
 * @doc:  the document
 * @value:  the value of the text
 * @int len:  the length of the string value
 *
 * Parse the value string and build the node list associated. Should
 * produce a flat tree with only TEXTs and ENTITY_REFs.
 * return values: a pointer to the first child
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
			if (val != NULL) free(val);
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
		free(val);
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
 * return values: a pointer to the first child
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
			if (val != NULL) free(val);
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
		free(val);
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
 * return values: a pointer to the string copy, the calller must free it.
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
	    else
		ret = xmlStrcat(ret, xmlEncodeEntities(doc, node->content));
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
 * return values: a pointer to the attribute
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
    cur = (xmlAttrPtr) malloc(sizeof(xmlAttr));
    if (cur == NULL) {
        fprintf(stderr, "xmlNewProp : malloc failed\n");
	return(NULL);
    }

    cur->type = XML_ATTRIBUTE_NODE;
    cur->node = node; 
    cur->name = xmlStrdup(name);
    if (value != NULL)
	cur->val = xmlStringGetNodeList(node->doc, value);
    else 
	cur->val = NULL;
#ifndef WITHOUT_CORBA
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
 * return values: a pointer to the attribute
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
    cur = (xmlAttrPtr) malloc(sizeof(xmlAttr));
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
#ifndef WITHOUT_CORBA
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
    if (cur->name != NULL) free((char *) cur->name);
    if (cur->val != NULL) xmlFreeNodeList(cur->val);
    memset(cur, -1, sizeof(xmlAttr));
    free(cur);
}

/**
 * xmlNewNode:
 * @ns:  namespace if any
 * @name:  the node name
 * @content:  the text content if any
 *
 * Creation of a new node element. @ns and @content are optionnal (NULL).
 * If content is non NULL, a child list containing the TEXTs and
 * ENTITY_REFs node will be created.
 * return values: a pointer to the new node object.
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
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
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
    cur->properties = NULL;
    cur->name = xmlStrdup(name);
    cur->ns = ns;
    cur->nsDef = NULL;
    cur->content = NULL;
#ifndef WITHOUT_CORBA
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
 * return values: a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocNode(xmlDocPtr doc, xmlNsPtr ns,
                         const CHAR *name, CHAR *content) {
    xmlNodePtr cur;

    cur = xmlNewNode(ns, name);
    if (cur != NULL) {
        cur->doc = doc;
	if (content != NULL)
	    cur->childs = xmlStringGetNodeList(doc, content);
    }
    return(cur);
}


/**
 * xmlNewText:
 * @content:  the text content
 *
 * Creation of a new text node.
 * return values: a pointer to the new node object.
 */
xmlNodePtr
xmlNewText(const CHAR *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
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
 * return values: a pointer to the new node object.
 */
xmlNodePtr
xmlNewReference(xmlDocPtr doc, const CHAR *name) {
    xmlNodePtr cur;
    xmlEntityPtr ent;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
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
 * return values: a pointer to the new node object.
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
 * return values: a pointer to the new node object.
 */
xmlNodePtr
xmlNewTextLen(const CHAR *content, int len) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
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
 * return values: a pointer to the new node object.
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
 * return values: a pointer to the new node object.
 */
xmlNodePtr
xmlNewComment(CHAR *content) {
    xmlNodePtr cur;

    /*
     * Allocate a new node and fill the fields.
     */
    cur = (xmlNodePtr) malloc(sizeof(xmlNode));
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
 * xmlNewComment:
 * @doc:  the document
 * @content:  the comment content
 *
 * Creation of a new node containing a commentwithin a document.
 * return values: a pointer to the new node object.
 */
xmlNodePtr
xmlNewDocComment(xmlDocPtr doc, CHAR *content) {
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
 * return values: a pointer to the new node object.
 */
xmlNodePtr
xmlNewChild(xmlNodePtr parent, xmlNsPtr ns,
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
    } else {
        prev = parent->childs;
	while (prev->next != NULL) prev = prev->next;
	prev->next = cur;
	cur->prev = prev;
    }

    return(cur);
}

/**
 * xmlAddChild:
 * @parent:  the parent node
 * @cur:  the child node
 *
 * Add a new child element, to @parent, at the end of the child list.
 * return values: the child or NULL in case of error.
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
	    free(parent->content);
	    parent->content = NULL;
	}
    }
    if (parent->childs == NULL) {
        parent->childs = cur;
    } else {
        prev = parent->childs;
	while (prev->next != NULL) prev = prev->next;
	prev->next = cur;
	cur->prev = prev;
    }

    return(cur);
}

/**
 * xmlGetLastChild:
 * @parent:  the parent node
 *
 * Search the last child of a node.
 * return values: the last child or NULL if none.
 */
xmlNodePtr
xmlGetLastChild(xmlNodePtr parent) {
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
	if (cur->content != NULL) free(cur->content);
    if (cur->name != NULL) free((char *) cur->name);
    if (cur->nsDef != NULL) xmlFreeNsList(cur->nsDef);
    memset(cur, -1, sizeof(xmlNode));
    free(cur);
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
    if (cur->next != NULL)
        cur->next->prev = cur->prev;
    if (cur->prev != NULL)
        cur->prev->next = cur->next;
    cur->next = cur->prev = NULL;
    cur->parent = NULL;
}

/************************************************************************
 *									*
 *		Content access functions				*
 *									*
 ************************************************************************/
 
/**
 * xmlNodeGetContent:
 * @cur:  the node being read
 *
 * Read the value of a node, this can be either the text carried
 * directly by this node if it's a TEXT node or the aggregate string
 * of the values carried by this node child's (TEXT and ENTITY_REF).
 * Entity references are substitued.
 * Return value: a new CHAR * or NULL if no content is available.
 */
CHAR *
xmlNodeGetContent(xmlNodePtr cur) {
    if (cur == NULL) return(NULL);
    switch (cur->type) {
        case XML_DOCUMENT_FRAG_NODE:
        case XML_ELEMENT_NODE:
            return(xmlNodeListGetString(cur->doc, cur->childs, 1));
	    break;
        case XML_ATTRIBUTE_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
        case XML_NOTATION_NODE:
	    return(NULL);
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
	        free(cur->content);
		cur->content = NULL;
	    }
	    if (cur->childs != NULL) xmlFreeNode(cur->childs);
	    cur->childs = xmlStringGetNodeList(cur->doc, content);
	    break;
        case XML_ATTRIBUTE_NODE:
	    break;
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
	    if (cur->content != NULL) free(cur->content);
	    if (cur->childs != NULL) xmlFreeNode(cur->childs);
	    if (content != NULL)
		cur->content = xmlStrdup(content);
	    else 
		cur->content = NULL;
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
	        free(cur->content);
		cur->content = NULL;
	    }
	    if (cur->childs != NULL) xmlFreeNode(cur->childs);
	    cur->childs = xmlStringLenGetNodeList(cur->doc, content, len);
	    break;
        case XML_ATTRIBUTE_NODE:
	    break;
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_ENTITY_REF_NODE:
        case XML_ENTITY_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
	    if (cur->content != NULL) free(cur->content);
	    if (cur->childs != NULL) xmlFreeNode(cur->childs);
	    if (content != NULL)
		cur->content = xmlStrndup(content, len);
	    else 
		cur->content = NULL;
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_TYPE_NODE:
	    break;
        case XML_NOTATION_NODE:
	    if (cur->content != NULL) free(cur->content);
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
		last = cur->childs;
		while (last->next != NULL) last = last->next;
	    } else {
	        if (cur->content != NULL) {
		    cur->childs = xmlStringGetNodeList(cur->doc, cur->content);
		    free(cur->content);
		    cur->content = NULL;
		    if (cur->childs != NULL) {
			last = cur->childs;
			while (last->next != NULL) last = last->next;
                    }
		}
	    }
	    new = xmlStringLenGetNodeList(cur->doc, content, len);
	    if (new != NULL) {
		xmlAddChild(cur, new);
	        if ((last != NULL) && (last->next == new))
		    xmlTextMerge(last, new);
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
 * Return values: the first text node augmented
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
 * xmlSearchNs:
 * @doc:  the document
 * @node:  the current node
 * @nameSpace:  the namespace string
 *
 * Search a Ns registered under a given name space for a document.
 * recurse on the parents until it finds the defined namespace
 * or return NULL otherwise.
 * @nameSpace can be NULL, this is a search for the default namespace.
 * return values: the namespace pointer or NULL.
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
 * return values: the namespace pointer or NULL.
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
 * return values: the attribute value or NULL if not found.
 */
const CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name) {
    xmlAttrPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name)) 
	    return(xmlNodeListGetString(node->doc, prop->val, 1));
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
 * return values: the attribute pointer.
 */
xmlAttrPtr
xmlSetProp(xmlNodePtr node, const CHAR *name, const CHAR *value) {
    xmlAttrPtr prop = node->properties;

    while (prop != NULL) {
        if (!xmlStrcmp(prop->name, name)) {
	    if (prop->val != NULL) 
	        xmlFreeNode(prop->val);
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
 * return values: 1 yes, 0 no
 */
int
xmlNodeIsText(xmlNodePtr node) {
    if (node == NULL) return(0);

    if (node->type == XML_TEXT_NODE) return(1);
    return(0);
}

/**
 * xmlNodeIsText:
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

static CHAR *buffer = NULL;
static int buffer_index = 0;
static int buffer_size = 0;

/**
 * xmlBufferWriteCHAR:
 * @string:  the string to add
 *
 * routine which manage and grows an output buffer. This one add
 * CHARs at the end of the array.
 */
void
xmlBufferWriteCHAR(const CHAR *string) {
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

/**
 * xmlBufferWriteChar:
 * @string:  the string to add
 *
 * routine which manage and grows an output buffer. This one add
 * C chars at the end of the array.
 */
void
xmlBufferWriteChar(const char *string) {
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

/**
 * xmlGlobalNsDump:
 * @cur:  a namespace
 *
 * Dump a global Namespace, this is the old version based on PIs.
 */
static void
xmlGlobalNsDump(xmlNsPtr cur) {
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

/**
 * xmlGlobalNsListDump:
 * @cur:  the first namespace
 *
 * Dump a list of global Namespace, this is the old version based on PIs.
 */
static void
xmlGlobalNsListDump(xmlNsPtr cur) {
    while (cur != NULL) {
        xmlGlobalNsDump(cur);
	cur = cur->next;
    }
}

/**
 * xmlNsDump:
 * @cur:  a namespace
 *
 * Dump a local Namespace definition.
 * Should be called in the context of attributes dumps.
 */
static void
xmlNsDump(xmlNsPtr cur) {
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

/**
 * xmlNsListDump:
 * @cur:  the first namespace
 *
 * Dump a list of local Namespace definitions.
 * Should be called in the context of attributes dumps.
 */
static void
xmlNsListDump(xmlNsPtr cur) {
    while (cur != NULL) {
        xmlNsDump(cur);
	cur = cur->next;
    }
}

/**
 * xmlDtdDump:
 * @doc:  the document
 * 
 * Dump the XML document DTD, if any.
 */
static void
xmlDtdDump(xmlDocPtr doc) {
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

/**
 * xmlAttrDump:
 * @doc:  the document
 * @cur:  the attribute pointer
 *
 * Dump an XML attribute
 */
static void
xmlAttrDump(xmlDocPtr doc, xmlAttrPtr cur) {
    CHAR *value;

    if (cur == NULL) {
        fprintf(stderr, "xmlAttrDump : property == NULL\n");
	return;
    }
    xmlBufferWriteChar(" ");
    xmlBufferWriteCHAR(cur->name);
    value = xmlNodeListGetString(doc, cur->val, 0);
    if (value) {
	xmlBufferWriteChar("=\"");
	xmlBufferWriteCHAR(value);
	xmlBufferWriteChar("\"");
	free(value);
    }
}

/**
 * xmlAttrListDump:
 * @doc:  the document
 * @cur:  the first attribute pointer
 *
 * Dump a list of XML attributes
 */
static void
xmlAttrListDump(xmlDocPtr doc, xmlAttrPtr cur) {
    if (cur == NULL) {
        fprintf(stderr, "xmlAttrListDump : property == NULL\n");
	return;
    }
    while (cur != NULL) {
        xmlAttrDump(doc, cur);
	cur = cur->next;
    }
}


static void
xmlNodeDump(xmlDocPtr doc, xmlNodePtr cur, int level);
/**
 * xmlNodeListDump:
 * @doc:  the document
 * @cur:  the first node
 * @level: the imbrication level for indenting
 *
 * Dump an XML node list, recursive behaviour,children are printed too.
 */
static void
xmlNodeListDump(xmlDocPtr doc, xmlNodePtr cur, int level) {
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
		xmlBufferWriteChar("\n");
	    }
	}
        xmlNodeDump(doc, cur, level);
	cur = cur->next;
    }
    if ((xmlIndentTreeOutput) && (needIndent))
	for (i = 1;i < level;i++)
	    xmlBufferWriteChar("  ");
}

/**
 * xmlNodeDump:
 * @doc:  the document
 * @cur:  the current node
 * @level: the imbrication level for indenting
 *
 * Dump an XML node, recursive behaviour,children are printed too.
 */
static void
xmlNodeDump(xmlDocPtr doc, xmlNodePtr cur, int level) {
    int i;

    if (cur == NULL) {
        fprintf(stderr, "xmlNodeDump : node == NULL\n");
	return;
    }
    if (cur->type == XML_TEXT_NODE) {
	if (cur->content != NULL)
	    xmlBufferWriteCHAR(xmlEncodeEntities(doc, cur->content));
	return;
    }
    if (cur->type == XML_COMMENT_NODE) {
	if (cur->content != NULL) {
	    xmlBufferWriteChar("<!--");
	    xmlBufferWriteCHAR(cur->content);
	    xmlBufferWriteChar("-->");
	}
	return;
    }
    if (cur->type == XML_ENTITY_REF_NODE) {
        xmlBufferWriteChar("&");
	xmlBufferWriteCHAR(cur->name);
        xmlBufferWriteChar(";");
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
	xmlNodeListDump(doc, cur->childs, level + 1);
    }
    xmlBufferWriteChar("</");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(cur->ns->prefix);
	xmlBufferWriteChar(":");
    }

    xmlBufferWriteCHAR(cur->name);
    xmlBufferWriteChar(">\n");
}

/**
 * xmlDocContentDump:
 * @cur:  the document
 *
 * Dump an XML document.
 */
static void
xmlDocContentDump(xmlDocPtr cur) {
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

/**
 * xmlGetDocCompressMode:
 * @doc:  the document
 *
 * get the compression ratio for a document, ZLIB based
 * return values: 0 (uncompressed) to 9 (max compression)
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
 * return values: 0 (uncompressed) to 9 (max compression)
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
    if (cur == NULL) {
        fprintf(stderr, "xmlDocDump : document == NULL\n");
	return;
    }
    buffer_index = 0;
    xmlDocContentDump(cur);

    fwrite(buffer, sizeof(CHAR), buffer_index, f);
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
#ifdef HAVE_ZLIB_H
    gzFile zoutput = NULL;
    char mode[15];
#endif
    FILE *output = NULL;
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

