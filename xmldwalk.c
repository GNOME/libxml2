/*
 * xmldwalk.c : the document traversing API.for XML 
 *
 * this is heavily based upon the xmlTextReader streaming node API
 * of libxml2 by Daniel Veillard (daniel@veillard.com). In fact I
 * just copied and modified xmlreader.c
 *
 * So for license and disclaimer see the license and disclaimer of
 * libxml2.
 *
 * alfred@mickautsch.de
 */

#define IN_LIBXML
#include "libxml.h"

#ifdef LIBXML_WALKER_ENABLED
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlreader.h>
#include <libxml/xmldwalk.h>

struct _xmlDocWalker {
    xmlDocPtr doc;              /* current document */
    xmlNodePtr node;            /* current node */
    xmlNodePtr curnode;         /* current attribute node */
    int depth;                  /* depth of the current node */
    xmlDocWalkerState state;    /* state of the iterator */
};

/**
 * xmlNewDocWalker:
 * @doc:  the xmlDocPtr
 *
 * Creates a new instance of the xmlDocWalker
 *
 * Returns 0 in case of error, the new allocated xmlDocWalkerPtr otherwise
 */
xmlDocWalkerPtr
xmlNewDocWalker(xmlDocPtr doc)
{
    xmlDocWalkerPtr ret;

    if (doc == 0)
        return(0);

    ret = xmlMalloc(sizeof(xmlDocWalker));
    if (ret == 0) {
        xmlGenericError(xmlGenericErrorContext,
                        "xmlNewDocWalker : malloc failed\n");
        return(0);
    }

    memset(ret, 0, sizeof(xmlDocWalker));

    ret->doc = doc;
    ret->node = 0;
    ret->state = XML_DWALK_NONE;

    return ret;
}

/**
 * xmlFreeDocWalker:
 * @iter:  the xmlDocWalkerPtr
 *
 * Deallocate the xmlDocWalker
 */
void
xmlFreeDocWalker(xmlDocWalkerPtr iter)
{
    if (iter != 0)
        xmlFree(iter);
}

/**
 * xmlDocWalkerRewind:
 * @iter:  the xmlDocWalkerPtr
 *
 * Initializes the xmlDocWalker
 *
 * Returns 0 or -1 in case of error
 */
int
xmlDocWalkerRewind(xmlDocWalkerPtr iter)
{
    if (iter == 0 || iter->doc == 0)
        return(-1);

    if (iter->doc->children == 0)
        return(0);

    iter->state = XML_DWALK_NONE;
    iter->depth = 0;
    iter->node = 0;

    return(1);
}

/**
 * xmlDocWalkerStep:
 * @iter:  the xmlDocWalkerPtr
 *
 * Steps through the xml tree
 *
 * Returns 0 or -1 in case of error
 */
int
xmlDocWalkerStep(xmlDocWalkerPtr iter)
{
    if (iter == 0)
        return(-1);

    if (iter->state == XML_DWALK_END)
        return(0);

    if (iter->node == 0) {
        if (iter->doc->children == 0) {
            iter->state = XML_DWALK_END;
            return(0);
        }

        iter->node = iter->doc->children;
        iter->state = XML_DWALK_START;
        return(1);
    }

    if (iter->state != XML_DWALK_BACKTRACK) {
        if (iter->node->children != 0) {
            iter->node = iter->node->children;
            iter->depth++;
            iter->state = XML_DWALK_START;
            return(1);
        }

        if ((iter->node->type == XML_ELEMENT_NODE) ||
            (iter->node->type == XML_ATTRIBUTE_NODE)) {
            iter->state = XML_DWALK_BACKTRACK;
            return(1);
        }
    }

    if (iter->node->next != 0) {
        iter->node = iter->node->next;
        iter->state = XML_DWALK_START;
        return(1);
    }

    if (iter->node->parent != 0) {
        if (iter->node->parent->type == XML_DOCUMENT_NODE) {
            iter->state = XML_DWALK_END;
            return(0);
        }

        iter->node = iter->node->parent;
        iter->depth--;
        iter->state = XML_DWALK_BACKTRACK;
        return(1);
    }

    iter->state = XML_DWALK_END;

    return(1);
}

/**
 * xmlDocWalkerAttributeCount:
 * @iter:  the xmlDocWalkerPtr
 *
 * Provides the number of attributes of the current node
 *
 * Returns 0 if no attributes, -1 in case of error or the attribute count
 */
int
xmlDocWalkerAttributeCount(xmlDocWalkerPtr iter)
{
    int ret;
    xmlAttrPtr attr;
    xmlNsPtr ns;
    xmlNodePtr node;

    if (iter == 0)
        return(-1);

    if (iter->node == 0)
        return(0);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    if (node->type != XML_ELEMENT_NODE)
        return(0);

    ret = 0;
    attr = node->properties;
    while (attr != 0) {
        ret++;
        attr = attr->next;
    }

    ns = node->nsDef;
    while (ns != 0) {
        ret++;
        ns = ns->next;
    }

    return ret;
}

/**
 * xmlDocWalkerDepth:
 * @iter:  the xmlDocWalkerPtr
 *
 * The depth of the node in the tree.
 *
 * Returns the depth or -1 in case of error
 */
int
xmlDocWalkerDepth(xmlDocWalkerPtr iter)
{
    if (iter == 0)
        return(-1);

    if (iter->node == 0)
        return(0);

    if (iter->curnode != 0) {
        if ((iter->curnode->type == XML_ATTRIBUTE_NODE) ||
            (iter->curnode->type == XML_NAMESPACE_DECL))
            return iter->depth + 1;

        return iter->depth + 2;
    }

    return iter->depth;
}

/**
 * xmlDocWalkerHasAttributes:
 * @iter:  the xmlDocWalkerPtr
 *
 * Whether the node has attributes.
 *
 * Returns 1 if true, 0 if false, and -1 in case or error
 */
int
xmlDocWalkerHasAttributes(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;

    if (iter == 0)
        return(-1);

    if (iter->node == 0)
        return(0);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    if ((node->type == XML_ELEMENT_NODE) && (node->properties != 0))
        return(1);

    return(0);
}

/**
 * xmlDocWalkerHasValue:
 * @iter:  the xmlDocWalkerPtr
 *
 * Whether the node can have a text value.
 *
 * Returns 1 if true, 0 if false, and -1 in case or error
 */
int
xmlDocWalkerHasValue(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;

    if (iter == 0)
        return(-1);

    if (iter->node == 0)
        return(0);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    switch (node->type) {
        case XML_ATTRIBUTE_NODE:
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
        case XML_NAMESPACE_DECL:
            return(1);
        default:
            break;
    }

    return(0);
}

/**
 * xmlDocWalkerIsEmptyElement:
 * @iter:  the xmlDocWalkerPtr
 *
 * Check if the current node is empty
 *
 * Returns 1 if empty, 0 if not and -1 in case of error
 */
int
xmlDocWalkerIsEmptyElement(xmlDocWalkerPtr iter)
{
    if ((iter == 0) || (iter->node == 0))
        return(-1);

    if (iter->node->type != XML_ELEMENT_NODE)
        return(0);

    if (iter->curnode != 0)
        return(0);

    if (iter->node->children != 0)
        return(0);

    return(1);
}

/**
 * xmlDocWalkerLocalName:
 * @iter:  the xmlDocWalkerPtr
 *
 * The local name of the node.
 *
 * Returns the local name or NULL if not available
 */
xmlChar *
xmlDocWalkerLocalName(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;

    if ((iter == 0) || (iter->node == 0))
        return(0);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    if (node->type == XML_NAMESPACE_DECL) {
        xmlNsPtr ns = (xmlNsPtr) node;

        if (ns->prefix == 0)
            return xmlStrdup(BAD_CAST "xmlns");
        else
            return xmlStrdup(ns->prefix);
    }

    if ((node->type != XML_ELEMENT_NODE)
        && (node->type != XML_ATTRIBUTE_NODE))
        return (xmlDocWalkerName(iter));

    return xmlStrdup(node->name);

}

/**
 * xmlDocWalkerName:
 * @iter:  the xmlDocWalkerPtr
 *
 * The qualified name of the node, equal to Prefix :LocalName.
 *
 * Returns the local name or NULL if not available
 */
xmlChar *
xmlDocWalkerName(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;
    xmlChar *ret;

    if ((iter == 0) || (iter->node == 0))
        return(0);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    switch (node->type) {
        case XML_ELEMENT_NODE:
        case XML_ATTRIBUTE_NODE:
            if ((node->ns == 0) || (node->ns->prefix == NULL))
                return xmlStrdup(node->name);

            if ((ret = xmlStrdup(node->ns->prefix)) &&
                (ret = xmlStrcat(ret, BAD_CAST ":")) &&
                (ret = xmlStrcat(ret, node->name)))
                return ret;
            if (ret)
                xmlFree(ret);
            return(0);
        case XML_TEXT_NODE:
            return xmlStrdup(BAD_CAST "#text");
        case XML_CDATA_SECTION_NODE:
            return xmlStrdup(BAD_CAST "#cdata-section");
        case XML_ENTITY_NODE:
        case XML_ENTITY_REF_NODE:
            return xmlStrdup(node->name);
        case XML_PI_NODE:
            return xmlStrdup(node->name);
        case XML_COMMENT_NODE:
            return xmlStrdup(BAD_CAST "#comment");
        case XML_DOCUMENT_NODE:
        case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
            return xmlStrdup(BAD_CAST "#document");
        case XML_DOCUMENT_FRAG_NODE:
            return xmlStrdup(BAD_CAST "#document-fragment");
        case XML_NOTATION_NODE:
            return xmlStrdup(node->name);
        case XML_DOCUMENT_TYPE_NODE:
        case XML_DTD_NODE:
            return xmlStrdup(node->name);
        case XML_NAMESPACE_DECL:
            {
                xmlNsPtr ns = (xmlNsPtr) node;

                ret = xmlStrdup(BAD_CAST "xmlns");
                if (ns->prefix == 0)
                    return ret;
                if ((ret) &&
                    (ret = xmlStrcat(ret, BAD_CAST ":")) &&
                    (ret = xmlStrcat(ret, ns->prefix)))
                    return ret;
                if (ret)
                    xmlFree(ret);
                return(0);
            }
        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
        case XML_XINCLUDE_START:
        case XML_XINCLUDE_END:
            return(0);
    }

    return(0);
}

/**
 * xmlDocWalkerNodeType:
 * @iter:  the xmlDocWalkerPtr
 *
 * Get the node type of the current node
 * Reference:
 * http://dotgnu.org/pnetlib-doc/System/Xml/XmlNodeType.html
 *
 * Returns the xmlNodeType of the current node or -1 in case of error
 */
int
xmlDocWalkerNodeType(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;

    if (iter == 0)
        return(-1);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    if (node == 0)
        return(0);

    switch (node->type) {
        case XML_ELEMENT_NODE:
            if ((iter->state == XML_DWALK_END) ||
                (iter->state == XML_DWALK_BACKTRACK))
                return XML_READER_TYPE_END_ELEMENT;
            return XML_READER_TYPE_ELEMENT;

        case XML_NAMESPACE_DECL:
        case XML_ATTRIBUTE_NODE:
            return XML_READER_TYPE_ATTRIBUTE;

        case XML_TEXT_NODE:
            if (xmlIsBlankNode(iter->node)) {
                if (xmlNodeGetSpacePreserve(iter->node))
                    return XML_READER_TYPE_SIGNIFICANT_WHITESPACE;

                return XML_READER_TYPE_WHITESPACE;
            }
            return XML_READER_TYPE_TEXT;

        case XML_CDATA_SECTION_NODE:
            return XML_READER_TYPE_CDATA;

        case XML_ENTITY_REF_NODE:
            return XML_READER_TYPE_ENTITY_REFERENCE;

        case XML_ENTITY_NODE:
            return XML_READER_TYPE_ENTITY;

        case XML_PI_NODE:
            return XML_READER_TYPE_PROCESSING_INSTRUCTION;

        case XML_COMMENT_NODE:
            return XML_READER_TYPE_COMMENT;

        case XML_DOCUMENT_NODE:
        case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
            return XML_READER_TYPE_DOCUMENT;

        case XML_DOCUMENT_FRAG_NODE:
            return XML_READER_TYPE_DOCUMENT_FRAGMENT;

        case XML_NOTATION_NODE:
            return XML_READER_TYPE_NOTATION;

        case XML_DOCUMENT_TYPE_NODE:
        case XML_DTD_NODE:
            return XML_READER_TYPE_DOCUMENT_TYPE;

        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
        case XML_XINCLUDE_START:
        case XML_XINCLUDE_END:
            return XML_READER_TYPE_NONE;
    }

    return(-1);
}

/**
 * xmlDocWalkerPrefix:
 * @iter:  the xmlDocWalkerPtr
 *
 * A shorthand reference to the namespace associated with the node.
 *
 * Returns the prefix or NULL if not available
 */
xmlChar *
xmlDocWalkerPrefix(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;

    if ((iter == 0) || (iter->node == 0) || (iter->node->ns == 0))
        return(0);

    if (iter->curnode != NULL)
        node = iter->curnode;
    else
        node = iter->node;

    if (node->type == XML_NAMESPACE_DECL) {
        xmlNsPtr ns = (xmlNsPtr) node;

        if (ns->prefix == 0)
            return(0);

        return xmlStrdup(BAD_CAST "xmlns");
    }

    if ((node->type != XML_ELEMENT_NODE) &&
        (node->type != XML_ATTRIBUTE_NODE))
        return NULL;

    if ((node->ns != 0) && (node->ns->prefix != 0))
        return xmlStrdup(node->ns->prefix);

    return(0);
}

/**
 * xmlDocWalkerNamespaceUri:
 * @iter:  the xmlDocWalkerPtr
 *
 * The URI defining the namespace associated with the node.
 *
 * Returns the namespace URI or NULL if not available
 */
xmlChar *
xmlDocWalkerNamespaceUri(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;

    if ((iter == 0) || (iter->node == 0))
        return(0);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    if (node->type == XML_NAMESPACE_DECL)
        return xmlStrdup(BAD_CAST "http://www.w3.org/2000/xmlns/");

    if ((node->type != XML_ELEMENT_NODE)
        && (node->type != XML_ATTRIBUTE_NODE))
        return(0);

    if (node->ns != 0)
        return xmlStrdup(node->ns->href);

    return(0);
}

/**
 * xmlDocWalkerBaseUri:
 * @iter:  the xmlDocWalkerPtr
 *
 * The base URI of the node.
 *
 * Returns the base URI or NULL if not available
 */
xmlChar *
xmlDocWalkerBaseUri(xmlDocWalkerPtr iter)
{
    if ((iter == 0) || (iter->node == 0))
        return(0);

    return xmlNodeGetBase(0, iter->node);
}

/**
 * xmlDocWalkerValue:
 * @iter:  the xmlDocWalkerPtr
 *
 * Provides the text value of the node if present
 *
 * Returns the string or NULL if not available. The retsult must be deallocated
 *     with xmlFree()
 */
xmlChar *
xmlDocWalkerValue(xmlDocWalkerPtr iter)
{
    xmlNodePtr node;

    if ((iter == 0) || (iter->node == 0))
        return(0);

    if (iter->curnode != 0)
        node = iter->curnode;
    else
        node = iter->node;

    switch (node->type) {
        case XML_NAMESPACE_DECL:
            return xmlStrdup(((xmlNsPtr) node)->href);
        case XML_ATTRIBUTE_NODE:
            {
                xmlAttrPtr attr = (xmlAttrPtr) node;

                if (attr->parent != 0)
                    return xmlNodeListGetString(attr->parent->doc,
                                                attr->children, 1);
                else
                    return xmlNodeListGetString(0, attr->children, 1);
            }
            break;
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
            if (node->content != 0)
                return xmlStrdup(node->content);
        default:
            break;
    }
    return (NULL);
}

/**
 * xmlDocWalkerGetAttributeNo:
 * @iter:  the xmlDocWalkerPtr
 * @no: the zero-based index of the attribute relative to the containing element
 *
 * Provides the value of the attribute with the specified index relative
 * to the containing element.
 *
 * Returns a string containing the value of the specified attribute, or NULL
 *    in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlDocWalkerGetAttributeNo(xmlDocWalkerPtr iter, int no)
{
    xmlChar *ret;
    int i;
    xmlAttrPtr cur;
    xmlNsPtr ns;

    if ((iter == 0) || (iter->node == 0) || (iter->curnode != 0) ||
        (iter->node->type != XML_ELEMENT_NODE))
        return(0);

    ns = iter->node->nsDef;
    for (i = 0; i < no && ns != 0; i++)
        ns = ns->next;

    if (ns != 0)
        return (xmlStrdup(ns->href));

    cur = iter->node->properties;
    if (cur == 0)
        return(0);

    for (; i < no; i++) {
        cur = cur->next;
        if (cur == 0)
            return(0);
    }

    ret = xmlNodeListGetString(iter->node->doc, cur->children, 1);
    if (ret == 0)
        return (xmlStrdup((xmlChar *) ""));

    return ret;
}

/**
 * xmlDocWalkerGetAttribute:
 * @iter:  the xmlDocWalkerPtr
 * @name: the qualified name of the attribute.
 *
 * Provides the value of the attribute with the specified qualified name.
 *
 * Returns a string containing the value of the specified attribute, or NULL
 *    in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlDocWalkerGetAttribute(xmlDocWalkerPtr iter, const xmlChar * name)
{
    xmlChar *prefix = 0;
    xmlChar *localname;
    xmlNsPtr ns;
    xmlChar *ret = 0;

    if ((iter == 0) || (iter->node == 0) || (iter->curnode != 0) ||
        (iter->node->type != XML_ELEMENT_NODE))
        return(0);

    localname = xmlSplitQName2(name, &prefix);
    if (localname == 0)
        return xmlGetProp(iter->node, name);

    ns = xmlSearchNs(iter->node->doc, iter->node, prefix);
    if (ns != 0)
        ret = xmlGetNsProp(iter->node, localname, ns->href);

    if (localname != 0)
        xmlFree(localname);
    if (prefix != 0)
        xmlFree(prefix);

    return ret;
}

/**
 * xmlDocWalkerGetAttributeNs:
 * @iter:  the xmlDocWalkerPtr
 * @localName: the local name of the attribute.
 * @namespaceURI: the namespace URI of the attribute.
 *
 * Provides the value of the specified attribute
 *
 * Returns a string containing the value of the specified attribute, or NULL
 *    in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlDocWalkerGetAttributeNs(xmlDocWalkerPtr iter,
                           const xmlChar * localName,
                           const xmlChar * namespaceURI)
{
    if ((iter == 0) || (iter->node == 0)
        || (iter->node->type != XML_ELEMENT_NODE))
        return(0);

    return xmlGetNsProp(iter->node, localName, namespaceURI);
}

/**
 * xmlDocWalkerLookupNamespace:
 * @iter:  the xmlDocWalkerPtr
 * @prefix: the prefix whose namespace URI is to be resolved. To return
 *          the default namespace, specify NULL
 *
 * Resolves a namespace prefix in the scope of the current element.
 *
 * Returns a string containing the namespace URI to which the prefix maps
 *    or NULL in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlDocWalkerLookupNamespace(xmlDocWalkerPtr iter, const xmlChar * prefix)
{
    xmlNsPtr ns;

    if ((iter == 0) || (iter->node == 0))
        return(0);

    ns = xmlSearchNs(iter->node->doc, iter->node, prefix);
    if (ns == NULL)
        return (NULL);
    return (xmlStrdup(ns->href));
}

/**
 * xmlDocWalkerMoveToAttributeNo:
 * @iter:  the xmlDocWalkerPtr
 * @no: the zero-based index of the attribute relative to the containing
 *      element.
 *
 * Moves the position of the current instance to the attribute with
 * the specified index relative to the containing element.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlDocWalkerMoveToAttributeNo(xmlDocWalkerPtr iter, int no)
{
    int i;
    xmlAttrPtr cur;
    xmlNsPtr ns;

    if ((iter == 0) || (iter->node == 0))
        return(-1);

    if ((iter->state == XML_DWALK_NONE) ||
        (iter->state == XML_DWALK_BACKTRACK) ||
        (iter->state == XML_DWALK_END))
        return(0);

    if (iter->node->type != XML_ELEMENT_NODE)
        return(0);

    iter->curnode = NULL;

    ns = iter->node->nsDef;
    for (i = 0; i < no && ns != NULL; i++)
        ns = ns->next;

    if (ns != 0) {
        iter->curnode = (xmlNodePtr) ns;
        return(1);
    }

    cur = iter->node->properties;
    if (cur == 0)
        return(0);

    for (; i < no; i++) {
        cur = cur->next;
        if (cur == 0)
            return(0);
    }

    iter->curnode = (xmlNodePtr) cur;
    return(1);
}

/**
 * xmlDocWalkerMoveToAttribute:
 * @iter:  the xmlDocWalkerPtr
 * @name: the qualified name of the attribute.
 *
 * Moves the position of the current instance to the attribute with
 * the specified qualified name.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlDocWalkerMoveToAttribute(xmlDocWalkerPtr iter, const xmlChar * name)
{
    xmlChar *prefix = NULL;
    xmlChar *localname = NULL;
    xmlNsPtr ns;
    xmlAttrPtr prop;
    int ret = 0;

    if ((iter == 0) || (iter->node == 0) || (name == 0))
        return(-1);

    if ((iter->state == XML_DWALK_NONE) ||
        (iter->state == XML_DWALK_BACKTRACK) ||
        (iter->state == XML_DWALK_END))
        goto not_found;

    if (iter->node->type != XML_ELEMENT_NODE)
        goto not_found;

    localname = xmlSplitQName2(name, &prefix);
    if (localname == 0) {
        if (xmlStrEqual(name, BAD_CAST "xmlns")) {
            ns = iter->node->nsDef;
            while (ns != 0) {
                if (ns->prefix == 0) {
                    iter->curnode = (xmlNodePtr) ns;
                    goto found;
                }
                ns = ns->next;
            }

            goto not_found;
        }

        prop = iter->node->properties;
        while (prop != 0) {
            if (xmlStrEqual(prop->name, name) &&
                ((prop->ns == NULL) || (prop->ns->prefix == NULL))) {
                iter->curnode = (xmlNodePtr) prop;
                goto found;
            }
            prop = prop->next;
        }

        goto not_found;
    }

    if (xmlStrEqual(prefix, BAD_CAST "xmlns")) {
        ns = iter->node->nsDef;
        while (ns != 0) {
            if (ns->prefix != NULL && xmlStrEqual(ns->prefix, localname)) {
                iter->curnode = (xmlNodePtr) ns;
                goto found;
            }
            ns = ns->next;
        }
        goto not_found;
    }

    prop = iter->node->properties;
    while (prop != NULL) {
        if (xmlStrEqual(prop->name, localname) &&
            (prop->ns != NULL) && xmlStrEqual(prop->ns->prefix, prefix)) {
            iter->curnode = (xmlNodePtr) prop;
            goto found;
        }
        prop = prop->next;
    }

    if (0)
  found:{
        ret = 1;
    }
  not_found:

    if (localname != 0)
        xmlFree(localname);
    if (prefix != 0)
        xmlFree(prefix);
    return ret;
}

/**
 * xmlDocWalkerMoveToAttributeNs:
 * @iter:  the xmlDocWalkerPtr
 * @localName:  the local name of the attribute.
 * @namespaceURI:  the namespace URI of the attribute.
 *
 * Moves the position of the current instance to the attribute with the
 * specified local name and namespace URI.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlDocWalkerMoveToAttributeNs(xmlDocWalkerPtr iter,
                              const xmlChar * localName,
                              const xmlChar * namespaceURI)
{
    xmlAttrPtr prop;
    xmlNodePtr node;

    if ((iter == 0) || (iter->node == 0) || (localName == 0)
        || (namespaceURI == 0))
        return(-1);

    if ((iter->state == XML_DWALK_NONE) ||
        (iter->state == XML_DWALK_BACKTRACK) ||
        (iter->state == XML_DWALK_END))
        return(0);

    if (iter->node->type != XML_ELEMENT_NODE)
        return(0);

    node = iter->node;

    prop = node->properties;
    while (prop != NULL) {
        if (xmlStrEqual(prop->name, localName) &&
            ((prop->ns != NULL)
             && (xmlStrEqual(prop->ns->href, namespaceURI)))) {
            iter->curnode = (xmlNodePtr) prop;
            return(1);
        }

        prop = prop->next;
    }

    return(0);
}

/**
 * xmlDocWalkerMoveToFirstAttribute:
 * @iter:  the xmlDocWalkerPtr
 *
 * Moves the position of the current instance to the first attribute
 * associated with the current node.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlDocWalkerMoveToFirstAttribute(xmlDocWalkerPtr iter)
{
    if ((iter == 0) || (iter->node == 0))
        return(-1);

    if ((iter->state == XML_DWALK_NONE) ||
        (iter->state == XML_DWALK_BACKTRACK) ||
        (iter->state == XML_DWALK_END))
        return(0);

    if (iter->node->type != XML_ELEMENT_NODE)
        return(0);

    if (iter->node->nsDef != NULL) {
        iter->curnode = (xmlNodePtr) iter->node->nsDef;
        return(1);
    }

    if (iter->node->properties != NULL) {
        iter->curnode = (xmlNodePtr) iter->node->properties;
        return(1);
    }

    return(0);
}

/**
 * xmlDocWalkerMoveToNextAttribute:
 * @iter:  the xmlDocWalkerPtr
 *
 * Moves the position of the current instance to the next attribute
 * associated with the current node.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlDocWalkerMoveToNextAttribute(xmlDocWalkerPtr iter)
{
    if ((iter == 0) || (iter->node == 0))
        return(-1);

    if ((iter->state == XML_DWALK_NONE) ||
        (iter->state == XML_DWALK_BACKTRACK) ||
        (iter->state == XML_DWALK_END))
        return(0);

    if (iter->node->type != XML_ELEMENT_NODE)
        return(0);
    if (iter->curnode == NULL)
        return (xmlDocWalkerMoveToFirstAttribute(iter));

    if (iter->curnode->type == XML_NAMESPACE_DECL) {
        xmlNsPtr ns = (xmlNsPtr) iter->curnode;

        if (ns->next != NULL) {
            iter->curnode = (xmlNodePtr) ns->next;
            return(1);
        }
        if (iter->node->properties != NULL) {
            iter->curnode = (xmlNodePtr) iter->node->properties;
            return(1);
        }

        return(0);
    } else if ((iter->curnode->type == XML_ATTRIBUTE_NODE) &&
               (iter->curnode->next != NULL)) {
        iter->curnode = iter->curnode->next;
        return(1);
    }

    return(0);
}

/**
 * xmlDocWalkerMoveToElement:
 * @iter:  the xmlDocWalkerPtr
 *
 * Moves the position of the current instance to the node that
 * contains the current Attribute  node.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not moved
 */
int
xmlDocWalkerMoveToElement(xmlDocWalkerPtr iter)
{
    if ((iter == 0) || (iter->node == 0))
        return(-1);

    if ((iter->state == XML_DWALK_NONE) ||
        (iter->state == XML_DWALK_BACKTRACK) ||
        (iter->state == XML_DWALK_END))
        return(0);

    if (iter->node->type != XML_ELEMENT_NODE)
        return(0);

    if (iter->curnode != NULL) {
        iter->curnode = NULL;
        return(1);
    }

    return(0);
}

/**
 * xmlDocWalkerCurrentNode:
 * @iter:  the xmlDocWalkerPtr
 *
 * Hacking interface allowing to get the xmlNodePtr correponding to the
 * current node being accessed by the xmlDocWalker.
 *
 * Returns the xmlNodePtr or NULL in case of error.
 */
xmlNodePtr
xmlDocWalkerCurrentNode(xmlDocWalkerPtr iter)
{
    if (iter == 0)
        return(0);

    if (iter->curnode != NULL)
        return iter->curnode;

    return iter->node;
}

/**
 * xmlDocWalkerCurrentDoc:
 * @iter:  the xmlDocWalkerPtr
 *
 * Hacking interface allowing to get the xmlDocPtr correponding to the
 * current document being accessed by the xmlDocWalker.
 *
 * Returns the xmlDocPtr or NULL in case of error.
 */
xmlDocPtr
xmlDocWalkerCurrentDoc(xmlDocWalkerPtr iter)
{
    if (iter == 0)
        return(0);

    return iter->doc;
}

/**
 * xmlDocWalkerNext:
 * @iter:  the xmlDocWalkerPtr
 *
 * Step to the next sibling of the current node in document order
 *
 * Returns 1 if ok, 0 if there are no more nodes, or -1 in case of error
 */
int
xmlDocWalkerNext(xmlDocWalkerPtr iter)
{
    if ((iter == 0) || (iter->doc == 0))
        return(-1);

    if (iter->state == XML_DWALK_END)
        return(0);

    if (iter->node == 0)
        return xmlDocWalkerStep(iter);

    if (iter->node->next != 0) {
        iter->node = iter->node->next;
        iter->state = XML_DWALK_START;
        return(1);
    }

    return(0);
}
#endif /* LIBXML_WALKER_ENABLED */
