/*
 * "Canonical XML" implementation 
 * http://www.w3.org/TR/xml-c14n
 * 
 * "Exclusive XML Canonicalization" implementation
 * http://www.w3.org/TR/xml-exc-c14n
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "libxml.h"
#ifdef LIBXML_C14N_ENABLED

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/uri.h>
#include <libxml/xmlerror.h>
#include <libxml/globals.h>
#include <libxml/xpathInternals.h>
#include <libxml/c14n.h>

/************************************************************************
 *									*
 *		Some declaration better left private ATM		*
 *									*
 ************************************************************************/

typedef enum {
    XMLC14N_BEFORE_DOCUMENT_ELEMENT = 0,
    XMLC14N_INSIDE_DOCUMENT_ELEMENT = 1,
    XMLC14N_AFTER_DOCUMENT_ELEMENT = 2
} xmlC14NPosition;

typedef struct _xmlC14NCtx {
    /* input parameters */
    xmlDocPtr doc;
    xmlNodeSetPtr visible_nodes;
    int with_comments;
    xmlOutputBufferPtr buf;

    /* position in the XML document */
    xmlC14NPosition pos;
    int parent_is_doc;

    /* exclusive canonicalization */
    int exclusive;
    xmlNodeSetPtr ns_rendered;
    xmlChar **inclusive_ns_prefixes;
} xmlC14NCtx, *xmlC14NCtxPtr;


static int xmlC14NProcessNode(xmlC14NCtxPtr ctx, xmlNodePtr cur);
static int xmlC14NProcessNodeList(xmlC14NCtxPtr ctx, xmlNodePtr cur);
typedef enum {
    XMLC14N_NORMALIZE_ATTR = 0,
    XMLC14N_NORMALIZE_COMMENT = 1,
    XMLC14N_NORMALIZE_PI = 2,
    XMLC14N_NORMALIZE_TEXT = 3
} xmlC14NNormalizationMode;

static xmlChar *xmlC11NNormalizeString(const xmlChar * input,
                                       xmlC14NNormalizationMode mode);

#define 	xmlC11NNormalizeAttr( a ) \
    xmlC11NNormalizeString((a), XMLC14N_NORMALIZE_ATTR)
#define 	xmlC11NNormalizeComment( a ) \
    xmlC11NNormalizeString((a), XMLC14N_NORMALIZE_COMMENT)
#define 	xmlC11NNormalizePI( a )	\
    xmlC11NNormalizeString((a), XMLC14N_NORMALIZE_PI)
#define 	xmlC11NNormalizeText( a ) \
    xmlC11NNormalizeString((a), XMLC14N_NORMALIZE_TEXT)

/************************************************************************
 *									*
 *		The implementation internals				*
 *									*
 ************************************************************************/

/**
 * xmlC14NIsVisible:
 * @ctx: 		the C14N context
 * @node: 		the node to check
 *  		
 * Checks whether the given node is visible. If the XML document normalization
 * was called for the whole document then it is always "true".
 *
 * Returns 1 if the node is visible or 0 otherwise.  
 */

/* todo: make it a define? */
static int
xmlC14NIsVisible(xmlC14NCtxPtr ctx, void *node)
{
    /* 
     * If the input is an XPath node-set, then the node-set must explicitly 
     * contain every node to be rendered to the canonical form.
     */
    if ((ctx->visible_nodes != NULL) &&
        (!xmlXPathNodeSetContains(ctx->visible_nodes, (xmlNodePtr) node)))
    {
        return (0);
    }

    return (1);
}

/**
 * xmlC14NIsXmlNs:
 * @ns: 		the namespace to check
 *  		
 * Checks whether the given namespace is a default "xml:" namespace
 * with href="http://www.w3.org/XML/1998/namespace"
 *
 * Returns 1 if the node is default or 0 otherwise
 */

/* todo: make it a define? */
static int
xmlC14NIsXmlNs(xmlNsPtr ns)
{
    return ((ns != NULL) &&
            (xmlStrEqual(ns->prefix, BAD_CAST "xml")) &&
            (xmlStrEqual(ns->href,
                         BAD_CAST
                         "http://www.w3.org/XML/1998/namespace")));
}

/**
 * xmlExcC14NIsRendered:
 * @ctx			the C14N context 
 * @ns			the namespace to check
 *
 * Checks whether the given namespace was already rendered or not
 *
 * Returns 1 if we already wrote this namespace or 0 otherwise
 */
static int
xmlExcC14NIsRendered(xmlC14NCtxPtr ctx, xmlNsPtr ns)
{
    int i;

    if ((ctx == NULL) || (ctx->ns_rendered == NULL) || (ns == NULL)) {
        return (0);
    }

    if (ctx->ns_rendered->nodeTab != NULL) {
        for (i = ctx->ns_rendered->nodeNr - 1; i >= 0; --i) {
            xmlNsPtr ns1 = (xmlNsPtr) ctx->ns_rendered->nodeTab[i];

            if (xmlStrEqual(ns1->prefix, ns->prefix)) {
                return (xmlStrEqual(ns1->href, ns->href));
            }
        }
    }
    /*
     * if the default namespace xmlns="" is not defined yet then 
     * we do not want to print it out
     */
    return ((xmlStrlen(ns->prefix) == 0) && (xmlStrlen(ns->href) == 0));
}

/**
 * xmlC14NNamespacesCompare:
 * @ns1:		the pointer to first namespace
 * @ns2: 		the pointer to second namespace
 *
 * Compares the namespaces by names (prefixes).
 *
 * Returns -1 if ns1 < ns2, 0 if ns1 == ns2 or 1 if ns1 > ns2.
 */
static int
xmlC14NNamespacesCompare(xmlNsPtr ns1, xmlNsPtr ns2)
{
    if (ns1 == ns2)
        return (0);
    if (ns1 == NULL)
        return (-1);
    if (ns2 == NULL)
        return (1);

    return (xmlStrcmp(ns1->prefix, ns2->prefix));
}


/**
 * xmlC14NPrintNamespaces:
 * @ns:			the pointer to namespace
 * @ctx: 		the C14N context
 *
 * Prints the given namespace to the output buffer from C14N context.
 *
 * Returns 1 on success or 0 on fail.
 */
static int
xmlC14NPrintNamespaces(const xmlNsPtr ns, xmlC14NCtxPtr ctx)
{

    if ((ns == NULL) || (ctx == NULL)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NPrintNamespace: namespace or context pointer is null\n");
#endif
        return 0;
    }

    if (ns->prefix != NULL) {
        xmlOutputBufferWriteString(ctx->buf, " xmlns:");
        xmlOutputBufferWriteString(ctx->buf, (const char *) ns->prefix);
        xmlOutputBufferWriteString(ctx->buf, "=\"");
    } else {
        xmlOutputBufferWriteString(ctx->buf, " xmlns=\"");
    }
    xmlOutputBufferWriteString(ctx->buf, (const char *) ns->href);
    xmlOutputBufferWriteString(ctx->buf, "\"");
    return (1);
}

/**
 * xmlC14NProcessNamespacesAxis:
 * @ctx: 		the C14N context
 * @node:		the current node
 *
 * Prints out canonical namespace axis of the current node to the
 * buffer from C14N context as follows 
 *
 * Canonical XML v 1.0 (http://www.w3.org/TR/xml-c14n)
 *
 * Namespace Axis
 * Consider a list L containing only namespace nodes in the 
 * axis and in the node-set in lexicographic order (ascending). To begin 
 * processing L, if the first node is not the default namespace node (a node 
 * with no namespace URI and no local name), then generate a space followed 
 * by xmlns="" if and only if the following conditions are met:
 *    - the element E that owns the axis is in the node-set
 *    - The nearest ancestor element of E in the node-set has a default 
 *	    namespace node in the node-set (default namespace nodes always 
 *      have non-empty values in XPath)
 * The latter condition eliminates unnecessary occurrences of xmlns="" in 
 * the canonical form since an element only receives an xmlns="" if its 
 * default namespace is empty and if it has an immediate parent in the 
 * canonical form that has a non-empty default namespace. To finish 
 * processing  L, simply process every namespace node in L, except omit 
 * namespace node with local name xml, which defines the xml prefix, 
 * if its string value is http://www.w3.org/XML/1998/namespace.
 *
 * Exclusive XML Canonicalization v 1.0 (http://www.w3.org/TR/xml-exc-c14n)
 * Canonical XML applied to a document subset requires the search of the 
 * ancestor nodes of each orphan element node for attributes in the xml 
 * namespace, such as xml:lang and xml:space. These are copied into the 
 * element node except if a declaration of the same attribute is already 
 * in the attribute axis of the element (whether or not it is included in 
 * the document subset). This search and copying are omitted from the 
 * Exclusive XML Canonicalization method.
 *
 * Returns 0 on success or -1 on fail.
 */
static int
xmlC14NProcessNamespacesAxis(xmlC14NCtxPtr ctx, xmlNodePtr cur)
{
    xmlNsPtr ns;
    xmlListPtr list;
    xmlNodePtr visible_parent;
    xmlNodePtr node;
    xmlNsPtr prev;
    
    if ((ctx == NULL) || (cur == NULL) || (cur->type != XML_ELEMENT_NODE)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessNamespacesAxis: Null context or node pointer or type != XML_ELEMENT_NODE.\n");
#endif
        return (-1);
    }

    /*
     * Create a sorted list to store element namespaces
     */
    list =
        xmlListCreate(NULL, (xmlListDataCompare) xmlC14NNamespacesCompare);
    if (list == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessNamespacesAxis: list creation failed\n");
#endif
        return (-1);
    }

    /* find nearest visible parent */
    visible_parent = cur->parent;
    while ((visible_parent != NULL) &&
           (!xmlC14NIsVisible(ctx, visible_parent))) {
        visible_parent = visible_parent->parent;
    }

    /* 
     * todo: the libxml XPath implementation does not create 
     * nodes for all namespaces known to the node (i.e. for namespaces
     * defined in node parents). By this we need to now walk thru 
     * all namespace in current node and all invisible ancesstors
     */
    node = cur;
    while (cur != visible_parent) {
        for (ns = cur->nsDef; ns != NULL; ns = ns->next) {
            /* 
             * first of all ignore default "xml" namespace and 
             * already included namespace
             */
            if ((xmlC14NIsXmlNs(ns)) || (xmlListSearch(list, ns) != NULL)) {
                continue;
            }
	    prev = xmlSearchNs(ctx->doc, node, ns->prefix);
	    if(prev != ns) {
		/* we already processed a namespace with this name */
		continue;
	    }

            /*
             * Lookup nearest namespace after visible parent having
             * the same prefix. Namespace included if and only if one of 
             * the following:
             *   - another namespace having the same prefix but 
             *   different value found or
             *   - there is no namespaces having the same prefix and  
             *   it is not a default xmlns="" namespace (empty prefix 
             *   and empty href)
             */
            prev = xmlSearchNs(ctx->doc, visible_parent, ns->prefix);
            if ((prev == NULL) && ((xmlStrlen(ns->prefix) > 0) ||
                                   (xmlStrlen(ns->href) > 0))) {
                xmlListInsert(list, ns);
            } else if ((prev != NULL)
                       && (!xmlStrEqual(ns->href, prev->href))) {
                xmlListInsert(list, ns);
            }
        }
        cur = cur->parent;
    }

    /* 
     * print out all elements from list 
     */
    xmlListWalk(list, (xmlListWalker) xmlC14NPrintNamespaces,
                (const void *) ctx);

    /* 
     * Cleanup
     */
    xmlListDelete(list);
    return (0);
}

/**
 * xmlExcC14NProcessNamespacesAxis:
 * @ctx: 		the C14N context
 * @node:		the current node
 *
 * Prints out exclusive canonical namespace axis of the current node to the
 * buffer from C14N context as follows 
 *
 * Exclusive XML Canonicalization
 * http://www.w3.org/TR/xml-exc-c14n
 *
 * If the element node is in the XPath subset then output the node in 
 * accordance with Canonical XML except for namespace nodes which are 
 * rendered as follows:
 *
 * 1. Render each namespace node iff:
 *    * it is visibly utilized by the immediate parent element or one of 
 *      its attributes, or is present in InclusiveNamespaces PrefixList, and
 *    * its prefix and value do not appear in ns_rendered. ns_rendered is 
 *      obtained by popping the state stack in order to obtain a list of 
 *      prefixes and their values which have already been rendered by 
 *      an output ancestor of the namespace node's parent element.
 * 2. Append the rendered namespace node to the list ns_rendered of namespace 
 * nodes rendered by output ancestors. Push ns_rendered on state stack and 
 * recurse.
 * 3. After the recursion returns, pop thestate stack.
 *
 *
 * Returns 0 on success or -1 on fail.
 */
static int
xmlExcC14NProcessNamespacesAxis(xmlC14NCtxPtr ctx, xmlNodePtr cur)
{
    xmlListPtr list;
    xmlAttrPtr attr;
    xmlNsPtr ns;

    if ((ctx == NULL) || (cur == NULL) || (cur->type != XML_ELEMENT_NODE)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlExcC14NProcessNamespacesAxis: Null context or node pointer or type != XML_ELEMENT_NODE.\n");
#endif
        return (-1);
    }

    if ((!ctx->exclusive) || (ctx->ns_rendered == NULL)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlExcC14NProcessNamespacesAxis: called for non-exclusive canonization or rendered stack is NULL.\n");
#endif
        return (-1);

    }

    /*
     * Create a sorted list to store element namespaces
     */
    list =
        xmlListCreate(NULL, (xmlListDataCompare) xmlC14NNamespacesCompare);
    if (list == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlExcC14NProcessNamespacesAxis: list creation failed\n");
#endif
        return (-1);
    }

    /*
     * First of all, add all namespaces required by current node
     * (i.e. node namespace and all attribute namespaces)
     * todo: do we need to check for default "xml:" namespace
     */
    ns = (cur->ns != NULL) ? cur->ns : xmlSearchNs(ctx->doc, cur, NULL);
    if ((ns != NULL) && (!xmlC14NIsXmlNs(ns)) &&
        (xmlListSearch(list, ns) == NULL)) {
        if (!xmlExcC14NIsRendered(ctx, ns)) {
            xmlListInsert(list, ns);
            xmlXPathNodeSetAdd(ctx->ns_rendered, (xmlNodePtr) ns);
        }
    }
    attr = cur->properties;
    while (attr != NULL) {
        /* 
         * we need to check that attribute is visible and has non
         * default namespace (XML Namespaces: "default namespaces 
	   * do not apply directly to attributes")	 
         */
        if ((attr->ns != NULL) && xmlC14NIsVisible(ctx, attr) && 
        			 (xmlListSearch(list, attr->ns) == NULL) && 
				 (!xmlExcC14NIsRendered(ctx, attr->ns))) {
            xmlListInsert(list, attr->ns);
            xmlXPathNodeSetAdd(ctx->ns_rendered, (xmlNodePtr) attr->ns);
        }
        attr = attr->next;
    }

    /* 
     * Next add all inclusive namespaces if needed. 
     */
    if (ctx->inclusive_ns_prefixes != NULL) {
        int i;
        xmlChar *prefix;

        for (i = 0; ctx->inclusive_ns_prefixes[i] != NULL; ++i) {
            prefix = ctx->inclusive_ns_prefixes[i];
            /*
             * Special values for namespace with empty prefix
             */
            if (xmlStrEqual(prefix, BAD_CAST "#default")
                || xmlStrEqual(prefix, BAD_CAST "")) {
                prefix = NULL;
            }
            ns = xmlSearchNs(ctx->doc, cur, prefix);
            if ((ns != NULL) && (!xmlC14NIsXmlNs(ns))) {
                if (xmlListSearch(list, ns) == NULL &&
                    !xmlExcC14NIsRendered(ctx, ns)) {
                    xmlListInsert(list, ns);
                    xmlXPathNodeSetAdd(ctx->ns_rendered, (xmlNodePtr) ns);
                }
            }
        }
    }

    /* 
     * print out all elements from list 
     */
    xmlListWalk(list, (xmlListWalker) xmlC14NPrintNamespaces,
                (const void *) ctx);

    /* 
     * Cleanup
     */
    xmlListDelete(list);
    return (0);
}


/**
 * xmlC14NAttrsCompare:
 * @attr1:		the pointer to first attr
 * @attr2: 		the pointer to second attr
 *
 * Prints the given attribute to the output buffer from C14N context.
 *
 * Returns -1 if attr1 < attr2, 0 if attr1 == attr2 or 1 if attr1 > attr2.
 */
static int
xmlC14NAttrsCompare(xmlAttrPtr attr1, xmlAttrPtr attr2)
{
    int ret = 0;

    /*
     * Simple cases
     */
    if (attr1 == attr2)
        return (0);
    if (attr1 == NULL)
        return (-1);
    if (attr2 == NULL)
        return (1);
    if (attr1->ns == attr2->ns) {
        return (xmlStrcmp(attr1->name, attr2->name));
    }

    /* 
     * Attributes in the default namespace are first
     * because the default namespace is not applied to
     * unqualified attributes
     */
    if (attr1->ns == NULL)
        return (-1);
    if (attr2->ns == NULL)
        return (1);
    if (attr1->ns->prefix == NULL)
        return (-1);
    if (attr2->ns->prefix == NULL)
        return (1);

    ret = xmlStrcmp(attr1->ns->href, attr2->ns->href);
    if (ret == 0) {
        ret = xmlStrcmp(attr1->name, attr2->name);
    }
    return (ret);
}


/**
 * xmlC14NPrintAttrs:
 * @attr:		the pointer to attr
 * @ctx: 		the C14N context
 *
 * Prints out canonical attribute urrent node to the
 * buffer from C14N context as follows 
 *
 * Canonical XML v 1.0 (http://www.w3.org/TR/xml-c14n)
 *
 * Returns 1 on success or 0 on fail.
 */
static int
xmlC14NPrintAttrs(const xmlAttrPtr attr, xmlC14NCtxPtr ctx)
{
    xmlChar *value;
    xmlChar *buffer;

    if ((attr == NULL) || (ctx == NULL)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NPrintAttrs: attr == NULL or ctx == NULL\n");
#endif
        return (0);
    }

    xmlOutputBufferWriteString(ctx->buf, " ");
    if (attr->ns != NULL && xmlStrlen(attr->ns->prefix) > 0) {
        xmlOutputBufferWriteString(ctx->buf,
                                   (const char *) attr->ns->prefix);
        xmlOutputBufferWriteString(ctx->buf, ":");
    }
    xmlOutputBufferWriteString(ctx->buf, (const char *) attr->name);
    xmlOutputBufferWriteString(ctx->buf, "=\"");

    value = xmlNodeListGetString(attr->doc, attr->children, 1);
    /* todo: should we log an error if value==NULL ? */
    if (value != NULL) {
        buffer = xmlC11NNormalizeAttr(value);
        xmlFree(value);
        if (buffer != NULL) {
            xmlOutputBufferWriteString(ctx->buf, (const char *) buffer);
            xmlFree(buffer);
        } else {
#ifdef DEBUG_C14N
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NPrintAttrs: xmlC11NNormalizeAttr failed\n");
#endif
            return (0);
        }
    }
    xmlOutputBufferWriteString(ctx->buf, "\"");
    return (1);
}

/**
 * xmlC14NProcessAttrsAxis:
 * @ctx: 		the C14N context
 * @cur:		the current node
 *
 * Prints out canonical attribute axis of the current node to the
 * buffer from C14N context as follows 
 *
 * Canonical XML v 1.0 (http://www.w3.org/TR/xml-c14n)
 *
 * Attribute Axis 
 * In lexicographic order (ascending), process each node that 
 * is in the element's attribute axis and in the node-set.
 * 
 * The processing of an element node E MUST be modified slightly 
 * when an XPath node-set is given as input and the element's 
 * parent is omitted from the node-set.
 *
 *
 * Exclusive XML Canonicalization v 1.0 (http://www.w3.org/TR/xml-exc-c14n)
 *
 * Canonical XML applied to a document subset requires the search of the 
 * ancestor nodes of each orphan element node for attributes in the xml 
 * namespace, such as xml:lang and xml:space. These are copied into the 
 * element node except if a declaration of the same attribute is already 
 * in the attribute axis of the element (whether or not it is included in 
 * the document subset). This search and copying are omitted from the 
 * Exclusive XML Canonicalization method.
 *
 * Returns 0 on success or -1 on fail.
 */
static int
xmlC14NProcessAttrsAxis(xmlC14NCtxPtr ctx, xmlNodePtr cur)
{
    xmlAttrPtr attr;
    xmlListPtr list;

    if ((ctx == NULL) || (cur == NULL) || (cur->type != XML_ELEMENT_NODE)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessAttrsAxis: Null context or node pointer or type != XML_ELEMENT_NODE.\n");
#endif
        return (-1);
    }

    /*
     * Create a sorted list to store element attributes
     */
    list = xmlListCreate(NULL, (xmlListDataCompare) xmlC14NAttrsCompare);
    if (list == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessAttrsAxis: list creation failed\n");
#endif
        return (-1);
    }

    /* 
     * Add all visible attributes from current node. 
     */
    attr = cur->properties;
    while (attr != NULL) {
        /* check that attribute is visible */
        if (xmlC14NIsVisible(ctx, attr)) {
            xmlListInsert(list, attr);
        }
        attr = attr->next;
    }

    /* 
     * include attributes in "xml" namespace defined in ancestors
     * (only for non-exclusive XML Canonicalization)
     */
    if ((!ctx->exclusive) && (cur->parent != NULL)
        && (!xmlC14NIsVisible(ctx, cur->parent))) {
        /*
         * If XPath node-set is not specified then the parent is always 
         * visible!
         */
        cur = cur->parent;
        while (cur != NULL) {
            attr = cur->properties;
            while (attr != NULL) {
                if ((attr->ns != NULL)
                    && (xmlStrEqual(attr->ns->prefix, BAD_CAST "xml"))) {
                    if (xmlListSearch(list, attr) == NULL) {
                        xmlListInsert(list, attr);
                    }
                }
                attr = attr->next;
            }
            cur = cur->parent;
        }
    }

    /* 
     * print out all elements from list 
     */
    xmlListWalk(list, (xmlListWalker) xmlC14NPrintAttrs,
                (const void *) ctx);

    /* 
     * Cleanup
     */
    xmlListDelete(list);
    return (0);
}

/** 
 * xmlC14NCheckForRelativeNamespaces:
 * @ctx:		the C14N context
 * @cur:		the current element node
 *
 * Checks that current element node has no relative namespaces defined
 *
 * Returns 0 if the node has no relative namespaces or -1 otherwise.
 */
static int
xmlC14NCheckForRelativeNamespaces(xmlC14NCtxPtr ctx, xmlNodePtr cur)
{
    xmlNsPtr ns;

    if ((ctx == NULL) || (cur == NULL) || (cur->type != XML_ELEMENT_NODE)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NCheckForRelativeNamespaces: Null context or node pointer or type != XML_ELEMENT_NODE.\n");
#endif
        return (-1);
    }

    ns = cur->nsDef;
    while (ns != NULL) {
        if (xmlStrlen(ns->href) > 0) {
            xmlURIPtr uri;

            uri = xmlParseURI((const char *) ns->href);
            if (uri == NULL) {
#ifdef DEBUG_C14N
                xmlGenericError(xmlGenericErrorContext,
                                "xmlC14NCheckForRelativeNamespaces: unable to parse uri=\"%s\".\n",
                                ns->href);
#endif
                return (-1);
            }
            if (xmlStrlen((const xmlChar *) uri->scheme) == 0) {
                xmlFreeURI(uri);
                return (-1);
            }
            if ((!xmlStrEqual
                 ((const xmlChar *) uri->scheme, BAD_CAST "urn"))
                && (xmlStrlen((const xmlChar *) uri->server) == 0)) {
                xmlFreeURI(uri);
                return (-1);
            }
            xmlFreeURI(uri);
        }
        ns = ns->next;
    }
    return (0);
}

/**
 * xmlC14NProcessElementNode:
 * @ctx: 		the pointer to C14N context object
 * @cur:		the node to process
 *  		
 * Canonical XML v 1.0 (http://www.w3.org/TR/xml-c14n)
 *
 * Element Nodes
 * If the element is not in the node-set, then the result is obtained 
 * by processing the namespace axis, then the attribute axis, then 
 * processing the child nodes of the element that are in the node-set 
 * (in document order). If the element is in the node-set, then the result 
 * is an open angle bracket (<), the element QName, the result of 
 * processing the namespace axis, the result of processing the attribute 
 * axis, a close angle bracket (>), the result of processing the child 
 * nodes of the element that are in the node-set (in document order), an 
 * open angle bracket, a forward slash (/), the element QName, and a close 
 * angle bracket.
 *
 * Returns non-negative value on success or negative value on fail
 */
static int
xmlC14NProcessElementNode(xmlC14NCtxPtr ctx, xmlNodePtr cur, int visible)
{
    int ret;
    int ns_rendered_pos = 0;
    int parent_is_doc = 0;

    if ((ctx == NULL) || (cur == NULL) || (cur->type != XML_ELEMENT_NODE)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessElementNode: Null context or node pointer or type != XML_ELEMENT_NODE.\n");
#endif
        return (-1);
    }

    /* 
     * Check relative relative namespaces:
     * implementations of XML canonicalization MUST report an operation
     * failure on documents containing relative namespace URIs.
     */
    if (xmlC14NCheckForRelativeNamespaces(ctx, cur) < 0) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessElementNode: xmlC14NCheckForRelativeNamespaces failed.\n");
#endif
        return (-1);
    }


    /* 
     * Save ns_rendered stack position for exclusive 
     * processing
     */
    if ((ctx->exclusive) && (ctx->ns_rendered != NULL)) {
        ns_rendered_pos = ctx->ns_rendered->nodeNr;
    }

    if (visible) {	
        if (ctx->parent_is_doc) {
	    /* save this flag into the stack */
	    parent_is_doc = ctx->parent_is_doc;
	    ctx->parent_is_doc = 0;
            ctx->pos = XMLC14N_INSIDE_DOCUMENT_ELEMENT;
        }
        xmlOutputBufferWriteString(ctx->buf, "<");

        if ((cur->ns != NULL) && (xmlStrlen(cur->ns->prefix) > 0)) {
            xmlOutputBufferWriteString(ctx->buf,
                                       (const char *) cur->ns->prefix);
            xmlOutputBufferWriteString(ctx->buf, ":");
        }
        xmlOutputBufferWriteString(ctx->buf, (const char *) cur->name);

        if (ctx->exclusive) {
            ret = xmlExcC14NProcessNamespacesAxis(ctx, cur);
        } else {
            ret = xmlC14NProcessNamespacesAxis(ctx, cur);
        }
        if (ret < 0) {
#ifdef DEBUG_C14N
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessElementNode: xmlC14NProcessNamespacesAxis failed.\n");
#endif
            return (-1);
        }

        ret = xmlC14NProcessAttrsAxis(ctx, cur);
        if (ret < 0) {
#ifdef DEBUG_C14N
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessElementNode: xmlC14NProcessAttrsAxis failed.\n");
#endif
            return (-1);
        }

        xmlOutputBufferWriteString(ctx->buf, ">");
    }
    if (cur->children != NULL) {
        ret = xmlC14NProcessNodeList(ctx, cur->children);
        if (ret < 0) {
#ifdef DEBUG_C14N
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessElementNode: xmlC14NProcessNodeList failed.\n");
#endif
            return (-1);
        }
    }
    if (visible) {
        xmlOutputBufferWriteString(ctx->buf, "</");
        if ((cur->ns != NULL) && (xmlStrlen(cur->ns->prefix) > 0)) {
            xmlOutputBufferWriteString(ctx->buf,
                                       (const char *) cur->ns->prefix);
            xmlOutputBufferWriteString(ctx->buf, ":");
        }
        xmlOutputBufferWriteString(ctx->buf, (const char *) cur->name);
        xmlOutputBufferWriteString(ctx->buf, ">");
        if (parent_is_doc) {
	    /* restore this flag from the stack for next node */
            ctx->parent_is_doc = parent_is_doc;
	    ctx->pos = XMLC14N_AFTER_DOCUMENT_ELEMENT;
        }
    }

    /* 
     * Restore ns_rendered stack position for exclusive 
     * processing
     */
    if ((ctx->exclusive) && (ctx->ns_rendered != NULL)) {
        ctx->ns_rendered->nodeNr = ns_rendered_pos;
    }
    return (0);
}

/**
 * xmlC14NProcessNode:
 * @ctx: 		the pointer to C14N context object
 * @cur:		the node to process
 *  		
 * Processes the given node
 *
 * Returns non-negative value on success or negative value on fail
 */
static int
xmlC14NProcessNode(xmlC14NCtxPtr ctx, xmlNodePtr cur)
{
    int ret = 0;
    int visible;

    if ((ctx == NULL) || (cur == NULL)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessNode: Null context or node pointer.\n");
#endif
        return (-1);
    }

    visible = xmlC14NIsVisible(ctx, cur);
    switch (cur->type) {
        case XML_ELEMENT_NODE:
            ret = xmlC14NProcessElementNode(ctx, cur, visible);
            break;
        case XML_CDATA_SECTION_NODE:
        case XML_TEXT_NODE:
            /*
             * Text Nodes
             * the string value, except all ampersands are replaced 
             * by &amp;, all open angle brackets (<) are replaced by &lt;, all closing 
             * angle brackets (>) are replaced by &gt;, and all #xD characters are 
             * replaced by &#xD;.
             */
            /* cdata sections are processed as text nodes */
            /* todo: verify that cdata sections are included in XPath nodes set */
            if ((visible) && (cur->content != NULL)) {
                xmlChar *buffer;

                buffer = xmlC11NNormalizeText(cur->content);
                if (buffer != NULL) {
                    xmlOutputBufferWriteString(ctx->buf,
                                               (const char *) buffer);
                    xmlFree(buffer);
                } else {
#ifdef DEBUG_C14N
                    xmlGenericError(xmlGenericErrorContext,
                                    "xmlC14NProcessNode: xmlC11NNormalizeText() failed\n");
#endif
                    return (-1);
                }
            }
            break;
        case XML_PI_NODE:
            /* 
             * Processing Instruction (PI) Nodes- 
             * The opening PI symbol (<?), the PI target name of the node, 
             * a leading space and the string value if it is not empty, and 
             * the closing PI symbol (?>). If the string value is empty, 
             * then the leading space is not added. Also, a trailing #xA is 
             * rendered after the closing PI symbol for PI children of the 
             * root node with a lesser document order than the document 
             * element, and a leading #xA is rendered before the opening PI 
             * symbol of PI children of the root node with a greater document 
             * order than the document element.
             */
            if (visible) {
                if (ctx->pos == XMLC14N_AFTER_DOCUMENT_ELEMENT) {
                    xmlOutputBufferWriteString(ctx->buf, "\x0A<?");
                } else {
                    xmlOutputBufferWriteString(ctx->buf, "<?");
                }

                xmlOutputBufferWriteString(ctx->buf,
                                           (const char *) cur->name);
                if ((cur->content != NULL) && (*(cur->content) != '\0')) {
                    xmlChar *buffer;

                    xmlOutputBufferWriteString(ctx->buf, " ");

                    /* todo: do we need to normalize pi? */
                    buffer = xmlC11NNormalizePI(cur->content);
                    if (buffer != NULL) {
                        xmlOutputBufferWriteString(ctx->buf,
                                                   (const char *) buffer);
                        xmlFree(buffer);
                    } else {
#ifdef DEBUG_C14N
                        xmlGenericError(xmlGenericErrorContext,
                                        "xmlC14NProcessNode: xmlC11NNormalizePI() failed\n");
#endif
                        return (-1);
                    }
                }

                if (ctx->pos == XMLC14N_BEFORE_DOCUMENT_ELEMENT) {
                    xmlOutputBufferWriteString(ctx->buf, "?>\x0A");
                } else {
                    xmlOutputBufferWriteString(ctx->buf, "?>");
                }
            }
            break;
        case XML_COMMENT_NODE:
            /*
             * Comment Nodes
             * Nothing if generating canonical XML without  comments. For 
             * canonical XML with comments, generate the opening comment 
             * symbol (<!--), the string value of the node, and the 
             * closing comment symbol (-->). Also, a trailing #xA is rendered 
             * after the closing comment symbol for comment children of the 
             * root node with a lesser document order than the document 
             * element, and a leading #xA is rendered before the opening 
             * comment symbol of comment children of the root node with a 
             * greater document order than the document element. (Comment 
             * children of the root node represent comments outside of the 
             * top-level document element and outside of the document type 
             * declaration).
             */
            if (visible && ctx->with_comments) {
                if (ctx->pos == XMLC14N_AFTER_DOCUMENT_ELEMENT) {
                    xmlOutputBufferWriteString(ctx->buf, "\x0A<!--");
                } else {
                    xmlOutputBufferWriteString(ctx->buf, "<!--");
                }

                if (cur->content != NULL) {
                    xmlChar *buffer;

                    /* todo: do we need to normalize comment? */
                    buffer = xmlC11NNormalizeComment(cur->content);
                    if (buffer != NULL) {
                        xmlOutputBufferWriteString(ctx->buf,
                                                   (const char *) buffer);
                        xmlFree(buffer);
                    } else {
#ifdef DEBUG_C14N
                        xmlGenericError(xmlGenericErrorContext,
                                        "xmlC14NProcessNode: xmlC11NNormalizeComment() failed\n");
#endif
                        return (-1);
                    }
                }

                if (ctx->pos == XMLC14N_BEFORE_DOCUMENT_ELEMENT) {
                    xmlOutputBufferWriteString(ctx->buf, "-->\x0A");
                } else {
                    xmlOutputBufferWriteString(ctx->buf, "-->");
                }
            }
            break;
        case XML_DOCUMENT_NODE:
        case XML_DOCUMENT_FRAG_NODE:   /* should be processed as document? */
        case XML_DOCB_DOCUMENT_NODE:   /* should be processed as document? */
        case XML_HTML_DOCUMENT_NODE:   /* should be processed as document? */
            if (cur->children != NULL) {
                ctx->pos = XMLC14N_BEFORE_DOCUMENT_ELEMENT;
                ctx->parent_is_doc = 1;
                ret = xmlC14NProcessNodeList(ctx, cur->children);
            }
            break;

        case XML_ATTRIBUTE_NODE:
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessNode: XML_ATTRIBUTE_NODE is illegal here\n");
            return (-1);
        case XML_NAMESPACE_DECL:
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessNode: XML_NAMESPACE_DECL is illegal here\n");
            return (-1);
        case XML_ENTITY_REF_NODE:
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessNode: XML_ENTITY_REF_NODE is illegal here\n");
            return (-1);
        case XML_ENTITY_NODE:
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessNode: XML_ENTITY_NODE is illegal here\n");
            return (-1);

        case XML_DOCUMENT_TYPE_NODE:
        case XML_NOTATION_NODE:
        case XML_DTD_NODE:
        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
        case XML_XINCLUDE_START:
        case XML_XINCLUDE_END:
            /* 
             * should be ignored according to "W3C Canonical XML" 
             */
            break;
        default:
#ifdef DEBUG_C14N
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NProcessNode: unknown node type = %d\n",
                            cur->type);
#endif
            return (-1);
    }

    return (ret);
}

/**
 * xmlC14NProcessNodeList:
 * @ctx: 		the pointer to C14N context object
 * @cur:		the node to start from
 *  		
 * Processes all nodes in the row starting from cur.
 *
 * Returns non-negative value on success or negative value on fail
 */
static int
xmlC14NProcessNodeList(xmlC14NCtxPtr ctx, xmlNodePtr cur)
{
    int ret;

    if (ctx == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NProcessNodeList: Null context pointer.\n");
#endif
        return (-1);
    }

    for (ret = 0; cur != NULL && ret >= 0; cur = cur->next) {
        ret = xmlC14NProcessNode(ctx, cur);
    }
    return (ret);
}


/**
 * xmlC14NFreeCtx:
 * @ctx: the pointer to C14N context object
 * 		
 * Cleanups the C14N context object.
 */

static void
xmlC14NFreeCtx(xmlC14NCtxPtr ctx)
{
    if (ctx == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NFreeCtx: ctx == NULL\n");
#endif
        return;
    }

    if (ctx->ns_rendered != NULL) {
        xmlXPathFreeNodeSet(ctx->ns_rendered);
    }
    xmlFree(ctx);
}

/**
 * xmlC14NNewCtx:
 * @doc: 		the XML document for canonization
 * @nodes: 		the nodes set to be included in the canonized image
 *      		or NULL if all document nodes should be included
 * @exclusive:		the exclusive flag (0 - non-exclusive canonicalization;
 *			otherwise - exclusive canonicalization)
 * @inclusive_ns_prefixe the list of inclusive namespace prefixes 
 *			ended with a NULL or NULL if there is no
 *			inclusive namespaces (only for exclusive 
 *			canonicalization)
 * @with_comments: 	include comments in the result (!=0) or not (==0)
 * @buf: 		the output buffer to store canonical XML; this 
 *			buffer MUST have encoder==NULL because C14N requires
 *			UTF-8 output
 *  		
 * Creates new C14N context object to store C14N parameters.
 *
 * Returns pointer to newly created object (success) or NULL (fail)
 */
static xmlC14NCtxPtr
xmlC14NNewCtx(xmlDocPtr doc, xmlNodeSetPtr nodes,
              int exclusive, xmlChar ** inclusive_ns_prefixes,
              int with_comments, xmlOutputBufferPtr buf)
{
    xmlC14NCtxPtr ctx;

    if ((doc == NULL) || (buf == NULL)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NNewCtx: pointer to document or output buffer is NULL\n");
#endif
        return (NULL);
    }

    /*
     *  Validate the encoding output buffer encoding
     */
    if (buf->encoder != NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NNewCtx: output buffer encoder != NULL but C14N requires UTF8 output\n");
        return (NULL);
    }

    /*
     *  Validate the XML document encoding value, if provided.
     */
    if (doc->charset != XML_CHAR_ENCODING_UTF8) {
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NNewCtx: source document not in UTF8\n");
        return (NULL);
    }

    /*
     * Allocate a new xmlC14NCtxPtr and fill the fields.
     */
    ctx = (xmlC14NCtxPtr) xmlMalloc(sizeof(xmlC14NCtx));
    if (ctx == NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NNewCtx: malloc failed\n");
        return (NULL);
    }
    memset(ctx, 0, sizeof(xmlC14NCtx));

    /*
     * initialize C14N context
     */
    ctx->doc = doc;
    ctx->with_comments = with_comments;
    ctx->visible_nodes = nodes;
    ctx->buf = buf;
    ctx->parent_is_doc = 1;
    ctx->pos = XMLC14N_BEFORE_DOCUMENT_ELEMENT;

    /*
     * Set "exclusive" flag, create a nodes set for namespaces
     * stack and remember list of incluseve prefixes
     */
    if (exclusive) {
        ctx->exclusive = 1;
        ctx->ns_rendered = xmlXPathNodeSetCreate(NULL);
        ctx->inclusive_ns_prefixes = inclusive_ns_prefixes;
    }
    return (ctx);
}

/**
 * xmlC14NDocSaveTo:
 * @doc: 		the XML document for canonization
 * @nodes: 		the nodes set to be included in the canonized image
 *      		or NULL if all document nodes should be included
 * @exclusive:		the exclusive flag (0 - non-exclusive canonicalization;
 *			otherwise - exclusive canonicalization)
 * @inclusive_ns_prefixes: the list of inclusive namespace prefixes 
 *			ended with a NULL or NULL if there is no
 *			inclusive namespaces (only for exclusive 
 *			canonicalization, ignored otherwise)
 * @with_comments: 	include comments in the result (!=0) or not (==0)
 * @buf: 		the output buffer to store canonical XML; this 
 *			buffer MUST have encoder==NULL because C14N requires
 *			UTF-8 output
 *  		
 * Dumps the canonized image of given XML document into the provided buffer.
 * For details see "Canonical XML" (http://www.w3.org/TR/xml-c14n) or
 * "Exclusive XML Canonicalization" (http://www.w3.org/TR/xml-exc-c14n)
 *
 * Returns non-negative value on success or a negative value on fail  
 */
int
xmlC14NDocSaveTo(xmlDocPtr doc, xmlNodeSetPtr nodes,
                 int exclusive, xmlChar ** inclusive_ns_prefixes,
                 int with_comments, xmlOutputBufferPtr buf)
{
    xmlC14NCtxPtr ctx;
    int ret;

    if ((buf == NULL) || (doc == NULL)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocSaveTo: null return buffer or doc pointer\n");
#endif
        return (-1);
    }

    /*
     *  Validate the encoding output buffer encoding
     */
    if (buf->encoder != NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocSaveTo: output buffer encoder != NULL but C14N requires UTF8 output\n");
        return (-1);
    }

    ctx = xmlC14NNewCtx(doc, nodes, exclusive, inclusive_ns_prefixes,
                        with_comments, buf);
    if (ctx == NULL) {
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocSaveTo: unable to create C14N context\n");
        return (-1);
    }



    /*  
     * Root Node
     * The root node is the parent of the top-level document element. The 
     * result of processing each of its child nodes that is in the node-set 
     * in document order. The root node does not generate a byte order mark, 
     * XML declaration, nor anything from within the document type 
     * declaration.
     */
    if (doc->children != NULL) {
        ret = xmlC14NProcessNodeList(ctx, doc->children);
        if (ret < 0) {
#ifdef DEBUG_C14N
            xmlGenericError(xmlGenericErrorContext,
                            "xmlC14NDocSaveTo: process childrens' list failed.\n");
#endif
            xmlC14NFreeCtx(ctx);
            return (-1);
        }
    }

    /*
     * Flush buffer to get number of bytes written
     */
    ret = xmlOutputBufferFlush(buf);
    if (ret < 0) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocSaveTo: buffer flush failed.\n");
#endif
        xmlC14NFreeCtx(ctx);
        return (-1);
    }

    /* 
     * Cleanup
     */
    xmlC14NFreeCtx(ctx);
    return (ret);
}

/**
 * xmlC14NDocDumpMemory:
 * @doc: 		the XML document for canonization
 * @nodes: 		the nodes set to be included in the canonized image
 *      		or NULL if all document nodes should be included
 * @exclusive:		the exclusive flag (0 - non-exclusive canonicalization;
 *			otherwise - exclusive canonicalization)
 * @inclusive_ns_prefixes: the list of inclusive namespace prefixes 
 *			ended with a NULL or NULL if there is no
 *			inclusive namespaces (only for exclusive 
 *			canonicalization, ignored otherwise)
 * @with_comments: 	include comments in the result (!=0) or not (==0)
 * @doc_txt_ptr: 	the memory pointer for allocated canonical XML text;
 *			the caller of this functions is responsible for calling
 *			xmlFree() to free allocated memory 
 *  		
 * Dumps the canonized image of given XML document into memory.
 * For details see "Canonical XML" (http://www.w3.org/TR/xml-c14n) or
 * "Exclusive XML Canonicalization" (http://www.w3.org/TR/xml-exc-c14n)
 *
 * Returns the number of bytes written on success or a negative value on fail  
 */
int
xmlC14NDocDumpMemory(xmlDocPtr doc, xmlNodeSetPtr nodes,
                     int exclusive, xmlChar ** inclusive_ns_prefixes,
                     int with_comments, xmlChar ** doc_txt_ptr)
{
    int ret;
    xmlOutputBufferPtr buf;

    if (doc_txt_ptr == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocDumpMemory:  null return buffer pointer\n");
#endif
        return (-1);
    }

    *doc_txt_ptr = NULL;

    /*
     * create memory buffer with UTF8 (default) encoding 
     */
    buf = xmlAllocOutputBuffer(NULL);
    if (buf == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocDumpMemory: failed to allocate output buffer.\n");
#endif
        return (-1);
    }

    /*
     * canonize document and write to buffer
     */
    ret = xmlC14NDocSaveTo(doc, nodes, exclusive, inclusive_ns_prefixes,
                           with_comments, buf);
    if (ret < 0) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocDumpMemory: xmlC14NDocSaveTo failed.\n");
#endif
        (void) xmlOutputBufferClose(buf);
        return (-1);
    }

    ret = buf->buffer->use;
    if (ret > 0) {
        *doc_txt_ptr = xmlStrndup(buf->buffer->content, ret);
    }
    (void) xmlOutputBufferClose(buf);

    if ((*doc_txt_ptr == NULL) && (ret > 0)) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocDumpMemory: failed to allocate memory for document text representation\n");
#endif
        return (-1);
    }
    return (ret);
}

/**
 * xmlC14NDocSave:
 * @doc: 		the XML document for canonization
 * @nodes: 		the nodes set to be included in the canonized image
 *      		or NULL if all document nodes should be included
 * @exclusive:		the exclusive flag (0 - non-exclusive canonicalization;
 *			otherwise - exclusive canonicalization)
 * @inclusive_ns_prefixes: the list of inclusive namespace prefixes 
 *			ended with a NULL or NULL if there is no
 *			inclusive namespaces (only for exclusive 
 *			canonicalization, ignored otherwise)
 * @with_comments: 	include comments in the result (!=0) or not (==0)
 * @filename: 		the filename to store canonical XML image
 * @compression:	the compression level (zlib requred): 
 *				-1 - libxml default,
 *				 0 - uncompressed, 
 *				>0 - compression level
 *  		
 * Dumps the canonized image of given XML document into the file.
 * For details see "Canonical XML" (http://www.w3.org/TR/xml-c14n) or
 * "Exclusive XML Canonicalization" (http://www.w3.org/TR/xml-exc-c14n)
 *
 * Returns the number of bytes written success or a negative value on fail  
 */
int
xmlC14NDocSave(xmlDocPtr doc, xmlNodeSetPtr nodes,
               int exclusive, xmlChar ** inclusive_ns_prefixes,
               int with_comments, const char *filename, int compression)
{
    xmlOutputBufferPtr buf;
    int ret;

    if (filename == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocSave:  filename is NULL\n");
#endif
        return (-1);
    }
#ifdef HAVE_ZLIB_H
    if (compression < 0)
        compression = xmlGetCompressMode();
#endif

    /* 
     * save the content to a temp buffer, use default UTF8 encoding.
     */
    buf = xmlOutputBufferCreateFilename(filename, NULL, compression);
    if (buf == NULL) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocSave:  unable to create buffer for file=\"%s\" with compressin=%d\n",
                        filename, compression);
#endif
        return (-1);
    }

    /*
     * canonize document and write to buffer
     */
    ret = xmlC14NDocSaveTo(doc, nodes, exclusive, inclusive_ns_prefixes,
                           with_comments, buf);
    if (ret < 0) {
#ifdef DEBUG_C14N
        xmlGenericError(xmlGenericErrorContext,
                        "xmlC14NDocSave: xmlC14NDocSaveTo failed.\n");
#endif
        (void) xmlOutputBufferClose(buf);
        return (-1);
    }

    /* 
     * get the numbers of bytes written 
     */
    ret = xmlOutputBufferClose(buf);
    return (ret);
}



/*
 * Macro used to grow the current buffer.
 */
#define growBufferReentrant() {						\
    buffer_size *= 2;							\
    buffer = (xmlChar *)						\
    		xmlRealloc(buffer, buffer_size * sizeof(xmlChar));	\
    if (buffer == NULL) {						\
	perror("realloc failed");					\
	return(NULL);							\
    }									\
}

/** 
 * xmlC11NNormalizeString:
 * @input:		the input string
 * @mode:		the normalization mode (attribute, comment, PI or text)
 *
 * Converts a string to a canonical (normalized) format. The code is stolen
 * from xmlEncodeEntitiesReentrant(). Added normalization of \x09, \x0a, \x0A
 * and the @mode parameter
 *
 * Returns a normalized string (caller is responsible for calling xmlFree())
 * or NULL if an error occurs
 */
static xmlChar *
xmlC11NNormalizeString(const xmlChar * input,
                       xmlC14NNormalizationMode mode)
{
    const xmlChar *cur = input;
    xmlChar *buffer = NULL;
    xmlChar *out = NULL;
    int buffer_size = 0;

    if (input == NULL)
        return (NULL);

    /*
     * allocate an translation buffer.
     */
    buffer_size = 1000;
    buffer = (xmlChar *) xmlMalloc(buffer_size * sizeof(xmlChar));
    if (buffer == NULL) {
        perror("malloc failed");
        return (NULL);
    }
    out = buffer;

    while (*cur != '\0') {
        if ((out - buffer) > (buffer_size - 10)) {
            int indx = out - buffer;

            growBufferReentrant();
            out = &buffer[indx];
        }

        if ((*cur == '<') && ((mode == XMLC14N_NORMALIZE_ATTR) ||
                              (mode == XMLC14N_NORMALIZE_TEXT))) {
            *out++ = '&';
            *out++ = 'l';
            *out++ = 't';
            *out++ = ';';
        } else if ((*cur == '>') && (mode == XMLC14N_NORMALIZE_TEXT)) {
            *out++ = '&';
            *out++ = 'g';
            *out++ = 't';
            *out++ = ';';
        } else if ((*cur == '&') && ((mode == XMLC14N_NORMALIZE_ATTR) ||
                                     (mode == XMLC14N_NORMALIZE_TEXT))) {
            *out++ = '&';
            *out++ = 'a';
            *out++ = 'm';
            *out++ = 'p';
            *out++ = ';';
        } else if ((*cur == '"') && (mode == XMLC14N_NORMALIZE_ATTR)) {
            *out++ = '&';
            *out++ = 'q';
            *out++ = 'u';
            *out++ = 'o';
            *out++ = 't';
            *out++ = ';';
        } else if ((*cur == '\x09') && (mode == XMLC14N_NORMALIZE_ATTR)) {
            *out++ = '&';
            *out++ = '#';
            *out++ = 'x';
            *out++ = '9';
            *out++ = ';';
        } else if ((*cur == '\x0A') && (mode == XMLC14N_NORMALIZE_ATTR)) {
            *out++ = '&';
            *out++ = '#';
            *out++ = 'x';
            *out++ = 'A';
            *out++ = ';';
        } else if ((*cur == '\x0D') && ((mode == XMLC14N_NORMALIZE_ATTR) ||
                                        (mode == XMLC14N_NORMALIZE_TEXT) ||
                                        (mode == XMLC14N_NORMALIZE_COMMENT) ||
					(mode == XMLC14N_NORMALIZE_PI))) {
            *out++ = '&';
            *out++ = '#';
            *out++ = 'x';
            *out++ = 'D';
            *out++ = ';';
        } else {
            /*
             * Works because on UTF-8, all extended sequences cannot
             * result in bytes in the ASCII range.
             */
            *out++ = *cur;
        }
        cur++;
    }
    *out++ = 0;
    return (buffer);
}
#endif /* LIBXML_C14N_ENABLED */
