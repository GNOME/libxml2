/*
 * xinclude.c : Code to implement XInclude processing
 *
 * World Wide Web Consortium W3C Last Call Working Draft 16 May 2001
 * http://www.w3.org/TR/2001/WD-xinclude-20010516/
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

/*
 * TODO: compute XPointers nodesets
 * TODO: add an node intermediate API and handle recursion at this level
 */

#include "libxml.h"

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/uri.h>
#include <libxml/xpointer.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlerror.h>
#include <libxml/globals.h>

#ifdef LIBXML_XINCLUDE_ENABLED
#include <libxml/xinclude.h>

#define XINCLUDE_NS (const xmlChar *) "http://www.w3.org/2001/XInclude"
#define XINCLUDE_NODE (const xmlChar *) "include"
#define XINCLUDE_HREF (const xmlChar *) "href"
#define XINCLUDE_PARSE (const xmlChar *) "parse"
#define XINCLUDE_PARSE_XML (const xmlChar *) "xml"
#define XINCLUDE_PARSE_TEXT (const xmlChar *) "text"

/* #define DEBUG_XINCLUDE  */
#ifdef DEBUG_XINCLUDE
#ifdef LIBXML_DEBUG_ENABLED
#include <libxml/debugXML.h>
#endif
#endif

/************************************************************************
 *									*
 *			XInclude contexts handling			*
 *									*
 ************************************************************************/

/*
 * An XInclude context
 */
typedef xmlChar *xmlURL;
typedef struct _xmlXIncludeCtxt xmlXIncludeCtxt;
typedef xmlXIncludeCtxt *xmlXIncludeCtxtPtr;
struct _xmlXIncludeCtxt {
    xmlDocPtr             doc; /* the source document */
    int                 incNr; /* number of includes */
    int                incMax; /* size of includes tab */
    xmlNodePtr        *incTab; /* array of include nodes */
    xmlNodePtr        *repTab; /* array of replacement node lists */
    int                 docNr; /* number of parsed documents */
    int                docMax; /* size of parsed documents tab */
    xmlDocPtr         *docTab; /* array of parsed documents */
    xmlURL            *urlTab; /* array of parsed documents URLs */
    int                 txtNr; /* number of unparsed documents */
    int                txtMax; /* size of unparsed documents tab */
    xmlNodePtr        *txtTab; /* array of unparsed text nodes */
    xmlURL         *txturlTab; /* array of unparsed txtuments URLs */
};

static int
xmlXIncludeDoProcess(xmlXIncludeCtxtPtr ctxt, xmlDocPtr doc);

/**
 * xmlXIncludeNewContext:
 * @doc:  an XML Document
 *
 * Creates a new XInclude context
 *
 * Returns the new set
 */
static xmlXIncludeCtxtPtr
xmlXIncludeNewContext(xmlDocPtr doc) {
    xmlXIncludeCtxtPtr ret;

    if (doc == NULL)
	return(NULL);
    ret = (xmlXIncludeCtxtPtr) xmlMalloc(sizeof(xmlXIncludeCtxt));
    if (ret == NULL)
	return(NULL);
    memset(ret, 0, sizeof(xmlXIncludeCtxt));
    ret->doc = doc;
    ret->incNr = 0;
    ret->incMax = 0;
    ret->incTab = NULL;
    ret->repTab = NULL;
    ret->docNr = 0;
    ret->docMax = 0;
    ret->docTab = NULL;
    ret->urlTab = NULL;
    return(ret);
}

/**
 * xmlXIncludeFreeContext:
 * @ctxt: the XInclude context
 *
 * Free an XInclude context
 */
static void
xmlXIncludeFreeContext(xmlXIncludeCtxtPtr ctxt) {
    int i;

    if (ctxt == NULL)
	return;
    for (i = 0;i < ctxt->docNr;i++) {
	xmlFreeDoc(ctxt->docTab[i]);
	if (ctxt->urlTab[i] != NULL)
	    xmlFree(ctxt->urlTab[i]);
    }
    for (i = 0;i < ctxt->txtNr;i++) {
	if (ctxt->txturlTab[i] != NULL)
	    xmlFree(ctxt->txturlTab[i]);
    }
    if (ctxt->incTab != NULL)
	xmlFree(ctxt->incTab);
    if (ctxt->repTab != NULL)
	xmlFree(ctxt->repTab);
    if (ctxt->urlTab != NULL)
	xmlFree(ctxt->urlTab);
    if (ctxt->docTab != NULL)
	xmlFree(ctxt->docTab);
    if (ctxt->txtTab != NULL)
	xmlFree(ctxt->txtTab);
    if (ctxt->txturlTab != NULL)
	xmlFree(ctxt->txturlTab);
    xmlFree(ctxt);
}

/**
 * xmlXIncludeAddNode:
 * @ctxt:  the XInclude context
 * @node:  the new node
 * 
 * Add a new node to process to an XInclude context
 */
static void
xmlXIncludeAddNode(xmlXIncludeCtxtPtr ctxt, xmlNodePtr node) {
    if (ctxt->incMax == 0) {
	ctxt->incMax = 4;
        ctxt->incTab = (xmlNodePtr *) xmlMalloc(ctxt->incMax *
		                          sizeof(ctxt->incTab[0]));
        if (ctxt->incTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    return;
	}
        ctxt->repTab = (xmlNodePtr *) xmlMalloc(ctxt->incMax *
		                          sizeof(ctxt->repTab[0]));
        if (ctxt->repTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    return;
	}
    }
    if (ctxt->incNr >= ctxt->incMax) {
	ctxt->incMax *= 2;
        ctxt->incTab = (xmlNodePtr *) xmlRealloc(ctxt->incTab,
	             ctxt->incMax * sizeof(ctxt->incTab[0]));
        if (ctxt->incTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "realloc failed !\n");
	    return;
	}
        ctxt->repTab = (xmlNodePtr *) xmlRealloc(ctxt->repTab,
	             ctxt->incMax * sizeof(ctxt->repTab[0]));
        if (ctxt->repTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "realloc failed !\n");
	    return;
	}
    }
    ctxt->incTab[ctxt->incNr] = node;
    ctxt->repTab[ctxt->incNr] = NULL;
    ctxt->incNr++;
}

/**
 * xmlXIncludeAddDoc:
 * @ctxt:  the XInclude context
 * @doc:  the new document
 * @url:  the associated URL
 * 
 * Add a new document to the list. The XInclude recursive nature is handled
 * at this point.
 */
static void
xmlXIncludeAddDoc(xmlXIncludeCtxtPtr ctxt, xmlDocPtr doc, const xmlURL url) {
    xmlXIncludeCtxtPtr newctxt;
    int i;

    if (ctxt->docMax == 0) {
	ctxt->docMax = 4;
        ctxt->docTab = (xmlDocPtr *) xmlMalloc(ctxt->docMax *
		                          sizeof(ctxt->docTab[0]));
        if (ctxt->docTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    return;
	}
        ctxt->urlTab = (xmlURL *) xmlMalloc(ctxt->docMax *
		                          sizeof(ctxt->urlTab[0]));
        if (ctxt->urlTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    return;
	}
    }
    if (ctxt->docNr >= ctxt->docMax) {
	ctxt->docMax *= 2;
        ctxt->docTab = (xmlDocPtr *) xmlRealloc(ctxt->docTab,
	             ctxt->docMax * sizeof(ctxt->docTab[0]));
        if (ctxt->docTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "realloc failed !\n");
	    return;
	}
        ctxt->urlTab = (xmlURL *) xmlRealloc(ctxt->urlTab,
	             ctxt->docMax * sizeof(ctxt->urlTab[0]));
        if (ctxt->urlTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "realloc failed !\n");
	    return;
	}
    }
    ctxt->docTab[ctxt->docNr] = doc;
    ctxt->urlTab[ctxt->docNr] = xmlStrdup(url);
    ctxt->docNr++;

    /*
     * Handle recursion here.
     */

    newctxt = xmlXIncludeNewContext(doc);
    if (newctxt != NULL) {
	/*
	 * Copy the existing document set
	 */
	newctxt->docMax = ctxt->docMax;
	newctxt->docNr = ctxt->docNr;
        newctxt->docTab = (xmlDocPtr *) xmlMalloc(newctxt->docMax *
		                          sizeof(newctxt->docTab[0]));
        if (newctxt->docTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    xmlFree(newctxt);
	    return;
	}
        newctxt->urlTab = (xmlURL *) xmlMalloc(newctxt->docMax *
		                          sizeof(newctxt->urlTab[0]));
        if (ctxt->urlTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    xmlFree(newctxt);
	    return;
	}

	for (i = 0;i < ctxt->docNr;i++) {
	    newctxt->docTab[i] = ctxt->docTab[i];
	    newctxt->urlTab[i] = ctxt->urlTab[i];
	}
	xmlXIncludeDoProcess(newctxt, doc);
	for (i = 0;i < ctxt->docNr;i++) {
	    newctxt->docTab[i] = NULL;
	    newctxt->urlTab[i] = NULL;
	}
	xmlXIncludeFreeContext(newctxt);
    }
}

/**
 * xmlXIncludeAddTxt:
 * @ctxt:  the XInclude context
 * @txt:  the new text node
 * @url:  the associated URL
 * 
 * Add a new txtument to the list
 */
static void
xmlXIncludeAddTxt(xmlXIncludeCtxtPtr ctxt, xmlNodePtr txt, const xmlURL url) {
    if (ctxt->txtMax == 0) {
	ctxt->txtMax = 4;
        ctxt->txtTab = (xmlNodePtr *) xmlMalloc(ctxt->txtMax *
		                          sizeof(ctxt->txtTab[0]));
        if (ctxt->txtTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    return;
	}
        ctxt->txturlTab = (xmlURL *) xmlMalloc(ctxt->txtMax *
		                          sizeof(ctxt->txturlTab[0]));
        if (ctxt->txturlTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "malloc failed !\n");
	    return;
	}
    }
    if (ctxt->txtNr >= ctxt->txtMax) {
	ctxt->txtMax *= 2;
        ctxt->txtTab = (xmlNodePtr *) xmlRealloc(ctxt->txtTab,
	             ctxt->txtMax * sizeof(ctxt->txtTab[0]));
        if (ctxt->txtTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "realloc failed !\n");
	    return;
	}
        ctxt->txturlTab = (xmlURL *) xmlRealloc(ctxt->txturlTab,
	             ctxt->txtMax * sizeof(ctxt->urlTab[0]));
        if (ctxt->txturlTab == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
		    "realloc failed !\n");
	    return;
	}
    }
    ctxt->txtTab[ctxt->txtNr] = txt;
    ctxt->txturlTab[ctxt->txtNr] = xmlStrdup(url);
    ctxt->txtNr++;
}

/************************************************************************
 *									*
 *			XInclude I/O handling				*
 *									*
 ************************************************************************/

/**
 * xmlXIncludeLoadDoc:
 * @ctxt:  the XInclude context
 * @url:  the associated URL
 * @nr:  the xinclude node number
 * 
 * Load the document, and store the result in the XInclude context
 */
static void
xmlXIncludeLoadDoc(xmlXIncludeCtxtPtr ctxt, const xmlChar *url, int nr) {
    xmlDocPtr doc;
    xmlURIPtr uri;
    xmlChar *URL;
    xmlChar *fragment = NULL;
    int i;
    /*
     * Check the URL and remove any fragment identifier
     */
    uri = xmlParseURI((const char *)url);
    if (uri == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		    "XInclude: invalid value URI %s\n", url);
	return;
    }
    if (uri->fragment != NULL) {
	fragment = (xmlChar *) uri->fragment;
	uri->fragment = NULL;
    }
    URL = xmlSaveUri(uri);
    xmlFreeURI(uri);
    if (URL == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		    "XInclude: invalid value URI %s\n", url);
	if (fragment != NULL)
	    xmlFree(fragment);
	return;
    }

    /*
     * Handling of references to the local document are done
     * directly through ctxt->doc.
     */
    if ((URL[0] == 0) || (URL[0] == '#')) {
	doc = NULL;
        goto loaded;
    }

    /*
     * Prevent reloading twice the document.
     */
    for (i = 0; i < ctxt->docNr; i++) {
	if (xmlStrEqual(URL, ctxt->urlTab[i])) {
	    doc = ctxt->docTab[i];
	    goto loaded;
	}
    }
    /*
     * Load it.
     */
    doc = xmlParseFile((const char *)URL);
    if (doc == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		    "XInclude: could not load %s\n", URL);
	xmlFree(URL);
	if (fragment != NULL)
	    xmlFree(fragment);
	return;
    }
    xmlXIncludeAddDoc(ctxt, doc, URL);

loaded:
    if (fragment == NULL) {
	/*
	 * Add the top children list as the replacement copy.
	 */
	if (doc == NULL)
	{
	    /* Hopefully a DTD declaration won't be copied from
	     * the same document */
	    ctxt->repTab[nr] = xmlCopyNodeList(ctxt->doc->children);
	} else {
	    /* DTD declarations can't be copied from included files */
	    xmlNodePtr node = doc->children;
	    while (node != NULL)
	    {
		if (node->type == XML_DTD_NODE)
		{
		    xmlUnlinkNode(node);
		    xmlFreeNode(node);
		}
		node = node->next;
	    }
	    ctxt->repTab[nr] = xmlCopyNodeList(doc->children);
	}
    } else {
	/*
	 * Computes the XPointer expression and make a copy used
	 * as the replacement copy.
	 */
	xmlXPathObjectPtr xptr;
	xmlXPathContextPtr xptrctxt;
	xmlNodeSetPtr set;

	if (doc == NULL) {
	    xptrctxt = xmlXPtrNewContext(ctxt->doc, ctxt->incTab[nr], NULL);
	} else {
	    xptrctxt = xmlXPtrNewContext(doc, NULL, NULL);
	}
	if (xptrctxt == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
			"XInclude: could create XPointer context\n");
	    xmlFree(URL);
	    xmlFree(fragment);
	    return;
	}
	xptr = xmlXPtrEval(fragment, xptrctxt);
	if (xptr == NULL) {
	    xmlGenericError(xmlGenericErrorContext,
			"XInclude: XPointer evaluation failed: #%s\n",
			fragment);
	    xmlXPathFreeContext(xptrctxt);
	    xmlFree(URL);
	    xmlFree(fragment);
	    return;
	}
	switch (xptr->type) {
	    case XPATH_UNDEFINED:
	    case XPATH_BOOLEAN:
	    case XPATH_NUMBER:
	    case XPATH_STRING:
	    case XPATH_POINT:
	    case XPATH_USERS:
	    case XPATH_XSLT_TREE:
		xmlGenericError(xmlGenericErrorContext,
			"XInclude: XPointer is not a range: #%s\n",
			        fragment);
		xmlXPathFreeContext(xptrctxt);
		xmlFree(URL);
		xmlFree(fragment);
		return;
	    case XPATH_NODESET:
	    case XPATH_RANGE:
	    case XPATH_LOCATIONSET:
		break;
	}
	set = xptr->nodesetval;
	if (set != NULL) {
	    for (i = 0;i < set->nodeNr;i++) {
		if (set->nodeTab[i] == NULL)
		    continue;
		switch (set->nodeTab[i]->type) {
		    case XML_TEXT_NODE:
		    case XML_CDATA_SECTION_NODE:
		    case XML_ELEMENT_NODE:
		    case XML_ENTITY_REF_NODE:
		    case XML_ENTITY_NODE:
		    case XML_PI_NODE:
		    case XML_COMMENT_NODE:
		    case XML_DOCUMENT_NODE:
		    case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
		    case XML_DOCB_DOCUMENT_NODE:
#endif
			continue;
		    case XML_ATTRIBUTE_NODE:
			xmlGenericError(xmlGenericErrorContext,
			"XInclude: XPointer selects an attribute: #%s\n",
					fragment);
			set->nodeTab[i] = NULL;
			continue;
		    case XML_NAMESPACE_DECL:
			xmlGenericError(xmlGenericErrorContext,
			"XInclude: XPointer selects a namespace: #%s\n",
					fragment);
			set->nodeTab[i] = NULL;
			continue;
		    case XML_DOCUMENT_TYPE_NODE:
		    case XML_DOCUMENT_FRAG_NODE:
		    case XML_NOTATION_NODE:
		    case XML_DTD_NODE:
		    case XML_ELEMENT_DECL:
		    case XML_ATTRIBUTE_DECL:
		    case XML_ENTITY_DECL:
		    case XML_XINCLUDE_START:
		    case XML_XINCLUDE_END:
			xmlGenericError(xmlGenericErrorContext,
			"XInclude: XPointer selects unexpected nodes: #%s\n",
					fragment);
			set->nodeTab[i] = NULL;
			set->nodeTab[i] = NULL;
			continue; /* for */
		}
	    }
	}
	ctxt->repTab[nr] = xmlXPtrBuildNodeList(xptr);
	xmlXPathFreeObject(xptr);
	xmlXPathFreeContext(xptrctxt);
	xmlFree(fragment);
    }
    xmlFree(URL);
}

/**
 * xmlXIncludeLoadTxt:
 * @ctxt:  the XInclude context
 * @url:  the associated URL
 * @nr:  the xinclude node number
 * 
 * Load the content, and store the result in the XInclude context
 */
static void
xmlXIncludeLoadTxt(xmlXIncludeCtxtPtr ctxt, const xmlChar *url, int nr) {
    xmlParserInputBufferPtr buf;
    xmlNodePtr node;
    xmlURIPtr uri;
    xmlChar *URL;
    int i;
    /*
     * Check the URL and remove any fragment identifier
     */
    uri = xmlParseURI((const char *)url);
    if (uri == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		    "XInclude: invalid value URI %s\n", url);
	return;
    }
    if (uri->fragment != NULL) {
	xmlGenericError(xmlGenericErrorContext,
		"XInclude: fragment identifier forbidden for text: %s\n",
		uri->fragment);
	xmlFreeURI(uri);
	return;
    }
    URL = xmlSaveUri(uri);
    xmlFreeURI(uri);
    if (URL == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		    "XInclude: invalid value URI %s\n", url);
	return;
    }

    /*
     * Handling of references to the local document are done
     * directly through ctxt->doc.
     */
    if (URL[0] == 0) {
	xmlGenericError(xmlGenericErrorContext,
		"XInclude: text serialization of document not available\n");
	xmlFree(URL);
	return;
    }

    /*
     * Prevent reloading twice the document.
     */
    for (i = 0; i < ctxt->txtNr; i++) {
	if (xmlStrEqual(URL, ctxt->txturlTab[i])) {
	    node = xmlCopyNode(ctxt->txtTab[i], 1);
	    goto loaded;
	}
    }
    /*
     * Load it.
     * Issue 62: how to detect the encoding
     */
    buf = xmlParserInputBufferCreateFilename((const char *)URL, 0);
    if (buf == NULL) {
	xmlGenericError(xmlGenericErrorContext,
		    "XInclude: could not load %s\n", URL);
	xmlFree(URL);
	return;
    }
    node = xmlNewText(NULL);

    /*
     * Scan all chars from the resource and add the to the node
     */
    while (xmlParserInputBufferRead(buf, 128) > 0) {
	int len;
	const xmlChar *content;

	content = xmlBufferContent(buf->buffer);
	len = xmlBufferLength(buf->buffer);
	for (i = 0;i < len; i++) {
	    /*
	     * TODO: if the encoding issue is solved, scan UTF8 chars instead
	     */
	    if (!IS_CHAR(content[i])) {
		xmlGenericError(xmlGenericErrorContext,
		    "XInclude: %s contains invalid char %d\n", URL, content[i]);
	    } else {
		xmlNodeAddContentLen(node, &content[i], 1);
	    }
	}
	xmlBufferShrink(buf->buffer, len);
    }
    xmlFreeParserInputBuffer(buf);
    xmlXIncludeAddTxt(ctxt, node, URL);

loaded:
    /*
     * Add the element as the replacement copy.
     */
    ctxt->repTab[nr] = node;
    xmlFree(URL);
}

/************************************************************************
 *									*
 *			XInclude Processing				*
 *									*
 ************************************************************************/

/**
 * xmlXIncludePreProcessNode:
 * @ctxt: an XInclude context
 * @node: an XInclude node
 *
 * Implement the XInclude preprocessing, currently just adding the element
 * for further processing.
 *
 * Returns the result list or NULL in case of error
 */
static xmlNodePtr
xmlXIncludePreProcessNode(xmlXIncludeCtxtPtr ctxt, xmlNodePtr node) {
    xmlXIncludeAddNode(ctxt, node);
    return(0);
}

/**
 * xmlXIncludeLoadNode:
 * @ctxt: an XInclude context
 * @nr: the node number
 *
 * Find and load the infoset replacement for the given node.
 *
 * Returns 0 if substition succeeded, -1 if some processing failed
 */
static int
xmlXIncludeLoadNode(xmlXIncludeCtxtPtr ctxt, int nr) {
    xmlNodePtr cur;
    xmlChar *href;
    xmlChar *parse;
    xmlChar *base;
    xmlChar *URI;
    int xml = 1; /* default Issue 64 */

    if (ctxt == NULL)
	return(-1);
    if ((nr < 0) || (nr >= ctxt->incNr))
	return(-1);
    cur = ctxt->incTab[nr];
    if (cur == NULL)
	return(-1);

#ifdef DEBUG_XINCLUDE
    xmlDebugDumpNode(stdout, cur, 0);
#endif
    /*
     * read the attributes
     */
    href = xmlGetNsProp(cur, XINCLUDE_NS, XINCLUDE_HREF);
    if (href == NULL) {
	href = xmlGetProp(cur, XINCLUDE_HREF);
	if (href == NULL) {
	    xmlGenericError(xmlGenericErrorContext, "XInclude: no href\n");
	    return(-1);
	}
    }
    parse = xmlGetNsProp(cur, XINCLUDE_NS, XINCLUDE_PARSE);
    if (parse == NULL) {
	parse = xmlGetProp(cur, XINCLUDE_PARSE);
    }
    if (parse != NULL) {
	if (xmlStrEqual(parse, XINCLUDE_PARSE_XML))
	    xml = 1;
	else if (xmlStrEqual(parse, XINCLUDE_PARSE_TEXT))
	    xml = 0;
	else {
	    xmlGenericError(xmlGenericErrorContext,
		    "XInclude: invalid value %s for %s\n",
		            parse, XINCLUDE_PARSE);
	    if (href != NULL)
		xmlFree(href);
	    if (parse != NULL)
		xmlFree(parse);
	    return(-1);
	}
    }

    /*
     * compute the URI
     */
    base = xmlNodeGetBase(ctxt->doc, cur);
    if (base == NULL) {
	URI = xmlBuildURI(href, ctxt->doc->URL);
    } else {
	URI = xmlBuildURI(href, base);
    }
    if (URI == NULL) {
	xmlChar *escbase;
	xmlChar *eschref;
	/*
	 * Some escapeing may be needed
	 */
	escbase = xmlURIEscape(base);
	eschref = xmlURIEscape(href);
	URI = xmlBuildURI(eschref, escbase);
	if (escbase != NULL)
	    xmlFree(escbase);
	if (eschref != NULL)
	    xmlFree(eschref);
    }
    if (URI == NULL) {
	xmlGenericError(xmlGenericErrorContext, "XInclude: failed build URL\n");
	if (parse != NULL)
	    xmlFree(parse);
	if (href != NULL)
	    xmlFree(href);
	if (base != NULL)
	    xmlFree(base);
	return(-1);
    }
#ifdef DEBUG_XINCLUDE
    xmlGenericError(xmlGenericErrorContext, "parse: %s\n",
	    xml ? "xml": "text");
    xmlGenericError(xmlGenericErrorContext, "URI: %s\n", URI);
#endif

    /*
     * Cleanup
     */
    if (xml) {
	xmlXIncludeLoadDoc(ctxt, URI, nr);
	/* xmlXIncludeGetFragment(ctxt, cur, URI); */
    } else {
	xmlXIncludeLoadTxt(ctxt, URI, nr);
    }

    /*
     * Cleanup
     */
    if (URI != NULL)
	xmlFree(URI);
    if (parse != NULL)
	xmlFree(parse);
    if (href != NULL)
	xmlFree(href);
    if (base != NULL)
	xmlFree(base);
    return(0);
}

/**
 * xmlXIncludeIncludeNode:
 * @ctxt: an XInclude context
 * @nr: the node number
 *
 * Inplement the infoset replacement for the given node
 *
 * Returns 0 if substition succeeded, -1 if some processing failed
 */
static int
xmlXIncludeIncludeNode(xmlXIncludeCtxtPtr ctxt, int nr) {
    xmlNodePtr cur, end, list;

    if (ctxt == NULL)
	return(-1);
    if ((nr < 0) || (nr >= ctxt->incNr))
	return(-1);
    cur = ctxt->incTab[nr];
    if (cur == NULL)
	return(-1);

    /*
     * Change the current node as an XInclude start one, and add an
     * entity end one
     */
    cur->type = XML_XINCLUDE_START;
    end = xmlNewNode(cur->ns, cur->name);
    if (end == NULL) {
	xmlGenericError(xmlGenericErrorContext, 
		"XInclude: failed to build node\n");
	return(-1);
    }
    end->type = XML_XINCLUDE_END;
    xmlAddNextSibling(cur, end);

    /*
     * Add the list of nodes
     */
    list = ctxt->repTab[nr];
    ctxt->repTab[nr] = NULL;
    while (list != NULL) {
	cur = list;
	list = list->next;

        xmlAddPrevSibling(end, cur);
    }
    return(0);
}

/**
 * xmlXIncludeTestNode:
 * @node: an XInclude node
 *
 * test if the node is an XInclude node
 *
 * Returns 1 true, 0 otherwise
 */
static int
xmlXIncludeTestNode(xmlNodePtr node) {
    if (node == NULL)
	return(0);
    if (node->ns == NULL)
	return(0);
    if ((xmlStrEqual(node->name, XINCLUDE_NODE)) &&
	(xmlStrEqual(node->ns->href, XINCLUDE_NS))) return(1);
    return(0);
}

/**
 * xmlXIncludeDoProcess:
 * @ctxt: 
 * @doc: an XML document
 *
 * Implement the XInclude substitution on the XML document @doc
 *
 * Returns 0 if no substition were done, -1 if some processing failed
 *    or the number of substitutions done.
 */
static int
xmlXIncludeDoProcess(xmlXIncludeCtxtPtr ctxt, xmlDocPtr doc) {
    xmlNodePtr cur;
    int ret = 0;
    int i;

    if (doc == NULL)
	return(-1);
    if (ctxt == NULL)
	return(-1);

    /*
     * First phase: lookup the elements in the document
     */
    cur = xmlDocGetRootElement(doc);
    if (xmlXIncludeTestNode(cur))
	xmlXIncludePreProcessNode(ctxt, cur);
    while (cur != NULL) {
	/* TODO: need to work on entities -> stack */
	if ((cur->children != NULL) &&
	    (cur->children->type != XML_ENTITY_DECL)) {
	    cur = cur->children;
	    if (xmlXIncludeTestNode(cur))
		xmlXIncludePreProcessNode(ctxt, cur);
	} else if (cur->next != NULL) {
	    cur = cur->next;
	    if (xmlXIncludeTestNode(cur))
		xmlXIncludePreProcessNode(ctxt, cur);
	} else {
	    do {
		cur = cur->parent;
		if (cur == NULL) break; /* do */
		if (cur->next != NULL) {
		    cur = cur->next;
		    if (xmlXIncludeTestNode(cur))
			xmlXIncludePreProcessNode(ctxt, cur);
		    break; /* do */
		}
	    } while (cur != NULL);
	}
    }

    /*
     * Second Phase : collect the infosets fragments
     */
    for (i = 0;i < ctxt->incNr; i++) {
        xmlXIncludeLoadNode(ctxt, i);
    }

    /*
     * Third phase: extend the original document infoset.
     */
    for (i = 0;i < ctxt->incNr; i++) {
	xmlXIncludeIncludeNode(ctxt, i);
    }

    return(ret);
}

/**
 * xmlXIncludeProcess:
 * @doc: an XML document
 *
 * Implement the XInclude substitution on the XML document @doc
 *
 * Returns 0 if no substition were done, -1 if some processing failed
 *    or the number of substitutions done.
 */
int
xmlXIncludeProcess(xmlDocPtr doc) {
    xmlXIncludeCtxtPtr ctxt;
    int ret = 0;

    if (doc == NULL)
	return(-1);
    ctxt = xmlXIncludeNewContext(doc);
    if (ctxt == NULL)
	return(-1);
    ret = xmlXIncludeDoProcess(ctxt, doc);

    xmlXIncludeFreeContext(ctxt);
    return(ret);
}

#else /* !LIBXML_XINCLUDE_ENABLED */
#endif
