/*
 * HTMLtree.c : implemetation of access function for an HTML tree.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */


#include "libxml.h"
#ifdef LIBXML_HTML_ENABLED

#include <string.h> /* for memset() only ! */

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <libxml/xmlmemory.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/entities.h>
#include <libxml/valid.h>
#include <libxml/xmlerror.h>
#include <libxml/parserInternals.h>

/************************************************************************
 *									*
 *   		Getting/Setting encoding meta tags			*
 *									*
 ************************************************************************/

/**
 * htmlGetMetaEncoding:
 * @doc:  the document
 * 
 * Encoding definition lookup in the Meta tags
 *
 * Returns the current encoding as flagged in the HTML source
 */
const xmlChar *
htmlGetMetaEncoding(htmlDocPtr doc) {
    htmlNodePtr cur;
    const xmlChar *content;
    const xmlChar *encoding;

    if (doc == NULL)
	return(NULL);
    cur = doc->children;

    /*
     * Search the html
     */
    while (cur != NULL) {
	if (cur->name != NULL) {
	    if (xmlStrEqual(cur->name, BAD_CAST"html"))
		break;
	    if (xmlStrEqual(cur->name, BAD_CAST"head"))
		goto found_head;
	    if (xmlStrEqual(cur->name, BAD_CAST"meta"))
		goto found_meta;
	}
	cur = cur->next;
    }
    if (cur == NULL)
	return(NULL);
    cur = cur->children;

    /*
     * Search the head
     */
    while (cur != NULL) {
	if (cur->name != NULL) {
	    if (xmlStrEqual(cur->name, BAD_CAST"head"))
		break;
	    if (xmlStrEqual(cur->name, BAD_CAST"meta"))
		goto found_meta;
	}
	cur = cur->next;
    }
    if (cur == NULL)
	return(NULL);
found_head:
    cur = cur->children;

    /*
     * Search the meta elements
     */
found_meta:
    while (cur != NULL) {
	if (cur->name != NULL) {
	    if (xmlStrEqual(cur->name, BAD_CAST"meta")) {
		xmlAttrPtr attr = cur->properties;
		int http;
		const xmlChar *value;

		content = NULL;
		http = 0;
		while (attr != NULL) {
		    if ((attr->children != NULL) &&
		        (attr->children->type == XML_TEXT_NODE) &&
		        (attr->children->next == NULL)) {
#ifndef XML_USE_BUFFER_CONTENT
			value = attr->children->content;
#else
			value = xmlBufferContent(attr->children->content);
#endif
			if ((!xmlStrcasecmp(attr->name, BAD_CAST"http-equiv"))
			 && (!xmlStrcasecmp(value, BAD_CAST"Content-Type")))
			    http = 1;
			else if ((value != NULL)
			 && (!xmlStrcasecmp(attr->name, BAD_CAST"content")))
			    content = value;
			if ((http != 0) && (content != NULL))
			    goto found_content;
		    }
		    attr = attr->next;
		}
	    }
	}
	cur = cur->next;
    }
    return(NULL);

found_content:
    encoding = xmlStrstr(content, BAD_CAST"charset=");
    if (encoding == NULL) 
	encoding = xmlStrstr(content, BAD_CAST"Charset=");
    if (encoding == NULL) 
	encoding = xmlStrstr(content, BAD_CAST"CHARSET=");
    if (encoding != NULL) {
	encoding += 8;
    } else {
	encoding = xmlStrstr(content, BAD_CAST"charset =");
	if (encoding == NULL) 
	    encoding = xmlStrstr(content, BAD_CAST"Charset =");
	if (encoding == NULL) 
	    encoding = xmlStrstr(content, BAD_CAST"CHARSET =");
	if (encoding != NULL)
	    encoding += 9;
    }
    if (encoding != NULL) {
	while ((*encoding == ' ') || (*encoding == '\t')) encoding++;
    }
    return(encoding);
}

/**
 * htmlSetMetaEncoding:
 * @doc:  the document
 * @encoding:  the encoding string
 * 
 * Sets the current encoding in the Meta tags
 * NOTE: this will not change the document content encoding, just
 * the META flag associated.
 *
 * Returns 0 in case of success and -1 in case of error
 */
int
htmlSetMetaEncoding(htmlDocPtr doc, const xmlChar *encoding) {
    htmlNodePtr cur, meta;
    const xmlChar *content;
    char newcontent[100];


    if (doc == NULL)
	return(-1);

    if (encoding != NULL) {
	snprintf(newcontent, sizeof(newcontent), "text/html; charset=%s",
                encoding);
	newcontent[sizeof(newcontent) - 1] = 0;
    }

    cur = doc->children;

    /*
     * Search the html
     */
    while (cur != NULL) {
	if (cur->name != NULL) {
/*
	    if (xmlStrEqual(cur->name, BAD_CAST"html"))
		break;
	    if (xmlStrEqual(cur->name, BAD_CAST"body")) {
		if (encoding == NULL)
		    return(0);
		meta = xmlNewDocNode(doc, NULL, BAD_CAST"head", NULL);
		xmlAddPrevSibling(cur, meta);
		cur = meta;
		meta = xmlNewDocNode(doc, NULL, BAD_CAST"meta", NULL);
		xmlAddChild(cur, meta);
		xmlNewProp(meta, BAD_CAST"http-equiv", BAD_CAST"Content-Type");
		xmlNewProp(meta, BAD_CAST"content", BAD_CAST newcontent);
		return(0);
	    }
	    if (xmlStrEqual(cur->name, BAD_CAST"head"))
		goto found_head;
	    if (xmlStrEqual(cur->name, BAD_CAST"meta"))
		goto found_meta;
*/
	    if (xmlStrcasecmp(cur->name, BAD_CAST"html") == 0)
		break;
	    if (xmlStrcasecmp(cur->name, BAD_CAST"head") == 0)
		goto found_head;
	    if (xmlStrcasecmp(cur->name, BAD_CAST"meta") == 0)
		goto found_meta;
	}
	cur = cur->next;
    }
    if (cur == NULL)
	return(-1);
    cur = cur->children;

    /*
     * Search the head
     */
    while (cur != NULL) {
	if (cur->name != NULL) {
/*
	    if (xmlStrEqual(cur->name, BAD_CAST"head"))
		break;
	    if (xmlStrEqual(cur->name, BAD_CAST"body")) {
		if (encoding == NULL)
		    return(0);
		meta = xmlNewDocNode(doc, NULL, BAD_CAST"head", NULL);
		xmlAddPrevSibling(cur, meta);
		cur = meta;
		meta = xmlNewDocNode(doc, NULL, BAD_CAST"meta", NULL);
		xmlAddChild(cur, meta);
		xmlNewProp(meta, BAD_CAST"http-equiv", BAD_CAST"Content-Type");
		xmlNewProp(meta, BAD_CAST"content", BAD_CAST newcontent);
		return(0);
	    }
	    if (xmlStrEqual(cur->name, BAD_CAST"meta"))
		goto found_meta;
*/
	    if (xmlStrcasecmp(cur->name, BAD_CAST"head") == 0)
		break;
	    if (xmlStrcasecmp(cur->name, BAD_CAST"meta") == 0)
		goto found_meta;
	}
	cur = cur->next;
    }
    if (cur == NULL)
	return(-1);
found_head:
    if (cur->children == NULL) {
	if (encoding == NULL)
	    return(0);
	meta = xmlNewDocNode(doc, NULL, BAD_CAST"meta", NULL);
	xmlAddChild(cur, meta);
	xmlNewProp(meta, BAD_CAST"content", BAD_CAST newcontent);
	xmlNewProp(meta, BAD_CAST"http-equiv", BAD_CAST"Content-Type");
	return(0);
    }
    cur = cur->children;

found_meta:
    if (encoding != NULL) {
	/*
	 * Create a new Meta element with the right aatributes
	 */

	meta = xmlNewDocNode(doc, NULL, BAD_CAST"meta", NULL);
	xmlAddPrevSibling(cur, meta);
	xmlNewProp(meta, BAD_CAST"content", BAD_CAST newcontent);
	xmlNewProp(meta, BAD_CAST"http-equiv", BAD_CAST"Content-Type");
    }

    /*
     * Search and destroy all the remaining the meta elements carrying
     * encoding informations
     */
    while (cur != NULL) {
	if (cur->name != NULL) {
	    if (xmlStrcasecmp(cur->name, BAD_CAST"meta") == 0) {
		xmlAttrPtr attr = cur->properties;
		int http;
		const xmlChar *value;
                int same_charset;

		content = NULL;
		http = 0;
                same_charset = 0;
		while (attr != NULL) {
		    if ((attr->children != NULL) &&
		        (attr->children->type == XML_TEXT_NODE) &&
		        (attr->children->next == NULL)) {
#ifndef XML_USE_BUFFER_CONTENT
			value = attr->children->content;
#else
			value = xmlBufferContent(attr->children->content);
#endif
			if ((!xmlStrcasecmp(attr->name, BAD_CAST"http-equiv"))
			 && (!xmlStrcasecmp(value, BAD_CAST"Content-Type")))
			    http = 1;
			else 
                        {
                           if ((value != NULL) && 
				(!xmlStrcasecmp(attr->name, BAD_CAST"content")))
			      content = value;
			   else 
			     if ((!xmlStrcasecmp(attr->name, BAD_CAST"charset"))
			 		&& (!xmlStrcasecmp(value, encoding)))
			    same_charset = 1;
                        }
		        if ((http != 0) && (content != NULL) && (same_charset != 0))
			    break;
		    }
		    attr = attr->next;
		}
		if ((http != 0) && (content != NULL) && (same_charset != 0)) {
		    meta = cur;
		    cur = cur->next;
		    xmlUnlinkNode(meta);
                    xmlFreeNode(meta);
		    continue;
		}

	    }
	}
	cur = cur->next;
    }
    return(0);
}

/************************************************************************
 *									*
 *   		Dumping HTML tree content to a simple buffer		*
 *									*
 ************************************************************************/

static void
htmlDocContentDump(xmlBufferPtr buf, xmlDocPtr cur);

/**
 * htmlDtdDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * 
 * Dump the HTML document DTD, if any.
 */
static void
htmlDtdDump(xmlBufferPtr buf, xmlDocPtr doc) {
    xmlDtdPtr cur = doc->intSubset;

    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlDtdDump : no internal subset\n");
	return;
    }
    xmlBufferWriteChar(buf, "<!DOCTYPE ");
    xmlBufferWriteCHAR(buf, cur->name);
    if (cur->ExternalID != NULL) {
	xmlBufferWriteChar(buf, " PUBLIC ");
	xmlBufferWriteQuotedString(buf, cur->ExternalID);
	if (cur->SystemID != NULL) {
	    xmlBufferWriteChar(buf, " ");
	    xmlBufferWriteQuotedString(buf, cur->SystemID);
	} 
    }  else if (cur->SystemID != NULL) {
	xmlBufferWriteChar(buf, " SYSTEM ");
	xmlBufferWriteQuotedString(buf, cur->SystemID);
    }
    xmlBufferWriteChar(buf, ">\n");
}

/**
 * htmlAttrDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the attribute pointer
 *
 * Dump an HTML attribute
 */
static void
htmlAttrDump(xmlBufferPtr buf, xmlDocPtr doc, xmlAttrPtr cur) {
    xmlChar *value;

    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlAttrDump : property == NULL\n");
	return;
    }
    xmlBufferWriteChar(buf, " ");
    xmlBufferWriteCHAR(buf, cur->name);
    if (cur->children != NULL) {
	value = xmlNodeListGetString(doc, cur->children, 0);
	if (value) {
	    xmlBufferWriteChar(buf, "=");
	    xmlBufferWriteQuotedString(buf, value);
	    xmlFree(value);
	} else  {
	    xmlBufferWriteChar(buf, "=\"\"");
	}
    }
}

/**
 * htmlAttrListDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the first attribute pointer
 *
 * Dump a list of HTML attributes
 */
static void
htmlAttrListDump(xmlBufferPtr buf, xmlDocPtr doc, xmlAttrPtr cur) {
    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlAttrListDump : property == NULL\n");
	return;
    }
    while (cur != NULL) {
        htmlAttrDump(buf, doc, cur);
	cur = cur->next;
    }
}


void
htmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur);
/**
 * htmlNodeListDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the first node
 *
 * Dump an HTML node list, recursive behaviour,children are printed too.
 */
static void
htmlNodeListDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur) {
    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlNodeListDump : node == NULL\n");
	return;
    }
    while (cur != NULL) {
        htmlNodeDump(buf, doc, cur);
	cur = cur->next;
    }
}

/**
 * htmlNodeDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the current node
 *
 * Dump an HTML node, recursive behaviour,children are printed too.
 */
void
htmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur) {
    htmlElemDescPtr info;

    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlNodeDump : node == NULL\n");
	return;
    }
    /*
     * Special cases.
     */
    if (cur->type == XML_DTD_NODE)
	return;
    if (cur->type == XML_HTML_DOCUMENT_NODE) {
	htmlDocContentDump(buf, (xmlDocPtr) cur);
	return;
    }
    if (cur->type == HTML_TEXT_NODE) {
	if (cur->content != NULL) {
	    if ((cur->name == xmlStringText) ||
		(cur->name != xmlStringTextNoenc)) {
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
	    } else {
		xmlBufferWriteCHAR(buf, cur->content);
	    }
	}
	return;
    }
    if (cur->type == HTML_COMMENT_NODE) {
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
    if (cur->type == HTML_ENTITY_REF_NODE) {
        xmlBufferWriteChar(buf, "&");
	xmlBufferWriteCHAR(buf, cur->name);
        xmlBufferWriteChar(buf, ";");
	return;
    }

    /*
     * Get specific HTmL info for taht node.
     */
    info = htmlTagLookup(cur->name);

    xmlBufferWriteChar(buf, "<");
    xmlBufferWriteCHAR(buf, cur->name);
    if (cur->properties != NULL)
        htmlAttrListDump(buf, doc, cur->properties);

    if ((info != NULL) && (info->empty)) {
        xmlBufferWriteChar(buf, ">");
	if (cur->next != NULL) {
	    if ((cur->next->type != HTML_TEXT_NODE) &&
		(cur->next->type != HTML_ENTITY_REF_NODE))
		xmlBufferWriteChar(buf, "\n");
	}
	return;
    }
    if ((cur->content == NULL) && (cur->children == NULL)) {
        if ((info != NULL) && (info->endTag != 0))
	    xmlBufferWriteChar(buf, ">");
	else {
	    xmlBufferWriteChar(buf, "></");
	    xmlBufferWriteCHAR(buf, cur->name);
	    xmlBufferWriteChar(buf, ">");
	}
	if (cur->next != NULL) {
	    if ((cur->next->type != HTML_TEXT_NODE) &&
		(cur->next->type != HTML_ENTITY_REF_NODE))
		xmlBufferWriteChar(buf, "\n");
	}
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
        if ((cur->children->type != HTML_TEXT_NODE) &&
	    (cur->children->type != HTML_ENTITY_REF_NODE) &&
	    (cur->children != cur->last))
	    xmlBufferWriteChar(buf, "\n");
	htmlNodeListDump(buf, doc, cur->children);
        if ((cur->last->type != HTML_TEXT_NODE) &&
	    (cur->last->type != HTML_ENTITY_REF_NODE) &&
	    (cur->children != cur->last))
	    xmlBufferWriteChar(buf, "\n");
    }
    if (!htmlIsAutoClosed(doc, cur)) {
	xmlBufferWriteChar(buf, "</");
	xmlBufferWriteCHAR(buf, cur->name);
	xmlBufferWriteChar(buf, ">");
    }
#if 0
    if (!htmlIsAutoClosed(doc, cur)) {
	xmlBufferWriteChar(buf, "</");
	xmlBufferWriteCHAR(buf, cur->name);
	xmlBufferWriteChar(buf, ">");
    }
#else
    xmlBufferWriteChar(buf, "</");
    xmlBufferWriteCHAR(buf, cur->name);
    xmlBufferWriteChar(buf, ">");
#endif
    if (cur->next != NULL) {
        if ((cur->next->type != HTML_TEXT_NODE) &&
	    (cur->next->type != HTML_ENTITY_REF_NODE))
	    xmlBufferWriteChar(buf, "\n");
    }
}

/**
 * htmlNodeDumpFile:
 * @out:  the FILE pointer
 * @doc:  the document
 * @cur:  the current node
 *
 * Dump an HTML node, recursive behaviour,children are printed too.
 */
void
htmlNodeDumpFile(FILE *out, xmlDocPtr doc, xmlNodePtr cur) {
    xmlBufferPtr buf;

    buf = xmlBufferCreate();
    if (buf == NULL) return;
    htmlNodeDump(buf, doc, cur);
    xmlBufferDump(out, buf);
    xmlBufferFree(buf);
}

/**
 * htmlDocContentDump:
 * @buf:  the HTML buffer output
 * @cur:  the document
 *
 * Dump an HTML document.
 */
static void
htmlDocContentDump(xmlBufferPtr buf, xmlDocPtr cur) {
    int type;

    /*
     * force to output the stuff as HTML, especially for entities
     */
    type = cur->type;
    cur->type = XML_HTML_DOCUMENT_NODE;
    if (cur->intSubset != NULL)
        htmlDtdDump(buf, cur);
    else {
	/* Default to HTML-4.0 transitionnal @@@@ */
	xmlBufferWriteChar(buf, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\" \"http://www.w3.org/TR/REC-html40/loose.dtd\">");

    }
    if (cur->children != NULL) {
        htmlNodeListDump(buf, cur, cur->children);
    }
    xmlBufferWriteChar(buf, "\n");
    cur->type = (xmlElementType) type;
}

/**
 * htmlDocDumpMemory:
 * @cur:  the document
 * @mem:  OUT: the memory pointer
 * @size:  OUT: the memory lenght
 *
 * Dump an HTML document in memory and return the xmlChar * and it's size.
 * It's up to the caller to free the memory.
 */
void
htmlDocDumpMemory(xmlDocPtr cur, xmlChar**mem, int *size) {
    xmlBufferPtr buf;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        xmlGenericError(xmlGenericErrorContext,
		"htmlxmlDocDumpMemory : document == NULL\n");
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
    htmlDocContentDump(buf, cur);
    *mem = buf->content;
    *size = buf->use;
    xmlFree(buf);
}


/************************************************************************
 *									*
 *   		Dumping HTML tree content to an I/O output buffer	*
 *									*
 ************************************************************************/

/**
 * htmlDtdDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @encoding:  the encoding string
 * 
 * TODO: check whether encoding is needed
 *
 * Dump the HTML document DTD, if any.
 */
static void
htmlDtdDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc,
	          const char *encoding ATTRIBUTE_UNUSED) {
    xmlDtdPtr cur = doc->intSubset;

    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlDtdDump : no internal subset\n");
	return;
    }
    xmlOutputBufferWriteString(buf, "<!DOCTYPE ");
    xmlOutputBufferWriteString(buf, (const char *)cur->name);
    if (cur->ExternalID != NULL) {
	xmlOutputBufferWriteString(buf, " PUBLIC ");
	xmlBufferWriteQuotedString(buf->buffer, cur->ExternalID);
	if (cur->SystemID != NULL) {
	    xmlOutputBufferWriteString(buf, " ");
	    xmlBufferWriteQuotedString(buf->buffer, cur->SystemID);
	} 
    }  else if (cur->SystemID != NULL) {
	xmlOutputBufferWriteString(buf, " SYSTEM ");
	xmlBufferWriteQuotedString(buf->buffer, cur->SystemID);
    }
    xmlOutputBufferWriteString(buf, ">\n");
}

/**
 * htmlAttrDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the attribute pointer
 * @encoding:  the encoding string
 *
 * Dump an HTML attribute
 */
static void
htmlAttrDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc, xmlAttrPtr cur,
	           const char *encoding ATTRIBUTE_UNUSED) {
    xmlChar *value;

    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlAttrDump : property == NULL\n");
	return;
    }
    xmlOutputBufferWriteString(buf, " ");
    xmlOutputBufferWriteString(buf, (const char *)cur->name);
    if (cur->children != NULL) {
	value = xmlNodeListGetString(doc, cur->children, 0);
	if (value) {
	    xmlOutputBufferWriteString(buf, "=");
	    xmlBufferWriteQuotedString(buf->buffer, value);
	    xmlFree(value);
	} else  {
	    xmlOutputBufferWriteString(buf, "=\"\"");
	}
    }
}

/**
 * htmlAttrListDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the first attribute pointer
 * @encoding:  the encoding string
 *
 * Dump a list of HTML attributes
 */
static void
htmlAttrListDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc, xmlAttrPtr cur, const char *encoding) {
    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlAttrListDump : property == NULL\n");
	return;
    }
    while (cur != NULL) {
        htmlAttrDumpOutput(buf, doc, cur, encoding);
	cur = cur->next;
    }
}


void htmlNodeDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc,
	                xmlNodePtr cur, const char *encoding);

/**
 * htmlNodeListDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the first node
 * @encoding:  the encoding string
 *
 * Dump an HTML node list, recursive behaviour,children are printed too.
 */
static void
htmlNodeListDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, const char *encoding) {
    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlNodeListDump : node == NULL\n");
	return;
    }
    while (cur != NULL) {
        htmlNodeDumpOutput(buf, doc, cur, encoding);
	cur = cur->next;
    }
}

/**
 * htmlNodeDumpOutput:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the current node
 * @encoding:  the encoding string
 *
 * Dump an HTML node, recursive behaviour,children are printed too.
 */
void
htmlNodeDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc,
	           xmlNodePtr cur, const char *encoding) {
    htmlElemDescPtr info;

    if (cur == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"htmlNodeDump : node == NULL\n");
	return;
    }
    /*
     * Special cases.
     */
    if (cur->type == XML_DTD_NODE)
	return;
    if (cur->type == XML_HTML_DOCUMENT_NODE) {
	htmlDocContentDumpOutput(buf, (xmlDocPtr) cur, encoding);
	return;
    }
    if (cur->type == HTML_TEXT_NODE) {
	if (cur->content != NULL) {
	    if ((cur->name == xmlStringText) ||
		(cur->name != xmlStringTextNoenc)) {
		xmlChar *buffer;

#ifndef XML_USE_BUFFER_CONTENT
		buffer = xmlEncodeEntitiesReentrant(doc, cur->content);
#else
		buffer = xmlEncodeEntitiesReentrant(doc, 
					    xmlBufferContent(cur->content));
#endif 
		if (buffer != NULL) {
		    xmlOutputBufferWriteString(buf, (const char *)buffer);
		    xmlFree(buffer);
		}
	    } else {
		xmlOutputBufferWriteString(buf, (const char *)cur->content);
	    }
	}
	return;
    }
    if (cur->type == HTML_COMMENT_NODE) {
	if (cur->content != NULL) {
	    xmlOutputBufferWriteString(buf, "<!--");
#ifndef XML_USE_BUFFER_CONTENT
	    xmlOutputBufferWriteString(buf, (const char *)cur->content);
#else
	    xmlOutputBufferWriteString(buf, (const char *)
		                       xmlBufferContent(cur->content));
#endif
	    xmlOutputBufferWriteString(buf, "-->");
	}
	return;
    }
    if (cur->type == HTML_ENTITY_REF_NODE) {
        xmlOutputBufferWriteString(buf, "&");
	xmlOutputBufferWriteString(buf, (const char *)cur->name);
        xmlOutputBufferWriteString(buf, ";");
	return;
    }
    if (cur->type == HTML_PRESERVE_NODE) {
	if (cur->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT
	    xmlOutputBufferWriteString(buf, (const char *)cur->content);
#else
	    xmlOutputBufferWriteString(buf, (const char *)
		                       xmlBufferContent(cur->content));
#endif
	}
	return;
    }

    /*
     * Get specific HTML info for taht node.
     */
    info = htmlTagLookup(cur->name);

    xmlOutputBufferWriteString(buf, "<");
    xmlOutputBufferWriteString(buf, (const char *)cur->name);
    if (cur->properties != NULL)
        htmlAttrListDumpOutput(buf, doc, cur->properties, encoding);

    if ((info != NULL) && (info->empty)) {
        xmlOutputBufferWriteString(buf, ">");
	if (cur->next != NULL) {
	    if ((cur->next->type != HTML_TEXT_NODE) &&
		(cur->next->type != HTML_ENTITY_REF_NODE))
		xmlOutputBufferWriteString(buf, "\n");
	}
	return;
    }
    if ((cur->content == NULL) && (cur->children == NULL)) {
        if ((info != NULL) && (info->saveEndTag != 0) &&
/*
	    (xmlStrcasecmp(BAD_CAST info->name, BAD_CAST "html")) && 
	    (xmlStrcasecmp(BAD_CAST info->name, BAD_CAST "body"))) {
*/
	    (strcmp(info->name, "html")) && (strcmp(info->name, "body"))) {
	    xmlOutputBufferWriteString(buf, ">");
	} else {
	    xmlOutputBufferWriteString(buf, "></");
	    xmlOutputBufferWriteString(buf, (const char *)cur->name);
	    xmlOutputBufferWriteString(buf, ">");
	}
	if (cur->next != NULL) {
	    if ((cur->next->type != HTML_TEXT_NODE) &&
		(cur->next->type != HTML_ENTITY_REF_NODE))
		xmlOutputBufferWriteString(buf, "\n");
	}
	return;
    }
    xmlOutputBufferWriteString(buf, ">");
    if (cur->content != NULL) {
	    /*
	     * Uses the OutputBuffer property to automatically convert
	     * invalids to charrefs
	     */

#ifndef XML_USE_BUFFER_CONTENT
            xmlOutputBufferWriteString(buf, (const char *) cur->content);
#else
            xmlOutputBufferWriteString(buf, 
		           (const char *) xmlBufferContent(cur->content));
#endif 
    }
    if (cur->children != NULL) {
        if ((cur->children->type != HTML_TEXT_NODE) &&
	    (cur->children->type != HTML_ENTITY_REF_NODE) &&
	    (cur->children != cur->last))
	    xmlOutputBufferWriteString(buf, "\n");
	htmlNodeListDumpOutput(buf, doc, cur->children, encoding);
        if ((cur->last->type != HTML_TEXT_NODE) &&
	    (cur->last->type != HTML_ENTITY_REF_NODE) &&
	    (cur->children != cur->last))
	    xmlOutputBufferWriteString(buf, "\n");
    }
#if 0
    if (!htmlIsAutoClosed(doc, cur)) {
	xmlOutputBufferWriteString(buf, "</");
	xmlOutputBufferWriteString(buf, (const char *)cur->name);
	xmlOutputBufferWriteString(buf, ">");
    }
#else
    xmlOutputBufferWriteString(buf, "</");
    xmlOutputBufferWriteString(buf, (const char *)cur->name);
    xmlOutputBufferWriteString(buf, ">");
#endif
    if (cur->next != NULL) {
        if ((cur->next->type != HTML_TEXT_NODE) &&
	    (cur->next->type != HTML_ENTITY_REF_NODE))
	    xmlOutputBufferWriteString(buf, "\n");
    }
}

/**
 * htmlDocContentDump:
 * @buf:  the HTML buffer output
 * @cur:  the document
 * @encoding:  the encoding string
 *
 * Dump an HTML document.
 */
void
htmlDocContentDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr cur, const char *encoding) {
    int type;

    /*
     * force to output the stuff as HTML, especially for entities
     */
    type = cur->type;
    cur->type = XML_HTML_DOCUMENT_NODE;
    if (cur->intSubset != NULL) {
        htmlDtdDumpOutput(buf, cur, NULL);
#if 0
    /* Disabled for XSLT output */
    } else {
	/* Default to HTML-4.0 transitionnal @@@@ */
	xmlOutputBufferWriteString(buf, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\" \"http://www.w3.org/TR/REC-html40/loose.dtd\">\n");

#endif
    }
    if (cur->children != NULL) {
        htmlNodeListDumpOutput(buf, cur, cur->children, encoding);
    }
    xmlOutputBufferWriteString(buf, "\n");
    cur->type = (xmlElementType) type;
}

/************************************************************************
 *									*
 *		Saving functions front-ends				*
 *									*
 ************************************************************************/

/**
 * htmlDocDump:
 * @f:  the FILE*
 * @cur:  the document
 *
 * Dump an HTML document to an open FILE.
 *
 * returns: the number of byte written or -1 in case of failure.
 */
int
htmlDocDump(FILE *f, xmlDocPtr cur) {
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler = NULL;
    const char *encoding;
    int ret;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        xmlGenericError(xmlGenericErrorContext,
		"htmlDocDump : document == NULL\n");
#endif
	return(-1);
    }

    encoding = (const char *) htmlGetMetaEncoding(cur);

    if (encoding != NULL) {
	xmlCharEncoding enc;

	enc = xmlParseCharEncoding(encoding);
	if (enc != cur->charset) {
	    if (cur->charset != XML_CHAR_ENCODING_UTF8) {
		/*
		 * Not supported yet
		 */
		return(-1);
	    }

	    handler = xmlFindCharEncodingHandler(encoding);
	    if (handler == NULL)
		return(-1);
	}
    }

    /*
     * Fallback to HTML or ASCII when the encoding is unspecified
     */
    if (handler == NULL)
	handler = xmlFindCharEncodingHandler("HTML");
    if (handler == NULL)
	handler = xmlFindCharEncodingHandler("ascii");

    buf = xmlOutputBufferCreateFile(f, handler);
    if (buf == NULL) return(-1);
    htmlDocContentDumpOutput(buf, cur, NULL);

    ret = xmlOutputBufferClose(buf);
    return(ret);
}

/**
 * htmlSaveFile:
 * @filename:  the filename (or URL)
 * @cur:  the document
 *
 * Dump an HTML document to a file. If @filename is "-" the stdout file is
 * used.
 * returns: the number of byte written or -1 in case of failure.
 */
int
htmlSaveFile(const char *filename, xmlDocPtr cur) {
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler = NULL;
    const char *encoding;
    int ret;

    encoding = (const char *) htmlGetMetaEncoding(cur);

    if (encoding != NULL) {
	xmlCharEncoding enc;

	enc = xmlParseCharEncoding(encoding);
	if (enc != cur->charset) {
	    if (cur->charset != XML_CHAR_ENCODING_UTF8) {
		/*
		 * Not supported yet
		 */
		return(-1);
	    }

	    handler = xmlFindCharEncodingHandler(encoding);
	    if (handler == NULL)
		return(-1);
	}
    }

    /*
     * Fallback to HTML or ASCII when the encoding is unspecified
     */
    if (handler == NULL)
	handler = xmlFindCharEncodingHandler("HTML");
    if (handler == NULL)
	handler = xmlFindCharEncodingHandler("ascii");

    /* 
     * save the content to a temp buffer.
     */
    buf = xmlOutputBufferCreateFilename(filename, handler, cur->compression);
    if (buf == NULL) return(0);

    htmlDocContentDumpOutput(buf, cur, NULL);

    ret = xmlOutputBufferClose(buf);
    return(ret);
}

/**
 * htmlSaveFileEnc:
 * @filename:  the filename
 * @cur:  the document
 *
 * Dump an HTML document to a file using a given encoding.
 * 
 * returns: the number of byte written or -1 in case of failure.
 */
int
htmlSaveFileEnc(const char *filename, xmlDocPtr cur, const char *encoding) {
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler = NULL;
    int ret;

    if (encoding != NULL) {
	xmlCharEncoding enc;

	enc = xmlParseCharEncoding(encoding);
	if (enc != cur->charset) {
	    if (cur->charset != XML_CHAR_ENCODING_UTF8) {
		/*
		 * Not supported yet
		 */
		return(-1);
	    }

	    handler = xmlFindCharEncodingHandler(encoding);
	    if (handler == NULL)
		return(-1);
            htmlSetMetaEncoding(cur, (const xmlChar *) encoding);
	}
    } else {
	htmlSetMetaEncoding(cur, (const xmlChar *) "UTF-8");
    }

    /*
     * Fallback to HTML or ASCII when the encoding is unspecified
     */
    if (handler == NULL)
	handler = xmlFindCharEncodingHandler("HTML");
    if (handler == NULL)
	handler = xmlFindCharEncodingHandler("ascii");

    /* 
     * save the content to a temp buffer.
     */
    buf = xmlOutputBufferCreateFilename(filename, handler, 0);
    if (buf == NULL) return(0);

    htmlDocContentDumpOutput(buf, cur, encoding);

    ret = xmlOutputBufferClose(buf);
    return(ret);
}
#endif /* LIBXML_HTML_ENABLED */
