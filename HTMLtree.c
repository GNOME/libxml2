/*
 * HTMLtree.c : implemetation of access function for an HTML tree.
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

#include "xmlversion.h"
#ifdef LIBXML_HTML_ENABLED

#include <stdio.h>
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
        fprintf(stderr, "htmlDtdDump : no internal subset\n");
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
        fprintf(stderr, "htmlAttrDump : property == NULL\n");
	return;
    }
    xmlBufferWriteChar(buf, " ");
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
        fprintf(stderr, "htmlAttrListDump : property == NULL\n");
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
        fprintf(stderr, "htmlNodeListDump : node == NULL\n");
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
        fprintf(stderr, "htmlNodeDump : node == NULL\n");
	return;
    }
    /*
     * Special cases.
     */
    if (cur->type == XML_HTML_DOCUMENT_NODE) {
	htmlDocContentDump(buf, (xmlDocPtr) cur);
	return;
    }
    if (cur->type == HTML_TEXT_NODE) {
	if (cur->content != NULL) {
            xmlChar *buffer;

	    /* uses the HTML encoding routine !!!!!!!!!! */
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
    cur->type = type;
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
        fprintf(stderr, "htmlxmlDocDumpMemory : document == NULL\n");
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
    memset(buf, -1, sizeof(xmlBuffer));
    xmlFree(buf);
}


/**
 * htmlDocDump:
 * @f:  the FILE*
 * @cur:  the document
 *
 * Dump an HTML document to an open FILE.
 */
void
htmlDocDump(FILE *f, xmlDocPtr cur) {
    xmlBufferPtr buf;

    if (cur == NULL) {
#ifdef DEBUG_TREE
        fprintf(stderr, "htmlDocDump : document == NULL\n");
#endif
	return;
    }
    buf = xmlBufferCreate();
    if (buf == NULL) return;
    htmlDocContentDump(buf, cur);
    xmlBufferDump(f, buf);
    xmlBufferFree(buf);
}

/**
 * htmlSaveFile:
 * @filename:  the filename
 * @cur:  the document
 *
 * Dump an HTML document to a file.
 * 
 * returns: the number of byte written or -1 in case of failure.
 */
int
htmlSaveFile(const char *filename, xmlDocPtr cur) {
    xmlBufferPtr buf;
    FILE *output = NULL;
    int ret;

    /* 
     * save the content to a temp buffer.
     */
    buf = xmlBufferCreate();
    if (buf == NULL) return(0);
    htmlDocContentDump(buf, cur);

    output = fopen(filename, "w");
    if (output == NULL) return(-1);
    ret = xmlBufferDump(output, buf);
    fclose(output);

    xmlBufferFree(buf);
    return(ret * sizeof(xmlChar));
}

#endif /* LIBXML_HTML_ENABLED */
