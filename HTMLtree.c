/*
 * HTMLtree.c : implemetation of access function for an HTML tree.
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

#include "tree.h"
#include "entities.h"
#include "valid.h"

#define HTML_TEXT_NODE		XML_TEXT_NODE
#define HTML_ENTITY_REF_NODE	XML_ENTITY_REF_NODE
#define HTML_COMMENT_NODE	XML_COMMENT_NODE

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

    /* TODO !!! a lot more things to dump ... */
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
    CHAR *value;

    if (cur == NULL) {
        fprintf(stderr, "htmlAttrDump : property == NULL\n");
	return;
    }
    xmlBufferWriteChar(buf, " ");
    xmlBufferWriteCHAR(buf, cur->name);
    value = xmlNodeListGetString(doc, cur->val, 0);
    if (value) {
	xmlBufferWriteChar(buf, "=");
	xmlBufferWriteQuotedString(buf, value);
	free(value);
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


static void
htmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level);
/**
 * htmlNodeListDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the first node
 * @level: the imbrication level for indenting
 *
 * Dump an HTML node list, recursive behaviour,children are printed too.
 */
static void
htmlNodeListDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level) {
    int i;

    if (cur == NULL) {
        fprintf(stderr, "htmlNodeListDump : node == NULL\n");
	return;
    }
    while (cur != NULL) {
        if ((cur->type != HTML_TEXT_NODE) &&
	    (cur->type != HTML_ENTITY_REF_NODE)) {
		xmlBufferWriteChar(buf, "\n");
	}
        htmlNodeDump(buf, doc, cur, level);
	cur = cur->next;
    }
}

/**
 * htmlNodeDump:
 * @buf:  the HTML buffer output
 * @doc:  the document
 * @cur:  the current node
 * @level: the imbrication level for indenting
 *
 * Dump an HTML node, recursive behaviour,children are printed too.
 */
static void
htmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur, int level) {
    int i;

    if (cur == NULL) {
        fprintf(stderr, "htmlNodeDump : node == NULL\n");
	return;
    }
    if (cur->type == HTML_TEXT_NODE) {
	if (cur->content != NULL) {
            CHAR *buffer;

            buffer = xmlEncodeEntitiesReentrant(doc, cur->content);
	    if (buffer != NULL) {
		xmlBufferWriteCHAR(buf, buffer);
		free(buffer);
	    }
	}
	return;
    }
    if (cur->type == HTML_COMMENT_NODE) {
	if (cur->content != NULL) {
	    xmlBufferWriteChar(buf, "<!--");
	    xmlBufferWriteCHAR(buf, cur->content);
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

    xmlBufferWriteChar(buf, "<");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlBufferWriteCHAR(buf, cur->ns->prefix);
	xmlBufferWriteChar(buf, ":");
    }

    xmlBufferWriteCHAR(buf, cur->name);
    if (cur->nsDef)
        xmlNsListDump(buf, cur->nsDef);
    if (cur->properties != NULL)
        htmlAttrListDump(buf, doc, cur->properties);

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
	    free(buffer);
	}
    }
    if (cur->childs != NULL) {
	htmlNodeListDump(buf, doc, cur->childs, level + 1);
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
 * htmlDocContentDump:
 * @buf:  the HTML buffer output
 * @cur:  the document
 *
 * Dump an HTML document.
 */
static void
htmlDocContentDump(xmlBufferPtr buf, xmlDocPtr cur) {
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
        htmlDtdDump(buf, cur);
    if (cur->root != NULL) {
        htmlNodeDump(buf, cur, cur->root, 0);
    }
}

/**
 * htmlDocDumpMemory:
 * @cur:  the document
 * @mem:  OUT: the memory pointer
 * @size:  OUT: the memory lenght
 *
 * Dump an HTML document in memory and return the CHAR * and it's size.
 * It's up to the caller to free the memory.
 */
void
htmlDocDumpMemory(xmlDocPtr cur, CHAR**mem, int *size) {
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
    htmlDocContentDump(buf, cur);
    *mem = buf->content;
    *size = buf->use;
    memset(buf, -1, sizeof(xmlBuffer));
    free(buf);
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
        fprintf(stderr, "xmlDocDump : document == NULL\n");
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
    return(ret * sizeof(CHAR));
}

