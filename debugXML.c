/*
 * debugXML.c : This is a set of routines used for debugging the tree
 *              produced by the XML parser.
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "xmlmemory.h"
#include "tree.h"
#include "parser.h"
#include "debugXML.h"
#include "HTMLtree.h"
#include "HTMLparser.h"

#define IS_BLANK(c)							\
  (((c) == '\n') || ((c) == '\r') || ((c) == '\t') || ((c) == ' '))

void xmlDebugDumpString(FILE *output, const xmlChar *str) {
    int i;
    for (i = 0;i < 40;i++)
        if (str[i] == 0) return;
	else if (IS_BLANK(str[i])) fputc(' ', output);
	else fputc(str[i], output);
    fprintf(output, "...");
}

void xmlDebugDumpNamespace(FILE *output, xmlNsPtr ns, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);
    if (ns->type == XML_GLOBAL_NAMESPACE)
        fprintf(output, "old ");
    if (ns->prefix != NULL)
	fprintf(output, "namespace %s href=", ns->prefix);
    else
	fprintf(output, "default namespace href=");

    xmlDebugDumpString(output, ns->href);
    fprintf(output, "\n");
}

void xmlDebugDumpNamespaceList(FILE *output, xmlNsPtr ns, int depth) {
    while (ns != NULL) {
        xmlDebugDumpNamespace(output, ns, depth);
	ns = ns->next;
    }
}

void xmlDebugDumpEntity(FILE *output, xmlEntityPtr ent, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);
    switch (ent->type) {
        case XML_INTERNAL_GENERAL_ENTITY:
	    fprintf(output, "INTERNAL_GENERAL_ENTITY ");
	    break;
        case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
	    fprintf(output, "EXTERNAL_GENERAL_PARSED_ENTITY ");
	    break;
        case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
	    fprintf(output, "EXTERNAL_GENERAL_UNPARSED_ENTITY ");
	    break;
        case XML_INTERNAL_PARAMETER_ENTITY:
	    fprintf(output, "INTERNAL_PARAMETER_ENTITY ");
	    break;
        case XML_EXTERNAL_PARAMETER_ENTITY:
	    fprintf(output, "EXTERNAL_PARAMETER_ENTITY ");
	    break;
	default:
	    fprintf(output, "ENTITY_%d ! ", ent->type);
    }
    fprintf(output, "%s\n", ent->name);
    if (ent->ExternalID) {
        fprintf(output, shift);
        fprintf(output, "ExternalID=%s\n", ent->ExternalID);
    }
    if (ent->SystemID) {
        fprintf(output, shift);
        fprintf(output, "SystemID=%s\n", ent->SystemID);
    }
    if (ent->content) {
        fprintf(output, shift);
	fprintf(output, "content=");
	xmlDebugDumpString(output, ent->content);
	fprintf(output, "\n");
    }
}

void xmlDebugDumpAttr(FILE *output, xmlAttrPtr attr, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);
    fprintf(output, "ATTRIBUTE %s\n", attr->name);
    if (attr->val != NULL) 
        xmlDebugDumpNodeList(output, attr->val, depth + 1);
}

void xmlDebugDumpAttrList(FILE *output, xmlAttrPtr attr, int depth) {
    while (attr != NULL) {
        xmlDebugDumpAttr(output, attr, depth);
	attr = attr->next;
    }
}

void xmlDebugDumpOneNode(FILE *output, xmlNodePtr node, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);
    switch (node->type) {
	case XML_ELEMENT_NODE:
	    fprintf(output, "ELEMENT ");
	    if (node->ns != NULL)
	        fprintf(output, "%s:%s\n", node->ns->prefix, node->name);
	    else
	        fprintf(output, "%s\n", node->name);
	    break;
	case XML_ATTRIBUTE_NODE:
	    fprintf(output, "Error, ATTRIBUTE found here\n");
	    break;
	case XML_TEXT_NODE:
	    fprintf(output, "TEXT\n");
	    break;
	case XML_CDATA_SECTION_NODE:
	    fprintf(output, "CDATA_SECTION\n");
	    break;
	case XML_ENTITY_REF_NODE:
	    fprintf(output, "ENTITY_REF\n");
	    break;
	case XML_ENTITY_NODE:
	    fprintf(output, "ENTITY\n");
	    break;
	case XML_PI_NODE:
	    fprintf(output, "PI %s\n", node->name);
	    break;
	case XML_COMMENT_NODE:
	    fprintf(output, "COMMENT\n");
	    break;
	case XML_DOCUMENT_NODE:
	case XML_HTML_DOCUMENT_NODE:
	    fprintf(output, "Error, DOCUMENT found here\n");
	    break;
	case XML_DOCUMENT_TYPE_NODE:
	    fprintf(output, "DOCUMENT_TYPE\n");
	    break;
	case XML_DOCUMENT_FRAG_NODE:
	    fprintf(output, "DOCUMENT_FRAG\n");
	    break;
	case XML_NOTATION_NODE:
	    fprintf(output, "NOTATION\n");
	    break;
	default:
	    fprintf(output, "NODE_%d\n", node->type);
    }
    if (node->doc == NULL) {
        fprintf(output, shift);
	fprintf(output, "doc == NULL !!!\n");
    }
    if (node->nsDef != NULL) 
        xmlDebugDumpNamespaceList(output, node->nsDef, depth + 1);
    if (node->properties != NULL)
	xmlDebugDumpAttrList(output, node->properties, depth + 1);
    if (node->type != XML_ENTITY_REF_NODE) {
	if (node->content != NULL) {
	    fprintf(output, shift);
	    fprintf(output, "content=");
#ifndef XML_USE_BUFFER_CONTENT	    
	    xmlDebugDumpString(output, node->content);
#else
	    xmlDebugDumpString(output, xmlBufferContent(node->content));
#endif
	    fprintf(output, "\n");
	}
    } else {
        xmlEntityPtr ent;
	ent = xmlGetDocEntity(node->doc, node->name);
	if (ent != NULL)
	    xmlDebugDumpEntity(output, ent, depth + 1);
    }
}

void xmlDebugDumpNode(FILE *output, xmlNodePtr node, int depth) {
    xmlDebugDumpOneNode(output, node, depth);
    if (node->childs != NULL)
	xmlDebugDumpNodeList(output, node->childs, depth + 1);
}

void xmlDebugDumpNodeList(FILE *output, xmlNodePtr node, int depth) {
    while (node != NULL) {
        xmlDebugDumpNode(output, node, depth);
	node = node->next;
    }
}


void xmlDebugDumpDocumentHead(FILE *output, xmlDocPtr doc) {
    if (output == NULL) output = stdout;
    if (doc == NULL) {
        fprintf(output, "DOCUMENT == NULL !\n");
	return;
    }

    switch (doc->type) {
	case XML_ELEMENT_NODE:
	    fprintf(output, "Error, ELEMENT found here ");
	    break;
	case XML_ATTRIBUTE_NODE:
	    fprintf(output, "Error, ATTRIBUTE found here\n");
	    break;
	case XML_TEXT_NODE:
	    fprintf(output, "Error, TEXT\n");
	    break;
	case XML_CDATA_SECTION_NODE:
	    fprintf(output, "Error, CDATA_SECTION\n");
	    break;
	case XML_ENTITY_REF_NODE:
	    fprintf(output, "Error, ENTITY_REF\n");
	    break;
	case XML_ENTITY_NODE:
	    fprintf(output, "Error, ENTITY\n");
	    break;
	case XML_PI_NODE:
	    fprintf(output, "Error, PI\n");
	    break;
	case XML_COMMENT_NODE:
	    fprintf(output, "Error, COMMENT\n");
	    break;
	case XML_DOCUMENT_NODE:
	    fprintf(output, "DOCUMENT\n");
	    break;
	case XML_HTML_DOCUMENT_NODE:
	    fprintf(output, "HTML DOCUMENT\n");
	    break;
	case XML_DOCUMENT_TYPE_NODE:
	    fprintf(output, "Error, DOCUMENT_TYPE\n");
	    break;
	case XML_DOCUMENT_FRAG_NODE:
	    fprintf(output, "Error, DOCUMENT_FRAG\n");
	    break;
	case XML_NOTATION_NODE:
	    fprintf(output, "Error, NOTATION\n");
	    break;
	default:
	    fprintf(output, "NODE_%d\n", doc->type);
    }
    if (doc->name != NULL) {
	fprintf(output, "name=");
        xmlDebugDumpString(output, BAD_CAST doc->name);
	fprintf(output, "\n");
    }
    if (doc->version != NULL) {
	fprintf(output, "version=");
        xmlDebugDumpString(output, doc->version);
	fprintf(output, "\n");
    }
    if (doc->encoding != NULL) {
	fprintf(output, "encoding=");
        xmlDebugDumpString(output, doc->encoding);
	fprintf(output, "\n");
    }
    if (doc->standalone)
        fprintf(output, "standalone=true\n");
    if (doc->oldNs != NULL) 
        xmlDebugDumpNamespaceList(output, doc->oldNs, 0);
}

void xmlDebugDumpDocument(FILE *output, xmlDocPtr doc) {
    if (output == NULL) output = stdout;
    if (doc == NULL) {
        fprintf(output, "DOCUMENT == NULL !\n");
	return;
    }
    xmlDebugDumpDocumentHead(output, doc);
    if (((doc->type == XML_DOCUMENT_NODE) ||
         (doc->type == XML_HTML_DOCUMENT_NODE)) &&
        (doc->root != NULL))
        xmlDebugDumpNodeList(output, doc->root, 1);
}    

void xmlDebugDumpEntities(FILE *output, xmlDocPtr doc) {
    int i;
    xmlEntityPtr cur;

    if (output == NULL) output = stdout;
    if (doc == NULL) {
        fprintf(output, "DOCUMENT == NULL !\n");
	return;
    }

    switch (doc->type) {
	case XML_ELEMENT_NODE:
	    fprintf(output, "Error, ELEMENT found here ");
	    break;
	case XML_ATTRIBUTE_NODE:
	    fprintf(output, "Error, ATTRIBUTE found here\n");
	    break;
	case XML_TEXT_NODE:
	    fprintf(output, "Error, TEXT\n");
	    break;
	case XML_CDATA_SECTION_NODE:
	    fprintf(output, "Error, CDATA_SECTION\n");
	    break;
	case XML_ENTITY_REF_NODE:
	    fprintf(output, "Error, ENTITY_REF\n");
	    break;
	case XML_ENTITY_NODE:
	    fprintf(output, "Error, ENTITY\n");
	    break;
	case XML_PI_NODE:
	    fprintf(output, "Error, PI\n");
	    break;
	case XML_COMMENT_NODE:
	    fprintf(output, "Error, COMMENT\n");
	    break;
	case XML_DOCUMENT_NODE:
	    fprintf(output, "DOCUMENT\n");
	    break;
	case XML_HTML_DOCUMENT_NODE:
	    fprintf(output, "HTML DOCUMENT\n");
	    break;
	case XML_DOCUMENT_TYPE_NODE:
	    fprintf(output, "Error, DOCUMENT_TYPE\n");
	    break;
	case XML_DOCUMENT_FRAG_NODE:
	    fprintf(output, "Error, DOCUMENT_FRAG\n");
	    break;
	case XML_NOTATION_NODE:
	    fprintf(output, "Error, NOTATION\n");
	    break;
	default:
	    fprintf(output, "NODE_%d\n", doc->type);
    }
    if ((doc->intSubset != NULL) && (doc->intSubset->entities != NULL)) {
        xmlEntitiesTablePtr table = (xmlEntitiesTablePtr) 
	                            doc->intSubset->entities;
	fprintf(output, "Entities in internal subset\n");
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    fprintf(output, "%d : %s : ", i, cur->name);
	    switch (cur->type) {
		case XML_INTERNAL_GENERAL_ENTITY:
		    fprintf(output, "INTERNAL GENERAL");
		    break;
		case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
		    fprintf(output, "EXTERNAL PARSED");
		    break;
		case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
		    fprintf(output, "EXTERNAL UNPARSED");
		    break;
		case XML_INTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "INTERNAL PARAMETER");
		    break;
		case XML_EXTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "EXTERNAL PARAMETER");
		    break;
		default:
		    fprintf(output, "UNKNOWN TYPE %d",
			    cur->type);
	    }
	    if (cur->ExternalID != NULL) 
	        fprintf(output, "ID \"%s\"", cur->ExternalID);
	    if (cur->SystemID != NULL)
	        fprintf(output, "SYSTEM \"%s\"", cur->SystemID);
	    if (cur->orig != NULL)
	        fprintf(output, "\n orig \"%s\"", cur->orig);
	    if (cur->content != NULL)
	        fprintf(output, "\n content \"%s\"", cur->content);
	    fprintf(output, "\n");	
	}
    } else
	fprintf(output, "No entities in internal subset\n");
    if ((doc->extSubset != NULL) && (doc->extSubset->entities != NULL)) {
        xmlEntitiesTablePtr table = (xmlEntitiesTablePtr) 
	                            doc->extSubset->entities;
	fprintf(output, "Entities in external subset\n");
	for (i = 0;i < table->nb_entities;i++) {
	    cur = &table->table[i];
	    fprintf(output, "%d : %s : ", i, cur->name);
	    switch (cur->type) {
		case XML_INTERNAL_GENERAL_ENTITY:
		    fprintf(output, "INTERNAL GENERAL");
		    break;
		case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
		    fprintf(output, "EXTERNAL PARSED");
		    break;
		case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
		    fprintf(output, "EXTERNAL UNPARSED");
		    break;
		case XML_INTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "INTERNAL PARAMETER");
		    break;
		case XML_EXTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "EXTERNAL PARAMETER");
		    break;
		default:
		    fprintf(output, "UNKNOWN TYPE %d",
			    cur->type);
	    }
	    if (cur->ExternalID != NULL) 
	        fprintf(output, "ID \"%s\"", cur->ExternalID);
	    if (cur->SystemID != NULL)
	        fprintf(output, "SYSTEM \"%s\"", cur->SystemID);
	    if (cur->orig != NULL)
	        fprintf(output, "\n orig \"%s\"", cur->orig);
	    if (cur->content != NULL)
	        fprintf(output, "\n content \"%s\"", cur->content);
	    fprintf(output, "\n");	
	}
    } else
	fprintf(output, "No entities in external subset\n");
}

static int xmlLsCountNode(xmlNodePtr node) {
    int ret = 0;
    xmlNodePtr list = NULL;

    switch (node->type) {
	case XML_ELEMENT_NODE:
	    list = node->childs;
	    break;
	case XML_DOCUMENT_NODE:
	case XML_HTML_DOCUMENT_NODE:
	    list = ((xmlDocPtr) node)->root;
	    break;
	case XML_ATTRIBUTE_NODE:
	    list = ((xmlAttrPtr) node)->val;
	    break;
	case XML_TEXT_NODE:
	case XML_CDATA_SECTION_NODE:
	case XML_PI_NODE:
	case XML_COMMENT_NODE:
	    if (node->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT	    
		ret = xmlStrlen(node->content);
#else
		ret = xmlBufferLength(node->content);
#endif
            }
	    break;
	case XML_ENTITY_REF_NODE:
	case XML_DOCUMENT_TYPE_NODE:
	case XML_ENTITY_NODE:
	case XML_DOCUMENT_FRAG_NODE:
	case XML_NOTATION_NODE:
	    ret = 1;
	    break;
    }
    for (;list != NULL;ret++) 
        list = list->next;
    return(ret);
}

void xmlLsOneNode(FILE *output, xmlNodePtr node) {
    switch (node->type) {
	case XML_ELEMENT_NODE:
	    fprintf(output, "-");
	    break;
	case XML_ATTRIBUTE_NODE:
	    fprintf(output, "a");
	    break;
	case XML_TEXT_NODE:
	    fprintf(output, "t");
	    break;
	case XML_CDATA_SECTION_NODE:
	    fprintf(output, "c");
	    break;
	case XML_ENTITY_REF_NODE:
	    fprintf(output, "e");
	    break;
	case XML_ENTITY_NODE:
	    fprintf(output, "E");
	    break;
	case XML_PI_NODE:
	    fprintf(output, "p");
	    break;
	case XML_COMMENT_NODE:
	    fprintf(output, "c");
	    break;
	case XML_DOCUMENT_NODE:
	    fprintf(output, "d");
	    break;
	case XML_HTML_DOCUMENT_NODE:
	    fprintf(output, "h");
	    break;
	case XML_DOCUMENT_TYPE_NODE:
	    fprintf(output, "T");
	    break;
	case XML_DOCUMENT_FRAG_NODE:
	    fprintf(output, "F");
	    break;
	case XML_NOTATION_NODE:
	    fprintf(output, "N");
	    break;
	default:
	    fprintf(output, "?");
    }
    if (node->properties != NULL)
	fprintf(output, "a");
    else	
	fprintf(output, "-");
    if (node->nsDef != NULL) 
	fprintf(output, "n");
    else	
	fprintf(output, "-");

    fprintf(output, " %8d ", xmlLsCountNode(node));

    switch (node->type) {
	case XML_ELEMENT_NODE:
	    if (node->name != NULL)
		fprintf(output, "%s", node->name);
	    break;
	case XML_ATTRIBUTE_NODE:
	    if (node->name != NULL)
		fprintf(output, "%s", node->name);
	    break;
	case XML_TEXT_NODE:
	    if (node->content != NULL) {
#ifndef XML_USE_BUFFER_CONTENT	    
		xmlDebugDumpString(output, node->content);
#else
		xmlDebugDumpString(output, xmlBufferContent(node->content));
#endif
            }
	    break;
	case XML_CDATA_SECTION_NODE:
	    break;
	case XML_ENTITY_REF_NODE:
	    if (node->name != NULL)
		fprintf(output, "%s", node->name);
	    break;
	case XML_ENTITY_NODE:
	    if (node->name != NULL)
		fprintf(output, "%s", node->name);
	    break;
	case XML_PI_NODE:
	    if (node->name != NULL)
		fprintf(output, "%s", node->name);
	    break;
	case XML_COMMENT_NODE:
	    break;
	case XML_DOCUMENT_NODE:
	    break;
	case XML_HTML_DOCUMENT_NODE:
	    break;
	case XML_DOCUMENT_TYPE_NODE:
	    break;
	case XML_DOCUMENT_FRAG_NODE:
	    break;
	case XML_NOTATION_NODE:
	    break;
	default:
	    if (node->name != NULL)
		fprintf(output, "%s", node->name);
    }
    fprintf(output, "\n");
}

/****************************************************************
 *								*
 *	 	The XML shell related functions			*
 *								*
 ****************************************************************/

/*
 * TODO: Improvement/cleanups for the XML shell
 *     - allow to shell out an editor on a subpart
 *     - cleanup function registrations (with help) and calling
 *     - provide registration routines
 */

/**
 * xmlShellList:
 * @ctxt:  the shell context
 * @arg:  unused
 * @node:  a node
 * @node2:  unused
 *
 * Implements the XML shell function "ls"
 * Does an Unix like listing of the given node (like a directory)
 *
 * Returns 0
 */
int
xmlShellList(xmlShellCtxtPtr ctxt, char *arg, xmlNodePtr node,
                  xmlNodePtr node2) {
    xmlNodePtr cur;

    if ((node->type == XML_DOCUMENT_NODE) ||
        (node->type == XML_HTML_DOCUMENT_NODE)) {
        cur = ((xmlDocPtr) node)->root;
    } else if (node->childs != NULL) {
        cur = node->childs;
    } else {
	xmlLsOneNode(stdout, node);
        return(0);
    }
    while (cur != NULL) {
	xmlLsOneNode(stdout, cur);
	cur = cur->next;
    }
    return(0);
}

/**
 * xmlShellDir:
 * @ctxt:  the shell context
 * @arg:  unused
 * @node:  a node
 * @node2:  unused
 *
 * Implements the XML shell function "dir"
 * dumps informations about the node (namespace, attributes, content).
 *
 * Returns 0
 */
int
xmlShellDir(xmlShellCtxtPtr ctxt, char *arg, xmlNodePtr node,
                  xmlNodePtr node2) {
    if ((node->type == XML_DOCUMENT_NODE) ||
        (node->type == XML_HTML_DOCUMENT_NODE)) {
	xmlDebugDumpDocumentHead(stdout, (xmlDocPtr) node);
    } else if (node->type == XML_ATTRIBUTE_NODE) {
	xmlDebugDumpAttr(stdout, (xmlAttrPtr) node, 0);
    } else {
	xmlDebugDumpOneNode(stdout, node, 0);
    }
    return(0);
}

/**
 * xmlShellCat:
 * @ctxt:  the shell context
 * @arg:  unused
 * @node:  a node
 * @node2:  unused
 *
 * Implements the XML shell function "cat"
 * dumps the serialization node content (XML or HTML).
 *
 * Returns 0
 */
int
xmlShellCat(xmlShellCtxtPtr ctxt, char *arg, xmlNodePtr node,
                  xmlNodePtr node2) {
    if (ctxt->doc->type == XML_HTML_DOCUMENT_NODE) {
	if (node->type == XML_HTML_DOCUMENT_NODE)
	    htmlDocDump(stdout, (htmlDocPtr) node);
	else
	    htmlNodeDumpFile(stdout, ctxt->doc, node);
    } else {
	if (node->type == XML_DOCUMENT_NODE)
	    xmlDocDump(stdout, (xmlDocPtr) node);
	else
	    xmlElemDump(stdout, ctxt->doc, node);
    }
    printf("\n");
    return(0);
}

/**
 * xmlShellLoad:
 * @ctxt:  the shell context
 * @filename:  the file name
 * @node:  unused
 * @node2:  unused
 *
 * Implements the XML shell function "load"
 * loads a new document specified by the filename
 *
 * Returns 0 or -1 if loading failed
 */
int
xmlShellLoad(xmlShellCtxtPtr ctxt, char *filename, xmlNodePtr node,
             xmlNodePtr node2) {
    xmlDocPtr doc;
    int html = 0;

    if (ctxt->doc != NULL)
	html = (ctxt->doc->type == XML_HTML_DOCUMENT_NODE);

    if (html) {
	doc = htmlParseFile(filename, NULL);
    } else {
	doc = xmlParseFile(filename);
    }
    if (doc != NULL) {
        if (ctxt->loaded == 1) {
	    xmlFreeDoc(ctxt->doc);
	}
	ctxt->loaded = 1;
	xmlXPathFreeContext(ctxt->pctxt);
	xmlFree(ctxt->filename);
	ctxt->doc = doc;
	ctxt->node = (xmlNodePtr) doc;	 
	ctxt->pctxt = xmlXPathNewContext(doc);
	ctxt->filename = (char *) xmlStrdup((xmlChar *) filename);
    } else
        return(-1);
    return(0);
}

/**
 * xmlShellWrite:
 * @ctxt:  the shell context
 * @filename:  the file name
 * @node:  a node in the tree
 * @node2:  unused
 *
 * Implements the XML shell function "write"
 * Write the current node to the filename, it saves the serailization
 * of the subtree under the @node specified
 *
 * Returns 0 or -1 in case of error
 */
int
xmlShellWrite(xmlShellCtxtPtr ctxt, char *filename, xmlNodePtr node,
                  xmlNodePtr node2) {
    if (node == NULL)
        return(-1);
    if ((filename == NULL) || (filename[0] == 0)) {
        fprintf(stderr, "Write command requires a filename argument\n");
	return(-1);
    }
#ifdef W_OK
    if (access((char *) filename, W_OK)) {
        fprintf(stderr, "Cannot write to %s\n", filename);
	return(-1);
    }
#endif    
    switch(node->type) {
        case XML_DOCUMENT_NODE:
	    if (xmlSaveFile((char *) filename, ctxt->doc) < -1) {
		fprintf(stderr, "Failed to write to %s\n", filename);
		return(-1);
	    }
	    break;
        case XML_HTML_DOCUMENT_NODE:
	    if (htmlSaveFile((char *) filename, ctxt->doc) < 0) {
		fprintf(stderr, "Failed to write to %s\n", filename);
		return(-1);
	    }
	    break;
	default: {
	    FILE *f;

	    f = fopen((char *) filename, "w");
	    if (f == NULL) {
		fprintf(stderr, "Failed to write to %s\n", filename);
		return(-1);
	    }
	    xmlElemDump(f, ctxt->doc, node);
	    fclose(f);
	}
    }
    return(0);
}

/**
 * xmlShellSave:
 * @ctxt:  the shell context
 * @filename:  the file name (optionnal)
 * @node:  unused
 * @node2:  unused
 *
 * Implements the XML shell function "save"
 * Write the current document to the filename, or it's original name
 *
 * Returns 0 or -1 in case of error
 */
int 
xmlShellSave(xmlShellCtxtPtr ctxt, char *filename, xmlNodePtr node,
             xmlNodePtr node2) {
    if (ctxt->doc == NULL)
	return(-1);
    if ((filename == NULL) || (filename[0] == 0))
        filename = ctxt->filename;
#ifdef W_OK
    if (access((char *) filename, W_OK)) {
        fprintf(stderr, "Cannot save to %s\n", filename);
	return(-1);
    }
#endif
    switch(ctxt->doc->type) {
        case XML_DOCUMENT_NODE:
	    if (xmlSaveFile((char *) filename, ctxt->doc) < 0) {
		fprintf(stderr, "Failed to save to %s\n", filename);
	    }
	    break;
        case XML_HTML_DOCUMENT_NODE:
	    if (htmlSaveFile((char *) filename, ctxt->doc) < 0) {
		fprintf(stderr, "Failed to save to %s\n", filename);
	    }
	    break;
	default:
	    fprintf(stderr, 
	      "To save to subparts of a document use the 'write' command\n");
	    return(-1);
	    
    }
    return(0);
}

/**
 * xmlShellValidate:
 * @ctxt:  the shell context
 * @dtd:  the DTD URI (optionnal)
 * @node:  unused
 * @node2:  unused
 *
 * Implements the XML shell function "validate"
 * Validate the document, if a DTD path is provided, then the validation
 * is done against the given DTD.
 *
 * Returns 0 or -1 in case of error
 */
int 
xmlShellValidate(xmlShellCtxtPtr ctxt, char *dtd, xmlNodePtr node,
                 xmlNodePtr node2) {
    xmlValidCtxt vctxt;
    int res = -1;

    vctxt.userData = stderr;
    vctxt.error = (xmlValidityErrorFunc) fprintf;
    vctxt.warning = (xmlValidityWarningFunc) fprintf;

    if ((dtd == NULL) || (dtd[0] == 0)) {
        res = xmlValidateDocument(&vctxt, ctxt->doc);
    } else {
        xmlDtdPtr subset;

	subset = xmlParseDTD(NULL, (xmlChar *) dtd);
	if (subset != NULL) {
            res = xmlValidateDtd(&vctxt, ctxt->doc, subset);

	    xmlFreeDtd(subset);
	}
    }
    return(res);
}

/**
 * xmlShellDu:
 * @ctxt:  the shell context
 * @arg:  unused
 * @tree:  a node defining a subtree
 * @node2:  unused
 *
 * Implements the XML shell function "du"
 * show the structure of the subtree under node @tree
 * If @tree is null, the command works on the current node.
 *
 * Returns 0 or -1 in case of error
 */
int 
xmlShellDu(xmlShellCtxtPtr ctxt, char *arg, xmlNodePtr tree,
                  xmlNodePtr node2) {
    xmlNodePtr node;
    int indent = 0,i;

    if (tree == NULL) return(-1);
    node = tree;
    while (node != NULL) {
        if ((node->type == XML_DOCUMENT_NODE) ||
            (node->type == XML_HTML_DOCUMENT_NODE)) {
	    printf("/\n");
	} else if (node->type == XML_ELEMENT_NODE) {
	    for (i = 0;i < indent;i++)
	        printf("  ");
	    printf("%s\n", node->name);
	} else {
	}

	/*
	 * Browse the full subtree, deep first
	 */

        if ((node->type == XML_DOCUMENT_NODE) ||
            (node->type == XML_HTML_DOCUMENT_NODE)) {
	    node = ((xmlDocPtr) node)->root;
        } else if (node->childs != NULL) {
	    /* deep first */
	    node = node->childs;
	    indent++;
	} else if ((node != tree) && (node->next != NULL)) {
	    /* then siblings */
	    node = node->next;
	} else if (node != tree) {
	    /* go up to parents->next if needed */
	    while (node != tree) {
	        if (node->parent != NULL) {
		    node = node->parent;
		    indent--;
		}
		if ((node != tree) && (node->next != NULL)) {
		    node = node->next;
		    break;
		}
		if (node->parent == NULL) {
		    node = NULL;
		    break;
		}
		if (node == tree) {
		    node = NULL;
		    break;
		}
	    }
	    /* exit condition */
	    if (node == tree) 
	        node = NULL;
	} else
	    node = NULL;
    }
    return(0);
}

/**
 * xmlShellPwd:
 * @ctxt:  the shell context
 * @buffer:  the output buffer
 * @tree:  a node 
 * @node2:  unused
 *
 * Implements the XML shell function "pwd"
 * Show the full path from the root to the node, if needed building
 * thumblers when similar elements exists at a given ancestor level.
 * The output is compatible with XPath commands.
 *
 * Returns 0 or -1 in case of error
 */
int 
xmlShellPwd(xmlShellCtxtPtr ctxt, char *buffer, xmlNodePtr node,
                  xmlNodePtr node2) {
    xmlNodePtr cur, tmp, next;
    char buf[500];
    char sep;
    const char *name;
    int occur = 0;

    buffer[0] = 0;
    if (node == NULL) return(-1);
    cur = node;
    do {
	name = "";
	sep= '?';
	occur = 0;
	if ((cur->type == XML_DOCUMENT_NODE) ||
	    (cur->type == XML_HTML_DOCUMENT_NODE)) {
	    sep = '/';
	    next = NULL;
	} else if (cur->type == XML_ELEMENT_NODE) {
	    sep = '/';
	    name = (const char *)cur->name;
	    next = cur->parent;

	    /*
	     * Thumbler index computation
	     */
	    tmp = cur->prev;
            while (tmp != NULL) {
	        if (!xmlStrcmp(cur->name, tmp->name))
		    occur++;
	        tmp = tmp->prev;
	    }
	    if (occur == 0) {
	        tmp = cur->next;
		while (tmp != NULL) {
		    if (!xmlStrcmp(cur->name, tmp->name))
			occur++;
		    tmp = tmp->next;
		}
		if (occur != 0) occur = 1;
	    } else
	        occur++;
	} else if (cur->type == XML_ATTRIBUTE_NODE) {
	    sep = '@';
	    name = (const char *) (((xmlAttrPtr) cur)->name);
	    next = ((xmlAttrPtr) cur)->node;
	} else {
	    next = cur->parent;
	}
	if (occur == 0)
	    sprintf(buf, "%c%s%s", sep, name, buffer);
	else
	    sprintf(buf, "%c%s[%d]%s", sep, name, occur, buffer);
	strcpy(buffer, buf);
        cur = next;
    } while (cur != NULL);
    return(0);
}

/**
 * xmlShell
 * @doc:  the initial document
 * @filename:  the output buffer
 * @input:  the line reading function
 * @output:  the output FILE*
 *
 * Implements the XML shell 
 * This allow to load, validate, view, modify and save a document
 * using a environment similar to a UNIX commandline.
 */
void
xmlShell(xmlDocPtr doc, char *filename, xmlShellReadlineFunc input,
         FILE *output) {
    char prompt[500] = "/ > ";
    char *cmdline = NULL;
    int nbargs;
    char command[100];
    char arg[400];
    xmlShellCtxtPtr ctxt;
    xmlXPathObjectPtr list;

    if (doc == NULL)
        return;
    if (filename == NULL)
        return;
    if (input == NULL)
        return;
    if (output == NULL)
        return;
    ctxt = (xmlShellCtxtPtr) xmlMalloc(sizeof(xmlShellCtxt));
    if (ctxt == NULL) 
        return;
    ctxt->loaded = 0;
    ctxt->doc = doc;
    ctxt->input = input;
    ctxt->output = output;
    ctxt->filename = (char *) xmlStrdup((xmlChar *) filename);
    ctxt->node = (xmlNodePtr) ctxt->doc;	 

    ctxt->pctxt = xmlXPathNewContext(ctxt->doc);
    if (ctxt->pctxt == NULL) {
	xmlFree(ctxt);
	return;
    }
    while (1) {
        if (ctxt->node == (xmlNodePtr) ctxt->doc)
	    sprintf(prompt, "%s > ", "/");
	else if (ctxt->node->name)
	    sprintf(prompt, "%s > ", ctxt->node->name);
	else
	    sprintf(prompt, "? > ");

        cmdline = ctxt->input(prompt);
        if (cmdline == NULL) break;

	command[0] = 0;
	arg[0] = 0;
	nbargs = sscanf(cmdline, "%s %s", command, arg);

	if (command[0] == 0) continue;
        if (!strcmp(command, "exit"))
	    break;
        if (!strcmp(command, "quit"))
	    break;
        if (!strcmp(command, "bye"))
	    break;
	if (!strcmp(command, "validate")) {
	    xmlShellValidate(ctxt, arg, NULL, NULL);
	} else if (!strcmp(command, "load")) {
	    xmlShellLoad(ctxt, arg, NULL, NULL);
	} else if (!strcmp(command, "save")) {
	    xmlShellSave(ctxt, arg, NULL, NULL);
	} else if (!strcmp(command, "write")) {
	    xmlShellWrite(ctxt, arg, NULL, NULL);
	} else if (!strcmp(command, "free")) {
	    if (arg[0] == 0) {
		xmlMemShow(stdout, 0);
	    } else {
	        int len = 0;
		sscanf(arg, "%d", &len);
		xmlMemShow(stdout, len);
	    }
	} else if (!strcmp(command, "pwd")) {
	    char dir[500];
	    if (!xmlShellPwd(ctxt, dir, ctxt->node, NULL))
		printf("%s\n", dir);
	} else  if (!strcmp(command, "du")) {
	    xmlShellDu(ctxt, NULL, ctxt->node, NULL);
	} else  if ((!strcmp(command, "ls")) ||
	      (!strcmp(command, "dir"))) {
	    int dir = (!strcmp(command, "dir"));
	    if (arg[0] == 0) {
		if (dir)
		    xmlShellDir(ctxt, NULL, ctxt->node, NULL);
		else
		    xmlShellList(ctxt, NULL, ctxt->node, NULL);
	    } else {
	        ctxt->pctxt->node = ctxt->node;
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
	        ctxt->pctxt->nodelist = xmlXPathNodeSetCreate(ctxt->node);
		list = xmlXPathEval((xmlChar *) arg, ctxt->pctxt);
		if (list != NULL) {
		    switch (list->type) {
			case XPATH_UNDEFINED:
			    fprintf(stderr, "%s: no such node\n", arg);
			    break;
			case XPATH_NODESET: {
			    int i;

			    for (i = 0;i < list->nodesetval->nodeNr;i++) {
				if (dir)
				    xmlShellDir(ctxt, NULL,
				       list->nodesetval->nodeTab[i], NULL);
				else
				    xmlShellList(ctxt, NULL,
				       list->nodesetval->nodeTab[i], NULL);
			    }
			    break;
			}
			case XPATH_BOOLEAN:
			    fprintf(stderr, "%s is a Boolean\n", arg);
			    break;
			case XPATH_NUMBER:
			    fprintf(stderr, "%s is a number\n", arg);
			    break;
			case XPATH_STRING:
			    fprintf(stderr, "%s is a string\n", arg);
			    break;
		    }
		    xmlXPathFreeNodeSetList(list);
		} else {
		    fprintf(stderr, "%s: no such node\n", arg);
		}
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
		ctxt->pctxt->nodelist = NULL;
	    }
	} else if (!strcmp(command, "cd")) {
	    if (arg[0] == 0) {
		ctxt->node = (xmlNodePtr) ctxt->doc;
	    } else {
	        ctxt->pctxt->node = ctxt->node;
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
	        ctxt->pctxt->nodelist = xmlXPathNodeSetCreate(ctxt->node);
		list = xmlXPathEval((xmlChar *) arg, ctxt->pctxt);
		if (list != NULL) {
		    switch (list->type) {
			case XPATH_UNDEFINED:
			    fprintf(stderr, "%s: no such node\n", arg);
			    break;
			case XPATH_NODESET:
			    if (list->nodesetval->nodeNr == 1) {
				ctxt->node = list->nodesetval->nodeTab[0];
			    } else 
				fprintf(stderr, "%s is a %d Node Set\n",
				        arg, list->nodesetval->nodeNr);
			    break;
			case XPATH_BOOLEAN:
			    fprintf(stderr, "%s is a Boolean\n", arg);
			    break;
			case XPATH_NUMBER:
			    fprintf(stderr, "%s is a number\n", arg);
			    break;
			case XPATH_STRING:
			    fprintf(stderr, "%s is a string\n", arg);
			    break;
		    }
		    xmlXPathFreeNodeSetList(list);
		} else {
		    fprintf(stderr, "%s: no such node\n", arg);
		}
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
		ctxt->pctxt->nodelist = NULL;
	    }
	} else if (!strcmp(command, "cat")) {
	    if (arg[0] == 0) {
		xmlShellCat(ctxt, NULL, ctxt->node, NULL);
	    } else {
	        ctxt->pctxt->node = ctxt->node;
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
	        ctxt->pctxt->nodelist = xmlXPathNodeSetCreate(ctxt->node);
		list = xmlXPathEval((xmlChar *) arg, ctxt->pctxt);
		if (list != NULL) {
		    switch (list->type) {
			case XPATH_UNDEFINED:
			    fprintf(stderr, "%s: no such node\n", arg);
			    break;
			case XPATH_NODESET: {
			    int i;

			    for (i = 0;i < list->nodesetval->nodeNr;i++) {
			        if (i > 0) printf(" -------\n");
				xmlShellCat(ctxt, NULL,
				    list->nodesetval->nodeTab[i], NULL);
			    }
			    break;
			}
			case XPATH_BOOLEAN:
			    fprintf(stderr, "%s is a Boolean\n", arg);
			    break;
			case XPATH_NUMBER:
			    fprintf(stderr, "%s is a number\n", arg);
			    break;
			case XPATH_STRING:
			    fprintf(stderr, "%s is a string\n", arg);
			    break;
		    }
		    xmlXPathFreeNodeSetList(list);
		} else {
		    fprintf(stderr, "%s: no such node\n", arg);
		}
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
		ctxt->pctxt->nodelist = NULL;
	    }
	} else {
	    fprintf(stderr, "Unknown command %s\n", command);
	}
	free(cmdline); /* not xmlFree here ! */
    }
    xmlXPathFreeContext(ctxt->pctxt);
    if (ctxt->loaded) {
        xmlFreeDoc(ctxt->doc);
    }
    xmlFree(ctxt);
    if (cmdline != NULL)
        free(cmdline); /* not xmlFree here ! */
}

