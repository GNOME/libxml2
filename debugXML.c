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

#include "xmlversion.h"
#ifdef LIBXML_DEBUG_ENABLED

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/valid.h>
#include <libxml/debugXML.h>
#include <libxml/HTMLtree.h>
#include <libxml/HTMLparser.h>

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

void xmlDebugDumpDtd(FILE *output, xmlDtdPtr dtd, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);

    if (dtd->type != XML_DTD_NODE) {
	fprintf(output, "PBM: not a DTD\n");
	return;
    }
    if (dtd->name != NULL)
	fprintf(output, "DTD(%s)", dtd->name);
    else
	fprintf(output, "DTD");
    if (dtd->ExternalID != NULL)
	fprintf(output, ", PUBLIC %s", dtd->ExternalID);
    if (dtd->SystemID != NULL)
	fprintf(output, ", SYSTEM %s", dtd->SystemID);
    fprintf(output, "\n");
    /*
     * Do a bit of checking
     */
    if (dtd->parent == NULL)
	fprintf(output, "PBM: Dtd has no parent\n");
    if (dtd->doc == NULL)
	fprintf(output, "PBM: Dtd has no doc\n");
    if ((dtd->parent != NULL) && (dtd->doc != dtd->parent->doc))
	fprintf(output, "PBM: Dtd doc differs from parent's one\n");
    if (dtd->prev == NULL) {
	if ((dtd->parent != NULL) && (dtd->parent->children != (xmlNodePtr)dtd))
	    fprintf(output, "PBM: Dtd has no prev and not first of list\n");
    } else {
	if (dtd->prev->next != (xmlNodePtr) dtd)
	    fprintf(output, "PBM: Dtd prev->next : back link wrong\n");
    }
    if (dtd->next == NULL) {
	if ((dtd->parent != NULL) && (dtd->parent->last != (xmlNodePtr) dtd))
	    fprintf(output, "PBM: Dtd has no next and not last of list\n");
    } else {
	if (dtd->next->prev != (xmlNodePtr) dtd)
	    fprintf(output, "PBM: Dtd next->prev : forward link wrong\n");
    }
}

void xmlDebugDumpAttrDecl(FILE *output, xmlAttributePtr attr, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);

    if (attr->type != XML_ATTRIBUTE_DECL) {
	fprintf(output, "PBM: not a Attr\n");
	return;
    }
    if (attr->name != NULL)
	fprintf(output, "ATTRDECL(%s)", attr->name);
    else
	fprintf(output, "PBM ATTRDECL noname!!!");
    if (attr->elem != NULL)
	fprintf(output, " for %s", attr->elem);
    else
	fprintf(output, " PBM noelem!!!");
    switch (attr->atype) {
        case XML_ATTRIBUTE_CDATA:
	    fprintf(output, " CDATA");
	    break;
        case XML_ATTRIBUTE_ID:
	    fprintf(output, " ID");
	    break;
        case XML_ATTRIBUTE_IDREF:
	    fprintf(output, " IDREF");
	    break;
        case XML_ATTRIBUTE_IDREFS:
	    fprintf(output, " IDREFS");
	    break;
        case XML_ATTRIBUTE_ENTITY:
	    fprintf(output, " ENTITY");
	    break;
        case XML_ATTRIBUTE_ENTITIES:
	    fprintf(output, " ENTITIES");
	    break;
        case XML_ATTRIBUTE_NMTOKEN:
	    fprintf(output, " NMTOKEN");
	    break;
        case XML_ATTRIBUTE_NMTOKENS:
	    fprintf(output, " NMTOKENS");
	    break;
        case XML_ATTRIBUTE_ENUMERATION:
	    fprintf(output, " ENUMERATION");
	    break;
        case XML_ATTRIBUTE_NOTATION:
	    fprintf(output, " NOTATION ");
	    break;
    }
    if (attr->tree != NULL) {
	int i;
	xmlEnumerationPtr cur = attr->tree;

	for (i = 0;i < 5; i++) {
	    if (i != 0)
		fprintf(output, "|%s", cur->name);
	    else
		fprintf(output, " (%s", cur->name);
	    cur = cur->next;
	    if (cur == NULL) break;
	}
	if (cur == NULL)
	    fprintf(output, ")");
	else
	    fprintf(output, "...)");
    }
    switch (attr->def) {
        case XML_ATTRIBUTE_NONE:
	    break;
        case XML_ATTRIBUTE_REQUIRED:
	    fprintf(output, " REQUIRED");
	    break;
        case XML_ATTRIBUTE_IMPLIED:
	    fprintf(output, " IMPLIED");
	    break;
        case XML_ATTRIBUTE_FIXED:
	    fprintf(output, " FIXED");
	    break;
    }
    if (attr->defaultValue != NULL) {
	fprintf(output, "\"");
	xmlDebugDumpString(output, attr->defaultValue);
	fprintf(output, "\"");
    }
    printf("\n");

    /*
     * Do a bit of checking
     */
    if (attr->parent == NULL)
	fprintf(output, "PBM: Attr has no parent\n");
    if (attr->doc == NULL)
	fprintf(output, "PBM: Attr has no doc\n");
    if ((attr->parent != NULL) && (attr->doc != attr->parent->doc))
	fprintf(output, "PBM: Attr doc differs from parent's one\n");
    if (attr->prev == NULL) {
	if ((attr->parent != NULL) && (attr->parent->children != (xmlNodePtr)attr))
	    fprintf(output, "PBM: Attr has no prev and not first of list\n");
    } else {
	if (attr->prev->next != (xmlNodePtr) attr)
	    fprintf(output, "PBM: Attr prev->next : back link wrong\n");
    }
    if (attr->next == NULL) {
	if ((attr->parent != NULL) && (attr->parent->last != (xmlNodePtr) attr))
	    fprintf(output, "PBM: Attr has no next and not last of list\n");
    } else {
	if (attr->next->prev != (xmlNodePtr) attr)
	    fprintf(output, "PBM: Attr next->prev : forward link wrong\n");
    }
}

void xmlDebugDumpElemDecl(FILE *output, xmlElementPtr elem, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);

    if (elem->type != XML_ELEMENT_DECL) {
	fprintf(output, "PBM: not a Elem\n");
	return;
    }
    if (elem->name != NULL)
	fprintf(output, "ELEMDECL(%s)", elem->name);
    else
	fprintf(output, "PBM ELEMDECL noname!!!");
    switch (elem->etype) {
	case XML_ELEMENT_TYPE_EMPTY: 
	    fprintf(output, ", EMPTY");
	    break;
	case XML_ELEMENT_TYPE_ANY: 
	    fprintf(output, ", ANY");
	    break;
	case XML_ELEMENT_TYPE_MIXED: 
	    fprintf(output, ", MIXED ");
	    break;
	case XML_ELEMENT_TYPE_ELEMENT: 
	    fprintf(output, ", MIXED ");
	    break;
    }
    if (elem->content != NULL) {
	char buf[1001];

	buf[0] = 0;
	xmlSprintfElementContent(buf, elem->content, 1);
	buf[1000] = 0;
	fprintf(output, "%s", buf);
    }
    printf("\n");

    /*
     * Do a bit of checking
     */
    if (elem->parent == NULL)
	fprintf(output, "PBM: Elem has no parent\n");
    if (elem->doc == NULL)
	fprintf(output, "PBM: Elem has no doc\n");
    if ((elem->parent != NULL) && (elem->doc != elem->parent->doc))
	fprintf(output, "PBM: Elem doc differs from parent's one\n");
    if (elem->prev == NULL) {
	if ((elem->parent != NULL) && (elem->parent->children != (xmlNodePtr)elem))
	    fprintf(output, "PBM: Elem has no prev and not first of list\n");
    } else {
	if (elem->prev->next != (xmlNodePtr) elem)
	    fprintf(output, "PBM: Elem prev->next : back link wrong\n");
    }
    if (elem->next == NULL) {
	if ((elem->parent != NULL) && (elem->parent->last != (xmlNodePtr) elem))
	    fprintf(output, "PBM: Elem has no next and not last of list\n");
    } else {
	if (elem->next->prev != (xmlNodePtr) elem)
	    fprintf(output, "PBM: Elem next->prev : forward link wrong\n");
    }
}

void xmlDebugDumpEntityDecl(FILE *output, xmlEntityPtr ent, int depth) {
    int i;
    char shift[100];

    for (i = 0;((i < depth) && (i < 25));i++)
        shift[2 * i] = shift[2 * i + 1] = ' ';
    shift[2 * i] = shift[2 * i + 1] = 0;

    fprintf(output, shift);

    if (ent->type != XML_ENTITY_DECL) {
	fprintf(output, "PBM: not a Entity decl\n");
	return;
    }
    if (ent->name != NULL)
	fprintf(output, "ENTITYDECL(%s)", ent->name);
    else
	fprintf(output, "PBM ENTITYDECL noname!!!");
    switch (ent->etype) {
	case XML_INTERNAL_GENERAL_ENTITY: 
	    fprintf(output, ", internal\n");
	    break;
	case XML_EXTERNAL_GENERAL_PARSED_ENTITY: 
	    fprintf(output, ", external parsed\n");
	    break;
	case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: 
	    fprintf(output, ", unparsed\n");
	    break;
	case XML_INTERNAL_PARAMETER_ENTITY: 
	    fprintf(output, ", parameter\n");
	    break;
	case XML_EXTERNAL_PARAMETER_ENTITY: 
	    fprintf(output, ", external parameter\n");
	    break;
	case XML_INTERNAL_PREDEFINED_ENTITY: 
	    fprintf(output, ", predefined\n");
	    break;
    }
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

    /*
     * Do a bit of checking
     */
    if (ent->parent == NULL)
	fprintf(output, "PBM: Ent has no parent\n");
    if (ent->doc == NULL)
	fprintf(output, "PBM: Ent has no doc\n");
    if ((ent->parent != NULL) && (ent->doc != ent->parent->doc))
	fprintf(output, "PBM: Ent doc differs from parent's one\n");
    if (ent->prev == NULL) {
	if ((ent->parent != NULL) && (ent->parent->children != (xmlNodePtr)ent))
	    fprintf(output, "PBM: Ent has no prev and not first of list\n");
    } else {
	if (ent->prev->next != (xmlNodePtr) ent)
	    fprintf(output, "PBM: Ent prev->next : back link wrong\n");
    }
    if (ent->next == NULL) {
	if ((ent->parent != NULL) && (ent->parent->last != (xmlNodePtr) ent))
	    fprintf(output, "PBM: Ent has no next and not last of list\n");
    } else {
	if (ent->next->prev != (xmlNodePtr) ent)
	    fprintf(output, "PBM: Ent next->prev : forward link wrong\n");
    }
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
    switch (ent->etype) {
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
	    fprintf(output, "ENTITY_%d ! ", ent->etype);
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
    if (attr->children != NULL) 
        xmlDebugDumpNodeList(output, attr->children, depth + 1);

    /*
     * Do a bit of checking
     */
    if (attr->parent == NULL)
	fprintf(output, "PBM: Attr has no parent\n");
    if (attr->doc == NULL)
	fprintf(output, "PBM: Attr has no doc\n");
    if ((attr->parent != NULL) && (attr->doc != attr->parent->doc))
	fprintf(output, "PBM: Attr doc differs from parent's one\n");
    if (attr->prev == NULL) {
	if ((attr->parent != NULL) && (attr->parent->properties != attr))
	    fprintf(output, "PBM: Attr has no prev and not first of list\n");
    } else {
	if (attr->prev->next != attr)
	    fprintf(output, "PBM: Attr prev->next : back link wrong\n");
    }
    if (attr->next != NULL) {
	if (attr->next->prev != attr)
	    fprintf(output, "PBM: Attr next->prev : forward link wrong\n");
    }
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

    switch (node->type) {
	case XML_ELEMENT_NODE:
	    fprintf(output, shift);
	    fprintf(output, "ELEMENT ");
	    if (node->ns != NULL)
	        fprintf(output, "%s:%s\n", node->ns->prefix, node->name);
	    else
	        fprintf(output, "%s\n", node->name);
	    break;
	case XML_ATTRIBUTE_NODE:
	    fprintf(output, shift);
	    fprintf(output, "Error, ATTRIBUTE found here\n");
	    break;
	case XML_TEXT_NODE:
	    fprintf(output, shift);
	    fprintf(output, "TEXT\n");
	    break;
	case XML_CDATA_SECTION_NODE:
	    fprintf(output, shift);
	    fprintf(output, "CDATA_SECTION\n");
	    break;
	case XML_ENTITY_REF_NODE:
	    fprintf(output, shift);
	    fprintf(output, "ENTITY_REF(%s)\n", node->name);
	    break;
	case XML_ENTITY_NODE:
	    fprintf(output, shift);
	    fprintf(output, "ENTITY\n");
	    break;
	case XML_PI_NODE:
	    fprintf(output, shift);
	    fprintf(output, "PI %s\n", node->name);
	    break;
	case XML_COMMENT_NODE:
	    fprintf(output, shift);
	    fprintf(output, "COMMENT\n");
	    break;
	case XML_DOCUMENT_NODE:
	case XML_HTML_DOCUMENT_NODE:
	    fprintf(output, shift);
	    fprintf(output, "Error, DOCUMENT found here\n");
	    break;
	case XML_DOCUMENT_TYPE_NODE:
	    fprintf(output, shift);
	    fprintf(output, "DOCUMENT_TYPE\n");
	    break;
	case XML_DOCUMENT_FRAG_NODE:
	    fprintf(output, shift);
	    fprintf(output, "DOCUMENT_FRAG\n");
	    break;
	case XML_NOTATION_NODE:
	    fprintf(output, "NOTATION\n");
	    break;
	case XML_DTD_NODE:
	    xmlDebugDumpDtd(output, (xmlDtdPtr) node, depth);
	    return;
	case XML_ELEMENT_DECL:
	    xmlDebugDumpElemDecl(output, (xmlElementPtr) node, depth);
	    return;
	case XML_ATTRIBUTE_DECL:
	    xmlDebugDumpAttrDecl(output, (xmlAttributePtr) node, depth);
	    return;
        case XML_ENTITY_DECL:
	    xmlDebugDumpEntityDecl(output, (xmlEntityPtr) node, depth);
	    return;
	default:
	    fprintf(output, shift);
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
    /*
     * Do a bit of checking
     */
    if (node->parent == NULL)
	fprintf(output, "PBM: Node has no parent\n");
    if (node->doc == NULL)
	fprintf(output, "PBM: Node has no doc\n");
    if ((node->parent != NULL) && (node->doc != node->parent->doc))
	fprintf(output, "PBM: Node doc differs from parent's one\n");
    if (node->prev == NULL) {
	if ((node->parent != NULL) && (node->parent->children != node))
	    fprintf(output, "PBM: Node has no prev and not first of list\n");
    } else {
	if (node->prev->next != node)
	    fprintf(output, "PBM: Node prev->next : back link wrong\n");
    }
    if (node->next == NULL) {
	if ((node->parent != NULL) && (node->parent->last != node))
	    fprintf(output, "PBM: Node has no next and not last of list\n");
    } else {
	if (node->next->prev != node)
	    fprintf(output, "PBM: Node next->prev : forward link wrong\n");
    }
}

void xmlDebugDumpNode(FILE *output, xmlNodePtr node, int depth) {
    xmlDebugDumpOneNode(output, node, depth);
    if (node->children != NULL)
	xmlDebugDumpNodeList(output, node->children, depth + 1);
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
        (doc->children != NULL))
        xmlDebugDumpNodeList(output, doc->children, 1);
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
	    cur = table->table[i];
	    fprintf(output, "%d : %s : ", i, cur->name);
	    switch (cur->etype) {
		case XML_INTERNAL_GENERAL_ENTITY:
		    fprintf(output, "INTERNAL GENERAL, ");
		    break;
		case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
		    fprintf(output, "EXTERNAL PARSED, ");
		    break;
		case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
		    fprintf(output, "EXTERNAL UNPARSED, ");
		    break;
		case XML_INTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "INTERNAL PARAMETER, ");
		    break;
		case XML_EXTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "EXTERNAL PARAMETER, ");
		    break;
		default:
		    fprintf(output, "UNKNOWN TYPE %d",
			    cur->etype);
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
	    cur = table->table[i];
	    fprintf(output, "%d : %s : ", i, cur->name);
	    switch (cur->etype) {
		case XML_INTERNAL_GENERAL_ENTITY:
		    fprintf(output, "INTERNAL GENERAL, ");
		    break;
		case XML_EXTERNAL_GENERAL_PARSED_ENTITY:
		    fprintf(output, "EXTERNAL PARSED, ");
		    break;
		case XML_EXTERNAL_GENERAL_UNPARSED_ENTITY:
		    fprintf(output, "EXTERNAL UNPARSED, ");
		    break;
		case XML_INTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "INTERNAL PARAMETER, ");
		    break;
		case XML_EXTERNAL_PARAMETER_ENTITY:
		    fprintf(output, "EXTERNAL PARAMETER, ");
		    break;
		default:
		    fprintf(output, "UNKNOWN TYPE %d",
			    cur->etype);
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
	    list = node->children;
	    break;
	case XML_DOCUMENT_NODE:
	case XML_HTML_DOCUMENT_NODE:
	    list = ((xmlDocPtr) node)->children;
	    break;
	case XML_ATTRIBUTE_NODE:
	    list = ((xmlAttrPtr) node)->children;
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
	case XML_DTD_NODE:
        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
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
        cur = ((xmlDocPtr) node)->children;
    } else if (node->children != NULL) {
        cur = node->children;
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
#ifdef LIBXML_HTML_ENABLED
	if (node->type == XML_HTML_DOCUMENT_NODE)
	    htmlDocDump(stdout, (htmlDocPtr) node);
	else
	    htmlNodeDumpFile(stdout, ctxt->doc, node);
#else
	if (node->type == XML_DOCUMENT_NODE)
	    xmlDocDump(stdout, (xmlDocPtr) node);
	else
	    xmlElemDump(stdout, ctxt->doc, node);
#endif /* LIBXML_HTML_ENABLED */
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
#ifdef LIBXML_HTML_ENABLED
	doc = htmlParseFile(filename, NULL);
#else	
	printf("HTML support not compiled in\n");
	doc = NULL;
#endif /* LIBXML_HTML_ENABLED */
    } else {
	doc = xmlParseFile(filename);
    }
    if (doc != NULL) {
        if (ctxt->loaded == 1) {
	    xmlFreeDoc(ctxt->doc);
	}
	ctxt->loaded = 1;
#ifdef LIBXML_XPATH_ENABLED
	xmlXPathFreeContext(ctxt->pctxt);
#endif /* LIBXML_XPATH_ENABLED */
	xmlFree(ctxt->filename);
	ctxt->doc = doc;
	ctxt->node = (xmlNodePtr) doc;	 
#ifdef LIBXML_XPATH_ENABLED
	ctxt->pctxt = xmlXPathNewContext(doc);
#endif /* LIBXML_XPATH_ENABLED */
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
#ifdef LIBXML_HTML_ENABLED
	    if (htmlSaveFile((char *) filename, ctxt->doc) < 0) {
		fprintf(stderr, "Failed to write to %s\n", filename);
		return(-1);
	    }
#else
	    if (xmlSaveFile((char *) filename, ctxt->doc) < -1) {
		fprintf(stderr, "Failed to write to %s\n", filename);
		return(-1);
	    }
#endif /* LIBXML_HTML_ENABLED */
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
#ifdef LIBXML_HTML_ENABLED
	    if (htmlSaveFile((char *) filename, ctxt->doc) < 0) {
		fprintf(stderr, "Failed to save to %s\n", filename);
	    }
#else
	    if (xmlSaveFile((char *) filename, ctxt->doc) < 0) {
		fprintf(stderr, "Failed to save to %s\n", filename);
	    }
#endif /* LIBXML_HTML_ENABLED */
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
	    node = ((xmlDocPtr) node)->children;
        } else if (node->children != NULL) {
	    /* deep first */
	    node = node->children;
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
	    next = ((xmlAttrPtr) cur)->parent;
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

#ifdef LIBXML_XPATH_ENABLED
    ctxt->pctxt = xmlXPathNewContext(ctxt->doc);
    if (ctxt->pctxt == NULL) {
	xmlFree(ctxt);
	return;
    }
#endif /* LIBXML_XPATH_ENABLED */
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
#ifdef LIBXML_XPATH_ENABLED
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
	        ctxt->pctxt->nodelist = xmlXPathNodeSetCreate(ctxt->node);
		list = xmlXPathEval((xmlChar *) arg, ctxt->pctxt);
#else
		list = NULL;
#endif /* LIBXML_XPATH_ENABLED */
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
#ifdef LIBXML_XPATH_ENABLED
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
#endif /* LIBXML_XPATH_ENABLED */
		ctxt->pctxt->nodelist = NULL;
	    }
	} else if (!strcmp(command, "cd")) {
	    if (arg[0] == 0) {
		ctxt->node = (xmlNodePtr) ctxt->doc;
	    } else {
	        ctxt->pctxt->node = ctxt->node;
#ifdef LIBXML_XPATH_ENABLED
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
	        ctxt->pctxt->nodelist = xmlXPathNodeSetCreate(ctxt->node);
		list = xmlXPathEval((xmlChar *) arg, ctxt->pctxt);
#else
		list = NULL;
#endif /* LIBXML_XPATH_ENABLED */
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
#ifdef LIBXML_XPATH_ENABLED
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
#endif /* LIBXML_XPATH_ENABLED */
		ctxt->pctxt->nodelist = NULL;
	    }
	} else if (!strcmp(command, "cat")) {
	    if (arg[0] == 0) {
		xmlShellCat(ctxt, NULL, ctxt->node, NULL);
	    } else {
	        ctxt->pctxt->node = ctxt->node;
#ifdef LIBXML_XPATH_ENABLED
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
	        ctxt->pctxt->nodelist = xmlXPathNodeSetCreate(ctxt->node);
		list = xmlXPathEval((xmlChar *) arg, ctxt->pctxt);
#else
		list = NULL;
#endif /* LIBXML_XPATH_ENABLED */
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
#ifdef LIBXML_XPATH_ENABLED
		if (ctxt->pctxt->nodelist != NULL)
		    xmlXPathFreeNodeSet(ctxt->pctxt->nodelist);
#endif /* LIBXML_XPATH_ENABLED */
		ctxt->pctxt->nodelist = NULL;
	    }
	} else {
	    fprintf(stderr, "Unknown command %s\n", command);
	}
	free(cmdline); /* not xmlFree here ! */
    }
#ifdef LIBXML_XPATH_ENABLED
    xmlXPathFreeContext(ctxt->pctxt);
#endif /* LIBXML_XPATH_ENABLED */
    if (ctxt->loaded) {
        xmlFreeDoc(ctxt->doc);
    }
    xmlFree(ctxt);
    if (cmdline != NULL)
        free(cmdline); /* not xmlFree here ! */
}

#endif /* LIBXML_DEBUG_ENABLED */
