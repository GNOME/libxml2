/*
 * tree.h : describes the structures found in an tree resulting
 *          from an XML parsing.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __HTML_TREE_H__
#define __HTML_TREE_H__

#include <stdio.h>
#include <libxml/tree.h>


#ifdef __cplusplus
extern "C" {
#endif

#define HTML_TEXT_NODE		XML_TEXT_NODE
#define HTML_ENTITY_REF_NODE	XML_ENTITY_REF_NODE
#define HTML_COMMENT_NODE	XML_COMMENT_NODE

void htmlDocDumpMemory(xmlDocPtr cur, xmlChar**mem, int *size);
void htmlDocDump(FILE *f, xmlDocPtr cur);
int htmlSaveFile(const char *filename, xmlDocPtr cur);
void htmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur);
void htmlNodeDumpFile(FILE *out, xmlDocPtr doc, xmlNodePtr cur);

#ifdef __cplusplus
}
#endif

#endif /* __HTML_TREE_H__ */

