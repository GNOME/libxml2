/*
 * debugXML.h : Interfaces to a set of routines used for debugging the tree
 *              produced by the XML parser.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#ifndef __DEBUG_XML__
#define __DEBUG_XML__
#include "tree.h"

#ifdef __cplusplus
#define extern "C" {
#endif
extern void xmlDebugDumpString(FILE *output, const xmlChar *str);
extern void xmlDebugDumpAttr(FILE *output, xmlAttrPtr attr, int depth);
extern void xmlDebugDumpAttrList(FILE *output, xmlAttrPtr attr, int depth);
extern void xmlDebugDumpOneNode(FILE *output, xmlNodePtr node, int depth);
extern void xmlDebugDumpNode(FILE *output, xmlNodePtr node, int depth);
extern void xmlDebugDumpNodeList(FILE *output, xmlNodePtr node, int depth);
extern void xmlDebugDumpDocument(FILE *output, xmlDocPtr doc);
extern void xmlDebugDumpEntities(FILE *output, xmlDocPtr doc);
#ifdef __cplusplus
}
#endif
#endif /* __DEBUG_XML__ */
