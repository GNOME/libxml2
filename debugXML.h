/*
 * debugXML.h : Interfaces to a set of routines used for debugging the tree
 *              produced by the XML parser.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#ifndef __DEBUG_XML__
#define __DEBUG_XML__
#include "tree.h"

extern void xmlDebugDumpString(FILE *output, const CHAR *str);
extern void xmlDebugDumpAttr(FILE *output, xmlAttrPtr attr, int depth);
extern void xmlDebugDumpAttrList(FILE *output, xmlAttrPtr attr, int depth);
extern void xmlDebugDumpNode(FILE *output, xmlNodePtr node, int depth);
extern void xmlDebugDumpNodeList(FILE *output, xmlNodePtr node, int depth);
extern void xmlDebugDumpDocument(FILE *output, xmlDocPtr doc);
#endif /* __DEBUG_XML__ */
