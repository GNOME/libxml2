/*
 * valid.h : interface to the DTD handling and the validity checking
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */


#ifndef __XML_VALID_H__
#define __XML_VALID_H__
#include "tree.h"

extern xmlElementPtr xmlAddElementDecl(xmlDtdPtr dtd, char *name, int type, 
                                       xmlElementContentPtr content);
extern xmlElementContentPtr xmlNewElementContent(CHAR *name, int type);
extern void xmlFreeElementContent(xmlElementContentPtr cur);
#endif /* __XML_VALID_H__ */
