/*
 * save.h: Internal Interfaces for saving
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#ifndef __XML_SAVE_H__
#define __XML_SAVE_H__

#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

void xmlBufAttrSerializeTxtContent(xmlBufPtr buf, xmlDocPtr doc,
                                   xmlAttrPtr attr, const xmlChar * string);
void xmlBufDumpNotationTable(xmlBufPtr buf, xmlNotationTablePtr table);
void xmlBufDumpElementDecl(xmlBufPtr buf, xmlElementPtr elem);
void xmlBufDumpAttributeDecl(xmlBufPtr buf, xmlAttributePtr attr);
void xmlBufDumpEntityDecl(xmlBufPtr buf, xmlEntityPtr ent);

#ifdef __cplusplus
}
#endif
#endif /* __XML_SAVE_H__ */

