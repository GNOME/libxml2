/*
 * enc.h: Internal Interfaces for encoding in libxml2
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#ifndef __XML_ENC_H__
#define __XML_ENC_H__

#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

int xmlCharEncFirstLineInt(xmlCharEncodingHandler *handler, xmlBufferPtr out,
                           xmlBufferPtr in, int len);
int xmlCharEncFirstLineInput(xmlParserInputBufferPtr input, int len);
int xmlCharEncInput(xmlParserInputBufferPtr input);
int xmlCharEncOutput(xmlOutputBufferPtr output, int init);

#ifdef __cplusplus
}
#endif
#endif /* __XML_ENC_H__ */


