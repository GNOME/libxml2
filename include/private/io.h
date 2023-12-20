#ifndef XML_IO_H_PRIVATE__
#define XML_IO_H_PRIVATE__

#include <libxml/encoding.h>
#include <libxml/tree.h>
#include <libxml/xmlversion.h>

XML_HIDDEN void
xmlInitIOCallbacks(void);

XML_HIDDEN int
__xmlIOErr(int domain, int code, const char *extra);

XML_HIDDEN int
xmlParserInputBufferCreateFilenameSafe(const char *URI, xmlCharEncoding enc,
                                       xmlParserInputBufferPtr *out);
XML_HIDDEN xmlParserInputBufferPtr
xmlParserInputBufferCreateString(const xmlChar *str);

#ifdef LIBXML_OUTPUT_ENABLED
XML_HIDDEN xmlOutputBufferPtr
xmlAllocOutputBufferInternal(xmlCharEncodingHandlerPtr encoder);
#endif

#endif /* XML_IO_H_PRIVATE__ */
