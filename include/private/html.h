#ifndef XML_HTML_H_PRIVATE__
#define XML_HTML_H_PRIVATE__

#include <libxml/xmlversion.h>

#ifdef LIBXML_HTML_ENABLED

#define IS_WS_HTML(c) \
    (((c) == 0x20) || \
     (((c) >= 0x09) && ((c) <= 0x0D) && ((c) != 0x0B)))

typedef struct {
    size_t start;
    size_t end;
    size_t size;
} htmlMetaEncodingOffsets;

XML_HIDDEN xmlNodePtr
htmlCtxtParseContentInternal(xmlParserCtxtPtr ctxt, xmlParserInputPtr input);

XML_HIDDEN int
htmlParseContentType(const xmlChar *val, htmlMetaEncodingOffsets *off);

XML_HIDDEN void
htmlNodeDumpInternal(xmlOutputBufferPtr buf, xmlNodePtr cur,
                     const char *encoding, int format);

#endif /* LIBXML_HTML_ENABLED */

#endif /* XML_HTML_H_PRIVATE__ */

