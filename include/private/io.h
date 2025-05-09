#ifndef XML_IO_H_PRIVATE__
#define XML_IO_H_PRIVATE__

#include <libxml/encoding.h>
#include <libxml/tree.h>
#include <libxml/xmlversion.h>

/*
 * Initial buffer size should include
 *
 * - MINLEN = 4000 (I/O chunk size)
 * - INPUT_CHUNK = 250 (parser prefetch)
 * - LINE_LEN = 80 (shrink limit for error messages)
 * - some amount for unshrunken content.
 */
#define XML_IO_BUFFER_SIZE 6000

#define XML_ESCAPE_ATTR             (1u << 0)
#define XML_ESCAPE_NON_ASCII        (1u << 1)
#define XML_ESCAPE_HTML             (1u << 2)
#define XML_ESCAPE_QUOT             (1u << 3)

XML_HIDDEN xmlChar *
xmlEscapeText(const xmlChar *text, int flags);
#ifdef LIBXML_OUTPUT_ENABLED
XML_HIDDEN void
xmlSerializeText(xmlOutputBufferPtr buf, const xmlChar *string,
                 unsigned flags);
#endif

XML_HIDDEN void
xmlInitIOCallbacks(void);

XML_HIDDEN int
xmlNoNetExists(const char *filename);

XML_HIDDEN xmlParserErrors
xmlParserInputBufferCreateUrl(const char *URI, xmlCharEncoding enc,
                              xmlParserInputFlags flags,
                              xmlParserInputBufferPtr *out);

XML_HIDDEN xmlParserInputBufferPtr
xmlNewInputBufferString(const char *str, xmlParserInputFlags flags);
XML_HIDDEN xmlParserInputBufferPtr
xmlNewInputBufferMemory(const void *mem, size_t size,
                        xmlParserInputFlags flags, xmlCharEncoding enc);

XML_HIDDEN xmlParserErrors
xmlInputFromFd(xmlParserInputBufferPtr buf, int fd, xmlParserInputFlags flags);

#ifdef LIBXML_OUTPUT_ENABLED
XML_HIDDEN void
xmlOutputBufferWriteQuotedString(xmlOutputBufferPtr buf,
                                 const xmlChar *string);
#endif

#endif /* XML_IO_H_PRIVATE__ */
