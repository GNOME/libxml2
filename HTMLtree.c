/*
 * HTMLtree.c : implementation of access function for an HTML tree.
 *
 * See Copyright for the status of this software.
 *
 * Author: Daniel Veillard
 */


#define IN_LIBXML
#include "libxml.h"
#ifdef LIBXML_HTML_ENABLED

#include <string.h> /* for memset() only ! */
#include <ctype.h>
#include <stdlib.h>

#include <libxml/xmlmemory.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/entities.h>
#include <libxml/xmlerror.h>
#include <libxml/parserInternals.h>
#include <libxml/uri.h>

#include "private/buf.h"
#include "private/error.h"
#include "private/html.h"
#include "private/io.h"
#include "private/save.h"
#include "private/tree.h"

/************************************************************************
 *									*
 *		Getting/Setting encoding meta tags			*
 *									*
 ************************************************************************/

typedef struct {
    xmlAttrPtr attr; /* charset or content */
    const xmlChar *attrValue;
    htmlMetaEncodingOffsets off;
} htmlMetaEncoding;

static htmlNodePtr
htmlFindFirstChild(htmlNodePtr parent, const char *name) {
    htmlNodePtr child;

    for (child = parent->children; child != NULL; child = child->next) {
        if ((child->type == XML_ELEMENT_NODE) &&
            (child->ns == NULL) &&
            (xmlStrcasecmp(child->name, BAD_CAST name) == 0))
            return(child);
    }

    return(NULL);
}

static htmlNodePtr
htmlFindHead(htmlDocPtr doc) {
    htmlNodePtr html;

    if (doc == NULL)
        return(NULL);

    html = htmlFindFirstChild((htmlNodePtr) doc, "html");
    if (html == NULL)
        return(NULL);

    return(htmlFindFirstChild(html, "head"));
}

int
htmlParseContentType(const xmlChar *val, htmlMetaEncodingOffsets *off) {
    const xmlChar *p = val;

    while (1) {
        size_t start, end;

        while ((*p != 'c') && (*p != 'C')) {
            if (*p == 0)
                return(0);
            p += 1;
        }
        p += 1;

        if (xmlStrncasecmp(p, BAD_CAST "harset", 6) != 0)
            continue;

        p += 6;
        while (IS_WS_HTML(*p)) p += 1;

        if (*p != '=')
            continue;

        p += 1;
        while (IS_WS_HTML(*p)) p += 1;

        if (*p == 0)
            return(0);

        if ((*p == '"') || (*p == '\'')) {
            int quote = *p;

            p += 1;
            while (IS_WS_HTML(*p)) p += 1;

            start = p - val;
            end = start;

            while (*p != quote) {
                if (*p == 0)
                    return(0);
                if (!IS_WS_HTML(*p))
                    end = p + 1 - val;
                p += 1;
            }
        } else {
            start = p - val;

            while ((*p != 0) && (*p != ';') && (!IS_WS_HTML(*p)))
                p += 1;

            end = p - val;
        }

        off->start = start;
        off->end = end;
        off->size = p - val + strlen((char *) p);

        return(1);
    }

    return(0);
}

static xmlAttrPtr
htmlFindMetaEncodingAttr(htmlNodePtr elem, int *outIsContentType) {
    xmlAttrPtr attr, contentAttr = NULL;
    int isContentType = 0;

    if (xmlStrcasecmp(elem->name, BAD_CAST "meta") != 0)
        return(NULL);

    for (attr = elem->properties; attr != NULL; attr = attr->next) {
        if (attr->ns != NULL)
            continue;
        if (xmlStrcasecmp(attr->name, BAD_CAST "charset") == 0) {
            *outIsContentType = 0;
            return(attr);
        }
        if (xmlStrcasecmp(attr->name, BAD_CAST "content") == 0)
            contentAttr = attr;
        if ((xmlStrcasecmp(attr->name, BAD_CAST "http-equiv") == 0) &&
            (attr->children != NULL) &&
            (attr->children->type == XML_TEXT_NODE) &&
            (attr->children->next == NULL) &&
            (xmlStrcasecmp(attr->children->content,
                           BAD_CAST "Content-Type") == 0))
            isContentType = 1;
    }

    if ((isContentType) && (contentAttr != NULL)) {
        *outIsContentType = 1;
        return(contentAttr);
    }

    return(NULL);
}

static int
htmlParseMetaEncoding(htmlNodePtr elem, htmlMetaEncoding *menc) {
    xmlAttrPtr attr;
    const xmlChar *val = NULL;
    int isContentType;

    if ((elem->type != XML_ELEMENT_NODE) ||
        (elem->ns != NULL) ||
        (xmlStrcasecmp(elem->name, BAD_CAST "meta") != 0))
        return(0);

    attr = htmlFindMetaEncodingAttr(elem, &isContentType);
    if (attr == NULL)
        return(0);

    if ((attr->children != NULL) &&
        (attr->children->type == XML_TEXT_NODE) &&
        (attr->children->next == NULL) &&
        (attr->children->content != NULL))
        val = attr->children->content;
    else
        val = BAD_CAST "";


    if (!isContentType) {
        size_t size = strlen((char *) val);
        size_t start = 0;
        size_t end = size;

        while ((start < size) && (IS_WS_HTML(val[start])))
            start += 1;

        while ((end > 0) && (IS_WS_HTML(val[end-1])))
            end -= 1;

        menc->attr = attr;
        menc->attrValue = val;
        menc->off.start = start;
        menc->off.end = end;
        menc->off.size = size;

        return(1);
    } else {
        if (htmlParseContentType(val, &menc->off)) {
            menc->attr = attr;
            menc->attrValue = val;

            return(1);
        }
    }

    return(0);
}

static xmlChar *
htmlUpdateMetaEncoding(htmlMetaEncoding *menc, const char *encoding) {
    xmlChar *newVal, *p;
    size_t size, oldEncSize, newEncSize;

    /*
     * The pseudo "HTML" encoding only produces ASCII.
     */
    if (xmlStrcasecmp(BAD_CAST encoding, BAD_CAST "HTML") == 0)
        encoding = "ASCII";

    oldEncSize = menc->off.end - menc->off.start;
    newEncSize = strlen((char *) encoding);
    size = menc->off.size - oldEncSize + newEncSize;
    newVal = xmlMalloc(size + 1);
    if (newVal == NULL)
        return(NULL);

    p = newVal;
    memcpy(p, menc->attrValue, menc->off.start);
    p += menc->off.start;
    memcpy(p, encoding, newEncSize);
    p += newEncSize;
    memcpy(p, menc->attrValue + menc->off.end, menc->off.size - menc->off.end);
    newVal[size] = 0;

    return(newVal);
}

/**
 * Look up and encoding declaration in the meta tags.
 *
 * The returned string points into attribute content and can contain
 * trailing garbage. It should be copied before modifying or freeing
 * nodes.
 *
 * @param doc  the document
 * @returns the encoding ot NULL if not found.
 */
const xmlChar *
htmlGetMetaEncoding(htmlDocPtr doc) {
    htmlNodePtr head, node;

    head = htmlFindHead(doc);
    if (head == NULL)
        return(NULL);

    for (node = head->children; node != NULL; node = node->next) {
        htmlMetaEncoding menc;

        if (htmlParseMetaEncoding(node, &menc)) {
            /*
             * Returning a `const xmlChar *` only allows to return
             * a suffix. In http-equiv meta tags, there could be
             * more data after the charset, although it's probably
             * rare in practice.
             */
            return(menc.attrValue + menc.off.start);
        }
    }

    return(NULL);
}

/**
 * Creates or updates a meta tag with an encoding declaration.
 *
 * NOTE: This will not change the document content encoding.
 *
 * @param doc  the document
 * @param encoding  the encoding string
 * @returns 0 in case of success, 1 if no head element was found or
 * arguments are invalid and -1 if memory allocation failed.
 */
int
htmlSetMetaEncoding(htmlDocPtr doc, const xmlChar *encoding) {
    htmlNodePtr head, meta;
    int found = 0;

    if (encoding == NULL)
        return(1);

    head = htmlFindHead(doc);
    if (head == NULL)
        return(1);

    for (meta = head->children; meta != NULL; meta = meta->next) {
        htmlMetaEncoding menc;

        if (htmlParseMetaEncoding(meta, &menc)) {
            xmlChar *newVal;
            int ret;

            found = 1;

            newVal = htmlUpdateMetaEncoding(&menc, (char *) encoding);
            if (newVal == NULL)
                return(-1);
            xmlNodeSetContent((xmlNodePtr) menc.attr, NULL);
            ret = xmlNodeAddContent((xmlNodePtr) menc.attr, newVal);
            xmlFree(newVal);

            if (ret < 0)
                return(-1);
        }
    }

    if (found)
        return(0);

    meta = xmlNewDocNode(head->doc, NULL, BAD_CAST "meta", NULL);
    if (meta == NULL)
        return(-1);

    if (xmlNewProp(meta, BAD_CAST "charset", encoding) == NULL) {
        xmlFreeNode(meta);
        return(-1);
    }

    if (head->children == NULL)
        xmlAddChild(head, meta);
    else
        xmlAddPrevSibling(head->children, meta);

    return(0);
}

/**
 * These are the HTML attributes which will be output
 * in minimized form, i.e. `<option selected="selected">` will be
 * output as `<option selected>`, as per XSLT 1.0 16.2 "HTML Output Method"
 */
static const char* const htmlBooleanAttrs[] = {
  "checked", "compact", "declare", "defer", "disabled", "ismap",
  "multiple", "nohref", "noresize", "noshade", "nowrap", "readonly",
  "selected", NULL
};


/**
 * Determine if a given attribute is a boolean attribute. This
 * doesn't handle HTML5.
 *
 * @deprecated Internal function, don't use.
 *
 * @param name  the name of the attribute to check
 * @returns false if the attribute is not boolean, true otherwise.
 */
int
htmlIsBooleanAttr(const xmlChar *name)
{
    int i = 0;

    while (htmlBooleanAttrs[i] != NULL) {
        if (xmlStrcasecmp((const xmlChar *)htmlBooleanAttrs[i], name) == 0)
            return 1;
        i++;
    }
    return 0;
}

#ifdef LIBXML_OUTPUT_ENABLED
/************************************************************************
 *									*
 *		Dumping HTML tree content to a simple buffer		*
 *									*
 ************************************************************************/

static xmlParserErrors
htmlFindOutputEncoder(const char *encoding, xmlCharEncodingHandler **out) {
    /*
     * Fallback to HTML if the encoding is unspecified
     */
    if (encoding == NULL)
        encoding = "HTML";

    return(xmlOpenCharEncodingHandler(encoding, /* output */ 1, out));
}

/**
 * Serialize an HTML document to an xmlBuf.
 *
 * @param buf  the xmlBufPtr output
 * @param doc  the document (unused)
 * @param cur  the current node
 * @param format  should formatting newlines been added
 * @returns the number of bytes written or -1 in case of error
 */
static size_t
htmlBufNodeDumpFormat(xmlBufPtr buf, xmlDocPtr doc ATTRIBUTE_UNUSED,
                      xmlNodePtr cur, int format) {
    size_t use;
    size_t ret;
    xmlOutputBufferPtr outbuf;

    if (cur == NULL) {
	return ((size_t) -1);
    }
    if (buf == NULL) {
	return ((size_t) -1);
    }
    outbuf = (xmlOutputBufferPtr) xmlMalloc(sizeof(xmlOutputBuffer));
    if (outbuf == NULL)
	return ((size_t) -1);
    memset(outbuf, 0, sizeof(xmlOutputBuffer));
    outbuf->buffer = buf;
    outbuf->encoder = NULL;
    outbuf->writecallback = NULL;
    outbuf->closecallback = NULL;
    outbuf->context = NULL;
    outbuf->written = 0;

    use = xmlBufUse(buf);
    htmlNodeDumpInternal(outbuf, cur, NULL, format);
    if (outbuf->error)
        ret = (size_t) -1;
    else
        ret = xmlBufUse(buf) - use;
    xmlFree(outbuf);
    return (ret);
}

/**
 * Serialize an HTML node to an xmlBuffer. Always uses UTF-8.
 *
 * @param buf  the HTML buffer output
 * @param doc  the document
 * @param cur  the current node
 * @returns the number of bytes written or -1 in case of error
 */
int
htmlNodeDump(xmlBufferPtr buf, xmlDocPtr doc, xmlNodePtr cur) {
    xmlBufPtr buffer;
    size_t ret1;
    int ret2;

    if ((buf == NULL) || (cur == NULL))
        return(-1);

    xmlInitParser();
    buffer = xmlBufFromBuffer(buf);
    if (buffer == NULL)
        return(-1);

    ret1 = htmlBufNodeDumpFormat(buffer, doc, cur, 1);

    ret2 = xmlBufBackToBuffer(buffer, buf);

    if ((ret1 == (size_t) -1) || (ret2 < 0))
        return(-1);
    return(ret1 > INT_MAX ? INT_MAX : ret1);
}

/**
 * Serialize an HTML node to an xmlBuffer.
 *
 * If encoding is NULL, ASCII with HTML 4.0 named character entities
 * will be used. This is inefficient compared to UTF-8 and might be
 * changed in a future version.
 *
 * @param out  the FILE pointer
 * @param doc  the document (unused)
 * @param cur  the current node
 * @param encoding  the document encoding (optional)
 * @param format  should formatting newlines been added
 * @returns the number of bytes written or -1 in case of failure.
 */
int
htmlNodeDumpFileFormat(FILE *out, xmlDocPtr doc ATTRIBUTE_UNUSED,
	               xmlNodePtr cur, const char *encoding, int format) {
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler;
    int ret;

    xmlInitParser();

    /*
     * save the content to a temp buffer.
     */
    if (htmlFindOutputEncoder(encoding, &handler) != XML_ERR_OK)
        return(-1);
    buf = xmlOutputBufferCreateFile(out, handler);
    if (buf == NULL)
        return(-1);

    htmlNodeDumpInternal(buf, cur, NULL, format);

    ret = xmlOutputBufferClose(buf);
    return(ret);
}

/**
 * Same as htmlNodeDumpFileFormat() with `format` set to 1 which is
 * typically undesired. Use of this function is DISCOURAGED in favor
 * of htmlNodeDumpFileFormat().
 *
 * @param out  the FILE pointer
 * @param doc  the document
 * @param cur  the current node
 */
void
htmlNodeDumpFile(FILE *out, xmlDocPtr doc, xmlNodePtr cur) {
    htmlNodeDumpFileFormat(out, doc, cur, NULL, 1);
}

/**
 * Serialize an HTML node to a memory, also returning the size of
 * the result. It's up to the caller to free the memory.
 *
 * Uses the encoding of the document. If the document has no
 * encoding, ASCII with HTML 4.0 named character entities will
 * be used. This is inefficient compared to UTF-8 and might be
 * changed in a future version.
 *
 * @param cur  the document
 * @param mem  OUT: the memory pointer
 * @param size  OUT: the memory length
 * @param format  should formatting newlines been added
 */
void
htmlDocDumpMemoryFormat(xmlDocPtr cur, xmlChar**mem, int *size, int format) {
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler = NULL;

    xmlInitParser();

    if ((mem == NULL) || (size == NULL))
        return;
    *mem = NULL;
    *size = 0;
    if (cur == NULL)
	return;

    if (htmlFindOutputEncoder((char *) cur->encoding, &handler) != XML_ERR_OK)
        return;
    buf = xmlAllocOutputBuffer(handler);
    if (buf == NULL)
	return;

    htmlDocContentDumpFormatOutput(buf, cur, NULL, format);

    xmlOutputBufferFlush(buf);

    if (!buf->error) {
        if (buf->conv != NULL) {
            *size = xmlBufUse(buf->conv);
            *mem = xmlStrndup(xmlBufContent(buf->conv), *size);
        } else {
            *size = xmlBufUse(buf->buffer);
            *mem = xmlStrndup(xmlBufContent(buf->buffer), *size);
        }
    }

    xmlOutputBufferClose(buf);
}

/**
 * Same as htmlDocDumpMemoryFormat() with `format` set to 1 which
 * is typically undesired. Also see the warnings there. Use of
 * this function is DISCOURAGED in favor of
 * htmlDocContentDumpFormatOutput().
 *
 * @param cur  the document
 * @param mem  OUT: the memory pointer
 * @param size  OUT: the memory length
 */
void
htmlDocDumpMemory(xmlDocPtr cur, xmlChar**mem, int *size) {
    htmlDocDumpMemoryFormat(cur, mem, size, 1);
}


/************************************************************************
 *									*
 *		Dumping HTML tree content to an I/O output buffer	*
 *									*
 ************************************************************************/

/**
 * Serialize the HTML document's DTD, if any.
 *
 * Ignores `encoding` and uses the encoding of the output buffer.
 *
 * @param buf  the HTML buffer output
 * @param doc  the document
 * @param encoding  the encoding string (unused)
 */
static void
htmlDtdDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc,
	          const char *encoding ATTRIBUTE_UNUSED) {
    xmlDtdPtr cur = doc->intSubset;

    if (cur == NULL)
	return;
    xmlOutputBufferWriteString(buf, "<!DOCTYPE ");
    xmlOutputBufferWriteString(buf, (const char *)cur->name);
    if (cur->ExternalID != NULL) {
	xmlOutputBufferWriteString(buf, " PUBLIC ");
	xmlOutputBufferWriteQuotedString(buf, cur->ExternalID);
	if (cur->SystemID != NULL) {
	    xmlOutputBufferWriteString(buf, " ");
	    xmlOutputBufferWriteQuotedString(buf, cur->SystemID);
	}
    } else if (cur->SystemID != NULL &&
	       xmlStrcmp(cur->SystemID, BAD_CAST "about:legacy-compat")) {
	xmlOutputBufferWriteString(buf, " SYSTEM ");
	xmlOutputBufferWriteQuotedString(buf, cur->SystemID);
    }
    xmlOutputBufferWriteString(buf, ">\n");
}

/**
 * Serialize an HTML attribute.
 *
 * @param buf  the HTML buffer output
 * @param cur  the attribute pointer
 */
static void
htmlAttrDumpOutput(xmlOutputBufferPtr buf, xmlAttrPtr cur) {
    xmlChar *value;

    if (cur == NULL) {
	return;
    }
    xmlOutputBufferWriteString(buf, " ");
    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
        xmlOutputBufferWriteString(buf, (const char *)cur->ns->prefix);
	xmlOutputBufferWriteString(buf, ":");
    }
    xmlOutputBufferWriteString(buf, (const char *)cur->name);
    if ((cur->children != NULL) && (!htmlIsBooleanAttr(cur->name))) {
        int flags = XML_ESCAPE_HTML | XML_ESCAPE_ATTR;

        value = xmlNodeListGetStringInternal(cur->children, /* escape */ 1,
                                             flags);
	if (value) {
	    xmlOutputBufferWriteString(buf, "=");
	    if ((cur->ns == NULL) && (cur->parent != NULL) &&
		(cur->parent->ns == NULL) &&
		((!xmlStrcasecmp(cur->name, BAD_CAST "href")) ||
	         (!xmlStrcasecmp(cur->name, BAD_CAST "action")) ||
		 (!xmlStrcasecmp(cur->name, BAD_CAST "src")) ||
		 ((!xmlStrcasecmp(cur->name, BAD_CAST "name")) &&
		  (!xmlStrcasecmp(cur->parent->name, BAD_CAST "a"))))) {
		xmlChar *escaped;
		xmlChar *tmp = value;

		while (IS_BLANK_CH(*tmp)) tmp++;

		/*
                 * Angle brackets are technically illegal in URIs, but they're
                 * used in server side includes, for example. Curly brackets
                 * are illegal as well and often used in templates.
                 * Don't escape non-whitespace, printable ASCII chars for
                 * improved interoperability. Only escape space, control
                 * and non-ASCII chars.
		 */
		escaped = xmlURIEscapeStr(tmp,
                        BAD_CAST "\"#$%&+,/:;<=>?@[\\]^`{|}");
		if (escaped != NULL) {
		    xmlOutputBufferWriteQuotedString(buf, escaped);
		    xmlFree(escaped);
		} else {
                    buf->error = XML_ERR_NO_MEMORY;
		}
	    } else {
		xmlOutputBufferWriteQuotedString(buf, value);
	    }
	    xmlFree(value);
	} else  {
            buf->error = XML_ERR_NO_MEMORY;
	}
    }
}

/**
 * Serialize an HTML node to an output buffer.
 *
 * If `encoding` is specified, it is used to create or update meta
 * tags containing the character encoding.
 *
 * @param buf  the HTML buffer output
 * @param cur  the current node
 * @param encoding  the encoding string (optional)
 * @param format  should formatting newlines been added
 */
void
htmlNodeDumpInternal(xmlOutputBufferPtr buf, xmlNodePtr cur,
                     const char *encoding, int format) {
    xmlNodePtr root, parent, metaHead = NULL;
    xmlAttrPtr attr;
    const htmlElemDesc * info;

    xmlInitParser();

    if ((cur == NULL) || (buf == NULL)) {
	return;
    }

    root = cur;
    parent = cur->parent;
    while (1) {
        switch (cur->type) {
        case XML_HTML_DOCUMENT_NODE:
        case XML_DOCUMENT_NODE:
            if (((xmlDocPtr) cur)->intSubset != NULL) {
                htmlDtdDumpOutput(buf, (xmlDocPtr) cur, NULL);
            }
            if (cur->children != NULL) {
                /* Always validate cur->parent when descending. */
                if (cur->parent == parent) {
                    parent = cur;
                    cur = cur->children;
                    continue;
                }
            } else {
                xmlOutputBufferWriteString(buf, "\n");
            }
            break;

        case XML_ELEMENT_NODE: {
            htmlMetaEncoding menc;
            int isMeta = 0;
            int addMeta = 0;

            /*
             * Some users like lxml are known to pass nodes with a corrupted
             * tree structure. Fall back to a recursive call to handle this
             * case.
             */
            if ((cur->parent != parent) && (cur->children != NULL)) {
                htmlNodeDumpInternal(buf, cur, encoding, format);
                break;
            }

            /*
             * Get specific HTML info for that node.
             */
            if (cur->ns == NULL) {
                info = htmlTagLookup(cur->name);

                if (encoding != NULL) {
                    isMeta = htmlParseMetaEncoding(cur, &menc);

                    /*
                     * Don't add meta tag for "HTML" encoding.
                     */
                    if ((xmlStrcasecmp(BAD_CAST encoding,
                                       BAD_CAST "HTML") != 0) &&
                        (xmlStrcasecmp(cur->name, BAD_CAST "head") == 0) &&
                        (parent != NULL) &&
                        (parent->ns == NULL) &&
                        (xmlStrcasecmp(parent->name, BAD_CAST "html") == 0) &&
                        (parent->parent != NULL) &&
                        (parent->parent->parent == NULL) &&
                        (metaHead == NULL)) {
                        xmlNodePtr n;

                        metaHead = cur;
                        addMeta = 1;

                        for (n = cur->children; n != NULL; n = n->next) {
                            int unused;

                            if (htmlFindMetaEncodingAttr(n, &unused) != NULL) {
                                metaHead = NULL;
                                addMeta = 0;
                                break;
                            }
                        }
                    }
                }
            } else {
                info = NULL;
            }

            xmlOutputBufferWriteString(buf, "<");
            if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
                xmlOutputBufferWriteString(buf, (const char *)cur->ns->prefix);
                xmlOutputBufferWriteString(buf, ":");
            }
            xmlOutputBufferWriteString(buf, (const char *)cur->name);
            if (cur->nsDef)
                xmlNsListDumpOutput(buf, cur->nsDef);
            attr = cur->properties;
            while (attr != NULL) {
                if ((!isMeta) || (attr != menc.attr)) {
                    htmlAttrDumpOutput(buf, attr);
                } else {
                    xmlChar *newVal;

                    xmlOutputBufferWriteString(buf, " ");
                    xmlOutputBufferWriteString(buf, (char *) attr->name);

                    newVal = htmlUpdateMetaEncoding(&menc, encoding);
                    if (newVal == NULL) {
                        buf->error = XML_ERR_NO_MEMORY;
                        return;
                    }
                    xmlOutputBufferWriteString(buf, "=");
                    xmlOutputBufferWriteQuotedString(buf, newVal);
                    xmlFree(newVal);
                }
                attr = attr->next;
            }

            if ((info != NULL) && (info->empty)) {
                xmlOutputBufferWriteString(buf, ">");
            } else if (cur->children == NULL) {
                if ((info != NULL) && (info->saveEndTag != 0) &&
                    (xmlStrcmp(BAD_CAST info->name, BAD_CAST "html")) &&
                    (xmlStrcmp(BAD_CAST info->name, BAD_CAST "body"))) {
                    xmlOutputBufferWriteString(buf, ">");
                } else {
                    if (addMeta) {
                        xmlOutputBufferWriteString(buf, "><meta charset=\"");
                        /* TODO: Escape */
                        xmlOutputBufferWriteString(buf, encoding);
                        xmlOutputBufferWriteString(buf, "\"></");
                    } else {
                        xmlOutputBufferWriteString(buf, "></");
                    }
                    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
                        xmlOutputBufferWriteString(buf,
                                (const char *)cur->ns->prefix);
                        xmlOutputBufferWriteString(buf, ":");
                    }
                    xmlOutputBufferWriteString(buf, (const char *)cur->name);
                    xmlOutputBufferWriteString(buf, ">");
                }
            } else {
                xmlOutputBufferWriteString(buf, ">");
                if ((format) &&
                    ((addMeta) ||
                     ((info != NULL) && (!info->isinline) &&
                      (cur->children->type != HTML_TEXT_NODE) &&
                      (cur->children->type != HTML_ENTITY_REF_NODE) &&
                      (cur->children != cur->last) &&
                      (cur->name != NULL) &&
                      (cur->name[0] != 'p')))) /* p, pre, param */
                    xmlOutputBufferWriteString(buf, "\n");
                if (addMeta) {
                    xmlOutputBufferWriteString(buf, "<meta charset=\"");
                    /* TODO: Escape */
                    xmlOutputBufferWriteString(buf, encoding);
                    xmlOutputBufferWriteString(buf, "\">");
                    if ((format) &&
                        (cur->children->type != HTML_TEXT_NODE) &&
                        (cur->children->type != HTML_ENTITY_REF_NODE))
                        xmlOutputBufferWriteString(buf, "\n");
                }
                parent = cur;
                cur = cur->children;
                continue;
            }

            if ((format) && (cur->next != NULL) &&
                (info != NULL) && (!info->isinline)) {
                if ((cur->next->type != HTML_TEXT_NODE) &&
                    (cur->next->type != HTML_ENTITY_REF_NODE) &&
                    (parent != NULL) &&
                    (parent->name != NULL) &&
                    (parent->name[0] != 'p')) /* p, pre, param */
                    xmlOutputBufferWriteString(buf, "\n");
            }

            break;
        }

        case XML_ATTRIBUTE_NODE:
            htmlAttrDumpOutput(buf, (xmlAttrPtr) cur);
            break;

        case HTML_TEXT_NODE:
            if (cur->content == NULL)
                break;
            if (((cur->name == (const xmlChar *)xmlStringText) ||
                 (cur->name != (const xmlChar *)xmlStringTextNoenc)) &&
                ((parent == NULL) ||
                 ((xmlStrcasecmp(parent->name, BAD_CAST "script")) &&
                  (xmlStrcasecmp(parent->name, BAD_CAST "style"))))) {
                xmlChar *buffer;

                buffer = xmlEscapeText(cur->content, XML_ESCAPE_HTML);
                if (buffer == NULL) {
                    buf->error = XML_ERR_NO_MEMORY;
                    return;
                }
                xmlOutputBufferWriteString(buf, (const char *)buffer);
                xmlFree(buffer);
            } else {
                xmlOutputBufferWriteString(buf, (const char *)cur->content);
            }
            break;

        case HTML_COMMENT_NODE:
            if (cur->content != NULL) {
                xmlOutputBufferWriteString(buf, "<!--");
                xmlOutputBufferWriteString(buf, (const char *)cur->content);
                xmlOutputBufferWriteString(buf, "-->");
            }
            break;

        case HTML_PI_NODE:
            if (cur->name != NULL) {
                xmlOutputBufferWriteString(buf, "<?");
                xmlOutputBufferWriteString(buf, (const char *)cur->name);
                if (cur->content != NULL) {
                    xmlOutputBufferWriteString(buf, " ");
                    xmlOutputBufferWriteString(buf,
                            (const char *)cur->content);
                }
                xmlOutputBufferWriteString(buf, ">");
            }
            break;

        case HTML_ENTITY_REF_NODE:
            xmlOutputBufferWriteString(buf, "&");
            xmlOutputBufferWriteString(buf, (const char *)cur->name);
            xmlOutputBufferWriteString(buf, ";");
            break;

        case HTML_PRESERVE_NODE:
            if (cur->content != NULL) {
                xmlOutputBufferWriteString(buf, (const char *)cur->content);
            }
            break;

        default:
            break;
        }

        while (1) {
            if (cur == root)
                return;
            if (cur->next != NULL) {
                cur = cur->next;
                break;
            }

            cur = parent;
            /* cur->parent was validated when descending. */
            parent = cur->parent;

            if ((cur->type == XML_HTML_DOCUMENT_NODE) ||
                (cur->type == XML_DOCUMENT_NODE)) {
                xmlOutputBufferWriteString(buf, "\n");
            } else {
                if ((format) && (cur->ns == NULL))
                    info = htmlTagLookup(cur->name);
                else
                    info = NULL;

                if ((format) && (info != NULL) && (!info->isinline) &&
                    (cur->last->type != HTML_TEXT_NODE) &&
                    (cur->last->type != HTML_ENTITY_REF_NODE) &&
                    ((cur->children != cur->last) || (cur == metaHead)) &&
                    (cur->name != NULL) &&
                    (cur->name[0] != 'p')) /* p, pre, param */
                    xmlOutputBufferWriteString(buf, "\n");

                xmlOutputBufferWriteString(buf, "</");
                if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
                    xmlOutputBufferWriteString(buf, (const char *)cur->ns->prefix);
                    xmlOutputBufferWriteString(buf, ":");
                }
                xmlOutputBufferWriteString(buf, (const char *)cur->name);
                xmlOutputBufferWriteString(buf, ">");

                if ((format) && (info != NULL) && (!info->isinline) &&
                    (cur->next != NULL)) {
                    if ((cur->next->type != HTML_TEXT_NODE) &&
                        (cur->next->type != HTML_ENTITY_REF_NODE) &&
                        (parent != NULL) &&
                        (parent->name != NULL) &&
                        (parent->name[0] != 'p')) /* p, pre, param */
                        xmlOutputBufferWriteString(buf, "\n");
                }

                if (cur == metaHead)
                    metaHead = NULL;
            }
        }
    }
}

/**
 * Serialize an HTML node to an output buffer.
 *
 * @param buf  the HTML buffer output
 * @param doc  the document (unused)
 * @param cur  the current node
 * @param encoding  the encoding string (unused)
 * @param format  should formatting newlines been added
 */
void
htmlNodeDumpFormatOutput(xmlOutputBufferPtr buf,
                         xmlDocPtr doc ATTRIBUTE_UNUSED, xmlNodePtr cur,
                         const char *encoding ATTRIBUTE_UNUSED, int format) {
    htmlNodeDumpInternal(buf, cur, NULL, format);
}

/**
 * Same as htmlNodeDumpFormatOutput() with `format` set to 1 which is
 * typically undesired. Use of this function is DISCOURAGED in favor
 * of htmlNodeDumpFormatOutput().
 *
 * @param buf  the HTML buffer output
 * @param doc  the document (unused)
 * @param cur  the current node
 * @param encoding  the encoding string (unused)
 */
void
htmlNodeDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr doc ATTRIBUTE_UNUSED,
                   xmlNodePtr cur, const char *encoding ATTRIBUTE_UNUSED) {
    htmlNodeDumpInternal(buf, cur, NULL, 1);
}

/**
 * Serialize an HTML document to an output buffer.
 *
 * @param buf  the HTML buffer output
 * @param cur  the document
 * @param encoding  the encoding string (unused)
 * @param format  should formatting newlines been added
 */
void
htmlDocContentDumpFormatOutput(xmlOutputBufferPtr buf, xmlDocPtr cur,
	                       const char *encoding ATTRIBUTE_UNUSED,
                               int format) {
    htmlNodeDumpInternal(buf, (xmlNodePtr) cur, NULL, format);
}

/**
 * Same as htmlDocContentDumpFormatDump() with `format` set to 1
 * which is typically undesired. Use of this function is DISCOURAGED
 * in favor of htmlDocContentDumpFormatOutput().
 *
 * @param buf  the HTML buffer output
 * @param cur  the document
 * @param encoding  the encoding string (unused)
 */
void
htmlDocContentDumpOutput(xmlOutputBufferPtr buf, xmlDocPtr cur,
	                 const char *encoding ATTRIBUTE_UNUSED) {
    htmlNodeDumpInternal(buf, (xmlNodePtr) cur, NULL, 1);
}

/************************************************************************
 *									*
 *		Saving functions front-ends				*
 *									*
 ************************************************************************/

/**
 * Serialize an HTML document to an open `FILE`.
 *
 * Uses the encoding of the document. If the document has no
 * encoding, ASCII with HTML 4.0 named character entities will
 * be used. This is inefficient compared to UTF-8 and might be
 * changed in a future version.
 *
 * Enables "formatting" unconditionally which is typically
 * undesired.
 *
 * Use of this function is DISCOURAGED in favor of
 * htmlNodeDumpFileFormat().
 *
 * @param f  the FILE*
 * @param cur  the document
 * @returns the number of bytes written or -1 in case of failure.
 */
int
htmlDocDump(FILE *f, xmlDocPtr cur) {
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler = NULL;
    int ret;

    xmlInitParser();

    if ((cur == NULL) || (f == NULL)) {
	return(-1);
    }

    if (htmlFindOutputEncoder((char *) cur->encoding, &handler) != XML_ERR_OK)
        return(-1);
    buf = xmlOutputBufferCreateFile(f, handler);
    if (buf == NULL)
        return(-1);
    htmlDocContentDumpOutput(buf, cur, NULL);

    ret = xmlOutputBufferClose(buf);
    return(ret);
}

/**
 * Serialize an HTML document to a file.
 *
 * Same as htmlSaveFileFormat() with `encoding` set to NULL and
 * `format` set to 1 which is typically undesired.
 *
 * Use of this function is DISCOURAGED in favor of
 * htmlSaveFileFormat().
 *
 * @param filename  the filename (or URL)
 * @param cur  the document
 * @returns the number of bytes written or -1 in case of failure.
 */
int
htmlSaveFile(const char *filename, xmlDocPtr cur) {
    return(htmlSaveFileFormat(filename, cur, NULL, 1));
}

/**
 * Serialize an HTML document to a file using a given encoding.
 *
 * If `filename` is `"-"`, stdout is used. This is potentially
 * insecure and might be changed in a future version.
 *
 * If encoding is NULL, ASCII with HTML 4.0 named character entities
 * will be used. This is inefficient compared to UTF-8 and might be
 * changed in a future version.
 *
 * Sets or updates meta tags containing the character encoding.
 *
 * @param filename  the filename
 * @param cur  the document
 * @param format  should formatting newlines been added
 * @param encoding  the document encoding (optional)
 * @returns the number of bytes written or -1 in case of failure.
 */
int
htmlSaveFileFormat(const char *filename, xmlDocPtr cur,
	           const char *encoding, int format) {
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler = NULL;
    int ret;

    if ((cur == NULL) || (filename == NULL))
        return(-1);

    xmlInitParser();

    if (htmlFindOutputEncoder(encoding, &handler) != XML_ERR_OK)
        return(-1);

    /*
     * save the content to a temp buffer.
     */
    buf = xmlOutputBufferCreateFilename(filename, handler, cur->compression);
    if (buf == NULL)
        return(0);

    htmlDocContentDumpFormatOutput(buf, cur, encoding, format);

    ret = xmlOutputBufferClose(buf);
    return(ret);
}

/**
 * Serialize an HTML document to a file.
 *
 * Same as htmlSaveFileFormat() with `format` set to 1 which is
 * typically undesired. Also see the warnings there. Use of this
 * function is DISCOURAGED in favor of htmlSaveFileFormat().
 *
 * @param filename  the filename
 * @param cur  the document
 * @param encoding  the document encoding
 * @returns the number of bytes written or -1 in case of failure.
 */
int
htmlSaveFileEnc(const char *filename, xmlDocPtr cur, const char *encoding) {
    return(htmlSaveFileFormat(filename, cur, encoding, 1));
}

#endif /* LIBXML_OUTPUT_ENABLED */

#endif /* LIBXML_HTML_ENABLED */
