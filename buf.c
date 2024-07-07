/*
 * buf.c: memory buffers for libxml2
 *
 * new buffer structures and entry points to simplify the maintenance
 * of libxml2 and ensure we keep good control over memory allocations
 * and stay 64 bits clean.
 * The new entry point use the xmlBufPtr opaque structure and
 * xmlBuf...() counterparts to the old xmlBuf...() functions
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#define IN_LIBXML
#include "libxml.h"

#include <string.h>
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "private/buf.h"

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) -1)
#endif

#define WITH_BUFFER_COMPAT

#define BUF_FLAG_OOM        (1u << 0)
#define BUF_FLAG_OVERFLOW   (1u << 1)
#define BUF_FLAG_STATIC     (1u << 2)

#define BUF_ERROR(buf) ((buf)->flags & (BUF_FLAG_OOM | BUF_FLAG_OVERFLOW))
#define BUF_STATIC(buf) ((buf)->flags & BUF_FLAG_STATIC)

/**
 * xmlBuf:
 *
 * A buffer structure. The base of the structure is somehow compatible
 * with struct _xmlBuffer to limit risks on application which accessed
 * directly the input->buf->buffer structures.
 */

struct _xmlBuf {
    xmlChar *content;		/* The buffer content UTF8 */
#ifdef WITH_BUFFER_COMPAT
    unsigned int compat_use;    /* for binary compatibility */
    unsigned int compat_size;   /* for binary compatibility */
#endif
    xmlChar *mem;		/* Start of the allocation */
    size_t use;		        /* The buffer size used */
    size_t size;		/* The buffer size */
    size_t maxSize;             /* The maximum buffer size */
    unsigned flags;             /* flags */
};

#ifdef WITH_BUFFER_COMPAT
/*
 * Macro for compatibility with xmlBuffer to be used after an xmlBuf
 * is updated. This makes sure the compat fields are updated too.
 */
#define UPDATE_COMPAT(buf)				    \
     if (buf->size < INT_MAX) buf->compat_size = buf->size; \
     else buf->compat_size = INT_MAX;			    \
     if (buf->use < INT_MAX) buf->compat_use = buf->use; \
     else buf->compat_use = INT_MAX;

/*
 * Macro for compatibility with xmlBuffer to be used in all the xmlBuf
 * entry points, it checks that the compat fields have not been modified
 * by direct call to xmlBuffer function from code compiled before 2.9.0 .
 */
#define CHECK_COMPAT(buf)				    \
     if (buf->size != (size_t) buf->compat_size)	    \
         if (buf->compat_size < INT_MAX)		    \
	     buf->size = buf->compat_size;		    \
     if (buf->use != (size_t) buf->compat_use)		    \
         if (buf->compat_use < INT_MAX)			    \
	     buf->use = buf->compat_use;

#else /* ! WITH_BUFFER_COMPAT */
#define UPDATE_COMPAT(buf)
#define CHECK_COMPAT(buf)
#endif /* WITH_BUFFER_COMPAT */

/**
 * xmlBufMemoryError:
 * @extra:  extra information
 *
 * Handle an out of memory condition
 * To be improved...
 */
static void
xmlBufMemoryError(xmlBufPtr buf)
{
    if (!BUF_ERROR(buf))
        buf->flags |= BUF_FLAG_OOM;
}

/**
 * xmlBufOverflowError:
 * @extra:  extra information
 *
 * Handle a buffer overflow error
 * To be improved...
 */
static void
xmlBufOverflowError(xmlBufPtr buf)
{
    if (!BUF_ERROR(buf))
        buf->flags |= BUF_FLAG_OVERFLOW;
}

/**
 * xmlBufCreate:
 * @size: initial size of buffer
 *
 * routine to create an XML buffer.
 * returns the new structure.
 */
xmlBufPtr
xmlBufCreate(size_t size) {
    xmlBufPtr ret;

    if (size == SIZE_MAX)
        return(NULL);

    ret = xmlMalloc(sizeof(*ret));
    if (ret == NULL)
        return(NULL);

    ret->use = 0;
    ret->flags = 0;
    ret->size = size;
    ret->maxSize = SIZE_MAX;

    ret->mem = xmlMalloc(ret->size + 1);
    if (ret->mem == NULL) {
        xmlFree(ret);
        return(NULL);
    }
    ret->content = ret->mem;
    ret->content[0] = 0;

    UPDATE_COMPAT(ret);
    return(ret);
}

/**
 * xmlBufCreateMem:
 * @mem:  a memory area
 * @size:  size of the buffer excluding terminator
 * @isStatic:  whether the memory area is static
 *
 * Create a buffer initialized with memory.
 *
 * If @isStatic is set, uses the memory area directly as backing store.
 * The memory must be zero-terminated and not be modified for the
 * lifetime of the buffer. A static buffer can't be grown, modified or
 * detached, but it can be shrunk.
 *
 * Returns a new buffer.
 */
xmlBufPtr
xmlBufCreateMem(const xmlChar *mem, size_t size, int isStatic) {
    xmlBufPtr ret;

    if (mem == NULL)
        return(NULL);

    ret = xmlMalloc(sizeof(*ret));
    if (ret == NULL)
        return(NULL);

    if (isStatic) {
        /* Check that memory is zero-terminated */
        if (mem[size] != 0) {
            xmlFree(ret);
            return(NULL);
        }
        ret->flags = BUF_FLAG_STATIC;
        ret->mem = (xmlChar *) mem;
    } else {
        ret->flags = 0;
        ret->mem = xmlMalloc(size + 1);
        if (ret->mem == NULL) {
            xmlFree(ret);
            return(NULL);
        }
        memcpy(ret->mem, mem, size);
        ret->mem[size] = 0;
    }

    ret->use = size;
    ret->size = size;
    ret->maxSize = SIZE_MAX;
    ret->content = ret->mem;

    UPDATE_COMPAT(ret);
    return(ret);
}

/**
 * xmlBufDetach:
 * @buf:  the buffer
 *
 * Remove the string contained in a buffer and give it back to the
 * caller. The buffer is reset to an empty content.
 * This doesn't work with immutable buffers as they can't be reset.
 *
 * Returns the previous string contained by the buffer.
 */
xmlChar *
xmlBufDetach(xmlBufPtr buf) {
    xmlChar *ret;

    if ((buf == NULL) || (BUF_ERROR(buf)) || (BUF_STATIC(buf)))
        return(NULL);

    if (buf->content != buf->mem) {
        ret = xmlStrndup(buf->content, buf->use);
        xmlFree(buf->mem);
    } else {
        ret = buf->mem;
    }

    buf->content = NULL;
    buf->mem = NULL;
    buf->size = 0;
    buf->use = 0;

    UPDATE_COMPAT(buf);
    return ret;
}

/**
 * xmlBufFree:
 * @buf:  the buffer to free
 *
 * Frees an XML buffer. It frees both the content and the structure which
 * encapsulate it.
 */
void
xmlBufFree(xmlBufPtr buf) {
    if (buf == NULL)
	return;

    if (!BUF_STATIC(buf))
        xmlFree(buf->mem);
    xmlFree(buf);
}

/**
 * xmlBufEmpty:
 * @buf:  the buffer
 *
 * empty a buffer.
 */
void
xmlBufEmpty(xmlBufPtr buf) {
    if ((buf == NULL) || (BUF_ERROR(buf)) || (BUF_STATIC(buf)))
        return;
    if (buf->mem == NULL)
        return;
    CHECK_COMPAT(buf)

    buf->use = 0;
    buf->size += buf->content - buf->mem;
    buf->content = buf->mem;
    buf->content[0] = 0;

    UPDATE_COMPAT(buf)
}

/**
 * xmlBufShrink:
 * @buf:  the buffer to dump
 * @len:  the number of xmlChar to remove
 *
 * Remove the beginning of an XML buffer.
 * NOTE that this routine behaviour differs from xmlBufferShrink()
 * as it will return 0 on error instead of -1 due to size_t being
 * used as the return type.
 *
 * Returns the number of byte removed or 0 in case of failure
 */
size_t
xmlBufShrink(xmlBufPtr buf, size_t len) {
    if ((buf == NULL) || (BUF_ERROR(buf)))
        return(0);
    if (len == 0)
        return(0);
    CHECK_COMPAT(buf)

    if (len > buf->use)
        return(0);

    buf->use -= len;
    buf->content += len;
    buf->size -= len;

    UPDATE_COMPAT(buf)
    return(len);
}

/**
 * xmlBufGrowInternal:
 * @buf:  the buffer
 * @len:  the minimum free size to allocate
 *
 * Grow the available space of an XML buffer, @len is the target value
 *
 * Returns 0 on success, -1 in case of error
 */
static int
xmlBufGrowInternal(xmlBufPtr buf, size_t len) {
    size_t size;
    size_t start;
    xmlChar *newbuf;

    /*
     * If there's enough space at the start of the buffer,
     * move the contents.
     */
    start = buf->content - buf->mem;
    if (len <= start + buf->size - buf->use) {
        memmove(buf->mem, buf->content, buf->use + 1);
        buf->size += start;
        buf->content = buf->mem;
        return(0);
    }

    if (len >= buf->maxSize - buf->use) {
        xmlBufOverflowError(buf);
        return(-1);
    }

    if (buf->size > (size_t) len) {
        if (buf->size <= SIZE_MAX / 2)
            size = buf->size * 2;
        else
            size = buf->use + len;
    } else {
        size = buf->use + len;
        if (size < SIZE_MAX - 100)
            size += 100;
    }

    if (buf->content == buf->mem) {
        newbuf = xmlRealloc(buf->mem, size + 1);
        if (newbuf == NULL) {
            xmlBufMemoryError(buf);
            return(-1);
        }
    } else {
        newbuf = xmlMalloc(size + 1);
        if (newbuf == NULL) {
            xmlBufMemoryError(buf);
            return(-1);
        }
        if (buf->content != NULL)
            memcpy(newbuf, buf->content, buf->use + 1);
        xmlFree(buf->mem);
    }

    buf->mem = newbuf;
    buf->content = newbuf;
    buf->size = size;

    return(0);
}

/**
 * xmlBufGrow:
 * @buf:  the buffer
 * @len:  the minimum free size to allocate
 *
 * Grow the available space of an XML buffer, @len is the target value
 * This is been kept compatible with xmlBufferGrow() as much as possible
 *
 * Returns 0 on succes, -1 in case of error
 */
int
xmlBufGrow(xmlBufPtr buf, size_t len) {
    if ((buf == NULL) || (BUF_ERROR(buf)) || (BUF_STATIC(buf)))
        return(-1);
    CHECK_COMPAT(buf)

    if (len <= buf->size - buf->use)
        return(0);

    if (xmlBufGrowInternal(buf, len) < 0)
        return(-1);

    UPDATE_COMPAT(buf)
    return(0);
}

/**
 * xmlBufContent:
 * @buf:  the buffer
 *
 * Function to extract the content of a buffer
 *
 * Returns the internal content
 */

xmlChar *
xmlBufContent(const xmlBuf *buf)
{
    if ((!buf) || (BUF_ERROR(buf)))
        return NULL;

    return(buf->content);
}

/**
 * xmlBufEnd:
 * @buf:  the buffer
 *
 * Function to extract the end of the content of a buffer
 *
 * Returns the end of the internal content or NULL in case of error
 */

xmlChar *
xmlBufEnd(xmlBufPtr buf)
{
    if ((!buf) || (BUF_ERROR(buf)))
        return NULL;
    CHECK_COMPAT(buf)

    return(&buf->content[buf->use]);
}

/**
 * xmlBufAddLen:
 * @buf:  the buffer
 * @len:  the size which were added at the end
 *
 * Sometime data may be added at the end of the buffer without
 * using the xmlBuf APIs that is used to expand the used space
 * and set the zero terminating at the end of the buffer
 *
 * Returns -1 in case of error and 0 otherwise
 */
int
xmlBufAddLen(xmlBufPtr buf, size_t len) {
    if ((buf == NULL) || (BUF_ERROR(buf)) || (BUF_STATIC(buf)))
        return(-1);
    CHECK_COMPAT(buf)
    if (len > buf->size - buf->use)
        return(-1);
    buf->use += len;
    buf->content[buf->use] = 0;
    UPDATE_COMPAT(buf)
    return(0);
}

/**
 * xmlBufUse:
 * @buf:  the buffer
 *
 * Function to get the length of a buffer
 *
 * Returns the length of data in the internal content
 */

size_t
xmlBufUse(const xmlBufPtr buf)
{
    if ((!buf) || (BUF_ERROR(buf)))
        return 0;
    CHECK_COMPAT(buf)

    return(buf->use);
}

/**
 * xmlBufAvail:
 * @buf:  the buffer
 *
 * Function to find how much free space is allocated but not
 * used in the buffer. It reserves one byte for the NUL
 * terminator character that is usually needed, so there is
 * no need to subtract 1 from the result anymore.
 *
 * Returns the amount, or 0 if none or if an error occurred.
 */

size_t
xmlBufAvail(const xmlBufPtr buf)
{
    if ((!buf) || (BUF_ERROR(buf)))
        return 0;
    CHECK_COMPAT(buf)

    return(buf->size - buf->use);
}

/**
 * xmlBufIsEmpty:
 * @buf:  the buffer
 *
 * Tell if a buffer is empty
 *
 * Returns 0 if no, 1 if yes and -1 in case of error
 */
int
xmlBufIsEmpty(const xmlBufPtr buf)
{
    if ((!buf) || (BUF_ERROR(buf)))
        return(-1);
    CHECK_COMPAT(buf)

    return(buf->use == 0);
}

/**
 * xmlBufAdd:
 * @buf:  the buffer to dump
 * @str:  the #xmlChar string
 * @len:  the number of #xmlChar to add
 *
 * Add a string range to an XML buffer. if len == -1, the length of
 * str is recomputed.
 *
 * Returns 0 if successful, -1 in case of error.
 */
int
xmlBufAdd(xmlBufPtr buf, const xmlChar *str, size_t len) {
    if ((buf == NULL) || (BUF_ERROR(buf)) || (BUF_STATIC(buf)))
        return(-1);
    if (len == 0)
        return(0);
    if (str == NULL)
	return(-1);
    CHECK_COMPAT(buf)

    if (len > buf->size - buf->use) {
        if (xmlBufGrowInternal(buf, len) < 0)
            return(-1);
    }

    memmove(&buf->content[buf->use], str, len);
    buf->use += len;
    buf->content[buf->use] = 0;

    UPDATE_COMPAT(buf)
    return(0);
}

/**
 * xmlBufCat:
 * @buf:  the buffer to add to
 * @str:  the #xmlChar string
 *
 * Append a zero terminated string to an XML buffer.
 *
 * Returns 0 successful, a positive error code number otherwise
 *         and -1 in case of internal or API error.
 */
int
xmlBufCat(xmlBufPtr buf, const xmlChar *str) {
    return(xmlBufAdd(buf, str, strlen((const char *) str)));
}

/**
 * xmlBufFromBuffer:
 * @buffer: incoming old buffer to convert to a new one
 *
 * Helper routine to switch from the old buffer structures in use
 * in various APIs. It creates a wrapper xmlBufPtr which will be
 * used for internal processing until the xmlBufBackToBuffer() is
 * issued.
 *
 * Returns a new xmlBufPtr unless the call failed and NULL is returned
 */
xmlBufPtr
xmlBufFromBuffer(xmlBufferPtr buffer) {
    xmlBufPtr ret;

    if (buffer == NULL)
        return(NULL);

    ret = xmlMalloc(sizeof(xmlBuf));
    if (ret == NULL)
        return(NULL);

    ret->use = buffer->use;
    ret->flags = 0;
    ret->maxSize = SIZE_MAX;

    if (buffer->content == NULL) {
        ret->size = 50;
        ret->mem = xmlMalloc(ret->size + 1);
        ret->content = ret->mem;
        if (ret->mem == NULL)
            xmlBufMemoryError(ret);
        else
            ret->content[0] = 0;
    } else {
        ret->size = buffer->size - 1;
        ret->content = buffer->content;
        if (buffer->alloc == XML_BUFFER_ALLOC_IO)
            ret->mem = buffer->contentIO;
        else
            ret->mem = buffer->content;
    }

    UPDATE_COMPAT(ret);
    return(ret);
}

/**
 * xmlBufBackToBuffer:
 * @buf: new buffer wrapping the old one
 *
 * Function to be called once internal processing had been done to
 * update back the buffer provided by the user. This can lead to
 * a failure in case the size accumulated in the xmlBuf is larger
 * than what an xmlBuffer can support on 64 bits (INT_MAX)
 * The xmlBufPtr @buf wrapper is deallocated by this call in any case.
 *
 * Returns the old xmlBufferPtr unless the call failed and NULL is returned
 */
int
xmlBufBackToBuffer(xmlBufPtr buf, xmlBufferPtr ret) {
    if (ret == NULL)
        return(-1);
    CHECK_COMPAT(buf)

    if ((buf == NULL) || (BUF_ERROR(buf)) || (BUF_STATIC(buf)) ||
        (buf->use >= INT_MAX)) {
        if (!BUF_STATIC(buf))
            xmlBufFree(buf);
        ret->content = NULL;
        ret->contentIO = NULL;
        ret->use = 0;
        ret->size = 0;
        return(-1);
    }

    ret->use = buf->use;
    if (buf->size >= INT_MAX) {
        /* Keep the buffer but provide a truncated size value. */
        ret->size = INT_MAX;
    } else {
        ret->size = buf->size + 1;
    }
    ret->alloc = XML_BUFFER_ALLOC_IO;
    ret->content = buf->content;
    ret->contentIO = buf->mem;
    xmlFree(buf);
    return(0);
}

/**
 * xmlBufResetInput:
 * @buf: an xmlBufPtr
 * @input: an xmlParserInputPtr
 *
 * Update the input to use the current set of pointers from the buffer.
 *
 * Returns -1 in case of error, 0 otherwise
 */
int
xmlBufResetInput(xmlBufPtr buf, xmlParserInputPtr input) {
    return(xmlBufUpdateInput(buf, input, 0));
}

/**
 * xmlBufUpdateInput:
 * @buf: an xmlBufPtr
 * @input: an xmlParserInputPtr
 * @pos: the cur value relative to the beginning of the buffer
 *
 * Update the input to use the base and cur relative to the buffer
 * after a possible reallocation of its content
 *
 * Returns -1 in case of error, 0 otherwise
 */
int
xmlBufUpdateInput(xmlBufPtr buf, xmlParserInputPtr input, size_t pos) {
    if ((buf == NULL) || (input == NULL))
        return(-1);
    CHECK_COMPAT(buf)
    input->base = buf->content;
    input->cur = input->base + pos;
    input->end = &buf->content[buf->use];
    return(0);
}

