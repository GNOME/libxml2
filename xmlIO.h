/*
 * xmlIO.h : interface for the I/O interfaces used by the parser
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_IO_H__
#define __XML_IO_H__

#include <stdio.h>
#include "tree.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xmlParserInputBuffer {
    /* Inputs */
    FILE          *file;    /* Input on file handler */
    int              fd;    /* Input on a file descriptor */
/**********
#ifdef HAVE_ZLIB_H
    gzFile       gzfile;     Input on a compressed stream
#endif
 */
    
    
    xmlBufferPtr buffer;    /* Local buffer encoded in  UTF-8 */

} xmlParserInputBuffer;

typedef xmlParserInputBuffer *xmlParserInputBufferPtr;

#ifdef __cplusplus
}
#endif

#endif /* __XML_IO_H__ */
