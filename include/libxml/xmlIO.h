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
#include "parser.h"
#include "encoding.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xmlParserInputBuffer {
    /* Inputs */
    FILE          *file;    /* Input on file handler */
    void*        gzfile;    /* Input on a compressed stream */
    int              fd;    /* Input on a file descriptor */
    void         *netIO;    /* Input from a network stream */
    
    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */
    
    xmlBufferPtr buffer;    /* Local buffer encoded in  UTF-8 */

} xmlParserInputBuffer;

typedef xmlParserInputBuffer *xmlParserInputBufferPtr;

/*
 * Interfaces
 */

xmlParserInputBufferPtr
	xmlParserInputBufferCreateFilename	(const char *filename,
                                                 xmlCharEncoding enc);
xmlParserInputBufferPtr
	xmlParserInputBufferCreateFile		(FILE *file,
                                                 xmlCharEncoding enc);
xmlParserInputBufferPtr
	xmlParserInputBufferCreateFd		(int fd,
	                                         xmlCharEncoding enc);
int	xmlParserInputBufferRead		(xmlParserInputBufferPtr in,
						 int len);
int	xmlParserInputBufferGrow		(xmlParserInputBufferPtr in,
						 int len);
int	xmlParserInputBufferPush		(xmlParserInputBufferPtr in,
						 int len,
						 const char *buf);
void	xmlFreeParserInputBuffer		(xmlParserInputBufferPtr in);
char *	xmlParserGetDirectory			(const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* __XML_IO_H__ */
