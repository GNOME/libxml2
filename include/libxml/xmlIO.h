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

typedef struct _xmlParserInputBuffer xmlParserInputBuffer;
typedef xmlParserInputBuffer *xmlParserInputBufferPtr;
struct _xmlParserInputBuffer {
    /* Inputs */
    FILE          *file;    /* Input on file handler */
    void*        gzfile;    /* Input on a compressed stream */
    int              fd;    /* Input on a file descriptor */
    void        *httpIO;    /* Input from an HTTP stream */
    void         *ftpIO;    /* Input from an FTP stream */
    
    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */
    
    xmlBufferPtr buffer;    /* Local buffer encoded in  UTF-8 */
    /* Added when merging 2.3.5 code */
    xmlBufferPtr raw;       /* if encoder != NULL buffer for raw input */
};


/*
 * Interfaces
 */

xmlParserInputBufferPtr
	xmlAllocParserInputBuffer		(xmlCharEncoding enc);

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
