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
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/encoding.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*xmlInputMatchCallback) (char const *filename);
typedef void * (*xmlInputOpenCallback) (char const *filename);
typedef int (*xmlInputReadCallback) (void * context, char * buffer, int len);
typedef void (*xmlInputCloseCallback) (void * context);

typedef struct _xmlParserInputBuffer xmlParserInputBuffer;
typedef xmlParserInputBuffer *xmlParserInputBufferPtr;
struct _xmlParserInputBuffer {
    void*                  context;
    xmlInputReadCallback   readcallback;
    xmlInputCloseCallback  closecallback;
    
    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */
    
    xmlBufferPtr buffer;    /* Local buffer encoded in  UTF-8 */
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
xmlParserInputBufferPtr
	xmlParserInputBufferCreateIO		(xmlInputReadCallback   ioread,
						 xmlInputCloseCallback  ioclose,
						 void *ioctx,
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

int     xmlRegisterInputCallbacks		(xmlInputMatchCallback match,
						 xmlInputOpenCallback open,
						 xmlInputReadCallback read,
						 xmlInputCloseCallback close);
#ifdef __cplusplus
}
#endif

#endif /* __XML_IO_H__ */
