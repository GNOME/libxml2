/*
 * xmlIO.h : interface for the I/O interfaces used by the parser
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 *
 * 15 Nov 2000 ht - modified for VMS
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

/*
 * Those are the functions and datatypes for the parser input
 * I/O structures.
 */

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
    
    xmlBufferPtr buffer;    /* Local buffer encoded in UTF-8 */
    xmlBufferPtr raw;       /* if encoder != NULL buffer for raw input */
};


/*
 * Those are the functions and datatypes for the library output
 * I/O structures.
 */

typedef int (*xmlOutputMatchCallback) (char const *filename);
typedef void * (*xmlOutputOpenCallback) (char const *filename);
typedef int (*xmlOutputWriteCallback) (void * context, const char * buffer,
                                       int len);
typedef void (*xmlOutputCloseCallback) (void * context);

typedef struct _xmlOutputBuffer xmlOutputBuffer;
typedef xmlOutputBuffer *xmlOutputBufferPtr;
struct _xmlOutputBuffer {
    void*                   context;
    xmlOutputWriteCallback  writecallback;
    xmlOutputCloseCallback  closecallback;
    
    xmlCharEncodingHandlerPtr encoder; /* I18N conversions to UTF-8 */
    
    xmlBufferPtr buffer;    /* Local buffer encoded in UTF-8 or ISOLatin */
    xmlBufferPtr conv;      /* if encoder != NULL buffer for output */
    int written;            /* total number of byte written */
};

/*
 * Interfaces for input
 */

void	xmlRegisterDefaultInputCallbacks	(void);
xmlParserInputBufferPtr
	xmlAllocParserInputBuffer		(xmlCharEncoding enc);

#ifdef VMS
xmlParserInputBufferPtr
	xmlParserInputBufferCreateFname		(const char *URI,
                                                 xmlCharEncoding enc);
#define xmlParserInputBufferCreateFilename xmlParserInputBufferCreateFname
#else
xmlParserInputBufferPtr
	xmlParserInputBufferCreateFilename	(const char *URI,
                                                 xmlCharEncoding enc);
#endif

xmlParserInputBufferPtr
	xmlParserInputBufferCreateFile		(FILE *file,
                                                 xmlCharEncoding enc);
xmlParserInputBufferPtr
	xmlParserInputBufferCreateFd		(int fd,
	                                         xmlCharEncoding enc);
xmlParserInputBufferPtr
	xmlParserInputBufferCreateMem		(const char *mem, int size,
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

int     xmlRegisterInputCallbacks		(xmlInputMatchCallback matchFunc,
						 xmlInputOpenCallback openFunc,
						 xmlInputReadCallback readFunc,
						 xmlInputCloseCallback closeFunc);
/*
 * Interfaces for output
 */
void	xmlRegisterDefaultOutputCallbacks(void);
xmlOutputBufferPtr
	xmlAllocOutputBuffer		(xmlCharEncodingHandlerPtr encoder);

xmlOutputBufferPtr
	xmlOutputBufferCreateFilename	(const char *URI,
					 xmlCharEncodingHandlerPtr encoder,
					 int compression);

xmlOutputBufferPtr
	xmlOutputBufferCreateFile	(FILE *file,
					 xmlCharEncodingHandlerPtr encoder);

xmlOutputBufferPtr
	xmlOutputBufferCreateFd		(int fd,
					 xmlCharEncodingHandlerPtr encoder);

xmlOutputBufferPtr
	xmlOutputBufferCreateIO		(xmlOutputWriteCallback   iowrite,
					 xmlOutputCloseCallback  ioclose,
					 void *ioctx,
					 xmlCharEncodingHandlerPtr encoder);

int	xmlOutputBufferWrite		(xmlOutputBufferPtr out,
					 int len,
					 const char *buf);
int	xmlOutputBufferWriteString	(xmlOutputBufferPtr out,
					 const char *str);

int	xmlOutputBufferFlush		(xmlOutputBufferPtr out);
int	xmlOutputBufferClose		(xmlOutputBufferPtr out);

int     xmlRegisterOutputCallbacks	(xmlOutputMatchCallback matchFunc,
					 xmlOutputOpenCallback openFunc,
					 xmlOutputWriteCallback writeFunc,
					 xmlOutputCloseCallback closeFunc);

/*
 * This save function are part of tree.h and HTMLtree.h actually
 */
int		xmlSaveFileTo		(xmlOutputBuffer *buf,
					 xmlDocPtr cur,
					 const char *encoding);
int             xmlSaveFormatFileTo     (xmlOutputBuffer *buf,
					 xmlDocPtr cur,
				         const char *encoding,
				         int format);
void		xmlNodeDumpOutput	(xmlOutputBufferPtr buf,
					 xmlDocPtr doc,
					 xmlNodePtr cur,
					 int level,
					 int format,
					 const char *encoding);
void		htmlDocContentDumpOutput(xmlOutputBufferPtr buf,
					 xmlDocPtr cur,
					 const char *encoding);
#ifdef __cplusplus
}
#endif

#endif /* __XML_IO_H__ */
