/*
 * nanohttp.c: minimalist HTTP implementation to fetch external subsets.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */
 
#ifndef __NANO_HTTP_H__
#define __NANO_HTTP_H__

#include <libxml/xmlversion.h>
#ifdef LIBXML_HTTP_ENABLED

#ifdef __cplusplus
extern "C" {
#endif
void	xmlNanoHTTPInit		(void);
void	xmlNanoHTTPCleanup	(void);
void	xmlNanoHTTPScanProxy	(const char *URL);
int	xmlNanoHTTPFetch	(const char *URL,
				 const char *filename,
				 char **contentType);
void *	xmlNanoHTTPMethod	(const char *URL,
				 const char *method,
				 const char *input,
				 char **contentType,
				 const char *headers);
void *	xmlNanoHTTPOpen		(const char *URL,
				 char **contentType);
int	xmlNanoHTTPReturnCode	(void *ctx);
int	xmlNanoHTTPRead		(void *ctx,
				 void *dest,
				 int len);
int	xmlNanoHTTPSave		(void *ctxt,
				 const char *filename);
void	xmlNanoHTTPClose	(void *ctx);
#ifdef __cplusplus
}

#endif /* LIBXML_HTTP_ENABLED */
#endif
#endif /* __NANO_HTTP_H__ */
