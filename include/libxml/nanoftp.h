/*
 * nanohttp.c: minimalist FTP implementation to fetch external subsets.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */
 
#ifndef __NANO_FTP_H__
#define __NANO_FTP_H__
#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ftpListCallback) (void *userData,
	                         const char *filename, const char* attrib,
	                         const char *owner, const char *group,
				 unsigned long size, int links, int year,
				 const char *month, int day, int minute);
typedef void (*ftpDataCallback) (void *userData, const char *data, int len);


void *	xmlNanoFTPConnectTo	(const char *hostname, int port);
int	xmlNanoFTPClose		(void *ctx);
void *	xmlNanoFTPOpen		(const char *URL);
int	xmlNanoFTPFetch		(const char *URL,
				 const char *filename);
int	xmlNanoFTPRead		(void *ctx,
				 void *dest,
				 int len);
int	xmlNanoFTPGet		(void *ctxt, ftpDataCallback callback,
	                         void *userData, const char *filename);
#ifdef __cplusplus
}
#endif
#endif /* __NANO_FTP_H__ */
