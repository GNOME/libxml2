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

/**
 * ftpListCallback: 
 * A callback for the xmlNanoFTPList command
 */
typedef void (*ftpListCallback) (void *userData,
	                         const char *filename, const char* attrib,
	                         const char *owner, const char *group,
				 unsigned long size, int links, int year,
				 const char *month, int day, int minute);
/**
 * ftpDataCallback: 
 * A callback for the xmlNanoFTPGet command
 */
typedef void (*ftpDataCallback) (void *userData, const char *data, int len);

/*
 * Init
 */
void	xmlNanoFTPInit		(void);

/*
 * Creating/freeing contexts
 */
void *	xmlNanoFTPNewCtxt	(const char *URL);
void	xmlNanoFTPFreeCtxt	(void * ctx);
void * 	xmlNanoFTPConnectTo	(const char *server,
				 int port);
/*
 * Opening/closing session connections
 */
void * 	xmlNanoFTPOpen		(const char *URL);
int	xmlNanoFTPConnect	(void *ctx);
int	xmlNanoFTPClose		(void *ctx);
int	xmlNanoFTPQuit		(void *ctx);


/*
 * Rathern internal commands
 */
int	xmlNanoFTPGetResponse	(void *ctx);
int	xmlNanoFTPCheckResponse	(void *ctx);

/*
 * CD/DIR/GET handlers
 */
int	xmlNanoFTPCwd		(void *ctx,
				 char *directory);

int	xmlNanoFTPGetConnection	(void *ctx);
int	xmlNanoFTPCloseConnection(void *ctx);
int	xmlNanoFTPList		(void *ctx,
				 ftpListCallback callback,
				 void *userData,
				 char *filename);
int	xmlNanoFTPGetSocket	(void *ctx,
				 const char *filename);
int	xmlNanoFTPGet		(void *ctx,
				 ftpDataCallback callback,
				 void *userData,
				 const char *filename);
int	xmlNanoFTPRead		(void *ctx,
				 void *dest,
				 int len);

#ifdef __cplusplus
}
#endif
#endif /* __NANO_FTP_H__ */
