/*
 * nanohttp.c: minimalist HTTP GET implementation to fetch external subsets.
 *             focuses on size, streamability, reentrancy and portability
 *
 * This is clearly not a general purpose HTTP implementation
 * If you look for one, check:
 *         http://www.w3.org/Library/
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */
 
/* TODO add compression support, Send the Accept- , and decompress on the
        fly with ZLIB if found at compile-time */

#ifdef WIN32
#define INCLUDE_WINSOCK
#include "win32config.h"
#else
#include "config.h"
#endif

#include "xmlversion.h"

#ifdef LIBXML_HTTP_ENABLED
#include <stdio.h>
#include <string.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h> 
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <libxml/xmlmemory.h>
#include <libxml/nanohttp.h>

#ifdef STANDALONE
#define DEBUG_HTTP
#endif

#define XML_NANO_HTTP_MAX_REDIR	10

#define XML_NANO_HTTP_CHUNK	4096

#define XML_NANO_HTTP_CLOSED	0
#define XML_NANO_HTTP_WRITE	1
#define XML_NANO_HTTP_READ	2
#define XML_NANO_HTTP_NONE	4

typedef struct xmlNanoHTTPCtxt {
    char *protocol;	/* the protocol name */
    char *hostname;	/* the host name */
    int port;		/* the port */
    char *path;		/* the path within the URL */
    int fd;		/* the file descriptor for the socket */
    int state;		/* WRITE / READ / CLOSED */
    char *out;		/* buffer sent (zero terminated) */
    char *outptr;	/* index within the buffer sent */
    char *in;		/* the receiving buffer */
    char *content;	/* the start of the content */
    char *inptr;	/* the next byte to read from network */
    char *inrptr;	/* the next byte to give back to the client */
    int inlen;		/* len of the input buffer */
    int last;		/* return code for last operation */
    int returnValue;	/* the protocol return value */
    char *contentType;	/* the MIME type for the input */
    char *location;	/* the new URL in case of redirect */
} xmlNanoHTTPCtxt, *xmlNanoHTTPCtxtPtr;

static int initialized = 0;
static char *proxy = NULL;	/* the proxy name if any */
static int proxyPort;	/* the proxy port if any */

/**
 * xmlNanoHTTPInit:
 *
 * Initialize the HTTP protocol layer.
 * Currently it just checks for proxy informations
 */

void
xmlNanoHTTPInit(void) {
    const char *env;

    if (initialized)
	return;

    if (proxy == NULL) {
	proxyPort = 80;
	env = getenv("no_proxy");
	if (env != NULL)
	    goto done;
	env = getenv("http_proxy");
	if (env != NULL) {
	    xmlNanoHTTPScanProxy(env);
	    goto done;
	}
	env = getenv("HTTP_PROXY");
	if (env != NULL) {
	    xmlNanoHTTPScanProxy(env);
	    goto done;
	}
    }
done:
    initialized = 1;
}

/**
 * xmlNanoHTTPClenup:
 *
 * Cleanup the HTTP protocol layer.
 */

void
xmlNanoHTTPCleanup(void) {
    if (proxy != NULL)
	xmlFree(proxy);
    initialized = 0;
    return;
}

/**
 * xmlNanoHTTPScanURL:
 * @ctxt:  an HTTP context
 * @URL:  The URL used to initialize the context
 *
 * (Re)Initialize an HTTP context by parsing the URL and finding
 * the protocol host port and path it indicates.
 */

static void
xmlNanoHTTPScanURL(xmlNanoHTTPCtxtPtr ctxt, const char *URL) {
    const char *cur = URL;
    char buf[4096];
    int index = 0;
    int port = 0;

    if (ctxt->protocol != NULL) { 
        xmlFree(ctxt->protocol);
	ctxt->protocol = NULL;
    }
    if (ctxt->hostname != NULL) { 
        xmlFree(ctxt->hostname);
	ctxt->hostname = NULL;
    }
    if (ctxt->path != NULL) { 
        xmlFree(ctxt->path);
	ctxt->path = NULL;
    }
    if (URL == NULL) return;
    buf[index] = 0;
    while (*cur != 0) {
        if ((cur[0] == ':') && (cur[1] == '/') && (cur[2] == '/')) {
	    buf[index] = 0;
	    ctxt->protocol = xmlMemStrdup(buf);
	    index = 0;
            cur += 3;
	    break;
	}
	buf[index++] = *cur++;
    }
    if (*cur == 0) return;

    buf[index] = 0;
    while (1) {
        if (cur[0] == ':') {
	    buf[index] = 0;
	    ctxt->hostname = xmlMemStrdup(buf);
	    index = 0;
	    cur += 1;
	    while ((*cur >= '0') && (*cur <= '9')) {
	        port *= 10;
		port += *cur - '0';
		cur++;
	    }
	    if (port != 0) ctxt->port = port;
	    while ((cur[0] != '/') && (*cur != 0)) 
	        cur++;
	    break;
	}
        if ((*cur == '/') || (*cur == 0)) {
	    buf[index] = 0;
	    ctxt->hostname = xmlMemStrdup(buf);
	    index = 0;
	    break;
	}
	buf[index++] = *cur++;
    }
    if (*cur == 0) 
        ctxt->path = xmlMemStrdup("/");
    else {
        index = 0;
        buf[index] = 0;
	while (*cur != 0)
	    buf[index++] = *cur++;
	buf[index] = 0;
	ctxt->path = xmlMemStrdup(buf);
    }	
}

/**
 * xmlNanoHTTPScanProxy:
 * @URL:  The proxy URL used to initialize the proxy context
 *
 * (Re)Initialize the HTTP Proxy context by parsing the URL and finding
 * the protocol host port it indicates.
 * Should be like http://myproxy/ or http://myproxy:3128/
 * A NULL URL cleans up proxy informations.
 */

void
xmlNanoHTTPScanProxy(const char *URL) {
    const char *cur = URL;
    char buf[4096];
    int index = 0;
    int port = 0;

    if (proxy != NULL) { 
        xmlFree(proxy);
	proxy = NULL;
    }
    if (proxyPort != 0) { 
	proxyPort = 0;
    }
#ifdef DEBUG_HTTP
    if (URL == NULL)
	printf("Removing HTTP proxy info\n");
    else
	printf("Using HTTP proxy %s\n", URL);
#endif
    if (URL == NULL) return;
    buf[index] = 0;
    while (*cur != 0) {
        if ((cur[0] == ':') && (cur[1] == '/') && (cur[2] == '/')) {
	    buf[index] = 0;
	    index = 0;
            cur += 3;
	    break;
	}
	buf[index++] = *cur++;
    }
    if (*cur == 0) return;

    buf[index] = 0;
    while (1) {
        if (cur[0] == ':') {
	    buf[index] = 0;
	    proxy = xmlMemStrdup(buf);
	    index = 0;
	    cur += 1;
	    while ((*cur >= '0') && (*cur <= '9')) {
	        port *= 10;
		port += *cur - '0';
		cur++;
	    }
	    if (port != 0) proxyPort = port;
	    while ((cur[0] != '/') && (*cur != 0)) 
	        cur++;
	    break;
	}
        if ((*cur == '/') || (*cur == 0)) {
	    buf[index] = 0;
	    proxy = xmlMemStrdup(buf);
	    index = 0;
	    break;
	}
	buf[index++] = *cur++;
    }
}

/**
 * xmlNanoHTTPNewCtxt:
 * @URL:  The URL used to initialize the context
 *
 * Allocate and initialize a new HTTP context.
 *
 * Returns an HTTP context or NULL in case of error.
 */

static xmlNanoHTTPCtxtPtr
xmlNanoHTTPNewCtxt(const char *URL) {
    xmlNanoHTTPCtxtPtr ret;

    ret = (xmlNanoHTTPCtxtPtr) xmlMalloc(sizeof(xmlNanoHTTPCtxt));
    if (ret == NULL) return(NULL);

    memset(ret, 0, sizeof(xmlNanoHTTPCtxt));
    ret->port = 80;
    ret->returnValue = 0;

    xmlNanoHTTPScanURL(ret, URL);

    return(ret);
}

/**
 * xmlNanoHTTPFreeCtxt:
 * @ctxt:  an HTTP context
 *
 * Frees the context after closing the connection.
 */

static void
xmlNanoHTTPFreeCtxt(xmlNanoHTTPCtxtPtr ctxt) {
    if (ctxt == NULL) return;
    if (ctxt->hostname != NULL) xmlFree(ctxt->hostname);
    if (ctxt->protocol != NULL) xmlFree(ctxt->protocol);
    if (ctxt->path != NULL) xmlFree(ctxt->path);
    if (ctxt->out != NULL) xmlFree(ctxt->out);
    if (ctxt->in != NULL) xmlFree(ctxt->in);
    if (ctxt->contentType != NULL) xmlFree(ctxt->contentType);
    if (ctxt->location != NULL) xmlFree(ctxt->location);
    ctxt->state = XML_NANO_HTTP_NONE;
    if (ctxt->fd >= 0) close(ctxt->fd);
    ctxt->fd = -1;
    xmlFree(ctxt);
}

/**
 * xmlNanoHTTPSend:
 * @ctxt:  an HTTP context
 *
 * Send the input needed to initiate the processing on the server side
 */

static void
xmlNanoHTTPSend(xmlNanoHTTPCtxtPtr ctxt) {
    if (ctxt->state & XML_NANO_HTTP_WRITE)
	ctxt->last = write(ctxt->fd, ctxt->outptr, strlen(ctxt->outptr));
}

/**
 * xmlNanoHTTPRecv:
 * @ctxt:  an HTTP context
 *
 * Read information coming from the HTTP connection.
 * This is a blocking call (but it blocks in select(), not read()).
 *
 * Returns the number of byte read or -1 in case of error.
 */

static int
xmlNanoHTTPRecv(xmlNanoHTTPCtxtPtr ctxt) {
    fd_set rfd;
    struct timeval tv;


    while (ctxt->state & XML_NANO_HTTP_READ) {
	if (ctxt->in == NULL) {
	    ctxt->in = (char *) xmlMalloc(65000 * sizeof(char));
	    if (ctxt->in == NULL) {
	        ctxt->last = -1;
		return(-1);
	    }
	    ctxt->inlen = 65000;
	    ctxt->inptr = ctxt->content = ctxt->inrptr = ctxt->in;
	}
	if (ctxt->inrptr > ctxt->in + XML_NANO_HTTP_CHUNK) {
	    int delta = ctxt->inrptr - ctxt->in;
	    int len = ctxt->inptr - ctxt->inrptr;
	    
	    memmove(ctxt->in, ctxt->inrptr, len);
	    ctxt->inrptr -= delta;
	    ctxt->content -= delta;
	    ctxt->inptr -= delta;
	}
        if ((ctxt->in + ctxt->inlen) < (ctxt->inptr + XML_NANO_HTTP_CHUNK)) {
	    int d_inptr = ctxt->inptr - ctxt->in;
	    int d_content = ctxt->content - ctxt->in;
	    int d_inrptr = ctxt->inrptr - ctxt->in;

	    ctxt->inlen *= 2;
            ctxt->in = (char *) xmlRealloc(ctxt->in, ctxt->inlen);
	    if (ctxt->in == NULL) {
	        ctxt->last = -1;
		return(-1);
	    }
            ctxt->inptr = ctxt->in + d_inptr;
            ctxt->content = ctxt->in + d_content;
            ctxt->inrptr = ctxt->in + d_inrptr;
	}
	ctxt->last = read(ctxt->fd, ctxt->inptr, XML_NANO_HTTP_CHUNK);
	if (ctxt->last > 0) {
	    ctxt->inptr += ctxt->last;
	    return(ctxt->last);
	}
	if (ctxt->last == 0) {
	    return(0);
	}
#ifdef EWOULDBLOCK
	if ((ctxt->last == -1) && (errno != EWOULDBLOCK)) {
	    return(0);
	}
#endif
	tv.tv_sec=10;
	tv.tv_usec=0;
	FD_ZERO(&rfd);
	FD_SET(ctxt->fd, &rfd);
	
	if(select(ctxt->fd+1, &rfd, NULL, NULL, &tv)<1)
		return(0);
    }
    return(0);
}

/**
 * xmlNanoHTTPReadLine:
 * @ctxt:  an HTTP context
 *
 * Read one line in the HTTP server output, usually for extracting
 * the HTTP protocol informations from the answer header.
 *
 * Returns a newly allocated string with a copy of the line, or NULL
 *         which indicate the end of the input.
 */

static char *
xmlNanoHTTPReadLine(xmlNanoHTTPCtxtPtr ctxt) {
    char buf[4096];
    char *bp=buf;
    
    while(bp - buf < 4095) {
	if(ctxt->inrptr == ctxt->inptr) {
	    if (xmlNanoHTTPRecv(ctxt) == 0) {
		if (bp == buf)
		    return(NULL);
		else
		    *bp = 0;
		return(xmlMemStrdup(buf));
	    }
	}
	*bp = *ctxt->inrptr++;
	if(*bp == '\n') {
	    *bp = 0;
	    return(xmlMemStrdup(buf));
	}
	if(*bp != '\r')
	    bp++;
    }
    buf[4095] = 0;
    return(xmlMemStrdup(buf));
}


/**
 * xmlNanoHTTPScanAnswer:
 * @ctxt:  an HTTP context
 * @line:  an HTTP header line
 *
 * Try to extract useful informations from the server answer.
 * We currently parse and process:
 *  - The HTTP revision/ return code
 *  - The Content-Type
 *  - The Location for redirrect processing.
 *
 * Returns -1 in case of failure, the file descriptor number otherwise
 */

static void
xmlNanoHTTPScanAnswer(xmlNanoHTTPCtxtPtr ctxt, const char *line) {
    const char *cur = line;

    if (line == NULL) return;

    if (!strncmp(line, "HTTP/", 5)) {
        int version = 0;
	int ret = 0;

	cur += 5;
	while ((*cur >= '0') && (*cur <= '9')) {
	    version *= 10;
	    version += *cur - '0';
	    cur++;
	}
	if (*cur == '.') {
	    cur++;
	    if ((*cur >= '0') && (*cur <= '9')) {
		version *= 10;
		version += *cur - '0';
		cur++;
	    }
	    while ((*cur >= '0') && (*cur <= '9'))
		cur++;
	} else
	    version *= 10;
	if ((*cur != ' ') && (*cur != '\t')) return;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	if ((*cur < '0') || (*cur > '9')) return;
	while ((*cur >= '0') && (*cur <= '9')) {
	    ret *= 10;
	    ret += *cur - '0';
	    cur++;
	}
	if ((*cur != 0) && (*cur != ' ') && (*cur != '\t')) return;
	ctxt->returnValue = ret;
    } else if (!strncmp(line, "Content-Type:", 13)) {
        cur += 13;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	if (ctxt->contentType != NULL)
	    xmlFree(ctxt->contentType);
	ctxt->contentType = xmlMemStrdup(cur);
    } else if (!strncmp(line, "ContentType:", 12)) {
        cur += 12;
	if (ctxt->contentType != NULL) return;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	ctxt->contentType = xmlMemStrdup(cur);
    } else if (!strncmp(line, "content-type:", 13)) {
        cur += 13;
	if (ctxt->contentType != NULL) return;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	ctxt->contentType = xmlMemStrdup(cur);
    } else if (!strncmp(line, "contenttype:", 12)) {
        cur += 12;
	if (ctxt->contentType != NULL) return;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	ctxt->contentType = xmlMemStrdup(cur);
    } else if (!strncmp(line, "Location:", 9)) {
        cur += 9;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	if (ctxt->location != NULL)
	    xmlFree(ctxt->location);
	ctxt->location = xmlMemStrdup(cur);
    } else if (!strncmp(line, "location:", 9)) {
        cur += 9;
	if (ctxt->location != NULL) return;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	ctxt->location = xmlMemStrdup(cur);
    }
}

/**
 * xmlNanoHTTPConnectAttempt:
 * @ia:  an internet adress structure
 * @port:  the port number
 *
 * Attempt a connection to the given IP:port endpoint. It forces
 * non-blocking semantic on the socket, and allow 60 seconds for
 * the host to answer.
 *
 * Returns -1 in case of failure, the file descriptor number otherwise
 */

static int
xmlNanoHTTPConnectAttempt(struct in_addr ia, int port)
{
    int s=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sin;
    fd_set wfd;
    struct timeval tv;
    int status;
    
    if(s==-1) {
#ifdef DEBUG_HTTP
	perror("socket");
#endif
	return(-1);
    }
    
#ifdef _WINSOCKAPI_
    {
	long levents = FD_READ | FD_WRITE | FD_ACCEPT |
		       FD_CONNECT | FD_CLOSE ;
	int rv = 0 ;
	u_long one = 1;

	status = ioctlsocket(s, FIONBIO, &one) == SOCKET_ERROR ? -1 : 0;
    }
#else /* _WINSOCKAPI_ */
#if defined(VMS)
    {
	int enable = 1;
	status = IOCTL(s, FIONBIO, &enable);
    }
#else /* VMS */
    if((status = fcntl(s, F_GETFL, 0)) != -1) {
#ifdef O_NONBLOCK
	status |= O_NONBLOCK;
#else /* O_NONBLOCK */
#ifdef F_NDELAY
	status |= F_NDELAY;
#endif /* F_NDELAY */
#endif /* !O_NONBLOCK */
	status = fcntl(s, F_SETFL, status);
    }
    if(status < 0) {
#ifdef DEBUG_HTTP
	perror("nonblocking");
#endif
	close(s);
	return(-1);
    }
#endif /* !VMS */
#endif /* !_WINSOCKAPI_ */


    sin.sin_family = AF_INET;	
    sin.sin_addr   = ia;
    sin.sin_port   = htons(port);
    
    if((connect(s, (struct sockaddr *)&sin, sizeof(sin))==-1) &&
       (errno != EINPROGRESS)) {
	perror("connect");
	close(s);
	return(-1);
    }	
    
    tv.tv_sec = 60;		/* We use 60 second timeouts for now */
    tv.tv_usec = 0;
    
    FD_ZERO(&wfd);
    FD_SET(s, &wfd);
    
    switch(select(s+1, NULL, &wfd, NULL, &tv))
    {
	case 0:
	    /* Time out */
	    close(s);
	    return(-1);
	case -1:
	    /* Ermm.. ?? */
#ifdef DEBUG_HTTP
	    perror("select");
#endif
	    close(s);
	    return(-1);
    }
    
    return(s);
}
 
/**
 * xmlNanoHTTPConnectHost:
 * @host:  the host name
 * @port:  the port number
 *
 * Attempt a connection to the given host:port endpoint. It tries
 * the multiple IP provided by the DNS if available.
 *
 * Returns -1 in case of failure, the file descriptor number otherwise
 */

static int
xmlNanoHTTPConnectHost(const char *host, int port)
{
    struct hostent *h;
    int i;
    int s;
    
    h=gethostbyname(host);
    if(h==NULL)
    {
#ifdef DEBUG_HTTP
	fprintf(stderr,"unable to resolve '%s'.\n", host);
#endif
	return(-1);
    }
    
    for(i=0; h->h_addr_list[i]; i++)
    {
	struct in_addr ia;
	memcpy(&ia, h->h_addr_list[i],4);
	s = xmlNanoHTTPConnectAttempt(ia, port);
	if(s != -1)
	    return(s);
    }

#ifdef DEBUG_HTTP
    fprintf(stderr, "unable to connect to '%s'.\n", host);
#endif
    return(-1);
}


/**
 * xmlNanoHTTPOpen:
 * @URL:  The URL to load
 * @contentType:  if available the Content-Type information will be
 *                returned at that location
 *
 * This function try to open a connection to the indicated resource
 * via HTTP GET.
 *
 * Returns NULL in case of failure, otherwise a request handler.
 *     The contentType, if provided must be freed by the caller
 */

void *
xmlNanoHTTPOpen(const char *URL, char **contentType) {
    xmlNanoHTTPCtxtPtr ctxt;
    char buf[4096];
    int ret;
    char *p;
    int head;
    int nbRedirects = 0;
    char *redirURL = NULL;
    
    xmlNanoHTTPInit();
    if (contentType != NULL) *contentType = NULL;

retry:
    if (redirURL == NULL)
	ctxt = xmlNanoHTTPNewCtxt(URL);
    else {
	ctxt = xmlNanoHTTPNewCtxt(redirURL);
	xmlFree(redirURL);
	redirURL = NULL;
    }

    if ((ctxt->protocol == NULL) || (strcmp(ctxt->protocol, "http"))) {
        xmlNanoHTTPFreeCtxt(ctxt);
	if (redirURL != NULL) xmlFree(redirURL);
        return(NULL);
    }
    if (ctxt->hostname == NULL) {
        xmlNanoHTTPFreeCtxt(ctxt);
        return(NULL);
    }
    if (proxy)
	ret = xmlNanoHTTPConnectHost(proxy, proxyPort);
    else
	ret = xmlNanoHTTPConnectHost(ctxt->hostname, ctxt->port);
    if (ret < 0) {
        xmlNanoHTTPFreeCtxt(ctxt);
        return(NULL);
    }
    ctxt->fd = ret;
    if (proxy) {
#ifdef HAVE_SNPRINTF
	if (ctxt->port != 80)
	    snprintf(buf, sizeof(buf),
		     "GET http://%s:%d%s HTTP/1.0\r\nHost: %s\r\n\r\n",
		 ctxt->hostname, ctxt->port, ctxt->path, ctxt->hostname);
	else 
	    snprintf(buf, sizeof(buf),"GET http://%s%s HTTP/1.0\r\nHost: %s\r\n\r\n",
		 ctxt->hostname, ctxt->path, ctxt->hostname);
#else
	if (ctxt->port != 80)
	    sprintf(buf, 
		     "GET http://%s:%d%s HTTP/1.0\r\nHost: %s\r\n\r\n",
		 ctxt->hostname, ctxt->port, ctxt->path, ctxt->hostname);
	else 
	    sprintf(buf, "GET http://%s%s HTTP/1.0\r\nHost: %s\r\n\r\n",
		 ctxt->hostname, ctxt->path, ctxt->hostname);
#endif
#ifdef DEBUG_HTTP
	if (ctxt->port != 80)
	    printf("-> Proxy GET http://%s:%d%s HTTP/1.0\n-> Host: %s\n\n",
	           ctxt->hostname, ctxt->port, ctxt->path, ctxt->hostname);
	else
	    printf("-> Proxy GET http://%s%s HTTP/1.0\n-> Host: %s\n\n",
	           ctxt->hostname, ctxt->path, ctxt->hostname);
#endif
    } else {
#ifdef HAVE_SNPRINTF
	snprintf(buf, sizeof(buf),"GET %s HTTP/1.0\r\nHost: %s\r\n\r\n",
		 ctxt->path, ctxt->hostname);
#else
	sprintf(buf, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n",
		 ctxt->path, ctxt->hostname);
#endif
#ifdef DEBUG_HTTP
	printf("-> GET %s HTTP/1.0\n-> Host: %s\n\n",
	       ctxt->path, ctxt->hostname);
#endif
    }
    ctxt->outptr = ctxt->out = xmlMemStrdup(buf);
    ctxt->state = XML_NANO_HTTP_WRITE;
    xmlNanoHTTPSend(ctxt);
    ctxt->state = XML_NANO_HTTP_READ;
    head = 1;

    while ((p = xmlNanoHTTPReadLine(ctxt)) != NULL) {
        if (head && (*p == 0)) {
	    head = 0;
	    ctxt->content = ctxt->inrptr;
	    xmlFree(p);
	    break;
	}
	xmlNanoHTTPScanAnswer(ctxt, p);

#ifdef DEBUG_HTTP
	if (p != NULL) printf("<- %s\n", p);
#endif
        if (p != NULL) xmlFree(p);
    }

    if ((ctxt->location != NULL) && (ctxt->returnValue >= 300) &&
        (ctxt->returnValue < 400)) {
#ifdef DEBUG_HTTP
	printf("\nRedirect to: %s\n", ctxt->location);
#endif
	while (xmlNanoHTTPRecv(ctxt)) ;
        if (nbRedirects < XML_NANO_HTTP_MAX_REDIR) {
	    nbRedirects++;
	    redirURL = xmlMemStrdup(ctxt->location);
	    xmlNanoHTTPFreeCtxt(ctxt);
	    goto retry;
	}
	xmlNanoHTTPFreeCtxt(ctxt);
#ifdef DEBUG_HTTP
	printf("Too many redirrects, aborting ...\n");
#endif
	return(NULL);

    }

    if ((contentType != NULL) && (ctxt->contentType != NULL))
        *contentType = xmlMemStrdup(ctxt->contentType);

#ifdef DEBUG_HTTP
    if (ctxt->contentType != NULL)
	printf("\nCode %d, content-type '%s'\n\n",
	       ctxt->returnValue, ctxt->contentType);
    else
	printf("\nCode %d, no content-type\n\n",
	       ctxt->returnValue);
#endif

    return((void *) ctxt);
}

/**
 * xmlNanoHTTPRead:
 * @ctx:  the HTTP context
 * @dest:  a buffer
 * @len:  the buffer length
 *
 * This function tries to read @len bytes from the existing HTTP connection
 * and saves them in @dest. This is a blocking call.
 *
 * Returns the number of byte read. 0 is an indication of an end of connection.
 *         -1 indicates a parameter error.
 */
int
xmlNanoHTTPRead(void *ctx, void *dest, int len) {
    xmlNanoHTTPCtxtPtr ctxt = (xmlNanoHTTPCtxtPtr) ctx;

    if (ctx == NULL) return(-1);
    if (dest == NULL) return(-1);
    if (len <= 0) return(0);

    while (ctxt->inptr - ctxt->inrptr < len) {
        if (xmlNanoHTTPRecv(ctxt) == 0) break;
    }
    if (ctxt->inptr - ctxt->inrptr < len)
        len = ctxt->inptr - ctxt->inrptr;
    memcpy(dest, ctxt->inrptr, len);
    ctxt->inrptr += len;
    return(len);
}

/**
 * xmlNanoHTTPClose:
 * @ctx:  the HTTP context
 *
 * This function closes an HTTP context, it ends up the connection and
 * free all data related to it.
 */
void
xmlNanoHTTPClose(void *ctx) {
    xmlNanoHTTPCtxtPtr ctxt = (xmlNanoHTTPCtxtPtr) ctx;

    if (ctx == NULL) return;

    xmlNanoHTTPFreeCtxt(ctxt);
}

#ifndef DEBUG_HTTP
#define DEBUG_HTTP
#endif
/**
 * xmlNanoHTTPMethod:
 * @URL:  The URL to load
 * @method:  the HTTP method to use
 * @input:  the input string if any
 * @contentType:  the Content-Type information IN and OUT
 * @headers:  the extra headers
 *
 * This function try to open a connection to the indicated resource
 * via HTTP using the given @method, adding the given extra headers
 * and the input buffer for the request content.
 *
 * Returns NULL in case of failure, otherwise a request handler.
 *     The contentType, if provided must be freed by the caller
 */

void *
xmlNanoHTTPMethod(const char *URL, const char *method, const char *input,
                  char **contentType, const char *headers) {
    xmlNanoHTTPCtxtPtr ctxt;
    char buf[20000];
    int ret;
    char *p;
    int head;
    int nbRedirects = 0;
    char *redirURL = NULL;
    
    if (URL == NULL) return(NULL);
    if (method == NULL) method = "GET";
    if (contentType != NULL) *contentType = NULL;

retry:
    if (redirURL == NULL)
	ctxt = xmlNanoHTTPNewCtxt(URL);
    else {
	ctxt = xmlNanoHTTPNewCtxt(redirURL);
	xmlFree(redirURL);
	redirURL = NULL;
    }

    if ((ctxt->protocol == NULL) || (strcmp(ctxt->protocol, "http"))) {
        xmlNanoHTTPFreeCtxt(ctxt);
	if (redirURL != NULL) xmlFree(redirURL);
        return(NULL);
    }
    if (ctxt->hostname == NULL) {
        xmlNanoHTTPFreeCtxt(ctxt);
        return(NULL);
    }
    ret = xmlNanoHTTPConnectHost(ctxt->hostname, ctxt->port);
    if (ret < 0) {
        xmlNanoHTTPFreeCtxt(ctxt);
        return(NULL);
    }
    ctxt->fd = ret;

    if (input == NULL) {
        if (headers == NULL) {
	    if ((contentType == NULL) || (*contentType == NULL)) {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
		         "%s %s HTTP/1.0\r\nHost: %s\r\n\r\n",
			 method, ctxt->path, ctxt->hostname);
#else
		sprintf(buf,
		         "%s %s HTTP/1.0\r\nHost: %s\r\n\r\n",
			 method, ctxt->path, ctxt->hostname);
#endif
	    } else {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
		     "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\n\r\n",
			 method, ctxt->path, ctxt->hostname, *contentType);
#else
		sprintf(buf,
		     "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\n\r\n",
			 method, ctxt->path, ctxt->hostname, *contentType);
#endif
	    }
	} else {
	    if ((contentType == NULL) || (*contentType == NULL)) {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
		         "%s %s HTTP/1.0\r\nHost: %s\r\n%s\r\n",
			 method, ctxt->path, ctxt->hostname, headers);
#else
		sprintf(buf,
		         "%s %s HTTP/1.0\r\nHost: %s\r\n%s\r\n",
			 method, ctxt->path, ctxt->hostname, headers);
#endif
	    } else {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
		 "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\n%s\r\n",
			 method, ctxt->path, ctxt->hostname, *contentType,
			 headers);
#else
		sprintf(buf,
		 "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\n%s\r\n",
			 method, ctxt->path, ctxt->hostname, *contentType,
			 headers);
#endif
	    }
	}
    } else {
        int len = strlen(input);
        if (headers == NULL) {
	    if ((contentType == NULL) || (*contentType == NULL)) {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
		 "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
			 method, ctxt->path, ctxt->hostname, len, input);
#else
		sprintf(buf,
		 "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
			 method, ctxt->path, ctxt->hostname, len, input);
#endif
	    } else {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
"%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
			 method, ctxt->path, ctxt->hostname, *contentType, len,
			 input);
#else
		sprintf(buf,
"%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
			 method, ctxt->path, ctxt->hostname, *contentType, len,
			 input);
#endif
	    }
	} else {
	    if ((contentType == NULL) || (*contentType == NULL)) {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
	     "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Length: %d\r\n%s\r\n%s",
			 method, ctxt->path, ctxt->hostname, len,
			 headers, input);
#else
		sprintf(buf,
	     "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Length: %d\r\n%s\r\n%s",
			 method, ctxt->path, ctxt->hostname, len,
			 headers, input);
#endif
	    } else {
#ifdef HAVE_SNPRINTF
		snprintf(buf, sizeof(buf),
"%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s\r\n%s",
			 method, ctxt->path, ctxt->hostname, *contentType,
			 len, headers, input);
#else
		sprintf(buf,
"%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s\r\n%s",
			 method, ctxt->path, ctxt->hostname, *contentType,
			 len, headers, input);
#endif
	    }
	}
    }
#ifdef DEBUG_HTTP
    printf("-> %s", buf);
#endif
    ctxt->outptr = ctxt->out = xmlMemStrdup(buf);
    ctxt->state = XML_NANO_HTTP_WRITE;
    xmlNanoHTTPSend(ctxt);
    ctxt->state = XML_NANO_HTTP_READ;
    head = 1;

    while ((p = xmlNanoHTTPReadLine(ctxt)) != NULL) {
        if (head && (*p == 0)) {
	    head = 0;
	    ctxt->content = ctxt->inrptr;
	    if (p != NULL) xmlFree(p);
	    break;
	}
	xmlNanoHTTPScanAnswer(ctxt, p);

#ifdef DEBUG_HTTP
	if (p != NULL) printf("<- %s\n", p);
#endif
        if (p != NULL) xmlFree(p);
    }

    if ((ctxt->location != NULL) && (ctxt->returnValue >= 300) &&
        (ctxt->returnValue < 400)) {
#ifdef DEBUG_HTTP
	printf("\nRedirect to: %s\n", ctxt->location);
#endif
	while (xmlNanoHTTPRecv(ctxt)) ;
        if (nbRedirects < XML_NANO_HTTP_MAX_REDIR) {
	    nbRedirects++;
	    redirURL = xmlMemStrdup(ctxt->location);
	    xmlNanoHTTPFreeCtxt(ctxt);
	    goto retry;
	}
	xmlNanoHTTPFreeCtxt(ctxt);
#ifdef DEBUG_HTTP
	printf("Too many redirrects, aborting ...\n");
#endif
	return(NULL);

    }

    if ((contentType != NULL) && (ctxt->contentType != NULL))
        *contentType = xmlMemStrdup(ctxt->contentType);
    else if (contentType != NULL)
        *contentType = NULL;

#ifdef DEBUG_HTTP
    if (ctxt->contentType != NULL)
	printf("\nCode %d, content-type '%s'\n\n",
	       ctxt->returnValue, ctxt->contentType);
    else
	printf("\nCode %d, no content-type\n\n",
	       ctxt->returnValue);
#endif

    return((void *) ctxt);
}

/**
 * xmlNanoHTTPFetch:
 * @URL:  The URL to load
 * @filename:  the filename where the content should be saved
 * @contentType:  if available the Content-Type information will be
 *                returned at that location
 *
 * This function try to fetch the indicated resource via HTTP GET
 * and save it's content in the file.
 *
 * Returns -1 in case of failure, 0 incase of success. The contentType,
 *     if provided must be freed by the caller
 */
int
xmlNanoHTTPFetch(const char *URL, const char *filename, char **contentType) {
    void *ctxt;
    char buf[4096];
    int fd;
    int len;
    
    ctxt = xmlNanoHTTPOpen(URL, contentType);
    if (ctxt == NULL) return(-1);

    if (!strcmp(filename, "-")) 
        fd = 0;
    else {
        fd = open(filename, O_CREAT | O_WRONLY, 00644);
	if (fd < 0) {
	    xmlNanoHTTPClose(ctxt);
	    if ((contentType != NULL) && (*contentType != NULL)) {
	        xmlFree(*contentType);
		*contentType = NULL;
	    }
	    return(-1);
	}
    }

    while ((len = xmlNanoHTTPRead(ctxt, buf, sizeof(buf))) > 0) {
	write(fd, buf, len);
    }

    xmlNanoHTTPClose(ctxt);
    close(fd);
    return(0);
}

/**
 * xmlNanoHTTPSave:
 * @ctxt:  the HTTP context
 * @filename:  the filename where the content should be saved
 *
 * This function saves the output of the HTTP transaction to a file
 * It closes and free the context at the end
 *
 * Returns -1 in case of failure, 0 incase of success.
 */
int
xmlNanoHTTPSave(void *ctxt, const char *filename) {
    char buf[4096];
    int fd;
    int len;
    
    if (ctxt == NULL) return(-1);

    if (!strcmp(filename, "-")) 
        fd = 0;
    else {
        fd = open(filename, O_CREAT | O_WRONLY);
	if (fd < 0) {
	    xmlNanoHTTPClose(ctxt);
	    return(-1);
	}
    }

    while ((len = xmlNanoHTTPRead(ctxt, buf, sizeof(buf))) > 0) {
	write(fd, buf, len);
    }

    xmlNanoHTTPClose(ctxt);
    return(0);
}

/**
 * xmlNanoHTTPReturnCode:
 * @ctx:  the HTTP context
 *
 * Returns the HTTP return code for the request.
 */
int
xmlNanoHTTPReturnCode(void *ctx) {
    xmlNanoHTTPCtxtPtr ctxt = (xmlNanoHTTPCtxtPtr) ctx;

    if (ctxt == NULL) return(-1);

    return(ctxt->returnValue);
}

#ifdef STANDALONE
int main(int argc, char **argv) {
    char *contentType = NULL;

    if (argv[1] != NULL) {
	if (argv[2] != NULL) 
	    xmlNanoHTTPFetch(argv[1], argv[2], &contentType);
        else
	    xmlNanoHTTPFetch(argv[1], "-", &contentType);
	if (contentType != NULL) xmlFree(contentType);
    } else {
        printf("%s: minimal HTTP GET implementation\n", argv[0]);
        printf("\tusage %s [ URL [ filename ] ]\n", argv[0]);
    }
    xmlNanoHTTPCleanup();
    xmlMemoryDump();
    return(0);
}
#endif /* STANDALONE */
#else /* !LIBXML_HTTP_ENABLED */
#ifdef STANDALONE
#include <stdio.h>
int main(int argc, char **argv) {
    printf("%s : HTTP support not compiled in\n", argv[0]);
    return(0);
}
#endif /* STANDALONE */
#endif /* LIBXML_HTTP_ENABLED */
