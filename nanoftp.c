/*
 * ftp.c: basic handling of an FTP command connection to check for
 *        directory availability. No transfer is needed.
 *
 *  Reference: RFC 959
 */

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#include "xmlmemory.h"
#include "nanoftp.h"

/* #define DEBUG_FTP 1  */
#ifdef STANDALONE
#define DEBUG_FTP 1
#endif

static char hostname[100];

#define FTP_COMMAND_OK		200
#define FTP_SYNTAX_ERROR	500
#define FTP_GET_PASSWD		331

typedef struct xmlNanoFTPCtxt {
    char *protocol;	/* the protocol name */
    char *hostname;	/* the host name */
    int port;		/* the port */
    char *path;		/* the path within the URL */
    char *user;		/* user string */
    char *passwd;	/* passwd string */
    struct sockaddr_in ftpAddr; /* the socket address struct */
    int passive;	/* currently we support only passive !!! */
    int controlFd;	/* the file descriptor for the control socket */
    int dataFd;		/* the file descriptor for the data socket */
    int state;		/* WRITE / READ / CLOSED */
    int returnValue;	/* the protocol return value */
} xmlNanoFTPCtxt, *xmlNanoFTPCtxtPtr;

/**
 * xmlNanoFTPScanURL:
 * @ctx:  an FTP context
 * @URL:  The URL used to initialize the context
 *
 * (Re)Initialize an FTP context by parsing the URL and finding
 * the protocol host port and path it indicates.
 */

static void
xmlNanoFTPScanURL(void *ctx, const char *URL) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
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
        buf[index] = 0;
	while (*cur != 0) {
	    if ((cur[0] == '#') || (cur[0] == '?'))
	        break;
	    buf[index++] = *cur++;
	}
	buf[index] = 0;
	ctxt->path = xmlMemStrdup(buf);
    }	
}

/**
 * xmlNanoFTPNewCtxt:
 * @URL:  The URL used to initialize the context
 *
 * Allocate and initialize a new FTP context.
 *
 * Returns an FTP context or NULL in case of error.
 */

xmlNanoFTPCtxtPtr
xmlNanoFTPNewCtxt(const char *URL) {
    xmlNanoFTPCtxtPtr ret;

    ret = (xmlNanoFTPCtxtPtr) xmlMalloc(sizeof(xmlNanoFTPCtxt));
    if (ret == NULL) return(NULL);

    memset(ret, 0, sizeof(xmlNanoFTPCtxt));
    ret->port = 21;
    ret->passive = 1;
    ret->returnValue = 0;

    if (URL != NULL)
	xmlNanoFTPScanURL(ret, URL);

    return(ret);
}

/**
 * xmlNanoFTPFreeCtxt:
 * @ctxt:  an FTP context
 *
 * Frees the context after closing the connection.
 */

static void
xmlNanoFTPFreeCtxt(xmlNanoFTPCtxtPtr ctxt) {
    if (ctxt == NULL) return;
    if (ctxt->hostname != NULL) xmlFree(ctxt->hostname);
    if (ctxt->protocol != NULL) xmlFree(ctxt->protocol);
    if (ctxt->path != NULL) xmlFree(ctxt->path);
    ctxt->passive = 1;
    if (ctxt->controlFd >= 0) close(ctxt->controlFd);
    ctxt->controlFd = -1;
    xmlFree(ctxt);
}

/*
 * Initialize the FTP handling.
 */

void xmlNanoFTPInit(void) {
    static int done = 0;
    if (done) return;
    gethostname(hostname, sizeof(hostname));
    done = 1;
}

/*
 * Parsing of the server answer, we just extract the code.
 * return 0 for errors
 *     +XXX for last line of response
 *     -XXX for response to be continued
 */
int
xmlNanoFTPParseResponse(void *ctx, char *buf, int len) {
    int val = 0;

    if (len < 3) return(-1);
    if ((*buf >= '0') && (*buf <= '9')) 
        val = val * 10 + (*buf - '0');
    else
        return(0);
    buf++;
    if ((*buf >= '0') && (*buf <= '9')) 
        val = val * 10 + (*buf - '0');
    else
        return(0);
    buf++;
    if ((*buf >= '0') && (*buf <= '9')) 
        val = val * 10 + (*buf - '0');
    else
        return(0);
    buf++;
    if (*buf == '-') 
        return(-val);
    return(val);
}

/*
 * Read the response from the FTP server after a command.
 * Returns the code number
 *
 */
int
xmlNanoFTPReadResponse(void *ctx, char *buf, int size) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char *ptr, *end;
    int len;
    int res = -1;

    if (size <= 0) return(-1);

get_more:
    if ((len = recv(ctxt->controlFd, buf, size - 1, 0)) < 0) {
	close(ctxt->controlFd); ctxt->controlFd = -1;
        ctxt->controlFd = -1;
        return(-1);
    }
    if (len == 0) {
        return(-1);
    }

    end = &buf[len];
    *end = 0;
#ifdef DEBUG_FTP
    printf(buf);
#endif
    ptr = buf;
    while (ptr < end) {
        res = xmlNanoFTPParseResponse(ctxt, ptr, end - ptr);
	if (res > 0) break;
	if (res == 0) {
#ifdef DEBUG_FTP
	    fprintf(stderr, "xmlNanoFTPReadResponse failed: %s\n", ptr);
#endif
	    return(-1);
	}
	while ((ptr < end) && (*ptr != '\n')) ptr++;
	if (ptr >= end) {
#ifdef DEBUG_FTP
	    fprintf(stderr, "xmlNanoFTPReadResponse: unexpected end %s\n", buf);
#endif
	    return((-res) / 100);
	}
	if (*ptr != '\r') ptr++;
    }

    if (res < 0) goto get_more;

#ifdef DEBUG_FTP
    printf("Got %d\n", res);
#endif
    return(res / 100);
}

/*
 * Get the response from the FTP server after a command.
 * Returns the code number
 *
 */
int
xmlNanoFTPGetResponse(void *ctx) {
    char buf[16 * 1024 + 1];

/**************
    fd_set rfd;
    struct timeval tv;
    int res;

    tv.tv_sec = 10;
    tv.tv_usec = 0;
    FD_ZERO(&rfd);
    FD_SET(ctxt->controlFd, &rfd);
    res = select(ctxt->controlFd + 1, &rfd, NULL, NULL, &tv);
    if (res <= 0) return(res);
 **************/

    return(xmlNanoFTPReadResponse(ctx, buf, 16 * 1024));
}

/*
 * Check if there is a response from the FTP server after a command.
 * Returns the code number, or 0
 */
int
xmlNanoFTPCheckResponse(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[1024 + 1];
    fd_set rfd;
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&rfd);
    FD_SET(ctxt->controlFd, &rfd);
    switch(select(ctxt->controlFd + 1, &rfd, NULL, NULL, &tv)) {
	case 0:
	    return(0);
	case -1:
#ifdef DEBUG_FTP
	    perror("select");
#endif
	    return(-1);
			
    }

    return(xmlNanoFTPReadResponse(ctx, buf, 1024));
}

/*
 * Send the user authentification
 */

int
sendUser(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[200];
    int len;
    int res;

    if (ctxt->user == NULL)
	len = snprintf(buf, sizeof(buf), "USER anonymous\r\n");
    else
	len = snprintf(buf, sizeof(buf), "USER %s\r\n", ctxt->user);
#ifdef DEBUG_FTP
    printf(buf);
#endif
    res = send(ctxt->controlFd, buf, len, 0);
    if (res < 0) return(res);
    return(0);
}

/*
 * Send the password authentification
 */

int
sendPasswd(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[200];
    int len;
    int res;

    if (ctxt->passwd == NULL)
	len = snprintf(buf, sizeof(buf), "PASS libxml@%s\r\n", hostname);
    else
	len = snprintf(buf, sizeof(buf), "PASS %s\r\n", ctxt->passwd);
#ifdef DEBUG_FTP
    printf(buf);
#endif
    res = send(ctxt->controlFd, buf, len, 0);
    if (res < 0) return(res);
    return(0);
}

/*
 * Send a QUIT
 */

int
sendQuit(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[200];
    int len;
    int res;

    len = snprintf(buf, sizeof(buf), "QUIT\r\n");
#ifdef DEBUG_FTP
    printf(buf);
#endif
    res = send(ctxt->controlFd, buf, len, 0);
    return(0);
}

/*
 * Connecting to the server, port 21 by default.
 */

int
xmlNanoFTPConnect(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    struct hostent *hp;
    int res;

    if (ctxt == NULL)
	return(-1);
    if (ctxt->hostname == NULL)
	return(-1);

    /*
     * do the blocking DNS query.
     */
    hp = gethostbyname(ctxt->hostname);
    if (hp == NULL)
        return(-1);

    /*
     * Prepare the socket
     */
    memset(&ctxt->ftpAddr, 0, sizeof(ctxt->ftpAddr));
    ctxt->ftpAddr.sin_family = AF_INET;
    memcpy(&ctxt->ftpAddr.sin_addr, hp->h_addr_list[0], hp->h_length);
    if (ctxt->port == 0)
        ctxt->port = 21;
    ctxt->ftpAddr.sin_port = htons(ctxt->port);
    ctxt->controlFd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctxt->controlFd < 0)
        return(-1);

    /*
     * Do the connect.
     */
    if (connect(ctxt->controlFd, (struct sockaddr *) &ctxt->ftpAddr,
                sizeof(struct sockaddr_in)) < 0) {
        close(ctxt->controlFd); ctxt->controlFd = -1;
        ctxt->controlFd = -1;
	return(-1);
    }

    /*
     * Wait for the HELLO from the server.
     */
    res = xmlNanoFTPGetResponse(ctxt);
    if (res != 2) {
        close(ctxt->controlFd); ctxt->controlFd = -1;
        ctxt->controlFd = -1;
	return(-1);
    }

    /*
     * State diagram for the login operation on the FTP server
     *
     * Reference: RFC 959
     *
     *                       1
     * +---+   USER    +---+------------->+---+
     * | B |---------->| W | 2       ---->| E |
     * +---+           +---+------  |  -->+---+
     *                  | |       | | |
     *                3 | | 4,5   | | |
     *    --------------   -----  | | |
     *   |                      | | | |
     *   |                      | | | |
     *   |                 ---------  |
     *   |               1|     | |   |
     *   V                |     | |   |
     * +---+   PASS    +---+ 2  |  ------>+---+
     * |   |---------->| W |------------->| S |
     * +---+           +---+   ---------->+---+
     *                  | |   | |     |
     *                3 | |4,5| |     |
     *    --------------   --------   |
     *   |                    | |  |  |
     *   |                    | |  |  |
     *   |                 -----------
     *   |             1,3|   | |  |
     *   V                |  2| |  |
     * +---+   ACCT    +---+--  |   ----->+---+
     * |   |---------->| W | 4,5 -------->| F |
     * +---+           +---+------------->+---+
     */
    res = sendUser(ctxt);
    if (res < 0) {
        close(ctxt->controlFd); ctxt->controlFd = -1;
        ctxt->controlFd = -1;
	return(-1);
    }
    res = xmlNanoFTPGetResponse(ctxt);
    switch (res) {
	case 2:
	    return(0);
	case 3:
	    break;
	case 1:
	case 4:
	case 5:
        case -1:
	default:
	    close(ctxt->controlFd); ctxt->controlFd = -1;
	    ctxt->controlFd = -1;
	    return(-1);
    }
    res = sendPasswd(ctxt);
    if (res < 0) {
        close(ctxt->controlFd); ctxt->controlFd = -1;
        ctxt->controlFd = -1;
	return(-1);
    }
    res = xmlNanoFTPGetResponse(ctxt);
    switch (res) {
	case 2:
	    return(0);
	case 3:
	    fprintf(stderr, "FTP server asking for ACCNT on anonymous\n");
	case 1:
	case 4:
	case 5:
        case -1:
	default:
	    close(ctxt->controlFd); ctxt->controlFd = -1;
	    ctxt->controlFd = -1;
	    return(-1);
    }

    return(0);
}

/*
 * Connecting to a given server server/port
 */

void *
xmlNanoFTPConnectTo(const char *server, int port) {
    xmlNanoFTPCtxtPtr ctxt;
    int res;

    xmlNanoFTPInit();
    if (server == NULL) 
	return(NULL);
    ctxt = xmlNanoFTPNewCtxt(NULL);
    ctxt->hostname = xmlMemStrdup(server);
    if (port != 0)
	ctxt->port = port;
    res = xmlNanoFTPConnect(ctxt);
    if (res < 0) {
	xmlNanoFTPFreeCtxt(ctxt);
	return(NULL);
    }
    return(ctxt);
}

/*
 * Check an FTP directory on the server
 */

int
xmlNanoFTPCwd(void *ctx, char *directory) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[400];
    int len;
    int res;

    /*
     * Expected response code for CWD:
     *
     * CWD
     *     250
     *     500, 501, 502, 421, 530, 550
     */
    len = snprintf(buf, sizeof(buf), "CWD %s\r\n", directory);
#ifdef DEBUG_FTP
    printf(buf);
#endif
    res = send(ctxt->controlFd, buf, len, 0);
    if (res < 0) return(res);
    res = xmlNanoFTPGetResponse(ctxt);
    if (res == 4) {
	close(ctxt->controlFd); ctxt->controlFd = -1;
	ctxt->controlFd = -1;
	return(-1);
    }
    if (res == 2) return(1);
    if (res == 5) {
	return(0);
    }
    return(0);
}

/*
 * xmlNanoFTPGetConnection
 */
int
xmlNanoFTPGetConnection(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[200], *cur;
    int len, i;
    int res;
    unsigned char ad[6], *adp, *portp;
    unsigned int temp[6];
    struct sockaddr_in dataAddr;
    size_t dataAddrLen;

    ctxt->dataFd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ctxt->dataFd < 0) {
        fprintf(stderr, "xmlNanoFTPGetConnection: failed to create socket\n");
    }
    dataAddrLen = sizeof(dataAddr);
    memset(&dataAddr, 0, dataAddrLen);
    dataAddr.sin_family = AF_INET;

    if (ctxt->passive) {
	len = snprintf(buf, sizeof(buf), "PASV\r\n");
#ifdef DEBUG_FTP
	printf(buf);
#endif
	res = send(ctxt->controlFd, buf, len, 0);
	if (res < 0) {
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return(res);
	}
        res = xmlNanoFTPReadResponse(ctx, buf, sizeof(buf) -1);
	if (res != 2) {
	    if (res == 5) {
	        close(ctxt->dataFd); ctxt->dataFd = -1;
		return(-1);
	    } else {
		/*
		 * retry with an active connection
		 */
	        close(ctxt->dataFd); ctxt->dataFd = -1;
	        ctxt->passive = 0;
	    }
	}
	cur = &buf[4];
	while (((*cur < '0') || (*cur > '9')) && *cur != '\0') cur++;
	if (sscanf(cur, "%d,%d,%d,%d,%d,%d", &temp[0], &temp[1], &temp[2],
	            &temp[3], &temp[4], &temp[5]) != 6) {
	    fprintf(stderr, "Invalid answer to PASV\n");
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return(-1);
	}
	for (i=0; i<6; i++) ad[i] = (unsigned char) (temp[i] & 0xff);
	memcpy(&dataAddr.sin_addr, &ad[0], 4);
	memcpy(&dataAddr.sin_port, &ad[4], 2);
	if (connect(ctxt->dataFd, (struct sockaddr *) &dataAddr, dataAddrLen) < 0) {
	    fprintf(stderr, "Failed to create a data connection\n");
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return (-1);
	}
    } else {
        getsockname(ctxt->dataFd, (struct sockaddr *) &dataAddr, &dataAddrLen);
	dataAddr.sin_port = 0;
	if (bind(ctxt->dataFd, (struct sockaddr *) &dataAddr, dataAddrLen) < 0) {
	    fprintf(stderr, "Failed to bind a port\n");
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return (-1);
	}
        getsockname(ctxt->dataFd, (struct sockaddr *) &dataAddr, &dataAddrLen);

	if (listen(ctxt->dataFd, 1) < 0) {
	    fprintf(stderr, "Could not listen on port %d\n",
	            ntohs(dataAddr.sin_port));
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return (-1);
	}
	adp = (unsigned char *) &dataAddr.sin_addr;
	portp = (unsigned char *) &dataAddr.sin_port;
	len = snprintf(buf, sizeof(buf), "PORT %d,%d,%d,%d,%d,%d\r\n",
	               adp[0] & 0xff, adp[1] & 0xff, adp[2] & 0xff, adp[3] & 0xff,
		       portp[0] & 0xff, portp[1] & 0xff);
        buf[sizeof(buf) - 1] = 0;
#ifdef DEBUG_FTP
	printf(buf);
#endif

	res = send(ctxt->controlFd, buf, len, 0);
	if (res < 0) {
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return(res);
	}
        res = xmlNanoFTPGetResponse(ctxt);
	if (res != 2) {
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return(-1);
        }
    }
    return(ctxt->dataFd);
    
}

/*
 * xmlNanoFTPCloseConnection
 */
int
xmlNanoFTPCloseConnection(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    int res;

    close(ctxt->dataFd); ctxt->dataFd = -1;
    res = xmlNanoFTPGetResponse(ctxt);
    if (res != 2) {
	close(ctxt->dataFd); ctxt->dataFd = -1;
	close(ctxt->controlFd); ctxt->controlFd = -1;
	return(-1);
    }
    return(0);
}

/*
 * xmlNanoFTPParseList
 */

static int
xmlNanoFTPParseList(const char *list, ftpListCallback callback, void *userData) {
    const char *cur = list;
    char filename[151];
    char attrib[11];
    char owner[11];
    char group[11];
    char month[4];
    int year = 0;
    int minute = 0;
    int hour = 0;
    int day = 0;
    unsigned long size = 0;
    int links = 0;
    int i;

    if (!strncmp(cur, "total", 5)) {
        cur += 5;
	while (*cur == ' ') cur++;
	while ((*cur >= '0') && (*cur <= '9'))
	    links = (links * 10) + (*cur++ - '0');
	while ((*cur == ' ') || (*cur == '\n')  || (*cur == '\r'))
	    cur++;
	return(cur - list);
    } else if (*list == '+') {
	return(0);
    } else {
	while ((*cur == ' ') || (*cur == '\n')  || (*cur == '\r'))
	    cur++;
	if (*cur == 0) return(0);
	i = 0;
	while (*cur != ' ') {
	    if (i < 10) 
		attrib[i++] = *cur;
	    cur++;
	    if (*cur == 0) return(0);
	}
	attrib[10] = 0;
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
	while ((*cur >= '0') && (*cur <= '9'))
	    links = (links * 10) + (*cur++ - '0');
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
	i = 0;
	while (*cur != ' ') {
	    if (i < 10) 
		owner[i++] = *cur;
	    cur++;
	    if (*cur == 0) return(0);
	}
	owner[i] = 0;
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
	i = 0;
	while (*cur != ' ') {
	    if (i < 10) 
		group[i++] = *cur;
	    cur++;
	    if (*cur == 0) return(0);
	}
	group[i] = 0;
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
	while ((*cur >= '0') && (*cur <= '9'))
	    size = (size * 10) + (*cur++ - '0');
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
	i = 0;
	while (*cur != ' ') {
	    if (i < 3)
		month[i++] = *cur;
	    cur++;
	    if (*cur == 0) return(0);
	}
	month[i] = 0;
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
        while ((*cur >= '0') && (*cur <= '9'))
	    day = (day * 10) + (*cur++ - '0');
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
	if ((cur[1] == 0) || (cur[2] == 0)) return(0);
	if ((cur[1] == ':') || (cur[2] == ':')) {
	    while ((*cur >= '0') && (*cur <= '9'))
		hour = (hour * 10) + (*cur++ - '0');
	    if (*cur == ':') cur++;
	    while ((*cur >= '0') && (*cur <= '9'))
		minute = (minute * 10) + (*cur++ - '0');
	} else {
	    while ((*cur >= '0') && (*cur <= '9'))
		year = (year * 10) + (*cur++ - '0');
	}
	while (*cur == ' ') cur++;
	if (*cur == 0) return(0);
	i = 0;
	while ((*cur != '\n')  && (*cur != '\r')) {
	    if (i < 150)
		filename[i++] = *cur;
	    cur++;
	    if (*cur == 0) return(0);
	}
	filename[i] = 0;
	if ((*cur != '\n') && (*cur != '\r'))
	    return(0);
	while ((*cur == '\n')  || (*cur == '\r'))
	    cur++;
    }
    if (callback != NULL) {
        callback(userData, filename, attrib, owner, group, size, links,
		 year, month, day, minute);
    }
    return(cur - list);
}

/*
 * xmlNanoFTPList
 */
int
xmlNanoFTPList(void *ctx, ftpListCallback callback, void *userData) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[4096 + 1];
    int len, res;
    int index = 0, base;
    fd_set rfd, efd;
    struct timeval tv;

    ctxt->dataFd = xmlNanoFTPGetConnection(ctxt);

    len = snprintf(buf, sizeof(buf), "LIST -L\r\n");
#ifdef DEBUG_FTP
    printf(buf);
#endif
    res = send(ctxt->controlFd, buf, len, 0);
    if (res < 0) {
	close(ctxt->dataFd); ctxt->dataFd = -1;
	return(res);
    }
    res = xmlNanoFTPReadResponse(ctxt, buf, sizeof(buf) -1);
    if (res != 1) {
	close(ctxt->dataFd); ctxt->dataFd = -1;
	return(-res);
    }

    do {
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	FD_ZERO(&rfd);
	FD_SET(ctxt->dataFd, &rfd);
	FD_ZERO(&efd);
	FD_SET(ctxt->dataFd, &efd);
	res = select(ctxt->dataFd + 1, &rfd, NULL, &efd, &tv);
	if (res < 0) {
#ifdef DEBUG_FTP
	    perror("select");
#endif
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return(-1);
	}
	if (res == 0) {
	    res = xmlNanoFTPCheckResponse(ctxt);
	    if (res < 0) {
		close(ctxt->dataFd); ctxt->dataFd = -1;
		ctxt->dataFd = -1;
		return(-1);
	    }
	    if (res == 2) {
		close(ctxt->dataFd); ctxt->dataFd = -1;
		return(0);
	    }

	    continue;
	}

	if ((len = read(ctxt->dataFd, &buf[index], sizeof(buf) - (index + 1))) < 0) {
#ifdef DEBUG_FTP
	    perror("read");
#endif
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    ctxt->dataFd = -1;
	    return(-1);
	}
#ifdef DEBUG_FTP
        write(1, &buf[index], len);
#endif
	index += len;
	buf[index] = 0;
	base = 0;
	do {
	    res = xmlNanoFTPParseList(&buf[base], callback, userData);
	    base += res;
	} while (res > 0);

	memmove(&buf[0], &buf[base], index - base);
	index -= base;
    } while (len != 0);
    xmlNanoFTPCloseConnection(ctxt);
    return(0);
}

/*
 * xmlNanoFTPGetSocket:
 */

int
xmlNanoFTPGetSocket(void *ctx, const char *filename) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[300];
    int res, len;
    if (filename == NULL)
	return(-1);
    ctxt->dataFd = xmlNanoFTPGetConnection(ctxt);

    len = snprintf(buf, sizeof(buf), "TYPE I\r\n");
#ifdef DEBUG_FTP
    printf(buf);
#endif
    res = send(ctxt->controlFd, buf, len, 0);
    if (res < 0) {
	close(ctxt->dataFd); ctxt->dataFd = -1;
	return(res);
    }
    res = xmlNanoFTPReadResponse(ctxt, buf, sizeof(buf) -1);
    if (res != 2) {
	close(ctxt->dataFd); ctxt->dataFd = -1;
	return(-res);
    }
    len = snprintf(buf, sizeof(buf), "RETR %s\r\n", filename);
#ifdef DEBUG_FTP
    printf(buf);
#endif
    res = send(ctxt->controlFd, buf, len, 0);
    if (res < 0) {
	close(ctxt->dataFd); ctxt->dataFd = -1;
	return(res);
    }
    res = xmlNanoFTPReadResponse(ctxt, buf, sizeof(buf) -1);
    if (res != 1) {
	close(ctxt->dataFd); ctxt->dataFd = -1;
	return(-res);
    }
    return(ctxt->dataFd);
}

/*
 * xmlNanoFTPList
 */
int
xmlNanoFTPGet(void *ctx, ftpDataCallback callback, void *userData, const char *filename) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;
    char buf[4096];
    int len = 0, res;
    fd_set rfd;
    struct timeval tv;

    if (filename == NULL)
	return(-1);
    if (callback == NULL)
	return(-1);
    if (xmlNanoFTPGetSocket(ctxt, filename) < 0)
	return(-1);

    do {
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	FD_ZERO(&rfd);
	FD_SET(ctxt->dataFd, &rfd);
	res = select(ctxt->dataFd + 1, &rfd, NULL, NULL, &tv);
	if (res < 0) {
#ifdef DEBUG_FTP
	    perror("select");
#endif
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return(-1);
	}
	if (res == 0) {
	    res = xmlNanoFTPCheckResponse(ctxt);
	    if (res < 0) {
		close(ctxt->dataFd); ctxt->dataFd = -1;
		ctxt->dataFd = -1;
		return(-1);
	    }
	    if (res == 2) {
		close(ctxt->dataFd); ctxt->dataFd = -1;
		return(0);
	    }

	    continue;
	}
	if ((len = read(ctxt->dataFd, &buf, sizeof(buf))) < 0) {
	    callback(userData, buf, len);
	    close(ctxt->dataFd); ctxt->dataFd = -1;
	    return(-1);
	}
	callback(userData, buf, len);
    } while (len != 0);

    return(xmlNanoFTPCloseConnection(ctxt));
}

/**
 * xmlNanoFTPRead:
 * @ctx:  the FTP context
 * @dest:  a buffer
 * @len:  the buffer length
 *
 * This function tries to read @len bytes from the existing FTP connection
 * and saves them in @dest. This is a blocking call.
 *
 * Returns the number of byte read. 0 is an indication of an end of connection.
 *         -1 indicates a parameter error.
 */
int
xmlNanoFTPRead(void *ctx, void *dest, int len) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;

    if (ctx == NULL) return(-1);
    if (ctxt->dataFd < 0) return(0);
    if (dest == NULL) return(-1);
    if (len <= 0) return(0);

    len = read(ctxt->dataFd, dest, len);
#ifdef DEBUG_FTP
    printf("Read %d bytes\n", len);
#endif
    if (len <= 0) {
	xmlNanoFTPCloseConnection(ctxt);
    }
    return(len);
}

/*
 * xmlNanoFTPOpen:
 * @URL: the URL to the resource
 *
 * Start to fetch the given ftp:// resource
 */

void *
xmlNanoFTPOpen(const char *URL) {
    xmlNanoFTPCtxtPtr ctxt;
    int sock;

    xmlNanoFTPInit();
    if (URL == NULL) return(NULL);
    if (strncmp("ftp://", URL, 6)) return(NULL);

    ctxt = xmlNanoFTPNewCtxt(URL);
    if (ctxt == NULL) return(NULL);
    if (xmlNanoFTPConnect(ctxt) < 0) {
	xmlNanoFTPFreeCtxt(ctxt);
	return(NULL);
    }
    sock = xmlNanoFTPGetSocket(ctxt, ctxt->path);
    if (sock < 0) {
	xmlNanoFTPFreeCtxt(ctxt);
	return(NULL);
    }
    return(ctxt);
}

/*
 * Disconnect from the FTP server.
 */

int
xmlNanoFTPClose(void *ctx) {
    xmlNanoFTPCtxtPtr ctxt = (xmlNanoFTPCtxtPtr) ctx;

    if (ctxt == NULL)
	return(-1);

    if (ctxt->dataFd >= 0) {
	close(ctxt->dataFd);
	ctxt->dataFd = -1;
    }
    if (ctxt->controlFd >= 0) {
	sendQuit(ctxt);
	close(ctxt->controlFd);
	ctxt->controlFd = -1;
    }
    xmlNanoFTPFreeCtxt(ctxt);
    return(0);
}

#ifdef STANDALONE
/************************************************************************
 * 									*
 * 			Basic test in Standalone mode			*
 * 									*
 ************************************************************************/
void ftpList(void *userData, const char *filename, const char* attrib,
	     const char *owner, const char *group, unsigned long size, int links,
	     int year, const char *month, int day, int minute) {
    printf("%s %s %s %ld %s\n", attrib, owner, group, size, filename);
}
void ftpData(void *userData, const char *data, int len) {
    if (userData == NULL) return;
    if (len <= 0) {
	fclose(userData);
	return;
    }	
    fwrite(data, len, 1, userData);
}

int main(int argc, char **argv) {
    void *ctxt;
    FILE *output;
    int res;
    const char *tstfile = "tstfile";

    xmlNanoFTPInit();
    if (argc > 1) {
	ctxt = xmlNanoFTPConnectTo(argv[1], 0);
	if (argc > 2)
	    tstfile = argv[2];
    } else
	ctxt = xmlNanoFTPConnectTo("localhost", 0);
    if (ctxt == NULL) {
        fprintf(stderr, "Couldn't connect to localhost\n");
        exit(1);
    }
    res = xmlNanoFTPCwd(ctxt, "/linux");
    if (res < 0) {
        fprintf(stderr, "disconnected\n");
	xmlNanoFTPClose(ctxt);
	exit(1);
    }
    if (res == 0) {
        fprintf(stderr, "/linux : CWD failed\n");
    } else {
        fprintf(stderr, "/linux : CWD successful\n");
    }
    res = xmlNanoFTPCwd(ctxt, "/toto");
    if (res < 0) {
        fprintf(stderr, "disconnected\n");
	xmlNanoFTPClose(ctxt);
	exit(1);
    }
    if (res == 0) {
        fprintf(stderr, "/toto : CWD failed\n");
    } else {
        fprintf(stderr, "/toto : CWD successful\n");
    }
    xmlNanoFTPList(ctxt, ftpList, NULL);
    output = fopen("/tmp/tstdata", "w");
    if (output != NULL) {
	if (xmlNanoFTPGet(ctxt, ftpData, (void *) output, tstfile) < 0)
	    fprintf(stderr, "Failed to get file %s\n", tstfile);
	
    }
    xmlNanoFTPClose(ctxt);
    xmlMemoryDump();
    exit(0);
}
#endif /* STANDALONE */
