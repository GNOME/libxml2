#ifndef __LIBXML_WIN32_CONFIG__
#define __LIBXML_WIN32_CONFIG__

#define HAVE_CTYPE_H
#define HAVE_STDLIB_H
#define HAVE_MALLOC_H
#define HAVE_TIME_H
#define HAVE_FCNTL_H

#include <io.h>

#define SOCKLEN_T int
#ifdef NEED_SOCKETS
#include <winsock2.h>

#define EWOULDBLOCK             WSAEWOULDBLOCK
#define EINPROGRESS             WSAEINPROGRESS
#define EALREADY                WSAEALREADY
#define ENOTSOCK                WSAENOTSOCK
#define EDESTADDRREQ            WSAEDESTADDRREQ
#define EMSGSIZE                WSAEMSGSIZE
#define EPROTOTYPE              WSAEPROTOTYPE
#define ENOPROTOOPT             WSAENOPROTOOPT
#define EPROTONOSUPPORT         WSAEPROTONOSUPPORT
#define ESOCKTNOSUPPORT         WSAESOCKTNOSUPPORT
#define EOPNOTSUPP              WSAEOPNOTSUPP
#define EPFNOSUPPORT            WSAEPFNOSUPPORT
#define EAFNOSUPPORT            WSAEAFNOSUPPORT
#define EADDRINUSE              WSAEADDRINUSE
#define EADDRNOTAVAIL           WSAEADDRNOTAVAIL
#define ENETDOWN                WSAENETDOWN
#define ENETUNREACH             WSAENETUNREACH
#define ENETRESET               WSAENETRESET
#define ECONNABORTED            WSAECONNABORTED
#define ECONNRESET              WSAECONNRESET
#define ENOBUFS                 WSAENOBUFS
#define EISCONN                 WSAEISCONN
#define ENOTCONN                WSAENOTCONN
#define ESHUTDOWN               WSAESHUTDOWN
#define ETOOMANYREFS            WSAETOOMANYREFS
#define ETIMEDOUT               WSAETIMEDOUT
#define ECONNREFUSED            WSAECONNREFUSED
#define ELOOP                   WSAELOOP
#define ENAMETOOLONG            WSAENAMETOOLONG
#define EHOSTDOWN               WSAEHOSTDOWN
#define EHOSTUNREACH            WSAEHOSTUNREACH
#define ENOTEMPTY               WSAENOTEMPTY
#define EPROCLIM                WSAEPROCLIM
#define EUSERS                  WSAEUSERS
#define EDQUOT                  WSAEDQUOT
#define ESTALE                  WSAESTALE
#define EREMOTE                 WSAEREMOTE
#endif /* INCLUDE_WINSOCK */

#define HAVE_ISINF
#define HAVE_ISNAN

#include <math.h>
#ifdef _MSC_VER
/* MS C-runtime has functions which can be used in order to determine if
   a given floating-point variable contains NaN, (+-)INF. These are 
   preferred, because floating-point technology is considered propriatary
   by MS and we can assume that their functions know more about their 
   oddities than we do. */
#include <float.h>
/* Bjorn Reese figured a quite nice construct for isinf() using the _fpclass
   function. */
#ifndef isinf
#define isinf(d) ((_fpclass(d) == _FPCLASS_PINF) ? 1 \
	: ((_fpclass(d) == _FPCLASS_NINF) ? -1 : 0))
#endif
/* _isnan(x) returns nonzero if (x == NaN) and zero otherwise. */
#ifndef isnan
#define isnan(d) (_isnan(d))
#endif
#else /* _MSC_VER */
static int isinf (double d) {
    int expon = 0;
    double val = frexp (d, &expon);
    if (expon == 1025) {
        if (val == 0.5) {
            return 1;
        } else if (val == -0.5) {
            return -1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}
static int isnan (double d) {
    int expon = 0;
    double val = frexp (d, &expon);
    if (expon == 1025) {
        if (val == 0.5) {
            return 0;
        } else if (val == -0.5) {
            return 0;
        } else {
            return 1;
        }
    } else {
        return 0;
    }
}
#endif /* _MSC_VER */

#include <direct.h>

#define HAVE_SYS_STAT_H
#define HAVE__STAT
#define HAVE_STAT

#include <libxml/xmlwin32version.h>

#ifdef _MSC_VER
/* We don't use trio when compiling under MSVC. This is not because trio
   is bad, but because MSVC has no easy way to conditionally include a .c
   file in the project. In order to enable trio usage, we would have to compile
   all trio functionality into the executable, even if we don't use it.
   Since MS C-runtime has all required functions, trio is not necessary. */
#ifdef WITH_TRIO
#undef WITH_TRIO
#endif /* WITH_TRIO */
#ifndef WITHOUT_TRIO
#define WITHOUT_TRIO
#endif /* WITHOUT_TRIO */
/* Microsoft's C runtime names all non-ANSI functions with a leading
   underscore. Since functionality is still the same, they can be used. */
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#endif /* _MSC_VER */

#ifndef LIBXML_DLL_IMPORT
#if defined(_MSC_VER) && !defined(IN_LIBXML) && !defined(LIBXML_STATIC)
#define LIBXML_DLL_IMPORT __declspec(dllimport)
#else
#define LIBXML_DLL_IMPORT
#endif
#endif

#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED
#endif

#endif /* __LIBXML_WIN32_CONFIG__ */

