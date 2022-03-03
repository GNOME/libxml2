#ifndef __LIBXML_WIN32_CONFIG__
#define __LIBXML_WIN32_CONFIG__

#define SEND_ARG2_CAST
#define GETHOSTBYNAME_ARG_CAST

#define HAVE_SYS_STAT_H
#define HAVE_STAT
#define HAVE_FCNTL_H
#include <io.h>
#include <direct.h>

#include <libxml/xmlversion.h>

#ifndef ICONV_CONST
#define ICONV_CONST const
#endif

/*
 * Windows platforms may define except 
 */
#undef except

#if defined(_MSC_VER)
#define mkdir(p,m) _mkdir(p)
#if _MSC_VER < 1900
#define snprintf _snprintf
#endif
#if _MSC_VER < 1500
#define vsnprintf(b,c,f,a) _vsnprintf(b,c,f,a)
#endif
#elif defined(__MINGW32__)
#define mkdir(p,m) _mkdir(p)
#endif

/* Threading API to use should be specified here for compatibility reasons.
   This is however best specified on the compiler's command-line. */
#if defined(LIBXML_THREAD_ENABLED)
#if !defined(HAVE_PTHREAD_H) && !defined(HAVE_WIN32_THREADS) && !defined(_WIN32_WCE)
#define HAVE_WIN32_THREADS
#endif
#endif

/* Some third-party libraries far from our control assume the following
   is defined, which it is not if we don't include windows.h. */
#if !defined(FALSE)
#define FALSE 0
#endif
#if !defined(TRUE)
#define TRUE (!(FALSE))
#endif

#endif /* __LIBXML_WIN32_CONFIG__ */

