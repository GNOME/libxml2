/**
 * threads.c: set of generic threading related routines
 *
 * See Copyright for the status of this software.
 *
 * Gary Pennington <Gary.Pennington@uk.sun.com>
 * daniel@veillard.com
 */

#define IN_LIBXML
#include "libxml.h"

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include <libxml/threads.h>
#include <libxml/parser.h>
#ifdef LIBXML_CATALOG_ENABLED
#include <libxml/catalog.h>
#endif
#ifdef LIBXML_SCHEMAS_ENABLED
#include <libxml/xmlschemastypes.h>
#include <libxml/relaxng.h>
#endif

#if defined(SOLARIS)
#include <note.h>
#endif

#include "private/cata.h"
#include "private/dict.h"
#include "private/enc.h"
#include "private/error.h"
#include "private/globals.h"
#include "private/io.h"
#include "private/memory.h"
#include "private/threads.h"
#include "private/xpath.h"

/*
 * TODO: this module still uses malloc/free and not xmlMalloc/xmlFree
 *       to avoid some craziness since xmlMalloc/xmlFree may actually
 *       be hosted on allocated blocks needing them for the allocation ...
 */

/*
 * xmlRMutex are reentrant mutual exception locks
 */
struct _xmlRMutex {
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_t lock;
    unsigned int held;
    unsigned int waiters;
    pthread_t tid;
    pthread_cond_t cv;
#elif defined HAVE_WIN32_THREADS
    CRITICAL_SECTION cs;
#else
    int empty;
#endif
};

static xmlRMutexPtr xmlLibraryLock = NULL;

/**
 * xmlInitMutex:
 * @mutex:  the mutex
 *
 * Initialize a mutex.
 */
void
xmlInitMutex(xmlMutexPtr mutex)
{
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_init(&mutex->lock, NULL);
#elif defined HAVE_WIN32_THREADS
    InitializeCriticalSection(&mutex->cs);
#else
    (void) mutex;
#endif
}

/**
 * xmlNewMutex:
 *
 * xmlNewMutex() is used to allocate a libxml2 token struct for use in
 * synchronizing access to data.
 *
 * Returns a new simple mutex pointer or NULL in case of error
 */
xmlMutexPtr
xmlNewMutex(void)
{
    xmlMutexPtr tok;

    tok = malloc(sizeof(xmlMutex));
    if (tok == NULL)
        return (NULL);
    xmlInitMutex(tok);
    return (tok);
}

/**
 * xmlCleanupMutex:
 * @mutex:  the simple mutex
 *
 * Reclaim resources associated with a mutex.
 */
void
xmlCleanupMutex(xmlMutexPtr mutex)
{
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_destroy(&mutex->lock);
#elif defined HAVE_WIN32_THREADS
    DeleteCriticalSection(&mutex->cs);
#else
    (void) mutex;
#endif
}

/**
 * xmlFreeMutex:
 * @tok:  the simple mutex
 *
 * Free a mutex.
 */
void
xmlFreeMutex(xmlMutexPtr tok)
{
    if (tok == NULL)
        return;

    xmlCleanupMutex(tok);
    free(tok);
}

/**
 * xmlMutexLock:
 * @tok:  the simple mutex
 *
 * xmlMutexLock() is used to lock a libxml2 token.
 */
void
xmlMutexLock(xmlMutexPtr tok)
{
    if (tok == NULL)
        return;
#ifdef HAVE_POSIX_THREADS
    /*
     * This assumes that __libc_single_threaded won't change while the
     * lock is held.
     */
    pthread_mutex_lock(&tok->lock);
#elif defined HAVE_WIN32_THREADS
    EnterCriticalSection(&tok->cs);
#endif

}

/**
 * xmlMutexUnlock:
 * @tok:  the simple mutex
 *
 * xmlMutexUnlock() is used to unlock a libxml2 token.
 */
void
xmlMutexUnlock(xmlMutexPtr tok)
{
    if (tok == NULL)
        return;
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_unlock(&tok->lock);
#elif defined HAVE_WIN32_THREADS
    LeaveCriticalSection(&tok->cs);
#endif
}

/**
 * xmlNewRMutex:
 *
 * xmlRNewMutex() is used to allocate a reentrant mutex for use in
 * synchronizing access to data. token_r is a re-entrant lock and thus useful
 * for synchronizing access to data structures that may be manipulated in a
 * recursive fashion.
 *
 * Returns the new reentrant mutex pointer or NULL in case of error
 */
xmlRMutexPtr
xmlNewRMutex(void)
{
    xmlRMutexPtr tok;

    tok = malloc(sizeof(xmlRMutex));
    if (tok == NULL)
        return (NULL);
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_init(&tok->lock, NULL);
    tok->held = 0;
    tok->waiters = 0;
    pthread_cond_init(&tok->cv, NULL);
#elif defined HAVE_WIN32_THREADS
    InitializeCriticalSection(&tok->cs);
#endif
    return (tok);
}

/**
 * xmlFreeRMutex:
 * @tok:  the reentrant mutex
 *
 * xmlRFreeMutex() is used to reclaim resources associated with a
 * reentrant mutex.
 */
void
xmlFreeRMutex(xmlRMutexPtr tok ATTRIBUTE_UNUSED)
{
    if (tok == NULL)
        return;
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_destroy(&tok->lock);
    pthread_cond_destroy(&tok->cv);
#elif defined HAVE_WIN32_THREADS
    DeleteCriticalSection(&tok->cs);
#endif
    free(tok);
}

/**
 * xmlRMutexLock:
 * @tok:  the reentrant mutex
 *
 * xmlRMutexLock() is used to lock a libxml2 token_r.
 */
void
xmlRMutexLock(xmlRMutexPtr tok)
{
    if (tok == NULL)
        return;
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_lock(&tok->lock);
    if (tok->held) {
        if (pthread_equal(tok->tid, pthread_self())) {
            tok->held++;
            pthread_mutex_unlock(&tok->lock);
            return;
        } else {
            tok->waiters++;
            while (tok->held)
                pthread_cond_wait(&tok->cv, &tok->lock);
            tok->waiters--;
        }
    }
    tok->tid = pthread_self();
    tok->held = 1;
    pthread_mutex_unlock(&tok->lock);
#elif defined HAVE_WIN32_THREADS
    EnterCriticalSection(&tok->cs);
#endif
}

/**
 * xmlRMutexUnlock:
 * @tok:  the reentrant mutex
 *
 * xmlRMutexUnlock() is used to unlock a libxml2 token_r.
 */
void
xmlRMutexUnlock(xmlRMutexPtr tok ATTRIBUTE_UNUSED)
{
    if (tok == NULL)
        return;
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_lock(&tok->lock);
    tok->held--;
    if (tok->held == 0) {
        if (tok->waiters)
            pthread_cond_signal(&tok->cv);
        memset(&tok->tid, 0, sizeof(tok->tid));
    }
    pthread_mutex_unlock(&tok->lock);
#elif defined HAVE_WIN32_THREADS
    LeaveCriticalSection(&tok->cs);
#endif
}

/************************************************************************
 *									*
 *			Library wide thread interfaces			*
 *									*
 ************************************************************************/

/**
 * xmlGetThreadId:
 *
 * DEPRECATED: Internal function, do not use.
 *
 * xmlGetThreadId() find the current thread ID number
 * Note that this is likely to be broken on some platforms using pthreads
 * as the specification doesn't mandate pthread_t to be an integer type
 *
 * Returns the current thread ID number
 */
int
xmlGetThreadId(void)
{
#ifdef HAVE_POSIX_THREADS
    pthread_t id;
    int ret;

    id = pthread_self();
    /* horrible but preserves compat, see warning above */
    memcpy(&ret, &id, sizeof(ret));
    return (ret);
#elif defined HAVE_WIN32_THREADS
    return GetCurrentThreadId();
#else
    return ((int) 0);
#endif
}

/**
 * xmlLockLibrary:
 *
 * xmlLockLibrary() is used to take out a re-entrant lock on the libxml2
 * library.
 */
void
xmlLockLibrary(void)
{
    xmlRMutexLock(xmlLibraryLock);
}

/**
 * xmlUnlockLibrary:
 *
 * xmlUnlockLibrary() is used to release a re-entrant lock on the libxml2
 * library.
 */
void
xmlUnlockLibrary(void)
{
    xmlRMutexUnlock(xmlLibraryLock);
}

/**
 * xmlInitThreads:
 *
 * DEPRECATED: Alias for xmlInitParser.
 */
void
xmlInitThreads(void)
{
    xmlInitParser();
}

/**
 * xmlCleanupThreads:
 *
 * DEPRECATED: This function is a no-op. Call xmlCleanupParser
 * to free global state but see the warnings there. xmlCleanupParser
 * should be only called once at program exit. In most cases, you don't
 * have call cleanup functions at all.
 */
void
xmlCleanupThreads(void)
{
}

/************************************************************************
 *									*
 *			Library wide initialization			*
 *									*
 ************************************************************************/

static int xmlParserInitialized = 0;

#ifdef HAVE_POSIX_THREADS
static pthread_once_t onceControl = PTHREAD_ONCE_INIT;
#elif defined HAVE_WIN32_THREADS
static INIT_ONCE onceControl = INIT_ONCE_STATIC_INIT;
#else
static int onceControl = 0;
#endif

static void
xmlInitParserInternal(void) {
#if defined(_WIN32) && \
    !defined(LIBXML_THREAD_ALLOC_ENABLED) && \
    (!defined(LIBXML_STATIC) || defined(LIBXML_STATIC_FOR_DLL))
    if (xmlFree == free)
        atexit(xmlCleanupParser);
#endif

    /*
     * Note that the initialization code must not make memory allocations.
     */
    xmlInitRandom(); /* Required by xmlInitGlobalsInternal */
    xmlInitMemoryInternal();
    xmlInitGlobalsInternal();
    xmlInitDictInternal();
    xmlInitEncodingInternal();
#if defined(LIBXML_XPATH_ENABLED)
    xmlInitXPathInternal();
#endif
    xmlInitIOCallbacks();
#ifdef LIBXML_CATALOG_ENABLED
    xmlInitCatalogInternal();
#endif

    xmlParserInitialized = 1;
}

#if defined(HAVE_WIN32_THREADS)
static BOOL
xmlInitParserWinWrapper(INIT_ONCE *initOnce ATTRIBUTE_UNUSED,
                        void *parameter ATTRIBUTE_UNUSED,
                        void **context ATTRIBUTE_UNUSED) {
    xmlInitParserInternal();
    return(TRUE);
}
#endif

/**
 * xmlInitParser:
 *
 * Initialization function for the XML parser.
 *
 * Call once from the main thread before using the library in
 * multithreaded programs.
 */
void
xmlInitParser(void) {
#ifdef HAVE_POSIX_THREADS
    pthread_once(&onceControl, xmlInitParserInternal);
#elif defined(HAVE_WIN32_THREADS)
    InitOnceExecuteOnce(&onceControl, xmlInitParserWinWrapper, NULL, NULL);
#else
    if (onceControl == 0) {
        xmlInitParserInternal();
        onceControl = 1;
    }
#endif
}

/**
 * xmlCleanupParser:
 *
 * This function is named somewhat misleadingly. It does not clean up
 * parser state but global memory allocated by the library itself. This
 * function is mainly useful to avoid false positives from memory leak
 * checkers and SHOULD ONLY BE CALLED RIGHT BEFORE THE WHOLE PROCESS
 * EXITS.
 *
 * WARNING: If a process is multithreaded or uses other shared or
 * dynamic libraries, calling this function may cause crashes if
 * another thread or library is still using libxml2. It can be very
 * hard to guess if libxml2 is in use by a process. In case of doubt
 * abstain from calling this function.
 */
void
xmlCleanupParser(void) {
    if (!xmlParserInitialized)
        return;

    /* These functions can call xmlFree. */
    xmlCleanupCharEncodingHandlers();
#ifdef LIBXML_CATALOG_ENABLED
    xmlCatalogCleanup();
    xmlCleanupCatalogInternal();
#endif
#ifdef LIBXML_SCHEMAS_ENABLED
    xmlSchemaCleanupTypes();
    xmlRelaxNGCleanupTypes();
#endif

    /* These functions should never call xmlFree. */
    xmlCleanupDictInternal();
    xmlCleanupRandom();
    xmlCleanupGlobalsInternal();

    /*
     * Must come last. xmlCleanupGlobalsInternal can call xmlFree which
     * uses xmlMemMutex in debug mode.
     */
    xmlCleanupMemoryInternal();

    xmlParserInitialized = 0;

    /*
     * This is a bit sketchy but should make reinitialization work.
     */
#ifdef HAVE_POSIX_THREADS
    {
        pthread_once_t tmp = PTHREAD_ONCE_INIT;
        memcpy(&onceControl, &tmp, sizeof(tmp));
    }
#elif defined(HAVE_WIN32_THREADS)
    {
        INIT_ONCE tmp = INIT_ONCE_STATIC_INIT;
        memcpy(&onceControl, &tmp, sizeof(tmp));
    }
#else
    onceControl = 0;
#endif
}

#if defined(HAVE_FUNC_ATTRIBUTE_DESTRUCTOR) && \
    !defined(LIBXML_THREAD_ALLOC_ENABLED) && \
    !defined(LIBXML_STATIC) && \
    !defined(_WIN32)
static void
ATTRIBUTE_DESTRUCTOR
xmlDestructor(void) {
    /*
     * Calling custom deallocation functions in a destructor can cause
     * problems, for example with Nokogiri.
     */
    if (xmlFree == free)
        xmlCleanupParser();
}
#endif
