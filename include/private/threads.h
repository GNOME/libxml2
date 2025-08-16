#ifndef XML_THREADS_H_PRIVATE__
#define XML_THREADS_H_PRIVATE__

#include <libxml/threads.h>

#ifdef LIBXML_THREAD_ENABLED
  #ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #ifdef _WIN32_WINNT
      #undef _WIN32_WINNT
    #endif
    #define _WIN32_WINNT 0x0600
    #include <windows.h>
    #define HAVE_WIN32_THREADS
  #else
    #include <pthread.h>
    #define HAVE_POSIX_THREADS
  #endif
#endif

/*
 * xmlMutex are a simple mutual exception locks
 */
struct _xmlMutex {
#ifdef HAVE_POSIX_THREADS
    pthread_mutex_t lock;
#elif defined HAVE_WIN32_THREADS
    CRITICAL_SECTION cs;
#else
    int empty;
#endif
};

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

#if defined(LIBXML_THREAD_ENABLED) && \
    __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)

/** Atomic reference count */
typedef _Atomic size_t xmlRefCount;

/**
 * Initialize refcount.
 *
 * @param r  refcount
 */
static XML_INLINE void
xmlRefCountInit(xmlRefCount *r) {
    *r = 1;
}

/**
 * Increase refcount.
 *
 * @param r  refcount
 */
static XML_INLINE void
xmlRefCountInc(xmlRefCount *r) {
    *r += 1;
}

/**
 * Decrease refcount.
 *
 * @param r  refcount
 * @returns 0 if refcount reached zero, 1 otherwise
 */
static XML_INLINE int
xmlRefCountDec(xmlRefCount *r) {
    return --*r > 0;
}

#elif defined(HAVE_POSIX_THREADS)

typedef struct {
    pthread_mutex_t mutex;
    size_t count;
} xmlRefCount;

static XML_INLINE void
xmlRefCountInit(xmlRefCount *r) {
    pthread_mutex_init(&r->mutex, NULL);
    r->count = 1;
}

static XML_INLINE void
xmlRefCountInc(xmlRefCount *r) {
    pthread_mutex_lock(&r->mutex);
    r->count += 1;
    pthread_mutex_unlock(&r->mutex);
}

static XML_INLINE int
xmlRefCountDec(xmlRefCount *r) {
    size_t val;

    pthread_mutex_lock(&r->mutex);
    val = --r->count;
    pthread_mutex_unlock(&r->mutex);

    if (val > 0)
        return 1;

    pthread_mutex_destroy(&r->mutex);
    return 0;
}

#elif defined(HAVE_WIN32_THREADS)

#ifdef _WIN64

typedef __int64 xmlRefCount;

static XML_INLINE void
xmlRefCountInit(xmlRefCount *r) {
    *r = 1;
}

static XML_INLINE void
xmlRefCountInc(xmlRefCount *r) {
    InterlockedIncrement64(r);
}

static XML_INLINE int
xmlRefCountDec(xmlRefCount *r) {
    return InterlockedDecrement64(r) > 0;
}

#else /* 32-bit */

typedef long xmlRefCount;

static XML_INLINE void
xmlRefCountInit(xmlRefCount *r) {
    *r = 1;
}

static XML_INLINE void
xmlRefCountInc(xmlRefCount *r) {
    InterlockedIncrement(r);
}

static XML_INLINE int
xmlRefCountDec(xmlRefCount *r) {
    return InterlockedDecrement(r) > 0;
}

#endif

#else /* no threads */

typedef size_t xmlRefCount;

static XML_INLINE void
xmlRefCountInit(xmlRefCount *r) {
    *r = 1;
}

static XML_INLINE void
xmlRefCountInc(xmlRefCount *r) {
    *r += 1;
}

static XML_INLINE int
xmlRefCountDec(xmlRefCount *r) {
    return --*r > 0;
}

#endif

XML_HIDDEN void
xmlInitMutex(xmlMutex *mutex);
XML_HIDDEN void
xmlCleanupMutex(xmlMutex *mutex);

XML_HIDDEN void
xmlInitRMutex(xmlRMutex *mutex);
XML_HIDDEN void
xmlCleanupRMutex(xmlRMutex *mutex);

#ifdef LIBXML_SCHEMAS_ENABLED
XML_HIDDEN void
xmlInitSchemasTypesInternal(void);
XML_HIDDEN void
xmlCleanupSchemasTypesInternal(void);
#endif

#ifdef LIBXML_RELAXNG_ENABLED
XML_HIDDEN void
xmlInitRelaxNGInternal(void);
XML_HIDDEN void
xmlCleanupRelaxNGInternal(void);
#endif


#endif /* XML_THREADS_H_PRIVATE__ */
