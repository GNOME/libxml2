/*
 * xmlmemory.h: interface for the memory allocation debug.
 *
 * daniel@veillard.com
 */


#ifndef _DEBUG_MEMORY_ALLOC_
#define _DEBUG_MEMORY_ALLOC_

#include <stdio.h>
#if defined(WIN32) && defined(_MSC_VER)
#include <libxml/xmlwin32version.h>
#else
#include <libxml/xmlversion.h>
#endif

/**
 * DEBUG_MEMORY:
 *
 * should be activated only done when debugging libxml. It replaces the
 * allocator with a collect and debug shell to the libc allocator.
 * DEBUG_MEMORY should be activated only when debugging 
 * libxml i.e. if libxml has been configured with --with-debug-mem too
 */
/* #define DEBUG_MEMORY_FREED */
/* #define DEBUG_MEMORY_LOCATION */

#ifdef DEBUG
#ifndef DEBUG_MEMORY
#define DEBUG_MEMORY
#endif
#endif

/**
 * DEBUG_MEMORY_LOCATION:
 *
 * DEBUG_MEMORY_LOCATION should be activated only when debugging 
 * libxml i.e. if libxml has been configured with --with-debug-mem too
 */
#ifdef DEBUG_MEMORY_LOCATION

/**
 * MEM_LIST:
 *
 * keep track of all allocated blocks for error reporting 
 */
#define MEM_LIST /* keep a list of all the allocated memory blocks */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The XML memory wrapper support 4 basic overloadable functions
 */
typedef void (*xmlFreeFunc)(void *);
typedef void *(*xmlMallocFunc)(size_t);
typedef void *(*xmlReallocFunc)(void *, size_t);
typedef char *(*xmlStrdupFunc)(const char *);

/*
 * The 4 interfaces used for all memory handling within libxml
 */
LIBXML_DLL_IMPORT extern xmlFreeFunc xmlFree;
LIBXML_DLL_IMPORT extern xmlMallocFunc xmlMalloc;
LIBXML_DLL_IMPORT extern xmlReallocFunc xmlRealloc;
LIBXML_DLL_IMPORT extern xmlStrdupFunc xmlMemStrdup;

/*
 * The way to overload the existing functions
 */
int     xmlMemSetup	(xmlFreeFunc freeFunc,
			 xmlMallocFunc mallocFunc,
			 xmlReallocFunc reallocFunc,
			 xmlStrdupFunc strdupFunc);
int     xmlMemGet	(xmlFreeFunc *freeFunc,
			 xmlMallocFunc *mallocFunc,
			 xmlReallocFunc *reallocFunc,
			 xmlStrdupFunc *strdupFunc);

/*
 * Initialization of the memory layer
 */
int	xmlInitMemory	(void);

/*
 * Those are specific to the XML debug memory wrapper
 */
int	xmlMemUsed	(void);
void	xmlMemDisplay	(FILE *fp);
void	xmlMemShow	(FILE *fp, int nr);
void	xmlMemoryDump	(void);
int	xmlInitMemory	(void);

#ifdef DEBUG_MEMORY_LOCATION
/**
 * xmlMalloc:
 * @size:  number of bytes to allocate
 *
 * Wrapper for the malloc() function used in the XML library
 *
 * Returns the pointer to the allocated area or NULL in case of error
 */
#define xmlMalloc(size) xmlMallocLoc((size), __FILE__, __LINE__)
/**
 * xmlRealloc:
 * @ptr:  pointer to the existing allocated area
 * @size:  number of bytes to allocate
 *
 * Wrapper for the realloc() function used in the XML library
 *
 * Returns the pointer to the allocated area or NULL in case of error
 */
#define xmlRealloc(ptr, size) xmlReallocLoc((ptr), (size), __FILE__, __LINE__)
/**
 * xmlMemStrdup:
 * @str:  pointer to the existing string
 *
 * Wrapper for the strdup() function, xmlStrdup() is usually preferred
 *
 * Returns the pointer to the allocated area or NULL in case of error
 */
#define xmlMemStrdup(str) xmlMemStrdupLoc((str), __FILE__, __LINE__)

void *	xmlMallocLoc(size_t size, const char *file, int line);
void *	xmlReallocLoc(void *ptr,size_t size, const char *file, int line);
char *	xmlMemStrdupLoc(const char *str, const char *file, int line);
#endif /* DEBUG_MEMORY_LOCATION */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* _DEBUG_MEMORY_ALLOC_ */

