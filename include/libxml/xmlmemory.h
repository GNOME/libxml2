/*
 * xmlmemory.h: interface for the memory allocation debug.
 *
 * Daniel.Veillard@w3.org
 */


#ifndef _DEBUG_MEMORY_ALLOC_
#define _DEBUG_MEMORY_ALLOC_

#define NO_DEBUG_MEMORY

#ifdef NO_DEBUG_MEMORY
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#define xmlFree(x) free((x))
#define xmlMalloc(x) malloc(x)
#define xmlRealloc(p, x) realloc((p), (x))
#define xmlMemStrdup(x) strdup((x))
#define xmlInitMemory()
#define xmlMemUsed()
#define xmlInitMemory()
#define xmlMemoryDump()
#define xmlMemDisplay(x)
#define xmlMemShow(x, d)

#else /* ! NO_DEBUG_MEMORY */
#include <stdio.h>

/* #define DEBUG_MEMORY */ /* */

#define DEBUG_MEMORY_LOCATION

#ifdef DEBUG
#ifndef DEBUG_MEMORY
#define DEBUG_MEMORY
#endif
#endif

#define MEM_LIST /* keep a list of all the allocated memory blocks */

#ifdef __cplusplus
extern "C" {
#endif
int	xmlInitMemory	(void);
void *	xmlMalloc	(int size);
void *	xmlRealloc	(void *ptr,
			 int size);
void	xmlFree		(void *ptr);
char *	xmlMemStrdup	(const char *str);
int	xmlMemUsed	(void);
void	xmlMemDisplay	(FILE *fp);
void	xmlMemShow	(FILE *fp, int nr);
void	xmlMemoryDump	(void);
int	xmlInitMemory	(void);

#ifdef DEBUG_MEMORY_LOCATION
#define xmlMalloc(x) xmlMallocLoc((x), __FILE__, __LINE__)
#define xmlRealloc(p, x) xmlReallocLoc((p), (x), __FILE__, __LINE__)
#define xmlMemStrdup(x) xmlMemStrdupLoc((x), __FILE__, __LINE__)

extern void *	xmlMallocLoc(int size, const char *file, int line);
extern void *	xmlReallocLoc(void *ptr,int size, const char *file, int line);
extern char *	xmlMemStrdupLoc(const char *str, const char *file, int line);
#ifdef __cplusplus
}
#endif
#endif /* DEBUG_MEMORY_LOCATION */
#endif /* ! NO_DEBUG_MEMORY */

#endif  /* _DEBUG_MEMORY_ALLOC_ */

