/*
 * xmlmemory.h: interface for the memory allocation debug.
 *
 * Daniel.Veillard@w3.org
 */


#ifndef _DEBUG_MEMORY_ALLOC_
#define _DEBUG_MEMORY_ALLOC_

#include <stdio.h>
#include <libxml/xmlversion.h>

/*
 * DEBUG_MEMORY_LOCATION should be activated only done when debugging 
 * libxml.
 */
/* #define DEBUG_MEMORY_FREED */
/* #define DEBUG_MEMORY_LOCATION */

#ifdef DEBUG
#ifndef DEBUG_MEMORY
#define DEBUG_MEMORY
#endif
#endif

#ifdef DEBUG_MEMORY_LOCATION
#define MEM_LIST /* keep a list of all the allocated memory blocks */
#define DEBUG_MEMORY_FREED
#endif

#ifdef DEBUG_MEMORY_FREED
#define MEM_CLEANUP(p,l) memset((p), -1, (l));
#else
#define MEM_CLEANUP(p,l)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The XML memory wrapper support 4 basic overloadable functions
 */
typedef void (*xmlFreeFunc)(void *);
typedef void *(*xmlMallocFunc)(int);
typedef void *(*xmlReallocFunc)(void *, int);
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
#define xmlMalloc(x) xmlMallocLoc((x), __FILE__, __LINE__)
#define xmlRealloc(p, x) xmlReallocLoc((p), (x), __FILE__, __LINE__)
#define xmlMemStrdup(x) xmlMemStrdupLoc((x), __FILE__, __LINE__)

void *	xmlMallocLoc(int size, const char *file, int line);
void *	xmlReallocLoc(void *ptr,int size, const char *file, int line);
char *	xmlMemStrdupLoc(const char *str, const char *file, int line);
#endif /* DEBUG_MEMORY_LOCATION */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* _DEBUG_MEMORY_ALLOC_ */

