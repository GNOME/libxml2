/*
 * memory.c:  libxml memory allocator wrapper.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#define HAVE_FCNTL_H
#include <io.h>
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#include "xmlmemory.h"

#ifndef NO_DEBUG_MEMORY
#ifdef xmlMalloc
#undef xmlMalloc
#endif
#ifdef xmlRealloc
#undef xmlRealloc
#endif
#ifdef xmlMemStrdup
#undef xmlMemStrdup
#endif

extern void xmlMemoryDump(void);

/*
 * Each of the blocks allocated begin with a header containing informations
 */

#define MEMTAG 0x5aa5

#define MALLOC_TYPE 1
#define REALLOC_TYPE 2
#define STRDUP_TYPE 3

typedef struct memnod {
    unsigned int   mh_tag;
    unsigned int   mh_type;
    unsigned long  mh_number;
    size_t         mh_size;
#ifdef MEM_LIST
   struct memnod *mh_next;
   struct memnod *mh_prev;
#endif
   const char    *mh_file;
   unsigned int   mh_line;
}  MEMHDR;


#ifdef SUN4
#define ALIGN_SIZE  16
#else
#define ALIGN_SIZE  sizeof(double)
#endif
#define HDR_SIZE    sizeof(MEMHDR)
#define RESERVE_SIZE (((HDR_SIZE + (ALIGN_SIZE-1)) \
		      / ALIGN_SIZE ) * ALIGN_SIZE)


#define CLIENT_2_HDR(a) ((MEMHDR *) (((char *) (a)) - RESERVE_SIZE))
#define HDR_2_CLIENT(a)    ((void *) (((char *) (a)) + RESERVE_SIZE))


static unsigned long  debugMemSize = 0;
static int block=0;
#ifdef MEM_LIST
static MEMHDR *memlist = NULL;
#endif

void debugmem_tag_error(void *addr);
#ifdef MEM_LIST
void  debugmem_list_add(MEMHDR *);
void debugmem_list_delete(MEMHDR *);
#endif
#define Mem_Tag_Err(a) debugmem_tag_error(a);

#ifndef TEST_POINT
#define TEST_POINT
#endif

/**
 * xmlMallocLoc:
 * @size:  an int specifying the size in byte to allocate.
 * @file:  the file name or NULL
 * @file:  the line number
 *
 * a malloc() equivalent, with logging of the allocation info.
 *
 * Returns a pointer to the allocated area or NULL in case of lack of memory.
 */

void *
xmlMallocLoc(int size, const char * file, int line)
{
    MEMHDR *p;
    
#ifdef DEBUG_MEMORY
    fprintf(stderr, "Malloc(%d)\n",size);
#endif

    TEST_POINT
    
    p = (MEMHDR *) malloc(RESERVE_SIZE+size);

    if (!p) {
     fprintf(stderr, "xmlMalloc : Out of free space\n");
     xmlMemoryDump();
    }   
    p->mh_tag = MEMTAG;
    p->mh_number = ++block;
    p->mh_size = size;
    p->mh_type = MALLOC_TYPE;
    p->mh_file = file;
    p->mh_line = line;
    debugMemSize += size;
#ifdef MEM_LIST
    debugmem_list_add(p);
#endif

#ifdef DEBUG_MEMORY
    fprintf(stderr, "Malloc(%d) Ok\n",size);
#endif
    

    TEST_POINT

    return(HDR_2_CLIENT(p));
}

/**
 * xmlMalloc:
 * @size:  an int specifying the size in byte to allocate.
 *
 * a malloc() equivalent, with logging of the allocation info.
 *
 * Returns a pointer to the allocated area or NULL in case of lack of memory.
 */

void *
xmlMalloc(int size)
{
    return(xmlMallocLoc(size, "none", 0));
}

/**
 * xmlReallocLoc:
 * @ptr:  the initial memory block pointer
 * @size:  an int specifying the size in byte to allocate.
 * @file:  the file name or NULL
 * @file:  the line number
 *
 * a realloc() equivalent, with logging of the allocation info.
 *
 * Returns a pointer to the allocated area or NULL in case of lack of memory.
 */

void *
xmlReallocLoc(void *ptr,int size, const char * file, int line)
{
    MEMHDR *p;
    unsigned long number;

    TEST_POINT

    p = CLIENT_2_HDR(ptr);
    number = p->mh_number;
    if (p->mh_tag != MEMTAG) {
       Mem_Tag_Err(p);
	 goto error;
    }
    p->mh_tag = ~MEMTAG;
    debugMemSize -= p->mh_size;
#ifdef MEM_LIST
    debugmem_list_delete(p);
#endif

    p = (MEMHDR *) realloc(p,RESERVE_SIZE+size);
    if (!p) {
	 goto error;
    }
    p->mh_tag = MEMTAG;
    p->mh_number = number;
    p->mh_type = REALLOC_TYPE;
    p->mh_size = size;
    p->mh_file = file;
    p->mh_line = line;
    debugMemSize += size;
#ifdef MEM_LIST
    debugmem_list_add(p);
#endif

    TEST_POINT

    return(HDR_2_CLIENT(p));
    
error:    
    return(NULL);
}

/**
 * xmlRealloc:
 * @ptr:  the initial memory block pointer
 * @size:  an int specifying the size in byte to allocate.
 *
 * a realloc() equivalent, with logging of the allocation info.
 *
 * Returns a pointer to the allocated area or NULL in case of lack of memory.
 */

void *
xmlRealloc(void *ptr,int size) {
    return(xmlReallocLoc(ptr, size, "none", 0));
}

/**
 * xmlFree:
 * @ptr:  the memory block pointer
 *
 * a free() equivalent, with error checking.
 */
void
xmlFree(void *ptr)
{
    MEMHDR *p;

    TEST_POINT

    p = CLIENT_2_HDR(ptr);
    if (p->mh_tag != MEMTAG) {
       Mem_Tag_Err(p);
       goto error;
    }
    p->mh_tag = ~MEMTAG;
    debugMemSize -= p->mh_size;

#ifdef MEM_LIST
    debugmem_list_delete(p);
#endif
    free(p);

    TEST_POINT

    return;
    
error:    
    fprintf(stderr, "xmlFree(%X) error\n", (unsigned int) ptr);
    return;
}

/**
 * xmlMemStrdupLoc:
 * @ptr:  the initial string pointer
 * @file:  the file name or NULL
 * @file:  the line number
 *
 * a strdup() equivalent, with logging of the allocation info.
 *
 * Returns a pointer to the new string or NULL if allocation error occured.
 */

char *
xmlMemStrdupLoc(const char *str, const char *file, int line)
{
    char *s;
    size_t size = strlen(str) + 1;
    MEMHDR *p;

    TEST_POINT

    p = (MEMHDR *) malloc(RESERVE_SIZE+size);
    if (!p) {
      goto error;
    }
    p->mh_tag = MEMTAG;
    p->mh_number = ++block;
    p->mh_size = size;
    p->mh_type = STRDUP_TYPE;
    p->mh_file = file;
    p->mh_line = line;
    debugMemSize += size;
#ifdef MEM_LIST
    debugmem_list_add(p);
#endif
    s = HDR_2_CLIENT(p);
    
    if (s != NULL)
      strcpy(s,str);
    else
      goto error;
    
    TEST_POINT

    return(s);

error:
    return(NULL);
}

/**
 * xmlMemStrdup:
 * @ptr:  the initial string pointer
 *
 * a strdup() equivalent, with logging of the allocation info.
 *
 * Returns a pointer to the new string or NULL if allocation error occured.
 */

char *
xmlMemStrdup(const char *str) {
    return(xmlMemStrdupLoc(str, "none", 0));
}

/**
 * xmlMemUsed:
 *
 * returns the amount of memory currenly allocated
 *
 * Returns an int representing the amount of memory allocated.
 */

int
xmlMemUsed(void) {
     return(debugMemSize);
}

/**
 * xmlMemDisplay:
 * @fp:  a FILE descriptor used as the output file, if NULL, the result is
 8       written to the file .memorylist
 *
 * show in-extenso the memory blocks allocated
 */

void
xmlMemDisplay(FILE *fp)
{
#ifdef MEM_LIST
    MEMHDR *p;
    int     idx;
#if defined(HAVE_LOCALTIME) && defined(HAVE_STRFTIME)
    time_t currentTime;
    char buf[500];
    struct tm * tstruct;

    currentTime = time(NULL);
    tstruct = localtime(&currentTime);
    strftime(buf, sizeof(buf) - 1, "%c", tstruct);
    fprintf(fp,"      %s\n\n", buf);
#endif

    
    fprintf(fp,"      MEMORY ALLOCATED : %lu\n",debugMemSize);
    fprintf(fp,"BLOCK  NUMBER   SIZE  TYPE\n");
    idx = 0;
    p = memlist;
    while (p) {
	  fprintf(fp,"%-5u  %6lu %6u ",idx++,p->mh_number,p->mh_size);
        switch (p->mh_type) {
           case STRDUP_TYPE:fprintf(fp,"strdup()  in ");break;
           case MALLOC_TYPE:fprintf(fp,"malloc()  in ");break;
          case REALLOC_TYPE:fprintf(fp,"realloc() in ");break;
                    default:fprintf(fp,"   ???    in ");break;
        }
	  if (p->mh_file != NULL) fprintf(fp,"%s(%d)", p->mh_file, p->mh_line);
        if (p->mh_tag != MEMTAG)
	      fprintf(fp,"  INVALID");
        fprintf(fp,"\n");
        p = p->mh_next;
    }
#else
    fprintf(fp,"Memory list not compiled (MEM_LIST not defined !)\n");
#endif
}

#ifdef MEM_LIST

void debugmem_list_add(MEMHDR *p)
{
     p->mh_next = memlist;
     p->mh_prev = NULL;
     if (memlist) memlist->mh_prev = p;
     memlist = p;
#ifdef MEM_LIST_DEBUG
     if (stderr)
     Mem_Display(stderr);
#endif
}

void debugmem_list_delete(MEMHDR *p)
{
     if (p->mh_next)
     p->mh_next->mh_prev = p->mh_prev;
     if (p->mh_prev)
     p->mh_prev->mh_next = p->mh_next;
     else memlist = p->mh_next;
#ifdef MEM_LIST_DEBUG
     if (stderr)
     Mem_Display(stderr);
#endif
}

#endif

/*
 * debugmem_tag_error : internal error function.
 */
 
void debugmem_tag_error(void *p)
{
     fprintf(stderr, "Memory tag error occurs :%p \n\t bye\n", p);
#ifdef MEM_LIST
     if (stderr)
     xmlMemDisplay(stderr);
#endif
}

FILE *xmlMemoryDumpFile = NULL;


/**
 * xmlMemoryDump:
 *
 * Dump in-extenso the memory blocks allocated to the file .memorylist
 */

void
xmlMemoryDump(void)
{
    FILE *dump;

    dump = fopen(".memdump", "w");
    if (dump == NULL) xmlMemoryDumpFile = stdout;
    else xmlMemoryDumpFile = dump;

    xmlMemDisplay(xmlMemoryDumpFile);

    if (dump != NULL) fclose(dump);
}


/****************************************************************
 *								*
 *		Initialization Routines				*
 *								*
 ****************************************************************/

/**
 * xmlInitMemory:
 *
 * Initialize the memory layer.
 *
 * Returns 0 on success
 */


int
xmlInitMemory(void)
{
     int ret;
    
#ifdef DEBUG_MEMORY
     fprintf(stderr, "xmlInitMemory() Ok\n");
#endif     
     ret = 0;
     return(ret);
}

#endif /* ! NO_DEBUG_MEMORY */
