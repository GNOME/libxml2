/*
 * xmlmodule.c :
 *
 * See Copyright for the status of this software.
 *
 * joelwreed@comcast.net
 */

#define IN_LIBXML
#include "libxml.h"

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlmodule.h>
#include <libxml/globals.h>

#ifdef LIBXML_MODULES_ENABLED

struct _xmlModule {
  unsigned char* name;
  void* handle;
};

static void* xmlModulePlatformOpen(const char* name);
static int xmlModulePlatformClose(void* handle);
static void* xmlModulePlatformSymbol(void* handle, const char* name);

/************************************************************************
 *									*
 * 		module memory error handler				*
 *									*
 ************************************************************************/
/**
 * xmlModuleErrMemory:
 * @extra:  extra information
 *
 * Handle an out of memory condition
 */
static void
xmlModuleErrMemory(xmlModulePtr module, const char *extra)
{
    const char *name = NULL;
    if (module != NULL) {
      name = (const char *) module->name;
    }

    __xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_MODULE,
                    XML_ERR_NO_MEMORY, XML_ERR_FATAL, NULL, 0, extra,
                    name, NULL, 0, 0,
                    "Memory allocation failed : %s\n", extra);
}

xmlModulePtr xmlModuleOpen(const char* name)
{
  xmlModulePtr module;

  module = (xmlModulePtr) xmlMalloc(sizeof(xmlModule));
  if (module == NULL) {
    xmlModuleErrMemory(NULL, "creating module");
    return(NULL);
  }

  memset(module, 0, sizeof(xmlModule));

  module->handle = xmlModulePlatformOpen(name);

  if (module->handle == NULL) {
    xmlFree(module);
    __xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_MODULE,
                    XML_MODULE_OPEN, XML_ERR_FATAL, NULL, 0, 0,
                    name, NULL, 0, 0,
                    "failed to open %s\n", name);
    return 0;
  }

  module->name = xmlStrdup((const xmlChar*)name);
  return (module);
}

void* xmlModuleSymbol(xmlModulePtr module, const char* name)
{
  void* symbol;

  if (NULL == module) {
    __xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_MODULE,
                    XML_MODULE_OPEN, XML_ERR_FATAL, NULL, 0, 0,
                    NULL, NULL, 0, 0,
                    "null module pointer\n", 0);
     return 0;
 }

  symbol = xmlModulePlatformSymbol(module->handle, name);

  if (symbol == 0) {
    __xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_MODULE,
                    XML_MODULE_OPEN, XML_ERR_FATAL, NULL, 0, 0,
                    symbol, NULL, 0, 0,
                    "failed to find symbol: %s\n", 0);
    return 0;
  }

  return (symbol);
}

int xmlModuleClose(xmlModulePtr module)
{
  int rc;

  if (NULL == module) {
    __xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_MODULE,
                    XML_MODULE_OPEN, XML_ERR_FATAL, NULL, 0, 0,
                    NULL, NULL, 0, 0,
                    "null module pointer\n", 0);
    return -1;
  }

  rc = xmlModulePlatformClose(module->handle);

  if (rc != 0) {
    __xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_MODULE,
                    XML_MODULE_OPEN, XML_ERR_FATAL, NULL, 0, 0,
                    (const char*)module->name, NULL, 0, 0,
                    "failed to close: %s\n", 0);
    return -2;
  }

  rc = xmlModuleFree(module);
  return (rc);
}

int xmlModuleFree(xmlModulePtr module)
{
  if (NULL == module) {
    __xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_MODULE,
                    XML_MODULE_OPEN, XML_ERR_FATAL, NULL, 0, 0,
                    NULL, NULL, 0, 0,
                    "null module pointer\n", 0);
    return -1;
  }

  xmlFree(module->name);
  xmlFree(module);

  return (0);
}

#ifdef HAVE_DLOPEN

#include <dlfcn.h>

/*
 * xmlModulePlatformOpen:
 * returns a handle on success, and zero on error.
 */ 

static void* xmlModulePlatformOpen(const char* name)
{
  void* handle;
  handle = dlopen(name, RTLD_GLOBAL|RTLD_NOW);
  return (handle);
}

/*
 * xmlModulePlatformClose:
 * returns 0 on success, and non-zero on error.
 */ 

static int xmlModulePlatformClose(void* handle)
{
  int rc;
  rc = dlclose(handle);
  return (rc);
}

/*
 * xmlModulePlatformSymbol:
 * returns loaded symbol on success, and zero on error.
 */ 

static void* xmlModulePlatformSymbol(void* handle, const char* name)
{
  void* sym;
  sym = dlsym(handle, name);
  return (sym);
}

#endif /* HAVE_DLOPEN */

#ifdef HAVE_SHLLOAD /* HAVE_SHLLOAD */

/*
 * xmlModulePlatformOpen:
 * returns a handle on success, and zero on error.
 */ 

void* xmlModulePlatformOpen(const char* name)
{
  void* handle;
  handle = shl_load(name, BIND_IMMEDIATE, 0L);
  return (handle);
}

/*
 * xmlModulePlatformClose:
 * returns 0 on success, and non-zero on error.
 */ 

int xmlModulePlatformClose(void* handle)
{
  int rc;
  rc = shl_unload(handle);
  return (rc);
}

/*
 * xmlModulePlatformSymbol:
 * returns loaded symbol on success, and zero on error.
 */ 

void* xmlModulePlatformSymbol(void* handle, const char* name)
{
  void* sym;
  int rc; 
  
  errno = 0;
  rc = shl_findsym(handle, name, TYPE_PROCEDURE, &sym); 
  if (-1 == rc && 0 == errno) {
    rc = shl_findsym(handle, sym, TYPE_DATA, &sym); 
  }
  return (sym);
}

#endif /* HAVE_SHLLOAD */

#ifdef _WIN32

#include <windows.h>

/*
 * xmlModulePlatformOpen:
 * returns a handle on success, and zero on error.
 */ 

void* xmlModulePlatformOpen(const char* name)
{
  void* handle;
  handle = LoadLibrary(name);
  return (handle);
}

/*
 * xmlModulePlatformClose:
 * returns 0 on success, and non-zero on error.
 */ 

int xmlModulePlatformClose(void* handle)
{
  int rc;
  rc = FreeLibrary(handle);
  return (0 == rc);
}

/*
 * xmlModulePlatformSymbol:
 * returns loaded symbol on success, and zero on error.
 */ 

void* xmlModulePlatformSymbol(void* handle, const char* name)
{
  void* sym;
  sym = GetProcAddress(handle, name);
  return (sym);
}

#endif /* _WIN32 */

#ifdef HAVE_BEOS

#include <kernel/image.h>

/*
 * xmlModulePlatformOpen:
 * beos api info: http://www.beunited.org/bebook/The%20Kernel%20Kit/Images.html
 * returns a handle on success, and zero on error.
 */ 

void* xmlModulePlatformOpen(const char* name)
{
  void* handle;
  handle = (void*)load_add_on(name);
  return (handle);
}

/*
 * xmlModulePlatformClose:
 * beos api info: http://www.beunited.org/bebook/The%20Kernel%20Kit/Images.html
 * returns 0 on success, and non-zero on error.
 */ 

int xmlModulePlatformClose(void* handle)
{
  status_t rc;
  rc = unload_add_on((image_id)handle);

  if (rc == B_OK) return 0;
  else return -1;
}

/*
 * xmlModulePlatformSymbol:
 * beos api info: http://www.beunited.org/bebook/The%20Kernel%20Kit/Images.html
 * returns loaded symbol on success, and zero on error.
 */ 

void* xmlModulePlatformSymbol(void* handle, const char* name)
{
  void* sym;
  status_t rc;

  rc = get_image_symbol((image_id)handle, name, B_SYMBOL_TYPE_ANY, &sym);

  if (rc == B_OK) return sym;
  else return 0;
}

#endif /* HAVE_BEOS */

#ifdef HAVE_OS2

#include <os2.h>

/*
 * xmlModulePlatformOpen:
 * os2 api info: http://www.edm2.com/os2api/Dos/DosLoadModule.html
 * returns a handle on success, and zero on error.
 */ 

void* xmlModulePlatformOpen(const char* name)
{
  char errbuf[255];
  void* handle;
  int rc;

  rc = DosLoadModule(errbuf, sizeof(errbuf), name, &handle);

  if (rc) return 0;
  else return (handle);
}

/*
 * xmlModulePlatformClose:
 * os2 api info: http://www.edm2.com/os2api/Dos/DosFreeModule.html
 * returns 0 on success, and non-zero on error.
 */ 

int xmlModulePlatformClose(void* handle)
{
  int rc;
  rc = DosFreeModule(handle);
  return (rc);
}

/*
 * xmlModulePlatformSymbol:
 * os2 api info: http://www.edm2.com/os2api/Dos/DosQueryProcAddr.html
 * returns loaded symbol on success, and zero on error.
 */ 

void* xmlModulePlatformSymbol(void* handle, const char* name)
{
  void* sym;
  int rc;
  rc = DosQueryProcAddr(handle, 0, name, &sym);

  if (rc) return 0;
  else return (sym);
}

#endif /* HAVE_OS2 */

#endif /* LIBXML_MODULES_ENABLED */

