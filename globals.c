/*
 * globals.c: definition and handling of the set of global variables
 *            of the library
 *
 * See Copyright for the status of this software.
 *
 * Gary Pennington <Gary.Pennington@uk.sun.com>
 * daniel@veillard.com
 */

#define IN_LIBXML
#include "libxml.h"

#include <stdlib.h>
#include <string.h>

#define XML_GLOBALS_NO_REDEFINITION
#include <libxml/globals.h>
#include <libxml/xmlmemory.h>
#include <libxml/threads.h>
#include <libxml/SAX.h>

#include "private/error.h"
#include "private/globals.h"
#include "private/threads.h"
#include "private/tree.h"

/*
 * Helpful Macro
 */
#ifdef LIBXML_THREAD_ENABLED
#define IS_MAIN_THREAD (xmlIsMainThread())
#else
#define IS_MAIN_THREAD 1
#endif

/*
 * Mutex to protect "ForNewThreads" variables
 */
static xmlMutex xmlThrDefMutex;

#define XML_DECLARE_MEMBER(name, type, attrs) \
  type gs_##name;

struct _xmlGlobalState {
#define XML_OP XML_DECLARE_MEMBER
XML_GLOBALS
#undef XML_OP
};

#ifdef LIBXML_THREAD_ENABLED
static void
xmlFreeGlobalState(void *state);
#endif

#ifdef HAVE_POSIX_THREADS

/*
 * Weak symbol hack, see threads.c
 */
#if defined(__GNUC__) && \
    defined(__GLIBC__) && \
    __GLIBC__ * 100 + __GLIBC_MINOR__ < 234

#define XML_PTHREAD_WEAK

static int libxml_is_threaded = -1;

#endif

static pthread_key_t globalkey;

#elif defined HAVE_WIN32_THREADS

#if defined(HAVE_COMPILER_TLS)

static __declspec(thread) xmlGlobalState tlstate;
static __declspec(thread) int tlstate_inited = 0;

#else /* HAVE_COMPILER_TLS */

static DWORD globalkey = TLS_OUT_OF_INDEXES;

#if defined(LIBXML_STATIC) && !defined(LIBXML_STATIC_FOR_DLL)

typedef struct _xmlGlobalStateCleanupHelperParams {
    HANDLE thread;
    void *memory;
} xmlGlobalStateCleanupHelperParams;

static void
xmlGlobalStateCleanupHelper(void *p)
{
    xmlGlobalStateCleanupHelperParams *params =
        (xmlGlobalStateCleanupHelperParams *) p;
    WaitForSingleObject(params->thread, INFINITE);
    CloseHandle(params->thread);
    xmlFreeGlobalState(params->memory);
    free(params);
    _endthread();
}

#else /* LIBXML_STATIC && !LIBXML_STATIC_FOR_DLL */

typedef struct _xmlGlobalStateCleanupHelperParams {
    void *memory;
    struct _xmlGlobalStateCleanupHelperParams *prev;
    struct _xmlGlobalStateCleanupHelperParams *next;
} xmlGlobalStateCleanupHelperParams;

static xmlGlobalStateCleanupHelperParams *cleanup_helpers_head = NULL;
static CRITICAL_SECTION cleanup_helpers_cs;

#endif /* LIBXMLSTATIC && !LIBXML_STATIC_FOR_DLL */

#endif /* HAVE_COMPILER_TLS */

#endif /* HAVE_WIN32_THREADS */

/************************************************************************
 *									*
 *	All the user accessible global variables of the library		*
 *									*
 ************************************************************************/

/*
 * Memory allocation routines
 */

#if defined(DEBUG_MEMORY_LOCATION)
xmlFreeFunc xmlFree = (xmlFreeFunc) xmlMemFree;
xmlMallocFunc xmlMalloc = (xmlMallocFunc) xmlMemMalloc;
xmlMallocFunc xmlMallocAtomic = (xmlMallocFunc) xmlMemMalloc;
xmlReallocFunc xmlRealloc = (xmlReallocFunc) xmlMemRealloc;
xmlStrdupFunc xmlMemStrdup = (xmlStrdupFunc) xmlMemoryStrdup;
#else
/**
 * xmlFree:
 * @mem: an already allocated block of memory
 *
 * The variable holding the libxml free() implementation
 */
xmlFreeFunc xmlFree = free;
/**
 * xmlMalloc:
 * @size:  the size requested in bytes
 *
 * The variable holding the libxml malloc() implementation
 *
 * Returns a pointer to the newly allocated block or NULL in case of error
 */
xmlMallocFunc xmlMalloc = malloc;
/**
 * xmlMallocAtomic:
 * @size:  the size requested in bytes
 *
 * The variable holding the libxml malloc() implementation for atomic
 * data (i.e. blocks not containing pointers), useful when using a
 * garbage collecting allocator.
 *
 * Returns a pointer to the newly allocated block or NULL in case of error
 */
xmlMallocFunc xmlMallocAtomic = malloc;
/**
 * xmlRealloc:
 * @mem: an already allocated block of memory
 * @size:  the new size requested in bytes
 *
 * The variable holding the libxml realloc() implementation
 *
 * Returns a pointer to the newly reallocated block or NULL in case of error
 */
xmlReallocFunc xmlRealloc = realloc;
/**
 * xmlPosixStrdup
 * @cur:  the input char *
 *
 * a strdup implementation with a type signature matching POSIX
 *
 * Returns a new xmlChar * or NULL
 */
static char *
xmlPosixStrdup(const char *cur) {
    return((char*) xmlCharStrdup(cur));
}
/**
 * xmlMemStrdup:
 * @str: a zero terminated string
 *
 * The variable holding the libxml strdup() implementation
 *
 * Returns the copy of the string or NULL in case of error
 */
xmlStrdupFunc xmlMemStrdup = xmlPosixStrdup;
#endif /* DEBUG_MEMORY_LOCATION */

/**
 * xmlParserVersion:
 *
 * Constant string describing the internal version of the library
 */
const char *xmlParserVersion = LIBXML_VERSION_STRING LIBXML_VERSION_EXTRA;

/**
 * xmlBufferAllocScheme:
 *
 * DEPRECATED: Don't use.
 *
 * Global setting, default allocation policy for buffers, default is
 * XML_BUFFER_ALLOC_EXACT
 */
xmlBufferAllocationScheme xmlBufferAllocScheme = XML_BUFFER_ALLOC_EXACT;
static xmlBufferAllocationScheme xmlBufferAllocSchemeThrDef = XML_BUFFER_ALLOC_EXACT;
/**
 * xmlDefaultBufferSize:
 *
 * DEPRECATED: Don't use.
 *
 * Global setting, default buffer size. Default value is BASE_BUFFER_SIZE
 */
int xmlDefaultBufferSize = BASE_BUFFER_SIZE;
static int xmlDefaultBufferSizeThrDef = BASE_BUFFER_SIZE;

/*
 * Parser defaults
 */

/**
 * oldXMLWDcompatibility:
 *
 * Global setting, DEPRECATED.
 */
int oldXMLWDcompatibility = 0; /* DEPRECATED */
/**
 * xmlParserDebugEntities:
 *
 * DEPRECATED: Don't use
 *
 * Global setting, asking the parser to print out debugging information.
 * while handling entities.
 * Disabled by default
 */
int xmlParserDebugEntities = 0;
static int xmlParserDebugEntitiesThrDef = 0;
/**
 * xmlDoValidityCheckingDefaultValue:
 *
 * DEPRECATED: Use the modern options API with XML_PARSE_DTDVALID.
 *
 * Global setting, indicate that the parser should work in validating mode.
 * Disabled by default.
 */
int xmlDoValidityCheckingDefaultValue = 0;
static int xmlDoValidityCheckingDefaultValueThrDef = 0;
/**
 * xmlGetWarningsDefaultValue:
 *
 * DEPRECATED: Don't use
 *
 * Global setting, indicate that the DTD validation should provide warnings.
 * Activated by default.
 */
int xmlGetWarningsDefaultValue = 1;
static int xmlGetWarningsDefaultValueThrDef = 1;
/**
 * xmlLoadExtDtdDefaultValue:
 *
 * DEPRECATED: Use the modern options API with XML_PARSE_DTDLOAD.
 *
 * Global setting, indicate that the parser should load DTD while not
 * validating.
 * Disabled by default.
 */
int xmlLoadExtDtdDefaultValue = 0;
static int xmlLoadExtDtdDefaultValueThrDef = 0;
/**
 * xmlPedanticParserDefaultValue:
 *
 * DEPRECATED: Use the modern options API with XML_PARSE_PEDANTIC.
 *
 * Global setting, indicate that the parser be pedantic
 * Disabled by default.
 */
int xmlPedanticParserDefaultValue = 0;
static int xmlPedanticParserDefaultValueThrDef = 0;
/**
 * xmlLineNumbersDefaultValue:
 *
 * DEPRECATED: The modern options API always enables line numbers.
 *
 * Global setting, indicate that the parser should store the line number
 * in the content field of elements in the DOM tree.
 * Disabled by default since this may not be safe for old classes of
 * application.
 */
int xmlLineNumbersDefaultValue = 0;
static int xmlLineNumbersDefaultValueThrDef = 0;
/**
 * xmlKeepBlanksDefaultValue:
 *
 * DEPRECATED: Use the modern options API with XML_PARSE_NOBLANKS.
 *
 * Global setting, indicate that the parser should keep all blanks
 * nodes found in the content
 * Activated by default, this is actually needed to have the parser
 * conformant to the XML Recommendation, however the option is kept
 * for some applications since this was libxml1 default behaviour.
 */
int xmlKeepBlanksDefaultValue = 1;
static int xmlKeepBlanksDefaultValueThrDef = 1;
/**
 * xmlSubstituteEntitiesDefaultValue:
 *
 * DEPRECATED: Use the modern options API with XML_PARSE_NOENT.
 *
 * Global setting, indicate that the parser should not generate entity
 * references but replace them with the actual content of the entity
 * Disabled by default, this should be activated when using XPath since
 * the XPath data model requires entities replacement and the XPath
 * engine does not handle entities references transparently.
 */
int xmlSubstituteEntitiesDefaultValue = 0;
static int xmlSubstituteEntitiesDefaultValueThrDef = 0;

/**
 * xmlRegisterNodeDefaultValue:
 *
 * DEPRECATED: Don't use
 */
xmlRegisterNodeFunc xmlRegisterNodeDefaultValue = NULL;
static xmlRegisterNodeFunc xmlRegisterNodeDefaultValueThrDef = NULL;

/**
 * xmlDeregisterNodeDefaultValue:
 *
 * DEPRECATED: Don't use
 */
xmlDeregisterNodeFunc xmlDeregisterNodeDefaultValue = NULL;
static xmlDeregisterNodeFunc xmlDeregisterNodeDefaultValueThrDef = NULL;

/**
 * xmlParserInputBufferCreateFilenameValue:
 *
 * DEPRECATED: Don't use
 */
xmlParserInputBufferCreateFilenameFunc xmlParserInputBufferCreateFilenameValue = NULL;
static xmlParserInputBufferCreateFilenameFunc xmlParserInputBufferCreateFilenameValueThrDef = NULL;

/**
 * xmlOutputBufferCreateFilenameValue:
 *
 * DEPRECATED: Don't use
 */
xmlOutputBufferCreateFilenameFunc xmlOutputBufferCreateFilenameValue = NULL;
static xmlOutputBufferCreateFilenameFunc xmlOutputBufferCreateFilenameValueThrDef = NULL;

/**
 * xmlGenericError:
 *
 * Global setting: function used for generic error callbacks
 */
xmlGenericErrorFunc xmlGenericError = xmlGenericErrorDefaultFunc;
static xmlGenericErrorFunc xmlGenericErrorThrDef = xmlGenericErrorDefaultFunc;
/**
 * xmlStructuredError:
 *
 * Global setting: function used for structured error callbacks
 */
xmlStructuredErrorFunc xmlStructuredError = NULL;
static xmlStructuredErrorFunc xmlStructuredErrorThrDef = NULL;
/**
 * xmlGenericErrorContext:
 *
 * Global setting passed to generic error callbacks
 */
void *xmlGenericErrorContext = NULL;
static void *xmlGenericErrorContextThrDef = NULL;
/**
 * xmlStructuredErrorContext:
 *
 * Global setting passed to structured error callbacks
 */
void *xmlStructuredErrorContext = NULL;
static void *xmlStructuredErrorContextThrDef = NULL;
xmlError xmlLastError;

/*
 * output defaults
 */
/**
 * xmlIndentTreeOutput:
 *
 * Global setting, asking the serializer to indent the output tree by default
 * Enabled by default
 */
int xmlIndentTreeOutput = 1;
static int xmlIndentTreeOutputThrDef = 1;

/**
 * xmlTreeIndentString:
 *
 * The string used to do one-level indent. By default is equal to "  " (two spaces)
 */
const char *xmlTreeIndentString = "  ";
static const char *xmlTreeIndentStringThrDef = "  ";

/**
 * xmlSaveNoEmptyTags:
 *
 * Global setting, asking the serializer to not output empty tags
 * as <empty/> but <empty></empty>. those two forms are indistinguishable
 * once parsed.
 * Disabled by default
 */
int xmlSaveNoEmptyTags = 0;
static int xmlSaveNoEmptyTagsThrDef = 0;

#ifdef LIBXML_SAX1_ENABLED
/**
 * xmlDefaultSAXHandler:
 *
 * DEPRECATED: This handler is unused and will be removed from future
 * versions.
 *
 * Default SAX version1 handler for XML, builds the DOM tree
 */
xmlSAXHandlerV1 xmlDefaultSAXHandler = {
    xmlSAX2InternalSubset,
    xmlSAX2IsStandalone,
    xmlSAX2HasInternalSubset,
    xmlSAX2HasExternalSubset,
    xmlSAX2ResolveEntity,
    xmlSAX2GetEntity,
    xmlSAX2EntityDecl,
    xmlSAX2NotationDecl,
    xmlSAX2AttributeDecl,
    xmlSAX2ElementDecl,
    xmlSAX2UnparsedEntityDecl,
    xmlSAX2SetDocumentLocator,
    xmlSAX2StartDocument,
    xmlSAX2EndDocument,
    xmlSAX2StartElement,
    xmlSAX2EndElement,
    xmlSAX2Reference,
    xmlSAX2Characters,
    xmlSAX2Characters,
    xmlSAX2ProcessingInstruction,
    xmlSAX2Comment,
    xmlParserWarning,
    xmlParserError,
    xmlParserError,
    xmlSAX2GetParameterEntity,
    xmlSAX2CDataBlock,
    xmlSAX2ExternalSubset,
    1,
};
#endif /* LIBXML_SAX1_ENABLED */

/**
 * xmlDefaultSAXLocator:
 *
 * DEPRECATED: Don't use
 *
 * The default SAX Locator
 * { getPublicId, getSystemId, getLineNumber, getColumnNumber}
 */
xmlSAXLocator xmlDefaultSAXLocator = {
    xmlSAX2GetPublicId,
    xmlSAX2GetSystemId,
    xmlSAX2GetLineNumber,
    xmlSAX2GetColumnNumber
};

#if defined(LIBXML_HTML_ENABLED) && defined(LIBXML_SAX1_ENABLED)
/**
 * htmlDefaultSAXHandler:
 *
 * DEPRECATED: This handler is unused and will be removed from future
 * versions.
 *
 * Default old SAX v1 handler for HTML, builds the DOM tree
 */
xmlSAXHandlerV1 htmlDefaultSAXHandler = {
    xmlSAX2InternalSubset,
    NULL,
    NULL,
    NULL,
    NULL,
    xmlSAX2GetEntity,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    xmlSAX2SetDocumentLocator,
    xmlSAX2StartDocument,
    xmlSAX2EndDocument,
    xmlSAX2StartElement,
    xmlSAX2EndElement,
    NULL,
    xmlSAX2Characters,
    xmlSAX2IgnorableWhitespace,
    xmlSAX2ProcessingInstruction,
    xmlSAX2Comment,
    xmlParserWarning,
    xmlParserError,
    xmlParserError,
    NULL,
    xmlSAX2CDataBlock,
    NULL,
    1,
};
#endif /* LIBXML_HTML_ENABLED */

/************************************************************************
 *									*
 *			Per thread global state handling		*
 *									*
 ************************************************************************/

/**
 * xmlInitGlobals:
 *
 * DEPRECATED: Alias for xmlInitParser.
 */
void xmlInitGlobals(void) {
    xmlInitParser();
}

/**
 * xmlInitGlobalsInternal:
 *
 * Additional initialisation for multi-threading
 */
void xmlInitGlobalsInternal(void) {
    xmlInitMutex(&xmlThrDefMutex);

#ifdef HAVE_POSIX_THREADS
#ifdef XML_PTHREAD_WEAK
    if (libxml_is_threaded == -1)
        libxml_is_threaded =
            (pthread_getspecific != NULL) &&
            (pthread_setspecific != NULL) &&
            (pthread_key_create != NULL) &&
            (pthread_key_delete != NULL);
    if (libxml_is_threaded == 0)
        return;
#endif /* XML_PTHREAD_WEAK */
    pthread_key_create(&globalkey, xmlFreeGlobalState);
#elif defined(HAVE_WIN32_THREADS)
#if !defined(HAVE_COMPILER_TLS)
#if !defined(LIBXML_STATIC) || defined(LIBXML_STATIC_FOR_DLL)
    InitializeCriticalSection(&cleanup_helpers_cs);
#endif
    globalkey = TlsAlloc();
#endif
#endif
}

/**
 * xmlCleanupGlobals:
 *
 * DEPRECATED: This function is a no-op. Call xmlCleanupParser
 * to free global state but see the warnings there. xmlCleanupParser
 * should be only called once at program exit. In most cases, you don't
 * have call cleanup functions at all.
 */
void xmlCleanupGlobals(void) {
}

/**
 * xmlCleanupGlobalsInternal:
 *
 * Additional cleanup for multi-threading
 */
void xmlCleanupGlobalsInternal(void) {
    xmlResetError(&xmlLastError);

    xmlCleanupMutex(&xmlThrDefMutex);

#ifdef HAVE_POSIX_THREADS
#ifdef XML_PTHREAD_WEAK
    if (libxml_is_threaded == 0)
        return;
#endif /* XML_PTHREAD_WEAK */
    pthread_key_delete(globalkey);
#elif defined(HAVE_WIN32_THREADS)
#if !defined(HAVE_COMPILER_TLS)
    if (globalkey != TLS_OUT_OF_INDEXES) {
#if !defined(LIBXML_STATIC) || defined(LIBXML_STATIC_FOR_DLL)
        xmlGlobalStateCleanupHelperParams *p;

        EnterCriticalSection(&cleanup_helpers_cs);
        p = cleanup_helpers_head;
        while (p != NULL) {
            xmlGlobalStateCleanupHelperParams *temp = p;

            p = p->next;
            xmlFreeGlobalState(temp->memory);
            free(temp);
        }
        cleanup_helpers_head = 0;
        LeaveCriticalSection(&cleanup_helpers_cs);
#endif
        TlsFree(globalkey);
        globalkey = TLS_OUT_OF_INDEXES;
    }
#if !defined(LIBXML_STATIC) || defined(LIBXML_STATIC_FOR_DLL)
    DeleteCriticalSection(&cleanup_helpers_cs);
#endif
#endif
#endif
}

/**
 * xmlInitializeGlobalState:
 * @gs: a pointer to a newly allocated global state
 *
 * DEPRECATED: Internal function, do not use.
 *
 * xmlInitializeGlobalState() initialize a global state with all the
 * default values of the library.
 */
void
xmlInitializeGlobalState(xmlGlobalStatePtr gs)
{
    xmlMutexLock(&xmlThrDefMutex);

#if defined(LIBXML_HTML_ENABLED) && defined(LIBXML_LEGACY_ENABLED) && defined(LIBXML_SAX1_ENABLED)
    inithtmlDefaultSAXHandler(&gs->gs_htmlDefaultSAXHandler);
#endif

    gs->gs_oldXMLWDcompatibility = 0;
    gs->gs_xmlBufferAllocScheme = xmlBufferAllocSchemeThrDef;
    gs->gs_xmlDefaultBufferSize = xmlDefaultBufferSizeThrDef;
#if defined(LIBXML_SAX1_ENABLED) && defined(LIBXML_LEGACY_ENABLED)
    initxmlDefaultSAXHandler(&gs->gs_xmlDefaultSAXHandler, 1);
#endif /* LIBXML_SAX1_ENABLED */
    gs->gs_xmlDefaultSAXLocator.getPublicId = xmlSAX2GetPublicId;
    gs->gs_xmlDefaultSAXLocator.getSystemId = xmlSAX2GetSystemId;
    gs->gs_xmlDefaultSAXLocator.getLineNumber = xmlSAX2GetLineNumber;
    gs->gs_xmlDefaultSAXLocator.getColumnNumber = xmlSAX2GetColumnNumber;
    gs->gs_xmlDoValidityCheckingDefaultValue =
         xmlDoValidityCheckingDefaultValueThrDef;
#if defined(DEBUG_MEMORY_LOCATION)
    gs->gs_xmlFree = (xmlFreeFunc) xmlMemFree;
    gs->gs_xmlMalloc = (xmlMallocFunc) xmlMemMalloc;
    gs->gs_xmlMallocAtomic = (xmlMallocFunc) xmlMemMalloc;
    gs->gs_xmlRealloc = (xmlReallocFunc) xmlMemRealloc;
    gs->gs_xmlMemStrdup = (xmlStrdupFunc) xmlMemoryStrdup;
#endif
    gs->gs_xmlGetWarningsDefaultValue = xmlGetWarningsDefaultValueThrDef;
    gs->gs_xmlIndentTreeOutput = xmlIndentTreeOutputThrDef;
    gs->gs_xmlTreeIndentString = xmlTreeIndentStringThrDef;
    gs->gs_xmlKeepBlanksDefaultValue = xmlKeepBlanksDefaultValueThrDef;
    gs->gs_xmlLineNumbersDefaultValue = xmlLineNumbersDefaultValueThrDef;
    gs->gs_xmlLoadExtDtdDefaultValue = xmlLoadExtDtdDefaultValueThrDef;
    gs->gs_xmlParserDebugEntities = xmlParserDebugEntitiesThrDef;
    gs->gs_xmlParserVersion = LIBXML_VERSION_STRING;
    gs->gs_xmlPedanticParserDefaultValue = xmlPedanticParserDefaultValueThrDef;
    gs->gs_xmlSaveNoEmptyTags = xmlSaveNoEmptyTagsThrDef;
    gs->gs_xmlSubstituteEntitiesDefaultValue =
        xmlSubstituteEntitiesDefaultValueThrDef;

    gs->gs_xmlGenericError = xmlGenericErrorThrDef;
    gs->gs_xmlStructuredError = xmlStructuredErrorThrDef;
    gs->gs_xmlGenericErrorContext = xmlGenericErrorContextThrDef;
    gs->gs_xmlStructuredErrorContext = xmlStructuredErrorContextThrDef;
    gs->gs_xmlRegisterNodeDefaultValue = xmlRegisterNodeDefaultValueThrDef;
    gs->gs_xmlDeregisterNodeDefaultValue = xmlDeregisterNodeDefaultValueThrDef;

    gs->gs_xmlParserInputBufferCreateFilenameValue =
        xmlParserInputBufferCreateFilenameValueThrDef;
    gs->gs_xmlOutputBufferCreateFilenameValue =
        xmlOutputBufferCreateFilenameValueThrDef;
    memset(&gs->gs_xmlLastError, 0, sizeof(xmlError));

    xmlMutexUnlock(&xmlThrDefMutex);
}

#ifdef LIBXML_THREAD_ENABLED
/**
 * xmlFreeGlobalState:
 * @state:  a thread global state
 *
 * xmlFreeGlobalState() is called when a thread terminates with a non-NULL
 * global state. It is is used here to reclaim memory resources.
 */
static void
xmlFreeGlobalState(void *state)
{
    xmlGlobalState *gs = (xmlGlobalState *) state;

    /* free any memory allocated in the thread's xmlLastError */
    xmlResetError(&(gs->gs_xmlLastError));
    free(state);
}

/**
 * xmlNewGlobalState:
 *
 * xmlNewGlobalState() allocates a global state. This structure is used to
 * hold all data for use by a thread when supporting backwards compatibility
 * of libxml2 to pre-thread-safe behaviour.
 *
 * Returns the newly allocated xmlGlobalStatePtr or NULL in case of error
 */
static xmlGlobalStatePtr
xmlNewGlobalState(void)
{
    xmlGlobalState *gs;

    gs = malloc(sizeof(xmlGlobalState));
    if (gs == NULL) {
	xmlGenericError(xmlGenericErrorContext,
			"xmlGetGlobalState: out of memory\n");
        return (NULL);
    }

    memset(gs, 0, sizeof(xmlGlobalState));
    xmlInitializeGlobalState(gs);
    return (gs);
}
#endif /* LIBXML_THREAD_ENABLED */

/**
 * xmlCheckThreadLocalStorage:
 *
 * Check whether thread-local storage could be allocated.
 *
 * In multithreaded environments, this function should be called once
 * in each thread before calling other library functions to make sure
 * that thread-local storage was allocated properly.
 *
 * Returns 0 on success or -1 if a memory allocation failed. A failed
 * allocation signals a typically fatal and irrecoverable out-of-memory
 * situation. Don't call any library functions in this case.
 *
 * This function never fails for the "main" thread which is the first
 * thread calling xmlInitParser.
 *
 * Available since v2.12.0.
 */
int
xmlCheckThreadLocalStorage(void) {
    if (IS_MAIN_THREAD)
        return(0);
    return((xmlGetGlobalState() == NULL) ? -1 : 0);
}

/**
 * xmlGetGlobalState:
 *
 * DEPRECATED: Internal function, do not use.
 *
 * xmlGetGlobalState() is called to retrieve the global state for a thread.
 *
 * Returns the thread global state or NULL in case of error
 */
xmlGlobalStatePtr
xmlGetGlobalState(void)
{
#ifdef HAVE_POSIX_THREADS
    xmlGlobalState *globalval;

    if ((globalval = (xmlGlobalState *)
         pthread_getspecific(globalkey)) == NULL) {
        xmlGlobalState *tsd = xmlNewGlobalState();
	if (tsd == NULL)
	    return(NULL);

        pthread_setspecific(globalkey, tsd);
        return (tsd);
    }
    return (globalval);
#elif defined HAVE_WIN32_THREADS
#if defined(HAVE_COMPILER_TLS)
    if (!tlstate_inited) {
        tlstate_inited = 1;
        xmlInitializeGlobalState(&tlstate);
    }
    return &tlstate;
#else /* HAVE_COMPILER_TLS */
    xmlGlobalState *globalval;
    xmlGlobalStateCleanupHelperParams *p;
#if defined(LIBXML_STATIC) && !defined(LIBXML_STATIC_FOR_DLL)
    globalval = (xmlGlobalState *) TlsGetValue(globalkey);
#else
    p = (xmlGlobalStateCleanupHelperParams *) TlsGetValue(globalkey);
    globalval = (xmlGlobalState *) (p ? p->memory : NULL);
#endif
    if (globalval == NULL) {
        xmlGlobalState *tsd = xmlNewGlobalState();

        if (tsd == NULL)
	    return(NULL);
        p = (xmlGlobalStateCleanupHelperParams *)
            malloc(sizeof(xmlGlobalStateCleanupHelperParams));
	if (p == NULL) {
            xmlGenericError(xmlGenericErrorContext,
                            "xmlGetGlobalState: out of memory\n");
            xmlFreeGlobalState(tsd);
	    return(NULL);
	}
        p->memory = tsd;
#if defined(LIBXML_STATIC) && !defined(LIBXML_STATIC_FOR_DLL)
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                        GetCurrentProcess(), &p->thread, 0, TRUE,
                        DUPLICATE_SAME_ACCESS);
        TlsSetValue(globalkey, tsd);
        _beginthread(xmlGlobalStateCleanupHelper, 0, p);
#else
        EnterCriticalSection(&cleanup_helpers_cs);
        if (cleanup_helpers_head != NULL) {
            cleanup_helpers_head->prev = p;
        }
        p->next = cleanup_helpers_head;
        p->prev = NULL;
        cleanup_helpers_head = p;
        TlsSetValue(globalkey, p);
        LeaveCriticalSection(&cleanup_helpers_cs);
#endif

        return (tsd);
    }
    return (globalval);
#endif /* HAVE_COMPILER_TLS */
#else
    return (NULL);
#endif
}

/**
 * DllMain:
 * @hinstDLL: handle to DLL instance
 * @fdwReason: Reason code for entry
 * @lpvReserved: generic pointer (depends upon reason code)
 *
 * Entry point for Windows library. It is being used to free thread-specific
 * storage.
 *
 * Returns TRUE always
 */
#ifdef HAVE_POSIX_THREADS
#elif defined(HAVE_WIN32_THREADS) && !defined(HAVE_COMPILER_TLS) && (!defined(LIBXML_STATIC) || defined(LIBXML_STATIC_FOR_DLL))
#if defined(LIBXML_STATIC_FOR_DLL)
int
xmlDllMain(ATTRIBUTE_UNUSED void *hinstDLL, unsigned long fdwReason,
           ATTRIBUTE_UNUSED void *lpvReserved)
#else
/* declare to avoid "no previous prototype for 'DllMain'" warning */
/* Note that we do NOT want to include this function declaration in
   a public header because it's meant to be called by Windows itself,
   not a program that uses this library.  This also has to be exported. */

XMLPUBFUN BOOL WINAPI
DllMain (HINSTANCE hinstDLL,
         DWORD     fdwReason,
         LPVOID    lpvReserved);

BOOL WINAPI
DllMain(ATTRIBUTE_UNUSED HINSTANCE hinstDLL, DWORD fdwReason,
        ATTRIBUTE_UNUSED LPVOID lpvReserved)
#endif
{
    switch (fdwReason) {
        case DLL_THREAD_DETACH:
            if (globalkey != TLS_OUT_OF_INDEXES) {
                xmlGlobalState *globalval = NULL;
                xmlGlobalStateCleanupHelperParams *p =
                    (xmlGlobalStateCleanupHelperParams *)
                    TlsGetValue(globalkey);
                globalval = (xmlGlobalState *) (p ? p->memory : NULL);
                if (globalval) {
                    xmlFreeGlobalState(globalval);
                    TlsSetValue(globalkey, NULL);
                }
                if (p) {
                    EnterCriticalSection(&cleanup_helpers_cs);
                    if (p == cleanup_helpers_head)
                        cleanup_helpers_head = p->next;
                    else
                        p->prev->next = p->next;
                    if (p->next != NULL)
                        p->next->prev = p->prev;
                    LeaveCriticalSection(&cleanup_helpers_cs);
                    free(p);
                }
            }
            break;
    }
    return TRUE;
}
#endif

void
xmlThrDefSetGenericErrorFunc(void *ctx, xmlGenericErrorFunc handler) {
    xmlMutexLock(&xmlThrDefMutex);
    xmlGenericErrorContextThrDef = ctx;
    if (handler != NULL)
	xmlGenericErrorThrDef = handler;
    else
	xmlGenericErrorThrDef = xmlGenericErrorDefaultFunc;
    xmlMutexUnlock(&xmlThrDefMutex);
}

void
xmlThrDefSetStructuredErrorFunc(void *ctx, xmlStructuredErrorFunc handler) {
    xmlMutexLock(&xmlThrDefMutex);
    xmlStructuredErrorContextThrDef = ctx;
    xmlStructuredErrorThrDef = handler;
    xmlMutexUnlock(&xmlThrDefMutex);
}

xmlBufferAllocationScheme xmlThrDefBufferAllocScheme(xmlBufferAllocationScheme v) {
    xmlBufferAllocationScheme ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlBufferAllocSchemeThrDef;
    xmlBufferAllocSchemeThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefDefaultBufferSize(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlDefaultBufferSizeThrDef;
    xmlDefaultBufferSizeThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefDoValidityCheckingDefaultValue(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlDoValidityCheckingDefaultValueThrDef;
    xmlDoValidityCheckingDefaultValueThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefGetWarningsDefaultValue(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlGetWarningsDefaultValueThrDef;
    xmlGetWarningsDefaultValueThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefIndentTreeOutput(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlIndentTreeOutputThrDef;
    xmlIndentTreeOutputThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

const char * xmlThrDefTreeIndentString(const char * v) {
    const char * ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlTreeIndentStringThrDef;
    xmlTreeIndentStringThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefKeepBlanksDefaultValue(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlKeepBlanksDefaultValueThrDef;
    xmlKeepBlanksDefaultValueThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefLineNumbersDefaultValue(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlLineNumbersDefaultValueThrDef;
    xmlLineNumbersDefaultValueThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefLoadExtDtdDefaultValue(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlLoadExtDtdDefaultValueThrDef;
    xmlLoadExtDtdDefaultValueThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefParserDebugEntities(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlParserDebugEntitiesThrDef;
    xmlParserDebugEntitiesThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefPedanticParserDefaultValue(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlPedanticParserDefaultValueThrDef;
    xmlPedanticParserDefaultValueThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefSaveNoEmptyTags(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlSaveNoEmptyTagsThrDef;
    xmlSaveNoEmptyTagsThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

int xmlThrDefSubstituteEntitiesDefaultValue(int v) {
    int ret;
    xmlMutexLock(&xmlThrDefMutex);
    ret = xmlSubstituteEntitiesDefaultValueThrDef;
    xmlSubstituteEntitiesDefaultValueThrDef = v;
    xmlMutexUnlock(&xmlThrDefMutex);
    return ret;
}

/**
 * xmlRegisterNodeDefault:
 * @func: function pointer to the new RegisterNodeFunc
 *
 * Registers a callback for node creation
 *
 * Returns the old value of the registration function
 */
xmlRegisterNodeFunc
xmlRegisterNodeDefault(xmlRegisterNodeFunc func)
{
    xmlRegisterNodeFunc old = xmlRegisterNodeDefaultValue;

    __xmlRegisterCallbacks = 1;
    xmlRegisterNodeDefaultValue = func;
    return(old);
}

xmlRegisterNodeFunc
xmlThrDefRegisterNodeDefault(xmlRegisterNodeFunc func)
{
    xmlRegisterNodeFunc old;

    xmlMutexLock(&xmlThrDefMutex);
    old = xmlRegisterNodeDefaultValueThrDef;

    __xmlRegisterCallbacks = 1;
    xmlRegisterNodeDefaultValueThrDef = func;
    xmlMutexUnlock(&xmlThrDefMutex);

    return(old);
}

/**
 * xmlDeregisterNodeDefault:
 * @func: function pointer to the new DeregisterNodeFunc
 *
 * Registers a callback for node destruction
 *
 * Returns the previous value of the deregistration function
 */
xmlDeregisterNodeFunc
xmlDeregisterNodeDefault(xmlDeregisterNodeFunc func)
{
    xmlDeregisterNodeFunc old = xmlDeregisterNodeDefaultValue;

    __xmlRegisterCallbacks = 1;
    xmlDeregisterNodeDefaultValue = func;
    return(old);
}

xmlDeregisterNodeFunc
xmlThrDefDeregisterNodeDefault(xmlDeregisterNodeFunc func)
{
    xmlDeregisterNodeFunc old;

    xmlMutexLock(&xmlThrDefMutex);
    old = xmlDeregisterNodeDefaultValueThrDef;

    __xmlRegisterCallbacks = 1;
    xmlDeregisterNodeDefaultValueThrDef = func;
    xmlMutexUnlock(&xmlThrDefMutex);

    return(old);
}

xmlParserInputBufferCreateFilenameFunc
xmlThrDefParserInputBufferCreateFilenameDefault(xmlParserInputBufferCreateFilenameFunc func)
{
    xmlParserInputBufferCreateFilenameFunc old;

    xmlMutexLock(&xmlThrDefMutex);
    old = xmlParserInputBufferCreateFilenameValueThrDef;
    if (old == NULL) {
		old = __xmlParserInputBufferCreateFilename;
	}

    xmlParserInputBufferCreateFilenameValueThrDef = func;
    xmlMutexUnlock(&xmlThrDefMutex);

    return(old);
}

xmlOutputBufferCreateFilenameFunc
xmlThrDefOutputBufferCreateFilenameDefault(xmlOutputBufferCreateFilenameFunc func)
{
    xmlOutputBufferCreateFilenameFunc old;

    xmlMutexLock(&xmlThrDefMutex);
    old = xmlOutputBufferCreateFilenameValueThrDef;
#ifdef LIBXML_OUTPUT_ENABLED
    if (old == NULL) {
		old = __xmlOutputBufferCreateFilename;
	}
#endif
    xmlOutputBufferCreateFilenameValueThrDef = func;
    xmlMutexUnlock(&xmlThrDefMutex);

    return(old);
}

/* Define thread-local storage accessors with macro magic */

#ifdef LIBXML_THREAD_ENABLED
  #define XML_DEFINE_GLOBAL_WRAPPER(name, type, attrs) \
    type *__##name(void) { \
      if (IS_MAIN_THREAD) \
        return (&name); \
      else \
        return (&xmlGetGlobalState()->gs_##name); \
    }

  #define XML_OP XML_DEFINE_GLOBAL_WRAPPER
  XML_GLOBALS
  #undef XML_OP
#endif

