/*
 * libxml.c: this modules implements the main part of the glue of the
 *           libxml2 library and the Python interpreter. It provides the
 *           entry points where an automatically generated stub is either
 *           unpractical or would not match cleanly the Python model.
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */
#include <Python.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlerror.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlmemory.h>
#include "libxml_wrap.h"
#include "libxml2-py.h"

/* #define DEBUG */
/* #define DEBUG_XPATH */
/* #define DEBUG_ERROR */
/* #define DEBUG_MEMORY */

/************************************************************************
 *									*
 *		Memory debug interface					*
 *									*
 ************************************************************************/

extern void xmlMemFree(void *ptr);
extern void *xmlMemMalloc(size_t size);
extern void *xmlMemRealloc(void *ptr,size_t size);
extern char *xmlMemoryStrdup(const char *str);

static int libxmlMemoryDebugActivated = 0;
static long libxmlMemoryAllocatedBase = 0;

static int libxmlMemoryDebug = 0;
static xmlFreeFunc freeFunc = NULL;
static xmlMallocFunc mallocFunc = NULL;
static xmlReallocFunc reallocFunc = NULL;
static xmlStrdupFunc strdupFunc = NULL;

PyObject *
libxml_xmlDebugMemory(PyObject *self, PyObject *args) {
    int activate;
    PyObject *py_retval;
    long ret;

    if (!PyArg_ParseTuple(args, "i:xmlDebugMemory", &activate))
        return(NULL);

#ifdef DEBUG_MEMORY
    printf("libxml_xmlDebugMemory(%d) called\n", activate);
#endif

    if (activate != 0) {
	if (libxmlMemoryDebug == 0) {
	    /*
	     * First initialize the library and grab the old memory handlers
	     * and switch the library to memory debugging
	     */
	    xmlMemGet((xmlFreeFunc *) &freeFunc,
		      (xmlMallocFunc *)&mallocFunc,
		      (xmlReallocFunc *)&reallocFunc,
		      (xmlStrdupFunc *) &strdupFunc);
	    if ((freeFunc == xmlMemFree) && (mallocFunc == xmlMemMalloc) &&
		(reallocFunc == xmlMemRealloc) &&
		(strdupFunc == xmlMemoryStrdup)) {
		libxmlMemoryAllocatedBase = xmlMemUsed();
	    } else {
		ret = (long) xmlMemSetup(xmlMemFree, xmlMemMalloc,
			                 xmlMemRealloc, xmlMemoryStrdup);
		if (ret < 0)
		    goto error;
		libxmlMemoryAllocatedBase = xmlMemUsed();
	    }
	    xmlInitParser();
	    ret = 0;
	} else if (libxmlMemoryDebugActivated == 0) {
	    libxmlMemoryAllocatedBase = xmlMemUsed();
	    ret = 0;
	} else {
	    ret = xmlMemUsed() - libxmlMemoryAllocatedBase;
	}
	libxmlMemoryDebug = 1;
	libxmlMemoryDebugActivated = 1;
    } else {
	if (libxmlMemoryDebugActivated == 1)
	    ret = xmlMemUsed() - libxmlMemoryAllocatedBase;
	else
	    ret = 0;
	libxmlMemoryDebugActivated = 0;
    }
error:
    py_retval = libxml_longWrap(ret);
    return(py_retval);
}

PyObject *
libxml_xmlDumpMemory(PyObject *self, PyObject *args) {

    if (libxmlMemoryDebug != 0)
	xmlMemoryDump();
    Py_INCREF(Py_None);
    return(Py_None);
}

/************************************************************************
 *									*
 *		Handling SAX/xmllib/sgmlop callback interfaces		*
 *									*
 ************************************************************************/

typedef struct pySAXhandler {
    PyObject *startDocument;
    /* TODO !!! */
} pySAXhandler, *pySAXhandlerPtr;

/************************************************************************
 *									*
 *		Handling of specific parser context			*
 *									*
 ************************************************************************/

PyObject *
libxml_xmlCreatePushParser(PyObject *self, PyObject *args) {
    xmlChar *chunk;
    int size;
    xmlChar *URI;
    PyObject *pyobj_SAX;
    xmlSAXHandlerPtr SAX = NULL;
    pySAXhandlerPtr SAXdata = NULL; 
    xmlParserCtxtPtr ret;
    PyObject *pyret;

    if (!PyArg_ParseTuple(args, "Oziz:xmlCreatePushParser", &pyobj_SAX,
		          &chunk, &size, &URI))
        return(NULL);

#ifdef DEBUG_ERROR
    printf("libxml_xmlCreatePushParser(%p, %s, %d, %s) called\n",
	   pyobj_SAX, chunk, size, URI);
#endif
    if (pyobj_SAX != Py_None) {
	printf("xmlCreatePushParser: event interface not supported yet !\n");
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = xmlCreatePushParserCtxt(SAX, SAXdata, chunk, size, URI);
    pyret = libxml_xmlParserCtxtPtrWrap(ret);
    return(pyret);
}

PyObject *
libxml_htmlCreatePushParser(PyObject *self, PyObject *args) {
    xmlChar *chunk;
    int size;
    xmlChar *URI;
    PyObject *pyobj_SAX;
    xmlSAXHandlerPtr SAX = NULL;
    pySAXhandlerPtr SAXdata = NULL; 
    xmlParserCtxtPtr ret;
    PyObject *pyret;

    if (!PyArg_ParseTuple(args, "Oziz:htmlCreatePushParser", &pyobj_SAX,
		          &chunk, &size, &URI))
        return(NULL);

#ifdef DEBUG_ERROR
    printf("libxml_htmlCreatePushParser(%p, %s, %d, %s) called\n",
	   pyobj_SAX, chunk, size, URI);
#endif
    if (pyobj_SAX != Py_None) {
	printf("htmlCreatePushParser: event interface not supported yet !\n");
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = htmlCreatePushParserCtxt(SAX, SAXdata, chunk, size, URI,
	                           XML_CHAR_ENCODING_NONE);
    pyret = libxml_xmlParserCtxtPtrWrap(ret);
    return(pyret);
}

/************************************************************************
 *									*
 *			Error message callback				*
 *									*
 ************************************************************************/

static PyObject *libxml_xmlPythonErrorFuncHandler = NULL;
static PyObject *libxml_xmlPythonErrorFuncCtxt = NULL;

static void
libxml_xmlErrorFuncHandler(void *ctx, const char *msg, ...) {
    int       size;
    int       chars;
    char     *larger;
    va_list   ap;
    char     *str;
    PyObject *list;
    PyObject *message;
    PyObject *result;

#ifdef DEBUG_ERROR
    printf("libxml_xmlErrorFuncHandler(%p, %s, ...) called\n", ctx, msg);
#endif


    if (libxml_xmlPythonErrorFuncHandler == NULL) {
	va_start(ap, msg);
	vfprintf(stdout, msg, ap);
	va_end(ap);
    } else {
	str = (char *) xmlMalloc(150);
	if (str == NULL) 
	    return;

	size = 150;

	while (1) {
	    va_start(ap, msg);
	    chars = vsnprintf(str, size, msg, ap);
	    va_end(ap);
	    if ((chars > -1) && (chars < size))
		break;
	    if (chars > -1)
		size += chars + 1;
	    else
		size += 100;
	    if ((larger = (char *) xmlRealloc(str, size)) == NULL) {
		xmlFree(str);
		return;
	    }
	    str = larger;
	}

	list = PyTuple_New(2);
	PyTuple_SetItem(list, 0, libxml_xmlPythonErrorFuncCtxt);
	Py_XINCREF(libxml_xmlPythonErrorFuncCtxt);
	message = libxml_charPtrWrap(str);
	PyTuple_SetItem(list, 1, message);
	result = PyEval_CallObject(libxml_xmlPythonErrorFuncHandler, list);
	Py_XDECREF(list);
	Py_XDECREF(result);
    }
}

static void
libxml_xmlErrorInitialize(void) {
#ifdef DEBUG_ERROR
    printf("libxml_xmlErrorInitialize() called\n");
#endif
    xmlSetGenericErrorFunc(NULL, libxml_xmlErrorFuncHandler);
}

PyObject *
libxml_xmlRegisterErrorHandler(PyObject *self, PyObject *args) {
    PyObject *py_retval;
    PyObject *pyobj_f;
    PyObject *pyobj_ctx;

    if (!PyArg_ParseTuple(args, "OO:xmlRegisterErrorHandler", &pyobj_f,
		          &pyobj_ctx))
        return(NULL);

#ifdef DEBUG_ERROR
    printf("libxml_registerXPathFunction(%p, %p) called\n", pyobj_ctx, pyobj_f);
#endif

    if (libxml_xmlPythonErrorFuncHandler != NULL) {
	Py_XDECREF(libxml_xmlPythonErrorFuncHandler);
    }
    if (libxml_xmlPythonErrorFuncCtxt != NULL) {
	Py_XDECREF(libxml_xmlPythonErrorFuncCtxt);
    }

    Py_XINCREF(pyobj_ctx);
    Py_XINCREF(pyobj_f);

    /* TODO: check f is a function ! */
    libxml_xmlPythonErrorFuncHandler = pyobj_f;
    libxml_xmlPythonErrorFuncCtxt = pyobj_ctx;

    py_retval = libxml_intWrap(1);
    return(py_retval);
}
/************************************************************************
 *									*
 *			XPath extensions				*
 *									*
 ************************************************************************/

static int libxml_xpathCallbacksInitialized = 0;

typedef struct libxml_xpathCallback {
    xmlXPathContextPtr ctx;
    xmlChar *name;
    xmlChar *ns_uri;
    PyObject *function;
} libxml_xpathCallback, *libxml_xpathCallbackPtr;
static libxml_xpathCallback libxml_xpathCallbacks[10];
static int libxml_xpathCallbacksNb = 0;
static int libxml_xpathCallbacksMax = 10;

/* TODO: this is not reentrant !!! MUST FIX with a per context hash */
static PyObject *current_function = NULL;

static void
libxml_xmlXPathFuncCallback(xmlXPathParserContextPtr ctxt, int nargs) {
    PyObject *list, *cur, *result;
    xmlXPathObjectPtr obj;
    int i;

#ifdef DEBUG_XPATH
    printf("libxml_xmlXPathFuncCallback called\n");
#endif

    list = PyTuple_New(nargs);
    for (i = 0;i < nargs;i++) {
	obj = valuePop(ctxt);
	cur = libxml_xmlXPathObjectPtrWrap(obj);
	PyTuple_SetItem(list, i, cur);
    }
    result = PyEval_CallObject(current_function, list);
    Py_DECREF(list);

    obj = libxml_xmlXPathObjectPtrConvert(result);
    valuePush(ctxt, obj);
}

static xmlXPathFunction
libxml_xmlXPathFuncLookupFunc(void *ctxt, const xmlChar *name,
	                      const xmlChar *ns_uri) {
    int i;
#ifdef DEBUG_XPATH
    printf("libxml_xmlXPathFuncLookupFunc(%p, %s, %s) called\n",
	   ctxt, name, ns_uri);
#endif
    for (i = 0;i < libxml_xpathCallbacksNb;i++) {
	if ((ctxt == libxml_xpathCallbacks[i].ctx) &&
	    (xmlStrEqual(name, libxml_xpathCallbacks[i].name)) &&
	    (xmlStrEqual(ns_uri, libxml_xpathCallbacks[i].ns_uri))) {
	    current_function = libxml_xpathCallbacks[i].function;
	    return(libxml_xmlXPathFuncCallback);
	}
    }
    current_function = NULL;
    return(NULL);
}

static void
libxml_xpathCallbacksInitialize(void) {
    int i;

    if (libxml_xpathCallbacksInitialized != 0)
	return;

#ifdef DEBUG_XPATH
    printf("libxml_xpathCallbacksInitialized called\n");
#endif

    for (i = 0;i < 10;i++) {
	libxml_xpathCallbacks[i].ctx = NULL;
	libxml_xpathCallbacks[i].name = NULL;
	libxml_xpathCallbacks[i].ns_uri = NULL;
	libxml_xpathCallbacks[i].function = NULL;
    }
    current_function = NULL;
    libxml_xpathCallbacksInitialized = 1;
}

PyObject *
libxml_xmlRegisterXPathFunction(PyObject *self, PyObject *args) {
    PyObject *py_retval;
    int c_retval = 0;
    xmlChar *name;
    xmlChar *ns_uri;
    xmlXPathContextPtr ctx;
    PyObject *pyobj_ctx;
    PyObject *pyobj_f;
    int i;

    if (!PyArg_ParseTuple(args, "OszO:registerXPathFunction", &pyobj_ctx,
		          &name, &ns_uri, &pyobj_f))
        return(NULL);

    ctx = (xmlXPathContextPtr) PyxmlXPathContext_Get(pyobj_ctx);
    if (libxml_xpathCallbacksInitialized == 0)
	libxml_xpathCallbacksInitialize();
    xmlXPathRegisterFuncLookup(ctx, libxml_xmlXPathFuncLookupFunc, ctx);

    if ((pyobj_ctx == NULL) || (name == NULL) || (pyobj_f == NULL)) {
	py_retval = libxml_intWrap(-1);
	return(py_retval);
    }

#ifdef DEBUG_XPATH
    printf("libxml_registerXPathFunction(%p, %s, %s) called\n",
	   ctx, name, ns_uri);
#endif
    for (i = 0;i < libxml_xpathCallbacksNb;i++) {
	if ((ctx == libxml_xpathCallbacks[i].ctx) &&
	    (xmlStrEqual(name, libxml_xpathCallbacks[i].name)) &&
	    (xmlStrEqual(ns_uri, libxml_xpathCallbacks[i].ns_uri))) {
	    Py_XINCREF(pyobj_f);
	    Py_XDECREF(libxml_xpathCallbacks[i].function);
	    libxml_xpathCallbacks[i].function = pyobj_f;
	    c_retval = 1;
	    goto done;
	}
    }
    if (libxml_xpathCallbacksNb >= libxml_xpathCallbacksMax) {
	printf("libxml_registerXPathFunction() table full\n");
    } else {
	i = libxml_xpathCallbacksNb++;
	Py_XINCREF(pyobj_f);
        libxml_xpathCallbacks[i].ctx = ctx;
        libxml_xpathCallbacks[i].name = xmlStrdup(name);
        libxml_xpathCallbacks[i].ns_uri = xmlStrdup(ns_uri);
	libxml_xpathCallbacks[i].function = pyobj_f;
	c_retval = 1;
    }
done:
    py_retval = libxml_intWrap((int) c_retval);
    return(py_retval);
}

/************************************************************************
 *									*
 *			Global properties access			*
 *									*
 ************************************************************************/
static PyObject *
libxml_name(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    const xmlChar *res;

    if (!PyArg_ParseTuple(args, "O:name", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_name: cur = %p type %d\n", cur, cur->type);
#endif

    switch(cur->type) {
	case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
#endif
	case XML_HTML_DOCUMENT_NODE: {
	    xmlDocPtr doc = (xmlDocPtr) cur;
	    res = doc->URL;
	    break;
	}
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    res = attr->name;
	    break;
	}
	case XML_NAMESPACE_DECL: {
	    xmlNsPtr ns = (xmlNsPtr) cur;
	    res = ns->prefix;
	    break;
	}
	default:
	    res = cur->name;
	    break;
    }
    resultobj = libxml_constxmlCharPtrWrap(res);

    return resultobj;
}

static PyObject *
libxml_doc(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlDocPtr res;

    if (!PyArg_ParseTuple(args, "O:doc", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_doc: cur = %p\n", cur);
#endif

    switch(cur->type) {
	case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
#endif
	case XML_HTML_DOCUMENT_NODE:
	    res = NULL;
	    break;
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    res = attr->doc;
	    break;
	}
	case XML_NAMESPACE_DECL:
	    res = NULL;
	    break;
	default:
	    res = cur->doc;
	    break;
    }
    resultobj = libxml_xmlDocPtrWrap(res);
    return resultobj;
}

static PyObject *
libxml_properties(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur = NULL;
    xmlAttrPtr res;

    if (!PyArg_ParseTuple(args, "O:properties", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);
    if (cur->type == XML_ELEMENT_NODE)
	res = cur->properties;
    else
	res = NULL;
    resultobj = libxml_xmlAttrPtrWrap(res);
    return resultobj;
}

static PyObject *
libxml_next(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, "O:next", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_next: cur = %p\n", cur);
#endif

    switch(cur->type) {
	case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
#endif
	case XML_HTML_DOCUMENT_NODE:
	    res = NULL;
	    break;
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    res = (xmlNodePtr) attr->next;
	    break;
	}
	case XML_NAMESPACE_DECL: {
	    xmlNsPtr ns = (xmlNsPtr) cur;
	    res = (xmlNodePtr) ns->next;
	    break;
	}
	default:
	    res = cur->next;
	    break;

    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}

static PyObject *
libxml_prev(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, "O:prev", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_prev: cur = %p\n", cur);
#endif

    switch(cur->type) {
	case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
#endif
	case XML_HTML_DOCUMENT_NODE:
	    res = NULL;
	    break;
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    res = (xmlNodePtr) attr->next;
	}
	case XML_NAMESPACE_DECL:
	    res = NULL;
	    break;
	default:
	    res = cur->next;
	    break;
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}

static PyObject *
libxml_children(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, "O:children", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_children: cur = %p\n", cur);
#endif

    switch(cur->type) {
	case XML_ELEMENT_NODE:
	case XML_ENTITY_REF_NODE:
	case XML_ENTITY_NODE:
	case XML_PI_NODE:
	case XML_COMMENT_NODE:
	case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
#endif
	case XML_HTML_DOCUMENT_NODE:
	case XML_DTD_NODE:
	    res = cur->children;
	    break;
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    res = attr->children;
	    break;
	}
	default:
	    res = NULL;
	    break;
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}

static PyObject *
libxml_last(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, "O:last", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_last: cur = %p\n", cur);
#endif

    switch(cur->type) {
	case XML_ELEMENT_NODE:
	case XML_ENTITY_REF_NODE:
	case XML_ENTITY_NODE:
	case XML_PI_NODE:
	case XML_COMMENT_NODE:
	case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
#endif
	case XML_HTML_DOCUMENT_NODE:
	case XML_DTD_NODE:
	    res = cur->last;
	    break;
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    res = attr->last;
	}
	default:
	    res = NULL;
	    break;
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}

static PyObject *
libxml_parent(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, "O:parent", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_parent: cur = %p\n", cur);
#endif

    switch(cur->type) {
	case XML_DOCUMENT_NODE:
	case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
#endif
	    res = NULL;
	    break;
	case XML_ATTRIBUTE_NODE: {
	    xmlAttrPtr attr = (xmlAttrPtr) cur;
	    res = attr->parent;
	}
	case XML_ENTITY_DECL:
	case XML_NAMESPACE_DECL:
	case XML_XINCLUDE_START:
	case XML_XINCLUDE_END:
	    res = NULL;
	    break;
	default:
	    res = cur->parent;
	    break;
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}

static PyObject *
libxml_type(PyObject *self, PyObject *args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    const xmlChar *res;

    if (!PyArg_ParseTuple(args, "O:last", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_type: cur = %p\n", cur);
#endif

    switch(cur->type) {
        case XML_ELEMENT_NODE:
	    res = (const xmlChar *) "element"; break;
        case XML_ATTRIBUTE_NODE:
	    res = (const xmlChar *) "attribute"; break;
        case XML_TEXT_NODE:
	    res = (const xmlChar *) "text"; break;
        case XML_CDATA_SECTION_NODE:
	    res = (const xmlChar *) "cdata"; break;
        case XML_ENTITY_REF_NODE:
	    res = (const xmlChar *) "entity_ref"; break;
        case XML_ENTITY_NODE:
	    res = (const xmlChar *) "entity"; break;
        case XML_PI_NODE:
	    res = (const xmlChar *) "pi"; break;
        case XML_COMMENT_NODE:
	    res = (const xmlChar *) "comment"; break;
        case XML_DOCUMENT_NODE:
	    res = (const xmlChar *) "document_xml"; break;
        case XML_DOCUMENT_TYPE_NODE:
	    res = (const xmlChar *) "doctype"; break;
        case XML_DOCUMENT_FRAG_NODE:
	    res = (const xmlChar *) "fragment"; break;
        case XML_NOTATION_NODE:
	    res = (const xmlChar *) "notation"; break;
        case XML_HTML_DOCUMENT_NODE:
	    res = (const xmlChar *) "document_html"; break;
        case XML_DTD_NODE:
	    res = (const xmlChar *) "dtd"; break;
        case XML_ELEMENT_DECL:
	    res = (const xmlChar *) "elem_decl"; break;
        case XML_ATTRIBUTE_DECL:
	    res = (const xmlChar *) "attribute_decl"; break;
        case XML_ENTITY_DECL:
	    res = (const xmlChar *) "entity_decl"; break;
        case XML_NAMESPACE_DECL:
	    res = (const xmlChar *) "namespace"; break;
        case XML_XINCLUDE_START:
	    res = (const xmlChar *) "xinclude_start"; break;
        case XML_XINCLUDE_END:
	    res = (const xmlChar *) "xinclude_end"; break;
#ifdef LIBXML_DOCB_ENABLED
	case XML_DOCB_DOCUMENT_NODE:
	    res = (const xmlChar *) "document_docbook"; break;
#endif
    }
#ifdef DEBUG
    printf("libxml_type: cur = %p: %s\n", cur, res);
#endif

    resultobj = libxml_constxmlCharPtrWrap(res);
    return resultobj;
}

/************************************************************************
 *									*
 *			Specific accessor functions			*
 *									*
 ************************************************************************/
PyObject *
libxml_xmlNodeGetNsDefs(PyObject *self, PyObject *args) {
    PyObject *py_retval;
    xmlNsPtr c_retval;
    xmlNodePtr node;
    PyObject *pyobj_node;

    if (!PyArg_ParseTuple(args, "O:xmlNodeGetNsDefs", &pyobj_node))
        return(NULL);
    node = (xmlNodePtr) PyxmlNode_Get(pyobj_node);

    if ((node == NULL) || (node->type != XML_ELEMENT_NODE)) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    c_retval = node->nsDef;
    py_retval = libxml_xmlNsPtrWrap((xmlNsPtr) c_retval);
    return(py_retval);
}

PyObject *
libxml_xmlNodeGetNs(PyObject *self, PyObject *args) {
    PyObject *py_retval;
    xmlNsPtr c_retval;
    xmlNodePtr node;
    PyObject *pyobj_node;

    if (!PyArg_ParseTuple(args, "O:xmlNodeGetNs", &pyobj_node))
        return(NULL);
    node = (xmlNodePtr) PyxmlNode_Get(pyobj_node);

    if ((node == NULL) || (node->type != XML_ELEMENT_NODE)) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    c_retval = node->ns;
    py_retval = libxml_xmlNsPtrWrap((xmlNsPtr) c_retval);
    return(py_retval);
}

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libxmlMethods[] = {
#include "libxml2-export.c"
    { "name", libxml_name, METH_VARARGS },
    { "children", libxml_children, METH_VARARGS },
    { "properties", libxml_properties, METH_VARARGS },
    { "last", libxml_last, METH_VARARGS },
    { "prev", libxml_prev, METH_VARARGS },
    { "next", libxml_next, METH_VARARGS },
    { "parent", libxml_parent, METH_VARARGS },
    { "type", libxml_type, METH_VARARGS },
    { "doc", libxml_doc, METH_VARARGS },
};

void init_libxml(void) {
    PyObject *m;
    m = Py_InitModule("_libxml", libxmlMethods);
    libxml_xmlErrorInitialize();
}

