/*
 * libxml.c: this modules implements the main part of the glue of the
 *           libxml2 library and the Python interpreter. It provides the
 *           entry points where an automatically generated stub is either
 *           unpractical or would not match cleanly the Python model.
 *
 * If compiled with MERGED_MODULES, the entry point will be used to
 * initialize both the libxml2 and the libxslt wrappers
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */
#include <Python.h>
#include <fileobject.h>
#include "config.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlerror.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlIO.h>
#include "libxml_wrap.h"
#include "libxml2-py.h"

/* #define DEBUG */
/* #define DEBUG_SAX */
/* #define DEBUG_XPATH */
/* #define DEBUG_ERROR */
/* #define DEBUG_MEMORY */
/* #define DEBUG_FILES */
/* #define DEBUG_LOADER */

void initlibxml2mod(void);

/**
 * TODO:
 *
 * macro to flag unimplemented blocks
 */
#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

/************************************************************************
 *									*
 *		Memory debug interface					*
 *									*
 ************************************************************************/

extern void xmlMemFree(void *ptr);
extern void *xmlMemMalloc(size_t size);
extern void *xmlMemRealloc(void *ptr, size_t size);
extern char *xmlMemoryStrdup(const char *str);

static int libxmlMemoryDebugActivated = 0;
static long libxmlMemoryAllocatedBase = 0;

static int libxmlMemoryDebug = 0;
static xmlFreeFunc freeFunc = NULL;
static xmlMallocFunc mallocFunc = NULL;
static xmlReallocFunc reallocFunc = NULL;
static xmlStrdupFunc strdupFunc = NULL;

PyObject *
libxml_xmlDebugMemory(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    int activate;
    PyObject *py_retval;
    long ret;

    if (!PyArg_ParseTuple(args, (char *) "i:xmlDebugMemory", &activate))
        return (NULL);

#ifdef DEBUG_MEMORY
    printf("libxml_xmlDebugMemory(%d) called\n", activate);
#endif

    if (activate != 0) {
        if (libxmlMemoryDebug == 0) {
            /*
             * First initialize the library and grab the old memory handlers
             * and switch the library to memory debugging
             */
            xmlMemGet((xmlFreeFunc *) & freeFunc,
                      (xmlMallocFunc *) & mallocFunc,
                      (xmlReallocFunc *) & reallocFunc,
                      (xmlStrdupFunc *) & strdupFunc);
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
    return (py_retval);
}

PyObject *
libxml_xmlDumpMemory(ATTRIBUTE_UNUSED PyObject * self,
                     ATTRIBUTE_UNUSED PyObject * args)
{

    if (libxmlMemoryDebug != 0)
        xmlMemoryDump();
    Py_INCREF(Py_None);
    return (Py_None);
}

/************************************************************************
 *									*
 *		Handling Python FILE I/O at the C level			*
 *	The raw I/O attack diectly the File objects, while the		*
 *	other routines address the ioWrapper instance instead		*
 *									*
 ************************************************************************/

/**
 * xmlPythonFileCloseUnref:
 * @context:  the I/O context
 *
 * Close an I/O channel
 */
static int
xmlPythonFileCloseRaw (void * context) {
    PyObject *file, *ret;

#ifdef DEBUG_FILES
    printf("xmlPythonFileCloseUnref\n");
#endif
    file = (PyObject *) context;
    if (file == NULL) return(-1);
    ret = PyEval_CallMethod(file, (char *) "close", (char *) "()");
    if (ret != NULL) {
	Py_DECREF(ret);
    }
    Py_DECREF(file);
    return(0);
}

/**
 * xmlPythonFileReadRaw:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Read @len bytes to @buffer from the Python file in the I/O channel
 *
 * Returns the number of bytes read
 */
static int
xmlPythonFileReadRaw (void * context, char * buffer, int len) {
    PyObject *file;
    PyObject *ret;
    int lenread = -1;
    char *data;

#ifdef DEBUG_FILES
    printf("xmlPythonFileReadRaw: %d\n", len);
#endif
    file = (PyObject *) context;
    if (file == NULL) return(-1);
    ret = PyEval_CallMethod(file, (char *) "read", (char *) "(i)", len);
    if (ret == NULL) {
	printf("xmlPythonFileReadRaw: result is NULL\n");
	return(-1);
    } else if (PyString_Check(ret)) {
	lenread = PyString_Size(ret);
	data = PyString_AsString(ret);
	if (lenread > len)
	    memcpy(buffer, data, len);
	else
	    memcpy(buffer, data, lenread);
	Py_DECREF(ret);
    } else {
	printf("xmlPythonFileReadRaw: result is not a String\n");
	Py_DECREF(ret);
    }
    return(lenread);
}

/**
 * xmlPythonFileRead:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Read @len bytes to @buffer from the I/O channel.
 *
 * Returns the number of bytes read
 */
static int
xmlPythonFileRead (void * context, char * buffer, int len) {
    PyObject *file;
    PyObject *ret;
    int lenread = -1;
    char *data;

#ifdef DEBUG_FILES
    printf("xmlPythonFileRead: %d\n", len);
#endif
    file = (PyObject *) context;
    if (file == NULL) return(-1);
    ret = PyEval_CallMethod(file, (char *) "io_read", (char *) "(i)", len);
    if (ret == NULL) {
	printf("xmlPythonFileRead: result is NULL\n");
	return(-1);
    } else if (PyString_Check(ret)) {
	lenread = PyString_Size(ret);
	data = PyString_AsString(ret);
	if (lenread > len)
	    memcpy(buffer, data, len);
	else
	    memcpy(buffer, data, lenread);
	Py_DECREF(ret);
    } else {
	printf("xmlPythonFileRead: result is not a String\n");
	Py_DECREF(ret);
    }
    return(lenread);
}

/**
 * xmlFileWrite:
 * @context:  the I/O context
 * @buffer:  where to drop data
 * @len:  number of bytes to write
 *
 * Write @len bytes from @buffer to the I/O channel.
 *
 * Returns the number of bytes written
 */
static int
xmlPythonFileWrite (void * context, const char * buffer, int len) {
    PyObject *file;
    PyObject *string;
    PyObject *ret;
    int written = -1;

#ifdef DEBUG_FILES
    printf("xmlPythonFileWrite: %d\n", len);
#endif
    file = (PyObject *) context;
    if (file == NULL) return(-1);
    string = PyString_FromStringAndSize(buffer, len);
    if (string == NULL) return(-1);
    ret = PyEval_CallMethod(file, (char *) "io_write", (char *) "(O)", string);
    Py_DECREF(string);
    if (ret == NULL) {
	printf("xmlPythonFileWrite: result is NULL\n");
	return(-1);
    } else if (PyInt_Check(ret)) {
	written = (int) PyInt_AsLong(ret);
	Py_DECREF(ret);
    } else if (ret == Py_None) {
	written = len;
	Py_DECREF(ret);
    } else {
	printf("xmlPythonFileWrite: result is not an Int nor None\n");
	Py_DECREF(ret);
    }
    return(written);
}

/**
 * xmlPythonFileClose:
 * @context:  the I/O context
 *
 * Close an I/O channel
 */
static int
xmlPythonFileClose (void * context) {
    PyObject *file, *ret;

#ifdef DEBUG_FILES
    printf("xmlPythonFileClose\n");
#endif
    file = (PyObject *) context;
    if (file == NULL) return(-1);
    ret = PyEval_CallMethod(file, (char *) "io_close", (char *) "()");
    if (ret != NULL) {
	Py_DECREF(ret);
    }
    return(0);
}

/**
 * xmlOutputBufferCreatePythonFile:
 * @file:  a PyFile_Type
 * @encoder:  the encoding converter or NULL
 *
 * Create a buffered output for the progressive saving to a PyFile_Type
 * buffered C I/O
 *
 * Returns the new parser output or NULL
 */
static xmlOutputBufferPtr
xmlOutputBufferCreatePythonFile(PyObject *file, 
	                        xmlCharEncodingHandlerPtr encoder) {
    xmlOutputBufferPtr ret;

    if (file == NULL) return(NULL);

    ret = xmlAllocOutputBuffer(encoder);
    if (ret != NULL) {
        ret->context = file;
	/* Py_INCREF(file); */
	ret->writecallback = xmlPythonFileWrite;
	ret->closecallback = xmlPythonFileClose;
    }

    return(ret);
}

PyObject *
libxml_xmlCreateOutputBuffer(ATTRIBUTE_UNUSED PyObject *self, PyObject *args) {
    PyObject *py_retval;
    PyObject *file;
    xmlChar  *encoding;
    xmlCharEncodingHandlerPtr handler = NULL;
    xmlOutputBufferPtr buffer;


    if (!PyArg_ParseTuple(args, (char *)"Oz:xmlOutputBufferCreate",
		&file, &encoding))
	return(NULL);
    if ((encoding != NULL) && (encoding[0] != 0)) {
	handler = xmlFindCharEncodingHandler((const char *) encoding);
    }
    buffer = xmlOutputBufferCreatePythonFile(file, handler);
    if (buffer == NULL)
	printf("libxml_xmlCreateOutputBuffer: buffer == NULL\n");
    py_retval = libxml_xmlOutputBufferPtrWrap(buffer);
    return(py_retval);
}


/**
 * xmlParserInputBufferCreatePythonFile:
 * @file:  a PyFile_Type
 * @encoder:  the encoding converter or NULL
 *
 * Create a buffered output for the progressive saving to a PyFile_Type
 * buffered C I/O
 *
 * Returns the new parser output or NULL
 */
static xmlParserInputBufferPtr
xmlParserInputBufferCreatePythonFile(PyObject *file, 
	                        xmlCharEncoding encoding) {
    xmlParserInputBufferPtr ret;

    if (file == NULL) return(NULL);

    ret = xmlAllocParserInputBuffer(encoding);
    if (ret != NULL) {
        ret->context = file;
	/* Py_INCREF(file); */
	ret->readcallback = xmlPythonFileRead;
	ret->closecallback = xmlPythonFileClose;
    }

    return(ret);
}

PyObject *
libxml_xmlCreateInputBuffer(ATTRIBUTE_UNUSED PyObject *self, PyObject *args) {
    PyObject *py_retval;
    PyObject *file;
    xmlChar  *encoding;
    xmlCharEncoding enc = XML_CHAR_ENCODING_NONE;
    xmlParserInputBufferPtr buffer;


    if (!PyArg_ParseTuple(args, (char *)"Oz:xmlParserInputBufferCreate",
		&file, &encoding))
	return(NULL);
    if ((encoding != NULL) && (encoding[0] != 0)) {
	enc = xmlParseCharEncoding((const char *) encoding);
    }
    buffer = xmlParserInputBufferCreatePythonFile(file, enc);
    if (buffer == NULL)
	printf("libxml_xmlParserInputBufferCreate: buffer == NULL\n");
    py_retval = libxml_xmlParserInputBufferPtrWrap(buffer);
    return(py_retval);
}

/************************************************************************
 *									*
 *		Providing the resolver at the Python level		*
 *									*
 ************************************************************************/

static xmlExternalEntityLoader defaultExternalEntityLoader = NULL;
static PyObject *pythonExternalEntityLoaderObjext;

static xmlParserInputPtr
pythonExternalEntityLoader(const char *URL, const char *ID,
			   xmlParserCtxtPtr ctxt) {
    xmlParserInputPtr result = NULL;
    if (pythonExternalEntityLoaderObjext != NULL) {
	PyObject *ret;
	PyObject *ctxtobj;

	ctxtobj = libxml_xmlParserCtxtPtrWrap(ctxt);
#ifdef DEBUG_LOADER
	printf("pythonExternalEntityLoader: ready to call\n");
#endif

	ret = PyObject_CallFunction(pythonExternalEntityLoaderObjext,
		      (char *) "(ssO)", URL, ID, ctxtobj);
#ifdef DEBUG_LOADER
	printf("pythonExternalEntityLoader: result ");
	PyObject_Print(ret, stdout, 0);
	printf("\n");
#endif

	if (ret != NULL) {
	    if (PyObject_HasAttrString(ret, (char *) "read")) {
		xmlParserInputBufferPtr buf;

		buf = xmlAllocParserInputBuffer(XML_CHAR_ENCODING_NONE);
		if (buf != NULL) {
		    buf->context = ret;
		    buf->readcallback = xmlPythonFileReadRaw;
		    buf->closecallback = xmlPythonFileCloseRaw;
		    result = xmlNewIOInputStream(ctxt, buf,
			                         XML_CHAR_ENCODING_NONE);
		}
	    } else {
		printf("pythonExternalEntityLoader: can't read\n");
	    }
	    if (result == NULL) {
		Py_DECREF(ret);
	    }
	}
    }
    if ((result == NULL) && (defaultExternalEntityLoader != NULL)) {
	result = defaultExternalEntityLoader(URL, ID, ctxt);
    }
    return(result);
}

PyObject *
libxml_xmlSetEntityLoader(ATTRIBUTE_UNUSED PyObject *self, PyObject *args) {
    PyObject *py_retval;
    PyObject *loader;

    if (!PyArg_ParseTuple(args, (char *)"O:libxml_xmlSetEntityLoader",
		&loader))
	return(NULL);

#ifdef DEBUG_LOADER
    printf("libxml_xmlSetEntityLoader\n");
#endif
    if (defaultExternalEntityLoader == NULL) 
	defaultExternalEntityLoader = xmlGetExternalEntityLoader();

    pythonExternalEntityLoaderObjext = loader;
    xmlSetExternalEntityLoader(pythonExternalEntityLoader);

    py_retval = PyInt_FromLong(0);
    return(py_retval);
}


/************************************************************************
 *									*
 *		Handling SAX/xmllib/sgmlop callback interfaces		*
 *									*
 ************************************************************************/

static void
pythonStartElement(void *user_data, const xmlChar * name,
                   const xmlChar ** attrs)
{
    int i;
    PyObject *handler;
    PyObject *dict;
    PyObject *attrname;
    PyObject *attrvalue;
    PyObject *result = NULL;
    int type = 0;

#ifdef DEBUG_SAX
    printf("pythonStartElement(%s) called\n", name);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "startElement"))
        type = 1;
    else if (PyObject_HasAttrString(handler, (char *) "start"))
        type = 2;
    if (type != 0) {
        /*
         * the xmllib interface always generate a dictionnary,
         * possibly empty
         */
        if ((attrs == NULL) && (type == 1)) {
            Py_XINCREF(Py_None);
            dict = Py_None;
        } else if (attrs == NULL) {
            dict = PyDict_New();
        } else {
            dict = PyDict_New();
            for (i = 0; attrs[i] != NULL; i++) {
                attrname = PyString_FromString((char *) attrs[i]);
                i++;
                if (attrs[i] != NULL) {
                    attrvalue = PyString_FromString((char *) attrs[i]);
                } else {
                    Py_XINCREF(Py_None);
                    attrvalue = Py_None;
                }
                PyDict_SetItem(dict, attrname, attrvalue);
            }
        }

        if (type == 1)
            result = PyObject_CallMethod(handler, (char *) "startElement",
                                         (char *) "sO", name, dict);
        else if (type == 2)
            result = PyObject_CallMethod(handler, (char *) "start",
                                         (char *) "sO", name, dict);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(dict);
        Py_XDECREF(result);
    }
}

static void
pythonStartDocument(void *user_data)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonStartDocument() called\n");
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "startDocument")) {
        result =
            PyObject_CallMethod(handler, (char *) "startDocument", NULL);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonEndDocument(void *user_data)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonEndDocument() called\n");
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "endDocument")) {
        result =
            PyObject_CallMethod(handler, (char *) "endDocument", NULL);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
    /*
     * The reference to the handler is released there
     */
    Py_XDECREF(handler);
}

static void
pythonEndElement(void *user_data, const xmlChar * name)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonEndElement(%s) called\n", name);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "endElement")) {
        result = PyObject_CallMethod(handler, (char *) "endElement",
                                     (char *) "s", name);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    } else if (PyObject_HasAttrString(handler, (char *) "end")) {
        result = PyObject_CallMethod(handler, (char *) "end",
                                     (char *) "s", name);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonReference(void *user_data, const xmlChar * name)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonReference(%s) called\n", name);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "reference")) {
        result = PyObject_CallMethod(handler, (char *) "reference",
                                     (char *) "s", name);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonCharacters(void *user_data, const xmlChar * ch, int len)
{
    PyObject *handler;
    PyObject *result = NULL;
    int type = 0;

#ifdef DEBUG_SAX
    printf("pythonCharacters(%s, %d) called\n", ch, len);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "characters"))
        type = 1;
    else if (PyObject_HasAttrString(handler, (char *) "data"))
        type = 2;
    if (type != 0) {
        if (type == 1)
            result = PyObject_CallMethod(handler, (char *) "characters",
                                         (char *) "s#", ch, len);
        else if (type == 2)
            result = PyObject_CallMethod(handler, (char *) "data",
                                         (char *) "s#", ch, len);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonIgnorableWhitespace(void *user_data, const xmlChar * ch, int len)
{
    PyObject *handler;
    PyObject *result = NULL;
    int type = 0;

#ifdef DEBUG_SAX
    printf("pythonIgnorableWhitespace(%s, %d) called\n", ch, len);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "ignorableWhitespace"))
        type = 1;
    else if (PyObject_HasAttrString(handler, (char *) "data"))
        type = 2;
    if (type != 0) {
        if (type == 1)
            result =
                PyObject_CallMethod(handler,
                                    (char *) "ignorableWhitespace",
                                    (char *) "s#", ch, len);
        else if (type == 2)
            result =
                PyObject_CallMethod(handler, (char *) "data",
                                    (char *) "s#", ch, len);
        Py_XDECREF(result);
    }
}

static void
pythonProcessingInstruction(void *user_data,
                            const xmlChar * target, const xmlChar * data)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonProcessingInstruction(%s, %s) called\n", target, data);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "processingInstruction")) {
        result = PyObject_CallMethod(handler, (char *)
                                     "processingInstruction",
                                     (char *) "ss", target, data);
        Py_XDECREF(result);
    }
}

static void
pythonComment(void *user_data, const xmlChar * value)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonComment(%s) called\n", value);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "comment")) {
        result =
            PyObject_CallMethod(handler, (char *) "comment", (char *) "s",
                                value);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonWarning(void *user_data, const char *msg, ...)
{
    PyObject *handler;
    PyObject *result;
    va_list args;
    char buf[1024];

#ifdef DEBUG_SAX
    printf("pythonWarning(%s) called\n", msg);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "warning")) {
        va_start(args, msg);
        vsnprintf(buf, 1023, msg, args);
        va_end(args);
        buf[1023] = 0;
        result =
            PyObject_CallMethod(handler, (char *) "warning", (char *) "s",
                                buf);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonError(void *user_data, const char *msg, ...)
{
    PyObject *handler;
    PyObject *result;
    va_list args;
    char buf[1024];

#ifdef DEBUG_SAX
    printf("pythonError(%s) called\n", msg);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "error")) {
        va_start(args, msg);
        vsnprintf(buf, 1023, msg, args);
        va_end(args);
        buf[1023] = 0;
        result =
            PyObject_CallMethod(handler, (char *) "error", (char *) "s",
                                buf);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonFatalError(void *user_data, const char *msg, ...)
{
    PyObject *handler;
    PyObject *result;
    va_list args;
    char buf[1024];

#ifdef DEBUG_SAX
    printf("pythonFatalError(%s) called\n", msg);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "fatalError")) {
        va_start(args, msg);
        vsnprintf(buf, 1023, msg, args);
        va_end(args);
        buf[1023] = 0;
        result =
            PyObject_CallMethod(handler, (char *) "fatalError",
                                (char *) "s", buf);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonCdataBlock(void *user_data, const xmlChar * ch, int len)
{
    PyObject *handler;
    PyObject *result = NULL;
    int type = 0;

#ifdef DEBUG_SAX
    printf("pythonCdataBlock(%s, %d) called\n", ch, len);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "cdataBlock"))
        type = 1;
    else if (PyObject_HasAttrString(handler, (char *) "cdata"))
        type = 2;
    if (type != 0) {
        if (type == 1)
            result =
                PyObject_CallMethod(handler, (char *) "cdataBlock",
                                    (char *) "s#", ch, len);
        else if (type == 2)
            result =
                PyObject_CallMethod(handler, (char *) "cdata",
                                    (char *) "s#", ch, len);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonExternalSubset(void *user_data,
                     const xmlChar * name,
                     const xmlChar * externalID, const xmlChar * systemID)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonExternalSubset(%s, %s, %s) called\n",
           name, externalID, systemID);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "externalSubset")) {
        result =
            PyObject_CallMethod(handler, (char *) "externalSubset",
                                (char *) "sss", name, externalID,
                                systemID);
        Py_XDECREF(result);
    }
}

static void
pythonEntityDecl(void *user_data,
                 const xmlChar * name,
                 int type,
                 const xmlChar * publicId,
                 const xmlChar * systemId, xmlChar * content)
{
    PyObject *handler;
    PyObject *result;

    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "entityDecl")) {
        result = PyObject_CallMethod(handler, (char *) "entityDecl",
                                     (char *) "sisss", name, type,
                                     publicId, systemId, content);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}



static void

pythonNotationDecl(void *user_data,
                   const xmlChar * name,
                   const xmlChar * publicId, const xmlChar * systemId)
{
    PyObject *handler;
    PyObject *result;

    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "notationDecl")) {
        result = PyObject_CallMethod(handler, (char *) "notationDecl",
                                     (char *) "sss", name, publicId,
                                     systemId);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonAttributeDecl(void *user_data,
                    const xmlChar * elem,
                    const xmlChar * name,
                    int type,
                    int def,
                    const xmlChar * defaultValue, xmlEnumerationPtr tree)
{
    PyObject *handler;
    PyObject *nameList;
    PyObject *newName;
    xmlEnumerationPtr node;
    PyObject *result;
    int count;

    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "attributeDecl")) {
        count = 0;
        for (node = tree; node != NULL; node = node->next) {
            count++;
        }
        nameList = PyList_New(count);
        count = 0;
        for (node = tree; node != NULL; node = node->next) {
            newName = PyString_FromString((char *) node->name);
            PyList_SetItem(nameList, count, newName);
            count++;
        }
        result = PyObject_CallMethod(handler, (char *) "attributeDecl",
                                     (char *) "ssiisO", elem, name, type,
                                     def, defaultValue, nameList);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(nameList);
        Py_XDECREF(result);
    }
}

static void
pythonElementDecl(void *user_data,
                  const xmlChar * name,
                  int type, ATTRIBUTE_UNUSED xmlElementContentPtr content)
{
    PyObject *handler;
    PyObject *obj;
    PyObject *result;

    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "elementDecl")) {
        /* TODO: wrap in an elementContent object */
        printf
            ("pythonElementDecl: xmlElementContentPtr wrapper missing !\n");
        obj = Py_None;
        /* Py_XINCREF(Py_None); isn't the reference just borrowed ??? */
        result = PyObject_CallMethod(handler, (char *) "elementDecl",
                                     (char *) "siO", name, type, obj);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonUnparsedEntityDecl(void *user_data,
                         const xmlChar * name,
                         const xmlChar * publicId,
                         const xmlChar * systemId,
                         const xmlChar * notationName)
{
    PyObject *handler;
    PyObject *result;

    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "unparsedEntityDecl")) {
        result =
            PyObject_CallMethod(handler, (char *) "unparsedEntityDecl",
                                (char *) "ssss", name, publicId, systemId,
                                notationName);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static void
pythonInternalSubset(void *user_data, const xmlChar * name,
                     const xmlChar * ExternalID, const xmlChar * SystemID)
{
    PyObject *handler;
    PyObject *result;

#ifdef DEBUG_SAX
    printf("pythonInternalSubset(%s, %s, %s) called\n",
           name, ExternalID, SystemID);
#endif
    handler = (PyObject *) user_data;
    if (PyObject_HasAttrString(handler, (char *) "internalSubset")) {
        result = PyObject_CallMethod(handler, (char *) "internalSubset",
                                     (char *) "sss", name, ExternalID,
                                     SystemID);
        if (PyErr_Occurred())
            PyErr_Print();
        Py_XDECREF(result);
    }
}

static xmlSAXHandler pythonSaxHandler = {
    pythonInternalSubset,
    NULL,                       /* TODO pythonIsStandalone, */
    NULL,                       /* TODO pythonHasInternalSubset, */
    NULL,                       /* TODO pythonHasExternalSubset, */
    NULL,                       /* TODO pythonResolveEntity, */
    NULL,                       /* TODO pythonGetEntity, */
    pythonEntityDecl,
    pythonNotationDecl,
    pythonAttributeDecl,
    pythonElementDecl,
    pythonUnparsedEntityDecl,
    NULL,                       /* OBSOLETED pythonSetDocumentLocator, */
    pythonStartDocument,
    pythonEndDocument,
    pythonStartElement,
    pythonEndElement,
    pythonReference,
    pythonCharacters,
    pythonIgnorableWhitespace,
    pythonProcessingInstruction,
    pythonComment,
    pythonWarning,
    pythonError,
    pythonFatalError,
    NULL,                       /* TODO pythonGetParameterEntity, */
    pythonCdataBlock,
    pythonExternalSubset,
    1
};

/************************************************************************
 *									*
 *		Handling of specific parser context			*
 *									*
 ************************************************************************/

PyObject *
libxml_xmlCreatePushParser(ATTRIBUTE_UNUSED PyObject * self,
                           PyObject * args)
{
    const char *chunk;
    int size;
    const char *URI;
    PyObject *pyobj_SAX = NULL;
    xmlSAXHandlerPtr SAX = NULL;
    xmlParserCtxtPtr ret;
    PyObject *pyret;

    if (!PyArg_ParseTuple
        (args, (char *) "Oziz:xmlCreatePushParser", &pyobj_SAX, &chunk,
         &size, &URI))
        return (NULL);

#ifdef DEBUG
    printf("libxml_xmlCreatePushParser(%p, %s, %d, %s) called\n",
           pyobj_SAX, chunk, size, URI);
#endif
    if (pyobj_SAX != Py_None) {
        SAX = &pythonSaxHandler;
        Py_INCREF(pyobj_SAX);
        /* The reference is released in pythonEndDocument() */
    }
    ret = xmlCreatePushParserCtxt(SAX, pyobj_SAX, chunk, size, URI);
    pyret = libxml_xmlParserCtxtPtrWrap(ret);
    return (pyret);
}

PyObject *
libxml_htmlCreatePushParser(ATTRIBUTE_UNUSED PyObject * self,
                            PyObject * args)
{
    const char *chunk;
    int size;
    const char *URI;
    PyObject *pyobj_SAX = NULL;
    xmlSAXHandlerPtr SAX = NULL;
    xmlParserCtxtPtr ret;
    PyObject *pyret;

    if (!PyArg_ParseTuple
        (args, (char *) "Oziz:htmlCreatePushParser", &pyobj_SAX, &chunk,
         &size, &URI))
        return (NULL);

#ifdef DEBUG
    printf("libxml_htmlCreatePushParser(%p, %s, %d, %s) called\n",
           pyobj_SAX, chunk, size, URI);
#endif
    if (pyobj_SAX != Py_None) {
        SAX = &pythonSaxHandler;
        Py_INCREF(pyobj_SAX);
        /* The reference is released in pythonEndDocument() */
    }
    ret = htmlCreatePushParserCtxt(SAX, pyobj_SAX, chunk, size, URI,
                                   XML_CHAR_ENCODING_NONE);
    pyret = libxml_xmlParserCtxtPtrWrap(ret);
    return (pyret);
}

PyObject *
libxml_xmlSAXParseFile(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    int recover;
    const char *URI;
    PyObject *pyobj_SAX = NULL;
    xmlSAXHandlerPtr SAX = NULL;

    if (!PyArg_ParseTuple(args, (char *) "Osi:xmlSAXParseFile", &pyobj_SAX,
                          &URI, &recover))
        return (NULL);

#ifdef DEBUG
    printf("libxml_xmlSAXParseFile(%p, %s, %d) called\n",
           pyobj_SAX, URI, recover);
#endif
    if (pyobj_SAX == Py_None) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    SAX = &pythonSaxHandler;
    Py_INCREF(pyobj_SAX);
    /* The reference is released in pythonEndDocument() */
    xmlSAXParseFileWithData(SAX, URI, recover, pyobj_SAX);
    Py_INCREF(Py_None);
    return (Py_None);
}

PyObject *
libxml_htmlSAXParseFile(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    const char *URI;
    const char *encoding;
    PyObject *pyobj_SAX = NULL;
    xmlSAXHandlerPtr SAX = NULL;

    if (!PyArg_ParseTuple
        (args, (char *) "Osz:htmlSAXParseFile", &pyobj_SAX, &URI,
         &encoding))
        return (NULL);

#ifdef DEBUG
    printf("libxml_htmlSAXParseFile(%p, %s, %s) called\n",
           pyobj_SAX, URI, encoding);
#endif
    if (pyobj_SAX == Py_None) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    SAX = &pythonSaxHandler;
    Py_INCREF(pyobj_SAX);
    /* The reference is released in pythonEndDocument() */
    htmlSAXParseFile(URI, encoding, SAX, pyobj_SAX);
    Py_INCREF(Py_None);
    return (Py_None);
}

/************************************************************************
 *									*
 *			Error message callback				*
 *									*
 ************************************************************************/

static PyObject *libxml_xmlPythonErrorFuncHandler = NULL;
static PyObject *libxml_xmlPythonErrorFuncCtxt = NULL;

static void
libxml_xmlErrorFuncHandler(ATTRIBUTE_UNUSED void *ctx, const char *msg,
                           ...)
{
    int size;
    int chars;
    char *larger;
    va_list ap;
    char *str;
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
libxml_xmlErrorInitialize(void)
{
#ifdef DEBUG_ERROR
    printf("libxml_xmlErrorInitialize() called\n");
#endif
    xmlSetGenericErrorFunc(NULL, libxml_xmlErrorFuncHandler);
}

PyObject *
libxml_xmlRegisterErrorHandler(ATTRIBUTE_UNUSED PyObject * self,
                               PyObject * args)
{
    PyObject *py_retval;
    PyObject *pyobj_f;
    PyObject *pyobj_ctx;

    if (!PyArg_ParseTuple
        (args, (char *) "OO:xmlRegisterErrorHandler", &pyobj_f,
         &pyobj_ctx))
        return (NULL);

#ifdef DEBUG_ERROR
    printf("libxml_registerXPathFunction(%p, %p) called\n", pyobj_ctx,
           pyobj_f);
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
    return (py_retval);
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

static void
libxml_xmlXPathFuncCallback(xmlXPathParserContextPtr ctxt, int nargs)
{
    PyObject *list, *cur, *result;
    xmlXPathObjectPtr obj;
    xmlXPathContextPtr rctxt;
    PyObject *current_function = NULL;
    const xmlChar *name;
    const xmlChar *ns_uri;
    int i;

    if (ctxt == NULL)
        return;
    rctxt = ctxt->context;
    if (rctxt == NULL)
        return;
    name = rctxt->function;
    ns_uri = rctxt->functionURI;
#ifdef DEBUG_XPATH
    printf("libxml_xmlXPathFuncCallback called name %s URI %s\n", name,
           ns_uri);
#endif

    /*
     * Find the function, it should be there it was there at lookup
     */
    for (i = 0; i < libxml_xpathCallbacksNb; i++) {
        if (                    /* TODO (ctxt == libxml_xpathCallbacks[i].ctx) && */
               (xmlStrEqual(name, libxml_xpathCallbacks[i].name)) &&
               (xmlStrEqual(ns_uri, libxml_xpathCallbacks[i].ns_uri))) {
            current_function = libxml_xpathCallbacks[i].function;
        }
    }
    if (current_function == NULL) {
        printf
            ("libxml_xmlXPathFuncCallback: internal error %s not found !\n",
             name);
        return;
    }

    list = PyTuple_New(nargs + 1);
    PyTuple_SetItem(list, 0, libxml_xmlXPathParserContextPtrWrap(ctxt));
    for (i = 0; i < nargs; i++) {
        obj = valuePop(ctxt);
        cur = libxml_xmlXPathObjectPtrWrap(obj);
        PyTuple_SetItem(list, i + 1, cur);
    }
    result = PyEval_CallObject(current_function, list);
    Py_DECREF(list);

    obj = libxml_xmlXPathObjectPtrConvert(result);
    valuePush(ctxt, obj);
}

static xmlXPathFunction
libxml_xmlXPathFuncLookupFunc(void *ctxt, const xmlChar * name,
                              const xmlChar * ns_uri)
{
    int i;

#ifdef DEBUG_XPATH
    printf("libxml_xmlXPathFuncLookupFunc(%p, %s, %s) called\n",
           ctxt, name, ns_uri);
#endif
    /*
     * This is called once only. The address is then stored in the
     * XPath expression evaluation, the proper object to call can
     * then still be found using the execution context function
     * and functionURI fields.
     */
    for (i = 0; i < libxml_xpathCallbacksNb; i++) {
        if ((ctxt == libxml_xpathCallbacks[i].ctx) &&
            (xmlStrEqual(name, libxml_xpathCallbacks[i].name)) &&
            (xmlStrEqual(ns_uri, libxml_xpathCallbacks[i].ns_uri))) {
            return (libxml_xmlXPathFuncCallback);
        }
    }
    return (NULL);
}

static void
libxml_xpathCallbacksInitialize(void)
{
    int i;

    if (libxml_xpathCallbacksInitialized != 0)
        return;

#ifdef DEBUG_XPATH
    printf("libxml_xpathCallbacksInitialized called\n");
#endif

    for (i = 0; i < 10; i++) {
        libxml_xpathCallbacks[i].ctx = NULL;
        libxml_xpathCallbacks[i].name = NULL;
        libxml_xpathCallbacks[i].ns_uri = NULL;
        libxml_xpathCallbacks[i].function = NULL;
    }
    libxml_xpathCallbacksInitialized = 1;
}

PyObject *
libxml_xmlRegisterXPathFunction(ATTRIBUTE_UNUSED PyObject * self,
                                PyObject * args)
{
    PyObject *py_retval;
    int c_retval = 0;
    xmlChar *name;
    xmlChar *ns_uri;
    xmlXPathContextPtr ctx;
    PyObject *pyobj_ctx;
    PyObject *pyobj_f;
    int i;

    if (!PyArg_ParseTuple
        (args, (char *) "OszO:registerXPathFunction", &pyobj_ctx, &name,
         &ns_uri, &pyobj_f))
        return (NULL);

    ctx = (xmlXPathContextPtr) PyxmlXPathContext_Get(pyobj_ctx);
    if (libxml_xpathCallbacksInitialized == 0)
        libxml_xpathCallbacksInitialize();
    xmlXPathRegisterFuncLookup(ctx, libxml_xmlXPathFuncLookupFunc, ctx);

    if ((pyobj_ctx == NULL) || (name == NULL) || (pyobj_f == NULL)) {
        py_retval = libxml_intWrap(-1);
        return (py_retval);
    }
#ifdef DEBUG_XPATH
    printf("libxml_registerXPathFunction(%p, %s, %s) called\n",
           ctx, name, ns_uri);
#endif
    for (i = 0; i < libxml_xpathCallbacksNb; i++) {
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
    return (py_retval);
}

/************************************************************************
 *									*
 *			Global properties access			*
 *									*
 ************************************************************************/
static PyObject *
libxml_name(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    const xmlChar *res;

    if (!PyArg_ParseTuple(args, (char *) "O:name", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_name: cur = %p type %d\n", cur, cur->type);
#endif

    switch (cur->type) {
        case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
        case XML_HTML_DOCUMENT_NODE:{
                xmlDocPtr doc = (xmlDocPtr) cur;

                res = doc->URL;
                break;
            }
        case XML_ATTRIBUTE_NODE:{
                xmlAttrPtr attr = (xmlAttrPtr) cur;

                res = attr->name;
                break;
            }
        case XML_NAMESPACE_DECL:{
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
libxml_doc(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlDocPtr res;

    if (!PyArg_ParseTuple(args, (char *) "O:doc", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_doc: cur = %p\n", cur);
#endif

    switch (cur->type) {
        case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
        case XML_HTML_DOCUMENT_NODE:
            res = NULL;
            break;
        case XML_ATTRIBUTE_NODE:{
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
libxml_properties(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur = NULL;
    xmlAttrPtr res;

    if (!PyArg_ParseTuple(args, (char *) "O:properties", &obj))
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
libxml_next(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, (char *) "O:next", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_next: cur = %p\n", cur);
#endif

    switch (cur->type) {
        case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
        case XML_HTML_DOCUMENT_NODE:
            res = NULL;
            break;
        case XML_ATTRIBUTE_NODE:{
                xmlAttrPtr attr = (xmlAttrPtr) cur;

                res = (xmlNodePtr) attr->next;
                break;
            }
        case XML_NAMESPACE_DECL:{
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
libxml_prev(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, (char *) "O:prev", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_prev: cur = %p\n", cur);
#endif

    switch (cur->type) {
        case XML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
        case XML_HTML_DOCUMENT_NODE:
            res = NULL;
            break;
        case XML_ATTRIBUTE_NODE:{
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
libxml_children(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, (char *) "O:children", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_children: cur = %p\n", cur);
#endif

    switch (cur->type) {
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
        case XML_ATTRIBUTE_NODE:{
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
libxml_last(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, (char *) "O:last", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_last: cur = %p\n", cur);
#endif

    switch (cur->type) {
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
        case XML_ATTRIBUTE_NODE:{
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
libxml_parent(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    xmlNodePtr res;

    if (!PyArg_ParseTuple(args, (char *) "O:parent", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_parent: cur = %p\n", cur);
#endif

    switch (cur->type) {
        case XML_DOCUMENT_NODE:
        case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
            res = NULL;
            break;
        case XML_ATTRIBUTE_NODE:{
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
libxml_type(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *resultobj, *obj;
    xmlNodePtr cur;
    const xmlChar *res = NULL;

    if (!PyArg_ParseTuple(args, (char *) "O:last", &obj))
        return NULL;
    cur = PyxmlNode_Get(obj);

#ifdef DEBUG
    printf("libxml_type: cur = %p\n", cur);
#endif

    switch (cur->type) {
        case XML_ELEMENT_NODE:
            res = (const xmlChar *) "element";
            break;
        case XML_ATTRIBUTE_NODE:
            res = (const xmlChar *) "attribute";
            break;
        case XML_TEXT_NODE:
            res = (const xmlChar *) "text";
            break;
        case XML_CDATA_SECTION_NODE:
            res = (const xmlChar *) "cdata";
            break;
        case XML_ENTITY_REF_NODE:
            res = (const xmlChar *) "entity_ref";
            break;
        case XML_ENTITY_NODE:
            res = (const xmlChar *) "entity";
            break;
        case XML_PI_NODE:
            res = (const xmlChar *) "pi";
            break;
        case XML_COMMENT_NODE:
            res = (const xmlChar *) "comment";
            break;
        case XML_DOCUMENT_NODE:
            res = (const xmlChar *) "document_xml";
            break;
        case XML_DOCUMENT_TYPE_NODE:
            res = (const xmlChar *) "doctype";
            break;
        case XML_DOCUMENT_FRAG_NODE:
            res = (const xmlChar *) "fragment";
            break;
        case XML_NOTATION_NODE:
            res = (const xmlChar *) "notation";
            break;
        case XML_HTML_DOCUMENT_NODE:
            res = (const xmlChar *) "document_html";
            break;
        case XML_DTD_NODE:
            res = (const xmlChar *) "dtd";
            break;
        case XML_ELEMENT_DECL:
            res = (const xmlChar *) "elem_decl";
            break;
        case XML_ATTRIBUTE_DECL:
            res = (const xmlChar *) "attribute_decl";
            break;
        case XML_ENTITY_DECL:
            res = (const xmlChar *) "entity_decl";
            break;
        case XML_NAMESPACE_DECL:
            res = (const xmlChar *) "namespace";
            break;
        case XML_XINCLUDE_START:
            res = (const xmlChar *) "xinclude_start";
            break;
        case XML_XINCLUDE_END:
            res = (const xmlChar *) "xinclude_end";
            break;
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
            res = (const xmlChar *) "document_docbook";
            break;
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
libxml_xmlNodeGetNsDefs(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *py_retval;
    xmlNsPtr c_retval;
    xmlNodePtr node;
    PyObject *pyobj_node;

    if (!PyArg_ParseTuple
        (args, (char *) "O:xmlNodeGetNsDefs", &pyobj_node))
        return (NULL);
    node = (xmlNodePtr) PyxmlNode_Get(pyobj_node);

    if ((node == NULL) || (node->type != XML_ELEMENT_NODE)) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    c_retval = node->nsDef;
    py_retval = libxml_xmlNsPtrWrap((xmlNsPtr) c_retval);
    return (py_retval);
}

PyObject *
libxml_xmlNodeGetNs(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *py_retval;
    xmlNsPtr c_retval;
    xmlNodePtr node;
    PyObject *pyobj_node;

    if (!PyArg_ParseTuple(args, (char *) "O:xmlNodeGetNs", &pyobj_node))
        return (NULL);
    node = (xmlNodePtr) PyxmlNode_Get(pyobj_node);

    if ((node == NULL) || (node->type != XML_ELEMENT_NODE)) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    c_retval = node->ns;
    py_retval = libxml_xmlNsPtrWrap((xmlNsPtr) c_retval);
    return (py_retval);
}

/************************************************************************
 *									*
 *			Serialization front-end				*
 *									*
 ************************************************************************/

static PyObject *
libxml_serializeNode(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *py_retval = NULL;
    xmlChar *c_retval;
    PyObject *pyobj_node;
    xmlNodePtr node;
    xmlDocPtr doc;
    const char *encoding;
    int format;
    int len;

    if (!PyArg_ParseTuple(args, (char *) "Ozi:serializeNode", &pyobj_node,
                          &encoding, &format))
        return (NULL);
    node = (xmlNodePtr) PyxmlNode_Get(pyobj_node);

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    if (node->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr) node;
        xmlDocDumpFormatMemoryEnc(doc, &c_retval, &len,
                                  (const char *) encoding, format);
        py_retval = libxml_charPtrWrap((char *) c_retval);
    } else if (node->type == XML_HTML_DOCUMENT_NODE) {
        xmlOutputBufferPtr buf;
        xmlCharEncodingHandlerPtr handler = NULL;

        doc = (xmlDocPtr) node;
        if (encoding != NULL)
            htmlSetMetaEncoding(doc, (const xmlChar *) encoding);
        encoding = (const char *) htmlGetMetaEncoding(doc);

        if (encoding != NULL) {
            handler = xmlFindCharEncodingHandler(encoding);
            if (handler == NULL) {
                Py_INCREF(Py_None);
                return (Py_None);
            }
        }

        /*
         * Fallback to HTML or ASCII when the encoding is unspecified
         */
        if (handler == NULL)
            handler = xmlFindCharEncodingHandler("HTML");
        if (handler == NULL)
            handler = xmlFindCharEncodingHandler("ascii");

        buf = xmlAllocOutputBuffer(handler);
        if (buf == NULL) {
            Py_INCREF(Py_None);
            return (Py_None);
        }
        htmlDocContentDumpFormatOutput(buf, doc, encoding, format);
        xmlOutputBufferFlush(buf);
        if (buf->conv != NULL) {
            len = buf->conv->use;
            c_retval = buf->conv->content;
            buf->conv->content = NULL;
        } else {
            len = buf->buffer->use;
            c_retval = buf->buffer->content;
            buf->buffer->content = NULL;
        }
        (void) xmlOutputBufferClose(buf);
        py_retval = libxml_charPtrWrap((char *) c_retval);
    } else {
        doc = node->doc;
        if (doc->type == XML_DOCUMENT_NODE) {
            xmlOutputBufferPtr buf;
            xmlCharEncodingHandlerPtr handler = NULL;

            if (encoding != NULL) {
                handler = xmlFindCharEncodingHandler(encoding);
                if (handler == NULL) {
                    Py_INCREF(Py_None);
                    return (Py_None);
                }
            }

            buf = xmlAllocOutputBuffer(handler);
            if (buf == NULL) {
                Py_INCREF(Py_None);
                return (Py_None);
            }
            xmlNodeDumpOutput(buf, doc, node, 0, format, encoding);
            xmlOutputBufferFlush(buf);
            if (buf->conv != NULL) {
                len = buf->conv->use;
                c_retval = buf->conv->content;
                buf->conv->content = NULL;
            } else {
                len = buf->buffer->use;
                c_retval = buf->buffer->content;
                buf->buffer->content = NULL;
            }
            (void) xmlOutputBufferClose(buf);
            py_retval = libxml_charPtrWrap((char *) c_retval);
        } else if (doc->type == XML_HTML_DOCUMENT_NODE) {
            xmlOutputBufferPtr buf;
            xmlCharEncodingHandlerPtr handler = NULL;

            if (encoding != NULL)
                htmlSetMetaEncoding(doc, (const xmlChar *) encoding);
            encoding = (const char *) htmlGetMetaEncoding(doc);
            if (encoding != NULL) {
                handler = xmlFindCharEncodingHandler(encoding);
                if (handler == NULL) {
                    Py_INCREF(Py_None);
                    return (Py_None);
                }
            }

            /*
             * Fallback to HTML or ASCII when the encoding is unspecified
             */
            if (handler == NULL)
                handler = xmlFindCharEncodingHandler("HTML");
            if (handler == NULL)
                handler = xmlFindCharEncodingHandler("ascii");

            buf = xmlAllocOutputBuffer(handler);
            if (buf == NULL) {
                Py_INCREF(Py_None);
                return (Py_None);
            }
            htmlNodeDumpFormatOutput(buf, doc, node, encoding, format);
            xmlOutputBufferFlush(buf);
            if (buf->conv != NULL) {
                len = buf->conv->use;
                c_retval = buf->conv->content;
                buf->conv->content = NULL;
            } else {
                len = buf->buffer->use;
                c_retval = buf->buffer->content;
                buf->buffer->content = NULL;
            }
            (void) xmlOutputBufferClose(buf);
            py_retval = libxml_charPtrWrap((char *) c_retval);
        } else {
            Py_INCREF(Py_None);
            return (Py_None);
        }
    }
    return (py_retval);
}

static PyObject *
libxml_saveNodeTo(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *py_file = NULL;
    FILE *output;
    PyObject *pyobj_node;
    xmlNodePtr node;
    xmlDocPtr doc;
    const char *encoding;
    int format;
    int len;
    xmlOutputBufferPtr buf;
    xmlCharEncodingHandlerPtr handler = NULL;

    if (!PyArg_ParseTuple(args, (char *) "OOzi:serializeNode", &pyobj_node,
                          &py_file, &encoding, &format))
        return (NULL);
    node = (xmlNodePtr) PyxmlNode_Get(pyobj_node);

    if (node == NULL) {
        return (PyInt_FromLong((long) -1));
    }
    if ((py_file == NULL) || (!(PyFile_Check(py_file)))) {
        return (PyInt_FromLong((long) -1));
    }
    output = PyFile_AsFile(py_file);
    if (output == NULL) {
        return (PyInt_FromLong((long) -1));
    }

    if (node->type == XML_DOCUMENT_NODE) {
        doc = (xmlDocPtr) node;
    } else if (node->type == XML_HTML_DOCUMENT_NODE) {
        doc = (xmlDocPtr) node;
    } else {
        doc = node->doc;
    }
    if (doc->type == XML_HTML_DOCUMENT_NODE) {
        if (encoding == NULL)
            encoding = (const char *) htmlGetMetaEncoding(doc);
    }
    if (encoding != NULL) {
        handler = xmlFindCharEncodingHandler(encoding);
        if (handler == NULL) {
            return (PyInt_FromLong((long) -1));
        }
    }
    if (doc->type == XML_HTML_DOCUMENT_NODE) {
        if (handler == NULL)
            handler = xmlFindCharEncodingHandler("HTML");
        if (handler == NULL)
            handler = xmlFindCharEncodingHandler("ascii");
    }

    buf = xmlOutputBufferCreateFile(output, handler);
    if (node->type == XML_DOCUMENT_NODE) {
        len = xmlSaveFormatFileTo(buf, doc, encoding, format);
    } else if (node->type == XML_HTML_DOCUMENT_NODE) {
        htmlDocContentDumpFormatOutput(buf, doc, encoding, format);
        len = xmlOutputBufferClose(buf);
    } else if (doc->type == XML_HTML_DOCUMENT_NODE) {
        htmlNodeDumpFormatOutput(buf, doc, node, encoding, format);
        len = xmlOutputBufferClose(buf);
    } else {
        xmlNodeDumpOutput(buf, doc, node, 0, format, encoding);
        len = xmlOutputBufferClose(buf);
    }
    return (PyInt_FromLong((long) len));
}

/************************************************************************
 *									*
 *			Extra stuff					*
 *									*
 ************************************************************************/
PyObject *
libxml_xmlNewNode(ATTRIBUTE_UNUSED PyObject * self, PyObject * args)
{
    PyObject *py_retval;
    xmlChar *name;
    xmlNodePtr node;

    if (!PyArg_ParseTuple(args, (char *) "s:xmlNewNode", &name))
        return (NULL);
    node = (xmlNodePtr) xmlNewNode(NULL, name);
    printf("NewNode: %s : %p\n", name, (void *) node);

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    py_retval = libxml_xmlNodePtrWrap(node);
    return (py_retval);
}

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libxmlMethods[] = {
#include "libxml2-export.c"
    {(char *) "name", libxml_name, METH_VARARGS, NULL},
    {(char *) "children", libxml_children, METH_VARARGS, NULL},
    {(char *) "properties", libxml_properties, METH_VARARGS, NULL},
    {(char *) "last", libxml_last, METH_VARARGS, NULL},
    {(char *) "prev", libxml_prev, METH_VARARGS, NULL},
    {(char *) "next", libxml_next, METH_VARARGS, NULL},
    {(char *) "parent", libxml_parent, METH_VARARGS, NULL},
    {(char *) "type", libxml_type, METH_VARARGS, NULL},
    {(char *) "doc", libxml_doc, METH_VARARGS, NULL},
    {(char *) "xmlNewNode", libxml_xmlNewNode, METH_VARARGS, NULL},
    {(char *) "serializeNode", libxml_serializeNode, METH_VARARGS, NULL},
    {(char *) "saveNodeTo", libxml_saveNodeTo, METH_VARARGS, NULL},
    {(char *) "outputBufferCreate", libxml_xmlCreateOutputBuffer, METH_VARARGS, NULL},
    {(char *) "inputBufferCreate", libxml_xmlCreateInputBuffer, METH_VARARGS, NULL},
    {(char *) "setEntityLoader", libxml_xmlSetEntityLoader, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

#ifdef MERGED_MODULES
extern void initlibxsltmod(void);
#endif

void
initlibxml2mod(void)
{
    static int initialized = 0;
    PyObject *m;

    if (initialized != 0)
        return;
    xmlRegisterDefaultOutputCallbacks();
    xmlRegisterDefaultInputCallbacks();
    m = Py_InitModule((char *) "libxml2mod", libxmlMethods);
    initialized = 1;
    libxml_xmlErrorInitialize();

#ifdef MERGED_MODULES
    initlibxsltmod();
#endif
}
