#include <Python.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/catalog.h>
#include <libxml/threads.h>
#include <libxml/nanoftp.h>
#include <libxml/nanohttp.h>
#include <libxml/uri.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/debugXML.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/xinclude.h>
#include <libxml/xpointer.h>

#define PyxmlNode_Get(v) (((PyxmlNode_Object *)(v))->obj)

typedef struct {
    PyObject_HEAD
    xmlNodePtr obj;
} PyxmlNode_Object;

#define PyxmlXPathContext_Get(v) (((PyxmlXPathContext_Object *)(v))->obj)
typedef struct {
    PyObject_HEAD
    xmlXPathContextPtr obj;
} PyxmlXPathContext_Object;

#define PyparserCtxt_Get(v) (((PyparserCtxt_Object *)(v))->obj)
typedef struct {
    PyObject_HEAD
    xmlParserCtxtPtr obj;
} PyparserCtxt_Object;

PyObject * libxml_intWrap(int val);
PyObject * libxml_xmlCharPtrWrap(xmlChar *str);
PyObject * libxml_constxmlCharPtrWrap(const xmlChar *str);
PyObject * libxml_charPtrWrap(char *str);
PyObject * libxml_constcharPtrWrap(const char *str);
PyObject * libxml_xmlDocPtrWrap(xmlDocPtr doc);
PyObject * libxml_xmlNodePtrWrap(xmlNodePtr node);
PyObject * libxml_xmlAttrPtrWrap(xmlAttrPtr attr);
PyObject * libxml_xmlNsPtrWrap(xmlNsPtr ns);
PyObject * libxml_xmlAttributePtrWrap(xmlAttributePtr ns);
PyObject * libxml_xmlElementPtrWrap(xmlElementPtr ns);
PyObject * libxml_doubleWrap(double val);
PyObject * libxml_xmlXPathContextPtrWrap(xmlXPathContextPtr ctxt);
PyObject * libxml_xmlParserCtxtPtrWrap(xmlParserCtxtPtr ctxt);
PyObject * libxml_xmlXPathObjectPtrWrap(xmlXPathObjectPtr obj);

xmlXPathObjectPtr libxml_xmlXPathObjectPtrConvert(PyObject * obj);
