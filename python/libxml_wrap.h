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

#define PyxmlNode_Get(v) (((PyxmlNode_Object *)(v))->obj)

typedef struct {
    PyObject_HEAD
    xmlNodePtr obj;
} PyxmlNode_Object;

PyObject * libxml_intWrap(int val);
PyObject * libxml_xmlCharPtrWrap(const xmlChar *str);
PyObject * libxml_charPtrWrap(const char *str);
PyObject * libxml_xmlDocPtrWrap(xmlDocPtr doc);
PyObject * libxml_xmlNodePtrWrap(xmlNodePtr node);
PyObject * libxml_xmlAttrPtrWrap(xmlAttrPtr attr);
PyObject * libxml_doubleWrap(double val);

