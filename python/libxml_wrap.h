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

PyObject * libxml_intWrap(int val);
PyObject * libxml_xmlCharPtrWrap(const xmlChar *str);
PyObject * libxml_charPtrWrap(const char *str);
PyObject * libxml_xmlDocPtrWrap(xmlDocPtr doc);
PyObject * libxml_xmlNodePtrWrap(xmlNodePtr node);
PyObject * libxml_xmlAttrPtrWrap(xmlAttrPtr attr);
