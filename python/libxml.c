#include <Python.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libxml_wrap.h"
#include "libxml2-py.h"

/* #define DEBUG */

/************************************************************************
 *									*
 *			Per type specific glue				*
 *									*
 ************************************************************************/
PyObject *
libxml_intWrap(int val) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_intWrap: val = %d\n", val);
#endif
    ret = PyInt_FromLong((long) val);
    return(ret);
}

PyObject *
libxml_doubleWrap(double val) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_doubleWrap: val = %f\n", val);
#endif
    ret = PyFloat_FromDouble((double) val);
    return(ret);
}

PyObject *
libxml_charPtrWrap(char *str) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlcharPtrWrap: str = %s\n", str);
#endif
    if (str == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    /* TODO: look at deallocation */
    ret = PyString_FromString(str);
    xmlFree(str);
    return(ret);
}

PyObject *
libxml_xmlCharPtrWrap(xmlChar *str) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlCharPtrWrap: str = %s\n", str);
#endif
    if (str == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    /* TODO: look at deallocation */
    ret = PyString_FromString(str);
    xmlFree(str);
    return(ret);
}

PyObject *
libxml_constcharPtrWrap(const char *str) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlcharPtrWrap: str = %s\n", str);
#endif
    if (str == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    /* TODO: look at deallocation */
    ret = PyString_FromString(str);
    return(ret);
}

PyObject *
libxml_constxmlCharPtrWrap(const xmlChar *str) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlCharPtrWrap: str = %s\n", str);
#endif
    if (str == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    /* TODO: look at deallocation */
    ret = PyString_FromString(str);
    return(ret);
}

PyObject *
libxml_xmlDocPtrWrap(xmlDocPtr doc) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlDocPtrWrap: doc = %p\n", doc);
#endif
    if (doc == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    /* TODO: look at deallocation */
    ret = PyCObject_FromVoidPtrAndDesc((void *) doc, "xmlDocPtr", NULL);
    return(ret);
}

PyObject *
libxml_xmlNodePtrWrap(xmlNodePtr node) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlNodePtrWrap: node = %p\n", node);
#endif
    if (node == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) node, "xmlNodePtr", NULL);
    return(ret);
}

PyObject *
libxml_xmlNsPtrWrap(xmlNsPtr ns) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlNsPtrWrap: node = %p\n", ns);
#endif
    if (ns == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) ns, "xmlNsPtr", NULL);
    return(ret);
}

PyObject *
libxml_xmlAttrPtrWrap(xmlAttrPtr attr) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlAttrNodePtrWrap: attr = %p\n", attr);
#endif
    if (attr == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) attr, "xmlAttrPtr", NULL);
    return(ret);
}

PyObject *
libxml_xmlAttributePtrWrap(xmlAttributePtr attr) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlAttributePtrWrap: attr = %p\n", attr);
#endif
    if (attr == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) attr, "xmlAttributePtr", NULL);
    return(ret);
}

PyObject *
libxml_xmlElementPtrWrap(xmlElementPtr elem) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlElementNodePtrWrap: elem = %p\n", elem);
#endif
    if (elem == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) elem, "xmlElementPtr", NULL);
    return(ret);
}

PyObject *
libxml_xmlXPathContextPtrWrap(xmlXPathContextPtr ctxt) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlXPathContextPtrWrap: ctxt = %p\n", ctxt);
#endif
    if (ctxt == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) ctxt, "xmlXPathContextPtr",
	                               NULL);
    return(ret);
}

PyObject *
libxml_xmlXPathObjectPtrWrap(xmlXPathObjectPtr obj) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlXPathObjectPtrWrap: ctxt = %p\n", obj);
#endif
    if (obj == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    switch(obj->type) {
        case XPATH_XSLT_TREE:
	    /* TODO !!!! Allocation problems */
        case XPATH_NODESET:
	    if ((obj->nodesetval == NULL) || (obj->nodesetval->nodeNr == 0))
		ret = PyList_New(0);
	    else {
		int i;
		xmlNodePtr node;

		ret = PyList_New(obj->nodesetval->nodeNr);
		for (i = 0;i < obj->nodesetval->nodeNr;i++) {
		    node = obj->nodesetval->nodeTab[i];
		    /* TODO: try to cast directly to the proper node type */
		    PyList_SetItem(ret, i, libxml_xmlNodePtrWrap(node));
		}
	    }
	    break;
        case XPATH_BOOLEAN:
	    ret = PyInt_FromLong((long) obj->boolval);
	    break;
        case XPATH_NUMBER:
	    ret = PyFloat_FromDouble(obj->floatval);
	    break;
        case XPATH_STRING:
	    ret = PyString_FromString(obj->stringval);
	    break;
        case XPATH_POINT:
        case XPATH_RANGE:
        case XPATH_LOCATIONSET:
	default:
	    printf("Unable to convert XPath object type %d\n", obj->type);
	    Py_INCREF(Py_None);
	    ret = Py_None;
    }
    xmlXPathFreeObject(obj);
    return(ret);
}

/************************************************************************
 *									*
 *		The PyxmlNode type					*
 *									*
 ************************************************************************/
static void
PyxmlNode_dealloc(PyxmlNode_Object * self)
{
    printf("TODO PyxmlNode_dealloc\n");
    PyMem_DEL(self);
}

static int
PyxmlNode_compare(PyxmlNode_Object * self, PyxmlNode_Object * v)
{
    if (self->obj == v->obj)
        return 0;
    if (self->obj > v->obj)
        return -1;
    return 1;
}

static long
PyxmlNode_hash(PyxmlNode_Object * self)
{
    return (long) self->obj;
}

static PyObject *
PyxmlNode_repr(PyxmlNode_Object * self)
{
    char buf[100];

    sprintf(buf, "<xmlNode of type %d at %lx>",
            PyxmlNode_Get(self)->type,
            (long) PyxmlNode_Get(self));
    return PyString_FromString(buf);
}

static char PyxmlNode_Type__doc__[] = "This is the type of libxml Nodes";

static PyTypeObject PyxmlNode_Type = {
    PyObject_HEAD_INIT(&PyType_Type)
        0,                      /*ob_size */
    "xmlNode",                  /*tp_name */
    sizeof(PyxmlNode_Object),   /*tp_basicsize */
    0,                          /*tp_itemsize */
    (destructor) PyxmlNode_dealloc,/*tp_dealloc */
    (printfunc) 0,              /*tp_print */
    (getattrfunc) 0,            /*tp_getattr */
    (setattrfunc) 0,            /*tp_setattr */
    (cmpfunc) PyxmlNode_compare,/*tp_compare */
    (reprfunc) PyxmlNode_repr,  /*tp_repr */
    0,                          /*tp_as_number */
    0,                          /*tp_as_sequence */
    0,                          /*tp_as_mapping */
    (hashfunc) PyxmlNode_hash,  /*tp_hash */
    (ternaryfunc) 0,            /*tp_call */
    (reprfunc) 0,               /*tp_str */
    0L, 0L, 0L, 0L,
    PyxmlNode_Type__doc__
};

/************************************************************************
 *									*
 *		The PyxmlXPathContext type					*
 *									*
 ************************************************************************/
static void
PyxmlXPathContext_dealloc(PyxmlXPathContext_Object * self)
{
    printf("TODO PyxmlXPathContext_dealloc\n");
    PyMem_DEL(self);
}

static int
PyxmlXPathContext_compare(PyxmlXPathContext_Object * self, PyxmlXPathContext_Object * v)
{
    if (self->obj == v->obj)
        return 0;
    if (self->obj > v->obj)
        return -1;
    return 1;
}

static long
PyxmlXPathContext_hash(PyxmlXPathContext_Object * self)
{
    return (long) self->obj;
}

static PyObject *
PyxmlXPathContext_repr(PyxmlXPathContext_Object * self)
{
    char buf[100];

    sprintf(buf, "<xmlXPathContext at %lx>",
            (long) PyxmlXPathContext_Get(self));
    return PyString_FromString(buf);
}

static char PyxmlXPathContext_Type__doc__[] = "This is the type of XPath evaluation contexts";

PyTypeObject PyxmlXPathContext_Type = {
    PyObject_HEAD_INIT(&PyType_Type)
        0,                      /*ob_size */
    "xmlXPathContext",                  /*tp_name */
    sizeof(PyxmlXPathContext_Object),   /*tp_basicsize */
    0,                          /*tp_itemsize */
    (destructor) PyxmlXPathContext_dealloc,/*tp_dealloc */
    (printfunc) 0,              /*tp_print */
    (getattrfunc) 0,            /*tp_getattr */
    (setattrfunc) 0,            /*tp_setattr */
    (cmpfunc) PyxmlXPathContext_compare,/*tp_compare */
    (reprfunc) PyxmlXPathContext_repr,  /*tp_repr */
    0,                          /*tp_as_number */
    0,                          /*tp_as_sequence */
    0,                          /*tp_as_mapping */
    (hashfunc) PyxmlXPathContext_hash,  /*tp_hash */
    (ternaryfunc) 0,            /*tp_call */
    (reprfunc) 0,               /*tp_str */
    0L, 0L, 0L, 0L,
    PyxmlXPathContext_Type__doc__
};

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
    { "doc", libxml_doc, METH_VARARGS }
};

void init_libxml(void) {
    PyObject *m, *d;
    m = Py_InitModule("_libxml", libxmlMethods);
    d = PyModule_GetDict(m);
    PyDict_SetItemString(d, "xmlNodeType", (PyObject *)&PyxmlNode_Type);
    PyDict_SetItemString(d, "xmlXPathContextType", (PyObject *)&PyxmlXPathContext_Type);
}

