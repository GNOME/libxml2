/*
 * types.c: converter functions between the internal representation
 *          and the Python objects
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */
#include "libxml_wrap.h"

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
libxml_longWrap(long val) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_longWrap: val = %ld\n", val);
#endif
    ret = PyInt_FromLong(val);
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
libxml_charPtrConstWrap(const char *str) {
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
libxml_xmlCharPtrConstWrap(const xmlChar *str) {
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
libxml_xmlURIPtrWrap(xmlURIPtr uri) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlURIPtrWrap: uri = %p\n", uri);
#endif
    if (uri == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) uri, "xmlURIPtr", NULL);
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
libxml_xmlXPathParserContextPtrWrap(xmlXPathParserContextPtr ctxt)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlXPathParserContextPtrWrap: ctxt = %p\n", ctxt);
#endif
    if (ctxt == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) ctxt,
                                       "xmlXPathParserContextPtr", NULL);
    return (ret);
}

PyObject *
libxml_xmlParserCtxtPtrWrap(xmlParserCtxtPtr ctxt) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlParserCtxtPtrWrap: ctxt = %p\n", ctxt);
#endif
    if (ctxt == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) ctxt, "xmlParserCtxtPtr",
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

xmlXPathObjectPtr
libxml_xmlXPathObjectPtrConvert(PyObject * obj) {
    xmlXPathObjectPtr ret;

#ifdef DEBUG
    printf("libxml_xmlXPathObjectPtrConvert: obj = %p\n", obj);
#endif
    if (obj == NULL) {
	return(NULL);
    }
    if PyFloat_Check(obj) {
	ret = xmlXPathNewFloat((double) PyFloat_AS_DOUBLE(obj));
    } else if PyString_Check(obj) {
	xmlChar *str;

	str = xmlStrndup((const xmlChar *)PyString_AS_STRING(obj),
		         PyString_GET_SIZE(obj));
	ret = xmlXPathWrapString(str);
    } else {
	printf("Unable to convert Python Object to XPath");
    }
    Py_DECREF(obj);
    return(ret);
}

PyObject *
libxml_xmlCatalogPtrWrap(xmlCatalogPtr catal) {
    PyObject *ret;

#ifdef DEBUG
    printf("libxml_xmlNodePtrWrap: catal = %p\n", catal);
#endif
    if (catal == NULL) {
	Py_INCREF(Py_None);
	return(Py_None);
    }
    ret = PyCObject_FromVoidPtrAndDesc((void *) catal, "xmlCatalogPtr", NULL);
    return(ret);
}


