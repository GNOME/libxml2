import _libxml

#
# This class is the ancestor of all the Node classes. It provides
# the basic functionalities shared by all nodes (and handle
# gracefylly the exception), like name, navigation in the tree,
# doc reference and content access
#
class xmlCore:
    def __init__(self, _obj=None):
        if _obj != None: 
	    self._o = _obj;
	    return
	self._o = None

    def __getattr__(self, attr):
        if attr == "parent":
	    ret = _libxml.parent(self._o)
	    if ret == None:
	        return None
	    return xmlNode(_obj=ret)
        elif attr == "properties":
	    ret = _libxml.properties(self._o)
	    if ret == None:
	        return None
	    return xmlAttr(_obj=ret)
	elif attr == "children":
	    ret = _libxml.children(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "last":
	    ret = _libxml.last(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "next":
	    ret = _libxml.next(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "prev":
	    ret = _libxml.prev(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "content":
	    return self.content()
	elif attr == "name":
	    return _libxml.name(self._o)
	elif attr == "type":
	    return _libxml.type(self._o)
	elif attr == "doc":
	    ret = _libxml.doc(self._o)
	    if ret == None:
		return None
	    return xmlDoc(_doc=ret)
	raise AttributeError,attr

	#
	# Those are common attributes to nearly all type of nodes
	#
    def get_parent(self):
	ret = _libxml.parent(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_children(self):
	ret = _libxml.children(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_last(self):
	ret = _libxml.last(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_next(self):
	ret = _libxml.next(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_properties(self):
	ret = _libxml.properties(self._o)
	if ret == None:
	    return None
	return xmlAttr(_obj=ret)
    def get_doc(self):
	ret = _libxml.doc(self._o)
	if ret == None:
	    return None
	return xmlDoc(_obj=ret)
    def get_prev(self):
	ret = _libxml.prev(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_content(self):
	return _libxml.xmlNodeGetContent(self._o)
    def getContent(self):
	return _libxml.xmlNodeGetContent(self._o)
    def get_name(self):
	return _libxml.name(self._o)
    def get_type(self):
	return _libxml.type(self._o)
    def get_doc(self):
	ret = _libxml.doc(self._o)
	if ret == None:
	    return None
	return xmlDoc(_doc=ret)
    def free(self):
        _libxml.freeDoc(self._o)
	    
#
# converters to present a nicer view of the XPath returns
#
def nodeWrap(o):
    # TODO try to cast to the most appropriate node class
    name = _libxml.name(o)
    if name == "element" or name == "text":
        return xmlNode(_obj=o)
    if name == "attribute":
        return xmlAttr(_obj=o)
    if name[0:8] == "document":
        return xmlDoc(_obj=o)
    if name[0:8] == "namespace":
        return xmlNs(_obj=o)
    if name == "elem_decl":
        return xmlElement(_obj=o)
    if name == "attribute_decl":
        return xmlAtribute(_obj=o)
    if name == "entity_decl":
        return xmlEntity(_obj=o)
    if name == "dtd":
        return xmlAttr(_obj=o)
    return xmlNode(_obj=o)

def xpathObjectRet(o):
    if type(o) == type([]) or type(o) == type(()):
        ret = map(lambda x: nodeWrap(x), o)
	return ret
    return o

#
# register an XPath function
#
def registerXPathFunction(ctxt, name, ns_uri, f):
    ret = _libxml.xmlRegisterXPathFunction(ctxt, name, ns_uri, f)

#
# Everything below this point is automatically generated
#

