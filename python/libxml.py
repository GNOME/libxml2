import libxml2mod

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
	    ret = libxml2mod.parent(self._o)
	    if ret == None:
	        return None
	    return xmlNode(_obj=ret)
        elif attr == "properties":
	    ret = libxml2mod.properties(self._o)
	    if ret == None:
	        return None
	    return xmlAttr(_obj=ret)
	elif attr == "children":
	    ret = libxml2mod.children(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "last":
	    ret = libxml2mod.last(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "next":
	    ret = libxml2mod.next(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "prev":
	    ret = libxml2mod.prev(self._o)
	    if ret == None:
		return None
	    return xmlNode(_obj=ret)
	elif attr == "content":
	    return libxml2mod.xmlNodeGetContent(self._o)
	elif attr == "name":
	    return libxml2mod.name(self._o)
	elif attr == "type":
	    return libxml2mod.type(self._o)
	elif attr == "doc":
	    ret = libxml2mod.doc(self._o)
	    if ret == None:
		return None
	    return xmlDoc(_doc=ret)
	raise AttributeError,attr

	#
	# Those are common attributes to nearly all type of nodes
	#
    def get_parent(self):
	ret = libxml2mod.parent(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_children(self):
	ret = libxml2mod.children(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_last(self):
	ret = libxml2mod.last(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_next(self):
	ret = libxml2mod.next(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_properties(self):
	ret = libxml2mod.properties(self._o)
	if ret == None:
	    return None
	return xmlAttr(_obj=ret)
    def get_doc(self):
	ret = libxml2mod.doc(self._o)
	if ret == None:
	    return None
	return xmlDoc(_obj=ret)
    def get_prev(self):
	ret = libxml2mod.prev(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_content(self):
	return libxml2mod.xmlNodeGetContent(self._o)
    def getContent(self):
	return libxml2mod.xmlNodeGetContent(self._o)
    def get_name(self):
	return libxml2mod.name(self._o)
    def get_type(self):
	return libxml2mod.type(self._o)
    def get_doc(self):
	ret = libxml2mod.doc(self._o)
	if ret == None:
	    return None
	return xmlDoc(_doc=ret)
    def free(self):
        libxml2mod.freeDoc(self._o)
	    
#
# converters to present a nicer view of the XPath returns
#
def nodeWrap(o):
    # TODO try to cast to the most appropriate node class
    name = libxml2mod.name(o)
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
    ret = libxml2mod.xmlRegisterXPathFunction(ctxt, name, ns_uri, f)

#
# Everything below this point is automatically generated
#

