import _libxml

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
	    return xmlNode(_obj=ret)
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
    def get_prev(self):
	ret = _libxml.prev(self._o)
	if ret == None:
	    return None
	return xmlNode(_obj=ret)
    def get_content(self):
	return self.content()
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
# Everything below this point is automatically generated
#
