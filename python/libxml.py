import libxml2mod

#
# Errors raised by the wrappers when some tree handling failed.
#
class treeError:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class parserError:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class uriError:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class xpathError:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class ioWrapper:
    def __init__(self, _obj):
        self.__io = _obj
        self._o = None

    def io_close(self):
        if self.__io == None:
	    return(-1)
	self.__io.close()
	self.__io = None
	return(0)

    def io_flush(self):
        if self.__io == None:
	    return(-1)
	self.__io.flush()
	return(0)

    def io_read(self, len = -1):
        if self.__io == None:
	    return(-1)
        if len < 0:
	    return(self.__io.read())
	return(self.__io.read(len))

    def io_write(self, str, len = -1):
        if self.__io == None:
	    return(-1)
        if len < 0:
	    return(self.__io.write(str))
	return(self.__io.write(str, len))

class ioReadWrapper(ioWrapper):
    def __init__(self, _obj, enc = ""):
        ioWrapper.__init__(self, _obj)
        self._o = libxml2mod.xmlCreateInputBuffer(self, enc)

    def __del__(self):
        print "__del__"
        self.io_close()
        if self._o != None:
            libxml2mod.xmlFreeParserInputBuffer(self._o)
        self._o = None

    def close(self):
        self.io_close()
        if self._o != None:
            libxml2mod.xmlFreeParserInputBuffer(self._o)
        self._o = None

class ioWriteWrapper(ioWrapper):
    def __init__(self, _obj, enc = ""):
        ioWrapper.__init__(self, _obj)
        self._o = libxml2mod.xmlCreateOutputBuffer(self, enc)

    def __del__(self):
        print "__del__"
        self.io_close()
        if self._o != None:
            libxml2mod.xmlOutputBufferClose(self._o)
        self._o = None

    def close(self):
        self.io_close()
        if self._o != None:
            libxml2mod.xmlOutputBufferClose(self._o)
        self._o = None

#
# Example of a class to handle SAX events
#
class SAXCallback:
    """Base class for SAX handlers"""
    def startDocument(self):
        """called at the start of the document"""
        pass

    def endDocument(self):
        """called at the end of the document"""
        pass

    def startElement(self, tag, attrs):
        """called at the start of every element, tag is the name of
	   the element, attrs is a dictionary of the element's attributes"""
        pass

    def endElement(self, tag):
        """called at the start of every element, tag is the name of
	   the element"""
        pass

    def characters(self, data):
        """called when character data have been read, data is the string
	   containing the data, multiple consecutive characters() callback
	   are possible."""
        pass

    def cdataBlock(self, data):
        """called when CDATA section have been read, data is the string
	   containing the data, multiple consecutive cdataBlock() callback
	   are possible."""
        pass

    def reference(self, name):
        """called when an entity reference has been found"""
        pass

    def ignorableWhitespace(self, data):
        """called when potentially ignorable white spaces have been found"""
        pass

    def processingInstruction(self, target, data):
        """called when a PI has been found, target contains the PI name and
	   data is the associated data in the PI"""
        pass

    def comment(self, content):
        """called when a comment has been found, content contains the comment"""
        pass

    def externalSubset(self, name, externalID, systemID):
        """called when a DOCTYPE declaration has been found, name is the
	   DTD name and externalID, systemID are the DTD public and system
	   identifier for that DTd if available"""
        pass

    def internalSubset(self, name, externalID, systemID):
        """called when a DOCTYPE declaration has been found, name is the
	   DTD name and externalID, systemID are the DTD public and system
	   identifier for that DTD if available"""
        pass

    def entityDecl(self, name, type, externalID, systemID, content):
        """called when an ENTITY declaration has been found, name is the
	   entity name and externalID, systemID are the entity public and
	   system identifier for that entity if available, type indicates
	   the entity type, and content reports it's string content"""
        pass

    def notationDecl(self, name, externalID, systemID):
        """called when an NOTATION declaration has been found, name is the
	   notation name and externalID, systemID are the notation public and
	   system identifier for that notation if available"""
        pass

    def attributeDecl(self, elem, name, type, defi, defaultValue, nameList):
        """called when an ATTRIBUTE definition has been found"""
	pass

    def elementDecl(self, name, type, content):
        """called when an ELEMENT definition has been found"""
	pass

    def entityDecl(self, name, publicId, systemID, notationName):
        """called when an unparsed ENTITY declaration has been found,
	   name is the entity name and publicId,, systemID are the entity
	   public and system identifier for that entity if available,
	   and notationName indicate the associated NOTATION"""
        pass

    def warning(self, msg):
        print msg

    def error(self, msg):
        raise parserError(msg)

    def fatalError(self, msg):
        raise parserError(msg)

#
# This class is the ancestor of all the Node classes. It provides
# the basic functionalities shared by all nodes (and handle
# gracefylly the exception), like name, navigation in the tree,
# doc reference, content access and serializing to a string or URI
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
		if self.type == "document_xml" or self.type == "document_html":
		    return xmlDoc(_obj=self._o)
		else:
		    return None
            return xmlDoc(_obj=ret)
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
        return xmlDoc(_obj=ret)
    def free(self):
        libxml2mod.freeDoc(self._o)

    #
    # Serialization routines, the optional arguments have the following
    # meaning:
    #     encoding: string to ask saving in a specific encoding
    #     format: if 1 the serializer is asked to indent the output
    #
    def serialize(self, encoding = None, format = 0):
        return libxml2mod.serializeNode(self._o, encoding, format)
    def saveTo(self, file, encoding = None, format = 0):
        return libxml2mod.saveNodeTo(self._o, file, encoding, format)
            
    #
    # Selecting nodes using XPath, a bit slow because the context
    # is allocated/freed every time but convenient.
    #
    def xpathEval(self, expr):
	doc = self.doc
	if doc == None:
	    return None
	ctxt = doc.xpathNewContext()
	ctxt.setContextNode(self)
	res = ctxt.xpathEval(expr)
	ctxt.xpathFreeContext()
	return res
	
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

