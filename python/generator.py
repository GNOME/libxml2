#!/usr/bin/python -u
#
# generate python wrappers from the XML API description
#

functions = {}

import os
import string
import xmllib
try:
    import sgmlop
except ImportError:
    sgmlop = None # accelerator not available

debug = 0

if sgmlop:
    class FastParser:
	"""sgmlop based XML parser.  this is typically 15x faster
	   than SlowParser..."""

	def __init__(self, target):

	    # setup callbacks
	    self.finish_starttag = target.start
	    self.finish_endtag = target.end
	    self.handle_data = target.data

	    # activate parser
	    self.parser = sgmlop.XMLParser()
	    self.parser.register(self)
	    self.feed = self.parser.feed
	    self.entity = {
		"amp": "&", "gt": ">", "lt": "<",
		"apos": "'", "quot": '"'
		}

	def close(self):
	    try:
		self.parser.close()
	    finally:
		self.parser = self.feed = None # nuke circular reference

	def handle_entityref(self, entity):
	    # <string> entity
	    try:
		self.handle_data(self.entity[entity])
	    except KeyError:
		self.handle_data("&%s;" % entity)

else:
    FastParser = None


class SlowParser(xmllib.XMLParser):
    """slow but safe standard parser, based on the XML parser in
       Python's standard library."""

    def __init__(self, target):
	self.unknown_starttag = target.start
	self.handle_data = target.data
	self.unknown_endtag = target.end
	xmllib.XMLParser.__init__(self)

def getparser(target = None):
    # get the fastest available parser, and attach it to an
    # unmarshalling object.  return both objects.
    if target == None:
	target = docParser()
    if FastParser:
	return FastParser(target), target
    return SlowParser(target), target

class docParser:
    def __init__(self):
        self._methodname = None
	self._data = []
	self.in_function = 0

    def close(self):
        if debug:
	    print "close"

    def getmethodname(self):
        return self._methodname

    def data(self, text):
        if debug:
	    print "data %s" % text
        self._data.append(text)

    def start(self, tag, attrs):
        if debug:
	    print "start %s, %s" % (tag, attrs)
	if tag == 'function':
	    self._data = []
	    self.in_function = 1
	    self.function = None
	    self.function_args = []
	    self.function_descr = None
	    self.function_return = None
	    self.function_file = None
	    if attrs.has_key('name'):
	        self.function = attrs['name']
	    if attrs.has_key('file'):
	        self.function_file = attrs['file']
	elif tag == 'info':
	    self._data = []
	elif tag == 'arg':
	    if self.in_function == 1:
	        self.function_arg_name = None
	        self.function_arg_type = None
	        self.function_arg_info = None
		if attrs.has_key('name'):
		    self.function_arg_name = attrs['name']
		if attrs.has_key('type'):
		    self.function_arg_type = attrs['type']
		if attrs.has_key('info'):
		    self.function_arg_info = attrs['info']
	elif tag == 'return':
	    if self.in_function == 1:
	        self.function_return_type = None
	        self.function_return_info = None
		if attrs.has_key('type'):
		    self.function_return_type = attrs['type']
		if attrs.has_key('info'):
		    self.function_return_info = attrs['info']


    def end(self, tag):
        if debug:
	    print "end %s" % tag
	if tag == 'function':
	    if self.function != None:
	        function(self.function, self.function_descr,
		         self.function_return, self.function_args,
			 self.function_file)
		self.in_function = 0
	elif tag == 'arg':
	    if self.in_function == 1:
	        self.function_args.append([self.function_arg_name,
		                           self.function_arg_type,
					   self.function_arg_info])
	elif tag == 'return':
	    if self.in_function == 1:
	        self.function_return = [self.function_return_type,
		                        self.function_return_info]
	elif tag == 'info':
	    str = ''
	    for c in self._data:
		str = str + c
	    if self.in_function == 1:
	        self.function_descr = str
	        
	        
def function(name, desc, ret, args, file):
    global functions

    functions[name] = (desc, ret, args, file)


skipped_modules = {
    'xmlmemory': None,
    'DOCBparser': None,
    'SAX': None,
    'hash': None,
    'list': None,
    'threads': None,
}
skipped_types = {
    'int *': "usually a return type",
    'xmlSAXHandlerPtr': "not the proper interface for SAX",
    'htmlSAXHandlerPtr': "not the proper interface for SAX",
    'xmlParserCtxtPtr': "not the proper interface for the parser",
    'htmlParserCtxtPtr': "not the proper interface for the parser",
    'xmlRMutexPtr': "thread specific, skipped",
    'xmlMutexPtr': "thread specific, skipped",
    'xmlGlobalStatePtr': "thread specific, skipped",
    'xmlListPtr': "internal representation not suitable for python",
    'xmlBufferPtr': "internal representation not suitable for python",
    'FILE *': None,
}
py_types = {
    'void': (None, None, None, None),
    'int':  ('i', None, "int", "int"),
    'long':  ('i', None, "int", "int"),
    'double':  ('d', None, "double", "double"),
    'unsigned int':  ('i', None, "int", "int"),
    'xmlChar':  ('c', None, "int", "int"),
    'unsigned char *':  ('s', None, "charPtr", "char *"),
    'char *':  ('s', None, "charPtr", "char *"),
    'const char *':  ('s', None, "charPtr", "char *"),
    'xmlChar *':  ('s', None, "xmlCharPtr", "xmlChar *"),
    'const xmlChar *':  ('s', None, "xmlCharPtr", "xmlChar *"),
    'xmlNodePtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlNodePtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlNode *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlNode *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlDtdPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlDtdPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlDtd *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlDtd *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlAttrPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlAttrPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlAttr *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlAttr *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlEntityPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlEntityPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlEntity *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlEntity *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlElementPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlElementPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlElement *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlElement *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlAttributePtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlAttributePtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlAttribute *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlAttribute *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlNsPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlNsPtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlNs *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const xmlNs *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'xmlDocPtr':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'const xmlDocPtr':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'xmlDoc *':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'const xmlDoc *':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'htmlDocPtr':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'const htmlDocPtr':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'htmlDoc *':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'const htmlDoc *':  ('O', "xmlNode", "xmlDocPtr", "xmlDocPtr"),
    'htmlNodePtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const htmlNodePtr':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'htmlNode *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
    'const htmlNode *':  ('O', "xmlNode", "xmlNodePtr", "xmlNodePtr"),
}

unknown_types = {}

def print_function_wrapper(name, output, export, include):
    global py_types
    global unknown_types
    global functions
    global skipped_modules

    try:
	(desc, ret, args, file) = functions[name]
    except:
        print "failed to get function %s infos"
        return

    if skipped_modules.has_key(file):
        return 0

    c_call = "";
    format=""
    format_args=""
    c_args=""
    c_return=""
    c_convert=""
    for arg in args:
	# This should be correct
	if arg[1][0:6] == "const ":
	    arg[1] = arg[1][6:]
        c_args = c_args + "    %s %s;\n" % (arg[1], arg[0])
	if py_types.has_key(arg[1]):
	    (f, t, n, c) = py_types[arg[1]]
	    if f != None:
		format = format + f
	    if t != None:
	        format_args = format_args + ", &pyobj_%s" % (arg[0])
		c_args = c_args + "    PyObject *pyobj_%s;\n" % (arg[0])
		c_convert = c_convert + \
		   "    %s = (%s) Py%s_Get(pyobj_%s);\n" % (arg[0],
		   arg[1], t, arg[0]);
	    else:
		format_args = format_args + ", &%s" % (arg[0])
	    if c_call != "":
	        c_call = c_call + ", ";
	    c_call = c_call + "%s" % (arg[0])
	else:
	    if skipped_types.has_key(arg[1]):
	        return 0
	    if unknown_types.has_key(arg[1]):
	        lst = unknown_types[arg[1]]
		lst.append(name)
	    else:
	        unknown_types[arg[1]] = [name]
	    return -1
    if format != "":
        format = format + ":%s" % (name)

    if ret[0] == 'void':
        c_call = "\n    %s(%s);\n" % (name, c_call);
	ret_convert = "    Py_INCREF(Py_None);\n    return(Py_None);\n"
    elif py_types.has_key(ret[0]):
	(f, t, n, c) = py_types[ret[0]]
	c_return = "    %s c_retval;\n" % (ret[0])
        c_call = "\n    c_retval = %s(%s);\n" % (name, c_call);
	ret_convert = "    py_retval = libxml_%sWrap((%s) c_retval);\n" % (n,c)
	ret_convert = ret_convert + "    return(py_retval);\n"
    else:
	if skipped_types.has_key(ret[0]):
	    return 0
	if unknown_types.has_key(ret[0]):
	    lst = unknown_types[ret[0]]
	    lst.append(name)
	else:
	    unknown_types[ret[0]] = [name]
	return -1

    include.write("PyObject * ")
    include.write("libxml_%s(PyObject *self, PyObject *args);\n" % (name))
    export.write("    { \"%s\", libxml_%s, METH_VARARGS },\n" % (name, name))
    output.write("PyObject *\n")
    output.write("libxml_%s(PyObject *self, PyObject *args) {\n" % (name))
    if ret[0] != 'void':
	output.write("    PyObject *py_retval;\n")
    if c_return != "":
	output.write(c_return)
    if c_args != "":
	output.write(c_args)
    if format != "":
	output.write("\n    if (!PyArg_ParseTuple(args, \"%s\"%s))\n" %
	             (format, format_args))
	output.write("        return(NULL);\n")
    if c_convert != "":
	output.write(c_convert)
                                                              
    output.write(c_call)
    output.write(ret_convert)
    output.write("}\n\n")
    return 1

try:
    f = open("libxml2-api.xml")
    data = f.read()
    (parser, target)  = getparser()
    parser.feed(data)
    parser.close()
except IOError, msg:
    print file, ":", msg

print "Found %d functions in libxml2-api.xml" % (len(functions.keys()))
nb_wrap = 0
failed = 0
skipped = 0

include = open("libxml2-py.h", "w")
include.write("/* Generated */\n\n")
export = open("libxml2-export.c", "w")
export.write("/* Generated */\n\n")
wrapper = open("libxml2-py.c", "w")
wrapper.write("/* Generated */\n\n")
wrapper.write("#include <Python.h>\n")
wrapper.write("#include <libxml/tree.h>\n")
wrapper.write("#include \"libxml_wrap.h\"\n")
wrapper.write("#include \"libxml2-py.h\"\n\n")
for function in functions.keys():
    ret = print_function_wrapper(function, wrapper, export, include)
    if ret < 0:
        failed = failed + 1
	del functions[function]
    if ret == 0:
        skipped = skipped + 1
	del functions[function]
    if ret == 1:
        nb_wrap = nb_wrap + 1
include.close()
export.close()
wrapper.close()

print "Generated %d wrapper functions, %d failed, %d skipped\n" % (nb_wrap,
							  failed, skipped);
print "Missing type converters: %s" % (unknown_types.keys())

function_classes = {}
for name in functions.keys():
    (desc, ret, args, file) = functions[name]
    if name[0:3] == "xml" and len(args) >= 1 and args[0][1] == "xmlNodePtr":
        if name[0:11] == "xmlNodeList":
	    func = name[11:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (0, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
	elif name[0:7] == "xmlNode":
	    func = name[7:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (0, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
	elif name[0:6] == "xmlGet":
	    func = name[6:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (0, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
	else:
	    func = name[3:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (0, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
    elif name[0:3] == "xml" and len(args) >= 2 and args[1][1] == "xmlNodePtr":
        if name[0:11] == "xmlNodeList":
	    func = name[11:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (1, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
	elif name[0:7] == "xmlNode":
	    func = name[7:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (1, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
	elif name[0:6] == "xmlGet":
	    func = name[6:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (1, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
	else:
	    func = name[3:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (1, func, name, ret, args, file)
	    if function_classes.has_key('xmlNode'):
		function_classes['xmlNode'].append(info)
	    else:
		function_classes['xmlNode'] = [info]
    elif name[0:3] == "xml" and len(args) >= 1 and args[0][1] == "xmlDocPtr":
	if name[0:6] == "xmlDoc":
	    func = name[6:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (0, func, name, ret, args, file)
	    if function_classes.has_key('xmlDoc'):
		function_classes['xmlDoc'].append(info)
	    else:
		function_classes['xmlDoc'] = [info]
	elif name[0:6] == "xmlGet":
	    func = name[6:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (0, func, name, ret, args, file)
	    if function_classes.has_key('xmlDoc'):
		function_classes['xmlDoc'].append(info)
	    else:
		function_classes['xmlDoc'] = [info]
	else:
	    func = name[3:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (0, func, name, ret, args, file)
	    if function_classes.has_key('xmlDoc'):
		function_classes['xmlDoc'].append(info)
	    else:
		function_classes['xmlDoc'] = [info]
    elif name[0:3] == "xml" and len(args) >= 2 and args[1][1] == "xmlDocPtr":
	if name[0:6] == "xmlDoc":
	    func = name[6:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (1, func, name, ret, args, file)
	    if function_classes.has_key('xmlDoc'):
		function_classes['xmlDoc'].append(info)
	    else:
		function_classes['xmlDoc'] = [info]
	elif name[0:6] == "xmlGet":
	    func = name[6:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (1, func, name, ret, args, file)
	    if function_classes.has_key('xmlDoc'):
		function_classes['xmlDoc'].append(info)
	    else:
		function_classes['xmlDoc'] = [info]
	else:
	    func = name[3:]
	    func = string.lower(func[0:1]) + func[1:]
	    info = (1, func, name, ret, args, file)
	    if function_classes.has_key('xmlDoc'):
		function_classes['xmlDoc'].append(info)
	    else:
		function_classes['xmlDoc'] = [info]
    elif ret[0] == "xmlDocPtr" or ret[0] == "xmlDtdPtr":
	func = name[3:]
	func = string.lower(func[0:1]) + func[1:]
	info = (0, func, name, ret, args, file)
	if function_classes.has_key('None'):
	    function_classes['None'].append(info)
	else:
	    function_classes['None'] = [info]
    else:
        print "unable to guess class for %s:%s" % (file,name)

classes_type = {
    "xmlNodePtr": ("._o", "xmlNode(_obj=%s)"),
    "xmlNode *": ("._o", "xmlNode(_obj=%s)"),
    "xmlDocPtr": ("._o", "xmlDoc(_obj=%s)"),
    "xmlDocPtr *": ("._o", "xmlDoc(_obj=%s)"),
    "xmlAttrPtr": ("._o", "xmlNode(_obj=%s)"),
    "xmlAttr *": ("._o", "xmlNode(_obj=%s)"),
    "xmlNsPtr": ("._o", "xmlNode(_obj=%s)"),
    "xmlNs *": ("._o", "xmlNode(_obj=%s)"),
    "xmlDtdPtr": ("._o", "xmlNode(_obj=%s)"),
    "xmlDtd *": ("._o", "xmlNode(_obj=%s)"),
    "xmlEntityPtr": ("._o", "xmlNode(_obj=%s)"),
    "xmlEntity *": ("._o", "xmlNode(_obj=%s)"),
}

classes = open("libxml2class.py", "w")

if function_classes.has_key("None"):
    for info in function_classes["None"]:
	(index, func, name, ret, args, file) = info
	classes.write("def %s(" % func)
	n = 0
	for arg in args:
	    if n != 0:
	        classes.write(", ")
	    classes.write("%s" % arg[0])
	    n = n + 1
	classes.write("):\n")
	if ret[0] != "void":
	    classes.write("    ret = ");
	else:
	    classes.write("    ");
	classes.write("_libxml.%s(" % name)
	n = 0
	for arg in args:
	    if n != 0:
		classes.write(", ");
	    classes.write("%s" % arg[0])
	    if classes_type.has_key(arg[1]):
		classes.write(classes_type[arg[1]][0])
	    n = n + 1
	classes.write(")\n");
	if ret[0] != "void":
	    if classes_type.has_key(ret[0]):
		classes.write("    if ret == None: return None\n");
		classes.write("    return ");
		classes.write(classes_type[ret[0]][1] % ("ret"));
		classes.write("\n");
	    else:
		classes.write("    return ret\n");
	classes.write("\n");

for classname in function_classes.keys():
    if classname == "None":
        pass
    else:
	classes.write("class %s(xmlCore):\n" % classname);
        if classname == "xmlNode":
	    classes.write("    def __init__(self, _obj=None):\n")
	    classes.write("        self._o = None\n")
	    classes.write("        xmlCore.__init__(self, _obj=_obj)\n\n")
        elif classname == "xmlDoc":
	    classes.write("    def __init__(self, _obj=None):\n")
	    classes.write("        self._o = None\n")
	    classes.write("        xmlCore.__init__(self, _obj=_obj)\n\n")
	else:
	    classes.write("    def __init__(self, _obj=None):\n")
	    classes.write("        if _obj != None:self._o = _obj;return\n")
	    classes.write("        self._o = None\n\n");
	for info in function_classes[classname]:
	    (index, func, name, ret, args, file) = info
	    classes.write("    def %s(self" % func)
	    n = 0
	    for arg in args:
	        if n != index:
		    classes.write(", %s" % arg[0])
		n = n + 1
	    classes.write("):\n")
	    if ret[0] != "void":
	        classes.write("        ret = ");
	    else:
	        classes.write("        ");
	    classes.write("_libxml.%s(" % name)
	    n = 0
	    for arg in args:
	        if n != 0:
		    classes.write(", ");
	        if n != index:
		    classes.write("%s" % arg[0])
		else:
		    classes.write("self");
		if classes_type.has_key(arg[1]):
		    classes.write(classes_type[arg[1]][0])
		n = n + 1
	    classes.write(")\n");
	    if ret[0] != "void":
	        if classes_type.has_key(ret[0]):
		    classes.write("        if ret == None: return None\n");
		    classes.write("        return ");
		    classes.write(classes_type[ret[0]][1] % ("ret"));
		    classes.write("\n");
		else:
		    classes.write("        return ret\n");
	    classes.write("\n");

classes.close()
