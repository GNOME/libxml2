#!/usr/bin/python -u
#
# generate python wrappers from the XML API description
#

functions = {}

import os
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
}
py_types = {
    'void': (None, None, None),
    'int':  ('i', None, "int"),
    'xmlChar':  ('c', None, "int"),
    'char *':  ('s', None, "charPtr"),
    'const char *':  ('s', None, "charPtr"),
    'xmlChar *':  ('s', None, "xmlCharPtr"),
    'const xmlChar *':  ('s', None, "xmlCharPtr"),
}

unknown_types = {}

def print_function_wrapper(name, output):
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
    for arg in args:
        c_args = c_args + "    %s %s;\n" % (arg[1], arg[0])
	if py_types.has_key(arg[1]):
	    (f, t, n) = py_types[arg[1]]
	    if f != None:
		format = format + f
	    if t != None:
	        format_args = format_args + ", &%s" % (t)
	    format_args = format_args + ", &%s" % (arg[0])
	    if c_call != "":
	        c_call = c_call + ", ";
	    c_call = c_call + "%s" % (arg[0])
	else:
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
	(f, t, n) = py_types[ret[0]]
	c_return = "    %s c_retval;\n" % (ret[0])
        c_call = "\n    c_retval = %s(%s);\n" % (name, c_call);
	ret_convert = "    py_retval = libxml_%sWrap(c_retval);\n    return(py_retval);\n" % (n)
    else:
	if unknown_types.has_key(ret[0]):
	    lst = unknown_types[ret[0]]
	    lst.append(name)
	else:
	    unknown_types[ret[0]] = [name]
	return -1

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

wrapper = open("libxml2-py.c", "w")
wrapper.write("/* Generated */\n\n")
wrapper.write("#include <Python.h>\n")
wrapper.write("#include <libxml/tree.h>\n")
wrapper.write("#include \"libxml_wrap.h\"\n")
wrapper.write("#include \"libxml2-py.h\"\n\n")
for function in functions.keys():
    ret = print_function_wrapper(function, wrapper)
    if ret < 0:
        failed = failed + 1
    if ret == 1:
        nb_wrap = nb_wrap + 1
    if ret == 0:
        skipped = skipped + 1
wrapper.close()

print "Generated %d wrapper functions, %d failed, %d skipped\n" % (nb_wrap,
							  failed, skipped);
print "Missing type converters: %s" % (unknown_types.keys())
