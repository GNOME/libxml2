#!/usr/bin/python -u
#
# tries to parse the output of gtk-doc declaration files and make
# an XML reusable description from them
#
import sys
import string

ids = {}

macros = {}
variables = {}
structs = {}
typedefs = {}
enums = {}
functions = {}
user_functions = {}
ret_types = {}
types = {}

sections = []
files = {}
identifiers_file = {}
identifiers_type = {}

##################################################################
#
#          Indexer to generate the word index
#
##################################################################
index = {}


def indexString(id, str):
    if str == None:
        return
    str = string.replace(str, "'", ' ')
    str = string.replace(str, '"', ' ')
    str = string.replace(str, "/", ' ')
    str = string.replace(str, '*', ' ')
    str = string.replace(str, "[", ' ')
    str = string.replace(str, "]", ' ')
    str = string.replace(str, "(", ' ')
    str = string.replace(str, ")", ' ')
    str = string.replace(str, "<", ' ')
    str = string.replace(str, '>', ' ')
    str = string.replace(str, "&", ' ')
    str = string.replace(str, '#', ' ')
    str = string.replace(str, ",", ' ')
    str = string.replace(str, '.', ' ')
    str = string.replace(str, ';', ' ')
    tokens = string.split(str)
    for token in tokens:
        try:
	    c = token[0]
	    if string.find(string.letters, c) < 0:
	        pass
	    elif len(token) < 3:
		pass
	    else:
		lower = string.lower(token)
		# TODO: generalize this a bit
		if lower == 'and' or lower == 'the':
		    pass
		elif index.has_key(token):
		    index[token].append(id)
		else:
		    index[token] = [id]
	except:
	    pass
       


##################################################################
#
#          Parsing: libxml-decl.txt
#
##################################################################
def mormalizeTypeSpaces(raw, function):
    global types

    tokens = string.split(raw)
    type = ''
    for token in tokens:
	if type != '':
	    type = type + ' ' + token
	else:
	    type = token
    if types.has_key(type):
        types[type].append(function)
    else:
        types[type] = [function]
    return type

def removeComments(raw):
    while string.find(raw, '/*') > 0:
        e = string.find(raw, '/*')
	tmp = raw[0:e]
	raw = raw[e:]
	e = string.find(raw, '*/')
	if e > 0:
	    raw = tmp + raw[e + 2:]
	else:
	    raw = tmp
    return raw

def extractArgs(raw, function):
    raw = removeComments(raw)
    raw = string.replace(raw, '\n', ' ')
    raw = string.replace(raw, '\r', ' ')
    list = string.split(raw, ",")
    ret = []
    for arg in list:
        i = len(arg)
	if i == 0:
	    continue
	i = i - 1
	c = arg[i]
	while string.find(string.letters, c) >= 0 or \
	      string.find(string.digits, c) >= 0 or c == '_':
	    i = i - 1
	    if i < 0:
	        break
	    c = arg[i]
	name = arg[i+1:]
        while string.find(string.whitespace, c) >= 0:
	    i = i - 1
	    if i < 0:
	        break
	    c = arg[i]
	type = mormalizeTypeSpaces(arg[0:i+1], function)
	if name == 'void' and type == '':
	    pass
	else:
	    ret.append([type, name, ''])

    return ret

def extractTypes(raw, function):
    global ret_types

    tokens = string.split(raw)
    type = ''
    for token in tokens:
	if type != '':
	    type = type + ' ' + token
	else:
	    type = token
    if ret_types.has_key(type):
        ret_types[type].append(function)
    else:
        ret_types[type] = [function]

    return type

def parseMacro():
    global input
    global macros
    global variables

    var = 1
    line = input.readline()[:-1]
    while line != "</MACRO>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	elif string.find(line, "#define") >= 0:
	    var = 0
	line = input.readline()[:-1]

    if var == 1:
	variables[name] = ['', ''] # type, info
	identifiers_type[name] = "variable"
    else:
	macros[name] = [[], ''] # args, info
	identifiers_type[name] = "macro"

def parseStruct():
    global input
    global structs

    line = input.readline()[:-1]
    while line != "</STRUCT>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    structs[name] = ''
    identifiers_type[name] = "struct"

def parseTypedef():
    global input
    global typedefs

    line = input.readline()[:-1]
    while line != "</TYPEDEF>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    typedefs[name] = ''
    identifiers_type[name] = "typedef"

def parseEnum():
    global input
    global enums

    line = input.readline()[:-1]
    consts = []
    while line != "</ENUM>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	elif string.find(line, 'enum') >= 0:
	    pass
	elif string.find(line, '{') >= 0:
	    pass
	elif string.find(line, '}') >= 0:
	    pass
	elif string.find(line, ';') >= 0:
	    pass
	else:
	    comment = string.find(line, '/*')
	    if comment >= 0:
	        line = line[0:comment]
	    decls = string.split(line, ",")
	    for decl in decls:
		val = string.split(decl, "=")[0]
		tokens = string.split(val)
		if len(tokens) >= 1:
		    token = tokens[0]
		    if string.find(string.letters, token[0]) >= 0:
			consts.append(token)
			identifiers_type[token] = "const"
	line = input.readline()[:-1]
        
    enums[name] = [consts, '']
    identifiers_type[name] = "enum"

def parseStaticFunction():
    global input
    global user_functions

    line = input.readline()[:-1]
    type = None
    signature = ""
    while line != "</USER_FUNCTION>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
        elif line[0:9] == "<RETURNS>" and line[-10:] == "</RETURNS>":
	    type = extractTypes(line[9:-10], name)
	else:
	    signature = signature + line
	line = input.readline()[:-1]

    args = extractArgs(signature, name)
    user_functions[name] = [[type, ''] , args, '']
    identifiers_type[name] = "functype"

def parseFunction():
    global input
    global functions

    line = input.readline()[:-1]
    type = None
    signature = ""
    while line != "</FUNCTION>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
        elif line[0:9] == "<RETURNS>" and line[-10:] == "</RETURNS>":
	    type = extractTypes(line[9:-10], name)
	else:
	    signature = signature + line
	line = input.readline()[:-1]

    args = extractArgs(signature, name)
    functions[name] = [[type, ''] , args, '']
    identifiers_type[name] = "function"

print "Parsing: libxml-decl.txt"
input = open('libxml-decl.txt')
while 1:
    line = input.readline()
    if not line:
        break
    line = line[:-1]
    if line == "<MACRO>":
        parseMacro()
    elif line == "<ENUM>":
        parseEnum()
    elif line == "<FUNCTION>":
        parseFunction()
    elif line == "<STRUCT>":
        parseStruct()
    elif line == "<TYPEDEF>":
        parseTypedef()
    elif line == "<USER_FUNCTION>":
        parseStaticFunction()
    elif len(line) >= 1 and line[0] == "<":
        print "unhandled %s" % (line)

print "Parsed: %d macros. %d structs, %d typedefs, %d enums" % (
          len(macros.keys()), len(structs.keys()), len(typedefs.keys()),
	  len(enums))
c = 0
for enum in enums.keys():
    consts = enums[enum][0]
    c = c + len(consts)
print "        %d variables, %d constants, %d functions and %d functypes" % (
          len(variables.keys()), c, len(functions.keys()),
	  len(user_functions.keys()))
print "The functions manipulates %d different types" % (len(types.keys()))
print "The functions returns %d different types" % (len(ret_types.keys()))

##################################################################
#
#          Parsing: libxml-decl-list.txt
#
##################################################################
def parseSection():
    global input
    global sections
    global files
    global identifiers_file

    tokens = []
    line = input.readline()[:-1]
    while line != "</SECTION>":
        if line[0:6] == "<FILE>" and line[-7:] == "</FILE>":
	    name = line[6:-7]
	elif len(line) > 0:
	    tokens.append(line)
	line = input.readline()[:-1]

    sections.append(name)
    files[name] = tokens
    for token in tokens:
        identifiers_file[token] = name
	#
	# Small transitivity for enum values
	#
	if enums.has_key(token):
	    for const in enums[token][0]:
	        identifiers_file[const] = name

print "Parsing: libxml-decl-list.txt"
input = open('libxml-decl-list.txt')
while 1:
    line = input.readline()
    if not line:
        break
    line = line[:-1]
    if line == "<SECTION>":
        parseSection()
    elif len(line) >= 1 and line[0] == "<":
        print "unhandled %s" % (line)

print "Parsed: %d files %d identifiers" % (len(files), len(identifiers_file.keys()))
##################################################################
#
#          Parsing: xml/*.xml
#          To enrich the existing info with extracted comments
#
##################################################################

nbcomments = 0

def insertParameterComment(id, name, value, is_param):
    global nbcomments

    indexString(id, value)
    if functions.has_key(id):
        if is_param == 1:
	    args = functions[id][1]
	    found = 0
	    for arg in args:
		if arg[1] == name:
		    arg[2] = value
		    found = 1
		    break
	    if found == 0 and name != '...':
		print "Arg %s not found on function %s description" % (name, id)
		return
	else:
	    ret = functions[id][0]
	    ret[1] = value
    elif user_functions.has_key(id):
        if is_param == 1:
	    args = user_functions[id][1]
	    found = 0
	    for arg in args:
		if arg[1] == name:
		    arg[2] = value
		    found = 1
		    break
	    if found == 0 and name != '...':
		print "Arg %s not found on functype %s description" % (name, id)
		print args
		return
	else:
	    ret = user_functions[id][0]
	    ret[1] = value
    elif macros.has_key(id):
        if is_param == 1:
	    args = macros[id][0]
	    found = 0
	    for arg in args:
		if arg[0] == name:
		    arg[1] = value
		    found = 1
		    break
	    if found == 0:
	        args.append([name, value])
	else:
	    print "Return info for macro %s: %s" % (id, value)
#	    ret = macros[id][0]
#	    ret[1] = value
    else:
        print "lost specific comment %s: %s: %s" % (id, name, value)
	return
    nbcomments = nbcomments + 1

def insertComment(name, title, value, id):
    global nbcomments

    ids[name] = id
    indexString(name, value)
    if functions.has_key(name):
        functions[name][2] = value
	return "function"
    elif typedefs.has_key(name):
        typedefs[name] = value
	return "typedef"
    elif macros.has_key(name):
        macros[name][1] = value
	return "macro"
    elif variables.has_key(name):
        variables[name][1] = value
	return "variable"
    elif structs.has_key(name):
        structs[name] = value
	return "struct"
    elif enums.has_key(name):
        enums[name][1] = value
	return "enum"
    elif user_functions.has_key(name):
        user_functions[name][2] = value
	return "user_function"
    else:
        print "lost comment %s: %s" % (name, value)
	return "unknown"
    nbcomments = nbcomments + 1


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
	self.id = None
	self.title = None
	self.descr = None
	self.string = None

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
	if tag == 'refsect2':
	    self.id = None
	    self.title = None
	    self.descr = None
	    self.string = None
	    self.type = None
	    self.in_parameter = 0
	    self.is_parameter = 0
	    self.parameter = None
	    self.parameter_info = None
	    self.entry = 0
	elif tag == 'para':
	    self._data = []
	elif tag == 'title':
	    self._data = []
	elif tag == 'tgroup':
	    self.in_parameter = 1
	elif tag == 'row':
	    self._data = []
	    self.entry = 0
	elif tag == 'entry':
	    self.entry = self.entry + 1
	elif tag == 'parameter' and self.in_parameter == 1:
	    self._data = []
	elif tag == 'anchor' and self.id == None:
	    if attrs.has_key('id'):
	        self.orig_id = attrs['id']
		self.id = string.replace(self.orig_id, '-CAPS', '')
		self.id = string.replace(self.id, '-', '_')

    def end(self, tag):
        if debug:
	    print "end %s" % tag
	if tag == 'refsect2':
	    self.type = insertComment(self.id, self.title, self.string,
	                              self.orig_id)
	    self.string = None
	elif tag == 'row':
	    if self.parameter_info != None and self.parameter_info != '':
		insertParameterComment(self.id, self.parameter,
				       self.parameter_info, self.is_parameter)
	    self.parameter_info = None
	    self.parameter = 0
	    self.is_parameter = 0
	elif tag == 'parameter' and self.in_parameter == 1 and self.entry == 1:
	    str = ''
	    for c in self._data:
		str = str + c
	    str = string.replace(str, '\n', ' ')
	    str = string.replace(str, '\r', ' ')
	    str = string.replace(str, '    ', ' ')
	    str = string.replace(str, '   ', ' ')
	    str = string.replace(str, '  ', ' ')
	    while len(str) >= 1 and str[0] == ' ':
		str=str[1:]
	    self.parameter = str
	    self.is_parameter = 1
	    self._data = []
	elif tag == 'para' or tag == 'entry':
	    str = ''
	    for c in self._data:
		str = str + c
	    str = string.replace(str, '\n', ' ')
	    str = string.replace(str, '\r', ' ')
	    str = string.replace(str, '    ', ' ')
	    str = string.replace(str, '   ', ' ')
	    str = string.replace(str, '  ', ' ')
	    while len(str) >= 1 and str[0] == ' ':
		str=str[1:]
	    if self.string == None:
		self.string = str
	    elif self.in_parameter == 1:
		self.parameter_info = str
	    self._data = []
	elif tag == 'title':
	    str = ''
	    for c in self._data:
	        str = str + c
	    str = string.replace(str, '\n', ' ')
	    str = string.replace(str, '\r', ' ')
	    str = string.replace(str, '    ', ' ')
	    str = string.replace(str, '   ', ' ')
	    str = string.replace(str, '  ', ' ')
	    while len(str) >= 1 and str[0] == ' ':
		str=str[1:]
	    self.title = str

xmlfiles = 0
filenames = os.listdir("xml")
for filename in filenames:
    try:
        f = open("xml/" + filename, 'r')
    except IOError, msg:
        print file, ":", msg
	continue
    data = f.read()
    (parser, target)  = getparser()
    parser.feed(data)
    parser.close()
    xmlfiles = xmlfiles + 1

print "Parsed: %d XML files collexting %d comments" % (xmlfiles, nbcomments)

##################################################################
#
#          Saving: libxml2-api.xml
#
##################################################################

def escape(raw):
    raw = string.replace(raw, '&', '&amp;')
    raw = string.replace(raw, '<', '&lt;')
    raw = string.replace(raw, '>', '&gt;')
    raw = string.replace(raw, "'", '&apos;')
    raw = string.replace(raw, '"', '&quot;')
    return raw

print "Saving XML description libxml2-api.xml"
output = open("libxml2-api.xml", "w")
output.write('<?xml version="1.0" encoding="ISO-8859-1"?>\n')
output.write("<api name='libxml2'>\n")
output.write("  <files>\n")
for file in files.keys():
    output.write("    <file name='%s'>\n" % file)
    for symbol in files[file]:
        output.write("     <exports symbol='%s'/>\n" % (symbol))
    output.write("    </file>\n")
output.write("  </files>\n")

output.write("  <symbols>\n")
symbols=macros.keys()
for i in structs.keys(): symbols.append(i)
for i in variables.keys(): variables.append(i)
for i in typedefs.keys(): symbols.append(i)
for i in enums.keys():
    symbols.append(i)
    for j in enums[i][0]:
        symbols.append(j)
for i in functions.keys(): symbols.append(i)
for i in user_functions.keys(): symbols.append(i)
symbols.sort()
prev = None
for i in symbols:
    if i == prev:
#        print "Symbol %s redefined" % (i)
	continue
    else:
        prev = i
    if identifiers_type.has_key(i):
        type = identifiers_type[i]
	
        if identifiers_file.has_key(i):
	    file = identifiers_file[i]
	else:
	    file = None

	output.write("    <%s name='%s'" % (type, i))
	if file != None:
	    output.write(" file='%s'" % (file))
	if type == "function":
	   output.write(">\n");
	   (ret, args, doc) = functions[i]
	   if doc != None and doc != '':
	       output.write("      <info>%s</info>\n" % (escape(doc)))
	   if ret[1] != None and ret[1] != '':
	       output.write("      <return type='%s' info='%s'/>\n" % (
	                    ret[0], escape(ret[1])))
	   else:
	       if ret[0] != 'void' and\
	          ret[0][0:4] != 'void': # This one is actually a bug in GTK Doc
		   print "Description for return on %s is missing" % (i)
	       output.write("      <return type='%s'/>\n" % (ret[0]))
	   for arg in args:
	       if arg[2] != None and arg[2] != '':
		   output.write("      <arg name='%s' type='%s' info='%s'/>\n" %
		                (arg[1], arg[0], escape(arg[2])))
	       else:
	           if arg[0] != '...':
		       print "Description for %s on %s is missing" % (arg[1], i)
		   output.write("      <arg name='%s' type='%s'/>\n" % (
				arg[1], arg[0]))
	   output.write("    </%s>\n" % (type));
	elif type == 'functype':
	   output.write(">\n");
	   (ret, args, doc) = user_functions[i]
	   if doc != None and doc != '':
	       output.write("      <info>%s</info>\n" % (escape(doc)))
	   if ret[1] != None and ret[1] != '':
	       output.write("      <return type='%s' info='%s'/>\n" % (
	                    ret[0], escape(ret[1])))
	   else:
	       if ret[0] != 'void' and\
	          ret[0][0:4] != 'void': # This one is actually a bug in GTK Doc
		   print "Description for return on %s is missing" % (i)
	       output.write("      <return type='%s'/>\n" % (ret[0]))
	   for arg in args:
	       if arg[2] != None and arg[2] != '':
		   output.write("      <arg name='%s' type='%s' info='%s'/>\n" %
		                (arg[1], arg[0], escape(arg[2])))
	       else:
	           if arg[0] != '...':
		       print "Description for %s on %s is missing" % (arg[1], i)
		   output.write("      <arg name='%s' type='%s'/>\n" % (
				arg[1], arg[0]))
	   output.write("    </%s>\n" % (type));
	elif type == 'macro':
	   output.write(">\n");
	   if macros[i][1] != None and macros[i][1] != '':
	       output.write("      <info>%s</info>\n" % (escape(macros[i][1])))
	   else:
	       print "Description for %s is missing" % (i)
	   args = macros[i][0]
	   for arg in args:
	       if arg[1] != None and arg[1] != '':
		   output.write("      <arg name='%s' info='%s'/>\n" %
		                (arg[0], escape(arg[1])))
	       else:
	           print "Description for %s on %s is missing" % (arg[1], i)
		   output.write("      <arg name='%s'/>\n" % (arg[0]))
	   output.write("    </%s>\n" % (type));
	elif type == 'struct':
	   if structs[i] != None and structs[i] != '':
	       output.write(" info='%s'/>\n" % (escape(structs[i])))
	   else:
	       output.write("/>\n");
	elif type == 'variable':
	   if variables[i][1] != None and variables[i][1] != '':
	       output.write(" info='%s'/>\n" % (escape(variables[i])))
	   else:
	       output.write("/>\n");
	elif type == 'typedef':
	   if typedefs[i] != None and typedefs[i] != '':
	       output.write(" info='%s'/>\n" % (escape(typedefs[i])))
	   else:
	       output.write("/>\n");
	else:
	   output.write("/>\n");
    else:
        print "Symbol %s not found in identifiers list" % (i)
output.write("  </symbols>\n")
output.write("</api>\n")
output.close()
print "generated XML for %d symbols" % (len(symbols))

##################################################################
#
#          Saving: libxml2-api.xml
#
##################################################################

hash = {}
for file in files.keys():
    for symbol in files[file]:
        hash[symbol] = file

def link(id):
    if ids.has_key(id):
        target = string.upper(ids[id])
    else:
	target = string.upper(id)
    if hash.has_key(id):
        module = string.lower(hash[id])
    else:
        module = 'index'
    file = 'html/libxml-' + module + '.html';
    return file + '#' + target
    
print "Saving XML crossreferences libxml2-refs.xml"
output = open("libxml2-refs.xml", "w")
output.write('<?xml version="1.0" encoding="ISO-8859-1"?>\n')
output.write("<apirefs name='libxml2'>\n")
output.write("  <references>\n")
typ = ids.keys()
typ.sort()
for id in typ:
    output.write("    <reference name='%s' href='%s'/>\n" % (id, link(id)))
output.write("  </references>\n")
output.write("  <alpha>\n")
letter = None
ids = ids.keys()
ids.sort()
for id in ids:
    if id[0] != letter:
        if letter != None:
	    output.write("    </letter>\n")
        letter = id[0]
	output.write("    <letter name='%s'>\n" % (letter))
    output.write("    <ref name='%s'/>\n" % (id))
if letter != None:
    output.write("    </letter>\n")
output.write("  </alpha>\n")
output.write("  <constructors>\n")
typ = ret_types.keys()
typ.sort()
for type in typ:
    if type == '' or type == 'void' or type == "int" or type == "char *" or \
       type == "const char *" :
        continue
    output.write("    <type name='%s'>\n" % (type))
    ids = ret_types[type]
    for id in ids:
	output.write("      <ref name='%s'/>\n" % (id))
    output.write("    </type>\n")
output.write("  </constructors>\n")
output.write("  <functions>\n")
typ = types.keys()
typ.sort()
for type in typ:
    if type == '' or type == 'void' or type == "int" or type == "char *" or \
       type == "const char *" :
        continue
    output.write("    <type name='%s'>\n" % (type))
    ids = types[type]
    for id in ids:
	output.write("      <ref name='%s'/>\n" % (id))
    output.write("    </type>\n")
output.write("  </functions>\n")

output.write("  <files>\n")
typ = files.keys()
typ.sort()
for file in typ:
    output.write("    <file name='%s'>\n" % (file))
    for id in files[file]:
	output.write("      <ref name='%s'/>\n" % (id))
    output.write("    </file>\n")
output.write("  </files>\n")

output.write("  <index>\n")
typ = index.keys()
typ.sort()
letter = None
count = 0
chunk = 0
chunks = []
for id in typ:
    if len(index[id]) > 30:
        continue
    if id[0] != letter:
        if letter == None or count > 200:
	    if letter != None:
		output.write("      </letter>\n")
	        output.write("    </chunk>\n")
		count = 0
		chunks.append(["chunk%s" % (chunk -1), first_letter, letter])
	    output.write("    <chunk name='chunk%s'>\n" % (chunk))
	    first_letter = id[0]
	    chunk = chunk + 1
        elif letter != None:
	    output.write("      </letter>\n")
        letter = id[0]
	output.write("      <letter name='%s'>\n" % (letter))
    output.write("        <word name='%s'>\n" % (id))
    tokens = index[id];
    tokens.sort()
    tok = None
    for token in index[id]:
        if tok == token:
	    continue
	tok = token
	output.write("          <ref name='%s'/>\n" % (token))
	count = count + 1
    output.write("        </word>\n")
if letter != None:
    output.write("      </letter>\n")
    output.write("    </chunk>\n")
    output.write("    <chunks>\n")
    for ch in chunks:
        output.write("      <chunk name='%s' start='%s' end='%s'/>\n" % (
	             ch[0], ch[1], ch[2]))
    output.write("    </chunks>\n")
output.write("  </index>\n")

output.write("</apirefs>\n")
output.close()
