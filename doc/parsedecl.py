#!/usr/bin/python -u
#
# tries to parse the output of gtk-doc declaration files and make
# an XML reusable description from them
#
# TODO: try to extracts comments from the DocBook output of

import sys
import string

macros = []
structs = []
typedefs = []
enums = {}
functions = {}
private_functions = {}
ret_types = {}
types = {}

sections = []
files = {}
identifiers_file = {}
identifiers_type = {}

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
    list = string.split(raw, ",")
    ret = []
    for arg in list:
        i = len(arg)
	if i == 0:
	    continue
	i = i - 1
	c = arg[i]
	while string.find(string.letters, c) >= 0 or \
	      string.find(string.digits, c) >= 0:
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
#	print "list: %s -> %s, %s" % (list, type, name)
	ret.append((type, name))
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

    line = input.readline()[:-1]
    while line != "</MACRO>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    macros.append(name)
    identifiers_type[name] = "macro"

def parseStruct():
    global input
    global structs

    line = input.readline()[:-1]
    while line != "</STRUCT>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    structs.append(name)
    identifiers_type[name] = "struct"

def parseTypedef():
    global input
    global typedefs

    line = input.readline()[:-1]
    while line != "</TYPEDEF>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    typedefs.append(name)
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
        
    enums[name] = consts
    identifiers_type[name] = "enum"

def parseStaticFunction():
    global input
    global private_functions

    line = input.readline()[:-1]
    type = None
    signature = None
    while line != "</USER_FUNCTION>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
        elif line[0:9] == "<RETURNS>" and line[-10:] == "</RETURNS>":
	    type = extractTypes(line[9:-10], name)
	else:
	    signature = line
	line = input.readline()[:-1]

    args = extractArgs(signature, name)
    private_functions[name] = (type , args)
    identifiers_type[name] = "private_func"

def parseFunction():
    global input
    global functions

    line = input.readline()[:-1]
    type = None
    signature = None
    while line != "</FUNCTION>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
        elif line[0:9] == "<RETURNS>" and line[-10:] == "</RETURNS>":
	    type = extractTypes(line[9:-10], name)
	else:
	    signature = line
	line = input.readline()[:-1]

    args = extractArgs(signature, name)
    functions[name] = (type , args)
    identifiers_type[name] = "function"

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
	    for const in enums[token]:
	        identifiers_file[const] = name

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
          len(macros), len(structs), len(typedefs), len(enums))
c = 0
for enum in enums.keys():
    consts = enums[enum]
    c = c + len(consts)
print "        %d constants, %d functions and %d private functions" % (
          c, len(functions.keys()), len(private_functions.keys()))
print "The functions manipulates %d different types" % (len(types.keys()))
print "The functions returns %d different types" % (len(ret_types.keys()))

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

print "Saving XML description libxml2-api.xml"
output = open("libxml2-api.xml", "w")
output.write("<api name='libxml2'>\n")
output.write("  <files>\n")
for file in files.keys():
    output.write("    <file name='%s'>\n" % file)
    for symbol in files[file]:
        output.write("     <exports symbol='%s'/>\n" % (symbol))
    output.write("    </file>\n")
output.write("  </files>\n")

output.write("  <symbols>\n")
symbols=macros
for i in structs: symbols.append(i)
for i in typedefs: symbols.append(i)
for i in enums.keys():
    symbols.append(i)
    for j in enums[i]:
        symbols.append(j)
for i in functions.keys(): symbols.append(i)
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
	   (ret, args) = functions[i]
	   output.write("      <return type='%s'/>\n" % (ret))
	   for arg in args:
	       output.write("      <arg name='%s' type='%s'/>\n" % (
	                    arg[1], arg[0]))
	   output.write("    </%s>\n" % (type));
	else:
	   output.write("/>\n");
    else:
        print "Symbol %s not found in identifiers list" % (i)
output.write("  </symbols>\n")
output.write("</api>\n")
print "generated XML for %d symbols" % (len(symbols))
