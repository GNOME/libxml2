#!/usr/bin/python -u
#
# tries to parse the output of gtk-doc declaration files and make
# something usable from them
#

import sys
import string

input = open('doc/libxml-decl.txt')
macros = []
structs = []
typedefs = []
enums = {}
functions = {}
private_functions = {}
types = {}

def extractTypes(raw, function):
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

def parseMacro():
    global input
    global macros

    line = input.readline()[:-1]
    while line != "</MACRO>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    macros.append(name)

def parseStruct():
    global input
    global structs

    line = input.readline()[:-1]
    while line != "</STRUCT>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    structs.append(name)

def parseTypedef():
    global input
    global typedefs

    line = input.readline()[:-1]
    while line != "</TYPEDEF>":
        if line[0:6] == "<NAME>" and line[-7:] == "</NAME>":
	    name = line[6:-7]
	line = input.readline()[:-1]

    typedefs.append(name)

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
	line = input.readline()[:-1]
        
    enums[name] = consts

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

    args = string.split(signature, ",")
    sig = []
    for arg in args:
        l = string.split(arg)
	sig.append(extractTypes(l[0], name))

    private_functions[name] = (type , sig)

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

    args = string.split(signature, ",")
    sig = []
    for arg in args:
        l = string.split(arg)
	sig.append(extractTypes(l[0], name))

    functions[name] = (type , sig)

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
print "The functions uses %d different types" % (len(types.keys()))
for type in types.keys():
    if string.find(type, '*') >= 0 or (type[0:3] != 'xml' and
       type[0:4] != 'html' and type[0:4] != 'docb'):
#        print "  %s : %s" % (type, types[type])
        print "  %s" % (type)
