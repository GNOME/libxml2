#!/usr/bin/python -u
#
# Indexes the examples and build doc and web pages.
#
import string
import sys
try:
    import libxml2
except:
    sys.exit(1)
sys.path.append("..")
from apibuild import CParser, escape

symbols = {}
api_dict = None
api_doc = None

def load_api():
    global api_dict
    global api_doc

    if api_dict != None:
        return
    api_dict = {}
    try:
        print "loading ../libxml2-api.xml"
        api_doc = libxml2.parseFile("../libxml2-api.xml")
    except:
        print "failed to parse ../libxml2-api.xml"
	sys.exit(1)

def find_symbol(name):
    global api_dict
    global api_doc

    if api_doc == None:
        load_api()

    if name == None:
        return
    if api_dict.has_key(name):
        return api_dict[name]
    ctxt = api_doc.xpathNewContext()
    res = ctxt.xpathEval("/api/symbols/*[@name = '%s']" % (name))
    if type(res) == type([]) and len(res) >= 1:
        if len(res) > 1:
	    print "Found %d references to %s in the API" % (len(res), name)
	node = res[0]
	typ = node.name
	file = node.xpathEval("string(@file)")
	info = node.xpathEval("string(info)")
    else:
        print "Reference %s not found in the API" % (name)
	return None
    ret = (typ, file, info)
    api_dict[name] = ret
    return ret

def parse_top_comment(filename, comment):
    res = {}
    lines = string.split(comment, "\n")
    item = None
    for line in lines:
        while line != "" and line[0] == ' ':
	    line = line[1:]
        while line != "" and line[0] == '*':
	    line = line[1:]
        while line != "" and line[0] == ' ':
	    line = line[1:]
	try:
	    (it, line) = string.split(line, ":", 1)
	    item = it
	    while line != "" and line[0] == ' ':
		line = line[1:]
	    if res.has_key(item):
	        res[item] = res[item] + " " + line
	    else:
		res[item] = line
	except:
	    if item != None:
	        if res.has_key(item):
		    res[item] = res[item] + " " + line
		else:
		    res[item] = line
    return res

def parse(filename, output):
    global symbols

    parser = CParser(filename)
    parser.collect_references()
    idx = parser.parse()
    info = parse_top_comment(filename, parser.top_comment)
    output.write("  <example filename='%s'>\n" % filename)
    try:
        purpose = info['purpose']
	output.write("    <purpose>%s</purpose>\n" % purpose);
    except:
        print "Example %s lacks a purpose description" % (filename)
    try:
        usage = info['usage']
	output.write("    <usage>%s</usage>\n" % usage);
    except:
        print "Example %s lacks an usage description" % (filename)
    try:
        author = info['author']
	output.write("    <author>%s</author>\n" % author);
    except:
        print "Example %s lacks an author description" % (filename)
    try:
        copy = info['copy']
	output.write("    <copy>%s</copy>\n" % copy);
    except:
        print "Example %s lacks a copyright description" % (filename)
    for topic in info.keys():
        if topic != "purpose" and topic != "usage" and \
	   topic != "author" and topic != "copy":
	    str = info[topic]
	    output.write("    <extra topic='%s'>%s</extra>\n" % str)
#    print idx.functions
    output.write("    <uses>\n")
    for include in idx.includes.keys():
        if include.find("libxml") != -1:
	    output.write("      <include>%s</include>\n" % (escape(include)))
    for ref in idx.references.keys():
        id = idx.references[ref]
	name = id.get_name()
	line = id.get_lineno()
	if symbols.has_key(name):
	    sinfo = symbols[name]
	    refs = sinfo[0]
	    # gather at most 5 references per symbols
	    if refs > 5:
	        continue
	    sinfo[refs] = filename
	    sinfo[0] = refs + 1
	else:
	    symbols[name] = [1, filename]
	info = find_symbol(name)
	if info != None:
	    type = info[0]
	    file = info[1]
	    output.write("      <%s line='%d' file='%s'>%s</%s>\n" % (type,
	                 line, file, name, type))
	else:
	    type = id.get_type()
	    output.write("      <%s line='%d'>%s</%s>\n" % (type,
	                 line, name, type))
	    
    output.write("    </uses>\n")
    output.write("  </example>\n")
    
    return idx

def dump_symbols(output):
    global symbols

    output.write("  <symbols>\n")
    keys = symbols.keys()
    keys.sort()
    for symbol in keys:
        output.write("    <symbol name='%s'>\n" % (symbol))
	info = symbols[symbol]
	i = 1
	while i < len(info):
	    output.write("      <ref filename='%s'/>\n" % (info[i]))
	    i = i + 1
        output.write("    </symbol>\n")
    output.write("  </symbols>\n")

if __name__ == "__main__":
    load_api()
    output = open("examples.xml", "w")
    output.write("<examples>\n")

    parse("example1.c", output)

    dump_symbols(output)
    output.write("</examples>\n")
    output.close()

