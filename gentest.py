#!/usr/bin/python -u
#
# generate a tester program for the API
#
import sys
import os
import string
try:
    import libxml2
except:
    print "libxml2 python bindings not available, skipping testapi.c generation"
    sys.exit(0)

#
# Modules we don't want skip in API test
#
skipped_modules = [ "SAX", "SAX2", "xlink", "threads", "globals",
  "xpathInternals", "parserInternals", "xmlmemory",
  "xmlversion", "debugXML", "xmlexports", "DOCBparser",

  # temporary
  "xmlautomata", "xmlregexp", "c14n",
  
]

#
# Some function really need to be skipped for the tests.
#
skipped_functions = [
# block on I/O
"xmlFdRead", "xmlReadFd", "xmlCtxtReadFd",
"htmlFdRead", "htmlReadFd", "htmlCtxtReadFd",
"xmlReaderNewFd", "xmlReaderForFd",
"xmlIORead", "xmlReadIO", "xmlCtxtReadIO",
"htmlIORead", "htmlReadIO", "htmlCtxtReadIO",
"xmlReaderNewIO", "xmlBufferDump", "xmlNanoFTPConnect",
"xmlNanoFTPConnectTo",
# library state cleanup, generate false leak informations and other
# troubles, heavillyb tested otherwise.
"xmlCleanupParser", "xmlRelaxNGCleanupTypes", "xmlSetListDoc",
"xmlSetTreeDoc", "xmlUnlinkNode",
# hard to avoid leaks in the tests
"xmlStrcat", "xmlStrncat", "xmlCatalogAddLocal", "xmlNewTextWriterDoc",
# unimplemented
"xmlTextReaderReadInnerXml", "xmlTextReaderReadOuterXml",
"xmlTextReaderReadString",
# destructor
"xmlListDelete", "xmlOutputBufferClose", "xmlNanoFTPClose",
# deprecated
"xmlCatalogGetPublic", "xmlCatalogGetSystem", "xmlEncodeEntities",
"xmlNewGlobalNs",
# allocators
"xmlMemFree",
# verbosity
"xmlCatalogSetDebug",
]

#
# Those functions have side effect on the global state
# and hence generate errors on memory allocation tests
#
skipped_memcheck = [ "xmlLoadCatalog", "xmlAddEncodingAlias",
   "xmlSchemaInitTypes", "xmlNanoFTPProxy", "xmlNanoFTPScanProxy",
   "xmlNanoHTTPScanProxy", "xmlResetLastError", "xmlCatalogConvert",
   "xmlCatalogRemove", "xmlLoadCatalogs", "xmlCleanupCharEncodingHandlers",
   "xmlInitCharEncodingHandlers", "xmlCatalogCleanup",
   "htmlParseFile" # loads the catalogs
]

#
# Extra code needed for some test cases
#
extra_pre_call = {
   "xmlSAXUserParseFile":
       "if (sax == (xmlSAXHandlerPtr)&xmlDefaultSAXHandler) user_data = NULL;",
   "xmlSAXUserParseMemory":
       "if (sax == (xmlSAXHandlerPtr)&xmlDefaultSAXHandler) user_data = NULL;",
   "xmlParseBalancedChunkMemory":
       "if (sax == (xmlSAXHandlerPtr)&xmlDefaultSAXHandler) user_data = NULL;",
   "xmlParseBalancedChunkMemoryRecover":
       "if (sax == (xmlSAXHandlerPtr)&xmlDefaultSAXHandler) user_data = NULL;",
   "xmlParserInputBufferCreateFd":
       "if (fd >= 0) fd = -1;",
}
extra_post_call = {
   "xmlAddChild": 
       "if (ret_val == NULL) { xmlFreeNode(cur) ; cur = NULL ; }",
   "xmlAddChildList": 
       "if (ret_val == NULL) { xmlFreeNodeList(cur) ; cur = NULL ; }",
   "xmlAddSibling":
       "if (ret_val == NULL) { xmlFreeNode(elem) ; elem = NULL ; }",
   "xmlAddNextSibling":
       "if (ret_val == NULL) { xmlFreeNode(elem) ; elem = NULL ; }",
   "xmlAddPrevSibling": 
       "if (ret_val == NULL) { xmlFreeNode(elem) ; elem = NULL ; }",
   "xmlDocSetRootElement": 
       "if (doc == NULL) { xmlFreeNode(root) ; root = NULL ; }",
   "xmlReplaceNode": 
       """if (cur != NULL) {
              xmlUnlinkNode(cur);
              xmlFreeNode(cur) ; cur = NULL ; }
          if (old != NULL) {
              xmlUnlinkNode(old);
              xmlFreeNode(old) ; old = NULL ; }
	  ret_val = NULL;""",
   "xmlTextMerge": 
       """if ((first != NULL) && (first->type != XML_TEXT_NODE)) {
              xmlUnlinkNode(second);
              xmlFreeNode(second) ; second = NULL ; }""",
   "xmlBuildQName": 
       """if ((ret_val != NULL) && (ret_val != ncname) &&
              (ret_val != prefix) && (ret_val != memory))
              xmlFree(ret_val);
	  ret_val = NULL;""",
   "xmlDictReference": "xmlDictFree(dict);",
   # Functions which deallocates one of their parameters
   "xmlXPathConvertBoolean": """val = NULL;""",
   "xmlXPathConvertNumber": """val = NULL;""",
   "xmlXPathConvertString": """val = NULL;""",
   "xmlSaveFileTo": """buf = NULL;""",
   "xmlSaveFormatFileTo": """buf = NULL;""",
   "xmlIOParseDTD": "input = NULL;",
   "xmlRemoveProp": "cur = NULL;",
   "xmlNewNs": "if ((node == NULL) && (ret_val != NULL)) xmlFreeNs(ret_val);",
   "xmlCopyNamespace": "if (ret_val != NULL) xmlFreeNs(ret_val);",
   "xmlCopyNamespaceList": "if (ret_val != NULL) xmlFreeNsList(ret_val);",
   "xmlNewTextWriter": "if (ret_val != NULL) out = NULL;",
   "xmlNewTextWriterPushParser": "if (ret_val != NULL) ctxt = NULL;",
}

modules = []

def is_skipped_module(name):
    for mod in skipped_modules:
        if mod == name:
	    return 1
    return 0

def is_skipped_function(name):
    for fun in skipped_functions:
        if fun == name:
	    return 1
    # Do not test destructors
    if string.find(name, 'Free') != -1:
        return 1
    return 0

def is_skipped_memcheck(name):
    for fun in skipped_memcheck:
        if fun == name:
	    return 1
    return 0

missing_types = {}
def add_missing_type(name, func):
    try:
        list = missing_types[name]
	list.append(func)
    except:
        missing_types[name] = [func]

generated_param_types = []
def add_generated_param_type(name):
    generated_param_types.append(name)

generated_return_types = []
def add_generated_return_type(name):
    generated_return_types.append(name)

missing_functions = {}
missing_functions_nr = 0
def add_missing_functions(name, module):
    global missing_functions_nr

    missing_functions_nr = missing_functions_nr + 1
    try:
        list = missing_functions[module]
	list.append(name)
    except:
        missing_functions[module] = [name]

#
# Provide the type generators and destructors for the parameters
#

def type_convert(str, name, info, module, function, pos):
#    res = string.replace(str, "    ", " ")
#    res = string.replace(str, "   ", " ")
#    res = string.replace(str, "  ", " ")
    res = string.replace(str, " *", "_ptr")
#    res = string.replace(str, "*", "_ptr")
    res = string.replace(res, " ", "_")
    res = string.replace(res, "htmlNode", "xmlNode")
    res = string.replace(res, "htmlDoc", "xmlDoc")
    res = string.replace(res, "htmlParser", "xmlParser")
    if res == 'const_char_ptr':
        if string.find(name, "file") != -1 or \
           string.find(name, "uri") != -1 or \
           string.find(name, "URI") != -1 or \
           string.find(info, "filename") != -1 or \
           string.find(info, "URI") != -1 or \
           string.find(info, "URL") != -1:
	    if string.find(function, "Save") != -1:
	        return('fileoutput')
	    return('filepath')
    if res == 'void_ptr':
        if module == 'nanoftp' and name == 'ctx':
	    return('xmlNanoFTPCtxtPtr')
        if function == 'xmlNanoFTPNewCtxt':
	    return('xmlNanoFTPCtxtPtr')
        if module == 'nanohttp' and name == 'ctx':
	    return('xmlNanoHTTPCtxtPtr')
        if function == 'xmlIOHTTPOpenW':
	    return('xmlNanoHTTPCtxtPtr')
	if string.find(name, "data") != -1:
	    return('userdata');
	if string.find(name, "user") != -1:
	    return('userdata');
    if res == 'xmlDoc_ptr':
        res = 'xmlDocPtr';
    if res == 'xmlNode_ptr':
        res = 'xmlNodePtr';
    if res == 'xmlDict_ptr':
        res = 'xmlDictPtr';
    if res == 'xmlNodePtr' and pos != 0:
        if (function == 'xmlAddChild' and pos == 2) or \
	   (function == 'xmlAddChildList' and pos == 2) or \
           (function == 'xmlAddNextSibling' and pos == 2) or \
           (function == 'xmlAddSibling' and pos == 2) or \
           (function == 'xmlDocSetRootElement' and pos == 2) or \
           (function == 'xmlReplaceNode' and pos == 2) or \
           (function == 'xmlTextMerge') or \
	   (function == 'xmlAddPrevSibling' and pos == 2):
	    return('xmlNodePtr_in');
    if res == 'const xmlBufferPtr':
        res = 'xmlBufferPtr';
    if res == 'xmlChar_ptr' and name == 'name' and \
       string.find(function, "EatName") != -1:
        return('eaten_name')
    if res == 'void_ptr*':
        res = 'void_ptr_ptr'
    if res == 'char_ptr*':
        res = 'char_ptr_ptr'
    if res == 'xmlChar_ptr*':
        res = 'xmlChar_ptr_ptr'
    if res == 'const_xmlChar_ptr*':
        res = 'const_xmlChar_ptr_ptr'
    if res == 'const_char_ptr*':
        res = 'const_char_ptr_ptr'
        
    return res

known_param_types = []

def is_known_param_type(name, rtype):
    global test
    for type in known_param_types:
        if type == name:
	    return 1
    for type in generated_param_types:
        if type == name:
	    return 1

    if name[-3:] == 'Ptr' or name[-4:] == '_ptr':
        if rtype[0:6] == 'const ':
	    crtype = rtype[6:]
	else:
	    crtype = rtype

        test.write("""
#define gen_nb_%s 1
static %s gen_%s(int no ATTRIBUTE_UNUSED, int nr ATTRIBUTE_UNUSED) {
    return(NULL);
}
static void des_%s(int no ATTRIBUTE_UNUSED, %s val ATTRIBUTE_UNUSED, int nr ATTRIBUTE_UNUSED) {
}
""" % (name, crtype, name, name, rtype))
        add_generated_param_type(name)
        return 1

    return 0

#
# Provide the type destructors for the return values
#

known_return_types = []

def is_known_return_type(name):
    for type in known_return_types:
        if type == name:
	    return 1
    return 0

#
# Copy the beginning of the C test program result
#

input = open("testapi.c", "r")
test = open('testapi.c.new', 'w')

def compare_and_save():
    global test

    test.close()
    input = open("testapi.c", "r").read()
    test = open('testapi.c.new', "r").read()
    if input != test:
        os.system("rm testapi.c ; mv testapi.c.new testapi.c")
        print("Updated testapi.c")
    else:
        print("Generated testapi.c is identical")

line = input.readline()
while line != "":
    if line == "/* CUT HERE: everything below that line is generated */\n":
        break;
    if line[0:15] == "#define gen_nb_":
        type = string.split(line[15:])[0]
	known_param_types.append(type)
    if line[0:19] == "static void desret_":
        type = string.split(line[19:], '(')[0]
	known_return_types.append(type)
    test.write(line)
    line = input.readline()
input.close()

if line == "":
    print "Could not find the CUT marker in testapi.c skipping generation"
    test.close()
    sys.exit(0)

print("Scanned testapi.c: found %d parameters types and %d return types\n" % (
      len(known_param_types), len(known_return_types)))
test.write("/* CUT HERE: everything below that line is generated */\n")


#
# Open the input API description
#
doc = libxml2.readFile('doc/libxml2-api.xml', None, 0)
if doc == None:
    print "Failed to load doc/libxml2-api.xml"
    sys.exit(1)
ctxt = doc.xpathNewContext()

#
# Generate constructors and return type handling for all enums
#
enums = ctxt.xpathEval("/api/symbols/typedef[@type='enum']")
for enum in enums:
    name = enum.xpathEval('string(@name)')
    if name == None:
        continue;

    if is_known_param_type(name, name) == 0:
	values = ctxt.xpathEval("/api/symbols/enum[@type='%s']" % name)
	i = 0
	vals = []
	for value in values:
	    vname = value.xpathEval('string(@name)')
	    if vname == None:
		continue;
	    i = i + 1
	    if i >= 5:
		break;
	    vals.append(vname)
	if vals == []:
	    print "Didn't found any value for enum %s" % (name)
	    continue
	test.write("#define gen_nb_%s %d\n" % (name, len(vals)))
	test.write("""static %s gen_%s(int no, int nr ATTRIBUTE_UNUSED) {\n""" %
	           (name, name))
	i = 1
	for value in vals:
	    test.write("    if (no == %d) return(%s);\n" % (i, value))
	    i = i + 1
	test.write("""    return(0);
}
""");
	known_param_types.append(name)

    if is_known_return_type(name) == 0:
        test.write("""static void des_%s(int no ATTRIBUTE_UNUSED, %s val ATTRIBUTE_UNUSED, int nr ATTRIBUTE_UNUSED) {
}
static void desret_%s(%s val ATTRIBUTE_UNUSED) {
}

""" % (name, name, name, name))
	known_return_types.append(name)

#
# Load the interfaces
# 
headers = ctxt.xpathEval("/api/files/file")
for file in headers:
    name = file.xpathEval('string(@name)')
    if (name == None) or (name == ''):
        continue

    #
    # Some module may be skipped because they don't really consists
    # of user callable APIs
    #
    if is_skipped_module(name):
        continue

    #
    # do not test deprecated APIs
    #
    desc = file.xpathEval('string(description)')
    if string.find(desc, 'DEPRECATED') != -1:
        print "Skipping deprecated interface %s" % name
	continue;

    test.write("#include <libxml/%s.h>\n" % name)
    modules.append(name)
        
#
# Generate the callers signatures
# 
for module in modules:
    test.write("static int test_%s(void);\n" % module);

#
# Generate the top caller
# 

test.write("""
/**
 * testlibxml2:
 *
 * Main entry point of the tester for the full libxml2 module,
 * it calls all the tester entry point for each module.
 *
 * Returns the number of error found
 */
static int
testlibxml2(void)
{
    int ret = 0;

""")

for module in modules:
    test.write("    ret += test_%s();\n" % module)

test.write("""
    printf("Total: %d functions, %d tests, %d errors\\n",
           function_tests, call_tests, ret);
    return(ret);
}

""")

#
# How to handle a function
# 
nb_tests = 0

def generate_test(module, node):
    global test
    global nb_tests
    nb_cond = 0
    no_gen = 0

    name = node.xpathEval('string(@name)')
    if is_skipped_function(name):
        return

    #
    # check we know how to handle the args and return values
    # and store the informations for the generation
    #
    try:
	args = node.xpathEval("arg")
    except:
        args = []
    t_args = []
    n = 0
    for arg in args:
        n = n + 1
        rtype = arg.xpathEval("string(@type)")
	if rtype == 'void':
	    break;
	info = arg.xpathEval("string(@info)")
	nam = arg.xpathEval("string(@name)")
        type = type_convert(rtype, nam, info, module, name, n)
	if is_known_param_type(type, rtype) == 0:
	    add_missing_type(type, name);
	    no_gen = 1
	t_args.append((nam, type, rtype, info))
    
    try:
	rets = node.xpathEval("return")
    except:
        rets = []
    t_ret = None
    for ret in rets:
        rtype = ret.xpathEval("string(@type)")
	info = ret.xpathEval("string(@info)")
        type = type_convert(rtype, 'return', info, module, name, 0)
	if rtype == 'void':
	    break
	if is_known_return_type(type) == 0:
	    add_missing_type(type, name);
	    no_gen = 1
	t_ret = (type, rtype, info)
	break

    test.write("""
static int
test_%s(void) {
    int ret = 0;

""" % (name))

    if no_gen == 1:
        add_missing_functions(name, module)
	test.write("""
    /* missing type support */
    return(ret);
}

""")
        return

    try:
	conds = node.xpathEval("cond")
	for cond in conds:
	    test.write("#ifdef %s\n" % (cond.get_content()))
	    nb_cond = nb_cond + 1
    except:
        pass
    
    # Declare the memory usage counter
    no_mem = is_skipped_memcheck(name)
    if no_mem == 0:
	test.write("    int mem_base;\n");

    # Declare the return value
    if t_ret != None:
        test.write("    %s ret_val;\n" % (t_ret[1]))

    # Declare the arguments
    for arg in t_args:
        (nam, type, rtype, info) = arg;
        if (type[-3:] == 'Ptr' or type[-4:] == '_ptr') and \
	    rtype[0:6] == 'const ':
	    crtype = rtype[6:]
	else:
	    crtype = rtype
	# add declaration
	test.write("    %s %s; /* %s */\n" % (crtype, nam, info))
	test.write("    int n_%s;\n" % (nam))
    test.write("\n")

    # Cascade loop on of each argument list of values
    for arg in t_args:
        (nam, type, rtype, info) = arg;
	#
	test.write("    for (n_%s = 0;n_%s < gen_nb_%s;n_%s++) {\n" % (
	           nam, nam, type, nam))
    
    # log the memory usage
    if no_mem == 0:
	test.write("        mem_base = xmlMemBlocks();\n");

    # prepare the call
    i = 0;
    for arg in t_args:
        (nam, type, rtype, info) = arg;
	#
	test.write("        %s = gen_%s(n_%s, %d);\n" % (nam, type, nam, i))
	i = i + 1;

    # do the call, and clanup the result
    if extra_pre_call.has_key(name):
	test.write("        %s\n"% (extra_pre_call[name]))
    if t_ret != None:
	test.write("\n        ret_val = %s(" % (name))
	need = 0
	for arg in t_args:
	    (nam, type, rtype, info) = arg
	    if need:
	        test.write(", ")
	    else:
	        need = 1
	    test.write("%s" % nam);
	test.write(");\n")
	if extra_post_call.has_key(name):
	    test.write("        %s\n"% (extra_post_call[name]))
	test.write("        desret_%s(ret_val);\n" % t_ret[0])
    else:
	test.write("\n        %s(" % (name));
	need = 0;
	for arg in t_args:
	    (nam, type, rtype, info) = arg;
	    if need:
	        test.write(", ")
	    else:
	        need = 1
	    test.write("%s" % nam)
	test.write(");\n")
	if extra_post_call.has_key(name):
	    test.write("        %s\n"% (extra_post_call[name]))

    test.write("        call_tests++;\n");

    # Free the arguments
    i = 0;
    for arg in t_args:
        (nam, type, rtype, info) = arg;
	#
	test.write("        des_%s(n_%s, %s, %d);\n" % (type, nam, nam, i))
	i = i + 1;

    test.write("        xmlResetLastError();\n");
    # Check the memory usage
    if no_mem == 0:
	test.write("""        if (mem_base != xmlMemBlocks()) {
            printf("Leak of %%d blocks found in %s",
	           xmlMemBlocks() - mem_base);
	    ret++;
""" % (name));
	for arg in t_args:
	    (nam, type, rtype, info) = arg;
	    test.write("""            printf(" %%d", n_%s);\n""" % (nam))
	test.write("""            printf("\\n");\n""")
	test.write("        }\n")

    for arg in t_args:
	test.write("    }\n")

    #
    # end of conditional
    #
    while nb_cond > 0:
        test.write("#endif\n")
	nb_cond = nb_cond -1

    nb_tests = nb_tests + 1;

    test.write("""
    function_tests++;
    return(ret);
}

""")
    
#
# Generate all module callers
#
for module in modules:
    # gather all the functions exported by that module
    try:
	functions = ctxt.xpathEval("/api/symbols/function[@file='%s']" % (module))
    except:
        print "Failed to gather functions from module %s" % (module)
	continue;

    # iterate over all functions in the module generating the test
    i = 0
    nb_tests_old = nb_tests
    for function in functions:
        i = i + 1
        generate_test(module, function);

    # header
    test.write("""static int
test_%s(void) {
    int ret = 0;

    printf("Testing %s : %d of %d functions ...\\n");
""" % (module, module, nb_tests - nb_tests_old, i))

    # iterate over all functions in the module generating the call
    for function in functions:
        name = function.xpathEval('string(@name)')
	if is_skipped_function(name):
	    continue
	test.write("    ret += test_%s();\n" % (name))

    # footer
    test.write("""
    if (ret != 0)
	printf("Module %s: %%d errors\\n", ret);
    return(ret);
}
""" % (module))

#
# Generate direct module caller
#
test.write("""static int
test_module(const char *module) {
""");
for module in modules:
    test.write("""    if (!strcmp(module, "%s")) return(test_%s());\n""" % (
        module, module))
test.write("""    return(0);
}
""");

print "Generated test for %d modules and %d functions" %(len(modules), nb_tests)

compare_and_save()

missing_list = []
for missing in missing_types.keys():
    if missing == 'va_list' or missing == '...':
        continue;

    n = len(missing_types[missing])
    missing_list.append((n, missing))

def compare_missing(a, b):
    return b[0] - a[0]

missing_list.sort(compare_missing)
print "Missing support for %d functions and %d types see missing.lst" % (missing_functions_nr, len(missing_list))
lst = open("missing.lst", "w")
lst.write("Missing support for %d types" % (len(missing_list)))
lst.write("\n")
for miss in missing_list:
    lst.write("%s: %d :" % (miss[1], miss[0]))
    i = 0
    for n in missing_types[miss[1]]:
        i = i + 1
        if i > 5:
	    lst.write(" ...")
	    break
	lst.write(" %s" % (n))
    lst.write("\n")
lst.write("\n")
lst.write("\n")
lst.write("Missing support per module");
for module in missing_functions.keys():
    lst.write("module %s:\n   %s\n" % (module, missing_functions[module]))

lst.close()


