#!/usr/bin/python -u
#
# Setup script for libxml2 and libxslt if found
#
import sys, os
from distutils.core import setup, Extension


def missing(file):
    if os.access(file, os.R_OK) == 0:
        return 1
    return 0

xml_files = ["libxml2-api.xml", "libxml2-python-api.xml",
             "libxml.c", "libxml.py", "libxml_wrap.h", "types.c",
	     "xmlgenerator.py", "README", "TODO"]

xslt_files = ["libxslt-api.xml", "libxslt-python-api.xml",
             "libxslt.c", "libxsl.py", "libxslt_wrap.h",
	     "xsltgenerator.py"]

if missing("libxml2-py.c") or missing("libxml2.py"):
    try:
	try:
	    import xmlgenerator
	except:
	    import generator
    except:
	print "failed to find and generate stubs for libxml2, aborting ..."
	print sys.exc_type, sys.exc_value
	sys.exit(1)

    head = open("libxml.py", "r")
    generated = open("libxml2class.py", "r")
    result = open("libxml2.py", "w")
    for line in head.readlines():
	result.write(line)
    for line in generated.readlines():
	result.write(line)
    head.close()
    generated.close()
    result.close()

with_xslt=0
if missing("libxslt-py.c") or missing("libxslt.py"):
    if missing("xsltgenerator.py") or missing("libxslt-api.xml"):
        print "libxslt stub generator not found, libxslt not built"
    else:
	try:
	    import xsltgenerator
	except:
	    print "failed to generate stubs for libxslt, aborting ..."
	    print sys.exc_type, sys.exc_value
	else:
	    head = open("libxsl.py", "r")
	    generated = open("libxsltclass.py", "r")
	    result = open("libxslt.py", "w")
	    for line in head.readlines():
		result.write(line)
	    for line in generated.readlines():
		result.write(line)
	    head.close()
	    generated.close()
	    result.close()
	    with_xslt=1
else:
    with_xslt=1


descr = "libxml2 package"
modules = [ 'libxml2' ]
c_files = ['libxml2-py.c', 'libxml.c', 'types.c' ]
includes= ["/usr/include/libxml2"]
libs    = ["xml2", "m", "z"]
macros  = []
if with_xslt == 1:
    descr = "libxml2 and libxslt package"
    #
    # We are gonna build 2 identical shared libs with merge initializing
    # both libxml2mod and libxsltmod
    #
    c_files = c_files + ['libxslt-py.c', 'libxslt.c']
    libs.insert(0, 'xslt')
    includes.append("/usr/include/libxslt")
    modules.append('libxslt')
    macros.append(('MERGED_MODULES', '1'))


extens=[Extension('libxml2mod', c_files, include_dirs=includes,
                  libraries=libs, define_macros=macros)] 
if with_xslt == 1:
    extens.append(Extension('libxsltmod', c_files, include_dirs=includes,
			    libraries=libs))

if missing("MANIFEST"):
    global xml_files

    manifest = open("MANIFEST", "w")
    manifest.write("setup.py\n")
    for file in xml_files:
        manifest.write(file + "\n")
    if with_xslt == 1:
	for file in xslt_files:
	    manifest.write(file + "\n")
    manifest.close()

setup (name = "libxml2-python",
       version = "2.4.16",
       description = descr,
       author = "Daniel Veillard",
       author_email = "veillard@redhat.com",
       url = "http://xmlsoft.org/python.html",
       licence="MIT Licence",

       py_modules=modules,
       ext_modules=extens,
       )

sys.exit(0)

