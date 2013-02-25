#!/usr/bin/python -u
#
# This tests custom input callbacks
#
import sys
import StringIO
import libxml2

# We implement a new scheme, py://strings/ that will reference this dictionary
pystrings = {
    'catalogs/catalog.xml' :
'''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE catalog PUBLIC "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN" "http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd">
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <rewriteSystem systemIdStartString="http://example.com/dtds/" rewritePrefix="../dtds/"/>
</catalog>''',

    'xml/sample.xml' :
'''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root SYSTEM "http://example.com/dtds/sample.dtd">
<root>&sample.entity;</root>''',

    'dtds/sample.dtd' :
'''
<!ELEMENT root (#PCDATA)>
<!ENTITY sample.entity "replacement text">'''
}

def verify_doc(doc):
    e = doc.getRootElement()
    if e.name != 'root':
        raise ValueError("name")
    if e.content != 'replacement text':
        raise ValueError("content")

prefix = "py://strings/"
def my_input_cb(URI):
    idx = URI.startswith(prefix)
    if idx == -1:
        return None
    path = URI[len(prefix):]
    if path not in pystrings:
        print "my_input_cb: path does not exist, '%s'" % path
        return None
    print "my_input_cb: loading '%s'" % URI
    return StringIO.StringIO(pystrings[path])

opts = libxml2.XML_PARSE_DTDLOAD | libxml2.XML_PARSE_NONET | libxml2.XML_PARSE_COMPACT
startURL = prefix + "xml/sample.xml"
catURL = prefix + "catalogs/catalog.xml"

# Check that we cannot read custom schema without custom callback
print
print "Test 1: Expecting failure to load (custom scheme not handled)"
try:
    doc = libxml2.readFile(startURL, None, opts)
    print "Read custom scheme without registering handler succeeded?"
    sys.exit(1)
except libxml2.treeError, e:
    pass

# Register handler and try to load the same entity
print
print "Test 2: Expecting failure to load (no catalog - cannot load DTD)"
libxml2.registerInputCallback(my_input_cb)
doc = libxml2.readFile(startURL, None, opts)
try:
    verify_doc(doc)
    print "Doc was loaded?"
except ValueError, e:
    if str(e) != "content":
        print "Doc verify failed"
doc.freeDoc()

# Register a catalog (also accessible via pystr://) and retry
print
print "Test 3: Expecting successful loading"
parser = libxml2.createURLParserCtxt(startURL, opts)
parser.addLocalCatalog(catURL)
parser.parseDocument()
doc = parser.doc()
verify_doc(doc)
doc.freeDoc()

# Unregister custom callback when parser is already created
print
print "Test 4: Expect failure to read (custom callback unregistered during read)"
parser = libxml2.createURLParserCtxt(startURL, opts)
libxml2.popInputCallbacks()
parser.addLocalCatalog(catURL)
parser.parseDocument()
doc = parser.doc()
try:
    verify_doc(doc)
    print "Doc was loaded?"
except ValueError, e:
    if str(e) != "content":
        print "Doc verify failed"
doc.freeDoc()

# Try to load the document again
print
print "Test 5: Expect failure to load (callback unregistered)"
try:
    doc = libxml2.readFile(startURL, None, opts)
    print "Read custom scheme without registering handler succeeded?"
    sys.exit(1)
except libxml2.treeError, e:
    pass

# But should be able to read standard I/O yet...
print
print "Test 6: Expect successful loading using standard I/O"
doc = libxml2.readFile("tst.xml", None, opts)
doc.freeDoc()

# Now pop ALL input callbacks, should fail to load even standard I/O
print
print "Test 7: Remove all input callbacks, expect failure to load using standard I/O"
try:
    while True:
        libxml2.popInputCallbacks()
except IndexError, e:
    print "Popped all input callbacks: " + str(e)
try:
    doc = libxml2.readFile("tst.xml", None, opts)
except libxml2.treeError, e:
    pass
