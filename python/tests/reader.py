#!/usr/bin/python -u
import libxml2
import StringIO
import sys

# Memory debug specific
libxml2.debugMemory(1)

f = StringIO.StringIO("""<a><b b1="b1"/><c>content of c</c></a>""")
input = libxml2.inputBuffer(f)
reader = input.newTextReader()
ret = reader.read()
if ret != 1:
    print "Error reading to first element"
    sys.exit(1)
if reader.name() != "a" or reader.isEmptyElement() != 0 or \
   reader.nodeType() != 1 or reader.hasAttributes() != 0:
    print "Error reading the first element"
    sys.exit(1)
ret = reader.read()
if ret != 1:
    print "Error reading to second element"
    sys.exit(1)
if reader.name() != "b" or reader.isEmptyElement() != 1 or \
   reader.nodeType() != 1 or reader.hasAttributes() != 1:
    print "Error reading the second element"
    sys.exit(1)
ret = reader.read()
if ret != 1:
    print "Error reading to third element"
    sys.exit(1)
if reader.name() != "c" or reader.isEmptyElement() != 0 or \
   reader.nodeType() != 1 or reader.hasAttributes() != 0:
    print "Error reading the third element"
    sys.exit(1)
ret = reader.read()
if ret != 1:
    print "Error reading to text node"
    sys.exit(1)
if reader.name() != "#text" or reader.isEmptyElement() != 0 or \
   reader.nodeType() != 3 or reader.hasAttributes() != 0 or \
   reader.value() != "content of c":
    print "Error reading the text node"
    sys.exit(1)
ret = reader.read()
if ret != 1:
    print "Error reading to end of third element"
    sys.exit(1)
if reader.name() != "c" or reader.isEmptyElement() != 0 or \
   reader.nodeType() != 15 or reader.hasAttributes() != 0:
    print "Error reading the end of third element"
    sys.exit(1)
ret = reader.read()
if ret != 1:
    print "Error reading to end of first element"
    sys.exit(1)
if reader.name() != "a" or reader.isEmptyElement() != 0 or \
   reader.nodeType() != 15 or reader.hasAttributes() != 0:
    print "Error reading the end of first element"
    sys.exit(1)
ret = reader.read()
if ret != 0:
    print "Error reading to end of document"
    sys.exit(1)

#
# example from the XmlTextReader docs
#
f = StringIO.StringIO("""<test xmlns:dt="urn:datatypes" dt:type="int"/>""")
input = libxml2.inputBuffer(f)
reader = input.newTextReader()

ret = reader.read()
if ret != 1:
    print "Error reading test element"
    sys.exit(1)
if reader.getAttributeNo(0) != "urn:datatypes" or \
   reader.getAttributeNo(1) != "int" or \
   reader.getAttributeNs("type", "urn:datatypes") != "int" or \
   reader.getAttribute("dt:type") != "int":
    print "error reading test attributes"
    sys.exit(1)

del f
del input
del reader

# Memory debug specific
libxml2.cleanupParser()
if libxml2.debugMemory(1) == 0:
    print "OK"
else:
    print "Memory leak %d bytes" % (libxml2.debugMemory(1))
    libxml2.dumpMemory()
