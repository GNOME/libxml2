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

#
# example from the XmlTextReader docs
#
f = StringIO.StringIO("""<root xmlns:a="urn:456">
<item>
<ref href="a:b"/>
</item>
</root>""")
input = libxml2.inputBuffer(f)
reader = input.newTextReader()

ret = reader.read()
while ret == 1:
    if reader.name() == "ref":
        if reader.lookupNamespace("a") != "urn:456":
	    print "error resolving namespace prefix"
	    sys.exit(1)
	break
    ret = reader.read()
if ret != 1:
    print "Error finding the ref element"
    sys.exit(1)

#
# Home made example for the various attribute access functions
#
f = StringIO.StringIO("""<testattr xmlns="urn:1" xmlns:a="urn:2" b="b" a:b="a:b"/>""")
input = libxml2.inputBuffer(f)
reader = input.newTextReader()
ret = reader.read()
if ret != 1:
    print "Error reading the testattr element"
    sys.exit(1)
#
# Attribute exploration by index
#
if reader.moveToAttributeNo(0) != 1:
    print "Failed moveToAttribute(0)"
    sys.exit(1)
if reader.value() != "urn:1":
    print "Failed to read attribute(0)"
    sys.exit(1)
if reader.name() != "xmlns":
    print "Failed to read attribute(0) name"
    sys.exit(1)
if reader.moveToAttributeNo(1) != 1:
    print "Failed moveToAttribute(1)"
    sys.exit(1)
if reader.value() != "urn:2":
    print "Failed to read attribute(1)"
    sys.exit(1)
if reader.name() != "xmlns:a":
    print "Failed to read attribute(1) name"
    sys.exit(1)
if reader.moveToAttributeNo(2) != 1:
    print "Failed moveToAttribute(2)"
    sys.exit(1)
if reader.value() != "b":
    print "Failed to read attribute(2)"
    sys.exit(1)
if reader.name() != "b":
    print "Failed to read attribute(2) name"
    sys.exit(1)
if reader.moveToAttributeNo(3) != 1:
    print "Failed moveToAttribute(3)"
    sys.exit(1)
if reader.value() != "a:b":
    print "Failed to read attribute(3)"
    sys.exit(1)
if reader.name() != "a:b":
    print "Failed to read attribute(3) name"
    sys.exit(1)
#
# Attribute exploration by name
#
if reader.moveToAttribute("xmlns") != 1:
    print "Failed moveToAttribute('xmlns')"
    sys.exit(1)
if reader.value() != "urn:1":
    print "Failed to read attribute('xmlns')"
    sys.exit(1)
if reader.moveToAttribute("xmlns:a") != 1:
    print "Failed moveToAttribute('xmlns')"
    sys.exit(1)
if reader.value() != "urn:2":
    print "Failed to read attribute('xmlns:a')"
    sys.exit(1)
if reader.moveToAttribute("b") != 1:
    print "Failed moveToAttribute('b')"
    sys.exit(1)
if reader.value() != "b":
    print "Failed to read attribute('b')"
    sys.exit(1)
if reader.moveToAttribute("a:b") != 1:
    print "Failed moveToAttribute('a:b')"
    sys.exit(1)
if reader.value() != "a:b":
    print "Failed to read attribute('a:b')"
    sys.exit(1)
if reader.moveToAttributeNs("b", "urn:2") != 1:
    print "Failed moveToAttribute('b', 'urn:2')"
    sys.exit(1)
if reader.value() != "a:b":
    print "Failed to read attribute('b', 'urn:2')"
    sys.exit(1)
#
# Go back and read in sequence
#
if reader.moveToElement() != 1:
    print "Failed to move back to element"
    sys.exit(1)
if reader.moveToFirstAttribute() != 1:
    print "Failed to move to first attribute"
    sys.exit(1)
if reader.value() != "urn:1":
    print "Failed to read attribute(0)"
    sys.exit(1)
if reader.name() != "xmlns":
    print "Failed to read attribute(0) name"
    sys.exit(1)
if reader.moveToNextAttribute() != 1:
    print "Failed to move to next attribute"
    sys.exit(1)
if reader.value() != "urn:2":
    print "Failed to read attribute(1)"
    sys.exit(1)
if reader.name() != "xmlns:a":
    print "Failed to read attribute(1) name"
    sys.exit(1)
if reader.moveToNextAttribute() != 1:
    print "Failed to move to next attribute"
    sys.exit(1)
if reader.value() != "b":
    print "Failed to read attribute(2)"
    sys.exit(1)
if reader.name() != "b":
    print "Failed to read attribute(2) name"
    sys.exit(1)
if reader.moveToNextAttribute() != 1:
    print "Failed to move to next attribute"
    sys.exit(1)
if reader.value() != "a:b":
    print "Failed to read attribute(3)"
    sys.exit(1)
if reader.name() != "a:b":
    print "Failed to read attribute(3) name"
    sys.exit(1)
if reader.moveToNextAttribute() != 0:
    print "Failed to detect last attribute"
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
