#!/usr/bin/python -u
#
# this tests the basic APIs of the XmlTextReader interface
#
import libxml2
import StringIO
import sys

# Memory debug specific
libxml2.debugMemory(1)

f = StringIO.StringIO("""<a><b b1="b1"/><c>content of c</c></a>""")
input = libxml2.inputBuffer(f)
reader = input.newTextReader("test1")
ret = reader.Read()
if ret != 1:
    print "Error reading to first element"
    sys.exit(1)
if reader.Name() != "a" or reader.IsEmptyElement() != 0 or \
   reader.NodeType() != 1 or reader.HasAttributes() != 0:
    print "Error reading the first element"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "Error reading to second element"
    sys.exit(1)
if reader.Name() != "b" or reader.IsEmptyElement() != 1 or \
   reader.NodeType() != 1 or reader.HasAttributes() != 1:
    print "Error reading the second element"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "Error reading to third element"
    sys.exit(1)
if reader.Name() != "c" or reader.IsEmptyElement() != 0 or \
   reader.NodeType() != 1 or reader.HasAttributes() != 0:
    print "Error reading the third element"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "Error reading to text node"
    sys.exit(1)
if reader.Name() != "#text" or reader.IsEmptyElement() != 0 or \
   reader.NodeType() != 3 or reader.HasAttributes() != 0 or \
   reader.Value() != "content of c":
    print "Error reading the text node"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "Error reading to end of third element"
    sys.exit(1)
if reader.Name() != "c" or reader.IsEmptyElement() != 0 or \
   reader.NodeType() != 15 or reader.HasAttributes() != 0:
    print "Error reading the end of third element"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "Error reading to end of first element"
    sys.exit(1)
if reader.Name() != "a" or reader.IsEmptyElement() != 0 or \
   reader.NodeType() != 15 or reader.HasAttributes() != 0:
    print "Error reading the end of first element"
    sys.exit(1)
ret = reader.Read()
if ret != 0:
    print "Error reading to end of document"
    sys.exit(1)

#
# example from the XmlTextReader docs
#
f = StringIO.StringIO("""<test xmlns:dt="urn:datatypes" dt:type="int"/>""")
input = libxml2.inputBuffer(f)
reader = input.newTextReader("test2")

ret = reader.Read()
if ret != 1:
    print "Error reading test element"
    sys.exit(1)
if reader.GetAttributeNo(0) != "urn:datatypes" or \
   reader.GetAttributeNo(1) != "int" or \
   reader.GetAttributeNs("type", "urn:datatypes") != "int" or \
   reader.GetAttribute("dt:type") != "int":
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
reader = input.newTextReader("test3")

ret = reader.Read()
while ret == 1:
    if reader.Name() == "ref":
        if reader.LookupNamespace("a") != "urn:456":
	    print "error resolving namespace prefix"
	    sys.exit(1)
	break
    ret = reader.Read()
if ret != 1:
    print "Error finding the ref element"
    sys.exit(1)

#
# Home made example for the various attribute access functions
#
f = StringIO.StringIO("""<testattr xmlns="urn:1" xmlns:a="urn:2" b="b" a:b="a:b"/>""")
input = libxml2.inputBuffer(f)
reader = input.newTextReader("test4")
ret = reader.Read()
if ret != 1:
    print "Error reading the testattr element"
    sys.exit(1)
#
# Attribute exploration by index
#
if reader.MoveToAttributeNo(0) != 1:
    print "Failed moveToAttribute(0)"
    sys.exit(1)
if reader.Value() != "urn:1":
    print "Failed to read attribute(0)"
    sys.exit(1)
if reader.Name() != "xmlns":
    print "Failed to read attribute(0) name"
    sys.exit(1)
if reader.MoveToAttributeNo(1) != 1:
    print "Failed moveToAttribute(1)"
    sys.exit(1)
if reader.Value() != "urn:2":
    print "Failed to read attribute(1)"
    sys.exit(1)
if reader.Name() != "xmlns:a":
    print "Failed to read attribute(1) name"
    sys.exit(1)
if reader.MoveToAttributeNo(2) != 1:
    print "Failed moveToAttribute(2)"
    sys.exit(1)
if reader.Value() != "b":
    print "Failed to read attribute(2)"
    sys.exit(1)
if reader.Name() != "b":
    print "Failed to read attribute(2) name"
    sys.exit(1)
if reader.MoveToAttributeNo(3) != 1:
    print "Failed moveToAttribute(3)"
    sys.exit(1)
if reader.Value() != "a:b":
    print "Failed to read attribute(3)"
    sys.exit(1)
if reader.Name() != "a:b":
    print "Failed to read attribute(3) name"
    sys.exit(1)
#
# Attribute exploration by name
#
if reader.MoveToAttribute("xmlns") != 1:
    print "Failed moveToAttribute('xmlns')"
    sys.exit(1)
if reader.Value() != "urn:1":
    print "Failed to read attribute('xmlns')"
    sys.exit(1)
if reader.MoveToAttribute("xmlns:a") != 1:
    print "Failed moveToAttribute('xmlns')"
    sys.exit(1)
if reader.Value() != "urn:2":
    print "Failed to read attribute('xmlns:a')"
    sys.exit(1)
if reader.MoveToAttribute("b") != 1:
    print "Failed moveToAttribute('b')"
    sys.exit(1)
if reader.Value() != "b":
    print "Failed to read attribute('b')"
    sys.exit(1)
if reader.MoveToAttribute("a:b") != 1:
    print "Failed moveToAttribute('a:b')"
    sys.exit(1)
if reader.Value() != "a:b":
    print "Failed to read attribute('a:b')"
    sys.exit(1)
if reader.MoveToAttributeNs("b", "urn:2") != 1:
    print "Failed moveToAttribute('b', 'urn:2')"
    sys.exit(1)
if reader.Value() != "a:b":
    print "Failed to read attribute('b', 'urn:2')"
    sys.exit(1)
#
# Go back and read in sequence
#
if reader.MoveToElement() != 1:
    print "Failed to move back to element"
    sys.exit(1)
if reader.MoveToFirstAttribute() != 1:
    print "Failed to move to first attribute"
    sys.exit(1)
if reader.Value() != "urn:1":
    print "Failed to read attribute(0)"
    sys.exit(1)
if reader.Name() != "xmlns":
    print "Failed to read attribute(0) name"
    sys.exit(1)
if reader.MoveToNextAttribute() != 1:
    print "Failed to move to next attribute"
    sys.exit(1)
if reader.Value() != "urn:2":
    print "Failed to read attribute(1)"
    sys.exit(1)
if reader.Name() != "xmlns:a":
    print "Failed to read attribute(1) name"
    sys.exit(1)
if reader.MoveToNextAttribute() != 1:
    print "Failed to move to next attribute"
    sys.exit(1)
if reader.Value() != "b":
    print "Failed to read attribute(2)"
    sys.exit(1)
if reader.Name() != "b":
    print "Failed to read attribute(2) name"
    sys.exit(1)
if reader.MoveToNextAttribute() != 1:
    print "Failed to move to next attribute"
    sys.exit(1)
if reader.Value() != "a:b":
    print "Failed to read attribute(3)"
    sys.exit(1)
if reader.Name() != "a:b":
    print "Failed to read attribute(3) name"
    sys.exit(1)
if reader.MoveToNextAttribute() != 0:
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
