#!/usr/bin/python -u
#
# this tests the entities substitutions with the XmlTextReader interface
#
import sys
import StringIO
import libxml2

docstr="""<?xml version='1.0'?>
<!DOCTYPE doc [
<!ENTITY tst "<p>test</p>">
]>
<doc>&tst;</doc>"""

# Memory debug specific
libxml2.debugMemory(1)

#
# First test, normal don't substitute entities.
#
f = StringIO.StringIO(docstr)
input = libxml2.inputBuffer(f)
reader = input.newTextReader("test_noent")
ret = reader.Read()
if ret != 1:
    print "Error reading to root"
    sys.exit(1)
if reader.Name() == "doc" or reader.NodeType() == 10:
    ret = reader.Read()
if ret != 1:
    print "Error reading to root"
    sys.exit(1)
if reader.Name() != "doc" or reader.NodeType() != 1:
    print "test_normal: Error reading the root element"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "test_normal: Error reading to the entity"
    sys.exit(1)
if reader.Name() != "tst" or reader.NodeType() != 5:
    print "test_normal: Error reading the entity"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "test_normal: Error reading to the end of root"
    sys.exit(1)
if reader.Name() != "doc" or reader.NodeType() != 15:
    print "test_normal: Error reading the end of the root element"
    sys.exit(1)
ret = reader.Read()
if ret != 0:
    print "test_normal: Error detecting the end"
    sys.exit(1)

#
# Second test, completely substitute the entities.
#
f = StringIO.StringIO(docstr)
input = libxml2.inputBuffer(f)
reader = input.newTextReader("test_noent")
reader.SetParserProp(libxml2.PARSER_SUBST_ENTITIES, 1)
ret = reader.Read()
if ret != 1:
    print "Error reading to root"
    sys.exit(1)
if reader.Name() == "doc" or reader.NodeType() == 10:
    ret = reader.Read()
if ret != 1:
    print "Error reading to root"
    sys.exit(1)
if reader.Name() != "doc" or reader.NodeType() != 1:
    print "test_noent: Error reading the root element"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "test_noent: Error reading to the entity content"
    sys.exit(1)
if reader.Name() != "p" or reader.NodeType() != 1:
    print "test_noent: Error reading the p element from entity"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "test_noent: Error reading to the text node"
    sys.exit(1)
if reader.NodeType() != 3 or reader.Value() != "test":
    print "test_noent: Error reading the text node"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "test_noent: Error reading to the end of p element"
    sys.exit(1)
if reader.Name() != "p" or reader.NodeType() != 15:
    print "test_noent: Error reading the end of the p element"
    sys.exit(1)
ret = reader.Read()
if ret != 1:
    print "test_noent: Error reading to the end of root"
    sys.exit(1)
if reader.Name() != "doc" or reader.NodeType() != 15:
    print "test_noent: Error reading the end of the root element"
    sys.exit(1)
ret = reader.Read()
if ret != 0:
    print "test_noent: Error detecting the end"
    sys.exit(1)

#
# cleanup
#
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
