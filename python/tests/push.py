#!/usr/bin/python -u
import sys
import libxml2

ctxt = libxml2.createPushParser(None, "<foo", 4, "test.xml")
ctxt.parseChunk("/>", 2, 1)
doc = ctxt.doc()
ctxt=None
if doc.name != "test.xml":
    print "document name error"
    sys.exit(1)
root = doc.children
if root.name != "foo":
    print "root element name error"
    sys.exit(1)
doc.freeDoc()
i = 10000
while i > 0:
    ctxt = libxml2.createPushParser(None, "<foo", 4, "test.xml")
    ctxt.parseChunk("/>", 2, 1)
    doc = ctxt.doc()
    doc.freeDoc()
    i = i -1
ctxt=None
print "OK"
