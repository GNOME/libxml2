#!/usr/bin/python -u
import sys
import libxml2

doc = libxml2.parseFile("tst.xml")
if doc.name != "tst.xml":
    print "doc.name failed"
    sys.exit(1)
root = doc.children
if root.name != "doc":
    print "root.name failed"
    sys.exit(1)
child = root.children
if child.name != "foo":
    print "child.name failed"
    sys.exit(1)
doc.freeDoc()
print "OK"
