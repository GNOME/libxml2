#!/usr/bin/python -u
import libxml2

doc = libxml2.parseFile("tst.xml")
print doc.name
root = doc.children
print root.name
child = root.children
print child.name
doc.freeDoc()
