#!/usr/bin/python -u
#
# this test exercise the XPath basic engine, parser, etc, and
# allows to detect memory leaks
#
import libxml2

doc = libxml2.parseFile("tst.xml")
print doc
i = 1000
while i > 0:
    doc = libxml2.parseFile("tst.xml")
    ctxt = doc.xpathNewContext()
    res = ctxt.xpathEval("//*")
    doc.freeDoc()
    i = i -1
doc = libxml2.parseFile("tst.xml")
ctxt = doc.xpathNewContext()
res = ctxt.xpathEval("//*")
print res
doc.freeDoc()
