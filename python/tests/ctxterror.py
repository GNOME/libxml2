#!/usr/bin/python -u
#
# This test exercise the redirection of error messages with a
# functions defined in Python.
#
import sys
import libxml2

# Memory debug specific
libxml2.debugMemory(1)

expect="""--> Opening and ending tag mismatch: x and y
"""

err=""
def callback(ctx, str):
     global err

     err = err + "%s %s" % (ctx, str)

s = """<x></y>"""

parserCtxt = libxml2.createPushParser(None,"",0,"test.xml")
parserCtxt.registerErrorHandler(callback, "-->")
parserCtxt.registerWarningHandler(callback, "-->")
parserCtxt.parseChunk(s,len(s),1)
doc = parserCtxt.doc()
doc.freeDoc()
parserCtxt = None

if err != expect:
    print "error"
    print "received %s" %(err)
    print "expected %s" %(expect)
    sys.exit(1)

i = 10000
while i > 0:
    parserCtxt = libxml2.createPushParser(None,"",0,"test.xml")
    parserCtxt.registerErrorHandler(callback, "-->")
    parserCtxt.registerWarningHandler(callback, "-->")
    parserCtxt.parseChunk(s,len(s),1)
    doc = parserCtxt.doc()
    doc.freeDoc()
    parserCtxt = None
    err = ""
    i = i - 1

# Memory debug specific
libxml2.cleanupParser()
if libxml2.debugMemory(1) == 0:
    print "OK"
else:
    print "Memory leak %d bytes" % (libxml2.debugMemory(1))
    libxml2.dumpMemory()
