#!/usr/bin/python -u
#
# This test exercise the redirection of error messages with a
# functions defined in Python.
#
import sys
import libxml2

# Memory debug specific
libxml2.debugMemory(1)

expect='--> warning: --> failed to load external entity "missing.xml"\n'
err=""
def callback(ctx, str):
     global err

     err = err + "%s %s" % (ctx, str)

libxml2.registerErrorHandler(callback, "-->")
doc = libxml2.parseFile("missing.xml")
if err != expect:
    print "error"
    print "received %s" %(err)
    print "expected %s" %(expect)
    sys.exit(1)

i = 10000
while i > 0:
    doc = libxml2.parseFile("missing.xml")
    err = ""
    i = i - 1

# Memory debug specific
libxml2.cleanupParser()
if libxml2.debugMemory(1) == 0:
    print "OK"
else:
    print "Memory leak %d bytes" % (libxml2.debugMemory(1))
    libxml2.dumpMemory()
