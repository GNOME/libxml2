#!/usr/bin/python -u
import libxml2

def foo(x):
    # print "foo called %s" % (x)
    return x + 1

def bar(x):
    # print "foo called %s" % (x)
    return "%s" % (x + 1)

doc = libxml2.parseFile("tst.xml")
ctxt = doc.xpathNewContext()
res = ctxt.xpathEval("//*")
print res

libxml2.registerXPathFunction(ctxt._o, "foo", None, foo)
libxml2.registerXPathFunction(ctxt._o, "bar", None, bar)
i = 10000
while i > 0:
    res = ctxt.xpathEval("foo(1)")
    i = i - 1
print res
i = 10000
while i > 0:
    res = ctxt.xpathEval("bar(1)")
    i = i - 1
print res
doc.freeDoc()
