#!/usr/bin/python -u
import sys
import libxml2
import StringIO

print "Skipped"
sys.exit(1)

# Memory debug specific
libxml2.debugMemory(1)

#f = open('res', 'w')
f = StringIO.StringIO()
buf = libxml2.createOutputBuffer(f, "ISO-8859-1")
buf.write(3, "foo")
buf.writeString("bar")
buf.close()
del buf

if f.getvalue() != "foobar":
    print "Failed to save to StringIO"
    sys.exit(1)

del f

# Memory debug specific
libxml2.cleanupParser()
if libxml2.debugMemory(1) == 0:
    print "OK"
else:
    print "Memory leak %d bytes" % (libxml2.debugMemory(1))
    libxml2.dumpMemory()

