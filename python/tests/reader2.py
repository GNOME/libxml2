#!/usr/bin/python -u
#
# this tests the DTD validation with the XmlTextReader interface
#
import sys
import glob
import string
import StringIO
import libxml2

# Memory debug specific
libxml2.debugMemory(1)

err=""
expect="""../../test/valid/xlink.xml:450: validity error: ID dt-arc already defined
	<p><termdef id="dt-arc" term="Arc">
                                   ^
../../test/valid/xlink.xml:529: validity error: attribute def line 199 references an unknown ID "dt-xlg"
<?Pub *0000052575?>
                   ^
../../test/valid/rss.xml:172: validity error: Element rss does not carry attribute version
</rss>
      ^
"""
def callback(ctx, str):
    global err
    err = err + "%s" % (str)
libxml2.registerErrorHandler(callback, "")

valid_files = files = glob.glob("../../test/valid/*.x*")
for file in valid_files:
    if string.find(file, "t8") != -1:
        continue
    reader = libxml2.newTextReaderFilename(file)
    #print "%s:" % (file)
    reader.SetParserProp(libxml2.PARSER_VALIDATE, 1)
    ret = reader.Read()
    while ret == 1:
        ret = reader.Read()
    if ret != 0:
        print "Error parsing and validating %s" % (file)
	#sys.exit(1)

if err != expect:
    print err

#
# another separate test based on Stephane Bidoul one
#
s = """
<!DOCTYPE test [
<!ELEMENT test (x,b)>
<!ELEMENT x (c)>
<!ELEMENT b (#PCDATA)>
<!ELEMENT c (#PCDATA)>
<!ENTITY x "<x><c>xxx</c></x>">
]>
<test>
    &x;
    <b>bbb</b>
</test>
"""
expect="""1,test
3,#text
1,x
1,c
3,#text
15,c
15,x
3,#text
1,b
3,#text
15,b
3,#text
15,test
"""
res=""
err=""

input = libxml2.inputBuffer(StringIO.StringIO(s))
reader = input.newTextReader("test2")
reader.SetParserProp(libxml2.PARSER_LOADDTD,1)
reader.SetParserProp(libxml2.PARSER_DEFAULTATTRS,1)
reader.SetParserProp(libxml2.PARSER_SUBST_ENTITIES,1)
reader.SetParserProp(libxml2.PARSER_VALIDATE,1)
while reader.Read() == 1:
    res = res + "%s,%s\n" % (reader.NodeType(),reader.Name())

if res != expect:
    print "test2 failed: unexpected output"
    print res
    sys.exit(1)
if err != "":
    print "test2 failed: validation error found"
    print err
    sys.exit(1)

del input
del reader

# Memory debug specific
libxml2.cleanupParser()
if libxml2.debugMemory(1) == 0:
    print "OK"
else:
    print "Memory leak %d bytes" % (libxml2.debugMemory(1))
    libxml2.dumpMemory()
