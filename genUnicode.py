#!/usr/bin/python -u
#
# Original script modified in November 2003 to take advantage of
# the character-validation range routines, and updated to the
# current Unicode information (Version 4.0.1)
#
# NOTE: there is an 'alias' facility for blocks which are not present in
#	the current release, but are needed for ABI compatibility.  This
#	must be accomplished MANUALLY!  Define the alias in the variable
#	'blockAliases', then MANUALLY provide a function to return the
#	appropriate value.
#
import sys
import string
import time

webpage = "http://www.unicode.org/Public/4.0-Update1/UCD-4.0.1d5b.html"
sources = "Blocks-4.0.1d1b.txt UnicodeData-4.0.1d1b.txt"

blockAliases = "CombiningMarksforSymbols Greek PrivateUse"

# minTableSize gives the minimum number of ranges which must be present
# before a range table is produced.  If there are less than this
# number, inline comparisons are generated
minTableSize = 8

(blockfile, catfile) = string.split(sources)

#
# First create a dictionary for the block names
#
BlockNames = {}

#
# Next put in aliases for blocks not currently present, but needed
# for ABI compatibility (THIS IS A HORRIBLE HACK!)
#
aliases = string.split(blockAliases, ' ')
for name in aliases:
    BlockNames[name] = []

#
# Now process the "blocks" file, reducing it to a dictionary
# indexed by blockname, containing a tuple with the applicable
# block range
#
try:
    blocks = open(blockfile, "r")
except:
    print "Missing %s, aborting ..." % blockfile
    sys.exit(1)

for line in blocks.readlines():
    if line[0] == '#':
        continue
    line = string.strip(line)
    if line == '':
        continue
    try:
        fields = string.split(line, ';')
        range = string.strip(fields[0])
        (start, end) = string.split(range, "..")
        name = string.strip(fields[1])
        name = string.replace(name, ' ', '')
    except:
        print "Failed to process line: %s" % (line)
        continue
    BlockNames[name] = ("0x"+start, "0x"+end)
blocks.close()
print "Parsed %d blocks descriptions" % (len(BlockNames.keys()))

#
# Next process the Categories file. This is more complex, since
# the file is in code sequence, and we need to invert it.  We use
# a dictionary with index category-name, with each entry containing
# all the ranges (codepoints) of that category.  Note that category
# names comprise two parts - the general category, and the "subclass"
# within that category.  Therefore, both "general category" (which is
# the first character of the 2-character category-name) and the full
# (2-character) name are entered into this dictionary.
#
try:
    data = open(catfile, "r")
except:
    print "Missing %s, aborting ..." % catfile
    sys.exit(1)

nbchar = 0;
Categories = {}
for line in data.readlines():
    if line[0] == '#':
        continue
    line = string.strip(line)
    if line == '':
        continue
    try:
        fields = string.split(line, ';')
        point = string.strip(fields[0])
        value = 0
        while point != '':
            value = value * 16
            if point[0] >= '0' and point[0] <= '9':
                value = value + ord(point[0]) - ord('0')
            elif point[0] >= 'A' and point[0] <= 'F':
                value = value + 10 + ord(point[0]) - ord('A')
            elif point[0] >= 'a' and point[0] <= 'f':
                value = value + 10 + ord(point[0]) - ord('a')
            point = point[1:]
        name = fields[2]
    except:
        print "Failed to process line: %s" % (line)
        continue
    
    nbchar = nbchar + 1
    # update entry for "full name"
    try:
        Categories[name].append(value)
    except:
        try:
            Categories[name] = [value]
        except:
            print "Failed to process line: %s" % (line)
    # update "general category" name
    try:
        Categories[name[0]].append(value)
    except:
        try:
            Categories[name[0]] = [value]
        except:
            print "Failed to process line: %s" % (line)

blocks.close()
print "Parsed %d char generating %d categories" % (nbchar, len(Categories.keys()))

#
# The data is now all read.  Time to process it into a more useful form.
#
# reduce the number list into ranges
for cat in Categories.keys():
    list = Categories[cat]
    start = -1
    prev = -1
    end = -1
    ranges = []
    for val in list:
        if start == -1:
            start = val
            prev = val
            continue
        elif val == prev + 1:
            prev = val
            continue
        elif prev == start:
            ranges.append((prev, prev))
            start = val
            prev = val
            continue
        else:
            ranges.append((start, prev))
            start = val
            prev = val
            continue
    if prev == start:
        ranges.append((prev, prev))
    else:
        ranges.append((start, prev))
    Categories[cat] = ranges

#
# Assure all data is in alphabetic order, since we will be doing binary
# searches on the tables.
#
bkeys = BlockNames.keys()
bkeys.sort()

ckeys = Categories.keys()
ckeys.sort()

#
# Generate the resulting files
#
try:
    header = open("include/libxml/xmlunicode.h", "w")
except:
    print "Failed to open include/libxml/xmlunicode.h"
    sys.exit(1)

try:
    output = open("xmlunicode.c", "w")
except:
    print "Failed to open xmlunicode.c"
    sys.exit(1)

date = time.asctime(time.localtime(time.time()))

header.write(
"""/*
 * xmlunicode.h: this header exports interfaces for the Unicode character APIs
 *
 * This file is automatically generated from the
 * UCS description files of the Unicode Character Database
 * %s
 * using the genUnicode.py Python script.
 *
 * Generation date: %s
 * Sources: %s
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __XML_UNICODE_H__
#define __XML_UNICODE_H__

#include <libxml/xmlversion.h>

#ifdef __cplusplus
extern "C" {
#endif

""" % (webpage, date, sources));

output.write(
"""/*
 * xmlunicode.c: this module implements the Unicode character APIs
 *
 * This file is automatically generated from the
 * UCS description files of the Unicode Character Database
 * %s
 * using the genUnicode.py Python script.
 *
 * Generation date: %s
 * Sources: %s
 * Daniel Veillard <veillard@redhat.com>
 */

#define IN_LIBXML
#include "libxml.h"

#ifdef LIBXML_UNICODE_ENABLED

#include <string.h>
#include <libxml/xmlversion.h>
#include <libxml/xmlunicode.h>
#include <libxml/chvalid.h>

typedef int (xmlIntFunc)(int);	/* just to keep one's mind untwisted */

typedef struct {
    const char *rangename;
    xmlIntFunc *func;
} xmlUnicodeRange;

typedef struct {
    xmlUnicodeRange *table;
    int		    numentries;
} xmlUnicodeNameTable;


static xmlIntFunc *xmlUnicodeLookup(xmlUnicodeNameTable *tptr, const char *tname);

static xmlUnicodeRange xmlUnicodeBlocks[] = {
""" % (webpage, date, sources));

flag = 0
for block in bkeys:
    name = string.replace(block, '-', '')
    if flag:
        output.write(',\n')
    else:
        flag = 1
    output.write('  {"%s", xmlUCSIs%s}' % (name, name))
output.write('};\n\n')

output.write('static xmlUnicodeRange xmlUnicodeCats[] = {\n')
flag = 0;
for name in ckeys:
    if flag:
        output.write(',\n')
    else:
        flag = 1
    output.write('  {"%s", xmlUCSIsCat%s}' % (name, name))
output.write('};\n\n')

#
# For any categories with more than minTableSize ranges we generate
# a range table suitable for xmlCharInRange
#
for name in ckeys:
  if len(Categories[name]) > minTableSize:
    numshort = 0
    numlong = 0
    ranges = Categories[name]
    sptr = "NULL"
    lptr = "NULL"
    for range in ranges:
      (low, high) = range
      if high < 0x10000:
        if numshort == 0:
          pline = "static xmlChSRange xml%sS[] = {" % name
          sptr = "xml%sS" % name
        else:
          pline += ", "
        numshort += 1
      else:
        if numlong == 0:
          if numshort > 0:
            output.write(pline + " };\n")
          pline = "static xmlChLRange xml%sL[] = {" % name
          lptr = "xml%sL" % name
        else:
          pline += ", "
        numlong += 1
      if len(pline) > 60:
        output.write(pline + "\n")
        pline = "    "
      pline += "{%s, %s}" % (hex(low), hex(high))
    output.write(pline + " };\nstatic xmlChRangeGroup xml%sG = {%s,%s,%s,%s};\n\n"
         % (name, numshort, numlong, sptr, lptr))


output.write(
"""xmlUnicodeNameTable xmlUnicodeBlockTbl = {xmlUnicodeBlocks, %s};
xmlUnicodeNameTable xmlUnicodeCatTbl = {xmlUnicodeCats, %s};

/**
 * xmlUnicodeLookup:
 * @tptr: pointer to the name table
 * @name: name to be found
 *
 * binary table lookup for user-supplied name
 *
 * Returns pointer to range function if found, otherwise NULL
 */
static xmlIntFunc
*xmlUnicodeLookup(xmlUnicodeNameTable *tptr, const char *tname) {
    int low, high, mid, cmp;
    xmlUnicodeRange *sptr;

    low = 0;
    high = tptr->numentries - 1;
    sptr = tptr->table;
    while (low <= high) {
	mid = (low + high) / 2;
	if ((cmp=strcmp(tname, sptr[mid].rangename)) == 0)
	    return (sptr[mid].func);
	if (cmp < 0)
	    high = mid - 1;
	else
	    low = mid + 1;
    }
    return (NULL);    
}

""" % (len(BlockNames), len(Categories)) )

for block in bkeys:
    name = string.replace(block, '-', '')
    header.write("XMLPUBFUN int XMLCALL xmlUCSIs%s\t(int code);\n" % name)
    if len(BlockNames[block]) == 0:	# ignore aliases
        continue
    (start, end) = BlockNames[block]
    output.write("/**\n * xmlUCSIs%s:\n * @code: UCS code point\n" % (name))
    output.write(" *\n * Check whether the character is part of %s UCS Block\n"%
                 (block))
    output.write(" *\n * Returns 1 if true 0 otherwise\n */\n");
    output.write("int\nxmlUCSIs%s(int code) {\n" % name)
    output.write("    return((code >= %s) && (code <= %s));\n" % (start, end))
    output.write("}\n\n")

header.write("\nXMLPUBFUN int XMLCALL xmlUCSIsBlock\t(int code, const char *block);\n\n")
output.write(
"""/**
 * xmlUCSIsBlock:
 * @code: UCS code point
 * @block: UCS block name
 *
 * Check whether the character is part of the UCS Block
 *
 * Returns 1 if true, 0 if false and -1 on unknown block
 */
int
xmlUCSIsBlock(int code, const char *block) {
    xmlIntFunc *func;

    func = xmlUnicodeLookup(&xmlUnicodeBlockTbl, block);
    if (func == NULL)
	return (-1);
    return (func(code));
}

""")

for name in ckeys:
    ranges = Categories[name]
    header.write("XMLPUBFUN int XMLCALL xmlUCSIsCat%s\t(int code);\n" % name)
    output.write("/**\n * xmlUCSIsCat%s:\n * @code: UCS code point\n" % (name))
    output.write(" *\n * Check whether the character is part of %s UCS Category\n"%
                 (name))
    output.write(" *\n * Returns 1 if true 0 otherwise\n */\n");
    output.write("int\nxmlUCSIsCat%s(int code) {\n" % name)
    if len(Categories[name]) > minTableSize:
        output.write("    return(xmlCharInRange((unsigned int)code, &xml%sG)"
            % name)
    else:
        start = 1
        for range in ranges:
            (begin, end) = range;
            if start:
                output.write("    return(");
                start = 0
            else:
                output.write(" ||\n           ");
            if (begin == end):
                output.write("(code == %s)" % (hex(begin)))
            else:
                output.write("((code >= %s) && (code <= %s))" % (
                         hex(begin), hex(end)))
    output.write(");\n}\n\n")

header.write("\nXMLPUBFUN int XMLCALL xmlUCSIsCat\t(int code, const char *cat);\n")
output.write(
"""/**
 * xmlUCSIsCat:
 * @code: UCS code point
 * @cat: UCS Category name
 *
 * Check whether the character is part of the UCS Category
 *
 * Returns 1 if true, 0 if false and -1 on unknown category
 */
int
xmlUCSIsCat(int code, const char *cat) {
    xmlIntFunc *func;

    func = xmlUnicodeLookup(&xmlUnicodeCatTbl, cat);
    if (func == NULL)
	return (-1);
    return (func(code));
}

/*
    The following routines are an UGLY HACK to provide aliases for block
    names which are not in the current release, but are needed for ABI
    compatibility.
*/

/**
 * xmlUCSIsCombiningMarksforSymbols:
 * @code: UCS code point
 *
 * Check whether the character is part of CombiningMarksforSymbols UCS Block
 *
 * Returns 1 if true 0 otherwise
 */
int
xmlUCSIsCombiningMarksforSymbols(int code) {
    return((code >= 0x20D0) && (code <= 0x20FF));
}

/**
 * xmlUCSIsGreek:
 * @code: UCS code point
 *
 * Check whether the character is part of Greek UCS Block
 *
 * Returns 1 if true 0 otherwise
 */
int
xmlUCSIsGreek(int code) {
    return((code >= 0x370) && (code <= 0x3FF));
}

/**
 * xmlUCSIsPrivateUse:
 * @code: UCS code point
 *
 * Check whether the character is part of PrivateUse UCS Block
 *
 * Returns 1 if true 0 otherwise
 */
int
xmlUCSIsPrivateUse(int code) {
    if ( ((code >= 0xE000)  && (code <= 0xF8FF)) ||
	 ((code >= 0xF0000) && (code <= 0xFFFFD))||
	 ((code >= 0x100000)&& (code <= 0x10FFFD)) )
	return (1);
    else
	return (0);
}


#endif /* LIBXML_UNICODE_ENABLED */
""")

header.write("""
#ifdef __cplusplus
}
#endif
#endif /* __XML_UNICODE_H__ */
""");

header.close()
output.close()
