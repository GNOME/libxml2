#!/usr/bin/env python3
#
# generate a test program for the API
#

import xml.etree.ElementTree as etree
import re
import sys

import xmlmod

# Globals

dtors = {
    'htmlDocPtr': 'xmlFreeDoc',
    'htmlParserCtxtPtr': 'htmlFreeParserCtxt',
    'xmlAutomataPtr': 'xmlFreeAutomata',
    'xmlBufferPtr': 'xmlBufferFree',
    'xmlCatalogPtr': 'xmlFreeCatalog',
    'xmlChar *': 'xmlFree',
    'xmlDOMWrapCtxtPtr': 'xmlDOMWrapFreeCtxt',
    'xmlDictPtr': 'xmlDictFree',
    'xmlDocPtr': 'xmlFreeDoc',
    'xmlDtdPtr': 'xmlFreeDtd',
    'xmlEntitiesTablePtr': 'xmlFreeEntitiesTable',
    'xmlEnumerationPtr': 'xmlFreeEnumeration',
    'xmlListPtr': 'xmlListDelete',
    'xmlModulePtr': 'xmlModuleFree',
    'xmlMutexPtr': 'xmlFreeMutex',
    'xmlNodePtr': 'xmlFreeNode',
    'xmlNodeSetPtr': 'xmlXPathFreeNodeSet',
    'xmlNsPtr': 'xmlFreeNs',
    'xmlOutputBufferPtr': 'xmlOutputBufferClose',
    'xmlParserCtxtPtr': 'xmlFreeParserCtxt',
    'xmlParserInputBufferPtr': 'xmlFreeParserInputBuffer',
    'xmlParserInputPtr': 'xmlFreeInputStream',
    'xmlRMutexPtr': 'xmlFreeRMutex',
    'xmlRelaxNGValidCtxtPtr': 'xmlRelaxNGFreeValidCtxt',
    'xmlSaveCtxtPtr': 'xmlSaveClose',
    'xmlSchemaFacetPtr': 'xmlSchemaFreeFacet',
    'xmlSchemaValPtr': 'xmlSchemaFreeValue',
    'xmlSchemaValidCtxtPtr': 'xmlSchemaFreeValidCtxt',
    'xmlTextWriterPtr': 'xmlFreeTextWriter',
    'xmlURIPtr': 'xmlFreeURI',
    'xmlValidCtxtPtr': 'xmlFreeValidCtxt',
    'xmlXPathContextPtr': 'xmlXPathFreeContext',
    'xmlXPathParserContextPtr': 'xmlXPathFreeParserContext',
    'xmlXPathObjectPtr': 'xmlXPathFreeObject',
}

blockList = {
    # init/cleanup
    'xmlCleanupParser': True,
    'xmlInitParser': True,

    # arg must be non-NULL
    'xmlMemStrdupLoc': True,
    'xmlMemoryStrdup': True,

    # Returns void pointer which must be freed
    'xmlMallocAtomicLoc': True,
    'xmlMallocLoc': True,
    'xmlMemMalloc': True,
    'xmlMemRealloc': True,
    'xmlReallocLoc': True,

    # Would reset the error handler
    'xmlSetStructuredErrorFunc': True,

    # Prints errors
    'xmlCatalogGetPublic': True,
    'xmlCatalogGetSystem': True,
    'xmlDebugDumpDTD': True,
    'xmlDebugDumpDocument': True,
    'xmlDebugDumpNode': True,
    'xmlDebugDumpString': True,
    'xmlParserError': True,
    'xmlParserWarning': True,
    'xmlParserValidityError': True,
    'xmlParserValidityWarning': True,

    # Internal parser unctions, ctxt must be non-NULL
    'xmlParseAttribute': True,
    'xmlParseAttributeListDecl': True,
    'xmlParseAttributeType': True,
    'xmlParseCDSect': True,
    'xmlParseCharData': True,
    'xmlParseCharRef': True,
    'xmlParseComment': True,
    'xmlParseDefaultDecl': True,
    'xmlParseDocTypeDecl': True,
    'xmlParseEndTag': True,
    'xmlParseElement': True,
    'xmlParseElementChildrenContentDecl': True,
    'xmlParseElementContentDecl': True,
    'xmlParseElementDecl': True,
    'xmlParseElementMixedContentDecl': True,
    'xmlParseEncName': True,
    'xmlParseEncodingDecl': True,
    'xmlParseEntityDecl': True,
    'xmlParseEntityValue': True,
    'xmlParseEnumeratedType': True,
    'xmlParseEnumerationType': True,
    'xmlParseExternalID': True,
    'xmlParseExternalSubset': True,
    'xmlParseMarkupDecl': True,
    'xmlParseMisc': True,
    'xmlParseName': True,
    'xmlParseNmtoken': True,
    'xmlParseNotationDecl': True,
    'xmlParseNotationType': True,
    'xmlParsePEReference': True,
    'xmlParsePI': True,
    'xmlParsePITarget': True,
    'xmlParsePubidLiteral': True,
    'xmlParseReference': True,
    'xmlParseSDDecl': True,
    'xmlParseStartTag': True,
    'xmlParseSystemLiteral': True,
    'xmlParseTextDecl': True,
    'xmlParseVersionInfo': True,
    'xmlParseVersionNum': True,
    'xmlParseXMLDecl': True,
    'xmlParserHandlePEReference': True,
    'xmlSkipBlankChars': True,

    # reads from stdin
    'htmlReadFd': True,
    'xmlReadFd': True,
    'xmlReaderForFd': True,
}

# Parse document

if len(sys.argv) > 1:
    srcPref = sys.argv[1] + '/'
else:
    srcPref = ''

doc = etree.parse(srcPref + 'doc/libxml2-api.xml')

# Create map of symbols to filenames

filenames = {}

for file in doc.find('files').findall('file'):
    filename = file.get('name')

    for export in file.findall('exports'):
        filenames[export.get('symbol')] = filename

# Process functions

functions = {}

for func in doc.find('symbols').findall('function'):
    name = func.get('name')
    if name in blockList:
        continue

    module1, module2 = xmlmod.findModules(filenames[name], name)

    cargs = []
    for arg in func.findall('arg'):
        atype = arg.get('type')
        if re.search(r'(Ptr|\*)$', atype):
            cargs.append('NULL')
        else:
            cargs.append('0')

    mfunc = functions.get(module1)
    if mfunc is None:
        mfunc = {}
        functions[module1] = mfunc

    mmfunc = mfunc.get(module2)
    if mmfunc is None:
        mmfunc = []
        mfunc[module2] = mmfunc

    code = f'{name}({', '.join(cargs)})'

    rtype = func.find('return').get('type')
    dtor = dtors.get(rtype)
    if dtor is not None:
        code = f'{dtor}({code})'
    elif rtype == 'xmlHashTablePtr':
        code = f'xmlHashFree({code}, NULL)'

    mmfunc.append(f'    {code};')

# Write output

test = open(srcPref + 'testapi.c', 'w')

test.write("""/*
 * testapi.c: libxml2 API tester program.
 *
 * Automatically generated by gentest.py from libxml2-api.xml
 *
 * See Copyright for the status of this software.
 */

/* Disable deprecation warnings */
#define XML_DEPRECATED

#include "libxml.h"
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/c14n.h>
#include <libxml/catalog.h>
#include <libxml/debugXML.h>
#include <libxml/parserInternals.h>
#include <libxml/pattern.h>
#include <libxml/relaxng.h>
#include <libxml/schematron.h>
#include <libxml/uri.h>
#include <libxml/xinclude.h>
#include <libxml/xlink.h>
#include <libxml/xmlmodule.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlschemastypes.h>
#include <libxml/xmlwriter.h>
#include <libxml/xpathInternals.h>
#include <libxml/xpointer.h>

static void
ignoreError(void *userData ATTRIBUTE_UNUSED,
            const xmlError *error ATTRIBUTE_UNUSED) {
}

int
main(int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED) {
    xmlInitParser();
    xmlSetStructuredErrorFunc(NULL, ignoreError);

""")

for module1 in sorted(functions.keys()):
    mfunc = functions[module1]

    if module1 != '':
        test.write(f'#ifdef LIBXML_{module1}_ENABLED\n')

    for module2 in sorted(mfunc.keys()):
        mmfunc = mfunc[module2]

        if module2 != '':
            test.write(f'#ifdef LIBXML_{module2}_ENABLED\n')

        for code in mmfunc:
            test.write(code + '\n')

        if module2 != '':
            test.write(f'#endif /* LIBXML_{module2}_ENABLED */\n')

    if module1 != '':
        test.write(f'#endif /* LIBXML_{module1}_ENABLED */\n')

    test.write('\n')

test.write("""    xmlCleanupParser();
    return 0;
}
""")
