""" A SAX2 driver for libxml2, on top of it's XmlReader API

USAGE
    # put this file (drv_libxml2.py) in PYTHONPATH
    import xml.sax
    reader = xml.sax.make_parser(["drv_libxml2"])
    # ...and the rest is standard python sax.

CAVEATS
    - Lexical handlers are supported, except for start/endEntity
      (waiting for XmlReader.ResolveEntity) and start/endDTD
    - as understand it, libxml2 error handlers are globals (per thread);
      each call to parse() registers a new error handler, 
      overwriting any previously registered handler 
      --> you can't have 2 LibXml2Reader active at the same time
    
TODO
    - search for TODO
    - some ErrorHandler events (warning)
    - some ContentHandler events (setDocumentLocator, skippedEntity)
    - EntityResolver (using libxml2.?)
    - DTDHandler (if/when libxml2 exposes such node types)
    - DeclHandler (if/when libxml2 exposes such node types)
    - property_xml_string?
    - feature_string_interning?
    - Incremental parser
    - additional performance tuning:
      - one might cache callbacks to avoid some name lookups
      - one might implement a smarter way to pass attributes to startElement
        (some kind of lazy evaluation?)
      - there might be room for improvement in start/endPrefixMapping
      - other?

"""

__author__  = u"Stéphane Bidoul <sbi@skynet.be>"
__version__ = "0.2"

import codecs
import sys
from types import StringType, UnicodeType
StringTypes = (StringType,UnicodeType)

from xml.sax._exceptions import *
from xml.sax import xmlreader, saxutils
from xml.sax.handler import \
     feature_namespaces, \
     feature_namespace_prefixes, \
     feature_string_interning, \
     feature_validation, \
     feature_external_ges, \
     feature_external_pes, \
     property_lexical_handler, \
     property_declaration_handler, \
     property_dom_node, \
     property_xml_string

# libxml2 returns strings as UTF8
_decoder = codecs.lookup("utf8")[1]
def _d(s):
    if s is None:
        return s
    else:
        return _decoder(s)[0]

try:
    import libxml2
except ImportError, e:
    raise SAXReaderNotAvailable("libxml2 not available: " \
                                "import error was: %s" % e)

def _registerErrorHandler(handler):
    if not sys.modules.has_key('libxslt'):
        # normal behaviour when libxslt is not imported
        libxml2.registerErrorHandler(handler,"drv_libxml2")
    else:
        # when libxslt is imported, one must
        # use libxst's error handler instead (see libxml2 bug 102181)
        import libxslt
        libxslt.registerErrorHandler(handler,"drv_libxml2")

class LibXml2Reader(xmlreader.XMLReader):

    def __init__(self):
        xmlreader.XMLReader.__init__(self)
        # features
        self.__ns = 0
        self.__nspfx = 0
        self.__validate = 0
        # parsing flag
        self.__parsing = 0
        # additional handlers
        self.__lex_handler = None
        self.__decl_handler = None
        # error messages accumulator
        self.__errors = None

    def _errorHandler(self,ctx,str):
        if self.__errors is None:
            self.__errors = []
        self.__errors.append(str)

    def _reportError(self,callback):
        # TODO: use SAXParseException, but we need a Locator for that
        # TODO: distinguish warnings from errors
        msg = "".join(self.__errors)
        self.__errors = None
        callback(SAXException(msg))

    def parse(self, source):
        self.__parsing = 1
        _registerErrorHandler(self._errorHandler)
        try:
            # prepare source and create reader
            if type(source) in StringTypes:
                reader = libxml2.newTextReaderFilename(source)
            else:
                source = saxutils.prepare_input_source(source)
                input = libxml2.inputBuffer(source.getByteStream())
                reader = input.newTextReader(source.getSystemId())
            # configure reader
            reader.SetParserProp(libxml2.PARSER_LOADDTD,1)
            reader.SetParserProp(libxml2.PARSER_DEFAULTATTRS,1)
            reader.SetParserProp(libxml2.PARSER_SUBST_ENTITIES,1)
            reader.SetParserProp(libxml2.PARSER_VALIDATE,self.__validate)
            # we reuse attribute maps (for a slight performance gain)
            if self.__ns:
                attributesNSImpl = xmlreader.AttributesNSImpl({},{})
            else:
                attributesImpl = xmlreader.AttributesImpl({})
            # prefixes to pop (for endPrefixMapping)
            prefixes = []
            # start loop
            self._cont_handler.startDocument()
            while 1:
                r = reader.Read()
                # check for errors
                if r == 1:
                    if not self.__errors is None:
                        # non-fatal error
                        self._reportError(self._err_handler.error)
                elif r == 0:
                    if not self.__errors is None:
                        # non-fatal error
                        self._reportError(self._err_handler.error)
                    break
                else:
                    # fatal error
                    if not self.__errors is None:
                        self._reportError(self._err_handler.fatalError)
                    else:
                        self._err_handler.fatalError(\
                            SAXException("Read failed (no details available)"))
                    break
                # get node type
                nodeType = reader.NodeType()
                # Element
                if nodeType == 1: 
                    if self.__ns:
                        eltName = (_d(reader.NamespaceUri()),\
                                   _d(reader.LocalName()))
                        eltQName = _d(reader.Name())
                        attributesNSImpl._attrs = attrs = {}
                        attributesNSImpl._qnames = qnames = {}
                        newPrefixes = []
                        while reader.MoveToNextAttribute():
                            qname = _d(reader.Name())
                            value = _d(reader.Value())
                            if qname.startswith("xmlns"):
                                if len(qname) > 5:
                                    newPrefix = qname[6:]
                                else:
                                    newPrefix = None
                                newPrefixes.append(newPrefix)
                                self._cont_handler.startPrefixMapping(\
                                    newPrefix,value)
                                if not self.__nspfx:
                                    continue # don't report xmlns attribute
                            attName = (_d(reader.NamespaceUri()),
                                       _d(reader.LocalName()))
                            qnames[attName] = qname
                            attrs[attName] = value
                        self._cont_handler.startElementNS( \
                            eltName,eltQName,attributesNSImpl) 
                        if reader.IsEmptyElement():
                            self._cont_handler.endElementNS(eltName,eltQName)
                            for newPrefix in newPrefixes:
                                self._cont_handler.endPrefixMapping(newPrefix)
                        else:
                            prefixes.append(newPrefixes)
                    else:
                        eltName = _d(reader.Name())
                        attributesImpl._attrs = attrs = {}
                        while reader.MoveToNextAttribute():
                            attName = _d(reader.Name())
                            attrs[attName] = _d(reader.Value())
                        self._cont_handler.startElement( \
                            eltName,attributesImpl)
                        if reader.IsEmptyElement():
                            self._cont_handler.endElement(eltName)
                # EndElement
                elif nodeType == 15: 
                    if self.__ns:
                        self._cont_handler.endElementNS( \
                             (_d(reader.NamespaceUri()),_d(reader.LocalName())),
                             _d(reader.Name()))
                        for prefix in prefixes.pop():
                            self._cont_handler.endPrefixMapping(prefix)
                    else:
                        self._cont_handler.endElement(_d(reader.Name()))
                # Text
                elif nodeType == 3: 
                    self._cont_handler.characters(_d(reader.Value()))
                # Whitespace
                elif nodeType == 13: 
                    self._cont_handler.ignorableWhitespace(_d(reader.Value()))
                # SignificantWhitespace
                elif nodeType == 14:
                    self._cont_handler.characters(_d(reader.Value()))
                # CDATA
                elif nodeType == 4:
                    if not self.__lex_handler is None:
                        self.__lex_handler.startCDATA()
                    self._cont_handler.characters(_d(reader.Value()))
                    if not self.__lex_handler is None:
                        self.__lex_handler.endCDATA()
                # EntityReference
                elif nodeType == 5:
                    if not self.__lex_handler is None:
                        self.startEntity(_d(reader.Name()))
                    reader.ResolveEntity()
                # EndEntity
                elif nodeType == 16:
                    if not self.__lex_handler is None:
                        self.endEntity(_d(reader.Name()))
                # ProcessingInstruction
                elif nodeType == 7: 
                    self._cont_handler.processingInstruction( \
                        _d(reader.Name()),_d(reader.Value()))
                # Comment
                elif nodeType == 8:
                    if not self.__lex_handler is None:
                        self.__lex_handler.comment(_d(reader.Value()))
                # DocumentType
                elif nodeType == 10:
                    #if not self.__lex_handler is None:
                    #    self.__lex_handler.startDTD()
                    pass # TODO (how to detect endDTD? on first non-dtd event?)
                # XmlDeclaration
                elif nodeType == 17:
                    pass # TODO
                # Entity
                elif nodeType == 6:
                    pass # TODO (entity decl)
                # Notation (decl)
                elif nodeType == 12:
                    pass # TODO
                # Attribute (never in this loop)
                #elif nodeType == 2: 
                #    pass
                # Document (not exposed)
                #elif nodeType == 9: 
                #    pass
                # DocumentFragment (never returned by XmlReader)
                #elif nodeType == 11:
                #    pass
                # None
                #elif nodeType == 0:
                #    pass
                # -
                else:
                    raise SAXException("Unexpected node type %d" % nodeType)
            if r == 0:
                self._cont_handler.endDocument()
            reader.Close()
        finally:
            self.__parsing = 0
            # TODO: unregister error handler?

    def setDTDHandler(self, handler):
        # TODO (when supported, the inherited method works just fine)
        raise SAXNotSupportedException("DTDHandler not supported")

    def setEntityResolver(self, resolver):
        # TODO (when supported, the inherited method works just fine)
        raise SAXNotSupportedException("EntityResolver not supported")

    def getFeature(self, name):
        if name == feature_namespaces:
            return self.__ns
        elif name == feature_namespace_prefixes:
            return self.__nspfx
        elif name == feature_validation:
            return self.__validate
        elif name == feature_external_ges:
            return 1 # TODO (does that relate to PARSER_LOADDTD)?
        elif name == feature_external_pes:
            return 1 # TODO (does that relate to PARSER_LOADDTD)?
        else:
            raise SAXNotRecognizedException("Feature '%s' not recognized" % \
                                            name)

    def setFeature(self, name, state):
        if self.__parsing:
            raise SAXNotSupportedException("Cannot set feature %s " \
                                           "while parsing" % name)
        if name == feature_namespaces:
            self.__ns = state
        elif name == feature_namespace_prefixes:
            self.__nspfx = state
        elif name == feature_validation:
            self.__validate = state
        elif name == feature_external_ges:
            if state == 0:
                # TODO (does that relate to PARSER_LOADDTD)?
                raise SAXNotSupportedException("Feature '%s' not supported" % \
                                               name)
        elif name == feature_external_pes:
            if state == 0:
                # TODO (does that relate to PARSER_LOADDTD)?
                raise SAXNotSupportedException("Feature '%s' not supported" % \
                                               name)
        else:
            raise SAXNotRecognizedException("Feature '%s' not recognized" % \
                                            name)

    def getProperty(self, name):
        if name == property_lexical_handler:
            return self.__lex_handler
        elif name == property_declaration_handler:
            return self.__decl_handler
        else:
            raise SAXNotRecognizedException("Property '%s' not recognized" % \
                                            name)

    def setProperty(self, name, value):     
        if name == property_lexical_handler:
            self.__lex_handler = value
        elif name == property_declaration_handler:
            # TODO: remove if/when libxml2 supports dtd events
            raise SAXNotSupportedException("Property '%s' not supported" % \
                                           name)
            self.__decl_handler = value
        else:
            raise SAXNotRecognizedException("Property '%s' not recognized" % \
                                            name)

def create_parser():
    return LibXml2Reader()

