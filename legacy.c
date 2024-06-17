/*
 * legacy.c: set of deprecated routines, not to be used anymore but
 *           kept purely for ABI compatibility
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#define IN_LIBXML
#include "libxml.h"

#ifdef LIBXML_LEGACY_ENABLED
#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>

/************************************************************************
 *									*
 *		Deprecated functions kept for compatibility		*
 *									*
 ************************************************************************/

#ifdef LIBXML_HTML_ENABLED
XMLPUBFUN xmlChar *
htmlDecodeEntities(void *ctxt, int len, xmlChar end, xmlChar end2,
                   xmlChar end3);

xmlChar *
htmlDecodeEntities(void *ctxt ATTRIBUTE_UNUSED, int len ATTRIBUTE_UNUSED,
                   xmlChar end ATTRIBUTE_UNUSED, xmlChar end2 ATTRIBUTE_UNUSED,
                   xmlChar end3 ATTRIBUTE_UNUSED) {
    return (NULL);
}
#endif

/*
 * entities.h
 */

XMLPUBFUN void
xmlInitializePredefinedEntities(void);

void
xmlInitializePredefinedEntities(void) {
}

XMLPUBFUN void
xmlCleanupPredefinedEntities(void);

void
xmlCleanupPredefinedEntities(void) {
}

XMLPUBFUN const xmlChar *
xmlEncodeEntities(void *doc, const xmlChar *input);

const xmlChar *
xmlEncodeEntities(void *doc ATTRIBUTE_UNUSED,
                  const xmlChar *input ATTRIBUTE_UNUSED) {
    return (NULL);
}

/*
 * parser.h
 *
 * Headers are public for now.
 */

int
xmlGetFeaturesList(int *len, const char **result ATTRIBUTE_UNUSED) {
    *len = 0;
    return(0);
}

int
xmlGetFeature(xmlParserCtxtPtr ctxt ATTRIBUTE_UNUSED,
              const char *name ATTRIBUTE_UNUSED,
              void *result ATTRIBUTE_UNUSED) {
    return(-1);
}

int
xmlSetFeature(xmlParserCtxtPtr ctxt ATTRIBUTE_UNUSED,
              const char *name ATTRIBUTE_UNUSED,
              void *value ATTRIBUTE_UNUSED) {
    return(-1);
}

/*
 * parserInternals.h
 */

XMLPUBFUN xmlChar *
xmlDecodeEntities(void *ctxt, int len, int what, xmlChar end, xmlChar end2,
                  xmlChar end3);

xmlChar *
xmlDecodeEntities(void *ctxt ATTRIBUTE_UNUSED, int len ATTRIBUTE_UNUSED,
                  int what ATTRIBUTE_UNUSED, xmlChar end ATTRIBUTE_UNUSED,
                  xmlChar end2 ATTRIBUTE_UNUSED,
                  xmlChar end3 ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN xmlChar *
xmlNamespaceParseNCName(void *ctxt);

xmlChar *
xmlNamespaceParseNCName(void *ctxt ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN xmlChar *
xmlNamespaceParseQName(void *ctxt, xmlChar **prefix);

xmlChar *
xmlNamespaceParseQName(void *ctxt ATTRIBUTE_UNUSED,
                       xmlChar **prefix ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN xmlChar *
xmlNamespaceParseNSDef(void *ctxt);

xmlChar *
xmlNamespaceParseNSDef(void *ctxt ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN xmlChar *
xmlParseQuotedString(void *ctxt);

xmlChar *
xmlParseQuotedString(void *ctxt ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN void
xmlParseNamespace(void *ctxt);

void
xmlParseNamespace(void *ctxt ATTRIBUTE_UNUSED) {
}

XMLPUBFUN xmlChar *
xmlScanName(void *ctxt);

xmlChar *
xmlScanName(void *ctxt ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN void
xmlParserHandleReference(void *ctxt);

void
xmlParserHandleReference(void *ctxt ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
xmlHandleEntity(void *ctxt, void *entity);

void
xmlHandleEntity(void *ctxt ATTRIBUTE_UNUSED, void *entity ATTRIBUTE_UNUSED) {
}

typedef	void
(*xmlEntityReferenceFunc)(void *ent, void *firstNode, void *lastNode);

XMLPUBFUN void
xmlSetEntityReferenceFunc(xmlEntityReferenceFunc func);

void
xmlSetEntityReferenceFunc(xmlEntityReferenceFunc func ATTRIBUTE_UNUSED) {
}

/*
 * tree.h
 */

XMLPUBFUN void *
xmlNewGlobalNs(void *doc, const xmlChar *href, const xmlChar *prefix);

void *
xmlNewGlobalNs(void *doc ATTRIBUTE_UNUSED,
               const xmlChar *href ATTRIBUTE_UNUSED,
               const xmlChar *prefix ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN void
xmlUpgradeOldNs(void *doc);

void
xmlUpgradeOldNs(void *doc ATTRIBUTE_UNUSED) {
}

/*
 * SAX.h
 */

XMLPUBFUN const xmlChar *
getPublicId(void *ctx);

const xmlChar *
getPublicId(void *ctx ATTRIBUTE_UNUSED){
    return(NULL);
}

XMLPUBFUN const xmlChar *
getSystemId(void *ctx);

const xmlChar *
getSystemId(void *ctx ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN int
getLineNumber(void *ctx);

int
getLineNumber(void *ctx ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
getColumnNumber(void *ctx);

int
getColumnNumber(void *ctx ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
isStandalone(void *ctx);

int
isStandalone(void *ctx ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
hasInternalSubset(void *ctx);

int
hasInternalSubset(void *ctx ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
hasExternalSubset(void *ctx);

int
hasExternalSubset(void *ctx ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN void
internalSubset(void *ctx, const xmlChar *name,
               const xmlChar *ExternalID, const xmlChar *SystemID);

void
internalSubset(void *ctx ATTRIBUTE_UNUSED,
               const xmlChar *name ATTRIBUTE_UNUSED,
               const xmlChar *ExternalID ATTRIBUTE_UNUSED,
               const xmlChar *SystemID ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
externalSubset(void *ctx, const xmlChar *name,
               const xmlChar *ExternalID, const xmlChar *SystemID);

void
externalSubset(void *ctx ATTRIBUTE_UNUSED,
               const xmlChar *name ATTRIBUTE_UNUSED,
               const xmlChar *ExternalID ATTRIBUTE_UNUSED,
               const xmlChar *SystemID ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void *
resolveEntity(void *ctx, const xmlChar * publicId,
              const xmlChar * systemId);

void *
resolveEntity(void *ctx ATTRIBUTE_UNUSED,
              const xmlChar * publicId ATTRIBUTE_UNUSED,
              const xmlChar * systemId ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
getEntity(void *ctx, const xmlChar *name);

void *
getEntity(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
getParameterEntity(void *ctx, const xmlChar *name);

void *
getParameterEntity(void *ctx ATTRIBUTE_UNUSED,
                   const xmlChar *name ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void
entityDecl(void *ctx, const xmlChar *name, int type,
           const xmlChar *publicId, const xmlChar *systemId,
           xmlChar *content);

void
entityDecl(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name ATTRIBUTE_UNUSED,
           int type ATTRIBUTE_UNUSED, const xmlChar *publicId ATTRIBUTE_UNUSED,
           const xmlChar *systemId ATTRIBUTE_UNUSED,
           xmlChar *content ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
attributeDecl(void *ctx, const xmlChar *elem, const xmlChar *fullname,
              int type, int def, const xmlChar *defaultValue, void *tree);

void
attributeDecl(void *ctx ATTRIBUTE_UNUSED,
              const xmlChar *elem ATTRIBUTE_UNUSED,
              const xmlChar *fullname ATTRIBUTE_UNUSED,
              int type ATTRIBUTE_UNUSED, int def ATTRIBUTE_UNUSED,
              const xmlChar *defaultValue ATTRIBUTE_UNUSED,
              void *tree ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
elementDecl(void *ctx, const xmlChar *name, int type, void *content);

void
elementDecl(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name ATTRIBUTE_UNUSED,
            int type ATTRIBUTE_UNUSED, void *content ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
notationDecl(void *ctx, const xmlChar *name, const xmlChar *publicId,
             const xmlChar *systemId);

void
notationDecl(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name ATTRIBUTE_UNUSED,
             const xmlChar *publicId ATTRIBUTE_UNUSED,
             const xmlChar *systemId ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
unparsedEntityDecl(void *ctx, const xmlChar *name, const xmlChar *publicId,
                   const xmlChar *systemId, const xmlChar *notationName);

void
unparsedEntityDecl(void *ctx ATTRIBUTE_UNUSED,
                   const xmlChar *name ATTRIBUTE_UNUSED,
                   const xmlChar *publicId ATTRIBUTE_UNUSED,
                   const xmlChar *systemId ATTRIBUTE_UNUSED,
                   const xmlChar *notationName ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
setDocumentLocator(void *ctx, void *loc);

void
setDocumentLocator(void *ctx ATTRIBUTE_UNUSED, void *loc ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
startDocument(void *ctx);

void
startDocument(void *ctx ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
endDocument(void *ctx);

void
endDocument(void *ctx ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
attribute(void *ctx, const xmlChar *fullname, const xmlChar *value);

void
attribute(void *ctx ATTRIBUTE_UNUSED, const xmlChar *fullname ATTRIBUTE_UNUSED,
          const xmlChar *value ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
startElement(void *ctx, const xmlChar *fullname, const xmlChar **atts);

void
startElement(void *ctx ATTRIBUTE_UNUSED,
             const xmlChar *fullname ATTRIBUTE_UNUSED,
             const xmlChar **atts ATTRIBUTE_UNUSED) {
    xmlSAX2StartElement(ctx, fullname, atts);
}

XMLPUBFUN void
endElement(void *ctx, const xmlChar *name);

void
endElement(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
reference(void *ctx, const xmlChar *name);

void
reference(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
characters(void *ctx, const xmlChar *ch, int len);

void
characters(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch ATTRIBUTE_UNUSED,
           int len ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
ignorableWhitespace(void *ctx, const xmlChar *ch, int len);

void
ignorableWhitespace(void *ctx ATTRIBUTE_UNUSED,
                    const xmlChar *ch ATTRIBUTE_UNUSED,
                    int len ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
processingInstruction(void *ctx, const xmlChar *target, const xmlChar *data);

void
processingInstruction(void *ctx ATTRIBUTE_UNUSED,
                      const xmlChar *target ATTRIBUTE_UNUSED,
                      const xmlChar *data ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
globalNamespace(void *ctx, const xmlChar *href, const xmlChar *prefix);

void
globalNamespace(void *ctx ATTRIBUTE_UNUSED,
                const xmlChar *href ATTRIBUTE_UNUSED,
                const xmlChar *prefix ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
setNamespace(void *ctx, const xmlChar *name);

void
setNamespace(void *ctx ATTRIBUTE_UNUSED,
             const xmlChar *name ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void *
getNamespace(void *ctx);

void *
getNamespace(void *ctx ATTRIBUTE_UNUSED) {
    return (NULL);
}

XMLPUBFUN int
checkNamespace(void *ctx, xmlChar *namespace);

int
checkNamespace(void *ctx ATTRIBUTE_UNUSED,
               xmlChar *namespace ATTRIBUTE_UNUSED) {
    return (0);
}

XMLPUBFUN void
namespaceDecl(void *ctx, const xmlChar *href, const xmlChar *prefix);

void
namespaceDecl(void *ctx ATTRIBUTE_UNUSED, const xmlChar *href ATTRIBUTE_UNUSED,
              const xmlChar *prefix ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
comment(void *ctx, const xmlChar *value);

void
comment(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
cdataBlock(void *ctx, const xmlChar *value, int len);

void
cdataBlock(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value ATTRIBUTE_UNUSED,
           int len ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
initxmlDefaultSAXHandler(void *hdlr, int warning);

void
initxmlDefaultSAXHandler(void *hdlr ATTRIBUTE_UNUSED,
                         int warning ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
inithtmlDefaultSAXHandler(void *hdlr);

void
inithtmlDefaultSAXHandler(void *hdlr ATTRIBUTE_UNUSED) {
}

/*
 * nanoftp.h
 */

#ifdef _WIN32
  #include <winsock2.h>
#else
  #define SOCKET int
#endif

typedef void
(*ftpListCallback)(void *userData, const char *filename, const char *attrib,
                   const char *owner, const char *group, unsigned long size,
                   int links, int year, const char *month, int day, int hour,
                   int minute);

typedef void
(*ftpDataCallback) (void *userData, const char *data, int len);

XMLPUBFUN void
xmlNanoFTPInit(void);

void
xmlNanoFTPInit(void) {
}

XMLPUBFUN void
xmlNanoFTPCleanup(void);

void
xmlNanoFTPCleanup(void) {
}

XMLPUBFUN void
xmlNanoFTPProxy(const char *host, int port, const char *user,
                const char *passwd, int type);

void
xmlNanoFTPProxy(const char *host ATTRIBUTE_UNUSED, int port ATTRIBUTE_UNUSED,
                const char *user ATTRIBUTE_UNUSED,
	        const char *passwd ATTRIBUTE_UNUSED, int type ATTRIBUTE_UNUSED) {
}

XMLPUBFUN int
xmlNanoFTPUpdateURL(void *ctx, const char *URL);

int
xmlNanoFTPUpdateURL(void *ctx ATTRIBUTE_UNUSED,
                    const char *URL ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN void
xmlNanoFTPScanProxy(const char *URL);

void
xmlNanoFTPScanProxy(const char *URL ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void *
xmlNanoFTPNewCtxt(const char *URL);

void*
xmlNanoFTPNewCtxt(const char *URL ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void
xmlNanoFTPFreeCtxt(void *ctx);

void
xmlNanoFTPFreeCtxt(void * ctx ATTRIBUTE_UNUSED) {
}

XMLPUBFUN int
xmlNanoFTPGetResponse(void *ctx);

int
xmlNanoFTPGetResponse(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPCheckResponse(void *ctx);

int
xmlNanoFTPCheckResponse(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPQuit(void *ctx);

int
xmlNanoFTPQuit(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPConnect(void *ctx);

int
xmlNanoFTPConnect(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN void *
xmlNanoFTPConnectTo(const char *server, int port);

void*
xmlNanoFTPConnectTo(const char *server ATTRIBUTE_UNUSED,
                    int port ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN int
xmlNanoFTPCwd(void *ctx, const char *directory);

int
xmlNanoFTPCwd(void *ctx ATTRIBUTE_UNUSED,
              const char *directory ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPDele(void *ctx, const char *file);

int
xmlNanoFTPDele(void *ctx ATTRIBUTE_UNUSED, const char *file ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN SOCKET
xmlNanoFTPGetConnection(void *ctx);

SOCKET
xmlNanoFTPGetConnection(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPCloseConnection(void *ctx);

int
xmlNanoFTPCloseConnection(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPList(void *ctx, ftpListCallback callback, void *userData,
	       const char *filename);

int
xmlNanoFTPList(void *ctx ATTRIBUTE_UNUSED,
               ftpListCallback callback ATTRIBUTE_UNUSED,
               void *userData ATTRIBUTE_UNUSED,
	       const char *filename ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN SOCKET
xmlNanoFTPGetSocket(void *ctx, const char *filename);

SOCKET
xmlNanoFTPGetSocket(void *ctx ATTRIBUTE_UNUSED,
                    const char *filename ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPGet(void *ctx, ftpDataCallback callback, void *userData,
	      const char *filename);

int
xmlNanoFTPGet(void *ctx ATTRIBUTE_UNUSED,
              ftpDataCallback callback ATTRIBUTE_UNUSED,
              void *userData ATTRIBUTE_UNUSED,
	      const char *filename ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlNanoFTPRead(void *ctx, void *dest, int len);

int
xmlNanoFTPRead(void *ctx ATTRIBUTE_UNUSED, void *dest ATTRIBUTE_UNUSED,
               int len ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN void *
xmlNanoFTPOpen(const char *URL);

void*
xmlNanoFTPOpen(const char *URL ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN int
xmlNanoFTPClose(void *ctx);

int
xmlNanoFTPClose(void *ctx ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlIOFTPMatch(const char *filename);

int
xmlIOFTPMatch(const char *filename ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN void *
xmlIOFTPOpen(const char *filename);

void *
xmlIOFTPOpen(const char *filename ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN int
xmlIOFTPRead(void *context, char *buffer, int len);

int
xmlIOFTPRead(void *context ATTRIBUTE_UNUSED, char *buffer ATTRIBUTE_UNUSED,
             int len ATTRIBUTE_UNUSED) {
    return(-1);
}

XMLPUBFUN int
xmlIOFTPClose(void *context);

int
xmlIOFTPClose(void *context ATTRIBUTE_UNUSED) {
    return(-1);
}

/*
 * xpointer.h
 */

XMLPUBFUN void *
xmlXPtrNewRange(void *start, int startindex,
                void *end, int endindex);

void *
xmlXPtrNewRange(void *start ATTRIBUTE_UNUSED,
                int startindex ATTRIBUTE_UNUSED,
                void *end ATTRIBUTE_UNUSED,
                int endindex ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrNewRangePoints(void *start, void *end);

void *
xmlXPtrNewRangePoints(void *start ATTRIBUTE_UNUSED,
                      void *end ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrNewRangePointNode(void *start, void *end);

void *
xmlXPtrNewRangePointNode(void *start ATTRIBUTE_UNUSED,
                         void *end ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrNewRangeNodePoint(void *start, void *end);

void *
xmlXPtrNewRangeNodePoint(void *start ATTRIBUTE_UNUSED,
                         void *end ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrNewRangeNodes(void *start, void *end);

void *
xmlXPtrNewRangeNodes(void *start ATTRIBUTE_UNUSED,
                     void *end ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrNewCollapsedRange(void *start);

void *
xmlXPtrNewCollapsedRange(void *start ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrNewRangeNodeObject(void *start, void *end);

void *
xmlXPtrNewRangeNodeObject(void *start ATTRIBUTE_UNUSED,
                          void *end ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrLocationSetCreate(void *val);

void *
xmlXPtrLocationSetCreate(void *val ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void
xmlXPtrLocationSetAdd(void *cur, void *val);

void
xmlXPtrLocationSetAdd(void *cur ATTRIBUTE_UNUSED,
                      void *val ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void *
xmlXPtrLocationSetMerge(void *val1, void *val2);

void *
xmlXPtrLocationSetMerge(void *val1 ATTRIBUTE_UNUSED,
                        void *val2 ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void
xmlXPtrLocationSetDel(void *cur, void *val);

void
xmlXPtrLocationSetDel(void *cur ATTRIBUTE_UNUSED,
                      void *val ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
xmlXPtrLocationSetRemove(void *cur, int val);

void
xmlXPtrLocationSetRemove(void *cur ATTRIBUTE_UNUSED,
                         int val ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
xmlXPtrFreeLocationSet(void *obj);

void
xmlXPtrFreeLocationSet(void *obj ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void *
xmlXPtrNewLocationSetNodes(void *start, void *end);

void *
xmlXPtrNewLocationSetNodes(void *start ATTRIBUTE_UNUSED,
                           void *end ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrNewLocationSetNodeSet(void *set);

void *
xmlXPtrNewLocationSetNodeSet(void *set ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrWrapLocationSet(void *val);

void *
xmlXPtrWrapLocationSet(void *val ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void *
xmlXPtrBuildNodeList(void *obj);

void *
xmlXPtrBuildNodeList(void *obj ATTRIBUTE_UNUSED) {
    return(NULL);
}

XMLPUBFUN void
xmlXPtrRangeToFunction(void *ctxt, int nargs);

void
xmlXPtrRangeToFunction(void *ctxt ATTRIBUTE_UNUSED,
                       int nargs ATTRIBUTE_UNUSED) {
}

/*
 * xmllint shell functions formerly in debugXML.h
 */

XMLPUBFUN void
xmlLsOneNode(FILE *output, xmlNodePtr node);

void
xmlLsOneNode(FILE *output ATTRIBUTE_UNUSED, xmlNodePtr node ATTRIBUTE_UNUSED) {
}

XMLPUBFUN int
xmlLsCountNode(xmlNodePtr node);

int
xmlLsCountNode(xmlNodePtr node ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN const char *
xmlBoolToText(int boolval);

const char *
xmlBoolToText(int boolval) {
    if (boolval)
        return("True");
    else
        return("False");
}

#ifdef LIBXML_XPATH_ENABLED
XMLPUBFUN void
xmlShellPrintXPathError(int errorType, const char *arg);

void
xmlShellPrintXPathError(int errorType ATTRIBUTE_UNUSED,
                        const char *arg ATTRIBUTE_UNUSED) {
}

XMLPUBFUN void
xmlShellPrintXPathResult(void *list);

void
xmlShellPrintXPathResult(void *list ATTRIBUTE_UNUSED) {
}

XMLPUBFUN int
xmlShellList(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellList(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
             void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
xmlShellBase(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellBase(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
             void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
xmlShellDir(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellDir(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
            void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
xmlShellLoad(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellLoad(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
             void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

#ifdef LIBXML_OUTPUT_ENABLED
XMLPUBFUN void
xmlShellPrintNode(void *node);

void
xmlShellPrintNode(void *ctxt ATTRIBUTE_UNUSED) {
}

XMLPUBFUN int
xmlShellCat(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellCat(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
            void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
xmlShellWrite(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellWrite(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
              void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
xmlShellSave(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellSave(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
             void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}
#endif /* LIBXML_OUTPUT_ENABLED */

#ifdef LIBXML_VALID_ENABLED
XMLPUBFUN int
xmlShellValidate(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellValidate(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
                 void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}
#endif /* LIBXML_VALID_ENABLED */

XMLPUBFUN int
xmlShellDu(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellDu(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
           void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

XMLPUBFUN int
xmlShellPwd(void *ctxt, char *arg, void *node, void *node2);

int
xmlShellPwd(void *ctxt ATTRIBUTE_UNUSED, char *arg ATTRIBUTE_UNUSED,
            void *node ATTRIBUTE_UNUSED, void *node2 ATTRIBUTE_UNUSED) {
    return(0);
}

typedef char * (*xmlShellReadlineFunc)(char *prompt);

XMLPUBFUN void
xmlShell(void *doc, char *filename, xmlShellReadlineFunc input, void *output);

void
xmlShell(void *doc ATTRIBUTE_UNUSED, char *filename ATTRIBUTE_UNUSED,
         xmlShellReadlineFunc input ATTRIBUTE_UNUSED,
         void *output ATTRIBUTE_UNUSED) {
}
#endif /* LIBXML_XPATH_ENABLED */

#endif /* LIBXML_LEGACY_ENABLED */

