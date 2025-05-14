#ifndef XML_TREE_H_PRIVATE__
#define XML_TREE_H_PRIVATE__

XML_HIDDEN extern int
xmlRegisterCallbacks;

XML_HIDDEN int
xmlSearchNsSafe(xmlNode *node, const xmlChar *href, xmlNs **out);
XML_HIDDEN int
xmlSearchNsByHrefSafe(xmlNode *node, const xmlChar *href, xmlNs **out);

XML_HIDDEN int
xmlNodeParseContent(xmlNode *node, const xmlChar *content, int len);
XML_HIDDEN xmlNode *
xmlStaticCopyNode(xmlNode *node, xmlDoc *doc, xmlNode *parent,
                  int extended);
XML_HIDDEN xmlNode *
xmlStaticCopyNodeList(xmlNode *node, xmlDoc *doc, xmlNode *parent);
XML_HIDDEN const xmlChar *
xmlSplitQName4(const xmlChar *name, xmlChar **prefixPtr);

XML_HIDDEN xmlChar *
xmlNodeListGetStringInternal(const xmlNode *node, int escape, int flags);

#endif /* XML_TREE_H_PRIVATE__ */
