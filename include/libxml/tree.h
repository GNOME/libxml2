/*
 * tree.h : describes the structures found in an tree resulting
 *          from an XML parsing.
 *
 * See Copyright for the status of this software.
 *
 * $Id$
 */

#ifndef __XML_TREE_H__
#define __XML_TREE_H__


#ifdef __cplusplus
extern "C" {
#endif

/*
 * The different element types carried by an XML tree
 *
 * NOTE: This is synchronized with DOM Level1 values
 *       See http://www.w3.org/TR/REC-DOM-Level-1/
 */
typedef enum {
    XML_ELEMENT_NODE=		1,
    XML_ATTRIBUTE_NODE=		2,
    XML_TEXT_NODE=		3,
    XML_CDATA_SECTION_NODE=	4,
    XML_ENTITY_REF_NODE=	5,
    XML_ENTITY_NODE=		6,
    XML_PI_NODE=		7,
    XML_COMMENT_NODE=		8,
    XML_DOCUMENT_NODE=		9,
    XML_DOCUMENT_TYPE_NODE=	10,
    XML_DOCUMENT_FRAG_NODE=	11,
    XML_NOTATION_NODE=		12
} xmlElementType;

/*
 * Size of an internal character representation.
 *
 * Currently we use 8bit chars internal representation for memory efficiency,
 * but the parser is not tied to that, just define UNICODE to switch to
 * a 16 bits internal representation. Note that with 8 bits wide
 * CHARs one can still use UTF-8 to handle correctly non ISO-Latin
 * input.
 */
#ifdef UNICODE
typedef unsigned short CHAR;
#else
typedef unsigned char CHAR;
#endif

/*
 * a DTD Notation definition
 * TODO !!!!
 */

/*
 * a DTD Attribute definition
 * TODO !!!!
 */

/*
 * a DTD Element definition.
 */
#define XML_ELEMENT_TYPE_EMPTY		1
#define XML_ELEMENT_TYPE_ANY		2
#define XML_ELEMENT_TYPE_MIXED		3
#define XML_ELEMENT_TYPE_ELEMENT	4

typedef struct xmlElement {
    const CHAR    *name;	/* Element name */
    int            type;	/* type (too simple, to extend ...) */
    /* TODO !!! more needed */
} xmlElement, *xmlElementPtr;

/*
 * An XML namespace.
 * Note that prefix == NULL is valid, it defines the default namespace
 * within the subtree (until overriden).
 */

#define XML_GLOBAL_NAMESPACE		1 /* old style global namespace */
#define XML_LOCAL_NAMESPACE		2 /* new style local scoping */

typedef struct xmlNs {
    struct xmlNs  *next;	/* next Ns link for this node  */
    int            type;	/* global or local */
    const CHAR    *href;	/* URL for the namespace */
    const CHAR    *prefix;	/* prefix for the namespace */
} xmlNs, *xmlNsPtr;

/*
 * An XML DtD, as defined by <!DOCTYPE.
 */
typedef struct xmlDtd {
    const CHAR    *name;	/* Name of the DTD */
    const CHAR    *ExternalID;	/* External identifier for PUBLIC DTD */
    const CHAR    *SystemID;	/* URI for a SYSTEM or PUBLIC DTD */
    void          *elements;    /* Hash table for elements if any */
    void          *entities;    /* Hash table for entities if any */
    /* struct xmlDtd *next;	 * next  link for this document  */
} xmlDtd, *xmlDtdPtr;

/*
 * A attribute of an XML node.
 */
typedef struct xmlAttr {
#ifndef XML_WITHOUT_CORBA
    void           *_private;	/* for Corba, must be first ! */
    void           *vepv;	/* for Corba, must be next ! */
#endif
    xmlElementType  type;       /* XML_ATTRIBUTE_NODE, must be third ! */
    struct xmlNode *node;	/* attr->node link */
    struct xmlAttr *next;	/* parent->childs link */
    const CHAR     *name;       /* the name of the property */
    struct xmlNode *val;        /* the value of the property */
} xmlAttr, *xmlAttrPtr;

/*
 * A node in an XML tree.
 */
typedef struct xmlNode {
#ifndef XML_WITHOUT_CORBA
    void           *_private;	/* for Corba, must be first ! */
    void           *vepv;	/* for Corba, must be next ! */
#endif
    xmlElementType  type;	/* type number in the DTD, must be third ! */
    struct xmlDoc  *doc;	/* the containing document */
    struct xmlNode *parent;	/* child->parent link */
    struct xmlNode *next;	/* next sibling link  */
    struct xmlNode *prev;	/* previous sibling link  */
    struct xmlNode *childs;	/* parent->childs link */
    struct xmlAttr *properties;	/* properties list */
    const CHAR     *name;       /* the name of the node, or the entity */
    xmlNs          *ns;         /* pointer to the associated namespace */
    xmlNs          *nsDef;      /* namespace definitions on this node */
    CHAR           *content;    /* the content */
} xmlNode, *xmlNodePtr;

/*
 * An XML document.
 */
typedef struct xmlDoc {
#ifndef XML_WITHOUT_CORBA
    void           *_private;	/* for Corba, must be first ! */
    void           *vepv;	/* for Corba, must be next ! */
#endif
    xmlElementType  type;       /* XML_DOCUMENT_NODE, must be second ! */
    char           *name;	/* name/filename/URI of the document */
    const CHAR     *version;	/* the XML version string */
    const CHAR     *encoding;   /* encoding, if any */
    int             compression;/* level of zlib compression */
    int             standalone; /* standalone document (no external refs) */
    struct xmlDtd  *dtd;	/* the document DTD if available */
    struct xmlNs   *oldNs;	/* Global namespace, the old way */
    void           *entities;   /* Hash table for general entities if any */
    struct xmlNode *root;	/* the document tree */
} xmlDoc, *xmlDocPtr;

/*
 * Variables.
 */
extern xmlNsPtr baseDTD;
extern int oldXMLWDcompatibility;/* maintain compatibility with old WD */
extern int xmlIndentTreeOutput;  /* try to indent the tree dumps */

/*
 * Creating/freeing new structures
 */
extern xmlDtdPtr xmlNewDtd(xmlDocPtr doc, const CHAR *name,
                    const CHAR *ExternalID, const CHAR *SystemID);
extern void xmlFreeDtd(xmlDtdPtr cur);
extern xmlNsPtr xmlNewGlobalNs(xmlDocPtr doc, const CHAR *href, const CHAR *AS);
extern xmlNsPtr xmlNewNs(xmlNodePtr node, const CHAR *href, const CHAR *AS);
extern void xmlFreeNs(xmlNsPtr cur);
extern xmlDocPtr xmlNewDoc(const CHAR *version);
extern void xmlFreeDoc(xmlDocPtr cur);
extern xmlAttrPtr xmlNewDocProp(xmlDocPtr doc, const CHAR *name,
                                const CHAR *value);
extern xmlAttrPtr xmlNewProp(xmlNodePtr node, const CHAR *name,
                             const CHAR *value);
extern void xmlFreePropList(xmlAttrPtr cur);
extern void xmlFreeProp(xmlAttrPtr cur);
extern xmlAttrPtr xmlCopyProp(xmlAttrPtr cur);
extern xmlAttrPtr xmlCopyPropList(xmlAttrPtr cur);
extern xmlDtdPtr xmlCopyDtd(xmlDtdPtr dtd);
extern xmlDocPtr xmlCopyDoc(xmlDocPtr doc, int recursive);

/*
 * Creating new nodes
 */
extern xmlNodePtr xmlNewDocNode(xmlDocPtr doc, xmlNsPtr ns,
                             const CHAR *name, CHAR *content);
extern xmlNodePtr xmlNewNode(xmlNsPtr ns, const CHAR *name);
extern xmlNodePtr xmlNewChild(xmlNodePtr parent, xmlNsPtr ns,
                              const CHAR *name, CHAR *content);
extern xmlNodePtr xmlNewDocText(xmlDocPtr doc, const CHAR *content);
extern xmlNodePtr xmlNewText(const CHAR *content);
extern xmlNodePtr xmlNewDocTextLen(xmlDocPtr doc, const CHAR *content, int len);
extern xmlNodePtr xmlNewTextLen(const CHAR *content, int len);
extern xmlNodePtr xmlNewDocComment(xmlDocPtr doc, CHAR *content);
extern xmlNodePtr xmlNewComment(CHAR *content);
extern xmlNodePtr xmlNewReference(xmlDocPtr doc, const CHAR *name);
extern xmlNodePtr xmlCopyNode(xmlNodePtr node, int recursive);
extern xmlNodePtr xmlCopyNodeList(xmlNodePtr node);

/*
 * Navigating
 */
extern xmlNodePtr xmlGetLastChild(xmlNodePtr node);
extern int xmlNodeIsText(xmlNodePtr node);

/*
 * Changing the structure
 */
extern xmlNodePtr xmlAddChild(xmlNodePtr parent, xmlNodePtr cur);
extern void xmlUnlinkNode(xmlNodePtr cur);

extern xmlNodePtr xmlTextMerge(xmlNodePtr first, xmlNodePtr second);
extern void xmlTextConcat(xmlNodePtr node, const CHAR *content, int len);

extern void xmlFreeNodeList(xmlNodePtr cur);
extern void xmlFreeNode(xmlNodePtr cur);

/*
 * Namespaces
 */
extern xmlNsPtr xmlSearchNs(xmlDocPtr doc, xmlNodePtr node,
                            const CHAR *nameSpace);
extern xmlNsPtr xmlSearchNsByHref(xmlDocPtr doc, xmlNodePtr node,
                                  const CHAR *href);
extern void xmlSetNs(xmlNodePtr node, xmlNsPtr ns);
extern xmlNsPtr xmlCopyNamespace(xmlNsPtr cur);
extern xmlNsPtr xmlCopyNamespaceList(xmlNsPtr cur);

/*
 * Changing the content.
 */
extern xmlAttrPtr xmlSetProp(xmlNodePtr node, const CHAR *name,
                             const CHAR *value);
extern const CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name);
extern xmlNodePtr xmlStringGetNodeList(xmlDocPtr doc, const CHAR *value);
extern xmlNodePtr xmlStringLenGetNodeList(xmlDocPtr doc, const CHAR *value,
                                          int len);
extern CHAR *xmlNodeListGetString(xmlDocPtr doc, xmlNodePtr list, int inLine);
extern void xmlNodeSetContent(xmlNodePtr cur, const CHAR *content);
extern void xmlNodeSetContentLen(xmlNodePtr cur, const CHAR *content, int len);
extern void xmlNodeAddContent(xmlNodePtr cur, const CHAR *content);
extern void xmlNodeAddContentLen(xmlNodePtr cur, const CHAR *content, int len);
extern CHAR *xmlNodeGetContent(xmlNodePtr cur);

/*
 * Internal, don't use
 */
extern void xmlBufferWriteCHAR(const CHAR *string);
extern void xmlBufferWriteChar(const char *string);

/*
 * Saving
 */
extern void xmlDocDumpMemory(xmlDocPtr cur, CHAR**mem, int *size);
extern void xmlDocDump(FILE *f, xmlDocPtr doc);
int xmlSaveFile(const char *filename, xmlDocPtr cur);

/*
 * Compression
 */
extern int  xmlGetDocCompressMode (xmlDocPtr doc);
extern void xmlSetDocCompressMode (xmlDocPtr doc, int mode);
extern int  xmlGetCompressMode(void);
extern void xmlSetCompressMode(int mode);

#ifdef __cplusplus
}
#endif

#endif /* __XML_TREE_H__ */

