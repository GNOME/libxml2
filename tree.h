/*
 * tree.h : describes the structures found in an tree resulting
 *          from an XML parsing.
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifndef __XML_TREE_H__
#define __XML_TREE_H__


#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

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
 */

typedef struct xmlNotation {
    const CHAR               *name;	/* Notation name */
    const CHAR               *PublicID;	/* Public identifier, if any */
    const CHAR               *SystemID;	/* System identifier, if any */
} xmlNotation;
typedef xmlNotation *xmlNotationPtr;

/*
 * a DTD Attribute definition
 */

typedef enum {
    XML_ATTRIBUTE_CDATA = 1,
    XML_ATTRIBUTE_ID,
    XML_ATTRIBUTE_IDREF	,
    XML_ATTRIBUTE_IDREFS,
    XML_ATTRIBUTE_ENTITY,
    XML_ATTRIBUTE_ENTITIES,
    XML_ATTRIBUTE_NMTOKEN,
    XML_ATTRIBUTE_NMTOKENS,
    XML_ATTRIBUTE_ENUMERATION,
    XML_ATTRIBUTE_NOTATION
} xmlAttributeType;

typedef enum {
    XML_ATTRIBUTE_NONE = 1,
    XML_ATTRIBUTE_REQUIRED,
    XML_ATTRIBUTE_IMPLIED,
    XML_ATTRIBUTE_FIXED
} xmlAttributeDefault;

typedef struct xmlEnumeration {
    struct xmlEnumeration    *next;	/* next one */
    const CHAR               *name;	/* Enumeration name */
} xmlEnumeration;
typedef xmlEnumeration *xmlEnumerationPtr;

typedef struct xmlAttribute {
    const CHAR            *elem;	/* Element holding the attribute */
    const CHAR            *name;	/* Attribute name */
    xmlAttributeType       type;	/* The type */
    xmlAttributeDefault    def;		/* the default */
    const CHAR            *defaultValue;/* or the default value */
    xmlEnumerationPtr      tree;        /* or the enumeration tree if any */
} xmlAttribute;
typedef xmlAttribute *xmlAttributePtr;

/*
 * a DTD Element definition.
 */
typedef enum {
    XML_ELEMENT_CONTENT_PCDATA = 1,
    XML_ELEMENT_CONTENT_ELEMENT,
    XML_ELEMENT_CONTENT_SEQ,
    XML_ELEMENT_CONTENT_OR
} xmlElementContentType;

typedef enum {
    XML_ELEMENT_CONTENT_ONCE = 1,
    XML_ELEMENT_CONTENT_OPT,
    XML_ELEMENT_CONTENT_MULT,
    XML_ELEMENT_CONTENT_PLUS
} xmlElementContentOccur;

typedef struct xmlElementContent {
    xmlElementContentType     type;	/* PCDATA, ELEMENT, SEQ or OR */
    xmlElementContentOccur    ocur;	/* ONCE, OPT, MULT or PLUS */
    const CHAR               *name;	/* Element name */
    struct xmlElementContent *c1;	/* first child */
    struct xmlElementContent *c2;	/* second child */
} xmlElementContent;
typedef xmlElementContent *xmlElementContentPtr;

typedef enum {
    XML_ELEMENT_TYPE_EMPTY = 1,
    XML_ELEMENT_TYPE_ANY,
    XML_ELEMENT_TYPE_MIXED,
    XML_ELEMENT_TYPE_ELEMENT
} xmlElementTypeVal;

typedef struct xmlElement {
    const CHAR          *name;		/* Element name */
    xmlElementTypeVal    type;		/* The type */
    xmlElementContentPtr content;	/* the allowed element content */
} xmlElement;
typedef xmlElement *xmlElementPtr;

/*
 * An XML namespace.
 * Note that prefix == NULL is valid, it defines the default namespace
 * within the subtree (until overriden).
 */

typedef enum {
    XML_GLOBAL_NAMESPACE = 1,	/* old style global namespace */
    XML_LOCAL_NAMESPACE		/* new style local scoping */
} xmlNsType;

typedef struct xmlNs {
    struct xmlNs  *next;	/* next Ns link for this node  */
    xmlNsType      type;	/* global or local */
    const CHAR    *href;	/* URL for the namespace */
    const CHAR    *prefix;	/* prefix for the namespace */
} xmlNs;
typedef xmlNs *xmlNsPtr;

/*
 * An XML DtD, as defined by <!DOCTYPE.
 */
typedef struct xmlDtd {
    const CHAR    *name;	/* Name of the DTD */
    const CHAR    *ExternalID;	/* External identifier for PUBLIC DTD */
    const CHAR    *SystemID;	/* URI for a SYSTEM or PUBLIC DTD */
    void          *notations;   /* Hash table for notations if any */
    void          *elements;    /* Hash table for elements if any */
    void          *attributes;  /* Hash table for attributes if any */
    void          *entities;    /* Hash table for entities if any */
    /* struct xmlDtd *next;	 * next  link for this document  */
} xmlDtd;
typedef xmlDtd *xmlDtdPtr;

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
} xmlAttr;
typedef xmlAttr *xmlAttrPtr;

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
    struct xmlNode *last;	/* last child link */
    struct xmlAttr *properties;	/* properties list */
    const CHAR     *name;       /* the name of the node, or the entity */
    xmlNs          *ns;         /* pointer to the associated namespace */
    xmlNs          *nsDef;      /* namespace definitions on this node */
    CHAR           *content;    /* the content */
} _xmlNode;
typedef _xmlNode xmlNode;
typedef _xmlNode *xmlNodePtr;

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
    struct xmlDtd  *intSubset;	/* the document internal subset */
    struct xmlDtd  *extSubset;	/* the document external subset */
    struct xmlNs   *oldNs;	/* Global namespace, the old way */
    struct xmlNode *root;	/* the document tree */
} _xmlDoc;
typedef _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;

/*
 * A buffer structure
 */

typedef struct xmlBuffer {
    CHAR *content;		/* The buffer content UTF8 */
    unsigned int use;		/* The buffer size used */
    unsigned int size;		/* The buffer size */
} _xmlBuffer;
typedef _xmlBuffer xmlBuffer;
typedef xmlBuffer *xmlBufferPtr;

/*
 * Variables.
 */
extern xmlNsPtr baseDTD;
extern int oldXMLWDcompatibility;/* maintain compatibility with old WD */
extern int xmlIndentTreeOutput;  /* try to indent the tree dumps */

/*
 * Handling Buffers.
 */

xmlBufferPtr xmlBufferCreate(void);
void xmlBufferFree(xmlBufferPtr buf);
int xmlBufferDump(FILE *file, xmlBufferPtr buf);
void xmlBufferAdd(xmlBufferPtr buf, const CHAR *str, int len);
void xmlBufferCat(xmlBufferPtr buf, const CHAR *str);
void xmlBufferCCat(xmlBufferPtr buf, const char *str);

/*
 * Creating/freeing new structures
 */
xmlDtdPtr xmlCreateIntSubset(xmlDocPtr doc, const CHAR *name,
                    const CHAR *ExternalID, const CHAR *SystemID);
xmlDtdPtr xmlNewDtd(xmlDocPtr doc, const CHAR *name,
                    const CHAR *ExternalID, const CHAR *SystemID);
void xmlFreeDtd(xmlDtdPtr cur);
xmlNsPtr xmlNewGlobalNs(xmlDocPtr doc, const CHAR *href, const CHAR *prefix);
xmlNsPtr xmlNewNs(xmlNodePtr node, const CHAR *href, const CHAR *prefix);
void xmlFreeNs(xmlNsPtr cur);
xmlDocPtr xmlNewDoc(const CHAR *version);
void xmlFreeDoc(xmlDocPtr cur);
xmlAttrPtr xmlNewDocProp(xmlDocPtr doc, const CHAR *name,
                                const CHAR *value);
xmlAttrPtr xmlNewProp(xmlNodePtr node, const CHAR *name,
                             const CHAR *value);
void xmlFreePropList(xmlAttrPtr cur);
void xmlFreeProp(xmlAttrPtr cur);
xmlAttrPtr xmlCopyProp(xmlAttrPtr cur);
xmlAttrPtr xmlCopyPropList(xmlAttrPtr cur);
xmlDtdPtr xmlCopyDtd(xmlDtdPtr dtd);
xmlDocPtr xmlCopyDoc(xmlDocPtr doc, int recursive);

/*
 * Creating new nodes
 */
xmlNodePtr xmlNewDocNode(xmlDocPtr doc, xmlNsPtr ns,
                             const CHAR *name, const CHAR *content);
xmlNodePtr xmlNewNode(xmlNsPtr ns, const CHAR *name);
xmlNodePtr xmlNewChild(xmlNodePtr parent, xmlNsPtr ns,
                              const CHAR *name, const CHAR *content);
xmlNodePtr xmlNewDocText(xmlDocPtr doc, const CHAR *content);
xmlNodePtr xmlNewText(const CHAR *content);
xmlNodePtr xmlNewDocTextLen(xmlDocPtr doc, const CHAR *content, int len);
xmlNodePtr xmlNewTextLen(const CHAR *content, int len);
xmlNodePtr xmlNewDocComment(xmlDocPtr doc, const CHAR *content);
xmlNodePtr xmlNewComment(const CHAR *content);
xmlNodePtr xmlNewReference(xmlDocPtr doc, const CHAR *name);
xmlNodePtr xmlCopyNode(xmlNodePtr node, int recursive);
xmlNodePtr xmlCopyNodeList(xmlNodePtr node);

/*
 * Navigating
 */
xmlNodePtr xmlGetLastChild(xmlNodePtr parent);
int xmlNodeIsText(xmlNodePtr node);

/*
 * Changing the structure
 */
xmlNodePtr xmlAddChild(xmlNodePtr parent, xmlNodePtr cur);
void xmlUnlinkNode(xmlNodePtr cur);

xmlNodePtr xmlTextMerge(xmlNodePtr first, xmlNodePtr second);
void xmlTextConcat(xmlNodePtr node, const CHAR *content, int len);

void xmlFreeNodeList(xmlNodePtr cur);
void xmlFreeNode(xmlNodePtr cur);

/*
 * Namespaces
 */
xmlNsPtr xmlSearchNs(xmlDocPtr doc, xmlNodePtr node,
                            const CHAR *nameSpace);
xmlNsPtr xmlSearchNsByHref(xmlDocPtr doc, xmlNodePtr node,
                                  const CHAR *href);
void xmlSetNs(xmlNodePtr node, xmlNsPtr ns);
xmlNsPtr xmlCopyNamespace(xmlNsPtr cur);
xmlNsPtr xmlCopyNamespaceList(xmlNsPtr cur);

/*
 * Changing the content.
 */
xmlAttrPtr xmlSetProp(xmlNodePtr node, const CHAR *name,
                             const CHAR *value);
CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name);
xmlNodePtr xmlStringGetNodeList(xmlDocPtr doc, const CHAR *value);
xmlNodePtr xmlStringLenGetNodeList(xmlDocPtr doc, const CHAR *value,
                                          int len);
CHAR *xmlNodeListGetString(xmlDocPtr doc, xmlNodePtr list, int inLine);
void xmlNodeSetContent(xmlNodePtr cur, const CHAR *content);
void xmlNodeSetContentLen(xmlNodePtr cur, const CHAR *content, int len);
void xmlNodeAddContent(xmlNodePtr cur, const CHAR *content);
void xmlNodeAddContentLen(xmlNodePtr cur, const CHAR *content, int len);
CHAR *xmlNodeGetContent(xmlNodePtr cur);

/*
 * Internal, don't use
 */
void xmlBufferWriteCHAR(xmlBufferPtr buf, const CHAR *string);
void xmlBufferWriteChar(xmlBufferPtr buf, const char *string);
void xmlBufferWriteQuotedString(xmlBufferPtr buf, const CHAR *string);

/*
 * Saving
 */
void xmlDocDumpMemory(xmlDocPtr cur, CHAR**mem, int *size);
void xmlDocDump(FILE *f, xmlDocPtr cur);
int xmlSaveFile(const char *filename, xmlDocPtr cur);

/*
 * Compression
 */
int  xmlGetDocCompressMode (xmlDocPtr doc);
void xmlSetDocCompressMode (xmlDocPtr doc, int mode);
int  xmlGetCompressMode(void);
void xmlSetCompressMode(int mode);

#ifdef __cplusplus
}
#endif

#endif /* __XML_TREE_H__ */

