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
 * Type definitions
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
    struct xmlNode *node;	/* attr->node link */
    struct xmlAttr *next;	/* parent->childs link */
    const CHAR     *name;       /* the name of the property */
    const CHAR     *value;      /* the value of the property */
} xmlAttr, *xmlAttrPtr;

/*
 * A node in an XML tree.
 */
#define XML_TYPE_TEXT		1
#define XML_TYPE_COMMENT	2
#define XML_TYPE_ENTITY		3

typedef struct xmlNode {
    struct xmlNode *parent;	/* child->parent link */
    struct xmlNode *next;	/* next sibling link  */
    struct xmlNode *childs;	/* parent->childs link */
    struct xmlAttr *properties;	/* properties list */
    int             type;	/* type number in the DTD */
    const CHAR     *name;       /* the name of the node, or the entity */
    xmlNs          *ns;         /* pointer to the associated namespace */
    xmlNs          *nsDef;      /* namespace definitions on this node */
    CHAR           *content;    /* the content */
} xmlNode, *xmlNodePtr;

/*
 * An XML document.
 */
typedef struct xmlDoc {
    char           *name;	/* name/filename/URI of the document */
    const CHAR     *version;	/* the XML version string */
    const CHAR     *encoding;   /* encoding, if any */
    int             standalone; /* standalone document (no external refs) */
    struct xmlDtd  *dtd;	/* the document DTD if available */
    struct xmlNs   *oldNs;	/* Global namespace, the old way */
    void          *entities;    /* Hash table for general entities if any */
    struct xmlNode *root;	/* the document tree */
} xmlDoc, *xmlDocPtr;

/*
 * Variables.
 */
extern xmlNsPtr baseDTD;
extern int oldXMLWDcompatibility;/* maintain compatibility with old WD */
extern int xmlIndentTreeOutput;  /* try to indent the tree dumps */

/*
 * Functions.
 */
extern xmlDtdPtr xmlNewDtd(xmlDocPtr doc, const CHAR *name,
                    const CHAR *ExternalID, const CHAR *SystemID);
extern void xmlFreeDtd(xmlDtdPtr cur);
extern xmlNsPtr xmlNewGlobalNs(xmlDocPtr doc, const CHAR *href, const CHAR *AS);
extern xmlNsPtr xmlNewNs(xmlNodePtr node, const CHAR *href, const CHAR *AS);
extern void xmlFreeNs(xmlNsPtr cur);
extern xmlDocPtr xmlNewDoc(const CHAR *version);
extern void xmlFreeDoc(xmlDocPtr cur);
extern xmlAttrPtr xmlNewProp(xmlNodePtr node, const CHAR *name,
                             const CHAR *value);
extern xmlAttrPtr xmlSetProp(xmlNodePtr node, const CHAR *name,
                             const CHAR *value);
extern const CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name);
extern void xmlFreePropList(xmlAttrPtr cur);
extern void xmlFreeProp(xmlAttrPtr cur);
extern xmlNodePtr xmlNewNode(xmlNsPtr ns, const CHAR *name, CHAR *content);
extern xmlNodePtr xmlNewText(const CHAR *content);
extern xmlNodePtr xmlNewTextLen(const CHAR *content, int len);
extern xmlNodePtr xmlNewComment(CHAR *content);
extern xmlNodePtr xmlAddChild(xmlNodePtr parent, xmlNodePtr cur);
extern xmlNodePtr xmlGetLastChild(xmlNodePtr node);
extern int xmlNodeIsText(xmlNodePtr node);
extern void xmlTextConcat(xmlNodePtr node, const CHAR *content, int len);
extern void xmlFreeNodeList(xmlNodePtr cur);
extern void xmlFreeNode(xmlNodePtr cur);
extern void xmlNodeSetContent(xmlNodePtr cur, const CHAR *content);
extern void xmlNodeSetContentLen(xmlNodePtr cur, const CHAR *content, int len);
extern void xmlNodeAddContent(xmlNodePtr cur, const CHAR *content);
extern void xmlNodeAddContentLen(xmlNodePtr cur, const CHAR *content, int len);
extern xmlNsPtr xmlSearchNs(xmlDocPtr doc, xmlNodePtr node,
                            const CHAR *nameSpace);
extern xmlNsPtr xmlSearchNsByHref(xmlDocPtr doc, xmlNodePtr node,
                                  const CHAR *href);
extern void xmlSetNs(xmlNodePtr node, xmlNsPtr ns);
extern xmlNodePtr xmlNewChild(xmlNodePtr parent, xmlNsPtr ns,
                              const CHAR *name, CHAR *content);

extern void xmlDocDumpMemory(xmlDocPtr cur, CHAR**mem, int *size);
extern void xmlDocDump(FILE *f, xmlDocPtr doc);
extern void xmlBufferWriteCHAR(const CHAR *string);
extern void xmlBufferWriteChar(const char *string);


#ifdef __cplusplus
}
#endif

#endif /* __XML_TREE_H__ */

