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
 * Constants.
 */
#define XML_TYPE_TEXT		1

/*
 * An XML DTD defining a given name space.
 */
typedef struct xmlDtd {
    struct xmlDtd *next;	/* next Dtd link for this document  */
    const CHAR    *href;	/* URL for the DTD */
    const CHAR    *AS;	        /* URL for the DTD */
    void          *entities;    /* Hash table for entities if any */
} xmlDtd, *xmlDtdPtr;

/*
 * A property of an XML node.
 */
typedef struct xmlProp {
    struct xmlNode *node;	/* prop->node link */
    struct xmlProp *next;	/* parent->childs link */
    const CHAR     *name;       /* the name of the property */
    const CHAR     *value;      /* the value of the property */
} xmlProp, *xmlPropPtr;

/*
 * A node in an XML tree.
 */
typedef struct xmlNode {
    struct xmlNode *parent;	/* child->parent link */
    struct xmlNode *next;	/* next sibling link  */
    struct xmlNode *childs;	/* parent->childs link */
    struct xmlProp *properties;	/* properties list */
    int             type;	/* type number in the DTD */
    const CHAR     *name;       /* the name of the node */
    xmlDtd         *dtd;        /* pointer to the DTD */
    CHAR           *content;    /* the content */
} xmlNode, *xmlNodePtr;

/*
 * An XML document.
 */
typedef struct xmlDoc {
    const CHAR     *version;	/* the XML version string */
    struct xmlDtd  *dtds;       /* referenced DTDs */
    struct xmlNode *root;	/* parent->childs link */
    void           *entities;   /* Hash table for entities if any */
} xmlDoc, *xmlDocPtr;

/*
 * Variables.
 */
extern xmlDtdPtr baseDTD;
extern int oldXMLWDcompatibility;/* maintain compatibility with old WD */

/*
 * Functions.
 */
extern xmlDtdPtr xmlNewDtd(xmlDocPtr doc, const CHAR *href, const CHAR *AS);
extern void xmlFreeDtd(xmlDtdPtr cur);
extern xmlDocPtr xmlNewDoc(const CHAR *version);
extern void xmlFreeDoc(xmlDocPtr cur);
extern xmlPropPtr xmlNewProp(xmlNodePtr node, const CHAR *name,
                             const CHAR *value);
extern const CHAR *xmlGetProp(xmlNodePtr node, const CHAR *name);
extern void xmlFreePropList(xmlPropPtr cur);
extern void xmlFreeProp(xmlPropPtr cur);
extern xmlNodePtr xmlNewNode(xmlDtdPtr dtd, const CHAR *name, CHAR *content);
extern xmlNodePtr xmlNewText(CHAR *content);
extern xmlNodePtr xmlAddChild(xmlNodePtr parent, xmlNodePtr cur);
extern void xmlFreeNodeList(xmlNodePtr cur);
extern void xmlFreeNode(xmlNodePtr cur);
extern void xmlNodeSetContent(xmlNodePtr cur, CHAR *content);
extern xmlDtdPtr xmlSearchDtd(xmlDocPtr doc, CHAR *nameSpace);
extern xmlNodePtr xmlNewChild(xmlNodePtr parent, xmlDtdPtr dtd,
                              const CHAR *name, CHAR *content);

extern void xmlDocDumpMemory(xmlDocPtr cur, CHAR**mem, int *size);
extern void xmlDocDump(FILE *f, xmlDocPtr doc);


#ifdef __cplusplus
}
#endif

#endif /* __XML_TREE_H__ */

