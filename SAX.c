/*
 * SAX.c : Default SAX handler to build a tree.
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include "tree.h"
#include "parser.h"
#include "parserInternals.h"
#include "valid.h"
#include "entities.h"
#include "xml-error.h"

/* #define DEBUG_SAX */

/**
 * getPublicId:
 * @ctx: the user data (XML parser context)
 *
 * Return the public ID e.g. "-//SGMLSOURCE//DTD DEMO//EN"
 *
 * Returns a CHAR *
 */
const CHAR *
getPublicId(void *ctx)
{
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */
    return(NULL);
}

/**
 * getSystemId:
 * @ctx: the user data (XML parser context)
 *
 * Return the system ID, basically URL or filename e.g.
 * http://www.sgmlsource.com/dtds/memo.dtd
 *
 * Returns a CHAR *
 */
const CHAR *
getSystemId(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    return(ctxt->input->filename); 
}

/**
 * getLineNumber:
 * @ctx: the user data (XML parser context)
 *
 * Return the line number of the current parsing point.
 *
 * Returns an int
 */
int
getLineNumber(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    return(ctxt->input->line);
}

/**
 * getColumnNumber:
 * @ctx: the user data (XML parser context)
 *
 * Return the column number of the current parsing point.
 *
 * Returns an int
 */
int
getColumnNumber(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    return(ctxt->input->col);
}

/*
 * The default SAX Locator.
 */

xmlSAXLocator xmlDefaultSAXLocator = {
    getPublicId, getSystemId, getLineNumber, getColumnNumber
};

/**
 * isStandalone:
 * @ctx: the user data (XML parser context)
 *
 * Is this document tagged standalone ?
 *
 * Returns 1 if true
 */
int
isStandalone(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    return(ctxt->myDoc->standalone == 1);
}

/**
 * hasInternalSubset:
 * @ctx: the user data (XML parser context)
 *
 * Does this document has an internal subset
 *
 * Returns 1 if true
 */
int
hasInternalSubset(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    return(ctxt->myDoc->intSubset != NULL);
}

/**
 * hasExternalSubset:
 * @ctx: the user data (XML parser context)
 *
 * Does this document has an external subset
 *
 * Returns 1 if true
 */
int
hasExternalSubset(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    return(ctxt->myDoc->extSubset != NULL);
}

/**
 * internalSubset:
 * @ctx: the user data (XML parser context)
 *
 * Does this document has an internal subset
 */
void
internalSubset(void *ctx, const CHAR *name,
	       const CHAR *ExternalID, const CHAR *SystemID)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.internalSubset(%s, %s, %s)\n",
            name, ExternalID, SystemID);
#endif
    xmlCreateIntSubset(ctxt->myDoc, name, ExternalID, SystemID);
    if (((ExternalID != NULL) || (SystemID != NULL)) &&
        (ctxt->validate && ctxt->wellFormed && ctxt->myDoc)) {
	/*
	 * Try to fetch and parse the external subset.
	 */
	xmlDtdPtr ret = NULL;
	xmlParserCtxtPtr dtdCtxt;
	xmlParserInputPtr input = NULL;
	xmlCharEncoding enc;

	dtdCtxt = xmlNewParserCtxt();
	if (dtdCtxt == NULL) return;

	/*
	 * Ask the Entity resolver to load the damn thing
	 */
	if ((ctxt->directory != NULL) && (dtdCtxt->directory == NULL))
	    dtdCtxt->directory = xmlStrdup(ctxt->directory);

	if ((dtdCtxt->sax != NULL) && (dtdCtxt->sax->resolveEntity != NULL))
	    input = dtdCtxt->sax->resolveEntity(dtdCtxt->userData, ExternalID,
	                                        SystemID);
	if (input == NULL) {
	    xmlFreeParserCtxt(dtdCtxt);
	    return;
	}

	/*
	 * plug some encoding conversion routines here. !!!
	 */
	xmlPushInput(dtdCtxt, input);
	enc = xmlDetectCharEncoding(dtdCtxt->input->cur);
	xmlSwitchEncoding(dtdCtxt, enc);

	if (input->filename == NULL)
	    input->filename = xmlStrdup(SystemID);
	input->line = 1;
	input->col = 1;
	input->base = dtdCtxt->input->cur;
	input->cur = dtdCtxt->input->cur;
	input->free = NULL;

	/*
	 * let's parse that entity knowing it's an external subset.
	 */
	xmlParseExternalSubset(dtdCtxt, ExternalID, SystemID);

	if (dtdCtxt->myDoc != NULL) {
	    if (dtdCtxt->wellFormed) {
		ret = dtdCtxt->myDoc->intSubset;
		dtdCtxt->myDoc->intSubset = NULL;
	    } else {
		ret = NULL;
	    }
	    xmlFreeDoc(dtdCtxt->myDoc);
	    dtdCtxt->myDoc = NULL;
	}
	xmlFreeParserCtxt(dtdCtxt);
	
	ctxt->myDoc->extSubset = ret;
    }
}

/**
 * resolveEntity:
 * @ctx: the user data (XML parser context)
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * Special entity resolver, better left to the parser, it has
 * more context than the application layer.
 * The default behaviour is to NOT resolve the entities, in that case
 * the ENTITY_REF nodes are built in the structure (and the parameter
 * values).
 *
 * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
 */
xmlParserInputPtr
resolveEntity(void *ctx, const CHAR *publicId, const CHAR *systemId)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.resolveEntity(%s, %s)\n", publicId, systemId);
#endif

    /*
     * TODO : not 100% sure that the appropriate handling in that case.
     */
    if (systemId != NULL) {
        if (!xmlStrncmp(systemId, "http://", 7)) {
	    /* !!!!!!!!! TODO */
	} else if (!xmlStrncmp(systemId, "ftp://", 6)) {
	    /* !!!!!!!!! TODO */
	} else {
	    return(xmlNewInputFromFile(ctxt, systemId));
	}
    }
    return(NULL);
}

/**
 * getEntity:
 * @ctx: the user data (XML parser context)
 * @name: The entity name
 *
 * Get an entity by name
 *
 * Returns the xmlEntityPtr if found.
 */
xmlEntityPtr
getEntity(void *ctx, const CHAR *name)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlEntityPtr ret;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.getEntity(%s)\n", name);
#endif

    ret = xmlGetDocEntity(ctxt->myDoc, name);
    return(ret);
}

/**
 * getParameterEntity:
 * @ctx: the user data (XML parser context)
 * @name: The entity name
 *
 * Get a parameter entity by name
 *
 * Returns the xmlEntityPtr if found.
 */
xmlEntityPtr
getParameterEntity(void *ctx, const CHAR *name)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlEntityPtr ret;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.getParameterEntity(%s)\n", name);
#endif

    ret = xmlGetParameterEntity(ctxt->myDoc, name);
    return(ret);
}


/**
 * entityDecl:
 * @ctx: the user data (XML parser context)
 * @name:  the entity name 
 * @type:  the entity type 
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 * @content: the entity value (without processing).
 *
 * An entity definition has been parsed
 */
void
entityDecl(void *ctx, const CHAR *name, int type,
          const CHAR *publicId, const CHAR *systemId, CHAR *content)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.entityDecl(%s, %d, %s, %s, %s)\n",
            name, type, publicId, systemId, content);
#endif
    xmlAddDocEntity(ctxt->myDoc, name, type, publicId, systemId, content);
}

/**
 * attributeDecl:
 * @ctx: the user data (XML parser context)
 * @name:  the attribute name 
 * @type:  the attribute type 
 * @publicId: The public ID of the attribute
 * @systemId: The system ID of the attribute
 * @content: the attribute value (without processing).
 *
 * An attribute definition has been parsed
 */
void
attributeDecl(void *ctx, const CHAR *elem, const CHAR *name,
              int type, int def, const CHAR *defaultValue,
	      xmlEnumerationPtr tree)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlAttributePtr attr;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.attributeDecl(%s, %s, %d, %d, %s, ...)\n",
            elem, name, type, def, defaultValue);
#endif
    attr = xmlAddAttributeDecl(&ctxt->vctxt, ctxt->myDoc->intSubset, elem,
                               name, type, def, defaultValue, tree);
    if (attr == 0) ctxt->valid = 0;
    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
	ctxt->valid &= xmlValidateAttributeDecl(&ctxt->vctxt, ctxt->myDoc,
	                                        attr);
}

/**
 * elementDecl:
 * @ctx: the user data (XML parser context)
 * @name:  the element name 
 * @type:  the element type 
 * @publicId: The public ID of the element
 * @systemId: The system ID of the element
 * @content: the element value (without processing).
 *
 * An element definition has been parsed
 */
void
elementDecl(void *ctx, const CHAR *name, int type,
	    xmlElementContentPtr content)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlElementPtr elem;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.elementDecl(%s, %d, ...)\n",
            name, type);
#endif
    
    elem = xmlAddElementDecl(&ctxt->vctxt, ctxt->myDoc->intSubset,
                             name, type, content);
    if (elem == 0) ctxt->valid = 0;
    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
	ctxt->valid &= xmlValidateElementDecl(&ctxt->vctxt, ctxt->myDoc, elem);
}

/**
 * notationDecl:
 * @ctx: the user data (XML parser context)
 * @name: The name of the notation
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * What to do when a notation declaration has been parsed.
 * TODO Not handled currently.
 */
void
notationDecl(void *ctx, const CHAR *name,
	     const CHAR *publicId, const CHAR *systemId)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNotationPtr nota;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.notationDecl(%s, %s, %s)\n", name, publicId, systemId);
#endif

    nota = xmlAddNotationDecl(&ctxt->vctxt, ctxt->myDoc->intSubset, name,
                              publicId, systemId);
    if (nota == 0) ctxt->valid = 0;
    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
	ctxt->valid &= xmlValidateNotationDecl(&ctxt->vctxt, ctxt->myDoc,
	                                       nota);
}

/**
 * unparsedEntityDecl:
 * @ctx: the user data (XML parser context)
 * @name: The name of the entity
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 * @notationName: the name of the notation
 *
 * What to do when an unparsed entity declaration is parsed
 * TODO Create an Entity node.
 */
void
unparsedEntityDecl(void *ctx, const CHAR *name,
		   const CHAR *publicId, const CHAR *systemId,
		   const CHAR *notationName)
{
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.unparsedEntityDecl(%s, %s, %s, %s)\n",
            name, publicId, systemId, notationName);
#endif
}

/**
 * setDocumentLocator:
 * @ctx: the user data (XML parser context)
 * @loc: A SAX Locator
 *
 * Receive the document locator at startup, actually xmlDefaultSAXLocator
 * Everything is available on the context, so this is useless in our case.
 */
void
setDocumentLocator(void *ctx, xmlSAXLocatorPtr loc)
{
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.setDocumentLocator()\n");
#endif
}

/**
 * startDocument:
 * @ctx: the user data (XML parser context)
 *
 * called when the document start being processed.
 */
void
startDocument(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlDocPtr doc;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startDocument()\n");
#endif
    doc = ctxt->myDoc = xmlNewDoc(ctxt->version);
    if (doc != NULL) {
	if (ctxt->encoding != NULL)
	    doc->encoding = xmlStrdup(ctxt->encoding);
	else
	    doc->encoding = NULL;
	doc->standalone = ctxt->standalone;
    }
}

/**
 * endDocument:
 * @ctx: the user data (XML parser context)
 *
 * called when the document end has been detected.
 */
void
endDocument(void *ctx)
{
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.endDocument()\n");
#endif
}

/**
 * attribute:
 * @ctx: the user data (XML parser context)
 * @name:  The attribute name
 * @value:  The attribute value
 *
 * Handle an attribute that has been read by the parser.
 * The default handling is to convert the attribute into an
 * DOM subtree and past it in a new xmlAttr element added to
 * the element.
 */
void
attribute(void *ctx, const CHAR *fullname, const CHAR *value)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlAttrPtr ret;
    CHAR *name;
    CHAR *ns;

/****************
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.attribute(%s, %s)\n", fullname, value);
#endif
 ****************/
    /*
     * Split the full name into a namespace prefix and the tag name
     */
    name = xmlSplitQName(fullname, &ns);

    /*
     * Check whether it's a namespace definition
     */
    if ((ns == NULL) &&
        (name[0] == 'x') && (name[1] == 'm') && (name[2] == 'l') &&
        (name[3] == 'n') && (name[4] == 's') && (name[5] == 0)) {
	/* a default namespace definition */
	xmlNewNs(ctxt->node, value, NULL);
	if (name != NULL) 
	    free(name);
	return;
    }
    if ((ns != NULL) && (ns[0] == 'x') && (ns[1] == 'm') && (ns[2] == 'l') &&
        (ns[3] == 'n') && (ns[4] == 's') && (ns[5] == 0)) {
	/* a standard namespace definition */
	xmlNewNs(ctxt->node, value, name);
	free(ns);
	if (name != NULL) 
	    free(name);
	return;
    }

    ret = xmlNewProp(ctxt->node, name, NULL);

    if ((ret != NULL) && (ctxt->replaceEntities == 0))
	ret->val = xmlStringGetNodeList(ctxt->myDoc, value);

    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
        ctxt->valid &= xmlValidateOneAttribute(&ctxt->vctxt, ctxt->myDoc,
					       ctxt->node, ret, value);

    if (name != NULL) 
	free(name);
    if (ns != NULL) 
	free(ns);
}

/**
 * startElement:
 * @ctx: the user data (XML parser context)
 * @name:  The element name
 * @atts:  An array of name/value attributes pairs, NULL terminated
 *
 * called when an opening tag has been processed.
 * TODO We currently have a small pblm with the arguments ...
 */
void
startElement(void *ctx, const CHAR *fullname, const CHAR **atts)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;
    xmlNodePtr parent = ctxt->node;
    xmlNsPtr ns;
    CHAR *name;
    CHAR *prefix;
    const CHAR *att;
    const CHAR *value;

    int i;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startElement(%s)\n", fullname);
#endif
    /*
     * Split the full name into a namespace prefix and the tag name
     */
    name = xmlSplitQName(fullname, &prefix);


    /*
     * Note : the namespace resolution is deferred until the end of the
     *        attributes parsing, since local namespace can be defined as
     *        an attribute at this level.
     */
    ret = xmlNewDocNode(ctxt->myDoc, NULL, name, NULL);
    if (ret == NULL) return;
    if (ctxt->myDoc->root == NULL)
        ctxt->myDoc->root = ret;

    /*
     * We are parsing a new node.
     */
    nodePush(ctxt, ret);

    /*
     * Link the child element
     */
    if (parent != NULL)
	xmlAddChild(parent, ctxt->node);

    /*
     * process all the attributes.
     */
    if (atts != NULL) {
        i = 0;
	att = atts[i++];
	value = atts[i++];
        while ((att != NULL) && (value != NULL)) {
	    /*
	     * Handle one pair of attribute/value
	     */
	    attribute(ctxt, att, value);

	    /*
	     * Next ones
	     */
	    att = atts[i++];
	    value = atts[i++];
	}
    }

    /*
     * Search the namespace, note that since the attributes have been
     * processed, the local namespaces are available.
     */
    ns = xmlSearchNs(ctxt->myDoc, ret, prefix);
    if ((ns == NULL) && (parent != NULL))
	ns = xmlSearchNs(ctxt->myDoc, parent, prefix);
    xmlSetNs(ret, ns);

    if (prefix != NULL)
	free(prefix);
    if (name != NULL)
	free(name);

}

/**
 * endElement:
 * @ctx: the user data (XML parser context)
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
void
endElement(void *ctx, const CHAR *name)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserNodeInfo node_info;
    xmlNodePtr cur = ctxt->node;

#ifdef DEBUG_SAX
    if (name == NULL)
        fprintf(stderr, "SAX.endElement(NULL)\n");
    else
	fprintf(stderr, "SAX.endElement(%s)\n", name);
#endif
    
    /* Capture end position and add node */
    if (cur != NULL && ctxt->record_info) {
      node_info.end_pos = ctxt->input->cur - ctxt->input->base;
      node_info.end_line = ctxt->input->line;
      node_info.node = cur;
      xmlParserAddNodeInfo(ctxt, &node_info);
    }

    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
        ctxt->valid &= xmlValidateOneElement(&ctxt->vctxt, ctxt->myDoc,
					     cur);

    
    /*
     * end of parsing of this node.
     */
    nodePop(ctxt);
}

/**
 * reference:
 * @ctx: the user data (XML parser context)
 * @name:  The entity name
 *
 * called when an entity reference is detected. 
 */
void
reference(void *ctx, const CHAR *name)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.reference(%s)\n", name);
#endif
    ret = xmlNewReference(ctxt->myDoc, name);
    xmlAddChild(ctxt->node, ret);
}

/**
 * characters:
 * @ctx: the user data (XML parser context)
 * @ch:  a CHAR string
 * @len: the number of CHAR
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
void
characters(void *ctx, const CHAR *ch, int len)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr lastChild;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.characters(%.30s, %d)\n", ch, len);
#endif
    /*
     * Handle the data if any. If there is no child
     * add it as content, otherwise if the last child is text,
     * concatenate it, else create a new node of type text.
     */

    lastChild = xmlGetLastChild(ctxt->node);
    if (lastChild == NULL)
	xmlNodeAddContentLen(ctxt->node, ch, len);
    else {
	if (xmlNodeIsText(lastChild))
	    xmlTextConcat(lastChild, ch, len);
	else {
	    lastChild = xmlNewTextLen(ch, len);
	    xmlAddChild(ctxt->node, lastChild);
	}
    }
}

/**
 * ignorableWhitespace:
 * @ctx: the user data (XML parser context)
 * @ch:  a CHAR string
 * @len: the number of CHAR
 *
 * receiving some ignorable whitespaces from the parser.
 * Question: how much at a time ???
 */
void
ignorableWhitespace(void *ctx, const CHAR *ch, int len)
{
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.ignorableWhitespace(%.30s, %d)\n", ch, len);
#endif
}

/**
 * processingInstruction:
 * @ctx: the user data (XML parser context)
 * @target:  the target name
 * @data: the PI data's
 * @len: the number of CHAR
 *
 * A processing instruction has been parsed.
 */
void
processingInstruction(void *ctx, const CHAR *target,
                      const CHAR *data)
{
    /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.processingInstruction(%s, %s)\n", target, data);
#endif
}

/**
 * globalNamespace:
 * @ctx: the user data (XML parser context)
 * @href:  the namespace associated URN
 * @prefix: the namespace prefix
 *
 * An old global namespace has been parsed.
 */
void
globalNamespace(void *ctx, const CHAR *href, const CHAR *prefix)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.globalNamespace(%s, %s)\n", href, prefix);
#endif
    xmlNewGlobalNs(ctxt->myDoc, href, prefix);
}

/**
 * setNamespace:
 * @ctx: the user data (XML parser context)
 * @name:  the namespace prefix
 *
 * Set the current element namespace.
 */
void
setNamespace(void *ctx, const CHAR *name)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNsPtr ns;
    xmlNodePtr parent;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.setNamespace(%s)\n", name);
#endif
    ns = xmlSearchNs(ctxt->myDoc, ctxt->node, name);
    if (ns == NULL) { /* ctxt->node may not have a parent yet ! */
        if (ctxt->nodeNr >= 2) {
	    parent = ctxt->nodeTab[ctxt->nodeNr - 2];
	    if (parent != NULL)
		ns = xmlSearchNs(ctxt->myDoc, parent, name);
	}
    }
    xmlSetNs(ctxt->node, ns);
}

/**
 * getNamespace:
 * @ctx: the user data (XML parser context)
 *
 * Get the current element namespace.
 */
xmlNsPtr
getNamespace(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNsPtr ret;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.getNamespace()\n");
#endif
    ret = ctxt->node->ns;
    return(ret);
}

/**
 * checkNamespace:
 * @ctx: the user data (XML parser context)
 * @namespace: the namespace to check against
 *
 * Check that the current element namespace is the same as the
 * one read upon parsing.
 */
int
checkNamespace(void *ctx, CHAR *namespace)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr cur = ctxt->node;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.checkNamespace(%s)\n", namespace);
#endif

    /*
     * Check that the Name in the ETag is the same as in the STag.
     */
    if (namespace == NULL) {
        if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
		 "End tags for %s don't hold the namespace %s\n",
		                 cur->name, cur->ns->prefix);
	    ctxt->wellFormed = 0;
	}
    } else {
        if ((cur->ns == NULL) || (cur->ns->prefix == NULL)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
		 "End tags %s holds a prefix %s not used by the open tag\n",
		                 cur->name, namespace);
	    ctxt->wellFormed = 0;
	} else if (strcmp(namespace, cur->ns->prefix)) {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
    "Start and End tags for %s don't use the same namespaces: %s and %s\n",
	                         cur->name, cur->ns->prefix, namespace);
	    ctxt->wellFormed = 0;
	} else
	    return(1);
    }
    return(0);
}

/**
 * namespaceDecl:
 * @ctx: the user data (XML parser context)
 * @href:  the namespace associated URN
 * @prefix: the namespace prefix
 *
 * A namespace has been parsed.
 */
void
namespaceDecl(void *ctx, const CHAR *href, const CHAR *prefix)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
#ifdef DEBUG_SAX
    if (prefix == NULL)
	fprintf(stderr, "SAX.namespaceDecl(%s, NULL)\n", href);
    else
	fprintf(stderr, "SAX.namespaceDecl(%s, %s)\n", href, prefix);
#endif
    xmlNewNs(ctxt->node, href, prefix);
}

/**
 * comment:
 * @ctx: the user data (XML parser context)
 * @value:  the comment content
 *
 * A comment has been parsed.
 */
void
comment(void *ctx, const CHAR *value)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.comment(%s)\n", value);
#endif
    ret = xmlNewDocComment(ctxt->myDoc, value);
    xmlAddChild(ctxt->node, ret);
    /* !!!!! merges */
}

/**
 * cdataBlock:
 * @ctx: the user data (XML parser context)
 * @value:  The pcdata content
 * @len:  the block length
 *
 * called when a pcdata block has been parsed
 */
void
cdataBlock(void *ctx, const CHAR *value, int len)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.pcdata(%s, %d)\n", name, len);
#endif
    ret = xmlNewCDataBlock(ctxt->myDoc, value, len);
    xmlAddChild(ctxt->node, ret);
    /* !!!!! merges */
}

/*
 * Default handler for XML, builds the DOM tree
 */
xmlSAXHandler xmlDefaultSAXHandler = {
    internalSubset,
    isStandalone,
    hasInternalSubset,
    hasExternalSubset,
    resolveEntity,
    getEntity,
    entityDecl,
    notationDecl,
    attributeDecl,
    elementDecl,
    unparsedEntityDecl,
    setDocumentLocator,
    startDocument,
    endDocument,
    startElement,
    endElement,
    reference,
    characters,
    ignorableWhitespace,
    processingInstruction,
    comment,
    xmlParserWarning,
    xmlParserError,
    xmlParserError,
    getParameterEntity,
    cdataBlock,
};

/**
 * xmlDefaultSAXHandlerInit:
 *
 * Initialize the default SAX handler
 */
void
xmlDefaultSAXHandlerInit(void)
{
    xmlDefaultSAXHandler.internalSubset = internalSubset;
    xmlDefaultSAXHandler.isStandalone = isStandalone;
    xmlDefaultSAXHandler.hasInternalSubset = hasInternalSubset;
    xmlDefaultSAXHandler.hasExternalSubset = hasExternalSubset;
    xmlDefaultSAXHandler.resolveEntity = resolveEntity;
    xmlDefaultSAXHandler.getEntity = getEntity;
    xmlDefaultSAXHandler.getParameterEntity = getParameterEntity;
    xmlDefaultSAXHandler.entityDecl = entityDecl;
    xmlDefaultSAXHandler.attributeDecl = attributeDecl;
    xmlDefaultSAXHandler.elementDecl = elementDecl;
    xmlDefaultSAXHandler.notationDecl = notationDecl;
    xmlDefaultSAXHandler.unparsedEntityDecl = unparsedEntityDecl;
    xmlDefaultSAXHandler.setDocumentLocator = setDocumentLocator;
    xmlDefaultSAXHandler.startDocument = startDocument;
    xmlDefaultSAXHandler.endDocument = endDocument;
    xmlDefaultSAXHandler.startElement = startElement;
    xmlDefaultSAXHandler.endElement = endElement;
    xmlDefaultSAXHandler.reference = reference;
    xmlDefaultSAXHandler.characters = characters;
    xmlDefaultSAXHandler.cdataBlock = cdataBlock;
    xmlDefaultSAXHandler.ignorableWhitespace = ignorableWhitespace;
    xmlDefaultSAXHandler.processingInstruction = processingInstruction;
    xmlDefaultSAXHandler.comment = comment;
    xmlDefaultSAXHandler.warning = xmlParserWarning;
    xmlDefaultSAXHandler.error = xmlParserError;
    xmlDefaultSAXHandler.fatalError = xmlParserError;
}

/*
 * Default handler for HTML, builds the DOM tree
 */
xmlSAXHandler htmlDefaultSAXHandler = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    getEntity,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    setDocumentLocator,
    startDocument,
    endDocument,
    startElement,
    endElement,
    NULL,
    characters,
    ignorableWhitespace,
    NULL,
    comment,
    xmlParserWarning,
    xmlParserError,
    xmlParserError,
    getParameterEntity,
    NULL,
};

/**
 * htmlDefaultSAXHandlerInit:
 *
 * Initialize the default SAX handler
 */
void
htmlDefaultSAXHandlerInit(void)
{
    htmlDefaultSAXHandler.internalSubset = NULL;
    htmlDefaultSAXHandler.isStandalone = NULL;
    htmlDefaultSAXHandler.hasInternalSubset = NULL;
    htmlDefaultSAXHandler.hasExternalSubset = NULL;
    htmlDefaultSAXHandler.resolveEntity = NULL;
    htmlDefaultSAXHandler.getEntity = getEntity;
    htmlDefaultSAXHandler.getParameterEntity = NULL;
    htmlDefaultSAXHandler.entityDecl = NULL;
    htmlDefaultSAXHandler.attributeDecl = NULL;
    htmlDefaultSAXHandler.elementDecl = NULL;
    htmlDefaultSAXHandler.notationDecl = NULL;
    htmlDefaultSAXHandler.unparsedEntityDecl = NULL;
    htmlDefaultSAXHandler.setDocumentLocator = setDocumentLocator;
    htmlDefaultSAXHandler.startDocument = startDocument;
    htmlDefaultSAXHandler.endDocument = endDocument;
    htmlDefaultSAXHandler.startElement = startElement;
    htmlDefaultSAXHandler.endElement = endElement;
    htmlDefaultSAXHandler.reference = NULL;
    htmlDefaultSAXHandler.characters = characters;
    htmlDefaultSAXHandler.cdataBlock = NULL;
    htmlDefaultSAXHandler.ignorableWhitespace = ignorableWhitespace;
    htmlDefaultSAXHandler.processingInstruction = NULL;
    htmlDefaultSAXHandler.comment = comment;
    htmlDefaultSAXHandler.warning = xmlParserWarning;
    htmlDefaultSAXHandler.error = xmlParserError;
    htmlDefaultSAXHandler.fatalError = xmlParserError;
}
