/*
 * SAX.c : Default SAX handler to build a tree.
 *
 * See Copyright for the status of this software.
 *
 * Daniel Veillard <Daniel.Veillard@w3.org>
 */


#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include "xmlmemory.h"
#include "tree.h"
#include "parser.h"
#include "parserInternals.h"
#include "valid.h"
#include "entities.h"
#include "xml-error.h"
#include "debugXML.h"
#include "xmlIO.h"
#include "SAX.h"
#include "uri.h"

/* #define DEBUG_SAX */
/* #define DEBUG_SAX_TREE */

/* a couple of the old parser 1.8.11 entry points needed */
void xmlOldParseExternalSubset(xmlParserCtxtPtr ctxt,
	const xmlChar *ExternalID, const xmlChar *SystemID);
void xmlOldPushInput(xmlParserCtxtPtr ctxt, xmlParserInputPtr input);

/**
 * getPublicId:
 * @ctx: the user data (XML parser context)
 *
 * Return the public ID e.g. "-//SGMLSOURCE//DTD DEMO//EN"
 *
 * Returns a xmlChar *
 */
const xmlChar *
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
 * Returns a xmlChar *
 */
const xmlChar *
getSystemId(void *ctx)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    return(BAD_CAST ctxt->input->filename); 
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
 * Callback on internal subset declaration.
 */
void
internalSubset(void *ctx, const xmlChar *name,
	       const xmlChar *ExternalID, const xmlChar *SystemID)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.internalSubset(%s, %s, %s)\n",
            name, ExternalID, SystemID);
#endif
    if (ctxt->myDoc == NULL)
	return;
    if (ctxt->pedantic) {
	/* 2.3.5 parser handler */
	if (ctxt->myDoc->intSubset == NULL) 
	    xmlCreateIntSubset(ctxt->myDoc, name, ExternalID, SystemID);
	if (((ExternalID != NULL) || (SystemID != NULL)) &&
	    (ctxt->validate && ctxt->wellFormed && ctxt->myDoc)) {
	    /*
	     * Try to fetch and parse the external subset.
	     * Grabbed from externalSubset in 2.3.5
	     */
	    xmlParserInputPtr oldinput;
	    int oldinputNr;
	    int oldinputMax;
	    xmlParserInputPtr *oldinputTab;
	    int oldwellFormed;
	    xmlParserInputPtr input = NULL;
	    xmlCharEncoding enc;
	    int oldcharset;

	    /*
	     * Ask the Entity resolver to load the damn thing
	     */
	    if ((ctxt->sax != NULL) && (ctxt->sax->resolveEntity != NULL))
		input = ctxt->sax->resolveEntity(ctxt->userData, ExternalID,
						    SystemID);
	    if (input == NULL) {
		return;
	    }

	    xmlNewDtd(ctxt->myDoc, name, ExternalID, SystemID);

	    /*
	     * make sure we won't destroy the main document context
	     */
	    oldinput = ctxt->input;
	    oldinputNr = ctxt->inputNr;
	    oldinputMax = ctxt->inputMax;
	    oldinputTab = ctxt->inputTab;
	    oldwellFormed = ctxt->wellFormed;
	    oldcharset = ctxt->charset;

	    ctxt->inputTab = (xmlParserInputPtr *)
			     xmlMalloc(5 * sizeof(xmlParserInputPtr));
	    if (ctxt->inputTab == NULL) {
		ctxt->errNo = XML_ERR_NO_MEMORY;
		if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		    ctxt->sax->error(ctxt->userData, 
			 "externalSubset: out of memory\n");
		ctxt->errNo = XML_ERR_NO_MEMORY;
		ctxt->input = oldinput;
		ctxt->inputNr = oldinputNr;
		ctxt->inputMax = oldinputMax;
		ctxt->inputTab = oldinputTab;
		ctxt->charset = oldcharset;
		return;
	    }
	    ctxt->inputNr = 0;
	    ctxt->inputMax = 5;
	    ctxt->input = NULL;
	    xmlPushInput(ctxt, input);

	    /*
	     * On the fly encoding conversion if needed
	     */
	    enc = xmlDetectCharEncoding(ctxt->input->cur);
	    xmlSwitchEncoding(ctxt, enc);

	    if (input->filename == NULL)
		input->filename = (char *) xmlStrdup(SystemID);
	    input->line = 1;
	    input->col = 1;
	    input->base = ctxt->input->cur;
	    input->cur = ctxt->input->cur;
	    input->free = NULL;

	    /*
	     * let's parse that entity knowing it's an external subset.
	     */
	    ctxt->inSubset = 2;
	    xmlParseExternalSubset(ctxt, ExternalID, SystemID);

	    /*
	     * Free up the external entities
	     */

	    while (ctxt->inputNr > 1)
		xmlPopInput(ctxt);
	    xmlFreeInputStream(ctxt->input);
	    xmlFree(ctxt->inputTab);

	    /*
	     * Restore the parsing context of the main entity
	     */
	    ctxt->input = oldinput;
	    ctxt->inputNr = oldinputNr;
	    ctxt->inputMax = oldinputMax;
	    ctxt->inputTab = oldinputTab;
	    ctxt->charset = oldcharset;
	    /* ctxt->wellFormed = oldwellFormed; */
	}
    } else {
	/* old 1.8.11 code */
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
	    ctxt->pedantic = 0;

	    /*
	     * Ask the Entity resolver to load the damn thing
	     */
	    if ((ctxt->directory != NULL) && (dtdCtxt->directory == NULL))
		dtdCtxt->directory = (char *) xmlStrdup(BAD_CAST ctxt->directory);

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
	    xmlOldPushInput(dtdCtxt, input);
	    enc = xmlDetectCharEncoding(dtdCtxt->input->cur);
	    xmlSwitchEncoding(dtdCtxt, enc);

	    if (input->filename == NULL)
		input->filename = (char *) xmlStrdup(SystemID);
	    input->line = 1;
	    input->col = 1;
	    input->base = dtdCtxt->input->cur;
	    input->cur = dtdCtxt->input->cur;
	    input->free = NULL;

	    /*
	     * let's parse that entity knowing it's an external subset.
	     */
	    xmlOldParseExternalSubset(dtdCtxt, ExternalID, SystemID);

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
}

/**
 * resolveEntity:
 * @ctx: the user data (XML parser context)
 * @publicId: The public ID of the entity
 * @systemId: The system ID of the entity
 *
 * The entity loader, to control the loading of external entities,
 * the application can either:
 *    - override this resolveEntity() callback in the SAX block
 *    - or better use the xmlSetExternalEntityLoader() function to
 *      set up it's own entity resolution routine
 *
 * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
 */
xmlParserInputPtr
resolveEntity(void *ctx, const xmlChar *publicId, const xmlChar *systemId)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.resolveEntity(%s, %s)\n", publicId, systemId);
#endif

    return(xmlLoadExternalEntity((const char *) systemId,
				 (const char *) publicId, ctxt));
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
getEntity(void *ctx, const xmlChar *name)
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
getParameterEntity(void *ctx, const xmlChar *name)
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
entityDecl(void *ctx, const xmlChar *name, int type,
          const xmlChar *publicId, const xmlChar *systemId, xmlChar *content)
{
    xmlEntityPtr ent;
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

#ifdef DEBUG_SAX
    xmlGenericError(xmlGenericErrorContext,
	    "SAX.entityDecl(%s, %d, %s, %s, %s)\n",
            name, type, publicId, systemId, content);
#endif
    if (ctxt->pedantic) {
	/* 2.3.5 parser */
	if (ctxt->inSubset == 1) {
	    xmlAddDocEntity(ctxt->myDoc, name, type, publicId,
				  systemId, content);
	    if ((type == XML_INTERNAL_PARAMETER_ENTITY) ||
		(type == XML_EXTERNAL_PARAMETER_ENTITY))
		ent = xmlGetParameterEntity(ctxt->myDoc, name);
	    else
		ent = xmlGetDocEntity(ctxt->myDoc, name);
	    if ((ent == NULL) && (ctxt->pedantic) &&
		(ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
		ctxt->sax->warning(ctxt, 
		 "Entity(%s) already defined in the internal subset\n", name);
	    if ((ent != NULL) && (ent->URI == NULL) && (systemId != NULL)) {
		xmlChar *URI;
		const char *base = NULL;

		if (ctxt->input != NULL)
		    base = ctxt->input->filename;
		if (base == NULL)
		    base = ctxt->directory;
	    
		URI = xmlBuildURI(systemId, (const xmlChar *) base);
		ent->URI = URI;
	    }
	} else if (ctxt->inSubset == 2) {
	    xmlAddDtdEntity(ctxt->myDoc, name, type, publicId,
				  systemId, content);
	    if ((type == XML_INTERNAL_PARAMETER_ENTITY) ||
		(type == XML_EXTERNAL_PARAMETER_ENTITY))
		ent = xmlGetParameterEntity(ctxt->myDoc, name);
	    else
		ent = xmlGetDtdEntity(ctxt->myDoc, name);
	    if ((ent == NULL) && (ctxt->pedantic) &&
		(ctxt->sax != NULL) && (ctxt->sax->warning != NULL))
		ctxt->sax->warning(ctxt, 
		 "Entity(%s) already defined in the external subset\n", name);
	    if ((ent != NULL) && (ent->URI == NULL) && (systemId != NULL)) {
		xmlChar *URI;
		const char *base = NULL;

		if (ctxt->input != NULL)
		    base = ctxt->input->filename;
		if (base == NULL)
		    base = ctxt->directory;
	    
		URI = xmlBuildURI(systemId, (const xmlChar *) base);
		ent->URI = URI;
	    }
	} else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
		 "SAX.entityDecl(%s) called while not in subset\n", name);
	}
    } else {
	/* 1.8.11 parser */
	xmlAddDocEntity(ctxt->myDoc, name, type, publicId, systemId, content);
    }
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
attributeDecl(void *ctx, const xmlChar *elem, const xmlChar *name,
              int type, int def, const xmlChar *defaultValue,
	      xmlEnumerationPtr tree)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlAttributePtr attr;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.attributeDecl(%s, %s, %d, %d, %s, ...)\n",
            elem, name, type, def, defaultValue);
#endif
    if (ctxt->pedantic) {
	/* 2.3.5 parser code */
	if (ctxt->inSubset == 1)
	    attr = xmlAddAttributeDecl(&ctxt->vctxt, ctxt->myDoc->intSubset,
				 elem, name, type, def, defaultValue, tree);
	else if (ctxt->inSubset == 2)
	    attr = xmlAddAttributeDecl(&ctxt->vctxt, ctxt->myDoc->extSubset,
				 elem, name, type, def, defaultValue, tree);
	else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
		 "SAX.attributeDecl(%s) called while not in subset\n", name);
	    return;
	}
    } else {
	/* 1.8.11 parser */
	attr = xmlAddAttributeDecl(&ctxt->vctxt, ctxt->myDoc->intSubset, elem,
				   name, type, def, defaultValue, tree);
    }
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
elementDecl(void *ctx, const xmlChar *name, int type,
	    xmlElementContentPtr content)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlElementPtr elem;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.elementDecl(%s, %d, ...)\n",
            name, type);
#endif
    
    if (ctxt->pedantic) {
	/* 2.3.5 parser code */
	if (ctxt->inSubset == 1)
	    elem = xmlAddElementDecl(&ctxt->vctxt, ctxt->myDoc->intSubset,
				 name, (xmlElementTypeVal) type, content);
	else if (ctxt->inSubset == 2)
	    elem = xmlAddElementDecl(&ctxt->vctxt, ctxt->myDoc->extSubset,
				 name, (xmlElementTypeVal) type, content);
	else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
		 "SAX.elementDecl(%s) called while not in subset\n", name);
	    return;
	}
    } else {
	/* 1.8.11 parser code */
	elem = xmlAddElementDecl(&ctxt->vctxt, ctxt->myDoc->intSubset,
				 name, type, content);
    }
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
 */
void
notationDecl(void *ctx, const xmlChar *name,
	     const xmlChar *publicId, const xmlChar *systemId)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNotationPtr nota;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.notationDecl(%s, %s, %s)\n", name, publicId, systemId);
#endif

    if (ctxt->pedantic) {
	/* 2.3.5 parser code */
	if (ctxt->inSubset == 1)
	    nota = xmlAddNotationDecl(&ctxt->vctxt, ctxt->myDoc->intSubset, name,
				  publicId, systemId);
	else if (ctxt->inSubset == 2)
	    nota = xmlAddNotationDecl(&ctxt->vctxt, ctxt->myDoc->extSubset, name,
				  publicId, systemId);
	else {
	    if ((ctxt->sax != NULL) && (ctxt->sax->error != NULL))
		ctxt->sax->error(ctxt, 
		 "SAX.notationDecl(%s) called while not in subset\n", name);
	    return;
	}
    } else {
	nota = xmlAddNotationDecl(&ctxt->vctxt, ctxt->myDoc->intSubset, name,
				  publicId, systemId);
    }
    if (nota == NULL) ctxt->valid = 0;
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
 */
void
unparsedEntityDecl(void *ctx, const xmlChar *name,
		   const xmlChar *publicId, const xmlChar *systemId,
		   const xmlChar *notationName)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.unparsedEntityDecl(%s, %s, %s, %s)\n",
            name, publicId, systemId, notationName);
#endif
    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
	ctxt->valid &= xmlValidateNotationUse(&ctxt->vctxt, ctxt->myDoc,
	                                      notationName);
    xmlAddDocEntity(ctxt->myDoc, name,
                    XML_EXTERNAL_GENERAL_UNPARSED_ENTITY,
		    publicId, systemId, notationName);
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
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.endDocument()\n");
#endif
    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
	ctxt->valid &= xmlValidateDocumentFinal(&ctxt->vctxt, ctxt->myDoc);
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
attribute(void *ctx, const xmlChar *fullname, const xmlChar *value)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlAttrPtr ret;
    xmlChar *name;
    xmlChar *ns;
    xmlNsPtr namespace;

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
	    xmlFree(name);
	return;
    }
    if ((ns != NULL) && (ns[0] == 'x') && (ns[1] == 'm') && (ns[2] == 'l') &&
        (ns[3] == 'n') && (ns[4] == 's') && (ns[5] == 0)) {
	/* a standard namespace definition */
	xmlNewNs(ctxt->node, value, name);
	xmlFree(ns);
	if (name != NULL) 
	    xmlFree(name);
	return;
    }

    if (ns != NULL)
	namespace = xmlSearchNs(ctxt->myDoc, ctxt->node, ns);
    else {
	namespace = NULL;
    }

    /* !!!!!! <a toto:arg="" xmlns:toto="http://toto.com"> */
    ret = xmlNewNsProp(ctxt->node, namespace, name, NULL);

    if (ret != NULL) {
        if ((ctxt->replaceEntities == 0) && (!ctxt->html))
	    ret->val = xmlStringGetNodeList(ctxt->myDoc, value);
	else
	    ret->val = xmlNewDocText(ctxt->myDoc, value);
    }

    if (ctxt->validate && ctxt->wellFormed &&
        ctxt->myDoc && ctxt->myDoc->intSubset)
        ctxt->valid &= xmlValidateOneAttribute(&ctxt->vctxt, ctxt->myDoc,
					       ctxt->node, ret, value);
    else {
        /*
	 * when validating, the ID registration is done at the attribute
	 * validation level. Otherwise we have to do specific handling here.
	 */
	if (xmlIsID(ctxt->myDoc, ctxt->node, ret))
	    xmlAddID(&ctxt->vctxt, ctxt->myDoc, value, ret);
	else if (xmlIsRef(ctxt->myDoc, ctxt->node, ret))
	    xmlAddRef(&ctxt->vctxt, ctxt->myDoc, value, ret);
    }

    if (name != NULL) 
	xmlFree(name);
    if (ns != NULL) 
	xmlFree(ns);
}

/**
 * startElement:
 * @ctx: the user data (XML parser context)
 * @name:  The element name
 * @atts:  An array of name/value attributes pairs, NULL terminated
 *
 * called when an opening tag has been processed.
 */
void
startElement(void *ctx, const xmlChar *fullname, const xmlChar **atts)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;
    xmlNodePtr parent = ctxt->node;
    xmlNsPtr ns;
    xmlChar *name;
    xmlChar *prefix;
    const xmlChar *att;
    const xmlChar *value;
    int i;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.startElement(%s)\n", fullname);
#endif

    /*
     * First check on validity:
     */
    if (ctxt->validate && (ctxt->myDoc->extSubset == NULL) && 
        ((ctxt->myDoc->intSubset == NULL) ||
	 ((ctxt->myDoc->intSubset->notations == NULL) && 
	  (ctxt->myDoc->intSubset->elements == NULL) &&
	  (ctxt->myDoc->intSubset->attributes == NULL) && 
	  (ctxt->myDoc->intSubset->entities == NULL)))) {
	if (ctxt->vctxt.error != NULL) {
            ctxt->vctxt.error(ctxt->vctxt.userData,
	      "Validation failed: no DTD found !\n");
	}
	ctxt->validate = 0;
    }
       

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
    if (ctxt->myDoc->root == NULL) {
#ifdef DEBUG_SAX_TREE
	fprintf(stderr, "Setting %s as root\n", name);
#endif
        ctxt->myDoc->root = ret;
    } else if (parent == NULL) {
        parent = ctxt->myDoc->root;
    }

    /*
     * We are parsing a new node.
     */
#ifdef DEBUG_SAX_TREE
    fprintf(stderr, "pushing(%s)\n", name);
#endif
    nodePush(ctxt, ret);

    /*
     * Link the child element
     */
    if (parent != NULL) {
        if (parent->type == XML_ELEMENT_NODE) {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "adding child %s to %s\n", name, parent->name);
#endif
	    xmlAddChild(parent, ret);
	} else {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "adding sibling %s to ", name);
	    xmlDebugDumpOneNode(stderr, parent, 0);
#endif
	    xmlAddSibling(parent, ret);
	}
    }

    /*
     * process all the attributes whose name start with "xml"
     */
    if (atts != NULL) {
        i = 0;
	att = atts[i++];
	value = atts[i++];
        while ((att != NULL) && (value != NULL)) {
	    if ((att[0] == 'x') && (att[1] == 'm') && (att[2] == 'l'))
		attribute(ctxt, att, value);

	    att = atts[i++];
	    value = atts[i++];
	}
    }

    /*
     * process all the other attributes
     */
    if (atts != NULL) {
        i = 0;
	att = atts[i++];
	value = atts[i++];
        while ((att != NULL) && (value != NULL)) {
	    if ((att[0] != 'x') || (att[1] != 'm') || (att[2] != 'l'))
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
	xmlFree(prefix);
    if (name != NULL)
	xmlFree(name);

}

/**
 * endElement:
 * @ctx: the user data (XML parser context)
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
void
endElement(void *ctx, const xmlChar *name)
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
#ifdef DEBUG_SAX_TREE
    fprintf(stderr, "popping(%s)\n", cur->name);
#endif
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
reference(void *ctx, const xmlChar *name)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.reference(%s)\n", name);
#endif
    ret = xmlNewReference(ctxt->myDoc, name);
#ifdef DEBUG_SAX_TREE
    fprintf(stderr, "add reference %s to %s \n", name, ctxt->node->name);
#endif
    xmlAddChild(ctxt->node, ret);
}

/**
 * characters:
 * @ctx: the user data (XML parser context)
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
void
characters(void *ctx, const xmlChar *ch, int len)
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

    if (ctxt->node == NULL) {
#ifdef DEBUG_SAX_TREE
	fprintf(stderr, "add chars: ctxt->node == NULL !\n");
#endif
        return;
    }
    lastChild = xmlGetLastChild(ctxt->node);
#ifdef DEBUG_SAX_TREE
    fprintf(stderr, "add chars to %s \n", ctxt->node->name);
#endif
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
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some ignorable whitespaces from the parser.
 * Question: how much at a time ???
 */
void
ignorableWhitespace(void *ctx, const xmlChar *ch, int len)
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
 * @len: the number of xmlChar
 *
 * A processing instruction has been parsed.
 */
void
processingInstruction(void *ctx, const xmlChar *target,
                      const xmlChar *data)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;
    xmlNodePtr parent = ctxt->node;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.processingInstruction(%s, %s)\n", target, data);
#endif

    ret = xmlNewPI(target, data);
    if (ret == NULL) return;
    ret->doc = ctxt->myDoc;
    if (ctxt->myDoc->root == NULL) {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "Setting PI %s as root\n", target);
#endif
        ctxt->myDoc->root = ret;
    } else if (parent == NULL) {
        parent = ctxt->myDoc->root;
    }
    if (parent != NULL) {
        if (parent->type == XML_ELEMENT_NODE) {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "adding PI child %s to %s\n", target, parent->name);
#endif
	    xmlAddChild(parent, ret);
	} else {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "adding PI sibling %s to ", target);
	    xmlDebugDumpOneNode(stderr, parent, 0);
#endif
	    xmlAddSibling(parent, ret);
	}
    }

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
globalNamespace(void *ctx, const xmlChar *href, const xmlChar *prefix)
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
setNamespace(void *ctx, const xmlChar *name)
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
checkNamespace(void *ctx, xmlChar *namespace)
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
	} else if (xmlStrcmp(namespace, cur->ns->prefix)) {
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
namespaceDecl(void *ctx, const xmlChar *href, const xmlChar *prefix)
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
comment(void *ctx, const xmlChar *value)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret;
    xmlNodePtr parent = ctxt->node;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.comment(%s)\n", value);
#endif
    ret = xmlNewDocComment(ctxt->myDoc, value);
    if (ret == NULL) return;

    if (ctxt->myDoc->root == NULL) {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "Setting comment as root\n");
#endif
        ctxt->myDoc->root = ret;
    } else if (parent == NULL) {
        parent = ctxt->myDoc->root;
    }
    if (parent != NULL) {
        if (parent->type == XML_ELEMENT_NODE) {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "adding comment child to %s\n", parent->name);
#endif
	    xmlAddChild(parent, ret);
	} else {
#ifdef DEBUG_SAX_TREE
	    fprintf(stderr, "adding comment sibling to ");
	    xmlDebugDumpOneNode(stderr, parent, 0);
#endif
	    xmlAddSibling(parent, ret);
	}
    }
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
cdataBlock(void *ctx, const xmlChar *value, int len)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlNodePtr ret, lastChild;

#ifdef DEBUG_SAX
    fprintf(stderr, "SAX.pcdata(%.10s, %d)\n", value, len);
#endif
    lastChild = xmlGetLastChild(ctxt->node);
#ifdef DEBUG_SAX_TREE
    fprintf(stderr, "add chars to %s \n", ctxt->node->name);
#endif
    if ((lastChild != NULL) &&
        (lastChild->type == XML_CDATA_SECTION_NODE)) {
	xmlTextConcat(lastChild, value, len);
    } else {
	ret = xmlNewCDataBlock(ctxt->myDoc, value, len);
	xmlAddChild(ctxt->node, ret);
    }
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
