/*
 * Summary: implementation of XML Schema Datatypes
 * Description: module providing the XML Schema Datatypes implementation
 *              both definition and validity checking
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Daniel Veillard
 */


#ifndef __XML_SCHEMA_TYPES_H__
#define __XML_SCHEMA_TYPES_H__

#include <libxml/xmlversion.h>

#ifdef LIBXML_SCHEMAS_ENABLED

#include <libxml/schemasInternals.h>
#include <libxml/xmlschemas.h>

#ifdef __cplusplus
extern "C" {
#endif

XMLPUBFUN void XMLCALL		
    		xmlSchemaInitTypes		(void);
XMLPUBFUN void XMLCALL		
		xmlSchemaCleanupTypes		(void);
XMLPUBFUN xmlSchemaTypePtr XMLCALL 
		xmlSchemaGetPredefinedType	(const xmlChar *name,
						 const xmlChar *ns);
XMLPUBFUN int XMLCALL		
		xmlSchemaValidatePredefinedType	(xmlSchemaTypePtr type,
						 const xmlChar *value,
						 xmlSchemaValPtr *val);
XMLPUBFUN int XMLCALL		
		xmlSchemaValPredefTypeNode	(xmlSchemaTypePtr type,
						 const xmlChar *value,
						 xmlSchemaValPtr *val,
						 xmlNodePtr node);
XMLPUBFUN int XMLCALL		
		xmlSchemaValidateFacet		(xmlSchemaTypePtr base,
						 xmlSchemaFacetPtr facet,
						 const xmlChar *value,
						 xmlSchemaValPtr val);
XMLPUBFUN void XMLCALL		
		xmlSchemaFreeValue		(xmlSchemaValPtr val);
XMLPUBFUN xmlSchemaFacetPtr XMLCALL 
		xmlSchemaNewFacet		(void);
XMLPUBFUN int XMLCALL		
		xmlSchemaCheckFacet		(xmlSchemaFacetPtr facet,
						 xmlSchemaTypePtr typeDecl,
						 xmlSchemaParserCtxtPtr ctxt,
						 const xmlChar *name);
XMLPUBFUN void XMLCALL		
		xmlSchemaFreeFacet		(xmlSchemaFacetPtr facet);
XMLPUBFUN int XMLCALL		
		xmlSchemaCompareValues		(xmlSchemaValPtr x,
						 xmlSchemaValPtr y);

#ifdef __cplusplus
}
#endif

#endif /* LIBXML_SCHEMAS_ENABLED */
#endif /* __XML_SCHEMA_TYPES_H__ */
