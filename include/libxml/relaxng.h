/*
 * relaxng.h: header for the implementation of the Relax-NG validation
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#ifndef __XML_RELAX_NG__
#define __XML_RELAX_NG__

#include <libxml/hash.h>

typedef struct _xmlRelaxNG xmlRelaxNG;
typedef xmlRelaxNG *xmlRelaxNGPtr;


/**
 * A schemas validation context
 */
typedef void (*xmlRelaxNGValidityErrorFunc) (void *ctx, const char *msg, ...);
typedef void (*xmlRelaxNGValidityWarningFunc) (void *ctx, const char *msg, ...);

typedef struct _xmlRelaxNGParserCtxt xmlRelaxNGParserCtxt;
typedef xmlRelaxNGParserCtxt *xmlRelaxNGParserCtxtPtr;

typedef struct _xmlRelaxNGValidCtxt xmlRelaxNGValidCtxt;
typedef xmlRelaxNGValidCtxt *xmlRelaxNGValidCtxtPtr;

/*
 * xmlRelaxNGValidErr:
 *
 * List of possible Relax NG validation errors
 */
typedef enum {
    XML_RELAXNG_OK = 0,
    XML_RELAXNG_ERR_MEMORY,
    XML_RELAXNG_ERR_TYPE,
    XML_RELAXNG_ERR_TYPEVAL,
    XML_RELAXNG_ERR_DUPID,
    XML_RELAXNG_ERR_TYPECMP,
    XML_RELAXNG_ERR_NOSTATE,
    XML_RELAXNG_ERR_NODEFINE,
    XML_RELAXNG_ERR_LISTEXTRA,
    XML_RELAXNG_ERR_LISTEMPTY,
    XML_RELAXNG_ERR_INTERNODATA,
    XML_RELAXNG_ERR_INTERSEQ,
    XML_RELAXNG_ERR_INTEREXTRA,
    XML_RELAXNG_ERR_ELEMNAME,
    XML_RELAXNG_ERR_ATTRNAME,
    XML_RELAXNG_ERR_ELEMNONS,
    XML_RELAXNG_ERR_ATTRNONS,
    XML_RELAXNG_ERR_ELEMWRONGNS,
    XML_RELAXNG_ERR_ATTRWRONGNS,
    XML_RELAXNG_ERR_ELEMEXTRANS,
    XML_RELAXNG_ERR_ATTREXTRANS,
    XML_RELAXNG_ERR_ELEMNOTEMPTY,
    XML_RELAXNG_ERR_NOELEM,
    XML_RELAXNG_ERR_NOTELEM,
    XML_RELAXNG_ERR_ATTRVALID,
    XML_RELAXNG_ERR_CONTENTVALID,
    XML_RELAXNG_ERR_EXTRACONTENT,
    XML_RELAXNG_ERR_INVALIDATTR,
    XML_RELAXNG_ERR_DATAELEM,
    XML_RELAXNG_ERR_VALELEM,
    XML_RELAXNG_ERR_LISTELEM,
    XML_RELAXNG_ERR_DATATYPE,
    XML_RELAXNG_ERR_VALUE,
    XML_RELAXNG_ERR_LIST,
    XML_RELAXNG_ERR_NOGRAMMAR,
    XML_RELAXNG_ERR_EXTRADATA,
    XML_RELAXNG_ERR_LACKDATA,
    XML_RELAXNG_ERR_INTERNAL,
    XML_RELAXNG_ERR_ELEMWRONG,
    XML_RELAXNG_ERR_TEXTWRONG
} xmlRelaxNGValidErr;

/*
 * Interfaces for parsing.
 */
xmlRelaxNGParserCtxtPtr xmlRelaxNGNewParserCtxt	(const char *URL);
xmlRelaxNGParserCtxtPtr xmlRelaxNGNewMemParserCtxt(const char *buffer,
						 int size);
xmlRelaxNGParserCtxtPtr xmlRelaxNGNewDocParserCtxt(xmlDocPtr doc);

void		xmlRelaxNGFreeParserCtxt	(xmlRelaxNGParserCtxtPtr ctxt);
void		xmlRelaxNGSetParserErrors(xmlRelaxNGParserCtxtPtr ctxt,
					 xmlRelaxNGValidityErrorFunc err,
					 xmlRelaxNGValidityWarningFunc warn,
					 void *ctx);
int		xmlRelaxNGGetParserErrors(xmlRelaxNGParserCtxtPtr ctxt,
					 xmlRelaxNGValidityErrorFunc *err,
					 xmlRelaxNGValidityWarningFunc *warn,
					 void **ctx);
xmlRelaxNGPtr	xmlRelaxNGParse		(xmlRelaxNGParserCtxtPtr ctxt);
void		xmlRelaxNGFree		(xmlRelaxNGPtr schema);
void		xmlRelaxNGDump		(FILE *output,
					 xmlRelaxNGPtr schema);
void		xmlRelaxNGDumpTree	(FILE * output,
					 xmlRelaxNGPtr schema);
/*
 * Interfaces for validating
 */
void		xmlRelaxNGSetValidErrors(xmlRelaxNGValidCtxtPtr ctxt,
					 xmlRelaxNGValidityErrorFunc err,
					 xmlRelaxNGValidityWarningFunc warn,
					 void *ctx);
int		xmlRelaxNGGetValidErrors(xmlRelaxNGValidCtxtPtr ctxt,
					 xmlRelaxNGValidityErrorFunc *err,
					 xmlRelaxNGValidityWarningFunc *warn,
					 void **ctx);
xmlRelaxNGValidCtxtPtr	xmlRelaxNGNewValidCtxt	(xmlRelaxNGPtr schema);
void			xmlRelaxNGFreeValidCtxt	(xmlRelaxNGValidCtxtPtr ctxt);
int			xmlRelaxNGValidateDoc	(xmlRelaxNGValidCtxtPtr ctxt,
					 	 xmlDocPtr doc);
void			xmlRelaxNGCleanupTypes	(void);
/*
 * Interfaces for progressive validation when possible
 */
int	xmlRelaxNGValidatePushElement	(xmlRelaxNGValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 xmlNodePtr elem);
int	xmlRelaxNGValidatePushCData	(xmlRelaxNGValidCtxtPtr ctxt,
					 const xmlChar *data,
					 int len);
int	xmlRelaxNGValidatePopElement	(xmlRelaxNGValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 xmlNodePtr elem);
int	xmlRelaxNGValidateFullElement	(xmlRelaxNGValidCtxtPtr ctxt,
					 xmlDocPtr doc,
					 xmlNodePtr elem);
#endif /* __XML_RELAX_NG__ */
