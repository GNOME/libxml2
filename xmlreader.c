/*
 * xmlreader.c: implements the xmlTextReader streaming node API
 *
 * NOTE: 
 *   XmlTextReader.Normalization Property won't be supported, since
 *     it makes the parser non compliant to the XML recommendation
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#define IN_LIBXML
#include "libxml.h"

#include <string.h> /* for memset() only ! */

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <libxml/xmlmemory.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlreader.h>

/* #define DEBUG_CALLBACKS */
/* #define DEBUG_READER */

/**
 * TODO:
 *
 * macro to flag unimplemented blocks
 */
#define TODO 								\
    xmlGenericError(xmlGenericErrorContext,				\
	    "Unimplemented block at %s:%d\n",				\
            __FILE__, __LINE__);

#ifdef DEBUG_READER
#define DUMP_READER xmlTextReaderDebug(reader);
#else
#define DUMP_READER
#endif

/************************************************************************
 *									*
 *	The parser: maps the Text Reader API on top of the existing	*
 *		parsing routines building a tree			*
 *									*
 ************************************************************************/

#define XML_TEXTREADER_INPUT	1
#define XML_TEXTREADER_CTXT	2

typedef enum {
    XML_TEXTREADER_MODE_INITIAL = 0,
    XML_TEXTREADER_MODE_INTERACTIVE = 1,
    XML_TEXTREADER_MODE_ERROR = 2,
    XML_TEXTREADER_MODE_EOF =3,
    XML_TEXTREADER_MODE_CLOSED = 4,
    XML_TEXTREADER_MODE_READING = 5
} xmlTextReaderMode;

typedef enum {
    XML_TEXTREADER_NONE = -1,
    XML_TEXTREADER_START= 0,
    XML_TEXTREADER_ELEMENT= 1,
    XML_TEXTREADER_END= 2,
    XML_TEXTREADER_EMPTY= 3,
    XML_TEXTREADER_BACKTRACK= 4,
    XML_TEXTREADER_DONE= 5
} xmlTextReaderState;

struct _xmlTextReader {
    int				mode;	/* the parsing mode */
    int				allocs;	/* what structure were deallocated */
    xmlTextReaderState		state;
    xmlParserCtxtPtr		ctxt;	/* the parser context */
    xmlSAXHandlerPtr		sax;	/* the parser SAX callbacks */
    xmlParserInputBufferPtr	input;	/* the input */
    startElementSAXFunc		startElement;/* initial SAX callbacks */
    endElementSAXFunc		endElement;  /* idem */
    charactersSAXFunc		characters;
    cdataBlockSAXFunc		cdataBlock;
    unsigned int 		base;	/* base of the segment in the input */
    unsigned int 		cur;	/* current position in the input */
    xmlNodePtr			node;	/* current node */
    xmlNodePtr			curnode;/* current attribute node */
    int				depth;  /* depth of the current node */
    xmlNodePtr			faketext;/* fake xmlNs chld */
    int				wasempty;/* was the last node empty */
};

#ifdef DEBUG_READER
static void
xmlTextReaderDebug(xmlTextReaderPtr reader) {
    if ((reader == NULL) || (reader->ctxt == NULL)) {
	fprintf(stderr, "xmlTextReader NULL\n");
	return;
    }
    fprintf(stderr, "xmlTextReader: state %d depth %d ",
	    reader->state, reader->depth);
    if (reader->node == NULL) {
	fprintf(stderr, "node = NULL\n");
    } else {
	fprintf(stderr, "node %s\n", reader->node->name);
    }
    fprintf(stderr, "  input: base %d, cur %d, depth %d: ",
	    reader->base, reader->cur, reader->ctxt->nodeNr);
    if (reader->input->buffer == NULL) {
	fprintf(stderr, "buffer is NULL\n");
    } else {
#ifdef LIBXML_DEBUG_ENABLED
	xmlDebugDumpString(stderr,
		&reader->input->buffer->content[reader->cur]);
#endif
	fprintf(stderr, "\n");
    }
}
#endif

/**
 * xmlTextReaderStartElement:
 * @ctx: the user data (XML parser context)
 * @fullname:  The element name, including namespace prefix
 * @atts:  An array of name/value attributes pairs, NULL terminated
 *
 * called when an opening tag has been processed.
 */
static void
xmlTextReaderStartElement(void *ctx, const xmlChar *fullname,
	                  const xmlChar **atts) {
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserCtxtPtr origctxt;
    xmlTextReaderPtr reader = ctxt->_private;

#ifdef DEBUG_CALLBACKS
    printf("xmlTextReaderStartElement(%s)\n", fullname);
#endif
    if ((reader != NULL) && (reader->startElement != NULL)) {
	/*
	 * when processing an entity, the context may have been changed
	 */
	origctxt = reader->ctxt;
	reader->startElement(ctx, fullname, atts);
	if (origctxt->validate) {
	    ctxt->valid &= xmlValidatePushElement(&origctxt->vctxt,
				 ctxt->myDoc, ctxt->node, fullname);
	}
    }
    reader->state = XML_TEXTREADER_ELEMENT;
}

/**
 * xmlTextReaderEndElement:
 * @ctx: the user data (XML parser context)
 * @fullname:  The element name, including namespace prefix
 *
 * called when an ending tag has been processed.
 */
static void
xmlTextReaderEndElement(void *ctx, const xmlChar *fullname) {
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserCtxtPtr origctxt;
    xmlTextReaderPtr reader = ctxt->_private;

#ifdef DEBUG_CALLBACKS
    printf("xmlTextReaderEndElement(%s)\n", fullname);
#endif
    if ((reader != NULL) && (reader->endElement != NULL)) {
	xmlNodePtr node = ctxt->node;
	/*
	 * when processing an entity, the context may have been changed
	 */
	origctxt = reader->ctxt;

	reader->endElement(ctx, fullname);

	if (origctxt->validate) {
	    ctxt->valid &= xmlValidatePopElement(&origctxt->vctxt,
		                ctxt->myDoc, node, fullname);
	}
    }
    if (reader->state == XML_TEXTREADER_ELEMENT)
	reader->wasempty = 1;
    else
	reader->wasempty = 0;
}

/**
 * xmlTextReaderCharacters:
 * @ctx: the user data (XML parser context)
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some chars from the parser.
 */
static void
xmlTextReaderCharacters(void *ctx, const xmlChar *ch, int len)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlParserCtxtPtr origctxt;
    xmlTextReaderPtr reader = ctxt->_private;

#ifdef DEBUG_CALLBACKS
    printf("xmlTextReaderCharacters()\n");
#endif
    if ((reader != NULL) && (reader->characters != NULL)) {
	reader->characters(ctx, ch, len);
	/*
	 * when processing an entity, the context may have been changed
	 */
	origctxt = reader->ctxt;

	if (origctxt->validate) {
	    ctxt->valid &= xmlValidatePushCData(&origctxt->vctxt, ch, len);
	}
    }
}

/**
 * xmlTextReaderCDataBlock:
 * @ctx: the user data (XML parser context)
 * @value:  The pcdata content
 * @len:  the block length
 *
 * called when a pcdata block has been parsed
 */
static void
xmlTextReaderCDataBlock(void *ctx, const xmlChar *ch, int len)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
    xmlTextReaderPtr reader = ctxt->_private;

#ifdef DEBUG_CALLBACKS
    printf("xmlTextReaderCDataBlock()\n");
#endif
    if ((reader != NULL) && (reader->cdataBlock != NULL)) {
	reader->cdataBlock(ctx, ch, len);

	if (ctxt->validate) {
	    ctxt->valid &= xmlValidatePushCData(&ctxt->vctxt, ch, len);
	}
    }
}

/**
 * xmlTextReaderPushData:
 * @reader:  the xmlTextReaderPtr used
 *
 * Push data down the progressive parser until a significant callback
 * got raised.
 *
 * Returns -1 in case of failure, 0 otherwise
 */
static int
xmlTextReaderPushData(xmlTextReaderPtr reader) {
    unsigned int cur = reader->cur;
    xmlBufferPtr inbuf;
    int val;
    int oldstate;

    if ((reader->input == NULL) || (reader->input->buffer == NULL))
	return(-1);

    oldstate = reader->state;
    reader->state = XML_TEXTREADER_NONE;
    inbuf = reader->input->buffer;
    while (reader->state == XML_TEXTREADER_NONE) {
	if (cur >= inbuf->use) {
	    /*
	     * Refill the buffer unless we are at the end of the stream
	     */
	    if (reader->mode != XML_TEXTREADER_MODE_EOF) {
		val = xmlParserInputBufferRead(reader->input, 4096);
		if (val <= 0) {
		    reader->mode = XML_TEXTREADER_MODE_EOF;
		    reader->state = oldstate;
		    if ((oldstate != XML_TEXTREADER_START) ||
			(reader->ctxt->myDoc != NULL))
			return(val);
		}
	    } else 
		break;
	}
	if ((inbuf->content[cur] == '>') || (inbuf->content[cur] == '&')) {
	    cur = cur + 1;
	    val = xmlParseChunk(reader->ctxt,
		          (const char *) &inbuf->content[reader->cur],
			  cur - reader->cur, 0);
	    if (val != 0)
		return(-1);
	    reader->cur = cur;
	    break;
	} else {
	    cur = cur + 1;

	    /*
	     * One may have to force a flush at some point when parsing really
	     * large CDATA sections
	     */
	    if ((cur - reader->cur > 4096) && (reader->base == 0) &&
		(reader->mode == XML_TEXTREADER_MODE_INTERACTIVE)) {
		cur = cur + 1;
		val = xmlParseChunk(reader->ctxt,
			      (const char *) &inbuf->content[reader->cur],
			      cur - reader->cur, 0);
		if (val != 0)
		    return(-1);
		reader->cur = cur;
	    }
	}
    }
    /*
     * Discard the consumed input when needed and possible
     */
    if (reader->mode == XML_TEXTREADER_MODE_INTERACTIVE) {
	if ((reader->cur >= 4096) && (reader->base == 0)) {
	    val = xmlBufferShrink(inbuf, cur);
	    if (val >= 0) {
		reader->cur -= val;
	    }
	}
    }

    /*
     * At the end of the stream signal that the work is done to the Push
     * parser.
     */
    if (reader->mode == XML_TEXTREADER_MODE_EOF) {
	if (reader->mode != XML_TEXTREADER_DONE) {
	    val = xmlParseChunk(reader->ctxt,
		    (const char *) &inbuf->content[reader->cur], 0, 1);
	    reader->mode = XML_TEXTREADER_DONE;
	}
    }
    reader->state = oldstate;
    return(0);
}

/**
 * xmlTextReaderRead:
 * @reader:  the xmlTextReaderPtr used
 *
 *  Moves the position of the current instance to the next node in
 *  the stream, exposing its properties.
 *
 *  Returns 1 if the node was read successfully, 0 if there is no more
 *          nodes to read, or -1 in case of error
 */
int
xmlTextReaderRead(xmlTextReaderPtr reader) {
    int val, olddepth, wasempty;
    xmlTextReaderState oldstate;
    xmlNodePtr oldnode;

    if ((reader == NULL) || (reader->ctxt == NULL))
	return(-1);
    if (reader->ctxt->wellFormed != 1)
	return(-1);

#ifdef DEBUG_READER
    fprintf(stderr, "\nREAD ");
    DUMP_READER
#endif
    reader->curnode = NULL;
    if (reader->mode == XML_TEXTREADER_MODE_INITIAL) {
	reader->mode = XML_TEXTREADER_MODE_INTERACTIVE;
	/*
	 * Initial state
	 */
	do {
	    val = xmlTextReaderPushData(reader);
	    if (val < 0)
		return(-1);
	} while ((reader->ctxt->node == NULL) &&
		 (reader->mode != XML_TEXTREADER_MODE_EOF));
	if (reader->ctxt->node == NULL) {
	    if (reader->ctxt->myDoc != NULL)
		reader->node = reader->ctxt->myDoc->children;
	    if (reader->node == NULL)
		return(-1);
	} else {
	    reader->node = reader->ctxt->nodeTab[0];
	}
	reader->depth = 0;
	return(1);
    }
    oldstate = reader->state;
    olddepth = reader->ctxt->nodeNr;
    oldnode = reader->node;
    wasempty = ((reader->wasempty == 1) && (reader->ctxt->node != NULL) &&
	        (reader->ctxt->node->last == reader->node));

    /*
     * If we are not backtracking on ancestors or examined nodes,
     * that the parser didn't finished or that we arent at the end
     * of stream, continue processing.
     */
    while (((oldstate == XML_TEXTREADER_BACKTRACK) ||
            (reader->node->children == NULL) ||
	    (reader->node->type == XML_ENTITY_REF_NODE) ||
	    (reader->node->type == XML_DTD_NODE)) &&
	   (reader->node->next == NULL) &&
	   (reader->ctxt->nodeNr == olddepth) &&
	   (reader->ctxt->instate != XML_PARSER_EOF)) {
	val = xmlTextReaderPushData(reader);
	if (val < 0)
	    return(-1);
	if (reader->node == NULL)
	    return(0);
    }
    if (oldstate != XML_TEXTREADER_BACKTRACK) {
	if ((reader->node->children != NULL) &&
	    (reader->node->type != XML_ENTITY_REF_NODE) &&
	    (reader->node->type != XML_DTD_NODE)) {
	    reader->node = reader->node->children;
	    reader->depth++;
	    reader->state = XML_TEXTREADER_ELEMENT;
	    DUMP_READER
	    return(1);
	}
    }
    if (reader->node->next != NULL) {
	if ((oldstate == XML_TEXTREADER_ELEMENT) &&
            (reader->node->type == XML_ELEMENT_NODE) &&
	    (wasempty == 0)) {
	    reader->state = XML_TEXTREADER_END;
	    DUMP_READER
	    return(1);
	}
	reader->node = reader->node->next;
	reader->state = XML_TEXTREADER_ELEMENT;
	DUMP_READER
	/*
	 * Cleanup of the old node
	 */
	if (oldnode->type != XML_DTD_NODE) {
	    xmlUnlinkNode(oldnode);
	    xmlFreeNode(oldnode);
	}

	return(1);
    }
    if ((oldstate == XML_TEXTREADER_ELEMENT) &&
	(reader->node->type == XML_ELEMENT_NODE) &&
	(wasempty == 0)) {
	reader->state = XML_TEXTREADER_END;
	DUMP_READER
	return(1);
    }
    reader->node = reader->node->parent;
    if ((reader->node == NULL) ||
	(reader->node->type == XML_DOCUMENT_NODE) ||
#ifdef LIBXML_DOCB_ENABLED
	(reader->node->type == XML_DOCB_DOCUMENT_NODE) ||
#endif
	(reader->node->type == XML_HTML_DOCUMENT_NODE)) {
	if (reader->mode != XML_TEXTREADER_DONE) {
	    val = xmlParseChunk(reader->ctxt, "", 0, 1);
	    reader->mode = XML_TEXTREADER_DONE;
	}
	reader->node = NULL;
	reader->depth = -1;

	/*
	 * Cleanup of the old node
	 */
	if (oldnode->type != XML_DTD_NODE) {
	    xmlUnlinkNode(oldnode);
	    xmlFreeNode(oldnode);
	}

	return(0);
    }
    reader->depth--;
    reader->state = XML_TEXTREADER_BACKTRACK;
    DUMP_READER
    return(1);
}

/**
 * xmlTextReaderReadState:
 * @reader:  the xmlTextReaderPtr used
 *
 * Gets the read state of the reader.
 *
 * Returns the state value, or -1 in case of error
 */
int
xmlTextReaderReadState(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    return(reader->mode);
}

/**
 * xmlTextReaderReadInnerXml:
 * @reader:  the xmlTextReaderPtr used
 *
 * Reads the contents of the current node, including child nodes and markup.
 *
 * Returns a string containing the XML content, or NULL if the current node
 *         is neither an element nor attribute, or has no child nodes. The 
 *         string must be deallocated by the caller.
 */
xmlChar *
xmlTextReaderReadInnerXml(xmlTextReaderPtr reader) {
    TODO
    return(NULL);
}

/**
 * xmlTextReaderReadOuterXml:
 * @reader:  the xmlTextReaderPtr used
 *
 * Reads the contents of the current node, including child nodes and markup.
 *
 * Returns a string containing the XML content, or NULL if the current node
 *         is neither an element nor attribute, or has no child nodes. The 
 *         string must be deallocated by the caller.
 */
xmlChar *
xmlTextReaderReadOuterXml(xmlTextReaderPtr reader) {
    TODO
    return(NULL);
}

/**
 * xmlTextReaderReadString:
 * @reader:  the xmlTextReaderPtr used
 *
 * Reads the contents of an element or a text node as a string.
 *
 * Returns a string containing the contents of the Element or Text node,
 *         or NULL if the reader is positioned on any other type of node.
 *         The string must be deallocated by the caller.
 */
xmlChar *
xmlTextReaderReadString(xmlTextReaderPtr reader) {
    TODO
    return(NULL);
}

/**
 * xmlTextReaderReadBase64:
 * @reader:  the xmlTextReaderPtr used
 * @array:  a byte array to store the content.
 * @offset:  the zero-based index into array where the method should
 *           begin to write.
 * @len:  the number of bytes to write.
 *
 * Reads and decodes the Base64 encoded contents of an element and
 * stores the result in a byte buffer.
 *
 * Returns the number of bytes written to array, or zero if the current
 *         instance is not positioned on an element or -1 in case of error.
 */
int
xmlTextReaderReadBase64(xmlTextReaderPtr reader, unsigned char *array,
	                int offset, int len) {
    if ((reader == NULL) || (reader->ctxt == NULL))
	return(-1);
    if (reader->ctxt->wellFormed != 1)
	return(-1);

    if ((reader->node == NULL) || (reader->node->type == XML_ELEMENT_NODE))
	return(0);
    TODO
    return(0);
}

/**
 * xmlTextReaderReadBinHex:
 * @reader:  the xmlTextReaderPtr used
 * @array:  a byte array to store the content.
 * @offset:  the zero-based index into array where the method should
 *           begin to write.
 * @len:  the number of bytes to write.
 *
 * Reads and decodes the BinHex encoded contents of an element and
 * stores the result in a byte buffer.
 *
 * Returns the number of bytes written to array, or zero if the current
 *         instance is not positioned on an element or -1 in case of error.
 */
int
xmlTextReaderReadBinHex(xmlTextReaderPtr reader, unsigned char *array,
	                int offset, int len) {
    if ((reader == NULL) || (reader->ctxt == NULL))
	return(-1);
    if (reader->ctxt->wellFormed != 1)
	return(-1);

    if ((reader->node == NULL) || (reader->node->type == XML_ELEMENT_NODE))
	return(0);
    TODO
    return(0);
}

/************************************************************************
 *									*
 *			Constructor and destructors			*
 *									*
 ************************************************************************/
/**
 * xmlNewTextReader:
 * @input: the xmlParserInputBufferPtr used to read data
 * @URI: the URI information for the source if available
 *
 * Create an xmlTextReader structure fed with @input
 *
 * Returns the new xmlTextReaderPtr or NULL in case of error
 */
xmlTextReaderPtr
xmlNewTextReader(xmlParserInputBufferPtr input, const char *URI) {
    xmlTextReaderPtr ret;
    int val;

    if (input == NULL)
	return(NULL);
    ret = xmlMalloc(sizeof(xmlTextReader));
    if (ret == NULL) {
        xmlGenericError(xmlGenericErrorContext,
		"xmlNewTextReader : malloc failed\n");
	return(NULL);
    }
    memset(ret, 0, sizeof(xmlTextReader));
    ret->input = input;
    ret->sax = (xmlSAXHandler *) xmlMalloc(sizeof(xmlSAXHandler));
    if (ret->sax == NULL) {
	xmlFree(ret);
        xmlGenericError(xmlGenericErrorContext,
		"xmlNewTextReader : malloc failed\n");
	return(NULL);
    }
    memcpy(ret->sax, &xmlDefaultSAXHandler, sizeof(xmlSAXHandler));
    ret->startElement = ret->sax->startElement;
    ret->sax->startElement = xmlTextReaderStartElement;
    ret->endElement = ret->sax->endElement;
    ret->sax->endElement = xmlTextReaderEndElement;
    ret->characters = ret->sax->characters;
    ret->sax->characters = xmlTextReaderCharacters;
    ret->cdataBlock = ret->sax->cdataBlock;
    ret->sax->cdataBlock = xmlTextReaderCDataBlock;

    ret->mode = XML_TEXTREADER_MODE_INITIAL;
    ret->node = NULL;
    ret->curnode = NULL;
    val = xmlParserInputBufferRead(input, 4);
    if (val >= 4) {
	ret->ctxt = xmlCreatePushParserCtxt(ret->sax, NULL,
			(const char *) ret->input->buffer->content, 4, URI);
	ret->base = 0;
	ret->cur = 4;
    } else {
	ret->ctxt = xmlCreatePushParserCtxt(ret->sax, NULL, NULL, 0, URI);
	ret->base = 0;
	ret->cur = 0;
    }
    ret->ctxt->_private = ret;
    ret->ctxt->linenumbers = 1;
    ret->allocs = XML_TEXTREADER_CTXT;
    return(ret);

}

/**
 * xmlNewTextReaderFilename:
 * @URI: the URI of the resource to process
 *
 * Create an xmlTextReader structure fed with the resource at @URI
 *
 * Returns the new xmlTextReaderPtr or NULL in case of error
 */
xmlTextReaderPtr
xmlNewTextReaderFilename(const char *URI) {
    xmlParserInputBufferPtr input;
    xmlTextReaderPtr ret;
    char *directory = NULL;

    input = xmlParserInputBufferCreateFilename(URI, XML_CHAR_ENCODING_NONE);
    if (input == NULL)
	return(NULL);
    ret = xmlNewTextReader(input, URI);
    if (ret == NULL) {
	xmlFreeParserInputBuffer(input);
	return(NULL);
    }
    ret->allocs |= XML_TEXTREADER_INPUT;
    if (ret->ctxt->directory == NULL)
        directory = xmlParserGetDirectory(URI);
    if ((ret->ctxt->directory == NULL) && (directory != NULL))
        ret->ctxt->directory = (char *) xmlStrdup((xmlChar *) directory);
    if (directory != NULL)
	xmlFree(directory);
    return(ret);
}

/**
 * xmlFreeTextReader:
 * @reader:  the xmlTextReaderPtr
 *
 * Deallocate all the resources associated to the reader
 */
void
xmlFreeTextReader(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return;
    if (reader->ctxt != NULL) {
	if (reader->ctxt->myDoc != NULL) {
	    xmlFreeDoc(reader->ctxt->myDoc);
	    reader->ctxt->myDoc = NULL;
	}
	if ((reader->ctxt->vctxt.vstateTab != NULL) &&
	    (reader->ctxt->vctxt.vstateMax > 0)){
	    xmlFree(reader->ctxt->vctxt.vstateTab);
	    reader->ctxt->vctxt.vstateTab = 0;
	    reader->ctxt->vctxt.vstateMax = 0;
	}
	if (reader->allocs & XML_TEXTREADER_CTXT)
	    xmlFreeParserCtxt(reader->ctxt);
    }
    if (reader->sax != NULL)
	xmlFree(reader->sax);
    if ((reader->input != NULL)  && (reader->allocs & XML_TEXTREADER_INPUT))
	xmlFreeParserInputBuffer(reader->input);
    if (reader->faketext != NULL) {
	xmlFreeNode(reader->faketext);
    }
    xmlFree(reader);
}

/************************************************************************
 *									*
 *			Methods for XmlTextReader			*
 *									*
 ************************************************************************/
/**
 * xmlTextReaderClose:
 * @reader:  the xmlTextReaderPtr used
 *
 * This method releases any resources allocated by the current instance
 * changes the state to Closed and close any underlying input.
 *
 * Returns 0 or -1 in case of error
 */
int
xmlTextReaderClose(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    reader->node = NULL;
    reader->curnode = NULL;
    reader->mode = XML_TEXTREADER_MODE_CLOSED;
    if (reader->ctxt != NULL) {
	if (reader->ctxt->myDoc != NULL) {
	    xmlFreeDoc(reader->ctxt->myDoc);
	    reader->ctxt->myDoc = NULL;
	}
	if (reader->allocs & XML_TEXTREADER_CTXT) {
	    xmlFreeParserCtxt(reader->ctxt);
	    reader->allocs -= XML_TEXTREADER_CTXT;
	}
    }
    if (reader->sax != NULL) {
        xmlFree(reader->sax);
	reader->sax = NULL;
    }
    if ((reader->input != NULL)  && (reader->allocs & XML_TEXTREADER_INPUT)) {
	xmlFreeParserInputBuffer(reader->input);
	reader->allocs -= XML_TEXTREADER_INPUT;
    }
    return(0);
}

/**
 * xmlTextReaderGetAttributeNo:
 * @reader:  the xmlTextReaderPtr used
 * @no: the zero-based index of the attribute relative to the containing element
 *
 * Provides the value of the attribute with the specified index relative
 * to the containing element.
 *
 * Returns a string containing the value of the specified attribute, or NULL
 *    in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlTextReaderGetAttributeNo(xmlTextReaderPtr reader, int no) {
    xmlChar *ret;
    int i;
    xmlAttrPtr cur;
    xmlNsPtr ns;

    if (reader == NULL)
	return(NULL);
    if (reader->node == NULL)
	return(NULL);
    if (reader->curnode != NULL)
	return(NULL);
    /* TODO: handle the xmlDecl */
    if (reader->node->type != XML_ELEMENT_NODE) 
	return(NULL);

    ns = reader->node->nsDef;
    for (i = 0;(i < no) && (ns != NULL);i++) {
	ns = ns->next;
    }
    if (ns != NULL)
	return(xmlStrdup(ns->href));

    cur = reader->node->properties;
    if (cur == NULL)
	return(NULL);
    for (;i < no;i++) {
	cur = cur->next;
	if (cur == NULL)
	    return(NULL);
    }
    /* TODO walk the DTD if present */

    ret = xmlNodeListGetString(reader->node->doc, cur->children, 1);
    if (ret == NULL) return(xmlStrdup((xmlChar *)""));
    return(ret);
}

/**
 * xmlTextReaderGetAttribute:
 * @reader:  the xmlTextReaderPtr used
 * @name: the qualified name of the attribute.
 *
 * Provides the value of the attribute with the specified qualified name.
 *
 * Returns a string containing the value of the specified attribute, or NULL
 *    in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlTextReaderGetAttribute(xmlTextReaderPtr reader, const xmlChar *name) {
    xmlChar *prefix = NULL;
    xmlChar *localname;
    xmlNsPtr ns;
    xmlChar *ret = NULL;

    if ((reader == NULL) || (name == NULL))
	return(NULL);
    if (reader->node == NULL)
	return(NULL);
    if (reader->curnode != NULL)
	return(NULL);

    /* TODO: handle the xmlDecl */
    if (reader->node->type != XML_ELEMENT_NODE)
	return(NULL);

    localname = xmlSplitQName2(name, &prefix);
    if (localname == NULL)
	return(xmlGetProp(reader->node, name));
    
    ns = xmlSearchNs(reader->node->doc, reader->node, prefix);
    if (ns != NULL)
        ret = xmlGetNsProp(reader->node, localname, ns->href);

    if (localname != NULL)
        xmlFree(localname);
    if (prefix != NULL)
        xmlFree(prefix);
    return(ret);
}


/**
 * xmlTextReaderGetAttributeNs:
 * @reader:  the xmlTextReaderPtr used
 * @localName: the local name of the attribute.
 * @namespaceURI: the namespace URI of the attribute.
 *
 * Provides the value of the specified attribute
 *
 * Returns a string containing the value of the specified attribute, or NULL
 *    in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlTextReaderGetAttributeNs(xmlTextReaderPtr reader, const xmlChar *localName,
			    const xmlChar *namespaceURI) {
    if ((reader == NULL) || (localName == NULL))
	return(NULL);
    if (reader->node == NULL)
	return(NULL);
    if (reader->curnode != NULL)
	return(NULL);

    /* TODO: handle the xmlDecl */
    if (reader->node->type != XML_ELEMENT_NODE)
	return(NULL);

    return(xmlGetNsProp(reader->node, localName, namespaceURI));
}

/**
 * xmlTextReaderGetRemainder:
 * @reader:  the xmlTextReaderPtr used
 *
 * Method to get the remainder of the buffered XML. this method stops the
 * parser, set its state to End Of File and return the input stream with
 * what is left that the parser did not use.
 *
 * Returns the xmlParserInputBufferPtr attached to the XML or NULL
 *    in case of error.
 */
xmlParserInputBufferPtr
xmlTextReaderGetRemainder(xmlTextReaderPtr reader) {
    xmlParserInputBufferPtr ret = NULL;

    if (reader == NULL)
	return(NULL);
    if (reader->node == NULL)
	return(NULL);

    reader->node = NULL;
    reader->curnode = NULL;
    reader->mode = XML_TEXTREADER_MODE_EOF;
    if (reader->ctxt != NULL) {
	if (reader->ctxt->myDoc != NULL) {
	    xmlFreeDoc(reader->ctxt->myDoc);
	    reader->ctxt->myDoc = NULL;
	}
	if (reader->allocs & XML_TEXTREADER_CTXT) {
	    xmlFreeParserCtxt(reader->ctxt);
	    reader->allocs -= XML_TEXTREADER_CTXT;
	}
    }
    if (reader->sax != NULL) {
        xmlFree(reader->sax);
	reader->sax = NULL;
    }
    if (reader->allocs & XML_TEXTREADER_INPUT) {
	ret = reader->input;
	reader->allocs -= XML_TEXTREADER_INPUT;
    } else {
	/*
	 * Hum, one may need to duplicate the data structure because
	 * without reference counting the input may be freed twice:
	 *   - by the layer which allocated it.
	 *   - by the layer to which would have been returned to.
	 */
	TODO
	return(NULL);
    }
    return(ret);
}

/**
 * xmlTextReaderLookupNamespace:
 * @reader:  the xmlTextReaderPtr used
 * @prefix: the prefix whose namespace URI is to be resolved. To return
 *          the default namespace, specify NULL
 *
 * Resolves a namespace prefix in the scope of the current element.
 *
 * Returns a string containing the namespace URI to which the prefix maps
 *    or NULL in case of error. The string must be deallocated by the caller.
 */
xmlChar *
xmlTextReaderLookupNamespace(xmlTextReaderPtr reader, const xmlChar *prefix) {
    xmlNsPtr ns;

    if (reader == NULL)
	return(NULL);
    if (reader->node == NULL)
	return(NULL);

    ns = xmlSearchNs(reader->node->doc, reader->node, prefix);
    if (ns == NULL)
	return(NULL);
    return(xmlStrdup(ns->href));
}

/**
 * xmlTextReaderMoveToAttributeNo:
 * @reader:  the xmlTextReaderPtr used
 * @no: the zero-based index of the attribute relative to the containing
 *      element.
 *
 * Moves the position of the current instance to the attribute with
 * the specified index relative to the containing element.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlTextReaderMoveToAttributeNo(xmlTextReaderPtr reader, int no) {
    int i;
    xmlAttrPtr cur;
    xmlNsPtr ns;

    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(-1);
    /* TODO: handle the xmlDecl */
    if (reader->node->type != XML_ELEMENT_NODE) 
	return(-1);

    reader->curnode = NULL;

    ns = reader->node->nsDef;
    for (i = 0;(i < no) && (ns != NULL);i++) {
	ns = ns->next;
    }
    if (ns != NULL) {
	reader->curnode = (xmlNodePtr) ns;
	return(1);
    }

    cur = reader->node->properties;
    if (cur == NULL)
	return(0);
    for (;i < no;i++) {
	cur = cur->next;
	if (cur == NULL)
	    return(0);
    }
    /* TODO walk the DTD if present */

    reader->curnode = (xmlNodePtr) cur;
    return(1);
}

/**
 * xmlTextReaderMoveToAttribute:
 * @reader:  the xmlTextReaderPtr used
 * @name: the qualified name of the attribute.
 *
 * Moves the position of the current instance to the attribute with
 * the specified qualified name.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlTextReaderMoveToAttribute(xmlTextReaderPtr reader, const xmlChar *name) {
    xmlChar *prefix = NULL;
    xmlChar *localname;
    xmlNsPtr ns;
    xmlAttrPtr prop;

    if ((reader == NULL) || (name == NULL))
	return(-1);
    if (reader->node == NULL)
	return(-1);

    /* TODO: handle the xmlDecl */
    if (reader->node->type != XML_ELEMENT_NODE)
	return(0);

    localname = xmlSplitQName2(name, &prefix);
    if (localname == NULL) {
	/*
	 * Namespace default decl
	 */
	if (xmlStrEqual(name, BAD_CAST "xmlns")) {
	    ns = reader->node->nsDef;
	    while (ns != NULL) {
		if (ns->prefix == NULL) {
		    reader->curnode = (xmlNodePtr) ns;
		    return(1);
		}
		ns = ns->next;
	    }
	    return(0);
	}

	prop = reader->node->properties;
	while (prop != NULL) {
	    /*
	     * One need to have
	     *   - same attribute names
	     *   - and the attribute carrying that namespace
	     */
	    if ((xmlStrEqual(prop->name, name)) &&
		((prop->ns == NULL) || (prop->ns->prefix == NULL))) {
		reader->curnode = (xmlNodePtr) prop;
		return(1);
	    }
	    prop = prop->next;
	}
	return(0);
    }
    
    /*
     * Namespace default decl
     */
    if (xmlStrEqual(prefix, BAD_CAST "xmlns")) {
	ns = reader->node->nsDef;
	while (ns != NULL) {
	    if ((ns->prefix != NULL) && (xmlStrEqual(ns->prefix, localname))) {
		reader->curnode = (xmlNodePtr) ns;
		goto found;
	    }
	    ns = ns->next;
	}
	goto not_found;
    }
    prop = reader->node->properties;
    while (prop != NULL) {
	/*
	 * One need to have
	 *   - same attribute names
	 *   - and the attribute carrying that namespace
	 */
	if ((xmlStrEqual(prop->name, localname)) &&
	    (prop->ns != NULL) && (xmlStrEqual(prop->ns->prefix, prefix))) {
	    reader->curnode = (xmlNodePtr) prop;
	    goto found;
	}
	prop = prop->next;
    }
not_found:
    if (localname != NULL)
        xmlFree(localname);
    if (prefix != NULL)
        xmlFree(prefix);
    return(0);

found:
    if (localname != NULL)
        xmlFree(localname);
    if (prefix != NULL)
        xmlFree(prefix);
    return(1);
}

/**
 * xmlTextReaderMoveToAttributeNs:
 * @reader:  the xmlTextReaderPtr used
 * @localName:  the local name of the attribute.
 * @namespaceURI:  the namespace URI of the attribute.
 *
 * Moves the position of the current instance to the attribute with the
 * specified local name and namespace URI.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlTextReaderMoveToAttributeNs(xmlTextReaderPtr reader,
	const xmlChar *localName, const xmlChar *namespaceURI) {
    xmlAttrPtr prop;
    xmlNodePtr node;

    if ((reader == NULL) || (localName == NULL) || (namespaceURI == NULL))
	return(-1);
    if (reader->node == NULL)
	return(-1);
    if (reader->node->type != XML_ELEMENT_NODE)
	return(0);
    node = reader->node;

    /*
     * A priori reading http://www.w3.org/TR/REC-xml-names/ there is no
     * namespace name associated to "xmlns"
     */
    prop = node->properties;
    while (prop != NULL) {
	/*
	 * One need to have
	 *   - same attribute names
	 *   - and the attribute carrying that namespace
	 */
        if (xmlStrEqual(prop->name, localName) &&
	    ((prop->ns != NULL) &&
	     (xmlStrEqual(prop->ns->href, namespaceURI)))) {
	    reader->curnode = (xmlNodePtr) prop;
	    return(1);
        }
	prop = prop->next;
    }
    return(0);
}

/**
 * xmlTextReaderMoveToFirstAttribute:
 * @reader:  the xmlTextReaderPtr used
 *
 * Moves the position of the current instance to the first attribute
 * associated with the current node.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlTextReaderMoveToFirstAttribute(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(-1);
    if (reader->node->type != XML_ELEMENT_NODE)
	return(0);

    if (reader->node->nsDef != NULL) {
	reader->curnode = (xmlNodePtr) reader->node->nsDef;
	return(1);
    }
    if (reader->node->properties != NULL) {
	reader->curnode = (xmlNodePtr) reader->node->properties;
	return(1);
    }
    return(0);
}

/**
 * xmlTextReaderMoveToNextAttribute:
 * @reader:  the xmlTextReaderPtr used
 *
 * Moves the position of the current instance to the next attribute
 * associated with the current node.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not found
 */
int
xmlTextReaderMoveToNextAttribute(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(-1);
    if (reader->node->type != XML_ELEMENT_NODE)
	return(0);
    if (reader->curnode == NULL)
	return(xmlTextReaderMoveToFirstAttribute(reader));

    if (reader->curnode->type == XML_NAMESPACE_DECL) {
	xmlNsPtr ns = (xmlNsPtr) reader->curnode;
	if (ns->next != NULL) {
	    reader->curnode = (xmlNodePtr) ns->next;
	    return(1);
	}
	if (reader->node->properties != NULL) {
	    reader->curnode = (xmlNodePtr) reader->node->properties;
	    return(1);
	}
	return(0);
    } else if ((reader->curnode->type == XML_ATTRIBUTE_NODE) &&
	       (reader->curnode->next != NULL)) {
	reader->curnode = reader->curnode->next;
	return(1);
    }
    return(0);
}

/**
 * xmlTextReaderMoveToElement:
 * @reader:  the xmlTextReaderPtr used
 *
 * Moves the position of the current instance to the node that
 * contains the current Attribute  node.
 *
 * Returns 1 in case of success, -1 in case of error, 0 if not moved
 */
int
xmlTextReaderMoveToElement(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(-1);
    if (reader->node->type != XML_ELEMENT_NODE)
	return(0);
    if (reader->curnode != NULL) {
	reader->curnode = NULL;
	return(1);
    }
    return(0);
}

/**
 * xmlTextReaderReadAttributeValue:
 * @reader:  the xmlTextReaderPtr used
 *
 * Parses an attribute value into one or more Text and EntityReference nodes.
 *
 * Returns 1 in case of success, 0 if the reader was not positionned on an
 *         ttribute node or all the attribute values have been read, or -1
 *         in case of error.
 */
int
xmlTextReaderReadAttributeValue(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(-1);
    if (reader->curnode == NULL)
	return(0);
    if (reader->curnode->type == XML_ATTRIBUTE_NODE) {
	if (reader->curnode->children == NULL)
	    return(0);
	reader->curnode = reader->curnode->children;
    } else if (reader->curnode->type == XML_NAMESPACE_DECL) {
	xmlNsPtr ns = (xmlNsPtr) reader->curnode;

	if (reader->faketext == NULL) {
	    reader->faketext = xmlNewDocText(reader->node->doc, 
		                             ns->href);
	} else {
            if (reader->faketext->content != NULL)
		xmlFree(reader->faketext->content);
	    reader->faketext->content = xmlStrdup(ns->href);
	}
	reader->curnode = reader->faketext;
    } else {
	if (reader->curnode->next == NULL)
	    return(0);
	reader->curnode = reader->curnode->next;
    }
    return(1);
}

/************************************************************************
 *									*
 *			Acces API to the current node			*
 *									*
 ************************************************************************/
/**
 * xmlTextReaderAttributeCount:
 * @reader:  the xmlTextReaderPtr used
 *
 * Provides the number of attributes of the current node
 *
 * Returns 0 i no attributes, -1 in case of error or the attribute count
 */
int
xmlTextReaderAttributeCount(xmlTextReaderPtr reader) {
    int ret;
    xmlAttrPtr attr;
    xmlNsPtr ns;
    xmlNodePtr node;

    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(0);
    
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;

    if (node->type != XML_ELEMENT_NODE)
	return(0);
    if ((reader->state == XML_TEXTREADER_END) ||
	(reader->state == XML_TEXTREADER_BACKTRACK))
	return(0);
    ret = 0;
    attr = node->properties;
    while (attr != NULL) {
	ret++;
	attr = attr->next;
    }
    ns = node->nsDef;
    while (ns != NULL) {
	ret++;
	ns = ns->next;
    }
    return(ret);
}

/**
 * xmlTextReaderNodeType:
 * @reader:  the xmlTextReaderPtr used
 *
 * Get the node type of the current node
 * Reference:
 * http://dotgnu.org/pnetlib-doc/System/Xml/XmlNodeType.html
 *
 * Returns the xmlNodeType of the current node or -1 in case of error
 */
int
xmlTextReaderNodeType(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(0);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;
    switch (node->type) {
        case XML_ELEMENT_NODE:
	    if ((reader->state == XML_TEXTREADER_END) ||
		(reader->state == XML_TEXTREADER_BACKTRACK))
		return(15);
	    return(1);
        case XML_NAMESPACE_DECL:
        case XML_ATTRIBUTE_NODE:
	    return(2);
        case XML_TEXT_NODE:
	    return(3); /* TODO: SignificantWhitespace == 14 Whitespace == 13 */
        case XML_CDATA_SECTION_NODE:
	    return(4);
        case XML_ENTITY_REF_NODE:
	    return(5);
        case XML_ENTITY_NODE:
	    return(6);
        case XML_PI_NODE:
	    return(7);
        case XML_COMMENT_NODE:
	    return(8);
        case XML_DOCUMENT_NODE:
        case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
	    return(9);
        case XML_DOCUMENT_FRAG_NODE:
	    return(11);
        case XML_NOTATION_NODE:
	    return(12);
        case XML_DOCUMENT_TYPE_NODE:
        case XML_DTD_NODE:
	    return(10);

        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
        case XML_XINCLUDE_START:
        case XML_XINCLUDE_END:
	    return(0);
    }
    return(-1);
}

/**
 * xmlTextReaderIsEmptyElement:
 * @reader:  the xmlTextReaderPtr used
 *
 * Check if the current node is empty
 *
 * Returns 1 if empty, 0 if not and -1 in case of error
 */
int
xmlTextReaderIsEmptyElement(xmlTextReaderPtr reader) {
    if ((reader == NULL) || (reader->node == NULL))
	return(-1);
    if (reader->node->type != XML_ELEMENT_NODE)
	return(0);
    if (reader->node->children != NULL)
	return(0);
    if (reader->node != reader->ctxt->node)
	return(1);
    if ((reader->ctxt->node != NULL) &&
	(reader->node == reader->ctxt->node->last) &&
	(reader->wasempty == 1))
	return(1);
    return(0);
}

/**
 * xmlTextReaderLocalName:
 * @reader:  the xmlTextReaderPtr used
 *
 * The local name of the node.
 *
 * Returns the local name or NULL if not available
 */
xmlChar *
xmlTextReaderLocalName(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    if ((reader == NULL) || (reader->node == NULL))
	return(NULL);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;
    if (node->type == XML_NAMESPACE_DECL) {
	xmlNsPtr ns = (xmlNsPtr) node;
	if (ns->prefix == NULL)
	    return(xmlStrdup(BAD_CAST "xmlns"));
	else
	    return(xmlStrdup(ns->prefix));
    }
    if ((node->type != XML_ELEMENT_NODE) &&
	(node->type != XML_ATTRIBUTE_NODE))
	return(xmlTextReaderName(reader));
    return(xmlStrdup(node->name));
}

/**
 * xmlTextReaderName:
 * @reader:  the xmlTextReaderPtr used
 *
 * The qualified name of the node, equal to Prefix :LocalName.
 *
 * Returns the local name or NULL if not available
 */
xmlChar *
xmlTextReaderName(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    xmlChar *ret;

    if ((reader == NULL) || (reader->node == NULL))
	return(NULL);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;
    switch (node->type) {
        case XML_ELEMENT_NODE:
        case XML_ATTRIBUTE_NODE:
	    if ((node->ns == NULL) ||
		(node->ns->prefix == NULL))
		return(xmlStrdup(node->name));
	    
	    ret = xmlStrdup(node->ns->prefix);
	    ret = xmlStrcat(ret, BAD_CAST ":");
	    ret = xmlStrcat(ret, node->name);
	    return(ret);
        case XML_TEXT_NODE:
	    return(xmlStrdup(BAD_CAST "#text"));
        case XML_CDATA_SECTION_NODE:
	    return(xmlStrdup(BAD_CAST "#cdata-section"));
        case XML_ENTITY_NODE:
        case XML_ENTITY_REF_NODE:
	    return(xmlStrdup(node->name));
        case XML_PI_NODE:
	    return(xmlStrdup(node->name));
        case XML_COMMENT_NODE:
	    return(xmlStrdup(BAD_CAST "#comment"));
        case XML_DOCUMENT_NODE:
        case XML_HTML_DOCUMENT_NODE:
#ifdef LIBXML_DOCB_ENABLED
        case XML_DOCB_DOCUMENT_NODE:
#endif
	    return(xmlStrdup(BAD_CAST "#document"));
        case XML_DOCUMENT_FRAG_NODE:
	    return(xmlStrdup(BAD_CAST "#document-fragment"));
        case XML_NOTATION_NODE:
	    return(xmlStrdup(node->name));
        case XML_DOCUMENT_TYPE_NODE:
        case XML_DTD_NODE:
	    return(xmlStrdup(node->name));
        case XML_NAMESPACE_DECL: {
	    xmlNsPtr ns = (xmlNsPtr) node;

	    ret = xmlStrdup(BAD_CAST "xmlns");
	    if (ns->prefix == NULL)
		return(ret);
	    ret = xmlStrcat(ret, BAD_CAST ":");
	    ret = xmlStrcat(ret, ns->prefix);
	    return(ret);
	}

        case XML_ELEMENT_DECL:
        case XML_ATTRIBUTE_DECL:
        case XML_ENTITY_DECL:
        case XML_XINCLUDE_START:
        case XML_XINCLUDE_END:
	    return(NULL);
    }
    return(NULL);
}

/**
 * xmlTextReaderPrefix:
 * @reader:  the xmlTextReaderPtr used
 *
 * A shorthand reference to the namespace associated with the node.
 *
 * Returns the prefix or NULL if not available
 */
xmlChar *
xmlTextReaderPrefix(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    if ((reader == NULL) || (reader->node == NULL))
	return(NULL);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;
    if (node->type == XML_NAMESPACE_DECL) {
	xmlNsPtr ns = (xmlNsPtr) node;
	if (ns->prefix == NULL)
	    return(NULL);
	return(xmlStrdup(BAD_CAST "xmlns"));
    }
    if ((node->type != XML_ELEMENT_NODE) &&
	(node->type != XML_ATTRIBUTE_NODE))
	return(NULL);
    if ((node->ns != NULL) || (node->ns->prefix != NULL))
	return(xmlStrdup(node->ns->prefix));
    return(NULL);
}

/**
 * xmlTextReaderNamespaceUri:
 * @reader:  the xmlTextReaderPtr used
 *
 * The URI defining the namespace associated with the node.
 *
 * Returns the namespace URI or NULL if not available
 */
xmlChar *
xmlTextReaderNamespaceUri(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    if ((reader == NULL) || (reader->node == NULL))
	return(NULL);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;
    if (node->type == XML_NAMESPACE_DECL)
	return(xmlStrdup(BAD_CAST "http://www.w3.org/2000/xmlns/"));
    if ((node->type != XML_ELEMENT_NODE) &&
	(node->type != XML_ATTRIBUTE_NODE))
	return(NULL);
    if (node->ns != NULL)
	return(xmlStrdup(node->ns->href));
    return(NULL);
}

/**
 * xmlTextReaderBaseUri:
 * @reader:  the xmlTextReaderPtr used
 *
 * The base URI of the node.
 *
 * Returns the base URI or NULL if not available
 */
xmlChar *
xmlTextReaderBaseUri(xmlTextReaderPtr reader) {
    if ((reader == NULL) || (reader->node == NULL))
	return(NULL);
    return(xmlNodeGetBase(NULL, reader->node));
}

/**
 * xmlTextReaderDepth:
 * @reader:  the xmlTextReaderPtr used
 *
 * The depth of the node in the tree.
 *
 * Returns the depth or -1 in case of error
 */
int
xmlTextReaderDepth(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(0);

    if (reader->curnode != NULL) {
	if ((reader->curnode->type == XML_ATTRIBUTE_NODE) ||
	    (reader->curnode->type == XML_NAMESPACE_DECL))
	    return(reader->depth + 1);
	return(reader->depth + 2);
    }
    return(reader->depth);
}

/**
 * xmlTextReaderHasAttributes:
 * @reader:  the xmlTextReaderPtr used
 *
 * Whether the node has attributes.
 *
 * Returns 1 if true, 0 if false, and -1 in case or error
 */
int
xmlTextReaderHasAttributes(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(0);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;

    if ((node->type == XML_ELEMENT_NODE) &&
	(node->properties != NULL))
	return(1);
    /* TODO: handle the xmlDecl */
    return(0);
}

/**
 * xmlTextReaderHasValue:
 * @reader:  the xmlTextReaderPtr used
 *
 * Whether the node can have a text value.
 *
 * Returns 1 if true, 0 if false, and -1 in case or error
 */
int
xmlTextReaderHasValue(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    if (reader == NULL)
	return(-1);
    if (reader->node == NULL)
	return(0);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;

    switch (node->type) {
        case XML_ATTRIBUTE_NODE:
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
	    return(1);
	default:
	    return(0);
    }
    return(0);
}

/**
 * xmlTextReaderValue:
 * @reader:  the xmlTextReaderPtr used
 *
 * Provides the text value of the node if present
 *
 * Returns the string or NULL if not available. The retsult must be deallocated
 *     with xmlFree()
 */
xmlChar *
xmlTextReaderValue(xmlTextReaderPtr reader) {
    xmlNodePtr node;
    if (reader == NULL)
	return(NULL);
    if (reader->node == NULL)
	return(NULL);
    if (reader->curnode != NULL)
	node = reader->curnode;
    else
	node = reader->node;

    switch (node->type) {
        case XML_NAMESPACE_DECL:
	    return(xmlStrdup(((xmlNsPtr) node)->href));
        case XML_ATTRIBUTE_NODE:{
	    xmlAttrPtr attr = (xmlAttrPtr) node;

	    if (attr->parent != NULL)
		return (xmlNodeListGetString
			(attr->parent->doc, attr->children, 1));
	    else
		return (xmlNodeListGetString(NULL, attr->children, 1));
	    break;
	}
        case XML_TEXT_NODE:
        case XML_CDATA_SECTION_NODE:
        case XML_PI_NODE:
        case XML_COMMENT_NODE:
            if (node->content != NULL)
                return (xmlStrdup(node->content));
	default:
	    return(NULL);
    }
    return(NULL);
}

/**
 * xmlTextReaderIsDefault:
 * @reader:  the xmlTextReaderPtr used
 *
 * Whether an Attribute  node was generated from the default value
 * defined in the DTD or schema.
 *
 * Returns 0 if not defaulted, 1 if defaulted, and -1 in case of error
 */
int
xmlTextReaderIsDefault(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    return(0);
}

/**
 * xmlTextReaderQuoteChar:
 * @reader:  the xmlTextReaderPtr used
 *
 * The quotation mark character used to enclose the value of an attribute.
 *
 * Returns " or ' and -1 in case of error
 */
int
xmlTextReaderQuoteChar(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    /* TODO maybe lookup the attribute value for " first */
    return((int) '"');
}

/**
 * xmlTextReaderXmlLang:
 * @reader:  the xmlTextReaderPtr used
 *
 * The xml:lang scope within which the node resides.
 *
 * Returns the xml:lang value or NULL if none exists.
 */
xmlChar *
xmlTextReaderXmlLang(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(NULL);
    if (reader->node == NULL)
	return(NULL);
    return(xmlNodeGetLang(reader->node));
}

/**
 * xmlTextReaderNormalization:
 * @reader:  the xmlTextReaderPtr used
 *
 * The value indicating whether to normalize white space and attribute values.
 * Since attribute value and end of line normalizations are a MUST in the XML
 * specification only the value true is accepted. The broken bahaviour of
 * accepting out of range character entities like &#0; is of course not
 * supported either.
 *
 * Returns 1 or -1 in case of error.
 */
int
xmlTextReaderNormalization(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(-1);
    return(1);
}

/************************************************************************
 *									*
 *			Extensions to the base APIs			*
 *									*
 ************************************************************************/

/**
 * xmlTextReaderSetParserProp:
 * @reader:  the xmlTextReaderPtr used
 * @prop:  the xmlParserProperties to set
 * @value:  usually 0 or 1 to (de)activate it
 *
 * Change the parser processing behaviour by changing some of its internal
 * properties. Note that some properties can only be changed before any
 * read has been done.
 *
 * Returns 0 if the call was successful, or -1 in case of error
 */
int
xmlTextReaderSetParserProp(xmlTextReaderPtr reader, int prop, int value) {
    xmlParserProperties p = (xmlParserProperties) prop;
    xmlParserCtxtPtr ctxt;

    if ((reader == NULL) || (reader->ctxt == NULL))
	return(-1);
    ctxt = reader->ctxt;

    switch (p) {
        case XML_PARSER_LOADDTD:
	    if (value != 0) {
		if (ctxt->loadsubset == 0) {
		    if (reader->mode != XML_TEXTREADER_MODE_INITIAL)
			return(-1);
		    ctxt->loadsubset = XML_DETECT_IDS;
		}
	    } else {
		ctxt->loadsubset = 0;
	    }
	    return(0);
        case XML_PARSER_DEFAULTATTRS:
	    if (value != 0) {
		ctxt->loadsubset |= XML_COMPLETE_ATTRS;
	    } else {
		if (ctxt->loadsubset & XML_COMPLETE_ATTRS)
		    ctxt->loadsubset -= XML_COMPLETE_ATTRS;
	    }
	    return(0);
        case XML_PARSER_VALIDATE:
	    if (value != 0) {
		ctxt->validate = 1;
	    } else {
		ctxt->validate = 0;
	    }
	    return(0);
        case XML_PARSER_SUBST_ENTITIES:
	    if (value != 0) {
		ctxt->replaceEntities = 1;
	    } else {
		ctxt->replaceEntities = 0;
	    }
	    return(0);
    }
    return(-1);
}

/**
 * xmlTextReaderGetParserProp:
 * @reader:  the xmlTextReaderPtr used
 * @prop:  the xmlParserProperties to get
 *
 * Read the parser internal property.
 *
 * Returns the value, usually 0 or 1, or -1 in case of error.
 */
int
xmlTextReaderGetParserProp(xmlTextReaderPtr reader, int prop) {
    xmlParserProperties p = (xmlParserProperties) prop;
    xmlParserCtxtPtr ctxt;

    if ((reader == NULL) || (reader->ctxt == NULL))
	return(-1);
    ctxt = reader->ctxt;

    switch (p) {
        case XML_PARSER_LOADDTD:
	    if ((ctxt->loadsubset != 0) || (ctxt->validate != 0))
		return(1);
	    return(0);
        case XML_PARSER_DEFAULTATTRS:
	    if (ctxt->loadsubset & XML_COMPLETE_ATTRS)
		return(1);
	    return(0);
        case XML_PARSER_VALIDATE:
	    return(ctxt->validate);
	case XML_PARSER_SUBST_ENTITIES:
	    return(ctxt->replaceEntities);
    }
    return(-1);
}

/**
 * xmlTextReaderCurrentNode:
 * @reader:  the xmlTextReaderPtr used
 *
 * Hacking interface allowing to get the xmlNodePtr correponding to the
 * current node being accessed by the xmlTextReader. This is dangerous
 * because the underlying node may be destroyed on the next Reads.
 *
 * Returns the xmlNodePtr or NULL in case of error.
 */
xmlNodePtr
xmlTextReaderCurrentNode(xmlTextReaderPtr reader) {
    if (reader == NULL)
	return(NULL);
    
    if (reader->curnode != NULL)
	return(reader->curnode);
    return(reader->node);
}

/**
 * xmlTextReaderCurrentDoc:
 * @reader:  the xmlTextReaderPtr used
 *
 * Hacking interface allowing to get the xmlDocPtr correponding to the
 * current document being accessed by the xmlTextReader. This is dangerous
 * because the associated node may be destroyed on the next Reads.
 *
 * Returns the xmlDocPtr or NULL in case of error.
 */
xmlDocPtr
xmlTextReaderCurrentDoc(xmlTextReaderPtr reader) {
    if ((reader == NULL) || (reader->ctxt == NULL))
	return(NULL);
    
    return(reader->ctxt->myDoc);
}

/************************************************************************
 *									*
 *			Utilities					*
 *									*
 ************************************************************************/
/**
 * xmlBase64Decode:
 * @in:  the input buffer
 * @inlen:  the size of the input (in), the size read from it (out)
 * @to:  the output buffer
 * @tolen:  the size of the output (in), the size written to (out)
 *
 * Base64 decoder, reads from @in and save in @to
 *
 * Returns 0 if all the input was consumer, 1 if the Base64 end was reached,
 *         2 if there wasn't enough space on the output or -1 in case of error.
 */
static int
xmlBase64Decode(const unsigned char *in, unsigned long *inlen,
	        unsigned char *to, unsigned long *tolen) {
    unsigned long incur;		/* current index in in[] */
    unsigned long inblk;		/* last block index in in[] */
    unsigned long outcur;		/* current index in out[] */
    unsigned long inmax;		/* size of in[] */
    unsigned long outmax;		/* size of out[] */
    unsigned char cur;			/* the current value read from in[] */
    unsigned char intmp[3], outtmp[4];	/* temporary buffers for the convert */
    int nbintmp;			/* number of byte in intmp[] */
    int is_ignore;			/* cur should be ignored */
    int is_end = 0;			/* the end of the base64 was found */
    int retval = 1;
    int i;

    if ((in == NULL) || (inlen == NULL) || (to == NULL) || (tolen == NULL))
	return(-1);

    incur = 0;
    inblk = 0;
    outcur = 0;
    inmax = *inlen;
    outmax = *tolen;
    nbintmp = 0;

    while (1) {
        if (incur >= inmax)
            break;
        cur = in[incur++];
        is_ignore = 0;
        if ((cur >= 'A') && (cur <= 'Z'))
            cur = cur - 'A';
        else if ((cur >= 'a') && (cur <= 'z'))
            cur = cur - 'a' + 26;
        else if ((cur >= '0') && (cur <= '9'))
            cur = cur - '0' + 52;
        else if (cur == '+')
            cur = 62;
        else if (cur == '/')
            cur = 63;
        else if (cur == '.')
            cur = 0;
        else if (cur == '=') /*no op , end of the base64 stream */
            is_end = 1;
        else {
            is_ignore = 1;
	    if (nbintmp == 0)
		inblk = incur;
	}

        if (!is_ignore) {
            int nbouttmp = 3;
            int is_break = 0;

            if (is_end) {
                if (nbintmp == 0)
                    break;
                if ((nbintmp == 1) || (nbintmp == 2))
                    nbouttmp = 1;
                else
                    nbouttmp = 2;
                nbintmp = 3;
                is_break = 1;
            }
            intmp[nbintmp++] = cur;
	    /*
	     * if intmp is full, push the 4byte sequence as a 3 byte
	     * sequence out
	     */
            if (nbintmp == 4) {
                nbintmp = 0;
                outtmp[0] = (intmp[0] << 2) | ((intmp[1] & 0x30) >> 4);
                outtmp[1] =
                    ((intmp[1] & 0x0F) << 4) | ((intmp[2] & 0x3C) >> 2);
                outtmp[2] = ((intmp[2] & 0x03) << 6) | (intmp[3] & 0x3F);
		if (outcur + 3 >= outmax) {
		    retval = 2;
		    break;
		}

                for (i = 0; i < nbouttmp; i++)
		    to[outcur++] = outtmp[i];
		inblk = incur;
            }

            if (is_break) {
		retval = 0;
                break;
	    }
        }
    }

    *tolen = outcur;
    *inlen = inblk;
    return (retval);
}

/*
 * Test routine for the xmlBase64Decode function
 */
#if 0
int main(int argc, char **argv) {
    char *input = "  VW4 gcGV0        \n      aXQgdGVzdCAuCg== ";
    char output[100];
    char output2[100];
    char output3[100];
    unsigned long inlen = strlen(input);
    unsigned long outlen = 100;
    int ret;
    unsigned long cons, tmp, tmp2, prod;

    /*
     * Direct
     */
    ret = xmlBase64Decode(input, &inlen, output, &outlen);

    output[outlen] = 0;
    printf("ret: %d, inlen: %ld , outlen: %ld, output: '%s'\n", ret, inlen, outlen, output);
    
    /*
     * output chunking
     */
    cons = 0;
    prod = 0;
    while (cons < inlen) {
	tmp = 5;
	tmp2 = inlen - cons;

	printf("%ld %ld\n", cons, prod);
	ret = xmlBase64Decode(&input[cons], &tmp2, &output2[prod], &tmp);
	cons += tmp2;
	prod += tmp;
	printf("%ld %ld\n", cons, prod);
    }
    output2[outlen] = 0;
    printf("ret: %d, cons: %ld , prod: %ld, output: '%s'\n", ret, cons, prod, output2);

    /*
     * input chunking
     */
    cons = 0;
    prod = 0;
    while (cons < inlen) {
	tmp = 100 - prod;
	tmp2 = inlen - cons;
	if (tmp2 > 5)
	    tmp2 = 5;

	printf("%ld %ld\n", cons, prod);
	ret = xmlBase64Decode(&input[cons], &tmp2, &output3[prod], &tmp);
	cons += tmp2;
	prod += tmp;
	printf("%ld %ld\n", cons, prod);
    }
    output3[outlen] = 0;
    printf("ret: %d, cons: %ld , prod: %ld, output: '%s'\n", ret, cons, prod, output3);
    return(0);

}
#endif
