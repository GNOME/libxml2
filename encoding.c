/*
 * encoding.c : implements the encoding conversion functions needed for XML
 *
 * Related specs: 
 * rfc2044        (UTF-8 and UTF-16) F. Yergeau Alis Technologies
 * [ISO-10646]    UTF-8 and UTF-16 in Annexes
 * [ISO-8859-1]   ISO Latin-1 characters codes.
 * [UNICODE]      The Unicode Consortium, "The Unicode Standard --
 *                Worldwide Character Encoding -- Version 1.0", Addison-
 *                Wesley, Volume 1, 1991, Volume 2, 1992.  UTF-8 is
 *                described in Unicode Technical Report #4.
 * [US-ASCII]     Coded Character Set--7-bit American Standard Code for
 *                Information Interchange, ANSI X3.4-1986.
 *
 * Original code for IsoLatin1 and UTF-16 by "Martin J. Duerst" <duerst@w3.org>
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include <unicode.h>

#include "encoding.h"


/*
 * From rfc2044: encoding of the Unicode values on UTF-8:
 *
 * UCS-4 range (hex.)           UTF-8 octet sequence (binary)
 * 0000 0000-0000 007F   0xxxxxxx
 * 0000 0080-0000 07FF   110xxxxx 10xxxxxx
 * 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx 
 *
 * I hope we won't use values > 0xFFFF anytime soon !
 */

/**
 * isolat1ToUTF8:
 * @out:  a pointer ot an array of bytes to store the result
 * @outlen:  the lenght of @out
 * @in:  a pointer ot an array of ISO Latin 1 chars
 * @inlen:  the lenght of @in
 *
 * Take a block of ISO Latin 1 chars in and try to convert it to an UTF-8
 * block of chars out.
 * Returns the number of byte written, or -1 by lack of space.
 */
int
isolat1ToUTF8(unsigned char* out, int outlen, unsigned char* in, int inlen)
{
  iconv_t u;
  size_t i;
  
  unsigned char *o = out;

  u = unicode_iconv_open("UTF-8", "ISO-8859-1");
  i = unicode_iconv(u, &in, &inlen, &out, &outlen);

  unicode_iconv_close(u);

  if (i==-1)
    return i;
  else
    return out - o;
}

/**
 * UTF8Toisolat1:
 * @out:  a pointer ot an array of bytes to store the result
 * @outlen:  the lenght of @out
 * @in:  a pointer ot an array of UTF-8 chars
 * @inlen:  the lenght of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an ISO Latin 1
 * block of chars out.
 * TODO: need a fallback mechanism ...
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 */
int
UTF8Toisolat1(unsigned char* out, int outlen, unsigned char* in, int inlen)
{
  iconv_t u;
  size_t i;
  
  unsigned char *o = out;

  u = unicode_iconv_open("ISO-8859-1", "UTF-8");
  i = unicode_iconv(u, &in, &inlen, &out, &outlen);

  unicode_iconv_close(u);

  if (i==-1)
    return i;
  else
    return out - o;
}

/**
 * UTF16ToUTF8:
 * @out:  a pointer ot an array of bytes to store the result
 * @outlen:  the lenght of @out
 * @in:  a pointer ot an array of UTF-16 chars (array of unsigned shorts)
 * @inlen:  the lenght of @in
 *
 * Take a block of UTF-16 ushorts in and try to convert it to an UTF-8
 * block of chars out.
 * Returns the number of byte written, or -1 by lack of space.
 */
int
UTF16ToUTF8(unsigned char* out, int outlen, unsigned short* in, int inlen)
{
  iconv_t u;
  size_t i;
  
  unsigned char *o = out;

  u = unicode_iconv_open("UTF-8", "UTF-16");
  i = unicode_iconv(u, &in, &inlen, &out, &outlen);

  unicode_iconv_close(u);

  if (i==-1)
    return i;
  else
    return out - o;
}

/**
 * UTF8ToUTF16:
 * @out:  a pointer ot an array of shorts to store the result
 * @outlen:  the lenght of @out (number of shorts)
 * @in:  a pointer ot an array of UTF-8 chars
 * @inlen:  the lenght of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an UTF-16
 * block of chars out.
 * TODO: need a fallback mechanism ...
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 */
int
UTF8ToUTF16(unsigned short* out, int outlen, unsigned char* in, int inlen)
{
  iconv_t u;
  size_t i;
  
  unsigned short *o = out;

  u = unicode_iconv_open("UTF-16", "UTF-8");
  i = unicode_iconv(u, &in, &inlen, &out, &outlen);

  unicode_iconv_close(u);

  if (i==-1)
    return i;
  else
    return out - o;
}


/**
 * xmlDetectCharEncoding:
 * @in:  a pointer to the first bytes of the XML entity, must be at least
 *       4 bytes long.
 *
 * Guess the encoding of the entity using the first bytes of the entity content
 * accordingly of the non-normative appendix F of the XML-1.0 recommendation.
 * 
 * Returns one of the XML_CHAR_ENCODING_... values.
 */
xmlCharEncoding
xmlDetectCharEncoding(const unsigned char* in)
{
    if ((in[0] == 0x00) && (in[1] == 0x00) &&
        (in[2] == 0x00) && (in[3] == 0x3C))
	return(XML_CHAR_ENCODING_UCS4BE);
    if ((in[0] == 0x3C) && (in[1] == 0x00) &&
        (in[2] == 0x00) && (in[3] == 0x00))
	return(XML_CHAR_ENCODING_UCS4LE);
    if ((in[0] == 0x00) && (in[1] == 0x00) &&
        (in[2] == 0x3C) && (in[3] == 0x00))
	return(XML_CHAR_ENCODING_UCS4_2143);
    if ((in[0] == 0x00) && (in[1] == 0x3C) &&
        (in[2] == 0x00) && (in[3] == 0x00))
	return(XML_CHAR_ENCODING_UCS4_3412);
    if ((in[0] == 0xFE) && (in[1] == 0xFF))
	return(XML_CHAR_ENCODING_UTF16BE);
    if ((in[0] == 0xFF) && (in[1] == 0xFE))
	return(XML_CHAR_ENCODING_UTF16LE);
    if ((in[0] == 0x4C) && (in[1] == 0x6F) &&
        (in[2] == 0xA7) && (in[3] == 0x94))
	return(XML_CHAR_ENCODING_EBCDIC);
    if ((in[0] == 0x3C) && (in[1] == 0x3F) &&
        (in[2] == 0x78) && (in[3] == 0x6D))
	return(XML_CHAR_ENCODING_UTF8);
    return(XML_CHAR_ENCODING_NONE);
}

/**
 * xmlParseCharEncoding:
 * @name:  the encoding name as parsed, in UTF-8 format (ASCII actually)
 *
 * Conpare the string to the known encoding schemes already known. Note
 * that the comparison is case insensitive accordingly to the section
 * [XML] 4.3.3 Character Encoding in Entities.
 * 
 * Returns one of the XML_CHAR_ENCODING_... values or XML_CHAR_ENCODING_NONE
 * if not recognized.
 */
xmlCharEncoding
xmlParseCharEncoding(const char* name)
{
    char upper[500];
    int i;

    for (i = 0;i < 499;i++) {
        upper[i] = toupper(name[i]);
	if (upper[i] == 0) break;
    }
    upper[i] = 0;

    if (!strcmp(upper, "")) return(XML_CHAR_ENCODING_NONE);
    if (!strcmp(upper, "UTF-8")) return(XML_CHAR_ENCODING_UTF8);
    if (!strcmp(upper, "UTF8")) return(XML_CHAR_ENCODING_UTF8);

    /*
     * NOTE: if we were able to parse this, the endianness of UTF16 is
     *       already found and in use
     */
    if (!strcmp(upper, "UTF-16")) return(XML_CHAR_ENCODING_UTF16LE);
    if (!strcmp(upper, "UTF16")) return(XML_CHAR_ENCODING_UTF16LE);
    
    if (!strcmp(upper, "ISO-10646-UCS-2")) return(XML_CHAR_ENCODING_UCS2);
    if (!strcmp(upper, "UCS-2")) return(XML_CHAR_ENCODING_UCS2);
    if (!strcmp(upper, "UCS2")) return(XML_CHAR_ENCODING_UCS2);

    /*
     * NOTE: if we were able to parse this, the endianness of UCS4 is
     *       already found and in use
     */
    if (!strcmp(upper, "ISO-10646-UCS-4")) return(XML_CHAR_ENCODING_UCS4LE);
    if (!strcmp(upper, "UCS-4")) return(XML_CHAR_ENCODING_UCS4LE);
    if (!strcmp(upper, "UCS4")) return(XML_CHAR_ENCODING_UCS4LE);

    
    if (!strcmp(upper,  "ISO-8859-1")) return(XML_CHAR_ENCODING_8859_1);
    if (!strcmp(upper,  "ISO-LATIN-1")) return(XML_CHAR_ENCODING_8859_1);
    if (!strcmp(upper,  "ISO LATIN 1")) return(XML_CHAR_ENCODING_8859_1);

    if (!strcmp(upper,  "ISO-8859-2")) return(XML_CHAR_ENCODING_8859_2);
    if (!strcmp(upper,  "ISO-LATIN-2")) return(XML_CHAR_ENCODING_8859_2);
    if (!strcmp(upper,  "ISO LATIN 2")) return(XML_CHAR_ENCODING_8859_2);

    if (!strcmp(upper,  "ISO-8859-3")) return(XML_CHAR_ENCODING_8859_3);
    if (!strcmp(upper,  "ISO-8859-4")) return(XML_CHAR_ENCODING_8859_4);
    if (!strcmp(upper,  "ISO-8859-5")) return(XML_CHAR_ENCODING_8859_5);
    if (!strcmp(upper,  "ISO-8859-6")) return(XML_CHAR_ENCODING_8859_6);
    if (!strcmp(upper,  "ISO-8859-7")) return(XML_CHAR_ENCODING_8859_7);
    if (!strcmp(upper,  "ISO-8859-8")) return(XML_CHAR_ENCODING_8859_8);
    if (!strcmp(upper,  "ISO-8859-9")) return(XML_CHAR_ENCODING_8859_9);

    if (!strcmp(upper, "ISO-2022-JP")) return(XML_CHAR_ENCODING_2022_JP);
    if (!strcmp(upper, "Shift_JIS")) return(XML_CHAR_ENCODING_SHIFT_JIS);
    if (!strcmp(upper, "EUC-JP")) return(XML_CHAR_ENCODING_EUC_JP);
    return(XML_CHAR_ENCODING_ERROR);
}

/****************************************************************
 *								*
 *		Char encoding handlers				*
 *								*
 ****************************************************************/

/* the size should be growable, but it's not a big deal ... */
#define MAX_ENCODING_HANDLERS 50
static xmlCharEncodingHandlerPtr *handlers = NULL;
static int nbCharEncodingHandler = 0;

/*
 * The default is UTF-8 for XML, that's also the default used for the
 * parser internals, so the default encoding handler is NULL
 */

static xmlCharEncodingHandlerPtr xmlDefaultCharEncodingHandler = NULL;

/**
 * xmlNewCharEncodingHandler:
 * @name:  the encoding name, in UTF-8 format (ASCCI actually)
 * @input:  the xmlCharEncodingInputFunc to read that encoding
 * @output:  the xmlCharEncodingOutputFunc to write that encoding
 *
 * Create and registers an xmlCharEncodingHandler.
 * Returns the xmlCharEncodingHandlerPtr created (or NULL in case of error).
 */
xmlCharEncodingHandlerPtr
xmlNewCharEncodingHandler(const char *name, xmlCharEncodingInputFunc input,
                          xmlCharEncodingOutputFunc output) {
    xmlCharEncodingHandlerPtr handler;
    char upper[500];
    int i;
    char *up = 0;

    /*
     * Keep only the uppercase version of the encoding.
     */
    if (name == NULL) {
        fprintf(stderr, "xmlNewCharEncodingHandler : no name !\n");
	return(NULL);
    }
    for (i = 0;i < 499;i++) {
        upper[i] = toupper(name[i]);
	if (upper[i] == 0) break;
    }
    upper[i] = 0;
    up = strdup(upper);
    if (up == NULL) {
        fprintf(stderr, "xmlNewCharEncodingHandler : out of memory !\n");
	return(NULL);
    }

    /*
     * allocate and fill-up an handler block.
     */
    handler = (xmlCharEncodingHandlerPtr)
              malloc(sizeof(xmlCharEncodingHandler));
    if (handler == NULL) {
        fprintf(stderr, "xmlNewCharEncodingHandler : out of memory !\n");
	return(NULL);
    }
    handler->input = input;
    handler->output = output;
    handler->name = up;

    /*
     * registers and returns the handler.
     */
    xmlRegisterCharEncodingHandler(handler);
    return(handler);
}

/**
 * xmlInitCharEncodingHandlers:
 *
 * Initialize the char encoding support, it registers the default
 * encoding supported.
 * NOTE: while public theis function usually don't need to be called
 *       in normal processing.
 */
void
xmlInitCharEncodingHandlers(void) {
    if (handlers != NULL) return;

    handlers = (xmlCharEncodingHandlerPtr *)
        malloc(MAX_ENCODING_HANDLERS * sizeof(xmlCharEncodingHandlerPtr));

    if (handlers == NULL) {
        fprintf(stderr, "xmlInitCharEncodingHandlers : out of memory !\n");
	return;
    }
    xmlNewCharEncodingHandler("UTF-8", NULL, NULL);
    xmlNewCharEncodingHandler("UTF-16", UTF16ToUTF8, UTF8ToUTF16);
    xmlNewCharEncodingHandler("ISO-8859-1", isolat1ToUTF8, UTF8Toisolat1);
}

/**
 * xmlRegisterCharEncodingHandler:
 * @handler:  the xmlCharEncodingHandlerPtr handler block
 *
 * Register the char encoding handler, surprizing, isn't it ?
 */
void
xmlRegisterCharEncodingHandler(xmlCharEncodingHandlerPtr handler) {
    if (handlers == NULL) xmlInitCharEncodingHandlers();
    if (handler == NULL) {
        fprintf(stderr, "xmlRegisterCharEncodingHandler: NULL handler !\n");
	return;
    }

    if (nbCharEncodingHandler >= MAX_ENCODING_HANDLERS) {
        fprintf(stderr, 
	"xmlRegisterCharEncodingHandler: Too many handler registered\n");
        fprintf(stderr, "\tincrease MAX_ENCODING_HANDLERS : %s\n", __FILE__);
	return;
    }
    handlers[nbCharEncodingHandler++] = handler;
}

/**
 * xmlGetCharEncodingHandler:
 * @enc:  an xmlCharEncoding value.
 *
 * Search in the registrered set the handler able to read/write that encoding.
 *
 * Returns the handler or NULL if not found
 */
xmlCharEncodingHandlerPtr
xmlGetCharEncodingHandler(xmlCharEncoding enc) {
    if (handlers == NULL) xmlInitCharEncodingHandlers();
    /* TODO !!!!!!! */
    return(NULL);
}

/**
 * xmlGetCharEncodingHandler:
 * @enc:  a string describing the char encoding.
 *
 * Search in the registrered set the handler able to read/write that encoding.
 *
 * Returns the handler or NULL if not found
 */
xmlCharEncodingHandlerPtr
xmlFindCharEncodingHandler(const char *name) {
    char upper[500];
    int i;

    if (handlers == NULL) xmlInitCharEncodingHandlers();
    if (name == NULL) return(xmlDefaultCharEncodingHandler);
    if (name[0] == 0) return(xmlDefaultCharEncodingHandler);

    for (i = 0;i < 499;i++) {
        upper[i] = toupper(name[i]);
	if (upper[i] == 0) break;
    }
    upper[i] = 0;

    for (i = 0;i < nbCharEncodingHandler; i++)
        if (!strcmp(name, handlers[i]->name))
	    return(handlers[i]);

    return(NULL);
}

