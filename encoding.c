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

#ifdef WIN32
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include "encoding.h"
#ifdef HAVE_UNICODE_H
#include <unicode.h>
#endif
#include "xmlmemory.h"

#ifdef HAVE_UNICODE_H

#else /* ! HAVE_UNICODE_H */
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
 * @out:  a pointer to an array of bytes to store the result
 * @outlen:  the length of @out
 * @in:  a pointer to an array of ISO Latin 1 chars
 * @inlen:  the length of @in
 *
 * Take a block of ISO Latin 1 chars in and try to convert it to an UTF-8
 * block of chars out.
 * Returns the number of byte written, or -1 by lack of space.
 */
int
isolat1ToUTF8(unsigned char* out, int outlen, unsigned char* in, int inlen)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned char* inend= in+inlen;
    unsigned char c;

    while (in < inend) {
        c= *in++;
        if (c < 0x80) {
            if (out >= outend)  return -1;
            *out++ = c;
        }
        else {
            if (out >= outend)  return -1;
            *out++ = 0xC0 | (c >> 6);
            if (out >= outend)  return -1;
            *out++ = 0x80 | (0x3F & c);
        }
    }
    return out-outstart;
}

/**
 * UTF8Toisolat1:
 * @out:  a pointer to an array of bytes to store the result
 * @outlen:  the length of @out
 * @in:  a pointer to an array of UTF-8 chars
 * @inlen:  the length of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an ISO Latin 1
 * block of chars out.
 * TODO: UTF8Toisolat1 need a fallback mechanism ...
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 */
int
UTF8Toisolat1(unsigned char* out, int outlen, unsigned char* in, int inlen)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned char* inend= in+inlen;
    unsigned char c;

    while (in < inend) {
        c= *in++;
        if (c < 0x80) {
            if (out >= outend)  return -1;
            *out++= c;
        }
        else if (((c & 0xFE) == 0xC2) && in<inend) {
            if (out >= outend)  return -1;
            *out++= ((c & 0x03) << 6) | (*in++ & 0x3F);
        }
        else  return -2;
    }
    return out-outstart;
}

/**
 * UTF16ToUTF8:
 * @out:  a pointer to an array of bytes to store the result
 * @outlen:  the length of @out
 * @in:  a pointer to an array of UTF-16 chars (array of unsigned shorts)
 * @inlen:  the length of @in
 *
 * Take a block of UTF-16 ushorts in and try to convert it to an UTF-8
 * block of chars out.
 * Returns the number of byte written, or -1 by lack of space.
 */
int
UTF16ToUTF8(unsigned char* out, int outlen, unsigned short* in, int inlen)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned short* inend= in+inlen;
    unsigned int c, d;
    int bits;

    while (in < inend) {
        c= *in++;
        if ((c & 0xFC00) == 0xD800) {    /* surrogates */
            if ((in<inend) && (((d=*in++) & 0xFC00) == 0xDC00)) {
                c &= 0x03FF;
                c <<= 10;
                c |= d & 0x03FF;
                c += 0x10000;
            }
            else  return -1;
        }

      /* assertion: c is a single UTF-4 value */

        if (out >= outend)  return -1;
        if      (c <    0x80) {  *out++=  c;                bits= -6; }
        else if (c <   0x800) {  *out++= (c >>  6) | 0xC0;  bits=  0; }
        else if (c < 0x10000) {  *out++= (c >> 12) | 0xE0;  bits=  6; }
        else                  {  *out++= (c >> 18) | 0xF0;  bits= 12; }
 
        for ( ; bits > 0; bits-= 6) {
            if (out >= outend)  return -1;
            *out++= (c >> bits) & 0x3F;
        }
    }
    return out-outstart;
}

/**
 * UTF8ToUTF16:
 * @out:  a pointer to an array of shorts to store the result
 * @outlen:  the length of @out (number of shorts)
 * @in:  a pointer to an array of UTF-8 chars
 * @inlen:  the length of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an UTF-16
 * block of chars out.
 * TODO: UTF8ToUTF16 need a fallback mechanism ...
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed.
 */
int
UTF8ToUTF16(unsigned short* out, int outlen, unsigned char* in, int inlen)
{
    unsigned short* outstart= out;
    unsigned short* outend= out+outlen;
    unsigned char* inend= in+inlen;
    unsigned int c, d, trailing;

    while (in < inend) {
      d= *in++;
      if      (d < 0x80)  { c= d; trailing= 0; }
      else if (d < 0xC0)  return -2;    /* trailing byte in leading position */
      else if (d < 0xE0)  { c= d & 0x1F; trailing= 1; }
      else if (d < 0xF0)  { c= d & 0x0F; trailing= 2; }
      else if (d < 0xF8)  { c= d & 0x07; trailing= 3; }
      else return -2;    /* no chance for this in UTF-16 */

      for ( ; trailing; trailing--) {
          if ((in >= inend) || (((d= *in++) & 0xC0) != 0x80))  return -1;
          c <<= 6;
          c |= d & 0x3F;
      }

      /* assertion: c is a single UTF-4 value */
        if (c < 0x10000) {
            if (out >= outend)  return -1;
            *out++ = c;
        }
        else if (c < 0x110000) {
            if (out+1 >= outend)  return -1;
            c -= 0x10000;
            *out++ = 0xD800 | (c >> 10);
            *out++ = 0xDC00 | (c & 0x03FF);
        }
        else  return -1;
    }
    return out-outstart;
}

#endif /* ! HAVE_UNICODE_H */

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
 * @name:  the encoding name, in UTF-8 format (ASCII actually)
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
    up = xmlMemStrdup(upper);
    if (up == NULL) {
        fprintf(stderr, "xmlNewCharEncodingHandler : out of memory !\n");
	return(NULL);
    }

    /*
     * allocate and fill-up an handler block.
     */
    handler = (xmlCharEncodingHandlerPtr)
              xmlMalloc(sizeof(xmlCharEncodingHandler));
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
 * NOTE: while public, this function usually doesn't need to be called
 *       in normal processing.
 */
void
xmlInitCharEncodingHandlers(void) {
    if (handlers != NULL) return;

    handlers = (xmlCharEncodingHandlerPtr *)
        xmlMalloc(MAX_ENCODING_HANDLERS * sizeof(xmlCharEncodingHandlerPtr));

    if (handlers == NULL) {
        fprintf(stderr, "xmlInitCharEncodingHandlers : out of memory !\n");
	return;
    }
    xmlNewCharEncodingHandler("UTF-8", NULL, NULL);
#ifdef HAVE_UNICODE_H
#else
    /* xmlNewCharEncodingHandler("UTF-16", UTF16ToUTF8, UTF8ToUTF16); */
    xmlNewCharEncodingHandler("ISO-8859-1", isolat1ToUTF8, UTF8Toisolat1);
#endif
}

/**
 * xmlCleanupCharEncodingHandlers:
 *
 * Cleanup the memory allocated for the char encoding support, it
 * unregisters all the encoding handlers.
 */
void
xmlCleanupCharEncodingHandlers(void) {
    if (handlers == NULL) return;

    for (;nbCharEncodingHandler > 0;) {
        nbCharEncodingHandler--;
	if (handlers[nbCharEncodingHandler] != NULL) {
	    xmlFree(handlers[nbCharEncodingHandler]->name);
	    xmlFree(handlers[nbCharEncodingHandler]);
	}
    }
    xmlFree(handlers);
    handlers = NULL;
    nbCharEncodingHandler = 0;
    xmlDefaultCharEncodingHandler = NULL;
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
    /* TODO xmlGetCharEncodingHandler !!!!!!! */
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

