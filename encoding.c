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
#include <libxml/encoding.h>
#include <libxml/xmlmemory.h>

xmlCharEncodingHandlerPtr xmlUTF16LEHandler = NULL;
xmlCharEncodingHandlerPtr xmlUTF16BEHandler = NULL;

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
 * xmlCheckUTF8: Check utf-8 string for legality.
 * @utf: Pointer to putative utf-8 encoded string.
 *
 * Checks @utf for being valid utf-8. @utf is assumed to be
 * null-terminated. This function is not super-strict, as it will
 * allow longer utf-8 sequences than necessary. Note that Java is
 * capable of producing these sequences if provoked. Also note, this
 * routine checks for the 4-byte maxiumum size, but does not check for
 * 0x10ffff maximum value.
 *
 * Return value: true if @utf is valid.
 **/
int
xmlCheckUTF8(const unsigned char *utf)
{
    int ix;
    unsigned char c;

    for (ix = 0; (c = utf[ix]);) {
        if (c & 0x80) {
	    if ((utf[ix + 1] & 0xc0) != 0x80)
	        return(0);
	    if ((c & 0xe0) == 0xe0) {
	        if ((utf[ix + 2] & 0xc0) != 0x80)
		    return(0);
	        if ((c & 0xf0) == 0xf0) {
		    if ((c & 0xf8) != 0xf0 || (utf[ix + 3] & 0xc0) != 0x80)
		        return(0);
		    ix += 4;
		    /* 4-byte code */
	        } else
		  /* 3-byte code */
		    ix += 3;
	    } else
	      /* 2-byte code */
	        ix += 2;
	} else
	    /* 1-byte code */
	    ix++;
      }
      return(1);
}

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
isolat1ToUTF8(unsigned char* out, int outlen,
              const unsigned char* in, int *inlen) {
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    const unsigned char* inend= in+*inlen;
    unsigned char c;

    while (in < inend) {
        c= *in++;
        if (c < 0x80) {
            if (out >= outend)  return(-1);
            *out++ = c;
        }
        else {
            if (out >= outend)  return(-1);
            *out++ = 0xC0 | (c >> 6);
            if (out >= outend)  return(-1);
            *out++ = 0x80 | (0x3F & c);
        }
    }
    return(out-outstart);
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
 *     if the transcoding fails (for *in is not valid utf8 string or
 *     the result of transformation can't fit into the encoding we want)
 * The value of @inlen after return is the number of octets consumed
 *     as the return value is positive, else unpredictiable.
 */
int
UTF8Toisolat1(unsigned char* out, int outlen,
              const unsigned char* in, int *inlen) {
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    const unsigned char* inend= in+*inlen;
    unsigned char c;

    while (in < inend) {
        c= *in++;
        if (c < 0x80) {
            if (out >= outend)  return(-1);
            *out++= c;
        }
	else if (in == inend) {
            *inlen -= 1;
            break;
	}
	else if (((c & 0xFC) == 0xC0) && ((*in & 0xC0) == 0x80)) {
	    /* a two byte utf-8 and can be encoding as isolate1 */
            *out++= ((c & 0x03) << 6) | (*in++ & 0x3F);
	}
	else
	    return(-2);
	/* TODO : some should be represent as "&#x____;" */
    }
    return(out-outstart);
}

/**
 * UTF16LEToUTF8:
 * @out:  a pointer to an array of bytes to store the result
 * @outlen:  the length of @out
 * @inb:  a pointer to an array of UTF-16LE passwd as a byte array
 * @inlenb:  the length of @in in UTF-16LE chars
 *
 * Take a block of UTF-16LE ushorts in and try to convert it to an UTF-8
 * block of chars out. This function assume the endian properity
 * is the same between the native type of this machine and the
 * inputed one.
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding fails (for *in is not valid utf16 string)
 *     The value of *inlen after return is the number of octets consumed
 *     as the return value is positive, else unpredictiable.
 */
int
UTF16LEToUTF8(unsigned char* out, int outlen,
            const unsigned char* inb, int *inlenb)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned short* in = (unsigned short*) inb;
    unsigned short* inend;
    unsigned int c, d, inlen;
    unsigned char *tmp;
    int bits;

    if ((*inlenb % 2) == 1)
        (*inlenb)--;
    inlen = *inlenb / 2;
    inend= in + inlen;
    while (in < inend) {
#ifdef BIG_ENDIAN
	tmp = (unsigned char *) in;
	c = *tmp++;
	c = c | (((unsigned int)*tmp) << 8);
	in++;
#else /* BIG_ENDIAN */
        c= *in++;
#endif /* BIG_ENDIAN */
        if ((c & 0xFC00) == 0xD800) {    /* surrogates */
            if (in >= inend) {           /* (in > inend) shouldn't happens */
                (*inlenb) -= 2;
                break;
            }
#ifdef BIG_ENDIAN
            tmp = (unsigned char *) in;
            d = *tmp++;
	    d = d | (((unsigned int)*tmp) << 8);
	    in++;
#else /* BIG_ENDIAN */
            d = *in++;
#endif /* BIG_ENDIAN */
            if ((d & 0xFC00) == 0xDC00) {
                c &= 0x03FF;
                c <<= 10;
                c |= d & 0x03FF;
                c += 0x10000;
            }
            else
	        return(-2);
        }

	/* assertion: c is a single UTF-4 value */
        if (out >= outend)
	    return(-1);
        if      (c <    0x80) {  *out++=  c;                bits= -6; }
        else if (c <   0x800) {  *out++= ((c >>  6) & 0x1F) | 0xC0;  bits=  0; }
        else if (c < 0x10000) {  *out++= ((c >> 12) & 0x0F) | 0xE0;  bits=  6; }
        else                  {  *out++= ((c >> 18) & 0x07) | 0xF0;  bits= 12; }
 
        for ( ; bits >= 0; bits-= 6) {
            if (out >= outend)
	        return(-1);
            *out++= ((c >> bits) & 0x3F) | 0x80;
        }
    }
    return(out-outstart);
}

/**
 * UTF8ToUTF16LE:
 * @outb:  a pointer to an array of bytes to store the result
 * @outlen:  the length of @outb
 * @in:  a pointer to an array of UTF-8 chars
 * @inlen:  the length of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an UTF-16LE
 * block of chars out.
 * TODO: UTF8ToUTF16LE need a fallback mechanism ...
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed. 
 */
int
UTF8ToUTF16LE(unsigned char* outb, int outlen,
            const unsigned char* in, int *inlen)
{
    unsigned short* out = (unsigned short*) outb;
    unsigned short* outstart= out;
    unsigned short* outend;
    const unsigned char* inend= in+*inlen;
    unsigned int c, d, trailing;
#ifdef BIG_ENDIAN
    unsigned char *tmp;
    unsigned short tmp1, tmp2;
#endif /* BIG_ENDIAN */

    outlen /= 2; /* convert in short length */
    outend = out + outlen;
    while (in < inend) {
      d= *in++;
      if      (d < 0x80)  { c= d; trailing= 0; }
      else if (d < 0xC0)
          return(-2);    /* trailing byte in leading position */
      else if (d < 0xE0)  { c= d & 0x1F; trailing= 1; }
      else if (d < 0xF0)  { c= d & 0x0F; trailing= 2; }
      else if (d < 0xF8)  { c= d & 0x07; trailing= 3; }
      else
          return(-2);    /* no chance for this in UTF-16 */

      if (inend - in < trailing) {
          *inlen -= (inend - in);
          break;
      } 

      for ( ; trailing; trailing--) {
          if ((in >= inend) || (((d= *in++) & 0xC0) != 0x80))
	      return(-1);
          c <<= 6;
          c |= d & 0x3F;
      }

      /* assertion: c is a single UTF-4 value */
        if (c < 0x10000) {
            if (out >= outend)
	        return(-1);
#ifdef BIG_ENDIAN
            tmp = (unsigned char *) out;
            *tmp = c ;
            *(tmp + 1) = c >> 8 ;
            out++;
#else /* BIG_ENDIAN */
            *out++ = c;
#endif /* BIG_ENDIAN */
        }
        else if (c < 0x110000) {
            if (out+1 >= outend)
	        return(-1);
            c -= 0x10000;
#ifdef BIG_ENDIAN
            tmp1 = 0xD800 | (c >> 10);
            tmp = (unsigned char *) out;
            *tmp = tmp1;
            *(tmp + 1) = tmp1 >> 8;
            out++;

            tmp2 = 0xDC00 | (c & 0x03FF);
            tmp = (unsigned char *) out;
            *tmp  = tmp2;
            *(tmp + 1) = tmp2 >> 8;
            out++;
#else /* BIG_ENDIAN */
            *out++ = 0xD800 | (c >> 10);
            *out++ = 0xDC00 | (c & 0x03FF);
#endif /* BIG_ENDIAN */
        }
        else
	    return(-1);
    }
    return(out-outstart);
}

/**
 * UTF16BEToUTF8:
 * @out:  a pointer to an array of bytes to store the result
 * @outlen:  the length of @out
 * @inb:  a pointer to an array of UTF-16 passwd as a byte array
 * @inlenb:  the length of @in in UTF-16 chars
 *
 * Take a block of UTF-16 ushorts in and try to convert it to an UTF-8
 * block of chars out. This function assume the endian properity
 * is the same between the native type of this machine and the
 * inputed one.
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding fails (for *in is not valid utf16 string)
 * The value of *inlen after return is the number of octets consumed
 *     as the return value is positive, else unpredictiable.
 */
int
UTF16BEToUTF8(unsigned char* out, int outlen,
            const unsigned char* inb, int *inlenb)
{
    unsigned char* outstart= out;
    unsigned char* outend= out+outlen;
    unsigned short* in = (unsigned short*) inb;
    unsigned short* inend;
    unsigned int c, d, inlen;
#ifdef BIG_ENDIAN
#else /* BIG_ENDIAN */
    unsigned char *tmp;
#endif /* BIG_ENDIAN */    
    int bits;

    if ((*inlenb % 2) == 1)
        (*inlenb)--;
    inlen = *inlenb / 2;
    inend= in + inlen;
    while (in < inend) {
#ifdef BIG_ENDIAN    
        c= *in++;
#else
        tmp = (unsigned char *) in;
	c = *tmp++;
	c = c << 8;
	c = c | (unsigned int) *tmp;
	in++;
#endif	
        if ((c & 0xFC00) == 0xD800) {    /* surrogates */
	    if (in >= inend) {           /* (in > inend) shouldn't happens */
	        (*inlenb) -= 2;
		break;
	    }

#ifdef BIG_ENDIAN
            d= *in++;
#else
            tmp = (unsigned char *) in;
	    d = *tmp++;
	    d = d << 8;
	    d = d | (unsigned int) *tmp;
	    in++;
#endif	    
            if ((d & 0xFC00) == 0xDC00) {
                c &= 0x03FF;
                c <<= 10;
                c |= d & 0x03FF;
                c += 0x10000;
            }
            else 
	        return(-2);
        }

	/* assertion: c is a single UTF-4 value */
        if (out >= outend) 
	    return(-1);
        if      (c <    0x80) {  *out++=  c;                bits= -6; }
        else if (c <   0x800) {  *out++= ((c >>  6) & 0x1F) | 0xC0;  bits=  0; }
        else if (c < 0x10000) {  *out++= ((c >> 12) & 0x0F) | 0xE0;  bits=  6; }
        else                  {  *out++= ((c >> 18) & 0x07) | 0xF0;  bits= 12; }
 
        for ( ; bits >= 0; bits-= 6) {
            if (out >= outend) 
	        return(-1);
            *out++= ((c >> bits) & 0x3F) | 0x80;
        }
    }
    return(out-outstart);
}

/**
 * UTF8ToUTF16BE:
 * @outb:  a pointer to an array of bytes to store the result
 * @outlen:  the length of @outb
 * @in:  a pointer to an array of UTF-8 chars
 * @inlen:  the length of @in
 *
 * Take a block of UTF-8 chars in and try to convert it to an UTF-16BE
 * block of chars out.
 * TODO: UTF8ToUTF16BE need a fallback mechanism ...
 *
 * Returns the number of byte written, or -1 by lack of space, or -2
 *     if the transcoding failed. 
 */
int
UTF8ToUTF16BE(unsigned char* outb, int outlen,
            const unsigned char* in, int *inlen)
{
    unsigned short* out = (unsigned short*) outb;
    unsigned short* outstart= out;
    unsigned short* outend;
    const unsigned char* inend= in+*inlen;
    unsigned int c, d, trailing;
#ifdef BIG_ENDIAN
#else
    unsigned char *tmp;
    unsigned short tmp1, tmp2;
#endif /* BIG_ENDIAN */    

    outlen /= 2; /* convert in short length */
    outend = out + outlen;
    while (in < inend) {
      d= *in++;
      if      (d < 0x80)  { c= d; trailing= 0; }
      else if (d < 0xC0)
          return(-2);    /* trailing byte in leading position */
      else if (d < 0xE0)  { c= d & 0x1F; trailing= 1; }
      else if (d < 0xF0)  { c= d & 0x0F; trailing= 2; }
      else if (d < 0xF8)  { c= d & 0x07; trailing= 3; }
      else
          return(-2);    /* no chance for this in UTF-16 */

      if (inend - in < trailing) {
          *inlen -= (inend - in);
          break;
      } 

      for ( ; trailing; trailing--) {
          if ((in >= inend) || (((d= *in++) & 0xC0) != 0x80))  return(-1);
          c <<= 6;
          c |= d & 0x3F;
      }

      /* assertion: c is a single UTF-4 value */
        if (c < 0x10000) {
            if (out >= outend)  return(-1);
#ifdef BIG_ENDIAN
            *out++ = c;
#else
            tmp = (unsigned char *) out;
            *tmp = c >> 8;
            *(tmp + 1) = c;
            out++;
#endif /* BIG_ENDIAN */
        }
        else if (c < 0x110000) {
            if (out+1 >= outend)  return(-1);
            c -= 0x10000;
#ifdef BIG_ENDIAN
            *out++ = 0xD800 | (c >> 10);
            *out++ = 0xDC00 | (c & 0x03FF);
#else
            tmp1 = 0xD800 | (c >> 10);
            tmp = (unsigned char *) out;
            *tmp = tmp1 >> 8;
            *(tmp + 1) = tmp1;
            out++;

            tmp2 = 0xDC00 | (c & 0x03FF);
            tmp = (unsigned char *) out;
            *tmp = tmp2 >> 8;
            *(tmp + 1) = tmp2;
            out++;
#endif
        }
        else  return(-1);
    }
    return(out-outstart);
}

/**
 * xmlDetectCharEncoding:
 * @in:  a pointer to the first bytes of the XML entity, must be at least
 *       4 bytes long.
 * @len:  pointer to the length of the buffer
 *
 * Guess the encoding of the entity using the first bytes of the entity content
 * accordingly of the non-normative appendix F of the XML-1.0 recommendation.
 * 
 * Returns one of the XML_CHAR_ENCODING_... values.
 */
xmlCharEncoding
xmlDetectCharEncoding(const unsigned char* in, int len)
{
    if (len >= 4) {
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
	if ((in[0] == 0x4C) && (in[1] == 0x6F) &&
	    (in[2] == 0xA7) && (in[3] == 0x94))
	    return(XML_CHAR_ENCODING_EBCDIC);
	if ((in[0] == 0x3C) && (in[1] == 0x3F) &&
	    (in[2] == 0x78) && (in[3] == 0x6D))
	    return(XML_CHAR_ENCODING_UTF8);
    }
    if (len >= 2) {
	if ((in[0] == 0xFE) && (in[1] == 0xFF))
	    return(XML_CHAR_ENCODING_UTF16BE);
	if ((in[0] == 0xFF) && (in[1] == 0xFE))
	    return(XML_CHAR_ENCODING_UTF16LE);
    }
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
xmlNewCharEncodingHandler(const char *name, 
                          xmlCharEncodingInputFunc input,
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
    xmlUTF16LEHandler = 
          xmlNewCharEncodingHandler("UTF-16LE", UTF16LEToUTF8, UTF8ToUTF16LE);
    xmlUTF16BEHandler = 
          xmlNewCharEncodingHandler("UTF-16BE", UTF16BEToUTF8, UTF8ToUTF16BE);
    xmlNewCharEncodingHandler("ISO-8859-1", isolat1ToUTF8, UTF8Toisolat1);
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
    switch (enc) {
        case XML_CHAR_ENCODING_ERROR:
	    return(NULL);
        case XML_CHAR_ENCODING_NONE:
	    return(NULL);
        case XML_CHAR_ENCODING_UTF8:
	    return(NULL);
        case XML_CHAR_ENCODING_UTF16LE:
	    return(xmlUTF16LEHandler);
        case XML_CHAR_ENCODING_UTF16BE:
	    return(xmlUTF16BEHandler);
        case XML_CHAR_ENCODING_EBCDIC:
	    return(NULL);
        case XML_CHAR_ENCODING_UCS4LE:
	    return(NULL);
        case XML_CHAR_ENCODING_UCS4BE:
	    return(NULL);
        case XML_CHAR_ENCODING_UCS4_2143:
	    return(NULL);
        case XML_CHAR_ENCODING_UCS4_3412:
	    return(NULL);
        case XML_CHAR_ENCODING_UCS2:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_1:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_2:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_3:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_4:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_5:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_6:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_7:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_8:
	    return(NULL);
        case XML_CHAR_ENCODING_8859_9:
	    return(NULL);
        case XML_CHAR_ENCODING_2022_JP:
        case XML_CHAR_ENCODING_SHIFT_JIS:
        case XML_CHAR_ENCODING_EUC_JP:
	    return(NULL);
    }
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

