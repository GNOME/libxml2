/**
 * uri.c: set of generic URI related routines 
 *
 * Reference: RFC 2396
 *
 * See Copyright for the status of this software.
 *
 * Daniel.Veillard@w3.org
 */

#ifdef WIN32
#define INCLUDE_WINSOCK
#include "win32config.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/uri.h>

/**
 * alpha    = lowalpha | upalpha
 */
#define IS_ALPHA(x) (IS_LOWALPHA(x) || IS_UPALPHA(x))


/**
 * lowalpha = "a" | "b" | "c" | "d" | "e" | "f" | "g" | "h" | "i" | "j" |
 *            "k" | "l" | "m" | "n" | "o" | "p" | "q" | "r" | "s" | "t" |
 *            "u" | "v" | "w" | "x" | "y" | "z"
 */

#define IS_LOWALPHA(x) (((x) >= 'a') && ((x) <= 'z'))

/**
 * upalpha = "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H" | "I" | "J" |
 *           "K" | "L" | "M" | "N" | "O" | "P" | "Q" | "R" | "S" | "T" |
 *           "U" | "V" | "W" | "X" | "Y" | "Z"
 */
#define IS_UPALPHA(x) (((x) >= 'A') && ((x) <= 'Z'))

/**
 * digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
 */

#define IS_DIGIT(x) (((x) >= '0') && ((x) <= '9'))

/**
 * alphanum = alpha | digit
 */

#define IS_ALPHANUM(x) (IS_ALPHA(x) || IS_DIGIT(x))

/**
 * he(x) = digit | "A" | "B" | "C" | "D" | "E" | "F" |
 *               "a" | "b" | "c" | "d" | "e" | "f"
 */

#define IS_HEX(x) ((IS_DIGIT(x)) || (((x) >= 'a') && ((x) <= 'f')) || \
	    (((x) >= 'A') && ((x) <= 'F')))

/**
 * mark = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
 */

#define IS_MARK(x) (((x) == '-') || ((x) == '_') || ((x) == '.') ||	\
    ((x) == '!') || ((x) == '~') || ((x) == '*') || ((x) == '\'') ||	\
    ((x) == '(') || ((x) == ')'))


/**
 * reserved = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | ","
 */

#define IS_RESERVED(x) (((x) == ';') || ((x) == '/') || ((x) == '?') ||	\
        ((x) == ':') || ((x) == '@') || ((x) == '&') || ((x) == '=') ||	\
	((x) == '+') || ((x) == '$') || ((x) == ','))

/**
 * unreserved = alphanum | mark
 */

#define IS_UNRESERVED(x) (IS_ALPHANUM(x) || IS_MARK(x))

/**
 * escaped = "%" hex hex
 */

#define IS_ESCAPED(p) ((*(p) == '%') && (IS_HEX((p)[1])) &&		\
	    (IS_HEX((p)[2])))

/**
 * uric_no_slash = unreserved | escaped | ";" | "?" | ":" | "@" |
 *                        "&" | "=" | "+" | "$" | ","
 */
#define IS_URIC_NO_SLASH(p) ((IS_UNRESERVED(*(p))) || (IS_ESCAPED(p)) ||\
	        ((*(p) == ';')) || ((*(p) == '?')) || ((*(p) == ':')) ||\
	        ((*(p) == '@')) || ((*(p) == '&')) || ((*(p) == '=')) ||\
	        ((*(p) == '+')) || ((*(p) == '$')) || ((*(p) == ',')))

/**
 * pchar = unreserved | escaped | ":" | "@" | "&" | "=" | "+" | "$" | ","
 */
#define IS_PCHAR(p) ((IS_UNRESERVED(*(p))) || (IS_ESCAPED(p)) ||	\
	        ((*(p) == ':')) || ((*(p) == '@')) || ((*(p) == '&')) ||\
	        ((*(p) == '=')) || ((*(p) == '+')) || ((*(p) == '$')) ||\
	        ((*(p) == ',')))

/**
 * rel_segment   = 1*( unreserved | escaped |
 *                 ";" | "@" | "&" | "=" | "+" | "$" | "," )
 */

#define IS_SEGMENT(p) ((IS_UNRESERVED(*(p))) || (IS_ESCAPED(p)) ||	\
          ((*(p) == ';')) || ((*(p) == '@')) || ((*(p) == '&')) ||	\
	  ((*(p) == '=')) || ((*(p) == '+')) || ((*(p) == '$')) ||	\
	  ((*(p) == ',')))

/**
 * scheme = alpha *( alpha | digit | "+" | "-" | "." )
 */

#define IS_SCHEME(x) ((IS_ALPHA(x)) || (IS_DIGIT(x)) ||			\
	              ((x) == '+') || ((x) == '-') || ((x) == '.'))

/**
 * reg_name = 1*( unreserved | escaped | "$" | "," |
 *                ";" | ":" | "@" | "&" | "=" | "+" )
 */

#define IS_REG_NAME(p) ((IS_UNRESERVED(*(p))) || (IS_ESCAPED(p)) ||	\
       ((*(p) == '$')) || ((*(p) == ',')) || ((*(p) == ';')) ||		\
       ((*(p) == ':')) || ((*(p) == '@')) || ((*(p) == '&')) ||		\
       ((*(p) == '=')) || ((*(p) == '+')))

/**
 * userinfo = *( unreserved | escaped | ";" | ":" | "&" | "=" |
 *                      "+" | "$" | "," )
 */
#define IS_USERINFO(p) ((IS_UNRESERVED(*(p))) || (IS_ESCAPED(p)) ||	\
       ((*(p) == ';')) || ((*(p) == ':')) || ((*(p) == '&')) ||		\
       ((*(p) == '=')) || ((*(p) == '+')) || ((*(p) == '$')) ||		\
       ((*(p) == ',')))

/**
 * uric = reserved | unreserved | escaped
 */

#define IS_URIC(p) ((IS_UNRESERVED(*(p))) || (IS_ESCAPED(p)) ||		\
	            (IS_RESERVED(*(p))))

/**
 * Skip to next pointer char, handle escaped sequences
 */

#define NEXT(p) ((*p == '%')? p += 3 : p++)

/**
 * Productions from the spec.
 *
 *    authority     = server | reg_name
 *    reg_name      = 1*( unreserved | escaped | "$" | "," |
 *                        ";" | ":" | "@" | "&" | "=" | "+" )
 *
 * path          = [ abs_path | opaque_part ]
 */

/**
 * xmlCreateURI:
 *
 * Simply creates an empty xmlURI
 *
 * Returns the new structure or NULL in case of error
 */
xmlURIPtr
xmlCreateURI(void) {
    xmlURIPtr ret;

    ret = (xmlURIPtr) xmlMalloc(sizeof(xmlURI));
    if (ret == NULL) {
	fprintf(stderr, "xmlCreateURI: out of memory\n");
	return(NULL);
    }
    memset(ret, 0, sizeof(xmlURI));
    return(ret);
}

/**
 * xmlSaveUri:
 * @uri:  pointer to an xmlURI
 *
 * Save the URI as an escaped string
 *
 * Returns a new string (to be deallocated by caller)
 */
xmlChar *
xmlSaveUri(xmlURIPtr uri) {
    xmlChar *ret = NULL;
    const char *p;
    int len;
    int max;

    if (uri == NULL) return(NULL);


    max = 80;
    ret = xmlMalloc((max + 1) * sizeof(xmlChar));
    if (ret == NULL) {
	fprintf(stderr, "xmlSaveUri: out of memory\n");
	return(NULL);
    }
    len = 0;

    if (uri->scheme != NULL) {
	p = uri->scheme;
	while (*p != 0) {
	    if (len >= max) {
		max *= 2;
		ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		if (ret == NULL) {
		    fprintf(stderr, "xmlSaveUri: out of memory\n");
		    return(NULL);
		}
	    }
	    ret[len++] = *p++;
	}
	if (len >= max) {
	    max *= 2;
	    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
	    if (ret == NULL) {
		fprintf(stderr, "xmlSaveUri: out of memory\n");
		return(NULL);
	    }
	}
	ret[len++] = ':';
    }
    if (uri->opaque != NULL) {
	p = uri->opaque;
	while (*p != 0) {
	    if (len + 3 >= max) {
		max *= 2;
		ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		if (ret == NULL) {
		    fprintf(stderr, "xmlSaveUri: out of memory\n");
		    return(NULL);
		}
	    }
	    if ((IS_UNRESERVED(*(p))) ||
	        ((*(p) == ';')) || ((*(p) == '?')) || ((*(p) == ':')) ||
	        ((*(p) == '@')) || ((*(p) == '&')) || ((*(p) == '=')) ||
	        ((*(p) == '+')) || ((*(p) == '$')) || ((*(p) == ',')))
		ret[len++] = *p++;
	    else {
		int val = *p++;
		ret[len++] = '%';
		switch (val / 0x10) {
		    case 0xF: ret[len++] = 'F'; break;
		    case 0xE: ret[len++] = 'E'; break;
		    case 0xD: ret[len++] = 'D'; break;
		    case 0xC: ret[len++] = 'C'; break;
		    case 0xB: ret[len++] = 'B'; break;
		    case 0xA: ret[len++] = 'A'; break;
		    default: ret[len++] = '0' + (val / 0x10);
		}
		switch (val % 0x10) {
		    case 0xF: ret[len++] = 'F'; break;
		    case 0xE: ret[len++] = 'E'; break;
		    case 0xD: ret[len++] = 'D'; break;
		    case 0xC: ret[len++] = 'C'; break;
		    case 0xB: ret[len++] = 'B'; break;
		    case 0xA: ret[len++] = 'A'; break;
		    default: ret[len++] = '0' + (val % 0x10);
		}
	    }
	}
	if (len >= max) {
	    max *= 2;
	    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
	    if (ret == NULL) {
		fprintf(stderr, "xmlSaveUri: out of memory\n");
		return(NULL);
	    }
	}
	ret[len++] = 0;
    } else {
	if (uri->server != NULL) {
	    if (len + 3 >= max) {
		max *= 2;
		ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		if (ret == NULL) {
		    fprintf(stderr, "xmlSaveUri: out of memory\n");
		    return(NULL);
		}
	    }
	    ret[len++] = '/';
	    ret[len++] = '/';
	    if (uri->user != NULL) {
		p = uri->user;
		while (*p != 0) {
		    if (len + 3 >= max) {
			max *= 2;
			ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
			if (ret == NULL) {
			    fprintf(stderr, "xmlSaveUri: out of memory\n");
			    return(NULL);
			}
		    }
		    if ((IS_UNRESERVED(*(p))) ||
			((*(p) == ';')) || ((*(p) == ':')) || ((*(p) == '&')) ||
			((*(p) == '=')) || ((*(p) == '+')) || ((*(p) == '$')) ||
			((*(p) == ',')))
			ret[len++] = *p++;
		    else {
			int val = *p++;
			ret[len++] = '%';
			switch (val / 0x10) {
			    case 0xF: ret[len++] = 'F'; break;
			    case 0xE: ret[len++] = 'E'; break;
			    case 0xD: ret[len++] = 'D'; break;
			    case 0xC: ret[len++] = 'C'; break;
			    case 0xB: ret[len++] = 'B'; break;
			    case 0xA: ret[len++] = 'A'; break;
			    default: ret[len++] = '0' + (val / 0x10);
			}
			switch (val % 0x10) {
			    case 0xF: ret[len++] = 'F'; break;
			    case 0xE: ret[len++] = 'E'; break;
			    case 0xD: ret[len++] = 'D'; break;
			    case 0xC: ret[len++] = 'C'; break;
			    case 0xB: ret[len++] = 'B'; break;
			    case 0xA: ret[len++] = 'A'; break;
			    default: ret[len++] = '0' + (val % 0x10);
			}
		    }
		}
		if (len + 3 >= max) {
		    max *= 2;
		    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		    if (ret == NULL) {
			fprintf(stderr, "xmlSaveUri: out of memory\n");
			return(NULL);
		    }
		}
		ret[len++] = '@';
	    }
	    p = uri->server;
	    while (*p != 0) {
		if (len >= max) {
		    max *= 2;
		    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		    if (ret == NULL) {
			fprintf(stderr, "xmlSaveUri: out of memory\n");
			return(NULL);
		    }
		}
		ret[len++] = *p++;
	    }
	    if (uri->port > 0) {
		if (len + 10 >= max) {
		    max *= 2;
		    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		    if (ret == NULL) {
			fprintf(stderr, "xmlSaveUri: out of memory\n");
			return(NULL);
		    }
		}
		len += sprintf((char *) &ret[len], ":%d", uri->port);
	    }
	} else if (uri->authority != NULL) {
	    if (len + 3 >= max) {
		max *= 2;
		ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		if (ret == NULL) {
		    fprintf(stderr, "xmlSaveUri: out of memory\n");
		    return(NULL);
		}
	    }
	    ret[len++] = '/';
	    ret[len++] = '/';
	    p = uri->authority;
	    while (*p != 0) {
		if (len + 3 >= max) {
		    max *= 2;
		    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		    if (ret == NULL) {
			fprintf(stderr, "xmlSaveUri: out of memory\n");
			return(NULL);
		    }
		}
		if ((IS_UNRESERVED(*(p))) ||
                    ((*(p) == '$')) || ((*(p) == ',')) || ((*(p) == ';')) ||
                    ((*(p) == ':')) || ((*(p) == '@')) || ((*(p) == '&')) ||
                    ((*(p) == '=')) || ((*(p) == '+')))
		    ret[len++] = *p++;
		else {
		    int val = *p++;
		    ret[len++] = '%';
		    switch (val / 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val / 0x10);
		    }
		    switch (val % 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val % 0x10);
		    }
		}
	    }
	}
	if (uri->path != NULL) {
	    p = uri->path;
	    while (*p != 0) {
		if (len + 3 >= max) {
		    max *= 2;
		    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		    if (ret == NULL) {
			fprintf(stderr, "xmlSaveUri: out of memory\n");
			return(NULL);
		    }
		}
		if ((IS_UNRESERVED(*(p))) || ((*(p) == '/')) ||
                    ((*(p) == ';')) || ((*(p) == '@')) || ((*(p) == '&')) ||
	            ((*(p) == '=')) || ((*(p) == '+')) || ((*(p) == '$')) ||
	            ((*(p) == ',')))
		    ret[len++] = *p++;
		else {
		    int val = *p++;
		    ret[len++] = '%';
		    switch (val / 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val / 0x10);
		    }
		    switch (val % 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val % 0x10);
		    }
		}
	    }
	}
	if (uri->query != NULL) {
	    if (len + 3 >= max) {
		max *= 2;
		ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		if (ret == NULL) {
		    fprintf(stderr, "xmlSaveUri: out of memory\n");
		    return(NULL);
		}
	    }
	    ret[len++] = '?';
	    p = uri->query;
	    while (*p != 0) {
		if (len + 3 >= max) {
		    max *= 2;
		    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		    if (ret == NULL) {
			fprintf(stderr, "xmlSaveUri: out of memory\n");
			return(NULL);
		    }
		}
		if ((IS_UNRESERVED(*(p))) || (IS_RESERVED(*(p)))) 
		    ret[len++] = *p++;
		else {
		    int val = *p++;
		    ret[len++] = '%';
		    switch (val / 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val / 0x10);
		    }
		    switch (val % 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val % 0x10);
		    }
		}
	    }
	}
	if (uri->fragment != NULL) {
	    if (len + 3 >= max) {
		max *= 2;
		ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		if (ret == NULL) {
		    fprintf(stderr, "xmlSaveUri: out of memory\n");
		    return(NULL);
		}
	    }
	    ret[len++] = '#';
	    p = uri->fragment;
	    while (*p != 0) {
		if (len + 3 >= max) {
		    max *= 2;
		    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
		    if (ret == NULL) {
			fprintf(stderr, "xmlSaveUri: out of memory\n");
			return(NULL);
		    }
		}
		if ((IS_UNRESERVED(*(p))) || (IS_RESERVED(*(p)))) 
		    ret[len++] = *p++;
		else {
		    int val = *p++;
		    ret[len++] = '%';
		    switch (val / 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val / 0x10);
		    }
		    switch (val % 0x10) {
			case 0xF: ret[len++] = 'F'; break;
			case 0xE: ret[len++] = 'E'; break;
			case 0xD: ret[len++] = 'D'; break;
			case 0xC: ret[len++] = 'C'; break;
			case 0xB: ret[len++] = 'B'; break;
			case 0xA: ret[len++] = 'A'; break;
			default: ret[len++] = '0' + (val % 0x10);
		    }
		}
	    }
	}
	if (len >= max) {
	    max *= 2;
	    ret = xmlRealloc(ret, (max + 1) * sizeof(xmlChar));
	    if (ret == NULL) {
		fprintf(stderr, "xmlSaveUri: out of memory\n");
		return(NULL);
	    }
	}
	ret[len++] = 0;
    }
    return(ret);
}

/**
 * xmlPrintURI:
 * @stream:  a FILE* for the output
 * @uri:  pointer to an xmlURI
 *
 * Prints the URI in the stream @steam.
 */
void
xmlPrintURI(FILE *stream, xmlURIPtr uri) {
    xmlChar *out;

    out = xmlSaveUri(uri);
    if (out != NULL) {
	fprintf(stream, "%s", out);
	xmlFree(out);
    }
}

/**
 * xmlCleanURI:
 * @uri:  pointer to an xmlURI
 *
 * Make sure the xmlURI struct is free of content
 */
void
xmlCleanURI(xmlURIPtr uri) {
    if (uri == NULL) return;

    if (uri->scheme != NULL) xmlFree(uri->scheme);
    uri->scheme = NULL;
    if (uri->server != NULL) xmlFree(uri->server);
    uri->server = NULL;
    if (uri->user != NULL) xmlFree(uri->user);
    uri->user = NULL;
    if (uri->path != NULL) xmlFree(uri->path);
    uri->path = NULL;
    if (uri->fragment != NULL) xmlFree(uri->fragment);
    uri->fragment = NULL;
    if (uri->opaque != NULL) xmlFree(uri->opaque);
    uri->opaque = NULL;
    if (uri->authority != NULL) xmlFree(uri->authority);
    uri->authority = NULL;
    if (uri->query != NULL) xmlFree(uri->query);
    uri->query = NULL;
}

/**
 * xmlFreeURI:
 * @uri:  pointer to an xmlURI
 *
 * Free up the xmlURI struct
 */
void
xmlFreeURI(xmlURIPtr uri) {
    if (uri == NULL) return;

    if (uri->scheme != NULL) xmlFree(uri->scheme);
    if (uri->server != NULL) xmlFree(uri->server);
    if (uri->user != NULL) xmlFree(uri->user);
    if (uri->path != NULL) xmlFree(uri->path);
    if (uri->fragment != NULL) xmlFree(uri->fragment);
    if (uri->opaque != NULL) xmlFree(uri->opaque);
    if (uri->authority != NULL) xmlFree(uri->authority);
    if (uri->query != NULL) xmlFree(uri->query);
    memset(uri, -1, sizeof(xmlURI));
    xmlFree(uri);
}

/**
 * xmlURIUnescapeString:
 * @str:  the string to unescape
 * @len:   the lenght in bytes to unescape (or <= 0 to indicate full string)
 * @target:  optionnal destination buffer
 *
 * Unescaping routine, does not do validity checks !
 * Output is direct unsigned char translation of %XX values (no encoding)
 *
 * Returns an copy of the string, but unescaped
 */
char *
xmlURIUnescapeString(const char *str, int len, char *target) {
    char *ret, *out;
    const char *in;

    if (str == NULL)
	return(NULL);
    if (len <= 0) len = strlen(str);
    if (len <= 0) return(NULL);

    if (target == NULL) {
	ret = (char *) xmlMalloc(len + 1);
	if (ret == NULL) {
	    fprintf(stderr, "xmlURIUnescapeString: out of memory\n");
	    return(NULL);
	}
    } else
	ret = target;
    in = str;
    out = ret;
    while(len > 0) {
	if (*in == '%') {
	    in++;
	    if ((*in >= '0') && (*in <= '9')) 
	        *out = (*in - '0');
	    else if ((*in >= 'a') && (*in <= 'f'))
	        *out = (*in - 'a') + 10;
	    else if ((*in >= 'A') && (*in <= 'F'))
	        *out = (*in - 'A') + 10;
	    in++;
	    if ((*in >= '0') && (*in <= '9')) 
	        *out = *out * 16 + (*in - '0');
	    else if ((*in >= 'a') && (*in <= 'f'))
	        *out = *out * 16 + (*in - 'a') + 10;
	    else if ((*in >= 'A') && (*in <= 'F'))
	        *out = *out * 16 + (*in - 'A') + 10;
	    in++;
	    len -= 3;
	    out++;
	} else {
	    *out++ = *in++;
	    len--;
	}
    }
    *out = 0;
    return(ret);
}


/**
 * xmlParseURIFragment:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse an URI fragment string and fills in the appropriate fields
 * of the @uri structure.
 * 
 * fragment = *uric
 *
 * Returns 0 or the error code
 */
int
xmlParseURIFragment(xmlURIPtr uri, const char **str) {
    const char *cur = *str;

    if (str == NULL) return(-1);

    while (IS_URIC(cur)) NEXT(cur);
    if (uri != NULL) {
	if (uri->fragment != NULL) xmlFree(uri->fragment);
	uri->fragment = xmlURIUnescapeString(*str, cur - *str, NULL);
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseURIQuery:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse the query part of an URI
 * 
 * query = *uric
 *
 * Returns 0 or the error code
 */
int
xmlParseURIQuery(xmlURIPtr uri, const char **str) {
    const char *cur = *str;

    if (str == NULL) return(-1);

    while (IS_URIC(cur)) NEXT(cur);
    if (uri != NULL) {
	if (uri->query != NULL) xmlFree(uri->query);
	uri->query = xmlURIUnescapeString(*str, cur - *str, NULL);
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseURIScheme:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse an URI scheme
 * 
 * scheme = alpha *( alpha | digit | "+" | "-" | "." )
 *
 * Returns 0 or the error code
 */
int
xmlParseURIScheme(xmlURIPtr uri, const char **str) {
    const char *cur;

    if (str == NULL)
	return(-1);
    
    cur = *str;
    if (!IS_ALPHA(*cur))
	return(2);
    cur++;
    while (IS_SCHEME(*cur)) cur++;
    if (uri != NULL) {
	if (uri->scheme != NULL) xmlFree(uri->scheme);
	uri->scheme = xmlURIUnescapeString(*str, cur - *str, NULL); /* !!! strndup */
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseURIOpaquePart:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse an URI opaque part
 * 
 * opaque_part = uric_no_slash *uric
 *
 * Returns 0 or the error code
 */
int
xmlParseURIOpaquePart(xmlURIPtr uri, const char **str) {
    const char *cur;

    if (str == NULL)
	return(-1);
    
    cur = *str;
    if (!IS_URIC_NO_SLASH(cur)) {
	return(3);
    }
    NEXT(cur);
    while (IS_URIC(cur)) NEXT(cur);
    if (uri != NULL) {
	if (uri->opaque != NULL) xmlFree(uri->opaque);
	uri->opaque = xmlURIUnescapeString(*str, cur - *str, NULL);
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseURIServer:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse a server subpart of an URI, it's a finer grain analysis
 * of the authority part.
 * 
 * server        = [ [ userinfo "@" ] hostport ]
 * userinfo      = *( unreserved | escaped |
 *                       ";" | ":" | "&" | "=" | "+" | "$" | "," )
 * hostport      = host [ ":" port ]
 * host          = hostname | IPv4address
 * hostname      = *( domainlabel "." ) toplabel [ "." ]
 * domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
 * toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
 * IPv4address   = 1*digit "." 1*digit "." 1*digit "." 1*digit
 * port          = *digit
 *
 * Returns 0 or the error code
 */
int
xmlParseURIServer(xmlURIPtr uri, const char **str) {
    const char *cur;
    const char *host, *tmp;

    if (str == NULL)
	return(-1);
    
    cur = *str;

    /*
     * is there an userinfo ?
     */
    while (IS_USERINFO(cur)) NEXT(cur);
    if (*cur == '@') {
	if (uri != NULL) {
	    if (uri->user != NULL) xmlFree(uri->user);
	    uri->user = xmlURIUnescapeString(*str, cur - *str, NULL);
	}
	cur++;
    } else {
	if (uri != NULL) {
	    if (uri->user != NULL) xmlFree(uri->user);
	    uri->user = NULL;
	}
        cur = *str;
    }
    /*
     * host part of hostport can derive either an IPV4 address
     * or an unresolved name. Check the IP first, it easier to detect
     * errors if wrong one
     */
    host = cur;
    if (IS_DIGIT(*cur)) {
        while(IS_DIGIT(*cur)) cur++;
	if (*cur != '.')
	    goto host_name;
	cur++;
	if (!IS_DIGIT(*cur))
	    goto host_name;
        while(IS_DIGIT(*cur)) cur++;
	if (*cur != '.')
	    goto host_name;
	cur++;
	if (!IS_DIGIT(*cur))
	    goto host_name;
        while(IS_DIGIT(*cur)) cur++;
	if (*cur != '.')
	    goto host_name;
	cur++;
	if (!IS_DIGIT(*cur))
	    goto host_name;
        while(IS_DIGIT(*cur)) cur++;
	if (uri != NULL) {
	    if (uri->authority != NULL) xmlFree(uri->authority);
	    uri->authority = NULL;
	    if (uri->server != NULL) xmlFree(uri->server);
	    uri->server = xmlURIUnescapeString(host, cur - host, NULL);
	}
	goto host_done;
    }
host_name:
    /*
     * the hostname production as-is is a parser nightmare.
     * simplify it to 
     * hostname = *( domainlabel "." ) domainlabel [ "." ]
     * and just make sure the last label starts with a non numeric char.
     */
    if (!IS_ALPHANUM(*cur))
        return(6);
    while (IS_ALPHANUM(*cur)) {
        while ((IS_ALPHANUM(*cur)) || (*cur == '-')) cur++;
	if (*cur == '.')
	    cur++;
    }
    tmp = cur;
    tmp--;
    while (IS_ALPHANUM(*tmp) && (*tmp != '.') && (tmp >= host)) tmp--;
    tmp++;
    if (!IS_ALPHA(*tmp))
        return(7);
    if (uri != NULL) {
	if (uri->authority != NULL) xmlFree(uri->authority);
	uri->authority = NULL;
	if (uri->server != NULL) xmlFree(uri->server);
	uri->server = xmlURIUnescapeString(host, cur - host, NULL);
    }

host_done:

    /*
     * finish by checking for a port presence.
     */
    if (*cur == ':') {
        cur++;
	if (IS_DIGIT(*cur)) {
	    if (uri != NULL)
	        uri->port = 0;
	    while (IS_DIGIT(*cur)) {
	        if (uri != NULL)
		    uri->port = uri->port * 10 + (*cur - '0');
		cur++;
	    }
	}
    }
    *str = cur;
    return(0);
}	

/**
 * xmlParseURIRelSegment:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse an URI relative segment
 * 
 * rel_segment = 1*( unreserved | escaped | ";" | "@" | "&" | "=" |
 *                          "+" | "$" | "," )
 *
 * Returns 0 or the error code
 */
int
xmlParseURIRelSegment(xmlURIPtr uri, const char **str) {
    const char *cur;

    if (str == NULL)
	return(-1);
    
    cur = *str;
    if (!IS_SEGMENT(cur)) {
	return(3);
    }
    NEXT(cur);
    while (IS_SEGMENT(cur)) NEXT(cur);
    if (uri != NULL) {
	if (uri->path != NULL) xmlFree(uri->path);
	uri->path = xmlURIUnescapeString(*str, cur - *str, NULL);
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseURIPathSegments:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 * @slash:  should we add a leading slash
 *
 * Parse an URI set of path segments
 * 
 * path_segments = segment *( "/" segment )
 * segment       = *pchar *( ";" param )
 * param         = *pchar
 *
 * Returns 0 or the error code
 */
int
xmlParseURIPathSegments(xmlURIPtr uri, const char **str, int slash) {
    const char *cur;

    if (str == NULL)
	return(-1);
    
    cur = *str;

    do {
	while (IS_PCHAR(cur)) NEXT(cur);
	if (*cur == ';') {
	    cur++;
	    while (IS_PCHAR(cur)) NEXT(cur);
	}
	if (*cur != '/') break;
	cur++;
    } while (1);
    if (uri != NULL) {
	int len, len2 = 0;
	char *path;

	/*
	 * Concat the set of path segments to the current path
	 */
	len = cur - *str;
	if (slash)
	    len++;

	if (uri->path != NULL) {
	    len2 = strlen(uri->path);
	    len += len2;
	}
        path = (char *) xmlMalloc(len + 1);
	if (path == NULL) {
	    fprintf(stderr, "xmlParseURIPathSegments: out of memory\n");
	    *str = cur;
	    return(-1);
	}
	if (uri->path != NULL)
	    memcpy(path, uri->path, len2);
	if (slash) {
	    path[len2] = '/';
	    len2++;
	}
	xmlURIUnescapeString(*str, cur - *str, &path[len2]);
	if (uri->path != NULL)
	    xmlFree(uri->path);
	uri->path = path;
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseURIAuthority:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse the authority part of an URI.
 * 
 * authority = server | reg_name
 * server    = [ [ userinfo "@" ] hostport ]
 * reg_name  = 1*( unreserved | escaped | "$" | "," | ";" | ":" |
 *                        "@" | "&" | "=" | "+" )
 *
 * Note : this is completely ambiguous since reg_name is allowed to
 *        use the full set of chars in use by server:
 *
 *        3.2.1. Registry-based Naming Authority
 *
 *        The structure of a registry-based naming authority is specific
 *        to the URI scheme, but constrained to the allowed characters
 *        for an authority component.
 *
 * Returns 0 or the error code
 */
int
xmlParseURIAuthority(xmlURIPtr uri, const char **str) {
    const char *cur;
    int ret;

    if (str == NULL)
	return(-1);
    
    cur = *str;

    /*
     * try first to parse it as a server string.
     */
    ret = xmlParseURIServer(uri, str);
    if (ret == 0)
        return(0);

    /*
     * failed, fallback to reg_name
     */
    if (!IS_REG_NAME(cur)) {
	return(5);
    }
    NEXT(cur);
    while (IS_REG_NAME(cur)) NEXT(cur);
    if (uri != NULL) {
	if (uri->server != NULL) xmlFree(uri->server);
	uri->server = NULL;
	if (uri->user != NULL) xmlFree(uri->user);
	uri->user = NULL;
	if (uri->authority != NULL) xmlFree(uri->authority);
	uri->authority = xmlURIUnescapeString(*str, cur - *str, NULL);
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseURIHierPart:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse an URI hirarchical part
 * 
 * hier_part = ( net_path | abs_path ) [ "?" query ]
 * abs_path = "/"  path_segments
 * net_path = "//" authority [ abs_path ]
 *
 * Returns 0 or the error code
 */
int
xmlParseURIHierPart(xmlURIPtr uri, const char **str) {
    int ret;
    const char *cur;

    if (str == NULL)
	return(-1);
    
    cur = *str;

    if ((cur[0] == '/') && (cur[1] == '/')) {
	cur += 2;
	ret = xmlParseURIAuthority(uri, &cur);
	if (ret != 0)
	    return(ret);
	if (cur[0] == '/') {
	    cur++;
	    ret = xmlParseURIPathSegments(uri, &cur, 1);
	}
    } else if (cur[0] == '/') {
	cur++;
	ret = xmlParseURIPathSegments(uri, &cur, 1);
    } else {
	return(4);
    }
    if (ret != 0)
	return(ret);
    if (*cur == '?') {
	cur++;
	ret = xmlParseURIQuery(uri, &cur);
	if (ret != 0)
	    return(ret);
    }
    *str = cur;
    return(0);
}

/**
 * xmlParseAbsoluteURI:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse an URI reference string and fills in the appropriate fields
 * of the @uri structure
 * 
 * absoluteURI   = scheme ":" ( hier_part | opaque_part )
 *
 * Returns 0 or the error code
 */
int
xmlParseAbsoluteURI(xmlURIPtr uri, const char **str) {
    int ret;

    if (str == NULL)
	return(-1);
    
    ret = xmlParseURIScheme(uri, str);
    if (ret != 0) return(ret);
    if (**str != ':')
	return(1);
    (*str)++;
    if (**str == '/')
	return(xmlParseURIHierPart(uri, str));
    return(xmlParseURIOpaquePart(uri, str));
}

/**
 * xmlParseRelativeURI:
 * @uri:  pointer to an URI structure
 * @str:  pointer to the string to analyze
 *
 * Parse an relative URI string and fills in the appropriate fields
 * of the @uri structure
 * 
 * relativeURI = ( net_path | abs_path | rel_path ) [ "?" query ]
 * abs_path = "/"  path_segments
 * net_path = "//" authority [ abs_path ]
 * rel_path = rel_segment [ abs_path ]
 *
 * Returns 0 or the error code
 */
int
xmlParseRelativeURI(xmlURIPtr uri, const char **str) {
    int ret = 0;
    const char *cur;

    if (str == NULL)
	return(-1);
    
    cur = *str;
    if ((cur[0] == '/') && (cur[1] == '/')) {
	cur += 2;
	ret = xmlParseURIAuthority(uri, &cur);
	if (ret != 0)
	    return(ret);
	if (cur[0] == '/') {
	    cur++;
	    ret = xmlParseURIPathSegments(uri, &cur, 1);
	}
    } else if (cur[0] == '/') {
	cur++;
	ret = xmlParseURIPathSegments(uri, &cur, 1);
    } else {
	ret = xmlParseURIRelSegment(uri, &cur);
	if (ret != 0)
	    return(ret);
	if (cur[0] == '/') {
	    cur++;
	    ret = xmlParseURIPathSegments(uri, &cur, 1);
	}
    }
    if (ret != 0)
	return(ret);
    if (*cur == '?') {
	cur++;
	ret = xmlParseURIQuery(uri, &cur);
	if (ret != 0)
	    return(ret);
    }
    *str = cur;
    return(ret);
}

/**
 * xmlParseURIReference:
 * @uri:  pointer to an URI structure
 * @str:  the string to analyze
 *
 * Parse an URI reference string and fills in the appropriate fields
 * of the @uri structure
 * 
 * URI-reference = [ absoluteURI | relativeURI ] [ "#" fragment ]
 *
 * Returns 0 or the error code
 */
int
xmlParseURIReference(xmlURIPtr uri, const char *str) {
    int ret;
    const char *tmp = str;

    if (str == NULL)
	return(-1);
    xmlCleanURI(uri);

    /*
     * Try first to parse aboslute refs, then fallback to relative if
     * it fails.
     */
    ret = xmlParseAbsoluteURI(uri, &str);
    if (ret != 0) {
	xmlCleanURI(uri);
	str = tmp;
        ret = xmlParseRelativeURI(uri, &str);
    }
    if (ret != 0) {
	xmlCleanURI(uri);
	return(ret);
    }

    if (*str == '#') {
	str++;
	ret = xmlParseURIFragment(uri, &str);
	if (ret != 0) return(ret);
    }
    if (*str != 0) {
	xmlCleanURI(uri);
	return(1);
    }
    return(0);
}

/**
 * xmlNormalizeURIPath:
 * @path:  pointer to the path string
 *
 * applies the 5 normalization steps to a path string
 * Normalization occurs directly on the string, no new allocation is done
 *
 * Returns 0 or an error code
 */
int
xmlNormalizeURIPath(char *path) {
    int cur, out;

    if (path == NULL)
	return(-1);
    cur = 0;
    out = 0;
    while ((path[cur] != 0) && (path[cur] != '/')) cur++;
    if (path[cur] == 0)
	return(0);

    /* we are positionned at the beginning of the first segment */
    cur++;
    out = cur;

    /*
     * Analyze each segment in sequence.
     */
    while (path[cur] != 0) {
	/*
	 * c) All occurrences of "./", where "." is a complete path segment,
	 *    are removed from the buffer string.
	 */
	if ((path[cur] == '.') && (path[cur + 1] == '/')) {
	    cur += 2;
	    continue;
	}

	/*
	 * d) If the buffer string ends with "." as a complete path segment,
	 *    that "." is removed.
	 */
	if ((path[cur] == '.') && (path[cur + 1] == 0)) {
	    path[out] = 0;
	    break;
	}

	/* read the segment */
	while ((path[cur] != 0) && (path[cur] != '/')) {
	    path[out++] = path[cur++];
	}
	path[out++] = path[cur];
	if (path[cur] != 0) {
	    cur++;
	}
    }

    cur = 0;
    out = 0;
    while ((path[cur] != 0) && (path[cur] != '/')) cur++;
    if (path[cur] == 0)
	return(0);
    /* we are positionned at the beginning of the first segment */
    cur++;
    out = cur;
    /*
     * Analyze each segment in sequence.
     */
    while (path[cur] != 0) {
	/*
	 * e) All occurrences of "<segment>/../", where <segment> is a
	 *    complete path segment not equal to "..", are removed from the
	 *    buffer string.  Removal of these path segments is performed
	 *    iteratively, removing the leftmost matching pattern on each
	 *    iteration, until no matching pattern remains.
	 */
	if ((cur > 1) && (out > 1) &&
	    (path[cur] == '/') && (path[cur + 1] == '.') &&
	    (path[cur + 2] == '.') && (path[cur + 3] == '/') &&
	    ((path[out] != '.') || (path[out - 1] != '.') ||
	     (path[out - 2] != '/'))) {
	    cur += 3;
	    out --;
	    while ((out > 0) && (path[out] != '/')) { out --; }
	    path[out] = 0;
            continue;
	}

	/*
	 * f) If the buffer string ends with "<segment>/..", where <segment>
	 *    is a complete path segment not equal to "..", that
	 *    "<segment>/.." is removed.
	 */
	if ((path[cur] == '/') && (path[cur + 1] == '.') &&
	    (path[cur + 2] == '.') && (path[cur + 3] == 0) &&
	    ((path[out] != '.') || (path[out - 1] != '.') ||
	     (path[out - 2] != '/'))) {
	    cur += 4;
	    out --;
	    while ((out > 0) && (path[out - 1] != '/')) { out --; }
	    path[out] = 0;
            continue;
	}
        
	path[out++] = path[cur++]; /* / or 0 */
    }
    path[out] = 0;

    /*
     * g) If the resulting buffer string still begins with one or more
     *    complete path segments of "..", then the reference is 
     *    considered to be in error. Implementations may handle this
     *    error by retaining these components in the resolved path (i.e.,
     *    treating them as part of the final URI), by removing them from
     *    the resolved path (i.e., discarding relative levels above the
     *    root), or by avoiding traversal of the reference.
     *
     * We discard them from the final path.
     */
    cur = 0;
    while ((path[cur] == '/') && (path[cur + 1] == '.') &&
	   (path[cur + 2] == '.'))
	cur += 3;
    if (cur != 0) {
	out = 0;
	while (path[cur] != 0) path[out++] = path[cur++];
	path[out] = 0;
    }
    return(0);
}

/**
 * xmlBuildURI:
 * @URI:  the URI instance found in the document
 * @base:  the base value
 *
 * Computes he final URI of the reference done by checking that
 * the given URI is valid, and building the final URI using the
 * base URI. This is processed according to section 5.2 of the 
 * RFC 2396
 *
 * 5.2. Resolving Relative References to Absolute Form
 *
 * Returns a new URI string (to be freed by the caller) or NULL in case
 *         of error.
 */
xmlChar *
xmlBuildURI(const xmlChar *URI, const xmlChar *base) {
    xmlChar *val = NULL;
    int ret, len, index, cur, out;
    xmlURIPtr ref = NULL;
    xmlURIPtr bas = NULL;
    xmlURIPtr res = NULL;


    /*
     * 1) The URI reference is parsed into the potential four components and
     *    fragment identifier, as described in Section 4.3.
     */
    ref = xmlCreateURI();
    if (ref == NULL)
	goto done;
    ret = xmlParseURIReference(ref, (const char *) URI);
    if (ret != 0)
	goto done;
    bas = xmlCreateURI();
    if (bas == NULL)
	goto done;
    ret = xmlParseURIReference(bas, (const char *) base);
    if (ret != 0)
	goto done;

    /*
     * 2) If the path component is empty and the scheme, authority, and
     *    query components are undefined, then it is a reference to the
     *    current document and we are done.  Otherwise, the reference URI's
     *    query and fragment components are defined as found (or not found)
     *    within the URI reference and not inherited from the base URI.
     */
    res = xmlCreateURI();
    if (res == NULL)
	goto done;
    if ((ref->scheme == NULL) && (ref->path == NULL) &&
	((ref->authority == NULL) && (ref->server == NULL)) &&
	(ref->query == NULL)) {
	if (ref->fragment == NULL)
	    goto done;
        res->fragment = xmlMemStrdup(ref->fragment);
	val = xmlSaveUri(res);
	goto done;
    }

    /*
     * 3) If the scheme component is defined, indicating that the reference
     *    starts with a scheme name, then the reference is interpreted as an
     *    absolute URI and we are done.  Otherwise, the reference URI's
     *    scheme is inherited from the base URI's scheme component.
     */
    if (ref->scheme != NULL) {
	val = xmlSaveUri(ref);
	goto done;
    }
    res->scheme = xmlMemStrdup(bas->scheme);

    /*
     * 4) If the authority component is defined, then the reference is a
     *    network-path and we skip to step 7.  Otherwise, the reference
     *    URI's authority is inherited from the base URI's authority
     *    component, which will also be undefined if the URI scheme does not
     *    use an authority component.
     */
    if ((ref->authority != NULL) || (ref->server != NULL)) {
	if (ref->authority != NULL)
	    res->authority = xmlMemStrdup(ref->authority);
	else {
	    res->server = xmlMemStrdup(ref->server);
	    if (ref->user != NULL)
		res->user = xmlMemStrdup(ref->user);
            res->port = ref->port;		
	}
	if (ref->path != NULL)
	    res->path = xmlMemStrdup(ref->path);
	if (ref->query != NULL)
	    res->query = xmlMemStrdup(ref->query);
	if (ref->fragment != NULL)
	    res->fragment = xmlMemStrdup(ref->fragment);
	goto step_7;
    }
    if (bas->authority != NULL)
	res->authority = xmlMemStrdup(bas->authority);
    else if (bas->server != NULL) {
	res->server = xmlMemStrdup(bas->server);
	if (bas->user != NULL)
	    res->user = xmlMemStrdup(bas->user);
	res->port = bas->port;		
    }

    /*
     * 5) If the path component begins with a slash character ("/"), then
     *    the reference is an absolute-path and we skip to step 7.
     */
    if ((ref->path != NULL) && (ref->path[0] == '/')) {
	res->path = xmlMemStrdup(ref->path);
	if (ref->query != NULL)
	    res->query = xmlMemStrdup(ref->query);
	if (ref->fragment != NULL)
	    res->fragment = xmlMemStrdup(ref->fragment);
	goto step_7;
    }


    /*
     * 6) If this step is reached, then we are resolving a relative-path
     *    reference.  The relative path needs to be merged with the base
     *    URI's path.  Although there are many ways to do this, we will
     *    describe a simple method using a separate string buffer.
     *
     * Allocate a buffer large enough for the result string.
     */
    len = 2; /* extra / and 0 */
    if (ref->path != NULL)
	len += strlen(ref->path);
    if (bas->path != NULL)
	len += strlen(bas->path);
    res->path = (char *) xmlMalloc(len);
    if (res->path == NULL) {
	fprintf(stderr, "xmlBuildURI: out of memory\n");
	goto done;
    }
    res->path[0] = 0;

    /*
     * a) All but the last segment of the base URI's path component is
     *    copied to the buffer.  In other words, any characters after the
     *    last (right-most) slash character, if any, are excluded.
     */
    cur = 0;
    out = 0;
    if (bas->path != NULL) {
	while (bas->path[cur] != 0) {
	    while ((bas->path[cur] != 0) && (bas->path[cur] != '/'))
		cur++;
	    if (bas->path[cur] == 0)
		break;

	    cur++;
	    while (out < cur) {
		res->path[out] = bas->path[out];
		out++;
	    }
	}
    }
    res->path[out] = 0;

    /*
     * b) The reference's path component is appended to the buffer
     *    string.
     */
    if (ref->path != NULL) {
	index = 0;
	while (ref->path[index] != 0) {
	    res->path[out++] = ref->path[index++];
	}
    }
    res->path[out] = 0;

    /*
     * Steps c) to h) are really path normalization steps
     */
    xmlNormalizeURIPath(res->path);

step_7:

    /*
     * 7) The resulting URI components, including any inherited from the
     *    base URI, are recombined to give the absolute form of the URI
     *    reference.
     */
    val = xmlSaveUri(res);

done:
    if (ref != NULL)
	xmlFreeURI(ref);
    if (base != NULL)
	xmlFreeURI(bas);
    if (res != NULL)
	xmlFreeURI(res);
    return(val);
}


