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

#include "xmlmemory.h"
#include "uri.h"

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
 *

 *
      authority     = server | reg_name
      server        = [ [ userinfo "@" ] hostport ]

 *    reg_name      = 1*( unreserved | escaped | "$" | "," |
 *                        ";" | ":" | "@" | "&" | "=" | "+" )

 *    userinfo      = *( unreserved | escaped |
 *                       ";" | ":" | "&" | "=" | "+" | "$" | "," )

      hostport      = host [ ":" port ]
      host          = hostname | IPv4address
      hostname      = *( domainlabel "." ) toplabel [ "." ]
      domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
      toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
      IPv4address   = 1*digit "." 1*digit "." 1*digit "." 1*digit
      port          = *digit

      path          = [ abs_path | opaque_part ]


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
 * xmlPrintURI:
 * @stream:  a FILE* for the output
 * @uri:  pointer to an xmlURI
 *
 * Prints the URI in the stream @steam.
 */
void
xmlPrintURI(FILE *stream, xmlURIPtr uri) {
    if (uri == NULL) return;

    /* TODO !!! URI encoding ... improper ! */
    if (uri->scheme != NULL) 
	fprintf(stderr, "%s:", uri->scheme);
    if (uri->opaque != NULL) {
	fprintf(stderr, "%s", uri->opaque);
    } else {
	if (uri->authority != NULL)
	    fprintf(stderr, "//%s", uri->authority);

	/* TODO !!!
	if (uri->server != NULL) xmlFree(uri->server);
	 */

	if (uri->path != NULL)
	    fprintf(stderr, "%s", uri->path);

	if (uri->query != NULL)
	    fprintf(stderr, "?%s", uri->query);
	if (uri->fragment != NULL)
	    fprintf(stderr, "#%s", uri->fragment);
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
    if (uri->path != NULL) xmlFree(uri->path);
    if (uri->fragment != NULL) xmlFree(uri->fragment);
    if (uri->opaque != NULL) xmlFree(uri->opaque);
    if (uri->authority != NULL) xmlFree(uri->authority);
    if (uri->query != NULL) xmlFree(uri->query);
    memset(uri, -1, sizeof(xmlURI));
    xmlFree(uri);
}

/**
 * xmlURIUnescape:
 * @str:  the string to unescape
 * @len:   the lenght in bytes to unescape (or <= 0 to indicate full string)
 * @target:  optionnal destination buffer
 *
 * Unescaping routine, does not do validity checks !
 *
 * Returns an copy of the string, but unescaped
 */
char *
xmlURIUnescape(const char *str, int len, char *target) {
    char *ret, *out;
    const char *in;

    if (str == NULL)
	return(NULL);
    if (len <= 0) len = strlen(str);
    if (len <= 0) return(NULL);

    if (target == NULL) {
	ret = (char *) xmlMalloc(len + 1);
	if (ret == NULL) {
	    fprintf(stderr, "xmlURIUnescape: out of memory\n");
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
	uri->fragment = xmlURIUnescape(*str, cur - *str, NULL);
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
	uri->query = xmlURIUnescape(*str, cur - *str, NULL);
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
	uri->scheme = xmlURIUnescape(*str, cur - *str, NULL); /* !!! strndup */
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
	uri->opaque = xmlURIUnescape(*str, cur - *str, NULL);
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
	uri->path = xmlURIUnescape(*str, cur - *str, NULL);
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
	xmlURIUnescape(*str, cur - *str, &path[len2]);
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

    if (str == NULL)
	return(-1);
    
    cur = *str;
    if (!IS_REG_NAME(cur)) {
	return(5);
    }
    NEXT(cur);
    while (IS_REG_NAME(cur)) NEXT(cur);
    if (uri != NULL) {
	if (uri->authority != NULL) xmlFree(uri->authority);
	uri->authority = xmlURIUnescape(*str, cur - *str, NULL);

	/* @@ Parse the authority to try to extract server infos !!! */
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
 * Returns a new URI string (to be freed by the caller)
 */
xmlChar *
xmlBuildURI(const xmlChar *URI, const xmlChar *base) {
    /* TODO */
    return(NULL);
}


#ifdef STANDALONE
int main(int argc, char **argv) {
    int i, ret;
    xmlURIPtr uri;

    uri = xmlCreateURI();
    if (argc <= 1) {
	char str[1024];

        while (1) {
	    /*
	     * read one line in string buffer.
	     */
	    if (fgets (&str[0], sizeof (str) - 1, stdin) == NULL)
	       break;

	    /*
	     * remove the ending spaces
	     */
	    i = strlen(str);
	    while ((i > 0) &&
		   ((str[i - 1] == '\n') || (str[i - 1] == '\r') ||
		    (str[i - 1] == ' ') || (str[i - 1] == '\t'))) {
		i--;
		str[i] = 0;
	    }
	    if (i <= 0)
		continue;

	    ret = xmlParseURIReference(uri, str);
	    if (ret != 0)
		printf("%s : error %d\n", str, ret);
	    else {
		xmlPrintURI(stdout, uri);
		printf("\n");
	    }

        }
    } else {
	for (i = 1;i < argc;i++) {
	    ret = xmlParseURIReference(uri, argv[i]);
	    if (ret != 0)
		printf("%s : error %d\n", argv[i], ret);
	    else {
		xmlPrintURI(stdout, uri);
		printf("\n");
	    }
	}
    }
    xmlFreeURI(uri);
    exit(0);
}
#endif
