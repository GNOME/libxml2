/*************************************************************************
 *
 * $Id$
 *
 * Copyright (C) 1998 Bjorn Reese and Daniel Stenberg.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE AUTHORS AND
 * CONTRIBUTORS ACCEPT NO RESPONSIBILITY IN ANY CONCEIVABLE MANNER.
 *
 *************************************************************************
 *
 * Avoid heap allocation at all costs to ensure that the trio functions
 * are async-safe. The exceptions are the printf/fprintf functions, which
 * uses fputc, and the asprintf functions and the <alloc> modifier, which
 * by design are required to allocate form the heap.
 *
 ************************************************************************/

/* DV for libxml */
#include <libxml/xmlversion.h>
#ifdef WITH_TRIO
#include "config.h"
/*
 * DV changes applied
 * excluded all unused interfaces, renamed them without the trio prefix
 */

/*
 * FIXME:
 *  - Scan is probably too permissive about its modifiers.
 *  - Width for floating-point numbers (does it make sense?)
 *  - Add hex-float to TrioReadDouble
 *  - C escapes in %#[] ?
 *  - Multibyte characters (done for format parsing, except scan groups)
 *  - Widechar
 *  - Complex numbers? (C99 _Complex)
 *  - Boolean values? (C99 _Bool)
 *  - C99 NaN(n-char-sequence) missing
 *  - Should we support the GNU %a alloc modifier? GNU has an ugly hack
 *    for %a, because C99 used %a for other purposes. If specified as
 *    %as or %a[ it is interpreted as the alloc modifier, otherwise as
 *    the C99 hex-float. This means that you cannot scan %as as a hex-float
 *    immediately followed by an 's'.
 */

static const char rcsid[] = "@(#)$Id$";

#if defined(__STDC__) && (__STDC_VERSION__ >= 199901L)
# define TRIO_C99 /* FIXME: C99 support has not been properly tested */
#endif
#define TRIO_BSD
#define TRIO_GNU
#define TRIO_MISC
#define TRIO_UNIX98
#define TRIO_EXTENSION
#define TRIO_ERRORS

#if defined(unix) || defined(__xlC__) /* AIX xlC workaround */
# define PLATFORM_UNIX
#elif defined(AMIGA) && defined(__GNUC__)
# define PLATFORM_UNIX
#endif

/*************************************************************************
 * Include files
 */


#include "trio.h"
#include "strio.h"
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include <float.h>
#include <stdarg.h>
#include <errno.h>
#if defined(TRIO_C99)
# include <stdint.h>
#endif
#if defined(PLATFORM_UNIX)
# include <unistd.h>
# include <locale.h>
# define USE_LOCALE
#endif
#ifndef DEBUG
# define NDEBUG
#endif
#include <assert.h>

/*************************************************************************
 * Generic definitions
 */

#ifndef NULL
# define NULL 0
#endif
#define NIL ((char)0)
#ifdef __cplusplus
# undef TRUE
# undef FALSE
# define TRUE true
# define FALSE false
# define BOOLEAN_T bool
#else
# ifndef FALSE
#  define FALSE (1 == 0)
#  define TRUE (! FALSE)
# endif
# define BOOLEAN_T int
#endif

/* mincore() can be used for debugging purposes */
#define VALID(x) (NULL != (x))

/* Encode the error code and the position. This is decoded
 * with TRIO_ERROR_CODE and TRIO_ERROR_POSITION.
 */
#if defined(TRIO_ERRORS)
# define TRIO_ERROR_RETURN(x,y) (- ((x) + ((y) << 8)))
#else
# define TRIO_ERROR_RETURN(x,y) (-1)
#endif

/*************************************************************************
 * Internal definitions
 */

#if defined(__STDC_ISO_10646__) || defined(MB_LEN_MAX)
# define USE_MULTIBYTE
#endif

#if !defined(USE_LONGLONG)
# if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#  define USE_LONGLONG
# elif defined(__SUNPRO_C)
#  define USE_LONGLONG
# elif defined(_LONG_LONG) || defined(_LONGLONG)
#  define USE_LONGLONG
# endif
#endif

/* The extra long numbers */
#if defined(USE_LONGLONG)
# define LONGLONG long long
# define ULONGLONG unsigned long long
#else
# define LONGLONG long
# define ULONGLONG unsigned long
#endif

/* The longest possible integer */
#if defined(TRIO_C99)
# define LONGEST uintmax_t
# define SLONGEST intmax_t
#else
# define LONGEST ULONGLONG
# define SLONGEST LONGLONG
#endif

/* The maximal number of digits are for base 2 */
#define MAX_CHARS_IN(x) (sizeof(x) * CHAR_BIT + 1)
/* The width of a pointer. The number of bits in a hex digit is 4 */
#define POINTER_WIDTH ((sizeof("0x") - 1) + sizeof(void *) * CHAR_BIT / 4)

/* Infinite and Not-A-Number for floating-point */
#if defined(HUGE_VAL)
# define USE_INFINITE
# if defined(TRIO_C99)
#  define IS_INFINITE(x) isinf(x)
# else
#  define IS_INFINITE(x) (((x)==HUGE_VAL) ? 1 : (((x)==-HUGE_VAL) ? -1 : 0))
# endif
# define INFINITE_LOWER "inf"
# define INFINITE_UPPER "INF"
# define LONG_INFINITE_LOWER "infinite"
# define LONG_INFINITE_UPPER "INFINITE"
#endif
#if defined(NAN)
# define USE_NAN
# define IS_NAN(x) isnan(x)
# define NAN_LOWER "nan"
# define NAN_UPPER "NAN"
#endif

/* Various constants */
enum {
  TYPE_PRINT = 1,
  TYPE_SCAN  = 2,

  /* Flags. Use maximum 32 */
  FLAGS_NEW                 = 0,
  FLAGS_STICKY              = 1,
  FLAGS_SPACE               = 2 * FLAGS_STICKY,
  FLAGS_SHOWSIGN            = 2 * FLAGS_SPACE,
  FLAGS_LEFTADJUST          = 2 * FLAGS_SHOWSIGN,
  FLAGS_ALTERNATIVE         = 2 * FLAGS_LEFTADJUST,
  FLAGS_SHORT               = 2 * FLAGS_ALTERNATIVE,
  FLAGS_SHORTSHORT          = 2 * FLAGS_SHORT,
  FLAGS_LONG                = 2 * FLAGS_SHORTSHORT,
  FLAGS_QUAD                = 2 * FLAGS_LONG,
  FLAGS_LONGDOUBLE          = 2 * FLAGS_QUAD,
  FLAGS_SIZE_T              = 2 * FLAGS_LONGDOUBLE,
  FLAGS_PTRDIFF_T           = 2 * FLAGS_SIZE_T,
  FLAGS_INTMAX_T            = 2 * FLAGS_PTRDIFF_T,
  FLAGS_NILPADDING          = 2 * FLAGS_INTMAX_T,
  FLAGS_UNSIGNED            = 2 * FLAGS_NILPADDING,
  FLAGS_UPPER               = 2 * FLAGS_UNSIGNED,
  FLAGS_WIDTH               = 2 * FLAGS_UPPER,
  FLAGS_WIDTH_PARAMETER     = 2 * FLAGS_WIDTH,
  FLAGS_PRECISION           = 2 * FLAGS_WIDTH_PARAMETER,
  FLAGS_PRECISION_PARAMETER = 2 * FLAGS_PRECISION,
  FLAGS_BASE                = 2 * FLAGS_PRECISION_PARAMETER,
  FLAGS_BASE_PARAMETER      = 2 * FLAGS_BASE,
  FLAGS_FLOAT_E             = 2 * FLAGS_BASE_PARAMETER,
  FLAGS_FLOAT_G             = 2 * FLAGS_FLOAT_E,
  FLAGS_QUOTE               = 2 * FLAGS_FLOAT_G,
  FLAGS_WIDECHAR            = 2 * FLAGS_QUOTE,
  FLAGS_ALLOC               = 2 * FLAGS_WIDECHAR,
  FLAGS_IGNORE              = 2 * FLAGS_ALLOC,
  FLAGS_IGNORE_PARAMETER    = 2 * FLAGS_IGNORE,
  FLAGS_SIZE_PARAMETER      = 2 * FLAGS_IGNORE_PARAMETER,
  /* Reused flags */
  FLAGS_EXCLUDE             = FLAGS_SHORT,
  /* Compounded flags */
  FLAGS_ALL_SIZES           = FLAGS_LONG | FLAGS_QUAD | FLAGS_INTMAX_T | FLAGS_PTRDIFF_T | FLAGS_SIZE_T,

  NO_POSITION  = -1,
  NO_WIDTH     =  0,
  NO_PRECISION = -1,
  NO_SIZE      = -1,

  NO_BASE      = -1,
  MIN_BASE     =  2,
  MAX_BASE     = 36,
  BASE_BINARY  =  2,
  BASE_OCTAL   =  8,
  BASE_DECIMAL = 10,
  BASE_HEX     = 16,

  /* Maximal number of allowed parameters */
  MAX_PARAMETERS = 64,
  /* Maximal number of characters in class */
  MAX_CHARACTER_CLASS = UCHAR_MAX,

  /* Maximal length of locale separator strings */
  MAX_LOCALE_SEPARATOR_LENGTH = 64,
  /* Maximal number of integers in grouping */
  MAX_LOCALE_GROUPS = 64
};

#define NO_GROUPING ((int)CHAR_MAX)

/* Fundamental formatting parameter types */
#define FORMAT_UNKNOWN   0
#define FORMAT_INT       1
#define FORMAT_DOUBLE    2
#define FORMAT_CHAR      3
#define FORMAT_STRING    4
#define FORMAT_POINTER   5
#define FORMAT_COUNT     6
#define FORMAT_PARAMETER 7
#define FORMAT_GROUP     8
#if defined(TRIO_GNU)
# define FORMAT_ERRNO   10
#endif

/* Character constants */
#define CHAR_IDENTIFIER '%'
#define CHAR_BACKSLASH '\\'
#define CHAR_QUOTE '\"'
#define CHAR_ADJUST ' '

/* Character class expressions */
#define CLASS_ALNUM ":alnum:"
#define CLASS_ALPHA ":alpha:"
#define CLASS_CNTRL ":cntrl:"
#define CLASS_DIGIT ":digit:"
#define CLASS_GRAPH ":graph:"
#define CLASS_LOWER ":lower:"
#define CLASS_PRINT ":print:"
#define CLASS_PUNCT ":punct:"
#define CLASS_SPACE ":space:"
#define CLASS_UPPER ":upper:"
#define CLASS_XDIGIT ":xdigit:"

/*
 * SPECIFIERS:
 *
 *
 * a  Hex-float
 * A  Hex-float
 * c  Character
 * C  Widechar character (wint_t)
 * d  Decimal
 * e  Float
 * E  Float
 * F  Float
 * F  Float
 * g  Float
 * G  Float
 * i  Integer
 * m  Error message
 * n  Count
 * o  Octal
 * p  Pointer
 * s  String
 * S  Widechar string (wchar_t)
 * u  Unsigned
 * x  Hex
 * X  Hex
 * [  Group
 *
 * Reserved:
 *
 * D  Binary Coded Decimal %D(length,precision) (OS/390)
 */
#define SPECIFIER_CHAR 'c'
#define SPECIFIER_STRING 's'
#define SPECIFIER_DECIMAL 'd'
#define SPECIFIER_INTEGER 'i'
#define SPECIFIER_UNSIGNED 'u'
#define SPECIFIER_OCTAL 'o'
#define SPECIFIER_HEX 'x'
#define SPECIFIER_HEX_UPPER 'X'
#define SPECIFIER_FLOAT_E 'e'
#define SPECIFIER_FLOAT_E_UPPER 'E'
#define SPECIFIER_FLOAT_F 'f'
#define SPECIFIER_FLOAT_F_UPPER 'F'
#define SPECIFIER_FLOAT_G 'g'
#define SPECIFIER_FLOAT_G_UPPER 'G'
#define SPECIFIER_POINTER 'p'
#define SPECIFIER_GROUP '['
#define SPECIFIER_UNGROUP ']'
#define SPECIFIER_COUNT 'n'
#if defined(TRIO_UNIX98)
# define SPECIFIER_CHAR_UPPER 'C'
# define SPECIFIER_STRING_UPPER 'S'
#endif
#if defined(TRIO_C99)
# define SPECIFIER_HEXFLOAT 'a'
# define SPECIFIER_HEXFLOAT_UPPER 'A'
#endif
#if defined(TRIO_GNU)
# define SPECIFIER_ERRNO 'm'
#endif
#if defined(TRIO_EXTENSION)
# define SPECIFIER_BINARY 'b'
# define SPECIFIER_BINARY_UPPER 'B'
#endif

/*
 * QUALIFIERS:
 *
 *
 * Numbers = d,i,o,u,x,X
 * Float = a,A,e,E,f,F,g,G
 * String = s
 * Char = c
 *
 *
 * 9$ Position
 *      Use the 9th parameter. 9 can be any number between 1 and
 *      the maximal argument
 *
 * 9 Width
 *      Set width to 9. 9 can be any number, but must not be postfixed
 *      by '$'
 *
 * h  Short
 *    Numbers:
 *      (unsigned) short int
 *
 * hh Short short
 *    Numbers:
 *      (unsigned) char
 *
 * l  Long
 *    Numbers:
 *      (unsigned) long int
 *    String:
 *      as the S specifier
 *    Char:
 *      as the C specifier
 *
 * ll Long Long
 *    Numbers:
 *      (unsigned) long long int
 *
 * L  Long Double
 *    Float
 *      long double
 *
 * #  Alternative
 *    Float:
 *      Decimal-point is always present
 *    String:
 *      non-printable characters are handled as \number
 *
 *    Spacing
 *
 * +  Sign
 *
 * -  Alignment
 *
 * .  Precision
 *
 * *  Parameter
 *    print: use parameter
 *    scan: no parameter (ignore)
 *
 * q  Quad
 *
 * Z  size_t
 *
 * w  Widechar
 *
 * '  Thousands/quote
 *    Numbers:
 *      Integer part grouped in thousands
 *    Binary numbers:
 *      Number grouped in nibbles (4 bits)
 *    String:
 *      Quoted string
 *
 * j  intmax_t
 * t  prtdiff_t
 * z  size_t
 *
 * !  Sticky
 * @  Parameter (for both print and scan)
 *
 * Extensions:
 * NB: Some of these have been deprecated.
 * <alloc>    = GNU 'a' qualifier
 * <base=n>   = sets base to 'n' (int)
 * <fill=c>   = fill with 'c' (char)
 * <quote>    = quote string
 */
#define QUALIFIER_POSITION '$'
#define QUALIFIER_SHORT 'h'
#define QUALIFIER_LONG 'l'
#define QUALIFIER_LONG_UPPER 'L'
#define QUALIFIER_ALTERNATIVE '#'
#define QUALIFIER_SPACE ' '
#define QUALIFIER_PLUS '+'
#define QUALIFIER_MINUS '-'
#define QUALIFIER_DOT '.'
#define QUALIFIER_STAR '*'
#define QUALIFIER_CIRCUMFLEX '^'
#if defined(TRIO_C99)
# define QUALIFIER_SIZE_T 'z'
# define QUALIFIER_PTRDIFF_T 't'
# define QUALIFIER_INTMAX_T 'j'
#endif
#if defined(TRIO_BSD) || defined(TRIO_GNU)
# define QUALIFIER_QUAD 'q'
#endif
#if defined(TRIO_GNU)
# define QUALIFIER_SIZE_T_UPPER 'Z'
#endif
#if defined(TRIO_MISC)
# define QUALIFIER_WIDECHAR 'w'
#endif
#if defined(TRIO_EXTENSION)
# define QUALIFIER_QUOTE '\''
# define QUALIFIER_STICKY '!'
# define QUALIFIER_VARSIZE '&' /* This should remain undocumented */
# define QUALIFIER_PARAM '@' /* Experimental */
# define QUALIFIER_COLON ':' /* For scanlists */
# define QUALIFIER_EXTENSIONBEGIN '<'
# define QUALIFIER_EXTENSIONEND '>'
# define QUALIFIER_EXTENSIONSEPARATOR ','
# define QUALIFIER_EXTENSIONVALUE '='
#endif

/* Internal structure for parameters */
typedef struct {
  int type;
  int flags;
  int width;
  size_t precision;
  int base;
  int varsize;
  int indexAfterSpecifier;
  union {
    char *string;
    void *pointer;
    union {
      SLONGEST asSigned;
      LONGEST asUnsigned;
    } number;
    double doubleNumber;
    double *doublePointer;
    long double longdoubleNumber;
    long double *longdoublePointer;
    int errorNumber;
  } data;
} parameter_T;

/* Internal structure */
typedef struct _trio_T {
  void *location;
  void (*OutStream)(struct _trio_T *, int);
  void (*InStream)(struct _trio_T *, int *);
  /* The number of characters that would have been written/read if
   * there had been sufficient space.
   */
  size_t processed;
  /* The number of characters that are actually written/read.
   * Processed and committed with only differ for the *nprintf
   * and *nscanf functions.
   */
  size_t committed;
  size_t max;
  unsigned int current;
} trio_T;


/*************************************************************************
 * Package scope variables
 */

#if defined(PLATFORM_UNIX)
extern int errno;
#endif

#if defined(USE_LOCALE)
static struct lconv *globalLocaleValues = NULL;
#endif
/* UNIX98 says "in a locale where the radix character is not defined,
 * the radix character defaults to a period (.)"
 */
static char globalDecimalPoint[MAX_LOCALE_SEPARATOR_LENGTH] = ".";
static char globalThousandSeparator[MAX_LOCALE_SEPARATOR_LENGTH] = ",";
static char globalGrouping[MAX_LOCALE_GROUPS] = { (char)NO_GROUPING };

static const char globalDigitsLower[] = "0123456789abcdefghijklmnopqrstuvwxyz";
static const char globalDigitsUpper[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static BOOLEAN_T globalDigitsUnconverted = TRUE;
static int globalDigitArray[128];

static const char null[] = "(nil)";

static const char extensionFill[] = "fill";
static const size_t extensionFillSize = sizeof(extensionFill) - 1;
static const char extensionAlloc[] = "alloc";
static const size_t extensionAllocSize = sizeof(extensionAlloc) - 1;
static const char extensionBase[] = "base";
static const size_t extensionBaseSize = sizeof(extensionBase) - 1;
static const char extensionQuote[] = "quote";
static const size_t extensionQuoteSize = sizeof(extensionQuote) - 1;


/*************************************************************************
 * TrioIsQualifier [private]
 *
 * Description:
 *  Remember to add all new qualifiers to this function.
 *  QUALIFIER_POSITION must not be added.
 */
static BOOLEAN_T
TrioIsQualifier(const char ch)
{
  /* QUALIFIER_POSITION is not included */
  switch (ch)
    {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case QUALIFIER_PLUS:
    case QUALIFIER_MINUS:
    case QUALIFIER_SPACE:
    case QUALIFIER_DOT:
    case QUALIFIER_STAR:
    case QUALIFIER_ALTERNATIVE:
    case QUALIFIER_SHORT:
    case QUALIFIER_LONG:
    case QUALIFIER_LONG_UPPER:
    case QUALIFIER_CIRCUMFLEX:
#if defined(QUALIFIER_SIZE_T)
    case QUALIFIER_SIZE_T:
#endif
#if defined(QUALIFIER_PTRDIFF_T)
    case QUALIFIER_PTRDIFF_T:
#endif
#if defined(QUALIFIER_INTMAX_T)
    case QUALIFIER_INTMAX_T:
#endif
#if defined(QUALIFIER_QUAD)
    case QUALIFIER_QUAD:
#endif
#if defined(QUALIFIER_SIZE_T_UPPER)
    case QUALIFIER_SIZE_T_UPPER:
#endif
#if defined(QUALIFIER_WIDECHAR)
    case QUALIFIER_WIDECHAR:
#endif
#if defined(QUALIFIER_EXTENSIONBEGIN)
    case QUALIFIER_EXTENSIONBEGIN:
#endif
#if defined(QUALIFIER_QUOTE)
    case QUALIFIER_QUOTE:
#endif
#if defined(QUALIFIER_STICKY)
    case QUALIFIER_STICKY:
#endif
#if defined(QUALIFIER_VARSIZE)
    case QUALIFIER_VARSIZE:
#endif
#if defined(QUALIFIER_PARAM)
    case QUALIFIER_PARAM:
#endif
      return TRUE;
    default:
      return FALSE;
    }
}

/*************************************************************************
 * TrioSetLocale [private]
 */
static void
TrioSetLocale()
{
#if defined(USE_LOCALE)
  globalLocaleValues = (struct lconv *)localeconv();
  if (StrLength(globalLocaleValues->decimal_point) > 0)
    {
      StrCopyMax(globalDecimalPoint,
		 sizeof(globalDecimalPoint),
		 globalLocaleValues->decimal_point);
    }
  if (StrLength(globalLocaleValues->thousands_sep) > 0)
    {
      StrCopyMax(globalThousandSeparator,
		 sizeof(globalThousandSeparator),
		 globalLocaleValues->thousands_sep);
    }
  if (StrLength(globalLocaleValues->grouping) > 0)
    {
      StrCopyMax(globalGrouping,
		 sizeof(globalGrouping),
		 globalLocaleValues->grouping);
    }
#endif
}

/*************************************************************************
 * TrioGetPosition [private]
 *
 * Get the %n$ position.
 */
static int
TrioGetPosition(const char *format, int *indexPointer)
{
  char *tmpformat;
  int number = 0;
  int index = *indexPointer;

  number = (int)StrToLong(&format[index], &tmpformat, BASE_DECIMAL);
  index = (int)(tmpformat - format);
  if ((number != 0) && (QUALIFIER_POSITION == format[index++]))
    {
      *indexPointer = index;
      /* number is decreased by 1, because n$ starts from 1, whereas
       * the array it is indexing starts from 0.
       */
      return number - 1;
    }
  return NO_POSITION;
}

/*************************************************************************
 * TrioPreprocess [private]
 *
 * Description:
 *  Parse the format string
 */
static int
TrioPreprocess(int type,
	       const char *format,
	       parameter_T *parameters,
	       va_list arglist)
{
#if defined(TRIO_ERRORS)
  /* Count the number of times a parameter is referenced */
  unsigned short usedEntries[MAX_PARAMETERS];
#endif
  /* Parameter counters */
  int parameterPosition;
  int currentParam;
  int maxParam = -1;
  BOOLEAN_T insideExtension;  /* Are we inside an <> extension? */
  /* Utility variables */
  int flags;
  int width;
  int precision;
  int varsize;
  int base;
  int index;  /* Index into formatting string */
  int dots;  /* Count number of dots in modifier part */
  BOOLEAN_T positional;  /* Does the specifier have a positional? */
  BOOLEAN_T got_sticky = FALSE;  /* Are there any sticky modifiers at all? */
  /* indices specifies the order in which the parameters must be
   * read from the va_args (this is necessary to handle positionals)
   */
  int indices[MAX_PARAMETERS];
  int pos = 0;
  /* Various variables */
  char ch;
  int charlen;
  int i = -1;
  int num;
  int work;
  char *tmpformat;


#if defined(TRIO_ERRORS)
  /* The 'parameters' array is not initialized, but we need to
   * know which entries we have used.
   */
  memset(usedEntries, 0, sizeof(usedEntries));
#endif

  index = 0;
  parameterPosition = 0;
#if defined(USE_MULTIBYTE)
  mblen(NULL, 0);
#endif
  
  while (format[index])
    {
#if defined(USE_MULTIBYTE)
      if (! isascii(format[index]))
	{
	  /* Multibyte characters cannot be legal specifiers or
	   * modifiers, so we skip over them.
	   */
	  charlen = mblen(&format[index], MB_LEN_MAX);
	  index += (charlen > 0) ? charlen : 1;
	  continue; /* while */
	}
#endif
      if (CHAR_IDENTIFIER == format[index++])
	{
	  if (CHAR_IDENTIFIER == format[index])
	    {
	      index++;
	      continue; /* while */
	    }

	  flags = FLAGS_NEW;
	  insideExtension = FALSE;
	  dots = 0;
	  currentParam = TrioGetPosition(format, &index);
	  positional = (NO_POSITION != currentParam);
	  if (!positional)
	    {
	      /* We have no positional, get the next counter */
	      currentParam = parameterPosition;
	    }
          if(currentParam >= MAX_PARAMETERS)
	    {
	      /* Bail out completely to make the error more obvious */
	      return TRIO_ERROR_RETURN(TRIO_ETOOMANY, index);
	    }

	  if (currentParam > maxParam)
	    maxParam = currentParam;

	  /* Default values */
	  width = NO_WIDTH;
	  precision = NO_PRECISION;
	  base = NO_BASE;
	  varsize = NO_SIZE;

	  while (TrioIsQualifier(format[index])
		 || insideExtension)
	    {
	      ch = format[index++];

#if defined(TRIO_EXTENSION)
	      if (insideExtension)
		{
		  if (QUALIFIER_EXTENSIONSEPARATOR == ch)
		    {
		      ch = QUALIFIER_EXTENSIONBEGIN;
		    }
		  else
		    {
		      insideExtension = FALSE;
		    }
		}
	      if (QUALIFIER_EXTENSIONBEGIN == ch)
		{
		  /* Parse extended format */
		  insideExtension = TRUE;
		  work = index;

		  switch (format[work])
		    {
		    case 'a':
		      /* <alloc> */
		      if (StrEqualMax(extensionAlloc, extensionAllocSize,
				      &format[work]))
			{
			  flags |= FLAGS_ALLOC;
			  work += extensionAllocSize;
			}
		      break;

		    case 'b':
		      /* <base=c> */
		      if (StrEqualMax(extensionBase, extensionBaseSize,
				      &format[work]))
			{
			  work += extensionBaseSize;
			  if (QUALIFIER_EXTENSIONVALUE == format[work])
			    {
			      work++;
			      base = StrToLong(&format[work], &tmpformat, BASE_DECIMAL);
			      work += (int)(tmpformat - &format[work]);
			      if ((base < MIN_BASE) || (base > MAX_BASE))
				return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
			    }
			}
		      break;

#if 0
		      /* Deprecated */
		    case 'f':
		      if (StrEqualMax(extensionFill, extensionFillSize,
				      &format[work]))
			{
			  work += extensionFillSize;
			  if (QUALIFIER_EXTENSIONVALUE == format[work])
			    {
			      work++;
			      adjust = format[work++];
			    }
			}
#endif
		    case 'q':
		      /* <quote> */
		      if (StrEqualMax(extensionQuote, extensionQuoteSize,
				      &format[work]))
			{
			  flags |= FLAGS_QUOTE;
			  work += extensionQuoteSize;
#if 0
			  /* Deprecated */
			  if (QUALIFIER_EXTENSIONVALUE == format[work])
			    {
			      work++;
			      quote = format[work++];
			    }
#endif
			}
		      break;

		    default:
		      break;
		    }
		  
		  if (QUALIFIER_EXTENSIONEND == work[format])
		    {
		      insideExtension = FALSE;
		      index = ++work;
		    }
		}
#endif /* defined(TRIO_EXTENSION) */

	      switch (ch)
		{
#if defined(TRIO_EXTENSION)
		case QUALIFIER_EXTENSIONBEGIN:
		case QUALIFIER_EXTENSIONSEPARATOR:
		  /* Everything is fine, but ignore */
		  break;
#endif
		case QUALIFIER_SPACE:
		  flags |= FLAGS_SPACE;
		  break;

		case QUALIFIER_PLUS:
		  flags |= FLAGS_SHOWSIGN;
		  break;

		case QUALIFIER_MINUS:
		  flags |= FLAGS_LEFTADJUST;
		  flags &= ~FLAGS_NILPADDING;
		  break;

		case QUALIFIER_ALTERNATIVE:
		  flags |= FLAGS_ALTERNATIVE;
		  break;

		case QUALIFIER_DOT:
		  if (dots == 0) /* Precision */
		    {
		      dots++;

		      /* Skip if no precision */
		      if (QUALIFIER_DOT == format[index])
			break;
		      
		      /* After the first dot we have the precision */
		      flags |= FLAGS_PRECISION;
		      if ((QUALIFIER_STAR == format[index]) ||
			  (QUALIFIER_PARAM == format[index]))
			{
			  index++;
			  flags |= FLAGS_PRECISION_PARAMETER;

			  precision = TrioGetPosition(format, &index);
			  if (precision == NO_POSITION)
			    {
			      parameterPosition++;
			      if (positional)
				precision = parameterPosition;
			      else
				{
				  precision = currentParam;
				  currentParam = precision + 1;
				}
			    }
			  else
			    {
			      if (! positional)
				currentParam = precision + 1;
			      if (width > maxParam)
				maxParam = precision;
			    }
			  if (currentParam > maxParam)
			    maxParam = currentParam;
			}
		      else
			{
			  precision = StrToLong(&format[index], &tmpformat, BASE_DECIMAL);
			  index = (int)(tmpformat - format);
			}
		    }
		  else if (dots == 1) /* Base */
		    {
		      dots++;
		      
		      /* After the second dot we have the base */
		      flags |= FLAGS_BASE;
		      if ((QUALIFIER_STAR == format[index]) ||
			  (QUALIFIER_PARAM == format[index]))
			{
			  index++;
			  flags |= FLAGS_BASE_PARAMETER;
			  base = TrioGetPosition(format, &index);
			  if (base == NO_POSITION)
			    {
			      parameterPosition++;
			      if (positional)
				base = parameterPosition;
			      else
				{
				  base = currentParam;
				  currentParam = base + 1;
				}
			    }
			  else
			    {
			      if (! positional)
				currentParam = base + 1;
			      if (base > maxParam)
				maxParam = base;
			    }
			  if (currentParam > maxParam)
			    maxParam = currentParam;
			}
		      else
			{
			  base = StrToLong(&format[index], &tmpformat, BASE_DECIMAL);
			  if (base > MAX_BASE)
			    return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
			  index = (int)(tmpformat - format);
			}
		    }
		  else
		    {
		      return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
		    }
		  break; /* QUALIFIER_DOT */

		case QUALIFIER_PARAM:
		  type = TYPE_PRINT;
		  /* FALLTHROUGH */
		case QUALIFIER_STAR:
		  /* This has different meanings for print and scan */
		  if (TYPE_PRINT == type)
		    {
		      /* Read with from parameter */
		      flags |= (FLAGS_WIDTH | FLAGS_WIDTH_PARAMETER);
		      width = TrioGetPosition(format, &index);
		      if (width == NO_POSITION)
			{
			  parameterPosition++;
			  if (positional)
			    width = parameterPosition;
			  else
			    {
			      width = currentParam;
			      currentParam = width + 1;
			    }
			}
		      else
			{
			  if (! positional)
			    currentParam = width + 1;
			  if (width > maxParam)
			    maxParam = width;
			}
		      if (currentParam > maxParam)
			maxParam = currentParam;
		    }
		  else
		    {
		      /* Scan, but do not store result */
		      flags |= FLAGS_IGNORE;
		    }

		  break; /* QUALIFIER_STAR */

		case '0':
		  if (! (flags & FLAGS_LEFTADJUST))
		    flags |= FLAGS_NILPADDING;
		  /* FALLTHROUGH */
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
		  flags |= FLAGS_WIDTH;
		  /* &format[index - 1] is used to "rewind" the read
		   * character from format
		   */
		  width = StrToLong(&format[index - 1], &tmpformat, BASE_DECIMAL);
		  index = (int)(tmpformat - format);
		  break;

		case QUALIFIER_SHORT:
		  if (flags & FLAGS_SHORTSHORT)
		    return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
		  else if (flags & FLAGS_SHORT)
		    flags |= FLAGS_SHORTSHORT;
		  else
		    flags |= FLAGS_SHORT;
		  break;

		case QUALIFIER_LONG:
		  if (flags & FLAGS_QUAD)
		    return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
		  else if (flags & FLAGS_LONG)
		    flags |= FLAGS_QUAD;
		  else
		    flags |= FLAGS_LONG;
		  break;

		case QUALIFIER_LONG_UPPER:
		  flags |= FLAGS_LONGDOUBLE;
		  break;

#if defined(QUALIFIER_SIZE_T)
		case QUALIFIER_SIZE_T:
		  flags |= FLAGS_SIZE_T;
		  /* Modify flags for later truncation of number */
		  if (sizeof(size_t) == sizeof(ULONGLONG))
		    flags |= FLAGS_QUAD;
		  else if (sizeof(size_t) == sizeof(long))
		    flags |= FLAGS_LONG;
		  break;
#endif

#if defined(QUALIFIER_PTRDIFF_T)
		case QUALIFIER_PTRDIFF_T:
		  flags |= FLAGS_PTRDIFF_T;
		  if (sizeof(ptrdiff_t) == sizeof(ULONGLONG))
		    flags |= FLAGS_QUAD;
		  else if (sizeof(ptrdiff_t) == sizeof(long))
		    flags |= FLAGS_LONG;
		  break;
#endif

#if defined(QUALIFIER_INTMAX_T)
		case QUALIFIER_INTMAX_T:
		  flags |= FLAGS_INTMAX_T;
		  if (sizeof(intmax_t) == sizeof(ULONGLONG))
		    flags |= FLAGS_QUAD;
		  else if (sizeof(intmax_t) == sizeof(long))
		    flags |= FLAGS_LONG;
		  break;
#endif

#if defined(QUALIFIER_QUAD)
		case QUALIFIER_QUAD:
		  flags |= FLAGS_QUAD;
		  break;
#endif

#if defined(QUALIFIER_WIDECHAR)
		case QUALIFIER_WIDECHAR:
		  flags |= FLAGS_WIDECHAR;
		  break;
#endif

#if defined(QUALIFIER_SIZE_T_UPPER)
		case QUALIFIER_SIZE_T_UPPER:
		  break;
#endif

#if defined(QUALIFIER_QUOTE)
		case QUALIFIER_QUOTE:
		  flags |= FLAGS_QUOTE;
		  break;
#endif

#if defined(QUALIFIER_STICKY)
		case QUALIFIER_STICKY:
		  flags |= FLAGS_STICKY;
		  got_sticky = TRUE;
		  break;
#endif
		  
#if defined(QUALIFIER_VARSIZE)
		case QUALIFIER_VARSIZE:
		  flags |= FLAGS_SIZE_PARAMETER;
		  parameterPosition++;
		  if (positional)
		    varsize = parameterPosition;
		  else
		    {
		      varsize = currentParam;
		      currentParam = varsize + 1;
		    }
		  if (currentParam > maxParam)
		    maxParam = currentParam;
		  break;
#endif

		default:
		  /* Bail out completely to make the error more obvious */
                  return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
		}
	    } /* while qualifier */

	  /* Parameters only need the type and value. The value is
	   * read later.
	   */
	  if (flags & FLAGS_WIDTH_PARAMETER)
	    {
#if defined(TRIO_ERRORS)
	      usedEntries[width] += 1;
#endif
	      parameters[pos].type = FORMAT_PARAMETER;
	      indices[width] = pos;
	      width = pos++;
	    }
	  if (flags & FLAGS_PRECISION_PARAMETER)
	    {
#if defined(TRIO_ERRORS)
	      usedEntries[precision] += 1;
#endif
	      parameters[pos].type = FORMAT_PARAMETER;
	      indices[precision] = pos;
	      precision = pos++;
	    }
	  if (flags & FLAGS_BASE_PARAMETER)
	    {
#if defined(TRIO_ERRORS)
	      usedEntries[base] += 1;
#endif
	      parameters[pos].type = FORMAT_PARAMETER;
	      indices[base] = pos;
	      base = pos++;
	    }
	  if (flags & FLAGS_SIZE_PARAMETER)
	    {
#if defined(TRIO_ERRORS)
	      usedEntries[varsize] += 1;
#endif
	      parameters[pos].type = FORMAT_PARAMETER;
	      indices[varsize] = pos;
	      varsize = pos++;
	    }
	  
	  indices[currentParam] = pos;
	  
	  switch (format[index++])
	    {
#if defined(SPECIFIER_CHAR_UPPER)
	    case SPECIFIER_CHAR_UPPER:
	      flags |= FLAGS_LONG;
	      /* FALLTHROUGH */
#endif
	    case SPECIFIER_CHAR:
	      parameters[pos].type = FORMAT_CHAR;
	      break;

#if defined(SPECIFIER_STRING_UPPER)
	    case SPECIFIER_STRING_UPPER:
	      flags |= FLAGS_LONG;
	      /* FALLTHROUGH */
#endif
	    case SPECIFIER_STRING:
	      parameters[pos].type = FORMAT_STRING;
	      break;

	    case SPECIFIER_GROUP:
	      if (TYPE_SCAN == type)
		{
		  parameters[pos].type = FORMAT_GROUP;
		  while (format[index])
		    {
		      if (format[index++] == SPECIFIER_UNGROUP)
			break; /* while */
		    }
		}
	      break;
	      
	    case SPECIFIER_INTEGER:
	      parameters[pos].type = FORMAT_INT;
	      break;
	      
	    case SPECIFIER_UNSIGNED:
	      flags |= FLAGS_UNSIGNED;
	      parameters[pos].type = FORMAT_INT;
	      break;

	    case SPECIFIER_DECIMAL:
	      /* Disable base modifier */
	      flags &= ~FLAGS_BASE_PARAMETER;
	      base = BASE_DECIMAL;
	      parameters[pos].type = FORMAT_INT;
	      break;

	    case SPECIFIER_OCTAL:
	      flags &= ~FLAGS_BASE_PARAMETER;
	      base = BASE_OCTAL;
	      parameters[pos].type = FORMAT_INT;
	      break;

#if defined(SPECIFIER_BINARY)
	    case SPECIFIER_BINARY_UPPER:
	      flags |= FLAGS_UPPER;
	      /* FALLTHROUGH */
	    case SPECIFIER_BINARY:
	      flags |= FLAGS_NILPADDING;
	      flags &= ~FLAGS_BASE_PARAMETER;
	      base = BASE_BINARY;
	      parameters[pos].type = FORMAT_INT;
	      break;
#endif

	    case SPECIFIER_HEX_UPPER:
	      flags |= FLAGS_UPPER;
	      /* FALLTHROUGH */
	    case SPECIFIER_HEX:
	      flags |= FLAGS_UNSIGNED;
	      flags &= ~FLAGS_BASE_PARAMETER;
	      base = BASE_HEX;
	      parameters[pos].type = FORMAT_INT;
	      break;

	    case SPECIFIER_FLOAT_E_UPPER:
	      flags |= FLAGS_UPPER;
	      /* FALLTHROUGH */
	    case SPECIFIER_FLOAT_E:
	      flags |= FLAGS_FLOAT_E;
	      parameters[pos].type = FORMAT_DOUBLE;
	      break;

	    case SPECIFIER_FLOAT_G_UPPER:
	      flags |= FLAGS_UPPER;
	      /* FALLTHROUGH */
	    case SPECIFIER_FLOAT_G:
	      flags |= FLAGS_FLOAT_G;
	      parameters[pos].type = FORMAT_DOUBLE;
	      break;

	    case SPECIFIER_FLOAT_F_UPPER:
	      flags |= FLAGS_UPPER;
	      /* FALLTHROUGH */
	    case SPECIFIER_FLOAT_F:
	      parameters[pos].type = FORMAT_DOUBLE;
	      break;

	    case SPECIFIER_POINTER:
	      parameters[pos].type = FORMAT_POINTER;
	      break;

	    case SPECIFIER_COUNT:
	      parameters[pos].type = FORMAT_COUNT;
	      break;

#if defined(SPECIFIER_HEXFLOAT)
# if defined(SPECIFIER_HEXFLOAT_UPPER)
	    case SPECIFIER_HEXFLOAT_UPPER:
	      flags |= FLAGS_UPPER;
	      /* FALLTHROUGH */
# endif
	    case SPECIFIER_HEXFLOAT:
	      base = BASE_HEX;
	      parameters[pos].type = FORMAT_DOUBLE;
	      break;
#endif

#if defined(FORMAT_ERRNO)
	    case SPECIFIER_ERRNO:
	      parameters[pos].type = FORMAT_ERRNO;
	      break;
#endif

	    default:
	      /* Bail out completely to make the error more obvious */
              return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
	    }

#if defined(TRIO_ERRORS)
	  /*  Count the number of times this entry has been used */
	  usedEntries[currentParam] += 1;
#endif
	  
	  /* Find last sticky parameters */
	  if (got_sticky && !(flags & FLAGS_STICKY))
	    {
	      for (i = pos - 1; i >= 0; i--)
		{
		  if (parameters[i].type == FORMAT_PARAMETER)
		    continue;
		  if ((parameters[i].flags & FLAGS_STICKY) &&
		      (parameters[i].type == parameters[pos].type))
		    {
		      /* Do not overwrite current qualifiers */
		      flags |= (parameters[i].flags & ~FLAGS_STICKY);
		      if (width == NO_WIDTH)
			width = parameters[i].width;
		      if (precision == NO_PRECISION)
			precision = parameters[i].precision;
		      if (base == NO_BASE)
			base = parameters[i].base;
		      break;
		    }
		}
	    }
	  
	  parameters[pos].indexAfterSpecifier = index;
	  parameters[pos].flags = flags;
	  parameters[pos].width = width;
	  parameters[pos].precision = precision;
	  parameters[pos].base = (base == NO_BASE) ? BASE_DECIMAL : base;
	  parameters[pos].varsize = varsize;
	  pos++;
	  
	  if (!positional)
	    parameterPosition++;
	  
	} /* if identifier */
      
    } /* while format characters left */

  for (num = 0; num <= maxParam; num++)
    {
#if defined(TRIO_ERRORS)
      if (usedEntries[num] != 1)
	{
	  if (usedEntries[num] == 0) /* gap detected */
	    return TRIO_ERROR_RETURN(TRIO_EGAP, num);
	  else /* double references detected */
	    return TRIO_ERROR_RETURN(TRIO_EDBLREF, num);
	}
#endif
      
      i = indices[num];

      /* FORMAT_PARAMETERS are only present if they must be read,
       * so it makes no sense to check the ignore flag (besides,
       * the flags variable is not set for that particular type)
       */
      if ((parameters[i].type != FORMAT_PARAMETER) &&
	  (parameters[i].flags & FLAGS_IGNORE))
	continue; /* for all arguments */

      /* The stack arguments are read according to ANSI C89
       * default argument promotions:
       *
       *  char           = int
       *  short          = int
       *  unsigned char  = unsigned int
       *  unsigned short = unsigned int
       *  float          = double
       *
       * In addition to the ANSI C89 these types are read (the
       * default argument promotions of C99 has not been
       * considered yet)
       *
       *  long long
       *  long double
       *  size_t
       *  ptrdiff_t
       *  intmax_t
       */
      switch (parameters[i].type)
	{
	case FORMAT_GROUP:
	case FORMAT_STRING:
	  parameters[i].data.string = va_arg(arglist, char *);
	  break;

	case FORMAT_POINTER:
	case FORMAT_COUNT:
	case FORMAT_UNKNOWN:
	  parameters[i].data.pointer = va_arg(arglist, void *);
	  break;

	case FORMAT_CHAR:
	case FORMAT_INT:
	  if (TYPE_SCAN == type)
	    {
	      parameters[i].data.pointer = (LONGEST *)va_arg(arglist, void *);
	    }
	  else
	    {
#if defined(QUALIFIER_VARSIZE)
	      if (parameters[i].flags & FLAGS_SIZE_PARAMETER)
		{
		  /* Variable sizes are mapped onto the fixed sizes,
		   * in accordance with integer promotion.
		   */
		  parameters[i].flags &= ~FLAGS_ALL_SIZES;
		  varsize = (int)parameters[parameters[i].varsize].data.number.asUnsigned;
		  if (varsize <= (int)sizeof(int))
		    ;
		  else if (varsize <= (int)sizeof(long))
		    parameters[i].flags |= FLAGS_LONG;
#if defined(QUALIFIER_INTMAX_T)
		  else if (varsize <= (int)sizeof(LONGLONG))
		    parameters[i].flags |= FLAGS_QUAD;
		  else
		    parameters[i].flags |= FLAGS_INTMAX_T;
#else
		  else
		    parameters[i].flags |= FLAGS_QUAD;
#endif
		}
#endif
#if defined(QUALIFIER_SIZE_T) || defined(QUALIFIER_SIZE_T_UPPER)
	      if (parameters[i].flags & FLAGS_SIZE_T)
		parameters[i].data.number.asUnsigned = (LONGEST)va_arg(arglist, size_t);
	      else
#endif
#if defined(QUALIFIER_PTRDIFF_T)
	      if (parameters[i].flags & FLAGS_PTRDIFF_T)
		parameters[i].data.number.asUnsigned = (LONGEST)va_arg(arglist, ptrdiff_t);
	      else
#endif
#if defined(QUALIFIER_INTMAX_T)
	      if (parameters[i].flags & FLAGS_INTMAX_T)
		parameters[i].data.number.asUnsigned = (LONGEST)va_arg(arglist, intmax_t);
	      else
#endif
	      if (parameters[i].flags & FLAGS_QUAD)
		parameters[i].data.number.asUnsigned = (LONGEST)va_arg(arglist, ULONGLONG);
	      else if (parameters[i].flags & FLAGS_LONG)
		parameters[i].data.number.asUnsigned = (LONGEST)va_arg(arglist, long);
	      else
		parameters[i].data.number.asUnsigned = (LONGEST)va_arg(arglist, int);
	    }
	  break;

	case FORMAT_PARAMETER:
	  parameters[i].data.number.asUnsigned = (LONGEST)va_arg(arglist, int);
	  break;

	case FORMAT_DOUBLE:
	  if (TYPE_SCAN == type)
	    {
	      if (parameters[i].flags & FLAGS_LONG)
		parameters[i].data.longdoublePointer = va_arg(arglist, long double *);
	      else
		parameters[i].data.doublePointer = va_arg(arglist, double *);
	    }
	  else
	    {
	      if (parameters[i].flags & FLAGS_LONG)
		parameters[i].data.longdoubleNumber = va_arg(arglist, long double);
	      else
		parameters[i].data.longdoubleNumber = (long double)va_arg(arglist, double);
	    }
	  break;

#if defined(FORMAT_ERRNO)
	case FORMAT_ERRNO:
	  parameters[i].data.errorNumber = errno;
	  break;
#endif

	default:
	  break;
	}
    } /* for all specifiers */
  return num;
}


/*************************************************************************
 *
 * FORMATTING
 *
 ************************************************************************/


/*************************************************************************
 * TrioWriteNumber [private]
 *
 * Description:
 *  Output a number.
 *  The complexity of this function is a result of the complexity
 *  of the dependencies of the flags.
 */
static void
TrioWriteNumber(trio_T *self,
		LONGEST number,
		int flags,
		int width,
		int precision,
		int base)
{
  BOOLEAN_T isNegative;
  char buffer[MAX_CHARS_IN(LONGEST)
	     * MAX_LOCALE_SEPARATOR_LENGTH
	     * MAX_LOCALE_GROUPS];
  char *bufferend;
  char *pointer;
  const char *digits;
  int i;
  int length;
  char *p;
  int charsPerThousand;
  int groupingIndex;
  int count;

  assert(VALID(self));
  assert(VALID(self->OutStream));
  assert((base >= MIN_BASE && base <= MAX_BASE) || (base == NO_BASE));

  digits = (flags & FLAGS_UPPER) ? globalDigitsUpper : globalDigitsLower;

  if (flags & FLAGS_UNSIGNED)
    isNegative = FALSE;
  else if ((isNegative = (((SLONGEST)number) < 0)))
    number = -number;

  if (flags & FLAGS_QUAD)
    number &= (ULONGLONG)-1;
  else if (flags & FLAGS_LONG)
    number &= (unsigned long)-1;
  else
    number &= (unsigned int)-1;
  
  /* Build number */
  pointer = bufferend = &buffer[sizeof(buffer) - 1];
  *pointer-- = NIL;
  charsPerThousand = (int)globalGrouping[0];
  groupingIndex = 1;
  for (i = 1; i < (int)sizeof(buffer); i++)
    {
      *pointer-- = digits[number % base];
      number /= base;
      if (number == 0)
	break;

      if ((flags & FLAGS_QUOTE)
	  && (charsPerThousand != NO_GROUPING)
	  && (i % charsPerThousand == 0))
	{
	  /*
	   * We are building the number from the least significant
	   * to the most significant digit, so we have to copy the
	   * thousand separator backwards
	   */
	  length = StrLength(globalThousandSeparator);
	  if (((int)(pointer - buffer) - length) > 0)
	    {
	      p = &globalThousandSeparator[length - 1];
	      while (length-- > 0)
		*pointer-- = *p--;
	    }

	  /* Advance to next grouping number */
	  switch (globalGrouping[groupingIndex])
	    {
	    case CHAR_MAX: /* Disable grouping */
	      charsPerThousand = NO_GROUPING;
	      break;
	    case 0: /* Repeat last group */
	      break;
	    default:
	      charsPerThousand = (int)globalGrouping[groupingIndex++];
	      break;
	    }
	}
    }

  /* Adjust width */
  width -= (bufferend - pointer) - 1;

  /* Adjust precision */
  if (NO_PRECISION != precision)
    {
      precision -= (bufferend - pointer) - 1;
      if (precision < 0)
	precision = 0;
      flags |= FLAGS_NILPADDING;
    }

  /* Adjust width further */
  if (isNegative || (flags & FLAGS_SHOWSIGN) || (flags & FLAGS_SPACE))
    width--;
  if (flags & FLAGS_ALTERNATIVE)
    {
      switch (base)
	{
	case BASE_BINARY:
	case BASE_HEX:
	  width -= 2;
	  break;
	case BASE_OCTAL:
	  width--;
	  break;
	default:
	  break;
	}
    }

  /* Output prefixes spaces if needed */
  if (! ((flags & FLAGS_LEFTADJUST) ||
	 ((flags & FLAGS_NILPADDING) && (precision == NO_PRECISION))))
    {
      count = (precision == NO_PRECISION) ? 0 : precision;
      while (width-- > count)
	self->OutStream(self, CHAR_ADJUST);
    }

  /* width has been adjusted for signs and alternatives */
  if (isNegative)
    self->OutStream(self, '-');
  else if (flags & FLAGS_SHOWSIGN)
    self->OutStream(self, '+');
  else if (flags & FLAGS_SPACE)
    self->OutStream(self, ' ');

  if (flags & FLAGS_ALTERNATIVE)
    {
      switch (base)
	{
	case BASE_BINARY:
	  self->OutStream(self, '0');
	  self->OutStream(self, (flags & FLAGS_UPPER) ? 'B' : 'b');
	  break;

	case BASE_OCTAL:
	  self->OutStream(self, '0');
	  break;

	case BASE_HEX:
	  self->OutStream(self, '0');
	  self->OutStream(self, (flags & FLAGS_UPPER) ? 'X' : 'x');
	  break;

	default:
	  break;
	} /* switch base */
    }

  /* Output prefixed zero padding if needed */
  if (flags & FLAGS_NILPADDING)
    {
      if (precision == NO_PRECISION)
	precision = width;
      while (precision-- > 0)
	{
	  self->OutStream(self, '0');
	  width--;
	}
    }

  /* Output the number itself */
  while (*(++pointer))
    {
      self->OutStream(self, *pointer);
    }

  /* Output trailing spaces if needed */
  if (flags & FLAGS_LEFTADJUST)
    {
      while (width-- > 0)
	self->OutStream(self, CHAR_ADJUST);
    }
}

/*************************************************************************
 * TrioWriteString [private]
 *
 * Description:
 *  Output a string
 */
static void
TrioWriteString(trio_T *self,
		const char *string,
		int flags,
		int width,
		int precision)
{
  int length;
  int ch;

  assert(VALID(self));
  assert(VALID(self->OutStream));

  if (string == NULL)
    {
      string = null;
      length = sizeof(null) - 1;
      /* Disable quoting for the null pointer */
      flags &= (~FLAGS_QUOTE);
      width = 0;
    }
  else
    {
      length = StrLength(string);
    }
  if ((NO_PRECISION != precision) &&
      (precision < length))
    {
      length = precision;
    }
  width -= length;

  if (flags & FLAGS_QUOTE)
    self->OutStream(self, CHAR_QUOTE);

  if (! (flags & FLAGS_LEFTADJUST))
    {
      while (width-- > 0)
	self->OutStream(self, CHAR_ADJUST);
    }

  while (length-- > 0)
    {
      /* The ctype parameters must be an unsigned char (or EOF) */
      ch = (unsigned char)(*string++);
      if (flags & FLAGS_ALTERNATIVE)
	{
	  if (! (isprint(ch) || isspace(ch)))
	    {
	      /* Non-printable characters are converted to C escapes or
	       * \number, if no C escape exists.
	       */
	      self->OutStream(self, CHAR_BACKSLASH);
	      switch (ch)
		{
		case '\a': /* alert */
		  self->OutStream(self, 'a');
		  break;
		case '\b': /* backspace */
		  self->OutStream(self, 'b');
		  break;
		case '\f': /* formfeed */
		  self->OutStream(self, 'f');
		  break;
		case '\n': /* newline */
		  self->OutStream(self, 'n');
		  break;
		case '\r': /* carriage return */
		  self->OutStream(self, 'r');
		  break;
		case '\t': /* horizontal tab */
		  self->OutStream(self, 't');
		  break;
		case '\v': /* vertical tab */
		  self->OutStream(self, 'v');
		  break;
		case '\\': /* backslash */
		  self->OutStream(self, '\\');
		  break;
		default: /* the rest */
		  self->OutStream(self, 'x');
		  TrioWriteNumber(self, (ULONGLONG)ch,
				  FLAGS_UNSIGNED | FLAGS_NILPADDING,
				  2, 2, BASE_HEX);
		  break;
		}
	    }
	  else if (ch == CHAR_BACKSLASH)
	    {
	      self->OutStream(self, CHAR_BACKSLASH);
	      self->OutStream(self, CHAR_BACKSLASH);
	    }
	  else
	    {
	      self->OutStream(self, ch);
	    }
	}
      else
	{
	  self->OutStream(self, ch);
	}
    }

  if (flags & FLAGS_LEFTADJUST)
    {
      while (width-- > 0)
	self->OutStream(self, CHAR_ADJUST);
    }
  if (flags & FLAGS_QUOTE)
    self->OutStream(self, CHAR_QUOTE);
}

/*************************************************************************
 * TrioWriteDouble [private]
 */
static void
TrioWriteDouble(trio_T *self,
		long double longdoubleNumber,
		int flags,
		int width,
		int precision,
		int base)
{
  int charsPerThousand;
  int length;
  double number;
  double precisionPower;
  double workNumber;
  int integerDigits;
  int fractionDigits;
  int exponentDigits;
  int visibleDigits;
  int expectedWidth;
  int exponent;
  unsigned int uExponent;
  double dblBase;
  BOOLEAN_T isNegative;
  BOOLEAN_T isExponentNegative = FALSE;
  BOOLEAN_T isHex;
  const char *digits;
  char numberBuffer[MAX_CHARS_IN(double)
		   * MAX_LOCALE_SEPARATOR_LENGTH
		   * MAX_LOCALE_GROUPS];
  char *numberPointer;
  char exponentBuffer[MAX_CHARS_IN(double)];
  char *exponentPointer;
  int groupingIndex;
  char *work;
  int i;
  BOOLEAN_T onlyzero;
  
  assert(VALID(self));
  assert(VALID(self->OutStream));
  assert(base == BASE_DECIMAL || base == BASE_HEX);

  number = (double)longdoubleNumber;
  
#if defined(USE_INFINITE)
  /* Handle infinite numbers and non-a-number first */
  switch (IS_INFINITE(number))
    {
    case 1:
      TrioWriteString(self,
		      (flags & FLAGS_UPPER)
		      ? INFINITE_UPPER
		      : INFINITE_LOWER,
		      flags, width, precision);
      return;

    case -1:
      TrioWriteString(self,
		      (flags & FLAGS_UPPER)
		      ? "-" INFINITE_UPPER
		      : "-" INFINITE_LOWER,
		      flags, width, precision);
      return;

    default:
      break;
    }
#endif
#if defined(USE_NAN)
  if (IS_NAN(number))
    {
      TrioWriteString(self,
		      (flags & FLAGS_UPPER)
		      ? NAN_UPPER
		      : NAN_LOWER,
		      0, 0, 0, 0, 0);
      return;
    }
#endif

  /* Normal numbers */
  digits = (flags & FLAGS_UPPER) ? globalDigitsUpper : globalDigitsLower;
  isHex = (base == BASE_HEX);
  dblBase = (double)base;
  
  if (precision == NO_PRECISION)
    precision = FLT_DIG;
  precisionPower = pow(10.0, (double)precision);
  
  isNegative = (number < 0.0);
  if (isNegative)
    number = -number;
  
  if ((flags & FLAGS_FLOAT_G) || isHex)
    {
      if ((number < 1.0e-4) || (number > precisionPower))
	flags |= FLAGS_FLOAT_E;
#if defined(TRIO_UNIX98)
      if (precision == 0)
	precision = 1;
#endif
    }

  if (flags & FLAGS_FLOAT_E)
    {
      /* Scale the number */
      workNumber = log10(number);
      if (workNumber == -HUGE_VAL)
	{
	  exponent = 0;
	  /* Undo setting */
	  if (flags & FLAGS_FLOAT_G)
	    flags &= ~FLAGS_FLOAT_E;
	}
      else
	{
	  exponent = (int)floor(workNumber);
	  number /= pow(10.0, (double)exponent);
	  isExponentNegative = (exponent < 0);
	  uExponent = (isExponentNegative) ? -exponent : exponent;
	  /* No thousand separators */
	  flags &= ~FLAGS_QUOTE;
	}
    }

  /*
   * Truncated number.
   *
   * precision is number of significant digits for FLOAT_G
   * and number of fractional digits for others
   */
  integerDigits = (number > DBL_EPSILON)
    ? 1 + (int)log10(floor(number))
    : 1;
  fractionDigits = (flags & FLAGS_FLOAT_G)
    ? precision - integerDigits
    : precision;
  number = floor(0.5 + number * pow(10.0, (double)fractionDigits));
  if ((int)log10(number) + 1 > integerDigits + fractionDigits)
    {
      /* Adjust if number was rounded up one digit (ie. 99 to 100) */
      integerDigits++;
    }
  visibleDigits = integerDigits + fractionDigits;
  
  /* Build the fraction part */
  numberPointer = &numberBuffer[sizeof(numberBuffer) - 1];
  *numberPointer = NIL;
  onlyzero = TRUE;
  for (i = 0; i < fractionDigits; i++)
    {
      *(--numberPointer) = digits[(int)fmod(number, dblBase)];
      number = floor(number / dblBase);
      
      /* Prune trailing zeroes */
      if (numberPointer[0] != digits[0])
	onlyzero = FALSE;
      else if (onlyzero && (numberPointer[0] == digits[0]))
	numberPointer++;
    }
  
  /* Insert decimal point */
  if ((flags & FLAGS_ALTERNATIVE) || ((fractionDigits > 0) && !onlyzero))
    {
      i = StrLength(globalDecimalPoint);
      while (i> 0)
	{
	  *(--numberPointer) = globalDecimalPoint[--i];
	}
    }
  /* Insert the integer part and thousand separators */
  charsPerThousand = (int)globalGrouping[0];
  groupingIndex = 1;
  for (i = 1; i < integerDigits + 1; i++)
    {
      *(--numberPointer) = digits[(int)fmod(number, dblBase)];
      number = floor(number / dblBase);
      if (number < DBL_EPSILON)
	break;

      if ((i > 0)
	  && ((flags & (FLAGS_FLOAT_E | FLAGS_QUOTE)) == FLAGS_QUOTE)
	  && (charsPerThousand != NO_GROUPING)
	  && (i % charsPerThousand == 0))
	{
	  /*
	   * We are building the number from the least significant
	   * to the most significant digit, so we have to copy the
	   * thousand separator backwards
	   */
	  length = StrLength(globalThousandSeparator);
	  integerDigits += length;
	  if (((int)(numberPointer - numberBuffer) - length) > 0)
	    {
	      work = &globalThousandSeparator[length - 1];
	      while (length-- > 0)
		*(--numberPointer) = *work--;
	    }

	  /* Advance to next grouping number */
	  if (charsPerThousand != NO_GROUPING)
	    {
	      switch (globalGrouping[groupingIndex])
		{
		case CHAR_MAX: /* Disable grouping */
		  charsPerThousand = NO_GROUPING;
		  break;
		case 0: /* Repeat last group */
		  break;
		default:
		  charsPerThousand = (int)globalGrouping[groupingIndex++];
		  break;
		}
	    }
	}
    }
  
  /* Build the exponent */
  exponentDigits = 0;
  if (flags & FLAGS_FLOAT_E)
    {
      exponentPointer = &exponentBuffer[sizeof(exponentBuffer) - 1];
      *exponentPointer-- = NIL;
      do {
	*exponentPointer-- = digits[uExponent % base];
	uExponent /= base;
	exponentDigits++;
      } while (uExponent);
    }

  /* Calculate expected width.
   *  sign + integer part + thousands separators + decimal point
   *  + fraction + exponent
   */
  expectedWidth = StrLength(numberPointer);
  if (isNegative || (flags & FLAGS_SHOWSIGN))
    expectedWidth += sizeof("-") - 1;
  if (exponentDigits > 0)
    expectedWidth += exponentDigits + sizeof("E+") - 1;
  if (isExponentNegative)
    expectedWidth += sizeof('-') - 1;
  if (isHex)
    expectedWidth += sizeof("0X") - 1;
  
  /* Output prefixing */
  if (flags & FLAGS_NILPADDING)
    {
      /* Leading zeros must be after sign */
      if (isNegative)
	self->OutStream(self, '-');
      else if (flags & FLAGS_SHOWSIGN)
	self->OutStream(self, '+');
      if (isHex)
	{
	  self->OutStream(self, '0');
	  self->OutStream(self, (flags & FLAGS_UPPER) ? 'X' : 'x');
	}
      if (!(flags & FLAGS_LEFTADJUST))
	{
	  for (i = expectedWidth; i < width; i++)
	    {
	      self->OutStream(self, '0');
	    }
	}
    }
  else
    {
      /* Leading spaces must be before sign */
      if (!(flags & FLAGS_LEFTADJUST))
	{
	  for (i = expectedWidth; i < width; i++)
	    {
	      self->OutStream(self, CHAR_ADJUST);
	    }
	}
      if (isNegative)
	self->OutStream(self, '-');
      else if (flags & FLAGS_SHOWSIGN)
	self->OutStream(self, '+');
      if (isHex)
	{
	  self->OutStream(self, '0');
	  self->OutStream(self, (flags & FLAGS_UPPER) ? 'X' : 'x');
	}
    }
  /* Output number */
  for (i = 0; numberPointer[i]; i++)
    {
      self->OutStream(self, numberPointer[i]);
    }
  /* Output exponent */
  if (exponentDigits > 0)
    {
      self->OutStream(self,
		      isHex
		      ? ((flags & FLAGS_UPPER) ? 'P' : 'p')
		      : ((flags & FLAGS_UPPER) ? 'E' : 'e'));
      self->OutStream(self, (isExponentNegative) ? '-' : '+');
      for (i = 0; i < exponentDigits; i++)
	{
	  self->OutStream(self, exponentPointer[i + 1]);
	}
    }
  /* Output trailing spaces */
  if (flags & FLAGS_LEFTADJUST)
    {
      for (i = expectedWidth; i < width; i++)
	{
	  self->OutStream(self, CHAR_ADJUST);
	}
    }
}

/*************************************************************************
 * TrioFormat [private]
 *
 * Description:
 *  This is the main engine for formatting output
 */
static int
TrioFormat(void *destination,
	   size_t destinationSize,
	   void (*OutStream)(trio_T *, int),
	   const char *format,
	   va_list args)
{
#if defined(USE_MULTIBYTE)
  int charlen;
#endif
  int status;
  parameter_T parameters[MAX_PARAMETERS];
  trio_T internalData;
  trio_T *data;
  int i;
  const char *string;
  void *pointer;
  int flags;
  int width;
  int precision;
  int base;
  int index;
  ULONGLONG number;

  assert(VALID(OutStream));
  assert(VALID(format));
  assert(VALID(args));

  /* memset(&parameters, 0, sizeof(parameters)); */
  memset(&internalData, 0, sizeof(internalData));
  data = &internalData;
  data->OutStream = OutStream;
  data->location = destination;
  data->max = destinationSize;

#if defined(USE_LOCALE)
  if (NULL == globalLocaleValues)
    {
      TrioSetLocale();
    }
#endif

  status = TrioPreprocess(TYPE_PRINT, format, parameters, args);
  if (status < 0)
    return status;

  index = 0;
  i = 0;
#if defined(USE_MULTIBYTE)
  mblen(NULL, 0);
#endif
  
  while (format[index])
    {
#if defined(USE_MULTIBYTE)
      if (! isascii(format[index]))
	{
	  charlen = mblen(&format[index], MB_LEN_MAX);
	  while (charlen-- > 0)
	    {
	      OutStream(data, format[index++]);
	    }
	  continue; /* while */
	}
#endif
      if (CHAR_IDENTIFIER == format[index])
	{
	  if (CHAR_IDENTIFIER == format[index + 1])
	    {
	      OutStream(data, CHAR_IDENTIFIER);
	      index += 2;
	    }
	  else
	    {
	      /* Skip the parameter entries */
	      while (parameters[i].type == FORMAT_PARAMETER)
		i++;
	      
	      flags = parameters[i].flags;

	      /* Find width */
	      width = parameters[i].width;
	      if (flags & FLAGS_WIDTH_PARAMETER)
		{
		  /* Get width from parameter list */
		  width = (int)parameters[width].data.number.asSigned;
		}
	      
	      /* Find precision */
	      if (flags & FLAGS_PRECISION)
		{
		  precision = parameters[i].precision;
		  if (flags & FLAGS_PRECISION_PARAMETER)
		    {
		      /* Get precision from parameter list */
		      precision = (int)parameters[precision].data.number.asSigned;
		    }
		}
	      else
		{
		  precision = NO_PRECISION;
		}

	      /* Find base */
	      base = parameters[i].base;
	      if (flags & FLAGS_BASE_PARAMETER)
		{
		  /* Get base from parameter list */
		  base = (int)parameters[base].data.number.asSigned;
		}
	      
	      switch (parameters[i].type)
		{
		case FORMAT_CHAR:
		  if (flags & FLAGS_QUOTE)
		    OutStream(data, CHAR_QUOTE);
		  if (! (flags & FLAGS_LEFTADJUST))
		    {
		      while (--width > 0)
			OutStream(data, CHAR_ADJUST);
		    }

		  OutStream(data, (char)parameters[i].data.number.asSigned);

		  if (flags & FLAGS_LEFTADJUST)
		    {
		      while(--width > 0)
			OutStream(data, CHAR_ADJUST);
		    }
		  if (flags & FLAGS_QUOTE)
		    OutStream(data, CHAR_QUOTE);

		  break; /* FORMAT_CHAR */

		case FORMAT_INT:
		  if (base == NO_BASE)
		    base = BASE_DECIMAL;

		  TrioWriteNumber(data,
				  parameters[i].data.number.asUnsigned,
				  flags,
				  width,
				  precision,
				  base);

		  break; /* FORMAT_INT */

		case FORMAT_DOUBLE:
		  TrioWriteDouble(data,
				  parameters[i].data.longdoubleNumber,
				  flags,
				  width,
				  precision,
				  base);
		  break; /* FORMAT_DOUBLE */

		case FORMAT_STRING:
		  TrioWriteString(data,
				  parameters[i].data.string,
				  flags,
				  width,
				  precision);
		  break; /* FORMAT_STRING */

		case FORMAT_POINTER:
		  pointer = parameters[i].data.pointer;
		  if (NULL == pointer)
		    {
		      string = null;
		      while (*string)
			OutStream(data, *string++);
		    }
		  else
		    {
		      /* The subtraction of the null pointer is a workaround
		       * to avoid a compiler warning. The performance overhead
		       * is negligible (and likely to be removed by an
		       * optimising compiler). The (char *) casting is done
		       * to please ANSI C++.
		       */
		      number = (ULONGLONG)((char *)parameters[i].data.pointer
					   - (char *)0);
		      /* Shrink to size of pointer */
		      number &= (ULONGLONG)-1;
		      flags |= (FLAGS_UNSIGNED | FLAGS_ALTERNATIVE |
				FLAGS_NILPADDING);
		      TrioWriteNumber(data,
				      number,
				      flags,
				      POINTER_WIDTH,
				      precision,
				      BASE_HEX);
		    }
		  break; /* FORMAT_POINTER */

		case FORMAT_COUNT:
		  pointer = parameters[i].data.pointer;
		  if (NULL != pointer)
		    {
		      /* C99 paragraph 7.19.6.1.8 says "the number of
		       * characters written to the output stream so far by
		       * this call", which is data->committed
		       */
#if defined(QUALIFIER_SIZE_T) || defined(QUALIFIER_SIZE_T_UPPER)
		      if (flags & FLAGS_SIZE_T)
			*(size_t *)pointer = (size_t)data->committed;
		      else
#endif
#if defined(QUALIFIER_PTRDIFF_T)
		      if (flags & FLAGS_PTRDIFF_T)
			*(ptrdiff_t *)pointer = (ptrdiff_t)data->committed;
		      else
#endif
#if defined(QUALIFIER_INTMAX_T)
		      if (flags & FLAGS_INTMAX_T)
			*(intmax_t *)pointer = (intmax_t)data->committed;
		      else
#endif
		      if (flags & FLAGS_QUAD)
			{
			  *(ULONGLONG int *)pointer = (ULONGLONG)data->committed;
			}
		      else if (flags & FLAGS_LONG)
			{
			  *(long int *)pointer = (long int)data->committed;
			}
		      else if (flags & FLAGS_SHORT)
			{
			  *(short int *)pointer = (short int)data->committed;
			}
		      else
			{
			  *(int *)pointer = (int)data->committed;
			}
		    }
		  break; /* FORMAT_COUNT */

		case FORMAT_PARAMETER:
		  break; /* FORMAT_PARAMETER */

#if defined(FORMAT_ERRNO)
		case FORMAT_ERRNO:
		  string = StrError(parameters[i].data.errorNumber);
		  if (string)
		    {
		      TrioWriteString(data,
				      string,
				      flags,
				      width,
				      precision);
		    }
		  else
		    {
		      OutStream(data, '#');
		      TrioWriteNumber(data,
				      (LONGEST)parameters[i].data.errorNumber,
				      flags,
				      width,
				      precision,
				      BASE_DECIMAL);
		    }
		  break; /* FORMAT_ERRNO */
#endif

		default:
		  break;
		} /* switch parameter type */

	      /* Prepare for next */
	      index = parameters[i].indexAfterSpecifier;
	      i++;
	    }
	}
      else /* not identifier */
	{
	  OutStream(data, format[index++]);
	}
    }

  return data->processed;
}

/*************************************************************************
 * TrioOutStreamFile [private]
 */
static void
TrioOutStreamFile(trio_T *self, int output)
{
  FILE *file = (FILE *)self->location;

  assert(VALID(self));
  assert(VALID(file));

  self->processed++;
  self->committed++;
  (void)fputc(output, file);
}

/*************************************************************************
 * TrioOutStreamFileDescriptor [private]
 */
static void
TrioOutStreamFileDescriptor(trio_T *self, int output)
{
  int fd = *((int *)self->location);
  char ch;

  assert(VALID(self));

  ch = (char)output;
  (void)write(fd, &ch, sizeof(char));
  self->processed++;
  self->committed++;
}

/*************************************************************************
 * TrioOutStreamString [private]
 */
static void
TrioOutStreamString(trio_T *self, int output)
{
  char **buffer = (char **)self->location;

  assert(VALID(self));
  assert(VALID(buffer));

  **buffer = (char)output;
  (*buffer)++;
  self->processed++;
  self->committed++;
}

/*************************************************************************
 * TrioOutStreamStringMax [private]
 */
static void
TrioOutStreamStringMax(trio_T *self, int output)
{
  char **buffer;

  assert(VALID(self));
  buffer = (char **)self->location;
  assert(VALID(buffer));

  if (self->processed < self->max)
    {
      **buffer = (char)output;
      (*buffer)++;
      self->committed++;
    }
  self->processed++;
}

/*************************************************************************
 * TrioOutStreamStringDynamic [private]
 */
#define DYNAMIC_START_SIZE 32
struct dynamicBuffer {
  char *buffer;
  size_t length;
  size_t allocated;
};

static void
TrioOutStreamStringDynamic(trio_T *self, int output)
{
  struct dynamicBuffer *infop;
  
  assert(VALID(self));
  assert(VALID(self->location));

  infop = (struct dynamicBuffer *)self->location;

  if (infop->buffer == NULL)
    {
      /* Start with a reasonable size */
      infop->buffer = (char *)malloc(DYNAMIC_START_SIZE);
      if (infop->buffer == NULL)
	return; /* fail */
      
      infop->allocated = DYNAMIC_START_SIZE;
      self->processed = 0;
      self->committed = 0;
    }
  else if (self->committed + sizeof(NIL) >= infop->allocated)
    {
      char *newptr;
      
      /* Allocate increasing chunks */
      newptr = (char *)realloc(infop->buffer, infop->allocated * 2);
      
      if (newptr == NULL)
	return;

      infop->buffer = newptr;
      infop->allocated *= 2;
    }
  
  infop->buffer[self->committed] = output;
  self->committed++;
  self->processed++;
  
  infop->length = self->committed;
}

#ifndef HAVE_PRINTF
/*************************************************************************
 * trio_printf
 */
int
printf(const char *format, ...)
{
  int status;
  va_list args;

  assert(VALID(format));
  
  va_start(args, format);
  status = TrioFormat(stdout, 0, TrioOutStreamFile, format, args);
  va_end(args);
  return status;
}
#endif

#ifndef HAVE_FPRINTF
/*************************************************************************
 * trio_fprintf
 */
int
fprintf(FILE *file, const char *format, ...)
{
  int status;
  va_list args;

  assert(VALID(file));
  assert(VALID(format));
  
  va_start(args, format);
  status = TrioFormat(file, 0, TrioOutStreamFile, format, args);
  va_end(args);
  return status;
}
#endif

#ifndef HAVE_VFPRINTF
/*************************************************************************
 * trio_vfprintf
 */
int
vfprintf(FILE *file, const char *format, va_list args)
{
  assert(VALID(file));
  assert(VALID(format));
  assert(VALID(args));
  
  return TrioFormat(file, 0, TrioOutStreamFile, format, args);
}
#endif

#ifndef HAVE_SPRINTF
/*************************************************************************
 * trio_sprintf
 */
int
sprintf(char *buffer, const char *format, ...)
{
  int status;
  va_list args;

  assert(VALID(buffer));
  assert(VALID(format));
  
  va_start(args, format);
  status = TrioFormat(&buffer, 0, TrioOutStreamString, format, args);
  *buffer = NIL; /* Terminate with NIL character */
  va_end(args);
  return status;
}
#endif

#ifndef HAVE_VSPRINTF
/*************************************************************************
 * trio_vsprintf
 */
int
vsprintf(char *buffer, const char *format, va_list args)
{
  int status;

  assert(VALID(buffer));
  assert(VALID(format));
  assert(VALID(args));

  status = TrioFormat(&buffer, 0, TrioOutStreamString, format, args);
  *buffer = NIL;
  return status;
}
#endif

#ifndef HAVE_SNPRINTF
/*************************************************************************
 * trio_snprintf
 */
int
snprintf(char *buffer, size_t bufferSize, const char *format, ...)
{
  int status;
  va_list args;

  assert(VALID(buffer));
  assert(VALID(format));

  va_start(args, format);
  status = TrioFormat(&buffer, bufferSize > 0 ? bufferSize - 1 : 0,
		      TrioOutStreamStringMax, format, args);
  if (bufferSize > 0)
    *buffer = NIL;
  va_end(args);
  return status;
}
#endif

#ifndef  HAVE_VSNPRINTF
/*************************************************************************
 * trio_vsnprintf
 */
int
vsnprintf(char *buffer, size_t bufferSize, const char *format,
	       va_list args)
{
  int status;

  assert(VALID(buffer));
  assert(VALID(format));
  assert(VALID(args));

  status = TrioFormat(&buffer, bufferSize > 0 ? bufferSize - 1 : 0,
		      TrioOutStreamStringMax, format, args);
  if (bufferSize > 0)
    *buffer = NIL;
  return status;
}
#endif

/*************************************************************************
 *
 * SCANNING
 *
 ************************************************************************/

/* DV for libxml */
#ifndef HAVE_SSCANF

/*************************************************************************
 * TrioSkipWhitespaces [private]
 */
static int
TrioSkipWhitespaces(trio_T *self)
{
  int ch;

  ch = self->current;
  while (isspace(ch))
    {
      self->InStream(self, &ch);
    }
  return ch;
}

/*************************************************************************
 * TrioGetCharacterClass [private]
 *
 * FIXME:
 *  multibyte
 */
static int
TrioGetCharacterClass(const char *format,
		      int *indexPointer,
		      int *flagsPointer,
		      int *characterclass)
{
  int index = *indexPointer;
  int i;
  char ch;
  char range_begin;
  char range_end;

  *flagsPointer &= ~FLAGS_EXCLUDE;

  if (format[index] == QUALIFIER_CIRCUMFLEX)
    {
      *flagsPointer |= FLAGS_EXCLUDE;
      index++;
    }
  /* If the ungroup character is at the beginning of the scanlist,
   * it will be part of the class, and a second ungroup character
   * must follow to end the group.
   */
  if (format[index] == SPECIFIER_UNGROUP)
    {
      characterclass[(int)SPECIFIER_UNGROUP]++;
      index++;
    }
  /* Minus is used to specify ranges. To include minus in the class,
   * it must be at the beginning of the list
   */
  if (format[index] == QUALIFIER_MINUS)
    {
      characterclass[(int)QUALIFIER_MINUS]++;
      index++;
    }
  /* Collect characters */
  for (ch = format[index];
       ch != SPECIFIER_UNGROUP && ch != NIL;
       ch = format[++index])
    {
      switch (ch)
	{
	case QUALIFIER_MINUS: /* Scanlist ranges */
	  
	  /* Both C99 and UNIX98 describes ranges as implementation-
	   * defined.
	   *
	   * We support the following behaviour (although this may
	   * change as we become wiser)
	   * - only increasing ranges, ie. [a-b] but not [b-a]
	   * - transitive ranges, ie. [a-b-c] == [a-c]
	   * - trailing minus, ie. [a-] is interpreted as an 'a'
	   *   and a '-'
	   * - duplicates (although we can easily convert these
	   *   into errors)
	   */
	  range_begin = format[index - 1];
	  range_end = format[++index];
	  if (range_end == SPECIFIER_UNGROUP)
	    {
	      /* Trailing minus is included */
	      characterclass[(int)ch]++;
	      ch = range_end;
	      break; /* for */
	    }
	  if (range_end == NIL)
	    return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
	  if (range_begin > range_end)
	    return TRIO_ERROR_RETURN(TRIO_ERANGE, index);
	    
	  for (i = (int)range_begin; i <= (int)range_end; i++)
	    characterclass[i]++;
	    
	  ch = range_end;
	  break;

	case QUALIFIER_COLON: /* Character class expressions */
	  
	  if (StrEqualMax(CLASS_ALNUM, sizeof(CLASS_ALNUM) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isalnum(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_ALNUM) - 1;
	    }
	  else if (StrEqualMax(CLASS_ALPHA, sizeof(CLASS_ALPHA) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isalpha(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_ALPHA) - 1;
	    }
	  else if (StrEqualMax(CLASS_CNTRL, sizeof(CLASS_CNTRL) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (iscntrl(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_CNTRL) - 1;
	    }
	  else if (StrEqualMax(CLASS_DIGIT, sizeof(CLASS_DIGIT) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isdigit(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_DIGIT) - 1;
	    }
	  else if (StrEqualMax(CLASS_GRAPH, sizeof(CLASS_GRAPH) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isgraph(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_GRAPH) - 1;
	    }
	  else if (StrEqualMax(CLASS_LOWER, sizeof(CLASS_LOWER) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (islower(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_LOWER) - 1;
	    }
	  else if (StrEqualMax(CLASS_PRINT, sizeof(CLASS_PRINT) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isprint(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_PRINT) - 1;
	    }
	  else if (StrEqualMax(CLASS_PUNCT, sizeof(CLASS_PUNCT) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (ispunct(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_PUNCT) - 1;
	    }
	  else if (StrEqualMax(CLASS_SPACE, sizeof(CLASS_SPACE) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isspace(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_SPACE) - 1;
	    }
	  else if (StrEqualMax(CLASS_UPPER, sizeof(CLASS_UPPER) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isupper(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_UPPER) - 1;
	    }
	  else if (StrEqualMax(CLASS_XDIGIT, sizeof(CLASS_XDIGIT) - 1,
			  &format[index]))
	    {
	      for (i = 0; i < MAX_CHARACTER_CLASS; i++)
		if (isxdigit(i))
		  characterclass[i]++;
	      index += sizeof(CLASS_XDIGIT) - 1;
	    }
	  else
	    {
	      characterclass[(int)ch]++;
	    }
	  break;

	default:
	  characterclass[(int)ch]++;
	  break;
	}
    }
  return 0;
}

/*************************************************************************
 * TrioReadNumber [private]
 *
 * We implement our own number conversion in preference of strtol and
 * strtoul, because we must handle 'long long' and thousand separators.
 */
static BOOLEAN_T
TrioReadNumber(trio_T *self, LONGEST *target, int flags, int width, int base)
{
  LONGEST number = 0;
  int digit;
  int count;
  BOOLEAN_T isNegative = FALSE;
  int j;

  assert(VALID(self));
  assert(VALID(self->InStream));
  assert((base >= MIN_BASE && base <= MAX_BASE) || (base == NO_BASE));

  TrioSkipWhitespaces(self);
  
  if (!(flags & FLAGS_UNSIGNED))
    {
      /* Leading sign */
      if (self->current == '+')
	{
	  self->InStream(self, NULL);
	}
      else if (self->current == '-')
	{
	  self->InStream(self, NULL);
	  isNegative = TRUE;
	}
    }
  
  count = self->processed;
  
  if (flags & FLAGS_ALTERNATIVE)
    {
      switch (base)
	{
	case NO_BASE:
	case BASE_OCTAL:
	case BASE_HEX:
	case BASE_BINARY:
	  if (self->current == '0')
	    {
	      self->InStream(self, NULL);
	      if (self->current)
		{
		  if ((base == BASE_HEX) &&
		      (toupper(self->current) == 'X'))
		    {
		      self->InStream(self, NULL);
		    }
		  else if ((base == BASE_BINARY) &&
			   (toupper(self->current) == 'B'))
		    {
		      self->InStream(self, NULL);
		    }
		}
	    }
	  else
	    return FALSE;
	  break;
	default:
	  break;
	}
    }

  while (((width == NO_WIDTH) || (self->processed - count < width)) &&
	 (! ((self->current == EOF) || isspace(self->current))))
    {
      if (isascii(self->current))
	{
	  digit = globalDigitArray[self->current];
	  /* Abort if digit is not allowed in the specified base */
	  if ((digit == -1) || (digit >= base))
	    break;
	}
      else if (flags & FLAGS_QUOTE)
	{
	  /* Compare with thousands separator */
	  for (j = 0; globalThousandSeparator[j] && self->current; j++)
	    {
	      if (globalThousandSeparator[j] != self->current)
		break;

	      self->InStream(self, NULL);
	    }
	  if (globalThousandSeparator[j])
	    break; /* Mismatch */
	  else
	    continue; /* Match */
	}
      else
	break;
            
      number *= base;
      number += digit;

      self->InStream(self, NULL);
    }

  /* Was anything read at all? */
  if (self->processed == count)
    return FALSE;
  
  if (target)
    *target = (isNegative) ? -number : number;
  return TRUE;
}

/*************************************************************************
 * TrioReadChar [private]
 */
static BOOLEAN_T
TrioReadChar(trio_T *self, char *target, int width)
{
  int i;
  
  assert(VALID(self));
  assert(VALID(self->InStream));

  for (i = 0;
       (self->current != EOF) && (i < width);
       i++)
    {
      if (target)
	target[i] = self->current;
      self->InStream(self, NULL);
    }
  return TRUE;
}

/*************************************************************************
 * TrioReadString [private]
 */
static BOOLEAN_T
TrioReadString(trio_T *self, char *target, int flags, int width)
{
  int i;
  char ch;
  LONGEST number;
  
  assert(VALID(self));
  assert(VALID(self->InStream));

  TrioSkipWhitespaces(self);
    
  /* Continue until end of string is reached, a whitespace is encountered,
   * or width is exceeded
   */
  for (i = 0;
       ((width == NO_WIDTH) || (i < width)) &&
       (! ((self->current == EOF) || isspace(self->current)));
       i++)
    {
      ch = self->current;
      if ((flags & FLAGS_ALTERNATIVE) && (ch == CHAR_BACKSLASH))
	{
	  self->InStream(self, NULL);
	  switch (self->current)
	    {
	    case 'a':
	      ch = '\a';
	      break;
	    case 'b':
	      ch = '\b';
	      break;
	    case 'f':
	      ch = '\f';
	      break;
	    case 'n':
	      ch = '\n';
	      break;
	    case 'r':
	      ch = '\r';
	      break;
	    case 't':
	      ch = '\t';
	      break;
	    case 'v':
	      ch = '\v';
	      break;
	    case '\\':
	      ch = '\\';
	      break;
	    default:
	      if (isdigit(self->current))
		{
		  /* Read octal number */
		  if (!TrioReadNumber(self, &number, 0, 3, BASE_OCTAL))
		    return FALSE;
		  ch = (char)number;
		}
	      else if (toupper(self->current) == 'X')
		{
		  /* Read hexadecimal number */
		  self->InStream(self, NULL);
		  if (!TrioReadNumber(self, &number, 0, 2, BASE_HEX))
		    return FALSE;
		  ch = (char)number;
		}
	      else
		{
		  ch = self->current;
		}
	      break;
	    }
	}
      if (target)
	target[i] = ch;
      self->InStream(self, NULL);
    }
  if (target)
    target[i] = NIL;
  return TRUE;
}

/*************************************************************************
 * TrioReadGroup [private]
 *
 * FIXME: characterclass does not work with multibyte characters
 */
static BOOLEAN_T
TrioReadGroup(trio_T *self,
	      char *target,
	      int *characterclass,
	      int flags,
	      int width)
{
  unsigned int ch;
  int i;
  
  assert(VALID(self));
  assert(VALID(self->InStream));

  ch = self->current;
  for (i = 0;
       ((width == NO_WIDTH) || (i < width)) &&
       (! ((ch == EOF) ||
	   (((flags & FLAGS_EXCLUDE) != 0) ^ (characterclass[ch] == 0))));
       i++)
    {
      if (target)
	target[i] = (char)ch;
      self->InStream(self, &ch);
    }
  
  if (target)
    target[i] = NIL;
  return TRUE;
}

/*************************************************************************
 * TrioReadDouble [private]
 *
 * FIXME:
 *  add hex-float format
 *  add long double
 */
static BOOLEAN_T
TrioReadDouble(trio_T *self,
	       double *target,
	       int flags,
	       int width)
{
  int ch;
  char doubleString[512] = "";
  int index = 0;
  int start;

  if ((width == NO_WIDTH) || (width > sizeof(doubleString) - 1))
    width = sizeof(doubleString) - 1;
  
  TrioSkipWhitespaces(self);
  
  /* Read entire double number from stream. StrToDouble requires a
   * string as input, but InStream can be anything, so we have to
   * collect all characters.
   */
  ch = self->current;
  if ((ch == '+') || (ch == '-'))
    {
      doubleString[index++] = ch;
      self->InStream(self, &ch);
      width--;
    }

  start = index;
#if defined(USE_INFINITE) || defined(USE_NAN)
  switch (ch)
    {
#if defined(USE_NAN)
    case 'n':
    case 'N':
      /* Not-a-number */
      if (index != 0)
	break;
      /* FALLTHROUGH */
#endif
    case 'i':
    case 'I':
      /* Infinity */
      while (isalpha(ch) && (index - start < width))
	{
	  doubleString[index++] = ch;
	  self->InStream(self, &ch);
	}
      doubleString[index] = NIL;

#if defined(USE_INFINITE)
      /* Case insensitive string comparison */
      if (StrEqual(&doubleString[start], INFINITE_UPPER) ||
	  StrEqual(&doubleString[start], LONG_INFINITE_UPPER))
	{
	  *target = ((start == 1 && doubleString[0] == '-'))
	    ? -HUGE_VAL
	    : HUGE_VAL;
	  return TRUE;
	}
#endif
#if defined(USE_NAN)
      if (StrEqual(doubleString, NAN_LOWER))
	{
	  /* NaN must not have a preceeding + nor - */
	  *target = NAN;
	  return TRUE;
	}
#endif
      return FALSE;
      
    default:
      break;
    }
#endif
  
  while (isdigit(ch) && (index - start < width))
    {
      /* Integer part */
      doubleString[index++] = ch;
      self->InStream(self, &ch);
    }
  if (ch == '.')
    {
      /* Decimal part */
      doubleString[index++] = ch;
      self->InStream(self, &ch);
      while (isdigit(ch) && (index - start < width))
	{
	  doubleString[index++] = ch;
	  self->InStream(self, &ch);
	}
      if ((ch == 'e') || (ch == 'E'))
	{
	  /* Exponent */
	  doubleString[index++] = ch;
	  self->InStream(self, &ch);
	  if ((ch == '+') || (ch == '-'))
	    {
	      doubleString[index++] = ch;
	      self->InStream(self, &ch);
	    }
	  while (isdigit(ch) && (index - start < width))
	    {
	      doubleString[index++] = ch;
	      self->InStream(self, &ch);
	    }
	}
    }

  if ((index == start) || (*doubleString == NIL))
    return FALSE;
  
  if (flags & FLAGS_LONGDOUBLE)
/*     *longdoublePointer = StrToLongDouble()*/;
  else
    {
      *target = StrToDouble(doubleString, NULL);
    }
  return TRUE;
}

/*************************************************************************
 * TrioReadPointer [private]
 */
static BOOLEAN_T
TrioReadPointer(trio_T *self, void **target, int flags)
{
  LONGEST number;
  char buffer[sizeof(null)];

  flags |= (FLAGS_UNSIGNED | FLAGS_ALTERNATIVE | FLAGS_NILPADDING);
  
  if (TrioReadNumber(self,
		     &number,
		     flags,
		     POINTER_WIDTH,
		     BASE_HEX))
    {
      /* The addition is a workaround for a compiler warning */
      if (target)
	*target = (void *)0 + number;
      return TRUE;
    }
  else if (TrioReadString(self,
			  (flags & FLAGS_IGNORE)
			  ? NULL
			  : buffer,
			  0,
			  sizeof(null) - 1))
    {  
      if (StrEqualCase(buffer, null))
	{
	  if (target)
	    *target = NULL;
	  return TRUE;
	}
    }
  return FALSE;
}

/*************************************************************************
 * TrioScan [private]
 */
static int
TrioScan(void *source,
	 size_t sourceSize,
	 void (*InStream)(trio_T *, int *),
	 const char *format,
	 va_list args)
{
#if defined(USE_MULTIBYTE)
  int charlen;
#endif
  int status;
  int assignment;
  parameter_T parameters[MAX_PARAMETERS];
  trio_T internalData;
  trio_T *data;
  int ch;
  int cnt;
  int index; /* Index of format string */
  int i; /* Index of current parameter */
  int flags;
  int width;
  int base;
  void *pointer;

  assert(VALID(InStream));
  assert(VALID(format));
  assert(VALID(args));

  memset(&internalData, 0, sizeof(internalData));
  data = &internalData;
  data->InStream = InStream;
  data->location = source;
  data->max = sourceSize;

#if defined(USE_LOCALE)
  if (NULL == globalLocaleValues)
    {
      TrioSetLocale();
    }
#endif
  if (globalDigitsUnconverted)
    {
      memset(globalDigitArray, -1, sizeof(globalDigitArray));
      for (i = 0; i < sizeof(globalDigitsLower) - 1; i++)
	{
	  globalDigitArray[(int)globalDigitsLower[i]] = i;
	  globalDigitArray[(int)globalDigitsUpper[i]] = i;
	}
      globalDigitsUnconverted = FALSE;
    }
  
  status = TrioPreprocess(TYPE_SCAN, format, parameters, args);
  if (status < 0)
    return status;

  assignment = 0;
  i = 0;
  index = 0;
  data->InStream(data, &ch);

#if defined(USE_MULTIBYTE)
  mblen(NULL, 0);
#endif

  while (format[index])
    {
#if defined(USE_MULTIBYTE)
      if (! isascii(format[index]))
	{
	  charlen = mblen(&format[index], MB_LEN_MAX);
	  /* Compare multibyte characters in format string */
	  for (cnt = 0; cnt < charlen - 1; cnt++)
	    {
	      if (ch != format[index + cnt])
		{
		  return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
		}
	      data->InStream(data, &ch);
	    }
	  continue; /* while */
	}
#endif
      if (EOF == ch)
	return EOF;
      
      if (CHAR_IDENTIFIER == format[index])
	{
	  if (CHAR_IDENTIFIER == format[index + 1])
	    {
	      /* Two % in format matches one % in input stream */
	      if (CHAR_IDENTIFIER == ch)
		{
		  data->InStream(data, &ch);
		  index += 2;
		  continue; /* while format chars left */
		}
	      else
		return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
	    }

	  /* Skip the parameter entries */
	  while (parameters[i].type == FORMAT_PARAMETER)
	    i++;
	  
	  flags = parameters[i].flags;
	  /* Find width */
	  width = parameters[i].width;
	  if (flags & FLAGS_WIDTH_PARAMETER)
	    {
	      /* Get width from parameter list */
	      width = (int)parameters[width].data.number.asSigned;
	    }
	  /* Find base */
	  base = parameters[i].base;
	  if (flags & FLAGS_BASE_PARAMETER)
	    {
	      /* Get base from parameter list */
	      base = (int)parameters[base].data.number.asSigned;
	    }
	  
	  switch (parameters[i].type)
	    {
	    case FORMAT_INT:
	      {
		LONGEST number;

		if (0 == base)
		  base = BASE_DECIMAL;

		if (!TrioReadNumber(data,
				    &number,
				    flags,
				    width,
				    base))
		  return assignment;
		assignment++;
		
		if (!(flags & FLAGS_IGNORE))
		  {
		    pointer = parameters[i].data.pointer;
#if defined(QUALIFIER_SIZE_T) || defined(QUALIFIER_SIZE_T_UPPER)
		    if (flags & FLAGS_SIZE_T)
		      *(size_t *)pointer = (size_t)number;
		    else
#endif
#if defined(QUALIFIER_PTRDIFF_T)
		    if (flags & FLAGS_PTRDIFF_T)
		      *(ptrdiff_t *)pointer = (ptrdiff_t)number;
		    else
#endif
#if defined(QUALIFIER_INTMAX_T)
		    if (flags & FLAGS_INTMAX_T)
		      *(intmax_t *)pointer = (intmax_t)number;
		    else
#endif
		    if (flags & FLAGS_QUAD)
		      *(ULONGLONG int *)pointer = (ULONGLONG)number;
		    else if (flags & FLAGS_LONG)
		      *(long int *)pointer = (long int)number;
		    else if (flags & FLAGS_SHORT)
		      *(short int *)pointer = (short int)number;
		    else
		      *(int *)pointer = (int)number;
		  }
	      }
	      break; /* FORMAT_INT */
	      
	    case FORMAT_STRING:
	      if (!TrioReadString(data,
				  (flags & FLAGS_IGNORE)
				  ? NULL
				  : parameters[i].data.string,
				  flags,
				  width))
		return assignment;
	      assignment++;
	      break; /* FORMAT_STRING */
	      
	    case FORMAT_DOUBLE:
	      if (!TrioReadDouble(data,
				  (flags & FLAGS_IGNORE)
				  ? NULL
				  : parameters[i].data.doublePointer,
				  flags,
				  width))
		return assignment;
	      assignment++;
	      break; /* FORMAT_DOUBLE */

	    case FORMAT_GROUP:
	      {
		int characterclass[MAX_CHARACTER_CLASS + 1];
		int rc;
		
		index += 2;
		memset(characterclass, 0, sizeof(characterclass));
		rc = TrioGetCharacterClass(format, &index, &flags,
					   characterclass);
		if (rc < 0)
		  return rc;

		if (!TrioReadGroup(data,
				   (flags & FLAGS_IGNORE)
				   ? NULL
				   : parameters[i].data.string,
				   characterclass,
				   flags,
				   parameters[i].width))
		  return assignment;
		assignment++;
	      }
	      break; /* FORMAT_GROUP */
	      
	    case FORMAT_COUNT:
	      pointer = parameters[i].data.pointer;
	      if (NULL != pointer)
		{
#if defined(QUALIFIER_SIZE_T) || defined(QUALIFIER_SIZE_T_UPPER)
		  if (flags & FLAGS_SIZE_T)
		    *(size_t *)pointer = (size_t)data->committed;
		  else
#endif
#if defined(QUALIFIER_PTRDIFF_T)
		  if (flags & FLAGS_PTRDIFF_T)
		    *(ptrdiff_t *)pointer = (ptrdiff_t)data->committed;
		  else
#endif
#if defined(QUALIFIER_INTMAX_T)
		  if (flags & FLAGS_INTMAX_T)
		    *(intmax_t *)pointer = (intmax_t)data->committed;
		  else
#endif
		  if (flags & FLAGS_QUAD)
		    {
		      *(ULONGLONG int *)pointer = (ULONGLONG)data->committed;
		    }
		  else if (flags & FLAGS_LONG)
		    {
		      *(long int *)pointer = (long int)data->committed;
		    }
		  else if (flags & FLAGS_SHORT)
		    {
		      *(short int *)pointer = (short int)data->committed;
		    }
		  else
		    {
		      *(int *)pointer = (int)data->committed;
		    }
		}
	      break; /* FORMAT_COUNT */
	      
	    case FORMAT_CHAR:
	      if (!TrioReadChar(data,
				(flags & FLAGS_IGNORE)
				? NULL
				: parameters[i].data.string,
				(width == NO_WIDTH) ? 1 : width))
		return assignment;
	      assignment++;
	      break; /* FORMAT_CHAR */
	      
	    case FORMAT_POINTER:
	      if (!TrioReadPointer(data,
				   (flags & FLAGS_IGNORE)
				   ? NULL
				   : parameters[i].data.pointer,
				   flags))
		return assignment;
	      assignment++;
	      break; /* FORMAT_POINTER */
	      
	    case FORMAT_PARAMETER:
	      break; /* FORMAT_PARAMETER */
	      
	    default:
	      return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
	    }
	  ch = data->current;
	  index = parameters[i].indexAfterSpecifier;
	  i++;
	}
      else /* Not an % identifier */
	{
	  if (isspace((int)format[index]))
	    {
	      /* Whitespaces may match any amount of whitespaces */
	      ch = TrioSkipWhitespaces(data);
	    }
	  else if (ch == format[index])
	    {
	      data->InStream(data, &ch);
	    }
	  else
	    return TRIO_ERROR_RETURN(TRIO_EINVAL, index);
	  
	  index++;
	}
    }
  return assignment;
}

/*************************************************************************
 * TrioInStreamFile [private]
 */
static void
TrioInStreamFile(trio_T *self, int *intPointer)
{
  FILE *file = (FILE *)self->location;

  assert(VALID(self));
  assert(VALID(file));

  self->current = fgetc(file);
  self->processed++;
  self->committed++;
  
  if (VALID(intPointer))
    {
      *intPointer = self->current;
    }
}

/*************************************************************************
 * TrioInStreamFileDescriptor [private]
 */
static void
TrioInStreamFileDescriptor(trio_T *self, int *intPointer)
{
  int fd = *((int *)self->location);
  int size;
  unsigned char input;

  assert(VALID(self));

  size = read(fd, &input, sizeof(char));
  self->current = (size == 0) ? EOF : input;
  self->processed++;
  self->committed++;
  
  if (VALID(intPointer))
    {
      *intPointer = self->current;
    }
}

/*************************************************************************
 * TrioInStreamString [private]
 */
static void
TrioInStreamString(trio_T *self, int *intPointer)
{
  unsigned char **buffer;

  assert(VALID(self));
  assert(VALID(self->InStream));
  assert(VALID(self->location));

  buffer = (unsigned char **)self->location;
  self->current = (*buffer)[0];
  if (self->current == NIL)
    self->current = EOF;
  (*buffer)++;
  self->processed++;
  self->committed++;
  
  if (VALID(intPointer))
    {
      *intPointer = self->current;
    }
}

/*************************************************************************
 * trio_sscanf
 */
int
sscanf(const char *buffer, const char *format, ...)
{
  int status;
  va_list args;

  assert(VALID(buffer));
  assert(VALID(format));
  
  va_start(args, format);
  status = TrioScan(&buffer, 0, TrioInStreamString, format, args);
  va_end(args);
  return status;
}

/* DV for libxml */
#endif /* !HAVE_SSCANF */
#endif /* WITH_TRIO */
