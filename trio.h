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
 ************************************************************************/

#ifndef H_TRIO
#define H_TRIO

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

/*
 * Error codes.
 *
 * Remember to add a textual description to trio_strerror.
 */
enum {
  TRIO_EOF      = 1,
  TRIO_EINVAL   = 2,
  TRIO_ETOOMANY = 3,
  TRIO_EDBLREF  = 4,
  TRIO_EGAP     = 5,
  TRIO_ENOMEM   = 6,
  TRIO_ERANGE   = 7
};

/* Error macros */
#define TRIO_ERROR_CODE(x) ((-(x)) & 0x00FF)
#define TRIO_ERROR_POSITION(x) ((-(x)) >> 8)
#define TRIO_ERROR_NAME(x) trio_strerror(x)

/*
 * trio_sprintf(target, format, ...)
 * trio_snprintf(target, maxsize, format, ...)
 *
 *   Build 'target' according to 'format' and succesive
 *   arguments. This is equal to the sprintf() and
 *   snprintf() functions.
 */

int trio_printf(const char *format, ...);
int trio_vprintf(const char *format, va_list args);
int trio_fprintf(FILE *file, const char *format, ...);
int trio_vfprintf(FILE *file, const char *format, va_list args);
int trio_dprintf(int fd, const char *format, ...);
int trio_vdprintf(int fd, const char *format, va_list args);
int trio_sprintf(char *buffer, const char *format, ...);
int trio_snprintf(char *buffer, size_t max, const char *format, ...);
int trio_snprintfcat(char *buffer, size_t max, const char *format, ...);
int trio_vsprintf(char *buffer, const char *format, va_list args);
int trio_vsnprintf(char *buffer, size_t bufferSize, const char *format,
		   va_list args);
int trio_vsnprintfcat(char *buffer, size_t bufferSize, const char *format,
                      va_list args);
char *trio_aprintf(const char *format, ...);
char *trio_vaprintf(const char *format, va_list args);
int trio_asprintf(char **ret, const char *format, ...);
int trio_vasprintf(char **ret, const char *format, va_list args);

int trio_scanf(const char *format, ...);
int trio_vscanf(const char *format, va_list args);
int trio_fscanf(FILE *file, const char *format, ...);
int trio_vfscanf(FILE *file, const char *format, va_list args);
int trio_dscanf(int fd, const char *format, ...);
int trio_vdscanf(int fd, const char *format, va_list args);
int trio_sscanf(const char *buffer, const char *format, ...);
int trio_vsscanf(const char *buffer, const char *format, va_list args);

const char *trio_strerror(int);

#ifdef TRIO_REPLACE_STDIO
/* Replace the <stdio.h> functions */
#define printf trio_printf
#define vprintf trio_vprintf
#define fprintf trio_fprintf
#define vfprintf trio_vfprintf
#define sprintf trio_sprintf
#define vsprintf trio_vsprintf
#define snprintf trio_snprintf
#define vsnprintf trio_vsnprintf
#define scanf trio_scanf
#define vscanf trio_vscanf
#define fscanf trio_fscanf
#define vfscanf trio_vfscanf
#define sscanf trio_sscanf
#define vsscanf trio_vsscanf
/* These aren't stdio functions, but we make them look similar */
#define dprintf trio_dprintf
#define vdprintf trio_vdprintf
#define aprintf trio_aprintf
#define vaprintf trio_vaprintf
#define asprintf trio_asprintf
#define vasprintf trio_vasprintf
#define dscanf trio_dscanf
#define vdscanf trio_vdscanf
#endif

/* strio compatible names */
#define StrScan sscanf /* FIXME: must be trio_sscanf */
#define StrFormat trio_sprintf
#define StrFormatMax trio_snprintf
#define StrFormatAlloc trio_aprintf
#define StrFormatAppendMax trio_snprintfcat

#endif /* H_TRIO */
