/*
 * libxml.h: internal header only used during the compilation of libxml
 *
 * See COPYRIGHT for the status of this software
 *
 * Author: breese@users.sourceforge.net
 */

#ifndef __XML_LIBXML_H__
#define __XML_LIBXML_H__

#if !defined(WIN32) || defined(__CYGWIN__)
#include "win32config.h"
#else
#include "config.h"
#endif

#include <libxml/xmlversion.h>

#ifdef WITHOUT_TRIO
#include <stdio.h>
#else
#define TRIO_REPLACE_STDIO
#include "trio.h"
#endif

#endif /* ! __XML_LIBXML_H__ */
