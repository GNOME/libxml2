/*
 * dict.h: dictionary of reusable strings, just used to avoid allocation
 *         and freeing operations.
 *
 * Copyright (C) 2003 Daniel Veillard.
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
 * Author: daniel@veillard.com
 */

#ifndef __XML_DICT_H__
#define __XML_DICT_H__

#include <libxml/xmlversion.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The dictionnary.
 */
typedef struct _xmlDict xmlDict;
typedef xmlDict *xmlDictPtr;

/*
 * Constructor and destructor.
 */
XMLPUBFUN xmlDictPtr XMLCALL
			xmlDictCreate	(void);
XMLPUBFUN void XMLCALL			
			xmlDictFree	(xmlDictPtr dict);

/*
 * Lookup of entry in the dictionnary.
 */
XMLPUBFUN const xmlChar * XMLCALL		
			xmlDictLookup	(xmlDictPtr dict,
		                         const xmlChar *name,
		                         int len);
XMLPUBFUN int XMLCALL			
			xmlDictSize	(xmlDictPtr dict);
#ifdef __cplusplus
}
#endif
#endif /* ! __XML_DICT_H__ */
