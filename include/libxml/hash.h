/*
 * hash.c: chained hash tables
 *
 * Copyright (C) 2000 Bjorn Reese and Daniel Veillard.
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
 * Author: bjorn.reese@systematic.dk
 */

#ifndef __XML_HASH_H__
#define __XML_HASH_H__

#include <libxml/parser.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A single entry in the hash table
 */
typedef struct _xmlHashEntry xmlHashEntry;
typedef xmlHashEntry *xmlHashEntryPtr;
struct _xmlHashEntry {
    struct _xmlHashEntry *next;
    xmlChar *name;
    void *payload;
};

/*
 * The entire hash table
 */
typedef struct _xmlHashTable xmlHashTable;
typedef xmlHashTable *xmlHashTablePtr;
struct _xmlHashTable {
    struct _xmlHashEntry **table;
    int size;
};

/*
 * function types:
 */
typedef void (*xmlHashDeallocator)(void *payload);
typedef void *(*xmlHashCopier)(void *payload);
typedef void *(*xmlHashScanner)(void *payload, void *data);

/*
 * Constructor and destructor
 */
xmlHashTablePtr		xmlHashCreate	(int size);
void			xmlHashFree	(xmlHashTablePtr table,
					 xmlHashDeallocator f);

/*
 * Add a new entry to the hash table
 */
int			xmlHashAddEntry	(xmlHashTablePtr table,
		                         const xmlChar *name,
		                         void *userdata);
int			xmlHashUpdateEntry(xmlHashTablePtr table,
		                         const xmlChar *name,
		                         void *userdata,
					 xmlHashDeallocator f);
/*
 * Retrieve the userdata
 */
void *			xmlHashLookup	(xmlHashTablePtr table,
					 const xmlChar *name);

/*
 * Helpers
 */
xmlHashTablePtr		xmlHashCopy	(xmlHashTablePtr table,
					 xmlHashCopier f);
void			xmlHashScan	(xmlHashTablePtr table,
					 xmlHashScanner f,
					 void *data);
#ifdef __cplusplus
}
#endif
#endif /* ! __XML_HASH_H__ */
