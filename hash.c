/*
 * hash.c: chained hash tables
 *
 * Reference: Your favorite introductory book on algorithms
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

#include <libxml/hash.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

/*
 * xmlHashComputeKey:
 * Calculate the hash key
 */
static unsigned long
xmlHashComputeKey(xmlHashTablePtr table, const xmlChar *string) {
    unsigned long value = 0L;
    char ch;
    
    while ((ch = *string++) != 0) {
        /* value *= 31; */
        value += (unsigned long)ch;
    }
    return (value % table->size);
}

/**
 * xmlHashCreate:
 * @size: the size of the hash table
 *
 * Create a new xmlHashTablePtr.
 *
 * Returns the newly created object, or NULL if an error occured.
 */
xmlHashTablePtr
xmlHashCreate(int size) {
    xmlHashTablePtr table;
  
    if (size <= 0)
        size = 256;
  
    table = xmlMalloc(sizeof(xmlHashTable));
    if (table) {
        table->size = size;
        table->table = xmlMalloc(size * sizeof(xmlHashEntry));
        if (table->table) {
  	    memset(table->table, 0, size * sizeof(xmlHashEntry));
  	    return(table);
        }
        xmlFree(table);
    }
    return(NULL);
}

/**
 * xmlHashFree:
 * @table: the hash table
 * @f:  the deallocator function for items in the hash
 *
 * Free the hash table and its contents. The userdata is
 * deallocated with f if provided.
 */
void
xmlHashFree(xmlHashTablePtr table, xmlHashDeallocator f) {
    int i;
    xmlHashEntryPtr iter;
    xmlHashEntryPtr next;

    if (table == NULL)
	return;
    if (table->table) {
	for(i = 0; i < table->size; i++) {
	    iter = table->table[i];
	    while (iter) {
		next = iter->next;
		if (iter->name)
		    xmlFree(iter->name);
		if (f)
		    f(iter->payload);
		iter->payload = NULL;
		xmlFree(iter);
		iter = next;
	    }
	    table->table[i] = NULL;
	}
	xmlFree(table->table);
    }
    xmlFree(table);
}

/**
 * xmlHashAddEntry:
 * @table: the hash table
 * @name: the name of the userdata
 * @userdata: a pointer to the userdata
 *
 * Add the userdata to the hash table. This can later be retrieved
 * by using the name. Duplicate names generate errors.
 *
 * Returns 0 the addition succeeded and -1 in case of error.
 */
int
xmlHashAddEntry(xmlHashTablePtr table, const xmlChar *name, void *userdata) {
    unsigned long key;
    xmlHashEntryPtr entry;
    xmlHashEntryPtr insert;

    if ((table == NULL) || name == NULL)
	return(-1);

    /*
     * Check for duplicate and insertion location.
     */
    key = xmlHashComputeKey(table, name);
    if (table->table[key] == NULL) {
	insert = NULL;
    } else {
	for (insert = table->table[key]; insert->next != NULL;
	     insert = insert->next) {
	    if (xmlStrEqual(insert->name, name))
		return(-1);
	}
	if (xmlStrEqual(insert->name, name))
	    return(-1);
    }

    entry = xmlMalloc(sizeof(xmlHashEntry));
    if (entry == NULL)
	return(-1);
    entry->name = xmlStrdup(name);
    entry->payload = userdata;
    entry->next = NULL;


    if (insert == NULL) {
	table->table[key] = entry;
    } else {
	insert->next = entry;
    }
    return(0);
}

/**
 * xmlHashUpdateEntry:
 * @table: the hash table
 * @name: the name of the userdata
 * @userdata: a pointer to the userdata
 * @f: the deallocator function for replaced item (if any)
 *
 * Add the userdata to the hash table. This can later be retrieved
 * by using the name. Existing entry for this name will be removed
 * and freed with @f if found.
 *
 * Returns 0 the addition succeeded and -1 in case of error.
 */
int
xmlHashUpdateEntry(xmlHashTablePtr table, const xmlChar *name,
	           void *userdata, xmlHashDeallocator f) {
    unsigned long key;
    xmlHashEntryPtr entry;
    xmlHashEntryPtr insert;

    if ((table == NULL) || name == NULL)
	return(-1);

    /*
     * Check for duplicate and insertion location.
     */
    key = xmlHashComputeKey(table, name);
    if (table->table[key] == NULL) {
	insert = NULL;
    } else {
	for (insert = table->table[key]; insert->next != NULL;
	     insert = insert->next) {
	    if (xmlStrEqual(insert->name, name)) {
		if (f)
		    f(insert->payload);
		insert->payload = userdata;
		return(0);
	    }
	}
	if (xmlStrEqual(insert->name, name)) {
	    if (f)
		f(insert->payload);
	    insert->payload = userdata;
	    return(0);
	}
    }

    entry = xmlMalloc(sizeof(xmlHashEntry));
    if (entry == NULL)
	return(-1);
    entry->name = xmlStrdup(name);
    entry->payload = userdata;
    entry->next = NULL;


    if (insert == NULL) {
	table->table[key] = entry;
    } else {
	insert->next = entry;
    }
    return(0);
}

/**
 * xmlHashLookup:
 * @table: the hash table
 * @name: the name of the userdata
 *
 * Find the userdata specified by the name.
 *
 * Returns the a pointer to the userdata
 */
void *
xmlHashLookup(xmlHashTablePtr table, const xmlChar *name) {
    unsigned long key;
    xmlHashEntryPtr entry;

    if (table == NULL)
	return(NULL);
    if (name == NULL)
	return(NULL);
    key = xmlHashComputeKey(table, name);
    for (entry = table->table[key]; entry != NULL; entry = entry->next) {
	if (xmlStrEqual(name, entry->name))
	    return(entry->payload);
    }
    return(NULL);
}

/**
 * xmlHashScan:
 * @table: the hash table
 * @f:  the scanner function for items in the hash
 * @data:  extra data passed to f
 *
 * Scan the hash table and applied f to each value.
 */
void
xmlHashScan(xmlHashTablePtr table, xmlHashScanner f, void *data) {
    int i;
    xmlHashEntryPtr iter;
    xmlHashEntryPtr next;

    if (table == NULL)
	return;
    if (f == NULL)
	return;

    if (table->table) {
	for(i = 0; i < table->size; i++) {
	    iter = table->table[i];
	    while (iter) {
		next = iter->next;
		if (f)
		    f(iter->payload, data);
		iter = next;
	    }
	}
    }
}

/**
 * xmlHashCopy:
 * @table: the hash table
 * @f:  the copier function for items in the hash
 *
 * Scan the hash table and applied f to each value.
 *
 * Returns the new table or NULL in case of error.
 */
xmlHashTablePtr
xmlHashCopy(xmlHashTablePtr table, xmlHashCopier f) {
    int i;
    xmlHashEntryPtr iter;
    xmlHashEntryPtr next;
    xmlHashTablePtr ret;

    if (table == NULL)
	return(NULL);
    if (f == NULL)
	return(NULL);

    ret = xmlHashCreate(table->size);
    if (table->table) {
	for(i = 0; i < table->size; i++) {
	    iter = table->table[i];
	    while (iter) {
		next = iter->next;
		xmlHashAddEntry(ret, iter->name, f(iter));
		iter = next;
	    }
	}
    }
    return(ret);
}

