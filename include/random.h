/*
 * random.h
 *
 * $Id: random.h,v 1.1.1.1 2006/12/19 12:56:36 zipbreake Exp $
 */
#ifndef INCLUDED_random_h
#define INCLUDED_random_h

struct Client;

/*
 * Proto types
 */

extern int random_seed_set(struct Client* from, const char* const* fields,
			   int count);

extern unsigned int ircrandom(void);

#endif /* INCLUDED_random_h */
