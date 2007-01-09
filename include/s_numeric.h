/*
 * s_numeric.h
 *
 * $Id: s_numeric.h,v 1.1.1.1 2006/12/19 12:56:39 zipbreake Exp $
 */
#ifndef INCLUDED_s_numeric_h
#define INCLUDED_s_numeric_h

struct Client;

/*
 * Prototypes
 */

extern int do_numeric(int numeric, int nnn, struct Client *cptr, struct Client *sptr,
    int parc, char *parv[]);

#endif /* INCLUDED_s_numeric_h */
