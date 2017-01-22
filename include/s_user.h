/*
 * s_user.h
 *
 * $Id: s_user.h,v 1.1.1.1 2006/12/19 12:56:39 zipbreake Exp $
 */
#ifndef INCLUDED_s_user_h
#define INCLUDED_s_user_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;
struct User;
struct Channel;
struct MsgBuf;

/*
 * Macros
 */

/*
 * Nick flood limit
 * Minimum time between nick changes.
 * (The first two changes are allowed quickly after another however).
 */
#define NICK_DELAY 30

/*
 * Target flood time.
 * Minimum time between target changes.
 * (MAXTARGETS are allowed simultaneously however).
 * Its set to a power of 2 because we devide through it quite a lot.
 */
#define TARGET_DELAY 128

/* return values for hunt_server() */

#define HUNTED_NOSUCH   (-1)    /* if the hunted server is not found */
#define HUNTED_ISME     0       /* if this server should execute the command */
#define HUNTED_PASS     1       /* if message passed onwards successfully */

/* used when sending to #mask or $mask */

#define MATCH_SERVER  1
#define MATCH_HOST    2

#define COOKIE_VERIFIED 0xffffffff

extern struct SLink *opsarray[];

typedef void (*InfoFormatter)(struct Client* who, struct Client *sptr, struct MsgBuf* buf);

/*
 * Prototypes
 */
extern struct User* make_user(struct Client *cptr);
extern void         free_user(struct User *user);
extern int          register_user(struct Client* cptr, struct Client* sptr,
                                  const char* nick, char* username);

extern void         user_count_memory(size_t* count_out, size_t* bytes_out);

extern int do_nick_name(char* nick);
extern int set_nick_name(struct Client* cptr, struct Client* sptr,
                         const char* nick, int parc, char* parv[]);
extern void send_umode_out(struct Client* cptr, struct Client* sptr, int old, int oldrh,
			   int prop);
extern int whisper(struct Client* source, const char* nick,
                   const char* channel, const char* text, int is_notice);
extern void send_user_info(struct Client* to, char* names, int rpl,
                           InfoFormatter fmt);
extern int add_silence(struct Client* sptr, const char* mask);

extern int hide_hostmask(struct Client *cptr, unsigned int flags);
extern int set_user_mode(struct Client *cptr, struct Client *sptr,
                         int parc, char *parv[]);
extern int is_silenced(struct Client *sptr, struct Client *acptr);
extern int hunt_server(int, struct Client *cptr, struct Client *sptr,
    char *command, int server, int parc, char *parv[]);
extern int hunt_server_cmd(struct Client *from, const char *cmd,
			   const char *tok, struct Client *one,
			   int MustBeOper, const char *pattern, int server,
			   int parc, char *parv[]);
extern int hunt_server_prio_cmd(struct Client *from, const char *cmd,
				const char *tok, struct Client *one,
				int MustBeOper, const char *pattern,
				int server, int parc, char *parv[]);
extern struct Client* next_client(struct Client* next, const char* ch);
extern char *umode_str(struct Client *cptr);
extern void send_umode(struct Client *cptr, struct Client *sptr, int old, int oldrh, int sendmask, int rhsendmask);
extern int del_silence(struct Client *sptr, char *mask);
extern void set_snomask(struct Client *, unsigned int, int);
extern int is_snomask(char *);
extern int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created);
extern void add_target(struct Client *sptr, void *target);
extern unsigned int umode_make_snomask(unsigned int oldmask, char *arg,
                                       int what);
extern int send_supported(struct Client *cptr);

#define NAMES_ALL 1 /* List all users in channel */
#define NAMES_VIS 2 /* List only visible users in non-secret channels */
#define NAMES_EON 4 /* Add an 'End Of Names' reply to the end */

void do_names(struct Client* sptr, struct Channel* chptr, int filter);

#endif /* INCLUDED_s_user_h */
