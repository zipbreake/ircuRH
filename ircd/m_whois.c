/*
 * IRC - Internet Relay Chat, ircd/m_whois.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: m_whois.c,v 1.1.1.1 2006/12/19 12:55:22 zipbreake Exp $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "whocmds.h"

#include <assert.h>
#include <string.h>

/*
 * 2000-07-01: Isomer
 *  * Rewritten to make this understandable
 *  * You can nolonger /whois unregistered clients.
 *  
 *
 * General rules:
 *  /whois nick always shows the nick.
 *  /whois wild* shows the nick if:
 *   * they aren't +i and aren't on any channels.
 *   * they are on a common channel.
 *   * they aren't +i and are on a public channel. (not +p and not +s)
 *   * they aren't +i and are on a private channel. (+p but not +s)
 *  Or to look at it another way (I think):
 *   * +i users are only shown if your on a common channel.
 *   * users on +s channels only aren't shown.
 *
 *  whois doesn't show what channels a +k client is on, for the reason that
 *  /whois X or /whois W floods a user off the server. :)
 *
 * nb: if the code and this comment disagree, the codes right and I screwed
 *     up.
 */

/*
 * Send whois information for acptr to sptr
 */
static void do_whois(struct Client* sptr, struct Client *acptr, int parc)
{
  struct Client *a2cptr=0;
  struct Channel *chptr=0;
  int mlen;
  int len;
  static char buf[512];
  int canal_oculto = 0;
  int haspriv = 0;
  
  const struct User* user = cli_user(acptr);
  const char* name = (!*(cli_name(acptr))) ? "?" : cli_name(acptr);  
  a2cptr = user->server;
  assert(user);
  if (IsViewip(sptr) || (acptr == sptr)) {
	send_reply(sptr, RPL_WHOISUSER, name, user->username, get_realhost(acptr),
			  cli_info(acptr));
  }
  else {
	send_reply(sptr, RPL_WHOISUSER, name, user->username, get_virtualhost(acptr),
			  cli_info(acptr));
  }

  /* Display the channels this user is on. */
#if 0
  if (!IsChannelService(acptr))
#else
  if (1)
#endif
  {
    struct Membership* chan;
    mlen = strlen(cli_name(&me)) + strlen(cli_name(sptr)) + 12 + strlen(name);
    len = 0;
    *buf = '\0';
    for (chan = user->channel; chan; chan = chan->next_channel)
    {
       chptr = chan->channel;
       
       if (!ShowChannel(sptr, chptr))
	   {
		   if (!IsAdmin(sptr))
          continue;
		   *(buf + len++) = '(';
		   canal_oculto = 1;
	   }
          
       if (acptr != sptr && IsZombie(chan))
          continue;
          
       if (len+strlen(chptr->chname) + mlen > BUFSIZE - 5) 
       {
          send_reply(sptr, SND_EXPLICIT | RPL_WHOISCHANNELS, "%s :%s", name, buf);
          *buf = '\0';
          len = 0;
       }
       if (IsDeaf(acptr))
         *(buf + len++) = '-';
	    if (is_chan_owner(acptr, chptr))
		     *(buf + len++) = '.';
		else if (is_chan_op(acptr, chptr))
			 *(buf + len++) = '@';
		else if (is_chan_halfop(acptr, chptr))
			 *(buf + len++) = '%';
		else if (has_voice(acptr, chptr))
			 *(buf + len++) = '+';
		else if (IsZombie(chan))
			 *(buf + len++) = '!';
	   if (len)
			  *(buf + len) = '\0';
       strcpy(buf + len, chptr->chname);
       len += strlen(chptr->chname);
	   if (canal_oculto)
	   {
		   strcat(buf + len++, ") ");
		   canal_oculto = 0;
	   }
	   else
		   strcat(buf + len, " ");
       len++;
     }
     if (buf[0] != '\0')
        send_reply(sptr, RPL_WHOISCHANNELS, name, buf);
  }

  haspriv = IsAnOper(sptr) || es_representante(sptr);
  if (IsMe(a2cptr))
  {
    if ((acptr != sptr) && feature_bool(FEAT_HIS_WHOIS_SERVERNAME) && !haspriv)
      send_reply(sptr, RPL_WHOISSERVER, name, feature_str(FEAT_RH_PSEUDO_SERVERNAME),
        feature_str(FEAT_HIS_SERVERINFO));
    else
      send_reply(sptr, RPL_WHOISSERVER, name, feature_str(FEAT_RH_PSEUDO_SERVERNAME),
        feature_str(FEAT_HIS_SERVERINFO));
  }
  else
  {
    if (IsHiddenserv(a2cptr) && !haspriv)
      send_reply(sptr, RPL_WHOISSERVER, name, feature_str(FEAT_HIS_SERVERNAME),
        feature_str(FEAT_HIS_SERVERINFO));
    else
      send_reply(sptr, RPL_WHOISSERVER, name, cli_name(a2cptr),
        cli_info(a2cptr));
  }


  if (user)
  {
    if (user->away)
       send_reply(sptr, RPL_AWAY, name, user->away);

	if (IsRegnick(acptr))
		send_reply(sptr, RPL_WHOISREGNICK, name);
	else if (IsSuspended(acptr))
		send_reply(sptr, RPL_WHOISSUSPEND, name);
	if (IsIdentified(acptr))
		send_reply(sptr, RPL_WHOISIDENTIFIED, name);

	if (IsBot(acptr))
		send_reply(sptr, RPL_WHOISBOT, name, feature_str(FEAT_NETWORK));

	if (IsPreoper(acptr))
		send_reply(sptr, RPL_WHOISRHPRIVS, name, "PreOPERador", feature_str(FEAT_NETWORK));
	else if (IsHelpOp(acptr))
		send_reply(sptr, RPL_WHOISRHPRIVS, name, "OPERador", feature_str(FEAT_NETWORK));
	else if (IsCoadmin(acptr))
		send_reply(sptr, RPL_WHOISRHPRIVS, name, "CoADMINistrador", feature_str(FEAT_NETWORK));
	else if (IsAdmin(acptr))
		send_reply(sptr, RPL_WHOISRHPRIVS, name, "ADMINistrador", feature_str(FEAT_NETWORK));
	if (IsDevel(acptr))
		send_reply(sptr, RPL_WHOISDEVELOPER, name, feature_str(FEAT_NETWORK));

	if (IsOnlyreg(acptr))
		send_reply(sptr, RPL_MSGONLYREG, name);

    if (IsAnOper(acptr) && (HasPriv(acptr, PRIV_DISPLAY) ||
			    HasPriv(sptr, PRIV_SEE_OPERS)))
       send_reply(sptr, RPL_WHOISOPERATOR, name);

//    if (IsAccount(acptr))
//      send_reply(sptr, RPL_WHOISACCOUNT, name, user->account);

	if ((cli_flags(acptr) & FLAGS_HIDDENHOST) && (acptr == sptr || IsViewip(sptr))) {
		send_reply(sptr, RPL_WHOISVHOST, name, get_virtualhost(acptr));
	}

    if (IsRegnick(sptr))
	{
	    send_reply(sptr, RPL_WHOISMODES, name, umode_str(acptr));
	}
	if (IsAdmin(sptr))
	{
		send_reply(sptr, RPL_WHOISNUMERIC, name, cli_yxx(cli_user(acptr)->server),
													 cli_yxx(acptr));
	}


    if (HasHiddenHost(acptr) && IsAnOper(sptr))
      send_reply(sptr, RPL_WHOISACTUALLY, name, user->username,
        user->realhost, ircd_ntoa((const char*) &(cli_ip(acptr))));
   
    /* Hint: if your looking to add more flags to a user, eg +h, here's
     *       probably a good place to add them :)
     */
     
    if (MyConnect(acptr) && (!feature_bool(FEAT_HIS_WHOIS_IDLETIME) ||
			     sptr == acptr || IsAnOper(sptr) || parc >= 3))
      send_reply(sptr, RPL_WHOISIDLE, name, CurrentTime - user->last, 
		 cli_firsttime(acptr));
  }
}

/*
 * Search and return as many people as matched by the wild 'nick'.
 * returns the number of people found (or, obviously, 0, if none where
 * found).
 */
static int do_wilds(struct Client* sptr, char *nick, int count, int parc)
{
  struct Client *acptr; /* Current client we're concidering */
  struct User *user; 	/* the user portion of the client */
  char *name; 		/* the name of this client */
  struct Membership* chan; 
  int invis; 		/* does +i apply? */
  int member;		/* Is this user on any channels? */
  int showperson;       /* Should we show this person? */
  int found = 0 ;	/* How many were found? */
  
  /* Ech! This is hidious! */
  for (acptr = GlobalClientList; (acptr = next_client(acptr, nick));
      acptr = cli_next(acptr))
  {
    if (!IsRegistered(acptr)) 
      continue;
      
    if (IsServer(acptr))
      continue;

    /*
     * I'm always last :-) and acptr->next == 0!!
     *
     * Isomer: Does this strike anyone else as being a horrible hidious
     *         hack?
     */
    if (IsMe(acptr)) {
      assert(!cli_next(acptr));
      break;
    }
    
    /*
     * 'Rules' established for sending a WHOIS reply:
     *
     * - if wildcards are being used dont send a reply if
     *   the querier isnt any common channels and the
     *   client in question is invisible.
     *
     * - only send replies about common or public channels
     *   the target user(s) are on;
     */
    user = cli_user(acptr);
    name = (!*(cli_name(acptr))) ? "?" : cli_name(acptr);
    assert(user);

    invis = (acptr != sptr) && IsInvisible(acptr);
    member = (user && user->channel) ? 1 : 0;
    showperson = !invis && !member;
    
    /* Should we show this person now? */
    if (showperson) {
    	found++;
    	do_whois(sptr, acptr, parc);
    	if (count+found>MAX_WHOIS_LINES)
    	  return found;
    	continue;
    }
    
    /* Step through the channels this user is on */
    for (chan = user->channel; chan; chan = chan->next_channel)
    {
      struct Channel *chptr = chan->channel;

      /* If this is a public channel, show the person */
      if (!invis && PubChannel(chptr)) {
        showperson = 1;
        break;
      }
      
      /* if this channel is +p and not +s, show them */
      if (!invis && HiddenChannel(chptr) && !SecretChannel(chptr)) {
          showperson = 1;
          break;
      }
      
      member = find_channel_member(sptr, chptr) ? 1 : 0;
      if (invis && !member)
        continue;

      /* If sptr isn't really on this channel, skip it */
      if (IsZombie(chan))
        continue;
       
      /* Is this a common channel? */ 
      if (member) {
        showperson = 1;
        break;
      }
    } /* of for (chan in channels) */
    
    /* Don't show this person */
    if (!showperson)
      continue;
      
    do_whois(sptr, acptr, parc);
    found++;
    if (count+found>MAX_WHOIS_LINES)
       return found;  
  } /* of global client list */
  
  return found;
}

/*
 * m_whois - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server, or a nickname representing a server to target.
 * parv[2] = nickname masklist
 */
CMD_FUNC(m_whois)
{
  char*           nick;
  char*           tmp;
  char*           p = 0;
  int             found = 0;
  int		  total = 0;
  struct Client *bcptr;

  if (parc < 2)
  {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }

  if (parc > 2)
  {
    /* For convenience: Accept a nickname as first parameter, by replacing
     * it with the correct servername - as is needed by hunt_server().
     * This is the secret behind the /whois nick nick trick.
     */
    if (feature_int(FEAT_HIS_REMOTE)) {
      /* If remote queries are disabled, then use the *second* parameter of
       * of whois, so /whois nick nick still works.
       */
      if (!IsAnOper(sptr)) {
	if (!(bcptr=FindUser(parv[2]))) {
	  send_reply(sptr, ERR_NOSUCHNICK, parv[2]);
	  send_reply(sptr, RPL_ENDOFWHOIS, parv[2]);
	  return 0;
	}
	parv[1] = parv[2];
      }
    }

    if (hunt_server_cmd(sptr, CMD_WHOIS, cptr, 0, "%C :%s", 1, parc, parv) !=
       HUNTED_ISME)
    return 0;
    
    parv[1] = parv[2];
  }

  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    int wilds;

    found = 0;
    
    collapse(nick);
    
    wilds = (strchr(nick, '?') || strchr(nick, '*'));
    if (!wilds) {
      struct Client *acptr = 0;
      /* No wildcards */
      acptr = FindUser(nick);
      if (acptr && !IsServer(acptr)) {
        do_whois(sptr, acptr, parc);
        found = 1;
      }
    }
    else /* wilds */
    	found=do_wilds(sptr, nick, total, parc);

    if (!found)
      send_reply(sptr, ERR_NOSUCHNICK, nick);
    total+=found;
    if (total >= MAX_WHOIS_LINES) {
      send_reply(sptr, ERR_QUERYTOOLONG, parv[1]);
      break;
    }
    if (p)
      p[-1] = ',';
  } /* of tokenised parm[1] */
  send_reply(sptr, RPL_ENDOFWHOIS, parv[1]);

  return 0;
}

/*
 * ms_whois - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = nickname masklist
 *
 * or
 *
 * parv[1] = target server, or a nickname representing a server to target.
 * parv[2] = nickname masklist
 */
CMD_FUNC(ms_whois)
{
  char*           nick;
  char*           tmp;
  char*           p = 0;
  int             found = 0;
  int		  total = 0;

  if (parc < 2)
  {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }

  if (parc > 2)
  {
    if (hunt_server_cmd(sptr, CMD_WHOIS, cptr, 0, "%C :%s", 1, parc, parv) !=
        HUNTED_ISME)
      return 0;
    parv[1] = parv[2];
  }

  total = 0;
  
  for (tmp = parv[1]; (nick = ircd_strtok(&p, tmp, ",")); tmp = 0)
  {
    struct Client *acptr = 0;

    found = 0;
    
    collapse(nick);
    

    acptr = FindUser(nick);
    if (acptr && !IsServer(acptr)) {
      found++;
      do_whois(sptr, acptr, parc);
    }

    if (!found)
      send_reply(sptr, ERR_NOSUCHNICK, nick);
      
    total+=found;
      
    if (total >= MAX_WHOIS_LINES) {
      send_reply(sptr, ERR_QUERYTOOLONG, parv[1]);
      break;
    }
      
    if (p)
      p[-1] = ',';
  } /* of tokenised parm[1] */
  send_reply(sptr, RPL_ENDOFWHOIS, parv[1]);

  return 0;
}
