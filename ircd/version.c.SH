echo "Extracting ircd/version.c ..."

if test -r version.c
then
   generation=`sed -n 's/^char \*generation = \"\(.*\)\";/\1/p' < version.c`
   if test ! "$generation" ; then generation=0; fi
else
   generation=0
fi

generation=`expr $generation + 1`

sum=sum
if $sum s_serv.c 1> /dev/null 2>&1; then
:
else
  sum=cksum
fi
sumsserv=`$sum s_serv.c 2> /dev/null`;
sumsuser=`$sum s_user.c 2> /dev/null`;
sumchan=`$sum channel.c 2> /dev/null`;
sumsbsd=`$sum s_bsd.c 2> /dev/null`;
sumhash=`$sum hash.c 2> /dev/null`;
sumsmisc=`$sum s_misc.c 2> /dev/null`;
sumircd=`$sum ircd.c 2> /dev/null`;

creation=`date | \
awk '{if (NF == 6) \
	 { print $1 " "	 $2 " " $3 " "	$6 " at " $4 " " $5 } \
else \
	 { print $1 " "	 $2 " " $3 " " $7 " at " $4 " " $5 " " $6 }}'`

cvsversion=`cat ../.patches`

/bin/cat >version.c <<!SUB!THIS!
/*
 * IRC - Internet Relay Chat, ircd/version.c
 * Copyright (C) 1990 Chelsea Ashley Dyerman
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
 */

/*
 * This file is generated by version.c.SH. Any changes made will go away.
 */

#include "version.h"
#include "patchlevel.h"

const char *generation = "$generation";
const char *creation = "$creation";
const char *version = BASE_VERSION ".RH.$cvsversion";

const char *infotext[] = {
    "IRC --",
    "This program is free software; see LICENSE in the distribution",
    "",
    "Based on the original code written by Jarkko Oikarinen, version 2.6:",
    "Wiz	  Jarkko Oikarinen	   <jto@tolsun.oulu.fi>",
    "",
    "The main developer of version u2.9 and u2.10 was:",
    "Run	  Carlo Wood		   <carlo@runaway.xs4all.nl>",
    "",
    "The current head developer of the u2.10 source tree is:",
    "Bleep        Thomas Helvey            <tomh@inxpress.net>",
    "",
    "Contributors to this release:",
    "Kev, Isomer, Gte, Ghostwolf, Bleep",
    "Debugging and support:",
    "SeKs, Maniac-, HeKTik, OmniDynmc, Liandrin, Dianora",
    "Special thanks to Angel and Buff for believing in us and putting"
    "up with frantic late night phone calls"
    "",
    "Thanks goes to all other people who contributed to any version.",
    "A full listing of all coders can be found in doc/Authors in the",
    "source.",
    " ",
    "-== RedHispana.Org ==-",
    " ",
    "Desarrollador hasta la version RH.2.108:",
    "RyDeN       Alberto Alonso       <ryden@redhispana.org>",
    " ",
    "Otros desarrolladores para RH.2.108",
    "mount       Jorge Duarte         <mount@redhispana.org>",
    " ",
    "Desarrollador principal:",
    "ZipBreake   Javier Fdez. Vi�a    <javier@jfv.es>",
    " ",
    "Este IRCd tiene partes de la Base de Datos Distribuida",
    "del ircuH y el algoritmo de cifrado RC4 del Bahamut.",
    " ",
    "-[ En memoria de Raquel Alonso Pinto ]-",
    " ",
    "[$sumsserv] [$sumchan] [$sumsbsd] [$sumsuser]",
    "[$sumhash] [$sumsmisc] [$sumircd]",
    0,
};
!SUB!THIS!
