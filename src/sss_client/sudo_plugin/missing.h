/*
 * Copyright (c) 1996, 1998-2005, 2008, 2009-2010
 *	Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#ifndef _SUDO_MISSING_H
#define _SUDO_MISSING_H

#include <stdio.h>
#include <stdarg.h>

/*
 * Macros and functions that may be missing on some operating systems.
 */


/*
 * If we lack getprogname(), emulate with __progname if possible.
 * Otherwise, add a prototype for use with our own getprogname.c.
 */
#ifndef HAVE_GETPROGNAME
# ifdef HAVE___PROGNAME
extern const char *__progname;
#  define getprogname()          (__progname)
# else
const char *getprogname(void);
void setprogname(const char *);
#endif /* HAVE___PROGNAME */
#endif /* !HAVE_GETPROGNAME */


#endif /* _SUDO_MISSING_H */
