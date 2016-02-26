/*******************************************************************************
 *                                                                             *
 *       Filename:  error.h                                                    *
 *                                                                             *
 *    Description:  Error handling procedures and macros                       *
 *                                                                             *
 *        Version:  1.0                                                        *
 *        Created:  02/19/2016 03:30:40 PM                                     *
 *       Revision:  none                                                       *
 *         Author:  Theodore Ahlfeld (twa2108)                                 *
 *       Compiler:  gcc                                                        *
 *                                                                             *
 *   Organization:                                                             *
 *                                                                             *
 ******************************************************************************/

#ifndef TTUNNEL_ERROR_H
#define TTUNNEL_ERROR_H

/* Error Handling Macros and Routines */
#define errhandle(a) goto a
#define seterrhandle(a) a:
#define ERRCHK(v, op, p, e) \
    if((v) op (p)) {errmsg = e; errhandle(err);}

static const char *errmsg = nullptr;

/*
 * Kills program print error to stderr
 * const char *msg  -> Message to present
 */
void die_with_msg(const char *msg);

/*
 * Kills program using perror
 * const char *msg  -> Message to present
 */
void die_with_err(const char *err);

#endif //TTUNNEL_ERROR_H
