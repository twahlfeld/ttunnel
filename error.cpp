/*******************************************************************************
 *                                                                             *
 *       Filename:  error.cpp                                                  *
 *                                                                             *
 *    Description:  Error handling procedures                                  *
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

#include <cstdio>
#include <cstdlib>
#include "error.h"

/*
 * Kills program print error to stderr
 * const char *msg  -> Message to present
 */
void die_with_msg(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

/*
 * Kills program using perror
 * const char *msg  -> Message to present
 */
void die_with_err(const char *err)
{
    perror(err);
    exit(1);
}
