/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2017.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU Lesser General Public License as published   *
* by the Free Software Foundation, either version 3 or (at your option)   *
* any later version. This program is distributed without any warranty.    *
* See the files COPYING.lgpl-v3 and COPYING.gpl-v3 for details.           *
\*************************************************************************/

/**
 * 2017-11-03 Miguel Pardal <miguel.pardal@tecnico.ulisboa.pt>
 * -> Code adapted to work with SSL_read
 */

/* read_line.h
   Header file for read_line.c.
*/
#ifndef READ_LINE_H
#define READ_LINE_H

#include <sys/types.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

ssize_t readTLSLine(gnutls_session_t s, void *buffer, size_t n);
//ssize_t readLine(int fd, void *buffer, size_t n);

#endif
