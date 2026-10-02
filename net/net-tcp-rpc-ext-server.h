/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2016-2018 Telegram Messenger Inc                 
              2016-2018 Nikolai Durov
*/

#pragma once

#define __ALLOW_UNOBFS__ 0

#include "net/net-tcp-rpc-server.h"
#include "net/net-connections.h"

extern conn_type_t ct_tcp_rpc_ext_server;

int tcp_rpcs_compact_parse_execute (connection_job_t c);

void tcp_rpcs_set_ext_secret(unsigned char secret[16]);

/* Returns the index of the secret the limit was applied to, or -1 when no
   configured secret matches. */
int tcp_rpcs_set_ext_secret_max_conn(unsigned char secret[16], int max_conn);
/* 1 when the connection may proceed, 0 when the secret is at its limit. */
int tcp_rpcs_acquire_ext_secret(int secret_id);
void tcp_rpcs_release_ext_secret(int secret_id);
int tcp_rpcs_ext_secret_conn_count(int secret_id);
/* 32 hex digits into 16 bytes; -1 on anything else. */
int tcp_rpcs_parse_hex_secret(const char *text, unsigned char secret[16]);
/* Replaces the live secret table from a file. Returns the number of active
   secrets, or -1 when the file is unusable, leaving the table untouched. */
int tcp_rpcs_load_ext_secret_file(const char *path);

void tcp_rpc_add_proxy_domain (const char *domain);

void tcp_rpc_init_proxy_domains();
