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

/* Device accounting. A device is an authorisation, identified by auth_key_id;
   they are counted per data centre because one device holds one key in each. */
void tcp_rpcs_set_ext_secret_max_devices(int secret_id, int max_devices);
/* Slot index for this device, or -1 when the secret is at its device limit. */
int tcp_rpcs_claim_device(int secret_id, int dc, long long auth_key_id, double now);
/* 1 when the slot still belongs to this device and was refreshed. */
int tcp_rpcs_touch_device(int secret_id, int slot, long long auth_key_id, double now);

/* 1 when this secret is sold by device; 0 when it is not limited that way. */
int tcp_rpcs_ext_secret_limits_devices(int secret_id);

/* Socket priority to tag this secret's client connections with, so that tc on
   the host can put them in a rate limited band. 0 means unshaped. */
int tcp_rpcs_ext_secret_priority(int secret_id);

/* How each client handshake ended. A rejected handshake is not closed - the
   connection is left to read and discard, so a prober learns nothing - which
   also means a refusal is otherwise invisible: the client sits "connected"
   and nothing is ever logged. These counters are the only record of it. */
enum ext_handshake_outcome {
  EXT_HS_OK,
  /* No configured secret decrypts the header: a stale link, a scanner. */
  EXT_HS_UNKNOWN_SECRET,
  /* Fake-TLS handshake that matched a secret but failed later checks. */
  EXT_HS_BAD_TLS,
  /* Turned away at the buffer pool watermark. */
  EXT_HS_POOL_PRESSURE,
  /* The secret was at its connection limit. */
  EXT_HS_CONNECTION_LIMIT,
  /* No usable header within the handshake timeout; the connection is closed. */
  EXT_HS_TIMEOUT,
  EXT_HS_OUTCOMES
};

#define EXT_SECRETS_MAX 16

/* Snapshot of everything the proxy reports per secret. Plain values so that
   it can be copied into the shared-memory block workers publish their
   statistics through, and summed there. */
struct ext_secret_stats {
  long long handshakes[EXT_HS_OUTCOMES];
  long long secret_handshakes_ok[EXT_SECRETS_MAX];
  long long secret_connection_limit[EXT_SECRETS_MAX];
  long long secret_device_refusals[EXT_SECRETS_MAX];
  /* Client connections past the handshake, per secret. */
  int secret_connections[EXT_SECRETS_MAX];
  /* Distinct devices on currently open connections: distinct auth_key_ids per
     data centre, the largest of those - the same rule the device limit
     enforces. A recent value, recomputed every few seconds. */
  int secret_clients[EXT_SECRETS_MAX];
};

void tcp_rpcs_count_handshake(connection_job_t c, enum ext_handshake_outcome outcome, int secret_id);
void tcp_rpcs_count_device_refusal(int secret_id);

/* Registry of client connections past the handshake, by fd: what /metrics
   needs to count clients without walking the engine's connection table, which
   holds descriptors of every kind. */
void tcp_rpcs_ext_conn_key(connection_job_t c, int dc, long long auth_key_id);
void tcp_rpcs_ext_conn_closed(connection_job_t c);
/* Recomputes secret_clients from the registry; cheap enough for a cron. */
void tcp_rpcs_update_client_counts(void);
void tcp_rpcs_fetch_ext_stats(struct ext_secret_stats *out);

/* Short identifier for a configured secret, safe to show: the first eight hex
   digits of its SHA-256, never of the secret itself. Empty for a free slot. */
const char *tcp_rpcs_ext_secret_id(int secret_id);
int tcp_rpcs_ext_secret_count(void);
int tcp_rpcs_ext_secret_max_devices(int secret_id);

void tcp_rpc_add_proxy_domain (const char *domain);

void tcp_rpc_init_proxy_domains();
