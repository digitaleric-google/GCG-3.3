/*
 * Linux hardware socket API
 *
 * Copyright (C) 2011 Google Inc.
 * Author: San Mehat <san@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _LINUX_HWSOCKET_H
#define _LINUX_HWSOCKET_H

#include <linux/net.h>
#include <linux/poll.h>
#include <linux/socket.h>

/* IPv4 max URI length is 28 (including NULL): xxx://aaa.bbb.ccc.ddd:eeeee */
#define HWSOCKET_URI_MAXLEN 28

struct sock;
struct msghdr;

extern int hwsocket_accept(struct sock *sk,
			   struct socket *newsocket, int flags);
extern int hwsocket_bind(struct sock *sk, const char *uri,
			 struct sockaddr *address);
extern void hwsocket_close(struct sock *sk);
extern int hwsocket_shutdown(struct sock *sk, int how);
extern int hwsocket_connect(struct sock *sk, const char *uri);
/* For disconnecting UDP sockets */
extern int hwsocket_disconnect(struct sock *sk);
extern int hwsocket_create_unconnected(struct sock *sk, const char *uri);
extern int hwsocket_getname(struct sock *newsk, struct sockaddr *address,
			    int *addrlen, int peer);
extern int hwsocket_listen(struct sock *sk, const int backlog);
extern void hwsocket_poll(struct file *file, struct sock *sk, poll_table *wait,
			  unsigned int *mask);
extern int hwsocket_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
extern int hwsocket_recvmsg(struct kiocb *iocb, struct socket *sock,
			    struct msghdr *msg, size_t size, int flags);
extern int hwsocket_ioctl(struct socket *sock, unsigned int cmd,
			  unsigned long arg);
extern int hwsocket_setsockopt(struct socket *sock,
			       int level,
			       int optname,
			       char __user *optval,
			       int optlen);
extern int hwsocket_getsockopt(struct socket *sock,
			       int level,
			       int optname,
			       char __user *optval,
			       int __user *optlen);

extern int is_sockaddr_hwsocket(enum sock_type type, struct sockaddr *addr,
				int addr_len);

extern char *sockaddr_to_uri(enum sock_type type,
			     struct sockaddr *addr,
			     int addrlen,
			     char *buffer,
			     int buffsize);

#endif
