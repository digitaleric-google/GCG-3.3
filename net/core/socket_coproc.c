/*
 * Linux socket co-processor subsystem.
 *
 * Copyright (C) 2011 Google Inc.
 * Author: San Mehat <san@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h> /* for scatter test */
#include <linux/socket_coproc.h>
#include <linux/hwsocket.h>
#include <linux/in.h>

#include <net/tcp.h> /* For TCP_NODELAY */

/* Initialize the coprocessor system */
void socket_coproc_init()
{
	pr_info("Socket co-processor subsystem v0.1\n");
}

int socket_coproc_create(struct net *net,
			 struct socket *sock,
			 int protocol,
			 int kern)
{
	return -ENOTSOCK;
}

int socket_coproc_connect(struct socket *sock,
			  struct sockaddr *address,
			  int addrlen,
			  unsigned int flags)
{
	char uri[HWSOCKET_URI_MAXLEN];
	int err;

	/* Route to hwsocket_connect if the destination is a hwsocket address
	 * or if the socket is already routed to hwsocket (which would be the
	 * case if a UDP socket has been bound to a hwsocket address, and then
	 * a connect() is issued on that socket. */
	if (!is_sockaddr_hwsocket(sock->type, address, addrlen) &&
		!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;

	if (address->sa_family == AF_UNSPEC &&
	    sock->sk->sk_protocol == IPPROTO_UDP) {
		err = hwsocket_disconnect(sock->sk);
	} else {
		sockaddr_to_uri(sock->type, address, addrlen, uri, sizeof(uri));
		err = hwsocket_connect(sock->sk, uri);
		if (!err)
			set_bit(SOCK_HWASSIST, &sock->flags);
	}
	return err;
}

int socket_coproc_bind(struct socket *sock,
		       struct sockaddr *address,
		       int addrlen)
{
	/* XXX eliminate stack allocations. */
	char uri[HWSOCKET_URI_MAXLEN];
	int err;

	pr_debug("\n%s: sk %p len %u\n", __func__, address, addrlen);

	if (!is_sockaddr_hwsocket(sock->type, address, addrlen)) {
		pr_debug("%s: returning ENOTSOCK\n", __func__);
		return -ENOTSOCK;
	}

	/* XXX does this "user addr" need to be converted to a URI? */
	sockaddr_to_uri(sock->type, address, addrlen, uri, sizeof(uri));
	pr_debug("%s: sockaddr_to_uri: %s\n", __func__, uri);
	err = hwsocket_bind(sock->sk, uri, address);
	if (!err)
		set_bit(SOCK_HWASSIST, &sock->flags);
	return err;
}

int socket_coproc_recvmsg(struct kiocb *iocb,
			  struct socket *sock,
			  struct msghdr *msg, size_t size,
			  int flags)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	return hwsocket_recvmsg(iocb, sock, msg, size, flags);
}

int socket_coproc_accept(struct socket *sock,
			 struct socket *newsock,
			 int flags)
{
	int err;
	pr_debug("%s sock %p newsock %p\n", __func__, sock->sk, newsock->sk);
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	err = hwsocket_accept(sock->sk, newsock, flags);
	if (!err)
		set_bit(SOCK_HWASSIST, &newsock->flags);
	return err;
}

int socket_coproc_release(struct socket *sock)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;

	pr_debug("%s\n", __func__);
	hwsocket_close(sock->sk);
	return 0;
}

int socket_coproc_ioctl(struct socket *sock,
			unsigned int cmd,
			unsigned long arg)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return hwsocket_ioctl(sock, cmd, arg);
}

int socket_coproc_splice_read(struct socket *sock,
			      loff_t *ppos,
			      struct pipe_inode_info *pipe,
			      size_t len,
			      unsigned int flags)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return -ENOSYS;
}

int socket_coproc_poll(struct file *file,
		       struct socket *sock,
		       poll_table *wait,
		       unsigned int *mask)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	hwsocket_poll(file, sock->sk, wait, mask);
	return 0;
}

int socket_coproc_mmap(struct file *file,
		       struct socket *sock,
		       struct vm_area_struct *vma)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return -ENOSYS;
}

int socket_coproc_sendmsg(struct kiocb *iocb,
			  struct socket *sock,
			  struct msghdr *msg,
			  size_t size)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags)) {
		int ret = 0;
		char uri[HWSOCKET_URI_MAXLEN];
		/* If this isn't an hwsocket socket, but there is a
		 * msg_name field that specifies a hwsocket destination
		 * address, we need to route it to hwsocket_sendmsg. */
		if (!is_sockaddr_hwsocket(sock->type, msg->msg_name,
					  msg->msg_namelen))
			return -ENOTSOCK;
		sockaddr_to_uri(sock->type, msg->msg_name, msg->msg_namelen,
				uri, sizeof(uri));
		pr_debug("%s: sockaddr_to_uri: %s\n", __func__, uri);
		ret = hwsocket_create_unconnected(sock->sk, uri);
		if (!ret) {
			/* Fall through. */
			set_bit(SOCK_HWASSIST, &sock->flags);
		} else {
			return ret;
		}
	}
	return hwsocket_sendmsg(sock->sk, msg, size);
}

int socket_coproc_listen(struct socket *sock, int backlog)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return hwsocket_listen(sock->sk, backlog);
}

int socket_coproc_getname(struct socket *newsock,
			  struct sockaddr *address,
			  int *addrlen,
			  int peer)
{
	if (!test_bit(SOCK_HWASSIST, &newsock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return hwsocket_getname(newsock->sk, address, addrlen, peer);
}

int socket_coproc_setsockopt(struct socket *sock,
			     int level,
			     int optname,
			     char __user *optval,
			     int optlen)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return hwsocket_setsockopt(sock, level, optname, optval, optlen);
}

int socket_coproc_getsockopt(struct socket *sock,
			     int level,
			     int optname,
			     char __user *optval,
			     int __user *optlen)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return hwsocket_getsockopt(sock, level, optname, optval, optlen);
}

int socket_coproc_shutdown(struct socket *sock, int how)
{
	if (!test_bit(SOCK_HWASSIST, &sock->flags))
		return -ENOTSOCK;
	pr_debug("%s\n", __func__);
	return hwsocket_shutdown(sock->sk, how);
}
