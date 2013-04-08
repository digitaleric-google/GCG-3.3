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

#ifndef _LINUX_SOCKET_COPROC_H_
#define _LINUX_SOCKET_COPROC_H_

#ifdef CONFIG_SOCK_COPROC
extern void socket_coproc_init(void);
extern int socket_coproc_create(struct net *net,
				struct socket *sock,
				int protocol,
				int kern);
extern int socket_coproc_connect(struct socket *sock,
				 struct sockaddr *address,
				 int addrlen,
				 unsigned int flags);
extern int socket_coproc_recvmsg(struct kiocb *iocb,
				 struct socket *sock,
				 struct msghdr *msg,
				 size_t size,
				 int flags);
extern int socket_coproc_accept(struct socket *sock,
				struct socket *newsock,
				int flags);
extern int socket_coproc_release(struct socket *sock);
extern int socket_coproc_bind(struct socket *sock,
			      struct sockaddr *address,
			      int addrlen);
extern int socket_coproc_ioctl(struct socket *sock,
			       unsigned int cmd,
			       unsigned long arg);
extern int socket_coproc_splice_read(struct socket *sock,
				     loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len,
				     unsigned int flags);
extern int socket_coproc_poll(struct file *file,
			      struct socket *sock,
			      poll_table *wait,
			      unsigned int *mask);
extern int socket_coproc_mmap(struct file *file,
			      struct socket *sock,
			      struct vm_area_struct *vma);
extern int socket_coproc_sendmsg(struct kiocb *iocb,
				 struct socket *sock,
				 struct msghdr *msg,
				 size_t size);
extern int socket_coproc_listen(struct socket *sock, int backlog);
extern int socket_coproc_getname(struct socket *sock,
				 struct sockaddr *address,
				 int *addrlen,
				 int peer);
extern int socket_coproc_setsockopt(struct socket *sock,
				    int level,
				    int optname,
				    char __user *optval,
				    int optlen);
extern int socket_coproc_getsockopt(struct socket *sock,
				    int level,
				    int optname,
				    char __user *optval,
				    int __user *optlen);
extern int socket_coproc_shutdown(struct socket *sock, int how);

#else  /* CONFIG_SOCK_COPROC */

static inline void socket_coproc_init(void) {}
static inline int socket_coproc_create(struct net *net,
				       struct socket *sock,
				       int protocol,
				       int kern)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_connect(struct socket *sock,
					struct sockaddr *address,
					int addrlen,
					unsigned int flags)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_recvmsg(struct kiocb *iocb,
					struct socket *sock,
					struct msghdr *msg,
					size_t size,
					int flags)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_accept(struct socket *sock,
				       struct socket *newsock,
				       int flags)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_release(struct socket *sock)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_bind(struct socket *sock,
				     struct sockaddr *address,
				     int addrlen)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_ioctl(struct socket *sock,
				      unsigned int cmd,
				      unsigned long arg)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_splice_read(struct socket *sock,
					    loff_t *ppos,
					    struct pipe_inode_info *pipe,
					    size_t len,
					    unsigned int flags)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_poll(struct file *file,
			      struct socket *sock,
			      poll_table *wait,
			      unsigned int *mask)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_mmap(struct file *file,
				     struct socket *sock,
				     struct vm_area_struct *vma)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_sendmsg(struct kiocb *iocb,
					struct socket *sock,
					struct msghdr *msg,
					size_t size)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_listen(struct socket *sock, int backlog)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_getname(struct socket *sock,
					struct sockaddr *address,
					int *addrlen,
					int peer)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_setsockopt(struct socket *sock, int level,
					   int optname, char __user *optval,
					   int optlen)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_getsockopt(struct socket *sock, int level,
					   int optname, char __user *optval,
					   int __user *optlen)
{
	return -ENOTSOCK;
}

static inline int socket_coproc_shutdown(struct socket *sock, int how)
{
	return -ENOTSOCK;
}

#endif  /* CONFIG_SOCK_COPROC */

#endif /* _LINUX_SOCKET_COPROC_H_ */
