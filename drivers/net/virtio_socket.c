/*
 * Virtio-socket driver.
 *
 * Copyright (C) 2011 Google Inc.
 * Author: San Mehat <san@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

/*
 * This driver implements virtualized sockets, backed by a virtio_socket
 * piece of (virtual) hardware.
 *
 * Currently, the symbol naming conventions are as follows:
 *
 * hwsocket_* - These symbols are the entrypoints into the driver from
 * the "socket coprocessor" layer.  They are named as such to keep it
 * clear to the reader what our entrypoints are.  Eventually, the socket
 * coprocessor code will likely need to be re-worked to not be so
 * tightly coupled with this driver, but for the moment, we are the
 * only coprocessor, so that is fine.
 *
 * virtsocket_* - Internal implementation only.  These functions should
 * be completely private to this compile module.
 *
 * vs_* - Short form symbol prefix used for ancillary data structures
 * used to manage driver-local state.  Functions may also use this
 * prefix if they are utility functions for the respective vs_* data
 * types.
 */

#define pr_fmt(fmt) "virtiosocket: " fmt

#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/hwsocket.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/uaccess.h>
#include <linux/in.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <asm/ioctls.h>
#include <linux/wait.h>
#include <linux/hardirq.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/tcp.h> /* For TCP_NODELAY */

#define VIRTIO_SOCKET_F_RX_HEADER	0 /* Receive buffers have headers. */
#define VIRTIO_SOCKET_F_LARGE_BUFFERS	1 /* Use large buffers for receive. */
#define VIRTIO_SOCKET_F_TX_HEADER	2 /* Transmit buffers have headers. */

/* Hardcoded to always pass 169.254.0.0/16 requests to the hardware */
#define VS_PASSTHROUGH_NET	0xA9FE0000
#define VS_PASSTHROUGH_MASK	0xFFFF0000


#define VIRTIO_SOCKET_NOMEM_REFILL_DELAY (HZ/10)
/*
 * The max RX buffer is sized such that we avoid having to make data buffer
 * allocations larger than a page.  We subtract out the skb_shared_info that
 * the networking layer will add to the tail of the data, and also subtract
 * out a cacheline so that cache line alignment doesn't push us over a page.
 */
#define MAX_RX_PACKET_LEN ((PAGE_SIZE - sizeof(struct skb_shared_info)) \
			   & ~(SMP_CACHE_BYTES - 1))
#define MAX_LARGE_RX_PACKET_LEN (((PAGE_SIZE - sizeof(struct skb_shared_info)) \
				 & ~(SMP_CACHE_BYTES - 1)) + \
				(MAX_SKB_FRAGS * PAGE_SIZE))
#define MAX_RX_BUFFER_DEPTH  ((2 * 1024 * 1024) / MAX_RX_PACKET_LEN)
#define MAX_LARGE_RX_BUFFER_DEPTH  ((2 * 1024 * 1024) / MAX_LARGE_RX_PACKET_LEN)

struct virtio_socket_ctrl_hdr {
	__u32 cmd;
} __packed;
#define VIRTIO_SOCKET_CMD_UNKNOWN	0
#define VIRTIO_SOCKET_CMD_CONNECT	1
#define VIRTIO_SOCKET_CMD_CLOSE		2
#define VIRTIO_SOCKET_CMD_DATA		3
#define VIRTIO_SOCKET_CMD_BIND		4
#define VIRTIO_SOCKET_CMD_LISTEN	5
#define VIRTIO_SOCKET_CMD_ACCEPT	6
#define VIRTIO_SOCKET_CMD_GETSOCKNAME	7
#define VIRTIO_SOCKET_CMD_GETPEERNAME	8
#define VIRTIO_SOCKET_CMD_SHUTDOWN_RX	9
#define VIRTIO_SOCKET_CMD_SHUTDOWN_TX	10
#define VIRTIO_SOCKET_CMD_RX_BUFFERS_NOW_AVAILABLE 11
#define VIRTIO_SOCKET_CMD_DATA_HDR	12
#define VIRTIO_SOCKET_CMD_CREATE_UNCONNECTED_SOCKET 13

/*
 * Frames received from the device may be special non-data signals related to
 * a socket.  Each has its own data format in the rx buffer.
 * These signals are identified by the device returning a value in the
 * returned 'len' response field that have the most significant bit set.
 */
static bool virtio_socket_len_is_signal(u32 len)
{
	return len & (1U << 31);
}

/*
 * The following magic values are encoded in the length of received frames, and
 * signal non-data messages.
 */
#define VIRTIO_SOCKET_RX_REMOTE_SHUTDOWN	0xFFFFFFFF
#define VIRTIO_SOCKET_ACCEPTS_AVAILABLE		0xFFFFFFFE
#define VIRTIO_SOCKET_ACCEPTS_NOT_AVAILABLE	0xFFFFFFFD
#define VIRTIO_SOCKET_WRITES_PLUGGED		0xFFFFFFFC
#define VIRTIO_SOCKET_WRITES_UNPLUGGED		0xFFFFFFFB
#define VIRTIO_SOCKET_RECEIVE_OVERRUN		0xFFFFFFFA
#define VIRTIO_SOCKET_SOCKET_RELEASED		0xFFFFFFF9

/* Default weight for how much work should be processed per loop. */
#define NAPI_WEIGHT 64

/*
 * Receive/transmit header for datagrams.  Allows remote peer name
 * identification and frame information.
 */
struct virtio_socket_data_header {
	/* Socket handle/struct sock pointer.  Must always be first. */
	__u64	guest_socket_handle;
	/* Offset from the beginning of the header to the datagram start. */
	__u32	frame_offset;
	/* Frame length information for datagrams. */
	__u32	frame_len;
	/* Offset from the beginning of the header to the peer URI. */
	__u32	uri_offset;
	/* Peer URI length. */
	__u32	uri_len;
} __packed;

/* Private data in the struct sk_buff used by virtiosocket. */
struct virtio_socket_skb_cb {
	/* Length passed in via the virtio queue. */
	__u32					len;
	/* Data cursor position. */
	__u32					cursor;
	/* Frame end position. */
	__u32					frame_end;
	/* Whether this sk_buff has a receive header or not. */
	bool has_receive_header;
} __packed;

struct virtio_socket_connect_args {
	__u64	guest_socket_handle;
	__u32	uri_len;
	__u8	endpoint_uri[0];
} __packed;

struct virtio_socket_bind_args {
	__u64	guest_socket_handle;
	__u32	uri_len;
	__u8	endpoint_uri[0];
} __packed;

struct virtio_socket_listen_args {
	__u64	guest_socket_handle;
	__u32	backlog;
} __packed;

struct virtio_socket_accept_args {
	__u64	guest_socket_handle;
	__u64	new_socket_handle;
} __packed;

struct virtio_socket_simple_args {
	__u64	guest_socket_handle;
} __packed;

struct virtio_socket_data_args {
	__u64   guest_socket_handle;
	__u32   len;
} __packed;

typedef __u8 virtio_socket_ctrl_ack;

/*
 * Device-specific error codes for control messages.
 */
#define VIRTIO_SOCKET_OK			0x00
#define VIRTIO_SOCKET_NOTHANDLED		0x01
#define VIRTIO_SOCKET_NOSUCHCOMMAND		0x02
#define VIRTIO_SOCKET_NOSUCHSOCKETHANDLE	0x03
#define VIRTIO_SOCKET_HANDLEALREADYEXISTS	0x04

/*
 * Error codes with bit 7 set semantically map to errno values.
 */
#define VIRTIO_SOCKET_EINVAL		0x80
#define VIRTIO_SOCKET_EAGAIN		0x81
#define VIRTIO_SOCKET_ECONNABORTED	0x82
#define VIRTIO_SOCKET_EIO		0x83
#define VIRTIO_SOCKET_EISCONN		0x84
#define VIRTIO_SOCKET_ENOTCONN		0x85
#define VIRTIO_SOCKET_EPIPE		0x86
#define VIRTIO_SOCKET_ENETUNREACH	0x87
#define VIRTIO_SOCKET_EADDRNOTAVAIL	0x88
#define VIRTIO_SOCKET_ECONNREFUSED	0x89
#define VIRTIO_SOCKET_EHOSTUNREACH	0x8a
#define VIRTIO_SOCKET_EADDRINUSE	0x8b


/*
 * Maximum SKB fragments (to hold a full 64k-ish fragment) plus one for the
 * command-specific header, plus one for the "extra" information the
 * command-specific header may require (peer URI in sendmsg, for example).
 */
#define VIRTIO_SOCKET_SEND_COMMAND_SG_MAX (MAX_SKB_FRAGS + 2)

struct virtsocket_info {
	struct napi_struct napi;
	struct virtio_device *vdev;
	struct virtqueue *drv_rx;
	struct virtqueue *drv_tx;
	struct virtqueue *drv_ctl;

	/* Serializes the rx queue.  Taken in BH context. */
	struct spinlock rx_lock;
	/* Serializes the ctl queue.  Taken in BH context. */
	struct spinlock ctl_lock;
	wait_queue_head_t ctl_enqueue_space;

	/*
	 * Whether or not receive packets have a header (true) or just a handle
	 * (false).
	 */
	bool receive_has_header;

	/* Use large buffers (true) or not (false). */
	bool largeones;

	/*
	 * Whether or transmit receive packets have a header (true) or just a
	 * handle (false).
	 */
	bool transmit_has_header;

	/*
	 * The count of outstanding hijacked sockets.
	 */
	atomic_long_t hijacked_sockets;

	/*
	 * The count of sockets from the connect path that are referenced.
	 */
	atomic_long_t connect_refs;

	/*
	 * The count of sockets from the bind path that are referenced.
	 */
	atomic_long_t bind_refs;

	/*
	 * The count of sockets from the accept path that are referenced.
	 */
	atomic_long_t accept_refs;
};

/*
 * Command status states
 *
 * Commands become "issued" when they are first sent to the hardware.
 * Valid transitions include:
 *   armed  -> issued      --   New command is issued and will be waited
 *			      upon by the issuer.
 *   armed  -> ignored     --   Command was issued but no one is waiting
 *			      on the result to come back from the
 *			      hardware.
 *   issued -> responded   --   Transition occurs in the bottom half
 *			      when the reply comes back from hardware.
 *   issued -> cancelled   --   If the process that created the command
 *			      gave up on the request due to an
 *			      interruption.
 *
 *   If a command is "responded", the issuing thread must cleanup.  If
 *   it is cancelled, the ->cancel() callback is invoked when a response
 *   comes back from the hardware.   This callback can then undo
 *   whatever state needs to be cleaned up.  The cancel callback should
 *   _not_ free the cmd.
 */
enum vs_cmd_status {
	VS_CMD_ARMED = 1,
	VS_CMD_ISSUED,
	VS_CMD_CANCELLED,
	VS_CMD_RESPONDED,
	VS_CMD_IGNORED,
};

struct vs_cmd;
typedef void (*vs_cmd_callback_t)(struct vs_cmd *);

struct vs_cmd {
	spinlock_t lock;		/* Protects the cmd_status */
	struct completion complete;	/* Used for waiting for a command. */

	enum vs_cmd_status cmd_status; /* protected by wqh->lock once issued */
	bool interruptible;

	struct list_head cancel_list;  /* Used to enqueue cancel work */

	/* Callbacks */
	struct sock *socket;		/* Socket when needed on callbacks.
					   Holds a reference to the socket. */
	vs_cmd_callback_t cancel;	/* Called from process context */
	vs_cmd_callback_t cleanup;	/* Called from bottom half context
					 * Only valid on 'ignored' cmds. */

	/* Buffers used as part of the virtio command transaction */
	struct virtio_socket_ctrl_hdr ctrl; /* out-only */
	virtio_socket_ctrl_ack hw_ack;      /* in-only */

	/* Buffers for specific commands */
	union {
		struct virtio_socket_accept_args accept_args;
		struct virtio_socket_bind_args bind_args;
		struct virtio_socket_connect_args connect_args;
		struct virtio_socket_data_args data_args;
		struct virtio_socket_data_header data_header;
		struct virtio_socket_listen_args listen_args;
		struct virtio_socket_simple_args simple_args;
		struct virtio_socket_bind_args create_unconnected_args;
	};

	/*
	 * Buffer space for sending the guest control block address to the
	 * host.  Defined to be 64bit physical address regardless of our
	 * pointer width.
	 */
	u64 guest_control_block;

	/* Space to be used by issuers of vs_cmds. */
	void *private;
	u64 data;
	struct list_head reuse_list;   /* Used to enqueue re-used cancels.
					  Should be used with sk_lock held. */
};

static struct net_device *net_device;

/* Accessor into the skb's control block for storing private data. */
static struct virtio_socket_skb_cb *skb_private(struct sk_buff *skb)
{
	return (struct virtio_socket_skb_cb *)(skb->cb);
}

/* Return the receive header for a struct sk_buff. */
static struct virtio_socket_data_header *vs_receive_header(
	struct sk_buff *skb)
{
	return skb_private(skb)->has_receive_header ?
	       ((struct virtio_socket_data_header *) skb->head) : NULL;
}

/* Return the receive header for a struct sk_buff. */
static unsigned int vs_skb_datasize(struct sk_buff *skb)
{
	return skb_end_pointer(skb) - skb->head;
}

/*
 * Pull a socket handle from the sk_buff, changing the data pointer to point
 * past the header.
 */
static struct sock *pop_socket_handle(struct sk_buff *skb)
{
	struct sock *sk;
	u64 *handle = (u64 *)skb->data;
	BUG_ON(!handle);
	skb_put(skb, sizeof(*handle));
	skb_pull(skb, sizeof(*handle));
	sk = (struct sock *)(*handle);
	return sk;
}

/*
 * Allocate a vs_cmd.
 *
 * Returns NULL on failure to allocate memory.
 */
static struct vs_cmd *vs_alloc_cmd(u32 cmd_key)
{
	struct vs_cmd *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return NULL;
	spin_lock_init(&cmd->lock);
	init_completion(&cmd->complete);
	cmd->ctrl.cmd = cmd_key;
	cmd->cmd_status = VS_CMD_ARMED;

	return cmd;
}

/*
 * Allocate a vs_cmd that is prepared for an interruptible wait.
 *
 * Returns NULL on failure to allocate memory.
 */
static struct vs_cmd *
vs_alloc_interruptible_cmd(u32 cmd_key,
			   vs_cmd_callback_t cancel_cb, struct sock *sk)
{
	struct vs_cmd *cmd;

	BUG_ON(cancel_cb == NULL);

	cmd = vs_alloc_cmd(cmd_key);
	if (!cmd)
		return cmd;

	cmd->cancel = cancel_cb;
	cmd->interruptible = true;

	/*
	 * Bump the reference count so that the socket is available in
	 * the cancel path.
	 */
	sock_hold(sk);
	cmd->socket = sk;

	return cmd;
}

static void vs_destroy_cmd(struct vs_cmd *cmd)
{
	if (cmd->socket)
		sock_put(cmd->socket);
	kfree(cmd);
}

/*
 * Send a virtsocket command to the hardware.
 *
 * Returns zero on success, or a negative error code on failure:
 *   -EINTR: Returned if the vs_cmd was interruptible and we got a signal
 *   while waiting for space.
 */
static int
__vs_issue_cmd(struct vs_cmd *cmd, struct scatterlist *data, int out, int in)
{
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	struct scatterlist *s, sg[VIRTIO_SOCKET_SEND_COMMAND_SG_MAX + 2];
	DEFINE_WAIT(wait);
	int err;
	int i;

	BUG_ON(out + in > VIRTIO_SOCKET_SEND_COMMAND_SG_MAX);
	/*
	 * Setup the actual scatterlist passed to the hardware.  note
	 * that 'sg' here is okay on stack as it isn't referenced once
	 * virtqueue_add_buf() returns.
	 *
	 * Layout:
	 *   - One out buffer for the control header.
	 *   - Caller elements (out followed by in).
	 *   - One in buffer for the message response.
	 */
	out++;
	in++;
	sg_init_table(sg, out + in);
	sg_set_buf(&sg[0], &cmd->ctrl, sizeof(cmd->ctrl));
	for_each_sg(data, s, out + in - 2, i)
		sg_set_buf(&sg[i + 1], sg_virt(s), s->length);
	sg_set_buf(&sg[out + in - 1], &cmd->hw_ack, sizeof(cmd->hw_ack));

again:
	/*
	 * Handle running out of room by queueing up on a wait_queue_head
	 * waiting to be kicked by the control interrupt.
	 */
	spin_lock_bh(&drv_info->ctl_lock);
	prepare_to_wait(&drv_info->ctl_enqueue_space, &wait,
			cmd->interruptible ?
			  TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
	err = virtqueue_add_buf(drv_info->drv_ctl, sg, out, in, cmd,
				GFP_ATOMIC);
	if (err == -ENOSPC) {
		spin_unlock_bh(&drv_info->ctl_lock);
		if (!cmd->interruptible || !signal_pending(current))
			schedule();
		finish_wait(&drv_info->ctl_enqueue_space, &wait);
		if (cmd->interruptible && signal_pending(current)) {
			err = -EINTR;
			goto out;
		}
		goto again;
	}
	finish_wait(&drv_info->ctl_enqueue_space, &wait);
	if (err < 0)
		goto out_unlock;

	virtqueue_kick(drv_info->drv_ctl);
out_unlock:
	spin_unlock_bh(&drv_info->ctl_lock);
out:
	return err > 0 ? 0 : err;
}

static int
vs_issue_cmd(struct vs_cmd *cmd, struct scatterlist *data, int out, int in)
{
	BUG_ON(cmd->cmd_status != VS_CMD_ARMED);

	cmd->cmd_status = VS_CMD_ISSUED;

	return __vs_issue_cmd(cmd, data, out, in);
}

static int
vs_issue_and_forget_cmd(struct vs_cmd *cmd, vs_cmd_callback_t cleanup,
			struct scatterlist *data, int out, int in)
{
	BUG_ON(cmd->cmd_status != VS_CMD_ARMED);

	cmd->cmd_status = VS_CMD_IGNORED;
	cmd->cleanup = cleanup;

	return __vs_issue_cmd(cmd, data, out, in);
}

static int vs_ack_to_ret(virtio_socket_ctrl_ack ack)
{
	switch (ack) {
	/* Device specific error codes. */
	case VIRTIO_SOCKET_OK:
		return 0;
	case VIRTIO_SOCKET_NOTHANDLED:
		return -ENOTSOCK;
	case VIRTIO_SOCKET_NOSUCHCOMMAND:
		pr_err("Device did not recognize command\n");
		return -EIO;
	case VIRTIO_SOCKET_NOSUCHSOCKETHANDLE:
		pr_debug("Device did not recognize socket handle\n");
		return -EIO;
	case VIRTIO_SOCKET_HANDLEALREADYEXISTS:
		pr_err("Device already knows about this handle\n");
		return -EIO;
	/* Errno mapped error codes. */
	case VIRTIO_SOCKET_EINVAL:
		return -EINVAL;
	case VIRTIO_SOCKET_EAGAIN:
		return -EAGAIN;
	case VIRTIO_SOCKET_ECONNABORTED:
		return -ECONNABORTED;
	case VIRTIO_SOCKET_EIO:
		return -EIO;
	case VIRTIO_SOCKET_EISCONN:
		return -EISCONN;
	case VIRTIO_SOCKET_ENOTCONN:
		return -ENOTCONN;
	case VIRTIO_SOCKET_EPIPE:
		return -EPIPE;
	case VIRTIO_SOCKET_ENETUNREACH:
		return -ENETUNREACH;
	case VIRTIO_SOCKET_EADDRNOTAVAIL:
		return -EADDRNOTAVAIL;
	case VIRTIO_SOCKET_ECONNREFUSED:
		return -ECONNREFUSED;
	case VIRTIO_SOCKET_EHOSTUNREACH:
		return -EHOSTUNREACH;
	case VIRTIO_SOCKET_EADDRINUSE:
		return -EADDRINUSE;
	default:
		if (printk_ratelimit())
			pr_warn("Unrecognized ack from device: %d\n", ack);
		return -EIO;
	}
}

/*
 * Wait for an issued command to complete.
 *
 * cmd is consumed by this call.
 * deal_with_cancel specifies whether or not to cancel the command when the wait
 * for the command completion is interrupted.
 *
 * Must be called from process context.
 *
 * Returns:
 *      0:  The command is completed and was successful.
 * -EINTR:  The command was interrupted by a pending signal.  The cancel
 *          callback will eventually be invoked when the command is completed,
 *          unless deal_with_cancel was false..
 *  other:  Other negative errno values may be returned from the hardware.
 */
static int __vs_complete_cmd(struct vs_cmd *cmd, bool deal_with_cancel)
{
	int ret;

	if (cmd->interruptible)
		ret = wait_for_completion_interruptible(&cmd->complete);
	else
		ret = wait_for_completion_killable(&cmd->complete);
	if (ret == -ERESTARTSYS) {
		bool call_cancel = false;

		/*
		 * If the caller doesn't want us to deal with the cancel, just
		 * return -EINTR immediately.  It is assumed that the
		 * caller will re-call __vs_complete_cmd later.
		 */
		if (!deal_with_cancel)
			return -EINTR;

		/*
		 * We must check if the command status is still issued
		 * here as it may have completed before we acquired the
		 * lock.
		 */
		spin_lock_irq(&cmd->lock);
		if (cmd->cmd_status == VS_CMD_ISSUED)
			cmd->cmd_status = VS_CMD_CANCELLED;
		else if (cmd->cmd_status == VS_CMD_RESPONDED)
			call_cancel = true;
		else
			BUG();
		spin_unlock_irq(&cmd->lock);
		ret = -EINTR;
		if (call_cancel) {
			cmd->cancel(cmd);
			vs_destroy_cmd(cmd);
		}
	} else {
		/* The command has completed. */
		BUG_ON(cmd->cmd_status != VS_CMD_RESPONDED);
		ret = vs_ack_to_ret(cmd->hw_ack);
		vs_destroy_cmd(cmd);
	}
	return ret;
}

static int vs_complete_cmd(struct vs_cmd *cmd)
{
	return __vs_complete_cmd(cmd, true);
}

static LIST_HEAD(cancel_work_list);
static DEFINE_SPINLOCK(cancel_work_lock);
static void invoke_cancels(struct work_struct *work)
{
	struct vs_cmd *cmd, *tmp;

	spin_lock_irq(&cancel_work_lock);
	list_for_each_entry_safe(cmd, tmp, &cancel_work_list, cancel_list) {
		cmd->cancel(cmd);
		list_del(&cmd->cancel_list);
		vs_destroy_cmd(cmd);
	}
	spin_unlock_irq(&cancel_work_lock);
}
static DECLARE_WORK(cancel_work, invoke_cancels);

static void handle_ctl_queue(unsigned long unused)
{
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	unsigned int len;
	struct vs_cmd *cmd;
	enum vs_cmd_status cmd_status;
	LIST_HEAD(cmds_to_cancel);

	BUG_ON(!in_interrupt());

	/*
	 * TODO: Currently, this loop can potentially take a long time.
	 * It would be better to have it spin for a little while,
	 * followed perhaps by processing in the bottom half.  Getting
	 * this registered with NAPI is probably the best solution,
	 * though we currently do not export a network device.
	 */
	spin_lock(&drv_info->ctl_lock);
	while ((cmd = virtqueue_get_buf(drv_info->drv_ctl, &len)) != NULL) {
		bool destroy_cmd = false;
		bool complete_cmd = false;

		spin_lock(&cmd->lock);
		cmd_status = cmd->cmd_status;
		if (cmd_status == VS_CMD_IGNORED) {
			destroy_cmd = true;
		} else if (cmd_status == VS_CMD_ISSUED) {
			/* Process still waiting */
			cmd->cmd_status = VS_CMD_RESPONDED;
			complete_cmd = true;
		} else if (cmd_status == VS_CMD_CANCELLED) {
			list_add_tail(&cmd->cancel_list, &cmds_to_cancel);
		} else
			BUG();
		spin_unlock(&cmd->lock);
		if (complete_cmd)
			complete(&cmd->complete);
		if (destroy_cmd) {
			if (cmd->cleanup)
				cmd->cleanup(cmd);
			vs_destroy_cmd(cmd);
		}
	}
	wake_up(&drv_info->ctl_enqueue_space);
	spin_unlock(&drv_info->ctl_lock);
	if (!list_empty(&cmds_to_cancel)) {
		spin_lock(&cancel_work_lock);
		list_splice(&cmds_to_cancel, &cancel_work_list);
		spin_unlock(&cancel_work_lock);
		schedule_work(&cancel_work);
	}
}
static DECLARE_TASKLET(ctl_tasklet, handle_ctl_queue, 0);

static void virtsocket_ctl_cb(struct virtqueue *svq)
{
	tasklet_hi_schedule(&ctl_tasklet);
}

int is_sockaddr_hwsocket(enum sock_type type, struct sockaddr *addr,
			 int addrlen)
{
	struct sockaddr_in *in = (struct sockaddr_in *) addr;

	if (!addr || addrlen < sizeof(*in))
		return 0;
	if (addr->sa_family != AF_INET)
		return 0;
	if (type != SOCK_STREAM && type != SOCK_DGRAM)
		return 0;
	/*  TODO(mikew): ask hardware or check a cache */
	if (in->sin_addr.s_addr == htonl(INADDR_LOOPBACK + 1))
		return 1;
	if ((in->sin_addr.s_addr & htonl(VS_PASSTHROUGH_MASK)) ==
	    htonl(VS_PASSTHROUGH_NET))
		return 1;
	return 0;
}

int hwsocket_ioctl(struct socket *sock, unsigned int cmd,
		   unsigned long arg)
{
	struct sock *sk = sock->sk;
	int ret;
	switch (cmd) {
	case FIONREAD:
		{
			struct sk_buff *skb;
			int amount = 0;
			lock_sock(sk);
			skb_queue_walk(&sk->sk_receive_queue, skb) {
				int new_amount = amount +
					skb_private(skb)->frame_end -
					skb_private(skb)->cursor;
				/* TODO: we don't process the backlog here. */
				if (new_amount < amount)
					break;
				amount = new_amount;
			}
			release_sock(sk);
			ret = put_user(amount, (int __user *)arg);
			break;
		}
	default:
		ret = -ENOSYS;
		break;
	}
	return ret;
}

int hwsocket_setsockopt(struct socket *sock,
			int level,
			int optname,
			char __user *optval,
			int optlen)
{
	if (level == SOL_TCP && optname == TCP_NODELAY)
		return 0; /* FIXME(digitaleric): really implement! */
	return -ENOSYS;
}

int hwsocket_getsockopt(struct socket *sock,
			int level,
			int optname,
			char __user *optval,
			int __user *optlen)
{
	return -ENOSYS;
}

/*
 * Returns true when writes are no longer plugged.
 * Called from process context.
 */
static bool vs_writes_no_longer_plugged(struct sock *sk)
{
	struct inet_sock *isk = inet_sk(sk);
	bool ret;

	/* TODO(mikew): This seems like a lot of serialization. */
	local_bh_disable();
	bh_lock_sock(sk);
	ret = !isk->writes_plugged;
	bh_unlock_sock(sk);
	local_bh_enable();
	return ret;
}

/* Returns true if writes are not currently plugged. */
static int __must_check vs_wait_sendmsg(struct sock *sk)
{
	int rc;
	/* TODO(mikew): Plumb timeout here */
	long timeo = MAX_SCHEDULE_TIMEOUT;
	DEFINE_WAIT(wait);

	prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	rc = sk_wait_event(sk, &timeo, vs_writes_no_longer_plugged(sk));
	clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	finish_wait(sk_sleep(sk), &wait);
	return rc;
}

static void wake_socket_data(struct sock *sk, long poll_mask, long async_band)
{
	/* TODO(fes): Use poll_mask and async_band. */
	struct socket_wq *wq;
	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLIN | POLLRDNORM);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
}

void vs_scatter_cleanup(struct vs_cmd *cmd)
{
	int idx;
	struct scatterlist *sg = (struct scatterlist *) cmd->private;
	for (idx = 0; idx < cmd->data; idx++) {
		/* Everything is offset by one as the first sg entry actually
		 * stores the data_args or data_header. */
		kfree(sg_virt(&sg[idx + 1]));
	}
	kfree(sg);
}

void vs_write_cleanup(struct vs_cmd *cmd)
{
	int ret = vs_ack_to_ret(cmd->hw_ack);
	if (ret == -EPIPE || ret == -ENOTCONN || ret == -EIO ||
	    ret == -ECONNRESET) {
		struct sock *sk;
		pr_debug("Remote side tx shutdown\n");
		/* Get the right struct sock pointer if headers are in use. */
		if (cmd->ctrl.cmd == VIRTIO_SOCKET_CMD_DATA_HDR)
			sk = (struct sock *)
				cmd->data_header.guest_socket_handle;
		else
			sk = (struct sock *)
				cmd->data_args.guest_socket_handle;
		bh_lock_sock(sk);
		sk->sk_shutdown |= SEND_SHUTDOWN;
		wake_socket_data(sk, POLLOUT | POLLHUP, POLL_OUT);
		bh_unlock_sock(sk);
	}
	vs_scatter_cleanup(cmd);
}

static void vs_free_skb_frags(struct sk_buff *skb, int starting_at)
{
	int i;
	for (i = starting_at; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		/* TODO(mikew): Convert this over to the frag API? */
		__free_page(f->page.p);
	}
	skb_shinfo(skb)->nr_frags = starting_at;
}

char *sockaddr_to_uri(enum sock_type type,
		      struct sockaddr *addr,
		      int addrlen,
		      char *buffer,
		      int buffsize)
{
	memset(buffer, 0, buffsize);
	switch (addr->sa_family) {
	case AF_INET: {
		static char *type_names[] = {
			[SOCK_STREAM] = "tcp",
			[SOCK_DGRAM] = "udp",
		};
		struct sockaddr_in *in = (struct sockaddr_in *) addr;
		u32 ip = ntohl(in->sin_addr.s_addr);
		if (type >= ARRAY_SIZE(type_names) || !type_names[type]) {
			WARN_ON_ONCE(1);
			snprintf(buffer, buffsize, "unknown://");
			break;
		}
		snprintf(buffer,
			 buffsize,
			 "%s://%u.%u.%u.%u:%u",
			 type_names[type],
			 (ip >> 24) & 0xff,
			 (ip >> 16) & 0xff,
			 (ip >> 8) & 0xff,
			 ip & 0xff,
			 ntohs(in->sin_port));
		break;
	}
	default:
		pr_err("Unsupported AF (%u)\n", addr->sa_family);
		snprintf(buffer, buffsize, "unknown://");
	}
	return buffer;
}

/*
 * Transmit up to 'size' bytes of the data described by msg, in a single
 * send data command.
 */
static int __hwsocket_sendmsg(struct sock *sk, struct iovec **iov,
			      __kernel_size_t *iovlen, size_t size,
			      struct sockaddr *peer, int peer_len,
			      bool blocking)
{
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	struct vs_cmd *cmd;
	int err;
	struct scatterlist *sg;
	size_t data_copied;
	int sg_index;
	int sgvecs_left;
	int pages_needed;
	char *peer_uri;
	int peer_uri_len;
	__u32 *len_ptr;
	int extra_sg;

	BUG_ON(!net_device);

	/*
	 * We want to carry the lock_sock() across the cmd send below as
	 * we'd like to only allow a single user process to transmit
	 * something for any given
	 * "vs_writes_no_longer_plugged() == true"
	 */
	lock_sock(sk);

	if (sk->sk_shutdown & SEND_SHUTDOWN) {
		release_sock(sk);
		return -EPIPE;
	}
	if (blocking) {
		bool unplugged;
		do {
			unplugged = vs_wait_sendmsg(sk);
			if (signal_pending(current)) {
				release_sock(sk);
				return -EINTR;
			}
		} while (!unplugged);
	} else if (!vs_writes_no_longer_plugged(sk)) {
		release_sock(sk);
		return -EAGAIN;
	}

	pr_debug("%s: sk %p size %lu\n", __func__, sk, size);
	pr_debug("%s: iovlen %d\n", __func__, (int)*iovlen);

	if (drv_info->transmit_has_header && peer && peer_len) {
		peer_uri = kmalloc(HWSOCKET_URI_MAXLEN, GFP_KERNEL);
		if (!peer_uri) {
			release_sock(sk);
			return -ENOMEM;
		}
		sockaddr_to_uri((sk->sk_protocol == IPPROTO_TCP ? SOCK_STREAM :
				 SOCK_DGRAM), peer, peer_len, peer_uri,
				HWSOCKET_URI_MAXLEN);
		peer_uri_len = strlen(peer_uri);
	} else {
		peer_uri = NULL;
		peer_uri_len = 0;
	}

	/*
	 * For UDP, we need to send the entire datagram and fail otherwise.  TCP
	 * can send part of the buffer, because for SOCK_STREAM, data doesn't
	 * have to be sent in a single command (the bytes sent in this call to
	 * sendmsg is returned, and the caller is responsible for continuing
	 * from that point.
	 */
	extra_sg = (peer_uri ? 2 : 1);
	pages_needed = round_up(size, PAGE_SIZE) / PAGE_SIZE;
	if (sk->sk_protocol != IPPROTO_TCP) {
		if (pages_needed + extra_sg >
		    VIRTIO_SOCKET_SEND_COMMAND_SG_MAX) {
			kfree(peer_uri);
			release_sock(sk);
			return -EMSGSIZE;
		}
	} else {
		if (pages_needed + extra_sg >
		    VIRTIO_SOCKET_SEND_COMMAND_SG_MAX)
			pages_needed = VIRTIO_SOCKET_SEND_COMMAND_SG_MAX -
				       extra_sg;
	}

	err = -ENOMEM;
	cmd = vs_alloc_cmd((drv_info->transmit_has_header ?
			    VIRTIO_SOCKET_CMD_DATA_HDR :
			    VIRTIO_SOCKET_CMD_DATA));
	if (!cmd) {
		kfree(peer_uri);
		release_sock(sk);
		return PTR_ERR(cmd);
	}

	/* The Scatterlist can't be on the stack.
	 * Number of entries is number of iovecs plus one for the command
	 */
	sg = kmalloc(sizeof(struct scatterlist) * (pages_needed + extra_sg),
		     GFP_KERNEL);
	if (!sg) {
		vs_destroy_cmd(cmd);
		kfree(peer_uri);
		release_sock(sk);
		return err;
	}
	sg_init_table(sg, pages_needed + extra_sg);
	cmd->private = sg;
	/* Use data to count the number of segments allocated,
	 * so we can free them up in scatter_cleanup. */
	cmd->data = 0;

	/* Note that we consume one sg element for the args. */
	sgvecs_left = pages_needed;
	sg_index = 1;

	if (drv_info->transmit_has_header) {
		__u32 offset = sizeof(cmd->data_header);
		sg_set_buf(&sg[0], &cmd->data_header, sizeof(cmd->data_header));
		len_ptr = &cmd->data_header.frame_len;
		cmd->data_header.guest_socket_handle = (__u64) sk;
		cmd->data_header.uri_offset = offset;
		cmd->data_header.uri_len = peer_uri_len;
		if (peer_uri) {
			sg_set_buf(&sg[sg_index], peer_uri, peer_uri_len);
			cmd->data++;
			sg_index++;
		}
		offset += peer_uri_len;
		cmd->data_header.frame_offset = offset;
		cmd->data_header.frame_len = 0;
	} else {
		sg_set_buf(&sg[0], &cmd->data_args, sizeof(cmd->data_args));
		len_ptr = &cmd->data_args.len;
		cmd->data_args.guest_socket_handle = (__u64) sk;
		cmd->data_args.len = 0;
	}

	/* Iterate through the vectors that we are building */
	while (--sgvecs_left >= 0 && *iovlen) {
		size_t buffer_size = min(PAGE_SIZE, size);
		size_t buffer_left = buffer_size;
		unsigned char *buffer, *buffer_start;

		buffer = buffer_start = kmalloc(buffer_size, GFP_KERNEL);
		if (!buffer_start)
			goto out_err; /* TODO(mikew): Handle this correctly? */

		/* Iterate through the user's iovec */
		while (*iovlen && buffer_left) {
			size_t to_copy = min(buffer_left, (*iov)->iov_len);
			if (copy_from_user(buffer, (*iov)->iov_base, to_copy)) {
				kfree(buffer_start);
				err = -EFAULT;
				goto out_err;
			}
			(*iov)->iov_len -= to_copy;
			(*iov)->iov_base += to_copy;
			if ((*iov)->iov_len == 0) {
				/* Move onto the next iovec */
				(*iov)++;
				(*iovlen)--;
			}
			buffer_left -= to_copy;
			buffer += to_copy;

			*len_ptr += to_copy;
		}

		cmd->data++;
		sg_set_buf(&sg[sg_index], buffer_start, buffer - buffer_start);
		sg_index++;
		size -= buffer_size;
	}

	data_copied = *len_ptr;
	err = vs_issue_and_forget_cmd(cmd, vs_write_cleanup, sg, sg_index, 0);
	if (err < 0)
		goto out_err;
	release_sock(sk);
	return data_copied;
out_err:
	vs_scatter_cleanup(cmd);
	vs_destroy_cmd(cmd);
	release_sock(sk);
	return err;
}

int hwsocket_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	/* Loop and issue as many commands as possible */
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	int ret;
	size_t data_copied = 0;
	__kernel_size_t iovlen = msg->msg_iovlen;
	struct iovec *iov = msg->msg_iov;
	int flags = msg->msg_flags;
	bool blocking = !(flags & MSG_DONTWAIT);
	struct sockaddr *peer = NULL;
	int peer_len = 0;

	if (sk->sk_protocol != IPPROTO_TCP &&
	    msg->msg_name && msg->msg_namelen) {
		ret = -ENOTCONN;
		if (sk->sk_state == TCP_ESTABLISHED &&
		    msg->msg_namelen >= sizeof(struct sockaddr_in)) {
			struct inet_sock *inet = inet_sk(sk);
			struct sockaddr_in *sin =
				(struct sockaddr_in *)msg->msg_name;
			if (sin->sin_family == AF_INET &&
			    sin->sin_port == inet->inet_dport &&
			    sin->sin_addr.s_addr == inet->inet_daddr) {
				/* Allow msg_name to specify existing remote. */
				ret = 0;
			}
		} else if (drv_info->transmit_has_header &&
			   msg->msg_namelen >= sizeof(struct sockaddr_in)) {
			peer = msg->msg_name;
			peer_len = msg->msg_namelen;
			ret = 0;
		}
		if (ret) {
			pr_warn("hwsocket_sendmsg does not support destination "
				"addresses in msg_name.\n");
			return ret;
		}
	}
	/* TODO(mikew): How do we serialize with a close event? */
	while (size) {
		ret = __hwsocket_sendmsg(sk, &iov, &iovlen, size, peer,
					 peer_len, blocking);
		if (ret < 0) {
			if (data_copied != 0)
				return data_copied;
			else
				return ret;
		}
		data_copied += ret;
		size -= ret;
	}
	return data_copied;
}

static bool vs_recvmsg_should_wake_up(struct sock *sk)
{
	if (!skb_queue_empty(&sk->sk_receive_queue))
		return true;
	if ((sk->sk_shutdown & RCV_SHUTDOWN) != 0)
		return true;
	return false;
}

/*
 * Blocks until there is either data on the socket, the receive side of the
 * socket has closed, or there is a signal pending.
 *
 * Must be called with lock_sock().  May drop and re-acquire the lock_sock().
 */
static void vs_wait_recvmsg(struct sock *sk)
{
	/* TODO(mikew): Plumb timeout here */
	long timeo = MAX_SCHEDULE_TIMEOUT;
	DEFINE_WAIT(wait);

	prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	while (1) {
		bool rc;
		rc = sk_wait_event(sk, &timeo, vs_recvmsg_should_wake_up(sk));
		if (rc || signal_pending(current))
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
}

/*
 * Schedule a work item to be processed.  Returns true if this call set the work
 * bit, or false if it was already set.
 * Does not need to be called with the sock bh-locked.
 */
static bool __schedule_cmd_work(struct sock *sk, unsigned long cmd_work,
				unsigned long delay)
{
	struct inet_sock *isk = inet_sk(sk);
	unsigned long expected_bitmap, previous_bitmap, new_bitmap;
	BUG_ON(!in_interrupt());
	/* reference is released when work is done. */
	sock_hold(sk);
	do {
		expected_bitmap = atomic_long_read(&isk->cmd_bitmap);
		new_bitmap = expected_bitmap;
		/* Already set?  If so, nothing to do. */
		if (__test_and_set_bit(cmd_work, &new_bitmap)) {
			sock_put(sk);
			return false;
		}
		previous_bitmap = atomic_long_cmpxchg(&isk->cmd_bitmap,
						      expected_bitmap,
						      new_bitmap);
	} while (previous_bitmap != expected_bitmap);
	schedule_delayed_work(&isk->cmd_work, delay);
	return true;
}

/*
 * Schedule a work item to be processed.
 * Must be called from process context.  Will bh-lock the socket temporarily.
 */
static void schedule_cmd_work(struct sock *sk, unsigned long cmd_work,
			      unsigned long delay)
{
	local_bh_disable();
	bh_lock_sock(sk);
	__schedule_cmd_work(sk, cmd_work, delay);
	bh_unlock_sock(sk);
	local_bh_enable();
}

static void notify_host_rx_tail_updated(struct sock *sk)
{
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	struct scatterlist sg[1];
	struct vs_cmd *cmd;
	int ret;

	pr_debug("Notifying host that rx_tail moved\n");

	pr_debug("%s: sk %p\n", __func__, sk);

	BUG_ON(!drv_info);

	cmd = vs_alloc_cmd(VIRTIO_SOCKET_CMD_RX_BUFFERS_NOW_AVAILABLE);
	if (!cmd) {
		/* Try again in a little while. */
		schedule_cmd_work(sk, VIRTIO_SOCKET_SCHEDULED_RX_UNDERRUN,
				  VIRTIO_SOCKET_NOMEM_REFILL_DELAY);
		return;
	}

	cmd->simple_args.guest_socket_handle = (__u64) sk;

	sg_init_table(sg, 1);
	sg_set_buf(&sg[0], &cmd->simple_args, sizeof(cmd->simple_args));

	ret = vs_issue_and_forget_cmd(cmd, NULL, sg, 1, 0);
	if (ret) {
		vs_destroy_cmd(cmd);
		schedule_cmd_work(sk, VIRTIO_SOCKET_SCHEDULED_RX_UNDERRUN,
				  VIRTIO_SOCKET_NOMEM_REFILL_DELAY);
		return;
	}
	pr_debug("%s: sk %p notify rx_tail update\n", __func__, sk);
}

/*
 * update_rx_tail: Move the rx tail forward, notifying the host if neccesary.
 * Called from process context with the socket user locked.
 */
static void update_rx_tail(struct sock *sk, int buffers_completed)
{
	struct inet_sock *isk = inet_sk(sk);
	bool host_waiting_for_rx_tail;

	if (!buffers_completed)
		return;
	/*
	 * We need to BH-lock the socket to serialize against the bottom
	 * half processing of notifications.
	 */
	local_bh_disable();
	bh_lock_sock(sk);
	/*
	 * TODO(mikew): This *happens* to be atomic from the host's
	 * perspective as it is a 32bit store, but is this true for all
	 * architectures?
	 */
	isk->gcb.rx_tail += buffers_completed;
	host_waiting_for_rx_tail = isk->host_waiting_for_rx_tail;
	isk->host_waiting_for_rx_tail = false;
	bh_unlock_sock(sk);
	local_bh_enable();
	/* Notify the host if it was waiting for the rx_tail to move. */
	if (host_waiting_for_rx_tail)
		notify_host_rx_tail_updated(sk);
}

/* Translate a URI path NULL-terminated string into a sockaddr. */
static int vs_parse_uri_to_address(const char *buffer,
				   u32 uri_length,
				   struct sockaddr *address,
				   int *addrlen)
{
	unsigned long port;
	struct sockaddr_in addrin = {0};
	addrin.sin_family = AF_INET;

	/*
	 * We only understand URIs in the form:
	 * tcp://<ipv4 address>:<port>
	 * aka: tcp://127.0.0.1:3234
	 */
	if (strncmp(buffer, "tcp://", 6) &&
	    strncmp(buffer, "udp://", 6))
		return -EINVAL;
	buffer += 6;

	if (!in4_pton(buffer, -1, (u8 *)&addrin.sin_addr.s_addr, ':', &buffer))
		return -EINVAL;

	/* Skip over ':' */
	buffer++;

	if (kstrtoul(buffer, 10, &port))
		return -EINVAL;
	if (port > 65535)
		return -EINVAL;
	addrin.sin_port = htons(port);
	memcpy(address, &addrin, sizeof(addrin));
	*addrlen = sizeof(addrin);
	return 0;
}

/* Translate a URI path into a sockaddr. */
static int vs_parse_buffer_to_address(char *buffer,
				      size_t buf_length,
				      struct sockaddr *address,
				      int *addrlen)
{
	u32 uri_length;

	/* Force termination on the buffer */
	buffer[buf_length - 1] = '\0';

	if (buf_length < 4)
		return -EINVAL;
	/*
	 * The first 32 bits are the length of the URI, without the nul
	 * terminator.
	 */
	memcpy(&uri_length, buffer, 4);
	buffer += 4;

	return vs_parse_uri_to_address(buffer, uri_length, address, addrlen);
}

int hwsocket_recvmsg(struct kiocb *iocb, struct socket *sock,
		     struct msghdr *msg, size_t size, int flags)
{
	struct sk_buff *skb, *tmpskb;
	struct sock *sk = sock->sk;
	int skb_eaten = 0;
	int copied = 0;
	int ret;

	if (!size)
		return 0;
	lock_sock(sk);
	if (!(flags & MSG_DONTWAIT))
		vs_wait_recvmsg(sk);
	if (signal_pending(current)) {
		ret = -EINTR;
		goto out;
	}
	if (skb_queue_empty(&sk->sk_receive_queue)) {
		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			/* Signal that the socket is closed */
			ret = 0;
		} else {
			/* Signal the user to come back later */
			ret = -EAGAIN;
		}
		goto out;
	}
	/*
	 * If this is a stream, copy as much as we want.  Otherwise, copy one
	 * datagram only.  For datagrams, discard the remaining data.
	 */
	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmpskb) {
		struct virtio_socket_data_header *receive_header;
		size_t to_copy = min(size,
			(size_t)(skb_private(skb)->frame_end -
				 skb_private(skb)->cursor));
		if (skb_copy_datagram_iovec(skb, skb_private(skb)->cursor,
					    msg->msg_iov, to_copy)) {
			/* Faulted */
			if (copied)
				ret = copied;
			else
				ret = -EFAULT;
			goto out;
		} else if (!(flags & MSG_PEEK))
			skb_private(skb)->cursor += to_copy;
		receive_header = vs_receive_header(skb);
		if (sk->sk_protocol != IPPROTO_TCP &&
		    msg->msg_name && msg->msg_namelen &&
		    msg->msg_namelen >= sizeof(struct sockaddr_in) &&
		    receive_header &&
		    receive_header->uri_offset &&
		    receive_header->uri_len) {
			/*
			 * URI offset and length have been validated already.
			 * However, the sk_buff's data pointer and lengths were
			 * previously adjusted to only contain the actual data.
			 * We need to expand the length and move back the data
			 * pointer so that it contains everything passed by the
			 * hardware.
			 */
			struct virtio_socket_data_header *receive_header =
				vs_receive_header(skb);
			unsigned int uri_len = receive_header->uri_len;
			char *uri = kmalloc(uri_len + 1, GFP_KERNEL);
			if (!uri) {
				/* Can't handle this, but the sk_buff isn't
				 * bad, so just rewind. */
				if (!(flags & MSG_PEEK))
					skb_private(skb)->cursor -= to_copy;
				ret = -ENOMEM;
				goto out;
			} else {
				int res;
				skb_copy_bits(
					skb, receive_header->uri_offset,
					uri, receive_header->uri_len);
				uri[uri_len] = '\0';
				res = vs_parse_uri_to_address(
					uri, uri_len, msg->msg_name,
					&msg->msg_namelen);
				if (res) {
					/* Consume this sk_buff, it is bad. */
					ret = res;
					kfree(uri);
					sk_eat_skb(sk, skb, 0);
					skb_eaten++;
					pr_warn("Invalid header from device\n");
					goto out;
				}
				kfree(uri);
			}
		} else
			msg->msg_namelen = 0;
		if (!(flags & MSG_PEEK)) {
			if (sk->sk_protocol != IPPROTO_TCP) {
				sk_eat_skb(sk, skb, 0);
				skb_eaten++;
			} else {
				if (skb_private(skb)->frame_end ==
				    skb_private(skb)->cursor) {
					/* Completed this packet */
					sk_eat_skb(sk, skb, 0);
					skb_eaten++;
				} else {
					/* Packet not totally consumed, just
					 * consume the bytes we read, which has
					 * already been done above by adjusting
					 * the cursor value. */
					BUG_ON(size != to_copy);
				}
			}
		}
		size -= to_copy;
		copied += to_copy;
		if (size == 0)
			break;
		if (sk->sk_protocol != IPPROTO_TCP)
			break;
	}
	ret = copied;
	if (ret == 0 && size != 0) {
		pr_warn("Not sure how this happened.");
		ret = -EAGAIN;
	}
out:
	update_rx_tail(sk, skb_eaten);
	release_sock(sk);
	return ret;
}

/*
 * Shutdown the read side of the connection.
 * Assumes the sock is user locked.
 */
static void shutdown_rd(struct sock *sk)
{
	/* TODO(mikew): Implement me. */
}

/*
 * Shutdown the write side of the connection.
 * Assumes the sock is user locked.
 */
static int shutdown_wr(struct sock *sk)
{
	struct scatterlist sg[1];
	struct vs_cmd *cmd;
	int ret;

	cmd = vs_alloc_cmd(VIRTIO_SOCKET_CMD_SHUTDOWN_TX);
	if (!cmd) {
		pr_warn("Not enough memory to shutdown tx a virtio-socket\n");
		return -ENOMEM;
	}
	cmd->simple_args.guest_socket_handle = (__u64)sk;

	sg_init_table(sg, 1);
	sg_set_buf(&sg[0], &cmd->simple_args, sizeof(cmd->simple_args));

	ret = vs_issue_cmd(cmd, sg, 1, 0);
	if (ret) {
		vs_destroy_cmd(cmd);
		pr_warn("Failed to issue shutdown tx on virtio-socket\n");
		return ret;
	}

	return vs_complete_cmd(cmd);
}

int hwsocket_shutdown(struct sock *sk, int how)
{
	int ret = 0;
	lock_sock(sk);
	if ((how & SHUT_RD) && !(sk->sk_shutdown & RCV_SHUTDOWN))
		shutdown_rd(sk);
	if ((how & SHUT_WR) && !(sk->sk_shutdown & SEND_SHUTDOWN))
		ret = shutdown_wr(sk);
	release_sock(sk);
	/*
	 * TODO(mikew): Figure out how to map error codes from the device to
	 * the same error codes that userland typically expects.
	 */
	return ret;
}

void hwsocket_close(struct sock *sk)
{
	struct scatterlist sg[1];
	struct vs_cmd *cmd;
	int ret;

	pr_debug("%s: sk %p\n", __func__, sk);

	cmd = vs_alloc_cmd(VIRTIO_SOCKET_CMD_CLOSE);
	if (!cmd) {
		pr_warn("Not enough memory to release a virtio-socket\n");
		return;
	}

	cmd->simple_args.guest_socket_handle = (__u64) sk;

	sg_init_table(sg, 1);
	sg_set_buf(&sg[0], &cmd->simple_args, sizeof(cmd->simple_args));

	lock_sock(sk);
	if (sock_flag(sk, SOCK_DEAD)) {
		pr_warn("hwsocket_close called on dead socket: %p\n", sk);
		vs_destroy_cmd(cmd);
		release_sock(sk);
		return;
	}
	sk->sk_state = TCP_CLOSE;
	sock_orphan(sk);
	release_sock(sk);

	ret = vs_issue_and_forget_cmd(cmd, NULL, sg, 1, 0);
	/* issue and forget should never fail as we are not interruptible. */
	BUG_ON(ret != 0);
	pr_debug("%s: sk %p closed OK\n", __func__, sk);
}

static void vs_cancel_connect(struct vs_cmd *cmd)
{
	pr_debug("Connect cancelled!\n");
	kfree(cmd->private); /* uri */
}

/*
 * Returns the current line level indicating whether accept()
 * should go to the host.
 * Called from process context.
 */
static bool vs_accept_level(struct sock *sk)
{
	struct inet_sock *isk = inet_sk(sk);
	bool ret;

	/* TODO(mikew): This seems like a lot of serialization. */
	local_bh_disable();
	bh_lock_sock(sk);
	ret = isk->accept_level_is_high;
	bh_unlock_sock(sk);
	local_bh_enable();
	return ret;
}

static int __must_check vs_wait_accept(struct sock *sk)
{
	int rc;
	/* TODO(mikew): Plumb timeout here */
	long timeo = MAX_SCHEDULE_TIMEOUT;
	DEFINE_WAIT(wait);

	prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	rc = sk_wait_event(sk, &timeo, vs_accept_level(sk));
	clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	finish_wait(sk_sleep(sk), &wait);
	return rc;
}

static void virtsocket_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff_head *list = &sk->sk_receive_queue;
	unsigned long flags;

	skb->dev = NULL;
	skb_set_owner_r(skb, sk);

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_tail(list, skb);
	spin_unlock_irqrestore(&list->lock, flags);

	wake_socket_data(sk, POLLIN | POLLRDNORM, POLL_IN);
}

static int virtsocket_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	virtsocket_queue_rcv_skb(sk, skb);
	/* We never fail to enqueue on the receive queue. */
	return 0;
}

/*
 * Callback that is invoked as scheduled work to pick up any outstanding
 * work that needs to happen in process context.
 * Called from process context.
 */
static void process_cmd_work(struct work_struct *work)
{
	struct inet_sock *isk;
	struct sock *sk;
	unsigned long work_flags;

	isk = container_of(work, struct inet_sock, cmd_work.work);
	sk = (struct sock *)(isk);

	/*
	 * We clear out the bitmap here, as items may want to reschedule
	 * themselves again.
	 */
	work_flags = atomic_long_xchg(&isk->cmd_bitmap, 0);

	/* Process each work item.  Each delayed work may enqueue again. */
	if (test_bit(VIRTIO_SOCKET_SCHEDULED_RX_UNDERRUN, &work_flags)) {
		__clear_bit(VIRTIO_SOCKET_SCHEDULED_RX_UNDERRUN, &work_flags);
		notify_host_rx_tail_updated(sk);
		sock_put(sk);
	}
	/* There better not be any work left in our local flags. */
	BUG_ON(work_flags != 0);
}

static void __virtsocket_hijack_sk(struct sock *sk)
{
	struct inet_sock *isk = inet_sk(sk);
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	isk->saved_sk_backlog_rcv = sk->sk_backlog_rcv;
	sk->sk_backlog_rcv = virtsocket_backlog_rcv;
	isk->accept_level_is_high = false;
	isk->writes_plugged = false;
	isk->host_waiting_for_rx_tail = false;
	INIT_DELAYED_WORK(&isk->cmd_work, process_cmd_work);
	atomic_long_set(&isk->cmd_bitmap, 0);
	INIT_LIST_HEAD(&isk->pending_accepts);
	atomic_long_inc(&drv_info->hijacked_sockets);
}

static void virtsocket_hijack_sk(struct sock *sk)
{
	/* TODO(fes): This is a terrible hack. */
	if (sk->sk_backlog_rcv == virtsocket_backlog_rcv) {
		pr_debug("Tried to hijack a sock that is already hijacked.\n");
		return;
	}
	__virtsocket_hijack_sk(sk);
}

/* Pending accepts from struct socks that were unhijacked. */
static LIST_HEAD(release_accepts_work_list);
/* Protects the release_accepts_work_list, acquired in IRQ context. */
static DEFINE_SPINLOCK(release_accepts_work_lock);

/*
 * Release any pending accepts that were detached from a struct sock that was
 * unhijacked.  This is run as a task in a workqueue, and therefore called from
 * process context.
 */
static void invoke_release_accepts(struct work_struct *work)
{
	LIST_HEAD(release_accepts);
	spin_lock_irq(&release_accepts_work_lock);
	list_splice_init(&release_accepts_work_list, &release_accepts);
	spin_unlock_irq(&release_accepts_work_lock);
	while (!list_empty(&release_accepts)) {
		__u32 cmds[] = { VIRTIO_SOCKET_CMD_SHUTDOWN_TX,
				 VIRTIO_SOCKET_CMD_SHUTDOWN_RX };
		struct scatterlist sg[1];
		int i, ret;
		struct vs_cmd *shutdown_cmd;
		struct vs_cmd *cmd = list_first_entry(&release_accepts,
					 struct vs_cmd, reuse_list);
		struct sock *newsk = (struct sock *)
			cmd->accept_args.new_socket_handle;
		list_del(&cmd->reuse_list);

		for (i = 0; i < ARRAY_SIZE(cmds); ++i) {
			shutdown_cmd = vs_alloc_cmd(cmds[i]);
			if (!shutdown_cmd) {
				pr_warn("Not enough memory to send cmd %d"
					"on pending accept, leaking sock %p.\n",
					cmds[i], newsk);
				continue;
			}
			shutdown_cmd->simple_args.guest_socket_handle =
				(__u64)newsk;

			sg_init_table(sg, 1);
			sg_set_buf(&sg[0], &shutdown_cmd->simple_args,
				   sizeof(shutdown_cmd->simple_args));

			ret = vs_issue_and_forget_cmd(shutdown_cmd, NULL, sg, 1,
						      0);
			if (ret) {
				vs_destroy_cmd(shutdown_cmd);
				pr_warn("Failed to issue cmd %d on "
					"pending accept, leaking sock %p\n",
					cmds[i], newsk);
			}
		}

		newsk->sk_state = TCP_CLOSE;
		sock_orphan(newsk);
		sock_put(newsk);  /* Release one for the protocol. */
		sock_put(newsk);  /* Release one for the function. */
		vs_destroy_cmd(cmd);
	}
}

static DECLARE_WORK(release_accepts_work, invoke_release_accepts);

static void virtsocket_unhijack_sk(struct sock *sk)
{
	struct inet_sock *isk = inet_sk(sk);
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	if (sk->sk_backlog_rcv == virtsocket_backlog_rcv) {
		unsigned long flags;
		/* Delete any outstanding accepts. */
		local_bh_disable();
		bh_lock_sock(sk);
		spin_lock_irqsave(&release_accepts_work_lock, flags);
		list_splice_init(&isk->pending_accepts,
				 &release_accepts_work_list);
		spin_unlock_irqrestore(&release_accepts_work_lock, flags);
		bh_unlock_sock(sk);
		local_bh_enable();
		schedule_work(&release_accepts_work);
		sk->sk_backlog_rcv = isk->saved_sk_backlog_rcv;
		atomic_long_dec(&drv_info->hijacked_sockets);
	}
}

static u64 init_guest_control_block(struct sock *sk)
{
	struct virtsocket_info *info = netdev_priv(net_device);
	struct inet_sock *isk = inet_sk(sk);
	/* TODO(mikew): Wire this up to SO_RCVBUF ? */
	isk->gcb.rx_buffer_depth = (info->largeones ?
				     MAX_LARGE_RX_BUFFER_DEPTH :
				     MAX_RX_BUFFER_DEPTH);
	isk->gcb.rx_tail = 0;
	return (u64)virt_to_bus(&isk->gcb);
}

int hwsocket_connect(struct sock *sk, const char *uri)
{
	struct scatterlist sg[3];
	struct vs_cmd *cmd;
	char *uri_copy;
	int err;
	struct virtsocket_info *drv_info = netdev_priv(net_device);

	/* TODO: Implement NON-Blocking connect() */
	pr_debug("%s: sk %p uri %s\n", __func__, sk, uri);

	if (!net_device)
		return -ENOTSOCK;

	/* We have to copy the URI so that it is visible to the hardware
	 * in the case where this connect is interrupted. */
	uri_copy = kstrdup(uri, GFP_KERNEL);
	if (!uri_copy)
		return -ENOMEM;

	cmd = vs_alloc_interruptible_cmd(VIRTIO_SOCKET_CMD_CONNECT,
					 vs_cancel_connect, sk);
	if (!cmd) {
		kfree(uri_copy);
		return PTR_ERR(cmd);
	}

	/*
	 * TODO: Currently, a connect may be interrupted but already
	 * sent to the hardware.  In this case, the cancel callback
	 * would need to close the underlying hardware socket.  This can
	 * cause a race as we currently address the connections by the
	 * socket pointer, which can race with the cancel callback if
	 * userland comes back and issues a second connect quickly in
	 * sequence.
	 *
	 * One way to fix this would be to use hardware assigned
	 * identifiers for the socket handles.  Another would be to
	 * disallow the socket to be re-used (through free and
	 * re-allocation) and by blocking subsequent connects.
	 */

	cmd->connect_args.guest_socket_handle = (__u64) sk;
	cmd->connect_args.uri_len = strlen(uri_copy) + 1;
	cmd->private = uri_copy;
	cmd->guest_control_block = init_guest_control_block(sk);

	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], &cmd->connect_args, sizeof(cmd->connect_args));
	sg_set_buf(&sg[1], uri_copy, strlen(uri_copy) + 1);
	sg_set_buf(&sg[2], &cmd->guest_control_block,
		   sizeof(cmd->guest_control_block));

	/* Add a hold--this is owned by us until we issue the command. */
	sock_hold(sk);
	inet_sk(sk)->first_referenced_from =
		VIRTIO_SOCKET_REFERENCED_IN_CONNECT;
	atomic_long_inc(&drv_info->connect_refs);
	err = vs_issue_cmd(cmd, sg, 3, 0);
	if (err < 0) {
		sock_put(sk);  /* Failed command, device has no refcount. */
		atomic_long_dec(&drv_info->connect_refs);
		kfree(uri_copy);
		vs_destroy_cmd(cmd);
		return err;
	}

	/*
	 * The hold is now owned by the device and will be released with a
	 * VIRTIO_SOCKET_SOCKET_RELEASED message.
	 */
	err = vs_complete_cmd(cmd);
	/* If the connect was interrupted, the uri is freed in
	 * vs_cancel_connect. */
	if (err == -EINTR)
		return err;
	if (!err) {
		struct sockaddr_in sin;
		struct inet_sock *inet = inet_sk(sk);
		int addrlen = sizeof(sin);
		virtsocket_hijack_sk(sk);
		err = vs_parse_uri_to_address(uri_copy, strlen(uri_copy),
					      (struct sockaddr *)&sin,
					      &addrlen);
		if (!err) {
			inet->inet_daddr = sin.sin_addr.s_addr;
			inet->inet_dport = sin.sin_port;
			sk->sk_state = TCP_ESTABLISHED;
		}
	}
	kfree(uri_copy);

	return err;
}

static void vs_cancel_bind(struct vs_cmd *cmd)
{
	pr_debug("Bind cancelled\n");
	kfree(cmd->private); /* uri */
}

int hwsocket_bind_internal(struct sock *sk, int bind_cmd, const char *uri,
			   struct sockaddr *address)
{
	struct inet_sock *isk = inet_sk(sk);
	struct scatterlist sg[3];
	struct vs_cmd *cmd;
	char *uri_copy;
	int err;
	struct virtio_socket_bind_args *bind_args;
	struct virtsocket_info *drv_info = netdev_priv(net_device);

	pr_debug("%s: sk %p uri %s\n", __func__, sk, uri);

	if (!net_device)
		return -ENOTSOCK;

	/* We have to copy the URI so that it is visible to the hardware
	 * in the case where this connect is interrupted. */
	uri_copy = kstrdup(uri, GFP_KERNEL);
	if (!uri_copy)
		return -ENOMEM;

	/* XXX - should this be interruptible?  I'm guessing if we're */
	/* going to propogate asynch-ness, for now, it should be. */
	cmd = vs_alloc_interruptible_cmd(bind_cmd, vs_cancel_bind, sk);
	if (!cmd) {
		pr_warn("Not enough memory to bind a virtio-socket\n");
		kfree(uri_copy);
		return PTR_ERR(cmd);
	}

	switch (bind_cmd) {
	case VIRTIO_SOCKET_CMD_BIND:
		bind_args = &cmd->bind_args;
		break;
	case VIRTIO_SOCKET_CMD_CREATE_UNCONNECTED_SOCKET:
		bind_args = &cmd->create_unconnected_args;
		break;
	default:
		/* This shouldn't ever happen. */
		BUG();
	}
	bind_args->guest_socket_handle = (__u64) sk;
	bind_args->uri_len = strlen(uri) + 1;
	cmd->private = uri_copy;
	cmd->guest_control_block = init_guest_control_block(sk);

	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], bind_args, sizeof(*bind_args));
	sg_set_buf(&sg[1], uri_copy, strlen(uri_copy) + 1);
	sg_set_buf(&sg[2], &cmd->guest_control_block,
		   sizeof(cmd->guest_control_block));
	pr_debug("%s: size(0) 0x%x size(1) 0x%x\n", __func__,
		(int)sizeof(*bind_args), (int)strlen(uri_copy) + 1);

	pr_debug("%s: hwsocket_bind\n", __func__);

	/* Add a hold--this is owned by us until we issue the command. */
	sock_hold(sk);
	inet_sk(sk)->first_referenced_from = VIRTIO_SOCKET_REFERENCED_IN_BIND;
	atomic_long_inc(&drv_info->bind_refs);
	err = vs_issue_cmd(cmd, sg, 3, 0);
	if (err < 0) {
		sock_put(sk);  /* Failed command, device has no refcount. */
		atomic_long_dec(&drv_info->bind_refs);
		kfree(uri_copy);
		vs_destroy_cmd(cmd);
		return err;
	}

	/*
	 * The hold is now owned by the device and will be released with a
	 * VIRTIO_SOCKET_SOCKET_RELEASED message.
	 */
	err = vs_complete_cmd(cmd);
	if (err == -EINTR)
		return err;
	kfree(uri_copy);
	if (!err) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
		virtsocket_hijack_sk(sk);
		if (addr_in) {
			isk->inet_saddr = addr_in->sin_addr.s_addr;
			isk->inet_sport = addr_in->sin_port;
		}
	}
	return err;
}

/* This is basically a bind, but with a different command value. */
int hwsocket_create_unconnected(struct sock *sk, const char *uri)
{
	/* TODO(fes): Probably need a lock_sock here. */
	return hwsocket_bind_internal(
		sk, VIRTIO_SOCKET_CMD_CREATE_UNCONNECTED_SOCKET, uri, NULL);
}

int hwsocket_bind(struct sock *sk, const char *uri, struct sockaddr *address)
{
	return hwsocket_bind_internal(sk, VIRTIO_SOCKET_CMD_BIND, uri, address);
}

int hwsocket_disconnect(struct sock *sk)
{
	sk->sk_state = TCP_CLOSE;
	/* TODO(fes): Need to pass a disconnect message to the device. */
	pr_warn("Disconnect called on a virtio-socket\n");
	return 0;
}

int hwsocket_listen(struct sock *sk, const int backlog)
{
	struct scatterlist sg[1];
	struct vs_cmd *cmd;
	int ret;

	pr_debug("%s: sk %p backlog %d\n", __func__, sk, backlog);

	BUG_ON(!net_device);

	/*
	 * TODO(mikew): validate that we aren't connected nor already
	 * listening!
	 */

	cmd = vs_alloc_cmd(VIRTIO_SOCKET_CMD_LISTEN);
	if (!cmd) {
		pr_warn("Not enough memory to listen on a virtio-socket\n");
		return PTR_ERR(cmd);
	}

	cmd->listen_args.guest_socket_handle = (__u64) sk;
	cmd->listen_args.backlog = backlog;

	sg_init_table(sg, 1);
	sg_set_buf(&sg[0], &cmd->listen_args, sizeof(cmd->listen_args));

	ret = vs_issue_cmd(cmd, sg, 1, 0);
	/* The command should always succeed as we are not interruptible. */
	BUG_ON(ret != 0);

	return vs_complete_cmd(cmd);
}

void hwsocket_poll(struct file *file, struct sock *sk, poll_table *wait,
		   unsigned int *mask)
{
	struct inet_sock *isk = inet_sk(sk);

	sock_poll_wait(file, sk_sleep(sk), wait);
	*mask = 0;
	/* Notify that there is data to read. */
	if (!skb_queue_empty(&sk->sk_receive_queue))
		*mask |= POLLIN | POLLRDNORM;
	/*
	 * If this is a listening socket, notify that the user should try and
	 * accept.
	 *
	 * TODO(mikew): Need to check that this is a listening socket!
	 */
	if (isk->accept_level_is_high)
		*mask |= POLLIN | POLLRDNORM;
	/* Notify the user if the socket was closed */
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		*mask |= POLLIN | POLLRDNORM | POLLRDHUP;
	if (sk->sk_shutdown & SEND_SHUTDOWN)
		*mask |= POLLOUT | POLLHUP;
	/* TODO(mikew): This should only apply for connected sockets */
	if (!isk->writes_plugged)
		*mask |= POLLOUT | POLLWRNORM;
}

static void vs_cancel_accept(struct vs_cmd *cmd)
{
	struct sock *listen_sock;

	listen_sock = (struct sock *)cmd->accept_args.guest_socket_handle;

	/*
	 * Cancelled accept left an orphan to clean up.
	 * Enqueue it on the main socket for the moment.
	 */
	pr_err("TODO(mikew): Accept drop due to a signal, sk: %p, newsk: %p",
		(struct sock *)cmd->accept_args.guest_socket_handle,
		(struct sock *)cmd->accept_args.new_socket_handle);


	/* XXX: For the moment, leak the child socket.  Closing it would
	 * involve bouncing down into process context, which still wouldn't be
	 * the right thing to do. */

	/* Drop the ref that was associated with the cmd */
	sock_put(listen_sock);
}

/*
 * Return the current accept level ID.
 * Called from process context.
 */
static void get_accept_level(struct sock *sk, bool *is_high, u64 *levelid)
{
	struct inet_sock *isk = inet_sk(sk);
	local_bh_disable();
	bh_lock_sock(sk);
	*is_high = isk->accept_level_is_high;
	*levelid = isk->accept_level;
	bh_unlock_sock(sk);
	local_bh_enable();
}

int __hwsocket_accept(struct sock *sk, struct socket *newsocket, int flags)
{
	struct sock *newsk;
	struct scatterlist sg[2];
	struct vs_cmd *cmd;
	u64 accept_levelid;
	bool accept_is_high;
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	struct inet_sock *isk = inet_sk(sk);

	int err;

	pr_debug("%s: socket %p newsock %p\n", __func__, sk, newsocket);

	BUG_ON(!net_device);

	/* Figure out if we should service this accept or fail fast */
	get_accept_level(sk, &accept_is_high, &accept_levelid);
	if (!accept_is_high)
		return -EAGAIN;

	if (!list_empty(&isk->pending_accepts)) {
		cmd = list_first_entry(&isk->pending_accepts, struct vs_cmd,
				       reuse_list);
		list_del(&cmd->reuse_list);
		newsk = (struct sock *) cmd->accept_args.new_socket_handle;
		lock_sock(newsk);
	} else {
		/*
		 * Allocate a new sock.  This sock will be bound to the accept
		 * call, but will only bind to newsocket if the accept() that
		 * invoked us hasn't been interrupted by a signal.  If not, it
		 * should be enqueued onto the listening socket for subsequent
		 * accept calls.
		 */
		newsk = sk_clone_lock(sk, GFP_KERNEL);
		if (!newsk)
			return -ENOMEM;
		newsk->sk_prot->init(newsk);
		/*
		 * Add a hold--this is owned by us until we issue the command.
		 */
		sock_hold(newsk);
		inet_sk(newsk)->first_referenced_from =
			VIRTIO_SOCKET_REFERENCED_IN_ACCEPT;
		atomic_long_inc(&drv_info->accept_refs);
		/* TODO(mikew): This isn't really a hijack ... */
		__virtsocket_hijack_sk(newsk);

		/*
		 * From here until a successful issue of the cmd, we have four
		 * reference counts to the struct sock.  One for the cmd, one
		 * for the device, and two from sk_clone.  Errors in this space
		 * need to decrement the refcount by three.  The cmd owns its
		 * reference count.
		 */

		/*
		 * Drop the lock after setting up sock state (which is empty)
		 *
		 * Does this open a race where data can come in before
		 * we've associated the socket?  Yes, because data may be
		 * enqueued on the socket from bottom-half context before we've
		 * processed the graphing of the socket here.   For this reason,
		 * we keep the socket user-locked so that received data is
		 * enqueued on the backlog until the sock is grafted onto the
		 * socket.
		 */
		BUG_ON(!spin_is_locked(&newsk->sk_lock.slock));
		bh_unlock_sock(newsk);
		lock_sock(newsk);

		/* Hold the socket so it is available for the cancel path */
		sock_hold(sk);

		cmd = vs_alloc_interruptible_cmd(VIRTIO_SOCKET_CMD_ACCEPT,
						 vs_cancel_accept, sk);
		if (!cmd) {
			pr_warn("Not enough memory to accept a virtio-socket"
				"\n");
			err = -ENOMEM;
			goto out_err;
		}

		cmd->accept_args.guest_socket_handle = (__u64)sk;
		cmd->accept_args.new_socket_handle = (__u64)newsk;
		cmd->guest_control_block = init_guest_control_block(newsk);

		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], &cmd->accept_args, sizeof(cmd->accept_args));
		sg_set_buf(&sg[1], &cmd->guest_control_block,
			   sizeof(cmd->guest_control_block));

		err = vs_issue_cmd(cmd, sg, 2, 0);
		if (err < 0)
			goto out_err;

		/*
		 * From here on out, the host owns the reference from our
		 * hijack, and will deliver a message when it is gone.  We need
		 * to release the two reference counts from sk_clone on failure
		 * exit paths, and one on success.
		 */
	}

	err = __vs_complete_cmd(cmd, false);
	if (err == -EINTR) {
		list_add(&cmd->reuse_list, &isk->pending_accepts);
		release_sock(newsk);
		/* When interrupted, the sock gets owned by the cancel path. */
		return err;
	}

	/* Answered */
	sock_put(sk);  /* Drop reference that was bound to the cmd for cancel */

	if (!err) {
		/* Accepted! Associate the sock with the user's socket */
		sock_graft(newsk, newsocket);
		newsk->sk_state = TCP_ESTABLISHED;
		release_sock(newsk);
	} else {
		if (err == -EAGAIN) {
			u64 new_accept_levelid;
			get_accept_level(sk, &accept_is_high,
					 &new_accept_levelid);
			if (accept_is_high &&
			    new_accept_levelid != accept_levelid) {
				/*
				 * We didn't process the accept, but we should
				 * try again as another level interrupt came.
				 */
				/* TODO(mikew): Is restartsys appropriate? */
				err = -ERESTARTSYS;
			}
		}
		/* Cleanup */
		newsk->sk_state = TCP_CLOSE;
		sock_orphan(newsk);
		release_sock(newsk);
		sock_put(newsk);  /* Release one for the protocol. */
	}

	sock_put(newsk);  /* Release one for the local function. */
	return err;
out_err:
	newsk->sk_state = TCP_CLOSE;
	sock_orphan(newsk);
	release_sock(newsk);
	sock_put(newsk);  /* Release the hold from the device. */
	atomic_long_dec(&drv_info->accept_refs);
	sock_put(newsk);  /* Release one for the protocol. */
	sock_put(newsk);  /* Release one for the local function. */

	sock_put(sk);
	if (cmd)
		vs_destroy_cmd(cmd);
	return err;
}

int hwsocket_accept(struct sock *sk, struct socket *newsocket, int flags)
{
	int ret;
	lock_sock(sk);
	if (!(flags & O_NONBLOCK)) {
		do {
			bool level_is_high = vs_wait_accept(sk);
			if (signal_pending(current)) {
				ret = -EINTR;
				break;
			}
			if (level_is_high)
				ret = __hwsocket_accept(sk, newsocket, flags);
		} while (ret == -EAGAIN);
	} else
		ret = __hwsocket_accept(sk, newsocket, flags);
	release_sock(sk);
	return ret;
}

static void vs_cancel_getname(struct vs_cmd *cmd)
{
	struct page *page = cmd->private;
	__free_page(page);
}

extern int hwsocket_getname(struct sock *sk, struct sockaddr *address,
			    int *addrlen, int peer)
{
	struct scatterlist sg[2];
	struct page *page;
	struct vs_cmd *cmd;
	int err;

	if (!peer) {
		struct inet_sock *isk = inet_sk(sk);
		/* Local name */
		struct sockaddr_in *inaddr = (struct sockaddr_in *)address;
		*addrlen = sizeof(struct sockaddr_in);
		inaddr->sin_family = AF_INET;
		inaddr->sin_addr.s_addr = isk->inet_saddr;
		inaddr->sin_port = isk->inet_sport;
		return 0;
	}

	pr_debug("%s: newsk %p uri %p\n", __func__, sk, address);

	BUG_ON(!net_device);

	cmd = vs_alloc_interruptible_cmd(VIRTIO_SOCKET_CMD_GETPEERNAME,
					 vs_cancel_getname, sk);
	if (!cmd)
		return -ENOMEM;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		vs_destroy_cmd(cmd);
		return -ENOMEM;
	}

	cmd->simple_args.guest_socket_handle = (__u64) sk;

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], &cmd->simple_args, sizeof(cmd->simple_args));
	sg_set_page(&sg[1], page, PAGE_SIZE, 0);
	cmd->private = page;

	err = vs_issue_cmd(cmd, sg, 1, 1);
	if (err) {
		__free_page(page);
		vs_destroy_cmd(cmd);
		return err;
	}

	err = vs_complete_cmd(cmd);
	if (err == -EINTR)
		return err;
	if (!err)
		err = vs_parse_buffer_to_address(page_address(page), PAGE_SIZE,
						 address, addrlen);
	__free_page(page);
	return err;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SOCKET, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static void virtsocket_tx_cb(struct virtqueue *svq)
{
	pr_debug("%s:\n", __func__);
}

/* Add a large buffer to the receive queue, return 0 if successful. */
static int virtsocket_fill_rx_largeone_reuse_frags(
	struct virtsocket_info *drv_info, struct sk_buff* source_frags,
	gfp_t gfp_flags)
{
	struct sk_buff *skb;
	int i, err;
	struct scatterlist rx_sg[MAX_SKB_FRAGS + 1];

	if (!source_frags)
		return -EINVAL;
	if (skb_shinfo(source_frags)->nr_frags != MAX_SKB_FRAGS) {
		pr_warn("Error, tried to reuse too few page fragments\n");
		vs_free_skb_frags(source_frags, 0);
		return -EINVAL;
	}
	/* Set the source fragments length to zero. */
	skb_shinfo(source_frags)->nr_frags = 0;
	skb = alloc_skb(MAX_RX_PACKET_LEN, gfp_flags);
	if (!skb) {
		vs_free_skb_frags(source_frags, 0);
		return -ENOMEM;
	}
	/* If source_frags was set, we now "own" the fragments, and freeing
	 * skb will free the fragments. */

	/* Ensure skb->data, skb->head are quadword for receive . */
	BUG_ON(drv_info->receive_has_header &&
	       !IS_ALIGNED((unsigned long)skb->head, sizeof(void *)));

	/* Chain the sk_buff data to the scatter gather list. */
	sg_set_buf(&rx_sg[0], skb->data, vs_skb_datasize(skb));
	for (i = 0; i < MAX_SKB_FRAGS; ++i) {
		/* TODO(mikew): Port to the frag API. */
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		skb_frag_t *sf = &skb_shinfo(source_frags)->frags[i];
		WARN_ON(!sf->page.p);
		f->page.p = sf->page.p;
		WARN_ON(sf->size != PAGE_SIZE);
		f->size = sf->size;
		WARN_ON(sf->page_offset != 0);
		f->page_offset = sf->page_offset;
		skb_shinfo(skb)->nr_frags++;
		sg_set_buf(&rx_sg[i + 1], page_address(f->page.p), PAGE_SIZE);
	}

	/* Queue the large buffer.  We are not in the bottom half. */
	spin_lock(&drv_info->rx_lock);
	err = virtqueue_add_buf(drv_info->drv_rx, rx_sg, 0,
				MAX_SKB_FRAGS + 1, skb, gfp_flags);
	spin_unlock(&drv_info->rx_lock);
	if (err < 0)
		__kfree_skb(skb);

	return err;
}

static int virtsocket_fill_rx_largeone(struct virtsocket_info *drv_info,
				       gfp_t gfp_flags) {
	struct sk_buff *skb;
	int i, err;
	struct scatterlist rx_sg[MAX_SKB_FRAGS + 1];

	skb = alloc_skb(MAX_RX_PACKET_LEN, gfp_flags);
	if (!skb)
		return -ENOMEM;
	/* Ensure skb->data, skb->head are quadword for receive . */
	BUG_ON(drv_info->receive_has_header &&
	       !IS_ALIGNED((unsigned long)skb->head, sizeof(void *)));

	/* Chain the sk_buff data to the scatter gather list. */
	sg_set_buf(&rx_sg[0], skb->data, vs_skb_datasize(skb));
	for (i = 0; i < MAX_SKB_FRAGS; ++i) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		f->page.p = alloc_page(gfp_flags);
		if (!f->page.p) {
			__kfree_skb(skb);
			return -ENOMEM;
		}
		f->size = PAGE_SIZE;
		f->page_offset = 0;
		skb_shinfo(skb)->nr_frags++;
		sg_set_buf(&rx_sg[i + 1], page_address(f->page.p), PAGE_SIZE);
	}

	/* Queue the large buffer. */
	spin_lock_bh(&drv_info->rx_lock);
	err = virtqueue_add_buf(drv_info->drv_rx, rx_sg, 0,
				MAX_SKB_FRAGS + 1, skb, gfp_flags);
	spin_unlock_bh(&drv_info->rx_lock);
	if (err < 0)
		__kfree_skb(skb);

	return err;
}

static void virtsocket_adjust(struct virtsocket_info *drv_info,
			      struct sk_buff *skb, unsigned int len)
{
	unsigned int pages_used;

	/* Only called from the virtio socket poll routine. */
	BUG_ON(!in_softirq());

	/* Handle special inline data signals.  Here we just need to release the
	 * associated pages.*/
	if (virtio_socket_len_is_signal(len)) {
		/* Attempt to re-use all of the fragments. */
		if (drv_info->largeones)
			virtsocket_fill_rx_largeone_reuse_frags(drv_info, skb,
								GFP_KERNEL);
		BUG_ON(skb->sk);
		/* Data signals never use a receive header.  Use the old
		 * skb_pull mechanism. */
		skb->sk = pop_socket_handle(skb);
		return;
	}

	/* Adjust the skb data lengths and pointers. */
	if (drv_info->receive_has_header) {
		/*
		 * When a header is present, len is the entire data blob.  The
		 * frame length is in the header.
		 */
		unsigned int frame_end, uri_end;
		struct virtio_socket_data_header *receive_header;
		skb_private(skb)->has_receive_header = true;
		receive_header = vs_receive_header(skb);
		BUG_ON(skb->sk);
		skb->sk = (struct sock *)(receive_header->guest_socket_handle);
		frame_end = receive_header->frame_offset +
			receive_header->frame_len;
		uri_end = receive_header->uri_offset +
			receive_header->uri_len;
		if (frame_end > len || uri_end > len) {
			pr_err("Invalid receive header for len %d, frame_end: "
			       "%d, uri_end: %d\n",
			       len,
			       frame_end,
			       uri_end);
			__kfree_skb(skb);
			return;
		}
		if (frame_end > receive_header->uri_offset &&
		    receive_header->frame_offset < uri_end) {
			pr_err("Invalid receive header for frame offset: %d, "
			       "end: %d, uri offset: %d, end: %d\n",
			       receive_header->frame_offset,
			       frame_end,
			       receive_header->uri_offset,
			       uri_end);
			__kfree_skb(skb);
			return;
		}
		if (uri_end > receive_header->frame_offset &&
		    receive_header->uri_offset < frame_end) {
			pr_err("Invalid receive header for frame offset: %d, "
			       "end: %d, uri offset: %d, end: %d\n",
			       receive_header->frame_offset,
			       frame_end,
			       receive_header->uri_offset,
			       uri_end);
			__kfree_skb(skb);
			return;
		}
		skb_private(skb)->cursor = receive_header->frame_offset;
		skb_private(skb)->frame_end = frame_end;
		skb->len = max(frame_end, uri_end);
		skb->data_len = skb->len - min(vs_skb_datasize(skb), skb->len);
	} else {
		skb_private(skb)->has_receive_header = false;
		skb_private(skb)->cursor = sizeof(u64);
		skb_private(skb)->frame_end = len + sizeof(u64);
		skb->len = len + sizeof(u64);
		skb->data_len = skb->len - min(vs_skb_datasize(skb), len);
	}

	/* Adjust fragments, freeing unused ones (pages beyond data_len). */
	pages_used = round_up(skb->data_len, PAGE_SIZE) / PAGE_SIZE;
	BUG_ON(pages_used > skb_shinfo(skb)->nr_frags);
	if (pages_used < skb_shinfo(skb)->nr_frags) {
		/* Attempt to re-use all of the fragments. */
		if (pages_used == 0) {
			if (drv_info->largeones)
				virtsocket_fill_rx_largeone_reuse_frags(
					drv_info, skb, GFP_KERNEL);
		} else {
			vs_free_skb_frags(skb, pages_used);
		}
	}
}

/* Add one page to the receive queue, return 0 if successful. */
static int virtsocket_fill_rx_one(struct virtsocket_info *drv_info,
				  gfp_t gfp_flags)
{
	struct scatterlist sg[1];
	struct sk_buff *skb;
	int ret;

	skb = alloc_skb(MAX_RX_PACKET_LEN, gfp_flags);
	if (!skb)
		return -ENOMEM;
	/* Ensure skb->data, skb->head are quadword for receive . */
	BUG_ON(drv_info->receive_has_header &&
	       ((unsigned long) skb->head % sizeof(u64)));

	sg_init_table(sg, 1);
	sg_set_buf(&sg[0], skb->data, vs_skb_datasize(skb));
	spin_lock_bh(&drv_info->rx_lock);
	ret = virtqueue_add_buf(drv_info->drv_rx, sg, 0, 1, skb, GFP_ATOMIC);
	spin_unlock_bh(&drv_info->rx_lock);
	if (ret < 0)
		__kfree_skb(skb);
	return ret;
}

static int virtsocket_fill_rx_queue(struct virtsocket_info *drv_info,
				    gfp_t gfp_flags)
{
	int count = 0;
	int ret = 0;
	while (1) {
		/* TODO(fes): Should check if there is space to fill the queue
		 * before allocating. */
		if (drv_info->largeones)
			ret = virtsocket_fill_rx_largeone(drv_info, gfp_flags);
		else
			ret = virtsocket_fill_rx_one(drv_info, gfp_flags);
		/* If there was an error or less than enough to add another,
		 * bail.  For large receive buffers, since we don't use
		 * indirect, we need enough entries for each fragment. */
		if (ret <= 0 ||
		    (drv_info->largeones && ret < (MAX_SKB_FRAGS + 1)))
			break;
		count++;
	}
	spin_lock_bh(&drv_info->rx_lock);
	virtqueue_kick(drv_info->drv_rx);
	spin_unlock_bh(&drv_info->rx_lock);
	return (ret < 0 ? ret : 0);
}

static void delayed_refill_rx_queue(struct work_struct *work);
static DECLARE_DELAYED_WORK(refill_rx_work, delayed_refill_rx_queue);

static void delayed_refill_rx_queue(struct work_struct *work)
{
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	/* TODO(mikew): Locking */
	int ret = virtsocket_fill_rx_queue(drv_info, GFP_KERNEL);
	if (ret == -ENOMEM)
		schedule_delayed_work(&refill_rx_work,
				      VIRTIO_SOCKET_NOMEM_REFILL_DELAY);
}

/*
 * Process a "remote endpoint stopped sending us data" message from the host.
 * Called from bottom-half context.
 */
static void handle_remote_shutdown(struct sock *sk, struct sk_buff *skb)
{
	pr_debug("Remote side has shutdown\n");
	bh_lock_sock(sk);
	sk->sk_shutdown |= RCV_SHUTDOWN;
	wake_socket_data(sk, POLLIN | POLLRDNORM | POLLRDHUP, POLL_IN);
	bh_unlock_sock(sk);
}

/*
 * Process a "accepts are now available" message from the host.
 * Called from bottom-half context.
 */
static void handle_accepts_available(struct sock *sk, struct sk_buff *skb,
				     bool edge_is_high)
{
	struct inet_sock *isk = inet_sk(sk);
	u64 *levelid;

	/* TODO(mikew): Make sure this sock is listening! */
	bh_lock_sock(sk);
	BUG_ON(edge_is_high == isk->accept_level_is_high);
	skb_put(skb, sizeof(u64));
	levelid = (u64 *)skb->data;
	isk->accept_level = *levelid;
	isk->accept_level_is_high = edge_is_high;

	if (edge_is_high)
		wake_socket_data(sk, POLLIN | POLLRDNORM | POLLRDHUP, POLL_IN);
	bh_unlock_sock(sk);
}

/*
 * Process a "writes are plugged" message from the host.
 * Called from bottom-half context.
 */
static void handle_writes_plugged(struct sock *sk, bool is_plugged)
{
	struct inet_sock *isk = inet_sk(sk);
	bh_lock_sock(sk);
	isk->writes_plugged = is_plugged;
	if (!is_plugged)
		wake_socket_data(sk, POLLOUT | POLLWRNORM, POLL_OUT);
	bh_unlock_sock(sk);
}

static void virtsocket_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	if (sk_rcvqueues_full(sk, skb)) {
		pr_debug("TODO(mikew): Add an RX plug here so the host stops "
			 "sending us data for the socket.\n");
	}

	__sk_add_backlog(sk, skb);
	sk->sk_backlog.len += skb->truesize;
}

/*
 * Process a "receive overrun" message from the host.
 * Called from bottom-half context.
 */
static void handle_receive_overrun(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *isk = inet_sk(sk);
	u32 rx_tail_seen;

	BUG_ON(!in_softirq());

	skb_put(skb, sizeof(u32));
	rx_tail_seen = *(u32 *)skb->data;
	pr_debug("receive underrun on %p at rx_tail=%u\n", sk, rx_tail_seen);
	bh_lock_sock(sk);
	if (rx_tail_seen == isk->gcb.rx_tail)
		isk->host_waiting_for_rx_tail = true;
	else
		__schedule_cmd_work(sk, VIRTIO_SOCKET_SCHEDULED_RX_UNDERRUN, 0);
	bh_unlock_sock(sk);
}

/*
 * Process a "socket released" message from the host.  This means we can
 * decrement the refcount added in the hijack path.
 * Called from bottom-half context.
 */
static void handle_socket_released(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *isk = inet_sk(sk);
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	BUG_ON(!in_softirq());
	virtsocket_unhijack_sk(sk);
	/* Decrement the refcount on the struct sock.  This is the refcount
	 * from the sock_hold before the handle was sent to the device for the
	 * first time. */
	sock_put(sk);
	switch (isk->first_referenced_from) {
	case VIRTIO_SOCKET_REFERENCED_IN_CONNECT:
		atomic_long_dec(&drv_info->connect_refs);
		break;
	case VIRTIO_SOCKET_REFERENCED_IN_BIND:
		atomic_long_dec(&drv_info->bind_refs);
		break;
	case VIRTIO_SOCKET_REFERENCED_IN_ACCEPT:
		atomic_long_dec(&drv_info->accept_refs);
		break;
	default:
		break;
	}
}

static void handle_rx_signal(struct sock *sk, struct sk_buff *skb,
			     unsigned signal)
{
	switch (signal) {
	case VIRTIO_SOCKET_RX_REMOTE_SHUTDOWN:
		handle_remote_shutdown(sk, skb);
		break;
	case VIRTIO_SOCKET_ACCEPTS_AVAILABLE:
		handle_accepts_available(sk, skb, true);
		break;
	case VIRTIO_SOCKET_ACCEPTS_NOT_AVAILABLE:
		handle_accepts_available(sk, skb, false);
		break;
	case VIRTIO_SOCKET_WRITES_PLUGGED:
		handle_writes_plugged(sk, true);
		break;
	case VIRTIO_SOCKET_WRITES_UNPLUGGED:
		handle_writes_plugged(sk, false);
		break;
	case VIRTIO_SOCKET_RECEIVE_OVERRUN:
		handle_receive_overrun(sk, skb);
		break;
	case VIRTIO_SOCKET_SOCKET_RELEASED:
		handle_socket_released(sk, skb);
		break;
	default:
		pr_warn("Unhandled signal %x\n", signal);
	}
	__kfree_skb(skb);
}

/*
 * Receive packet and enqueue it onto the correct socket.
 * Called from bottom-half context.
 */
static void handle_rx_skb(struct sk_buff *skb, unsigned len)
{
	struct sock *sk = skb->sk;

	/*
	 * Drop any packets of zero length.
	 * The device can send these spuriously.
	 */
	if (len == 0 || (skb_private(skb)->has_receive_header &&
			 vs_receive_header(skb)->frame_len == 0)) {
		__kfree_skb(skb);
		return;
	}
	/* Handle special inline data signals */
	if (virtio_socket_len_is_signal(len)) {
		handle_rx_signal(sk, skb, len);
		return;
	}

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		virtsocket_queue_rcv_skb(sk, skb);
	else
		virtsocket_add_backlog(sk, skb);
	bh_unlock_sock(sk);
}

static void virtsocket_rx_cb(struct virtqueue *rvq)
{
	struct virtsocket_info *info = netdev_priv(net_device);
	/* Schedule NAPI, Suppress further interrupts if successful. */
	if (napi_schedule_prep(&info->napi)) {
		virtqueue_disable_cb(rvq);
		__napi_schedule(&info->napi);
	}
}

static void virtsocket_setup(struct net_device *net_device)
{
	/* Nothing to do? */
}

static const struct net_device_ops virtsocket_netdev_ops = {
	/* Nothing at the moment. */
};

static int virtsocket_poll(struct napi_struct *napi, int budget)
{
	struct virtsocket_info *drv_info;
	unsigned received = 0;
	unsigned len;
	struct sk_buff *skb;
	struct list_head *pos, *npos;
	LIST_HEAD(skb_list);
	int ret;

	BUG_ON(!in_softirq());

	drv_info = container_of(napi, struct virtsocket_info, napi);

again:
	/* Receive packets and count them */
	spin_lock(&drv_info->rx_lock);
	while (received < budget &&
	       (skb = virtqueue_get_buf(drv_info->drv_rx, &len)) != NULL) {
		list_add_tail((struct list_head *)skb, &skb_list);
		skb_private(skb)->len = len;
		received++;
	}
	spin_unlock(&drv_info->rx_lock);

	/* Process the packets */
	list_for_each_safe(pos, npos, &skb_list) {
		list_del(pos);
		skb = (struct sk_buff *)pos;
		virtsocket_adjust(drv_info, skb, skb_private(skb)->len);
		handle_rx_skb(skb, skb_private(skb)->len);
	}

	/* Refill the rx buffers */
	ret = virtsocket_fill_rx_queue(drv_info, GFP_ATOMIC);
	if (ret == -ENOMEM) {
		/* Schedule to refill in background */
		schedule_delayed_work(&refill_rx_work, 0);
	}

	/* Are we out of packets?  If so, stop napi */
	if (received < budget) {
		napi_complete(napi);
		if (!virtqueue_enable_cb(drv_info->drv_rx) &&
		    napi_schedule_prep(napi)) {
			virtqueue_disable_cb(drv_info->drv_rx);
			__napi_schedule(napi);
			goto again;
		}
	}
	return received;
}

static void virtsocket_napi_enable(struct virtsocket_info *info)
{
	napi_enable(&info->napi);

	/* If all buffers were filled by other side before we napi_enabled, we
	 * won't get another interrupt, so process any outstanding packets
	 * now.  virtnet_poll wants re-enable the queue, so we disable here.
	 * We synchronize against interrupts via NAPI_STATE_SCHED */
	if (napi_schedule_prep(&info->napi)) {
		virtqueue_disable_cb(info->drv_rx);
		__napi_schedule(&info->napi);
	}
}

static ssize_t virtsocket_attr_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf);

static DEVICE_ATTR(hijacked_sockets, 0444,
	virtsocket_attr_show, NULL);

static DEVICE_ATTR(connect_refs, 0444,
	virtsocket_attr_show, NULL);

static DEVICE_ATTR(bind_refs, 0444,
	virtsocket_attr_show, NULL);

static DEVICE_ATTR(accept_refs, 0444,
	virtsocket_attr_show, NULL);

static struct attribute *virtsocket_attrs[] = {
	&dev_attr_hijacked_sockets.attr,
	&dev_attr_connect_refs.attr,
	&dev_attr_bind_refs.attr,
	&dev_attr_accept_refs.attr,
	NULL
};
static struct attribute_group virtsocket_attr_group = {
	.name = "stats",
	.attrs = virtsocket_attrs,
};

static ssize_t virtsocket_attr_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct virtsocket_info *drv_info = netdev_priv(net_device);
	if (attr == &dev_attr_hijacked_sockets) {
		return sprintf(buf, "%lu\n",
			       atomic_long_read(&drv_info->hijacked_sockets));
	} else if (attr == &dev_attr_connect_refs) {
		return sprintf(buf, "%lu\n",
			       atomic_long_read(&drv_info->connect_refs));
	} else if (attr == &dev_attr_bind_refs) {
		return sprintf(buf, "%lu\n",
			       atomic_long_read(&drv_info->bind_refs));
	} else if (attr == &dev_attr_accept_refs) {
		return sprintf(buf, "%lu\n",
			       atomic_long_read(&drv_info->accept_refs));
	}
	return 0;
}

static int virtsocket_probe(struct virtio_device *vdev)
{
	struct net_device *nd;
	struct virtsocket_info *info;
	struct virtqueue *vqs[3];
	vq_callback_t *callbacks[] = { virtsocket_rx_cb,
				       virtsocket_tx_cb,
				       virtsocket_ctl_cb };
	const char *names[] = { "input", "output", "control" };
	int err;

	pr_debug("%s:\n", __func__);

	if (net_device) {
		pr_err("Only one VirtioSocket card is supported\n");
		return -EBUSY;
	}

	nd = alloc_netdev_mqs(sizeof(*info), "virtsock%d",
			      virtsocket_setup, 1, 1);
	if (!nd)
		return -ENOMEM;
	info = netdev_priv(nd);

	info->receive_has_header =
		virtio_has_feature(vdev, VIRTIO_SOCKET_F_RX_HEADER);
	info->largeones =
		virtio_has_feature(vdev, VIRTIO_SOCKET_F_LARGE_BUFFERS);
	info->transmit_has_header =
		virtio_has_feature(vdev, VIRTIO_SOCKET_F_TX_HEADER);

	spin_lock_init(&info->rx_lock);
	spin_lock_init(&info->ctl_lock);

	atomic_long_set(&info->hijacked_sockets, 0);
	atomic_long_set(&info->connect_refs, 0);
	atomic_long_set(&info->bind_refs, 0);
	atomic_long_set(&info->accept_refs, 0);
	err = sysfs_create_group(&vdev->dev.kobj, &virtsocket_attr_group);
	if (err) {
		pr_err("Failed to create virtsocket sysfs node\n");
		goto out_free_netdev;
	}

	err = vdev->config->find_vqs(vdev, 3, vqs, callbacks, names);
	if (err) {
		pr_err("Failed to find vqs (%d)\n", err);
		goto out_remove_sysfs;
	}

	info->drv_rx = vqs[0];
	info->drv_tx = vqs[1];
	info->drv_ctl = vqs[2];
	init_waitqueue_head(&info->ctl_enqueue_space);
	netif_napi_add(nd, &info->napi, virtsocket_poll, NAPI_WEIGHT);

	pr_debug("virtsocket: registered device\n");

	/* TODO(mikew) Locking? */
	virtsocket_fill_rx_queue(info, GFP_KERNEL);

	nd->netdev_ops = &virtsocket_netdev_ops;

	err = register_netdev(nd);
	if (err)
		goto out_remove_sysfs;

	net_device = nd;

	/* TODO(mikew): Eventually, this should happen on interface open */
	virtsocket_napi_enable(info);

	return 0;

out_remove_sysfs:
	sysfs_remove_group(&vdev->dev.kobj, &virtsocket_attr_group);
out_free_netdev:
	free_netdev(nd);
	return err;
}

static void virtsocket_changed(struct virtio_device *vdev)
{
	pr_debug("%s:\n", __func__);
}

static void __devexit virtsocket_remove(struct virtio_device *vdev)
{
	pr_debug("%s:\n", __func__);
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
	unregister_netdev(net_device);
	net_device = NULL;
	sysfs_remove_group(&vdev->dev.kobj, &virtsocket_attr_group);
}

static unsigned int features[] = {
	VIRTIO_SOCKET_F_RX_HEADER, VIRTIO_SOCKET_F_LARGE_BUFFERS,
	VIRTIO_SOCKET_F_TX_HEADER
};

static struct virtio_driver virtio_socket_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtsocket_probe,
	.remove =	__devexit_p(virtsocket_remove),
	.config_changed = virtsocket_changed,
};

static int __init init(void)
{
	return register_virtio_driver(&virtio_socket_driver);
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_socket_driver);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio socket driver");
MODULE_LICENSE("GPL");
