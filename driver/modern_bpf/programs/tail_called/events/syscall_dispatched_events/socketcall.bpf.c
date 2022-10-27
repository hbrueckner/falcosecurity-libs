/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <syscall.h>

/* Definitions */
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/
#define SYS_ACCEPT4	18		/* sys_accept4(2)		*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)		*/
#define SOCKETCALL_MAX	21


/* Helpers */
static __always_inline int stash_sc_args(unsigned long *args)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return bpf_map_update_elem(&socketcall_args_map, &id, args, BPF_ANY);
}

static __always_inline unsigned long *unstash_sc_args()
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return bpf_map_lookup_elem(&socketcall_args_map, &id);
}

static __always_inline void delete_sc_args()
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	bpf_map_delete_elem(&socketcall_args_map, &id);
}


static __always_inline int sc_to_syscall_id(int sc_id)
{
	int syscall_id = 0;

        switch (sc_id) {
        case SYS_SOCKET:
#ifdef __NR_socket
		syscall_id = __NR_socket;
#endif
		break;
        case SYS_BIND:
#ifdef __NR_bind
		syscall_id = __NR_bind;
#endif
		break;
        case SYS_CONNECT:
#ifdef __NR_connect
		syscall_id = __NR_connect;
#endif
                break;
        case SYS_LISTEN:
#ifdef __NR_listen
		syscall_id = __NR_listen;
#endif
                break;
        case SYS_ACCEPT:
#ifdef __NR_accept
		syscall_id = __NR_accept;
#endif
                break;
        case SYS_GETSOCKNAME:
#ifdef __NR_getsockname
		syscall_id = __NR_getsockname;
#endif
                break;
        case SYS_GETPEERNAME:
#ifdef __NR_getpeername
		syscall_id = __NR_getpeername;
#endif
                break;
        case SYS_SOCKETPAIR:
#ifdef __NR_socketpair
		syscall_id = __NR_socketpair;
#endif
                break;
        case SYS_SEND:
#ifdef __NR_send
		syscall_id = __NR_send;
#endif
                break;
        case SYS_RECV:
#ifdef __NR_recv
		syscall_id = __NR_recv;
#endif
                break;
        case SYS_SENDTO:
#ifdef __NR_sendto
		syscall_id = __NR_sendto;
#endif
                break;
        case SYS_RECVFROM:
#ifdef __NR_recvfrom
		syscall_id = __NR_recvfrom;
#endif
                break;
        case SYS_SHUTDOWN:
#ifdef __NR_shutdown
		syscall_id = __NR_shutdown;
#endif
                break;
        case SYS_SETSOCKOPT:
#ifdef __NR_setsockopt
		syscall_id = __NR_setsockopt;
#endif
                break;
        case SYS_GETSOCKOPT:
#ifdef __NR_getsockopt
		syscall_id = __NR_getsockopt;
#endif
                break;
        case SYS_SENDMSG:
#ifdef __NR_sendmsg
		syscall_id = __NR_sendmsg;
#endif
                break;
        case SYS_RECVMSG:
#ifdef __NR_recvmsg
		syscall_id = __NR_recvmsg;
#endif
                break;
        case SYS_ACCEPT4:
#ifdef __NR_accept4
		syscall_id = __NR_accept4;
#endif
                break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
        case SYS_RECVMMSG:
#ifdef __NR_recvmmsg
		syscall_id = __NR_recvmmsg;
#endif
                break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
        case SYS_SENDMMSG:
#ifdef __NR_sendmmsg
		syscall_id = __NR_sendmmsg;
#endif
                break;
#endif
	};

	return syscall_id;
}

static __always_inline int store_sc_args(int sc_id, void *sc_args_ptr)
{
	int rc;
	unsigned long sc_args[6] = {};

        /* BPF verifier:
         *
         * Using nas[socketcall_id] causes an exception due to arithmetic operations
         * on the size argument. Therefore, use a switch statement instead, and directly
         * specify the number of bytes (arguments) to read.
         */
#define AL(x) ((x) * sizeof(unsigned long))
        switch (sc_id) {
        case SYS_SOCKET:
        case SYS_BIND:
        case SYS_CONNECT:
        case SYS_ACCEPT:
        case SYS_GETSOCKNAME:
        case SYS_GETPEERNAME:
        case SYS_SENDMSG:
        case SYS_RECVMSG:
		rc = bpf_probe_read_user(sc_args, AL(3), sc_args_ptr);
		break;

        case SYS_LISTEN:
        case SYS_SHUTDOWN:
		rc = bpf_probe_read_user(sc_args, AL(2), sc_args_ptr);
                break;

        case SYS_SOCKETPAIR:
        case SYS_SEND:
        case SYS_RECV:
        case SYS_ACCEPT4:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
        case SYS_SENDMMSG:
#endif
		rc = bpf_probe_read_user(sc_args, AL(4), sc_args_ptr);
                break;

        case SYS_SENDTO:
        case SYS_RECVFROM:
		rc = bpf_probe_read_user(sc_args, AL(6), sc_args_ptr);
                break;

        case SYS_SETSOCKOPT:
        case SYS_GETSOCKOPT:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
        case SYS_RECVMMSG:
#endif
		rc = bpf_probe_read_user(sc_args, AL(5), sc_args_ptr);
                break;
	default:
		rc = 1;
		break;
	};

	if (rc || stash_sc_args(sc_args))
		return 1;

	return 0;
}

static void __always_inline socket_tail_call(void *ctx, struct pt_regs *regs, bool is_enter)
{
	/* Get socketcall call identifier */
	s32 sc_id = extract__syscall_argument(regs, 0);

	/* Get socketcall arguments */
	unsigned long sc_args_ptr = extract__syscall_argument(regs, 1);

	/* Get syscall identifier for dispatching */
	int syscall_id = sc_to_syscall_id(sc_id);
	if (!syscall_id)
		return;

	/* Debug */
	bpf_printk("socketcall_%d: sc_id=%i syscall_id=%i", is_enter ? 'e' : 'x', sc_id, syscall_id);

	if (store_sc_args(sc_id, (void *)sc_args_ptr))
		return;

	if (is_enter)
		bpf_tail_call(ctx, &syscall_enter_tail_table, syscall_id);
	else
		bpf_tail_call(ctx, &syscall_exit_tail_table, syscall_id);
}


/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(socketcall_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Multiplex socket call - enter event */
	socket_tail_call(ctx, regs, true);

	/* The BPF tail call will never return, if this section is being reached,
	 * there was an error in preparation. In such cases, emit a socketcall
	 * event.
	 */
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SOCKETCALL_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SOCKETCALL_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(socketcall_x,
	     struct pt_regs *regs,
	     long ret)
{
	/* Multiplex socket call - exit event */
	socket_tail_call(ctx, regs, false);


	/* The BPF tail call will never return, if this section is being reached,
	 * there was an error in preparation. In such cases, emit a socketcall
	 * event.
	 */
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, SOCKETCALL_X_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_SOCKETCALL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: call (type: PT_INT32) */
	/* TODO provide an enum mapping for call */
	s32 sc_id = extract__syscall_argument(regs, 0);
	ringbuf__store_s32(&ringbuf, (s32)sc_id);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
