/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#ifdef CAPTURE_SOCKETCALL

#include <helpers/interfaces/syscalls_dispatcher.h>
#include <helpers/base/maps_getters.h>
#include <syscall.h>

/* Do a compile-time check on socketcall syscall presence */
#ifndef __NR_socketcall
#error CAPTURE_SOCKETCALL defined but architecture does not support socketcall()
#endif

#endif


/* All the functions that are called in bpf to extract parameters
 * start with the `extract` prefix.
 */

/////////////////////////
// SYSCALL ARGUMENTS EXTRACION
////////////////////////

/**
 * @brief Extract a specific syscall argument
 *
 * @param regs pointer to the strcut where we find the arguments
 * @param idx index of the argument to extract
 * @return generic unsigned long value that can be a pointer to the arg
 * or directly the value, it depends on the type of arg.
 */
static __always_inline unsigned long extract__syscall_argument(struct pt_regs *regs, int idx)
{
	unsigned long arg;
	switch(idx)
	{
	case 0:
		arg = PT_REGS_PARM1_CORE_SYSCALL(regs);
		break;
	case 1:
		arg = PT_REGS_PARM2_CORE_SYSCALL(regs);
		break;
	case 2:
		arg = PT_REGS_PARM3_CORE_SYSCALL(regs);
		break;
	case 3:
		arg = PT_REGS_PARM4_CORE_SYSCALL(regs);
		break;
	case 4:
		arg = PT_REGS_PARM5_CORE_SYSCALL(regs);
		break;
	case 5:
		/* Not defined in libbpf, look at `definitions_helpers.h` */
		arg = PT_REGS_PARM6_CORE_SYSCALL(regs);
		break;
	default:
		arg = 0;
	}

	return arg;
}

/* Number of arguments for netwock / socket system calls */
#define SC_ARG_NUM_SOCKET	3
#define SC_ARG_NUM_BIND		3

/**
 * @brief Extract one ore more arguments related to a network / socket system call.
 *
 * This function takes into consideration whether the network system call has been
 * called directly (e.g. accept4) or through the socketcall system call multiplexer.
 * For the socketcall multiplexer, arguments are extracted from the second argument
 * of the socketcall system call.  See socketcall(2) for more information.
 *
 * @param argv Pointer to store up to @num arguments of size `unsigned long`
 * @param num Number of arguments to extract
 * @param regs Pointer to the struct pt_regs to access arguments and system call ID
 */
static __always_inline void extract__network_args(void *argv, int num, struct pt_regs *regs)
{
#ifdef CAPTURE_SOCKETCALL
	int id = syscalls_dispatcher__get_syscall_id(regs);
	if(id == __NR_socketcall)
	{
		unsigned long args_pointer = extract__syscall_argument(regs, 1);
		bpf_probe_read_user(argv, num * sizeof(unsigned long), (void*)args_pointer);
		return;
	}
#endif
	for (int i = 0; i < num; i++)
	{
		unsigned long *dst = (unsigned long *)argv;
		dst[i] = extract__syscall_argument(regs, i);
	}
}

#ifdef CAPTURE_SOCKETCALL

/* Definitions */
#define SC_SYS_SOCKET     1               /* sys_socket(2)                */
#define SC_SYS_BIND       2               /* sys_bind(2)                  */
#define SC_SYS_CONNECT    3               /* sys_connect(2)               */
#define SC_SYS_LISTEN     4               /* sys_listen(2)                */
#define SC_SYS_ACCEPT     5               /* sys_accept(2)                */
#define SC_SYS_GETSOCKNAME        6               /* sys_getsockname(2)           */
#define SC_SYS_GETPEERNAME        7               /* sys_getpeername(2)           */
#define SC_SYS_SOCKETPAIR 8               /* sys_socketpair(2)            */
#define SC_SYS_SEND       9               /* sys_send(2)                  */
#define SC_SYS_RECV       10              /* sys_recv(2)                  */
#define SC_SYS_SENDTO     11              /* sys_sendto(2)                */
#define SC_SYS_RECVFROM   12              /* sys_recvfrom(2)              */
#define SC_SYS_SHUTDOWN   13              /* sys_shutdown(2)              */
#define SC_SYS_SETSOCKOPT 14              /* sys_setsockopt(2)            */
#define SC_SYS_GETSOCKOPT 15              /* sys_getsockopt(2)            */
#define SC_SYS_SENDMSG    16              /* sys_sendmsg(2)               */
#define SC_SYS_RECVMSG    17              /* sys_recvmsg(2)               */
#define SC_SYS_ACCEPT4    18              /* sys_accept4(2)               */
#define SC_SYS_RECVMMSG   19              /* sys_recvmmsg(2)              */
#define SC_SYS_SENDMMSG   20              /* sys_sendmmsg(2)              */
#define SC_SOCKETCALL_MAX  21

/*
 * If there are direct socket call variants available, they should be marked
 * interesting.  This function determines if a socketcall ID is of interest
 * depending on the setting of the direct system call.  In case, a direct
 * system call does not exist, always consider the socketcall ID as interesting.
 */
static __always_inline bool is_sc_interesting(int sc_id)
{
	/* We use the evt_pair just to have enter and exit events in one shot */
	const u32 sc_to_syscall[SC_SOCKETCALL_MAX] = {
#ifdef __NR_socket
		[SC_SYS_SOCKET] = __NR_socket,
#endif
#ifdef __NR_bind
		[SC_SYS_BIND] = __NR_bind,
#endif
#ifdef __NR_connect
		[SC_SYS_CONNECT] = __NR_connect,
#endif
#ifdef __NR_listen
		[SC_SYS_LISTEN] = __NR_listen,
#endif
#ifdef __NR_accept
		[SC_SYS_ACCEPT] = __NR_accept,
#endif
#ifdef __NR_getsockname
		[SC_SYS_GETSOCKNAME] = __NR_getsockname,
#endif
#ifdef __NR_getpeername
		[SC_SYS_GETPEERNAME] = __NR_getpeername,
#endif
#ifdef __NR_socketpair
		[SC_SYS_SOCKETPAIR] = __NR_socketpair,
#endif
#ifdef __NR_send
		[SC_SYS_SEND] = __NR_send,
#endif
#ifdef __NR_recv
		[SC_SYS_RECV]  = __NR_recv,
#endif
#ifdef __NR_sendto
		[SC_SYS_SENDTO] = __NR_sendto,
#endif
#ifdef __NR_recvfrom
		[SC_SYS_RECVFROM] = __NR_recvfrom,
#endif
#ifdef __NR_shutdown
		[SC_SYS_SHUTDOWN]  = __NR_shutdown,
#endif
#ifdef __NR_setsockopt
		[SC_SYS_SETSOCKOPT] = __NR_setsockopt,
#endif
#ifdef __NR_getsockopt
		[SC_SYS_GETSOCKOPT] = __NR_getsockopt,
#endif
#ifdef __NR_sendmsg
		[SC_SYS_SENDMSG] = __NR_sendmsg,
#endif
#ifdef __NR_recvmsg
		[SC_SYS_RECVMSG] = __NR_recvmsg,
#endif
#ifdef __NR_accept4
		[SC_SYS_ACCEPT4] = __NR_accept4,
#endif
#ifdef __NR_recvmmsg
		[SC_SYS_RECVMMSG] = __NR_recvmmsg,
#endif
#ifdef __NR_sendmmsg
		[SC_SYS_SENDMMSG] = __NR_sendmmsg,
#endif
	};

	if(sc_id < 1 || sc_id >= SC_SOCKETCALL_MAX)
		return false;

	u32 syscall_id = sc_to_syscall[sc_id];

	/* Consider the socketcall ID as interesting if there is no
	 * direct system call available (which can be tested).
	 */
	if (!syscall_id)
		return true;

	return maps__64bit_interesting_syscall(syscall_id);
}

#endif
