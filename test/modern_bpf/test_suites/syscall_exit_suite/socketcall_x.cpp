#include "../../event_class/event_class.h"

#if defined(__NR_socketcall)

#include <sys/socket.h>

TEST(SyscallExit, socketcallX_failure)
{
	auto evt_test = get_syscall_event_test(__NR_socketcall, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int call = -1;
	unsigned long *args = NULL;
	assert_syscall_state(SYSCALL_FAILURE, "socketcall", syscall(__NR_socketcall, call, args));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: call (type: PT_INT32) */
	evt_test->assert_numeric_param(2, (int32_t)call);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(2);
}

TEST(SyscallExit, socketcallX_socket_success)
{
	/* Let's call socket(2) via the socketcall syscall, so expecting a socket exit
	 * event.
	 */
	auto evt_test = get_syscall_event_test(__NR_socket, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int call = 1; /* SYS_SOCKET */
	unsigned long args[3] = {AF_INET, SOCK_RAW, PF_INET};

	int socket_fd = syscall(__NR_socketcall, call, args);
	assert_syscall_state(SYSCALL_SUCCESS, "socket_fd", socket_fd, NOT_EQUAL, -1);
	syscall(__NR_close, socket_fd);

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	evt_test->assert_numeric_param(1, (int64_t)socket_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif
