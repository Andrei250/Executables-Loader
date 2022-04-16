/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>

#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction defaultAction;
int filePointer;


static void segvHandler(int signum, siginfo_t *info, void *context) {
	int pageSize = getpagesize();
	char *address = (char *)info->si_addr;

	if (signum == SIGSEGV) {
		int pgNr = -1;
		int addrNr = (int) address;
		int i = 0;
		int segNumber = exec->segments_no;

		for (i = 0; i < segNumber; ++i) {
			uintptr_t vaddr = exec->segments[i].vaddr;
			unsigned int memSize = exec->segments[i].mem_size;

			if (addrNr >= vaddr && addrNr < vaddr + memSize) {
				pgNr = (uintptr_t)(address - vaddr) / pageSize;
				break;
			}
		}

		// If we cannot find the error in segments
		// or the page is already mapped
		// run the default handler
		int *arr = i < segNumber ? (int *) exec->segments[i].data : NULL;

		if (pgNr < 0 || i >= segNumber || arr[pgNr] == 1) {
			defaultAction.sa_sigaction(signum, info, context);
			return;
		}

		// Otherwise, map the page
		*((int *) exec->segments[i].data + pgNr) = 1;

		char *rc;
		int rcvCd;
		int totalPages = exec->segments[i].file_size / pageSize;
		uintptr_t vaddr = exec->segments[i].vaddr;
		void *mapAddr = (void *)(vaddr + pgNr * pageSize);
		int memLft = exec->segments[i].mem_size - exec->segments[i].file_size;

		if (pgNr <= totalPages) {
			rc = mmap(mapAddr, pageSize, PROT_NONE,
								MAP_PRIVATE | MAP_FIXED, filePointer,
								pgNr * pageSize + exec->segments[i].offset);

			if (rc == (char *) -1)
				exit(EXIT_FAILURE);
		} else {
			rc = mmap(mapAddr, pageSize, PROT_NONE,
								MAP_SHARED | MAP_ANONYMOUS, 0, 0);

			if (rc == (char *) -1)
				exit(EXIT_FAILURE);
		}

		rcvCd = mprotect(mapAddr, pageSize, exec->segments[i].perm);

		if (rcvCd < 0)
			exit(EXIT_FAILURE);

		// If it is the last page, we should complete with 0s at the end
		// of the file_size.
		if (totalPages == pgNr && memLft) {
			void *addr = (void *) (exec->segments[i].file_size + vaddr);
			int space = (pgNr + 1) * pageSize - exec->segments[i].file_size;

			rc = memset(addr, 0, space);

			if (rc < (char *) 0)
				exit(EXIT_FAILURE);
		}
	}

}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = segvHandler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);

	rc = sigaction(SIGSEGV, &sa, &defaultAction);

	if (rc < 0)
		exit(EXIT_FAILURE);

	return -1;
}

int so_execute(char *path, char *argv[])
{
	filePointer = open(path, O_RDONLY);

	if (filePointer < 0)
		exit(EXIT_FAILURE);

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	int pageSize = getpagesize();

	for (int i = 0; i < exec->segments_no; ++i) {
		int numberOfPages = exec->segments[i].mem_size / pageSize;

		// for each page into the segment save if the page is mapper or not
		exec->segments[i].data = calloc(numberOfPages, sizeof(int));
	}

	so_start_exec(exec, argv);

	return -1;
}
