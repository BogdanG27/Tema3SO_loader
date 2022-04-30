#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "exec_parser.h"

typedef struct {
	so_exec_t *exec;
	int exec_fd;
	struct sigaction *prev_handler;
} TInfo;

TInfo info;

void mapPage(int page_fault_addr, so_seg_t *segment, siginfo_t *sinfo)
{
	int pageSize = getpagesize();
	// if the segment is not yet allocated, calloc mem for it
	if (segment->data == NULL) {
		int pagesToAlloc = segment->mem_size / pageSize;

		segment->data = (void *) calloc(pagesToAlloc, sizeof(char));
	}

	// finding page_index and page address
	int page_index = (page_fault_addr - segment->vaddr) / pageSize;
	int page_addr = page_index * pageSize;

	// if the page is already mapped
	if (((char *)(segment->data))[page_index] == 1)
		(*info.prev_handler).sa_sigaction(SIGSEGV, sinfo, NULL);

	/* Mapping page and mark it as allocated*/
	((char *)(segment->data))[page_index] = 1;
	void *addr = (void *)(segment->vaddr + page_addr);
	char *memMaped = mmap(addr, pageSize, PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANON, 0, 0);

	// reading data from file
	lseek(info.exec_fd, segment->offset + page_addr, SEEK_SET);
	if (page_addr < segment->file_size) {
		int size = segment->file_size - page_addr < pageSize ?
			segment->file_size - page_addr : pageSize;
		int bytes_read = read(info.exec_fd, (void *) memMaped, size);

		if (bytes_read < 0)
			exit(EXIT_FAILURE);
	}

	// set the permissions for the page
	mprotect(memMaped, pageSize, segment->perm);
}

void handler(int sig_no, siginfo_t *sig_info, void *context)
{
	int page_fault_addr = (int)sig_info->si_addr;

	for (int i = 0; i < info.exec->segments_no; i++) {
		so_seg_t *segment = &(info.exec)->segments[i];

		// check if the page is in a segment and is not mapped
		// if yes then map the page with the perms
		int cond1 = segment->vaddr <= page_fault_addr;
		int cond2 = page_fault_addr < segment->vaddr + segment->mem_size;
		if (cond1 && cond2) {
			mapPage(page_fault_addr, segment, sig_info);
			return;
		}
	}
	// if anything else (the other 2 cases) call the deafult handler
	(*info.prev_handler).sa_sigaction(SIGSEGV, sig_info, NULL);
}

int so_init_loader(void)
{
	// load the new handler
	struct sigaction sa;

	sa.sa_sigaction = handler;
	sigaction(SIGSEGV, &sa, NULL);

	info.exec = (so_exec_t *) calloc(1, sizeof(so_exec_t));

	return 0;
}

int so_execute(char *path, char *argv[])
{
	info.exec = so_parse_exec(path);
	if (!(info.exec))
		return -1;

	info.exec_fd = open(path, O_RDONLY, 0644);
	so_start_exec(info.exec, argv);

	return 0;
}
