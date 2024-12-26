#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stddef.h>

#include "filesys/off_t.h"

void syscall_init(void);

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) - 1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/** ----- #Project 2: System Call ----- */
#ifndef VM
void check_address(void *addr);
#else
/** #Project 3: Anonymous Page */
struct page *check_address(void *addr);
#endif

void halt(void);
void exit(int status);
pid_t fork(const char *thread_name);
int exec(const char *cmd_line);
int wait(pid_t);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
int tell(int fd);
void close(int fd);

/** Project 3: Memory Mapped Files */
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);
void munmap(void *addr);

/** Project 4: File System */
bool isdir(int fd);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);

/** #Project 2: System Call */
extern struct lock filesys_lock;  // 파일 읽기/쓰기 용 lock

/** #Project 2: Extend File Descriptor (Extra) */
int dup2(int oldfd, int newfd);

#endif /* userprog/syscall.h */
