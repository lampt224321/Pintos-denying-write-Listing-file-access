#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
typedef int off_t; // Hoặc long nếu bạn cần hỗ trợ số lớn hơn.
tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);

/** #Project 2: Command Line Parsing */
void argument_stack(char **argv, int argc, struct intr_frame *if_);

/** #Project 2: System Call */
thread_t *get_child_process(int pid);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
int process_close_file(int fd);
int process_insert_file(int fd, struct file *f);

/** #Project 3: Memory Mapped Files */
bool lazy_load_segment(struct page *page, void *aux);

/** Project 3: Anonymous Page */
struct aux {
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
};

#define STDIN  0x1
#define STDOUT 0x2
#define STDERR 0x3

#endif /* userprog/process.h */
