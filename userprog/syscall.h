#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);
void exit (int status);

// Tracks an open file and its descriptor for a process.
struct file_process
{
  int fd;                // Unique file descriptor for this process.
  struct file *file;     // Pointer to the opened file object.
  struct list_elem elem; // Used to link into the process's open file list.
};

#endif /* userprog/syscall.h */
