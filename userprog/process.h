#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

// Tracks a child process and coordinates load and wait synchronization.
struct child_process
{
  tid_t pid;       // Thread ID of the child process.
  int exit_status; // Exit code returned when the child ends.
  bool exited;     // True if the child has exited.

  struct semaphore sema_load; // Syncs parent and child during load.
  bool load_success;          // True if the load succeeded.

  struct semaphore sema_wait; // Blocks parent until child exits.
  struct list_elem elem;      // Links to parent's child list.
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
