#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"

// Global lock to serialize file system operations in syscalls.
struct lock file_lock;

static void syscall_handler (struct intr_frame *);
static void *getpage (const void *address);
static void get_arg (struct intr_frame *f, int *args, int num);
void validate_str (const void *str);
static struct file *get_file (int fd);

// Initialize syscall subsystem and register INT 0x30 handler.
void syscall_init (void)
{
  lock_init (&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Gets the args from the stack, validates them using getpage,
// and stores them in args array.
static void get_arg (struct intr_frame *f, int *args, int num)
{
  int *ptr;
  for (int i = 0; i < num; i++)
    {
      ptr = (int *) f->esp + i + 1;
      for (int j = 0; j < 4; j++)
        {
          getpage ((const void *) ((char *) ptr + j));
        }
      args[i] = *ptr;
    }
}

// Validate user address and return its kernel mapping.
static void *getpage (const void *address)
{
  if (address == NULL || !is_user_vaddr (address))
    {
      exit (-1);
    }
  void *ptr = pagedir_get_page (active_pd (), address);

  if (!ptr)
    {
      exit (-1);
    }
  return ptr;
}

// Ensure a user string is readable up to NUL.
void validate_str (const void *str)
{
  while (*(char *) getpage (str) != 0)
    {
      str = (char *) str + 1;
    }
}

// Find open file by descriptor in current thread.
struct file *get_file (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *list_elem_ptr = list_begin (&cur->file_list);

  while (list_elem_ptr != list_end (&cur->file_list))
    {
      struct list_elem *next_elem = list_next (list_elem_ptr);
      struct file_process *file_entry =
          list_entry (list_elem_ptr, struct file_process, elem);

      if (fd == file_entry->fd)
        {
          return file_entry->file;
        }

      list_elem_ptr = next_elem;
    }
  return NULL;
}

// Syscall handler function, stores return value in f->eax.
static void syscall_handler (struct intr_frame *f UNUSED)
{
  for (int i = 0; i < 4; i++)
    {
      getpage ((const void *) ((char *) f->esp + i));
    }
  int *syscall_number = getpage (f->esp);
  int args[3];
  switch (*syscall_number)
    {
        case SYS_HALT: {
          shutdown_power_off ();
          break;
        }

        case SYS_EXIT: {
          struct thread *cur = thread_current ();
          get_arg (f, args, 1);
          int status = args[0];
          if (cur->cp != NULL)
            {
              cur->cp->exit_status = status;
            }
          if (status < 0) {
            status = -1;
          }
          printf ("%s: exit(%d)\n", cur->name, status);
          thread_exit ();
          break;
        }

        case SYS_EXEC: {
          get_arg (f, args, 1);
          validate_str ((const void *) args[0]);
          args[0] = (int) getpage ((const void *) args[0]);
          lock_acquire (&file_lock);
          f->eax = process_execute ((const char *) args[0]);
          lock_release (&file_lock);
          break;
        }

        case SYS_WAIT: {
          get_arg (f, args, 1);
          int pid = args[0];
          f->eax = process_wait (pid);
          break;
        }

        case SYS_CREATE: {
          get_arg (f, args, 2);
          validate_str ((const void *) args[0]);
          const char *name = (const char *) getpage ((const void *) args[0]);
          lock_acquire (&file_lock);
          int result = filesys_create (name, args[1]);
          lock_release (&file_lock);
          f->eax = result;
          break;
        }

        case SYS_REMOVE: {
          get_arg (f, args, 1);
          validate_str ((const void *) args[0]);
          const char *name = (const char *) getpage ((const void *) args[0]);
          lock_acquire (&file_lock);
          f->eax = filesys_remove (name);
          lock_release (&file_lock);
          break;
        }

        case SYS_OPEN: {
          get_arg (f, args, 1);
          validate_str ((const void *) args[0]);
          args[0] = (int) getpage ((const void *) args[0]);
          lock_acquire (&file_lock);
          struct file *file = filesys_open ((const char *) args[0]);
          if (file == NULL)
            {
              f->eax = -1;
              lock_release (&file_lock);
            }
          else
            {
              struct file_process *fp = palloc_get_page (0);
              if (fp == NULL)
                {
                  f->eax = -1;
                  lock_release (&file_lock);
                }
              else
                {
                  struct thread *cur = thread_current ();
                  fp->file = file;
                  fp->fd = cur->fd;
                  cur->fd++;
                  list_push_back (&cur->file_list, &fp->elem);
                  f->eax = fp->fd;
                  lock_release (&file_lock);
                }
            }
          break;
        }

        case SYS_FILESIZE: {
          get_arg (f, args, 1);
          int fd = args[0];
          lock_acquire (&file_lock);
          struct file *file = get_file (fd);
          if (file == NULL)
            {
              lock_release (&file_lock);
              f->eax = -1;
            }
          else
            {
              int size = file_length (file);
              lock_release (&file_lock);
              f->eax = size;
            }
          break;
        }

        case SYS_READ: {
          // args[0] = file descriptor, args[1] = buffer, args[2] = size
          get_arg (f, args, 3);
          void *buf = getpage ((const void *) args[1]);
          if (args[2] < 0)
            {
              f->eax = args[2];
              break;
            }
          if (args[0] == 0)
            {
              uint8_t *buf = (uint8_t *) args[1];
              for (int i = 0; i < args[2]; i++)
                {
                  buf[i] = input_getc ();
                }
              f->eax = args[2];
              break;
            }

          lock_acquire (&file_lock);
          struct file *fp = get_file (args[0]);
          if (!fp)
            {
              lock_release (&file_lock);
              f->eax = -1;
              break;
            }
          int read = file_read (fp, buf, args[2]);
          lock_release (&file_lock);
          f->eax = read;
          break;
        }

        case SYS_WRITE: {
          get_arg (f, args, 3);
          int fd = args[0];
          void *buffer = getpage (((const void *) args[1]));
          unsigned size = args[2];

          if (fd == 1)
            {
              putbuf (buffer, size);
              f->eax = size;
              break;
            }
          lock_acquire (&file_lock);
          struct file *fp = get_file (fd);
          if (!fp)
            {
              lock_release (&file_lock);
              f->eax = -1;
              break;
            }
          int write = file_write (fp, buffer, size);
          lock_release (&file_lock);
          f->eax = write;
          break;
        }

        case SYS_SEEK: {
          get_arg (f, args, 2);
          lock_acquire (&file_lock);
          struct file *file = get_file (args[0]);
          if (file == NULL)
            {
              lock_release (&file_lock);
              f->eax = -1;
              break;
            }
          file_seek (file, args[1]);
          lock_release (&file_lock);
          break;
        }

        case SYS_TELL: {
          get_arg (f, args, 1);
          lock_acquire (&file_lock);
          struct file *file = get_file (args[0]);
          if (file == NULL)
            {
              lock_release (&file_lock);
              f->eax = -1;
              break;
            }
          off_t offset = file_tell (file);
          lock_release (&file_lock);
          f->eax = offset;
          break;
        }

        case SYS_CLOSE: {
          get_arg (f, args, 1);
          lock_acquire (&file_lock);

          struct thread *cur = thread_current ();
          struct list_elem *current_elem = list_begin (&cur->file_list);
          int fd_to_close = args[0];

          while (current_elem != list_end (&cur->file_list))
            {
              struct list_elem *next_elem = list_next (current_elem);
              struct file_process *file_entry =
                  list_entry (current_elem, struct file_process, elem);
              if (fd_to_close == file_entry->fd || fd_to_close == -1)
                {
                  file_close (file_entry->file);
                  list_remove (&file_entry->elem);
                  palloc_free_page (file_entry);
                  if (fd_to_close != -1)
                    {
                      break;
                    }
                }
              current_elem = next_elem;
            }
          lock_release (&file_lock);
          break;
        }
      default:
        break;
    }
}

// Terminate current process with status, print message, and calls thread_exit.
void exit (int status)
{
  struct thread *cur = thread_current ();
  if (cur->cp != NULL)
    {
      cur->cp->exit_status = status;
    }
  if (status < 0)
    status = -1;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}
