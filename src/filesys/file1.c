#include "filesys/file.h"

#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/inode.h"
#include "threads/malloc.h"

#define MAX_LOG_ENTRIES 100

/* Opens a file for the given INODE, of which it takes ownership,
 * and returns the new file. Returns a null pointer if an
 * allocation fails or if INODE is null. */
struct file *file_open(struct inode *inode) {
    struct file *file = calloc(1, sizeof *file);
    if (inode != NULL && file != NULL) {
        file->inode = inode;
        file->pos = 0;
        file->deny_write = false;
        file->access_log_count = 0; //new
        memset(file->access_log, 0, sizeof(file->access_log)); //new

        file->dup_count = 0;
        return file;
    } else {
        inode_close(inode);
        free(file);
        return NULL;
    }
}

/* Opens and returns a new file for the same inode as FILE.
 * Returns a null pointer if unsuccessful. */
struct file *file_reopen(struct file *file) {
    return file_open(inode_reopen(file->inode));
}

/* Duplicate the file object including attributes and returns a new file for the
 * same inode as FILE. Returns a null pointer if unsuccessful. */
struct file *file_duplicate(struct file *file) {
    struct file *nfile = file_open(inode_reopen(file->inode));
    if (nfile) {
        nfile->pos = file->pos;
        nfile->dup_count = file->dup_count + 1; //new
        if (file->deny_write)
            file_deny_write(nfile);
    }
    return nfile;
}

/* Closes FILE. */
void file_close(struct file *file) {
    if (file != NULL) {
        list_file_access(file); // Print the log before closing the file
        file_allow_write(file);
        inode_close(file->inode);
        free(file);
    }
}

/* Returns the inode encapsulated by FILE. */
struct inode *file_get_inode(struct file *file) {
    return file->inode;
}

/* Reads SIZE bytes from FILE into BUFFER,
 * starting at the file's current position.
 * Returns the number of bytes actually read,
 * which may be less than SIZE if end of file is reached.
 * Advances FILE's position by the number of bytes read. */
off_t file_read(struct file *file, void *buffer, off_t size) {
    off_t bytes_read = inode_read_at(file->inode, buffer, size, file->pos);
    file->pos += bytes_read;
//new:
    if (file->access_log_count < MAX_LOG_ENTRIES) {
        struct file_log_entry *entry = &file->access_log[file->access_log_count++];
        strlcpy(entry->operation, "read", sizeof(entry->operation));

        entry->size = bytes_read;
    }

    return bytes_read;
}

/* Reads SIZE bytes from FILE into BUFFER,
 * starting at offset FILE_OFS in the file.
 * Returns the number of bytes actually read,
 * which may be less than SIZE if end of file is reached.
 * The file's current position is unaffected. */
off_t file_read_at(struct file *file, void *buffer, off_t size, off_t file_ofs) {
    return inode_read_at(file->inode, buffer, size, file_ofs);
}

/* Writes SIZE bytes from BUFFER into FILE,
 * starting at the file's current position.
 * Returns the number of bytes actually written,
 * which may be less than SIZE if end of file is reached.
 * Advances FILE's position by the number of bytes read. */
off_t file_write(struct file *file, const void *buffer, off_t size) {
    if (inode_get_type(file->inode) == 1) // Directories cannot be written
        return -1;

    off_t bytes_written = inode_write_at(file->inode, buffer, size, file->pos);
    file->pos += bytes_written;
//new
    if (file->access_log_count < MAX_LOG_ENTRIES) {
        struct file_log_entry *entry = &file->access_log[file->access_log_count++];
        strlcpy(entry->operation, "write", sizeof(entry->operation));
        entry->size = bytes_written;
    }

    return bytes_written;
}

/* Writes SIZE bytes from BUFFER into FILE,
 * starting at offset FILE_OFS in the file.
 * Returns the number of bytes actually written,
 * which may be less than SIZE if end of file is reached.
 * The file's current position is unaffected. */
off_t file_write_at(struct file *file, const void *buffer, off_t size, off_t file_ofs) {
    return inode_write_at(file->inode, buffer, size, file_ofs);
}

/* Prevents write operations on FILE's underlying inode
 * until file_allow_write() is called or FILE is closed. */
void file_deny_write(struct file *file) {
    ASSERT(file != NULL);
    if (!file->deny_write) {
        file->deny_write = true;
        inode_deny_write(file->inode);
    }
}

/* Re-enables write operations on FILE's underlying inode.
 * (Writes might still be denied by some other file that has the
 * same inode open.) */
void file_allow_write(struct file *file) {
    ASSERT(file != NULL);
    if (file->deny_write) {
        file->deny_write = false;
        inode_allow_write(file->inode);
    }
}

/* Returns the size of FILE in bytes. */
off_t file_length(struct file *file) {
    ASSERT(file != NULL);
    return inode_length(file->inode);
}

/* Sets the current position in FILE to NEW_POS bytes from the
 * start of the file. */
void file_seek(struct file *file, off_t new_pos) {
    ASSERT(file != NULL);
    ASSERT(new_pos >= 0);
    file->pos = new_pos;
}

/* Returns the current position in FILE as a byte offset from the
 * start of the file. */
off_t file_tell(struct file *file) {
    ASSERT(file != NULL);
    return file->pos;
}

/* Logs and prints the access log of the given FILE. */
void list_file_access(const struct file *file) {
    if (file == NULL) {
        printf("No file operations logged.\n");
        return;
    }

    printf("File Access Log:\n");
    printf("Operations Logged: %d\n", file->access_log_count);

    for (int i = 0; i < file->access_log_count; i++) {
        printf("Operation: %s | Size: %d bytes\n",
               file->access_log[i].operation, file->access_log[i].size);
    }
}

