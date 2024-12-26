#include "filesys/inode.h"

#include <debug.h>
#include <list.h>
#include <round.h>
#include <string.h>

#include "filesys/fat.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
    disk_sector_t start; /* First data sector. */
    off_t length;        /* File size in bytes. */
    unsigned magic;      /* Magic number. */

    /** #Project 4: File System */
    // uint32_t unused[125]; /* Not used. */
    uint32_t unused[92]; /* Not used. */
    uint32_t type;       /* 0: file, 1: directory, 2: link*/
    char path[128];      /* linkpath */
};

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t bytes_to_sectors(off_t size) {
    return DIV_ROUND_UP(size, DISK_SECTOR_SIZE);
}

/** #Project 4: File System - Error 처리 */
static disk_sector_t byte_to_sector(const struct inode *inode, off_t pos);

static struct inode *inode_backup;

/* In-memory inode. */
struct inode {
    struct list_elem elem;  /* Element in inode list. */
    disk_sector_t sector;   /* Sector number of disk location. */
    int open_cnt;           /* Number of openers. */
    bool removed;           /* True if deleted, false otherwise. */
    int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
    struct inode_disk data; /* Inode content. */
};

#ifndef EFILESYS
/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static disk_sector_t byte_to_sector(const struct inode *inode, off_t pos) {
    ASSERT(inode != NULL);
    if (pos < inode->data.length)
        return inode->data.start + pos / DISK_SECTOR_SIZE;
    else
        return -1;
}
#endif

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
    list_init(&open_inodes);

    /** Project 4: Soft Link */
    inode_backup = NULL;
}

#ifndef EFILESYS
/* Initializes an inode with LENGTH bytes of data and writes
 * the new inode to sector SECTOR on the file system disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool inode_create(disk_sector_t sector, off_t length, int32_t type) {
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
     * one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == DISK_SECTOR_SIZE);

    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL) {
        size_t sectors = bytes_to_sectors(length);
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;

        if (free_map_allocate(sectors, &disk_inode->start)) {
            disk_write(filesys_disk, sector, disk_inode);
            if (sectors > 0) {
                static char zeros[DISK_SECTOR_SIZE];
                size_t i;

                for (i = 0; i < sectors; i++)
                    disk_write(filesys_disk, disk_inode->start + i, zeros);
            }
            success = true;
        }
        free(disk_inode);
    }
    return success;
}
#endif

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *inode_open(disk_sector_t sector) {
    struct list_elem *e;
    struct inode *inode;

    /* Check whether this inode is already open. */
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
        inode = list_entry(e, struct inode, elem);
        if (inode->sector == sector) {
            inode_reopen(inode);
            return inode;
        }
    }

    /* Allocate memory. */
    inode = malloc(sizeof *inode);
    if (inode == NULL)
        return NULL;

    /* Initialize. */
    list_push_front(&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    disk_read(filesys_disk, inode->sector, &inode->data);

    return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen(struct inode *inode) {
    if (inode != NULL)
        inode->open_cnt++;
    return inode;
}

/* Returns INODE's inode number. */
disk_sector_t inode_get_inumber(const struct inode *inode) {
    return inode->sector;
}

#ifndef EFILESYS
/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode) {
    /* Ignore null pointer. */
    if (inode == NULL)
        return;

    /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0) {
        /* Remove from inode list and release lock. */
        list_remove(&inode->elem);

        /* Deallocate blocks if removed. */
        if (inode->removed) {
            free_map_release(inode->sector, 1);
            free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
        }

        free(inode);
    }
}
#endif

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void inode_remove(struct inode *inode) {
    ASSERT(inode != NULL);
    inode->removed = true;
}

#ifndef EFILESYS
/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset) {
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    while (size > 0) {
        /* Disk sector to read, starting byte offset within sector. */
        disk_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % DISK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = DISK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
            /* Read full sector directly into caller's buffer. */
            disk_read(filesys_disk, sector_idx, buffer + bytes_read);
        } else {
            /* Read sector into bounce buffer, then partially copy
             * into caller's buffer. */
            if (bounce == NULL) {
                bounce = malloc(DISK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }
            disk_read(filesys_disk, sector_idx, bounce);
            memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
    }
    free(bounce);

    return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size, off_t offset) {
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;

    if (inode->deny_write_cnt)
        return 0;

    while (size > 0) {
        /* Sector to write, starting byte offset within sector. */
        disk_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % DISK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = DISK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
            /* Write full sector directly to disk. */
            disk_write(filesys_disk, sector_idx, buffer + bytes_written);
        } else {
            /* We need a bounce buffer. */
            if (bounce == NULL) {
                bounce = malloc(DISK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }

            /* If the sector contains data before or after the chunk
               we're writing, then we need to read in the sector
               first.  Otherwise we start with a sector of all zeros. */
            if (sector_ofs > 0 || chunk_size < sector_left)
                disk_read(filesys_disk, sector_idx, bounce);
            else
                memset(bounce, 0, DISK_SECTOR_SIZE);
            memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
            disk_write(filesys_disk, sector_idx, bounce);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
    }
    free(bounce);

    return bytes_written;
}
#endif

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode) {
    inode->deny_write_cnt++;
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode) {
    ASSERT(inode->deny_write_cnt > 0);
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode) {
    return inode->data.length;
}

#ifdef EFILESYS
static disk_sector_t byte_to_sector(const struct inode *inode, off_t pos) {
    ASSERT(inode != NULL);

    cluster_t target = sector_to_cluster(inode->data.start);

    while (pos >= DISK_SECTOR_SIZE) {  // file length보다 pos가 크면 새로운 cluster를 할당
        if (fat_get(target) == EOChain)
            fat_create_chain(target);

        target = fat_get(target);
        pos -= DISK_SECTOR_SIZE;
    }

    disk_sector_t sector = cluster_to_sector(target);
    return sector;
}

/** #Project 4: File System - Initializes an inode with LENGTH bytes of data and writes
 * the new inode to sector SECTOR on the file system disk. */
bool inode_create(disk_sector_t sector, off_t length, int32_t type) {
    struct inode_disk *disk_inode = NULL;
    cluster_t start_clst;
    bool success = false;

    ASSERT(length >= 0);
    ASSERT(sizeof *disk_inode == DISK_SECTOR_SIZE);

    /* create disk_node and initialize*/
    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL) {
        size_t sectors = bytes_to_sectors(length);

        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->type = type;

        /* data cluster allocation */
        if (start_clst = fat_create_chain(0)) {
            disk_inode->start = cluster_to_sector(start_clst);
            /* write disk_inode on disk */
            disk_write(filesys_disk, sector, disk_inode);

            if (sectors > 0) {
                static char zeros[DISK_SECTOR_SIZE];
                cluster_t target = start_clst;
                disk_sector_t w_sector;
                size_t i;

                /* make cluster chain based length and initialize zero*/
                while (sectors > 0) {
                    w_sector = cluster_to_sector(target);
                    disk_write(filesys_disk, w_sector, zeros);

                    target = fat_create_chain(target);
                    sectors--;
                }
            }

            success = true;
        }

        free(disk_inode);
    }

    return success;
}

/** #Project 4: File System - Closes INODE and writes it to disk. */
void inode_close(struct inode *inode) {
    /* Ignore null pointer. */
    if (inode == NULL)
        return;

    /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0) {
        struct inode *data_inode = check_is_link(inode);  // link에 원본 data를 저장

        /* Remove from inode list and release lock. */
        list_remove(&inode->elem);

        /* Deallocate blocks if removed. */
        if (inode->removed)
            fat_remove_chain(inode->sector, 0);

        disk_write(filesys_disk, inode->sector, &data_inode->data);  // inode close 시 disk에 저장

        data_inode = return_is_link(inode);

        free(inode);
    }
}

/** #Project 4: File System - Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset) {
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    inode = check_is_link(inode);

    while (size > 0) {
        /* Disk sector to read, starting byte offset within sector. */
        disk_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % DISK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = DISK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
            /* Read full sector directly into caller's buffer. */
            disk_read(filesys_disk, sector_idx, buffer + bytes_read);
        } else {
            /* Read sector into bounce buffer, then partially copy
             * into caller's buffer. */
            if (bounce == NULL) {
                bounce = malloc(DISK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }
            disk_read(filesys_disk, sector_idx, bounce);
            memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
    }
    free(bounce);

    inode = return_is_link(inode);

    return bytes_read;
}

/** #Project 4: File System - Writes SIZE bytes from BUFFER into INODE, starting at OFFSET. */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size, off_t offset) {
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;
    off_t ori_offset = offset;  // backup

    if (inode->deny_write_cnt)
        return 0;

    inode = check_is_link(inode);

    while (size > 0) {
        /* Sector to write, starting byte offset within sector. */
        disk_sector_t sector_idx = byte_to_sector(inode, offset);
        int sector_ofs = offset % DISK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        int sector_left = DISK_SECTOR_SIZE - sector_ofs;
        int min_left = sector_left;  // limit 없으므로 삭제

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
            /* Write full sector directly to disk. */
            disk_write(filesys_disk, sector_idx, buffer + bytes_written);
        } else {
            /* We need a bounce buffer. */
            if (bounce == NULL) {
                bounce = malloc(DISK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }

            /* If the sector contains data before or after the chunk
               we're writing, then we need to read in the sector
               first.  Otherwise we start with a sector of all zeros. */
            if (sector_ofs > 0 || chunk_size < sector_left)
                disk_read(filesys_disk, sector_idx, bounce);
            else
                memset(bounce, 0, DISK_SECTOR_SIZE);
            memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
            disk_write(filesys_disk, sector_idx, bounce);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
    }
    free(bounce);

    if (inode_length(inode) < ori_offset + bytes_written)  // inode length 갱신
        inode->data.length = ori_offset + bytes_written;

    inode = return_is_link(inode);

    return bytes_written;
}
#endif

/** #Project 4: File System - Returns the type, in bool, of INODE's data. */
int32_t inode_get_type(const struct inode *inode) {
    return inode->data.type;
}

/** #Project 4: File System - Returns the removed, in bool, of INODE */
bool inode_is_removed(const struct inode *inode) {
    return inode->removed;
}

/** #Project 4: File System - Returns the sector, in bytes, of INODE */
disk_sector_t inode_sector(struct inode *inode) {
    return inode->sector;
}

void inode_set_linkpath(struct inode *inode, const char *path) {
    strlcpy(inode->data.path, path, 128);
}

char *inode_get_linkpath(struct inode *inode) {
    return inode->data.path;
}

struct inode *check_is_link(struct inode *inode) {
    if (inode_get_type(inode) != 2)
        return inode;

    inode_backup = inode;

    while (inode_get_type(inode) == 2) {
        char target[128];
        target[0] = '\0';

        struct dir *target_dir = parse_path(inode->data.path, target);

        if (!dir_lookup(target_dir, target, &inode)) {
            inode = inode_backup;
            inode_backup = NULL;
            exit(-404);
        }

        if (inode_is_removed(inode)) {
            inode = inode_backup;
            inode_backup = NULL;
            exit(-503);
        }
    }

    return inode;
}

struct inode *return_is_link(struct inode *inode) {
    if (inode_backup == NULL)
        return inode;

    struct inode *temp = inode_backup;
    inode_backup = NULL;

    return temp;
}