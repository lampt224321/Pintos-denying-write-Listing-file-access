/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

/** Project 3: Memory Mapped Files */
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {
    // In this function, you can setup anything related to the file backed page.
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;

    struct aux *aux = (struct aux *)page->uninit.aux;
    file_page->file = aux->file;
    file_page->offset = aux->offset;
    file_page->page_read_bytes = aux->page_read_bytes;

    return true;
}

/** Project 3: Swap In/Out - Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page UNUSED = &page->file;

    return lazy_load_segment(page, file_page);
}

/** Project 3: Swap In/Out - Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_write_at(file_page->file, page->va, file_page->page_read_bytes, file_page->offset);
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    }

    page->frame->page = NULL;
    page->frame = NULL;
    pml4_clear_page(thread_current()->pml4, page->va);

    return true;
}

/** Project 3: Anonymous Page - Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;

    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_write_at(file_page->file, page->va, file_page->page_read_bytes, file_page->offset);
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    }

    if (page->frame) {
        list_remove(&page->frame->frame_elem);
        page->frame->page = NULL;
        page->frame = NULL;
        free(page->frame);
    }

    pml4_clear_page(thread_current()->pml4, page->va);
}

/** Project 3: Memory Mapped Files - Memory Mapping - Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    lock_acquire(&filesys_lock);
    struct file *mfile = file_reopen(file);
    void *ori_addr = addr;
    size_t read_bytes = (length > file_length(mfile)) ? file_length(mfile) : length;
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(addr) == 0);
    ASSERT(offset % PGSIZE == 0);

    struct aux *aux;
    while (read_bytes > 0 || zero_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        aux = (struct aux *)malloc(sizeof(struct aux));
        if (!aux)
            goto err;

        aux->file = mfile;
        aux->offset = offset;
        aux->page_read_bytes = page_read_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, aux)) {
            goto err;
        }

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        addr += PGSIZE;
        offset += page_read_bytes;
    }
    lock_release(&filesys_lock);

    return ori_addr;

err:
    free(aux);
    lock_release(&filesys_lock);
    return NULL;
}

/** Project 3: Memory Mapped Files - Memory Mapping - Do the munmap */
void do_munmap(void *addr) {
    struct thread *curr = thread_current();
    struct page *page;

    lock_acquire(&filesys_lock);
    while ((page = spt_find_page(&curr->spt, addr))) {
        if (page)
            destroy(page);

        addr += PGSIZE;
    }
    lock_release(&filesys_lock);
}
