#ifndef VM_VM_H
#define VM_VM_H
#include <hash.h>
#include <stdbool.h>

#include "threads/palloc.h"

enum vm_type {
    /* page not initialized */
    VM_UNINIT = 0,
    /* page not related to the file, aka anonymous page */
    VM_ANON = 1,
    /* page that realated to the file */
    VM_FILE = 2,
    /* page that hold the page cache, for project 4 */
    VM_PAGE_CACHE = 3,

    /* Bit flags to store state */

    /* Auxillary bit flag marker for store information. You can add more
     * markers, until the value is fit in the int. */
    VM_MARKER_0 = (1 << 3),  // STACK MARKER
    VM_MARKER_1 = (1 << 4),

    /* DO NOT EXCEED THIS VALUE. */
    VM_MARKER_END = (1 << 31),
};

#include "vm/anon.h"
#include "vm/file.h"
#include "vm/uninit.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

#define STACK_LIMIT (USER_STACK - (1 << 20))  // 1MB 제한

/* "페이지"의 표현.
 * 이것은 일종의 "상위 클래스"로서, uninit_page, file_page, anon_page, page_cache(project4)라는 4개의 "하위 클래스"를 가지고 있습니다..
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page {
    const struct page_operations *operations;
    void *va;            /* Address in terms of user space */
    struct frame *frame; /* Back reference for frame */

    /** Project 3: Memory Management - Your implementation */
    struct hash_elem hash_elem;
    bool writable;
    bool accessible; /** Project 3: Copy On Write (Extra) */

    /* Per-type data are binded into the union.
     * Each function automatically detects the current union */
    union {
        struct uninit_page uninit;
        struct anon_page anon;
        struct file_page file;
#ifdef EFILESYS
        struct page_cache page_cache;
#endif
    };
};

/* The representation of "frame" */
struct frame {
    void *kva;
    struct page *page;

    /** Project 3: Memory Management - 리스트 객체 추가  */
    struct list_elem frame_elem;
};

/* 페이지 작업을 위한 함수 테이블입니다.
 * 이는 C에서 "인터페이스"를 구현하는 한 가지 방법입니다.
 * "method" 테이블을 구조체 멤버에 넣고 필요할 때마다 호출하세요. */
struct page_operations {
    bool (*swap_in)(struct page *, void *);
    bool (*swap_out)(struct page *);
    void (*destroy)(struct page *);
    enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in((page), v)
#define swap_out(page)   (page)->operations->swap_out(page)
#define destroy(page)                \
    if ((page)->operations->destroy) \
    (page)->operations->destroy(page)

/* 현재 프로세스의 메모리 공간을 나타냅니다.
 * 우리는 이 구조체에 대한 특정 디자인을 따르도록 강요하고 싶지 않습니다.
 * 모든 디자인은 귀하에게 달려 있습니다. */

struct supplemental_page_table {
    struct hash spt_hash; /** Project 3: Memory Management - 해시 테이블 사용 */
};

#include "threads/thread.h"
void supplemental_page_table_init(struct supplemental_page_table *spt);
bool supplemental_page_table_copy(struct supplemental_page_table *dst, struct supplemental_page_table *src);
void supplemental_page_table_kill(struct supplemental_page_table *spt);
struct page *spt_find_page(struct supplemental_page_table *spt, void *va);
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page);
void spt_remove_page(struct supplemental_page_table *spt, struct page *page);

void vm_init(void);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) vm_alloc_page_with_initializer((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page(struct page *page);
bool vm_claim_page(void *va);
enum vm_type page_get_type(struct page *page);

bool vm_handle_wp(struct page *page UNUSED);

#endif /* VM_VM_H */
