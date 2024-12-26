/* vm.c: Generic interface for virtual memory objects. */
#include "vm/vm.h"

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/inspect.h"

static struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
    list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/** Project 3: Anonymous Page - 이니셜라이저를 사용하여 보류 중인 페이지 개체를 만듭니다.
 *  페이지를 만들고 싶다면 직접 만들지 말고 이 함수나 `vm_alloc_page`를 통해 만들어주세요. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        struct page *page = (struct page *)malloc(sizeof(struct page));

        typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
        initializerFunc initializer = NULL;

        switch (VM_TYPE(type)) {
            case VM_ANON:
                initializer = anon_initializer;
                break;
            case VM_FILE:
                initializer = file_backed_initializer;
                break;
        }

        uninit_new(page, upage, init, type, aux, initializer);

        page->writable = writable;

        /* TODO: Insert the page into the spt. */
        return spt_insert_page(spt, page);
    }
err:
    return false;
}

/** Project 3: Memory Management - spt에서 va를 찾아 페이지를 리턴합니다. 오류가 발생하면 NULL을 반환합니다. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    /* TODO: Fill this function. */
    struct page *page = (struct page *)malloc(sizeof(struct page));     // 가상 주소에 대응하는 해시 값 도출을 위해 새로운 페이지 할당
    page->va = pg_round_down(va);                                       // 가상 주소의 시작 주소를 페이지의 va에 복제
    struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);  // spt hash 테이블에서 hash_elem과 같은 hash를 갖는 페이지를 찾아서 return
    free(page);                                                         // 복제한 페이지 삭제

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/** Project 3: Memory Management - 검증을 통해 spt에 PAGE를 삽입합니다. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    /* TODO: Fill this function. */
    return hash_insert(&spt->spt_hash, &page->hash_elem) ? false : true;  // 존재하지 않으면 삽입
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    hash_delete(&thread_current()->spt.spt_hash, &page->hash_elem);
    vm_dealloc_page(page);
    return true;
}

/** Project 3: Memory Management - 제거될 구조체 프레임을 가져옵니다. */
static struct frame *vm_get_victim(void) {
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */
    struct thread *curr = thread_current();

    // Second Chance 방식으로 결정
    struct list_elem *e = list_begin(&frame_table);
    for (e; e != list_end(&frame_table); e = list_next(e)) {
        victim = list_entry(e, struct frame, frame_elem);
        if (pml4_is_accessed(curr->pml4, victim->page->va))
            pml4_set_accessed(curr->pml4, victim->page->va, false);  // pml4가 최근에 사용됐다면 기회를 한번 더 준다.
        else
            return victim;
    }

    return list_entry(list_begin(&frame_table), struct frame, frame_elem);
}

/** Project 3: Memory Management - 한 페이지를 제거하고 해당 프레임을 반환합니다. 오류가 발생하면 NULL을 반환합니다.*/
static struct frame *vm_evict_frame(void) {
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */
    if (victim->page)
        swap_out(victim->page);

    return victim;
}

/** Project 3: Memory Management - palloc()을 실행하고 프레임을 가져옵니다. 사용 가능한 페이지가 없으면 해당 페이지를 제거하고 반환합니다.
 *  이는 항상 유효한 주소를 반환합니다. 즉, 사용자 풀 메모리가 가득 찬 경우 이 함수는 사용 가능한 메모리 공간을 확보하기 위해 프레임을 제거합니다.*/
static struct frame *vm_get_frame(void) {
    /* TODO: Fill this function. */
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    ASSERT(frame != NULL);

    frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);  // 유저 풀(실제 메모리)에서 페이지를 할당 받는다.

    if (frame->kva == NULL)
        frame = vm_evict_frame();  // Swap Out 수행
    else
        list_push_back(&frame_table, &frame->frame_elem);  // frame table에 추가

    frame->page = NULL;
    ASSERT(frame->page == NULL);

    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {
    bool success = false;
    if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true)) {
        success = vm_claim_page(addr);

        if (success) {
            /* stack bottom size 갱신 */
            thread_current()->stack_bottom -= PGSIZE;
        }
    }
}

/** Project 3: Copy On Write (Extra) - Handle the fault on write_protected page */
bool vm_handle_wp(struct page *page UNUSED) {
    if (!page->accessible)
        return false;

    void *kva = page->frame->kva;

    page->frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

    if (page->frame->kva == NULL)
        page->frame = vm_evict_frame();  // Swap Out 수행

    memcpy(page->frame->kva, kva, PGSIZE);

    if (!pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->accessible))
        return false;

    return true;
}

/** Project 3: Memory Management - Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = spt_find_page(&thread_current()->spt, addr);

    /* TODO: Validate the fault */
    if (addr == NULL || is_kernel_vaddr(addr))
        return false;

    /** Project 3: Copy On Write (Extra) - 접근한 메모리의 page가 존재하고 write 요청인데 write protected인 경우라 발생한 fault일 경우*/
    if (!not_present && write)
        return vm_handle_wp(page);

    /** Project 3: Copy On Write (Extra) - 이전에 만들었던 페이지인데 swap out되어서 현재 spt에서 삭제하였을 때 stack_growth 대신 claim_page를 하기 위해 조건 분기 */
    if (!page) {
        /** Project 3: Stack Growth - stack growth로 처리할 수 있는 경우 */
        /* stack pointer 아래 8바이트는 페이지 폴트 발생 & addr 위치를 USER_STACK에서 1MB로 제한 */
        void *stack_pointer = user ? f->rsp : thread_current()->stack_pointer;
        if (stack_pointer - 8 <= addr && addr >= STACK_LIMIT && addr <= USER_STACK) {
            vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
            return true;
        }
        return false;
    }

    return vm_do_claim_page(page);  // demand page 수행
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/** Project 3: Copy On Write (Extra) - VA에 할당된 페이지를 복제. */
static bool vm_copy_claim_page(struct supplemental_page_table *dst, void *va, void *kva, bool writable) {
    struct page *page = spt_find_page(dst, va);

    if (page == NULL)
        return false;

    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));

    if (!frame)
        return false;

    /* Set links */
    page->accessible = writable;  // 접근 권한 설정
    frame->page = page;
    page->frame = frame;
    frame->kva = kva;

    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, false)) {
        free(frame);
        return false;
    }

    list_push_back(&frame_table, &frame->frame_elem);  // frame table에 추가

    return swap_in(page, frame->kva);
}

/** Project 3: Memory Management - VA에 할당된 페이지를 요청하세요. */
bool vm_claim_page(void *va UNUSED) {
    /* TODO: Fill this function */
    struct page *page = spt_find_page(&thread_current()->spt, va);

    if (page == NULL)
        return false;

    return vm_do_claim_page(page);
}

/** Project 3: Memory Management - PAGE를 요청하고 mmu를 설정하십시오. */
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
        return false;

    return swap_in(page, frame->kva);  // uninit_initialize
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    hash_init(&spt->spt_hash, hash_func, less_func, NULL);
}

/** Project 3: Anonymous Page - Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {
    struct hash_iterator iter;
    struct page *dst_page;
    struct aux *aux;

    hash_first(&iter, &src->spt_hash);

    while (hash_next(&iter)) {
        struct page *src_page = hash_entry(hash_cur(&iter), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        switch (type) {
            case VM_UNINIT:  // src 타입이 initialize 되지 않았을 경우
                if (!vm_alloc_page_with_initializer(page_get_type(src_page), upage, writable, src_page->uninit.init, src_page->uninit.aux))
                    goto err;
                break;

            case VM_FILE:  // src 타입이 FILE인 경우
                if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, &src_page->file))
                    goto err;

                dst_page = spt_find_page(dst, upage);  // 대응하는 물리 메모리 데이터 복제
                if (!file_backed_initializer(dst_page, type, NULL))
                    goto err;

                dst_page->frame = src_page->frame;
                if (!pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, src_page->writable))
                    goto err;

                break;

            case VM_ANON:                                   // src 타입이 anon인 경우
                if (!vm_alloc_page(type, upage, writable))  // UNINIT 페이지 생성 및 초기화
                    goto err;

                // if (!vm_claim_page(upage))  // 물리 메모리와 매핑하고 initialize
                //     goto err;

                // struct page *dst_page = spt_find_page(dst, upage);  // 대응하는 물리 메모리 데이터 복제
                // memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);

                /** Project 3: Copy On Write (Extra) - 메모리에 load된 데이터를 write하지 않는 이상 똑같은 메모리를 사용하는데
                 *  2개의 복사본을 만드는 것은 메모리가 낭비가 난다. 따라서 write 요청이 들어왔을 때만 해당 페이지에 대한 물리메모리를
                 *  할당하고 맵핑하면 된다. */
                if (!vm_copy_claim_page(dst, upage, src_page->frame->kva, writable))  // 물리 메모리와 매핑하고 initialize
                    goto err;

                break;

            default:
                goto err;
        }
    }

    return true;

err:
    return false;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    hash_clear(&spt->spt_hash, hash_destructor);  // 해시 테이블의 모든 요소 제거
}