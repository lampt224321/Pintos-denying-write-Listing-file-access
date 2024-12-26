#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"

/** Project 3: Swap In/Out */
#include "threads/vaddr.h"

struct page;
enum vm_type;

/** Project 3: Swap In/Out - 한 페이지를 섹터 단위로 관리 */
#define SLOT_SIZE (PGSIZE / DISK_SECTOR_SIZE)

/** Project 3: Swap In/Out - Sector Indexing용 Page 구조체 선언 */
struct anon_page {
    size_t slot;
};

void vm_anon_init(void);
bool anon_initializer(struct page *page, enum vm_type type, void *kva);

#endif
