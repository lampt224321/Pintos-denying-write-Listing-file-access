#ifndef THREADS_INTERRUPT_H
#define THREADS_INTERRUPT_H

#include <stdbool.h>
#include <stdint.h>

/* Interrupts on or off? */
enum intr_level {
    INTR_OFF, /* Interrupts disabled. */
    INTR_ON   /* Interrupts enabled. */
};

enum intr_level intr_get_level(void);
enum intr_level intr_set_level(enum intr_level);
enum intr_level intr_enable(void);
enum intr_level intr_disable(void);

/* Interrupt stack frame. */
struct gp_registers {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;

    /* 인덱스 레지스터 */
    uint64_t rsi;  // Source Index - 출발지 주소 저장
    uint64_t rdi;  // Destination Index - 목적지 주소 저장

    /* 포인터 레지스터 */
    uint64_t rbp;  // Base Pointer - Stack Pointer의 바닥 주소

    /* 범용 레지스터 */
    uint64_t rdx;  // Data Register - rax를 보조하는 역할 및 나누기 연산시 나머지 저장
    uint64_t rcx;  // Counter Register - Count 역할 수행
    uint64_t rbx;  // Base Register - 주소 지정에 사용 및 산수 변수 저장
    uint64_t rax;  // Accumulator - 산술 연산 및 함수 반환값 처리
} __attribute__((packed));

struct intr_frame {
    /* intr-stubs.S의 intr_entry에 의해 푸시됨.
       중단된 작업의 저장된 레지스터입니다. */
    struct gp_registers R;  // 정수 레지스터 구간
    uint16_t es;            // Extra Segment - Extra Data 영역
    uint16_t __pad1;
    uint32_t __pad2;
    uint16_t ds;  // Data Segment - 데이터 영역
    uint16_t __pad3;
    uint32_t __pad4;
    /* intr-stubs.S의 intrNN_stub에 의해 푸시됨. */
    uint64_t vec_no; /* Interrupt vector number. */
                     /* 때로는 CPU에 의해 푸시되고, 그렇지 않으면 일관성을 위해 intrNN_stub에 의해 0으로 푸시됩니다.
                        CPU는 이를 'EIP' (Extended) Instruction Pointer 바로 아래에 두지만 우리는 여기로 옮깁니다. */
    uint64_t error_code;
    /* CPU에 의해 푸시됨.
       중단된 작업의 저장된 레지스터입니다.. */
    uintptr_t rip;  // Instruction Pointer = Program Counter 다음에 실행될 명령의 주소
    uint16_t cs;    // Code Segment - 명령어 영역
    uint16_t __pad5;
    uint32_t __pad6;
    uint64_t eflags;  // Extended Flags - 상태, 제어, 시스템 플래그 -> 레지스터가 어떤 일을 수행하는 지
    uintptr_t rsp;    // Stack Pointer - 스택 포인터
    uint16_t ss;      // Stack Segment - 임시 Stack 영역
    uint16_t __pad7;
    uint32_t __pad8;
} __attribute__((packed));

typedef void intr_handler_func(struct intr_frame *);

void intr_init(void);
void intr_register_ext(uint8_t vec, intr_handler_func *, const char *name);
void intr_register_int(uint8_t vec, int dpl, enum intr_level, intr_handler_func *, const char *name);
bool intr_context(void);
void intr_yield_on_return(void);

void intr_dump_frame(const struct intr_frame *);
const char *intr_name(uint8_t vec);

#endif /* threads/interrupt.h */
