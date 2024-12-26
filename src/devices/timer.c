#include "devices/timer.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>

#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops(unsigned loops);
static void busy_wait(int64_t loops);
static void real_time_sleep(int64_t num, int32_t denom);

/* 초당 100 회 인터럽트하도록 8254 Programmable Interval Timer (PIT) 설정 및 인터럽트 등록 */
void timer_init(void) {
    /* 8254 입력 주파수를 TIMER_FREQ로 나눠서 가장 가까운 값으로 반올림
       PC가 1초에 1193180 Hz의 클럭 신호를 발생시키기 때문에 1초에 100번 인터럽트를 발생시키게 하기 위한 값 */
    uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;  //
    outb(0x43, 0x34);                                          /* CW: counter 0(00), LSB then MSB(11), mode 2(010), binary(0). */
    outb(0x40, count & 0xff);                                  // 하위 8 Bit 체크 ** 8bit bus로 연결되어 있음
    outb(0x40, count >> 8);                                    // 상위 8 Bit 체크

    intr_register_ext(0x20, timer_interrupt, "8254 Timer");  // 외부 인터럽트 핸들러를 호출하기 위한 VEC Number 등록
}

/* Pintos 구동 사양에 맞게 loops_per_tick 보정 */
void timer_calibrate(void) {
    unsigned high_bit, test_bit;

    ASSERT(intr_get_level() == INTR_ON);
    printf("Calibrating timer...  ");

    /* 1024부터 근사한 2의 거듭제곱으로 loops_per_tick 상승 */
    loops_per_tick = 1u << 10;
    while (!too_many_loops(loops_per_tick << 1)) {
        loops_per_tick <<= 1;
        ASSERT(loops_per_tick != 0);
    }

    /* loops_per_tick의 다음 8 bit 다듬기 */
    high_bit = loops_per_tick;
    for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
        if (!too_many_loops(high_bit | test_bit))
            loops_per_tick |= test_bit;

    printf("%'" PRIu64 " loops/s.\n", (uint64_t)loops_per_tick * TIMER_FREQ);
}

/* OS 부팅 이후 타이머 틱 수 반환 */
int64_t timer_ticks(void) {
    enum intr_level old_level = intr_disable();
    int64_t t = ticks;
    intr_set_level(old_level);
    barrier();
    return t;
}

/* then 이후 경과된 타이머 틱 수 반환 (should returned by timer_ticks()) */
int64_t timer_elapsed(int64_t then) {
    return timer_ticks() - then;
}

/* 대략 ticks 동안 타이머 틱 일시정지 */
void timer_sleep(int64_t ticks) {
    int64_t start = timer_ticks();

    ASSERT(intr_get_level() == INTR_ON);

    /** #Alarm Clock start + ticks 동안 쓰레드 sleep  */
    thread_sleep(start + ticks);

    // while (timer_elapsed(start) < ticks) {
    //     thread_yield();  // 쓰레드 인계
    // }
}

/* 대략 MS miliseconds동안 일시정지 */
void timer_msleep(int64_t ms) {
    real_time_sleep(ms, 1000);
}

/* 대략 US microseconds동안 일시정지 */
void timer_usleep(int64_t us) {
    real_time_sleep(us, 1000 * 1000);
}

/* 대략 NS nanoseconds동안 일시정지 */
void timer_nsleep(int64_t ns) {
    real_time_sleep(ns, 1000 * 1000 * 1000);
}

/* 타이머 상태 출력 */
void timer_print_stats(void) {
    printf("Timer: %" PRId64 " ticks\n", timer_ticks());
}

/* 타이머 인터럽트 핸들러 */
static void timer_interrupt(struct intr_frame *args UNUSED) {
    ticks++;
    thread_tick();

    /** #Advanced Scheduler mlfqs 스케줄러의 경우 */
    if (thread_mlfqs) {
        mlfqs_increment();

        if (!(ticks % 4)) {
            mlfqs_recalc_priority();

            if (!(ticks % TIMER_FREQ)) {
                mlfqs_load_avg();
                mlfqs_recalc_recent_cpu();
            }
        }
    }

    /** #Alarm Clock 현재 활성화되어야 하는 thread가 있는지 탐색하여 활성화 */
    if (get_next_tick_to_awake() <= ticks)
        thread_awake(ticks);
}

/* loop가 1개 초과시 true 반환 */
static bool too_many_loops(unsigned loops) {
    /* Wait for a timer tick. */
    int64_t start = ticks;
    while (ticks == start)
        barrier();

    /* Run LOOPS loops. */
    start = ticks;
    busy_wait(loops);

    /* If the tick count changed, we iterated too long. */
    barrier();
    return start != ticks;
}

/* 짧은 지연을 구현하기 위해 간단한 루프 LOOPS 회 반복

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE busy_wait(int64_t loops) {
    while (loops-- > 0)
        barrier();
}

/* 대략 NUM/DENOM seconds 동안 sleep */
static void real_time_sleep(int64_t num, int32_t denom) {
    /* NUM/DENOM seconds를 내림하여 timer ticks로 변환

           (NUM / DENOM) s
       ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
       1 s / TIMER_FREQ ticks
       */
    int64_t ticks = num * TIMER_FREQ / denom;

    ASSERT(intr_get_level() == INTR_ON);
    if (ticks > 0) {
        /* We're waiting for at least one full timer tick.  Use
           timer_sleep() because it will yield the CPU to other
           processes. */
        timer_sleep(ticks);
    } else {
        /* Otherwise, use a busy-wait loop for more accurate
           sub-tick timing.  We scale the numerator and denominator
           down by 1000 to avoid the possibility of overflow. */
        ASSERT(denom % 1000 == 0);
        busy_wait(loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
    }
}
