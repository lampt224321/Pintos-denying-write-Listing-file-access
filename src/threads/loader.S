/* 이 파일은 MIT의 6.828 과정에서 사용된 소스 코드에서 파생되었습니다. 원본 저작권
   표시는 아래에 전체 내용이 나와 있습니다. */

/*
 * Copyright (C) 1997 Massachusetts Institute of Technology 
 *
 * 이 소프트웨어는 다음 라이센스에 따라 저작권 소유자에 의해 제공됩니다. 이 소프트
 * 웨어를 획득, 사용 및/또는 복사함으로써 귀하는 다음 이용 약관을 읽고 이해했으며
 * 준수할 것에 동의합니다.
 *
 * 이 고지 사항의 전체 텍스트가 당신이 수정한 사항을 포함하여 소프트웨어 및 문서의
 * 모든 사본 또는 그 일부에 표시되는 경우 본 소프트웨어 및 해당 문서를 어떤 목적으
 * 로든 수수료나 로열티 없이 사용, 복사, 수정, 배포 및 판매할 수 있는 권한이 부여
 * 됩니다.
 *
 * 이 소프트웨어는 "있는 그대로" 제공되며 저작권 보유자는 명시적이든 묵시적이든 어
 * 떠한 진술이나 보증도 하지 않습니다. 예를 들어(단, 이에 국한되지는 않음) 저작권
 * 보유자는 특정 목적에 대한 상품성이나 적합성에 대한 진술이나 보증을 하지 않으며,
 * 소프트웨어나 문서의 사용이 제3자의 특허, 저작권, 상표 또는 기타 권리를 침해하지
 * 않습니다. 저작권 보유자는 이 소프트웨어 문서의 사용에 대해 어떠한 책임도 지지
 * 않습니다.
 *
 * 저작권 소유자의 이름과 상표는 구체적인 사전 서면 허가 없이 소프트웨어와 관련된
 * 광고 또는 홍보에 사용할 수 없습니다. 이 소프트웨어 및 관련 문서의 저작권에 대한
 * 소유권은 항상 저작권 소유자에게 있습니다. 모든 저작권 소유자 목록을 보려면 이
 * 소프트웨어와 함께 제공된 AUTHORS 파일을 참조하십시오.
 *
 * 이 파일은 이전에 저작권이 있는 소프트웨어에서 파생되었을 수 있습니다. 이 저작권
 * 은 AUTHORS 파일에 나열된 저작권 보유자가 변경한 경우에만 적용됩니다. 이 파일의
 * 나머지 부분에는 아래 나열된 저작권 표시가 적용됩니다.
 */

#include "threads/loader.h"
	
#### 커널 로더.

#### 이 코드는 하드 디스크의 첫 번째 섹터에 저장되어야 합니다. BIOS가 실행되면 물
#### 리적 주소 0x7c00-0x7e00(512바이트)에 이 코드가 로드됩니다. 그런 다음 리얼 
#### 모드에서는 시작 부분으로 이동합니다. 이 코드는 모든 메모리에 액세스할 수 있도
#### 록 보호 모드(32비트 모드)로 전환하고 커널을 메모리에 로드한 다음 start.S가 
#### 연결된 커널의 첫 번째 바이트로 점프합니다.
	
/* Flags in control register 0. */
#define CR0_PE 0x00000001      /* Protection Enable. */
#define CR0_EM 0x00000004      /* (Floating-point) Emulation. */
#define CR0_PG 0x80000000      /* Paging. */
#define CR0_WP 0x00010000      /* Write-Protect enable in kernel mode. */


.globl start
start:
	
# 코드는 16비트 세그먼트인 리얼 모드에서 실행됩니다.
	.code16

# 인터럽트를 처리할 준비가 되어 있지 않으므로 인터럽트를 비활성화합니다.
# 훨씬 나중에 보호 모드로 유지됩니다.
# 문자열 명령은 위쪽으로 이동합니다(예: 아래의 "rep Stosl").

	cli
	cld

# 데이터 세그먼트를 설정합니다.

	subw %ax, %ax
	movw %ax, %es
	movw %ax, %ds

# 스택 세그먼트를 설정합니다.
# 스택은 우리부터 시작하여 아래쪽으로 성장합니다.
# 우리는 스택을 사용하지 않지만 BIOS는 작동할 수 있으므로 호출합니다.

	movw %ax, %ss
	movw $0x7c00, %sp
	
#### A20을 ​​활성화합니다. 주소 라인 20은 머신이 부팅될 때 low에 연결되어 약 1MB의
#### 메모리 주소 지정을 방지합니다. 이 코드로 수정됩니다.
	
# 바쁜 동안 폴링 상태 등록.

1:	inb $0x64, %al
	testb $0x2, %al
	jnz 1b

# 출력 포트 쓰기 명령을 보냅니다.

	movb $0xd1, %al
	outb %al, $0x64

# 바쁜 동안 폴링 상태 등록.

1:	inb $0x64, %al
	testb $0x2, %al
	jnz 1b

# A20 라인을 활성화합니다.

	movb $0xdf, %al
	outb %al, $0x60

#### 인터럽트 15h 기능 e820h를 통해 메모리 크기를 가져옵니다. 이제 우리 핀토스는 
#### x86_64에서 실행됩니다. "확장 메모리 크기 가져오기" 작업은 우리 목적에 충분하지
#### 않습니다.

	mov $0xe820, %eax  # command
	mov $(E820_MAP4), %edi  # dst
	xor %ebx, %ebx
	mov $0x534d4150, %edx # magic
	mov $24, %ecx
	int $0x15
	cmp %eax, %edx
	test %ebx, %ebx
	je panic
	mov $24, %ebp

parse_e820:
	mov %ecx, -4(%edi)
	add $24, %edi
	mov $0xe820, %eax
	mov $24, %ecx
	int $0x15
	jc e820_parse_done
	add $24, %ebp
	test %ebx, %ebx
	jne parse_e820

e820_parse_done:
	mov %ecx, -4(%edi)
	movl $0x40, MULTIBOOT_FLAG
	movl %ebp, MULTIBOOT_MMAP_LEN
	movl $(E820_MAP), MULTIBOOT_MMAP_ADDR # e820

#### 보호 모드로 전환합니다.

# 인터럽트는 여전히 꺼져 있다는 것에 주의하세요.

# GDTR을 우리의 GDT로 지정하세요. 보호 모드에는 GDT가 필요합니다.
# GDT 설명자의 32비트가 모두 로드되도록 하려면 data32 접두사가 필요합니다(기본값은
# 24비트만 로드하는 것입니다).

	data32 lgdt gdtdesc

# 그런 다음 CR0에서 다음 비트를 켭니다.
#    PE (Protect Enable): 그러면 보호 모드가 켜집니다.
#    PG (Paging): 페이징을 켭니다.
#    WP (Write Protect): 설정되지 않은 경우 0 code ignores 경고가 울립니다
#       페이지 테이블의 쓰기 방지 비트(!)
#    EM (Emulation): 부동 소수점 명령어를 강제로 트랩합니다.
#       우리는 부동 소수점을 지원하지 않습니다.
	
	movl %cr0, %eax
	orl $CR0_PE, %eax
	movl %eax, %cr0
	
# 이제 16비트 세그먼트에서는 보호 모드에 있습니다. CPU에는 여전히 %cs의 세그먼트 
# 설명자에 캐시된 리얼 모드 코드 세그먼트가 있습니다. %cs를 다시 로드해야 하며 가장
# 쉬운 방법은 멀리 점프를 사용하는 것입니다.
# 32비트 세그먼트에 있지 않기 때문에 32비트 오프셋으로 점프하려면 data32 접두사가 
# 필요합니다.

	data32 ljmp $SEL_KCSEG, $protcseg

# 이제 32비트 세그먼트의 보호 모드에 있습니다.

	.code32

# 다른 모든 세그먼트 레지스터와 스택 포인터를 다시 로드하여 새 GDT를 가리킵니다.

protcseg:
	movw $SEL_KDSEG, %ax
	movw %ax, %ds		
	movw %ax, %es		
	movw %ax, %fs		
	movw %ax, %gs		
	movw %ax, %ss
	movl $LOADER_PHYS_BASE + 0x30000, %esp

#### IDE 컨트롤러를 직접 프로빙하여 물리적 주소 LOADER_PHYS_BASE에서 시작하여 커널
#### 을 로드합니다.

	movl $1, %ebx
	movl $LOADER_PHYS_BASE, %edi

# 데이터를 폴링할 예정이므로 IDE 컨트롤러에 의한 인터럽트 전달을 비활성화합니다.
# (이렇게 하지 않으면 부팅 중에 인터럽트 컨트롤러를 재설정한 후 Bochs 2.2.6에서 IDE
# 컨트롤러도 재설정하더라도 나중에 우리에게 IDE 인터럽트를 전달하지 않습니다.)

	movw $0x3f6, %dx
	movb $0x02, %al
	outb %al, %dx
	
read_sector:

# 컨트롤러가 사용 중인 동안 상태 레지스터를 폴링합니다.

	movl $0x1f7, %edx
1:	inb %dx, %al
	testb $0x80, %al
	jnz 1b

# 단일 섹터를 읽습니다.

	movl $0x1f2, %edx
	movb $1, %al
	outb %al, %dx

# 하위 28비트에 쓸 섹터 번호입니다.
# LBA mode, device 0 in top 4 bits.

	movl %ebx, %eax
	andl $0x0fffffff, %eax
	orl $0xe0000000, %eax

# %eax를 포트 0x1f3...0x1f6에 덤프합니다.

	movl $4, %ecx
1:	incw %dx
	outb %al, %dx
	shrl $8, %eax
	loop 1b

# 명령 레지스터에 대한 READ 명령입니다.

	incw %dx
	movb $0x20, %al
	outb %al, %dx

# 컨트롤러가 사용 중인 동안 상태 레지스터를 폴링합니다.

1:	inb %dx, %al
	testb $0x80, %al
	jnz 1b

# 데이터가 준비될 때까지 상태 레지스터를 폴링합니다.

1:	inb %dx, %al
	testb $0x08, %al
	jz 1b

# 전송 섹터.

	movl $256, %ecx
	movl $0x1f0, %edx
	rep insw

# 다음 섹터.

	incl %ebx
	cmpl $KERNEL_LOAD_PAGES*8 + 1, %ebx
	jnz read_sector

#### 커널 진입점으로 점프합니다.
	movl $LOADER_PHYS_BASE, %eax
	call *%eax
	jmp panic

#### GDT

gdt:
	.quad 0x0000000000000000	# null seg
	.quad 0x00cf9a000000ffff	# code seg
	.quad 0x00cf92000000ffff  # data seg
	
gdtdesc:
	.word	0x17			# sizeof (gdt) - 1
	.long	gdt

#### Fatal error.
#### Print panic_message (with help from the BIOS) and spin.

panic:  .code16			# We only panic in real mode.
	movw $panic_message, %si
	movb $0xe, %ah
	subb %bh, %bh
1:	lodsb
	test %al, %al
2:	jz 2b			# Spin.
	int $0x10
	jmp 1b

panic_message:
	.ascii "Panic!"
	.byte 0

#### 명령줄 인수 및 해당 개수.
#### 이것은 `pintos' 유틸리티에 의해 작성되고 커널에 의해 읽혀집니다.
#### 로더 자체는 명령줄에서 아무 작업도 수행하지 않습니다.
	.org LOADER_ARG_CNT - LOADER_BASE
arg_cnt:
	.long 0
	.org LOADER_ARGS - LOADER_BASE
args:
	.fill 0x80, 1, 0

#### 부트 섹터 서명.
#### BIOS는 이것이 올바르게 설정되었는지 확인합니다.
	.org LOADER_SIG - LOADER_BASE
	.word 0xaa55
