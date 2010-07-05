#ifndef _ASM_X86_SPINLOCK_TYPES_H
#define _ASM_X86_SPINLOCK_TYPES_H

#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif

#if (NR_CPUS < 256)
typedef u8  __ticket_t;
#else
typedef u16 __ticket_t;
#endif

#define TICKET_SHIFT	(sizeof(__ticket_t) * 8)
#define TICKET_MASK	((1 << TICKET_SHIFT) - 1)

typedef struct raw_spinlock {
	union {
		unsigned int slock;
		struct __raw_tickets {
			__ticket_t head, tail;
		} tickets;
	};
#ifdef CONFIG_PARAVIRT_SPINLOCKS
	__ticket_t waiting;
#endif
} raw_spinlock_t;

#define __RAW_SPIN_LOCK_UNLOCKED	{ { .slock = 0 } }

typedef struct {
	unsigned int lock;
} raw_rwlock_t;

#define __RAW_RW_LOCK_UNLOCKED		{ RW_LOCK_BIAS }

#endif /* _ASM_X86_SPINLOCK_TYPES_H */
