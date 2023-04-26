// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_SCI_H
#define _ASM_X86_SCI_H

#ifdef CONFIG_SYSCALL_ISOLATION

struct sci_task_data {
	pgd_t		*pgd;
	unsigned long	cr3_offset;
	unsigned long	backtrace_size;
	unsigned long	*backtrace;
	unsigned long	ptes_count;
	pte_t		**ptes;
};

struct sci_percpu_data {
	unsigned long		sci_syscall;
	unsigned long		sci_cr3_offset;
};

DECLARE_PER_CPU_PAGE_ALIGNED(struct sci_percpu_data, cpu_sci);

void sci_check_boottime_disable(void);

int sci_init(struct task_struct *tsk);
void sci_exit(struct task_struct *tsk);

bool sci_verify_and_map(struct pt_regs *regs, unsigned long addr,
			unsigned long hw_error_code);
void sci_clear_data(void);

static inline void sci_switch_to(struct task_struct *next)
{
	this_cpu_write(cpu_sci.sci_syscall, next->in_isolated_syscall);
	if (next->sci)
		this_cpu_write(cpu_sci.sci_cr3_offset, next->sci->cr3_offset);
}

#else /* CONFIG_SYSCALL_ISOLATION */

static inline void sci_check_boottime_disable(void) {}

static inline bool sci_verify_and_map(struct pt_regs *regs,unsigned long addr,
				      unsigned long hw_error_code)
{
	return true;
}

static inline void sci_clear_data(void) {}

static inline void sci_switch_to(struct task_struct *next) {}

#endif /* CONFIG_SYSCALL_ISOLATION */

#endif /* _ASM_X86_SCI_H */
