// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2019 IBM Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Author: Mike Rapoport <rppt@linux.ibm.com>
 *
 * This code is based on pti.c, see it for the original copyrights
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/sizes.h>
#include <linux/sci.h>
#include <linux/random.h>

#include <asm/cpufeature.h>
#include <asm/hypervisor.h>
#include <asm/cmdline.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/sections.h>
#include <asm/traps.h>

#undef pr_fmt
#define pr_fmt(fmt)     "SCI: " fmt

#define SCI_MAX_PTES 256
#define SCI_MAX_BACKTRACE 64

__visible DEFINE_PER_CPU_PAGE_ALIGNED(struct sci_percpu_data, cpu_sci);

/*
 * Walk the shadow copy of the page tables to PMD level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Allocation failures are not handled here because the entire page
 * table will be freed in sci_free_pagetable.
 *
 * Returns a pointer to a PMD on success, or NULL on failure.
 */
static pmd_t *sci_pagetable_walk_pmd(struct mm_struct *mm,
				     pgd_t *pgd, unsigned long address)
{
	p4d_t *p4d;
	pud_t *pud;

	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return NULL;

	pud = pud_alloc(mm, p4d, address);
	if (!pud)
		return NULL;

	return pmd_alloc(mm, pud, address);
}

/*
 * Walk the shadow copy of the page tables to PTE level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Returns a pointer to a PTE on success, or NULL on failure.
 */
static pte_t *sci_pagetable_walk_pte(struct mm_struct *mm,
				     pgd_t *pgd, unsigned long address)
{
	pmd_t *pmd = sci_pagetable_walk_pmd(mm, pgd, address);

	if (!pmd)
		return NULL;

	if (__pte_alloc(mm, pmd))
		return NULL;

	return pte_offset_kernel(pmd, address);
}

/*
 * Clone a single page mapping
 *
 * The new mapping in the @target_pgdp is always created for base
 * page. If the orinal page table has the page at @addr mapped at PMD
 * level, we anyway create at PTE in the target page table and map
 * only PAGE_SIZE.
 */
static pte_t *sci_clone_page(struct mm_struct *mm,
			     pgd_t *pgdp, pgd_t *target_pgdp,
			     unsigned long addr)
{
	pte_t *pte, *target_pte, ptev;
	pgd_t *pgd, *target_pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset_pgd(pgdp, addr);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	target_pgd = pgd_offset_pgd(target_pgdp, addr);

	if (pmd_large(*pmd)) {
		pgprot_t flags;
		unsigned long pfn;

		/*
		 * We map only PAGE_SIZE rather than the entire huge page.
		 * The PTE will have the same pgprot bits as the origial PMD
		 */
		flags = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		pfn = pmd_pfn(*pmd) + pte_index(addr);
		ptev = pfn_pte(pfn, flags);
	} else {
		pte = pte_offset_kernel(pmd, addr);
		if (pte_none(*pte) || !(pte_flags(*pte) & _PAGE_PRESENT))
			return NULL;

		ptev = *pte;
	}

	target_pte = sci_pagetable_walk_pte(mm, target_pgd, addr);
	if (!target_pte)
		return NULL;

	*target_pte = ptev;

	return target_pte;
}

/*
 * Clone a range keeping the same leaf mappings
 *
 * If the range has holes they are simply skipped
 */
static int sci_clone_range(struct mm_struct *mm,
			   pgd_t *pgdp, pgd_t *target_pgdp,
			   unsigned long start, unsigned long end)
{
	unsigned long addr;

	/*
	 * Clone the populated PMDs which cover start to end. These PMD areas
	 * can have holes.
	 */
	for (addr = start; addr < end;) {
		pte_t *pte, *target_pte;
		pgd_t *pgd, *target_pgd;
		pmd_t *pmd, *target_pmd;
		p4d_t *p4d;
		pud_t *pud;

		/* Overflow check */
		if (addr < start)
			break;

		pgd = pgd_offset_pgd(pgdp, addr);
		if (pgd_none(*pgd))
			return 0;

		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d))
			return 0;

		pud = pud_offset(p4d, addr);
		if (pud_none(*pud)) {
			addr += PUD_SIZE;
			continue;
		}

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			addr += PMD_SIZE;
			continue;
		}

		target_pgd = pgd_offset_pgd(target_pgdp, addr);

		if (pmd_large(*pmd)) {
			target_pmd = sci_pagetable_walk_pmd(mm, target_pgd,
							    addr);
			if (!target_pmd)
				return -ENOMEM;

			*target_pmd = *pmd;

			addr += PMD_SIZE;
			continue;
		} else {
			pte = pte_offset_kernel(pmd, addr);
			if (pte_none(*pte)) {
				addr += PAGE_SIZE;
				continue;
			}

			target_pte = sci_pagetable_walk_pte(mm, target_pgd,
							    addr);
			if (!target_pte)
				return -ENOMEM;

			*target_pte = *pte;

			addr += PAGE_SIZE;
		}
	}

	return 0;
}

/*
 * we have to map the syscall entry because we'll fault there after
 * CR3 switch and before the verifier is able to detect this as proper
 * access
 */
extern void do_syscall_64(unsigned long nr, struct pt_regs *regs);
unsigned long syscall_entry_addr = (unsigned long)do_syscall_64;

static void sci_reset_backtrace(struct sci_task_data *sci)
{
	memset(sci->backtrace, 0, sci->backtrace_size);
	sci->backtrace[0] = syscall_entry_addr;
	sci->backtrace_size = 1;
}

static inline void sci_sync_user_pagetable(struct task_struct *tsk)
{
	pgd_t *u_pgd = kernel_to_user_pgdp(tsk->mm->pgd);
	pgd_t *sci_pgd = tsk->sci->pgd;

	down_write(&tsk->mm->mmap_sem);
	memcpy(sci_pgd, u_pgd, PGD_KERNEL_START * sizeof(pgd_t));
	up_write(&tsk->mm->mmap_sem);
}

static int sci_free_pte_range(struct mm_struct *mm, pmd_t *pmd)
{
	pte_t *ptep = pte_offset_kernel(pmd, 0);

	pmd_clear(pmd);
	pte_free(mm, virt_to_page(ptep));
	mm_dec_nr_ptes(mm);

	return 0;
}

static int sci_free_pmd_range(struct mm_struct *mm, pud_t *pud)
{
	pmd_t *pmd, *pmdp;
	int i;

	pmdp = pmd_offset(pud, 0);

	for (i = 0, pmd = pmdp; i < PTRS_PER_PMD; i++, pmd++)
		if (!pmd_none(*pmd) && !pmd_large(*pmd))
			sci_free_pte_range(mm, pmd);

	pud_clear(pud);
	pmd_free(mm, pmdp);
	mm_dec_nr_pmds(mm);

	return 0;
}

static int sci_free_pud_range(struct mm_struct *mm, p4d_t *p4d)
{
	pud_t *pud, *pudp;
	int i;

	pudp = pud_offset(p4d, 0);

	for (i = 0, pud = pudp; i < PTRS_PER_PUD; i++, pud++)
		if (!pud_none(*pud))
			sci_free_pmd_range(mm, pud);

	p4d_clear(p4d);
	pud_free(mm, pudp);
	mm_dec_nr_puds(mm);

	return 0;
}

static int sci_free_p4d_range(struct mm_struct *mm, pgd_t *pgd)
{
	p4d_t *p4d, *p4dp;
	int i;

	p4dp = p4d_offset(pgd, 0);

	for (i = 0, p4d = p4dp; i < PTRS_PER_P4D; i++, p4d++)
		if (!p4d_none(*p4d))
			sci_free_pud_range(mm, p4d);

	pgd_clear(pgd);
	p4d_free(mm, p4dp);

	return 0;
}

static int sci_free_pagetable(struct task_struct *tsk, pgd_t *sci_pgd)
{
	struct mm_struct *mm = tsk->mm;
	pgd_t *pgd, *pgdp = sci_pgd;

#ifdef SCI_SHARED_PAGE_TABLES
	int i;

	for (i = KERNEL_PGD_BOUNDARY; i < PTRS_PER_PGD; i++) {
		if (i >= pgd_index(VMALLOC_START) &&
		    i < pgd_index(__START_KERNEL_map))
			continue;
		pgd = pgdp + i;
		sci_free_p4d_range(mm, pgd);
	}
#else
	for (pgd = pgdp + KERNEL_PGD_BOUNDARY; pgd < pgdp + PTRS_PER_PGD; pgd++)
		if (!pgd_none(*pgd))
			sci_free_p4d_range(mm, pgd);
#endif


	return 0;
}

static int sci_pagetable_init(struct task_struct *tsk, pgd_t *sci_pgd)
{
	struct mm_struct *mm = tsk->mm;
	pgd_t *k_pgd = mm->pgd;
	pgd_t *u_pgd = kernel_to_user_pgdp(k_pgd);
	unsigned long stack = (unsigned long)tsk->stack;
	unsigned long addr;
	unsigned int cpu;
	pte_t *pte;
	int ret;

	/* copy the kernel part of user visible page table */
	ret = sci_clone_range(mm, u_pgd, sci_pgd, CPU_ENTRY_AREA_BASE,
			      CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE);
	if (ret)
		goto err_free_pagetable;

	ret = sci_clone_range(mm, u_pgd, sci_pgd,
			      (unsigned long) __entry_text_start,
			      (unsigned long) __irqentry_text_end);
	if (ret)
		goto err_free_pagetable;

	ret = sci_clone_range(mm, mm->pgd, sci_pgd,
			      stack, stack + THREAD_SIZE);
	if (ret)
		goto err_free_pagetable;

	ret = -ENOMEM;
	for_each_possible_cpu(cpu) {
		addr = (unsigned long)&per_cpu(cpu_sci, cpu);
		pte = sci_clone_page(mm, k_pgd, sci_pgd, addr);
		if (!pte)
			goto err_free_pagetable;
	}

	/* plus do_syscall_64 */
	pte = sci_clone_page(mm, k_pgd, sci_pgd, syscall_entry_addr);
	if (!pte)
		goto err_free_pagetable;

	return 0;

err_free_pagetable:
	sci_free_pagetable(tsk, sci_pgd);
	return ret;
}

static int sci_alloc(struct task_struct *tsk)
{
	struct sci_task_data *sci;
	int err = -ENOMEM;

	if (!static_cpu_has(X86_FEATURE_SCI))
		return 0;

	if (tsk->sci)
		return 0;

	sci = kzalloc(sizeof(*sci), GFP_KERNEL);
	if (!sci)
		return err;

	sci->ptes = kcalloc(SCI_MAX_PTES, sizeof(*sci->ptes), GFP_KERNEL);
	if (!sci->ptes)
		goto free_sci;

	sci->backtrace = kcalloc(SCI_MAX_BACKTRACE, sizeof(*sci->backtrace),
				  GFP_KERNEL);
	if (!sci->backtrace)
		goto free_ptes;

	sci->pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL);
	if (!sci->pgd)
		goto free_backtrace;

	err = sci_pagetable_init(tsk, sci->pgd);
	if (err)
		goto free_pgd;

	sci_reset_backtrace(sci);

	tsk->sci = sci;

	return 0;

free_pgd:
	free_page((unsigned long)sci->pgd);
free_backtrace:
	kfree(sci->backtrace);
free_ptes:
	kfree(sci->ptes);
free_sci:
	kfree(sci);
	return err;
}

int sci_init(struct task_struct *tsk)
{
	if (!tsk->sci) {
		int err = sci_alloc(tsk);

		if (err)
			return err;
	}

	sci_sync_user_pagetable(tsk);

	return 0;
}

void sci_exit(struct task_struct *tsk)
{
	struct sci_task_data *sci = tsk->sci;

	if (!static_cpu_has(X86_FEATURE_SCI))
		return;

	if (!sci)
		return;

	sci_free_pagetable(tsk, tsk->sci->pgd);
	free_page((unsigned long)sci->pgd);
	kfree(sci->backtrace);
	kfree(sci->ptes);
	kfree(sci);
}

void sci_clear_data(void)
{
	struct sci_task_data *sci = current->sci;
	int i;

	if (WARN_ON(!sci))
		return;

	for (i = 0; i < sci->ptes_count; i++)
		pte_clear(NULL, 0, sci->ptes[i]);

	memset(sci->ptes, 0, sci->ptes_count);
	sci->ptes_count = 0;

	sci_reset_backtrace(sci);
}

static void sci_add_pte(struct sci_task_data *sci, pte_t *pte)
{
	int i;

	for (i = sci->ptes_count - 1; i >= 0; i--)
		if (pte == sci->ptes[i])
			return;
	sci->ptes[sci->ptes_count++] = pte;
}

static void sci_add_rip(struct sci_task_data *sci, unsigned long rip)
{
	int i;

	for (i = sci->backtrace_size - 1; i >= 0; i--)
		if (rip == sci->backtrace[i])
			return;

	sci->backtrace[sci->backtrace_size++] = rip;
}

static bool sci_verify_code_access(struct sci_task_data *sci,
				   struct pt_regs *regs, unsigned long addr)
{
	char namebuf[KSYM_NAME_LEN];
	unsigned long offset, size;
	const char *symbol;
	char *modname;


	/* instruction fetch outside kernel or module text */
	if (!(is_kernel_text(addr) || is_module_text_address(addr)))
		return false;

	/* no symbol matches the address */
	symbol = kallsyms_lookup(addr, &size, &offset, &modname, namebuf);
	if (!symbol)
		return false;

	/* BPF or ftrace? */
	if (symbol != namebuf)
		return false;

	/* access in the middle of a function */
	if (offset) {
		int i = 0;

		for (i = sci->backtrace_size - 1; i >= 0; i--) {
			unsigned long rip = sci->backtrace[i];

			/* allow jumps to the next page of already mapped one */
			if ((addr >> PAGE_SHIFT) == ((rip >> PAGE_SHIFT) + 1))
				return true;
		}

		return false;
	}

	sci_add_rip(sci, regs->ip);

	return true;
}

bool sci_verify_and_map(struct pt_regs *regs, unsigned long addr,
			unsigned long hw_error_code)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	struct sci_task_data *sci = tsk->sci;
	pte_t *pte;

	/* run out of room for metadata, can't grant access */
	if (sci->ptes_count >= SCI_MAX_PTES ||
	    sci->backtrace_size >= SCI_MAX_BACKTRACE)
		return false;

	/* only code access is checked */
	if (hw_error_code & X86_PF_INSTR &&
	    !sci_verify_code_access(sci, regs, addr))
		return false;

	pte = sci_clone_page(mm, mm->pgd, sci->pgd, addr);
	if (!pte)
		return false;

	sci_add_pte(sci, pte);

	return true;
}

void __init sci_check_boottime_disable(void)
{
	char arg[5];
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_PCID)) {
		pr_info("System call isolation requires PCID\n");
		return;
	}

	/* Assume SCI is disabled unless explicitly overridden. */
	ret = cmdline_find_option(boot_command_line, "sci", arg, sizeof(arg));
	if (ret == 2 && !strncmp(arg, "on", 2)) {
		setup_force_cpu_cap(X86_FEATURE_SCI);
		pr_info("System call isolation is enabled\n");
		return;
	}

	pr_info("System call isolation is disabled\n");
}
