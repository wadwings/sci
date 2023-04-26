#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <asm/special_insns.h>

SYSCALL_DEFINE0(get_answer)
{
	return 42;
}

#define BUF_SIZE 1024

typedef void (*foo)(void);

SYSCALL_DEFINE2(sci_write_dmesg, const char __user *, ubuf, size_t, count)
{
	char buf[BUF_SIZE];

	if (!ubuf || count >= BUF_SIZE)
		return -EINVAL;

	buf[count] = '\0';
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	printk("%s\n", buf);

	return count;
}

SYSCALL_DEFINE2(sci_write_dmesg_bad, const char __user *, ubuf, size_t, count)
{
	unsigned long addr = (unsigned long)(void *)hugetlb_reserve_pages;
	char buf[BUF_SIZE];
	foo func1;

	addr += 0xc5;
	func1 = (foo)(void *)addr;
	func1();

	if (!ubuf || count >= BUF_SIZE)
		return -EINVAL;

	buf[count] = '\0';
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	printk("%s\n", buf);

	return count;
}
