/*
 *  Copyright 2011 Google Inc. All Rights Reserved.
 *  Author: Matt Alexander <matta@google.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#define AUTHOR "Matt Alexander <matta@google.com>"
#define DESC "Attempts to switch to Real Mode"
#define LICENSE "GPL"
#define PROCFS_NAME "modelock_test"
#define PROCFS_PERMS (S_IFREG | S_IWUSR)
#define GO_REAL "REAL"


static int procfile_write(struct file *file, const char *buffer,
			  unsigned long count, void *data)
{
	if (strncmp(buffer, GO_REAL, strlen(GO_REAL)) == 0) {
		printk(KERN_INFO "Attempting Real Mode...\n");
		/*
		 * TODO(matta): Instead of just crashing the box by only
		 * changing the PE and PG bits in cr0 to 0, go through all
		 * the steps required to fully move to Real Mode.
		 * For now we just want to verify that the attempt is
		 * blocked by the modelock.
		 */
		asm volatile("cli;"
			     "push %rax;"
			     "movq %cr0, %rax;"
			     "and $0x7FFFFFFE, %rax;"
			     "movq %rax, %cr0;"
			     "pop %rax;"
			     "sti;");
		return -EPERM;
	} else {
		return -EINVAL;
	}
}

static int __init modetest_start(void)
{
	struct proc_dir_entry *modetest_file;
	modetest_file = create_proc_entry(PROCFS_NAME, PROCFS_PERMS, NULL);

	if (modetest_file == NULL) {
		printk(KERN_ALERT "Error: could not initialize /proc/%s\n",
		       PROCFS_NAME);
		return -ENOMEM;
	}

	modetest_file->write_proc = procfile_write;
	modetest_file->uid = 0;
	modetest_file->gid = 0;
	modetest_file->size = 0;

	return 0;
}

module_init(modetest_start);

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE(LICENSE);
