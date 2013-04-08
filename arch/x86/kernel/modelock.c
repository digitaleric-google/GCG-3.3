/*
 *  Copyright 2010 Google Inc. All Rights Reserved.
 *  Author: John Lee <jilee@google.com>
 *  Cleaned up by: Mike Waychison <mikew@google.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/modelock.h>
#include <asm/processor.h>

/*
 * "enable_modelock=NUM" kernel boot param
 *	NUM=0: does not enable modelock
 *	NUM=1 or non-zero: enable modelock. default
 * Add "enable_modelock=0" to kernel boot cmd line to disable modelock
 */
static int enable_modelock __cpuinitdata = 1;

static int __cpuinit parse_enable_modelock(char *arg)
{
	int enable;

	if (get_option(&arg, &enable) && enable == 0)
		enable_modelock = 0;

	return 1;
}
__setup("enable_modelock=", parse_enable_modelock);

void __cpuinit modelock_init(void)
{
	u64 cap_cr0 = 0, cap_cr4 = 0, cap_efer = 0;

	if (!enable_modelock) {
		pr_info("modelock disabled by boot param\n");
		return;
	}

	if (rdmsrl_safe(MSR_MODELOCK_CR0_CAP, &cap_cr0)
	 || rdmsrl_safe(MSR_MODELOCK_CR4_CAP, &cap_cr4)
	 || rdmsrl_safe(MSR_MODELOCK_EFER_CAP, &cap_efer)) {
		pr_info("Modelock unsupported\n");
		return;
	}

	pr_info("modelock cap  CR0:0x%llx\n", cap_cr0);
	pr_info("modelock cap  CR4:0x%llx\n", cap_cr4);
	pr_info("modelock cap EFER:0x%llx\n", cap_efer);

	cap_cr0 &= MODELOCK_CR0_ENABLE;
	cap_cr4 &= MODELOCK_CR4_ENABLE;
	cap_efer &= MODELOCK_EFER_ENABLE;

	if (wrmsr_safe(MSR_MODELOCK_CR0, (unsigned)cap_cr0, cap_cr0 >> 32))
		goto fail;
	if (wrmsr_safe(MSR_MODELOCK_CR4, (unsigned)cap_cr4, cap_cr4 >> 32))
		goto fail;
	if (wrmsr_safe(MSR_MODELOCK_EFER, (unsigned)cap_efer, cap_efer >> 32))
		goto fail;

	pr_info("Modelock enabled\n");
	return;
fail:
	pr_warn("Failed to enable modelock\n");
}
