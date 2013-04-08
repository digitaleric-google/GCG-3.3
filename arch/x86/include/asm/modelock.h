#ifndef _ASM_X86_MODELOCK_H
#define _ASM_X86_MODELOCK_H

/* MSRs to set and activate modelock: WRONLY */
#define MSR_MODELOCK_CR0        0xf0000000
#define MSR_MODELOCK_CR4        0xf0000001
#define MSR_MODELOCK_EFER       0xf0000002

/* MSRs to get the modelock capability: RDONLY */
#define MSR_MODELOCK_CR0_CAP    0xf0000010
#define MSR_MODELOCK_CR4_CAP    0xf0000011
#define MSR_MODELOCK_EFER_CAP   0xf0000012

/* modelock bits that are to be monitored/locked. */
#define MODELOCK_CR0_ENABLE        (X86_CR0_PG | X86_CR0_PE)
#define MODELOCK_CR4_ENABLE        (X86_CR4_PSE | X86_CR4_PAE)
#define MODELOCK_EFER_ENABLE       EFER_LME

#ifdef CONFIG_X86_MODELOCK
void __cpuinit modelock_init(void);
#else
static inline void modelock_init(void) {}
#endif

#endif /* _ASM_X86_MODELOCK_H */
