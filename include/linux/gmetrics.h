/*  linux/include/linux/gmetrics.h
 *
 */
#ifndef _LINUX_GMETRICS_H_
#define _LINUX_GMETRICS_H_

#include <linux/types.h>

struct list_head;

#ifdef CONFIG_GOOGLE_METRICS
/*
 * Register a metric pointer for exporting to hardware.
 */
extern struct list_head *metric_register_ptr(const char *metric_name,
					     phys_addr_t ptr,
					     int ptr_size_bytes);

/* Unregister a previously registered metric */
extern void metric_unregister_ptr(struct list_head *entry);
#else
static inline struct list_head *metric_register_ptr(const char *name,
						    phys_addr_t ptr,
						    int ptr_size_bytes)
{
	return NULL;
}
static inline void metric_unregister_ptr(struct list_head *entry)
{
}
#endif /* CONFIG_GOOGLE_METRICS */

#endif /* _LINUX_GMETRICS_H_ */
