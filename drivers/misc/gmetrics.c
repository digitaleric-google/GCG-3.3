/*
 * Driver for the Google performance metrics recorder card.
 *
 * Copyright (C) 2011 Google Inc.
 * Author: San Mehat <san@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/leds.h>
#include <linux/ctype.h>
#include <linux/gmetrics.h>

#include "gmetrics.h"

static struct class *metrics_class;

struct metric_binding {
	char *metric_name;
	phys_addr_t ptr;
	int ptr_size_bytes;
	struct list_head list;
};

static LIST_HEAD(bound_metrics);
static DEFINE_MUTEX(bound_metrics_lock);

static u32 gm_read_reg(struct gm_hwinfo *hw, int m_idx, int offset)
{
	void __iomem *base = hw->iobase + (GMETRICS_REGSPACE_SIZE * m_idx);
	return ioread32(base + offset);
}

static void gm_write_reg(struct gm_hwinfo *hw, int m_idx, int offset,
			u32 value)
{
	void __iomem *base = hw->iobase + (GMETRICS_REGSPACE_SIZE * m_idx);
	iowrite32(value, base + offset);
}

static u32 gm_read_status(struct gm_hwinfo *hw, int m_idx)
{
	return gm_read_reg(hw, m_idx, GMETRICS_REG_STATUS);
}

static void gm_clr_status_done(struct gm_hwinfo *hw, int m_idx)
{
	gm_write_reg(hw, m_idx, GMETRICS_REG_STATUS, GMETRICS_STATUS_DONE);
}

static void gm_clr_status_err(struct gm_hwinfo *hw, int m_idx)
{
	gm_write_reg(hw, m_idx, GMETRICS_REG_STATUS, GMETRICS_STATUS_ERR);
}

static void gm_write_dma_ptr(struct gm_hwinfo *hw,
			     int m_idx,
			     phys_addr_t addr)
{
	gm_write_reg(hw, m_idx, GMETRICS_REG_DMAPTR1, (addr >> 32));
	gm_write_reg(hw, m_idx, GMETRICS_REG_DMAPTR0, (addr & 0xffffffff));
}

static int wait_for_cmd_done_or_err(struct gm_hwinfo *hw, int m_idx)
{
	int wait = GM_CMDWAIT_MAX;

	for (; wait; wait--) {
		u32 status = gm_read_status(hw, m_idx);
		if (status & GMETRICS_STATUS_ERR)
			return -EIO;
		else if (status & GMETRICS_STATUS_DONE)
			return 0;
		udelay(1);
	}
	return -ETIMEDOUT;
}

static void __devexit gm_unmap_device(struct pci_dev *pdev,
				      struct gm_hwinfo *hw)
{
	pci_iounmap(pdev, hw->iobase);
}

static int __devinit gm_map_device(struct pci_dev *pdev, struct gm_hwinfo *hw)
{
	hw->iobase = pci_iomap(pdev, 0, 0);
	if (hw->iobase == NULL) {
		dev_err(&pdev->dev, "Error mapping io\n");
		return -ENOMEM;
	}

	return 0;
}

static void gm_remove(struct pci_dev *pdev)
{
	struct gm_hwinfo *gm_hw = pci_get_drvdata(pdev);

	gm_unmap_device(pdev, gm_hw);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	kfree(gm_hw);
}

static int gm_do_cmd(struct gm_hwinfo *hw, int m_idx, int cmd)
{
	int err;
	gm_write_reg(hw, m_idx, GMETRICS_REG_COMMAND, cmd);

	err = wait_for_cmd_done_or_err(hw, m_idx);
	if (err) {
		gm_clr_status_err(hw, m_idx);
		return err;
	}
	gm_clr_status_done(hw, m_idx);
	return 0;
}


static u32 get_num_metrics(struct gm_hwinfo *hw)
{
	u32 num = 0;
	int err = 0;

	gm_write_dma_ptr(hw, 0, virt_to_phys(&num));
	gm_write_reg(hw, 0, GMETRICS_REG_DMALEN, 4);
	err = gm_do_cmd(hw, 0, GMETRICS_CMD_READNUMMETRICS);
	if (err) {
		pr_err("Failed to get metrics count.");
		return 0;
	}
	return num;
}

static int set_metric_ptr(struct gm_hwinfo *hw, int m_idx, phys_addr_t ptr,
			  int size_bytes)
{
	BUG_ON(!mutex_is_locked(&bound_metrics_lock));

	gm_write_dma_ptr(hw, m_idx, ptr);
	gm_write_reg(hw, m_idx, GMETRICS_REG_DMALEN, size_bytes);
	if (gm_do_cmd(hw, m_idx, GMETRICS_CMD_SETMETRICDMA))
		return -EIO;
	return 0;
}

static int clr_metric_ptr(struct gm_hwinfo *hw, int m_idx)
{
	if (gm_do_cmd(hw, m_idx, GMETRICS_CMD_CLRMETRICDMA))
		return -EIO;
	return 0;
}

static void gm_trigger(struct gm_metric *metric)
{
	if (gm_do_cmd(metric->hw, metric->index, GMETRICS_CMD_TRIGGER))
		pr_err("Failed to trigger %s\n", metric->name);
}

#ifdef CONFIG_NEW_LEDS
static void gm_led_brightness_set(struct led_classdev *led,
				  enum led_brightness brightness)
{
	struct gm_metric *metric =
		container_of(led, struct gm_metric, led);
	metric->value = brightness;
	if (metric->is_triggered)
		gm_trigger(metric);
}
#endif

static void gm_destroy_metric(struct gm_hwinfo *hw, int m_idx)
{
	if (hw->metrics[m_idx]) {
		gm_do_cmd(hw, m_idx, GMETRICS_CMD_CLRMETRICDMA);
		kfree(hw->metrics[m_idx]);
	} else {
		pr_err("Attempt to destroy uncreated metric\n");
	}
}

static size_t find_metadata_length(struct gm_metric *metric)
{
	const char *start = metric->metadata_buf;
	const char *p = metric->metadata_buf;

	while ((p - start < sizeof(metric->metadata_buf)) && (p[0] || p[1]))
		p++;
	return p - start + 2;
}

static ssize_t metadata_read(struct file *filp,
			     struct kobject *kobj,
			     struct bin_attribute *bin_attr,
			     char *buf, loff_t offset, size_t count)
{
	struct device *dev =
		container_of(kobj, struct device, kobj);
	struct gm_metric *metric = dev_get_drvdata(dev);
	size_t metadata_len = find_metadata_length(metric);

	return memory_read_from_buffer(buf, count, &offset,
				       metric->metadata_buf,
				       metadata_len);
}

static const struct bin_attribute metadata_attr = {
	.attr = {.name = "metadata", .mode = 0400},
	.read = metadata_read,
};

static int __devinit gm_init_metric(struct gm_hwinfo *hw, int m_idx)
{
	int err = 0;
	struct gm_metric *metric = kzalloc(sizeof(*metric), GFP_KERNEL);

	if (!metric)
		return -ENOMEM;
	metric->hw = hw;
	metric->index = hw->num_metrics;
	hw->metrics[hw->num_metrics++] = metric;
	metric->is_triggered = (gm_read_status(hw, m_idx) &
				GMETRICS_STATUS_TRIG);

	gm_write_dma_ptr(hw, m_idx, virt_to_phys(metric->metadata_buf));
	gm_write_reg(hw, m_idx, GMETRICS_REG_DMALEN,
		     sizeof(metric->metadata_buf));

	err = gm_do_cmd(hw, m_idx, GMETRICS_CMD_READMETADATA);
	if (err) {
		pr_err("Failed to read metadata.");
		goto err_free;
	}

	if (strncmp(metric->metadata_buf, "name=", 5)) {
		pr_err("Failed to find metric name in metdata.\n");
		err = -EIO;
		goto err_free;
	}
	strncpy(metric->name, &metric->metadata_buf[5], GM_NAME_MAX);

	metric->dev = device_create(metrics_class, NULL, 0, metric,
				    "%s", metric->name);

	if (IS_ERR(metric->dev)) {
		pr_err("Failed to create device.");
		err = PTR_ERR(metric->dev);
		goto err_free;
	}
	err = sysfs_create_bin_file(&metric->dev->kobj, &metadata_attr);
	if (err) {
		pr_err("Failed to create sysfs bin file\n");
		goto err_unregister_dev;
	}

	/* Set a default location for this metric */
	if (set_metric_ptr(hw, m_idx, virt_to_phys(&metric->value),
			   sizeof(metric->value))) {
		pr_err("Failed to set metric dma ptr.");
		goto err_destroy_bin;
	}

	pr_info("Metric: %s, triggered: %d\n", metric->name,
		metric->is_triggered);
	return 0;

err_destroy_bin:
	sysfs_remove_bin_file(&metric->dev->kobj, &metadata_attr);
err_unregister_dev:
	device_unregister(metric->dev);
err_free:
	kfree(metric);
	return err;
}

static int _lookup_mdevice(struct device *dev, void *data)
{
	const char *name = (const char *) data;
	struct gm_metric *metric = dev_get_drvdata(dev);

	if (!strcmp(metric->name, name))
		return 1;
	return 0;
}

struct list_head *metric_register_ptr(const char *metric_name, phys_addr_t ptr,
			 int ptr_size_bytes)
{
	struct metric_binding *binding;
	struct metric_binding *chk;
	struct device *dev;
	int err;

	pr_debug("reg: metric %s ptr %llx, size %d\n", metric_name, ptr,
		 ptr_size_bytes);

	mutex_lock(&bound_metrics_lock);

	err = -EBUSY;
	/* Check for duplicate binding */
	list_for_each_entry(chk, &bound_metrics, list) {
		if (!strcmp(metric_name, chk->metric_name)) {
			pr_err("Metric %s is already bound\n", metric_name);
			goto fail;
		}
	}

	err = -ENOMEM;
	binding = kzalloc(sizeof(*binding), GFP_KERNEL);
	if (binding == NULL)
		goto fail;
	binding->metric_name = kstrdup(metric_name, GFP_KERNEL);
	if (binding->metric_name == NULL) {
		kfree(binding);
		goto fail;
	}
	binding->ptr = ptr;
	binding->ptr_size_bytes = ptr_size_bytes;
	list_add_tail(&binding->list, &bound_metrics);

	/* If the metric exists then bind it */
	dev = class_find_device(metrics_class, NULL,
				(void *) metric_name, _lookup_mdevice);
	if (dev) {
		struct gm_metric *metric = dev_get_drvdata(dev);
		struct gm_hwinfo *hw = metric->hw;
		pr_info("Binding metric %s to %llx (size %d)\n",
			metric_name, ptr, ptr_size_bytes);
		if (set_metric_ptr(hw, metric->index, ptr, ptr_size_bytes))
			BUG();
	}

	mutex_unlock(&bound_metrics_lock);
	return &binding->list;
fail:
	mutex_unlock(&bound_metrics_lock);
	return ERR_PTR(err);
}
EXPORT_SYMBOL(metric_register_ptr);

void metric_unregister_ptr(struct list_head *entry)
{
	struct metric_binding *binding = list_entry(entry,
						    struct metric_binding,
						    list);
	struct device *dev = class_find_device(metrics_class,
					       NULL,
					       (void *) binding->metric_name,
					       _lookup_mdevice);

	mutex_lock(&bound_metrics_lock);

	if (dev) {
		struct gm_metric *metric = dev_get_drvdata(dev);
		struct gm_hwinfo *hw = metric->hw;
		if (set_metric_ptr(hw,
				   metric->index,
				   virt_to_phys(&metric->value),
				   sizeof(metric->value))) {
			BUG();
		}
	}

	kfree(binding->metric_name);
	list_del(entry);
	kfree(binding);

	mutex_unlock(&bound_metrics_lock);
}
EXPORT_SYMBOL(metric_unregister_ptr);

static int __devinit gm_probe(struct pci_dev *pdev,
			       const struct pci_device_id *ent)
{
	int err;
	struct gm_hwinfo *gm_hw;
	u32 num_metrics;
	int i;
	int cleanup_range = 0;
	struct metric_binding *binding;

	/* track global allocations for this device */
	err = -ENOMEM;
	gm_hw = kzalloc(sizeof(*gm_hw), GFP_KERNEL);
	if (!gm_hw)
		goto out;

	gm_hw->gm_dev = pdev;

	err = pci_enable_device(pdev);
	if (err)
		goto free;

	pci_set_master(pdev);

	err = pci_request_regions(pdev, GMETRICS_NAME);
	if (err)
		goto disable;

	err = gm_map_device(pdev, gm_hw);
	if (err)
		goto free_regions;

	pci_set_drvdata(pdev, gm_hw);

	num_metrics = get_num_metrics(gm_hw);

	pr_info("Found %u metrics\n", num_metrics);
	mutex_lock(&bound_metrics_lock);
	for (i = 0; i < num_metrics; i++) {
		err = gm_init_metric(gm_hw, i);
		if (err) {
			mutex_unlock(&bound_metrics_lock);
			goto free_metrics;
		}

		cleanup_range = i;
	}

	list_for_each_entry(binding, &bound_metrics, list) {
		struct device *dev;

		/* If the metric exists then bind it */
		dev = class_find_device(metrics_class,
					NULL,
					(void *) binding->metric_name,
					_lookup_mdevice);
		if (dev) {
			struct gm_metric *metric = dev_get_drvdata(dev);
			struct gm_hwinfo *hw = metric->hw;
			pr_info("Binding metric %s to %llx (size %d)\n",
				binding->metric_name, binding->ptr,
				binding->ptr_size_bytes);
			if (set_metric_ptr(hw, metric->index, binding->ptr,
					   binding->ptr_size_bytes)) {
				BUG();
			}
		} else {
			pr_warn("Hardware does not have metric '%s'\n",
				binding->metric_name);
		}
	}
	mutex_unlock(&bound_metrics_lock);

	return 0;

free_metrics:
	for (i = 0; i < cleanup_range; i++)
		gm_destroy_metric(gm_hw, i);
	gm_unmap_device(pdev, gm_hw);
free_regions:
	pci_release_regions(pdev);
disable:
	pci_disable_device(pdev);
free:
	kfree(gm_hw);
out:
	return err;
}

static DEFINE_PCI_DEVICE_TABLE(gm_devices) = {
	{ PCI_DEVICE(GMETRICS_VENDOR_ID, GMETRICS_DEVICE_ID) },
	{ }
};

MODULE_DEVICE_TABLE(pci, gm_devices);

static struct pci_driver gm_driver = {
	.name	  = GMETRICS_NAME,
	.id_table = gm_devices,
	.probe	  = gm_probe,
	.remove	  = __devexit_p(gm_remove),
};

static ssize_t metrics_value_show(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	struct gm_metric *metric = dev_get_drvdata(dev);
	return sprintf(buf, "%llu\n", metric->value);
}

static ssize_t metrics_value_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t size)
{
	struct gm_metric *metric = dev_get_drvdata(dev);
	u64 value;

	if (strict_strtoull(buf, 10, &value))
		return -EINVAL;

	metric->value = value;
	if (metric->is_triggered) {
		gm_trigger(metric);
#ifdef CONFIG_NEW_LEDS
		if (value < metric->led.max_brightness)
			metric->led.brightness = value;
		else
			metric->led.brightness = metric->led.max_brightness;
#endif
	}
	return size;
}

static struct device_attribute metrics_class_attrs[] = {
	__ATTR(value, 0644, metrics_value_show, metrics_value_store),
	__ATTR_NULL,
};

static int __init gm_init(void)
{
	int err;

	metrics_class = class_create(THIS_MODULE, "metrics");
	if (IS_ERR(metrics_class))
		return PTR_ERR(metrics_class);
	metrics_class->dev_attrs = metrics_class_attrs;

	err = pci_register_driver(&gm_driver);
	if (err)
		pr_err("failed to register pci driver\n");
	return err;
}

int _release_metric_ptr(struct device *dev, void *data)
{
	struct gm_metric *metric = dev_get_drvdata(dev);
	struct gm_hwinfo *hw = metric->hw;
	clr_metric_ptr(hw, metric->index);
	return 0;
}

static void __exit gm_exit(void)
{
	struct metric_binding *entry, *n;

	mutex_lock(&bound_metrics_lock);
	class_for_each_device(metrics_class, NULL, NULL, _release_metric_ptr);
	list_for_each_entry_safe(entry, n, &bound_metrics, list) {
		list_del(&entry->list);
		kfree(entry->metric_name);
		kfree(entry);
	}
	mutex_unlock(&bound_metrics_lock);
	pci_unregister_driver(&gm_driver);
	class_destroy(metrics_class);
}

MODULE_VERSION("1.0");
MODULE_ALIAS(GMETRICS_NAME);
MODULE_DESCRIPTION(GMETRICS_NAME);
MODULE_AUTHOR("San Mehat <san@google.com>");
MODULE_LICENSE("GPL v2");

module_init(gm_init);
module_exit(gm_exit);
