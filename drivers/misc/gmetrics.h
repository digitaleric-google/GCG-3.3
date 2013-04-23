/*
 * linux/drivers/misc/gmetrics.h
 *
 * Copyright (C) 2011 Google Inc.
 * Author: San Mehat <san@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __GMETRICS_H
#define __GMETRICS_H

#define GMETRICS_NAME "gmetrics"

#define GMETRICS_VENDOR_ID 0x1AE0
#define GMETRICS_DEVICE_ID 0x6442

/* Maximum number of metrics we support */
#define GM_METRICS_MAX 64

/* Maximum number of metadata items per metric */
#define GM_METADATA_MAX 32

#define GM_NAME_MAX 255

/* Maximum number of iterations to wait for a command to complete */
#define GM_CMDWAIT_MAX 1000

struct gm_hwinfo;

struct gm_metric {
	struct device *dev;

	int index;

	struct gm_hwinfo *hw;

	/*
	 * Name of the metric.
	 */
	char name[GM_NAME_MAX];

	/*
	 * True if the metric must be triggered by software
	 * before it is sampled by the hardware.
	 */
	bool is_triggered;

	/*
	 * The buffer which holds metadata strings
	 * from the device.
	 */
	char metadata_buf[PAGE_SIZE];

#ifdef CONFIG_LEDS_CLASS
	/*
	 * Each metric by default is connected to an LED.
	 */
	struct led_classdev led;
#endif

	/*
	 * The current 'value' of the metric. This is the
	 * default metric source DMA buffer.
	 */
	u64 value;
};

struct gm_hwinfo {
	char __iomem *iobase;
	struct pci_dev *gm_dev;
	struct gm_metric *metrics[GM_METRICS_MAX];
	int num_metrics;
};

#define GMETRICS_REGSPACE_SIZE	64

#define GMETRICS_REG_STATUS	0x00
# define GMETRICS_STATUS_BUSY	(1 << 0)
# define GMETRICS_STATUS_ERR	(1 << 1)
# define GMETRICS_STATUS_DONE	(1 << 2)
# define GMETRICS_STATUS_TRIG   (1 << 31)

#define GMETRICS_REG_COMMAND		0x04
# define GMETRICS_CMD_READNUMMETRICS	0x01
# define GMETRICS_CMD_READMETADATA	0x02
# define GMETRICS_CMD_SETMETRICDMA	0x03
# define GMETRICS_CMD_CLRMETRICDMA	0x04
# define GMETRICS_CMD_TRIGGER		0x05

#define GMETRICS_REG_DMAPTR1	0x08
#define GMETRICS_REG_DMAPTR0	0x0C
#define GMETRICS_REG_DMALEN	0x10

#endif /* __GMETRICS_H */
