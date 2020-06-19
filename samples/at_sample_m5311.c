/*
 * Copyright (c) 2006-2020, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2020-03-09     LXG       the first version
 */
#include <drivers/m5311/class/at_devices_m5311.h>

#define LOG_TAG				"at_m5311"
#include <at_log.h>
#ifdef AT_DEVICE_USING_M5311
#define M5311_DEVICE_NAME	"nb_0"


static struct at_device_m5311 nb_0 = {
		M5311_DEVICE_NAME,
		M5311_CLIENT_NAME,

		M5311_POWER_PIN,
		M5311_STATUS_PIN,
		M5311_RECIEVE_BUFF_LEN,
};

static int m5311_device_register(void)
{
	struct at_device_m5311 *m5311 = &nb_0;

	return at_device_register(&(m5311->device),
								m5311->device_name,
								m5311->client_name,
								AT_DEVICE_CLASS_M5311,
								(void *) m5311);
}

INIT_APP_EXPORT(m5311_device_register);

#endif
