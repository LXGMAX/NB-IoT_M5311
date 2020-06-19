/*
 * Copyright (c) 2006-2020, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2020-03-09     LXG       the first version
 */
#ifndef DRIVERS_M5311_M5311_H_
#define DRIVERS_M5311_M5311_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <at_device.h>


#define AT_DEVICE_USING_M5311

#ifdef AT_DEVICE_USING_M5311

#define AT_DEVICE_CLASS_M5311	0x13U
// #define AT_DEVICE_M5311_INIT_ASYN
/* M5311 develop part begin */
#define M5311_CLIENT_NAME 		"uart2"
#define M5311_POWER_PIN 		30	//PB14 30
#define M5311_STATUS_PIN 		-1
#define M5311_RECIEVE_BUFF_LEN 	4096
/* M5311 develop part end*/

/*	Max number of sockets supported by the m5311 device	*/
#define AT_DEVICE_M5311_SOCKETS_NUM		5

struct at_device_m5311{
		char *device_name;
		char *client_name;

		int power_pin;
		int power_status_pin;
		size_t recieve_line_num;
		struct at_device device;
		void *user_data;
};

#ifdef AT_USING_SOCKET
/* m5311 device socket initialize */
int m5311_socket_init(struct at_device *device);

/* m5311 device class socket register */
int m5311_socket_class_register(struct at_device_class *class);

#endif /* AT_USING_SOCKET */

#endif /* AT_DEVICE_USING_M5311 */

#ifdef __cplusplus
}
#endif



#endif /* DRIVERS_M5311_M5311_H_ */
