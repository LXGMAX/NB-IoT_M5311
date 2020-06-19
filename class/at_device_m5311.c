/*
 * Copyright (c) 2006-2020, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 * Notes: 驱动参考BC26修改而来，现已正常接入at组件，但还不规范接入env配置工具
 * Change Logs:
 * Date           Author       Notes
 * 2020-03-17     LXGMAX       the first version
 */

#include <stdio.h>
#include <string.h>

#include <drivers/m5311/class/at_devices_m5311.h>

#define LOG_TAG                        "at.dev.m5311"
#include <at_log.h>

#ifdef AT_DEVICE_USING_M5311

#define M5311_WAIT_CONNECT_TIME          3000
#define M5311_THREAD_STACK_SIZE          2048
#define M5311_THREAD_PRIORITY            (RT_THREAD_PRIORITY_MAX/2)
/*
 * m5311 module power on
 */
static void m5311_power_on(struct at_device *device)
{
	struct at_device_m5311 *m5311 = RT_NULL;
	m5311 = (struct at_device_m5311 *) device->user_data;
	/*	检查电源脚状态	*/
    if (m5311->power_pin == -1){
        return;
    }

    //rt_pin_write(m5311->power_pin, PIN_HIGH);

    rt_pin_write(m5311->power_pin, PIN_LOW);
    rt_thread_mdelay(500);
    rt_pin_write(m5311->power_pin, PIN_HIGH);
}

static void m5311_power_off(struct at_device *device)
{
    struct at_device_m5311 *m5311 = RT_NULL;
    m5311 = (struct at_device_m5311 *) device->user_data;
    /* not nead to set pin configuration for M5311 device power on */
    if (m5311->power_pin == -1 || m5311->power_status_pin == -1){
        return;
    }

    if (rt_pin_read(m5311->power_status_pin) == PIN_LOW){
        return;
    }
    rt_pin_write(m5311->power_pin, PIN_HIGH);

    while (rt_pin_read(m5311->power_status_pin) == PIN_HIGH){
        rt_thread_mdelay(3100);
    }
    rt_pin_write(m5311->power_pin, PIN_LOW);
}

/* ====================  m5311 network interface operations ================= */
/* set m5311 network interface device status and address information
 * 设置m5311模块网络接口状态和地址信息
 * */
static int m5311_netdev_set_info(struct netdev *netdev)
{
#define M5311_IMEI_RESP_SIZE      512	//响应结构体大小
#define M5311_IPADDR_RESP_SIZE    16
#define M5311_DNS_RESP_SIZE       96
#define M5311_INFO_RESP_TIMO      rt_tick_from_millisecond(1000)

    int result = RT_EOK;
    ip_addr_t addr;
    at_response_t resp = RT_NULL;
    struct at_device *device = RT_NULL;
    struct at_client *client = RT_NULL;

    RT_ASSERT(netdev);

    device = at_device_get_by_name(AT_DEVICE_NAMETYPE_NETDEV, netdev->name);
    if (device == RT_NULL){
        LOG_E("get device(%s) failed.", netdev->name);
        return -RT_ERROR;
    }
    client = device->client;

    /* set network interface device up status */
    //netdev_low_level_set_link_status(netdev, RT_TRUE);
    //netdev_low_level_set_status(netdev, RT_TRUE);
    netdev_low_level_set_dhcp_status(netdev, RT_TRUE);
    /*	创建at响应结构体	*/
    resp = at_create_resp(M5311_IMEI_RESP_SIZE, 0, M5311_INFO_RESP_TIMO);
    if (resp == RT_NULL) {
        LOG_E("no memory for resp create <m5311>.");
        result = -RT_ENOMEM;
        goto __exit;
    }

    /* set network interface device hardware address(IMEI) */
    {
        #define M5311_NETDEV_HWADDR_LEN   8
        #define M5311_IMEI_LEN            15

        char imei[M5311_IMEI_LEN] = {0};
        int i = 0, j = 0;

        /* send "AT+GSN" commond to get device IMEI */
        if (at_obj_exec_cmd(client, resp, "AT+GSN") < 0) {
            result = -RT_ERROR;
            goto __exit;
        }

        if (at_resp_parse_line_args(resp, 2, "%s", imei) <= 0){
            LOG_E("%s device prase \"AT+GSN\" cmd error.", device->name);
            result = -RT_ERROR;
            goto __exit;
        }

        LOG_D("%s device IMEI number: %s", device->name, imei);

        netdev->hwaddr_len = M5311_NETDEV_HWADDR_LEN;
        /* get hardware address by IMEI */
        for (i = 0, j = 0; i < M5311_NETDEV_HWADDR_LEN && j < M5311_IMEI_LEN; i++, j+=2){
            if (j != M5311_IMEI_LEN - 1){
                netdev->hwaddr[i] = (imei[j] - '0') * 10 + (imei[j + 1] - '0');
            }else{
                netdev->hwaddr[i] = (imei[j] - '0');
            }
        }
    }

    /* set network interface device IP address
     *	获取IP地址
     * */
    {
        #define IP_ADDR_SIZE_MAX    16
        char ipaddr[IP_ADDR_SIZE_MAX] = {0};

        /* send "AT+CGPADDR=1" commond to get IP address */
        if (at_obj_exec_cmd(device->client, resp, "AT+CGPADDR=1") != RT_EOK){
        	result = -RT_ERROR;
        	goto __exit;
        }
        /* 解析响应的数据
         * parse response data "+CGPADDR: 1,<IP_address>"
         * */
        if (at_resp_parse_line_args_by_kw(resp, "+CGPADDR:", "+CGPADDR: %*d,%s", ipaddr) <= 0){
            LOG_E("%s device run \"AT+CGPADDR=1\" cmd error.", device->name);
            result = -RT_ERROR;
            goto __exit;
        }
        LOG_D("%s device IP address: %s", device->name, ipaddr);

        /*  set network interface address information
         * 	给网卡地址
         * */
        inet_aton(ipaddr, &addr);
        netdev_low_level_set_ipaddr(netdev, &addr);
    }

    /*  set network interface device dns server
     * 	查询DNS
     * */
    {
        #define DNS_ADDR_SIZE_MAX   16
        char dns_server1[DNS_ADDR_SIZE_MAX] = {0}, dns_server2[DNS_ADDR_SIZE_MAX] = {0};

        at_resp_set_info(resp, M5311_DNS_RESP_SIZE, 0, M5311_INFO_RESP_TIMO);

        /* send "AT+QIDNSCFG?" commond to get DNS servers address */
        if (at_obj_exec_cmd(client, resp, "AT+DNSSER?") < 0){
            result = -RT_ERROR;
            goto __exit;
        }

        if (at_resp_parse_line_args_by_kw(resp, "+DNSSER: 0,\"%[^\"]\"", dns_server1) <= 0 ||
                at_resp_parse_line_args_by_kw(resp, "+DNSSER: 1,\"%[^\"]\"", dns_server2) <= 0)
        {
            LOG_E("%s device prase \"AT+DNSSER?\" cmd error.", device->name);
            result = -RT_ERROR;
            goto __exit;
        }

        LOG_D("%s device primary DNS server address: %s", device->name, dns_server1);
        LOG_D("%s device secondary DNS server address: %s", device->name, dns_server2);

        inet_aton(dns_server1, &addr);
        netdev_low_level_set_dns_server(netdev, 0, &addr);

        inet_aton(dns_server2, &addr);
        netdev_low_level_set_dns_server(netdev, 1, &addr);
    }

__exit:
    if (resp){
        at_delete_resp(resp);
    }
    return result;
}

/**
 * Check link status task entry
 * 	循环检测设备是否在线
 * @param parameter
 */
static void check_link_status_entry(void *parameter)
{
#define M5311_LINK_STATUS_OK   1
#define M5311_LINK_RESP_SIZE   64
#define M5311_LINK_RESP_TIMO   (3 * RT_TICK_PER_SECOND)
#define M5311_LINK_DELAY_TIME  (30 * RT_TICK_PER_SECOND)

    struct netdev *netdev = (struct netdev *)parameter;
    struct at_device *device = RT_NULL;
    at_response_t resp = RT_NULL;
    int link_status;

    device = at_device_get_by_name(AT_DEVICE_NAMETYPE_NETDEV, netdev->name);
    if (device == RT_NULL){
        LOG_E("get device(%s) failed.", netdev->name);
        return;
    }

    resp = at_create_resp(M5311_LINK_RESP_SIZE, 0, M5311_LINK_RESP_TIMO);
    if (resp == RT_NULL){
        LOG_E("no memory for resp create.");
        return;
    }

	while (1){
        /* send "AT+CGATT" commond  to check netweork interface device link status */
        if (at_obj_exec_cmd(device->client, resp, "AT+CGATT?") < 0){
            rt_thread_mdelay(M5311_LINK_DELAY_TIME);
            continue;
        }

        link_status = -1;
        at_resp_parse_line_args_by_kw(resp, "+CGATT:", "+CGATT: %d", &link_status);

        /* check the network interface device link status  */
        if ((M5311_LINK_STATUS_OK == link_status) != netdev_is_link_up(netdev)){
            netdev_low_level_set_link_status(netdev, (M5311_LINK_STATUS_OK == link_status));
        }
        rt_thread_mdelay(M5311_LINK_DELAY_TIME);
    }
}

static int m5311_netdev_check_link_status(struct netdev *netdev)
{
#define M5311_LINK_THREAD_TICK           20
#define M5311_LINK_THREAD_STACK_SIZE     (1024 + 1024)
#define M5311_LINK_THREAD_PRIORITY       (RT_THREAD_PRIORITY_MAX - 2)

    rt_thread_t tid;
    char tname[RT_NAME_MAX] = {0};

    RT_ASSERT(netdev);

    rt_snprintf(tname, RT_NAME_MAX, "%s", netdev->name);

    tid = rt_thread_create( tname,
    						check_link_status_entry,
    						(void *)netdev,
							M5311_LINK_THREAD_STACK_SIZE,
							M5311_LINK_THREAD_PRIORITY,
							M5311_LINK_THREAD_TICK );
    if (tid){
        rt_thread_startup(tid);
    }
    return RT_EOK;
}

static int m5311_net_init(struct at_device *device);

static int m5311_netdev_set_up(struct netdev *netdev)
{
    struct at_device *device = RT_NULL;

    device = at_device_get_by_name(AT_DEVICE_NAMETYPE_NETDEV, netdev->name);
    if (device == RT_NULL){
        LOG_E("get device(%s) failed.", netdev->name);
        return -RT_ERROR;
    }

    if (device->is_init == RT_FALSE){
        m5311_net_init(device);
        device->is_init = RT_TRUE;

        netdev_low_level_set_status(netdev, RT_TRUE);
        LOG_D("network interface device(%s) set up status.", netdev->name);
    }
    return RT_EOK;
}

static int m5311_netdev_set_down(struct netdev *netdev)
{
    struct at_device *device = RT_NULL;

    device = at_device_get_by_name(AT_DEVICE_NAMETYPE_NETDEV, netdev->name);
    if (device == RT_NULL)
    {
        LOG_E("get device(%s) failed.", netdev->name);
        return -RT_ERROR;
    }

    if (device->is_init == RT_TRUE)
    {
        m5311_power_off(device);
        device->is_init = RT_FALSE;

        netdev_low_level_set_status(netdev, RT_FALSE);
        LOG_D("network interface device(%s) set down status.", netdev->name);
    }

    return RT_EOK;
}
/*
 * set DNS server
 * */
static int m5311_netdev_set_dns_server(struct netdev *netdev, uint8_t dns_num, ip_addr_t *dns_server)
{
#define M5311_DNS_RESP_LEN		8
#define M5311_DNS_RESP_TIMEO	rt_tick_from_millisecond(300)

    int result = RT_EOK;
    at_response_t resp = RT_NULL;
    struct at_device *device = RT_NULL;

    RT_ASSERT(netdev);
    RT_ASSERT(dns_server);

    device = at_device_get_by_name(AT_DEVICE_NAMETYPE_NETDEV, netdev->name);
    if (device == RT_NULL){
        LOG_E("get device(%s) failed.", netdev->name);
        return - RT_ERROR;
    }

    resp = at_create_resp(M5311_DNS_RESP_LEN, 0, M5311_DNS_RESP_TIMEO);
    if (resp == RT_NULL){
        LOG_E("no memory for resp create.");
        return -RT_ENOMEM;
    }

    /* send "AT+DNSSER=<server_ip>[,<dns_id>[,<iptype>]]" commond to set dns servers
     * 	设置DNS地址
     * */
    if (at_exec_cmd(resp, "AT+DNSSER=\"%s\",%d,0", inet_ntoa(*dns_server), dns_num) < 0){
        result = -RT_ERROR;
        goto __exit;
    }
    netdev_low_level_set_dns_server(netdev, dns_num, dns_server);

__exit:
    if (resp){
        at_delete_resp(resp);
    }
    return result;
}

/**
 * ping function
 *
 * @param netdev
 * @param host
 * @param data_len
 * @param timeout
 * @param ping_resp
 * @return
 */
#ifdef NETDEV_USING_PING
static int m5311_netdev_ping(struct netdev *netdev, const char *host,
		size_t data_len, uint32_t timeout, struct netdev_ping_resp *ping_resp)
{
#define M5311_PING_RESP_SIZE       128
#define M5311_PING_IP_SIZE         16
#define M5311_PING_TIMEO           (5 * RT_TICK_PER_SECOND)

    int result = RT_EOK;
    at_response_t resp = RT_NULL;
    char ip_addr[M5311_PING_IP_SIZE] = {0};
    int response = -1, time, ttl;
    struct at_device *device = RT_NULL;

    RT_ASSERT(netdev);
    RT_ASSERT(host);
    RT_ASSERT(ping_resp);

    device = at_device_get_by_name(AT_DEVICE_NAMETYPE_NETDEV, netdev->name);
    if (device == RT_NULL){
        LOG_E("get device(%s) failed.", netdev->name);
        return - RT_ERROR;
    }

    resp = at_create_resp(M5311_PING_RESP_SIZE, 5, M5311_PING_TIMEO);
    if (resp == RT_NULL){
        LOG_E("no memory for resp create.");
        return  -RT_ENOMEM;
    }
    /* send "AT+PING=<remote addr>[,<p_size>[,<timeout>[,<p_count>[,<type>]]]]" commond to send ping request */
    if (at_obj_exec_cmd(device->client, resp, "AT+PING=\"%s\",64,5000,1", host) < 0){
        result = -RT_ERROR;
        goto __exit;
    }

    if (at_resp_parse_line_args_by_kw(resp, "+PING:","+PING: %d", &response) <= 0){
    	if (at_resp_parse_line_args_by_kw(resp, "+PINGERR:", "+PINGERR: %d", &response) <= 0){

    		LOG_D("PING timeout");
    	}
    }

    /* Received the ping response from the server */
    if (response == 0)
    {
        if (at_resp_parse_line_args_by_kw(resp, "+PING:", "+PING: %s,%d,%d",
        								  ip_addr,
										  &ttl,
										  &time) <= 0)
        {
        	rt_thread_mdelay(500);
            result = -RT_ERROR;
            goto __exit;
        }
    }

    /* prase response number */
    switch (response){
    	case 0:
    		inet_aton(ip_addr, &(ping_resp->ip_addr));
    		ping_resp->data_len = data_len;
    		ping_resp->ticks = time;
    		ping_resp->ttl = ttl;
			result = RT_EOK;
    		break;
    	case 1:
    		result = -RT_ETIMEOUT;
    		break;
    	default:
    		result = -RT_ERROR;
    		break;
    }

 __exit:
    if (resp){
        at_delete_resp(resp);
    }

    return result;
}
#endif /* NETDEV_USING_PING */

/*
 * 网络设备状态
 * */
const struct netdev_ops m5311_netdev_ops ={
    m5311_netdev_set_up,
    m5311_netdev_set_down,

    RT_NULL, /* not support set ip, netmask, gatway address */
    m5311_netdev_set_dns_server,
    RT_NULL, /* not support set DHCP status */

#ifdef NETDEV_USING_PING
    m5311_netdev_ping,
#endif
    RT_NULL,
};

static struct netdev *m5311_netdev_add(const char *netdev_name)
{
#define M5311_NETDEV_MTU       1500

    struct netdev *netdev = RT_NULL;

    RT_ASSERT(netdev_name);

    netdev = (struct netdev *) rt_calloc(1, sizeof(struct netdev));
    if (netdev == RT_NULL){
        LOG_E("no memory for netdev ceate(m5311).");
        return RT_NULL;
    }

    netdev->mtu = M5311_NETDEV_MTU;
    netdev->ops = &m5311_netdev_ops;

#ifdef SAL_USING_AT
    extern int sal_at_netdev_set_pf_info(struct netdev *netdev);
    /* set the network interface socket/netdb operations */
    sal_at_netdev_set_pf_info(netdev);
#endif

    netdev_register(netdev, netdev_name, RT_NULL);

    return netdev;
}

/* =============================  m5311 device operations =============================
 * 设备操作
 *
 * */

#define AT_SEND_CMD(client, resp, resp_line, timeout, cmd)											\
    do {																							\
        (resp) = at_resp_set_info((resp), 128, (resp_line), rt_tick_from_millisecond(timeout));		\
        if (at_obj_exec_cmd((client),(resp), (cmd)) < 0) {											\
            result = -RT_ERROR;																		\
            goto __exit;																			\
        }																							\
    } while(0);																						\

/* init for m5311 */
static void m5311_init_thread_entry(void *parameter)
{
#define INIT_RETRY                     5	//初始化尝试次数
#define CPIN_RETRY                     5	//设备插卡检测尝试次数
#define CSQ_RETRY                      10	//信号强度
#define CREG_RETRY                     10	//网络注册状态查询

    at_response_t resp = RT_NULL;
    int i;
    int retry_num = INIT_RETRY;
    char parsed_data[10];
    rt_err_t result = RT_EOK;
    struct at_device *device = (struct at_device *)parameter;
    struct at_client *client = device->client;

    resp = at_create_resp(128, 0, rt_tick_from_millisecond(300));
    if (resp == RT_NULL){
        LOG_E("no memory for resp create(m5311).");
        return;
    }

    LOG_D("start init m5311 device(%s)", device->name);

    while (retry_num--) {
        /* power on the m5311 device */
        m5311_power_on(device);
        rt_thread_mdelay(1000);

        /* wait m5311 startup finish */
        if (at_client_obj_wait_connect(client, M5311_WAIT_CONNECT_TIME)) {
            result = -RT_ETIMEOUT;
            goto __exit;
        }

        /* disable echo */
        AT_SEND_CMD(client, resp, 0, 300, "ATE0");	//关闭用户指令返回
        /* get module version */
        AT_SEND_CMD(client, resp, 0, 300, "ATI");	//输出设备信号信息
        /* LED Status	指示网络注册状态，未注册时快闪，已注册时慢闪
         * AT+CMSYSCTRL=<op>,<mode>[,<nonreg_h>,<reg_h>,<nonreg_l>,<reg_l>]
         * 	*/
        AT_SEND_CMD(client, resp, 0, 300, "AT+CMSYSCTRL=0,2,50,80,50,700");
        AT_SEND_CMD(client,resp,0,300,"AT+SM=LOCK_FOREVER");	//关闭休眠
        /* show module version */
        for (i = 0; i < (int) resp->line_counts - 1; i++){
            LOG_D("%s", at_resp_get_line(resp, i + 1));
        }
        /* check SIM card */
        for (i = 0; i < CPIN_RETRY; i++){
            AT_SEND_CMD(client, resp, 2, 5 * RT_TICK_PER_SECOND, "AT+CPIN?");	//SIM卡插入状态

            if (at_resp_get_line_by_kw(resp, "READY")){
                LOG_D("%s device SIM card detection success.", device->name);
                break;
            }
            rt_thread_mdelay(1000);
        }
        if (i == CPIN_RETRY){
            LOG_E("SIM card detection failed!");
            result = -RT_ERROR;
            goto __exit;
        }
        /* waiting for dirty data to be digested */
        rt_thread_mdelay(10);
        /* check signal strength */
        for (i = 0; i < CSQ_RETRY; i++){
            AT_SEND_CMD(client, resp, 0, 300, "AT+CSQ");	//检查信号强度
            at_resp_parse_line_args_by_kw(resp, "+CSQ:", "+CSQ: %s", &parsed_data);
            if (rt_strncmp(parsed_data, "99,99", sizeof(parsed_data))){
                LOG_D("%s device signal strength: %s", device->name, parsed_data);
                break;
            }
            rt_thread_mdelay(1000);
        }

        if (i == CSQ_RETRY){
            LOG_E("%s device signal strength check failed(%s).", device->name, parsed_data);
            result = -RT_ERROR;
            goto __exit;
        }
        /* check the network is registered */
        for (i = 0; i < CREG_RETRY; i++){
            AT_SEND_CMD(client, resp, 0, 300, "AT+CREG?");
            at_resp_parse_line_args_by_kw(resp, "+CREG:", "+CREG: %s", &parsed_data);
            if (!rt_strncmp(parsed_data, "0,1", sizeof(parsed_data)) ||
                    !rt_strncmp(parsed_data, "0,5", sizeof(parsed_data)) ||
					!rt_strncmp(parsed_data, "0,6", sizeof(parsed_data)))
            {
            	/* 网络注册失败 */
                LOG_D("%s device Network is registered(%s).", device->name, parsed_data);
                break;
            }
            rt_thread_mdelay(1000);
        }
        if (i == CREG_RETRY){
            LOG_E("%s device Network is register failed(%s)", device->name, parsed_data);
            result = -RT_ERROR;
            goto __exit;
        }

        /* initialize successfully  */
        result = RT_EOK;
        break;

    __exit:
        if (result != RT_EOK){
            /* power off the m5311 device */
            m5311_power_off(device);
            rt_thread_mdelay(1000);

            LOG_I("%s device initialize retry...", device->name);
        }
    }	//while end

    if (resp)
        at_delete_resp(resp);

    if (result == RT_EOK){
        m5311_netdev_set_info(device->netdev);						//进入网卡设置
        /* check and create link staus sync thread  */
        if (rt_thread_find(device->netdev->name) == RT_NULL)
            m5311_netdev_check_link_status(device->netdev);

        LOG_I("%s device network initialize success(m5311).", device->name);
    }else{
        LOG_E("%s device network initialize failed(%d)(m5311).", device->name, result);
    }
}
/**
 *	 模块网络初始化
 * */
static int m5311_net_init(struct at_device *device)
{
#ifdef AT_DEVICE_M5311_INIT_ASYN
    rt_thread_t tid;

    tid = rt_thread_create("m5311_net_init",
    		m5311_init_thread_entry,
			(void *)device,
            M5311_THREAD_STACK_SIZE,
			M5311_THREAD_PRIORITY, 20);
    if (tid){
        rt_thread_startup(tid);
    }else{
        LOG_E("create %s device init thread failed.", device->name);
        return -RT_ERROR;
    }
#else
    m5311_init_thread_entry(device);
#endif /* AT_DEVICE_M5311_INIT_ASYN */

    return RT_EOK;
}
/**
 *	 模块设备初始化
 * */
static int m5311_init(struct at_device *device)
{
    struct at_device_m5311 *m5311 = (struct at_device_m5311 *) device->user_data;

    /* initialize AT client */
    at_client_init(m5311->client_name, m5311->recieve_line_num);

    device->client = at_client_get(m5311->client_name);
    if (device->client == RT_NULL){
        LOG_E("get AT client(%s) failed.", m5311->client_name);
        return -RT_ERROR;
    }

#ifdef AT_USING_SOCKET
    m5311_socket_init(device);
#endif

    /* add m5311 netdev to the netdev list */
    device->netdev = m5311_netdev_add(m5311->device_name);
    if (device->netdev == RT_NULL){
        LOG_E("get netdev(%s) failed.", m5311->device_name);
        return -RT_ERROR;
    }

    /* initialize m5311 pin configuration */
    if (m5311->power_pin != -1 && m5311->power_status_pin != -1){
        rt_pin_mode(m5311->power_pin, PIN_MODE_OUTPUT);
        rt_pin_mode(m5311->power_status_pin, PIN_MODE_INPUT);
    }

    /* initialize m5311 device network */
    return m5311_netdev_set_up(device->netdev);
}

static int m5311_deinit(struct at_device *device)
{
    return m5311_netdev_set_down(device->netdev);
}

/*============m5311 origin at command operations end=========================*/
static int m5311_control(struct at_device *device, int cmd, void *arg)
{
    int result = -RT_ERROR;

    RT_ASSERT(device);

    switch (cmd){
    	case AT_DEVICE_CTRL_POWER_ON:
    	case AT_DEVICE_CTRL_POWER_OFF:
    	case AT_DEVICE_CTRL_RESET:
    	case AT_DEVICE_CTRL_LOW_POWER:
    	case AT_DEVICE_CTRL_SLEEP:
    	case AT_DEVICE_CTRL_WAKEUP:
    	case AT_DEVICE_CTRL_NET_CONN:
    	case AT_DEVICE_CTRL_NET_DISCONN:
    	case AT_DEVICE_CTRL_GET_SIGNAL:
    	case AT_DEVICE_CTRL_GET_VER:
    		LOG_W("not support the control command(%d).", cmd);
    		break;
    	default:
    		LOG_E("input error control command(%d).", cmd);
    		break;
    }

    return result;
}
static const struct at_device_ops m5311_device_ops =
{
    m5311_init,
    m5311_deinit,
    m5311_control,
};

static int m5311_device_class_register(void)
{
    struct at_device_class *class = RT_NULL;

    class = (struct at_device_class *) rt_calloc(1, sizeof(struct at_device_class));
    if (class == RT_NULL){
    	LOG_E("no memory for device class create.");
    	return -RT_ENOMEM;
    }

    /* fill m5311 device class object */
#ifdef AT_USING_SOCKET
    m5311_socket_class_register(class);
#endif
    class->device_ops = &m5311_device_ops;

    return at_device_class_register(class, AT_DEVICE_CLASS_M5311);
}

INIT_DEVICE_EXPORT(m5311_device_class_register);
MSH_CMD_EXPORT(m5311_ori_ping, nbiot ping);
#endif /* AT_DEVICE_USING_M5311 */

