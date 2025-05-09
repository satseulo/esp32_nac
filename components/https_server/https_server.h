#ifndef __HTTPS_SERVER_H
#define __HTTPS_SERVER_H

#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <sys/param.h>
//#include "esp_netif.h"
//#include "esp_eth.h"
#include "esp_http_server.h"

typedef struct {
    httpd_req_t *req;
    char response[512];
} http_response_msg_t;

httpd_handle_t start_webserver(void);

#endif