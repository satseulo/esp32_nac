// #include <esp_wifi.h>
// #include <esp_event.h>
#include <esp_log.h>
// #include <esp_system.h>
// #include <nvs_flash.h>
// #include <sys/param.h>
// #include "esp_netif.h"
// #include "esp_eth.h"
// #include "protocol_examples_common.h"

#include <esp_https_server.h>
#include "esp_tls.h"
#include "sdkconfig.h"
#include "https_server.h"
/* A simple example that demonstrates how to create GET and POST
 * handlers and start an HTTPS server.
*/
extern SemaphoreHandle_t enc28j60_tx_lock;
static const char *TAG = "example";

extern QueueHandle_t http_tx_queue;  // Đảm bảo bạn đã tạo queue này ở nơi khác

extern const uint8_t login_html_start[] asm("_binary_login_html_start");
extern const uint8_t login_html_end[]   asm("_binary_login_html_end");

esp_err_t login_get_handler(httpd_req_t *req) {
    size_t len = login_html_end - login_html_start;

    xSemaphoreTake(enc28j60_tx_lock, portMAX_DELAY);
    esp_err_t err = httpd_resp_send(req, (const char *)login_html_start, len);
    xSemaphoreGive(enc28j60_tx_lock);

    if (err != ESP_OK) {
        ESP_LOGE("HTTP", "Gửi login_get_handler thất bại: %s", esp_err_to_name(err));
    }

    return err;
}

esp_err_t login_post_handler(httpd_req_t *req) {
    char buf[100];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) return ESP_FAIL;
    buf[len] = '\0';

    char *user = strstr(buf, "username=");
    char *pass = strstr(buf, "password=");

    const char *response_text = "Malformed login request";

    if (user && pass) {
        user += strlen("username=");
        pass += strlen("password=");

        char *pass_end = strchr(pass, '&');
        if (pass_end) *pass_end = '\0';

        if (strncmp(user, "admin", 5) == 0 && strncmp(pass, "1234", 4) == 0) {
            response_text = "Login successful";
        } else {
            response_text = "Invalid credentials";
        }
    }

    xSemaphoreTake(enc28j60_tx_lock, portMAX_DELAY);
    esp_err_t err = httpd_resp_sendstr(req, response_text);
    xSemaphoreGive(enc28j60_tx_lock);

    if (err != ESP_OK) {
        ESP_LOGE("HTTP", "Gửi login_post_handler thất bại: %s", esp_err_to_name(err));
    }

    return err;
}

httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server");

    // httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    // extern const unsigned char servercert_start[] asm("_binary_servercert_pem_start");
    // extern const unsigned char servercert_end[]   asm("_binary_servercert_pem_end");
    // conf.servercert = servercert_start;
    // conf.servercert_len = servercert_end - servercert_start;

    // extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    // extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    // conf.prvtkey_pem = prvtkey_pem_start;
    // conf.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;
    //esp_err_t ret = httpd_ssl_start(&server, &conf);
    httpd_config_t conf = HTTPD_DEFAULT_CONFIG();
    esp_err_t ret = httpd_start(&server, &conf);

    if (ESP_OK != ret) {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }
    httpd_uri_t login_get_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = login_get_handler
    };
    httpd_register_uri_handler(server, &login_get_uri);

    httpd_uri_t login_post_uri = {
        .uri = "/login",
        .method = HTTP_POST,
        .handler = login_post_handler
    };
    httpd_register_uri_handler(server, &login_post_uri);

    // Set URI handlers
    return server;
}
