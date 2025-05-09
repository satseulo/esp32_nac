#ifndef MAIN_H
#define MAIN_H

#define CONFIG_EXAMPLE_ENC28J60_SPI_HOST 1
#define CONFIG_EXAMPLE_ENC28J60_SCLK_GPIO 14
#define CONFIG_EXAMPLE_ENC28J60_MOSI_GPIO 13
#define CONFIG_EXAMPLE_ENC28J60_MISO_GPIO 12
#define CONFIG_EXAMPLE_ENC28J60_CS_GPIO 15
#define CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ 8
#define CONFIG_EXAMPLE_ENC28J60_INT_GPIO 18
#define CONFIG_EXAMPLE_ENC28J60_DUPLEX_HALF 0  // Nếu đây là boolean, dùng 1 thay vì 'y'
#define CONFIG_EXAMPLE_ENC28J60_DUPLEX_FULL 1 


extern const uint8_t ENC28J60_MAC_ADDR[6];
extern const esp_ip4_addr_t ESP32_IP;
extern const esp_ip4_addr_t ESP32_GATEWAY;
extern const esp_ip4_addr_t ESP32_NETMASK;

static void enc28j60_init();
static void eth_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
static void got_ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
static void my_arp_sender_task(void *arg);
void NAC_button_task(void *arg);

#endif // MAIN_H
