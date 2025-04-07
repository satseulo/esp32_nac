#ifndef MAIN_H
#define MAIN_H

#define CONFIG_EXAMPLE_ENC28J60_SPI_HOST 1
#define CONFIG_EXAMPLE_ENC28J60_SCLK_GPIO 14
#define CONFIG_EXAMPLE_ENC28J60_MOSI_GPIO 13
#define CONFIG_EXAMPLE_ENC28J60_MISO_GPIO 12
#define CONFIG_EXAMPLE_ENC28J60_CS_GPIO 15
#define CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ 8
#define CONFIG_EXAMPLE_ENC28J60_INT_GPIO 27
#define CONFIG_EXAMPLE_ENC28J60_DUPLEX_HALF 1  // Nếu đây là boolean, dùng 1 thay vì 'y'
#define CONFIG_EXAMPLE_ENC28J60_DUPLEX_FULL 1 

static const uint8_t ENC28J60_MAC_ADDR[6] = { 0x02, 0x00, 0x00, 0x12, 0x34, 0x56 };


static void enc28j60_init();
static void eth_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
static void got_ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
#endif // MAIN_H
