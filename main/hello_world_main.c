/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */
#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"// layer1
#include "esp_eth.h"//layer1
#include "lwip/etharp.h"  // Thêm dòng này
#include "esp_event.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "esp_eth_enc28j60.h"
#include "driver/spi_master.h"
#include "lwip/ip4_addr.h"// tầng ip
#include "nac.h"
#include "main.h"
#include "https_server.h"
#include "esp_eth_enc28j60.h"

#define HTTP_QUEUE_SIZE 10

static const char *TAG = "ENC28J60";
#define LED_PIN GPIO_NUM_2
#define SCAN_BUTTON GPIO_NUM_5
#define BLOCK_BUTTON GPIO_NUM_25

esp_netif_t *eth_netif = NULL;
esp_eth_handle_t eth_handle = NULL;
TaskHandle_t NAC_button_handle = NULL;
QueueHandle_t my_button_Queue, arp_queue; 
QueueHandle_t http_tx_queue = NULL;
SemaphoreHandle_t enc28j60_tx_lock;

bool led_state = false;
const uint8_t ENC28J60_MAC_ADDR[6] = { 0x02, 0x00, 0x00, 0x12, 0x34, 0x56 };
const esp_ip4_addr_t ESP32_IP       = { .addr = ESP_IP4TOADDR(192, 168, 0, 160) };
const esp_ip4_addr_t ESP32_GATEWAY  = { .addr = ESP_IP4TOADDR(192, 168, 0, 1) };
const esp_ip4_addr_t ESP32_NETMASK  = { .addr = ESP_IP4TOADDR(255, 255, 255, 0) };
const esp_ip4_addr_t ESP32_HONEYPOT  = { .addr = ESP_IP4TOADDR(192, 168, 0 ,220) };
static void IRAM_ATTR gpio_isr_handler(void* arg)
{
    gpio_num_t gpio_num = (gpio_num_t)arg;  // Lấy mã số chân GPIO từ đối số
    led_state = !led_state;  // Chuyển đổi trạng thái LED
    xQueueSendFromISR(my_button_Queue, &gpio_num, NULL);  //gửi vào queue: trong queue lưu gpio_num
}

void app_main(void)
{
    gpio_config_t scan_io = {};
    scan_io.pin_bit_mask = (1ULL << SCAN_BUTTON);
    scan_io.mode = GPIO_MODE_INPUT;
    scan_io.pull_up_en = GPIO_PULLUP_ENABLE;
    scan_io.pull_down_en = GPIO_PULLDOWN_DISABLE;
    scan_io.intr_type = GPIO_INTR_NEGEDGE; // Ngắt cạnh xuống
    gpio_config(&scan_io);

    gpio_config_t block_io = {};
    block_io.pin_bit_mask = (1ULL << BLOCK_BUTTON);
    block_io.mode = GPIO_MODE_INPUT;
    block_io.pull_up_en = GPIO_PULLUP_ENABLE;
    block_io.pull_down_en = GPIO_PULLDOWN_DISABLE;
    block_io.intr_type = GPIO_INTR_NEGEDGE; // Ngắt cạnh xuống
    gpio_config(&block_io);

    gpio_config_t led_io = {};
    led_io.pin_bit_mask = (1ULL << LED_PIN);
    led_io.mode = GPIO_MODE_OUTPUT;
    led_io.pull_up_en = GPIO_PULLUP_DISABLE;
    led_io.pull_down_en = GPIO_PULLDOWN_DISABLE;
    led_io.intr_type = GPIO_INTR_DISABLE; 
    gpio_config(&led_io);

    ESP_ERROR_CHECK(gpio_install_isr_service(0));  // bật trình xử lý ngắt
    gpio_isr_handler_add(SCAN_BUTTON, gpio_isr_handler, (void *)SCAN_BUTTON);//tham số đầu viết số chân cho tk gpio_isr_handler_add, mỗi gpio 1 hàm
    gpio_isr_handler_add(BLOCK_BUTTON, gpio_isr_handler, (void *)BLOCK_BUTTON);//tham só cuối cho phép truyền vào trong hàm
    gpio_intr_enable(SCAN_BUTTON);    /* Enable the Interrupt */
    gpio_intr_enable(BLOCK_BUTTON);    /* Enable the Interrupt */

    // tạo netif, cho event_loop hoạt động
    ESP_ERROR_CHECK(esp_netif_init());// khởi tạo network interface
    ESP_ERROR_CHECK(esp_event_loop_create_default());// tạo loop xử lý ngắt wifi, ethernet các kiểu

    //layer network
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH(); //tạo 1 biến struct lưu định dạng mặc định của giao diện mạng ethernet(netif_ethe)
    eth_netif = esp_netif_new(&cfg); // tạo giao diện mạng bằng hàm esp_netif_new , trả về(error type)

    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));// đăng ký sự kiện ethernet
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &got_ip_event_handler, NULL));// đăng ký sự kiện ip

    //layer 1,2 (khởi tạo chỉ trên con enc)
    enc28j60_init();
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));// có thể dùng để khởi động lwip luôn

    // khởi tạo ip tĩnh
    esp_netif_ip_info_t ip_info;
    ip_info.ip      = ESP32_IP;
    ip_info.gw      = ESP32_GATEWAY;
    ip_info.netmask = ESP32_NETMASK;
    ESP_ERROR_CHECK(esp_netif_dhcpc_stop(eth_netif)); // chặn hoạt động của DHCP==> không cho cấp phát động. DHCP do lwip chạy
    ESP_ERROR_CHECK(esp_netif_set_ip_info(eth_netif, &ip_info));// gắn thông tin ip vào netif

    // hook setup ethertnet (hoạt động chính của nac)
    setup_ethernet_hook();

    // tạo tất cả mọi thứ xong đến tạo queue xong đến tạo task==> xử lý xong hết khởi tạo rồi mới chạy
    my_button_Queue = xQueueCreate(3, sizeof(gpio_num_t));  // gán handle vào giá trị 1 hàm==> thực chất là đã có handle rồi
    xTaskCreatePinnedToCore(NAC_button_task, "NAC", 4096, NULL, 10, &NAC_button_handle, 0);  // Core 0// bước tạo task để task kiểm tra queue

    enc28j60_tx_lock = xSemaphoreCreateMutex();
    // Khởi tạo queue, task arp
    arp_queue = xQueueCreate(ARP_QUEUE_SIZE, sizeof(arp_packet_info_t));// queue của nac// arp_queue
    if (arp_queue == NULL) {
        ESP_LOGE(TAG, "Không thể tạo hàng đợi ARP");
    } else {
        xTaskCreate(my_arp_sender_task, "arp_sender_task", 4096, NULL, 2, NULL);
        ESP_LOGI(TAG, "Tạo task gửi ARP OK");
    }

    start_webserver();
}

static void enc28j60_init()
{
    //config các chân spi buscfg.xxxxx là chân của esp, lấy luôn giá trị macro cho trường hợp enc28j60
    spi_bus_config_t buscfg = {
        .miso_io_num = CONFIG_EXAMPLE_ENC28J60_MISO_GPIO,
        .mosi_io_num = CONFIG_EXAMPLE_ENC28J60_MOSI_GPIO,
        .sclk_io_num = CONFIG_EXAMPLE_ENC28J60_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(CONFIG_EXAMPLE_ENC28J60_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));//chạy bus initialize
    /* ENC28J60 ethernet driver is based on spi driver */
    spi_device_interface_config_t spi_devcfg = {
        .mode = 0,
        .clock_speed_hz = CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ * 1000 * 1000,
        .spics_io_num = CONFIG_EXAMPLE_ENC28J60_CS_GPIO,
        .queue_size = 7,
        .cs_ena_posttrans = enc28j60_cal_spi_cs_hold_time(CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ),
    };// gán các tham số truyền thông spi
    eth_enc28j60_config_t enc28j60_config = ETH_ENC28J60_DEFAULT_CONFIG(CONFIG_EXAMPLE_ENC28J60_SPI_HOST, &spi_devcfg);
    // dùng tham số truyền thông tạo struct đặc thù để config enc
    enc28j60_config.int_gpio_num = CONFIG_EXAMPLE_ENC28J60_INT_GPIO;// hàm mẫu chỉ cho truyền 2 biến nên phải đổi thành 3
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();// config mac(layer2.1), đưa về cấu hình mac mặc định
    esp_eth_mac_t *mac = esp_eth_mac_new_enc28j60(&enc28j60_config, &mac_config);//cấu hình spi theo tham số, gán các hàm api điều khiển mac, 
                                                                                     //tạo task xử lý gói tin
    // config layer 1:phy
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.autonego_timeout_ms = 0; // ENC28J60 doesn't support auto-negotiation
    phy_config.reset_gpio_num = -1; // ENC28J60 doesn't have a pin to reset internal PHY
    esp_eth_phy_t *phy = esp_eth_phy_new_enc28j60(&phy_config);
 
    //cấu hình ethernet: yêu cầu cả mac và phy
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));

    /* ENC28J60 doesn't burn any factory MAC address, we need to set it manually.
       02:00:00 is a Locally Administered OUI range so should not be used except when testing on a LAN under your control.
    */
    mac->set_addr(mac, (uint8_t *)ENC28J60_MAC_ADDR);

    // ENC28J60 Errata #1 check
    if (emac_enc28j60_get_chip_info(mac) < ENC28J60_REV_B5 && CONFIG_EXAMPLE_ENC28J60_SPI_CLOCK_MHZ < 8) {
        ESP_LOGE(TAG, "SPI frequency must be at least 8 MHz for chip revision less than 5");
        ESP_ERROR_CHECK(ESP_FAIL);
    }
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));// gán netif vừa tạo với lwip, đồng thời khởi động lwip

    /* It is recommended to use ENC28J60 in Full Duplex mode since multiple errata exist to the Half Duplex mode */
    if(CONFIG_EXAMPLE_ENC28J60_DUPLEX_FULL)
    {
        eth_duplex_t duplex = ETH_DUPLEX_FULL;
        ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_DUPLEX_MODE, &duplex));
    }
    ESP_LOGI(TAG, "ENC28J60 INT GPIO: %d", enc28j60_config.int_gpio_num);
}

static void eth_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    switch (event_id) {// báo kết nối ethernet
        case ETHERNET_EVENT_CONNECTED:
            ESP_LOGI(TAG, "Ethernet Link Up");
            eth_duplex_t duplex = ETH_DUPLEX_FULL;
            esp_eth_ioctl(eth_handle, ETH_CMD_G_DUPLEX_MODE, &duplex);
            ESP_LOGI(TAG, "working in full duplex");
            break;
        case ETHERNET_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "Ethernet Link Down");
            break;
        case ETHERNET_EVENT_START:
            ESP_LOGI(TAG, "Ethernet Started");
            break;
        case ETHERNET_EVENT_STOP:
            ESP_LOGI(TAG, "Ethernet Stopped");
            break;
        default:
            break;
    }
}

static void got_ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    const esp_netif_ip_info_t *ip_info = &event->ip_info;
    ESP_LOGI(TAG, "Ethernet Got IP Address");// báo gắn được ip
    ESP_LOGI(TAG, "ETHIP:" IPSTR, IP2STR(&ip_info->ip));
    my_nac_arp_scan(eth_netif);
}

static void my_arp_sender_task(void *arg)
{
    arp_packet_info_t pkt;

    while (1) {
        // Đọc gói tin từ hàng đợi
        if (xQueueReceive(arp_queue, &pkt, portMAX_DELAY) == pdTRUE) {
            esp_netif_t *esp_netif = (esp_netif_t *)pkt.netif;  // Chuyển đổi đúng kiểu

            esp_netif_iodriver_handle eth_handle = NULL;  // Khai báo và khởi tạo driver handle
            esp_eth_mac_t *mac = NULL;

            // Lấy driver Ethernet từ netif
            eth_handle = esp_netif_get_io_driver(esp_netif);
            if (eth_handle != NULL) {
                // Lấy địa chỉ MAC của thiết bị Ethernet
                if (esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, &mac) == ESP_OK && mac) {

                    // Đợi nếu đang truyền Ethernet
                    while (enc28j60_is_transmitting(mac)) {
                        vTaskDelay(pdMS_TO_TICKS(1));  // đợi 1ms trước khi thử lại
                    }
                }
            }
            // Gọi hàm sao chép ARP raw và xử lý
            my_copy_etharp_raw(
                pkt.netif,
                &pkt.ethsrc,
                &pkt.ethdst,
                &pkt.hwsrc,
                &pkt.ipsrc,
                &pkt.hwdst,
                &pkt.ipdst,
                pkt.opcode
            );
            vTaskDelay(pdMS_TO_TICKS(1));  // đợi 1ms trước khi thử lại
        }
    }
}

void NAC_button_task(void *arg)
{
    gpio_num_t gpio_num;
    while(1){
        if(xQueueReceive(my_button_Queue, &gpio_num, portMAX_DELAY)){
            if (gpio_num == BLOCK_BUTTON){
                //xSemaphoreTake(enc28j60_tx_lock, portMAX_DELAY);
                my_nac_arp_scan(eth_netif);
                //xSemaphoreGive(enc28j60_tx_lock);
            }
            else if(gpio_num == SCAN_BUTTON){
                //xSemaphoreTake(enc28j60_tx_lock, portMAX_DELAY);
                my_arp_table_print();
                //xSemaphoreGive(enc28j60_tx_lock);
            }
        }
        gpio_set_level(LED_PIN, led_state);
    }
}
 

