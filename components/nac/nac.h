#ifndef __NAC_H
#define __NAC_H
#include "esp_err.h"
#include "hal/gpio_types.h"
#include "esp_netif.h"
#include "lwip/netif.h" 
#include "lwip/ip_addr.h"
#include "lwip/prot/ethernet.h" //chứa struct mac 
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "esp_log.h"
#include "netif/ethernet.h" // Thêm thư viện chứa ethernet_input()
#define LWIP_IANA_HWTYPE_ETHERNET 1

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define MY_ARP_TABLE_SIZE 10
typedef enum {
  TRUSTED,   // Được tin cậy
  UNTRUSTED, // Không đáng tin cậy
  BLOCKED    // Bị chặn
} my_nac_label;

typedef struct {
  ip4_addr_t ip;          // địa chỉ ip
  struct eth_addr mac[6]; // địa chỉ mac  
  my_nac_label status;    // trạng thái (TRUSTED, UNTRUSTED, BLOCKED)
  int arp_request_count;  // biến đếm để check quét arp
  int arp_timer;          // lưu thời gian để check quét arp
} my_arp_entry_custom_t;

 extern struct eth_addr mac_boardcast;// = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

//my nac
void setup_ethernet_hook();
err_t my_ethernet_input(struct pbuf *p, struct netif *netif);
err_t my_check_if_arp(struct pbuf *p, struct netif *netif);
void my_etharp_input(struct pbuf *p, struct netif *netif);
void my_etharp_update_arp_entry(ip4_addr_t *ip, uint8_t *mac);
u8_t my_etharp_find_entry(ip4_addr_t *ip);
//void check_free_memory();

void my_nac_arp_scan(esp_netif_t *eth_netif);//thực hiện quét mạng, tham số là netif
void my_nac_arp_block(esp_netif_t *eth_netif, struct eth_addr target_mac, ip4_addr_t target_ip, struct eth_addr block_mac, ip4_addr_t block_ip);// đưa địa chỉ của esp32, địa chỉ của thằng bị 
void my_nac_arp_unblock(esp_netif_t *eth_netif, struct eth_addr unblock_mac, ip4_addr_t unblock_ip);// gửi hết lại cả cái bảng arp cho nó
//void my_nac_fix_connection();// được gọi khi phát hiện có thằng đang spoofing, khả năng cao là phải fix hết cả mạng==> 2 hàm for

#endif