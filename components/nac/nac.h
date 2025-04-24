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
extern const uint8_t ENC28J60_MAC_ADDR[6];
extern const esp_ip4_addr_t ESP32_IP;
extern const esp_ip4_addr_t ESP32_GATEWAY;
extern const esp_ip4_addr_t ESP32_NETMASK;
extern struct eth_addr mac_boardcast;
extern struct eth_addr mac_unknown;
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define MY_ARP_TABLE_SIZE 10
#define ARP_QUEUE_SIZE 512
#define ARP_SCAN_DETECT 3
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// struct để chuyển vào queue
typedef struct {
  struct netif *netif;
  struct eth_addr ethsrc;
  struct eth_addr ethdst;//
  struct eth_addr hwsrc;
  struct eth_addr hwdst;//
  ip4_addr_t ipsrc;
  ip4_addr_t ipdst;
  u16_t opcode;
} arp_packet_info_t;
//enum status
typedef enum {
  TRUSTED,   // Được tin cậy
  UNTRUSTED, // Không đáng tin cậy
  BLOCKED    // Bị chặn
} my_nac_label;
// enum cho hàm tìm entry
typedef enum {
  MY_ENTRY_STATUS_NOT_FOUND = -1,     // Trường hợp 3: không trùng IP
  MY_ENTRY_STATUS_CONFLICT = -2,      // Trường hợp 2: IP trùng nhưng MAC khác
  MY_ENTRY_STATUS_MATCHED = 0         // Trường hợp 1: IP & MAC giống → return index
} my_entry_status_t;
// struct bảng arp
typedef struct {
  ip4_addr_t ip;          // địa chỉ ip
  struct eth_addr mac; // địa chỉ mac  
  my_nac_label status;    // trạng thái (TRUSTED, UNTRUSTED, BLOCKED)
  int arp_request_count;  // biến đếm để check quét arp
  int arp_timer;          // lưu thời gian để check quét arp
} my_arp_entry_custom_t;   


void my_enqueue_arp_packet(const arp_packet_info_t *pkt);     
err_t my_copy_etharp_raw(struct netif *netif, const struct eth_addr *ethsrc_addr,
  const struct eth_addr *ethdst_addr, const struct eth_addr *hwsrc_addr,
  const ip4_addr_t *ipsrc_addr, const struct eth_addr *hwdst_addr,
  const ip4_addr_t *ipdst_addr, const u16_t opcode);

void setup_ethernet_hook();                                    
err_t my_ethernet_input(struct pbuf *p, struct netif *netif);  
err_t my_check_if_arp(struct pbuf *p, struct netif *netif);    
void my_etharp_input(struct pbuf *p, struct netif *netif);     
my_entry_status_t my_check_entry(const ip4_addr_t *ipaddr, const struct eth_addr *mac, int *matched_index);
u8_t my_etharp_add_entry(ip4_addr_t *ip, struct eth_addr *mac, my_nac_label status);
int add_arp_request_count(int index);
void my_nac_arp_scan(esp_netif_t *eth_netif);
void my_nac_arp_block(esp_netif_t *eth_netif, struct eth_addr block_mac, ip4_addr_t block_ip);
void my_nac_arp_unblock(esp_netif_t *eth_netif, struct eth_addr unblock_mac, ip4_addr_t unblock_ip);
void my_arp_table_print();
void check_free_memory();



#endif