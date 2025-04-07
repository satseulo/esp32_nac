#include  "nac.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"// có hàm void *esp_netif_get_netif_impl(esp_netif_t *esp_netif)
#include "esp_heap_caps.h" // kiểm tra bộ nhớ
static const char *TAG = "NAC";
extern esp_netif_t *eth_netif;

my_arp_entry_custom_t my_arp_table[MY_ARP_TABLE_SIZE];
int my_arp_table_index = 0;

const char* status_labels[] = {
    "TRUSTED",   // TRUSTED = 0
    "UNTRUSTED", // UNTRUSTED = 1
    "BLOCKED"    // BLOCKED = 2
  };
static err_t
my_copy_etharp_raw(struct netif *netif, const struct eth_addr *ethsrc_addr,
           const struct eth_addr *ethdst_addr,
           const struct eth_addr *hwsrc_addr, const ip4_addr_t *ipsrc_addr,
           const struct eth_addr *hwdst_addr, const ip4_addr_t *ipdst_addr,
           const u16_t opcode)
{
  struct pbuf *p;
  err_t result = ERR_OK;
  struct etharp_hdr *hdr;

  LWIP_ASSERT("netif != NULL", netif != NULL);

  /* allocate a pbuf for the outgoing ARP request packet */
  p = pbuf_alloc(PBUF_LINK, SIZEOF_ETHARP_HDR, PBUF_RAM);
  /* could allocate a pbuf for an ARP request? */
  if (p == NULL) {
    return ERR_MEM;
  }

  hdr = (struct etharp_hdr *)p->payload;
  hdr->opcode = lwip_htons(opcode);

  /* Write the ARP MAC-Addresses */
  SMEMCPY(&hdr->shwaddr, hwsrc_addr, ETH_HWADDR_LEN);
  SMEMCPY(&hdr->dhwaddr, hwdst_addr, ETH_HWADDR_LEN);
  /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
   * structure packing. */
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->sipaddr, ipsrc_addr);
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->dipaddr, ipdst_addr);

  hdr->hwtype = PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET);
  hdr->proto = PP_HTONS(ETHTYPE_IP);
  /* set hwlen and protolen */
  hdr->hwlen = ETH_HWADDR_LEN;
  hdr->protolen = sizeof(ip4_addr_t);
  ethernet_output(netif, p, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);

  /* free ARP query packet */
  pbuf_free(p);
  /* could not allocate pbuf for ARP request */

  return result;
}

//đổi hook để thay vì xử lý theo thứ tự thì gọi my_ethernet_input trước
void setup_ethernet_hook() {
    struct netif *lwip_netif = netif_list; // Duyệt qua danh sách netif
    while (lwip_netif != NULL) {
        if (lwip_netif->state == eth_netif) { // Kiểm tra netif nào liên kết với eth_netif
            lwip_netif->input = my_ethernet_input;
            ESP_LOGI(TAG, "Ethernet RX Hook set successfully!");
            return;
        }
        lwip_netif = lwip_netif->next;
    }
    ESP_LOGE(TAG, "Failed to find LWIP netif");
}
//gọi hàm my_check_if_arp, return về xử lý lwip cũng ở hàm này
err_t my_ethernet_input(struct pbuf *p, struct netif *netif) {
    struct pbuf *local_p;   // Khai báo con trỏ mới để chứa sao chép pbuf
    // Tạo bản sao của pbuf mới
    local_p = pbuf_alloc(PBUF_RAW, p->len, PBUF_POOL);
    if (local_p == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for pbuf");
        pbuf_free(p);
        //check_free_memory();
        return ERR_MEM;
    }

    // Sao chép dữ liệu từ pbuf gốc vào bản sao
    if (pbuf_copy(local_p, p) != ERR_OK) {
        ESP_LOGE(TAG, "Failed to copy pbuf data");
        pbuf_free(p);
        pbuf_free(local_p);
        //check_free_memory();
        return ERR_MEM;
    }

    my_check_if_arp(local_p,netif);//thêm hàm check if arp
    pbuf_free(local_p);
    //check_free_memory();
    return ethernet_input(p, netif);  // sau khi xử lý xong việc của mình, móc tiếp lại cho lwip xử lý
}
//kiểm tra nếu là arp thì gọi tiếp hàm my_etharp_input
err_t my_check_if_arp(struct pbuf *p, struct netif *netif) {
    struct eth_hdr *ethhdr;
    u16_t type;

    LWIP_ASSERT_CORE_LOCKED();

    if (p->len <= SIZEOF_ETH_HDR) {
        pbuf_free(p);
        return ERR_OK;  // Không cần giải phóng ở đây nếu không có lỗi
    }

    ethhdr = (struct eth_hdr *)p->payload;
    type = ethhdr->type;

    if (type == PP_HTONS(ETHTYPE_ARP)) {
        if (!(netif->flags & NETIF_FLAG_ETHARP)) {
            pbuf_free(p);
            return ERR_OK;  // Không cần giải phóng ở đây nếu không xử lý ARP
        }

        if (pbuf_remove_header(p, SIZEOF_ETH_HDR)) {
            pbuf_free(p);
            return ERR_OK;  // Không cần giải phóng nếu lỗi khi bỏ qua header
        }
        my_etharp_input(p, netif);
    }
    return ERR_OK;
}
//hàm xử lý bản tin arp
void my_etharp_input(struct pbuf *p, struct netif *netif)
{
  //ESP_LOGI(TAG, "my_etharp_input started");
  struct etharp_hdr *hdr;
  /* these are aligned properly, whereas the ARP header fields might not be */
  ip4_addr_t sipaddr, dipaddr;
//   u8_t for_us, from_us;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif != NULL", (netif != NULL), return;);
  hdr = (struct etharp_hdr *)p->payload;

  /* RFC 826 "Packet Reception": */
  if ((hdr->hwtype != PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET)) ||
      (hdr->hwlen != ETH_HWADDR_LEN) ||
      (hdr->protolen != sizeof(ip4_addr_t)) ||
      (hdr->proto != PP_HTONS(ETHTYPE_IP)))  {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                ("etharp_input: packet dropped, wrong hw type, hwlen, proto, protolen or ethernet type (%"U16_F"/%"U16_F"/%"U16_F"/%"U16_F")\n",
                 hdr->hwtype, (u16_t)hdr->hwlen, hdr->proto, (u16_t)hdr->protolen));
    pbuf_free(p);
    return;
  }

  IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&sipaddr, &hdr->sipaddr);
  IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&dipaddr, &hdr->dipaddr);

  my_etharp_update_arp_entry(&sipaddr, hdr->shwaddr.addr);
}
//thêm arp entry vào bảng, trước khi thêm gọi hàm my_etharp_find_entry
void my_etharp_update_arp_entry(ip4_addr_t *ip, uint8_t *mac) {
    ip4_addr_t zero_ip;
    IP4_ADDR(&zero_ip, 0, 0, 0, 0);
    if (my_etharp_find_entry(ip) || ip4_addr_cmp(ip, &zero_ip)) {
        ESP_LOGI(TAG, "dia chi ip da co trong bang");
        return; // Nếu đã tồn tại thì không thêm
    }
    else if (my_arp_table_index < MY_ARP_TABLE_SIZE) {
        my_arp_table[my_arp_table_index].ip = *ip;
        memcpy(my_arp_table[my_arp_table_index].mac, mac, 6);
        my_arp_table[my_arp_table_index].status= UNTRUSTED;
        //my_arp_table[my_arp_table_index].active = 1;

        my_arp_table_index++;
        ESP_LOGI(TAG, "da them thiet bi vao bang arp");
        for(int i = 0;i<my_arp_table_index;i++)
        {
            ESP_LOGI(TAG, "IP: %s MAC: %02X:%02X:%02X:%02X:%02X:%02X Status: %s",
                ip4addr_ntoa(&my_arp_table[i].ip),
                my_arp_table[i].mac->addr[0], my_arp_table[i].mac->addr[1], 
                my_arp_table[i].mac->addr[2], my_arp_table[i].mac->addr[3], 
                my_arp_table[i].mac->addr[4], my_arp_table[i].mac->addr[5],
                status_labels[my_arp_table[i].status]);
        }
    }
}
// hàm kiểm tra trùng ip
u8_t my_etharp_find_entry(ip4_addr_t *ip) {
    //ESP_LOGI(TAG, "da vao ham my_etharp_find_entry");
    for (int i = 0; i < my_arp_table_index; i++) {
      if (ip4_addr_cmp(&my_arp_table[i].ip, ip)) {
        return 1; // Đã tồn tại
      }
    }
    return 0; // Chưa tồn tại
}

void my_nac_arp_scan(esp_netif_t *eth_netif){
    struct netif *lwip_netif = esp_netif_get_netif_impl(eth_netif);
    ip4_addr_t ipser;
    ip4_addr_t current_ip = lwip_netif->ip_addr.u_addr.ip4;
    uint8_t first_octet = ip4_addr1(&current_ip);
    uint8_t second_octet = ip4_addr2(&current_ip);
    uint8_t third_octet = ip4_addr3(&current_ip);
    uint8_t new_octet4;
    //hàm gui arp
    for(int i=0;i<=255;i++)
    {
       new_octet4 = i;
       IP4_ADDR(&ipser, first_octet, second_octet, third_octet, new_octet4);
       etharp_request(lwip_netif, &ipser);
       vTaskDelay(1 / portTICK_PERIOD_MS); //thoi gian giua hai goi arp quet
    }
}

void my_nac_arp_block(esp_netif_t *eth_netif, struct eth_addr target_mac, ip4_addr_t target_ip, struct eth_addr block_mac, ip4_addr_t block_ip){
    // printf("Thuc hien block\n");//  tức là hàm gốc này sẽ sửa mỗi khi có 1 tk thay đổi chỉ 1 địa chỉ ip của 1 tk thôi là cũng dính rồi
    struct netif *lwip_netif = esp_netif_get_netif_impl(eth_netif);
    my_copy_etharp_raw(lwip_netif,
                (struct eth_addr *)lwip_netif->hwaddr, &target_mac,//  này gọi là GARP: ip gửi và ip nhận là giống nhau==> dùng để 
                (struct eth_addr *)lwip_netif->hwaddr, &block_ip,  //   chuyển địa chỉ của mình sang fake:==> chặn tk block
                &mac_boardcast, &block_ip, ARP_REQUEST);
    my_copy_etharp_raw(lwip_netif,
                (struct eth_addr *)lwip_netif->hwaddr, &target_mac,
                (struct eth_addr *)lwip_netif->hwaddr, &block_ip,
                &mac_boardcast, &block_ip, ARP_REPLY);
    my_copy_etharp_raw(lwip_netif,
                (struct eth_addr *)lwip_netif->hwaddr, &block_mac,
                (struct eth_addr *)lwip_netif->hwaddr, &target_ip,// gửi arp giả mạo cho thằng bị chặn==> khỏi lấy thông tin
                &block_mac, &block_ip, ARP_REPLY);
    for(int i = 0; i< my_arp_table_index;i++)
    {
        // if(my_arp_table[i].status!= BLOCKED)
        // {
            my_copy_etharp_raw(lwip_netif,
                (struct eth_addr *)lwip_netif->hwaddr, &target_mac,// này dùng để bảo target là mình là người có ip của tk giả mạo
                (struct eth_addr *)lwip_netif->hwaddr, &block_ip,
                &target_mac, &my_arp_table[i].ip, ARP_REPLY);  
        // }
    }
    for(int i = 0; i< my_arp_table_index;i++)
    {
        if(ip4_addr_cmp(&my_arp_table[i].ip, &block_ip))
        {
            my_arp_table[i].status = BLOCKED;
            break;
        }
    }
}

void my_nac_arp_unblock(esp_netif_t *eth_netif, struct eth_addr unblock_mac, ip4_addr_t unblock_ip){
    struct netif *lwip_netif = esp_netif_get_netif_impl(eth_netif);
    for(int i = 0; i< my_arp_table_index;i++)
    {
        if(!ip4_addr_cmp(&my_arp_table[i].ip, &unblock_ip))
        {
            my_copy_etharp_raw(lwip_netif,                                // gửi địa chỉ thằng chặn cho mọi người
                (struct eth_addr *)lwip_netif->hwaddr, my_arp_table[i].mac,
                &unblock_mac, &unblock_ip,  
                my_arp_table[i].mac, &my_arp_table[i].ip, 
                ARP_REPLY);
            my_copy_etharp_raw(lwip_netif,                                // gửi địa chỉ mọi người cho thằng chặn
                (struct eth_addr *)lwip_netif->hwaddr, &unblock_mac,
                my_arp_table[i].mac, &my_arp_table[i].ip, 
                &unblock_mac, &unblock_ip,  
                ARP_REPLY);
        }
    }
    for(int i = 0; i< my_arp_table_index;i++)
        {
        if(ip4_addr_cmp(&my_arp_table[i].ip, &unblock_ip))
        {
            my_arp_table[i].status = UNTRUSTED;
            break;
        }
    }
}

void check_free_memory() {
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    printf("Free heap: %u bytes, Largest block: %u bytes\n", (unsigned int)free_heap, (unsigned int)largest_block);
}
