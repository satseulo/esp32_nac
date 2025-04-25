#include "nac.h"
#include "esp_timer.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"// có hàm void *esp_netif_get_netif_impl(esp_netif_t *esp_netif)
#include "esp_heap_caps.h" // kiểm tra bộ nhớ
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static const char *TAG = "NAC";
extern esp_netif_t *eth_netif;                              // netif được tạo trong file main
extern QueueHandle_t arp_queue;                                     // queue xử lý arp, cũng được tạo trong file main
my_arp_entry_custom_t my_arp_table[MY_ARP_TABLE_SIZE];     // tạo bảng arp
const char* status_labels[] = {                                 //label bằng chữ để in ra màn hình
    "TRUSTED",   // TRUSTED = 0
    "UNTRUSTED", // UNTRUSTED = 1
    "BLOCKED"    // BLOCKED = 2
  };
struct eth_addr mac_boardcast = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};     //  frame mac boardcast
struct eth_addr mac_unknown = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};       //  frame mac unknown
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// hàm nhét gói tin vào queue
void my_enqueue_arp_packet(const arp_packet_info_t *pkt)         
{
    if (arp_queue == NULL) return;
    if (xQueueSend(arp_queue, pkt, pdMS_TO_TICKS(10)) != pdTRUE) {
        ESP_LOGW(TAG, "Queue ARP đầy, bỏ gói");
    }
}
// hàm copy từ etharp, không khác gì hàm gốc. hàm gốc để static nhưng không muốn đổi gốc ==> lôi ra
err_t
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
void setup_ethernet_hook()
{
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
err_t my_ethernet_input(struct pbuf *p, struct netif *netif)
{
    // tạo thêm 1 struct để xử lý code của nac, struct, struct gốc để lwip xử lý
    struct pbuf *local_p;   // Khai báo con trỏ mới để chứa sao chép pbuf
    // Tạo bản sao của pbuf mới
    local_p = pbuf_alloc(PBUF_RAW, p->len, PBUF_POOL);
    if (local_p == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for pbuf");
        return ERR_MEM;
    }

    // Sao chép dữ liệu từ pbuf gốc vào bản sao
    if (pbuf_copy(local_p, p) != ERR_OK) {
        ESP_LOGE(TAG, "Failed to copy pbuf data");
        pbuf_free(local_p);
        return ERR_MEM;
    }

    err_t err = ethernet_input(p, netif);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "ethernet_input failed");
        pbuf_free(local_p);
        return err;
    }
    
    my_check_if_arp(local_p,netif);//thêm hàm check if arp
    return ERR_OK;  // sau khi xử lý xong việc của mình, móc tiếp lại cho lwip xử lý
}
//kiểm tra nếu là arp thì gọi tiếp hàm my_etharp_input
err_t my_check_if_arp(struct pbuf *p, struct netif *netif)
{
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
    else{
         pbuf_free(p);
    }
    return ERR_OK;
}
//hàm xử lý bản tin arp
void my_etharp_input(struct pbuf *p, struct netif *netif)
{
    struct etharp_hdr *hdr;
    /* these are aligned properly, whereas the ARP header fields might not be */
    ip4_addr_t sipaddr, dipaddr;
    struct netif *lwip_netif = esp_netif_get_netif_impl(eth_netif);
    //u8_t for_us, from_us, boardcast;

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

    struct eth_addr src_mac,dst_mac;  // Khai báo biến mac để lưu địa chỉ MAC từ ARP request
    memcpy(src_mac.addr, hdr->shwaddr.addr, 6);
    memcpy(dst_mac.addr, hdr->dhwaddr.addr, 6);
    IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&sipaddr, &hdr->sipaddr);
    IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&dipaddr, &hdr->dipaddr);

  //my_etharp_update_arp_entry(&sipaddr, hdr->shwaddr.addr);   //không cho entry mọi nơi nữa
    switch (hdr->opcode) {
        /* ARP request? */
        case PP_HTONS(ARP_REQUEST):
        {
        /* trường hợp arp request: kiểm tra có ip không? */
        int index;
        my_entry_status_t result = my_check_entry(&sipaddr, &src_mac, &index);
        if(result == MY_ENTRY_STATUS_MATCHED )
        {
            if(my_arp_table[index].status == BLOCKED)    //nhận request(boardcast) từ thằng block 
            {
                ESP_LOGI(TAG, "Nhận ARP request: từ blocked");  
                //==> cần ngăn tk block biết trong mạng và ngăn thằng trong mạng biết thằng block
                add_arp_request_count(index);                          // vẫn phải đếm arp request??

                ESP_LOGI(TAG, "send garp");                                // gửi GARP để chiếm ip của thằng blocked
                arp_packet_info_t garp_pkt;                                
                garp_pkt.netif = lwip_netif;                               // Gán con trỏ netif
                garp_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;  // src_mac: ESP32 MAC 
                garp_pkt.ethdst = mac_boardcast;                           // dest_mac: broadcast FF:FF:FF:FF:FF:FF
                garp_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;   // sender_mac: ESP32 MAC (giả mạo)
                garp_pkt.ipsrc = sipaddr;                                  // sender_ip: IP muốn chặn, là source ip của gói tin gửi đến
                garp_pkt.hwdst = mac_unknown;                              // target_mac: unknown 00:00:00:00:00:00
                garp_pkt.ipdst = sipaddr;                                  // target_ip: trùng sender_ip ⇒ GARP
                garp_pkt.opcode = ARP_REPLY;                               // không gửi garp request vì có thể tk kia phản hồi lại
                my_enqueue_arp_packet(&garp_pkt);
                    
                // nếu nó hỏi đến thằng nào đó trong bảng
                //==> trả lời thằng hỏi là địa chỉ đấy của mình==> thằng hỏi không biết địa chỉ trong mạng==> bảo vệ
                for(int i = 0;i< MY_ARP_TABLE_SIZE;i++)
                {
                    if(ip4_addr_cmp(&my_arp_table[i].ip, &dipaddr))
                    {
                        ESP_LOGI(TAG, "send arp_reinforce");
                            arp_packet_info_t arp_reinforce_pkt;
                            arp_reinforce_pkt.netif = lwip_netif;                                // Gán con trỏ netif
                            arp_reinforce_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;   // src_mac: ESP32 MAC
                            arp_reinforce_pkt.ethdst = src_mac;                                  // dest_mac: MAC của BLOCKED
                            arp_reinforce_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;    // sender_mac: ESP32 MAC 
                            arp_reinforce_pkt.ipsrc = dipaddr;                                   // sender_ip: IP trong mạng (CẦN BẢO VỆ)
                            arp_reinforce_pkt.hwdst = src_mac;                                   // target_mac: MAC của BLOCKED
                            arp_reinforce_pkt.ipdst = sipaddr;                                   // target_ip: IP của BLOCKED
                            arp_reinforce_pkt.opcode = ARP_REPLY;                                // opcode: ARP reply
                            my_enqueue_arp_packet(&arp_reinforce_pkt);
                    }
                }
            }
            else if(my_arp_table[index].status == UNTRUSTED)  //  nhận request từ thằng untrusted
            {
                ESP_LOGI(TAG, "Nhận ARP request: từ untrusted"); 
                // nếu thằng này quét mạng ==> block
                if(add_arp_request_count(index)> ARP_SCAN_DETECT)
                {
                    my_nac_arp_block(eth_netif, my_arp_table[index].mac, my_arp_table[index].ip);
                    break;
                }
                ip4_addr_t honeypot_ip;
                ip4_addr_set(&honeypot_ip, (const ip4_addr_t *)&ESP32_HONEYPOT);
                if(ip4_addr_cmp(&honeypot_ip, &dipaddr))
                {
                    my_nac_arp_block(eth_netif, my_arp_table[index].mac, my_arp_table[index].ip);
                    break;
                }

                ESP_LOGI(TAG, "send arp to blocked");
                // sửa để cho thằng bị block dù nhận được gói tin request boardcast cũng không lưu được thông tin của thằng untrusted
                for (int i = 0; i < MY_ARP_TABLE_SIZE; i++)
                { 
                    if(my_arp_table[i].status == BLOCKED)
                    {
                        // Gửi bản tin ARP giả cho tất cả thiết bị BLOCKED
                            arp_packet_info_t arp_to_blocked_pkt;
                            arp_to_blocked_pkt.netif = lwip_netif;                                   // Gán con trỏ netif
                            arp_to_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;      // src_mac: ESP32 MAC
                            arp_to_blocked_pkt.ethdst = my_arp_table[i].mac;                         // dest_mac: gửi cho BLOCKED
                            arp_to_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;       // sender_mac: ESP32 MAC 
                            arp_to_blocked_pkt.ipsrc = sipaddr;                                      // sender_ip: IP của UNTRUST (CẦN BẢO VỆ)
                            arp_to_blocked_pkt.hwdst = my_arp_table[i].mac;                          // target_mac: MAC của BLOCKED
                            arp_to_blocked_pkt.ipdst = my_arp_table[i].ip;                           // target_ip: IP của BLOCKED
                            arp_to_blocked_pkt.opcode = ARP_REPLY;
                            my_enqueue_arp_packet(&arp_to_blocked_pkt);

                        // nếu bản tin trên thực sự gửi tới 1 IP bị block-> thằng block sẽ trả lời -> mình cần giả bản tin trả lời kìa
                        if (ip4_addr_cmp(&my_arp_table[i].ip, &dipaddr))
                        {
                            arp_packet_info_t arp_from_blocked_pkt;
                            arp_from_blocked_pkt.netif = lwip_netif;                                  // Gán con trỏ netif
                            arp_from_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;     // src_mac: ESP32 MAC
                            arp_from_blocked_pkt.ethdst = src_mac;                                    // dest_mac: MAC của UNTRUST (CẦN BẢO VỆ)
                            arp_from_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;      // sender_mac: ESP32 MAC
                            arp_from_blocked_pkt.ipsrc = dipaddr;                                     // sender_ip: IP bị hỏi (BLOCKED)
                            arp_from_blocked_pkt.hwdst = src_mac;                                     // target_mac: MAC của UNTRUST (CẦN BẢO VỆ)
                            arp_from_blocked_pkt.ipdst = sipaddr;                                     // target_ip: IP của UNTRUST (CẦN BẢO VỆ)
                            arp_from_blocked_pkt.opcode = ARP_REPLY;
                            my_enqueue_arp_packet(&arp_from_blocked_pkt);
                        }
                    }
                }
            }
            else// thiết bị tin tưởng
            {
                ESP_LOGI(TAG, "Nhận ARP request: từ trusted"); 
                add_arp_request_count(index);

                // sửa để cho thằng bị block dù nhận được gói tin request boardcast cũng không lưu được thông tin của thằng trusted
                for (int i = 0; i < MY_ARP_TABLE_SIZE; i++)
                {
                    ESP_LOGI(TAG, "send arp to blocked"); 
                    if(my_arp_table[i].status == BLOCKED)
                    {
                        // Gửi bản tin ARP giả cho tất cả thiết bị BLOCKED
                            arp_packet_info_t arp_to_blocked_pkt;
                            arp_to_blocked_pkt.netif = lwip_netif;                                    // Gán con trỏ netif
                            arp_to_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;       // src_mac: ESP32 MAC
                            arp_to_blocked_pkt.ethdst = my_arp_table[i].mac;                          // dest_mac: MAC của BLOCKED
                            arp_to_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;        // sender_mac: ESP32 MAC 
                            arp_to_blocked_pkt.ipsrc = sipaddr;                                       // sender_ip: IP của TRUSTED (CẦN BẢO VỆ)
                            arp_to_blocked_pkt.hwdst = my_arp_table[i].mac;                           // target_mac: MAC của BLOCKED
                            arp_to_blocked_pkt.ipdst = my_arp_table[i].ip;                            // target_ip: IP của BLOCKED
                            arp_to_blocked_pkt.opcode = ARP_REPLY;
                            my_enqueue_arp_packet(&arp_to_blocked_pkt);

                        // nếu bản tin trên thực sự gửi tới 1 IP bị block-> thằng block sẽ trả lời -> mình cần giả bản tin trả lời kìa
                        if (ip4_addr_cmp(&my_arp_table[i].ip, &dipaddr))
                        {
                            arp_packet_info_t arp_from_blocked_pkt;
                            arp_from_blocked_pkt.netif = lwip_netif;                                  // Gán con trỏ netif
                            arp_from_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;     // src_mac: ESP32 MAC
                            arp_from_blocked_pkt.ethdst = src_mac;                                    // dest_mac: MAC của TRUSTED (CẦN BẢO VỆ)
                            arp_from_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;      // sender_mac: ESP32 MAC
                            arp_from_blocked_pkt.ipsrc = dipaddr;                                     // sender_ip: IP của BLOCKED
                            arp_from_blocked_pkt.hwdst = src_mac;                                     // target_mac: MAC của TRUSTED (CẦN BẢO VỆ)
                            arp_from_blocked_pkt.ipdst = sipaddr;                                     // target_ip: IP của TRUSTED (CẦN BẢO VỆ)
                            arp_from_blocked_pkt.opcode = ARP_REPLY;
                            my_enqueue_arp_packet(&arp_from_blocked_pkt);
                        }
                    }
                }
            }
        }
        else if(result == MY_ENTRY_STATUS_CONFLICT) 
        {
            // trường hợp 1 thằng gửi request bị trùng ip với thằng khác(khác MAC)
            // trường hợp này chỉ gặp 1 lần với mỗi 1 tk trùng ip
            // khi tk trùng ip gửi gói tin đầu tiên==> nó bị block luôn. do trong block phải viết garp rồi nên cũng không cần sửa đích
            // thực ra không giải quyết gì mấy vì vẫn phải garp cả cái ip đấy luôn==> thằng cũ cũng chết==> cảnh báo vẫn ngon nhất
            // gọi hàm block theo địa chỉ mac và ip
            my_etharp_add_entry(&sipaddr, &src_mac, BLOCKED);// thêm entry dạng blocked
            //GỬI GARP, có thể xem xét tắt đi vì cũng không nên block thẳng cái ip kia

            arp_packet_info_t garp_pkt;
            garp_pkt.netif = lwip_netif;                                         // Gán con trỏ netif
            garp_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;            // src_mac: ESP32 MAC
            garp_pkt.ethdst = mac_boardcast;                                     // dest_mac: broadcast FF:FF:FF:FF:FF:FF
            garp_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;             // sender_mac: ESP32 MAC 
            garp_pkt.ipsrc = sipaddr;                                            // sender_ip: IP của BLOCKED
            garp_pkt.hwdst = mac_unknown;                                        // target_mac: unknown 00:00:00:00:00:00
            garp_pkt.ipdst = sipaddr;                                            // target_ip: trùng sender_ip ⇒ GARP
            garp_pkt.opcode = ARP_REPLY;
            my_enqueue_arp_packet(&garp_pkt);
            // đặt cảnh báo trên web
        }
        else
        {
            // trường hợp 1 thằng mới hoàn toàn gửi request
            // sửa để cho thằng bị block dù nhận được gói tin request boardcast cũng không lưu được thông tin của thằng mới
            for (int i = 0; i < MY_ARP_TABLE_SIZE; i++)
            {
                // Gửi bản tin ARP giả cho tất cả thiết bị BLOCKED
                if(my_arp_table[i].status == BLOCKED)
                {
                    // Gửi bản tin ARP giả cho tất cả thiết bị BLOCKED
                        arp_packet_info_t arp_to_blocked_pkt;
                        arp_to_blocked_pkt.netif = lwip_netif;                                    // Gán con trỏ netif
                        arp_to_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;       // src_mac: ESP32 MAC
                        arp_to_blocked_pkt.ethdst = my_arp_table[i].mac;                          // dest_mac: MAC của BLOCKED
                        arp_to_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;        // sender_mac: ESP32 MAC 
                        arp_to_blocked_pkt.ipsrc = sipaddr;                                       // sender_ip: IP của UNTRUST (CẦN BẢO VỆ)
                        arp_to_blocked_pkt.hwdst = my_arp_table[i].mac;                           // target_mac: MAC của BLOCKED
                        arp_to_blocked_pkt.ipdst = my_arp_table[i].ip;                            // target_ip: IP của BLOCKED
                        arp_to_blocked_pkt.opcode = ARP_REPLY;
                        my_enqueue_arp_packet(&arp_to_blocked_pkt);

                    // nếu bản tin trên thực sự gửi tới 1 IP bị block-> thằng block sẽ trả lời -> mình cần giả bản tin trả lời kìa
                    if (ip4_addr_cmp(&my_arp_table[i].ip, &dipaddr))
                    {
                        arp_packet_info_t arp_from_blocked_pkt;
                        arp_from_blocked_pkt.netif = lwip_netif;                                  // Gán con trỏ netif
                        arp_from_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;     // src_mac: ESP32 MAC
                        arp_from_blocked_pkt.ethdst = src_mac;                                    // dest_mac: MAC của UNTRUST (CẦN BẢO VỆ)
                        arp_from_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;      // sender_mac: ESP32 MAC
                        arp_from_blocked_pkt.ipsrc = dipaddr;                                     // sender_ip: IP của BLOCKED
                        arp_from_blocked_pkt.hwdst = src_mac;                                     // target_mac: MAC của UNTRUST (CẦN BẢO VỆ)
                        arp_from_blocked_pkt.ipdst = sipaddr;                                     // target_ip: IP của UNTRUST (CẦN BẢO VỆ)
                        arp_from_blocked_pkt.opcode = ARP_REPLY;
                        my_enqueue_arp_packet(&arp_from_blocked_pkt);
                    }
                }
            }
            // thêm entry dưới dạng UNTRUSTED
            ESP_LOGI(TAG, "TẠO ENTRY MỚI(safe from blocked)");
            my_etharp_add_entry(&sipaddr, &src_mac, UNTRUSTED);

        }
        break;
        }
        case PP_HTONS(ARP_REPLY)://reply là thông thường là tin unicast==> nếu gửi cho nac thì chỉ có 3 trường hợp: đến nac, đến blocked và garp 
        {
            int index;
            my_entry_status_t result = my_check_entry(&sipaddr, &src_mac, &index);
            if (memcmp(ENC28J60_MAC_ADDR, dst_mac.addr, sizeof(struct eth_addr)) == 0)// trùng mac với esp32 (TH1 và 2)
            {
                if(ip4_addr_cmp(&ESP32_IP, &dipaddr))// trùng ip với esp32==> đây là bản tin chỉ gửi cho nac, xuất hiện lúc nac scan
                {
                    if(result == MY_ENTRY_STATUS_MATCHED)// có ip sẵn rồi, không bị trùng
                    {
                        ESP_LOGI(TAG, "Nhận arp reply: gửi cho nac: entry hợp lệ sẵn rồi nên không làm gì");  
                    }
                    else if(result == MY_ENTRY_STATUS_CONFLICT)//bị trùng
                    {
                        ESP_LOGI(TAG, "Nhận arp reply: gửi cho nac: bị trùng ip, block");  
                        // gửi cảnh báo lên webserver
                        // có block không??, giống cái trên
                        my_etharp_add_entry(&sipaddr, &src_mac, BLOCKED);
                        arp_packet_info_t garp_pkt;
                        garp_pkt.netif = lwip_netif;                                         // Gán con trỏ netif
                        garp_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;            // src_mac: ESP32 MAC
                        garp_pkt.ethdst = mac_boardcast;                                     // dest_mac: broadcast FF:FF:FF:FF:FF:FF
                        garp_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;             // sender_mac: ESP32 MAC 
                        garp_pkt.ipsrc = sipaddr;                                            // sender_ip: IP của BLOCKED
                        garp_pkt.hwdst = mac_unknown;                                        // target_mac: unknown 00:00:00:00:00:00
                        garp_pkt.ipdst = sipaddr;                                            // target_ip: trùng sender_ip ⇒ GARP
                        garp_pkt.opcode = ARP_REPLY;
                        my_enqueue_arp_packet(&garp_pkt);
                        // đặt cảnh báo trên web
                    }
                    else//
                    {
                        ESP_LOGI(TAG, "Nhận arp reply: gửi cho nac: tạo entry mới");
                        my_etharp_add_entry(&sipaddr, &src_mac, UNTRUSTED);// tạo entry mới

                    }
                }
                else// đây là trường hợp thiết bị phản hồi cho 1 thiết bị bị block: mac của mình nhưng ip của thằng khác
                {
                    // trường hợp này thực ra không cần làm gì vì cái này chứng tỏ thiết bị bị block đã bị chiếm IP rồi
                    // có thể gửi lên websserver
                }
            }
            else   // khác mac với esp mà vẫn gửi đến mình ==> board cast
            { 
                // kiểm tra nguồn có đáng tin cậy không(block?? trùng ip??)
                // nếu có thì lo bảo vệ thằng này
                // nếu không thì BLOCK luôn
                if(result == MY_ENTRY_STATUS_MATCHED)// có ip sẵn rồi, không bị trùng
                {
                    ESP_LOGI(TAG, "Nhận arp reply: gửi boardcast: kiểm tra thằng gửi có tin được không"); 
                    if(my_arp_table[index].status != BLOCKED)// tin được
                    {
                        ESP_LOGI(TAG, "Nhận arp reply: gửi boardcast: tin được: sửa thằng bị block"); 
                        for (int i = 0; i < MY_ARP_TABLE_SIZE; i++)
                        {
                            if(my_arp_table[i].status == BLOCKED)
                            {
                                // Gửi bản tin ARP giả cho tất cả thiết bị BLOCKED
                                arp_packet_info_t arp_to_blocked_pkt;
                                arp_to_blocked_pkt.netif = lwip_netif;                                   // Gán con trỏ netif
                                arp_to_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;      // src_mac: ESP32 MAC
                                arp_to_blocked_pkt.ethdst = my_arp_table[i].mac;                         // dest_mac: MAC của BLOCKED
                                arp_to_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;       // sender_mac: ESP32 MAC 
                                arp_to_blocked_pkt.ipsrc = sipaddr;                                      // sender_ip: IP của TRUST (CẦN BẢO VỆ)
                                arp_to_blocked_pkt.hwdst = my_arp_table[i].mac;                          // target_mac: MAC của BLOCKED
                                arp_to_blocked_pkt.ipdst = my_arp_table[i].ip;                           // target_ip: IP của BLOCKED
                                arp_to_blocked_pkt.opcode = ARP_REPLY;
                                my_enqueue_arp_packet(&arp_to_blocked_pkt);
                            }
                        }
                    }
                    else// thằng gửi là thằng bị block
                    {
                        ESP_LOGI(TAG, "Nhận arp reply: gửi boardcast: thằng gửi bị block: GARP ngược lại");
                        arp_packet_info_t garp_pkt;
                        garp_pkt.netif = lwip_netif;                                                // Gán con trỏ netif
                        garp_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;                   // src_mac: ESP32 MAC 
                        garp_pkt.ethdst = mac_boardcast;                                            // dest_mac: broadcast FF:FF:FF:FF:FF:FF
                        garp_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;                    // sender_mac: ESP32 MAC 
                        garp_pkt.ipsrc = sipaddr;                                                   // sender_ip: IP muốn chặn
                        garp_pkt.hwdst = mac_boardcast;                                             // target_mac: unknown 00:00:00:00:00:00
                        garp_pkt.ipdst = sipaddr;                                                   // target_ip: trùng sender_ip ⇒ GARP
                        garp_pkt.opcode = ARP_REPLY;
                        my_enqueue_arp_packet(&garp_pkt);
                    }
                }
                else if(result == MY_ENTRY_STATUS_CONFLICT)//bị trùng
                {
                    ESP_LOGI(TAG, "Nhận arp reply: gửi boardcast: bị trùng ip, block");  
                    // gửi cảnh báo lên webserver
                    // có block không??, giống cái trên
                    my_etharp_add_entry(&sipaddr, &src_mac, BLOCKED);
                    arp_packet_info_t garp_pkt;
                    garp_pkt.netif = lwip_netif;                                         // Gán con trỏ netif
                    garp_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;            // src_mac: ESP32 MAC
                    garp_pkt.ethdst = mac_boardcast;                                     // dest_mac: broadcast FF:FF:FF:FF:FF:FF
                    garp_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;             // sender_mac: ESP32 MAC 
                    garp_pkt.ipsrc = sipaddr;                                            // sender_ip: IP của BLOCKED
                    garp_pkt.hwdst = mac_unknown;                                        // target_mac: unknown 00:00:00:00:00:00
                    garp_pkt.ipdst = sipaddr;                                            // target_ip: trùng sender_ip ⇒ GARP
                    garp_pkt.opcode = ARP_REPLY;
                    my_enqueue_arp_packet(&garp_pkt);
                    // đặt cảnh báo trên web
                }
                else// thiết bị mới
                {
                    ESP_LOGI(TAG, "Nhận arp reply: gửi boardcast: tạo entry mới + sửa những thằng blocked"); 
                    my_etharp_add_entry(&sipaddr, &src_mac, UNTRUSTED);// tạo entry mới

                    for (int i = 0; i < MY_ARP_TABLE_SIZE; i++)
                    {
                        if(my_arp_table[i].status == BLOCKED)
                        {
                            // Gửi bản tin ARP giả cho tất cả thiết bị BLOCKED
                            arp_packet_info_t arp_to_blocked_pkt;
                            arp_to_blocked_pkt.netif = lwip_netif;                                   // Gán con trỏ netif
                            arp_to_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;      // src_mac: ESP32 MAC
                            arp_to_blocked_pkt.ethdst = my_arp_table[i].mac;                         // dest_mac: MAC của BLOCKED
                            arp_to_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;       // sender_mac: ESP32 MAC 
                            arp_to_blocked_pkt.ipsrc = sipaddr;                                      // sender_ip: IP của UNTRUST (CẦN BẢO VỆ)
                            arp_to_blocked_pkt.hwdst = my_arp_table[i].mac;                          // target_mac: MAC của BLOCKED
                            arp_to_blocked_pkt.ipdst = my_arp_table[i].ip;                           // target_ip: IP của BLOCKED
                            arp_to_blocked_pkt.opcode = ARP_REPLY;
                            my_enqueue_arp_packet(&arp_to_blocked_pkt);
                        }
                    }
                }
            }
        break;
        }
        default:

        break;
    }
    /* free ARP packet */
    pbuf_free(p);
}
// hàm kiểm tra entry,  nếu có thì trả về vị trí ở biến index, nếu trùng IP thì cho ra trạng thái conflict
my_entry_status_t my_check_entry(const ip4_addr_t *ipaddr, const struct eth_addr *mac, int *matched_index)
{
    bool conflict_found = false;

    for (int i = 0; i < MY_ARP_TABLE_SIZE; i++) {
        if (ip4_addr_cmp(&my_arp_table[i].ip, ipaddr)) {
            // IP trùng
            if (memcmp(my_arp_table[i].mac.addr, mac, sizeof(struct eth_addr)) == 0) {
                // Trường hợp 1: IP & MAC giống
                if (matched_index) *matched_index = i;
                return MY_ENTRY_STATUS_MATCHED;
            } else {
                // Trường hợp 2: IP trùng nhưng MAC khác
                conflict_found = true;
            }
        }
    }

    if (conflict_found) {
        return MY_ENTRY_STATUS_CONFLICT;
    }

    // Trường hợp 3: không có IP nào trùng
    return MY_ENTRY_STATUS_NOT_FOUND;
}
// thêm arp vào bảng: bắt buộc phải biết trước arp entry này đã có trong bảng chưa thì mới gọi cái này
u8_t my_etharp_add_entry(ip4_addr_t *ip, struct eth_addr *mac, my_nac_label status)
{
    ip4_addr_t zero_ip;
    uint8_t zero_mac[6] = {0};
    IP4_ADDR(&zero_ip, 0, 0, 0, 0);

    // Tìm entry trống để thêm
    for (int i = 0; i < MY_ARP_TABLE_SIZE; i++) {
        bool ip_is_zero = ip4_addr_cmp(&my_arp_table[i].ip, &zero_ip);
        bool mac_is_zero = memcmp(my_arp_table[i].mac.addr, zero_mac, 6) == 0;

        if (ip_is_zero && mac_is_zero) {
            // Entry trống, thêm tại đây
            my_arp_table[i].ip = *ip;

            // Sao chép địa chỉ MAC vào bảng ARP
            memcpy(my_arp_table[i].mac.addr, mac->addr, 6);  // Dùng mac->addr để lấy 6 byte MAC

            my_arp_table[i].status = status;

            ESP_LOGI(TAG, "Đã thêm thiết bị vào bảng ARP tại index %d", i);

            // In bảng ARP
            // thấy thừa thì vứt đoạn này đi cũng được
            for (int j = 0; j < MY_ARP_TABLE_SIZE; j++) {
                if (!ip4_addr_cmp(&my_arp_table[j].ip, &zero_ip)) {
                    ESP_LOGI(TAG, "IP: %s MAC: %02X:%02X:%02X:%02X:%02X:%02X Status: %s",
                        ip4addr_ntoa(&my_arp_table[i].ip),
                        my_arp_table[j].mac.addr[0], my_arp_table[j].mac.addr[1], 
                        my_arp_table[j].mac.addr[2], my_arp_table[j].mac.addr[3], 
                        my_arp_table[j].mac.addr[4], my_arp_table[j].mac.addr[5],
                        status_labels[my_arp_table[j].status]);
                }
            }
            return 1;  // Thêm thành công, trả về 1
        }
    }
    // Nếu không còn chỗ trống trong bảng ARP
    ESP_LOGI(TAG, "Bảng ARP đã đầy, không còn chỗ trống để thêm!");
    return 0;  // Không thêm được entry, trả về 0
}
// hàm đếm request liên tiếp
int add_arp_request_count(int index)
{
    int x = esp_timer_get_time();
    if((x - my_arp_table[index].arp_timer) < 10000000 || (my_arp_table[index].arp_timer - x) > 10000000)// thay đổi đơn vị để thành 10 giây
    {
        my_arp_table[index].arp_request_count++;
    }
    else
    {
        my_arp_table[index].arp_timer = esp_timer_get_time();
        my_arp_table[index].arp_request_count = 1;
    }
    ESP_LOGI(TAG, "ARP_REQUEST_COUNT: %d", my_arp_table[index].arp_request_count);
    return my_arp_table[index].arp_request_count;
}
// quét arp, nếu nút không chống rung ==> có thể tràn queue
void my_nac_arp_scan(esp_netif_t *eth_netif)
{
    struct netif *lwip_netif = esp_netif_get_netif_impl(eth_netif);
    ip4_addr_t ipser;
    ip4_addr_t current_ip = lwip_netif->ip_addr.u_addr.ip4;
    uint8_t first_octet = ip4_addr1(&current_ip);
    uint8_t second_octet = ip4_addr2(&current_ip);
    uint8_t third_octet = ip4_addr3(&current_ip);
    uint8_t new_octet4;
    //hàm gửi arp
    for(int i=0;i<=255;i++)
    {
       new_octet4 = i;
       IP4_ADDR(&ipser, first_octet, second_octet, third_octet, new_octet4);
       arp_packet_info_t arp_scan_pkt;
       arp_scan_pkt.netif = lwip_netif;                                    // Gán con trỏ netif
       arp_scan_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;       // src_mac: ESP32 MAC 
       arp_scan_pkt.ethdst = mac_boardcast;                                // dest_mac: broadcast FF:FF:FF:FF:FF:FF
       arp_scan_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;        // sender_mac: ESP32 MAC 
       arp_scan_pkt.ipsrc = current_ip;                                    // sender_ip: ESP32 IP
       arp_scan_pkt.hwdst = mac_unknown;                                   // target_mac: unknown 00:00:00:00:00:00
       arp_scan_pkt.ipdst = ipser;                                         // target_ip: IP scan đến
       arp_scan_pkt.opcode = ARP_REQUEST;
       my_enqueue_arp_packet(&arp_scan_pkt);
    }
}
// block arp, cần cả ip và mac
void my_nac_arp_block(esp_netif_t *eth_netif, struct eth_addr block_mac, ip4_addr_t block_ip){
    ESP_LOGI(TAG, "gọi hàm block ");
    ip4_addr_t zero_ip;
    //uint8_t zero_mac[6] = {0};
    IP4_ADDR(&zero_ip, 0, 0, 0, 0);

    // garp chiếm ip của con cần chặn
    struct netif *lwip_netif = esp_netif_get_netif_impl(eth_netif);
    arp_packet_info_t garp_pkt;
    garp_pkt.netif = lwip_netif;                                        // Gán con trỏ netif
    garp_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;           // src_mac: ESP32 MAC 
    garp_pkt.ethdst = mac_boardcast;                                    // dest_mac: broadcast FF:FF:FF:FF:FF:FF
    garp_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;            // sender_mac: ESP32 MAC 
    garp_pkt.ipsrc = block_ip;                                          // sender_ip: IP muốn chặn
    garp_pkt.hwdst = mac_unknown;                                       // target_mac: unknown 00:00:00:00:00:00
    garp_pkt.ipdst = block_ip;                                          // target_ip: trùng sender_ip ⇒ GARP
    garp_pkt.opcode = ARP_REPLY;
    my_enqueue_arp_packet(&garp_pkt);

    for(int i = 0; i < MY_ARP_TABLE_SIZE;i++)// sửa lại bảng arp của thằng bị block==> không biết mạng có gì
    {
        if(ip4_addr_cmp(&my_arp_table[i].ip, &block_ip) && (memcmp(my_arp_table[i].mac.addr, block_mac.addr, sizeof(struct eth_addr)) == 0))
        {
            // đổi nhãn của thằng này
            my_arp_table[i].status = BLOCKED;
        }
        else if(!ip4_addr_cmp(&my_arp_table[i].ip, &zero_ip))
        {
            // sửa bảng của thằng bị chặn==> blocked không biết thiết bị nào
            arp_packet_info_t arp_to_blocked_pkt;
            arp_to_blocked_pkt.netif = lwip_netif;                               // Gán con trỏ netif
            arp_to_blocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;  // src_mac: ESP32 MAC
            arp_to_blocked_pkt.ethdst = block_mac;                               // dest_mac: MAC của BLOCKED
            arp_to_blocked_pkt.hwsrc = *(struct eth_addr *)lwip_netif->hwaddr;   // sender_mac: ESP32 MAC 
            arp_to_blocked_pkt.ipsrc = my_arp_table[i].ip;                       // sender_ip: IP trong bảng (CẦN BẢO VỆ)
            arp_to_blocked_pkt.hwdst = block_mac;                                // target_mac: MAC của BLOCKED
            arp_to_blocked_pkt.ipdst = block_ip;                                 // target_ip: IP của BLOCKED
            arp_to_blocked_pkt.opcode = ARP_REPLY;
            my_enqueue_arp_packet(&arp_to_blocked_pkt);   
        }
    }
}
// unblock arp, cần cả ip và mac
void my_nac_arp_unblock(esp_netif_t *eth_netif, struct eth_addr unblock_mac, ip4_addr_t unblock_ip){
    ESP_LOGI(TAG, "gọi hàm unblock ");
    ip4_addr_t zero_ip;
    //uint8_t zero_mac[6] = {0};
    IP4_ADDR(&zero_ip, 0, 0, 0, 0);

    // sửa bảng arp của chính con được unblock và tất cả con trong mạng
    // không gửi garp vì thằng blocked cũng sẽ biết
    struct netif *lwip_netif = esp_netif_get_netif_impl(eth_netif);
    for(int i = 0; i < MY_ARP_TABLE_SIZE;i++)// chạy với mỗi thằng trong mạng
    {
        if(ip4_addr_cmp(&my_arp_table[i].ip, &unblock_ip) && (memcmp(my_arp_table[i].mac.addr, unblock_mac.addr, sizeof(struct eth_addr)) == 0))
        {
            // sửa label của thằng được unblock
            my_arp_table[i].status = TRUSTED;
        }
        else if((my_arp_table[i].status != BLOCKED) && (!ip4_addr_cmp(&my_arp_table[i].ip, &zero_ip)))
        {
            // với mấy thằng không bị chặn: sửa lại bảng chuẩn của nó + cho thằng trong bảng biết 
            // gửi cho thằng được unblock
            arp_packet_info_t arp_to_unblocked_pkt;
            arp_to_unblocked_pkt.netif = lwip_netif;                               // Gán con trỏ netif
            arp_to_unblocked_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;  // src_mac: ESP32 MAC
            arp_to_unblocked_pkt.ethdst = unblock_mac;                             // dest_mac: MAC của UNBLOCKED
            arp_to_unblocked_pkt.hwsrc = my_arp_table[i].mac;                      // sender_mac: MAC an toàn
            arp_to_unblocked_pkt.ipsrc = my_arp_table[i].ip;                       // sender_ip: IP an toàn
            arp_to_unblocked_pkt.hwdst = unblock_mac;                              // target_mac: MAC của UNBLOCKED
            arp_to_unblocked_pkt.ipdst = unblock_ip;                               // target_ip: IP của UNBLOCKED
            arp_to_unblocked_pkt.opcode = ARP_REPLY;
            my_enqueue_arp_packet(&arp_to_unblocked_pkt);   
            // gửi cho thằng trong mạng
            arp_packet_info_t arp_table_fix_pkt;
            arp_table_fix_pkt.netif = lwip_netif;                                    // Gán con trỏ netif
            arp_table_fix_pkt.ethsrc = *(struct eth_addr *)lwip_netif->hwaddr;       // src_mac: ESP32 MAC
            arp_table_fix_pkt.ethdst = my_arp_table[i].mac;                          // dest_mac:  MAC an toàn
            arp_table_fix_pkt.hwsrc = unblock_mac;                                   // sender_mac: MAC của UNBLOCKED
            arp_table_fix_pkt.ipsrc = unblock_ip;                                    // sender_ip: IP của UNBLOCKED
            arp_table_fix_pkt.hwdst = my_arp_table[i].mac;                           // target_mac: MAC an toàn
            arp_table_fix_pkt.ipdst = my_arp_table[i].ip;                            // target_ip: IP an toàn
            arp_table_fix_pkt.opcode = ARP_REPLY;
            my_enqueue_arp_packet(&arp_table_fix_pkt); 
        }
    }
}
// in bảng ARP bằng logi
void my_arp_table_print()
{ 
    // IN BẢNG ARP
    ESP_LOGI(TAG, "In bảng ARP");
    for (int j = 0; j < MY_ARP_TABLE_SIZE; j++) {
            ESP_LOGI(TAG, "IP: %s MAC: %02X:%02X:%02X:%02X:%02X:%02X Status: %s",
                ip4addr_ntoa(&my_arp_table[j].ip),
                my_arp_table[j].mac.addr[0], my_arp_table[j].mac.addr[1], 
                my_arp_table[j].mac.addr[2], my_arp_table[j].mac.addr[3], 
                my_arp_table[j].mac.addr[4], my_arp_table[j].mac.addr[5],
                status_labels[my_arp_table[j].status]);
    }
}
// check bộ nhớ trong quá trình debug
void check_free_memory()
{
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    printf("Free heap: %u bytes, Largest block: %u bytes\n", (unsigned int)free_heap, (unsigned int)largest_block);
}
