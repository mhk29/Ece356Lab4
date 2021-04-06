/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"
#include <string.h>

void sr_handleippacket(struct sr_instance *, uint8_t *, unsigned int, char *);
void sr_handlearppacket(struct sr_instance *, uint8_t *, unsigned int, char *);
struct sr_rt *sr_rt_calc(struct sr_instance *sr, uint32_t destination_ip);


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/** ARGS:
  * uint8_t* packet -> packet buffer (contains full packet and ethernet header)
  * char* interface -> name of receiving interface
  **/

void sr_handlepacket(struct       sr_instance *sr,
                     uint8_t      *packet/* lent */,
                     unsigned int len,
                     char         *interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */

  if (ethertype_ip == ethertype(packet)) 
  {
    printf("IP Packet \n")
    sr_handleippacket(sr, packet, len, interface);
  } 
  else if (ethertype_arp == ethertype(packet)) 
  {
    printf("ARP Packet \n")
    sr_handlearppacket(sr, packet, len, interface);
  }
}/* end sr_handlepacket */


void sr_handleippacket( struct        sr_instance *sr,
                        uint8_t       *packet/* lent */,
                        unsigned int  len,
                        char          *interface/* lent */)
{
 
  /* Headers */ 
  printf("Making Headers: ")
  sr_ethernet_hdr_t *eth_head = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t *ip_head = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_head = (sr_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
  struct sr_if *t_iface = sr_get_interface(sr, interface);
  printf("DONE! \n")


  if (len < sizeof(sr_ip_hdr_t))
  {
    printf("Headers are too short 0\n");
    return;
  }

  /* Step 2a: Perform IP Header Checksum Calculation */  
  uint16_t ext_sum = ip_head->ip_sum;
  printf("ext_sum: %d\n", ext_sum);
  ip_head->ip_sum = 0;
  ip_head->ip_sum = cksum(ip_head, sizeof(sr_ip_hdr_t));
  printf("ip_head->ip_sum: %d\n", ip_head->ip_sum);

/*
  if (ip_head->ip_sum != 0xffff) 
  {
    printf("Bad IP Checksum 1\n");
    return;
  } 
*/
  if (ip_head->ip_sum != ext_sum) 
  {
    printf("Bad IP Checksum 2\n");
    ip_head->ip_sum = ext_sum;
    return;
  }

  /* Step 2b: If destination router is router's own IP */
  /* First, let's check if this packet is for router's own IP */ 
  struct sr_if *curr = sr->if_list;
  struct sr_if *d_iface = NULL;
  while (curr) 
  {
    if (ip_head->ip_dst == curr->ip) 
    { 
      printf("d_iface != NULL \n");
      d_iface = curr;
      break;
    }
    curr = curr -> next;
  }
  if (d_iface) 
  {
    printf("%d\n",d_iface);
    /* Is the packet an icmp packet? */
    /* Step 2bi: Type 0 ICMP ECHO request */
    if ((uint8_t) ip_protocol_icmp == ip_head->ip_p) 
    { 
      /* Size Check */            
      /*
      if (sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) > len) 
      {
        printf("Headers are too short 1\n");
        return;
      }
      */
      /* This packet is a proper icmp packet */
      /* Let's perform a checksum check for icmp for safety */
      /*
      uint16_t orig_sum = icmp_head->icmp_sum;
      icmp_head->icmp_sum = 0;
      icmp_head->icmp_sum = cksum(icmp_head, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
      if (icmp_head->icmp_sum != orig_sum) 
      {
        printf("Headers are too short 2\n");
        icmp_head->icmp_sum = orig_sum;
        return;
      }
      */

      /* We now know we have an icmp packet */
      /* Step 2bi1: Return if not ICMP ECHO request */
      printf("Echo Type\n");
      sr_icmp_t8_hdr_t *icmp_8head = (sr_icmp_t8_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_8head->icmp_type !=  0x08) 
      {
        printf("Not Echo Type\n");
        return;
      }      


      /* Step 2bi2: Generate Correct ICMP reply packet */
      printf("Type 0: Echo Reply\n");

      /* Step 2bi2a: Generate Correct ICMP reply packet */
      /* int header_len = sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); */
      unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
      uint8_t *send_icmp = (uint8_t*) malloc(outgoing_len);
      printf("send_icmp malloc done block: %d || bytes: %d\n", send_icmp, outgoing_len);
      /* memset(send_icmp, 0, sizeof(uint8_t) * outgoing_len); */


      /* Step 2bi2b: Fill ICMP Code, type in ICMP header */
      /*** Check if icmp header should be sr_icmp_t8_hdr_t ***/
      sr_ethernet_hdr_t *send_ethernet_head = (sr_ethernet_hdr_t*) (send_icmp);        
      sr_ip_hdr_t *send_ip_head = (sr_ip_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t));
      sr_icmp_hdr_t *send_icmp_head = (sr_icmp_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /* 
      struct sr_if *o_interface = sr_get_interface(sr, interface);
      uint32_t source_ip = o_interface->ip;
      */

      /* Step 2bi2c: Prepare ICMP Header*/
      /* Make sure checksum is done correctly */
      memcpy(send_icmp_head, icmp_head, outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)); 
      send_icmp_head->icmp_code = 0;
      send_icmp_head->icmp_type = 0;
      send_icmp_head->icmp_sum = 0;
      send_icmp_head->icmp_sum = cksum(send_icmp_head, sizeof(outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));

      print_hdr_icmp((uint8_t *)send_icmp_head);

      /* Step 2bi2d: Prepare IP Header*/
      memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
      send_ip_head->ip_src = ip_head->ip_dst;
      send_ip_head->ip_dst = ip_head->ip_src;
      send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
      send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
      send_ip_head->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
      send_ip_head->ip_sum = 0;
      send_ip_head->ip_sum = cksum(send_ip_head, outgoing_len - sizeof(sr_ethernet_hdr_t));

      print_hdr_ip((uint8_t *)send_ip_head);

      /* Step 2bi2e: Prepare Ethernet Header*/
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

      memcpy(send_ethernet_head->ether_shost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_dhost, t_iface->addr, sizeof(t_iface->addr));
      send_ethernet_head->ether_type = eth_head->ether_type;
      
      print_hdr_eth((uint8_t *)send_ethernet_head);

      /* Step 2bi3: Send back to Sender*/
      sr_send_packet(sr, send_icmp, outgoing_len, interface);
      
      /* Free and Return */
      free(arp_entry);
      free(send_icmp);
      return;


    }
    else 
    /* Step 2bii: Type 3 ICMP Destination Protocol Unreachable */
    {

      /* Copying Step 2bii2: Generate Correct ICMP Destination protocol unreachable (DRU) packet */      
      printf("Type 3: DRU Packet\n");

      /* Step 2bii2a: Generate Correct ICMP DRU packet */
      /* int header_len = sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); */
      unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
      uint8_t *send_icmp = (uint8_t*) malloc(outgoing_len);
      printf("send_icmp malloc done block: %d || bytes: %d\n", send_icmp, outgoing_len);
      /* memset(send_icmp, 0, sizeof(uint8_t) * outgoing_len); */

      /* Step 2bii2b: Fill ICMP Code, type in ICMP header */
      sr_ethernet_hdr_t *send_ethernet_head = (sr_ethernet_hdr_t*) (send_icmp);        
      sr_ip_hdr_t *send_ip_head = (sr_ip_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t));
      sr_icmp_t3_hdr_t *send_icmp_head = (sr_icmp_t3_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      struct sr_if *o_interface = sr_get_interface(sr, interface);
      uint32_t source_ip = o_interface->ip;
      
      /* Step 2bii2c: Prepare ICMP Header */
      /* Note the below line is different from above, uses ip_head
      Make sure checksum is done correctly */
      memcpy(send_icmp_head->data, ip_head, 28 * sizeof(uint8_t)); 
      send_icmp_head->icmp_code = 3;
      send_icmp_head->icmp_type = 3;
      send_icmp_head->icmp_sum = 0;
      send_icmp_head->icmp_sum = cksum(send_icmp_head, sizeof(sr_icmp_hdr_t));

      print_hdr_icmp((uint8_t *)send_icmp_head);

      /* Step 2bii2d: Prepare IP Header */
      memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
      send_ip_head->ip_src = source_ip;
      send_ip_head->ip_dst = ip_head->ip_src;
      send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
      send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
      send_ip_head->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
      send_ip_head->ip_sum = 0;
      send_ip_head->ip_sum = cksum(send_ip_head, outgoing_len - sizeof(sr_ethernet_hdr_t));

      print_hdr_ip((uint8_t *)send_ip_head);

      /* Step 2bii2e: Prepare Ethernet Header */
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

      memcpy(send_ethernet_head->ether_shost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_dhost, t_iface->addr, sizeof(t_iface->addr));
      send_ethernet_head->ether_type = eth_head->ether_type;

      print_hdr_eth((uint8_t *)send_ethernet_head);

      /* Step 2bii3: Send back to Sender*/
      sr_send_packet(sr, send_icmp, outgoing_len, interface);
      
      /* Free and Return */
      free(arp_entry);
      free(send_icmp);
      return;


    }
  }
  else 
  /* packet is not for router's own IP */
  {
    /* Perform longest prefix matching calculation for Step 2cii */
    struct sr_rt *in_table = sr_rt_calc(sr, ip_head->ip_dst);

    if (ip_head->ip_ttl == 1) 
    /* Step 2ci: Type 11 ICMP Time Exceeded */
    {

      printf("Type 11: DRU Packet\n");

      /* Step 2cia: Generate Correct ICMP Time Exceeded packet */
      /* int header_len = sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); */
      unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
      uint8_t *send_icmp = (uint8_t*) malloc(outgoing_len);
      printf("send_icmp malloc done block: %d || bytes: %d\n", send_icmp, outgoing_len);
      /* memset(send_icmp, 0, sizeof(uint8_t) * outgoing_len); */

      /* Step 2cib: Fill ICMP Code, type in ICMP header */
      sr_ethernet_hdr_t *send_ethernet_head = (sr_ethernet_hdr_t*) (send_icmp);        
      sr_ip_hdr_t *send_ip_head = (sr_ip_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t));
      sr_icmp_t11_hdr_t *send_icmp_head = (sr_icmp_t11_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      struct sr_if *o_interface = sr_get_interface(sr, interface);
      uint32_t source_ip = o_interface->ip;

      /* Step 2cic: Prepare ICMP Header */
      /* Note the below line is different from above, uses ip_head
      Make sure checksum is done correctly */
      memcpy(send_icmp_head->data, ip_head, 28 * sizeof(uint8_t)); 
      send_icmp_head->icmp_code = 0;
      send_icmp_head->icmp_type = 11;
      send_icmp_head->icmp_sum = 0;
      send_icmp_head->icmp_sum = cksum(send_icmp_head, sizeof(sr_icmp_hdr_t));

      /* Step 2cid: Prepare IP Header */
      memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
      send_ip_head->ip_src = source_ip;
      send_ip_head->ip_dst = ip_head->ip_src;
      send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
      send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
      send_ip_head->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
      send_ip_head->ip_sum = 0;
      send_ip_head->ip_sum = cksum(send_ip_head, outgoing_len - sizeof(sr_ethernet_hdr_t));

      /* Step 2cie: Prepare Ethernet Header */
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

      memcpy(send_ethernet_head->ether_shost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_dhost, t_iface->addr, sizeof(t_iface->addr));
      send_ethernet_head->ether_type = eth_head->ether_type;

      print_hdr_eth((uint8_t *)send_ethernet_head);
      print_hdr_ip((uint8_t *)send_ip_head);
      print_hdr_icmp((uint8_t *)send_icmp_head);

      /* Step 2cif: Send back to Sender*/
      sr_send_packet(sr, send_icmp, outgoing_len, interface);
      
      /* Free and Return */
      free(arp_entry);
      free(send_icmp);
      return;

    }
    else if (!in_table) 
    /* Step 2cii: Type 3 ICMP DEST_NET_UNREACHABLE */
    {
      printf("Type 3: DEST_NET_UNREACHABLE Packet\n");

      /* Step 2cii2a: Generate Correct ICMP DRU packet */
      /* int header_len = sizeof(sr_icmp_t11_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); */
      unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
      uint8_t *send_icmp = (uint8_t*) malloc(outgoing_len);
      printf("send_icmp malloc done block: %d || bytes: %d\n", send_icmp, outgoing_len);
      /* memset(send_icmp, 0, sizeof(uint8_t) * outgoing_len); */

      /* Step 2cii2b: Fill ICMP Code, type in ICMP header */
      sr_ethernet_hdr_t *send_ethernet_head = (sr_ethernet_hdr_t*) (send_icmp);        
      sr_ip_hdr_t *send_ip_head = (sr_ip_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t));
      sr_icmp_t3_hdr_t *send_icmp_head = (sr_icmp_t3_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      struct sr_if *o_interface = sr_get_interface(sr, interface);
      uint32_t source_ip = o_interface->ip;
      
      /* Step 2cii2c: Prepare ICMP Header */
      /* Note the below line is different from above, uses ip_head
      Make sure checksum is done correctly */
      memcpy(send_icmp_head->data, ip_head, 28 * sizeof(uint8_t)); 
      send_icmp_head->icmp_code = 0;
      send_icmp_head->icmp_type = 3;
      send_icmp_head->icmp_sum = 0;
      send_icmp_head->icmp_sum = cksum(send_icmp_head, sizeof(sr_icmp_hdr_t));

      print_hdr_icmp((uint8_t *)send_icmp_head);

      /* Step 2ciid: Prepare IP Header */
      memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
      send_ip_head->ip_src = source_ip;
      send_ip_head->ip_dst = ip_head->ip_src;
      send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
      send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
      send_ip_head->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
      send_ip_head->ip_sum = 0;
      send_ip_head->ip_sum = cksum(send_ip_head, outgoing_len - sizeof(sr_ethernet_hdr_t));

      print_hdr_ip((uint8_t *)send_ip_head);

      /* Step 2ciie: Prepare Ethernet Header */
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

      memcpy(send_ethernet_head->ether_shost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_dhost, t_iface->addr, sizeof(t_iface->addr));
      send_ethernet_head->ether_type = eth_head->ether_type;

      print_hdr_eth((uint8_t *)send_ethernet_head);

      /* Step 2ciif: Send back to Sender*/
      sr_send_packet(sr, send_icmp, outgoing_len, interface);
      
      /* Free and Return */
      free(arp_entry);
      free(send_icmp);
      return;
    }
    else
    /* Step 2ciii: Other */
    {
      

    }

    
    return;
  }

} /* end sr_handleippacket */

/* Algorithm for longest prefix matching below */ 
struct sr_rt *sr_rt_calc( struct    sr_instance *sr, 
                          uint32_t  destination_ip)
{/*
    struct sr_rt *routing_table_node = sr->routing_table;
    struct sr_rt *best_match = NULL;
    while (routing_table_node) {
        if ((routing_table_node->dest.s_addr & routing_table_node->mask.s_addr) == (destination_ip & routing_table_node->mask.s_addr)) {
            if (!best_match || (routing_table_node->mask.s_addr > best_match->mask.s_addr)) {
                best_match = routing_table_node;
            }
        }
        routing_table_node = routing_table_node->next;
    }
    return best_match; 
  */

  struct sr_rt* iterator;
  struct sr_rt* matching_prefix = NULL;
  int longest = 0;
  struct in_addr address;
  address.s_addr = destination_ip;
  for (iterator = sr->routing_table; iterator != NULL; iterator = iterator->next) 
  {
    if
      (
        (longest <= iterator->mask.s_addr) 
        && 
        ( (iterator->dest.s_addr & iterator->mask.s_addr) == (address.s_addr & iterator->mask.s_addr) )
      ) 
    {
         longest = iterator->mask.s_addr;
         matching_prefix = iterator;
    }
  }

  return matching_prefix;
  

} /* end sr_rt_calc */


void sr_handlearppacket(  struct        sr_instance* sr,
                          uint8_t       *packet/* lent */,
                          unsigned int  len,
                          char*         interface/* lent */)
{
  
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) packet;
  /* ARP packet */
  if(ntohs(ethernet_hdr->ether_type) == ethertype_arp) 
  {
      sr_arp_hdr_t* ARP_hdr = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
      if(ntohs(ARP_hdr->ar_op) == arp_op_request) /* if ARP Request */
      {
        /* insert the Sender MAC to the ARP cache */
        sr_arpcache_insert(&sr->cache,ARP_hdr->ar_sha,ARP_hdr->ar_sip);
        /* find all pending packets and send out *** NOT FOR CHECKPOINT 1 & 2 ** *
        // Generate correct ARP response
            // 1. Malloc a space to store the Ethernet and ARP header */
            char* Eth_Arp_Buf = (char*) malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
            /* 2. Fill the ARP Header (Opcode, sender IP, Sender MAC, Target IP, Target MAC) */
            sr_arp_hdr_t* temp = (sr_arp_hdr_t*) (Eth_Arp_Buf + sizeof(sr_ethernet_hdr_t));
            /* Set each field manually */
            temp->ar_hrd = ARP_hdr->ar_hrd;
            temp->ar_pro = ARP_hdr->ar_pro;
            temp->ar_hln = ARP_hdr->ar_hln;
            temp->ar_pln = ARP_hdr->ar_pln;
            temp->ar_op  = htons(arp_op_reply);
            memcpy(temp->ar_tha,ARP_hdr->ar_sha,sizeof(ARP_hdr->ar_sha));
            temp->ar_tip = ARP_hdr->ar_sip;
            /* get interface struct */
            struct sr_if* intface = sr_get_interface(sr,interface);
            /*continue filling ARP*/
            memcpy(temp->ar_sha,intface->addr,sizeof(intface->addr));
            temp->ar_sip = intface->ip;
            /* 3. Fill Ethernet Header (Source MAC, Dest MAC, Ethernet type) */
            sr_ethernet_hdr_t* temp2 = (sr_ethernet_hdr_t*) Eth_Arp_Buf;
            /* Set manually */
            memcpy(temp2->ether_dhost,ethernet_hdr->ether_shost,sizeof(ethernet_hdr->ether_shost));
            memcpy(temp2->ether_shost,intface->addr,sizeof(intface->addr));
            temp2->ether_type = htons(ethertype_arp);
            /* / *** All info is in the received input packet. Lookup source MAC in sr_if struct of outgoing interface** */
        /* Send ARP response back to the Sender */
        sr_send_packet(sr,(uint8_t*) Eth_Arp_Buf,sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t),interface);
      }  
  }

  printf("*** -> Received packet of length %d \n",len);

} /* end sr_handlearppacket */
