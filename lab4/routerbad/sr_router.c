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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t            *packet/* lent */,
                     unsigned int       len,
                     char               *interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */

  if (ethertype_ip == ethertype(packet)) 
  {
    printf("IP Packet \n");
    sr_handleippacket(sr, packet, len, interface);
  } 
  else if (ethertype_arp == ethertype(packet)) 
  {
    printf("ARP Packet \n");
    sr_handlearppacket(sr, packet, len, interface);
  }

}/* end sr_handlepacket */


void sr_handleippacket(struct sr_instance  *sr,
                       uint8_t             *packet/* lent */,
                       unsigned int        len,
                       char                *interface/* lent */)
{
 
  /* Headers */ 
  printf("Making Headers: ");
  sr_ethernet_hdr_t *eth_head = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t *ip_head = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_head = (sr_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
  struct sr_if *t_iface = sr_get_interface(sr, interface);
  printf("DONE! \n");


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
      /* int header_len = sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); */
      unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
      uint8_t *send_icmp = (uint8_t*) malloc(outgoing_len);
      printf("send_icmp malloc done block: %s || bytes: %d\n", send_icmp, outgoing_len);
      /* memset(send_icmp, 0, sizeof(uint8_t) * outgoing_len); */


      /* Step 2bi2b: Fill ICMP Code, type in ICMP header */
      /*** Check if icmp header should be sr_icmp_t8_hdr_t ***/
      sr_ethernet_hdr_t *send_ethernet_head = (sr_ethernet_hdr_t*) (send_icmp);        
      sr_ip_hdr_t *send_ip_head = (sr_ip_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t));
      sr_icmp_hdr_t *send_icmp_head = (sr_icmp_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      
      struct sr_if *o_interface = sr_get_interface(sr, interface);
      /*uint32_t source_ip = o_interface->ip;
      */

      /* Step 2bi2c: Prepare ICMP Header*/
      /* Make sure checksum is done correctly */
      int icmp_len = outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
      memcpy(send_icmp_head, icmp_8head, icmp_len); 
      send_icmp_head->icmp_code = 0;
      send_icmp_head->icmp_type = 0;
      send_icmp_head->icmp_sum = 0;
      send_icmp_head->icmp_sum = cksum(send_icmp_head, icmp_len);

      print_hdr_icmp((uint8_t *)send_icmp_head);

      /* Step 2bi2d: Prepare IP Header*/
      memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
      int ip_len = outgoing_len - sizeof(sr_ethernet_hdr_t);
      send_ip_head->ip_src = ip_head->ip_dst;
      send_ip_head->ip_dst = ip_head->ip_src;
      send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
      send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
      send_ip_head->ip_len = htons(ip_len);
      send_ip_head->ip_sum = 0;
      send_ip_head->ip_sum = cksum(send_ip_head, ip_len);


      print_hdr_ip((uint8_t *)send_ip_head);

      /* Step 2bi2e: Prepare Ethernet Header*/
      /* Change here since  */ 
      /*
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

      memcpy(send_ethernet_head->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_shost, t_iface->addr, sizeof(t_iface->addr));

      send_ethernet_head->ether_type = eth_head->ether_type; */
      memcpy(send_ethernet_head->ether_dhost, o_interface->addr, sizeof(o_interface->addr));
      memcpy(send_ethernet_head->ether_shost, eth_head->ether_shost, sizeof(eth_head->ether_shost));

      send_ethernet_head->ether_type = eth_head->ether_type;
      
      print_hdr_eth((uint8_t *)send_ethernet_head);

      /* Step 2bi3: Send back to Sender*/
      sr_send_packet(sr, send_icmp, outgoing_len, interface);
      
      /* Free and Return */
      /* free(arp_entry); */
      free(send_icmp);
      return;


    }
    else 
    /* Step 2bii: Type 3 ICMP Destination Protocol Unreachable */
    {

      /* Copying Step 2bii2: Generate Correct ICMP Destination protocol unreachable (DRU) packet */      
      printf("Type 3: DRU Packet\n");

      /* Step 2bii2a: Generate Correct ICMP DRU packet */
      /* int header_len = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t); */
      unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
      uint8_t *send_icmp = (uint8_t*) malloc(outgoing_len);
      printf("send_icmp malloc done block: %s || bytes: %d\n", send_icmp, outgoing_len);
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
      int icmp_len = outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
      send_icmp_head->icmp_code = 3;
      send_icmp_head->icmp_type = 3;
      send_icmp_head->icmp_sum = 0;
      send_icmp_head->icmp_sum = cksum(send_icmp_head,icmp_len);

      print_hdr_icmp((uint8_t *)send_icmp_head);

      /* Step 2bii2d: Prepare IP Header */
      memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
      int ip_len = outgoing_len - sizeof(sr_ethernet_hdr_t);
      send_ip_head->ip_src = source_ip;
      send_ip_head->ip_dst = ip_head->ip_src;
      send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
      send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
      send_ip_head->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
      send_ip_head->ip_sum = 0;
      send_ip_head->ip_sum = cksum(send_ip_head, ip_len);

      print_hdr_ip((uint8_t *)send_ip_head);

      /* Step 2bii2e: Prepare Ethernet Header */
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

      memcpy(send_ethernet_head->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_shost, t_iface->addr, sizeof(t_iface->addr));
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
      printf("send_icmp malloc done block: %s || bytes: %d\n", send_icmp, outgoing_len);
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
      int icmp_len = outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
      send_icmp_head->icmp_code = 0;
      send_icmp_head->icmp_type = 11;
      send_icmp_head->icmp_sum = 0;
      send_icmp_head->icmp_sum = cksum(send_icmp_head, icmp_len);

      /* Step 2cid: Prepare IP Header */
      memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
      int ip_len = outgoing_len - sizeof(sr_ethernet_hdr_t);
      send_ip_head->ip_src = source_ip;
      send_ip_head->ip_dst = ip_head->ip_src;
      send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
      send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
      send_ip_head->ip_len = htons(ip_len);
      send_ip_head->ip_sum = 0;
      send_ip_head->ip_sum = cksum(send_ip_head, ip_len);

      /* Step 2cie: Prepare Ethernet Header */
      struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

      memcpy(send_ethernet_head->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_shost, t_iface->addr, sizeof(t_iface->addr));
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
      printf("send_icmp malloc done block: %s || bytes: %d\n", send_icmp, outgoing_len);
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
      send_icmp_head->icmp_sum = cksum(send_icmp_head, outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
      
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

      memcpy(send_ethernet_head->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
      memcpy(send_ethernet_head->ether_shost, t_iface->addr, sizeof(t_iface->addr));
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
    /* Step 2ciii: Otherwise */
    {

      unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
          
      ip_head->ip_ttl = ip_head->ip_ttl - 1;
      ip_head->ip_sum = 0;
      ip_head->ip_sum = cksum(ip_head, sizeof(sr_ip_hdr_t));

      /* Make sure to free in all possible cases */
      struct sr_arpentry *check_arp_entry = sr_arpcache_lookup(&(sr->cache), in_table->gw.s_addr);


      sr_ethernet_hdr_t *send_ethernet_head = (sr_ethernet_hdr_t*) (packet);        

      struct sr_if *o_interface = sr_get_interface(sr, in_table->interface); /* note in_table->interface, could just be interface */ 

      memcpy(send_ethernet_head->ether_shost, o_interface->addr, sizeof(o_interface->addr));

      if (!check_arp_entry)
      {
        struct sr_arpreq *queued_arp_req = sr_arpcache_queuereq(&(sr->cache), in_table->gw.s_addr /*ip_head->ip_dst*/,
                                               packet, len, in_table->interface);
        /* maybe there's supposed to be a handle_arpreq(sr, queued_arp_req); call here, but don't think so */
        return;
      }

      memcpy(send_ethernet_head->ether_dhost, check_arp_entry->mac, sizeof(check_arp_entry->mac));
      sr_send_packet(sr, packet, outgoing_len, o_interface->name);
     
      return;

    }
    return;
  }

} /* end sr_handleippacket */



/* Algorithm for longest prefix matching below */ 
struct sr_rt *sr_rt_calc(struct sr_instance  *sr, 
                         uint32_t            destination_ip)
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


void sr_handlearppacket(struct sr_instance  *sr,
                        uint8_t             *packet/* lent */,
                        unsigned int        len,
                        char                *interface/* lent */)
{
  
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) packet;
  /* ARP packet */
  if(ntohs(ethernet_hdr->ether_type) == ethertype_arp) 
  {
      printf("ARP Packet ethertype\n");
      sr_arp_hdr_t* ARP_hdr = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
      if(ntohs(ARP_hdr->ar_op) == arp_op_request) /* if ARP Request */
      {
        printf("ARP Request\n");
        /* insert the Sender MAC to the ARP cache */
        sr_arpcache_insert(&sr->cache,ARP_hdr->ar_sha,ARP_hdr->ar_sip);
        printf("sr_arpcache_insert\n");        

        /* find all pending packets and send out *** NOT FOR CHECKPOINT 1 & 2 */
        struct sr_if *ipiface = sr_get_interface(sr, interface);

/*
        while (req)
        {
          printf("new request\n");
          struct sr_packet *packet1 = req->packets;
          while (packet1) 
          {
            printf("new packet\n");
            sr_send_packet(sr, packet1->buf, packet1->len, packet1->iface);
            packet1 = packet1->next;
          }
          req = req->next;
        } */
        /* Generate correct ARP response
            // 1. Malloc a space to store the Ethernet and ARP header */
            char* Eth_Arp_Buf = (char*) malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
            printf("Eth_Arp_Buf malloc done block: %s \n", Eth_Arp_Buf);
            /* 2. Fill the ARP Header (Opcode, sender IP, Sender MAC, Target IP, Target MAC) */
            sr_arp_hdr_t* temp = (sr_arp_hdr_t*) (Eth_Arp_Buf + sizeof(sr_ethernet_hdr_t));
            temp->ar_hrd = ARP_hdr->ar_hrd;
            temp->ar_pro = ARP_hdr->ar_pro;
            temp->ar_hln = ARP_hdr->ar_hln;
            temp->ar_pln = ARP_hdr->ar_pln;
            temp->ar_op  = htons(arp_op_reply);
            memcpy(temp->ar_tha,ARP_hdr->ar_sha,sizeof(ARP_hdr->ar_sha));
            temp->ar_tip = ARP_hdr->ar_sip;
            print_hdr_arp((uint8_t *)temp);
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
            print_hdr_eth((uint8_t *)temp2);

            /* / *** All info is in the received input packet. Lookup source MAC in sr_if struct of outgoing interface** */
        /* Send ARP response back to the Sender */
        sr_send_packet(sr,(uint8_t*) Eth_Arp_Buf,sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t),interface);
        printf("sent packet\n");
        free(Eth_Arp_Buf);
        printf("freed Eth_Arp_Buf\n");
      }  
      else if(ntohs(ARP_hdr->ar_op) == arp_op_reply)
      {
        printf("ARP Reply\n");
        struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,ARP_hdr->ar_sha,ARP_hdr->ar_sip); 
        printf("sr_arpcache_insert\n");        

        printf("sr_get_interface and sr_arpcache_queuereq done\n");        

        printf("new request\n");
        struct sr_packet *packet1 = req->packets;
        while (packet1) 
        {
          printf("new packet\n");
          sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t* ) packet1->buf;
          memcpy(ether_hdr->ether_dhost, ARP_hdr->ar_sha ,6);
          sr_send_packet(sr, packet1->buf, packet1->len, packet1->iface);
          packet1 = packet1->next;
        }

        sr_arpreq_destroy(&sr->cache, req);
      }
  }

  printf("*** -> Received packet of length %d \n",len);

} /* end sr_handlearppacket */

/*
        int arpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t *arpPacket = (uint8_t*) malloc(arpPacketLen);
        sr_ethernet_hdr_t *send_ethernet_head = (struct sr_ethernet_hdr*) arpPacket;

        uint8_t *mac = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
        for (int i = 0; i < ETHER_ADDR_LEN; i++) 
        {
          mac[i] = 255;
        }
        memcpy(send_ethernet_head->ether_dhost, mac, sizeof(mac));

        struct sr_if *current = sr->if_list;
        uint8_t *thiscopy;

        while(current) 
        {
          memcpy(send_ethernet_head->ether_shost, current->addr, sizeof(current->addr));
          send_ethernet_head->ether_type = htons(ethertype_arp);
  
          sr_arp_hdr_t *arp_head = (sr_arp_hdr_t *) (arpPacket + sizeof(sr_ethernet_hdr_t));
          arp_head->ar_hrd = htons(1);
          arp_head->ar_pro = htons(2048);
          arp_head->ar_hln = 6;
          arp_head->ar_pln = 4;
          arp_head->ar_op = htons(arp_op_request);

          memcpy(arp_head->ar_sha, current->addr, sizeof(current->addr));
          memcpy(arp_head->ar_tha, 0, sizeof(arp_head->ar_tha)); /* make sure right size of copy */
/*
          arp_head->ar_sip = current->ip;
          arp_head->ar_tip = ip; 

          thiscopy = malloc(arpPacketLen);
          memcpy(copyPacket, send_ethernet_head, arpPacketLen);

          sr_send_packet(sr, copyPacket, arpPacketLen, current->name);
          free(thiscopy);

          current = current->next;
        }

        free(mac);
        free(arpPacket);  */