#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend a request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/

void sr_handle_arpreq(struct sr_arpreq*  req, 
                      struct sr_instance *sr)
{
    time_t now = time(NULL); 
    /* 1: Check if larger than 1.0s, if not just return */
    /*struct sr_arpreq* next = req->next;*/
    if (difftime(now, req->sent)>=1.0) 
    {
        printf("difftime(now, req->sent)>=1.0\n");
        /*2: Check if ARP request has been sent >= 5 times */
        if(req->times_sent >= 5) 
        {
            printf("req->times_sent >= 5\n");
            struct sr_packet *packetstr = req->packets;
            while(packetstr)
            {
                printf("new packetstr\n");
                /* routing table request, get interface from there; need to look up destination of icmp packet 
                that's what helps us get the actual interface */

                uint8_t *packet = packetstr->buf;
                sr_ethernet_hdr_t *eth_head = (sr_ethernet_hdr_t*) (packet);
                sr_ip_hdr_t *ip_head = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
                struct sr_rt *in_table = sr_rt_calc(sr, ip_head->ip_dst);
                printf("headers retrieved\n");

                if (!in_table)
                {
                    printf("not in table sr_handle_arpreq\n");
                    packetstr = packetstr->next;
                    continue;
                }

                char *interface = in_table->interface;

                /*2a: send DEST_HOST_UNREACHABLE ICMP Type 3, Code 1 packet back to sender*/
                printf("Type 3: DEST_HOST_UNREACHABLE Packet\n");
                unsigned int outgoing_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_head->ip_len);
                uint8_t *send_icmp = (uint8_t*) malloc(outgoing_len);
                printf("send_icmp malloc done block: %s || bytes: %d\n", send_icmp, outgoing_len);
                sr_ethernet_hdr_t *send_ethernet_head = (sr_ethernet_hdr_t*) (send_icmp);        
                sr_ip_hdr_t *send_ip_head = (sr_ip_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t));
                sr_icmp_t3_hdr_t *send_icmp_head = (sr_icmp_t3_hdr_t*) (send_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                struct sr_if *o_interface = sr_get_interface(sr, interface); 
                uint32_t source_ip = o_interface->ip;
                    
                /* Prepare ICMP Header */
                memcpy(send_icmp_head->data, ip_head, 28 * sizeof(uint8_t)); 
                send_icmp_head->icmp_code = 1;
                send_icmp_head->icmp_type = 3;
                send_icmp_head->icmp_sum = 0;
                send_icmp_head->icmp_sum = cksum(send_icmp_head, outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                    
                print_hdr_icmp((uint8_t *)send_icmp_head);

                /* Prepare IP Header */
                memcpy(send_ip_head, ip_head, sizeof(sr_ip_hdr_t)); 
                send_ip_head->ip_src = source_ip;
                send_ip_head->ip_dst = ip_head->ip_src;
                send_ip_head->ip_ttl = 100; /* 64 == INIT_TTL */
                send_ip_head->ip_p = 1; /* 1 == ip_protocol_icmp */
                send_ip_head->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
                send_ip_head->ip_sum = 0;
                send_ip_head->ip_sum = cksum(send_ip_head, outgoing_len - sizeof(sr_ethernet_hdr_t));

                print_hdr_ip((uint8_t *)send_ip_head);

                /* Prepare Ethernet Header */
                struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ip_head->ip_src);

                memcpy(send_ethernet_head->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
                memcpy(send_ethernet_head->ether_shost, o_interface->addr, sizeof(o_interface->addr));
                send_ethernet_head->ether_type = eth_head->ether_type;

                print_hdr_eth((uint8_t *)send_ethernet_head);

                /* Send back to Sender*/
                sr_send_packet(sr, send_icmp, outgoing_len, interface);
                    
                /* Free and Return */
                free(arp_entry);
                free(send_icmp);

                /*2b: destroy ARP request*/
                
                /* get next packet */
                packetstr = packetstr->next;
            }
        sr_arpreq_destroy(&(sr->cache), req);
        } 
        /*3: If ARP request has been sent <5 times*/
        else if(req->times_sent < 5) 
        {
            /*3a: send ARP request packet again*/
            req->times_sent = req->times_sent +1;
            req->sent = now;
            /* packet from the packet list */
            struct sr_packet *packetstr = req->packets;
  /*          sr_arp_hdr_t *arp_head = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)); */
            /*3b: updates the times_sent and current send time*/
            /* / *** All info is in the received input packet. Lookup source MAC in sr_if struct of outgoing interface** */
            /* outgoing interface so this has our info in it */
            struct sr_if* intface = sr_get_interface(sr,packetstr->iface);
            /* Generate correct ARP response */
            /* 1. Malloc a space to store the Ethernet and ARP header */
            uint8_t* Eth_Arp_Buf = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
            /* 2. Fill the ARP Header (Opcode, sender IP, Sender MAC, Target IP, Target MAC) */
            sr_arp_hdr_t* temp = (sr_arp_hdr_t*) (Eth_Arp_Buf + sizeof(sr_ethernet_hdr_t));
            temp->ar_hrd = htons(1); /* ARP_hdr->ar_hrd */  
            temp->ar_pro = htons(0x0800); /* 0x0800 ARP_hdr->ar_pro*/
            temp->ar_hln = 6; /* ARP_hdr->ar_hln*/
            temp->ar_pln = 4; /* ARP_hdr->ar_pln */
            temp->ar_op  = htons(1); /* htons(arp_op_request) == 0x0001 */
            /*temp->ar_tha = 0xff; */
            memset(temp->ar_tha,0xff,6*sizeof(unsigned char));
            temp->ar_tip = req->ip; /* arp_head->ar_sip */
            /* get interface struct */
            /* interface is the same as the interface in the packet */
            /*continue filling ARP*/
            memcpy(temp->ar_sha,intface->addr,sizeof(intface->addr));
            temp->ar_sip = intface->ip;
            /* 3. Fill Ethernet Header (Source MAC, Dest MAC, Ethernet type) */
            sr_ethernet_hdr_t* temp2 = (sr_ethernet_hdr_t*) Eth_Arp_Buf;
            /* Set manually */
            memset(temp2->ether_dhost,0xff,6*sizeof(unsigned char));
            memcpy(temp2->ether_shost,intface->addr,sizeof(intface->addr));
            temp2->ether_type = htons(ethertype_arp);

            sr_send_packet(sr,Eth_Arp_Buf,sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t),packetstr->iface);
            free(Eth_Arp_Buf);
        }
    }
    return;
}

void sr_arpcache_sweepreqs(struct sr_instance *sr) 
{
    /*Logic: for each ARP request in the ARP cache, check whether time between current and last sent is larger than 1sec
    if not larger than 1sec, return*/
    struct sr_arpreq *req;
    struct sr_arpreq *next = NULL;
    for (req = sr->cache.requests; req != NULL; req = next) 
    {
        next = req->next;
        sr_handle_arpreq(req, sr);
    }
    return;
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = NULL;
        if (req->packets == NULL){
            req->packets = new_pkt;
        }
        else{
            struct sr_packet *p = req->packets;
            while(p->next != NULL)
                p = p->next;
            p->next = new_pkt;
        }
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

