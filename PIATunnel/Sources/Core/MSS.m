//
//  MSS.m
//  PIATunnel
//
//  Created by Davide De Rosa on 2/7/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <arpa/inet.h>

#import "MSS.h"

const int FLAG_SYN      = 2;
const int PROTO_TCP     = 6;
const int OPT_END       = 0;
const int OPT_NOP       = 1;
const int OPT_MSS       = 2;
const int MSS_VAL       = 1250;

typedef struct {
    uint8_t hdr_len:4, ver:4, x[8], proto;
} ip_hdr_t;

typedef struct {
    uint8_t x1[12];
    uint8_t x2:4, hdr_len:4, flags;
    uint16_t x3, sum, x4;
} tcp_hdr_t;

typedef struct {
    uint8_t opt, size;
    uint16_t mss;
} tcp_opt_t;

static inline void MSSUpdateSum(uint16_t* sum_ptr, uint16_t* val_ptr, uint16_t new_val)
{
    uint32_t sum = (~ntohs(*sum_ptr) & 0xffff) + (~ntohs(*val_ptr) & 0xffff) + new_val;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    *sum_ptr = htons(~sum & 0xffff);
    *val_ptr = htons(new_val);
}

void MSSFix(uint8_t *data, NSInteger data_len)
{
    ip_hdr_t *iph = (ip_hdr_t*)data;
    if (iph->proto != PROTO_TCP)  return;
    uint32_t iph_size = iph->hdr_len*4;
    if (iph_size+sizeof(tcp_hdr_t) > data_len)  return;
    
    tcp_hdr_t *tcph = (tcp_hdr_t*)(data + iph_size);
    if (!(tcph->flags & FLAG_SYN))  return;
    uint8_t *opts = data + iph_size + sizeof(tcp_hdr_t);

    uint32_t tcph_len = tcph->hdr_len*4, optlen = tcph_len-sizeof(tcp_hdr_t);
    if (iph_size+sizeof(tcp_hdr_t)+optlen > data_len)  return;

    for (uint32_t i = 0; i < optlen;) {
        tcp_opt_t *o = (tcp_opt_t*)&opts[i];
        if (o->opt == OPT_END)  return;
        if (o->opt == OPT_MSS) {
            if (i+o->size > optlen)  return;
            if (ntohs(o->mss) <= MSS_VAL)  return;
            MSSUpdateSum(&tcph->sum, &o->mss, MSS_VAL);
            return;
        }
        i += (o->opt == OPT_NOP) ? 1 : o->size;
    }
}
