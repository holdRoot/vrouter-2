#pragma once

int ipv4_route_init(uint32_t nb_entries);

int ipv4_route_add(uint32_t label, uint8_t* ip, struct nexthop* nh);

int ipv4_route_del(uint32_t label, uint8_t* ip);

void* ipv4_lookup(uint32_t label, uint8_t* ip);

int bcast_pkt_handler(CC_UNUSED void* data, struct packet* pkt);