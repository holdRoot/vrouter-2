#pragma once

int virtio_tx_packet(CC_UNUSED void* data, struct packet* pkt);

void* virtio_rx_packet(void* arg);

