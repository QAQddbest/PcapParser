/**
 * Created by OliverDD on 2020/5/21.
 */

#ifndef PCAPPARSER_PCAP_H
#define PCAPPARSER_PCAP_H

#include <stdint.h>

typedef struct PcapFileHeader{
    uint32_t magic;
    uint16_t major;
    uint16_t minor;
    uint32_t this_zone;
    uint32_t sig_figs;
    uint32_t snap_len;
    uint32_t link_type;
}PcapFileHeader;

typedef struct PcapPacketHeader{
    struct TimeStamp{
        uint32_t timestamp_h;
        uint32_t timestamp_l;
    }timestamp;
    uint32_t cap_len;
    uint32_t len;
}PcapPacketHeader;

PcapFileHeader *readPcapFileHeader(FILE *);
PcapPacketHeader *readPcapPacketHeader(FILE *);

#endif //PCAPPARSER_PCAP_H
