/**
 * Created by OliverDD on 2020/5/21.
 */

#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"

PcapFileHeader *readPcapFileHeader(FILE *file){
    PcapFileHeader *pcapFileHeader = malloc(sizeof(struct PcapFileHeader));
    fread(pcapFileHeader, sizeof(struct PcapFileHeader), 1, file);
    return pcapFileHeader;
}

PcapPacketHeader *readPcapPacketHeader(FILE *file){
    PcapPacketHeader *pcapPacketHeader = malloc(sizeof(struct PcapPacketHeader));
    fread(pcapPacketHeader, sizeof(struct PcapPacketHeader), 1, file);
    return pcapPacketHeader;
}
