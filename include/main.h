/**
 * Created by OliverDD on 2020/5/21.
 */

#ifndef PCAPPARSER_MAIN_H
#define PCAPPARSER_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap.h"
#include "tools.h"

typedef struct Result{
    uint32_t src;
    uint32_t des;
    uint32_t size;
    struct TimeStamp timestamp;
}Result;

Result *handleTlv(FILE *);

#endif //PCAPPARSER_MAIN_H
