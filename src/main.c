#include "main.h"

Result *handleTlv(FILE *file) {
    Result *result = malloc(sizeof(Result));
    /* 读入数据包头 */
    PcapPacketHeader *p = readPcapPacketHeader(file);
    memcpy(&(result->timestamp), &(p->timestamp), sizeof(struct TimeStamp));
    memcpy(&(result->size), &(p->len), sizeof(p->len));
    uint64_t START_POINT = ftell(file); // 对齐起点
    uint32_t size = 4; // 记录包体前4字节和除去9号TLV的大小；用于9号体内偏移
    //printf("对齐起点是%llx\n", START_POINT);
    /* 读取数据包体 */
    fseek(file, 4, SEEK_CUR);
    //printf("Packet header读入大小为%u\n", result->size);
    uint16_t tlv_len;
    uint16_t tlv_type;
    uint64_t position = 0;
    while (1) {
        fread(&tlv_len, 2, 1, file);
        fread(&tlv_type, 2, 1, file);
        if (tlv_type != 9) { // 跳过当前TLV
            //printf("当前位置%lx, tlv type为%u，tlv len为%u\n", ftell(file), tlv.tlv_type, tlv.tlv_len);
            fseek(file, (tlv_len - 4), SEEK_CUR);
            size += tlv_len;
        } else {
            fseek(file, 12, SEEK_CUR);
            fread(&(result->src), sizeof(result->src), 1, file);
            fread(&(result->des), sizeof(result->des), 1, file);
            long temp = (result->size - (size + 24));
            //printf("9号体偏移%ld\n", temp);
            fseek(file, temp, SEEK_CUR); // 巨坑：使用包大小来偏移，而不是第九TLV；因为可能有最后空白字符
            break;
        }
        position = (ftell(file) - START_POINT) % 4;
        if(position != 0){
            position = 4 - position;
            //printf("=>在文件%lx位置发生对齐    移动%llx\n", ftell(file), position);
            fseek(file, position, SEEK_CUR); // 对齐问题
            size += position;
            //printf("=>移动后位置%lx\n", ftell(file));
        }
    }
    return result;
}

int main() {
    FILE *file = fopen("D:\\Temp\\temp.pcap", "rb");
    FILE *out = fopen("result.csv", "w");
    fseek(file, 0L, SEEK_END);
    long FSIZE = ftell(file);
    fseek(file, 0L, SEEK_SET);
    PcapFileHeader *p = readPcapFileHeader(file);
    if(p->link_type != 239){
        fprintf(stderr, "错误: 该pcap文件不是nflog link type。\n");
        return 1;
    }
    fprintf(out, "src,des,size,timestamp\n");
    while (ftell(file) != FSIZE) {
        Result *result = handleTlv(file);
        fprintf(out, "%u.%u.%u.%u,%u.%u.%u.%u,%u,%lf\n",
               (uint8_t) (((unsigned char *) &(result->src))[0]),
               (uint8_t) (((unsigned char *) &(result->src))[1]),
               (uint8_t) (((unsigned char *) &(result->src))[2]),
               (uint8_t) (((unsigned char *) &(result->src))[3]),
               (uint8_t) (((unsigned char *) &(result->des))[0]),
               (uint8_t) (((unsigned char *) &(result->des))[1]),
               (uint8_t) (((unsigned char *) &(result->des))[2]),
               (uint8_t) (((unsigned char *) &(result->des))[3]),
               result->size,
               (result->timestamp.timestamp_h) + uint2decimal(result->timestamp.timestamp_l)
        );
        free(result);
    }
    free(p);
    fclose(file);
    fclose(out);
    return 0;
}