#include "main.h"

Result *handleTlv(FILE *file) {
    Result *result = malloc(sizeof(Result));
    /* �������ݰ�ͷ */
    PcapPacketHeader *p = readPcapPacketHeader(file);
    memcpy(&(result->timestamp), &(p->timestamp), sizeof(struct TimeStamp));
    memcpy(&(result->size), &(p->len), sizeof(p->len));
    uint64_t START_POINT = ftell(file); // �������
    uint32_t size = 4; // ��¼����ǰ4�ֽںͳ�ȥ9��TLV�Ĵ�С������9������ƫ��
    //printf("���������%llx\n", START_POINT);
    /* ��ȡ���ݰ��� */
    fseek(file, 4, SEEK_CUR);
    //printf("Packet header�����СΪ%u\n", result->size);
    uint16_t tlv_len;
    uint16_t tlv_type;
    uint64_t position = 0;
    while (1) {
        fread(&tlv_len, 2, 1, file);
        fread(&tlv_type, 2, 1, file);
        if (tlv_type != 9) { // ������ǰTLV
            //printf("��ǰλ��%lx, tlv typeΪ%u��tlv lenΪ%u\n", ftell(file), tlv.tlv_type, tlv.tlv_len);
            fseek(file, (tlv_len - 4), SEEK_CUR);
            size += tlv_len;
        } else {
            fseek(file, 12, SEEK_CUR);
            fread(&(result->src), sizeof(result->src), 1, file);
            fread(&(result->des), sizeof(result->des), 1, file);
            long temp = (result->size - (size + 24));
            //printf("9����ƫ��%ld\n", temp);
            fseek(file, temp, SEEK_CUR); // �޿ӣ�ʹ�ð���С��ƫ�ƣ������ǵھ�TLV����Ϊ���������հ��ַ�
            break;
        }
        position = (ftell(file) - START_POINT) % 4;
        if(position != 0){
            position = 4 - position;
            //printf("=>���ļ�%lxλ�÷�������    �ƶ�%llx\n", ftell(file), position);
            fseek(file, position, SEEK_CUR); // ��������
            size += position;
            //printf("=>�ƶ���λ��%lx\n", ftell(file));
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
        fprintf(stderr, "����: ��pcap�ļ�����nflog link type��\n");
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