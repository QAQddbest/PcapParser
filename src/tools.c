/**
 * Created by OliverDD on 2020/5/23.
 */

#include "tools.h"

double uint2decimal(uint32_t src){
    double result = 0.0;
    while(src != 0){
        result += src%10;
        result /= 10;
        src /= 10;
    }
    return result;
}