#ifndef __MAP_H_
#define __MAP_H_

#ifdef __cplusplus
extern "C" {
#endif


#include "afp.h"

#define AFP_MAPPING_UNKNOWN 0
#define AFP_MAPPING_COMMON 1
#define AFP_MAPPING_LOGINIDS 2
#define AFP_MAPPING_NAME 3

unsigned int map_string_to_num(char * name);
char * get_mapping_name(struct afp_volume * volume);

#ifdef __cplusplus
}
#endif

#endif
