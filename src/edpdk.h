/**
 * Copyright (c) 2013 Tieto Global Oy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _EDPDK_H_
#define _EDPDK_H_

#define PACKET_SIZE         2048
#define BUF_SIZE            (PACKET_SIZE)
#define READ_SIZE           (BUF_SIZE)

#define HEADER_SIZE         2
#define HEADER_BYTES_COUNT  2

#define CMD_ARITY           3
#define RESULT_ARITY        2

/* Port encode/decode session info. */
struct port_se {
    int offset;
    int version;
    int arity;
    int type;
    long int pkt_len;
    ei_x_buff result;
    unsigned char rpacket[PACKET_SIZE];
    unsigned char xpacket[PACKET_SIZE];
    char cmd[MAXATOMLEN];
    unsigned long port;
};

#endif
