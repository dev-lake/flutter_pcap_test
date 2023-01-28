//
// Created by Lake on 2023/1/19.
//

#ifndef FLUTTER_PCAP_TEST_CAPTURE_H
#define FLUTTER_PCAP_TEST_CAPTURE_H

#define SIZE_ETHERNET 14
typedef unsigned char u_char;
#include "dart_api.h"
#include "dart_api_dl.h"
#include "dart_native_api.h"

int run_capture(void * data, const char * dev, const char * path);
void set_dart_port(Dart_Port_DL port);
int stop_capture();
// Dart_NativeMessageHandler recvHandler(Dart_Port dest_port_id, Dart_CObject* message);

#endif //FLUTTER_PCAP_TEST_CAPTURE_H
