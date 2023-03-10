
import 'dart:core';
import 'dart:async';
import 'dart:isolate';
import 'package:flutter/material.dart';
import 'dart:ffi' as ffi;
import 'libpcap/libpcap_bindings.dart';
import 'dart:io' show Directory, Platform, sleep;
import 'package:ffi/ffi.dart';
import 'package:short_uuids/short_uuids.dart';

const uuid = ShortUuid();

class PcapController {
  pcap_if_t? curDev;  // Current selected device
  bool started = false;  // started or not
  late Isolate worker;
  late final LibPcap libpcap;  // pcaplib
  List<pcap_if_t> devices = [];  // device list
  bool devfreshing = false;
  String? outfile;
  int pktCount = 0;
  int pktTotalSize = 0;
  List<Map> packetsInfo = []; // [{index: 1, proto: tcp, src: ip, dst: ip, caplen: 100}]

  PcapController() {
    // load libpcap
    final pcaplib = ffi.DynamicLibrary.open('libpcap.dylib');
    libpcap = LibPcap(pcaplib);
    devices = loadDevInfos();
  }

  List<String> get devNames {
    List<String> names = [];
    for(pcap_if_t dev in devices) {
      if(dev.name != ffi.nullptr) names.add(dev.name.cast<Utf8>().toDartString());
    }
    return names;
  }

  List<pcap_if_t> loadDevInfos() {
    List<pcap_if_t> devices = [];
    ffi.Pointer<pcap_if_t> alldevs = calloc.allocate<pcap_if_t>(1);
    var errbuf = calloc.allocate<ffi.Char>(PCAP_ERRBUF_SIZE);
    libpcap.pcap_findalldevs(
        ffi.Pointer.fromAddress(alldevs.address), errbuf);
    for (var dev = alldevs; dev != ffi.nullptr; dev = dev.ref.next) {
      if(dev != ffi.nullptr && dev.ref.name != ffi.nullptr) devices.add(dev.ref);
    }
    return devices;
  }

  void addPktInfo(String proto, String src, String dst, int capLen) {
    packetsInfo.add({
      'index': uuid.generate(),
      'proto': proto,
      'src': src,
      'dst': dst,
      'caplen': capLen
    });
  }

  // String get devNet {
  //   var errbuf = calloc.allocate<ffi.Char>(PCAP_ERRBUF_SIZE);
  //   ffi.Pointer<ffi.UnsignedInt> net = calloc.allocate<ffi.UnsignedInt>(1)
  //   ffi.Pointer<ffi.UnsignedInt> mask = calloc.allocate<ffi.UnsignedInt>(1);
  //   if(curDev != ffi.nullptr) {
  //     libpcap.pcap_lookupnet(curDev!.name, net, mask, errbuf);
  //   }
  //   return net.cast<ffi.Uint32>().asTypedList<ffi.Uint8>();
  // }

  Future<void> refresh() async {
    devices = loadDevInfos();
  }
}

