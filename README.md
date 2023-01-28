# flutter_pcap_test

A project of pcap capture using Flutter & libpcap.

## Compile
### Compile Flutter
flutter build macos

### Compile C lib
cd lib/packet_worker/build
cmake .. && make
复制 libpacket_worker.dylib 到 build/macos/Build/Products/Release/flutter_pcap_test.app/Contents/MacOS

## Run
cd build/macos/Build/Products/Release/flutter_pcap_test.app/Contents/MacOS

sudo ./flutter_pcap_test
