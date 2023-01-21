import 'dart:core';
import 'dart:isolate';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_pcap_test/packet_worker/packet_worker_bindings.dart';
import 'dart:ffi' as ffi;
import 'libpcap/libpcap_bindings.dart';
import 'dart:io' show Directory, Platform, sleep;
import 'package:ffi/ffi.dart';
import 'package:bot_toast/bot_toast.dart';
import 'pcap_controller.dart';

PcapController pcapController = PcapController();
// load libpcap
final pcaplib = ffi.DynamicLibrary.open('libpcap.dylib');
LibPcap libpcap = LibPcap(pcaplib);

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.cyan,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
      debugShowCheckedModeBanner: false,
      builder: BotToastInit(),
      navigatorObservers: [BotToastNavigatorObserver()],
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});
  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {


  void _startListen() async {
    final reqPort = ReceivePort();
    final rspPort = ReceivePort();
    final capIsolate = Isolate.spawn((sendPort) {
      ffi.Pointer<ffi.Char> dev = "en0".toNativeUtf8().cast<ffi.Char>();
      ffi.Pointer<ffi.Char> errbuf = calloc.allocate<ffi.Char>(PCAP_ERRBUF_SIZE);
      ffi.Pointer<pcap_t> pcap = libpcap.pcap_open_live(dev, 65535, 0, 0, errbuf);
      if (pcap == ffi.nullptr) {
        print("err: ${errbuf.cast<Utf8>().toDartString()}");
        return ;
      }
    }, rspPort.sendPort);
    setState(() {
      pcapController.started = !pcapController.started;
    });
  }

  void _selectDev(pcap_if_t? dev) {
    setState(() {
      pcapController.curDev = dev;
    });
  }

  void _selectOutFile() async {
    String? outputFile = await FilePicker.platform.saveFile(
        dialogTitle: 'Please select an output file:',
        fileName: 'capture.pcap',
        lockParentWindow: true
    );

    debugPrint(outputFile);

    if (outputFile != null) {
      setState(() {
        pcapController.outfile = outputFile;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        elevation: 0,
        title: Text("FluDump", style: TextStyle(color: Colors.white),),
        actions: [
          Container(
            margin: EdgeInsets.symmetric(vertical: 5, horizontal: 5),
            child: pcapController.devices.length == 0 ? ErrIcon() : DropdownButton(
              value: pcapController.curDev ?? pcapController.devices.first,
              items: pcapController.devices.map(
                  (pcap_if_t dev) {
                    return DropdownMenuItem(
                      child: dev.name != ffi.nullptr ? Center(child: Text(dev.name.cast<Utf8>().toDartString())) : Text("UnKnown"),
                      value: dev,
                      alignment: AlignmentDirectional.center,
                    );
                  }
              ).toList(),
              onChanged: _selectDev,
              style: const TextStyle(color: Colors.white),
              alignment: AlignmentDirectional.center,
              dropdownColor: Theme.of(context).primaryColor,
            ),
          ),
          IconButton(
            onPressed: pcapController.devfreshing ? null : () {
              var cancleLoading = BotToast.showLoading();
              pcapController.refresh().then(
                  (v) {
                    debugPrint("Device Updated, refresh GUI: ${pcapController.devNames}");
                    setState(() {
                      pcapController.devices;
                    });
                    cancleLoading();
                    BotToast.showText(text: "Done");
                  }
              );
            },
            icon: const Icon(Icons.refresh, color: Colors.white,),

          ),
        ],
      ),
      body: Column(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: <Widget>[
          Placeholder(),
          Expanded(child: Placeholder()),
          Row(
            mainAxisAlignment: MainAxisAlignment.start,
            children: [
              IconButton(
                  onPressed: _selectOutFile,
                  icon: Icon(Icons.folder),
              ),
              Expanded(
                child: Text(
                  pcapController.outfile ?? "NOT Selected",
                  maxLines: 1,
                ),
              ),

            ],
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _startListen,
        tooltip: 'Increment',
        child:  pcapController.started ? const Icon(Icons.pause) : const Icon(Icons.play_arrow),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}

class ErrIcon extends StatelessWidget {
  const ErrIcon({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return const Icon(Icons.error_outline_outlined, color: Colors.red,);
  }
}
