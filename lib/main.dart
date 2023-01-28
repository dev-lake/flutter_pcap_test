import 'dart:core';
import 'dart:isolate';
import 'package:file_picker/file_picker.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter_pcap_test/packet_worker/packet_worker_bindings.dart';
import 'package:horizontal_data_table/horizontal_data_table.dart';
import 'dart:ffi' as ffi;
import 'libpcap/libpcap_bindings.dart';
import 'dart:io' show Directory, Platform, sleep;
import 'package:ffi/ffi.dart';
import 'package:bot_toast/bot_toast.dart';
import 'pcap_controller.dart';
import 'chart.dart';

PcapController pcapController = PcapController();
// load Dart_InitializeApiDL

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

  // 开启或停止抓包
  void _startOrStopListen() async {
    if(!pcapController.started) {
      if(pcapController.curDev == null) {
        BotToast.showText(text: "未选择设备");
        return;
      }
      if(pcapController.outfile == null || pcapController.outfile == "") {
        BotToast.showText(text: "路径未选择");
        return;
      }
      _startListen();
      pcapController.started = true;
      BotToast.showText(text: "开始抓包...");
    } else {
      _stopListen();
      // pcapController.started = false;
      BotToast.showText(text: "结束抓包...");
    }
    setState(() {
       pcapController.started;
    });
  }

  // 向Isolate发送停止指令
  void _stopListen() async {
    stopCapture();
    pcapController.worker.kill(priority: Isolate.immediate);
    BotToast.showLoading(); // 界面 loading 等待 isolate 结束的消息
    setState(() {
      pcapController.pktTotalSize = 0;
      pcapController.pktCount = 0;
    });
  }

  // 生成新的libpcap worker
  void _startListen() async {
    dartInitApiDL(ffi.NativeApi.initializeApiDLData);
    // 生成新的抓包 Isolate
    final rspPort = ReceivePort();
    // 发送 sendport 给 C++
    setDartPort(rspPort.sendPort.nativePort);
    pcapController.worker = await Isolate.spawn(
        _pcapWorker,
        [pcapController.curDev!.name.cast<Utf8>().toDartString(), pcapController.outfile ?? "./capture.pcap"],
        errorsAreFatal: false
    );
    /* 监听Isolate发送来的消息
      并更新到 GUI
     */
    rspPort.listen((message) {
      print("message: ${message}");
      const caplenStrSize = "caplen:".length;
      if(message.toString().isEmpty) {
        print("Received a Empty Packet");
        return;
      }

      if(message.toString() == "isolate:exit") { // 监听 Isolate 退出消息
        BotToast.showText(text: "抓包已结束");
        BotToast.closeAllLoading();
        setState(() {
          pcapController.started = false;
        });
      }
      else {  // 监听数据包消息
        late String proto, src, dst;
        late int capLen;
        pcapController.pktCount++;
        message.toString().split(';').forEach((element) { // element format: key1:value1;key2:value2;key3:value3
          List<String> ele = element.split(':'); // ele format: kay:value
          if(ele.length != 2) {
            debugPrint('err: receive illgeal element $element');
            return;
          }
          print(ele);
          if(ele[0] == 'caplen') { // packet length
            capLen = int.parse(ele[1]);
            pcapController.pktTotalSize += capLen;
          } else if (ele[0] ==  'proto') { // protocol
            proto = ele[1];
          } else if (ele[0] == 'src') { // src IP
            src = ele[1];
          } else if (ele[0] == 'dst') { // dst IP
            dst = ele[1];
          }
        });
        pcapController.addPktInfo(proto, src, dst, capLen);
        print('packetsInfo size ${pcapController.packetsInfo.length}');
        // update GUI
        setState(() {
          pcapController.pktCount;
          pcapController.pktTotalSize;
          pcapController.packetsInfo;
        });
      }


    });

  }

  // Isolate worker
  static void _pcapWorker(List<String> param)  {
    print("start capture ${param[0]}");

    // 调用 libpcap 抓包代码并阻塞
    int ret = runCapture(
      ffi.NativeApi.initializeApiDLData,
      param[0].toNativeUtf8(),
      param[1].toNativeUtf8()
    );

    if (ret == 0) {
      debugPrint('captured stoped normally');
    } else if (ret == 1) {
      debugPrint('failed start capture');
    } else if (ret == 2) {
      debugPrint('pcap_loop err');
    }

    Isolate.exit();
  }

  // 选择设备回调函数
  void _selectDev(pcap_if_t? dev) {
    setState(() {
      pcapController.curDev = dev;
    });
    BotToast.showText(text: '已选择设备[${dev?.name.cast<Utf8>().toDartString()}]');
  }

  // 选择输出文件路径回调设备
  void _selectOutFile() async {
    String? outputFile = await FilePicker.platform.saveFile(
        dialogTitle: 'Please select an output file:',
        fileName: 'capture.pcap',
        lockParentWindow: true
    );

    debugPrint(outputFile);

    if (outputFile != null) {
      BotToast.showText(text: '输出路径已选择');
      setState(() {
        pcapController.outfile = outputFile;
      });
    } else {
      BotToast.showText(text: '已取消路径选择');
    }
  }

  Widget _getTitleItemWidget(String label, double width) {
    return Container(
      child: Text(label, style: TextStyle(fontWeight: FontWeight.bold)),
      width: width,
      height: 30,
      padding: EdgeInsets.fromLTRB(5, 0, 0, 0),
      alignment: Alignment.centerLeft,
    );
  }

  // 标题栏统计数据标题样式
  var statStyle = const TextStyle(color: Colors.white);
  // 标题栏统计数据样式
  var statNumStyle = const TextStyle(fontSize: 18, color: Colors.white, fontWeight: FontWeight.bold);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        elevation: 0,
        title: Text("FluDump", style: TextStyle(color: Colors.white),),
        actions: [
          Column(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              Text(pcapController.pktCount.toString(), style: statNumStyle),
              Text("抓包总数", style: statStyle),
            ],
          ),
          const SizedBox(width: 20),
          Column(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              Text(pcapController.pktTotalSize.toString(), style: statNumStyle),
              Text("总大小", style: statStyle),
            ],
          ),
          const SizedBox(width: 20,),
          Container(
            margin: EdgeInsets.symmetric(vertical: 5, horizontal: 5),
            child: pcapController.devices.length == 0 ? ErrIcon() : DropdownButton(
              value: pcapController.curDev ?? null,
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
          Expanded(
            child: Column(
              mainAxisSize: MainAxisSize.max,
              children: [
                pcapController.started ?
                LineChartSample2() :
                const SizedBox(
                  height: 200,
                  child: Center(
                    child: Text('Ready', style: TextStyle(fontSize: 20, color: Colors.black45),),
                  ),
                ),
                Expanded(
                  child: HorizontalDataTable(
                    leftHandSideColumnWidth: 100,
                    rightHandSideColumnWidth: 700,
                    itemCount: pcapController.packetsInfo.length,
                    isFixedHeader: true,
                    rowSeparatorWidget: const Divider(
                      color: Colors.black54,
                      height: 1.0,
                      thickness: 0.0,
                    ),

                    headerWidgets: [
                      _getTitleItemWidget('#', 100),
                      _getTitleItemWidget('Proto', 100),
                      _getTitleItemWidget('SRC IP', 200),
                      _getTitleItemWidget('DST IP', 200),
                      _getTitleItemWidget('Size', 100),
                    ],
                    leftSideItemBuilder: (ctx, index) {
                      return Container(
                        width: 100,
                        child: Text('$index'),
                      );
                    },
                    rightSideItemBuilder: (ctx, index) {
                      return Row(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          Container(
                            width: 100,
                            child: Text('${pcapController.packetsInfo[index]['proto']}'),
                          ),
                          Container(
                            width: 200,
                            child: Text('${pcapController.packetsInfo[index]['src']}'),
                          ),
                          Container(
                            width: 200,
                            child: Text('${pcapController.packetsInfo[index]['dst']}'),
                          ),
                          Container(
                            width: 100,
                            child: Text('${pcapController.packetsInfo[index]['caplen']}'),
                          ),
                        ],
                      );
                    },
                  ),
                )
              ],
            ),
          ),
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
        onPressed: _startOrStopListen,
        tooltip: pcapController.started ? 'stop' : 'start',
        child:  pcapController.started ? const Icon(Icons.pause) : const Icon(Icons.play_arrow),
      ),
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
