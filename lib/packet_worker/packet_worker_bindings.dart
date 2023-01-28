import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';

final dylib = ffi.DynamicLibrary.open('libpacket_worker.dylib');

// runCapture
typedef run_capture_native_t = ffi.Int Function(ffi.Pointer<ffi.Void> data, ffi.Pointer<Utf8> dev, ffi.Pointer<Utf8> path);
typedef run_capture_t        = int Function(ffi.Pointer<ffi.Void> data, ffi.Pointer<Utf8> dev, ffi.Pointer<Utf8> path);

final runCapture = dylib.lookupFunction<run_capture_native_t, run_capture_t>('run_capture');

// stopCapture
typedef stop_capture_native_t = ffi.Int Function();
typedef stop_capture_t = int Function();

final stopCapture = dylib.lookupFunction<stop_capture_native_t, stop_capture_t>('stop_capture');

// dart initialize api dl
typedef dart_init_api_dl_native_t = ffi.Int Function(ffi.Pointer<ffi.Void> data);
typedef dart_init_api_dl_t = int Function(ffi.Pointer<ffi.Void> data);

final dartInitApiDL =
    dylib.lookupFunction<dart_init_api_dl_native_t, dart_init_api_dl_t>('Dart_InitializeApiDL');

// void set_dart_port(Dart_Port_DL port)
typedef Dart_Port_DL_t = ffi.Int64;
typedef set_dart_port_native_t  = ffi.Void Function(Dart_Port_DL_t port);
typedef set_dart_port_t  = void Function(int port);
final setDartPort = dylib.lookupFunction<set_dart_port_native_t, set_dart_port_t>('set_dart_port');