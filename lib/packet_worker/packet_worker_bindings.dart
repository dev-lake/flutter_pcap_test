import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';

typedef run_capture_native_t = ffi.Int Function(ffi.Pointer<Utf8> dev);
typedef run_capture_t        = int Function(ffi.Pointer<Utf8> dev);

final dylib = ffi.DynamicLibrary.open('libpacket_worker.dylib');

final runCapture = dylib.lookupFunction<run_capture_native_t, run_capture_t>('run_capture');

