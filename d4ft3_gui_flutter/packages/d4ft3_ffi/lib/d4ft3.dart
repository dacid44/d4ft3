import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'dart:io' show Platform;

typedef HelloWorld = int Function();

typedef SendTextNative = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Uint16);
typedef SendText = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, int);

typedef FreeStringNative = Void Function(Pointer<Utf8>);
typedef FreeString = void Function(Pointer<Utf8>);

DynamicLibrary load({String basePath = ''}) {
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('${basePath}libd4ft3_ffi.so');
  } else if (Platform.isWindows) {
    return DynamicLibrary.open('${basePath}libd4ft3_ffi.dll');
  } else {
    throw UnsupportedPlatform('${Platform.operatingSystem} is not supported!');
  }
}

class UnsupportedPlatform implements Exception {
  UnsupportedPlatform(String s);
}

class D4ft3 {
  static DynamicLibrary? _lib;

  D4ft3() {
    if (_lib != null) return;

    if (Platform.isWindows || Platform.isLinux) {
      _lib = load(basePath: '../target/release/');
    } else {
      _lib = load();
    }
  }

  String sendText(String s, String addr, int port) {
    final send_text = _lib!.lookupFunction<SendTextNative, SendText>('send_text');
    final free_string = _lib!.lookupFunction<FreeStringNative, FreeString>('free_string');

    final sUtf8 = s.toNativeUtf8();
    final addrUtf8 = addr.toNativeUtf8();
    final result = send_text(sUtf8, addrUtf8, port);
    malloc.free(sUtf8);
    malloc.free(addrUtf8);
    final message = result.toDartString();
    free_string(result);

    return message;
  }
}

