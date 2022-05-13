import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'dart:io' show Platform;

class D4ftFfiResult extends Struct {
  external Pointer<Utf8> value;
  external Pointer<Utf8> message;
}

class D4ftResult {
  String value;
  String message;
  D4ftResult(this.value, this.message);
}

typedef SendTextNative = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Uint16, Bool);
typedef SendText = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, int, bool);

typedef ReceiveTextNative = D4ftFfiResult Function(Pointer<Utf8>, Uint16, Bool);
typedef ReceiveText = D4ftFfiResult Function(Pointer<Utf8>, int, bool);

typedef ReceiveTextAsyncNative = Pointer<Utf8> Function(Pointer<Utf8>, Uint16, Bool);
typedef ReceiveTextAsync = Pointer<Utf8> Function(Pointer<Utf8>, int, bool);

typedef SendTextAsyncNative = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Uint16, Bool);
typedef SendTextAsync = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, int, bool);

typedef CancelTask = Pointer<Utf8> Function();

typedef GetResult = D4ftFfiResult Function();

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

  String sendText(String s, String addr, int port, bool connect) {
    final send_text = _lib!.lookupFunction<SendTextNative, SendText>('send_text');
    final free_string = _lib!.lookupFunction<FreeStringNative, FreeString>('free_string');

    final sUtf8 = s.toNativeUtf8();
    final addrUtf8 = addr.toNativeUtf8();
    final result = send_text(sUtf8, addrUtf8, port, connect);
    malloc.free(sUtf8);
    malloc.free(addrUtf8);
    final message = result.toDartString();
    free_string(result);

    return message;
  }

  D4ftResult receiveText(String addr, int port, bool connect) {
    final receive_text = _lib!.lookupFunction<ReceiveTextNative, ReceiveText>('receive_text');
    final free_string = _lib!.lookupFunction<FreeStringNative, FreeString>('free_string');

    final addrUtf8 = addr.toNativeUtf8();
    final result = receive_text(addrUtf8, port, connect);
    malloc.free(addrUtf8);

    final ret = D4ftResult(result.value.toDartString(), result.message.toDartString());
    free_string(result.value);
    free_string(result.message);

    return ret;
  }

  Future<D4ftResult> _waitForResult(String future_result) async {
    final get_result = _lib!.lookupFunction<GetResult, GetResult>('get_result');
    final free_string = _lib!.lookupFunction<FreeStringNative, FreeString>('free_string');

    if (future_result != 'started task') {
      return D4ftResult('', future_result);
    }

    D4ftResult? result;
    while (true) {
      D4ftFfiResult result_ffi = get_result();
      result = D4ftResult(result_ffi.value.toDartString(), result_ffi.message.toDartString());
      free_string(result_ffi.value);
      free_string(result_ffi.message);

      if (result.message != "") {
        break;
      }

      await Future.delayed(const Duration(milliseconds: 100));
    }

    return result;
  }

  Future<String> sendTextAsync(String s, String addr, int port, bool connect) async {
    final send_text_async = _lib!.lookupFunction<SendTextAsyncNative, SendTextAsync>('receive_text_async');
    final free_string = _lib!.lookupFunction<FreeStringNative, FreeString>('free_string');

    final sUtf8 = s.toNativeUtf8();
    final addrUtf8 = addr.toNativeUtf8();
    final future_result_ffi = send_text_async(sUtf8, addrUtf8, port, connect);
    malloc.free(addrUtf8);
    malloc.free(sUtf8);
    final future_result = future_result_ffi.toDartString();
    free_string(future_result_ffi);

    return (await _waitForResult(future_result)).message;
  }

  Future<D4ftResult> receiveTextAsync(String addr, int port, bool connect) async {
    final receive_text_async = _lib!.lookupFunction<ReceiveTextAsyncNative, ReceiveTextAsync>('receive_text_async');
    final free_string = _lib!.lookupFunction<FreeStringNative, FreeString>('free_string');

    final addrUtf8 = addr.toNativeUtf8();
    final future_result_ffi = receive_text_async(addrUtf8, port, connect);
    malloc.free(addrUtf8);
    final future_result = future_result_ffi.toDartString();
    free_string(future_result_ffi);

    return await _waitForResult(future_result);
  }

  String cancelTask() {
    final cancel_task = _lib!.lookupFunction<CancelTask, CancelTask>('cancel_task');
    final free_string = _lib!.lookupFunction<FreeStringNative, FreeString>('free_string');

    final result_ffi = cancel_task();
    final result = result_ffi.toDartString();
    free_string(result_ffi);

    return result;
  }
}

