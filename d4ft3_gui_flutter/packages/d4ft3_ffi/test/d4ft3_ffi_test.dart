import 'package:flutter_test/flutter_test.dart';
import 'package:d4ft3_ffi/d4ft3_ffi.dart';
import 'package:d4ft3_ffi/d4ft3_ffi_platform_interface.dart';
import 'package:d4ft3_ffi/d4ft3_ffi_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockD4ft3FfiPlatform 
    with MockPlatformInterfaceMixin
    implements D4ft3FfiPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final D4ft3FfiPlatform initialPlatform = D4ft3FfiPlatform.instance;

  test('$MethodChannelD4ft3Ffi is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelD4ft3Ffi>());
  });

  test('getPlatformVersion', () async {
    D4ft3Ffi d4ft3FfiPlugin = D4ft3Ffi();
    MockD4ft3FfiPlatform fakePlatform = MockD4ft3FfiPlatform();
    D4ft3FfiPlatform.instance = fakePlatform;
  
    expect(await d4ft3FfiPlugin.getPlatformVersion(), '42');
  });
}
