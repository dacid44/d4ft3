import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:d4ft3_ffi/d4ft3_ffi_method_channel.dart';

void main() {
  MethodChannelD4ft3Ffi platform = MethodChannelD4ft3Ffi();
  const MethodChannel channel = MethodChannel('d4ft3_ffi');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await platform.getPlatformVersion(), '42');
  });
}
