import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'd4ft3_ffi_platform_interface.dart';

/// An implementation of [D4ft3FfiPlatform] that uses method channels.
class MethodChannelD4ft3Ffi extends D4ft3FfiPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('d4ft3_ffi');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
