import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'd4ft3_ffi_method_channel.dart';

abstract class D4ft3FfiPlatform extends PlatformInterface {
  /// Constructs a D4ft3FfiPlatform.
  D4ft3FfiPlatform() : super(token: _token);

  static final Object _token = Object();

  static D4ft3FfiPlatform _instance = MethodChannelD4ft3Ffi();

  /// The default instance of [D4ft3FfiPlatform] to use.
  ///
  /// Defaults to [MethodChannelD4ft3Ffi].
  static D4ft3FfiPlatform get instance => _instance;
  
  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [D4ft3FfiPlatform] when
  /// they register themselves.
  static set instance(D4ft3FfiPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
