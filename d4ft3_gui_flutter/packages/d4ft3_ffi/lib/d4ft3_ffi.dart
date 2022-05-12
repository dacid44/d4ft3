
import 'd4ft3_ffi_platform_interface.dart';

class D4ft3Ffi {
  Future<String?> getPlatformVersion() {
    return D4ft3FfiPlatform.instance.getPlatformVersion();
  }
}
