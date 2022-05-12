#ifndef FLUTTER_PLUGIN_D4FT3_FFI_PLUGIN_H_
#define FLUTTER_PLUGIN_D4FT3_FFI_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace d4ft3_ffi {

class D4ft3FfiPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  D4ft3FfiPlugin();

  virtual ~D4ft3FfiPlugin();

  // Disallow copy and assign.
  D4ft3FfiPlugin(const D4ft3FfiPlugin&) = delete;
  D4ft3FfiPlugin& operator=(const D4ft3FfiPlugin&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace d4ft3_ffi

#endif  // FLUTTER_PLUGIN_D4FT3_FFI_PLUGIN_H_
