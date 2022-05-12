#include "include/d4ft3_ffi/d4ft3_ffi_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "d4ft3_ffi_plugin.h"

void D4ft3FfiPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  d4ft3_ffi::D4ft3FfiPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
