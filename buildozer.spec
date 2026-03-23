[app]
title = SecureMessenger
package.name = securemessenger
package.domain = com.securemsg
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0.0
requirements = python3,kivy,android,pyjnius,certifi
android.permissions = INTERNET,CAMERA,RECORD_AUDIO,MODIFY_AUDIO_SETTINGS,ACCESS_NETWORK_STATE
android.api = 33
android.minapi = 24
android.arch = arm64-v8a
orientation = portrait
fullscreen = 0
android.allow_backup = True
p4a.branch = master
# icon
# presplash

[buildozer]
log_level = 2
