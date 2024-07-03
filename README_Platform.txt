How to build Module for Platform
- It is only for modules are needed to using Android build system.
- Please check its own install information under its folder for other module.

[Step to build]
1. Get android open source.
    : version info - Android 13.0
    ( Download site : http://source.android.com )

2. Copy module that you want to build - to original android open source
   If same module exist in android open source, you should replace it. (no overwrite)
   
  # It is possible to build all modules at once.
  
3. You should add module name to 'PRODUCT_PACKAGES' in 'build/make/target/product/base_system.mk' as following case.
	case 1) libexifa : should add 'libexifa.camera.samsung' to PRODUCT_PACKAGES
	case 2) libjpega : should add 'libjpega.camera.samsung' to PRODUCT_PACKAGES
	case 3) keyutils : should add 'libknox_keyutils' to PRODUCT_PACKAGES
	

ex.) [build/make/target/product/base_system.mk] - add all module name for case 1 ~ 3 at once
    
# libexifa
PRODUCT_PACKAGES += \
    libexifa.camera.samsung
    
# libjpega
PRODUCT_PACKAGES += \
    libjpega.camera.samsung
    
# KeyUtils
PRODUCT_PACKAGES += \
    libknox_keyutils
   
4. excute build command
   ./build_64bit.sh

5. Note : 
   To download the source code of S/W listed below, please visit http://opensource.samsung.com and find "Mobile -> Mobile Application" menu, 
   and then, you will be able to download what you want. 
   You might save time in finding the right one by making use of the search keyword below. 
	- SamsungDataStore.apk : "SamsungDataStore"
	- AREmoji.apk : "AREmoji"
	- SmartSwitch.apk : "Smart Switch"
	- MdecService.apk : "MdecService"
	- SamsungCamera.apk : "Camera"
	- DeXonPC.apk : "DeXonPC"
	- SamsungCalendar.apk : "SamsungCalendar"
	- SAssistant_downloadable.apk : "SAssistant"
	- VoiceNote_5.0.apk : "Voice Recorder"
	- BixbyWakeup.apk : "BixbyWakeup"
	- SBrowser_18.1.apk : "SBrowser"
	- SamsungConnect.apk : "SamsungConnect"
	- VoiceNote_5.0.apk : "Voice Recorder"
	- SamsungMessages.apk : "Messaging"
	- BixbyVisionFramework3.5.apk : "BixbyVisionFramework"
	- KidsHome.apk : "KidsHome"
	- SamsungConnect.apk : "SamsungConnect"
	- Notes40_Removable.apk : "Samsung Notes"
	- Fmm.apk : "FMM"
	- Notes40_Removable.apk : "Samsung Notes"
	- SmartSwitch.apk : "Smart Switch"
