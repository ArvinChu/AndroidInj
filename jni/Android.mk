LOCAL_PATH 	:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := spice_hook
LOCAL_SRC_FILES := spice_hook.c
LOCAL_C_INCLUDES += $(LOCAL_PATH)/inj
LOCAL_LDLIBS 	+= -L$(SYSROOT)/usr/lib \
					-llog -ldl -lstdc++ -lz \
                   -malign-double -malign-loops -landroid
LOCAL_CFLAGS 	:= -DANDROID -DTHUMB \
					-std=gnu99 -Wall -Wno-sign-compare -Wno-deprecated-declarations -Wl,--no-undefined \
					-fPIC -DPIC -O3 -funroll-loops -ffast-math -funwind-tables -mfpu=neon -mfloat-abi=softfp
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=  hook_mouse.c
LOCAL_MODULE := hook_mouse
LOCAL_LDLIBS += -llog
LOCAL_C_INCLUDES += $(LOCAL_PATH)/inj
include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under, $(LOCAL_PATH))