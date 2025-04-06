#pragma once

#include "/jvm/jni.h"
#include "/jvm/jvmti.h"

#include <iostream>
#include <string>
#include <memory>     
#include <filesystem> 
#include <fstream>    
#include <vector>     
#include <atomic>     
#include <sstream>    

#include <windows.h>

void JNICALL ClassFileLoadHook(
    jvmtiEnv* jvmti_env,
    JNIEnv* jni_env,
    jclass class_being_redefined,
    jobject loader,
    const char* name,
    jobject protection_domain,
    jint class_data_len,
    const unsigned char* class_data,
    jint* new_class_data_len,
    unsigned char** new_class_data
);

namespace hook {

    class c_hook
    {
    private: 
        JavaVM* m_vm = nullptr;
        JNIEnv* m_jni_env = nullptr; 
        jvmtiEnv* m_jvmti_env = nullptr;
        bool m_jvmti_hook_active = false;

    public: 
        void logger(const std::string& text);

        c_hook() = default;
        ~c_hook(); 

        c_hook(const c_hook&) = delete;
        c_hook& operator=(const c_hook&) = delete;
        c_hook(c_hook&&) = delete;
        c_hook& operator=(c_hook&&) = delete;

        bool attach(); 
        void detach(); 
        bool setup_jvmti_hooks(); 
        void teardown_jvmti_hooks(); 

    
        bool trigger_retransformation_for_all_classes(); 

    }; 

    inline std::unique_ptr<c_hook> instance;

} 