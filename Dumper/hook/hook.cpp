
#include "hook.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <algorithm>
#include <atomic>
#include <sstream>

std::atomic<int> unknown_class_counter = 0;

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
    unsigned char** new_class_data)
{
    auto local_instance = hook::instance.get();
    std::string log_name_str = (name ? name : "!!! Nameless Class !!!");

    std::string event_type_log;
    if (class_being_redefined != nullptr) {
        event_type_log = "Retransform/Redefine";
    }
    else {
        event_type_log = "Initial Load";
    }

    std::string common_log_part = ": Class: " + log_name_str +
        " (Length: " + std::to_string(class_data_len) + " bytes)";
    if (local_instance) {
        local_instance->logger("ClassFileLoadHook [" + event_type_log + "]" + common_log_part);
    }
    else {
        std::cerr << "[ClassFileLoadHook] [" << event_type_log << "]" << common_log_part
            << " (instance is null!)" << std::endl;
    }

    if (class_data != nullptr && class_data_len > 0) {
        std::string file_system_name;

        if (name != nullptr && strlen(name) > 0) {
            file_system_name = name;
            std::replace(file_system_name.begin(), file_system_name.end(), '/', '\\');
            file_system_name = (class_being_redefined ? "RETRANSFORMED_" : "INITIAL_") + file_system_name;
        }
        else {
            int current_count = unknown_class_counter.fetch_add(1);
            std::ostringstream oss;
            oss << "ZOV_CLASS_" << (class_being_redefined ? "REDEF_" : "INIT_") << current_count;
            file_system_name = oss.str();

            if (local_instance) {
                local_instance->logger("ClassFileLoadHook: CLAZZ [" + event_type_log + "] " + file_system_name);
            }
            else {
                std::cerr << "[ClassFileLoadHook] CLAZZ [" << event_type_log << "]. name: " << file_system_name << std::endl;
            }
        }

        std::filesystem::path dump_dir = "C:/ZOV_DUMPER_SON";
        std::filesystem::path file_path = dump_dir / (file_system_name + ".class");
        std::filesystem::path parent_path = file_path.parent_path();

        try {
            if (!parent_path.empty() && !std::filesystem::exists(parent_path)) {
                std::error_code ec;
                if (!std::filesystem::create_directories(parent_path, ec) && ec) {
                    if (local_instance) local_instance->logger("ClassFileLoadHook: Directory creation error: " + parent_path.string() + " | " + ec.message());
                }
            }

            std::ofstream outfile(file_path, std::ios::binary | std::ios::out | std::ios::trunc);
            if (outfile.is_open()) {
                if (local_instance) local_instance->logger("ClassFileLoadHook: Dumping class [" + event_type_log + "]: " + log_name_str + " -> " + file_path.string());
                outfile.write(reinterpret_cast<const char*>(class_data), class_data_len);
                outfile.close();
                if (!outfile) {
                    if (local_instance) local_instance->logger("ClassFileLoadHook: File write error: " + file_path.string());
                }
            }
            else {
                if (local_instance) local_instance->logger("ClassFileLoadHook: Failed to open dump file: " + file_path.string());
            }
        }
        catch (const std::exception& e) {
            if (local_instance) local_instance->logger("ClassFileLoadHook: Exception while dumping class [" + event_type_log + "] " + log_name_str + " (" + file_system_name + "): " + e.what());
            else std::cerr << "[ClassFileLoadHook] Exception while dumping class [" << event_type_log << "] " << log_name_str << " (" << file_system_name << "): " << e.what() << std::endl;
        }
    }
    else {
        if (local_instance) local_instance->logger("ClassFileLoadHook: [" + event_type_log + "]" + log_name_str);
        else std::cerr << "[ClassFileLoadHook] Warning [" << event_type_log << "] " << log_name_str << std::endl;
    }

    *new_class_data_len = 0;
    *new_class_data = nullptr;
}

namespace hook {

    void c_hook::logger(const std::string& text) {
        std::string full_msg = "[DRAMPER] " + text;
        std::cerr << full_msg << std::endl;
    }

    bool c_hook::attach() {
        logger("Attach to JVM");
        if (m_vm) { logger("Already connected."); return true; }

        HMODULE jvm_module = GetModuleHandleA("jvm.dll");
        if (!jvm_module) { logger("jvm.dll not found lol " + std::to_string(GetLastError())); return false; }

        using JNI_GetCreatedJavaVMs_t = jint(JNICALL*)(JavaVM**, jsize, jsize*);
        JNI_GetCreatedJavaVMs_t JNI_GetCreatedJavaVMs_ptr = (JNI_GetCreatedJavaVMs_t)GetProcAddress(jvm_module, "JNI_GetCreatedJavaVMs");
        if (!JNI_GetCreatedJavaVMs_ptr) { logger("erorr: " + std::to_string(GetLastError())); return false; }

        jsize num_vms = 0;
        jint res = JNI_GetCreatedJavaVMs_ptr(&m_vm, 1, &num_vms);
        if (res != JNI_OK || num_vms == 0 || m_vm == nullptr) {
            logger("JNI_GetCreatedJavaVMs failed or no VMs found. Result: " + std::to_string(res) + ", Count: " + std::to_string(num_vms));
            m_vm = nullptr; return false;
        }
        logger("JavaVM obtained successfully.");

        res = m_vm->GetEnv(reinterpret_cast<void**>(&m_jni_env), JNI_VERSION_1_6);
        if (res == JNI_EDETACHED) {
            res = m_vm->AttachCurrentThread(reinterpret_cast<void**>(&m_jni_env), nullptr);
            if (res != JNI_OK || m_jni_env == nullptr) {
                m_jni_env = nullptr;
            }
            else {
            }
        }
        else if (res != JNI_OK || m_jni_env == nullptr) {
            m_jni_env = nullptr;
        }
        else {
        }

        res = m_vm->GetEnv(reinterpret_cast<void**>(&m_jvmti_env), JVMTI_VERSION_1_2);
        if (res != JNI_OK || m_jvmti_env == nullptr) {
            logger("GetEnv for JVMTI failed. Result: " + std::to_string(res) + (m_jvmti_env ? "" : " (jvmtiEnv is null)") + ". Check JVMTI version.");
            m_jvmti_env = nullptr;
            m_jni_env = nullptr;
            m_vm = nullptr;
            return false;
        }

        if (!setup_jvmti_hooks()) {
            m_jvmti_env = nullptr;
            m_jni_env = nullptr;
            m_vm = nullptr;
            return false;
        }

        logger("Successfully connected to JVM ready JVMTI hooks.");
        return true;
    }

    bool c_hook::setup_jvmti_hooks() {
        if (!m_jvmti_env) { logger("setup_jvmti_hooks: Error - m_jvmti_env is NULL!"); return false; }
        if (m_jvmti_hook_active) { logger("JVMTI hooks already active."); return true; }


        jvmtiCapabilities capabilities = { 0 };
        capabilities.can_generate_all_class_hook_events = 1;
        capabilities.can_retransform_classes = 1;
        capabilities.can_get_source_file_name = 0;
        capabilities.can_get_line_numbers = 0;

        jvmtiError err = m_jvmti_env->AddCapabilities(&capabilities);
        if (err != JVMTI_ERROR_NONE && err != JVMTI_ERROR_NOT_AVAILABLE) {
            logger("Error adding JVMTI capabilities: " + std::to_string(err));
            jvmtiCapabilities current_caps = { 0 };
            m_jvmti_env->GetCapabilities(&current_caps);
            if (!current_caps.can_generate_all_class_hook_events || !current_caps.can_retransform_classes) {
                return false;
            }
        }
        else if (err == JVMTI_ERROR_NOT_AVAILABLE) {
            jvmtiCapabilities current_caps = { 0 };
            m_jvmti_env->GetCapabilities(&current_caps);
            if (!current_caps.can_generate_all_class_hook_events || !current_caps.can_retransform_classes) {
                return false;
            }
        }
        else {
        }

        jvmtiEventCallbacks callbacks = { 0 };
        callbacks.ClassFileLoadHook = ::ClassFileLoadHook;

        err = m_jvmti_env->SetEventCallbacks(&callbacks, sizeof(callbacks));
        if (err != JVMTI_ERROR_NONE) {
            return false;
        }
        logger("JVMTI callbacks set successfully.");

        err = m_jvmti_env->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
        if (err != JVMTI_ERROR_NONE) {
            jvmtiEventCallbacks empty_callbacks = { 0 };
            m_jvmti_env->SetEventCallbacks(&empty_callbacks, sizeof(empty_callbacks));
            return false;
        }
        logger("JVMTI_EVENT_CLASS_FILE_LOAD_HOOK enabled.");

        m_jvmti_hook_active = true;
        return true;
    }

    bool c_hook::trigger_retransformation_for_all_classes() {
        logger("Attempting to trigger retransformation for ALL loaded classes.");

        if (!m_jvmti_env) {
            return false;
        }

        jvmtiCapabilities current_caps = { 0 };
        jvmtiError err = m_jvmti_env->GetCapabilities(&current_caps);
        if (err != JVMTI_ERROR_NONE) {
            logger("Error getting JVMTI capabilities: " + std::to_string(err));
            return false;
        }
        if (!current_caps.can_retransform_classes) {
            return false;
        }
        logger("can_retransform_classes is active");
        jint class_count = 0;
        jclass* classes_ptr = nullptr;
        logger("Calling GetLoadedClasses...");
        err = m_jvmti_env->GetLoadedClasses(&class_count, &classes_ptr);

        if (err != JVMTI_ERROR_NONE) {
            return false;
        }
        logger("GetLoadedClasses callback with " + std::to_string(class_count) + " classes");

        if (class_count == 0 || classes_ptr == nullptr) {
            logger("No classes loaded");
            if (classes_ptr) {
                m_jvmti_env->Deallocate(reinterpret_cast<unsigned char*>(classes_ptr));
                logger("Memory deallocated");
            }
            return true;
        }

        jclass* classes_to_retransform = classes_ptr;
        jint count_to_retransform = class_count;

        logger("Retransforming " + std::to_string(count_to_retransform) + " classes. Calling RetransformClasses...");

        err = m_jvmti_env->RetransformClasses(
            count_to_retransform,
            classes_to_retransform
        );

        logger("RetransformClasses called");
        jvmtiError dealloc_err = m_jvmti_env->Deallocate(reinterpret_cast<unsigned char*>(classes_ptr));
        if (dealloc_err != JVMTI_ERROR_NONE) {
            logger("Deallocation error: " + std::to_string(dealloc_err));
        }
        else {
        }
        classes_ptr = nullptr;
        classes_to_retransform = nullptr;

        if (err == JVMTI_ERROR_NONE) {
            logger("RetransformClasses call successful.");
            logger("ClassFileLoadHook (with class_being_redefined != nullptr) triggered.");
            return true;
        }
        else {
            std::string error_msg = "Error in RetransformClasses: " + std::to_string(err);
            switch (err) {
            case JVMTI_ERROR_MUST_POSSESS_CAPABILITY: error_msg += " (Missing 'can_retransform_classes' capability)"; break;
            case JVMTI_ERROR_INVALID_CLASS:           error_msg += " (One of the classes in array is invalid)"; break;
            case JVMTI_ERROR_UNMODIFIABLE_CLASS:
                logger("JVMTI_ERROR_UNMODIFIABLE_CLASS.");
                return true;
            case JVMTI_ERROR_NULL_POINTER:            error_msg += " (NULL array passed)"; break;
            case JVMTI_ERROR_INVALID_ENVIRONMENT:     error_msg += " (Invalid jvmtiEnv)"; break;
            }

            logger(error_msg);
            return false;
        }
    }

    void c_hook::teardown_jvmti_hooks() {
        if (!m_jvmti_env || !m_jvmti_hook_active) {
            if (m_jvmti_hook_active) logger("teardown_jvmti_hooks: Cannot remove hooks (no jvmtiEnv).");
            m_jvmti_hook_active = false;
            return;
        }

        logger("Removing JVMTI hooks...");
        jvmtiError err;

        err = m_jvmti_env->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
        if (err != JVMTI_ERROR_NONE) {
            logger("Error disabling JVMTI_EVENT_CLASS_FILE_LOAD_HOOK: " + std::to_string(err));
        }
        else {
            logger("JVMTI_EVENT_CLASS_FILE_LOAD_HOOK disabled.");
        }

        jvmtiEventCallbacks empty_callbacks = { 0 };
        err = m_jvmti_env->SetEventCallbacks(&empty_callbacks, sizeof(empty_callbacks));
        if (err != JVMTI_ERROR_NONE) {
            logger("Error clearing callbacks: " + std::to_string(err));
        }
        else {
            logger("JVMTI callbacks cleared.");
        }

        m_jvmti_hook_active = false;
    }

    void c_hook::detach() {

        if (m_jvmti_env && m_jvmti_hook_active) {
            teardown_jvmti_hooks();
        }
        else {
            m_jvmti_hook_active = false;
        }

        m_jvmti_env = nullptr;
        m_jni_env = nullptr;
        m_vm = nullptr;

    }

    c_hook::~c_hook() {
        detach();
    }
}
