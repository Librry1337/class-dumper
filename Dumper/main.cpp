
#include "main.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <windows.h>

namespace main {

    void thread(HMODULE dll) {
        std::cout << "CLAZZER TRAHER HOOKED STARTED" << std::endl;

        if (hook::instance) {
            hook::instance.reset();
        }
        hook::instance = std::make_unique<hook::c_hook>();

        if (!hook::instance->attach()) {
            std::cerr << "!!! Error connecting to JVM or setting up JVMTI hook. Terminating thread." << std::endl;
            hook::instance.reset();
            FreeLibraryAndExitThread(dll, 1);
            return;
        }

        std::cout << " CLAZZER TRAHER INICILIZING XD " << std::endl;

  

        bool request_sent = hook::instance->trigger_retransformation_for_all_classes();

        if (request_sent) {

        }
        else {
            std::cerr << " !!! Failed to initiate retransformation for ALL classes. Check hook log ([JVMTI HOOK]) for details. !!!" << std::endl;
        }


        std::cout << " ---> CLAZZ HAS BEEN DEPORTED  " << std::endl;

        while (true) {
            if (GetAsyncKeyState(VK_END) & 0x8000) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        hook::instance.reset();

        FreeLibraryAndExitThread(dll, 0);
    }

} // namespace main
