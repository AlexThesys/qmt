#pragma once

#include <stdint.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <emmintrin.h>

class spinlock 
{
    std::atomic<int32_t> _lock{0};

public:
    void lock() 
    {
        static const auto ns = std::chrono::nanoseconds(1);
        for (int i = 0; _lock.load() || std::atomic_exchange(&_lock, 1); i++) {
            if (i == 8) {
                i = 0;
                std::this_thread::sleep_for(ns);
            }
            _mm_pause();
        }
    }

    void unlock() 
    {
        _lock.store(0);
    }
};





