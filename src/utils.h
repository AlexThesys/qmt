#pragma once

#include <stdint.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <array>
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

class semaphore
{
	std::mutex m;
	std::condition_variable cv;
	volatile int ready;
public:
	semaphore() : ready(0) {}
	void wait()
	{
		std::unique_lock<std::mutex> lock(m);
		cv.wait(lock, [this]() { return this->ready; });
		this->ready = 0;
	}
	void signal()
	{
		{
			std::unique_lock<std::mutex> lock(m);
			ready = 1;
		}
		cv.notify_one();
	}
};

class semaphore_counting
{
	std::mutex m;
	std::condition_variable cv;
	volatile int counter = 0;
	int max_count;
public:
	semaphore_counting() : counter(0), max_count(1) {} // binary semaphore by default
	semaphore_counting(int mcount) : counter(0), max_count(mcount) {}
	void set_max_count(int count) {
		max_count = count;
	}
	void wait() {
		std::unique_lock<std::mutex> lock(m);
		if (counter == 0) {
			cv.wait(lock, [this]() { return counter != 0; });
			counter--;
		}
	}
	void signal() {
		{
			std::unique_lock<std::mutex> lock(m);
			if (counter < max_count) {
				counter++;
			}
		}
		cv.notify_one();
	}
	void signal(int count) {
		{
			std::unique_lock<std::mutex> lock(m);
			const int new_count = counter + count;
			counter = (new_count < max_count) ? new_count : max_count;
		}
		cv.notify_all();
	}
};

template <typename T, size_t sz_pow_2>
class circular_buffer
{
    static constexpr size_t capacity = 1 << sz_pow_2;

    std::array<T, capacity> queue;
    uint32_t read_idx;
    uint32_t write_idx;
    std::atomic<uint32_t> size{0};
    spinlock guard;
public:
    circular_buffer() : read_idx(0), write_idx(0) {}

    bool is_empty() const
    {
        return (size.load() == 0);
    }

    bool is_full() const
    {
        return (size.load() == capacity);
    }

    bool try_read(T& item)
    {
        guard.lock();
        if (is_empty()) {
            guard.unlock();
            return false;
        }
        item = queue[read_idx];
        guard.unlock();
        return true;
    }

    void advance()
    {
        guard.lock();
        std::atomic_fetch_add(&size, -1);
        read_idx = (read_idx + 1) & (capacity - 1);
        guard.unlock();
    }

    bool try_pop(T& item)
    {
        guard.lock();
        if (is_empty()) {
            guard.unlock();
            return false;
        }
        item = queue[read_idx];
        std::atomic_fetch_add(&size, -1);
        read_idx = (read_idx + 1) & (capacity - 1);
        guard.unlock();
        return true;
    }

    bool try_push(const T& task) {
        guard.lock();
        if (is_full()) {
            guard.unlock();
            return false;
        }
        queue[write_idx] = task;
        std::atomic_fetch_add(&size, 1);
        write_idx = (write_idx + 1) & (capacity - 1);
        guard.unlock();
        return true;
    }
};
