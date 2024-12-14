#pragma once

#include <condition_variable>
#include <mutex>

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