#include <iostream>
#include <thread>
#include <mutex>
#include <vector>

class SharedBuffer {
public:
    SharedBuffer() : data_(nullptr), size_(0) {}

    ~SharedBuffer() {
        std::lock_guard<std::mutex> lock(mtx_);
        delete[] data_;
    }

    void allocate(size_t size) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (data_ != nullptr) {
            delete[] data_;
        }
        data_ = new int[size];
        size_ = size;
    }

    void resize(size_t new_size) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (new_size == size_) return;
        if (data_ != nullptr) {
            delete[] data_;
        }
        data_ = new int[new_size];
        size_ = new_size;
    }

    int read(size_t index) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (index >= size_) return -1;
        return data_[index];
    }

    void write(size_t index, int value) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (index >= size_) return;
        data_[index] = value;
    }

private:
    int* data_;
    size_t size_;
    std::mutex mtx_;
};

void writer_thread(SharedBuffer& buf) {
    for (int i = 0; i < 10; ++i) {
        buf.resize(100);
        buf.write(i, i * 2);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void reader_thread(SharedBuffer& buf) {
    for (int i = 0; i < 10; ++i) {
        int val = buf.read(i);
        if (val != -1) {
            std::cout << "Read: " << val << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
}

int main() {
    SharedBuffer buf;
    buf.allocate(50);

    std::thread t1(writer_thread, std::ref(buf));
    std::thread t2(reader_thread, std::ref(buf));

    t1.join();
    t2.join();

    return 0;
}

