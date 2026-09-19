#include <cstdio>
#include <cstring>
class SharedBuffer {
public:
    SharedBuffer(size_t n) : size_(n), data_(new char[n]) {}
    ~SharedBuffer() { delete[] data_; }
    char get(size_t off) { if (off < size_) return data_[off]; return 0; }
private:
    size_t size_; char* data_;
};
int main() {
    SharedBuffer* b = new SharedBuffer(64);
    delete b;                       // 析构：delete[] data_ 不置空（样本原样）
    printf("析构后 get(0) 返回: %c（UAF 静默或崩溃）\n", b->get(0));
    printf("幸存退出\n");
    return 0;
}
