// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#ifndef MMVECTOR_H_
#define MMVECTOR_H_

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <utility>

#include "./align.h"

namespace {  // NOLINT(build/namespaces_headers)

enum class InitMode {
  CreateTemporary,
  CreatePersistent,
  OpenExisting,
};

template <typename T>
class MmVector {
 public:
  using iterator = T*;
  using const_iterator = const T*;
  using reference = T&;
  using const_reference = const T&;

  MmVector() : fd_(-1), storage_(nullptr), capacity_(0) {}
  template <typename U>
  MmVector(const MmVector<U>&) = delete;
  ~MmVector() {
    if (storage_ != nullptr) {
      if (ftruncate(fd_, kOverhead + storage_->size * sizeof(T)) == 0)
        capacity_ = storage_->size;
      munmap(storage_, kOverhead + capacity_ * sizeof(T));
    }
    close(fd_);
  }

  [[nodiscard]] int Init(const char* path, InitMode mode) {
    switch (mode) {
      case InitMode::CreateTemporary: {
        size_t len = strlen(path);
        std::unique_ptr<char[]> tempPath(new char[len + 7]);
        memcpy(&tempPath[0], path, len);
        memset(&tempPath[len], 'X', 6);
        tempPath[len + 6] = '\0';
        fd_ = mkstemp(tempPath.get());
        if (fd_ == -1) return -errno;
        unlink(tempPath.get());
        return InitCreated();
      }
      case InitMode::CreatePersistent:
        fd_ = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd_ == -1) return -errno;
        return InitCreated();
      case InitMode::OpenExisting:
        fd_ = open(path, O_RDWR);
        if (fd_ == -1) return -errno;
        return InitOpened();
      default:
        return -EINVAL;
    }
  }

  [[nodiscard]] int InitCreated() {
    if (ftruncate(fd_, kOverhead) == -1) return -errno;
    void* newStorage =
        mmap(nullptr, kOverhead, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (newStorage == MAP_FAILED) return -errno;
    storage_ = static_cast<Storage*>(newStorage);
    storage_->size = 0;
    return 0;
  }

  [[nodiscard]] int InitOpened() {
    Storage header;
    if (ReadN(fd_, &header, kOverhead) != kOverhead) return -errno;
    void* newStorage = mmap(nullptr, kOverhead + header.size * sizeof(T),
                            PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (newStorage == MAP_FAILED) return -errno;
    storage_ = static_cast<Storage*>(newStorage);
    capacity_ = storage_->size;
    return 0;
  }

  bool IsInitalized() const { return storage_ != nullptr; }

  T* data() { return storage_->entries; }
  const T* data() const { return storage_->entries; }
  size_t size() const { return storage_->size; }
  size_t capacity() const { return capacity_; }
  iterator begin() { return storage_->entries; }
  const_iterator begin() const { return storage_->entries; }
  iterator end() { return &storage_->entries[storage_->size]; }
  const_iterator end() const { return &storage_->entries[storage_->size]; }
  reference front() { return storage_->entries[0]; }
  const_reference front() const { return storage_->entries[0]; }
  reference back() { return storage_->entries[storage_->size - 1]; }
  const_reference back() const { return storage_->entries[storage_->size - 1]; }
  reference operator[](size_t n) { return storage_->entries[n]; }
  const_reference operator[](size_t n) const { return storage_->entries[n]; }

  void reserve(size_t n) {
    if (n <= capacity_) return;
    if (ftruncate(fd_, kOverhead + n * sizeof(T)) == -1) throw std::bad_alloc();
    void* newStorage = mremap(storage_, kOverhead + capacity_ * sizeof(T),
                              kOverhead + n * sizeof(T), MREMAP_MAYMOVE);
    if (newStorage == MAP_FAILED) throw std::bad_alloc();
    storage_ = static_cast<Storage*>(newStorage);
    capacity_ = n;
  }

  void push_back(const T& val) {
    if (storage_->size + 1 > capacity_) Grow();
    storage_->entries[storage_->size++] = val;
  }

  template <typename... Args>
  reference emplace_back(Args&&... args) {
    if (storage_->size + 1 > capacity_) Grow();
    new (&storage_->entries[storage_->size]) T(std::forward(args)...);
    return storage_->entries[storage_->size++];
  }

  template <typename InputIterator>
  void insert(iterator position, InputIterator first, InputIterator last) {
    size_t i = position - &storage_->entries[0];
    size_t n = last - first;
    if (i + n > capacity_) {
      Grow(GetAligned((i + n - capacity_) * sizeof(T), kGrowAmount));
      position = &storage_->entries[i];
    }
    InputIterator input = first;
    iterator end = &storage_->entries[storage_->size];
    while (position != end && input != last) *(position++) = *(input++);
    while (input != last) new (position++) T(*(input++));
    storage_->size = std::max(storage_->size, n + i);
  }

  void resize(size_t n, T val = T()) {
    if (n > capacity_)
      Grow(GetAligned((n - capacity_) * sizeof(T), kGrowAmount));
    for (size_t i = storage_->size; i < n; i++)
      new (&storage_->entries[i]) T(val);
    storage_->size = n;
  }

 private:
  static constexpr size_t kGrowAmount =
      (sizeof(void*) == 8 ? 1024 : 64) * 1024 * 1024;

  void Grow(size_t bytes = kGrowAmount) {
    reserve(capacity_ + bytes / sizeof(T));
  }

  int fd_;
  struct Storage {
    size_t size;
    T entries[1];  // C++ has no FAM!
  };
  static constexpr size_t kOverhead = sizeof(Storage) - sizeof(T);
  Storage* storage_;
  size_t capacity_;
};

}  // namespace

#endif  // MMVECTOR_H_
