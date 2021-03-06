//===----------------------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// <functional>

// class function<R(ArgTypes...)>

// R operator()(ArgTypes... args) const

#include <functional>
#include <new>
#include <cstdlib>
#include <cassert>

// 0 args, return void

int count = 0;

void f_void_0()
{
    ++count;
}

struct A_void_0
{
    void operator()() {++count;}
};

void
test_void_0()
{
    int save_count = count;
    // function
    {
    std::function<void ()> r1(f_void_0);
    r1();
    assert(count == save_count+1);
    save_count = count;
    }
    // function pointer
    {
    void (*fp)() = f_void_0;
    std::function<void ()> r1(fp);
    r1();
    assert(count == save_count+1);
    save_count = count;
    }
    // functor
    {
    A_void_0 a0;
    std::function<void ()> r1(a0);
    r1();
    assert(count == save_count+1);
    save_count = count;
    }
}

int main()
{
    test_void_0();
}
