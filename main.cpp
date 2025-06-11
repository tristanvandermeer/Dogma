// Today we are learning
#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h> // Windows specific, test on VM
#include <tlhelp32.h>  
#include <winternl.h>
#endif

#pragma once // <---- Still learning about this

using namespace std; // Standard namespace (?)

/*---------------------------------------------------------------------------*/
/*-------------------------- TESTING BEGINS BELOW ---------------------------*/
/*---------------------------------------------------------------------------*/

const string foo = "bar";
int foobar = foo.length(); // Wow ! (Alternatively use size())
string input_string;

string string_input() {
    cout << "Please enter literally anything";
    getline(cin, input_string);
    cout << "You input: " << input_string;
    return input_string;
}

int main() {
    cout << "Ok so new language is hard";
    return 0;
}

int square(const int x) { // Just need to learn the syntax
    return x*x;
}

class MyClass { // Class definition
public:
    int val; // Attributes

    void kill() {// Method
        cout << "Value: " << val << endl;
    }
};

