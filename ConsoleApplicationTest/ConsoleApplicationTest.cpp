// ConsoleApplicationTest.cpp : Defines the entry point for the console application.
//


#include "stdafx.h"
#include "stdio.h"
#include <string>
#include <windows.h> 
#include <iostream>
#include "MidPointEncryption.h"

#pragma comment(lib, "MidPointEncryption.lib")


int main()
{
    char test[] = "allo";
	std::string test1 = "test";
	std::string test2 =   MPEncryption::MPEncryptDecrypt::Encrypt(test1);
	std::cout << test2;
    return 0;
}

