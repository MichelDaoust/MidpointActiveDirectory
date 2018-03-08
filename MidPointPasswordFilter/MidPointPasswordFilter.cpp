/**
*
* Copyright (c) 2009 Mauri Marco All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Portions Copyright 2013 Salford Software Ltd
**/


#include "stdafx.h"
#include <stdexcept>
#include <fstream>
#include <shlobj.h>

#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>
#include <winnt.h>
#include <vector>
#include <algorithm>

#include <string>
#include <iostream>
#include <string.h>
#include <sstream>


#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INVALID_SID              ((NTSTATUS)0xC0000078L)
#endif

/*new... */
#define BUFSIZE 2048 

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;

HANDLE g_hInputFile = NULL;

bool CreateChildProcess(std::string password, HANDLE & processId, HANDLE & threadId);
//void ReadFromPipe(void);

/*...new */


// Function prototypes
BOOLEAN NTAPI InitializeChangeNotify();
NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING, ULONG, PUNICODE_STRING);
BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, BOOLEAN);

// check if file exists
// Must open with mode r to read only and fail if the file doesn't exist
// Do not want to create the file if it doesn't exist as this defies the 
// purpose of the function.
bool fileExists(wchar_t *filename)
{
	FILE* file = _wfopen(filename, L"r");
	if (file != NULL)
	{
		fclose(file);
		return true;
	}
	else
	{
		return false;
	}
}


void WriteLogger(std::string message, std::string filename)
{
	std::cout << message;
	WCHAR path[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path))) {

		//convert from wide char to narrow char array
		char ch[260];
		char DefChar = ' ';
		WideCharToMultiByte(CP_ACP, 0, path, -1, ch, 260, &DefChar, NULL);

		//A std:string  using the char* constructor.
		std::string ss(ch);
		std::basic_string<char> str = "\\" + filename + ".txt";
		ss.append(str);

		std::ofstream ofs(ss, std::ofstream::out | std::ofstream::app);
		ofs << message << std::endl;
		ofs.close();
	}
}

// initialise the log file permissions
BOOLEAN NTAPI InitializeChangeNotify()
{

	WriteLogger("InitializeChangeNotify begin", "output20");

	std::string test1 = "test";
	//	std::string test2 = MPEncryption::MPEncryptDecrypt::Encrypt(test1);
	//	std::cout << test2;

	WriteLogger("InitializeChangeNotify begin 2", "output20");




	wchar_t returnMessage[256] = { 0 };
	wsprintf(returnMessage, L"InitializeChangeNotify");

	// Set the permissions for the log file
	wchar_t systempath[MAX_PATH + 1];
	if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, systempath)))
	{
		WriteLogger("InitializeChangeNotify after GetFolderPath", "output1");

		wchar_t *totalpath = lstrcat(systempath, CHANGE_FILE_FOLDER);
		CreateDirectory(totalpath, NULL);
		WriteLogger("InitializeChangeNotify after Create Directory", "output1");
		totalpath = lstrcat(totalpath, LOG_FILE_NAME);

		// If file already exists then call would break
		// since it tries to create the file and set permissions
		if (!fileExists(totalpath))
		{
			WriteLogger("InitializeChangeNotify before set log permission", "output1");
			setLogFilePermissions(totalpath);
			WriteLogger("InitializeChangeNotify before set log permission", "output1");
		}


	}
	wchar_t message[] = L"Starting MidPointPasswordFilter";
	writeLog(message, false);

	WriteLogger("InitializeChangeNotify END", "output1");

	return true;
}

/*
bool ReadLines(std::vector<std::string> & list)
{
WriteLogger("Readline BEGIN", "output1");



while (std::getline(data_stream, line, '\n')) {

//Read One Line
char temp[BUFSIZE / 2];
temp[dwRead / 2 + 1] = '\0';
memcpy(temp, chBuf, dwRead);
std::string lineRead(temp);
list.push_back(lineRead);
}

WriteLogger("Readline END", "output1");

return dwRead;
}
*/


bool CreateChildProcess(std::string password, HANDLE & processId, HANDLE & threadId)
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{
	WriteLogger("CREATECHILDPROCESS BEGIN", "output1");

	std::string temp = "\"C:\\Program Files\\Evolveum\\MidPoint Password Filter\\MidPointPasswordFilterEncryptor.exe\" e ";
	temp.append(password);
	WriteLogger(temp, "Just After is Argument of process");
	WriteLogger(temp, "output21");


	TCHAR * szCmdline = new TCHAR[temp.size() + 1];
	szCmdline[temp.size()] = 0;
	std::copy(temp.begin(), temp.end(), szCmdline);
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 

	memset(&piProcInfo, '\0', sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = g_hChildStd_OUT_Wr;
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	//	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	// Create the child process. 			



	bSuccess = CreateProcess(NULL,
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 

	int value = GetLastError();
	processId = piProcInfo.hProcess;
	threadId = piProcInfo.hThread;

	WriteLogger("CREATECHILDPROCESS END", "output1");

	return bSuccess;
}


//the event: password has changed successfully
NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword)
{

	WriteLogger("PasswordChangeNotify begin", "output21");

	std::string test1 = "test";
	//	std::string test2 = MPEncryption::MPEncryptDecrypt::Encrypt(test1);
	//	std::cout << test2;

	WriteLogger("PasswordChangeNotify begin", "output21");

	SECURITY_ATTRIBUTES saAttr;

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Create a pipe for the child process's STDOUT. 

	WriteLogger("PasswordChangeNotify Before Create Pipe", "output21");
	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
		WriteLogger("PasswordChangeNotify error create pipe", "output21");


	// Ensure the read handle to the pipe for STDOUT is not inherited.
	WriteLogger("PasswordChangeNotify SetHandleInformation", "output21");

	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		WriteLogger("PasswordChangeNotify error create pipe", "output21");



	int nLen = 0;

	WriteLogger("PasswordChangeNotify before copy username", "output21");


	//copy username
	int userLength = UserName->Length / sizeof(wchar_t);
	wchar_t* username = (wchar_t*)malloc((userLength + 1) * sizeof(wchar_t));
	wchar_t* z = wcsncpy(username, UserName->Buffer, userLength);


	//set the last character to null
	username[userLength] = '\0';
	WriteLogger("PasswordChangeNotify after copy username", "output21");

	std::wcout << username << std::endl;
	//convert the password from widechar to utf-8
	int passwordLength = NewPassword->Length / sizeof(wchar_t);
	nLen = WideCharToMultiByte(CP_UTF8, 0, NewPassword->Buffer, passwordLength, 0, 0, 0, 0);
	char* password = (char*)malloc((nLen + 1) * sizeof(char));
	nLen = WideCharToMultiByte(CP_UTF8, 0, NewPassword->Buffer, passwordLength, password, nLen, 0, 0);
	//set the last character to null
	password[nLen] = NULL;

	WriteLogger("after convert password to utf-8", "output21");

	try {

		HANDLE processHandle;
		HANDLE threadHandle;
		std::string str(password);
		WriteLogger("Before CreateChildProcess", "output21");
		if (!CreateChildProcess(str, processHandle, threadHandle))
		{
			wchar_t message[] = L"Error couldn't start encryption process";
			writeLog(message, false);
		}

		WriteLogger("After CreateChildProcess", "output21");




		//Encrypt the password
		//	StreamReader^ myStreamReader;
		//	Process^ myProcess;
		//	try
		//	{
		//		String^ encArgs = gcnew String(password);
		//		encArgs = "e " + encArgs;

		//		myProcess = gcnew Process;
		//		myProcess->StartInfo->FileName = "C:\\Program Files\\Evolveum\\MidPoint Password Filter\\MidPointPasswordFilterEncryptor.exe";
		//		myProcess->StartInfo->Arguments = encArgs;
		//		myProcess->StartInfo->UseShellExecute = false;
		//		myProcess->StartInfo->RedirectStandardOutput = true;
		//		myProcess->Start();
		//	}


		// Read the standard output of the spawned process.
		//		myStreamReader = myProcess->StandardOutput;
		//		String^ line;
		//		String^ encryptedString;
		//		bool start = false;
		//		bool end = false;
		//		while (!end && (line = myStreamReader->ReadLine()))
		//		{

		std::string encryptedString;
		std::vector<std::string> lines;
		bool start = false;
		bool end = false;
		WriteLogger("Before ReadLine", "output21");


		//Read the output stream encrypted file
		DWORD dwRead;
		char chBuf[BUFSIZE];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

		//We have to read a line 
		bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0)
		{
			wchar_t message[] = L"Could not read input from encryption process";
			writeLog(message, false);
			return 0;
		}

		chBuf[dwRead] = '\0';
		std::stringstream data_stream(chBuf);
		std::string line;
		WriteLogger(data_stream.str(), "output21");


		while (!end && std::getline(data_stream, line, '\r'))
		{

			line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
			WriteLogger("line Items below ", "output21");
			WriteLogger(line, "output21");

			if (start)
			{
				if (line == "END ENCRYPTION")
				{
					// Found end tag - stop parsing encryptedString
					// Don't want to add end tag to encryptedString
					end = true;
				}
				else
				{
					// If the line is between start and end tags then append it to encryptedString
					encryptedString += line;
				}
			}

			if (line == "START ENCRYPTION")
			{
				// Found start tag - must check this AFTER attempting to add to encryptedString 
				// Otherwise the start tag would be added to the encryptedString
				start = true;
			}
		}



		WriteLogger("Before wait for single Object", "output21");
		WaitForSingleObject(processHandle, 10000);

		CloseHandle(processHandle);
		CloseHandle(threadHandle);

		//Close the Child Standard output
		CloseHandle(g_hChildStd_OUT_Rd);
		//write the password change out to a file
		//need to record timestamp, username and hashed password to update other systems

		WriteLogger("After close handle", "output21");


		wchar_t * encPwd = new wchar_t[encryptedString.length() + 1];
		std::copy(encryptedString.begin(), encryptedString.end(), encPwd);
		encPwd[encryptedString.length()] = 0;

		size_t convertedChars = 0;
		size_t  sizeInBytes = ((encryptedString.length() + 1) * 2);
		errno_t err = 0;
		char *cEncPwd = new char[sizeInBytes];

		//		pin_ptr<const wchar_t> encPwd = PtrToStringChars(encryptedString);
		//		size_t convertedChars = 0;
		//		size_t  sizeInBytes = ((encryptedString->Length + 1) * 2);
		//		errno_t err = 0;
		//		char *cEncPwd = (char *)malloc(sizeInBytes);


		//myProcess->WaitForExit();

		//		pin_ptr<const wchar_t> encPwd = PtrToStringChars(encryptedString);
		//		size_t convertedChars = 0;
		//		size_t  sizeInBytes = ((encryptedString->Length + 1) * 2);
		//		errno_t err = 0;
		//		char *cEncPwd = (char *)malloc(sizeInBytes);

		WriteLogger("Prepare sending message to log", "output21");

		err = wcstombs_s(&convertedChars, cEncPwd, sizeInBytes, encPwd, sizeInBytes);
		if (err == 0)
		{
			WriteLogger("Before conversion after ", "output21");
			std::string tempo(cEncPwd);
			WriteLogger(tempo, "output21");
			size_t encPwdSize = strlen(cEncPwd) + 1;
			wchar_t* wEncPwd = new wchar_t[encPwdSize];
			mbstowcs(wEncPwd, cEncPwd, encPwdSize);

			std::wstring message(username);
			message.append(L", ");
			message += wEncPwd;

			WriteLogger("Before sending message to log", "output21");
			if (writeLog(const_cast<wchar_t*>(message.c_str()), true))
			{
				wchar_t message[] = CHANGE_PASSWORD_MESSAGE;
				writeMessageToLog(message, username);
			}
			else
			{
				wchar_t message[] = L"Error writing the credentials to file";
				writeLog(message, false);
			}
			WriteLogger("After sending message to log", "output21");

		}
		else
		{
			wchar_t message[] = L"Error processing the password";
			writeLog(message, false);
		}
		delete[] encPwd;
		delete[] cEncPwd;

	}
	catch (std::exception const& e)
	{
		wchar_t message[] = L"Error Encrypting Password";
		writeLog(message, false);
	}

	//zero the password
	SecureZeroMemory(password, nLen);
	//free the memory
	//free(message);
	//free(z);
	free(username);
	free(password);

	//can I return something else in case of error?

	WriteLogger("PasswordChangeNotify END", "output1");


	return STATUS_SUCCESS;
}

//don't apply any password policy
BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation)
{
	return TRUE;
}
