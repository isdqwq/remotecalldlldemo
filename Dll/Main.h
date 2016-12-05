#pragma once

#ifndef MAIN_H
#define MAIN_H
#include <Windows.h>
#include <stdio.h>

extern "C" void __declspec(dllexport)Dll_Load(DWORD ul_reason_for_call);
#endif