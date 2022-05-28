#pragma once

#include <iostream>
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <Lmcons.h>
#include <stdlib.h>
#include <stdio.h>

#define DEBUG true

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#define ADDR unsigned __int64
#define readword __readgsqword
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#define ADDR unsigned __int32
#define readword __readfsdword
#endif