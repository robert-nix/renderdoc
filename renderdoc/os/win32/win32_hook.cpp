/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2022 Baldur Karlsson
 * Copyright (c) 2014 Crytek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

// must be separate so that it's included first and not sorted by clang-format
#include <windows.h>

#include <tlhelp32.h>
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include "common/common.h"
#include "common/threading.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"
#include "MinHook.h"

#define VERBOSE_DEBUG_HOOK OPTION_OFF

static std::set<uintptr_t> hooked;

bool ApplyHook(FunctionHook &hook, void *target, bool &already)
{
  if(hooked.find((uintptr_t)target) != hooked.end())
  {
    RDCWARN("ApplyHook already hooked 0x%p", target);
    already = true;
    return true;
  }

  hooked.insert((uintptr_t)target);
  RDCLOG("ApplyHook(target=0x%p, orig=0x%p, function=%s)\n", target, hook.orig,
         hook.function.c_str());

  // @HACK: target impl versions of these as of d3d11.dll (10.0.22000.1042; 10/11/2022) build
  if(hook.function == "D3D11CreateDeviceAndSwapChain")
  {
    target = (void *)((uintptr_t)target - 0x523a0 + 0x14e40);
  }
  if(hook.function == "D3D11CreateDevice")
  {
    target = (void *)((uintptr_t)target - 0x52220 + 0x52330);
  }

  void *_orig = nullptr;
  if(MH_CreateHook(target, hook.hook, hook.orig ? hook.orig : &_orig) != MH_OK)
  {
    RDCERR("Failed to create hook 0x%p\n", target);
    return false;
  }

  if(MH_EnableHook(target) != MH_OK)
  {
    RDCERR("Failed to enable hook 0x%p\n", target);
    return false;
  }

  return true;
}

struct DllHookset
{
  HMODULE module = NULL;
  // if we have multiple copies of the dll loaded (unlikely), the other module handles will be
  // stored here
  rdcarray<HMODULE> altmodules;
  rdcarray<FunctionHook> FunctionHooks;
  rdcarray<FunctionLoadCallback> Callbacks;

  void ApplyHooks()
  {
    // the module could have been unloaded after our toolhelp snapshot, especially if we spent a
    // long time
    // dealing with a previous module (like adding our hooks).
    wchar_t modpath[1024] = {0};
    GetModuleFileNameW(module, modpath, 1023);
    if(modpath[0] == 0)
      return;

    // increment the module reference count, so it doesn't disappear while we're processing it
    // there's a very small race condition here between if GetModuleFileName returns, the module is
    // unloaded then we load it again. The only way around that is inserting very scary locks
    // between here
    // and FreeLibrary that I want to avoid. Worst case, we load a dll, hook it, then unload it
    // again.
    HMODULE refcountModHandle = LoadLibraryW(modpath);

    for(auto &hook : FunctionHooks)
    {
      bool _already = false;
      ApplyHook(hook, GetProcAddress(module, hook.function.c_str()), _already);
    }

    FreeLibrary(refcountModHandle);
  }
};

struct CachedHookData
{
  bool hookAll = true;

  std::map<rdcstr, DllHookset> DllHooks;
  HMODULE ownmodule = NULL;
  Threading::CriticalSection lock;
  char lowername[512] = {};

  std::set<rdcstr> ignores;

  std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> libraryIntercept;

  int32_t posthooking = 0;

  void ApplyHooks(const char *modName, HMODULE module)
  {
    {
      size_t i = 0;
      while(modName[i])
      {
        lowername[i] = (char)tolower(modName[i]);
        i++;
      }
      lowername[i] = 0;
    }

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== ApplyHooks(%s, %p)", modName, module);
#endif

    // fraps seems to non-safely modify the assembly around the hook function, if
    // we modify its import descriptors it leads to a crash as it hooks OUR functions.
    // instead, skip modifying the import descriptors, it will hook the 'real' d3d functions
    // and we can call them and have fraps + renderdoc playing nicely together.
    // we also exclude some other overlay renderers here, such as steam's
    //
    // Also we exclude ourselves here - just in case the application has already loaded
    // renderdoc.dll, or tries to load it.
    if(strstr(lowername, "fraps") || strstr(lowername, "gameoverlayrenderer") ||
       strstr(lowername, STRINGIZE(RDOC_DLL_FILE) ".dll") == lowername)
      return;

    for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
    {
      if(!_stricmp(it->first.c_str(), modName))
      {
        if(it->second.module == NULL)
        {
          it->second.module = module;
          it->second.ApplyHooks();
        }
      }
    }

    // for safety (and because we don't need to), ignore these modules
    if(!_stricmp(modName, "kernel32.dll") || !_stricmp(modName, "powrprof.dll") ||
       !_stricmp(modName, "CoreMessaging.dll") || !_stricmp(modName, "opengl32.dll") ||
       !_stricmp(modName, "gdi32.dll") || !_stricmp(modName, "gdi32full.dll") ||
       !_stricmp(modName, "nvoglv32.dll") || !_stricmp(modName, "nvoglv64.dll") ||
       !_stricmp(modName, "vulkan-1.dll") || !_stricmp(modName, "nvcuda.dll") ||
       strstr(lowername, "cudart") == lowername || strstr(lowername, "msvcr") == lowername ||
       strstr(lowername, "msvcp") == lowername || strstr(lowername, "nv-vk") == lowername ||
       strstr(lowername, "amdvlk") == lowername || strstr(lowername, "igvk") == lowername ||
       strstr(lowername, "nvopencl") == lowername || strstr(lowername, "nvapi") == lowername)
      return;

    if(ignores.find(lowername) != ignores.end())
      return;
  }
};

static CachedHookData *s_HookData = NULL;

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

static void ForAllModules(std::function<void(const MODULEENTRY32 &me32)> callback)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;

  // up to 10 retries
  for(int i = 0; i < 10; i++)
  {
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

    if(hModuleSnap == INVALID_HANDLE_VALUE)
    {
      DWORD err = GetLastError();

      RDCWARN("CreateToolhelp32Snapshot() -> 0x%08x", err);

      // retry if error is ERROR_BAD_LENGTH
      if(err == ERROR_BAD_LENGTH)
        continue;
    }

    // didn't retry, or succeeded
    break;
  }

  if(hModuleSnap == INVALID_HANDLE_VALUE)
  {
    RDCERR("Couldn't create toolhelp dump of modules in process");
    return;
  }

  MODULEENTRY32 me32;
  RDCEraseEl(me32);
  me32.dwSize = sizeof(MODULEENTRY32);

  BOOL success = Module32First(hModuleSnap, &me32);

  if(success == FALSE)
  {
    DWORD err = GetLastError();

    RDCERR("Couldn't get first module in process: 0x%08x", err);
    CloseHandle(hModuleSnap);
    return;
  }

  do
  {
    callback(me32);
  } while(Module32Next(hModuleSnap, &me32));

  CloseHandle(hModuleSnap);
}

static void HookAllModules()
{
  if(!s_HookData->hookAll)
    return;

  ForAllModules(
      [](const MODULEENTRY32 &me32) { s_HookData->ApplyHooks(me32.szModule, me32.hModule); });

  // check if we're already in this section of code, and if so don't go in again.
  int32_t prev = Atomic::CmpExch32(&s_HookData->posthooking, 0, 1);

  if(prev != 0)
    return;

  // for all loaded modules, call callbacks now
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
  {
    if(it->second.module == NULL)
      continue;

    rdcarray<FunctionLoadCallback> callbacks;
    // don't call callbacks next time
    callbacks.swap(it->second.Callbacks);

    for(FunctionLoadCallback cb : callbacks)
      if(cb)
        cb(it->second.module);
  }

  Atomic::CmpExch32(&s_HookData->posthooking, 1, 0);
}

static void InitHookData()
{
  if(s_HookData)
  {
    return;
  }

  if(MH_Initialize() != MH_OK)
  {
    RDCERR("Failed to initialize MinHook!\n");
  }

  s_HookData = new CachedHookData;

  RDCASSERT(s_HookData->DllHooks.empty());

  GetModuleHandleEx(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
      (LPCTSTR)&s_HookData, &s_HookData->ownmodule);
}

void LibraryHooks::RegisterFunctionHook(const char *libraryName, const FunctionHook &hook)
{
  if(!_stricmp(libraryName, "kernel32.dll"))
  {
    if(hook.function == "LoadLibraryA" || hook.function == "LoadLibraryW" ||
       hook.function == "LoadLibraryExA" || hook.function == "LoadLibraryExW" ||
       hook.function == "GetProcAddress")
    {
      RDCERR("Cannot hook LoadLibrary* or GetProcAddress, as these are hooked internally");
      return;
    }
  }
  s_HookData->DllHooks[strlower(rdcstr(libraryName))].FunctionHooks.push_back(hook);
}

void LibraryHooks::RegisterLibraryHook(const char *libraryName, FunctionLoadCallback loadedCallback)
{
  s_HookData->DllHooks[strlower(rdcstr(libraryName))].Callbacks.push_back(loadedCallback);
}

void LibraryHooks::IgnoreLibrary(const char *libraryName)
{
  rdcstr lowername = libraryName;

  for(size_t i = 0; i < lowername.size(); i++)
    lowername[i] = (char)tolower(lowername[i]);

  s_HookData->ignores.insert(lowername);
}

void LibraryHooks::BeginHookRegistration()
{
  InitHookData();
}

// hook all functions for currently loaded modules.
// some of these hooks (as above) will hook LoadLibrary/GetProcAddress, to protect
void LibraryHooks::EndHookRegistration()
{
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("Applying hooks");
#endif

  HookAllModules();
}

void LibraryHooks::Refresh()
{
  // don't need to refresh on windows
}

void LibraryHooks::ReplayInitialise() {}

void LibraryHooks::RemoveHooks()
{
  LibraryHooks::RemoveHookCallbacks();

  for(auto it = hooked.begin(); it != hooked.end(); ++it)
  {
    if(MH_DisableHook((LPVOID)*it) != MH_OK)
    {
      RDCERR("Failed to disable hook 0x%p", *it);
      continue;
    }
    if(MH_RemoveHook((LPVOID)*it) != MH_OK)
    {
      RDCERR("Failed to remove hook 0x%p", *it);
    }
  }
}

bool LibraryHooks::Detect(const char *identifier)
{
  bool ret = false;
  ForAllModules([&ret, identifier](const MODULEENTRY32 &me32) {
    if(GetProcAddress(me32.hModule, identifier) != NULL)
      ret = true;
  });
  return ret;
}

void Win32_RegisterManualModuleHooking()
{
  InitHookData();

  s_HookData->hookAll = false;
}

void Win32_InterceptLibraryLoads(std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> callback)
{
  s_HookData->libraryIntercept = callback;
}

void Win32_ManualHookModule(rdcstr modName, HMODULE module)
{
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

  modName = strlower(modName);

  s_HookData->DllHooks[modName].module = module;

  for(FunctionHook &hook : s_HookData->DllHooks[modName].FunctionHooks)
  {
    if(hook.orig)
      *hook.orig = GetProcAddress(module, hook.function.c_str());
  }

  s_HookData->ApplyHooks(modName.c_str(), module);
}

// android only hooking functions, not used on win32
ScopedSuppressHooking::ScopedSuppressHooking() {}

ScopedSuppressHooking::~ScopedSuppressHooking() {}
