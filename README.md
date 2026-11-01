# **MythareNoTopMost**
> 通过注入DLL，让极域取消置顶

建议使用：极域工具箱 url：https://github.com/BengbuGuards/MythwareToolkit

因为它似乎没有让窗口化的广播取消置顶，所以出现了本程序。
部分版本极域可能失效（防注入DLL的最尴尬）


1. 因为时间紧凑，这个程序很多是AI完成的（看注释）
2. 你需要MinHook才能编译：minhook的github项目 url：https://github.com/TsudaKageyu/minhook
3. 将“StudentMain.exe”改为其它或使用命令行参数可以将DLL注入到其它程序，实现更多效果。
4. cpp文件中是“hook_x86.dll”,要想编译x64尝试换成“hook_x64.dll”（除非你乐意出现名称带x64的x86 Dll文件）

> **注意：本程序仅供测试和兴趣，如果用于其它，那么不关我的事。**

---
编译：
---
## 一、MinGW-w64 x86（32 位）


**DLL：**
```bat
i686-w64-mingw32-g++ -shared -static -O2 -I include -I MinHook\src -o hook_x86.dll hook64.cpp MinHook\src\buffer.c MinHook\src\trampoline.c MinHook\src\hook.c MinHook\src\hde\hde32.c MinHook\src\hde\hde64.c -luser32
```

**注入器：**
```bat
i686-w64-mingw32-g++ -O2 -static -mwindows -o injector_x86.exe injector.cpp -lshell32 -luser32 -ladvapi32
```

---

## 二、MinGW-w64 x64（64 位）

**DLL：**
```bat
x86_64-w64-mingw32-g++ -shared -static -O2 -I include -I MinHook\src -o hook_x64.dll hook64.cpp MinHook\src\buffer.c MinHook\src\trampoline.c MinHook\src\hook.c MinHook\src\hde\hde32.c MinHook\src\hde\hde64.c -luser32
```

**注入器：**
```bat
x86_64-w64-mingw32-g++ -O2 -static -mwindows -o injector_x64.exe injector.cpp -lshell32 -luser32 -ladvapi32
```

---

## 三、MSVC x86（32 位）

**DLL：**
```bat
cl /LD /MT /O2 /EHsc /I include /I MinHook\src hook64.cpp MinHook\src\buffer.c MinHook\src\trampoline.c MinHook\src\hook.c MinHook\src\hde\hde32.c MinHook\src\hde\hde64.c /Fe:hook_x86.dll /link user32.lib
```

**注入器：**
```bat
cl /EHsc /O2 /MT injector.cpp /Fe:injector_x86.exe /link /SUBSYSTEM:WINDOWS user32.lib shell32.lib advapi32.lib
```

---

## 四、MSVC x64（64 位）

**DLL：**
```bat
cl /LD /MT /O2 /EHsc /I include /I MinHook\src hook64.cpp MinHook\src\buffer.c MinHook\src\trampoline.c MinHook\src\hook.c MinHook\src\hde\hde32.c MinHook\src\hde\hde64.c /Fe:hook_x64.dll /link user32.lib
```

**注入器：**
```bat
cl /EHsc /O2 /MT injector.cpp /Fe:injector_x64.exe /link /SUBSYSTEM:WINDOWS user32.lib shell32.lib advapi32.lib
```
