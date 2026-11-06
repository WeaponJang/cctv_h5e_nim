@echo off
chcp 65001 >nul
cls
REM =============================================================================
REM 编译nim.bat — h5e Nim 版构建脚本（Nim 2.2.12 + MinGW-w64）
REM
REM 产物：
REM   dec.exe     GUI 子系统（双击 = 图形界面，可拖放视频）
REM
REM 链接选项统一在 nim.cfg 中维护（静态链接 / hpp 目标文件 / 版本资源）。
REM
REM 注意：echo 的内容一律用 ASCII。cmd 解析 .bat 是按启动时的代码页取字节，
REM       chcp 65001 只影响控制台输出，UTF-8 中文在 echo 里仍会被拆坏
REM       （尤其全角括号和 ^< ^| 转义），因此中文只放在 REM 注释里。
REM =============================================================================
cd /d "%~dp0"

REM ---- 工具链定位：PATH 优先，回退已知安装位置 ----
where nim >nul 2>nul
if errorlevel 1 (
  if exist "C:\cc\nim\bin\nim.exe" set "PATH=%PATH%;C:\cc\nim\bin"
)
where g++ >nul 2>nul
if errorlevel 1 (
  if exist "C:\cc\mingw64\bin\g++.exe" set "PATH=%PATH%;C:\cc\mingw64\bin"
)
where nim >nul 2>nul
if errorlevel 1 (echo [ERROR] nim not found, need Nim 2.2.x & pause & exit /b 1)
where g++ >nul 2>nul
if errorlevel 1 (echo [ERROR] g++ not found, need MinGW-w64 & pause & exit /b 1)
where windres >nul 2>nul
if errorlevel 1 (echo [ERROR] windres not found, need MinGW-w64 & pause & exit /b 1)

REM ---- 1. hpp 原样编译为 C++ 目标文件（C ABI + 全部内联核心，一字不改）----
echo [1/3] Compiling decrypt core -> cctv_h5e.o
g++ -std=c++20 -O2 -fno-exceptions -fno-rtti -x c++ -DCCTV_H5E_IMPLEMENTATION -c cctv_h5e_decrypt.hpp -o cctv_h5e.o
if errorlevel 1 (echo [ERROR] cctv_h5e_decrypt.hpp build failed & pause & exit /b 1)

REM ---- 2. 版本资源（图标 + 文件属性 + 进程清单 app.manifest）----
REM     app.manifest 声明 Common Controls 6.0 与 dpiAware，
REM     缺了它按钮/进度条会退回 Win95 经典样式。
echo [2/3] Compiling version resource -> version_res.o
windres -i version.rc -O coff -o version_res.o
if errorlevel 1 (echo [ERROR] version.rc build failed & pause & exit /b 1)

REM ---- 3. GUI 产物（窗口程序，无控制台）----
echo [3/3] Building GUI target -> dec.exe
nim c -d:release --app:gui -o:dec.exe h5e_app.nim
if errorlevel 1 (echo [ERROR] GUI build failed & pause & exit /b 1)

echo.
echo BUILD OK
dir /n/b dec.exe
echo.
echo Usage:
echo   dec.exe   GUI, drag and drop TS / MP4 onto the window
echo.

REM ---- 启动 GUI 便于立即验收（不阻塞脚本）----
start "" dec.exe
pause>nul
