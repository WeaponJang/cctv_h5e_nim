# cctv_h5e_decrypt（Nim 版）

把 `hls_h5e` 加密的 CCTV 录像（`.ts` / `.mp4`）原位解密并重新封装为标准 MP4 的小工具。
解密核心是纯 C++ 实现的 `cctv_h5e_decrypt.hpp`，Nim 侧负责分块调度、调用 ffmpeg 封装，以及 Win32 原生 GUI 壳。

产物为**静态链接的单文件 exe**，无需安装运行时，拷贝即可用。

**dec_tui.c** 是一份 c23 的基于 TUI 界面的代码,如果图形化界面无法运行可用此平替。

## 功能

- **GUI**：拖放视频到窗口即可（也可把文件拖到 exe 图标上启动），输出默认同目录、文件名加 `_dec` 后缀；可取消、有进度与日志。
- 输入支持 `.ts` 与 `.mp4`（MP4 会先归一化为 TS 再解密）。
- 输出先写 `.part`，成功后原子替换，失败时目标文件保持原样。
- 视频 PID 可指定，默认 `0x100`。

## 目录结构

```
.
├── cctv_h5e_decrypt.hpp   # 解密核心（C++ header-only，含 C ABI 导出）
├── h5e_core.nim           # 核心逻辑：C ABI 绑定 / PES 分块 / ffmpeg 封装
├── h5e_gui.nim            # Win32 原生 GUI（winim/lean + 少量 FFI）
├── h5e_app.nim            # 程序入口
├── nim.cfg                # 编译与链接选项（静态链接 / 目标文件 / 资源）
├── version.rc             # 版本信息 + 图标 + 清单资源
├── app.manifest           # Common Controls 6.0 + dpiAware
├── app.ico
├── 编译nim.bat             # 一键构建
└── vendor/winim           # 内置 winim（Windows API 绑定，见下方说明）
```

## 依赖

| 依赖 | 用途 | 版本参考 |
|---|---|---|
| [Nim](https://nim-lang.org/) | 编译器 | 2.2.x（开发用 2.2.12） |
| [MinGW-w64](https://www.mingw-w64.org/) | `g++` 编译 hpp、`windres` 编译资源 | GCC 13+ |
| [ffmpeg](https://ffmpeg.org/) | TS/MP4 封装（**运行时**依赖） | 任意较新版本 |

`ffmpeg` 的查找顺序：显式路径 → 环境变量 `FFMPEG_PATH` → `PATH`。
最省事的做法是把 `ffmpeg.exe` 放到 `dec.exe` 同目录，或把其目录加入 `PATH`。

`winim` 已内置在 `vendor/`，不需要联网 `nimble install`。

## 编译

双击 `编译nim.bat`，或手动执行：

```bat
REM 1. 把 header-only 核心编译为 C++ 目标文件
g++ -std=c++20 -O2 -fno-exceptions -fno-rtti -x c++ -DCCTV_H5E_IMPLEMENTATION -c cctv_h5e_decrypt.hpp -o cctv_h5e.o

REM 2. 编译图标 / 版本 / 清单资源
windres -i version.rc -O coff -o version_res.o

REM 3. 构建 dec.exe
nim c -d:release --app:gui -o:dec.exe h5e_app.nim
```

链接参数（静态运行时、`-luser32` / `-lgdi32` / `-lcomctl32` 等）统一在 `nim.cfg` 中维护。

## 使用

双击 `dec.exe` 启动图形界面：

1. 把 `.ts` / `.mp4` 拖到窗口任意位置，或点“浏览…”选择文件；
2. 输出路径默认同目录、文件名加 `_dec` 后缀，可点“另存为…”修改；
3. 点“开始解密”，进度条与日志区实时刷新，中途可取消。

界面上可指定视频 PID，默认 `0x100`（有效范围 `0x0000`–`0x1FFF`）。

## 实现要点

- **按 PES 起点分块**（单块 64MB）：块内原地解密，PTB 长度变化由 AF 填充吸收，避免解密器拿到半截 PES。
- **Session 全程复用**：`type25` 决定 `new_mode`，一旦丢弃后续块全部解不动。
- **GUI 不用工作线程**：转换在 UI 线程内跑，每个进度回调泵一次消息，界面不假死且规避跨线程访问 UI 句柄的竞态。

## vendor/winim 说明

本项目只用到 `winim/lean`（`core` + `utils` + `winstr` 及其 `inc` 依赖）。为控制仓库体积，`vendor/winim` 已裁剪为**仅保留该依赖闭包**（约 1.9MB），移除了 `clr` / `com` / `dotnet` / `extra`、未引用的 `inc/*.nim`，以及 WebView2 的静态库。

如需使用 winim 的其他模块（COM、WebView2、shellapi 等），从上游 <https://github.com/khchen/winim> 取完整源码覆盖 `vendor/winim` 即可。

## 免责声明

本项目仅用于个人学习、研究与自有设备录像的备份恢复。请确保你对所处理的内容拥有合法使用权，并遵守当地法律法规。
