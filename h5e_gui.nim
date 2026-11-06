# =============================================================================
# h5e_gui.nim — 图形界面壳（Win32 原生，winim/lean + 少量 FFI）
# =============================================================================
#
# 交互设计：
#   - 拖放视频到窗口任意位置即可填入输入；也支持“浏览…”选择
#   - 输出恒为 MP4，默认与输入同目录、文件名加 _dec 后缀
#   - 转换在 UI 线程内跑，但每个回调都泵一遍消息：界面不假死，
#     取消按钮能及时被点到（核心模块在块边界检查取消标志）
#
# 为什么不用线程：
#   convertToMp4 的回调是 Nim 闭包，跨线程要么开 --threads:on 管理 GC
#   状态，要么绕开 GC 传字符串；单线程 + 泵消息（PeekMessage）能拿到
#   同样的效果，且不会出现“工作线程回调碰 UI 句柄”的竞态。
#
# 依赖：
#   winim/lean（vendor 内置）提供 user32/gdi32 绑定；
#   shell32/comdlg32/comctl32 用 dynlib 声明，运行期由系统加载。
# =============================================================================

import std/[os, strutils, times]
import h5e_core
import winim/lean

# ===== 额外 FFI（winim/lean 不含 shellapi / commdlg / commctrl）=====

type
  HDROP = HANDLE

  # Nim 标识符忽略大小写与下划线，类型名不能叫 INITCOMMONCONTROLSEX
  # （会与下面的 InitCommonControlsEx 过程同名）。
  CommonControlsEx = object
    dwSize: DWORD
    dwICC: DWORD

  # OPENFILENAMEW：字段顺序与 commdlg.h 严格一致，
  # 布局错一位 GetOpenFileNameW 就会失败（lStructSize 校验）。
  OPENFILENAMEW = object
    lStructSize: DWORD
    hwndOwner: HWND
    hInstance: HINSTANCE
    lpstrFilter: LPCWSTR
    lpstrCustomFilter: LPWSTR
    nMaxCustFilter: DWORD
    nFilterIndex: DWORD
    lpstrFile: LPWSTR
    nMaxFile: DWORD
    lpstrFileTitle: LPWSTR
    nMaxFileTitle: DWORD
    lpstrInitialDir: LPCWSTR
    lpstrTitle: LPCWSTR
    Flags: DWORD
    nFileOffset: WORD
    nFileExtension: WORD
    lpstrDefExt: LPCWSTR
    lCustData: LPARAM
    lpfnHook: LPVOID
    lpTemplateName: LPCWSTR
    pvReserved: LPVOID
    dwReserved: DWORD
    FlagsEx: DWORD

when sizeof(int) == 8:
  static:
    doAssert sizeof(OPENFILENAMEW) == 152
else:
  static:
    doAssert sizeof(OPENFILENAMEW) == 88

const
  # winim 的 DWORD 是 int32（Win32 原生定义），常量跟着标注类型
  ICC_PROGRESS_CLASS: DWORD = 0x00000020

  # 进度条消息（commctrl.h）：直接基于 WM_USER 计算，
  # 类型跟着 winim 的 UINT 走，避免自定常量类型不匹配 SendMessageW。
  PBM_SETPOS     = WM_USER + 2
  PBM_SETRANGE32 = WM_USER + 6

  # 文件对话框标志（commdlg.h）
  OFN_OVERWRITEPROMPT: DWORD = 0x00000002
  OFN_HIDEREADONLY:    DWORD = 0x00000004
  OFN_NOCHANGEDIR:     DWORD = 0x00000008
  OFN_PATHMUSTEXIST:   DWORD = 0x00000800
  OFN_FILEMUSTEXIST:   DWORD = 0x00001000
  OFN_EXPLORER:        DWORD = 0x00080000

proc DragAcceptFiles(hwnd: HWND, fAccept: WINBOOL)
  {.importc, stdcall, dynlib: "shell32.dll".}
proc DragQueryFileW(hDrop: HDROP, iFile: UINT, lpszFile: LPWSTR, cch: UINT): UINT
  {.importc, stdcall, dynlib: "shell32.dll".}
proc DragFinish(hDrop: HDROP) {.importc, stdcall, dynlib: "shell32.dll".}
proc ShellExecuteW(hwnd: HWND, lpOperation, lpFile, lpParameters, lpDirectory: LPCWSTR,
                   nShowCmd: INT): HINSTANCE {.importc, stdcall, dynlib: "shell32.dll".}
proc GetOpenFileNameW(ofn: ptr OPENFILENAMEW): WINBOOL
  {.importc, stdcall, dynlib: "comdlg32.dll".}
proc GetSaveFileNameW(ofn: ptr OPENFILENAMEW): WINBOOL
  {.importc, stdcall, dynlib: "comdlg32.dll".}
proc InitCommonControlsEx(picce: ptr CommonControlsEx): WINBOOL
  {.importc, stdcall, dynlib: "comctl32.dll".}

# ===== 常量 =====

const
  AppTitle = "CCTV H5E 视频解密"
  WinClassName = "H5eGuiMain"

  IdInput    = 101
  IdOutput   = 102
  IdBtnIn    = 103
  IdBtnOut   = 104
  IdPid      = 105
  IdStart    = 106
  IdCancel   = 107
  IdLog      = 108
  IdProgress = 109
  IdStatus   = 110
  IdPct      = 111
  IdLogTitle = 112

  # 设计尺寸一律按 96 DPI 写，运行期由 dp() 换算到实际 DPI。
  # 客户区 820x600：三行输入 + 进度条 + 自适应日志区 + 底部操作行。
  ClientW = 820
  ClientH = 600
  MinClientW = 680
  MinClientH = 500

  ProgressClass = "msctls_progress32"

  # 配色。集中在这里调，避免十六进制散落到各处
  ClrWindow:  COLORREF = RGB(0xF4, 0xF6, 0xF8)  # 窗口底：极浅灰蓝
  ClrSurface: COLORREF = RGB(0xFF, 0xFF, 0xFF)  # 输入区：纯白
  ClrText:    COLORREF = RGB(0x2B, 0x31, 0x38)  # 主文字：近黑
  ClrTextDim: COLORREF = RGB(0x7A, 0x82, 0x8C)  # 提示/状态：中灰

# ===== 界面状态 =====

type
  GuiState = object
    hwnd: HWND
    hInput, hOutput: HWND
    hBtnIn, hBtnOut: HWND
    hPid, hHint: HWND
    hLblIn, hLblOut, hLblPid: HWND
    hStart, hCancel: HWND
    hProgress, hLog, hStatus: HWND
    hPct, hLogTitle: HWND
    font: HFONT          # 正文（雅黑）
    fontLog: HFONT       # 日志区（小一号，信息密度更高）
    fontSmall: HFONT     # 百分比/分区小标题
    brWindow: HBRUSH     # 窗口底色
    brSurface: HBRUSH    # 输入区底色
    winStyle: DWORD      # 建窗样式，WM_GETMINMAXINFO 反推外框要用
    dpi: int             # 当前屏幕 DPI（96 为基准）
    busy: bool            # 转换进行中
    cancelRequested: bool # 用户点了取消 / 关了窗口

var g: GuiState

# ===== 小工具 =====

proc dp(v: int): int =
  ## 96 DPI 下的设计像素 → 当前 DPI 的实际像素。
  ## 四舍五入而不是截断：dp(1) 在 125% 下得到 1 而不是 0，细边距不会凭空消失。
  if g.dpi <= 0 or g.dpi == 96: return v
  (v * g.dpi + 48) div 96

proc initDpi() =
  ## 取屏幕 DPI。清单已声明 dpiAware（system aware），
  ## 所以这里的值就是真实缩放比例，不是被系统拉伸后的值。
  let screenDc = GetDC(0)
  let d = int(GetDeviceCaps(screenDc, LOGPIXELSY))
  discard ReleaseDC(0, screenDc)
  g.dpi = if d > 0: d else: 96

proc setText(h: HWND, s: string) =
  ## 显式建 WideCString 再取址传参。
  ## 不直接依赖 string→LPCWSTR 的隐式转换：它的临时缓冲区在 -d:release
  ## 下可能提前释放，表现为“调用成功但控件文本没变”。
  if h == 0: return
  let w = newWideCString(s)
  discard SetWindowTextW(h, cast[LPCWSTR](w[0].unsafeAddr))

proc getText(h: HWND): string =
  if h == 0: return ""
  let n = int(GetWindowTextLengthW(h))
  if n <= 0: return ""
  let buf = newWideCString("", n + 1)
  discard GetWindowTextW(h, buf, int32(n + 1))
  result = $buf

proc setStatus(s: string) =
  setText(g.hStatus, s)

proc setProgress(pct: int) =
  let v = max(0, min(100, pct))
  if g.hProgress != 0:
    SendMessageW(g.hProgress, PBM_SETPOS, WPARAM(v), 0)
  # 进度条右侧同步一个数字：空槽时看不出跑了多少
  setText(g.hPct, $v & "%")

proc appendLog(msg: string) =
  ## 只读 EDIT 追加一行：临时解除只读 → 定位末尾 → 插入 → 恢复只读。
  if g.hLog == 0: return
  # 行数过多时整段清空，避免 EDIT 内部缓冲无限膨胀拖慢界面
  if int(SendMessageW(g.hLog, EM_GETLINECOUNT, 0, 0)) > 5000:
    SetWindowTextW(g.hLog, "")
  let textLen = int(SendMessageW(g.hLog, WM_GETTEXTLENGTH, 0, 0))
  SendMessageW(g.hLog, EM_SETREADONLY, 0, 0)
  SendMessageW(g.hLog, EM_SETSEL, WPARAM(textLen), LPARAM(textLen))
  let payload = if textLen == 0: msg else: "\r\n" & msg
  let wtext = newWideCString(payload)
  # 必须传字符数据指针：cast[LPARAM](wtext) 会把对象头（长度字段）
  # 当成指针发过去，EDIT 收到的是无效地址。
  SendMessageW(g.hLog, EM_REPLACESEL, 0, cast[LPARAM](wtext[0].unsafeAddr))
  SendMessageW(g.hLog, EM_SETREADONLY, 1, 0)
  # 滚到最新一行
  let lines = int(SendMessageW(g.hLog, EM_GETLINECOUNT, 0, 0))
  SendMessageW(g.hLog, EM_LINESCROLL, 0, LPARAM(lines))

proc pumpMessages(): bool =
  ## 处理一遍待处理消息。返回 false 表示收到 WM_QUIT（窗口已销毁）。
  var msg: MSG
  while PeekMessageW(addr msg, 0, 0, 0, PM_REMOVE) != 0:
    if msg.message == WM_QUIT:
      return false
    TranslateMessage(addr msg)
    DispatchMessageW(addr msg)
  true

proc lockUi(busy: bool) =
  ## 转换期间锁住输入相关控件，只留“取消”可点
  EnableWindow(g.hInput, not busy)
  EnableWindow(g.hOutput, not busy)
  EnableWindow(g.hBtnIn, not busy)
  EnableWindow(g.hBtnOut, not busy)
  EnableWindow(g.hPid, not busy)
  EnableWindow(g.hStart, not busy)
  EnableWindow(g.hCancel, busy)

proc defaultOutput(inPath: string): string =
  let (dir, name, _) = splitFile(inPath)
  result = dir / (name & "_dec.mp4")

proc parsePid(s: string): uint16 =
  var t = s.strip()
  if t.len == 0: return DefaultVideoPid
  try:
    if t.startsWith("0x") or t.startsWith("0X"):
      let v = parseHexInt(t)
      if v <= 0x1FFF: return uint16(v)
    else:
      let v = parseInt(t)
      if v >= 0 and v <= 0x1FFF: return uint16(v)
  except ValueError:
    discard
  DefaultVideoPid

proc fmtDuration(seconds: float): string =
  if seconds < 60:
    result = formatFloat(seconds, ffDecimal, 1) & " 秒"
  else:
    let total = int(seconds)
    result = $(total div 60) & " 分 " & align($(total mod 60), 2, '0') & " 秒"

# ===== 文件对话框 =====

const VideoFilter =
  "视频文件 (*.ts;*.mp4;*.m2ts;*.m4v;*.mov)\0" &
  "*.ts;*.mp4;*.m2ts;*.m4v;*.mov\0" &
  "MPEG-TS (*.ts;*.m2ts)\0*.ts;*.m2ts\0" &
  "MP4 视频 (*.mp4;*.m4v;*.mov)\0*.mp4;*.m4v;*.mov\0" &
  "所有文件 (*.*)\0*.*\0\0"

const MaxPathBuf = 4096

proc pickFile(owner: HWND, saveMode: bool, initial: string, title: string): string =
  ## 打开文件对话框。initial 只用来推导起始目录，不预填文件名。
  let buf = newWideCString("", MaxPathBuf)
  let filterW = newWideCString(VideoFilter)
  let titleW = newWideCString(title)
  let defExtW = newWideCString("mp4")
  var initDirW = newWideCString("")
  if initial.len > 0:
    let d = parentDir(initial)
    if d.len > 0:
      initDirW = newWideCString(d)

  var ofn: OPENFILENAMEW
  ofn.lStructSize = DWORD(sizeof(OPENFILENAMEW))
  ofn.hwndOwner = owner
  ofn.hInstance = GetModuleHandle(nil)
  ofn.lpstrFilter = filterW
  ofn.lpstrFile = buf
  ofn.nMaxFile = DWORD(MaxPathBuf)
  ofn.lpstrInitialDir = initDirW
  ofn.lpstrTitle = titleW
  ofn.Flags = OFN_EXPLORER or OFN_PATHMUSTEXIST or OFN_NOCHANGEDIR or OFN_HIDEREADONLY
  if saveMode:
    ofn.Flags = ofn.Flags or OFN_OVERWRITEPROMPT
    ofn.lpstrDefExt = defExtW
  else:
    ofn.Flags = ofn.Flags or OFN_FILEMUSTEXIST

  let ok = if saveMode: GetSaveFileNameW(addr ofn) else: GetOpenFileNameW(addr ofn)
  if ok == 0: return ""
  result = $buf

# ===== 转换流程 =====

proc samePath(a, b: string): bool =
  ## 比较两个路径是否指向同一位置。
  ## 不能用 expandFilename：目标文件还不存在时它会抛 OSError。
  ## Nim 2.2 的 normalizePath 是就地修改（var 参数），不是返回值。
  var pa = absolutePath(a)
  var pb = absolutePath(b)
  normalizePath(pa)
  normalizePath(pb)
  cmpIgnoreCase(pa, pb) == 0

proc convertFlow() =
  let inPath = getText(g.hInput).strip()
  if inPath.len == 0:
    discard MessageBoxW(g.hwnd, "请先选择要解密的视频文件（可直接拖放进来）。",
                        AppTitle, MB_ICONWARNING)
    return
  if not fileExists(inPath):
    discard MessageBoxW(g.hwnd, "输入文件不存在：" & inPath, AppTitle, MB_ICONWARNING)
    return

  var outPath = getText(g.hOutput).strip()
  if outPath.len == 0:
    outPath = defaultOutput(inPath)
    setText(g.hOutput, outPath)
  if samePath(inPath, outPath):
    discard MessageBoxW(g.hwnd, "输出文件不能与输入文件相同，请换一个输出路径。",
                        AppTitle, MB_ICONWARNING)
    return

  let ff = findFfmpeg()
  if ff.len == 0:
    discard MessageBoxW(g.hwnd,
      "找不到 ffmpeg.exe。\n\n" &
      "请把 ffmpeg 加入 PATH，或设置环境变量 FFMPEG_PATH 指向 ffmpeg.exe。",
      AppTitle, MB_ICONERROR)
    return

  let vpid = parsePid(getText(g.hPid))

  g.busy = true
  g.cancelRequested = false
  lockUi(true)
  setProgress(0)
  setStatus("准备中…")

  let t0 = epochTime()
  appendLog("── 开始处理 ──")
  appendLog("输入：" & inPath)
  appendLog("输出：" & outPath)
  appendLog("ffmpeg：" & ff)
  if vpid != DefaultVideoPid:
    appendLog("视频 PID：0x" & toHex(vpid.int, 3).toUpperAscii)

  var lastPct = -1
  # 解密阶段占进度条 0-70%，封装阶段由 ffmpeg 自行完成（进度条停在 70）
  let res = convertToMp4(inPath, outPath, ff, vpid,
    progress = proc(done, total: int64) {.closure, gcsafe.} =
      if total > 0:
        let pct = int(done * 70 div total)
        if pct != lastPct:
          lastPct = pct
          setProgress(pct)
          setStatus("解密中… " & $pct & "%")
      discard pumpMessages()      # 让取消按钮保持可点
    ,
    log = proc(msg: string) {.closure, gcsafe.} =
      appendLog(msg)
      discard pumpMessages()
    ,
    cancel = proc(): bool {.closure, gcsafe.} =
      discard pumpMessages()
      result = g.cancelRequested
  )

  let elapsed = epochTime() - t0
  g.busy = false
  lockUi(false)
  g.cancelRequested = false

  case res.outcome
  of outcomeOk:
    setProgress(100)
    setStatus("完成 · 用时 " & fmtDuration(elapsed))
    appendLog("完成：解密 " & $res.stats.nals & " 个 NAL，" &
              $res.stats.chunks & " 块，用时 " & fmtDuration(elapsed))
    appendLog("输出：" & res.outputPath)
    let choice = MessageBoxW(g.hwnd,
      "解密完成。\n\n用时 " & fmtDuration(elapsed) & "\n输出：" & res.outputPath &
      "\n\n是否打开所在文件夹？",
      AppTitle, MB_ICONINFORMATION or MB_YESNO)
    if choice == IDYES:
      discard ShellExecuteW(g.hwnd, "open", "explorer.exe",
                            newWideCString("/select,\"" & res.outputPath & "\""),
                            nil, SW_SHOWNORMAL)
  of outcomeNoVideo:
    setProgress(100)
    setStatus("未找到视频 PES")
    appendLog("警告：" & res.message)
    discard MessageBoxW(g.hwnd,
      res.message & "\n\n输出文件已生成，但画面仍是加密的。" &
      "\n可尝试在“视频 PID”里指定正确的 PID（常见 0x100 / 0x101 / 0x200）。",
      AppTitle, MB_ICONWARNING)
  of outcomeCancelled:
    setProgress(0)
    setStatus("已取消")
    appendLog("已取消，未生成输出文件。")
  else:
    setStatus("失败")
    appendLog("失败：" & res.message)
    discard MessageBoxW(g.hwnd, "处理失败。\n\n" & res.message, AppTitle, MB_ICONERROR)

  if g.hwnd != 0:
    SetForegroundWindow(g.hwnd)

proc onStart() =
  ## 点“开始”的统一入口：转换过程中的任何异常都在这里兜住，
  ## 不能让它掀掉消息循环（否则表现为“点了按钮程序就消失”）。
  if g.busy: return
  try:
    convertFlow()
  except CatchableError as e:
    g.busy = false
    g.cancelRequested = false
    lockUi(false)
    setStatus("内部错误")
    appendLog("内部错误：" & e.msg)
    discard MessageBoxW(g.hwnd, "发生内部错误：\n" & e.msg, AppTitle, MB_ICONERROR)

# ===== 窗口过程 =====

proc createChild(parent: HWND, cls: LPCWSTR, text: string, style, exStyle: int,
                 x, y, w, h: int, id: int): HWND =
  let wtext = newWideCString(text)
  result = CreateWindowExW(DWORD(exStyle), cls, wtext, DWORD(style),
    int32(x), int32(y), int32(w), int32(h),
    parent, cast[HMENU](id), GetModuleHandle(nil), nil)

proc place(h: HWND, x, y, cx, cy: int, repaint: WINBOOL = TRUE) =
  ## MoveWindow 只接受 int32，而 layout 里算出来的都是 int，
  ## 在这里统一收口转换；句柄为 0 时直接跳过。
  if h == 0: return
  MoveWindow(h, int32(x), int32(y), int32(cx), int32(cy), repaint)

proc layout() =
  ## 尺寸全部从客户区实测宽高推导：拖边框时整体重排，不依赖建窗时的常量。
  ##
  ## 竖向分三段：
  ##   1. 三行输入（标签 | 输入框 | 行尾按钮，三列各自对齐）
  ##   2. 进度条
  ##   3. 日志区吃掉剩余高度；底部操作行贴底
  if g.hwnd == 0 or g.hInput == 0: return

  var rc: RECT
  GetClientRect(g.hwnd, addr rc)
  let cw = int(rc.right)
  let ch = int(rc.bottom)
  # 建窗初期客户区可能还没成型，此时排一遍只会把控件挤成一团
  if cw < dp(200) or ch < dp(150): return

  let pad    = dp(20)     # 四周边距
  let gap    = dp(10)     # 控件横向间隙
  let labelW = dp(66)     # 标签列宽（“输出文件”四个全角字不裁切）
  let rowH   = dp(30)     # 单行控件高度
  let rowGap = dp(10)     # 行间距
  let btnW   = dp(96)     # 行尾按钮宽

  # 三列竖向对齐：标签 | 输入 | 行尾按钮
  let labX  = pad
  let editX = pad + labelW + gap
  let actX  = cw - pad - btnW
  let editW = max(dp(160), actX - gap - editX)

  var y = dp(20)

  place(g.hLblIn, labX, y, labelW, rowH)
  place(g.hInput, editX, y, editW, rowH)
  place(g.hBtnIn, actX, y, btnW, rowH)
  y += rowH + rowGap

  place(g.hLblOut, labX, y, labelW, rowH)
  place(g.hOutput, editX, y, editW, rowH)
  place(g.hBtnOut, actX, y, btnW, rowH)
  y += rowH + rowGap

  let pidW = dp(100)
  place(g.hLblPid, labX, y, labelW, rowH)
  place(g.hPid, editX, y, pidW, rowH)
  # 提示文字拿本行右侧剩余宽度；文本本身保持简短，宽度永远够用
  let hintX = editX + pidW + dp(14)
  let hintW = max(dp(120), actX + btnW - hintX)
  place(g.hHint, hintX, y + (rowH - dp(19)) div 2, hintW, dp(19))
  y += rowH + dp(18)

  # 进度行：条 + 右侧百分比，两者垂直居中
  let pctW = dp(52)
  let barH = dp(18)
  place(g.hProgress, pad, y, cw - 2 * pad - pctW - dp(10), barH)
  place(g.hPct, cw - pad - pctW, y, pctW, barH + dp(2))
  y += barH + dp(16)

  # 日志区：上方一行小标题，让白块有个交代
  place(g.hLogTitle, pad, y, cw - 2 * pad, dp(16))
  y += dp(16) + dp(6)

  # 底部操作行贴底，日志区吃掉中间剩余空间
  let actionH = dp(38)
  let actionY = ch - dp(20) - actionH
  let cancelW = dp(104)
  let startW  = dp(124)
  let cancelX = cw - pad - cancelW
  let startX  = cancelX - gap - startW
  let logH = max(dp(80), actionY - dp(18) - y)

  place(g.hLog, pad, y, cw - 2 * pad, logH)
  place(g.hStatus, pad, actionY + (actionH - dp(22)) div 2,
        max(dp(100), startX - gap - pad), dp(22))
  place(g.hStart, startX, actionY, startW, actionH)
  place(g.hCancel, cancelX, actionY, cancelW, actionH)

proc onDrop(hDrop: HDROP) =
  let n = int(DragQueryFileW(hDrop, 0, nil, 0))
  if n > 0:
    let buf = newWideCString("", n + 2)
    discard DragQueryFileW(hDrop, 0, buf, UINT(n + 1))
    let path = $buf
    if path.len > 0:
      setText(g.hInput, path)
      setText(g.hOutput, defaultOutput(path))
      appendLog("已选择：" & path)
  DragFinish(hDrop)

proc WindowProc(hwnd: HWND, message: UINT, wParam: WPARAM,
                lParam: LPARAM): LRESULT {.stdcall.} =
  case message
  of WM_CREATE:
    g.hwnd = hwnd

    # 字体：雅黑优先，缺失时系统自动回退。
    # 高度按 DPI 缩放，否则在 125%/144% 屏上字会显得很小。
    let face = newWideCString("Microsoft YaHei UI")
    g.font = CreateFontW(int32(-dp(15)), 0, 0, 0, FW_NORMAL, 0, 0, 0,
                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                         CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH or FF_DONTCARE, face)
    g.fontLog = CreateFontW(int32(-dp(14)), 0, 0, 0, FW_NORMAL, 0, 0, 0,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            DEFAULT_PITCH or FF_DONTCARE, face)
    g.fontSmall = CreateFontW(int32(-dp(13)), 0, 0, 0, FW_NORMAL, 0, 0, 0,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH or FF_DONTCARE, face)

    # 标签兼做单行却垂直居中（SS_CENTERIMAGE），否则文字会贴在框顶。
    let labelStyle = WS_CHILD or WS_VISIBLE or SS_LEFT or SS_CENTERIMAGE
    # 编辑框只保留 WS_EX_CLIENTEDGE 一种边框：
    # 之前 WS_BORDER + 客户端边同时用，会画出两道框线。
    let editStyle = WS_CHILD or WS_VISIBLE or WS_TABSTOP or ES_AUTOHSCROLL
    let btnStyle = WS_CHILD or WS_VISIBLE or WS_TABSTOP or BS_PUSHBUTTON

    # 坐标全交给 layout() 算，这里只给 0 占位，避免两处尺寸各写一份。
    g.hLblIn = createChild(hwnd, "STATIC", "输入文件", labelStyle, 0, 0, 0, 0, 0, 0)
    g.hInput = createChild(hwnd, "EDIT", "", editStyle, WS_EX_CLIENTEDGE,
                           0, 0, 0, 0, IdInput)
    g.hBtnIn = createChild(hwnd, "BUTTON", "浏览…", btnStyle, 0, 0, 0, 0, 0, IdBtnIn)

    g.hLblOut = createChild(hwnd, "STATIC", "输出文件", labelStyle, 0, 0, 0, 0, 0, 0)
    g.hOutput = createChild(hwnd, "EDIT", "", editStyle, WS_EX_CLIENTEDGE,
                            0, 0, 0, 0, IdOutput)
    g.hBtnOut = createChild(hwnd, "BUTTON", "另存为…", btnStyle, 0, 0, 0, 0, 0, IdBtnOut)

    g.hLblPid = createChild(hwnd, "STATIC", "视频 PID", labelStyle, 0, 0, 0, 0, 0, 0)
    g.hPid = createChild(hwnd, "EDIT", "0x100", editStyle, WS_EX_CLIENTEDGE,
                         0, 0, 0, 0, IdPid)
    # 旧文本在 480px 里装不下，尾部被窗口裁掉。
    # 改成短句（常见取值写在日志区和失败提示里），任何窗口宽度都放得下。
    g.hHint = createChild(hwnd, "STATIC", "默认 0x100，解不出画面时再改",
                          labelStyle, 0, 0, 0, 0, 0, 0)

    var ccx = CommonControlsEx(
      dwSize: DWORD(sizeof(CommonControlsEx)),
      dwICC: ICC_PROGRESS_CLASS)
    discard InitCommonControlsEx(addr ccx)
    g.hProgress = createChild(hwnd, ProgressClass, "",
      WS_CHILD or WS_VISIBLE, WS_EX_CLIENTEDGE, 0, 0, 0, 0, IdProgress)
    SendMessageW(g.hProgress, PBM_SETRANGE32, 0, LPARAM(100))
    SendMessageW(g.hProgress, PBM_SETPOS, 0, 0)
    # 进度条右侧的百分比；右对齐，位数变化时不跳动
    g.hPct = createChild(hwnd, "STATIC", "0%", labelStyle or SS_RIGHT,
                         0, 0, 0, 0, 0, IdPct)

    g.hLogTitle = createChild(hwnd, "STATIC", "处理日志", labelStyle,
                              0, 0, 0, 0, 0, IdLogTitle)
    g.hLog = createChild(hwnd, "EDIT", "",
      WS_CHILD or WS_VISIBLE or WS_VSCROLL or ES_MULTILINE or ES_AUTOVSCROLL or
      ES_READONLY or ES_LEFT,
      WS_EX_CLIENTEDGE, 0, 0, 0, 0, IdLog)

    g.hStatus = createChild(hwnd, "STATIC", "就绪：把 TS / MP4 拖进窗口，或点“浏览…”",
                            labelStyle, 0, 0, 0, 0, 0, IdStatus)
    # “开始”用默认按钮：有主题时会画出主操作强调色，回车也能触发
    g.hStart = createChild(hwnd, "BUTTON", "开始解密",
                           btnStyle or BS_DEFPUSHBUTTON, 0, 0, 0, 0, 0, IdStart)
    g.hCancel = createChild(hwnd, "BUTTON", "取消", btnStyle, 0, 0, 0, 0, 0, IdCancel)
    EnableWindow(g.hCancel, false)

    # 统一字体：之前漏了 STATIC 标签，它们一直在用系统默认的宋体
    for h in [g.hLblIn, g.hLblOut, g.hLblPid, g.hHint, g.hInput, g.hOutput,
              g.hBtnIn, g.hBtnOut, g.hPid, g.hStatus, g.hStart, g.hCancel]:
      SendMessageW(h, WM_SETFONT, WPARAM(g.font), LPARAM(TRUE))
    SendMessageW(g.hLog, WM_SETFONT, WPARAM(g.fontLog), LPARAM(TRUE))
    for h in [g.hPct, g.hLogTitle]:
      SendMessageW(h, WM_SETFONT, WPARAM(g.fontSmall), LPARAM(TRUE))

    # 单行输入框：限长 + 左右内缩，文字不贴边框
    for h in [g.hInput, g.hOutput, g.hPid]:
      SendMessageW(h, EM_SETLIMITTEXT, WPARAM(2048), 0)
      SendMessageW(h, EM_SETMARGINS, WPARAM(EC_LEFTMARGIN or EC_RIGHTMARGIN),
                   LPARAM((dp(8) shl 16) or dp(6)))
    # 日志区同样留内边距，中文贴着边线很难看
    SendMessageW(g.hLog, EM_SETMARGINS, WPARAM(EC_LEFTMARGIN or EC_RIGHTMARGIN),
                 LPARAM((dp(10) shl 16) or dp(10)))

    DragAcceptFiles(hwnd, TRUE)
    layout()
    return 0

  of WM_SIZE:
    layout()
    return 0

  of WM_GETMINMAXINFO:
    # 限制最小尺寸，再小日志区就没了。
    # 给的是外框尺寸，所以先拿客户区最小尺寸反推非客户区。
    let mmi = cast[ptr MINMAXINFO](lParam)
    var rc = RECT(left: 0, top: 0,
                  right: LONG(dp(MinClientW)), bottom: LONG(dp(MinClientH)))
    AdjustWindowRectEx(addr rc, g.winStyle, FALSE, 0)
    mmi.ptMinTrackSize.x = rc.right - rc.left
    mmi.ptMinTrackSize.y = rc.bottom - rc.top
    return 0

  of WM_CTLCOLORSTATIC, WM_CTLCOLOREDIT:
    # 默认情况下每块 STATIC / EDIT 都用自己的背景刷，灰底窗上会浮出一堆
    # 白方块。这里统一：输入类控件给白底，其余文字透明、透出窗口底色。
    let hdc = cast[HDC](wParam)
    let ctl = cast[HWND](lParam)
    if ctl == g.hLog or ctl == g.hInput or ctl == g.hOutput or ctl == g.hPid:
      SetBkColor(hdc, ClrSurface)
      return cast[LRESULT](g.brSurface)
    SetBkMode(hdc, TRANSPARENT)
    if ctl == g.hHint or ctl == g.hStatus or ctl == g.hPct or ctl == g.hLogTitle:
      SetTextColor(hdc, ClrTextDim)
    else:
      SetTextColor(hdc, ClrText)
    return cast[LRESULT](g.brWindow)

  of WM_DROPFILES:
    onDrop(cast[HDROP](wParam))
    return 0

  of WM_COMMAND:
    let id = int(wParam and 0xFFFF)
    case id
    of IdBtnIn:
      let cur = getText(g.hInput)
      let p = pickFile(hwnd, false, cur, "选择要解密的视频文件")
      if p.len > 0:
        setText(g.hInput, p)
        setText(g.hOutput, defaultOutput(p))
        appendLog("已选择：" & p)
    of IdBtnOut:
      let cur = getText(g.hOutput)
      let p = pickFile(hwnd, true, cur, "选择输出 MP4 文件")
      if p.len > 0:
        setText(g.hOutput, p)
    of IdStart:
      onStart()
    of IdCancel:
      if g.busy:
        g.cancelRequested = true
        setStatus("正在取消…")
    else:
      discard
    return 0

  of WM_CLOSE:
    if g.busy:
      # 转换中：只置取消标志，等块边界退出后再关
      g.cancelRequested = true
      setStatus("正在取消…")
      return 0
    DestroyWindow(hwnd)
    return 0

  of WM_DESTROY:
    # 子窗口已随父窗口销毁，此时删字体/画刷不会影响绘制
    if g.brWindow != 0: discard DeleteObject(g.brWindow)
    if g.brSurface != 0: discard DeleteObject(g.brSurface)
    if g.font != 0: discard DeleteObject(g.font)
    if g.fontLog != 0: discard DeleteObject(g.fontLog)
    if g.fontSmall != 0: discard DeleteObject(g.fontSmall)
    PostQuitMessage(0)
    return 0

  else:
    return DefWindowProc(hwnd, message, wParam, lParam)

# ===== 入口 =====

proc runGui*() =
  ## 注册窗口类 → 建窗 → 消息循环。由 h5e_app.nim 调用。
  when defined(windows):
    # 清单（app.manifest）已声明 dpiAware，这里的调用会返回失败；
    # 保留它是给不带清单的调试构建兜底。
    discard SetProcessDPIAware()
  initDpi()

  # 窗口 / 输入区背景刷：后面 WM_CTLCOLOR* 里直接复用
  g.brWindow = CreateSolidBrush(ClrWindow)
  g.brSurface = CreateSolidBrush(ClrSurface)

  let hInstance = GetModuleHandle(nil)

  let classNameW = newWideCString(WinClassName)
  let titleW = newWideCString(AppTitle)
  let hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(1))
  let cursor = LoadCursorW(0, IDC_ARROW)

  var wc: WNDCLASSEXW
  wc.cbSize = DWORD(sizeof(WNDCLASSEXW))
  wc.style = CS_HREDRAW or CS_VREDRAW
  wc.lpfnWndProc = WindowProc
  wc.cbClsExtra = 0
  wc.cbWndExtra = 0
  wc.hInstance = hInstance
  wc.hIcon = (if hIcon != 0: hIcon else: LoadIconW(0, IDI_APPLICATION))
  wc.hIconSm = wc.hIcon
  wc.hCursor = cursor
  wc.hbrBackground = g.brWindow
  wc.lpszMenuName = nil
  wc.lpszClassName = classNameW

  if RegisterClassExW(addr wc) == 0:
    discard MessageBoxW(0, "窗口类注册失败。", AppTitle, MB_ICONERROR)
    return

  # 可拖边框拉伸：尺寸先按客户区目标反推外框
  var rc = RECT(left: 0, top: 0,
                right: LONG(dp(ClientW)), bottom: LONG(dp(ClientH)))
  let style = DWORD(WS_OVERLAPPEDWINDOW)
  # WM_GETMINMAXINFO 在建窗期间就会到达，必须先备好样式
  g.winStyle = style
  AdjustWindowRectEx(addr rc, style, FALSE, 0)
  let winW = rc.right - rc.left
  let winH = rc.bottom - rc.top
  let screenW = GetSystemMetrics(SM_CXSCREEN)
  let screenH = GetSystemMetrics(SM_CYSCREEN)
  let posX = max(0, (screenW - winW) div 2)
  let posY = max(0, (screenH - winH) div 2)

  let hwnd = CreateWindowExW(WS_EX_ACCEPTFILES, classNameW, titleW, style,
    posX, posY, winW, winH, 0, 0, hInstance, nil)
  if hwnd == 0:
    discard MessageBoxW(0, "主窗口创建失败。", AppTitle, MB_ICONERROR)
    return

  # 拖动 exe 图标到窗口外启动时，命令行第一个参数直接当输入
  let args = commandLineParams()
  if args.len > 0 and fileExists(args[0]):
    setText(g.hInput, args[0])
    setText(g.hOutput, defaultOutput(args[0]))

  ShowWindow(hwnd, SW_SHOW)
  UpdateWindow(hwnd)

  # 日志区先给两行引导：空白白块看不出这里是干什么的。
  # 放在 ShowWindow 之后写，是因为 WM_CREATE 期间 EDIT 还没完成初次布局，
  # 那时插入的文本会被随后的首次绘制擦掉。
  setText(g.hLog, "提示：把 TS / MP4 拖进窗口，或点“浏览…”选择文件。\r\n" &
                 "解密进度与 ffmpeg 日志会实时显示在这里。")
  var msg: MSG
  while GetMessageW(addr msg, 0, 0, 0) > 0:
    TranslateMessage(addr msg)
    DispatchMessageW(addr msg)
