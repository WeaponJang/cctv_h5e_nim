# =============================================================================
# h5e_core.nim — h5e 解密 + MP4 封装核心（与界面解耦的纯逻辑层）
# =============================================================================
#
# 职责：
#   1. 绑定 cctv_h5e_decrypt.hpp 导出的 C ABI（已编译为 cctv_h5e.o）
#   2. 分块解密 TS：按 PES 边界切块，块内原地解密，长度变化由 AF 填充吸收
#   3. 封装 ffmpeg 调用：TS → MP4 封装、MP4 → TS 归一化
#
# 设计要点：
#   - 复用 hpp 里的分块策略（h5e_scan_pes_starts / h5e_decrypt_stream 思路）：
#     只在 PES 起点切块，避免解密器拿到半截 PES。
#   - Session 全程复用：type25 决定 new_mode，丢掉它后面所有块都解不动。
#   - 输出先写 .part，成功后同卷原子替换，失败时目标文件保持原样。
# =============================================================================

import std/[os, strutils, osproc, streams]

type
  H5eSession* = pointer

  # 解密统计
  DecryptStats* = object
    bytes*: int64          # 已处理的字节数
    nals*: int64           # 交给解密器的 NAL 数
    chunks*: int64         # 分块数
    pesFound*: bool        # 是否找到视频 PES

  # 解密结果
  DecryptOutcome* = enum
    outcomeOk,             # 成功
    outcomeNoVideo,        # 未找到视频 PES（未解密任何 NAL）
    outcomeReadError,      # 读取失败
    outcomeWriteError,     # 写入失败
    outcomeDecryptError,   # 解密器返回异常
    outcomeSizeMismatch,   # 输出长度与输入不一致
    outcomeCancelled       # 用户主动取消

  # 单文件处理结果
  FileResult* = object
    outcome*: DecryptOutcome
    outputPath*: string
    stats*: DecryptStats
    message*: string

{.push cdecl.}
proc cctv_h5e_session_create(): H5eSession {.importc: "cctv_h5e_session_create".}
proc cctv_h5e_session_destroy(s: H5eSession) {.importc: "cctv_h5e_session_destroy".}
proc cctv_h5e_session_reset(s: H5eSession) {.importc: "cctv_h5e_session_reset", used.}
proc cctv_h5e_decrypt_ts(s: H5eSession, ts: pointer, tsLen: csize_t, vpid: uint16): cint
  {.importc: "cctv_h5e_decrypt_ts".}
proc cctv_h5e_version(): cstring {.importc: "cctv_h5e_version".}
{.pop.}

const
  DefaultVideoPid* = 0x100'u16
  ChunkBytes* = 64'i64 * 1024 * 1024   # 单块 64 MB
  TsPacketSize* = 188

proc h5eVersion*(): string =
  ## 解密核心版本串（来自 hpp）
  let p = cctv_h5e_version()
  if p.isNil: return "unknown"
  result = $p

# ===== 分块边界扫描 =====
# 视频 PES 起点（PID 命中且 PUSI 置位）。分块只能切在这里：切在包中间或 PES
# 中间，解密器会拿到半截 PES，输出就和“整文件一次处理”不一致了。
# 顺序读一遍，索引只存 64 位偏移（每帧 8 字节），扫描缓冲固定 1.5 MB 左右。
proc scanPesStarts(f: File, vpid: uint16): (seq[int64], bool) =
  const blockSize = TsPacketSize * 8192   # 188 的整数倍，缓冲里始终是整包
  var buf = newSeq[uint8](blockSize)
  var have = 0
  var base = 0'i64
  var starts: seq[int64] = @[]
  while true:
    let got = f.readBuffer(addr buf[0], blockSize - have)
    if got == 0:
      # 读到文件尾才算正常结束；否则说明读取出错
      if int64(base + have) != f.getFileSize():
        return (@[], false)
      break
    have += got
    let pkts = have div TsPacketSize
    for i in 0 ..< pkts:
      let off = i * TsPacketSize
      if buf[off] != 0x47: continue                    # 失步包直接跳过
      # PID 高 5 位必须先转 uint16 再左移：uint8 直接 shl 8 会把高 8 位截掉，
      # 0x100 会被算成 0x00，一个 PES 都扫不出来
      let b1 = uint16(buf[off + 1])
      let b2 = uint16(buf[off + 2])
      if ((b1 and 0x1F'u16) shl 8 or b2) != vpid: continue
      if (buf[off + 1] and 0x40) == 0: continue        # 不是 PES 起点
      starts.add(base + int64(off))
    let used = pkts * TsPacketSize
    have -= used
    if have > 0:
      copyMem(addr buf[0], addr buf[used], have)
    base += int64(used)
  # 文件尾不足 188 字节的残包凑不成包，只能丢弃
  (starts, true)

# ===== 单文件解密 =====
# 按 PES 边界分块解密：每块“读入 → 原地解密 → 追加写 part”，
# Session 全程复用。
proc decryptTsFile*(inPath, outPath: string, vpid: uint16 = DefaultVideoPid,
                    progress: proc(done: int64, total: int64) {.closure, gcsafe.} = nil,
                    cancel: proc(): bool {.closure, gcsafe.} = nil): FileResult =
  result.outputPath = outPath
  if not fileExists(inPath):
    result.outcome = outcomeReadError
    result.message = "输入文件不存在：" & inPath
    return
  let totalSize = getFileSize(inPath)
  if totalSize < 0:
    result.outcome = outcomeReadError
    result.message = "无法读取输入文件：" & inPath
    return
  if totalSize == 0:
    result.outcome = outcomeReadError
    result.message = "输入文件为空：" & inPath
    return

  var f: File
  if not open(f, inPath, fmRead):
    result.outcome = outcomeReadError
    result.message = "无法打开输入文件：" & inPath
    return

  let (pesStarts, scanOk) = scanPesStarts(f, vpid)
  f.close()
  if not scanOk:
    result.outcome = outcomeReadError
    result.message = "读取输入文件失败：" & inPath
    return

  result.stats.pesFound = pesStarts.len > 0
  let partPath = outPath & ".part"
  var fout: File
  if not open(fout, partPath, fmWrite):
    result.outcome = outcomeWriteError
    result.message = "无法写入输出文件：" & partPath
    return

  var session = cctv_h5e_session_create()
  if session.isNil:
    fout.close()
    removeFile(partPath)
    result.outcome = outcomeDecryptError
    result.message = "解密器初始化失败"
    return

  # 分块循环：块起点永远是 PES 起点（首块是 0），保证块内 PES 完整。
  var written = 0'i64
  var begin = 0'i64
  var cursor = 0
  var failed = false

  while begin < totalSize:
    # 只块间检查：块内解密不可中断，块边界是最安全的取消点
    if cancel != nil and cancel():
      failed = true
      result.outcome = outcomeCancelled
      result.message = "已取消"
      break
    let want = begin + ChunkBytes
    while cursor < pesStarts.len and pesStarts[cursor] < want:
      cursor += 1
    let blockEnd = if cursor < pesStarts.len: pesStarts[cursor] else: totalSize
    # 没有任何视频 PES 时按固定块原样搬运
    let blockLen = blockEnd - begin

    var buf = newString(int(blockLen))
    if not open(f, inPath, fmRead):
      failed = true
      result.outcome = outcomeReadError
      result.message = "读取输入文件失败：" & inPath
      break
    f.setFilePos(begin)
    let got = f.readBuffer(addr buf[0], int(blockLen))
    f.close()
    if got != int(blockLen):
      failed = true
      result.outcome = outcomeReadError
      result.message = "读取输入文件失败：" & inPath
      break

    if result.stats.pesFound:
      # 原地解密：长度由 AF 填充吸收，块内字节数不变
      let nals = cctv_h5e_decrypt_ts(session, addr buf[0], csize_t(blockLen), vpid)
      if nals < 0:
        failed = true
        result.outcome = outcomeDecryptError
        result.message = "解密失败（核心返回异常）"
        break
      result.stats.nals += int64(nals)
      result.stats.chunks += 1

    if fout.writeBuffer(addr buf[0], int(blockLen)) != int(blockLen):
      failed = true
      result.outcome = outcomeWriteError
      result.message = "写入输出文件失败：" & partPath
      break

    written += blockLen
    result.stats.bytes = written
    if progress != nil:
      progress(written, totalSize)
    begin = blockEnd

  cctv_h5e_session_destroy(session)
  fout.close()

  if failed:
    removeFile(partPath)
    return

  if written != totalSize:
    removeFile(partPath)
    result.outcome = outcomeSizeMismatch
    result.message = "解密结果长度异常（" & $written & " / " & $totalSize & " 字节）"
    return

  # 原子替换：part 已完整落盘后才动目标文件
  try:
    if fileExists(outPath):
      removeFile(outPath)
    moveFile(partPath, outPath)
  except OSError:
    removeFile(partPath)
    result.outcome = outcomeWriteError
    result.message = "无法替换输出文件：" & outPath
    return

  if not result.stats.pesFound:
    result.outcome = outcomeNoVideo
    result.message = "未找到视频 PES（PID 0x" & toHex(vpid.int, 3).toUpperAscii & "），输入已原样复制，未解密任何 NAL"
  else:
    result.outcome = outcomeOk

# ===== ffmpeg 调用 =====
type
  FfmpegResult* = object
    ok*: bool
    code*: int
    log*: string          # 完整输出（逐行拼接）
    tail*: string         # 末尾几行，失败时直接给用户看

proc findFfmpeg*(explicitPath = ""): string =
  ## 定位 ffmpeg：优先显式路径，其次环境变量 FFMPEG_PATH，最后 PATH
  if explicitPath.len > 0 and fileExists(explicitPath):
    return explicitPath
  let envPath = getEnv("FFMPEG_PATH", "")
  if envPath.len > 0 and fileExists(envPath):
    return envPath
  let exeName = if getEnv("OS", "") == "Windows_NT": "ffmpeg.exe" else: "ffmpeg"
  # 在 PATH 中逐段查找
  for dir in getEnv("PATH", "").split(';'):
    if dir.len == 0: continue
    let cand = dir / exeName
    if fileExists(cand):
      return cand
  # 常见的免安装目录
  for cand in ["C:\\cc\\ffmpeg\\bin\\" & exeName, "C:\\ffmpeg\\bin\\" & exeName]:
    if fileExists(cand):
      return cand
  return ""

proc runFfmpeg*(ffmpegPath: string, args: seq[string],
                onLine: proc(line: string) {.closure, gcsafe.} = nil): FfmpegResult =
  ## 执行 ffmpeg，逐行捕获输出（stderr 并进 stdout 管道，实时推给调用方）。
  ##
  ## 用 readLine 而不是 readAll：readAll 只能读到 44 字节就返回，日志不完整；
  ## readLine 能逐行读到进度条刷新，界面日志不会卡住。
  ##
  ## 关键顺序（Nim 2.2 Windows osproc 实测结论）：
  ##   1. readLine 逐行读
  ##   2. 用 peekExitCode 轮询拿真实退出码
  ##   3. 最后才 close()
  ## 反过来的顺序（先 close 再 waitForExit）会踩两个坑：
  ##   - close() 会连进程句柄一起关掉，waitForExit 拿到的是假退出码 0
  ##   - 直接 waitForExit 而不 close，waitForSingleObject 会永久挂起
  if ffmpegPath.len == 0 or not fileExists(ffmpegPath):
    result.ok = false
    result.code = -1
    result.log = "找不到 ffmpeg 可执行文件"
    result.tail = result.log
    return
  var fullArgs = @["-hide_banner", "-nostdin", "-y"]
  fullArgs.add(args)
  try:
    let child = startProcess(ffmpegPath, args = fullArgs, options = {poStdErrToStdOut})
    var lines: seq[string] = @[]
    # 管道逐行读，实时推送给日志窗口
    var line = newStringOfCap(256)
    while child.outputStream.readLine(line):
      lines.add line
      if onLine != nil:
        onLine(line)
    # EOF 只代表输出流关闭，ffmpeg 可能还在收尾；轮询拿真实退出码
    result.code = -1
    for _ in 0 ..< 200:          # 最多等 10 秒
      result.code = child.peekExitCode()
      if result.code != -1: break
      sleep(50)
    child.close()
    result.ok = result.code == 0
    result.log = lines.join("\n").strip()
    if not result.ok:
      # 取末尾非空行作为错误摘要：ffmpeg 的致命错误总在最后几行
      var tail: seq[string] = @[]
      for i in countdown(lines.len - 1, 0):
        if lines[i].strip().len == 0: continue
        tail.add lines[i]
        if tail.len >= 5: break
      for i in countdown(tail.len - 1, 0):
        result.tail.add tail[i]
        if i > 0: result.tail.add "\n"
  except OSError as e:
    result.ok = false
    result.code = -1
    result.log = "启动 ffmpeg 失败：" & e.msg
    result.tail = result.log

proc tsToMp4*(ffmpegPath, tsPath, mp4Path: string,
               onLine: proc(line: string) {.closure, gcsafe.} = nil): FfmpegResult =
  ## TS → MP4：只做封装（-c copy），不重新编码
  result = runFfmpeg(ffmpegPath, @[
    "-i", tsPath,
    "-c", "copy",
    "-movflags", "+faststart",
    mp4Path
  ], onLine)

proc mp4ToTs*(ffmpegPath, mp4Path, tsPath: string,
              onLine: proc(line: string) {.closure, gcsafe.} = nil): FfmpegResult =
  ## MP4 → TS：把 MP4 里的 H.264 还原成带起始码的 TS，
  ## 使解密器能按 NAL 起始码切分（MP4 内是长度前缀，不是起始码）。
  result = runFfmpeg(ffmpegPath, @[
    "-i", mp4Path,
    "-c", "copy",
    "-bsf:v", "h264_mp4toannexb",
    "-f", "mpegts",
    tsPath
  ], onLine)

proc isMp4File*(path: string): bool =
  ## 依据扩展名判断输入类型（.ts 走原生路径，其余按 MP4 归一化）
  let ext = splitFile(path).ext.toLowerAscii
  ext == ".mp4" or ext == ".m4v" or ext == ".mov" or ext == ".mkv"

proc isTsFile*(path: string): bool =
  let ext = splitFile(path).ext.toLowerAscii
  ext == ".ts" or ext == ".m2ts" or ext == ".mts"

proc cleanFfLine(line: string): string =
  ## ffmpeg 用 \r 刷新进度，一行里可能叠了多段 \r；只取最后一段才有意义。
  let parts = line.split('\r')
  result = parts[^1].strip()

# ===== 高层入口 =====
# 输入：TS 或 MP4；输出：恒定 MP4。
# 步骤：
#   TS  输入 → 解密(TS) → ffmpeg 封装 → MP4
#   MP4 输入 → ffmpeg 转 TS(还原起始码) → 解密(TS) → ffmpeg 封装 → MP4
proc convertToMp4*(inputPath, outputPath: string, ffmpegPath: string,
                   vpid: uint16 = DefaultVideoPid,
                   progress: proc(done: int64, total: int64) {.closure, gcsafe.} = nil,
                   log: proc(msg: string) {.closure, gcsafe.} = nil,
                   cancel: proc(): bool {.closure, gcsafe.} = nil): FileResult =
  if ffmpegPath.len == 0:
    result.outcome = outcomeDecryptError
    result.message = "找不到 ffmpeg，请安装 ffmpeg 或设置 FFMPEG_PATH 环境变量"
    return

  # ffmpeg 的行级输出过滤后转给 log（跳过空行和纯进度行）
  proc ffLog(line: string) {.closure, gcsafe.} =
    if log == nil: return
    let cleaned = cleanFfLine(line)
    if cleaned.len == 0: return
    if cleaned.startsWith("frame=") and cleaned.contains("fps="): return
    log("  ffmpeg │ " & cleaned)

  let workDir = getTempDir()
  let stem = splitFile(inputPath).name
  let tmpTs = workDir / (stem & "_h5e_" & $getCurrentProcessId() & ".ts")

  var tsToDecrypt = inputPath
  var needCleanupTs = false

  if log != nil:
    log("输入：" & inputPath)

  # --- MP4 输入：先归一化成 TS（恢复 NAL 起始码）---
  if isMp4File(inputPath):
    if log != nil:
      log("检测到 MP4 输入，先转成 TS 以恢复 NAL 起始码…")
    let r = mp4ToTs(ffmpegPath, inputPath, tmpTs, ffLog)
    if r.ok:
      tsToDecrypt = tmpTs
      needCleanupTs = true
    else:
      # 扩展名是 mp4 但内容未必是，回退成按 TS 直接解密原文件
      if log != nil:
        log("MP4 → TS 转换失败，回退为按 TS 直接解密原文件…")
      removeFile(tmpTs)

  # --- 解密（进度按当前处理的 TS 计）---
  if log != nil:
    log("解密中…")
  let tmpDecTs = workDir / (stem & "_h5e_dec_" & $getCurrentProcessId() & ".ts")
  let dec = decryptTsFile(tsToDecrypt, tmpDecTs, vpid, progress, cancel)

  if dec.outcome != outcomeOk and dec.outcome != outcomeNoVideo:
    result = dec
    if needCleanupTs:
      removeFile(tmpTs)
    removeFile(tmpDecTs)
    return

  result.stats = dec.stats

  # --- 封装成 MP4 ---
  if log != nil:
    log("封装为 MP4…")
  let mp4 = tsToMp4(ffmpegPath, tmpDecTs, outputPath, ffLog)
  removeFile(tmpDecTs)
  if needCleanupTs:
    removeFile(tmpTs)

  if not mp4.ok:
    result.outcome = outcomeDecryptError
    let detail = if mp4.tail.len > 0: mp4.tail else: mp4.log
    result.message = "MP4 封装失败（ffmpeg 退出码 " & $mp4.code & "）\n" & detail
    return

  result.outcome = dec.outcome
  result.outputPath = outputPath
  result.message = dec.message
  if result.message.len == 0:
    result.message = "完成"
