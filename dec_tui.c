/* ============================================================================
 * dec_tui.c —— “输入媒体 → FFmpeg 转封装 MP4(分片) → 解密 → FFmpeg 转封装 MP4”
 * ============================================================================
 *
 * 与 dec.c 的关系：本文件由 dec.c 复制派生。解密引擎（TEA-16 / EPB / 网格布局 /
 * type1、type5、classic 分派 / 会话状态）与 dec.c 逐字节相同，解密算法一行未改；
 * 区别只在“视频 NAL 从哪里来、解密后写回哪里”：
 *
 *   dec.c        : 输入本身就是加密 TS → 按 188 字节包 + 视频 PID 重组 PES →
 *                  扫 NAL start code → 原地解密 → 撑 AF 补差额 → 写回 TS
 *   dec_tui.c : 输入(TS/MP4) 先由 ffmpeg 命令行流复制成分片 MP4，再从 moof/trun
 *                  描述的样本里按 AVCC 长度前缀取 NAL → 同一套引擎解密 →
 *                  把变短的 NAL 连同新长度写回样本 → 改写 trun 的样本字节数与
 *                  mdat 大小 → 仍是分片 MP4 → 再交给 ffmpeg 流复制成最终 MP4
 *
 * 三个阶段严格串行，不调换、不跳过、不合并：
 *   ① ffmpeg -i <输入> -map 0:v:0 -c copy -movflags +frag_keyframe+empty_moov
 *            +default_base_moof -f mp4 <临时>/stage1.m4v
 *            -map 0:a:0 -c copy -f mp4 <临时>/audio.m4a
 *      （真实落盘；一条命令行两个输出：输入只解复用一次，视频流复制进分片 MP4、音频流
 *        同时复制进 MP4 音频轨 —— 音频旁路。输入没有音频流时这条命令在“解析输出参数”
 *        阶段就失败，程序退回“只转视频”，再探测输入有没有音频流决定是否旁路）
 *   ② 本程序：stage1.m4v → stage2.m4v（视频 NAL 解密，容器仍是分片 MP4）
 *   ③ ffmpeg -i stage2.m4v -i audio.m4a -map 0:v:0 -map 1:a:0 -c copy \
 *      -movflags +faststart
 *            -f mp4 <输出>.part  → 原子替换 <输出>
 *
 * 用法：dec_tui.exe <输入.ts|.mp4> <输出.mp4> [--ffmpeg <ffmpeg路径>]
 *       dec_tui.exe      （不带任何参数：进入 TUI 界面填写参数，Enter 开始；
 *                            收集完成后走的就是上面同一条流水线）
 * 编译：gcc -std=c23 -Os -s -flto -ffunction-sections -fdata-sections
 *              -Wl,--gc-sections -DNDEBUG -o dec_tui.exe dec_tui.c -lshell32
 *       （见 编译dec_tui.cmd）
 * ========================================================================== */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>

#if !defined(_WIN32)
/* 非 Windows 平台没有宽字符命令行/文件 API，直接提示退出 */
int main(void) {
    fputs("dec_tui.exe 仅支持 Windows\n", stderr);
    return 1;
}
#else

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h> /* CommandLineToArgvW：取宽字符命令行，链接需 -lshell32 */

#define H5E_VERSION "cctv_h5e MP4 pipeline 4.0.0.0 (F5/F1+EPB+AF/audio-bypass)"

/* MP4 路径下的默认视频选择：stage1.m4v 只有一条视频轨，pid 退化为此常量（与 dec.c 默认一致） */
#define H5E_DEFAULT_VIDEO_PID 0x100u

/* 会话句柄：状态结构定义见引擎段末尾 */
typedef struct cctv_h5e_session cctv_h5e_session;

#if defined(__GNUC__) || defined(__clang__)
#  define H5E_UNUSED __attribute__((unused))
#else
#  define H5E_UNUSED
#endif

#define H5E_GRID_TAIL_GUARD 17u   /* 网格单元起点处至少要剩余这么多字节（跟随播放器判定） */
#define H5E_TYPE1_MIN_LEN   129u  /* 短于该长度的 type1 原样透传（不网格解密、不丢 EPB） */
#define H5E_CLASSIC_MIN_LEN 48u   /* classic 网格的最小 NAL / RBSP 长度（type5 与 type1 共用） */

/* 解析密钥窗口时的有界前缀长度：只需覆盖 RBSP[0..31] 对应的 EBSP 字节。
 * 最坏情况（00 00 03 反复）下第 31 个 RBSP 字节落在偏移 48 之前，64 留足余量。 */
#define H5E_PREFIX_WINDOW   64u


/* ============================ 解密引擎开始 ============================ */
/* 以下到“解密引擎（NAL 级）结束”为止的代码与 dec.c 逐字节一致，勿单独改动；
 * 要与 dec.c 同步修改。 */

/* TEA-16：8 字节分组、小端 32 位字、delta = 0x9E3779B9、16 轮。
 * 加密版只在自查时用来验证解密，CLI 路径不调用。 */
static H5E_UNUSED void h5e_tea_encrypt_block(uint8_t out[8], const uint8_t in[8],
                                            const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 16; i++) {
        sum += delta;
        v0 += (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        v1 += (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
    }
    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

/* TEA-16 解密：轮序与轮数和加密一致，sum 从 delta*16 递减回 0。 */
static void h5e_tea_decrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    const uint32_t delta = 0x9E3779B9u;
    uint32_t sum = delta * 16u;
    for (int i = 0; i < 16; i++) {
        v1 -= (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
        v0 -= (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        sum -= delta;
    }
    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

/* 收集 NAL 中所有 EPB（00 00 03）的起点偏移，供网格解密后统一丢弃 0x03。
 * 用 memchr 批量找 0x00（内部是字宽/SIMD 实现），再验证后两个字节；
 * 命中后跳 3 字节——00 00 03 的第二、三个字节不可能再是 EPB 起点。
 * 返回 0 成功；-1 为内存不足。 */
static int h5e_collect_epb(const uint8_t *nal, size_t len, size_t **out_pos, size_t *out_n) {
    *out_pos = NULL;
    *out_n = 0;
    if (!nal || len < 3) return 0;
    size_t cap = len / 3 + 1;
    size_t *epbs = (size_t *)malloc(cap * sizeof(size_t));
    if (!epbs) return -1;
    size_t n = 0;
    size_t i = 0;
    const size_t limit = len - 2; /* 候选起点 i 必须满足 i + 2 < len */
    while (i < limit) {
        const uint8_t *p = (const uint8_t *)memchr(nal + i, 0, limit - i);
        if (!p) break;
        size_t e = (size_t)(p - nal);
        if (nal[e + 1] == 0 && nal[e + 2] == 3) {
            epbs[n++] = e;
            i = e + 3;
        } else {
            i = e + 1;
        }
    }
    *out_pos = epbs;
    *out_n = n;
    return 0;
}

/* 按记录好的位置丢掉 EPB 的第三个字节 0x03，返回删除后的长度。
 * 删掉的字节集合与 dec.c 一致（每个 epbs[i] + 2），只是把逆序逐次 memmove 换成
 * 前向按段批量搬运：读游标 r 到下一个删除点之间的整段一次搬完，整体 O(n)。
 * dec.c 的 require_intact 恒为 false（播放器按解密前的位置盲删），故不再保留。 */
static size_t h5e_drop_epb_03(uint8_t *nal, size_t len, const size_t *epbs, size_t n) {
    if (!nal || n == 0) return len;
    size_t w = 0; /* 写游标 */
    size_t r = 0; /* 读游标（未搬运的起点） */
    for (size_t i = 0; i < n; i++) {
        const size_t del = epbs[i] + 2;
        if (del >= len) continue; /* 与 dec.c 的 "e + 2 >= nlen" 保护对应（实际不可达） */
        if (del < r) continue;    /* 防御：EPB 间距 >= 3，实际不会触发 */
        memmove(nal + w, nal + r, del - r);
        w += del - r;
        r = del + 1;
    }
    if (r < len) {
        memmove(nal + w, nal + r, len - r);
        w += len - r;
    }
    return w;
}

/* RBSP 下标 → EBSP 偏移（取代 dec.c 的 r2e[] 整表）。
 * 游标 k 只前进不回退：k = max{ m : epbs[m] + 2 - m <= r }，则 e = r + k。
 * epbs 严格升序且间距 >= 3，该式对 k 单调，所以线性推进就能拿到最大值，
 * 结果与 dec.c 的 r2e[r] 逐值相同。 */
typedef struct {
    const size_t *epbs; /* 升序 EPB 起点（EBSP 坐标） */
    size_t nep;
    size_t k; /* 已越过的 EPB 数 */
} h5e_rbsp_map;

static void h5e_rbsp_map_init(h5e_rbsp_map *m, const size_t *epbs, size_t nep) {
    m->epbs = epbs;
    m->nep = nep;
    m->k = 0;
}

/* 前置条件：调用方保证 r 单调不减，且 r < nr（RBSP 总长）。 */
static size_t h5e_rbsp_at(h5e_rbsp_map *m, size_t r) {
    while (m->k < m->nep && m->epbs[m->k] + 2 - m->k <= r) m->k++;
    return r + m->k;
}

/* 有界前缀解析：把 RBSP[start .. start+n) 的字节取到 out，只看前 64 字节。
 * 返回 0 成功；1 表示窗口内确定不了（调用方须回退到 h5e_gather_rbsp_full）。
 * EPB 的前两个 0x00 仍算 RBSP 字节，只跳过第三个字节 0x03——
 * 即 dec.c 里“先填 i、i+1，再 i += 3”的等价写法。 */
static int h5e_gather_rbsp_prefix(const uint8_t *nal, size_t len, size_t start, uint8_t *out,
                                  size_t n) {
    const size_t wlen = (len < (size_t)H5E_PREFIX_WINDOW) ? len : (size_t)H5E_PREFIX_WINDOW;
    size_t r = 0, e = 0, got = 0;
    while (e < wlen && got < n) {
        if (e + 2 < wlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
            for (int t = 0; t < 2 && got < n; t++) {
                if (r >= start) out[got++] = nal[e + t];
                r++;
            }
            e += 3; /* 跳过 EPB 的 03：RBSP 下标不前进 */
            continue;
        }
        if (r >= start) out[got++] = nal[e];
        r++;
        e++;
    }
    return (got == n) ? 0 : 1;
}

/* 全量回退路径：结果与 dec.c 的 r2e[] 完全等价，只在前缀窗口不够时才走。
 * 返回 0 成功；1 表示下标越界或内存不足（对应 dec.c 返回 0 的情形）。 */
static int h5e_gather_rbsp_full(const uint8_t *nal, size_t len, size_t start, uint8_t *out,
                                size_t n) {
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return 1;
    const size_t nr = len - nep;
    if (start + n > nr) {
        free(epbs);
        return 1;
    }
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    for (size_t b = 0; b < n; b++) out[b] = nal[h5e_rbsp_at(&m, start + b)];
    free(epbs);
    return 0;
}

/* 步长闭式解：直接由密钥字节算出网格间隔，不做查表拟合 */
static const uint16_t h5e_type5_f5_base[6] = {160, 192, 224, 256, 288, 320};

/* F5 步长：把密钥前 4 字节当小端 32 位数，模 6 选中 BASE 档位，
 * 再或上同下标的密钥字节——所以间隔总是落在 160..320 这 6 个档位里。
 * key16 只需前 6 字节有效。 */
static uint32_t h5e_type5_stride_f5(const uint8_t *key16) {
    uint32_t le = (uint32_t)key16[0] | ((uint32_t)key16[1] << 8) |
                  ((uint32_t)key16[2] << 16) | ((uint32_t)key16[3] << 24);
    unsigned idx = (unsigned)(le % 6u);
    return (uint32_t)h5e_type5_f5_base[idx] | (uint32_t)key16[idx];
}

/* 从 type5 NAL 取密钥（RBSP[5:11] 共 6 字节）算 F5 步长。
 * 只读 6 字节，因此先走有界前缀，窗口不够时回退全量；
 * 两条路径取到的字节相同，步长自然相同。取不到时返回 0。 */
static uint32_t h5e_type5_stride_from_nal(const uint8_t *nal, size_t len) {
    if (!nal || len < 21) return 0;
    uint8_t key[6];
    if (h5e_gather_rbsp_prefix(nal, len, 5, key, 6) != 0 &&
        h5e_gather_rbsp_full(nal, len, 5, key, 6) != 0) {
        return 0; /* 对应 dec.c 的 nr < 11 或建表失败 */
    }
    return h5e_type5_stride_f5(key);
}

/* type1 的 F1 步长：档位选择规则与 F5 相同，只是密钥改成 RBSP[1:7]。 */
static uint32_t h5e_type1_stride_from_nal(const uint8_t *nal, size_t len) {
    if (!nal || len < 7) return 0;
    uint8_t key[6];
    if (h5e_gather_rbsp_prefix(nal, len, 1, key, 6) != 0 &&
        h5e_gather_rbsp_full(nal, len, 1, key, 6) != 0) {
        return 0; /* 对应 dec.c 的 nr < 7 或建表失败 */
    }
    return h5e_type5_stride_f5(key);
}

/* type1 的 G 变换：16 步移位寄存器运算，每步由 fbit 反馈产生一个输出位；
 * 帧头所属的“族”决定其中若干步的反馈位要取反（翻转掩码）。 */
static int h5e_type1_fbit(uint32_t W) {
    const int w0 = (W >> 0) & 1;
    const int w8 = (W >> 8) & 1;
    const int w15 = (W >> 15) & 1;
    const int w19 = (W >> 19) & 1;
    const int w25 = (W >> 25) & 1;
    const int w30 = (W >> 30) & 1;
    const int w31 = (W >> 31) & 1;
    const int t = w0 | w8;
    return (w31 ^ w15 ^ t ^ (w8 & w19) ^ (w25 & (w0 ^ w19)) ^ (w0 & (1 ^ w8) & w30) ^
            ((1 ^ w0) & w19 & w30) ^ (w25 & w30 & (w8 ^ w19))) & 1;
}

/* 注入位闭式：切片头第 2、3 字节拼成 16 位字后按位反转。
 * 第 s 步 (0..7) 注入 nal[2] 的第 (7-s) 位，第 s 步 (8..15) 注入 nal[1] 的第 (15-s) 位。
 * 取代按帧头“家族”拟合的翻转表 + B 步常量叠加：后者只覆盖已观测到的帧头，
 * 且 0x61 族的掩码与 nal[1] 无关，遇到未拟合的 (nal[1], nal[2]) 组合会整帧解错。 */
static uint16_t h5e_type1_header_bits(uint8_t b1, uint8_t b2) {
    const uint32_t w = ((uint32_t)b2 << 8) | b1;
    uint16_t m = 0;
    for (int s = 0; s < 16; s++) m = (uint16_t)(m | (uint16_t)(((w >> (15 - s)) & 1u) << s));
    return m;
}

/* G 变换主体：W = Y:X 拼成 32 位寄存器，跑 16 步。
 * 每步输出位 = fbit ^ 注入位，输出按 s=0 对应最高位拼成 P1，
 * 寄存器左移并把输出位回填。X/Y 是小端读出的两个 16 位单元，P1 即解密后的前 2 字节。 */
static uint16_t h5e_type1_G(uint16_t X, uint16_t Y, uint16_t bits) {
    uint32_t W = (uint32_t)X | ((uint32_t)Y << 16);
    uint16_t P1 = 0;
    for (int s = 0; s < 16; s++) {
        const int b = h5e_type1_fbit(W) ^ ((bits >> s) & 1);
        P1 = (uint16_t)(P1 | (b << (15 - s)));
        W = ((W << 1) | (uint32_t)b) & 0xFFFFFFFFu;
    }
    return P1;
}

/* type1 新模式网格：起始下标、间隔、尾部余量都由会话给出（默认 64 / F1 步长 / 17）。
 * 单元只 4 字节，尾部仍要求留足 guard 字节；字节一律经映射表按 RBSP 取。
 * 与 type5 的差别：只要存在 EPB 就丢 03，不看有没有解过单元。
 * 返回处理后的 NAL 长度。 */
static size_t h5e_decrypt_type1_new(uint8_t *nal, size_t len, uint32_t stride, size_t start,
                                    size_t guard) {
    if (!nal || stride < 4 || len < H5E_TYPE1_MIN_LEN) return len;
    /* 帧头在循环前快照，注入位是它的纯函数，提出来只算一次；
     * 没有任何单元能写到 RBSP[0..2]（start >= 32），所以提前算安全。 */
    const uint16_t bits = h5e_type1_header_bits(nal[1], nal[2]);
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    const size_t nr = len - nep; /* 与 dec.c 的 nr 完全相同 */
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    bool any_cell = false;
    for (size_t k = 0;; k++) {
        const size_t o = start + k * (size_t)stride;
        if (o + guard > nr || o + 4 > nr) break;
        size_t off[4];
        for (size_t b = 0; b < 4; b++) off[b] = h5e_rbsp_at(&m, o + b);
        const uint16_t X = (uint16_t)(nal[off[0]] | (nal[off[1]] << 8));
        const uint16_t Y = (uint16_t)(nal[off[2]] | (nal[off[3]] << 8));
        const uint16_t P1 = h5e_type1_G(X, Y, bits);
        nal[off[0]] = (uint8_t)(P1 & 0xFF);
        nal[off[1]] = (uint8_t)((P1 >> 8) & 0xFF);
        nal[off[2]] = (uint8_t)(X & 0xFF);
        nal[off[3]] = (uint8_t)((X >> 8) & 0xFF);
        any_cell = true;
    }
    /* 与 type5/classic 一致：一个单元都没解过的 NAL 原样透传，不丢 EPB。 */
    size_t out_len = len;
    if (nep != 0 && any_cell) out_len = h5e_drop_epb_03(nal, len, epbs, nep);
    free(epbs);
    return out_len;
}

/* type5 新模式网格：TEA 密钥取 RBSP[5:21]，单元从 RBSP[64] 开始、间隔 stride，
 * 每个单元 8 字节。密钥与单元都按 RBSP 编号，因此 EPB 必须靠映射表换算。
 * 至少解过一个单元才丢 EPB 03。返回处理后的 NAL 长度。 */
static size_t h5e_decrypt_type5_new(uint8_t *nal, size_t len, uint32_t stride) {
    if (!nal || len < 21 || stride < 8) return len;
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    const size_t nr = len - nep;
    if (nr < 21) {
        free(epbs);
        return len;
    }
    /* 密钥窗口内若有 EPB，EBSP 与 RBSP 的偏移就错开了，
     * 必须经映射表取字节，否则密钥错、后面所有单元全解错。 */
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[h5e_rbsp_at(&m, 5 + b)];
    uint8_t tmp[8];
    bool any_cell = false;
    for (size_t k = 0;; k++) {
        const size_t o = 64 + k * (size_t)stride;
        if (o + H5E_GRID_TAIL_GUARD > nr || o + 8 > nr) break;
        size_t off[8];
        for (size_t b = 0; b < 8; b++) off[b] = h5e_rbsp_at(&m, o + b);
        for (size_t b = 0; b < 8; b++) tmp[b] = nal[off[b]];
        h5e_tea_decrypt_block(tmp, tmp, key);
        for (size_t b = 0; b < 8; b++) nal[off[b]] = tmp[b];
        any_cell = true;
    }
    /* 丢 EPB 03 属于网格处理：一个单元都没解过的 NAL 原样透传 */
    size_t out_len = len;
    if (nep != 0 && any_cell) out_len = h5e_drop_epb_03(nal, len, epbs, nep);
    free(epbs);
    return out_len;
}

/* classic 网格（老流：type25 出现的是 01 06 而不是 01 09）：起点 32、间隔 80、
 * 每单元 8 字节 TEA-16，密钥取 RBSP[16:32]；尾单元要求还剩一整个 stride。
 * 至少解过一个单元才丢 EPB 03。返回处理后的 NAL 长度。 */
static size_t h5e_decrypt_classic_grid(uint8_t *nal, size_t len) {
    if (!nal || len < H5E_CLASSIC_MIN_LEN) return len;
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    const size_t nr = len - nep;
    if (nr < H5E_CLASSIC_MIN_LEN) {
        free(epbs);
        return len;
    }
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[h5e_rbsp_at(&m, 16 + b)];
    bool any_cell = false;
    for (size_t k = 0;; k++) {
        const size_t o = 32 + k * (size_t)80;
        if (o + 80 > nr) break;
        size_t off[8];
        for (size_t b = 0; b < 8; b++) off[b] = h5e_rbsp_at(&m, o + b);
        uint8_t blk[8];
        for (size_t b = 0; b < 8; b++) blk[b] = nal[off[b]];
        h5e_tea_decrypt_block(blk, blk, key);
        for (size_t b = 0; b < 8; b++) nal[off[b]] = blk[b];
        any_cell = true;
    }
    /* 连一个 classic 单元（32+80）都放不下的 NAL 原样透传：
     * 此时丢 EPB 只会让长度变短，却没解出任何内容。 */
    size_t out_len = len;
    if (nep != 0 && any_cell) out_len = h5e_drop_epb_03(nal, len, epbs, nep);
    free(epbs);
    return out_len;
}

/* 会话：跨 NAL、跨分块保留的解密状态 */
struct cctv_h5e_session {
    bool new_mode;       /* 网格布局：true = 新模式（type25 魔数 01 09），false = classic（01 06） */
    bool should_decrypt; /* 是否解密：看 type25 的 payload[0] 是不是 1 */
    size_t type1_start;  /* type1 新模式网格的起始 RBSP 下标 */
    size_t type1_guard;  /* type1 网格的尾部判定余量 */
    size_t type1_min_len;/* 短于该长度的 type1 不解密 */
};

/* 会话初始状态：classic 布局、不解密 type1/type5，等 type25 把开关打开 */
static void h5e_session_init(cctv_h5e_session *s) {
    s->new_mode = false;
    s->should_decrypt = false;
    s->type1_start = 64;
    s->type1_guard = H5E_GRID_TAIL_GUARD;
    s->type1_min_len = H5E_TYPE1_MIN_LEN;
}

/* 单条 NAL 的分派入口：type25 只更新会话状态（开关 + 网格布局）；
 * type1/type5 在开关打开时按当前布局解密，并把新长度写回 *io_len。 */
static void h5e_session_on_nal(cctv_h5e_session *s, uint8_t *nal, size_t *io_len) {
    if (!s || !nal || !io_len || *io_len < 1) return;
    const size_t len = *io_len;
    const int ntype = nal[0] & 0x1f;
    if (ntype == 25) {
        s->should_decrypt = (len >= 2 && nal[1] == 1);
        /* 魔数决定网格布局，且允许中途双向切换（老流先 01 06 classic，
         * 后续分片再切到 01 09 新模式）：01 09 → 新模式；01 06 → classic。 */
        if (len >= 4 && nal[2] == 0x01) {
            if (nal[3] == 0x09) s->new_mode = true;
            else if (nal[3] == 0x06) s->new_mode = false;
        }
        return;
    }
    if ((ntype != 1 && ntype != 5) || !s->should_decrypt) return;
    if (!s->new_mode) {
        /* classic 的 type1 仍按 type1_min_len 透传；type5 只受 classic 网格的 48 字节门槛约束 */
        if (ntype == 1 && len < s->type1_min_len) return;
        *io_len = h5e_decrypt_classic_grid(nal, len);
        return;
    }
    if (ntype == 5) {
        uint32_t S = h5e_type5_stride_from_nal(nal, len);
        if (S >= 8) *io_len = h5e_decrypt_type5_new(nal, len, S);
        return;
    }
    if (ntype == 1) {
        if (len < s->type1_min_len) return;
        uint32_t S = h5e_type1_stride_from_nal(nal, len);
        if (S == 0) S = 511u;
        *io_len = h5e_decrypt_type1_new(nal, len, S, s->type1_start, s->type1_guard);
    }
}

/* ===================== 解密引擎（NAL 级）结束 ===================== */

/* ================= MPEG-TS 层（保留语义，MP4 路径不调用） ================= */
/*
 * 下面这一段是 dec.c 的 TS 处理层，原样保留：
 *   - 它体现“视频 PID → PES 重组 → PES 内的 NAL → 解密后按 188 字节回填”的
 *     原始语义，与 MP4 路径共用同一个会话与同一套 NAL 解密核心；
 *   - MP4 路径不需要它，因为样本里已经带 NALU 长度前缀，解密变短后直接改写长度即可，
 *     等价于这里的“撑 AF 补偿”；
 *   - 保留它是为了让两条路径的语义可对照，也便于将来把中间格式换回 TS 时直接复用。
 */

/* 把单个 TS 包的 AF 撑大，从 payload 尾部抢走 need 字节（用 0xFF 填）。
 * 本来只有 payload 的包新建 AF（afc 1→3），已有 AF 的包则延长 AF 体。
 * 返回实际抢到的字节数。 */
static H5E_UNUSED size_t h5e_expand_af_steal(uint8_t *data, size_t len, size_t pkt_off, size_t need) {
    if (!data || need == 0 || pkt_off + 188 > len) return 0;
    int afc = (data[pkt_off + 3] & 0x30) >> 4;
    if (afc == 1) {
        /* 无 AF：新建 AF，占用 1（长度字节）+ af_len 字节 */
        if (need < 1) return 0;
        size_t af_len = need - 1;
        if (af_len > 182) af_len = 182;
        size_t steal = 1 + af_len;
        uint8_t old_payload[184];
        memcpy(old_payload, data + pkt_off + 4, 184);
        data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30); /* afc=3：AF + payload */
        data[pkt_off + 4] = (uint8_t)af_len;
        if (af_len > 0) {
            data[pkt_off + 5] = 0x00; /* AF flags：无随机接入点、无 PCR */
            for (size_t i = 1; i < af_len; i++) data[pkt_off + 5 + i] = 0xFF;
        }
        size_t new_pl = 184 - steal;
        memcpy(data + pkt_off + 5 + af_len, old_payload, new_pl);
        return steal;
    }
    if (afc == 2 || afc == 3) {
        size_t af_len = data[pkt_off + 4];
        size_t pi = 5 + af_len;
        if (pi >= 188) return 0;
        size_t old_payload_len = 188 - pi;
        size_t add = need < old_payload_len ? need : old_payload_len;
        if (add == 0) return 0;
        if (af_len + add > 182) {
            add = 182 - af_len;
            if (add == 0) return 0;
        }
        size_t new_af_len = af_len + add;
        uint8_t old_payload[184];
        memcpy(old_payload, data + pkt_off + pi, old_payload_len);
        /* 新腾出的空间填 0xFF（TS 标准的 AF 保留值） */
        for (size_t i = 0; i < add; i++) data[pkt_off + 5 + af_len + i] = 0xFF;
        data[pkt_off + 4] = (uint8_t)new_af_len;
        size_t new_pl = old_payload_len - add;
        memcpy(data + pkt_off + 5 + new_af_len, old_payload, new_pl);
        if (new_pl == 0) data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x20); /* 只剩 AF：afc=2 */
        else data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30);            /* 还有 payload：afc=3 */
        return add;
    }
    return 0;
}

/* 一个 TS 包在缓冲里的 payload 区间，用于把重组后的 PES 按原顺序散写回去。 */
typedef struct {
    size_t pkt_off; /* 包起始在 TS 缓冲内的偏移 */
    size_t pi;      /* 包内 payload 起始（afc=1 时 4，否则 5 + AF 长度） */
    size_t pl;      /* 包内 payload 字节数 */
} h5e_span;

/* ES 内找到的一处 NAL start code。 */
typedef struct {
    size_t pos; /* start code 在 ES 内的偏移 */
    size_t sc;  /* start code 长度：3（00 00 01）或 4（00 00 00 01） */
} h5e_sc;

/* 缓冲按需扩容：*cap 是当前元素容量，elem 是单元素字节数，need 是所需元素数。
 * 容量从 64 起按 2 倍递增；缓冲只在单个 PES 规模内增长，与块大小无关。
 * 返回 0 成功；-1 为溢出或内存不足，此时原缓冲仍然有效。
 * MP4 路径也复用它做分片缓冲的扩容。 */
static int h5e_reserve(void **buf, size_t *cap, size_t need, size_t elem) {
    if (need <= *cap) return 0;
    size_t ncap = *cap ? *cap : 64;
    while (ncap < need) {
        if (ncap > SIZE_MAX / 2) {
            ncap = need;
            break;
        }
        ncap <<= 1;
    }
    if (elem == 0 || ncap > SIZE_MAX / elem) return -1;
    void *p = realloc(*buf, ncap * elem);
    if (!p) return -1;
    *buf = p;
    *cap = ncap;
    return 0;
}

/* 处理 PES 的工作区：所有缓冲都按需增长并跨 PES 复用，不逐块释放。 */
typedef struct {
    cctv_h5e_session *session; /* 跨 PES、跨块复用的解密状态 */
    uint8_t *pes;              /* 累积的 PES 字节，同时也存放重建结果（省掉单独的 out 缓冲） */
    h5e_span *spans;           /* 该 PES 各包 payload 区间 */
    h5e_sc *starts;            /* 该 PES 内的 NAL start code 列表 */
    size_t pes_n, pes_cap;
    size_t spans_n, spans_cap;
    size_t starts_n, starts_cap;
    size_t nal_count; /* 经过会话的 NAL 数，用于判断是否真的解到了东西 */
    bool oom;         /* 扩容失败标记：上层据此区分“内存不足”与“没有 NAL” */
} h5e_ts_ctx;

/* 处理一个完整 PES，分四个阶段：跳过 PES 头 → 扫 NAL start code → 逐条解密并
 * 原地重建 → 撑 AF 补差额后散写回各包 payload。 */
static H5E_UNUSED void h5e_flush_pes(uint8_t *data, size_t len, h5e_ts_ctx *ctx) {
    if (ctx->pes_n == 0) return;
    uint8_t *pes = ctx->pes;
    const size_t pes_n = ctx->pes_n;

    size_t base_skip = 0;
    if (pes_n >= 9 && pes[0] == 0 && pes[1] == 0 && pes[2] == 1) base_skip = 9 + pes[8];
    if (base_skip > pes_n) {
        ctx->pes_n = 0;
        ctx->spans_n = 0;
        return;
    }

    const size_t es_off = base_skip;
    const size_t es_n = pes_n - es_off;
    uint8_t *es = pes + es_off;

    /* 扫描 ES 内的 NAL start code：memchr 找 0x00，再判 4 字节 / 3 字节；
     * 优先次序与推进方式与 dec.c 的逐字节版一致 */
    size_t ns = 0;
    for (size_t i = 0; i + 3 < es_n;) {
        const uint8_t *p = (const uint8_t *)memchr(es + i, 0, (es_n - 3) - i);
        if (!p) break;
        const size_t j = (size_t)(p - es);
        size_t sc = 0;
        if (j + 4 <= es_n && es[j + 1] == 0 && es[j + 2] == 0 && es[j + 3] == 1) {
            sc = 4;
        } else if (es[j + 1] == 0 && es[j + 2] == 1) {
            sc = 3;
        }
        if (sc == 0) {
            i = j + 1;
            continue;
        }
        if (h5e_reserve((void **)&ctx->starts, &ctx->starts_cap, ns + 1, sizeof(h5e_sc)) != 0) {
            ctx->oom = true;
            ctx->pes_n = 0;
            ctx->spans_n = 0;
            ctx->starts_n = 0;
            return;
        }
        ctx->starts[ns].pos = j;
        ctx->starts[ns].sc = sc;
        ns++;
        i = j + sc;
    }
    ctx->starts_n = ns;

    /* 原地重建：out_n 是 pes 内的写游标，恒不越过“已消费的读位置” */
    size_t out_n = base_skip;

    size_t cursor = 0;
    for (size_t idx = 0; idx < ns; idx++) {
        const size_t pos = ctx->starts[idx].pos;
        const size_t sc = ctx->starts[idx].sc;
        const size_t end = (idx + 1 < ns) ? ctx->starts[idx + 1].pos : es_n;
        if (cursor < pos) {
            memmove(pes + out_n, es + cursor, pos - cursor);
            out_n += pos - cursor;
        }
        memmove(pes + out_n, es + pos, sc);
        out_n += sc;
        if (pos + sc >= end) {
            cursor = end;
            continue;
        }
        /* 就地解密：解密只会丢 EPB 的 03（收缩），所以直接改 PES 缓冲安全 */
        uint8_t *nal = es + pos + sc;
        size_t nlen = end - (pos + sc);
        size_t io = nlen;
        h5e_session_on_nal(ctx->session, nal, &io);
        ctx->nal_count++;
        memmove(pes + out_n, nal, io);
        out_n += io;
        cursor = end;
    }
    if (cursor < es_n) {
        memmove(pes + out_n, es + cursor, es_n - cursor);
        out_n += es_n - cursor;
    }

    /* 解密后变短了：从最后一个包往前逐个撑 AF，把差额吃回来；
     * capacity 取 AF 扩展前各包 payload 之和。 */
    size_t capacity = 0;
    for (size_t i = 0; i < ctx->spans_n; i++) capacity += ctx->spans[i].pl;
    if (capacity > out_n) {
        size_t remaining = capacity - out_n;
        for (size_t i = ctx->spans_n; i-- > 0 && remaining > 0;) {
            size_t got = h5e_expand_af_steal(data, len, ctx->spans[i].pkt_off, remaining);
            remaining -= got;
        }
        /* AF 长度变了，按新包头重算各包 payload 区间（无 payload 的包直接丢弃） */
        size_t nn = 0;
        for (size_t i = 0; i < ctx->spans_n; i++) {
            const size_t pkt_off = ctx->spans[i].pkt_off;
            int afc = (data[pkt_off + 3] & 0x30) >> 4;
            if (afc == 0 || afc == 2) continue;
            size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[pkt_off + 4]);
            if (pi >= 188) continue;
            ctx->spans[nn].pkt_off = pkt_off;
            ctx->spans[nn].pi = pi;
            ctx->spans[nn].pl = 188 - pi;
            nn++;
        }
        ctx->spans_n = nn;
    }

    size_t off = 0;
    for (size_t i = 0; i < ctx->spans_n; i++) {
        const size_t pkt_off = ctx->spans[i].pkt_off;
        const size_t pi = ctx->spans[i].pi;
        const size_t pl = ctx->spans[i].pl;
        size_t chunk = (off < out_n) ? (out_n - off) : 0;
        if (chunk > pl) chunk = pl;
        if (chunk > 0) memcpy(data + pkt_off + pi, pes + off, chunk);
        if (chunk < pl) {
            /* AF 吸收不下的残留尾部用 0xFF 填满 */
            memset(data + pkt_off + pi + chunk, 0xFF, pl - chunk);
        }
        off += pl;
    }

    ctx->pes_n = 0;
    ctx->spans_n = 0;
}

/* 原地解密一个 TS 缓冲里指定 PID 的全部视频 NAL。
 * 做法：按 188 字节遍历 TS 包，把同一个 PES 的 payload 依次攒起来，
 * 遇到 PUSI（新 PES 的起点）就先把上一个 PES 冲掉。
 * 返回 >= 0 为经过会话的 NAL 数；-1 为内存不足。 */
static H5E_UNUSED long long h5e_decrypt_ts_inplace(uint8_t *data, size_t len,
                                                   cctv_h5e_session *session, uint16_t vpid) {
    if (!data || len < 188) return 0;

    h5e_ts_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.session = session;

    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (data[off] != 0x47) continue;
        uint16_t pid = (uint16_t)(((data[off + 1] & 0x1f) << 8) | data[off + 2]);
        if (pid != vpid) continue;
        bool pusi = (data[off + 1] & 0x40) != 0;
        int afc = (data[off + 3] & 0x30) >> 4;
        if (afc == 0 || afc == 2) continue;
        size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[off + 4]);
        if (pi >= 188) continue;
        size_t payload_len = 188 - pi;
        if (pusi) h5e_flush_pes(data, len, &ctx);
        if (h5e_reserve((void **)&ctx.pes, &ctx.pes_cap, ctx.pes_n + payload_len, 1) != 0 ||
            h5e_reserve((void **)&ctx.spans, &ctx.spans_cap, ctx.spans_n + 1, sizeof(h5e_span)) != 0) {
            ctx.oom = true;
            break;
        }
        memcpy(ctx.pes + ctx.pes_n, data + off + pi, payload_len);
        ctx.pes_n += payload_len;
        ctx.spans[ctx.spans_n].pkt_off = off;
        ctx.spans[ctx.spans_n].pi = pi;
        ctx.spans[ctx.spans_n].pl = payload_len;
        ctx.spans_n++;
    }
    if (!ctx.oom) h5e_flush_pes(data, len, &ctx);

    const size_t nal_count = ctx.nal_count;
    const bool oom = ctx.oom;
    free(ctx.pes);
    free(ctx.spans);
    free(ctx.starts);
    return oom ? -1 : (long long)nal_count;
}

/* ====================== 通用工具：宽字符 / 路径 / UTF-8 ====================== */

/* 宽字符转 UTF-8，只为把中文路径打印到控制台 */
static char *h5e_utf8_from_wide(const wchar_t *w) {
    if (!w) return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char *s = (char *)malloc((size_t)n);
    if (!s) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL) <= 0) {
        free(s);
        return NULL;
    }
    return s;
}

/* 打印一行带路径的中文提示（路径走 UTF-8，控制台已切到 CP_UTF8） */
static void h5e_msg_path(const char *prefix, const wchar_t *path) {
    char *u = h5e_utf8_from_wide(path);
    fprintf(stderr, "%s%s\n", prefix, u ? u : "?");
    free(u);
}

static wchar_t *h5e_wcsdup(const wchar_t *s) {
    if (!s) return NULL;
    const size_t n = wcslen(s);
    wchar_t *p = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    if (!p) return NULL;
    memcpy(p, s, (n + 1) * sizeof(wchar_t));
    return p;
}

/* 拼接目录与文件名：自动补一个反斜杠 */
static wchar_t *h5e_path_join(const wchar_t *dir, const wchar_t *name) {
    if (!dir || !name) return NULL;
    const size_t a = wcslen(dir), b = wcslen(name);
    const bool need_sep = (a > 0 && dir[a - 1] != L'\\' && dir[a - 1] != L'/');
    wchar_t *p = (wchar_t *)malloc((a + (need_sep ? 1u : 0u) + b + 1) * sizeof(wchar_t));
    if (!p) return NULL;
    memcpy(p, dir, a * sizeof(wchar_t));
    size_t k = a;
    if (need_sep) p[k++] = L'\\';
    memcpy(p + k, name, b * sizeof(wchar_t));
    p[k + b] = L'\0';
    return p;
}

/* 给输出路径加上 .part 后缀：与目标同目录，后续改名才是同卷原子重命名 */
static wchar_t *h5e_part_path(const wchar_t *out_path) {
    const size_t len = wcslen(out_path);
    if (len == 0 || len > 32000) return NULL;
    wchar_t *p = (wchar_t *)malloc((len + 8) * sizeof(wchar_t));
    if (!p) return NULL;
    memcpy(p, out_path, (len + 1) * sizeof(wchar_t));
    memcpy(p + len, L".part", 6 * sizeof(wchar_t));
    return p;
}

/* 取绝对路径：避免 ffmpeg 子进程相对路径与当前目录产生歧义 */
static wchar_t *h5e_full_path(const wchar_t *p) {
    if (!p || !*p) return NULL;
    wchar_t *buf = NULL;
    size_t cap = 512;
    for (;;) {
        wchar_t *t = (wchar_t *)realloc(buf, cap * sizeof(wchar_t));
        if (!t) {
            free(buf);
            return NULL;
        }
        buf = t;
        DWORD n = GetFullPathNameW(p, (DWORD)cap, buf, NULL);
        if (n == 0) {
            free(buf);
            return NULL;
        }
        if ((size_t)n < cap) return buf;
        cap = (size_t)n + 1; /* 缓冲区不够：按返回值重新分配 */
    }
}

/* 存在且是普通文件（不是目录） */
static bool h5e_is_regular_file(const wchar_t *p) {
    DWORD attr = GetFileAttributesW(p);
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

/* 取扩展名（不含点），用于判定输入格式 */
static const wchar_t *h5e_extension_of(const wchar_t *p) {
    if (!p) return L"";
    const wchar_t *dot = NULL;
    for (const wchar_t *q = p; *q; q++) {
        if (*q == L'.') dot = q;
        else if (*q == L'\\' || *q == L'/') dot = NULL; /* 目录里的点不算扩展名 */
    }
    return dot ? dot + 1 : L"";
}

static bool h5e_ext_is(const wchar_t *ext, const wchar_t *want) {
    if (!ext || !want) return false;
    for (size_t i = 0;; i++) {
        const wchar_t a = (wchar_t)towlower(ext[i]);
        const wchar_t b = (wchar_t)towlower(want[i]);
        if (a != b) return false;
        if (a == L'\0') return true;
    }
}

/* 文件大小（-1 表示取不到） */
static long long h5e_file_size(const wchar_t *p) {
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER sz;
    const bool ok = GetFileSizeEx(h, &sz) != 0 && sz.QuadPart >= 0;
    CloseHandle(h);
    return ok ? (long long)sz.QuadPart : -1;
}

/* 唯一临时目录：%TEMP%\cctv_h5e_<pid>_<tick>_<n>，n 递增以避开并发冲突 */
static wchar_t *h5e_temp_dir_new(void) {
    wchar_t base[MAX_PATH + 2];
    const DWORD n = GetTempPathW(MAX_PATH, base);
    if (n == 0 || n >= MAX_PATH) return NULL;
    for (unsigned tries = 0; tries < 1000; tries++) {
        wchar_t name[80];
        swprintf(name, 80, L"cctv_h5e_%lu_%llu_%u", (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64(), tries);
        wchar_t *dir = h5e_path_join(base, name);
        if (!dir) return NULL;
        if (CreateDirectoryW(dir, NULL)) return dir;
        const DWORD err = GetLastError();
        free(dir);
        if (err != ERROR_ALREADY_EXISTS) return NULL;
    }
    return NULL;
}

/* 清掉临时目录里登记的所有中间文件（stage1.m4v / stage2.m4v / audio.m4a），再删目录本身 */
static void h5e_temp_dir_remove(const wchar_t *dir, wchar_t *const *files, size_t n) {
    for (size_t i = 0; files && i < n; i++)
        if (files[i]) DeleteFileW(files[i]);
    if (dir) RemoveDirectoryW(dir);
}

/* ================= MP4 分片解析与视频样本解密（本文件新增部分） ================= */
/*
 * 为什么在 MP4 样本层解密：
 *   阶段 1 产出的分片 MP4 里，每条样本是 AVCC 格式：NALU 前面带 lengthSize（1..4）
 *   字节大端长度。它天然把“NAL 边界”写在数据里，因此：
 *     - 取 NAL 不需要扫描 start code（等价于 dec.c 扫 00 00 01/00 00 00 01）；
 *     - 解密后 NAL 变短（丢 EPB 03）只需重写长度前缀、trun 里的样本字节数和 mdat 大小。
 *   解密核心 h5e_session_on_nal() 的入参永远是“去掉 start code / 长度前缀的 NAL
 *   本体”，两条路径完全一致；EPB 的收集与丢弃也仍然发生在核心内部。
 */

#define H5E_MP4_MAX_BOX  (256u << 20) /* 单个 moof / mdat 荷载上限：挡住坏文件 */
#define H5E_MP4_MAX_MOOV (64u << 20)  /* moov 上限（正常只有几百字节到几 MB） */
#define H5E_MP4_MAX_TRUN 4u           /* 允许一个 moof 内出现的 trun 数 */

/* FourCC 常量：与 box 里的 4 个字节按大端一一对应 */
#define H5E_CC(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

/* 视频轨信息：全部来自 moov，阶段 1 的中间文件里只有这一条轨 */
typedef struct {
    uint32_t track_id;    /* moov/trak/tkhd 的 track_ID，tfhd 必须与之一致 */
    uint32_t length_size; /* NALU 长度前缀字节数 1..4（avcC[4] / hvcC[21] 的低 2 位 + 1） */
} h5e_mp4_track;

/* 一个 box 头：size 含头部，hdr 是头部长度（8，或 largesize 的 16） */
typedef struct {
    uint64_t size;
    uint64_t hdr;
    uint32_t type;
} h5e_box;

/* moof 里一条 trun 的样本尺寸表位置：尺寸表按 stride 排列，size 字段不一定在首 4 字节 */
typedef struct {
    uint8_t *first;   /* moof 缓冲内首条记录的起点（可写，回写时就地改 size 字段） */
    size_t stride;    /* 每条记录的字节数（duration / size / flags / cts 的组合） */
    size_t size_off;  /* size 字段相对记录起点的偏移 */
    uint32_t count;   /* 样本条数 */
    int64_t data_off; /* trun 的 data-offset；没有该字段时为 -1 */
} h5e_trun;

static uint32_t h5e_be_read(const uint8_t *p, size_t n) {
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | (uint32_t)p[i];
    return v;
}

static void h5e_be_write(uint8_t *p, size_t n, uint32_t v) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
}

static uint64_t h5e_be_read64(const uint8_t *p) {
    return ((uint64_t)h5e_be_read(p, 4) << 32) | (uint64_t)h5e_be_read(p + 4, 4);
}

static void h5e_be_write64(uint8_t *p, uint64_t v) {
    h5e_be_write(p, 4, (uint32_t)(v >> 32));
    h5e_be_write(p + 4, 4, (uint32_t)(v & 0xFFFFFFFFu));
}

/* 读一个 box 头。*at_eof 表示已经到文件尾（正常结束）；size 字段为 0 按“到文件尾”折算。
 * 返回 0 成功；-2 读失败；-5 结构非法（大小自相矛盾）。 */
static int h5e_box_read(FILE *f, long long fsize, h5e_box *b, bool *at_eof) {
    *at_eof = false;
    uint8_t h[16];
    const size_t got = fread(h, 1, 8, f);
    if (got == 0) {
        *at_eof = true;
        return 0;
    }
    if (got != 8) return -2;
    uint64_t size = h5e_be_read(h, 4);
    b->type = h5e_be_read(h + 4, 4);
    b->hdr = 8;
    if (size == 1) { /* largesize：紧跟 8 字节 64 位长度 */
        if (fread(h + 8, 1, 8, f) != 8) return -2;
        size = h5e_be_read64(h + 8);
        b->hdr = 16;
    }
    if (size == 0) { /* 到文件尾 */
        const long long pos = _ftelli64(f);
        if (pos < 0 || fsize < pos) return -5;
        size = (uint64_t)(fsize - pos);
    }
    if (size < b->hdr) return -5;
    b->size = size;
    return 0;
}

/* 写回 box 头：宽度沿用原头（8 或 16），不把小 box 悄悄升级成 largesize */
static bool h5e_box_write_hdr(FILE *f, uint32_t type, uint64_t size, uint64_t hdr) {
    uint8_t h[16];
    if (hdr == 16) {
        h5e_be_write(h, 4, 1);
        h5e_be_write(h + 4, 4, type);
        h5e_be_write64(h + 8, size);
    } else {
        if (size > 0xFFFFFFFFull) return false;
        h5e_be_write(h, 4, (uint32_t)size);
        h5e_be_write(h + 4, 4, type);
    }
    return fwrite(h, 1, (size_t)hdr, f) == (size_t)hdr;
}

/* 在父 box 荷载 p[0..n) 里顺序取子 box：*cur 为游标，每调用一次前进一个 box。
 * 越界或 size 非法返回 false（调用方按“结构异常”处理）。 */
static bool h5e_mp4_next(const uint8_t *p, size_t n, size_t *cur, uint32_t *type, size_t *pay,
                         size_t *pay_n) {
    const size_t o = *cur;
    if (o + 8 > n) return false;
    uint64_t size = h5e_be_read(p + o, 4);
    const uint32_t t = h5e_be_read(p + o + 4, 4);
    size_t hdr = 8;
    if (size == 1) {
        if (o + 16 > n) return false;
        size = h5e_be_read64(p + o + 8);
        hdr = 16;
    } else if (size == 0) {
        size = (uint64_t)(n - o);
    }
    if (size < hdr || size > (uint64_t)(n - o)) return false;
    *type = t;
    *pay = o + hdr;
    *pay_n = (size_t)size - hdr;
    *cur = o + (size_t)size;
    return true;
}

/* 找第一个指定类型的子 box，返回其荷载指针；找不到返回 NULL */
static const uint8_t *h5e_mp4_child(const uint8_t *p, size_t n, uint32_t type, size_t *out_n) {
    size_t cur = 0, pay = 0, pay_n = 0;
    uint32_t t = 0;
    while (h5e_mp4_next(p, n, &cur, &t, &pay, &pay_n)) {
        if (t == type) {
            if (out_n) *out_n = pay_n;
            return p + pay;
        }
    }
    return NULL;
}

/* 从 moov 里取视频轨：track_ID 与 NALU 长度前缀字节数。
 *   AVC  : 样本条目 avc1/avc3 → avcC，[4] 的低 2 位是 lengthSizeMinusOne
 *   HEVC : 样本条目 hvc1/hev1 → hvcC，[21] 的低 2 位是 lengthSizeMinusOne
 * 返回 0 成功；1 没有视频轨；2 视频编码不是 AVC/HEVC；3 结构异常。 */
static int h5e_mp4_parse_moov(const uint8_t *moov, size_t n, h5e_mp4_track *tr) {
    size_t cur = 0, pay = 0, pay_n = 0;
    uint32_t type = 0;
    while (h5e_mp4_next(moov, n, &cur, &type, &pay, &pay_n)) {
        if (type != H5E_CC('t', 'r', 'a', 'k')) continue;
        const uint8_t *trak = moov + pay;

        size_t mdia_n = 0, hdlr_n = 0, tkhd_n = 0, minf_n = 0, stbl_n = 0, stsd_n = 0;
        const uint8_t *mdia = h5e_mp4_child(trak, pay_n, H5E_CC('m', 'd', 'i', 'a'), &mdia_n);
        if (!mdia) continue;
        const uint8_t *hdlr = h5e_mp4_child(mdia, mdia_n, H5E_CC('h', 'd', 'l', 'r'), &hdlr_n);
        /* hdlr 荷载：version/flags(4) + pre_defined(4) + handler_type(4) */
        if (!hdlr || hdlr_n < 12 || h5e_be_read(hdlr + 8, 4) != H5E_CC('v', 'i', 'd', 'e'))
            continue;

        /* tkhd 荷载：version 0 时 track_ID 在偏移 12，version 1 时在 20 */
        const uint8_t *tkhd = h5e_mp4_child(trak, pay_n, H5E_CC('t', 'k', 'h', 'd'), &tkhd_n);
        if (!tkhd || tkhd_n < 24) return 3;
        const uint32_t track_id =
            (tkhd[0] == 1) ? h5e_be_read(tkhd + 20, 4) : h5e_be_read(tkhd + 12, 4);

        const uint8_t *minf = h5e_mp4_child(mdia, mdia_n, H5E_CC('m', 'i', 'n', 'f'), &minf_n);
        const uint8_t *stbl =
            minf ? h5e_mp4_child(minf, minf_n, H5E_CC('s', 't', 'b', 'l'), &stbl_n) : NULL;
        const uint8_t *stsd =
            stbl ? h5e_mp4_child(stbl, stbl_n, H5E_CC('s', 't', 's', 'd'), &stsd_n) : NULL;
        if (!stsd || stsd_n < 8) return 3;

        /* stsd 荷载：version/flags(4) + entry_count(4)，随后是样本条目 */
        const uint8_t *e = stsd + 8;
        const uint8_t *end = stsd + stsd_n;
        while ((size_t)(end - e) >= 8) {
            const uint64_t esz = h5e_be_read(e, 4);
            const uint32_t fmt = h5e_be_read(e + 4, 4);
            if (esz < 8 || esz > (uint64_t)(end - e)) return 3;
            const bool avc =
                (fmt == H5E_CC('a', 'v', 'c', '1') || fmt == H5E_CC('a', 'v', 'c', '3'));
            const bool hevc =
                (fmt == H5E_CC('h', 'v', 'c', '1') || fmt == H5E_CC('h', 'e', 'v', '1'));
            if (!avc && !hevc) return 2; /* av01 等：不做 NAL 级解密 */
            /* 视觉样本条目头 = box 头(8) + 78 字节固定字段，之后才是 avcC / hvcC */
            if (esz < 86) return 3;
            size_t cfg_n = 0;
            const uint8_t *cfg =
                h5e_mp4_child(e + 86, (size_t)esz - 86,
                              hevc ? H5E_CC('h', 'v', 'c', 'C') : H5E_CC('a', 'v', 'c', 'C'),
                              &cfg_n);
            const size_t at = hevc ? 21u : 4u;
            if (!cfg || cfg_n <= at) return 3;
            tr->track_id = track_id;
            tr->length_size = (uint32_t)(cfg[at] & 3) + 1u;
            return 0;
        }
        return 3; /* 样本条目里没有 avc1/avc3/hvc1/hev1 */
    }
    return 1;
}

/* 从 moof 荷载里收集全部 trun（阶段 1 只写纯视频，所以限定单 traf）。
 * 返回 0 成功；3 结构不支持：多 traf、track_ID 不是视频轨、trun 里没有逐样本字节数表、
 * 带 base-data-offset（改长度后该绝对偏移会错）、字段越界等。 */
static int h5e_mp4_parse_moof(uint8_t *moof, size_t n, uint32_t track_id, h5e_trun *truns,
                              size_t *ntrun) {
    *ntrun = 0;
    size_t cur = 0, pay = 0, pay_n = 0;
    uint32_t type = 0;
    size_t ntraf = 0;
    while (h5e_mp4_next(moof, n, &cur, &type, &pay, &pay_n)) {
        if (type != H5E_CC('t', 'r', 'a', 'f')) continue;
        if (++ntraf > 1) return 3;

        const uint8_t *traf = moof + pay;
        size_t tcur = 0, tpay = 0, tpay_n = 0;
        uint32_t ttype = 0;
        bool have_tfhd = false;
        while (h5e_mp4_next(traf, pay_n, &tcur, &ttype, &tpay, &tpay_n)) {
            const uint8_t *kid = traf + tpay;
            if (ttype == H5E_CC('t', 'f', 'h', 'd')) {
                if (tpay_n < 8) return 3;
                const uint32_t flags = h5e_be_read(kid, 4) & 0xFFFFFFu;
                if (h5e_be_read(kid + 4, 4) != track_id) return 3; /* 不是视频轨 */
                if (flags & 0x000001u) return 3; /* base-data-offset：样本变短后偏移会错 */
                have_tfhd = true;
            } else if (ttype == H5E_CC('t', 'r', 'u', 'n')) {
                if (!have_tfhd || *ntrun >= H5E_MP4_MAX_TRUN || tpay_n < 8) return 3;
                const uint32_t flags = h5e_be_read(kid, 4) & 0xFFFFFFu;
                const uint32_t cnt = h5e_be_read(kid + 4, 4);
                if (!(flags & 0x000200u)) return 3; /* 没有逐样本字节数表，改不了长度 */
                size_t off = 8;
                int64_t data_off = -1;
                if (flags & 0x000001u) {
                    if (off + 4 > tpay_n) return 3;
                    data_off = (int64_t)(int32_t)h5e_be_read(kid + off, 4);
                    off += 4;
                }
                if (flags & 0x000004u) off += 4; /* first_sample_flags */
                /* 记录字段顺序固定为 duration → size → flags → cts */
                size_t stride = 0;
                if (flags & 0x000100u) stride += 4; /* duration */
                const size_t size_off = stride;
                stride += 4;                        /* size */
                if (flags & 0x000400u) stride += 4; /* flags */
                if (flags & 0x000800u) stride += 4; /* composition time offset */
                if (off > tpay_n || (uint64_t)cnt * stride > (uint64_t)(tpay_n - off)) return 3;
                h5e_trun *t = &truns[(*ntrun)++];
                t->first = (uint8_t *)kid + off;
                t->stride = stride;
                t->size_off = size_off;
                t->count = cnt;
                t->data_off = data_off;
            }
        }
    }
    return (*ntrun > 0) ? 0 : 3;
}

/* 重写一条样本：样本就是“长度前缀 + NALU”的序列，没有额外头部（不像 FLV 那样有
 * 帧类型/CTS）。out 与 in 等长即可（解密只会缩短）。返回新的样本字节数。 */
static size_t h5e_mp4_rewrite_sample(cctv_h5e_session *s, uint32_t ls, uint8_t *in, size_t n,
                                     uint8_t *out, size_t *nalus) {
    size_t w = 0, r = 0;
    while (r + ls <= n) {
        const uint32_t len = h5e_be_read(in + r, ls);
        r += ls;
        if (len == 0) { /* 空 NALU：只写回长度 0 */
            h5e_be_write(out + w, ls, 0);
            w += ls;
            continue;
        }
        if ((size_t)len > n - r) { /* 长度越界：剩下的原样拷贝，不再解 */
            memcpy(out + w, in + r, n - r);
            w += n - r;
            r = n;
            break;
        }
        uint8_t *nal = in + r;
        size_t io = (size_t)len;
        h5e_session_on_nal(s, nal, &io);
        if (io > (size_t)len) io = (size_t)len; /* 防御：核心只会收缩，不允许变长 */
        (*nalus)++;
        h5e_be_write(out + w, ls, (uint32_t)io);
        w += ls;
        memcpy(out + w, nal, io);
        w += io;
        r += len;
    }
    if (r < n) { /* 尾部残字节原样保留 */
        memcpy(out + w, in + r, n - r);
        w += n - r;
    }
    return w;
}

/* 从文件读 need 字节到按需扩容的缓冲；返回 0 成功、-2 读失败、-3 内存不足 */
static int h5e_read_block(FILE *f, uint8_t **buf, size_t *cap, size_t need) {
    if (h5e_reserve((void **)buf, cap, need ? need : 1u, 1) != 0) return -3;
    if (need && fread(*buf, 1, need, f) != need) return -2;
    return 0;
}

/* 搬运 n 字节：fo 为 NULL 时只读不写（相当于跳过）。用调用方给的小缓冲分块，
 * 所以再大的 box 也不会一次性占内存。返回 0 成功、-2 读失败、-4 写失败 */
static int h5e_copy_bytes(FILE *fi, FILE *fo, uint64_t n, uint8_t *scratch, size_t scratch_n) {
    while (n > 0) {
        const size_t chunk = (n < (uint64_t)scratch_n) ? (size_t)n : scratch_n;
        if (fread(scratch, 1, chunk, fi) != chunk) return -2;
        if (fo && fwrite(scratch, 1, chunk, fo) != chunk) return -4;
        n -= chunk;
    }
    return 0;
}

/* stage1.m4v → stage2.m4v：逐分片重写视频样本（会话跨分片复用）。
 * 返回 >= 0：经过会话的 NAL 数；负数：
 *   -1 参数错 -2 读失败 -3 内存不足 -4 写失败 -5 不是合法 MP4
 *   -6 没有视频轨 / 编码不支持 / 没有任何 NAL（对应 dec.c 的 nal_total == 0 失败判定）
 *   -7 分片结构与预期不符（多轨、缺逐样本字节数表、base-data-offset、字段越发等） */
static long long h5e_decrypt_mp4_w(const wchar_t *in_path, const wchar_t *out_path,
                                   size_t *frags_out, size_t *written_out, bool *unsupported_out) {
    if (frags_out) *frags_out = 0;
    if (written_out) *written_out = 0;
    if (unsupported_out) *unsupported_out = false;
    if (!in_path || !out_path) return -1;

    const long long fsize = h5e_file_size(in_path);
    if (fsize < 8) return -5;
    FILE *fi = _wfopen(in_path, L"rb");
    if (!fi) return -2;
    FILE *fo = _wfopen(out_path, L"wb");
    if (!fo) {
        fclose(fi);
        return -4;
    }

    cctv_h5e_session session;
    h5e_session_init(&session);
    h5e_mp4_track track;
    memset(&track, 0, sizeof track);
    bool have_track = false;
    bool unsupported = false;

    uint8_t *box_buf = NULL, *mdat_buf = NULL, *out_buf = NULL;
    size_t box_cap = 0, mdat_cap = 0, out_cap = 0;
    uint8_t scratch[64 * 1024];
    size_t nalus = 0, frags = 0, written = 0;
    int rc = 0;

    for (;;) {
        h5e_box b;
        bool at_eof = false;
        int r = h5e_box_read(fi, fsize, &b, &at_eof);
        if (r != 0) {
            rc = r;
            goto done;
        }
        if (at_eof) break;
        const uint64_t payload = b.size - b.hdr;

        if (b.type == H5E_CC('m', 'o', 'o', 'v')) {
            /* moov：取视频轨的 track_ID 与 NALU 长度前缀字节数，然后原样写回 */
            if (payload > H5E_MP4_MAX_MOOV) {
                rc = -5;
                goto done;
            }
            if ((r = h5e_read_block(fi, &box_buf, &box_cap, (size_t)payload)) != 0) {
                rc = r;
                goto done;
            }
            const int pr = h5e_mp4_parse_moov(box_buf, (size_t)payload, &track);
            if (pr == 2) { /* 视频编码不是 AVC/HEVC：根本没法 NAL 级解密 */
                unsupported = true;
                rc = -6;
                goto done;
            }
            if (pr != 0) {
                rc = (pr == 1) ? -6 : -5;
                goto done;
            }
            have_track = true;
            if (!h5e_box_write_hdr(fo, b.type, b.size, b.hdr)) {
                rc = -4;
                goto done;
            }
            if (payload && fwrite(box_buf, 1, (size_t)payload, fo) != (size_t)payload) {
                rc = -4;
                goto done;
            }
            written += (size_t)b.size;
        } else if (b.type == H5E_CC('m', 'o', 'o', 'f')) {
            /* 一个分片 = moof（样本说明）+ mdat（样本数据）。
             * 样本变短后只需改 trun 里的逐样本字节数与 mdat 大小：moof 长度不变
             * （字段定长、条数不变），所以 trun 的 data-offset 仍然成立。 */
            if (!have_track || payload > H5E_MP4_MAX_BOX) {
                rc = -7;
                goto done;
            }
            if ((r = h5e_read_block(fi, &box_buf, &box_cap, (size_t)payload)) != 0) {
                rc = r;
                goto done;
            }
            h5e_trun truns[H5E_MP4_MAX_TRUN];
            size_t ntrun = 0;
            if (h5e_mp4_parse_moof(box_buf, (size_t)payload, track.track_id, truns, &ntrun) != 0) {
                rc = -7;
                goto done;
            }
            h5e_box mb;
            if ((r = h5e_box_read(fi, fsize, &mb, &at_eof)) != 0) {
                rc = r;
                goto done;
            }
            if (at_eof || mb.type != H5E_CC('m', 'd', 'a', 't') ||
                mb.size - mb.hdr > H5E_MP4_MAX_BOX) {
                rc = -7;
                goto done;
            }
            const size_t mpay = (size_t)(mb.size - mb.hdr);
            if ((r = h5e_read_block(fi, &mdat_buf, &mdat_cap, mpay)) != 0) {
                rc = r;
                goto done;
            }
            if (h5e_reserve((void **)&out_buf, &out_cap, mpay ? mpay : 1u, 1) != 0) {
                rc = -3;
                goto done;
            }

            /* 样本数据在 mdat 荷载内首尾相接；trun 的 data-offset 相对 moof 起点 */
            const size_t data_base = (size_t)b.size + (size_t)mb.hdr;
            size_t rp = 0, wp = 0;
            for (size_t i = 0; i < ntrun; i++) {
                const h5e_trun *t = &truns[i];
                if (t->data_off >= 0) {
                    const size_t want = (size_t)t->data_off;
                    if ((uint64_t)t->data_off < (uint64_t)data_base || want - data_base > mpay ||
                        want - data_base < rp) {
                        rc = -7;
                        goto done;
                    }
                    const size_t at = want - data_base;
                    if (at > rp) { /* 分片内的 padding：原样搬运，保持偏移不变 */
                        memcpy(out_buf + wp, mdat_buf + rp, at - rp);
                        wp += at - rp;
                        rp = at;
                    }
                }
                for (uint32_t k = 0; k < t->count; k++) {
                    uint8_t *rec = t->first + (size_t)k * t->stride;
                    const uint32_t sz = h5e_be_read(rec + t->size_off, 4);
                    if ((size_t)sz > mpay - rp) {
                        rc = -7;
                        goto done;
                    }
                    const size_t nw = h5e_mp4_rewrite_sample(&session, track.length_size, mdat_buf + rp,
                                                             (size_t)sz, out_buf + wp, &nalus);
                    h5e_be_write(rec + t->size_off, 4, (uint32_t)nw);
                    rp += sz;
                    wp += nw;
                }
            }
            if (rp < mpay) { /* 没有样本描述覆盖到的尾部原样保留 */
                memcpy(out_buf + wp, mdat_buf + rp, mpay - rp);
                wp += mpay - rp;
            }

            if (!h5e_box_write_hdr(fo, b.type, b.size, b.hdr)) {
                rc = -4;
                goto done;
            }
            if (payload && fwrite(box_buf, 1, (size_t)payload, fo) != (size_t)payload) {
                rc = -4;
                goto done;
            }
            if (!h5e_box_write_hdr(fo, mb.type, mb.hdr + (uint64_t)wp, mb.hdr)) {
                rc = -4;
                goto done;
            }
            if (wp && fwrite(out_buf, 1, wp, fo) != wp) {
                rc = -4;
                goto done;
            }
            written += (size_t)b.size + (size_t)mb.hdr + wp;
            frags++;
        } else if (b.type == H5E_CC('m', 'f', 'r', 'a') || b.type == H5E_CC('s', 'i', 'd', 'x')) {
            /* mfra / sidx 按“字节偏移”记账，样本变短后必然失效；两者都是可选的，直接丢弃。
             * 这会让后续 box 的绝对位置前移，但 trun 的 data-offset 相对 moof 起点，不受影响
             * （带 base-data-offset 的分片已在 h5e_mp4_parse_moof 里拒绝）。 */
            if ((r = h5e_copy_bytes(fi, NULL, payload, scratch, sizeof scratch)) != 0) {
                rc = r;
                goto done;
            }
        } else {
            /* ftyp / styp / free / mdat（无 moof 描述）等：与样本长度无关，原样搬运 */
            if (!h5e_box_write_hdr(fo, b.type, b.size, b.hdr)) {
                rc = -4;
                goto done;
            }
            if ((r = h5e_copy_bytes(fi, fo, payload, scratch, sizeof scratch)) != 0) {
                rc = r;
                goto done;
            }
            written += (size_t)b.size;
        }
    }

    /* 一个视频 NAL 都没经过会话：中间文件里没有可解密的视频，按失败处理，
     * 绝不产出“看着成功其实是原文”的副本（与 dec.c 的判定一致）。 */
    if (!have_track || frags == 0 || nalus == 0) {
        rc = -6;
        goto done;
    }

done:
    free(box_buf);
    free(mdat_buf);
    free(out_buf);
    if (rc == 0 && fflush(fo) != 0) rc = -4;
    fclose(fo);
    fclose(fi);
    if (rc == 0) {
        if (frags_out) *frags_out = frags;
        if (written_out) *written_out = written;
        if (unsupported_out) *unsupported_out = unsupported;
        return (long long)nalus;
    }
    return rc;
}

/* ========================= 文件探测小工具 ========================= */

/* MP4 的 ftyp box 位于偏移 4（.m4v / .m4a / .mp4 都一样） */
static bool h5e_file_is_mp4(const wchar_t *p) {
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint8_t buf[12];
    DWORD got = 0;
    const bool ok = ReadFile(h, buf, 12, &got, NULL) != 0 && got == 12 &&
                    memcmp(buf + 4, "ftyp", 4) == 0;
    CloseHandle(h);
    return ok;
}

/* ===================== ffmpeg 子进程调用（命令行，不是 libav*） ===================== */

typedef struct {
    wchar_t *p;
    size_t n, cap;
} h5e_wbuf;

static bool h5e_wbuf_add(h5e_wbuf *b, const wchar_t *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->n + n + 1) cap <<= 1;
        wchar_t *t = (wchar_t *)realloc(b->p, cap * sizeof(wchar_t));
        if (!t) return false;
        b->p = t;
        b->cap = cap;
    }
    if (n) memcpy(b->p + b->n, s, n * sizeof(wchar_t));
    b->n += n;
    b->p[b->n] = L'\0';
    return true;
}

static bool h5e_wbuf_adds(h5e_wbuf *b, const wchar_t *s) {
    return h5e_wbuf_add(b, s, s ? wcslen(s) : 0);
}

static bool h5e_wbuf_addc(h5e_wbuf *b, wchar_t c) {
    return h5e_wbuf_add(b, &c, 1);
}

/* 按 CreateProcessW 的解析规则拼一个参数：
 *   - 空参数或含空格 / 制表 / 换行 / 引号时必须用双引号包住；
 *   - 引号前的反斜杠要加倍；字符串结尾的反斜杠也要加倍（否则会转义掉收尾引号）。 */
static bool h5e_wbuf_add_arg(h5e_wbuf *b, const wchar_t *arg) {
    if (!arg) arg = L"";
    if (b->n > 0 && !h5e_wbuf_addc(b, L' ')) return false;
    if (*arg != L'\0' && wcspbrk(arg, L" \t\n\v\"") == NULL) return h5e_wbuf_adds(b, arg);
    if (!h5e_wbuf_addc(b, L'"')) return false;
    const wchar_t *p = arg;
    for (;;) {
        size_t bs = 0;
        while (*p == L'\\') {
            p++;
            bs++;
        }
        if (*p == L'\0') {
            for (size_t i = 0; i < bs * 2; i++)
                if (!h5e_wbuf_addc(b, L'\\')) return false;
            break;
        }
        if (*p == L'"') {
            for (size_t i = 0; i < bs * 2 + 1; i++)
                if (!h5e_wbuf_addc(b, L'\\')) return false;
            if (!h5e_wbuf_addc(b, L'"')) return false;
            p++;
        } else {
            for (size_t i = 0; i < bs; i++)
                if (!h5e_wbuf_addc(b, L'\\')) return false;
            if (!h5e_wbuf_addc(b, *p)) return false;
            p++;
        }
    }
    return h5e_wbuf_addc(b, L'"');
}

/* 启动 ffmpeg 并等它退出。
 * 子进程继承 stdout/stderr，所以 ffmpeg 自己的报错会直接出现在控制台；
 * *spawn_failed 区分“启动不了（不存在/无权限）”与“跑完但返回非 0”。 */
static DWORD h5e_run_ffmpeg(const wchar_t *exe, wchar_t *const *args, int nargs,
                            bool *spawn_failed) {
    if (spawn_failed) *spawn_failed = false;
    h5e_wbuf b;
    memset(&b, 0, sizeof b);
    bool ok = h5e_wbuf_add_arg(&b, exe);
    for (int i = 0; ok && i < nargs; i++) ok = h5e_wbuf_add_arg(&b, args[i]);
    if (!ok) {
        free(b.p);
        if (spawn_failed) *spawn_failed = true;
        return (DWORD)-1;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    memset(&pi, 0, sizeof pi);
    si.cb = sizeof si;
    const BOOL created = CreateProcessW(exe, b.p, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    free(b.p);
    if (!created) {
        if (spawn_failed) *spawn_failed = true;
        return (DWORD)-1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

/* 定位 ffmpeg：显式 --ffmpeg（可给 exe 或所在目录）优先，否则搜索 PATH */
static wchar_t *h5e_find_ffmpeg(const wchar_t *want) {
    if (want && *want) {
        wchar_t *full = h5e_full_path(want);
        if (!full) return NULL;
        DWORD attr = GetFileAttributesW(full);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            wchar_t *j = h5e_path_join(full, L"ffmpeg.exe");
            free(full);
            if (!j) return NULL;
            full = j;
            attr = GetFileAttributesW(full);
        }
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0) return full;
        free(full);
        return NULL;
    }
    wchar_t buf[MAX_PATH];
    const DWORD n = SearchPathW(NULL, L"ffmpeg.exe", NULL, MAX_PATH, buf, NULL);
    if (n > 0 && n < MAX_PATH) return h5e_wcsdup(buf);
    return NULL;
}

/* 判定输入里到底有没有音频流：让 ffmpeg 把 0:a:0 映射到一个空输出，-t 0 表示不写任何数据，
 * 所以这一步只解析容器头，代价与文件大小无关。
 * 有音频流：映射成功、正常退出（0）；没有音频流：在“解析输出参数”阶段就失败（退出码 22）。
 * 返回 0 已得出结论；-1 表示 ffmpeg 启动不了（无法判断）。 */
static int h5e_ffmpeg_has_audio(const wchar_t *ffmpeg, const wchar_t *in_path, bool *has_audio) {
    if (has_audio) *has_audio = false;
    if (!ffmpeg || !in_path || !has_audio) return -1;
    wchar_t *args[] = {L"-hide_banner", L"-nostdin", L"-loglevel", L"error",
                       L"-i",         (wchar_t *)in_path,
                       L"-map",       L"0:a:0",     L"-t",        L"0",
                       L"-c",         L"copy",      L"-f",        L"null",
                       L"-"}; /* 路径只作为命令行参数传递，不会被回写 */
    bool spawn_failed = false;
    const DWORD code = h5e_run_ffmpeg(ffmpeg, args, (int)(sizeof args / sizeof args[0]),
                                      &spawn_failed);
    if (spawn_failed) return -1;
    *has_audio = (code == 0);
    return 0;
}

/* ============================== 三阶段流水线 ============================== */

/* 退出码：成功 0，其余按失败阶段区分，便于批处理定位 */
enum {
    H5E_RC_OK = 0,
    H5E_RC_USAGE = 1,          /* 参数错误 */
    H5E_RC_INPUT = 2,          /* 输入不存在 / 扩展名不支持 */
    H5E_RC_FFMPEG_MISSING = 3, /* ffmpeg 不存在或无法启动 */
    H5E_RC_STAGE1 = 4,         /* 第一次 ffmpeg 转封装 / 音频旁路抽取失败 */
    H5E_RC_DECRYPT = 5,        /* 解密失败 */
    H5E_RC_STAGE2 = 6,         /* 第二次 ffmpeg 转封装失败 */
    H5E_RC_OUTPUT = 7          /* 输出目录不可写 / 最终替换失败 */
};

static int h5e_pipeline(const wchar_t *in_arg, const wchar_t *out_arg, const wchar_t *ffmpeg_arg) {
    int rc = H5E_RC_OK;
    wchar_t *in_full = NULL, *out_full = NULL, *ffmpeg = NULL;
    wchar_t *dir = NULL, *m4v1 = NULL, *m4v2 = NULL, *audio = NULL, *part = NULL;
    wchar_t *temps[3] = {NULL, NULL, NULL}; /* 临时目录内的中间文件，统一由 cleanup 清理 */
    bool audio_ready = false;                /* 音频旁路是否已成功抽出音频 */
    bool dual_ok = false; /* 阶段 1 是否用“一条命令双输出”同时拿到视频与音频 */
    bool part_kept = false;

    /* ---------- 0. 前置检查：输入文件、扩展名、输出目录可写、ffmpeg ---------- */
    if (!h5e_is_regular_file(in_arg)) {
        h5e_msg_path("错误：输入文件不存在或不是普通文件：", in_arg);
        rc = H5E_RC_INPUT;
        goto cleanup;
    }
    const wchar_t *ext = h5e_extension_of(in_arg);
    if (!h5e_ext_is(ext, L"ts") && !h5e_ext_is(ext, L"mp4")) {
        h5e_msg_path("错误：不支持的输入格式（仅支持 .ts / .mp4）：", in_arg);
        rc = H5E_RC_INPUT;
        goto cleanup;
    }
    in_full = h5e_full_path(in_arg);
    out_full = h5e_full_path(out_arg);
    part = out_full ? h5e_part_path(out_full) : NULL;
    if (!in_full || !out_full || !part) {
        fprintf(stderr, "错误：路径解析失败（参数过长或内存不足）\n");
        rc = H5E_RC_USAGE;
        goto cleanup;
    }
    if (h5e_ext_is(h5e_extension_of(out_full), L"ts")) {
        h5e_msg_path("警告：输出扩展名不是 .mp4，内容仍为 MP4：", out_full);
    }

    /* 输出目录可写：先建出 <输出>.part 再删掉。这一步能提前暴露“目录只读/无权限”，
     * 不至于白跑完解密才发现写不进去。 */
    {
        HANDLE probe = CreateFileW(part, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        if (probe == INVALID_HANDLE_VALUE) {
            h5e_msg_path("错误：输出目录不可写，无法创建：", part);
            rc = H5E_RC_OUTPUT;
            goto cleanup;
        }
        CloseHandle(probe);
        DeleteFileW(part);
    }

    ffmpeg = h5e_find_ffmpeg(ffmpeg_arg);
    if (!ffmpeg) {
        if (ffmpeg_arg && *ffmpeg_arg) {
            h5e_msg_path("错误：指定的 ffmpeg 不存在：", ffmpeg_arg);
        } else {
            fprintf(stderr, "错误：找不到 ffmpeg.exe（可用 --ffmpeg <路径> 指定）\n");
        }
        rc = H5E_RC_FFMPEG_MISSING;
        goto cleanup;
    }

    dir = h5e_temp_dir_new();
    m4v1 = dir ? h5e_path_join(dir, L"stage1.m4v") : NULL;
    m4v2 = dir ? h5e_path_join(dir, L"stage2.m4v") : NULL;
    audio = dir ? h5e_path_join(dir, L"audio.m4a") : NULL; /* 音频旁路（与两个 m4v 同目录） */
    temps[0] = m4v1;
    temps[1] = m4v2;
    temps[2] = audio;
    if (!dir || !m4v1 || !m4v2 || !audio) {
        fprintf(stderr, "错误：无法创建临时目录（%%TEMP%% 不可写或内存不足）\n");
        rc = H5E_RC_OUTPUT;
        goto cleanup;
    }

    /* ---------- 1. 输入 → 分片 MP4（纯视频 m4v）+ 音频旁路（一条命令行，双输出，流复制不重编码） ----------
     * ffmpeg 支持一条命令行写多个输出：输入只解复用一次，视频流复制成分片 MP4、音频流同时
     * 复制进 MP4 音频轨；省掉的是重复解复用与一次进程启动。
     *
     * 视频输出固定带 -movflags +frag_keyframe+empty_moov+default_base_moof：
     *   - frag_keyframe：关键帧处分片，才能让“每条样本多少字节”写在 moof/trun 里，
     *     第 2 阶段只改字段值、不动布局；
     *   - empty_moov：moov 立即落盘（分片输出的标准写法）；
     *   - default_base_moof：trun 的 data-offset 相对 moof 起点，mdat 变短也不会失配。
     * 视频输出只映射 0:v:0：中间文件必须是纯视频，才能保证“单 traf、可按轨改写”。
     *
     * 第二个输出故意用 -map 0:a:0（不带 ?）：输入没有音频流时 ffmpeg 在“解析输出参数”
     * 阶段就失败（退出码 22），两个中间文件都不会落盘，于是下面走回退路径——只转视频，
     * 再探测输入有没有音频流决定是否旁路。 */
    fprintf(stderr, "[1/3] FFmpeg 转封装：输入 -> 分片 MP4（视频）+ 音频旁路（-c copy）\n");
    h5e_msg_path("      输入：", in_full);
    h5e_msg_path("      视频：", m4v1);
    h5e_msg_path("      音频：", audio);
    {
        /* 两个输出：先分片 MP4（纯视频），再音频旁路 MP4 音频轨 */
        wchar_t *args[] = {L"-hide_banner", L"-nostdin", L"-loglevel", L"error", L"-y",
                           L"-i",         in_full,     L"-map",      L"0:v:0",     L"-c",
                           L"copy",       L"-movflags",
                           L"+frag_keyframe+empty_moov+default_base_moof",
                           L"-f",         L"mp4",      m4v1,         L"-map",      L"0:a:0",
                           L"-c",         L"copy",     L"-f",        L"mp4",       audio};
        bool spawn_failed = false;
        const DWORD code = h5e_run_ffmpeg(ffmpeg, args, (int)(sizeof args / sizeof args[0]),
                                          &spawn_failed);
        if (spawn_failed) {
            h5e_msg_path("错误：ffmpeg 无法启动：", ffmpeg);
            rc = H5E_RC_FFMPEG_MISSING;
            goto cleanup;
        }
        dual_ok = (code == 0);
        if (!dual_ok) {
            fprintf(stderr,
                    "      [1/3] 单命令双输出未成功（退出码 %ld）：多半是输入没有音频流；\n"
                    "      回退为只转视频，再探测输入有没有音频流决定是否旁路\n",
                    (long)(int32_t)code);
        }
    }
    if (!dual_ok) {
        /* 回退：只产出 stage1.m4v（不映射音频，输入无音频也能成功） */
        wchar_t *args[] = {L"-hide_banner", L"-nostdin", L"-loglevel", L"error", L"-y",
                           L"-i",         in_full,     L"-map",      L"0:v:0",     L"-c",
                           L"copy",       L"-movflags",
                           L"+frag_keyframe+empty_moov+default_base_moof",
                           L"-f",         L"mp4",      m4v1};
        bool spawn_failed = false;
        const DWORD code = h5e_run_ffmpeg(ffmpeg, args, (int)(sizeof args / sizeof args[0]),
                                          &spawn_failed);
        if (spawn_failed) {
            h5e_msg_path("错误：ffmpeg 无法启动：", ffmpeg);
            rc = H5E_RC_FFMPEG_MISSING;
            goto cleanup;
        }
        if (code != 0) {
            fprintf(stderr,
                    "错误：第一次 FFmpeg 转封装失败（退出码 %ld）——输入可能不是可识别的 TS/MP4，\n"
                    "      或其中的视频参数集(SPS/PPS)无法被解析\n",
                    (long)(int32_t)code);
            rc = H5E_RC_STAGE1;
            goto cleanup;
        }
    }
    {
        const long long sz = h5e_file_size(m4v1);
        if (sz < 64 || !h5e_file_is_mp4(m4v1)) {
            fprintf(stderr, "错误：FFmpeg 未生成有效的 MP4 中间文件（大小 %lld）\n", sz);
            rc = H5E_RC_STAGE1;
            goto cleanup;
        }
        fprintf(stderr, "      分片 MP4 已生成：%lld 字节\n", sz);
    }

    /* ---------- 1b. 音频旁路：判定 / 校验（除回退路径外不再单跑 ffmpeg） ----------
     * 单命令双输出成功时，audio.m4a 已与 stage1.m4v 一起产出，这里只做校验。
     * 只有回退路径才需要判断“输入到底有没有音频”：直接问 ffmpeg（-t 0 只解容器头，
     * 不读内容）——有，就单独抽一次；没有，就降级为只合成视频，并在日志里明说，绝不静默产出。
     * 抽音频失败按“第一次转封装失败”返回非零，不产出一个看着成功、音频却不一致的成品。 */
    if (dual_ok) {
        const long long asz = h5e_file_size(audio);
        if (asz < 64 || !h5e_file_is_mp4(audio)) {
            fprintf(stderr, "错误：FFmpeg 未生成有效的音频旁路文件（大小 %lld）\n", asz);
            rc = H5E_RC_STAGE1;
            goto cleanup;
        }
        audio_ready = true;
        fprintf(stderr, "      音频已抽出：%lld 字节（来自原始输入，与视频分开成两个中间文件）\n",
                asz);
    } else {
        bool has_audio = false;
        const int prc = h5e_ffmpeg_has_audio(ffmpeg, in_full, &has_audio);
        if (prc != 0) {
            fprintf(stderr,
                    "[1/3] 注意：无法判定输入是否带音频（ffmpeg 无法启动），跳过音频旁路，\n"
                    "      最终 MP4 只含视频\n");
        } else if (!has_audio) {
            fprintf(stderr,
                    "[1/3] 注意：输入里没有音频流，跳过音频旁路，最终 MP4 只含视频\n");
        } else {
            fprintf(stderr, "[1/3] FFmpeg 抽音频：输入 -> 音频旁路（-c copy，不重编码）\n");
            h5e_msg_path("      音频：", audio);
            /* 只做流复制：不重编码、不裁剪（-map 已限定只取音频流，无需 -vn 之类副作用） */
            wchar_t *aargs[] = {L"-hide_banner", L"-nostdin", L"-loglevel", L"error", L"-y",
                                L"-i",         in_full,     L"-map",      L"0:a:0",     L"-c",
                                L"copy",       L"-f",        L"mp4",       audio};
            bool spawn_failed = false;
            const DWORD code = h5e_run_ffmpeg(ffmpeg, aargs, (int)(sizeof aargs / sizeof aargs[0]),
                                              &spawn_failed);
            if (spawn_failed) {
                h5e_msg_path("错误：ffmpeg 无法启动：", ffmpeg);
                rc = H5E_RC_FFMPEG_MISSING;
                goto cleanup;
            }
            if (code != 0) {
                fprintf(stderr,
                        "错误：音频旁路抽取失败（退出码 %ld）——输入的音频流无法用 -c copy\n"
                        "      流复制进 MP4 音频轨（编码不受 MP4 支持？）；为避免产出音频\n"
                        "      与参考不一致的成品，本次处理中止\n",
                        (long)(int32_t)code);
                rc = H5E_RC_STAGE1;
                goto cleanup;
            }
            const long long asz = h5e_file_size(audio);
            if (asz < 64 || !h5e_file_is_mp4(audio)) {
                fprintf(stderr, "错误：FFmpeg 未生成有效的音频旁路文件（大小 %lld）\n", asz);
                rc = H5E_RC_STAGE1;
                goto cleanup;
            }
            audio_ready = true;
            fprintf(stderr, "      音频已抽出：%lld 字节（来自原始输入，与视频分开成两个中间文件）\n",
                    asz);
        }
    }

    /* ---------- 2. 分片 MP4 → 解密后的分片 MP4（本程序的 hls_h5e 核心） ---------- */
    fprintf(stderr, "[2/3] 解密 MP4 视频样本（复用 dec.c 引擎，容器仍为分片 MP4）\n");
    h5e_msg_path("      解密结果：", m4v2);
    {
        size_t frags = 0, written = 0;
        bool unsupported = false;
        const long long nalus = h5e_decrypt_mp4_w(m4v1, m4v2, &frags, &written, &unsupported);
        if (nalus < 0) {
            const char *why = "未知错误";
            switch ((int)nalus) {
                case -1: why = "参数错误"; break;
                case -2: why = "读取 MP4 中间文件失败"; break;
                case -3: why = "内存不足"; break;
                case -4: why = "写出解密中间文件失败（磁盘空间不足？）"; break;
                case -5: why = "MP4 中间文件格式不合法"; break;
                case -6:
                    why = unsupported ? "MP4 里的视频编码不是 AVC/HEVC，无法 NAL 级解密"
                                      : "MP4 里没有可解密的视频样本（缺视频轨或数据异常）";
                    break;
                case -7:
                    why = "MP4 分片结构与预期不符（多轨 / 缺逐样本字节数表 / base-data-offset）";
                    break;
                default: break;
            }
            fprintf(stderr, "错误：解密失败 rc=%lld (%s)\n", nalus, why);
            rc = H5E_RC_DECRYPT;
            goto cleanup;
        }
        fprintf(stderr, "      分片：%zu，经过会话的 NAL：%lld，解密结果：%zu 字节\n", frags, nalus,
                written);
    }

    /* ---------- 3. 解密后的分片 MP4（+ 音频旁路）→ 最终 MP4（先写 .part） ---------- */
    fprintf(stderr, "[3/3] FFmpeg 转封装：解密结果%s -> MP4（-c copy）\n",
            audio_ready ? " + 音频旁路" : "");
    if (audio_ready) {
        h5e_msg_path("      视频（解密后）：", m4v2);
        h5e_msg_path("      音频（旁路）：", audio);
    }
    h5e_msg_path("      输出：", part);
    {
        /* 双输入合成：0 = 解密后的视频分片 MP4，1 = 从原始输入抽出的音频轨。
         * 视频轨经历样本改写，音频轨保持原样，所以分两个文件再合起来。 */
        wchar_t *args_ab[] = {L"-hide_banner", L"-nostdin", L"-loglevel", L"error", L"-y",
                             L"-i",         m4v2,        L"-i",         audio,        L"-map",
                             L"0:v:0",     L"-map",     L"1:a:0",     L"-c",        L"copy",
                             L"-movflags",  L"+faststart", L"-f",      L"mp4",      part};
        /* 降级路径：无音频可旁路时只合成视频（仍用可选映射，不会因缺音频流报错） */
        wchar_t *args_sv[] = {L"-hide_banner", L"-nostdin", L"-loglevel", L"error", L"-y",
                             L"-i",         m4v2,        L"-map",      L"0:v:0",    L"-map",
                             L"0:a:0?",     L"-c",       L"copy",     L"-movflags", L"+faststart",
                             L"-f",         L"mp4",      part};
        wchar_t **args = audio_ready ? args_ab : args_sv;
        const int nargs = audio_ready ? (int)(sizeof args_ab / sizeof args_ab[0])
                                      : (int)(sizeof args_sv / sizeof args_sv[0]);
        bool spawn_failed = false;
        const DWORD code = h5e_run_ffmpeg(ffmpeg, args, nargs, &spawn_failed);
        if (spawn_failed) {
            h5e_msg_path("错误：ffmpeg 无法启动：", ffmpeg);
            rc = H5E_RC_FFMPEG_MISSING;
            goto cleanup;
        }
        if (code != 0) {
            fprintf(stderr, "错误：第二次 FFmpeg 转封装失败（退出码 %ld）\n", (long)(int32_t)code);
            rc = H5E_RC_STAGE2;
            goto cleanup;
        }
    }
    {
        const long long sz = h5e_file_size(part);
        if (sz <= 0 || !h5e_file_is_mp4(part)) {
            fprintf(stderr, "错误：FFmpeg 未生成有效的 MP4（大小 %lld）\n", sz);
            rc = H5E_RC_STAGE2;
            goto cleanup;
        }
        fprintf(stderr, "      MP4 已写出：%lld 字节\n", sz);
    }

    /* ---------- 4. 原子替换：成功后才让 <输出> 出现在磁盘上 ---------- */
    if (!MoveFileExW(part, out_full, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        part_kept = true; /* 成品留在 .part 里，方便手动改名 */
        h5e_msg_path("错误：最终替换失败（目标被占用/只读？），成品保留在：", part);
        rc = H5E_RC_OUTPUT;
        goto cleanup;
    }

    h5e_msg_path("完成：", out_full);
    fprintf(stderr, "      处理顺序已确认：输入 -> 分片 MP4 -> 解密 -> MP4（视频）%s\n",
            audio_ready ? "；音频：输入 -> MP4 音频轨（旁路 -c copy，未经过视频中间文件）"
                        : "；音频：无（已跳过音频旁路）");
    fprintf(stderr, "      引擎版本：%s\n", H5E_VERSION);

cleanup:
    if (rc != H5E_RC_OK && part && !part_kept) DeleteFileW(part);
    h5e_temp_dir_remove(dir, temps, 3);
    free(in_full);
    free(out_full);
    free(ffmpeg);
    free(dir);
    free(m4v1);
    free(m4v2);
    free(audio);
    free(part);
    return rc;
}

/* ============================== TUI 输入界面 ============================== */
/*
 * 无参数启动时，先用本界面收集“输入文件 / 输出文件 / ffmpeg 路径”，收集完成后恢复
 * 控制台，再走与命令行完全相同的 h5e_pipeline()——两条入口共用同一条流水线，
 * 解密与转封装行为不受界面影响（dec.c 参照实现不动）。
 *
 * 界面只有两屏：
 *   表单屏：↑↓/Tab 换字段，直接编辑路径；F2 浏览磁盘；Enter 开始；Esc 退出。
 *   浏览屏：列出目录内容（输入只列 .ts/.mp4，ffmpeg 只列 .exe）；Enter 选中；
 *           空格/→ 进入光标处目录；Backspace 回上级；Esc 取消。
 *
 * 画法：整屏先拼进 CHAR_INFO 缓冲，最后一次 WriteConsoleOutputW 刷出，不闪烁；
 * 进界面前把控制台缓冲区缩到窗口尺寸（这样按 (0,0) 画的整屏一定可见），退出时复原。
 * stdin 不是控制台（被重定向）时退回逐行问答，保证脚本里也能用。
 */

#define H5E_TUI_CAP   1024 /* 单个输入项的最大字符数 */
#define H5E_TUI_MIN_W 48   /* 窗口小于该尺寸就提示放大 */
#define H5E_TUI_MIN_H 14

/* 配色：黑底上按“正文 / 次要 / 强调”分层。
 * 注意前景色单独用 FOREGROUND_INTENSITY 会得到“亮黑”，实际渲染出来是深灰，
 * 在黑底上对比度极低，所以次要信息改成亮青，正文用亮白，分隔线用中灰。 */
#define H5E_TUI_ATTR_TEXT \
    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY) /* 亮白：正文 */
#define H5E_TUI_ATTR_DIM \
    (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY) /* 亮青：次要提示 */
#define H5E_TUI_ATTR_LABEL (FOREGROUND_GREEN | FOREGROUND_INTENSITY) /* 亮绿：字段名 */
#define H5E_TUI_ATTR_RULE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) /* 中灰：分隔线 */
#define H5E_TUI_ATTR_FOCUS \
    (BACKGROUND_BLUE | BACKGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define H5E_TUI_ATTR_TITLE H5E_TUI_ATTR_FOCUS
#define H5E_TUI_ATTR_ERR   (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define H5E_TUI_ATTR_OK    (FOREGROUND_GREEN | FOREGROUND_INTENSITY)

/* UTF-8 窄串 → 宽串，失败返回 NULL（调用方负责 free） */
static wchar_t *h5e_wide_from_utf8(const char *s) {
    if (!s) return NULL;
    const int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *p = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!p) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, p, n) <= 0) {
        free(p);
        return NULL;
    }
    return p;
}

/* 宽串有界拷贝（含结尾 0） */
static void h5e_wcopy(wchar_t *dst, size_t cap, const wchar_t *src) {
    if (!dst || cap == 0) return;
    size_t n = src ? wcslen(src) : 0;
    if (n >= cap) n = cap - 1;
    if (n) memcpy(dst, src, n * sizeof(wchar_t));
    dst[n] = L'\0';
}

/* 一个宽字符在控制台占几格：CJK / 全角 2 格，其余 1 格 */
static int h5e_tui_cell_width(wchar_t c) {
    if (c < 0x7f) return 1;
    if ((c >= 0x1100 && c <= 0x115f) || (c >= 0x2e80 && c <= 0xa4cf) ||
        (c >= 0xac00 && c <= 0xd7a3) || (c >= 0xf900 && c <= 0xfaff) ||
        (c >= 0xfe30 && c <= 0xfe6f) || (c >= 0xff00 && c <= 0xff60) ||
        (c >= 0xffe0 && c <= 0xffe6))
        return 2;
    return 1;
}

/* 字符串占用的格数（与显示宽度一致，用于右对齐） */
static int h5e_tui_cells(const wchar_t *s) {
    int n = 0;
    for (; s && *s; s++) n += h5e_tui_cell_width(*s);
    return n;
}

/* 屏幕：整屏先拼在这里，最后按行刷给控制台 */
typedef struct {
    CHAR_INFO *cells; /* 本帧内容：宽字符写在前格，尾格记 0（表示“已被前一格占去”） */
    int w, h;
} h5e_tui_screen;

static bool h5e_tui_screen_resize(h5e_tui_screen *s, int w, int h) {
    if (w <= 0 || h <= 0) return false;
    if (s->cells && s->w == w && s->h == h) return true;
    CHAR_INFO *p = (CHAR_INFO *)realloc(s->cells, (size_t)w * (size_t)h * sizeof(CHAR_INFO));
    if (!p) return false;
    s->cells = p;
    s->w = w;
    s->h = h;
    return true;
}

static void h5e_tui_screen_free(h5e_tui_screen *s) {
    free(s->cells);
    s->cells = NULL;
    s->w = s->h = 0;
}

static void h5e_tui_screen_fill(h5e_tui_screen *s, WORD attr) {
    const size_t n = (size_t)s->w * (size_t)s->h;
    for (size_t i = 0; i < n; i++) {
        s->cells[i].Char.UnicodeChar = L' ';
        s->cells[i].Attributes = attr;
    }
}

/* 整行铺成某个属性（标题条 / 光标行） */
static void h5e_tui_screen_bar(h5e_tui_screen *s, int y, WORD attr) {
    if (y < 0 || y >= s->h) return;
    for (int x = 0; x < s->w; x++) {
        s->cells[(size_t)y * s->w + x].Char.UnicodeChar = L' ';
        s->cells[(size_t)y * s->w + x].Attributes = attr;
    }
}

/* 矩形区域铺成某个属性（输入框底纹） */
static void h5e_tui_screen_rect(h5e_tui_screen *s, int x0, int y0, int x1, int y1, WORD attr) {
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > s->w) x1 = s->w;
    if (y1 > s->h) y1 = s->h;
    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            s->cells[(size_t)y * s->w + x].Char.UnicodeChar = L' ';
            s->cells[(size_t)y * s->w + x].Attributes = attr;
        }
    }
}

/* 画一个宽字符（占 1 或 2 格）：越界不写，返回是否写下 */
static bool h5e_tui_put_wchar(h5e_tui_screen *s, int x, int y, wchar_t c, WORD attr, int max_x) {
    if (max_x > s->w) max_x = s->w;
    const int cw = h5e_tui_cell_width(c);
    if (x < 0 || y < 0 || y >= s->h || x + cw > max_x) return false;
    CHAR_INFO *ci = &s->cells[(size_t)y * s->w + x];
    ci->Char.UnicodeChar = c;
    ci->Attributes = attr;
    if (cw == 2) { /* 尾格交给宽字符自己占 */
        ci[1].Char.UnicodeChar = 0;
        ci[1].Attributes = attr;
    }
    return true;
}

/* 画字符串：到 max_x（不含）为止，控制字符跳过 */
static void h5e_tui_screen_text(h5e_tui_screen *s, int x, int y, const wchar_t *str, WORD attr,
                                int max_x) {
    if (!str) return;
    int cx = x;
    for (const wchar_t *p = str; *p; p++) {
        if (*p < 0x20) continue;
        const int cw = h5e_tui_cell_width(*p);
        if (!h5e_tui_put_wchar(s, cx, y, *p, attr, max_x)) break;
        cx += cw;
    }
}

/* 画字符并自动折行（最多 max_rows 行），返回实际占用的行数 */
static int h5e_tui_screen_wrap(h5e_tui_screen *s, int x, int y, int max_rows, const wchar_t *str,
                               WORD attr) {
    if (!str || max_rows <= 0) return 0;
    const int max_x = s->w - 1;
    int row = 0, cx = x;
    for (const wchar_t *p = str; *p && row < max_rows; p++) {
        if (*p == L'\n') {
            row++;
            cx = x;
            continue;
        }
        if (*p < 0x20) continue;
        const int cw = h5e_tui_cell_width(*p);
        if (cx + cw > max_x) {
            row++;
            cx = x;
            if (row >= max_rows) break;
        }
        h5e_tui_put_wchar(s, cx, y + row, *p, attr, max_x);
        cx += cw;
    }
    return row + 1;
}

/* 虚拟终端（VT）序列支持：Win10 1809+ 有，旧系统 SetConsoleMode 会失败，自动退回老办法 */
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#  define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* 控制台：进入 TUI 前保存，退出时复原 */
typedef struct {
    HANDLE in, out;
    DWORD in_mode, out_mode;
    COORD saved_size;
    WORD saved_attr;
    CONSOLE_CURSOR_INFO saved_cursor;
    wchar_t *linebuf; /* 刷屏用的行缓冲（跨帧复用） */
    size_t linecap;
    bool vt;      /* 已开启 VT：用备用屏幕缓冲区 + CUP 定位 */
    bool cur_vis; /* VT 下当前是否显示光标（只在变化时发序列） */
    bool active;
} h5e_tui_console;

/* 直接写一段宽字符（VT 序列与普通文本都走这里） */
static void h5e_tui_puts(const h5e_tui_console *c, const wchar_t *s) {
    if (!c->out || !s || !*s) return;
    DWORD wrote = 0;
    (void)WriteConsoleW(c->out, s, (DWORD)wcslen(s), &wrote, NULL);
}

/* 尽力锁住控制台窗口尺寸：只对经典 conhost 窗口（ConsoleWindowClass）生效。
 * Windows Terminal 等宿主的窗口是多标签共享的，改它会影响别的标签，所以直接跳过。
 * 做法：去掉可缩放边框与“最大化”按钮，并删掉系统菜单里的“大小/最大化”。
 * 局限：宿主自己的“改字体大小”、控制台属性里的“布局”仍能改列数，那是宿主行为。 */
static void h5e_tui_lock_window(bool lock) {
    HWND w = GetConsoleWindow();
    if (!w) return;
    wchar_t cls[64] = {0};
    if (GetClassNameW(w, cls, 63) <= 0) return;
    if (wcscmp(cls, L"ConsoleWindowClass") != 0) return;

    const LONG style = GetWindowLongW(w, GWL_STYLE);
    const LONG want = lock ? (style & ~(LONG)(WS_SIZEBOX | WS_MAXIMIZEBOX))
                           : (style | (LONG)(WS_SIZEBOX | WS_MAXIMIZEBOX));
    if (want != style) (void)SetWindowLongW(w, GWL_STYLE, want);

    HMENU sys = GetSystemMenu(w, FALSE);
    if (sys) {
        if (lock) {
            (void)DeleteMenu(sys, SC_SIZE, MF_BYCOMMAND);
            (void)DeleteMenu(sys, SC_MAXIMIZE, MF_BYCOMMAND);
        } else {
            (void)AppendMenuW(sys, MF_SEPARATOR, 0, NULL);
            (void)AppendMenuW(sys, MF_STRING, SC_SIZE, L"大小(&S)");
            (void)AppendMenuW(sys, MF_STRING, SC_MAXIMIZE, L"最大化(&X)");
        }
    }
    (void)SetWindowPos(w, NULL, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
}

/* 缓冲区缩到与窗口同样大：按 (0,0) 画的整屏一定可见，不必关心滚动 */
static void h5e_tui_fit_buffer(const h5e_tui_console *c) {
    CONSOLE_SCREEN_BUFFER_INFO bi;
    if (!GetConsoleScreenBufferInfo(c->out, &bi)) return;
    const SHORT w = (SHORT)(bi.srWindow.Right - bi.srWindow.Left + 1);
    const SHORT h = (SHORT)(bi.srWindow.Bottom - bi.srWindow.Top + 1);
    if (w <= 0 || h <= 0) return;
    if (bi.dwSize.X == w && bi.dwSize.Y == h) return;
    (void)SetConsoleScreenBufferSize(c->out, (COORD){w, h});
}

static bool h5e_tui_console_open(h5e_tui_console *c) {
    memset(c, 0, sizeof *c);
    c->in = GetStdHandle(STD_INPUT_HANDLE);
    c->out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!c->in || !c->out || c->in == INVALID_HANDLE_VALUE || c->out == INVALID_HANDLE_VALUE)
        return false;
    if (!GetConsoleMode(c->in, &c->in_mode)) return false; /* stdin 被重定向：交给逐行问答 */
    if (!GetConsoleMode(c->out, &c->out_mode)) return false;

    CONSOLE_SCREEN_BUFFER_INFO bi;
    if (!GetConsoleScreenBufferInfo(c->out, &bi)) return false;
    c->saved_size = bi.dwSize;
    c->saved_attr = bi.wAttributes;
    c->saved_cursor.dwSize = 0;
    c->saved_cursor.bVisible = TRUE;
    c->active = true; /* 从这里开始，close 一定能把模式复原 */

    /* 输入：关掉行缓冲与回显，Esc / Ctrl+C 由本程序自己处理 */
    DWORD im = c->in_mode & ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
    im |= ENABLE_WINDOW_INPUT;
    (void)SetConsoleMode(c->in, im);

    /* 输出：先试开虚拟终端（Win10 1809+ 支持）。开了就用备用屏幕缓冲区，
     * TUI 不占用主屏，退出后用户原来的输出与滚动历史原样回来；
     * 不支持就退回“缩缓冲区 + 整屏清空”的老办法。 */
    const DWORD om = c->out_mode | ENABLE_PROCESSED_OUTPUT;
    if (SetConsoleMode(c->out, om | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        c->vt = true;
    } else {
        (void)SetConsoleMode(c->out, om);
    }

    CONSOLE_CURSOR_INFO ci;
    if (GetConsoleCursorInfo(c->out, &ci)) c->saved_cursor = ci;

    if (c->vt) {
        h5e_tui_puts(c, L"\x1b[?25l");   /* 先藏光标 */
        h5e_tui_puts(c, L"\x1b[?1049h"); /* 切到备用屏幕缓冲区 */
        h5e_tui_puts(c, L"\x1b[0m");
        h5e_tui_puts(c, L"\x1b[2J"); /* 清屏（宿主不支持 ?1049 时当普通清屏用） */
        h5e_tui_puts(c, L"\x1b[H");
        c->cur_vis = false;
    } else {
        h5e_tui_fit_buffer(c);
        /* 整屏先清干净：最后一列本程序不写，留着旧内容会显脏 */
        CONSOLE_SCREEN_BUFFER_INFO b2;
        if (GetConsoleScreenBufferInfo(c->out, &b2)) {
            const COORD home = {0, 0};
            const DWORD total = (DWORD)b2.dwSize.X * (DWORD)b2.dwSize.Y;
            DWORD n = 0;
            (void)FillConsoleOutputCharacterW(c->out, L' ', total, home, &n);
            (void)FillConsoleOutputAttribute(c->out, H5E_TUI_ATTR_TEXT, total, home, &n);
            (void)SetConsoleCursorPosition(c->out, home);
        }
        ci.bVisible = TRUE;
        ci.dwSize = 25;
        (void)SetConsoleCursorInfo(c->out, &ci);
    }

    h5e_tui_lock_window(true); /* 能锁就锁（仅经典 conhost 生效） */
    return true;
}

static void h5e_tui_console_close(h5e_tui_console *c) {
    if (!c->active) return;
    h5e_tui_lock_window(false);
    if (c->vt) {
        /* 回主屏幕缓冲区：用户的滚动历史与光标位置一并还原 */
        h5e_tui_puts(c, L"\x1b[0m");
        h5e_tui_puts(c, L"\x1b[?25h");
        h5e_tui_puts(c, L"\x1b[?1049l");
    } else {
        /* 清屏并把光标放回左上角，别把 TUI 残影留在后续日志里 */
        CONSOLE_SCREEN_BUFFER_INFO bi;
        if (GetConsoleScreenBufferInfo(c->out, &bi)) {
            const COORD home = {0, 0};
            const DWORD total = (DWORD)bi.dwSize.X * (DWORD)bi.dwSize.Y;
            DWORD n = 0;
            (void)FillConsoleOutputCharacterW(c->out, L' ', total, home, &n);
            (void)FillConsoleOutputAttribute(c->out, H5E_TUI_ATTR_TEXT, total, home, &n);
            (void)SetConsoleCursorPosition(c->out, home);
        }
    }
    (void)SetConsoleMode(c->in, c->in_mode);
    (void)SetConsoleMode(c->out, c->out_mode);
    (void)SetConsoleTextAttribute(c->out, c->saved_attr);
    if (c->saved_cursor.dwSize) (void)SetConsoleCursorInfo(c->out, &c->saved_cursor);
    if (c->saved_size.X > 0 && c->saved_size.Y > 0)
        (void)SetConsoleScreenBufferSize(c->out, c->saved_size);
    free(c->linebuf);
    c->linebuf = NULL;
    c->linecap = 0;
    c->active = false;
}

static bool h5e_tui_console_size(const h5e_tui_console *c, int *w, int *h) {
    CONSOLE_SCREEN_BUFFER_INFO bi;
    if (!GetConsoleScreenBufferInfo(c->out, &bi)) return false;
    *w = bi.srWindow.Right - bi.srWindow.Left + 1;
    *h = bi.srWindow.Bottom - bi.srWindow.Top + 1;
    return *w > 0 && *h > 0;
}

/* 整屏刷到控制台：逐行、按属性分段写“文本”。
 *
 * 这里不用 WriteConsoleOutputW：ConPTY（Windows Terminal）会把“宽字符 + 尾格 0”
 * 当成两个独立单元格，中文后面会多出一个方块并整体右移。改成直接写文本后，
 * 宽字符由终端自己按 2 列排版，尾格的 0 跳过不写，中文位置就不会漂。
 * 每帧全部重画（不做“只重画变化行”的差分）：差分会把“行内容与屏幕实际内容”
 * 绑在一起，一旦发生过意外滚屏就再也对不上，反而留下重影。整屏重画的代价
 * 只有几十次 WriteConsoleW，足以跟得上按键。 */
static bool h5e_tui_console_flush(h5e_tui_console *c, h5e_tui_screen *s) {
    if (!s->cells || s->w <= 1 || s->h <= 0) return false;
    const int w = s->w; /* 逻辑宽度：屏幕本身已比控制台窄，写满也不会换行 */
    if (c->linecap < (size_t)s->w + 8) {
        const size_t cap = (size_t)s->w + 8;
        wchar_t *p = (wchar_t *)realloc(c->linebuf, cap * sizeof(wchar_t));
        if (!p) return false;
        c->linebuf = p;
        c->linecap = cap;
    }

    bool ok = true;
    for (int y = 0; y < s->h && ok; y++) {
        const size_t rowoff = (size_t)y * (size_t)s->w;
        if (c->vt) {
            /* VT 下用 CUP 定位：坐标相对可视区域，不依赖缓冲区原点 */
            wchar_t seq[24];
            swprintf(seq, sizeof seq / sizeof seq[0], L"\x1b[%d;1H", y + 1);
            h5e_tui_puts(c, seq);
        } else if (!SetConsoleCursorPosition(c->out, (COORD){0, (SHORT)y})) {
            ok = false;
            break;
        }
        int x = 0;
        while (x < w) {
            const WORD attr = s->cells[rowoff + x].Attributes;
            int n = 0;
            while (x < w && s->cells[rowoff + x].Attributes == attr) {
                const wchar_t ch = s->cells[rowoff + x].Char.UnicodeChar;
                if (ch) c->linebuf[n++] = ch; /* 宽字符尾格的 0 不写 */
                x++;
            }
            if (n == 0) continue;
            (void)SetConsoleTextAttribute(c->out, attr);
            DWORD wrote = 0;
            if (!WriteConsoleW(c->out, c->linebuf, (DWORD)n, &wrote, NULL) || wrote != (DWORD)n) {
                ok = false;
                break;
            }
        }
    }
    return ok;
}

enum { H5E_TUI_EV_KEY = 0, H5E_TUI_EV_RESIZE = 1, H5E_TUI_EV_FAIL = 2 };

/* 读一个事件：普通按键 / 窗口尺寸变化；鼠标等其它事件跳过 */
static int h5e_tui_read_event(const h5e_tui_console *c, KEY_EVENT_RECORD *key) {
    for (;;) {
        INPUT_RECORD ir;
        DWORD got = 0;
        if (!ReadConsoleInputW(c->in, &ir, 1, &got)) return H5E_TUI_EV_FAIL;
        if (got == 0) continue;
        if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT) return H5E_TUI_EV_RESIZE;
        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
            *key = ir.Event.KeyEvent;
            return H5E_TUI_EV_KEY;
        }
    }
}

/* ============================ TUI：可编辑字段与表单屏 ============================ */

typedef struct {
    wchar_t text[H5E_TUI_CAP];
    size_t len;
    size_t cur; /* 光标（0..len） */
} h5e_tui_field;

/* 表单的字段顺序：0 输入文件，1 输出文件，2 ffmpeg 路径 */
typedef struct {
    h5e_tui_field field[3];
    int focus;
    wchar_t status[512];
    WORD status_attr;
    h5e_tui_console con;
    h5e_tui_screen scr;
    int caret_x, caret_y;
    bool caret;
} h5e_tui;

/* 收集好的三项参数：空串表示未指定 */
typedef struct {
    wchar_t input[H5E_TUI_CAP];
    wchar_t output[H5E_TUI_CAP];
    wchar_t ffmpeg[H5E_TUI_CAP];
} h5e_tui_result;

static void h5e_tui_field_set(h5e_tui_field *f, const wchar_t *s) {
    f->len = 0;
    f->cur = 0;
    f->text[0] = L'\0';
    if (!s) return;
    h5e_wcopy(f->text, H5E_TUI_CAP, s);
    f->len = wcslen(f->text);
    f->cur = f->len;
}

static void h5e_tui_field_insert(h5e_tui_field *f, wchar_t ch) {
    if (f->len + 1 >= H5E_TUI_CAP) return;
    memmove(f->text + f->cur + 1, f->text + f->cur, (f->len - f->cur + 1) * sizeof(wchar_t));
    f->text[f->cur++] = ch;
    f->len++;
}

static void h5e_tui_field_backspace(h5e_tui_field *f) {
    if (f->cur == 0) return;
    memmove(f->text + f->cur - 1, f->text + f->cur, (f->len - f->cur + 1) * sizeof(wchar_t));
    f->cur--;
    f->len--;
}

static void h5e_tui_field_delete(h5e_tui_field *f) {
    if (f->cur >= f->len) return;
    memmove(f->text + f->cur, f->text + f->cur + 1, (f->len - f->cur) * sizeof(wchar_t));
    f->len--;
}

/* 去掉首尾空白与引号：从资源管理器“复制为路径”常带双引号 */
static void h5e_tui_field_trim(h5e_tui_field *f) {
    size_t b = 0, e = f->len;
    while (b < e && (f->text[b] == L' ' || f->text[b] == L'\t' || f->text[b] == L'"')) b++;
    while (e > b && (f->text[e - 1] == L' ' || f->text[e - 1] == L'\t' || f->text[e - 1] == L'"')) e--;
    if (b == 0 && e == f->len) return;
    const size_t n = e - b;
    if (n) memmove(f->text, f->text + b, n * sizeof(wchar_t));
    f->text[n] = L'\0';
    f->len = n;
    if (f->cur > n) f->cur = n;
}

static void h5e_tui_set_status(h5e_tui *t, WORD attr, const wchar_t *msg) {
    const size_t cap = sizeof t->status / sizeof t->status[0];
    h5e_wcopy(t->status, cap, msg);
    t->status_attr = attr;
}

/* 计算显示起点与光标列：聚焦时保证光标可见，失焦时露出尾部（文件名在尾巴上） */
static void h5e_tui_field_view(const h5e_tui_field *f, int boxw, bool focused, size_t *from,
                               int *cur_col) {
    *from = 0;
    *cur_col = 0;
    if (boxw <= 0) return;
    const int keep = focused ? (boxw - 1) : boxw; /* 聚焦时留一格给光标 */
    if (keep <= 0) return;
    size_t i = focused ? f->cur : f->len;
    int cells = 0;
    while (i > 0) {
        const int cw = h5e_tui_cell_width(f->text[i - 1]);
        if (cells + cw > keep) break;
        cells += cw;
        i--;
    }
    *from = i;
    *cur_col = focused ? cells : 0;
}

/* 画一行字段：标签 + 输入框；聚焦时整条输入框反显，并把光标位置记到 t 里 */
static void h5e_tui_draw_field(h5e_tui *t, int y, const wchar_t *label, h5e_tui_field *f,
                               bool focused, const wchar_t *hint) {
    h5e_tui_screen *s = &t->scr;
    const int x_label = 2, x_box = 14, right = s->w - 2;
    if (right - x_box < 6) return;
    h5e_tui_screen_text(s, x_label - 2, y, focused ? L">" : L" ",
                        focused ? H5E_TUI_ATTR_LABEL : H5E_TUI_ATTR_RULE, s->w);
    /* 字段名固定用亮绿：不随焦点变，始终能一眼看到三个字段在哪 */
    h5e_tui_screen_text(s, x_label, y, label, H5E_TUI_ATTR_LABEL, x_box);
    h5e_tui_screen_rect(s, x_box, y, right, y + 1,
                        focused ? H5E_TUI_ATTR_FOCUS : H5E_TUI_ATTR_TEXT);

    const WORD attr = focused ? H5E_TUI_ATTR_FOCUS : H5E_TUI_ATTR_TEXT;
    const int inner = right - x_box - 2; /* 左右各留一格内边距 */
    if (inner <= 0) return;
    if (f->len == 0 && !focused) {
        h5e_tui_screen_text(s, x_box + 1, y, hint, H5E_TUI_ATTR_DIM, right - 1);
        return;
    }
    size_t from = 0;
    int col = 0;
    h5e_tui_field_view(f, inner, focused, &from, &col);
    h5e_tui_screen_text(s, x_box + 1, y, f->text + from, attr, right - 1);
    if (focused) {
        t->caret_x = x_box + 1 + col;
        t->caret_y = y;
    }
}

/* 画表单屏 */
static void h5e_tui_render(h5e_tui *t) {
    h5e_tui_screen *s = &t->scr;
    h5e_tui_screen_fill(s, H5E_TUI_ATTR_TEXT);
    t->caret = false;

    if (s->w < H5E_TUI_MIN_W || s->h < H5E_TUI_MIN_H) {
        h5e_tui_screen_text(s, 0, 0, L"窗口太小，请放大窗口后继续（至少 48x14）", H5E_TUI_ATTR_ERR,
                            s->w);
        return;
    }

    /* 标题条 + 右对齐版本号 */
    h5e_tui_screen_bar(s, 0, H5E_TUI_ATTR_TITLE);
    h5e_tui_screen_text(s, 1, 0, L" cctv_h5e 解密（输入 -> 分片 MP4 -> 解密 -> MP4）",
                        H5E_TUI_ATTR_TITLE, s->w);
    {
        wchar_t *ver = h5e_wide_from_utf8(H5E_VERSION);
        if (ver) {
            const int x = s->w - 2 - h5e_tui_cells(ver);
            if (x > 2) h5e_tui_screen_text(s, x, 0, ver, H5E_TUI_ATTR_TITLE, s->w - 1);
            free(ver);
        }
    }

    h5e_tui_screen_text(s, 2, 1, L"无参数启动：在此填写参数；带参数启动仍按原命令行用法执行",
                        H5E_TUI_ATTR_DIM, s->w);
    for (int x = 0; x < s->w; x++) h5e_tui_put_wchar(s, x, 2, L'-', H5E_TUI_ATTR_RULE, s->w);

    h5e_tui_draw_field(t, 4, L"输入文件", &t->field[0], t->focus == 0,
                       L"（.ts / .mp4，F2 浏览）");
    h5e_tui_draw_field(t, 5, L"输出文件", &t->field[1], t->focus == 1,
                       L"（.mp4，留空则自动生成 *_dec.mp4）");
    h5e_tui_draw_field(t, 6, L"ffmpeg", &t->field[2], t->focus == 2,
                       L"（留空则自动搜索 PATH）");

    if (t->status[0]) h5e_tui_screen_wrap(s, 2, 8, 2, t->status, t->status_attr);

    for (int x = 0; x < s->w; x++) h5e_tui_put_wchar(s, x, s->h - 2, L'-', H5E_TUI_ATTR_RULE, s->w);
    h5e_tui_screen_text(s, 2, s->h - 1,
                        L"上下键 换字段   Tab 下一个   F2 浏览   Enter 开始   Esc 退出",
                        H5E_TUI_ATTR_DIM, s->w);
    t->caret = true;
}

/* 开一帧：先把缓冲区对齐窗口尺寸，再让离屏缓冲跟上 */
static bool h5e_tui_begin_frame(h5e_tui *t) {
    if (!t->con.vt) h5e_tui_fit_buffer(&t->con); /* 备用屏幕的缓冲区随窗口，无需调整 */
    int w = 0, h = 0;
    if (!h5e_tui_console_size(&t->con, &w, &h)) return false;
    /* 右侧留 2 列余量：既不写到缓冲区右下角（会触发整屏上滚），也让个别字符
     * 的宽度判断偏差不会把整行推过行尾（换行同样会把画面整体上移）。 */
    if (w > 6) w -= 2;
    return h5e_tui_screen_resize(&t->scr, w, h);
}

/* 结束一帧：整屏刷出，并把光标放到/藏到该在的地方 */
static bool h5e_tui_end_frame(h5e_tui *t) {
    if (!h5e_tui_console_flush(&t->con, &t->scr)) return false;
    if (t->con.vt) {
        if (t->caret) {
            wchar_t seq[24];
            swprintf(seq, sizeof seq / sizeof seq[0], L"\x1b[%d;%dH", t->caret_y + 1,
                     t->caret_x + 1);
            h5e_tui_puts(&t->con, seq);
        }
        if (t->con.cur_vis != t->caret) { /* 只在变化时发序列 */
            h5e_tui_puts(&t->con, t->caret ? L"\x1b[?25h" : L"\x1b[?25l");
            t->con.cur_vis = t->caret;
        }
    } else {
        if (t->caret)
            (void)SetConsoleCursorPosition(t->con.out,
                                           (COORD){(SHORT)t->caret_x, (SHORT)t->caret_y});
        CONSOLE_CURSOR_INFO ci = {25, t->caret ? TRUE : FALSE};
        (void)SetConsoleCursorInfo(t->con.out, &ci);
    }
    return true;
}

/* 由输入路径推导默认输出：同目录、同主名 + _dec.mp4 */
static bool h5e_tui_derive_output(const wchar_t *in_path, wchar_t *out, size_t cap) {
    const size_t n = in_path ? wcslen(in_path) : 0;
    if (n == 0 || n + 9 > cap) return false;
    size_t dot = n;
    for (size_t i = n; i-- > 0;) {
        if (in_path[i] == L'.') {
            dot = i;
            break;
        }
        if (in_path[i] == L'\\' || in_path[i] == L'/') break; /* 目录里的点不算扩展名 */
    }
    if (dot) memcpy(out, in_path, dot * sizeof(wchar_t));
    memcpy(out + dot, L"_dec.mp4", 9 * sizeof(wchar_t));
    return true;
}

/* 输出路径的父目录必须已存在且是目录 */
static bool h5e_tui_out_dir_ok(const wchar_t *path) {
    wchar_t dir[H5E_TUI_CAP];
    const size_t n = path ? wcslen(path) : 0;
    if (n == 0) return false;
    h5e_wcopy(dir, H5E_TUI_CAP, path);
    size_t i = n;
    while (i > 0 && dir[i - 1] != L'\\' && dir[i - 1] != L'/') i--;
    if (i == 0) return true; /* 只有文件名：目录就是当前目录 */
    dir[i - 1] = L'\0';
    if (dir[0] == L'\0') return false;
    const DWORD attr = GetFileAttributesW(dir);
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

/* 校验三项参数（含自动补全），不通过时把原因写进状态行 */
static bool h5e_tui_validate(h5e_tui *t) {
    h5e_tui_field *fin = &t->field[0], *fout = &t->field[1], *fff = &t->field[2];
    h5e_tui_field_trim(fin);
    h5e_tui_field_trim(fout);
    h5e_tui_field_trim(fff);

    if (fin->len == 0) {
        h5e_tui_set_status(t, H5E_TUI_ATTR_ERR, L"请先填写输入文件（.ts / .mp4）");
        t->focus = 0;
        return false;
    }
    if (!h5e_is_regular_file(fin->text)) {
        h5e_tui_set_status(t, H5E_TUI_ATTR_ERR, L"输入文件不存在，或不是普通文件");
        t->focus = 0;
        return false;
    }
    const wchar_t *iext = h5e_extension_of(fin->text);
    if (!h5e_ext_is(iext, L"ts") && !h5e_ext_is(iext, L"mp4")) {
        h5e_tui_set_status(t, H5E_TUI_ATTR_ERR, L"输入格式不支持：只接受 .ts / .mp4");
        t->focus = 0;
        return false;
    }

    if (fout->len == 0) {
        wchar_t derived[H5E_TUI_CAP];
        if (!h5e_tui_derive_output(fin->text, derived, H5E_TUI_CAP)) {
            h5e_tui_set_status(t, H5E_TUI_ATTR_ERR, L"输出路径太长，请手动填写输出文件");
            t->focus = 1;
            return false;
        }
        h5e_tui_field_set(fout, derived);
    }
    if (wcscmp(fout->text, fin->text) == 0) {
        h5e_tui_set_status(t, H5E_TUI_ATTR_ERR, L"输出文件不能与输入文件相同");
        t->focus = 1;
        return false;
    }
    if (!h5e_tui_out_dir_ok(fout->text)) {
        h5e_tui_set_status(t, H5E_TUI_ATTR_ERR, L"输出目录不存在，请改选一个已存在的目录");
        t->focus = 1;
        return false;
    }

    if (fff->len != 0) {
        wchar_t *p = h5e_find_ffmpeg(fff->text);
        if (!p) {
            h5e_tui_set_status(t, H5E_TUI_ATTR_ERR, L"指定的 ffmpeg 不存在（清空可改回 PATH 搜索）");
            t->focus = 2;
            return false;
        }
        h5e_tui_field_set(fff, p); /* 顺手换成解析后的完整路径 */
        free(p);
    } else {
        wchar_t *p = h5e_find_ffmpeg(NULL);
        if (!p) {
            h5e_tui_set_status(t, H5E_TUI_ATTR_ERR,
                               L"PATH 里找不到 ffmpeg.exe，请填写 ffmpeg 路径（F2 浏览）");
            t->focus = 2;
            return false;
        }
        free(p);
    }

    h5e_tui_set_status(t, H5E_TUI_ATTR_OK, L"参数就绪，正在启动处理");
    return true;
}

/* ============================ TUI：目录浏览面板 ============================ */

typedef struct {
    wchar_t name[264];
    bool dir;
} h5e_tui_entry;

typedef struct {
    h5e_tui_entry *v;
    size_t n, cap;
} h5e_tui_list;

static bool h5e_tui_list_add(h5e_tui_list *l, const wchar_t *name, bool dir) {
    if (l->n == l->cap) {
        const size_t cap = l->cap ? l->cap * 2 : 64;
        h5e_tui_entry *p = (h5e_tui_entry *)realloc(l->v, cap * sizeof(h5e_tui_entry));
        if (!p) return false;
        l->v = p;
        l->cap = cap;
    }
    h5e_tui_entry *e = &l->v[l->n++];
    h5e_wcopy(e->name, sizeof e->name / sizeof e->name[0], name);
    e->dir = dir;
    return true;
}

static void h5e_tui_list_free(h5e_tui_list *l) {
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

/* 目录在前，同类按名称不区分大小写排序 */
static int h5e_tui_entry_cmp(const void *a, const void *b) {
    const h5e_tui_entry *x = (const h5e_tui_entry *)a, *y = (const h5e_tui_entry *)b;
    if (x->dir != y->dir) return x->dir ? -1 : 1;
    for (size_t i = 0;; i++) {
        const wchar_t ca = (wchar_t)towlower(x->name[i]);
        const wchar_t cb = (wchar_t)towlower(y->name[i]);
        if (ca != cb) return ca < cb ? -1 : 1;
        if (ca == L'\0') return 0;
    }
}

/* 列出目录：next == 0 只列子目录；否则只列扩展名命中的文件 */
static bool h5e_tui_list_dir(const wchar_t *dir, const wchar_t *const *exts, size_t next,
                             h5e_tui_list *l) {
    if (!dir || !*dir) return false;
    wchar_t pat[H5E_TUI_CAP + 4];
    const size_t cap = sizeof pat / sizeof pat[0];
    const size_t n = wcslen(dir);
    if (n + 4 > cap) return false;
    memcpy(pat, dir, n * sizeof(wchar_t));
    size_t k = n;
    if (dir[n - 1] != L'\\' && dir[n - 1] != L'/') pat[k++] = L'\\';
    pat[k++] = L'*';
    pat[k] = L'\0';

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ok = h5e_tui_list_add(l, fd.cFileName, true) && ok;
            continue;
        }
        if (next == 0) continue; /* 只要目录 */
        const wchar_t *ext = h5e_extension_of(fd.cFileName);
        bool hit = false;
        for (size_t i = 0; i < next && !hit; i++) hit = h5e_ext_is(ext, exts[i]);
        if (!hit) continue;
        ok = h5e_tui_list_add(l, fd.cFileName, false) && ok;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (ok && l->n > 1) qsort(l->v, l->n, sizeof(h5e_tui_entry), h5e_tui_entry_cmp);
    return ok;
}

/* 上一级目录；已在盘符根时返回 false */
static bool h5e_tui_parent_dir(wchar_t *dir) {
    size_t n = wcslen(dir);
    while (n > 0 && (dir[n - 1] == L'\\' || dir[n - 1] == L'/')) n--;
    if (n == 0) return false;
    size_t i = n;
    while (i > 0 && dir[i - 1] != L'\\' && dir[i - 1] != L'/') i--;
    if (i == 0) return false;
    dir[i - 1] = L'\0';
    n = wcslen(dir);
    if (n == 0) return false;
    if (dir[n - 1] == L':') { /* "C:" 这种盘符根要补回反斜杠 */
        if (n + 2 > H5E_TUI_CAP) return false;
        dir[n] = L'\\';
        dir[n + 1] = L'\0';
    }
    return true;
}

/* 进入子目录 */
static bool h5e_tui_enter_dir(wchar_t *dir, const wchar_t *name) {
    wchar_t *p = h5e_path_join(dir, name);
    if (!p) return false;
    const bool ok = wcslen(p) < H5E_TUI_CAP;
    if (ok) h5e_wcopy(dir, H5E_TUI_CAP, p);
    free(p);
    return ok;
}

/* 浏览起点：当前字段里的路径能用就从那里开始，否则从当前工作目录开始 */
static void h5e_tui_start_dir(const wchar_t *hint, wchar_t *dir, size_t cap) {
    h5e_tui_field tmp;
    memset(&tmp, 0, sizeof tmp);
    if (hint && *hint) {
        h5e_tui_field_set(&tmp, hint);
        h5e_tui_field_trim(&tmp);
    }
    if (tmp.len != 0) {
        const DWORD attr = GetFileAttributesW(tmp.text);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            if (attr & FILE_ATTRIBUTE_DIRECTORY) {
                h5e_wcopy(dir, cap, tmp.text);
                return;
            }
            size_t i = tmp.len;
            while (i > 0 && tmp.text[i - 1] != L'\\' && tmp.text[i - 1] != L'/') i--;
            if (i > 1) { /* 是文件：取它的所在目录 */
                tmp.text[i - 1] = L'\0';
                h5e_wcopy(dir, cap, tmp.text);
                return;
            }
        }
    }
    if (!GetCurrentDirectoryW((DWORD)cap, dir) || dir[0] == L'\0') h5e_wcopy(dir, cap, L"C:\\");
}

/* 画浏览面板：标题 + 当前目录 + 列表 + 快捷键 */
static void h5e_tui_render_browse(h5e_tui *t, const wchar_t *label, const wchar_t *dir,
                                  const h5e_tui_list *l, size_t sel, size_t top, bool pick_dir) {
    h5e_tui_screen *s = &t->scr;
    h5e_tui_screen_fill(s, H5E_TUI_ATTR_TEXT);
    if (s->w < 30 || s->h < 8) {
        h5e_tui_screen_text(s, 0, 0, L"窗口太小，请放大窗口后继续", H5E_TUI_ATTR_ERR, s->w);
        return;
    }
    h5e_tui_screen_bar(s, 0, H5E_TUI_ATTR_TITLE);
    h5e_tui_screen_text(s, 1, 0, label, H5E_TUI_ATTR_TITLE, s->w);
    h5e_tui_screen_text(s, 2, 1, L"当前目录：", H5E_TUI_ATTR_DIM, s->w);
    h5e_tui_screen_text(s, 12, 1, dir, H5E_TUI_ATTR_LABEL, s->w);
    for (int x = 0; x < s->w; x++) h5e_tui_put_wchar(s, x, 2, L'-', H5E_TUI_ATTR_RULE, s->w);

    const int rows = s->h - 5;
    if (l->n == 0) {
        h5e_tui_screen_text(s, 2, 3, L"（此目录下没有可选项，Backspace 回上级）", H5E_TUI_ATTR_DIM,
                            s->w);
    } else {
        for (int r = 0; r < rows; r++) {
            const size_t i = top + (size_t)r;
            if (i >= l->n) break;
            const int y = 3 + r;
            const bool cur = (i == sel);
            if (cur) h5e_tui_screen_bar(s, y, H5E_TUI_ATTR_FOCUS);
            const WORD attr =
                cur ? H5E_TUI_ATTR_FOCUS : (l->v[i].dir ? H5E_TUI_ATTR_LABEL : H5E_TUI_ATTR_TEXT);
            h5e_tui_screen_text(s, 2, y, cur ? L">" : L" ", attr, s->w);
            int x = 4;
            if (l->v[i].dir) {
                h5e_tui_screen_text(s, x, y, L"[目录] ", attr, s->w);
                x += 7;
            }
            h5e_tui_screen_text(s, x, y, l->v[i].name, attr, s->w);
        }
    }

    for (int x = 0; x < s->w; x++) h5e_tui_put_wchar(s, x, s->h - 2, L'-', H5E_TUI_ATTR_RULE, s->w);
    h5e_tui_screen_text(s, 2, s->h - 1,
                        pick_dir
                            ? L"Enter 选当前目录   空格/右键 进入目录   Backspace 上级   Esc 取消"
                            : L"Enter 选中   空格/右键 进入目录   Backspace 上级   Esc 取消",
                        H5E_TUI_ATTR_DIM, s->w);
}

/* 浏览面板主循环：pick_dir = true 时返回一个目录，否则返回一个文件路径 */
static bool h5e_tui_browse(h5e_tui *t, bool pick_dir, const wchar_t *label,
                           const wchar_t *const *exts, size_t next, wchar_t *out,
                           size_t out_cap) {
    wchar_t dir[H5E_TUI_CAP];
    h5e_tui_start_dir(t->field[t->focus].text, dir, H5E_TUI_CAP);

    h5e_tui_list l;
    memset(&l, 0, sizeof l);
    (void)h5e_tui_list_dir(dir, exts, next, &l);

    size_t sel = 0, top = 0;
    bool ok = false;
    for (;;) {
        if (!h5e_tui_begin_frame(t)) break;
        h5e_tui_render_browse(t, label, dir, &l, sel, top, pick_dir);
        t->caret = false;
        if (!h5e_tui_end_frame(t)) break;

        KEY_EVENT_RECORD k;
        const int ev = h5e_tui_read_event(&t->con, &k);
        if (ev == H5E_TUI_EV_FAIL) break;
        if (ev == H5E_TUI_EV_RESIZE) continue;

        const int rows = t->scr.h - 5;
        const int vk = k.wVirtualKeyCode;
        bool reload = false;

        if (vk == VK_ESCAPE) break;
        if (vk == VK_UP) {
            if (sel > 0) sel--;
        } else if (vk == VK_DOWN) {
            if (sel + 1 < l.n) sel++;
        } else if (vk == VK_PRIOR) {
            sel = (rows > 0 && sel > (size_t)rows) ? sel - (size_t)rows : 0;
        } else if (vk == VK_NEXT) {
            if (rows > 0) {
                sel += (size_t)rows;
                if (sel >= l.n) sel = l.n ? l.n - 1 : 0;
            }
        } else if (vk == VK_HOME) {
            sel = 0;
        } else if (vk == VK_END) {
            sel = l.n ? l.n - 1 : 0;
        } else if (vk == VK_BACK) {
            if (h5e_tui_parent_dir(dir)) {
                reload = true;
                sel = 0;
                top = 0;
            }
        } else if (vk == VK_SPACE || vk == VK_RIGHT) {
            if (sel < l.n && l.v[sel].dir && h5e_tui_enter_dir(dir, l.v[sel].name)) {
                reload = true;
                sel = 0;
                top = 0;
            }
        } else if (vk == VK_RETURN) {
            if (pick_dir) {
                h5e_wcopy(out, out_cap, dir);
                ok = true;
                break;
            }
            if (sel < l.n) {
                if (l.v[sel].dir) {
                    if (h5e_tui_enter_dir(dir, l.v[sel].name)) {
                        reload = true;
                        sel = 0;
                        top = 0;
                    }
                } else {
                    wchar_t *full = h5e_path_join(dir, l.v[sel].name);
                    if (full) {
                        h5e_wcopy(out, out_cap, full);
                        free(full);
                        ok = true;
                        break;
                    }
                }
            }
        }

        if (reload) {
            l.n = 0;
            (void)h5e_tui_list_dir(dir, exts, next, &l);
        }
        if (rows > 0) { /* 让选中项始终落在可视区间内 */
            if (sel < top) top = sel;
            if (sel >= top + (size_t)rows) top = sel - (size_t)rows + 1;
        }
    }
    h5e_tui_list_free(&l);
    return ok;
}

/* ============================ TUI：主循环与退路 ============================ */

/* 读一行 UTF-8 输入（stdin 被重定向时的退路） */
static bool h5e_tui_read_line(wchar_t *buf, size_t cap) {
    char tmp[4096];
    if (!buf || cap < 2) return false;
    buf[0] = L'\0';
    if (!fgets(tmp, sizeof tmp, stdin)) return false;
    size_t n = strlen(tmp);
    while (n > 0 && (tmp[n - 1] == '\n' || tmp[n - 1] == '\r')) tmp[--n] = '\0';
    if (n == 0) return true;
    const int w = MultiByteToWideChar(CP_UTF8, 0, tmp, (int)n, buf, (int)cap - 1);
    buf[(w > 0 && (size_t)w < cap) ? (size_t)w : 0] = L'\0';
    return true;
}

/* 控制台不支持 TUI（stdin 被重定向）时：逐行问答，脚本里也能用 */
static bool h5e_tui_prompt(h5e_tui_result *res) {
    h5e_tui t;
    memset(&t, 0, sizeof t);
    fprintf(stderr, "（控制台不支持 TUI 输入，改用逐行输入；输入文件直接回车则退出）\n");
    for (;;) {
        fprintf(stderr, "输入文件（.ts / .mp4）: ");
        if (!h5e_tui_read_line(t.field[0].text, H5E_TUI_CAP)) return false;
        t.field[0].len = t.field[0].cur = wcslen(t.field[0].text);
        h5e_tui_field_trim(&t.field[0]);
        if (t.field[0].len == 0) return false;

        fprintf(stderr, "输出文件（回车自动生成）: ");
        if (!h5e_tui_read_line(t.field[1].text, H5E_TUI_CAP)) return false;
        t.field[1].len = t.field[1].cur = wcslen(t.field[1].text);

        fprintf(stderr, "ffmpeg 路径（回车自动搜索 PATH）: ");
        if (!h5e_tui_read_line(t.field[2].text, H5E_TUI_CAP)) return false;
        t.field[2].len = t.field[2].cur = wcslen(t.field[2].text);

        if (h5e_tui_validate(&t)) {
            h5e_wcopy(res->input, H5E_TUI_CAP, t.field[0].text);
            h5e_wcopy(res->output, H5E_TUI_CAP, t.field[1].text);
            h5e_wcopy(res->ffmpeg, H5E_TUI_CAP, t.field[2].text);
            return true;
        }
        char *err = h5e_utf8_from_wide(t.status);
        fprintf(stderr, "错误：%s\n", err ? err : "?");
        free(err);
        memset(&t.field, 0, sizeof t.field); /* 重新填一轮 */
    }
}

/* 无参数启动的入口：成功返回 true，res 里是三项参数；用户取消返回 false */
static bool h5e_tui_collect(h5e_tui_result *res) {
    if (!res) return false;
    h5e_tui t;
    memset(&t, 0, sizeof t);

    if (!h5e_tui_console_open(&t.con)) {
        h5e_tui_console_close(&t.con);
        h5e_tui_screen_free(&t.scr);
        return h5e_tui_prompt(res);
    }

    h5e_tui_set_status(&t, H5E_TUI_ATTR_DIM, L"上下键 选择字段，F2 从磁盘挑选路径，Enter 开始处理");
    bool confirmed = false;
    for (;;) {
        if (!h5e_tui_begin_frame(&t)) break;
        h5e_tui_render(&t);
        if (!h5e_tui_end_frame(&t)) break;

        KEY_EVENT_RECORD k;
        const int ev = h5e_tui_read_event(&t.con, &k);
        if (ev == H5E_TUI_EV_FAIL) break;
        if (ev == H5E_TUI_EV_RESIZE) continue;

        h5e_tui_field *f = &t.field[t.focus];
        const int vk = k.wVirtualKeyCode;
        const bool shift = (k.dwControlKeyState & SHIFT_PRESSED) != 0;
        const bool ctrl = (k.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
        const bool alt = (k.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED)) != 0;

        if (vk == VK_ESCAPE || (ctrl && vk == 'C')) break; /* 取消 */
        if (vk == VK_UP) {
            t.focus = (t.focus + 2) % 3;
            continue;
        }
        if (vk == VK_DOWN) {
            t.focus = (t.focus + 1) % 3;
            continue;
        }
        if (vk == VK_TAB) {
            t.focus = shift ? (t.focus + 2) % 3 : (t.focus + 1) % 3;
            continue;
        }
        if (vk == VK_F2) {
            static const wchar_t *const in_exts[] = {L"ts", L"mp4"};
            static const wchar_t *const exe_exts[] = {L"exe"};
            wchar_t picked[H5E_TUI_CAP];
            picked[0] = L'\0';
            bool got;
            if (t.focus == 0) {
                got = h5e_tui_browse(&t, false, L"选择输入文件（.ts / .mp4）", in_exts, 2, picked,
                                     H5E_TUI_CAP);
            } else if (t.focus == 2) {
                got = h5e_tui_browse(&t, false, L"选择 ffmpeg.exe", exe_exts, 1, picked,
                                     H5E_TUI_CAP);
            } else {
                got = h5e_tui_browse(&t, true, L"选择输出目录（文件名自动沿用输入名 + _dec.mp4）",
                                     NULL, 0, picked, H5E_TUI_CAP);
            }
            if (got && picked[0]) {
                if (t.focus == 1) {
                    /* 选中目录：套上用输入文件名推导出的文件名 */
                    wchar_t name[H5E_TUI_CAP];
                    wchar_t *full = NULL;
                    if (h5e_tui_derive_output(t.field[0].text, name, H5E_TUI_CAP)) {
                        const wchar_t *base = name;
                        for (const wchar_t *q = name; *q; q++)
                            if (*q == L'\\' || *q == L'/') base = q + 1;
                        full = h5e_path_join(picked, base);
                    }
                    if (full) {
                        h5e_tui_field_set(&t.field[1], full);
                        free(full);
                    } else {
                        h5e_tui_field_set(&t.field[1], picked);
                    }
                } else {
                    h5e_tui_field_set(&t.field[t.focus], picked);
                    if (t.focus == 0 && t.field[1].len == 0) {
                        wchar_t derived[H5E_TUI_CAP];
                        if (h5e_tui_derive_output(picked, derived, H5E_TUI_CAP))
                            h5e_tui_field_set(&t.field[1], derived);
                    }
                }
                h5e_tui_set_status(&t, H5E_TUI_ATTR_DIM, L"已填入路径，Enter 开始处理");
            }
            continue;
        }
        if (vk == VK_RETURN) {
            if (!h5e_tui_validate(&t)) continue;
            confirmed = true;
            break;
        }
        if (vk == VK_LEFT) {
            if (f->cur > 0) f->cur--;
            continue;
        }
        if (vk == VK_RIGHT) {
            if (f->cur < f->len) f->cur++;
            continue;
        }
        if (vk == VK_HOME) {
            f->cur = 0;
            continue;
        }
        if (vk == VK_END) {
            f->cur = f->len;
            continue;
        }
        if (vk == VK_DELETE) {
            h5e_tui_field_delete(f);
            continue;
        }
        if (vk == VK_BACK) {
            h5e_tui_field_backspace(f);
            continue;
        }
        if (k.uChar.UnicodeChar >= 0x20 && !ctrl && !alt) {
            h5e_tui_field_insert(f, k.uChar.UnicodeChar);
            if (t.status_attr == H5E_TUI_ATTR_ERR) h5e_tui_set_status(&t, H5E_TUI_ATTR_DIM, L"");
            continue;
        }
    }

    h5e_tui_console_close(&t.con);
    h5e_tui_screen_free(&t.scr);
    if (!confirmed) return false;
    h5e_wcopy(res->input, H5E_TUI_CAP, t.field[0].text);
    h5e_wcopy(res->output, H5E_TUI_CAP, t.field[1].text);
    h5e_wcopy(res->ffmpeg, H5E_TUI_CAP, t.field[2].text);
    return true;
}

/* ============================== 命令行入口 ============================== */

int main(void) {
    /* 控制台切到 UTF-8：源码字串本身是 UTF-8，这样中文提示在任何语言的 Windows 下都不乱码 */
    SetConsoleOutputCP(CP_UTF8);

    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        fprintf(stderr, "错误：无法解析命令行\n");
        return H5E_RC_USAGE;
    }

    /* 无参数：进 TUI 收集参数；只要带了参数，就一律按原命令行用法执行，行为不变 */
    if (argc == 1) {
        h5e_tui_result res;
        memset(&res, 0, sizeof res);
        if (!h5e_tui_collect(&res)) {
            fprintf(stderr, "已取消\n");
            LocalFree(argv);
            return H5E_RC_OK;
        }
        h5e_msg_path("输入文件：", res.input);
        h5e_msg_path("输出文件：", res.output);
        if (res.ffmpeg[0]) h5e_msg_path("ffmpeg  ：", res.ffmpeg);
        const int rc = h5e_pipeline(res.input, res.output, res.ffmpeg[0] ? res.ffmpeg : NULL);
        LocalFree(argv);
        return rc;
    }

    if (argc < 3) {
        fprintf(stderr,
                "cctv_h5e_decrypt（MP4 流水线版）—— 输入 -> 分片 MP4 -> 解密 -> MP4\n"
                "  %s\n"
                "用法: dec_tui.exe <输入.ts|输入.mp4> <输出.mp4> [--ffmpeg <ffmpeg路径>]\n"
                "      dec_tui.exe（不带任何参数：进入 TUI 界面填写参数）\n"
                "说明: 视频 PID 固定使用默认值 0x%X（--pid 已废弃）；路径可含空格与中文\n",
                H5E_VERSION, H5E_DEFAULT_VIDEO_PID);
        LocalFree(argv);
        return H5E_RC_USAGE;
    }

    const wchar_t *ffmpeg_arg = NULL;
    for (int i = 3; i < argc; i++) {
        if (wcscmp(argv[i], L"--ffmpeg") == 0 && i + 1 < argc) {
            ffmpeg_arg = argv[++i];
            continue;
        }
        if (wcscmp(argv[i], L"--pid") == 0) {
            /* 已废弃：值直接丢弃，始终用默认 0x100（中间文件只有一条视频轨，pid 已无过滤意义） */
            char *u = h5e_utf8_from_wide(argv[i]);
            fprintf(stderr, "警告：%s 已废弃并被忽略，视频 PID 固定为 0x%X\n", u ? u : "--pid",
                    H5E_DEFAULT_VIDEO_PID);
            free(u);
            if (i + 1 < argc) ++i;
            continue;
        }
        {
            char *u = h5e_utf8_from_wide(argv[i]);
            fprintf(stderr, "错误：未知参数 %s\n", u ? u : "?");
            free(u);
        }
        LocalFree(argv);
        return H5E_RC_USAGE;
    }

    const int rc = h5e_pipeline(argv[1], argv[2], ffmpeg_arg);
    LocalFree(argv);
    return rc;
}

#endif /* _WIN32 */
