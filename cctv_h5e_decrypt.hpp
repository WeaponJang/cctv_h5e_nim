// =============================================================================
// cctv_h5e_decrypt.hpp
// Single-header pure C++ decrypt for CCTV hls_h5e (new-mode) MPEG-TS
// =============================================================================
//
// Features:
//   - Closed-form type5 stride F5 and type1 stride F1 (no lookup tables)
//   - Type1 G transform with multi-header flip mask (01a8xx / 61exxx)
//   - TEA-16 for type5; classic mode fallback before type25
//   - EPB (00 00 03) grid alignment + 03 drop (matches official worker)
//   - MPEG-TS PES rebuild with adaptation-field stuffing for length shrink
//
// No WASM, no VMP bytecode, no network.
//
// C++ usage:
//   #include "cctv_h5e_decrypt.hpp"
//   std::vector<uint8_t> out = cctv_h5e::decrypt_ts_default(data, len);
//
// CLI (one translation unit):
//   Windows (GCC, 宽字符入口): g++ -std=c++20 -O2 -municode -o dec.exe cctv_h5e_decrypt.cpp
//   Linux/macOS (窄入口 UTF-8): c++ -std=c++20 -O2 -o dec cctv_h5e_decrypt.cpp
//   只有定义 CCTV_H5E_CLI 时下面的 main 才会编入；它与驱动文件 cctv_h5e_decrypt.cpp
//   里的 main 二选一，不要同时启用。
//
// Research / reverse-engineering documentation. Use at your own risk.
// =============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <utility>
#include <tuple>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace cctv_h5e {

// ===== TEA / classic / type5 (EPB-aware) =====
// Standard TEA-16, little-endian 32-bit words, delta = 0x9E3779B9.
// Matches src/cctv_h5e_pure.py tea_encrypt_block / tea_decrypt_block.

inline void tea_encrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    std::memcpy(&v0, in, 4);
    std::memcpy(&v1, in + 4, 4);
    std::memcpy(&k0, key, 4);
    std::memcpy(&k1, key + 4, 4);
    std::memcpy(&k2, key + 8, 4);
    std::memcpy(&k3, key + 12, 4);
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 16; i++) {
        sum += delta;
        v0 += (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        v1 += (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
    }
    std::memcpy(out, &v0, 4);
    std::memcpy(out + 4, &v1, 4);
}

inline void tea_decrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    std::memcpy(&v0, in, 4);
    std::memcpy(&v1, in + 4, 4);
    std::memcpy(&k0, key, 4);
    std::memcpy(&k1, key + 4, 4);
    std::memcpy(&k2, key + 8, 4);
    std::memcpy(&k3, key + 12, 4);
    const uint32_t delta = 0x9E3779B9u;
    uint32_t sum = delta * 16u;
    for (int i = 0; i < 16; i++) {
        v1 -= (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
        v0 -= (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        sum -= delta;
    }
    std::memcpy(out, &v0, 4);
    std::memcpy(out + 4, &v1, 4);
}

// Classic layout (no type25): key@16, start=32, stride=80.
// Superseded by decrypt_classic_grid (EPB-aware, official-oracle verified);
// kept only as the plain-EBSP reference form.
inline void decrypt_classic(uint8_t* nal, size_t len) {
    if (len < 40) return;
    const uint8_t* key = nal + 16;
    for (size_t j = 0; 32 + j * 80 + 8 <= len; j++) {
        size_t o = 32 + j * 80;
        tea_decrypt_block(nal + o, nal + o, key);
    }
}

// Worker grid entry requires this many bytes remaining at a cell start.
// type1 rewrites 4 bytes and type5 rewrites 8, yet both stop at the same margin.
inline constexpr size_t kGridTailGuard = 17;

// RBSP→EBSP position map (EPB 0x03 skipped). Worker indexes key bytes and grid
// cells on RBSP, so a cell/key window that straddles an EPB must read through
// this map instead of raw EBSP offsets.
inline void build_rbsp_map(const uint8_t* nal, size_t len, std::vector<size_t>& r2e) {
    r2e.clear();
    r2e.reserve(len);
    for (size_t i = 0; i < len; ) {
        if (i + 2 < len && nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            r2e.push_back(i);
            r2e.push_back(i + 1);
            i += 3;
        } else {
            r2e.push_back(i);
            i++;
        }
    }
}

// Collect EPB positions (start of 00 00 03).
inline void collect_epb_positions(const uint8_t* nal, size_t len,
                                  std::vector<size_t>& epbs) {
    epbs.clear();
    if (!nal || len < 3) return;
    for (size_t i = 0; i + 2 < len; i++) {
        if (nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) epbs.push_back(i);
    }
}

// Drop the 0x03 at each recorded EPB position (from the end). Returns new length.
// The worker drops by pre-decrypt position: a cell that rewrote the leading
// 00 00 still gets its third byte removed, so `require_intact=false` matches it.
// `require_intact=true` stays available for the plain-EBSP reference path; it
// leaves the byte in place when a cell rewrote the 00 00 prefix.
inline size_t drop_epb_03(uint8_t* nal, size_t len, const std::vector<size_t>& epbs,
                          bool require_intact = true) {
    if (!nal) return len;
    size_t nlen = len;
    for (auto it = epbs.rbegin(); it != epbs.rend(); ++it) {
        size_t e = *it;
        if (e + 2 >= nlen) continue;
        if (require_intact && !(nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3)) continue;
        std::memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
        nlen--;
    }
    return nlen;
}

// Type5 new-mode: key@5, start=64, stride S, EPB-aware (same as type1).
// Worker grid guard needs 17 bytes at logical cell start; TEA only writes 8.
// Cells are indexed on RBSP length via r2e (skip EPB 0x03), matching worker:
// a cell that straddles an EPB must read its 8 ciphertext bytes from the
// EBSP positions. Returns new NAL length after optional EPB 03 drop.
inline size_t decrypt_type5_new(uint8_t* nal, size_t len, uint32_t stride) {
    if (!nal || len < 21 || stride < 8) return len;
    std::vector<size_t> epbs;
    std::vector<size_t> r2e;
    collect_epb_positions(nal, len, epbs);
    build_rbsp_map(nal, len, r2e);
    const size_t rbsp_len = r2e.size();
    if (rbsp_len < 21) return len;
    // TEA key lives at RBSP[5:21]; an EPB inside that window shifts the raw
    // EBSP bytes and would corrupt every cell (CCTVVideoDownloader#115).
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[r2e[5 + b]];
    uint8_t tmp[8];
    bool anyCell = false;
    for (size_t k = 0;; k++) {
        size_t o = 64 + k * (size_t)stride;
        if (o + kGridTailGuard > rbsp_len || o + 8 > rbsp_len) break;
        for (size_t b = 0; b < 8; b++) tmp[b] = nal[r2e[o + b]];
        tea_decrypt_block(tmp, tmp, key);
        for (size_t b = 0; b < 8; b++) nal[r2e[o + b]] = tmp[b];
        anyCell = true;
    }
    // EPB drop belongs to grid handling: a NAL too short for any cell is passed
    // through untouched (worker leaves sub-grid type1/type5 as-is).
    if (epbs.empty() || !anyCell) return len;
    return drop_epb_03(nal, len, epbs, false);
}

inline bool is_type25_enable(const uint8_t* nal, size_t len) {
    return len >= 4 && (nal[0] & 0x1f) == 25 && nal[2] == 0x01 && nal[3] == 0x09;
}

// ===== F5 / F1 stride =====
inline constexpr uint16_t kType5F5Base[6] = {160, 192, 224, 256, 288, 320};

// key16: 16-byte TEA key at nal+5 (only first 6 bytes used for F5).
inline uint32_t type5_stride_f5(const uint8_t* key16) {
    uint32_t le = (uint32_t)key16[0]
                | ((uint32_t)key16[1] << 8)
                | ((uint32_t)key16[2] << 16)
                | ((uint32_t)key16[3] << 24);
    unsigned idx = (unsigned)(le % 6u);
    return (uint32_t)kType5F5Base[idx] | (uint32_t)key16[idx];
}

// Convenience: NAL with header+RBSP, needs len >= 11 (pref >= 21).
inline uint32_t type5_stride_from_nal(const uint8_t* nal, size_t len) {
    if (!nal || len < 21) return 0;
    // key[0..5] = RBSP[5..10] (TEA key head); EPB 0x03 is not part of RBSP.
    std::vector<size_t> r2e;
    build_rbsp_map(nal, len, r2e);
    if (r2e.size() < 11) return 0;
    uint8_t key[6];
    for (size_t b = 0; b < 6; b++) key[b] = nal[r2e[5 + b]];
    return type5_stride_f5(key);
}

// Type1 F1: same BASE/select as F5, key = RBSP[1..6].
inline uint32_t type1_stride_f1(const uint8_t* nal, size_t len) {
    if (!nal || len < 7) return 0;
    std::vector<size_t> r2e;
    build_rbsp_map(nal, len, r2e);
    if (r2e.size() < 7) return 0;
    uint8_t key[6];
    for (size_t b = 0; b < 6; b++) key[b] = nal[r2e[1 + b]];
    return type5_stride_f5(key);
}

// ===== Type1 G + EPB helpers =====
inline int type1_fbit(uint32_t W) {
    const int w0  = (W >> 0)  & 1;
    const int w8  = (W >> 8)  & 1;
    const int w15 = (W >> 15) & 1;
    const int w19 = (W >> 19) & 1;
    const int w25 = (W >> 25) & 1;
    const int w30 = (W >> 30) & 1;
    const int w31 = (W >> 31) & 1;
    const int t = w0 | w8;
    return (w31 ^ w15 ^ t
            ^ (w8 & w19)
            ^ (w25 & (w0 ^ w19))
            ^ (w0 & (1 ^ w8) & w30)
            ^ ((1 ^ w0) & w19 & w30)
            ^ (w25 & w30 & (w8 ^ w19))) & 1;
}

inline bool type1_is_B_step(int s) {
    return s == 2 || s == 8 || s == 9 || s == 10;
}

// Bitmask of steps to invert Fbit (bit s set => flip step s).
inline uint16_t type1_flip_mask_from_header(const uint8_t hdr[3]) {
    const uint8_t b0 = hdr[0], b1 = hdr[1], b2 = hdr[2];
    uint16_t m = 0;
    auto setb = [&](int s) { m = (uint16_t)(m | (uint16_t)(1u << s)); };
    if (b0 == 0x01 && b1 == 0xA8) {
        if ((b2 >> 7) & 1) setb(0);
        if ((b2 >> 6) & 1) setb(1);
        if (1 ^ ((b2 >> 5) & 1)) setb(2);
        if ((b2 >> 4) & 1) setb(3);
        if ((b2 >> 3) & 1) setb(4);
        if ((b2 >> 1) & 1) setb(6);
        if ((b2 >> 0) & 1) setb(7);
        setb(9);
        setb(12);
        return m;
    }
    if (b0 == 0x61) {
        if ((b2 >> 1) & 1) setb(0);
        if ((b2 >> 0) & 1) setb(1);
        if (1 ^ ((b2 >> 5) & 1)) setb(2);
        if ((b2 >> 3) & 1) setb(4);
        if ((b2 >> 2) & 1) setb(5);
        if ((b2 >> 1) & 1) setb(6);
        if ((b2 >> 0) & 1) setb(7);
        if ((b2 >> 3) & 1) setb(14);
        if ((b2 >> 2) & 1) setb(15);
        return m;
    }
    // Slice-header family: nal_type=1 and b1 high nibble 0x9, split by b1[2]
    // into two subfamilies (2026-09-05, legacy 2018 corpus guid ef2366a5…:
    // s13=b1[2] exact on 269/269 headers; 9a/9b subfamily rules EXACT on 104
    // consistent headers / all 16 steps):
    //   9c..9f (b1[2]=1): s2=b0[0]^b2[5], s9..s12/s14=b0[0], s13=1, s15=b1[0]
    //   9a/9b (b1[2]=0): s2=~b2[5],     s9..s12/s14=1,     s13=0, s15=b1[0]
    if ((b0 & 0x1f) == 1 && (b1 & 0xf0) == 0x90) {
        const int t = (b1 >> 2) & 1;
        if ((b2 >> 7) & 1) setb(0);
        if ((b2 >> 6) & 1) setb(1);
        int s2 = ((b0 >> 0) & 1) ^ ((b2 >> 5) & 1);
        if (!t) s2 = 1 ^ ((b2 >> 5) & 1);
        if (s2) setb(2);
        if ((b2 >> 4) & 1) setb(3);
        if ((b2 >> 3) & 1) setb(4);
        if ((b2 >> 2) & 1) setb(5);
        if ((b2 >> 1) & 1) setb(6);
        if ((b2 >> 0) & 1) setb(7);
        if (t) {
            if ((b0 >> 0) & 1) {
                setb(9); setb(10); setb(11); setb(12); setb(14);
            }
            setb(13);
        } else {
            setb(9); setb(10); setb(11); setb(12); setb(14);
        }
        if ((b1 >> 0) & 1) setb(15);
        return m;
    }
    // SD 450-tier family (2010 4:3 corpus, `41 88 b2`): b2[0..2] drive s7/s6/s5,
    // the 9/10/12 block is fixed and s14 stays clear. Fitted on b2=83/84/85;
    // the other b2 bits follow the same layout as the 0x61 family.
    if (b0 == 0x41 && b1 == 0x88) {
        if ((b2 >> 7) & 1) setb(0);
        if ((b2 >> 6) & 1) setb(1);
        if (1 ^ ((b2 >> 5) & 1)) setb(2);
        if ((b2 >> 4) & 1) setb(3);
        if ((b2 >> 3) & 1) setb(4);
        if ((b2 >> 2) & 1) setb(5);
        if ((b2 >> 1) & 1) setb(6);
        if ((b2 >> 0) & 1) setb(7);
        setb(9); setb(10); setb(12);
        if ((b1 >> 0) & 1) setb(15);
        return m;
    }
    // Unknown family: no flips (same as 61e020 core only).
    return 0;
}

inline uint16_t type1_G_flips(uint16_t X, uint16_t Y, uint16_t flip_mask) {
    uint32_t W = (uint32_t)X | ((uint32_t)Y << 16);
    uint16_t P1 = 0;
    for (int s = 0; s < 16; s++) {
        int fv = type1_fbit(W) ^ ((flip_mask >> s) & 1);
        int b = fv ^ (type1_is_B_step(s) ? 1 : 0);
        P1 = (uint16_t)(P1 | (b << (15 - s)));
        W = ((W << 1) | (uint32_t)b) & 0xFFFFFFFFu;
    }
    return P1;
}

inline uint16_t type1_G(uint16_t X, uint16_t Y) {
    // Header 61e020 / empty flip set.
    return type1_G_flips(X, Y, 0);
}

inline uint16_t type1_G_nal(uint16_t X, uint16_t Y, const uint8_t nal_hdr[3]) {
    return type1_G_flips(X, Y, type1_flip_mask_from_header(nal_hdr));
}

inline void type1_decrypt_block(uint8_t blk[4]) {
    const uint16_t X = (uint16_t)(blk[0] | (blk[1] << 8));
    const uint16_t Y = (uint16_t)(blk[2] | (blk[3] << 8));
    const uint16_t P1 = type1_G(X, Y);
    blk[0] = (uint8_t)(P1 & 0xFF);
    blk[1] = (uint8_t)((P1 >> 8) & 0xFF);
    blk[2] = (uint8_t)(X & 0xFF);
    blk[3] = (uint8_t)((X >> 8) & 0xFF);
}

inline void type1_decrypt_block_nal(uint8_t blk[4], const uint8_t nal_hdr[3]) {
    const uint16_t X = (uint16_t)(blk[0] | (blk[1] << 8));
    const uint16_t Y = (uint16_t)(blk[2] | (blk[3] << 8));
    const uint16_t P1 = type1_G_nal(X, Y, nal_hdr);
    blk[0] = (uint8_t)(P1 & 0xFF);
    blk[1] = (uint8_t)((P1 >> 8) & 0xFF);
    blk[2] = (uint8_t)(X & 0xFF);
    blk[3] = (uint8_t)((X >> 8) & 0xFF);
}

// Count EPBs with start index strictly before `o`.
inline size_t epb_adj_before(const std::vector<size_t>& epbs, size_t o) {
    size_t n = 0;
    for (size_t e : epbs)
        if (e < o) n++;
        else break;
    return n;
}

// Worker grid entry threshold for type1 NALs (classic and new-mode alike):
// shorter NALs pass through with no rewrite and no EPB drop.
inline constexpr size_t kType1MinLen = 129;

// Grid guard: require ``guard`` bytes remaining at RBSP cell start (default 17)
// even though only 4 bytes are rewritten. Cell bytes via RBSP→EBSP map
// (skip EPB 0x03); then drop still-intact 0x03. Returns new NAL length.
inline size_t decrypt_type1_new(uint8_t* nal, size_t len, uint32_t stride = 511,
                                size_t start = 64, size_t guard = kGridTailGuard) {
    if (!nal || stride < 4 || len < kType1MinLen) return len;
    const uint8_t hdr[3] = {nal[0], nal[1], nal[2]};
    std::vector<size_t> epbs;
    std::vector<size_t> r2e;
    collect_epb_positions(nal, len, epbs);
    build_rbsp_map(nal, len, r2e);
    const size_t rbsp_len = r2e.size();
    for (size_t k = 0;; k++) {
        size_t o = start + k * (size_t)stride;
        if (o + guard > rbsp_len || o + 4 > rbsp_len) break;
        uint8_t blk[4] = {nal[r2e[o]], nal[r2e[o + 1]], nal[r2e[o + 2]],
                          nal[r2e[o + 3]]};
        type1_decrypt_block_nal(blk, hdr);
        nal[r2e[o]] = blk[0];
        nal[r2e[o + 1]] = blk[1];
        nal[r2e[o + 2]] = blk[2];
        nal[r2e[o + 3]] = blk[3];
    }
    if (epbs.empty()) return len;
    return drop_epb_03(nal, len, epbs, false);
}

// Classic layout (type25 enable seen but 01 09 magic absent, e.g. legacy 2018
// streams): EPB-aware RBSP grid, start=32, stride=80, 8-byte TEA-16 cells,
// key @ RBSP[16:32]. Verified against official worker oracle (241/250 exact
// NALs on a legacy shard). Tail cell requires a full stride of RBSP remaining.
// Output length shrinks when still-intact EPB 0x03 bytes are dropped.
inline size_t decrypt_classic_grid(uint8_t* nal, size_t len) {
    if (!nal || len < kType1MinLen) return len;
    std::vector<size_t> epbs;
    std::vector<size_t> r2e;
    collect_epb_positions(nal, len, epbs);
    build_rbsp_map(nal, len, r2e);
    const size_t rbsp_len = r2e.size();
    if (rbsp_len < kType1MinLen) return len;
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[r2e[16 + b]];
    bool anyCell = false;
    for (size_t k = 0;; k++) {
        size_t o = 32 + k * 80;
        if (o + 80 > rbsp_len) break;
        uint8_t blk[8];
        for (size_t b = 0; b < 8; b++) blk[b] = nal[r2e[o + b]];
        tea_decrypt_block(blk, blk, key);
        for (size_t b = 0; b < 8; b++) nal[r2e[o + b]] = blk[b];
        anyCell = true;
    }
    // A NAL shorter than one classic cell (32 + 80) is passed through untouched;
    // dropping its EPBs would shorten it without decrypting anything.
    if (epbs.empty() || !anyCell) return len;
    return drop_epb_03(nal, len, epbs, false);
}

// ===== Session =====

// Session: type25 enables new-mode; strides F5/F1 closed form only.
struct Session {
    bool new_mode = false;
    // Player-layer gate (vhs_drm2 var d): type25 payload[0]==1 enables decryption
    // of following 1/5 NALs, otherwise they pass through untouched. Streams
    // without any type25 (e.g. plaintext fallback on the h5e path) stay intact.
    bool shouldDecrypt = false;
    size_t type1_start = 64;
    size_t type1_guard = kGridTailGuard;
    // Worker leaves type1 NALs shorter than this untouched (no grid, no EPB drop).
    size_t type1_min_len = 129;

    uint32_t resolve_type5_stride(const uint8_t* nal, size_t len) const {
        return type5_stride_from_nal(nal, len);
    }
    uint32_t resolve_type1_stride(const uint8_t* nal, size_t len) const {
        uint32_t s = type1_stride_f1(nal, len);
        return s ? s : 511u;
    }

    void on_nal(uint8_t* nal, size_t* io_len) {
        if (!nal || !io_len || *io_len < 1) return;
        size_t len = *io_len;
        const int ntype = nal[0] & 0x1f;
        if (ntype == 25) {
            shouldDecrypt = len >= 2 && nal[1] == 1;
            // Magic selects the cell layout and switches BOTH ways mid-stream
            // (legacy 2018 streams start with 01 06 classic, then switch to
            // 01 09 new-mode at the next shard):
            //   01 09 -> new-mode grid; 01 06 -> classic grid.
            if (len >= 4 && nal[2] == 0x01) {
                if (nal[3] == 0x09) new_mode = true;
                else if (nal[3] == 0x06) new_mode = false;
            }
            return;
        }
        if ((ntype != 1 && ntype != 5) || !shouldDecrypt) return;
        if (!new_mode) {
            *io_len = decrypt_classic_grid(nal, len);
            return;
        }
        if (ntype == 5) {
            uint32_t S = resolve_type5_stride(nal, len);
            if (S >= 8) *io_len = decrypt_type5_new(nal, len, S);
            return;
        }
        if (ntype == 1) {
            if (len < type1_min_len) return;
            uint32_t S = resolve_type1_stride(nal, len);
            *io_len = decrypt_type1_new(nal, len, S, type1_start, type1_guard);
        }
    }
    void on_nal(uint8_t* nal, size_t len) {
        size_t n = len;
        on_nal(nal, &n);
    }
    void reset() { new_mode = false; shouldDecrypt = false; }
};

// ===== MPEG-TS =====
// Expand AF stuffing on one TS packet; return bytes stolen from payload.
inline size_t expand_af_steal(uint8_t* data, size_t len, size_t pkt_off, size_t need) {
    if (!data || need == 0 || pkt_off + 188 > len) return 0;
    int afc = (data[pkt_off + 3] & 0x30) >> 4;
    if (afc == 1) {
        // payload only → introduce AF. af_len = need - 1 (see Python notes).
        if (need < 1) return 0;
        size_t af_len = need - 1;
        if (af_len > 182) af_len = 182;
        size_t steal = 1 + af_len;
        uint8_t old_payload[184];
        std::memcpy(old_payload, data + pkt_off + 4, 184);
        data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30);  // afc=3
        data[pkt_off + 4] = (uint8_t)af_len;
        if (af_len > 0) {
            data[pkt_off + 5] = 0x00;  // flags
            for (size_t i = 1; i < af_len; i++) data[pkt_off + 5 + i] = 0xFF;
        }
        size_t new_pl = 184 - steal;
        std::memcpy(data + pkt_off + 5 + af_len, old_payload, new_pl);
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
        std::memcpy(old_payload, data + pkt_off + pi, old_payload_len);
        // extend AF body with 0xFF
        for (size_t i = 0; i < add; i++) data[pkt_off + 5 + af_len + i] = 0xFF;
        data[pkt_off + 4] = (uint8_t)new_af_len;
        size_t new_pl = old_payload_len - add;
        std::memcpy(data + pkt_off + 5 + new_af_len, old_payload, new_pl);
        if (new_pl == 0)
            data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x20);  // afc=2
        else
            data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30);  // afc=3
        return add;
    }
    return 0;
}

// Decrypt all video NALs in a TS buffer in-place.
// Returns number of NALs passed through session.on_nal.
inline size_t decrypt_ts_inplace(uint8_t* data, size_t len, Session& session,
                                 uint16_t vpid = 0x100) {
    if (!data || len < 188) return 0;

    std::vector<uint8_t> pes;
    // (packet_off, payload_start_in_packet, payload_len)
    std::vector<std::tuple<size_t, size_t, size_t>> spans;
    size_t nal_count = 0;

    auto flush = [&]() {
        if (pes.empty()) return;

        size_t base_skip = 0;
        if (pes.size() >= 9 && pes[0] == 0 && pes[1] == 0 && pes[2] == 1) {
            base_skip = 9 + pes[8];
        }
        if (base_skip > pes.size()) {
            pes.clear();
            spans.clear();
            return;
        }

        std::vector<uint8_t> pes_hdr(pes.begin(), pes.begin() + (std::ptrdiff_t)base_skip);
        std::vector<uint8_t> es(pes.begin() + (std::ptrdiff_t)base_skip, pes.end());

        // Find NAL start codes in ES
        std::vector<std::pair<size_t, size_t>> starts;  // (pos, sc_len)
        size_t i = 0;
        while (i + 3 < es.size()) {
            if (i + 4 <= es.size() && es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 0 &&
                es[i + 3] == 1) {
                starts.emplace_back(i, 4);
                i += 4;
            } else if (es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 1) {
                starts.emplace_back(i, 3);
                i += 3;
            } else {
                i++;
            }
        }

        std::vector<uint8_t> new_es;
        new_es.reserve(es.size());
        size_t cursor = 0;
        for (size_t idx = 0; idx < starts.size(); idx++) {
            size_t pos = starts[idx].first;
            size_t sc = starts[idx].second;
            size_t end = (idx + 1 < starts.size()) ? starts[idx + 1].first : es.size();
            if (cursor < pos) new_es.insert(new_es.end(), es.begin() + (std::ptrdiff_t)cursor,
                                            es.begin() + (std::ptrdiff_t)pos);
            new_es.insert(new_es.end(), es.begin() + (std::ptrdiff_t)pos,
                          es.begin() + (std::ptrdiff_t)(pos + sc));
            if (pos + sc >= end) {
                cursor = end;
                continue;
            }
            size_t nal_len = end - (pos + sc);
            std::vector<uint8_t> nal(es.begin() + (std::ptrdiff_t)(pos + sc),
                                     es.begin() + (std::ptrdiff_t)end);
            size_t nlen = nal.size();
            session.on_nal(nal.data(), &nlen);
            nal_count++;
            new_es.insert(new_es.end(), nal.begin(), nal.begin() + (std::ptrdiff_t)nlen);
            cursor = end;
        }
        if (cursor < es.size())
            new_es.insert(new_es.end(), es.begin() + (std::ptrdiff_t)cursor, es.end());

        std::vector<uint8_t> new_pes = pes_hdr;
        new_pes.insert(new_pes.end(), new_es.begin(), new_es.end());

        size_t capacity = 0;
        for (auto& sp : spans) capacity += std::get<2>(sp);
        if (capacity > new_pes.size()) {
            size_t remaining = capacity - new_pes.size();
            for (auto it = spans.rbegin(); it != spans.rend() && remaining > 0; ++it) {
                size_t pkt_off = std::get<0>(*it);
                size_t got = expand_af_steal(data, len, pkt_off, remaining);
                remaining -= got;
            }
            // recompute spans after AF changes
            std::vector<std::tuple<size_t, size_t, size_t>> new_spans;
            for (auto& sp : spans) {
                size_t pkt_off = std::get<0>(sp);
                int afc = (data[pkt_off + 3] & 0x30) >> 4;
                if (afc == 0 || afc == 2) continue;
                size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[pkt_off + 4]);
                if (pi >= 188) continue;
                new_spans.emplace_back(pkt_off, pi, 188 - pi);
            }
            spans.swap(new_spans);
        }

        size_t off = 0;
        for (auto& sp : spans) {
            size_t pkt_off = std::get<0>(sp);
            size_t pi = std::get<1>(sp);
            size_t pl = std::get<2>(sp);
            size_t chunk = new_pes.size() - off;
            if (chunk > pl) chunk = pl;
            if (chunk > 0)
                std::memcpy(data + pkt_off + pi, new_pes.data() + off, chunk);
            if (chunk < pl) {
                // residual (should be rare if AF absorb worked)
                std::memset(data + pkt_off + pi + chunk, 0xFF, pl - chunk);
            }
            off += pl;
            if (off >= new_pes.size()) {
                // clear any further payloads already handled by AF shrink
            }
        }

        pes.clear();
        spans.clear();
    };

    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (data[off] != 0x47) continue;
        uint16_t pid =
            (uint16_t)(((data[off + 1] & 0x1f) << 8) | data[off + 2]);
        if (pid != vpid) continue;
        bool pusi = (data[off + 1] & 0x40) != 0;
        int afc = (data[off + 3] & 0x30) >> 4;
        if (afc == 0 || afc == 2) continue;
        size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[off + 4]);
        if (pi >= 188) continue;
        size_t payload_len = 188 - pi;
        if (pusi) flush();
        pes.insert(pes.end(), data + off + pi, data + off + 188);
        spans.emplace_back(off, pi, payload_len);
    }
    flush();
    return nal_count;
}

// Copy-based decrypt: returns plaintext TS.
inline std::vector<uint8_t> decrypt_ts(const uint8_t* data, size_t len,
                                       Session& session,
                                       uint16_t vpid = 0x100) {
    std::vector<uint8_t> out(data, data + len);
    decrypt_ts_inplace(out.data(), out.size(), session, vpid);
    return out;
}

// Convenience: fresh session with embedded tables (key05 + head12).
inline std::vector<uint8_t> decrypt_ts_default(const uint8_t* data, size_t len,
                                               uint16_t vpid = 0x100) {
    Session session;
    return decrypt_ts(data, len, session, vpid);
}


}  // namespace cctv_h5e

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cctv_h5e_session cctv_h5e_session;

cctv_h5e_session* cctv_h5e_session_create(void);
void cctv_h5e_session_destroy(cctv_h5e_session* s);
void cctv_h5e_session_reset(cctv_h5e_session* s);
int cctv_h5e_decrypt_nal(cctv_h5e_session* s, uint8_t* nal, size_t* io_nal_len);
int cctv_h5e_decrypt_ts(cctv_h5e_session* s, uint8_t* ts, size_t ts_len, uint16_t vpid);
int cctv_h5e_decrypt_ts_alloc(const uint8_t* ts_in, size_t ts_len,
                              uint8_t** out_ts, size_t* out_len, uint16_t vpid);
void cctv_h5e_free(void* p);
const char* cctv_h5e_version(void);

#ifdef __cplusplus
}
#endif

#if defined(CCTV_H5E_IMPLEMENTATION)

struct cctv_h5e_session {
    cctv_h5e::Session impl;
};

cctv_h5e_session* cctv_h5e_session_create(void) {
    return new cctv_h5e_session();
}
void cctv_h5e_session_destroy(cctv_h5e_session* s) { delete s; }
void cctv_h5e_session_reset(cctv_h5e_session* s) {
    if (s) s->impl.reset();
}
int cctv_h5e_decrypt_nal(cctv_h5e_session* s, uint8_t* nal, size_t* io_nal_len) {
    if (!s || !nal || !io_nal_len) return -1;
    s->impl.on_nal(nal, io_nal_len);
    return 0;
}
int cctv_h5e_decrypt_ts(cctv_h5e_session* s, uint8_t* ts, size_t ts_len, uint16_t vpid) {
    if (!s || !ts) return -1;
    return (int)cctv_h5e::decrypt_ts_inplace(ts, ts_len, s->impl, vpid);
}
int cctv_h5e_decrypt_ts_alloc(const uint8_t* ts_in, size_t ts_len,
                              uint8_t** out_ts, size_t* out_len, uint16_t vpid) {
    if (!ts_in || !out_ts || !out_len) return -1;
    auto v = cctv_h5e::decrypt_ts_default(ts_in, ts_len, vpid);
    *out_len = v.size();
    *out_ts = (uint8_t*)std::malloc(v.empty() ? 1 : v.size());
    if (!*out_ts) return -1;
    if (!v.empty()) std::memcpy(*out_ts, v.data(), v.size());
    return 0;
}
void cctv_h5e_free(void* p) { std::free(p); }
const char* cctv_h5e_version(void) {
    return "cctv_h5e pure F5/F1+EPB+AF 1.0 (2026-07-23)";
}

#endif

#if defined(CCTV_H5E_CLI)
// 与 cctv_h5e_decrypt.cpp 的入口保持同步（两边逐行一致，只差 static/匿名命名空间）：
// Windows 走 wmain + _wfopen + UTF-8 输出代码页与 ANSI，文件名与提示都不经 ACP 中转；
// 其他平台保留窄 main（路径按 UTF-8 字节处理）。
#include <chrono>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <sys/types.h>  // off_t
#  include <unistd.h>     // isatty
#endif

// 终端适配：只有 stderr 真的连着终端时才切 UTF-8 代码页并开启 ANSI 转义；
// 重定向到文件/管道时不换代码页、不插转义序列，输出保持纯 UTF-8 文本。
class H5eConsole {
public:
    H5eConsole() {
#if defined(_WIN32)
        HANDLE h = ::GetStdHandle(STD_ERROR_HANDLE);
        DWORD mode = 0;
        if (h && h != INVALID_HANDLE_VALUE && ::GetConsoleMode(h, &mode)) {
            is_tty_ = true;
            saved_cp_ = ::GetConsoleOutputCP();
            if (saved_cp_ != CP_UTF8) ::SetConsoleOutputCP(CP_UTF8);
            saved_mode_ = mode;
            vt_ = ::SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
            // 本进程独占这个控制台 => 是双击/快捷方式新开的窗口，退出后会立刻消失
            DWORD pids[2] = {0, 0};
            owns_console_ = ::GetConsoleProcessList(pids, 2) == 1;
        }
#else
        vt_ = ::isatty(::fileno(stderr)) != 0;
#endif
        if (std::getenv("H5E_NO_PAUSE") != nullptr) owns_console_ = false;  // 禁用退出暂停
        if (std::getenv("NO_COLOR") != nullptr) {
            vt_ = false;  // 遵守 NO_COLOR 约定
        } else if (const char* force = std::getenv("CLICOLOR_FORCE")) {
            if (*force && std::strcmp(force, "0") != 0) vt_ = true;  // 管道/CI 里强制上色
        }
    }
    ~H5eConsole() {
#if defined(_WIN32)
        if (is_tty_ && saved_cp_ && saved_cp_ != CP_UTF8)
            ::SetConsoleOutputCP(saved_cp_);
        if (is_tty_ && vt_) {
            HANDLE h = ::GetStdHandle(STD_ERROR_HANDLE);
            if (h && h != INVALID_HANDLE_VALUE) ::SetConsoleMode(h, saved_mode_);
        }
#endif
    }
    bool color() const { return vt_; }
    bool owns_console() const { return owns_console_; }

private:
#if defined(_WIN32)
    bool is_tty_ = false;
    DWORD saved_mode_ = 0;
    UINT saved_cp_ = 0;
#endif
    bool vt_ = false;
    bool owns_console_ = false;
};

// ANSI SGR 上色：未连终端时一律返回空串，调用点不用写分支
struct H5ePainter {
    bool on;
    const char* operator()(const char* sgr) const { return on ? sgr : ""; }
};

constexpr const char* h5e_sgr_plain = "";
constexpr const char* h5e_sgr_reset = "\x1b[0m";
constexpr const char* h5e_sgr_bold = "\x1b[1m";
constexpr const char* h5e_sgr_red = "\x1b[31m";
constexpr const char* h5e_sgr_yellow = "\x1b[33m";
constexpr const char* h5e_sgr_green = "\x1b[32m";
constexpr const char* h5e_sgr_dim = "\x1b[2m";

// 信息行统一格式：“2 空格 + 两个汉字的标签(4 列) + 3 空格 + 正文”，
// 标签固定两个汉字，所以 版本/用法/参数/示例/错误/警告/完成/提示 能纵向对齐。
static void h5e_note(const H5ePainter& paint, const char* sgr, const char* label,
                     const char* text) {
    std::fprintf(stderr, "  %s%s%s   %s\n", paint(sgr), label, paint(h5e_sgr_reset), text);
}

// 双击运行时 Windows 会为本进程新建一个控制台，程序一退出窗口就消失，用法和错误
// 根本来不及看。只有“自己独占控制台”时才停一下等回车；从终端、管道、计划任务
// 启动时（控制台里还有别的进程 / 根本没有控制台）不停，H5E_NO_PAUSE=1 可禁用。
struct H5ePauseOnExit {
    const H5eConsole& console;
    const H5ePainter& paint;
    ~H5ePauseOnExit() {
        if (!console.owns_console()) return;
        std::fprintf(stderr, "\n");
        h5e_note(paint, h5e_sgr_dim, "提示", "按回车键退出…");
        std::fflush(stderr);
        int c = 0;
        while ((c = std::getchar()) != '\n' && c != EOF) {
        }
    }
};

// 45,037,092 —— 字节数按千分位排版，长数字不再难读
static std::string h5e_group(uint64_t v) {
    const std::string s = std::to_string(v);
    std::string out;
    out.reserve(s.size() + s.size() / 3);
    for (size_t i = 0; i < s.size(); i++) {
        if (i && (s.size() - i) % 3 == 0) out += ',';
        out += s[i];
    }
    return out;
}

// 耗时：用整数毫秒拼成“0.47 秒”，不依赖浮点格式化（结果确定，也无浮点误差）
static std::string h5e_seconds(long long ms) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%lld.%02lld 秒", ms / 1000, ms % 1000 / 10);
    return buf;
}

// 路径类型：Windows 用宽字符串（原生 UTF-16），其他平台用字节串（UTF-8）。
// 这里刻意不用 <filesystem>：单是 path + file_size 就会把 locale/iostream 整套
// facet、异常运行时和 demangler 拉进静态链接，实测多出 880 KB（1.13 MB vs 0.25 MB），
// 而我们需要/只需要“拿着一份路径传给 _wfopen”。
#if defined(_WIN32)
using h5e_path = std::wstring;
#else
using h5e_path = std::string;
#endif

// path -> UTF-8 字节（宽字符直转，emoji 这类代理对也不会被截断）
static std::string h5e_path_utf8(const h5e_path& p) {
#if defined(_WIN32)
    if (p.empty()) return {};
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, p.c_str(), (int)p.size(),
                                           nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string s((size_t)need, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, p.c_str(), (int)p.size(), s.data(), need,
                          nullptr, nullptr);
    return s;
#else
    return p;
#endif
}

// Windows 用 _wfopen 直接给宽路径（绕开 ACP），其他平台用 fopen
static std::FILE* h5e_fopen(const h5e_path& p, bool for_write) {
#if defined(_WIN32)
    return ::_wfopen(p.c_str(), for_write ? L"wb" : L"rb");
#else
    return std::fopen(p.c_str(), for_write ? "wb" : "rb");
#endif
}

// ===== 64 位文件定位/取长 =====
// 旧实现用 fseek/ftell（Windows 的 long 只有 32 位），超过 2 GB 的输入连长度都
// 取不到；分块必须能按偏移随机定位，所以统一走 64 位接口。
static int64_t h5e_file_size(std::FILE* f) {
#if defined(_WIN32)
    if (::_fseeki64(f, 0, SEEK_END) != 0) return -1;
    const int64_t n = ::_ftelli64(f);
    if (::_fseeki64(f, 0, SEEK_SET) != 0) return -1;
    return n;
#else
    if (::fseeko(f, 0, SEEK_END) != 0) return -1;
    const int64_t n = (int64_t)::ftello(f);
    if (::fseeko(f, 0, SEEK_SET) != 0) return -1;
    return n;
#endif
}

static bool h5e_seek(std::FILE* f, int64_t off) {
#if defined(_WIN32)
    return ::_fseeki64(f, off, SEEK_SET) == 0;
#else
    return ::fseeko(f, (off_t)off, SEEK_SET) == 0;
#endif
}

// 分阶段输出：part 与目标同目录，最后的替换才是同卷 rename
static h5e_path h5e_part_path(const h5e_path& out) {
#if defined(_WIN32)
    return out + L".part";
#else
    return out + ".part";
#endif
}

static bool h5e_remove(const h5e_path& p) {
#if defined(_WIN32)
    return ::_wremove(p.c_str()) == 0;
#else
    return std::remove(p.c_str()) == 0;
#endif
}

// 原子替换：part 已经完整落盘（长度校验过）后才调用；失败时目标保持原样。
// rename 在同一卷内是原子的，而 part 就建在目标所在目录，天然满足同卷。
static bool h5e_replace(const h5e_path& part, const h5e_path& dst) {
#if defined(_WIN32)
    return ::MoveFileExW(part.c_str(), dst.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return std::rename(part.c_str(), dst.c_str()) == 0;
#endif
}

// ===== 分块解密 =====
// 阶段返回码：0 成功，负数是失败发生在哪一步（用来选提示文案）
enum {
    kH5eStageOk = 0,
    kH5eStageRead = -1,
    kH5eStageWrite = -2,
    kH5eStageDecrypt = -3,
};

struct H5eDecryptStats {
    uint64_t bytes = 0;    // 已写出的字节数
    uint64_t nals = 0;     // 交给解密器的 NAL 数
    uint64_t chunks = 0;   // 分块数
};

// 视频 PES 起点（PID 命中且 PUSI 置位）。分块只能切在这里：切在包中间或 PES
// 中间，解密器会拿到半截 PES，输出就和“整文件一次处理”不一致了。
// 顺序读一遍，索引只存 64 位偏移（每帧 8 字节），扫描缓冲固定 1.5 MB 左右。
static std::vector<int64_t> h5e_scan_pes_starts(std::FILE* f, uint16_t vpid, bool* read_ok) {
    constexpr size_t kBlock = 188 * 8192;  // 188 的整数倍，缓冲里始终是整包
    std::vector<int64_t> starts;
    std::vector<uint8_t> buf(kBlock);
    size_t have = 0;
    int64_t base = 0;  // buf[0] 在文件里的绝对偏移
    if (read_ok) *read_ok = true;
    for (;;) {
        const size_t got = std::fread(buf.data() + have, 1, kBlock - have, f);
        if (got == 0) {
            if (read_ok && std::ferror(f)) *read_ok = false;
            break;
        }
        have += got;
        const size_t pkts = have / 188;
        for (size_t i = 0; i < pkts; i++) {
            const uint8_t* p = buf.data() + i * 188;
            if (p[0] != 0x47) continue;                        // 失步包直接跳过
            if ((((p[1] & 0x1F) << 8) | p[2]) != vpid) continue;
            if ((p[1] & 0x40) == 0) continue;                  // 不是 PES 起点
            starts.push_back(base + (int64_t)(i * 188));
        }
        const size_t used = pkts * 188;
        have -= used;
        std::memmove(buf.data(), buf.data() + used, have);
        base += (int64_t)used;
    }
    return starts;  // 文件尾不足 188 字节的残包凑不成包，只能丢弃
}

// 按 PES 边界分块解密：每块“读入 → 原地解密 → 追加写 part”，
// Session 全程复用（type25 决定 new_mode，丢掉它后面所有块都解不动）。
// 内存 = 单块（约 64 MB，遇到跨块的超长 PES 会更大）+ 分块索引。
static int h5e_decrypt_stream(std::FILE* in, std::FILE* out, int64_t total,
                              const std::vector<int64_t>& pes_starts, uint16_t vpid,
                              H5eDecryptStats* st) {
    constexpr int64_t kChunkBytes = 64LL << 20;
    cctv_h5e_session* s = cctv_h5e_session_create();
    if (!s) return kH5eStageDecrypt;
    std::vector<uint8_t> chunk;
    chunk.reserve((size_t)kChunkBytes);
    int stage = kH5eStageOk;
    size_t next = 0;    // pes_starts 游标，只增不减
    int64_t begin = 0;  // 本块起点：首块 0，之后都是 PES 起点
    while (begin < total) {
        const int64_t want = begin + kChunkBytes;
        while (next < pes_starts.size() && pes_starts[next] < want) next++;
        const int64_t end = next < pes_starts.size() ? pes_starts[next] : total;
        const size_t len = (size_t)(end - begin);
        chunk.resize(len);
        if (!h5e_seek(in, begin) || std::fread(chunk.data(), 1, len, in) != len) {
            stage = kH5eStageRead;
            break;
        }
        // 原地解密：长度由 AF 填充吸收，块内字节数不变
        const int nals = cctv_h5e_decrypt_ts(s, chunk.data(), len, vpid);
        if (nals < 0) {
            stage = kH5eStageDecrypt;
            break;
        }
        if (std::fwrite(chunk.data(), 1, len, out) != len) {
            stage = kH5eStageWrite;
            break;
        }
        if (st) {
            st->bytes += len;
            st->nals += (uint64_t)nals;
            st->chunks++;
        }
        begin = end;
    }
    cctv_h5e_session_destroy(s);
    return stage;
}

// 没有任何视频 PES：解密器不会改动一个字节，按固定块原样搬运即可——
// 结果与旧行为（输出等于输入）一致，又不会把整个文件读进内存。
static int h5e_copy_stream(std::FILE* in, std::FILE* out, int64_t total, H5eDecryptStats* st) {
    constexpr int64_t kBlock = 1LL << 20;
    std::vector<uint8_t> buf((size_t)kBlock);
    if (!h5e_seek(in, 0)) return kH5eStageRead;
    for (int64_t done = 0; done < total;) {
        const int64_t left = total - done;
        const size_t want = (size_t)(left < kBlock ? left : kBlock);
        if (std::fread(buf.data(), 1, want, in) != want) return kH5eStageRead;
        if (std::fwrite(buf.data(), 1, want, out) != want) return kH5eStageWrite;
        done += (int64_t)want;
        if (st) {
            st->bytes += want;
            st->chunks++;
        }
    }
    return kH5eStageOk;
}

#if defined(_WIN32)
int wmain(int argc, wchar_t** argv)
#else
int main(int argc, char** argv)
#endif
{
    const H5eConsole console;                // UTF-8 代码页 + ANSI，仅终端下生效
    const H5ePainter paint{console.color()};
    const H5ePauseOnExit pause_on_exit{console, paint};  // 双击时窗口不一闪而过
    const auto t0 = std::chrono::steady_clock::now();
    const char* ver = cctv_h5e_version();
    const std::string prog = h5e_path_utf8(argv[0]);

    if (argc < 3) {
        h5e_note(paint, h5e_sgr_red, "错误",
                 "参数不足：至少需要 <输入文件.ts> 与 <输出文件.ts> 两个参数");
        std::fprintf(stderr, "\n");
        std::fprintf(stderr, "  %scctv_h5e_decrypt · 纯 C++ hls_h5e TS 解密工具%s\n",
                     paint(h5e_sgr_bold), paint(h5e_sgr_reset));
        std::fprintf(stderr,
                     "  ────────────────────────────────────────────────\n");
        h5e_note(paint, h5e_sgr_plain, "版本", ver);
        h5e_note(paint, h5e_sgr_plain, "用法",
                 (prog + " <输入文件.ts> <输出文件.ts> [--pid 0x100]").c_str());
        h5e_note(paint, h5e_sgr_plain, "参数", "--pid <十六进制>   指定视频 PID，默认 0x100");
        h5e_note(paint, h5e_sgr_plain, "示例", "dec.exe 加密.ts 解密.ts");
        h5e_note(paint, h5e_sgr_plain, "    ", "dec.exe 加密.ts 解密.ts --pid 0x1fff");
        return 1;
    }
    uint16_t vpid = 0x100;
    for (int i = 3; i < argc; i++) {
        if (h5e_path_utf8(argv[i]) != "--pid") continue;
        if (i + 1 >= argc) {
            h5e_note(paint, h5e_sgr_yellow, "警告", "--pid 后缺少取值，已回退到默认 0x100");
            break;
        }
        const std::string val = h5e_path_utf8(argv[++i]);
        char* end = nullptr;
        const unsigned long n = std::strtoul(val.c_str(), &end, 0);
        if (end == val.c_str() || *end != '\0') {
            h5e_note(paint, h5e_sgr_yellow, "警告",
                     ("--pid 取值 \"" + val + "\" 无法解析，已回退到默认 0x100").c_str());
            continue;
        }
        vpid = (uint16_t)n;
        if (n > 0x1FFFu) {
            char msg[160];
            std::snprintf(msg, sizeof msg,
                          "--pid 0x%lX 超出 13 位 PID 范围（0x0000-0x1FFF），不会命中任何分包", n);
            h5e_note(paint, h5e_sgr_yellow, "警告", msg);
        }
    }
    const h5e_path in_path(argv[1]);
    const h5e_path out_path(argv[2]);
    const h5e_path part_path = h5e_part_path(out_path);

    std::FILE* fin = h5e_fopen(in_path, false);
    const int64_t in_size = fin ? h5e_file_size(fin) : -1;
    if (!fin || in_size < 0) {
        if (fin) std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("无法读取输入文件：" + h5e_path_utf8(in_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认文件存在、不是目录，且当前用户有读取权限");
        return 1;
    }
    if (in_size == 0) {
        std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("输入文件为空：" + h5e_path_utf8(in_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认拿到的是完整的加密 TS，而不是还没下载完的空壳");
        return 1;
    }

    // 先扫一遍视频 PES 起点当分块边界（顺序读，只存偏移）
    bool scan_ok = true;
    const std::vector<int64_t> pes_starts = h5e_scan_pes_starts(fin, vpid, &scan_ok);
    if (!scan_ok) {
        std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("读取输入文件失败：" + h5e_path_utf8(in_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认文件没有被截断或占用，磁盘可以正常读取");
        return 1;
    }

    // 全程只写 part：目标文件在成功前一个字节都不动
    std::FILE* fpart = h5e_fopen(part_path, true);
    if (!fpart) {
        std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("无法写入输出文件：" + h5e_path_utf8(part_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认目标目录存在、不是只读，且磁盘空间充足");
        return 1;
    }

    H5eDecryptStats stats;
    int stage = pes_starts.empty()
                    ? h5e_copy_stream(fin, fpart, in_size, &stats)
                    : h5e_decrypt_stream(fin, fpart, in_size, pes_starts, vpid, &stats);
    // close 的返回值也要看——缓冲落盘失败只会在这里暴露
    const bool flushed = (std::fclose(fpart) == 0);
    std::fclose(fin);  // 先放开输入：<输入> 与 <输出> 是同一个文件时才能替掉
    if (stage == kH5eStageOk && !flushed) stage = kH5eStageWrite;

    if (stage != kH5eStageOk) {
        h5e_remove(part_path);
        if (stage == kH5eStageRead) {
            h5e_note(paint, h5e_sgr_red, "错误",
                     ("读取输入文件失败：" + h5e_path_utf8(in_path)).c_str());
            h5e_note(paint, h5e_sgr_dim, "提示", "请确认文件没有被截断或占用，磁盘可以正常读取");
        } else if (stage == kH5eStageWrite) {
            h5e_note(paint, h5e_sgr_red, "错误",
                     ("无法写入输出文件：" + h5e_path_utf8(part_path)).c_str());
            h5e_note(paint, h5e_sgr_dim, "提示", "临时文件已删除，目标文件未被改动；请检查磁盘空间与目录权限");
        } else {
            h5e_note(paint, h5e_sgr_red, "错误", "解密失败（原生 h5e 返回异常）");
            h5e_note(paint, h5e_sgr_dim, "提示", "请确认输入确实是 hls_h5e 加密的 TS，且 --pid 指向视频流");
        }
        return 1;
    }
    if (stats.bytes != (uint64_t)in_size) {
        h5e_remove(part_path);
        char msg[128];
        std::snprintf(msg, sizeof msg, "解密结果长度异常（%llu / %llu 字节）",
                      (unsigned long long)stats.bytes, (unsigned long long)in_size);
        h5e_note(paint, h5e_sgr_red, "错误", msg);
        h5e_note(paint, h5e_sgr_dim, "提示", "临时文件已删除，目标文件未被改动");
        return 1;
    }

    // 只有到这里才动目标文件：同目录 rename，失败时目标保持原样
    if (!h5e_replace(part_path, out_path)) {
        std::string msg = "无法替换输出文件";
#if defined(_WIN32)
        msg += "（Win32 错误 " + std::to_string((unsigned long)::GetLastError()) + "）";
#endif
        msg += "：";
        msg += h5e_path_utf8(out_path);
        h5e_remove(part_path);
        h5e_note(paint, h5e_sgr_red, "错误", msg.c_str());
        h5e_note(paint, h5e_sgr_dim, "提示",
                 "临时文件已删除，目标文件未被改动；请确认目标没有被其他程序占用、目录可写");
        return 1;
    }

    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t0)
                             .count();
    char detail[160];
    std::snprintf(detail, sizeof detail, "视频 PID 0x%03X · %llu 块 · %llu NAL · 耗时 %s",
                  (unsigned)vpid, (unsigned long long)stats.chunks,
                  (unsigned long long)stats.nals, h5e_seconds(ms).c_str());
    h5e_note(paint, h5e_sgr_green, "完成",
             (h5e_group(stats.bytes) + " 字节 → " + h5e_path_utf8(out_path)).c_str());
    h5e_note(paint, h5e_sgr_dim, "详情", detail);
    if (pes_starts.empty()) {
        char warn[160];
        std::snprintf(warn, sizeof warn,
                      "未找到视频 PES（PID 0x%03X），输入已原样复制，未解密任何 NAL",
                      (unsigned)vpid);
        h5e_note(paint, h5e_sgr_dim, "提示", warn);
    }
    return 0;
}
#endif
