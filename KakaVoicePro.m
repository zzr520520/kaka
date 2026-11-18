#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <math.h>
#import <string.h>
#import <stdio.h>
#import <mach-o/dyld.h>
#include "tweetnacl.h"
#include "kp_aes.h"

// TweetNaCl 只在生成随机密钥时用到，dylib 侧只验签，这里给个实现避免链接失败
void randombytes(unsigned char *buf, unsigned long long len) {
    arc4random_buf(buf, (size_t)len);
}

// ==========================================
// 1. 全局配置与状态（v29.0：无损抢麦 + 7 级机架 + 动态采样率）
// ==========================================
static _Atomic BOOL  g_dspEnabled        = YES;
static _Atomic BOOL  g_losslessPriority  = YES;   // 一级：关 APM 回声/降噪 + 禁 DTX + 放开门限
static _Atomic BOOL  g_deepBypassVP      = NO;    // 二级高风险：硬件 VP / AudioSession 模式，默认关闭
static _Atomic int   g_opusBitrateBps    = 320000;
static _Atomic float g_sampleRate        = 48000.0f;

static _Atomic BOOL  g_lowCutEnabled     = YES;
static _Atomic BOOL  g_gateEnabled       = NO;
static _Atomic float g_gateThreshold     = 0.012f;

static _Atomic BOOL  g_pitchEnabled      = NO;
static _Atomic float g_pitchShiftVal     = 1.0f;
static _Atomic BOOL  g_throatEnabled     = YES;

static _Atomic BOOL  g_compEnabled       = YES;
static _Atomic float g_compThresh        = 0.25f;
static _Atomic float g_compRatio         = 4.0f;

static _Atomic BOOL  g_eq10Enabled       = YES;
#define EQ10_BANDS 10
static const float kEq10Freqs[EQ10_BANDS] = {
    60.0f, 125.0f, 250.0f, 500.0f, 1000.0f, 2000.0f, 3500.0f, 6000.0f, 10000.0f, 14000.0f
};
static _Atomic float g_eq10Gains[EQ10_BANDS] = {
    -3.0f, -1.5f, 1.5f, 0.5f, 1.0f, 2.5f, 4.5f, 3.0f, 2.5f, 1.5f
};

static _Atomic BOOL  g_imagerEnabled     = YES;
static _Atomic float g_imagerWidth       = 1.35f;

static _Atomic BOOL  g_bassLaneEnabled   = YES;
static _Atomic float g_bassLaneCutoff    = 220.0f;

static _Atomic BOOL  g_tubeEnabled       = YES;
static _Atomic float g_tubeDrive         = 8.0f;
static _Atomic float g_tubeWet           = 0.55f;

static _Atomic BOOL  g_reverbEnabled     = NO;
static _Atomic float g_reverbRoom        = 0.88f;
static _Atomic float g_reverbWet         = 0.28f;

static _Atomic BOOL  g_limiterEnabled    = YES;
static _Atomic float g_makeupGain        = 3.5f;
static _Atomic float g_limiterCeiling    = 32400.0f;

static _Atomic BOOL  g_mixDspEnabled     = YES;
static _Atomic float g_bgmVolume         = 0.45f;
static _Atomic float g_sfxVolume         = 1.0f;
static _Atomic BOOL  g_duckEnabled       = NO;   // v29.5：默认不再自动压低伴奏
static float         g_duckGain          = 1.0f;
static float         g_musicDuck         = 1.0f; // 放歌时人声让位系数（平滑）
static _Atomic BOOL  g_oneTapMasterLock = NO;    // 一键霸麦锁定（防削波/防被压制）
static _Atomic float g_bgmDuckFloor     = 0.20f; // 说话时伴奏保留比例
static _Atomic BOOL  g_bgmMasterSync    = YES;   // 锁定联动伴奏避让
static _Atomic BOOL  g_clipLoop          = NO;

// v29.5：本地屏蔽他人声音（只静音远端播放，不改服务端）
static _Atomic BOOL  g_shieldRemote      = NO;
static _Atomic BOOL  g_shieldLowOnly     = NO;   // YES=压低到 20%，NO=全屏蔽
static NSMutableArray *g_shieldTracks;
static void kp_shield_apply(void);
static void kp_toggle_master_lock(BOOL lock);

// 兼容旧字段（原 UI / 悬浮球仍会读取）
static _Atomic BOOL  g_eqEnabled         = YES;
static _Atomic BOOL  g_excEnabled        = YES;
static _Atomic BOOL  g_haasEnabled       = NO;
static _Atomic BOOL  g_boostOn           = YES;
static NSString *g_bgmName = nil;

// 诊断 + 实时三路仪表
static _Atomic int  g_vuMic     = 0;
static _Atomic int  g_vuMix     = 0;
static _Atomic int  g_vuIn      = 0;
static _Atomic int  g_vuGr      = 0;
static _Atomic int  g_vuOut     = 0;
static _Atomic long g_pcmCalls  = 0;
static _Atomic long g_mixCalls  = 0;
static _Atomic long g_frames    = 0;
static _Atomic int  g_hookState = 0;

#define KP_VERSION @"v30.5"
#define HPF_ALPHA_80HZ 0.9896f
#define MAX_CHANNELS   8
#define REVERB_CH      2

#define KEY_DSP_ON       @"kaka_dsp_enabled"
#define KEY_LOSSLESS_ON  @"kaka_lossless_priority"
#define KEY_DEEP_VP_ON   @"kaka_deep_bypass_vp"
#define KEY_BITRATE_BPS  @"kaka_opus_bitrate_bps"
#define KEY_LOWCUT_ON    @"kaka_lowcut_enabled"
#define KEY_GAIN_VAL     @"kaka_gain_val"
#define KEY_CEIL_VAL     @"kaka_ceil_val"
#define KEY_MIXDSP_ON    @"kaka_mixdsp_enabled"
#define KEY_PITCH_ON     @"kaka_pitch_enabled"
#define KEY_PITCH_VAL    @"kaka_pitch_val"
#define KEY_THROAT_ON    @"kaka_throat_enabled"
#define KEY_GATE_ON      @"kaka_gate_enabled"
#define KEY_GATE_THR     @"kaka_gate_thr"
#define KEY_COMP_ON      @"kaka_comp_enabled"
#define KEY_COMP_THR     @"kaka_comp_thr"
#define KEY_COMP_RATIO   @"kaka_comp_ratio"
#define KEY_EQ10_ON      @"kaka_eq10_enabled"
#define KEY_EQ10_GAINS   @"kaka_eq10_gains"
#define KEY_IMAGER_ON    @"kaka_imager_enabled"
#define KEY_IMAGER_W     @"kaka_imager_width"
#define KEY_BASS_ON      @"kaka_basslane_enabled"
#define KEY_BASS_FC      @"kaka_basslane_cutoff"
#define KEY_TUBE_ON      @"kaka_tube_enabled"
#define KEY_TUBE_DRIVE   @"kaka_tube_drive"
#define KEY_TUBE_WET     @"kaka_tube_wet"
#define KEY_LIMITER_ON   @"kaka_limiter_enabled"
#define KEY_REVERB_ON    @"kaka_reverb_enabled"
#define KEY_REVERB_ROOM  @"kaka_reverb_room"
#define KEY_REVERB_WET   @"kaka_reverb_wet"
#define KEY_BGM_VOL      @"kaka_bgm_vol"
#define KEY_SFX_VOL      @"kaka_sfx_vol"
#define KEY_BGM_NAME     @"kaka_bgm_name"
#define KEY_DUCK_ON      @"kaka_duck_enabled"
#define KEY_MASTER_LOCK  @"kaka_master_lock"
#define KEY_SHIELD_ON    @"kaka_shield_remote"
#define KEY_SHIELD_LOW   @"kaka_shield_low_only"
#define KEY_PRIORITY_LOUD @"kaka_priority_loud"
#define KEY_CLIP_LOOP    @"kaka_clip_loop"
#define KEY_EQ_ON        @"kaka_eq_on"
#define KEY_EXC_ON       @"kaka_exc_on"
#define KEY_HAAS_ON      @"kaka_haas_on"
#define KEY_OTT_ON       @"kaka_ott_on"
#define KEY_BOOST_MODE   @"kaka_boost_mode"

static float g_dc_x1[MAX_CHANNELS] = {0};
static float g_dc_y1[MAX_CHANNELS] = {0};

// v29.7：强声霸麦（Priority Loudness）
static _Atomic BOOL g_priorityLoud = NO;
static float g_hpfAlpha      = 0.9896f;   // 80Hz @48k
static float g_compAtkCoef   = 0.006f;
static float g_compRelCoef   = 0.00015f;

static void kp_rebuild_filter_bank(void);

static void load_saved_settings(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if ([ud objectForKey:KEY_DSP_ON]) {
        g_dspEnabled     = [ud boolForKey:KEY_DSP_ON];
        g_lowCutEnabled  = [ud boolForKey:KEY_LOWCUT_ON];
        g_makeupGain     = [ud floatForKey:KEY_GAIN_VAL];
        g_limiterCeiling = [ud floatForKey:KEY_CEIL_VAL];
        g_mixDspEnabled  = [ud boolForKey:KEY_MIXDSP_ON];
        g_pitchEnabled   = [ud boolForKey:KEY_PITCH_ON];
        g_pitchShiftVal  = [ud floatForKey:KEY_PITCH_VAL];
        g_gateEnabled    = [ud boolForKey:KEY_GATE_ON];
        g_gateThreshold  = [ud floatForKey:KEY_GATE_THR];
        g_reverbEnabled  = [ud boolForKey:KEY_REVERB_ON];
        g_reverbRoom     = [ud floatForKey:KEY_REVERB_ROOM];
        g_reverbWet      = [ud floatForKey:KEY_REVERB_WET];
        g_bgmVolume      = [ud floatForKey:KEY_BGM_VOL];
        g_sfxVolume      = [ud floatForKey:KEY_SFX_VOL];
        g_bgmName        = [ud stringForKey:KEY_BGM_NAME];
    }
    if ([ud objectForKey:KEY_LOSSLESS_ON]) g_losslessPriority = [ud boolForKey:KEY_LOSSLESS_ON];
    if ([ud objectForKey:KEY_DEEP_VP_ON])  g_deepBypassVP     = [ud boolForKey:KEY_DEEP_VP_ON];
    if ([ud objectForKey:KEY_BITRATE_BPS]) g_opusBitrateBps   = (int)[ud integerForKey:KEY_BITRATE_BPS];
    if ([ud objectForKey:KEY_THROAT_ON])   g_throatEnabled    = [ud boolForKey:KEY_THROAT_ON];
    if ([ud objectForKey:KEY_COMP_ON])     g_compEnabled      = [ud boolForKey:KEY_COMP_ON];
    if ([ud objectForKey:KEY_COMP_THR])    g_compThresh       = [ud floatForKey:KEY_COMP_THR];
    if ([ud objectForKey:KEY_COMP_RATIO])  g_compRatio        = [ud floatForKey:KEY_COMP_RATIO];
    if ([ud objectForKey:KEY_EQ10_ON])     g_eq10Enabled      = [ud boolForKey:KEY_EQ10_ON];
    if ([ud objectForKey:KEY_IMAGER_ON])   g_imagerEnabled    = [ud boolForKey:KEY_IMAGER_ON];
    if ([ud objectForKey:KEY_IMAGER_W])    g_imagerWidth      = [ud floatForKey:KEY_IMAGER_W];
    if ([ud objectForKey:KEY_BASS_ON])     g_bassLaneEnabled  = [ud boolForKey:KEY_BASS_ON];
    if ([ud objectForKey:KEY_BASS_FC])     g_bassLaneCutoff   = [ud floatForKey:KEY_BASS_FC];
    if ([ud objectForKey:KEY_TUBE_ON])     g_tubeEnabled      = [ud boolForKey:KEY_TUBE_ON];
    if ([ud objectForKey:KEY_TUBE_DRIVE])  g_tubeDrive        = [ud floatForKey:KEY_TUBE_DRIVE];
    if ([ud objectForKey:KEY_TUBE_WET])    g_tubeWet          = [ud floatForKey:KEY_TUBE_WET];
    if ([ud objectForKey:KEY_LIMITER_ON])  g_limiterEnabled   = [ud boolForKey:KEY_LIMITER_ON];
    if ([ud objectForKey:KEY_DUCK_ON])     g_duckEnabled      = [ud boolForKey:KEY_DUCK_ON];
    if ([ud objectForKey:KEY_SHIELD_ON])   g_shieldRemote     = [ud boolForKey:KEY_SHIELD_ON];
    if ([ud objectForKey:KEY_SHIELD_LOW])  g_shieldLowOnly    = [ud boolForKey:KEY_SHIELD_LOW];
    if ([ud objectForKey:KEY_PRIORITY_LOUD]) g_priorityLoud   = [ud boolForKey:KEY_PRIORITY_LOUD];
    if ([ud objectForKey:KEY_MASTER_LOCK])   g_oneTapMasterLock = [ud boolForKey:KEY_MASTER_LOCK];
    if ([ud objectForKey:KEY_CLIP_LOOP])   g_clipLoop         = [ud boolForKey:KEY_CLIP_LOOP];
    // v29.5 一次性迁移：旧版本默认开着“自动压低伴奏”，升级后强制关一次
    if ([ud objectForKey:@"kaka_duck_migrated_295"] == nil) {
        g_duckEnabled = NO;
        [ud setBool:NO forKey:KEY_DUCK_ON];
        [ud setBool:YES forKey:@"kaka_duck_migrated_295"];
    }

    NSArray *eqArr = [ud arrayForKey:KEY_EQ10_GAINS];
    if (eqArr.count == EQ10_BANDS) {
        for (int i = 0; i < EQ10_BANDS; i++) {
            float g = [eqArr[i] floatValue];
            if (g < -12.0f) g = -12.0f;
            if (g > 12.0f)  g = 12.0f;
            g_eq10Gains[i] = g;
        }
    }
    if (g_opusBitrateBps != 192000 && g_opusBitrateBps != 256000 &&
        g_opusBitrateBps != 320000 && g_opusBitrateBps != 510000) g_opusBitrateBps = 320000;
    // 一次性迁移：旧版本留下的 192k / 更低缓存，升级后统一提到 320k
    NSString *migKey = @"kaka_bitrate_migrated_294";
    if ([ud objectForKey:migKey] == nil) {
        if (g_opusBitrateBps < 256000) {
            g_opusBitrateBps = 320000;
            [ud setInteger:g_opusBitrateBps forKey:KEY_BITRATE_BPS];  // 落盘，避免下次 UI 再读回旧值
        }
        [ud setBool:YES forKey:migKey];
    }
    if (g_makeupGain < 1.0f || g_makeupGain > 20.0f)                g_makeupGain = 3.5f;
    if (g_limiterCeiling < 20000.0f || g_limiterCeiling > 32767.0f) g_limiterCeiling = 32400.0f;
    if (g_pitchShiftVal < 0.5f || g_pitchShiftVal > 1.8f)           g_pitchShiftVal = 1.0f;
    if (g_gateThreshold < 0.003f || g_gateThreshold > 0.08f)        g_gateThreshold = 0.012f;
    if (g_compThresh < 0.08f || g_compThresh > 0.75f)               g_compThresh = 0.25f;
    if (g_compRatio < 1.5f || g_compRatio > 10.0f)                  g_compRatio = 4.0f;
    if (g_imagerWidth < 0.5f || g_imagerWidth > 2.0f)               g_imagerWidth = 1.35f;
    if (g_bassLaneCutoff < 80.0f || g_bassLaneCutoff > 1250.0f)     g_bassLaneCutoff = 220.0f;
    if (g_tubeDrive < 1.0f || g_tubeDrive > 28.0f)                  g_tubeDrive = 8.0f;
    if (g_tubeWet < 0.0f || g_tubeWet > 1.0f)                       g_tubeWet = 0.55f;
    if (g_reverbRoom < 0.0f || g_reverbRoom > 0.95f)                g_reverbRoom = 0.88f;
    if (g_reverbWet < 0.0f || g_reverbWet > 0.8f)                   g_reverbWet = 0.28f;
    if (g_bgmVolume < 0.0f || g_bgmVolume > 1.0f)                   g_bgmVolume = 0.45f;
    if (g_sfxVolume < 0.0f || g_sfxVolume > 1.0f)                   g_sfxVolume = 1.0f;

    kp_rebuild_filter_bank();
}

static void save_current_settings(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setBool:g_dspEnabled       forKey:KEY_DSP_ON];
    [ud setBool:g_losslessPriority forKey:KEY_LOSSLESS_ON];
    [ud setBool:g_deepBypassVP     forKey:KEY_DEEP_VP_ON];
    [ud setInteger:g_opusBitrateBps forKey:KEY_BITRATE_BPS];
    [ud setBool:g_lowCutEnabled    forKey:KEY_LOWCUT_ON];
    [ud setFloat:g_makeupGain      forKey:KEY_GAIN_VAL];
    [ud setFloat:g_limiterCeiling  forKey:KEY_CEIL_VAL];
    [ud setBool:g_mixDspEnabled    forKey:KEY_MIXDSP_ON];
    [ud setBool:g_pitchEnabled     forKey:KEY_PITCH_ON];
    [ud setFloat:g_pitchShiftVal   forKey:KEY_PITCH_VAL];
    [ud setBool:g_throatEnabled    forKey:KEY_THROAT_ON];
    [ud setBool:g_gateEnabled      forKey:KEY_GATE_ON];
    [ud setFloat:g_gateThreshold   forKey:KEY_GATE_THR];
    [ud setBool:g_compEnabled      forKey:KEY_COMP_ON];
    [ud setFloat:g_compThresh      forKey:KEY_COMP_THR];
    [ud setFloat:g_compRatio       forKey:KEY_COMP_RATIO];
    [ud setBool:g_eq10Enabled      forKey:KEY_EQ10_ON];
    [ud setBool:g_imagerEnabled    forKey:KEY_IMAGER_ON];
    [ud setFloat:g_imagerWidth     forKey:KEY_IMAGER_W];
    [ud setBool:g_bassLaneEnabled  forKey:KEY_BASS_ON];
    [ud setFloat:g_bassLaneCutoff  forKey:KEY_BASS_FC];
    [ud setBool:g_tubeEnabled      forKey:KEY_TUBE_ON];
    [ud setFloat:g_tubeDrive       forKey:KEY_TUBE_DRIVE];
    [ud setFloat:g_tubeWet         forKey:KEY_TUBE_WET];
    [ud setBool:g_limiterEnabled   forKey:KEY_LIMITER_ON];
    [ud setBool:g_reverbEnabled    forKey:KEY_REVERB_ON];
    [ud setFloat:g_reverbRoom      forKey:KEY_REVERB_ROOM];
    [ud setFloat:g_reverbWet       forKey:KEY_REVERB_WET];
    [ud setFloat:g_bgmVolume       forKey:KEY_BGM_VOL];
    [ud setFloat:g_sfxVolume       forKey:KEY_SFX_VOL];
    [ud setBool:g_duckEnabled      forKey:KEY_DUCK_ON];
    [ud setBool:g_shieldRemote     forKey:KEY_SHIELD_ON];
    [ud setBool:g_shieldLowOnly    forKey:KEY_SHIELD_LOW];
    [ud setBool:g_priorityLoud     forKey:KEY_PRIORITY_LOUD];
    [ud setBool:g_oneTapMasterLock forKey:KEY_MASTER_LOCK];
    [ud setBool:g_clipLoop         forKey:KEY_CLIP_LOOP];
    NSMutableArray *eqArr = [NSMutableArray arrayWithCapacity:EQ10_BANDS];
    for (int i = 0; i < EQ10_BANDS; i++) {
        float g = g_eq10Gains[i];
        [eqArr addObject:@(g)];
    }
    [ud setObject:eqArr forKey:KEY_EQ10_GAINS];
}

// ==========================================
// 2. 变声：相位声码器（smbPitchShift 算法）
// 延迟 768 采样（48kHz 约 16ms），重采样在频域完成，音质稳定
// ==========================================
#define PITCH_MAX_FRAME_LEN 4096
#define PITCH_FFT_SIZE      1024
#define PITCH_OSAMP         4
#define PITCH_MAX_CH        2
#define PITCH_CHUNK         1024

typedef struct {
    float inFIFO[PITCH_MAX_FRAME_LEN];
    float outFIFO[PITCH_MAX_FRAME_LEN];
    float fftWorkspace[2 * PITCH_MAX_FRAME_LEN];
    float lastPhase[PITCH_MAX_FRAME_LEN / 2 + 1];
    float sumPhase[PITCH_MAX_FRAME_LEN / 2 + 1];
    float outputAccum[2 * PITCH_MAX_FRAME_LEN];
    float anaFreq[PITCH_MAX_FRAME_LEN];
    float anaMagn[PITCH_MAX_FRAME_LEN];
    float synFreq[PITCH_MAX_FRAME_LEN];
    float synMagn[PITCH_MAX_FRAME_LEN];
    long  rover;
} KPPitchState;

static KPPitchState g_pitchState[PITCH_MAX_CH];
static float g_pitchScratchIn[PITCH_CHUNK];
static float g_pitchScratchOut[PITCH_CHUNK];

static void kp_smb_fft(float *fftBuffer, long fftFrameSize, long sign) {
    float wr, wi, arg, *p1, *p2, temp;
    float tr, ti, ur, ui, *p1r, *p1i, *p2r, *p2i;
    long i, bitm, j, le, le2, k;

    for (i = 2; i < 2 * fftFrameSize - 2; i += 2) {
        for (bitm = 2, j = 0; bitm < 2 * fftFrameSize; bitm <<= 1) {
            if (i & bitm) j++;
            j <<= 1;
        }
        if (i < j) {
            p1 = fftBuffer + i;
            p2 = fftBuffer + j;
            temp = *p1; *(p1++) = *p2; *(p2++) = temp;
            temp = *p1; *p1 = *p2; *p2 = temp;
        }
    }

    long steps = (long)(log((double)fftFrameSize) / log(2.0) + 0.5);
    for (k = 0, le = 2; k < steps; k++) {
        le <<= 1;
        le2 = le >> 1;
        ur = 1.0f;
        ui = 0.0f;
        arg = (float)M_PI / (le2 >> 1);
        wr = cosf(arg);
        wi = sign * sinf(arg);
        for (j = 0; j < le2; j += 2) {
            p1r = fftBuffer + j;
            p1i = p1r + 1;
            p2r = p1r + le2;
            p2i = p2r + 1;
            for (i = j; i < 2 * fftFrameSize; i += le) {
                tr = *p2r * ur - *p2i * ui;
                ti = *p2r * ui + *p2i * ur;
                *p2r = *p1r - tr;
                *p2i = *p1i - ti;
                *p1r += tr;
                *p1i += ti;
                p1r += le; p1i += le;
                p2r += le; p2i += le;
            }
            tr = ur * wr - ui * wi;
            ui = ur * wi + ui * wr;
            ur = tr;
        }
    }
}

static void kp_pitch_shift(float pitchShift, long numSamps, float sampleRate,
                           const float *indata, float *outdata, UInt32 ch) {
    KPPitchState *st = &g_pitchState[ch];

    const long fftFrameSize = PITCH_FFT_SIZE;
    const long osamp = PITCH_OSAMP;
    const long fftFrameSize2 = fftFrameSize / 2;
    const long stepSize = fftFrameSize / osamp;
    const double freqPerBin = sampleRate / (double)fftFrameSize;
    const double expct = 2.0 * M_PI * (double)stepSize / (double)fftFrameSize;
    const long inFifoLatency = fftFrameSize - stepSize;

    if (st->rover == 0) st->rover = inFifoLatency;

    for (long i = 0; i < numSamps; i++) {
        st->inFIFO[st->rover] = indata[i];
        outdata[i] = st->outFIFO[st->rover - inFifoLatency];
        st->rover++;

        if (st->rover >= fftFrameSize) {
            st->rover = inFifoLatency;

            for (long k = 0; k < fftFrameSize; k++) {
                float window = (float)(-0.5 * cos(2.0 * M_PI * (double)k / (double)fftFrameSize) + 0.5);
                st->fftWorkspace[2 * k] = st->inFIFO[k] * window;
                st->fftWorkspace[2 * k + 1] = 0.0f;
            }

            kp_smb_fft(st->fftWorkspace, fftFrameSize, -1);

            for (long k = 0; k <= fftFrameSize2; k++) {
                double real = st->fftWorkspace[2 * k];
                double imag = st->fftWorkspace[2 * k + 1];
                double magn = 2.0 * sqrt(real * real + imag * imag);
                double phase = atan2(imag, real);

                double tmp = phase - st->lastPhase[k];
                st->lastPhase[k] = (float)phase;
                tmp -= (double)k * expct;

                long qpd = (long)(tmp / M_PI);
                if (qpd >= 0) qpd += qpd & 1;
                else qpd -= qpd & 1;
                tmp -= M_PI * (double)qpd;

                tmp = (double)osamp * tmp / (2.0 * M_PI);
                tmp = (double)k * freqPerBin + tmp * freqPerBin;

                st->anaMagn[k] = (float)magn;
                st->anaFreq[k] = (float)tmp;
            }

            memset(st->synMagn, 0, (size_t)fftFrameSize * sizeof(float));
            memset(st->synFreq, 0, (size_t)fftFrameSize * sizeof(float));

            for (long k = 0; k <= fftFrameSize2; k++) {
                long index = (long)((double)k * pitchShift);
                if (index <= fftFrameSize2) {
                    st->synMagn[index] += st->anaMagn[k];
                    st->synFreq[index] = (float)(st->anaFreq[k] * pitchShift);
                }
            }

            for (long k = 0; k <= fftFrameSize2; k++) {
                double magn = st->synMagn[k];
                double tmp = st->synFreq[k];

                tmp -= (double)k * freqPerBin;
                tmp /= freqPerBin;
                tmp = 2.0 * M_PI * tmp / (double)osamp;
                tmp += (double)k * expct;

                st->sumPhase[k] += (float)tmp;
                double phase = st->sumPhase[k];

                st->fftWorkspace[2 * k] = (float)(magn * cos(phase));
                st->fftWorkspace[2 * k + 1] = (float)(magn * sin(phase));
            }

            for (long k = fftFrameSize + 2; k < 2 * fftFrameSize; k++) {
                st->fftWorkspace[k] = 0.0f;
            }

            kp_smb_fft(st->fftWorkspace, fftFrameSize, 1);

            for (long k = 0; k < fftFrameSize; k++) {
                float window = (float)(-0.5 * cos(2.0 * M_PI * (double)k / (double)fftFrameSize) + 0.5);
                st->outputAccum[k] += 2.0f * window * st->fftWorkspace[2 * k] / (float)(fftFrameSize2 * osamp);
            }

            for (long k = 0; k < stepSize; k++) st->outFIFO[k] = st->outputAccum[k];
            memmove(st->outputAccum, st->outputAccum + stepSize, (size_t)fftFrameSize * sizeof(float));
            for (long k = 0; k < inFifoLatency; k++) st->inFIFO[k] = st->inFIFO[k + stepSize];
        }
    }
}

static void kp_pitch_reset(void) {
    memset(g_pitchState, 0, sizeof(g_pitchState));
}

static void kp_pitch_process_s16(int16_t *pcm, UInt32 frames, UInt32 channels) {
    if (!pcm || frames == 0 || channels == 0 || channels > PITCH_MAX_CH) return;

    float shift = g_pitchShiftVal;
    if (fabsf(shift - 1.0f) < 0.02f) return;

    for (UInt32 f0 = 0; f0 < frames; f0 += PITCH_CHUNK) {
        UInt32 n = frames - f0;
        if (n > PITCH_CHUNK) n = PITCH_CHUNK;

        for (UInt32 c = 0; c < channels; c++) {
            for (UInt32 i = 0; i < n; i++) {
                g_pitchScratchIn[i] = (float)pcm[(f0 + i) * channels + c];
            }
            kp_pitch_shift(shift, (long)n, 48000.0f, g_pitchScratchIn, g_pitchScratchOut, c);
            for (UInt32 i = 0; i < n; i++) {
                float s = g_pitchScratchOut[i];
                if (s > 32767.0f) s = 32767.0f;
                if (s < -32768.0f) s = -32768.0f;
                pcm[(f0 + i) * channels + c] = (int16_t)s;
            }
        }
    }
}

// ==========================================
// 3. Freeverb 混响（comb → allpass 串联，每声道独立状态）
// ==========================================
#define COMB_N   8
#define AP_N     4
#define COMB_BUF 2048
#define AP_BUF   1024

static const int kCombTune[COMB_N] = {1116, 1188, 1277, 1356, 1422, 1491, 1557, 1617};
static const int kApTune[AP_N]     = {556, 441, 341, 225};

typedef struct {
    float buf[COMB_BUF];
    int   size;
    int   idx;
    float store;
} KPComb;

typedef struct {
    float buf[AP_BUF];
    int   size;
    int   idx;
} KPAllpass;

typedef struct {
    KPComb    comb[COMB_N];
    KPAllpass ap[AP_N];
} KPReverb;

static KPReverb g_reverb[REVERB_CH];

static void kp_reverb_reset(void) {
    memset(g_reverb, 0, sizeof(g_reverb));
    for (int c = 0; c < REVERB_CH; c++) {
        for (int i = 0; i < COMB_N; i++) {
            g_reverb[c].comb[i].size = kCombTune[i];
            g_reverb[c].comb[i].idx = 0;
            g_reverb[c].comb[i].store = 0.0f;
        }
        for (int i = 0; i < AP_N; i++) {
            g_reverb[c].ap[i].size = kApTune[i];
            g_reverb[c].ap[i].idx = 0;
        }
    }
}

// 返回湿声（与输入同量级）
static inline float kp_reverb_tick(float in, UInt32 ch) {
    KPReverb *rv = &g_reverb[ch < REVERB_CH ? ch : 0];
    float room = g_reverbRoom;
    const float damp = 0.28f;
    float sum = 0.0f;

    for (int i = 0; i < COMB_N; i++) {
        KPComb *cf = &rv->comb[i];
        float out = cf->buf[cf->idx];
        cf->store = out * (1.0f - damp) + cf->store * damp;
        cf->buf[cf->idx] = in + cf->store * room;
        cf->idx++;
        if (cf->idx >= cf->size) cf->idx = 0;
        sum += out;
    }
    sum *= 0.125f;

    for (int i = 0; i < AP_N; i++) {
        KPAllpass *af = &rv->ap[i];
        float bufOut = af->buf[af->idx];
        float out = bufOut - sum;
        af->buf[af->idx] = sum + bufOut * 0.5f;
        af->idx++;
        if (af->idx >= af->size) af->idx = 0;
        sum = out;
    }
    return sum;
}

// ==========================================
// 4. 复刻 PC VST 7 级机架 DSP 链（双缓冲无锁系数 + 动态采样率 + 独立 GR）
// ==========================================
typedef struct {
    float b0, b1, b2, a1, a2;
} KPBiquadCoef;

typedef struct {
    float z1, z2;
} KPBiquadState;

typedef struct {
    KPBiquadCoef throat[2];
    KPBiquadCoef eq10[EQ10_BANDS];
    KPBiquadCoef bassLP;
} KPFilterBank;

static KPFilterBank g_filterBanks[2];
static _Atomic int  g_activeBank = 0;

static inline float kp_biquad_run(float x, const KPBiquadCoef *c, KPBiquadState *s) {
    float y = c->b0 * x + s->z1;
    s->z1 = c->b1 * x - c->a1 * y + s->z2;
    s->z2 = c->b2 * x - c->a2 * y;
    return y;
}

static void kp_rbj_peaking(KPBiquadCoef *c, float fs, float f0, float Q, float dB) {
    if (fabsf(dB) < 0.05f || f0 >= fs * 0.48f) {
        c->b0 = 1.0f; c->b1 = 0.0f; c->b2 = 0.0f; c->a1 = 0.0f; c->a2 = 0.0f;
        return;
    }
    float A = powf(10.0f, dB / 40.0f);
    float w0 = 2.0f * (float)M_PI * f0 / fs;
    float cosw = cosf(w0);
    float alpha = sinf(w0) / (2.0f * Q);
    float a0 = 1.0f + alpha / A;
    c->b0 = (1.0f + alpha * A) / a0;
    c->b1 = (-2.0f * cosw) / a0;
    c->b2 = (1.0f - alpha * A) / a0;
    c->a1 = (-2.0f * cosw) / a0;
    c->a2 = (1.0f - alpha / A) / a0;
}

static void kp_rbj_lowpass(KPBiquadCoef *c, float fs, float f0, float Q) {
    if (f0 >= fs * 0.48f) f0 = fs * 0.45f;
    float w0 = 2.0f * (float)M_PI * f0 / fs;
    float cosw = cosf(w0);
    float alpha = sinf(w0) / (2.0f * Q);
    float a0 = 1.0f + alpha;
    c->b0 = ((1.0f - cosw) * 0.5f) / a0;
    c->b1 = (1.0f - cosw) / a0;
    c->b2 = c->b0;
    c->a1 = (-2.0f * cosw) / a0;
    c->a2 = (1.0f - alpha) / a0;
}

static void kp_rebuild_filter_bank(void) {
    float fs = g_sampleRate;
    if (fs < 8000.0f || fs > 96000.0f) fs = 48000.0f;
    int next = 1 - g_activeBank;
    KPFilterBank *B = &g_filterBanks[next];
    if (g_priorityLoud) {
        // 强声霸麦：2.2k / 3.4k 各 +4dB，换掉喉音的两个频点
        kp_rbj_peaking(&B->throat[0], fs, 2200.0f, 1.05f, 4.0f);
        kp_rbj_peaking(&B->throat[1], fs, 3400.0f, 1.05f, 4.0f);
    } else {
        kp_rbj_peaking(&B->throat[0], fs, 210.0f,  1.2f, 2.8f);
        kp_rbj_peaking(&B->throat[1], fs, 2800.0f, 1.4f, 2.2f);
    }
    for (int i = 0; i < EQ10_BANDS; i++) {
        float q = (i == 0 || i == EQ10_BANDS - 1) ? 0.9f : 1.35f;
        float g = g_eq10Gains[i];
        kp_rbj_peaking(&B->eq10[i], fs, kEq10Freqs[i], q, g);
    }
    kp_rbj_lowpass(&B->bassLP, fs, g_bassLaneCutoff, 0.707f);

    // 高通：普通 80Hz，强声霸麦 100Hz
    float fc = g_priorityLoud ? 100.0f : 80.0f;
    g_hpfAlpha = expf(-2.0f * 3.14159265f * fc / fs);

    // 压缩时间常数：强声霸麦 attack 2ms / release 80ms
    float atk = g_priorityLoud ? 0.002f : 0.004f;
    float rel = g_priorityLoud ? 0.080f : 0.140f;
    g_compAtkCoef = 1.0f - expf(-1.0f / (fs * atk));
    g_compRelCoef = 1.0f - expf(-1.0f / (fs * rel));

    g_activeBank = next;
}

static float g_gateEnv[MAX_CHANNELS]  = {0};
static float g_gateGain[MAX_CHANNELS] = {1.0f};
static int   g_gateOpen[MAX_CHANNELS] = {0};
static KPBiquadState g_throatSt[MAX_CHANNELS][2];
static KPBiquadState g_eq10St[MAX_CHANNELS][EQ10_BANDS];
static KPBiquadState g_bassLPSt[MAX_CHANNELS];

static void kp_gate_reset(void) {
    memset(g_gateEnv, 0, sizeof(g_gateEnv));
    memset(g_gateOpen, 0, sizeof(g_gateOpen));
    for (int i = 0; i < MAX_CHANNELS; i++) g_gateGain[i] = 1.0f;
}

static void kp_eq_init(void) {
    memset(g_throatSt, 0, sizeof(g_throatSt));
    memset(g_eq10St, 0, sizeof(g_eq10St));
    memset(g_bassLPSt, 0, sizeof(g_bassLPSt));
    kp_rebuild_filter_bank();
    kp_rebuild_filter_bank();
}

// ---------- ⑥ TubeDriver：非对称电子管饱和 ----------
static float g_tubePreHP[MAX_CHANNELS] = {0};
static float g_tubePreX1[MAX_CHANNELS] = {0};
static float g_tubePostLP[MAX_CHANNELS] = {0};
static inline float kp_tube_sample(float xn, UInt32 ch) {
    float hp = xn - g_tubePreX1[ch] + 0.994f * g_tubePreHP[ch];
    g_tubePreX1[ch] = xn;
    g_tubePreHP[ch] = hp;

    float drive = g_tubeDrive;
    float bias  = 0.16f;
    float d     = hp * (1.0f + drive * 0.22f) + bias;
    float sat   = tanhf(d) - tanhf(bias);
    g_tubePostLP[ch] += (sat - g_tubePostLP[ch]) * 0.65f;
    float norm = g_tubePostLP[ch] / (1.0f + drive * 0.08f);
    float wet = g_tubeWet;
    return xn * (1.0f - wet) + norm * wet;
}

// ---------- ② DYNAM-IZER 双向压缩（向下压限 + 向上提拉） ----------
static float g_compEnv[MAX_CHANNELS] = {0};
static float g_grCompPeak = 0.0f;
static float g_grLimPeak  = 0.0f;
// v29.5：输出 RMS 护栏。只往下压，不往上补，防止 -0.0dB 死电方波
static float g_rmsTrim = 1.0f;

static inline float kp_comp_sample(float xn, UInt32 ch) {
    float absx = fabsf(xn);
    float coef = (absx > g_compEnv[ch]) ? g_compAtkCoef : g_compRelCoef;
    g_compEnv[ch] += (absx - g_compEnv[ch]) * coef;
    float env = g_compEnv[ch];

    // 1) 向上提拉（v30.2 修正）：0.045→0.080 之间线性渐入，0.080 以上满额
    //    低于 0.045（4.5%）一律不提拉 —— 原来门槛 0.012 会把 7% 的底噪放大到 95%，
    //    一开大增益就是“人声和底噪一起糊”。最大提拉从 5.0 压到 1.85，彻底杜绝发糊
    float upGain = 1.0f;
    float thr = g_compThresh;
    if (absx < 0.55f && env > 0.045f && env < thr && thr > 0.001f) {
        float maxUp = g_priorityLoud ? 1.85f : 1.50f;
        float base = powf(thr / env, 0.45f);
        if (base > maxUp) base = maxUp;
        float ramp = (env - 0.045f) / 0.035f;
        if (ramp < 0.0f) ramp = 0.0f;
        if (ramp > 1.0f) ramp = 1.0f;
        upGain = 1.0f + (base - 1.0f) * ramp;
    }

    // 2) 向下压限：超过阈值按压缩比压紧
    float downGain = 1.0f;
    if (env > thr && thr > 0.001f) {
        float overDb = 20.0f * log10f(env / thr);
        float redDb  = overDb * (1.0f - 1.0f / g_compRatio);
        downGain = powf(10.0f, -redDb / 20.0f);
        float grPct = (1.0f - downGain) * 140.0f;
        if (grPct > g_grCompPeak) g_grCompPeak = grPct;
    }
    return xn * upGain * downGain;
}

// ---------- ④ Suya 声场：单声道也能出空间（7ms + 13ms 双抽头早期反射） ----------
#define SUYA_BUF_LEN 1024
static float g_suyaBuf[MAX_CHANNELS][SUYA_BUF_LEN];
static int   g_suyaIdx[MAX_CHANNELS] = {0};

static inline float kp_suya_mono_space(float xn, UInt32 ch) {
    int w = g_suyaIdx[ch];
    g_suyaBuf[ch][w] = xn;
    int r1 = (w - 336 + SUYA_BUF_LEN) & (SUYA_BUF_LEN - 1);  // 7ms @48k
    int r2 = (w - 624 + SUYA_BUF_LEN) & (SUYA_BUF_LEN - 1);  // 13ms @48k
    g_suyaIdx[ch] = (w + 1) & (SUYA_BUF_LEN - 1);
    float amt = (g_imagerWidth - 0.5f) * 0.28f;
    if (amt < 0.0f) amt = 0.0f;
    return xn + (g_suyaBuf[ch][r1] * 0.65f - g_suyaBuf[ch][r2] * 0.35f) * amt;
}

// ---------- ⑦ 前瞻硬限幅器 ----------
#define KP_LOOK 192
typedef struct {
    float buf[KP_LOOK];
    int   idx;
    float gr;
    float hold;
} KPLim;
static KPLim g_lim[MAX_CHANNELS];

static void kp_lim_reset(void) {
    memset(g_lim, 0, sizeof(g_lim));
    for (int i = 0; i < MAX_CHANNELS; i++) g_lim[i].gr = 1.0f;
}

static inline float kp_limiter_tick(float x, UInt32 ch, float ceilNorm) {
    KPLim *L = &g_lim[ch];
    float delayed = L->buf[L->idx];
    L->buf[L->idx] = x;
    L->idx = (L->idx + 1) % KP_LOOK;

    float ax = fabsf(x);
    if (ax > L->hold) L->hold = ax;
    else              L->hold += (ax - L->hold) * 0.0008f;

    float targetGr = (L->hold > ceilNorm && L->hold > 1e-6f) ? (ceilNorm / L->hold) : 1.0f;
    if (targetGr < L->gr) L->gr += (targetGr - L->gr) * 0.35f;
    else                  L->gr += (targetGr - L->gr) * 0.001f;

    float grPct = (1.0f - L->gr) * 140.0f;
    if (grPct > g_grLimPeak) g_grLimPeak = grPct;

    float out = delayed * L->gr;
    if (out > ceilNorm)  out = ceilNorm;
    if (out < -ceilNorm) out = -ceilNorm;
    return out;
}

// 人声前级（v30.0 精简）：低切 → 门限 → 喉音提亮 → 10 段 EQ → 双向压缩
static inline float kp_voice_pre_sample(float inSample, UInt32 ch, const KPFilterBank *bank) {
    float y = inSample;
    if (g_lowCutEnabled) {
        float fy = y - g_dc_x1[ch] + g_hpfAlpha * g_dc_y1[ch];
        g_dc_x1[ch] = y;
        g_dc_y1[ch] = fy;
        y = fy;
    }
    if (g_gateEnabled && !g_losslessPriority) {
        float a = fabsf(y) * (1.0f / 32768.0f);
        if (a > g_gateEnv[ch]) g_gateEnv[ch] += (a - g_gateEnv[ch]) * 0.35f;
        else                   g_gateEnv[ch] += (a - g_gateEnv[ch]) * 0.0006f;
        float thr = g_gateThreshold;
        if (g_gateOpen[ch]) { if (g_gateEnv[ch] < thr * 0.55f) g_gateOpen[ch] = 0; }
        else                { if (g_gateEnv[ch] > thr)         g_gateOpen[ch] = 1; }
        float target = g_gateOpen[ch] ? 1.0f : 0.0f;
        g_gateGain[ch] += (target - g_gateGain[ch]) * (g_gateOpen[ch] ? 0.02f : 0.0012f);
        y *= g_gateGain[ch];
    }

    float xn = y * (1.0f / 32768.0f);
    if (g_throatEnabled) {
        xn = kp_biquad_run(xn, &bank->throat[0], &g_throatSt[ch][0]);
        xn = kp_biquad_run(xn, &bank->throat[1], &g_throatSt[ch][1]);
    }
    if (g_eq10Enabled && g_eqEnabled) {
        for (int b = 0; b < EQ10_BANDS; b++) {
            xn = kp_biquad_run(xn, &bank->eq10[b], &g_eq10St[ch][b]);
        }
    }
    // v30.0：删除 TubeDriver —— tanhf 非线性挤压把波峰拍平成准方波，
    // 峰值因数丢失后 Opus 在多人房会当噪音/削波丢弃，是发糊的主因
    if (g_compEnabled) {
        xn = kp_comp_sample(xn, ch);
    }
    return xn * 32768.0f;
}

// ==========================================
// 5. 音效 / BGM 播放器（音频线程无锁读取，只在主线程装载）
// ==========================================
#define SFX_SLOT 4
#define AUDIO_MAX_FRAMES (48000 * 600)   // 单文件上限 10 分钟

typedef struct {
    int16_t *pcm;
    UInt32   len;
} KPAudioClip;

static KPAudioClip g_sfxClip[SFX_SLOT];
static _Atomic int      g_sfxPos[SFX_SLOT];
static _Atomic int      g_sfxOn[SFX_SLOT];

static int16_t *g_bgmPcm = NULL;
static _Atomic int g_bgmLen = 0;
static _Atomic int g_bgmPos = 0;
static _Atomic int g_bgmOn  = 0;

// 退役缓冲：避免音频线程正在读时被 free
#define BGM_RETIRE 3
static int16_t *g_bgmRetired[BGM_RETIRE];
static int      g_bgmRetiredSlot = 0;

static void kp_bgm_retire(int16_t *old) {
    if (!old) return;
    if (g_bgmRetired[g_bgmRetiredSlot]) free(g_bgmRetired[g_bgmRetiredSlot]);
    g_bgmRetired[g_bgmRetiredSlot] = old;
    g_bgmRetiredSlot = (g_bgmRetiredSlot + 1) % BGM_RETIRE;
}

static void kp_play_sfx(int index) {
    if (index < 0 || index >= SFX_SLOT) return;
    if (!g_sfxClip[index].pcm) return;
    g_sfxPos[index] = 0;
    g_sfxOn[index]  = 1;
}

// ==========================================
// 6. 音频文件解码（MP3 / WAV / M4A → 48kHz 单声道 S16）
// ==========================================
static int16_t *kp_load_audio(NSString *path, UInt32 *outCount) {
    if (!path || ![path length]) return NULL;
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return NULL;

    ExtAudioFileRef f = NULL;
    OSStatus st = ExtAudioFileOpenURL((__bridge CFURLRef)[NSURL fileURLWithPath:path], &f);
    if (st != noErr || !f) return NULL;

    AudioStreamBasicDescription fileFmt;
    UInt32 sz = sizeof(fileFmt);
    if (ExtAudioFileGetProperty(f, kExtAudioFileProperty_FileDataFormat, &sz, &fileFmt) != noErr || fileFmt.mSampleRate <= 0) {
        ExtAudioFileDispose(f);
        return NULL;
    }

    SInt64 fileFrames = 0;
    sz = sizeof(fileFrames);
    ExtAudioFileGetProperty(f, kExtAudioFileProperty_FileLengthFrames, &sz, &fileFrames);

    // 关键：文件帧数按文件采样率计，必须换算到 48kHz，并留 1 秒余量
    double ratio = 48000.0 / fileFmt.mSampleRate;
    SInt64 destFrames = (SInt64)((double)fileFrames * ratio) + 48000;
    if (destFrames < 48000) destFrames = 48000;
    if (destFrames > AUDIO_MAX_FRAMES) destFrames = AUDIO_MAX_FRAMES;

    AudioStreamBasicDescription client;
    memset(&client, 0, sizeof(client));
    client.mFormatID         = kAudioFormatLinearPCM;
    client.mSampleRate       = 48000.0;
    client.mFormatFlags      = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    client.mBitsPerChannel   = 16;
    client.mChannelsPerFrame = 1;
    client.mFramesPerPacket  = 1;
    client.mBytesPerFrame    = 2;
    client.mBytesPerPacket   = 2;

    if (ExtAudioFileSetProperty(f, kExtAudioFileProperty_ClientDataFormat, sizeof(client), &client) != noErr) {
        ExtAudioFileDispose(f);
        return NULL;
    }

    int16_t *buf = (int16_t *)calloc((size_t)destFrames, sizeof(int16_t));
    if (!buf) { ExtAudioFileDispose(f); return NULL; }

    UInt32 written = 0;
    while (written < (UInt32)destFrames) {
        UInt32 want = 2048;
        if (want > (UInt32)destFrames - written) want = (UInt32)destFrames - written;

        AudioBufferList abl;
        abl.mNumberBuffers = 1;
        abl.mBuffers[0].mNumberChannels = 1;
        abl.mBuffers[0].mDataByteSize   = want * 2;
        abl.mBuffers[0].mData           = buf + written;

        UInt32 got = want;
        OSStatus r = ExtAudioFileRead(f, &got, &abl);
        if (r != noErr || got == 0) break;
        written += got;
    }

    ExtAudioFileDispose(f);

    if (written == 0) { free(buf); return NULL; }
    if (outCount) *outCount = written;
    return buf;
}

// 无素材时的内置合成音效
static int16_t *kp_synth_sfx(int type, UInt32 *outCount) {
    UInt32 n = 48000;
    int16_t *buf = (int16_t *)calloc(n, sizeof(int16_t));
    if (!buf) return NULL;

    unsigned int seed = (unsigned int)(type * 7919 + 12345);
    for (UInt32 i = 0; i < n; i++) {
        float t = (float)i / 48000.0f;
        float s = 0.0f;

        if (type == 0) {
            // 掌声：噪声脉冲群 + 衰减包络
            seed = seed * 1103515245u + 12345u;
            float nz = ((float)((seed >> 16) & 0x7FFF) / 16384.0f) - 1.0f;
            float burst = 0.55f + 0.45f * sinf(2.0f * (float)M_PI * 11.0f * t);
            s = nz * burst * expf(-t * 2.6f) * 0.55f;
        } else if (type == 1) {
            // 笑声：带颤音的调频音
            float freq = 320.0f + 120.0f * sinf(2.0f * (float)M_PI * 5.5f * t);
            s = sinf(2.0f * (float)M_PI * freq * t) * (0.5f + 0.5f * sinf(2.0f * (float)M_PI * 2.2f * t)) * expf(-t * 1.6f) * 0.6f;
        } else if (type == 2) {
            // 欢呼：三音和弦 + 起伏
            float a = sinf(2.0f * (float)M_PI * 523.25f * t);
            float b = sinf(2.0f * (float)M_PI * 659.25f * t);
            float c = sinf(2.0f * (float)M_PI * 783.99f * t);
            s = (a + b + c) / 3.0f * (0.6f + 0.4f * sinf(2.0f * (float)M_PI * 3.0f * t)) * expf(-t * 1.2f) * 0.65f;
        } else {
            // 口哨：下滑音
            float f0 = 1800.0f - 1100.0f * t;
            s = sinf(2.0f * (float)M_PI * f0 * t) * expf(-t * 3.5f) * 0.5f;
        }
        if (s > 1.0f) s = 1.0f;
        if (s < -1.0f) s = -1.0f;
        buf[i] = (int16_t)(s * 26000.0f);
    }
    if (outCount) *outCount = n;
    return buf;
}

static NSString *kp_documents_path(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static void kp_load_sfx_library(void) {
    NSString *dir = [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio/SFX"];
    for (int i = 0; i < SFX_SLOT; i++) {
        UInt32 n = 0;
        int16_t *buf = NULL;

        NSString *base = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"sfx_%d", i]];
        for (NSString *ext in @[@"mp3", @"m4a", @"wav", @"caf"]) {
            NSString *p = [base stringByAppendingPathExtension:ext];
            if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
                buf = kp_load_audio(p, &n);
                if (buf) break;
            }
        }
        if (!buf) buf = kp_synth_sfx(i, &n);

        g_sfxClip[i].pcm = buf;
        g_sfxClip[i].len = n;
        g_sfxPos[i] = 0;
        g_sfxOn[i] = 0;
    }
}

// ==========================================
// 7. 音效 / BGM 的删除与重建
// ==========================================
static void kp_log(NSString *fmt, ...);
static void kp_bgm_load_name(NSString *name);
static void kp_show_bgm_menu(void);
static void kp_show_bgm_delete_menu(void);

static NSString *kp_sfx_dir(void) {
    return [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio/SFX"];
}

// 删除某个音效槽的自定义文件，并重建为出厂合成音；返回是否真的删掉了文件
static BOOL kp_reset_sfx_slot(int idx) {
    if (idx < 0 || idx >= SFX_SLOT) return NO;

    g_sfxOn[idx] = 0;
    g_sfxPos[idx] = 0;

    BOOL removed = NO;
    NSString *base = [kp_sfx_dir() stringByAppendingPathComponent:[NSString stringWithFormat:@"sfx_%d", idx]];
    for (NSString *ext in @[@"mp3", @"m4a", @"wav", @"caf"]) {
        NSString *p = [base stringByAppendingPathExtension:ext];
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            if ([[NSFileManager defaultManager] removeItemAtPath:p error:nil]) removed = YES;
        }
    }

    UInt32 n = 0;
    int16_t *fresh = kp_synth_sfx(idx, &n);
    int16_t *old = g_sfxClip[idx].pcm;

    g_sfxClip[idx].pcm = fresh;
    g_sfxClip[idx].len = n;

    if (old) {
        // 音频线程可能仍在读这块内存，延迟回收
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ free(old); });
    }
    kp_log(@"sfx %d reset (removed=%d)", idx, (int)removed);
    return removed;
}

// 删除伴奏：停播、释放、删文件
static void kp_delete_bgm(void) {
    g_bgmOn  = 0;
    g_bgmPos = 0;

    int16_t *old = g_bgmPcm;
    g_bgmPcm = NULL;
    g_bgmLen = 0;
    kp_bgm_retire(old);

    g_bgmName = nil;
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:KEY_BGM_NAME];
    kp_log(@"bgm cleared");
}

// ==========================================
// 7.5 话术板 Voice Bank：录制 / 播放 / 删除
// ==========================================
#define CLIP_SLOT        4
#define CLIP_SECONDS     60
#define CLIP_MAX_SAMPLES (48000 * CLIP_SECONDS)

static int16_t *g_clipPcm = NULL;
static _Atomic int g_clipLen = 0;
static _Atomic int g_clipPos = 0;
static _Atomic int g_clipOn  = 0;
static int g_clipPlayingSlot = -1;

// 录音状态：主线程分配/回收缓冲，音频线程只写，靠原子标志切换
static _Atomic int    g_recOn    = 0;
static _Atomic int    g_recCount = 0;
static int16_t       *g_recBuf   = NULL;
static int            g_recSlot  = 0;

// 录音缓冲延迟回收：刚停下时音频线程可能还在写这块内存
#define REC_RETIRE 2
static int16_t *g_recRetired[REC_RETIRE];
static int      g_recRetiredSlot = 0;

static NSString *kp_clip_dir(void) {
    NSString *dir = [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio/VoiceBank"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static NSString *kp_clip_path(int slot) {
    return [kp_clip_dir() stringByAppendingPathComponent:[NSString stringWithFormat:@"clip_%d.wav", slot]];
}

static BOOL kp_clip_exists(int slot) {
    return [[NSFileManager defaultManager] fileExistsAtPath:kp_clip_path(slot)];
}

// 48kHz 单声道 16bit WAV
static BOOL kp_write_wav(NSString *path, const int16_t *pcm, UInt32 count) {
    if (!path.length || !pcm || count == 0) return NO;
    FILE *f = fopen(path.UTF8String, "wb");
    if (!f) return NO;

    uint32_t dataSize = count * 2;
    uint32_t riffSize = 36 + dataSize;
    uint32_t rate     = 48000;
    uint32_t byteRate = rate * 2;
    uint16_t align    = 2;
    uint16_t bits     = 16;
    uint16_t chans    = 1;
    uint16_t fmt      = 1;
    uint32_t fmtSize  = 16;

    fwrite("RIFF", 1, 4, f);
    fwrite(&riffSize, 4, 1, f);
    fwrite("WAVEfmt ", 1, 8, f);
    fwrite(&fmtSize, 4, 1, f);
    fwrite(&fmt, 2, 1, f);
    fwrite(&chans, 2, 1, f);
    fwrite(&rate, 4, 1, f);
    fwrite(&byteRate, 4, 1, f);
    fwrite(&align, 2, 1, f);
    fwrite(&bits, 2, 1, f);
    fwrite("data", 1, 4, f);
    fwrite(&dataSize, 4, 1, f);
    size_t w = fwrite(pcm, 2, count, f);
    fclose(f);
    return w == (size_t)count;
}

static void kp_rec_start(int slot) {
    if (g_recOn) return;
    if (slot < 0 || slot >= CLIP_SLOT) slot = 0;

    int16_t *buf = (int16_t *)malloc((size_t)CLIP_MAX_SAMPLES * sizeof(int16_t));
    if (!buf) {
        kp_log(@"clip rec: malloc failed");
        return;
    }
    memset(buf, 0, (size_t)CLIP_MAX_SAMPLES * sizeof(int16_t));

    g_recBuf   = buf;
    g_recCount = 0;
    g_recSlot  = slot;
    g_recOn    = 1;
    kp_log(@"clip rec start slot=%d", slot);
}

// 录完统一推到满幅：峰值对齐到 32000，最多放 +18dB
static void kp_normalize_clip(int16_t *buf, int cnt) {
    if (!buf || cnt <= 0) return;
    float peak = 0.0f;
    for (int i = 0; i < cnt; i++) {
        float v = fabsf((float)buf[i]);
        if (v > peak) peak = v;
    }
    if (peak < 300.0f) return;                 // 几乎无声，不动
    float gain = 32000.0f / peak;
    if (gain > 8.0f)  gain = 8.0f;             // 最多 +18dB，防底噪爆炸
    if (gain > 0.999f && gain < 1.001f) return;
    for (int i = 0; i < cnt; i++) {
        float v = (float)buf[i] * gain;
        if (v > 32767.0f)  v = 32767.0f;
        if (v < -32768.0f) v = -32768.0f;
        buf[i] = (int16_t)v;
    }
    kp_log(@"clip normalize peak=%.0f gain=%.2fx", peak, gain);
}

static BOOL kp_rec_stop(void) {
    if (!g_recOn) return NO;
    g_recOn = 0;

    int cnt = g_recCount;
    int16_t *buf = g_recBuf;
    g_recBuf = NULL;
    g_recCount = 0;

    BOOL ok = NO;
    if (buf && cnt > 4800) {   // 至少 0.1 秒
        kp_normalize_clip(buf, cnt);
        ok = kp_write_wav(kp_clip_path(g_recSlot), buf, (UInt32)cnt);
    }

    if (buf) {
        if (g_recRetired[g_recRetiredSlot]) free(g_recRetired[g_recRetiredSlot]);
        g_recRetired[g_recRetiredSlot] = buf;
        g_recRetiredSlot = (g_recRetiredSlot + 1) % REC_RETIRE;
    }
    kp_log(@"clip rec stop slot=%d samples=%d ok=%d", g_recSlot, cnt, (int)ok);
    return ok;
}

static void kp_clip_stop(void) {
    g_clipOn = 0;
    g_clipPos = 0;
    g_clipPlayingSlot = -1;
}

static void kp_clip_play(int slot) {
    if (slot < 0 || slot >= CLIP_SLOT) return;

    // 再点同一句 = 停止
    if (g_clipOn && g_clipPlayingSlot == slot) {
        kp_clip_stop();
        kp_log(@"clip stop slot=%d", slot);
        return;
    }
    if (!kp_clip_exists(slot)) return;

    NSString *path = kp_clip_path(slot);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        UInt32 n = 0;
        int16_t *buf = kp_load_audio(path, &n);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!buf || n == 0) {
                kp_log(@"clip decode failed slot=%d", slot);
                return;
            }
            g_clipOn = 0;
            int16_t *old = g_clipPcm;
            g_clipPcm = buf;
            g_clipLen = (int)n;
            g_clipPos = 0;
            g_clipPlayingSlot = slot;
            kp_bgm_retire(old);
            g_clipOn = 1;
            kp_log(@"clip play slot=%d (%.1fs)", slot, (double)n / 48000.0);
        });
    });
}

static void kp_clip_delete(int slot) {
    if (g_clipPlayingSlot == slot) kp_clip_stop();
    [[NSFileManager defaultManager] removeItemAtPath:kp_clip_path(slot) error:nil];
    kp_log(@"clip delete slot=%d", slot);
}

// ==========================================
// 7.5 已停用：强制改写 App 的拾音开关会直接让采集失效
// （保留空实现，避免再被误调用）
// ==========================================
static void kp_unchain_builtin_limits(Class dev) {
    (void)dev;
}

// ==========================================
// 7.6 诊断探针（只读，不改任何行为）
// ==========================================
static double g_probeLast    = 0;
static long   g_probeCalls   = 0;
static long   g_probeFrames  = 0;
static int    g_probeInPeak  = 0;
static int    g_probeOutPeak = 0;
static double g_probeSumSq   = 0;
static long   g_probeSamples = 0;
static int    g_probeCh      = 0;

static void kp_probe_flush(void) {
    double now = CACurrentMediaTime();
    if (g_probeLast == 0.0) { g_probeLast = now; return; }
    if (now - g_probeLast < 5.0) return;
    double rms = (g_probeSamples > 0) ? sqrt(g_probeSumSq / (double)g_probeSamples) : 0.0;
    double db  = 20.0 * log10(rms > 1e-9 ? rms : 1e-9);
    kp_log(@"probe: calls=%ld frames=%ld ch=%d inPeak=%d%% outPeak=%d%% outRMS=%.1fdB",
           g_probeCalls, g_probeFrames, g_probeCh,
           g_probeInPeak, g_probeOutPeak, db);
    g_probeLast = now;
    g_probeCalls = 0; g_probeFrames = 0; g_probeCh = 0;
    g_probeInPeak = 0; g_probeOutPeak = 0;
    g_probeSumSq = 0; g_probeSamples = 0;
}

static void kp_probe_tick(const int16_t *pcm, UInt32 frames, UInt32 chs, BOOL primary) {
    kp_probe_flush();
    if (!primary) return;
    g_probeCalls++;
    g_probeFrames += frames;
    g_probeCh = (int)chs;
    UInt32 n = frames * chs;
    for (UInt32 i = 0; i < n; i++) {
        int a = pcm[i] < 0 ? -(int)pcm[i] : (int)pcm[i];
        int pct = a * 100 / 32768;
        if (pct > g_probeInPeak) g_probeInPeak = pct;
    }
}

static void kp_probe_out(const int16_t *pcm, UInt32 frames, UInt32 chs, BOOL primary) {
    if (!primary) return;
    UInt32 n = frames * chs;
    for (UInt32 i = 0; i < n; i++) {
        int a = pcm[i] < 0 ? -(int)pcm[i] : (int)pcm[i];
        int pct = a * 100 / 32768;
        if (pct > g_probeOutPeak) g_probeOutPeak = pct;
        double v = (double)pcm[i] * (1.0 / 32768.0);
        g_probeSumSq += v * v;
    }
    g_probeSamples += n;
}

// 方法存在性探测：只判断 selector 是否存在，不调用、不 Swizzle
static void kp_probe_selectors(void) {
    static BOOL once = NO;
    if (once) return;
    once = YES;

    Class dev = objc_getClass("KakaStereoAudioDevice");
    Class mix = objc_getClass("KakaAudioMixer");
    Class cfg = objc_getClass("RTCAudioProcessingConfig");
    Class adm = objc_getClass("RTCAudioDeviceModule");

    kp_log(@"probe: KakaStereoAudioDevice=%d gate=%d vp=%d", dev != NULL,
           dev && class_getInstanceMethod(dev, @selector(roomCaptureGateEnabled)) != NULL,
           dev && class_getInstanceMethod(dev, @selector(voiceProcessingActive)) != NULL);
    kp_log(@"probe: KakaAudioMixer=%d willEnableEngine=%d", mix != NULL,
           mix && class_getInstanceMethod(mix, @selector(audioDeviceModule:willEnableEngine:isPlayoutEnabled:isRecordingEnabled:isVoiceProcessingEnabled:)) != NULL);
    kp_log(@"probe: RTCAudioProcessingConfig=%d agc1set=%d agc2set=%d", cfg != NULL,
           cfg && class_getInstanceMethod(cfg, @selector(setIsAutoGainControl1Enabled:)) != NULL,
           cfg && class_getInstanceMethod(cfg, @selector(setIsAutoGainControl2Enabled:)) != NULL);
    kp_log(@"probe: RTCAudioDeviceModule=%d vpAGCset=%d", adm != NULL,
           adm && class_getInstanceMethod(adm, @selector(setVoiceProcessingAGCEnabled:)) != NULL);

    // v29.5：把这三个类的方法名打进日志，用于锁定远端播放/混音入口
    const char *names[3] = { "KakaStereoAudioDevice", "KakaAudioMixer", "KakaRoomMusicRenderer" };
    for (int k = 0; k < 3; k++) {
        Class c = objc_getClass(names[k]);
        if (!c) { kp_log(@"probe-m: %s 不存在", names[k]); continue; }
        unsigned int cnt = 0;
        Method *ms = class_copyMethodList(c, &cnt);
        kp_log(@"probe-m: %s 共 %u 个方法", names[k], cnt);
        unsigned int lim = cnt < 40 ? cnt : 40;
        for (unsigned int i = 0; i < lim; i++) kp_log(@"probe-m:   -[%s %s]", names[k], sel_getName(method_getName(ms[i])));
        if (ms) free(ms);
    }
    Class recv = objc_getClass("RTCRtpReceiver");
    Class trk  = objc_getClass("RTCAudioTrack");
    kp_log(@"probe: RTCRtpReceiver=%d RTCAudioTrack=%d", recv != NULL, trk != NULL);
}

// ==========================================
// 8. 主处理入口
// ==========================================
// ==========================================
// 授权模块 v27：Ed25519 签名 + 产品隔离 + 一机一码 + 熵解密参数表
// 私钥只在发码机里；本文件仅含混淆公钥，无法用于伪造授权码
// ==========================================
static NSString *const KP_PRODUCT_ID = @"KAKA_VOICE";

// Ed25519 公钥（32 字节，异或 0x5A 混淆，避免被字符串/特征搜索直接定位）
static const uint8_t KP_PUBKEY_OBF[32] = {
    0x19, 0x23, 0x01, 0xCD, 0xBA, 0xDB, 0xA3, 0x02,
    0x4A, 0xC8, 0x08, 0x6E, 0x78, 0x2E, 0xF3, 0x7F,
    0x35, 0xBC, 0x7A, 0xF1, 0x8A, 0xD7, 0x0E, 0xD3,
    0x09, 0xDA, 0xED, 0x82, 0xF5, 0x75, 0x78, 0xF2
};
static const uint8_t KP_PUBKEY_XOR = 0x5A;

// 核心参数表：加密后直接放在卡密里（AES-128-ECB，密钥 = 卡密里的 16 位随机熵）
// clientId 参与 check 校验，删掉/清零会让 token 校验一并失败 -> 直接静音
#define KP_DSP_TOKEN 0x5A5AA5A5u

#pragma pack(push, 1)
typedef struct {
    float    preamp;    //  0
    float    drive;     //  4
    float    ceiling;   //  8
    float    mix;       // 12
    uint32_t clientId;  // 16  买家编号（溯源）
    uint32_t token;     // 20
    uint32_t check;     // 24  FNV-1a(前 24 字节)
    uint32_t reserved;  // 28
} KPDspParams;          // 32 字节 = AES 分组整倍数
#pragma pack(pop)

static KPDspParams g_dspParams = { 0 };

static uint32_t kp_fnv1a(const uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static _Atomic BOOL g_licOk = NO;
static NSString *g_licExpireStr = @"未授权";
static NSString *g_licDevice   = @"";
static NSString *g_licReason   = @"未激活";

#define KP_LIC_CODE_NAME  @"lic.code"
#define KP_LIC_TS_NAME    @"lic.ts"

// Keychain：删 App 不会清除，用来存设备锚点与时间水印
static NSString *const KP_KC_SERVICE = @"com.kaka.voice.lic.v28";
static NSString *const KP_KC_SEED    = @"dev_seed";
static NSString *const KP_KC_TIME    = @"time_wm";
static NSString *const KP_KC_NET     = @"net_sync";

static void kp_log(NSString *fmt, ...);

static NSData *kp_kc_get(NSString *acct) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KP_KC_SERVICE,
        (__bridge id)kSecAttrAccount: acct,
        (__bridge id)kSecReturnData:  @YES
    };
    CFTypeRef out = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &out) == errSecSuccess) {
        return (__bridge_transfer NSData *)out;
    }
    return nil;
}

// 删除只用最小 query；写入时再带 value/accessibility，
// 避免把 value 属性混进删除条件导致 errSecParam
static BOOL kp_kc_set(NSString *acct, NSData *data) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KP_KC_SERVICE,
        (__bridge id)kSecAttrAccount: acct
    };
    SecItemDelete((__bridge CFDictionaryRef)q);

    NSMutableDictionary *add = [q mutableCopy];
    add[(__bridge id)kSecValueData]     = data;
    add[(__bridge id)kSecAttrAccessible] =
        (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    if (st != errSecSuccess) kp_log(@"LIC: keychain 写入失败 %d", (int)st);
    return st == errSecSuccess;
}

static long long kp_kc_get_ll(NSString *acct) {
    NSData *d = kp_kc_get(acct);
    long long v = 0;
    if (d.length == sizeof(v)) [d getBytes:&v length:sizeof(v)];
    return v;
}

static void kp_kc_set_ll(NSString *acct, long long v) {
    kp_kc_set(acct, [NSData dataWithBytes:&v length:sizeof(v)]);
}

static NSString *kp_lic_dir(void) {
    NSString *doc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [doc stringByAppendingPathComponent:@"KakaAudio"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

// 降级：keychain 不可用（重签缺 entitlement 报 -34018）时退回 IDFV
static NSString *kp_lic_idfv_raw(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    if (!idfv) idfv = @"";
    NSString *s = [[[idfv stringByReplacingOccurrencesOfString:@"-" withString:@""]
                    stringByReplacingOccurrencesOfString:@" " withString:@""] uppercaseString];
    if (s.length < 16) return @"0000000000000000";
    return [s substringToIndex:16];
}

// 设备码：32 字节随机锚点存 keychain -> SHA256 -> 前 16 位
// keychain 项是 ThisDeviceOnly，不可迁移、删 App 不清除
static NSString *kp_lic_dev_raw(void) {
    static NSString *cached = nil;
    if (cached) return cached;

    NSData *seed = kp_kc_get(KP_KC_SEED);
    if (seed.length != 32) {
        uint8_t r[32];
        if (SecRandomCopyBytes(kSecRandomDefault, 32, r) == errSecSuccess) {
            NSData *d = [NSData dataWithBytes:r length:32];
            if (kp_kc_set(KP_KC_SEED, d)) seed = d;
        }
    }

    if (seed.length == 32) {
        uint8_t dg[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(seed.bytes, (CC_LONG)seed.length, dg);
        char hex[17];
        for (int i = 0; i < 8; i++) sprintf(hex + i * 2, "%02X", dg[i]);
        hex[16] = '\0';
        cached = [NSString stringWithUTF8String:hex];
        kp_log(@"LIC: 设备锚点取自 keychain");
    } else {
        cached = kp_lic_idfv_raw();
        kp_log(@"LIC: keychain 不可用，设备码降级为 IDFV");
    }
    return cached;
}

static NSString *kp_lic_dev_disp(void) {
    NSString *r = kp_lic_dev_raw();
    return [NSString stringWithFormat:@"%@-%@-%@-%@",
            [r substringWithRange:NSMakeRange(0, 4)],
            [r substringWithRange:NSMakeRange(4, 4)],
            [r substringWithRange:NSMakeRange(8, 4)],
            [r substringWithRange:NSMakeRange(12, 4)]];
}

static NSString *kp_lic_norm(NSString *s) {
    if (!s) return @"";
    NSString *t = [s stringByReplacingOccurrencesOfString:@"-" withString:@""];
    t = [t stringByReplacingOccurrencesOfString:@" " withString:@""];
    t = [t stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    return [t uppercaseString];
}

// 时间水印：keychain + 文件 + 偏好三处取最大值
// keychain 那一路删 App 也不会清，是防"重装洗时间"的关键
static long long kp_lic_last_ts(void) {
    long long a = kp_kc_get_ll(KP_KC_TIME);
    long long b = 0, c = 0;
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_TS_NAME];
    NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    if (s.length) b = [s longLongValue];
    c = (long long)[[NSUserDefaults standardUserDefaults] doubleForKey:@"kaka_lic_ts"];
    long long m = (a > b) ? a : b;
    return (m > c) ? m : c;
}

// 无条件写入三处（允许下调），只给"可信网络时间"用
static void kp_lic_force_ts(long long ts) {
    if (ts <= 0) return;
    kp_kc_set_ll(KP_KC_TIME, ts);
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_TS_NAME];
    [[NSString stringWithFormat:@"%lld", ts] writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setDouble:(double)ts forKey:@"kaka_lic_ts"];
    [ud synchronize];
}

// trusted=YES 是网络取到的权威时间：可直接覆盖（含向下修正）
// trusted=NO  是本机时间：只增不减，且单次最多前进 1 天
static void kp_lic_save_ts(long long ts, BOOL trusted) {
    if (ts <= 0) return;
    if (trusted) { kp_lic_force_ts(ts); return; }

    long long last = kp_lic_last_ts();
    long long v = ts;
    if (last > 0 && ts > last + 86400LL) v = last + 86400LL;
    if (v <= last) return;
    kp_lic_force_ts(v);
}

// 同步取一次权威时间（激活路径专用，最多阻塞约 5 秒；失败返回 0）
static long long kp_lic_fetch_net_time(void) {
    NSArray *urls = @[@"https://captive.apple.com/hotspot-detect.html",
                      @"https://www.apple.com/library/test/success.html"];
    for (NSString *u in urls) {
        __block long long got = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        NSMutableURLRequest *req =
            [NSMutableURLRequest requestWithURL:[NSURL URLWithString:u]
                                    cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                timeoutInterval:2.5];
        req.HTTPMethod = @"HEAD";

        [[[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *d, NSURLResponse *resp, NSError *err) {
                if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                    NSString *ds = ((NSHTTPURLResponse *)resp).allHeaderFields[@"Date"];
                    if (ds) {
                        NSDateFormatter *df = [[NSDateFormatter alloc] init];
                        df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
                        df.dateFormat = @"EEE, dd MMM yyyy HH:mm:ss zzz";
                        NSDate *nd = [df dateFromString:ds];
                        if (nd) got = (long long)[nd timeIntervalSince1970];
                    }
                }
                dispatch_semaphore_signal(sem);
        }] resume];

        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
        if (got > 1704067200LL) return got;
    }
    return 0;
}

// 机会主义对时：HEAD 苹果的联网探测页，只取响应头 Date
// 6 小时内只打一次，成功则把权威时间写进水印（不受 1 天跳变限制）
static void kp_lic_net_sync(void) {
    long long lastSync = kp_kc_get_ll(KP_KC_NET);
    long long now = (long long)[[NSDate date] timeIntervalSince1970];
    if (lastSync > 0 && now >= lastSync && now - lastSync < 6 * 3600LL) return;

    NSURL *url = [NSURL URLWithString:@"https://captive.apple.com/hotspot-detect.html"];
    NSMutableURLRequest *req =
        [NSMutableURLRequest requestWithURL:url
                                cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                            timeoutInterval:4.0];
    req.HTTPMethod = @"HEAD";

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *resp, NSError *err) {
            if (![resp isKindOfClass:[NSHTTPURLResponse class]]) return;
            NSString *ds = ((NSHTTPURLResponse *)resp).allHeaderFields[@"Date"];
            if (!ds) return;

            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
            df.dateFormat = @"EEE, dd MMM yyyy HH:mm:ss zzz";
            NSDate *nd = [df dateFromString:ds];
            if (!nd) return;

            long long netTS = (long long)[nd timeIntervalSince1970];
            if (netTS < 1704067200LL) return;

            kp_lic_save_ts(netTS, YES);
            kp_kc_set_ll(KP_KC_NET, netTS);
            kp_log(@"LIC: 联网对时成功 %lld", netTS);
    }] resume];
}

// 只认 Frida 这类明确特征；不再拉黑 libhooker / cydiaubiquitous，
// 否则正常越狱用户会被误杀成"卡密无效"
static BOOL kp_lic_env_safe(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "FridaGadget") || strstr(nm, "frida-agent")) {
            kp_log(@"LIC: 检测到 Frida 注入 %s", nm);
            return NO;
        }
    }
    return YES;
}

static NSString *kp_lic_stored_code(void) {
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_CODE_NAME];
    NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    if (s.length) return s;
    return [[NSUserDefaults standardUserDefaults] stringForKey:@"kaka_lic_code"];
}

static void kp_lic_store_code(NSString *code) {
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_CODE_NAME];
    [code writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:code forKey:@"kaka_lic_code"];
    [ud synchronize];
}

// 用卡密自带的熵解出参数表（密文也在卡密里，dylib 不再存任何明文参数）
// 三重校验：长度 -> token -> FNV 完整性（含 clientId），任一失败参数保持全 0
static void kp_dsp_inject(NSString *entropyHex, NSString *encB64) {
    memset(&g_dspParams, 0, sizeof(g_dspParams));
    if (entropyHex.length != 16) { kp_log(@"LIC: 熵长度异常"); return; }

    NSData *enc = [[NSData alloc] initWithBase64EncodedString:encB64 options:0];
    if (enc.length != sizeof(KPDspParams)) {
        kp_log(@"LIC: 参数密文长度异常 %lu", (unsigned long)enc.length);
        return;
    }

    uint8_t key[16];
    memcpy(key, entropyHex.UTF8String, 16);

    uint8_t plain[32];
    kpa_decrypt_ecb(key, enc.bytes, plain, 32);

    KPDspParams tmp;
    memcpy(&tmp, plain, sizeof(KPDspParams));

    if (tmp.token != KP_DSP_TOKEN) {
        kp_log(@"LIC: 参数表解密失败（熵不匹配）");
        return;
    }
    if (tmp.check != kp_fnv1a(plain, 24)) {
        kp_log(@"LIC: 参数完整性校验失败（可能被篡改）");
        return;
    }

    g_dspParams = tmp;
    kp_log(@"LIC: 参数已注入 client=#%u preamp=%.2f drive=%.2f",
           tmp.clientId, tmp.preamp, tmp.drive);
}

// 授权码里除签名段外都可能被微信插入空白，全部剥掉再验
static NSString *kp_lic_clean(NSString *code) {
    if (!code) return @"";
    NSMutableString *m = [NSMutableString stringWithCapacity:code.length];
    for (NSUInteger i = 0; i < code.length; i++) {
        unichar ch = [code characterAtIndex:i];
        if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' || ch == 0x3000) continue;
        [m appendFormat:@"%C", ch];
    }
    return m;
}

static BOOL kp_lic_verify(NSString *code) {
    g_licOk = NO;
    g_licReason = @"未激活";
    memset(&g_dspParams, 0, sizeof(g_dspParams));

    // 环境自检 + 后台对时（对时不阻塞本次校验）
    if (!kp_lic_env_safe()) { g_licReason = @"运行环境异常"; return NO; }
    kp_lic_net_sync();

    NSString *c = kp_lic_clean(code);
    if (c.length < 40) { g_licReason = @"授权码格式错误"; return NO; }

    NSArray *parts = [c componentsSeparatedByString:@"."];
    if (parts.count != 2) { g_licReason = @"授权码格式错误"; return NO; }

    NSString *payload = parts[0];
    NSData *sigData = [[NSData alloc] initWithBase64EncodedString:parts[1] options:0];
    if (sigData.length != 64) {
        g_licReason = @"签名长度异常";
        kp_log(@"LIC: 签名长度 %lu", (unsigned long)sigData.length);
        return NO;
    }

    // ① 先验签：Ed25519（64 字节签名 + 明文载荷）
    NSData *msgData = [payload dataUsingEncoding:NSUTF8StringEncoding];
    if (!msgData || msgData.length == 0) { g_licReason = @"载荷为空"; return NO; }

    uint8_t pk[32];
    for (int i = 0; i < 32; i++) pk[i] = KP_PUBKEY_OBF[i] ^ KP_PUBKEY_XOR;

    size_t smLen = 64 + msgData.length;
    uint8_t *sm = (uint8_t *)malloc(smLen);
    uint8_t *mo = (uint8_t *)malloc(smLen);
    if (!sm || !mo) { free(sm); free(mo); g_licReason = @"内存不足"; return NO; }

    memcpy(sm, sigData.bytes, 64);
    memcpy(sm + 64, msgData.bytes, msgData.length);

    unsigned long long moLen = 0;
    int vret = crypto_sign_open(mo, &moLen, sm, smLen, pk);
    free(sm);
    free(mo);

    if (vret != 0) {
        g_licReason = @"签名校验失败（伪造或已损坏）";
        kp_log(@"LIC: 验签失败 ret=%d", vret);
        return NO;
    }

    // ② 载荷五段：产品#设备#到期#熵#参数密文
    NSArray *fields = [payload componentsSeparatedByString:@"#"];
    if (fields.count != 5) {
        g_licReason = @"授权码内容异常";
        kp_log(@"LIC: 载荷段数 %lu", (unsigned long)fields.count);
        return NO;
    }

    NSString *prodID  = fields[0];
    NSString *devID   = kp_lic_norm(fields[1]);
    NSString *expStr  = fields[2];
    NSString *entropy = fields[3];
    NSString *encB64  = fields[4];

    // ③ 产品隔离：买一个插件不能解锁全部
    if (![prodID isEqualToString:KP_PRODUCT_ID]) {
        g_licReason = @"授权码不属于本插件";
        kp_log(@"LIC: 产品不匹配 %@", prodID);
        return NO;
    }

    // ④ 一机一码
    if (![devID isEqualToString:kp_lic_dev_raw()]) {
        g_licReason = @"设备码不匹配（此码属于另一台设备）";
        kp_log(@"LIC: 设备不匹配 %@ != %@", devID, kp_lic_dev_raw());
        return NO;
    }

    // ⑤ 熵必须是 16 位十六进制（同时就是 AES 密钥）
    BOOL hexOk = (entropy.length == 16);
    for (NSUInteger i = 0; hexOk && i < entropy.length; i++) {
        unichar ch = [entropy characterAtIndex:i];
        BOOL isHex = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F');
        if (!isHex) hexOk = NO;
    }
    if (!hexOk) {
        g_licReason = @"授权码内容异常";
        kp_log(@"LIC: 熵非法 [%@]", entropy);
        return NO;
    }
    if (encB64.length < 40) { g_licReason = @"授权码内容异常"; return NO; }

    // ⑥ 到期字段强校验：必须 10 位纯数字，且落在 2024-01-01 ~ 2038-01-19
    BOOL digits = (expStr.length == 10);
    for (NSUInteger i = 0; digits && i < expStr.length; i++) {
        unichar ch = [expStr characterAtIndex:i];
        if (ch < '0' || ch > '9') digits = NO;
    }
    if (!digits) {
        g_licReason = @"到期字段异常";
        kp_log(@"LIC: 到期字段非法 [%@]", expStr);
        return NO;
    }
    long long exp = [expStr longLongValue];
    if (exp < 1704067200LL || exp > 2147483647LL) {
        g_licReason = @"到期时间越界";
        return NO;
    }

    // ⑦ 时间判定：以「本机时间」和「历史水印」中较晚者为准
    // 水印在 keychain 里，删 App 也不会丢 -> 把表调回去骗不过去
    long long now = (long long)[[NSDate date] timeIntervalSince1970];
    long long wm  = kp_lic_last_ts();
    long long eff = (wm > now) ? wm : now;

    if (wm > 0 && now + 300 < wm) {
        // 水印比本机时间还超前：多半是用户自己把表调错过（测试/误调）。
        // 用网络权威时间去校正水印——真实网络时间不可能比历史水印更早，
        // 所以这里的"允许下调"对故意回拨的攻击者没有任何帮助。
        long long netTS = kp_lic_fetch_net_time();
        if (netTS > 0) {
            kp_lic_force_ts(netTS);
            kp_kc_set_ll(KP_KC_NET, netTS);
            kp_log(@"LIC: 时间校正 now=%lld 旧水印=%lld 网络=%lld", now, wm, netTS);
            wm  = netTS;
            eff = (wm > now) ? wm : now;
        }
        if (now + 300 < wm) {
            g_licReason = @"检测到系统时间被回拨";
            kp_log(@"LIC: 时间回拨 now=%lld wm=%lld", now, wm);
            return NO;
        }
    }

    if (eff > exp) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"yyyy-MM-dd HH:mm"];
        g_licExpireStr = [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)exp]];
        g_licReason = [NSString stringWithFormat:@"已过期（%@）", g_licExpireStr];
        kp_log(@"LIC: 已过期 eff=%lld exp=%lld", eff, exp);
        return NO;
    }

    // 通过全部校验后才推进水印，防止改到 2038 把水印顶死导致自锁
    kp_lic_save_ts(now, NO);

    // ⑧ 用卡密自带的熵解出参数表：没有这一步，DSP 拿到的是全 0
    kp_dsp_inject(entropy, encB64);
    if (g_dspParams.token != KP_DSP_TOKEN) {
        g_licReason = @"参数激活失败";
        return NO;
    }

    NSDateFormatter *df2 = [[NSDateFormatter alloc] init];
    [df2 setDateFormat:@"yyyy-MM-dd HH:mm"];
    g_licExpireStr = [df2 stringFromDate:[NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)exp]];
    g_licOk = YES;
    g_licReason = @"已授权";
    kp_log(@"LIC: 授权通过，到期 %@", g_licExpireStr);
    return YES;
}

static BOOL kp_lic_activate(NSString *code) {
    BOOL ok = kp_lic_verify(code);
    if (ok) kp_lic_store_code([code stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]);
    return ok;
}

static void kp_lic_load(void) {
    g_licDevice = kp_lic_dev_disp();
    NSString *saved = kp_lic_stored_code();
    if (saved.length) kp_lic_verify(saved);
    else kp_log(@"LIC: 未检测到授权码");
}

// 独立授权窗口：浮窗是自建 UIWindow，普通 present 会被它盖住/吃不到点击，
// 所以用一个更高层级的专用窗口承载弹窗，保证可见、可点。
static UIButton *g_licBar = nil;

static void kp_lic_refresh_bar(void) {
    if (!g_licBar) return;
    if (g_licOk) {
        [g_licBar setTitle:[NSString stringWithFormat:@"%@  已授权 · 到期 %@", KP_VERSION, g_licExpireStr]
                  forState:UIControlStateNormal];
        [g_licBar setTitleColor:[UIColor colorWithWhite:0.40 alpha:1.0] forState:UIControlStateNormal];
        g_licBar.backgroundColor = [UIColor clearColor];
    } else {
        [g_licBar setTitle:[NSString stringWithFormat:@"未授权 · 点此激活   设备码 %@", kp_lic_dev_disp()]
                  forState:UIControlStateNormal];
        [g_licBar setTitleColor:[UIColor colorWithRed:1.0 green:0.62 blue:0.52 alpha:1.0]
                       forState:UIControlStateNormal];
        g_licBar.backgroundColor = [UIColor colorWithRed:0.52 green:0.12 blue:0.10 alpha:0.95];
    }
}

static UIWindow *g_licWin = nil;

static UIAlertController *kp_lic_build_alert(void) {
    NSString *state = g_licOk
        ? [NSString stringWithFormat:@"已授权，到期 %@", g_licExpireStr]
        : [NSString stringWithFormat:@"未授权（%@）", g_licReason];

    NSString *msg = [NSString stringWithFormat:
                     @"本机设备码：\n%@\n\n当前状态：%@\n\n把设备码发给作者换授权码，粘贴到下方后点【立即激活】。",
                     kp_lic_dev_disp(), state];

    UIAlertController *al = [UIAlertController alertControllerWithTitle:@"授权激活"
                                                                message:msg
                                                         preferredStyle:UIAlertControllerStyleAlert];
    [al addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"粘贴授权码（很长）";
        tf.font = [UIFont systemFontOfSize:10];
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];

    __weak UIAlertController *weakAl = al;
    [al addAction:[UIAlertAction actionWithTitle:@"复制设备码" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) {
        [UIPasteboard generalPasteboard].string = kp_lic_dev_disp();
        kp_log(@"LIC: 设备码已复制 %@", kp_lic_dev_disp());
        UIAlertController *tip = [UIAlertController alertControllerWithTitle:@"已复制"
                                                                    message:kp_lic_dev_disp()
                                                             preferredStyle:UIAlertControllerStyleAlert];
        [tip addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *b) {
            UIAlertController *again = kp_lic_build_alert();
            [g_licWin.rootViewController presentViewController:again animated:YES completion:nil];
        }]];
        [g_licWin.rootViewController presentViewController:tip animated:YES completion:nil];
    }]];

    [al addAction:[UIAlertAction actionWithTitle:@"立即激活" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) {
        NSString *input = weakAl.textFields.firstObject.text;
        BOOL ok = kp_lic_activate(input);
        NSString *t = ok ? @"激活成功" : @"激活失败";
        NSString *m = ok ? [NSString stringWithFormat:@"已授权，到期 %@", g_licExpireStr] : g_licReason;
        UIAlertController *r = [UIAlertController alertControllerWithTitle:t message:m
                                                           preferredStyle:UIAlertControllerStyleAlert];
        [r addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *b) {
            if (ok) {
                g_licWin.hidden = YES;
                g_licWin = nil;
                kp_lic_refresh_bar();
            }
        }]];
        [g_licWin.rootViewController presentViewController:r animated:YES completion:nil];
    }]];

    [al addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel
                                        handler:^(UIAlertAction *a) {
        g_licWin.hidden = YES;
        g_licWin = nil;
    }]];
    return al;
}

static void kp_lic_show_alert(void) {
    if (g_licWin) return;

    CGRect scr = [UIScreen mainScreen].bounds;
    g_licWin = [[UIWindow alloc] initWithFrame:scr];
    g_licWin.windowLevel = UIWindowLevelAlert + 200;
    g_licWin.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.45];

    UIViewController *host = [[UIViewController alloc] init];
    host.view.backgroundColor = [UIColor clearColor];
    g_licWin.rootViewController = host;

    // iOS 13+ 必须绑定 windowScene，否则窗口不显示
    if (@available(iOS 13.0, *)) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.windowScene) { g_licWin.windowScene = w.windowScene; break; }
        }
    }

    [g_licWin makeKeyAndVisible];
    [host presentViewController:kp_lic_build_alert() animated:YES completion:nil];
    kp_log(@"LIC: 打开授权窗口");
}

#define KP_PROC_CHUNK 1024

static inline void kp_process_pcm(int16_t *pcm, UInt32 frames, UInt32 chs, BOOL isPrimary) {
    if (!g_licOk) return;
    if (!pcm || frames == 0) return;
    if (chs < 1) chs = 1;
    if (chs > 2) chs = 2;
    if (g_dspParams.token != KP_DSP_TOKEN) {
        memset(pcm, 0, (size_t)frames * chs * sizeof(int16_t));
        return;
    }

    kp_probe_tick(pcm, frames, chs, isPrimary);
    UInt32 chOff = isPrimary ? 0 : 4;
    const KPFilterBank *bank = &g_filterBanks[g_activeBank];
    g_grCompPeak = 0.0f;
    g_grLimPeak  = 0.0f;

    UInt32 total = frames * chs;
    float rawPeak = 0.0f;
    for (UInt32 i = 0; i < total; i++) {
        float r = fabsf((float)pcm[i]) * (1.0f / 32768.0f);
        if (r > rawPeak) rawPeak = r;
    }

    if (isPrimary && g_pitchEnabled) {
        kp_pitch_process_s16(pcm, frames, chs);
    }

    float gain = g_makeupGain;
    float ceilNorm = g_limiterCeiling * (1.0f / 32768.0f);
    if (ceilNorm > 0.999f) ceilNorm = 0.999f;
    float outPeak = 0.0f;
    float fs = g_sampleRate > 8000.0f ? g_sampleRate : 48000.0f;
    float sumSq = 0.0f;
    int   rmsCnt = 0;

    float fbuf[2 * KP_PROC_CHUNK];
    for (UInt32 f0 = 0; f0 < frames; f0 += KP_PROC_CHUNK) {
        UInt32 curFrames = frames - f0;
        if (curFrames > KP_PROC_CHUNK) curFrames = KP_PROC_CHUNK;
        int16_t *subPcm = pcm + f0 * chs;

        for (UInt32 f = 0; f < curFrames; f++) {
            for (UInt32 c = 0; c < chs; c++) {
                float s = (float)subPcm[f * chs + c];
                if (isPrimary) {
                    s = kp_voice_pre_sample(s, chOff + c, bank);
                } else if (g_compEnabled) {
                    s = kp_comp_sample(s * (1.0f / 32768.0f), chOff + c) * 32768.0f;
                }
                fbuf[f * chs + c] = s;
            }
        }

        if (isPrimary && g_recOn) {
            int16_t *rb = g_recBuf;
            if (rb) {
                int cnt = g_recCount;
                for (UInt32 f = 0; f < curFrames && cnt < CLIP_MAX_SAMPLES; f++) {
                    float rv = fbuf[f * chs];
                    if (rv > 32767.0f) rv = 32767.0f;
                    if (rv < -32768.0f) rv = -32768.0f;
                    rb[cnt++] = (int16_t)rv;
                }
                g_recCount = cnt;
            }
        }

        if (isPrimary) {
            BOOL clipOn = (g_clipOn != 0);
            BOOL duckOn = g_duckEnabled;   // v30.1：闪避只由“说话闪避”开关决定，一键锁定不再强制
            float floorV = g_bgmDuckFloor > 0.02f ? g_bgmDuckFloor : 0.20f;
            float target = (duckOn && (rawPeak > 0.025f || clipOn)) ? floorV : 1.0f;
            float dt  = (float)curFrames / fs;
            float tau = (target < g_duckGain) ? 0.030f : 0.280f;
            float a   = 1.0f - expf(-dt / tau);
            if (a > 1.0f) a = 1.0f;
            g_duckGain += (target - g_duckGain) * a;

            // v30.1：取消“人声给伴奏让幅”，BGM 与人声同级，靠限幅总线统一控峰
        }

        for (UInt32 f = 0; f < curFrames; f++) {
            float L = fbuf[f * chs] * (1.0f / 32768.0f);
            float R = (chs >= 2) ? (fbuf[f * chs + 1] * (1.0f / 32768.0f)) : L;

            // v30.0：删除 Suya 延迟声场（ch=1 单声道做 7ms/13ms 延迟叠加，
            // 会与直达声形成梳状滤波：金属空洞感 + 多人麦极易发糊、被误判回声）
            // v30.0：删除 bassLANE 低频归中（全链路单声道采集，低频本来就无左右可分）
            if (isPrimary && g_reverbEnabled) {
                float wL = kp_reverb_tick(L * 32768.0f, 0) * (1.0f / 32768.0f);
                float wR = (chs >= 2) ? (kp_reverb_tick(R * 32768.0f, 1) * (1.0f / 32768.0f)) : wL;
                L = L * (1.0f - g_reverbWet) + wL * g_reverbWet;
                R = R * (1.0f - g_reverbWet) + wR * g_reverbWet;
            }

            L *= gain * g_rmsTrim;
            R *= gain * g_rmsTrim;

            // v30.1：BGM/音效/话术移入限幅器【之前】，与人声共用同一条防掐断总线。
            // 人声+伴奏作为一个整体过前瞻限幅，波峰因数保留，网关才会把它当正常语音流放行。
            if (isPrimary) {
                float mus = 0.0f;
                for (int s = 0; s < SFX_SLOT; s++) {
                    if (!g_sfxOn[s]) continue;
                    int pos = g_sfxPos[s];
                    if (pos >= (int)g_sfxClip[s].len) { g_sfxOn[s] = 0; continue; }
                    mus += (float)g_sfxClip[s].pcm[pos] * g_sfxVolume;
                    g_sfxPos[s] = pos + 1;
                }
                if (g_bgmOn && g_bgmPcm && g_bgmLen > 0) {
                    int pos = g_bgmPos;
                    if (pos >= g_bgmLen) pos = 0;   // 自动无缝循环
                    // 只有在“说话闪避”打开时才让位，否则 BGM 全功率与人声平级
                    float duckFactor = g_duckEnabled ? g_duckGain : 1.0f;
                    mus += (float)g_bgmPcm[pos] * g_bgmVolume * duckFactor;
                    g_bgmPos = pos + 1;
                }
                if (g_clipOn && g_clipPcm && g_clipLen > 0) {
                    int pos = g_clipPos;
                    if (pos >= g_clipLen && g_clipLoop) pos = 0;
                    if (pos < g_clipLen) {
                        mus += (float)g_clipPcm[pos];
                        g_clipPos = pos + 1;
                    } else {
                        g_clipOn = 0;
                        g_clipPlayingSlot = -1;
                    }
                }
                if (mus != 0.0f) {
                    float m = mus * (1.0f / 32768.0f);
                    // 音乐自身先做一次软封顶，避免单路就把总线顶穿
                    if (m > 0.65f)  m = 0.65f + 0.15f * tanhf((m - 0.65f) * 4.0f);
                    if (m < -0.65f) m = -0.65f + 0.15f * tanhf((m + 0.65f) * 4.0f);
                    L += m;
                    R += m;
                }
            }

            // 人声+BGM 一起进前瞻限幅，输出峰值锁在 ceiling，不产生方波
            if (g_limiterEnabled && g_boostOn) {
                L = kp_limiter_tick(L, chOff + 0, ceilNorm);
                if (chs >= 2) R = kp_limiter_tick(R, chOff + 1, ceilNorm);
            } else {
                L = tanhf(L) * ceilNorm;
                if (chs >= 2) R = tanhf(R) * ceilNorm;
            }

            float pL = fabsf(L), pR = (chs >= 2) ? fabsf(R) : 0.0f;
            if (pL > outPeak) outPeak = pL;
            if (pR > outPeak) outPeak = pR;
            if (isPrimary) { sumSq += L * L; rmsCnt++; }

            int32_t iL = (int32_t)(L * 32767.0f);
            if (iL > 32767) iL = 32767;
            if (iL < -32768) iL = -32768;
            subPcm[f * chs] = (int16_t)iL;

            if (chs >= 2) {
                int32_t iR = (int32_t)(R * 32767.0f);
                if (iR > 32767) iR = 32767;
                if (iR < -32768) iR = -32768;
                subPcm[f * chs + 1] = (int16_t)iR;
            }
        }

        // 输出 RMS 护栏：目标 -9dBFS，超标快压、回落慢放，只压不提
        if (isPrimary && rmsCnt > 0) {
            float rms = sqrtf(sumSq / (float)rmsCnt);
            if (rms > 0.0001f) {
                // v30.2：霸麦目标 -10.5dBFS（0.300），普通 -11dBFS（0.280）
                // 比原来 -8dBFS 多留 2.5dB 波峰余量，网关不会把这条流判成持续噪音
                float tgt = g_priorityLoud ? 0.300f : 0.280f;
                float want = tgt / rms;
                if (want > 1.0f) want = 1.0f;
                float coef = (want < g_rmsTrim) ? 0.12f : 0.005f;
                g_rmsTrim += (want - g_rmsTrim) * coef;
                if (g_rmsTrim < 0.20f) g_rmsTrim = 0.20f;
                if (g_rmsTrim > 1.0f)  g_rmsTrim = 1.0f;
            }
            sumSq = 0.0f;
            rmsCnt = 0;
        }
    }

    kp_probe_out(pcm, frames, chs, isPrimary);
    int vuIn  = (int)(rawPeak * 100.0f); if (vuIn > 100)  vuIn = 100;
    int vuOut = (int)(outPeak * 100.0f); if (vuOut > 100) vuOut = 100;
    float maxGr = (g_grCompPeak > g_grLimPeak) ? g_grCompPeak : g_grLimPeak;
    int vuGr  = (int)maxGr;              if (vuGr > 100)  vuGr = 100;

    if (isPrimary) {
        if (vuIn > g_vuIn)   g_vuIn = vuIn;
        if (vuOut > g_vuOut) g_vuOut = vuOut;
        if (vuGr > g_vuGr)   g_vuGr = vuGr;
        if (vuOut > g_vuMic) g_vuMic = vuOut;
    } else {
        if (vuOut > g_vuMix) g_vuMix = vuOut;
    }
    g_frames++;
}

// ==========================================
// 8. Hook：KakaStereoAudioDevice + KakaAudioMixer
// ==========================================
static int  (*orig_deliverPCM)(id, SEL, int16_t *, unsigned int, unsigned long long, const AudioTimeStamp *) = NULL;
static void (*orig_mixerPCM)(id, SEL, int16_t *, unsigned long long, unsigned long long, double) = NULL;
static void (*orig_willEnableEngine)(id, SEL, id, BOOL, BOOL, BOOL, BOOL) = NULL;
static BOOL (*orig_captureGate)(id, SEL) = NULL;
static void (*orig_setCaptureGate)(id, SEL, BOOL) = NULL;
static BOOL (*orig_speakerAEC)(id, SEL) = NULL;
static void (*orig_setSpeakerAEC)(id, SEL, BOOL) = NULL;
static void (*orig_stopRecording)(id, SEL) = NULL;

static BOOL kp_hook_capture_gate(id self, SEL _cmd) {
    if (g_dspEnabled || g_priorityLoud) return NO;
    return orig_captureGate ? orig_captureGate(self, _cmd) : NO;
}
static void kp_hook_set_capture_gate(id self, SEL _cmd, BOOL en) {
    if (orig_setCaptureGate) {
        BOOL v = (g_dspEnabled || g_priorityLoud) ? NO : en;
        orig_setCaptureGate(self, _cmd, v);
    }
}
static BOOL kp_hook_speaker_aec(id self, SEL _cmd) {
    if (g_losslessPriority || g_priorityLoud || g_shieldRemote) return NO;
    return orig_speakerAEC ? orig_speakerAEC(self, _cmd) : NO;
}
static void kp_hook_set_speaker_aec(id self, SEL _cmd, BOOL en) {
    if (orig_setSpeakerAEC) {
        BOOL v = (g_losslessPriority || g_priorityLoud || g_shieldRemote) ? NO : en;
        orig_setSpeakerAEC(self, _cmd, v);
    }
}
static void kp_hook_stop_recording(id self, SEL _cmd) {
    kp_log(@"[mic-guard] stopRecording called");
    if (orig_stopRecording) orig_stopRecording(self, _cmd);
}
static void kp_hook_will_enable_engine(id self, SEL _cmd, id adm, BOOL eng, BOOL playout, BOOL rec, BOOL vp) {
    // VP 只在“深度旁路 / 强声霸麦 / 屏蔽器”任一开启时强制关，默认保持原样
    BOOL forceOff = (g_deepBypassVP || g_priorityLoud || g_shieldRemote);
    if (vp) {
        kp_log(@"[engine] willEnable=%d play=%d rec=%d vp=%d->%d",
               (int)eng, (int)playout, (int)rec, (int)vp, (int)(forceOff ? 0 : vp));
    }
    if (orig_willEnableEngine) {
        orig_willEnableEngine(self, _cmd, adm, eng, playout, rec, forceOff ? NO : vp);
    }
}

static int kp_deliver_pcm(id self, SEL _cmd, int16_t *pcm, unsigned int frames, unsigned long long channels, const AudioTimeStamp *ts) {
    g_pcmCalls++;
    if (g_dspEnabled && pcm && frames > 0) {
        kp_process_pcm(pcm, frames, (UInt32)channels, YES);
    }
    return orig_deliverPCM(self, _cmd, pcm, frames, channels, ts);
}

static void kp_mixer_pcm(id self, SEL _cmd, int16_t *pcm, unsigned long long frames, unsigned long long channels, double rate) {
    g_mixCalls++;
    if (rate >= 8000.0 && rate <= 96000.0 && fabsf((float)rate - g_sampleRate) > 10.0f) {
        g_sampleRate = (float)rate;
        kp_rebuild_filter_bank();
    }
    if (g_dspEnabled && (g_mixDspEnabled || g_losslessPriority) && pcm && frames > 0) {
        kp_process_pcm(pcm, (UInt32)frames, (UInt32)channels, NO);
    }
    orig_mixerPCM(self, _cmd, pcm, frames, channels, rate);
}

static int kp_install_hooks(void) {
    int state = 0;
    Class dev = objc_getClass("KakaStereoAudioDevice");
    if (dev) {
        Method m = class_getInstanceMethod(dev, @selector(deliverPCM:frames:channels:timestamp:));
        if (m && !orig_deliverPCM) {
            orig_deliverPCM = (int (*)(id, SEL, int16_t *, unsigned int, unsigned long long, const AudioTimeStamp *))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_deliver_pcm);
        }
        if (orig_deliverPCM) state |= 1;

        Method mg = class_getInstanceMethod(dev, @selector(roomCaptureGateEnabled));
        if (mg && !orig_captureGate) {
            orig_captureGate = (BOOL (*)(id, SEL))method_getImplementation(mg);
            method_setImplementation(mg, (IMP)kp_hook_capture_gate);
        }
        Method msg = class_getInstanceMethod(dev, @selector(setRoomCaptureGateEnabled:));
        if (msg && !orig_setCaptureGate) {
            orig_setCaptureGate = (void (*)(id, SEL, BOOL))method_getImplementation(msg);
            method_setImplementation(msg, (IMP)kp_hook_set_capture_gate);
        }

        // 外放回声抑制：护盾/霸麦/无损时强制关，防远端声把本地麦压掉
        Method maeG = class_getInstanceMethod(dev, @selector(speakerphoneEchoCancellation));
        if (maeG && !orig_speakerAEC) {
            orig_speakerAEC = (BOOL (*)(id, SEL))method_getImplementation(maeG);
            method_setImplementation(maeG, (IMP)kp_hook_speaker_aec);
        }
        Method maeS = class_getInstanceMethod(dev, @selector(setSpeakerphoneEchoCancellation:));
        if (maeS && !orig_setSpeakerAEC) {
            orig_setSpeakerAEC = (void (*)(id, SEL, BOOL))method_getImplementation(maeS);
            method_setImplementation(maeS, (IMP)kp_hook_set_speaker_aec);
        }
        kp_log(@"[anticut] dev gate=%d spkAEC=%d", orig_captureGate != NULL, orig_speakerAEC != NULL);

        // 记录意外停麦，便于定位是不是被外部打断
        Method mStop = class_getInstanceMethod(dev, @selector(stopRecording));
        if (mStop && !orig_stopRecording) {
            orig_stopRecording = (void (*)(id, SEL))method_getImplementation(mStop);
            method_setImplementation(mStop, (IMP)kp_hook_stop_recording);
        }
    }
    Class mixer = objc_getClass("KakaAudioMixer");
    if (mixer) {
        Method m = class_getInstanceMethod(mixer, @selector(processPCM:frames:channels:rate:));
        if (m && !orig_mixerPCM) {
            orig_mixerPCM = (void (*)(id, SEL, int16_t *, unsigned long long, unsigned long long, double))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_mixer_pcm);
        }
        if (orig_mixerPCM) state |= 2;

        Method me = class_getInstanceMethod(mixer, @selector(audioDeviceModule:willEnableEngine:isPlayoutEnabled:isRecordingEnabled:isVoiceProcessingEnabled:));
        if (me && !orig_willEnableEngine) {
            orig_willEnableEngine = (void (*)(id, SEL, id, BOOL, BOOL, BOOL, BOOL))method_getImplementation(me);
            method_setImplementation(me, (IMP)kp_hook_will_enable_engine);
        }
    }
    kp_probe_selectors();
    return state;
}

// ==========================================
// 9. 多开 Keychain 隔离（fishhook）
// ==========================================
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);

static NSString *g_bundleId = nil;

static NSString *kp_bundle_id(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_bundleId = [[NSBundle mainBundle] bundleIdentifier];
        if (!g_bundleId) g_bundleId = @"com.isolated.clone";
    });
    return g_bundleId;
}

static CFMutableDictionaryRef kp_isolate_query(CFDictionaryRef query) {
    if (!query) return NULL;
    CFMutableDictionaryRef mq = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
    if (!mq) return NULL;

    NSMutableDictionary *dict = (__bridge NSMutableDictionary *)mq;
    [dict removeObjectForKey:(__bridge id)kSecAttrAccessGroup];

    NSString *bid = kp_bundle_id();
    id service = dict[(__bridge id)kSecAttrService];
    if ([service isKindOfClass:[NSString class]]) {
        dict[(__bridge id)kSecAttrService] = [NSString stringWithFormat:@"%@.%@", service, bid];
    }
    id account = dict[(__bridge id)kSecAttrAccount];
    if ([account isKindOfClass:[NSString class]]) {
        dict[(__bridge id)kSecAttrAccount] = [NSString stringWithFormat:@"%@.%@", account, bid];
    }
    return mq;
}

static OSStatus kp_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFMutableDictionaryRef q = kp_isolate_query(query);
    OSStatus s = orig_SecItemCopyMatching(q ?: query, result);
    if (q) CFRelease(q);
    return s;
}

static OSStatus kp_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFMutableDictionaryRef q = kp_isolate_query(attributes);
    OSStatus s = orig_SecItemAdd(q ?: attributes, result);
    if (q) CFRelease(q);
    return s;
}

static OSStatus kp_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrs) {
    CFMutableDictionaryRef q = kp_isolate_query(query);
    OSStatus s = orig_SecItemUpdate(q ?: query, attrs);
    if (q) CFRelease(q);
    return s;
}

static OSStatus kp_SecItemDelete(CFDictionaryRef query) {
    CFMutableDictionaryRef q = kp_isolate_query(query);
    OSStatus s = orig_SecItemDelete(q ?: query);
    if (q) CFRelease(q);
    return s;
}

// fishhook
struct rebinding { const char *name; void *replacement; void **replaced; };
extern int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

// ==========================================
// 10. 悬浮 UI
// ==========================================
@interface KPFloatWindow : UIWindow <UIDocumentPickerDelegate>
- (void)kp_show_toast:(NSString *)text;
@end

@implementation KPFloatWindow

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self) return nil;
    return v;
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count == 0) return;

    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    dir = [dir stringByAppendingPathComponent:@"KakaAudio/BGM"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSMutableArray<NSString *> *imported = [NSMutableArray array];
    NSMutableArray<NSString *> *failed   = [NSMutableArray array];

    for (NSURL *url in urls) {
        BOOL scoped = [url startAccessingSecurityScopedResource];
        NSString *name = url.lastPathComponent;
        if (!name.length) { if (scoped) [url stopAccessingSecurityScopedResource]; continue; }

        NSString *dst = [dir stringByAppendingPathComponent:name];
        [[NSFileManager defaultManager] removeItemAtPath:dst error:nil];
        NSError *err = nil;
        BOOL ok = [[NSFileManager defaultManager] copyItemAtURL:url
                                                          toURL:[NSURL fileURLWithPath:dst]
                                                          error:&err];
        if (scoped) [url stopAccessingSecurityScopedResource];

        if (ok) [imported addObject:name];
        else    [failed addObject:name];
    }

    if (imported.count == 0) {
        [self kp_show_toast:@"导入失败，换个格式试试"];
        return;
    }

    // 全部按文件名落到 BGM 目录，默认播放最后导入的那首
    NSString *last = imported.lastObject;
    kp_bgm_load_name(last);

    if (failed.count) {
        [self kp_show_toast:[NSString stringWithFormat:@"成功 %lu 首，失败 %lu 首",
                             (unsigned long)imported.count, (unsigned long)failed.count]];
    } else {
        [self kp_show_toast:[NSString stringWithFormat:@"已导入 %lu 首：%@",
                             (unsigned long)imported.count, last]];
    }
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
}

- (void)kp_show_toast:(NSString *)text {
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 260, 40)];
    l.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.85];
    l.textColor = [UIColor whiteColor];
    l.font = [UIFont systemFontOfSize:12];
    l.textAlignment = NSTextAlignmentCenter;
    l.numberOfLines = 0;
    l.layer.cornerRadius = 10;
    l.layer.masksToBounds = YES;
    l.center = CGPointMake(CGRectGetMidX(self.bounds), CGRectGetMidY(self.bounds));
    l.alpha = 0.0;
    [self addSubview:l];
    [UIView animateWithDuration:0.2 animations:^{ l.alpha = 1.0; } completion:^(BOOL f) {
        [UIView animateWithDuration:0.3 delay:2.2 options:0 animations:^{ l.alpha = 0.0; } completion:^(BOOL d) {
            [l removeFromSuperview];
        }];
    }];
}

@end

static KPFloatWindow *g_win = nil;
static UIButton      *g_ball = nil;
static UIView        *g_panel = nil;
static UIView        *g_pageRack = nil;
static UIView        *g_pageEq   = nil;
static UIView        *g_pageVoice = nil;
static UIView        *g_pageSound = nil;
static UIView        *g_pageClip  = nil;
static UIView        *g_vuInFill  = nil;
static UIView        *g_vuGrFill  = nil;
static UIView        *g_vuOutFill = nil;
static CGFloat        g_vuTrackW  = 84.0;

#define KP_PANEL_W  300.0f
#define KP_PANEL_H  470.0f
#define KP_PAGE_Y    74.0f
#define KP_PAGE_H   374.0f
static UILabel       *g_statLabel = nil;
static UILabel       *g_bgmLabel = nil;
static UISwitch      *g_bgmSwitch = nil;
static UILabel       *g_clipStat = nil;
static UIButton      *g_recBtn = nil;
static UISwitch      *g_clipLoopSw = nil;
static NSArray<UIButton *> *g_clipBtns = nil;
static NSArray<UIButton *> *g_slotBtns = nil;
static int            g_clipSlotSel = 0;
static NSTimer       *g_tick = nil;

// ==========================================
// 10.1 多伴奏文件管理
// ==========================================
static void kp_haptic(void);
static void kp_clip_refresh_ui(void);
static UIViewController *kp_top_vc(void);
static void kp_present(UIViewController *vc);
static void kp_open_importer(void);

static NSString *kp_bgm_dir(void) {
    NSString *dir = [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio/BGM"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static NSString *kp_bgm_path(NSString *name) {
    return [kp_bgm_dir() stringByAppendingPathComponent:name];
}

// 已导入的伴奏列表（按名字排序）
static NSArray<NSString *> *kp_bgm_files(void) {
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:kp_bgm_dir() error:nil];
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *f in all) {
        NSString *e = f.pathExtension.lowercaseString;
        if ([e isEqualToString:@"mp3"] || [e isEqualToString:@"m4a"] ||
            [e isEqualToString:@"wav"] || [e isEqualToString:@"caf"]) {
            [out addObject:f];
        }
    }
    return [out sortedArrayUsingSelector:@selector(localizedStandardCompare:)];
}

// 把指定伴奏载入内存并开始循环播放
static void kp_bgm_load_name(NSString *name) {
    if (!name.length) return;
    NSString *path = kp_bgm_path(name);
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        UInt32 n = 0;
        int16_t *buf = kp_load_audio(path, &n);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!buf || n == 0) {
                kp_log(@"bgm decode failed: %@", name);
                return;
            }
            g_bgmOn = 0;
            int16_t *old = g_bgmPcm;
            g_bgmPcm = buf;
            g_bgmLen = (int)n;
            g_bgmPos = 0;
            kp_bgm_retire(old);

            g_bgmName = name;
            [[NSUserDefaults standardUserDefaults] setObject:name forKey:KEY_BGM_NAME];
            g_bgmOn = 1;
            if (g_bgmSwitch) g_bgmSwitch.on = YES;
            kp_log(@"bgm load %@ (%.1fs)", name, (double)n / 48000.0);
        });
    });
}

// 删除指定伴奏文件；若正在播放则先停
static void kp_bgm_delete_name(NSString *name) {
    if (!name.length) return;
    if (g_bgmName && [g_bgmName isEqualToString:name]) {
        kp_delete_bgm();
        if (g_bgmSwitch) g_bgmSwitch.on = NO;
    }
    [[NSFileManager defaultManager] removeItemAtPath:kp_bgm_path(name) error:nil];
    kp_log(@"bgm deleted: %@", name);
}

static void kp_show_bgm_menu(void) {
    NSArray<NSString *> *files = kp_bgm_files();
    if (files.count == 0) {
        kp_open_importer();
        return;
    }

    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"选择播放伴奏"
                                                                  message:nil
                                                           preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *name in files) {
        BOOL cur = (g_bgmName && [g_bgmName isEqualToString:name]);
        NSString *title = cur ? [NSString stringWithFormat:@"%@  (播放中)", name] : name;
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            kp_bgm_load_name(name);
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

    // iPad 上必须给锚点，否则崩溃
    if (g_ball) {
        sheet.popoverPresentationController.sourceView = g_ball;
        sheet.popoverPresentationController.sourceRect = g_ball.bounds;
    }
    kp_present(sheet);
}

static void kp_show_bgm_delete_menu(void) {
    NSArray<NSString *> *files = kp_bgm_files();
    if (files.count == 0) {
        kp_haptic();
        [g_win kp_show_toast:@"还没有导入伴奏"];
        return;
    }

    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"删除伴奏"
                                                                  message:@"从沙盒中彻底删除该音频文件"
                                                           preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *name in files) {
        BOOL cur = (g_bgmName && [g_bgmName isEqualToString:name]);
        NSString *title = cur ? [NSString stringWithFormat:@"删除 %@ (播放中)", name]
                              : [NSString stringWithFormat:@"删除 %@", name];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
            kp_bgm_delete_name(name);
            if (g_bgmLabel && ![g_bgmName length]) {
                g_bgmLabel.text = @"伴奏未导入";
                g_bgmLabel.textColor = [UIColor colorWithWhite:0.62 alpha:1.0];
            }
            kp_haptic();
            [g_win kp_show_toast:[NSString stringWithFormat:@"已删除 %@", name]];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

    if (g_ball) {
        sheet.popoverPresentationController.sourceView = g_ball;
        sheet.popoverPresentationController.sourceRect = g_ball.bounds;
    }
    kp_present(sheet);
}

static NSString *kp_pitch_desc(float p) {
    if (!g_pitchEnabled) return @"[已关]";
    if (p < 0.70f) return @"[低音炮]";
    if (p < 0.88f) return @"[大叔音]";
    if (p < 0.98f) return @"[青叔音]";
    if (p <= 1.05f) return @"[自然原声]";
    if (p < 1.35f) return @"[御姐音]";
    if (p < 1.65f) return @"[萝莉音]";
    return @"[花栗鼠]";
}

static NSString *kp_ceil_text(float c) {
    if (c > 32767.0f) return [NSString stringWithFormat:@"压限峰值 %.0f (超过满幅=硬削顶)", (double)c];
    return [NSString stringWithFormat:@"压限峰值 %.0f / 32767", (double)c];
}

static UILabel *kp_label(CGRect r, NSString *text, CGFloat size, UIColor *color, BOOL bold) {
    UILabel *l = [[UILabel alloc] initWithFrame:r];
    l.text = text;
    l.textColor = color;
    l.font = bold ? [UIFont boldSystemFontOfSize:size] : [UIFont systemFontOfSize:size];
    return l;
}

static UISwitch *kp_switch(CGRect r, BOOL on, void (^handler)(BOOL)) {
    UISwitch *sw = [[UISwitch alloc] initWithFrame:r];
    sw.on = on;
    sw.transform = CGAffineTransformMakeScale(0.85, 0.85);
    [sw addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        handler(sw.on);
    }] forControlEvents:UIControlEventValueChanged];
    return sw;
}

static UISlider *kp_slider(CGRect r, float min, float max, float val, void (^handler)(float)) {
    UISlider *s = [[UISlider alloc] initWithFrame:r];
    s.minimumValue = min;
    s.maximumValue = max;
    s.value = val;
    [s addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        handler(s.value);
    }] forControlEvents:UIControlEventValueChanged];
    return s;
}

static void kp_haptic(void) {
    UIImpactFeedbackGenerator *fb = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
    [fb prepare];
    [fb impactOccurred];
}

static UIViewController *kp_top_vc(void) {
    UIWindow *target = nil;

    // 1. 优先前台活跃场景里真正的 key window（跳过我们自己的悬浮窗）
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if (![sc isKindOfClass:[UIWindowScene class]]) continue;
        if (sc.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *w in ((UIWindowScene *)sc).windows) {
            if (w == g_win) continue;
            if (!w.rootViewController) continue;
            if (w.isKeyWindow) { target = w; break; }
            if (!target) target = w;
        }
        if (target && target.isKeyWindow) break;
    }

    // 2. 退而求其次：任意有 rootViewController 的窗口
    if (!target) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w == g_win || !w.rootViewController) continue;
            target = w;
            break;
        }
    }

    UIViewController *vc = target.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static void kp_present(UIViewController *vc) {
    UIViewController *top = kp_top_vc();
    if (!top || !vc) {
        kp_log(@"present failed: no top vc");
        return;
    }
    // 已经有弹窗在展示时先让开，避免 present 静默失败
    if (top.presentedViewController) return;
    [top presentViewController:vc animated:YES completion:nil];
}

static void kp_open_importer(void) {
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.audio"]
                                                              inMode:UIDocumentPickerModeImport];
    picker.delegate = g_win;
    picker.allowsMultipleSelection = YES;
    kp_present(picker);
}

static void kp_update_ball(void) {
    if (!g_ball) return;

    if (!g_dspEnabled) {
        [g_ball setTitle:@"调音:关" forState:UIControlStateNormal];
        g_ball.backgroundColor = [UIColor colorWithWhite:0.28 alpha:0.95];
        return;
    }

    BOOL anySfx = NO;
    for (int i = 0; i < SFX_SLOT; i++) if (g_sfxOn[i]) { anySfx = YES; break; }

    NSString *tag = @"";
    if (g_recOn) tag = @" 录";
    else if (g_clipOn) tag = @" 话术";
    else if (anySfx) tag = @" 音效";
    else if (g_bgmOn) tag = @" BGM";

    NSString *title;
    if (g_pcmCalls == 0) {
        title = [NSString stringWithFormat:@"%.1fx 待触发", (double)g_makeupGain];
    } else if (g_pitchEnabled) {
        title = [NSString stringWithFormat:@"%.1fx 变%.2f%s|%d", (double)g_makeupGain,
                 (double)g_pitchShiftVal, tag.UTF8String, g_vuMic];
    } else {
        title = [NSString stringWithFormat:@"%.1fx%s|%d", (double)g_makeupGain, tag.UTF8String, g_vuMic];
    }
    if (g_oneTapMasterLock) title = [NSString stringWithFormat:@"锁|%@", title];
    [g_ball setTitle:title forState:UIControlStateNormal];

    if (g_vuMic > 8 || anySfx || g_clipOn) {
        g_ball.backgroundColor = [UIColor colorWithRed:0.00 green:0.70 blue:0.34 alpha:0.98];
    } else {
        g_ball.backgroundColor = [UIColor colorWithRed:0.05 green:0.46 blue:0.24 alpha:0.96];
    }
}

// ==========================================
// 一键霸麦锁定：一次锁死清晰度/响度/护盾/伴奏联动参数
// 原则：不靠 tanhf 硬削波换响度，靠前瞻限幅 + 中高频提亮换穿透力
// ==========================================
static void kp_toggle_master_lock(BOOL lock) {
    g_oneTapMasterLock = lock;
    if (lock) {
        g_dspEnabled       = YES;
        g_losslessPriority = YES;
        g_priorityLoud     = YES;
        g_lowCutEnabled    = YES;
        g_gateEnabled      = NO;      // 多人抢麦时避免吞字
        g_throatEnabled    = YES;
        g_compEnabled      = YES;
        g_compThresh       = 0.32f;   // v30.2：门限抬高，底噪不参与提拉
        g_compRatio        = 3.2f;    // 适度压缩，保留说话节奏
        g_eq10Enabled      = YES;
        g_limiterEnabled   = YES;
        g_limiterCeiling   = 30800.0f; // v30.2：留 6% 余量，[mixproc] 峰值绝不撞 100%
        g_makeupGain       = 1.45f;    // v30.2：黄金总增益，配合双峰提亮不过载
        // v30.0：这三项在精简链路里已不参与处理，锁定态一并置 NO
        g_imagerEnabled    = NO;       // 关 Suya 声场，规避梳状滤波
        g_haasEnabled      = NO;
        g_bassLaneEnabled  = NO;       // 关 bassLANE，单声道下无意义
        g_tubeEnabled      = NO;       // 关电子管，杜绝 tanh 挤平方波

        // 远端护盾：把别人声音压低到 20%，避免外放/耳返回声抑制
        g_shieldRemote     = YES;
        g_shieldLowOnly    = YES;
        kp_shield_apply();

        // v30.1：锁定不碰 BGM 开关与“说话闪避”开关，放不放歌你自己控
        g_opusBitrateBps   = 192000; // 黄金并发档：放歌接近无损，多人房不被拥塞踢出

        // 锁死 10 段曲线：削 120Hz 以下浑浊，2.5k/4.2k 提亮穿透
        static const float masterEq[EQ10_BANDS] = {
            -6.0f, -3.5f, -1.0f, 0.5f, 1.5f, 3.5f, 4.8f, 3.5f, 2.0f, 1.0f
        };
        for (int i = 0; i < EQ10_BANDS; i++) {
            g_eq10Gains[i] = masterEq[i];
        }
        kp_rebuild_filter_bank();
        kp_log(@"[MASTER-LOCK] 一键霸麦已锁定：防削波电平+高穿透音色+192k并发档");
    } else {
        g_shieldRemote = NO;
        kp_shield_apply();
        kp_log(@"[MASTER-LOCK] 已解除一键锁定，恢复自定义调节");
    }
    save_current_settings();
    kp_update_ball();
}

static void kp_attach_scene(void);

static void kp_tick(void) {
    // 场景可能比悬浮窗晚就绪：持续补挂，直到成功
    if (g_win && g_ball) {
        if (@available(iOS 13.0, *)) {
            if (!g_win.windowScene) kp_attach_scene();
        }
    }

    kp_update_ball();

    if (g_panel && !g_panel.hidden && g_pageClip && !g_pageClip.hidden) {
        kp_clip_refresh_ui();
    }

    if (g_panel && !g_panel.hidden && g_statLabel) {
        NSString *state = @"未找类";
        if (g_hookState == 3) state = @"A+B";
        else if (g_hookState == 1) state = @"仅A";
        else if (g_hookState == 2) state = @"仅B";

        g_statLabel.text = [NSString stringWithFormat:@"%@  %.1fkHz  %dk  A%ld B%ld",
                            state, (double)g_sampleRate / 1000.0, g_opusBitrateBps / 1000,
                            (long)g_pcmCalls, (long)g_mixCalls];
    }
    if (g_bgmLabel) {
        if (g_bgmLen <= 0) {
            g_bgmLabel.text = @"伴奏未导入";
            g_bgmLabel.textColor = [UIColor colorWithWhite:0.62 alpha:1.0];
        } else {
            UInt32 sec = (UInt32)(g_bgmLen / 48000);
            NSString *name = g_bgmName.length ? g_bgmName : @"已载入";
            g_bgmLabel.text = [NSString stringWithFormat:@"%@  %u:%02u %@",
                               name, sec / 60, sec % 60, g_bgmOn ? @"播放中" : @"已停止"];
            g_bgmLabel.textColor = [UIColor colorWithRed:0.25 green:0.82 blue:0.45 alpha:0.95];
        }
    }

    if (g_vuMic > 0) g_vuMic = (int)(g_vuMic * 0.55f);
    if (g_vuMix > 0) g_vuMix = (int)(g_vuMix * 0.55f);

    // 三路 VU：面板打开时才刷新，关闭时清零省电
    if (g_panel && !g_panel.hidden && g_vuInFill) {
        CGFloat tw = g_vuTrackW;
        g_vuInFill.frame  = CGRectMake(0, 0, tw * (CGFloat)g_vuIn  / 100.0f, 7);
        g_vuGrFill.frame  = CGRectMake(0, 0, tw * (CGFloat)g_vuGr  / 100.0f, 7);
        g_vuOutFill.frame = CGRectMake(0, 0, tw * (CGFloat)g_vuOut / 100.0f, 7);
        if (g_vuIn  > 0) g_vuIn  = (int)(g_vuIn  * 0.78f);
        if (g_vuGr  > 0) g_vuGr  = (int)(g_vuGr  * 0.82f);
        if (g_vuOut > 0) g_vuOut = (int)(g_vuOut * 0.78f);
    } else {
        g_vuIn = g_vuGr = g_vuOut = 0;
    }
}

static void kp_toggle_panel(void) {
    if (!g_panel) return;
    g_panel.hidden = !g_panel.hidden;
}

// ---------- 调音页：7 级机架（可滚动） ----------
static UISwitch *kp_row_switch(UIView *parent, CGFloat y, CGFloat w, NSString *title,
                               BOOL on, void (^handler)(BOOL)) {
    [parent addSubview:kp_label(CGRectMake(16, y, w - 92, 22), title, 12,
                                [UIColor colorWithWhite:0.88 alpha:1.0], NO)];
    UISwitch *sw = kp_switch(CGRectMake(w - 62, y - 2, 50, 22), on, handler);
    [parent addSubview:sw];
    return sw;
}

static void kp_build_rack_page(CGFloat w) {
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    sv.showsVerticalScrollIndicator = YES;
    sv.alwaysBounceVertical = YES;
    sv.contentInset = UIEdgeInsetsMake(0, 0, 14, 0);
    sv.contentSize = CGSizeMake(w, 1100);
    [g_panel addSubview:sv];
    g_pageRack = sv;

    UIView *c = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, 1100)];
    [sv addSubview:c];

    UIColor *dim = [UIColor colorWithWhite:0.60 alpha:1.0];
    UIColor *sec = [UIColor colorWithRed:0.30 green:0.78 blue:0.50 alpha:1.0];
    CGFloat y = 2;

    [c addSubview:kp_label(CGRectMake(16, y, w - 32, 16), @"4 级核心链（话放 → 母带）", 10, sec, YES)];
    y += 20;

    // v30.3：一键霸麦开关已移到悬浮面板顶部（VU 正下方），这里不再重复放一个

    // ---- 第 1 级 Vocal Range ----
    kp_row_switch(c, y, w, @"1 · Vocal Range 喉音", g_throatEnabled, ^(BOOL on) {
        g_throatEnabled = on;
        save_current_settings();
    });
    y += 30;

    // ---- 第 2 级 DYNAM-IZER ----
    kp_row_switch(c, y, w, @"2 · DYNAM-IZER 压缩", g_compEnabled, ^(BOOL on) {
        g_compEnabled = on;
        save_current_settings();
    });
    y += 26;
    UILabel *ct = kp_label(CGRectMake(16, y, 260, 14),
                           [NSString stringWithFormat:@"压缩门限 %.2f", (double)g_compThresh], 10, dim, NO);
    [c addSubview:ct];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 0.08f, 0.75f, g_compThresh, ^(float v) {
        g_compThresh = v;
        ct.text = [NSString stringWithFormat:@"压缩门限 %.2f", (double)v];
        save_current_settings();
    })];
    y += 34;
    UILabel *cr = kp_label(CGRectMake(16, y, 260, 14),
                           [NSString stringWithFormat:@"压缩比 %.1f : 1", (double)g_compRatio], 10, dim, NO);
    [c addSubview:cr];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 1.5f, 10.0f, g_compRatio, ^(float v) {
        g_compRatio = v;
        cr.text = [NSString stringWithFormat:@"压缩比 %.1f : 1", (double)v];
        save_current_settings();
    })];
    y += 34;

    // ---- 第 3 级 Pro-Q ----
    kp_row_switch(c, y, w, @"3 · Pro-Q 10 段 EQ", g_eq10Enabled, ^(BOOL on) {
        g_eq10Enabled = on;
        save_current_settings();
    });
    y += 24;
    [c addSubview:kp_label(CGRectMake(16, y, w - 32, 14), @"各频段增益在「EQ」页里调", 9,
                           [UIColor colorWithWhite:0.50 alpha:1.0], NO)];
    y += 18;

    // ---- 第 4 级 限制器（唯一让你既大又不破音的模块） ----
    kp_row_switch(c, y, w, @"4 · 限制器 3.1（前瞻砖墙）", g_limiterEnabled, ^(BOOL on) {
        g_limiterEnabled = on;
        save_current_settings();
    });
    y += 26;
    UILabel *ceilText = kp_label(CGRectMake(16, y, w - 32, 14), kp_ceil_text(g_limiterCeiling), 10, dim, NO);
    [c addSubview:ceilText];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 20000.0f, 50000.0f, g_limiterCeiling, ^(float v) {
        g_limiterCeiling = v;
        ceilText.text = kp_ceil_text(v);
        save_current_settings();
    })];
    y += 34;

    // ---- 话放 / 总线 / 传输 ----
    [c addSubview:kp_label(CGRectMake(16, y, w - 32, 16), @"话放 / 总线 / 传输", 10, sec, YES)];
    y += 20;

    kp_row_switch(c, y, w, @"电台总开关", g_dspEnabled, ^(BOOL on) {
        g_dspEnabled = on;
        kp_update_ball();
        save_current_settings();
    });
    y += 30;

    kp_row_switch(c, y, w, @"强声霸麦（优先响度）", g_priorityLoud, ^(BOOL on) {
        g_priorityLoud = on;
        kp_rebuild_filter_bank();   // 100Hz 高通 + 2.2k/3.4k 提亮 + 快压缩一起切换
        save_current_settings();
        kp_log(@"[priority] state=%s", on ? "ON" : "OFF");
    });
    y += 30;

    kp_row_switch(c, y, w, @"80Hz 低切（霸麦 100Hz）", g_lowCutEnabled, ^(BOOL on) {
        g_lowCutEnabled = on;
        save_current_settings();
    });
    y += 30;

    kp_row_switch(c, y, w, @"智能噪声门", g_gateEnabled, ^(BOOL on) {
        g_gateEnabled = on;
        kp_gate_reset();
        save_current_settings();
    });
    y += 26;
    UILabel *gateText = kp_label(CGRectMake(16, y, 260, 14),
                                 [NSString stringWithFormat:@"门限阈值 %.3f", (double)g_gateThreshold], 10, dim, NO);
    [c addSubview:gateText];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 0.003f, 0.08f, g_gateThreshold, ^(float v) {
        g_gateThreshold = v;
        gateText.text = [NSString stringWithFormat:@"门限阈值 %.3f", (double)v];
        save_current_settings();
    })];
    y += 34;

    kp_row_switch(c, y, w, @"Freeverb 大厅混响", g_reverbEnabled, ^(BOOL on) {
        g_reverbEnabled = on;
        if (on) kp_reverb_reset();
        save_current_settings();
    });
    y += 26;
    UILabel *wetText = kp_label(CGRectMake(16, y, 260, 14),
                                [NSString stringWithFormat:@"混响湿声 %.0f%%", (double)(g_reverbWet * 100)], 10, dim, NO);
    [c addSubview:wetText];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 0.0f, 0.8f, g_reverbWet, ^(float v) {
        g_reverbWet = v;
        wetText.text = [NSString stringWithFormat:@"混响湿声 %.0f%%", (double)(v * 100)];
        save_current_settings();
    })];
    y += 34;

    UILabel *gainText = kp_label(CGRectMake(16, y, 260, 14),
                                 [NSString stringWithFormat:@"总增益 %.1fx", (double)g_makeupGain], 10, dim, NO);
    [c addSubview:gainText];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 1.0f, 30.0f, g_makeupGain, ^(float v) {
        g_makeupGain = v;
        gainText.text = [NSString stringWithFormat:@"总增益 %.1fx", (double)v];
        kp_update_ball();
        save_current_settings();
    })];
    y += 34;

    kp_row_switch(c, y, w, @"混音通道也处理", g_mixDspEnabled, ^(BOOL on) {
        g_mixDspEnabled = on;
        save_current_settings();
    });
    y += 28;

    kp_row_switch(c, y, w, @"强力增响（软膝限幅）", g_boostOn, ^(BOOL on) {
        g_boostOn = on;
        save_current_settings();
    });
    y += 30;

    // ---- 码率 ----
    [c addSubview:kp_label(CGRectMake(16, y, w - 32, 16), @"Opus 码率（重进房间生效）", 10, dim, NO)];
    y += 20;
    NSArray *rateVals  = @[@192000, @256000, @320000, @510000];
    NSArray *rateNames = @[@"192k", @"256k", @"320k", @"510k"];
    CGFloat rbw = (w - 32 - 18) / 4.0f;
    NSMutableArray<UIButton *> *rateBtns = [NSMutableArray array];
    for (int i = 0; i < 4; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16 + i * (rbw + 6), y, rbw, 26);
        b.layer.cornerRadius = 6;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        [b setTitle:rateNames[i] forState:UIControlStateNormal];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        int bps = [rateVals[i] intValue];
        b.backgroundColor = (bps == g_opusBitrateBps)
            ? [UIColor colorWithRed:0.15 green:0.50 blue:0.85 alpha:0.98]
            : [UIColor colorWithWhite:0.20 alpha:0.95];
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            g_opusBitrateBps = bps;
            for (UIButton *x in rateBtns) {
                x.backgroundColor = (x == b)
                    ? [UIColor colorWithRed:0.15 green:0.50 blue:0.85 alpha:0.98]
                    : [UIColor colorWithWhite:0.20 alpha:0.95];
            }
            save_current_settings();
        }] forControlEvents:UIControlEventTouchUpInside];
        [c addSubview:b];
        [rateBtns addObject:b];
    }
    y += 32;

    // ---- 采集链路（两级开关） ----
    kp_row_switch(c, y, w, @"无损优先（关 AEC/降噪）", g_losslessPriority, ^(BOOL on) {
        g_losslessPriority = on;
        save_current_settings();
    });
    y += 28;

    kp_row_switch(c, y, w, @"深度旁路（高风险·默认关）", g_deepBypassVP, ^(BOOL on) {
        g_deepBypassVP = on;
        save_current_settings();
    });
    y += 28;

    kp_row_switch(c, y, w, @"屏蔽他人声音（防压制护盾）", g_shieldRemote, ^(BOOL on) {
        g_shieldRemote = on;
        kp_shield_apply();
        kp_log(@"[shield] state=%s mode=%s tracks=%lu", on ? "ON" : "OFF",
               g_shieldLowOnly ? "20pct" : "mute",
               (unsigned long)g_shieldTracks.count);
        save_current_settings();
    });
    y += 28;

    kp_row_switch(c, y, w, @"只压低到 20%（不静音）", g_shieldLowOnly, ^(BOOL on) {
        g_shieldLowOnly = on;
        kp_shield_apply();
        kp_log(@"[shield] state=%s mode=%s tracks=%lu", g_shieldRemote ? "ON" : "OFF",
               on ? "20pct" : "mute",
               (unsigned long)g_shieldTracks.count);
        save_current_settings();
    });
    y += 30;

    g_statLabel = kp_label(CGRectMake(16, y, w - 32, 18), @"Hook:安装中...", 9,
                           [UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:0.95], NO);
    g_statLabel.textAlignment = NSTextAlignmentCenter;
    [c addSubview:g_statLabel];
}

// ---------- EQ 页：10 段增益 ----------
static void kp_build_eq_page(CGFloat w) {
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    sv.showsVerticalScrollIndicator = YES;
    sv.alwaysBounceVertical = YES;
    [g_panel addSubview:sv];
    g_pageEq = sv;

    CGFloat contentH = 24 + EQ10_BANDS * 44 + 40;
    sv.contentSize = CGSizeMake(w, contentH);
    UIView *c = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, contentH)];
    [sv addSubview:c];

    [c addSubview:kp_label(CGRectMake(16, 2, w - 32, 16), @"10 段 EQ  ·  -12 dB ~ +12 dB", 10,
                           [UIColor colorWithRed:0.30 green:0.78 blue:0.50 alpha:1.0], YES)];

    UIColor *dim = [UIColor colorWithWhite:0.60 alpha:1.0];
    NSMutableArray<UILabel *>  *valLabels = [NSMutableArray array];
    NSMutableArray<UISlider *> *sliders   = [NSMutableArray array];

    for (int i = 0; i < EQ10_BANDS; i++) {
        CGFloat y = 24 + i * 44;
        float f = kEq10Freqs[i];
        NSString *fs;
        if (f >= 1000.0f) {
            fs = (fmodf(f, 1000.0f) < 1.0f)
                ? [NSString stringWithFormat:@"%.0fk", (double)(f / 1000.0f)]
                : [NSString stringWithFormat:@"%.1fk", (double)(f / 1000.0f)];
        } else {
            fs = [NSString stringWithFormat:@"%.0f", (double)f];
        }
        [c addSubview:kp_label(CGRectMake(16, y + 2, 44, 16), fs, 10, dim, NO)];

        UILabel *vl = kp_label(CGRectMake(w - 60, y + 2, 44, 16),
                               [NSString stringWithFormat:@"%+.1f", (double)g_eq10Gains[i]], 10,
                               [UIColor colorWithRed:0.35 green:0.80 blue:1.0 alpha:1.0], YES);
        vl.textAlignment = NSTextAlignmentRight;
        [c addSubview:vl];
        [valLabels addObject:vl];

        UISlider *s = kp_slider(CGRectMake(62, y + 2, w - 62 - 16 - 48, 18), -12.0f, 12.0f, g_eq10Gains[i], ^(float v) {
            g_eq10Gains[i] = v;
            vl.text = [NSString stringWithFormat:@"%+.1f", (double)v];
            kp_rebuild_filter_bank();
        });
        [s addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            save_current_settings();
        }] forControlEvents:UIControlEventTouchUpInside | UIControlEventTouchUpOutside];
        [c addSubview:s];
        [sliders addObject:s];
    }

    UIButton *rst = [UIButton buttonWithType:UIButtonTypeCustom];
    rst.frame = CGRectMake(16, 24 + EQ10_BANDS * 44, w - 32, 30);
    rst.layer.cornerRadius = 8;
    rst.backgroundColor = [UIColor colorWithWhite:0.22 alpha:0.95];
    [rst setTitle:@"恢复默认 EQ 曲线" forState:UIControlStateNormal];
    [rst setTitleColor:[UIColor colorWithWhite:0.88 alpha:1.0] forState:UIControlStateNormal];
    rst.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [rst addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        static const float def[EQ10_BANDS] = {
            -3.0f, -1.5f, 1.5f, 0.5f, 1.0f, 2.5f, 4.5f, 3.0f, 2.5f, 1.5f
        };
        for (int i = 0; i < EQ10_BANDS; i++) {
            g_eq10Gains[i] = def[i];
            sliders[i].value = def[i];
            valLabels[i].text = [NSString stringWithFormat:@"%+.1f", (double)def[i]];
        }
        kp_rebuild_filter_bank();
        save_current_settings();
        kp_haptic();
    }] forControlEvents:UIControlEventTouchUpInside];
    [c addSubview:rst];
}

// ---------- 变声页 ----------
static void kp_build_voice_page(CGFloat w) {
    g_pageVoice = [[UIView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    g_pageVoice.hidden = YES;
    [g_panel addSubview:g_pageVoice];

    UIColor *fg = [UIColor colorWithWhite:0.86 alpha:1.0];

    [g_pageVoice addSubview:kp_label(CGRectMake(16, 6, 160, 22), @"实时变声", 12, fg, NO)];
    [g_pageVoice addSubview:kp_switch(CGRectMake(w - 62, 4, 50, 22), g_pitchEnabled, ^(BOOL on) {
        g_pitchEnabled = on;
        if (on) kp_pitch_reset();
        kp_update_ball();
        save_current_settings();
    })];

    UILabel *valText = kp_label(CGRectMake(16, 44, 260, 20),
                                [NSString stringWithFormat:@"音调 %.2fx %@", (double)g_pitchShiftVal, kp_pitch_desc(g_pitchShiftVal)],
                                12, [UIColor colorWithRed:0.25 green:0.8 blue:1.0 alpha:1.0], YES);
    [g_pageVoice addSubview:valText];

    [g_pageVoice addSubview:kp_slider(CGRectMake(16, 68, w - 32, 22), 0.5f, 1.8f, g_pitchShiftVal, ^(float v) {
        g_pitchShiftVal = v;
        valText.text = [NSString stringWithFormat:@"音调 %.2fx %@", (double)v, kp_pitch_desc(v)];
        kp_update_ball();
        save_current_settings();
    })];

    NSArray *presets = @[@"低音炮 0.60", @"大叔 0.82", @"原声 1.00", @"御姐 1.28", @"萝莉 1.50"];
    for (int i = 0; i < (int)presets.count; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16, 104 + i * 38, w - 32, 32);
        b.backgroundColor = [UIColor colorWithWhite:0.18 alpha:0.95];
        b.layer.cornerRadius = 8;
        [b setTitle:presets[i] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:12];
        NSNumber *valueObj = @[@0.60f, @0.82f, @1.00f, @1.28f, @1.50f][i];
        float v = valueObj.floatValue;
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            g_pitchShiftVal = v;
            g_pitchEnabled = (fabsf(v - 1.0f) > 0.02f);
            if (g_pitchEnabled) kp_pitch_reset();
            valText.text = [NSString stringWithFormat:@"音调 %.2fx %@", (double)v, kp_pitch_desc(v)];
            kp_update_ball();
            save_current_settings();
        }] forControlEvents:UIControlEventTouchUpInside];
        [g_pageVoice addSubview:b];
    }

    UILabel *tip = kp_label(CGRectMake(16, 104 + 5 * 38 + 4, w - 32, 30),
                            @"变声会引入约 16ms 延迟，关闭后归零", 10,
                            [UIColor colorWithWhite:0.5 alpha:1.0], NO);
    tip.numberOfLines = 0;
    [g_pageVoice addSubview:tip];
}

// ---------- 音效 / BGM 页 ----------
static void kp_build_sound_page(CGFloat w) {
    g_pageSound = [[UIView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    g_pageSound.hidden = YES;
    [g_panel addSubview:g_pageSound];

    NSArray *titles = @[@"掌声", @"笑声", @"欢呼", @"口哨"];
    for (int i = 0; i < SFX_SLOT; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16 + (i % 2) * ((w - 32) / 2 + 6), 6 + (i / 2) * 44, (w - 44) / 2, 38);
        b.backgroundColor = [UIColor colorWithRed:0.18 green:0.28 blue:0.36 alpha:0.95];
        b.layer.cornerRadius = 8;
        [b setTitle:titles[i] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
        int idx = i;
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            kp_play_sfx(idx);
        }] forControlEvents:UIControlEventTouchUpInside];

        // 长按删除自定义音效，恢复出厂合成音
        NSString *selName = [NSString stringWithFormat:@"kp_sfx_lp_%d:", idx];
        SEL lpSel = NSSelectorFromString(selName);
        class_addMethod([b class], lpSel, imp_implementationWithBlock(^(id _self, UILongPressGestureRecognizer *rec) {
            if (rec.state != UIGestureRecognizerStateBegan) return;
            BOOL removed = kp_reset_sfx_slot(idx);
            UIButton *btn = (UIButton *)_self;
            btn.backgroundColor = removed ? [UIColor colorWithRed:0.18 green:0.28 blue:0.36 alpha:0.95]
                                          : [UIColor colorWithWhite:0.22 alpha:0.95];
            kp_haptic();
            [g_win kp_show_toast:removed ? @"已删除自定义音效，恢复默认" : @"当前使用的就是默认音效"];
        }), "v@:@");
        UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:b action:lpSel];
        lp.minimumPressDuration = 0.5;
        [b addGestureRecognizer:lp];

        [g_pageSound addSubview:b];
    }

    UILabel *hint = kp_label(CGRectMake(16, 90, w - 32, 16), @"长按音效键可删除自定义文件、恢复默认", 10,
                             [UIColor colorWithWhite:0.5 alpha:1.0], NO);
    hint.textAlignment = NSTextAlignmentCenter;
    [g_pageSound addSubview:hint];

    UIColor *fg = [UIColor colorWithWhite:0.86 alpha:1.0];

    UILabel *sfxVolText = kp_label(CGRectMake(16, 112, 260, 16),
                                   [NSString stringWithFormat:@"音效音量 %.0f%%", (double)(g_sfxVolume * 100)], 10,
                                   [UIColor colorWithWhite:0.62 alpha:1.0], NO);
    [g_pageSound addSubview:sfxVolText];
    [g_pageSound addSubview:kp_slider(CGRectMake(16, 126, w - 32, 18), 0.0f, 1.0f, g_sfxVolume, ^(float v) {
        g_sfxVolume = v;
        sfxVolText.text = [NSString stringWithFormat:@"音效音量 %.0f%%", (double)(v * 100)];
        save_current_settings();
    })];

    [g_pageSound addSubview:kp_label(CGRectMake(16, 156, 140, 22), @"伴奏 BGM", 12, fg, NO)];
    g_bgmSwitch = kp_switch(CGRectMake(w - 62, 154, 50, 22), g_bgmOn, ^(BOOL on) {
        if (on && g_bgmLen == 0) {
            NSArray<NSString *> *files = kp_bgm_files();
            NSString *pick = nil;
            if (g_bgmName.length && [files containsObject:g_bgmName]) pick = g_bgmName;
            else pick = files.firstObject;
            if (pick) {
                kp_bgm_load_name(pick);
                return;
            }
            g_bgmOn = 0;
            g_bgmSwitch.on = NO;
            [g_win kp_show_toast:@"还没有伴奏，先点导入"];
            return;
        }
        g_bgmOn = on ? 1 : 0;
    });
    [g_pageSound addSubview:g_bgmSwitch];

    g_bgmLabel = kp_label(CGRectMake(16, 182, w - 32, 16), @"伴奏未导入", 10,
                          [UIColor colorWithWhite:0.62 alpha:1.0], NO);
    [g_pageSound addSubview:g_bgmLabel];

    CGFloat bw3 = (w - 44) / 3;

    UIButton *importBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    importBtn.frame = CGRectMake(16, 204, bw3, 34);
    importBtn.backgroundColor = [UIColor colorWithRed:0.15 green:0.45 blue:0.85 alpha:0.95];
    importBtn.layer.cornerRadius = 8;
    [importBtn setTitle:@"导入" forState:UIControlStateNormal];
    importBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [importBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        kp_open_importer();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageSound addSubview:importBtn];

    UIButton *switchBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    switchBtn.frame = CGRectMake(16 + bw3 + 6, 204, bw3, 34);
    switchBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.58 blue:0.34 alpha:0.95];
    switchBtn.layer.cornerRadius = 8;
    [switchBtn setTitle:@"切换" forState:UIControlStateNormal];
    switchBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [switchBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        kp_show_bgm_menu();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageSound addSubview:switchBtn];

    UIButton *deleteBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    deleteBtn.frame = CGRectMake(16 + (bw3 + 6) * 2, 204, bw3, 34);
    deleteBtn.backgroundColor = [UIColor colorWithRed:0.72 green:0.18 blue:0.18 alpha:0.95];
    deleteBtn.layer.cornerRadius = 8;
    [deleteBtn setTitle:@"删除" forState:UIControlStateNormal];
    deleteBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [deleteBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        kp_show_bgm_delete_menu();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageSound addSubview:deleteBtn];

    UILabel *duckLabel = kp_label(CGRectMake(16, 244, 200, 22), @"说话自动压低伴奏", 12, fg, NO);
    [g_pageSound addSubview:duckLabel];
    [g_pageSound addSubview:kp_switch(CGRectMake(w - 62, 242, 50, 22), g_duckEnabled, ^(BOOL on) {
        g_duckEnabled = on;
        save_current_settings();
    })];

    UILabel *bgmVolText = kp_label(CGRectMake(16, 276, 260, 16),
                                   [NSString stringWithFormat:@"伴奏音量 %.0f%%", (double)(g_bgmVolume * 100)], 10,
                                   [UIColor colorWithWhite:0.62 alpha:1.0], NO);
    [g_pageSound addSubview:bgmVolText];
    [g_pageSound addSubview:kp_slider(CGRectMake(16, 290, w - 32, 18), 0.0f, 1.0f, g_bgmVolume, ^(float v) {
        g_bgmVolume = v;
        bgmVolText.text = [NSString stringWithFormat:@"伴奏音量 %.0f%%", (double)(v * 100)];
        save_current_settings();
    })];

    UILabel *tip = kp_label(CGRectMake(16, 312, w - 32, 36),
                            @"自定义音效：Documents/KakaAudio/SFX/sfx_0~3.mp3（长按按钮删除）",
                            10, [UIColor colorWithWhite:0.5 alpha:1.0], NO);
    tip.numberOfLines = 0;
    [g_pageSound addSubview:tip];
}

static NSArray<UIButton *> *g_tabBtns = nil;

static void kp_clip_refresh_ui(void) {
    for (NSInteger i = 0; g_clipBtns && i < (NSInteger)g_clipBtns.count; i++) {
        UIButton *b = g_clipBtns[i];
        BOOL has = kp_clip_exists((int)i);
        BOOL playing = (g_clipOn != 0) && (g_clipPlayingSlot == (int)i);

        if (playing) {
            NSString *t = g_clipLoop ? @"%ld 循环中" : @"%ld 播放中";
            [b setTitle:[NSString stringWithFormat:t, (long)i + 1] forState:UIControlStateNormal];
            b.backgroundColor = [UIColor colorWithRed:0.14 green:0.58 blue:0.33 alpha:0.98];
            [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        } else if (has) {
            [b setTitle:[NSString stringWithFormat:@"%ld 已录制", (long)i + 1] forState:UIControlStateNormal];
            b.backgroundColor = [UIColor colorWithRed:0.16 green:0.32 blue:0.46 alpha:0.98];
            [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        } else {
            [b setTitle:[NSString stringWithFormat:@"%ld 空槽位", (long)i + 1] forState:UIControlStateNormal];
            b.backgroundColor = [UIColor colorWithWhite:0.22 alpha:0.95];
            [b setTitleColor:[UIColor colorWithWhite:0.62 alpha:1.0] forState:UIControlStateNormal];
        }
    }

    for (NSInteger i = 0; g_slotBtns && i < (NSInteger)g_slotBtns.count; i++) {
        UIButton *b = g_slotBtns[i];
        BOOL sel = ((int)i == g_clipSlotSel);
        b.backgroundColor = sel ? [UIColor colorWithRed:0.68 green:0.26 blue:0.24 alpha:0.98]
                                : [UIColor colorWithWhite:0.24 alpha:0.95];
        [b setTitleColor:sel ? [UIColor whiteColor] : [UIColor colorWithWhite:0.75 alpha:1.0]
                 forState:UIControlStateNormal];
    }

    if (g_recBtn) {
        if (g_recOn) {
            int sec = (int)(g_recCount / 48000);
            if (g_recCount >= CLIP_MAX_SAMPLES) {
                [g_recBtn setTitle:@"已录满 1:00，点这里保存" forState:UIControlStateNormal];
                g_recBtn.backgroundColor = [UIColor colorWithRed:0.72 green:0.52 blue:0.12 alpha:1.0];
            } else {
                [g_recBtn setTitle:[NSString stringWithFormat:@"停止并保存   %d:%02d", sec / 60, sec % 60]
                          forState:UIControlStateNormal];
                g_recBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.62 blue:0.30 alpha:1.0];
            }
        } else {
            [g_recBtn setTitle:[NSString stringWithFormat:@"录到槽位 %d", g_clipSlotSel + 1]
                      forState:UIControlStateNormal];
            g_recBtn.backgroundColor = [UIColor colorWithRed:0.66 green:0.20 blue:0.20 alpha:0.98];
        }
    }

    if (g_clipStat) {
        if (g_recOn) {
            g_clipStat.text = @"录制中… 现在说话会被录进去（最长 60 秒）";
            g_clipStat.textColor = [UIColor colorWithRed:1.0 green:0.42 blue:0.38 alpha:1.0];
        } else {
            NSMutableArray *have = [NSMutableArray array];
            for (int i = 0; i < CLIP_SLOT; i++) {
                if (kp_clip_exists(i)) [have addObject:[NSString stringWithFormat:@"%d", i + 1]];
            }
            if (have.count == 0) {
                g_clipStat.text = @"还没有录音：先选槽位，再点红色按钮";
                g_clipStat.textColor = [UIColor colorWithWhite:0.60 alpha:1.0];
            } else {
                g_clipStat.text = [NSString stringWithFormat:@"已录制槽位 %@，点上方即可播放",
                                   [have componentsJoinedByString:@" / "]];
                g_clipStat.textColor = [UIColor colorWithRed:0.30 green:0.80 blue:0.50 alpha:1.0];
            }
        }
    }
}

static void kp_build_clip_page(CGFloat w) {
    UIColor *dim = [UIColor colorWithWhite:0.55 alpha:1.0];

    g_pageClip = [[UIView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    g_pageClip.hidden = YES;
    [g_panel addSubview:g_pageClip];

    [g_pageClip addSubview:kp_label(CGRectMake(16, 0, w - 32, 16),
                                    @"录好的话术会带着机架效果一起播出去", 10, dim, NO)];

    NSMutableArray *clipBtns = [NSMutableArray array];
    for (int i = 0; i < CLIP_SLOT; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16 + (i % 2) * 134, 20 + (i / 2) * 44, 128, 38);
        b.layer.cornerRadius = 8;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            kp_haptic();
            kp_clip_play((int)i);
            kp_clip_refresh_ui();
        }] forControlEvents:UIControlEventTouchUpInside];

        SEL lpSel = NSSelectorFromString([NSString stringWithFormat:@"kpClipLp%d:", i]);
        class_addMethod([b class], lpSel, imp_implementationWithBlock(^(id _self, UILongPressGestureRecognizer *gr) {
            if (gr.state != UIGestureRecognizerStateBegan) return;
            if (!kp_clip_exists(i)) return;
            kp_clip_delete(i);
            kp_haptic();
            kp_clip_refresh_ui();
            [g_win kp_show_toast:[NSString stringWithFormat:@"已删除槽位 %d", i + 1]];
        }), "v@:@");
        [b addGestureRecognizer:[[UILongPressGestureRecognizer alloc] initWithTarget:b action:lpSel]];

        [g_pageClip addSubview:b];
        [clipBtns addObject:b];
    }
    g_clipBtns = clipBtns;

    [g_pageClip addSubview:kp_label(CGRectMake(16, 112, w - 32, 16), @"录制到哪个槽位", 10, dim, NO)];

    NSMutableArray *slotBtns = [NSMutableArray array];
    CGFloat slotW = (w - 32 - 3 * 6) / 4.0;
    for (int i = 0; i < CLIP_SLOT; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16 + i * (slotW + 6), 130, slotW, 28);
        b.layer.cornerRadius = 7;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [b setTitle:[NSString stringWithFormat:@"%d", i + 1] forState:UIControlStateNormal];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            if (g_recOn) return;
            g_clipSlotSel = (int)i;
            kp_haptic();
            kp_clip_refresh_ui();
        }] forControlEvents:UIControlEventTouchUpInside];
        [g_pageClip addSubview:b];
        [slotBtns addObject:b];
    }
    g_slotBtns = slotBtns;

    g_recBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    g_recBtn.frame = CGRectMake(16, 168, w - 32, 40);
    g_recBtn.layer.cornerRadius = 9;
    g_recBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [g_recBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [g_recBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        if (g_recOn) {
            BOOL ok = kp_rec_stop();
            kp_haptic();
            [g_win kp_show_toast:ok ? @"已保存" : @"太短了，没保存"];
        } else {
            if (g_pcmCalls == 0) {
                [g_win kp_show_toast:@"先进房间上麦，麦克风跑起来才能录"];
                return;
            }
            kp_rec_start(g_clipSlotSel);
            kp_haptic();
        }
        kp_clip_refresh_ui();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageClip addSubview:g_recBtn];

    // 循环播放开关
    UILabel *loopLabel = kp_label(CGRectMake(16, 212, 200, 20), @"循环播放当前话术", 11,
                                  [UIColor colorWithWhite:0.85 alpha:1.0], NO);
    [g_pageClip addSubview:loopLabel];
    g_clipLoopSw = kp_switch(CGRectMake(w - 62, 210, 50, 22), g_clipLoop, ^(BOOL on) {
        g_clipLoop = on;
        save_current_settings();
        kp_clip_refresh_ui();
    });
    [g_pageClip addSubview:g_clipLoopSw];

    g_clipStat = kp_label(CGRectMake(16, 240, w - 32, 30), @"", 10, dim, NO);
    g_clipStat.numberOfLines = 2;
    g_clipStat.textAlignment = NSTextAlignmentCenter;
    [g_pageClip addSubview:g_clipStat];

    UILabel *tip = kp_label(CGRectMake(16, 274, w - 32, 40),
                            @"点一下播放，再点一下停止；长按删除该条录音\n开启循环后会一直重复，直到再点一次停止",
                            10, [UIColor colorWithWhite:0.5 alpha:1.0], NO);
    tip.numberOfLines = 0;
    tip.textAlignment = NSTextAlignmentCenter;
    [g_pageClip addSubview:tip];

    kp_clip_refresh_ui();
}

static void kp_select_tab(NSInteger idx) {
    g_pageRack.hidden  = (idx != 0);
    g_pageEq.hidden    = (idx != 1);
    g_pageSound.hidden = (idx != 2);
    g_pageClip.hidden  = (idx != 3);
    g_pageVoice.hidden = (idx != 4);

    for (UIButton *b in g_tabBtns) {
        BOOL sel = (b.tag == idx);
        b.backgroundColor = sel ? [UIColor colorWithRed:0.15 green:0.60 blue:0.34 alpha:1.0]
                                : [UIColor colorWithRed:0.20 green:0.20 blue:0.24 alpha:1.0];
        [b setTitleColor:sel ? [UIColor whiteColor] : [UIColor colorWithWhite:0.80 alpha:1.0]
                 forState:UIControlStateNormal];
    }
}

static void kp_build_panel(void) {
    CGFloat w = KP_PANEL_W, h = KP_PANEL_H;
    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGFloat sh = [UIScreen mainScreen].bounds.size.height;

    g_panel = [[UIView alloc] initWithFrame:CGRectMake((sw - w) / 2, (sh - h) / 2, w, h)];
    g_panel.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.97];
    g_panel.layer.cornerRadius = 16;
    g_panel.layer.borderWidth = 1.0;
    g_panel.layer.borderColor = [UIColor colorWithWhite:0.34 alpha:0.85].CGColor;
    g_panel.hidden = YES;

    // 自定义分页标签：系统 UISegmentedControl 在这个 App 的浅色外观下会用深色字，
    // 深底深字几乎看不见，所以自己画
    NSArray<NSString *> *titles = @[@"调音", @"EQ", @"音效", @"话术", @"变声"];
    NSMutableArray *btns = [NSMutableArray array];
    CGFloat btnW = 46, btnH = 30, gap = 4, x = 8;
    for (NSUInteger i = 0; i < titles.count; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(x + (CGFloat)i * (btnW + gap), 8, btnW, btnH);
        b.tag = (NSInteger)i;
        b.layer.cornerRadius = 7;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [b setTitle:titles[i] forState:UIControlStateNormal];
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            kp_select_tab(b.tag);
        }] forControlEvents:UIControlEventTouchUpInside];
        [g_panel addSubview:b];
        [btns addObject:b];
    }
    g_tabBtns = btns;

    // 三路实时 VU：IN / GR / OUT
    NSArray<NSString *> *vuNames = @[@"IN", @"GR", @"OUT"];
    UIColor *vuColors[3] = {
        [UIColor colorWithRed:0.22 green:0.82 blue:0.42 alpha:1.0],
        [UIColor colorWithRed:0.98 green:0.68 blue:0.20 alpha:1.0],
        [UIColor colorWithRed:0.28 green:0.62 blue:1.00 alpha:1.0]
    };
    CGFloat vuW = (w - 32 - 16) / 3.0;
    g_vuTrackW = vuW;
    for (int i = 0; i < 3; i++) {
        CGFloat vx = 16 + i * (vuW + 8);
        [g_panel addSubview:kp_label(CGRectMake(vx, 40, vuW, 12), vuNames[i], 8.5,
                                     [UIColor colorWithWhite:0.55 alpha:1.0], YES)];
        UIView *track = [[UIView alloc] initWithFrame:CGRectMake(vx, 53, vuW, 7)];
        track.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.13];
        track.layer.cornerRadius = 3.5;
        track.layer.masksToBounds = YES;
        UIView *fill = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 0, 7)];
        fill.backgroundColor = vuColors[i];
        fill.layer.cornerRadius = 3.5;
        fill.layer.masksToBounds = YES;
        [track addSubview:fill];
        [g_panel addSubview:track];
        if (i == 0)      g_vuInFill  = fill;
        else if (i == 1) g_vuGrFill  = fill;
        else             g_vuOutFill = fill;
    }

    UIButton *close = [UIButton buttonWithType:UIButtonTypeCustom];
    close.frame = CGRectMake(w - 42, 8, 32, 30);
    [close setTitle:@"✕" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
    [close addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        g_panel.hidden = YES;
        save_current_settings();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:close];

    kp_build_rack_page(w);
    kp_build_eq_page(w);
    kp_build_voice_page(w);
    kp_build_sound_page(w);
    kp_build_clip_page(w);

    // 底部授权条：未授权时整条红色，点一下弹授权框
    CGFloat barH = 17;
    g_licBar = [UIButton buttonWithType:UIButtonTypeCustom];
    g_licBar.frame = CGRectMake(10, h - barH - 3, w - 20, barH);
    g_licBar.layer.cornerRadius = 5;
    g_licBar.titleLabel.font = [UIFont systemFontOfSize:9];
    g_licBar.contentHorizontalAlignment = UIControlContentHorizontalAlignmentCenter;
    [g_licBar addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        kp_lic_show_alert();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:g_licBar];
    kp_lic_refresh_bar();

    kp_select_tab(0);

    [g_win addSubview:g_panel];
}

// ==========================================
// 诊断日志：沙盒 Documents/KakaAudio/rack.log
// ==========================================
static void kp_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSString *doc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [doc stringByAppendingPathComponent:@"KakaAudio"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSString *path = [dir stringByAppendingPathComponent:@"rack.log"];
    NSString *line = [NSString stringWithFormat:@"[%.2f] %@\n", [NSDate date].timeIntervalSince1970, msg];

    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

static void kp_attach_scene(void) {
    if (!g_win) return;
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            if (ws.activationState == UISceneActivationStateForegroundActive ||
                ws.activationState == UISceneActivationStateForegroundInactive) {
                g_win.windowScene = ws;
                kp_log(@"scene attached, state=%ld", (long)ws.activationState);
                return;
            }
        }
    }
}

static void kp_build_ui(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_win) return;
        kp_log(@"build_ui: enter");
        load_saved_settings();
        kp_reverb_reset();
        kp_gate_reset();
        kp_load_sfx_library();
        kp_log(@"build_ui: audio assets ready");

        // 后台恢复上次播放的伴奏（不自动播放）
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            NSString *name = g_bgmName;
            if (!name.length) return;
            NSString *p = [kp_bgm_dir() stringByAppendingPathComponent:name];
            if (![[NSFileManager defaultManager] fileExistsAtPath:p]) return;
            UInt32 n = 0;
            int16_t *buf = kp_load_audio(p, &n);
            if (!buf || n == 0) return;
            dispatch_async(dispatch_get_main_queue(), ^{
                if (g_bgmLen > 0) { free(buf); return; }
                g_bgmPcm = buf;
                g_bgmLen = (int)n;
                g_bgmPos = 0;
                kp_log(@"bgm restored: %@", name);
            });
        });

        g_win = [[KPFloatWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        kp_attach_scene();
        g_win.windowLevel = UIWindowLevelAlert + 100;
        g_win.backgroundColor = [UIColor clearColor];
        g_win.hidden = NO;

        g_ball = [UIButton buttonWithType:UIButtonTypeCustom];
        g_ball.frame = CGRectMake(16, 160, 150, 36);
        g_ball.layer.cornerRadius = 18;
        g_ball.layer.masksToBounds = YES;
        g_ball.layer.borderWidth = 1.2;
        g_ball.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.75].CGColor;
        g_ball.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        [g_ball setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [g_ball addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            kp_toggle_panel();
        }] forControlEvents:UIControlEventTouchUpInside];

        SEL panSel = NSSelectorFromString(@"kp_pan:");
        class_addMethod([g_ball class], panSel, imp_implementationWithBlock(^(id _self, UIPanGestureRecognizer *pan) {
            UIView *v = pan.view;
            CGPoint t = [pan translationInView:v.superview];
            v.center = CGPointMake(v.center.x + t.x, v.center.y + t.y);
            [pan setTranslation:CGPointZero inView:v.superview];
        }), "v@:@");
        [g_ball addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:g_ball action:panSel]];

        [g_win addSubview:g_ball];
        kp_build_panel();
        kp_log(@"build_ui: window + panel ready");

        kp_tick();
        g_tick = [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer *_Nonnull t) {
            kp_tick();
        }];
    });
}

// ==========================================
// 11. 入口
// ==========================================

// 把某个 BOOL 属性的 getter 锁死为 NO，setter 强制传 NO（防外部再打开）
static void kp_lock_bool_prop(Class cls, NSString *getterName, NSString *setterName) {
    SEL g = NSSelectorFromString(getterName);
    SEL s = NSSelectorFromString(setterName);
    Method mg = class_getInstanceMethod(cls, g);
    if (mg) {
        method_setImplementation(mg, imp_implementationWithBlock(^BOOL(id _s) {
            (void)_s;
            return NO;
        }));
    }
    Method ms = class_getInstanceMethod(cls, s);
    if (ms) {
        IMP orig = method_getImplementation(ms);
        method_setImplementation(ms, imp_implementationWithBlock(^(id _s, BOOL en) {
            (void)en;
            ((void (*)(id, SEL, BOOL))orig)(_s, s, NO);
        }));
    }
}

static BOOL (*kp_orig_av_setMode)(id, SEL, NSString *, NSError **) = NULL;
static BOOL kp_hook_av_setMode(id self, SEL _cmd, NSString *mode, NSError **err) {
    NSString *targetMode = mode;
    if (g_deepBypassVP && [mode isEqualToString:@"AVAudioSessionModeVoiceChat"]) {
        targetMode = @"AVAudioSessionModeDefault";
    }
    return kp_orig_av_setMode ? kp_orig_av_setMode(self, _cmd, targetMode, err) : YES;
}

// 关掉系统 / WebRTC 的 AGC：否则你声音一大，它就把增益偷偷拉回去
static void kp_disable_agc(void) {
    // ① WebRTC 设备层
    Class adm = objc_getClass("RTCAudioDeviceModule");
    if (adm) {
        Method m = class_getInstanceMethod(adm, @selector(setVoiceProcessingAGCEnabled:));
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id _s, BOOL en) { (void)en; }));
        m = class_getInstanceMethod(adm, @selector(isVoiceProcessingAGCEnabled));
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id _s) { return NO; }));
    }

    // ② WebRTC APM：v29.8 硬锁 AGC / 降噪 / 瞬态抑制，AEC 改为条件关
    Class cfg = objc_getClass("RTCAudioProcessingConfig");
    if (cfg) {
        kp_lock_bool_prop(cfg, @"isAutoGainControl1Enabled", @"setIsAutoGainControl1Enabled:");
        kp_lock_bool_prop(cfg, @"isAutoGainControl2Enabled", @"setIsAutoGainControl2Enabled:");
        kp_lock_bool_prop(cfg, @"isNoiseSuppressionEnabled", @"setIsNoiseSuppressionEnabled:");
        kp_lock_bool_prop(cfg, @"isTransientSuppressionEnabled", @"setIsTransientSuppressionEnabled:");
        kp_lock_bool_prop(cfg, @"isHighPassFilterEnabled", @"setIsHighPassFilterEnabled:");

        // AEC：无损优先 / 强声霸麦 / 屏蔽器 任一开启时强制关，其余情况交还原实现
        Method mg = class_getInstanceMethod(cfg, @selector(isEchoCancellerEnabled));
        if (mg) {
            IMP orig = method_getImplementation(mg);
            method_setImplementation(mg, imp_implementationWithBlock(^BOOL(id _s) {
                if (g_losslessPriority || g_priorityLoud || g_shieldRemote) return NO;
                return ((BOOL (*)(id, SEL))orig)(_s, @selector(isEchoCancellerEnabled));
            }));
        }
        Method ms = class_getInstanceMethod(cfg, @selector(setIsEchoCancellerEnabled:));
        if (ms) {
            IMP orig = method_getImplementation(ms);
            method_setImplementation(ms, imp_implementationWithBlock(^(id _s, BOOL en) {
                BOOL v = (g_losslessPriority || g_priorityLoud || g_shieldRemote) ? NO : en;
                ((void (*)(id, SEL, BOOL))orig)(_s, @selector(setIsEchoCancellerEnabled:), v);
            }));
        }
        kp_log(@"[apm] hard-lock AGC1/AGC2/NS/TS/HPF, condAEC");
    }

    // ④ AVAudioSession 模式：仅二级高风险开关打开时才改，默认不动
    Class avs = objc_getClass("AVAudioSession");
    if (avs) {
        Method m = class_getInstanceMethod(avs, @selector(setMode:error:));
        if (m && !kp_orig_av_setMode) {
            kp_orig_av_setMode = (BOOL (*)(id, SEL, NSString *, NSError **))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_hook_av_setMode);
        }
    }

    // ③ iOS VoiceProcessingIO 硬件单元
    Class ion = objc_getClass("AVAudioInputNode");
    if (ion) {
        Method m = class_getInstanceMethod(ion, @selector(setVoiceProcessingAGCEnabled:));
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id _s, BOOL en) { (void)en; }));
        m = class_getInstanceMethod(ion, @selector(isVoiceProcessingAGCEnabled));
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id _s) { return NO; }));
    }
}

// ---------- SDP 劫持：把 opus 协商锁定到 192kbps / 立体声 / CBR ----------
static id (*kp_orig_init_sdp)(id, SEL, NSInteger, NSString *) = NULL;

static NSString *kp_sdp_patch(NSString *sdp) {
    if (![sdp containsString:@"opus/48000"]) return sdp;

    NSInteger opusBr = g_opusBitrateBps;
    if (opusBr != 192000 && opusBr != 256000 && opusBr != 320000 && opusBr != 510000) opusBr = 320000;

    NSString *sep = [sdp containsString:@"\r\n"] ? @"\r\n" : @"\n";
    NSMutableArray<NSString *> *lines = [[sdp componentsSeparatedByString:sep] mutableCopy];

    // ① 从 a=rtpmap:<pt> opus/48000/2 取真实 payload type（111/109/63 都可能）
    NSString *pt = nil;
    NSUInteger rtpmapIdx = NSNotFound;
    for (NSUInteger i = 0; i < lines.count; i++) {
        NSString *ln = lines[i];
        if (![ln hasPrefix:@"a=rtpmap:"]) continue;
        if ([ln rangeOfString:@"opus/48000"].location == NSNotFound) continue;
        NSRange sp = [ln rangeOfString:@" "];
        if (sp.location == NSNotFound || sp.location <= 9) continue;
        pt = [ln substringWithRange:NSMakeRange(9, sp.location - 9)];
        rtpmapIdx = i;
        break;
    }
    if (pt.length == 0) pt = @"111";

    BOOL changed = NO;
    BOOL hitFmtp = NO;
    NSString *fkey = [NSString stringWithFormat:@"a=fmtp:%@", pt];

    // ② 改 fmtp：按 ; 拆分后过滤同名参数，再统一追加（幂等，且不会误伤 sprop-stereo）
    for (NSUInteger i = 0; i < lines.count; i++) {
        NSString *ln = lines[i];
        if (![ln hasPrefix:fkey]) continue;
        if (ln.length > fkey.length && [ln characterAtIndex:fkey.length] != ' ') continue;

        NSString *rest = (ln.length > fkey.length) ? [ln substringFromIndex:fkey.length] : @"";
        NSMutableArray<NSString *> *keep = [NSMutableArray array];
        for (NSString *kv in [rest componentsSeparatedByString:@";"]) {
            NSString *t = [kv stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceCharacterSet]];
            if (t.length == 0) continue;
            if ([t hasPrefix:@"maxaveragebitrate="] || [t hasPrefix:@"stereo="] ||
                [t hasPrefix:@"sprop-stereo="]     || [t hasPrefix:@"cbr="] ||
                [t hasPrefix:@"usedtx="]           || [t hasPrefix:@"useinbandfec="] ||
                [t hasPrefix:@"maxplaybackrate="]  || [t hasPrefix:@"sprop-maxcapturerate="]) continue;
            [keep addObject:t];
        }
        [keep addObject:@"stereo=1"];
        [keep addObject:@"sprop-stereo=1"];
        [keep addObject:[NSString stringWithFormat:@"maxaveragebitrate=%ld", (long)opusBr]];
        [keep addObject:@"maxplaybackrate=48000"];
        [keep addObject:@"sprop-maxcapturerate=48000"];
        [keep addObject:@"cbr=1"];
        [keep addObject:@"usedtx=0"];
        [keep addObject:@"useinbandfec=1"];
        lines[i] = [NSString stringWithFormat:@"%@ %@",
                    fkey, [keep componentsJoinedByString:@";"]];
        hitFmtp = YES;
        changed = YES;
        break;
    }

    // 没有 fmtp 行就紧跟 rtpmap 补一条
    if (!hitFmtp && rtpmapIdx != NSNotFound) {
        NSString *nf = [NSString stringWithFormat:
                        @"%@ stereo=1;sprop-stereo=1;maxaveragebitrate=%ld;maxplaybackrate=48000;sprop-maxcapturerate=48000;cbr=1;usedtx=0;useinbandfec=1",
                        fkey, (long)opusBr];
        [lines insertObject:nf atIndex:rtpmapIdx + 1];
        changed = YES;
    }

    // ③ 在 m=audio 段补 b=AS / b=TIAS
    // SDP 规定媒体段内顺序为 m= → i= → c= → b= → k= → a=，所以必须排在 c= 之后
    for (NSUInteger i = 0; i < lines.count; i++) {
        if (![lines[i] hasPrefix:@"m=audio"]) continue;
        NSUInteger pos = i + 1;
        BOOL hasB = NO;
        for (NSUInteger j = i + 1; j < lines.count; j++) {
            NSString *lj = lines[j];
            if (lj.length == 0) continue;
            if ([lj hasPrefix:@"m="]) break;
            if ([lj hasPrefix:@"b="]) { hasB = YES; break; }
            if ([lj hasPrefix:@"i="] || [lj hasPrefix:@"c="]) { pos = j + 1; continue; }
            if ([lj hasPrefix:@"a="] || [lj hasPrefix:@"k="]) break;
        }
        if (!hasB) {
            [lines insertObject:[NSString stringWithFormat:@"b=AS:%ld", (long)(opusBr / 1000)] atIndex:pos];
            [lines insertObject:[NSString stringWithFormat:@"b=TIAS:%ld", (long)opusBr] atIndex:pos + 1];
            changed = YES;
        }
        break;
    }

    if (!changed) return sdp;
    kp_log(@"SDP: opus pt=%@ -> %ldkbps stereo cbr usedtx=0", pt, (long)(opusBr / 1000));
    return [lines componentsJoinedByString:sep];
}

static id kp_hook_init_sdp(id self, SEL _cmd, NSInteger type, NSString *sdp) {
    NSString *patched = sdp;
    @try {
        if (sdp.length) {
            NSString *p = kp_sdp_patch(sdp);
            // 结果必须仍是合法 SDP，否则宁可放弃提速也不能弄哑推流
            if ([p containsString:@"m=audio"] && [p containsString:@"opus/48000"]) {
                patched = p;
            } else {
                kp_log(@"SDP: 补丁结果异常，回退原 SDP");
            }
        }
    } @catch (NSException *e) {
        kp_log(@"SDP: 补丁异常 %@，回退原 SDP", e.reason);
        patched = sdp;
    }
    return kp_orig_init_sdp(self, _cmd, type, patched);
}

static void kp_setup_sdp_hook(void) {
    Class cls = objc_getClass("RTCSessionDescription");
    if (!cls) {
        kp_log(@"SDP: 未发现 RTCSessionDescription，跳过");
        return;
    }
    Method m = class_getInstanceMethod(cls, @selector(initWithType:sdp:));
    if (!m) {
        kp_log(@"SDP: 未找到 initWithType:sdp:");
        return;
    }
    kp_orig_init_sdp = (id (*)(id, SEL, NSInteger, NSString *))method_getImplementation(m);
    method_setImplementation(m, (IMP)kp_hook_init_sdp);
    kp_log(@"SDP: hook 已安装");
}

// ---------- RTCRtpSender：锁死发送码率与网络优先级 ----------
static BOOL kp_senderHooked = NO;
static void (*kp_orig_setParamsCH)(id, SEL, id, void (^)(NSError *)) = NULL;
static void (*kp_orig_setParams)(id, SEL, id) = NULL;

static void kp_lock_send_params(id params) {
    if (!params) return;
    id encs = nil;
    @try { encs = [params valueForKey:@"encodings"]; } @catch (NSException *e) { return; }
    if (![encs isKindOfClass:[NSArray class]]) return;

    NSNumber *br = @(g_opusBitrateBps);
    for (id enc in encs) {
        @try { [enc setValue:br forKey:@"maxBitrateBps"]; } @catch (NSException *e) {}
        @try { [enc setValue:@(4) forKey:@"networkPriority"]; } @catch (NSException *e) {}
        @try { [enc setValue:@(1) forKey:@"priority"]; } @catch (NSException *e) {}
    }
}

static void kp_hook_setParamsCH(id self, SEL _cmd, id params, void (^handler)(NSError *)) {
    kp_lock_send_params(params);
    if (kp_orig_setParamsCH) kp_orig_setParamsCH(self, _cmd, params, handler);
}

static void kp_hook_setParams(id self, SEL _cmd, id params) {
    kp_lock_send_params(params);
    if (kp_orig_setParams) kp_orig_setParams(self, _cmd, params);
}

static void kp_setup_sender_hook(void) {
    if (kp_senderHooked) return;
    Class cls = objc_getClass("RTCRtpSender");
    if (!cls) return;

    Method m1 = class_getInstanceMethod(cls, @selector(setParameters:completionHandler:));
    if (m1) {
        kp_orig_setParamsCH = (void (*)(id, SEL, id, void (^)(NSError *)))method_getImplementation(m1);
        method_setImplementation(m1, (IMP)kp_hook_setParamsCH);
    }
    Method m2 = class_getInstanceMethod(cls, @selector(setParameters:));
    if (m2) {
        kp_orig_setParams = (void (*)(id, SEL, id))method_getImplementation(m2);
        method_setImplementation(m2, (IMP)kp_hook_setParams);
    }
    if (m1 || m2) {
        kp_senderHooked = YES;
        kp_log(@"RTP: sender setParameters hook 已安装 (%s%s)",
               m1 ? "async" : "", m2 ? "+sync" : "");
    }
}

// ---------- v29.5：屏蔽他人声音（只静音远端播放轨，不动服务端） ----------
static BOOL kp_shieldHooked = NO;
static id   (*kp_orig_recv_track)(id, SEL) = NULL;
static void (*kp_orig_recv_setTrack)(id, SEL, id) = NULL;
static BOOL (*kp_orig_mst_isEnabled)(id, SEL) = NULL;
static void (*kp_orig_mst_setEnabled)(id, SEL, BOOL) = NULL;
static void (*kp_orig_aud_setEnabled)(id, SEL, BOOL) = NULL;

static void kp_shield_note_track(id t) {
    if (!t) return;
    if (!g_shieldTracks) g_shieldTracks = [NSMutableArray array];
    @synchronized (g_shieldTracks) {
        if (![g_shieldTracks containsObject:t]) {
            [g_shieldTracks addObject:t];
            if (g_shieldTracks.count > 24) [g_shieldTracks removeObjectAtIndex:0];
        }
    }
    if (g_shieldRemote) kp_shield_apply();
}

static void kp_shield_set_volume(id t, float v) {
    @try {
        id src = [t valueForKey:@"source"];
        SEL s = NSSelectorFromString(@"setVolume:");
        if (src && [src respondsToSelector:s]) {
            ((void (*)(id, SEL, double))objc_msgSend)(src, s, (double)v);
        }
    } @catch (NSException *e) {}
}

// 0=正常 1=压低到 20% 2=全屏蔽
static int kp_shield_level(void) {
    if (!g_shieldRemote) return 0;
    return g_shieldLowOnly ? 1 : 2;
}

static void kp_shield_apply(void) {
    if (!g_shieldTracks) return;
    int lv = kp_shield_level();
    NSArray *snapshot = nil;
    @synchronized (g_shieldTracks) { snapshot = [g_shieldTracks copy]; }
    for (id t in snapshot) {
        @try {
            BOOL en = (lv != 2);
            [t setValue:@(en) forKey:@"isEnabled"];
            kp_shield_set_volume(t, lv == 1 ? 0.2f : (lv == 2 ? 0.0f : 1.0f));
        }
        @catch (NSException *e) {}
    }
}

static id kp_hook_recv_track(id self, SEL _cmd) {
    id t = kp_orig_recv_track ? kp_orig_recv_track(self, _cmd) : nil;
    kp_shield_note_track(t);
    return t;
}

static void kp_hook_recv_setTrack(id self, SEL _cmd, id t) {
    kp_shield_note_track(t);
    if (kp_orig_recv_setTrack) kp_orig_recv_setTrack(self, _cmd, t);
}

static BOOL kp_hook_mst_isEnabled(id self, SEL _cmd) {
    if (g_shieldRemote && !g_shieldLowOnly && g_shieldTracks &&
        [g_shieldTracks containsObject:self]) return NO;
    return kp_orig_mst_isEnabled ? kp_orig_mst_isEnabled(self, _cmd) : YES;
}

static void kp_hook_mst_setEnabled(id self, SEL _cmd, BOOL en) {
    if (g_shieldRemote && !g_shieldLowOnly && g_shieldTracks &&
        [g_shieldTracks containsObject:self]) en = NO;
    if (kp_orig_mst_setEnabled) kp_orig_mst_setEnabled(self, _cmd, en);
}

static void kp_hook_aud_setEnabled(id self, SEL _cmd, BOOL en) {
    if (g_shieldRemote && !g_shieldLowOnly && g_shieldTracks &&
        [g_shieldTracks containsObject:self]) en = NO;
    if (kp_orig_aud_setEnabled) kp_orig_aud_setEnabled(self, _cmd, en);
}

static void kp_setup_shield_hook(void) {
    if (kp_shieldHooked) return;

    Class recv = objc_getClass("RTCRtpReceiver");
    Class mst  = objc_getClass("RTCMediaStreamTrack");
    Class aud  = objc_getClass("RTCAudioTrack");
    if (!recv && !mst && !aud) return;

    BOOL ok = NO;
    if (recv) {
        SEL sTrack = NSSelectorFromString(@"track");
        SEL sSet   = NSSelectorFromString(@"setTrack:");
        Method m1 = class_getInstanceMethod(recv, sTrack);
        Method m2 = class_getInstanceMethod(recv, sSet);
        if (m1) {
            kp_orig_recv_track = (id (*)(id, SEL))method_getImplementation(m1);
            method_setImplementation(m1, (IMP)kp_hook_recv_track);
            ok = YES;
        }
        if (m2) {
            kp_orig_recv_setTrack = (void (*)(id, SEL, id))method_getImplementation(m2);
            method_setImplementation(m2, (IMP)kp_hook_recv_setTrack);
            ok = YES;
        }
    }

    // 真正的开关在父类 RTCMediaStreamTrack 的 -setIsEnabled: / -isEnabled
    Class enabledCls = mst ? mst : aud;
    if (enabledCls) {
        Method g = class_getInstanceMethod(enabledCls, NSSelectorFromString(@"isEnabled"));
        Method s = class_getInstanceMethod(enabledCls, NSSelectorFromString(@"setIsEnabled:"));
        if (g) {
            kp_orig_mst_isEnabled = (BOOL (*)(id, SEL))method_getImplementation(g);
            method_setImplementation(g, (IMP)kp_hook_mst_isEnabled);
            ok = YES;
        }
        if (s) {
            kp_orig_mst_setEnabled = (void (*)(id, SEL, BOOL))method_getImplementation(s);
            method_setImplementation(s, (IMP)kp_hook_mst_setEnabled);
            ok = YES;
        }
    }
    // 老版本 WebRTC 用 -setEnabled:
    if (aud) {
        Method s2 = class_getInstanceMethod(aud, NSSelectorFromString(@"setEnabled:"));
        if (s2) {
            kp_orig_aud_setEnabled = (void (*)(id, SEL, BOOL))method_getImplementation(s2);
            method_setImplementation(s2, (IMP)kp_hook_aud_setEnabled);
            ok = YES;
        }
    }

    if (ok) {
        kp_shieldHooked = YES;
        kp_log(@"[shield] hook installed recv=%d mst=%d aud=%d", recv != NULL, mst != NULL, aud != NULL);
    }
}

// ---------- v29.6：KAKA 原生放行 Hook（防止底层拦本地采集/放歌） ----------
static BOOL kp_kakaAllowHooked = NO;
static BOOL (*kp_orig_capAllow)(id, SEL) = NULL;
static void (*kp_orig_setCapAllow)(id, SEL, BOOL) = NULL;
static BOOL (*kp_orig_musicAllow)(id, SEL) = NULL;
static void (*kp_orig_setMusicAllow)(id, SEL, BOOL) = NULL;
static void (*kp_orig_mixProc)(id, SEL, int16_t *, unsigned long long, unsigned long long, double) = NULL;
static _Atomic long g_mixProcCalls = 0;

static BOOL kp_hook_capAllow(id self, SEL _cmd) {
    if (g_losslessPriority) return YES;
    return kp_orig_capAllow ? kp_orig_capAllow(self, _cmd) : YES;
}

static void kp_hook_setCapAllow(id self, SEL _cmd, BOOL v) {
    if (g_losslessPriority) v = YES;
    if (kp_orig_setCapAllow) kp_orig_setCapAllow(self, _cmd, v);
}

static BOOL kp_hook_musicAllow(id self, SEL _cmd) {
    if (g_losslessPriority) return YES;
    return kp_orig_musicAllow ? kp_orig_musicAllow(self, _cmd) : YES;
}

static void kp_hook_setMusicAllow(id self, SEL _cmd, BOOL v) {
    if (g_losslessPriority) v = YES;
    if (kp_orig_setMusicAllow) kp_orig_setMusicAllow(self, _cmd, v);
}

static void kp_hook_mixProc(id self, SEL _cmd, int16_t *pcm, unsigned long long frames,
                            unsigned long long chs, double rate) {
    long n = ++g_mixProcCalls;
    // 在“原方法之后”再统计，才能看到 KakaAudioMixer 真正输出的电平
    if (kp_orig_mixProc) kp_orig_mixProc(self, _cmd, pcm, frames, chs, rate);

    static double lastT = 0;
    static int peak = 0;
    static double sumSq = 0;
    static long samples = 0;
    if (pcm && frames > 0) {
        unsigned long long total = frames * (chs > 0 ? chs : 1);
        for (unsigned long long i = 0; i < total; i++) {
            int a = pcm[i] < 0 ? -(int)pcm[i] : (int)pcm[i];
            int p = (int)((a * 100) / 32768);
            if (p > peak) peak = p;
            double f = (double)pcm[i] / 32768.0;
            sumSq += f * f;
            samples++;
        }
    }
    double now = CACurrentMediaTime();
    if (lastT == 0) { lastT = now; return; }
    if (now - lastT >= 5.0) {
        double rms = (samples > 0) ? sqrt(sumSq / (double)samples) : 0.0;
        double db  = 20.0 * log10(rms > 1e-9 ? rms : 1e-9);
        kp_log(@"[mixproc] calls=%ld frames=%llu ch=%llu rate=%.0f outPeak=%d%% outRMS=%.1fdB",
               n, frames, chs, rate, peak, db);
        lastT = now; peak = 0; sumSq = 0; samples = 0;
    }
}

// ---------- v30.1：防“超 3 人房”偷偷关采集轨 / 重置采集门限 ----------
static void (*kp_orig_setCapTrackEn)(id, SEL, id, BOOL) = NULL;
static void (*kp_orig_resetCapGate)(id, SEL) = NULL;

static void kp_hook_setCapTrackEn(id self, SEL _cmd, id track, BOOL en) {
    if (g_oneTapMasterLock || g_priorityLoud) en = YES;   // 锁定时禁止业务层关采集
    if (kp_orig_setCapTrackEn) kp_orig_setCapTrackEn(self, _cmd, track, en);
}

static void kp_hook_resetCapGate(id self, SEL _cmd) {
    if (g_oneTapMasterLock || g_priorityLoud) {
        kp_log(@"[anticut] 拦截多人房重置采集门限");
        return;
    }
    if (kp_orig_resetCapGate) kp_orig_resetCapGate(self, _cmd);
}

static void kp_setup_kaka_allow_hooks(void) {
    if (kp_kakaAllowHooked) return;

    Class dev = objc_getClass("KakaStereoAudioDevice");
    Class mix = objc_getClass("KakaAudioMixer");
    if (!dev && !mix) return;

    BOOL ok = NO;
    if (dev) {
        SEL gSel = NSSelectorFromString(@"roomCaptureDeliveryAllowed");
        SEL sSel = NSSelectorFromString(@"setRoomCaptureDeliveryAllowed:");
        Method g = class_getInstanceMethod(dev, gSel);
        Method s = class_getInstanceMethod(dev, sSel);
        if (g) {
            kp_orig_capAllow = (BOOL (*)(id, SEL))method_getImplementation(g);
            method_setImplementation(g, (IMP)kp_hook_capAllow);
            ok = YES;
        }
        if (s) {
            kp_orig_setCapAllow = (void (*)(id, SEL, BOOL))method_getImplementation(s);
            method_setImplementation(s, (IMP)kp_hook_setCapAllow);
            ok = YES;
        }
        kp_log(@"[allow] dev gate get=%d set=%d", g != NULL, s != NULL);

        // v30.1：封死“第 4 个人上麦时关采集轨 / 重置采集门限”的后门
        SEL ctSel = NSSelectorFromString(@"kakaSetCaptureTrack:enabled:");
        Method ct = class_getInstanceMethod(dev, ctSel);
        if (ct) {
            kp_orig_setCapTrackEn = (void (*)(id, SEL, id, BOOL))method_getImplementation(ct);
            method_setImplementation(ct, (IMP)kp_hook_setCapTrackEn);
            ok = YES;
        }
        SEL rcSel = NSSelectorFromString(@"kakaResetCaptureGate");
        Method rc = class_getInstanceMethod(dev, rcSel);
        if (rc) {
            kp_orig_resetCapGate = (void (*)(id, SEL))method_getImplementation(rc);
            method_setImplementation(rc, (IMP)kp_hook_resetCapGate);
            ok = YES;
        }
        kp_log(@"[anticut] setCaptureTrack=%d resetCapGate=%d", ct != NULL, rc != NULL);
    }
    if (mix) {
        SEL gSel = NSSelectorFromString(@"roomMusicAllowed");
        SEL sSel = NSSelectorFromString(@"setRoomMusicAllowed:");
        SEL mSel = NSSelectorFromString(@"mixProcessedPCM:frames:channels:rate:");
        Method g = class_getInstanceMethod(mix, gSel);
        Method s = class_getInstanceMethod(mix, sSel);
        Method mp = class_getInstanceMethod(mix, mSel);
        if (g) {
            kp_orig_musicAllow = (BOOL (*)(id, SEL))method_getImplementation(g);
            method_setImplementation(g, (IMP)kp_hook_musicAllow);
            ok = YES;
        }
        if (s) {
            kp_orig_setMusicAllow = (void (*)(id, SEL, BOOL))method_getImplementation(s);
            method_setImplementation(s, (IMP)kp_hook_setMusicAllow);
            ok = YES;
        }
        if (mp) {
            kp_orig_mixProc = (void (*)(id, SEL, int16_t *, unsigned long long, unsigned long long, double))method_getImplementation(mp);
            method_setImplementation(mp, (IMP)kp_hook_mixProc);
            ok = YES;
        }
        kp_log(@"[allow] mix music get=%d set=%d mixProc=%d", g != NULL, s != NULL, mp != NULL);
    }
    if (ok) kp_kakaAllowHooked = YES;
}

__attribute__((constructor)) static void kp_entry(void) {
    load_saved_settings();  // 必须最先读：SDP 协商可能早于 UI 构建
    kp_lic_load();          // 再读授权，未授权则全部机架功能跳过
    kp_disable_agc();
    kp_eq_init();
    // SDP 劫持：默认开启，置 NSUserDefaults kaka_sdp_boost = NO 可关闭
    NSUserDefaults *udSdp = [NSUserDefaults standardUserDefaults];
    BOOL sdpBoost = [udSdp objectForKey:@"kaka_sdp_boost"] ? [udSdp boolForKey:@"kaka_sdp_boost"] : YES;
    if (sdpBoost) {
        kp_setup_sdp_hook();
        kp_setup_sender_hook();
        kp_setup_shield_hook();
        kp_setup_kaka_allow_hooks();
    } else {
        kp_log(@"SDP: 已被 kaka_sdp_boost=NO 关闭");
    }
    kp_reverb_reset();
    kp_gate_reset();
    kp_lim_reset();

    struct rebinding rebinds[] = {
        {"SecItemCopyMatching", (void *)kp_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemAdd",          (void *)kp_SecItemAdd,          (void **)&orig_SecItemAdd},
        {"SecItemUpdate",       (void *)kp_SecItemUpdate,       (void **)&orig_SecItemUpdate},
        {"SecItemDelete",       (void *)kp_SecItemDelete,       (void **)&orig_SecItemDelete},
    };
    rebind_symbols(rebinds, sizeof(rebinds) / sizeof(rebinds[0]));

    // 类可能还没注册：每秒重试，最多 90 秒
    dispatch_async(dispatch_get_main_queue(), ^{
        kp_log(@"dylib loaded %@", KP_VERSION);
        __block int tries = 0;
        NSTimer *t = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *_Nonnull timer) {
            int s = kp_install_hooks();
            if (s != g_hookState) kp_log(@"hooks state -> %d", s);
            g_hookState = s;
            kp_setup_sender_hook();   // WebRTC 类延迟加载时补挂
            kp_setup_shield_hook();
            kp_setup_kaka_allow_hooks();
            kp_shield_apply();
            if ((s == 3 && kp_senderHooked && kp_shieldHooked && kp_kakaAllowHooked) || ++tries > 90) [timer invalidate];
        }];
        (void)t;

        // 独立巡检：房间新上麦 / 重协商产生新远端轨时，0.5s 内补静音
        NSTimer *sh = [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *_Nonnull timer) {
            if (!g_shieldRemote) return;
            kp_shield_apply();
        }];
        (void)sh;
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        kp_build_ui();
    });
}
