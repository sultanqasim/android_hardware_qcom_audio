/*
 * Copyright (C) 2016 The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "htc_tfa_amp"
#include <cutils/log.h>

#include "htc_amp.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sound/asound.h>

#define AMP_PATH "/dev/tfa9888"
#define HTC_AMP_PCM_DEVICE 47

static int htc_tfa_perform(struct audio_device *adev, const char *amp_seq_file);
static int htc_mi2s_open(struct audio_device *adev, struct pcm **pcm);
static int htc_mi2s_close(struct audio_device *adev, struct pcm **pcm);
static int htc_tfa_load(const char *amp_seq_file);
static int amp_load_sequence(FILE *seq, int amp_fd);

int htc_tfa_init(struct audio_device *adev)
{
    return htc_tfa_perform(adev, "/system/etc/tfa9888_init.asq");
}

int htc_tfa_unmute(struct audio_device *adev)
{
    return htc_tfa_perform(adev, "/system/etc/tfa9888_enable.asq");
}

int htc_tfa_mute(struct audio_device *adev)
{
    return htc_tfa_perform(adev, "/system/etc/tfa9888_disable.asq");
}

static int htc_tfa_perform(struct audio_device *adev, const char *amp_seq_file)
{
    struct pcm *pcm;
    int ret;

    ret = htc_mi2s_open(adev, &pcm);
    if (ret) {
        ALOGE("Failed to open HTC I2S device");
        return ret;
    }

    ret = htc_tfa_load(amp_seq_file);
    if (ret) {
        ALOGE("Failed to load TFA amplifier sequence %s", amp_seq_file);
        htc_mi2s_close(adev, &pcm);
        return ret;
    }

    return htc_mi2s_close(adev, &pcm);
}

static int htc_mi2s_open(struct audio_device *adev, struct pcm **pcm)
{
    struct mixer_ctl *ctl;
    struct pcm_config conf;
    struct pcm_params *params;

    ctl = mixer_get_ctl_by_name(adev->mixer, "QUAT_MI2S_RX_DL_HL Switch");
    if (ctl == NULL) {
        ALOGE("Failed to get mixer ctl");
        return -1;
    }

    params = pcm_params_get(adev->snd_card, HTC_AMP_PCM_DEVICE, 0);
    if (params == NULL) {
        ALOGE("Failed to get PCM params");
        return -2;
    }

    memset(&conf, 0, sizeof(struct pcm_config));
    conf.channels = 1;
    conf.rate = 48000;
    conf.period_count = pcm_params_get_max(params, PCM_PARAM_PERIODS);

    pcm_params_free(params);

    mixer_ctl_set_value(ctl, 0, 1);

    *pcm = pcm_open(adev->snd_card, HTC_AMP_PCM_DEVICE, 0, &conf);
    if (!*pcm) {
        ALOGE("Failed to open PCM device");
        return -3;
    }

    if (!pcm_is_ready(*pcm)) {
        ALOGE("PCM is not ready");
        pcm_close(*pcm);
        *pcm = NULL;
        return -4;
    }

    return 0;
}

static int htc_mi2s_close(struct audio_device *adev, struct pcm **pcm)
{
    struct mixer_ctl *ctl;
    int ret = 0;

    ctl = mixer_get_ctl_by_name(adev->mixer, "QUAT_MI2S_RX_DL_HL Switch");
    if (ctl == NULL) {
        ALOGE("Failed to get mixer ctl");
        ret = -1;
    } else {
        mixer_ctl_set_value(ctl, 0, 0);
    }

    if (*pcm) {
        pcm_close(*pcm);
        *pcm = NULL;
    }

    return ret;
}

static int htc_tfa_load(const char *amp_seq_file)
{
    FILE *seq;
    int amp;
    int ret;

    amp = open(AMP_PATH, O_RDWR);
    if (amp < 0) {
        ALOGE("Failed to open amplifier %s", AMP_PATH);
        return -errno;
    }

    seq = fopen(amp_seq_file, "rb");
    if (!seq) {
        close(amp);
        return -3;
    }

    ret = amp_load_sequence(seq, amp);
    if (ret == -4) {
        ALOGE("Unexpected EOF");
    } else if (ret == -5) {
        ALOGE("IO error");
    } else if (ret == -6) {
        ALOGE("An unexpected response was received");
    }

    fclose(seq);
    close(amp);

    return ret;
}

static void log_traffic(char *buff, unsigned int length, bool good)
{
    // for verbose logging of I2C traffic
    char logstr[1024];
    unsigned int x;

    if (length > 255) {
        ALOGV("traffic too long");
        return;
    }

    for (x = 0; x < length; x++) {
        sprintf(logstr + x*3, "%02X ", buff[x]);
    }
    sprintf(logstr + x*3, good ? "good" : "bad");

    ALOGI("%s", logstr);
}

static int amp_load_sequence(FILE *seq, int amp_fd)
{
    char buff[255];
    char buff2[255];
    int ret = 0;
    unsigned int do_write, length;
    size_t len_read, len_written;

    while (true) {
        do_write = fgetc(seq);
        if ((int)do_write == EOF) {
            // this is the normal place to EOF
            break;
        }

        length = fgetc(seq);
        if ((int)length == EOF) {
            ret = -4;
            break;
        }
        length &= 0xFF;

        len_read = fread(buff, 1, length, seq);
        if (len_read < length) {
            ret = -4;
            break;
        }

        if (do_write) {
            len_written = write(amp_fd, buff, length);
            if (len_written < length) {
                ret = -5;
                break;
            }
        } else {
            len_read = read(amp_fd, buff2, length);
            if (len_read < length) {
                ret = -5;
                break;
            }
            if (memcmp(buff, buff2, length) != 0) {
                // don't give up
                ret = -6;
                log_traffic(buff2, length, false);
            } else {
                log_traffic(buff2, length, true);
            }
        }
    }

    return ret;
}
