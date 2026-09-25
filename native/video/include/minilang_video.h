/*
 * Copyright 2026 Nils Kopal
 * Licensed under the Apache License, Version 2.0.
 *
 * Stable C ABI used by std.video. Implementations own all media-framework
 * objects and never invoke MiniLang callbacks from backend threads.
 */
#ifndef MINILANG_VIDEO_H
#define MINILANG_VIDEO_H

#include <stdint.h>

#ifdef __cplusplus
#define MLV_EXTERN extern "C"
#else
#define MLV_EXTERN extern
#endif

#ifdef _WIN32
#define MLV_EXPORT MLV_EXTERN __declspec(dllexport)
#else
#define MLV_EXPORT MLV_EXTERN __attribute__((visibility("default")))
#endif

enum {
    MLV_STATE_EMPTY = 0,
    MLV_STATE_LOADING = 1,
    MLV_STATE_READY = 2,
    MLV_STATE_PLAYING = 3,
    MLV_STATE_PAUSED = 4,
    MLV_STATE_STOPPED = 5,
    MLV_STATE_BUFFERING = 6,
    MLV_STATE_ENDED = 7,
    MLV_STATE_FAILED = 8,
    MLV_STATE_CLOSED = 9
};

enum {
    MLV_EVENT_NONE = 0,
    MLV_EVENT_READY = 1,
    MLV_EVENT_PLAYING = 2,
    MLV_EVENT_PAUSED = 3,
    MLV_EVENT_STOPPED = 4,
    MLV_EVENT_BUFFERING = 5,
    MLV_EVENT_ENDED = 6,
    MLV_EVENT_FORMAT_CHANGED = 7,
    MLV_EVENT_ERROR = 8
};

MLV_EXPORT uint32_t mlv_abi_version(void);
MLV_EXPORT int mlv_backend(unsigned char *message, int capacity);
MLV_EXPORT void *mlv_open(const char *source, uintptr_t window_handle, int allow_network);
MLV_EXPORT int mlv_attach(void *handle, uintptr_t window_handle);
MLV_EXPORT int mlv_play(void *handle);
MLV_EXPORT int mlv_pause(void *handle);
MLV_EXPORT int mlv_stop(void *handle);
MLV_EXPORT int mlv_seek(void *handle, int64_t milliseconds);
MLV_EXPORT int mlv_set_volume(void *handle, double volume);
MLV_EXPORT int mlv_set_muted(void *handle, int muted);
MLV_EXPORT int mlv_set_rate(void *handle, double rate);
MLV_EXPORT int mlv_set_loop(void *handle, int enabled);
MLV_EXPORT int mlv_state(void *handle);
MLV_EXPORT int64_t mlv_position_ms(void *handle);
MLV_EXPORT int64_t mlv_duration_ms(void *handle);
MLV_EXPORT int mlv_has_audio(void *handle);
MLV_EXPORT int mlv_has_video(void *handle);
MLV_EXPORT int mlv_video_width(void *handle);
MLV_EXPORT int mlv_video_height(void *handle);
MLV_EXPORT int mlv_poll_event(void *handle, unsigned char *message, int capacity);
MLV_EXPORT int mlv_event_code(void *handle);
MLV_EXPORT int mlv_error(void *handle, unsigned char *message, int capacity);
MLV_EXPORT void mlv_close(void *handle);

#endif
