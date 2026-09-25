/*
 * Copyright 2026 Nils Kopal
 * Licensed under the Apache License, Version 2.0.
 *
 * This bridge intentionally uses GStreamer's stable C ABI through dlopen. That
 * keeps the MiniLang SDK build independent of development headers while still
 * reporting a missing runtime as a catchable std.video error.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/minilang_video.h"

typedef struct _GstElement GstElement;
typedef struct _GstBus GstBus;
typedef struct _GstSample GstSample;
typedef struct _GstCaps GstCaps;
typedef struct _GstStructure GstStructure;
typedef struct {
    uint32_t domain;
    int code;
    char *message;
} GError;

// GstMessage exposes its type after the stable GstMiniObject prefix. Keeping
// this public ABI layout locally avoids a build-time dependency on headers.
typedef struct {
    uintptr_t type;
    int refcount;
    int lockstate;
    unsigned flags;
    void *copy;
    void *dispose;
    void *free_object;
    unsigned n_qdata;
    void *qdata;
} GstMiniObjectLayout;

typedef struct _GstMessage {
    GstMiniObjectLayout mini_object;
    int type;
} GstMessage;

enum {
    GST_STATE_NULL = 1,
    GST_STATE_READY = 2,
    GST_STATE_PAUSED = 3,
    GST_STATE_PLAYING = 4,
    GST_STATE_CHANGE_FAILURE = 0,
    GST_FORMAT_TIME = 3,
    GST_SEEK_FLAG_FLUSH = 1,
    GST_SEEK_FLAG_ACCURATE = 2,
    GST_SEEK_TYPE_NONE = 0,
    GST_SEEK_TYPE_SET = 1
};

#define GST_CLOCK_TIME_NONE UINT64_MAX
#define GST_MESSAGE_EOS ((uint64_t)1 << 0)
#define GST_MESSAGE_ERROR ((uint64_t)1 << 1)
#define GST_MESSAGE_BUFFERING ((uint64_t)1 << 5)

typedef int (*fn_gst_init_check)(int *, char ***, GError **);
typedef GstElement *(*fn_gst_element_factory_make)(const char *, const char *);
typedef int (*fn_gst_element_set_state)(GstElement *, int);
typedef int (*fn_gst_element_get_state)(GstElement *, int *, int *, uint64_t);
typedef GstBus *(*fn_gst_element_get_bus)(GstElement *);
typedef GstMessage *(*fn_gst_bus_timed_pop_filtered)(GstBus *, uint64_t, uint64_t);
typedef void (*fn_gst_message_parse_error)(GstMessage *, GError **, char **);
typedef void (*fn_gst_message_parse_buffering)(GstMessage *, int *);
typedef int (*fn_gst_element_query_position)(GstElement *, int, int64_t *);
typedef int (*fn_gst_element_query_duration)(GstElement *, int, int64_t *);
typedef int (*fn_gst_element_seek_simple)(GstElement *, int, int, int64_t);
typedef int (*fn_gst_element_seek)(GstElement *, double, int, int, int, int64_t, int, int64_t);
typedef char *(*fn_gst_filename_to_uri)(const char *, GError **);
typedef void (*fn_gst_mini_object_unref)(void *);
typedef void *(*fn_gst_object_ref_sink)(void *);
typedef GstCaps *(*fn_gst_sample_get_caps)(GstSample *);
typedef const GstStructure *(*fn_gst_caps_get_structure)(const GstCaps *, unsigned);
typedef int (*fn_gst_structure_get_int)(const GstStructure *, const char *, int *);
typedef void (*fn_gst_video_overlay_set_window_handle)(void *, uintptr_t);
typedef void (*fn_g_object_set)(void *, const char *, ...);
typedef void (*fn_g_object_get)(void *, const char *, ...);
typedef void (*fn_g_object_unref)(void *);
typedef void (*fn_g_signal_emit_by_name)(void *, const char *, ...);
typedef void (*fn_g_free)(void *);
typedef void (*fn_g_error_free)(GError *);

typedef struct {
    void *gstreamer;
    void *gstvideo;
    void *gobject;
    void *glib;
    char error[512];
    int ready;

    fn_gst_init_check init_check;
    fn_gst_element_factory_make element_factory_make;
    fn_gst_element_set_state element_set_state;
    fn_gst_element_get_state element_get_state;
    fn_gst_element_get_bus element_get_bus;
    fn_gst_bus_timed_pop_filtered bus_pop;
    fn_gst_message_parse_error message_parse_error;
    fn_gst_message_parse_buffering message_parse_buffering;
    fn_gst_element_query_position query_position;
    fn_gst_element_query_duration query_duration;
    fn_gst_element_seek_simple seek_simple;
    fn_gst_element_seek seek;
    fn_gst_filename_to_uri filename_to_uri;
    fn_gst_mini_object_unref mini_unref;
    fn_gst_object_ref_sink object_ref_sink;
    fn_gst_sample_get_caps sample_get_caps;
    fn_gst_caps_get_structure caps_get_structure;
    fn_gst_structure_get_int structure_get_int;
    fn_gst_video_overlay_set_window_handle overlay_set_window;
    fn_g_object_set object_set;
    fn_g_object_get object_get;
    fn_g_object_unref object_unref;
    fn_g_signal_emit_by_name signal_emit;
    fn_g_free free_mem;
    fn_g_error_free error_free;
} Backend;

static Backend g_backend;
static pthread_once_t g_backend_once = PTHREAD_ONCE_INIT;
static _Thread_local char g_open_error[512];

#define LOAD_REQUIRED(handle, field, symbol)                                      \
    do {                                                                          \
        *(void **)(&g_backend.field) = dlsym((handle), (symbol));                 \
        if (!g_backend.field) {                                                    \
            snprintf(g_backend.error, sizeof(g_backend.error),                    \
                     "GStreamer symbol %s is unavailable", (symbol));             \
            return;                                                               \
        }                                                                         \
    } while (0)

static void backend_init(void) {
    memset(&g_backend, 0, sizeof(g_backend));
    g_backend.gstreamer = dlopen("libgstreamer-1.0.so.0", RTLD_NOW | RTLD_LOCAL);
    g_backend.gstvideo = dlopen("libgstvideo-1.0.so.0", RTLD_NOW | RTLD_LOCAL);
    g_backend.gobject = dlopen("libgobject-2.0.so.0", RTLD_NOW | RTLD_LOCAL);
    g_backend.glib = dlopen("libglib-2.0.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!g_backend.gstreamer || !g_backend.gstvideo ||
        !g_backend.gobject || !g_backend.glib) {
        snprintf(g_backend.error, sizeof(g_backend.error),
                 "GStreamer 1.x runtime libraries are not installed");
        return;
    }

    LOAD_REQUIRED(g_backend.gstreamer, init_check, "gst_init_check");
    LOAD_REQUIRED(g_backend.gstreamer, element_factory_make, "gst_element_factory_make");
    LOAD_REQUIRED(g_backend.gstreamer, element_set_state, "gst_element_set_state");
    LOAD_REQUIRED(g_backend.gstreamer, element_get_state, "gst_element_get_state");
    LOAD_REQUIRED(g_backend.gstreamer, element_get_bus, "gst_element_get_bus");
    LOAD_REQUIRED(g_backend.gstreamer, bus_pop, "gst_bus_timed_pop_filtered");
    LOAD_REQUIRED(g_backend.gstreamer, message_parse_error, "gst_message_parse_error");
    LOAD_REQUIRED(g_backend.gstreamer, message_parse_buffering, "gst_message_parse_buffering");
    LOAD_REQUIRED(g_backend.gstreamer, query_position, "gst_element_query_position");
    LOAD_REQUIRED(g_backend.gstreamer, query_duration, "gst_element_query_duration");
    LOAD_REQUIRED(g_backend.gstreamer, seek_simple, "gst_element_seek_simple");
    LOAD_REQUIRED(g_backend.gstreamer, seek, "gst_element_seek");
    LOAD_REQUIRED(g_backend.gstreamer, filename_to_uri, "gst_filename_to_uri");
    LOAD_REQUIRED(g_backend.gstreamer, mini_unref, "gst_mini_object_unref");
    LOAD_REQUIRED(g_backend.gstreamer, object_ref_sink, "gst_object_ref_sink");
    LOAD_REQUIRED(g_backend.gstreamer, sample_get_caps, "gst_sample_get_caps");
    LOAD_REQUIRED(g_backend.gstreamer, caps_get_structure, "gst_caps_get_structure");
    LOAD_REQUIRED(g_backend.gstreamer, structure_get_int, "gst_structure_get_int");
    LOAD_REQUIRED(g_backend.gstvideo, overlay_set_window, "gst_video_overlay_set_window_handle");
    LOAD_REQUIRED(g_backend.gobject, object_set, "g_object_set");
    LOAD_REQUIRED(g_backend.gobject, object_get, "g_object_get");
    LOAD_REQUIRED(g_backend.gobject, object_unref, "g_object_unref");
    LOAD_REQUIRED(g_backend.gobject, signal_emit, "g_signal_emit_by_name");
    LOAD_REQUIRED(g_backend.glib, free_mem, "g_free");
    LOAD_REQUIRED(g_backend.glib, error_free, "g_error_free");

    GError *error = NULL;
    if (!g_backend.init_check(NULL, NULL, &error)) {
        snprintf(g_backend.error, sizeof(g_backend.error), "%s",
                 error && error->message ? error->message : "GStreamer initialization failed");
        if (error) g_backend.error_free(error);
        return;
    }
    g_backend.ready = 1;
}

enum { QUEUE_CAPACITY = 64, MESSAGE_CAPACITY = 512 };

typedef struct {
    int kind;
    int code;
    char message[MESSAGE_CAPACITY];
} QueuedEvent;

typedef struct {
    pthread_mutex_t lock;
    GstElement *playbin;
    GstBus *bus;
    QueuedEvent queue[QUEUE_CAPACITY];
    int head;
    int size;
    int last_event_code;
    char error[MESSAGE_CAPACITY];
    int state;
    int loop;
    int muted;
    double volume;
    double rate;
    uintptr_t window;
    int ready_reported;
    int width;
    int height;
} Player;

static Player *as_player(void *handle) {
    return (Player *)handle;
}

static void set_open_error(const char *message) {
    snprintf(g_open_error, sizeof(g_open_error), "%s",
             message ? message : "native media error");
}

static int copy_text(const char *text, unsigned char *message, int capacity) {
    if (!message || capacity <= 0) return 0;
    const char *source = text ? text : "";
    const size_t length = strnlen(source, MESSAGE_CAPACITY);
    const size_t available = (size_t)(capacity - 1);
    const size_t copied = length < available ? length : available;
    memcpy(message, source, copied);
    message[copied] = 0;
    return (int)copied;
}

static void set_error(Player *player, const char *message) {
    if (!player) {
        set_open_error(message);
        return;
    }
    pthread_mutex_lock(&player->lock);
    snprintf(player->error, sizeof(player->error), "%s",
             message ? message : "native media error");
    pthread_mutex_unlock(&player->lock);
}

static void push_event(Player *player, int kind, int code, const char *message) {
    pthread_mutex_lock(&player->lock);
    if (player->size == QUEUE_CAPACITY) {
        player->head = (player->head + 1) % QUEUE_CAPACITY;
        --player->size;
    }
    const int slot = (player->head + player->size) % QUEUE_CAPACITY;
    player->queue[slot].kind = kind;
    player->queue[slot].code = code;
    snprintf(player->queue[slot].message, MESSAGE_CAPACITY, "%s",
             message ? message : "");
    ++player->size;
    pthread_mutex_unlock(&player->lock);
}

static int pop_event(Player *player, unsigned char *message, int capacity) {
    int kind = MLV_EVENT_NONE;
    pthread_mutex_lock(&player->lock);
    if (player->size > 0) {
        QueuedEvent *event = &player->queue[player->head];
        kind = event->kind;
        player->last_event_code = event->code;
        if (message && capacity > 0) {
            snprintf((char *)message, (size_t)capacity, "%s", event->message);
        }
        player->head = (player->head + 1) % QUEUE_CAPACITY;
        --player->size;
    } else if (message && capacity > 0) {
        message[0] = 0;
    }
    pthread_mutex_unlock(&player->lock);
    return kind;
}

static int is_network_source(const char *source) {
    const char *scheme = source ? strstr(source, "://") : NULL;
    if (!scheme) return 0;
    const size_t length = (size_t)(scheme - source);
    return !(length == 4 && strncasecmp(source, "file", 4) == 0);
}

static char *make_uri(const char *source) {
    if (!source || !*source) {
        set_open_error("source must be non-empty");
        return NULL;
    }
    if (strstr(source, "://") || strncasecmp(source, "file:", 5) == 0) {
        return strdup(source);
    }

    char *absolute = realpath(source, NULL);
    if (!absolute) {
        set_open_error("media file does not exist");
        return NULL;
    }
    GError *error = NULL;
    char *uri = g_backend.filename_to_uri(absolute, &error);
    free(absolute);
    if (!uri) {
        set_open_error(error && error->message
            ? error->message : "cannot convert media path to URI");
        if (error) g_backend.error_free(error);
        return NULL;
    }
    char *copy = strdup(uri);
    g_backend.free_mem(uri);
    if (!copy) set_open_error("cannot allocate media source URI");
    return copy;
}

static void drain_backend_messages(Player *player) {
    GstMessage *message;
    const uint64_t wanted = GST_MESSAGE_ERROR | GST_MESSAGE_EOS | GST_MESSAGE_BUFFERING;
    while ((message = g_backend.bus_pop(player->bus, 0, wanted)) != NULL) {
        if (message->type == (int)GST_MESSAGE_ERROR) {
            GError *error = NULL;
            char *debug = NULL;
            g_backend.message_parse_error(message, &error, &debug);
            const char *text = error && error->message ? error->message : "GStreamer playback error";
            const int code = error ? error->code : 0;
            set_error(player, text);
            player->state = MLV_STATE_FAILED;
            push_event(player, MLV_EVENT_ERROR, code, text);
            if (debug) g_backend.free_mem(debug);
            if (error) g_backend.error_free(error);
        } else if (message->type == (int)GST_MESSAGE_EOS) {
            player->state = MLV_STATE_ENDED;
            push_event(player, MLV_EVENT_ENDED, 0, "");
            if (player->loop) {
                g_backend.seek_simple(player->playbin, GST_FORMAT_TIME,
                                      GST_SEEK_FLAG_FLUSH, 0);
                g_backend.element_set_state(player->playbin, GST_STATE_PLAYING);
                player->state = MLV_STATE_PLAYING;
            }
        } else if (message->type == (int)GST_MESSAGE_BUFFERING) {
            int percent = 0;
            g_backend.message_parse_buffering(message, &percent);
            if (percent < 100) {
                player->state = MLV_STATE_BUFFERING;
                push_event(player, MLV_EVENT_BUFFERING, percent, "");
            } else if (player->state == MLV_STATE_BUFFERING) {
                player->state = MLV_STATE_READY;
                push_event(player, MLV_EVENT_READY, 100, "");
            }
        }
        g_backend.mini_unref(message);
    }

    if (!player->ready_reported) {
        int current = GST_STATE_NULL;
        int pending = GST_STATE_NULL;
        const int result = g_backend.element_get_state(
            player->playbin, &current, &pending, 0);
        (void)pending;
        if (result != GST_STATE_CHANGE_FAILURE && current >= GST_STATE_PAUSED) {
            player->ready_reported = 1;
            if (player->state == MLV_STATE_LOADING) player->state = MLV_STATE_READY;
            push_event(player, MLV_EVENT_READY, 0, "");
        }
    }
}

static int set_rate_now(Player *player, double rate) {
    int64_t position = 0;
    if (!g_backend.query_position(player->playbin, GST_FORMAT_TIME, &position)) {
        position = 0;
    }
    return g_backend.seek(player->playbin, rate, GST_FORMAT_TIME,
                          GST_SEEK_FLAG_FLUSH | GST_SEEK_FLAG_ACCURATE,
                          GST_SEEK_TYPE_SET, position,
                          GST_SEEK_TYPE_NONE, 0);
}

static void query_dimensions(Player *player, int *width, int *height) {
    *width = player->width;
    *height = player->height;
    if (*width > 0 && *height > 0) return;
    GstSample *sample = NULL;
    g_backend.signal_emit(player->playbin, "convert-sample", NULL, &sample);
    if (!sample) return;
    GstCaps *caps = g_backend.sample_get_caps(sample);
    if (caps) {
        const GstStructure *structure = g_backend.caps_get_structure(caps, 0);
        if (structure) {
            g_backend.structure_get_int(structure, "width", width);
            g_backend.structure_get_int(structure, "height", height);
            if (*width > 0 && *height > 0) {
                player->width = *width;
                player->height = *height;
            }
        }
    }
    g_backend.mini_unref(sample);
}

MLV_EXPORT uint32_t mlv_abi_version(void) {
    return 1;
}

MLV_EXPORT int mlv_backend(unsigned char *message, int capacity) {
    return copy_text("gstreamer", message, capacity);
}

MLV_EXPORT void *mlv_open(const char *source, uintptr_t window_handle, int allow_network) {
    g_open_error[0] = '\0';
    pthread_once(&g_backend_once, backend_init);
    if (!g_backend.ready) {
        set_open_error(g_backend.error);
        return NULL;
    }
    if (is_network_source(source) && !allow_network) {
        set_open_error("network media is disabled; set allowNetwork explicitly");
        return NULL;
    }

    char *uri = make_uri(source);
    if (!uri) return NULL;

    Player *player = (Player *)calloc(1, sizeof(Player));
    if (!player) {
        free(uri);
        set_open_error("cannot allocate video player");
        return NULL;
    }
    pthread_mutex_init(&player->lock, NULL);
    player->state = MLV_STATE_EMPTY;
    player->volume = 1.0;
    player->rate = 1.0;
    player->window = window_handle;

    player->playbin = g_backend.element_factory_make("playbin", NULL);
    if (!player->playbin) {
        set_open_error("GStreamer playbin element is unavailable");
        pthread_mutex_destroy(&player->lock);
        free(player);
        free(uri);
        return NULL;
    }
    g_backend.object_ref_sink(player->playbin);
    player->bus = g_backend.element_get_bus(player->playbin);
    if (!player->bus) {
        set_open_error("GStreamer playbin did not provide an event bus");
        g_backend.object_unref(player->playbin);
        pthread_mutex_destroy(&player->lock);
        free(player);
        free(uri);
        return NULL;
    }

    g_backend.object_set(player->playbin, "uri", uri, NULL);
    free(uri);

    GstElement *sink = g_backend.element_factory_make(
        window_handle ? "autovideosink" : "fakesink", NULL);
    if (sink) {
        g_backend.object_ref_sink(sink);
        g_backend.object_set(sink, "sync", 1, NULL);
        g_backend.object_set(player->playbin, "video-sink", sink, NULL);
        g_backend.object_unref(sink);
    }
    if (window_handle) {
        g_backend.overlay_set_window(player->playbin, window_handle);
    }

    const int change = g_backend.element_set_state(player->playbin, GST_STATE_PAUSED);
    if (change == GST_STATE_CHANGE_FAILURE) {
        set_open_error("GStreamer could not prepare the media source");
        g_backend.object_unref(player->bus);
        g_backend.object_unref(player->playbin);
        pthread_mutex_destroy(&player->lock);
        free(player);
        return NULL;
    }
    player->state = MLV_STATE_LOADING;
    return player;
}

MLV_EXPORT int mlv_attach(void *handle, uintptr_t window_handle) {
    Player *player = as_player(handle);
    if (!player || !window_handle) return 0;
    if (player->state == MLV_STATE_PLAYING ||
        player->state == MLV_STATE_BUFFERING) {
        set_error(player, "attach must be called before playback");
        return 0;
    }

    g_backend.element_set_state(player->playbin, GST_STATE_NULL);
    GstElement *sink = g_backend.element_factory_make("autovideosink", NULL);
    if (!sink) {
        set_error(player, "GStreamer autovideosink is unavailable");
        return 0;
    }
    g_backend.object_ref_sink(sink);
    g_backend.object_set(player->playbin, "video-sink", sink, NULL);
    g_backend.object_unref(sink);
    player->window = window_handle;
    g_backend.overlay_set_window(player->playbin, window_handle);
    if (g_backend.element_set_state(player->playbin, GST_STATE_PAUSED) ==
        GST_STATE_CHANGE_FAILURE) {
        set_error(player, "GStreamer could not attach the video target");
        return 0;
    }
    player->state = MLV_STATE_LOADING;
    player->ready_reported = 0;
    return 1;
}

MLV_EXPORT int mlv_play(void *handle) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (g_backend.element_set_state(player->playbin, GST_STATE_PLAYING) ==
        GST_STATE_CHANGE_FAILURE) {
        set_error(player, "GStreamer could not start playback");
        return 0;
    }
    if (player->rate != 1.0 && !set_rate_now(player, player->rate)) {
        set_error(player, "GStreamer could not apply playback rate");
        return 0;
    }
    player->state = MLV_STATE_PLAYING;
    push_event(player, MLV_EVENT_PLAYING, 0, "");
    return 1;
}

MLV_EXPORT int mlv_pause(void *handle) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (g_backend.element_set_state(player->playbin, GST_STATE_PAUSED) ==
        GST_STATE_CHANGE_FAILURE) {
        set_error(player, "GStreamer could not pause playback");
        return 0;
    }
    player->state = MLV_STATE_PAUSED;
    push_event(player, MLV_EVENT_PAUSED, 0, "");
    return 1;
}

MLV_EXPORT int mlv_stop(void *handle) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (g_backend.element_set_state(player->playbin, GST_STATE_PAUSED) ==
        GST_STATE_CHANGE_FAILURE ||
        !g_backend.seek_simple(player->playbin, GST_FORMAT_TIME,
                               GST_SEEK_FLAG_FLUSH, 0)) {
        set_error(player, "GStreamer could not stop playback");
        return 0;
    }
    player->state = MLV_STATE_STOPPED;
    push_event(player, MLV_EVENT_STOPPED, 0, "");
    return 1;
}

MLV_EXPORT int mlv_seek(void *handle, int64_t milliseconds) {
    Player *player = as_player(handle);
    if (!player || milliseconds < 0 ||
        milliseconds > INT64_C(9223372036854)) return 0;
    if (!g_backend.seek_simple(player->playbin, GST_FORMAT_TIME,
                               GST_SEEK_FLAG_FLUSH | GST_SEEK_FLAG_ACCURATE,
                               milliseconds * INT64_C(1000000))) {
        set_error(player, "GStreamer could not seek");
        return 0;
    }
    return 1;
}

MLV_EXPORT int mlv_set_volume(void *handle, double volume) {
    Player *player = as_player(handle);
    if (!player || !isfinite(volume) || volume < 0.0 || volume > 1.0) return 0;
    g_backend.object_set(player->playbin, "volume", volume, NULL);
    player->volume = volume;
    return 1;
}

MLV_EXPORT int mlv_set_muted(void *handle, int muted) {
    Player *player = as_player(handle);
    if (!player) return 0;
    g_backend.object_set(player->playbin, "mute", muted ? 1 : 0, NULL);
    player->muted = muted != 0;
    return 1;
}

MLV_EXPORT int mlv_set_rate(void *handle, double rate) {
    Player *player = as_player(handle);
    if (!player || !isfinite(rate) || rate < 0.25 || rate > 4.0) return 0;
    player->rate = rate;
    if ((player->state == MLV_STATE_PLAYING ||
         player->state == MLV_STATE_PAUSED) &&
        !set_rate_now(player, rate)) {
        set_error(player, "GStreamer could not apply playback rate");
        return 0;
    }
    return 1;
}

MLV_EXPORT int mlv_set_loop(void *handle, int enabled) {
    Player *player = as_player(handle);
    if (!player) return 0;
    player->loop = enabled != 0;
    return 1;
}

MLV_EXPORT int mlv_state(void *handle) {
    Player *player = as_player(handle);
    if (!player) return MLV_STATE_CLOSED;
    drain_backend_messages(player);
    return player->state;
}

MLV_EXPORT int64_t mlv_position_ms(void *handle) {
    Player *player = as_player(handle);
    int64_t value = 0;
    if (!player || !g_backend.query_position(
            player->playbin, GST_FORMAT_TIME, &value)) return 0;
    return value / INT64_C(1000000);
}

MLV_EXPORT int64_t mlv_duration_ms(void *handle) {
    Player *player = as_player(handle);
    int64_t value = 0;
    if (!player || !g_backend.query_duration(
            player->playbin, GST_FORMAT_TIME, &value)) return -1;
    return value / INT64_C(1000000);
}

MLV_EXPORT int mlv_has_audio(void *handle) {
    Player *player = as_player(handle);
    int count = 0;
    if (player) g_backend.object_get(player->playbin, "n-audio", &count, NULL);
    return count > 0 ? 1 : 0;
}

MLV_EXPORT int mlv_has_video(void *handle) {
    Player *player = as_player(handle);
    int count = 0;
    if (player) g_backend.object_get(player->playbin, "n-video", &count, NULL);
    return count > 0 ? 1 : 0;
}

MLV_EXPORT int mlv_video_width(void *handle) {
    Player *player = as_player(handle);
    int width = 0;
    int height = 0;
    if (player) query_dimensions(player, &width, &height);
    return width;
}

MLV_EXPORT int mlv_video_height(void *handle) {
    Player *player = as_player(handle);
    int width = 0;
    int height = 0;
    if (player) query_dimensions(player, &width, &height);
    return height;
}

MLV_EXPORT int mlv_poll_event(void *handle, unsigned char *message, int capacity) {
    Player *player = as_player(handle);
    if (!player) {
        if (message && capacity > 0) message[0] = 0;
        return MLV_EVENT_NONE;
    }
    drain_backend_messages(player);
    return pop_event(player, message, capacity);
}

MLV_EXPORT int mlv_event_code(void *handle) {
    Player *player = as_player(handle);
    return player ? player->last_event_code : 0;
}

MLV_EXPORT int mlv_error(void *handle, unsigned char *message, int capacity) {
    Player *player = as_player(handle);
    if (!player) return copy_text(g_open_error, message, capacity);
    pthread_mutex_lock(&player->lock);
    const int copied = copy_text(player->error, message, capacity);
    pthread_mutex_unlock(&player->lock);
    return copied;
}

MLV_EXPORT void mlv_close(void *handle) {
    Player *player = as_player(handle);
    if (!player) return;
    player->state = MLV_STATE_CLOSED;
    g_backend.element_set_state(player->playbin, GST_STATE_NULL);
    g_backend.object_unref(player->bus);
    g_backend.object_unref(player->playbin);
    pthread_mutex_destroy(&player->lock);
    free(player);
}
