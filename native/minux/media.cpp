/* Copyright 2026 Nils Kopal. Apache-2.0.
 * Native MinUX media backend: PCM WAV and uncompressed BGR AVI.
 * Codec, device and attachment failures are reported through the stable ABI.
 */
#include "../video/include/minilang_video.h"
#include <common/audio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
using namespace MinUX::common;
extern "C" int mg_present_bmp(void *, const char *);
extern "C" int mg_video_target(void *);
extern "C" int mkstemps(char *, int);

struct Player {
  pthread_mutex_t lock;
  pthread_t thread;
  int thread_started, closing, state, error, event_code;
  int events[64], head, count;
  char message[256];
  unsigned char *file, *samples;
  size_t file_size, sample_count;
  uint32_t sample_rate, width, height, stride, frame_microseconds;
  uint32_t *frames, frame_count, frame_capacity;
  int bits, loop, muted, audio, device, drained;
  double volume, rate, cursor, position, duration;
  uint64_t start_time, submitted, completion_base;
  void *window;
  char bitmap[2][128];
  int bitmap_fd[2], video_headers;
  uint32_t last_frame, bitmap_slot;
};
static pthread_mutex_t device_lock = PTHREAD_MUTEX_INITIALIZER;
static Player *device_owner;
static uint64_t now_ms() {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    return 0;
  return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static uint16_t u16(const unsigned char *p) {
  return (uint16_t)(p[0] | p[1] << 8);
}
static uint32_t u32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}
static void put32(unsigned char *p, uint32_t n) {
  for (int i = 0; i < 4; i++)
    p[i] = n >> (i * 8);
}
static int four(const unsigned char *p, const char *s) {
  return !memcmp(p, s, 4);
}
static void copy_message(unsigned char *output, int capacity,
                         const char *text) {
  if (!output || capacity <= 0)
    return;
  size_t n = strlen(text);
  if (n >= (size_t)capacity)
    n = capacity - 1;
  memcpy(output, text, n);
  output[n] = 0;
}
static void event(Player *p, int kind) {
  if (p->count == 64) {
    p->head = (p->head + 1) % 64;
    p->count--;
  }
  p->events[(p->head + p->count++) % 64] = kind;
}
static int failure(Player *p, const char *message, int code) {
  p->error = code;
  p->state = MLV_STATE_FAILED;
  copy_message((unsigned char *)p->message, sizeof(p->message), message);
  event(p, MLV_EVENT_ERROR);
  return 0;
}
static int read_file(Player *p, const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  off_t size = lseek(fd, 0, SEEK_END);
  if (size < 12 || size > (256LL << 20) || lseek(fd, 0, SEEK_SET) < 0) {
    close(fd);
    return 0;
  }
  p->file = (unsigned char *)malloc((size_t)size);
  if (!p->file) {
    close(fd);
    return 0;
  }
  p->file_size = size;
  size_t done = 0;
  while (done < (size_t)size) {
    ssize_t n = read(fd, p->file + done, size - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0 || (size_t)n > size - done) {
      close(fd);
      return 0;
    }
    done += n;
  }
  return close(fd) == 0;
}
static int wav(Player *p) {
  const unsigned char *format = 0, *data = 0;
  size_t format_size = 0, data_size = 0;
  size_t end = (size_t)u32(p->file + 4) + 8;
  if (end > p->file_size || end < 12)
    return 0;
  for (size_t at = 12; at + 8 <= end;) {
    size_t n = u32(p->file + at + 4), begin = at + 8;
    if (n > end - begin)
      return 0;
    if (four(p->file + at, "fmt ")) {
      if (format)
        return 0;
      format = p->file + begin;
      format_size = n;
    }
    if (four(p->file + at, "data")) {
      if (data)
        return 0;
      data = p->file + begin;
      data_size = n;
    }
    size_t next = begin + n + (n & 1);
    if (next > end)
      return 0;
    at = next;
  }
  if (!format || format_size < 16 || !data || u16(format) != 1)
    return 0;
  uint32_t channels = u16(format + 2), rate = u32(format + 4),
           bits = u16(format + 14), align = u16(format + 12);
  if (!channels || channels > 8 || rate < 4000 || rate > 192000 ||
      (bits != 8 && bits != 16 && bits != 24 && bits != 32) ||
      align != channels * (bits / 8) || data_size % align ||
      u32(format + 8) != (uint64_t)rate * align)
    return 0;
  size_t input_count = data_size / align;
  if (!input_count)
    return 0;
  p->sample_rate = rate > 44100 ? 44100 : rate;
  p->sample_count = (uint64_t)input_count * p->sample_rate / rate;
  p->samples = (unsigned char *)malloc(p->sample_count);
  if (!p->samples)
    return 0;
  for (size_t i = 0; i < p->sample_count; i++) {
    const unsigned char *sample =
        data + ((uint64_t)i * rate / p->sample_rate) * align;
    int64_t sum = 0;
    for (uint32_t ch = 0; ch < channels; ch++, sample += bits / 8) {
      int32_t value;
      if (bits == 8)
        value = ((int32_t)sample[0] - 128) * 16777216;
      else if (bits == 16)
        value = (int32_t)(int16_t)u16(sample) * 65536;
      else if (bits == 24) {
        uint32_t raw = (uint32_t)sample[0] << 8 | (uint32_t)sample[1] << 16 |
                       (uint32_t)sample[2] << 24;
        value = (int32_t)raw;
      } else
        value = (int32_t)u32(sample);
      sum += value;
    }
    p->samples[i] = (unsigned char)((sum / channels) / 16777216 + 128);
  }
  p->audio = 1;
  p->duration = (double)input_count * 1000 / rate;
  return 1;
}
static int avi_chunks(Player *p, size_t begin, size_t end, int depth,
                      int in_movi) {
  if (depth > 8)
    return 0;
  for (size_t at = begin; at + 8 <= end;) {
    const unsigned char *id = p->file + at;
    size_t n = u32(id + 4), data = at + 8;
    if (n > end - data)
      return 0;
    if (four(id, "LIST")) {
      if (n < 4 || !avi_chunks(p, data + 4, data + n, depth + 1,
                               in_movi || four(p->file + data, "movi")))
        return 0;
    } else if (four(id, "avih")) {
      if (n < 56 || p->width || p->frame_count || u32(p->file + data + 24) != 1)
        return 0;
      p->frame_microseconds = u32(p->file + data);
      p->width = u32(p->file + data + 32);
      p->height = u32(p->file + data + 36);
    } else if (four(id, "strh")) {
      // This backend deliberately rejects compressed or multiplexed audio
      // instead of silently dropping a stream from the source.
      if (n < 48 || p->video_headers++ || !four(p->file + data, "vids"))
        return 0;
    } else if (four(id, "strf")) {
      if (n < 40 || p->bits || p->frame_count || u32(p->file + data) < 40 ||
          u16(p->file + data + 12) != 1 || u32(p->file + data + 16) != 0)
        return 0;
      p->bits = u16(p->file + data + 14);
      if (u32(p->file + data + 4) != p->width ||
          u32(p->file + data + 8) != p->height)
        return 0;
    } else if (in_movi && id[0] == '0' && id[1] == '0' && id[2] == 'd' &&
               (id[3] == 'b' || id[3] == 'c')) {
      if (p->frame_count >= 100000)
        return 0;
      if (p->frame_count == p->frame_capacity) {
        uint32_t cap = p->frame_capacity ? p->frame_capacity * 2 : 64;
        void *grown = realloc(p->frames, cap * sizeof(uint32_t));
        if (!grown)
          return 0;
        p->frames = (uint32_t *)grown;
        p->frame_capacity = cap;
      }
      if (!p->width || !p->height || p->width > 4096 || p->height > 2160 ||
          (p->bits != 24 && p->bits != 32))
        return 0;
      p->stride = (p->width * (p->bits / 8) + 3) & ~3U;
      if ((uint64_t)p->stride * p->height > n)
        return 0;
      p->frames[p->frame_count++] = data;
    }
    size_t next = data + n + (n & 1);
    if (next > end)
      return 0;
    at = next;
  }
  return 1;
}
static int avi(Player *p) {
  size_t end = (size_t)u32(p->file + 4) + 8;
  if (end > p->file_size || end < 12 || !avi_chunks(p, 12, end, 0, 0) ||
      !p->frame_count || !p->frame_microseconds)
    return 0;
  p->duration = (double)p->frame_count * p->frame_microseconds / 1000;
  return 1;
}
static int bitmap(Player *p, uint32_t frame_number) {
  if (frame_number >= p->frame_count)
    return 0;
  unsigned char header[54] = {0};
  uint32_t length = p->stride * p->height;
  header[0] = 'B';
  header[1] = 'M';
  put32(header + 2, 54 + length);
  put32(header + 10, 54);
  put32(header + 14, 40);
  put32(header + 18, p->width);
  put32(header + 22, p->height);
  header[26] = 1;
  header[28] = p->bits;
  put32(header + 34, length);
  uint32_t slot = p->bitmap_slot++ % 2;
  const char *path = p->bitmap[slot];
  int fd = p->bitmap_fd[slot];
  if (fd < 0 || lseek(fd, 0, SEEK_SET) < 0)
    return 0;
  const unsigned char *parts[2] = {header, p->file + p->frames[frame_number]};
  size_t lengths[2] = {54, length};
  int ok = 1;
  for (int i = 0; i < 2 && ok; i++) {
    size_t done = 0;
    while (done < lengths[i]) {
      ssize_t n = write(fd, parts[i] + done, lengths[i] - done);
      if (n <= 0) {
        ok = 0;
        break;
      }
      done += n;
    }
  }
  return ok && mg_present_bmp(p->window, path);
}
static void release_device(Player *p) {
  if (p->device >= 0) {
    ioctl(p->device, MINUX_IOCTL_AUDIO_STOP, 0);
    close(p->device);
    p->device = -1;
  }
  pthread_mutex_lock(&device_lock);
  if (device_owner == p)
    device_owner = 0;
  pthread_mutex_unlock(&device_lock);
}
static int acquire_device(Player *p) {
  pthread_mutex_lock(&device_lock);
  int available = !device_owner || device_owner == p;
  if (available)
    device_owner = p;
  pthread_mutex_unlock(&device_lock);
  if (!available)
    return failure(p, "MinUX audio device is already in use", EBUSY);
  p->device = open("/dev/audio0", O_WRONLY);
  MinuxAudioInfo info = {};
  MinuxAudioFormat format = {};
  format.sampleRate = p->sample_rate;
  if (p->device < 0 || ioctl(p->device, MINUX_IOCTL_AUDIO_GET_INFO, &info) ||
      !info.available ||
      ioctl(p->device, MINUX_IOCTL_AUDIO_SET_FORMAT, &format)) {
    release_device(p);
    return failure(p, "MinUX audio playback device is unavailable", ENODEV);
  }
  p->completion_base = info.bytesCompleted;
  p->submitted = 0;
  p->drained = 0;
  return 1;
}
static void *worker(void *context) {
  Player *p = (Player *)context;
  for (;;) {
    pthread_mutex_lock(&p->lock);
    if (p->closing) {
      pthread_mutex_unlock(&p->lock);
      break;
    }
    if (p->state == MLV_STATE_PLAYING) {
      if (p->audio) {
        unsigned char samples[512];
        size_t n = 0;
        double cursor = p->cursor;
        size_t chunk = p->sample_rate / 100;
        if (chunk > sizeof(samples))
          chunk = sizeof(samples);
        while (n < chunk && cursor < p->sample_count) {
          int value = (int)p->samples[(size_t)cursor] - 128;
          samples[n++] =
              p->muted ? 128 : (unsigned char)(128 + value * p->volume);
          cursor += p->rate;
        }
        if (n) {
          ssize_t written = write(p->device, samples, n);
          if (written <= 0 || (size_t)written > n) {
            failure(p, "MinUX audio device write failed", EIO);
            release_device(p);
          } else {
            p->cursor += written * p->rate;
            p->submitted += written;
            p->position = p->cursor * 1000 / p->sample_rate;
          }
        } else {
          MinuxAudioInfo info = {};
          if (ioctl(p->device, MINUX_IOCTL_AUDIO_GET_INFO, &info))
            failure(p, "MinUX audio completion query failed", EIO);
          else if (info.bytesCompleted - p->completion_base >= p->submitted)
            p->drained = 1;
        }
      } else {
        uint64_t current = now_ms();
        p->position += (current - p->start_time) * p->rate;
        p->start_time = current;
        uint32_t frame_number =
            (uint32_t)(p->position * 1000 / p->frame_microseconds);
        if (frame_number < p->frame_count && frame_number != p->last_frame) {
          if (p->window && !bitmap(p, frame_number))
            failure(p, "MinUX video attachment failed", EIO);
          p->last_frame = frame_number;
        }
      }
      if (p->state == MLV_STATE_PLAYING &&
          (p->audio ? p->drained : p->position >= p->duration)) {
        if (p->loop) {
          p->cursor = p->position = 0;
          p->start_time = now_ms();
          p->last_frame = ~0U;
          p->drained = 0;
        } else {
          p->position = p->duration;
          p->state = MLV_STATE_ENDED;
          event(p, MLV_EVENT_ENDED);
          release_device(p);
        }
      }
    }
    pthread_mutex_unlock(&p->lock);
    usleep(10000);
  }
  return 0;
}
MLV_EXPORT uint32_t mlv_abi_version() { return 1; }
MLV_EXPORT int mlv_backend(unsigned char *output, int capacity) {
  copy_message(output, capacity, "MinUX PCM WAV / uncompressed AVI");
  return 1;
}
MLV_EXPORT void *mlv_open(const char *source, uint64_t window_handle,
                          int allow_network) {
  (void)allow_network;
  Player *p = (Player *)calloc(1, sizeof(Player));
  if (!p)
    return 0;
  if (pthread_mutex_init(&p->lock, 0)) {
    free(p);
    return 0;
  }
  p->device = -1;
  p->state = MLV_STATE_LOADING;
  p->volume = p->rate = 1;
  p->window = (void *)window_handle;
  p->last_frame = ~0U;
  for (int i = 0; i < 2; i++)
    p->bitmap_fd[i] = -1;
  if (!source || strstr(source, "://") || !read_file(p, source) ||
      !four(p->file, "RIFF") ||
      !(four(p->file + 8, "WAVE")   ? wav(p)
        : four(p->file + 8, "AVI ") ? avi(p)
                                    : 0)) {
    failure(p,
            "MinUX supports local integer PCM WAV and uncompressed "
            "single-video-stream BGR AVI",
            ENOTSUP);
    return p;
  }
  if (p->frame_count) {
    for (int i = 0; i < 2; i++) {
      strcpy(p->bitmap[i], "/tmp/minilang-video-XXXXXX.bmp");
      p->bitmap_fd[i] = mkstemps(p->bitmap[i], 4);
      if (p->bitmap_fd[i] < 0) {
        failure(p, "MinUX video frame file could not be created", EIO);
        return p;
      }
    }
  }
  if (pthread_create(&p->thread, 0, worker, p)) {
    failure(p, "MinUX media worker could not start", EAGAIN);
    return p;
  }
  p->thread_started = 1;
  p->state = MLV_STATE_READY;
  event(p, MLV_EVENT_READY);
  return p;
}
MLV_EXPORT int mlv_attach(void *handle, uint64_t window_handle) {
  Player *p = (Player *)handle;
  if (!p || !mg_video_target((void *)window_handle))
    return 0;
  pthread_mutex_lock(&p->lock);
  p->window = (void *)window_handle;
  p->last_frame = ~0U;
  pthread_mutex_unlock(&p->lock);
  return 1;
}
MLV_EXPORT int mlv_play(void *handle) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  int ok = p->state != MLV_STATE_FAILED && !p->closing;
  if (ok && p->state != MLV_STATE_PLAYING) {
    if (p->state == MLV_STATE_ENDED)
      p->cursor = p->position = 0;
    if (p->audio)
      ok = acquire_device(p);
    if (ok) {
      p->start_time = now_ms();
      p->state = MLV_STATE_PLAYING;
      event(p, MLV_EVENT_PLAYING);
    }
  }
  pthread_mutex_unlock(&p->lock);
  return ok;
}
MLV_EXPORT int mlv_pause(void *handle) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  int ok = p->state != MLV_STATE_FAILED;
  if (ok) {
    release_device(p);
    p->state = MLV_STATE_PAUSED;
    event(p, MLV_EVENT_PAUSED);
  }
  pthread_mutex_unlock(&p->lock);
  return ok;
}
MLV_EXPORT int mlv_stop(void *handle) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  int ok = p->state != MLV_STATE_FAILED;
  if (ok) {
    release_device(p);
    p->cursor = p->position = 0;
    p->state = MLV_STATE_STOPPED;
    p->last_frame = ~0U;
    event(p, MLV_EVENT_STOPPED);
  }
  pthread_mutex_unlock(&p->lock);
  return ok;
}
MLV_EXPORT int mlv_seek(void *handle, int64_t milliseconds) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  int ok = p->state != MLV_STATE_FAILED && milliseconds >= 0 &&
           milliseconds <= p->duration;
  if (ok) {
    int playing = p->state == MLV_STATE_PLAYING;
    if (p->audio) {
      release_device(p);
      if (playing)
        ok = acquire_device(p);
    }
    p->position = milliseconds;
    p->cursor = (double)milliseconds * p->sample_rate / 1000;
    p->start_time = now_ms();
    p->last_frame = ~0U;
    p->drained = 0;
  }
  pthread_mutex_unlock(&p->lock);
  return ok;
}
MLV_EXPORT int mlv_set_volume(void *handle, double volume) {
  Player *p = (Player *)handle;
  if (!p || !(volume >= 0 && volume <= 1))
    return 0;
  pthread_mutex_lock(&p->lock);
  p->volume = volume;
  pthread_mutex_unlock(&p->lock);
  return 1;
}
MLV_EXPORT int mlv_set_muted(void *handle, int muted) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  p->muted = muted != 0;
  pthread_mutex_unlock(&p->lock);
  return 1;
}
MLV_EXPORT int mlv_set_rate(void *handle, double rate) {
  Player *p = (Player *)handle;
  if (!p || !(rate >= 0.25 && rate <= 4))
    return 0;
  pthread_mutex_lock(&p->lock);
  p->rate = rate;
  pthread_mutex_unlock(&p->lock);
  return 1;
}
MLV_EXPORT int mlv_set_loop(void *handle, int enabled) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  int ok = p->state != MLV_STATE_FAILED;
  if (ok)
    p->loop = enabled != 0;
  pthread_mutex_unlock(&p->lock);
  return ok;
}
MLV_EXPORT int mlv_state(void *handle) {
  Player *p = (Player *)handle;
  if (!p)
    return MLV_STATE_CLOSED;
  pthread_mutex_lock(&p->lock);
  int state = p->state;
  pthread_mutex_unlock(&p->lock);
  return state;
}
MLV_EXPORT int64_t mlv_position_ms(void *handle) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  int64_t n = p->position;
  if (n > p->duration)
    n = p->duration;
  pthread_mutex_unlock(&p->lock);
  return n;
}
MLV_EXPORT int64_t mlv_duration_ms(void *handle) {
  Player *p = (Player *)handle;
  return p ? (int64_t)p->duration : 0;
}
MLV_EXPORT int mlv_has_audio(void *handle) {
  Player *p = (Player *)handle;
  return p ? p->audio : 0;
}
MLV_EXPORT int mlv_has_video(void *handle) {
  Player *p = (Player *)handle;
  return p ? p->frame_count != 0 : 0;
}
MLV_EXPORT int mlv_video_width(void *handle) {
  Player *p = (Player *)handle;
  return p ? p->width : 0;
}
MLV_EXPORT int mlv_video_height(void *handle) {
  Player *p = (Player *)handle;
  return p ? p->height : 0;
}
MLV_EXPORT int mlv_poll_event(void *handle, unsigned char *message,
                              int capacity) {
  Player *p = (Player *)handle;
  if (!p)
    return 0;
  pthread_mutex_lock(&p->lock);
  int kind = 0;
  if (p->count) {
    kind = p->events[p->head];
    p->head = (p->head + 1) % 64;
    p->count--;
    p->event_code = kind == MLV_EVENT_ERROR ? p->error : 0;
  }
  copy_message(message, capacity, kind == MLV_EVENT_ERROR ? p->message : "");
  pthread_mutex_unlock(&p->lock);
  return kind;
}
MLV_EXPORT int mlv_event_code(void *handle) {
  Player *p = (Player *)handle;
  return p ? p->event_code : 0;
}
MLV_EXPORT int mlv_error(void *handle, unsigned char *message, int capacity) {
  Player *p = (Player *)handle;
  if (!p)
    return EINVAL;
  pthread_mutex_lock(&p->lock);
  copy_message(message, capacity, p->message);
  int code = p->error;
  pthread_mutex_unlock(&p->lock);
  return code;
}
MLV_EXPORT void mlv_close(void *handle) {
  Player *p = (Player *)handle;
  if (!p)
    return;
  pthread_mutex_lock(&p->lock);
  p->closing = 1;
  release_device(p);
  pthread_mutex_unlock(&p->lock);
  if (p->thread_started)
    pthread_join(p->thread, 0);
  pthread_mutex_destroy(&p->lock);
  for (int i = 0; i < 2; i++)
    if (p->bitmap_fd[i] >= 0) {
      close(p->bitmap_fd[i]);
      unlink(p->bitmap[i]);
    }
  free(p->frames);
  free(p->samples);
  free(p->file);
  free(p);
}
