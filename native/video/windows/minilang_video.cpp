/*
 * Copyright 2026 Nils Kopal
 * Licensed under the Apache License, Version 2.0.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfmediaengine.h>
#include <shlwapi.h>
#include <oleauto.h>
#include <mmsystem.h>

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>

#include "../include/minilang_video.h"

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winmm.lib")

namespace {

constexpr int kQueueCapacity = 64;
constexpr int kMessageCapacity = 512;
constexpr int64_t kMaxMilliseconds = INT64_C(9223372036854);

struct QueuedEvent {
    int kind = MLV_EVENT_NONE;
    int code = 0;
    char message[kMessageCapacity]{};
};

struct Player;
void player_event(Player *player, DWORD event, DWORD_PTR param1, DWORD param2);

class MediaNotify final : public IMFMediaEngineNotify {
public:
    explicit MediaNotify(Player *owner) : refs_(1), owner_(owner) {}

    void detach() {
        // Wait for an EventNotify call which already observed the owner. Once
        // the exclusive lock is acquired, no callback can retain the pointer
        // while the Player is being torn down.
        AcquireSRWLockExclusive(&owner_lock_);
        owner_.store(nullptr, std::memory_order_release);
        ReleaseSRWLockExclusive(&owner_lock_);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(IMFMediaEngineNotify)) {
            *object = static_cast<IMFMediaEngineNotify *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return refs_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG value = refs_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (value == 0) delete this;
        return value;
    }

    HRESULT STDMETHODCALLTYPE EventNotify(DWORD event, DWORD_PTR param1, DWORD param2) override {
        AcquireSRWLockShared(&owner_lock_);
        Player *owner = owner_.load(std::memory_order_acquire);
        if (owner) player_event(owner, event, param1, param2);
        ReleaseSRWLockShared(&owner_lock_);
        return S_OK;
    }

private:
    std::atomic<ULONG> refs_;
    std::atomic<Player *> owner_;
    SRWLOCK owner_lock_ = SRWLOCK_INIT;
};

struct Player {
    CRITICAL_SECTION lock{};
    QueuedEvent queue[kQueueCapacity]{};
    int head = 0;
    int size = 0;
    int last_event_code = 0;
    char error[kMessageCapacity]{};

    std::atomic<int> state{MLV_STATE_EMPTY};
    IMFMediaEngine *engine = nullptr;
    MediaNotify *notify = nullptr;
    MCIDEVICEID midi_device = 0;
    std::wstring source;
    uintptr_t window = 0;
    HWND owned_window = nullptr;
    double volume = 1.0;
    double rate = 1.0;
    bool muted = false;
    bool loop = false;
    bool mf_started = false;
    bool co_initialized = false;
    bool midi = false;
    bool midi_started = false;
    bool midi_end_reported = false;
    DWORD midi_base_tempo = 500000;
    DWORD owner_thread = 0;

    Player() {
        InitializeCriticalSection(&lock);
        error[0] = '\0';
    }

    ~Player() {
        DeleteCriticalSection(&lock);
    }

    void set_error(const char *message) {
        EnterCriticalSection(&lock);
        strncpy_s(error, message ? message : "native media error", _TRUNCATE);
        LeaveCriticalSection(&lock);
    }

    void push(int kind, int code = 0, const char *message = "") {
        EnterCriticalSection(&lock);
        if (size == kQueueCapacity) {
            head = (head + 1) % kQueueCapacity;
            --size;
        }
        const int slot = (head + size) % kQueueCapacity;
        queue[slot].kind = kind;
        queue[slot].code = code;
        strncpy_s(queue[slot].message, message ? message : "", _TRUNCATE);
        ++size;
        LeaveCriticalSection(&lock);
    }

    int pop(unsigned char *message, int capacity) {
        EnterCriticalSection(&lock);
        if (size == 0) {
            LeaveCriticalSection(&lock);
            if (message && capacity > 0) message[0] = 0;
            return MLV_EVENT_NONE;
        }
        const QueuedEvent event = queue[head];
        head = (head + 1) % kQueueCapacity;
        --size;
        last_event_code = event.code;
        if (message && capacity > 0) {
            const size_t limit = static_cast<size_t>(capacity - 1);
            const size_t count = strnlen_s(event.message, kMessageCapacity);
            const size_t copied = count < limit ? count : limit;
            memcpy(message, event.message, copied);
            message[copied] = 0;
        }
        LeaveCriticalSection(&lock);
        return event.kind;
    }
};

thread_local char g_open_error[kMessageCapacity] = "";

void set_open_error(const char *message) {
    strncpy_s(g_open_error, message ? message : "native media error", _TRUNCATE);
}

int copy_text(const char *text, unsigned char *message, int capacity) {
    if (!message || capacity <= 0) return 0;
    const char *source = text ? text : "";
    const size_t available = static_cast<size_t>(capacity - 1);
    const size_t length = strnlen_s(source, kMessageCapacity);
    const size_t copied = length < available ? length : available;
    memcpy(message, source, copied);
    message[copied] = 0;
    return static_cast<int>(copied);
}

std::string hresult_message(HRESULT result) {
    char system[320]{};
    const DWORD count = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(result), 0, system,
        static_cast<DWORD>(sizeof(system)), nullptr);
    if (count == 0) {
        char fallback[64]{};
        sprintf_s(fallback, "HRESULT 0x%08X", static_cast<unsigned>(result));
        return fallback;
    }
    while (system[0] && (system[strlen(system) - 1] == '\r' ||
                         system[strlen(system) - 1] == '\n')) {
        system[strlen(system) - 1] = '\0';
    }
    return system;
}

bool fail(Player *player, const char *operation, HRESULT result) {
    const std::string message = std::string(operation) + ": " + hresult_message(result);
    if (player) player->set_error(message.c_str());
    else set_open_error(message.c_str());
    return false;
}

bool is_network_source(const std::string &source) {
    const size_t scheme = source.find("://");
    if (scheme == std::string::npos) return false;
    std::string prefix = source.substr(0, scheme);
    for (char &ch : prefix) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return prefix != "file";
}

bool is_midi_source(const std::string &source) {
    size_t end = source.find_first_of("?#");
    if (end == std::string::npos) end = source.size();
    std::string path = source.substr(0, end);
    for (char &ch : path) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return (path.size() >= 4 && path.compare(path.size() - 4, 4, ".mid") == 0) ||
           (path.size() >= 5 && path.compare(path.size() - 5, 5, ".midi") == 0);
}

bool utf8_to_wide(const char *input, std::wstring &output) {
    if (!input || !*input) return false;
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, nullptr, 0);
    if (count <= 1) return false;
    output.resize(static_cast<size_t>(count));
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                            output.data(), count) != count) return false;
    output.resize(static_cast<size_t>(count - 1));
    return true;
}

bool source_url(const char *input, bool allow_network, std::wstring &output) {
    const std::string source(input ? input : "");
    if (source.empty()) {
        set_open_error("source must be non-empty");
        return false;
    }
    if (is_network_source(source) && !allow_network) {
        set_open_error("network media is disabled; set allowNetwork explicitly");
        return false;
    }
    if (!utf8_to_wide(input, output)) {
        set_open_error("source is not valid UTF-8");
        return false;
    }
    if (source.find("://") != std::string::npos || source.rfind("file:", 0) == 0) {
        return true;
    }

    DWORD needed = GetFullPathNameW(output.c_str(), 0, nullptr, nullptr);
    if (needed == 0) {
        set_open_error("cannot resolve media path");
        return false;
    }
    std::wstring absolute(static_cast<size_t>(needed), L'\0');
    DWORD actual = GetFullPathNameW(output.c_str(), needed, absolute.data(), nullptr);
    if (actual == 0 || actual >= needed) {
        set_open_error("cannot resolve media path");
        return false;
    }
    absolute.resize(actual);
    if (GetFileAttributesW(absolute.c_str()) == INVALID_FILE_ATTRIBUTES) {
        set_open_error("media file does not exist");
        return false;
    }

    // UrlCreateFromPath may percent-encode every byte of a non-ASCII path.
    // Reserve the worst practical expansion instead of imposing MAX_PATH or
    // an arbitrary URL-length limit.
    if (absolute.size() > (UINT32_MAX - 32u) / 12u) {
        set_open_error("media path is too long");
        return false;
    }
    DWORD url_size = static_cast<DWORD>(absolute.size() * 12u + 32u);
    std::wstring url(static_cast<size_t>(url_size), L'\0');
    HRESULT result = UrlCreateFromPathW(absolute.c_str(), url.data(), &url_size, 0);
    if (FAILED(result)) {
        fail(nullptr, "UrlCreateFromPathW", result);
        return false;
    }
    url.resize(url_size);
    output = std::move(url);
    return true;
}

// MCI's sequencer consumes filesystem paths rather than Media Foundation
// URLs. Resolve both ordinary paths and file: URLs without imposing MAX_PATH.
bool local_source_path(const char *input, std::wstring &output) {
    const std::string source(input ? input : "");
    if (source.empty() || is_network_source(source)) {
        set_open_error("MIDI playback requires a local file");
        return false;
    }
    std::wstring supplied;
    if (!utf8_to_wide(input, supplied)) {
        set_open_error("source is not valid UTF-8");
        return false;
    }
    if (source.rfind("file:", 0) == 0) {
        DWORD count = static_cast<DWORD>(supplied.size() + 1);
        std::wstring decoded(static_cast<size_t>(count), L'\0');
        const HRESULT result = PathCreateFromUrlW(supplied.c_str(), decoded.data(), &count, 0);
        if (FAILED(result)) {
            fail(nullptr, "PathCreateFromUrlW", result);
            return false;
        }
        decoded.resize(count);
        supplied = std::move(decoded);
    }

    const DWORD needed = GetFullPathNameW(supplied.c_str(), 0, nullptr, nullptr);
    if (needed == 0) {
        set_open_error("cannot resolve MIDI path");
        return false;
    }
    std::wstring absolute(static_cast<size_t>(needed), L'\0');
    const DWORD actual = GetFullPathNameW(supplied.c_str(), needed, absolute.data(), nullptr);
    if (actual == 0 || actual >= needed) {
        set_open_error("cannot resolve MIDI path");
        return false;
    }
    absolute.resize(actual);
    const DWORD attributes = GetFileAttributesW(absolute.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        set_open_error("media file does not exist");
        return false;
    }
    output = std::move(absolute);
    return true;
}

std::string mci_message(MCIERROR error) {
    wchar_t wide[256]{};
    if (!mciGetErrorStringW(error, wide, static_cast<UINT>(std::size(wide)))) {
        char fallback[64]{};
        sprintf_s(fallback, "MCI error %u", static_cast<unsigned>(error));
        return fallback;
    }
    const int count = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (count <= 1) return "MCI error";
    std::string result(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, result.data(), count, nullptr, nullptr);
    result.resize(static_cast<size_t>(count - 1));
    return result;
}

bool fail_mci(Player *player, const char *operation, MCIERROR error) {
    const std::string message = std::string(operation) + ": " + mci_message(error);
    if (player) player->set_error(message.c_str());
    else set_open_error(message.c_str());
    return false;
}

bool midi_status(Player *player, DWORD item, DWORD &value) {
    MCI_STATUS_PARMS parameters{};
    parameters.dwItem = item;
    const MCIERROR result = mciSendCommandW(
        player->midi_device, MCI_STATUS, MCI_STATUS_ITEM,
        reinterpret_cast<DWORD_PTR>(&parameters));
    if (result != 0) return fail_mci(player, "query MIDI status", result);
    value = static_cast<DWORD>(parameters.dwReturn);
    return true;
}

void close_midi(Player *player) {
    if (!player || player->midi_device == 0) return;
    mciSendCommandW(player->midi_device, MCI_STOP, 0, 0);
    mciSendCommandW(player->midi_device, MCI_CLOSE, 0, 0);
    player->midi_device = 0;
}

bool create_midi(Player *player) {
    MCI_OPEN_PARMSW open{};
    open.lpstrDeviceType = L"sequencer";
    open.lpstrElementName = player->source.c_str();
    MCIERROR result = mciSendCommandW(
        0, MCI_OPEN, MCI_OPEN_TYPE | MCI_OPEN_ELEMENT,
        reinterpret_cast<DWORD_PTR>(&open));
    if (result != 0) return fail_mci(player, "open MIDI source", result);
    player->midi_device = open.wDeviceID;

    MCI_SEQ_SET_PARMS settings{};
    settings.dwTimeFormat = MCI_FORMAT_MILLISECONDS;
    result = mciSendCommandW(
        player->midi_device, MCI_SET, MCI_SET_TIME_FORMAT,
        reinterpret_cast<DWORD_PTR>(&settings));
    if (result != 0) {
        close_midi(player);
        return fail_mci(player, "select MIDI time format", result);
    }
    DWORD tempo = 0;
    if (midi_status(player, MCI_SEQ_STATUS_TEMPO, tempo) && tempo != 0) {
        player->midi_base_tempo = tempo;
    } else {
        // Tempo probing is optional. Clear its diagnostic so ordinary playback
        // remains usable on minimal third-party MCI sequencers.
        player->set_error("");
    }
    player->state.store(MLV_STATE_READY, std::memory_order_release);
    player->push(MLV_EVENT_READY);
    return true;
}

void update_midi_state(Player *player) {
    if (!player || !player->midi || !player->midi_started ||
        player->state.load(std::memory_order_acquire) != MLV_STATE_PLAYING) return;
    DWORD mode = 0;
    if (!midi_status(player, MCI_STATUS_MODE, mode)) {
        player->state.store(MLV_STATE_FAILED, std::memory_order_release);
        player->push(MLV_EVENT_ERROR, 0, "cannot query MIDI playback state");
        return;
    }
    if (mode == MCI_MODE_PLAY) return;

    DWORD position = 0;
    DWORD duration = 0;
    if (!midi_status(player, MCI_STATUS_POSITION, position) ||
        !midi_status(player, MCI_STATUS_LENGTH, duration)) {
        player->state.store(MLV_STATE_FAILED, std::memory_order_release);
        player->push(MLV_EVENT_ERROR, 0, "cannot query MIDI playback position");
        return;
    }
    const bool at_end = duration > 0 && position + 2 >= duration;
    if (!at_end) return;
    if (player->loop) {
        MCI_SEEK_PARMS seek{};
        MCIERROR result = mciSendCommandW(
            player->midi_device, MCI_SEEK, MCI_SEEK_TO_START,
            reinterpret_cast<DWORD_PTR>(&seek));
        if (result == 0) result = mciSendCommandW(player->midi_device, MCI_PLAY, 0, 0);
        if (result == 0) {
            return;
        }
        fail_mci(player, "restart looping MIDI source", result);
        player->state.store(MLV_STATE_FAILED, std::memory_order_release);
        player->push(MLV_EVENT_ERROR, static_cast<int>(result), "cannot restart looping MIDI source");
        return;
    }
    if (!player->midi_end_reported) {
        player->midi_end_reported = true;
        player->state.store(MLV_STATE_ENDED, std::memory_order_release);
        player->push(MLV_EVENT_ENDED);
    }
}

void release_engine(Player *player) {
    if (!player) return;
    if (player->notify) player->notify->detach();
    if (player->engine) {
        player->engine->Shutdown();
        player->engine->Release();
        player->engine = nullptr;
    }
    if (player->notify) {
        player->notify->Release();
        player->notify = nullptr;
    }
}

bool create_engine(Player *player) {
    IMFAttributes *attributes = nullptr;
    IMFMediaEngineClassFactory *factory = nullptr;

    MediaNotify *notify = new (std::nothrow) MediaNotify(player);
    if (!notify) {
        player->set_error("cannot allocate Media Foundation callback");
        return false;
    }

    HRESULT result = MFCreateAttributes(&attributes, 4);
    if (SUCCEEDED(result)) result = attributes->SetUnknown(MF_MEDIA_ENGINE_CALLBACK, notify);
    if (SUCCEEDED(result) && player->window != 0) {
        result = attributes->SetUINT64(
            MF_MEDIA_ENGINE_PLAYBACK_HWND,
            static_cast<UINT64>(player->window));
    }
    if (SUCCEEDED(result)) {
        result = CoCreateInstance(
            CLSID_MFMediaEngineClassFactory, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&factory));
    }
    if (SUCCEEDED(result)) {
        result = factory->CreateInstance(0, attributes, &player->engine);
    }
    if (factory) factory->Release();
    if (attributes) attributes->Release();
    if (FAILED(result)) {
        notify->detach();
        notify->Release();
        return fail(player, "create Media Foundation engine", result);
    }

    player->notify = notify;
    BSTR source = SysAllocStringLen(player->source.data(),
                                    static_cast<UINT>(player->source.size()));
    if (!source) {
        release_engine(player);
        player->set_error("cannot allocate media source URL");
        return false;
    }
    result = player->engine->SetSource(source);
    SysFreeString(source);
    if (SUCCEEDED(result)) result = player->engine->SetVolume(player->volume);
    if (SUCCEEDED(result)) result = player->engine->SetMuted(player->muted ? TRUE : FALSE);
    if (SUCCEEDED(result)) result = player->engine->SetPlaybackRate(player->rate);
    if (SUCCEEDED(result)) result = player->engine->SetLoop(player->loop ? TRUE : FALSE);
    if (SUCCEEDED(result)) result = player->engine->Load();
    if (FAILED(result)) {
        release_engine(player);
        return fail(player, "load media source", result);
    }
    player->state.store(MLV_STATE_LOADING, std::memory_order_release);
    return true;
}

Player *as_player(void *handle) {
    return static_cast<Player *>(handle);
}

void player_event(Player *player, DWORD event, DWORD_PTR param1, DWORD) {
    if (!player) return;
    switch (event) {
    case MF_MEDIA_ENGINE_EVENT_LOADEDMETADATA:
    case MF_MEDIA_ENGINE_EVENT_CANPLAY:
        player->state.store(MLV_STATE_READY, std::memory_order_release);
        player->push(MLV_EVENT_READY);
        break;
    case MF_MEDIA_ENGINE_EVENT_PLAYING:
        player->state.store(MLV_STATE_PLAYING, std::memory_order_release);
        player->push(MLV_EVENT_PLAYING);
        break;
    case MF_MEDIA_ENGINE_EVENT_PAUSE:
        if (player->state.load(std::memory_order_acquire) != MLV_STATE_STOPPED) {
            player->state.store(MLV_STATE_PAUSED, std::memory_order_release);
            player->push(MLV_EVENT_PAUSED);
        }
        break;
    case MF_MEDIA_ENGINE_EVENT_WAITING:
    case MF_MEDIA_ENGINE_EVENT_BUFFERINGSTARTED:
        player->state.store(MLV_STATE_BUFFERING, std::memory_order_release);
        player->push(MLV_EVENT_BUFFERING);
        break;
    case MF_MEDIA_ENGINE_EVENT_BUFFERINGENDED:
    case MF_MEDIA_ENGINE_EVENT_CANPLAYTHROUGH:
        player->state.store(MLV_STATE_READY, std::memory_order_release);
        player->push(MLV_EVENT_READY);
        break;
    case MF_MEDIA_ENGINE_EVENT_ENDED:
        player->state.store(MLV_STATE_ENDED, std::memory_order_release);
        player->push(MLV_EVENT_ENDED);
        break;
    case MF_MEDIA_ENGINE_EVENT_FORMATCHANGE:
    case MF_MEDIA_ENGINE_EVENT_TRACKSCHANGE:
        player->push(MLV_EVENT_FORMAT_CHANGED);
        break;
    case MF_MEDIA_ENGINE_EVENT_ERROR: {
        int code = static_cast<int>(param1);
        HRESULT extended = E_FAIL;
        IMFMediaError *media_error = nullptr;
        if (player->engine && SUCCEEDED(player->engine->GetError(&media_error)) && media_error) {
            code = static_cast<int>(media_error->GetErrorCode());
            extended = media_error->GetExtendedErrorCode();
            media_error->Release();
        }
        const std::string message = hresult_message(extended);
        player->set_error(message.c_str());
        player->state.store(MLV_STATE_FAILED, std::memory_order_release);
        player->push(MLV_EVENT_ERROR, code, message.c_str());
        break;
    }
    default:
        break;
    }
}

} // namespace

MLV_EXPORT uint32_t mlv_abi_version(void) {
    return 1;
}

MLV_EXPORT int mlv_backend(unsigned char *message, int capacity) {
    return copy_text("media-foundation", message, capacity);
}

MLV_EXPORT void *mlv_open(const char *source, uintptr_t window_handle, int allow_network) {
    g_open_error[0] = '\0';
    const std::string source_text(source ? source : "");
    const bool use_midi = is_midi_source(source_text) && !is_network_source(source_text);
    std::wstring resolved;
    if (use_midi) {
        if (!local_source_path(source, resolved)) return nullptr;
    } else if (!source_url(source, allow_network != 0, resolved)) {
        return nullptr;
    }

    Player *player = new (std::nothrow) Player();
    if (!player) {
        set_open_error("cannot allocate video player");
        return nullptr;
    }
    player->source = std::move(resolved);
    player->window = window_handle;
    player->owner_thread = GetCurrentThreadId();
    player->midi = use_midi;

    if (player->midi) {
        if (!create_midi(player)) {
            strncpy_s(g_open_error, player->error, _TRUNCATE);
            delete player;
            return nullptr;
        }
        return player;
    }

    // A hidden target keeps headless playback and metadata probing fully
    // clocked. attach() replaces it with the caller's visible child window.
    if (player->window == 0) {
        player->owned_window = CreateWindowExW(
            0, L"STATIC", L"", WS_POPUP, 0, 0, 2, 2,
            nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (!player->owned_window) {
            set_open_error("cannot create hidden video target");
            delete player;
            return nullptr;
        }
        player->window = reinterpret_cast<uintptr_t>(player->owned_window);
    }

    HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(result)) {
        player->co_initialized = true;
    } else if (result != RPC_E_CHANGED_MODE) {
        fail(nullptr, "CoInitializeEx", result);
        if (player->owned_window) DestroyWindow(player->owned_window);
        delete player;
        return nullptr;
    }
    result = MFStartup(MF_VERSION, MFSTARTUP_FULL);
    if (FAILED(result)) {
        fail(nullptr, "MFStartup", result);
        if (player->co_initialized) CoUninitialize();
        if (player->owned_window) DestroyWindow(player->owned_window);
        delete player;
        return nullptr;
    }
    player->mf_started = true;
    if (!create_engine(player)) {
        strncpy_s(g_open_error, player->error, _TRUNCATE);
        MFShutdown();
        if (player->co_initialized) CoUninitialize();
        if (player->owned_window) DestroyWindow(player->owned_window);
        delete player;
        return nullptr;
    }
    return player;
}

MLV_EXPORT int mlv_attach(void *handle, uintptr_t window_handle) {
    Player *player = as_player(handle);
    if (!player || window_handle == 0) return 0;
    if (player->midi) {
        player->set_error("MIDI playback has no video target");
        return 0;
    }
    const int state = player->state.load(std::memory_order_acquire);
    if (state == MLV_STATE_PLAYING || state == MLV_STATE_BUFFERING) {
        player->set_error("attach must be called before playback");
        return 0;
    }
    release_engine(player);
    if (player->owned_window) {
        DestroyWindow(player->owned_window);
        player->owned_window = nullptr;
    }
    player->window = window_handle;
    return create_engine(player) ? 1 : 0;
}

MLV_EXPORT int mlv_play(void *handle) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (player->midi) {
        if (player->midi_device == 0) return 0;
        if (player->state.load(std::memory_order_acquire) == MLV_STATE_ENDED) {
            MCI_SEEK_PARMS seek{};
            const MCIERROR seek_result = mciSendCommandW(
                player->midi_device, MCI_SEEK, MCI_SEEK_TO_START,
                reinterpret_cast<DWORD_PTR>(&seek));
            if (seek_result != 0) return fail_mci(player, "rewind MIDI source", seek_result) ? 1 : 0;
        }
        const MCIERROR result = mciSendCommandW(player->midi_device, MCI_PLAY, 0, 0);
        if (result != 0) return fail_mci(player, "play MIDI source", result) ? 1 : 0;
        player->midi_started = true;
        player->midi_end_reported = false;
        player->state.store(MLV_STATE_PLAYING, std::memory_order_release);
        player->push(MLV_EVENT_PLAYING);
        return 1;
    }
    if (!player->engine) return 0;
    const HRESULT result = player->engine->Play();
    if (FAILED(result)) {
        fail(player, "play", result);
        return 0;
    }
    player->state.store(MLV_STATE_PLAYING, std::memory_order_release);
    return 1;
}

MLV_EXPORT int mlv_pause(void *handle) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (player->midi) {
        if (player->midi_device == 0) return 0;
        const MCIERROR result = mciSendCommandW(player->midi_device, MCI_PAUSE, 0, 0);
        if (result != 0) return fail_mci(player, "pause MIDI source", result) ? 1 : 0;
        player->state.store(MLV_STATE_PAUSED, std::memory_order_release);
        player->push(MLV_EVENT_PAUSED);
        return 1;
    }
    if (!player->engine) return 0;
    const HRESULT result = player->engine->Pause();
    if (FAILED(result)) {
        fail(player, "pause", result);
        return 0;
    }
    player->state.store(MLV_STATE_PAUSED, std::memory_order_release);
    return 1;
}

MLV_EXPORT int mlv_stop(void *handle) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (player->midi) {
        if (player->midi_device == 0) return 0;
        MCIERROR result = mciSendCommandW(player->midi_device, MCI_STOP, 0, 0);
        MCI_SEEK_PARMS seek{};
        if (result == 0) result = mciSendCommandW(
            player->midi_device, MCI_SEEK, MCI_SEEK_TO_START,
            reinterpret_cast<DWORD_PTR>(&seek));
        if (result != 0) return fail_mci(player, "stop MIDI source", result) ? 1 : 0;
        player->midi_started = false;
        player->midi_end_reported = false;
        player->state.store(MLV_STATE_STOPPED, std::memory_order_release);
        player->push(MLV_EVENT_STOPPED);
        return 1;
    }
    if (!player->engine) return 0;
    HRESULT result = player->engine->Pause();
    if (SUCCEEDED(result)) result = player->engine->SetCurrentTime(0.0);
    if (FAILED(result)) {
        fail(player, "stop", result);
        return 0;
    }
    player->state.store(MLV_STATE_STOPPED, std::memory_order_release);
    player->push(MLV_EVENT_STOPPED);
    return 1;
}

MLV_EXPORT int mlv_seek(void *handle, int64_t milliseconds) {
    Player *player = as_player(handle);
    if (!player || milliseconds < 0 ||
        milliseconds > kMaxMilliseconds) return 0;
    if (player->midi) {
        if (player->midi_device == 0 || milliseconds > MAXDWORD) return 0;
        const bool resume = player->state.load(std::memory_order_acquire) == MLV_STATE_PLAYING;
        MCI_SEEK_PARMS seek{};
        seek.dwTo = static_cast<DWORD>(milliseconds);
        MCIERROR result = mciSendCommandW(
            player->midi_device, MCI_SEEK, MCI_TO,
            reinterpret_cast<DWORD_PTR>(&seek));
        if (result == 0 && resume) {
            result = mciSendCommandW(player->midi_device, MCI_PLAY, 0, 0);
        }
        if (result != 0) return fail_mci(player, "seek MIDI source", result) ? 1 : 0;
        player->midi_end_reported = false;
        return 1;
    }
    if (!player->engine) return 0;
    const HRESULT result = player->engine->SetCurrentTime(
        static_cast<double>(milliseconds) / 1000.0);
    if (FAILED(result)) {
        fail(player, "seek", result);
        return 0;
    }
    return 1;
}

MLV_EXPORT int mlv_set_volume(void *handle, double volume) {
    Player *player = as_player(handle);
    if (!player || !std::isfinite(volume) || volume < 0.0 || volume > 1.0) return 0;
    if (player->midi) {
        player->volume = volume;
        return 1;
    }
    if (!player->engine) return 0;
    const HRESULT result = player->engine->SetVolume(volume);
    if (FAILED(result)) {
        fail(player, "set volume", result);
        return 0;
    }
    player->volume = volume;
    return 1;
}

MLV_EXPORT int mlv_set_muted(void *handle, int muted) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (player->midi) {
        if (player->midi_device == 0) return 0;
        MCI_SEQ_SET_PARMS settings{};
        settings.dwAudio = MCI_SET_AUDIO_ALL;
        const DWORD flags = MCI_SET_AUDIO | (muted ? MCI_SET_OFF : MCI_SET_ON);
        const MCIERROR result = mciSendCommandW(
            player->midi_device, MCI_SET, flags,
            reinterpret_cast<DWORD_PTR>(&settings));
        // Some sequencers expose no per-instance audio switch. Keep the
        // logical setting without mutating the process-wide MIDI mapper.
        if (result != 0 && result != MCIERR_UNSUPPORTED_FUNCTION) {
            return fail_mci(player, "set MIDI muted state", result) ? 1 : 0;
        }
        player->muted = muted != 0;
        return 1;
    }
    if (!player->engine) return 0;
    const HRESULT result = player->engine->SetMuted(muted ? TRUE : FALSE);
    if (FAILED(result)) {
        fail(player, "set muted", result);
        return 0;
    }
    player->muted = muted != 0;
    return 1;
}

MLV_EXPORT int mlv_set_rate(void *handle, double rate) {
    Player *player = as_player(handle);
    if (!player || !std::isfinite(rate) || rate < 0.25 || rate > 4.0) return 0;
    if (player->midi) {
        if (player->midi_device == 0) return 0;
        MCI_SEQ_SET_PARMS settings{};
        settings.dwTempo = static_cast<DWORD>(std::llround(
            static_cast<double>(player->midi_base_tempo) / rate));
        const MCIERROR result = mciSendCommandW(
            player->midi_device, MCI_SET, MCI_SEQ_SET_TEMPO,
            reinterpret_cast<DWORD_PTR>(&settings));
        if (result != 0) return fail_mci(player, "set MIDI playback rate", result) ? 1 : 0;
        player->rate = rate;
        return 1;
    }
    if (!player->engine) return 0;
    const HRESULT result = player->engine->SetPlaybackRate(rate);
    if (FAILED(result)) {
        fail(player, "set playback rate", result);
        return 0;
    }
    player->rate = rate;
    return 1;
}

MLV_EXPORT int mlv_set_loop(void *handle, int enabled) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (player->midi) {
        player->loop = enabled != 0;
        return 1;
    }
    if (!player->engine) return 0;
    const HRESULT result = player->engine->SetLoop(enabled ? TRUE : FALSE);
    if (FAILED(result)) {
        fail(player, "set loop", result);
        return 0;
    }
    player->loop = enabled != 0;
    return 1;
}

MLV_EXPORT int mlv_state(void *handle) {
    Player *player = as_player(handle);
    update_midi_state(player);
    return player ? player->state.load(std::memory_order_acquire) : MLV_STATE_CLOSED;
}

MLV_EXPORT int64_t mlv_position_ms(void *handle) {
    Player *player = as_player(handle);
    if (!player) return 0;
    if (player->midi) {
        DWORD value = 0;
        return midi_status(player, MCI_STATUS_POSITION, value) ? value : 0;
    }
    if (!player->engine) return 0;
    return static_cast<int64_t>(player->engine->GetCurrentTime() * 1000.0);
}

MLV_EXPORT int64_t mlv_duration_ms(void *handle) {
    Player *player = as_player(handle);
    if (!player) return -1;
    if (player->midi) {
        DWORD value = 0;
        return midi_status(player, MCI_STATUS_LENGTH, value) ? value : -1;
    }
    if (!player->engine) return -1;
    const double duration = player->engine->GetDuration();
    if (!std::isfinite(duration) || duration < 0.0) return -1;
    return static_cast<int64_t>(duration * 1000.0);
}

MLV_EXPORT int mlv_has_audio(void *handle) {
    Player *player = as_player(handle);
    if (player && player->midi && player->midi_device != 0) return 1;
    return player && player->engine && player->engine->HasAudio() ? 1 : 0;
}

MLV_EXPORT int mlv_has_video(void *handle) {
    Player *player = as_player(handle);
    if (player && player->midi) return 0;
    return player && player->engine && player->engine->HasVideo() ? 1 : 0;
}

MLV_EXPORT int mlv_video_width(void *handle) {
    Player *player = as_player(handle);
    if (player && player->midi) return 0;
    if (!player || !player->engine) return 0;
    DWORD width = 0;
    return SUCCEEDED(player->engine->GetNativeVideoSize(&width, nullptr))
        ? static_cast<int>(width) : 0;
}

MLV_EXPORT int mlv_video_height(void *handle) {
    Player *player = as_player(handle);
    if (player && player->midi) return 0;
    if (!player || !player->engine) return 0;
    DWORD height = 0;
    return SUCCEEDED(player->engine->GetNativeVideoSize(nullptr, &height))
        ? static_cast<int>(height) : 0;
}

MLV_EXPORT int mlv_poll_event(void *handle, unsigned char *message, int capacity) {
    Player *player = as_player(handle);
    if (!player) {
        if (message && capacity > 0) message[0] = 0;
        return MLV_EVENT_NONE;
    }
    update_midi_state(player);
    return player->pop(message, capacity);
}

MLV_EXPORT int mlv_event_code(void *handle) {
    Player *player = as_player(handle);
    return player ? player->last_event_code : 0;
}

MLV_EXPORT int mlv_error(void *handle, unsigned char *message, int capacity) {
    Player *player = as_player(handle);
    if (!player) return copy_text(g_open_error, message, capacity);
    EnterCriticalSection(&player->lock);
    const int copied = copy_text(player->error, message, capacity);
    LeaveCriticalSection(&player->lock);
    return copied;
}

MLV_EXPORT void mlv_close(void *handle) {
    Player *player = as_player(handle);
    if (!player) return;
    player->state.store(MLV_STATE_CLOSED, std::memory_order_release);
    close_midi(player);
    release_engine(player);
    if (player->owned_window) DestroyWindow(player->owned_window);
    if (player->mf_started) MFShutdown();
    if (player->co_initialized && player->owner_thread == GetCurrentThreadId()) {
        CoUninitialize();
    }
    delete player;
}
