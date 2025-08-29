// Slot-based C++ module manager atop lib/lkmod.
// Stores ET_DYN ELF blobs in a fixed-capacity per-slot pool and
// provides slot-indexed load/call/unload operations.

#pragma once

#include <lk/err.h>
#include <stdint.h>
#include <stddef.h>

#include <lkmod/lkmod.h>
#include <kernel/mutex.h>

class GaiaModuleManager {
public:
    class Handle;
    enum class SlotState : uint32_t {
        Empty = 0,
        Registered,
        Loaded,
    };

    struct Config {
        void *pool_base = nullptr;  // optional external pool base
        size_t pool_size = 0;       // size of external pool
        size_t slot_capacity = 0;   // required (>0)
        uint32_t slot_count = 0;    // required if pool_base == nullptr
        const lkmod_api_t *api = nullptr; // optional API passed to modules
        bool run_el0 = false;       // if true, modules load into EL0 aspace (calls via EL0 worker: TODO)
    };

    struct Info {
        SlotState state{};
        size_t blob_size{};
        size_t blob_capacity{};
        const char *entry_symbol{};
        lkmod_module_t *mod{};
        uintptr_t mod_base{};
        size_t mod_size{};
        uint32_t inflight_calls{};
    };

    GaiaModuleManager() = default;
    explicit GaiaModuleManager(const Config &cfg) { (void)init(cfg); }
    ~GaiaModuleManager();

    status_t init(const Config &cfg);
    status_t shutdown();

    // pool/slot config
    size_t slot_capacity() const { return slot_capacity_; }
    uint32_t slot_count() const { return slot_count_; }

    // blob management
    status_t register_blob(uint32_t slot_id, const void *blob, size_t len, bool overwrite);
    status_t unregister_blob(uint32_t slot_id);

    // load/unload
    status_t load(uint32_t slot_id);
    status_t unload(uint32_t slot_id);

    // entry symbol management
    status_t set_entry(uint32_t slot_id, const char *symbol);
    const char *get_entry(uint32_t slot_id) const;

    // immediate call
    status_t call(uint32_t slot_id, const char *sym,
                  int64_t a0=0, int64_t a1=0, int64_t a2=0, int64_t a3=0,
                  int64_t *ret_out=nullptr);
    status_t call_entry(uint32_t slot_id,
                        int64_t a0=0, int64_t a1=0, int64_t a2=0, int64_t a3=0,
                        int64_t *ret_out=nullptr);

    // info
    status_t get_info(uint32_t slot_id, Info *out) const;

    // RAII acquisition: pins the slot (refcount++) while alive.
    Handle acquire(uint32_t slot_id);
    status_t acquire(uint32_t slot_id, Handle *out);

private:
    struct Slot;
    friend class Handle;

    bool inited_ = false;
    void *pool_ = nullptr;
    size_t pool_size_ = 0;
    size_t slot_capacity_ = 0;
    uint32_t slot_count_ = 0;
    bool pool_owned_ = false;
    const lkmod_api_t *api_ = nullptr;
    bool run_el0_ = false;

    // C-style primitives from LK kernel
    mutable mutex_t lock_{};
    Slot *slots_ = nullptr; // array

    bool valid_slot(uint32_t id) const { return inited_ && id < slot_count_; }
};

// RAII handle that pins a loaded slot to prevent unload while in use.
class GaiaModuleManager::Handle {
public:
    Handle() = default;
    ~Handle();

    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;

    Handle(Handle &&other) noexcept { move_from(other); }
    Handle &operator=(Handle &&other) noexcept {
        if (this != &other) { release(); move_from(other); }
        return *this;
    }

    explicit operator bool() const { return mgr_ != nullptr; }
    uint32_t slot() const { return slot_id_; }

    // Untyped convenience: forwards to manager's call using int64 args
    status_t call(const char *sym,
                  int64_t a0=0, int64_t a1=0, int64_t a2=0, int64_t a3=0,
                  int64_t *ret_out=nullptr) const;

    // Typed call by function signature: R(Args...)
    template <typename R, typename... Args, R(*Dummy)(Args...) = nullptr>
    status_t call(const char *sym, R *ret_out, Args... args) const {
        if (!mgr_ || !sym) return ERR_INVALID_ARGS;
        GaiaModuleManager::Slot *s = &mgr_->slots_[slot_id_];
        if (s->state != SlotState::Loaded || !s->mod) return ERR_NOT_FOUND;
        uintptr_t addr = lkmod_lookup(s->mod, sym);
        if (!addr) return ERR_NOT_FOUND;
        using FnPtr = R (*)(Args...);
        FnPtr fn = reinterpret_cast<FnPtr>(addr);
        if (ret_out) *ret_out = fn(args...);
        else { (void)fn(args...); }
        return NO_ERROR;
    }

    // Typed call for void return: void(Args...)
    template <typename... Args, void(*Dummy)(Args...) = nullptr>
    status_t call(const char *sym, Args... args) const {
        if (!mgr_ || !sym) return ERR_INVALID_ARGS;
        GaiaModuleManager::Slot *s = &mgr_->slots_[slot_id_];
        if (s->state != SlotState::Loaded || !s->mod) return ERR_NOT_FOUND;
        uintptr_t addr = lkmod_lookup(s->mod, sym);
        if (!addr) return ERR_NOT_FOUND;
        using FnPtr = void (*)(Args...);
        FnPtr fn = reinterpret_cast<FnPtr>(addr);
        fn(args...);
        return NO_ERROR;
    }

    // Typed call to preset entry symbol
    template <typename R, typename... Args, R(*Dummy)(Args...) = nullptr>
    status_t call_entry(R *ret_out, Args... args) const {
        const char *sym = mgr_ ? mgr_->get_entry(slot_id_) : nullptr;
        if (!sym) return ERR_NOT_FOUND;
        return call<R, Args...>(sym, ret_out, args...);
    }

    template <typename... Args, void(*Dummy)(Args...) = nullptr>
    status_t call_entry(Args... args) const {
        const char *sym = mgr_ ? mgr_->get_entry(slot_id_) : nullptr;
        if (!sym) return ERR_NOT_FOUND;
        return call(sym, args...);
    }

private:
    friend class GaiaModuleManager; // allow manager to create/move handles
    GaiaModuleManager *mgr_ = nullptr;
    uint32_t slot_id_ = 0;

    Handle(GaiaModuleManager *mgr, uint32_t slot_id) : mgr_(mgr), slot_id_(slot_id) {}
    void move_from(Handle &other) {
        mgr_ = other.mgr_;
        slot_id_ = other.slot_id_;
        other.mgr_ = nullptr;
        other.slot_id_ = 0;
    }
    void release();
};
