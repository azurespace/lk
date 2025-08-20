# lkmod Module Manager (GaiaModuleManager)

이 문서는 `lkmod` 런타임 로더 위에 구축된 C++ 기반 슬롯형 모듈 매니저 `GaiaModuleManager` 설계를 설명합니다. 목표는 slot_id로 ELF 바이너리를 메모리 풀에 등록하고(load), 심볼로 엔트리 함수를 호출(call), 안전하게 언로드(unload)하는 기능을 제공하는 것입니다.

## 핵심 개념
- 슬롯 단위 관리: 각 슬롯은 고정 용량(slot_capacity)의 blob 저장 영역과, 로드된 모듈 핸들(선택적)을 가짐
- 메모리 풀: 외부 제공(pool_base) 또는 내부 할당(page_alloc). 풀은 slot_count × slot_capacity 크기
- 동시성/수명: LK 커널 mutex로 슬롯 테이블을 보호하고, 사용 중(refcount>0)에는 unload가 되지 않도록 보장
  - 단발 호출은 호출 구간 동안만 refcount를 올려 안전하게 수행
  - 장기 사용은 RAII 핸들을 통해 refcount를 보유해, 핸들이 살아있는 동안 언로드 금지
- 로더: 실제 ELF 로딩/재배치는 기존 `lib/lkmod`(C) 사용. 매니저는 수명과 호출만 담당

## 상태 전이
- Empty → Registered: register_blob 성공
- Registered → Loaded: load 성공
- Loaded → Registered: unload 성공
- Registered → Empty: unregister 성공

## C++ API 요약
- 클래스: `GaiaModuleManager`
- 초기화/해제
  - `status_t init(const Config&)`, `status_t shutdown()`
  - `slot_count()`, `slot_capacity()`
- 슬롯 관리
  - `register_blob(slot, blob, len, overwrite=false)` / `unregister_blob(slot)`
  - `load(slot)` / `unload(slot)`
  - `get_info(slot, Info*)`
  - `set_entry(slot, symbol)` / `get_entry(slot)`
- 호출
  - 즉시 호출(단발):
    - `call(slot, symbol, a0..a3, &ret)`
    - `call_entry(slot, a0..a3, &ret)` (사전 설정된 엔트리 심볼 사용)
    - 위 두 API는 호출 구간 동안 내부적으로 refcount를 올려 unload를 차단
  - RAII 핸들(장기 사용):
    - `Handle acquire(slot)` 혹은 `status_t acquire(slot, Handle*)`
    - `Handle`는 소멸자에서 refcount를 감소시키는 이동 전용 RAII 타입
    - 타입 안전 호출: `handle.call<R(Args...)>("sym", &ret, args...)`, `handle.call<void(Args...)>("sym", args...)`
    - 엔트리 호출: `handle.call_entry<R(Args...)>(&ret, args...)`, `handle.call_entry<void(Args...)>(args...)`
    - 핸들이 살아있는 동안 해당 슬롯 `unload(slot)`은 `ERR_BUSY`로 실패

## 사용 예
```
#include <lkmod/gaia_module_manager.h>

GaiaModuleManager::Config cfg;
cfg.slot_capacity = 256 * 1024; // 256 KiB per slot
cfg.slot_count = 8;             // 8 slots (내부 풀 할당)
GaiaModuleManager mgr;
mgr.init(cfg);

// 1) blob 등록 → 2) 로드 → 3) 엔트리 호출
mgr.register_blob(0, blob_ptr, blob_len, true);
mgr.load(0);
mgr.set_entry(0, "hello_add");
// (A) 단발 호출: 호출 구간 동안만 모듈이 pin 됨
int64_t ret = 0;
mgr.call_entry(0, 7, 5, 0, 0, &ret);

// (B) RAII 핸들로 장기 사용: 핸들이 생존하는 동안 unload 금지
GaiaModuleManager::Handle h = mgr.acquire(0);
if (h) {
    // 타입 안전 템플릿 호출 (반환값 있음)
    int r2 = 0;
    h.call<int(int,int)>("hello_add", &r2, 1, 2);

    // 엔트리 심볼로 호출 (void 반환 예)
    mgr.set_entry(0, "hello_run");
    h.call_entry<void(int)>(42);
    // ... 필요 시 여러 번 호출 가능
} // 여기서 h 소멸 → refcount 감소

// 4) 언로드/언레지스터
mgr.unload(0);
mgr.unregister_blob(0);

mgr.shutdown();
```

## 구현 위치
- 헤더: `lib/lkmodmgr/include/lkmod/gaia_module_manager.h`
- 구현: `lib/lkmodmgr/gaia_module_manager.cpp`
- 빌드: `lib/lkmodmgr/rules.mk`

## 주의사항
- Refcount/RAII: `call*`은 호출 구간 동안 내부적으로 refcount를 증가시켜 언로드를 차단합니다. 장기 점유가 필요하면 반드시 `Handle`을 획득해 사용하세요.
- Unload 규칙: `unload(slot)`은 refcount>0(핸들 보유 또는 호출 진행 중)일 때 `ERR_BUSY`로 즉시 실패합니다. 블로킹하지 않습니다.
- Shutdown 규칙: `shutdown()`은 어느 슬롯이든 refcount>0이면 `ERR_BUSY`를 반환하며 풀 해제를 생략합니다.
- 검증: 모듈이 신뢰되지 않는 경우를 대비해, 필요 시 상위 계층에서 해시/서명 검증을 추가하세요.

## 구현 메모
- 현재 구현은 단발 호출에 대한 in-flight refcount를 제공하며, RAII 핸들은 API에 순차 도입 예정입니다.
- RAII 도입 시 `Handle`은 이동만 허용하고 복사는 금지되며, 유효성 검사를 위한 명시적 boolean 변환 연산자를 제공합니다.
