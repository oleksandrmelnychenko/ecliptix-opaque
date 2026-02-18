# Порівняння бенчмарків: Apple M1 Pro vs Windows PC

Цей документ збирає результати бенчмарків на двох платформах для порівняння продуктивності Hybrid PQ-OPAQUE.

---

## Як запустити бенчмарки на цьому ПК (Windows)

1. **Залежності (vcpkg):**
   ```powershell
   # Якщо ще не встановлено (або вже встановлено в C:\Users\123\vcpkg):
   git clone https://github.com/microsoft/vcpkg.git C:\Users\123\vcpkg
   C:\Users\123\vcpkg\bootstrap-vcpkg.bat
   C:\Users\123\vcpkg\vcpkg install libsodium:x64-windows liboqs:x64-windows
   $env:VCPKG_ROOT = "C:\Users\123\vcpkg"
   ```

2. **Збірка та запуск:**
   ```powershell
   cd c:\Users\123\CLionProjects\ecliptix-opaque
   cmake -B build -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCHMARKS=ON
   cmake --build build --config Release
   ```

3. **Запуск усіх бенчмарків і збереження виводу:**

   Одним викликом (рекомендовано):
   ```powershell
   cmake --build build --config Release --target run_benchmarks
   ```
   Зберегти вивід у файл:
   ```powershell
   cmake --build build --config Release --target run_benchmarks 2>&1 | Out-File -FilePath docs\bench_windows_full.txt -Encoding utf8
   ```

   Або запускати exe вручну (шлях: `build\Release\` для Visual Studio, `build\` для Ninja):
   ```powershell
   cd build
   .\Release\bench_micro.exe
   .\Release\bench_protocol.exe
   .\Release\bench_throughput.exe
   .\Release\bench_overhead.exe
   ```

4. Після запуску заповни секцію **«Результати — Windows PC»** нижче (скопіюй ключові числа з виводу або з `docs/complete_test_benchmark_results.md` для Apple).

---

## Результати — Apple M1 Pro (10 cores, 16 GB RAM)

*Джерело: [complete_test_benchmark_results.md](complete_test_benchmark_results.md). Компілятор: AppleClang 17.0.0, Release -O3.*

### Мікропримітиви (медіана μs)

| Операція | Mean (μs) | Median (μs) |
|----------|-----------|-------------|
| Ristretto255 keypair | 19.6 | 18.9 |
| Single DH | 43.7 | 43.4 |
| 3DH | 133.0 | 133.7 |
| ML-KEM-768 keygen | 17.1 | 17.1 |
| ML-KEM-768 encaps | 18.2 | 18.3 |
| ML-KEM-768 decaps | 20.8 | 20.5 |
| ML-KEM-768 full round | 55.3 | 54.1 |
| OPRF Blind | 78.2 | 64.9 |
| OPRF Evaluate | 44.2 | 43.7 |
| OPRF Finalize | 81.6 | 74.6 |
| Argon2id (MODERATE) | **625 000** | **592 400** |

### Фази протоколу

| Фаза | Час |
|------|-----|
| Реєстрація (повна) | 615.6 ms |
| Автентифікація (повна) | 586.0 ms |
| Server KE2 only (без Argon2id) | 0.332 ms/op |

### Пропускна здатність

| Метрика | Значення |
|---------|----------|
| Повна автентифікація | ~1.6 auth/s |
| Сервер KE2 only | **3009.6 ops/s** |

---

## Результати — Windows PC (цей ПК)

*Результати отримано на локальній машині. Release, vcpkg (libsodium 1.0.20, liboqs 0.12.0).*

**Платформа:** Windows, 32 ядра CPU, 31.8 GB RAM (x86_64)  
**Компілятор:** MSVC 19.43 (1943)  
**Дата:** 2026-02-17

### Мікропримітиви (медіана μs)

| Операція | Mean (μs) | Median (μs) |
|----------|-----------|-------------|
| Ristretto255 keypair | 20.0 | 19.9 |
| Single DH | 64.8 | 64.5 |
| 3DH | 198.2 | 196.0 |
| ML-KEM-768 keygen | 69.4 | 68.7 |
| ML-KEM-768 encaps | 72.0 | 71.5 |
| ML-KEM-768 decaps | 48.4 | 48.2 |
| ML-KEM-768 full round | 194.0 | 191.5 |
| OPRF Blind | 87.1 | 86.9 |
| OPRF Evaluate | 64.8 | 64.5 |
| OPRF Finalize | 92.4 | 91.8 |
| Argon2id (MODERATE) | 205 899 | **205 311** (≈205.3 ms) |

### Фази протоколу

| Фаза | Час |
|------|-----|
| Реєстрація (повна) | 227.4 ms (median) |
| Автентифікація (повна) | 202.6 ms (median) |
| Server KE2 only | 0.551 ms/op |

### Пропускна здатність

| Метрика | Значення |
|---------|----------|
| Повна автентифікація | ~4.4 auth/s |
| Сервер KE2 only | **1813.7 ops/s** |

---

## Порівняння: Apple M1 Pro vs Windows PC

| Метрика | Apple M1 Pro | Windows PC | Відношення (PC / Apple) |
|---------|--------------|-------------|--------------------------|
| ML-KEM-768 full round (μs) | 55.3 | 191.5 | 3.46× повільніше на PC |
| 3DH (μs) | 133.0 | 196.0 | 1.47× повільніше на PC |
| Argon2id (ms) | ~625 | ~205 | **3.05× швидше на PC** |
| Повна автентифікація (ms) | 586 | 202.6 | **2.89× швидше на PC** |
| Сервер KE2 (ops/s) | 3009.6 | 1813.7 | 1.66× повільніше на PC |

**Висновки:**
- **Аргон2ід і повна автентифікація на Windows PC значно швидші** (~3×): ймовірно, через більшу кількість ядер (32 vs 10) і інші оптимізації libsodium/Argon2 на x86, або інші параметри збірки.
- **ML-KEM-768 і 3DH на PC повільніші** (1.5–3.5×): M1 має дуже ефективні крипто-інструкції та оптимізований liboqs для ARM; на x86 без AVX2/AVX-512 ML-KEM може бути повільнішим.
- **Серверна пропускна здатність (лише KE2)** вища на M1 (3009 vs 1814 ops/s) — узгоджується з тим, що крипто-примітиви (EC, KEM) на ARM у цій збірці швидші.
- Wire overhead однаковий (2712 B); латентність end-to-end на PC нижча завдяки швидшому Argon2id.

---

*Wire overhead (розміри повідомлень) однаковий на всіх платформах: 2712 B для повної автентифікації (див. complete_test_benchmark_results.md).*
