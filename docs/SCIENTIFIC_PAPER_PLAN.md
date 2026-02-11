# План наукової статті (30 сторінок)

## Робоча назва

**"Гібридний постквантовий протокол автентифікації на основі парольного ключового обміну OPAQUE з інтеграцією ML-KEM-768"**

Англійська версія: *"A Hybrid Post-Quantum Authentication Protocol Based on OPAQUE Password-Authenticated Key Exchange with ML-KEM-768 Integration"*

---

## Наукова новизна (одна, чітко сформульована)

**Вперше запропоновано та реалізовано гібридну схему розширення протоколу OPAQUE (asymmetric PAKE), яка забезпечує одночасну стійкість до класичних та квантових атак шляхом обов'язкової інтеграції механізму інкапсуляції ключів ML-KEM-768 у потік автентифікованого ключового обміну 3DH, з комбінуванням класичного та постквантового ключового матеріалу через HKDF-Extract із контекстним зв'язуванням транскрипту.**

### Деталізація новизни:

1. **Не опціональна, а обов'язкова постквантова складова** — на відміну від більшості гібридних підходів (TLS 1.3 hybrid, Signal PQ), ML-KEM-768 є невід'ємною частиною протоколу, а не додатковим шаром.

2. **Специфічна конструкція комбінатора** — об'єднання IKM від 3DH (96 байт: dh1||dh2||dh3) та shared secret від ML-KEM-768 (32 байт) через HKDF-Extract з міченим (labeled) транскриптом як сіллю, що забезпечує зв'язування всіх криптографічних контекстів.

3. **Розширення транскрипту** — до стандартного mac_input додано kem_public_key та kem_ciphertext, що гарантує цілісність постквантової складової в рамках взаємної автентифікації.

4. **Збереження всіх властивостей OPAQUE** — password secrecy, forward secrecy, mutual authentication, resistance to offline dictionary attacks — в гібридній конструкції.

---

## Структура статті з розподілом сторінок

### 1. Анотація / Abstract (~0.5 стор.)
- Проблема: загроза квантових комп'ютерів для існуючих протоколів автентифікації на основі паролів
- Мета: розробка гібридного PQ-розширення OPAQUE
- Метод: інтеграція ML-KEM-768 в 3DH ключовий обмін з HKDF-комбінуванням
- Результат: протокол зберігає всі класичні властивості безпеки OPAQUE та додає стійкість до квантових атак
- Ключові слова: OPAQUE, PAKE, ML-KEM-768, постквантова криптографія, гібридний ключовий обмін, Ristretto255

### 2. Вступ (~2.5 стор.)

**Зміст:**
- Актуальність проблеми парольної автентифікації в контексті квантової загрози
  - Статистика: >80% веб-автентифікації базується на паролях
  - Алгоритм Шора: загроза для DH, ECDH, RSA (основи більшості PAKE)
  - Timeline квантової загрози: NIST PQC стандартизація (FIPS 203, серпень 2024)
- Обмеження існуючих підходів
  - Класичний OPAQUE (draft-irtf-cfrg-opaque) не має PQ-захисту
  - SRP, SPAKE2 — вразливі до квантових атак на DLP
  - Чисто PQ-PAKE — недостатньо зрілі, відсутність гарантій без класичного fallback
- Мета дослідження: розробка гібридної конструкції, що додає PQ-стійкість до OPAQUE без втрати існуючих властивостей безпеки
- Внесок роботи (contribution statement)
- Структура статті

### 3. Аналіз літературних джерел та існуючих рішень (~4.5 стор.)

**3.1 Протоколи парольного автентифікованого ключового обміну (PAKE) (~1.5 стор.)**
- Таксономія PAKE: balanced vs. augmented (aPAKE)
- EKE (Bellovin & Merritt, 1992) — перший PAKE
- SRP (Stanford, RFC 2945) — широко використовуваний aPAKE
- SPAKE2 (Abdalla & Pointcheval) — IETF стандарт
- OPAQUE (Jarecki, Krawczyk, Xu, 2018) — найбільш безпечний aPAKE з OPRF
- Порівняльна таблиця властивостей протоколів

**3.2 Протокол OPAQUE: формальний опис (~1.5 стор.)**
- Визначення OPRF (Oblivious Pseudorandom Function)
- Фази: реєстрація та автентифікація
- Ключовий обмін 3DH (triple Diffie-Hellman)
- Envelope механізм: зберігання облікових даних
- Формальні властивості безпеки: UC-security model (Canetti framework)
- Специфікація IETF: draft-irtf-cfrg-opaque

**3.3 Постквантова криптографія та механізми інкапсуляції ключів (~1.5 стор.)**
- Загроза квантових обчислень для DLP/ECDLP
- NIST PQC стандартизація: ML-KEM (FIPS 203), ML-DSA (FIPS 204)
- ML-KEM-768 (Kyber): lattice-based KEM, Module-LWE задача
  - Параметри безпеки: IND-CCA2, рівень безпеки NIST Level 3
  - Розміри: pk=1184, ct=1088, ss=32
- Гібридні підходи в TLS 1.3 (RFC 9999 draft), Signal (PQXDH), WireGuard
- Відсутність стандартизованого гібридного PQ-PAKE як відкрита проблема

### 4. Постановка задачі (~2 стор.)

**4.1 Формулювання проблеми (~1 стор.)**
- Формальна модель загроз: класичний + квантовий противник
  - Класичний противник: MITM, replay, offline dictionary attack
  - Квантовий противник: "harvest now, decrypt later" (HNDL)
  - Композитний противник: має доступ до квантового оракула
- Вимоги до рішення:
  - R1: Збереження всіх властивостей безпеки OPAQUE
  - R2: Стійкість до квантових атак на ключовий обмін
  - R3: Мінімальне збільшення overhead (повідомлення, round-trips)
  - R4: Гібридна безпека ("AND" модель: зламати потрібно і класичну, і PQ частину)
  - R5: Сумісність із існуючою інфраструктурою (кількість повідомлень = 3)

**4.2 Формальні визначення (~1 стор.)**
- Визначення гібридного aPAKE
- Модель безпеки: розширення UC-security для OPAQUE з PQ-складовою
- Нотація та позначення для подальшого викладу

### 5. Запропонований протокол: Hybrid PQ-OPAQUE (~8 стор.) ⟵ ОСНОВНА ЧАСТИНА

**5.1 Архітектура та огляд (~1.5 стор.)**
- Загальна схема (діаграма потоку повідомлень)
- Криптографічні примітиви:

  | Компонент | Примітив | Бібліотека | Призначення |
  |-----------|----------|------------|-------------|
  | Група | Ristretto255 | libsodium | OPRF, DH |
  | KEM | ML-KEM-768 | liboqs | PQ-захист |
  | KSF | Argon2id | libsodium | Розтягування пароля |
  | MAC | HMAC-SHA512 | libsodium | Взаємна автентифікація |
  | AEAD | XChaCha20-Poly1305 | libsodium | Шифрування envelope |
  | KDF | HKDF-SHA512 | libsodium | Деривація ключів |

- Константи та розміри повідомлень (таблиця)
- Система доменних розділювачів (domain separation labels)

**5.2 Фаза реєстрації (~1.5 стор.)**
- Крок 1: Клієнт → OPRF Blind
  - `credential_request = Blind(secure_key)` (Ristretto255)
  - Генерація статичної ключової пари `(initiator_private, initiator_public)`
- Крок 2: Сервер → OPRF Evaluate
  - Деривація OPRF-ключа: `oprf_key = DeriveOPRFKey(server_secret, account_id)`
  - `evaluated_element = ScalarMult(oprf_key, credential_request)`
  - Відповідь: `registration_response = evaluated_element || server_public_key`
- Крок 3: Клієнт → Finalize + Envelope
  - OPRF Finalize → `oprf_output`
  - `randomized_pwd = Argon2id(H(context || oprf_output || secure_key), salt)`
  - `envelope_key = HKDF-Expand(HKDF-Extract(salt, randomized_pwd), "EnvelopeKey")`
  - `envelope = Seal(envelope_key, server_pub || client_priv || client_pub)`
  - `registration_record = envelope || initiator_public_key`
- Діаграма послідовності (sequence diagram)

**5.3 Фаза автентифікації: гібридний ключовий обмін (~3.5 стор.)** ⟵ ЯДРО НОВИЗНИ
- **KE1: Ініціатор → Респондер**
  - OPRF Blind: `credential_request = Blind(secure_key)`
  - Ефемерна EC пара: `(eph_priv, eph_pub) ← KeyGen(Ristretto255)`
  - ML-KEM-768 пара: `(kem_pk, kem_sk) ← ML-KEM.KeyGen()`
  - Випадковий nonce: `nonce ← Random(24)`
  - Повідомлення: `KE1 = credential_request || eph_pub || nonce || kem_pk` (1272 байт)

- **KE2: Респондер → Ініціатор**
  - OPRF Evaluate → `evaluated_element`
  - Ефемерна EC пара: `(resp_eph_priv, resp_eph_pub) ← KeyGen(Ristretto255)`
  - **Класичний 3DH:**
    - `dh1 = ScalarMult(resp_static_priv, init_static_pub)`
    - `dh2 = ScalarMult(resp_static_priv, init_eph_pub)`
    - `dh3 = ScalarMult(resp_eph_priv, init_static_pub)`
  - **ML-KEM Encapsulation:**
    - `(kem_ct, kem_ss) ← ML-KEM.Encaps(kem_pk)`
  - **Гібридне комбінування (НАУКОВА НОВИЗНА):**
    - `ikm_classical = dh1 || dh2 || dh3` (96 байт)
    - `ikm_combined = ikm_classical || kem_ss` (128 байт)
    - `transcript = H("TranscriptContext" || init_eph_pub || resp_eph_pub || init_nonce || resp_nonce || init_static_pub || resp_static_pub || cred_response || kem_pk || kem_ct)`
    - `salt = "PqCombinerContext" || transcript`
    - `PRK = HKDF-Extract(salt, ikm_combined)`
    - `session_key = HKDF-Expand(PRK, "PQ-v1/SessionKey", 64)`
    - `master_key = HKDF-Expand(PRK, "PQ-v1/MasterKey", 32)`
    - `resp_mac_key = HKDF-Expand(PRK, "PQ-v1/ResponderMAC", 64)`
    - `init_mac_key = HKDF-Expand(PRK, "PQ-v1/InitiatorMAC", 64)`
  - `resp_mac = HMAC-SHA512(resp_mac_key, transcript)`
  - Повідомлення: `KE2 = resp_nonce || resp_eph_pub || cred_response || resp_mac || kem_ct` (1376 байт)

- **KE3: Ініціатор → Респондер**
  - OPRF Finalize → envelope open → відновлення ключів
  - Дзеркальне обчислення 3DH + ML-KEM Decapsulation
  - Гібридне комбінування (ідентичне серверу)
  - Перевірка `resp_mac`
  - `init_mac = HMAC-SHA512(init_mac_key, transcript)`
  - Повідомлення: `KE3 = init_mac` (64 байт)

- **Завершення (Server Finish):**
  - Перевірка `init_mac`
  - Обидві сторони мають ідентичні `session_key` та `master_key`

- Повна діаграма протоколу (figure)
- Таблиця порівняння розмірів повідомлень: класичний OPAQUE vs. Hybrid PQ-OPAQUE

**5.4 Система доменних розділювачів (~0.5 стор.)**
- 12 класичних міток + 6 постквантових міток
- Обґрунтування: collision resistance, domain separation
- Перехід між контекстами `ECLIPTIX-OPAQUE-v1/*` та `ECLIPTIX-OPAQUE-PQ-v1/*`

**5.5 Механізм захисту пам'яті (~1 стор.)**
- SecureBuffer: page-aligned, mlock'd пам'ять
- SecureAllocator: кросплатформна реалізація (VirtualLock / mlock)
- Гарантована зеронізація через sodium_memzero
- Захист від swap-атак та cold boot attacks
- Constant-time порівняння MAC (crypto_verify_64)

### 6. Аналіз безпеки (~5 стор.)

**6.1 Формальний аналіз властивостей безпеки (~2 стор.)**
- **Теорема 1 (Password Secrecy):** Скомпрометований сервер не може відновити пароль
  - Доведення: OPRF з Ristretto255 забезпечує, що сервер бачить лише blinded елемент; envelope зашифрований ключем, що залежить від пароля через Argon2id
  - ML-KEM не впливає на password secrecy (пароль не входить до KEM)

- **Теорема 2 (Forward Secrecy):** Компрометація довгострокових ключів не розкриває минулі сесії
  - Доведення: ефемерні DH (dh2, dh3) + ефемерний ML-KEM keypair; PRK залежить від ефемерного матеріалу обох сторін
  - Hybrid forward secrecy: достатньо, щоб хоча б одна складова (EC або KEM) зберігала ефемерність

- **Теорема 3 (Mutual Authentication):** Обидві сторони автентифіковані
  - Доведення: MAC на основі PRK, що включає статичні ключі обох сторін + транскрипт з усіма публічними елементами (включаючи kem_pk та kem_ct)

- **Теорема 4 (Hybrid Security — "AND" model):** Для зламу потрібно подолати І класичну, І PQ складову
  - Доведення: PRK = HKDF-Extract(salt, dh1||dh2||dh3||kem_ss); HKDF-Extract з HMAC-SHA512 є PRF; якщо хоча б один з входів (класичний IKM або kem_ss) є випадковим, PRK є псевдовипадковим

**6.2 Аналіз стійкості до відомих атак (~2 стор.)**
- **Offline dictionary attack:** OPRF + Argon2id (незмінно від класичного OPAQUE)
- **Online dictionary attack:** out of scope (application-level rate limiting)
- **Man-in-the-Middle:** 3DH + KEM + transcript binding → MAC verification fails
- **Replay attack:** nonce + ephemeral keys + kem_pk freshness
- **Harvest Now Decrypt Later (HNDL):** ML-KEM-768 (Module-LWE, NIST Level 3)
- **Key Compromise Impersonation (KCI):** аналіз впливу компрометації static key
- **Side-channel attacks:** делегування до libsodium/liboqs (constant-time implementations)
- **Tampering detection:** bit-flipping на KE1/KE2/KE3 → MAC verification failure

**6.3 Порівняння з існуючими гібридними підходами (~1 стор.)**

| Властивість | TLS 1.3 Hybrid | Signal PQXDH | WireGuard PQ | **Hybrid PQ-OPAQUE** |
|-------------|----------------|--------------|--------------|---------------------|
| Тип протоколу | Key Exchange | Ratcheting | VPN Tunnel | **aPAKE** |
| Парольна автентифікація | Ні | Ні | Ні | **Так** |
| OPRF (password hiding) | Ні | Ні | Ні | **Так** |
| Forward secrecy | Так | Так | Так | **Так** |
| PQ KEM | Kyber/ML-KEM | ML-KEM | McEliece | **ML-KEM-768** |
| Hybrid model | OR | AND | AND | **AND** |
| Серверна сторона не бачить пароль | N/A | N/A | N/A | **Так** |
| Round-trips | 1 RTT | Async | 1 RTT | **1.5 RTT (3 msg)** |

### 7. Реалізація та експериментальна оцінка (~3.5 стор.)

**7.1 Архітектура реалізації (~1 стор.)**
- C++23 реалізація, кросплатформна (macOS, Linux, Windows, iOS, Android)
- Залежності: libsodium 1.0.20+, liboqs 0.12.0+
- Модульна архітектура: core → initiator/responder → interop (C API, JNI, .NET, Swift)
- Hardening: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, RELRO, ASLR
- Тестування: Catch2 v3.4.0, покриття: реєстрація, автентифікація, tampering

**7.2 Оцінка продуктивності (~1.5 стор.)**
- **Overhead розмірів повідомлень:**

  | Повідомлення | Класичний OPAQUE | Hybrid PQ-OPAQUE | Overhead |
  |-------------|------------------|------------------|----------|
  | KE1 | 88 байт | 1272 байт | +1184 (kem_pk) |
  | KE2 | 288 байт | 1376 байт | +1088 (kem_ct) |
  | KE3 | 64 байт | 64 байт | 0 |
  | **Сума** | **440 байт** | **2712 байт** | **+2272 (+516%)** |

- Аналіз: overhead повністю зумовлений розмірами ML-KEM-768 pk/ct; кількість round-trips не змінюється (залишається 3 повідомлення / 1.5 RTT)
- Обчислювальна складність: порівняння часу для реєстрації та автентифікації
  - 3x DH (Ristretto255) ~0.1ms
  - ML-KEM KeyGen + Encaps/Decaps ~0.05ms
  - Argon2id (MODERATE) ~500ms-3s (домінуючий компонент — не змінюється)
  - Висновок: overhead ML-KEM є незначним порівняно з Argon2id
- Бенчмарки на різних платформах (таблиця)

**7.3 Оцінка безпеки реалізації (~1 стор.)**
- Аналіз memory safety: SecureBuffer, zeroization coverage
- Аналіз побічних каналів: constant-time операції
- Результати статичного аналізу коду
- Валідація вхідних даних: перевірка Ristretto255 точок, розмірів повідомлень
- Обмеження: debug logging в dev-режимі, відсутність формальної верифікації

### 8. Обговорення (~1.5 стор.)
- Обговорення результатів у контексті поставлених вимог (R1-R5)
- Обмеження запропонованого підходу:
  - Протокол є "OPAQUE-like", не претендує на повну відповідність IETF draft
  - ML-KEM-768 збільшує розмір повідомлень на ~2.3 КБ
  - Відсутність formal verification (Tamarin/ProVerif)
  - Залежність від коректності libsodium/liboqs
- Напрямки подальших досліджень:
  - Формальна верифікація в моделі ProVerif/Tamarin
  - Інтеграція ML-DSA для підпису замість MAC
  - Оптимізація для IoT (менші PQ-параметри: ML-KEM-512)
  - Стандартизація PQ-OPAQUE в рамках IETF CFRG

### 9. Висновки (~1 стор.)
- Підсумок наукової новизни
- Основні результати:
  1. Розроблено гібридну конструкцію PQ-OPAQUE з ML-KEM-768
  2. Доведено збереження всіх класичних властивостей безпеки
  3. Показано, що overhead (2.3 КБ на автентифікацію) є прийнятним
  4. Реалізовано кросплатформну бібліотеку C++23
- Практична значимість: готове рішення для transition до постквантової автентифікації

### 10. Список використаних джерел (~2 стор., ~30-40 посилань)

**Ключові джерела:**
1. Jarecki, S., Krawczyk, H., Xu, J. "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks." EUROCRYPT 2018.
2. IETF Draft: draft-irtf-cfrg-opaque — The OPAQUE Augmented PAKE Protocol
3. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM), August 2024
4. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
5. Krawczyk, H. "HMQV: A High-Performance Secure Diffie-Hellman Protocol." CRYPTO 2005.
6. Bellare, M., Pointcheval, D., Rogaway, P. "Authenticated Key Exchange Secure Against Dictionary Attacks." EUROCRYPT 2000.
7. Bellovin, S.M., Merritt, M. "Encrypted Key Exchange." ACM CCS 1992.
8. Abdalla, M., Pointcheval, D. "Simple Password-Based Encrypted Key Exchange Protocols." CT-RSA 2005.
9. Canetti, R. "Universally Composable Security." FOCS 2001.
10. Krawczyk, H., Eronen, P. "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." RFC 5869.
11. Biryukov, A., Dinu, D., Khovratovich, D. "Argon2: New Generation of Memory-Hard Functions for Password Hashing." Euro S&P 2016.
12. Hamburg, M. "Decaf: Eliminating Cofactors Through Point Compression." CRYPTO 2015.
13. de Valence, H., et al. "Ristretto: A Technique for Constructing Prime-Order Groups." IETF draft.
14. Avanzi, R., et al. "CRYSTALS-Kyber: Algorithm Specifications and Supporting Documentation." NIST PQC Round 3.
15. Stebila, D., Mosca, M. "Post-quantum key exchange for the Internet and the Open Quantum Safe project." SAC 2016.
16. Bindel, N., et al. "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange." PQCrypto 2019.
17. Schwabe, P., Stebila, D., Wiggers, T. "Post-Quantum TLS Without Handshake Signatures." ACM CCS 2020.
18. Brendel, J., Fischlin, M., Günther, F., Janson, C., Stebila, D. "Towards Post-Quantum Security for Signal's X3DH Handshake." SAC 2020.
19. Denis, F. "libsodium: A Modern and Easy-to-Use Crypto Library." https://libsodium.org
20. Open Quantum Safe Project. "liboqs: C library for prototyping and experimenting with quantum-resistant cryptography." https://openquantumsafe.org

---

## Візуальні матеріали (figures/tables)

### Figures (планується ~8-10):
1. **Fig. 1** — Загальна архітектура Hybrid PQ-OPAQUE (блок-схема)
2. **Fig. 2** — Потік реєстрації (sequence diagram)
3. **Fig. 3** — Потік автентифікації з ML-KEM (sequence diagram) ← ключова
4. **Fig. 4** — Структура гібридного комбінатора ключів (HKDF tree)
5. **Fig. 5** — Формат повідомлень KE1, KE2, KE3 (wire format diagram)
6. **Fig. 6** — Структура Envelope (nonce || ciphertext || auth_tag)
7. **Fig. 7** — Модель загроз (threat model diagram)
8. **Fig. 8** — Порівняння overhead: класичний OPAQUE vs. PQ-OPAQUE (bar chart)
9. **Fig. 9** — Час виконання фаз протоколу (benchmark chart)
10. **Fig. 10** — Архітектура реалізації (модульна діаграма)

### Tables (планується ~6-8):
1. **Table 1** — Порівняння PAKE-протоколів (SRP, SPAKE2, OPAQUE, PQ-OPAQUE)
2. **Table 2** — Криптографічні примітиви та їх параметри
3. **Table 3** — Константи та розміри повідомлень
4. **Table 4** — Доменні розділювачі (labels)
5. **Table 5** — Overhead повідомлень: класичний vs. гібридний
6. **Table 6** — Порівняння з іншими гібридними підходами (TLS, Signal, WG)
7. **Table 7** — Бенчмарки продуктивності
8. **Table 8** — Аналіз виконання вимог безпеки

---

## Розподіл сторінок (підсумок)

| Розділ | Сторінки | % |
|--------|----------|---|
| Анотація | 0.5 | 2% |
| 1. Вступ | 2.5 | 8% |
| 2. Аналіз літератури | 4.5 | 15% |
| 3. Постановка задачі | 2.0 | 7% |
| 4. Запропонований протокол | 8.0 | 27% |
| 5. Аналіз безпеки | 5.0 | 17% |
| 6. Реалізація та експерименти | 3.5 | 12% |
| 7. Обговорення | 1.5 | 5% |
| 8. Висновки | 1.0 | 3% |
| Список джерел | 1.5 | 5% |
| **Разом** | **~30** | **100%** |

---

## Порядок написання (рекомендований)

1. **Розділ 5** (Протокол) — спочатку, оскільки це ядро статті
2. **Розділ 6** (Аналіз безпеки) — відразу після протоколу
3. **Розділ 3** (Літературний огляд) — з усвідомленням, що саме порівнювати
4. **Розділ 4** (Постановка задачі) — формалізація після розуміння рішення
5. **Розділ 7** (Реалізація) — на основі існуючого коду
6. **Розділ 2** (Вступ) — коли вся картина зрозуміла
7. **Розділ 8** (Обговорення + Висновки) — фінальний штрих
8. **Розділ 1** (Анотація) — останнім, як стисле резюме

---

## Важливі зауваження

### Щодо наукової новизни:
- Основний акцент: **конструкція гібридного комбінатора** (combine_key_material) та **розширений транскрипт** з PQ-елементами
- Новизна НЕ в окремих примітивах (Ristretto255, ML-KEM-768 — відомі), а в їх **композиції в рамках aPAKE**
- У відкритій літературі немає стандартизованого гібридного PQ-OPAQUE — це gap, який заповнює стаття

### Щодо обмежень (чесно вказати):
- Протокол "OPAQUE-like", не повністю відповідає IETF draft
- Формальна верифікація (Tamarin/ProVerif) не проведена — це future work
- Безпека побічних каналів делегована бібліотекам
- Немає детермінованих тест-векторів для відтворюваності

### Щодо стилю:
- Мова: визначити (українська / англійська) залежно від цільового видання
- Формат: залежить від журналу/конференції (IEEE, ACM, Springer LNCS)
- Математична нотація: використовувати стандартну криптографічну нотацію
