# PLAN — PHASE 2 (§8.2) — Run WJoOf

- **Protocol**: AGENTS.md — PHASE 2 PLAN (no edits, no tests, no subagents; single-authored)
- **Inputs**: §8.1 AUDIT REPORT (`docs/AUDIT_REPORT_PHASE1_WJOOF.md`) + read-only factual checks
- **Scope mandate (human)**: โฟกัสแก้ระบบ LLM เท่านั้น (Wiring, Gate, Validator, Auxiliary Logic) — ห้ามแตะ scanner / container / MSF execution (มนุษย์กำลังรัน Pipeline WJoOf ใหม่ใน terminal แยก)
- **Verification mandate (human)**: Replay จาก artifact `WJoOf` เก่าเท่านั้น — ห้ามรัน Pipeline ใหม่
- **Status**: AWAITING APPROVAL

---

## P1 — Hypothesis

**Bottleneck ถัดไป = provider** (ไม่ใช่ gate แล้ว)

- gate/wiring fix (A) **ทำงานจริงใน production**: artifact จากรันที่มนุษย์กำลังรัน (อ่าน read-only) `output/resolver/guidance/llm_guidance_2026-10-24_Tz4d6.json` แสดง `status: OUTCOMES_RECORDED`, `outcome_count: 3`, `diagnostics: 27` (ทุกตัว `CVE_STATUS_NO_MSF_MODULE`) → `schedule_field_guidance` path ผ่าน gate ถึง provider แล้ว (บทสรุป §8.1.9 ที่ว่า "ไม่เคยถึง provider" เป็นข้อเท็จจริงของรัน WJoOf เท่านั้น — ตอนนี้มีหลักฐานใหม่)
- แต่ provider leg ล้มเหลวทั้ง 3 CVE ด้วย `TimeoutError: The read operation timed out` (timeout 45s, model `gemini-3.8-flash`) — เป็น **provider-level failure ใหม่ ต่างจาก 503 เดิม** (§2.3 ยัง UNKNOWN ไม่มีหลักฐานใน repo)
- บั๊ก (B) auxiliary payload/protocol เป็นคนละ bucket (form/config consistency) — แก้อิสระจากการแก้ (A)

**สรุปแผน**: พิสูจน์ (A) ด้วย replay (zero-code) → แก้ (B) → ตรวจสอบ (B) ด้วย replay ชุดเดียวกัน

**หลักฐาน**: `llm_guidance_2026-10-24_Tz4d6.json` (outcome_count=3, TimeoutError ×3); §8.1.7 ข้อ 9-10; §8.1.8 U1/U4; `resolver/config.py:385` vs `:452-453`; `submission.py:296-298`; `artifacts.py:119-124`; `mode` มี consumer แค่ `artifacts.py:121` + `submission.py:279-290`; `payload.required` มี consumer แค่ `artifacts.py:108` + `submission.py:298` (ไม่มีผลต่อ executor)

---

## P2 — Minimal change set (exact files + functions)

### (A) Wiring — เปลี่ยนโค้ด = ศูนย์ (zero-code)

| # | File / function | เหตุผล (one-line) |
|---|---|---|
| A1 | `tools/replay_wjoof_guidance.py` — **NEW FILE**: snapshot + SHA-256 check, artifact→object reconstruction ผ่าน `src/kalama/resolution/config_codec.py` (`exploit_config_from_dict`, `_candidate`), เรียก `schedule_field_guidance`, modes `--gate-only` / `--smoke` / `--full` / `--aux-check`, เขียนผลลง `output/replay/wjoof_replay_2026-10-24/` เท่านั้น | ตรวจสอบ (A) จาก artifact เก่าเท่านั้น (ไม่รัน pipeline) และไม่เขียนทับไฟล์ใด ๆ |
| A2 | `llm_fields.py` / `orchestrator.py` / `runtime.py` — **NOT in change set** (fix อยู่ใน working tree แล้ว; แผนนี้ตรวจสอบอย่างเดียว) | กันแก้เกินจำเป็น; commit เฉพาะถ้ามนุษย์สั่ง (ดู S7) |

### (B) Auxiliary payload/protocol — แก้ 3 ไฟล์ + 2 ไฟล์ทดสอบ

| # | File / function | การแก้ | เหตุผล |
|---|---|---|---|
| B1 | `src/kalama/resolver/config.py` | ยก `requires_payload = protocol.run_exploit and not module_path.startswith("auxiliary/")` (`:385`) เป็น helper `_requires_payload()` แล้วใช้ร่วมกันที่ `validate_exploit_config` (`:385`) **และ** `build_exploit_config` payload `ExploitValue(required=...)` (`:452-453`) | §8.1.7 ข้อ 9: form ต้องไม่ขัด validator — single source of truth |
| B2 | `src/kalama/resolution/submission.py` | (i) เงื่อนไข `if run_exploit: payload.required=True` (`:296-298`) ต้องกัน auxiliary ด้วย helper เดียวกัน; (ii) เพิ่ม branch mode `run-only` → `(run_check, run_exploit) = (False, True)` และ `check-then-run` → `(True, True)` (ค่า boolean เดิมเป๊ะ) โดย**คง branch `exploit-only` เดิมไว้** | ข้อ 9 (force ซ้ำหลัง human confirm) + ข้อ 10 (round-trip ยอมรับ label ใหม่) + backward-compatible กับ form เก่าที่ human เพิ่ง generate |
| B3 | `src/kalama/resolution/artifacts.py` | mode derivation (`:119-124`): เมื่อ selected module (`value or suggested_value`) ขึ้นต้น `auxiliary/` → label `run-only` (ไม่มี check) / `check-then-run` (`run_check=True`) แทน exploit- labels | §8.1.7 ข้อ 10: label ต้องไม่โกหกว่าเป็น scanner — **display + ingestion เท่านั้น ไม่แตะ boolean ที่ feed executor** |
| B4 | `tests/unit/test_resolver_config.py` (extend) | test: auxiliary → `payload.required==False` + validate ไม่ออก `PAYLOAD_SELECTION_REQUIRED`; exploit module → `required=True` (regression จาก test `:194`) | ปกป้อง invariant ของ B1 |
| B5 | `tests/integration/test_attack_form_submission.py` (extend; fixture-only, mock backend — baseline ก่อน) | test: mode ใหม่ submit ได้และให้ boolean เดิม; label เก่า `exploit-only` ยังใช้ได้; auxiliary payload ไม่ถูก force required | ปกป้อง B2/B3 round-trip |

**เหตุผลที่เลือกไฟล์เหล่านี้เท่านั้น**: `mode` มี consumer แค่ `artifacts.py:121` (เขียน) กับ `submission.py:279-290` (อ่าน); `payload.required` มี consumer แค่ `artifacts.py:108` (แสดง) + `submission.py:298` (force) — **ไม่มีผลต่อ executor** (`execution/*` อ่านแค่ `payload.value` / `run_exploit` ซึ่งไม่ถูกแก้)

---

## P3 — Explicit non-goals

1. ไม่แตะ scanner / target / verification / execution / docker / metasploit / dispatcher (ขอบเขตงานมนุษย์) — โดยเฉพาะ**ไม่แก้ `_build_execution_protocol`** (`resolver/config.py:196-207`) เพราะ `run_exploit` feed `execution/attempt.py:188-242` และ `oracle.py` = พฤติกรรม MSF
2. ไม่รัน pipeline ใหม่ ไม่ re-scan ไม่ restart container ไม่ execute MSF — verification = replay จาก artifact WJoOf เก่า + unit tests เท่านั้น
3. ไม่เขียน/แก้ `output/resolver/**`, `output/state/**` — อ่าน + snapshot เขียนลง `output/replay/` (dir ใหม่) เท่านั้น
4. ไม่ commit ใด ๆ (รวมทั้งไฟล์ wiring) — เฉพาะถ้ามนุษย์สั่งแจ้ง (S7)
5. ไม่แก้ model / base_url / timeout ใน config — S2 ใช้ `.env` ปัจจุบันตามเดิม; ถ้าจะทดสอบ model อื่น = stop-and-ask (T3)
6. ไม่แก้ validator / gate / whitelist / budget policy — S3 ถ้าเจอ `finish_reason=length` = รายงานอย่างเดียว ขอ approval แยก
7. ไม่แตะไฟล์ที่ human กำลังแก้อยู่: `desktop/*`, `doctor.py`, `README.md`, `.env.example`, `.gitignore`, `tools/viper_evidence_viewer.py`, `.env`
8. ไม่แก้ silent-skip diagnostics (§8.1.3 B3) และไม่แก้ `session_confirmation_expected=run_exploit` quirk (`submission.py:292`) — บันทึกเป็น observation เท่านั้น
9. **ห้ามใช้ `git checkout` / `git restore` / `git reset` กับไฟล์ใด ๆ เด็ดขาด** — จะทำลาย wiring fix ที่ยัง uncommitted + งาน human ที่ uncommitted

---

## P4 — Step order (incremental; ทุก step จบด้วย §8.3 แล้ว PAUSE)

### S0 — Baseline & snapshot (read-only + เขียนลง `/tmp/opencode/phase3-backup/` เท่านั้น)
- คำสั่ง:
  - 4 unit files: `./.venv/bin/python -m unittest tests.unit.test_openai_compatible tests.unit.test_guidance tests.unit.test_resolver_llm_field_scheduling tests.unit.test_resolver_llm_candidate_binding` → คาด `Ran 29 / OK`
  - `tests.unit.test_resolver_config` → นับ baseline
  - `tests.integration.test_attack_form_submission` → นับ baseline (ถ้ามีการเรียก external จริง → STOP)
  - `git status --porcelain` เก็บ baseline
  - SHA-256 backup ไฟล์เป้าหมาย 5 ไฟล์ → `/tmp/opencode/phase3-backup/`
  - copy `output/resolver/resolver_2026-10-24_WJoOf.json` + `output/state/run_WJoOf.json` → `output/replay/wjoof_replay_2026-10-24/input/` แล้ว assert SHA ตรง `8f491ba2b3eadcbf01014eef970aa2840c529a871a40f863c1a91c6ef45a0c83` (จาก guidance artifact L8) กัน human ทับ
- Expected: 29 OK; snapshot SHA match; baseline counts บันทึกแล้ว
- (การรันเทสต์ baseline นี้เป็นการดำเนินการใน Phase 3 เท่านั้น — ไม่ใช่ตอนนี้)

### S1 — สร้าง harness (new file) + gate replay offline
- คำสั่ง: `./.venv/bin/python tools/replay_wjoof_guidance.py --gate-only` (ไม่ใช้ network: provider=None)
- Expected: `outcome_count=3` (CVE-2019-2215, CVE-2019-13272, CVE-2017-9798 ผ่าน `has_useful_evidence`) + `diagnostics=27` `CVE_STATUS_NO_MSF_MODULE` + round-trip assert ของ reconstruction ผ่านหมด → **ยืนยัน (A) จาก artifact เก่า**
- ถ้า outcome ≠ 3 หรี่ reconstruction assert fail → **X2 STOP + เข้า re-audit เฉพาะจุดนั้น**

### S2 — Provider smoke (isolated)
- คำสั่ง: `--smoke` (post เดียวถึง `base_url` จาก `.env`, model `gemini-3.8-flash`, ไม่เขียนไฟล์ config ใด ๆ)
- Expected: PASS = HTTP 200 + parsed JSON + `finish_reason ∈ {stop, end_turn}`; บันทึก elapsed / status / usage
- FAIL ทุกกรณี (TimeoutError หลัง bounded retry / 503) → รายงาน **provider-level FAIL** (§8.3) แล้วไปต่อ S3 — ห้ามแก้ pipeline ให้หลบ (X5); ถ้าจะลอง model/URL อื่น → STOP ขอ approval (T3)

### S3 — Full replay (gate + provider + validator)
- คำสั่ง: `--full`
- Expected: 3 outcomes; แยกบรรทัดชัดเจน 3 buckets:
  - **provider leg**: status / finish_reason / usage / model ที่ใช้จริง
  - **gate leg**: per-CVE เหตุผล (diagnostics)
  - **validator leg**: `validation_state` + issues ต่อ CVE ถ้า proposal ถึง validator; ถ้า provider fail → `UNAVAILABLE` และ validator = N/A — ห้ามปน (§0.6)
- divergence ที่ต้องบันทึก: `knowledge_guidance={}` (ไม่มี knowledge dir สำหรับ WJoOf — ตรวจแล้ว) และ `KALAMA_GUIDANCE_CVES` ต้องว่าง

### S4 — Bug B step 1: `resolver/config.py` + B4 tests
- แก้ตาม B1 + เพิ่ม test ตาม B4
- Verify: `./.venv/bin/python -m unittest tests.unit.test_openai_compatible tests.unit.test_guidance tests.unit.test_resolver_llm_field_scheduling tests.unit.test_resolver_llm_candidate_binding tests.unit.test_resolver_config`
- Expected: `Ran (29+N) … OK` — ถ้า 4 เดิม fail → revert (P6) + re-audit

### S5 — Bug B step 2 (atomic pair): `artifacts.py` + `submission.py` + B5 tests
- **ก่อน step นี้: primary แจ้งมนุษย์สั้น ๆ ว่ากำลังแก้ไฟล์ form-layer** (ทั้งคู่แก้พร้อมกันใน step เดียว = ไม่มีหน้าต่างเวลาที่ form ใหม่เข้า submission เก่า; label เก่า `exploit-only` ยังรับได้เสมอ → form ที่ human เพิ่ง generate ใช้ได้ทั้งก่อน-หลังแก้)
- Verify: 4 files + `test_resolver_config` + `test_attack_form_submission` เทียบ baseline S0
- Expected: OK ทั้งหมด; mode ใหม่ round-trip ได้, mode เก่าไม่ถูกตัด

### S6 — Bug B verification จาก artifact WJoOf
- คำสั่ง: `--aux-check` (rebuild `build_exploit_config` สำหรับ 3 CVE จาก snapshot + `target_facts_from_state` โดยใช้โค้ดหลัง S4-S5)
- Expected:
  - CVE-2017-9798 → `payload.required==False` + mode `run-only`
  - CVE-2019-2215 → `payload.required==True` (regression, exploit module)
  - CVE-2019-13272 → `payload.required==False` (เดิมก็ False: mode check-only)
  - ทั้งหมดเทียบกับค่าใน `attack_form_WJoOf_r1.yaml` เก่า **โดยไม่เขียนทับมัน**
- จบด้วยรัน 4 files อีกครั้ง (X4)

### S7 (conditional — เฉพาะถ้ามนุษย์สั่ง) — commit
- fileList จำกัด: `src/kalama/resolution/llm_fields.py`, `src/kalama/resolution/orchestrator.py`, `src/kalama/runtime.py`, `src/kalama/guidance/__init__.py`, `src/kalama/guidance/openai_compatible.py`, `tests/unit/test_openai_compatible.py`, `tests/unit/test_resolver_llm_field_scheduling.py` + ไฟล์ Bug B (B1-B5) + `tools/replay_wjoof_guidance.py`
- **ไม่มีการ commit ในแผนเวอร์ชันนี้ 除非สั่งแจ้ง**

---

## P5 — Test plan

- **Invariant ทุกครั้งหลังแก้ (X4)**: 4 ไฟล์ = `Ran 29 / OK` (test ใหม่ทั้งหมดอยู่นอก 4 ไฟล์นี้ เพื่อให้ 29 เป็น invariant)
- **Baseline-then-compare**:
  - `tests.unit.test_resolver_config` — มี test `:194` `test_exploit_protocol_requires_payload_but_confirmed_check_only_does_not` ที่ต้องยังผ่าน (B1 ห้ามเปลี่ยนพฤติกรรม exploit module)
  - `tests.integration.test_attack_form_submission` — 20 tests, mock backend; ถ้า baseline มี fail อยู่แล้ว เทียบเฉพาะ regression
- **Behavioral verification = replay** (S1 / S3 / S6) — ไม่มีการรัน pipeline ใหม่
- **Test ใหม่**: B4 (payload rule) + B5 (mode round-trip)
- ห้าม: network นอกจาก provider leg ของ S2/S3, docker, MSF

---

## P6 — Rollback

- S0 เก็บ SHA-256 copy ของไฟล์เป้าหมายไว้ `/tmp/opencode/phase3-backup/` → ขั้นไหน FAIL คืนเฉพาะไฟล์ของ step นั้นจาก backup แล้วรัน 4 files ยืนยัน `Ran 29 / OK` แล้วเข้า re-audit
- ไฟล์ใหม่ (`tools/replay_wjoof_guidance.py`, `output/replay/`) ลบได้ทันที ไม่มีผลข้างเคียง
- **ห้าม `git checkout` / `git restore` / `git reset` เด็ดขาด** (จะลบ wiring fix + งาน human ที่ uncommitted)

---

## P7 — Approval gate

ขอบเขต: ระบบ LLM เท่านั้น — ไฟล์ที่จะแตะทั้งหมด:

| ประเภท | ไฟล์ |
|---|---|
| แก้ (Bug B) | `src/kalama/resolver/config.py`, `src/kalama/resolution/submission.py`, `src/kalama/resolution/artifacts.py` |
| ขยาย test | `tests/unit/test_resolver_config.py`, `tests/integration/test_attack_form_submission.py` |
| ใหม่ | `tools/replay_wjoof_guidance.py` (+ ผลใน `output/replay/` เท่านั้น) |
| ไม่แตะ (A) | `llm_fields.py`, `orchestrator.py`, `runtime.py` (คงไว้ ตรวจสอบอย่างเดียว) |
| ห้ามแตะ | scanner / target / verification / execution / docker / metasploit / dispatcher / `desktop/*` / `doctor.py` / `README.md` / `.env*` / `tools/viper_evidence_viewer.py` / `output/resolver/**` / `output/state/**` |

Verification ทุกครั้งอ้างอิง artifact WJoOf เก่าผ่าน snapshot ที่ SHA-verified — ไม่รัน pipeline ใหม่ ไม่ชนกับงานมนุษย์

---

**AWAITING APPROVAL — no code will be written until I receive APPROVED.**
