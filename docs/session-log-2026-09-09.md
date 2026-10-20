# บันทึกเซสชัน 2026-09-09 — BEFORE attribution fix + patch rounds (2d8ru/struts2)

> MIGRATION 2026-09-09: เคส `output-*/` ที่รูทย้ายเข้า `output/<case>/` แล้ว
> (เช่น `output-2d8ru-struts2-fullpipeline` -> `output/2d8ru-struts2-fullpipeline`)
> พาธในไฟล์ + sha256 ถูกซ่อมให้ตรง, สคริปต์/`.gitignore`/CLI help อัปเดตแล้ว
> คำสั่งประวัติข้างล่างยังแสดงพาธเดิมตามที่รันจริง ไม่ได้แก้ประวัติ

> เอกสารนี้รวบรวม: คำสั่งที่รันทั้งหมด, ผลลัพธ์, ตำแหน่งไฟล์artifact, และสถานะปัจจุบัน
> ข้อจำกัดที่ถือตลอดเซสชัน: ใช้โมเดลถูกสุด, ไม่ใช้ Astra/LLM (guidance ไม่เคยถูกเปิด),
> ไม่แก้ scanner/prioritizer/resolver/Attack-Form-schema/patch/evaluation/frontend,
> ไม่ลบ historical artifacts, ไม่แก้ RunState เอง

## 0. สถานะระบบ ณ เวลาบันทึก (สำคัญ)

- **containers หายไปเกือบหมด**: `docker ps` เหลือแค่ `msf-resolver-host`, `kalama-workbench-modern`
  (`docker ps -a` เหลือแค่ struts2-vuln/mysql-db ที่ Exited) — victim/after/patch-workspace
  ~25 ตัว (J1Thf, Ng16e, lkW2d, neZfP, M58zM, 5d93W, GyxMo, …) ถูกถอดออกไปแล้ว
  (ไม่ใช่ฝีมือเอเจนต์ — เอเจนต์ไม่เคยลบ container)
- **images ยังอยู่ครบ**: `2d8ru/struts2:latest` (7aa386b4b606),
  `kalama/struts2:patched-lkw2d` (2d2ad7db), `:patched-nezfp` (62d91a13),
  `:patched-m58zm` (1bf86f12), `:patched-gyxmo` (ffd62695ffa3)
- **state files อยู่ครบ** (`output-2d8ru-struts2-fullpipeline/state/*.json`)
- **run cQkOX ค้างที่สถานะ RUNNING/STEP_4_RESOLVER** (เกิดจาก `continue` ถูก abort กลางคัน
  ตามคำสั่งเบรกของผู้ใช้) — จะทำให้รันใหม่ติด `ACTIVE_RUN_CONFLICT` จนกว่าจะเคลียร์
  (ต้องแก้ state โดยตรง = ต้องขออนุมัติก่อน ยังไม่ได้ทำ)

## 1. Phase 1 — แก้ BEFORE session-attribution (root cause: ephemeral msfconsole)

### 1.1 ปัญหาเดิม (ยืนยันจากโค้ด + J1Thf artifact)
- `src/kalama/execution/attempt.py` เดิมเรียก `check()` → `exploit(run -z)` → `sessions()`
  เป็น **msfconsole คนละ process กัน 3 ครั้ง** (`executor.py`)
- reverse shell ตายพร้อม process แรก → inventory หลังได้ `[]` → 3 CVE ของ J1Thf
  (5638/9805 มี session opened จริง, 9791 มี command executed) ถูกจัดเป็น
  INCONCLUSIVE / CHECK_WITHOUT_ATTRIBUTABLE_IMPACT ทั้งหมด

### 1.2 ไฟล์ที่แก้ (4 ไฟล์ + เทสต์ใหม่ 1 ไฟล์; ไม่แตะ oracle.py/scanner/resolver)
- `src/kalama/execution/executor.py` (+447 บรรทัด): `run_attempt()` — msfconsole ครั้งเดียว
  (baseline listing → check → `run -z` → `sleep 7` → post listing, คั่นด้วย echo markers);
  `attribute_same_invocation()` (ต้องมี **ทั้ง** stdout `session opened` ตรง target+LHOST/LPORT
  **และ** listing ยืนยัน session id เดียวกัน, stdout-only ไม่นับ);
  `extract_command_impact()` แบบ conservative (ข้อความ `Command executed` ลอยๆ ไม่นับ);
  parser รองรับทั้งตาราง legacy และบล็อก verbose (`Session ID/Tunnel/Via`);
  `session_settle_seconds()` default 7s (env `KALAMA_SESSION_SETTLE_SECONDS`)
- `src/kalama/execution/attempt.py`: ใช้ `run_attempt()` ถ้ามี (fallback วิธีเดิมถ้าไม่มี),
  ส่ง impact เข้า oracle, เขียน `impact_evidence` เฉพาะเมื่อ COLLECTED
- `src/kalama/execution/orchestrator.py`, `src/kalama/reexploit/orchestrator.py`:
  ส่งผ่าน `session_settle_seconds`
- `tests/unit/test_same_invocation_attribution.py` (ใหม่, 12 เทสต์ ครอบคลุม 7 เคสที่สั่ง)

### 1.3 คำสั่งเทสต์ + ผล
- `.venv\Scripts\python -m unittest tests.unit.test_same_invocation_attribution
  tests.integration.test_before_exploit tests.unit.test_execution_session_attribution
  tests.unit.test_execution_fixture_support` → **35 tests, OK**
- `... -m unittest tests.integration.test_reexploit tests.integration.test_patch_planning
  tests.integration.test_evaluation` → **18 tests, OK**

### 1.4 Validation runs (fresh run, ไม่แตะ J1Thf)
- `kalama --output-root output-2d8ru-struts2-fullpipeline run --image 2d8ru/struts2`
  → `continue` (resolver) → `submit-attack-form` (mirror ตัวเลือกที่ approve ใน J1Thf:
  3 CVE + module/protocol/payload เดิม, LPORT ชุดใหม่, 13 skip) → `continue` (before)
- **Ng16e**: INCONCLUSIVE 3 ตัว (เจอ parser gap — `sessions -l -v -x` รีเทิร์นบล็อก verbose
  ไม่ใช่ตาราง) → แก้ parser → replay stdout จริงของ Ng16e ผ่านโค้ดใหม่ได้ TARGET_MATCH ทั้งคู่
- **lkW2d** (victim 172.18.0.18): **EXPLOIT_SUCCEEDED 2** (5638, 9805 / ATTRIBUTABLE_SESSION,
  eligible), INCONCLUSIVE 1 (9791) — ผ่านเกณฑ์ ≥2
  - ATTACK_BEFORE: `output-2d8ru-struts2-fullpipeline/msf/before/attack_res_2026-09-08_lkW2d.json`
    sha256 `9b9b5c85c6f0fbf9c11a7126f141cd4c8cce38ef7414109dda248e5d86190417`
- **J1Thf ไม่เปลี่ยนแปลง**: ยัง PAUSED/STEP_5_PATCH, INCONCLUSIVE 3 เหมือนเดิม

## 2. Phase 2 — Patch planning (lkW2d)

- `continue lkW2d` → patch_plan (auto discovery) → Patch Form 8 actions:
  patch-001..007 = struts2-core ต่างเวอร์ชันใน demo apps อื่น (2.3.1/2.3.14.2/2.3.15.1/
  2.3.20.1/2.3.24.1/2.3.30/2.5.10), patch-008 = rest-plugin 2.3.20.1 (5638+9805)
- สำรวจ victim (read-only): S2-045/S2-052 มีทั้ง exploded dir + WAR (WAR 2 ไฟล์ sha256
  ตรงกัน `0da0980f…436a5`, lib 26 ไฟล์เหมือนกันทุก byte), Tomcat 8.5.20/unpackWARs+autoDeploy,
  Java 1.8, baseline URLs (`/S2-045/`→302, `/S2-052/orders/3`→200)
- เป้าหมาย fix ร่วม: **Struts 2.3.34** (ปิด 5638 ที่ต้องการ ≥2.3.32 และ 9805 ที่ต้องการ ≥2.3.34,
  อยู่สาย 2.3.x); closure จาก `struts2-parent-2.3.34.pom`
- โหลด jar จาก `repo.maven.apache.org` อย่างเดียว + ตรวจ `.sha1` ทุกไฟล์ (ดู §5)
- `submit-patch-form lkW2d` (patch-004/008 = สลับ jar จริงใน 2 แอป;
  อีก 6 actions = scope-guard no-op ยืนยันว่าไม่แตะ) → `continue` (execution):
  **8/8 SUCCEEDED**, image `kalama/struts2:patched-lkw2d`, after-target 172.18.0.19

## 3. Patch rounds — สลับ jar ทีละชั้นตาม log (smoke test ตกทุกยก ยกเว้นยังไม่จบ)

| รอบ/รัน | ของใหม่ที่เพิ่ม | ผล smoke (after-target) | log-proven blocker ถัดไป |
|---|---|---|---|
| lkW2d att.1 | ชุด 2.3.34 5 ไฟล์ | 404/404 | `NoClassDefFoundError: xstream/security/TypePermission` (rest-plugin 2.3.34 vs xstream 1.4.2) |
| neZfP | + xstream-1.4.10 | 404/404 | `NoSuchMethodError: ognl.SimpleNode.isSequence` (xwork 2.3.34 vs ognl 3.0.6) |
| M58zM | + ognl-3.0.21 | 404/404 | `ClassNotFoundException: asm/commons/EmptyVisitor` ที่ `convention...buildClassFinder` (เจาะจงแล้วว่ามาจาก `xwork-core-2.3.34: DefaultClassFinder$InfoBuildingVisitor`; xwork POM ประกาศ `asm:asm`+`asm-commons` v3.3; มีแค่ xwork ที่ใช้ ASM) |
| 5d93W | (รอบเสีย — Docker daemon ค้างตอน exploit: check/exploit TIMEOUT + ENVIRONMENT_BINDING_STALE; BEFORE ออกมาเป็น NOT_EXECUTED/ENVIRONMENT_ERROR, ใช้ต่อไม่ได้) | — | ปัญหา infra ไม่ใช่แพตช์ |
| GyxMo | + asm-3.3/asm-commons-3.3, ถอด asm-5.0.2 | 404/404 | `NoSuchFieldError: VERSION_2_3_0` ที่ `FreemarkerManager.createConfiguration` (core 2.3.34 vs freemarker 2.3.19; ฟิลด์นี้มีตั้งแต่ 2.3.21 — closure บังคับ 2.3.22) |
| cQkOX | เริ่มรันใหม่แล้ว แต่ `continue` (resolver) **ถูก abort ตามคำสั่งเบรก** → ค้าง RUNNING | — | — |

ข้อพิสูจน์สำคัญระหว่างทาง: exploded lib ที่แพตช์แล้ว**ไม่ถูก WAR เขียนทับ** (ตรวจแล้วเป็นชุด 2.3.34 ล้วน),
`deployWAR` ใน log เป็น bookkeeping ของ Tomcat ตอน WAR กับ dir mtime เท่ากัน — ไม่มีการ merge jar เก่ากลับ

## 4. คำสั่ง Kalama ที่รันทั้งหมด (ตามลำดับ)

```
# รูปแบบทุกครั้ง: .venv\Scripts\python -m kalama --output-root output-2d8ru-struts2-fullpipeline <cmd>
run --image 2d8ru/struts2                      # J1Thf(เดิม), Ng16e, lkW2d, neZfP, M58zM, 5d93W, GyxMo, cQkOX
continue <run>                                  # ขั้น resolver / before-exploit / patch_plan / patch_execution
submit-attack-form <run> <draft>.yaml           # Ng16e, lkW2d(14811-13), neZfP(14911-13), M58zM(15111-13), 5d93W(15211-13), GyxMo(15311-13)
submit-patch-form <run> <draft>.yaml            # lkW2d r1, neZfP r1, M58zM r1, GyxMo r1
retry lkW2d --edit-plan                         # ถูกปฏิเสธ: PATCH_RETRY_NOT_FAILED (attempt 1 สำเร็จเชิงกลไก)
status <run>                                    # ตรวจสถานะหลายครั้ง
```
- สคริปต์ builder อยู่ใน `C:\Users\DISTOR~1\AppData\Local\Temp\opencode\`
  (`build_*_attack.py`, `build_*_patchform.py`, `fetch_*.py`)

## 5. Jar ที่โหลดจาก Maven Central (ตรวจ .sha1 ผ่านทุกไฟล์, เก็บใน Temp\opencode\fixed-jars-2.3.34)

| ไฟล์ | sha256 |
|---|---|
| struts2-core-2.3.34.jar | a988978e…91e9a66d |
| struts2-rest-plugin-2.3.34.jar | 9b36cd0b…068e1f1 |
| struts2-convention-plugin-2.3.34.jar | 2cc10761…6fa7b75 |
| struts2-config-browser-plugin-2.3.34.jar | 327ce754…cda4c26 |
| xwork-core-2.3.34.jar | 0812f06f…7efe835 |
| xstream-1.4.10.jar | a1587f35…40b00858 |
| ognl-3.0.21.jar | 9c5419fe…357c5f6 |
| freemarker-2.3.22.jar | 58502c0e…c25c1a9c |
| commons-fileupload-1.3.2.jar | 287d0b5b…25e04b25 |
| asm-3.3.jar | 07e685c3…1ac6a8da |
| asm-commons-3.3.jar | 1cc6e5bc…0ee96af |
| (อ้างอิง no-op) struts2-core-2.3.32.jar | 74261d1c…2be8f0 |
| (อ้างอิง no-op) struts2-core-2.5.10.1.jar | 62501827…2474bcad |

## 6. Artifacts หลัก (อยู่ใน output-2d8ru-struts2-fullpipeline/)

- ATTACK_BEFORE lkW2d: `msf/before/attack_res_2026-09-08_lkW2d.json` (`9b9b5c85…`)
- PATCH_RESULT: `patch/results/patch_result_2026-09-08_lkW2d_attempt_1.json` (`e137ff1a…`),
  `patch_result_2026-09-09_neZfP_attempt_1.json` (`5330e109…`),
  `patch_result_2026-09-09_M58zM_attempt_1.json` (`a9eda4bd…`)
- PATCH_FORM submissions: `patch/forms/submissions/patch_form_submission_{lkW2d,neZfP,M58zM,GyxMo}_r1.yaml`
- state: `state/run_{J1Thf,Ng16e,lkW2d,neZfP,M58zM,5d93W,GyxMo,cQkOX}.json`

## 7. สถานะรันทั้งหมดตอนนี้

| run | status | stage |
|---|---|---|
| J1Thf | PAUSED (ไม่แตะ) | STEP_5_PATCH |
| Ng16e | PAUSED | STEP_5_PATCH |
| lkW2d | PAUSED | STEP_6_AFTER_SCAN (patch att.1 จบ, smoke ตก) |
| neZfP | PAUSED | STEP_6_AFTER_SCAN (patch จบ, smoke ตก) |
| M58zM | PAUSED | STEP_6_AFTER_SCAN (patch จบ, smoke ตก) |
| 5d93W | PAUSED | STEP_5_PATCH (BEFORE เสียจาก Docker ค้าง — ใช้ต่อไม่ได้) |
| GyxMo | PAUSED | STEP_6_AFTER_SCAN (patch จบ, smoke ตกที่ freemarker) |
| cQkOX | **RUNNING ค้าง** | STEP_4_RESOLVER (continue ถูก abort) |

## 8. เรื่องที่ต้องตัดสินใจต่อ (ยังไม่ทำ รออนุมัติ)

1. **cQkOX ค้าง RUNNING** → บล็อก `ACTIVE_RUN_CONFLICT` สำหรับรันใหม่ทุกรัน;
   การปลดต้องแตะ state ไฟล์โดยตรง (ขัดคำสั่งเดิม) — ขออนุมัติก่อน
2. **รอบ freemarker-2.3.22** (log-proven แล้ว, jar โหลด+ตรวจแล้ว): ต้องรันใหม่ทั้งสาย
   (BEFORE ใหม่ + patch ใหม่) เพราะ retry ปิดสำหรับ attempt ที่สำเร็จเชิงกลไก
3. ยัง**ไม่เคยรัน** Trivy AFTER / re-exploit AFTER / evaluation เลย (ถูกห้ามไว้จนกว่า smoke จะผ่าน)
4. freemarker คือความหวังสุดท้ายของสายนี้ — ถ้ายัง 404 อีกด้วยสาเหตุใหม่ จะมารายงานต่อ
   (commons-fileupload ยังไม่มีหลักฐานว่าต้องเปลี่ยน)
