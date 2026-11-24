# Attack Form: Resolver, LLM Suggestion, and Human Confirmation Scope

## สถานะเอกสาร

เอกสารนี้กำหนด **ขอบเขตเป้าหมาย (target policy)** สำหรับการช่วยกรอก Attack Form
โดยแยกบทบาทของ Resolver, LLM และมนุษย์ออกจากกันอย่างชัดเจน

ข้อกำหนดสำคัญ:

- LLM ให้ได้เฉพาะ **คำแนะนำ (`suggested`)** พร้อมหลักฐานอ้างอิง
- LLM ห้ามเขียนค่า `confirmed`, ห้ามสร้าง `HUMAN_CONFIRMED` และห้าม submit form
- มนุษย์เป็นผู้ตรวจสอบและยืนยันขั้นสุดท้ายเสมอ
- Resolver และ validator ต้องทำงานแบบ deterministic และยังเป็น authority ในการรับหรือปฏิเสธข้อเสนอ
- LLM failure หรือหลักฐานไม่พอต้องปล่อย field เป็น unresolved ห้ามเดาค่า
- ขอบเขตเป้าหมายนี้ไม่ใช่คำอธิบาย capability ปัจจุบันทั้งหมด ดูหัวข้อ
  [ความต่างจาก implementation ปัจจุบัน](#ความต่างจาก-implementation-ปัจจุบัน)

## ลำดับการตัดสินใจ

ใช้ลำดับต่อไปนี้กับทุก field:

1. Resolver อ่าน scanner artifacts, runtime facts, Metasploit metadata, validated knowledge และ form state
2. ถ้ามีคำตอบเดียวที่พิสูจน์ได้และกฎอนุญาตให้ resolve อัตโนมัติ ให้ Resolver ใช้ค่านั้นโดยตรง
3. ถ้ามีหลายตัวเลือก, ข้อมูลขัดแย้ง หรือยังต้องตีความหลักฐาน จึงส่งเฉพาะ field ที่ unresolved ให้ LLM ช่วยเสนอ
4. Validator ตรวจชนิดข้อมูล, candidate membership, evidence references และข้อจำกัดของ field
5. ข้อเสนอที่ผ่าน validator ถูกแสดงเป็น `suggested` เท่านั้น
6. มนุษย์ตรวจหลักฐานและใส่ `confirmed` หรือเลือก `decision: skip`

```text
Artifacts / runtime / Metasploit / Knowledge
                    |
                    v
        Deterministic Resolver first
          |                    |
          | resolved           | unresolved / ambiguous
          v                    v
     use directly       LLM evidence-backed suggestion
                                |
                                v
                    deterministic validator
                                |
                                v
                         suggested in form
                                |
                                v
                    human review and confirmation
```

## ขอบเขต field ใน Attack Form

นโยบายเป้าหมายอนุญาตให้ LLM ช่วยเสนอทุกกลุ่มด้านล่าง **ยกเว้น**
`execution_protocol` และ `decision: skip` ซึ่งเป็นการอนุมัติของมนุษย์ ไม่ใช่การอนุมานข้อมูล

| Field | Resolver ใช้โดยตรงได้เมื่อ | LLM ช่วยอย่างไรเมื่อยัง unresolved | ผู้ยืนยันสุดท้าย |
|---|---|---|---|
| `module` | มี candidate เดียวที่ผูกกับ CVE/target อย่างไม่ขัดแย้ง | เปรียบเทียบหลาย candidates กับ CVE, component, platform, module references และ runtime context แล้วเสนอ candidate ที่มีหลักฐานรองรับ | มนุษย์ |
| `target.index` / `target.name` | module มี target เดียว หรือ metadata ระบุ default เดียวและเข้ากับ platform อย่างชัดเจน | เลือกจาก target list ที่ Metasploit ให้มาเท่านั้น พร้อมอ้าง platform และ module metadata | มนุษย์ |
| `targeturi` | มี route เดียวจาก validated knowledge หรือ runtime/application evidence ที่ตรง candidate | ตีความ module default, application path, image/lab facts และ route evidence เพื่อเสนอ path; ห้ามสร้าง route ที่ไม่มี evidence | มนุษย์ |
| `module_options` | required option มีค่าเดียวจาก module schema/default และไม่มี evidence ขัดแย้ง | เสนอเฉพาะ option ที่อยู่ใน live module schema โดยใช้ default, target facts และ field-specific evidence | มนุษย์ |
| `environment.rport` | มี service port เดียวที่เชื่อถือได้และสอดคล้องกับ module default/endpoint | เปรียบเทียบ exposed, listening, reachable, published ports และ module default แล้วเสนอ port ที่อยู่ใน supported set | มนุษย์ |
| `payload` | มี compatible payload เดียวและตรง platform/execution mode อย่างชัดเจน | เลือกจาก compatible payload list เท่านั้น โดยพิจารณา target OS/architecture, callback constraints และวัตถุประสงค์ที่มนุษย์กำหนด | มนุษย์ |
| `payload_options` | required option มี deterministic value เช่น listener address จาก network binding หรือมี default เดียว | เสนอเฉพาะ option ใน live payload schema เช่น `LHOST`, `LPORT`, path หรือ listener setting พร้อม evidence | มนุษย์ |
| `preconditions` | artifact พิสูจน์เงื่อนไขได้โดยตรงและไม่มีการเปลี่ยน state | สรุปเงื่อนไขที่ต้องตรวจจาก module metadata/validated knowledge; ต้องแยก facts ที่พิสูจน์แล้วออกจาก facts ที่ยัง `UNKNOWN` | มนุษย์ |
| `pre_attack` | มีขั้นตอนที่ผ่านการอนุมัติและบันทึกเป็น validated knowledge อยู่แล้ว | เสนอขั้นตอนเตรียมการพร้อม execution target และ evidence เท่านั้น; ห้ามรันคำสั่ง ห้ามถือว่าข้อเสนอได้รับอนุมัติ | มนุษย์ |
| `execution_protocol` | **ห้าม LLM ตัดสิน** แม้ระบบจะคำนวณ protocol ที่รองรับได้ | LLM อาจอธิบายผลกระทบให้มนุษย์อ่าน แต่ห้ามเสนอค่า form หรือเปลี่ยน mode | มนุษย์เท่านั้น |
| `decision: skip` | **ห้าม LLM ตัดสิน** | LLM อาจสรุป evidence gap แต่ห้ามเลือก skip หรือสร้างเหตุผลในฐานะการตัดสินใจแทนผู้ใช้ | มนุษย์เท่านั้น |

## เมื่อใดควรใช้ Resolver โดยตรงโดยไม่เรียก LLM

การมี field อยู่ในขอบเขต LLM ไม่ได้แปลว่าต้องเรียก LLM ทุกครั้ง หากคำตอบเป็น
deterministic ให้ Resolver resolve ก่อนเพื่อลดความคลุมเครือและลดการสร้างคำตอบเกินหลักฐาน

### `module`

- พบ module candidate เพียงตัวเดียว
- candidate ผูกกับ canonical CVE และ component context เดียวกัน
- platform และ module type ไม่ขัดกับ target facts

กรณีนี้ Resolver สามารถใช้ candidate เดียวได้ตามกฎที่กำหนด ไม่ต้องให้ LLM
"เลือก" สิ่งที่ไม่มีตัวเลือกอื่น

### `target.index` / `target.name`

- module มี target เดียว
- index/name มาจาก live Metasploit metadata และจับคู่กันแน่นอน

Resolver สามารถ project ค่าเดียวลง form ได้ อย่างไรก็ตาม หาก policy ยังต้องการ human
review ให้สถานะเป็น suggested/ready-for-confirmation แทนการอ้างว่าเป็น human confirmation

### `environment.rport`

- runtime มี service port เดียวที่เชื่อถือได้
- port ตรงกับ module default หรือ endpoint binding ที่พิสูจน์แล้ว

หากมีหลาย port, มีเพียง weak exposed metadata หรือ default ขัดกับ runtime evidence
จึงค่อยให้ LLM ช่วยจัดลำดับ evidence และเสนอค่า

### `module_options`

- option อยู่ใน live module schema
- มีค่า default เดียว
- ไม่มี target-specific evidence ที่ขัดกับ default
- option ไม่ต้องอาศัย secret, authorization หรือการเปลี่ยน state

Resolver ใช้ default โดยตรงได้ตามระดับความเชื่อมั่นที่ policy อนุญาต ส่วน option ที่ขึ้นกับ
application เช่น action name, virtual host หรือ custom path ควรคง unresolved หรือขอ LLM
ช่วยเสนอจาก evidence

### `payload`

- Metasploit พบ compatible payload เพียงตัวเดียว
- payload ตรงกับ target platform และ execution mode
- ไม่มี callback/network decision ที่ยัง unresolved

กรณีที่มีหลาย payload แม้ทั้งหมด compatible ก็ยังเป็นการเลือกเชิงวัตถุประสงค์ จึงให้ LLM
ช่วยเปรียบเทียบได้ แต่ข้อเสนอสุดท้ายยังต้องให้มนุษย์ยืนยัน

### `payload_options`

- option มีค่าเดียวจาก live payload schema/default
- `LHOST` ผูกกับ canonical listener/network fact ที่แน่นอน
- option ไม่ขึ้นกับการเลือกภายนอก เช่น listener port ที่ผู้ใช้ยังไม่ได้จัดสรร

ตัวอย่างเช่น default boolean ที่ไม่มี evidence ขัดแย้งอาจใช้ Resolver ได้โดยตรง แต่
`LPORT`, callback address หรือ path ที่มีหลายค่าที่เป็นไปได้ควรให้ LLM ช่วยอธิบายตัวเลือก
และให้มนุษย์ยืนยัน

### `preconditions`

Resolver สามารถระบุ fact ที่มีหลักฐานแล้ว เช่น platform, component version หรือ service
presence แต่ห้ามเปลี่ยน `UNKNOWN` ให้เป็นจริง หากเงื่อนไขต้องตีความหลาย artifact LLM อาจ
ช่วยสรุปได้ โดย validator ต้องคง distinction ระหว่าง observed, inferred และ unknown

### `pre_attack`

Resolver ใช้ได้โดยตรงเฉพาะขั้นตอนที่มาจาก validated knowledge และ policy อนุญาตให้ project
เป็น suggestion เท่านั้น การเสนอหรือ project ไม่ใช่สิทธิ์ในการ execute และไม่ใช่ confirmation

## วิธีที่ LLM ต้องช่วย

ข้อเสนอ LLM ทุก field ต้องมีคุณสมบัติดังนี้:

- รับเฉพาะ evidence pack ของ run, CVE, component และ candidate ที่กำลังพิจารณา
- ส่งกลับ typed value พร้อม `evidence_refs`
- อ้างได้เฉพาะ reference ที่อยู่ใน evidence pack
- เลือกได้เฉพาะ candidate/option/payload ที่ Resolver ให้มา ห้ามสร้างชื่อใหม่
- ตอบ `INSUFFICIENT_EVIDENCE` เมื่อหลักฐานไม่พอ
- ห้ามเขียนลง `confirmed` และห้ามเปลี่ยน field ที่ถูกยืนยันแล้ว
- ห้ามเปลี่ยน authorization, execute command, submit form หรือเริ่ม exploit
- suggestion ต้องผ่าน deterministic validator ก่อนแสดงใน Attack Form

แนวทางรายกลุ่ม:

- **Selection** (`module`, `target`, `payload`): rank เฉพาะรายการที่มีอยู่และอธิบาย evidence match/mismatch
- **Binding** (`targeturi`, `rport`, options): เชื่อม module requirement กับ runtime/application facts โดยไม่สร้าง facts ใหม่
- **Prerequisite interpretation** (`preconditions`): สรุปสิ่งที่พิสูจน์แล้วและระบุสิ่งที่ยังขาด
- **Preparation suggestion** (`pre_attack`): เสนอข้อความ/ขั้นตอนเพื่อ human review เท่านั้น และต้องผ่าน command-safety policy ก่อน project

## ส่วนที่สงวนให้มนุษย์เท่านั้น

### `execution_protocol`

การเลือก `check-only`, `exploit-only`, `check-then-exploit` หรือ `auxiliary-test` เป็นการ
อนุมัติพฤติกรรมการทำงาน ไม่ใช่การเติม configuration fact แม้ Resolver จะรู้ว่า module รองรับ
`check()` หรือ exploit ได้ LLM ต้องไม่มีสิทธิ์เลือก mode หรือ set `confirmed: true`

### `decision: skip`

การข้าม CVE เป็นการตัดสิน disposition ของงาน มนุษย์ต้องเลือกและให้เหตุผลเอง LLM อาจแสดง
evidence gap หรือข้อขัดแย้ง แต่ต้องไม่แปลงข้อมูลนั้นเป็นคำสั่ง `skip`

## ความต่างจาก implementation ปัจจุบัน

Production ปัจจุบันยังจำกัด LLM eligibility ไว้ที่:

```text
target
targeturi
rport
payload
```

ดังนั้น policy เป้าหมายในเอกสารนี้ยังต้องมีงาน implementation เพิ่มสำหรับ:

- `module`
- `module_options`
- `payload_options`
- `preconditions`
- `pre_attack`

ก่อนเปิด field เหล่านี้ ต้องเพิ่มหรือยืนยัน field-specific evidence contracts, typed schemas,
validator rules, projection ไปยัง `suggested` slots และ tests ที่พิสูจน์ว่า LLM ไม่สามารถ
เขียน `confirmed`, ข้าม human gate หรือเสนอค่าที่ไม่อยู่ใน artifact ได้

`execution_protocol` และ `decision: skip` ต้องคงอยู่นอก LLM proposal authority
ตามนโยบายนี้

## Invariants ที่ห้ามเปลี่ยน

- LLM output เป็น suggestion ไม่ใช่ confirmation
- `HUMAN_CONFIRMED` เกิดจาก human Attack Form submission เท่านั้น
- Resolver/validator เป็น authority ในการยอมรับหรือปฏิเสธ suggestion
- ค่า deterministic และค่าที่มนุษย์ยืนยันแล้วมีลำดับความสำคัญเหนือ LLM
- ไม่มี evidence ต้องเป็น `UNKNOWN`/unresolved ไม่ใช่ค่าที่คาดเดา
- การเสนอ `pre_attack` ไม่ได้ให้อำนาจ execute
- การ submit หรือเริ่ม exploit ต้องผ่าน human confirmation boundary เสมอ
