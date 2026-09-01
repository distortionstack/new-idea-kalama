# คู่มือใช้งาน Kalama MVP CLI

คู่มือนี้อธิบายวิธีใช้งาน Kalama ตั้งแต่เริ่มวิเคราะห์อิมเมจ Docker ไปจนถึงดูผลประเมินขั้นสุดท้าย โดย CLI จะทำงานตามสถานะที่บันทึกไว้ในไฟล์กลางของแต่ละรัน และคำสั่ง `continue` หนึ่งครั้งจะเดินหน้าเพียงหนึ่งขั้นเท่านั้น

> คำเตือน: ระบบนี้มีขั้นตอนเรียก Docker, Trivy และ Metasploit รวมถึงขั้นตอนโจมตีเป้าหมายทดสอบ ควรใช้เฉพาะในแล็บหรือระบบที่ได้รับอนุญาตเท่านั้น

## 1. Setup เครื่องและ dependency

โปรเจกต์ใช้ `pyproject.toml` เป็นแหล่งประกาศ Python dependency หลัก และมีสคริปต์ setup สำหรับ development กับ infrastructure:

```text
scripts/setup-dev.sh
setup-workbench.sh
```

dependency ที่ต้องมีประกอบด้วย:

```text
Python 3
PyYAML
Docker Engine พร้อม Docker CLI
อินเทอร์เน็ตสำหรับ EPSS, CISA KEV, Docker pull และ Trivy DB
kalama-workbench-modern ที่ setup จะสร้างและติดตั้ง Trivy ให้
Metasploit container ชื่อ msf-resolver-host
Docker network ชื่อ kalama-net
```

### 1.1 ตรวจ Python และสร้าง virtual environment

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

ตรวจว่า import dependency ได้:

```bash
python3 -c 'import yaml; print("PyYAML", yaml.__version__)'
```

> ถ้าระบบไม่มีโมดูล `venv` บน Debian/Ubuntu ให้ติดตั้งแพ็กเกจ `python3-venv` ก่อน ส่วนชื่อแพ็กเกจอาจต่างกันใน distribution อื่น

### 1.2 ติดตั้งและตรวจ Docker

ติดตั้ง Docker Engine ตามวิธีของระบบปฏิบัติการ แล้วตรวจว่า daemon ทำงานและ user ปัจจุบันเรียก Docker ได้:

```bash
docker version
docker run --rm hello-world
```

ถ้าพบ `permission denied` ที่ Docker socket ให้ตั้งสิทธิ์ Docker สำหรับ user ตามนโยบายของเครื่อง หรือใช้บัญชีที่มีสิทธิ์ อย่าแก้ด้วยการเปิดสิทธิ์ socket ให้ทุกคน

### 1.3 Trivy อยู่ใน `kalama-workbench-modern`

ไม่ต้องติดตั้ง Trivy บน host คำสั่ง `setup-workbench.sh` จะสร้าง container `kalama-workbench-modern`, mount `/var/run/docker.sock` และติดตั้ง Trivy ที่ผ่าน checksum verification ภายใน container นั้น

ชื่อ `kalama-workbench` เป็น container legacy จาก architecture เก่า setup ปัจจุบันจะไม่ inspect, start, rename, delete หรือแก้ไข container เดิมนี้

production scanner ของ Step 2 และ Step 6 เรียกในรูปแบบ:

```text
docker exec kalama-workbench-modern trivy image ...
```

artifact JSON ยังคงถูก validate และ publish แบบ atomic โดย Kalama บน host

### 1.4 เตรียม infrastructure ของแล็บ

ตรวจว่ามี network หรือยัง:

```bash
docker network inspect kalama-net
```

หลังติดตั้ง Python package ให้เรียก setup:

```bash
./setup-workbench.sh
```

setup จะสร้างหรือ reuse `kalama-net`, `kalama-workbench-modern` และ `msf-resolver-host` รวมถึง start container ที่ valid แต่หยุดอยู่ โดยจะไม่ลบหรือแทนที่ container ที่ conflict

### 1.5 ตรวจ managed infrastructure

ตรวจ workbench, Trivy และ Metasploit หลัง setup:

```bash
docker inspect -f '{{.State.Running}}' kalama-workbench-modern
docker exec kalama-workbench-modern docker info
docker exec kalama-workbench-modern trivy --version
docker inspect -f '{{.State.Running}}' msf-resolver-host
docker exec msf-resolver-host \
  /usr/src/metasploit-framework/msfconsole -q -n -x 'version; exit -y'
```

สถานะของ workbench และ MSF ควรเป็น `true`; `kalama doctor` จะตรวจ network attachment ให้อีกครั้ง

> อิมเมจ Metasploit ใช้พื้นที่และเวลา download ค่อนข้างมาก การเรียกครั้งแรกอาจใช้เวลาหลายนาที

### 1.6 เตรียมโปรเจกต์และ output

เปิดเทอร์มินัลที่โฟลเดอร์รากของโปรเจกต์:

```bash
cd /home/distorion/kalama-labs-area/new-idea-kalama
source .venv/bin/activate
mkdir -p output
```

ตรวจสอบว่า CLI พร้อมใช้งาน:

```bash
kalama --help
```

คำสั่งหลักที่ควรเห็น:

```text
run
continue
status
submit-attack-form
submit-patch-form
doctor
```

ค่าเริ่มต้นของโฟลเดอร์ผลลัพธ์คือ `output/` หากต้องการใช้ตำแหน่งอื่น ให้ใส่ `--output-root` ก่อนชื่อคำสั่ง:

```bash
python3 -m kalama --output-root ./my-output status aB3x9
```

ต้องใช้ `--output-root` เดิมกับทุกคำสั่งของรันนั้น มิฉะนั้น CLI จะมองหา state คนละตำแหน่ง

### 1.7 ตรวจ setup ก่อนเริ่มรัน

ตรวจความพร้อมด้วย Doctor และคำสั่ง read-only ต่อไปนี้:

```bash
python3 --version
python3 -c 'import yaml; print(yaml.__version__)'
docker version
docker exec kalama-workbench-modern trivy --version
docker network inspect kalama-net
docker inspect -f '{{.State.Running}}' msf-resolver-host
kalama doctor
```

ถ้า Doctor แสดง `READY` จึงเริ่ม `kalama run --image ...`

## 2. เริ่มรันใหม่

ใช้ `run --image` และระบุ Docker image ที่ต้องการทดสอบ:

```bash
python3 -m kalama run \
  --image vulhub/bash:4.3.0-with-httpd
```

คำสั่งนี้ใช้ orchestration เดิมเพื่อทำ:

```text
Step 2: เตรียมเป้าหมายและสแกนด้วย Trivy
Step 3: จัดลำดับ CVE
หยุดที่ขอบเขต Step 4
```

ตัวอย่างผลลัพธ์แบบย่อ:

```text
Run ID: aB3x9
Status: PAUSED
Current stage: STEP_4_RESOLVER
Requested image: vulhub/bash:4.3.0-with-httpd
State: /path/to/output/state/run_aB3x9.json

Next:
  python3 -m kalama continue aB3x9
```

จด `Run ID` เอาไว้ เพราะทุกคำสั่งหลังจากนี้อ้างอิงรันด้วย ID นี้

## 3. ตรวจสอบสถานะ

```bash
python3 -m kalama status aB3x9
```

ข้อมูลที่แสดงประกอบด้วย:

- สถานะรวมของรัน
- ขั้นตอนปัจจุบันและเหตุผลที่กำลังรอ
- Docker image และข้อมูลเป้าหมายก่อน/หลังแพตช์
- สถานะของแต่ละ stage
- สรุป artifact ที่สร้างแล้ว
- error แบบมีรหัสและข้อความ
- คำสั่งถัดไปที่เหมาะสม

สถานะสำคัญ:

| สถานะ | ความหมาย | สิ่งที่ควรทำ |
|---|---|---|
| `PAUSED` | พร้อมเดินหน้าขั้นถัดไป | ใช้ `continue` |
| `WAITING_FOR_USER_INPUT` | ต้องกรอก Attack Form หรือ Patch Form | ส่งฟอร์มด้วยคำสั่งที่ CLI แสดง |
| `COMPLETED` | รันเสร็จสมบูรณ์ | ดูผลและ artifact |
| `FAILED_FATAL` | ขั้นตอนล้มเหลวและห้ามเดินหน้าต่อ | อ่าน error และตรวจสภาพแวดล้อม |

## 4. เดินหน้าหนึ่งขั้น

```bash
python3 -m kalama continue aB3x9
```

กติกาสำคัญคือ:

```text
continue หนึ่งครั้ง = เรียก stage หนึ่งครั้ง
```

ตัวอย่างลำดับการใช้งาน:

```bash
python3 -m kalama continue aB3x9  # Resolver
python3 -m kalama status aB3x9

python3 -m kalama continue aB3x9  # Before Exploit เมื่อ config พร้อม
python3 -m kalama status aB3x9

python3 -m kalama continue aB3x9  # Patch Planning
```

CLI จะไม่วิ่งรวดเดียวตั้งแต่ Resolver ถึง Evaluation เพราะระบบต้องรักษาจุดตรวจสอบและขอบเขตที่ต้องให้มนุษย์ยืนยัน

## 5. กรอก Attack Form

ถ้า Resolver ต้องการข้อมูลเพิ่มเติม สถานะจะเป็น:

```text
Status: WAITING_FOR_USER_INPUT
Waiting reason: ATTACK_FORM
```

CLI จะแสดง path ของฟอร์ม canonical เช่น:

```text
output/resolver/forms/attack_form_aB3x9_r1.yaml
```

ไม่ควรแก้ artifact ต้นฉบับโดยตรง ให้คัดลอกเป็นไฟล์ submission ก่อน:

```bash
cp output/resolver/forms/attack_form_aB3x9_r1.yaml \
   attack_form_aB3x9_submit.yaml
```

เปิด `attack_form_aB3x9_submit.yaml` แล้วกรอกเฉพาะช่องที่ฟอร์มเปิดให้ยืนยัน เช่น module, target, option หรือ payload ตามข้อมูลจริงของแล็บ

จากนั้นส่งฟอร์ม:

```bash
python3 -m kalama submit-attack-form \
  aB3x9 \
  attack_form_aB3x9_submit.yaml
```

ตัวอย่างกรณียังกรอกไม่ครบ:

```text
Status: WAITING_FOR_USER_INPUT
Waiting reason: ATTACK_FORM

Next:
  Copy/edit the canonical form: ...attack_form_aB3x9_r2.yaml
  python3 -m kalama submit-attack-form aB3x9 FILE
```

นี่ไม่ใช่ความล้มเหลว ระบบรองรับ partial confirmation และจะสร้าง revision ถัดไปให้กรอกต่อ

เมื่อยืนยันครบแล้ว สถานะจะกลับเป็น `PAUSED` และสามารถใช้ `continue` เพื่อทำ Before Exploit ได้

## 6. กรอก Patch Form

หลัง Patch Planning หากระบบไม่มีหลักฐานเพียงพอสำหรับเลือกเวอร์ชันหรือวิธีแพตช์ จะพบ:

```text
Status: WAITING_FOR_USER_INPUT
Waiting reason: PATCH_FORM
```

คัดลอกฟอร์ม canonical เป็น submission:

```bash
cp output/patch/forms/patch_form_aB3x9_r1.yaml \
   patch_form_aB3x9_submit.yaml
```

กรอกข้อมูลที่ร้องขอ เช่น:

- `fix_type`
- เวอร์ชันเป้าหมาย
- แหล่ง artifact ที่เชื่อถือได้
- patch strategy
- command และ validation command เมื่อ strategy ต้องใช้

แล้วส่งฟอร์ม:

```bash
python3 -m kalama submit-patch-form \
  aB3x9 \
  patch_form_aB3x9_submit.yaml
```

การส่ง Patch Form เป็นเพียงการยืนยันแผน ยังไม่รันคำสั่งแพตช์ทันที เมื่อตรวจสอบสถานะแล้วจึงใช้:

```bash
python3 -m kalama continue aB3x9
```

เพื่อเรียก Patch Execution แยกอีกหนึ่งขั้น

## 7. ตัวอย่าง workflow ตั้งแต่ต้นจนจบ

```bash
export PYTHONPATH="$PWD/src/app"

# 1) สร้างรันและทำ Step 2-3
python3 -m kalama run --image vulhub/bash:4.3.0-with-httpd

# สมมติได้ Run ID = aB3x9
python3 -m kalama status aB3x9

# 2) Resolver
python3 -m kalama continue aB3x9

# 3) ตรวจว่าต้องกรอก Attack Form หรือไม่
python3 -m kalama status aB3x9

# ถ้ารอ ATTACK_FORM ให้คัดลอก แก้ และส่ง
cp output/resolver/forms/attack_form_aB3x9_r1.yaml attack-submit.yaml
${EDITOR:-vi} attack-submit.yaml
python3 -m kalama submit-attack-form aB3x9 attack-submit.yaml

# 4) Before Exploit
python3 -m kalama continue aB3x9

# 5) Patch Planning
python3 -m kalama continue aB3x9

# ถ้ารอ PATCH_FORM ให้คัดลอก แก้ และส่ง
python3 -m kalama status aB3x9
cp output/patch/forms/patch_form_aB3x9_r1.yaml patch-submit.yaml
${EDITOR:-vi} patch-submit.yaml
python3 -m kalama submit-patch-form aB3x9 patch-submit.yaml

# 6) Patch Execution
python3 -m kalama continue aB3x9

# 7) After-patch Trivy scan
python3 -m kalama continue aB3x9

# 8) Re-exploitation
python3 -m kalama continue aB3x9

# 9) Final evaluation
python3 -m kalama continue aB3x9

# 10) ดูผลสรุป
python3 -m kalama status aB3x9
```

จำนวนครั้งของ `continue` อาจต่างจากตัวอย่าง ถ้ารันหยุดรอฟอร์ม หรือบางขั้นไม่มีรายการให้ประมวลผล ให้ยึดคำแนะนำใน `Next:` จาก `status` เป็นหลัก

## 8. ดูผลเมื่อรันเสร็จ

เมื่อสำเร็จจะพบ:

```text
Status: COMPLETED
```

คำสั่ง `status` จะแสดง artifact ขั้นสุดท้ายหากมี:

```text
EVALUATION_DATASET
EVALUATION_METRICS
RUN_SUMMARY
```

และแสดง metrics จาก canonical summary เช่น Precision@N, Recall และ F1 โดย CLI จะไม่คำนวณค่าใหม่เอง

## 9. ข้อผิดพลาดที่พบบ่อย

### `No module named kalama`

ยังไม่ได้ตั้ง `PYTHONPATH` หรือไม่ได้อยู่ที่รากโปรเจกต์:

```bash
cd /home/distorion/kalama-labs-area/new-idea-kalama
export PYTHONPATH="$PWD/src/app"
```

### `RUN_NOT_FOUND`

ตรวจ Run ID และ `--output-root`:

```bash
python3 -m kalama --output-root ./output status aB3x9
```

CLI โหลดเฉพาะ `output/state/run_aB3x9.json` และจะไม่เดาว่ารันล่าสุดคือรันใด

### `INVALID_RUN_ID`

Run ID ต้องยาว 5 ตัว และใช้เฉพาะ `A-Z`, `a-z`, `0-9` เช่น:

```text
aB3x9
K8mP2
```

### `ACTIVE_RUN_CONFLICT`

มีรันอื่นอยู่ในสถานะ `RUNNING` ระบบอนุญาตให้มีหลาย state ที่บันทึกไว้ แต่ให้ execute ได้ครั้งละหนึ่งรันเท่านั้น

### `FAILED_FATAL`

ดู error ล่าสุด:

```bash
python3 -m kalama status aB3x9
```

`continue` จะไม่ฝืนรันต่อจากสถานะนี้ และ CLI รุ่นนี้ยังไม่มีคำสั่ง retry, abort หรือ automatic repair

### Docker, Trivy หรือ Metasploit ใช้งานไม่ได้

ตรวจสอบเครื่องมือและคอนเทนเนอร์ด้วยคำสั่ง read-only ก่อน:

```bash
docker version
docker exec kalama-workbench-modern trivy --version
docker network inspect kalama-net
docker inspect msf-resolver-host
```

Resolver และ exploitation คาดว่า `msf-resolver-host` พร้อมใช้งาน ส่วน Step 2 ใช้เครือข่าย `kalama-net`

## 10. หลักการเก็บผลลัพธ์

ไฟล์หลักของแต่ละรันคือ:

```text
output/state/run_<RUN_ID>.json
```

state นี้เป็นแหล่งความจริงของ workflow และบันทึก path กับ SHA-256 ของ artifact ที่แต่ละขั้นต้องใช้ ระบบจะไม่เลือกไฟล์ใหม่สุดจากโฟลเดอร์โดยอัตโนมัติ

โครงสร้างผลลัพธ์โดยประมาณ:

```text
output/
├── state/
├── trivy/
├── scoring/
├── resolver/
├── msf/
├── patch/
├── verification/
└── evaluation/
```

เก็บไฟล์ state และ artifact ของรันไว้ด้วยกัน เพื่อรักษาความสามารถในการตรวจสอบย้อนหลังและทำซ้ำผลการทดลอง
