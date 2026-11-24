# VIPER Resource Discovery Benchmark

ผล Task 5 provider spikes อยู่ใน [task5-report.md](task5-report.md) ส่วน benchmark เดิมด้านล่างเก็บไว้เป็น baseline และไม่ได้รันซ้ำโดยไม่จำเป็น

งานทดลองแบบ non-mutating สำหรับเปรียบเทียบ package metadata/resource discovery โดยไม่แก้ production code และไม่ติดตั้ง/รัน artifact ที่ดาวน์โหลดมา

## วิธีรัน

```bash
./.venv/bin/python research/resource-discovery-benchmark/benchmark.py
```

ผลลัพธ์จะอยู่ใน `results.json` และ response แยกเคสใน `raw/` จำกัด response ไว้ 2 MB และ timeout 15 วินาที (`BENCHMARK_TIMEOUT` ปรับได้) การรันจริงต้องมี network; ข้อผิดพลาดจะถูกบันทึกแทนการถือว่าเป็น `FAIL` ของ metadata

## ขอบเขตและสถานะ

รอบนี้ harness ตรวจ PURL, exact version, direct registry, deps.dev และ OSV baseline พร้อมบันทึก HTTP status/redirect/failure แยกจาก verification ผลรันจริงอยู่ใน `results.json`: Maven, npm, PyPI และ Cargo metadata/artifact endpoints ตอบ `200`; Debian Snapshot routes ที่ใช้ตอบ `404` และต้องตรวจ route/version mapping เพิ่มเติม ไม่ถือว่า Debian ไม่รองรับจากผลนี้เพียงอย่างเดียว การทดลอง network ก่อนหน้าได้ `BLOCKED_NETWORK` แต่รอบนี้รันด้วย network access ที่ได้รับอนุญาตแล้ว

ค่า `computed` จะถูกบันทึกเฉพาะ response body ที่อ่านครบภายใน limit; artifact ที่ถูกตัดเพราะเกิน limit จะเป็น `NOT_COMPUTED_TRUNCATED` และไม่มีการนำ hash นี้ไปอ้างเป็น trusted checksum

เครื่องมือ FetchCode, PurlDB, `purlcli`, ClearlyDefined, purl2meta, Software Heritage, ecosyste.ms, purl2src, purl2repo, ORT และ Debian Snapshot ต้องติดตั้ง/ตรวจเวอร์ชันและ endpoint ตามสภาพแวดล้อมจริงก่อนเพิ่ม adapter; ห้ามกรอกผลจาก documentation claims ลงใน `results.json`
