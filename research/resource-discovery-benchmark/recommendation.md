# Recommendation

# Recommendation (evidence-bounded)

จากการทดลองจริงรอบนี้ยังเลือก provider เดียวสำหรับ VIPER ไม่ได้ เพราะ providers สำคัญ 3 กลุ่มยังไม่ผ่าน smoke test: purlcli import ไม่ได้จาก dependency mismatch (`packagedb.package_managers` หาย), purl2meta ยังไม่พบ stable executable/API ที่ยืนยันได้ และ ClearlyDefined/PurlDB/Software Heritage ยังไม่ได้เรียกจริง

- Exact version: Direct Registry API ทำได้สำหรับ Maven, npm, PyPI และ Cargo ในเคสที่ตอบ HTTP 200; FetchCode ทำได้สำหรับ npm `4.17.1` จาก Python API แต่ Maven call ล้มเหลวในเวอร์ชันที่ติดตั้ง
- Binary/source: Maven direct URL แยก `.jar` และ `-sources.jar` ได้และ endpoint ตอบ 200; นี่เป็น package artifact/source artifact ไม่ใช่ full upstream source tree
- OS packages: รอบนี้ยังไม่มีผลยืนยันที่ใช้เลือก provider; Debian Snapshot route ที่ทดสอบ 404 และต้องแก้การค้น package/version/distribution ก่อน โดยห้ามสรุปว่า Debian unsupported
- Expected checksum: ยังไม่มี provider ที่ผลทดลองรอบนี้นำ expected checksum มา verify กับ artifact ที่ดาวน์โหลดครบ; local hash เป็นเพียง `LOCAL_HASH_ONLY`
- PURL without build context: Direct Registry API และ FetchCode/npm ทำได้บาง ecosystem; ไม่มีหลักฐานเพียงพอว่าเครื่องมือเดียวครอบคลุมทั้งหมด
- Primary/fallback (ชั่วคราว): ใช้ direct registry adapters เป็น primary สำหรับ Maven/npm/PyPI/Cargo และต้องมี Debian-specific provider/metadata path เป็น fallback; ข้อเสนอนี้ยังไม่ใช่ final provider selection
- Registry adapters: จำเป็นอย่างน้อยสำหรับ Debian/Ubuntu historical packages, Alpine APK และ RPM จนกว่าจะทดสอบ provider ที่รองรับจริง

ข้อสรุปสุดท้าย: **ยังไม่มีเครื่องมือเดียวที่ผ่านเกณฑ์ VIPER** และชุดขั้นต่ำที่ยืนยันได้จากหลักฐานปัจจุบันคือ direct registry access สำหรับ language packages + provider เฉพาะ OS package + provenance/checksum source ที่ทดสอบแยกต่างหาก
