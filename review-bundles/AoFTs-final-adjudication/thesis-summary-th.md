# AoFTs final adjudication: CVE-2015-1427 / Elasticsearch

## วัตถุประสงค์การทดลอง

การทดลอง AoFTs มีเป้าหมายเพื่อทดสอบ pipeline ของ Kalama/EVVP กับ CVE-2015-1427 บน Elasticsearch โดยเริ่มจากภาพ vulnerable ulhub/elasticsearch:1.4.2 ตรวจพบ CVE, จัดอันดับ, เลือก Metasploit module ผ่าน Attack Form, รัน exploit BEFORE, สร้างและยืนยัน Patch Form แบบ HUMAN_COMMAND, scan AFTER, re-exploit AFTER และสร้าง evaluation metrics โดยไม่แก้ไขผล historical/canonical หลังจบ pipeline

## สภาพแวดล้อมและ pipeline ที่จบจริง

Run ID: AoFTs

Canonical RunState: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.canonical_state.path)

สถานะสุดท้ายของ pipeline: COMPLETED, current stage STEP_8_EVALUATION

Pipeline completed stages ที่มี artifact หลักครบ ได้แก่ Trivy BEFORE, TOP30 BEFORE, Resolver/Attack Form, Exploit Config BEFORE, Attack BEFORE, Patch Plan/Form/Submission, Patch Result, Trivy AFTER, Remediation Scan Result, Exploit Config AFTER, Attack AFTER, Remediation Result, Evaluation Dataset/Metrics และ Run Summary

## BEFORE exploit evidence

BEFORE artifact: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.before_exploit.artifact_path)

SHA-256: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.before_exploit.artifact_sha256)

ผล BEFORE สำหรับ CVE-2015-1427 คือ EXPLOIT_SUCCEEDED โดย oracle เป็น VULNERABLE, evidence basis เป็น CHECK, completeness เป็น PARTIAL และ session attribution เป็น UNKNOWN พร้อม 
ew_session_ids = [] ตาม artifact. ดังนั้น BEFORE เป็นหลักฐานว่า pipeline สามารถขับ module ไปถึงผล vulnerable/check-positive และ exploit path ได้ แต่ความสมบูรณ์ของ session attribution ยังไม่เต็ม

## Remediation method และ version policy

การแก้ไขเป็น Fix Type B ผ่าน HUMAN_COMMAND ซึ่งเป็น manual-assisted remediation ไม่ใช่ automated provider เต็มรูปแบบ. Patch ใช้ target Elasticsearch 1.4.3 ตาม policy SAME_BRANCH พร้อม upstream security release evidence. Patch result สร้างภาพ kalama/elasticsearch:patched-aofts ด้วย image ID sha256:d2ff298e7aa856748b60d130bbf40a46e5f0d949fc163f5d7950e1a3a94e1658

Patch Result artifact: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.patch.artifact_path)

SHA-256: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.patch.artifact_sha256)

## AFTER scanner result

Trivy AFTER artifact: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.after_scanner.trivy_after_path)

SHA-256: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.after_scanner.trivy_after_sha256)

Remediation scan result ระบุว่า intended CVE ทั้งหมด 1 รายการ และ CVE-2015-1427 เป็น NOT_FOUND. ในเชิง scanner evidence การย้ายจาก Elasticsearch 1.4.2 ไป 1.4.3 จึงสอดคล้องกับ upstream claim ว่า 1.4.3 เป็น release ที่แก้ CVE นี้

## Original pipeline AFTER exploit result

ATTACK_AFTER artifact: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.original_pipeline_after.attack_after_path)

SHA-256: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.original_pipeline_after.attack_after_sha256)

AFTER config ตั้งค่า module xploit/multi/elasticsearch/search_groovy_script_compat, RHOSTS=172.18.0.11, RPORT=9200, LHOST=172.18.0.3, LPORT=4444. Pipeline result เดิม classify เป็น EXPLOIT_SUCCEEDED, oracle VULNERABLE, evidence basis CHECK, completeness PARTIAL

อย่างไรก็ตาม stdout ของ exploit มี anomaly สำคัญ: ระบุว่า payload stage/session ไปที่ 172.18.0.6 ทั้งที่ configured RHOSTS คือ 172.18.0.11. หลักฐาน Docker/RunState จากการ review ก่อนหน้าเชื่อม 172.18.0.6 กับ historical ictim-93AF1, ไม่ใช่ patched target ของ AoFTs. Canonical session evidence ยังระบุ 
ew_session_ids = [] และ ttribution = UNKNOWN. ดังนั้นผล AFTER เดิมเป็น check-based, partial, provisional failure ไม่ใช่หลักฐาน post-patch RCE ที่ผูกกับ patched target ได้แน่นอน

## Isolated patched-target validation

Diagnostic bundle: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.isolated_after_validation.bundle)

Diagnostic ID: $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.isolated_after_validation.diagnostic_id)

สร้าง isolated Docker network $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.isolated_after_validation.network) ที่มีเฉพาะ msf-resolver-host และ target diagnostic ictim-after-diag-aopts-192245. Target IP คือ $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.isolated_after_validation.target_ip), MSF IP คือ $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.isolated_after_validation.msf_ip), Elasticsearch version คือ $(@{schema=kalama.review.adjudication/v1; generated_at_utc=09/08/2026 12:42:54; run_id=AoFTs; source_of_truth=non-canonical review adjudication; production RunState and immutable artifacts are unchanged; repository=; canonical_state=; immutable_artifacts=System.Object[]; before_exploit=; patch=; after_scanner=; original_pipeline_after=; isolated_after_validation=; preserved_classifier_result=; strict_attributable_execution_adjudication=; metrics_context=; references=System.Object[]}.isolated_after_validation.elasticsearch_version), image ID ตรงกับ patched AoFTs image

Baseline ก่อนรัน: ไม่มี active sessions และไม่มี active jobs. หลังรัน: ไม่มี active sessions และไม่มี active jobs. Check result จาก fixture บน isolated patched target คือ 
ot exploitable; exploit abort ก่อนส่ง payload stage ด้วยข้อความว่า Java has not been executed และไม่มี session ถูกสร้าง

Diagnostic conclusion: NOT_REPRODUCED

ผลนี้ไม่พิสูจน์ว่า patched target exploit ไม่ได้ในทุกเงื่อนไข แต่ช่วยลดน้ำหนักของ anomaly เดิมอย่างมาก เพราะเมื่อ isolate target แล้วไม่เกิดทั้ง check-positive และ session evidence

## Discrepancy ระหว่าง scanner กับ empirical evidence

Scanner AFTER บอก CVE-2015-1427 NOT_FOUND. Original pipeline AFTER กลับ classify เป็น REMEDIATION_RESULT = FAILED เพราะ oracle เห็น CHECK=VULNERABLE. ความขัดแย้งนี้ควรถูกตีความเป็น evidence conflict ไม่ใช่ข้อสรุปตรง ๆ ว่า patch ล้มเหลวเชิง RCE

ภายใต้ strict attributable-execution criterion ผล final adjudication คือ UNRESOLVED: หลักฐานเดิมไม่ยืนยัน post-patch execution กับ ictim-after-AoFTs ได้ และ isolated follow-up ไม่ reproduce exploit แต่ยังไม่ใช่ negative proof ที่สมบูรณ์ตาม oracle ที่ออกแบบไว้

## Precision@30 และ eligible denominator

TOP30 มี 30 CVEs แต่มีเพียง 1 CVE ที่เข้าสู่ empirical attempt ได้จริง คือ CVE-2015-1427; อีก 29 รายการถูก exclude ด้วย NO_MSF_MODULE. ดังนั้นการอ่าน Precision@30 ต้องระบุ denominator เชิง execution ว่า eligible empirical denominator คือ 1/30. ค่า Precision@30 ใน metrics คือ 1.0 โดยเกิดจาก TP=1 และ FP=0 เฉพาะกลุ่มที่ eligible เท่านั้น จึงสะท้อนความสำเร็จของการเลือก CVE ที่ execute ได้ มากกว่าความครอบคลุม exploit validation ของ Top 30 ทั้งหมด

## Thesis-ready adjudication

- Historical production classification: REMEDIATION_RESULT = FAILED ถูก preserve ตาม canonical artifact
- Evidence-supported interpretation: check-based, partial, provisional failure with evidence conflict
- Strict attributable-execution result: UNRESOLVED
- Empirical remediation success: UNRESOLVED
- Empirical remediation failure: UNRESOLVED

ข้อสรุปสำหรับ thesis: AoFTs แสดง pipeline แบบครบวงจรได้จริง ตั้งแต่ scan → prioritize → exploit → manual-assisted patch → scan after → re-exploit → evaluate แต่กรณี AFTER exploit มี attribution anomaly ทำให้ไม่ควร claim ว่า patch 1.4.3 ถูกเจาะสำเร็จด้วย RCE หลัง remediation. สิ่งที่ claim ได้อย่างปลอดภัยคือ scanner ไม่พบ CVE หลัง patch, original pipeline classifier ให้ FAILED จาก check-positive, และ isolated validation ไม่ reproduce post-patch exploit/session evidence

## Future work

1. แยก MSF session/job state ต่อ run หรือใช้ isolated network ต่อ attempt เป็น default สำหรับ attribution-sensitive evaluation
2. เพิ่ม oracle condition ที่ต้องการ attributable session หรือ deterministic command evidence ก่อนนับ exploit success แบบเต็ม
3. แยก CHECK evidence, payload-delivery evidence, และ session/RCE evidence ใน metrics
4. บันทึก exact MSF resource script และ peer/session metadata เป็น immutable artifact
5. เพิ่ม policy สำหรับ fixture module ว่า check-only positive หลัง patchต้องไม่ override scanner remediation โดยไม่มี attributable execution

## References

- Elastic security issue #9655: https://github.com/elastic/elasticsearch/issues/9655 — รองรับ claim ว่า CVE-2015-1427 กระทบ Elasticsearch 1.3.0-1.3.7 และ 1.4.0-1.4.2; 1.3.8/1.4.3 ปิด dynamic Groovy behavior ที่เกี่ยวข้อง
- Elastic release announcement: https://discuss.elastic.co/t/elasticsearch-1-4-3-and-1-3-8-release-including-cve/22123 — รองรับ claim ว่า 1.4.3 และ 1.3.8 เป็น security/bug fix release รวม CVE fix
- Rapid7 module page: https://www.rapid7.com/db/modules/exploit/multi/elasticsearch/search_groovy_script/ — รองรับ claim ว่า module นี้เป็น RCE module สำหรับ Elasticsearch ก่อน 1.4.3 และเคย tested on 1.4.2
- Metasploit check-method documentation: https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-write-a-check-method.html — รองรับการแยก check-code semantics ออกจาก session attribution proof; Vulnerable ควรเป็น hard evidence ของ check method แต่ไม่เท่ากับ attributable session เสมอไป
- Project lab note: https://github.com/distortionstack/kalama/blob/main/note/cve-2015-1427 — รองรับ context ของ lab, historical Fix Type B, Trivy NOT FOUND และ re-exploit observations ของโปรเจกต์

