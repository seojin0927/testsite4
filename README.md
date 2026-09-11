# 🏥 testsite4: MedixCloud Smart Healthcare EMR Portal (21 Vulnerabilities Testbed)

## 📌 서비스 개요
- **서비스명**: MedixCloud (스마트 의료·원격진료 & 전자의무기록 EMR 포털)
- **실행 포트**: `http://localhost:3004`
- **구동 명령어**:
  ```bash
  cd testsite4
  npm start # 또는 node server.js
  ```

---

## 🚨 탑재된 21개 실전 취약점 명세 및 검증 방법

| 번호 | 취약점 명칭 | CWE / OWASP 분류 | 대상 엔드포인트 및 파일 | 상세 취약점 메커니즘 |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **SQL Injection (EMR 차트 검색)** | CWE-89 (A03:2021) | `GET /api/records/search?query=`<br/>`medical.controller.js` | 바인딩 없는 원시 SQL 쿼리 결합으로 `' OR '1'='1` 입력 시 전체 환자 기록 및 병력 덤프 |
| **2** | **SQL Injection (처방전 코드 조회)** | CWE-89 (A03:2021) | `POST /api/prescriptions/lookup`<br/>`medical.controller.js` | POST 본문의 `rxCode` 파라미터 따옴표 미처리로 데이터베이스 조작 |
| **3** | **BOLA / IDOR (타인 처방전 열람)** | CWE-639 (API1:2023) | `GET /api/prescriptions/:id`<br/>`medical.controller.js` | 로그인 환자 세션(`patient-101`)과 처방전 `patientId` 소유권 대조 누락으로 타인 기밀 처방전 열람 |
| **4** | **BFLA (마약류 처방전 강제 승인)** | CWE-862 (API5:2023) | `POST /api/prescriptions/:id/approve`<br/>`medical.controller.js` | 의사(`doctor`) 역할 검증 누락으로 일반 환자(`patient`)가 향정신성 수면제 처방전을 무단 승인 |
| **5** | **SSRF (PACS 의료 영상 웹훅)** | CWE-918 (A10:2021) | `POST /api/dicom/fetch`<br/>`medical.controller.js` | 외부 영상 수신 URL에 `169.254.169.254` 입력 시 AWS IMDS 메타데이터 및 IAM 키 탈취 |
| **6** | **Path Traversal (CT 스캔 다운로드)** | CWE-22 (A01:2021) | `GET /api/scans/download?file=`<br/>`medical.controller.js` | 상위 디렉터리 이동(`../../package.json`) 검증 부재로 시스템 및 소스코드 임의 열람 |
| **7** | **하드코딩된 AWS KMS 키 노출** | CWE-798 (Secrets Leak) | `GET /api/config`<br/>`ehr.config.js` | AWS KMS 마스터 키(`AKIA_MEDIX_...`) 및 DB 패스워드 소스코드 하드코딩 노출 |
| **8** | **Reflected XSS (진료 확인증)** | CWE-79 (A03:2021) | `GET /api/appointments/receipt`<br/>`medical.controller.js` | `patientName` 파라미터가 이스케이프 없이 HTML에 반영되어 임의 스크립트 실행 |
| **9** | **Stored XSS (문진표 증상 메모)** | CWE-79 (A03:2021) | `POST /api/consultation/intake`<br/>`medical.controller.js` | 환자가 등록한 증상 메모가 필터링 없이 의사 차트 화면에 영구 렌더링 |
| **10**| **CSRF (진료 예약 무단 취소)** | CWE-352 (A01:2021) | `POST /api/appointments/cancel`<br/>`medical.controller.js` | CSRF 토큰이나 Origin 검증이 없어 외부 악성 사이트 유도 클릭 시 환자 진료 취소 |
| **11**| **민감 건강 정보(PHI) 평문 저장** | CWE-312 (A02:2021) | `GET /api/billing-vault`<br/>`src/db/database.js` | 주민등록번호(RRN), 혈액형, 암 진단명이 DB에 마스킹 없이 평문 저장 및 반환 |
| **12**| **ReDoS (의사 면허 검증 정규식)** | CWE-1333 (A03:2021) | `POST /api/auth/validate-license`<br/>`medical.controller.js` | 중첩 정량자 정규식(`^([a-zA-Z0-9]+)*$`)으로 면허번호 검증 시 이벤트 루프 프리징 |
| **13**| **Open Redirect (원격 진료 연동)** | CWE-601 (A01:2021) | `GET /api/telehealth/join`<br/>`medical.controller.js` | 도메인 화이트리스트 검증 없이 전달받은 피싱 사이트 URL로 사용자 브라우저 강제 이동 |
| **14**| **와일드카드 CORS & Credentials** | CWE-942 (Misconfig) | `server.js` | 임의 Origin을 반사하면서 `Access-Control-Allow-Credentials: true` 동시 허용 |
| **15**| **안전하지 않은 EMR 세션 쿠키** | CWE-614 (A02:2021) | `server.js` | 세션 쿠키에 `httpOnly: false`, `secure: false` 플래그로 설정되어 JS 탈취 허용 |
| **16**| **Unprotected Cron (환자 백업 덤프)** | CWE-306 (API2:2023) | `GET /api/cron/patient-backup`<br/>`medical.controller.js` | `CRON_SECRET` 인증 누락으로 외부 누구나 대규모 환자 데이터베이스 백업 덤프 실행 |
| **17**| **무제한 2FA OTP 대입 (No Rate Limit)** | CWE-770 (API4:2023) | `POST /api/auth/verify-otp`<br/>`medical.controller.js` | 호출 횟수 제한이 없어 무작위 6자리 OTP 무차별 대입으로 의사 권한 탈취 |
| **18**| **진료 예약 동시성 결함 (Race Condition)** | CWE-362 (Concurrency) | `POST /api/appointments/book`<br/>`medical.controller.js` | 트랜잭션 락 부재로 동일 시간대 수술실/진료실을 2명의 환자가 동시 선점 |
| **19**| **진료 예외 스택 트레이스 노출** | CWE-209 (Info Disclosure) | `POST /api/records/parse-error`<br/>`medical.controller.js` | 예외 응답에 서버 절대 경로, Node 버전, DB 호스트 스택 트레이스 반환 |
| **20**| **디버그 텔레메트리 노출** | CWE-497 (Info Exposure) | `GET /api/debug/vital-telemetry`<br/>`medical.controller.js` | 프로덕션 환경에서 ICU 환자 심박수 및 클라우드 내부 VPC 서브넷 노출 |
| **21**| **Mass Assignment (프로필 권한 상승)** | CWE-915 (API6:2023) | `PUT /api/user/profile`<br/>`medical.controller.js` | 프로필 수정 시 `req.body`를 직접 덮어써 `{ "role": "doctor" }`로 의사 승격 |

---

## 🎮 웹 대시보드 실시간 테스트
브라우저에서 `http://localhost:3004`에 접속하면 **[MedixCloud 실전 취약점 21종 원클릭 검증 매트릭스]** 패널에서 21개 취약점을 원클릭으로 직접 격발 및 실시간 응답을 확인할 수 있습니다.
