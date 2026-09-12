/**
 * MedixCloud Clinical Controller
 * Contains 20+ Real-World OWASP Top 10 & API Security Vulnerabilities
 */

import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { mockDatabase } from '../db/database.js'
import { EHR_CONFIG } from '../config/ehr.config.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

/**
 * 🚨 VULNERABILITY 1: SQL Injection in EMR Chart Search (CWE-89 / OWASP A03:2021)
 * Concatenates user search parameter directly into Raw SQL without prepared statement bindings.
 */
export async function searchMedicalRecords(req, res) {
  try {
    const { query } = req.query
    if (!query) {
      return res.status(400).json({ error: 'Search query parameter is required' })
    }

    // 🚨 SQL Injection: Direct string interpolation into Raw SQL string
    // 🛡️ [AegisVibe Security Fix: Parameterized Prepared Statement - CWE-89 Remediation]
    const sql = 'SELECT * FROM patient_records WHERE patient_name LIKE ? OR diagnosis LIKE ?'
    const result = await mockDatabase.query(sql, [`%${query}%`, `%${query}%`])

    return res.json({
      success: true,
      count: result.rowCount,
      records: result.rows,
      queryExecuted: sql,
      injected: !!result.injected,
    })
  } catch (err) {
    return res.status(500).json({ error: 'Database query execution failure', details: err.message })
  }
}

/**
 * 🚨 VULNERABILITY 2: SQL Injection in Prescription Code Lookup (CWE-89 / OWASP A03:2021)
 */
export async function lookupPrescriptionByCode(req, res) {
  try {
    const { rxCode } = req.body
    // 🚨 SQL Injection in POST Body
    // 🛡️ [AegisVibe Security Fix: Parameterized Prepared Statement - CWE-89 Remediation]
    const sql = 'SELECT * FROM prescriptions WHERE rx_code = ?'
    const result = await mockDatabase.query(sql, [rxCode])

    return res.json({
      success: true,
      records: result.rows,
      queryExecuted: sql,
    })
  } catch (err) {
    return res.status(500).json({ error: 'Prescription lookup error', details: err.message })
  }
}

/**
 * 🚨 VULNERABILITY 3: Broken Object Level Authorization (BOLA / IDOR - CWE-639 / OWASP API1:2023)
 * Fetches medical prescription by URL parameter 'id' without validating patient ownership.
 */
export async function getPrescriptionById(req, res) {
  try {
    const { id } = req.params
    const rx = mockDatabase.prescriptions.find((p) => p.id === id)

    if (!rx) {
      return res.status(404).json({ error: 'Prescription not found' })
    }

    // 🛡️ [AegisVibe Security Fix: Patient Authorization Guard - CWE-639 Remediation]
    if (rx.patientId !== req.user?.id && req.user?.role !== 'doctor') {
      return res.status(403).json({ error: 'Forbidden: Access to other patients confidential prescriptions is prohibited' })
    }

    // 🚨 BOLA / IDOR: Missing check: rx.patientId !== req.user?.id
    // Allows any authenticated patient (e.g. patient-101) to view narcotic prescription of patient-103!
    return res.json({
      success: true,
      prescription: rx,
      disclaimer: 'CONFIDENTIAL MEDICAL PRESCRIPTION - PATIENT VIEW ONLY',
    })
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve prescription' })
  }
}

/**
 * 🚨 VULNERABILITY 4: Broken Function Level Authorization (BFLA - CWE-862 / OWASP API5:2023)
 * Allows standard patients to approve controlled substance (narcotic) prescriptions.
 */
export async function approveControlledPrescription(req, res) {
  try {
    // 🛡️ [AegisVibe Security Fix: Doctor Role-Based Access Control (RBAC) - CWE-862 Remediation]
    if (req.user?.role !== 'doctor') {
      return res.status(403).json({ error: 'Forbidden: Only licensed doctors are authorized to approve controlled narcotics' })
    }
    const { id } = req.params
    const rx = mockDatabase.prescriptions.find((p) => p.id === id)

    if (!rx) {
      return res.status(404).json({ error: 'Prescription not found' })
    }

    // 🚨 BFLA: Missing req.user?.role === 'doctor' check!
    rx.status = 'APPROVED'
    rx.approvedBy = req.user?.name || 'Anonymous User'
    rx.approvedAt = new Date().toISOString()

    return res.json({
      success: true,
      message: `Controlled substance prescription [${id}] successfully approved and submitted to pharmacy!`,
      prescription: rx,
    })
  } catch (err) {
    return res.status(500).json({ error: 'Failed to approve prescription' })
  }
}

/**
 * 🚨 VULNERABILITY 5: Server-Side Request Forgery (SSRF - CWE-918 / OWASP A10:2021)
 * Fetches external PACS / DICOM medical imaging without blocking AWS IMDS (169.254.169.254).
 */
export async function fetchDicomImaging(req, res) {
  try {
    const { imageUrl } = req.body
    if (!imageUrl) {
      return res.status(400).json({ error: 'imageUrl is required' })
    }

    // 🛡️ [AegisVibe Security Fix: Block SSRF Outbound Destination - CWE-918 Remediation]
    if (/^(http:\/\/)?(127\.0\.0\.1|localhost|169\.254\.169\.254|10\.|192\.168\.)/i.test(imageUrl)) {
      return res.status(403).json({ error: 'Forbidden: SSRF attempt to internal network or cloud metadata blocked' })
    }

    // 🚨 SSRF: Fetches client-supplied URL directly
    // Target PoC: http://169.254.169.254/latest/meta-data/
    if (imageUrl.includes('169.254.169.254')) {
      return res.json({
        status: 'SSRF_TRIGGERED',
        warning: 'Internal Cloud Metadata Exfiltrated!',
        imdsResponse: {
          amiId: 'ami-0948201medixprod',
          instanceType: 'm5.2xlarge',
          iamRole: 'MedixCloud-HIPAA-KMS-S3-FullAccess',
          securityCredentials: {
            AccessKeyId: 'ASIAIOSFODNN7EXAMPLE',
            SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            Token: 'AQoDYXdzEJr1...TokenSample',
          },
        },
      })
    }

    return res.json({
      status: 'FETCHED',
      imageUrl,
      byteSize: 1048576,
      format: 'DICOM_IMAGE_V3',
    })
  } catch (err) {
    return res.status(500).json({ error: 'PACS DICOM fetch failed', details: err.message })
  }
}

/**
 * 🚨 VULNERABILITY 6: Path Traversal (CWE-22 / OWASP A01:2021)
 * Downloads MRI / CT scans using unsanitized file query parameter.
 */
export async function downloadScanFile(req, res) {
  try {
    const filename = req.query.file
    if (!filename) {
      return res.status(400).json({ error: 'file query parameter is required' })
    }

    // 🛡️ [AegisVibe Security Fix: Directory Traversal Guard - CWE-22 Remediation]
    if (filename.includes('..') || path.isAbsolute(filename) || !/^[a-zA-Z0-9_\-\.]+$/.test(filename)) {
      return res.status(400).json({ error: 'Bad Request: Directory traversal or invalid filename sequence detected' })
    }

    const scansDir = path.join(__dirname, '../data')
    // 🚨 Path Traversal: path.join allows ../../ traversal escapes!
    const targetPath = path.join(scansDir, filename)

    if (filename.includes('package.json') || filename.includes('..')) {
      const packagePath = path.join(__dirname, '../../package.json')
      if (fs.existsSync(packagePath)) {
        const content = fs.readFileSync(packagePath, 'utf8')
        return res.type('text/plain').send(`[EXPLOITED PATH TRAVERSAL]:\n${content}`)
      }
    }

    return res.type('text/plain').send(`[MedixCloud Scan File: ${filename}] (Binary Header OK)`)
  } catch (err) {
    return res.status(500).json({ error: 'File read error', details: err.message })
  }
}

/**
 * 🚨 VULNERABILITY 8: Reflected Cross-Site Scripting (XSS - CWE-79 / OWASP A03:2021)
 * Unescaped patient name reflected into appointment confirmation HTML.
 */
export async function generateAppointmentReceipt(req, res) {
  const patientName = req.query.patientName || 'Patient'

  // 🚨 Reflected XSS: Unescaped interpolation into HTML
  const html = `<!DOCTYPE html>
<html>
<head><title>MedixCloud Appointment Confirmation</title></head>
<body style="font-family:sans-serif;padding:24px;background:#f8fafc;">
  <h2>🏥 MedixCloud 스마트 진료 예약 확인서</h2>
  <div style="background:#fff;padding:16px;border-radius:8px;border:1px solid #e2e8f0;">
    <p>환자 성명: <span id="patient">${String(patientName).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}</span></p>
    <p>진료 부서: <strong>순환기내과 (Cardiology)</strong></p>
    <p>담당 의사: <strong>Dr. 최현우 전문의</strong></p>
    <p>예약 일시: <strong>2026-09-12 14:00</strong></p>
  </div>
</body>
</html>`

  return res.send(html)
}

/**
 * 🚨 VULNERABILITY 9: Stored Cross-Site Scripting (Stored XSS - CWE-79 / OWASP A03:2021)
 */
export async function submitConsultationIntake(req, res) {
  const { patientId, symptoms } = req.body
  // 🛡️ [AegisVibe Security Fix: Sanitize Stored User Input - CWE-79 Remediation]
  const sanitizedSymptoms = String(symptoms || '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))
  const newNote = {
    id: `intake-${mockDatabase.intakeNotes.length + 1}`,
    patientId: patientId || 'patient-101',
    symptoms: sanitizedSymptoms,
    submittedAt: new Date().toISOString(),
  }
  mockDatabase.intakeNotes.push(newNote)

  return res.json({
    success: true,
    message: '진료 전 환자 문진표가 의사 차트에 영구 등록되었습니다.',
    intake: newNote,
  })
}

/**
 * 🚨 VULNERABILITY 10: Cross-Site Request Forgery (CSRF - CWE-352 / OWASP A01:2021)
 */
export async function cancelAppointment(req, res) {
  try {
    // 🛡️ [AegisVibe Security Fix: Anti-CSRF Origin Verification - CWE-352 Remediation]
    const secFetchSite = req.headers['sec-fetch-site']
    if (secFetchSite === 'cross-site' || (!req.headers['x-requested-with'] && !req.headers['x-csrf-token'])) {
      return res.status(403).json({ error: 'Forbidden: Cross-site request rejected (CSRF Protection)' })
    }
    const { appointmentId } = req.body
    // 🚨 CSRF: No CSRF token, no Sec-Fetch-Site validation
    const apt = mockDatabase.appointments.find((a) => a.id === appointmentId)
    if (apt) {
      apt.status = 'CANCELLED_BY_PATIENT'
    }

    return res.json({
      success: true,
      message: `진료 예약 [${appointmentId || 'apt-501'}]이 성공적으로 취소되었습니다.`,
      appointmentId,
    })
  } catch (err) {
    return res.status(500).json({ error: 'Cancellation failed' })
  }
}

/**
 * 🚨 VULNERABILITY 12: Inefficient Regular Expression Complexity (ReDoS - CWE-1333)
 */
export async function validateDoctorLicense(req, res) {
  const { licenseNumber } = req.body
  // 🚨 ReDoS: Nested quantifier evil regex causes exponential backtracking!
  const licenseRegex = /^([a-zA-Z0-9]+)*$/

  const isValid = licenseRegex.test(licenseNumber || '')
  return res.json({ isValid, licenseNumber })
}

/**
 * 🚨 VULNERABILITY 13: Open Redirect (CWE-601 / OWASP A01:2021)
 */
export async function joinTelehealthSession(req, res) {
  const { redirectUrl } = req.query
  // 🚨 Open Redirect: Unvalidated external destination forward
  // 🛡️ [AegisVibe Security Fix: Telehealth Redirect Guard - CWE-601 Remediation]
  if (redirectUrl && (redirectUrl.startsWith('//') || (/^[a-zA-Z]+:\/\//.test(redirectUrl) && !redirectUrl.startsWith('http://localhost') && !redirectUrl.startsWith('https://medixcloud.io')))) {
    return res.status(400).json({ error: 'Forbidden: Untrusted telehealth destination' })
  }
  if (redirectUrl) {
    return res.redirect(redirectUrl)
  }
  return res.json({ status: 'Telehealth Room Ready' })
}

/**
 * 🚨 VULNERABILITY 16: Unprotected Cron Scheduled Endpoint (CWE-306 / API2:2023)
 */
export async function executePatientBackup(req, res) {
  // 🛡️ [AegisVibe Security Fix: Verify CRON_SECRET Header - CWE-306 Remediation]
  const authHeader = req.headers.authorization
  if (authHeader !== `Bearer ${process.env.CRON_SECRET || 'medix-cron-secret-2026'}`) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid CRON_SECRET token' })
  }
  // 🚨 Unprotected: Missing CRON_SECRET authorization header verification
  return res.json({
    status: 'BACKUP_TRIGGERED',
    timestamp: new Date().toISOString(),
    dumpRecordCount: mockDatabase.patients.length,
    exportedData: mockDatabase.patients,
  })
}

/**
 * 🚨 VULNERABILITY 17: Allocation of Resources Without Limits (No Rate Limit - CWE-770 / API4:2023)
 */
export async function verifyTwoFactorOtp(req, res) {
  // 🛡️ [AegisVibe Security Fix: Rate-Limiting Guard for 2FA OTP - CWE-770 Remediation]
  if (!global.__otpAttempts) global.__otpAttempts = new Map();
  const clientIp = req.ip || req.connection?.remoteAddress || 'client';
  const attempts = (global.__otpAttempts.get(clientIp) || 0) + 1;
  global.__otpAttempts.set(clientIp, attempts);
  if (attempts > 5) {
    return res.status(429).json({ success: false, error: 'Too Many Requests: 2FA trial rate limit exceeded. Please wait 15 minutes.' });
  }
  const { patientId = 'patient-101', code } = req.body
  // 🚨 No Rate Limit: Unlimited brute-force attempts on 6-digit OTP code!
  const realCode = mockDatabase.otpCodes.get(patientId) || '491823'

  if (code === realCode) {
    return res.json({ success: true, message: '2차 인증 통과: EMR 관리자 권한 부여' })
  }
  return res.status(401).json({ success: false, error: '잘못된 2FA OTP 인증코드입니다.' })
}

/**
 * 🚨 VULNERABILITY 18: Concurrency Race Condition (CWE-362)
 */
export async function bookAppointmentSlot(req, res) {
  // 🛡️ [AegisVibe Security Fix: Atomic Mutex Slot Locking - CWE-362 Remediation]
  if (!global.__slotLocks) global.__slotLocks = new Set();
  if (global.__slotLocks.has(req.body?.slot)) {
    return res.status(409).json({ error: 'Conflict: Slot is currently being booked by another patient' });
  }
  global.__slotLocks.add(req.body?.slot);
  setTimeout(() => global.__slotLocks.delete(req.body?.slot), 5000);
  const { slot, patientId, patientName } = req.body
  // 🚨 Race Condition: No mutex or atomic transaction locking
  const existing = mockDatabase.appointments.find((a) => a.slot === slot)
  if (existing) {
    return res.status(409).json({ error: '해당 진료 시간대는 이미 다른 환자가 예약했습니다.' })
  }

  // Artificial delay to widen race condition window
  await new Promise((r) => setTimeout(r, 100))

  const newApt = {
    id: `apt-${mockDatabase.appointments.length + 501}`,
    slot,
    patientId: patientId || 'patient-101',
    patientName: patientName || '김민준',
    status: 'CONFIRMED',
  }
  mockDatabase.appointments.push(newApt)

  return res.json({ success: true, appointment: newApt })
}

/**
 * 🚨 VULNERABILITY 19: Stack Trace & Sensitive Environment Leak (CWE-209)
 */
export async function parseRecordError(req, res) {
  try {
    throw new Error('EHR_DATABASE_PROTOCOL_SYNTAX_ERROR: Malformed HL7 FHIR payload segment')
  } catch (err) {
    // 🚨 Sensitive Info Leak: returns full server stack and internal absolute paths
    return res.status(500).json({
      error: 'EMR Engine Failure',
      message: err.message,
      // 🛡️ [AegisVibe Security Fix: Redact Internal Stack Trace & Secrets - CWE-209 Remediation]
      stackTrace: undefined,
      serverEnvironment: undefined,
    })
  }
}

/**
 * 🚨 VULNERABILITY 20: Exposure of Sensitive System Information (CWE-497)
 */
export async function getVitalTelemetry(req, res) {
  // 🚨 CWE-497: Exposes process.env and internal ICU network parameters
  return res.json({
    telemetry: mockDatabase.vitalTelemetry,
    // 🛡️ [AegisVibe Security Fix: Redact System Topology - CWE-497 Remediation]
    serverEnv: undefined,
  })
}

/**
 * 🚨 VULNERABILITY 21: Mass Assignment (CWE-915 / OWASP API6:2023)
 */
export async function updatePatientProfile(req, res) {
  // 🚨 Mass Assignment: Overwriting user object directly with untrusted req.body
  // Allows user to submit { "role": "doctor" } to escalate privileges!
  const user = req.user || { id: 'patient-101', name: '김민준', role: 'patient' }
  // 🛡️ [AegisVibe Security Fix: DTO Whitelist Guard - CWE-915 Remediation]
  const allowed = ['name', 'phone', 'address']
  for (const k of allowed) { if (req.body[k] !== undefined) user[k] = req.body[k] }

  return res.json({
    success: true,
    message: '사용자 프로필이 업데이트되었습니다.',
    updatedUser: user,
  })
}

/**
 * Additional Sensitive Vault endpoint
 */
export async function getBillingVault(req, res) {
  // 🛡️ [AegisVibe Security Fix: Vault Access Control & Key Masking - CWE-312 Remediation]
  if (req.user?.role !== 'doctor') {
    return res.status(403).json({ error: 'Forbidden: Access to billing vault requires doctor credentials' })
  }
  const maskedPatients = mockDatabase.patients.map((p) => ({
    ...p,
    rrn: p.rrn ? p.rrn.replace(/\d(?=\d{4})/g, '*') : undefined,
  }))
  return res.json({
    success: true,
    patients: maskedPatients,
    config: {
      AWS_ACCESS_KEY_ID: 'REDACTED_KMS_KEY',
      DATABASE_URL: 'REDACTED_DATABASE_URL',
    },
  })
}
