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
    const sql = `SELECT * FROM patient_records WHERE patient_name LIKE '%${query}%' OR diagnosis LIKE '%${query}%'`
    const result = await mockDatabase.query(sql)

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
    const sql = `SELECT * FROM prescriptions WHERE rx_code = '${rxCode}'`
    const result = await mockDatabase.query(sql)

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
    <p>환자 성명: <span id="patient">${patientName}</span></p>
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
  const newNote = {
    id: `intake-${mockDatabase.intakeNotes.length + 1}`,
    patientId: patientId || 'patient-101',
    symptoms: symptoms || '', // 🚨 Stored without HTML sanitization
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
  if (redirectUrl) {
    return res.redirect(redirectUrl)
  }
  return res.json({ status: 'Telehealth Room Ready' })
}

/**
 * 🚨 VULNERABILITY 16: Unprotected Cron Scheduled Endpoint (CWE-306 / API2:2023)
 */
export async function executePatientBackup(req, res) {
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
      stackTrace: err.stack,
      serverEnvironment: {
        nodeVersion: process.version,
        platform: process.platform,
        cwd: process.cwd(),
        dbHost: 'internal-db.medixcloud.local:5432',
      },
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
    serverEnv: {
      NODE_ENV: process.env.NODE_ENV || 'production',
      AWS_REGION: EHR_CONFIG.AWS_REGION,
      VPC_SUBNET: '10.240.12.0/24 (Medix-ICU-Subnet)',
    },
  })
}

/**
 * 🚨 VULNERABILITY 21: Mass Assignment (CWE-915 / OWASP API6:2023)
 */
export async function updatePatientProfile(req, res) {
  // 🚨 Mass Assignment: Overwriting user object directly with untrusted req.body
  // Allows user to submit { "role": "doctor" } to escalate privileges!
  const user = req.user || { id: 'patient-101', name: '김민준', role: 'patient' }
  Object.assign(user, req.body)

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
  return res.json({
    success: true,
    patients: mockDatabase.patients,
    config: {
      AWS_ACCESS_KEY_ID: EHR_CONFIG.AWS_ACCESS_KEY_ID,
      DATABASE_URL: EHR_CONFIG.DATABASE_URL,
    },
  })
}
