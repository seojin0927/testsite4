import { Router } from 'express'
import {
  searchMedicalRecords,
  lookupPrescriptionByCode,
  getPrescriptionById,
  approveControlledPrescription,
  fetchDicomImaging,
  downloadScanFile,
  generateAppointmentReceipt,
  submitConsultationIntake,
  cancelAppointment,
  validateDoctorLicense,
  joinTelehealthSession,
  executePatientBackup,
  verifyTwoFactorOtp,
  bookAppointmentSlot,
  parseRecordError,
  getVitalTelemetry,
  updatePatientProfile,
  getBillingVault,
} from '../controllers/medical.controller.js'
import { EHR_CONFIG } from '../config/ehr.config.js'
import { mockDatabase } from '../db/database.js'

export const medicalRouter = Router()

// 1. SQL Injection Search
medicalRouter.get('/records/search', searchMedicalRecords)

// 2. SQL Injection POST Body
medicalRouter.post('/prescriptions/lookup', lookupPrescriptionByCode)

// 3. BOLA / IDOR Prescription Lookup
medicalRouter.get('/prescriptions/:id', getPrescriptionById)

// 4. BFLA Controlled Substance Approval
medicalRouter.post('/prescriptions/:id/approve', approveControlledPrescription)
medicalRouter.put('/prescriptions/:id/approve', approveControlledPrescription)

// 5. SSRF DICOM / PACS Webhook
medicalRouter.post('/dicom/fetch', fetchDicomImaging)

// 6. Path Traversal Scan Download
medicalRouter.get('/scans/download', downloadScanFile)

// 7. Hardcoded Secrets Leak
medicalRouter.get('/config', (req, res) => {
  res.json({
    service: EHR_CONFIG.serviceName,
    awsAccessKey: EHR_CONFIG.AWS_ACCESS_KEY_ID,
    awsSecretAccessKey: EHR_CONFIG.AWS_SECRET_ACCESS_KEY,
    databaseUrl: EHR_CONFIG.DATABASE_URL,
    hipaaKey: EHR_CONFIG.HIPAA_MASTER_CRYPTO_KEY,
  })
})

// 8. Reflected XSS
medicalRouter.get('/appointments/receipt', generateAppointmentReceipt)

// 9. Stored XSS
medicalRouter.post('/consultation/intake', submitConsultationIntake)

// 10. CSRF Appointment Cancellation
medicalRouter.post('/appointments/cancel', cancelAppointment)

// 11. Cleartext PHI & Billing Vault
medicalRouter.get('/billing-vault', getBillingVault)
medicalRouter.get('/billing/vault', getBillingVault)
medicalRouter.get('/patients/export-phi', (req, res) => res.json({ success: true, count: mockDatabase.patients.length, patients: mockDatabase.patients }))

// 12. ReDoS License Validation
medicalRouter.post('/auth/validate-license', validateDoctorLicense)
medicalRouter.post('/doctor/validate-license', validateDoctorLicense)

// 13. Open Redirect
medicalRouter.get('/telehealth/join', joinTelehealthSession)
medicalRouter.get('/telehealth/session', joinTelehealthSession)

// 16. Unprotected Cron Backup
medicalRouter.get('/cron/patient-backup', executePatientBackup)
medicalRouter.get('/patients/backup', executePatientBackup)

// 17. No Rate Limit 2FA OTP
medicalRouter.post('/auth/verify-otp', verifyTwoFactorOtp)
medicalRouter.post('/auth/2fa/verify', verifyTwoFactorOtp)

// 18. Concurrency Race Condition
medicalRouter.post('/appointments/book', bookAppointmentSlot)

// 19. Stack Trace Disclosure
medicalRouter.post('/records/parse-error', parseRecordError)

// 20. Debug Telemetry Leak
medicalRouter.get('/debug/vital-telemetry', getVitalTelemetry)
medicalRouter.get('/telemetry/vitals', getVitalTelemetry)

// 21. Mass Assignment Privilege Escalation
medicalRouter.put('/user/profile', updatePatientProfile)
medicalRouter.put('/patient/profile', updatePatientProfile)
