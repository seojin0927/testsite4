import express from 'express'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'
import { medicalRouter } from './src/routes/medical.routes.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 3004

/**
 * 🚨 VULNERABILITY 14: Permissive Cross-Origin Resource Sharing (CORS - CWE-942)
 * Reflects arbitrary client Origin while allowing credentials (Access-Control-Allow-Credentials: true).
 * Malicious web pages can make authenticated cross-origin requests to exfiltrate patient records!
 */
app.use((req, res, next) => {
  // 🛡️ [AegisVibe Security Fix: Strict CORS Whitelist - CWE-942 Remediation]
  const allowedOrigins = ['http://localhost:3003', 'http://localhost:3004', 'https://app.aegisvibe.io']
  const origin = allowedOrigins.includes(req.headers.origin) ? req.headers.origin : allowedOrigins[0]
  res.header('Access-Control-Allow-Origin', origin)
  res.header('Access-Control-Allow-Credentials', 'true')
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200)
  }
  next()
})

/**
 * 🚨 VULNERABILITY 15: Sensitive Session Cookie without HttpOnly & Secure Flags (CWE-614)
 * The EMR session cookie is set without HttpOnly and without Secure, allowing client-side JS theft.
 */
app.use((req, res, next) => {
  res.cookie('medix_ehr_session', 'sess_live_hospital_patient_101_alpha', {
    // 🛡️ [AegisVibe Security Fix: Secure Session Cookie Attributes - CWE-614 Remediation]
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',   // 🚨 Plaintext transmission!
  })
  next()
})

// Authentication Context Middleware
app.use((req, res, next) => {
  const authHeader = req.headers.authorization
  // Default to standard patient for easy security evaluation
  req.user = {
    id: 'patient-101',
    name: '김민준 (환자)',
    role: 'patient',
    department: '일반외래',
  }

  if (authHeader && authHeader.includes('Bearer doctor-master-token')) {
    req.user = {
      id: 'doc-001',
      name: 'Dr. 최현우 (내과 전문의)',
      role: 'doctor',
      department: '순환기내과',
    }
  }
  next()
})

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

// Mount Routes
app.use('/api', medicalRouter)

app.get('/api/health', (req, res) => {
  res.json({
    status: 'HEALTHY',
    service: 'MedixCloud Smart Healthcare EMR Portal',
    version: '3.4.0',
    port: PORT,
    activeVulnerabilities: 21,
  })
})

app.listen(PORT, () => {
  console.log(`[MedixCloud EMR Healthcare Portal] Running on http://localhost:${PORT}`)
})
