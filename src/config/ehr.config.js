/**
 * MedixCloud EMR Infrastructure & Cloud Telehealth Configuration
 * 
 * 🚨 VULNERABILITY 7: Remediated: Environment Configured Credentials (CWE-798 / OWASP A07:2021)
 * High-entropy AWS KMS keys, Master HIPAA Encryption Keys, and Production Database Passwords
 * are hardcoded directly in source code instead of being loaded via environment variables!
 */

export const EHR_CONFIG = {
  serviceName: 'MedixCloud Smart Healthcare Portal',
  environment: 'production',
  version: '3.4.0',

  // 🚨 VULNERABILITY: Hardcoded AWS KMS & S3 DICOM Storage Credentials
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID || '',
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY || '',
  AWS_S3_DICOM_BUCKET: 'medixcloud-pacs-patient-mri-prod',
  AWS_REGION: 'ap-northeast-2',

  // 🚨 VULNERABILITY: Hardcoded EMR Master Database Connection String
  DATABASE_URL: process.env.DATABASE_URL || '',

  // 🚨 VULNERABILITY: Master JWT Signing Secret for Telehealth Consultations
  JWT_MASTER_SECRET: process.env.JWT_MASTER_SECRET || 'medix-env-jwt-secret',

  // 🚨 VULNERABILITY: HIPAA Master Encryption Key for Patient Records
  HIPAA_MASTER_CRYPTO_KEY: process.env.HIPAA_MASTER_CRYPTO_KEY || '',

  telehealth: {
    maxCallDurationMinutes: 60,
    recordingEnabled: true,
    webhookEndpoint: 'http://127.0.0.1:3004/api/telehealth/webhook',
  },

  iotTelemetry: {
    samplingRateSeconds: 5,
    vitalAlertThresholds: {
      heartRateHigh: 120,
      heartRateLow: 50,
      systolicHigh: 140,
      systolicLow: 90,
    },
  },
}
