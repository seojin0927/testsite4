/**
 * MedixCloud EMR Infrastructure & Cloud Telehealth Configuration
 * 
 * 🚨 VULNERABILITY 7: Hardcoded Credentials & Production Secrets (CWE-798 / OWASP A07:2021)
 * High-entropy AWS KMS keys, Master HIPAA Encryption Keys, and Production Database Passwords
 * are hardcoded directly in source code instead of being loaded via environment variables!
 */

export const EHR_CONFIG = {
  serviceName: 'MedixCloud Smart Healthcare Portal',
  environment: 'production',
  version: '3.4.0',

  // 🚨 VULNERABILITY: Hardcoded AWS KMS & S3 DICOM Storage Credentials
  AWS_ACCESS_KEY_ID: 'AKIA_MEDIX_KMS_MASTER_KEY_2026_PROD',
  AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_MEDIX',
  AWS_S3_DICOM_BUCKET: 'medixcloud-pacs-patient-mri-prod',
  AWS_REGION: 'ap-northeast-2',

  // 🚨 VULNERABILITY: Hardcoded EMR Master Database Connection String
  DATABASE_URL: 'postgres://medix_admin:H0spitalP@ssw0rd2026Master!@internal-db.medixcloud.local:5432/ehr_prod',

  // 🚨 VULNERABILITY: Master JWT Signing Secret for Telehealth Consultations
  JWT_MASTER_SECRET: 'medix-ehr-hospital-telehealth-master-production-secret-2026',

  // 🚨 VULNERABILITY: HIPAA Master Encryption Key for Patient Records
  HIPAA_MASTER_CRYPTO_KEY: 'hipaa_live_master_crypto_key_9942a1bc',

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
