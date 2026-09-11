/**
 * MedixCloud EMR & Clinical In-Memory Database
 * 
 * 🚨 VULNERABILITY 11: Cleartext Storage of Sensitive Health Information (PHI / CWE-312)
 * High-risk patient Protected Health Information (PHI) including Resident Registration Numbers (RRN),
 * sensitive diagnoses (cancer, psychiatric records), and blood types are stored and returned in cleartext!
 */

export const mockDatabase = {
  patients: [
    {
      id: 'patient-101',
      name: '김민준 (Minjun Kim)',
      email: 'minjun.kim@hospital.example',
      rrn: '880512-1948201', // 🚨 CLEAR-TEXT RRN (주민등록번호)
      bloodType: 'AB+',
      insuranceNumber: 'NHIS-2026-981420',
      diagnosis: '2형 당뇨병 (Type 2 Diabetes) 및 고혈압',
      notes: '인슐린 펜 주사 주 2회 투약 중',
      storageMode: 'UNENCRYPTED_PLAINTEXT_PHI',
    },
    {
      id: 'patient-102',
      name: '이서연 (Seoyeon Lee)',
      email: 'seoyeon.lee@hospital.example',
      rrn: '951104-2049182', // 🚨 CLEAR-TEXT RRN
      bloodType: 'O+',
      insuranceNumber: 'NHIS-2026-114829',
      diagnosis: '초기 유방암 (Stage I Breast Carcinoma) 수술 후 경과 관찰',
      notes: '타목시펜 항호르몬 치료 진행 중. 기밀 암 등록 환자.',
      storageMode: 'UNENCRYPTED_PLAINTEXT_PHI',
    },
    {
      id: 'patient-103',
      name: '박도현 (Dohyun Park)',
      email: 'dohyun.park@hospital.example',
      rrn: '790321-1492019', // 🚨 CLEAR-TEXT RRN
      bloodType: 'A-',
      insuranceNumber: 'NHIS-2026-773910',
      diagnosis: '공황장애 (Panic Disorder) 및 중증 불면증',
      notes: '졸피뎀 및 알프라졸람 처방 이력 보유',
      storageMode: 'UNENCRYPTED_PLAINTEXT_PHI',
    },
  ],

  prescriptions: [
    {
      id: 'rx-2026-alpha-001',
      patientId: 'patient-101',
      patientName: '김민준',
      doctorName: 'Dr. 최현우 (내과 전문의)',
      medication: 'Metformin 500mg, Losartan 50mg',
      dosage: '1일 2회 식후 30분 복용',
      status: 'APPROVED',
      isControlledSubstance: false,
      signedDate: '2026-09-08',
    },
    {
      id: 'rx-2026-alpha-002',
      patientId: 'patient-102',
      patientName: '이서연',
      doctorName: 'Dr. 한지민 (종양외과 전문의)',
      medication: 'Tamoxifen 20mg, Zoladex Depot',
      dosage: '1일 1회 아침 복용',
      status: 'APPROVED',
      isControlledSubstance: false,
      signedDate: '2026-09-09',
    },
    {
      id: 'rx-2026-narcotic-999',
      patientId: 'patient-103',
      patientName: '박도현',
      doctorName: 'Dr. 정우성 (정신건강의학과 전문의)',
      medication: 'Zolpidem Tartrate 10mg (향정신성의약품 수면제)',
      dosage: '취침 전 1정 복용 (최대 14일분)',
      status: 'PENDING_APPROVAL', // 🚨 BFLA 타겟: 일반 환자가 무단 승인 가능!
      isControlledSubstance: true,
      signedDate: '2026-09-10',
    },
  ],

  appointments: [
    {
      id: 'apt-501',
      slot: '2026-09-12 14:00',
      doctor: 'Dr. 최현우',
      patientId: 'patient-101',
      patientName: '김민준',
      department: '순환기내과',
      status: 'CONFIRMED',
    },
    {
      id: 'apt-502',
      slot: '2026-09-12 15:00',
      doctor: 'Dr. 한지민',
      patientId: 'patient-102',
      patientName: '이서연',
      department: '종양내과',
      status: 'CONFIRMED',
    },
  ],

  intakeNotes: [
    {
      id: 'intake-1',
      patientId: 'patient-101',
      symptoms: '최근 2주간 아침 공복 혈당이 145mg/dL 이상 측정됨.',
      submittedAt: '2026-09-09T08:30:00Z',
    },
  ],

  doctors: [
    {
      id: 'doc-001',
      name: 'Dr. 최현우',
      licenseNumber: 'MD-KR-84920',
      role: 'doctor',
      department: '내과',
    },
    {
      id: 'doc-002',
      name: 'Dr. 한지민',
      licenseNumber: 'MD-KR-99124',
      role: 'doctor',
      department: '외과',
    },
  ],

  vitalTelemetry: {
    hospitalUnit: 'Medix-ICU-SmartWard-04',
    activeSensors: 42,
    patient101_vitals: {
      heartRate: 74,
      bloodPressure: '128/82',
      spO2: 98,
      temperature: 36.6,
      telemetryVpcSubnet: '10.240.12.0/24 (AWS VPC Internal)',
    },
  },

  otpCodes: new Map([['patient-101', '491823'], ['patient-102', '827104']]),

  /**
   * Simulated SQL Engine: supports vulnerable raw query vs safe parameterized binding
   */
  async query(sqlString, params = []) {
    // 1. Parameterized binding mode
    if (params && params.length > 0) {
      const keyword = String(params[0] || '').toLowerCase()
      const filtered = this.patients.filter((p) =>
        p.name.toLowerCase().includes(keyword) ||
        p.id.toLowerCase().includes(keyword) ||
        p.diagnosis.toLowerCase().includes(keyword)
      )
      return { rows: filtered, rowCount: filtered.length, parameterized: true }
    }

    // 2. Raw SQL string mode with SQL Injection detection
    const lowerSql = sqlString.toLowerCase()
    if (
      lowerSql.includes("' or '1'='1") ||
      lowerSql.includes("' or '1' = '1") ||
      lowerSql.includes("' union select") ||
      lowerSql.includes('" or "1"="1')
    ) {
      // 🚨 SQL Injection Exploit: Dump all patients!
      return {
        rows: this.patients,
        rowCount: this.patients.length,
        injected: true,
        sqlExecuted: sqlString,
      }
    }

    // Normal literal keyword match
    const match = sqlString.match(/WHERE\s+patient_name\s+LIKE\s+'%([^%']+)%'|WHERE\s+patient_id\s*=\s*'([^']+)'/i)
    const term = (match ? (match[1] || match[2]) : '').toLowerCase()
    const filtered = this.patients.filter((p) =>
      p.name.toLowerCase().includes(term) || p.id.toLowerCase().includes(term)
    )

    return { rows: filtered, rowCount: filtered.length, parameterized: false }
  },
}
