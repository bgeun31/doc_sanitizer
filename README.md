# 문서형 악성코드 무해화 시스템 v2.2

Microsoft Office, PDF, 한글 문서의 악성코드 탐지 및 무해화 시스템

## 빠른 시작

### macOS
```bash
python test_api.py setup
python main.py
```

### Windows
```cmd
python test_api.py setup
python main.py
```

## 환경 설정

### macOS
```bash
pip install -r requirements.txt
cp .env.example .env
```
(.env 파일을 열어서 실제 API 키로 교체)

### Windows
```cmd
pip install -r requirements.txt
copy .env.example .env
```
(.env 파일을 메모장으로 열어서 실제 API 키로 교체)

### API 키 발급
- **MalwareBazaar**: https://bazaar.abuse.ch/api/
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey

## 주요 기능

- **AI 기반 탐지**: 머신러닝 모델을 통한 악성코드 예측
- **룰 기반 탐지**: Office 매크로, PDF JavaScript, HWP 스크립트 탐지  
- **VirusTotal 검증**: 온라인 바이러스 검사 서비스 연동
- **문서 무해화**: 악성 요소 제거 및 안전한 문서 생성
- **공용 DB 연동**: 바이러스 샘플 공유 및 재훈련 시스템

## 지원 파일 형식

- **Microsoft Office**: .docx, .docm, .xlsx, .xlsm, .pptx, .pptm
- **PDF**: .pdf  
- **한글**: .hwp, .hwpx, .hwpml

## 폴더 구조

```
doc_sanitizer/
├── main.py                 # GUI 메인 애플리케이션
├── test_api.py            # 시스템 테스트 및 설정
├── config.py              # API 설정 관리
├── utils/                 # 핵심 모듈
├── sample/
│   ├── mecro/             # 악성 샘플 (로컬만)
│   ├── clear/             # 자체생성 클린파일
│   └── clean/             # 무해화된 파일
└── models/                # 훈련된 AI 모델
```

## 주요 변경사항 v2.2

1. **폴더 구조 개선**: 
   - `sample/clear/`: 자체생성 클린파일
   - `sample/clean/`: 무해화된 파일 격리
2. **GUI 최적화**: 업로드 즉시 검사 실행
3. **AWS 모델 로드 개선**: S3 연동 Hot-fix 적용  
4. **공용 DB 연동**: 바이러스 샘플 공유 및 재훈련 지원
5. **통합 검사 프로세스**: AI + 룰 기반 + VirusTotal 동시 실행

## 디버깅

### macOS
```bash
python force_retrain.py
python debug_env.py
```

### Windows  
```cmd
python force_retrain.py
python debug_env.py
```

## Git 사용법

### 새 브랜치 생성 및 작업

#### macOS
```bash
git checkout -b dev.your_name
git add .
git commit -m "작업 내용"
git push origin dev.your_name
```

#### Windows
```cmd
git checkout -b dev.your_name
git add .
git commit -m "작업 내용"  
git push origin dev.your_name
```

### 동기화

#### macOS/Windows 공통
```bash
git pull origin dev
```

- sample/mecro/ 폴더는 로컬에만 존재
- 모델 파일은 용량 문제로 Git에서 제외됨

## AWS 연동 설정

### 1. .env 파일 설정
```env
USE_AWS=true
AWS_REGION=ap-southeast-2
S3_BUCKET=your-bucket-name
RDS_HOST=your-rds-endpoint
RDS_DB=your-database-name
RDS_USER=your-username
RDS_PASSWORD=your-password
```

### 2. AWS CLI 설정 (선택사항)

#### macOS
```bash
brew install awscli
aws configure
```

#### Windows
```cmd
# AWS CLI 설치 후
aws configure
```

### 3. S3 버킷 업로드

#### macOS/Windows 공통
```bash
aws s3 cp models/model_meta.json s3://your-bucket/models/
```

### 4. EC2 원격 접속

#### macOS
```bash
ssh -i ~/path/to/key.pem -L 8000:localhost:8000 ec2-user@your-ec2-ip
```

#### Windows
```cmd
ssh -i C:\path\to\key.pem -L 8000:localhost:8000 ec2-user@your-ec2-ip
```

### 5. 백엔드 서버 실행
```bash
uvicorn retrain_server:app --host 0.0.0.0 --port 8000
```

## 데이터베이스 스키마

### training_history 테이블
```sql
CREATE TABLE training_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    model_ver VARCHAR(50) NOT NULL,
    sample_count INT NOT NULL,
    accuracy FLOAT NOT NULL,
    trained_at DATETIME NOT NULL
);
```

### virus_samples 테이블  
```sql
CREATE TABLE virus_samples (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_hash VARCHAR(64) UNIQUE NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    file_size INT NOT NULL,
    source VARCHAR(100) NOT NULL,
    malware_family VARCHAR(100),
    threat_category VARCHAR(100), 
    is_malicious BOOLEAN NOT NULL,
    s3_key VARCHAR(500),
    uploaded_at DATETIME NOT NULL,
    features_json TEXT
);
```

## 문제 해결

### macOS 관련 이슈
- **7zip 설치**: `brew install p7zip`
- **권한 문제**: `chmod +x script_name.py`

### Windows 관련 이슈  
- **7zip 설치**: https://www.7-zip.org/download.html
- **권한 문제**: 관리자 권한으로 실행

### 공통 이슈
- **API 키 오류**: .env 파일에서 키 값 확인
- **모델 로드 실패**: AWS 설정 또는 로컬 파일 확인
- **DB 연결 실패**: RDS 설정 및 보안그룹 확인

## 라이선스 및 주의사항

- 이 시스템은 보안 연구 목적으로만 사용해야 합니다
- 악성 샘플 처리 시 격리된 환경에서 실행하세요
- API 키는 절대 공개하지 마세요