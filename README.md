문서형 악성코드 무해화 시스템 v2.2 Microsoft Office, PDF, 한글 문서의 악성코드 탐지 및 무해화 시스템


# 빠른 시작   
```1. Mac OS```
```sh
python test_api.py setup
```
```sh
python main.py
```

```2. Windows OS```
```sh
python test_api.py setup
```
```sh
python main.py
```

# 환경 설정
```1. Mac OS```
```sh
pip install -r requirements.txt
```
```sh
cp .env.example .env
```
(.env 파일을 열어서 실제 API 키로 교체)

```2. Windows OS```
```sh
pip install -r requirements.txt
```
```sh
copy .env.example .env
```
(.env 파일을 메모장으로 열어서 실제 API 키로 교체)

```3. API 키 발급```
```sh
MalwareBazaar: https://bazaar.abuse.ch/api/
```
```sh
VirusTotal: https://www.virustotal.com/gui/my-apikey
```

# 프로젝트 다운로드(클론) 및 git 사용법

```
 1 프로젝트 다운로드(클론)
  - sourcetree 상단에 clone 버튼 클릭
  - 소스경로(https://github.com/bgeun31/doc_sanitizer), 목적지 경로(탐색 누르고 본인이 원하는 저장할 폴더 선택) 입력
  - 클론(clone) 클릭
  - 저장할 폴더에 정상적으로 프로젝트 파일들이 다운됐는지 확인

 2. git branch 생성 (최초 1회만 진행)
  - 상단에 브랜치 클릭
  - 새 브랜치 항목에 본인이 작업할 공간의 이름을 입력 후 브랜치 생성 클릭 (ex. dev.song)
  - 왼쪽 사이드바에 본인 브랜치에 점이 있는지 확인(현재 브랜치 확인)
  - 이후 다시 클론할 경우 왼쪽 사이드바에 원격-origin-본인 브랜치 순으로 클릭해서 이동하면 됨.

 3. git commit, pull, push 사용법
  - 본인이 코드를 수정하거나 작업하면 왼쪽 사이드바 '파일 상태'에 변경된 파일 목록이 뜸.
  - commit할 파일들을 올리고 하단 창에 본인이 작업한 내용을 작성하고 커밋을 하면 됨.
  - 작업하는 동안 commit을 진행하고 작업이 완료되면 상단에 push를 누르고 본인 브랜치만 체크한 후 Push 진행.
  - Github 본인 브랜치에 작업한 내용이 잘 올라갔는지 확인.
```


# 주요 기능
```
AI 기반 탐지: 머신러닝 모델을 통한 악성코드 예측
룰 기반 탐지: Office 매크로, PDF JavaScript, HWP 스크립트 탐지
VirusTotal 검증: 온라인 바이러스 검사 서비스 연동
문서 무해화: 악성 요소 제거 및 안전한 문서 생성
지원 파일 형식
Microsoft Office: .docx, .docm, .xlsx, .xlsm, .pptx, .pptm
PDF: .pdf
한글: .hwp, .hwpx, .hwpml
```

# 폴더 구조
```
doc_sanitizer/
├── main.py                 # GUI 메인 애플리케이션
├── test_api.py            # 시스템 테스트 및 설정
├── config.py              # API 설정 관리
├── utils/                 # 핵심 모듈
├── sample/
│   ├── mecro/             # 악성 샘플 (로컬만)
│   └── clear/             # 정상/정리된 파일
└── models/                # 훈련된 AI 모델
```

# 디버깅
```sh
python force_retrain.py
```
```sh
python debug_env.py
```

# Git 사용법
1. 새 브랜치 생성 및 커밋/푸쉬
```sh
git checkout -b dev.your_name
```
```sh
git add .
```
```sh
git commit -m "작업 내용"
```
```sh
git push origin dev.your_name
```
2. 동기화
```sh
git pull origin dev
```
- sample/mecro/ 폴더는 로컬에만 존재
- 모델 파일은 용량 문제로 Git에서 제외됨

# AWS EC2 시그니처 모델 관련 명령어
1. S3 버킷 업로드
```sh
aws s3 cp models/model_meta.json s3://doc-sanitizer-bucket/models/
```
2. CLI 원격 접속
```sh
ssh -i <키 경로> -L 8000:localhost:8000 ec2-user@<EC2 인스턴스 IP>
```
(키 경로 예시: C:\Users\sskm0\sanitizer_key.pem)
3. 백엔드 서버 열기
```sh
uvicorn retrain_server:app --host 0.0.0.0 --port 8000
```
