# config.py - 개선된 설정 (정상/악성 비율 조정)
import os
import socket
import platform
from dotenv import load_dotenv

load_dotenv()

USE_AWS = os.getenv("USE_AWS", "false").lower() == "true"
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-2")
S3_BUCKET = os.getenv("S3_BUCKET", "malware-sample-878585013612")

RDS_HOST = os.getenv("RDS_HOST")
RDS_DB = os.getenv("RDS_DB")
RDS_USER = os.getenv("RDS_USER")
RDS_PASSWORD = os.getenv("RDS_PASSWORD")

# EC2 연결 설정
EC2_HOST = os.getenv("EC2_HOST")
EC2_USER = os.getenv("EC2_USER", "ec2-user")
EC2_KEY_PATH = os.getenv("EC2_KEY_PATH", "sanitizer.ec2.pem")
EC2_REMOTE_PORT = os.getenv("EC2_REMOTE_PORT", "8000")
EC2_LOCAL_PORT = os.getenv("EC2_LOCAL_PORT", "8000")

# API 키 설정
API_KEYS = {
    'malwarebazaar': os.getenv('MALWARE_BAZAAR_API_KEY'),
    'triage': os.getenv('TRIAGE_API_KEY'),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
}

# API 엔드포인트 설정
API_ENDPOINTS = {
    'malwarebazaar_api': 'https://mb-api.abuse.ch/api/v1/',
    'triage_api': 'https://api.tria.ge/v0/',
    'triage_samples': 'https://api.tria.ge/v0/samples',
    'triage_search': 'https://api.tria.ge/v0/search',
    'virustotal_api': 'https://www.virustotal.com/api/v3/'
}

# 샘플 수집 설정 (악성 비율 증가, 정상 비율 감소)
SAMPLE_LIMITS = {
    'total_malware_target': 400,      # 악성 샘플 목표 증가
    'total_clean_target': 200,        # 정상 샘플 목표 감소
    'minimum_per_type': 50,
    'pdf_target': 120,                # PDF 악성 샘플 증가
    'word_target': 120,               # Word 악성 샘플 증가
    'excel_target': 80,
    'powerpoint_target': 60,
    'hwp_target': 40,
    'rtf_target': 20,
    'malwarebazaar_share': 0.6,       # MalwareBazaar 60%
    'triage_share': 0.4,              # Tria.ge 40%
    'clean_sample_ratio_limit': 0.5,  # 정상:악성 = 1:2 비율 (악성이 더 많음)
    'virustotal_verified_clean_ratio': 0.8,  # 정상 샘플의 80%는 VirusTotal 검증 필요
    'local_generated_clean_limit': 20  # 로컬 생성 정상 샘플 최대 20개
}

# 디렉토리 설정
DIRECTORIES = {
    'malware_samples': 'sample/mecro',
    'clean_samples': 'sample/clear',
    'sanitized_output': 'sample/clean',
    'models': 'models',
    'temp': 'temp',
    'temp_db_samples': 'temp_db_samples',
    'ec2_keys': 'keys'
}

# 악성코드 분류 매핑 (확장됨)
MALWARE_CLASSIFICATIONS = {
    'emotet': {
        'family': 'Trojan.Emotet',
        'type': '뱅킹 트로이목마',
        'threat_level': '높음',
        'description': '이메일을 통해 전파되며 금융정보를 탈취하고 추가 악성코드를 다운로드'
    },
    'trickbot': {
        'family': 'Trojan.TrickBot',
        'type': '뱅킹 트로이목마',
        'threat_level': '높음',
        'description': '온라인 뱅킹 자격증명을 훔치고 랜섬웨어 배포에 사용'
    },
    'qakbot': {
        'family': 'Trojan.QakBot',
        'type': '정보 탈취 트로이목마',
        'threat_level': '높음',
        'description': '이메일 자격증명과 금융정보를 탈취하며 네트워크 내 횡적 이동'
    },
    'formbook': {
        'family': 'Trojan.FormBook',
        'type': '정보 수집 트로이목마',
        'threat_level': '중간',
        'description': '키로거 기능으로 사용자 입력을 수집하고 웹브라우저 정보 탈취'
    },
    'agent_tesla': {
        'family': 'Trojan.AgentTesla',
        'type': '원격 접근 트로이목마',
        'threat_level': '중간',
        'description': '키로깅, 스크린샷 캡처, 웹캠 액세스 등 원격 모니터링'
    },
    'lokibot': {
        'family': 'Trojan.LokiBot',
        'type': '정보 탈취 트로이목마',
        'threat_level': '중간',
        'description': 'FTP, 이메일, 웹브라우저 자격증명과 암호화폐 지갑 정보 탈취'
    },
    'macro_malware': {
        'family': 'Trojan.MacroMalware',
        'type': '매크로 악성코드',
        'threat_level': '중간',
        'description': 'Office 문서의 매크로를 통해 실행되는 악성코드'
    },
    'pdf_exploit': {
        'family': 'Exploit.PDF',
        'type': 'PDF 익스플로잇',
        'threat_level': '높음',
        'description': 'PDF 뷰어의 취약점을 악용하여 악성코드를 실행'
    },
    'hwp_malware': {
        'family': 'Trojan.HWP',
        'type': 'HWP 악성코드',
        'threat_level': '중간',
        'description': '한글 문서에 포함된 스크립트를 통해 악성 행위 수행'
    },
    'generic_office': {
        'family': 'Trojan.OfficeDoc',
        'type': 'Office 문서 악성코드',
        'threat_level': '중간',
        'description': 'Office 문서를 통해 전파되는 일반적인 악성코드'
    }
}

# VirusTotal 설정 (개선됨)
VIRUSTOTAL_CONFIG = {
    'clean_threshold': 0,           # 악성 탐지 0개여야 정상으로 인정
    'suspicious_threshold': 0,      # 의심 탐지도 0개여야 함
    'minimum_engines': 15,          # 최소 15개 엔진에서 검사되어야 함
    'request_delay': 1.0,          # API 요청 간격 (초)
    'timeout': 30,                 # 요청 타임아웃 (초)
    'retry_count': 3,              # 재시도 횟수
    'clean_sample_sources': [       # 정상 샘플 검색 소스
        'type:pdf positives:0 size:100KB+',
        'type:office positives:0 size:50KB+',
        'type:document positives:0 engines:20+'
    ]
}

# 네트워크 및 서버 설정 개선
def get_local_ip():
    """로컬 IP 주소 자동 감지"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_hostname():
    """호스트명 조회"""
    try:
        return socket.gethostname()
    except Exception:
        return "localhost"


# 서버 연결 설정
SERVER_HOST = os.getenv("SERVER_HOST", get_local_ip())
SERVER_PORT = os.getenv("SERVER_PORT", "8000")

# 다중 서버 URL 생성
SERVER_URLS = [
    f"http://{SERVER_HOST}:{SERVER_PORT}",
    f"http://{get_local_ip()}:{SERVER_PORT}",
    f"http://{get_hostname()}:{SERVER_PORT}",
    f"http://localhost:{SERVER_PORT}",
    f"http://127.0.0.1:{SERVER_PORT}"
]

# 중복 제거
SERVER_URLS = list(dict.fromkeys(SERVER_URLS))

# 기본 서버 URL
SERVER_URL = SERVER_URLS[0]


def get_ec2_key_path():
    """EC2 키 파일 경로 자동 감지 (플랫폼별)"""
    current_os = platform.system().lower()

    # 환경변수에서 설정된 경우 우선 사용
    if EC2_KEY_PATH and os.path.exists(EC2_KEY_PATH):
        return EC2_KEY_PATH

    # 프로젝트 내 keys 디렉토리 확인
    project_key_path = os.path.join(DIRECTORIES['ec2_keys'], 'sanitizer.ec2.pem')
    if os.path.exists(project_key_path):
        return project_key_path

    # 현재 디렉토리 확인
    current_dir_key = 'sanitizer.ec2.pem'
    if os.path.exists(current_dir_key):
        return current_dir_key

    # 플랫폼별 기본 경로
    if current_os == 'windows':
        possible_paths = [
            os.path.join(os.path.expanduser('~'), 'Downloads', 'sanitizer.ec2.pem'),
            os.path.join('C:', 'keys', 'sanitizer.ec2.pem'),
            os.path.join(os.path.expanduser('~'), '.ssh', 'sanitizer.ec2.pem')
        ]
    else:  # macOS, Linux
        possible_paths = [
            os.path.join(os.path.expanduser('~'), 'Downloads', 'sanitizer.ec2.pem'),
            os.path.join(os.path.expanduser('~'), '.ssh', 'sanitizer.ec2.pem'),
            '/tmp/sanitizer.ec2.pem'
        ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    return None


def setup_ec2_key():
    """EC2 키 파일 설정 및 권한 조정"""
    key_path = get_ec2_key_path()

    if not key_path:
        print("[EC2] sanitizer.ec2.pem 파일을 찾을 수 없습니다")
        return None

    # keys 디렉토리가 없으면 생성
    os.makedirs(DIRECTORIES['ec2_keys'], exist_ok=True)

    # 프로젝트 내부로 키 파일 복사 (없는 경우)
    project_key_path = os.path.join(DIRECTORIES['ec2_keys'], 'sanitizer.ec2.pem')

    if key_path != project_key_path and not os.path.exists(project_key_path):
        try:
            import shutil
            shutil.copy2(key_path, project_key_path)
            key_path = project_key_path
            print(f"[EC2] 키 파일을 프로젝트 디렉토리로 복사: {project_key_path}")
        except Exception as e:
            print(f"[EC2] 키 파일 복사 실패: {e}")

    # Unix 계열에서 권한 설정
    if platform.system().lower() != 'windows':
        try:
            os.chmod(key_path, 0o600)
            print(f"[EC2] 키 파일 권한 설정 완료: {key_path}")
        except Exception as e:
            print(f"[EC2] 키 파일 권한 설정 실패: {e}")

    return key_path


def get_ssh_command():
    """플랫폼별 SSH 명령어 생성"""
    if not EC2_HOST:
        return None

    key_path = setup_ec2_key()
    if not key_path:
        return None

    current_os = platform.system().lower()

    # 기본 SSH 명령어
    ssh_cmd = [
        'ssh', '-i', key_path,
        '-L', f'{EC2_LOCAL_PORT}:localhost:{EC2_REMOTE_PORT}',
        f'{EC2_USER}@{EC2_HOST}'
    ]

    # Windows에서는 ssh.exe 경로 확인
    if current_os == 'windows':
        ssh_paths = [
            'ssh',  # PATH에 있는 경우
            r'C:\Windows\System32\OpenSSH\ssh.exe',
            r'C:\Program Files\Git\usr\bin\ssh.exe'
        ]

        ssh_executable = None
        for ssh_path in ssh_paths:
            try:
                import subprocess
                result = subprocess.run([ssh_path, '-V'],
                                        capture_output=True, timeout=5)
                if result.returncode == 0 or 'OpenSSH' in result.stderr.decode():
                    ssh_executable = ssh_path
                    break
            except:
                continue

        if ssh_executable:
            ssh_cmd[0] = ssh_executable
        else:
            print("[EC2] SSH 클라이언트를 찾을 수 없습니다")
            return None

    return ssh_cmd


def connect_to_ec2():
    """EC2 터널링 연결 수행"""
    ssh_cmd = get_ssh_command()

    if not ssh_cmd:
        print("[EC2] SSH 명령어 생성 실패")
        return False

    try:
        import subprocess

        print(f"[EC2] 연결 시도: {EC2_HOST}")
        print(f"[EC2] 포트 포워딩: {EC2_LOCAL_PORT} -> {EC2_REMOTE_PORT}")
        print(f"[EC2] SSH 명령어: {' '.join(ssh_cmd)}")

        # 백그라운드로 SSH 터널링 실행
        process = subprocess.Popen(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # 잠시 대기 후 연결 확인
        import time
        time.sleep(3)

        if process.poll() is None:  # 프로세스가 아직 실행 중
            print(f"[EC2] 터널링 연결 성공")
            print(f"[EC2] 로컬 접속 URL: http://localhost:{EC2_LOCAL_PORT}")
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"[EC2] 연결 실패: {stderr.decode()}")
            return False

    except Exception as e:
        print(f"[EC2] 연결 오류: {e}")
        return False


# EC2 설정
EC2_CONFIG = {
    'enabled': bool(EC2_HOST),
    'host': EC2_HOST,
    'user': EC2_USER,
    'key_path': EC2_KEY_PATH,
    'remote_port': EC2_REMOTE_PORT,
    'local_port': EC2_LOCAL_PORT,
    'auto_connect': os.getenv('EC2_AUTO_CONNECT', 'false').lower() == 'true'
}

# 네트워크 설정
NETWORK_CONFIG = {
    'connection_timeout': 10,
    'read_timeout': 30,
    'max_retries': 3,
    'retry_delay': 1.0,
    'server_urls': SERVER_URLS,
    'auto_failover': True,
    'ec2_enabled': EC2_CONFIG['enabled']
}

# RDS 연결 설정
RDS_CONFIG = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_recycle': 280,
    'pool_timeout': 30,
    'echo': False,
    'connect_timeout': 10
}

# 자동화 설정 (개선됨)
AUTOMATION_CONFIG = {
    'auto_upload_to_s3': True,
    'auto_save_to_rds': True,
    'duplicate_check': True,
    'feature_extraction': True,
    'cleanup_temp_files': True,
    'secure_delete_malware': True,
    'ec2_auto_connect': EC2_CONFIG['auto_connect'],
    'balance_dataset': True,           # 데이터셋 균형 조정
    'verify_clean_samples': True,      # 정상 샘플 검증 강화
    'malware_ratio_preference': 0.65   # 악성 샘플 비율 선호도
}

# 보안 설정
SECURITY_CONFIG = {
    'secure_file_deletion': True,
    'malware_isolation': True,
    'temp_file_cleanup': True,
    'rds_verification': True,
    'local_malware_auto_delete': True,
    'ec2_key_protection': True,
    'virustotal_verification': True    # VirusTotal 검증 필수
}

# 성능 최적화 설정
PERFORMANCE_CONFIG = {
    'batch_size': 100,
    'parallel_processing': True,
    'memory_limit_mb': 1024,
    'cache_features': True,
    'compress_samples': True,
    'duplicate_filter_early': True,
    'smart_sampling': True            # 스마트 샘플링 활성화
}

# 로그 설정
LOGGING_CONFIG = {
    'level': 'INFO',
    'max_size_mb': 10,
    'backup_count': 5,
    'enable_file_logging': True,
    'enable_console_logging': True,
    'ec2_connection_logs': True
}


# 디렉토리 자동 생성
def ensure_directories():
    """필요한 디렉토리들을 자동으로 생성"""
    for dir_path in DIRECTORIES.values():
        os.makedirs(dir_path, exist_ok=True)


# 설정 검증
def validate_config():
    """설정 유효성 검사"""
    issues = []

    # API 키 확인
    if not API_KEYS['malwarebazaar']:
        issues.append("MALWARE_BAZAAR_API_KEY가 설정되지 않음")

    if not API_KEYS['virustotal']:
        issues.append("VIRUSTOTAL_API_KEY가 설정되지 않음")

    # AWS 설정 확인
    if USE_AWS:
        if not S3_BUCKET or S3_BUCKET == "your-bucket-name":
            issues.append("S3_BUCKET이 올바르게 설정되지 않음")

        if not RDS_HOST:
            issues.append("RDS_HOST가 설정되지 않음")

    # EC2 설정 확인
    if EC2_CONFIG['enabled']:
        key_path = get_ec2_key_path()
        if not key_path:
            issues.append("EC2 키 파일(sanitizer.ec2.pem)을 찾을 수 없음")
        elif not os.path.exists(key_path):
            issues.append(f"EC2 키 파일이 존재하지 않음: {key_path}")

    # 디렉토리 확인
    for name, path in DIRECTORIES.items():
        if not os.path.exists(path):
            try:
                os.makedirs(path, exist_ok=True)
            except Exception as e:
                issues.append(f"디렉토리 생성 실패 ({name}): {e}")

    return issues


# 시스템 정보 조회
def get_system_info():
    """시스템 및 네트워크 정보 조회"""
    import platform

    return {
        'platform': platform.system(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'hostname': get_hostname(),
        'local_ip': get_local_ip(),
        'server_urls': SERVER_URLS,
        'aws_enabled': USE_AWS,
        'rds_configured': bool(RDS_HOST),
        'ec2_configured': EC2_CONFIG['enabled'],
        'ec2_host': EC2_HOST,
        'ec2_key_available': bool(get_ec2_key_path()),
        'api_keys_configured': {
            'malwarebazaar': bool(API_KEYS['malwarebazaar']),
            'virustotal': bool(API_KEYS['virustotal']),
            'triage': bool(API_KEYS['triage'])
        },
        'sample_collection_config': SAMPLE_LIMITS,
        'virustotal_config': VIRUSTOTAL_CONFIG
    }


# 초기화 시 디렉토리 생성 및 설정 검증
ensure_directories()

# EC2 키 파일 설정 (필요한 경우)
if EC2_CONFIG['enabled']:
    setup_ec2_key()

# 설정 검증 결과 (개발 모드에서만 출력)
if __name__ == "__main__":
    print("문서형 악성코드 무해화 시스템 v2.2 - 설정 정보")
    print("=" * 50)

    # 시스템 정보
    sys_info = get_system_info()
    print(f"플랫폼: {sys_info['platform']} {sys_info['architecture']}")
    print(f"Python: {sys_info['python_version']}")
    print(f"호스트명: {sys_info['hostname']}")
    print(f"로컬 IP: {sys_info['local_ip']}")

    # 서버 URL들
    print(f"\n서버 URL 후보:")
    for i, url in enumerate(SERVER_URLS, 1):
        print(f"  {i}. {url}")

    # API 키 상태
    print(f"\nAPI 키 설정:")
    for service, configured in sys_info['api_keys_configured'].items():
        status = "설정됨" if configured else "미설정"
        print(f"  {service}: {status}")

    # AWS 상태
    print(f"\nAWS 연동: {'활성화' if USE_AWS else '비활성화'}")
    if USE_AWS:
        print(f"  S3 버킷: {S3_BUCKET}")
        print(f"  RDS 설정: {'완료' if RDS_HOST else '미완료'}")

    # EC2 상태
    print(f"\nEC2 연결: {'활성화' if EC2_CONFIG['enabled'] else '비활성화'}")
    if EC2_CONFIG['enabled']:
        print(f"  EC2 호스트: {EC2_HOST}")
        print(f"  키 파일: {'사용 가능' if sys_info['ec2_key_available'] else '없음'}")
        print(f"  포트 포워딩: {EC2_LOCAL_PORT} -> {EC2_REMOTE_PORT}")

    # 샘플 수집 설정
    print(f"\n샘플 수집 설정:")
    print(f"  악성 샘플 목표: {SAMPLE_LIMITS['total_malware_target']}개")
    print(f"  정상 샘플 목표: {SAMPLE_LIMITS['total_clean_target']}개")
    print(f"  정상/악성 비율 제한: {SAMPLE_LIMITS['clean_sample_ratio_limit']}")
    print(f"  VirusTotal 검증 비율: {SAMPLE_LIMITS['virustotal_verified_clean_ratio']}")

    # 설정 검증
    issues = validate_config()
    if issues:
        print(f"\n설정 이슈:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print(f"\n모든 설정이 올바르게 구성되었습니다.")