#!/usr/bin/env python3
# setup_env.py - 환경 설정 및 검증 스크립트 v2.2 (EC2 지원)

import os
import sys
import platform
from dotenv import load_dotenv


def create_env_file():
    """새로운 .env 파일 생성 또는 기존 파일 업데이트"""
    print("환경 파일 설정")
    print("=" * 50)

    # 기존 .env 파일 확인
    env_exists = os.path.exists('.env')
    if env_exists:
        print("기존 .env 파일이 발견되었습니다.")

        # 기존 파일 읽기
        with open('.env', 'r', encoding='utf-8') as f:
            existing_content = f.read()

        # 누락된 키 확인
        missing_keys = []
        required_keys = [
            'MALWARE_BAZAAR_API_KEY',
            'VIRUSTOTAL_API_KEY',
            'TRIAGE_API_KEY',
            'USE_AWS',
            'AWS_REGION',
            'S3_BUCKET',
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'SERVER_HOST',
            'SERVER_PORT',
            'EC2_HOST',
            'EC2_USER',
            'EC2_KEY_PATH',
            'EC2_REMOTE_PORT',
            'EC2_LOCAL_PORT',
            'EC2_AUTO_CONNECT'
        ]

        for key in required_keys:
            if key not in existing_content:
                missing_keys.append(key)

        if missing_keys:
            print(f"누락된 설정: {', '.join(missing_keys)}")

            # 누락된 키 추가
            with open('.env', 'a', encoding='utf-8') as f:
                f.write('\n# 추가된 설정들\n')
                for key in missing_keys:
                    if key == 'USE_AWS':
                        f.write(f'{key}=true\n')
                    elif key == 'AWS_REGION':
                        f.write(f'{key}=ap-northeast-2\n')
                    elif key == 'S3_BUCKET':
                        f.write(f'{key}=sanitizer1\n')
                    elif key == 'AWS_ACCESS_KEY_ID':
                        f.write(f'{key}=your_aws_access_key_here\n')
                    elif key == 'AWS_SECRET_ACCESS_KEY':
                        f.write(f'{key}=your_aws_secret_key_here\n')
                    elif key == 'SERVER_HOST':
                        f.write(f'{key}=localhost\n')
                    elif key == 'SERVER_PORT':
                        f.write(f'{key}=8000\n')
                    elif key == 'EC2_HOST':
                        f.write(f'{key}=your-ec2-public-ip\n')
                    elif key == 'EC2_USER':
                        f.write(f'{key}=ec2-user\n')
                    elif key == 'EC2_KEY_PATH':
                        f.write(f'{key}=sanitizer.ec2.pem\n')
                    elif key == 'EC2_REMOTE_PORT':
                        f.write(f'{key}=8000\n')
                    elif key == 'EC2_LOCAL_PORT':
                        f.write(f'{key}=8000\n')
                    elif key == 'EC2_AUTO_CONNECT':
                        f.write(f'{key}=false\n')
                    else:
                        f.write(f'{key}=your_{key.lower()}_here\n')

            print("누락된 설정이 .env 파일에 추가되었습니다.")
        else:
            print("모든 필수 설정이 완료되어 있습니다.")
    else:
        print(".env 파일이 없습니다. 새로 생성합니다...")

        # 새 .env 파일 생성
        env_content = """# 문서형 악성코드 무해화 시스템 v2.2 - 설정파일

# API 키 설정 (필수)
MALWARE_BAZAAR_API_KEY=your_malware_bazaar_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
TRIAGE_API_KEY=your_triage_api_key_here

# 서버 설정 (필수)
SERVER_HOST=localhost
SERVER_PORT=8000

# EC2 연결 설정 (팀 공유용)
EC2_HOST=your-ec2-public-ip
EC2_USER=ec2-user
EC2_KEY_PATH=sanitizer.ec2.pem
EC2_REMOTE_PORT=8000
EC2_LOCAL_PORT=8000
EC2_AUTO_CONNECT=false

# AWS 설정 (선택사항)
USE_AWS=true
AWS_REGION=ap-northeast-2
S3_BUCKET=sanitizer1
AWS_ACCESS_KEY_ID=your_aws_access_key_here
AWS_SECRET_ACCESS_KEY=your_aws_secret_key_here

# RDS 데이터베이스 설정 (선택사항)
RDS_HOST=your-rds-endpoint
RDS_DB=your-database-name
RDS_USER=your-username
RDS_PASSWORD=your-password
"""

        with open('.env', 'w', encoding='utf-8') as f:
            f.write(env_content)

        print("새 .env 파일이 생성되었습니다.")

    print("\n다음 단계:")
    print("1. .env 파일을 열어서 실제 설정값으로 교체하세요")
    print("2. MalwareBazaar: https://bazaar.abuse.ch/api/")
    print("3. VirusTotal: https://www.virustotal.com/gui/my-apikey")
    print("4. EC2 사용시 EC2_HOST를 실제 IP로 변경")
    print("5. sanitizer.ec2.pem 파일을 프로젝트 폴더에 배치")


def setup_ec2_key():
    """EC2 키 파일 설정 및 팀 공유 준비"""
    print("\nEC2 키 파일 설정")
    print("=" * 50)

    # keys 디렉토리 생성
    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)

    key_filename = "sanitizer.ec2.pem"
    project_key_path = os.path.join(keys_dir, key_filename)

    # 현재 디렉토리에서 키 파일 찾기
    if os.path.exists(key_filename):
        # 프로젝트 keys 폴더로 이동
        if not os.path.exists(project_key_path):
            import shutil
            shutil.copy2(key_filename, project_key_path)
            print(f"키 파일을 keys/ 폴더로 이동: {project_key_path}")

        # 원본 파일 삭제 (보안상)
        os.remove(key_filename)
        print("루트 디렉토리의 키 파일 삭제 (보안 강화)")

    if os.path.exists(project_key_path):
        # Unix 계열에서 권한 설정
        if platform.system().lower() != 'windows':
            try:
                os.chmod(project_key_path, 0o600)
                print(f"키 파일 권한 설정 완료 (600): {project_key_path}")
            except Exception as e:
                print(f"권한 설정 실패: {e}")

        print(f"EC2 키 파일 준비 완료: {project_key_path}")

        # .gitignore에 keys/ 폴더 추가
        gitignore_path = ".gitignore"
        gitignore_content = ""

        if os.path.exists(gitignore_path):
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                gitignore_content = f.read()

        if "keys/" not in gitignore_content:
            with open(gitignore_path, 'a', encoding='utf-8') as f:
                if gitignore_content and not gitignore_content.endswith('\n'):
                    f.write('\n')
                f.write("# EC2 키 파일 (보안)\n")
                f.write("keys/\n")
                f.write("*.pem\n")
            print(".gitignore에 키 파일 제외 규칙 추가")

        return True
    else:
        print(f"EC2 키 파일을 찾을 수 없습니다: {key_filename}")
        print("다음 방법으로 키 파일을 준비하세요:")
        print(f"1. {key_filename} 파일을 프로젝트 루트 디렉토리에 배치")
        print("2. python setup_env.py 다시 실행")
        return False


def check_ec2_connection():
    """EC2 연결 확인"""
    print("\nEC2 연결 확인")
    print("=" * 50)

    load_dotenv()

    ec2_host = os.getenv('EC2_HOST')
    ec2_user = os.getenv('EC2_USER', 'ec2-user')
    ec2_local_port = os.getenv('EC2_LOCAL_PORT', '8000')
    ec2_remote_port = os.getenv('EC2_REMOTE_PORT', '8000')

    if not ec2_host or ec2_host == 'your-ec2-public-ip':
        print("EC2 설정이 되어있지 않습니다")
        return False

    print(f"EC2 호스트: {ec2_host}")
    print(f"사용자: {ec2_user}")
    print(f"포트 포워딩: {ec2_local_port} -> {ec2_remote_port}")

    # SSH 클라이언트 확인
    current_os = platform.system().lower()
    ssh_available = False

    if current_os == 'windows':
        ssh_paths = [
            'ssh',
            r'C:\Windows\System32\OpenSSH\ssh.exe',
            r'C:\Program Files\Git\usr\bin\ssh.exe'
        ]

        for ssh_path in ssh_paths:
            try:
                import subprocess
                result = subprocess.run([ssh_path, '-V'],
                                        capture_output=True, timeout=5)
                if result.returncode == 0 or 'OpenSSH' in result.stderr.decode():
                    print(f"SSH 클라이언트 발견: {ssh_path}")
                    ssh_available = True
                    break
            except:
                continue
    else:
        try:
            import subprocess
            result = subprocess.run(['ssh', '-V'],
                                    capture_output=True, timeout=5)
            if result.returncode == 0 or 'OpenSSH' in result.stderr.decode():
                print("SSH 클라이언트 사용 가능")
                ssh_available = True
        except:
            pass

    if not ssh_available:
        print("SSH 클라이언트를 찾을 수 없습니다")
        if current_os == 'windows':
            print("SSH 설치 방법:")
            print("1. Git for Windows 설치")
            print("2. OpenSSH 클라이언트 활성화")
        return False

    # 키 파일 확인
    from config import get_ec2_key_path
    key_path = get_ec2_key_path()

    if not key_path:
        print("EC2 키 파일을 찾을 수 없습니다")
        return False

    print(f"EC2 키 파일: {key_path}")

    print("\nEC2 연결 명령어:")
    print(f"ssh -i {key_path} -L {ec2_local_port}:localhost:{ec2_remote_port} {ec2_user}@{ec2_host}")

    return True


def check_server_status():
    """서버 상태 확인"""
    print("\n서버 연결 확인")
    print("=" * 50)

    load_dotenv()

    server_host = os.getenv('SERVER_HOST', 'localhost')
    server_port = os.getenv('SERVER_PORT', '8000')

    print(f"설정된 서버: {server_host}:{server_port}")

    try:
        import requests

        server_urls = [
            f"http://{server_host}:{server_port}",
            f"http://localhost:{server_port}",
            f"http://127.0.0.1:{server_port}"
        ]

        connected = False
        for url in server_urls:
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    print(f"서버 연결 성공: {url}")
                    connected = True
                    break
            except:
                continue

        if not connected:
            print("서버 연결 실패")
            print("\n내장 서버 사용:")
            print("  python main.py (자동으로 내장 서버 시작)")
            print("\nEC2 서버 사용:")
            print("  1. EC2 SSH 터널링 연결")
            print("  2. python main.py")

        return connected

    except ImportError:
        print("requests 모듈이 필요합니다: pip install requests")
        return False


def create_directories():
    """필요한 디렉토리들 생성"""
    print("\n디렉토리 구조 생성")
    print("=" * 50)

    directories = [
        'sample/mecro',  # 악성 샘플
        'sample/clear',  # 자체생성 클린파일
        'sample/clean',  # 무해화된 파일
        'models',  # AI 모델
        'temp',  # 임시 파일
        'temp_db_samples',  # DB 샘플 임시 저장
        'keys'  # EC2 키 파일
    ]

    created_count = 0
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"생성됨: {directory}/")
            created_count += 1
        else:
            print(f"존재함: {directory}/")

    print(f"\n{created_count}개 디렉토리가 생성되었습니다.")


def check_api_keys():
    """API 키 설정 확인"""
    print("\nAPI 키 설정 확인")
    print("=" * 50)

    load_dotenv()

    # 각 API 키 확인
    keys_status = {}

    # MalwareBazaar
    mb_key = os.getenv('MALWARE_BAZAAR_API_KEY')
    if mb_key and mb_key != 'your_malware_bazaar_api_key_here':
        keys_status['MalwareBazaar'] = '설정됨'
    else:
        keys_status['MalwareBazaar'] = '미설정'

    # VirusTotal
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    if vt_key and vt_key != 'your_virustotal_api_key_here':
        keys_status['VirusTotal'] = '설정됨'
    else:
        keys_status['VirusTotal'] = '미설정'

    # Tria.ge (선택사항)
    triage_key = os.getenv('TRIAGE_API_KEY')
    if triage_key and triage_key != 'your_triage_api_key_here':
        keys_status['Tria.ge'] = '설정됨 (선택사항)'
    else:
        keys_status['Tria.ge'] = '미설정 (선택사항)'

    # 서버 설정
    server_host = os.getenv('SERVER_HOST')
    server_port = os.getenv('SERVER_PORT')
    if server_host and server_port:
        keys_status['서버 설정'] = '설정됨'
    else:
        keys_status['서버 설정'] = '미설정'

    # EC2 설정
    ec2_host = os.getenv('EC2_HOST')
    if ec2_host and ec2_host != 'your-ec2-public-ip':
        keys_status['EC2 설정'] = '설정됨'
    else:
        keys_status['EC2 설정'] = '미설정 (선택사항)'

    # AWS 설정
    use_aws = os.getenv('USE_AWS', 'false').lower() == 'true'
    if use_aws:
        aws_region = os.getenv('AWS_REGION')
        s3_bucket = os.getenv('S3_BUCKET')
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')

        if (aws_region and s3_bucket and s3_bucket != 'your-bucket-name' and
                aws_access_key and aws_access_key != 'your_aws_access_key_here' and
                aws_secret_key and aws_secret_key != 'your_aws_secret_key_here'):
            keys_status['AWS'] = '설정됨'
        else:
            keys_status['AWS'] = '부분 설정'
    else:
        keys_status['AWS'] = '비활성화'

    # 결과 출력
    for service, status in keys_status.items():
        print(f"  {service}: {status}")

    # 필수 키 확인
    required_set = (mb_key and mb_key != 'your_malware_bazaar_api_key_here' and
                    vt_key and vt_key != 'your_virustotal_api_key_here' and
                    server_host and server_port)

    if required_set:
        print("\n필수 설정이 모두 완료되었습니다!")
        return True
    else:
        print("\n필수 설정이 완료되지 않았습니다.")
        print("   .env 파일을 열어서 실제 설정값으로 교체해주세요.")
        return False


def test_api_connections():
    """API 연결 테스트"""
    print("\nAPI 연결 테스트")
    print("=" * 50)

    try:
        from utils.api_client import APIClient

        client = APIClient()

        # MalwareBazaar 테스트
        print("MalwareBazaar 테스트 중...")
        mb_result = client.test_malware_bazaar_connection()
        print(f"  결과: {'연결 성공' if mb_result else '연결 실패'}")

        # VirusTotal 테스트
        print("\nVirusTotal 테스트 중...")
        vt_result = client.test_virustotal_connection()
        print(f"  결과: {'연결 성공' if vt_result else '연결 실패'}")

        return mb_result and vt_result

    except ImportError as e:
        print(f"모듈 임포트 실패: {e}")
        print("   필요한 패키지를 설치하세요: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"연결 테스트 실패: {e}")
        return False


def install_dependencies():
    """필요한 패키지 설치"""
    print("\n의존성 패키지 설치")
    print("=" * 50)

    try:
        import subprocess

        # requirements.txt에서 패키지 설치
        if os.path.exists('requirements.txt'):
            print("requirements.txt에서 패키지 설치 중...")
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print("모든 패키지 설치 완료")
                return True
            else:
                print(f"패키지 설치 실패: {result.stderr}")
                return False
        else:
            print("requirements.txt 파일이 없습니다")
            return False

    except Exception as e:
        print(f"설치 중 오류: {e}")
        return False


def check_aws_config():
    """AWS 설정 확인"""
    print("\nAWS 설정 확인")
    print("=" * 50)

    load_dotenv()
    use_aws = os.getenv('USE_AWS', 'false').lower() == 'true'

    if not use_aws:
        print("AWS 사용 안함 (USE_AWS=false)")
        return True

    # AWS 관련 환경변수 확인
    aws_region = os.getenv('AWS_REGION')
    s3_bucket = os.getenv('S3_BUCKET')
    aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    rds_host = os.getenv('RDS_HOST')

    print(f"AWS Region: {aws_region or '미설정'}")
    print(f"S3 Bucket: {s3_bucket or '미설정'}")
    print(f"AWS Access Key: {'설정됨' if aws_access_key and aws_access_key != 'your_aws_access_key_here' else '미설정'}")
    print(f"AWS Secret Key: {'설정됨' if aws_secret_key and aws_secret_key != 'your_aws_secret_key_here' else '미설정'}")
    print(f"RDS Host: {rds_host or '미설정 (선택사항)'}")

    # boto3 설치 확인
    try:
        import boto3
        print("boto3 라이브러리: 설치됨")

        # AWS 자격증명 확인
        if aws_access_key and aws_secret_key:
            print("AWS 자격증명: .env 파일에서 설정됨")
            return True
        else:
            try:
                session = boto3.Session()
                credentials = session.get_credentials()
                if credentials:
                    print("AWS 자격증명: 기본 설정에서 발견됨")
                    return True
                else:
                    print("AWS 자격증명: 미설정")
                    print("   .env 파일에 AWS_ACCESS_KEY_ID와 AWS_SECRET_ACCESS_KEY 설정 필요")
                    return False
            except Exception as cred_error:
                print(f"AWS 자격증명 확인 실패: {cred_error}")
                return False

    except ImportError:
        print("boto3 라이브러리: 미설치")
        print("   설치 명령어: pip install boto3")
        return False


def main():
    """메인 설정 프로세스"""
    print("문서형 악성코드 무해화 시스템 v2.2 - 환경 설정")
    print("=" * 60)

    # 1. 디렉토리 생성
    create_directories()

    # 2. .env 파일 생성/확인
    create_env_file()

    # 3. EC2 키 파일 설정
    ec2_key_ok = setup_ec2_key()

    # 4. 의존성 설치
    deps_ok = install_dependencies()

    # 5. API 키 확인
    keys_ok = check_api_keys()

    # 6. 서버 상태 확인
    server_ok = check_server_status()

    # 7. EC2 연결 확인
    ec2_ok = check_ec2_connection() if ec2_key_ok else True

    # 8. AWS 설정 확인
    aws_ok = check_aws_config()

    # 9. API 연결 테스트 (키가 설정된 경우만)
    if keys_ok:
        connections_ok = test_api_connections()
    else:
        connections_ok = False

    # 최종 결과
    print("\n" + "=" * 60)
    print("설정 완료 상태")
    print("=" * 60)
    print(f"디렉토리 구조: 완료")
    print(f"의존성 패키지: {'완료' if deps_ok else '실패'}")
    print(f"API 키 설정: {'완료' if keys_ok else '필요'}")
    print(f"서버 연결: {'완료' if server_ok else '내장 서버 사용'}")
    print(f"EC2 키 파일: {'완료' if ec2_key_ok else '선택사항'}")
    print(f"EC2 연결: {'완료' if ec2_ok else '선택사항'}")
    print(f"AWS 설정: {'완료' if aws_ok else '선택사항'}")
    print(f"API 연결: {'완료' if connections_ok else '확인 필요'}")

    if all([deps_ok, keys_ok]):
        print("\n기본 설정이 완료되었습니다!")
        print("다음 명령어로 시스템을 시작할 수 있습니다:")
        print("  python main.py")

        if ec2_key_ok:
            print("\nEC2 서버 사용:")
            load_dotenv()
            ec2_host = os.getenv('EC2_HOST')
            if ec2_host and ec2_host != 'your-ec2-public-ip':
                ec2_user = os.getenv('EC2_USER', 'ec2-user')
                ec2_local_port = os.getenv('EC2_LOCAL_PORT', '8000')
                ec2_remote_port = os.getenv('EC2_REMOTE_PORT', '8000')
                from config import get_ec2_key_path
                key_path = get_ec2_key_path()
                print(f"  ssh -i {key_path} -L {ec2_local_port}:localhost:{ec2_remote_port} {ec2_user}@{ec2_host}")

    else:
        print("\n일부 설정이 완료되지 않았습니다.")

        if not keys_ok:
            print("\nAPI 키 설정 방법:")
            print("1. .env 파일을 텍스트 에디터로 열기")
            print("2. 'your_api_key_here' 부분을 실제 발급받은 키로 교체")
            print("3. 파일 저장 후 다시 실행")

        if not ec2_key_ok:
            print("\nEC2 키 파일 설정 방법:")
            print("1. sanitizer.ec2.pem 파일을 프로젝트 루트에 배치")
            print("2. python setup_env.py 다시 실행")
            print("3. .env에서 EC2_HOST를 실제 IP로 변경")


if __name__ == "__main__":
    main()