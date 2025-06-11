# -*- coding: utf-8 -*-

import os
import requests
import time
import hashlib
import json
from typing import List, Tuple
from dotenv import load_dotenv

# 로컬 모듈 임포트를 위한 경로 설정
# 스크립트 실행 위치에 따라 모듈을 찾지 못하는 경우를 방지합니다.
try:
    import config
    from utils import db, aws_helper
except ImportError:
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import config
    from utils import db, aws_helper

# .env 파일에서 환경 변수 로드
load_dotenv()


class APIClient:
    """
    악성코드 정보 수집을 위한 외부 API(MalwareBazaar, VirusTotal, Tria.ge) 클라이언트.
    각 API와의 통신, 샘플 다운로드, 메타데이터 저장을 담당합니다.
    """

    def __init__(self):
        """API 클라이언트 초기화"""
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.triage_key = os.getenv('TRIAGE_API_KEY')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DocSanitizer/2.2'  # 요청 식별을 위한 User-Agent
        })

    def test_malware_bazaar_connection(self) -> bool:
        """MalwareBazaar API 연결을 테스트합니다."""
        if not self.malware_bazaar_key:
            return False
        try:
            headers = {'Auth-Key': self.malware_bazaar_key}
            data = {
                'query': 'get_info',
                'hash': '094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d'
            }
            response = self.session.post('https://mb-api.abuse.ch/api/v1/', data=data, headers=headers, timeout=10)
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/json' in content_type:
                try:
                    return response.json().get('query_status') != 'no_api_key'
                except Exception:
                    return False
            return False
        except requests.RequestException:
            return False


    def test_virustotal_connection(self) -> bool:
        """VirusTotal API 연결을 테스트합니다."""
        if not self.virustotal_key:
            return False
        try:
            headers = {'x-apikey': self.virustotal_key}
            response = self.session.get('https://www.virustotal.com/api/v3/users/current', headers=headers, timeout=10)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def test_triage_connection(self) -> bool:
        """Tria.ge API 연결을 테스트합니다."""
        if not self.triage_key:
            return False
        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}
            response = self.session.get('https://api.tria.ge/v0/samples', headers=headers, params={'limit': 1},
                                        timeout=10)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def _download_sample(self, sha256_hash: str, file_ext: str) -> str | None:
        """
        MalwareBazaar에서 단일 샘플을 내려받아 로컬에 저장한다.

        Parameters
        ----------
        sha256_hash : str
            다운로드할 샘플의 SHA-256 해시
        file_ext : str
            파일 확장자(“.doc”, “.docm”, “.xlsx” 등)

        Returns
        -------
        str | None
            성공 시 로컬 저장 경로, 실패 시 None
        """
        import io
        import json
        import os
        import shutil

        import pyzipper

        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_file", "sha256_hash": sha256_hash}
        headers = {"API-KEY": self.malware_bazaar_key}

        try:
            response = self.session.post(url, data=data, headers=headers, timeout=60)
        except Exception as e:
            print(f"  -> [오류] HTTP 요청 실패: {e}")
            return None

        # ---- 성공적인 HTTP 응답 처리 ----
        if response.status_code == 200:
            # 1) 크기가 비정상적으로 작으면 오류로 간주
            if len(response.content) < 100:
                print("  -> [오류] 응답이 비정상적으로 작음")
                return None

            # 2) ZIP 시그니처 우선 판별
            is_zip = response.content.startswith(b"PK\x03\x04")

            # 3) 헤더는 JSON, 내용은 ZIP일 수도 있음
            if not is_zip and "json" in response.headers.get("Content-Type", "").lower():
                try:
                    err_json = response.json()
                    print(f"  -> [오류] MalwareBazaar 오류 응답: {err_json}")
                    return None
                except json.JSONDecodeError:
                    # 헤더가 잘못 표기된 경우 → 계속 진행
                    pass
            elif not is_zip:
                # ZIP도 JSON도 아닌 경우
                print("  -> [오류] 예상치 못한 응답 형식")
                return None

            # 4) 실제 ZIP 해제
            try:
                zip_buffer = io.BytesIO(response.content)
                with pyzipper.AESZipFile(zip_buffer) as zf:
                    zf.setpassword(b"infected")
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        out_dir = config.DIRECTORIES["malware_samples"]
                        os.makedirs(out_dir, exist_ok=True)
                        out_path = os.path.join(out_dir, f"{sha256_hash}{file_ext}")
                        with zf.open(info) as src, open(out_path, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        print(f"  -> MB 다운로드 성공: {os.path.basename(out_path)}")
                        return out_path
            except Exception as e:
                print(f"  -> [오류] ZIP 해제 실패: {e}")
        else:
            # ---- HTTP 오류 응답 처리 ----
            try:
                print("  -> [오류] API 응답:", response.json())
            except json.JSONDecodeError:
                print("  -> [오류] API 응답(비 JSON):", response.text[:200])

        return None




    def collect_malware_samples_malware_bazaar(self, count: int = 150) -> List[str]:
        """MalwareBazaar에서 문서 관련 악성 샘플을 수집합니다."""
        if not self.malware_bazaar_key:
            print("[MB] API 키가 없어 수집을 건너뜁니다.")
            return []

        collected_files = []
        document_tags = [
            'maldoc', 'downloader', 'dropper', 'macro', 'vba', 'phishing',
            'infostealer', 'doc', 'docx', 'pdf', 'xls', 'xlsx', 'rtf'
        ]
        headers = {'Auth-Key': self.malware_bazaar_key}

        for tag in document_tags:
            if len(collected_files) >= count:
                break
            print(f"[MB] '{tag}' 태그 샘플 수집 중...")
            try:
                data = {'query': 'get_taginfo', 'tag': tag, 'limit': 100}
                response = self.session.post('https://mb-api.abuse.ch/api/v1/', data=data, headers=headers, timeout=30)

                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'application/json' in content_type:
                        try:
                            res_json = response.json()
                        except Exception as e:
                            print(f"  -> [오류] JSON 파싱 실패: {e}")
                            print(f"     응답 본문 일부: {response.text[:200]!r}")
                            continue

        # 이후 res_json 사용...
                        if res_json.get('query_status') == 'ok':
                            for sample in res_json.get('data', []):
                                if len(collected_files) >= count:
                                    break
                                if 'document' in sample.get('file_type_mime', ''):
                                    sha256_hash = sample.get('sha256_hash')
                                    file_ext = f".{sample.get('file_type')}" if sample.get('file_type') else ".bin"
                                    file_path = self._download_sample(sha256_hash, file_ext)
                                    if file_path:
                                        collected_files.append(file_path)
                                        self._save_sample_metadata(
                                            file_path, sha256_hash, True, 'malware_bazaar',
                                            sample.get('signature'), 'malware'
                                        )
                        else:
                            print(f"  -> [오류] query_status != ok: {res_json.get('query_status')}")
                    else:
                        print(f"  -> [오류] 예상치 못한 Content-Type: {content_type}")
                        print(f"     응답 내용 일부: {response.text[:200]!r}")
                else:
                    print(f"  -> [오류] HTTP {response.status_code}")
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'application/json' in content_type:
                        try:
                            print(f"     응답 내용: {response.json()}")
                        except Exception as e:
                            print(f"     JSON 파싱 실패: {e}")
                            print(f"     응답 텍스트: {response.text[:200]!r}")
                    else:
                        print(f"     Content-Type: {content_type}")
                        print(f"     응답 텍스트: {response.text[:200]!r}")

                time.sleep(5)

            except Exception as e:
                print(f"[MB] '{tag}' 태그 수집 중 오류: {e}")
                time.sleep(15)
                continue

        print(f"[MB] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files


    def collect_malware_samples_triage(self, count: int = 100) -> List[str]:
        """Tria.ge에서 문서 관련 악성 샘플을 수집합니다."""
        if not self.triage_key:
            print("[Triage] API 키가 없어 수집을 건너뜁니다.")
            return []

        collected_files = []
        headers = {'Authorization': f'Bearer {self.triage_key}'}
        # 문서형 악성코드와 관련된 다양한 검색 쿼리
        queries = [
            "tag:maldoc", "tag:downloader", "tag:dropper", "tag:infostealer",
            "tag:banker", "tag:rat", "family:emotet", "family:trickbot",
            "family:qakbot", "tag:maldoc AND tag:downloader", "tag:trojan"
        ]
        valid_extensions = ['.doc', '.docx', '.docm', '.pdf', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm',
                            '.hwp', '.rtf']

        for query in queries:
            if len(collected_files) >= count:
                break
            print(f"[Triage] 쿼리 실행: {query}")
            try:
                params = {'query': query, 'limit': 50, 'subset': 'public'}
                response = self.session.get('https://api.tria.ge/v0/search', headers=headers, params=params, timeout=30)

                if response.status_code == 200:
                    for sample in response.json().get('data', []):
                        if len(collected_files) >= count:
                            break
                        filename = sample.get('filename', '')
                        file_ext = os.path.splitext(filename)[1].lower()
                        # 파일 확장자로 문서 파일인지 확인
                        if file_ext in valid_extensions:
                            sample_id = sample.get('id')
                            file_path = self._download_triage_sample(sample_id, filename)
                            if file_path:
                                collected_files.append(file_path)
                                with open(file_path, 'rb') as f:
                                    file_hash = hashlib.sha256(f.read()).hexdigest()
                                self._save_sample_metadata(
                                    file_path, file_hash, True, 'triage',
                                    sample.get('family'), 'malware'
                                )
                else:
                    print(f"  -> 쿼리 실패 (HTTP {response.status_code})")
                    try:
                        print(f"     오류 상세: {response.json()}")
                    except json.JSONDecodeError:
                        pass
                time.sleep(3)  # API 요청 간격 조절
            except Exception as e:
                print(f"[Triage] 쿼리 중 오류 발생: {e}")
                time.sleep(10)
                continue
        print(f"[Triage] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files

    def collect_clean_samples_verified(self, count: int) -> List[str]:
        """로컬에 수동으로 추가된 정상 샘플을 가져옵니다."""
        print("[Clean] 자동 정상 샘플 수집은 지원하지 않습니다.")
        print("[Clean] 'import_clean_files.py'를 사용하여 신뢰할 수 있는 정상 파일을 수동으로 추가하세요.")

        local_clean_dir = config.DIRECTORIES.get('clean_samples')
        if os.path.exists(local_clean_dir):
            existing_files = [os.path.join(local_clean_dir, f) for f in os.listdir(local_clean_dir)
                              if os.path.isfile(os.path.join(local_clean_dir, f))]
            print(f"[Clean] 로컬에 저장된 정상 파일 {len(existing_files)}개를 사용합니다.")
            return existing_files[:count]
        return []

    def _download_triage_sample(self, sample_id: str, filename: str) -> str:
        """Tria.ge에서 단일 샘플을 다운로드합니다."""
        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}
            url = f'https://api.tria.ge/v0/samples/{sample_id}/sample'
            response = self.session.get(url, headers=headers, timeout=60)

            if response.status_code == 200:
                output_dir = config.DIRECTORIES['malware_samples']
                os.makedirs(output_dir, exist_ok=True)
                safe_filename = f"triage_{sample_id}_{filename.replace('/', '_')}"
                file_path = os.path.join(output_dir, safe_filename)
                with open(file_path, 'wb') as f:
                    f.write(response.content)
                return file_path
        except Exception as e:
            print(f"[Triage] 다운로드 실패 ({sample_id}): {e}")
        return None

    def _save_sample_metadata(self, file_path: str, file_hash: str, is_malicious: bool,
                              source: str, malware_family: str = None, threat_category: str = None):
        """수집된 샘플의 메타데이터를 데이터베이스와 S3(선택 사항)에 저장합니다."""
        try:
            # AWS 사용 설정이 켜져있으면 S3에 업로드
            s3_key = aws_helper.upload_virus_sample(file_path, file_hash) if config.USE_AWS else None
            # 데이터베이스에 메타데이터 저장
            db.save_virus_sample(
                file_path=file_path, file_hash=file_hash, is_malicious=is_malicious,
                source=source, malware_family=malware_family,
                threat_category=threat_category, s3_key=s3_key
            )
        except Exception as e:
            print(f"메타데이터 저장 실패 ({file_hash[:10]}): {e}")


def collect_training_data_with_progress(malware_count: int = 200, clean_count: int = 100,
                                        progress_callback=None) -> Tuple[List[str], List[str]]:
    """
    훈련 데이터셋(악성/정상 파일)을 수집하는 메인 함수.
    진행 상황을 콜백 함수로 전달할 수 있습니다.
    """

    def progress(msg):
        """진행 상황 메시지를 출력하거나 콜백 함수로 전달합니다."""
        if progress_callback:
            progress_callback(msg)
        else:
            print(f"[수집] {msg}")

    client = APIClient()
    progress("API 연결 상태 확인 중...")
    mb_available = client.test_malware_bazaar_connection()
    triage_available = client.test_triage_connection()
    progress(f"MalwareBazaar: {'사용 가능' if mb_available else '사용 불가'}")
    progress(f"Tria.ge: {'사용 가능' if triage_available else '사용 불가'}")

    malware_files = []

    # 사용 가능한 API 소스에 따라 수집 목표량을 분배
    if mb_available and triage_available:
        mb_target = malware_count // 2
        triage_target = malware_count // 2
    elif mb_available:
        mb_target = malware_count
        triage_target = 0
    elif triage_available:
        mb_target = 0
        triage_target = malware_count
    else:
        mb_target, triage_target = 0, 0

    if mb_available:
        progress(f"MalwareBazaar에서 악성 샘플 {mb_target}개 수집 시도...")
        malware_files.extend(client.collect_malware_samples_malware_bazaar(mb_target))

    if triage_available:
        progress(f"Tria.ge에서 악성 샘플 {triage_target}개 수집 시도...")
        malware_files.extend(client.collect_malware_samples_triage(triage_target))

    progress("로컬에서 정상 샘플 확인 중...")
    clean_files = client.collect_clean_samples_verified(clean_count)

    progress("중복 파일 제거 중...")
    malware_files = remove_duplicates(malware_files)
    clean_files = remove_duplicates(clean_files)

    # 최종 수집 결과를 보고. 비율 조절은 사용자가 직접 수행하도록 안내.
    progress(f"수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
    total_files = len(malware_files) + len(clean_files)
    if total_files > 0:
        malware_ratio = len(malware_files) / total_files * 100
        progress(f"최종 비율: 악성 {malware_ratio:.1f}%, 정상 {100 - malware_ratio:.1f}%")
        progress("데이터 비율이 맞지 않을 경우, 정상 파일을 수동으로 추가/제거하세요.")

    return malware_files, clean_files


def remove_duplicates(file_paths: List[str]) -> List[str]:
    """파일 경로 리스트에서 SHA256 해시를 기준으로 중복 파일을 식별하고 제거합니다."""
    unique_files = []
    seen_hashes = set()

    for file_path in file_paths:
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            if file_hash not in seen_hashes:
                unique_files.append(file_path)
                seen_hashes.add(file_hash)
            else:
                # 중복 파일인 경우, 물리적 파일 삭제
                try:
                    os.remove(file_path)
                except OSError:
                    pass
        except IOError as e:
            print(f"파일 읽기/해시 계산 실패 ({file_path}): {e}")

    return unique_files


if __name__ == "__main__":
    # 이 스크립트를 직접 실행할 경우, API 연결 테스트와 샘플 수집을 수행합니다.
    client = APIClient()
    print("=== API 연결 테스트 ===")
    print(f"MalwareBazaar: {client.test_malware_bazaar_connection()}")
    print(f"VirusTotal: {client.test_virustotal_connection()}")
    print(f"Tria.ge: {client.test_triage_connection()}")

    print("\n=== 샘플 수집 테스트 (악성 50개, 정상 30개) ===")
    malware_files, clean_files = collect_training_data_with_progress(50, 30)
    print(f"\n최종 수집 결과: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")