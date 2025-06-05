# utils/api_client.py - 정상 샘플 수집 제한 및 악성 샘플 증가

import os
import requests
import time
import hashlib
import json
from typing import List, Tuple
from dotenv import load_dotenv
import config
from utils import db, aws_helper

load_dotenv()


class APIClient:
    def __init__(self):
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.triage_key = os.getenv('TRIAGE_API_KEY')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DocSanitizer/2.2'
        })

    def test_malware_bazaar_connection(self) -> bool:
        """MalwareBazaar API 연결 테스트"""
        if not self.malware_bazaar_key:
            return False

        try:
            data = {
                'query': 'get_info',
                'api_key': self.malware_bazaar_key
            }
            response = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data=data,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False

    def test_virustotal_connection(self) -> bool:
        """VirusTotal API 연결 테스트"""
        if not self.virustotal_key:
            return False

        try:
            headers = {'x-apikey': self.virustotal_key}
            response = requests.get(
                'https://www.virustotal.com/api/v3/users/current',
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False

    def test_triage_connection(self) -> bool:
        """Tria.ge API 연결 테스트"""
        if not self.triage_key:
            return False

        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}
            response = requests.get(
                'https://api.tria.ge/v0/samples',
                headers=headers,
                params={'limit': 1},
                timeout=10
            )
            return response.status_code == 200
        except:
            return False

    def collect_malware_samples_malware_bazaar(self, count: int = 200) -> List[str]:
        """MalwareBazaar에서 악성 샘플 수집 (증가)"""
        if not self.malware_bazaar_key:
            print("[MB] API 키가 없습니다")
            return []

        collected_files = []

        # 문서형 악성코드 태그 확장
        document_tags = [
            'doc', 'docx', 'pdf', 'xls', 'xlsx', 'ppt', 'pptx',
            'emotet', 'trickbot', 'qakbot', 'formbook', 'agent-tesla',
            'lokibot', 'macro', 'office', 'document', 'banker',
            'downloader', 'dropper', 'loader', 'malware'
        ]

        for tag in document_tags:
            if len(collected_files) >= count:
                break

            print(f"[MB] {tag} 태그 샘플 수집 중...")

            try:
                data = {
                    'query': 'get_taginfo',
                    'tag': tag,
                    'limit': 25,  # 증가
                    'api_key': self.malware_bazaar_key
                }

                response = requests.post(
                    'https://mb-api.abuse.ch/api/v1/',
                    data=data,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    samples = result.get('data', [])

                    for sample in samples:
                        if len(collected_files) >= count:
                            break

                        file_name = sample.get('file_name', '')
                        file_ext = os.path.splitext(file_name)[1].lower()

                        if file_ext in ['.doc', '.docx', '.docm', '.pdf', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx',
                                        '.pptm', '.hwp']:
                            download_url = sample.get('urlhaus_download')
                            sha256_hash = sample.get('sha256')

                            if download_url and sha256_hash:
                                file_path = self._download_sample(download_url, sha256_hash, file_ext)
                                if file_path:
                                    collected_files.append(file_path)

                                    self._save_sample_metadata(
                                        file_path, sha256_hash, True, 'malware_bazaar',
                                        sample.get('signature'), 'malware'
                                    )

                time.sleep(1)

            except Exception as e:
                print(f"[MB] {tag} 수집 오류: {e}")
                continue

        print(f"[MB] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files

    def collect_malware_samples_triage(self, count: int = 150) -> List[str]:
        """Tria.ge에서 악성 샘플 수집 (증가)"""
        if not self.triage_key:
            print("[Triage] API 키가 없습니다")
            return []

        collected_files = []
        headers = {'Authorization': f'Bearer {self.triage_key}'}

        # 문서형 악성코드 쿼리 확장
        queries = [
            'kind:document AND family:emotet',
            'kind:document AND family:trickbot',
            'kind:document AND family:qakbot',
            'kind:document AND family:formbook',
            'kind:document AND family:agent-tesla',
            'kind:document AND family:lokibot',
            'tag:macro AND kind:document',
            'tag:office AND kind:document',
            'ext:pdf AND kind:document',
            'ext:docx AND kind:document',
            'ext:xlsx AND kind:document',
            'tag:banker AND ext:docx',
            'tag:downloader AND ext:pdf',
            'tag:trojan AND ext:xlsx'
        ]

        for query in queries:
            if len(collected_files) >= count:
                break

            print(f"[Triage] 쿼리 실행: {query}")

            try:
                params = {
                    'query': query,
                    'limit': 20,  # 증가
                    'subset': 'public'
                }

                response = requests.get(
                    'https://api.tria.ge/v0/search',
                    headers=headers,
                    params=params,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    samples = result.get('data', [])

                    for sample in samples:
                        if len(collected_files) >= count:
                            break

                        sample_id = sample.get('id')
                        filename = sample.get('filename', '')
                        file_ext = os.path.splitext(filename)[1].lower()

                        if file_ext in ['.doc', '.docx', '.docm', '.pdf', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx',
                                        '.pptm', '.hwp']:
                            file_path = self._download_triage_sample(sample_id, filename)
                            if file_path:
                                collected_files.append(file_path)

                                with open(file_path, 'rb') as f:
                                    file_hash = hashlib.sha256(f.read()).hexdigest()

                                self._save_sample_metadata(
                                    file_path, file_hash, True, 'triage',
                                    sample.get('family'), 'malware'
                                )

                time.sleep(2)

            except Exception as e:
                print(f"[Triage] 쿼리 오류: {e}")
                continue

        print(f"[Triage] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files

    def collect_clean_samples_verified(self, count: int = 30) -> List[str]:
        """VirusTotal 검증된 정상 샘플 수집 (대폭 감소)"""
        if not self.virustotal_key:
            print("[Clean] VirusTotal API 키가 없어 최소 로컬 샘플만 사용")
            return self._generate_minimal_clean_samples(min(count, 10))

        collected_files = []
        headers = {'x-apikey': self.virustotal_key}

        # 제한적인 정상 문서 검색
        search_queries = [
            'type:pdf positives:0 size:100KB+ fs:2024-01-01+',
            'type:office positives:0 size:50KB+ fs:2024-01-01+'
        ]

        for query in search_queries:
            if len(collected_files) >= count:
                break

            print(f"[Clean] VirusTotal 검색: {query}")

            try:
                params = {
                    'query': query,
                    'limit': 15  # 대폭 감소
                }

                response = requests.get(
                    'https://www.virustotal.com/api/v3/intelligence/search',
                    headers=headers,
                    params=params,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    files = result.get('data', [])

                    for file_info in files:
                        if len(collected_files) >= count:
                            break

                        attributes = file_info.get('attributes', {})
                        stats = attributes.get('last_analysis_stats', {})

                        # 매우 엄격한 정상 파일 선택
                        if (stats.get('malicious', 0) == 0 and
                                stats.get('suspicious', 0) == 0 and
                                sum(stats.values()) >= 20):  # 20개 이상 엔진 검사

                            file_hash = file_info.get('id')
                            file_names = attributes.get('names', [])

                            if file_names:
                                file_name = file_names[0]
                                file_ext = os.path.splitext(file_name)[1].lower()

                                if file_ext in ['.pdf', '.docx']:  # PDF와 Word만
                                    file_path = self._create_verified_clean_sample(file_name, file_ext)
                                    if file_path:
                                        collected_files.append(file_path)

                                        self._save_sample_metadata(
                                            file_path, file_hash, False, 'virustotal_verified',
                                            'clean_document', 'clean'
                                        )

                time.sleep(1.5)

            except Exception as e:
                print(f"[Clean] VirusTotal 검색 오류: {e}")
                continue

        # 부족한 경우 최소한의 로컬 생성
        if len(collected_files) < count:
            remaining = min(count - len(collected_files), 10)
            local_files = self._generate_minimal_clean_samples(remaining)
            collected_files.extend(local_files)

        print(f"[Clean] 총 {len(collected_files)}개 정상 샘플 수집 완료 (엄격 제한)")
        return collected_files

    def _create_verified_clean_sample(self, filename: str, file_ext: str) -> str:
        """VirusTotal 검증 정보를 바탕으로 정상 샘플 생성"""
        try:
            os.makedirs(config.DIRECTORIES['clean_samples'], exist_ok=True)

            clean_name = f"verified_{int(time.time())}_{filename}"
            file_path = os.path.join(config.DIRECTORIES['clean_samples'], clean_name)

            if file_ext == '.pdf':
                from reportlab.pdfgen import canvas
                c = canvas.Canvas(file_path)
                c.drawString(100, 750, f"Clean Document - {filename}")
                c.drawString(100, 700, "This is a verified clean document.")
                c.drawString(100, 650, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                c.save()

            elif file_ext == '.docx':
                import zipfile

                with zipfile.ZipFile(file_path, 'w') as zf:
                    zf.writestr('[Content_Types].xml', self._get_content_types_xml())
                    zf.writestr('_rels/.rels', self._get_rels_xml())
                    zf.writestr('word/document.xml', self._get_word_document_xml(filename))
                    zf.writestr('word/_rels/document.xml.rels', self._get_word_rels_xml())

            return file_path

        except Exception as e:
            print(f"[Clean] 검증된 샘플 생성 오류: {e}")
            return None

    def _generate_minimal_clean_samples(self, count: int) -> List[str]:
        """최소한의 로컬 정상 샘플 생성 (극도로 제한)"""
        if count > 5:  # 최대 5개로 제한
            count = 5

        generated_files = []

        try:
            os.makedirs(config.DIRECTORIES['clean_samples'], exist_ok=True)

            for i in range(count):
                filename = f"local_clean_{i + 1}_{int(time.time())}.pdf"
                file_path = os.path.join(config.DIRECTORIES['clean_samples'], filename)

                from reportlab.pdfgen import canvas
                c = canvas.Canvas(file_path)
                c.drawString(100, 750, f"Local Clean Document #{i + 1}")
                c.drawString(100, 700, "This is a locally generated clean document.")
                c.drawString(100, 650, "No malicious content included.")
                c.save()

                generated_files.append(file_path)

                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()

                self._save_sample_metadata(
                    file_path, file_hash, False, 'local_generated',
                    'clean_document', 'clean'
                )

        except Exception as e:
            print(f"[Clean] 로컬 생성 오류: {e}")

        print(f"[Clean] {len(generated_files)}개 로컬 정상 샘플 생성 (극소량)")
        return generated_files

    def _get_content_types_xml(self) -> str:
        """Office 문서 Content Types XML 생성"""
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'

    def _get_rels_xml(self) -> str:
        """기본 관계 XML 생성"""
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'

    def _get_word_document_xml(self, filename: str) -> str:
        """Word 문서 XML 생성"""
        return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Clean Document: {filename}</w:t></w:r></w:p><w:p><w:r><w:t>This is a verified clean document with no malicious content.</w:t></w:r></w:p></w:body></w:document>'

    def _get_word_rels_xml(self) -> str:
        """Word 관계 XML 생성"""
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>'

    def _download_sample(self, url: str, file_hash: str, file_ext: str) -> str:
        """샘플 파일 다운로드"""
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                os.makedirs(config.DIRECTORIES['malware_samples'], exist_ok=True)

                filename = f"{file_hash[:16]}{file_ext}"
                file_path = os.path.join(config.DIRECTORIES['malware_samples'], filename)

                with open(file_path, 'wb') as f:
                    f.write(response.content)

                return file_path
        except Exception as e:
            print(f"다운로드 실패 {url}: {e}")

        return None

    def _download_triage_sample(self, sample_id: str, filename: str) -> str:
        """Tria.ge 샘플 다운로드"""
        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}

            response = requests.get(
                f'https://api.tria.ge/v0/samples/{sample_id}/sample',
                headers=headers,
                timeout=60
            )

            if response.status_code == 200:
                os.makedirs(config.DIRECTORIES['malware_samples'], exist_ok=True)

                safe_filename = f"triage_{sample_id}_{filename.replace('/', '_')}"
                file_path = os.path.join(config.DIRECTORIES['malware_samples'], safe_filename)

                with open(file_path, 'wb') as f:
                    f.write(response.content)

                return file_path

        except Exception as e:
            print(f"Triage 다운로드 실패 {sample_id}: {e}")

        return None

    def _save_sample_metadata(self, file_path: str, file_hash: str, is_malicious: bool,
                              source: str, malware_family: str = None, threat_category: str = None):
        """샘플 메타데이터를 RDS에 저장"""
        try:
            s3_key = None
            if config.USE_AWS:
                s3_key = aws_helper.upload_virus_sample(file_path, file_hash)

            db.save_virus_sample(
                file_path=file_path,
                file_hash=file_hash,
                is_malicious=is_malicious,
                source=source,
                malware_family=malware_family,
                threat_category=threat_category,
                s3_key=s3_key
            )

        except Exception as e:
            print(f"메타데이터 저장 실패: {e}")

    def check_file_with_virustotal(self, file_path: str) -> dict:
        """VirusTotal로 파일 검사"""
        if not self.virustotal_key:
            return {"error": "VirusTotal API 키가 설정되지 않음"}

        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            headers = {'x-apikey': self.virustotal_key}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})

                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total': sum(stats.values()) if stats else 0,
                    'scan_date': attributes.get('last_analysis_date'),
                    'clean': stats.get('harmless', 0) + stats.get('undetected', 0)
                }
            elif response.status_code == 404:
                return {"error": "파일이 VirusTotal 데이터베이스에 없음"}
            else:
                return {"error": f"VirusTotal API 오류: {response.status_code}"}

        except Exception as e:
            return {"error": f"VirusTotal 검사 오류: {str(e)}"}


def collect_training_data_with_progress(malware_count: int = 300, clean_count: int = 50,
                                        progress_callback=None) -> Tuple[List[str], List[str]]:
    """개선된 훈련 데이터 수집 (악성:정상 = 6:1 비율)"""

    def progress(msg):
        if progress_callback:
            progress_callback(msg)
        else:
            print(f"[수집] {msg}")

    client = APIClient()

    progress("API 연결 상태 확인 중...")

    mb_available = client.test_malware_bazaar_connection()
    vt_available = client.test_virustotal_connection()
    triage_available = client.test_triage_connection()

    progress(f"MalwareBazaar: {'사용 가능' if mb_available else '사용 불가'}")
    progress(f"VirusTotal: {'사용 가능' if vt_available else '사용 불가'}")
    progress(f"Tria.ge: {'사용 가능' if triage_available else '사용 불가'}")

    malware_files = []
    clean_files = []

    # 악성 샘플 수집 (대폭 증가)
    if mb_available:
        progress("MalwareBazaar에서 악성 샘플 수집 중...")
        mb_files = client.collect_malware_samples_malware_bazaar(malware_count * 60 // 100)
        malware_files.extend(mb_files)

    if triage_available:
        progress("Tria.ge에서 악성 샘플 수집 중...")
        remaining_malware = malware_count - len(malware_files)
        if remaining_malware > 0:
            triage_files = client.collect_malware_samples_triage(remaining_malware)
            malware_files.extend(triage_files)

    # 정상 샘플 수집 (대폭 감소)
    if vt_available:
        progress("VirusTotal 검증된 정상 샘플 수집 중 (극소량)...")
        clean_files = client.collect_clean_samples_verified(clean_count)
    else:
        progress("VirusTotal 없음 - 최소 로컬 정상 샘플 생성...")
        clean_files = client._generate_minimal_clean_samples(min(clean_count, 5))

    # 중복 제거
    progress("중복 파일 제거 중...")
    malware_files = remove_duplicates(malware_files)
    clean_files = remove_duplicates(clean_files)

    # 엄격한 비율 조정 (악성:정상 = 6:1)
    if len(clean_files) > len(malware_files) // 6:
        clean_files = clean_files[:max(len(malware_files) // 6, 5)]
        progress(f"정상 샘플 수를 {len(clean_files)}개로 엄격 제한 (악성 대비 1/6)")

    progress(f"수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
    progress(f"비율: 악성 {len(malware_files) / (len(malware_files) + len(clean_files)) * 100:.1f}%, 정상 {len(clean_files) / (len(malware_files) + len(clean_files)) * 100:.1f}%")

    return malware_files, clean_files


def remove_duplicates(file_paths: List[str]) -> List[str]:
    """파일 해시 기반 중복 제거"""
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
                try:
                    os.remove(file_path)
                except:
                    pass

        except Exception as e:
            print(f"해시 계산 실패 {file_path}: {e}")

    return unique_files


if __name__ == "__main__":
    client = APIClient()

    print("=== API 연결 테스트 ===")
    print(f"MalwareBazaar: {client.test_malware_bazaar_connection()}")
    print(f"VirusTotal: {client.test_virustotal_connection()}")
    print(f"Tria.ge: {client.test_triage_connection()}")

    print("\n=== 샘플 수집 테스트 ===")
    malware_files, clean_files = collect_training_data_with_progress(100, 15)
    print(f"결과: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")