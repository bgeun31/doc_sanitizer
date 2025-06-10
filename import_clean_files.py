# import_clean_files.py
import os
import shutil
import time
import hashlib
from typing import List

# --- 설정 및 유틸리티 임포트 ---
# 프로젝트의 다른 모듈을 가져오기 위해 경로 설정
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from utils.virustotal_checker import VirusTotalChecker
from utils import db, aws_helper


def save_verified_clean_sample_metadata(file_path: str, file_hash: str):
    """검증된 정상 샘플의 데이터를 RDS와 S3에 저장"""
    try:
        # S3 업로드 (AWS 사용 시)
        s3_key = None
        if config.USE_AWS:
            print(f"  [AWS] S3 업로드 시도...")
            s3_key = aws_helper.upload_virus_sample(file_path, file_hash)
            if s3_key:
                print(f"  [AWS] S3 업로드 완료: {s3_key}")

        # RDS에 메타데이터 저장
        print(f"  [DB] 메타데이터 저장 시도...")
        db.save_virus_sample(
            file_path=file_path,
            file_hash=file_hash,
            is_malicious=False,  # 정상 파일로 명시
            source='verified_manual_import',  # 출처: 수동 검증 후 임포트
            malware_family='clean',
            threat_category='clean',
            s3_key=s3_key
        )
        print(f"  [DB] 메타데이터 저장 완료.")

    except Exception as e:
        print(f"  [오류] 메타데이터 저장 실패: {e}")


def verify_and_import_clean_samples(candidate_dir: str):
    """
    지정된 디렉토리의 파일들을 VirusTotal로 검증하고,
    '안전'하거나 '미등록'인 경우 정상 샘플로 DB에 저장 및 이동시키는 함수 (수정된 버전)
    """
    checker = VirusTotalChecker()
    if not checker.is_available():
        print("[오류] VirusTotal API 키가 없어 검증을 진행할 수 없습니다.")
        print("'.env' 파일에 VIRUSTOTAL_API_KEY를 설정해주세요.")
        return

    if not os.path.exists(candidate_dir):
        print(f"[오류] 후보 디렉토리를 찾을 수 없습니다: {candidate_dir}")
        print(f"폴더를 먼저 생성하고 정상 문서 파일을 넣어주세요.")
        return

    print(f"'{candidate_dir}' 폴더의 정상 샘플 후보 검증을 시작합니다...")

    verified_count = 0
    candidate_files = [f for f in os.listdir(candidate_dir) if os.path.isfile(os.path.join(candidate_dir, f))]

    if not candidate_files:
        print("검증할 파일이 없습니다. 후보 폴더에 파일을 추가해주세요.")
        return

    for filename in candidate_files:
        file_path = os.path.join(candidate_dir, filename)

        try:
            print(f"\n-> 검증 중: {filename}")
            result = checker.comprehensive_check(file_path)

            # API 응답 대기 (API 제한 준수)
            time.sleep(1)

            # --- 여기가 핵심 수정 부분 ---
            process_as_clean = False
            verdict = result.get('verdict', '알 수 없음')

            # CASE 1: VirusTotal이 이미 '안전'하다고 알고 있는 경우
            if result.get("method") == "hash_lookup" and verdict == "안전":
                if result.get("malicious", 0) == 0 and result.get("suspicious", 0) == 0:
                    print(f"  [결과] VirusTotal에서 '안전'한 파일로 확인되었습니다.")
                    process_as_clean = True
                else:
                    print(f"  [결과] 일부 엔진에서 악성/의심으로 탐지되어 추가하지 않습니다.")

            # CASE 2: VirusTotal에 없는 '미등록' 파일인 경우 (신뢰하는 파일이므로 안전으로 간주)
            elif verdict == "미등록" or verdict == "분석 중":
                print(f"  [결과] VirusTotal '미등록' 또는 '분석 중' 파일입니다. 신뢰하는 소스이므로 안전한 파일로 처리합니다.")
                process_as_clean = True

            # 그 외의 경우 (예: '악성', '의심' 등)
            else:
                print(f"  [결과] 안전한 파일로 확인되지 않았습니다. (상태: {verdict})")

            # 안전하다고 판단된 파일만 후속 처리
            if process_as_clean:
                # 파일을 sample/clear 폴더로 이동
                dest_path = os.path.join(config.DIRECTORIES['clean_samples'], filename)
                shutil.move(file_path, dest_path)
                print(f"  [파일] '{dest_path}'로 이동 완료.")

                # DB에 메타데이터 저장
                file_hash = result.get("file_hash")
                if not file_hash:  # 해시가 결과에 없으면 직접 계산
                    with open(dest_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()

                save_verified_clean_sample_metadata(dest_path, file_hash)
                verified_count += 1

        except Exception as e:
            print(f"  [오류] {filename} 검증 중 오류 발생: {e}")

    print(f"\n--- 검증 완료 ---")
    print(f"총 {len(candidate_files)}개 후보 중 {verified_count}개의 안전한 파일을 추가했습니다.")

if __name__ == "__main__":
    # 검증할 파일들이 들어있는 폴더 경로
    # 폴더가 없다면 직접 생성필요
    CANDIDATE_FOLDER = "sample/clean_candidates"
    os.makedirs(CANDIDATE_FOLDER, exist_ok=True)

    verify_and_import_clean_samples(CANDIDATE_FOLDER)