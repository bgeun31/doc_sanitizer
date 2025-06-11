import hashlib
import boto3
import config
import os
import json
from datetime import timezone
from botocore.exceptions import NoCredentialsError, ClientError
from dotenv import load_dotenv

load_dotenv()


def create_s3_client():
    """환경변수 기반 S3 클라이언트 생성"""
    try:
        # .env 파일에서 자격증명 읽기
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

        if access_key and secret_key:
            # 명시적 자격증명 사용
            return boto3.client(
                "s3",
                region_name=config.AWS_REGION,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        else:
            # 기본 자격증명 체인 사용
            return boto3.client("s3", region_name=config.AWS_REGION)
    except Exception as e:
        print(f"[AWS] S3 클라이언트 생성 실패: {e}")
        return None

# 전역 S3 클라이언트
s3 = create_s3_client()


def download(key, local):
    """S3에서 파일 다운로드"""
    if not config.USE_AWS:
        print("[AWS] USE_AWS=false → 다운로드 생략")
        return

    if s3 is None:
        print("[AWS] S3 클라이언트가 초기화되지 않음")
        return

    try:
        local_dir = os.path.dirname(local)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        print(f"[AWS] S3 → {local} 다운로드 시도")
        s3.download_file(config.S3_BUCKET, key, local)
        print("[AWS] 다운로드 완료")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchKey':
            print(f"[AWS] 파일이 S3에 존재하지 않음: {key}")
            if key == "models/model_meta.json":
                default_meta = {
                    "accuracy": 0.0,
                    "malware_samples": 0,
                    "clean_samples": 0,
                    "total_samples": 0,
                    "trained_at": "N/A",
                    "model_version": "1.0"
                }
                with open(local, 'w') as f:
                    json.dump(default_meta, f)
                print("[AWS] 기본 model_meta.json 생성")
        elif error_code == 'NoSuchBucket':
            print(f"[AWS] 버킷이 존재하지 않음: {config.S3_BUCKET}")
        else:
            print(f"[AWS] S3 오류: {error_code}")
    except NoCredentialsError:
        print("[AWS] AWS 자격증명이 설정되지 않음")
    except Exception as e:
        print(f"[AWS] 다운로드 실패: {e}")


def upload(local_path, s3_key):
    """로컬 파일을 S3에 업로드"""
    if not config.USE_AWS:
        print("[AWS] USE_AWS=false → 업로드 생략")
        return False

    if s3 is None:
        print("[AWS] S3 클라이언트가 초기화되지 않음")
        return False

    if not os.path.exists(local_path):
        print(f"[AWS] 업로드할 파일이 없음: {local_path}")
        return False

    try:
        print(f"[AWS] {local_path} → S3 업로드 시도")
        s3.upload_file(local_path, config.S3_BUCKET, s3_key)
        print(f"[AWS] 업로드 완료: s3://{config.S3_BUCKET}/{s3_key}")
        return True
    except NoCredentialsError:
        print("[AWS] AWS 자격증명이 설정되지 않음")
        return False
    except ClientError as e:
        error_code = e.response['Error']['Code']
        print(f"[AWS] 업로드 실패 - {error_code}: {e}")
        return False
    except Exception as e:
        print(f"[AWS] 업로드 실패: {e}")
        return False


def upload_virus_sample(local_path, file_hash):
    """바이러스 샘플을 S3에 업로드"""
    if not config.USE_AWS:
        return None

    if s3 is None:
        return None

    try:
        from datetime import datetime
        date_prefix = datetime.now().strftime("%Y/%m/%d")
        file_ext = os.path.splitext(local_path)[1]
        s3_key = f"virus_samples/{date_prefix}/{file_hash}{file_ext}"

        if upload(local_path, s3_key):
            return s3_key
        return None

    except Exception as e:
        print(f"[AWS] 바이러스 샘플 업로드 실패: {e}")
        return None


def download_virus_sample(s3_key, local_path):
    """S3에서 바이러스 샘플 다운로드"""
    if not config.USE_AWS:
        return False

    try:
        download(s3_key, local_path)
        return os.path.exists(local_path)
    except Exception as e:
        print(f"[AWS] 바이러스 샘플 다운로드 실패: {e}")
        return False


def list_virus_samples(prefix="virus_samples/"):
    """S3의 바이러스 샘플 목록 조회"""
    if not config.USE_AWS:
        return []

    if s3 is None:
        return []

    try:
        response = s3.list_objects_v2(
            Bucket=config.S3_BUCKET,
            Prefix=prefix
        )

        objects = response.get('Contents', [])
        return [obj['Key'] for obj in objects]

    except ClientError as e:
        print(f"[AWS] 샘플 목록 조회 실패: {e}")
        return []
    except Exception as e:
        print(f"[AWS] 샘플 목록 조회 실패: {e}")
        return []


def get_s3_model_info(key: str = "models/ensemble_model.pkl"):
    """S3 객체 메타데이터 + SHA256 해시 + 학습 메타 정보 반환"""
    try:
        # AWS 설정 확인
        if not config.USE_AWS:
            return {"error": "AWS가 비활성화됨"}

        if s3 is None:
            return {"error": "S3 클라이언트가 초기화되지 않음"}

        # S3에서 모델 파일 head 요청
        response = s3.head_object(Bucket=config.S3_BUCKET, Key=key)
        size_bytes = response['ContentLength']
        last_modified = response['LastModified'].astimezone(timezone.utc)

        # 모델 파일 다운로드 후 SHA256 해시 계산
        tmp_model = f"_tmp_{os.path.basename(key)}"
        s3.download_file(config.S3_BUCKET, key, tmp_model)

        with open(tmp_model, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        os.remove(tmp_model)

        # model_meta.json 다운로드 시도
        meta = None
        tmp_meta = "_tmp_model_meta.json"
        try:
            s3.download_file(config.S3_BUCKET, "models/model_meta.json", tmp_meta)
            with open(tmp_meta, "r") as f:
                meta = json.load(f)
            os.remove(tmp_meta)
        except ClientError as meta_error:
            error_code = meta_error.response['Error']['Code']
            if error_code == 'NoSuchKey':
                meta = {"error": "model_meta.json이 S3에 없음"}
            else:
                meta = {"error": f"model_meta.json 로드 실패: {error_code}"}
        except Exception as meta_err:
            meta = {"error": f"model_meta.json 로드 실패: {str(meta_err)}"}

        return {
            "size_mb": round(size_bytes / 1024 / 1024, 2),
            "last_modified": last_modified.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "sha256": sha256,
            "meta": meta
        }

    except NoCredentialsError:
        return {"error": "AWS 자격증명이 설정되지 않음"}
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchKey':
            return {"error": f"S3에 모델 파일이 없음: {key}"}
        elif error_code == 'NoSuchBucket':
            return {"error": f"S3 버킷이 존재하지 않음: {config.S3_BUCKET}"}
        elif error_code == 'Forbidden':
            return {"error": "S3 접근 권한이 없음"}
        else:
            return {"error": f"S3 오류: {error_code}"}
    except Exception as e:
        return {"error": f"알 수 없는 오류: {str(e)}"}


def sync_training_data_to_s3(local_dir="sample/mecro"):
    """로컬 훈련 데이터를 S3에 동기화"""
    if not config.USE_AWS or not os.path.exists(local_dir):
        return

    if s3 is None:
        return

    uploaded_count = 0

    try:
        for file_name in os.listdir(local_dir):
            file_path = os.path.join(local_dir, file_name)
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()

                s3_key = upload_virus_sample(file_path, file_hash)
                if s3_key:
                    uploaded_count += 1

                    try:
                        from utils.db import save_virus_sample
                        save_virus_sample(
                            file_path=file_path,
                            file_hash=file_hash,
                            is_malicious=True,
                            source="local_upload",
                            s3_key=s3_key
                        )
                    except Exception as db_error:
                        print(f"[DB] 메타데이터 저장 실패: {db_error}")

        print(f"[AWS] 훈련 데이터 동기화 완료: {uploaded_count}개 파일")

    except Exception as e:
        print(f"[AWS] 훈련 데이터 동기화 실패: {e}")


def cleanup_old_models(keep_count=5):
    """오래된 모델 파일들 정리"""
    if not config.USE_AWS:
        return

    if s3 is None:
        return

    try:
        response = s3.list_objects_v2(
            Bucket=config.S3_BUCKET,
            Prefix="models/"
        )

        objects = response.get('Contents', [])
        if len(objects) <= keep_count:
            return

        objects.sort(key=lambda x: x['LastModified'])

        to_delete = objects[:-keep_count]
        for obj in to_delete:
            s3.delete_object(Bucket=config.S3_BUCKET, Key=obj['Key'])
            print(f"[AWS] 오래된 모델 삭제: {obj['Key']}")

    except Exception as e:
        print(f"[AWS] 모델 정리 실패: {e}")


def get_bucket_info():
    """S3 버킷 정보 조회"""
    if not config.USE_AWS:
        return {"error": "AWS 비활성화"}

    if s3 is None:
        return {"error": "S3 클라이언트가 초기화되지 않음"}

    try:
        s3.head_bucket(Bucket=config.S3_BUCKET)

        response = s3.list_objects_v2(Bucket=config.S3_BUCKET)
        objects = response.get('Contents', [])

        total_size = sum(obj['Size'] for obj in objects)

        folder_stats = {}
        for obj in objects:
            folder = obj['Key'].split('/')[0] if '/' in obj['Key'] else 'root'
            if folder not in folder_stats:
                folder_stats[folder] = {'count': 0, 'size': 0}
            folder_stats[folder]['count'] += 1
            folder_stats[folder]['size'] += obj['Size']

        return {
            "bucket_name": config.S3_BUCKET,
            "total_objects": len(objects),
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "folder_stats": folder_stats
        }

    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {"error": f"S3 오류: {error_code}"}
    except Exception as e:
        return {"error": str(e)}


def test_aws_connection():
    """AWS 연결 테스트"""
    if not config.USE_AWS:
        return {"status": "disabled", "message": "AWS가 비활성화됨"}

    if s3 is None:
        return {"status": "error", "message": "S3 클라이언트 초기화 실패"}

    try:
        # S3 연결 테스트
        s3.head_bucket(Bucket=config.S3_BUCKET)

        # 간단한 객체 목록 조회
        s3.list_objects_v2(Bucket=config.S3_BUCKET, MaxKeys=1)

        return {
            "status": "success",
            "message": f"S3 버킷 '{config.S3_BUCKET}' 연결 성공",
            "bucket": config.S3_BUCKET,
            "region": config.AWS_REGION
        }

    except NoCredentialsError:
        return {"status": "error", "message": "AWS 자격증명이 설정되지 않음"}
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            return {"status": "error", "message": f"S3 버킷이 존재하지 않음: {config.S3_BUCKET}"}
        elif error_code == 'Forbidden':
            return {"status": "error", "message": "S3 접근 권한이 없음"}
        else:
            return {"status": "error", "message": f"S3 오류: {error_code}"}
    except Exception as e:
        return {"status": "error", "message": f"알 수 없는 오류: {str(e)}"}