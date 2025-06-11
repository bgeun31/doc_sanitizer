# test_api.py - 유동적 샘플 수집 기능 추가

import os
import sys
import argparse
from dotenv import load_dotenv
from utils.api_client import APIClient, collect_training_data_with_progress
from utils.model_manager import ModelManager
from utils.model_trainer import train_model
import config


class OptimizedProgressTracker:
    """최적화된 진행률 추적"""

    def __init__(self, total_steps: int):
        self.total_steps = total_steps
        self.current_step = 0

    def update(self, message: str = ""):
        """진행률 업데이트"""
        self.current_step += 1
        percentage = (self.current_step / self.total_steps) * 100
        bar_length = 30
        filled_length = int(bar_length * self.current_step // self.total_steps)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)

        sys.stdout.write(f'\r[{bar}] {percentage:.0f}% - {message}')
        sys.stdout.flush()

        if self.current_step == self.total_steps:
            print()


def run_flexible_collection(malware_count: int, clean_count: int):
    """지정된 개수만큼 샘플을 유동적으로 수집하는 함수"""
    print(f"샘플 수집 시작 (목표: 악성 {malware_count}개, 정상 {clean_count}개)")
    print("=" * 50)

    # API 키 확인
    api_client = APIClient()
    if not api_client.malware_bazaar_key:
        print("\nAPI 키 설정 필요: .env 파일에서 MALWARE_BAZAAR_API_KEY를 설정해주세요.")
        return False

    def progress_callback(message):
        print(f"[진행] {message}")

    try:
        malware_files, clean_files = collect_training_data_with_progress(
            malware_count=malware_count,
            clean_count=clean_count,
            progress_callback=progress_callback
        )
        print("\n샘플 수집 완료!")
        print(f"결과: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
        print("=" * 50)
        return True
    except Exception as e:
        print(f"\n샘플 수집 중 오류 발생: {e}")
        return False


def test_system():
    """시스템 상태 확인"""
    print("=== 시스템 상태 확인 ===")

    load_dotenv()

    print("1. API 연결 상태")
    api_client = APIClient()

    # MalwareBazaar API
    mb_status = "✅" if api_client.malware_bazaar_key and api_client.test_malware_bazaar_connection() else "❌"
    print(f"   MalwareBazaar: {mb_status}")

    # VirusTotal API
    vt_status = "✅" if api_client.virustotal_key and api_client.test_virustotal_connection() else "❌"
    print(f"   VirusTotal: {vt_status}")

    # Triage API
    triage_status = "✅" if api_client.triage_key and api_client.test_triage_connection() else "❌"
    print(f"   Tria.ge: {triage_status}")

    print("\n2. RDS 연결 상태")
    try:
        from utils.db import get_sample_statistics
        db_stats = get_sample_statistics()
        rds_status = "✅" if db_stats else "❌"
        print(f"   RDS 데이터베이스: {rds_status}")
        if db_stats:
            print(f"   DB 샘플 수: 악성 {db_stats.get('malicious_samples', 0)}개, 정상 {db_stats.get('clean_samples', 0)}개")
    except Exception as e:
        print(f"   RDS 데이터베이스: ❌ ({str(e)})")

    print("\n3. AWS 연결 상태")
    if config.USE_AWS:
        from utils.aws_helper import test_aws_connection
        aws_result = test_aws_connection()
        aws_status = "✅" if aws_result.get("status") == "success" else "❌"
        print(f"   AWS S3: {aws_status}")
        if aws_result.get("status") != "success":
            print(f"   오류: {aws_result.get('message', 'Unknown')}")
    else:
        print("   AWS S3: ⚠️ (비활성화)")

    print("\n4. AI 모델 상태")
    model_manager = ModelManager()

    model_available = model_manager.is_model_available()
    model_status = "✅" if model_available else "❌"
    print(f"   모델 파일: {model_status}")

    if model_available and model_manager.load_model():
        print(f"   모델 로드: ✅")
    else:
        print(f"   모델 로드: ❌")

    print("\n5. 로컬 훈련 데이터 상태")
    data_status = model_manager.get_training_data_status()
    print(f"   로컬 악성 샘플: {data_status['malware_samples']}개")
    print(f"   로컬 정상 샘플: {data_status['clean_samples']}개")

    data_sufficient = data_status['sufficient_data']
    sufficient_status = "✅" if data_sufficient else "⚠️"
    print(f"   데이터 충분성: {sufficient_status}")

    print("\n6. 내장 서버 상태")
    print(f"   내장 서버: ✅ (main.py 실행시 자동 시작)")
    print("   별도 서버 실행 불필요")

    print("=" * 40)

    return {
        'api_available': bool(api_client.malware_bazaar_key),
        'triage_available': bool(api_client.triage_key),
        'model_available': model_available,
        'data_sufficient': data_sufficient,
        'data_status': data_status,
        'embedded_server': True
    }


def setup_system_optimized():
    """최적화된 시스템 설정"""
    print("문서형 악성코드 무해화 시스템 v2.2 설정")
    print("=" * 50)

    test_results = test_system()

    if not test_results['api_available']:
        print("\nAPI 키 설정 필요")
        print("1. .env 파일 생성")
        print("2. MALWARE_BAZAAR_API_KEY=발급받은_키 추가")
        print("3. API 키 발급: https://bazaar.abuse.ch/api/")
        return False

    # 자동화 플로우 단계 계산
    steps_needed = 3  # 샘플 수집, 모델 훈련, 업로드

    progress = OptimizedProgressTracker(steps_needed)
    print(f"\n{steps_needed}단계 자동화 플로우 시작")

    try:
        # 1단계: 샘플 수집
        progress.update("샘플 수집 중")
        print("\n=== 1단계: 샘플 수집 ===")

        def progress_callback(message):
            print(f"[진행] {message}")

        try:
            malware_files, clean_files = collect_training_data_with_progress(
                malware_count=300,
                clean_count=50,
                progress_callback=progress_callback
            )

            print(f"수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
            malware_ratio = len(malware_files) / (len(malware_files) + len(clean_files)) * 100
            print(f"비율: 악성 {malware_ratio:.1f}%, 정상 {100 - malware_ratio:.1f}%")

            # RDS 상태 확인
            from utils.db import get_sample_statistics
            db_stats = get_sample_statistics()
            print(f"RDS 총 샘플: 악성 {db_stats.get('malicious_samples', 0)}개, 정상 {db_stats.get('clean_samples', 0)}개")

        except Exception as collect_error:
            print(f"샘플 수집 실패: {collect_error}")
            return False

        # 2단계: AI 모델 훈련
        progress.update("AI 모델 훈련 중")
        print("\n=== 2단계: AI 모델 훈련 ===")

        success = train_model()
        if not success:
            print("모델 훈련 실패")
            return False

        print("모델 훈련 성공!")

        # 3단계: 모델 S3 업로드
        progress.update("모델 S3 업로드 중")
        print("\n=== 3단계: 모델 S3 업로드 ===")

        if config.USE_AWS:
            from utils import aws_helper

            upload_files = [
                ("models/ensemble_model.pkl", "models/ensemble_model.pkl"),
                ("models/scaler.pkl", "models/scaler.pkl"),
                ("models/model_meta.json", "models/model_meta.json")
            ]

            upload_success = 0
            for local_path, s3_key in upload_files:
                if os.path.exists(local_path):
                    if aws_helper.upload(local_path, s3_key):
                        upload_success += 1
                        print(f"✅ {s3_key} 업로드 완료")
                    else:
                        print(f"❌ {s3_key} 업로드 실패")

            print(f"S3 업로드: {upload_success}/{len(upload_files)}개 파일 성공")
        else:
            print("AWS가 비활성화되어 S3 업로드 건너뜀")

        progress.update("설정 완료")

        print("\n전체 자동화 플로우 완료!")
        print("=" * 50)

        # 최종 상태 출력
        try:
            import json
            with open("models/model_meta.json") as f:
                meta = json.load(f)

            print("최종 시스템 상태:")
            print(f"   정확도: {meta.get('accuracy', 0):.4f}")
            if 'test_accuracy' in meta and meta['test_accuracy']:
                print(f"   테스트 정확도: {meta.get('test_accuracy', 0):.4f}")
            if 'cv_accuracy' in meta and meta['cv_accuracy']:
                print(f"   교차검증 정확도: {meta.get('cv_accuracy', 0):.4f}")
            print(f"   훈련 샘플 수: {meta.get('total_samples', 0)}개")
            print(f"   모델 버전: {meta.get('model_version', '1.0')}")
            print(f"   훈련 완료 시각: {meta.get('trained_at', 'N/A')}")

        except Exception as meta_error:
            print(f"메타 정보 로드 실패: {meta_error}")

        print("\n다음 명령어로 GUI를 실행하세요:")
        print("python main.py")
        print("\n내장 서버가 자동으로 시작됩니다")

        return True

    except Exception as e:
        print(f"\n자동화 플로우 중 오류 발생: {str(e)}")
        return False


def quick_test():
    """빠른 기능 테스트"""
    print("=== 빠른 기능 테스트 ===")

    model_manager = ModelManager()

    if not model_manager.is_model_available():
        print("모델이 없습니다. 'python test_api.py setup' 실행 필요")
        return

    if not model_manager.load_model():
        print("모델 로드 실패")
        return

    print("✅ 모델 로드 성공")

    # 테스트 파일 수집
    test_files = []

    if os.path.exists(config.DIRECTORIES['malware_samples']):
        malware_files = [
            os.path.join(config.DIRECTORIES['malware_samples'], f)
            for f in os.listdir(config.DIRECTORIES['malware_samples'])[:3]
            if os.path.isfile(os.path.join(config.DIRECTORIES['malware_samples'], f))
        ]
        test_files.extend(malware_files)

    if os.path.exists(config.DIRECTORIES['clean_samples']):
        clean_files = [
            os.path.join(config.DIRECTORIES['clean_samples'], f)
            for f in os.listdir(config.DIRECTORIES['clean_samples'])[:3]
            if os.path.isfile(os.path.join(config.DIRECTORIES['clean_samples'], f))
        ]
        test_files.extend(clean_files)

    if not test_files:
        print("테스트할 파일이 없습니다")
        return

    print(f"\n{len(test_files)}개 파일 예측 테스트")

    for file_path in test_files:
        file_name = os.path.basename(file_path)
        expected_type = "악성" if config.DIRECTORIES['malware_samples'] in file_path else "정상"

        result = model_manager.predict_file(file_path)

        if "error" in result:
            print(f"❌ {file_name}: {result['error']}")
        else:
            prediction = result['prediction']
            confidence = result['confidence']

            accuracy_icon = "✅" if prediction == expected_type else "❌"

            print(f"{accuracy_icon} {file_name}: {prediction} (신뢰도: {confidence:.2f})")

    print("\n=== 테스트 완료 ===")


def show_system_info():
    """시스템 정보 표시"""
    print("=== 시스템 정보 ===")

    model_manager = ModelManager()

    # 모델 정보
    model_info = model_manager.get_model_info()
    print(f"모델 상태: {'사용 가능' if model_info['model_available'] else '없음'}")

    if model_info['model_available']:
        print(f"모델 크기: {model_info.get('model_size_mb', 0)} MB")
        print(f"스케일러 크기: {model_info.get('scaler_size_kb', 0)} KB")

    # 로컬 데이터 정보
    data_status = model_manager.get_training_data_status()
    print(f"로컬 훈련 데이터: 악성 {data_status['malware_samples']}개, 정상 {data_status['clean_samples']}개")
    print(f"데이터 상태: {'충분' if data_status['sufficient_data'] else '부족'}")

    # RDS 데이터 정보
    try:
        from utils.db import get_sample_statistics
        db_stats = get_sample_statistics()
        print(f"RDS 데이터: 악성 {db_stats.get('malicious_samples', 0)}개, 정상 {db_stats.get('clean_samples', 0)}개")
        print(f"RDS 총 샘플: {db_stats.get('total_samples', 0)}개")
    except Exception as e:
        print(f"RDS 연결 실패: {e}")

    # API 상태
    api_client = APIClient()
    mb_available = bool(api_client.malware_bazaar_key)
    vt_available = bool(api_client.virustotal_key)
    triage_available = bool(api_client.triage_key)

    print(f"MalwareBazaar API: {'사용 가능' if mb_available else '키 없음'}")
    print(f"VirusTotal API: {'사용 가능' if vt_available else '키 없음'}")
    print(f"Triage API: {'사용 가능' if triage_available else '키 없음'}")

    # AWS 상태
    print(f"AWS 연동: {'활성화' if config.USE_AWS else '비활성화'}")
    if config.USE_AWS:
        print(f"S3 버킷: {config.S3_BUCKET}")
        print(f"AWS 리전: {config.AWS_REGION}")

    # 서버 상태
    print(f"서버 모드: 내장 서버 (main.py에서 자동 시작)")


def automated_retrain():
    """자동화된 모델 재훈련"""
    print("=== 자동화된 모델 재훈련 ===")

    try:
        # 1단계: 새로운 샘플 수집
        print("1단계: 새로운 샘플 수집 중...")

        def progress_callback(message):
            print(f"[진행] {message}")

        malware_files, clean_files = collect_training_data_with_progress(
            malware_count=300,
            clean_count=50,
            progress_callback=progress_callback
        )

        print(f"수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
        malware_ratio = len(malware_files) / (len(malware_files) + len(clean_files)) * 100
        print(f"비율: 악성 {malware_ratio:.1f}%, 정상 {100 - malware_ratio:.1f}%")

        # 2단계: 기존 모델 삭제 및 재훈련
        print("2단계: 기존 모델 삭제 및 재훈련 중...")

        # 기존 모델 파일 삭제
        if os.path.exists("models/ensemble_model.pkl"):
            os.remove("models/ensemble_model.pkl")
            print("기존 모델 삭제 완료")

        if os.path.exists("models/scaler.pkl"):
            os.remove("models/scaler.pkl")
            print("기존 스케일러 삭제 완료")

        success = train_model()

        if success:
            print("✅ 모델 재훈련 성공!")

            # 3단계: S3 업로드
            if config.USE_AWS:
                print("3단계: S3 업로드 중...")
                from utils import aws_helper

                upload_files = [
                    ("models/ensemble_model.pkl", "models/ensemble_model.pkl"),
                    ("models/scaler.pkl", "models/scaler.pkl"),
                    ("models/model_meta.json", "models/model_meta.json")
                ]

                for local_path, s3_key in upload_files:
                    if os.path.exists(local_path):
                        aws_helper.upload(local_path, s3_key)

                print("✅ S3 업로드 완료")

            # 결과 출력
            try:
                import json
                with open("models/model_meta.json") as f:
                    meta = json.load(f)

                print("\n재훈련 결과:")
                print(f"정확도: {meta.get('accuracy', 0):.4f}")
                if 'test_accuracy' in meta and meta['test_accuracy']:
                    print(f"테스트 정확도: {meta.get('test_accuracy', 0):.4f}")
                if 'cv_accuracy' in meta and meta['cv_accuracy']:
                    print(f"교차검증 정확도: {meta.get('cv_accuracy', 0):.4f}")
                print(f"총 샘플: {meta.get('total_samples', 0)}개")
                print(f"모델 버전: {meta.get('model_version', 'N/A')}")
                print(f"훈련 완료: {meta.get('trained_at', 'N/A')}")

            except Exception as meta_error:
                print(f"메타 정보 로드 실패: {meta_error}")

        else:
            print("❌ 모델 재훈련 실패")

    except Exception as e:
        print(f"❌ 자동화된 재훈련 중 오류: {str(e)}")


def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(description="문서형 악성코드 무해화 시스템 v2.2 - CLI")
    subparsers = parser.add_subparsers(dest="command", help="실행할 명령어")

    # 명령어 정의
    parser_info = subparsers.add_parser("info", help="시스템의 현재 상태와 설정을 확인합니다.")
    parser_test = subparsers.add_parser("test", help="로드된 모델로 간단한 예측 테스트를 수행합니다.")
    parser_retrain = subparsers.add_parser("retrain", help="자동화된 전체 프로세스로 모델을 새로 훈련합니다.")
    parser_setup = subparsers.add_parser("setup", help="API 샘플 수집부터 모델 훈련까지 전체 시스템을 설정합니다.")

    # 샘플 수집 명령어
    parser_collect = subparsers.add_parser("collect", help="원하는 개수만큼 악성/정상 샘플을 수집합니다.")
    parser_collect.add_argument("-m", "--malware", type=int, default=100, help="수집할 악성 샘플 개수 (기본값: 100)")
    parser_collect.add_argument("-c", "--clean", type=int, default=50, help="수집할 정상 샘플 개수 (기본값: 50)")

    # 인자 파싱 및 실행
    args = parser.parse_args()

    if args.command == "info":
        show_system_info()
    elif args.command == "test":
        quick_test()
    elif args.command == "retrain":
        automated_retrain()
    elif args.command == "setup":
        setup_system_optimized()
    elif args.command == "collect":
        run_flexible_collection(args.malware, args.clean)
    else:
        test_system()


if __name__ == "__main__":
    main()