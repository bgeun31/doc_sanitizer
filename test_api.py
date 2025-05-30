import os
import sys
from dotenv import load_dotenv
from utils.api_client import APIClient, collect_training_data
from utils.model_manager import ModelManager
from utils.model_trainer import train_model


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


def test_system():
    """시스템 상태 확인"""
    print("=== 시스템 상태 확인 ===")

    load_dotenv()

    print("1. API 연결 상태")
    api_client = APIClient()

    # MalwareBazaar API
    mb_status = "✅" if api_client.malware_bazaar_key and api_client.test_malware_bazaar_connection() else "❌"
    print(f"   MalwareBazaar: {mb_status}")

    # Triage API (선택사항)
    triage_status = "✅" if hasattr(api_client,
                                   'triage_key') and api_client.triage_key and api_client.test_triage_connection() else "⚠️"
    print(f"   Triage: {triage_status} (선택사항)")

    print("\n2. AI 모델 상태")
    model_manager = ModelManager()

    model_available = model_manager.is_model_available()
    model_status = "✅" if model_available else "❌"
    print(f"   모델 파일: {model_status}")

    if model_available and model_manager.load_model():
        print(f"   모델 로드: ✅")
    else:
        print(f"   모델 로드: ❌")

    print("\n3. 훈련 데이터 상태")
    data_status = model_manager.get_training_data_status()
    print(f"   악성 샘플: {data_status['malware_samples']}개")
    print(f"   정상 샘플: {data_status['clean_samples']}개")

    data_sufficient = data_status['sufficient_data']
    sufficient_status = "✅" if data_sufficient else "⚠️"
    print(f"   데이터 충분성: {sufficient_status}")

    print("=" * 40)

    return {
        'api_available': bool(api_client.malware_bazaar_key),
        'model_available': model_available,
        'data_sufficient': data_sufficient,
        'data_status': data_status
    }


def setup_system_optimized():
    """최적화된 시스템 설정"""
    print("🚀 문서형 악성코드 무해화 시스템 v2.0 설정")
    print("=" * 50)

    test_results = test_system()

    if not test_results['api_available']:
        print("\n⚠️  API 키 설정 필요")
        print("1. .env 파일 생성")
        print("2. MALWARE_BAZAAR_API_KEY=발급받은_키 추가")
        print("3. API 키 발급: https://bazaar.abuse.ch/api/")
        return False

    # 설정 단계 계산
    steps_needed = 1  # 기본 체크
    if not test_results['data_sufficient']:
        steps_needed += 1
    if not test_results['model_available']:
        steps_needed += 1

    progress = OptimizedProgressTracker(steps_needed)
    print(f"\n📋 {steps_needed}단계 설정 시작")

    # 데이터 수집
    if not test_results['data_sufficient']:
        current_malware = test_results['data_status']['malware_samples']
        current_clean = test_results['data_status']['clean_samples']

        print(f"\n현재 데이터: 악성 {current_malware}개, 정상 {current_clean}개")

        proceed = input("데이터를 수집하시겠습니까? (y/n): ").lower()
        if proceed != 'y':
            print("설정을 중단합니다.")
            return False

        try:
            progress.update("훈련 데이터 수집 중")
            collect_training_data(malware_count=300, clean_count=300)
            print("\n✅ 데이터 수집 완료")
        except Exception as e:
            print(f"\n❌ 데이터 수집 실패: {e}")
            return False

    # 모델 훈련
    if not test_results['model_available']:
        proceed = input("\nAI 모델을 훈련하시겠습니까? (y/n): ").lower()
        if proceed != 'y':
            print("설정을 중단합니다.")
            return False

        try:
            progress.update("AI 모델 훈련 중")
            success = train_model()
            if success:
                print("\n✅ 모델 훈련 완료")
            else:
                print("\n❌ 모델 훈련 실패")
                return False
        except Exception as e:
            print(f"\n❌ 모델 훈련 실패: {e}")
            return False

    progress.update("설정 완료")

    print("\n🎉 시스템 설정 완료!")
    print("다음 명령어로 GUI를 실행하세요:")
    print("python main.py")

    # 최종 상태 확인
    final_test = test_system()
    total_samples = final_test['data_status']['malware_samples'] + final_test['data_status']['clean_samples']
    model_status = "사용 가능" if final_test['model_available'] else "사용 불가"

    print(f"\n📊 최종 상태")
    print(f"   총 훈련 샘플: {total_samples}개")
    print(f"   AI 모델: {model_status}")

    return True


def quick_test():
    """빠른 기능 테스트"""
    print("=== 빠른 기능 테스트 ===")

    model_manager = ModelManager()

    if not model_manager.is_model_available():
        print("❌ 모델이 없습니다. 'python test_api.py setup' 실행 필요")
        return

    if not model_manager.load_model():
        print("❌ 모델 로드 실패")
        return

    print("✅ 모델 로드 성공")

    # 테스트 파일 수집
    test_files = []

    if os.path.exists("sample/mecro"):
        malware_files = [
            os.path.join("sample/mecro", f)
            for f in os.listdir("sample/mecro")[:3]
            if os.path.isfile(os.path.join("sample/mecro", f))
        ]
        test_files.extend(malware_files)

    if os.path.exists("sample/clear"):
        clean_files = [
            os.path.join("sample/clear", f)
            for f in os.listdir("sample/clear")[:3]
            if os.path.isfile(os.path.join("sample/clear", f))
        ]
        test_files.extend(clean_files)

    if not test_files:
        print("⚠️  테스트할 파일이 없습니다")
        return

    print(f"\n🧪 {len(test_files)}개 파일 예측 테스트")

    for file_path in test_files:
        file_name = os.path.basename(file_path)
        expected_type = "악성" if "mecro" in file_path else "정상"

        result = model_manager.predict_file(file_path)

        if "error" in result:
            print(f"❌ {file_name}: {result['error']}")
        else:
            prediction = result['prediction']
            confidence = result['confidence']

            # 정확도 확인
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

    # 데이터 정보
    data_status = model_manager.get_training_data_status()
    print(f"훈련 데이터: 악성 {data_status['malware_samples']}개, 정상 {data_status['clean_samples']}개")
    print(f"데이터 상태: {'충분' if data_status['sufficient_data'] else '부족'}")

    # API 상태
    api_client = APIClient()
    mb_available = bool(api_client.malware_bazaar_key)
    triage_available = bool(hasattr(api_client, 'triage_key') and api_client.triage_key)

    print(f"MalwareBazaar API: {'사용 가능' if mb_available else '키 없음'}")
    print(f"Triage API: {'사용 가능' if triage_available else '키 없음 (선택사항)'}")


def main():
    """메인 실행 함수"""
    import sys

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "setup":
            setup_system_optimized()
        elif command == "test":
            quick_test()
        elif command == "info":
            show_system_info()
        else:
            print("사용법:")
            print("  python test_api.py setup  - 시스템 초기 설정")
            print("  python test_api.py test   - 빠른 기능 테스트")
            print("  python test_api.py info   - 시스템 정보 확인")
    else:
        # 기본 실행: 시스템 상태 확인
        test_system()


if __name__ == "__main__":
    main()