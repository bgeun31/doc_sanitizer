# utils/model_manager.py - 최종 버전 (AWS 지원)

import os
from typing import Dict, Any
import config
from utils.feature_extractor import FeatureExtractor
from utils.model_trainer import ModelTrainer
from utils import aws_helper


class ModelManager:
    def __init__(self):
        self.trainer = ModelTrainer()
        self.feature_extractor = FeatureExtractor()
        self.model_loaded = False

        # 지원 파일 형식 정의
        self.supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

    def is_model_available(self) -> bool:
        """훈련된 모델이 있는지 확인 (AWS 우선)"""
        if config.USE_AWS:
            # AWS S3에서 모델 확인
            try:
                s3_info = aws_helper.get_s3_model_info("models/ensemble_model.pkl")
                if "error" not in s3_info:
                    # S3에 모델이 있으면 로컬로 다운로드
                    if not os.path.exists(self.trainer.model_path):
                        aws_helper.download("models/ensemble_model.pkl", self.trainer.model_path)
                    if not os.path.exists(self.trainer.scaler_path):
                        aws_helper.download("models/scaler.pkl", self.trainer.scaler_path)

                    return (os.path.exists(self.trainer.model_path) and
                            os.path.exists(self.trainer.scaler_path))
            except Exception as e:
                print(f"AWS 모델 확인 실패: {e}")

        # 로컬 모델 확인
        return (os.path.exists(self.trainer.model_path) and
                os.path.exists(self.trainer.scaler_path))

    def load_model(self) -> bool:
        """모델 로드 (AWS 우선)"""
        if self.model_loaded:
            return True

        # AWS에서 최신 모델 동기화
        if config.USE_AWS:
            try:
                self._sync_model_from_aws()
            except Exception as e:
                print(f"AWS 모델 동기화 실패: {e}")

        if not self.is_model_available():
            return False

        success = self.trainer.load_model()
        if success:
            self.model_loaded = True

        return success

    def _sync_model_from_aws(self):
        """AWS S3에서 모델 동기화"""
        model_files = {
            "models/ensemble_model.pkl": self.trainer.model_path,
            "models/scaler.pkl": self.trainer.scaler_path,
            "models/model_meta.json": "models/model_meta.json"
        }

        for s3_key, local_path in model_files.items():
            # 로컬 디렉토리 생성
            local_dir = os.path.dirname(local_path)
            if local_dir:
                os.makedirs(local_dir, exist_ok=True)

            # 로컬 파일이 없으면 다운로드
            if not os.path.exists(local_path):
                print(f"AWS에서 {s3_key} 다운로드 중...")
                aws_helper.download(s3_key, local_path)
            else:
                # S3와 로컬 파일 비교 (선택사항)
                try:
                    s3_info = aws_helper.get_s3_model_info(s3_key)
                    if "error" not in s3_info:
                        print(f"AWS 모델 확인 완료: {s3_key}")
                except Exception:
                    pass

    def predict_file(self, file_path: str) -> Dict[str, Any]:
        """파일 악성코드 예측 (지원 형식만)"""
        # 파일 형식 확인
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.supported_extensions:
            return {
                "error": f"지원되지 않는 파일 형식: {ext}",
                "prediction": "알 수 없음",
                "confidence": 0.0,
                "supported_formats": list(self.supported_extensions)
            }

        # 모델 로드 확인
        if not self.model_loaded:
            if not self.load_model():
                return {
                    "error": "모델이 로드되지 않았습니다. 먼저 모델을 훈련해주세요.",
                    "prediction": "알 수 없음",
                    "confidence": 0.0
                }

        return self.trainer.predict(file_path)

    def get_model_info(self) -> Dict[str, Any]:
        """모델 정보 반환 (AWS 정보 포함)"""
        info = {
            "model_available": self.is_model_available(),
            "model_loaded": self.model_loaded,
            "model_path": self.trainer.model_path,
            "scaler_path": self.trainer.scaler_path,
            "supported_formats": list(self.supported_extensions),
            "aws_enabled": config.USE_AWS
        }

        if self.is_model_available():
            try:
                # 로컬 모델 파일 크기
                if os.path.exists(self.trainer.model_path):
                    model_size = os.path.getsize(self.trainer.model_path)
                    info["model_size_mb"] = round(model_size / (1024 * 1024), 2)
                    info["model_created"] = os.path.getctime(self.trainer.model_path)

                if os.path.exists(self.trainer.scaler_path):
                    scaler_size = os.path.getsize(self.trainer.scaler_path)
                    info["scaler_size_kb"] = round(scaler_size / 1024, 2)

                # AWS 정보
                if config.USE_AWS:
                    s3_info = aws_helper.get_s3_model_info("models/ensemble_model.pkl")
                    if "error" not in s3_info:
                        info["aws_model_info"] = s3_info
                    else:
                        info["aws_error"] = s3_info["error"]

                # 훈련 기록 정보
                if os.path.exists(self.trainer.training_history_path):
                    history_size = os.path.getsize(self.trainer.training_history_path)
                    info["training_history_available"] = True
                    info["history_size_kb"] = round(history_size / 1024, 2)
                else:
                    info["training_history_available"] = False

            except Exception as e:
                info["file_info_error"] = str(e)

        return info

    def train_new_model(self, incremental=True, upload_to_aws=True) -> bool:
        """새 모델 훈련 (AWS 업로드 포함)"""
        print(f"=== 모델 {'업데이트 (증분 학습)' if incremental else '전체 훈련'} 시작 ===")

        # 기존 모델 언로드
        self.model_loaded = False
        self.trainer.ensemble_model = None

        # 훈련 방식 선택
        if incremental and self.is_model_available():
            success = self.trainer.incremental_train_model()
        else:
            success = self.trainer.train_model()

        if success:
            # 새 모델 로드
            self.load_model()

            # AWS에 업로드
            if upload_to_aws and config.USE_AWS:
                self._upload_model_to_aws()

            print(f"모델 {'업데이트' if incremental else '훈련'} 및 로드 완료!")
        else:
            print(f"모델 {'업데이트' if incremental else '훈련'} 실패")

        return success

    def _upload_model_to_aws(self):
        """훈련된 모델을 AWS S3에 업로드"""
        try:
            upload_files = [
                (self.trainer.model_path, "models/ensemble_model.pkl"),
                (self.trainer.scaler_path, "models/scaler.pkl"),
                ("models/model_meta.json", "models/model_meta.json")
            ]

            for local_path, s3_key in upload_files:
                if os.path.exists(local_path):
                    aws_helper.upload(local_path, s3_key)
                    print(f"AWS 업로드 완료: {s3_key}")

        except Exception as e:
            print(f"AWS 업로드 실패: {e}")

    def evaluate_current_model(self):
        """현재 모델 평가"""
        if not self.model_loaded:
            if not self.load_model():
                print("평가할 모델이 없습니다")
                return

        self.trainer.evaluate_model()

    def get_training_data_status(self) -> Dict[str, int]:
        """훈련 데이터 상태 확인 (지원 형식만)"""
        malware_count = 0
        clean_count = 0

        # 악성 샘플 카운트
        if os.path.exists("sample/mecro"):
            for f in os.listdir("sample/mecro"):
                file_path = os.path.join("sample/mecro", f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in self.supported_extensions):
                    malware_count += 1

        # 정상 샘플 카운트 (clear 폴더로 변경)
        if os.path.exists(config.DIRECTORIES['clean_samples']):
            for f in os.listdir(config.DIRECTORIES['clean_samples']):
                file_path = os.path.join(config.DIRECTORIES['clean_samples'], f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in self.supported_extensions):
                    clean_count += 1

        return {
            "malware_samples": malware_count,
            "clean_samples": clean_count,
            "total_samples": malware_count + clean_count,
            "sufficient_data": malware_count >= 10 and clean_count >= 10,
            "supported_formats": list(self.supported_extensions)
        }

    def batch_predict(self, file_paths: list) -> Dict[str, Dict]:
        """다중 파일 예측 (지원 형식만)"""
        if not self.model_loaded:
            if not self.load_model():
                return {"error": "모델을 로드할 수 없습니다"}

        results = {}
        supported_files = []
        unsupported_files = []

        # 파일 형식 필터링
        for file_path in file_paths:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self.supported_extensions:
                supported_files.append(file_path)
            else:
                unsupported_files.append(file_path)

        # 지원되는 파일 예측
        for file_path in supported_files:
            try:
                file_name = os.path.basename(file_path)
                prediction = self.predict_file(file_path)
                results[file_name] = prediction
            except Exception as e:
                results[os.path.basename(file_path)] = {
                    "error": f"예측 실패: {str(e)}"
                }

        # 지원되지 않는 파일 기록
        for file_path in unsupported_files:
            file_name = os.path.basename(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            results[file_name] = {
                "error": f"지원되지 않는 파일 형식: {ext}",
                "supported_formats": list(self.supported_extensions)
            }

        return results

    def get_model_performance_summary(self) -> Dict[str, Any]:
        """모델 성능 요약 정보"""
        if not self.model_loaded:
            if not self.load_model():
                return {"error": "모델을 로드할 수 없습니다"}

        try:
            # 현재 데이터로 빠른 성능 테스트
            features, labels = self.trainer.prepare_training_data()
            if features is None:
                return {"error": "성능 테스트용 데이터가 없습니다"}

            # 정규화
            features_scaled = self.trainer.scaler.transform(features)

            # 예측
            predictions = self.trainer.ensemble_model.predict(features_scaled)
            probabilities = self.trainer.ensemble_model.predict_proba(features_scaled)

            # 정확도 계산
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

            accuracy = accuracy_score(labels, predictions)
            precision = precision_score(labels, predictions, average='weighted', zero_division=0)
            recall = recall_score(labels, predictions, average='weighted', zero_division=0)
            f1 = f1_score(labels, predictions, average='weighted', zero_division=0)

            return {
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "test_samples": len(features),
                "malware_detected": int(sum(predictions)),
                "clean_detected": int(len(predictions) - sum(predictions))
            }

        except Exception as e:
            return {"error": f"성능 평가 중 오류: {str(e)}"}

    def get_supported_formats_info(self) -> Dict[str, Any]:
        """지원 파일 형식 정보"""
        format_info = {
            '.hwp': '한글 문서 (Hancom Office)',
            '.hwpx': '한글 문서 XML (Hancom Office)',
            '.docx': 'Microsoft Word 문서',
            '.docm': 'Microsoft Word 매크로 문서',
            '.pdf': 'Adobe PDF 문서',
            '.pptx': 'Microsoft PowerPoint 프레젠테이션',
            '.pptm': 'Microsoft PowerPoint 매크로 프레젠테이션',
            '.xlsx': 'Microsoft Excel 스프레드시트',
            '.xlsm': 'Microsoft Excel 매크로 스프레드시트'
        }

        return {
            "supported_extensions": list(self.supported_extensions),
            "format_descriptions": format_info,
            "total_supported": len(self.supported_extensions)
        }


# 전역 모델 매니저 인스턴스
model_manager = ModelManager()


def get_model_manager() -> ModelManager:
    """모델 매니저 인스턴스 반환"""
    return model_manager