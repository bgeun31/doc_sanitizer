# -*- coding: utf-8 -*-

import os
import pickle
import numpy as np
import hashlib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.utils.class_weight import compute_class_weight
import pandas as pd
from sqlalchemy import text

# 로컬 모듈 임포트
from utils.feature_extractor import FeatureExtractor
from utils import db, aws_helper
import config


class ModelTrainer:
    """
    악성코드 탐지 모델의 훈련, 평가, 예측, 저장, 로드 등 전체 파이프라인을 관리하는 클래스.
    데이터 준비, 특징 추출, 앙상블 모델 훈련, 성능 평가 및 모델 배포 관련 기능을 포함합니다.
    """

    def __init__(self):
        """ModelTrainer 초기화. 모델 및 관련 파일 경로를 설정합니다."""
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        self.ensemble_model = None
        self.model_path = "models/ensemble_model.pkl"
        self.scaler_path = "models/scaler.pkl"
        self.training_history_path = "models/training_history.pkl"

        os.makedirs("models", exist_ok=True)

    def prepare_training_data(self, malware_dir: str = None,
                              clean_dir: str = None, use_db: bool = True) -> tuple:
        """
        훈련 데이터를 준비합니다. 로컬 디렉토리와 RDS 데이터베이스에서 샘플을 로드하고,
        중복을 제거한 뒤 특징 벡터와 라벨을 반환합니다.

        :param malware_dir: 악성 샘플이 저장된 로컬 디렉토리
        :param clean_dir: 정상 샘플이 저장된 로컬 디렉토리
        :param use_db: RDS 데이터베이스 사용 여부
        :return: (특징 벡터, 라벨) 튜플. 데이터 준비 실패 시 (None, None).
        """
        print("=== 훈련 데이터 준비 중 ===")
        malware_dir = malware_dir or config.DIRECTORIES['malware_samples']
        clean_dir = clean_dir or config.DIRECTORIES['clean_samples']
        supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

        rds_malware_files, rds_clean_files = [], []
        if use_db:
            print("RDS에서 샘플 다운로드 중...")
            try:
                db_samples = self._load_training_data_from_db()
                print(f"RDS에서 로드된 샘플: {len(db_samples)}개")
                os.makedirs("temp_db_samples", exist_ok=True)

                for sample in db_samples:
                    if sample.s3_key and config.USE_AWS:
                        file_ext = sample.file_type or os.path.splitext(sample.file_name)[1]
                        local_path = os.path.join("temp_db_samples", f"{sample.file_hash[:16]}{file_ext}")
                        if aws_helper.download_virus_sample(sample.s3_key, local_path):
                            (rds_malware_files if sample.is_malicious else rds_clean_files).append(local_path)
                        else:
                            print(f"S3 다운로드 실패: {sample.s3_key}")
                print(f"RDS 샘플 다운로드: 악성 {len(rds_malware_files)}개, 정상 {len(rds_clean_files)}개")
            except Exception as db_error:
                print(f"RDS 로드 실패: {db_error}")

        # 로컬 파일 시스템에서 샘플 수집
        local_malware_files = [os.path.join(malware_dir, f) for f in os.listdir(malware_dir)
                               if os.path.isfile(os.path.join(malware_dir, f)) and os.path.splitext(f)[
                                   1].lower() in supported_extensions] if os.path.exists(malware_dir) else []
        local_clean_files = [os.path.join(clean_dir, f) for f in os.listdir(clean_dir)
                             if os.path.isfile(os.path.join(clean_dir, f)) and os.path.splitext(f)[
                                 1].lower() in supported_extensions] if os.path.exists(clean_dir) else []
        print(f"로컬 샘플: 악성 {len(local_malware_files)}개, 정상 {len(local_clean_files)}개")

        # RDS 데이터와 로컬 데이터를 합치고 중복 제거
        final_malware_files = self._remove_duplicate_files(rds_malware_files + local_malware_files)
        final_clean_files = self._remove_duplicate_files(rds_clean_files + local_clean_files)

        all_files = final_malware_files + final_clean_files
        all_labels = [1] * len(final_malware_files) + [0] * len(final_clean_files)

        if not all_files or len(final_malware_files) < 20 or len(final_clean_files) < 10:
            print("훈련 데이터 부족. (악성 최소 20개, 정상 최소 10개 필요)")
            return None, None

        print(f"최종 훈련 데이터: 악성 {len(final_malware_files)}개, 정상 {len(final_clean_files)}개 (총 {len(all_files)}개)")

        # 특징 추출
        print("특징 추출 중...")
        features = self.feature_extractor.extract_features_batch(all_files)
        labels = np.array(all_labels)

        print(f"특징 벡터 크기: {features.shape}")
        return features, labels

    def _remove_duplicate_files(self, file_paths: list) -> list:
        """SHA256 해시를 이용해 파일 리스트에서 중복을 제거합니다."""
        unique_files, seen_hashes = [], set()
        for file_path in file_paths:
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash not in seen_hashes:
                    unique_files.append(file_path)
                    seen_hashes.add(file_hash)
                else:
                    # 중복 발견 시 제거 로깅 (물리적 파일 삭제는 하지 않음)
                    print(f"중복 파일 건너뛰기: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"파일 해시 계산 실패 ({file_path}): {e}")
        return unique_files

    def _load_training_data_from_db(self):
        """RDS 데이터베이스에서 훈련 데이터를 로드합니다."""
        try:
            return db.get_training_samples(limit=2000)
        except Exception as e:
            print(f"RDS 데이터 로드 실패: {e}")
            return []

    def _cleanup_temp_files(self):
        """훈련 중 RDS에서 다운로드한 임시 파일들을 정리합니다."""
        temp_dir = "temp_db_samples"
        if os.path.exists(temp_dir):
            try:
                removed_count = 0
                for filename in os.listdir(temp_dir):
                    os.remove(os.path.join(temp_dir, filename))
                    removed_count += 1
                print(f"임시 파일 정리 완료: {removed_count}개 파일 삭제")
            except Exception as e:
                print(f"임시 파일 정리 오류: {e}")

    def _train_with_data(self, features: np.ndarray, labels: np.ndarray, test_size: float) -> tuple:
        """
        주어진 특징과 라벨 데이터로 실제 모델 훈련, 평가, 저장을 수행합니다.
        데이터 불균형 처리를 위해 클래스 가중치(class_weight)를 사용합니다.
        """
        try:
            # 원본 데이터의 불균형 비율을 그대로 사용하여 훈련
            print(f"\n=== 원본 데이터로 훈련 시작 ===")
            print(f"악성: {int(np.sum(labels))}개, 정상: {int(len(labels) - np.sum(labels))}개 (총 {len(features)}개)")

            # 데이터셋을 훈련 세트와 테스트 세트로 분할 (계층적 샘플링)
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=test_size, random_state=42,
                stratify=labels if len(np.unique(labels)) > 1 else None
            )

            # 데이터 불균형을 보정하기 위한 클래스별 가중치 계산
            class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
            class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
            print(f"클래스 가중치 적용: {class_weight_dict}")

            # 데이터 정규화 (Standard Scaling)
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # 개별 모델 훈련
            trained_models, _ = self.train_individual_models(X_train_scaled, X_test_scaled, y_train, y_test,
                                                             class_weight_dict)

            # 앙상블 모델 생성 및 훈련
            self.ensemble_model = self.create_ensemble_model(trained_models)
            self.ensemble_model.fit(X_train_scaled, y_train)

            print("\n=== 앙상블 모델 최종 평가 ===")
            ensemble_pred = self.ensemble_model.predict(X_test_scaled)
            test_accuracy = accuracy_score(y_test, ensemble_pred)

            # 교차 검증 (Stratified K-Fold)
            cv_folds = min(5, np.sum(y_train), len(y_train) - np.sum(y_train))
            cv_mean = test_accuracy
            if cv_folds > 1:
                skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
                cv_scores = cross_val_score(self.ensemble_model, X_train_scaled, y_train, cv=skf, scoring='accuracy')
                cv_mean = cv_scores.mean()

            # 최종 성능 지표 계산
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, ensemble_pred, average='weighted',
                                                                       zero_division=0)
            print(classification_report(y_test, ensemble_pred, target_names=['정상', '악성'], zero_division=0))
            print(f"혼동 행렬:\n{confusion_matrix(y_test, ensemble_pred)}")

            # 모델 저장 및 메타데이터 기록
            self.save_model()
            final_accuracy = min(test_accuracy, cv_mean)
            self.save_model_metadata(accuracy=final_accuracy, test_accuracy=test_accuracy, cv_accuracy=cv_mean,
                                     precision=precision, recall=recall, f1_score=f1,
                                     malware_count=int(np.sum(labels)), clean_count=int(len(labels) - np.sum(labels)),
                                     class_weights=class_weight_dict)

            if config.USE_AWS: self._upload_to_aws()
            self._cleanup_temp_files()
            print("모델 훈련 완료!")
            return True, final_accuracy

        except Exception as e:
            print(f"모델 훈련 실패: {e}")
            import traceback
            traceback.print_exc()
            self._cleanup_temp_files()
            return False, None

    def train_individual_models(self, X_train, X_test, y_train, y_test, class_weights: dict) -> tuple:
        """개별 분류기(RandomForest, GradientBoosting, SVM)를 훈련하고 평가합니다."""
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=200, random_state=42, class_weight=class_weights,
                                                   max_depth=10),
            'GradientBoosting': GradientBoostingClassifier(n_estimators=150, random_state=42, max_depth=6),
            'SVM': SVC(kernel='rbf', probability=True, random_state=42, class_weight=class_weights)
        }
        trained_models, model_scores = {}, {}
        print("\n=== 개별 모델 훈련 및 평가 ===")
        for name, model in models.items():
            print(f"\n{name} 훈련 중...")
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted',
                                                                       zero_division=0)

            trained_models[name] = model
            model_scores[name] = {'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1_score': f1}
            print(f"{name} - 정확도: {accuracy:.4f}, 정밀도: {precision:.4f}, 재현율: {recall:.4f}")
        return trained_models, model_scores

    def save_model_metadata(self, **kwargs):
        """훈련된 모델의 상세 메타데이터를 JSON 파일로 저장합니다."""
        from datetime import datetime
        meta = {
            "model_version": "2.3",
            "trained_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "data_balancing_strategy": "Class Weighting (No Resampling)",
            **kwargs
        }
        with open("models/model_meta.json", "w") as f:
            # numpy 타입을 python 기본 타입으로 변환하여 저장
            for k, v in meta.items():
                if isinstance(v, np.ndarray):
                    meta[k] = v.tolist()
                elif isinstance(v, (np.float32, np.float64)):
                    meta[k] = float(v)
            json.dump(meta, f, indent=2)
        print("model_meta.json 저장 완료.")

    def save_training_history(self, features: np.ndarray, labels: np.ndarray, accuracy: float,
                              model_version: str = "2.3"):
        """증분 학습을 위해 현재 훈련에 사용된 데이터와 성능을 저장합니다."""
        history_data = {
            "features": features, "labels": labels, "model_version": model_version,
            "training_date": pd.Timestamp.now(), "sample_count": len(features), "accuracy": accuracy
        }
        # RDS와 로컬 파일에 이중으로 기록 저장
        try:
            db.save_training_history(model_version, len(features), accuracy)
            print("RDS 훈련 기록 저장 완료")
        except Exception as rds_error:
            print(f"RDS 기록 저장 실패: {rds_error}")

        with open(self.training_history_path, "wb") as f:
            pickle.dump(history_data, f)
        print(f"로컬 훈련 기록 저장 완료: {len(features)}개 샘플, 정확도={accuracy:.3f}")

    def load_training_history(self) -> tuple:
        """증분 학습을 위해 저장된 이전 훈련 기록을 로드합니다."""
        if os.path.exists(self.training_history_path):
            try:
                with open(self.training_history_path, 'rb') as f:
                    history = pickle.load(f)
                print(f"이전 훈련 기록 로드: {history['sample_count']}개 샘플 (버전: {history['model_version']})")
                return history['features'], history['labels']
            except Exception as e:
                print(f"훈련 기록 로드 실패: {e}")
        return None, None

    def incremental_train_model(self, test_size: float = 0.25) -> bool:
        """
        기존 훈련 데이터에 새로운 데이터를 추가하여 모델을 재훈련(증분 학습)합니다.
        특징 벡터의 크기가 다를 경우, 새 데이터로만 훈련합니다.
        """
        print("=== 모델 증분 학습 시작 ===")
        new_features, new_labels = self.prepare_training_data(use_db=True)
        if new_features is None or len(new_features) == 0:
            print("새로운 훈련 데이터가 없어 증분 학습을 건너뜁니다.")
            return False

        old_features, old_labels = self.load_training_history()
        if old_features is not None and old_features.shape[1] == new_features.shape[1]:
            print(f"기존 데이터({len(old_features)}개)와 새 데이터({len(new_features)}개)를 결합합니다.")
            combined_features = np.vstack([old_features, new_features])
            combined_labels = np.concatenate([old_labels, new_labels])
        else:
            if old_features is not None:
                print("특징 벡터 크기가 변경되어 새 데이터로만 훈련합니다.")
            else:
                print("기존 데이터가 없어 새 데이터로만 훈련합니다.")
            combined_features, combined_labels = new_features, new_labels

        success, accuracy = self._train_with_data(combined_features, combined_labels, test_size)
        if success: self.save_training_history(combined_features, combined_labels, accuracy, "2.3+")
        return success

    def train_model(self, test_size: float = 0.25) -> bool:
        """전체 데이터를 처음부터 새로 훈련합니다 (Full Training)."""
        print("=== 모델 전체 훈련 시작 ===")
        features, labels = self.prepare_training_data(use_db=True)
        if features is None or len(features) == 0:
            print("훈련 데이터가 없어 전체 훈련을 중단합니다.")
            return False

        success, accuracy = self._train_with_data(features, labels, test_size)
        if success: self.save_training_history(features, labels, accuracy, "2.3")
        return success

    def _upload_to_aws(self):
        """훈련된 모델과 관련 파일들을 AWS S3에 업로드합니다."""
        print("AWS S3에 모델 파일 업로드 중...")
        try:
            for local_path, s3_key in [
                (self.model_path, "models/ensemble_model.pkl"),
                (self.scaler_path, "models/scaler.pkl"),
                ("models/model_meta.json", "models/model_meta.json")
            ]:
                if os.path.exists(local_path): aws_helper.upload(local_path, s3_key)
            print("AWS 업로드 완료")
        except Exception as e:
            print(f"AWS 업로드 실패: {e}")

    def create_ensemble_model(self, trained_models: dict) -> VotingClassifier:
        """
        훈련된 개별 모델들을 소프트 보팅(Soft Voting) 방식의 앙상블 모델로 결합합니다.
        각 모델의 예측 확률을 평균내어 최종 예측을 수행합니다.
        """
        print("\n소프트 보팅 앙상블 모델 생성...")
        return VotingClassifier(
            estimators=[(name, model) for name, model in trained_models.items()],
            voting='soft'
        )

    def save_model(self):
        """훈련된 앙상블 모델과 데이터 스케일러를 파일로 저장합니다."""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.ensemble_model, f)
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            print(f"모델 저장 완료: {self.model_path}")
        except Exception as e:
            print(f"모델 저장 실패: {e}")

    def load_model(self) -> bool:
        """저장된 모델과 스케일러를 로드합니다."""
        if not os.path.exists(self.model_path): return False
        try:
            with open(self.model_path, 'rb') as f:
                self.ensemble_model = pickle.load(f)
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            print("저장된 모델 로드 완료.")
            return True
        except Exception as e:
            print(f"모델 로드 실패: {e}")
            return False

    def predict(self, file_path: str) -> dict:
        """
        단일 파일에 대해 악성 여부를 예측합니다.
        개선된 신뢰도 계산법을 적용하여 예측의 확신도를 함께 반환합니다.
        """
        if self.ensemble_model is None and not self.load_model():
            return {"error": "모델을 로드할 수 없습니다"}

        try:
            features = self.feature_extractor.extract_features_batch([file_path])
            if features is None or len(features) == 0:
                return {"error": "파일에서 특징을 추출할 수 없습니다."}

            features_scaled = self.scaler.transform(features)
            prediction = self.ensemble_model.predict(features_scaled)[0]
            probability = self.ensemble_model.predict_proba(features_scaled)[0]

            # 예측 확률의 차이를 이용해 신뢰도(Confidence) 조정
            confidence = max(probability) * (0.5 + 0.5 * abs(probability[1] - probability[0]))

            return {
                "prediction": "악성" if prediction == 1 else "정상",
                "confidence": float(confidence),
                "malware_probability": float(probability[1]),
                "clean_probability": float(probability[0])
            }
        except Exception as e:
            return {"error": f"예측 중 오류 발생: {str(e)}"}

    def evaluate_model(self):
        """현재 로드된 모델의 성능을 전체 데이터셋으로 다시 평가합니다."""
        print("=== 모델 성능 재평가 ===")
        features, labels = self.prepare_training_data(use_db=True)
        if features is None: return

        features_scaled = self.scaler.transform(features)
        predictions = self.ensemble_model.predict(features_scaled)

        print(classification_report(labels, predictions, target_names=['정상', '악성'], zero_division=0))
        print(f"혼동 행렬:\n{confusion_matrix(labels, predictions)}")


def train_model():
    """모델 훈련을 실행하기 위한 메인 함수."""
    trainer = ModelTrainer()
    try:
        # 데이터 현황 출력
        db_stats = db.get_sample_statistics()
        print(f"RDS 데이터 현황: 악성 {db_stats.get('malicious_samples', 0)}개, 정상 {db_stats.get('clean_samples', 0)}개")
    except Exception as e:
        print(f"RDS 연결 실패 또는 통계 조회 오류: {e}")

    # 모델 훈련 실행
    if trainer.train_model():
        trainer.evaluate_model()


if __name__ == "__main__":
    train_model()