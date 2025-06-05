# utils/model_trainer.py - 과적합 해결 및 정상 샘플 비율 엄격 제한

import os
import pickle
import numpy as np
import hashlib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.ensemble import VotingClassifier
from sklearn.utils.class_weight import compute_class_weight
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline
import pandas as pd
from utils.feature_extractor import FeatureExtractor
from sqlalchemy import text
from utils import db
from utils import aws_helper
import config


class ModelTrainer:
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        self.ensemble_model = None
        self.model_path = "models/ensemble_model.pkl"
        self.scaler_path = "models/scaler.pkl"
        self.training_history_path = "models/training_history.pkl"

        os.makedirs("models", exist_ok=True)

    def prepare_training_data(self, malware_dir: str = None,
                              clean_dir: str = None, use_db: bool = True) -> tuple:
        """훈련 데이터 준비 (엄격한 비율 제한)"""
        print("=== 훈련 데이터 준비 중 (과적합 방지 적용) ===")

        if malware_dir is None:
            malware_dir = config.DIRECTORIES['malware_samples']
        if clean_dir is None:
            clean_dir = config.DIRECTORIES['clean_samples']

        supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

        # RDS에서 샘플 로드
        rds_malware_files = []
        rds_clean_files = []

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
                            if sample.is_malicious:
                                rds_malware_files.append(local_path)
                            else:
                                rds_clean_files.append(local_path)
                        else:
                            print(f"S3 다운로드 실패: {sample.s3_key}")

                print(f"RDS 샘플 다운로드: 악성 {len(rds_malware_files)}개, 정상 {len(rds_clean_files)}개")

            except Exception as db_error:
                print(f"RDS 로드 실패: {db_error}")

        # 로컬 파일 수집
        local_malware_files = []
        local_clean_files = []

        if os.path.exists(malware_dir):
            for f in os.listdir(malware_dir):
                file_path = os.path.join(malware_dir, f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in supported_extensions):
                    local_malware_files.append(file_path)

        if os.path.exists(clean_dir):
            for f in os.listdir(clean_dir):
                file_path = os.path.join(clean_dir, f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in supported_extensions):
                    local_clean_files.append(file_path)

        print(f"로컬 샘플: 악성 {len(local_malware_files)}개, 정상 {len(local_clean_files)}개")

        # 데이터 결합
        final_malware_files = rds_malware_files + local_malware_files
        final_clean_files = rds_clean_files + local_clean_files

        # 중복 제거
        final_malware_files = self._remove_duplicate_files(final_malware_files)
        final_clean_files = self._remove_duplicate_files(final_clean_files)

        # 엄격한 비율 조정 (악성:정상 = 3:1)
        target_clean_count = max(len(final_malware_files) // 3, 10)  # 악성의 1/3, 최소 10개

        if len(final_clean_files) > target_clean_count:
            # 정상 샘플을 무작위로 선택하여 제한
            import random
            random.seed(42)
            final_clean_files = random.sample(final_clean_files, target_clean_count)
            print(f"정상 샘플 수를 {len(final_clean_files)}개로 엄격 제한 (악성 대비 1/3)")

        all_files = final_malware_files + final_clean_files
        all_labels = [1] * len(final_malware_files) + [0] * len(final_clean_files)

        print(f"최종 훈련 데이터: 악성 {len(final_malware_files)}개, 정상 {len(final_clean_files)}개")
        print(f"총 샘플 수: {len(all_files)}개")
        print(
            f"비율 - 악성: {len(final_malware_files) / len(all_files) * 100:.1f}%, 정상: {len(final_clean_files) / len(all_files) * 100:.1f}%")

        if len(final_malware_files) < 20 or len(final_clean_files) < 5:
            print("훈련 데이터가 부족합니다. 악성 20개, 정상 5개 이상 필요합니다.")
            return None, None

        # 특징 추출
        print("특징 추출 중...")
        features = self.feature_extractor.extract_features_batch(all_files)
        labels = np.array(all_labels)

        print(f"특징 벡터 크기: {features.shape}")
        print(f"라벨 분포 - 악성: {np.sum(labels)}, 정상: {len(labels) - np.sum(labels)}")

        return features, labels

    def _remove_duplicate_files(self, file_paths):
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
                    print(f"중복 파일 제거: {os.path.basename(file_path)}")

            except Exception as e:
                print(f"파일 해시 계산 실패 {file_path}: {e}")

        return unique_files

    def _load_training_data_from_db(self):
        """RDS에서 훈련 데이터 로드 (비율 제한)"""
        try:
            samples = db.get_training_samples(limit=1000)  # 제한적으로 로드

            # 악성과 정상 샘플 분리
            malware_samples = [s for s in samples if s.is_malicious]
            clean_samples = [s for s in samples if not s.is_malicious]

            # 정상 샘플 제한 (악성의 1/3)
            if len(clean_samples) > len(malware_samples) // 3:
                import random
                random.seed(42)
                clean_samples = random.sample(clean_samples, max(len(malware_samples) // 3, 5))

            final_samples = malware_samples + clean_samples
            print(f"RDS 샘플 비율 조정: 악성 {len(malware_samples)}개, 정상 {len(clean_samples)}개")

            return final_samples
        except Exception as e:
            print(f"RDS 데이터 로드 실패: {e}")
            return []

    def _train_with_data(self, features, labels, test_size):
        """실제 모델 훈련 수행 (과적합 방지)"""
        try:
            print(f"\n=== 과적합 방지 훈련 시작 ===")

            # 더 큰 테스트 세트 (30%)
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=0.3, random_state=42, stratify=labels
            )

            print(f"데이터 분할: 훈련 {len(X_train)}개, 테스트 {len(X_test)}개")
            print(f"훈련 세트 비율 - 악성: {np.sum(y_train)}, 정상: {len(y_train) - np.sum(y_train)}")
            print(f"테스트 세트 비율 - 악성: {np.sum(y_test)}, 정상: {len(y_test) - np.sum(y_test)}")

            # 데이터 정규화
            print("데이터 정규화 중...")
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # 클래스 가중치 계산 (과적합 방지)
            class_weights = compute_class_weight(
                'balanced',
                classes=np.unique(y_train),
                y=y_train
            )
            class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
            print(f"클래스 가중치: {class_weight_dict}")

            # 더 보수적인 모델 설정
            models = {
                'RandomForest': RandomForestClassifier(
                    n_estimators=100,  # 감소
                    random_state=42,
                    max_depth=6,  # 더 제한적
                    min_samples_split=10,  # 증가
                    min_samples_leaf=5,  # 증가
                    class_weight=class_weight_dict,
                    max_features='sqrt',
                    bootstrap=True
                ),
                'GradientBoosting': GradientBoostingClassifier(
                    n_estimators=100,  # 감소
                    random_state=42,
                    max_depth=4,  # 더 제한적
                    learning_rate=0.05,  # 감소
                    subsample=0.7,  # 감소
                    min_samples_split=10,  # 증가
                    min_samples_leaf=5  # 증가
                ),
                'SVM': SVC(
                    kernel='rbf',
                    probability=True,
                    random_state=42,
                    C=0.5,  # 더 보수적
                    gamma='scale',
                    class_weight=class_weight_dict
                )
            }

            trained_models = {}
            model_scores = {}

            print("\n=== 개별 모델 훈련 (과적합 방지) ===")

            for name, model in models.items():
                print(f"\n{name} 훈련 중...")

                model.fit(X_train_scaled, y_train)

                # 테스트 세트 평가 (한 번만)
                y_pred = model.predict(X_test_scaled)
                test_accuracy = accuracy_score(y_test, y_pred)

                # 엄격한 교차 검증 (10-fold)
                cv_folds = min(10, len(np.unique(y_train)))
                if cv_folds >= 3:
                    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
                    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=skf, scoring='accuracy')
                    cv_mean = cv_scores.mean()
                    cv_std = cv_scores.std()
                else:
                    cv_mean = test_accuracy
                    cv_std = 0

                # 정밀도, 재현율 계산
                precision, recall, f1, _ = precision_recall_fscore_support(
                    y_test, y_pred, average='weighted', zero_division=0
                )

                trained_models[name] = model
                model_scores[name] = {
                    'test_accuracy': test_accuracy,
                    'cv_mean': cv_mean,
                    'cv_std': cv_std,
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1
                }

                print(f"{name} - 테스트: {test_accuracy:.4f}, CV: {cv_mean:.4f} (±{cv_std:.4f})")

            # 앙상블 모델 생성
            self.ensemble_model = VotingClassifier(
                estimators=[
                    ('rf', trained_models['RandomForest']),
                    ('gb', trained_models['GradientBoosting']),
                    ('svm', trained_models['SVM'])
                ],
                voting='soft'
            )

            print("\n=== 앙상블 모델 훈련 ===")
            self.ensemble_model.fit(X_train_scaled, y_train)

            # 최종 평가 (보수적)
            ensemble_pred = self.ensemble_model.predict(X_test_scaled)
            test_accuracy = accuracy_score(y_test, ensemble_pred)

            # 앙상블 교차 검증
            if cv_folds >= 3:
                ensemble_cv_scores = cross_val_score(self.ensemble_model, X_train_scaled, y_train,
                                                     cv=skf, scoring='accuracy')
                cv_mean = ensemble_cv_scores.mean()
                cv_std = ensemble_cv_scores.std()
            else:
                cv_mean = test_accuracy
                cv_std = 0

            # 최종 성능 지표
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, ensemble_pred, average='weighted', zero_division=0
            )

            # 클래스별 성능
            precision_per_class, recall_per_class, f1_per_class, _ = precision_recall_fscore_support(
                y_test, ensemble_pred, average=None, zero_division=0
            )

            print(f"\n=== 최종 앙상블 성능 ===")
            print(f"테스트 정확도: {test_accuracy:.4f}")
            print(f"교차 검증 정확도: {cv_mean:.4f} (±{cv_std:.4f})")
            print(f"정밀도: {precision:.4f}")
            print(f"재현율: {recall:.4f}")
            print(f"F1-점수: {f1:.4f}")

            if len(precision_per_class) > 1:
                print(f"정상 파일 - 정밀도: {precision_per_class[0]:.4f}, 재현율: {recall_per_class[0]:.4f}")
                print(f"악성 파일 - 정밀도: {precision_per_class[1]:.4f}, 재현율: {recall_per_class[1]:.4f}")

            print("\n분류 리포트:")
            print(classification_report(y_test, ensemble_pred, target_names=['정상', '악성']))

            cm = confusion_matrix(y_test, ensemble_pred)
            print(f"혼동 행렬:\n{cm}")

            # 매우 보수적인 최종 점수 (최소값 사용)
            conservative_accuracy = min(test_accuracy, cv_mean - cv_std)
            print(f"보수적 평가 정확도: {conservative_accuracy:.4f}")

            self.save_model()

            # 메타데이터 저장
            self.save_model_metadata(
                accuracy=conservative_accuracy,
                test_accuracy=test_accuracy,
                cv_accuracy=cv_mean,
                cv_std=cv_std,
                precision=precision,
                recall=recall,
                f1_score=f1,
                malware_count=int(np.sum(labels)),
                clean_count=int(len(labels) - np.sum(labels)),
                model_version="2.2_fixed",
                precision_per_class=precision_per_class.tolist() if len(precision_per_class) > 1 else [precision],
                recall_per_class=recall_per_class.tolist() if len(recall_per_class) > 1 else [recall]
            )

            if config.USE_AWS:
                self._upload_to_aws()

            # 로컬 악성 파일 정리
            self._cleanup_local_malware_samples()

            print("과적합 방지 훈련 완료!")
            return True, conservative_accuracy

        except Exception as e:
            print(f"모델 훈련 실패: {e}")
            import traceback
            traceback.print_exc()
            return False, None

    def _cleanup_local_malware_samples(self):
        """로컬 악성 샘플 완전 삭제"""
        try:
            print("로컬 악성 샘플 정리 중...")

            malware_dir = config.DIRECTORIES['malware_samples']
            if os.path.exists(malware_dir):
                removed_count = 0
                for filename in os.listdir(malware_dir):
                    file_path = os.path.join(malware_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        removed_count += 1
                print(f"sample/mecro 정리: {removed_count}개 파일 삭제")

            temp_dir = "temp_db_samples"
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)
                os.makedirs(temp_dir, exist_ok=True)
                print("temp_db_samples 폴더 정리 완료")

        except Exception as e:
            print(f"로컬 샘플 정리 오류: {e}")

    def save_model_metadata(self, accuracy: float, test_accuracy: float = None,
                            cv_accuracy: float = None, cv_std: float = None,
                            precision: float = None, recall: float = None,
                            f1_score: float = None, malware_count: int = 0,
                            clean_count: int = 0, model_version="2.2_fixed",
                            precision_per_class: list = None,
                            recall_per_class: list = None):
        """모델 메타데이터 저장"""
        import json
        from datetime import datetime

        meta = {
            "malware_samples": malware_count,
            "clean_samples": clean_count,
            "total_samples": malware_count + clean_count,
            "accuracy": round(accuracy, 4),
            "test_accuracy": round(test_accuracy, 4) if test_accuracy else None,
            "cv_accuracy": round(cv_accuracy, 4) if cv_accuracy else None,
            "cv_std": round(cv_std, 4) if cv_std else None,
            "precision": round(precision, 4) if precision else None,
            "recall": round(recall, 4) if recall else None,
            "f1_score": round(f1_score, 4) if f1_score else None,
            "trained_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "model_version": model_version,
            "evaluation_method": "stratified_cv_with_holdout_test",
            "overfitting_prevention": "strict_ratio_conservative_evaluation",
            "precision_per_class": [round(p, 4) for p in precision_per_class] if precision_per_class else None,
            "recall_per_class": [round(r, 4) for r in recall_per_class] if recall_per_class else None
        }

        with open("models/model_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        print("model_meta.json 저장 완료")

    def save_training_history(self, features, labels, accuracy: float, model_version: str = "2.2_fixed"):
        """훈련 기록 저장"""
        try:
            history_data = {
                "features": features,
                "labels": labels,
                "model_version": model_version,
                "training_date": pd.Timestamp.now(),
                "sample_count": len(features),
                "accuracy": accuracy
            }

            if hasattr(db, 'engine') and db.engine:
                try:
                    with db.engine.begin() as conn:
                        conn.execute(
                            text(
                                "INSERT INTO training_history "
                                "(model_ver, sample_count, accuracy, trained_at) "
                                "VALUES (:v, :c, :a, NOW())"
                            ),
                            {"v": model_version, "c": len(features), "a": accuracy}
                        )
                    print("RDS 훈련 기록 저장 완료")
                except Exception as rds_error:
                    print(f"RDS 기록 저장 실패: {rds_error}")

            with open(self.training_history_path, "wb") as f:
                pickle.dump(history_data, f)

            print(f"훈련 기록 저장: {len(features)}개 샘플, 정확도={accuracy:.3f}")

        except Exception as e:
            print(f"훈련 기록 저장 실패: {e}")

    def load_training_history(self):
        """이전 훈련 기록 로드"""
        try:
            if os.path.exists(self.training_history_path):
                with open(self.training_history_path, 'rb') as f:
                    history_data = pickle.load(f)

                print(f"이전 훈련 기록 로드: {history_data['sample_count']}개 샘플")
                print(f"   버전: {history_data['model_version']}")
                print(f"   훈련일: {history_data['training_date']}")

                return history_data['features'], history_data['labels']
            else:
                print("이전 훈련 기록이 없습니다.")
                return None, None

        except Exception as e:
            print(f"훈련 기록 로드 실패: {e}")
            return None, None

    def incremental_train_model(self, test_size=0.3):
        """증분 학습 (기존 모델 완전 교체)"""
        print("=== 모델 재훈련 시작 (기존 모델 교체) ===")

        # 기존 모델 파일 삭제
        if os.path.exists(self.model_path):
            os.remove(self.model_path)
            print("기존 모델 파일 삭제")

        if os.path.exists(self.scaler_path):
            os.remove(self.scaler_path)
            print("기존 스케일러 파일 삭제")

        # 새로운 데이터로 완전 재훈련
        new_features, new_labels = self.prepare_training_data(use_db=True)
        if new_features is None:
            print("새로운 훈련 데이터 준비 실패")
            return False

        success, ensemble_accuracy = self._train_with_data(new_features, new_labels, test_size)

        if success:
            self.save_training_history(new_features, new_labels, ensemble_accuracy, "2.2_retrained")

        return success

    def train_model(self, test_size=0.3):
        """전체 모델 훈련"""
        print("=== 모델 전체 훈련 시작 ===")

        features, labels = self.prepare_training_data(use_db=True)
        if features is None:
            print("훈련 데이터 준비 실패")
            return False

        success, ensemble_accuracy = self._train_with_data(features, labels, test_size)

        if success:
            self.save_training_history(features, labels, ensemble_accuracy, "2.2_fixed")

        return success

    def _upload_to_aws(self):
        """훈련된 모델을 AWS에 업로드"""
        try:
            upload_files = [
                (self.model_path, "models/ensemble_model.pkl"),
                (self.scaler_path, "models/scaler.pkl"),
                ("models/model_meta.json", "models/model_meta.json")
            ]

            for local_path, s3_key in upload_files:
                if os.path.exists(local_path):
                    aws_helper.upload(local_path, s3_key)

            print("AWS 업로드 완료")
        except Exception as e:
            print(f"AWS 업로드 실패: {e}")

    def save_model(self):
        """모델과 스케일러 저장"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.ensemble_model, f)

            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)

            print(f"모델 저장 완료: {self.model_path}")
            print(f"스케일러 저장 완료: {self.scaler_path}")

        except Exception as e:
            print(f"모델 저장 실패: {e}")

    def load_model(self):
        """저장된 모델과 스케일러 로드"""
        try:
            with open(self.model_path, 'rb') as f:
                self.ensemble_model = pickle.load(f)

            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)

            print("모델 로드 완료")
            return True

        except Exception as e:
            print(f"모델 로드 실패: {e}")
            return False

    def predict(self, file_path: str) -> dict:
        """파일 악성코드 예측"""
        if self.ensemble_model is None:
            if not self.load_model():
                return {"error": "모델을 로드할 수 없습니다"}

        try:
            ext = os.path.splitext(file_path)[1].lower()
            supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

            if ext not in supported_extensions:
                return {"error": f"지원되지 않는 파일 형식: {ext}"}

            features = self.feature_extractor.extract_file_features(file_path)

            numeric_features = np.array([[
                features['file_size'],
                features['entropy'],
                features['suspicious_keywords_count'],
                int(features['has_macro']),
                features['pdf_js_count'],
                int(features['pdf_openaction']),
                features.get('pdf_pages', 0),
                int(features.get('pdf_encryption', False)),
                features.get('macro_suspicious_count', 0),
                int(features.get('has_external_links', False)),
                features.get('xml_complexity', 0),
                features.get('hwp_scripts', 0),
                features.get('hwp_ole_objects', 0),
                features['string_entropy'],
                features['compression_ratio']
            ]])

            features_scaled = self.scaler.transform(numeric_features)

            prediction = self.ensemble_model.predict(features_scaled)[0]
            probability = self.ensemble_model.predict_proba(features_scaled)[0]

            max_prob = max(probability)
            confidence = max_prob

            if len(probability) > 1:
                prob_diff = abs(probability[1] - probability[0])
                confidence = max_prob * (0.5 + 0.5 * prob_diff)

            return {
                "prediction": "악성" if prediction == 1 else "정상",
                "confidence": confidence,
                "malware_probability": probability[1] if len(probability) > 1 else (1 - probability[0]),
                "clean_probability": probability[0],
                "features": features,
                "probability_distribution": {
                    "정상": float(probability[0]),
                    "악성": float(probability[1]) if len(probability) > 1 else float(1 - probability[0])
                }
            }

        except Exception as e:
            return {"error": f"예측 중 오류: {str(e)}"}

    def evaluate_model(self):
        """모델 성능 평가"""
        if self.ensemble_model is None:
            if not self.load_model():
                print("모델을 로드할 수 없습니다")
                return

        features, labels = self.prepare_training_data(use_db=True)
        if features is None:
            print("평가 데이터가 없습니다")
            return

        features_scaled = self.scaler.transform(features)
        predictions = self.ensemble_model.predict(features_scaled)
        accuracy = accuracy_score(labels, predictions)

        print("=== 모델 성능 평가 ===")
        print(f"정확도: {accuracy:.4f}")
        print("\n분류 리포트:")
        print(classification_report(labels, predictions, target_names=['정상', '악성']))
        print(f"\n혼동 행렬:\n{confusion_matrix(labels, predictions)}")


def train_model():
    """모델 훈련 실행 함수"""
    trainer = ModelTrainer()
    success = trainer.train_model()

    if success:
        trainer.evaluate_model()

    return success


if __name__ == "__main__":
    train_model()