# utils/model_trainer.py - 데이터 불균형 해결 및 성능 개선

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
        """훈련 데이터 준비 (불균형 해결 포함)"""
        print("=== 훈련 데이터 준비 중 (불균형 해결 적용) ===")

        if malware_dir is None:
            malware_dir = config.DIRECTORIES['malware_samples']
        if clean_dir is None:
            clean_dir = config.DIRECTORIES['clean_samples']

        supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

        all_files = []
        all_labels = []

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

        # 데이터 균형 조정 (악성 샘플이 더 많아야 함)
        if len(final_clean_files) > len(final_malware_files) * 0.6:
            # 정상 샘플이 악성 샘플의 60%를 초과하면 줄임
            target_clean_count = int(len(final_malware_files) * 0.6)
            final_clean_files = final_clean_files[:target_clean_count]
            print(f"정상 샘플 수를 {len(final_clean_files)}개로 조정")

        all_files = final_malware_files + final_clean_files
        all_labels = [1] * len(final_malware_files) + [0] * len(final_clean_files)

        print(f"최종 훈련 데이터: 악성 {len(final_malware_files)}개, 정상 {len(final_clean_files)}개")
        print(f"총 샘플 수: {len(all_files)}개")
        print(
            f"비율 - 악성: {len(final_malware_files) / (len(all_files)) * 100:.1f}%, 정상: {len(final_clean_files) / (len(all_files)) * 100:.1f}%")

        if len(final_malware_files) < 20 or len(final_clean_files) < 10:
            print("훈련 데이터가 부족합니다. 악성 20개, 정상 10개 이상 필요합니다.")
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
        """RDS에서 훈련 데이터 로드"""
        try:
            samples = db.get_training_samples(limit=2000)
            return samples
        except Exception as e:
            print(f"RDS 데이터 로드 실패: {e}")
            return []

    def _apply_data_balancing(self, features, labels):
        """데이터 불균형 해결 (SMOTE + 언더샘플링)"""
        print("\n=== 데이터 균형 조정 ===")

        # 원본 분포 확인
        unique, counts = np.unique(labels, return_counts=True)
        print(f"원본 분포 - 정상: {counts[0]}, 악성: {counts[1] if len(counts) > 1 else 0}")

        # 클래스 불균형이 심하지 않으면 그대로 사용
        if len(counts) > 1:
            imbalance_ratio = max(counts) / min(counts)
            print(f"불균형 비율: {imbalance_ratio:.2f}")

            if imbalance_ratio < 2.0:  # 2:1 비율 이하면 균형 조정 안함
                print("데이터 균형이 적절함 - 조정하지 않음")
                return features, labels

        try:
            # 1단계: SMOTE로 소수 클래스 오버샘플링 (적당히)
            smote = SMOTE(
                sampling_strategy=0.7,  # 소수 클래스를 다수 클래스의 70%까지 증가
                random_state=42,
                k_neighbors=min(5, min(counts) - 1) if min(counts) > 1 else 1
            )

            # 2단계: 랜덤 언더샘플링으로 다수 클래스 감소
            undersampler = RandomUnderSampler(
                sampling_strategy=0.6,  # 다수 클래스를 소수 클래스의 60% 비율로 감소
                random_state=42
            )

            # 파이프라인으로 순차 적용
            pipeline = Pipeline([
                ('smote', smote),
                ('undersample', undersampler)
            ])

            X_balanced, y_balanced = pipeline.fit_resample(features, labels)

            # 결과 확인
            unique_balanced, counts_balanced = np.unique(y_balanced, return_counts=True)
            print(f"조정 후 분포 - 정상: {counts_balanced[0]}, 악성: {counts_balanced[1] if len(counts_balanced) > 1 else 0}")
            print(f"총 샘플 수: {len(X_balanced)}개 (원본: {len(features)}개)")

            return X_balanced, y_balanced

        except Exception as e:
            print(f"데이터 균형 조정 실패: {e}")
            print("원본 데이터 사용")
            return features, labels

    def _train_with_data(self, features, labels, test_size):
        """실제 모델 훈련 수행 - 불균형 해결 적용"""
        try:
            # 데이터 균형 조정
            features_balanced, labels_balanced = self._apply_data_balancing(features, labels)

            # 데이터 분할
            X_train, X_test, y_train, y_test = train_test_split(
                features_balanced, labels_balanced, test_size=0.25, random_state=42,
                stratify=labels_balanced if len(np.unique(labels_balanced)) > 1 else None
            )

            print(f"\n=== 데이터 분할 결과 ===")
            print(f"훈련 세트: {len(X_train)}개")
            print(f"테스트 세트: {len(X_test)}개")

            # 클래스 가중치 계산
            class_weights = compute_class_weight(
                'balanced',
                classes=np.unique(y_train),
                y=y_train
            )
            class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
            print(f"클래스 가중치: {class_weight_dict}")

            # 데이터 정규화
            print("데이터 정규화 중...")
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # 개별 모델 훈련 (가중치 적용)
            trained_models, model_scores = self.train_individual_models(
                X_train_scaled, X_test_scaled, y_train, y_test, class_weight_dict
            )

            # 앙상블 모델 생성 및 훈련
            self.ensemble_model = self.create_ensemble_model(trained_models)
            self.ensemble_model.fit(X_train_scaled, y_train)

            print("\n=== 앙상블 모델 평가 ===")

            # 테스트 세트 평가
            ensemble_pred = self.ensemble_model.predict(X_test_scaled)
            test_accuracy = accuracy_score(y_test, ensemble_pred)

            # 교차 검증 평가
            cv_folds = min(5, len(np.unique(y_train)))
            if cv_folds > 1:
                skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
                cv_scores = cross_val_score(self.ensemble_model, X_train_scaled, y_train,
                                            cv=skf, scoring='accuracy')
                cv_mean = cv_scores.mean()
                cv_std = cv_scores.std()
            else:
                cv_mean = test_accuracy
                cv_std = 0

            # 정밀도, 재현율, F1-score 계산
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, ensemble_pred, average='weighted', zero_division=0
            )

            # 클래스별 상세 성능
            precision_per_class, recall_per_class, f1_per_class, _ = precision_recall_fscore_support(
                y_test, ensemble_pred, average=None, zero_division=0
            )

            print(f"테스트 세트 정확도: {test_accuracy:.4f}")
            print(f"교차 검증 정확도: {cv_mean:.4f} (+/- {cv_std * 2:.4f})")
            print(f"전체 정밀도: {precision:.4f}")
            print(f"전체 재현율: {recall:.4f}")
            print(f"전체 F1-점수: {f1:.4f}")

            # 클래스별 성능 출력
            if len(precision_per_class) > 1:
                print(f"\n클래스별 성능:")
                print(
                    f"정상 파일 - 정밀도: {precision_per_class[0]:.4f}, 재현율: {recall_per_class[0]:.4f}, F1: {f1_per_class[0]:.4f}")
                print(
                    f"악성 파일 - 정밀도: {precision_per_class[1]:.4f}, 재현율: {recall_per_class[1]:.4f}, F1: {f1_per_class[1]:.4f}")

            print("\n분류 리포트:")
            print(classification_report(y_test, ensemble_pred, target_names=['정상', '악성']))

            cm = confusion_matrix(y_test, ensemble_pred)
            print(f"혼동 행렬:\n{cm}")

            # 보수적인 성능 평가
            final_accuracy = min(test_accuracy, cv_mean)

            print(f"\n최종 보수적 평가 정확도: {final_accuracy:.4f}")

            self.save_model()

            # 메타데이터에 상세한 정보 저장
            self.save_model_metadata(
                accuracy=final_accuracy,
                test_accuracy=test_accuracy,
                cv_accuracy=cv_mean,
                cv_std=cv_std,
                precision=precision,
                recall=recall,
                f1_score=f1,
                malware_count=int(np.sum(labels_balanced)),
                clean_count=int(len(labels_balanced) - np.sum(labels_balanced)),
                model_version="2.2",
                class_weights=class_weight_dict,
                precision_per_class=precision_per_class.tolist() if len(precision_per_class) > 1 else [precision],
                recall_per_class=recall_per_class.tolist() if len(recall_per_class) > 1 else [recall]
            )

            if config.USE_AWS:
                self._upload_to_aws()

            # 로컬 악성 파일 완전 삭제
            self._cleanup_local_malware_samples()

            print("모델 훈련 완료!")
            return True, final_accuracy

        except Exception as e:
            print(f"모델 훈련 실패: {e}")
            import traceback
            traceback.print_exc()
            return False, None

    def _cleanup_local_malware_samples(self):
        """로컬 악성 샘플 완전 삭제"""
        try:
            print("=== 로컬 악성 샘플 정리 중 ===")

            # sample/mecro 폴더 정리
            malware_dir = config.DIRECTORIES['malware_samples']
            if os.path.exists(malware_dir):
                removed_count = 0
                for filename in os.listdir(malware_dir):
                    file_path = os.path.join(malware_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        removed_count += 1
                print(f"sample/mecro 정리: {removed_count}개 파일 삭제")

            # temp_db_samples 폴더 정리
            temp_dir = "temp_db_samples"
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)
                os.makedirs(temp_dir, exist_ok=True)
                print("temp_db_samples 폴더 정리 완료")

            print("로컬 악성 샘플 정리 완료 - 보안 강화됨")

        except Exception as e:
            print(f"로컬 샘플 정리 오류: {e}")

    def train_individual_models(self, X_train, X_test, y_train, y_test, class_weights):
        """개별 모델 훈련 - 클래스 가중치 적용"""
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=200,
                random_state=42,
                max_depth=10,
                min_samples_split=8,
                min_samples_leaf=4,
                class_weight=class_weights,
                max_features='sqrt',
                bootstrap=True
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=150,
                random_state=42,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                min_samples_split=8,
                min_samples_leaf=4
            ),
            'SVM': SVC(
                kernel='rbf',
                probability=True,
                random_state=42,
                C=1.0,
                gamma='scale',
                class_weight=class_weights
            )
        }

        trained_models = {}
        model_scores = {}

        print("\n=== 개별 모델 훈련 (클래스 가중치 적용) ===")

        for name, model in models.items():
            print(f"\n{name} 훈련 중...")

            model.fit(X_train, y_train)

            # 테스트 세트 평가
            y_pred = model.predict(X_test)
            test_accuracy = accuracy_score(y_test, y_pred)

            # 교차 검증
            cv_folds = min(3, len(np.unique(y_train)))
            if cv_folds > 1:
                cv_scores = cross_val_score(model, X_train, y_train, cv=cv_folds, scoring='accuracy')
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
                'f1_score': f1,
                'conservative_score': min(test_accuracy, cv_mean)
            }

            print(f"{name} - 테스트 정확도: {test_accuracy:.4f}")
            print(f"{name} - CV 평균: {cv_mean:.4f} (+/- {cv_std * 2:.4f})")
            print(f"{name} - 정밀도: {precision:.4f}, 재현율: {recall:.4f}, F1: {f1:.4f}")

        return trained_models, model_scores

    def save_model_metadata(self, accuracy: float, test_accuracy: float = None,
                            cv_accuracy: float = None, cv_std: float = None,
                            precision: float = None, recall: float = None,
                            f1_score: float = None, malware_count: int = 0,
                            clean_count: int = 0, model_version="2.2",
                            class_weights: dict = None, precision_per_class: list = None,
                            recall_per_class: list = None):
        """상세한 모델 메타데이터 저장"""
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
            "evaluation_method": "balanced_stratified_cv_with_smote",
            "class_weights": class_weights,
            "precision_per_class": [round(p, 4) for p in precision_per_class] if precision_per_class else None,
            "recall_per_class": [round(r, 4) for r in recall_per_class] if recall_per_class else None,
            "data_balancing": "SMOTE + RandomUnderSampler applied"
        }

        with open("models/model_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        print("model_meta.json 저장 완료 (균형 조정 정보 포함)")

    def save_training_history(self, features, labels, accuracy: float, model_version: str = "2.2"):
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

            # RDS에 기록 저장
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

            # 로컬 파일도 백업으로 저장
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

    def incremental_train_model(self, test_size=0.25):
        """증분 학습"""
        print("=== 모델 증분 학습 시작 ===")

        new_features, new_labels = self.prepare_training_data(use_db=True)
        if new_features is None:
            print("새로운 훈련 데이터 준비 실패")
            return False

        old_features, old_labels = self.load_training_history()

        if old_features is not None and old_labels is not None:
            print("기존 데이터와 새 데이터를 결합합니다...")

            try:
                if old_features.shape[1] != new_features.shape[1]:
                    print(f"특징 수가 다릅니다. 기존: {old_features.shape[1]}, 새로운: {new_features.shape[1]}")
                    print("기존 데이터를 무시하고 새 데이터로만 훈련합니다.")
                    combined_features = new_features
                    combined_labels = new_labels
                else:
                    combined_features = np.vstack([old_features, new_features])
                    combined_labels = np.concatenate([old_labels, new_labels])

                print(f"결합된 데이터: {len(combined_features)}개 샘플")
                print(f"  - 기존: {len(old_features)}개")
                print(f"  - 새로운: {len(new_features)}개")

            except Exception as e:
                print(f"데이터 결합 실패: {e}")
                print("새 데이터로만 훈련합니다.")
                combined_features = new_features
                combined_labels = new_labels
        else:
            print("기존 데이터가 없습니다. 새 데이터로만 훈련합니다.")
            combined_features = new_features
            combined_labels = new_labels

        success, ensemble_accuracy = self._train_with_data(combined_features, combined_labels, test_size)

        if success:
            self.save_training_history(combined_features, combined_labels, ensemble_accuracy, "2.2+")

        return success

    def train_model(self, test_size=0.25):
        """전체 모델 훈련"""
        print("=== 모델 전체 훈련 시작 ===")

        features, labels = self.prepare_training_data(use_db=True)
        if features is None:
            print("훈련 데이터 준비 실패")
            return False

        success, ensemble_accuracy = self._train_with_data(features, labels, test_size)

        if success:
            self.save_training_history(features, labels, ensemble_accuracy, "2.2")

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

    def create_ensemble_model(self, trained_models):
        """앙상블 모델 생성"""
        print("\n=== 앙상블 모델 생성 ===")

        voting_clf = VotingClassifier(
            estimators=[
                ('rf', trained_models['RandomForest']),
                ('gb', trained_models['GradientBoosting']),
                ('svm', trained_models['SVM'])
            ],
            voting='soft'  # 확률 기반 투표
        )

        return voting_clf

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
        """파일 악성코드 예측 (개선된 신뢰도 계산)"""
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

            # 신뢰도 계산 개선
            max_prob = max(probability)
            confidence = max_prob

            # 확률 차이를 고려한 신뢰도 조정
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

    malware_count = 0
    clean_count = 0

    if os.path.exists("sample/mecro"):
        malware_count = len([f for f in os.listdir("sample/mecro")
                             if os.path.isfile(os.path.join("sample/mecro", f))])

    if os.path.exists(config.DIRECTORIES['clean_samples']):
        clean_count = len([f for f in os.listdir(config.DIRECTORIES['clean_samples'])
                           if os.path.isfile(os.path.join(config.DIRECTORIES['clean_samples'], f))])

    print(f"로컬 데이터: 악성 {malware_count}개, 정상 {clean_count}개")

    try:
        db_stats = db.get_sample_statistics()
        print(f"RDS 데이터: 악성 {db_stats.get('malicious_samples', 0)}개, 정상 {db_stats.get('clean_samples', 0)}개")
    except:
        print("RDS 연결 없음")

    if malware_count + clean_count < 15:
        print("로컬 데이터가 부족하지만 RDS 데이터로 훈련을 진행합니다...")

    success = trainer.train_model()

    if success:
        trainer.evaluate_model()

    return success


if __name__ == "__main__":
    train_model()