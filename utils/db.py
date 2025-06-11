from sqlalchemy import create_engine, text, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import config
import os

Base = declarative_base()


class TrainingHistory(Base):
    __tablename__ = 'training_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    model_ver = Column(String(50), nullable=False)
    sample_count = Column(Integer, nullable=False)
    accuracy = Column(Float, nullable=False)
    trained_at = Column(DateTime, nullable=False)


class VirusSample(Base):
    __tablename__ = 'virus_samples'

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_name = Column(String(255), nullable=False)
    file_hash = Column(String(64), unique=True, nullable=False)
    file_type = Column(String(50), nullable=False)
    file_size = Column(Integer, nullable=False)
    source = Column(String(100), nullable=False)  # malware_bazaar, triage, etc
    malware_family = Column(String(100))
    threat_category = Column(String(100))
    is_malicious = Column(Boolean, nullable=False)
    s3_key = Column(String(500))  # S3 저장 경로
    uploaded_at = Column(DateTime, nullable=False)
    features_json = Column(Text)  # 추출된 특징을 JSON으로 저장


# 데이터베이스 연결 설정
if config.USE_AWS and all([config.RDS_HOST, config.RDS_USER]):
    # RDS 연결
    URI = f"mysql+pymysql://{config.RDS_USER}:{config.RDS_PASSWORD}" \
          f"@{config.RDS_HOST}/{config.RDS_DB}"
    engine = create_engine(URI, pool_recycle=280, echo=False)

    # 테이블 생성
    Base.metadata.create_all(engine)

    # 세션 팩토리
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    print(f"[DB] RDS 연결 성공: {config.RDS_HOST}")
else:
    # 로컬 SQLite 사용
    local_db_path = "local_database.db"
    URI = f"sqlite:///{local_db_path}"
    engine = create_engine(URI, echo=False)

    # 테이블 생성
    Base.metadata.create_all(engine)

    # 세션 팩토리
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    print(f"[DB] 로컬 SQLite 사용: {local_db_path}")


def get_db():
    """데이터베이스 세션 반환"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass


def save_virus_sample(file_path: str, file_hash: str, is_malicious: bool,
                      source: str = "unknown", malware_family: str = None,
                      threat_category: str = None, s3_key: str = None,
                      features_json: str = None):
    """바이러스 샘플 메타데이터 저장"""
    try:
        db = get_db()

        # 중복 확인
        existing = db.query(VirusSample).filter(VirusSample.file_hash == file_hash).first()
        if existing:
            print(f"[DB] 이미 존재하는 샘플: {file_hash[:16]}...")
            return existing.id

        # 새 샘플 저장
        sample = VirusSample(
            file_name=os.path.basename(file_path),
            file_hash=file_hash,
            file_type=os.path.splitext(file_path)[1].lower(),
            file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            source=source,
            malware_family=malware_family,
            threat_category=threat_category,
            is_malicious=is_malicious,
            s3_key=s3_key,
            uploaded_at=datetime.utcnow(),
            features_json=features_json
        )

        db.add(sample)
        db.commit()
        db.refresh(sample)

        print(f"[DB] 새 샘플 저장: {sample.file_name} (ID: {sample.id})")
        return sample.id

    except Exception as e:
        print(f"[DB] 샘플 저장 실패: {e}")
        return None
    finally:
        db.close()


def get_training_samples(limit: int = None):
    """훈련용 샘플 목록 조회"""
    try:
        db = get_db()

        query = db.query(VirusSample)
        if limit:
            query = query.limit(limit)

        samples = query.all()

        print(f"[DB] 훈련 샘플 조회: {len(samples)}개")
        return samples

    except Exception as e:
        print(f"[DB] 샘플 조회 실패: {e}")
        return []
    finally:
        db.close()


def get_sample_statistics():
    """샘플 통계 조회"""
    try:
        db = get_db()

        total_count = db.query(VirusSample).count()
        malicious_count = db.query(VirusSample).filter(VirusSample.is_malicious == True).count()
        clean_count = db.query(VirusSample).filter(VirusSample.is_malicious == False).count()

        # 소스별 통계
        source_stats = db.execute(
            text("SELECT source, COUNT(*) as count FROM virus_samples GROUP BY source")
        ).fetchall()

        # 파일 타입별 통계
        type_stats = db.execute(
            text("SELECT file_type, COUNT(*) as count FROM virus_samples GROUP BY file_type")
        ).fetchall()

        return {
            "total_samples": total_count,
            "malicious_samples": malicious_count,
            "clean_samples": clean_count,
            "source_distribution": dict(source_stats),
            "type_distribution": dict(type_stats)
        }

    except Exception as e:
        print(f"[DB] 통계 조회 실패: {e}")
        return {}
    finally:
        db.close()


# 초기화 시 필요한 모듈 import
try:
    from datetime import datetime
except ImportError:
    import datetime