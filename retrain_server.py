# retrain_server.py - 내장 서버용 최적화 버전

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import asyncio
from datetime import datetime
import json
from collections import deque
import os
import sys
import platform
import socket

app = FastAPI()

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 로그 버퍼 (최대 500줄로 축소)
log_buffer = deque(maxlen=500)


def add_log(message):
    """로그 버퍼에 추가 (내장 서버용 간소화)"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    log_buffer.append(log_entry)


def get_system_info():
    """시스템 정보 조회"""
    return {
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python_version": sys.version.split()[0],
        "hostname": socket.gethostname(),
        "local_ip": get_local_ip()
    }


def get_local_ip():
    """로컬 IP 주소 조회"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


@app.get("/")
def root():
    """서버 상태 확인"""
    return {
        "status": "ok",
        "service": "embedded_training_server",
        "version": "2.2",
        "mode": "embedded"
    }


@app.get("/health")
def health_check():
    """간소화된 헬스 체크"""
    try:
        # 핵심 모듈만 확인
        dependencies = {}

        core_modules = ["utils.model_trainer", "utils.db", "utils.api_client"]

        for module in core_modules:
            try:
                __import__(module)
                dependencies[module] = "OK"
            except ImportError as e:
                dependencies[module] = f"ERROR: {str(e)}"

        return {
            "status": "healthy",
            "dependencies": dependencies,
            "log_buffer_size": len(log_buffer)
        }

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "unhealthy", "error": str(e)}
        )


@app.get("/logs/recent")
def get_recent_logs():
    """최근 로그 반환"""
    return {"logs": list(log_buffer)}


@app.post("/train")
def train_model():
    """모델 훈련 (동기식) - 내장 서버용 (기존 모델 교체)"""
    try:
        add_log("내장 서버에서 모델 재훈련 시작 (기존 모델 교체)")

        # 기존 모델 삭제
        import os
        if os.path.exists("models/ensemble_model.pkl"):
            os.remove("models/ensemble_model.pkl")
            add_log("기존 모델 삭제 완료")

        if os.path.exists("models/scaler.pkl"):
            os.remove("models/scaler.pkl")
            add_log("기존 스케일러 삭제 완료")

        # 직접 모델 트레이너 사용
        from utils.model_trainer import train_model as train_func

        success = train_func()

        if success:
            add_log("모델 재훈련 성공")

            # 메타 정보 읽기
            try:
                with open("models/model_meta.json") as f:
                    meta = json.load(f)

                return {
                    "status": "success",
                    "trained_at": meta.get("trained_at"),
                    "accuracy": meta.get("accuracy"),
                    "test_accuracy": meta.get("test_accuracy"),
                    "cv_accuracy": meta.get("cv_accuracy"),
                    "cv_std": meta.get("cv_std"),
                    "precision": meta.get("precision"),
                    "recall": meta.get("recall"),
                    "f1_score": meta.get("f1_score"),
                    "malware_samples": meta.get("malware_samples"),
                    "clean_samples": meta.get("clean_samples"),
                    "total_samples": meta.get("total_samples"),
                    "model_version": meta.get("model_version"),
                    "overfitting_prevention": meta.get("overfitting_prevention"),
                    "message": "기존 모델 교체 완료"
                }
            except Exception as meta_error:
                add_log(f"메타 정보 로드 실패: {meta_error}")
                return {
                    "status": "success",
                    "message": "훈련 완료, 메타 정보 없음"
                }
        else:
            add_log("모델 재훈련 실패")
            return JSONResponse(
                status_code=500,
                content={"status": "error", "message": "훈련 실패"}
            )

    except Exception as e:
        add_log(f"모델 훈련 오류: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


@app.post("/train/stream")
async def train_model_stream():
    """모델 훈련 (스트리밍 로그) - 내장 서버용 (기존 모델 교체)"""

    async def generate():
        try:
            add_log("스트리밍 재훈련 시작")
            yield "내장 서버에서 모델 재훈련 시작 (기존 모델 교체)...\n"

            # 기존 모델 삭제
            import os
            if os.path.exists("models/ensemble_model.pkl"):
                os.remove("models/ensemble_model.pkl")
                yield "기존 모델 삭제 완료\n"

            if os.path.exists("models/scaler.pkl"):
                os.remove("models/scaler.pkl")
                yield "기존 스케일러 삭제 완료\n"

            # 훈련 실행
            from utils.model_trainer import ModelTrainer
            trainer = ModelTrainer()

            yield "1단계: 훈련 데이터 준비 중 (과적합 방지)...\n"

            # 데이터 준비
            features, labels = trainer.prepare_training_data()

            if features is None:
                yield "오류: 훈련 데이터 준비 실패\n"
                return

            yield f"데이터 준비 완료: {len(features)}개 샘플\n"
            malware_count = int(sum(labels))
            clean_count = len(labels) - malware_count
            malware_ratio = malware_count / len(labels) * 100
            yield f"비율: 악성 {malware_count}개({malware_ratio:.1f}%), 정상 {clean_count}개({100 - malware_ratio:.1f}%)\n"

            yield "2단계: 모델 재훈련 실행 중 (과적합 방지)...\n"

            # 훈련 실행
            success = trainer.train_model()

            if success:
                yield "재훈련 성공!\n"

                # 결과 출력
                try:
                    with open("models/model_meta.json") as f:
                        meta = json.load(f)

                    yield "\n=== 재훈련 결과 ===\n"
                    yield f"보수적 정확도: {meta.get('accuracy', 0):.4f}\n"

                    if 'test_accuracy' in meta and meta['test_accuracy']:
                        yield f"테스트 정확도: {meta.get('test_accuracy', 0):.4f}\n"
                    if 'cv_accuracy' in meta and meta['cv_accuracy']:
                        yield f"교차검증 정확도: {meta.get('cv_accuracy', 0):.4f}\n"
                    if 'cv_std' in meta and meta['cv_std']:
                        yield f"교차검증 표준편차: {meta.get('cv_std', 0):.4f}\n"
                    if 'precision' in meta and meta['precision']:
                        yield f"정밀도: {meta.get('precision', 0):.4f}\n"
                    if 'recall' in meta and meta['recall']:
                        yield f"재현율: {meta.get('recall', 0):.4f}\n"
                    if 'f1_score' in meta and meta['f1_score']:
                        yield f"F1-점수: {meta.get('f1_score', 0):.4f}\n"

                    yield f"악성 샘플: {meta.get('malware_samples', 0)}개\n"
                    yield f"정상 샘플: {meta.get('clean_samples', 0)}개\n"
                    yield f"모델 버전: {meta.get('model_version', '2.2_fixed')}\n"
                    yield f"훈련 완료: {meta.get('trained_at', 'N/A')}\n"

                    # 과적합 방지 확인
                    if meta.get('overfitting_prevention'):
                        yield f"과적합 방지: {meta.get('overfitting_prevention')}\n"

                    if meta.get('accuracy', 0) < 0.99:
                        yield "과적합 방지 적용됨 - 정상적인 성능\n"
                    else:
                        yield "주의: 높은 정확도 - 과적합 가능성 있음\n"

                    # 클래스별 성능
                    if 'precision_per_class' in meta and meta['precision_per_class']:
                        prec = meta['precision_per_class']
                        if len(prec) >= 2:
                            yield f"정상 파일 정밀도: {prec[0]:.4f}\n"
                            yield f"악성 파일 정밀도: {prec[1]:.4f}\n"

                    add_log(f"재훈련 완료 - 보수적 정확도: {meta.get('accuracy', 0):.4f}")

                except Exception as meta_error:
                    yield f"메타 정보 로드 실패: {str(meta_error)}\n"
                    add_log(f"메타 정보 로드 실패: {str(meta_error)}")
            else:
                yield "재훈련 실패\n"
                add_log("재훈련 실패")

            yield "\n=== 기존 모델 교체 완료 ===\n"

        except Exception as e:
            add_log(f"스트리밍 훈련 오류: {str(e)}")
            yield f"오류 발생: {str(e)}\n"

    return StreamingResponse(generate(), media_type="text/plain")


@app.get("/system/info")
def get_system_info_endpoint():
    """시스템 정보 조회"""
    try:
        info = get_system_info()
        info.update({
            "cwd": os.getcwd(),
            "mode": "embedded_server"
        })
        return info

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )


@app.on_event("startup")
async def startup_event():
    """서버 시작 이벤트"""
    add_log("내장 서버 시작")
    add_log(f"모드: 내장 서버")
    add_log(f"작업 디렉토리: {os.getcwd()}")


# API 요청 로깅 (간소화)
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()

    response = await call_next(request)

    # 중요한 요청만 로깅
    if request.url.path in ["/train", "/train/stream"]:
        duration = (datetime.now() - start_time).total_seconds()
        add_log(f"요청 처리: {request.url.path} ({duration:.2f}초)")

    return response


if __name__ == "__main__":
    import uvicorn

    print("내장 서버 모드로 실행됨")
    print("일반적으로 main.py에서 자동 실행됩니다.")

    # 독립 실행시 설정
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.getenv("SERVER_PORT", "8000")),
        log_level="error"
    )