# db_rebalancer.py - RDS 샘플 비율 자동 조정

import os
import random
from utils import db
from utils.db import get_db, VirusSample
from sqlalchemy import text


class DatabaseRebalancer:
    def __init__(self):
        self.target_malware_ratio = 0.75  # 악성 75%, 정상 25%

    def analyze_current_balance(self):
        """현재 RDS 샘플 비율 분석"""
        stats = db.get_sample_statistics()

        total = stats.get('total_samples', 0)
        malicious = stats.get('malicious_samples', 0)
        clean = stats.get('clean_samples', 0)

        if total == 0:
            return None

        current_malware_ratio = malicious / total

        return {
            'total_samples': total,
            'malicious_samples': malicious,
            'clean_samples': clean,
            'current_malware_ratio': current_malware_ratio,
            'target_malware_ratio': self.target_malware_ratio,
            'needs_rebalancing': abs(current_malware_ratio - self.target_malware_ratio) > 0.1
        }

    def rebalance_database(self, max_total_samples=400):
        """RDS 샘플 비율 자동 조정"""
        analysis = self.analyze_current_balance()

        if not analysis or not analysis['needs_rebalancing']:
            print("데이터베이스 비율 조정 불필요")
            return False

        print(f"현재 비율: 악성 {analysis['current_malware_ratio']:.2%}, 정상 {1 - analysis['current_malware_ratio']:.2%}")
        print(f"목표 비율: 악성 {self.target_malware_ratio:.2%}, 정상 {1 - self.target_malware_ratio:.2%}")

        # 목표 샘플 수 계산
        target_malware_count = int(max_total_samples * self.target_malware_ratio)
        target_clean_count = max_total_samples - target_malware_count

        print(f"목표 샘플 수: 악성 {target_malware_count}개, 정상 {target_clean_count}개")

        # 과도한 정상 샘플 제거
        if analysis['clean_samples'] > target_clean_count:
            excess_clean = analysis['clean_samples'] - target_clean_count
            self._remove_excess_clean_samples(excess_clean)

        # 부족한 악성 샘플은 API에서 추가 수집 필요하다고 알림
        if analysis['malicious_samples'] < target_malware_count:
            deficit_malware = target_malware_count - analysis['malicious_samples']
            print(f"악성 샘플 {deficit_malware}개 부족 - API 수집 필요")

        return True

    def _remove_excess_clean_samples(self, excess_count):
        """과도한 정상 샘플 제거 (오래된 것부터)"""
        try:
            session = get_db()

            # 오래된 정상 샘플부터 제거
            old_clean_samples = session.execute(
                text("""
                     SELECT id
                     FROM virus_samples
                     WHERE is_malicious = 0
                     ORDER BY uploaded_at ASC LIMIT :limit
                     """),
                {"limit": excess_count}
            ).fetchall()

            removed_count = 0
            for sample in old_clean_samples:
                session.execute(
                    text("DELETE FROM virus_samples WHERE id = :id"),
                    {"id": sample.id}
                )
                removed_count += 1

            session.commit()
            print(f"과도한 정상 샘플 {removed_count}개 제거 완료")

        except Exception as e:
            print(f"정상 샘플 제거 실패: {e}")
            session.rollback()
        finally:
            session.close()

    def remove_duplicate_samples(self):
        """RDS에서 중복 샘플 제거"""
        try:
            session = get_db()

            # 해시 기준 중복 찾기
            duplicates = session.execute(
                text("""
                     SELECT file_hash, COUNT(*) as count, MIN(id) as keep_id
                     FROM virus_samples
                     GROUP BY file_hash
                     HAVING COUNT (*) > 1
                     """)
            ).fetchall()

            removed_total = 0
            for dup in duplicates:
                # 가장 오래된 것 하나만 남기고 나머지 삭제
                session.execute(
                    text("""
                         DELETE
                         FROM virus_samples
                         WHERE file_hash = :hash
                           AND id != :keep_id
                         """),
                    {"hash": dup.file_hash, "keep_id": dup.keep_id}
                )
                removed_total += (dup.count - 1)

            session.commit()
            print(f"중복 샘플 {removed_total}개 제거 완료")

        except Exception as e:
            print(f"중복 제거 실패: {e}")
            session.rollback()
        finally:
            session.close()


def rebalance_command():
    """명령어로 실행할 수 있는 함수"""
    rebalancer = DatabaseRebalancer()

    print("=== RDS 데이터베이스 비율 조정 ===")

    # 현재 상태 분석
    analysis = rebalancer.analyze_current_balance()
    if not analysis:
        print("데이터베이스가 비어있습니다")
        return

    print(f"현재 상태:")
    print(f"  총 샘플: {analysis['total_samples']}개")
    print(f"  악성: {analysis['malicious_samples']}개 ({analysis['current_malware_ratio']:.1%})")
    print(f"  정상: {analysis['clean_samples']}개 ({1 - analysis['current_malware_ratio']:.1%})")

    if analysis['needs_rebalancing']:
        print("\n비율 조정이 필요합니다")
        rebalancer.remove_duplicate_samples()
        rebalancer.rebalance_database()
    else:
        print("\n비율이 적절합니다")


if __name__ == "__main__":
    rebalance_command()