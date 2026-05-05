"""작업 디렉터리 관리 — 소스 디렉터리를 임시 작업 디렉터리로 복사"""
import logging
import shutil
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def prepare_work_dir(source_dir: Path, base_dir: Path, request_id: str) -> Path:
    """source_dir 내용을 base_dir 안의 임시 디렉터리로 복사하여 작업 디렉터리 생성"""
    base_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix=f'tf-{request_id}-', dir=str(base_dir)))

    for tf_file in source_dir.glob('*.tf'):
        shutil.copy2(tf_file, work_dir / tf_file.name)

    logger.info(f'[{request_id}] Work dir prepared: {work_dir}')
    return work_dir


def cleanup_work_dir(work_dir: Path, request_id: str) -> None:
    shutil.rmtree(work_dir, ignore_errors=True)
    logger.info(f'[{request_id}] Work dir cleaned up: {work_dir}')
