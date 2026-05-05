"""codegen 처리 완료 → executor 호출 흐름"""
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..codegen.buffer import RoleBuffer
from ..codegen.policy_fetcher import PolicyFetcher
from ..codegen.tf_writer import write_workspace
from ..config import settings
from ..executor.runner import TerraformRunner
from ..executor.workspace import cleanup_work_dir, prepare_work_dir

logger = logging.getLogger(__name__)


class Pipeline:
    """코드 생성 → 실행 통합 파이프라인"""

    def __init__(
        self,
        output_base: Path,
        work_base: Path,
        runner: TerraformRunner,
    ):
        self.output_base = output_base
        self.work_base = work_base
        self.runner = runner

    def _build_request_id(self, buf: RoleBuffer) -> str:
        ts = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        return f'role-{buf.account_id}-{buf.role_name}-{ts}'

    def _state_key(self, buf: RoleBuffer) -> str:
        return f'aws/role-{buf.account_id}-{buf.role_name}.tfstate'

    async def process_buffer(self, buf: RoleBuffer) -> None:
        request_id = self._build_request_id(buf)
        logger.info(f'[{request_id}] === Pipeline started ===')

        # PolicyFetcher는 buffer 처리 1회당 생성/폐기 (자격증명 보안)
        fetcher = PolicyFetcher(
            audit_role_name=settings.audit_role_name,
            session_name=settings.assume_role_session_name,
            duration_seconds=settings.assume_role_duration_seconds,
        )

        try:
            # 1. Codegen: Customer Managed 본문 조회 + 코드 생성 + 디스크 저장
            source_dir = write_workspace(
                buf=buf,
                output_base=self.output_base,
                fetcher=fetcher,
                inline_max_chars=settings.inline_policy_max_chars,
            )
            logger.info(f'[{request_id}] Workspace written: {source_dir}')

            # 2. Executor: 임시 작업 디렉터리로 복사
            work_dir = prepare_work_dir(source_dir, self.work_base, request_id)

            # 3. Terraform 실행
            try:
                self.runner.execute(
                    work_dir=work_dir,
                    state_key=self._state_key(buf),
                    request_id=request_id,
                )
                logger.info(f'[{request_id}] === Pipeline succeeded ===')
            except Exception as e:
                logger.error(
                    f'[{request_id}] === Pipeline failed: {type(e).__name__}: {e} ==='
                )
            finally:
                cleanup_work_dir(work_dir, request_id)

        except Exception as e:
            logger.error(
                f'[{request_id}] === Pipeline failed at codegen: '
                f'{type(e).__name__}: {e} ===',
                exc_info=True,
            )
        finally:
            fetcher.close()
