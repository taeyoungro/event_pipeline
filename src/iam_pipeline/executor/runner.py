"""Terraform 실행 (init/plan/apply)"""
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from .cache import analyze_provider_cache_usage

logger = logging.getLogger(__name__)


class TerraformRunner:
    def __init__(
        self,
        state_bucket: str,
        state_region: str,
        lock_table: Optional[str],
        plugin_cache_dir: Path,
    ):
        self.state_bucket = state_bucket
        self.state_region = state_region
        self.lock_table = lock_table
        self.plugin_cache_dir = plugin_cache_dir

    def _env(self) -> dict:
        return {
            **os.environ,
            'TF_IN_AUTOMATION': 'true',
            'TF_INPUT': 'false',
            'TF_PLUGIN_CACHE_DIR': str(self.plugin_cache_dir),
            'TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE': 'true',
        }

    def _backend_args(self, state_key: str) -> list[str]:
        args = [
            f'-backend-config=bucket={self.state_bucket}',
            f'-backend-config=key={state_key}',
            f'-backend-config=region={self.state_region}',
            '-backend-config=encrypt=true',
        ]
        if self.lock_table:
            args.append(f'-backend-config=dynamodb_table={self.lock_table}')
        return args

    def _run(self, work_dir: Path, cmd: list[str], step: str, request_id: str):
        logger.info(f'[{request_id}] Running: {" ".join(cmd)}')
        r = subprocess.run(cmd, cwd=work_dir, env=self._env(),
                          capture_output=True, text=True)
        if r.returncode != 0:
            logger.error(f'[{request_id}] {step} failed (exit {r.returncode})')
            logger.error(f'[{request_id}] stdout: {r.stdout[-2000:]}')
            logger.error(f'[{request_id}] stderr: {r.stderr[-2000:]}')
            raise RuntimeError(f'Terraform {step} failed: {r.stderr[-500:]}')
        logger.info(f'[{request_id}] {step} succeeded')
        return r

    def execute(self, work_dir: Path, state_key: str, request_id: str) -> dict:
        """work_dir의 코드를 init → plan → apply 순으로 실행"""
        backend_args = self._backend_args(state_key)
        logger.info(f'[{request_id}] Backend: s3://{self.state_bucket}/{state_key}')

        init_r = self._run(
            work_dir,
            ['terraform', 'init', '-no-color', *backend_args],
            'init', request_id
        )
        analyze_provider_cache_usage(init_r.stdout, request_id)

        plan_r = self._run(
            work_dir,
            ['terraform', 'plan', '-no-color', '-out=tfplan'],
            'plan', request_id
        )

        apply_r = self._run(
            work_dir,
            ['terraform', 'apply', '-no-color', '-auto-approve', 'tfplan'],
            'apply', request_id
        )

        return {
            'init': init_r.stdout,
            'plan': plan_r.stdout,
            'apply': apply_r.stdout,
        }

    def destroy(self, work_dir: Path, state_key: str, request_id: str) -> dict:
        """Phase 1.4: DeleteRole — terraform init + destroy -auto-approve"""
        backend_args = self._backend_args(state_key)
        logger.info(
            f'[{request_id}] Destroy backend: s3://{self.state_bucket}/{state_key}'
        )

        init_r = self._run(
            work_dir,
            ['terraform', 'init', '-no-color', *backend_args],
            'init', request_id,
        )
        analyze_provider_cache_usage(init_r.stdout, request_id)

        destroy_r = self._run(
            work_dir,
            ['terraform', 'destroy', '-no-color', '-auto-approve'],
            'destroy', request_id,
        )

        return {'init': init_r.stdout, 'destroy': destroy_r.stdout}
