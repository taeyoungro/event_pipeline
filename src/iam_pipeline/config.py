"""환경 변수 기반 통합 설정"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore',
    )

    # 공통
    aws_region: str = 'us-east-1'
    secret_api_key: str = 'change-me-in-production'

    # Codegen
    output_base_dir: Path = Path('/home/ec2-user/iam_pipeline/output')
    payload_dir: Path = Path('/home/ec2-user/iam_pipeline/payloads')
    debounce_seconds: int = 5

    # 크로스 계정 어슘
    audit_role_name: str = 'AuditRole'             # 멤버 계정의 read-only role
    assume_role_session_name: str = 'iam-pipeline-codegen'
    assume_role_duration_seconds: int = 900        # 15분

    # IIC inline policy 길이 제한 (안전 마진 포함)
    inline_policy_max_chars: int = 32_000

    # Executor
    work_base_dir: Path = Path('/home/ec2-user/iam_pipeline/work')
    tf_state_bucket: str = 'nty-org-policy-terraform-state'
    tf_state_region: str = 'us-east-1'
    tf_state_lock_table: str = 'nty-tf-state-lock'
    tf_plugin_cache_dir: Path = Path('/var/cache/terraform/plugins')

    # Phase 2: 다중 계정 Assignment 태그 컨벤션
    iic_target_accounts_tag: str = 'iic-target-accounts'

    # Phase 4: 위험한 Trust Policy 차단
    block_wildcard_trust: bool = True

    # Phase 5.2: Bedrock RAG 최소권한 검증
    # 두 값 모두 .env(GitHub Secret 주입)에서 로드 — 코드 내 기본값 없음.
    bedrock_knowledge_base_id: str = ''
    bedrock_model_id: str = ''
    bedrock_region: str = 'us-east-1'
    bedrock_enable_rag_validation: bool = True

    # 로깅
    log_level: str = 'INFO'

    def ensure_dirs(self) -> None:
        for p in (self.output_base_dir, self.payload_dir, self.work_base_dir):
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
