"""Bedrock RAG를 통한 최소권한 검증"""
import json
import logging
import re
from typing import Optional

import boto3

logger = logging.getLogger(__name__)

# Bedrock이 ```json ... ``` 형태로 감싸 보낼 때 본문만 뽑기 위한 패턴
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)
# 모델이 사전/사후 설명을 붙여도 JSON 객체만 추출하기 위한 fallback 패턴
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _normalize_user(name: str) -> str:
    """'Security-Admin', 'SecurityAdmin', 'security admin'을 동일하게 비교하기 위한 정규화."""
    return re.sub(r"[-_\s]+", "", name).lower()


def _parse_json_response(response: str) -> dict:
    """Bedrock 응답 텍스트에서 JSON 객체를 안전하게 추출."""
    candidates: list[str] = []
    fenced = _JSON_FENCE_RE.search(response)
    if fenced:
        candidates.append(fenced.group(1))
    obj = _JSON_OBJECT_RE.search(response)
    if obj:
        candidates.append(obj.group(0))
    candidates.append(response.strip())

    for c in candidates:
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            continue
    raise ValueError(
        f"Bedrock response is not valid JSON. Raw response:\n{response[:500]}"
    )


class BedrockRAGValidator:
    """Bedrock Knowledge Base를 활용한 최소권한 및 프로젝트 참가 검증"""

    def __init__(
        self,
        knowledge_base_id: str,
        model_id: str,
        account_id: str,
        region: str = "us-east-1",
    ):
        """
        Args:
            model_id: 아래 셋 중 하나.
              1) 전체 ARN (arn:aws:bedrock:...) — 그대로 사용
              2) 시스템 inference profile ID (us./eu./apac./global. 접두사)
                 → arn:aws:bedrock:<region>:<account_id>:inference-profile/<id>
              3) foundation model ID (예: anthropic.claude-3-haiku-20240307-v1:0)
                 → arn:aws:bedrock:<region>::foundation-model/<id>
            account_id: inference profile ARN 구성에 사용할 AWS 계정 ID
              (.env의 AWS_ACCOUNT_ID로 주입)
        """
        if not knowledge_base_id:
            raise ValueError(
                "knowledge_base_id is empty — set BEDROCK_KNOWLEDGE_BASE_ID in .env"
            )
        if not model_id:
            raise ValueError(
                "model_id is empty — set BEDROCK_MODEL_ID in .env"
            )
        if not account_id:
            raise ValueError(
                "account_id is empty — set AWS_ACCOUNT_ID in .env"
            )
        if not region:
            raise ValueError(
                "region is empty — set BEDROCK_REGION in .env"
            )
        self.knowledge_base_id = knowledge_base_id
        self.model_id = model_id
        self.account_id = account_id
        self.region = region
        self._bedrock = boto3.client("bedrock-agent-runtime", region_name=region)
        self._bedrock_models = boto3.client("bedrock", region_name=region)
        self.model_arn = self._resolve_model_arn(model_id, region, account_id)
        logger.info(f"Resolved Bedrock modelArn: {self.model_arn}")

    @staticmethod
    def _resolve_model_arn(model_id: str, region: str, account_id: str) -> str:
        _PROFILE_PREFIXES = ("us.", "eu.", "apac.", "global.")

        # ARN으로 주어진 경우 마지막 경로 토큰만 추출 (ARN 내 리전은 무시하고 설정값 사용)
        bare = model_id.rsplit("/", 1)[-1] if model_id.startswith("arn:") else model_id

        # cross-region inference profile 접두사면 inference-profile ARN으로 재구성
        if bare.startswith(_PROFILE_PREFIXES):
            return f"arn:aws:bedrock:{region}:{account_id}:inference-profile/{bare}"

        # foundation-model: 항상 설정된 region으로 재조합 (ARN에 다른 리전이 포함돼도 교정)
        return f"arn:aws:bedrock:{region}::foundation-model/{bare}"

    async def validate_least_privilege(
        self,
        account_id: str,
        role_name: str,
        iic_user: str,
        policy_arns: set[str],
        target_account_ids: list[str],
        terraform_plan: Optional[str] = None,
        inline_policy_docs: Optional[dict[str, dict]] = None,
    ) -> dict:
        """
        RAG를 통한 최소권한 검증:
        1. 사용자가 요청 프로젝트에 참가 중인지 확인
        2. 요청된 권한이 프로젝트 목적에 맞는지 검증
        3. Terraform 계획과 실제 권한이 일치하는지 확인

        Args:
            terraform_plan: terraform plan 명령 출력 (선택사항)
            inline_policy_docs: CMP ARN → policy document 매핑.
                기존 PS에 새롭게 추가된 CMP의 실제 권한 내용을 RAG에 전달할 때 사용.
                ARN만으로는 내용을 알 수 없는 Customer Managed Policy에 한해 제공.

        Returns:
            {
                'approved': bool,
                'reason': str,
                'requires_approval': bool,
                'policies_validated': dict[str, bool],
            }
        """
        # 프로젝트 참가 여부 검증
        project_validation = await self._validate_project_participation(
            account_id, iic_user
        )
        if not project_validation["is_participant"]:
            return {
                "approved": False,
                "reason": (
                    f"User '{iic_user}' is not a participant in "
                    f"project for account {account_id}. "
                    f"Project: {project_validation.get('expected_project', 'Unknown')}"
                ),
                "requires_approval": False,
                "policies_validated": {},
            }

        # 권한 최소성 검증 (Terraform 계획 포함)
        policies_validation = await self._validate_policy_requirements(
            account_id,
            role_name,
            iic_user,
            policy_arns,
            project_validation.get("project_name", ""),
            terraform_plan=terraform_plan,
            inline_policy_docs=inline_policy_docs,
        )

        if policies_validation["has_unnecessary_policies"]:
            return {
                "approved": False,
                "reason": (
                    f"Unnecessary permissions detected: "
                    f"{', '.join(policies_validation['unnecessary_policies'])}. "
                    f"Only least-privilege permissions allowed."
                ),
                "requires_approval": True,
                "policies_validated": policies_validation["policy_details"],
            }

        return {
            "approved": True,
            "reason": "User and permissions validated successfully",
            "requires_approval": False,
            "policies_validated": policies_validation["policy_details"],
        }

    async def _validate_project_participation(
        self, account_id: str, iic_user: str
    ) -> dict:
        """사용 계정에 대한 프로젝트 참가 여부를 Knowledge Base에서 확인 (JSON 응답 강제)"""
        query = (
            f"You are a strict JSON-only API. Using the project documentation in the "
            f"knowledge base, determine whether the user is a participant of the project "
            f"associated with the given AWS account.\n\n"
            f"User to check: '{iic_user}'\n"
            f"AWS account ID: {account_id}\n\n"
            f"Treat user names as equal if they match after removing hyphens, "
            f"underscores, and spaces and lowercasing (e.g. 'Security-Admin' == "
            f"'SecurityAdmin' == 'security admin'). The user may also appear under a "
            f"role/title such as 'CISO' or '보안 팀장' — if the role description in the "
            f"documentation clearly refers to this user, treat them as a participant.\n\n"
            f"Respond with ONLY a single JSON object, no markdown, no commentary, no "
            f"code fences. Schema:\n"
            f'{{\n'
            f'  "is_participant": boolean,\n'
            f'  "project_name": string,\n'
            f'  "team_members": [string, ...],\n'
            f'  "scope": string,\n'
            f'  "evidence": string\n'
            f'}}'
        )

        rag_response = await self._invoke_rag(query)

        try:
            parsed = _parse_json_response(rag_response)
        except ValueError as e:
            logger.warning(f"Project participation JSON parse failed: {e}")
            return {
                "is_participant": False,
                "project_name": "",
                "expected_project": "",
                "team_members": [],
            }

        is_participant = bool(parsed.get("is_participant", False))
        # 모델이 사용자 이름을 정규화하지 못한 경우를 대비한 2차 안전망:
        # team_members 배열에 정규화 동치인 항목이 있으면 participant로 인정.
        members = [str(m) for m in parsed.get("team_members", []) or []]
        if not is_participant:
            target = _normalize_user(iic_user)
            for m in members:
                if target and target in _normalize_user(m):
                    is_participant = True
                    break

        return {
            "is_participant": is_participant,
            "project_name": str(parsed.get("project_name", "")),
            "expected_project": str(parsed.get("project_name", "")),
            "team_members": members,
            "scope": str(parsed.get("scope", "")),
            "evidence": str(parsed.get("evidence", "")),
        }

    async def _validate_policy_requirements(
        self,
        account_id: str,
        role_name: str,
        iic_user: str,
        policy_arns: set[str],
        project_name: str,
        terraform_plan: Optional[str] = None,
        inline_policy_docs: Optional[dict[str, dict]] = None,
    ) -> dict:
        """요청된 권한이 프로젝트 목적에 맞는지, 최소권한 원칙을 따르는지 검증

        terraform_plan을 포함하면 실제 리소스 변경과 권한 요청의 일치성 검증 가능.
        inline_policy_docs를 포함하면 CMP의 실제 권한 내용을 RAG 쿼리에 첨부.
        """
        # policy_arns(AMP) + inline_policy_docs 키(CMP) 합산으로 응답 schema 구성
        all_arns = set(policy_arns) | set(inline_policy_docs or {})
        policies_str = "\n".join(sorted(policy_arns)) if policy_arns else "(none)"

        query = (
            f"You are a strict JSON-only API. Evaluate whether each requested IAM "
            f"managed-policy is necessary for the project, based on the project "
            f"documentation in the knowledge base and (when provided) the Terraform "
            f"plan.\n\n"
            f"Project: {project_name}\n"
            f"Account: {account_id}\n"
            f"Role: {role_name}\n"
            f"User: {iic_user}\n"
            f"Requested AWS Managed Policy ARNs:\n{policies_str}\n\n"
        )

        if inline_policy_docs:
            query += "Newly attached Customer Managed Policies (embedded as inline in PS):\n"
            for arn, doc in sorted(inline_policy_docs.items()):
                doc_str = json.dumps(doc, indent=2)
                doc_str = doc_str[:1500] if len(doc_str) > 1500 else doc_str
                query += f"ARN: {arn}\nDocument:\n{doc_str}\n\n"

        if terraform_plan:
            plan_summary = terraform_plan[:2000] if len(terraform_plan) > 2000 else terraform_plan
            query += (
                f"Terraform Plan (resources to be created/modified):\n"
                f"{plan_summary}\n\n"
            )

        query += (
            f"Evaluation rules — apply STRICTLY before marking a policy as unnecessary:\n"
            f"1. A managed policy is NECESSARY if the service it grants access to is "
            f"mentioned, implied, or required for any task in the project documentation, "
            f"including services listed in budgets/cost tables and architecture diagrams.\n"
            f"2. Read-only / Audit / SecurityAudit / *_ReadOnlyAccess style managed "
            f"policies are LOW RISK; mark them necessary if the corresponding service "
            f"is referenced anywhere in the docs (including service names inside tables).\n"
            f"3. A policy is necessary even when not named explicitly when stated "
            f"operations cannot be performed without it. Example: 'disable compromised "
            f"IAM credentials' requires IAM permissions; 'monitor abnormal API calls' "
            f"implies CloudTrail; 'detect malicious traffic' implies GuardDuty; "
            f"'security findings aggregation' implies Security Hub.\n"
            f"4. Phrases like 'AWSLambda_FullAccess OR an equivalent managed policy' "
            f"mean variants and sibling read-only/admin policies of the same service "
            f"should all be considered acceptable.\n"
            f"5. When unsure, mark is_necessary=true with confidence=\"low\" rather "
            f"than false. Only mark is_necessary=false when the policy targets a "
            f"service totally unrelated to the project AND no documented scenario "
            f"could justify it.\n\n"
            f"Respond with ONLY a single JSON object, no markdown, no commentary, no "
            f"code fences. The 'policies' array must contain one entry per requested "
            f"policy ARN above, with the exact ARN string echoed back. Schema:\n"
            f'{{\n'
            f'  "policies": [\n'
            f'    {{\n'
            f'      "arn": string,                  // 위 요청 ARN 그대로\n'
            f'      "is_necessary": boolean,\n'
            f'      "confidence": "high" | "medium" | "low",\n'
            f'      "reason": string,\n'
            f'      "evidence": string              // 문서에서 근거가 된 구절/표 항목\n'
            f'    }}\n'
            f'  ],\n'
            f'  "summary": string\n'
            f'}}'
        )

        rag_response = await self._invoke_rag(query)

        try:
            parsed = _parse_json_response(rag_response)
        except ValueError as e:
            logger.warning(f"Policy validation JSON parse failed: {e}")
            # 파싱 실패 시 보수적으로 fail-closed: 모든 정책을 불필요로 표시해 승인 흐름으로 이동
            return {
                "has_unnecessary_policies": True,
                "unnecessary_policies": sorted(all_arns),
                "policy_details": {
                    arn: {"is_necessary": False, "reason": "RAG response not parseable"}
                    for arn in all_arns
                },
                "rag_analysis": rag_response,
            }

        details: dict[str, dict] = {}
        unnecessary: list[str] = []        # confidence=high인 false만 거부 대상
        low_confidence_flags: list[str] = []  # 그 외 false는 검토 대상으로만 기록
        by_arn = {
            str(item.get("arn", "")): item
            for item in parsed.get("policies", []) or []
            if isinstance(item, dict)
        }
        for arn in sorted(all_arns):
            item = by_arn.get(arn, {})
            is_necessary = bool(item.get("is_necessary", True))
            confidence = str(item.get("confidence", "low")).lower()
            reason = str(item.get("reason", "Within project scope" if is_necessary else ""))
            evidence = str(item.get("evidence", ""))
            details[arn] = {
                "is_necessary": is_necessary,
                "confidence": confidence,
                "reason": reason,
                "evidence": evidence,
            }
            if not is_necessary:
                if confidence == "high":
                    unnecessary.append(arn)
                else:
                    # 낮은 확신도의 false는 오탐 가능성이 높으므로 자동 거부하지 않고
                    # 관리자 검토 단계에서 함께 표시한다.
                    low_confidence_flags.append(arn)
                    logger.info(
                        f"Low-confidence 'unnecessary' verdict ignored for {arn} "
                        f"(confidence={confidence}, reason={reason!r})"
                    )

        return {
            "has_unnecessary_policies": len(unnecessary) > 0,
            "unnecessary_policies": unnecessary,
            "low_confidence_flags": low_confidence_flags,
            "policy_details": details,
            "rag_analysis": rag_response,
        }

    async def _invoke_rag(self, query: str) -> str:
        """Bedrock Knowledge Base에 RAG 질의 실행"""
        logger.info(f"Invoking Bedrock RAG with query: {query[:100]}...")
        print("\n" + "=" * 60)
        print("[RAG Query]")
        print(query)
        print("=" * 60)

        try:
            response = self._bedrock.retrieve_and_generate(
                input={"text": query},
                retrieveAndGenerateConfiguration={
                    "type": "KNOWLEDGE_BASE",
                    "knowledgeBaseConfiguration": {
                        "knowledgeBaseId": self.knowledge_base_id,
                        "modelArn": self.model_arn,
                        "retrievalConfiguration": {
                            "vectorSearchConfiguration": {
                                # 인덱스가 HYBRID를 미지원하므로 SEMANTIC 유지.
                                # 표/예산 항목까지 끌어오기 위해 결과 수만 늘림.
                                "numberOfResults": 10,
                                "overrideSearchType": "SEMANTIC",
                            }
                        },
                    },
                },
            )

            generated_text = response["output"]["text"]
            logger.info(f"RAG Response: {generated_text[:200]}...")
            print("\n[RAG Response]")
            print(generated_text)
            print("=" * 60 + "\n")
            return generated_text

        except Exception as e:
            logger.error(f"Bedrock RAG invocation failed: {e}")
            # Fail-open: 검증 불가 시 관리자 승인 요청
            raise RuntimeError(
                f"Bedrock RAG validation failed: {e}. "
                "Manual approval required."
            ) from e

