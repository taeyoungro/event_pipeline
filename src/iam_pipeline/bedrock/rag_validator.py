"""Bedrock RAG를 통한 최소권한 검증"""
import json
import logging
from typing import Optional

import boto3

logger = logging.getLogger(__name__)


class BedrockRAGValidator:
    """Bedrock Knowledge Base를 활용한 최소권한 및 프로젝트 참가 검증"""

    def __init__(
        self,
        knowledge_base_id: str,
        model_id: str,
        region: str = "us-east-1",
    ):
        if not knowledge_base_id:
            raise ValueError(
                "knowledge_base_id is empty — set BEDROCK_KNOWLEDGE_BASE_ID in .env"
            )
        if not model_id:
            raise ValueError(
                "model_id is empty — set BEDROCK_MODEL_ID in .env"
            )
        if not region:
            raise ValueError(
                "region is empty — set BEDROCK_REGION in .env"
            )
        self.knowledge_base_id = knowledge_base_id
        self.model_id = model_id
        self.region = region
        self._bedrock = boto3.client("bedrock-agent-runtime", region_name=region)
        self._bedrock_models = boto3.client("bedrock", region_name=region)

    async def validate_least_privilege(
        self,
        account_id: str,
        role_name: str,
        iic_user: str,
        policy_arns: set[str],
        target_account_ids: list[str],
        terraform_plan: Optional[str] = None,
    ) -> dict:
        """
        RAG를 통한 최소권한 검증:
        1. 사용자가 요청 프로젝트에 참가 중인지 확인
        2. 요청된 권한이 프로젝트 목적에 맞는지 검증
        3. Terraform 계획과 실제 권한이 일치하는지 확인

        Args:
            terraform_plan: terraform plan 명령 출력 (선택사항)

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
        """사용 계정에 대한 프로젝트 참가 여부를 Knowledge Base에서 확인"""
        query = (
            f"Is user '{iic_user}' a participant in the project "
            f"for AWS account {account_id}? "
            f"List the project name, team members, and project scope."
        )

        rag_response = await self._invoke_rag(query)

        # RAG 응답 분석
        is_participant = self._parse_participation_response(
            rag_response, iic_user, account_id
        )
        project_info = self._extract_project_info(rag_response)

        return {
            "is_participant": is_participant,
            "project_name": project_info.get("project_name", ""),
            "expected_project": project_info.get("expected_project", ""),
            "team_members": project_info.get("team_members", []),
        }

    async def _validate_policy_requirements(
        self,
        account_id: str,
        role_name: str,
        iic_user: str,
        policy_arns: set[str],
        project_name: str,
        terraform_plan: Optional[str] = None,
    ) -> dict:
        """요청된 권한이 프로젝트 목적에 맞는지, 최소권한 원칙을 따르는지 검증

        terraform_plan을 포함하면 실제 리소스 변경과 권한 요청의 일치성 검증 가능
        """
        policies_str = "\n".join(sorted(policy_arns))

        query = (
            f"Project: {project_name}\n"
            f"Account: {account_id}\n"
            f"Role: {role_name}\n"
            f"User: {iic_user}\n"
            f"Requested Policies:\n{policies_str}\n\n"
        )

        if terraform_plan:
            # tfplan 내용 요약 (전체를 포함하면 토큰이 과다하므로 앞 부분만)
            plan_summary = terraform_plan[:2000] if len(terraform_plan) > 2000 else terraform_plan
            query += (
                f"Terraform Plan (Resources to be created/modified):\n"
                f"{plan_summary}\n\n"
            )

        query += (
            f"Based on the project documentation and the Terraform plan:\n"
            f"1. Are these permissions necessary for the project scope and planned resources?\n"
            f"2. Are there any unnecessary or excessive permissions?\n"
            f"3. Do the permissions align with actual resources being deployed?\n"
            f"4. Are there permissions that could enable unauthorized actions beyond the project scope?\n"
            f"5. Does this comply with least-privilege principles?"
        )

        rag_response = await self._invoke_rag(query)

        # RAG 응답 분석
        policy_details = self._parse_policy_validation(rag_response, policy_arns)

        return {
            "has_unnecessary_policies": policy_details["has_unnecessary"],
            "unnecessary_policies": policy_details["unnecessary_list"],
            "policy_details": policy_details["details"],
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
                        "modelArn": f"arn:aws:bedrock:{self.region}::foundation-model/{self.model_id}",
                        "retrievalConfiguration": {
                            "vectorSearchConfiguration": {
                                "numberOfResults": 5,
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

    def _parse_participation_response(
        self, response: str, iic_user: str, account_id: str
    ) -> bool:
        """RAG 응답에서 사용자 참가 여부 추출"""
        response_lower = response.lower()

        # 긍정 표현 확인
        positive_indicators = [
            f"{iic_user.lower()} is a participant",
            f"{iic_user.lower()} is part of",
            f"{iic_user.lower()} is a member",
            "yes, the user is",
            "confirmed participant",
            "approved team member",
        ]

        # 부정 표현 확인
        negative_indicators = [
            f"{iic_user.lower()} is not",
            "not a participant",
            "not mentioned",
            "not part of",
            "not found",
            "cannot find",
            "no record of",
        ]

        has_positive = any(
            indicator in response_lower for indicator in positive_indicators
        )
        has_negative = any(
            indicator in response_lower for indicator in negative_indicators
        )

        return has_positive and not has_negative

    def _extract_project_info(self, response: str) -> dict:
        """RAG 응답에서 프로젝트 정보 추출"""
        result = {
            "project_name": "",
            "expected_project": "",
            "team_members": [],
        }

        # 간단한 문자열 파싱 (RAG 응답 구조에 맞게 조정 필요)
        lines = response.split("\n")
        for line in lines:
            if "project:" in line.lower():
                result["project_name"] = line.split(":", 1)[-1].strip()
            if "team" in line.lower() or "members" in line.lower():
                result["team_members"].append(line.strip())

        return result

    def _parse_policy_validation(self, response: str, policy_arns: set[str]) -> dict:
        """RAG 응답에서 정책 검증 결과 추출"""
        response_lower = response.lower()

        unnecessary_list = []
        details = {}

        for policy_arn in sorted(policy_arns):
            policy_name = policy_arn.split("/")[-1].lower()
            details[policy_arn] = {
                "is_necessary": True,
                "reason": "Within project scope",
            }

            # 정책이 불필요 또는 과도한지 확인
            unnecessary_keywords = [
                f"{policy_name} is unnecessary",
                f"{policy_name} is excessive",
                f"{policy_name} is not required",
                f"{policy_name} exceeds",
            ]

            if any(keyword in response_lower for keyword in unnecessary_keywords):
                unnecessary_list.append(policy_arn)
                details[policy_arn] = {
                    "is_necessary": False,
                    "reason": "Exceeds least-privilege principle",
                }

        has_unnecessary = (
            len(unnecessary_list) > 0
            or "unnecessary" in response_lower
            or "excessive" in response_lower
        )

        return {
            "has_unnecessary": has_unnecessary,
            "unnecessary_list": unnecessary_list,
            "details": details,
        }
