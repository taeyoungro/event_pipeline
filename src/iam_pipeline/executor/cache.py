"""Provider 캐시 사용 분석"""
import logging

logger = logging.getLogger(__name__)


def analyze_provider_cache_usage(stdout: str, request_id: str) -> None:
    hits, misses = [], []
    for line in stdout.splitlines():
        s = line.strip()
        if 'from the shared cache directory' in s:
            hits.append(s.lstrip('- ').strip())
        elif s.startswith('- Installed '):
            misses.append(s.lstrip('- ').strip())
    for e in hits:
        logger.info(f'[{request_id}] [CACHE HIT]  {e}')
    for e in misses:
        logger.warning(f'[{request_id}] [CACHE MISS] {e}')
    if hits or misses:
        total = len(hits) + len(misses)
        logger.info(
            f'[{request_id}] [CACHE SUMMARY] '
            f'hits={len(hits)}/{total}, misses={len(misses)}/{total}'
        )
