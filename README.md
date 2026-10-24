# image-spam-checker

디스코드 봇의 이미지 스팸 검사를 따로 떼어낸 서버예요. OpenCV와 차단 목록 DB를 봇 프로세스에서 분리해서, 무거운 이미지 비교가 봇 이벤트 루프에 영향을 주지 않아요.

## 하는 일

- 업로드된 이미지가 차단 목록에 있는지 검사: SHA-256 → 지각 해시(dHash) → ORB 특징점 부분 매칭(잘라내기·붙여넣기, 60% 이상 겹침)
- 멤버 신고 기록, 서로 다른 5명이 신고하면 자동 차단
- 신고 대기 목록, 신고 이미지 사본 보관, 수동 차단/해제

## 실행

```bash
pip install -r requirements.txt
export IMAGE_CHECKER_TOKEN=아주-긴-랜덤-문자열
export IMAGE_CHECKER_DATA_DIR=/data   # 기본값 ./data (SQLite 파일이 여기 저장돼요)
uvicorn app.main:app --host 0.0.0.0 --port 9000
```

`IMAGE_CHECKER_TOKEN`이 없으면 `/health`를 뺀 모든 요청이 503으로 거절돼요. 봇 쪽에는 같은 값을 `IMAGE_CHECKER_TOKEN`, 서버 주소를 `IMAGE_CHECKER_URL`로 넣어주세요. 워커는 1개로 돌려야 해요(차단 목록 캐시가 프로세스 메모리에 있어요).

## API

모든 요청에 `Authorization: Bearer <토큰>` 필요.

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/health` | 상태 확인 (인증 없음) |
| POST | `/v1/match` | multipart `image` → `{"hash": 일치한 차단 해시 \| null}` |
| POST | `/v1/reports` | multipart `image`, `reporter_id`, `filename`, `jump_url` → `status`: `recorded` / `duplicate` / `blocked` / `auto_blocked` |
| GET | `/v1/reports/pending?limit=50` | 아직 차단되지 않은 신고 목록 |
| GET | `/v1/images/{hash}` | 보관된 신고 이미지 (확장자는 `X-Filename-Ext` 헤더) |
| GET | `/v1/blacklist` | 차단 목록 |
| PUT | `/v1/blacklist/{hash}` | JSON `{added_by, source}` 로 차단 |
| DELETE | `/v1/blacklist/{hash}` | 차단 해제 (신고 기록도 초기화) |

## 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest
```
