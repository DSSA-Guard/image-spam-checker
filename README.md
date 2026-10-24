# image-spam-checker

디스코드 봇의 이미지 스팸 검사를 따로 떼어낸 서버예요. OpenCV와 차단 목록 DB를 봇 프로세스에서 분리해서, 무거운 이미지 비교가 봇 이벤트 루프에 영향을 주지 않아요.

## 하는 일

- 업로드된 이미지가 차단 목록에 있는지 검사: SHA-256 → 지각 해시(dHash) → ORB 특징점 부분 매칭(잘라내기·붙여넣기, 60% 이상 겹침)
- 신고되거나 차단된 이미지는 SHA-256 말고도 MD5, SHA-1, SHA-512, SHA3-256, BLAKE2b 해시를 함께 저장해요. 다른 도구나 공유 차단 목록에서 받은 해시로도 이미지를 찾아볼 수 있어요.
- 멤버 신고 기록, 서로 다른 5명이 신고하면 자동 차단
- 신고 대기 목록, 신고 이미지 사본 보관, 수동 차단/해제

## 실행

```bash
pip install -r requirements.txt
export IMAGE_CHECKER_ADMIN_PASSWORD=관리자-비밀번호        # 필수, 없으면 서버가 시작되지 않아요
export IMAGE_CHECKER_SESSION_SECRET=아주-긴-랜덤-문자열     # 선택, 없으면 재시작할 때 관리자 로그인이 풀려요
export IMAGE_CHECKER_COOKIE_SECURE=1                       # HTTPS 뒤에서 돌릴 때 켜 주세요
export IMAGE_CHECKER_DATA_DIR=/data                        # 기본값 ./data (SQLite 파일이 여기 저장돼요)
uvicorn app.main:app --host 0.0.0.0 --port 9000
```

워커는 1개로 돌려야 해요. 차단 목록과 API 키 캐시가 프로세스 메모리에 있어요.

## API 키 발급

1. `/admin`에 접속해서 관리자 비밀번호로 로그인해요.
2. 키 이름(예: `디스코드 봇 운영`)을 적고 발급을 누르면 `isc_…` 키가 한 번만 보여요. 바로 복사해 두세요.
3. 봇 환경 변수에 서버 주소는 `IMAGE_CHECKER_API_URL`, 키는 `IMAGE_CHECKER_API_KEY`로 넣어요.

키는 해시만 저장되기 때문에 잃어버리면 다시 볼 수 없어요. 새로 발급하고 예전 키는 폐기하면 돼요. 폐기한 키는 그 즉시 막혀요. 목록에서 키마다 마지막 사용 시각도 볼 수 있어요.

## API

`/v1` 요청에는 관리 페이지에서 발급한 키를 `Authorization: Bearer <키>`로 넣어야 해요.

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/health` | 상태 확인 (인증 없음) |
| GET | `/admin` | 관리 페이지 (관리자 비밀번호 로그인) |
| POST | `/v1/match` | multipart `image` → `{"hash": 일치한 차단 해시 \| null}` |
| POST | `/v1/reports` | multipart `image`, `reporter_id`, `filename`, `jump_url` → `status`: `recorded` / `duplicate` / `blocked` / `auto_blocked` |
| GET | `/v1/reports/pending?limit=50` | 아직 차단되지 않은 신고 목록 |
| GET | `/v1/images/{hash}` | 보관된 신고 이미지 (확장자는 `X-Filename-Ext` 헤더) |
| GET | `/v1/blacklist` | 차단 목록 (저장된 `md5`, `sha1`, `sha512`, `sha3_256`, `blake2b` 포함) |
| GET | `/v1/digests/{해시}` | MD5·SHA-1·SHA-256·SHA-512·SHA3-256·BLAKE2b 중 아무 해시로 조회 → `{"digests": {...}, "blacklisted": bool}`, 없으면 404 |
| PUT | `/v1/blacklist/{hash}` | JSON `{added_by, source}` 로 차단 |
| DELETE | `/v1/blacklist/{hash}` | 차단 해제 (신고 기록도 초기화) |

## 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest
```
