# Webhook Broker

**NATS JetStream 기반 Webhook 브로커 시스템**

GitHub 등의 웹훅을 중앙에서 받아 저장하고, 여러 클라이언트가 Pull 방식으로 자신의 권한에 맞는 메시지를 가져갈 수 있는 시스템입니다.

## 주요 기능

- ✅ **웹훅 수신 및 저장**: 모든 형태의 웹훅을 `/webhook/**` 경로로 수신
- ✅ **Pull 방식 메시지 조회**: 클라이언트가 원하는 시점에 메시지 가져오기
- ✅ **사용자별 진행 추적**: 각 사용자가 읽은 메시지 자동 추적
- ✅ **과거 메시지 재생**: 새 사용자도 과거 메시지 조회 가능
- ✅ **GitHub OAuth 인증**: GitHub 계정으로 로그인 및 권한 관리
- ✅ **권한 기반 필터링**: GitHub 레포지토리 권한에 따라 메시지 필터링

## 아키텍처

```
GitHub Webhooks
       ↓
[Webhook Broker API]
       ↓
[NATS JetStream]
 - Stream: WEBHOOKS
 - Subject: webhooks.{source}.{org}.{repo}
       ↓
[클라이언트 Pull API]
 - 사용자별 Durable Consumer
 - GitHub 권한 기반 필터링
```

## 기술 스택

- **Backend**: Node.js + TypeScript + Fastify
- **메시지 브로커**: NATS JetStream
- **데이터베이스**: PostgreSQL (Prisma ORM)
- **캐시**: Redis
- **인증**: GitHub OAuth 2.0 + JWT

## 빠른 시작

### 1. 사전 요구사항

- Node.js 18+
- Docker & Docker Compose
- GitHub OAuth App (개발용)

### 2. GitHub OAuth App 생성

1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App
2. 설정:
   - **Application name**: Webhook Broker (Dev)
   - **Homepage URL**: `http://localhost:3000`
   - **Authorization callback URL**: `http://localhost:3000/api/v1/auth/github/callback`
3. Client ID와 Client Secret 복사

### 3. 환경 변수 설정

```bash
cp .env.example .env
```

`.env` 파일 수정:
```env
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
JWT_SECRET=your-random-secret-key-here
```

### 4. 의존성 설치

```bash
npm install
```

### 5. 인프라 시작 (Docker Compose)

```bash
docker-compose up -d nats postgres redis
```

### 6. 데이터베이스 마이그레이션

```bash
npx prisma generate
npx prisma migrate dev --name init
```

### 7. 개발 서버 시작

```bash
npm run dev
```

서버가 `http://localhost:3000`에서 실행됩니다.

## API 사용 가이드

### 1. 인증

#### GitHub OAuth 로그인
```bash
# 브라우저에서 접속
open http://localhost:3000/api/v1/auth/github
```

응답:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "githubId": "12345",
    "username": "myusername",
    "email": "user@example.com"
  }
}
```

### 2. 웹훅 전송

```bash
curl -X POST http://localhost:3000/webhook/github/myorg/myrepo \
  -H "Content-Type: application/json" \
  -d '{"event": "push", "ref": "refs/heads/main"}'
```

응답:
```json
{
  "status": "accepted",
  "webhookPath": "/webhook/github/myorg/myrepo",
  "source": "github",
  "receivedAt": "2025-11-25T00:00:00.000Z"
}
```

### 3. 메시지 조회 (Pull)

```bash
curl -X GET "http://localhost:3000/api/v1/messages?limit=10" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

응답:
```json
{
  "messages": [
    {
      "id": "12345",
      "webhookPath": "/webhook/github/myorg/myrepo",
      "source": "github",
      "method": "POST",
      "headers": { ... },
      "payload": { ... },
      "receivedAt": "2025-11-25T00:00:00.000Z"
    }
  ],
  "nextCursor": "12345",
  "hasMore": true
}
```

### 4. 메시지 확인 (ACK)

```bash
curl -X POST http://localhost:3000/api/v1/messages/ack \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"messageIds": ["12345", "12346"]}'
```

응답:
```json
{
  "acknowledged": 2,
  "messageIds": ["12345", "12346"]
}
```

### 5. 통계 조회

```bash
curl -X GET http://localhost:3000/api/v1/messages/stats \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

응답:
```json
{
  "consumerName": "user_1",
  "filterSubjects": [
    "webhooks.github.myorg.myrepo",
    "webhooks.github.myorg.another-repo"
  ],
  "pending": 5,
  "delivered": 100,
  "ackFloor": 95,
  "redelivered": 2
}
```

## 프로젝트 구조

```
webhook-broker/
├── src/
│   ├── routes/
│   │   ├── webhook.ts      # POST /webhook/**
│   │   ├── auth.ts         # GitHub OAuth
│   │   └── messages.ts     # GET /messages, POST /messages/ack
│   ├── services/
│   │   ├── nats.ts         # NATS JetStream 클라이언트
│   │   ├── github.ts       # GitHub API 클라이언트
│   │   └── redis.ts        # Redis 캐시
│   ├── middleware/
│   │   └── auth.ts         # JWT 인증 미들웨어
│   ├── types/
│   │   └── index.ts        # TypeScript 타입 정의
│   ├── app.ts              # Fastify 앱 설정
│   ├── config.ts           # 환경 변수 관리
│   └── index.ts            # 진입점
├── prisma/
│   └── schema.prisma       # 데이터베이스 스키마
├── docker-compose.yml
├── Dockerfile
└── package.json
```

## 데이터베이스 스키마

### Users
- GitHub OAuth로 인증된 사용자 정보 저장
- GitHub Access Token 암호화 저장

### Consumers
- 사용자별 NATS Consumer 메타데이터
- 읽기 진행 상황 추적

### WebhookLogs
- 수신한 웹훅 로그 (메타데이터만)
- 실제 페이로드는 NATS에 저장

### Repositories
- 웹훅 경로와 NATS subject 매핑

## 개발

### 코드 포맷팅

```bash
npm run format
```

### 린트

```bash
npm run lint
```

### 프로덕션 빌드

```bash
npm run build
npm start
```

### Prisma Studio (DB GUI)

```bash
npm run prisma:studio
```

## 배포

### Docker Compose로 전체 스택 실행

```bash
docker-compose up -d
```

### 환경 변수 (프로덕션)

- `NODE_ENV=production`
- `GITHUB_WEBHOOK_SECRET`: GitHub webhook 서명 검증용
- `JWT_SECRET`: 강력한 랜덤 키 사용

## 다음 단계

### Phase 3: 고급 기능
- [ ] 구독 관리 시스템 (특정 레포만 구독)
- [ ] 메시지 필터링 (event type, branch 등)
- [ ] Rate limiting
- [ ] Webhook 재전송 (retry)

### Phase 4: 운영 최적화
- [ ] 메트릭 및 모니터링 (Prometheus + Grafana)
- [ ] API 문서 자동화 (Swagger/OpenAPI)
- [ ] 통합 테스트
- [ ] Kubernetes 배포 매니페스트

## 라이선스

MIT

## 기여

이슈와 PR을 환영합니다!

## 관련 문서

- [PROTOTYPE.md](./PROTOTYPE.md) - 초기 요구사항
- [plan.md](./plan.md) - 구현 계획 및 기술 조사
