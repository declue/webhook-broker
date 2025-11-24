# Webhook Broker 구현 계획

## 1. 기존 오픈소스 도구 분석

### 1.1 추천 오픈소스 도구

#### 🌟 Svix (https://www.svix.com/)
- **장점**:
  - Enterprise-grade webhook infrastructure
  - 자동 재시도, 속도 제한, 서명 검증 내장
  - 오픈소스 버전 제공
  - REST API 및 여러 SDK 제공
- **단점**:
  - Pull 모델보다는 Push 모델에 최적화
  - 사용자별 메시지 소비 추적이 복잡할 수 있음

#### 🔧 Hookdeck (https://hookdeck.com/)
- **장점**:
  - Webhook queue와 delivery 관리
  - 메시지 필터링 및 라우팅
  - 재시도 로직 내장
- **단점**:
  - SaaS 중심, 셀프호스팅 옵션 제한적
  - 비용 발생

#### 📨 Apache Kafka + Schema Registry
- **장점**:
  - 대규모 메시지 처리에 최적화
  - Consumer Group으로 메시지 소비 추적 가능
  - 높은 확장성과 내구성
  - 많은 커뮤니티 지원
- **단점**:
  - 설정 및 운영 복잡도가 높음
  - 작은 규모 프로젝트에는 과도할 수 있음

#### 🐰 RabbitMQ
- **장점**:
  - 다양한 메시징 패턴 지원
  - 설정이 Kafka보다 간단
  - 웹 관리 UI 제공
  - 메시지 우선순위, TTL 등 다양한 기능
- **단점**:
  - 권한 관리를 별도로 구현해야 함
  - Pull 모델 구현에 추가 작업 필요

#### ⚡ NATS JetStream (https://nats.io/)
- **장점**:
  - 경량화되고 빠른 성능
  - Pull/Push 모두 지원
  - 설정이 간단
  - 권한 관리 기능 내장
- **단점**:
  - Kafka보다 생태계가 작음

### 1.2 추천 조합

**Option A: NATS JetStream + Custom Auth Layer**
- NATS의 경량성과 Pull 지원 활용
- 커스텀 인증/권한 레이어 추가
- 가장 빠르게 프로토타입 구현 가능

**Option B: RabbitMQ + PostgreSQL**
- RabbitMQ로 메시지 큐 처리
- PostgreSQL로 메시지 영속화 및 권한 관리
- 중간 규모 프로젝트에 적합

**Option C: 완전 커스텀 구현**
- 요구사항에 정확히 맞춤
- 가장 높은 유연성
- 아래 상세 구현 계획 참조

---

## 2. 커스텀 구현 계획

### 2.1 시스템 아키텍처

```
┌─────────────┐
│   GitHub    │
│   Jira      │──── Webhooks ────┐
│   Others    │                  │
└─────────────┘                  ▼
                        ┌──────────────────┐
                        │  Webhook Broker  │
                        │   (REST API)     │
                        └──────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌─────────┐  ┌─────────┐  ┌──────────┐
              │PostgreSQL│  │  Redis  │  │Auth/ACL │
              │ Messages │  │  Cache  │  │ Service │
              └─────────┘  └─────────┘  └──────────┘
                    ▲
                    │
              ┌─────┴─────┐
              │   Clients │
              │(Pull API) │
              └───────────┘
```

### 2.2 기술 스택 제안

#### Backend
- **언어**: Go (성능, 동시성) 또는 Node.js (빠른 개발)
- **프레임워크**:
  - Go: Gin, Echo, 또는 Fiber
  - Node.js: Express, Fastify, 또는 NestJS
- **데이터베이스**: PostgreSQL (메시지 저장 및 쿼리)
- **캐시**: Redis (읽은 메시지 추적, 세션 관리)
- **인증**: JWT + OAuth 2.0 (GitHub 연동)

#### 선택적 기술
- **메시지 큐**: Redis Streams 또는 BullMQ (비동기 처리)
- **검색**: PostgreSQL Full-Text Search 또는 Elasticsearch
- **모니터링**: Prometheus + Grafana

### 2.3 데이터베이스 스키마

#### webhooks 테이블
```sql
CREATE TABLE webhooks (
    id BIGSERIAL PRIMARY KEY,
    webhook_path TEXT NOT NULL,           -- /webhook/github/repo1
    source TEXT NOT NULL,                  -- github, jira, etc
    payload JSONB NOT NULL,
    headers JSONB,
    received_at TIMESTAMP DEFAULT NOW(),

    -- 권한 관리
    owner_id INTEGER REFERENCES users(id),
    organization_id INTEGER REFERENCES organizations(id),
    is_public BOOLEAN DEFAULT FALSE,

    -- 인덱스 최적화
    CONSTRAINT valid_owner CHECK (owner_id IS NOT NULL OR organization_id IS NOT NULL)
);

CREATE INDEX idx_webhooks_path ON webhooks(webhook_path);
CREATE INDEX idx_webhooks_source ON webhooks(source);
CREATE INDEX idx_webhooks_received_at ON webhooks(received_at DESC);
CREATE INDEX idx_webhooks_owner ON webhooks(owner_id);
CREATE INDEX idx_webhooks_org ON webhooks(organization_id);
CREATE INDEX idx_webhooks_payload ON webhooks USING gin(payload);
```

#### users 테이블
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    github_id TEXT UNIQUE,              -- GitHub OAuth ID
    api_token TEXT UNIQUE,              -- API access token
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### organizations 테이블
```sql
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    github_org_name TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE organization_members (
    organization_id INTEGER REFERENCES organizations(id),
    user_id INTEGER REFERENCES users(id),
    role TEXT NOT NULL,                 -- admin, member, viewer
    PRIMARY KEY (organization_id, user_id)
);
```

#### message_consumption 테이블 (읽은 메시지 추적)
```sql
CREATE TABLE message_consumption (
    user_id INTEGER REFERENCES users(id),
    webhook_id BIGINT REFERENCES webhooks(id),
    consumed_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (user_id, webhook_id)
);

CREATE INDEX idx_consumption_user ON message_consumption(user_id, consumed_at);
```

#### webhook_subscriptions 테이블 (구독 관리)
```sql
CREATE TABLE webhook_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    webhook_path_pattern TEXT NOT NULL, -- /webhook/github/%
    filters JSONB,                      -- 추가 필터 (예: event_type, branch)
    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(user_id, webhook_path_pattern)
);
```

### 2.4 API 설계

#### Webhook 수신 API

```
POST /webhook/**
Content-Type: application/json
X-Webhook-Source: github
X-Webhook-Signature: sha256=...

Body: <any JSON payload>

Response: 202 Accepted
{
  "id": "123456",
  "received_at": "2025-11-25T00:00:00Z"
}
```

#### Pull API (메시지 조회)

```
GET /api/v1/messages?limit=50&after_id=12345&source=github
Authorization: Bearer <token>

Response: 200 OK
{
  "messages": [
    {
      "id": 12346,
      "webhook_path": "/webhook/github/repo1",
      "source": "github",
      "payload": {...},
      "received_at": "2025-11-25T00:00:00Z"
    }
  ],
  "next_cursor": "12400",
  "has_more": true
}
```

#### 메시지 확인 API (읽음 처리)

```
POST /api/v1/messages/ack
Authorization: Bearer <token>
Content-Type: application/json

{
  "message_ids": [12346, 12347, 12348]
}

Response: 200 OK
{
  "acknowledged": 3
}
```

#### 구독 관리 API

```
POST /api/v1/subscriptions
Authorization: Bearer <token>

{
  "webhook_path_pattern": "/webhook/github/myrepo/*",
  "filters": {
    "event_type": ["push", "pull_request"]
  }
}

GET /api/v1/subscriptions
DELETE /api/v1/subscriptions/{id}
```

### 2.5 권한 관리 로직

#### 메시지 접근 권한 확인 플로우

1. **경로 기반 권한**:
   - `/webhook/github/{org}/{repo}` → GitHub org 멤버십 확인
   - 사용자의 GitHub 토큰으로 repo 접근 권한 확인

2. **Owner 기반 권한**:
   - webhook 생성 시 owner_id 설정
   - owner만 해당 메시지 조회 가능

3. **Organization 기반 권한**:
   - organization_members 테이블 확인
   - 조직 멤버는 조직의 모든 webhook 조회 가능

4. **Public 메시지**:
   - is_public=true인 경우 모든 인증된 사용자 조회 가능

### 2.6 구현 단계

#### Phase 1: MVP (1-2주)
- [ ] 기본 프로젝트 구조 설정
- [ ] PostgreSQL 스키마 구현
- [ ] Webhook 수신 API 구현 (`POST /webhook/**`)
- [ ] 기본 인증 시스템 (API Token)
- [ ] Pull API 구현 (`GET /api/v1/messages`)
- [ ] 메시지 확인 API (`POST /api/v1/messages/ack`)
- [ ] 단위 테스트 작성

#### Phase 2: 권한 관리 (1주)
- [ ] GitHub OAuth 연동
- [ ] 경로 기반 권한 확인 로직
- [ ] Organization 멤버십 관리
- [ ] 권한 캐싱 (Redis)

#### Phase 3: 고급 기능 (1-2주)
- [ ] 구독 관리 시스템
- [ ] 메시지 필터링
- [ ] 페이지네이션 최적화
- [ ] Webhook 서명 검증 (GitHub, Jira 등)
- [ ] Rate limiting
- [ ] 메트릭 및 모니터링

#### Phase 4: 운영 및 최적화
- [ ] Docker 컨테이너화
- [ ] CI/CD 파이프라인
- [ ] 로그 수집 (ELK 또는 Loki)
- [ ] 성능 최적화 및 부하 테스트
- [ ] 문서화 (API 문서, 배포 가이드)

### 2.7 보안 고려사항

1. **Webhook 서명 검증**: GitHub HMAC 서명 확인
2. **Rate Limiting**: IP/User 기반 요청 제한
3. **SQL Injection 방지**: Prepared statements 사용
4. **XSS 방지**: JSON payload sanitization
5. **인증 토큰 저장**: bcrypt/argon2로 해싱
6. **HTTPS 강제**: 프로덕션 환경 필수
7. **CORS 정책**: 명시적 origin 허용

### 2.8 성능 최적화

1. **인덱싱**: 자주 쿼리되는 컬럼에 인덱스 추가
2. **연결 풀링**: 데이터베이스 연결 재사용
3. **캐싱**:
   - 권한 정보 Redis 캐싱 (TTL 5분)
   - 자주 조회되는 메시지 캐싱
4. **배치 처리**:
   - 메시지 ACK 배치 처리
   - 대량 webhook 수신 시 배치 insert
5. **비동기 처리**:
   - Webhook 수신 즉시 202 응답
   - 백그라운드에서 저장 및 권한 설정

### 2.9 모니터링 지표

- Webhook 수신 수 (per second)
- API 응답 시간 (p50, p95, p99)
- 데이터베이스 쿼리 성능
- 캐시 히트율
- 에러율
- 사용자별 메시지 소비율

---

## 3. 최종 추천

### 빠른 프로토타입이 필요한 경우
→ **NATS JetStream + Go + PostgreSQL**
- 1-2주 내 MVP 가능
- 가벼우면서 성능 좋음
- Pull 모델 기본 지원

### 장기 프로젝트 + 확장성 중요
→ **커스텀 구현 (Go/Node.js + PostgreSQL + Redis)**
- 완전한 제어 가능
- 정확한 요구사항 구현
- 4-6주 소요 예상

### 운영 부담 최소화
→ **Hookdeck 또는 Svix (SaaS 활용)**
- 즉시 사용 가능
- 운영 부담 없음
- 비용 발생

---

## 4. 다음 단계

1. ✅ 프로토타입 요구사항 정리 완료
2. ⬜ 기술 스택 결정
3. ⬜ 프로젝트 구조 초기화
4. ⬜ 데이터베이스 스키마 구현
5. ⬜ MVP 개발 시작
