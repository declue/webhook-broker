# Webhook Broker


많은 웹서비스, 특히 GitHub의 경우 Webhook으로 이벤트/로깅을 전달할 수 있음
이 서비스는 이러한 webhook을 받아주는 역할을 담당하는 서비스로 어떠한 형태의 webhook이든 모두 수용 가능 /webhook/** 모든 path 대응 가능.
/webhook/github/...
/webhook/atalassin/jira/.. 등등 depth에 상관 없이 모두 DB에 기록을 함. 

그리고 이후 다른 Application들은 pull 구조로 이러한 webhook 정보를 가져올 수 있음.

예를 들어 Electron로 빌드한 Desktop App을 쓰는 어떤 유저가 github actions 알림을 sub 하면 아직 받지 않은 메시지를 pull 할 수 있음.

그리고 한번 받은 메시지는 다시 받지 않게 됨.

하지만 새로운 User가 pull을 한다면 그 메시지를 받을 수 있음


근데 github webhook은 서버에 모두 기록될 수 있지만 이를 가져가는 app(사용자)는 자신의 권한에 맞는 메시지만 pull 할 수 있어야 함.

다른 사람, 다른 시스템의 webhook 메시지를 권한 없이 조회해서는 안됨.


이 웹서비스는 github api를 직접 날려 정보를 조회하는 토큰 비용을 아끼고, 중앙화된 DB를 통해 여러 사용자들에게 webhook을 발행하기 위한 목적임


