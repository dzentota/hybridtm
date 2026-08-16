# Справочник: DSL, Атрибуты, Перечисления

Полная документация по всем классам, атрибутам и перечислениям HybridTM.

---

## Оглавление

1. [CLI-команды](#cli-команды)
2. [ThreatModel — корневой объект модели](#threatmodel)
3. [TechnicalAsset — технические компоненты](#technicalasset)
4. [DataAsset — типы данных](#dataasset)
5. [TrustBoundary — границы доверия](#trustboundary)
6. [CommunicationLink — соединения](#communicationlink)
7. [Атрибуты кода](#атрибуты-кода)
8. [Перечисления](#перечисления)
9. [Быстрая шпаргалка по перечислениям](#быстрая-шпаргалка-по-перечислениям)

---

## CLI-команды

### `compile`

Компилирует DSL-файл и PHP-атрибуты в Threagile YAML.

```bash
php bin/hybridtm compile [options]
```

| Опция | По умолчанию | Описание |
|-------|-------------|----------|
| `--infra=PATH` | `threat-model.php` | Путь к DSL-файлу инфраструктуры |
| `--source=DIR` | `src/` | Директория для сканирования PHP-атрибутов |
| `--out=PATH` | `threagile.yaml` | Выходной файл Threagile YAML |

**Примеры:**

```bash
# Стандартный запуск
php bin/hybridtm compile

# Явные пути
php bin/hybridtm compile \
    --infra=security/threat-model.php \
    --source=app/src/ \
    --out=build/threagile.yaml

# В Docker (для CI без локального PHP)
docker run --rm \
    -v "$(pwd):/app" \
    -w /app \
    php:8.2-cli \
    php bin/hybridtm compile --infra=threat-model.php --source=src/
```

**Выходные сообщения:**

- `✓ Loaded DSL` — DSL-файл загружен и валиден
- `✓ Scanned N file(s), found M data flow(s)` — результат AST-сканирования
- `WARNING: [DataFlow@Class::method] ...` — предупреждения (атрибут не создан в YAML)
- `ERROR: ...` — критическая ошибка (неизвестный ID актива), выход с кодом 1

---

## ThreatModel

Корневой объект модели. Создаётся в DSL-файле, возвращается через `return $model;`.

```php
use HybridTM\DSL\ThreatModel;

$model = new ThreatModel('Название системы');
```

### Свойства

| Свойство | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `title` | `string` | _(конструктор)_ | Название системы / продукта |
| `description` | `string` | `''` | Краткое описание |
| `author` | `string` | `''` | Автор / владелец модели |
| `date` | `string` | `''` | Дата в формате `YYYY-MM-DD`; пустая → текущий год |
| `businessCriticality` | `BusinessCriticality` | `Important` | Критичность для бизнеса |
| `managementSummaryComment` | `string` | `''` | Комментарий для executive summary |

### Методы

| Метод | Описание |
|-------|----------|
| `addDataAsset(DataAsset)` | Добавить тип данных; возвращает `$this` |
| `addTechnicalAsset(TechnicalAsset)` | Добавить компонент; возвращает `$this` |
| `addTrustBoundary(TrustBoundary)` | Добавить границу доверия; возвращает `$this` |
| `getDataAsset(string $id)` | Найти DataAsset по ID или `null` |
| `getTechnicalAsset(string $id)` | Найти TechnicalAsset по ID или `null` |
| `getDataAssets()` | Все DataAssets, индексированные по ID |
| `getTechnicalAssets()` | Все TechnicalAssets, индексированные по ID |
| `getTrustBoundaries()` | Все TrustBoundaries, индексированные по ID |

---

## TechnicalAsset

Представляет технический компонент системы: сервис, базу данных, внешнюю систему.

```php
use HybridTM\DSL\TechnicalAsset;

$asset = new TechnicalAsset('asset-id', 'Human-readable Name');
// Если name не указан — name = id
```

### Свойства

| Свойство | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `id` | `string` | _(конструктор)_ | Уникальный ID (lowercase-kebab-case) |
| `name` | `string` | `= id` | Отображаемое название |
| `description` | `string` | `''` | Описание компонента |
| `type` | `AssetType` | `Process` | Роль компонента в системе |
| `usage` | `DataUsage` | `Business` | Цель использования |
| `usedAsClientByHuman` | `bool` | `false` | Прямое использование людьми (браузер, мобильное приложение) |
| `outOfScope` | `bool` | `false` | Исключить из анализа угроз |
| `justificationOutOfScope` | `string` | `''` | Обоснование исключения |
| `size` | `Size` | `Service` | Масштаб компонента |
| `technology` | `Technology` | `WebServiceRest` | Тип технологии |
| `internet` | `bool` | `false` | Доступен из интернета |
| `machine` | `Machine` | `Virtual` | Тип среды исполнения |
| `encryption` | `Encryption` | `None` | Шифрование данных at-rest |
| `owner` | `string` | `''` | Владелец (команда, email) |
| `confidentiality` | `Confidentiality` | `Internal` | Конфиденциальность |
| `integrity` | `Integrity` | `Operational` | Требование к целостности |
| `availability` | `Availability` | `Operational` | Требование к доступности |
| `justificationCiaRating` | `string` | `''` | Обоснование CIA-рейтинга |
| `multiTenant` | `bool` | `false` | Обслуживает нескольких tenant'ов |
| `redundant` | `bool` | `false` | Дублирован для HA |
| `customDevelopedParts` | `bool` | `false` | Содержит собственный код |
| `dataAssetsProcessed` | `string[]` | `[]` | ID DataAssets, обрабатываемых компонентом |
| `dataAssetsStored` | `string[]` | `[]` | ID DataAssets, хранимых компонентом |
| `dataFormatsAccepted` | `string[]` | `[]` | Принимаемые форматы данных |
| `tags` | `string[]` | `[]` | Теги для группировки |

### Методы

#### `communicatesTo()`

Создаёт `CommunicationLink` из этого актива к целевому.

```php
$link = $asset->communicatesTo(
    targetId: 'db',                              // ID целевого TechnicalAsset
    protocol: Protocol::JdbcEncrypted,           // протокол
    authentication: Authentication::Credentials, // аутентификация
    authorization: Authorization::TechnicalUser, // авторизация
    description: 'SQL queries to main DB',       // описание
);

// Далее настройте link по необходимости:
$link->dataSent     = ['user-data'];
$link->dataReceived = ['query-result'];
$link->vpn          = false;
$link->readonly     = false;
```

**ID ссылки** формируется автоматически как `{sourceId}-to-{targetId}`.

---

## DataAsset

Описывает тип данных, которые обрабатываются или хранятся в системе.

```php
use HybridTM\DSL\DataAsset;

$asset = new DataAsset('asset-id', 'Human-readable Name');
```

### Свойства

| Свойство | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `id` | `string` | _(конструктор)_ | Уникальный ID |
| `name` | `string` | `= id` | Отображаемое название |
| `description` | `string` | `''` | Описание |
| `usage` | `DataUsage` | `Business` | Цель использования |
| `origin` | `DataOrigin` | `Unknown` | Источник данных |
| `owner` | `string` | `''` | Владелец данных |
| `quantity` | `Quantity` | `Many` | Примерный объём |
| `confidentiality` | `Confidentiality` | `Internal` | Уровень конфиденциальности |
| `integrity` | `Integrity` | `Operational` | Требование к целостности |
| `availability` | `Availability` | `Operational` | Требование к доступности |
| `justificationCiaRating` | `string` | `''` | Обоснование CIA |
| `tags` | `string[]` | `[]` | Теги |

---

## TrustBoundary

Группирует технические активы по уровню доверия. Соответствует понятию security zone.

```php
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\TrustBoundaryType;

$boundary = new TrustBoundary(
    'boundary-id',
    'Boundary Name',
    TrustBoundaryType::NetworkCloudProvider,
);
```

### Свойства

| Свойство | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `id` | `string` | _(конструктор)_ | Уникальный ID |
| `name` | `string` | `= id` | Отображаемое название |
| `type` | `TrustBoundaryType` | `NetworkOnPrem` | Тип границы |
| `description` | `string` | `''` | Описание |
| `technicalAssetsInside` | `string[]` | `[]` | ID активов внутри границы |
| `trustBoundariesNested` | `string[]` | `[]` | ID вложенных границ |
| `tags` | `string[]` | `[]` | Теги |

### Методы

#### `addAssets(string ...$assetIds)`

Добавляет активы в границу. Дубликаты игнорируются. Возвращает `$this`.

```php
$boundary->addAssets('web-app', 'api-service', 'auth-service');
```

---

## CommunicationLink

Описывает соединение между двумя техническими активами. Создаётся через `TechnicalAsset::communicatesTo()`.

### Свойства

| Свойство | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `id` | `string` | _(авто)_ | `{sourceId}-to-{targetId}` |
| `targetAssetId` | `string` | _(конструктор)_ | ID целевого актива |
| `protocol` | `Protocol` | `Https` | Протокол передачи |
| `authentication` | `Authentication` | `None` | Механизм аутентификации |
| `authorization` | `Authorization` | `None` | Механизм авторизации |
| `description` | `string` | `''` | Описание потока |
| `usage` | `DataUsage` | `Business` | Цель использования |
| `vpn` | `bool` | `false` | Трафик через VPN |
| `ipFiltered` | `bool` | `false` | IP-фильтрация |
| `readonly` | `bool` | `false` | Только чтение |
| `dataSent` | `string[]` | `[]` | ID отправляемых DataAssets |
| `dataReceived` | `string[]` | `[]` | ID получаемых DataAssets |
| `tags` | `string[]` | `[]` | Теги |

---

## Атрибуты кода

### `#[AssetId(string $id)]`

**Где:** на классе  
**Назначение:** связывает класс с `TechnicalAsset` в DSL по ID

```php
#[AssetId('web-app')]
class UserController { ... }
```

- Только один `#[AssetId]` на класс
- ID должен точно совпадать с `TechnicalAsset::$id` в DSL
- Без `#[AssetId]` — `#[DataFlow]` создаёт предупреждение и не генерирует ссылку

---

### `#[DataFlow(...)]`

**Где:** на методе или функции (повторяемый)  
**Назначение:** объявляет поток данных от актива-источника (`#[AssetId]`) к целевому

```php
#[DataFlow(
    target: 'db',                              // обязательно
    protocol: Protocol::JdbcEncrypted,         // по умолчанию: Https
    authentication: Authentication::Credentials, // по умолчанию: None
    authorization: Authorization::TechnicalUser, // по умолчанию: None
    dataSent: ['user-data'],                   // по умолчанию: []
    dataReceived: ['query-result'],            // по умолчанию: []
    vpn: false,                                // по умолчанию: false
    ipFiltered: false,                         // по умолчанию: false
    readonly: false,                           // по умолчанию: false
)]
public function save(array $data): void { }
```

**Несколько потоков на одном методе** (например, метод вызывает два сервиса):

```php
#[DataFlow(target: 'auth-service', protocol: Protocol::Https, dataSent: ['session-token'])]
#[DataFlow(target: 'audit-log', protocol: Protocol::Https, dataSent: ['order-data'])]
public function checkout(array $cart): string { }
```

**Поведение при дублировании:** если `#[AssetId('a')]` и `#[DataFlow(target: 'b')]` уже есть явный `communicatesTo('b')` в DSL — компилятор дополнит существующий link данными из атрибута (не перезапишет).

---

### `#[Mitigation(...)]`

**Где:** на классе, методе или функции (повторяемый)  
**Назначение:** документирует принятую меру безопасности

```php
#[Mitigation(
    cwe: 'CWE-89',                         // обязательно: номер CWE
    description: 'PDO prepared statements', // обязательно: описание
    status: MitigationStatus::Mitigated,   // по умолчанию: Mitigated
)]
public function findUser(int $id): array { }
```

**Статусы:**

| Константа | Значение | Когда использовать |
|-----------|----------|--------------------|
| `MitigationStatus::Mitigated` | `mitigated` | Мера реализована и проверена |
| `MitigationStatus::InProgress` | `in-progress` | В работе |
| `MitigationStatus::Accepted` | `accepted` | Риск принят (с обоснованием) |
| `MitigationStatus::Unchecked` | `unchecked` | Не проверено |

---

### `#[ProcessesData(dataAssets: [...])]`

**Где:** на классе или методе (повторяемый)  
**Назначение:** отмечает, что компонент обрабатывает указанные DataAssets

```php
#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['user-pii', 'session-token', 'payment-data'])]
class UserController { }
```

Используйте для явного документирования того, с какими данными работает компонент, даже если нет исходящих `#[DataFlow]`.

---

## Перечисления

### `AssetType` — роль компонента

| Константа | YAML-значение | Когда использовать |
|-----------|--------------|-------------------|
| `ExternalEntity` | `external-entity` | Браузер, мобильный клиент, партнёрская система, пользователь |
| `Process` | `process` | Сервис, приложение, обрабатывающее данные |
| `Datastore` | `datastore` | База данных, кеш, файловое хранилище, очередь |

---

### `Authentication` — механизм аутентификации

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `None` | `none` | Нет аутентификации |
| `Credentials` | `credentials` | Login/password, API key |
| `SessionId` | `session-id` | Cookie/session |
| `Token` | `token` | JWT, OAuth Bearer token |
| `ClientCertificate` | `client-certificate` | mTLS |
| `TwoFactor` | `two-factor` | 2FA/MFA |
| `ExternalizedViaGateway` | `externalized-via-gateway` | Auth делегирован API Gateway / APIM |

---

### `Authorization` — механизм авторизации

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `None` | `none` | Нет авторизации |
| `TechnicalUser` | `technical-user` | Системный пользователь (service account) |
| `EnduserIdentityPropagation` | `enduser-identity-propagation` | Идентичность конечного пользователя пробрасывается (OIDC, JWT claims) |

---

### `Protocol` — протокол передачи

| Константа | YAML-значение | Типичное применение |
|-----------|-------------|---------------------|
| `Https` | `https` | REST API, веб-приложения |
| `Http` | `http` | Внутренние незащищённые (не рекомендуется) |
| `Wss` | `wss` | WebSocket TLS |
| `Ws` | `ws` | WebSocket plain |
| `JdbcEncrypted` | `jdbc-encrypted` | JDBC с TLS (PostgreSQL, MySQL) |
| `Jdbc` | `jdbc` | JDBC без TLS (не рекомендуется) |
| `OdbcEncrypted` | `odbc-encrypted` | ODBC с TLS |
| `Odbc` | `odbc` | ODBC без TLS |
| `SqlAccessProtocolEncrypted` | `sql-access-protocol-encrypted` | MySQL protocol с TLS |
| `SqlAccessProtocol` | `sql-access-protocol` | MySQL protocol без TLS |
| `NosqlAccessProtocolEncrypted` | `nosql-access-protocol-encrypted` | MongoDB, Redis с TLS |
| `NosqlAccessProtocol` | `nosql-access-protocol` | MongoDB, Redis без TLS |
| `BinaryEncrypted` | `binary-encrypted` | gRPC, Thrift, протокол бинарный + TLS |
| `Binary` | `binary` | Бинарный протокол без TLS |
| `TextEncrypted` | `text-encrypted` | Текстовый протокол + TLS |
| `Text` | `text` | Текстовый протокол без TLS |
| `Ssh` | `ssh` | SSH |
| `SshTunnel` | `ssh-tunnel` | SSH tunneling |
| `SmtpEncrypted` | `smtp-encrypted` | SMTP с STARTTLS / TLS |
| `Smtp` | `smtp` | SMTP без TLS |
| `Ldaps` | `ldaps` | LDAP over TLS |
| `Ldap` | `ldap` | LDAP без TLS (не рекомендуется) |
| `Jms` | `jms` | JMS / AMQP (RabbitMQ, ActiveMQ) |
| `Sftp` | `sftp` | Безопасный FTP |
| `Ftp` | `ftp` | FTP (не рекомендуется) |
| `Mqtt` | `mqtt` | MQTT (IoT) |
| `LocalFileAccess` | `local-file-access` | Доступ к файловой системе |
| `ContainerSpawning` | `container-spawning` | Запуск контейнеров (K8s API) |
| `InProcessLibraryCall` | `in-process-library-call` | Вызов внутри процесса |

---

### `Encryption` — шифрование at-rest

| Константа | YAML-значение | Когда использовать |
|-----------|-------------|-------------------|
| `None` | `none` | Нет шифрования |
| `Transparent` | `transparent` | Прозрачное шифрование диска (TDE, AWS EBS) |
| `DataWithSymmetricSharedKey` | `data-with-symmetric-shared-key` | AES с общим ключом (AWS KMS, GCP CMEK) |
| `DataWithAsymmetricSharedKey` | `data-with-asymmetric-shared-key` | RSA шифрование данных |
| `DataWithEnduserIndividualKey` | `data-with-enduser-individual-key` | E2E: ключ у конечного пользователя |

---

### `Confidentiality` — уровень конфиденциальности

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Public` | `public` | Публичные данные, ущерба от раскрытия нет |
| `Internal` | `internal` | Внутренние данные компании |
| `Restricted` | `restricted` | Ограниченный доступ (не все сотрудники) |
| `Confidential` | `confidential` | Конфиденциально (PII, коммерческая тайна) |
| `StrictlyConfidential` | `strictly-confidential` | Строго конфиденциально (пароли, ключи, PCI данные) |

---

### `Integrity` — требование к целостности

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Archive` | `archive` | Архивные данные, изменения некритичны |
| `Operational` | `operational` | Стандартная операционная целостность |
| `Important` | `important` | Нарушение целостности заметно и проблематично |
| `Critical` | `critical` | Нарушение целостности вызывает сбои |
| `MissionCritical` | `mission-critical` | Нарушение целостности — катастрофа |

---

### `Availability` — требование к доступности

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Archive` | `archive` | Редкий доступ, простой приемлем |
| `Operational` | `operational` | Плановые остановки допустимы |
| `Important` | `important` | Простой заметен, нежелателен |
| `Critical` | `critical` | Простой приводит к потерям |
| `MissionCritical` | `mission-critical` | Любой простой — катастрофа |

---

### `Technology` — тип технологии

| Константа | YAML-значение | Типичный компонент |
|-----------|-------------|-------------------|
| `Browser` | `browser` | Web browser |
| `Desktop` | `desktop` | Desktop application |
| `MobileApp` | `mobile-app` | iOS / Android app |
| `WebApplication` | `web-application` | Monolith web app (Symfony, Laravel) |
| `WebServiceRest` | `web-service-rest` | REST API microservice |
| `WebServiceSoap` | `web-service-soap` | SOAP web service |
| `WebServer` | `web-server` | Nginx, Apache |
| `ApplicationServer` | `application-server` | Tomcat, JBoss |
| `Database` | `database` | PostgreSQL, MySQL, MongoDB |
| `IdentityProvider` | `identity-provider` | Keycloak, Okta, Auth0 |
| `LdapServer` | `ldap-server` | Active Directory, OpenLDAP |
| `ReverseProxy` | `reverse-proxy` | Nginx reverse proxy |
| `LoadBalancer` | `load-balancer` | HAProxy, AWS ALB |
| `Waf` | `waf` | Web Application Firewall |
| `MessageQueue` | `message-queue` | RabbitMQ, Kafka, SQS |
| `StreamProcessing` | `stream-processing` | Kafka Streams, Flink |
| `BatchProcessing` | `batch-processing` | Batch jobs, ETL |
| `Function` | `function` | Lambda, Cloud Functions |
| `ContainerPlatform` | `container-platform` | Kubernetes, ECS |
| `Monitoring` | `monitoring` | Prometheus, Grafana, Datadog |
| `BuildPipeline` | `build-pipeline` | Jenkins, GitHub Actions |
| `SourcecodeRepository` | `sourcecode-repository` | GitHub, GitLab |
| `Vault` | `vault` | HashiCorp Vault, AWS Secrets Manager |
| `Erp` | `erp` | SAP, Microsoft Dynamics |
| `SearchIndex` | `search-index` | Elasticsearch, OpenSearch |
| `DataLake` | `data-lake` | S3, BigQuery |
| `Gateway` | `gateway` | API Gateway (Kong, AWS API GW) |
| `Scheduler` | `scheduler` | Cron, AWS EventBridge |
| `Mainframe` | `mainframe` | IBM z/OS |
| `Ai` | `ai` | ML-сервис, LLM endpoint |
| `Cli` | `cli` | Command line tool |

---

### `Machine` — тип среды исполнения

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Physical` | `physical` | Физический сервер / bare metal |
| `Virtual` | `virtual` | Виртуальная машина (VMware, EC2) |
| `Container` | `container` | Docker контейнер / K8s pod |
| `Serverless` | `serverless` | Lambda, Cloud Functions |

---

### `Size` — масштаб компонента

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `System` | `system` | Крупная система (несколько сервисов) |
| `Service` | `service` | Отдельный сервис / приложение |
| `Application` | `application` | Приложение с несколькими модулями |
| `Component` | `component` | Небольшой компонент, библиотека |

---

### `TrustBoundaryType` — тип границы доверия

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `NetworkOnPrem` | `network-on-prem` | On-premise сеть / дата-центр |
| `NetworkDedicatedHoster` | `network-dedicated-hoster` | Выделенный хостинг |
| `NetworkVirtualLan` | `network-virtual-lan` | VLAN |
| `NetworkCloudProvider` | `network-cloud-provider` | VPC (AWS, GCP, Azure) |
| `NetworkCloudSecurityGroup` | `network-cloud-security-group` | Security Group / firewall |
| `NetworkPolicyNamespaceIsolation` | `network-policy-namespace-isolation` | K8s Namespace с NetworkPolicy |
| `ExecutionEnvironment` | `execution-environment` | Execution environment (OS, runtime) |

---

### `DataOrigin` — источник данных

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Unknown` | `unknown` | Источник не определён |
| `UserInput` | `ui-input` | Ввод пользователя (форма, API запрос) |
| `FileImport` | `file-import` | Импорт из файла |
| `DeviceAccess` | `device-access` | Данные от устройства (IoT, mobile) |
| `ServiceCall` | `service-call` | Получены от другого сервиса |
| `TransferredFromPartner` | `transferred-from-partner` | Переданы партнёром / 3rd party |
| `InHouse` | `in-house` | Сгенерированы внутри системы |

---

### `DataUsage` — цель использования данных

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Business` | `business` | Бизнес-данные (основной поток) |
| `DevOps` | `devops` | Данные для DevOps / инфраструктуры |

---

### `Quantity` — приблизительный объём данных

| Константа | YAML-значение | Ориентир |
|-----------|-------------|----------|
| `VeryFew` | `very-few` | < 100 записей |
| `Few` | `few` | 100 – 10 000 |
| `Many` | `many` | 10 000 – 1 000 000 |
| `VeryMany` | `very-many` | > 1 000 000 |

---

### `BusinessCriticality` — критичность для бизнеса

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Archive` | `archive` | Архивная / неактивная система |
| `Operational` | `operational` | Поддерживает операции, не критична |
| `Important` | `important` | Важна, потеря заметна |
| `Critical` | `critical` | Критична, потеря серьёзно влияет на бизнес |
| `MissionCritical` | `mission-critical` | Потеря = остановка бизнеса |

---

### `MitigationStatus` — статус меры безопасности

| Константа | YAML-значение | Описание |
|-----------|-------------|----------|
| `Mitigated` | `mitigated` | Реализовано и верифицировано |
| `InProgress` | `in-progress` | В работе |
| `Accepted` | `accepted` | Риск принят (нужно обоснование) |
| `Unchecked` | `unchecked` | Не проверено |

---

## Быстрая шпаргалка по перечислениям

```php
use HybridTM\Enums\{
    AssetType, Authentication, Authorization, Availability,
    BusinessCriticality, Confidentiality, DataOrigin, DataUsage,
    Encryption, Integrity, Machine, MitigationStatus,
    Protocol, Quantity, Size, Technology, TrustBoundaryType
};

// Самые частые комбинации:

// REST API из браузера
$browserLink->protocol       = Protocol::Https;
$browserLink->authentication = Authentication::Token;      // JWT cookie
$browserLink->authorization  = Authorization::EnduserIdentityPropagation;

// Microservice → Microservice (internal)
$serviceLink->protocol       = Protocol::Https;
$serviceLink->authentication = Authentication::Token;      // service JWT
$serviceLink->authorization  = Authorization::TechnicalUser;

// Service → PostgreSQL (encrypted)
$dbLink->protocol       = Protocol::JdbcEncrypted;
$dbLink->authentication = Authentication::Credentials;
$dbLink->authorization  = Authorization::TechnicalUser;

// Service → Redis (NoSQL, TLS)
$redisLink->protocol       = Protocol::NosqlAccessProtocolEncrypted;
$redisLink->authentication = Authentication::Credentials;
$redisLink->authorization  = Authorization::TechnicalUser;

// Service → RabbitMQ (AMQP)
$mqLink->protocol       = Protocol::Jms;
$mqLink->authentication = Authentication::Credentials;
$mqLink->authorization  = Authorization::TechnicalUser;

// gRPC (encrypted binary)
$grpcLink->protocol       = Protocol::BinaryEncrypted;
$grpcLink->authentication = Authentication::ClientCertificate; // mTLS

// SSH / SCP
$sshLink->protocol       = Protocol::Ssh;
$sshLink->authentication = Authentication::ClientCertificate;

// External API (Stripe, Twilio, etc.)
$externalLink->protocol       = Protocol::Https;
$externalLink->authentication = Authentication::Token;      // API key / Bearer
$externalLink->authorization  = Authorization::TechnicalUser;
```
