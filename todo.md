
---

# PRD: HybridTM (PHP to Threagile Framework)

## 1. Executive Summary (Обзор проекта)

**HybridTM** — это фреймворк статического анализа кода для непрерывного моделирования угроз (Continuous Threat Modeling) в экосистеме PHP.
Инструмент извлекает макро-архитектуру из декларативного PHP-DSL, а микро-архитектуру (потоки данных) — из PHP 8 атрибутов, расставленных в бизнес-логике. Затем он компилирует эти данные в 100% валидный манифест **Threagile YAML** для последующей генерации DFD-диаграмм и отчетов об угрозах. Ключевая особенность: расстановка атрибутов в коде автоматизируется через инструкции для AI-ассистентов (Copilot, Claude Code).

## 2. Problem Statement (Проблематика)

* **PyTM / Традиционный TMaC:** Сильная связанность модели и логики поиска угроз, технический долг, генерация ложных срабатываний (False Positives), оторванность от реального кода.
* **Ручной TMiC (Threatspec):** Разработчики саботируют написание аннотаций безопасности, так как это замедляет разработку.
* **Решение:** Выносим анализ угроз во внешний стандартизированный движок (Threagile). Максимально усложняем схему атрибутов (для 100% покрытия Threagile), но полностью перекладываем их генерацию на LLM-ассистентов разработчиков.

## 3. Архитектура решения (Core Architecture)

Пайплайн состоит из четырех независимых компонентов:

1. **AI Copilot Skill (Контекст для генерации):** Набор правил (`.cursorrules` или промпты) для IDE, которые заставляют ИИ анализировать бизнес-логику метода и автоматически добавлять PHP-атрибуты HybridTM.
2. **Infrastructure DSL (Слой макро-архитектуры):** Отдельный PHP-файл (например, `threat_model.php`), описывающий узлы (`TechnicalAssets`), зоны доверия (`TrustBoundaries`) и типы данных (`DataAssets`).
3. **PHP 8 Attributes Library:** Строго типизированный набор атрибутов, полностью дублирующий enums и поля из спецификации Threagile.
4. **AST Compiler (CLI Tool):** Утилита на базе `nikic/php-parser`, которая парсит DSL и исходный код, линкует объекты и генерирует `threagile.yaml`.

---

## 4. Functional Requirements (Функциональные требования)

### 4.1. Слой Инфраструктуры (DSL)

Должен предоставлять Fluent API для объявления глобальных компонентов.

* **FR-1.1:** Поддержка создания `DataAsset` (с указанием CIA-триады: `confidentiality`, `integrity`, `availability`).
* **FR-1.2:** Поддержка создания `TechnicalAsset` (серверы, БД, брокеры сообщений) с указанием `machine`, `size`, `type`, `encryption`, `owner`.
* **FR-1.3:** Поддержка создания `TrustBoundary` (сети, VPC, роли) и вложенности активов в них.

### 4.2. Слой Атрибутов (PHP 8 Attributes)

Поскольку генерировать их будет ИИ, атрибуты должны требовать исчерпывающих данных.

* **FR-2.1:** Атрибут `#[DataFlow]` (аналог communication_link). Должен принимать параметры:
* `target` (string - ссылка на TechnicalAsset из DSL)
* `protocol` (enum: HTTP, TCP, etc.)
* `authentication` (enum: none, mutual, etc.)
* `authorization` (enum)
* `dataSent` (array of strings - ссылки на DataAssets)
* `dataReceived` (array of strings - ссылки на DataAssets)


* **FR-2.2:** Атрибут `#[Mitigation]` (аналог tags/custom risk rules в Threagile). Принимает:
* `cwe` (string)
* `description` (string)
* `status` (enum: implemented, planned)


* **FR-2.3:** Атрибут `#[ProcessesData]` (для указания, какие данные обрабатываются внутри самого сервиса без передачи).

### 4.3. Слой Компилятора (AST CLI)

* **FR-3.1:** CLI-команда `hybridtm compile --source=src/ --infra=threat_model.php --out=threagile.yaml`.
* **FR-3.2:** Статический анализ без выполнения кода. Компилятор не должен делать `require` или `include` файлов приложения (чтобы избежать фатальных ошибок и побочных эффектов). Используем только парсинг дерева (AST).
* **FR-3.3:** Валидатор ссылок (Cross-reference validation). Если атрибут ссылается на `target: 'PostgresDB'`, компилятор обязан проверить, существует ли актив `PostgresDB` в DSL. Если нет — бросить понятный Exception.
* **FR-3.4:** Сериализатор YAML. Сгенерированный файл должен строго соответствовать YAML-схеме актуальной версии Threagile.

### 4.4. Слой AI Integration (Copilot/Claude Skill)

* **FR-4.1:** Разработка системного промпта (например, файла `hybridtm.md` для включения в контекст IDE).
* **FR-4.2:** Промпт должен содержать:
* Справочник доступных DataAssets и TechnicalAssets текущего проекта.
* Инструкцию: "При написании или изменении метода, взаимодействующего с сетью, БД или файловой системой, ты обязан добавить атрибут `#[DataFlow]` перед сигнатурой метода, используя следующие правила...".



---

## 5. Non-Functional Requirements (Нефункциональные требования)

* **Производительность:** Компиляция проекта на 5000 классов не должна занимать более 15 секунд (критично для CI/CD).
* **Zero Dependencies in Prod:** Библиотека атрибутов (`hybridtm/attributes`) не должна тянуть за собой AST-парсер. Парсер (`hybridtm/compiler`) ставится только в `require-dev`.
* **Типизация:** 100% строгая типизация PHP (strict_types=1), использование PHP 8.1+ Enums для всех значений, которые в Threagile являются перечислениями (например, `Confidentiality::STRICTLY_CONFIDENTIAL`).

---

## 6. Маппинг данных (Data Dictionary: PHP -> Threagile)

Для генерации 100% полей LLM нужно знать, как мапить структуры.

| Концепт в HybridTM (PHP) | Сущность Threagile (YAML) | Обязательность |
| --- | --- | --- |
| `HybridTM\DSL\TechnicalAsset` | `technical_assets.[id]` | Да |
| Свойства `TechnicalAsset` (size, type) | `technical_assets.[id].size`, `.type`, etc. | Да |
| `HybridTM\DSL\DataAsset` | `data_assets.[id]` | Да |
| Свойства `DataAsset` (CIA triad) | `data_assets.[id].confidentiality`, etc. | Да |
| `#[DataFlow(target: 'X')]` | `technical_assets.[ТекущийУзел].communication_links.[ТекущийУзел-to-X]` | Да |
| Свойства `#[DataFlow]` (protocol, auth) | `.communication_links.[link].protocol`, `.authentication`, etc. | Да |
| `#[Mitigation(cwe: '123')]` | `.communication_links.[link].tags` (генерируем тег `mitigated:CWE-123`) | Нет |

---

## 7. Этапы реализации (Roadmap для генерации с LLM)

Поскольку вы будете кодить с LLM, разбейте задачу на эти изолированные промпты/этапы:

* **Phase 1: Domain & Attributes (Легкий этап)**
* Попросите LLM создать PHP 8.1 Enums для всех перечислений из документации Threagile (Sizes, Confidentiality, Protocols, etc.).
* Попросите создать классы атрибутов (`DataFlow`, `Mitigation`) с использованием этих Enums в конструкторе.


* **Phase 2: DSL Builder (Легкий этап)**
* Сгенерировать классы для описания инфраструктуры (`ThreatModel`, `TechnicalAsset`, `TrustBoundary`) с паттерном Builder или Fluent Interface.


* **Phase 3: AST Parser (Сложный этап)**
* Написать парсер на базе `nikic/php-parser`.
* Промпт: "Напиши NodeVisitor для php-parser, который находит методы с атрибутом `DataFlow` и извлекает все аргументы атрибута в DTO".


* **Phase 4: Compiler & Linker (Сложный этап)**
* Написать логику слияния (Merge) графа из DSL и графа из AST.
* Реализовать валидацию (поиск "висячих" ссылок).


* **Phase 5: YAML Dumper (Средний этап)**
* Трансляция внутреннего графа объектов в многомерный массив и экспорт через `symfony/yaml`.


* **Phase 6: AI Prompts (Важнейший этап)**
* Составить `SKILL.md` описав, как LLM должна сама использовать созданные в Phase 1 атрибуты при написании PHP-кода.


