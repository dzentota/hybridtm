# Наполнение базы знаний

KB — это дерево YAML-файлов, одна сущность на файл, валидируемых по
JSON Schema из `schema/kb/*.json` — используйте пример из
`examples/kb/*.json` как основу, а не пишите файл с нуля. Загружается
через `HybridTM\Kb\YamlKbLoader`, который также разрешает цепочки
`spec.extends`.

Пять видов сущностей, определяются полем `kind:`:

| Вид | Формат id | Назначение |
|---|---|---|
| `Component` | `db-mysql`, `abstract/relational-db` | Элемент палитры: traits, свойства, порты, применимые правила |
| `Threat` | `THREAT-SOME-NAME` | Заголовок, описание, STRIDE, базовые likelihood/impact, ссылки на стандарты |
| `Countermeasure` | `CM-SOME-NAME` | Контрмера: cost/effort/effectiveness, подсказки по внедрению для конкретных продуктов |
| `Rule` | `category/some-rule` | Условие `when`/`unless`/`then`, либо PHP-класс для правил-графов |
| `Trait` | `snake_case_name` | Документирует строку-трейт для палитры Studio — опционально, `hasTrait()` работает и без этого |

## Минимальный компонент

```yaml
apiVersion: hybridtm.io/kb/v1
kind: Component
metadata:
  id: db-mysql
  name: MySQL
  version: 1.0.0
  categories: [data, datastore]
  maturity: stable
spec:
  extends: abstract/relational-db
  mapping:
    type: datastore   # обязательно в каждом файле, даже при extends — схема
                       # валидирует каждый файл по отдельности, до разрешения extends
    technologies: [database]
  properties:
    - { id: version, label: 'Версия MySQL', type: string, group: 'General' }
  rules: []
```

`extends` объединяет `traits`/`properties`/`ports`/`rules`/`mapping`
родителя — потомку достаточно объявить только то, что действительно
новое.

## Единственная ошибка, которой стоит избегать

Список `rules:` у компонента — это **только метаданные для палитры**:
Rule Engine выполняет каждое правило уровня component из всей KB
против каждого технического актива в модели, отфильтровывая только по
собственному условию `when` этого правила, вне зависимости от того,
какой компонент упоминает его в своём `rules:`.

Это важно, потому что незаданное свойство читается как нулевое
значение своего типа (`false`, `''`, `0`) — никогда как «неизвестно».
Если разместить свойство на одном конкретном компоненте, а правило
привязать к трейту, который есть и у *других* компонентов, — все они
будут проверяться по свойству, которое никогда не объявляли, и
проверка `== false` может ложно сработать на всех них.

**Решение:**

- разместить свойство на общем абстрактном предке (сделав его
  действительно универсальным для всех с этим трейтом), либо
- добавить новый трейт, достаточно узкий, чтобы его объявляли только
  нужные компоненты, и привязать правило к нему (у трейтов нет такого
  риска ложных срабатываний — `hasTrait()` — это реальная проверка
  принадлежности, а не чтение свойства с нулевым значением по
  умолчанию).

## Минимальное правило

```yaml
apiVersion: hybridtm.io/kb/v1
kind: Rule
metadata:
  id: storage/unencrypted-at-rest
  priority: 100
spec:
  scope: component   # component | flow | boundary | model
  description: 'Хранилище данных без шифрования на диске.'
  when:
    all:
      - "component.hasTrait('datastore')"
      - "component.props.bool('encryption_at_rest') == false"
  unless:
    any:
      - "component.hasMitigationFor('CWE-311')"
  then:
    - raise: THREAT-DATA-AT-REST-UNENCRYPTED
      require: [CM-ENCRYPT-AT-REST]
    - suggest_fix:
        set: { encryption_at_rest: true }
        label: 'Включить шифрование на диске'
```

### Песочница выражений

Условия `when`/`unless` выполняются через symfony/expression-language,
но песочница структурная, а не перехватчик времени выполнения:
`component` предоставляет только публичную поверхность
`ComponentSubject` — `id`, `name`, `encryption`, `internet`,
`redundant`, `multiTenant`, `customDevelopedParts`, `outOfScope`,
`props`, `hasTrait(...)`, `hasAllTraits(...)`,
`storesConfidentialityAtLeast(...)`, `hasMitigationFor(...)`. Правила
уровня flow дополнительно получают `flow` с `source`/`target` (каждый
— `ComponentSubject`), `protocol` (`.value`, `.isEncrypted()`), `vpn`,
`ipFiltered`, `readonly`, `crossesTrustBoundary()`,
`carriesDataAtLeast(...)`. Больше ничего не доступно из выражения
правила.

### Вычисляемые трейты

Вычисляются самим движком из топологии модели, доступны любому правилу
через `hasTrait(...)` без объявления каким-либо компонентом:
`internet_reachable`, `stores_pii`, `handles_strictly_confidential`,
`single_point_of_failure`, `directly_exposed_datastore`, `behind_waf`.

## Golden-file фикстуры

Каждому декларативному правилу нужна пара фикстур в
`tests/Fixtures/Rules/<name>.json` — модель `positive`, которая
вызывает срабатывание, и `negative`, которая не вызывает.
`RuleGoldenFileTest` ломает сборку, если у правила нет фикстуры, и
прогоняет каждую фикстуру через настоящий Rule Engine и настоящую KB.
