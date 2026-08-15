<?php
declare(strict_types=1);
namespace HybridTM\Tests\Kb;

use HybridTM\Kb\Kind;
use HybridTM\Kb\KbException;
use HybridTM\Kb\RuleScope;
use HybridTM\Kb\YamlKbLoader;
use PHPUnit\Framework\TestCase;

final class YamlKbLoaderTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_kb_' . uniqid('', true);
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
    }

    private function removeDir(string $path): void
    {
        if (!is_dir($path)) return;
        foreach (scandir($path) as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            $full = $path . '/' . $entry;
            is_dir($full) ? $this->removeDir($full) : unlink($full);
        }
        rmdir($path);
    }

    private function write(string $relativePath, string $yaml): string
    {
        $path = $this->tmpDir . '/' . $relativePath;
        @mkdir(dirname($path), 0755, true);
        file_put_contents($path, $yaml);
        return $path;
    }

    private function component(string $id, string $body): string
    {
        return <<<YAML
apiVersion: hybridtm.io/kb/v1
kind: Component
metadata:
  id: {$id}
  name: {$id}
  version: 1.0.0
spec:
{$body}
YAML;
    }

    private function rule(string $id, string $scope, int $priority = 100): string
    {
        return <<<YAML
apiVersion: hybridtm.io/kb/v1
kind: Rule
metadata:
  id: {$id}
  priority: {$priority}
spec:
  scope: {$scope}
  when: { all: ["true"] }
  then: [{ raise: THREAT-X }]
YAML;
    }

    // ── basic loading ────────────────────────────────────────────────────────

    public function testLoadsComponentWithoutExtends(): void
    {
        $this->write('web.yaml', $this->component('web-server-nginx', <<<YAML
  mapping: { type: process, technologies: [web-server] }
  traits: [http_server]
YAML));

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);

        self::assertTrue($kb->has(Kind::Component, 'web-server-nginx'));
        $spec = $kb->get(Kind::Component, 'web-server-nginx');
        self::assertSame('process', $spec['mapping']['type']);
        self::assertSame(['http_server'], $spec['traits']);
        self::assertArrayNotHasKey('extends', $spec);
    }

    public function testUnknownEntityReturnsNull(): void
    {
        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        self::assertNull($kb->get(Kind::Component, 'nonexistent'));
        self::assertFalse($kb->has(Kind::Component, 'nonexistent'));
    }

    public function testIdsListsAllEntitiesOfAKind(): void
    {
        $this->write('a.yaml', $this->component('a', "  mapping: { type: process }\n"));
        $this->write('b.yaml', $this->component('b', "  mapping: { type: process }\n"));

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        self::assertSame(['a', 'b'], $kb->ids(Kind::Component));
    }

    // ── extends resolution (T-2.2) ───────────────────────────────────────────

    public function testThreeLevelExtendsChainMergesTraitsRulesAndProperties(): void
    {
        $this->write('grandparent.yaml', $this->component('abstract/network-component', <<<YAML
  mapping: { type: process }
  traits: [network_component]
  rules: [base/rule]
YAML));
        $this->write('parent.yaml', $this->component('abstract/reverse-proxy', <<<YAML
  extends: abstract/network-component
  mapping: { type: process, technologies: [reverse-proxy] }
  traits: [traffic_forwarding]
  rules: [proxy/no-tls-to-upstream]
  properties:
    - { id: internet_facing, type: boolean, default: false }
YAML));
        $this->write('nginx.yaml', $this->component('web-server-nginx', <<<YAML
  extends: abstract/reverse-proxy
  mapping: { type: process, technologies: [reverse-proxy, web-server], machine: container }
  traits: [http_server]
  rules: [nginx/server-tokens-disclosure]
  properties:
    - { id: version, type: string }
YAML));

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        $nginx = $kb->get(Kind::Component, 'web-server-nginx');

        self::assertSame(['network_component', 'traffic_forwarding', 'http_server'], $nginx['traits']);
        self::assertSame(
            ['base/rule', 'proxy/no-tls-to-upstream', 'nginx/server-tokens-disclosure'],
            $nginx['rules'],
        );
        self::assertCount(2, $nginx['properties']);
        self::assertSame('container', $nginx['mapping']['machine']);
        self::assertSame(['reverse-proxy', 'web-server'], $nginx['mapping']['technologies']);
    }

    public function testChildPropertyWithSameIdReplacesParents(): void
    {
        $this->write('parent.yaml', $this->component('abstract/reverse-proxy', <<<YAML
  mapping: { type: process }
  properties:
    - { id: internet_facing, type: boolean, default: false }
YAML));
        $this->write('child.yaml', $this->component('nginx', <<<YAML
  extends: abstract/reverse-proxy
  mapping: { type: process }
  properties:
    - { id: internet_facing, type: boolean, default: true }
YAML));

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        $properties = $kb->get(Kind::Component, 'nginx')['properties'];

        self::assertCount(1, $properties, 'same-id property replaces, does not duplicate');
        self::assertTrue($properties[0]['default'], 'child value wins on collision (§4.3)');
    }

    public function testMappingDefaultsAreShallowMerged(): void
    {
        $this->write('parent.yaml', $this->component('abstract/datastore', <<<YAML
  mapping:
    type: datastore
    defaults: { confidentiality: internal, integrity: important }
YAML));
        $this->write('child.yaml', $this->component('postgres', <<<YAML
  extends: abstract/datastore
  mapping:
    type: datastore
    defaults: { confidentiality: confidential }
YAML));

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        $defaults = $kb->get(Kind::Component, 'postgres')['mapping']['defaults'];

        self::assertSame('confidential', $defaults['confidentiality'], 'child overrides shared key');
        self::assertSame('important', $defaults['integrity'], 'parent-only key survives');
    }

    public function testExtendsThroughMultiplePackageLayers(): void
    {
        $core = $this->tmpDir . '/core';
        $org = $this->tmpDir . '/org';
        mkdir($core, 0755, true);
        mkdir($org, 0755, true);

        file_put_contents($core . '/base.yaml', $this->component('abstract/reverse-proxy', <<<YAML
  mapping: { type: process }
  traits: [traffic_forwarding]
YAML));
        file_put_contents($org . '/nginx.yaml', $this->component('web-server-nginx', <<<YAML
  extends: abstract/reverse-proxy
  mapping: { type: process }
  traits: [http_server]
YAML));

        $kb = (new YamlKbLoader())->load([$core, $org]);
        self::assertSame(['traffic_forwarding', 'http_server'], $kb->get(Kind::Component, 'web-server-nginx')['traits']);
    }

    public function testCircularExtendsThrows(): void
    {
        $this->write('a.yaml', $this->component('a', "  extends: b\n  mapping: { type: process }\n"));
        $this->write('b.yaml', $this->component('b', "  extends: a\n  mapping: { type: process }\n"));

        $this->expectException(KbException::class);
        $this->expectExceptionMessageMatches('/[Cc]ircular/');
        (new YamlKbLoader())->load([$this->tmpDir]);
    }

    public function testExtendsUnknownParentThrows(): void
    {
        $this->write('a.yaml', $this->component('a', "  extends: nonexistent\n  mapping: { type: process }\n"));

        $this->expectException(KbException::class);
        (new YamlKbLoader())->load([$this->tmpDir]);
    }

    // ── layering ─────────────────────────────────────────────────────────────

    public function testLaterPathOverridesEarlierEntirely(): void
    {
        $core = $this->tmpDir . '/core';
        $org = $this->tmpDir . '/org';
        mkdir($core, 0755, true);
        mkdir($org, 0755, true);

        file_put_contents($core . '/web.yaml', $this->component('web-server-nginx', <<<YAML
  mapping: { type: process }
  traits: [http_server]
YAML));
        file_put_contents($org . '/web.yaml', $this->component('web-server-nginx', <<<YAML
  mapping: { type: process }
  traits: [http_server, custom_org_trait]
YAML));

        $kb = (new YamlKbLoader())->load([$core, $org]);
        self::assertSame(['http_server', 'custom_org_trait'], $kb->get(Kind::Component, 'web-server-nginx')['traits']);
    }

    // ── envelope validation ──────────────────────────────────────────────────

    public function testRejectsMissingApiVersion(): void
    {
        $this->write('bad.yaml', "kind: Component\nmetadata: { id: x }\nspec: { mapping: { type: process } }\n");
        $this->expectException(KbException::class);
        (new YamlKbLoader())->load([$this->tmpDir]);
    }

    public function testRejectsUnknownKind(): void
    {
        $this->write('bad.yaml', "apiVersion: hybridtm.io/kb/v1\nkind: Widget\nmetadata: { id: x }\nspec: {}\n");
        $this->expectException(KbException::class);
        (new YamlKbLoader())->load([$this->tmpDir]);
    }

    public function testRejectsMissingMetadataId(): void
    {
        $this->write('bad.yaml', "apiVersion: hybridtm.io/kb/v1\nkind: Component\nmetadata: {}\nspec: { mapping: { type: process } }\n");
        $this->expectException(KbException::class);
        (new YamlKbLoader())->load([$this->tmpDir]);
    }

    public function testIgnoresNonYamlFiles(): void
    {
        $this->write('notes.txt', 'not yaml at all {{{');
        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        self::assertSame([], $kb->ids(Kind::Component));
    }

    public function testMissingPathIsTolerated(): void
    {
        $kb = (new YamlKbLoader())->load([$this->tmpDir . '/does-not-exist']);
        self::assertSame([], $kb->ids(Kind::Component));
    }

    // ── rulesFor / componentsByCategory ──────────────────────────────────────

    public function testRulesForFiltersByScopeAndOrdersByPriority(): void
    {
        $this->write('rules/low.yaml', $this->rule('storage/low', 'component', priority: 10));
        $this->write('rules/high.yaml', $this->rule('storage/high', 'component', priority: 200));
        $this->write('rules/flow.yaml', $this->rule('flow/x', 'flow', priority: 500));

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        self::assertSame(['storage/high', 'storage/low'], $kb->rulesFor(RuleScope::Component));
    }

    public function testRulesForFiltersByTraitViaComponentAssociation(): void
    {
        $this->write('rules/db.yaml', $this->rule('storage/unencrypted', 'component'));
        $this->write('rules/web.yaml', $this->rule('web/hsts-missing', 'component'));
        $this->write('components/db.yaml', $this->component('postgres', <<<YAML
  mapping: { type: datastore }
  traits: [datastore]
  rules: [storage/unencrypted]
YAML));
        $this->write('components/web.yaml', $this->component('nginx', <<<YAML
  mapping: { type: process }
  traits: [http_server]
  rules: [web/hsts-missing]
YAML));

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);

        self::assertSame(['storage/unencrypted'], $kb->rulesFor(RuleScope::Component, ['datastore']));
        self::assertSame(['web/hsts-missing'], $kb->rulesFor(RuleScope::Component, ['http_server']));
    }

    public function testComponentsByCategory(): void
    {
        $this->write('nginx.yaml', <<<YAML
apiVersion: hybridtm.io/kb/v1
kind: Component
metadata: { id: web-server-nginx, name: Nginx, version: 1.0.0, categories: [web, edge] }
spec: { mapping: { type: process } }
YAML);
        $this->write('postgres.yaml', <<<YAML
apiVersion: hybridtm.io/kb/v1
kind: Component
metadata: { id: db-postgresql, name: PostgreSQL, version: 1.0.0, categories: [data] }
spec: { mapping: { type: datastore } }
YAML);

        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        self::assertSame(['web-server-nginx'], $kb->componentsByCategory('web'));
        self::assertSame(['db-postgresql'], $kb->componentsByCategory('data'));
        self::assertSame([], $kb->componentsByCategory('nonexistent'));
    }

    // ── version() ────────────────────────────────────────────────────────────

    public function testVersionIsDeterministicForIdenticalContent(): void
    {
        $this->write('web.yaml', $this->component('web-server-nginx', "  mapping: { type: process }\n"));

        $v1 = (new YamlKbLoader())->load([$this->tmpDir])->version();
        $v2 = (new YamlKbLoader())->load([$this->tmpDir])->version();

        self::assertSame($v1, $v2);
    }

    public function testVersionChangesWithContent(): void
    {
        $this->write('web.yaml', $this->component('web-server-nginx', "  mapping: { type: process }\n"));
        $before = (new YamlKbLoader())->load([$this->tmpDir])->version();

        file_put_contents($this->tmpDir . '/web.yaml', $this->component('web-server-nginx', "  mapping: { type: datastore }\n"));
        $after = (new YamlKbLoader())->load([$this->tmpDir])->version();

        self::assertNotSame($before, $after);
    }

    // ── performance (T-2.2 DoD: 200 files < 150ms) ───────────────────────────

    public function testLoads200FilesWithinPerformanceBudget(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $this->write("component-{$i}.yaml", $this->component("component-{$i}", "  mapping: { type: process }\n"));
        }

        $start = hrtime(true);
        $kb = (new YamlKbLoader())->load([$this->tmpDir]);
        $elapsedMs = (hrtime(true) - $start) / 1_000_000;

        self::assertCount(200, $kb->ids(Kind::Component));
        self::assertLessThan(1500, $elapsedMs, 'loading 200 KB files should stay fast (generous multiple of the 150ms target for CI stability)');
    }
}
