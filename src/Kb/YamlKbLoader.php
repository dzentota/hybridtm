<?php
declare(strict_types=1);
namespace HybridTM\Kb;

use Symfony\Component\Yaml\Yaml;

/**
 * Reads `*.yaml`/`*.yml` KB files from one or more package directories,
 * layers them (later paths override earlier ones — core KB first, org
 * overrides last), and resolves `extends` for `Component` entities (T-2.2).
 *
 * Deep JSON-Schema validation of each document belongs to `hybridtm
 * kb:lint` (T-2.6), not here — this loader only checks the envelope it
 * needs to merge correctly (`apiVersion`, a known `kind`, `metadata.id`).
 */
final class YamlKbLoader implements KbLoaderInterface
{
    private const API_VERSION = 'hybridtm.io/kb/v1';

    public function load(array $paths): KnowledgeBaseInterface
    {
        /** @var array<string, array<string, array<string, mixed>>> $raw kind => id => raw spec */
        $raw = [];
        $fileHashes = [];

        foreach ($paths as $path) {
            foreach ($this->findYamlFiles($path) as $file) {
                $contents = (string) file_get_contents($file);
                $document = Yaml::parse($contents);

                if (!is_array($document)) {
                    throw KbException::schemaViolation($file, 'file does not contain a YAML mapping.');
                }

                [$kind, $id, $spec] = $this->readEnvelope($file, $document);

                $raw[$kind->value][$id] = $spec;
                $fileHashes[] = "{$kind->value}:{$id}:" . hash('sha256', $contents);
            }
        }

        // Other kinds don't support `extends` and pass through unchanged;
        // Component starts empty so resolveComponent() is the only writer —
        // pre-seeding it from $raw would make every component look
        // "already resolved" before extends is ever applied.
        $resolved = $raw;
        unset($resolved[Kind::Component->value]);
        $resolving = [];
        foreach (array_keys($raw[Kind::Component->value] ?? []) as $componentId) {
            $this->resolveComponent($componentId, $raw, $resolved, $resolving);
        }

        sort($fileHashes);
        $version = substr(hash('sha256', implode("\n", $fileHashes)), 0, 16);

        return new InMemoryKnowledgeBase($resolved, $version);
    }

    /**
     * @param array<string, mixed> $document
     * @return array{0: Kind, 1: string, 2: array<string, mixed>}
     */
    private function readEnvelope(string $file, array $document): array
    {
        if (($document['apiVersion'] ?? null) !== self::API_VERSION) {
            throw KbException::schemaViolation($file, 'missing or unexpected apiVersion.');
        }

        $kind = Kind::tryFrom((string) ($document['kind'] ?? ''));
        if ($kind === null) {
            throw KbException::schemaViolation($file, 'missing or unknown kind.');
        }

        $id = (string) ($document['metadata']['id'] ?? '');
        if ($id === '') {
            throw KbException::schemaViolation($file, 'missing metadata.id.');
        }

        $spec = (array) ($document['spec'] ?? []);
        $spec['metadata'] = (array) ($document['metadata'] ?? []);

        return [$kind, $id, $spec];
    }

    /** @return list<string> absolute file paths, deterministically ordered */
    private function findYamlFiles(string $directory): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $files = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(
            $directory,
            \FilesystemIterator::SKIP_DOTS,
        ));

        foreach ($it as $file) {
            if ($file instanceof \SplFileInfo && in_array($file->getExtension(), ['yaml', 'yml'], true)) {
                $files[] = $file->getPathname();
            }
        }

        sort($files);
        return $files;
    }

    /**
     * Recursively resolves `spec.extends` for one component, memoizing into
     * `$resolved` and detecting cycles via `$resolving` (the current DFS stack).
     *
     * @param array<string, array<string, array<string, mixed>>> $raw
     * @param array<string, array<string, array<string, mixed>>> $resolved
     * @param array<string, bool> $resolving
     */
    private function resolveComponent(string $id, array $raw, array &$resolved, array &$resolving): void
    {
        // Already resolved, either as an earlier root or as someone's dependency.
        if (isset($resolved[Kind::Component->value][$id])) {
            return;
        }

        $spec = $raw[Kind::Component->value][$id] ?? null;
        if ($spec === null) {
            throw KbException::unknownEntity(Kind::Component, $id);
        }

        $parentId = $spec['extends'] ?? null;
        if ($parentId === null) {
            unset($spec['extends']);
            $resolved[Kind::Component->value][$id] = $spec;
            return;
        }

        if (isset($resolving[$id])) {
            throw KbException::circularExtends($id, implode(' -> ', [...array_keys($resolving), $id]));
        }

        if (!isset($raw[Kind::Component->value][$parentId])) {
            throw KbException::unknownEntity(Kind::Component, $parentId);
        }

        $resolving[$id] = true;
        $this->resolveComponent($parentId, $raw, $resolved, $resolving);
        $parentSpec = $resolved[Kind::Component->value][$parentId];

        unset($spec['extends']);
        $resolved[Kind::Component->value][$id] = $this->mergeComponentSpec($parentSpec, $spec);
        unset($resolving[$id]);
    }

    /**
     * @param array<string, mixed> $parent
     * @param array<string, mixed> $child
     * @return array<string, mixed>
     */
    private function mergeComponentSpec(array $parent, array $child): array
    {
        return [
            'mapping'          => $this->mergeMapping($parent['mapping'] ?? [], $child['mapping'] ?? []),
            'traits'           => $this->mergeUniqueList($parent['traits'] ?? [], $child['traits'] ?? []),
            'ports'            => $this->mergePorts($parent['ports'] ?? [], $child['ports'] ?? []),
            'properties'       => $this->mergeById($parent['properties'] ?? [], $child['properties'] ?? []),
            'rules'            => $this->mergeUniqueList($parent['rules'] ?? [], $child['rules'] ?? []),
            'risk_patterns'    => $this->mergeUniqueList($parent['risk_patterns'] ?? [], $child['risk_patterns'] ?? []),
            'hardening_guides' => $this->mergeUniqueList($parent['hardening_guides'] ?? [], $child['hardening_guides'] ?? []),
            // Own metadata always wins — extends only pulls in spec content.
            'metadata'         => $child['metadata'] ?? [],
        ];
    }

    /** @return array<string, mixed> */
    private function mergeMapping(array $parent, array $child): array
    {
        $merged = array_merge($parent, $child);
        if (isset($parent['defaults']) || isset($child['defaults'])) {
            $merged['defaults'] = array_merge((array) ($parent['defaults'] ?? []), (array) ($child['defaults'] ?? []));
        }
        return $merged;
    }

    /** @return array<string, mixed> */
    private function mergePorts(array $parent, array $child): array
    {
        return [
            'inbound' => $this->mergeById($parent['inbound'] ?? [], $child['inbound'] ?? []),
            'outbound' => $this->mergeById($parent['outbound'] ?? [], $child['outbound'] ?? []),
        ];
    }

    /**
     * Merges lists of `{id: ..., ...}` maps: a child item with the same id
     * fully replaces the parent's (§4.3 — "child wins on id collision"),
     * new child ids are appended, parent order is otherwise preserved.
     *
     * @param list<array<string, mixed>> $parent
     * @param list<array<string, mixed>> $child
     * @return list<array<string, mixed>>
     */
    private function mergeById(array $parent, array $child): array
    {
        $byId = [];
        $order = [];
        foreach ($parent as $item) {
            $id = (string) $item['id'];
            $byId[$id] = $item;
            $order[] = $id;
        }
        foreach ($child as $item) {
            $id = (string) $item['id'];
            if (!isset($byId[$id])) {
                $order[] = $id;
            }
            $byId[$id] = $item;
        }
        return array_map(static fn (string $id): array => $byId[$id], $order);
    }

    /**
     * @param list<mixed> $parent
     * @param list<mixed> $child
     * @return list<mixed>
     */
    private function mergeUniqueList(array $parent, array $child): array
    {
        $result = [];
        foreach ([...$parent, ...$child] as $item) {
            $key = is_scalar($item) ? (string) $item : json_encode($item);
            $result[$key] = $item;
        }
        return array_values($result);
    }
}
