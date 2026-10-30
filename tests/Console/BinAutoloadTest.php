<?php

declare(strict_types=1);

namespace HybridTM\Tests\Console;

use PHPUnit\Framework\TestCase;

/** bin/hybridtm must find the autoloader when installed as a Composer dependency. */
final class BinAutoloadTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/hybridtm-bin-' . bin2hex(random_bytes(4));
        mkdir($this->tmp . '/vendor/dzentota/hybridtm/bin', 0o777, true);
        copy(dirname(__DIR__, 2) . '/bin/hybridtm', $this->tmp . '/vendor/dzentota/hybridtm/bin/hybridtm');
        file_put_contents(
            $this->tmp . '/vendor/autoload.php',
            '<?php return require ' . var_export(dirname(__DIR__, 2) . '/vendor/autoload.php', true) . ';',
        );
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmp));
    }

    public function testRunsFromVendorLayout(): void
    {
        exec(PHP_BINARY . ' ' . escapeshellarg($this->tmp . '/vendor/dzentota/hybridtm/bin/hybridtm') . ' --version 2>&1', $out, $code);
        self::assertSame(0, $code, implode("\n", $out));
        self::assertStringContainsString('HybridTM', implode("\n", $out));
    }

    public function testUsesComposerAutoloadPathGlobal(): void
    {
        $proxy = $this->tmp . '/proxy.php';
        file_put_contents($proxy, '<?php $GLOBALS[\'_composer_autoload_path\'] = ' . var_export($this->tmp . '/vendor/autoload.php', true) . ';'
            . ' include ' . var_export($this->tmp . '/vendor/dzentota/hybridtm/bin/hybridtm', true) . ';');
        // Move the real bin somewhere with no autoload nearby to prove the global is used.
        mkdir($this->tmp . '/isolated/a/b/bin', 0o777, true);
        rename($this->tmp . '/vendor/dzentota/hybridtm/bin/hybridtm', $this->tmp . '/isolated/a/b/bin/hybridtm');
        file_put_contents($proxy, str_replace('vendor/dzentota/hybridtm/bin', 'isolated/a/b/bin', (string) file_get_contents($proxy)));
        exec(PHP_BINARY . ' ' . escapeshellarg($proxy) . ' --version 2>&1', $out, $code);
        self::assertSame(0, $code, implode("\n", $out));
        self::assertStringContainsString('HybridTM', implode("\n", $out));
    }
}
