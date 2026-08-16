<?php

declare(strict_types=1);

namespace App\Report;

use Dompdf\Dompdf;
use Dompdf\Options;

/**
 * Renders a ReportData as a PDF (T-10.2) via Dompdf — an HTML template
 * rendered to PDF, not a scanned image, so text stays selectable/
 * searchable. Sections match the plan's spec: title, summary, DFD, risk
 * register, countermeasures, standards appendix. The DFD section is a
 * text-based component/flow listing rather than a rendered diagram — no
 * Graphviz/Mermaid renderer is available in this environment; the
 * mermaid/dot export endpoint (T-10.4) is the actual diagram, and a real
 * deployment would embed its rendered SVG here instead.
 */
final class PdfReportGenerator
{
    public function generate(ReportData $data): string
    {
        $options = new Options();
        $options->set('isRemoteEnabled', false);
        $options->set('isHtml5ParserEnabled', true);

        $dompdf = new Dompdf($options);
        $dompdf->loadHtml($this->html($data));
        $dompdf->setPaper('A4', 'portrait');
        $dompdf->render();

        return $dompdf->output();
    }

    private function html(ReportData $data): string
    {
        $e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

        $summaryRows = '';
        foreach ($data->result->countsBySeverity() as $severity => $count) {
            $summaryRows .= "<tr><td>{$e($severity)}</td><td>{$count}</td></tr>";
        }

        $componentRows = '';
        foreach ($data->model->getTechnicalAssets() as $id => $asset) {
            $componentRows .= '<tr><td>' . $e($id) . '</td><td>' . $e($asset->name) . '</td></tr>';
        }
        $flowRows = '';
        foreach ($data->model->getTechnicalAssets() as $sourceId => $asset) {
            foreach ($asset->communicationLinks as $link) {
                $flowRows .= '<tr><td>' . $e($sourceId) . '</td><td>' . $e($link->targetAssetId) . '</td><td>' . $e($link->protocol->value) . '</td></tr>';
            }
        }

        $findingRows = '';
        $countermeasureIds = [];
        $cweIds = [];
        foreach ($data->result->findings as $finding) {
            $findingRows .= '<tr><td>' . $e($finding->severity->value) . '</td><td>' . $e($finding->threatId) . '</td>'
                . '<td>' . $e((string) $finding->subject) . '</td><td>' . $e($finding->title) . '</td></tr>';
            foreach ($finding->countermeasureIds as $cmId) {
                $countermeasureIds[$cmId] = true;
            }
            foreach ($finding->standards->cwe as $cwe) {
                $cweIds[$cwe] = true;
            }
        }

        $countermeasureItems = implode('', array_map(
            static fn (string $id): string => '<li>' . $e($id) . '</li>',
            array_keys($countermeasureIds),
        ));
        $cweItems = implode('', array_map(
            static fn (int $cwe): string => "<li>CWE-{$cwe}</li>",
            array_keys($cweIds),
        ));

        $generatedAt = $e($data->generatedAt->format('Y-m-d H:i:s'));

        return <<<HTML
            <html>
            <head><style>
                body { font-family: sans-serif; font-size: 11px; }
                h1 { font-size: 22px; } h2 { font-size: 16px; margin-top: 24px; }
                table { width: 100%; border-collapse: collapse; margin-top: 8px; }
                th, td { border: 1px solid #ccc; padding: 4px 6px; text-align: left; }
                th { background: #eee; }
                .cover { text-align: center; margin-top: 120px; }
            </style></head>
            <body>
                <div class="cover">
                    <h1>Threat Model Report</h1>
                    <p><strong>{$e($data->projectTitle)}</strong> &mdash; {$e($data->modelTitle)}</p>
                    <p>Generated {$generatedAt}</p>
                </div>
                <div style="page-break-before: always;">
                    <h2>Summary</h2>
                    <table><tr><th>Severity</th><th>Count</th></tr>{$summaryRows}</table>

                    <h2>Data Flow Diagram (text)</h2>
                    <p>Components:</p>
                    <table><tr><th>ID</th><th>Name</th></tr>{$componentRows}</table>
                    <p>Data flows:</p>
                    <table><tr><th>Source</th><th>Target</th><th>Protocol</th></tr>{$flowRows}</table>

                    <h2>Risk Register</h2>
                    <table><tr><th>Severity</th><th>Threat</th><th>Subject</th><th>Title</th></tr>{$findingRows}</table>

                    <h2>Countermeasures</h2>
                    <ul>{$countermeasureItems}</ul>

                    <h2>Standards Appendix</h2>
                    <ul>{$cweItems}</ul>
                </div>
            </body>
            </html>
            HTML;
    }
}
