<?php

declare(strict_types=1);

namespace App\Report;

use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;

/**
 * Renders a ReportData as an XLSX risk register (T-10.3) — one sheet per
 * register/countermeasures, both plain data tables so a risk owner can
 * filter/pivot in Excel rather than just read a static PDF.
 */
final class XlsxReportGenerator
{
    public function generate(ReportData $data): string
    {
        $spreadsheet = new Spreadsheet();

        $risks = $spreadsheet->getActiveSheet();
        $risks->setTitle('Risk Register');
        $rows = [['Severity', 'Threat ID', 'Subject', 'Title', 'Likelihood', 'Impact', 'Countermeasures', 'CWE']];
        foreach ($data->result->findings as $finding) {
            $rows[] = [
                $finding->severity->value,
                $finding->threatId,
                (string) $finding->subject,
                $finding->title,
                $finding->likelihood->value,
                $finding->impact->value,
                implode(', ', $finding->countermeasureIds),
                implode(', ', array_map(static fn (int $c): string => "CWE-{$c}", $finding->standards->cwe)),
            ];
        }
        $risks->fromArray($rows, null, 'A1');
        foreach (range('A', 'H') as $col) {
            $risks->getColumnDimension($col)->setAutoSize(true);
        }

        $countermeasures = $spreadsheet->createSheet();
        $countermeasures->setTitle('Countermeasures');
        $countermeasureIds = [];
        foreach ($data->result->findings as $finding) {
            foreach ($finding->countermeasureIds as $cmId) {
                $countermeasureIds[$cmId] = ($countermeasureIds[$cmId] ?? 0) + 1;
            }
        }
        $cmRows = [['Countermeasure', 'Findings resolved']];
        foreach ($countermeasureIds as $id => $count) {
            $cmRows[] = [$id, $count];
        }
        $countermeasures->fromArray($cmRows, null, 'A1');
        foreach (range('A', 'B') as $col) {
            $countermeasures->getColumnDimension($col)->setAutoSize(true);
        }

        $spreadsheet->setActiveSheetIndex(0);

        $tmpPath = tempnam(sys_get_temp_dir(), 'hybridtm-report-') . '.xlsx';
        (new Xlsx($spreadsheet))->save($tmpPath);
        $bytes = file_get_contents($tmpPath);
        unlink($tmpPath);

        return $bytes;
    }
}
