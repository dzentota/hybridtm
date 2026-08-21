<?php

declare(strict_types=1);

namespace App\Report;

use PhpOffice\PhpWord\IOFactory;
use PhpOffice\PhpWord\PhpWord;

/** Renders a ReportData as a DOCX (T-10.3) via PhpWord — opens cleanly in Word, same sections as the PDF report. */
final class DocxReportGenerator
{
    public function generate(ReportData $data): string
    {
        $phpWord = new PhpWord();
        $section = $phpWord->addSection();

        $section->addTitle('Threat Model Report', 1);
        $section->addText("{$data->projectTitle} — {$data->modelTitle}", ['bold' => true]);
        $section->addText('Generated ' . $data->generatedAt->format('Y-m-d H:i:s'));

        $section->addTitle('Summary', 2);
        $summaryTable = $section->addTable(['borderSize' => 6, 'borderColor' => 'CCCCCC']);
        $summaryTable->addRow();
        $summaryTable->addCell(4000)->addText('Severity', ['bold' => true]);
        $summaryTable->addCell(2000)->addText('Count', ['bold' => true]);
        foreach ($data->result->countsBySeverity() as $severity => $count) {
            $summaryTable->addRow();
            $summaryTable->addCell(4000)->addText($severity);
            $summaryTable->addCell(2000)->addText((string) $count);
        }

        $section->addTitle('Data Flow Diagram (text)', 2);
        $section->addText('Components:');
        $componentsTable = $section->addTable(['borderSize' => 6, 'borderColor' => 'CCCCCC']);
        $componentsTable->addRow();
        $componentsTable->addCell(3000)->addText('ID', ['bold' => true]);
        $componentsTable->addCell(5000)->addText('Name', ['bold' => true]);
        foreach ($data->model->getTechnicalAssets() as $id => $asset) {
            $componentsTable->addRow();
            $componentsTable->addCell(3000)->addText($id);
            $componentsTable->addCell(5000)->addText($asset->name);
        }

        $section->addText('Data flows:');
        $flowsTable = $section->addTable(['borderSize' => 6, 'borderColor' => 'CCCCCC']);
        $flowsTable->addRow();
        $flowsTable->addCell(2500)->addText('Source', ['bold' => true]);
        $flowsTable->addCell(2500)->addText('Target', ['bold' => true]);
        $flowsTable->addCell(3000)->addText('Protocol', ['bold' => true]);
        foreach ($data->model->getTechnicalAssets() as $sourceId => $asset) {
            foreach ($asset->communicationLinks as $link) {
                $flowsTable->addRow();
                $flowsTable->addCell(2500)->addText($sourceId);
                $flowsTable->addCell(2500)->addText($link->targetAssetId);
                $flowsTable->addCell(3000)->addText($link->protocol->value);
            }
        }

        $section->addTitle('Risk Register', 2);
        $risksTable = $section->addTable(['borderSize' => 6, 'borderColor' => 'CCCCCC']);
        $risksTable->addRow();
        foreach (['Severity', 'Threat', 'Subject', 'Title'] as $header) {
            $risksTable->addCell(2500)->addText($header, ['bold' => true]);
        }
        $countermeasureIds = [];
        $cweIds = [];
        foreach ($data->result->findings as $finding) {
            $risksTable->addRow();
            $risksTable->addCell(2500)->addText($finding->severity->value);
            $risksTable->addCell(2500)->addText($finding->threatId);
            $risksTable->addCell(2500)->addText((string) $finding->subject);
            $risksTable->addCell(2500)->addText($finding->title);
            foreach ($finding->countermeasureIds as $cmId) {
                $countermeasureIds[$cmId] = true;
            }
            foreach ($finding->standards->cwe as $cwe) {
                $cweIds[$cwe] = true;
            }
        }

        $section->addTitle('Countermeasures', 2);
        foreach (array_keys($countermeasureIds) as $id) {
            $section->addListItem($id);
        }

        $section->addTitle('Standards Appendix', 2);
        foreach (array_keys($cweIds) as $cwe) {
            $section->addListItem("CWE-{$cwe}");
        }

        $tmpPath = tempnam(sys_get_temp_dir(), 'hybridtm-report-') . '.docx';
        IOFactory::createWriter($phpWord, 'Word2007')->save($tmpPath);
        $bytes = file_get_contents($tmpPath);
        unlink($tmpPath);

        return $bytes;
    }
}
