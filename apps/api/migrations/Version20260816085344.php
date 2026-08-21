<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260816085344 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE deep_analysis_result (id UUID NOT NULL, status VARCHAR(20) NOT NULL, findings JSON DEFAULT NULL, error TEXT DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, completed_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, model_version_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_658933AA22832C92 ON deep_analysis_result (model_version_id)');
        $this->addSql('CREATE TABLE model_version (id UUID NOT NULL, schema_version INT NOT NULL, data JSON NOT NULL, layout JSON DEFAULT NULL, kb_version VARCHAR(100) DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, version INT DEFAULT 1 NOT NULL, project_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_DF8FBA32166D1F9C ON model_version (project_id)');
        $this->addSql('CREATE TABLE risk_decision (id UUID NOT NULL, finding_stable_id VARCHAR(64) NOT NULL, status VARCHAR(20) NOT NULL, justification TEXT NOT NULL, ticket VARCHAR(100) DEFAULT NULL, expires_at DATE DEFAULT NULL, decided_by VARCHAR(200) NOT NULL, decided_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, project_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_6285FD27166D1F9C ON risk_decision (project_id)');
        $this->addSql('CREATE UNIQUE INDEX project_finding_unique ON risk_decision (project_id, finding_stable_id)');
        $this->addSql('CREATE TABLE threat_model_project (id UUID NOT NULL, slug VARCHAR(80) NOT NULL, title VARCHAR(200) NOT NULL, description TEXT DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, updated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8DE2CB33989D9B62 ON threat_model_project (slug)');
        $this->addSql('ALTER TABLE deep_analysis_result ADD CONSTRAINT FK_658933AA22832C92 FOREIGN KEY (model_version_id) REFERENCES model_version (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE model_version ADD CONSTRAINT FK_DF8FBA32166D1F9C FOREIGN KEY (project_id) REFERENCES threat_model_project (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE risk_decision ADD CONSTRAINT FK_6285FD27166D1F9C FOREIGN KEY (project_id) REFERENCES threat_model_project (id) ON DELETE CASCADE NOT DEFERRABLE');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE deep_analysis_result DROP CONSTRAINT FK_658933AA22832C92');
        $this->addSql('ALTER TABLE model_version DROP CONSTRAINT FK_DF8FBA32166D1F9C');
        $this->addSql('ALTER TABLE risk_decision DROP CONSTRAINT FK_6285FD27166D1F9C');
        $this->addSql('DROP TABLE deep_analysis_result');
        $this->addSql('DROP TABLE model_version');
        $this->addSql('DROP TABLE risk_decision');
        $this->addSql('DROP TABLE threat_model_project');
    }
}
