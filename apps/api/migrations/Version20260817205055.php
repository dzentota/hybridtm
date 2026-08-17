<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260817205055 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'model_template (save-as-template)';
    }

    public function up(Schema $schema): void
    {
        // NOTE: `doctrine:migrations:diff` also emitted a spurious
        // `DROP INDEX uniq_tenant_slug` here — a pre-existing, unrelated
        // schema-comparator drift against threat_model_project's composite
        // unique constraint (Version20260817150439), not anything to do
        // with this table. Deliberately dropped from this migration:
        // running it would have silently reintroduced the cross-tenant
        // slug-collision bug that constraint exists to prevent.
        $this->addSql(<<<'SQL'
            CREATE TABLE model_template (
              id UUID NOT NULL,
              name VARCHAR(200) NOT NULL,
              description TEXT DEFAULT NULL,
              data JSON NOT NULL,
              layout JSON DEFAULT NULL,
              created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL,
              tenant_id UUID NOT NULL,
              PRIMARY KEY (id)
            )
        SQL);
        $this->addSql('CREATE INDEX IDX_5DBA4E609033212A ON model_template (tenant_id)');
        $this->addSql(<<<'SQL'
            ALTER TABLE
              model_template
            ADD
              CONSTRAINT FK_5DBA4E609033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE
        SQL);

        // RLS-isolated like every other tenant-scoped table.
        $this->addSql('ALTER TABLE model_template ENABLE ROW LEVEL SECURITY');
        $this->addSql('ALTER TABLE model_template FORCE ROW LEVEL SECURITY');
        $this->addSql(<<<'SQL'
            CREATE POLICY tenant_isolation ON model_template
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)
            SQL);
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP POLICY IF EXISTS tenant_isolation ON model_template');
        $this->addSql('ALTER TABLE model_template NO FORCE ROW LEVEL SECURITY');
        $this->addSql('ALTER TABLE model_template DISABLE ROW LEVEL SECURITY');
        $this->addSql('ALTER TABLE model_template DROP CONSTRAINT FK_5DBA4E609033212A');
        $this->addSql('DROP TABLE model_template');
    }
}
