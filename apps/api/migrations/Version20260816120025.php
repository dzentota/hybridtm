<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/** Audit log table (T-9.5) — RLS-isolated like every other tenant-scoped table. */
final class Version20260816120025 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Audit log (T-9.5)';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE audit_log_entry (id UUID NOT NULL, actor_email VARCHAR(180) DEFAULT NULL, action VARCHAR(20) NOT NULL, entity_type VARCHAR(100) NOT NULL, entity_id UUID NOT NULL, patch JSON NOT NULL, ip_address VARCHAR(45) DEFAULT NULL, occurred_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_D2D938A29033212A ON audit_log_entry (tenant_id)');
        $this->addSql('ALTER TABLE audit_log_entry ADD CONSTRAINT FK_D2D938A29033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE');

        // ALTER DEFAULT PRIVILEGES from the T-9.1 migration already granted
        // SELECT/INSERT/UPDATE/DELETE on this new table; revoke UPDATE/
        // DELETE so "append-only" is enforced at the database privilege
        // level too, not just by this table's read-only ApiResource.
        $this->addSql('REVOKE UPDATE, DELETE ON audit_log_entry FROM hybridtm_app');
        $this->addSql('ALTER TABLE audit_log_entry ENABLE ROW LEVEL SECURITY');
        $this->addSql('ALTER TABLE audit_log_entry FORCE ROW LEVEL SECURITY');
        $this->addSql(<<<'SQL'
            CREATE POLICY tenant_isolation ON audit_log_entry
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)
            SQL);
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP POLICY IF EXISTS tenant_isolation ON audit_log_entry');
        $this->addSql('ALTER TABLE audit_log_entry NO FORCE ROW LEVEL SECURITY');
        $this->addSql('ALTER TABLE audit_log_entry DISABLE ROW LEVEL SECURITY');
        $this->addSql('ALTER TABLE audit_log_entry DROP CONSTRAINT FK_D2D938A29033212A');
        $this->addSql('DROP TABLE audit_log_entry');
    }
}
