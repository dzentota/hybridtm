<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260817150439 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // Slug uniqueness moves from global to per-tenant: every tenant's
        // Studio client bootstraps its demo project via the same hardcoded
        // 'studio-demo' slug, and reads are RLS-scoped per tenant, so a
        // global unique index let the first tenant silently block every
        // other tenant from ever creating that project (500 on insert).
        $this->addSql('DROP INDEX uniq_8de2cb33989d9b62');
        $this->addSql('CREATE UNIQUE INDEX uniq_tenant_slug ON threat_model_project (tenant_id, slug)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP INDEX uniq_tenant_slug');
        $this->addSql('CREATE UNIQUE INDEX uniq_8de2cb33989d9b62 ON threat_model_project (slug)');
    }
}
