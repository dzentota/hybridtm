<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Multi-tenancy + row-level security (T-9.1) and the project-membership
 * RBAC table (T-9.4).
 *
 * Existing rows (this dev database already has users/projects from
 * earlier sessions) are backfilled into a "default" tenant before the
 * tenant_id columns are made NOT NULL — auto-generated diffs don't know
 * to do this, so this migration was hand-edited, not purely generated.
 *
 * RLS is only meaningful against a non-superuser role: Postgres table
 * owners (and superusers) bypass RLS even with FORCE ROW LEVEL SECURITY.
 * The `hybridtm` role created by docker-compose's Postgres image is
 * always a superuser, so this migration creates a second, restricted
 * `hybridtm_app` role with NOBYPASSRLS for the app's runtime connection
 * (config/packages/doctrine.yaml's "app" DBAL connection) to actually
 * use.
 */
final class Version20260816114558 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Multi-tenancy (tenant_id + RLS) and project_membership (T-9.1/T-9.4)';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE tenant (id UUID NOT NULL, slug VARCHAR(80) NOT NULL, name VARCHAR(200) NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_4E59C462989D9B62 ON tenant (slug)');

        // A real deployment provisions the first tenant explicitly; this
        // dev database already has rows from earlier sessions with no
        // tenant concept at all, so give them somewhere to land.
        $this->addSql("INSERT INTO tenant (id, slug, name, created_at) VALUES (gen_random_uuid(), 'default', 'Default Tenant', now())");

        $this->addSql('CREATE TABLE project_membership (id UUID NOT NULL, role VARCHAR(20) NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, project_id UUID NOT NULL, user_id UUID NOT NULL, tenant_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX IDX_9E59A9B7166D1F9C ON project_membership (project_id)');
        $this->addSql('CREATE INDEX IDX_9E59A9B7A76ED395 ON project_membership (user_id)');
        $this->addSql('CREATE INDEX IDX_9E59A9B79033212A ON project_membership (tenant_id)');
        $this->addSql('CREATE UNIQUE INDEX project_user_unique ON project_membership (project_id, user_id)');
        $this->addSql('ALTER TABLE project_membership ADD CONSTRAINT FK_9E59A9B7166D1F9C FOREIGN KEY (project_id) REFERENCES threat_model_project (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE project_membership ADD CONSTRAINT FK_9E59A9B7A76ED395 FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE project_membership ADD CONSTRAINT FK_9E59A9B79033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE');

        foreach (['app_user', 'deep_analysis_result', 'model_version', 'risk_decision', 'threat_model_project'] as $table) {
            $this->addSql("ALTER TABLE {$table} ADD tenant_id UUID");
            $this->addSql("UPDATE {$table} SET tenant_id = (SELECT id FROM tenant WHERE slug = 'default')");
            $this->addSql("ALTER TABLE {$table} ALTER COLUMN tenant_id SET NOT NULL");
        }

        $this->addSql('ALTER TABLE app_user ADD CONSTRAINT FK_88BDF3E99033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('CREATE INDEX IDX_88BDF3E99033212A ON app_user (tenant_id)');
        $this->addSql('ALTER TABLE deep_analysis_result ADD CONSTRAINT FK_658933AA9033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('CREATE INDEX IDX_658933AA9033212A ON deep_analysis_result (tenant_id)');
        $this->addSql('ALTER TABLE model_version ADD CONSTRAINT FK_DF8FBA329033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('CREATE INDEX IDX_DF8FBA329033212A ON model_version (tenant_id)');
        $this->addSql('ALTER TABLE risk_decision ADD CONSTRAINT FK_6285FD279033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('CREATE INDEX IDX_6285FD279033212A ON risk_decision (tenant_id)');
        $this->addSql('ALTER TABLE threat_model_project ADD CONSTRAINT FK_8DE2CB339033212A FOREIGN KEY (tenant_id) REFERENCES tenant (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('CREATE INDEX IDX_8DE2CB339033212A ON threat_model_project (tenant_id)');

        // Restricted runtime role — see class docblock. Idempotent: a
        // re-run migrate (e.g. after a dropped app database in dev) must
        // not fail because the role already exists at the cluster level.
        $this->addSql(<<<'SQL'
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'hybridtm_app') THEN
                    CREATE ROLE hybridtm_app LOGIN PASSWORD 'hybridtm_app' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
                END IF;
            END
            $$;
            SQL);
        $this->addSql('GRANT CONNECT ON DATABASE hybridtm TO hybridtm_app');
        $this->addSql('GRANT USAGE ON SCHEMA public TO hybridtm_app');
        $this->addSql('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hybridtm_app');
        $this->addSql('GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO hybridtm_app');
        $this->addSql('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO hybridtm_app');

        // Row-level security: FORCE makes it apply even to the tables'
        // owning role (the migration-running superuser would otherwise
        // bypass it too when testing manually), though a Postgres
        // superuser always bypasses RLS regardless of FORCE — hence
        // hybridtm_app must never be a superuser.
        foreach (['threat_model_project', 'model_version', 'risk_decision', 'deep_analysis_result', 'project_membership'] as $table) {
            $this->addSql("ALTER TABLE {$table} ENABLE ROW LEVEL SECURITY");
            $this->addSql("ALTER TABLE {$table} FORCE ROW LEVEL SECURITY");
            $this->addSql(<<<SQL
                CREATE POLICY tenant_isolation ON {$table}
                    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)
                SQL);
        }
    }

    public function down(Schema $schema): void
    {
        foreach (['threat_model_project', 'model_version', 'risk_decision', 'deep_analysis_result', 'project_membership'] as $table) {
            $this->addSql("DROP POLICY IF EXISTS tenant_isolation ON {$table}");
            $this->addSql("ALTER TABLE {$table} NO FORCE ROW LEVEL SECURITY");
            $this->addSql("ALTER TABLE {$table} DISABLE ROW LEVEL SECURITY");
        }

        $this->addSql('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM hybridtm_app');
        $this->addSql('DROP ROLE IF EXISTS hybridtm_app');

        $this->addSql('ALTER TABLE project_membership DROP CONSTRAINT FK_9E59A9B7166D1F9C');
        $this->addSql('ALTER TABLE project_membership DROP CONSTRAINT FK_9E59A9B7A76ED395');
        $this->addSql('ALTER TABLE project_membership DROP CONSTRAINT FK_9E59A9B79033212A');
        $this->addSql('DROP TABLE project_membership');

        foreach (['app_user', 'deep_analysis_result', 'model_version', 'risk_decision', 'threat_model_project'] as $table) {
            $this->addSql("ALTER TABLE {$table} DROP COLUMN tenant_id");
        }

        $this->addSql('DROP TABLE tenant');
    }
}
