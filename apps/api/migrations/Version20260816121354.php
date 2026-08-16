<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/** Model version workflow status (T-9.6). */
final class Version20260816121354 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'ModelVersion workflow status (T-9.6)';
    }

    public function up(Schema $schema): void
    {
        $this->addSql("ALTER TABLE model_version ADD status VARCHAR(20) NOT NULL DEFAULT 'draft'");
        $this->addSql('ALTER TABLE model_version ALTER COLUMN status DROP DEFAULT');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('ALTER TABLE model_version DROP status');
    }
}
