<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\User;
use Doctrine\DBAL\Connection;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sets Postgres `app.tenant_id` on the restricted "app" connection for
 * every authenticated request (T-9.1) — the row-level security policies
 * on tenant-scoped tables check this session variable, so a request that
 * never sets it (or sets someone else's tenant) simply sees zero rows,
 * not an application-level 403.
 *
 * Priority is deliberately low (runs late in kernel.request): it must
 * fire after the security firewall has resolved the token, since
 * `Security::getUser()` is what determines the tenant. `getUser()` is
 * called explicitly here (rather than relying on it having "already run")
 * because the "app" firewall is `lazy: true` — the token isn't resolved
 * from the request until something actually asks for it.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: -10)]
final class TenantContextListener
{
    public function __construct(
        private readonly Security $security,
        #[Autowire(service: 'doctrine.dbal.app_connection')]
        private readonly Connection $connection,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $user = $this->security->getUser();
        if (!$user instanceof User || $user->tenant === null) {
            return;
        }

        // set_config() (unlike the SET command) accepts a bound parameter —
        // SET's syntax only takes a literal, so `SET app.tenant_id = ?`
        // is a Postgres syntax error, not something DBAL can parameterize.
        $this->connection->executeStatement(
            "SELECT set_config('app.tenant_id', ?, false)",
            [$user->tenant->getId()->toRfc4122()],
        );
    }
}
