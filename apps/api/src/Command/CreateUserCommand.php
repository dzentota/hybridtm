<?php

declare(strict_types=1);

namespace App\Command;

use App\Entity\Tenant;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * Bootstraps accounts and tenants (T-6.10/T-9.1) — there is no self-service
 * registration endpoint by design; account creation is an admin action.
 * Uses the "admin" entity manager (not the RLS-restricted "app" one):
 * this is an operator CLI tool, not a request handler.
 *
 * Deliberately never calls `$em->getRepository(...)` for User/Tenant: both
 * have a `ServiceEntityRepository` registered as a Symfony service, and
 * `EntityManager::getRepository()` resolves those through Doctrine
 * Bundle's `ContainerRepositoryFactory` — which fetches the *shared
 * service instance* from the container, not one bound to `$this->em`.
 * That shared instance resolves its own manager via
 * `ManagerRegistry::getManagerForClass()`, which is ambiguous here (both
 * "app" and "admin" map the same entity classes) and deterministically
 * picks "app" — silently ignoring the admin manager entirely. Plain DQL
 * against `$this->em` has no such indirection.
 */
#[AsCommand(name: 'app:create-user', description: 'Create a user account, creating its tenant if needed')]
final class CreateUserCommand extends Command
{
    public function __construct(
        #[Autowire(service: 'doctrine.orm.admin_entity_manager')]
        private readonly EntityManagerInterface $em,
        private readonly UserPasswordHasherInterface $hasher,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('email', InputArgument::REQUIRED)
            ->addArgument('password', InputArgument::REQUIRED)
            ->addOption('tenant', 't', InputOption::VALUE_REQUIRED, 'Tenant slug (created if it does not exist)', 'default')
            ->addOption('role', 'r', InputOption::VALUE_REQUIRED, 'ROLE_EDITOR or ROLE_ADMIN (ROLE_USER is implicit)', 'ROLE_EDITOR');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $email = (string) $input->getArgument('email');
        $password = (string) $input->getArgument('password');
        $tenantSlug = (string) $input->getOption('tenant');
        $role = (string) $input->getOption('role');

        $existing = $this->em->createQuery('SELECT u FROM App\Entity\User u WHERE u.email = :email')
            ->setParameter('email', $email)
            ->getOneOrNullResult();
        if ($existing !== null) {
            $io->error("A user with email \"{$email}\" already exists.");
            return Command::FAILURE;
        }

        $tenant = $this->em->createQuery('SELECT t FROM App\Entity\Tenant t WHERE t.slug = :slug')
            ->setParameter('slug', $tenantSlug)
            ->getOneOrNullResult();
        if ($tenant === null) {
            $tenant = new Tenant();
            $tenant->slug = $tenantSlug;
            $tenant->name = $tenantSlug;
            $this->em->persist($tenant);
            $io->note("Created tenant \"{$tenantSlug}\".");
        }

        $user = new User();
        $user->tenant = $tenant;
        $user->email = $email;
        $user->roles = [$role];
        $user->password = $this->hasher->hashPassword($user, $password);

        $this->em->persist($user);
        $this->em->flush();

        $io->success("Created user \"{$email}\" in tenant \"{$tenantSlug}\" with roles: " . implode(', ', $user->getRoles()));
        return Command::SUCCESS;
    }
}
