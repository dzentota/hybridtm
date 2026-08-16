<?php

declare(strict_types=1);

namespace App\Command;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * Bootstraps the first account(s) (T-6.10) — there is no self-service
 * registration endpoint by design; account creation is an admin action.
 */
#[AsCommand(name: 'app:create-user', description: 'Create a user account')]
final class CreateUserCommand extends Command
{
    public function __construct(
        private readonly UserRepository $users,
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
            ->addOption('role', 'r', InputOption::VALUE_REQUIRED, 'ROLE_EDITOR or ROLE_ADMIN (ROLE_USER is implicit)', 'ROLE_EDITOR');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $email = (string) $input->getArgument('email');
        $password = (string) $input->getArgument('password');
        $role = (string) $input->getOption('role');

        if ($this->users->findByEmail($email) !== null) {
            $io->error("A user with email \"{$email}\" already exists.");
            return Command::FAILURE;
        }

        $user = new User();
        $user->email = $email;
        $user->roles = [$role];
        $user->password = $this->hasher->hashPassword($user, $password);

        $this->em->persist($user);
        $this->em->flush();

        $io->success("Created user \"{$email}\" with roles: " . implode(', ', $user->getRoles()));
        return Command::SUCCESS;
    }
}
