<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\ApiToken;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * POST /api-tokens (T-6.10): mints a long-lived API token for the caller's
 * own account. The plaintext token is generated here and returned exactly
 * once in this response body — only its SHA-256 hash is persisted, so a
 * lost token cannot be recovered, only revoked (DELETE) and replaced.
 */
final class ApiTokenController
{
    public function __construct(
        private readonly Security $security,
        private readonly EntityManagerInterface $em,
    ) {
    }

    #[Route('/api-tokens', name: 'api_token_create', methods: ['POST'])]
    #[IsGranted('ROLE_USER')]
    public function __invoke(Request $request): Response
    {
        /** @var User $user */
        $user = $this->security->getUser();

        $payload = json_decode($request->getContent(), true) ?? [];
        $label = \is_string($payload['label'] ?? null) ? $payload['label'] : 'unlabeled';

        $plaintext = 'htm_' . bin2hex(random_bytes(32));

        $token = new ApiToken($user);
        $token->label = $label;
        $token->tokenHash = hash('sha256', $plaintext);

        $this->em->persist($token);
        $this->em->flush();

        return new JsonResponse([
            'id' => $token->getId()->toRfc4122(),
            'label' => $token->label,
            'token' => $plaintext,
            'createdAt' => $token->createdAt->format(\DateTimeInterface::ATOM),
        ], Response::HTTP_CREATED);
    }
}
