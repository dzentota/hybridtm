<?php

declare(strict_types=1);

namespace App\Security;

use App\Repository\ApiTokenRepository;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Single authenticator for every `Authorization: Bearer ...` request
 * (T-6.10) — deliberately one authenticator, not two competing ones.
 * Symfony's AuthenticatorManager runs every authenticator whose supports()
 * returns true and lets the *last* one that produces a response win, so a
 * separate lexik `jwt: ~` authenticator plus a separate ApiToken
 * authenticator on the same firewall would both "support" any Bearer
 * header (lexik's own supports() doesn't check the token's shape) and the
 * JWT authenticator's inevitable parse failure on an ApiToken value would
 * clobber a perfectly valid ApiToken authentication that had already
 * succeeded. Branching on the `htm_` prefix inside one authenticator
 * avoids that collision entirely.
 */
final class BearerTokenAuthenticator extends AbstractAuthenticator
{
    private const API_TOKEN_PREFIX = 'htm_';

    public function __construct(
        private readonly ApiTokenRepository $tokens,
        private readonly JWTTokenManagerInterface $jwtManager,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return str_starts_with($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $token = substr($request->headers->get('Authorization', ''), \strlen('Bearer '));

        if (str_starts_with($token, self::API_TOKEN_PREFIX)) {
            return $this->authenticateApiToken($token);
        }

        return $this->authenticateJwt($token);
    }

    private function authenticateApiToken(string $token): Passport
    {
        $apiToken = $this->tokens->findByHash(hash('sha256', $token));
        if ($apiToken === null || $apiToken->isExpired()) {
            throw new AuthenticationException('Invalid or expired API token.');
        }

        return new SelfValidatingPassport(new UserBadge($apiToken->user->getUserIdentifier()));
    }

    private function authenticateJwt(string $token): Passport
    {
        try {
            $payload = $this->jwtManager->parse($token);
        } catch (\Throwable $e) {
            throw new AuthenticationException('Invalid JWT token.', 0, $e);
        }

        $identifier = $payload[$this->jwtManager->getUserIdClaim()] ?? null;
        if (!\is_string($identifier) || $identifier === '') {
            throw new AuthenticationException('JWT token payload has no user identifier claim.');
        }

        return new SelfValidatingPassport(new UserBadge($identifier));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new JsonResponse(['error' => $exception->getMessage()], Response::HTTP_UNAUTHORIZED);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }
}
