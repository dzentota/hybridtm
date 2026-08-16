<?php

declare(strict_types=1);

namespace App\Controller;

use App\Service\KbProvider;
use HybridTM\Kb\Kind;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * GET /kb/bundle (T-6.2, §7.1): the whole merged knowledge base in one
 * response, for Studio's offline-capable component palette. ETag is the
 * KB's own version() (a content hash — see YamlKbLoader), so a client
 * that already has the current bundle gets a 304 instead of re-downloading
 * every component/threat/rule on every page load.
 */
final class KbController
{
    public function __construct(private readonly KbProvider $kbProvider)
    {
    }

    #[Route('/kb/bundle', name: 'kb_bundle', methods: ['GET'])]
    public function bundle(Request $request): Response
    {
        $kb = $this->kbProvider->get();
        $etag = '"' . $kb->version() . '"';

        if ($request->getETags() !== [] && \in_array($etag, $request->getETags(), true)) {
            return new Response(status: Response::HTTP_NOT_MODIFIED, headers: ['ETag' => $etag]);
        }

        $bundle = [
            'kbVersion' => $kb->version(),
            'traits' => $this->collect($kb, Kind::Trait),
            'components' => $this->collect($kb, Kind::Component),
            'threats' => $this->collect($kb, Kind::Threat),
            'countermeasures' => $this->collect($kb, Kind::Countermeasure),
            'rules' => $this->collect($kb, Kind::Rule),
            'riskPatterns' => $this->collect($kb, Kind::RiskPattern),
            'templates' => $this->collect($kb, Kind::Template),
        ];

        $response = new JsonResponse($bundle);
        $response->setEtag($kb->version());
        $response->setPublic();
        $response->setMaxAge(300);

        return $response;
    }

    /** @return array<string, array<string, mixed>> id => resolved spec */
    private function collect($kb, Kind $kind): array
    {
        $result = [];
        foreach ($kb->ids($kind) as $id) {
            $result[$id] = $kb->get($kind, $id);
        }
        return $result;
    }
}
