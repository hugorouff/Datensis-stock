<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Exception\TableNotFoundException;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/** Garde une API JSON meme si Doctrine / Symfony leve une exception. */
#[AsEventListener(event: KernelEvents::EXCEPTION, priority: 50)]
final class ExtensionApiExceptionSubscriber
{
    public function __construct(private readonly LoggerInterface $logger) {}

    public function __invoke(ExceptionEvent $event): void
    {
        if (!$event->isMainRequest() || !str_starts_with($event->getRequest()->getPathInfo(), '/api/extension/')) {
            return;
        }

        $exception = $event->getThrowable();
        $incident = bin2hex(random_bytes(6));

        if ($exception instanceof TableNotFoundException) {
            $status = 503;
            $message = 'Une table nécessaire à l’extension est absente. Lancez php bin/console app:extension:doctor --repair.';
            $code = 'EXTENSION_SCHEMA_MISSING';
        } elseif ($exception instanceof DbalException) {
            $status = 503;
            $message = 'La base de données est temporairement indisponible. Vérifiez la configuration Doctrine.';
            $code = 'EXTENSION_DATABASE_UNAVAILABLE';
        } elseif ($exception instanceof HttpExceptionInterface) {
            $status = $exception->getStatusCode();
            $message = $status >= 500 ? 'Erreur interne de l’API de l’extension.' : 'Requête refusée par le serveur.';
            $code = 'EXTENSION_HTTP_ERROR';
        } else {
            $status = 500;
            $message = 'Erreur interne de l’API de l’extension. Consultez les logs Symfony.';
            $code = 'EXTENSION_INTERNAL_ERROR';
        }

        // Aucun message d'exception, mot de passe, corps de requete ou jeton dans la reponse.
        if ($status >= 500) {
            $this->logger->error('Datensis Stock extension API incident {incident}', [
                'incident' => $incident,
                'exception' => $exception,
            ]);
        }

        $response = new JsonResponse([
            'error' => $message,
            'code' => $code,
            'incident' => $incident,
        ], $status, [
            'Cache-Control' => 'no-store, private',
            'Pragma' => 'no-cache',
            'X-Content-Type-Options' => 'nosniff',
        ]);
        if ($exception instanceof HttpExceptionInterface) {
            foreach ($exception->getHeaders() as $name => $value) {
                // Ne jamais perdre les en-tetes de securite/cache definis ci-dessus.
                if (!in_array(strtolower($name), ['cache-control', 'pragma', 'content-type', 'x-content-type-options'], true)) {
                    $response->headers->set($name, $value);
                }
            }
        }
        $event->setResponse($response);
    }
}
