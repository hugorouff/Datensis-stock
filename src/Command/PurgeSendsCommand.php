<?php

declare(strict_types=1);

namespace App\Command;

use Doctrine\DBAL\Connection;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'app:purge-expired-sends', description: 'Supprime les Send expires de la base.')]
final class PurgeSendsCommand extends Command
{
    public function __construct(private readonly Connection $connection)
    {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $count = $this->connection->executeStatement(
            'DELETE FROM secure_send WHERE expires_at <= :now',
            ['now'=>(new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s')]
        );
        $output->writeln(sprintf('<info>%d Send expire(s) supprime(s).</info>', $count));
        return Command::SUCCESS;
    }
}
