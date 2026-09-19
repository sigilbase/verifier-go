<?php

declare(strict_types=1);

/**
 * Builds a large format 1.1 bundle for the memory ceiling check, streaming
 * events to disk so the generator itself stays small: the Go verifier must
 * complete a 1,000,000-event bundle in under 128 MiB of resident memory.
 *
 *   php tools/build-large-bundle.php <events> <events-per-checkpoint> <out.zip>
 *
 * The bundle is signed with a fresh key; the matching --keys file is written
 * beside the archive as <out.zip>.keys.json. The construction is the one
 * the verifier repository's tests/FixtureGenerator.php uses (its writeBundle holds every event in
 * memory, which is what this script avoids).
 */
require_once __DIR__.'/../reference/verify.php';

if ($argc !== 4) {
    fwrite(STDERR, "usage: php tools/build-large-bundle.php <events> <events-per-checkpoint> <out.zip>\n");
    exit(2);
}

[$eventCount, $perCheckpoint, $zipPath] = [(int) $argv[1], (int) $argv[2], $argv[3]];
$zero = str_repeat('0', 64);

$keypair = sodium_crypto_sign_keypair();
$secretKey = sodium_crypto_sign_secretkey($keypair);
$publicKeyHex = bin2hex(sodium_crypto_sign_publickey($keypair));
$streamId = '019b7ca9-8c88-7f00-8000-0000000000ff';

$work = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-large-'.bin2hex(random_bytes(4));
mkdir($work, 0755, true);

$events = fopen($work.DIRECTORY_SEPARATOR.'events.ndjson', 'wb');
$prevHash = $zero;
$checkpoints = [];
$prevCheckpointHash = $zero;
$chunk = [];

for ($sequence = 1; $sequence <= $eventCount; $sequence++) {
    $payload = (object) ['n' => $sequence];
    $payloadHash = hash('sha256', canonical_encode($payload));
    $occurredAt = sprintf('2026-07-01T09:%02d:%02d.000000Z', intdiv($sequence, 60) % 60, $sequence % 60);
    $receivedAt = $occurredAt;

    $entryHash = hash('sha256', canonical_encode((object) [
        'v' => 1,
        'stream' => $streamId,
        'seq' => $sequence,
        'occurred_at' => $occurredAt,
        'received_at' => $receivedAt,
        'actor' => 'user:1',
        'action' => 'record.updated',
        'resource' => null,
        'payload_hash' => $payloadHash,
        'prev' => $prevHash,
    ]));

    fwrite($events, canonical_encode((object) [
        'v' => 1,
        'seq' => $sequence,
        'occurred_at' => $occurredAt,
        'received_at' => $receivedAt,
        'actor' => 'user:1',
        'action' => 'record.updated',
        'resource' => null,
        'payload' => $payload,
        'payload_hash' => $payloadHash,
        'prev_hash' => $prevHash,
        'entry_hash' => $entryHash,
    ])."\n");

    $chunk[] = (string) hex2bin($entryHash);
    $prevHash = $entryHash;

    if (count($chunk) === $perCheckpoint || $sequence === $eventCount) {
        $from = $sequence - count($chunk) + 1;
        $root = bin2hex(merkle_root($chunk));
        $createdAt = sprintf('2026-07-01T10:%02d:%02d.000000Z', intdiv(count($checkpoints), 60) % 60, count($checkpoints) % 60);

        $checkpointHash = hash('sha256', canonical_encode((object) [
            'v' => 1,
            'stream' => $streamId,
            'from' => $from,
            'to' => $sequence,
            'root' => $root,
            'prev_checkpoint' => $prevCheckpointHash,
            'created_at' => $createdAt,
        ]));

        $checkpoints[] = (object) [
            'v' => 1,
            'stream' => $streamId,
            'from' => $from,
            'to' => $sequence,
            'root' => $root,
            'prev_checkpoint' => $prevCheckpointHash,
            'created_at' => $createdAt,
            'checkpoint_hash' => $checkpointHash,
            'signature' => bin2hex(sodium_crypto_sign_detached((string) hex2bin($checkpointHash), $secretKey)),
            'public_key' => $publicKeyHex,
        ];

        $prevCheckpointHash = $checkpointHash;
        $chunk = [];
    }
}

fclose($events);

file_put_contents($work.DIRECTORY_SEPARATOR.'manifest.json', json_encode([
    'format' => 'sigilbase-evidence/1.1',
    'generated_at' => '2026-07-01T11:00:00.000000Z',
    'stream' => ['id' => $streamId, 'slug' => 'large-stream', 'name' => 'Large stream'],
    'range' => ['from' => 1, 'to' => $eventCount],
    'event_count' => $eventCount,
    'signing_keys' => [
        ['public_key' => $publicKeyHex, 'created_at' => '2026-01-01T00:00:00.000000Z', 'retired_at' => null],
    ],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

file_put_contents($work.DIRECTORY_SEPARATOR.'checkpoints.json', json_encode(['checkpoints' => $checkpoints], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

$zip = new ZipArchive;

if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "could not create [{$zipPath}]\n");
    exit(2);
}

foreach (['manifest.json', 'events.ndjson', 'checkpoints.json'] as $file) {
    $zip->addFile($work.DIRECTORY_SEPARATOR.$file, $file);
}

$zip->close();

file_put_contents($zipPath.'.keys.json', json_encode(['keys' => [[
    'key_id' => substr(hash('sha256', (string) hex2bin($publicKeyHex)), 0, 16),
    'public_key' => $publicKeyHex,
    'algorithm' => 'ed25519',
    'created_at' => '2026-01-01T00:00:00.000000Z',
    'retired_at' => null,
]]], JSON_PRETTY_PRINT));

foreach (['manifest.json', 'events.ndjson', 'checkpoints.json'] as $file) {
    unlink($work.DIRECTORY_SEPARATOR.$file);
}

rmdir($work);

echo "wrote {$zipPath} ({$eventCount} events, ".count($checkpoints)." checkpoints) and {$zipPath}.keys.json\n";
