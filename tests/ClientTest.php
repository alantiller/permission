<?php declare(strict_types=1);

namespace Alantiller\Permission\Tests;

use Alantiller\Permission\Client;
use Alantiller\Permission\Exceptions\AccessDeniedException;
use Alantiller\Permission\Exceptions\ConfigurationException;
use Alantiller\Permission\Exceptions\DatabaseException;
use Alantiller\Permission\Exceptions\NotFoundException;
use Alantiller\Permission\Exceptions\PolicyException;
use Alantiller\Permission\Exceptions\ValidationException;
use LogicException;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;
use Throwable;

/** Integration coverage runs against the exact application migration SQL in README.md. */
final class ClientTest extends TestCase
{
    /** @var PDO Isolated SQLite connection or explicitly configured MySQL test connection. */
    private PDO $pdo;

    /** @var Client Client configured for this test's tables. */
    private Client $client;

    /** @var array<string, mixed> Table configuration shared by clients in a test. */
    private array $config;

    /** @var array<string, string> Original table names mapped to isolated names. */
    private array $table_names;

    /** @var string SQL schema with this test's isolated table names. */
    private string $schema;

    /** @var bool Whether the test suite is running its optional MySQL backend. */
    private bool $mysql;

    /**
     * Create isolated tables from the migration SQL documented in README.md.
     *
     * The two SQL blocks are ordered MySQL then SQLite, matching alantiller/auth.
     * MySQL tables receive random prefixes; SQLite uses an in-memory database.
     *
     * @return void
     * @throws PDOException If connection or migration execution fails.
     * @throws \PHPUnit\Framework\AssertionFailedError If the documented schemas cannot be loaded.
     * @throws \Alantiller\Permission\Exceptions\ConfigurationException If the test configuration is invalid.
     * @throws DatabaseException If client connection configuration fails.
     */
    protected function setUp(): void
    {
        $dsn = getenv('PERMISSION_TEST_MYSQL_DSN');
        $this->mysql = is_string($dsn) && $dsn !== '';
        $this->pdo = is_string($dsn) && $dsn !== ''
            ? new PDO($dsn, getenv('PERMISSION_TEST_MYSQL_USER') ?: '', getenv('PERMISSION_TEST_MYSQL_PASSWORD') ?: '', [PDO::ATTR_EMULATE_PREPARES => false])
            : new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $prefix = 'ptest_' . bin2hex(random_bytes(6)) . '_';
        $this->table_names = [];
        $this->config = [];
        foreach ([
            'permissions' => 'permissions_table', 'roles' => 'roles_table',
            'role_permissions' => 'role_permissions_table', 'user_roles' => 'user_roles_table',
            'user_permissions' => 'user_permissions_table',
        ] as $table => $key) {
            $this->table_names[$table] = $prefix . $table;
            $this->config[$key] = $prefix . $table;
        }
        $readme = file_get_contents(dirname(__DIR__) . '/README.md');
        self::assertIsString($readme);
        preg_match_all('/```sql\n(.*?)\n```/s', $readme, $matches);
        self::assertCount(2, $matches[1], 'README must document MySQL and SQLite migration SQL.');
        $schema = $matches[1][$this->mysql ? 0 : 1];
        $this->schema = preg_replace_callback('/\b(permissions|roles|role_permissions|user_roles|user_permissions)\b/', fn (array $matches): string => $this->table_names[$matches[0]], $schema) ?? '';
        foreach (explode(';', $this->schema) as $statement) {
            if (trim($statement) !== '') {
                $this->pdo->exec($statement);
            }
        }
        $this->client = new Client($this->pdo, $this->config);
    }

    /** Roll back test-owned work and remove only this test's random table names. @return void */
    protected function tearDown(): void
    {
        if (isset($this->pdo) && $this->pdo->inTransaction()) {
            $this->pdo->rollBack();
        }
        if ($this->mysql && isset($this->table_names)) {
            foreach (array_reverse($this->table_names) as $table) {
                $this->pdo->exec("DROP TABLE IF EXISTS `$table`");
            }
        }
    }

    /** Deny unknown actions and unassigned users; construction creates no tables. @return void */
    public function test_default_denial_and_no_automatic_schema(): void
    {
        self::assertFalse($this->client->can(1, 'documents.read'));
        $this->client->create_permission('documents.read');
        self::assertFalse($this->client->can(1, 'documents.read'));
        self::assertSame([], $this->client->get_permissions_for_user(1));
        self::assertSame([], $this->client->get_roles_for_user(1));
        self::assertFalse($this->client->has_role(1, 'missing'));
        self::assertSame([], $this->client->get_permissions_for_role('missing'));
        $pdo = new PDO('sqlite::memory:');
        $pdo->exec('PRAGMA foreign_keys = ON');
        $empty = new Client($pdo);
        $statement = $pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'");
        self::assertNotFalse($statement);
        self::assertSame(0, (int) $statement->fetchColumn());
        $this->assert_throws(DatabaseException::class, static fn () => $empty->can(1, 'anything'));
    }

    /** Direct allow, deny and removal are idempotent and scoped to a user. @return void */
    public function test_direct_permission_lifecycle(): void
    {
        $client = $this->client;
        $client->create_permission('documents.read');
        $client->grant_permission_to_user(1, 'documents.read');
        $client->grant_permission_to_user(1, 'documents.read');
        self::assertTrue($client->can(1, 'documents.read'));
        self::assertFalse($client->can(2, 'documents.read'));
        self::assertSame(['documents.read'], $client->get_permissions_for_user(1));
        $client->deny_permission_to_user(1, 'documents.read');
        self::assertFalse($client->can(1, 'documents.read'));
        self::assertSame([], $client->get_permissions_for_user(1));
        $client->grant_permission_to_user(1, 'documents.read');
        self::assertTrue($client->can(1, 'documents.read'));
        self::assertTrue($client->revoke_permission_from_user(1, 'documents.read'));
        self::assertFalse($client->revoke_permission_from_user(1, 'documents.read'));
        self::assertFalse($client->can(1, 'documents.read'));
    }

    /** Multiple roles union their grants without duplicates or implicit admin powers. @return void */
    public function test_role_union_and_assignment_removal(): void
    {
        $client = $this->client;
        foreach (['documents.read', 'documents.edit', 'documents.delete'] as $permission) {
            $client->create_permission($permission);
        }
        foreach (['editor', 'reviewer', 'admin'] as $role) {
            $client->create_role($role);
            $client->assign_role(1, $role);
        }
        $client->assign_role(1, 'editor');
        $client->grant_permission_to_role('editor', 'documents.read');
        $client->grant_permission_to_role('editor', 'documents.read');
        $client->grant_permission_to_role('editor', 'documents.edit');
        $client->grant_permission_to_role('reviewer', 'documents.read');
        self::assertSame(['admin', 'editor', 'reviewer'], $client->get_roles_for_user(1));
        self::assertTrue($client->has_role(1, 'editor'));
        self::assertFalse($client->has_role(2, 'editor'));
        self::assertSame(['documents.edit', 'documents.read'], $client->get_permissions_for_user(1));
        self::assertSame(['documents.edit', 'documents.read'], $client->get_permissions_for_role('editor'));
        self::assertFalse($client->can(1, 'documents.delete'));
        self::assertTrue($client->remove_role(1, 'editor'));
        self::assertFalse($client->remove_role(1, 'editor'));
        self::assertFalse($client->can(1, 'documents.edit'));
        self::assertTrue($client->can(1, 'documents.read'));
        self::assertTrue($client->revoke_permission_from_role('reviewer', 'documents.read'));
        self::assertFalse($client->revoke_permission_from_role('reviewer', 'documents.read'));
        self::assertFalse($client->can(1, 'documents.read'));
    }

    /** An explicit denial wins across roles; removing it restores the role grant. @return void */
    public function test_denial_precedence_and_revoke_semantics(): void
    {
        $this->seed_editor();
        $client = $this->client;
        $client->deny_permission_to_user(1, 'documents.edit');
        self::assertFalse($client->can(1, 'documents.edit'));
        $client->create_role('manager');
        $client->grant_permission_to_role('manager', 'documents.edit');
        $client->assign_role(1, 'manager');
        self::assertFalse($client->can(1, 'documents.edit'));
        $client->revoke_permission_from_user(1, 'documents.edit');
        self::assertTrue($client->can(1, 'documents.edit'));
        $client->grant_permission_to_user(1, 'documents.edit');
        $client->remove_role(1, 'editor');
        $client->remove_role(1, 'manager');
        self::assertTrue($client->can(1, 'documents.edit'));
    }

    /** Scoped assignments never inherit from global or another team's assignments. @return void */
    public function test_strict_scope_isolation_and_shared_definitions(): void
    {
        $this->seed_editor();
        $a = new Client($this->pdo, $this->config + ['scope' => 'team:1']);
        $b = new Client($this->pdo, $this->config + ['scope' => 'team:2']);
        self::assertFalse($a->can(1, 'documents.edit'));
        $a->assign_role(1, 'editor');
        self::assertTrue($a->can(1, 'documents.edit'));
        self::assertFalse($b->can(1, 'documents.edit'));
        $a->deny_permission_to_user(1, 'documents.edit');
        self::assertFalse($a->can(1, 'documents.edit'));
        self::assertTrue($this->client->can(1, 'documents.edit'));
        $b->grant_permission_to_user(1, 'documents.edit');
        self::assertTrue($b->can(1, 'documents.edit'));
        $a->remove_role(1, 'editor');
        self::assertTrue($this->client->has_role(1, 'editor'));
        $this->client->create_permission('documents.read');
        $a->grant_permission_to_role('editor', 'documents.read');
        self::assertTrue($this->client->can(1, 'documents.read'));
        $this->client->delete_permission('documents.edit');
        self::assertFalse($b->can(1, 'documents.edit'));
    }

    /** Scope identifiers are exact and preserve case and maximum length. @return void */
    public function test_scope_boundaries(): void
    {
        $this->client->create_permission('read');
        foreach (['A', 'a', str_repeat('a', 128)] as $scope) {
            $client = new Client($this->pdo, $this->config + ['scope' => $scope]);
            self::assertFalse($client->can(1, 'read'));
            $client->grant_permission_to_user(1, 'read');
            self::assertTrue($client->can(1, 'read'));
        }
        self::assertFalse($this->client->can(1, 'read'));
    }

    /** Roles-disabled clients use only the two direct-permission tables. @return void */
    public function test_direct_only_mode_needs_no_role_tables(): void
    {
        foreach (['user_roles', 'role_permissions', 'roles'] as $name) {
            $this->pdo->exec('DROP TABLE ' . $this->table_names[$name]);
        }
        $direct = new Client($this->pdo, $this->config + ['roles_enabled' => false]);
        $direct->create_permission('read');
        $direct->grant_permission_to_user(1, 'read');
        self::assertTrue($direct->can(1, 'read'));
        self::assertSame(['read'], $direct->get_permissions_for_user(1));
        foreach ([
            fn () => $direct->create_role('editor'), fn () => $direct->delete_role('editor'),
            fn () => $direct->get_roles(), fn () => $direct->assign_role(1, 'editor'),
            fn () => $direct->remove_role(1, 'editor'), fn () => $direct->has_role(1, 'editor'),
            fn () => $direct->get_roles_for_user(1), fn () => $direct->get_permissions_for_role('editor'),
            fn () => $direct->grant_permission_to_role('editor', 'read'),
            fn () => $direct->revoke_permission_from_role('editor', 'read'),
        ] as $operation) {
            $this->assert_throws(ConfigurationException::class, $operation);
        }
        $direct->clear_user_assignments(1);
        self::assertFalse($direct->can(1, 'read'));
    }

    /** Policies restrict a grant and are skipped for missing grants and explicit denials. @return void */
    public function test_policy_ownership_and_evaluation_order(): void
    {
        $calls = 0;
        $client = new Client($this->pdo, $this->config + ['policies' => [
            'documents.edit' => static function (int $user_id, array $context) use (&$calls): bool {
                ++$calls;
                return ($context['owner_id'] ?? null) === $user_id;
            },
        ]]);
        self::assertFalse($client->can(1, 'documents.edit', ['owner_id' => 1]));
        self::assertSame(0, $calls);
        $this->seed_editor();
        self::assertFalse($client->can(1, 'documents.edit'));
        self::assertFalse($client->can(1, 'documents.edit', ['owner_id' => 2]));
        self::assertTrue($client->can(1, 'documents.edit', ['owner_id' => 1]));
        self::assertSame(3, $calls);
        self::assertSame(['documents.edit'], $client->get_permissions_for_user(1));
        self::assertSame(3, $calls);
        $client->deny_permission_to_user(1, 'documents.edit');
        self::assertFalse($client->can(1, 'documents.edit', ['owner_id' => 1]));
        self::assertSame(3, $calls);
    }

    /** Truthy values cannot grant access and policy exceptions preserve their identity. @return void */
    public function test_invalid_policy_results_and_failures(): void
    {
        $this->seed_editor();
        foreach ([1, 'yes', null, [], new \stdClass()] as $value) {
            $client = new Client($this->pdo, $this->config + ['policies' => ['documents.edit' => static fn () => $value]]);
            $this->assert_throws(PolicyException::class, fn () => $client->can(1, 'documents.edit'));
        }
        $failure = new LogicException('Policy service unavailable.');
        $client = new Client($this->pdo, $this->config + ['policies' => ['documents.edit' => static fn () => throw $failure]]);
        self::assertSame($failure, $this->assert_throws(LogicException::class, fn () => $client->can(1, 'documents.edit')));
    }

    /** authorize() returns normally on success and emits a context-free denial otherwise. @return void */
    public function test_authorize_and_exception_categories(): void
    {
        $this->seed_editor();
        $this->client->authorize(1, 'documents.edit');
        $exception = $this->assert_throws(AccessDeniedException::class, fn () => $this->client->authorize(2, 'documents.edit', ['secret' => 'private-value']));
        self::assertInstanceOf(AccessDeniedException::class, $exception);
        self::assertSame('access_denied', $exception->error_code);
        self::assertStringNotContainsString('private-value', $exception->getMessage());
    }

    /** Catalogues are sorted and repeated definition creation preserves descriptions. @return void */
    public function test_catalogue_idempotency_and_public_shapes(): void
    {
        $this->client->create_permission('z.read', 'Original');
        $this->client->create_permission('a.read', 'Read records');
        $this->client->create_permission('z.read', 'Replacement ignored');
        self::assertSame([
            ['name' => 'a.read', 'description' => 'Read records'],
            ['name' => 'z.read', 'description' => 'Original'],
        ], $this->client->get_permissions());
        $this->client->create_role('editor', 'Original role');
        $this->client->create_role('editor');
        self::assertSame([['name' => 'editor', 'description' => 'Original role']], $this->client->get_roles());
    }

    /** Missing definitions cause explicit management failures and are never auto-created. @return void */
    public function test_assignments_require_definitions(): void
    {
        foreach ([
            fn () => $this->client->assign_role(1, 'missing'),
            fn () => $this->client->grant_permission_to_user(1, 'missing'),
            fn () => $this->client->deny_permission_to_user(1, 'missing'),
            fn () => $this->client->grant_permission_to_role('missing', 'missing'),
        ] as $operation) {
            $this->assert_throws(NotFoundException::class, $operation);
        }
        $this->client->create_role('editor');
        $this->assert_throws(NotFoundException::class, fn () => $this->client->grant_permission_to_role('editor', 'missing'));
        self::assertSame([], $this->client->get_permissions());
    }

    /** Deleting definitions cascades all links, without leaving grants to revive on recreation. @return void */
    public function test_definition_deletion_cascades(): void
    {
        $this->seed_editor();
        $this->client->grant_permission_to_user(1, 'documents.edit');
        self::assertTrue($this->client->delete_permission('documents.edit'));
        self::assertFalse($this->client->delete_permission('documents.edit'));
        $this->client->create_permission('documents.edit');
        self::assertFalse($this->client->can(1, 'documents.edit'));
        self::assertSame([], $this->client->get_permissions_for_role('editor'));
        $this->client->grant_permission_to_role('editor', 'documents.edit');
        self::assertTrue($this->client->delete_role('editor'));
        self::assertFalse($this->client->delete_role('editor'));
        self::assertSame([], $this->client->get_roles_for_user(1));
        $this->client->create_role('editor');
        self::assertFalse($this->client->can(1, 'documents.edit'));
    }

    /** Scope cleanup removes both assignment sources, preserves other users and scopes, and commits. @return void */
    public function test_scoped_cleanup(): void
    {
        $this->seed_editor();
        $this->client->grant_permission_to_user(1, 'documents.edit');
        $this->client->assign_role(2, 'editor');
        $other = new Client($this->pdo, $this->config + ['scope' => 'other']);
        $other->assign_role(1, 'editor');
        $this->client->clear_user_assignments(1);
        self::assertFalse($this->pdo->inTransaction());
        self::assertFalse($this->client->can(1, 'documents.edit'));
        self::assertTrue($this->client->can(2, 'documents.edit'));
        self::assertTrue($other->can(1, 'documents.edit'));
        $this->client->clear_user_assignments(1);
        self::assertCount(1, $this->client->get_permissions());
    }

    /** Mutations and cleanup participate in the caller's transaction without committing it. @return void */
    public function test_caller_transaction_ownership(): void
    {
        $this->seed_editor();
        $this->pdo->beginTransaction();
        $this->client->clear_user_assignments(1);
        self::assertTrue($this->pdo->inTransaction());
        self::assertFalse($this->client->can(1, 'documents.edit'));
        $this->pdo->rollBack();
        self::assertTrue($this->client->can(1, 'documents.edit'));
        $this->pdo->beginTransaction();
        $this->client->grant_permission_to_user(2, 'documents.edit');
        self::assertTrue($this->pdo->inTransaction());
        $this->pdo->rollBack();
        self::assertFalse($this->client->can(2, 'documents.edit'));
    }

    /** Failed cleanup rolls back its first delete when it owns the transaction. @return void */
    public function test_cleanup_failure_is_atomic(): void
    {
        $this->client->create_permission('read');
        $this->client->grant_permission_to_user(1, 'read');
        $this->pdo->exec('DROP TABLE ' . $this->table_names['user_roles']);
        $this->assert_throws(DatabaseException::class, fn () => $this->client->clear_user_assignments(1));
        self::assertFalse($this->pdo->inTransaction());
        $direct = new Client($this->pdo, $this->config + ['roles_enabled' => false]);
        self::assertTrue($direct->can(1, 'read'));
    }

    /** Failed joined cleanup leaves rollback to the caller rather than ending unrelated work. @return void */
    public function test_cleanup_failure_in_caller_transaction(): void
    {
        $this->client->create_permission('read');
        $this->client->grant_permission_to_user(1, 'read');
        $this->pdo->exec('DROP TABLE ' . $this->table_names['user_roles']);
        $this->pdo->beginTransaction();
        $this->assert_throws(DatabaseException::class, fn () => $this->client->clear_user_assignments(1));
        self::assertTrue($this->pdo->inTransaction());
        $this->pdo->rollBack();
        $direct = new Client($this->pdo, $this->config + ['roles_enabled' => false]);
        self::assertTrue($direct->can(1, 'read'));
    }

    /** Existing clients and fresh instances observe writes rather than a process-local cache. @return void */
    public function test_no_stale_permission_cache(): void
    {
        $this->seed_editor();
        $fresh = new Client($this->pdo, $this->config);
        self::assertTrue($fresh->can(1, 'documents.edit'));
        $fresh->deny_permission_to_user(1, 'documents.edit');
        self::assertFalse($this->client->can(1, 'documents.edit'));
        $this->client->revoke_permission_from_user(1, 'documents.edit');
        self::assertTrue($fresh->can(1, 'documents.edit'));
    }

    /** Invalid configuration is rejected before any permission queries execute. @return void */
    public function test_configuration_validation(): void
    {
        foreach ([
            ['typo' => true], ['roles_enabled' => 1], ['policies' => null],
            ['policies' => ['Read' => static fn (): bool => true]],
            ['policies' => ['read' => 'not_a_callable']], ['policies' => [static fn (): bool => true]],
            ['scope' => ''], ['scope' => 1], ['scope' => ' white space'], ['scope' => str_repeat('a', 129)],
            ['scope' => "a\0b"], ['permissions_table' => 'schema.permissions'],
            ['permissions_table' => 'bad; DROP TABLE roles'], ['permissions_table' => ''],
            ['permissions_table' => str_repeat('a', 65)], ['permissions_table' => null],
            ['roles_table' => $this->config['permissions_table']],
            ['roles_table' => strtoupper((string) $this->config['permissions_table'])],
        ] as $config) {
            $this->assert_throws(ConfigurationException::class, fn () => new Client($this->pdo, array_replace($this->config, $config)));
        }
        $this->assert_throws(ConfigurationException::class, static fn () => new Client(new PDO('sqlite::memory:')));
    }

    /** Canonical names reject SQL-like input, wildcards, whitespace, Unicode and invalid boundaries. @return void */
    public function test_name_and_description_validation(): void
    {
        foreach (['', 'Read', '*', 'documents.*', ' read', 'read ', 'a..b', 'a.', '_read', '1read', 'é', "a\0b", str_repeat('a', 129)] as $name) {
            $this->assert_throws(ValidationException::class, fn () => $this->client->create_permission($name));
            $this->assert_throws(ValidationException::class, fn () => $this->client->can(1, $name));
        }
        foreach (['a', 'documents.read', 'reports:export', 'account_admin', 'site-admin', str_repeat('a', 128)] as $name) {
            $this->client->create_permission($name, str_repeat('a', 1000));
        }
        foreach ([str_repeat('a', 1001), "bad\xFF", "null\0byte"] as $description) {
            $this->assert_throws(ValidationException::class, fn () => $this->client->create_permission('read', $description));
        }
        self::assertCount(6, $this->client->get_permissions());
    }

    /** Positive user IDs include PHP_INT_MAX; zero and negative values are rejected everywhere. @return void */
    public function test_user_id_validation_and_upper_boundary(): void
    {
        foreach ([0, -1] as $id) {
            foreach ([
                fn () => $this->client->can($id, 'read'),
                fn () => $this->client->authorize($id, 'read'),
                fn () => $this->client->grant_permission_to_user($id, 'read'),
                fn () => $this->client->deny_permission_to_user($id, 'read'),
                fn () => $this->client->revoke_permission_from_user($id, 'read'),
                fn () => $this->client->get_permissions_for_user($id),
                fn () => $this->client->assign_role($id, 'editor'),
                fn () => $this->client->remove_role($id, 'editor'),
                fn () => $this->client->has_role($id, 'editor'),
                fn () => $this->client->get_roles_for_user($id),
                fn () => $this->client->clear_user_assignments($id),
            ] as $operation) {
                $this->assert_throws(ValidationException::class, $operation);
            }
        }
        $this->client->create_permission('read');
        $this->client->grant_permission_to_user(PHP_INT_MAX, 'read');
        self::assertTrue($this->client->can(PHP_INT_MAX, 'read'));
    }

    /** Foreign keys reject orphan references and CHECK constraints reject unknown effects. @return void */
    public function test_schema_integrity_constraints(): void
    {
        $this->seed_editor();
        $table = $this->table_names['user_permissions'];
        $this->assert_throws(PDOException::class, fn () => $this->pdo->exec("INSERT INTO $table (user_id, permission_name, scope, effect) VALUES (1, 'missing', '', 'allow')"));
        $this->assert_throws(PDOException::class, fn () => $this->pdo->exec("INSERT INTO $table (user_id, permission_name, scope, effect) VALUES (1, 'documents.edit', '', 'maybe')"));
    }

    /** Database faults retain their PDO cause and cannot be converted into an allow. @return void */
    public function test_database_failure_propagation(): void
    {
        $this->seed_editor();
        $this->pdo->exec('DROP TABLE ' . $this->table_names['user_roles']);
        $failure = $this->assert_throws(DatabaseException::class, fn () => $this->client->can(1, 'documents.edit'));
        self::assertInstanceOf(DatabaseException::class, $failure);
        self::assertSame('database_error', $failure->error_code);
        self::assertInstanceOf(PDOException::class, $failure->getPrevious());
    }

    /** Create an editor and its one permission for a behavior scenario. @return void */
    private function seed_editor(): void
    {
        $this->client->create_permission('documents.edit');
        $this->client->create_role('editor');
        $this->client->grant_permission_to_role('editor', 'documents.edit');
        $this->client->assign_role(1, 'editor');
    }

    /**
     * Assert an expected exception without stopping a multi-case regression test.
     *
     * @param class-string<Throwable> $class Expected exception class or ancestor.
     * @param callable(): mixed $operation One isolated operation expected to fail.
     * @return Throwable The captured exception for further identity or cause assertions.
     */
    private function assert_throws(string $class, callable $operation): Throwable
    {
        try {
            $operation();
        } catch (Throwable $exception) {
            self::assertInstanceOf($class, $exception);
            return $exception;
        }
        self::fail('Expected an exception of type ' . $class);
    }
}
