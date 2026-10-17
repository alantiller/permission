<?php declare(strict_types=1);

namespace Alantiller;

use Alantiller\Permission\Exceptions\AccessDeniedException;
use Alantiller\Permission\Exceptions\ConfigurationException;
use Alantiller\Permission\Exceptions\DatabaseException;
use Alantiller\Permission\Exceptions\NotFoundException;
use Alantiller\Permission\Exceptions\PolicyException;
use Alantiller\Permission\Exceptions\ValidationException;
use PDO;
use PDOException;
use PDOStatement;
use Throwable;

/**
 * Check explicit user grants, optional role grants and optional PHP policies.
 *
 * Denials override grants. Assignments belong to exactly one configured scope;
 * definitions and role-permission links are shared. The application owns users,
 * authentication, schema migrations and authorization of all management calls.
 * No current user or permission-result cache is retained.
 */
final class Permission
{
    /** @var PDO Application-owned connection, shared with its transaction boundaries. */
    private PDO $pdo;

    /** @var string Supported SQL dialect: mysql or sqlite. */
    private string $driver;

    /** @var array<string, string> Validated and quoted table identifiers. */
    private array $tables = [];

    /** @var bool Whether role APIs and role-based checks are enabled. */
    private bool $roles_enabled;

    /** @var string Empty string represents the global scope in the database. */
    private string $scope;

    /** @var array<string, callable(int, array<string, mixed>): mixed> Unchecked application callbacks; can() requires boolean results. */
    private array $policies;

    /**
     * Configure the permission service without creating tables or loading any user.
     *
     * Sets PDO error mode to exceptions. SQLite must already have foreign keys
     * enabled; MySQL tables must use InnoDB and the supplied constraints.
     * See README for all supported options. Unknown options are rejected.
     *
     * @param PDO $pdo Existing connection using pdo_mysql or pdo_sqlite.
     * @param array<string, mixed> $config Optional table names, roles_enabled, scope and policies.
     * @throws ConfigurationException If any option, driver or SQLite foreign-key setting is invalid.
     * @throws DatabaseException If PDO configuration fails.
     */
    public function __construct(PDO $pdo, array $config = [])
    {
        $defaults = [
            'permissions_table' => 'permissions',
            'roles_table' => 'roles',
            'role_permissions_table' => 'role_permissions',
            'user_roles_table' => 'user_roles',
            'user_permissions_table' => 'user_permissions',
            'roles_enabled' => true,
            'scope' => null,
            'policies' => [],
        ];
        if (array_diff_key($config, $defaults) !== []) {
            throw new ConfigurationException('Unknown configuration option.');
        }
        $config = array_replace($defaults, $config);
        if (!is_bool($config['roles_enabled'])) {
            throw new ConfigurationException('roles_enabled must be a boolean.');
        }
        if ($config['scope'] !== null && (!is_string($config['scope'])
            || preg_match('/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/D', $config['scope']) !== 1)) {
            throw new ConfigurationException('scope must be null or a 1–128 character ASCII scope identifier.');
        }
        if (!is_array($config['policies'])) {
            throw new ConfigurationException('policies must be an array keyed by permission name.');
        }
        $policies = [];
        foreach ($config['policies'] as $name => $policy) {
            if (!is_string($name) || !self::valid_name($name) || !is_callable($policy)) {
                throw new ConfigurationException('Each policy needs a valid permission name and callable.');
            }
            $policies[$name] = $policy;
        }
        $this->pdo = $pdo;
        try {
            $this->driver = (string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            if ($this->driver === 'sqlite') {
                $foreign_keys = $pdo->query('PRAGMA foreign_keys');
                if ($foreign_keys === false || (int) $foreign_keys->fetchColumn() !== 1) {
                    throw new ConfigurationException('Enable PRAGMA foreign_keys = ON before constructing Permission.');
                }
            }
        } catch (PDOException $exception) {
            throw new DatabaseException('Cannot configure the PDO connection.', previous: $exception);
        }
        if (!in_array($this->driver, ['mysql', 'sqlite'], true)) {
            throw new ConfigurationException('Supported PDO drivers are mysql and sqlite.');
        }
        $unquoted = [];
        foreach (['permissions', 'roles', 'role_permissions', 'user_roles', 'user_permissions'] as $key) {
            $name = $config[$key . '_table'];
            if (!is_string($name) || preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D', $name) !== 1) {
                throw new ConfigurationException($key . '_table must be a simple SQL identifier of 1–64 characters.');
            }
            $unquoted[] = strtolower($name);
            $quote = $this->driver === 'mysql' ? '`' : '"';
            $this->tables[$key] = $quote . $name . $quote;
        }
        if (count(array_unique($unquoted)) !== count($unquoted)) {
            throw new ConfigurationException('Each configured table name must be distinct, ignoring case.');
        }
        $this->roles_enabled = $config['roles_enabled'];
        $this->scope = $config['scope'] ?? '';
        $this->policies = $policies;
    }

    /**
     * Define a permission without granting it to anyone.
     *
     * Repeated calls leave the existing definition and description unchanged.
     * Definitions are shared across scopes; no policy is created automatically.
     *
     * @param string $permission Case-sensitive lowercase permission name, at most 128 ASCII characters.
     * @param string $description Human-readable UTF-8 text, at most 1000 bytes; empty is allowed.
     * @return void
     * @throws ValidationException If either value is malformed.
     * @throws DatabaseException If persistence fails.
     */
    public function create_permission(string $permission, string $description = ''): void
    {
        $this->create_definition('permissions', $permission, $description);
    }

    /**
     * Delete a permission and cascade all its assignments in every scope.
     *
     * @param string $permission Valid permission name to delete globally.
     * @return bool Whether the definition existed and was deleted.
     * @throws ValidationException If the name is invalid.
     * @throws DatabaseException If deletion or foreign-key cascades fail.
     */
    public function delete_permission(string $permission): bool
    {
        self::assert_name($permission);
        return $this->execute("DELETE FROM {$this->tables['permissions']} WHERE name = ?", [$permission])->rowCount() > 0;
    }

    /**
     * List the global permission catalogue without applying assignments or policies.
     *
     * @return list<array{name: string, description: string}> Definitions sorted by name, or an empty list.
     * @throws DatabaseException If the catalogue cannot be read.
     */
    public function get_permissions(): array
    {
        return $this->definitions('permissions');
    }

    /**
     * Define a shared role; this does not assign any permissions or users.
     *
     * Existing definitions and their descriptions are preserved on repeated calls.
     *
     * @param string $role Lowercase ASCII role name, at most 128 characters.
     * @param string $description UTF-8 description of at most 1000 bytes.
     * @return void
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If the name or description is invalid.
     * @throws DatabaseException If persistence fails.
     */
    public function create_role(string $role, string $description = ''): void
    {
        $this->require_roles();
        $this->create_definition('roles', $role, $description);
    }

    /**
     * Delete a role and cascade its links and user assignments in every scope.
     *
     * @param string $role Valid role name to delete globally.
     * @return bool Whether the role existed and was deleted.
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If the name is invalid.
     * @throws DatabaseException If deletion fails.
     */
    public function delete_role(string $role): bool
    {
        $this->require_roles();
        self::assert_name($role);
        return $this->execute("DELETE FROM {$this->tables['roles']} WHERE name = ?", [$role])->rowCount() > 0;
    }

    /**
     * List shared role definitions, without user assignments.
     *
     * @return list<array{name: string, description: string}> All roles sorted by name.
     * @throws ConfigurationException If roles are disabled.
     * @throws DatabaseException If reading fails.
     */
    public function get_roles(): array
    {
        $this->require_roles();
        return $this->definitions('roles');
    }

    /**
     * Add a permission to a role, affecting its holders in every scope.
     *
     * Repeated grants are idempotent. Both definitions must already exist.
     *
     * @param string $role Existing role name.
     * @param string $permission Existing permission name.
     * @return void
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If either name is invalid.
     * @throws NotFoundException If a definition is missing.
     * @throws DatabaseException If reading or writing fails, including concurrent definition deletion.
     */
    public function grant_permission_to_role(string $role, string $permission): void
    {
        $this->require_roles();
        $this->require_definition('roles', $role);
        $this->require_definition('permissions', $permission);
        $this->insert('role_permissions', ['role_name' => $role, 'permission_name' => $permission]);
    }

    /**
     * Remove one role-permission link globally; user overrides are preserved.
     *
     * @param string $role Valid role name; a missing role is treated as no link.
     * @param string $permission Valid permission name.
     * @return bool Whether a link was removed.
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If either name is invalid.
     * @throws DatabaseException If deletion fails.
     */
    public function revoke_permission_from_role(string $role, string $permission): bool
    {
        $this->require_roles();
        self::assert_name($role);
        self::assert_name($permission);
        return $this->execute("DELETE FROM {$this->tables['role_permissions']} WHERE role_name = ? AND permission_name = ?", [$role, $permission])->rowCount() > 0;
    }

    /**
     * List permissions linked to a role, without policies or user overrides.
     *
     * @param string $role Valid role name; missing roles return an empty list.
     * @return list<string> Permission names sorted alphabetically.
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If the role name is invalid.
     * @throws DatabaseException If reading fails.
     */
    public function get_permissions_for_role(string $role): array
    {
        $this->require_roles();
        self::assert_name($role);
        return $this->strings("SELECT permission_name FROM {$this->tables['role_permissions']} WHERE role_name = ? ORDER BY permission_name", [$role]);
    }

    /**
     * Assign a role to a user in this client's scope; repeated calls are harmless.
     *
     * The application must verify the user exists and authorize the assignment.
     *
     * @param int $user_id Positive authenticated-system user ID; no users table is queried.
     * @param string $role Existing role name.
     * @return void
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If the ID or name is invalid.
     * @throws NotFoundException If the role is not defined.
     * @throws DatabaseException If reading or writing fails.
     */
    public function assign_role(int $user_id, string $role): void
    {
        $this->require_roles();
        self::assert_user_id($user_id);
        $this->require_definition('roles', $role);
        $this->insert('user_roles', ['user_id' => $user_id, 'role_name' => $role, 'scope' => $this->scope]);
    }

    /**
     * Remove a role assignment in this scope without changing direct permissions.
     *
     * @param int $user_id Positive user ID.
     * @param string $role Valid role name.
     * @return bool Whether an assignment was removed.
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If either argument is invalid.
     * @throws DatabaseException If deletion fails.
     */
    public function remove_role(int $user_id, string $role): bool
    {
        $this->require_roles();
        self::assert_user_id($user_id);
        self::assert_name($role);
        return $this->execute("DELETE FROM {$this->tables['user_roles']} WHERE user_id = ? AND role_name = ? AND scope = ?", [$user_id, $role, $this->scope])->rowCount() > 0;
    }

    /**
     * List this user's role assignments in exactly this scope.
     *
     * Role membership is informational; use can() to check an action.
     *
     * @param int $user_id Positive user ID.
     * @return list<string> Assigned role names sorted alphabetically.
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If the user ID is invalid.
     * @throws DatabaseException If reading fails.
     */
    public function get_roles_for_user(int $user_id): array
    {
        $this->require_roles();
        self::assert_user_id($user_id);
        return $this->strings("SELECT role_name FROM {$this->tables['user_roles']} WHERE user_id = ? AND scope = ? ORDER BY role_name", [$user_id, $this->scope]);
    }

    /**
     * Check role membership in this scope without granting permission implicitly.
     *
     * @param int $user_id Positive user ID.
     * @param string $role Valid role name; missing roles return false.
     * @return bool Whether the role is assigned.
     * @throws ConfigurationException If roles are disabled.
     * @throws ValidationException If an argument is invalid.
     * @throws DatabaseException If reading fails.
     */
    public function has_role(int $user_id, string $role): bool
    {
        $this->require_roles();
        self::assert_user_id($user_id);
        self::assert_name($role);
        return $this->execute("SELECT 1 FROM {$this->tables['user_roles']} WHERE user_id = ? AND role_name = ? AND scope = ?", [$user_id, $role, $this->scope])->fetchColumn() !== false;
    }

    /**
     * Set a direct grant in this scope, replacing an existing direct denial.
     *
     * @param int $user_id Positive application-validated user ID.
     * @param string $permission Existing permission name.
     * @return void
     * @throws ValidationException If an argument is invalid.
     * @throws NotFoundException If the permission is not defined.
     * @throws DatabaseException If persistence fails.
     */
    public function grant_permission_to_user(int $user_id, string $permission): void
    {
        $this->set_user_permission($user_id, $permission, 'allow');
    }

    /**
     * Set an explicit denial in this scope, overriding all direct and role grants.
     *
     * @param int $user_id Positive application-validated user ID.
     * @param string $permission Existing permission name.
     * @return void
     * @throws ValidationException If an argument is invalid.
     * @throws NotFoundException If the permission is not defined.
     * @throws DatabaseException If persistence fails.
     */
    public function deny_permission_to_user(int $user_id, string $permission): void
    {
        $this->set_user_permission($user_id, $permission, 'deny');
    }

    /**
     * Remove a direct override in this scope, whether it is an allow or a deny.
     *
     * A role grant can become effective again after removing a denial. To block
     * access regardless of roles, use deny_permission_to_user() instead.
     *
     * @param int $user_id Positive user ID.
     * @param string $permission Valid permission name.
     * @return bool Whether an override was removed.
     * @throws ValidationException If an argument is invalid.
     * @throws DatabaseException If deletion fails.
     */
    public function revoke_permission_from_user(int $user_id, string $permission): bool
    {
        self::assert_user_id($user_id);
        self::assert_name($permission);
        return $this->execute("DELETE FROM {$this->tables['user_permissions']} WHERE user_id = ? AND permission_name = ? AND scope = ?", [$user_id, $permission, $this->scope])->rowCount() > 0;
    }

    /**
     * List effective database grants in this scope after subtracting denials.
     *
     * Policies are not evaluated: each may require a different resource context.
     * This list is suitable for administration; use can() at the point of access.
     *
     * @param int $user_id Positive user ID.
     * @return list<string> Unique permission names sorted alphabetically.
     * @throws ValidationException If the user ID is invalid.
     * @throws DatabaseException If reading fails.
     */
    public function get_permissions_for_user(int $user_id): array
    {
        self::assert_user_id($user_id);
        return $this->permission_names($user_id);
    }

    /**
     * Decide whether this user may perform an action with the supplied context.
     *
     * First require an effective grant in this scope; only then run the matching
     * policy, if configured. Unknown permissions and unassigned users return false.
     * Policies must return literal booleans and are never cached or inferred.
     * A database or policy failure propagates instead of granting access.
     *
     * @param int $user_id Positive ID obtained from trusted authentication.
     * @param string $permission Valid permission name, compared exactly without wildcards.
     * @param array<string, mixed> $context Application-loaded resource and other trusted policy inputs.
     * @return bool True only for a grant with no denial and a passing policy when present.
     * @throws ValidationException If the ID or permission name is invalid.
     * @throws DatabaseException If reading fails.
     * @throws PolicyException If a policy returns a non-boolean value.
     * @throws Throwable If application policy code throws; its original exception propagates.
     */
    public function can(int $user_id, string $permission, array $context = []): bool
    {
        self::assert_user_id($user_id);
        self::assert_name($permission);
        if ($this->permission_names($user_id, $permission) === []) {
            return false;
        }
        if (!isset($this->policies[$permission])) {
            return true;
        }
        $allowed = ($this->policies[$permission])($user_id, $context);
        if (!is_bool($allowed)) {
            throw new PolicyException('Policies must return a boolean.');
        }
        return $allowed;
    }

    /**
     * Require the same decision as can(), throwing on ordinary denial.
     *
     * The application maps this exception to its own HTTP or other response.
     * All database, validation and policy failures propagate unchanged.
     *
     * @param int $user_id Positive authenticated user ID.
     * @param string $permission Valid action name.
     * @param array<string, mixed> $context Trusted policy context.
     * @return void
     * @throws AccessDeniedException If can() returns false.
     * @throws ValidationException If the ID or name is invalid.
     * @throws DatabaseException If reading fails.
     * @throws PolicyException If a policy result is not boolean.
     * @throws Throwable If application policy code throws.
     */
    public function authorize(int $user_id, string $permission, array $context = []): void
    {
        if (!$this->can($user_id, $permission, $context)) {
            throw new AccessDeniedException('The requested action is not permitted.');
        }
    }

    /**
     * Remove all this user's assignments in this client's scope atomically.
     *
     * Definitions remain shared. If no transaction exists, this method owns one;
     * otherwise it joins the caller's transaction and never commits or rolls it
     * back. On any failure in a caller-owned transaction, the caller must roll back.
     * With roles disabled only direct overrides are removed. For account deletion,
     * see README for removing assignments across every scope.
     *
     * @param int $user_id Positive user ID whose scoped assignments should be removed.
     * @return void
     * @throws ValidationException If the ID is invalid.
     * @throws DatabaseException If deletion or transaction handling fails.
     * @throws Throwable If an unexpected failure occurs; owned transactions are rolled back.
     */
    public function clear_user_assignments(int $user_id): void
    {
        self::assert_user_id($user_id);
        $owned = !$this->pdo->inTransaction();
        try {
            if ($owned && !$this->pdo->beginTransaction()) {
                throw new DatabaseException('Cannot begin assignment cleanup.');
            }
            $this->execute("DELETE FROM {$this->tables['user_permissions']} WHERE user_id = ? AND scope = ?", [$user_id, $this->scope]);
            if ($this->roles_enabled) {
                $this->execute("DELETE FROM {$this->tables['user_roles']} WHERE user_id = ? AND scope = ?", [$user_id, $this->scope]);
            }
            if ($owned && !$this->pdo->commit()) {
                throw new DatabaseException('Cannot commit assignment cleanup.');
            }
        } catch (Throwable $exception) {
            if ($owned) {
                try {
                    $this->rollback_cleanup();
                } catch (PDOException $rollback_exception) {
                    throw new DatabaseException('Assignment cleanup failed and rollback also failed; discard this connection.', previous: $rollback_exception);
                }
            }
            if ($exception instanceof PDOException) {
                throw new DatabaseException('Assignment cleanup transaction failed.', previous: $exception);
            }
            throw $exception;
        }
    }

    /**
     * Roll back an owned cleanup transaction if the database still has one active.
     *
     * Check current connection state because some errors abort transactions in
     * the database before control returns to the caller.
     *
     * @return void
     * @throws PDOException If rollback fails; the caller wraps it as DatabaseException.
     */
    private function rollback_cleanup(): void
    {
        if ($this->pdo->inTransaction() && !$this->pdo->rollBack()) {
            throw new PDOException('Rollback returned false.');
        }
    }

    /**
     * Store an allow/deny override after checking the permission exists.
     *
     * @param int $user_id Positive application-validated user ID.
     * @param string $permission Existing valid permission name.
     * @param 'allow'|'deny' $effect Internal validated decision value.
     * @return void
     * @throws ValidationException If the ID or name is invalid.
     * @throws NotFoundException If the permission is missing.
     * @throws DatabaseException If reading or writing fails.
     */
    private function set_user_permission(int $user_id, string $permission, string $effect): void
    {
        self::assert_user_id($user_id);
        $this->require_definition('permissions', $permission);
        $this->insert('user_permissions', [
            'user_id' => $user_id, 'permission_name' => $permission,
            'scope' => $this->scope, 'effect' => $effect,
        ], 'effect');
    }

    /**
     * Resolve database grants and denials in one statement and snapshot.
     *
     * EXISTS avoids duplicate grants from multiple roles. Denials are checked
     * independently so no grant source can override them. Policies run later.
     *
     * @param int $user_id Previously validated user ID.
     * @param string|null $permission Optional previously validated exact name to restrict the query.
     * @return list<string> Sorted effective permission names.
     * @throws DatabaseException If reading fails.
     */
    private function permission_names(int $user_id, ?string $permission = null): array
    {
        $direct = "EXISTS (SELECT 1 FROM {$this->tables['user_permissions']} up
            WHERE up.permission_name = p.name AND up.user_id = ? AND up.scope = ? AND up.effect = 'allow')";
        $parameters = [$user_id, $this->scope];
        if ($this->roles_enabled) {
            $direct .= " OR EXISTS (SELECT 1 FROM {$this->tables['role_permissions']} rp
                JOIN {$this->tables['user_roles']} ur ON ur.role_name = rp.role_name
                WHERE rp.permission_name = p.name AND ur.user_id = ? AND ur.scope = ?)";
            array_push($parameters, $user_id, $this->scope);
        }
        $sql = "SELECT p.name FROM {$this->tables['permissions']} p WHERE ($direct)
            AND NOT EXISTS (SELECT 1 FROM {$this->tables['user_permissions']} denied
                WHERE denied.permission_name = p.name AND denied.user_id = ? AND denied.scope = ? AND denied.effect = 'deny')";
        array_push($parameters, $user_id, $this->scope);
        if ($permission !== null) {
            $sql .= ' AND p.name = ?';
            $parameters[] = $permission;
        }
        return $this->strings($sql . ' ORDER BY p.name', $parameters);
    }

    /**
     * Insert a definition while preserving any existing description.
     *
     * @param 'permissions'|'roles' $table Internal definition table key.
     * @param string $name Definition name to validate.
     * @param string $description UTF-8 description, at most 1000 bytes.
     * @return void
     * @throws ValidationException If either value is invalid.
     * @throws DatabaseException If writing fails.
     */
    private function create_definition(string $table, string $name, string $description): void
    {
        self::assert_name($name);
        if (strlen($description) > 1000 || preg_match('//u', $description) !== 1 || str_contains($description, "\0")) {
            throw new ValidationException('Descriptions must be UTF-8, at most 1000 bytes, without null bytes.');
        }
        $this->insert($table, ['name' => $name, 'description' => $description]);
    }

    /**
     * Read only the public fields of definition records.
     *
     * @param 'permissions'|'roles' $table Internal definition table key.
     * @return list<array{name: string, description: string}> Sorted public definitions.
     * @throws DatabaseException If reading fails.
     */
    private function definitions(string $table): array
    {
        $rows = $this->execute("SELECT name, description FROM {$this->tables[$table]} ORDER BY name", [])->fetchAll(PDO::FETCH_ASSOC);
        $result = [];
        foreach ($rows as $row) {
            $result[] = ['name' => (string) $row['name'], 'description' => (string) $row['description']];
        }
        return $result;
    }

    /**
     * Require an existing definition before assigning a reference to it.
     *
     * Foreign keys still protect deletion races between this read and the write.
     *
     * @param 'permissions'|'roles' $table Internal definition table key.
     * @param string $name Definition name to validate and find.
     * @return void
     * @throws ValidationException If the name is invalid.
     * @throws NotFoundException If the definition is absent.
     * @throws DatabaseException If reading fails.
     */
    private function require_definition(string $table, string $name): void
    {
        self::assert_name($name);
        if ($this->execute("SELECT 1 FROM {$this->tables[$table]} WHERE name = ?", [$name])->fetchColumn() === false) {
            throw new NotFoundException('Define the permission or role before assigning it.');
        }
    }

    /**
     * Perform a targeted idempotent insert, optionally replacing one field.
     *
     * Only private, hard-coded column names reach this method. Conflict handling
     * uses the primary key; unlike INSERT IGNORE, other database errors propagate.
     *
     * @param string $table Internal validated table key.
     * @param array<string, int|string> $values Internal column names and bound values.
     * @param string|null $update Internal column to replace on conflict, or null to retain the row.
     * @return void
     * @throws DatabaseException If persistence fails.
     */
    private function insert(string $table, array $values, ?string $update = null): void
    {
        $columns = implode(', ', array_keys($values));
        $placeholders = implode(', ', array_fill(0, count($values), '?'));
        $sql = "INSERT INTO {$this->tables[$table]} ($columns) VALUES ($placeholders)";
        if ($this->driver === 'mysql') {
            $column = $update ?? array_key_first($values);
            $sql .= " ON DUPLICATE KEY UPDATE $column = " . ($update === null ? $column : '?');
        } else {
            $keys = array_keys($values);
            $keys = array_values(array_diff($keys, ['description', 'effect']));
            $sql .= ' ON CONFLICT (' . implode(', ', $keys) . ') DO ';
            $sql .= $update === null ? 'NOTHING' : "UPDATE SET $update = ?";
        }
        $parameters = array_values($values);
        if ($update !== null) {
            $parameters[] = $values[$update];
        }
        $this->execute($sql, $parameters);
    }

    /**
     * Prepare and execute SQL with values bound separately from identifiers.
     *
     * @param string $sql Internal SQL using positional placeholders.
     * @param list<int|string> $parameters Bound values in placeholder order.
     * @return PDOStatement Executed statement ready to fetch or count affected rows.
     * @throws DatabaseException If preparation or execution fails.
     */
    private function execute(string $sql, array $parameters): PDOStatement
    {
        try {
            $statement = $this->pdo->prepare($sql);
            if ($statement === false || !$statement->execute($parameters)) {
                throw new DatabaseException('Cannot execute permission database operation.');
            }
            return $statement;
        } catch (PDOException $exception) {
            throw new DatabaseException('Permission database operation failed.', previous: $exception);
        }
    }

    /**
     * Read a single text column as a consistently indexed list.
     *
     * @param string $sql Internal parameterized SELECT statement.
     * @param list<int|string> $parameters Values in placeholder order.
     * @return list<string> Text values, or an empty list.
     * @throws DatabaseException If reading fails.
     */
    private function strings(string $sql, array $parameters): array
    {
        return array_values(array_map(static fn (mixed $value): string => (string) $value, $this->execute($sql, $parameters)->fetchAll(PDO::FETCH_COLUMN)));
    }

    /**
     * Reject role operations when the client is configured for direct permissions.
     *
     * @return void
     * @throws ConfigurationException If roles_enabled is false.
     */
    private function require_roles(): void
    {
        if (!$this->roles_enabled) {
            throw new ConfigurationException('Role APIs are unavailable when roles_enabled is false.');
        }
    }

    /**
     * Recognize exact lowercase ASCII names without whitespace or wildcard syntax.
     *
     * @param string $name Proposed role or permission name.
     * @return bool Whether the name has 1–128 characters and valid segments.
     */
    private static function valid_name(string $name): bool
    {
        return strlen($name) <= 128 && preg_match('/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/D', $name) === 1;
    }

    /**
     * Require a canonical role or permission name without silently normalizing it.
     *
     * @param string $name Name to validate; lowercase segments may use dot, underscore, colon or hyphen separators.
     * @return void
     * @throws ValidationException If the name is empty, too long or noncanonical.
     */
    private static function assert_name(string $name): void
    {
        if (!self::valid_name($name)) {
            throw new ValidationException('Names must contain 1–128 lowercase ASCII characters in alphanumeric segments, starting with a letter.');
        }
    }

    /**
     * Reject IDs that cannot identify an application user.
     *
     * Existence and account status remain the application's responsibility.
     *
     * @param int $user_id User ID in the range 1 to PHP_INT_MAX.
     * @return void
     * @throws ValidationException If the ID is zero or negative.
     */
    private static function assert_user_id(int $user_id): void
    {
        if ($user_id < 1) {
            throw new ValidationException('User IDs must be positive integers.');
        }
    }
}
