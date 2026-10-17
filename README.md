# alantiller/permission

A PHP authorization library built around **`new Client($pdo, $config)`**. Use direct user permissions, add roles when grouping helps, and attach PHP policies when an action also depends on a resource or business rule.

There are no third-party runtime packages. The library owns permission decisions and assignment persistence. Your application owns authentication, users, migrations, administration, resource loading and HTTP responses.

## Contents

- [Choosing a model](#choosing-a-model)
- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [How decisions work](#how-decisions-work)
- [Direct permissions](#direct-permissions)
- [Roles](#roles)
- [Policies](#policies)
- [Scopes and teams](#scopes-and-teams)
- [Using alantiller/auth](#using-alantillerauth)
- [Configuration](#configuration)
- [Database schema](#database-schema)
- [Transactions and concurrent changes](#transactions-and-concurrent-changes)
- [User deletion and cleanup](#user-deletion-and-cleanup)
- [API reference](#api-reference)
- [Errors](#errors)
- [Application responsibilities](#application-responsibilities)
- [Development](#development)
- [Design boundaries](#design-boundaries)
- [Development notes](#development-notes)

## Choosing a model

Start with permissions that describe actions, such as `documents.read` or `invoices.approve`. Application code checks those actions rather than hard-coding role names. You can then change how people receive permissions without rewriting the checks.

| Model | Configuration | Use when |
| --- | --- | --- |
| Direct permissions | `roles_enabled => false` | Each user has a small, individually managed set of actions. Only two tables are needed. |
| Permissions and roles | Default configuration | Users share job functions such as editor or reviewer. Direct exceptions are still supported. |
| Permissions and policies | Disable roles and configure `policies` | Users have direct grants, with ownership or other conditions checked in PHP. |
| Permissions, roles and policies | Enable roles and configure `policies` | Roles provide broad capabilities; policies constrain specific operations. |

**Recommended starting point:** permissions and roles, adding policies only for actions that need contextual checks. All four models use the same `can()` and `authorize()` methods. Roles can be introduced later by adding the three role tables and enabling them. Disabling roles makes existing role assignments inactive; it does not delete them.

A policy is an additional condition on a granted permission. It does not grant access by itself. For ownership checks, grant an action such as `documents.edit`, then attach a policy that requires ownership. This makes it possible to revoke the capability independently of ownership.

## Requirements and installation

- 64-bit PHP 8.1 or newer.
- PDO with `pdo_sqlite` or `pdo_mysql`.
- SQLite 3.24+ with foreign keys enabled on every connection, or MySQL 8.0.16+ with InnoDB and enforced foreign keys and check constraints.
- PHPUnit and PHPStan are development dependencies only. There is no dependency on `alantiller/auth` or a web framework.

When published through a Composer repository, install with:

```sh
composer require alantiller/permission
```

For this checkout:

```sh
composer install
```

Until publication, another local application can use a Composer path repository:

```json
{
    "repositories": [{"type": "path", "url": "../permission"}],
    "require": {"alantiller/permission": "@dev"}
}
```

Adapt the path to your layout. Production consumers can install with `composer install --no-dev` after resolving their dependencies.

## Quick start

Create the database tables through **your application's migrations** using the [MySQL](#mysql-migration-sql) or [SQLite](#sqlite-migration-sql) SQL below. The constructor never creates tables, runs migrations or seeds permissions.

```php
<?php declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Alantiller\Permission\Client;

$pdo = new PDO(
    'mysql:host=localhost;dbname=my_app;charset=utf8mb4',
    getenv('DB_USERNAME') ?: '',
    getenv('DB_PASSWORD') ?: '',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
);

$permissions = new Client($pdo, []);

// Run definition changes in trusted application setup or administration.
$permissions->create_permission('documents.read', 'Read documents');
$permissions->create_permission('documents.edit', 'Edit documents');
$permissions->create_role('editor', 'Document editors');
$permissions->grant_permission_to_role('editor', 'documents.read');
$permissions->grant_permission_to_role('editor', 'documents.edit');

// Your application has verified that account 42 exists and may receive this role.
$permissions->assign_role(42, 'editor');

// In a later request, derive this ID from your authenticated session.
$user_id = 42;
if ($permissions->can($user_id, 'documents.edit')) {
    // Perform the authorized operation.
}

// Alternatively, throw AccessDeniedException if the action is denied.
$permissions->authorize($user_id, 'documents.read');
```

For SQLite, configure the connection before constructing the client:

```php
$pdo = new PDO('sqlite:' . __DIR__ . '/app.sqlite');
$pdo->exec('PRAGMA foreign_keys = ON');
$pdo->exec('PRAGMA busy_timeout = 5000');
$permissions = new Client($pdo);
```

`Client` sets PDO's error mode to exceptions. It requires SQLite foreign-key enforcement to already be enabled, and rejects unsupported drivers. It does not inspect every table or constraint; install the documented schema correctly. PostgreSQL and MariaDB are not currently supported or verified.

### Scoped policy example

After applying the [SQLite migration](#sqlite-migration-sql) to `app.sqlite`, save the following as `quickstart.php` in your application directory alongside `vendor/`, then run `php quickstart.php`. The account and document IDs are demonstration data; running this against a new demonstration database creates the role and assignments explicitly.

```php
<?php declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Alantiller\Permission\Client;

$pdo = new PDO('sqlite:' . __DIR__ . '/app.sqlite');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$pdo->exec('PRAGMA foreign_keys = ON');

/**
 * Require ownership of the authoritative document passed by the application.
 *
 * @param int $user_id Authenticated account ID.
 * @param array<string, mixed> $context Trusted document context; missing ownership denies.
 * @return bool Whether the account owns the supplied document.
 */
function can_edit_document(int $user_id, array $context): bool
{
    $document = $context['document'] ?? null;
    return is_array($document) && ($document['owner_id'] ?? null) === $user_id;
}

$permissions = new Client($pdo, [
    'scope' => 'organisation:10',
    'policies' => ['documents.edit' => 'can_edit_document'],
]);
$permissions->create_permission('documents.edit', 'Edit owned documents');
$permissions->create_role('editor', 'Document editors');
$permissions->grant_permission_to_role('editor', 'documents.edit');
$permissions->assign_role(42, 'editor');

// Demonstration IDs stand in for authenticated accounts and server-loaded records.
$owned = ['document' => ['id' => 17, 'owner_id' => 42]];
$other = ['document' => ['id' => 18, 'owner_id' => 99]];
$decisions = [
    'Editor owns document' => $permissions->can(42, 'documents.edit', $owned),
    'Editor does not own document' => $permissions->can(42, 'documents.edit', $other),
    'Unassigned account' => $permissions->can(99, 'documents.edit', $other),
];
$permissions->deny_permission_to_user(42, 'documents.edit');
$decisions['Explicitly denied editor'] = $permissions->can(42, 'documents.edit', $owned);
$permissions->revoke_permission_from_user(42, 'documents.edit');
$decisions['Denial removed, role restored'] = $permissions->can(42, 'documents.edit', $owned);

foreach ($decisions as $label => $allowed) {
    echo $label . ': ' . ($allowed ? 'allowed' : 'denied') . PHP_EOL;
}
```

Expected output:

```text
Editor owns document: allowed
Editor does not own document: denied
Unassigned account: denied
Explicitly denied editor: denied
Denial removed, role restored: allowed
```

## How decisions work

For `can($user_id, $permission, $context)`:

1. Validate the positive integer user ID and canonical permission name.
2. Find a direct grant or, when enabled, a grant through any assigned role **in this client's scope**.
3. Reject the action if an explicit user denial exists in that scope. Denials override every role.
4. If there is an effective grant, run the policy registered for this exact permission, if any.
5. Allow only if the policy returns literal `true`, or no policy is registered.

Unknown permissions and users with no assignments return `false`. Invalid input throws. Database errors and policy exceptions propagate; they are never converted to successful access. Policies are skipped when the database decision denies access.

Names are exact: `documents.read` grants nothing for `documents.edit`. There are no wildcard permissions, implicit `admin` privileges, role hierarchies, guest access or superuser bypasses.

`get_permissions_for_user()` lists effective **database grants**, after denials. It does not evaluate policies because policies may require resource-specific context. Use `can()` or `authorize()` at the actual access boundary.

## Direct permissions

```php
$permissions = new Client($pdo, ['roles_enabled' => false]);
$permissions->create_permission('reports.export', 'Export reports');

$permissions->grant_permission_to_user(42, 'reports.export');
$permissions->can(42, 'reports.export'); // true

$permissions->deny_permission_to_user(42, 'reports.export');
$permissions->can(42, 'reports.export'); // false

$permissions->grant_permission_to_user(42, 'reports.export'); // Replaces the denial.
$permissions->revoke_permission_from_user(42, 'reports.export'); // Removes the override.
```

Each `(user_id, permission, scope)` has at most one direct override: `allow` or `deny`. A new grant replaces a denial, and a new denial replaces a grant. Repeated operations are safe.

**Revocation removes the direct override; it is not an unconditional denial.** If roles are enabled and still grant the action, removing a direct override can leave access allowed. Removing a denial can restore access through a role. Use `deny_permission_to_user()` when you need to block all grant sources in the scope.

The permission must be defined before assigning an allow or deny. Unknown definitions throw `NotFoundException`; they are never created from a typo in an assignment.

## Roles

Use a client with roles enabled, as in the quick start:

```php
$permissions->create_role('reviewer', 'Document reviewers');
$permissions->grant_permission_to_role('reviewer', 'documents.read');
$permissions->assign_role(42, 'reviewer');

$permissions->get_roles_for_user(42);           // ['editor', 'reviewer'] in the quick-start setup
$permissions->has_role(42, 'reviewer');       // true; membership only
$permissions->get_permissions_for_role('reviewer'); // ['documents.read']
$permissions->get_permissions_for_user(42);    // Sorted unique grants, minus explicit denials

$permissions->remove_role(42, 'reviewer');
$permissions->revoke_permission_from_role('reviewer', 'documents.read');
```

A user may have multiple roles. Their permissions are combined, with duplicate names removed. A role never inherits another role. Removing one role preserves direct overrides and permissions supplied by other roles.

Create calls are idempotent and preserve the original description. Editing descriptions is application-owned catalogue administration using a parameterized update; descriptions do not affect authorization. `get_permissions()` and `get_roles()` return arrays of `['name' => string, 'description' => string]`, sorted by name. Other list methods return sorted lists of names.

Role APIs throw `ConfigurationException` when `roles_enabled` is false. Direct-only clients do not query role tables, including during cleanup.

## Policies

Policies are application PHP callables supplied in configuration, keyed by permission name. They are not serialized or stored in the database. Each receives `(int $user_id, array $context)` and must return `bool`.

```php
/**
 * Permit document editing only when the authenticated user owns the loaded record.
 *
 * Missing or malformed context denies access. The application must load the
 * authoritative document and establish its tenant before calling this policy.
 *
 * @param int $user_id Authenticated account identifier.
 * @param array<string, mixed> $context Trusted context containing document.owner_id.
 * @return bool Whether ownership matches the authenticated account.
 */
function can_edit_owned_document(int $user_id, array $context): bool
{
    $document = $context['document'] ?? null;
    return is_array($document) && ($document['owner_id'] ?? null) === $user_id;
}

$permissions = new Client($pdo, [
    'policies' => [
        'documents.edit' => 'can_edit_owned_document',
    ],
]);

// An illustrative record; in an application, load this from your repository.
$document = ['id' => 17, 'owner_id' => 42];
$permissions->authorize(42, 'documents.edit', ['document' => $document]);
```

The user must also hold `documents.edit` through a direct or role grant. A policy returning true without that grant still denies. Policy registration can precede permission creation; registering a callback does not create a permission.

A returned `false` is an ordinary denial. Any non-boolean result, including `1`, `null` or `'yes'`, throws `PolicyException`. A typed callback that violates its native return type may throw PHP's `TypeError` first. Exceptions from your callback propagate unchanged. Keep policies free of side effects; every granted check can run the callback again.

Multiple conditions belong inside one policy: for example, ownership **and** a draft status. Objects with `__invoke`, closures, function names and valid method callables are supported.

**A permission without a registered policy requires only a database grant.** Register your complete policy map centrally and pass it to every relevant client. The library cannot infer that a missing policy was intended. Load resources on the server, normalize database IDs to integers, and never accept client-supplied ownership or tenant fields as authoritative context.

## Scopes and teams

Set a scope to isolate user assignments for an organisation, team, project or other application-defined boundary:

```php
// Resolve and authorize the active organisation in application code first.
$organisation_id = 10;
$permissions = new Client($pdo, [
    'scope' => 'organisation:' . $organisation_id,
    'policies' => $application_policies,
]);

$permissions->assign_role(42, 'editor'); // Assignment only in organisation:10.
$permissions->can(42, 'documents.edit', ['document' => $document]);
```

`null` is the default global scope, stored as an empty string. Named scopes are case-sensitive ASCII identifiers of 1–128 characters: start with a letter or digit and continue with letters, digits, `.`, `_`, `:` or `-`. Empty strings are rejected in configuration; use `null` for global.

**Scopes are exact and do not inherit.** A global assignment grants nothing in `organisation:10`. An assignment or denial in organisation 10 changes nothing in organisation 11. Use a new client with the intended configuration when changing scope; there is no mutable current user or scope setter.

Permission definitions, role definitions and role-permission links are shared across all scopes. Changing the permissions of `editor`, or deleting it, affects every scope using that role. Only user-role assignments and direct user overrides are scoped. For different role definitions per organisation, use distinct names such as `organisation:10:editor`, or separate table sets/databases.

A scope separates permission assignments, not application data. Your application and policies must still enforce that the resource belongs to the selected organisation. Scope selection itself is not proof of membership.

## Using alantiller/auth

Authenticate with `alantiller/auth` first, then pass its public user ID into this library. The connection and user IDs can be shared; no authentication methods or tables are coupled into this package.

```php
use Alantiller\Auth\Client as AuthClient;
use Alantiller\Permission\Client as PermissionClient;

$auth = new AuthClient($pdo, $auth_config);
$permissions = new PermissionClient($pdo, $permission_config);

// $auth_token comes from your application's session or bearer-token handling.
$result = $auth->authenticate_token($auth_token);
if (!$result['success']) {
    // Your application should return its unauthenticated response.
    throw new RuntimeException('Authentication required.');
}

$user_id = $result['user']['id'];
$permissions->authorize($user_id, 'documents.edit', ['document' => $document]);
```

This library does not check whether an ID exists, whether an account is active, or whether its session has expired. Authenticate on every protected request and remove stale assignments when deleting accounts. Keep auth's own transaction requirements in mind: do not wrap auth operations in an outer transaction if its contract disallows that.

## Configuration

All options are optional. Keys and new API names use snake_case. Unknown keys and invalid types throw `ConfigurationException`.

| Key | Default | Contract |
| --- | --- | --- |
| `permissions_table` | `permissions` | Permission catalogue table. |
| `roles_table` | `roles` | Shared role catalogue table. |
| `role_permissions_table` | `role_permissions` | Shared role-permission links. |
| `user_roles_table` | `user_roles` | Scoped user-role assignments. |
| `user_permissions_table` | `user_permissions` | Scoped direct allow/deny overrides. |
| `roles_enabled` | `true` | Literal boolean; false removes role queries and disables role APIs. |
| `scope` | `null` | Null for global, or a valid ASCII scope identifier. |
| `policies` | `[]` | Map of canonical permission names to callable `(int, array): bool`. |

Table names must have 1–64 ASCII letters, digits or underscores and start with a letter or underscore. All five names must be distinct, ignoring case, even with roles disabled. Database-qualified names such as `schema.permissions` are not accepted. Column names are fixed; table names are configurable.

```php
$permissions = new Client($pdo, [
    'permissions_table' => 'app_permissions',
    'roles_table' => 'app_roles',
    'role_permissions_table' => 'app_role_permissions',
    'user_roles_table' => 'app_user_roles',
    'user_permissions_table' => 'app_user_permissions',
    'roles_enabled' => true,
    'scope' => null,
    'policies' => [],
]);
```

Rename the tables and foreign-key references in your migration to match. If applying multiple table sets to one SQLite database, rename the explicit indexes too because SQLite index names are database-wide.

Names for roles and permissions have 1–128 lowercase ASCII characters, start with a letter, and contain alphanumeric segments separated by `.`, `_`, `:` or `-`. Examples: `read`, `documents.read`, `reports:export`, `site-admin`. No leading/trailing separators, consecutive separators, whitespace, Unicode or `*`. Values are not trimmed or lowercased automatically. Descriptions may be empty; otherwise they must be valid UTF-8, at most 1000 bytes, without null bytes. User IDs must be integers from 1 to `PHP_INT_MAX`. Use strict types at your application's PHP boundaries to avoid scalar coercion before library validation.

## Database schema

The complete migration SQL is included below. Apply it explicitly using your migration tool; the constructor never creates the schema. Integration tests read these SQL blocks directly from this README, following the same approach as `alantiller/auth`.

| Table | Columns and key | Meaning |
| --- | --- | --- |
| `permissions` | `name` primary key, `description` | Shared action catalogue. |
| `roles` | `name` primary key, `description` | Shared group catalogue. |
| `role_permissions` | Primary key `(role_name, permission_name)` | Shared role grants; foreign keys to both catalogues. |
| `user_roles` | Primary key `(user_id, role_name, scope)` | Assignments within one exact scope; foreign key to `roles`. |
| `user_permissions` | Primary key `(user_id, permission_name, scope)`, `effect` | Direct `allow` or `deny`; foreign key to `permissions`. |

Catalogue and scope comparisons use binary collations. Foreign keys cascade on definition deletion, so stale assignments do not revive if a deleted name is later recreated. Referencing-column indexes support the cascades, and the primary keys support user assignment lookups and enforce idempotency. There are no timestamps, session fields, policy blobs or implicit audit records.

In direct-only mode, migrate just `permissions`, `user_permissions` and its index. When enabling roles later, add `roles`, `role_permissions`, `user_roles` and their indexes. All five tables are required by the default configuration.

There is deliberately **no foreign key to a particular users table**: authentication and account storage remain independent. You may add `user_id` foreign keys with `ON DELETE CASCADE` in your application's migration when users share the database. With `alantiller/auth`, match MySQL's `BIGINT UNSIGNED` or SQLite's `INTEGER` user ID type. IDs must fit a positive PHP integer even if the database supports larger values.

### MySQL migration SQL

```sql
-- Application migration reference: MySQL 8.0.16+ using InnoDB.
CREATE TABLE permissions (
    name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE roles (
    name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE role_permissions (
    role_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    permission_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (role_name, permission_name),
    KEY role_permissions_permission_index (permission_name),
    FOREIGN KEY (role_name) REFERENCES roles (name) ON DELETE CASCADE,
    FOREIGN KEY (permission_name) REFERENCES permissions (name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_roles (
    user_id BIGINT UNSIGNED NOT NULL CHECK (user_id > 0),
    role_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scope VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, role_name, scope),
    KEY user_roles_role_index (role_name),
    FOREIGN KEY (role_name) REFERENCES roles (name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_permissions (
    user_id BIGINT UNSIGNED NOT NULL CHECK (user_id > 0),
    permission_name VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scope VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
    effect VARCHAR(5) CHARACTER SET ascii COLLATE ascii_bin NOT NULL CHECK (effect IN ('allow', 'deny')),
    PRIMARY KEY (user_id, permission_name, scope),
    KEY user_permissions_permission_index (permission_name),
    FOREIGN KEY (permission_name) REFERENCES permissions (name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### SQLite migration SQL

```sql
-- Application migration reference: run explicitly, never by the Client constructor.
PRAGMA foreign_keys = ON;

CREATE TABLE permissions (
    name TEXT NOT NULL COLLATE BINARY PRIMARY KEY,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE roles (
    name TEXT NOT NULL COLLATE BINARY PRIMARY KEY,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_name TEXT NOT NULL COLLATE BINARY,
    permission_name TEXT NOT NULL COLLATE BINARY,
    PRIMARY KEY (role_name, permission_name),
    FOREIGN KEY (role_name) REFERENCES roles (name) ON DELETE CASCADE,
    FOREIGN KEY (permission_name) REFERENCES permissions (name) ON DELETE CASCADE
);
CREATE INDEX role_permissions_permission_index ON role_permissions (permission_name);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL CHECK (user_id > 0),
    role_name TEXT NOT NULL COLLATE BINARY,
    scope TEXT NOT NULL COLLATE BINARY DEFAULT '',
    PRIMARY KEY (user_id, role_name, scope),
    FOREIGN KEY (role_name) REFERENCES roles (name) ON DELETE CASCADE
);
CREATE INDEX user_roles_role_index ON user_roles (role_name);

CREATE TABLE user_permissions (
    user_id INTEGER NOT NULL CHECK (user_id > 0),
    permission_name TEXT NOT NULL COLLATE BINARY,
    scope TEXT NOT NULL COLLATE BINARY DEFAULT '',
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    PRIMARY KEY (user_id, permission_name, scope),
    FOREIGN KEY (permission_name) REFERENCES permissions (name) ON DELETE CASCADE
);
CREATE INDEX user_permissions_permission_index ON user_permissions (permission_name);
```

## Transactions and concurrent changes

Most mutations consist of one atomic write after validation or a definition lookup. Upserts make repeated creation, assignments and direct effect changes idempotent without a read-then-insert race. Foreign keys reject references deleted concurrently after a definition lookup. A concurrent definition deletion may therefore produce `DatabaseException` rather than `NotFoundException`.

Single-operation methods do not begin, commit or roll back a transaction. You can combine permission changes with your own application changes:

```php
$pdo->beginTransaction();
try {
    $permissions->assign_role($user_id, 'editor');
    $permissions->grant_permission_to_user($user_id, 'reports.export');
    // Other related application writes using this connection.
    $pdo->commit();
} catch (Throwable $exception) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    throw $exception;
}
```

`clear_user_assignments()` performs multiple deletes. It starts and finishes its own transaction when none exists. Inside your transaction it joins it, never commits it, and leaves rollback to you on failure. No savepoints are introduced. Discard the connection if a rollback itself fails.

Each database permission decision uses one SELECT statement. Policy execution and the protected application operation happen afterwards; the library does not lock your resource or guarantee the decision remains valid until a later write. For sensitive ownership/status transitions, use application transactions, appropriate locks or conditional writes to keep the checked resource state valid. Database isolation determines visibility of concurrent changes. An existing repeatable-read transaction may retain an older snapshot even though the library has no cache.

There is no permission-result cache, so each check reads the database. Use the primary database where immediate revocation matters. Handle transient database-busy, deadlock or connection failures with your application's transaction retry policy; the library does not retry partial operations automatically.

## User deletion and cleanup

```php
$permissions->clear_user_assignments($user_id);
```

This removes direct overrides and, when roles are enabled, role assignments **only in the current scope**. It preserves other users, other scopes and shared definitions. Repeating it is safe.

For account deletion across all scopes, prefer application-owned `user_id` foreign keys with cascading deletion. Otherwise, delete both assignment tables' rows by user ID in your account-deletion transaction. For the default table names:

```php
$statement = $pdo->prepare('DELETE FROM user_permissions WHERE user_id = ?');
$statement->execute([$user_id]);
$statement = $pdo->prepare('DELETE FROM user_roles WHERE user_id = ?');
$statement->execute([$user_id]);
// Delete the application account in this same transaction.
```

Adapt table names and omit the role table only if your database has never used roles. A direct-only client intentionally leaves any existing role assignments untouched. Do not recycle user IDs while old assignments remain.

Deleting a permission or role is global catalogue administration: `delete_permission()` cascades its direct overrides and role links in every scope; `delete_role()` cascades its user assignments and permission links in every scope. Those operations require trusted administration regardless of the client's current scope.

## API reference

The public entry point is `Alantiller\Permission\Client`. All methods require the caller to authorize management access where applicable. Return values are native booleans, void or lists; this library does not return auth-style `success` result envelopes.

| Method | Return | Behavior |
| --- | --- | --- |
| `__construct(PDO $pdo, array $config = [])` | Client | Validate configuration; set PDO exception mode; create no schema. |
| `create_permission(string $permission, string $description = '')` | `void` | Insert a shared definition if missing; preserve existing descriptions. |
| `delete_permission(string $permission)` | `bool` | Delete globally and cascade links; false if missing. |
| `get_permissions()` | `list<array{name: string, description: string}>` | Sorted global permission catalogue. |
| `create_role(string $role, string $description = '')` | `void` | Insert a shared role if missing. |
| `delete_role(string $role)` | `bool` | Delete globally and cascade links; false if missing. |
| `get_roles()` | `list<array{name: string, description: string}>` | Sorted global role catalogue. |
| `grant_permission_to_role(string $role, string $permission)` | `void` | Add a shared link between existing definitions. |
| `revoke_permission_from_role(string $role, string $permission)` | `bool` | Remove a shared link; false if missing. |
| `get_permissions_for_role(string $role)` | `list<string>` | Sorted shared grants; empty if missing. |
| `assign_role(int $user_id, string $role)` | `void` | Assign an existing role in this scope. |
| `remove_role(int $user_id, string $role)` | `bool` | Remove a scoped role assignment; false if missing. |
| `get_roles_for_user(int $user_id)` | `list<string>` | Sorted role assignments in this scope. |
| `has_role(int $user_id, string $role)` | `bool` | Exact scoped membership only; no permission or policy evaluation. |
| `grant_permission_to_user(int $user_id, string $permission)` | `void` | Set a scoped direct allow, replacing an existing deny. |
| `deny_permission_to_user(int $user_id, string $permission)` | `void` | Set a scoped direct deny, replacing an existing allow. |
| `revoke_permission_from_user(int $user_id, string $permission)` | `bool` | Remove the direct allow/deny override; roles may still allow access. |
| `get_permissions_for_user(int $user_id)` | `list<string>` | Sorted effective database grants in this scope, without policies. |
| `can(int $user_id, string $permission, array $context = [])` | `bool` | Database grant minus denials, then optional policy. |
| `authorize(int $user_id, string $permission, array $context = [])` | `void` | Same decision as `can()`; throw on denial. |
| `clear_user_assignments(int $user_id)` | `void` | Atomic scoped cleanup; role rows included only when enabled. |

Names are validated even for missing-item removals and getters. Role APIs require `roles_enabled => true`. Definitions must exist for assignment methods; valid unknown names in removals, list methods, `has_role()` and `can()` use their documented false/empty result. Methods never verify user existence.

## Errors

All library exceptions live in `Alantiller\Permission\Exceptions` and extend `BaseException`, which extends PHP's `RuntimeException`. Each has a readonly snake_case `error_code` property, standard `getMessage()` and optional `getPrevious()` cause.

| Exception | `error_code` | Meaning |
| --- | --- | --- |
| `ConfigurationException` | `configuration_error` | Invalid options, unsupported driver, SQLite foreign keys disabled, or role API called in direct-only mode. |
| `ValidationException` | `validation_error` | Invalid ID, name or description. Native PHP parameter type errors remain `TypeError`. |
| `NotFoundException` | `not_found` | Assignment requires a permission or role that is not defined. |
| `DatabaseException` | `database_error` | Query or transaction failed; PDO failures are retained as previous causes. |
| `PolicyException` | `policy_error` | A policy returned a value that is not boolean. |
| `AccessDeniedException` | `access_denied` | `authorize()` received an ordinary denied decision. |

`can()` returns false for ordinary denial; it does not throw `AccessDeniedException`. Policy callback exceptions propagate with their original class and identity, including exceptions outside `BaseException`.

```php
use Alantiller\Permission\Exceptions\AccessDeniedException;
use Alantiller\Permission\Exceptions\DatabaseException;

try {
    $permissions->authorize($user_id, 'documents.edit', ['document' => $document]);
} catch (AccessDeniedException $exception) {
    // Map to your application's forbidden response.
} catch (DatabaseException $exception) {
    // Log privately and fail the request; do not proceed with the operation.
}
```

Do not expose exception traces or underlying PDO messages in public responses. Library messages do not include policy context or bound SQL values, but the previous PDO exception and your own callback exceptions can contain application details.

## Application responsibilities

- Authenticate the user and verify account status before checking permissions; use the authenticated ID rather than one supplied by a request body.
- Authorize every permission-management operation. Anyone able to call grant or assignment methods can change access; the library has no built-in administrator identity.
- Resolve and authorize the scope, load the actual resource, and enforce its tenant and ownership boundaries in trusted code.
- Register the same required policies in every relevant entry point, including workers and command-line tasks. Omitting a policy leaves the database grant sufficient.
- Apply the supplied constraints and migrations, manage account cleanup, and own transaction and retry boundaries.
- Enforce server-side checks at the operation itself. Hiding a button or checking role membership is insufficient.
- Own HTTP responses, CSRF protection, audit logging, policy dependencies, caching outside this library and administrative workflows.

## Development

```sh
composer install
composer validate --strict
composer check
```

`composer check` runs PHPStan at level 8 targeting PHP 8.1, then PHPUnit. Tests default to isolated SQLite in-memory databases and create tables from the SQL blocks in this README. They cover denial precedence, role unions, scope isolation, policies, invalid configuration/input, foreign-key cascades, no stale in-process results and transaction success/failure paths.

To run the same integration suite against a **dedicated disposable MySQL database**, provide:

```sh
PERMISSION_TEST_MYSQL_DSN='mysql:host=127.0.0.1;dbname=permission_test;charset=utf8mb4' \
PERMISSION_TEST_MYSQL_USER='permission_test' \
PERMISSION_TEST_MYSQL_PASSWORD='your-test-password' \
composer test
```

The MySQL user needs table creation/deletion and data access in that test database. Tests create randomly prefixed tables and remove only those tables. Do not point test credentials at production. Some tests always use SQLite to verify its connection requirements, so keep `pdo_sqlite` enabled for the MySQL run too.

In a sandbox that prevents PHPStan's local worker socket, use `composer analyse -- --debug` to run analysis without worker processes, followed by `composer test`. The debug flag changes execution mode, not analysis level.

See [Development notes](#development-notes) below for design decisions, compatibility and verification details. The package is MIT licensed; see [LICENCE](LICENCE).

## Design boundaries

This initial API intentionally supports exact permissions, additive roles, explicit per-user denials, optional restrictive policies and exact assignment scopes. It has no HTTP middleware, framework adapters, role inheritance, wildcard expansion, per-resource database ACLs, time-limited grants, built-in audit trail or persistent policy language.

Application policies can handle ownership and status without putting resource tables or business rules inside a reusable authorization library. If persisted per-record sharing or organisation-specific role definitions become necessary, design those contracts explicitly rather than hiding them inside wildcard names or implicit inheritance. The current method names and schema are intended for review before a first tagged release.

## Development notes

### 2026-10-15 — Initial library for review

The workspace started empty. The neighboring `alantiller/auth` checkout supplied the established package conventions: PHP 8.1+, 64-bit IDs, Composer/PSR-4, PDO, no third-party runtime packages, application-owned migrations, PHPUnit 10.5 and PHPStan level 8. Auth's implementation and public API were left untouched. The initial naming was subsequently changed to snake_case as requested below.

#### Model and ownership

- `Client(PDO $pdo, array $config = [])` is the single public service. It keeps configuration, an application-owned connection and policy callables, with no current user or result cache.
- Direct allow/deny overrides are the foundation. Roles are optional additive grant groups; policies are optional restrictive PHP callbacks. The same access-check API works with all four combinations.
- Explicit denial overrides every grant source. Removing an override exposes the remaining role grants. Unknown actions deny by default; malformed input and operational failures throw.
- Exact scopes isolate user assignments. Catalogues and role-permission links are shared. There is no global-scope inheritance or implicit administrator bypass.
- Policies run only after an effective grant. Callables must return literal booleans; callback exceptions propagate unchanged. A permission without a registered policy uses the database decision alone, so policy registration belongs in centralized application configuration.
- The application authenticates users, authorizes management calls, loads resources, verifies tenant membership, owns migrations, and cleans up deleted accounts. No dependency on auth's tables or HTTP behavior was introduced.

#### Persistence and compatibility

The MySQL and SQLite SQL blocks in this README are the authoritative schema examples and are executed directly by integration-test setup. Five tables support roles; direct-only deployments need just `permissions` and `user_permissions`. Definitions cascade on deletion, primary keys prevent duplicate assignments, and binary collations preserve exact identifiers. User foreign keys are intentionally application-owned.

SQLite requires 3.24+ for targeted UPSERT support, as documented in [SQLite's UPSERT reference](https://www.sqlite.org/lang_upsert.html). MySQL requires 8.0.16+ for enforced CHECK constraints, as documented in [MySQL's constraint introduction](https://dev.mysql.com/blog-archive/mysql-8-0-16-introducing-check-constraint/). InnoDB and foreign keys are required. PostgreSQL and MariaDB are outside the initial compatibility claim.

Single-write methods participate in existing application transactions. Scoped cleanup creates its own transaction only when needed; inside a caller-owned transaction, the caller owns rollback on failure. Integration coverage includes failure after the first delete. Access decisions use a single SQL statement for grant/denial resolution, but policies and protected resource writes remain subject to application transaction and locking rules.

This is a new package with no existing consumers or compatibility migration. Public API and schema changes should be reviewed before the first release. Catalogue descriptions are immutable through create calls; applications may update them with their own parameterized catalogue administration. No wildcard expansion, role inheritance, resource ACL persistence, framework adapters or cache backend was added.

#### Verification

- `composer validate --strict`: passed.
- `composer check`: passed in full with authorized local-worker socket access. PHPUnit on PHP 8.5.11 / in-memory SQLite completed 23 tests and 221 assertions, including configuration/input boundaries, all assignment sources, explicit denials, scope isolation, callback failures, foreign-key cascades and transaction ownership/rollback.
- PHPStan level 8 targeting PHP 8.1: passed for source, tests and the runnable example. `composer analyse -- --debug` also passed; debug mode avoids a local worker socket forbidden by the execution sandbox and preserves the configured analysis rules.
- The earlier standalone quick-start example: passed; demonstrated ownership checks, unassigned-user denial, explicit denial and restored role access.

Composer's initial sandboxed download could not resolve Packagist. An authorized dependency installation succeeded with its cache contained in `.cache/composer`. Installed dependencies and the generated library lock file are ignored, following the existing auth checkout's library convention.

MySQL integration and execution on the minimum PHP 8.1 runtime remain release checks. Only PHP 8.5 is installed here. Docker's CLI exists, but its daemon is not running; no isolated MySQL instance was available. The README gives the opt-in MySQL test command; tests use random table prefixes and must be pointed at a disposable database. Static PHP 8.1 targeting is not a substitute for running that runtime.

The implementation is local and has not been published to Composer or pushed to GitHub.

### 2026-10-15 — Switch project-defined identifiers to snake_case

Alan explicitly requested snake_case for this unreleased package. Public methods, parameter names, configuration keys, exception `error_code`, internal properties/helpers, test names and example identifiers now follow that convention. Classes remain PascalCase; inherited PHPUnit hooks, PHPUnit assertions, PDO calls and tool configuration retain their required external names.

This deliberately changes the draft public API without compatibility aliases. For example, use `create_permission()`, `assign_role()`, `roles_enabled` and `permissions_table`. Consumers of the earlier draft must update method calls, named arguments, configuration keys and exception-property access. Database tables and columns already used snake_case, so this change needs no database migration and does not change permission decisions. Documentation, PHPDoc and examples were updated together. The broader entity/tenant model is still being discussed and is not implemented by this naming change.

Verification for this revision: `composer analyse -- --debug` passed at PHPStan level 8; `composer test` passed with 23 tests and 221 assertions on PHP 8.5.11 / SQLite; the earlier standalone quick-start example produced the expected decisions. MySQL and minimum-runtime verification remain outstanding as noted above.

### 2026-10-17 — Consolidate documentation into README

All schemas, usage examples and development notes now live in this README to match the documentation layout of `alantiller/auth`. The separate database, documentation and example directories were removed. Tests now extract and execute the documented MySQL or SQLite migration SQL from this file, and PHPStan analyzes source and tests. The scoped policy example above replaces the separate example script. This changes documentation layout and test setup without changing the public API or database definitions. The entity/tenant redesign discussed separately remains unimplemented.

Verification: `composer validate --strict` and `composer analyse -- --debug` passed; `composer test` passed with 23 tests and 244 assertions on PHP 8.5.11 / SQLite. The scoped policy example was extracted from this README and run against a temporary database created from its documented SQLite SQL; its output matched the expected output above. The removed directories and stale file references were checked. MySQL and minimum PHP 8.1 runtime verification remain outstanding.
