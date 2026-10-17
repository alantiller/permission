<?php declare(strict_types=1);

namespace Alantiller\Permission\Exceptions;

/** Database failure; the original PDO exception is retained as the previous cause. */
class DatabaseException extends BaseException
{
    protected const ERROR_CODE = 'database_error';
}
