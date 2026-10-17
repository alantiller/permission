<?php declare(strict_types=1);

namespace Alantiller\Permission\Exceptions;

/** Invalid user identifier, definition name or description. */
class ValidationException extends BaseException
{
    protected const ERROR_CODE = 'validation_error';
}
