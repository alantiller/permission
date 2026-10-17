<?php declare(strict_types=1);

namespace Alantiller\Permission\Exceptions;

/** authorize() rejected the requested action. No policy context is included. */
class AccessDeniedException extends BaseException
{
    protected const ERROR_CODE = 'access_denied';
}
