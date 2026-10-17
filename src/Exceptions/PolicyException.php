<?php declare(strict_types=1);

namespace Alantiller\Permission\Exceptions;

/** A configured policy returned something other than a literal boolean. */
class PolicyException extends BaseException
{
    protected const ERROR_CODE = 'policy_error';
}
