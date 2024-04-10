<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;

class Admin extends BaseMiddleware
{
    public function handle($request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            if ($user->role_id != 100) {
                return response()->json(['status' => 'Unauthorized - Insufficient role privileges'], 403);
            }
        } catch (TokenExpiredException $e) {
            return response()->json(['status' => 'Token is Expired']);
        } catch (TokenInvalidException $e) {
            return response()->json(['status' => 'Token is Invalid']);
        } catch (JWTException $e) {
            return response()->json(['status' => 'Authorization Token not found']);
        }

        return $next($request);
    }
}