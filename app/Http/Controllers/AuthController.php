<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Validator;
use Hash;

/**
 * @group Products
 *
 * APIs for managing Products
 * 
 */
class AuthController extends Controller
{ 

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }
    /**
     * Register
     * 
     * This endpoint is used to register a user to the system.
     * 
     * @bodyParam name string required Example: wael
     * @bodyParam email string required Example: ian@gmail.com
     * @bodyParam password string required Example: 12345678
     *
     * @response scenario="Successful Register" {
     * "message": "User Successfully Registered",
     * "user : {
     *  "name" : "...."
     *  "email" : "...."
     *  }
     * }
     *
     * @response 400 scenario="Failed Reqister"{
     * "field": [ "the Field is required" ] 
     * Example :  "name": [
     *   "The name field is required."
     *   ],
     * }
     *
     */
    public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|min:2|max:100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }

    /**
     * Login
     *
     * This endpoint is used to login a user to the system.
     *
     * @bodyParam email string required Example: ian@gmail.com
     * @bodyParam password string required Example: 12345678
     *
     * @response scenario="Successful Login" {
     * "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvYXBpL2xvZ2luIiwiaWF0IjoxNjc3NDk0MjQxLCJleHAiOjE2Nzc0OTc4NDEsIm5iZiI6MTY3NzQ5NDI0MSwianRpIjoiNFpNVlVuQ0FoZ1E2UGt6UiIsInN1YiI6IjIiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.4NkkCmlRMy8qy2O3LtoB4f3_RMwa8tw6xlB1s5JRW4M",
     * "token_type": "Bearer"
     * "expire_in" : integer
     * }
     *
     * @response 401 scenario="Failed Login"{
     *  "error": "Unauthorized"
     * }
     *
     */

    public function login(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        if (!$token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Logout
     * 
     * this is end point for user logout
     * @header Authorization Bearer <your_token>
     * @authenticated
     * 
     * @response scenario="logout success" {
     *    "message": "User successfully logged out."
     * }
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'User successfully logged out.']);
    }

    /**
     * Refresh Token
     * 
     * @header Authorization Bearer <Token>
     * 
     * @response scenario="Success" {
     *      'access_token' => "new token",
     *      'token_type' => 'bearer',
     *     'expires_in' => 'auth()->factory()->getTTL() * 60'
     * }
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Profile
     * 
     * @header Authorization Bearer <Token>
     * 
     * @response scenario="Success" {
     *      'id' => "1",
     *      'name' => 'wael',
     *     'email' => 'wael@gmail.com'
     * }
     */

    public function profile()
    {
        return response()->json(auth()->user());
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
