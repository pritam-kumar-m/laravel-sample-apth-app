<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Auth;
use Validator;
use Illuminate\Support\Facades\Hash;
use Session;

class AuthController extends Controller
{

    private static $user;

    public function __construct()
    {
        // $this->middleware('auth:api', ['except' => ['login', 'register']]);
        self::$user = new User();
    }

    //Registstion api
    public function register(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|string|email|max:100|unique:users',
            'country' => 'required|string',
            'birthday' => 'required|string',
            'password' => 'required|string|min:7|max:20|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'country' => $request->country,
            'birthday' => $request->birthday,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'message' => 'User Register Sucessfully',
            'user' => $user
        ], 201);
    }

    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email',
                'password' => 'required|string|min:7'
            ]);

            // $request->Session()->put('loginId', $validator->validated());
            if ($validator->fails()) {
                return response()->json($validator->errors()->toJson(), 422);
            }
            if (!$token = auth()->attempt($validator->validated())) {
                return response()->json(['error' => 'Unauthorized'], 422);
            }
            // $request->Session()->put('loginId', $token);
            return $this->createNewToken($token);

        } catch (\Exception $exception) {
            return response()->json(['message' => $exception->getMessage()], 422);

        }


    }
    public function createNewToken($token)
    {

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }


    public function profile()
    {

        return response()->json(auth()->user());

    }

    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    public function dashboard()
    {
        return response()->json(['message' => 'Get Session Data', 'session' => Session::get('loginId')]);
    }

    public function ResetPassword(Request $request)
    {
        $user_data = auth()->user();
        $validator = Validator::make($request->all(), [
            'password' => 'required|string|min:7|max:20|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $update = self::$user->where('id', $user_data->id)->update( [
            'password'=>Hash::make($request->password)
        ]);

        if ($user_data) {
            return response()->json(['message' => 'Password Change sucessfully', 'user' => $update]);
        }
    }
}
