<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Models\User;

class AuthController extends Controller
{
    public function createUser(Request $request)
    {
        try {
            //Intenta validar si el usuario existe, o los datos son validos
            $validateUser = Validator::make($request->all(),
            [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required'
            ]);
            //Si la validación falla, retorna un error
            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'Lo sentimos, ha ocurrido un error',
                    'errors' => $validateUser->errors()
                ], 401);
            }
            //Si la validación es exitosa, crea el usuario
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);
            //Retorna un mensaje de éxito, junto con el token del usuario
            return response()->json([
                'status' => true,
                'message' => 'Usuario creado con exito',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);

        } catch (\Throwable $th) {
            //Cacha algun error y retorna un error
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }


    public function loginUser(Request $request)
    {
        try {
            //Intenta validar si los datos ingresados pertenecen a un usuario
            $validateUser = Validator::make($request->all(),
            [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            //Si la validación falla, retorna un error
            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            //si los datos no pertenecen a un usuario, retorna un error
            if(!Auth::attempt($request->only(['email', 'password']))){
                return response()->json([
                    'status' => false,
                    'message' => 'Credenciales incorrectas',
                ], 401);
            }
            //Consulta la base de datos para obtener el usuario
            $user = User::where('email', $request->email)->first();

            //Retorna un mensaje de éxito, junto con el token del usuario
            return response()->json([
                'status' => true,
                'message' => 'Inicio de sesión exitoso',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);

        }
        //Cacha algun error y retorna un error
        catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
}
