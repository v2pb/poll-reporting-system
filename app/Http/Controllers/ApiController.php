<?php

namespace App\Http\Controllers;



use App\Http\Controllers\Controller;

use App\Models\AssemblyConstituency;
use App\Models\Category;
use App\Models\District;
use App\Models\PollReport;
use App\Models\Role;
use App\Models\Time;
use App\Models\TokenManagement;
use App\Models\User;
use App\Models\UserLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;


class ApiController extends Controller
{
    /*--------------------------------- COMMON START -------------------------------------*/


    public function admin_update(Request $request)
    {
        //! min
        // Define the allowed parameters
        $allowedParams = ['old_number', 'new_number', 'name' , "password", "iv"]; // Include 'iv' if you're encrypting the password client-side

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['msg' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $rules = [
            'old_number' => 'required|digits:10|numeric|exists:users,phone',
            'new_number' => 'required|digits:10|numeric',
            'name' => 'required|string|regex:/^[A-Za-z ]+$/',
        ];
        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $user = User::where('phone', $request->old_number)->first();

        if (!$user) {
            return response()->json(['msg' => 'User with phone number ' . $request->old_number . ' not found'], 404);
        }

        if ($user->role_id != "100") {
            return response()->json(['msg' => 'Unauthorized'], 401);
        }

        // Initialize data to update with name; may add phone later if conditions are met
        $dataToUpdate = [
            'name' => $request->name,
        ];

        if ($request->old_number != $request->new_number) {
            $phoneExists = User::where('phone', $request->new_number)->exists();
            if ($phoneExists) {
                return response()->json(['msg' => 'The new phone number is already in use'], 400);
            }
            $dataToUpdate['phone'] = $request->new_number;
        }

        if ($request->filled('password')) {
   
            $iv = base64_decode($request->input('iv'));
            $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
            $encryptedPassword = base64_decode($request->input('password'));

            // Decrypt the password
            $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);


            $passwordValidationRules = [
                'password' => ['required', 'string', 'min:6', 'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$/'],
                //'iv' => ['required', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
            ];
            $passwordValidator = Validator::make(['password' => $decryptedPassword], $passwordValidationRules);

            if ($passwordValidator->fails()) {
                $firstErrorMessage = $passwordValidator->errors()->first('password');
                return response()->json(['msg' => $firstErrorMessage], 400);
            }
            // $dataToUpdate['password'] = $decryptedPassword;
        }

        $user->update($dataToUpdate);

        return response()->json(['msg' => 'User updated successfully'], 200);
    }

    public function get_admin_data(Request $request)
    {
        // Define the allowed parameters
        $allowedParams = ['phone'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $rules = [
            'phone' => 'required|digits:10|numeric|exists:users,phone',
        ];

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }
        $user = User::where('phone', $request->input('phone'))->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }
        if ($user->role_id != '100') {
            return response()->json(['message' => 'The selected phone is invalid for the required role.'], 403);
        }

        $transformedUser = [
            'name' => $user->name,
            'phone' => $user->phone,
        ];

        return response()->json($transformedUser);
    }

    /*--------------------------------- COMMON START -------------------------------------*/

    public function login(Request $request)
    {
        // Define the allowed parameters
        $allowedParams = ['iv', 'phone', 'password'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        try {
            $encryptedPhone = base64_decode($request->input('phone'));
            $encryptedPassword = base64_decode($request->input('password'));
            // $user_role_string = $request->input('user_role');
            $iv = base64_decode($request->input('iv'));
            $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');

            $decryptedPhone = openssl_decrypt($encryptedPhone, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);


            // $decryptedPhone = $request->input('phone'); //for testing please comment this 


            $validator = Validator::make(
                ['phone' => $decryptedPhone, 'password' => $decryptedPassword, 'iv' => $request->input('iv')],
                [
                    'phone' => 'required|numeric|phone_rule',
                    'password' => 'required|string|password_rule|min:6',
                    'iv' => ['required', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
                ]
            );

            if ($validator->fails()) {
                $firstErrorMessage = $validator->errors()->first();
                return response()->json(['msg' => $firstErrorMessage], 400);
            }

            $hashedPhone = hash('sha256', $decryptedPhone); //uncomment
            $decryptedPhone = $hashedPhone; 

            //$user = User::where('phone', $hashedPhone)->first();
            $user = User::where('phone', $decryptedPhone)->first();

            if (!$user) {
                return response()->json(['msg' => 'User not found'], 404);
            }

            if ($user->is_active !== true) {
                return response()->json(['msg' => 'User not activated'], 401);
            }

            // form validated....check credentials now..
            $log_user = new UserLog();
            $log_user->user_id = $decryptedPhone;
            $log_user->user_ip = $request->getClientIp();
            $log_user->mac_id =exec('getmac');

            if (User::where('phone', $decryptedPhone)->count() != 0) {
                $log_user->phone_number = $decryptedPhone;
                $log_user->user_name = User::select('name')->where('phone', $decryptedPhone)->first()->name;
                $log_user->user_role = User::select('role_id')->where('phone', $decryptedPhone)->first()->role_id;
                // $log_user->phone_number = User::where('phone', $decryptedPhone)->first()->phone;
                // $log_user->email = User::where('phone', $decryptedPhone)->first()->email;

            } else {
                $log_user->phone_number = $decryptedPhone;
                $log_user->user_name = "Un-registered User";
                $log_user->user_role = "NA";
            }

            $credentials = ['phone' => $decryptedPhone, 'password' => $decryptedPassword];
            if (!$token = JWTAuth::attempt($credentials)) {
                $log_user->is_login_successful = false;
                $log_user->save();
                return response()->json(['msg' => 'Unauthorized'], 401);
            }

            //before login attempt check if user already has active token, if yes make it invalid also delete the entry from token management table
            // if (TokenManagement::where('userid', $decryptedPhone)->count() > 0) {
            //     $oldToken = TokenManagement::where('userid', $decryptedPhone)->first()->active_token;
            //     try { //check if the token is already expired
            //         JWTAuth::setToken($oldToken)->invalidate();
            //     } catch (TokenExpiredException $e) {
            //         //token has already expired
            //     }
            //     TokenManagement::where('userid', $decryptedPhone)->firstorfail()->delete();
            // }

            // //before sending response store the new token in the token management table
            // $tokenEntry = new TokenManagement();
            // $tokenEntry->userid = $decryptedPhone;
            // $tokenEntry->active_token = $token;

            //log 
            $log_user->is_login_successful = true;
            $log_user->save();

            //if ($tokenEntry->save()) {
                $user = User::where('phone', $decryptedPhone)->first();
                return response()->json(['token' => $token, 'role' => $user['role_id'], "name" => $user["name"], "msg" => "Successful"], 200);
            //} else {
                //return response()->json(['msg' => 'The Token details could not be saved!'], 401);
            //}
        } catch (\Exception $e) {

            return response()->json(['msg' => 'Something went wrong!'], 400);
        }
    }
    /*--------------------------------- COMMON END-------------------------------------*/

    /*------------------------------ ADMIN START (ROLE: 100) ------------------------------------*/

    //Admin management
    function register_admin(Request $request)
    {

        $rules = [
            'name' => 'required|string|max:255|name_rule',
            'phone' => 'required|numeric|phone_rule|unique:users',
            'password' => [
                'required',
                'min:6',
                'password_rule',
            ],
            'iv' => ['required', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
            'sectorno' => 'nullable|remarks_rule',
            'psno' => ['nullable',Rule::notIn(['<script>', '</script>', 'min:16'])],
            'ac' => 'required|integer',
            'dist_id' => 'nullable|integer',
            'created_by' => 'nullable',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['msg' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        // Decrypt the password here before validation
        $iv = base64_decode($request->input('iv'));
        $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
        $encryptedPassword = base64_decode($request->input('password'));

        $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

        if ($decryptedPassword === false) {
            return response()->json(['msg' => 'Password decryption failed'], 422);
        }

        // Include the decrypted password in the data to be validated
        $dataToValidate = $request->all();
        $dataToValidate['password'] = $decryptedPassword;

        $validator = Validator::make($dataToValidate, $rules);

        $validator->after(function ($validator) use ($request) { // Add custom validation to check the file size
            $hashedPhone = hash('sha256', $request->phone);

            if (User::where('phone', $hashedPhone)->count() != 0) { 
                $validator->errors()->add('phone', 'The phone number is already taken.');
            }
        });

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        // Proceed to create the user with the decrypted and hashed password
        $user = new User([
            'name' => $request->name,
            'phone' => hash('sha256', $request->phone),
            'password' => bcrypt($decryptedPassword),
            'ac' => $request->ac,
            'role_id' => 100, // 100 role_id for Admin
            'sectorno' => $request->sectorno,
            'psno' => $request->psno,
            'dist_id' => $request->dist_id,
            'created_by' => $request->created_by,
        ]);

        $user->save();

        return response()->json(['msg' => "Success"], 201);
    }

    public function update_admin(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:users,id',
            'name' => 'required|string|name_rule|max:255',
            'phone' => [
                'sometimes',
                'required',
                'phone_rule',
                'numeric',
                 Rule::unique('users', 'phone')->ignore(User::where('id', $request->id)->first() ? User::where('id', $request->id)->first()->id : null, 'id'), // Ignore the current user's phone number
            ],
            'ac' => 'required|integer',
            'is_active' => 'required|in:true,false',
            'sectorno' => 'nullable|remarks_rule',
            'psno' => ['nullable',Rule::notIn(['<script>', '</script>', 'min:16'])],
            'dist_id' => 'nullable|integer',
            'password' => ['nullable', 'string', 'regex:/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', Rule::notIn(['<script>', '</script>'])],
            'iv' => ['nullable', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
            'updated_by' => 'nullable',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

        $user = User::find($request->id);
        if (!$user) {
            return response()->json(['msg' => 'User not found'], 404);
        }

        // Decrypt password if provided
        if ($request->filled('password')) {
            $iv = base64_decode($request->input('iv'));
            $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
            $encryptedPassword = base64_decode($request->input('password'));

            // Decrypt the password
            $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

            $passwordValidationRules = [
                'password' => ['required', 'string', 'min:6', 'password_rule'],
                // 'iv' => ['required', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
            ];
            $passwordValidator = Validator::make(['password' => $decryptedPassword], $passwordValidationRules);

            if ($passwordValidator->fails()) {
                $firstErrorMessage = $passwordValidator->errors()->first('password');
                return response()->json(['msg' => $firstErrorMessage], 400);
            }
            $user->password = bcrypt($decryptedPassword);
        }
        $user->name = $request->input('name');
        $user->phone = hash('sha256', $request->phone);
        $user->ac = $request->input('ac');
        $user->is_active = $request->input('is_active') === 'true'; // Convert string boolean to actual boolean
        $user->psno = $request->input('psno');
        $user->sectorno = $request->input('sectorno');
        $user->dist_id = $request->input('dist_id');
        $user->updated_by = JWTauth::user()->id;
        $user->save();
        return response()->json(['message' => 'User updated successfully']);
    }

    //user management 

    public function get_dropdown_roles(Request $request)
    {
        // Add is_active check to the query
        $roleList = Role::whereNot('role_id', 100)
                                ->where('status', true) // Ensure you check for active cells
                                ->select(
                                    'role_id as opt_id',
                                    'role_name as opt_name'
                                )
                                ->get();

        if ($roleList->isEmpty()) {
            return response()->json(['message' => 'No active roles found'], 404);
        }

        return response()->json($roleList, 200);
    }

    public function register_user(Request $request)
    {
        $rules = [
            'name' => 'required|string|max:255|name_rule',
            'phone' => 'required|numeric|phone_rule',
            'password' => [
                'required',
                'min:6',
                'password_rule',
            ],
            'iv' => ['required', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
            'sectorno' => 'nullable|remarks_rule',
            'psno' => 'nullable|remarks_rule',
            // 'ac' => 'required|integer', //get from created_by admin
            // 'dist_id' => 'nullable|integer', //get from created_by admin
            'role_id' => 'integer|in:200,300', 
            'created_by' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['msg' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        // Decrypt the password here before validation
        $iv = base64_decode($request->input('iv'));
        $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
        $encryptedPassword = base64_decode($request->input('password'));

        $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

        if ($decryptedPassword === false) {
            return response()->json(['msg' => 'Password decryption failed'], 422);
        }

        // Include the decrypted password in the data to be validated
        $dataToValidate = $request->all();
        $dataToValidate['password'] = $decryptedPassword;

        $validator = Validator::make($dataToValidate, $rules);

        $validator->after(function ($validator) use ($request) { // Add custom validation to check the file size
        $hashedPhone = hash('sha256', $request->phone);

            if (User::where('phone', $hashedPhone)->count() != 0) { 
                $validator->errors()->add('phone', 'The phone number is already taken.');
            }
        });

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        //get AC and District from the Created by Admin

        $userACId = User::where('id', JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['msg' => 'User or Assembly Constituency not found'], 404);
        }

        //if district available
        $userDistrictId = User::where('id', JWTauth::user()->id)->value('dist_id');

        // Proceed to create the user with the decrypted and hashed password
        $user = new User([
            'name' => $request->name,
            'phone' => hash('sha256', $request->phone),
            'password' => bcrypt($decryptedPassword),
            'ac' => $userACId,
            'role_id' => $request->role_id, // 200 role_id for User, 300 for Monitor
            'sectorno' => $request->sectorno,
            'psno' => $request->psno,
            'dist_id' => $userDistrictId,
            'created_by' => JWTauth::user()->id,
        ]);

        $user->save();

        return response()->json(['msg' => "Success"], 201);
    }

    public function dispose(Request $request)
    {
        // $rules = [
        //     'id' => 'required|string|exists:poll_report,id',
        // ];
        $rules = [
                 'id' => 'required|string',
            ];

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }


        $poll_report = PollReport::where('id', $request->input('id'))->first();


        if (!$poll_report) {
            return response()->json(['message' => 'Record not found'], 404);
        }

        // Update the dispose_status to 1
        $poll_report->active = 0;
        $poll_report->save(); // Save the changes to the database


        return response()->json(['message' => 'Record deleted successfully'], 200);
    }
    
    public function dispose_user(Request $request)
    {
        // $rules = [
        //     'id' => 'required|string|exists:poll_report,id',
        // ];
        $rules = [
                 'id' => 'required|string',
            ];

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }


        $poll_report = PollReport::where('id', $request->input('id'))->first();


        if (!$poll_report) {
            return response()->json(['message' => 'Record not found'], 404);
        }

        // Update the dispose_status to 1
        $poll_report->active = 0;
        $poll_report->save(); // Save the changes to the database


        return response()->json(['message' => 'Record deleted successfully'], 200);
    }

    public function get_user_data(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:users,id',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }
        $user = User::where('id', $request->input('id'))->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }
        if (!$user->ac) {
            return response()->json(['message' => 'Assembly Constituency not found for user'], 404);
        }

        if ($user->role_id == '100') {
            return response()->json(['message' => 'The selected phone is invalid for the required role.'], 403);
        }

        $transformedUser = [
            'id' => $user->id,
            'name' => $user->name,
            'phone' => hash('sha256', $user->phone),
            'ac' => $user->ac,
            'sectorno' => $user->sectorno,
            'psno' => $user->psno,
            'is_active' => $user->is_active,
            'role_id' => $user->role_id
        ];

        return response()->json($transformedUser);
    }

    public function update_user(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:users,id',
            'name' => 'required|string|name_rule|max:255',
            'phone' => [
                //'sometimes',
                'required',
                'phone_rule',
                'numeric',
                 //Rule::unique('users', 'phone')->ignore(User::where('id', $request->id)->first() ? User::where('id', //$request->id)->first()->id : null, 'id'), // Ignore the current user's phone number
            ],
            // 'ac' => 'required|integer',
            'is_active' => 'required|in:true,false',
            'sectorno' => 'nullable|remarks_rule',
            'psno' => 'nullable|remarks_rule',
            // 'dist_id' => 'nullable|integer',
            'password' => ['nullable', 'string', 'regex:/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', Rule::notIn(['<script>', '</script>'])],
            'iv' => ['nullable', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
            'updated_by' => 'nullable',
            'role_id' => 'integer|in:200,300',
        ];

        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count(array_intersect(array_keys($request->all()), $allowedParams)) !== count($request->all())) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }
        $validator = Validator::make($request->all(), $rules);
        $validator->after(function ($validator) use ($request) { // Add custom validation to check the file size
            $hashedPhone = hash('sha256', $request->phone);

            if (User::where('phone', $hashedPhone)
                    ->whereNot('id',$request->id)
                    ->count() != 0
                ) { 
                $validator->errors()->add('phone', 'The phone number is already taken.');
            }
        });

        

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $user = User::find($request->id);
        if (!$user) {
            return response()->json(['msg' => 'User not found'], 404);
        }

        $dataToUpdate = [
            'name' => $request->name,
            'phone' => hash('sha256', $request->phone),
            'sectorno' => $request->sectorno,
            'psno' => $request->psno,
            'is_active' => $request->is_active === 'true', // Ensure boolean value is correctly interpreted
            'updated_by' =>  JWTauth::user()->id,
            'role_id' => $request->role_id,
        ];

        if ($request->filled('password')) {

            $iv = base64_decode($request->input('iv'));
            $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
            $encryptedPassword = base64_decode($request->input('password'));

            // Decrypt the password
            $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

            // Secondary validation for the decrypted password
            $passwordValidationRules = [
                'password' => ['required', 'string', 'min:6', 'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$/'],
            ];
            $passwordValidator = Validator::make(['password' => $decryptedPassword], $passwordValidationRules);

            if ($passwordValidator->fails()) {
                $firstErrorMessage = $passwordValidator->errors()->first('password');
                return response()->json(['msg' => $firstErrorMessage], 400);
            }

            // Hash the decrypted password before updating
            $dataToUpdate['password'] = bcrypt($decryptedPassword);
        }

        $user->update($dataToUpdate);

        return response()->json(['msg' => 'User updated successfully'], 200);
    }

    public function get_register_users_list(Request $request)
    {
        $rules = [
            'uuid' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

        $data = $validator->validated();

        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['msg' => 'User or Assembly Constituency not found'], 404);
        }

        // If the user exists and has the correct role_id, fetch other users excluding this one
        $users = User::where('ac', $userACId)
            ->where('role_id', "200")
            ->get();

        // if ($users->isEmpty()) {
        //     return response()->json(['msg' => 'Users with the specified Assembly Constituency not found or does not have the required role'], 404);
        // }

        return response()->json($users);
    }

    //category master data management
    public function register_category(Request $request)
    {
        // return JWTauth::user();
        $rules = [
            'category_id' => 'required|integer',
            'category_name' => 'required|string|remarks_rule',
            'created_by' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['msg' => 'User or Assembly Constituency not found'], 404);
        }

        // Add validation rule for unique combination of category_name and ac
        $rules['category_name'] .= '|unique:categories,category_name,NULL,id,ac,' . $userACId;

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $categoryData = $validator->validated();

        $categoryData['ac'] = $userACId;

        //district available
        $userDistrictId = User::where('id',  JWTauth::user()->id)->value('dist_id');

        if ($userDistrictId) {
            $categoryData['district_id'] = $userDistrictId;
        }

        $category = Category::create($categoryData);

        return response()->json($category, 201);
    }

    public function get_category_details(Request $request)
    {
        $rules = [
            'category_id' => 'required|integer|exists:categories,id', // Assuming 'id' is the column you're validating against
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $categoryDetails = Category::where('id', $request->category_id)->first();

        if ($categoryDetails === null) {

            return response()->json(['message' => 'Category not found'], 404);
        }

        return response()->json($categoryDetails, 200);
    }

    public function update_category(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:categories,id',
            'category_id' => 'required|integer',
            'category_name' => [
                'sometimes',
                'required',
                'remarks_rule',
                'string',
                Rule::unique('categories')->where(function ($query) use ($request) {
                    return $query->where('category_name', $request->category_name)
                                    ->where('ac', Category::where('id', $request->id)->value('ac'));
                })->ignore(Category::where('id', $request->id)->first() ? Category::where('id', $request->id)->first()->id : null, 'id'), // Ignore the current Category ID when updating
            ],
            'is_active' => 'required|string|in:true,false',
            'updated_by' => 'required',
        ];

        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }
        if ($request->has('id')) {

            $category = Category::find($request->id);


            if (!$category) {
                return response()->json(['msg' => 'Category details not found'], 404);
            }

            $category->update([
                'category_id' => $request->category_id,
                'category_name' => $request->category_name,
                'is_active' => $request->is_active,
                'updated_by' =>  JWTauth::user()->id,
            ]);

            return response()->json(['msg' => 'Category details updated successfully'], 200);
        } else {
            return response()->json(['msg' => 'ID is required for updating'], 400);
        }
    }

    public function get_register_categories_list(Request $request)
    {
        $rules = [
            'phone' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['message' => 'User or Assembly Constituency not found'], 404);
        }

        $categories = Category::where('ac', $userACId)->get();

        if ($categories->isEmpty()) {

            return response()->json(['message' => 'No Categories found for this Assembly Constituency'], 404);
        }
        return response()->json($categories, 200);
    }

    //time master data management
    public function register_time(Request $request)
    {
        $rules = [
            'time_id' => 'required|integer',
            'time_name' => 'required|string|remarks_rule',
            'created_by' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['msg' => 'User or Assembly Constituency not found'], 404);
        }

        // Add validation rule for unique combination of time_name and ac
        $rules['time_name'] .= '|unique:times,time_name,NULL,id,ac,' . $userACId;

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $timeData = $validator->validated();

        $timeData['ac'] = $userACId;

        //district available
        $userDistrictId = User::where('id',  JWTauth::user()->id)->value('dist_id');

        if ($userDistrictId) {
            $timeData['district_id'] = $userDistrictId;
        }

        $time = Time::create($timeData);

        return response()->json($time, 201);
    }

    public function get_time_details(Request $request)
    {
        $rules = [
            'time_id' => 'required|integer|exists:times,id', // Assuming 'id' is the column you're validating against
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $timeDetails = Time::where('id', $request->time_id)->first();

        if ($timeDetails === null) {

            return response()->json(['message' => 'Time not found'], 404);
        }

        return response()->json($timeDetails, 200);
    }

    public function update_time(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:times,id',
            'time_id' => 'required|integer',
            'time_name' => [
                'sometimes',
                'required',
                'remarks_rule',
                'string',
                Rule::unique('times')->where(function ($query) use ($request) {
                    return $query->where('time_name', $request->time_name)
                                    ->where('ac', Time::where('id', $request->id)->value('ac'));
                })->ignore(Time::where('id', $request->id)->first() ? Time::where('id', $request->id)->first()->id : null, 'id'), // Ignore the current Time ID when updating
            ],
            'is_active' => 'required|string|in:true,false',
            'updated_by' => 'required',
        ];

        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }
        if ($request->has('id')) {

            $time = Time::find($request->id);


            if (!$time) {
                return response()->json(['msg' => 'Time details not found'], 404);
            }

            $time->update([
                'time_id' => $request->time_id,
                'time_name' => $request->time_name,
                'is_active' => $request->is_active,
                'updated_by' =>  JWTauth::user()->id,
            ]);

            return response()->json(['msg' => 'Time details updated successfully'], 200);
        } else {
            return response()->json(['msg' => 'ID is required for updating'], 400);
        }
    }

    public function get_register_times_list(Request $request)
    {
        $rules = [
            'phone' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['message' => 'User or Assembly Constituency not found'], 404);
        }

        $times = Time::where('ac', $userACId)->get();

        if ($times->isEmpty()) {

            return response()->json(['message' => 'No Times found for this Assembly Constituency'], 404);
        }
        return response()->json($times, 200);
    }

    //poll reports
    public function view_poll_reports(Request $request)
    {
        $rules = [
            'requested_by' => 'required',
            // 'start' => ['required', 'date', 'date_format:Y-m-d', 'after_or_equal:2024-01-01', 'before_or_equal:' . now()->format('Y-m-d')],
            // 'end' => ['required', 'date', 'date_format:Y-m-d', 'after_or_equal:2024-01-01', 'before_or_equal:' . now()->format('Y-m-d')],
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        // $start = $request->input("start");
        // $end = $request->input("end");
        //$userPhone = $request->input("requested_by"); //get the Admin's phone no.

        // Find the Admin's AC based on their phone number
        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['message' => 'User or Assembly Constituency not found'], 404);
        }

        //entered_by user's AC of poll reports should be the same as requested admin's AC
        $phones = User::where('role_id', 200)->where('ac', $userACId)->pluck('id'); //get the phone numbers having same AC as requested Admins
        $sector = User::where('id',  JWTauth::user()->id)->value('sectorno');

        if (PollReport::whereIn('entered_by', $phones)->count() > 0) {
            // Fetch poll reports within the specified date range and related to the Admin's AC
            $poll_reports = PollReport::whereIn('entered_by', $phones)
            ->where('active', '1')
            ->with("categoryDetail","timeDetail")
                //-> whereDate('created_at', '>=', $start)->whereDate('created_at', '<=', $end) //filter date range
                ->orderBy('created_at', 'DESC')
                ->get();
                $transformed = $poll_reports->map(function ($item) {
                    return [
                        'id' => $item->id,
                        'category' => $item->categoryDetail ? $item->categoryDetail->category_name : null,
                        'two_hourly' => $item->timeDetail? $item->timeDetail->time_name : null,
                        'remark' => $item->remarks,
                        'sector' => $item->sector,
                    ];
                });
                //$transformed.={'sector' => $sector},
                return response()->json($transformed,);
        } else {
            return response()->json(['message' => 'No Poll Reports found for this Assembly Constituency!'], 404);
        }
    }

    /*------------------------------ ADMIN END ------------------------------------*/
    /*------------------------------ USER START (ROLE: 200)------------------------------------*/

    public function get_dropdown_categories(Request $request)
    {
        $rules = [
            'phone' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        // Assuming you're using 'phone' from $request->all(), but you should use $request->input('phone')
        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['msg' => 'User or Assembly Constituency not found'], 404);
        }

        // Add is_active check to the query
        $categoryList = Category::where('ac', $userACId)
            ->where('is_active', true) // Ensure you check for active cells
            ->select(
                'id as opt_id',
                'category_name as opt_name'
            )
            ->get();

        if ($categoryList->isEmpty()) {
            return response()->json(['message' => 'No active categories found for this district'], 404);
        }

        return response()->json($categoryList, 200);
    }

    public function get_dropdown_times(Request $request)
    {
        $rules = [
            'phone' => 'required',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        // Assuming you're using 'phone' from $request->all(), but you should use $request->input('phone')
        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['msg' => 'User or Assembly Constituency not found'], 404);
        }

        // Add is_active check to the query
        $timeList = Time::where('ac', $userACId)
            ->where('is_active', true) // Ensure you check for active cells
            ->select(
                'id as opt_id',
                'time_name as opt_name'
            )
            ->get();

        if ($timeList->isEmpty()) {
            return response()->json(['message' => 'No active categories found for this district'], 404);
        }

        return response()->json($timeList, 200);
    }

    public function create_poll_report(Request $request)
    {
        $rules = [
            'category' => 'required|integer|exists:categories,id',
            'two_hourly' => [
                'nullable',
                'integer',
                // function ($attribute, $value, $fail) {
                //     if ($value != 0 && !Rule::exists('times', 'id')->where('id', $value)->exists()) {
                //         $fail('The selected ' . $attribute . ' is invalid.');
                //     }
                // },
            ],  
    
            // 'two_hourly' => 'nullable|integer|exists:times,id', //required_if:category,1
            'remarks' => 'required|string|remarks_rule|max:255',
            'entered_by' => 'required',
            
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $enteredBy = $request->input('entered_by');

        $user = User::where('id',  JWTauth::user()->id)->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        // $userACId = $user->ac;
        $reportData = $validator->validated();
        
        //PollReport::create($reportData);
        $pollReport = PollReport::create([
            'category' => $request->category,
            'two_hourly' => $request->two_hourly,
            'remarks' => $request->remarks,
            'entered_by' =>  JWTauth::user()->id,          
            'active' => '1',
            'sector' => User::where('id',  JWTauth::user()->id)->value('sectorno'), 
        ]);
        return response()->json($pollReport, 200);
        //return response()->json(['message' => 'Poll Status Report has been send successfully!'], 200);
    }

    //view poll status reports sent by them
    public function display_poll_status_reports(Request $request)
    {
        $rules = [
            'requested_by' => 'required',
            // 'start' => ['required', 'date', 'date_format:Y-m-d', 'after_or_equal:2024-01-01', 'before_or_equal:' . now()->format('Y-m-d')],
            // 'end' => ['required', 'date', 'date_format:Y-m-d', 'after_or_equal:2024-01-01', 'before_or_equal:' . now()->format('Y-m-d')],
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        // $start = $request->input("start");
        // $end = $request->input("end");
        $userPhone = $request->input("requested_by"); //get the logged in User's phone no.
        $sector = User::where('id',  JWTauth::user()->id)->value('sectorno');
        if (PollReport::where('entered_by',  JWTauth::user()->id)->count() > 0) {
            // Fetch poll reports sent by them
            $poll_reports = PollReport::where('entered_by',  JWTauth::user()->id)
                ->where('active', '1')
                ->with("categoryDetail","timeDetail")
                ->orderBy('created_at', 'DESC')
                ->get();

            $transformed = $poll_reports->map(function ($item) {
                return [
                    'id' => $item->id,
                    'category' => $item->categoryDetail ? $item->categoryDetail->category_name : null,
                    'two_hourly' => $item->timeDetail? $item->timeDetail->time_name : null,
                    'remark' => $item->remarks,
                    'sector' => $item->sector,
                ];
            });

            return response()->json($transformed);
        } else {
            return response()->json(['msg' => 'No Poll Reports sent by User'], 404);
        }
    }


    /*------------------------------ USER END ------------------------------------*/
    /*------------------------------ MONITORING ROLE START (ROLE: 300)------------------------------------*/
    //poll reports
    public function monitor_poll_reports(Request $request)
    {
        // $rules = [
            // 'requested_by' => 'required',
            // 'start' => ['required', 'date', 'date_format:Y-m-d', 'after_or_equal:2024-01-01', 'before_or_equal:' . now()->format('Y-m-d')],
            // 'end' => ['required', 'date', 'date_format:Y-m-d', 'after_or_equal:2024-01-01', 'before_or_equal:' . now()->format('Y-m-d')],
        // ];

        // Define the allowed parameters
        // $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        // if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
        //     return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        // }

        // $validator = Validator::make($request->all(), $rules);

        // if ($validator->fails()) {
        //     $firstErrorMessage = $validator->errors()->first();
        //     return response()->json(['msg' => $firstErrorMessage], 400);
        // }

        // $start = $request->input("start");
        // $end = $request->input("end");
        //$userPhone = $request->input("requested_by"); //get the Admin's phone no.

        // Find the Admin's AC based on their phone number
        $userACId = User::where('id',  JWTauth::user()->id)->value('ac');

        if (!$userACId) {
            return response()->json(['message' => 'User or Assembly Constituency not found'], 404);
        }

        //entered_by user's AC of poll reports should be the same as requested admin's AC
        $phones = User::where('role_id', 200)->where('ac', $userACId)->pluck('id'); //get the phone numbers having same AC as requested Admins
        $sector = User::where('id',  JWTauth::user()->id)->value('sectorno');

        if (PollReport::whereIn('entered_by', $phones)->count() > 0) {
            // Fetch poll reports within the specified date range and related to the Admin's AC
            $poll_reports = PollReport::whereIn('entered_by', $phones)
                                        ->where('active', '1')
                                        ->with("categoryDetail","timeDetail")
                                        //-> whereDate('created_at', '>=', $start)->whereDate('created_at', '<=', $end) //filter date range
                                        ->orderBy('created_at', 'DESC')
                                        ->get();
            $transformed = $poll_reports->map(function ($item) {
                return [
                    'id' => $item->id,
                    'category' => $item->categoryDetail ? $item->categoryDetail->category_name : null,
                    'two_hourly' => $item->timeDetail? $item->timeDetail->time_name : null,
                    'remark' => $item->remarks,
                    'sector' => $item->sector,
                ];
            });
            //$transformed.={'sector' => $sector},
            return response()->json($transformed,);
        } else {
            return response()->json(['message' => 'No Poll Reports found for this Assembly Constituency!'], 404);
        }
    }
  
    /*------------------------------ MONITORING END ------------------------------------*/
}